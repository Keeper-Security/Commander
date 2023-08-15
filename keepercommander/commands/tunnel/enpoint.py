import asyncio
import logging
import socket
import threading
import time
from ...display import bcolors
from datetime import timedelta
from typing import Optional
from queue import Queue

from keeper_secrets_manager_core.crypto import CryptoUtils

from .pam_connect import PAMConnection
from ...params import KeeperParams


class TunnelEntrance:

    def __init__(self, params: KeeperParams, convo_id: str, encrypt: bool, gateway_uid: str,
                 record_key_bytes: bytes = b'', port: int = None, timeout: int = 20):

        self.convo_id = convo_id
        self.port_value = port
        self.encrypt = encrypt
        self.is_connected = False
        self.gateway_uid = gateway_uid
        self.record_key_bytes = record_key_bytes
        self.start_time = time.time()
        self.loop = None
        self.timeout = timeout
        self.connection = None

        self.server: Optional[asyncio.Server] = None

        self._client_reader = None
        self._client_writer = None
        self.ping_count = 0
        # TODO: ASK MAX what type of keep alive requirement we have for this!!!!
        self.max_ping_count = 0

        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.server_task = None
        self.ws_is_ready = threading.Event()
        self.router_queue = Queue()
        self.tasks_ready = threading.Event()
        self.ws = PAMConnection(self.router_queue, self.convo_id, self.loop, params, self.gateway_uid, self.ws_is_ready,
                                self.encrypt)
        self.log(f'End init tunnel entrance', logging.DEBUG)

    @property
    def port(self) -> int:
        if self.port_value is not None:
            return self.port_value
        if self.is_connected:
            ep = next((x for x in self.server.sockets if x.family == socket.AF_INET), None)
            if ep:
                self.port_value = ep.getsockname()[1]
                return self.port_value
        return 0

    @property
    def uptime(self) -> str:
        if not self.is_connected:
            return '0'
        return str(timedelta(seconds=int(time.time() - self.start_time)))

    async def start_task(self):
        self.ws.connect()
        self.ws_is_ready.wait()
        self.log(f'WS Connection is ready', logging.DEBUG)

        await self.start_server()
        self.log(f'Local server is ready', logging.DEBUG)

        self.is_connected = True

        self.loop.create_task(self.start_router_to_local_tunnel_task())
        self.loop.create_task(self.start_local_to_router_tunnel_task())

        # Start ping task
        # ping_task_coroutine = self.ping_task()
        # asyncio.create_task(ping_task_coroutine)

        await self.write_to_router(b"ping")
        self.tasks_ready.set()
        self.log(f'Tunnel tasks are running', logging.DEBUG)
        return True

    async def ping_task(self):
        self.log(f'Starting commander to gateway ping task', logging.DEBUG)
        while self.is_connected:
            try:
                await asyncio.sleep(5)
                self.log(f'Pinging tunnel connection', logging.DEBUG)
                await self.write_to_router(b"ping")
                self.ping_count += 1
            except Exception as e:
                self.log(f'Exception in Tunnel connection ping failed: {str(e)}', logging.DEBUG)
                return

    async def wait_for_ready(self):
        self.tasks_ready.wait()

    async def start_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.connection = (reader, writer)
        self.log(f'Connection established', logging.DEBUG)

    async def start_server(self):
        try:
            self.server = await asyncio.start_server(self.start_connection, family=socket.AF_INET, host='localhost',
                                                     port=self.port)  # Bind to an available port

            self.log('Tunnel server binding successful', logging.DEBUG)
        except Exception as e:
            self.log(f'Failed to bind server: {e}', logging.DEBUG, bcolors.FAIL)
            return

        # Retrieve the bound port number
        ep = next((x for x in self.server.sockets if x.family == socket.AF_INET), None)
        if ep:
            self.port_value = ep.getsockname()[1]
            self.log(f'Tunnel server bound to port {self.port_value}', logging.DEBUG)

        self.log('Tunnel server is ready', logging.DEBUG)

        self.server_task = self.loop.create_task(self.run_server())

        self.log('Tunnel server started', logging.DEBUG)

    async def run_server(self):
        self.log(f'Tunnel server is {self.server}', logging.DEBUG)
        async with self.server:
            await self.server.serve_forever()

    async def disconnect(self):
        self.is_connected = False
        tasks = []
        for connection_no, c in self.connection:
            reader, writer = c
            try:
                reader.feed_eof()
                writer.close()
                tasks.append(writer.wait_closed())
            except Exception as e:
                self.log(f'Connection "{connection_no}" disconnect error: {e}', logging.ERROR, bcolors.FAIL)
        self.connection.clear()
        if len(tasks) > 0:
            f = asyncio.gather(*tasks)
            await f

        tasks.clear()
        if len(tasks) > 0:
            await asyncio.gather(*tasks)

    async def start_router_to_local_tunnel_task(self) -> None:
        if not self.is_connected:
            self.log(f'[Tunnel reader] not connected', logging.ERROR, bcolors.FAIL)
            return

        while self.is_connected:
            try:
                self.log(f'Waiting for data queue size: {self.router_queue.qsize()}', logging.DEBUG)
                unencrypted_data = self.router_queue.get()
                self.log(f'After data queue size: {self.router_queue.qsize()} '
                         f'Received type: {type(unencrypted_data)} len: {len(unencrypted_data)}', logging.DEBUG)

                self.router_queue.task_done()
                if isinstance(unencrypted_data, str):
                    if len(unencrypted_data) == 0:
                        unencrypted_data = b''
                    else:
                        self.log(f'Received message: {unencrypted_data}', logging.DEBUG)
                        if "ping" == unencrypted_data:
                            self.log(f'Received ping', logging.DEBUG)
                            await self.write_to_router(b"pong")
                            self.log(f'Sent pong', logging.DEBUG)
                            continue
                        elif "pong" == unencrypted_data:
                            self.log(f'Received pong', logging.DEBUG)
                            await self.write_to_router(b"ping")
                            # self.ping_count -= 1
                            continue
                        else:
                            self.log(f'Read {len(unencrypted_data)} bytes', logging.DEBUG)

                        if self.ping_count > self.max_ping_count:
                            self.is_connected = False
                            self.log(f'Ping count exceeded {self.max_ping_count}', logging.DEBUG)
                            await self.disconnect()
                            continue

                    if not isinstance(unencrypted_data, bytes):
                        continue
                    try:
                        if self.encrypt:
                            unencrypted_data = CryptoUtils.decrypt_aes(unencrypted_data, self.record_key_bytes)
                    except Exception as e:
                        self.log(f'Decryption error: {e}', logging.ERROR, bcolors.FAIL)
                        raise
                    await self.write_to_local(unencrypted_data)

                else:
                    self.log(f'Read type:{type(unencrypted_data)} length: {len(unencrypted_data)}', logging.DEBUG)

            except asyncio.TimeoutError:
                self.log(f"Tunnel reader didn't receive data in {self.timeout} seconds", logging.DEBUG,
                         bcolors.WARNING)
            except Exception as ex:
                self.log(f'Failed to read from tunnel: {ex}', logging.ERROR, bcolors.FAIL)
                raise ex
        self.log(f'Tunnel reader task stopped', logging.DEBUG)

    async def write_to_router(self, data: bytes):
        self.log(f'Sending message: {data}', logging.DEBUG)

        encrypted_data = data

        if self.encrypt:
            encrypted_data = CryptoUtils.encrypt_aes(data, self.record_key_bytes)

        payload = {
            ''
            'conversationId': self.convo_id,
            'value': f'{encrypted_data}'
        }
        self.ws.send(payload, self.gateway_uid)

    async def write_to_local(self, data: bytes) -> None:
        if self.connection is None:
            self.log('Data rejected: not connected', logging.DEBUG, bcolors.FAIL)
            return
        self.log(f'Sending data: {data}', logging.DEBUG)

        decrypted_data = data

        if self.encrypt:
            decrypted_data = CryptoUtils.decrypt_aes(data, self.record_key_bytes)

        _, writer = self.connection
        await writer.write(decrypted_data)

    async def read_from_local(self):
        if self.connection is None:
            return
        reader, _ = self.connection
        try:
            data = await reader.read(16 * 1024)
            if isinstance(data, bytes):
                if len(data) == 0 and reader.at_eof():
                    return
                else:
                    self.log(f'Read {len(data)} bytes', logging.DEBUG, bcolors.OKBLUE)
                    return data
        except Exception as e:
            self.log(f'Connection "{self.convo_id}" read failed: {e}', logging.ERROR, bcolors.FAIL)
            return

        self.log(f'[{self.convo_id}]: Connection "{self.convo_id}" closed', logging.DEBUG)

    async def start_local_to_router_tunnel_task(self):
        while self.is_connected:
            data = await self.read_from_local()
            try:
                if not data:
                    continue
                await self.write_to_router(data)
            except Exception as e:
                self.log(f'[{self.convo_id}]: Failed to write to tunnel: {e}', logging.ERROR, bcolors.FAIL)
        self.log(f'Queue processor exited', logging.DEBUG)

    def log(self, message: str, log_level=logging.INFO, start_color: bcolors = bcolors.OKGREEN):
        logging.log(log_level, f'{start_color}[{self.convo_id}][TunnelEntrance]: {message}{bcolors.ENDC}')
