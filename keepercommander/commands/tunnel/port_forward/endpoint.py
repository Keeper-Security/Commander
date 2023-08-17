import abc
import asyncio
import enum
import logging
import socket
from typing import Optional, Dict, Tuple, Iterable, Awaitable

from cryptography.hazmat.primitives.asymmetric import ec

from .crypto import generate_ec_key, unload_ec_public_key, load_ec_public_key, encrypt_ec, decrypt_ec
from .tunnel import ITunnel


class ControlMessage(enum.IntEnum):
    Ping = 1
    Pong = 2
    SharePublicKey = 10
    ApplicationMessage = 100    # 100 and more encrypted final implementation
    OpenConnection = 101
    CloseConnection = 102


class TunnelProtocol(abc.ABC):
    logger = logging.getLogger('keeper.port_forward')

    def __init__(self, tunnel: ITunnel, endpoint_name: str):
        self.tunnel = tunnel
        self.endpoint_name = endpoint_name
        self.is_reading = False
        self.private_key: Optional[ec.EllipticCurvePrivateKeyWithSerialization] = None
        self.public_key: Optional[ec.EllipticCurvePublicKeyWithSerialization] = None
        self.pair_public_key: Optional[ec.EllipticCurvePublicKeyWithSerialization] = None
        self.connections: Dict[int, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.queue: Optional[asyncio.Queue] = None
        self._is_running = False
        self._ping_attempt = 0

    @property
    def is_running(self):
        return self._is_running

    @property
    def is_paired(self) -> bool:
        return self.pair_public_key is not None

    async def connect(self):
        if not self.tunnel.is_connected:
            await self.tunnel.connect()

        self._is_running = True
        t1 = asyncio.create_task(self.start_tunnel_reader())
        t2 = asyncio.create_task(self.start_process_queue())
        tasks = [t1, t2]
        tasks.extend(self.start_extra_services())
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        await self.disconnect()

    async def disconnect(self):
        self._is_running = False
        tasks = []
        for connection_no, c in self.connections.items():
            reader, writer = c
            try:
                reader.feed_eof()
                writer.close()
                tasks.append(writer.wait_closed())
            except Exception as e:
                self.logger.debug('Endpoint %s: Connection "%d" disconnect error: %s',
                                  self.endpoint_name, connection_no, e)
            tasks.append(self.send_control_message(
                ControlMessage.CloseConnection, int.to_bytes(connection_no, 4, byteorder='big')))
        self.connections.clear()
        if len(tasks) > 0:
            f = asyncio.gather(*tasks)
            await f

        q = self.queue
        if q:
            await q.put((0, b''))

        await self.tunnel.disconnect()

        self.private_key = None
        self.public_key = None
        self.pair_public_key = None

        tasks.clear()
        tasks.extend(self.stop_extra_services())
        if len(tasks) > 0:
            await asyncio.gather(*tasks)

    def start_extra_services(self) -> Iterable[Awaitable]:
        yield from ()

    def stop_extra_services(self) -> Iterable[Awaitable]:
        yield from ()

    async def start_tunnel_reader(self) -> None:
        if not self.tunnel.is_connected:
            self.logger.warning('Endpoint %s: Tunnel reader: not connected', self.endpoint_name)
            return

        self.private_key, self.public_key = generate_ec_key()
        self.pair_public_key = None

        pub_key = unload_ec_public_key(self.public_key)

        self._ping_attempt = 0
        while self.tunnel.is_connected:
            try:
                if not self.pair_public_key:
                    logging.debug('Endpoint %s: Send key exchange request', self.endpoint_name)
                    await self.send_control_message(ControlMessage.SharePublicKey, pub_key)
                buffer = await self.tunnel.read(300 if self.pair_public_key else 100)
            except asyncio.TimeoutError as e:
                if self._ping_attempt > 3:
                    if self.tunnel.is_connected:
                        await self.tunnel.disconnect()
                    raise e
                self.logger.debug('Endpoint %s: Tunnel reader timed out', self.endpoint_name)
                if self.pair_public_key:
                    logging.debug('Endpoint %s: Send ping request', self.endpoint_name)
                    await self.send_control_message(ControlMessage.Ping)
                self._ping_attempt += 1
                continue
            except Exception as e:
                self.logger.warning('Endpoint %s: Failed to read from tunnel: %s', self.endpoint_name, e)
                raise e

            if not self.tunnel.is_connected:
                break

            if not isinstance(buffer, bytes):
                continue

            while len(buffer) > 0:
                is_packet_valid = True
                if len(buffer) >= 8:
                    connection_no = int.from_bytes(buffer[:4], byteorder='big')
                    length = int.from_bytes(buffer[4:8], byteorder='big')
                    buffer = buffer[8:]
                    if length <= len(buffer):
                        data = buffer[:length]
                        buffer = buffer[length:]
                        if connection_no == 0:
                            if len(data) >= 2:
                                message_no = int.from_bytes(data[:2], byteorder='big')
                                data = data[2:]
                                if message_no > ControlMessage.ApplicationMessage:
                                    try:
                                        if len(data) > 0:
                                            data = decrypt_ec(data, self.private_key)
                                    except Exception as e:
                                        is_packet_valid = False
                                        self.logger.warning('Endpoint %s: Decryption error: %s',
                                                            self.endpoint_name, e)
                                if is_packet_valid:
                                    await self.process_control_message(ControlMessage(message_no), data)
                            else:
                                is_packet_valid = False
                        else:
                            try:
                                data = decrypt_ec(data, self.private_key)
                                if self.queue:
                                    await self.queue.put((connection_no, data))
                            except Exception as e:
                                self.logger.warning('Endpoint %s: Decryption error: %s', self.endpoint_name, e)
                    else:
                        is_packet_valid = False
                else:
                    is_packet_valid = False

                if not is_packet_valid:
                    self.logger.info('Endpoint %s: Invalid packet ', self.endpoint_name)
                    buffer = ''

    async def _send_to_tunnel(self, connection_no: int, data: bytes) -> None:
        buffer = int.to_bytes(connection_no, 4, byteorder='big')
        buffer += int.to_bytes(len(data), 4, byteorder='big')
        buffer += data

        await self.tunnel.write(buffer)

    async def send_data_message(self, connection_no: int, data: bytes) -> None:
        if not self.is_paired:
            self.logger.warning('Endpoint %s: Data rejected: not paired', self.endpoint_name)
            return

        data = encrypt_ec(data, self.pair_public_key)
        await self._send_to_tunnel(connection_no, data)

    async def send_control_message(self, message_no: ControlMessage, data: Optional[bytes] = None) -> None:
        buffer = data if data is not None else b''
        if message_no >= ControlMessage.ApplicationMessage:
            if not self.is_paired:
                self.logger.warning('Endpoint %s: Control message %d rejected: not paired',
                                    self.endpoint_name, message_no)
                return
            buffer = encrypt_ec(buffer, self.pair_public_key)

        buffer = int.to_bytes(message_no, 2, byteorder='big') + buffer
        await self._send_to_tunnel(0, buffer)

    async def read_connection(self, connection_no: int):
        while self.is_running:
            c = self.connections.get(connection_no)
            if c is None:
                break
            reader, _ = c
            try:
                data = await reader.read(16 * 1024)
                if isinstance(data, bytes):
                    if len(data) == 0 and reader.at_eof():
                        break
                    else:
                        self.logger.debug('Endpoint %s: Connection "%d" read %d bytes',
                                          self.endpoint_name, connection_no, len(data))
                        await self.send_data_message(connection_no, data)
            except Exception as e:
                self.logger.debug('Endpoint %s: Connection "%d" read failed: %s',
                                  self.endpoint_name, connection_no, e)
                break

        c = self.connections.get(connection_no)
        if c is not None:
            del self.connections[connection_no]
            _, writer = c
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                self.logger.debug('Endpoint %s: Connection "%d" close failed: %s',
                                  self.endpoint_name, connection_no, e)

        await self.send_control_message(
            ControlMessage.CloseConnection, int.to_bytes(connection_no, 4, byteorder='big'))
        self.logger.debug('Endpoint %s: Connection "%d" closed', self.endpoint_name, connection_no)

    async def start_process_queue(self):
        self.queue = asyncio.Queue()
        while self.is_running:
            connection_no, data = await self.queue.get()
            try:
                if not self.is_running:
                    continue
                if connection_no == 0:
                    continue
                if not data:
                    continue
                c = self.connections.get(connection_no)
                if c is None:
                    self.logger.debug('Endpoint %s: Connection "%d" does not exist',
                                      self.endpoint_name, connection_no)
                    continue
                writer = c[1]
                writer.write(data)
                await writer.drain()
            except Exception as e:
                self.logger.warning('Endpoint %s: Connection "%d" failed to write: %s',
                                    self.endpoint_name, connection_no, e)
            finally:
                self.queue.task_done()

        self.queue = None
        self.logger.debug('Endpoint %s: Queue processor exited', self.endpoint_name)

    async def process_control_message(self, message_no: ControlMessage, data: bytes):
        if message_no == ControlMessage.Ping:
            logging.debug('Endpoint %s: Received ping request', self.endpoint_name)
            logging.debug('Endpoint %s: Send pong request', self.endpoint_name)
            await self.send_control_message(ControlMessage.Pong)
            self._ping_attempt = 0
        if message_no == ControlMessage.Pong:
            logging.debug('Endpoint %s: Received pong request', self.endpoint_name)
            self._ping_attempt = 0
        elif message_no == ControlMessage.SharePublicKey:
            try:
                self.pair_public_key = load_ec_public_key(data)
                logging.debug('Endpoint %s: Received session key', self.endpoint_name)
            except Exception as e:
                self.logger.info('Endpoint %s: Connecting to pair: Public key load error: %s',
                                 self.endpoint_name, e)
        elif message_no == ControlMessage.CloseConnection:
            if data and len(data) >= 4:
                connection_no = int.from_bytes(data[:4], byteorder='big')
                c = self.connections.get(connection_no)
                if c is not None:
                    del self.connections[connection_no]
                    reader, writer = c
                    reader.feed_eof()
                    writer.close()
            else:
                self.logger.debug('Endpoint %s: CloseConnection message requires "connection_no" parameter',
                                  self.endpoint_name)
        else:
            await self.on_control_message_received(message_no, data)

    async def on_control_message_received(self, message_no: ControlMessage, data: bytes):
        pass


class TunnelEntrance(TunnelProtocol):
    def __init__(self, tunnel: ITunnel, name: Optional[str] = None):
        super().__init__(tunnel, name or 'Entrance')
        self.server: Optional[asyncio.Server] = None
        self.connection_no = 1

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        connection_no = self.connection_no
        self.connection_no += 1
        self.connections[connection_no] = (reader, writer)
        self.logger.debug('Endpoint %s: Connection "%d" created', self.endpoint_name, connection_no)
        await self.send_control_message(
            ControlMessage.OpenConnection, int.to_bytes(connection_no, 4, byteorder='big'))

        await self.read_connection(connection_no)

    @property
    def port(self) -> int:
        if self.server and self.server.is_serving():
            ep = next((x for x in self.server.sockets if x.family == socket.AF_INET), None)
            if ep:
                return ep.getsockname()[1]
        return 0

    async def start_server(self):
        self.server = await asyncio.start_server(
            # TODO: this is where we define what can connect to this port. Need to make this configurable
            # via the config file
            self.handle_connection, family=socket.AF_INET, port=0)
        async with self.server:
            self.logger.info('Endpoint %s: Listening on port: %d', self.endpoint_name, self.port)
            await self.server.serve_forever()

    async def stop_server(self):
        s = self.server
        if s and s.is_serving():
            await s.wait_closed()

    def start_extra_services(self) -> Iterable[Awaitable]:
        yield self.start_server()

    def stop_extra_services(self) -> Iterable[Awaitable]:
        yield self.stop_server()


class TunnelExit(TunnelProtocol):
    def __init__(self, tunnel: ITunnel, host: str, port: int, name: Optional[str] = None):
        super().__init__(tunnel, name or 'Exit')
        self.host = host
        self.port = port

    async def _open_connection(self, connection_no: int):
        if connection_no in self.connections:
            return

        self.logger.debug('Endpoint %s: Connection "%d" open request', self.endpoint_name, connection_no)

        self.connections[connection_no] = await asyncio.open_connection(host=self.host, port=self.port)
        asyncio.create_task(self.read_connection(connection_no))

    async def on_control_message_received(self, message_no: ControlMessage, data: bytes) -> None:
        if message_no == ControlMessage.OpenConnection:
            if data and len(data) >= 4:
                connection_no = int.from_bytes(data[:4], byteorder='big')
                await self._open_connection(connection_no)
