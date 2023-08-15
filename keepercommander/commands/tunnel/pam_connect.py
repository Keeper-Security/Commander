import asyncio
import json
import logging
from typing import Optional

import websockets
from websockets.client import WebSocketClientProtocol

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

from keepercommander import utils, rest_api, crypto
from keepercommander.commands.pam.router_helper import get_controller_cookie, request_cookie_jar_to_str, \
    get_router_ws_url, router_send_message_to_gateway
from keepercommander.display import bcolors
from keepercommander.loginv3 import CommonHelperMethods
from keepercommander.proto import router_pb2, pam_pb2


WS_URL = "ws://localhost:8081/tunnel"
WS_INIT = {'kind': 'init'}
WS_LOG_FOLDER = 'dr-logs'
WS_SERVER_PING_INTERVAL_SEC = 5


MAX_PACKET_SIZE = 31 * 1024
MAX_BUFFER_SIZE = 24 * 1024


class PAMConnection:
    logger = logging.getLogger('keeper.aws_tunnel')

    def __init__(self, queue, convo_id, loop, params, gateway_uid, encrypt=True):
        self.ws = None  # type: Optional[WebSocketClientProtocol]
        self.verify_cert = True
        self.pair_id: Optional[str] = None
        self.loop = loop
        self.input_queue = asyncio.Queue()
        self.output_queue = queue
        self.convo_id = convo_id
        self.params = params
        self.gateway_uid = gateway_uid
        self.encrypt = encrypt

    def log(self, message: str, log_level=logging.INFO, start_color: bcolors = bcolors.OKGREEN):
        logging.log(log_level, f'{start_color}[{self.convo_id}][PAMConnection]: {message}{bcolors.ENDC}')

    @property
    def is_connected(self) -> bool:
        return self.ws is not None and self.pair_id is not None

    # async def ws_writer(self):
    #     ws = self.ws
    #     while ws.open:
    #         buffer = await self.input_queue.get()
    #         if buffer:
    #             await self.input_queue.put(buffer)
    #
    #     while not self.input_queue.empty():
    #         _ = self.input_queue.get_nowait()
    #         self.input_queue.task_done()
    #
    async def ws_reader(self):
        ws = self.ws
        async for message in ws:
            try:
                await self.output_queue.put(message)
                self.log(f'ws_reader new router_queue size: {self.output_queue.qsize()}', logging.DEBUG)
            except Exception as e:
                self.logger.warning(f'Failed to parse message: {e}')
                continue

    async def connect(self, on_connected) -> None:
        await self.disconnect()

        cookies_jar = get_controller_cookie(self.params, self.gateway_uid)
        if not cookies_jar:
            self.log('Unable to get controller cookie', logging.ERROR, bcolors.FAIL)
            return

        cookies_str = request_cookie_jar_to_str(cookies_jar)

        transmission_key = utils.generate_aes_key()
        server_public_key = rest_api.SERVER_PUBLIC_KEYS[self.params.rest_context.server_key_id]

        if self.params.rest_context.server_key_id < 7:
            encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
        else:
            encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)

        encrypted_session_token = crypto.encrypt_aes_v2(utils.base64_url_decode(self.params.session_token), transmission_key)

        router_url = get_router_ws_url(self.params)

        connection_url = (f'{router_url}/tunnel/{self.convo_id}?Authorization=KeeperUser%20{CommonHelperMethods.bytes_to_url_safe_str(encrypted_session_token)}&TransmissionKey={CommonHelperMethods.bytes_to_url_safe_str(encrypted_transmission_key)}')
        self.log(f'Connecting to router', logging.DEBUG)

        extra_headers = {"Cookie": cookies_str}

        self.ws = await websockets.connect(
            connection_url,
            extra_headers=extra_headers,
            ping_interval=WS_SERVER_PING_INTERVAL_SEC
        )

        self.log(f'ws started.', logging.DEBUG)

        payload_dict = {
            'kind': 'start',
            'encryptTunnel': self.encrypt,
            'conversationType': 'tunnel'
        }
        payload_json = json.dumps(payload_dict, default=lambda o: o.__dict__, sort_keys=True, indent=4)
        payload_bytes = payload_json.encode('utf-8')

        rq_proto = router_pb2.RouterControllerMessage()
        rq_proto.messageUid = url_safe_str_to_bytes(self.convo_id)
        rq_proto.controllerUid = url_safe_str_to_bytes(self.gateway_uid)
        rq_proto.messageType = pam_pb2.CMT_STREAM
        rq_proto.streamResponse = False
        rq_proto.payload = payload_bytes
        rq_proto.timeout = 1500000  # Default time out how long the response from the Gateway should be
        self.log(f'Sending start message to gateway', logging.DEBUG)
        router_send_message_to_gateway(
            self.params,
            transmission_key,
            rq_proto,
            self.gateway_uid)

        self.log(f'Connected to websocket finished', logging.DEBUG)
        on_connected.set()

        await self.ws_reader()

    async def disconnect(self) -> None:
        if self.ws:
            await self.ws.close()
            self.ws = None
        self.pair_id = None
        await self.input_queue.put(b'')
        while not self.output_queue.empty():
            _ = self.output_queue.get_nowait()
            self.output_queue.task_done()
    #
    # async def read(self, timeout: int = -1) -> bytes:
    #     if timeout > 0:
    #         buffer = await asyncio.wait_for(self.output_queue.get(), timeout)
    #     else:
    #         buffer = await self.output_queue.get()
    #     self.output_queue.task_done()
    #     return buffer
    #
    # async def write(self, data: bytes) -> None:
    #     if self.is_connected:
    #         while len(data) > 0:
    #             buffer = data[:MAX_BUFFER_SIZE]
    #             data = data[MAX_BUFFER_SIZE:]
    #             await self.input_queue.put(buffer)
    #     else:
    #         raise Exception('Not connected')

    # These methods are called by the websocket client running in a separate thread

    async def write(self, command_payload, controller_uid):
        data_dict = {'kind': 'STREAM', 'payload': command_payload, 'controllerUid': controller_uid}

        data_json = json.dumps(data_dict)

        await self.ws.send(data_json)
        self.log(f'Data sent {data_json}', logging.DEBUG)

    def on_open(self, ws):
        pass

    def on_message(self, ws, event_json):
        # this is the reception method for messages from the router
        self.log(f'on_message: {event_json}', logging.DEBUG)
        t = self.schedule_task(self.output_queue.put(event_json))
        self.log(f'on_message new router_queue size: {self.output_queue.qsize()}', logging.DEBUG)

    def schedule_task(self, task):
        return self.loop.create_task(task)

    def on_close(self, ws, reason, code):
        self.log(f'Connection closed: Status code: {code}, Message: {reason}', logging.INFO)

    def on_error(self, ws, error):
        self.log(f'Connection error: {error}', logging.ERROR, bcolors.FAIL)

