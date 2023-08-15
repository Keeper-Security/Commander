import asyncio
import json
import logging
import os
import time
from datetime import datetime
from threading import Thread

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


class PAMConnection:
    def __init__(self, queue, convo_id, loop, params, gateway_uid, ws_is_ready, encrypt=True):
        if not os.path.isdir(WS_LOG_FOLDER):
            os.makedirs(WS_LOG_FOLDER)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.convo_id = convo_id

        # one log file per opened connection
        self.ws_log_file = os.path.join(WS_LOG_FOLDER, f'{timestamp}.log')
        self.ws_app = None
        self.thread = None
        self.router_queue = queue
        self.loop = loop
        self.params = params
        self.gateway_uid = gateway_uid
        self.ws_is_ready = ws_is_ready
        self.encrypt = encrypt

    def log(self, message: str, log_level=logging.INFO, start_color: bcolors = bcolors.OKGREEN):
        logging.log(log_level, f'{start_color}[{self.convo_id}][PAMConnection]: {message}{bcolors.ENDC}')

    def connect(self):
        try:
            import websocket
        except ImportError:
            self.log('websocket-client module is missing. Use following command to install it:', logging.WARNING,
                     bcolors.WARNING)
            self.log('pip3 install -U websocket-client', logging.WARNING, bcolors.OKBLUE)
            return

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
        self.log(f'Connecting to router url', logging.DEBUG)
        self.ws_app = websocket.WebSocketApp(
            connection_url,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            cookie=cookies_str
        )

        self.thread = Thread(target=self.ws_app.run_forever, kwargs={
            'ping_interval': WS_SERVER_PING_INTERVAL_SEC,
            # frequency how ofter ping is send to the server to keep the connection alive
            'ping_payload': 'client-hello'},
                             daemon=True
                             )
        self.thread.start()
        # Wait for the websocket to be ready
        time.sleep(3)
        self.log(f'ws ping thread started.', logging.DEBUG)

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

        self.ws_is_ready.set()

        self.log(f'Connected to websocket finished', logging.DEBUG)

    def disconnect(self):
        if self.thread and self.thread.is_alive():
            self.ws_app.close()
            self.thread.join()

    def send(self, command_payload, controller_uid):
        data_dict = {'kind': 'STREAM', 'payload': command_payload, 'controllerUid': controller_uid}

        data_json = json.dumps(data_dict)

        self.ws_app.send(data_json)
        self.log(f'Data sent {data_json}', logging.DEBUG)

    # These methods are called by the websocket client running in a separate thread
    def on_open(self, ws):
        # self.ws_app.send(json.dumps(WS_INIT))
        pass

    def on_message(self, ws, event_json):
        # this is the reception method for messages from the router
        self.log(f'on_message: {event_json}', logging.DEBUG)
        self.router_queue.put(event_json)
        self.log(f'on_message new router_queue size: {self.router_queue.qsize()}', logging.DEBUG)

    def on_close(self, ws, reason, code):
        self.log(f'Connection closed: Status code: {code}, Message: {reason}', logging.INFO)

    def on_error(self, ws, error):
        self.log(f'Connection error: {error}', logging.ERROR, bcolors.FAIL)

