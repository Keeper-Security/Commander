import asyncio
import enum
import json
import logging
import os
import secrets
import socket
import string
import time
from datetime import datetime
from typing import Optional, Dict

from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.utils import int_to_bytes
from keeper_secrets_manager_core.utils import bytes_to_base64, base64_to_bytes, bytes_to_string, string_to_bytes, \
    bytes_to_int

from keepercommander.commands.pam.pam_dto import GatewayActionWebRTCSession
from keepercommander.commands.pam.router_helper import router_get_relay_access_creds, router_send_action_to_gateway
from keepercommander.display import bcolors
from keepercommander.error import CommandError
from keepercommander.params import KeeperParams
from keepercommander.proto import pam_pb2

logging.getLogger('aiortc').setLevel(logging.WARNING)
logging.getLogger('aioice').setLevel(logging.WARNING)

READ_TIMEOUT = 10
NONCE_LENGTH = 12
SYMMETRIC_KEY_LENGTH = RANDOM_LENGTH = 32
MESSAGE_MAX = 5

# Protocol constants
CONTROL_MESSAGE_NO_LENGTH = 2
CLOSE_CONNECTION_REASON_LENGTH = 1
TIME_STAMP_LENGTH = 8
CONNECTION_NO_LENGTH = DATA_LENGTH = 4
TERMINATOR = b';'
PROTOCOL_LENGTH = CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + CONTROL_MESSAGE_NO_LENGTH + len(TERMINATOR)
KRELAY_URL = 'KRELAY_URL'
ALT_KRELAY_URL = 'KRELAY_SERVER'

# WebRTC constants
# 16 MiB max https://viblast.com/blog/2015/2/25/webrtc-bufferedamount/, so we will use 14.4 MiB or 90% of the max,
# because in some cases if the max is reached the channel will close
BUFFER_THRESHOLD = 134217728 * .90
# 16 Kbytes max https://viblast.com/blog/2015/2/5/webrtc-data-channel-message-size/,
# so we will use the max minus bytes for the protocol
BUFFER_TRUNCATION_THRESHOLD = 16000 - PROTOCOL_LENGTH


class CloseConnectionReasons(enum.IntEnum):
    Normal = 0
    Error = 1
    Timeout = 2
    ServerRefuse = 4
    Client = 5
    Unknown = 6
    InvalidInstruction = 7
    GuacdRefuse = 8
    ConnectionLost = 9
    ConnectionFailed = 10
    TunnelClosed = 11


class ConnectionNotFoundException(Exception):
    pass


class ControlMessage(enum.IntEnum):
    Ping = 1
    Pong = 2
    OpenConnection = 101
    CloseConnection = 102
    ConnectionOpened = 103
    SendEOF = 104


def make_control_message(message_no, data=None):
    data = data if data is not None else b''
    buffer = int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big')
    # Add timestamp
    timestamp_ms = int(datetime.now().timestamp() * 1000)
    buffer += int.to_bytes(timestamp_ms, TIME_STAMP_LENGTH, byteorder='big')
    length = CONTROL_MESSAGE_NO_LENGTH + len(data)
    buffer += int.to_bytes(length, DATA_LENGTH, byteorder='big')
    buffer += int.to_bytes(message_no, CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
    buffer += data + TERMINATOR
    return buffer


def generate_random_bytes(pass_length=RANDOM_LENGTH):  # type: (int) -> bytes
    # Generate random bytes without worrying about character decoding
    random_bytes = secrets.token_bytes(pass_length)

    # Filter out non-printable bytes using a list comprehension
    printable_bytes = [byte for byte in random_bytes if
                       byte in string.printable.encode('utf-8') and byte not in b'\n\r']

    # Convert the list of bytes back to bytes
    filtered_bytes = bytes(printable_bytes)
    if len(filtered_bytes) < pass_length:
        # If the length of the filtered bytes is less than the requested length, call the function recursively
        # to generate more bytes
        return filtered_bytes + generate_random_bytes(pass_length - len(filtered_bytes))

    return filtered_bytes


def find_open_port(tried_ports: [], start_port=49152, end_port=65535, preferred_port=None, host="127.0.0.1"):
    """
    Find an open port in the range [start_port, end_port].
    The default range is from 49152 to 65535, which are the "ephemeral ports" or "dynamic ports.".
    :param tried_ports: A list of ports that have already been tried.
    :param start_port: The starting port number.
    :param end_port: The ending port number.
    :param preferred_port: A preferred port to check first.
    :param host: The host to check for open ports.
    :return: An open port number or None if no port is found.
    """
    if host is None:
        host = '127.0.0.1'
    if preferred_port and preferred_port not in tried_ports:
        if is_port_open(host, preferred_port):
            time.sleep(0.1)  # Short delay to ensure port release
            return preferred_port
        else:
            raise CommandError("Tunnel Start", f"Port {preferred_port} is already in use.")

    for port in range(start_port, end_port + 1):
        if port not in tried_ports and is_port_open(host, port):
            time.sleep(0.1)  # Short delay to ensure port release
            return port

    return None


def is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False
        except Exception as e:
            logging.error(f"Error while checking port {port}: {e}")
            return False


def establish_symmetric_key(private_key, client_public_key):
    # Perform ECDH key agreement
    shared_secret = private_key.exchange(ec.ECDH(), client_public_key)

    # Derive a symmetric key using HKDF
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=SYMMETRIC_KEY_LENGTH,
        salt=None,
        info=b'encrypt network traffic',
    ).derive(shared_secret)
    return AESGCM(symmetric_key)


def tunnel_encrypt(symmetric_key: AESGCM, data: bytes):
    """ Encrypts data using the symmetric key """
    nonce = os.urandom(NONCE_LENGTH)  # 12-byte nonce for AES-GCM
    d = nonce + symmetric_key.encrypt(nonce, data, None)
    return bytes_to_base64(d)


def tunnel_decrypt(symmetric_key: AESGCM, encrypted_data: str):
    """ Decrypts data using the symmetric key """
    data_bytes = base64_to_bytes(encrypted_data)
    if len(data_bytes) <= NONCE_LENGTH:
        return None
    nonce = data_bytes[:NONCE_LENGTH]
    data = data_bytes[NONCE_LENGTH:]
    try:
        return symmetric_key.decrypt(nonce, data, None)
    except Exception as e:
        logging.error(f'Error decrypting data: {e}')
        return None


class WebRTCConnection:
    def __init__(self, params: KeeperParams, record_uid, gateway_uid, symmetric_key,
                 print_ready_event: asyncio.Event, kill_server_event: asyncio.Event,
                 logger: Optional[logging.Logger] = None, server='keepersecurity.com'):

        self._pc = None
        self.web_rtc_queue = asyncio.Queue()
        self.closed = False
        self.data_channel = None
        self.print_ready_event = print_ready_event
        self.logger = logger
        self.endpoint_name = "Starting..."
        self.params = params
        self.record_uid = record_uid
        self.gateway_uid = gateway_uid
        self.symmetric_key = symmetric_key
        self.kill_server_event = kill_server_event
        # Using Keeper's STUN and TURN servers
        self.relay_url = 'krelay.' + server
        self.time_diff = datetime.now() - datetime.now()
        krelay_url = os.getenv(KRELAY_URL)
        if krelay_url:
            self.relay_url = krelay_url
        else:
            alt_krelay_url = os.getenv(ALT_KRELAY_URL)
            if alt_krelay_url:
                self.relay_url = alt_krelay_url
        self.logger.debug(f'Using relay server: {self.relay_url}')
        try:
            self.peer_ice_config()
            self.setup_data_channel()
            self.setup_event_handlers()
        except Exception as e:
            raise Exception(f'Error setting up WebRTC connection: {e}')

    async def signal_channel(self, kind: str):

        # make webRTC sdp offer
        try:
            if kind == 'start':
                offer = await self.make_offer()
            else:
                raise Exception(f'Invalid kind: {kind}')
        except socket.gaierror as e:
            if 'nodename nor servname provided, or not known' in str(e):
                print(
                    f"{bcolors.WARNING}Error connecting to relay server {self.relay_url}: {e}")
            else:
                print(
                    f"{bcolors.WARNING}Please upgrade Commander to the latest version to use this feature...{e}"
                    f"{bcolors.ENDC}")
            return
        except Exception as e:
            raise Exception(f'Error making WebRTC offer: {e}')
        data = {"offer": bytes_to_base64(offer)}
        string_data = json.dumps(data)
        bytes_data = string_to_bytes(string_data)
        encrypted_data = tunnel_encrypt(self.symmetric_key, bytes_data)
        self.logger.debug("-->. SEND START MESSAGE OVER REST TO GATEWAY")
        '''
            'inputs': {
                'recordUid': record_uid,            <-- the PAM resource record UID with Network information (REQUIRED)
                'conversationType': [
                    'tunnel', 'vnc', 'rdp', 'ssh', 'telnet', 'kubernetes', 
                    'mysql', 'postgresql', 'sql-server', 'http']       <-- What type of conversation is this (REQUIRED)
                'kind': ['start', 'disconnect'],                                     <-- What command to run (REQUIRED)
                'conversations': [List of conversations to disconnect],                <-- (Only for kind = disconnect)

                'data': {                                       <-- All data is encrypted with symmetric key (REQUIRED)
                    'offer': encrypted_WebRTC_sdp_offer,        <-- WebRTC SDP offer, base64 encoded
                }
            }
        '''
        # TODO: remove when reporting is deployed to krouter prod!!!
        dev_router = os.getenv("USE_REPORTING_COMPATABILITY_ROUTER")
        if dev_router:
            gateway_message_type = pam_pb2.CMT_CONNECT
            self.logger.warning("#" * 30 + f"Sending CMT_CONNECT message type. Sergey, this is good..." + "#" * 30)
        else:
            gateway_message_type = pam_pb2.CMT_GENERAL

        # TODO create objects for WebRTC inputs
        router_response = router_send_action_to_gateway(
            params=self.params,
            gateway_action=GatewayActionWebRTCSession(
                inputs={
                    "recordUid": self.record_uid,
                    'kind': kind,
                    'conversationType': 'tunnel',
                    "data": encrypted_data
                }
            ),
            message_type=gateway_message_type,
            is_streaming=False,
            destination_gateway_uid_str=self.gateway_uid,
            gateway_timeout=30000
        )
        if not router_response:
            self.kill_server_event.set()
            return
        gateway_response = router_response.get('response', {})
        if not gateway_response:
            raise Exception(f"Error getting response from the Gateway: {router_response}")
        self.endpoint_name = gateway_response.get('conversationId', )
        try:
            payload = json.loads(gateway_response.get('payload', None))
            if not payload:
                raise Exception(f"Error getting payload from the Gateway response: {gateway_response}")
        except Exception as e:
            raise Exception(f"Error getting payload from the Gateway response: {e}")

        if payload.get('is_ok', False) is False or payload.get('progress_status') == 'Error':
            raise Exception(f"Gateway response: {payload.get('data')}")

        data = payload.get('data', None)
        if not data:
            raise Exception(f"Error getting data from the Gateway response payload: {payload}")

        # decrypt the sdp answer
        try:
            data = tunnel_decrypt(self.symmetric_key, data)
        except Exception as e:
            raise Exception(f'Error decrypting WebRTC answer from data: {data}\nError: {e}')
        try:
            str_data = bytes_to_string(data).replace("'", '"')
            data = json.loads(str_data)
        except Exception as e:
            raise Exception(f'Error loading WebRTC answer from data: {data}\nError: {e}')
        if not data.get('answer'):
            raise Exception(f"Error getting answer from the Gateway response data: {data}")
        try:
            answer = base64_to_bytes(data.get('answer'))
        except Exception as e:
            raise Exception(f'Error decoding WebRTC answer from data: {data}\nError: {e}')
        await self.accept_answer(answer)

        self.logger.debug("starting private tunnel")

    def peer_ice_config(self):
        response = router_get_relay_access_creds(params=self.params, expire_sec=60000000)
        if response is None:
            raise Exception("Error getting relay access credentials")
        if hasattr(response, "time"):
            self.time_diff = datetime.now() - datetime.fromtimestamp(response.time)
        stun_url = f"stun:{self.relay_url}:3478"
        # Create an RTCIceServer instance for the STUN server
        stun_server = RTCIceServer(urls=stun_url)
        # Define the TURN server URL and credentials
        turn_url = f"turn:{self.relay_url}"
        # Create an RTCIceServer instance for the TURN server with credentials
        turn_server = RTCIceServer(urls=turn_url, username=response.username, credential=response.password)
        # Create a new RTCConfiguration with both STUN and TURN servers
        config = RTCConfiguration(iceServers=[stun_server, turn_server])

        self._pc = RTCPeerConnection(config)

    async def make_offer(self):
        offer = await self._pc.createOffer()
        await self._pc.setLocalDescription(offer)
        return self._pc.localDescription.sdp.encode('utf-8')

    async def accept_answer(self, answer):
        if isinstance(answer, bytes):
            answer = bytes_to_string(answer)
        await self._pc.setRemoteDescription(RTCSessionDescription(answer, "answer"))

    def setup_data_channel(self):
        self.data_channel = self._pc.createDataChannel("control", ordered=True)

    def setup_event_handlers(self):
        self.data_channel.on("open", self.on_data_channel_open)
        self.data_channel.on("message", self.on_data_channel_message)
        self._pc.on("datachannel", self.on_data_channel)
        self._pc.on("connectionstatechange", self.on_connection_state_change)

    def on_data_channel_open(self):
        self.print_ready_event.set()
        buffer = make_control_message(ControlMessage.Ping, b'')
        self.send_message(buffer)
        self.logger.debug(f'Endpoint {self.endpoint_name}: Data channel opened')

    def on_data_channel_message(self, message):
        self.web_rtc_queue.put_nowait(message)

    def on_data_channel(self, channel):
        channel.on("open", self.on_data_channel_open)
        channel.on("error", self.on_data_channel_error)
        channel.on("message", self.on_data_channel_message)

    def on_connection_state_change(self):
        self.logger.debug(f'Endpoint {self.endpoint_name}: Connection State has changed: {self._pc.connectionState}')
        if self._pc.connectionState == "connected":
            # Connection is established, you can now send/receive data
            pass
        elif self._pc.connectionState in ["disconnected", "failed", "closed"]:
            # Handle disconnection or failure here
            asyncio.get_event_loop().create_task(self.close_webrtc_connection())
            pass

    def is_data_channel_open(self):
        return (self.data_channel is not None and self.data_channel.readyState == "open"
                and self._pc.connectionState == "connected")

    def on_data_channel_error(self, error):
        self.logger.error(f'Endpoint {self.endpoint_name}: Data channel error: {error}')

    # Example usage of state check in a method
    def send_message(self, message):
        if self.is_data_channel_open():
            try:
                self.data_channel.send(message)
            except Exception as e:
                self.logger.error(f'Endpoint {self.endpoint_name}: Error sending message: {e}')
        else:
            self.logger.error(f'Endpoint {self.endpoint_name}: Data channel is not open.')

    async def close_webrtc_connection(self):
        if self.closed:
            return
        # Close the data channel
        if self.data_channel:
            try:
                self.data_channel.close()
                self.logger.error(f'Endpoint {self.endpoint_name}: Data channel closed')
            except Exception as e:
                self.logger.error(f'Endpoint {self.endpoint_name}: Error closing data channel: {e}')

        self.data_channel = None

        # Close the peer connection
        if self._pc:
            await self._pc.close()
            self.logger.error(f'Endpoint {self.endpoint_name}: Peer connection closed')

        # Clear the asyncio queue
        if self.web_rtc_queue:
            while not self.web_rtc_queue.empty():
                self.web_rtc_queue.get_nowait()
            self.web_rtc_queue = None

        # Reset instance variables
        self.data_channel = None
        self._pc = None
        self.kill_server_event.set()

        # Set the closed flag
        self.closed = True

    """
    This class is used to set up the tunnel entrance. This is used for the signaling phase and control messages.

    API calls offer/answer are encrypted using a shared secret derived from a key out of the record and the gateway's 
        own key.
    This tunnel is used to send control messages to the gateway: Ping, Pong, CloseConnection
    and ShareWebRTCDescription.
      There isn't a need for open connection because we send a start command in the discoveryrotation.py file.
      There is one connection or channel, 0 for control messages. We have the ability to add more channels if needed


    The tunnel uses WebRTC to connect to a peer on the gateway.

    The flow is as follows:
                                The pre tunnel (KRouter API calls/Signaling Phase)
       0. User enters a command to start a tunnel
       1. Commander sends a request to the KRouter API to get TURN server credentials
       2. Commander: makes a WebRTC peer, makes and offer, and sets its setLocalDescription.
       3. Commander sends tunnel start action to the gateway through krouter with offer encrypted using the shared 
            secret
       4. The Gateway gets that offer decrypts it with the shared secret and sets its setRemoteDescription, makes an 
            API call to krouter for TURN server credentials and makes an answer and sets its setLocalDescription.
       5. The gateway returns the answer encrypted using the shared secret in the response to the tunnel start action
        5.5 The Gateway sets up a tunnel exit
       6. Commander decrypts the answer and sets its setRemoteDescription to the answer it got from the gateway 
        6.5 The Commander sets up a tunnel entrance
       7 The two peers connect using STUN and TURN servers. If a direct connection can be made then the TURN server 
            is not used.

                                Setting up the tunnel
       8. Commander sets up a local server that listens for connections to a local port that the user has provided or a 
            random port if none is provided.
       9. Commander sends a ping message through the tunnel entrance to the tunnel exit
       10. The Gateway: receives the ping message and sends a pong message back establishing the
          connection
       11. Commander waits for a client to connect to the local server. Both sides wait for a set timeout to receive 
            data if the timeout is reached then a ping is sent. After 3 pings with no pongs the tunnel is closed.

                                User connects to the target
       12. Client connects to the tunnel's local server (localhost:[PORT].
       13. Tunnel Entrance (In Commander) sends an open connection message to the WebRTC connection and listens
            to the client forwarding on any data
       14. Tunnel Exit (On The Gateway): receives the open connection message and connects to the target
           host and port sending any data back to the WebRTC connection
       15. The session goes on until the CloseConnection message is sent, or the outer tunnel is closed.
       16. The User can repeat steps 12-16 as many times as they want

                              User closes the tunnel
       17. The User closes the tunnel and everything is cleaned up, and we can start back at step 1
    """


class ConnectionInfo:
    def __init__(self, reader: Optional[asyncio.StreamReader], writer: Optional[asyncio.StreamWriter],
                 message_counter: int, ping_time: Optional[float], to_tunnel_task: Optional[asyncio.Task],
                 start_time: datetime):
        self.reader = reader
        self.writer = writer
        self.message_counter = message_counter
        self.ping_time = ping_time
        self.to_tunnel_task = to_tunnel_task
        self.start_time = start_time
        self.transfer_latency_sum = 0
        self.transfer_latency_count = 0
        self.receive_latency_sum = 0
        self.receive_latency_count = 0
        self.transfer_size = 0
        self.receive_size = 0


class TunnelEntrance:
    """
    This class is used to forward data between a WebRTC connection and a connection to a target.
    Connection 0 is reserved for control messages. All other connections are for when a client connects
    This tunnel uses four control messages: Ping, Pong, OpenConnection and CloseConnection
    Data is broken into three parts: connection number, [message number], and data
    message number is only used in control messages. (if the connection number is 0 then there is a message number)
    """

    def __init__(self,
                 host,  # type: str
                 port,  # type: int
                 pc,  # type: WebRTCConnection
                 print_ready_event,  # type: asyncio.Event
                 logger=None,  # type: logging.Logger
                 connect_task=None,  # type: asyncio.Task
                 kill_server_event=None  # type: asyncio.Event
                 ):  # type: (...) -> None
        self.closing = False
        self.to_local_task = None
        self._ping_attempt = 0
        self.host = host
        self.server = None
        self.connection_no = 1
        self.connections: Dict[int, ConnectionInfo] = {0: ConnectionInfo(None, None, 0, None, None, datetime.now())}
        self._port = port
        self.logger = logger
        self.is_connected = True
        self.reader_task = asyncio.create_task(self.start_reader())
        self.kill_server_event = kill_server_event
        self.pc = pc
        self.print_ready_event = print_ready_event
        self.connect_task = connect_task
        self.eof_sent = False

    @property
    def port(self):
        return self._port

    async def send_to_web_rtc(self, data):
        if self.pc.is_data_channel_open():
            try:
                sleep_count = 0
                while (self.pc.data_channel is not None and
                       self.pc.data_channel.bufferedAmount >= BUFFER_THRESHOLD and
                       not self.kill_server_event.is_set() and
                       self.pc.is_data_channel_open()):
                    self.logger.debug(f"{bcolors.WARNING}Buffered amount is too high ({sleep_count * 100}) "
                                      f"{self.pc.data_channel.bufferedAmount}{bcolors.ENDC}")
                    await asyncio.sleep(sleep_count)
                    sleep_count += .01
                self.pc.send_message(data)
                # Yield control back to the event loop for other tasks to execute
                await asyncio.sleep(0)

            except Exception as e:
                self.logger.error(f'Endpoint {self.pc.endpoint_name}: Error sending message: {e}')
                await asyncio.sleep(0.1)
        else:
            if self.print_ready_event.is_set():
                self.logger.error(f'Endpoint {self.pc.endpoint_name}: Data channel is not open. Data not sent.')
            if self.connection_no > 1:
                self.kill_server_event.set()

    async def send_control_message(self, message_no, data=None):  # type: (ControlMessage, Optional[bytes]) -> None
        """
        Packet structure
         Control Message Packets
               [CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + CONTROL_MESSAGE_NO_LENGTH + DATA]
        """
        buffer = make_control_message(message_no, data)
        try:
            self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Sending Control command {message_no} len: {len(buffer)}'
                              f' to tunnel.')
            self.connections[0].transfer_size += len(buffer)
            await self.send_to_web_rtc(buffer)
        except Exception as e:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while sending control message: {e}")

    def update_stats(self, connection_no, data_size, timestamp):
        """
        Update the transfer stats for the connection
        :param connection_no:
        :param data_size:
        :param timestamp:
        :return:
        """
        c = self.connections.get(connection_no)
        if c:
            dt = datetime.fromtimestamp(timestamp/1000)
            c.receive_size += data_size
            td = datetime.now() + self.pc.time_diff - dt
            # Convert timedelta to total milliseconds
            td_milliseconds = (td.days * 24 * 60 * 60 + td.seconds) * 1000 + td.microseconds / 1000
            c.receive_latency_sum += td_milliseconds
            c.receive_latency_count += 1

    def report_stats(self, connection_no: int):
        """
        Report the stats for the connection
        :return:
        """
        con = self.connections.get(connection_no)
        if con:
            average_receive_latency = "Not Available"
            if con.receive_latency_count > 0:
                average_receive_latency = con.receive_latency_sum / con.receive_latency_count

            average_transfer_latency = "Not Available"
            if con.transfer_latency_count > 0:
                average_transfer_latency = con.transfer_latency_sum / con.transfer_latency_count
            self.logger.info(f"Endpoint {self.pc.endpoint_name}: Connection {connection_no} Stats:"
                             f"\n\tTransferred {con.transfer_size} bytes"
                             f"\n\tTransfer Latency Average: {average_transfer_latency} ms"
                             f"\n\tReceive Latency Average: {average_receive_latency} ms"
                             f"\n\tReceived {con.receive_size} bytes")

    async def process_control_message(self, message_no, data):  # type: (ControlMessage, Optional[bytes]) -> None
        if message_no == ControlMessage.CloseConnection:
            self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received close connection request')
            if data and len(data) > 0:

                target_connection_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                reason = CloseConnectionReasons.Unknown
                if len(data) >= CONNECTION_NO_LENGTH:
                    reason_int = int.from_bytes(data[CONNECTION_NO_LENGTH:], byteorder='big')
                    reason = CloseConnectionReasons(reason_int)
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Closing Connection {target_connection_no}' +
                                      (f'Reason: {reason}' if reason else ''))
                else:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Closing Connection {target_connection_no}')

                if target_connection_no == 0:
                    self.kill_server_event.set()
                else:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Closing connection '
                                      f'{target_connection_no}')
                    await self.close_connection(target_connection_no, reason)
        elif message_no == ControlMessage.Pong:
            self._ping_attempt = 0
            self.is_connected = True
            if len(data) >= 0:
                con_no = bytes_to_int(data)
                if con_no in self.connections:
                    self.connections[con_no].message_counter = 0
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received pong request')
                    if con_no != 0:
                        self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received ACK for {con_no}')
                    if self.connections[con_no].ping_time is not None:
                        time_now = time.perf_counter()
                        # from the time the ping was sent to the time the pong was received
                        latency = time_now - self.connections[con_no].ping_time

                        if self.connections[con_no].receive_latency_count > 0:
                            receive_latency_average = (self.connections[con_no].receive_latency_sum /
                                                       self.connections[con_no].receive_latency_count)
                            t_latency = self._round_trip_latency[-1] - receive_latency_average
                            self.connections[con_no].transfer_latency_sum += t_latency
                            self.connections[con_no].transfer_latency_count += 1
                        self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Round trip latency: {latency} ms')
                        self.connections[con_no].ping_time = None
            else:
                self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received pong request')
                if self.connections[0].ping_time is not None:
                    time_now = time.perf_counter()
                    # from the time the ping was sent to the time the pong was received
                    latency = time_now - self.connections[0].ping_time
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Round trip latency: {latency} ms')
                    self.connections[0].ping_time = None

        elif message_no == ControlMessage.Ping:
            if len(data) >= 0:
                con_no = bytes_to_int(data)
                if con_no in self.connections:
                    await self.send_control_message(ControlMessage.Pong, int_to_bytes(con_no))
                    if con_no == 0:
                        self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received ping request')
                    else:
                        if self.logger.level == logging.DEBUG:
                            self.report_stats(0)
                        self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received Ping for {con_no}')
                    if self.logger.level == logging.DEBUG:
                        # print the stats
                        self.report_stats(con_no)
                else:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Connection {con_no} not found')
            else:
                self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Connection not found')
        elif message_no == ControlMessage.ConnectionOpened:
            if len(data) >= CONNECTION_NO_LENGTH:
                if len(data) > CONNECTION_NO_LENGTH:
                    self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Received invalid open connection message"
                                      f" ({len(data)} bytes)")
                connection_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Starting reader for connection "
                                  f"{connection_no}")
                try:
                    self.connections[connection_no].to_tunnel_task = asyncio.create_task(
                        self.forward_data_to_tunnel(connection_no))  # From current connection to WebRTC connection
                    self.logger.debug(
                        f"Endpoint {self.pc.endpoint_name}: Started reader for connection {connection_no}")
                except ConnectionNotFoundException as e:
                    self.logger.debug(f"Endpoint {self.vendpoint_name}: Connection {connection_no} not found: {e}")
                except Exception as e:
                    self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error in forwarding data task: {e}")
            else:
                self.logger.error(f"Endpoint {self.pc.endpoint_name}: Invalid open connection message")
        elif message_no == ControlMessage.SendEOF:
            if len(data) >= CONNECTION_NO_LENGTH:
                con_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                if con_no in self.connections:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Sending EOF to {con_no}')
                    self.connections[con_no].writer.write_eof()
                else:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: EOF for Connection {con_no} not found')
        else:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name} Unknown tunnel control message: {message_no}')

    async def forward_data_to_local(self):
        """
        Forward data from WebRTC connection to the appropriate local connection based on connection_no.
        Packet structure
         Control Packets [CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + CONTROL_MESSAGE_NO_LENGTH + DATA]
         Data Packets [CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + DATA]
        """
        try:
            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Forwarding data to local...")
            buff = b''
            while not self.kill_server_event.is_set():
                if self.pc.closed:
                    self.kill_server_event.set()
                    break
                while len(buff) >= CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH:
                    connection_no = int.from_bytes(buff[:CONNECTION_NO_LENGTH], byteorder='big')
                    time_stamp = int.from_bytes(
                        buff[CONNECTION_NO_LENGTH:CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH], byteorder='big')
                    length = int.from_bytes(
                        buff[CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH:
                             CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH], byteorder='big')
                    if len(buff) >= CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length + len(TERMINATOR):
                        if (buff[(CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length):
                            (CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length + len(TERMINATOR))] !=
                                TERMINATOR):
                            self.logger.warning(f'Endpoint {self.pc.endpoint_name}: Invalid terminator')
                            # if we don't have a valid terminator then we don't know where the message ends or begins
                            self.kill_server_event.set()
                            break
                        self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Buffer data received data')
                        send_data = (buff[CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH:
                                     CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length])
                        self.update_stats(connection_no, len(send_data) + CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH +
                                          DATA_LENGTH, time_stamp)
                        buff = buff[CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length + len(TERMINATOR):]

                        if connection_no == 0:
                            # This is a control message
                            control_m = ControlMessage(int.from_bytes(send_data[:CONTROL_MESSAGE_NO_LENGTH],
                                                                      byteorder='big'))

                            send_data = send_data[CONTROL_MESSAGE_NO_LENGTH:]

                            await self.process_control_message(control_m, send_data)
                        else:
                            if connection_no not in self.connections:
                                self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Connection not found: "
                                                  f"{connection_no}")
                                continue

                            try:
                                self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Forwarding data to "
                                                  f"local for connection {connection_no} ({len(send_data)})")
                                self.connections[connection_no].writer.write(send_data)
                                await self.connections[connection_no].writer.drain()
                                # Yield control back to the event loop for other tasks to execute
                                await asyncio.sleep(0)
                            except Exception as ex:
                                self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while forwarding "
                                                  f"data to local: {ex}")

                                # Yield control back to the event loop for other tasks to execute
                                await asyncio.sleep(0)
                    else:
                        self.logger.debug(
                            f"Endpoint {self.pc.endpoint_name}: Buffer is too short {len(buff)} need "
                            f"{CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length + len(TERMINATOR)}")
                        # Yield control back to the event loop for other tasks to execute
                        await asyncio.sleep(0)
                        break
                if self.kill_server_event.is_set():
                    break
                try:
                    data = await asyncio.wait_for(self.pc.web_rtc_queue.get(), READ_TIMEOUT)
                except asyncio.TimeoutError as et:
                    if self._ping_attempt > 3:
                        if self.is_connected:
                            self.kill_server_event.set()
                        raise et
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Tunnel reader timed out')
                    if self.is_connected and self.pc.is_data_channel_open():
                        self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Send ping request')
                        await self.send_control_message(ControlMessage.Ping, int_to_bytes(0))

                        if self.logger.level == logging.DEBUG:
                            # print the stats
                            for c in self.connections.keys():
                                self.report_stats(c)
                        self._ping_attempt += 1
                    continue
                self.pc.web_rtc_queue.task_done()
                if not data or not self.is_connected:
                    self.logger.info(f"Endpoint {self.pc.endpoint_name}: Exiting forward data to local")
                    break
                elif len(data) == 0:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
                    continue
                elif isinstance(data, bytes):
                    self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Got data from WebRTC connection "
                                      f"{len(data)} bytes")
                    buff += data
                else:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)

            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Exiting forward data successfully.")
        except asyncio.CancelledError:
            pass

        except Exception as ex:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while forwarding data: {ex}")

        finally:
            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Closing tunnel")
            await self.stop_server(CloseConnectionReasons.Normal)

    async def start_reader(self):  # type: () -> None
        """
        Transfer data from WebRTC connection to local connections.
        """
        failed = False
        try:
            # From WebRTC server to local connections
            self.to_local_task = asyncio.create_task(self.forward_data_to_local())

            # Send hello world open connection message
            await self.send_control_message(ControlMessage.Ping, int_to_bytes(0))
            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Sent ping message to WebRTC connection")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while establishing WebRTC connection: {e}")
            failed = True
        finally:
            if failed:
                self.kill_server_event.set()
                self.is_connected = False
            return

    async def forward_data_to_tunnel(self, con_no):
        """
        Forward data from the given connection to the WebRTC connection
        """
        try:
            while not self.kill_server_event.is_set():
                c = self.connections.get(con_no)
                if c is None or not self.is_connected:
                    break
                try:
                    data = await c.reader.read(BUFFER_TRUNCATION_THRESHOLD)
                    self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Forwarding {len(data)} "
                                      f"bytes to tunnel for connection {con_no}")
                    if not data:
                        self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Connection {con_no} no data")
                        break
                    if isinstance(data, bytes):
                        if c.reader.at_eof() and len(data) == 0:
                            if not self.eof_sent:
                                await self.send_control_message(ControlMessage.SendEOF,
                                                                int_to_bytes(con_no, CONNECTION_NO_LENGTH))
                                self.eof_sent = True
                            # Yield control back to the event loop for other tasks to execute
                            await asyncio.sleep(0)
                            continue
                        else:
                            self.eof_sent = False
                            buffer = int.to_bytes(con_no, CONNECTION_NO_LENGTH, byteorder='big')
                            # Add timestamp
                            timestamp_ms = int(datetime.now().timestamp() * 1000)
                            buffer += int.to_bytes(timestamp_ms, TIME_STAMP_LENGTH, byteorder='big')
                            buffer += int.to_bytes(len(data), DATA_LENGTH, byteorder='big') + data + TERMINATOR
                            self.connections[con_no].transfer_size += len(buffer)
                            await self.send_to_web_rtc(buffer)

                            self.logger.debug(
                                f'Endpoint {self.pc.endpoint_name}: buffer size: {self.pc.data_channel.bufferedAmount}' +
                                f', time since start: {datetime.now() - c.start_time}')

                            c.message_counter += 1
                            if (c.message_counter >= MESSAGE_MAX and
                                    self.pc.data_channel.bufferedAmount > BUFFER_TRUNCATION_THRESHOLD):
                                c.ping_time = time.perf_counter()
                                await self.send_control_message(ControlMessage.Ping, int_to_bytes(con_no))
                                self._ping_attempt += 1
                                wait_count = 0
                                while c.message_counter >= MESSAGE_MAX:
                                    await asyncio.sleep(wait_count)
                                    wait_count += .1
                            elif (c.message_counter >= MESSAGE_MAX and
                                  self.pc.data_channel.bufferedAmount <= BUFFER_TRUNCATION_THRESHOLD):
                                c.message_counter = 0

                    else:
                        # Yield control back to the event loop for other tasks to execute
                        await asyncio.sleep(0)
                except Exception as e:
                    self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Connection '{con_no}' read failed: {e}")
                    break
        except Exception as e:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while forwarding data in connection "
                              f"{con_no}: {e}")

        if con_no not in self.connections:
            raise ConnectionNotFoundException(f"Connection {con_no} not found")

        # Send close connection message with con_no
        buff = int.to_bytes(con_no, CONNECTION_NO_LENGTH, byteorder='big')
        buff += int_to_bytes(CloseConnectionReasons.Normal.value)
        await self.send_control_message(ControlMessage.CloseConnection, buff)
        await self.close_connection(con_no, CloseConnectionReasons.Normal)

    async def handle_connection(self, reader, writer):  # type: (asyncio.StreamReader, asyncio.StreamWriter) -> None
        """
        This is called when a client connects to the local port starting a new session.
        """
        connection_no = self.connection_no
        self.connection_no += 1
        self.connections[connection_no] = ConnectionInfo(reader, writer, 0, None, None, datetime.now())
        self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Created local connection {connection_no}")

        # Send open connection message with con_no. this is required to be sent to start the connection
        await self.send_control_message(ControlMessage.OpenConnection,
                                        int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big'))

    async def start_server(self):  # type: (...) -> None
        """
        This server is used to listen for client connections to the local port.
        """
        if self.server:
            return
        if not self._port:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: No open ports found for local server")
            self.kill_server_event.set()
            return

        try:
            self.server = await asyncio.start_server(self.handle_connection, family=socket.AF_INET, host=self.host,
                                                     port=self._port)
            async with self.server:
                await self.server.serve_forever()
        except ConnectionRefusedError as er:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Connection Refused while starting server: {er}")
        except OSError as er:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: OS Error while starting server: {er}")
        except Exception as e:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while starting server: {e}")
        finally:
            if self.server is not None:
                self.server.close()
                try:
                    await asyncio.wait_for(self.server.wait_closed(), timeout=5.0)
                except asyncio.TimeoutError:
                    self.logger.warning(
                        f"Endpoint {self.pc.endpoint_name}: Timed out while trying to close server")
            self.kill_server_event.set()
            return

    async def stop_server(self, reason: CloseConnectionReasons):
        if self.closing:
            return

        self.closing = True
        if len(self.connections) > 1:
            for i in range(1, len(self.connections)):
                await self.close_connection(i, reason)

        try:
            buffer = int.to_bytes(0, CONNECTION_NO_LENGTH)
            buffer += int.to_bytes(reason.value, CLOSE_CONNECTION_REASON_LENGTH, byteorder='big')
            await self.send_control_message(ControlMessage.CloseConnection, buffer)
            await self.close_connection(0, reason)
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception sending Close connection {ex}')

        if self.kill_server_event is not None:
            if not self.kill_server_event.is_set():
                self.kill_server_event.set()
        try:
            # close aiortc data channel
            await self.pc.close_webrtc_connection()
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception closing data channel {ex}')

        try:
            self.server.close()
            await asyncio.wait_for(self.server.wait_closed(), timeout=5.0)
            self.server = None
        except asyncio.TimeoutError:
            self.logger.warning(
                f"Endpoint {self.pc.endpoint_name}: Timed out while trying to close server")
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception closing server {ex}')

        try:
            if self.connect_task is not None:
                self.connect_task.cancel()
        finally:
            self.logger.info(f"Endpoint {self.pc.endpoint_name}: Tunnel stopped")

    async def close_connection(self, connection_no, reason: CloseConnectionReasons):
        # print the stats
        self.report_stats(connection_no)
        try:
            buffer = int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big')
            buffer += int_to_bytes(reason.value)
            await self.send_control_message(ControlMessage.CloseConnection, buffer)
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception sending Close connection {ex}')

        if connection_no in self.connections.keys() and connection_no != 0:
            try:
                self.connections[connection_no].writer.close()
                # Wait for it to actually close.
                await asyncio.wait_for(self.connections[connection_no].writer.wait_closed(), timeout=5.0)
            except asyncio.TimeoutError:
                self.logger.warning(
                    f"Endpoint {self.pc.endpoint_name}: Timed out while trying to close connection "
                    f"{connection_no}")
            except Exception as ex:
                self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception closing connection {ex}')

            try:
                # clean up reader
                if self.connections[connection_no].reader is not None:
                    self.connections[connection_no].reader.feed_eof()
                    self.connections[connection_no].reader = None
            except Exception as ex:
                self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception closing reader {ex}')

            if connection_no in self.connections:
                try:
                    if self.connections[connection_no].to_tunnel_task is not None:
                        self.connections[connection_no].to_tunnel_task.cancel()
                except Exception as ex:
                    self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception canceling tasks {ex}')
                try:
                    del self.connections[connection_no]
                except Exception as ex:
                    self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception deleting connection {ex}')
            self.logger.info(f"Endpoint {self.pc.endpoint_name}: Closed connection {connection_no}")
        elif connection_no == 0:
            self.logger.info(f"Endpoint {self.pc.endpoint_name}: Closed control connection")
            try:
                del self.connections[connection_no]
            except Exception as ex:
                self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception deleting connection {ex}')
        else:
            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Connection {connection_no} not found")
