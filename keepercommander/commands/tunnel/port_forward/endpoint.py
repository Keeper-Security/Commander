import abc
import asyncio
import enum
import logging
import os
import secrets
import socket
import string
import time
from typing import Optional, Dict, Tuple, Any, List, Union, Sequence

from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer, RTCDataChannel
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.utils import int_to_bytes
from keeper_secrets_manager_core.utils import bytes_to_base64

from keepercommander.display import bcolors
from .tunnel import ITunnel

PRIVATE_BUFFER_TRUNCATION_THRESHOLD = 1400
READ_TIMEOUT = 10
PUBLIC_READ_TIMEOUT = 60
NON_PARED_READ_TIMEOUT = 5
CONTROL_MESSAGE_NO_LENGTH = HMAC_MESSAGE_LENGTH = 2
CONNECTION_NO_LENGTH = DATA_LENGTH = 4
LATENCY_COUNT = 5
NONCE_LENGTH = 12
SYMMETRIC_KEY_LENGTH = RANDOM_LENGTH = 32
TERMINATOR = b';'
FORWARDER_BUFFER_TRUNCATION_THRESHOLD = (CONNECTION_NO_LENGTH + DATA_LENGTH + PRIVATE_BUFFER_TRUNCATION_THRESHOLD
                                         + len(TERMINATOR))


class ConnectionNotFoundException(Exception):
    pass


class ControlMessage(enum.IntEnum):
    Ping = 1
    Pong = 2
    ShareWebRTCDescription = 11
    OpenConnection = 101
    CloseConnection = 102


def track_round_trip_latency(round_trip_latency, ping_time):  # type: (List[Any], float) -> List[float]
    time_now = time.perf_counter()
    if len(round_trip_latency) >= LATENCY_COUNT:
        round_trip_latency.pop(0)
    # from the time the ping was sent to the time the pong was received
    latency = time_now - ping_time
    # Store in milliseconds
    round_trip_latency.append(latency * 1000)
    return round_trip_latency


def calc_round_trip_latency_average(round_trip_latency):  # type: (Sequence[Union[float, int]]) -> float
    return sum(round_trip_latency) / len(round_trip_latency)
    # self.logger.debug(f'Endpoint {self.endpoint_name}: Private round trip latency average: {average_latency}')


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


def find_server_public_key(raw_public_key: bytes):
    try:
        # Gateway public keys use the P-256 curve, so we need to use the same curve
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_public_key)
    except Exception as e:
        logging.error(f"Error while loading public key: {e}")
        return None


class TunnelProtocol(abc.ABC):
    """
    This class is used to set up the public tunnel entrance. This is used for the signaling phase and control messages.

    The public tunnel is encrypted using a Private key out of the record and the gateway's public key.
    This tunnel is used to send control messages to the gateway: Ping, Pong, CloseConnection
    and ShareWebRTCDescription.
      There isn't a need for open connection because we send a start command in the discoveryrotation.py file.
      There is one connection or channel, 0 for control messages. We have the ability to add more channels if needed


    The private tunnel uses WebRTC to connect to a peer on the gateway.

    The flow is as follows:
                                The public tunnel Part I
       0. User enters a command to start a tunnel
       1. Commander sends a start command to the gateway through krouter
       2. Commander starts the public tunnel entrance and listens for messages from krouter
        2.5. The Gateway: starts the public tunnel exit, listens for messages from krouter
       3. There are ping and pong messages to keep the connection alive, and CloseConnection will close everything.
            These are all encrypted using the private key and the gateway's public key.

                                Signaling Phase
       4. Commander: makes a WebRTC peer, makes and offer, and sets its setLocalDescription. This offer gets send to the
            gateway through the public tunnel using a ShareWebRTCDescription message.
       5. The Gateway gets that sets its setRemoteDescription and makes an answer. This answer gets sent back to
            Commander in a ShareWebRTCDescription message.
       6. Commander sets its setRemoteDescription to the answer it got from the gateway and the two peers connect using
            STUN and TURN servers.

                                Setting up the private tunnel
       7. Commander sets up a local server that listens for connections to a
          local port that the user has provided or a random port if none is provided.
       8. Commander sends a private ping message through the private tunnel entrance to the private tunnel exit
       9. The Gateway: receives the private ping message and sends a private pong message back establishing the
          connection
       10. Commander waits for a client to connect to the local server.

                                User connects to the target host and port
       11. Client connects to the private tunnel's local server.
       12. Private Tunnel Entrance (In Commander) sends an open connection message to the WebRTC connection and listens
            to the client forwarding on any data
       13. Private Tunnel Exit (On The Gateway): receives the open connection message and connects to the target
           host and port sending any data back to the WebRTC connection
       14. The session goes on until the CloseConnection message is sent, or the outer tunnel is closed.
       15. The User can repeat steps 10-14 as many times as they want

                              User closes the public tunnel
      16. The User closes the public tunnel and everything is cleaned up, and we can start back at step 1
    """
    def __init__(self, tunnel,                    # type: ITunnel
                 endpoint_name = None,            # type: Optional[str]
                 logger = None,                   # type: logging.Logger
                 gateway_public_key_bytes = None, # type: bytes
                 client_private_key = "",         # type: str
                 host = "127.0.0.1",              # type: str
                 port = None,                     # type: int
                 ):                               # type: (...) -> None
        self.symmetric_key_aesgcm = None
        self.hmac_message = generate_random_bytes()
        self._round_trip_latency = []
        self.ping_time = None
        self.tunnel = tunnel
        self.endpoint_name = endpoint_name
        self.logger = logger
        self.target_port = port
        self.target_host = host
        self.private_tunnel = None
        self._ping_attempt = 0
        self.private_tunnel_server = None
        self.kill_server_event = asyncio.Event()
        self.gateway_public_key_bytes = gateway_public_key_bytes
        """
# Generate an EC private key
private_key = ec.generate_private_key(
    ec.SECP256R1(),  # Using P-256 curve
    backend=default_backend()
)
# Serialize to PEM format
private_key_str = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')
        """

        self.client_private_key_pem = serialization.load_pem_private_key(
            client_private_key.encode(),
            password=None,
            backend=default_backend()
        )
        self.server_public_key = None
        self.web_rtc_queue = asyncio.Queue()
        self.tunnel_ready = asyncio.Event()

        # Define the STUN server URL
        # stun_url = "stun:stun.l.google.com:19302"

        relay_url = 'relaybeta.keeperpamlab.com'
        stun_url = f"stun:{relay_url}:3478"

        # Create an RTCIceServer instance for the STUN server
        stun_server = RTCIceServer(urls=stun_url)

        # Define the TURN server URL and credentials
        # The transport parameter in the TURN server configuration (such as UDP, TCP, TLS, or DTLS) specifies the
        # protocol used for the connection between the peers and the TURN server.
        # Peer-to-peer communication through the TURN server is still DTLS encrypted end to end.
        turn_url = f"turn:{relay_url}:3478?transport=udp"
        '''
        # Define TURN server credentials
        username = "your_username"
        password = "your_password"
        
        # Define the TURN server URL with credentials
        
        # Create an RTCIceServer instance for the TURN server with credentials
        turn_server = RTCIceServer(urls=turn_url, username=username, credential=password)
        '''

        # Create an RTCIceServer instance for the TURN server
        turn_server = RTCIceServer(urls=turn_url)

        # Create a new RTCConfiguration with both STUN and TURN servers
        config = RTCConfiguration(iceServers=[stun_server, turn_server])

        self.pc = RTCPeerConnection(config)
        self.data_channel = self.pc.createDataChannel("chat", ordered=True, maxPacketLifeTime=None, maxRetransmits=None)

        def on_data_channel_open():
            self.logger.debug("Data channel opened")
            data = b''
            buffer = int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big')
            length = CONTROL_MESSAGE_NO_LENGTH + len(data)
            buffer += int.to_bytes(length, DATA_LENGTH, byteorder='big')
            buffer += int.to_bytes(ControlMessage.Ping, CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
            buffer += data + TERMINATOR
            self.data_channel.send(buffer)

        def on_data_channel_message(message):
            self.web_rtc_queue.put_nowait(message)

        def on_data_channel(channel):
            channel.on("open", on_data_channel_open)
            channel.on("message", on_data_channel_message)
            self.tunnel_ready.set()

        def on_connection_state_change():
            self.logger.debug(f"Connection State has changed: {self.pc.connectionState}")

            if self.pc.connectionState == "connected":
                # Connection is established, you can now send/receive data
                pass
            elif self.pc.connectionState == "connecting":
                pass
            elif self.pc.connectionState in ["disconnected", "failed", "closed"]:
                # Handle disconnection or failure here
                pass

        self.pc.on("datachannel", on_data_channel)

        self.pc.on("connectionstatechange", on_connection_state_change)

    def establish_symmetric_key(self):
        # Step 3: Perform ECDH key agreement
        shared_secret = self.client_private_key_pem.exchange(ec.ECDH(), self.server_public_key)

        # Step 4: Derive a symmetric key using HKDF
        symmetric_key = HKDF(
            algorithm=hashes.SHA256(),
            length=SYMMETRIC_KEY_LENGTH,
            salt=None,
            info=b'encrypt network traffic',
        ).derive(shared_secret)
        self.symmetric_key_aesgcm = AESGCM(symmetric_key)

    def tunnel_encrypt(self, data: bytes):
        """ Encrypts data using the symmetric key """
        nonce = os.urandom(NONCE_LENGTH)  # 12-byte nonce for AES-GCM
        d = nonce + self.symmetric_key_aesgcm.encrypt(nonce, data, None)
        return bytes_to_base64(d)

    def tunnel_decrypt(self, encrypted_data: bytes):
        """ Decrypts data using the symmetric key """
        if len(encrypted_data) <= NONCE_LENGTH:
            self.logger.error(f'Endpoint {self.endpoint_name}: Invalid encrypted data')
            return None
        nonce = encrypted_data[:NONCE_LENGTH]
        data = encrypted_data[NONCE_LENGTH:]
        try:
            return self.symmetric_key_aesgcm.decrypt(nonce, data, None)
        except Exception as e:
            self.logger.error(f'Endpoint {self.endpoint_name}: Failed to decrypt data: {e}')
            return None

    async def connect(self):
        if not self.tunnel.is_connected:
            await self.tunnel.connect()

        self.server_public_key = find_server_public_key(self.gateway_public_key_bytes)

        if self.server_public_key is None:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Invalid public key')
            await self.disconnect()
            raise Exception('Invalid public key')

        self.establish_symmetric_key()

        t1 = asyncio.create_task(self.start_tunnel_reader())
        tasks = [t1]
        self.logger.debug(f'Endpoint {self.endpoint_name}: Private tunnel started, sending HMAC to gateway')

        # Create an offer
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)

        # Send the offer to the server
        await self.send_control_message(ControlMessage.ShareWebRTCDescription,
                                        self.pc.localDescription.sdp.encode('utf-8'))

        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        await self.disconnect()

    async def disconnect(self):
        try:
            await self.send_control_message(ControlMessage.CloseConnection)
        finally:
            tasks = []
        try:
            self.tunnel.disconnect()
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception closing tunnel {ex}')
        try:
            if self.private_tunnel:
                tasks.append(self.private_tunnel.stop_server())
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception closing private tunnel {ex}')
        try:
            if len(tasks) > 0:
                await asyncio.gather(*tasks)
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception gathering tasks {ex}')

        self.kill_server_event.set()

    async def start_tunnel_reader(self) -> None:
        if not self.tunnel.is_connected:
            self.logger.warning(f'Endpoint {self.endpoint_name}: Tunnel reader: not connected')
            return

        self._ping_attempt = 0
        buff = b''
        '''
        Data structure of a packet
        +----------------------+----------------+---------------------------------+-------------+
        | Connection Number    | Data Length    | Data                            | Terminator  |
        | (4 bytes)            | (4 bytes)      | (variable length)               | (variable)  |
        +----------------------+----------------+---------------------------------+-------------+
        |                      |                |                                 |             |
        |       0 (for         |                | +-------------------+---------+ |             |
        |    control message)  |                | | Control Message   | Control | |             |
        |                      |                | | Number (2 bytes)  | Data    | |             |
        |                      |                | +-------------------+---------+ |             |
        |                      |                |                                 |             |
        +----------------------+----------------+---------------------------------+-------------+

        Breakdown of Each Part:
            Connection Number (4 bytes):
                This is the first part of the message.
                It's used to identify which type of message is being sent.
                In your code, a connection number of 0 signifies a control message.
            Data Length (4 bytes):
                This follows the connection number.
                It specifies the length of the actual data in bytes that follows this field.
            Data (variable length):
                The content of the message.
                Its length is determined by the "Data Length" field.
                For control messages, it further contains a control message number and the actual control data.
            Terminator (variable):
                Marks the end of the message.
                Check for this terminator to validate the end of a message.
                If the terminator is not found or is incorrect, it indicates a message boundary error.
        '''
        while self.tunnel.is_connected and not self.kill_server_event.is_set():
            if len(buff) >= CONNECTION_NO_LENGTH + DATA_LENGTH:
                # At this stage we have two connections. 0 is for control messages and 1 is for data
                connection_no = int.from_bytes(buff[:CONNECTION_NO_LENGTH], byteorder='big')
                length = int.from_bytes(buff[CONNECTION_NO_LENGTH:CONNECTION_NO_LENGTH + DATA_LENGTH],
                                        byteorder='big')
                # Wait for the rest of the data if it hasn't arrived yet
                if len(buff) >= CONNECTION_NO_LENGTH + DATA_LENGTH + length + len(TERMINATOR):
                    if buff[CONNECTION_NO_LENGTH + DATA_LENGTH + length:
                            CONNECTION_NO_LENGTH + DATA_LENGTH + length + len(TERMINATOR)] != TERMINATOR:
                        self.logger.warning(f'Endpoint {self.endpoint_name}: Invalid terminator')
                        # if we don't have a valid terminator then we don't know where the message ends or begins
                        break
                    s_data = buff[CONNECTION_NO_LENGTH + DATA_LENGTH: CONNECTION_NO_LENGTH + DATA_LENGTH + length]
                    buff = buff[CONNECTION_NO_LENGTH + DATA_LENGTH + length + len(TERMINATOR):]
                    if connection_no == 0:
                        # This is a control message
                        if len(s_data) >= CONTROL_MESSAGE_NO_LENGTH:
                            message_no = int.from_bytes(s_data[:CONTROL_MESSAGE_NO_LENGTH], byteorder='big')
                            s_data = s_data[CONTROL_MESSAGE_NO_LENGTH:]
                            await self.process_control_message(ControlMessage(message_no), s_data)
                    else:
                        # We have the ability to add more channels in the future if needed
                        self.logger.error(f"Endpoint {self.endpoint_name}: Invalid Public channel {connection_no}")
                        break
                else:
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Buffer is too short {len(buff)} need  "
                                      f"{CONNECTION_NO_LENGTH + DATA_LENGTH + length + len(TERMINATOR)}")
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
            else:
                # Yield control back to the event loop for other tasks to execute
                await asyncio.sleep(0)
            try:
                buffer = await self.tunnel.read(PUBLIC_READ_TIMEOUT)
                self.logger.debug(f"Endpoint {self.endpoint_name}: Received data from tunnel: {len(buffer)}")
                if isinstance(buffer, bytes):
                    decrypt_data = self.tunnel_decrypt(buffer)
                    buff += decrypt_data
                else:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
            except asyncio.TimeoutError as e:
                if self._ping_attempt > 3:
                    if self.tunnel.is_connected:
                        self.tunnel.disconnect()
                    raise e
                self.logger.debug(f'Endpoint {self.endpoint_name}: Tunnel reader timed out')
                self.logger.debug(f'Endpoint {self.endpoint_name}: Send ping request')
                self.ping_time = time.perf_counter()
                await self.send_control_message(ControlMessage.Ping)
                self._ping_attempt += 1
                continue
            except Exception as e:
                self.logger.warning(f'Endpoint {self.endpoint_name}: Failed to read from tunnel: {e}')
                break

            if not self.tunnel.is_connected:
                self.logger.info(f'Endpoint {self.endpoint_name}: Exiting public tunnel reader.')
                break

            if not isinstance(buffer, bytes):
                continue
        self.logger.info(f'Endpoint {self.endpoint_name}: Exiting public tunnel reader.')
        await self.disconnect()

    async def _send_to_tunnel(self, connection_no, data):  # type: (int, bytes) -> None
        buffer = int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big')
        buffer += int.to_bytes(len(data), DATA_LENGTH, byteorder='big')
        buffer += data + TERMINATOR
        buffer = self.tunnel_encrypt(buffer)
        self.logger.debug(f"Sending data to tunnel: {len(buffer)}")
        await self.tunnel.write(buffer)
        # Yield control back to the event loop for other tasks to execute
        await asyncio.sleep(0)

    async def send_control_message(self, message_no: ControlMessage, data: Optional[bytes] = None) -> None:
        buffer = int.to_bytes(message_no, CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
        buffer += data if data is not None else b''
        # Control messages are sent through connection 0
        await self._send_to_tunnel(0, buffer)

    async def process_control_message(self, message_no, data):  # type: (ControlMessage, bytes) -> None
        if message_no == ControlMessage.Ping:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Received ping request')
            self.logger.debug(f'Endpoint {self.endpoint_name}: Send pong request')
            await self.send_control_message(ControlMessage.Pong)
            self._ping_attempt = 0
        elif message_no == ControlMessage.Pong:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Received pong request')
            self._ping_attempt = 0
            if self.ping_time is not None:
                self._round_trip_latency = track_round_trip_latency(self._round_trip_latency, self.ping_time)
                self.logger.debug(f'Endpoint {self.endpoint_name}: Public round trip latency: '
                                  f'{self._round_trip_latency[-1]} ms')
                self.ping_time = None
        elif message_no == ControlMessage.ShareWebRTCDescription:
            if len(data[CONNECTION_NO_LENGTH:]) > 0:
                try:
                    await self.pc.setRemoteDescription(RTCSessionDescription(data[CONNECTION_NO_LENGTH:].decode(),
                                                                             "answer"))

                    self.logger.debug("starting private tunnel")

                    private_tunnel_event = asyncio.Event()

                    self.private_tunnel = PrivateTunnelEntrance(private_tunnel_event=private_tunnel_event,
                                                                host=self.target_host, port=self.target_port,
                                                                endpoint_name=self.endpoint_name,
                                                                kill_server_event=self.kill_server_event,
                                                                data_channel=self.data_channel,
                                                                incoming_queue=self.web_rtc_queue,
                                                                logger=self.logger)

                    private_tunnel_started = asyncio.Event()
                    self.private_tunnel_server = asyncio.create_task(self.private_tunnel.start_server(
                        private_tunnel_event, private_tunnel_started, self.tunnel_ready))
                    await private_tunnel_started.wait()

                    serving = self.private_tunnel.server.is_serving() if self.private_tunnel.server else False

                    if not serving:
                        self.logger.debug(f'Endpoint {self.endpoint_name}: Private tunnel failed to start')
                        await self.disconnect()
                        raise Exception('Private tunnel failed to start')

                except Exception as e:
                    self.logger.error(f"Error setting remote description: {e}")

        elif message_no == ControlMessage.CloseConnection:
            await self.disconnect()
        else:
            self.logger.info(f'Endpoint {self.endpoint_name}: Unknown control message {message_no}')


class PrivateTunnelEntrance:
    """
    This class is used to forward data between a WebRTC connection and a connection to a target.
    The Private Tunnel isn't connected to the public tunnel except that the public tunnel can close it.
    Connection 0 is reserved for control messages. All other connections are for when a client connects
    This private tunnel uses four control messages: Ping, Pong, OpenConnection and CloseConnection
    Data is broken into three parts: connection number, [message number], and data
    message number is only used in control messages. (if the connection number is 0 then there is a message number)
    """
    def __init__(self,
                 private_tunnel_event,          # type: asyncio.Event
                 host,                          # type: str
                 port,                          # type: int
                 endpoint_name,                 # type: str
                 kill_server_event,             # type: asyncio.Event
                 data_channel,                  # type: RTCDataChannel
                 incoming_queue,                # type: asyncio.Queue
                 logger = None,                 # type: logging.Logger
                 ):                             # type: (...) -> None
        self._round_trip_latency = []
        self.ping_time = None
        self.to_local_task = None
        self.private_tunnel_event = private_tunnel_event
        self._ping_attempt = 0
        self.host = host
        self.server = None
        self.connection_no = 1
        self.endpoint_name = endpoint_name
        self.connections: Dict[int, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self._port = port
        self.logger = logger
        self.is_connected = True
        self.reader_task = asyncio.create_task(self.start_reader())
        self.to_tunnel_tasks = {}
        self.kill_server_event = kill_server_event
        self.incoming_queue = incoming_queue
        self.data_channel = data_channel

    async def send_to_web_rtc(self, data):
        if self.data_channel.readyState == "open":
            self.data_channel.send(data)
            # Yield control back to the event loop for other tasks to execute
            await asyncio.sleep(0)
        else:
            print("Data channel is not open. Data not sent.")

    async def send_control_message(self, message_no, data = None):  # type: (ControlMessage, Optional[bytes]) -> None
        """
        Packet structure
         Control Message Packets [CONNECTION_NO_LENGTH + DATA_LENGTH + CONTROL_MESSAGE_NO_LENGTH + DATA]
        """
        data = data if data is not None else b''
        buffer = int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big')
        length = CONTROL_MESSAGE_NO_LENGTH + len(data)
        buffer += int.to_bytes(length, DATA_LENGTH, byteorder='big')
        buffer += int.to_bytes(message_no, CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
        buffer += data + TERMINATOR
        try:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Sending Control command {message_no} len: {len(buffer)}'
                              f' to tunnel.')
            await self.send_to_web_rtc(buffer)
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while sending private control message: {e}")

    async def process_control_message(self, message_no, data):  # type: (ControlMessage, Optional[bytes]) -> None
        if message_no == ControlMessage.CloseConnection:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Received private close connection request')
            if data and len(data) > 0:
                target_connection_no = int.from_bytes(data, byteorder='big')
                if target_connection_no == 0:
                    for c in list(self.connections):
                        await self.close_connection(c)
                else:
                    self.logger.debug(f'Endpoint {self.endpoint_name}: Closing private connection '
                                      f'{target_connection_no}')
                    await self.close_connection(target_connection_no)
        elif message_no == ControlMessage.Pong:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Received private pong request')
            self._ping_attempt = 0
            self.is_connected = True
            if self.ping_time is not None:
                self._round_trip_latency = track_round_trip_latency(self._round_trip_latency, self.ping_time)
                self.logger.debug(f'Endpoint {self.endpoint_name}: Private round trip latency: '
                                  f'{self._round_trip_latency[-1]} ms')
                self.ping_time = None
        elif message_no == ControlMessage.Ping:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Received private ping request')
            await self.send_control_message(ControlMessage.Pong)
        elif message_no == ControlMessage.OpenConnection:
            if len(data) >= CONNECTION_NO_LENGTH:
                if len(data) > CONNECTION_NO_LENGTH:
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Received invalid private open connection message"
                                      f" ({len(data)} bytes)")
                connection_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                self.logger.debug(f"Endpoint {self.endpoint_name}: Starting private reader for connection "
                                  f"{connection_no}")
                try:
                    self.to_tunnel_tasks[connection_no] = asyncio.create_task(
                        self.forward_data_to_tunnel(connection_no))  # From current connection to WebRTC connection
                    self.logger.debug(
                        f"Endpoint {self.endpoint_name}: Started private reader for connection {connection_no}")
                except ConnectionNotFoundException as e:
                    self.logger.error(f"Endpoint {self.endpoint_name}: Connection {connection_no} not found: {e}")
                except Exception as e:
                    self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding private data: {e}")
            else:
                self.logger.error(f"Endpoint {self.endpoint_name}: Invalid open connection message")
        else:
            self.logger.warning(f'Endpoint {self.endpoint_name} Unknown private tunnel control message: {message_no}')

    async def forward_data_to_local(self):
        """
        Forward data from WebRTC connection to the appropriate local connection based on connection_no.
        Packet structure
         Control Packets [CONNECTION_NO_LENGTH + DATA_LENGTH + CONTROL_MESSAGE_NO_LENGTH + DATA]
         Data Packets [CONNECTION_NO_LENGTH + DATA_LENGTH + DATA]
        """
        try:
            self.private_tunnel_event.set()
            self.logger.debug(f"Endpoint {self.endpoint_name}: Forwarding private data to local...")
            buff = b''
            should_exit = False
            while not self.kill_server_event.is_set() and not should_exit:
                while len(buff) >= CONNECTION_NO_LENGTH + DATA_LENGTH:
                    connection_no = int.from_bytes(buff[:CONNECTION_NO_LENGTH], byteorder='big')
                    length = int.from_bytes(buff[CONNECTION_NO_LENGTH:CONNECTION_NO_LENGTH+DATA_LENGTH],
                                            byteorder='big')
                    if len(buff) >= CONNECTION_NO_LENGTH + DATA_LENGTH + length + len(TERMINATOR):
                        if buff[CONNECTION_NO_LENGTH + DATA_LENGTH + length:
                                CONNECTION_NO_LENGTH + DATA_LENGTH + length + len(TERMINATOR)] != TERMINATOR:
                            self.logger.warning(f'Endpoint {self.endpoint_name}: Private Invalid terminator')
                            # if we don't have a valid terminator then we don't know where the message ends or begins
                            should_exit = True
                            break
                        self.logger.debug(f'Endpoint {self.endpoint_name}: Private buffer data received data')
                        send_data = buff[CONNECTION_NO_LENGTH + DATA_LENGTH:CONNECTION_NO_LENGTH + DATA_LENGTH + length]
                        buff = buff[CONNECTION_NO_LENGTH + DATA_LENGTH + length + len(TERMINATOR):]
                        if connection_no == 0:
                            # This is a control message
                            control_m = ControlMessage(int.from_bytes(send_data[:CONTROL_MESSAGE_NO_LENGTH],
                                                                      byteorder='big'))

                            send_data = send_data[CONTROL_MESSAGE_NO_LENGTH:]

                            await self.process_control_message(control_m, send_data)
                        else:
                            if connection_no not in self.connections:
                                self.logger.error(f"Endpoint {self.endpoint_name}: Private connection not found: "
                                                  f"{connection_no}")
                                continue

                            _, con_writer = self.connections[connection_no]
                            try:
                                self.logger.debug(f"Endpoint {self.endpoint_name}: Forwarding private data to "
                                                  f"local for connection {connection_no} ({len(send_data)})")
                                con_writer.write(send_data)
                                await con_writer.drain()
                                # Yield control back to the event loop for other tasks to execute
                                await asyncio.sleep(0)
                            except Exception as ex:
                                self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding "
                                                  f"private data to local: {ex}")

                                # Yield control back to the event loop for other tasks to execute
                                await asyncio.sleep(0)
                    else:
                        self.logger.debug(
                            f"Endpoint {self.endpoint_name}: Private buffer is too short {len(buff)} need "
                            f"{CONNECTION_NO_LENGTH + DATA_LENGTH + length + len(TERMINATOR)}")
                        # Yield control back to the event loop for other tasks to execute
                        await asyncio.sleep(0)
                        break
                try:
                    data = await asyncio.wait_for(self.incoming_queue.get(), READ_TIMEOUT)
                except asyncio.TimeoutError as et:
                    if self._ping_attempt > 3:
                        if self.is_connected:
                            await self.stop_server()
                        raise et
                    self.logger.debug(f'Endpoint {self.endpoint_name}: Private Tunnel reader timed out')
                    self.logger.debug(f'Endpoint {self.endpoint_name}: Send Private ping request')
                    self.ping_time = time.perf_counter()
                    await self.send_control_message(ControlMessage.Ping)
                    self._ping_attempt += 1
                    continue
                self.incoming_queue.task_done()
                if not data or not self.is_connected:
                    self.logger.info(f"Endpoint {self.endpoint_name}: Exiting forward private data to local")
                    break
                elif len(data) == 0:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
                    continue
                elif isinstance(data, bytes):
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Got private data from WebRTC connection "
                                      f"{len(data)} bytes)")
                    buff += data
                else:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)

            self.logger.debug(f"Endpoint {self.endpoint_name}: Exiting forward private data successfully.")
        except asyncio.CancelledError:
            pass

        except Exception as ex:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding private data: {ex}")

        finally:
            self.logger.debug(f"Endpoint {self.endpoint_name}: Closing private tunnel")
            await self.stop_server()

    async def start_reader(self):   # type: () -> None
        """
        Transfer data from WebRTC connection to local connections.
        """
        failed = False
        try:
            # From WebRTC server to local connections
            self.to_local_task = asyncio.create_task(self.forward_data_to_local())

            # Send hello world open connection message
            self.ping_time = time.perf_counter()
            await self.send_control_message(ControlMessage.Ping)
            self.logger.debug(f"Endpoint {self.endpoint_name}: Sent private ping message to WebRTC connection")
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while establishing WebRTC connection: {e}")
            failed = True
        finally:
            if failed:
                for connection_no in list(self.connections):
                    await self.close_connection(connection_no)
                await self.stop_server()
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
                reader, _ = c
                try:
                    data = await reader.read(PRIVATE_BUFFER_TRUNCATION_THRESHOLD)
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Forwarding private {len(data)} "
                                      f"bytes to tunnel for connection {con_no}")
                    if not data:
                        self.logger.debug(f"Endpoint {self.endpoint_name}: Connection {con_no} no data")
                        break
                    if isinstance(data, bytes):
                        if reader.at_eof() and len(data) == 0:
                            # Yield control back to the event loop for other tasks to execute
                            await asyncio.sleep(0)
                            continue
                        else:
                            buffer = int.to_bytes(con_no, CONNECTION_NO_LENGTH, byteorder='big')
                            buffer += int.to_bytes(len(data), DATA_LENGTH, byteorder='big') + data + TERMINATOR
                            await self.send_to_web_rtc(buffer)
                    else:
                        # Yield control back to the event loop for other tasks to execute
                        await asyncio.sleep(0)
                except Exception as e:
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Private connection '{con_no}' read failed: {e}")
                    break
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding private data in connection "
                              f"{con_no}: {e}")

        if con_no not in self.connections:
            raise ConnectionNotFoundException(f"Connection {con_no} not found")

        # Send close connection message with con_no
        await self.send_control_message(ControlMessage.CloseConnection, int.to_bytes(con_no, CONNECTION_NO_LENGTH,
                                                                                     byteorder='big'))
        await self.close_connection(con_no)

    async def handle_connection(self, reader, writer):  # type: (asyncio.StreamReader, asyncio.StreamWriter) -> None
        """
        This is called when a client connects to the local port starting a new session.
        """
        connection_no = self.connection_no
        self.connection_no += 1
        self.connections[connection_no] = (reader, writer)

        self.logger.debug(f"Endpoint {self.endpoint_name}: Created private local connection {connection_no}")

        # Send open connection message with con_no. this is required to be sent to start the connection
        await self.send_control_message(ControlMessage.OpenConnection,
                                        int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big'))

    async def start_server(self,
                           private_tunnel_event,    # type: asyncio.Event
                           private_tunnel_started,   # type: asyncio.Event
                           tunnel_ready             # type: asyncio.Event
                           ):                       # type: (...) -> None
        """
        This server is used to listen for client connections to the local port.
        """
        try:
            self._port = find_open_port(tried_ports=[], preferred_port=self._port, host=self.host)
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while finding open port: {e}")
            await self.print_not_ready()
            return
        try:
            self.server = await asyncio.start_server(self.handle_connection, family=socket.AF_INET, host=self.host,
                                                     port=self._port)
            async with self.server:
                private_tunnel_started.set()
                asyncio.create_task(self.print_ready(self.host, self._port, private_tunnel_event, tunnel_ready))
                await self.server.serve_forever()
        except ConnectionRefusedError as er:
            self.logger.error(f"Endpoint {self.endpoint_name}: Connection Refused while starting server: {er}")
            await self.print_not_ready()
            return
        except OSError as er:
            self.logger.error(f"Endpoint {self.endpoint_name}: OS Error while starting server: {er}")
            await self.print_not_ready()
            return
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while starting server: {e}")
            await self.print_not_ready()
            return

    async def print_not_ready(self):
        print(f'{bcolors.FAIL}+---------------------------------------------------------{bcolors.ENDC}')
        print(f'{bcolors.FAIL}| Endpoint {self.endpoint_name}{bcolors.ENDC} failed to start')
        print(f'{bcolors.FAIL}+---------------------------------------------------------{bcolors.ENDC}')
        await self.send_control_message(ControlMessage.CloseConnection, int_to_bytes(0))
        for c in list(self.connections):
            await self.close_connection(c)
        await self.stop_server()

    async def print_ready(self, host,           # type: str
                          port,                 # type: int
                          private_tunnel_event,  # type: asyncio.Event
                          tunnel_ready          # type: asyncio.Event
                          ):                    # type: (...) -> None
        """
        pretty prints the endpoint name and host:port after the tunnels are set up
        """
        try:
            await asyncio.wait_for(private_tunnel_event.wait(), timeout=60)
        except asyncio.TimeoutError:
            self.logger.debug(f"Endpoint {self.endpoint_name}: Timed out waiting for private tunnel to start")
            await self.print_not_ready()
            return

        if not self.server or not self.server.is_serving() if self.server else False:
            await self.print_not_ready()
            return

        try:
            await asyncio.wait_for(tunnel_ready.wait(), timeout=60)
        except asyncio.TimeoutError:
            self.logger.debug(f"Endpoint {self.endpoint_name}: Timed out waiting for private tunnel to start")
            await self.print_not_ready()
            return

        # Just sleep a little bit to print out last
        await asyncio.sleep(.5)
        host = host + ":" if host else ''
        print(f'{bcolors.OKGREEN}+---------------------------------------------------------{bcolors.ENDC}')
        print(
            f'{bcolors.OKGREEN}| Endpoint {bcolors.ENDC}{bcolors.OKBLUE}{self.endpoint_name}{bcolors.ENDC}'
            f'{bcolors.OKGREEN}: Listening on port: {bcolors.ENDC}'
            f'{bcolors.BOLD}{bcolors.OKBLUE}{host}{port}{bcolors.ENDC}')
        print(f'{bcolors.OKGREEN}+---------------------------------------------------------{bcolors.ENDC}')

    async def stop_server(self):
        try:
            await self.send_control_message(ControlMessage.CloseConnection, int_to_bytes(0))
            if self.server:
                self.server.close()
                await self.server.wait_closed()
                self.logger.debug(f"Endpoint {self.endpoint_name}: Local server stopped")
                self.server = None
            if self.reader_task:
                self.reader_task.cancel()
            for t in list(self.to_tunnel_tasks):
                self.to_tunnel_tasks[t].cancel()
            if self.to_local_task:
                self.to_local_task.cancel()
        finally:
            self.kill_server_event.set()

    async def close_connection(self, connection_no):
        try:
            await self.send_control_message(ControlMessage.CloseConnection,
                                            int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big'))
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception sending Close connection {ex}')

        if connection_no in self.connections:
            reader, writer = self.connections[connection_no]
            writer.close()
            # Wait for it to actually close.
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
            except asyncio.TimeoutError:
                self.logger.warning(
                    f"Endpoint {self.endpoint_name}: Timed out while trying to close Private connection "
                    f"{connection_no}")

            del self.connections[connection_no]
            self.logger.info(f"Endpoint {self.endpoint_name}: Closed Private connection {connection_no}")
        else:
            self.logger.info(f"Endpoint {self.endpoint_name}: Private Connection {connection_no} not found")
        if connection_no in self.to_tunnel_tasks:
            try:
                self.to_tunnel_tasks[connection_no].cancel()
            except Exception as ex:
                self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception canceling private tasks {ex}')
            del self.to_tunnel_tasks[connection_no]
            self.logger.info(f"Endpoint {self.endpoint_name}: Tasks closed for Private connection {connection_no}")
        else:
            self.logger.info(f"Endpoint {self.endpoint_name}: Private tasks for {connection_no} not found")
