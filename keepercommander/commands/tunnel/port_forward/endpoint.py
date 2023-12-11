import asyncio
import enum
import logging
import os
import secrets
import socket
import string
import time
from typing import Optional, Dict, Tuple

from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.utils import int_to_bytes
from keeper_secrets_manager_core.utils import bytes_to_base64, base64_to_bytes, bytes_to_string

from keepercommander.display import bcolors

logging.getLogger('aiortc').setLevel(logging.WARNING)
logging.getLogger('aioice').setLevel(logging.WARNING)

BUFFER_TRUNCATION_THRESHOLD = 1400
READ_TIMEOUT = 10
CONTROL_MESSAGE_NO_LENGTH = 2
CONNECTION_NO_LENGTH = DATA_LENGTH = 4
LATENCY_COUNT = 5
NONCE_LENGTH = 12
SYMMETRIC_KEY_LENGTH = RANDOM_LENGTH = 32
TERMINATOR = b';'


class ConnectionNotFoundException(Exception):
    pass


class ControlMessage(enum.IntEnum):
    Ping = 1
    Pong = 2
    OpenConnection = 101
    CloseConnection = 102
    ConnectionOpened = 103


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
    def __init__(self, endpoint_name: Optional[str] = "Keeper PAM Tunnel",
                 print_ready_event: Optional[asyncio.Event] = None, username: Optional[str] = None,
                 password: Optional[str] = None, logger: Optional[logging.Logger] = None):
        self.web_rtc_queue = asyncio.Queue()
        self.closed = False
        self.data_channel = None
        self.print_ready_event = print_ready_event

        # Define the STUN server URL
        # To use Google's STUN server
        '''
        stun_url = "stun:stun.l.google.com:19302"
        # Create an RTCIceServer instance for the TURN server
        turn_server = RTCIceServer(urls=turn_url)
        config = RTCConfiguration(iceServers=[stun_server])
        '''

        # Using Keeper's STUN and TURN servers
        # relay_url = 'relay.' + params.server  + '3478'  # relay.dev.keepersecurity.com:3478
        relay_url = 'relay.keeperpamlab.com'
        stun_url = f"stun:{relay_url}:3478"
        # Create an RTCIceServer instance for the STUN server
        stun_server = RTCIceServer(urls=stun_url)
        # Define the TURN server URL and credentials
        turn_url = f"turn:{relay_url}?transport=udp"
        # Create an RTCIceServer instance for the TURN server with credentials
        turn_server = RTCIceServer(urls=turn_url, username=username, credential=password)
        # Create a new RTCConfiguration with both STUN and TURN servers
        config = RTCConfiguration(iceServers=[stun_server, turn_server])

        self._pc = RTCPeerConnection(config)
        self.setup_data_channel()
        self.setup_event_handlers()
        self.logger = logger
        self.endpoint_name = endpoint_name

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

        self.logger.debug("Data channel opened")
        data = b''
        buffer = int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big')
        length = CONTROL_MESSAGE_NO_LENGTH + len(data)
        buffer += int.to_bytes(length, DATA_LENGTH, byteorder='big')
        buffer += int.to_bytes(ControlMessage.Ping, CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
        buffer += data + TERMINATOR
        self.data_channel.send(buffer)
        self.logger.error(f'Endpoint {self.endpoint_name}: Data channel opened')

    def on_data_channel_message(self, message):
        self.web_rtc_queue.put_nowait(message)

    def on_data_channel(self, channel):
        channel.on("open", self.on_data_channel_open)
        channel.on("message", self.on_data_channel_message)

    def on_connection_state_change(self):
        self.logger.debug(f'Endpoint {self.endpoint_name}: Connection State has changed: {self._pc.connectionState}')
        if self._pc.connectionState == "connected":
            # Connection is established, you can now send/receive data
            pass
        elif self._pc.connectionState in ["disconnected", "failed", "closed"]:
            # Handle disconnection or failure here
            pass

    def is_data_channel_open(self):
        return (self.data_channel is not None and self.data_channel.readyState == "open"
                and self._pc.connectionState == "connected")

    # Example usage of state check in a method
    def send_message(self, message):
        if self.is_data_channel_open():
            self.data_channel.send(message)
        else:
            self.logger.error(f'Endpoint {self.endpoint_name}: Data channel is not open.')

    async def close_connection(self):
        if self.closed:
            return
        # Close the data channel if it's open
        if self.data_channel and self.data_channel.readyState == "open":
            try:
                self.data_channel.close()
                self.data_channel = None
                self.logger.error(f'Endpoint {self.endpoint_name}: Data channel closed')
            except Exception as e:
                self.logger.error(f'Endpoint {self.endpoint_name}: Error closing data channel: {e}')

        # Close the peer connection
        if self._pc:
            await self._pc.close()
            self.logger.error(f'Endpoint {self.endpoint_name}: "Peer connection closed')

        # Clear the asyncio queue
        if self.web_rtc_queue:
            while not self.web_rtc_queue.empty():
                self.web_rtc_queue.get_nowait()
            self.web_rtc_queue = None

        # Reset instance variables
        self.data_channel = None
        self._pc = None

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


class TunnelEntrance:
    """
    This class is used to forward data between a WebRTC connection and a connection to a target.
    Connection 0 is reserved for control messages. All other connections are for when a client connects
    This tunnel uses four control messages: Ping, Pong, OpenConnection and CloseConnection
    Data is broken into three parts: connection number, [message number], and data
    message number is only used in control messages. (if the connection number is 0 then there is a message number)
    """
    def __init__(self,
                 host,                          # type: str
                 port,                          # type: int
                 endpoint_name,                 # type: str
                 pc,                            # type: WebRTCConnection
                 print_ready_event,             # type: asyncio.Event
                 logger = None,                 # type: logging.Logger
                 ):                             # type: (...) -> None
        self.closing = False
        self.ping_time = None
        self.to_local_task = None
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
        self.kill_server_event = asyncio.Event()
        self.pc = pc
        self.print_ready_event = print_ready_event
        self.server_task = None

    async def send_to_web_rtc(self, data):
        if self.pc.is_data_channel_open():
            self.pc.send_message(data)
            # Yield control back to the event loop for other tasks to execute
            await asyncio.sleep(0)
        else:
            if self.print_ready_event.is_set():
                self.logger.error(f'Endpoint {self.endpoint_name}: Data channel is not open. Data not sent.')

    async def send_control_message(self, message_no, data=None):  # type: (ControlMessage, Optional[bytes]) -> None
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
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while sending control message: {e}")

    async def process_control_message(self, message_no, data):  # type: (ControlMessage, Optional[bytes]) -> None
        if message_no == ControlMessage.CloseConnection:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Received close connection request')
            if data and len(data) > 0:
                target_connection_no = int.from_bytes(data, byteorder='big')
                if target_connection_no == 0:
                    for c in list(self.connections):
                        await self.close_connection(c)
                else:
                    self.logger.debug(f'Endpoint {self.endpoint_name}: Closing connection '
                                      f'{target_connection_no}')
                    await self.close_connection(target_connection_no)
        elif message_no == ControlMessage.Pong:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Received pong request')
            self._ping_attempt = 0
            self.is_connected = True
            if self.ping_time is not None:
                time_now = time.perf_counter()
                # from the time the ping was sent to the time the pong was received
                latency = time_now - self.ping_time
                self.logger.debug(f'Endpoint {self.endpoint_name}: Round trip latency: {latency} ms')
                self.ping_time = None
        elif message_no == ControlMessage.Ping:
            self.logger.debug(f'Endpoint {self.endpoint_name}: Received ping request')
            await self.send_control_message(ControlMessage.Pong)
        elif message_no == ControlMessage.ConnectionOpened:
            if len(data) >= CONNECTION_NO_LENGTH:
                if len(data) > CONNECTION_NO_LENGTH:
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Received invalid open connection message"
                                      f" ({len(data)} bytes)")
                connection_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                self.logger.debug(f"Endpoint {self.endpoint_name}: Starting reader for connection "
                                  f"{connection_no}")
                try:
                    self.to_tunnel_tasks[connection_no] = asyncio.create_task(
                        self.forward_data_to_tunnel(connection_no))  # From current connection to WebRTC connection
                    self.logger.debug(
                        f"Endpoint {self.endpoint_name}: Started reader for connection {connection_no}")
                except ConnectionNotFoundException as e:
                    self.logger.error(f"Endpoint {self.endpoint_name}: Connection {connection_no} not found: {e}")
                except Exception as e:
                    self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding data: {e}")
            else:
                self.logger.error(f"Endpoint {self.endpoint_name}: Invalid open connection message")
        else:
            self.logger.warning(f'Endpoint {self.endpoint_name} Unknown tunnel control message: {message_no}')

    async def forward_data_to_local(self):
        """
        Forward data from WebRTC connection to the appropriate local connection based on connection_no.
        Packet structure
         Control Packets [CONNECTION_NO_LENGTH + DATA_LENGTH + CONTROL_MESSAGE_NO_LENGTH + DATA]
         Data Packets [CONNECTION_NO_LENGTH + DATA_LENGTH + DATA]
        """
        try:
            self.logger.debug(f"Endpoint {self.endpoint_name}: Forwarding data to local...")
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
                            self.logger.warning(f'Endpoint {self.endpoint_name}: Invalid terminator')
                            # if we don't have a valid terminator then we don't know where the message ends or begins
                            should_exit = True
                            break
                        self.logger.debug(f'Endpoint {self.endpoint_name}: Buffer data received data')
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
                                self.logger.error(f"Endpoint {self.endpoint_name}: Connection not found: "
                                                  f"{connection_no}")
                                continue

                            _, con_writer = self.connections[connection_no]
                            try:
                                self.logger.debug(f"Endpoint {self.endpoint_name}: Forwarding data to "
                                                  f"local for connection {connection_no} ({len(send_data)})")
                                con_writer.write(send_data)
                                await con_writer.drain()
                                # Yield control back to the event loop for other tasks to execute
                                await asyncio.sleep(0)
                            except Exception as ex:
                                self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding "
                                                  f"data to local: {ex}")

                                # Yield control back to the event loop for other tasks to execute
                                await asyncio.sleep(0)
                    else:
                        self.logger.debug(
                            f"Endpoint {self.endpoint_name}: Buffer is too short {len(buff)} need "
                            f"{CONNECTION_NO_LENGTH + DATA_LENGTH + length + len(TERMINATOR)}")
                        # Yield control back to the event loop for other tasks to execute
                        await asyncio.sleep(0)
                        break
                try:
                    data = await asyncio.wait_for(self.pc.web_rtc_queue.get(), READ_TIMEOUT)
                except asyncio.TimeoutError as et:
                    if self._ping_attempt > 3:
                        if self.is_connected:
                            self.kill_server_event.set()
                        raise et
                    self.logger.debug(f'Endpoint {self.endpoint_name}: Tunnel reader timed out')
                    self.logger.debug(f'Endpoint {self.endpoint_name}: Send ping request')
                    self.ping_time = time.perf_counter()
                    await self.send_control_message(ControlMessage.Ping)
                    self._ping_attempt += 1
                    continue
                self.pc.web_rtc_queue.task_done()
                if not data or not self.is_connected:
                    self.logger.info(f"Endpoint {self.endpoint_name}: Exiting forward data to local")
                    break
                elif len(data) == 0:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
                    continue
                elif isinstance(data, bytes):
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Got data from WebRTC connection "
                                      f"{len(data)} bytes)")
                    buff += data
                else:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)

            self.logger.debug(f"Endpoint {self.endpoint_name}: Exiting forward data successfully.")
        except asyncio.CancelledError:
            pass

        except Exception as ex:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding data: {ex}")

        finally:
            self.logger.debug(f"Endpoint {self.endpoint_name}: Closing tunnel")
            self.kill_server_event.set()

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
            self.logger.debug(f"Endpoint {self.endpoint_name}: Sent ping message to WebRTC connection")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while establishing WebRTC connection: {e}")
            failed = True
        finally:
            if failed:
                for connection_no in list(self.connections):
                    await self.close_connection(connection_no)
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
                reader, _ = c
                try:
                    data = await reader.read(BUFFER_TRUNCATION_THRESHOLD)
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Forwarding {len(data)} "
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
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Connection '{con_no}' read failed: {e}")
                    break
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding data in connection "
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

        self.logger.debug(f"Endpoint {self.endpoint_name}: Created local connection {connection_no}")

        # Send open connection message with con_no. this is required to be sent to start the connection
        await self.send_control_message(ControlMessage.OpenConnection,
                                        int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big'))

    async def start_server(self):  # type: (...) -> None
        """
        This server is used to listen for client connections to the local port.
        """
        if self.server:
            return
        try:
            self._port = find_open_port(tried_ports=[], preferred_port=self._port, host=self.host)
        except asyncio.CancelledError:
            self.logger.info(f"Endpoint {self.endpoint_name}: Server has been cancelled. Cleaning up...")
            # Perform necessary cleanup here
            self.server.close()  # Close the server
            await self.server.wait_closed()  # Wait until the server is closed
            return

        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while finding open port: {e}")
            await self.print_not_ready()
            return

        if not self._port:
            self.logger.error(f"Endpoint {self.endpoint_name}: No open ports found for local server")
            await self.print_not_ready()
            return

        try:
            self.server = await asyncio.start_server(self.handle_connection, family=socket.AF_INET, host=self.host,
                                                     port=self._port)
            async with self.server:
                self.server_task = await asyncio.create_task(self.print_ready(self.host, self._port, self.print_ready_event))
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
        print(f'\n{bcolors.FAIL}+---------------------------------------------------------{bcolors.ENDC}')
        print(f'{bcolors.FAIL}| Endpoint {self.endpoint_name}{bcolors.ENDC} failed to start')
        print(f'{bcolors.FAIL}+---------------------------------------------------------{bcolors.ENDC}')
        await self.send_control_message(ControlMessage.CloseConnection, int_to_bytes(0))
        for c in list(self.connections):
            await self.close_connection(c)
        self.kill_server_event.set()

    async def print_ready(self, host,           # type: str
                          port,                 # type: int
                          print_ready_event,    # type: asyncio.Event
                          ):                    # type: (...) -> None
        """
        pretty prints the endpoint name and host:port after the tunnels are set up
        """
        wait_for_server = READ_TIMEOUT * 6
        try:
            await asyncio.wait_for(print_ready_event.wait(), wait_for_server)
        except TimeoutError:
            await self.print_not_ready()
            return

        if not self.server or not self.server.is_serving() if self.server else False:
            await self.print_not_ready()
            return

        # Sleep a little bit to print out last
        await asyncio.sleep(.5)
        host = host + ":" if host else ''
        print(f'\n{bcolors.OKGREEN}+---------------------------------------------------------------{bcolors.ENDC}')
        print(
            f'{bcolors.OKGREEN}| Endpoint {bcolors.ENDC}{bcolors.OKBLUE}{self.endpoint_name}{bcolors.ENDC}'
            f'{bcolors.OKGREEN}: Listening on port: {bcolors.ENDC}'
            f'{bcolors.BOLD}{bcolors.OKBLUE}{host}{port}{bcolors.ENDC}')
        print(f'{bcolors.OKGREEN}+---------------------------------------------------------------{bcolors.ENDC}')
        print(f'{bcolors.OKGREEN}View all open tunnels   : {bcolors.ENDC}{bcolors.OKBLUE}pam tunnel list{bcolors.ENDC}')
        print(f'{bcolors.OKGREEN}Tail logs on open tunnel: {bcolors.ENDC}'
              f'{bcolors.OKBLUE}pam tunnel tail ' +
              (f'--' if self.endpoint_name[0] == '-' else '') +
              f'{self.endpoint_name}{bcolors.ENDC}')
        print(f'{bcolors.OKGREEN}Stop a tunnel           : {bcolors.ENDC}'
              f'{bcolors.OKBLUE}pam tunnel stop ' +
              (f'--' if self.endpoint_name[0] == '-' else '') +
              f'{self.endpoint_name}{bcolors.ENDC}')

    async def stop_server(self):
        if self.closing:
            return
        try:
            await self.send_control_message(ControlMessage.CloseConnection, int_to_bytes(0))
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception sending Close connection {ex}')

        self.kill_server_event.set()
        try:
            # close aiortc data channel
            await self.pc.close_connection()
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception closing data channel {ex}')

        finally:
            self.closing = True
            self.logger.debug(f"Endpoint {self.endpoint_name}: Tunnel stopped")

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
                    f"Endpoint {self.endpoint_name}: Timed out while trying to close connection "
                    f"{connection_no}")

            del self.connections[connection_no]
            self.logger.info(f"Endpoint {self.endpoint_name}: Closed connection {connection_no}")
        else:
            self.logger.info(f"Endpoint {self.endpoint_name}: Connection {connection_no} not found")
        if connection_no in self.to_tunnel_tasks:
            try:
                self.to_tunnel_tasks[connection_no].cancel()
            except Exception as ex:
                self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception canceling tasks {ex}')
            del self.to_tunnel_tasks[connection_no]
            self.logger.info(f"Endpoint {self.endpoint_name}: Tasks closed for connection {connection_no}")
        else:
            self.logger.info(f"Endpoint {self.endpoint_name}: Tasks for {connection_no} not found")
