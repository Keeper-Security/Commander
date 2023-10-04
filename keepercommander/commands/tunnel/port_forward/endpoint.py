import abc
import asyncio
import base64
import enum
import logging
import os
import socket
import ssl
from typing import Optional, Dict, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.utils import int_to_bytes
from keeper_secrets_manager_core.utils import bytes_to_string

from keepercommander import utils
from keepercommander.display import bcolors
from .tunnel import ITunnel

BUFFER_TRUNCATION_THRESHOLD = 16 * 1024


class ControlMessage(enum.IntEnum):
    Ping = 1
    Pong = 2
    SharePublicKey = 10
    ApplicationMessage = 100    # 100 and more encrypted final implementation
    OpenConnection = 101
    CloseConnection = 102


def verify_tls_certificate(cert_data, public_key):
    """
    Verify the TLS certificate against the public key found in Keeper's public key file
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())

        # Extract the public key from the certificate
        cert_public_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        pem_public_key = serialization.load_pem_public_key(cert_public_key_pem.encode(), backend=default_backend())
        tls_public_key = pem_public_key.public_bytes(encoding=serialization.Encoding.DER,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo)
        decoded_public_key = base64.b64decode(public_key)

        # Extract the public key from the certificate
        public_key_object = cert.public_key()

        # Ensure it's an elliptic curve public key
        if isinstance(public_key_object, ec.EllipticCurvePublicKey):
            tls_raw_public_key = public_key_object.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
        else:
            raise ValueError("Not an elliptic curve public key")
        # Check if they match
        if tls_public_key == decoded_public_key:
            return True

    except InvalidSignature as e:
        # Handle invalid signature exception
        print(f"Certificate verification failed due to invalid signature: {e}")

    except Exception as e:
        # General exception handling
        print(f"Error during certificate verification: {e}")

    return False


def find_open_port(tried_ports: [], start_port=49152, end_port=65535, preferred_port=None):
    """
    Find an open port in the range [start_port, end_port].
    The default range is from 49152 to 65535, which are the "ephemeral ports" or "dynamic ports.".

    :param start_port: The starting port number.
    :param end_port: The ending port number.
    :param preferred_port: A preferred port to check first.
    :return: An open port number or None if no port is found.
    """
    if preferred_port is not None and preferred_port not in tried_ports:
        # Check if the preferred port is open
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                # Set the SO_REUSEADDR option
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", preferred_port))
                return preferred_port
            except OSError:
                pass  # Port is in use, continue to search
            except Exception as e:
                print(e)
                return None

    # Iterate over the range of port numbers
    available_ports = [port for port in range(start_port, end_port) if port not in tried_ports]
    if len(available_ports) == 0:
        return None
    for port in available_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                # Set the SO_REUSEADDR option
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # Try to bind to the port
                s.bind(("0.0.0.0", port))
                # If binding succeeds, return the port number
                return port
            except OSError:
                # If there's an error (port is in use), continue to the next port
                continue
            except Exception as e:
                print(e)
    return None


class TunnelProtocol(abc.ABC):
    """
    This class is used to set up the public tunnel entrance. Everything from the PlainTextForwarder to krouter

    The public tunnel is not encrypted and is used to send control messages to the gateway: Ping, Pong, CloseConnection
    and SharePublicKey.
      There isn't a need for open connection because we send a start command in the discoveryrotation.py file.
      The public tunnel also sends data to the tunnel.
      There are two connections or channels. 0 is for control messages and 1 is for data


    The private tunnel does a TLS connect to the port forwarder is on but the connection gets pushed through the tunnel
    How this works is this forwarder server listens to the same port that the TLS server is on the gateway
    The traffic locally connects to "localhost" and the port that this server is listening on but this forwards the data
    to the TLS server on the gateway where the TLS connection is made.

    The flow is as follows:
                                The public tunnel Part I
       0. User enters a command to start a tunnel
       1. Commander sends a start command to the gateway through krouter
       2. Commander starts the public tunnel entrance and listens for messages from krouter
        2.5. The Gateway: starts the public tunnel exit, listens for messages from krouter
       3. There are ping and pong messages to keep the connection alive, and CloseConnection will close everything.

                                Setting up the TLS server ( public tunnel Part II)
        3.5. The Gateway: sets up the TLS server on the port and sends the port and public cert to Commander in the
             SharePublicKey message. This also sets up the private tunnel exit other side of the TLS server as krouter
       4. Commander sends the port back to the gateway to approve (if the port isn't open it proposes a new port)
        4.5. The Gateway: if the port sent back is the same as the port it sent then continue, otherwise stop the TLS
             server and go back to step 3.5 trying out the port that was sent back if it is open otherwise propose a
             new port.
       5. Commander sets up the TLS forwarder on that same port. This forwarder reads data from localhost:port and sends
          it to the public tunnel. That gets routed to the gateway and then to the TLS server on
          the gateway's localhost:port

                                Setting up the private tunnel
       6. Commander verifies that the public key matches what it gets back from keeper app
       7. Commander sets up the private tunnel entrance to use the given cert and connects to localhost:port (the
          forwarder -> TLS server on the Gateway). This also sets up a local server that listens for connections to a
          local port that the user has provided or a random port if none is provided.
       8. Commander sends a private ping message through the private tunnel entrance to the private tunnel exit
       9. The Gateway: receives the private ping message and sends a private pong message back establishing the
          connection
       10. Commander waits for a client to connect to the local server.

                                User connects to the target host and port
       11. Client connects to the private tunnel's local server.
       12. Private Tunnel Entrance (In Commander) sends an open connection message to the TLS connection and listens to
           the client forwarding on any data
       13. Private Tunnel Exit (On The Gateway): receives the open connection message and connects to the target
           host and port sending any data back to the TLS connection
       14. The session goes on until the CloseConnection message is sent, or the outer tunnel is closed.
       15. The User can repeat steps 10-14 as many times as they want

                              User closes the public tunnel
      16. The User closes the public tunnel and everything is cleaned up, and we can start back at step 1
    """
    def __init__(self, tunnel: ITunnel, endpoint_name: Optional[str] = None, logger: logging.Logger = None,
                 gateway_uid: str = None):
        self.tunnel = tunnel
        self.endpoint_name = endpoint_name
        self.logger = logger
        self.gateway_uid = gateway_uid
        self.target_port = None
        self.target_host = None
        self.private_tunnel = None
        self._paired = False
        self._is_running = False
        self._ping_attempt = 0
        self.public_tunnel_port = None
        self.forwarder = None
        self.forwarder_incoming_queue = asyncio.Queue()
        self.forwarder_out_going_queue = asyncio.Queue()
        self.ports_tried = []

    async def connect(self, host="localhost", port=0):
        if not self.tunnel.is_connected:
            await self.tunnel.connect()

        self._is_running = True
        self.target_port = port
        self.target_host = host
        t1 = asyncio.create_task(self.start_tunnel_reader())
        tasks = [t1]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        await self.disconnect()

    async def disconnect(self):
        self._is_running = False
        tasks = []

        self.tunnel.disconnect()
        self._paired = False
        self.public_tunnel_port = None

        tasks.append(self.forwarder.stop())
        if len(tasks) > 0:
            await asyncio.gather(*tasks)

    async def start_tunnel_reader(self) -> None:
        if not self.tunnel.is_connected:
            self.logger.warning('Endpoint %s: Tunnel reader: not connected', self.endpoint_name)
            return

        self._ping_attempt = 0
        while self.tunnel.is_connected:
            try:
                buffer = await self.tunnel.read(BUFFER_TRUNCATION_THRESHOLD if self._paired else 100)
                self.logger.debug(f"Endpoint {self.endpoint_name}: Received data from tunnel: \n{buffer}\n")
            except asyncio.TimeoutError as e:
                if self._ping_attempt > 3:
                    if self.tunnel.is_connected:
                        self.tunnel.disconnect()
                    raise e
                self.logger.debug('Endpoint %s: Tunnel reader timed out', self.endpoint_name)
                if self._paired:
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
                    # At this stage we have two connections. 0 is for control messages and 1 is for data
                    connection_no = int.from_bytes(buffer[:4], byteorder='big')
                    length = int.from_bytes(buffer[4:8], byteorder='big')
                    buffer = buffer[8:]
                    if length <= len(buffer):
                        data = buffer[:length]
                        buffer = buffer[length:]
                        if connection_no == 0:
                            # This is a control message
                            if len(data) >= 2:
                                message_no = int.from_bytes(data[:2], byteorder='big')
                                data = data[2:]
                                if is_packet_valid:
                                    await self.process_control_message(ControlMessage(message_no), data)
                            else:
                                is_packet_valid = False
                        else:
                            # This is data
                            self.forwarder_incoming_queue.put_nowait(data)
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
        self.logger.debug(f"Sending data to tunnel: \n{buffer}\n")

        await self.tunnel.write(buffer)

    async def send_data_message(self, data: bytes) -> None:
        if not self._paired:
            self.logger.warning('Endpoint %s: Data rejected: not paired', self.endpoint_name)
            return

        await self._send_to_tunnel(1, data)

    async def send_control_message(self, message_no: ControlMessage, data: Optional[bytes] = None) -> None:
        buffer = data if data is not None else b''
        if message_no >= ControlMessage.ApplicationMessage:
            if not self._paired:
                self.logger.warning('Endpoint %s: Control message %d rejected: not paired',
                                    self.endpoint_name, message_no)
                return

        buffer = int.to_bytes(message_no, 2, byteorder='big') + buffer
        await self._send_to_tunnel(0, buffer)

    async def read_connection(self):
        while self._is_running:
            try:
                data = await self.forwarder_out_going_queue.get()
                self.forwarder_out_going_queue.task_done()
                if isinstance(data, bytes):
                    if len(data) == 0:
                        break
                    else:
                        self.logger.debug('Endpoint %s: read %d bytes',
                                          self.endpoint_name, len(data))
                        await self.send_data_message(data)
            except Exception as e:
                self.logger.debug('Endpoint %s: read failed: %s',
                                  self.endpoint_name, e)
                break

        await self.send_control_message(ControlMessage.CloseConnection)
        self.logger.debug('Endpoint %s: closed', self.endpoint_name)

    async def process_control_message(self, message_no: ControlMessage, data: bytes):
        if message_no == ControlMessage.Ping:
            logging.debug('Endpoint %s: Received ping request', self.endpoint_name)
            logging.debug('Endpoint %s: Send pong request', self.endpoint_name)
            await self.send_control_message(ControlMessage.Pong)
            self._ping_attempt = 0
        elif message_no == ControlMessage.Pong:
            logging.debug('Endpoint %s: Received pong request', self.endpoint_name)
            self._ping_attempt = 0
        elif message_no == ControlMessage.SharePublicKey:
            try:
                #  It will need to contain the public_tunnel_port
                self.public_tunnel_port = int.from_bytes(data[:2], byteorder='big')
                # Check if port is open
                tmp_port = find_open_port(tried_ports=self.ports_tried, preferred_port=self.public_tunnel_port)
                if tmp_port is None:
                    self.logger.info('Endpoint %s: Connecting to pair: No open port found', self.endpoint_name)
                    await self.disconnect()
                    return
                if tmp_port != self.public_tunnel_port:
                    self.ports_tried.append(self.public_tunnel_port)
                    # The port wasn't open, so send a new port to the gateway
                    if self.forwarder:
                        await self.forwarder.stop()
                        self.forwarder = None

                    if self.private_tunnel:
                        await self.private_tunnel.stop_server()
                        self.private_tunnel = None
                    open_port = find_open_port(tried_ports=self.ports_tried)
                    await self.send_control_message(ControlMessage.SharePublicKey, int_to_bytes(open_port))
                else:
                    self._paired = True

                    # TODO: get this from KSM ✓💰self.gateway_uid
                    tls_public_key = \
                        'BMh+qwlw84vD31go1Q+YYui0Wfb+6+YEpZQolY/oJ7u+RFyF7ptZtHtVN8Ijba5bFQEQIIHFho8/WYWCyo/0fQo='

                    received_cert = bytes_to_string(data[2:])

                    is_trusted = verify_tls_certificate(received_cert, tls_public_key)

                    if not is_trusted:
                        # TODO: why is the cert I am getting using a different public key then what I am finding?
                        pass
                        # await self.disconnect()
                        # return

                    asyncio.create_task(self.read_connection())

                    forwarder_event = asyncio.Event()
                    private_tunnel_event = asyncio.Event()

                    # Generate a random symmetric key for AES encryption
                    tunnel_symmetric_key = utils.generate_aes_key()
                    nonce = os.urandom(12)

                    self.forwarder = PlainTextForwarder(forwarder_event=forwarder_event,
                                                        public_tunnel_port=self.public_tunnel_port,
                                                        logger=self.logger,
                                                        out_going_queue=self.forwarder_out_going_queue,
                                                        incoming_queue=self.forwarder_incoming_queue,
                                                        tunnel_symmetric_key=tunnel_symmetric_key, nonce=nonce)

                    asyncio.create_task(self.forwarder.start())
                    logging.debug(f"started forwarder on port {self.public_tunnel_port}")

                    logging.debug("starting private tunnel")

                    self.private_tunnel = PrivateTunnelEntrance(private_tunnel_event=private_tunnel_event,
                                                                host=self.target_host, port=self.target_port,
                                                                public_tunnel_port=self.public_tunnel_port,
                                                                endpoint_name=self.endpoint_name, cert=received_cert,
                                                                logger=self.logger,
                                                                tunnel_symmetric_key=tunnel_symmetric_key, nonce=nonce)

                    # Making the TLS Connection through the tunnel
                    asyncio.create_task(self.private_tunnel.start_server(forwarder_event, private_tunnel_event))

                    serving = self.private_tunnel.server.is_serving() if self.private_tunnel.server else False

                    logging.debug(f'Private tunnel started {serving}')

                    logging.debug(f"sending control message with public tunnel port {self.public_tunnel_port}")
                    await self.send_control_message(ControlMessage.SharePublicKey,
                                                    int_to_bytes(self.public_tunnel_port))

                    logging.debug('Endpoint %s: Tunnel Setup', self.endpoint_name)

            except Exception as e:
                self.public_tunnel_port = None
                self.logger.info('Endpoint %s: Connecting to pair: Public key load error: %s',
                                 self.endpoint_name, e)
        elif message_no == ControlMessage.CloseConnection:
            await self.disconnect()
        else:
            self.logger.info('Endpoint %s: Unknown control message %d', self.endpoint_name, message_no)


class PlainTextForwarder:
    """
    This class is used to forward data between a server on local port and the tunnel
    The public tunnel reads/writes the two ques and forwards the data to krouter
    Any connection that is made to the local port is forwarded to the tunnel.
    How this works is this server listens to the same port that the TLS port is on the gateway
    The private tunnel locally connects to "localhost:port" that this server is listening on but this forwards the data
    to the TLS server on the gateway allowing the TLS connection to be made.
    """
    def __init__(self, forwarder_event: asyncio.Event,public_tunnel_port: int, logger: logging.Logger, out_going_queue: asyncio.Queue,
                 incoming_queue: asyncio.Queue, tunnel_symmetric_key: bytes = None, nonce: bytes = None):
        self.forwarder_event = forwarder_event
        self.client_tasks = []
        self.forwarder_server = None
        self.out_going_queue = out_going_queue
        self.incoming_queue = incoming_queue
        self.public_tunnel_port = public_tunnel_port
        self.logger = logger
        self.tunnel_symmetric_key = tunnel_symmetric_key
        self.nonce = nonce

    async def forwarder_handle_client(self, forwarder_reader: asyncio.StreamReader, forwarder_writer: asyncio.StreamWriter):
        data = await forwarder_reader.read(BUFFER_TRUNCATION_THRESHOLD)  # Receive data from the client

        cipher = AESGCM(self.tunnel_symmetric_key)
        try:
            decrypted_message = cipher.decrypt(self.nonce, data, associated_data=None)
        except Exception as e:
            self.logger.error(f"Error decrypting message: {e}")
            return

        if decrypted_message != b"Hello World":
            self.logger.error(f"Invalid connection disconnecting")
            return
        else:
            self.logger.debug(f"Password accepted connection")
            ciphertext = cipher.encrypt(self.nonce, b'Hello Back', associated_data=None)
            forwarder_writer.write(ciphertext)
            await forwarder_writer.drain()
        try:
            async def out_going_forward(f_reader):
                """
                reads data from the connection (private tunnel) and sends it out to the tunnel
                """
                try:
                    while True:
                        data = await f_reader.read(BUFFER_TRUNCATION_THRESHOLD)
                        if not data:
                            break
                        self.out_going_queue.put_nowait(data)
                        self.logger.debug(f"Forwarded {len(data)} bytes")
                except asyncio.CancelledError:
                    self.logger.debug("Cancelled forwarder out going")
                    pass

            async def incoming_forward(f_writer):
                """
                writes data from the tunnel to the connection (Private tunnel is the connection)
                """
                try:
                    while True:
                        data = await self.incoming_queue.get()
                        self.incoming_queue.task_done()
                        if not data:
                            break
                        f_writer.write(data)
                        self.logger.debug(f"Forwarded {len(data)} bytes")
                except asyncio.CancelledError:
                    self.logger.debug("Cancelled forwarder incoming")
                    pass
                finally:
                    f_writer.close()

            client_to_remote = asyncio.create_task(out_going_forward(forwarder_reader))
            remote_to_client = asyncio.create_task(incoming_forward(forwarder_writer))
            
            self.client_tasks.extend([client_to_remote, remote_to_client])
            self.forwarder_event.set()
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")

    async def start(self):
        self.forwarder_server = await asyncio.start_server(self.forwarder_handle_client, '0.0.0.0',
                                                           self.public_tunnel_port)

        async with self.forwarder_server:
            self.logger.info(f"Listening on 0.0.0.0:{self.public_tunnel_port}...")
            await self.forwarder_server.serve_forever()

    async def stop(self):
        if self.forwarder_server:
            self.forwarder_server.close()
            await self.forwarder_server.wait_closed()
            self.logger.info("Server stopped")

        # Cancel and gather the client tasks to clean up any running tasks
        if self.client_tasks:
            for task in self.client_tasks:
                task.cancel()
            await asyncio.gather(*self.client_tasks, return_exceptions=True)
            self.client_tasks = []


class PrivateTunnelEntrance:
    """
    This class is used to forward data between a server that clients connect to on a local port and a TLS connection.
    The private tunnel does a TLS connect to the public tunnel's forwarder and the traffic gets pushed through the
        public tunnel to the TLS server on the Gateway
    The TLS connection is made using the public cert of the TLS server on the gateway.
    The Private Tunnel treats the public tunnel like a public DNS provider.
    Connection 0 is reserved for control messages. All other connections are for when a client connects
    This private tunnel uses four control messages: Ping, Pong, OpenConnection and CloseConnection
    Data is broken into three parts: connection number, [message number], and data
    message number is only used in control messages. (if the connection number is 0 then there is a message number)
    """
    def __init__(self, private_tunnel_event: asyncio.Event, host: str, port: int, public_tunnel_port: int, endpoint_name, cert: str,
                 logger: logging.Logger = None, tunnel_symmetric_key: bytes = None, nonce: bytes = None):
        self.private_tunnel_event = private_tunnel_event
        self._ping_attempt = 0
        self.host = host
        self.server = None
        self.connection_no = 1
        self.endpoint_name = endpoint_name
        self.connections: Dict[int, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.public_tunnel_port = public_tunnel_port
        self.cert = cert
        self.tls_reader: Optional[asyncio.StreamReader] = None
        self.tls_writer: Optional[asyncio.StreamWriter] = None
        self._port = port
        self.logger = logger
        self.is_connected = False
        self.tunnel_symmetric_key = tunnel_symmetric_key
        self.nonce = nonce
        asyncio.create_task(self.start_tls_reader())

    async def send_control_message(self, message_no: ControlMessage, data: Optional[bytes] = None) -> None:
        buffer = data if data is not None else b''
        data = int.to_bytes(0, 4, byteorder='big')
        data += int.to_bytes(message_no, 2, byteorder='big')
        data += buffer
        try:
            self.tls_writer.write(data)
            await self.tls_writer.drain()
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while sending private control message: {e}")

    async def process_control_message(self, message_no: ControlMessage, data: bytes):
        if message_no == ControlMessage.CloseConnection:
            if data and len(data) > 0:
                target_connection_no = int.from_bytes(data, byteorder='big')
                await self.close_connection(target_connection_no)
        elif message_no == ControlMessage.Pong:
            self.logger.debug('Received private pong request')
            self._ping_attempt = 0
            self.is_connected = True
        elif message_no == ControlMessage.Ping:
            self.logger.debug('Received private ping request')
            await self.send_control_message(ControlMessage.Pong)
        else:
            self.logger.warning('Unknown private tunnel control message: %d', message_no)

    async def start_tls_reader(self):
        """
        Connect to the TLS server on the gateway.
        Transfer data from TLS connection to local connections.
        """
        async def forward_data_to_local():
            try:
                self.private_tunnel_event.set()
                self.logger.debug(f"Endpoint {self.endpoint_name}: Forwarding private data to local...")
                while True:
                    data = await self.tls_reader.read(BUFFER_TRUNCATION_THRESHOLD)  # Adjust buffer size as needed
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Got private data from tls server "
                                      f"{len(data)} bytes)")
                    if not data:
                        break
                    if len(data) >= 4:
                        con_no = int.from_bytes(data[:4], byteorder='big')
                        if con_no == 0:
                            # This is a control message
                            control_m = ControlMessage(int.from_bytes(data[4:6], byteorder='big'))
                            data = data[6:]
                            await self.process_control_message(control_m, data)
                        else:
                            if con_no in self.connections:
                                _, con_writer = self.connections[con_no]
                                try:
                                    data = data[4:]
                                    self.logger.debug(f"Endpoint {self.endpoint_name}: Forwarding private data to "
                                                      f"local for connection {con_no} ({len(data)})")
                                    con_writer.write(data)
                                    await con_writer.drain()
                                except Exception as ex:
                                    self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding "
                                                      f"private data to local: {ex}")
                self.logger.debug(f"Endpoint {self.endpoint_name}: Exiting forward private data successfully.")
            except asyncio.CancelledError:
                pass

            except Exception as ex:
                self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding private data: {ex}")

        try:
            # Establish a regular TCP connection to the server
            self.tls_reader, writer = await asyncio.open_connection('localhost', self.public_tunnel_port)

            # Encrypt the message with the symmetric key using AES
            cipher = AESGCM(self.tunnel_symmetric_key)
            ciphertext = cipher.encrypt(self.nonce, b'Hello World', associated_data=None)

            writer.write(ciphertext)
            await writer.drain()
            response = await self.tls_reader.read(BUFFER_TRUNCATION_THRESHOLD)
            try:
                decrypted_message = cipher.decrypt(self.nonce, response, associated_data=None)
            except Exception as e:
                self.logger.error(f"Error decrypting message: {e}")
                return
            if decrypted_message != b'Hello Back':
                self.logger.error(f"Endpoint {self.endpoint_name}: Failed to connect to forwarder")
                return
            else:
                self.logger.debug(f"Endpoint {self.endpoint_name}: Connection to forwarder accepted")

            # https://github.com/python/cpython/issues/96972
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.load_verify_locations(cadata=self.cert)
            # Establish a connection to localhost:server_port
            logging.debug(f"Endpoint {self.endpoint_name}: SSL context made")
            # Establish a connection to the TLS server on the gateway
            self.logger.debug(f"Endpoint {self.endpoint_name}: Attempting to establish TLS connection...")
            await writer.start_tls(ssl_context, server_hostname='localhost')
            self.logger.debug(f"Endpoint {self.endpoint_name}: TLS connection established successfully.")
            self.tls_writer = writer
            asyncio.create_task(forward_data_to_local())  # From TLS server to local connections

            # Send hello world open connection message
            await self.send_control_message(ControlMessage.Ping)
            self.logger.debug(f"Endpoint {self.endpoint_name}: Sent private ping message to TLS server")

        except ConnectionRefusedError:
            self.logger.error(f"Endpoint {self.endpoint_name}: TLS Connection refused. Ensure the server is running.")
        except TimeoutError:
            self.logger.error(f"Endpoint {self.endpoint_name}: TLS Connection timed out. Check the server and network.")
        except OSError as es:
            self.logger.error(f"Endpoint {self.endpoint_name}: TLS Error connecting: {es}")
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while establishing TLS connection: {e}")
            return

    async def forward_data_to_tunnel(self, con_no):
        """
        Forward data from the given connection to the TLS connection
        """
        try:
            while True:
                c = self.connections.get(con_no)
                if c is None:
                    break
                reader, _ = c
                try:
                    data = await reader.read(BUFFER_TRUNCATION_THRESHOLD)
                    self.logger.error(f"Endpoint {self.endpoint_name}: Forwarding private {len(data)}"
                                      f"bytes to tunnel for connection {con_no}")
                    if isinstance(data, bytes):
                        if len(data) == 0 and reader.at_eof():
                            break
                        else:
                            data = int.to_bytes(con_no, 4, byteorder='big') + data
                            self.tls_writer.write(data)
                            await self.tls_writer.drain()
                except asyncio.TimeoutError as e:
                    if self._ping_attempt > 3:
                        if self.server.is_serving():
                            for con in self.connections:
                                await self.close_connection(con)
                            self.server.close()
                        raise e
                    self.logger.debug(f"Endpoint {self.endpoint_name}: private reader timed out")
                    if self.is_connected:
                        logging.debug(f"Endpoint {self.endpoint_name}: Send private ping request")
                        await self.send_control_message(ControlMessage.Ping)
                    self._ping_attempt += 1
                    continue
                except Exception as e:
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Private connection '{con_no}' read failed: {e}")
                    break
            pass  # Handle task cancellation
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while forwarding private data in connection "
                              f"{con_no}: {e}")

        # Send close connection message with con_no
        await self.send_control_message(ControlMessage.CloseConnection, int.to_bytes(con_no, 4, byteorder='big'))

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        This is called when a client connects to the local port starting a new session.
        """
        connection_no = self.connection_no
        self.connection_no += 1
        self.connections[connection_no] = (reader, writer)

        self.logger.debug(f"Endpoint {self.endpoint_name}: Created private local connection {connection_no}")

        # Send open connection message with con_no. this is required to be sent to start the connection
        await self.send_control_message(ControlMessage.OpenConnection,
                                        int.to_bytes(connection_no, 4, byteorder='big'))

        self.logger.debug(f"Endpoint {self.endpoint_name}: Starting private reader for connection {connection_no}")
        asyncio.create_task(self.forward_data_to_tunnel(connection_no))  # From current connection to TLS server
        self.logger.debug(f"Endpoint {self.endpoint_name}: Started private reader for connection {connection_no}")

    @property
    def port(self) -> int:
        if self.server and self.server.is_serving():
            ep = next((x for x in self.server.sockets if x.family == socket.AF_INET), None)
            if ep:
                return ep.getsockname()[1]
        elif self._port:
            return self._port
        return 0

    async def start_server(self, forwarder_event: asyncio.Event, private_tunnel_event: asyncio.Event):
        """
        This server is used to listen for client connections to the local port.
        """
        self.server = await asyncio.start_server(self.handle_connection, family=socket.AF_INET, host=self.host,
                                                 port=self.port)
        async with self.server:
            asyncio.create_task(self.print_ready(self.host, self.port, forwarder_event, private_tunnel_event))
            await self.server.serve_forever()

    async def print_ready(self, host: str, port: int, forwarder_event: asyncio.Event,
                          private_tunnel_event: asyncio.Event):
        """
        pretty prints the endpoint name and host:port after the tunnels are set up
        """
        await forwarder_event.wait()
        await private_tunnel_event.wait()
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
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.logger.info(f"Endpoint {self.endpoint_name}: Local server stopped")

    async def close_connection(self, connection_no):
        if connection_no in self.connections:
            reader, writer = self.connections[connection_no]
            writer.close()
            await writer.wait_closed()
            del self.connections[connection_no]
            self.logger.info(f"Endpoint {self.endpoint_name}: Closed connection {connection_no}")
        else:
            self.logger.info(f"Endpoint {self.endpoint_name}: Connection {connection_no} not found")