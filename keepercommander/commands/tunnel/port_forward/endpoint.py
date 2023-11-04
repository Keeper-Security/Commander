import abc
import asyncio
import datetime
import enum
import hashlib
import hmac
import logging
import os
import secrets
import socket
import ssl
import string
import tempfile
import time
from typing import Optional, Dict, Tuple, Any, List, Union, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.utils import int_to_bytes
from keeper_secrets_manager_core.utils import bytes_to_string, bytes_to_base64, base64_to_bytes

from keepercommander import utils
from keepercommander.display import bcolors
from .tunnel import ITunnel

PRIVATE_BUFFER_TRUNCATION_THRESHOLD = 1400
READ_TIMEOUT = 10
NON_PARED_READ_TIMEOUT = 5
CONTROL_MESSAGE_NO_LENGTH = HMAC_MESSAGE_LENGTH = 2
CONNECTION_NO_LENGTH = DATA_LENGTH = 4
LATENCY_COUNT = 5
TERMINATOR = b';'
FORWARDER_BUFFER_TRUNCATION_THRESHOLD = (CONNECTION_NO_LENGTH + DATA_LENGTH + PRIVATE_BUFFER_TRUNCATION_THRESHOLD
                                         + len(TERMINATOR))


class HMACHandshakeFailedException(Exception):
    pass


class ConnectionNotFoundException(Exception):
    pass


class ControlMessage(enum.IntEnum):
    Ping = 1
    Pong = 2
    SharePublicKey = 10
    ApplicationMessage = 100    # 100 and more encrypted final implementation
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


def generate_random_bytes(pass_length=32):  # type: (int) -> bytes
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


def generate_secure_self_signed_cert(private_key_str):   # type: (str) -> Tuple[bytes, bytes]
    """
    Generate a secure self-signed certificate, possibly using an existing private key.
    :param private_key_str: PEM-formatted private key as a string.
    :return: Tuple containing the PEM-formatted certificate and private key
    """
    # This is the code that generates a new private key
    '''
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
    '''
    if not private_key_str:
        return b'', b''

    # Deserialize the provided private key from string
    private_key = serialization.load_pem_private_key(
        private_key_str.encode(),
        password=None,
        backend=default_backend()
    )

    # Define subject and issuer
    subject = issuer = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, u"secureEntity"),
    ])

    # Initialize certificate builder
    builder = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(private_key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))

    builder = builder.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)

    # Generate the self-signed certificate
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    # Serialize certificate and private key to PEM format
    cert_pem = certificate.public_bytes(encoding=serialization.Encoding.PEM)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    return cert_pem, private_key_pem


def create_client_ssl_context(server_public_cert_pem,
                              client_cert_pem=None,
                              client_private_key_pem=None):  # type(str, Optional[bytes], Optional[bytes]) -> None
    """
    Create a client-side SSL context.

    :param server_public_cert_pem: PEM-formatted server public certificate for server verification
    :param client_cert_pem: Optional PEM-formatted client certificate for mutual TLS
    :param client_private_key_pem: Optional PEM-formatted client private key for mutual TLS
    :return: Configured SSL context
    """

    # https://github.com/python/cpython/issues/96972
    # Create and configure the SSL context
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = True
    ssl_context.verify_mode = ssl.CERT_REQUIRED
    ssl_context.load_verify_locations(cadata=server_public_cert_pem)

    # If client's cert and private key are provided, configure mutual TLS
    # TODO: this is a workaround for the case when a custom parameter for the client's private key isn't given
    if client_cert_pem and client_private_key_pem:
        cert_file = tempfile.NamedTemporaryFile(delete=False)
        key_file = tempfile.NamedTemporaryFile(delete=False)

        try:
            # Write the client certificate and private key to temporary files
            with open(cert_file.name, 'wb') as f:
                f.write(client_cert_pem)
            with open(key_file.name, 'wb') as f:
                f.write(client_private_key_pem)

            # Load the client certificate and private key
            ssl_context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name)

        finally:
            # Remove the temporary files
            os.remove(cert_file.name)
            os.remove(key_file.name)

    return ssl_context


def verify_tls_certificate(cert_data, public_key):
    """
    Verify the TLS certificate against the public key found in Keeper's public key file
    """
    if public_key is None:
        # FIXME: this is a temporary workaround for the case when the public key API is not available in production
        #  not good!!!!
        #  don't do it!!!!
        #  Fix it when the public key API is available in production   <-------
        return True
        # return False

    try:
        cert = x509.load_pem_x509_certificate(cert_data.encode(), default_backend())

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
        if tls_raw_public_key == public_key:
            return True
        else:
            print(f"Mis Match TLS public key: \n{tls_raw_public_key}\nKeeper public key: \n{public_key}")

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
    :param tried_ports: A list of ports that have already been tried.
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

    # Iterate over the range of port numbers. +1 to include the end_port
    available_ports = [port for port in range(start_port, end_port+1) if port not in tried_ports]
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
    def __init__(self, tunnel,                    # type: ITunnel
                 endpoint_name = None,            # type: Optional[str]
                 logger = None,                   # type: logging.Logger
                 gateway_uid = None,              # type: str
                 gateway_public_key_bytes = None, # type: bytes
                 client_private_key = ""          # type: str
                 ):                               # type: (...) -> None
        self.server_cert = None
        self._round_trip_latency = []
        self.ping_time = None
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
        self.private_tunnel_server = None
        self.read_connection_task = None
        self.forwarder_task = None
        self.kill_server_event = asyncio.Event()
        self.gateway_public_key_bytes = gateway_public_key_bytes
        self.client_public_cert, self.client_private_key_pem = generate_secure_self_signed_cert(client_private_key)
        self.server_public_cert = None

    async def connect(self, host="localhost", port=0):
        if not self.tunnel.is_connected:
            await self.tunnel.connect()

        self._is_running = True
        self.target_port = port
        self.target_host = host
        t1 = asyncio.create_task(self.start_tunnel_reader())
        tasks = [t1]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

        await self.disconnect()

    async def disconnect(self):
        try:
            await self.send_control_message(ControlMessage.CloseConnection)
        finally:
            self._is_running = False
            self._paired = False
            self.public_tunnel_port = None
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
            if self.forwarder:
                tasks.append(self.forwarder.stop())
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception closing forwarder tunnel {ex}')
        try:
            if self.private_tunnel_server:
                self.private_tunnel_server.cancel()
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception closing private tunnel server{ex}')
        try:
            if self.read_connection_task:
                self.read_connection_task.cancel()
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception closing private tunnel {ex}')
        try:
            if self.forwarder_task:
                self.forwarder_task.cancel()
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception closing private tunnel {ex}')
        try:
            if len(tasks) > 0:
                await asyncio.gather(*tasks)
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.endpoint_name}: hit exception gathering tasks {ex}')

    async def start_tunnel_reader(self) -> None:
        if not self.tunnel.is_connected:
            self.logger.warning(f'Endpoint {self.endpoint_name}: Tunnel reader: not connected')
            return

        self._ping_attempt = 0
        buff = b''
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
                    elif connection_no == 1:
                        # This is data
                        self.forwarder_incoming_queue.put_nowait(s_data)
                        # Yield control back to the event loop for other tasks to execute
                        await asyncio.sleep(0)
                    else:
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
                buffer = await self.tunnel.read(READ_TIMEOUT if self._paired else NON_PARED_READ_TIMEOUT)
                self.logger.debug(f"Endpoint {self.endpoint_name}: Received data from tunnel: {len(buffer)}")
                if isinstance(buffer, bytes):
                    buff += buffer
                else:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
            except asyncio.TimeoutError as e:
                if self._ping_attempt > 3:
                    if self.tunnel.is_connected:
                        self.tunnel.disconnect()
                    raise e
                self.logger.debug(f'Endpoint {self.endpoint_name}: Tunnel reader timed out')
                if self._paired:
                    logging.debug(f'Endpoint {self.endpoint_name}: Send ping request')
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

        await self.disconnect()

    async def _send_to_tunnel(self, connection_no, data):  # type: (int, bytes) -> None
        buffer = int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big')
        buffer += int.to_bytes(len(data), DATA_LENGTH, byteorder='big')
        buffer += data + TERMINATOR
        self.logger.debug(f"Sending data to tunnel: {len(buffer)}")

        await self.tunnel.write(buffer)
        # Yield control back to the event loop for other tasks to execute
        await asyncio.sleep(0)

    async def send_data_message(self, data: bytes) -> None:
        if not self._paired:
            self.logger.warning(f'Endpoint {self.endpoint_name}: Data rejected: not paired')
            return

        await self._send_to_tunnel(1, data)

    async def send_control_message(self, message_no: ControlMessage, data: Optional[bytes] = None) -> None:
        if message_no >= ControlMessage.ApplicationMessage:
            if not self._paired:
                self.logger.warning(f'Endpoint {self.endpoint_name}: Control message {message_no} rejected: not paired')
                return

        buffer = int.to_bytes(message_no, CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
        buffer += data if data is not None else b''
        # Control messages are sent through connection 0
        await self._send_to_tunnel(0, buffer)

    async def read_connection(self):
        while self._is_running and not self.kill_server_event.is_set():
            try:
                data = await self.forwarder_out_going_queue.get()
                self.forwarder_out_going_queue.task_done()
                if isinstance(data, bytes):
                    if len(data) == 0:
                        self.logger.debug(f'Endpoint {self.endpoint_name}: Exiting outgoing forwarder')
                        break
                    else:
                        self.logger.debug(f'Endpoint {self.endpoint_name}: read {len(data)} bytes')
                        await self.send_data_message(data)
                else:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
            except Exception as e:
                self.logger.debug(f'Endpoint {self.endpoint_name}: read failed: {e}')
                break

        await self.send_control_message(ControlMessage.CloseConnection)
        self.logger.debug(f'Endpoint {self.endpoint_name}: closed')

    async def process_control_message(self, message_no, data):  # type: (ControlMessage, bytes) -> None
        if message_no == ControlMessage.Ping:
            logging.debug(f'Endpoint {self.endpoint_name}: Received ping request')
            logging.debug(f'Endpoint {self.endpoint_name}: Send pong request')
            await self.send_control_message(ControlMessage.Pong)
            self._ping_attempt = 0
        elif message_no == ControlMessage.Pong:
            logging.debug(f'Endpoint {self.endpoint_name}: Received pong request')
            self._ping_attempt = 0
            if self.ping_time is not None:
                self._round_trip_latency = track_round_trip_latency(self._round_trip_latency, self.ping_time)
                self.logger.debug(f'Endpoint {self.endpoint_name}: Public round trip latency: '
                                  f'{self._round_trip_latency[-1]} ms')
                self.ping_time = None
        elif message_no == ControlMessage.SharePublicKey:
            try:
                #  It will need to contain the public_tunnel_port
                self.public_tunnel_port = int.from_bytes(data[:CONTROL_MESSAGE_NO_LENGTH], byteorder='big')
                # Check if port is open
                tmp_port = find_open_port(tried_ports=self.ports_tried, preferred_port=self.public_tunnel_port)
                if tmp_port is None:
                    self.logger.info(f'Endpoint {self.endpoint_name}: Connecting to pair: No open port found')
                    await self.disconnect()
                    return
                elif tmp_port != self.public_tunnel_port:
                    if len(data[CONTROL_MESSAGE_NO_LENGTH:]) > 0:
                        self.server_public_cert = bytes_to_string(data[CONTROL_MESSAGE_NO_LENGTH:])
                    self.ports_tried.append(self.public_tunnel_port)
                    # The port wasn't open, so send a new port to the gateway
                    if self.forwarder:
                        await self.forwarder.stop()
                        self.forwarder = None

                    if self.private_tunnel:
                        await self.private_tunnel.stop_server()
                        self.private_tunnel = None

                    buffer = tmp_port.to_bytes(CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
                    buffer += self.client_public_cert
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Sending new port {tmp_port} and cert")
                    await self.send_control_message(ControlMessage.SharePublicKey, buffer)

                else:
                    if len(data[CONTROL_MESSAGE_NO_LENGTH:]) > 0:
                        self.server_public_cert = bytes_to_string(data[CONTROL_MESSAGE_NO_LENGTH:])

                        is_trusted = verify_tls_certificate(self.server_public_cert, self.gateway_public_key_bytes)

                        if not is_trusted:
                            await self.disconnect()
                            return

                        buffer = tmp_port.to_bytes(CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
                        buffer += self.client_public_cert
                        self.logger.debug(f"Endpoint {self.endpoint_name}: Sending port {tmp_port} and cert")
                        await self.send_control_message(ControlMessage.SharePublicKey, buffer)

                    else:
                        self._paired = True

                        self.read_connection_task = asyncio.create_task(self.read_connection())

                        forwarder_event = asyncio.Event()
                        private_tunnel_event = asyncio.Event()

                        # Generate a random symmetric key for AES encryption
                        tunnel_symmetric_key = utils.generate_aes_key()

                        self.forwarder = PlainTextForwarder(forwarder_event=forwarder_event,
                                                            public_tunnel_port=self.public_tunnel_port,
                                                            logger=self.logger,
                                                            out_going_queue=self.forwarder_out_going_queue,
                                                            incoming_queue=self.forwarder_incoming_queue,
                                                            kill_sever_event=self.kill_server_event,
                                                            tunnel_symmetric_key=tunnel_symmetric_key)

                        self.forwarder_task = asyncio.create_task(self.forwarder.start())
                        logging.debug(f"started forwarder on port {self.public_tunnel_port}")

                        logging.debug("starting private tunnel")

                        self.private_tunnel = PrivateTunnelEntrance(private_tunnel_event=private_tunnel_event,
                                                                    host=self.target_host, port=self.target_port,
                                                                    public_tunnel_port=self.public_tunnel_port,
                                                                    endpoint_name=self.endpoint_name,
                                                                    server_public_cert=self.server_public_cert,
                                                                    kill_server_event=self.kill_server_event,
                                                                    logger=self.logger,
                                                                    tunnel_symmetric_key=tunnel_symmetric_key,
                                                                    client_private_key_pem=self.client_private_key_pem,
                                                                    client_public_cert=self.client_public_cert)

                        # Making the TLS Connection through the tunnel
                        private_tunnel_started = asyncio.Event()
                        self.private_tunnel_server = asyncio.create_task(self.private_tunnel.start_server(
                            forwarder_event, private_tunnel_event, private_tunnel_started))
                        await private_tunnel_started.wait()

                        serving = self.private_tunnel.server.is_serving() if self.private_tunnel.server else False

                        if not serving:
                            logging.debug(f'Endpoint {self.endpoint_name}: Private tunnel failed to start')
                            await self.disconnect()
                            raise Exception('Private tunnel failed to start')

            except Exception as e:
                self.public_tunnel_port = None
                self.logger.info(f'Endpoint {self.endpoint_name}: Connecting to pair: Public key load error: {e}')
        elif message_no == ControlMessage.CloseConnection:
            await self.disconnect()
        else:
            self.logger.info(f'Endpoint {self.endpoint_name}: Unknown control message {message_no}')


class PlainTextForwarder:
    """
    This class is used to forward data between a server on local port and the tunnel
    The public tunnel reads/writes the two ques and forwards the data to krouter
    Any connection that is made to the local port is forwarded to the tunnel.
    How this works is this server listens to the same port that the TLS port is on the gateway
    The private tunnel locally connects to "localhost:port" that this server is listening on but this forwards the data
    to the TLS server on the gateway allowing the TLS connection to be made.
    """
    def __init__(self, forwarder_event,       # type: asyncio.Event
                 public_tunnel_port,          # type: int
                 logger,                      # type: logging.Logger
                 out_going_queue,             # type: asyncio.Queue
                 incoming_queue,              # type: asyncio.Queue
                 kill_sever_event,            # type: asyncio.Event
                 tunnel_symmetric_key = None  # type: bytes
                 ):                           # type: (...) -> None
        self.forwarder_event = forwarder_event
        self.client_tasks = []
        self.forwarder_server = None
        self.out_going_queue = out_going_queue
        self.incoming_queue = incoming_queue
        self.public_tunnel_port = public_tunnel_port
        self.logger = logger
        self.tunnel_symmetric_key = tunnel_symmetric_key
        self.kill_server_event = kill_sever_event

    async def forwarder_handle_client(self, forwarder_reader: asyncio.StreamReader,
                                      forwarder_writer: asyncio.StreamWriter, message=None):
        peer_name = forwarder_writer.get_extra_info('peername')
        self.logger.debug(f'Forwarder connection from {peer_name}')
        if peer_name[0] not in ['127.0.0.1', '::1']:
            forwarder_writer.close()
            await forwarder_writer.wait_closed()
            return
        received_data = await forwarder_reader.read(FORWARDER_BUFFER_TRUNCATION_THRESHOLD)
        self.logger.debug(f"Received data from hmac auth: \n{received_data}\n")

        if message is None:
            message = generate_random_bytes()

        # Calculate HMAC for received_message
        calculated_hmac = hmac.new(self.tunnel_symmetric_key, received_data, hashlib.sha256).digest()

        response_to_send = message + b'\n' + bytes_to_base64(calculated_hmac).encode()
        self.logger.debug(f"Sending data for hmac auth: \n{response_to_send}\n")

        forwarder_writer.write(response_to_send)
        await forwarder_writer.drain()

        received_message = await forwarder_reader.read(FORWARDER_BUFFER_TRUNCATION_THRESHOLD)
        self.logger.debug(f"Received data from hmac auth: \n{received_message}\n")

        received_hmac = base64_to_bytes(received_message)

        expected_calculated_hmac = hmac.new(self.tunnel_symmetric_key, message, hashlib.sha256).digest()

        # Compare the calculated HMAC with the received HMAC
        if expected_calculated_hmac != received_hmac:
            self.logger.error(f"Error handling client: Not authenticated")
            # Message integrity and authenticity compromised
            forwarder_writer.close()
            await forwarder_writer.wait_closed()
            return

        forwarder_writer.write(b'Authenticated\n')
        await forwarder_writer.drain()

        try:
            async def out_going_forward(f_reader: asyncio.StreamReader):
                """
                reads data from the connection (private tunnel) and sends it out to the tunnel
                """
                try:
                    while not self.kill_server_event.is_set():
                        data = await f_reader.read(FORWARDER_BUFFER_TRUNCATION_THRESHOLD)
                        if not data:
                            break
                        self.out_going_queue.put_nowait(data)
                        # Yield control back to the event loop for other tasks to execute
                        await asyncio.sleep(0)
                        self.logger.debug(f"Forwarded {len(data)} bytes")
                except asyncio.CancelledError:
                    self.logger.debug("Cancelled forwarder out going")
                    pass
                finally:
                    self.logger.debug("Closing forwarder out going")
                    if not self.forwarder_server or self.client_tasks:
                        await self.stop()

            async def incoming_forward(f_writer):
                """
                writes data from the tunnel to the connection (Private tunnel is the connection)
                """
                try:
                    while not self.kill_server_event.is_set():
                        data = await self.incoming_queue.get()
                        self.incoming_queue.task_done()
                        if not data:
                            break
                        f_writer.write(data)
                        await f_writer.drain()
                        # Yield control back to the event loop for other tasks to execute
                        await asyncio.sleep(0)
                        self.logger.debug(f"Forwarded {len(data)} bytes")
                except asyncio.CancelledError:
                    self.logger.debug("Cancelled forwarder incoming")
                    pass
                finally:
                    self.logger.debug("Closing forwarder incoming")
                    f_writer.close()
                    if not self.forwarder_server or self.client_tasks:
                        await self.stop()

            client_to_remote = asyncio.create_task(out_going_forward(forwarder_reader))
            remote_to_client = asyncio.create_task(incoming_forward(forwarder_writer))
            self.client_tasks.extend([client_to_remote, remote_to_client])
            self.forwarder_event.set()
        except Exception as e:
            self.logger.error(f"Forwarder Error handling client: {e}")
            if not self.forwarder_server or self.client_tasks:
                await self.stop()

    async def start(self):
        self.forwarder_server = await asyncio.start_server(self.forwarder_handle_client, '0.0.0.0',
                                                           self.public_tunnel_port)

        async with self.forwarder_server:
            self.logger.debug(f"Forwarder listening on 0.0.0.0:{self.public_tunnel_port}...")
            await self.forwarder_server.serve_forever()

    async def stop(self):
        self.kill_server_event.set()
        if self.forwarder_server:
            self.forwarder_server.close()
            await self.forwarder_server.wait_closed()
            self.forwarder_server = None
            self.logger.debug("Forwarder Server stopped")

        # Cancel and gather the client tasks to clean up any running tasks
        if self.client_tasks:
            for i in range(0, len(self.client_tasks)):
                try:
                    task = self.client_tasks.pop()
                    task.cancel()
                except Exception as ex:
                    self.logger.warning(f'Forwarder hit exception closing task {ex}')
            try:
                await asyncio.gather(*self.client_tasks, return_exceptions=True)
            except Exception as ex:
                self.logger.warning(f'Forwarder hit exception gathering tasks {ex}')
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
    def __init__(self,
                 private_tunnel_event,          # type: asyncio.Event
                 host,                          # type: str
                 port,                          # type: int
                 public_tunnel_port,            # type: int
                 endpoint_name, server_public_cert,  # type: str
                 kill_server_event,             # type: asyncio.Event
                 logger = None,                 # type: logging.Logger
                 tunnel_symmetric_key = None,   # type: bytes
                 client_private_key_pem = b'',  # type: bytes
                 client_public_cert = b''       # type: bytes
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
        self.public_tunnel_port = public_tunnel_port
        self.server_public_cert = server_public_cert
        self.tls_reader: Optional[asyncio.StreamReader] = None
        self.tls_writer: Optional[asyncio.StreamWriter] = None
        self._port = port
        self.logger = logger
        self.is_connected = True
        self.tunnel_symmetric_key = tunnel_symmetric_key
        self.tls_reader_task = asyncio.create_task(self.start_tls_reader())
        self.to_tunnel_tasks = {}
        self.kill_server_event = kill_server_event
        self.client_private_key_pem = client_private_key_pem
        self.client_public_cert = client_public_cert

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
            self.tls_writer.write(buffer)
            await self.tls_writer.drain()
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
                        self.forward_data_to_tunnel(connection_no))  # From current connection to TLS server
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
        Forward data from TLS connection to the appropriate local connection based on connection_no.
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

                data = await self.tls_reader.read(FORWARDER_BUFFER_TRUNCATION_THRESHOLD)  # Adjust buffer size as needed
                if self.tls_reader.at_eof() and len(data) == 0:
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
                    continue
                elif not data or not self.is_connected:
                    self.logger.info(f"Endpoint {self.endpoint_name}: Exiting forward private data to local")
                    break
                elif isinstance(data, bytes):
                    self.logger.debug(f"Endpoint {self.endpoint_name}: Got private data from tls server "
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

    async def start_tls_reader(self):   # type: () -> None
        """
        Connect to the TLS server on the gateway.
        Transfer data from TLS connection to local connections.
        """
        failed = False
        try:
            # Establish a regular TCP connection to the server
            self.tls_reader, self.tls_writer = await asyncio.open_connection('localhost', self.public_tunnel_port)
            await self.perform_hmac_handshakes()
            self.logger.debug(f"Endpoint {self.endpoint_name}: HMAC Handshake done")
            await self.perform_ssl_handshakes()
            self.logger.debug(f"Endpoint {self.endpoint_name}: SSL Handshake done")
            # From TLS server to local connections
            self.to_local_task = asyncio.create_task(self.forward_data_to_local())

            # Send hello world open connection message
            self.ping_time = time.perf_counter()
            await self.send_control_message(ControlMessage.Ping)
            self.logger.debug(f"Endpoint {self.endpoint_name}: Sent private ping message to TLS server")

        except ConnectionRefusedError:
            self.logger.error(f"Endpoint {self.endpoint_name}: TLS Connection refused. Ensure the server is running.")
            failed = True
        except TimeoutError:
            self.logger.error(f"Endpoint {self.endpoint_name}: TLS Connection timed out. Check the server and network.")
            failed = True
        except OSError as es:
            self.logger.error(f"Endpoint {self.endpoint_name}: TLS Error connecting: {es}")
            failed = True
        except HMACHandshakeFailedException as eh:
            self.logger.error(f"Endpoint {self.endpoint_name}: HMAC Handshake failed: {eh}")
            failed = True
        except Exception as e:
            self.logger.error(f"Endpoint {self.endpoint_name}: Error while establishing TLS connection: {e}")
            failed = True
        finally:
            if failed:
                for connection_no in list(self.connections):
                    await self.close_connection(connection_no)
                await self.stop_server()
                self.is_connected = False
            return

    async def perform_hmac_handshakes(self, message=None):
        """
        Perform the handshake with the TLS server on the gateway as well as the HMAC handshake
        """
        if message is None:
            message = generate_random_bytes()

        # Send challenge message
        self.logger.debug(f"Endpoint {self.endpoint_name}: Sending challenge hmac message to forwarder server "
                          f"{message}")
        self.tls_writer.write(message)
        self.logger.debug(f'start drain')
        await self.tls_writer.drain()
        self.logger.debug(f'end drain')
        received_data = await self.tls_reader.read(FORWARDER_BUFFER_TRUNCATION_THRESHOLD)
        self.logger.debug(f"Endpoint {self.endpoint_name}: Received data from forwarder: \n{received_data}\n")
        # Split the received_data into message and HMAC using the delimiter
        received_parts = received_data.split(b'\n')
        if len(received_parts) == HMAC_MESSAGE_LENGTH:
            # Now you have both the new challenge message and the HMAC
            received_message, received_hmac = received_parts
            received_hmac = base64_to_bytes(received_hmac)

            # Calculate HMAC
            expected_hmac_value = hmac.new(self.tunnel_symmetric_key, message, hashlib.sha256).digest()

            if expected_hmac_value != received_hmac:
                self.logger.error(f"Endpoint {self.endpoint_name}: Failed to connect to forwarder. HMAC mismatch")
                raise HMACHandshakeFailedException("HMAC handshake failed")

            # Calculate HMAC for received_message
            calculated_hmac = hmac.new(self.tunnel_symmetric_key, received_message, hashlib.sha256).digest()

            calculated_hmac_base64 = bytes_to_base64(calculated_hmac).encode()

            self.logger.debug(f"Endpoint {self.endpoint_name}: Sending calculated hmac to forwarder server "
                              f"{calculated_hmac_base64}")

            self.tls_writer.write(calculated_hmac_base64)
            await self.tls_writer.drain()

            received_data = await self.tls_reader.read(FORWARDER_BUFFER_TRUNCATION_THRESHOLD)
            self.logger.debug(f"Endpoint {self.endpoint_name}: Received data from forwarder: \n{received_data}\n")
            if received_data == b'Authenticated\n':
                self.logger.debug(f"Endpoint {self.endpoint_name}: HMAC Handshake done")
            else:
                self.logger.error(f"Endpoint {self.endpoint_name}: Failed to connect to forwarder got {received_data}")
                raise HMACHandshakeFailedException("Handshake failed. Invalid message")

        else:
            self.logger.error(f"Endpoint {self.endpoint_name}: Failed to connect to forwarder got {received_parts}")
            raise HMACHandshakeFailedException("Handshake failed. Invalid message")

        self.logger.debug(f"Endpoint {self.endpoint_name}: Connection to forwarder accepted")

    async def perform_ssl_handshakes(self):
        ssl_context = create_client_ssl_context(self.server_public_cert, self.client_public_cert,
                                                self.client_private_key_pem)
        # Establish a connection to localhost:server_port
        logging.debug(f"Endpoint {self.endpoint_name}: SSL context made")
        # Establish a connection to the TLS server on the gateway
        self.logger.debug(f"Endpoint {self.endpoint_name}: Attempting to establish TLS connection...")
        await self.tls_writer.start_tls(ssl_context, server_hostname='localhost')
        self.logger.debug(f"Endpoint {self.endpoint_name}: TLS connection established successfully.")

    async def forward_data_to_tunnel(self, con_no):
        """
        Forward data from the given connection to the TLS connection
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
                            self.tls_writer.write(buffer)
                            await self.tls_writer.drain()
                            # Yield control back to the event loop for other tasks to execute
                            await asyncio.sleep(0)
                    else:
                        # Yield control back to the event loop for other tasks to execute
                        await asyncio.sleep(0)
                except asyncio.TimeoutError as e:
                    if self._ping_attempt > 3:
                        self.is_connected = False
                        if self.server.is_serving():
                            for con in list(self.connections):
                                await self.close_connection(con)
                            self.server.close()
                        raise e
                    self.logger.debug(f"Endpoint {self.endpoint_name}: private reader timed out")
                    if self.is_connected:
                        logging.debug(f"Endpoint {self.endpoint_name}: Send private ping request")
                        self.ping_time = time.perf_counter()
                        await self.send_control_message(ControlMessage.Ping)
                    self._ping_attempt += 1
                    continue
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

    @property
    def port(self):       # type: () -> int
        if self.server and self.server.is_serving():
            ep = next((x for x in self.server.sockets if x.family == socket.AF_INET), None)
            if ep:
                return ep.getsockname()[1]
        elif self._port:
            return self._port
        return 0

    async def start_server(self, forwarder_event,   # type: asyncio.Event
                           private_tunnel_event,    # type: asyncio.Event
                           private_tunnel_started   # type: asyncio.Event
                           ):                       # type: (...) -> None
        """
        This server is used to listen for client connections to the local port.
        """
        self.server = await asyncio.start_server(self.handle_connection, family=socket.AF_INET, host=self.host,
                                                 port=self.port)
        async with self.server:
            private_tunnel_started.set()
            asyncio.create_task(self.print_ready(self.host, self.port, forwarder_event, private_tunnel_event))
            await self.server.serve_forever()

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
                          forwarder_event,      # type: asyncio.Event
                          private_tunnel_event  # type: asyncio.Event
                          ):                    # type: (...) -> None
        """
        pretty prints the endpoint name and host:port after the tunnels are set up
        """
        try:
            await asyncio.wait_for(forwarder_event.wait(), timeout=5)
        except asyncio.TimeoutError:
            self.logger.debug(f"Endpoint {self.endpoint_name}: Timed out waiting for forwarder to start")
            await self.print_not_ready()
            return
        try:
            await asyncio.wait_for(private_tunnel_event.wait(), timeout=60)
        except asyncio.TimeoutError:
            self.logger.debug(f"Endpoint {self.endpoint_name}: Timed out waiting for private tunnel to start")
            await self.print_not_ready()
            return

        if not self.server or not self.server.is_serving() if self.server else False:
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
            if self.tls_reader_task:
                self.tls_reader_task.cancel()
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
