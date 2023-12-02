import sys
import unittest
from unittest import mock

if sys.version_info >= (3, 15):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from keeper_secrets_manager_core.utils import base64_to_bytes
    from keepercommander.commands.tunnel.port_forward.tunnel import ITunnel
    from keepercommander.commands.tunnel.port_forward.endpoint import (ControlMessage, CONTROL_MESSAGE_NO_LENGTH,
                                                                       DATA_LENGTH, CONNECTION_NO_LENGTH, TunnelProtocol,
                                                                       TERMINATOR, find_server_public_key)


    # Only define the class if Python version is 3.8 or higher
    def make_private_key():
        private_key = ec.generate_private_key(
            ec.SECP256R1(),  # Using P-256 curve
            backend=default_backend()
        )
        return private_key

    class TestPublicTunnel(unittest.IsolatedAsyncioTestCase):

        async def asyncSetUp(self):
            # Initialize mock objects and test setup
            self.mock_tunnel = mock.AsyncMock(spec=ITunnel)
            self.mock_logger = mock.Mock()

            self.mock_tunnel.is_connected = True
            self.client_private_key = make_private_key()
            self.client_private_key_str = self.client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            self.gateway_public_key = make_private_key().public_key().public_bytes(encoding=serialization.Encoding.X962,
                                                                                   format=serialization.PublicFormat.
                                                                                   UncompressedPoint)

            self.tunnel_protocol = TunnelProtocol(self.mock_tunnel,  endpoint_name="Test Public",
                                                  logger=self.mock_logger,
                                                  gateway_public_key_bytes=self.gateway_public_key,
                                                  client_private_key=self.client_private_key_str, host="localhost",
                                                  port=8080)

            self.tunnel_protocol.private_tunnel_server = mock.AsyncMock()
            self.tunnel_protocol.read_connection_task = mock.AsyncMock()

            self.tunnel_protocol.server_public_key = find_server_public_key(
                self.tunnel_protocol.gateway_public_key_bytes)
            self.tunnel_protocol.establish_symmetric_key()

        async def asyncTearDown(self):
            await self.tunnel_protocol.disconnect()

        async def test_connect(self):
            self.mock_tunnel.is_connected = False
            with mock.patch.object(self.tunnel_protocol, 'start_tunnel_reader', return_value=None) as mock_start_reader, \
                 mock.patch.object(self.tunnel_protocol, 'disconnect', return_value=None) as mock_disconnect:

                await self.tunnel_protocol.connect()

                self.mock_tunnel.connect.assert_called_once()
                mock_start_reader.assert_called_once()
                mock_disconnect.assert_called_once()

        async def test_disconnect(self):
            with mock.patch.object(self.tunnel_protocol, 'send_control_message', return_value=None) as mock_send_control:
                await self.tunnel_protocol.disconnect()
                mock_send_control.assert_called_once_with(ControlMessage.CloseConnection)
                self.assertTrue(self.tunnel_protocol.kill_server_event.is_set())

        async def test_start_tunnel_reader_control(self):
            # build data for a ping control message
            data = b''
            data1 = int.to_bytes(ControlMessage.Ping, CONTROL_MESSAGE_NO_LENGTH, byteorder='big') + data
            buffer = int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big')
            buffer += int.to_bytes(len(data1), DATA_LENGTH, byteorder='big')
            buffer += data1 + TERMINATOR

            self.tunnel_protocol.tunnel.read = mock.AsyncMock()
            self.tunnel_protocol.tunnel.read.side_effect = [base64_to_bytes(self.tunnel_protocol.tunnel_encrypt(buffer)), None]
            with mock.patch.object(self.tunnel_protocol, 'process_control_message', return_value=None) as mock_process:
                await self.tunnel_protocol.start_tunnel_reader()
                self.mock_tunnel.read.assert_called()
                mock_process.assert_called_with(ControlMessage.Ping, data)

        async def test_send_to_tunnel(self):
            await self.tunnel_protocol._send_to_tunnel(1, b'data')
            self.mock_tunnel.write.assert_called_once()

        async def test_send_control_message(self):
            with mock.patch.object(self.tunnel_protocol, '_send_to_tunnel', return_value=None) as mock_send_to_tunnel:
                await self.tunnel_protocol.send_control_message(ControlMessage.Ping)
                mock_send_to_tunnel.assert_called_once()

        async def test_process_control_message(self):
            with mock.patch.object(self.tunnel_protocol, 'send_control_message', return_value=None) as mock_send_control:
                await self.tunnel_protocol.process_control_message(ControlMessage.Ping, b'')
                mock_send_control.assert_called_once_with(ControlMessage.Pong)
