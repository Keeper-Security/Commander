import asyncio
import hashlib
import hmac
import logging
import ssl
import sys
import unittest

from cryptography.utils import int_to_bytes
from keeper_secrets_manager_core.utils import bytes_to_base64
from keepercommander import utils
from keepercommander.commands.tunnel.port_forward.endpoint import (PrivateTunnelEntrance, ControlMessage,
                                                                   CONTROL_MESSAGE_NO_LENGTH, CONNECTION_NO_LENGTH,
                                                                   HMACHandshakeFailedException,
                                                                   ConnectionNotFoundException, generate_random_bytes,
                                                                   TERMINATOR, DATA_LENGTH)
from test_pam_tunnel import generate_self_signed_cert, new_private_key
from unittest import mock


if sys.version_info >= (3, 11):
    # Only define the class if Python version is 3.8 or higher
    class TestPrivateTunnelEntrance(unittest.IsolatedAsyncioTestCase):
        async def asyncSetUp(self):
            self.event = asyncio.Event()
            self.host = 'localhost'
            self.port = 8080
            self.public_tunnel_port = 8081
            self.endpoint_name = 'TestEndpoint'

            self.private_key, self.private_key_str = new_private_key()
            self.cert = generate_self_signed_cert(self.private_key)
            self.logger = mock.MagicMock(spec=logging)
            self.kill_server_event = asyncio.Event()
            self.tunnel_symmetric_key = utils.generate_aes_key()
            self.pte = PrivateTunnelEntrance(
                self.event, self.host, self.port, self.public_tunnel_port,
                self.endpoint_name, self.cert, self.kill_server_event, self.logger, self.tunnel_symmetric_key
            )

        async def asyncTearDown(self):
            await self.pte.stop_server()  # ensure the server is stopped after test

        async def test_perform_hmac_handshake(self):
            self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)
            # Mock asyncio.open_connection
            self.pte.tls_reader = mock.MagicMock(spec=asyncio.StreamReader)
            self.pte.logger = mock.MagicMock()

            # Set side effect for read method
            message = generate_random_bytes()
            calculated_hmac = hmac.new(self.tunnel_symmetric_key, message, hashlib.sha256).digest()
            self.pte.tls_reader.read.side_effect = [message + b'\n' + bytes_to_base64(calculated_hmac).encode(), b'Authenticated\n']

            await self.pte.perform_hmac_handshakes(message)
            self.pte.logger.debug.assert_called_with('Endpoint TestEndpoint: Connection to forwarder accepted')

        async def test_send_control_message(self):
            # Initialize self.pte.tls_writer with a mock object
            self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)

            # Mock write and drain methods
            with mock.patch.object(self.pte.tls_writer, 'write', new_callable=mock.AsyncMock) as mock_write, \
                 mock.patch.object(self.pte.tls_writer, 'drain', new_callable=mock.AsyncMock) as mock_drain:

                # Define the control message and optional data
                control_message = ControlMessage.Ping
                optional_data = b'some_data'

                # Call the method to test
                await self.pte.send_control_message(control_message, optional_data)

                # Prepare the expected data that should be passed to write method
                expected_data = int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big')
                length = CONTROL_MESSAGE_NO_LENGTH + len(optional_data)
                expected_data += int.to_bytes(length , DATA_LENGTH, byteorder='big')
                expected_data += int.to_bytes(control_message, CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
                expected_data += optional_data + TERMINATOR

                # Assertions
                mock_write.assert_called_once_with(expected_data)
                mock_drain.assert_called_once()

        async def test_send_control_message_with_error(self):
            # Initialize self.pte.tls_writer with a mock object
            self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)
            self.pte.logger = mock.MagicMock()

            # Set side effect to raise an exception
            self.pte.tls_writer.drain.side_effect = Exception("Mocked Exception")

            # Define the control message and optional data
            control_message = ControlMessage.Ping
            optional_data = b'some_data'

            # Call the method to test
            await self.pte.send_control_message(control_message, optional_data)

            # Prepare the expected error log message
            expected_error_message = (f"Endpoint {self.pte.endpoint_name}: Error while sending private control message: "
                                      f"Mocked Exception")

            # Assertions
            self.pte.logger.error.assert_called_once_with(expected_error_message)

        async def test_forward_data_to_local_normal(self):
            self.pte.tls_reader = mock.MagicMock(spec=asyncio.StreamReader)
            data = b'some_data'
            self.pte.tls_reader.read.side_effect = [b'\x00\x00\x00\x01' +
                                                    int.to_bytes(len(data), DATA_LENGTH, byteorder='big') +
                                                    data + TERMINATOR, None]
            self.pte.connections = {1: (None, mock.MagicMock(spec=asyncio.StreamWriter))}
            self.pte.logger = mock.MagicMock()

            await self.pte.forward_data_to_local()

            self.pte.connections[1][1].write.assert_called_with(b'some_data')
            self.pte.connections[1][1].drain.assert_called_once()
            self.assertTrue(self.pte.logger.method_calls[3] == (mock.call.debug('Endpoint TestEndpoint: Forwarding private '
                                                                                'data to local for connection 1 (9)')))

        async def test_forward_data_to_local_error(self):
            self.pte.tls_reader = mock.MagicMock(spec=asyncio.StreamReader)
            self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)
            data = b'some_data'
            self.pte.tls_reader.read.side_effect = [b'\x00\x00\x00\x01' +
                                                    int.to_bytes(len(data), DATA_LENGTH, byteorder='big') +
                                                    data + TERMINATOR, None]
            self.pte.connections = {1: (None, self.pte.tls_writer)}
            self.pte.logger = mock.MagicMock()
            self.pte.tls_writer.write.side_effect = Exception("Some error")

            await self.pte.forward_data_to_local()

            self.pte.logger.error.assert_called_with("Endpoint TestEndpoint: Error while sending private control message: "
                                                     "Some error")

        async def test_process_close_connection_message(self):
            with mock.patch.object(self.pte, 'close_connection', new_callable=mock.AsyncMock) as mock_close:
                await self.pte.process_control_message(ControlMessage.CloseConnection,
                                                       int.to_bytes(1, byteorder='big', length=CONNECTION_NO_LENGTH))
                mock_close.assert_called_with(1)

        async def test_process_pong_message(self):
            self.pte.logger = mock.MagicMock()
            await self.pte.process_control_message(ControlMessage.Pong, b'')
            self.pte.logger.debug.assert_called_with('Endpoint TestEndpoint: Received private pong request')
            self.assertEqual(self.pte._ping_attempt, 0)
            self.assertTrue(self.pte.is_connected)

        async def test_process_ping_message(self):
            with mock.patch.object(self.pte, 'send_control_message', new_callable=mock.AsyncMock) as mock_send:
                self.pte.logger = mock.MagicMock()
                await self.pte.process_control_message(ControlMessage.Ping, b'')
                self.pte.logger.debug.assert_called_with('Endpoint TestEndpoint: Received private ping request')
                mock_send.assert_called_with(ControlMessage.Pong)

        async def test_start_tls_reader(self):
            with mock.patch('asyncio.open_connection', new_callable=mock.AsyncMock) as mock_open_connection, \
                 mock.patch.object(self.pte, 'start_server', new_callable=mock.AsyncMock) as mock_start_server:
                await self.pte.start_tls_reader()
                mock_open_connection.assert_called_with('localhost', self.public_tunnel_port)

        async def test_start_tls_reader_normal(self):
            with mock.patch('asyncio.open_connection', new_callable=mock.AsyncMock) as mock_open_connection, \
                    mock.patch.object(self.pte, 'perform_hmac_handshakes', new_callable=mock.AsyncMock) as mock_hmac, \
                    mock.patch.object(self.pte, 'perform_ssl_handshakes', new_callable=mock.AsyncMock) as mock_ssl, \
                    mock.patch.object(self.pte, 'send_control_message', new_callable=mock.AsyncMock) as mock_send, \
                    mock.patch.object(self.pte, 'forward_data_to_local', new_callable=mock.AsyncMock) as mock_forward:
                mock_open_connection.return_value = (mock.MagicMock(), mock.MagicMock())
                mock_hmac.return_value = mock.MagicMock()
                mock_ssl.return_value = mock.MagicMock()

                self.pte.logger = mock.MagicMock()

                await self.pte.start_tls_reader()

                mock_send.assert_called_with(ControlMessage.Ping)
                self.pte.logger.debug.assert_called_with('Endpoint TestEndpoint: Sent private ping message to TLS server')
                mock_forward.assert_called_once()

        async def test_start_tls_reader_connection_refused_error(self):
            with mock.patch('asyncio.open_connection', new_callable=mock.AsyncMock) as mock_open_connection, \
                    mock.patch.object(self.pte, 'stop_server', new_callable=mock.AsyncMock) as mock_stop:
                mock_open_connection.side_effect = ConnectionRefusedError
                self.pte.logger = mock.MagicMock()

                await self.pte.start_tls_reader()

                self.pte.logger.error.assert_called_with('Endpoint TestEndpoint: TLS Connection refused. '
                                                         'Ensure the server is running.')
                mock_stop.assert_called()
                self.assertFalse(self.pte.is_connected)

        async def test_start_tls_reader_timeout_error(self):
            with mock.patch('asyncio.open_connection', new_callable=mock.AsyncMock) as mock_open_connection, \
                    mock.patch.object(self.pte, 'stop_server', new_callable=mock.AsyncMock) as mock_stop:
                mock_open_connection.side_effect = TimeoutError
                self.pte.logger = mock.MagicMock()

                await self.pte.start_tls_reader()

                self.pte.logger.error.assert_called_with('Endpoint TestEndpoint: TLS Connection timed out. '
                                                         'Check the server and network.')
                mock_stop.assert_called()
                self.assertFalse(self.pte.is_connected)

        async def test_start_tls_reader_os_error(self):
            with mock.patch('asyncio.open_connection', new_callable=mock.AsyncMock) as mock_open_connection, \
                    mock.patch.object(self.pte, 'stop_server', new_callable=mock.AsyncMock) as mock_stop:
                mock_open_connection.side_effect = OSError("Some OS Error")
                self.pte.logger = mock.MagicMock()

                await self.pte.start_tls_reader()

                self.pte.logger.error.assert_called_with('Endpoint TestEndpoint: TLS Error connecting: Some OS Error')
                mock_stop.assert_called()
                self.assertFalse(self.pte.is_connected)

        async def test_start_tls_reader_hmac_handshake_failed(self):
            with mock.patch('asyncio.open_connection', new_callable=mock.AsyncMock) as mock_open_connection, \
                    mock.patch.object(self.pte, 'stop_server', new_callable=mock.AsyncMock) as mock_stop, \
                    mock.patch.object(self.pte, 'perform_hmac_handshakes', new_callable=mock.AsyncMock) as mock_hmac:
                mock_open_connection.return_value = (mock.MagicMock(), mock.MagicMock())
                mock_hmac.side_effect = HMACHandshakeFailedException("HMAC Failed")
                self.pte.logger = mock.MagicMock()

                await self.pte.start_tls_reader()

                self.pte.logger.error.assert_called_with('Endpoint TestEndpoint: HMAC Handshake failed: HMAC Failed')
                mock_stop.assert_called()
                self.assertFalse(self.pte.is_connected)

        async def test_start_tls_reader_generic_exception(self):
            with mock.patch('asyncio.open_connection', new_callable=mock.AsyncMock) as mock_open_connection, \
                    mock.patch.object(self.pte, 'perform_hmac_handshakes', new_callable=mock.AsyncMock) as mock_hmac, \
                    mock.patch.object(self.pte, 'close_connection', new_callable=mock.AsyncMock) as mock_close, \
                    mock.patch.object(self.pte, 'stop_server', new_callable=mock.AsyncMock) as mock_stop:
                mock_open_connection.return_value = (mock.MagicMock(), mock.MagicMock())
                mock_hmac.side_effect = Exception("Some generic exception")
                self.pte.logger = mock.MagicMock()

                await self.pte.start_tls_reader()

                self.pte.logger.error.assert_called_with('Endpoint TestEndpoint: Error while establishing TLS connection: '
                                                         'Some generic exception')
                mock_stop.assert_called()
                self.assertFalse(self.pte.is_connected)

        async def test_perform_ssl_handshakes_success(self):
            self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)
            self.pte.logger = mock.MagicMock()
            with mock.patch('ssl.SSLContext') as mock_ssl_context:
                mock_context = mock.MagicMock()
                mock_ssl_context.return_value = mock_context

                await self.pte.perform_ssl_handshakes()

                mock_context.load_verify_locations.assert_called_with(cadata=self.pte.server_public_cert)
                self.pte.tls_writer.start_tls.assert_called_with(mock_context, server_hostname='localhost')
                self.pte.logger.debug.assert_called_with('Endpoint TestEndpoint: TLS connection established successfully.')

        async def test_perform_ssl_handshakes_start_tls_exception(self):
            self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)
            # Pass bytes as the first argument
            self.pte.tls_writer.start_tls.side_effect = asyncio.IncompleteReadError(b'', 1)
            with mock.patch('ssl.create_default_context') as mock_ssl_context:
                mock_context = mock.MagicMock()
                mock_ssl_context.return_value = mock_context

                with self.assertRaises(asyncio.IncompleteReadError):
                    await self.pte.perform_ssl_handshakes()

        async def test_perform_ssl_handshakes_load_verify_locations_exception(self):
            with mock.patch('ssl.SSLContext', new_callable=mock.MagicMock) as MockSSLContext:
                # No need to specify spec here, as MockSSLContext is already a mock of ssl.SSLContext
                mock_context = MockSSLContext.return_value

                # Set the side effect for the load_verify_locations method
                mock_context.load_verify_locations.side_effect = FileNotFoundError

                self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)
                # Mock asyncio.open_connection
                self.pte.tls_reader = mock.MagicMock(spec=asyncio.StreamReader)

                with self.assertRaises(FileNotFoundError):
                    await self.pte.perform_ssl_handshakes()

        # Test SSL Context Creation Failure
        async def test_perform_ssl_handshakes_context_failure(self):
            with mock.patch('ssl.create_default_context', side_effect=Exception("Context Error")):
                with self.assertRaises(Exception):
                    await self.pte.perform_ssl_handshakes()

        # Test Certificate Loading Failure
        async def test_perform_ssl_handshakes_cert_failure(self):
            with mock.patch('ssl.create_default_context') as mock_ssl_context:
                mock_context = mock.MagicMock()
                mock_context.load_verify_locations.side_effect = Exception("Cert Error")
                mock_ssl_context.return_value = mock_context
                with self.assertRaises(Exception):
                    await self.pte.perform_ssl_handshakes()

        # Test Server Hostname Mismatch
        async def test_perform_ssl_handshakes_hostname_mismatch(self):
            self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)
            self.pte.tls_writer.start_tls.side_effect = ssl.SSLCertVerificationError("Hostname mismatch")
            with mock.patch('ssl.create_default_context') as mock_ssl_context:
                mock_context = mock.MagicMock()
                mock_ssl_context.return_value = mock_context
                with self.assertRaises(ssl.SSLCertVerificationError):
                    await self.pte.perform_ssl_handshakes()

        # Test Successful Data Forwarding
        async def test_forward_data_to_tunnel_success(self):
            async def read_side_effect_gen(*args, **kwargs):
                yield b'hello world'
                while True:
                    await asyncio.sleep(1)

            # Create an instance of the generator
            read_gen = read_side_effect_gen()

            # Define the side effect function to use the generator
            async def read_side_effect(*args, **kwargs):
                return await read_gen.__anext__()

            mock_reader = mock.AsyncMock(spec=asyncio.StreamReader)
            mock_reader.read.side_effect = read_side_effect
            self.pte.tls_writer = mock.AsyncMock(spec=asyncio.StreamWriter)
            self.pte.connections[1] = (mock_reader, self.pte.tls_writer)

            # Run the task and wait for it to complete
            task = asyncio.create_task(self.pte.forward_data_to_tunnel(1))
            await asyncio.sleep(0.1)  # Give some time for the task to run
            task.cancel()  # Cancel the task to stop it from running indefinitely

            self.pte.tls_writer.write.assert_called()
            self.pte.tls_writer.drain.assert_called()

        # Test Connection Not Found
        async def test_forward_data_to_tunnel_no_connection(self):
            self.pte.connections = {}
            self.pte.tls_writer = mock.AsyncMock(spec=asyncio.StreamWriter)
            with self.assertRaises(ConnectionNotFoundException):
                await self.pte.forward_data_to_tunnel(1)

        # Test Timeout Error
        async def test_forward_data_to_tunnel_timeout_error(self):
            async def read_side_effect(*args, **kwargs):
                raise asyncio.TimeoutError()

            mock_reader = mock.AsyncMock(spec=asyncio.StreamReader)
            mock_reader.read.side_effect = read_side_effect
            mock_writer = mock.AsyncMock(spec=asyncio.StreamWriter)
            self.pte.connections[1] = (mock_reader, mock_writer)

            # Mock send_control_message method
            with mock.patch.object(self.pte, 'send_control_message',
                                   new_callable=mock.AsyncMock) as mock_send_control_message:
                await self.pte.forward_data_to_tunnel(1)

                # Assert that send_control_message was called with ControlMessage.Ping three times
                # and then with ControlMessage.CloseConnection
                expected_calls = [
                    mock.call(ControlMessage.Ping),
                    mock.call(ControlMessage.Ping),
                    mock.call(ControlMessage.Ping),
                    mock.call(ControlMessage.CloseConnection, int.to_bytes(1, CONNECTION_NO_LENGTH, byteorder='big'))
                ]
                mock_send_control_message.assert_has_calls(expected_calls)

        # Test Generic Exception
        async def test_forward_data_to_tunnel_generic_exception(self):
            async def read_side_effect(*args, **kwargs):
                raise Exception("Some generic exception")

            mock_reader = mock.AsyncMock(spec=asyncio.StreamReader)
            mock_reader.read.side_effect = read_side_effect
            mock_writer = mock.AsyncMock(spec=asyncio.StreamWriter)
            self.pte.connections[1] = (mock_reader, mock_writer)
            # Mock send_control_message method
            with mock.patch.object(self.pte, 'send_control_message',
                                   new_callable=mock.AsyncMock) as mock_send_control_message:
                await self.pte.forward_data_to_tunnel(1)

                # Assert that send_control_message was called with ControlMessage.Ping
                mock_send_control_message.assert_called_with(ControlMessage.CloseConnection,
                                                             int.to_bytes(1, CONNECTION_NO_LENGTH, byteorder='big'))

        # Test handle_connection
        async def test_handle_connection(self):
            mock_reader = mock.AsyncMock(spec=asyncio.StreamReader)
            mock_writer = mock.AsyncMock(spec=asyncio.StreamWriter)
            mock_send_control_message = mock.AsyncMock()
            mock_forward_data_to_tunnel = mock.AsyncMock()

            with mock.patch.object(self.pte, 'send_control_message', mock_send_control_message):
                await self.pte.handle_connection(mock_reader, mock_writer)

                # Check if send_control_message was called
                mock_send_control_message.assert_called_with(
                    ControlMessage.OpenConnection,
                    int.to_bytes(1, CONNECTION_NO_LENGTH, byteorder='big')
                )

        async def test_handle_connection_exception(self):
            mock_reader = mock.AsyncMock(spec=asyncio.StreamReader)
            mock_writer = mock.AsyncMock(spec=asyncio.StreamWriter)

            with mock.patch.object(self.pte, 'send_control_message', side_effect=Exception("Test Exception")), \
                    mock.patch.object(self.pte, 'forward_data_to_tunnel', side_effect=Exception("Test Exception")):
                with self.assertRaises(Exception):
                    await self.pte.handle_connection(mock_reader, mock_writer)

        # Test start_server
        async def test_start_server(self):
            with mock.patch('asyncio.start_server', new_callable=mock.AsyncMock) as mock_start_server:
                await self.pte.start_server(mock.AsyncMock(), mock.AsyncMock(), mock.AsyncMock())
                mock_start_server.assert_called()

        # Test start_server with Exception
        async def test_start_server_exception(self):
            with mock.patch('asyncio.start_server', side_effect=Exception("Test Exception")):
                with self.assertRaises(Exception):
                    await self.pte.start_server(mock.AsyncMock(), mock.AsyncMock(), mock.AsyncMock())

        # Test print_not_ready
        async def test_print_not_ready(self):
            with mock.patch.object(self.pte, 'send_control_message',
                                   new_callable=mock.AsyncMock) as mock_send_control_message:
                await self.pte.print_not_ready()
                mock_send_control_message.assert_called_with(ControlMessage.CloseConnection, int_to_bytes(0))

        # Test print_ready
        async def test_print_ready(self):
            with mock.patch('builtins.print') as mock_print:
                await self.pte.print_ready('localhost', 8080, mock.AsyncMock(), mock.AsyncMock())

            # Check if print was called (optional)
            mock_print.assert_called()

        # Test print_ready with TimeoutError
        async def test_print_ready_timeout_error_forwarder(self):
            forwarder_event = mock.AsyncMock(spec=asyncio.Event)
            forwarder_event.wait.side_effect = asyncio.TimeoutError()
            private_tunnel_event = mock.AsyncMock(spec=asyncio.Event)
            with mock.patch.object(self.pte, 'print_not_ready', new_callable=mock.AsyncMock) as mock_print_not_ready:
                await self.pte.print_ready('localhost', 8080, forwarder_event, private_tunnel_event)

            # Check if logger.debug was called
            self.pte.logger.debug.assert_called_with("Endpoint TestEndpoint: Timed out waiting for forwarder to start")
            # Check if print was called (optional)
            mock_print_not_ready.assert_called()

        # Test print_ready with TimeoutError
        async def test_print_ready_timeout_error_private_tunnel(self):
            forwarder_event = mock.AsyncMock(spec=asyncio.Event)
            private_tunnel_event = mock.AsyncMock(spec=asyncio.Event)
            private_tunnel_event.wait.side_effect = asyncio.TimeoutError()
            with mock.patch.object(self.pte, 'print_not_ready', new_callable=mock.AsyncMock) as mock_print_not_ready:
                await self.pte.print_ready('localhost', 8080, forwarder_event, private_tunnel_event)

            # Check if logger.debug was called
            self.pte.logger.debug.assert_called_with("Endpoint TestEndpoint: Timed out waiting for private tunnel to start")
            # Check if print was called (optional)
            mock_print_not_ready.assert_called()

        # Test stop_server
        async def test_stop_server(self):
            self.pte.server = mock.AsyncMock(spec=asyncio.Server)
            with mock.patch.object(self.pte.server, 'close', new_callable=mock.AsyncMock) as mock_close, \
                 mock.patch.object(self.pte.server, 'wait_closed', new_callable=mock.AsyncMock) as mock_wait_closed:
                await self.pte.stop_server()
                mock_close.assert_called()
                mock_wait_closed.assert_called()

        # Test stop_server with Exception
        async def test_stop_server_exception(self):
            self.pte.server = mock.AsyncMock(spec=asyncio.Server)
            with mock.patch.object(self.pte.server, 'close', side_effect=Exception("Test Exception")):
                with self.assertRaises(Exception):
                    await self.pte.stop_server()

        # Test close_connection
        async def test_close_connection(self):
            self.pte.connections[1] = (mock.AsyncMock(), mock.AsyncMock())
            await self.pte.close_connection(1)
            self.assertNotIn(1, self.pte.connections)

        # Test close_connection with Connection Not Found
        async def test_close_connection_not_found(self):
            await self.pte.close_connection(9999)  # 9999 is not in self.connections

            # Check if logger.info was called
            self.pte.logger.info.assert_called_with("Endpoint TestEndpoint: Private tasks for 9999 not found")
