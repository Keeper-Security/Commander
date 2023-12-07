import sys
import unittest
from unittest import mock

if sys.version_info >= (3, 15):
    import asyncio
    import logging
    import socket

    from aiortc import RTCDataChannel
    from cryptography.utils import int_to_bytes
    from keepercommander import utils
    from keepercommander.commands.tunnel.port_forward.endpoint import (TunnelEntrance, ControlMessage,
                                                                       CONTROL_MESSAGE_NO_LENGTH, CONNECTION_NO_LENGTH,
                                                                       ConnectionNotFoundException,
                                                                       TERMINATOR, DATA_LENGTH, WebRTCConnection)
    from test_pam_tunnel import new_private_key

    # Only define the class if Python version is 3.8 or higher
    class TestPrivateTunnelEntrance(unittest.IsolatedAsyncioTestCase):
        async def asyncSetUp(self):
            self.host = 'localhost'
            self.port = 8080
            self.endpoint_name = 'TestEndpoint'

            self.private_key, self.private_key_str = new_private_key()
            self.logger = mock.MagicMock(spec=logging)
            self.kill_server_event = asyncio.Event()
            self.tunnel_symmetric_key = utils.generate_aes_key()
            self.pc = mock.MagicMock(sepc=WebRTCConnection)
            self.pc.data_channel.readyState = 'open'
            self.incoming_queue = mock.MagicMock(sepc=asyncio.Queue())
            self.print_ready_event = asyncio.Event()
            self.pte = TunnelEntrance(self.host, self.port, self.endpoint_name, self.pc,
                                      self.print_ready_event, self.logger)

        async def set_queue_side_effect(self):
            data = b'some_data'

            async def mock_incoming_queue_get():
                # First yield
                yield b'\x00\x00\x00\x01' + int.to_bytes(len(data), DATA_LENGTH, byteorder='big') + data + TERMINATOR
                # Second yield
                yield None

            # Now use an iterator of this coroutine function as the side effect
            self.pte.pc.web_rtc_queue.get.side_effect = mock_incoming_queue_get().__anext__

        async def asyncTearDown(self):
            await self.pte.stop_server()  # ensure the server is stopped after test

        async def test_send_control_message(self):
            # Initialize self.pte.tls_writer with a mock object
            self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)

            # Mock write and drain methods
            with mock.patch.object(self.pte.pc.data_channel, 'send', new_callable=mock.AsyncMock) as mock_send:

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
                mock_send.assert_called_once_with(expected_data)

        async def test_send_control_message_with_error(self):
            # Initialize self.pte.tls_writer with a mock object
            self.pte.tls_writer = mock.MagicMock(spec=asyncio.StreamWriter)
            self.pte.logger = mock.MagicMock()

            # Set side effect to raise an exception
            self.pte.pc.data_channel.send.side_effect = Exception("Mocked Exception")

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
            await self.set_queue_side_effect()

            self.pte.connections = {1: (None, mock.MagicMock(spec=asyncio.StreamWriter))}
            self.pte.logger = mock.MagicMock()
            self.pte.kill_server_event = mock.MagicMock(spec=asyncio.Event)
            self.pte.kill_server_event.is_set.side_effect = [False, False, True]

            await self.pte.forward_data_to_local()

            self.pte.connections[1][1].write.assert_called_with(b'some_data')
            self.pte.connections[1][1].drain.assert_called_once()
            self.assertTrue(self.pte.logger.method_calls[3] == (mock.call.debug('Endpoint TestEndpoint: Forwarding private '
                                                                                'data to local for connection 1 (9)')))

        async def test_forward_data_to_local_error(self):
            await self.set_queue_side_effect()
            self.pte.connections = {1: (None, mock.MagicMock(spec=asyncio.StreamWriter))}
            self.pte.logger = mock.MagicMock()
            self.pte.kill_server_event = mock.MagicMock(spec=asyncio.Event)
            self.pte.kill_server_event.is_set.side_effect = [False, False, True]
            self.pte.connections[1][1].write.side_effect = Exception("Some error")

            await self.pte.forward_data_to_local()

            self.pte.logger.error.assert_called_with("Endpoint TestEndpoint: Error while forwarding private data to "
                                                     "local: Some error")

        async def test_process_close_connection_message(self):
            with mock.patch.object(self.pte, 'close_connection', new_callable=mock.AsyncMock) as mock_close:
                await self.pte.process_control_message(ControlMessage.CloseConnection,
                                                       int.to_bytes(1, byteorder='big', length=CONNECTION_NO_LENGTH))
                mock_close.assert_called_with(1)

        async def test_process_pong_message(self):
            self.pte.logger = mock.MagicMock()
            await self.pte.process_control_message(ControlMessage.Pong, b'')
            expected_calls = [
                mock.call('Endpoint TestEndpoint: Received private pong request')
            ]
            self.pte.logger.debug.assert_has_calls(expected_calls)
            self.assertEqual(self.pte._ping_attempt, 0)
            self.assertTrue(self.pte.is_connected)

        async def test_process_ping_message(self):
            with mock.patch.object(self.pte, 'send_control_message', new_callable=mock.AsyncMock) as mock_send:
                self.pte.logger = mock.MagicMock()
                await self.pte.process_control_message(ControlMessage.Ping, b'')
                self.pte.logger.debug.assert_called_with('Endpoint TestEndpoint: Received private ping request')
                mock_send.assert_called_with(ControlMessage.Pong)

        async def test_start_server(self):
            with mock.patch('asyncio.start_server', new_callable=mock.AsyncMock) as mock_open_connection, \
                 mock.patch.object(self.pte, 'handle_connection', new_callable=mock.AsyncMock) as mock_handle_connection:
                await self.pte.start_server()
                mock_open_connection.assert_called_with(mock_handle_connection, family=socket.AF_INET,
                                                        host='localhost', port=self.port)

        async def test_start_server_normal(self):
            with mock.patch('asyncio.start_server', new_callable=mock.AsyncMock) as mock_open_connection, \
                    mock.patch.object(self.pte, 'print_ready', new_callable=mock.AsyncMock) as print_ready:
                mock_open_connection.return_value = mock.MagicMock(spec=asyncio.Server)

                self.pte.logger = mock.MagicMock()

                await self.pte.start_server()

                print_ready.assert_called_once()

        async def test_start_server_connection_refused_error(self):
            with mock.patch('asyncio.start_server', new_callable=mock.AsyncMock) as mock_start_server, \
                    mock.patch.object(self.pte, 'stop_server', new_callable=mock.AsyncMock) as mock_stop:
                mock_start_server.side_effect = ConnectionRefusedError
                self.pte.logger = mock.MagicMock()

                await self.pte.start_server()

                self.pte.logger.error.assert_called_with('Endpoint TestEndpoint: Connection Refused while starting '
                                                         'server: ')
                mock_stop.assert_called()
                self.assertTrue(self.pte.server is None)

        async def test_start_server_timeout_error(self):
            with mock.patch('asyncio.start_server', new_callable=mock.AsyncMock) as mock_start_server, \
                    mock.patch.object(self.pte, 'stop_server', new_callable=mock.AsyncMock) as mock_stop:
                mock_start_server.side_effect = TimeoutError
                self.pte.logger = mock.MagicMock()

                await self.pte.start_server()

                self.pte.logger.error.assert_called_with('Endpoint TestEndpoint: OS Error while starting server: ')
                mock_stop.assert_called()
                self.assertTrue(self.pte.server is None)

        async def test_start_server_os_error(self):
            with mock.patch('asyncio.start_server', new_callable=mock.AsyncMock) as mock_start_server, \
                    mock.patch.object(self.pte, 'stop_server', new_callable=mock.AsyncMock) as mock_stop:
                mock_start_server.side_effect = OSError("Some OS Error")
                self.pte.logger = mock.MagicMock()

                await self.pte.start_server()

                self.pte.logger.error.assert_called_with('Endpoint TestEndpoint: OS Error while starting server: '
                                                         'Some OS Error')
                mock_stop.assert_called()
                self.assertTrue(self.pte.server is None)

        async def test_start_server_generic_exception(self):
            with mock.patch('asyncio.start_server', new_callable=mock.AsyncMock) as mock_start_server, \
                    mock.patch.object(self.pte, 'stop_server', new_callable=mock.AsyncMock) as mock_stop:
                mock_start_server.side_effect = Exception("Some generic exception")
                self.pte.logger = mock.MagicMock()

                await self.pte.start_server()

                self.pte.logger.error.assert_called_with('Endpoint TestEndpoint: Error while starting server: '
                                                         'Some generic exception')
                mock_stop.assert_called()
                self.assertTrue(self.pte.server is None)

        # Test Successful Data Forwarding
        async def test_forward_data_to_tunnel_success(self):

            async def read_side_effect_gen():
                yield b'hello world'  # First yield the required data
                while True:  # Then keep the coroutine alive without yielding further
                    await asyncio.sleep(1)

            # Create an instance of the generator
            read_gen = read_side_effect_gen()

            # Define an async function to handle the generator
            async def read_side_effect(*args, **kwargs):
                return await read_gen.asend(None)  # Use 'asend' to forward any args/kwargs if necessary

            # Mock StreamReader and set the side effect to the new async function
            mock_reader = mock.AsyncMock(spec=asyncio.StreamReader)
            mock_reader.read.side_effect = read_side_effect

            self.pte.connections[1] = (mock_reader, mock.AsyncMock(spec=asyncio.StreamWriter))

            self.pte.kill_server_event = mock.MagicMock(spec=asyncio.Event)
            self.pte.kill_server_event.is_set.side_effect = [False, False, True]
            self.pte.pc = mock.MagicMock(spec=WebRTCConnection)
            self.pte.pc.data_channel = mock.MagicMock(spec=RTCDataChannel)
            self.pte.pc.data_channel.readyState = 'open'

            # Run the task and wait for it to complete
            task = asyncio.create_task(self.pte.forward_data_to_tunnel(1))
            await asyncio.sleep(.01)  # Give some time for the task to run
            task.cancel()  # Cancel the task to stop it from running indefinitely

            self.pte.pc.data_channel.send.assert_called_with(b'\x00\x00\x00\x01\x00\x00\x00\x0bhello world;')

        # Test Connection Not Found
        async def test_forward_data_to_tunnel_no_connection(self):
            self.pte.connections = {}
            self.pte.tls_writer = mock.AsyncMock(spec=asyncio.StreamWriter)
            with self.assertRaises(ConnectionNotFoundException):
                await self.pte.forward_data_to_tunnel(1)

        # Test Timeout Error
        async def test_forward_data_to_tunnel_timeout_error(self):

            await self.set_queue_side_effect()
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

        # Test print_not_ready
        async def test_print_not_ready(self):
            with mock.patch.object(self.pte, 'send_control_message',
                                   new_callable=mock.AsyncMock) as mock_send_control_message:
                await self.pte.print_not_ready()
                mock_send_control_message.assert_called_with(ControlMessage.CloseConnection, int_to_bytes(0))

        # Test print_ready
        async def test_print_ready(self):
            with mock.patch('builtins.print') as mock_print:
                await self.pte.print_ready('localhost', 8080, mock.AsyncMock())

            # Check if print was called (optional)
            mock_print.assert_called()

        # Test print_ready with TimeoutError
        async def test_print_ready_timeout_error_forwarder(self):
            print_event = mock.AsyncMock(spec=asyncio.Event)
            print_event.wait.side_effect = asyncio.TimeoutError()
            with mock.patch.object(self.pte, 'print_not_ready', new_callable=mock.AsyncMock) as mock_print_not_ready:
                await self.pte.print_ready('localhost', 8080, print_event)

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
