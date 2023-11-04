import asyncio
import hashlib
import hmac
import sys
import unittest
from keeper_secrets_manager_core.utils import bytes_to_base64
from keepercommander import utils
from keepercommander.commands.tunnel.port_forward.tunnel import ITunnel
from keepercommander.commands.tunnel.port_forward.endpoint import (ControlMessage, CONTROL_MESSAGE_NO_LENGTH,
                                                                   DATA_LENGTH, CONNECTION_NO_LENGTH, TunnelProtocol,
                                                                   TERMINATOR, PlainTextForwarder,
                                                                   generate_random_bytes)
from unittest import mock


if sys.version_info >= (3, 11):
    # Only define the class if Python version is 3.8 or higher
    class TestPublicTunnel(unittest.IsolatedAsyncioTestCase):

        async def asyncSetUp(self):
            # Initialize mock objects and test setup
            self.mock_tunnel = mock.AsyncMock(spec=ITunnel)
            self.mock_logger = mock.Mock()

            self.mock_tunnel.is_connected = True
            self.tunnel_protocol = TunnelProtocol(self.mock_tunnel, logger=self.mock_logger)

            self.tunnel_protocol.private_tunnel_server = mock.AsyncMock()
            self.tunnel_protocol.read_connection_task = mock.AsyncMock()
            self.tunnel_protocol.forwarder_task = mock.AsyncMock()

        async def asyncTearDown(self):
            await self.tunnel_protocol.disconnect()

        async def test_connect(self):
            self.mock_tunnel.is_connected = False
            with mock.patch.object(self.tunnel_protocol, 'start_tunnel_reader', return_value=None) as mock_start_reader, \
                 mock.patch.object(self.tunnel_protocol, 'disconnect', return_value=None) as mock_disconnect:

                await self.tunnel_protocol.connect("localhost", 8080)

                self.mock_tunnel.connect.assert_called_once()
                mock_start_reader.assert_called_once()
                mock_disconnect.assert_called_once()

        async def test_disconnect(self):
            with mock.patch.object(self.tunnel_protocol, 'send_control_message', return_value=None) as mock_send_control:
                await self.tunnel_protocol.disconnect()
                mock_send_control.assert_called_once_with(ControlMessage.CloseConnection)
                self.assertFalse(self.tunnel_protocol._is_running)

        async def test_start_tunnel_reader_control(self):
            # build data for a ping control message
            data = b''
            data1 = int.to_bytes(ControlMessage.Ping, CONTROL_MESSAGE_NO_LENGTH, byteorder='big') + data
            buffer = int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big')
            buffer += int.to_bytes(len(data1), DATA_LENGTH, byteorder='big')
            buffer += data1 + TERMINATOR

            self.tunnel_protocol.tunnel.read = mock.AsyncMock()
            self.tunnel_protocol.tunnel.read.side_effect = [buffer, None]
            with mock.patch.object(self.tunnel_protocol, 'process_control_message', return_value=None) as mock_process:
                await self.tunnel_protocol.start_tunnel_reader()
                self.mock_tunnel.read.assert_called()
                mock_process.assert_called_with(ControlMessage.Ping, data)

        async def test_start_tunnel_reader_data(self):
            self.tunnel_protocol.tunnel.read = mock.AsyncMock()
            self.tunnel_protocol.tunnel.read.side_effect = [b'\x00\x00\x00\x01\x00\x00\x00\x04data;', None]
            await self.tunnel_protocol.start_tunnel_reader()
            self.mock_tunnel.read.assert_called()
            self.assertTrue(self.tunnel_protocol.forwarder_incoming_queue.qsize() == 1)
            data = self.tunnel_protocol.forwarder_incoming_queue.get_nowait()
            self.assertEqual(data, b'data')

        async def test_send_to_tunnel(self):
            await self.tunnel_protocol._send_to_tunnel(1, b'data')
            self.mock_tunnel.write.assert_called_once_with(b'\x00\x00\x00\x01\x00\x00\x00\x04data;')

        async def test_send_data_message(self):
            self.tunnel_protocol._paired = True
            with mock.patch.object(self.tunnel_protocol, '_send_to_tunnel', return_value=None) as mock_send_to_tunnel:
                await self.tunnel_protocol.send_data_message(b'data')
                mock_send_to_tunnel.assert_called_once_with(1, b'data')

        async def test_send_control_message(self):
            with mock.patch.object(self.tunnel_protocol, '_send_to_tunnel', return_value=None) as mock_send_to_tunnel:
                await self.tunnel_protocol.send_control_message(ControlMessage.Ping)
                mock_send_to_tunnel.assert_called_once()

        async def test_read_connection(self):
            self.tunnel_protocol._is_running = True

            # Mock send_data_message and send_control_message to avoid actual data sending
            with mock.patch.object(self.tunnel_protocol, 'send_data_message', return_value=None) as mock_send_data, \
                    mock.patch.object(self.tunnel_protocol, 'send_control_message', return_value=None) as mock_send_control:
                # Create a task for read_connection
                read_task = asyncio.create_task(self.tunnel_protocol.read_connection())

                # Simulate normal behavior by putting data into the queue
                self.tunnel_protocol.forwarder_out_going_queue.put_nowait(b'data')
                await asyncio.sleep(0.1)  # Give time for the loop to process the data
                mock_send_data.assert_called_once_with(b'data')

                # Simulate a break condition by putting an empty byte string into the queue
                self.tunnel_protocol.forwarder_out_going_queue.put_nowait(b'')
                await asyncio.sleep(0.1)  # Give time for the loop to break

                # Ensure the task has completed
                self.assertTrue(read_task.done())

                # Check if ControlMessage.CloseConnection was sent
                mock_send_control.assert_called_once_with(ControlMessage.CloseConnection)

        async def test_process_control_message(self):
            with mock.patch.object(self.tunnel_protocol, 'send_control_message', return_value=None) as mock_send_control:
                await self.tunnel_protocol.process_control_message(ControlMessage.Ping, b'')
                mock_send_control.assert_called_once_with(ControlMessage.Pong)

        async def test_read_connection_with_exception(self):
            self.tunnel_protocol._is_running = True

            # Mock send_data_message and send_control_message to avoid actual data sending
            with mock.patch.object(self.tunnel_protocol, 'send_data_message',
                                   side_effect=Exception("Mock Exception")) as mock_send_data, \
                    mock.patch.object(self.tunnel_protocol, 'send_control_message', return_value=None) as mock_send_control:
                # Create a task for read_connection
                read_task = asyncio.create_task(self.tunnel_protocol.read_connection())

                # Simulate normal behavior by putting data into the queue
                self.tunnel_protocol.forwarder_out_going_queue.put_nowait(b'data')
                await asyncio.sleep(0.1)  # Give time for the loop to process the data

                # Ensure the task has completed
                self.assertTrue(read_task.done())

                # Check if ControlMessage.CloseConnection was sent
                mock_send_control.assert_called_once_with(ControlMessage.CloseConnection)

                # Check if the logger was called due to the exception
                self.mock_logger.debug.assert_called_with('Endpoint None: closed')

        async def test_read_connection_with_invalid_data(self):
            self.tunnel_protocol._is_running = True

            # Mock send_data_message to avoid actual data sending
            with mock.patch.object(self.tunnel_protocol, 'send_data_message', return_value=None) as mock_send_data:
                # Create a task for read_connection
                read_task = asyncio.create_task(self.tunnel_protocol.read_connection())

                # Simulate putting a string into the queue
                self.tunnel_protocol.forwarder_out_going_queue.put_nowait('data')
                read_task.cancel()
                await asyncio.sleep(0.1)  # Give time for the loop to process the data

                # Ensure the task has completed
                self.assertTrue(read_task.done())

                # Check that send_data_message was not called
                mock_send_data.assert_not_called()

        async def test_read_connection_with_empty_queue(self):
            self.tunnel_protocol._is_running = True

            # Mock send_data_message to avoid actual data sending
            with mock.patch.object(self.tunnel_protocol, 'send_data_message', return_value=None) as mock_send_data:
                # Create a task for read_connection
                read_task = asyncio.create_task(self.tunnel_protocol.read_connection())
                await asyncio.sleep(0.1)  # Give time for the loop to process the data

                # Check that send_data_message was not called
                mock_send_data.assert_not_called()

        async def test_read_connection_with_is_running_false(self):
            self.tunnel_protocol._is_running = False

            # Mock send_data_message to avoid actual data sending
            with mock.patch.object(self.tunnel_protocol, 'send_data_message', return_value=None) as mock_send_data:
                # Create a task for read_connection
                read_task = asyncio.create_task(self.tunnel_protocol.read_connection())
                await asyncio.sleep(0.1)  # Give time for the loop to process the data

                # Check that send_data_message was not called
                mock_send_data.assert_not_called()

        async def test_read_connection_with_multiple_data(self):
            self.tunnel_protocol._is_running = True

            # Mock send_data_message to avoid actual data sending
            with mock.patch.object(self.tunnel_protocol, 'send_data_message', return_value=None) as mock_send_data:
                # Create a task for read_connection
                read_task = asyncio.create_task(self.tunnel_protocol.read_connection())

                # Simulate normal behavior by putting multiple data into the queue
                self.tunnel_protocol.forwarder_out_going_queue.put_nowait(b'data1')
                self.tunnel_protocol.forwarder_out_going_queue.put_nowait(b'data2')
                await asyncio.sleep(0.1)  # Give time for the loop to process the data

                # Check that send_data_message was called twice
                self.assertEqual(mock_send_data.call_count, 2)


    class TestPlainTextForwarder(unittest.IsolatedAsyncioTestCase):

        async def asyncSetUp(self):
            # Setup common resources
            self.forwarder_event = asyncio.Event()
            self.out_going_queue = asyncio.Queue()
            self.incoming_queue = asyncio.Queue()
            self.logger = mock.MagicMock()
            self.plain_text_forwarder = PlainTextForwarder(
                self.forwarder_event, 8080, self.logger,
                self.out_going_queue, self.incoming_queue, kill_sever_event=mock.MagicMock(),
                tunnel_symmetric_key=utils.generate_aes_key()
            )

        async def test_non_localhost_connection(self):
            # Setup
            mock_reader = mock.AsyncMock(spec=asyncio.StreamReader)
            mock_writer = mock.AsyncMock(spec=asyncio.StreamWriter)
            mock_writer.get_extra_info.return_value = ('192.168.1.1', 12345)  # Mocking a remote host connection

            # Execution
            await self.plain_text_forwarder.forwarder_handle_client(mock_reader, mock_writer)

            # Verification
            mock_writer.close.assert_called_once()  # Assert that the connection was closed
            mock_writer.wait_closed.assert_called_once()  # Assert that the close was awaited

        async def test_valid_connection_from_localhost(self):
            # Setup
            mock_reader = mock.AsyncMock(spec=asyncio.StreamReader)
            mock_writer = mock.AsyncMock(spec=asyncio.StreamWriter)
            mock_writer.get_extra_info.return_value = ('127.0.0.1', 12345)  # Mocking a localhost connection

            message = generate_random_bytes()
            calculated_hmac = hmac.new(self.plain_text_forwarder.tunnel_symmetric_key, message, hashlib.sha256).digest()

            # Define a side effect for mock_reader.read
            hmac_code = bytes_to_base64(calculated_hmac).encode()

            mock_reader.read.side_effect = [message, hmac_code]

            # Execution
            await self.plain_text_forwarder.forwarder_handle_client(mock_reader, mock_writer, message)

            # Verification
            self.assertTrue(len(self.plain_text_forwarder.client_tasks) == 2)  # Assert that the client task was removed
            mock_writer.close.assert_not_called()  # Assert that the connection was not closed
            await self.plain_text_forwarder.stop()  # Close the forwarder
            self.assertTrue(len(self.plain_text_forwarder.client_tasks) == 0)  # Assert that the client task was removed

        async def test_bad_hmac(self):
            mock_reader = mock.AsyncMock(spec=asyncio.StreamReader)
            mock_writer = mock.AsyncMock(spec=asyncio.StreamWriter)
            # Simulate data from the client
            mock_reader.read.return_value = b'message\nhmac'

            await self.plain_text_forwarder.forwarder_handle_client(mock_reader, mock_writer)

            mock_writer.close.assert_called_once()  # Assert that the connection was closed
            self.assertTrue(len(self.plain_text_forwarder.client_tasks) == 0)  # Assert that the client task was removed

        async def test_start(self):
            with mock.patch('asyncio.start_server') as mock_start_server:
                await self.plain_text_forwarder.start()
                mock_start_server.assert_called_once_with(
                    self.plain_text_forwarder.forwarder_handle_client, '0.0.0.0', 8080
                )

                # Verification
                self.assertTrue(self.plain_text_forwarder.forwarder_server.is_serving())
                await self.plain_text_forwarder.stop()
                self.assertTrue(self.plain_text_forwarder.forwarder_server is None)
                self.assertTrue(self.plain_text_forwarder.client_tasks == [])
