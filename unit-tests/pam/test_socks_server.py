import asyncio
import logging
import sys
import unittest
from unittest import mock
from unittest.mock import Mock

if sys.version_info >= (3, 8):
    from keepercommander.commands.tunnel.port_forward.endpoint import WebRTCConnection, \
        CloseConnectionReasons

    from keepercommander.commands.tunnel.port_forward.endpoint import SOCKS5Server


    class TestSOCKSServer(unittest.IsolatedAsyncioTestCase):
        async def asyncSetUp(self):

            # Set up asyncio event loop for testing
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.host = 'localhost'
            self.port = 8080
            self.kill_server_event = asyncio.Event()
            self.connect_task = mock.MagicMock(spec=asyncio.Task)
            self.logger = mock.MagicMock(spec=logging)
            self.kill_server_event = asyncio.Event()
            self.pc = mock.MagicMock(sepc=WebRTCConnection)
            self.pc.endpoint_name = 'TestEndpoint'
            self.pc.data_channel.readyState = 'open'
            self.pc.data_channel.bufferedAmount = 0
            self.print_ready_event = asyncio.Event()
            self.pte = SOCKS5Server(self.host, self.port, self.pc, self.print_ready_event, self.logger,
                                    self.connect_task, self.kill_server_event)

            self.reader = mock.AsyncMock()
            self.writer = mock.AsyncMock()

        async def asyncTearDown(self):
            await self.pte.stop_server(CloseConnectionReasons.Normal)  # ensure the server is stopped after test

        # def test_username_password_authenticate(self):
        #     # Example test for the username/password authentication method
        #
        #     # Mock reader and writer streams
        #     reader = mock.AsyncMock()
        #     writer = mock.AsyncMock()
        #
        #     # Mock the reader to simulate client sending authentication data
        #     reader.readexactly.side_effect = [
        #         b'\x01',  # Auth version
        #         b'\x0A',  # Username length
        #         b'defaultuser',  # Username
        #         b'\x0B',  # Password length
        #         b'defaultpass'  # Password
        #     ]
        #
        #     # Run the coroutine and get the result
        #     result = asyncio.run(self.pte.username_password_authenticate(reader, writer))
        #
        #     # Assert the authentication was successful
        #     self.assertTrue(result)

        # def test_successful_authentication(self):
        #     # Setup mock to simulate reading data from the reader
        #     self.reader.readexactly.side_effect = [
        #         b'\x01',  # Auth version
        #         b'\x0A',  # Username length
        #         b'defaultuser',  # Username
        #         b'\x0B',  # Password length
        #         b'defaultpass'  # Password
        #     ]
        #
        #     result = asyncio.run(self.pte.username_password_authenticate(self.reader, self.writer))
        #     self.assertTrue(result)
        #     # Check for success response
        #     self.writer.write.assert_called_with(b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')

        # def test_failed_authentication_wrong_credentials(self):
        #     # Setup mock with incorrect credentials
        #     self.reader.readexactly.side_effect = [
        #         b'\x01',  # Auth version
        #         b'\x07',  # Incorrect username length
        #         b'wrong',  # Incorrect username
        #         b'\x06',  # Incorrect password length
        #         b'123456'  # Incorrect password
        #     ]
        #     result = asyncio.run(self.pte.username_password_authenticate(self.reader, self.writer))
        #     self.assertFalse(result)
        #     # Check for failure response
        #     self.writer.write.assert_called_with(b'\x01\x01\x00\x01\x00\x00\x00\x00\x00\x00')
        #
        # def test_failed_authentication_bad_version(self):
        #     self.reader.readexactly.side_effect = [b'\x02']  # Incorrect auth version
        #
        #     result = asyncio.run(self.pte.username_password_authenticate(self.reader, self.writer))
        #     self.assertFalse(result)
        #     # This test assumes the function just returns False without sending a specific response for bad version

        async def test_handle_connection(self):

            self.writer.get_extra_info = Mock(return_value=('127.0.0.1', 12345))
            # Simulate the client's greeting and authentication method request
            self.reader.read.side_effect = [
                b'\x05\x01',  # SOCKS version 5, 1 authentication method supported
                b'\x05\x01\x00\x03'  # SOCKS version 5, 1 method selected, No Auth
            ]
            self.reader.readexactly.side_effect = [
                b'\x00\x02',  # No Auth and Username/Password methods
                b'\x0b',  # length of the domain name
                b'example.com',  # Domain name
                b'\x00\x50'  # port 80
            ]
            await self.pte.handle_connection(self.reader, self.writer)
            self.assertTrue(self.writer.write.called)

        # async def test_handle_connection_with_authentication(self):
        #     self.writer.get_extra_info = Mock(return_value=('127.0.0.1', 12345))
        #     # Simulate the client's greeting indicating Username/Password method supported and chosen
        #     self.reader.readexactly.side_effect = [
        #         b'\x02',  # Username/Password method
        #         b'\x01',  # Auth version
        #         b'\x09',  # Username length
        #         b'defaultuser',  # Username
        #         b'\x08',  # Password length
        #         b'defaultpass',  # Password
        #         b'\x0b',  # length of the domain name
        #         b'example.com',  # Domain name
        #         b'\x00\x50'  # port 80
        #     ]
        #
        #     self.reader.read.side_effect = [
        #         b'\x05\x01',  # SOCKS version 5, 2 authentication methods supported
        #         b'\x05\x01\x00\x03',  # SOCKS version 5, 1 method selected, No Auth, domain name address type
        #     ]
        #
        #     await self.pte.handle_connection(self.reader, self.writer)
        #     # Example assertion, adjust based on your protocol implementation
        #     # Assert success authentication response
        #     self.writer.write.assert_any_call(b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')

        async def test_handle_connection_with_unsupported_auth(self):
            self.writer.get_extra_info = Mock(return_value=('127.0.0.1', 12345))
            # Simulate the client's greeting with an unsupported authentication method
            self.reader.readexactly.side_effect = [
                b'\x03'  # An unsupported authentication method, e.g., GSSAPI
            ]

            self.reader.read.side_effect = [
                b'\x05\x01',  # SOCKS version 5, 1 authentication methods supported
            ]

            await self.pte.handle_connection(self.reader, self.writer)
            self.writer.write.assert_any_call(b'\x05\xff')  # Response indicating no acceptable methods

        async def test_handle_connection_with_invalid_version(self):
            self.writer.get_extra_info = Mock(return_value=('127.0.0.1', 12345))
            # Simulate the client's greeting with an invalid SOCKS version
            self.reader.read.side_effect = [
                b'\x03\x01',  # Invalid SOCKS version, e.g., SOCKS4
                b'\x00'  # No Auth method
            ]

            await self.pte.handle_connection(self.reader, self.writer)
            # Response indicating no acceptable methods
            self.writer.write.assert_any_call(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')
            self.writer.close.assert_called()  # Connection closed without proceeding

        async def test_handle_connection_with_unsupported_address_type(self):
            self.writer.get_extra_info = Mock(return_value=('127.0.0.1', 12345))
            # Simulate a SOCKS connection request with an unsupported address type
            self.reader.readexactly.side_effect = [
                b'\x00\x02',  # No Auth and Username/Password methods
                b'\x05',  # Unsupported address type (e.g., X.25)
            ]
            self.reader.read.side_effect = [
                b'\x05\x02',  # SOCKS version 5, 2 authentication methods supported
                b'\x05\x01\x00\x05',  # SOCKS version 5, 1 method selected, No Auth
            ]

            await self.pte.handle_connection(self.reader, self.writer)
            # Server response error for unsupported address type
            self.writer.write.assert_any_call(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')

        async def test_unsupported_command(self):
            # Simulate a SOCKS request with an unsupported command
            self.reader.readexactly.side_effect = [
                b'\x00',  # No Auth method
                b'\x0b',  # Length of the domain name
                b'example.com',  # Domain name
                b'\x00',
                b'\x50'  # Port 80
            ]

            self.reader.read.side_effect = [
                b'\x05\x01',  # SOCKS version 5, 2 authentication methods supported
                b'\x05\x02\x00\x03',  # Unsupported command (0x02 for BIND, as an example), domain name address type
            ]

            self.writer.get_extra_info = Mock(return_value=('127.0.0.1', 12345))

            await self.pte.handle_connection(self.reader, self.writer)
            # Check for a response indicating a command not supported error
            # 07 indicating a command not supported error
            self.writer.write.assert_any_call(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
