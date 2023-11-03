import socket
import string
import unittest
from unittest import mock
from keepercommander.commands.tunnel.port_forward.endpoint import (generate_random_bytes, find_open_port)


class TestVerifyTLSCertificate(unittest.TestCase):
    # TODO: Test that the TLS certificate is verified correctly when we figure it out
    def test_verify_tls_certificate(self):
        pass


class TestFindOpenPort(unittest.TestCase):
    def mock_bind(self, address):
        # Mock the behavior of socket.socket.bind
        port = address[1]
        if port in self.in_use_ports:
            raise OSError("Address already in use")
        else:
            print(f"Port {port} bound successfully.")

    def test_preferred_port(self):
        # Test that the function returns the preferred port if it's available
        preferred_port = 50000
        open_port = find_open_port([], preferred_port=preferred_port)
        self.assertEqual(open_port, preferred_port)

    def test_preferred_port_unavailable(self):
        # Mock the bind method to simulate that port 80 is in use
        with mock.patch('socket.socket.bind', side_effect=OSError("Address already in use")):
            preferred_port = 80
            open_port = find_open_port([], preferred_port=preferred_port)
            self.assertIsNone(open_port)

    def test_range(self):
        # Test that the function returns a port within the specified range
        start_port = 50000
        end_port = 50010
        open_port = find_open_port([], start_port=start_port, end_port=end_port)
        self.assertTrue(start_port <= open_port <= end_port)

    def test_no_available_ports(self):
        # Setup
        self.in_use_ports = set(range(50000, 50011))  # All these ports are in use

        # Patch
        with mock.patch.object(socket.socket, 'bind', side_effect=self.mock_bind):
            # Test
            open_port = find_open_port([], start_port=50000, end_port=50010)
            self.assertIsNone(open_port)

    def test_invalid_range(self):
        # Test that the function returns None if the range is invalid
        open_port = find_open_port([], start_port=50010, end_port=50000)
        self.assertIsNone(open_port)

    def test_socket_exception(self):
        # Test that the function handles exceptions other than OSError gracefully
        with mock.patch('socket.socket.bind', side_effect=Exception("Test exception")):
            open_port = find_open_port([])
            self.assertIsNone(open_port)

    def test_tried_ports(self):
        # Setup
        self.in_use_ports = {50000, 50001}  # These ports are in use

        # Patch
        with mock.patch.object(socket.socket, 'bind', side_effect=self.mock_bind):
            # Test
            open_port = find_open_port([50000, 50001], start_port=50000, end_port=50002)
            self.assertEqual(open_port, 50002)


class TestGenerateRandomBytes(unittest.TestCase):

    def test_default_length(self):
        # Test that the default length of the returned bytes is 32
        random_bytes = generate_random_bytes()
        self.assertEqual(len(random_bytes), 32, f'Length 32 failed found {len(random_bytes)} in '
                                                f'{random_bytes}')

    def test_custom_length(self):
        # Test custom lengths
        for length in [1, 10, 20, 50, 100]:
            random_bytes = generate_random_bytes(length)
            self.assertEqual(len(random_bytes), length, f'Length {length} failed found {len(random_bytes)} in '
                                                        f'{random_bytes}')

    def test_content(self):
        # Test that the returned bytes only contain printable characters
        for length in [1, 10, 20, 50, 100]:
            random_bytes = generate_random_bytes(length)
            self.assertTrue(all(byte in string.printable.encode('utf-8') for byte in random_bytes))

    def test_zero_length(self):
        # Test that a zero length returns an empty bytes object
        random_bytes = generate_random_bytes(0)
        self.assertEqual(random_bytes, b'')

    def test_negative_length(self):
        # Test that a negative length raises a ValueError
        with self.assertRaises(ValueError):
            generate_random_bytes(-1)

    def test_type(self):
        # Test that the return type is bytes
        random_bytes = generate_random_bytes()
        self.assertIsInstance(random_bytes, bytes)

    def test_uniqueness(self):
        # Test that multiple calls return different values
        random_bytes1 = generate_random_bytes()
        random_bytes2 = generate_random_bytes()
        self.assertNotEqual(random_bytes1, random_bytes2)
