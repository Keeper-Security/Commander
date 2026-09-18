import unittest
from unittest import mock

from keepercommander.error import CommandError
from keepercommander.commands.tunnel_and_connections import PAMTunnelDiagnoseCommand

import datetime
import socket
import string
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from keepercommander.commands.tunnel.port_forward.tunnel_helpers import (generate_random_bytes, find_open_port)

def generate_self_signed_cert(private_key):
    # Generate a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    return cert_pem


def new_private_key():
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
    return private_key, private_key_str


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
            with self.assertRaises(CommandError):
                open_port = find_open_port([], preferred_port=preferred_port)

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
            open_port = find_open_port([], start_port=49152, end_port=49153, host='localhost')
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


class TestPAMTunnelDiagnose(unittest.TestCase):
    def test_execute_passes_session_proxy_to_https_probes(self):
        proxies = {'http': 'http://proxy.example:8080', 'https': 'http://proxy.example:8080'}
        params = mock.MagicMock()
        params.server = 'keepersecurity.com'
        params.rest_context.proxies = proxies
        params.ssl_verify = '/path/to/ca.pem'

        with mock.patch('keepercommander.commands.tunnel_and_connections.get_relay_host',
                        return_value='relay.example'), \
                mock.patch('keepercommander.commands.tunnel_and_connections.get_router_host',
                           return_value='router.example'), \
                mock.patch('keepercommander.commands.tunnel_and_connections.get_or_create_tube_registry',
                           return_value=None), \
                mock.patch('keepercommander.commands.tunnel_and_connections.socket.getaddrinfo',
                           return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('203.0.113.1', 0))]), \
                mock.patch('keepercommander.commands.tunnel_and_connections.socket.gethostbyname',
                           return_value='203.0.113.1'), \
                mock.patch.object(PAMTunnelDiagnoseCommand, '_test_https',
                                  return_value=(True, 'reachable', 1)) as test_https, \
                mock.patch.object(PAMTunnelDiagnoseCommand, '_test_websocket',
                                  return_value=(True, 'reachable', 1)) as test_websocket, \
                mock.patch.object(PAMTunnelDiagnoseCommand, '_test_tcp_stun',
                                  return_value=(True, 'reachable', 1, None)), \
                mock.patch.object(PAMTunnelDiagnoseCommand, '_test_udp_stun',
                                  return_value=(True, 'reachable', 1, None)), \
                mock.patch.object(PAMTunnelDiagnoseCommand, '_test_turn',
                                  return_value=(True, 'reachable', 1)), \
                mock.patch.object(PAMTunnelDiagnoseCommand, '_test_udp_port',
                                  return_value=(True, 1)):
            PAMTunnelDiagnoseCommand().execute(params)

        test_https.assert_called_once_with(
            'keepersecurity.com', proxies=proxies, verify='/path/to/ca.pem')
        test_websocket.assert_called_once_with(
            'router.example', proxies=proxies, verify='/path/to/ca.pem')

    def test_https_uses_configured_proxy(self):
        proxies = {'http': 'http://proxy.example:8080', 'https': 'http://proxy.example:8080'}
        with mock.patch('keepercommander.commands.tunnel_and_connections.requests.get') as mock_get:
            mock_get.return_value.status_code = 200

            passed, _, _ = PAMTunnelDiagnoseCommand._test_https(
                'api.example', proxies=proxies, verify='/path/to/ca.pem')

        self.assertTrue(passed)
        mock_get.assert_called_once_with(
            'https://api.example:443/',
            headers={'User-Agent': 'keeper-pam-diagnose/1.0'},
            proxies=proxies,
            verify='/path/to/ca.pem',
            timeout=10,
            stream=True,
        )

    def test_websocket_uses_configured_proxy(self):
        proxies = {'http': 'http://proxy.example:8080', 'https': 'http://proxy.example:8080'}
        with mock.patch('keepercommander.commands.tunnel_and_connections.requests.get') as mock_get:
            mock_get.return_value.status_code = 101

            passed, _, _ = PAMTunnelDiagnoseCommand._test_websocket(
                'router.example', proxies=proxies, verify='/path/to/ca.pem')

        self.assertTrue(passed)
        mock_get.assert_called_once_with(
            'https://router.example:443/',
            headers={
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13',
                'User-Agent': 'keeper-pam-diagnose/1.0',
            },
            proxies=proxies,
            verify='/path/to/ca.pem',
            timeout=10,
            stream=True,
        )
