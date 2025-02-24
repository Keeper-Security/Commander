import sys
if sys.version_info >= (3, 8):
    import unittest
    from unittest.mock import patch
    import socket
    from datetime import timedelta
    from keepercommander.service.config.config_validation import ConfigValidator
    from keepercommander.service.util.exceptions import ValidationError

    class TestConfigValidator(unittest.TestCase):
        def setUp(self):
            self.validator = ConfigValidator()

        def test_validate_port_valid(self):
            """Test port validation with valid port numbers"""
            test_ports = [80, 443, 8080, 1024, 65535]
            for port in test_ports:
                with self.subTest(port=port):
                    with patch('socket.socket') as mock_socket:
                        mock_socket.return_value.__enter__.return_value.bind.return_value = None
                        result = self.validator.validate_port(port)
                        self.assertEqual(result, port)

        def test_validate_port_invalid_number(self):
            """Test port validation with invalid port numbers"""
            invalid_ports = [-1, 65536, 'abc', '']
            for port in invalid_ports:
                with self.subTest(port=port):
                    with self.assertRaises(ValidationError):
                        self.validator.validate_port(port)

        def test_validate_port_in_use(self):
            """Test port validation when port is already in use"""
            with patch('socket.socket') as mock_socket:
                mock_socket.return_value.__enter__.return_value.bind.side_effect = socket.error()
                with self.assertRaises(ValidationError) as context:
                    self.validator.validate_port(8080)
                self.assertIn("is already in use", str(context.exception))

        def test_validate_ngrok_token_valid(self):
            """Test ngrok token validation with valid tokens"""
            valid_tokens = [
                '1234567890abcdef',
                'abcdef1234567890',
                'abc123_def456-789'
            ]
            for token in valid_tokens:
                with self.subTest(token=token):
                    result = self.validator.validate_ngrok_token(token)
                    self.assertEqual(result, token)

        def test_validate_ngrok_token_invalid(self):
            """Test ngrok token validation with invalid tokens"""
            invalid_tokens = [
                '',
                '123',
                'abc@def',
                None
            ]
            for token in invalid_tokens:
                with self.subTest(token=token):
                    with self.assertRaises(ValidationError):
                        self.validator.validate_ngrok_token(token)

        def test_validate_rate_limit_valid(self):
            """Test rate limit validation with valid formats"""
            valid_limits = [
                '10/minute',
                '100/hour',
                '1000/day',
                '50 per minute',
                '200 per hour',
                '5000 per day'
            ]
            for limit in valid_limits:
                with self.subTest(limit=limit):
                    result = self.validator.validate_rate_limit(limit)
                    self.assertEqual(result, limit)

        def test_validate_rate_limit_invalid(self):
            """Test rate limit validation with invalid formats"""
            invalid_limits = [
                'abc',
                '10/second',
                '100 by hour',
            ]
            for limit in invalid_limits:
                with self.subTest(limit=limit):
                    with self.assertRaises(ValidationError):
                        self.validator.validate_rate_limit(limit)

        def test_validate_ip_list_valid(self):
            """Test IP list validation with valid IPs and CIDR blocks"""
            valid_ips = [
                '192.168.1.1',
                '10.0.0.0/24',
                '192.168.1.1,10.0.0.0/24',
                '2001:db8::1',
                'fe80::/10'
            ]
            for ip_list in valid_ips:
                with self.subTest(ip_list=ip_list):
                    result = self.validator.validate_ip_list(ip_list)
                    self.assertEqual(result, ip_list)

        def test_validate_ip_list_invalid(self):
            """Test IP list validation with invalid IPs"""
            invalid_ips = [
                '256.256.256.256',
                '192.168.1',
                '2001:xyz::1',
                '192.168.1.1/33',
            ]
            for ip_list in invalid_ips:
                with self.subTest(ip_list=ip_list):
                    with self.assertRaises(ValidationError):
                        self.validator.validate_ip_list(ip_list)

        def test_validate_encryption_key_valid(self):
            """Test encryption key validation with valid keys"""
            valid_key = 'abcdef1234567890ABCDEF1234567890'
            result = self.validator.validate_encryption_key(valid_key)
            self.assertEqual(result, valid_key)

        def test_validate_encryption_key_invalid(self):
            """Test encryption key validation with invalid keys"""
            invalid_keys = [
                '',
                '123456',
                'a' * 31,
                'a' * 33,
                'abc$%^&*()',
                None
            ]
            for key in invalid_keys:
                with self.subTest(key=key):
                    with self.assertRaises(ValidationError):
                        self.validator.validate_encryption_key(key)

        def test_parse_expiration_time_valid(self):
            """Test expiration time parsing with valid formats"""
            test_cases = [
                ('30m', timedelta(minutes=30)),
                ('24h', timedelta(hours=24)),
                ('7d', timedelta(days=7))
            ]
            for input_str, expected in test_cases:
                with self.subTest(input_str=input_str):
                    result = self.validator.parse_expiration_time(input_str)
                    self.assertEqual(result, expected)

        def test_parse_expiration_time_invalid(self):
            """Test expiration time parsing with invalid formats"""
            invalid_times = [
                '',
                '30x',
                '-30m',
                '0m',
                'abc',
            ]
            for time_str in invalid_times:
                with self.subTest(time_str=time_str):
                    with self.assertRaises(ValidationError):
                        self.validator.parse_expiration_time(time_str)