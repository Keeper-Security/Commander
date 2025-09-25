import sys
if sys.version_info >= (3, 8):
    import pytest
    from unittest import TestCase, mock
    from flask import Flask
    from keepercommander.service.decorators.auth import auth_check, policy_check
    from keepercommander.service.decorators.security import security_check, is_allowed_ip
    from keepercommander.service.util.config_reader import ConfigReader

    class TestAuthSecurity(TestCase):
        def setUp(self):
            self.app = Flask(__name__)
            self.client = self.app.test_client()
            
            @self.app.route('/test', methods=['POST'])
            @security_check
            @auth_check
            @policy_check
            def test_endpoint():
                return {'status': 'success'}, 200

        def test_auth_check_missing_api_key(self):
            """Test authentication with missing API key"""
            with self.app.test_request_context('/test', method='POST'):
                response = auth_check(lambda *args, **kwargs: ({'status': 'success'}, 200))()
                self.assertEqual(response[1], 401)
                self.assertEqual(response[0]['status'], 'error')
                self.assertIn('api key', response[0]['error'])

        @mock.patch.object(ConfigReader, 'read_config')
        def test_auth_check_invalid_api_key(self, mock_read_config):
            """Test authentication with invalid API key"""
            mock_read_config.return_value = "different_key"
            
            with self.app.test_request_context('/test', method='POST', 
                                            headers={'api-key': 'test_key'}):
                response = auth_check(lambda *args, **kwargs: ({'status': 'success'}, 200))()
                self.assertEqual(response[1], 401)
                self.assertEqual(response[0]['status'], 'error')

        @mock.patch.object(ConfigReader, 'read_config')
        def test_auth_check_expired_key(self, mock_read_config):
            """Test authentication with expired API key"""
            mock_read_config.side_effect = [
                "test_key",
                "2024-01-01T00:00:00"
            ]
            
            with self.app.test_request_context('/test', method='POST', 
                                            headers={'api-key': 'test_key'}):
                response = auth_check(lambda *args, **kwargs: ({'status': 'success'}, 200))()
                self.assertEqual(response[1], 401)
                self.assertEqual(response[0]['status'], 'error')
                self.assertIn('expired', response[0]['error'])

        # def test_security_check_blocked_ip(self):
        #     """Test security check with blocked IP"""
        #     with mock.patch.object(ConfigReader, 'read_config', return_value="192.168.1.1"):
        #         with self.app.test_request_context('/test', method='POST', 
        #                                         environ_base={'REMOTE_ADDR': '192.168.1.1'}):
        #             response = security_check(lambda *args, **kwargs: ({'status': 'success'}, 200))()
        #             response_data = response[0].get_json()
        #             self.assertEqual(response[1], 403) 
        #             self.assertEqual(response_data['error'], 'IP is blocked')

        def test_is_blocked_ip_single_ip(self):
            """Test IP blocking with single IP address"""
            blocked_ips = "192.168.1.1"
            allowed_ips="192.168.1.2"
            self.assertFalse(is_allowed_ip("192.168.1.1", allowed_ips, blocked_ips))
            self.assertTrue(is_allowed_ip("192.168.1.2", allowed_ips, blocked_ips))

        def test_is_blocked_ip_cidr(self):
            """Test IP blocking with CIDR notation"""
            allowed_ips="192.168.1.1"
            blocked_ips = "192.168.1.0"
            self.assertTrue(is_allowed_ip("192.168.1.1", allowed_ips, blocked_ips))
            self.assertFalse(is_allowed_ip("192.168.1.254", allowed_ips, blocked_ips))
            self.assertFalse(is_allowed_ip("192.168.2.1", allowed_ips, blocked_ips))

        @mock.patch.object(ConfigReader, 'read_config')
        def test_policy_check_allowed_command(self, mock_read_config):
            """Test policy check with allowed command"""
            mock_read_config.return_value = "list,get,search"
            
            with self.app.test_request_context('/test', method='POST',
                                            json={"command": "list"}):
                response = policy_check(lambda *args, **kwargs: ({'status': 'success'}, 200))()
                self.assertEqual(response[1], 200)
                self.assertEqual(response[0]['status'], 'success')

        @mock.patch.object(ConfigReader, 'read_config')
        def test_policy_check_denied_command(self, mock_read_config):
            """Test policy check with denied command"""
            mock_read_config.return_value = "list,get,search"
            
            with self.app.test_request_context('/test', method='POST',
                                            json={"command": "delete"}):
                response = policy_check(lambda *args, **kwargs: ({'status': 'success'}, 200))()
                self.assertEqual(response[1], 403)
                self.assertEqual(response[0]['status'], 'error')
                self.assertIn('Not permitted', response[0]['error'])