import os
import unittest
from unittest import mock

from keepercommander.service.util import tunneling


class TestGenerateNgrokUrl(unittest.TestCase):
    def test_background_mode_skips_fd_redirection_and_uses_subprocess(self):
        with mock.patch('keepercommander.service.util.tunneling.start_ngrok_with_url',
                         return_value=(1234, 'https://example.ngrok.io')) as mock_start, \
             mock.patch('keepercommander.service.util.tunneling.os.dup') as mock_dup:
            public_url, ngrok_pid = tunneling.generate_ngrok_url(
                port=8000, auth_token='tok', ngrok_custom_domain=None, run_mode='background'
            )

            self.assertEqual(public_url, 'https://example.ngrok.io')
            self.assertEqual(ngrok_pid, 1234)
            mock_start.assert_called_once_with(port=8000, auth_token='tok')
            # Background mode must not touch the process's own stdout/stderr fds -
            # doing so previously corrupted the interactive shell's console on Windows.
            mock_dup.assert_not_called()

    def test_foreground_mode_uses_pyngrok_connect(self):
        mock_tunnel = mock.Mock(public_url='https://example.ngrok.io')
        with mock.patch('keepercommander.service.util.tunneling.ngrok.connect', return_value=mock_tunnel) as mock_connect, \
             mock.patch('keepercommander.service.util.tunneling.os.dup', side_effect=[1, 2]), \
             mock.patch('keepercommander.service.util.tunneling.os.dup2'), \
             mock.patch('keepercommander.service.util.tunneling.os.open', return_value=3), \
             mock.patch('keepercommander.service.util.tunneling.os.close'):
            public_url, ngrok_pid = tunneling.generate_ngrok_url(
                port=8000, auth_token='tok', ngrok_custom_domain=None, run_mode='foreground'
            )

            self.assertEqual(public_url, 'https://example.ngrok.io')
            self.assertIsNone(ngrok_pid)
            mock_connect.assert_called_once()

    def test_missing_port_or_token_raises(self):
        with self.assertRaises(ValueError):
            tunneling.generate_ngrok_url(port=None, auth_token='tok', ngrok_custom_domain=None, run_mode='background')
        with self.assertRaises(ValueError):
            tunneling.generate_ngrok_url(port=8000, auth_token=None, ngrok_custom_domain=None, run_mode='background')


class TestGenerateCloudflareUrl(unittest.TestCase):
    def test_returns_public_url_and_pid_in_correct_order(self):
        # start_cloudflare_tunnel_with_url returns (pid, url); generate_cloudflare_url
        # must swap that to (url, pid) to match what CloudflareConfigurator expects.
        with mock.patch('keepercommander.service.util.tunneling.start_cloudflare_tunnel_with_url',
                         return_value=(4321, 'https://tunnel.example.com')):
            public_url, tunnel_pid = tunneling.generate_cloudflare_url(
                port=8000, tunnel_token='tok', custom_domain=None, run_mode='background'
            )

            self.assertEqual(public_url, 'https://tunnel.example.com')
            self.assertEqual(tunnel_pid, 4321)

    def test_missing_port_raises(self):
        with self.assertRaises(ValueError):
            tunneling.generate_cloudflare_url(port=None, tunnel_token='tok', custom_domain=None, run_mode='background')

    def test_missing_tunnel_token_raises(self):
        with self.assertRaises(ValueError):
            tunneling.generate_cloudflare_url(port=8000, tunnel_token='  ', custom_domain=None, run_mode='background')


class TestTunnelLogFiles(unittest.TestCase):
    def test_ngrok_and_cloudflare_logs_share_the_same_directory_as_the_service_log(self):
        ngrok_log = tunneling.get_tunnel_log_file('ngrok_subprocess.log')
        cloudflare_log = tunneling.get_tunnel_log_file('cloudflare_tunnel_subprocess.log')

        self.assertEqual(os.path.dirname(ngrok_log), os.path.dirname(cloudflare_log))
        self.assertEqual(os.path.dirname(ngrok_log), tunneling.TUNNEL_LOG_DIR)


if __name__ == '__main__':
    unittest.main()
