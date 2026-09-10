import os
import unittest
from unittest import mock

from keepercommander.service.util import tunneling


class TestStartNgrok(unittest.TestCase):
    def _mock_ngrok_setup(self):
        return [
            mock.patch('keepercommander.service.util.tunneling.conf.get_default', return_value=mock.Mock(ngrok_path='/bin/ngrok')),
            mock.patch('keepercommander.service.util.tunneling.ngrok.install_ngrok'),
            mock.patch('keepercommander.service.util.tunneling.time.sleep'),
        ]

    def test_raises_when_ngrok_exits_immediately(self):
        """A dead-on-arrival ngrok process (bad token, invalid flags, ...) must be
        reported as a failure, not returned to the caller as if it started fine."""
        mock_process = mock.Mock(pid=111, returncode=1)
        mock_process.poll.return_value = 1  # process has already exited

        patches = self._mock_ngrok_setup()
        with patches[0], patches[1], patches[2], \
             mock.patch('keepercommander.service.util.tunneling.spawn_detached_process', return_value=mock_process):
            with self.assertRaises(RuntimeError):
                tunneling.start_ngrok(port=8000, auth_token='tok')

    def test_returns_pid_when_ngrok_stays_running(self):
        mock_process = mock.Mock(pid=111, returncode=None)
        mock_process.poll.return_value = None  # still running

        patches = self._mock_ngrok_setup()
        with patches[0], patches[1], patches[2], \
             mock.patch('keepercommander.service.util.tunneling.spawn_detached_process', return_value=mock_process):
            # No real process has ppid 111, so the psutil lookup falls through and
            # start_ngrok returns the wrapper PID unchanged.
            pid = tunneling.start_ngrok(port=8000, auth_token='tok')

            self.assertEqual(pid, 111)


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

    def test_foreground_mode_closes_dupd_fds_if_redirection_setup_fails_partway(self):
        """If os.dup(1)/os.dup(2) succeed but the later os.open(devnull) fails, the
        duplicated fds must be closed instead of leaked - and ngrok should still start."""
        mock_tunnel = mock.Mock(public_url='https://example.ngrok.io')
        with mock.patch('keepercommander.service.util.tunneling.ngrok.connect', return_value=mock_tunnel) as mock_connect, \
             mock.patch('keepercommander.service.util.tunneling.os.dup', side_effect=[10, 11]), \
             mock.patch('keepercommander.service.util.tunneling.os.open', side_effect=OSError("too many open files")), \
             mock.patch('keepercommander.service.util.tunneling.os.close') as mock_close:
            public_url, ngrok_pid = tunneling.generate_ngrok_url(
                port=8000, auth_token='tok', ngrok_custom_domain=None, run_mode='foreground'
            )

            self.assertEqual(public_url, 'https://example.ngrok.io')
            mock_connect.assert_called_once()
            mock_close.assert_any_call(10)
            mock_close.assert_any_call(11)


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


class TestDownloadCloudflared(unittest.TestCase):
    def test_lookup_failure_is_logged_not_swallowed_silently(self):
        # Force platform.system() to an unsupported value so _download_cloudflared
        # raises right after the (logged) lookup failure, without attempting a real download.
        with mock.patch('keepercommander.service.util.tunneling.subprocess.run',
                         side_effect=OSError("cloudflared not found")), \
             mock.patch('keepercommander.service.util.tunneling.logging.debug') as mock_debug, \
             mock.patch('platform.system', return_value='unsupported'):
            with self.assertRaises(Exception):
                tunneling._download_cloudflared()

            mock_debug.assert_called_once()
            self.assertIn('cloudflared', mock_debug.call_args[0][0])


class TestTunnelLogFiles(unittest.TestCase):
    def test_ngrok_and_cloudflare_logs_share_the_same_directory_as_the_service_log(self):
        ngrok_log = tunneling.get_tunnel_log_file('ngrok_subprocess.log')
        cloudflare_log = tunneling.get_tunnel_log_file('cloudflare_tunnel_subprocess.log')

        self.assertEqual(os.path.dirname(ngrok_log), os.path.dirname(cloudflare_log))
        self.assertEqual(os.path.dirname(ngrok_log), tunneling.TUNNEL_LOG_DIR)


if __name__ == '__main__':
    unittest.main()
