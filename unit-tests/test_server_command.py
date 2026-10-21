import unittest
from types import SimpleNamespace
from unittest import mock

from keepercommander import cli


class TestServerCommand(unittest.TestCase):
    def test_can_change_server_to_self_hosted_host_before_login(self):
        params = SimpleNamespace(session_token=None, server='keepersecurity.com')
        server_url = 'https://smk.example.test'

        with mock.patch('keepercommander.cli.resolve_server', return_value=server_url) as resolve:
            cli.do_command(params, 'server smk.example.test')

        resolve.assert_called_once_with('smk.example.test')
        self.assertEqual(params.server, server_url)

    def test_cannot_change_server_while_logged_in(self):
        params = SimpleNamespace(session_token='session-token', server='keepersecurity.com')

        with mock.patch('keepercommander.cli.resolve_server') as resolve:
            with self.assertLogs(level='WARNING') as logs:
                cli.do_command(params, 'server smk.example.test')

        resolve.assert_not_called()
        self.assertEqual(params.server, 'keepersecurity.com')
        self.assertIn('Cannot change Keeper server while logged in', logs.output[0])


if __name__ == '__main__':
    unittest.main()
