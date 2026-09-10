import unittest
from unittest import mock

from keepercommander.__main__ import main


class TestServiceModeDispatch(unittest.TestCase):
    """The frozen background-service subprocess is detected via an explicit argv flag
    (SERVICE_MODE_FLAG), not an env var - see service_app.py for why."""

    def test_frozen_with_internal_flag_runs_background_service_and_returns(self):
        with mock.patch('sys.frozen', True, create=True), \
             mock.patch('sys._MEIPASS', '/frozen/path', create=True), \
             mock.patch('sys.argv', ['keeper.exe', '--internal-run-service']), \
             mock.patch('keepercommander.service.core.service_app.run_background_service') as mock_run, \
             mock.patch('keepercommander.utils.get_ssl_cert_file', return_value=None), \
             mock.patch('argparse.ArgumentParser.parse_known_args') as mock_parse_args:
            main()

            mock_run.assert_called_once()
            # If dispatch didn't return early, normal argument parsing would have run too.
            mock_parse_args.assert_not_called()

    def test_frozen_without_flag_does_not_start_the_service(self):
        with mock.patch('sys.frozen', True, create=True), \
             mock.patch('sys._MEIPASS', '/frozen/path', create=True), \
             mock.patch('sys.argv', ['keeper.exe', '--help']), \
             mock.patch('keepercommander.service.core.service_app.run_background_service') as mock_run, \
             mock.patch('keepercommander.utils.get_ssl_cert_file', return_value=None), \
             mock.patch('argparse.ArgumentParser.parse_known_args', side_effect=SystemExit(0)):
            with self.assertRaises(SystemExit):
                main()

            mock_run.assert_not_called()

    def test_not_frozen_ignores_the_flag_entirely(self):
        """Running from source, the flag has no special meaning and normal parsing proceeds."""
        with mock.patch('sys.frozen', False, create=True), \
             mock.patch('sys.argv', ['keeper', '--internal-run-service']), \
             mock.patch('keepercommander.service.core.service_app.run_background_service') as mock_run, \
             mock.patch('keepercommander.utils.get_ssl_cert_file', return_value=None), \
             mock.patch('argparse.ArgumentParser.parse_known_args', side_effect=SystemExit(2)):
            with self.assertRaises(SystemExit):
                main()

            mock_run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
