import unittest
from unittest import mock

from keepercommander.service.core.service_app import run_background_service


class TestRunBackgroundService(unittest.TestCase):
    def test_exits_nonzero_when_port_missing(self):
        """A missing port must abort startup, not fall through into flask_app.run(port=None)."""
        with mock.patch('keepercommander.service.app.create_app', return_value=mock.Mock()), \
             mock.patch('keepercommander.service.config.service_config.ServiceConfig') as mock_config, \
             mock.patch('keepercommander.service.core.globals.ensure_params_loaded'):
            mock_config.return_value.load_config.return_value = {}

            with self.assertRaises(SystemExit) as ctx:
                run_background_service()

            self.assertEqual(ctx.exception.code, 1)

    def test_runs_flask_app_when_port_present(self):
        mock_flask_app = mock.Mock()
        with mock.patch('keepercommander.service.app.create_app', return_value=mock_flask_app), \
             mock.patch('keepercommander.service.config.service_config.ServiceConfig') as mock_config, \
             mock.patch('keepercommander.service.core.globals.ensure_params_loaded'), \
             mock.patch('keepercommander.service.core.service_manager.ServiceManager.get_ssl_context',
                         return_value=None):
            mock_config.return_value.load_config.return_value = {"port": 8000}

            run_background_service()

            mock_flask_app.run.assert_called_once_with(host='0.0.0.0', port=8000, ssl_context=None)


if __name__ == '__main__':
    unittest.main()
