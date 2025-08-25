import sys
if sys.version_info >= (3, 8):
    import unittest
    from unittest.mock import patch, MagicMock
    import json
    from keepercommander.params import KeeperParams
    from keepercommander.service.config.service_config import ServiceConfig
    from keepercommander.service.util.exceptions import ValidationError

    class TestServiceConfig(unittest.TestCase):
        def setUp(self):
            self.service_config = ServiceConfig()
            self.test_config = {
                "title": "Commander Service Mode",
                "port": 8000,
                "ngrok": "n",
                "ngrok_auth_token": "",
                "ngrok_custom_domain": "",
                "ngrok_public_url": "",
                "is_advanced_security_enabled": "n",
                "rate_limiting": "",
                "ip_allowed_list": "",
                "ip_denied_list": "",
                "encryption": "",
                "encryption_private_key": "",
                "records": [],
                "tls_certificate":"",
                "certfile": "",
                "certpassword": "",
                "fileformat": "",
                "run_mode": "",
                "queue_enabled": "y"
            }

        def test_create_default_config(self):
            """Test creation of default configuration."""
            config = self.service_config.create_default_config()
            self.assertEqual(config["title"], "Commander Service Mode")
            self.assertIsNone(config["port"])
            self.assertEqual(config["ngrok"], "n")
            self.assertEqual(config["ngrok_auth_token"], "")
            self.assertEqual(config["is_advanced_security_enabled"], "n")

        def test_save_config_success(self):
            """Test successful configuration save."""
            with patch.object(self.service_config.format_handler, 'get_config_format') as mock_format, \
                patch.object(self.service_config.format_handler, '_save_json') as mock_save_json:
                
                mock_format.return_value = 'json'
                mock_save_json.return_value = self.service_config.config_path
                
                result = self.service_config.save_config(self.test_config)
                
                mock_format.assert_called_once()
                mock_save_json.assert_called_once()
                self.assertEqual(result, self.service_config.config_path)

        def test_save_config_io_error(self):
            """Test configuration save with IO error."""
            with patch.object(self.service_config.format_handler, 'get_config_format') as mock_format, \
                patch.object(self.service_config.format_handler, '_save_json') as mock_save_json:
                
                mock_format.return_value = 'json'
                mock_save_json.side_effect = IOError("Test error")
                
                with self.assertRaises(ValidationError):
                    self.service_config.save_config(self.test_config)
       
        @unittest.skip
        @patch('pathlib.Path.exists')
        @patch('pathlib.Path.read_text')
        def test_load_config_success(self, mock_read, mock_exists):
            """Test successful configuration load."""
            mock_exists.return_value = True
            mock_read.return_value = json.dumps(self.test_config)
            config = self.service_config.load_config()
            self.assertEqual(config, self.test_config)

        @patch('pathlib.Path.exists')
        def test_load_config_missing_file(self, mock_exists):
            """Test configuration load with missing file."""
            mock_exists.return_value = False
            with self.assertRaises(FileNotFoundError):
                self.service_config.load_config()

        def test_get_yes_no_input_valid(self):
            """Test yes/no input with valid inputs."""
            with patch('builtins.input', side_effect=['y']):
                result = self.service_config._get_yes_no_input("Test prompt")
                self.assertEqual(result, 'y')

            with patch('builtins.input', side_effect=['n']):
                result = self.service_config._get_yes_no_input("Test prompt")
                self.assertEqual(result, 'n')

        @patch('builtins.print')
        def test_get_yes_no_input_invalid_then_valid(self, mock_print):
            """Test yes/no input with invalid input followed by valid input."""
            with patch('builtins.input', side_effect=['invalid', 'y']):
                result = self.service_config._get_yes_no_input("Test prompt")
                self.assertEqual(result, 'y')
                mock_print.assert_called_once()

        @patch.object(ServiceConfig, 'cli_handler')
        def test_validate_command_list_valid(self, mock_cli_handler):
            """Test command list validation with valid commands."""
            mock_cli_handler.get_help_output.return_value = """
            Vault Commands:
            ls  list      List vault records
            get info     Display record details
            """
            params = MagicMock(spec=KeeperParams)
            result = self.service_config.validate_command_list("ls, get", params)
            self.assertEqual(result, "ls, get")

        @patch.object(ServiceConfig, 'cli_handler')
        def test_validate_command_list_invalid(self, mock_cli_handler):
            """Test command list validation with invalid commands."""
            mock_cli_handler.get_help_output.return_value = """
            Vault Commands:
            ls  list      List vault records
            get info     Display record details
            """
            params = MagicMock(spec=KeeperParams)
            with self.assertRaises(ValidationError):
                self.service_config.validate_command_list("invalid_command", params)

        @unittest.skip
        @patch.object(ServiceConfig, 'record_handler')
        def test_update_or_add_record(self, mock_record_handler):
            """Test record update/add functionality."""
            params = MagicMock(spec=KeeperParams)
            self.service_config.update_or_add_record(params)
            mock_record_handler.update_or_add_record.assert_called_once_with(
                params, self.service_config.title, self.service_config.config_path
            )