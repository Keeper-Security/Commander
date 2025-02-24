import sys
if sys.version_info >= (3, 8):
    import unittest
    from unittest.mock import Mock, patch
    from keepercommander.params import KeeperParams
    from keepercommander.service.commands.create_service import CreateService, StreamlineArgs

    class TestCreateService(unittest.TestCase):
        def setUp(self):
            self.params = Mock(spec=KeeperParams)
            self.command = CreateService()
            
        def test_get_parser(self):
            """Test parser creation with correct arguments."""
            parser = self.command.get_parser()
            
            args = parser.parse_args(['--port', '8080'])
            self.assertEqual(args.port, 8080)
            
            args = parser.parse_args(['--commands', 'record-list'])
            self.assertEqual(args.commands, 'record-list')
            
            args = parser.parse_args(['--ngrok', 'token123'])
            self.assertEqual(args.ngrok, 'token123')

        @patch('keepercommander.service.core.service_manager.ServiceManager')
        def test_execute_service_already_running(self, mock_service_manager):
            """Test execute when service is already running."""
            mock_service_manager.get_status.return_value = "Commander Service is Running on port 8080"
            
            with patch('builtins.print') as mock_print:
                self.command.execute(self.params)
                mock_print.assert_called_with("Error: Commander Service is already running.")

        def test_handle_configuration_streamlined(self):
            """Test streamlined configuration handling."""
            config_data = self.command.service_config.create_default_config()
            args = StreamlineArgs(port=8080, commands='record-list', ngrok=None)
            
            with patch.object(self.command.config_handler, 'handle_streamlined_config') as mock_streamlined:
                self.command._handle_configuration(config_data, self.params, args)
                mock_streamlined.assert_called_once_with(config_data, args, self.params)

        def test_handle_configuration_interactive(self):
            """Test interactive configuration handling."""
            config_data = self.command.service_config.create_default_config()
            args = StreamlineArgs(port=None, commands=None, ngrok=None)
            
            with patch.object(self.command.config_handler, 'handle_interactive_config') as mock_interactive, \
                patch.object(self.command.security_handler, 'configure_security') as mock_security:
                self.command._handle_configuration(config_data, self.params, args)
                mock_interactive.assert_called_once_with(config_data, self.params)
                mock_security.assert_called_once_with(config_data)

        def test_create_and_save_record(self):
            """Test record creation and saving."""
            config_data = self.command.service_config.create_default_config()
            args = StreamlineArgs(port=8080, commands='record-list', ngrok=None)
            
            with patch.object(self.command.service_config, 'create_record') as mock_create_record, \
                patch.object(self.command.service_config, 'save_config') as mock_save_config:
                
                mock_create_record.return_value = {'api-key': 'test-key'}
                self.command._create_and_save_record(config_data, self.params, args)
                
                mock_create_record.assert_called_once_with(
                    config_data["is_advanced_security_enabled"],
                    self.params,
                    args.commands
                )
                mock_save_config.assert_called_once_with(config_data, 'create')

        def test_validation_error_handling(self):
            """Test handling of validation errors during execution."""
            args = StreamlineArgs(port=-1, commands=None, ngrok=None)
            
            with patch('builtins.print') as mock_print:
                with patch.object(self.command.service_config, 'create_default_config') as mock_create_config:
                    mock_create_config.return_value = {}
                    self.command.execute(self.params, port=-1)
                    
                    mock_print.assert_called()

    if __name__ == '__main__':
        unittest.main()