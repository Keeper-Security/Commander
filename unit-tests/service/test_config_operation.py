import sys
if sys.version_info >= (3, 8):
    from unittest import TestCase, mock
    from keepercommander.params import KeeperParams
    from keepercommander.service.config.service_config import ServiceConfig
    from keepercommander.service.commands.config_operation import AddConfigService

    class TestConfigOperation(TestCase):
        def setUp(self):
            self.mock_params = mock.Mock(spec=KeeperParams)
            self.cmd = AddConfigService()
            
        def test_execute_with_existing_config(self):
            mock_config = {
                "is_advanced_security_enabled": "y",
                "records": []
            }
            mock_record = {
                "api-key": "test-api-key",
                "command_list": "list",
                "expiration_timestamp": "2024-12-31T23:59:59",
                #"expiration_of_token": ""
            }
            
            with mock.patch.object(ServiceConfig, 'load_config', return_value=mock_config), \
                mock.patch.object(ServiceConfig, 'create_record', return_value=mock_record), \
                mock.patch.object(ServiceConfig, 'save_config') as mock_save, \
                mock.patch('builtins.print'):
                
                self.cmd.execute(self.mock_params)
                
                expected_config = {
                    "is_advanced_security_enabled": "y",
                    "records": [mock_record]
                }
                mock_save.assert_called_once_with(expected_config)

        def test_execute_when_config_not_found(self):
            with mock.patch.object(ServiceConfig, 'load_config', side_effect=FileNotFoundError), \
                mock.patch('builtins.print') as mock_print:
                
                result = self.cmd.execute(self.mock_params)
                
                mock_print.assert_called_with(
                    "Error: Service configuration file not found. Please use 'service-create' command to create a service_config file."
                )
                self.assertEqual(result, '')

        def test_execute_with_general_error(self):
            with mock.patch.object(ServiceConfig, 'load_config', side_effect=Exception("Test error")), \
                mock.patch('builtins.print') as mock_print:
                
                result = self.cmd.execute(self.mock_params)
                
                mock_print.assert_called_with(
                    "Error: Service configuration file not found. Please use 'service-create' command to create a service_config file."
                )
                self.assertEqual(result, '')

        def test_create_and_add_record(self):
            mock_config = {
                "is_advanced_security_enabled": "n",
                "records": [{"existing": "record"}]
            }
            mock_record = {
                "api-key": "new-api-key",
                "command_list": "list",
                "expiration_timestamp": "2024-12-31T23:59:59",
                #"expiration_of_token": ""
            }
            
            with mock.patch.object(ServiceConfig, 'load_config', return_value=mock_config), \
                mock.patch.object(ServiceConfig, 'create_record', return_value=mock_record), \
                mock.patch.object(ServiceConfig, 'save_config') as mock_save, \
                mock.patch('builtins.print'):
                
                self.cmd.execute(self.mock_params)
                
                expected_config = {
                    "is_advanced_security_enabled": "n",
                    "records": [{"existing": "record"}, mock_record]
                }
                mock_save.assert_called_once_with(expected_config)