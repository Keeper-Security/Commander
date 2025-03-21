import sys
if sys.version_info >= (3, 8):
    import unittest
    from unittest import mock
    from pathlib import Path

    from keepercommander.params import KeeperParams
    from keepercommander.service.core.service_manager import ServiceManager
    from keepercommander.service.core.process_info import ProcessInfo
    from keepercommander.service.commands.handle_service import StartService, StopService, ServiceStatus

    class TestServiceManagement(unittest.TestCase):
        def setUp(self):
            self.params = mock.Mock(spec=KeeperParams)
            ProcessInfo._env_file = Path(__file__).parent / ".test_service.env"
            
            if ProcessInfo._env_file.exists():
                ProcessInfo._env_file.unlink()

        def tearDown(self):
            if ProcessInfo._env_file.exists():
                ProcessInfo._env_file.unlink()
                
        def test_start_service_when_not_running(self):
            """Test starting service when no existing service is running"""
            with mock.patch('keepercommander.service.core.service_manager.ServiceConfig') as mock_config, \
                mock.patch('os.getpid', return_value=12345), \
                mock.patch('keepercommander.service.app.create_app') as mock_create_app, \
                mock.patch('keepercommander.service.core.terminal_handler.TerminalHandler.get_terminal_info', return_value="/dev/test"):
                
                mock_config.return_value.load_config.return_value = {"port": 8000}
                
                mock_app = mock.Mock()
                mock_create_app.return_value = mock_app
                
                start_cmd = StartService()
                start_cmd.execute(self.params)
                
                process_info = ProcessInfo.load()
                self.assertEqual(process_info.pid, 12345)
                self.assertTrue(process_info.is_running)
                
                mock_app.run.assert_called_once_with(host='0.0.0.0', port=8000)
                    
        def test_start_service_when_already_running(self):
            """Test starting service when another instance is already running"""
            ProcessInfo.save(True)
            with mock.patch('os.getpid', return_value=12345), \
                mock.patch('psutil.Process') as mock_process:
                mock_process.return_value.is_running.return_value = True
                
                start_cmd = StartService()
                with mock.patch('builtins.print') as mock_print:
                    start_cmd.execute(self.params)
                    mock_print.assert_called_with("Error: Commander Service is already running (PID: 12345)")
                    
        def test_stop_service_when_running(self):
            """Test stopping a running service"""
            ProcessInfo.save(True)
            
            with mock.patch('os.getpid', return_value=9999), \
                mock.patch('keepercommander.service.core.terminal_handler.TerminalHandler.get_terminal_info', return_value="/dev/pts/0"), \
                mock.patch('psutil.Process') as mock_process:
                
                stop_cmd = StopService()
                stop_cmd.execute(self.params)
                
                mock_process.return_value.terminate.assert_called_once()
                self.assertFalse(ProcessInfo._env_file.exists())

        def test_stop_service_when_not_running(self):
            """Test stopping service when no service is running"""
            with mock.patch('builtins.print') as mock_print:
                stop_cmd = StopService()
                stop_cmd.execute(self.params)
                mock_print.assert_called_with("Error: No running service found to stop")
                
        def test_service_status_when_running(self):
            """Test getting status of running service"""
            ProcessInfo.save(True)
            with mock.patch('os.getpid', return_value=12345), \
                mock.patch('psutil.Process') as mock_process, \
                mock.patch('keepercommander.service.core.terminal_handler.TerminalHandler.get_terminal_info', return_value="unknown terminal"):
                mock_process.return_value.is_running.return_value = True
                
                status_cmd = ServiceStatus()
                with mock.patch('builtins.print') as mock_print:
                    status_cmd.execute(self.params)
                    expected_status = "Current status: Commander Service is Running (PID: 12345, Terminal: unknown terminal)"
                    mock_print.assert_called_with(expected_status)
                    
        def test_service_status_when_not_running(self):
            """Test getting status when no service is running"""
            status_cmd = ServiceStatus()
            with mock.patch('builtins.print') as mock_print:
                status_cmd.execute(self.params)
                mock_print.assert_called_with("Current status: Commander Service is Stopped")

        def test_process_info_save_load(self):
            """Test ProcessInfo save and load operations"""
            test_pid = 12345
            test_terminal = "/dev/test"
            
            with mock.patch('os.getpid', return_value=test_pid):
                ProcessInfo.save(is_running=True)
                
                loaded_info = ProcessInfo.load()
                self.assertEqual(loaded_info.pid, test_pid)
                self.assertTrue(loaded_info.is_running)

        def test_handle_shutdown(self):
            """Test service shutdown handler"""
            ServiceManager._is_running = True
            ServiceManager._flask_app = mock.Mock()
            
            ProcessInfo.save(is_running=True)
            
            ServiceManager._handle_shutdown()
            
            self.assertFalse(ServiceManager._is_running)
            self.assertIsNone(ServiceManager._flask_app)
            self.assertFalse(ProcessInfo._env_file.exists())

        def test_start_service_with_missing_config(self):
            """Test starting service with missing configuration file"""
            with mock.patch('keepercommander.service.core.service_manager.ServiceConfig') as mock_config, \
                mock.patch('keepercommander.service.app.create_app') as mock_create_app, \
                mock.patch('builtins.print') as mock_print:
                
                mock_config.return_value.load_config.side_effect = FileNotFoundError()
                
                mock_app = mock.Mock()
                mock_create_app.return_value = mock_app
                mock_app.run = mock.Mock()
                
                start_cmd = StartService()
                start_cmd.execute(self.params)
                
                mock_print.assert_called_with(
                    "Error: Service configuration file not found. Please use 'service-create' command to create a service_config file."
                )
                
                mock_app.run.assert_not_called()

        def test_start_service_with_missing_port(self):
            """Test starting service with missing port in configuration"""
            with mock.patch('keepercommander.service.core.service_manager.ServiceConfig') as mock_config, \
                mock.patch('keepercommander.service.app.create_app') as mock_create_app, \
                mock.patch('builtins.print') as mock_print:
                
                mock_config.return_value.load_config.return_value = {}
                
                mock_app = mock.Mock()
                mock_create_app.return_value = mock_app
                mock_app.run = mock.Mock()
                
                start_cmd = StartService()
                start_cmd.execute(self.params)
                
                mock_print.assert_called_with(
                    "Error: Service configuration is incomplete. Please configure the service port in service_config"
                )
                
                mock_app.run.assert_not_called()