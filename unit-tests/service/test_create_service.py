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
            
        args = parser.parse_args(['--cloudflare', 'cf_token123'])
        self.assertEqual(args.cloudflare, 'cf_token123')
            
        args = parser.parse_args(['--cloudflare_custom_domain', 'example.com'])
        self.assertEqual(args.cloudflare_custom_domain, 'example.com')

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
        args = StreamlineArgs(port=8080, commands='record-list', ngrok=None, allowedip='0.0.0.0' ,deniedip='', ngrok_custom_domain=None, cloudflare=None, cloudflare_custom_domain=None, tailscale=None, tailscale_advertise_tags=None, certfile='', certpassword='', fileformat='json', run_mode='foreground', queue_enabled='y', update_vault_record=None, ratelimit=None, encryption_key=None, token_expiration=None)
            
        with patch.object(self.command.config_handler, 'handle_streamlined_config') as mock_streamlined:
            self.command._handle_configuration(config_data, self.params, args)
            mock_streamlined.assert_called_once_with(config_data, args, self.params)

    def test_handle_configuration_interactive(self):
        """Test interactive configuration handling."""
        config_data = self.command.service_config.create_default_config()
        args =  StreamlineArgs(port=None, commands=None, ngrok=None, allowedip='' ,deniedip='', ngrok_custom_domain=None, cloudflare=None, cloudflare_custom_domain=None, tailscale=None, tailscale_advertise_tags=None, certfile='', certpassword='', fileformat='json', run_mode='foreground', queue_enabled=None, update_vault_record=None, ratelimit=None, encryption_key=None, token_expiration=None)
            
        with patch.object(self.command.config_handler, 'handle_interactive_config') as mock_interactive, \
            patch.object(self.command.security_handler, 'configure_security') as mock_security:
            self.command._handle_configuration(config_data, self.params, args)
            mock_interactive.assert_called_once_with(config_data, self.params)
            mock_security.assert_called_once_with(config_data)

    def test_create_and_save_record(self):
        """Test record creation and saving."""
        config_data = self.command.service_config.create_default_config()
        args = StreamlineArgs(port=8080, commands='record-list', ngrok=None, allowedip='0.0.0.0' ,deniedip='', ngrok_custom_domain=None, cloudflare=None, cloudflare_custom_domain=None, tailscale=None, tailscale_advertise_tags=None, certfile='', certpassword='', fileformat='json', run_mode='foreground', queue_enabled='y', update_vault_record=None, ratelimit=None, encryption_key=None, token_expiration=None)
            
        with patch.object(self.command.service_config, 'create_record') as mock_create_record, \
            patch.object(self.command.service_config, 'save_config') as mock_save_config:
                
            mock_create_record.return_value = {'api-key': 'test-key'}
            self.command._create_and_save_record(config_data, self.params, args)
                
            mock_create_record.assert_called_once_with(
                config_data["is_advanced_security_enabled"],
                self.params,
                args.commands,
                args.token_expiration,
                None,  # record_uid (update_vault_record is None)
                existing_api_key=None,
            )
            if(args.fileformat):
                config_data["fileformat"]= args.fileformat
            else:
                mock_save_config.assert_called_once_with(config_data, 'create')
                
    def test_validation_error_handling(self):
        """Test handling of validation errors during execution."""
        args =  StreamlineArgs(port=-1, commands='record-list', ngrok=None, allowedip='0.0.0.0' ,deniedip='', ngrok_custom_domain=None, cloudflare=None, cloudflare_custom_domain=None, tailscale=None, tailscale_advertise_tags=None, certfile='', certpassword='', fileformat='json', run_mode='foreground', queue_enabled='y', update_vault_record=None, ratelimit=None, encryption_key=None, token_expiration=None)
            
        with patch('builtins.print') as mock_print:
            with patch.object(self.command.service_config, 'create_default_config') as mock_create_config:
                mock_create_config.return_value = {}
                self.command.execute(self.params, port=-1)
                    
                mock_print.assert_called()

    def test_cloudflare_streamlined_configuration(self):
        """Test streamlined configuration with Cloudflare tunnel."""
        config_data = self.command.service_config.create_default_config()
        args = StreamlineArgs(
            port=8080, 
            commands='record-list', 
            ngrok=None, 
            allowedip='0.0.0.0',
            deniedip='', 
            ngrok_custom_domain=None, 
            cloudflare='cf_token123',
            cloudflare_custom_domain='tunnel.example.com',
            tailscale=None,
            tailscale_advertise_tags=None,
            certfile='', 
            certpassword='', 
            fileformat='json', 
            run_mode='foreground', 
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )
            
        with patch.object(self.command.config_handler, 'handle_streamlined_config') as mock_streamlined:
            self.command._handle_configuration(config_data, self.params, args)
            mock_streamlined.assert_called_once_with(config_data, args, self.params)

    def test_cloudflare_validation_missing_token(self):
        """Test validation error when Cloudflare token is missing but domain is provided."""
        args = StreamlineArgs(
            port=8080, 
            commands='record-list', 
            ngrok=None, 
            allowedip='0.0.0.0',
            deniedip='', 
            ngrok_custom_domain=None, 
            cloudflare=None,
            cloudflare_custom_domain='tunnel.example.com',
            tailscale=None,
            tailscale_advertise_tags=None,
            certfile='', 
            certpassword='', 
            fileformat='json', 
            run_mode='foreground', 
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )
            
        with patch('builtins.print') as mock_print:
            with patch.object(self.command.service_config, 'create_default_config') as mock_create_config:
                mock_create_config.return_value = {}
                self.command.execute(self.params, cloudflare_custom_domain='tunnel.example.com')
                mock_print.assert_called()

    def test_cloudflare_validation_missing_domain(self):
        """Test validation error when Cloudflare domain is missing but token is provided."""
        args = StreamlineArgs(
            port=8080, 
            commands='record-list', 
            ngrok=None, 
            allowedip='0.0.0.0',
            deniedip='', 
            ngrok_custom_domain=None, 
            cloudflare='cf_token123',
            cloudflare_custom_domain=None,
            tailscale=None,
            tailscale_advertise_tags=None,
            certfile='', 
            certpassword='', 
            fileformat='json', 
            run_mode='foreground', 
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )
            
        with patch('builtins.print') as mock_print:
            with patch.object(self.command.service_config, 'create_default_config') as mock_create_config:
                mock_create_config.return_value = {}
                self.command.execute(self.params, cloudflare='cf_token123')
                mock_print.assert_called()

    def test_cloudflare_and_ngrok_mutual_exclusion(self):
        """Test that Cloudflare and ngrok cannot be used together."""
        args = StreamlineArgs(
            port=8080, 
            commands='record-list', 
            ngrok='ngrok_token123', 
            allowedip='0.0.0.0',
            deniedip='', 
            ngrok_custom_domain='ngrok.example.com', 
            cloudflare='cf_token123',
            cloudflare_custom_domain='tunnel.example.com',
            tailscale=None,
            tailscale_advertise_tags=None,
            certfile='', 
            certpassword='', 
            fileformat='json', 
            run_mode='foreground', 
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )
            
        with patch('builtins.print') as mock_print:
            with patch.object(self.command.service_config, 'create_default_config') as mock_create_config:
                mock_create_config.return_value = {}
                self.command.execute(self.params, ngrok='ngrok_token123', cloudflare='cf_token123')
                mock_print.assert_called()

    @patch('keepercommander.service.config.cloudflare_config.CloudflareConfigurator.configure_cloudflare')
    def test_cloudflare_tunnel_startup_success(self, mock_cloudflare_configure):
        """Test successful Cloudflare tunnel startup."""
        config_data = self.command.service_config.create_default_config()
        config_data.update({
            'cloudflare': 'y',
            'cloudflare_tunnel_token': 'cf_token123',
            'cloudflare_custom_domain': 'tunnel.example.com',
            'port': 8080
        })
            
        mock_cloudflare_configure.return_value = 12345  # Mock PID
            
        args = StreamlineArgs(
            port=8080, 
            commands='record-list', 
            ngrok=None, 
            allowedip='0.0.0.0',
            deniedip='', 
            ngrok_custom_domain=None, 
            cloudflare='cf_token123',
            cloudflare_custom_domain='tunnel.example.com',
            tailscale=None,
            tailscale_advertise_tags=None,
            certfile='', 
            certpassword='', 
            fileformat='json', 
            run_mode='foreground', 
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )
            
        with patch.object(self.command.config_handler, 'handle_streamlined_config') as mock_streamlined:
            self.command._handle_configuration(config_data, self.params, args)
            mock_streamlined.assert_called_once_with(config_data, args, self.params)

    @patch('keepercommander.service.core.globals.init_globals')
    @patch('keepercommander.service.core.service_manager.ServiceManager.start_service')
    @patch('keepercommander.service.core.service_manager.ServiceManager.get_status')
    def test_cloudflare_tunnel_startup_failure(self, mock_get_status, mock_start_service, mock_init_globals):
        """Test Cloudflare tunnel startup failure due to firewall."""
        # Mock that service is not already running
        mock_get_status.return_value = "Commander Service is not running"
            
        # Mock service startup failure due to Cloudflare tunnel issues
        mock_start_service.side_effect = Exception("Commander Service failed to start: Cloudflare tunnel failed to connect. This is likely due to firewall/proxy blocking the connection.")
            
        with patch('builtins.print') as mock_print:
            with patch.object(self.command.service_config, 'create_default_config') as mock_create_config:
                with patch.object(self.command.service_config, 'create_record') as mock_create_record:
                    with patch.object(self.command.service_config, 'save_config') as mock_save_config:
                        with patch.object(self.command.service_config, 'update_or_add_record') as mock_update_record:
                            with patch.object(self.command.service_config.validator, 'validate_cloudflare_token') as mock_validate_token:
                                mock_create_config.return_value = {
                                    'is_advanced_security_enabled': 'n',
                                    'fileformat': 'json'
                                }
                                mock_create_record.return_value = {'api-key': 'test-key'}
                                mock_validate_token.return_value = 'cf_token123'  # Mock valid token
                                    
                                # This should trigger the exception handling in execute()
                                self.command.execute(
                                    self.params, 
                                    port=8080,
                                    allowedip='0.0.0.0',
                                    deniedip='',
                                    commands='record-list',
                                    ngrok=None,
                                    ngrok_custom_domain=None,
                                    cloudflare='cf_token123',
                                    cloudflare_custom_domain='tunnel.example.com',
                                    tailscale=None,
                                    tailscale_advertise_tags=None,
                                    certfile='',
                                    certpassword='',
                                    fileformat='json',
                                    run_mode='foreground',
                                    queue_enabled='y',
                                    update_vault_record=None,
                                    ratelimit=None,
                                    encryption_key=None,
                                    token_expiration=None
                                )
                                    
                                # Verify that the error was printed
                                mock_print.assert_called_with("Unexpected error: Commander Service failed to start: Cloudflare tunnel failed to connect. This is likely due to firewall/proxy blocking the connection.")

    def test_cloudflare_token_validation(self):
        """Test Cloudflare token format validation."""
        # Test valid token format
        args = StreamlineArgs(
            port=8080, 
            commands='record-list', 
            ngrok=None, 
            allowedip='0.0.0.0',
            deniedip='', 
            ngrok_custom_domain=None, 
            cloudflare='eyJhIjoiYWJjZGVmZ2hpams',  # Base64-like token
            cloudflare_custom_domain='tunnel.example.com',
            tailscale=None,
            tailscale_advertise_tags=None,
            certfile='', 
            certpassword='', 
            fileformat='json', 
            run_mode='foreground', 
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )
            
        with patch.object(self.command.config_handler, 'handle_streamlined_config') as mock_streamlined:
            config_data = self.command.service_config.create_default_config()
            self.command._handle_configuration(config_data, self.params, args)
            mock_streamlined.assert_called_once_with(config_data, args, self.params)

    def test_cloudflare_domain_validation(self):
        """Test Cloudflare custom domain validation."""
        # Test valid domain format
        args = StreamlineArgs(
            port=8080, 
            commands='record-list', 
            ngrok=None, 
            allowedip='0.0.0.0',
            deniedip='', 
            ngrok_custom_domain=None, 
            cloudflare='cf_token123',
            cloudflare_custom_domain='my-tunnel.example.com',
            tailscale=None,
            tailscale_advertise_tags=None,
            certfile='', 
            certpassword='', 
            fileformat='json', 
            run_mode='foreground', 
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )
            
        with patch.object(self.command.config_handler, 'handle_streamlined_config') as mock_streamlined:
            config_data = self.command.service_config.create_default_config()
            self.command._handle_configuration(config_data, self.params, args)
            mock_streamlined.assert_called_once_with(config_data, args, self.params)

    def test_get_parser_tailscale(self):
        """Test that -ts alone carries the auth key value, with no separate -tsk flag."""
        parser = self.command.get_parser()

        args = parser.parse_args(['--tailscale', 'tskey-auth-dummy'])
        self.assertEqual(args.tailscale, 'tskey-auth-dummy')
        self.assertFalse(hasattr(args, 'tailscale_auth_key'))

        args = parser.parse_args(['-ts', 'tskey-auth-dummy', '-tst', 'tag:commander-service'])
        self.assertEqual(args.tailscale, 'tskey-auth-dummy')
        self.assertEqual(args.tailscale_advertise_tags, 'tag:commander-service')

    def test_tailscale_streamlined_configuration(self):
        """Test streamlined configuration with Tailscale, -ts alone enabling it."""
        config_data = self.command.service_config.create_default_config()
        args = StreamlineArgs(
            port=8080,
            commands='record-list',
            ngrok=None,
            allowedip='0.0.0.0',
            deniedip='',
            ngrok_custom_domain=None,
            cloudflare=None,
            cloudflare_custom_domain=None,
            tailscale='tskey-auth-dummy',
            tailscale_advertise_tags=None,
            certfile='',
            certpassword='',
            fileformat='json',
            run_mode='foreground',
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )

        self.command.config_handler.handle_streamlined_config(config_data, args, self.params)
        self.assertEqual(config_data['tailscale'], 'y')
        self.assertEqual(config_data['tailscale_auth_key'], 'tskey-auth-dummy')

    def test_tailscale_advertise_tags_streamlined(self):
        """Test that -tst is threaded through to the internal config alongside -ts."""
        config_data = self.command.service_config.create_default_config()
        args = StreamlineArgs(
            port=8080,
            commands='record-list',
            ngrok=None,
            allowedip='0.0.0.0',
            deniedip='',
            ngrok_custom_domain=None,
            cloudflare=None,
            cloudflare_custom_domain=None,
            tailscale='tskey-client-dummy',
            tailscale_advertise_tags='tag:commander-service',
            certfile='',
            certpassword='',
            fileformat='json',
            run_mode='foreground',
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )

        self.command.config_handler.handle_streamlined_config(config_data, args, self.params)
        self.assertEqual(config_data['tailscale_advertise_tags'], 'tag:commander-service')

    def test_tailscale_omitted_disables_it(self):
        """Test that omitting -ts disables Tailscale without requiring any other flag."""
        config_data = self.command.service_config.create_default_config()
        args = StreamlineArgs(
            port=8080,
            commands='record-list',
            ngrok=None,
            allowedip='0.0.0.0',
            deniedip='',
            ngrok_custom_domain=None,
            cloudflare=None,
            cloudflare_custom_domain=None,
            tailscale=None,
            tailscale_advertise_tags=None,
            certfile='',
            certpassword='',
            fileformat='json',
            run_mode='foreground',
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )

        self.command.config_handler.handle_streamlined_config(config_data, args, self.params)
        self.assertEqual(config_data['tailscale'], 'n')
        self.assertEqual(config_data['tailscale_auth_key'], '')

    def test_tailscale_and_ngrok_mutual_exclusion(self):
        """Test that Ngrok takes priority and disables Tailscale, matching the Cloudflare/Ngrok exclusion pattern."""
        config_data = self.command.service_config.create_default_config()
        args = StreamlineArgs(
            port=8080,
            commands='record-list',
            ngrok='ngrok_token123',
            allowedip='0.0.0.0',
            deniedip='',
            ngrok_custom_domain='ngrok.example.com',
            cloudflare=None,
            cloudflare_custom_domain=None,
            tailscale='tskey-auth-dummy',
            tailscale_advertise_tags=None,
            certfile='',
            certpassword='',
            fileformat='json',
            run_mode='foreground',
            queue_enabled='y',
            update_vault_record=None,
            ratelimit=None,
            encryption_key=None,
            token_expiration=None
        )

        self.command.config_handler.handle_streamlined_config(config_data, args, self.params)
        self.assertEqual(config_data['ngrok'], 'y')
        self.assertEqual(config_data['tailscale'], 'n')
        self.assertEqual(config_data['tailscale_auth_key'], '')


class TestGetServiceUrl(unittest.TestCase):
    """_get_service_url (restored, release-branch-matching, plus one additive
    tailscale branch): ngrok > cloudflare > tailscale > localhost."""

    def setUp(self):
        self.command = CreateService()

    def test_tailscale_url_used_when_no_ngrok_or_cloudflare(self):
        config_data = {'tailscale_public_url': 'https://node.example.ts.net', 'queue_enabled': 'y'}
        self.assertEqual(self.command._get_service_url(config_data), 'https://node.example.ts.net/api/v2')

    def test_ngrok_still_takes_priority_over_tailscale(self):
        config_data = {
            'ngrok_public_url': 'https://abc.ngrok.io',
            'tailscale_public_url': 'https://node.example.ts.net',
            'queue_enabled': 'y',
        }
        self.assertEqual(self.command._get_service_url(config_data), 'https://abc.ngrok.io/api/v2')

    def test_falls_back_to_localhost_when_nothing_set(self):
        config_data = {'port': 8080, 'queue_enabled': 'y'}
        self.assertEqual(self.command._get_service_url(config_data), 'http://localhost:8080/api/v2')


class TestVaultMetadataWriteTiming(unittest.TestCase):
    """Matches the release branch exactly (confirmed via `git show release:...`):
    vault metadata is written synchronously, unconditionally, for every tunnel
    type right after record creation - no deferred/pending-metadata mechanism."""

    def setUp(self):
        self.params = Mock(spec=KeeperParams)
        self.command = CreateService()

    _FULL_EXECUTE_KWARGS = dict(
        port=8080, allowedip=None, deniedip=None, commands='record-list', ngrok=None,
        ngrok_custom_domain=None, cloudflare=None, cloudflare_custom_domain=None,
        tailscale=None, tailscale_advertise_tags=None, certfile=None, certpassword=None,
        fileformat='json', run_mode='foreground', queue_enabled='y', update_vault_record=None,
        ratelimit=None, encryption_key=None, token_expiration=None,
    )

    def test_execute_writes_ngrok_metadata_synchronously(self):
        with patch('keepercommander.service.core.service_manager.ServiceManager') as mock_sm, \
             patch.object(self.command, '_handle_configuration'), \
             patch.object(self.command, '_create_and_save_record', return_value='test-key'), \
             patch.object(self.command, '_get_service_url', return_value='https://abc.ngrok.io/api/v2'), \
             patch('keepercommander.service.commands.integrations.vault_metadata.write_service_metadata') as mock_write, \
             patch.object(self.command, '_upload_and_start_service'), \
             patch.object(self.command.service_config, 'create_default_config') as mock_config:
            mock_sm.get_status.return_value = "No Commander Service is running currently"
            mock_config.return_value = {'tailscale': 'n'}
            kwargs = dict(self._FULL_EXECUTE_KWARGS, ngrok='tok', update_vault_record='record-uid-1')
            self.command.execute(self.params, **kwargs)
            mock_write.assert_called_once_with(self.params, 'record-uid-1', 'https://abc.ngrok.io/api/v2', 'test-key')

    def test_execute_writes_tailscale_metadata_synchronously_too(self):
        """Unconditional, matching release - no tailscale-specific gating."""
        with patch('keepercommander.service.core.service_manager.ServiceManager') as mock_sm, \
             patch.object(self.command, '_handle_configuration'), \
             patch.object(self.command, '_create_and_save_record', return_value='test-key'), \
             patch.object(self.command, '_get_service_url', return_value='http://localhost:8080/api/v2'), \
             patch('keepercommander.service.commands.integrations.vault_metadata.write_service_metadata') as mock_write, \
             patch.object(self.command, '_upload_and_start_service'), \
             patch.object(self.command.service_config, 'create_default_config') as mock_config:
            mock_sm.get_status.return_value = "No Commander Service is running currently"
            mock_config.return_value = {'tailscale': 'y'}
            kwargs = dict(self._FULL_EXECUTE_KWARGS, tailscale='tskey-auth-xxx', update_vault_record='record-uid-1')
            self.command.execute(self.params, **kwargs)
            mock_write.assert_called_once_with(self.params, 'record-uid-1', 'http://localhost:8080/api/v2', 'test-key')

    def test_create_and_save_record_has_no_metadata_side_effects(self):
        """No set_pending_vault_metadata or any other global state - record
        creation/saving only, matching release exactly."""
        config_data = self.command.service_config.create_default_config()
        args = StreamlineArgs(
            port=8080, commands='record-list', ngrok=None, allowedip='0.0.0.0', deniedip='',
            ngrok_custom_domain=None, cloudflare=None, cloudflare_custom_domain=None,
            tailscale='tskey-auth-xxx', tailscale_advertise_tags=None, certfile='', certpassword='',
            fileformat='json', run_mode='foreground', queue_enabled='y',
            update_vault_record='record-uid-1', ratelimit=None, encryption_key=None,
            token_expiration=None,
        )
        with patch.object(self.command.service_config, 'create_record') as mock_create_record, \
             patch.object(self.command.service_config, 'save_config'):
            mock_create_record.return_value = {'api-key': 'test-key'}
            result = self.command._create_and_save_record(config_data, self.params, args)
            self.assertEqual(result, 'test-key')


if __name__ == '__main__':
    unittest.main()