import json
from unittest import TestCase, mock

from keepercommander import crypto, vault
from keepercommander.commands.pam_cloud import pam_cloud_credentials as mod
from keepercommander.error import CommandError


class SignInLocallyTest(TestCase):

    def _config(self, tenant='tenant-1', client='client-1'):
        record = vault.TypedRecord()
        record.type_name = 'pamAzureConfiguration'
        record.fields.append(vault.TypedField.new_field('secret', tenant, 'tenantId'))
        record.fields.append(vault.TypedField.new_field('secret', client, 'clientId'))
        return record

    def test_config_field_reads_by_label(self):
        config = self._config()
        self.assertEqual('tenant-1', mod._config_field(config, 'tenantId'))
        self.assertEqual('', mod._config_field(config, 'missing'))

    def test_builds_record_from_token_with_tenant_wide_default_scope(self):
        with mock.patch.object(mod.entra_sign_in, 'sign_in',
                               return_value={'access_token': 'at', 'expires_in': 3599}) as sign_in:
            record, expiration = mod._sign_in_locally(self._config(), 'alice@contoso.com', None)

        args, kwargs = sign_in.call_args
        self.assertEqual(('tenant-1', 'client-1', 'https://graph.microsoft.com/.default'), args)
        self.assertEqual('alice@contoso.com', kwargs['login_hint'])
        fields = {f.get('label') or f['type']: f['value'] for f in record['fields']}
        self.assertEqual('alice@contoso.com', fields['login'])
        self.assertEqual({'accessToken': 'at'}, json.loads(fields['privatePEMKey']))
        self.assertEqual('azure', fields['Provider'])
        self.assertTrue(expiration)

    def test_client_id_override(self):
        with mock.patch.object(mod.entra_sign_in, 'sign_in', return_value={'access_token': 'at'}) as sign_in:
            mod._sign_in_locally(self._config(), 'alice@contoso.com', 'override-client')

        self.assertEqual(('tenant-1', 'override-client', 'https://graph.microsoft.com/.default'),
                         sign_in.call_args.args)

    def test_scope_override_narrows_the_token(self):
        with mock.patch.object(mod.entra_sign_in, 'sign_in', return_value={'access_token': 'at'}) as sign_in:
            mod._sign_in_locally(self._config(), 'alice@contoso.com', None, 'https://management.azure.com/.default')

        self.assertEqual('https://management.azure.com/.default', sign_in.call_args.args[2])

    def test_missing_tenant_or_client_is_error(self):
        with self.assertRaises(CommandError):
            mod._sign_in_locally(self._config(client=''), 'alice@contoso.com', None)


class ExecuteTest(TestCase):
    """The requester is always the user who gets the token."""

    def _run(self, config_type, gateway_data=None, sent=None):
        params = mock.Mock()
        params.user = 'dev-admin@chan-demo.com'
        params.record_cache = {'CFG': {'record_key_unencrypted': crypto.get_random_bytes(32)}}
        resource = vault.TypedRecord()
        resource.record_uid = 'RES'
        resource.type_name = 'pamCloudResource'
        config = vault.TypedRecord()
        config.type_name = config_type
        config.fields.append(vault.TypedField.new_field('secret', 'tenant-1', 'tenantId'))
        config.fields.append(vault.TypedField.new_field('secret', 'client-1', 'clientId'))
        sent = {} if sent is None else sent

        def dispatch(_params, action, **_kw):
            sent.update(action.inputs)
            return gateway_data or {'success': True, 'clientSideAuth': True}

        args = {'record': 'RES', 'configuration': None, 'client_id': None, 'scope': None,
                'duration_seconds': None, 'gateway': None, 'save_record': False}
        with mock.patch.object(mod, 'resolve_pam_record', return_value=resource), \
                mock.patch.object(mod, '_resolve_config_uid', return_value='CFG'), \
                mock.patch.object(mod.vault.KeeperRecord, 'load', return_value=config), \
                mock.patch.object(mod, 'dispatch_streamed_access_elevation_action', side_effect=dispatch), \
                mock.patch.object(mod.entra_sign_in, 'sign_in',
                                  return_value={'access_token': 'at', 'expires_in': 3599}) as sign_in, \
                mock.patch('builtins.print'):
            mod.PAMCloudGenerateCredentialsCommand().execute(params, **args)
        return sent, sign_in

    def test_azure_signs_the_requester_in_and_sends_no_password(self):
        sent, sign_in = self._run('pamAzureConfiguration')

        self.assertTrue(sent['clientSideAuth'])
        self.assertEqual('dev-admin@chan-demo.com', sent['username'])
        self.assertNotIn('password', sent)
        self.assertEqual('dev-admin@chan-demo.com', sign_in.call_args.kwargs['login_hint'])

    def test_non_azure_is_left_to_the_gateway(self):
        sent = {}
        with self.assertRaises(CommandError):
            self._run('pamAwsConfiguration', gateway_data={'success': False, 'error': 'stop'}, sent=sent)

        self.assertNotIn('clientSideAuth', sent)
        self.assertEqual('dev-admin@chan-demo.com', sent['username'])

    def test_gateway_error_is_raised(self):
        with self.assertRaises(CommandError) as ctx:
            self._run('pamAzureConfiguration', gateway_data={'success': False, 'error': 'nope'})
        self.assertIn('nope', str(ctx.exception))
