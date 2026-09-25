"""
Unit tests for the KC (Commander) half of the ephemeral/--credential proxy
tunnel plan:

- Section 2.1: launch-credential preflight falls back to ephemeral JIT.
- Section 2.2: gateway timeout bump for ephemeral tunnel starts.
- Section 3.2: --credential/-cr proxy-target classification, allowSupplyUser
  gate, and record resolution for `pam tunnel start`.

These test the small, pure/near-pure functions extracted from
tunnel_and_connections.py / tunnel_helpers.py rather than the full CLI
command (which would require mocking KeeperParams/TunnelDAG/gateway network
calls not otherwise exercised by this repo's test suite).
"""

import unittest
from unittest import mock

from keepercommander.commands.tunnel_and_connections import (
    _classify_proxy_target,
    _detect_proxy_backend,
    _pam_allow_supply_user,
    _resolve_credential_record,
    _resource_has_ephemeral_jit,
)
from keepercommander.commands.tunnel.port_forward.tunnel_helpers import (
    credential_override_data_fields,
    credential_override_input_fields,
    ephemeral_gateway_timeout_ms,
)


class TestClassifyProxyTarget(unittest.TestCase):
    def test_database_record_is_keeperdb_proxy(self):
        is_db, is_rdp, is_ssh, error = _classify_proxy_target('rec-uid', 'pamDatabase', '', True, None)
        self.assertTrue(is_db)
        self.assertFalse(is_rdp)
        self.assertFalse(is_ssh)
        self.assertIsNone(error)

    def test_machine_rdp_record_is_keeperrdp_proxy(self):
        is_db, is_rdp, is_ssh, error = _classify_proxy_target('rec-uid', 'pamMachine', 'rdp', True, None)
        self.assertFalse(is_db)
        self.assertTrue(is_rdp)
        self.assertFalse(is_ssh)
        self.assertIsNone(error)

    def test_machine_ssh_record_is_keeperssh_proxy(self):
        is_db, is_rdp, is_ssh, error = _classify_proxy_target('rec-uid', 'pamMachine', 'ssh', True, None)
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertTrue(is_ssh)
        self.assertIsNone(error)

    def test_credential_alone_detects_ssh_proxy_without_proxy_flag(self):
        # --credential alone (no --proxy) still resolves to KeeperSSH Proxy
        # when the record is a pamMachine+SSH record — the gateway auto-routes
        # from the record's own settings regardless of the client-side flag.
        is_db, is_rdp, is_ssh, error = _classify_proxy_target('rec-uid', 'pamMachine', 'ssh', False, 'some-record')
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertTrue(is_ssh)
        self.assertIsNone(error)

    def test_unsupported_type_with_proxy_flag_gives_proxy_message(self):
        is_db, is_rdp, is_ssh, error = _classify_proxy_target('rec-uid', 'pamMachine', 'vnc', True, None)
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertFalse(is_ssh)
        self.assertIn('--proxy is supported on', error)

    def test_unsupported_type_with_credential_only_gives_plain_tunnel_message(self):
        # --credential with no --proxy, on a record that isn't proxy-capable
        # at all: distinct message from the --proxy-driven one above.
        is_db, is_rdp, is_ssh, error = _classify_proxy_target('rec-uid', 'pamMachine', 'vnc', False, 'some-record')
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertFalse(is_ssh)
        self.assertEqual(error, "--credential requires a proxied tunnel; plain tunnels don't authenticate.")

    def test_credential_on_database_record_is_rejected(self):
        # KeeperDB Proxy keeps "ephemeral always wins, no override" — reject
        # --credential outright instead of accepting a no-op flag.
        is_db, is_rdp, is_ssh, error = _classify_proxy_target('rec-uid', 'pamDatabase', '', True, 'some-record')
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertFalse(is_ssh)
        self.assertEqual(error, '--credential is not yet supported for KeeperDB Proxy tunnels.')

    def test_credential_on_database_record_rejected_even_without_proxy_flag(self):
        is_db, is_rdp, is_ssh, error = _classify_proxy_target('rec-uid', 'pamDatabase', '', False, 'some-record')
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertFalse(is_ssh)
        self.assertEqual(error, '--credential is not yet supported for KeeperDB Proxy tunnels.')

    def test_credential_alone_detects_rdp_proxy_without_proxy_flag(self):
        # --credential alone (no --proxy) still resolves to KeeperRDP Proxy
        # when the record is a pamMachine+RDP record — the gateway auto-routes
        # from the record's own settings regardless of the client-side flag.
        is_db, is_rdp, is_ssh, error = _classify_proxy_target('rec-uid', 'pamMachine', 'rdp', False, 'some-record')
        self.assertFalse(is_db)
        self.assertTrue(is_rdp)
        self.assertFalse(is_ssh)
        self.assertIsNone(error)


class TestDetectProxyBackend(unittest.TestCase):
    """_detect_proxy_backend drives the post-start proxy-ready banner for
    *every* tunnel start on a proxy-enabled record, not just ones started
    with --proxy/--credential — so it must read the record's actual
    allowKeeper*Proxy flags directly, unlike _classify_proxy_target (which
    only cares about record type/protocol, not whether the flag is set).
    """

    def test_database_proxy_enabled_via_portforward_bucket(self):
        is_db, is_rdp, is_ssh = _detect_proxy_backend(
            'pamDatabase', '', {'portForward': {'allowKeeperDBProxy': True}})
        self.assertTrue(is_db)
        self.assertFalse(is_rdp)
        self.assertFalse(is_ssh)

    def test_database_proxy_enabled_via_legacy_connection_bucket(self):
        is_db, is_rdp, is_ssh = _detect_proxy_backend(
            'pamDatabase', '', {'connection': {'allowKeeperDBProxy': True}})
        self.assertTrue(is_db)

    def test_database_record_without_flag_is_not_a_proxy(self):
        is_db, is_rdp, is_ssh = _detect_proxy_backend('pamDatabase', '', {'connection': {}})
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertFalse(is_ssh)

    def test_rdp_proxy_enabled(self):
        is_db, is_rdp, is_ssh = _detect_proxy_backend(
            'pamMachine', 'rdp', {'portForward': {'allowKeeperRDPProxy': True}})
        self.assertFalse(is_db)
        self.assertTrue(is_rdp)
        self.assertFalse(is_ssh)

    def test_rdp_record_without_flag_is_not_a_proxy(self):
        is_db, is_rdp, is_ssh = _detect_proxy_backend('pamMachine', 'rdp', {'portForward': {}})
        self.assertFalse(is_rdp)

    def test_ssh_proxy_enabled(self):
        is_db, is_rdp, is_ssh = _detect_proxy_backend(
            'pamMachine', 'ssh', {'portForward': {'allowKeeperSSHProxy': True}})
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertTrue(is_ssh)

    def test_ssh_record_without_flag_is_not_a_proxy(self):
        is_db, is_rdp, is_ssh = _detect_proxy_backend('pamMachine', 'ssh', {'portForward': {}})
        self.assertFalse(is_ssh)

    def test_unrelated_record_type_is_not_a_proxy(self):
        is_db, is_rdp, is_ssh = _detect_proxy_backend(
            'pamMachine', 'vnc', {'portForward': {'allowKeeperSSHProxy': True}})
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertFalse(is_ssh)

    def test_non_dict_pam_settings_is_not_a_proxy(self):
        is_db, is_rdp, is_ssh = _detect_proxy_backend('pamDatabase', '', None)
        self.assertFalse(is_db)
        self.assertFalse(is_rdp)
        self.assertFalse(is_ssh)


class TestPamAllowSupplyUser(unittest.TestCase):
    def test_true_when_set(self):
        self.assertTrue(_pam_allow_supply_user({'connection': {'allowSupplyUser': True}}))

    def test_false_when_absent(self):
        self.assertFalse(_pam_allow_supply_user({'connection': {}}))

    def test_false_when_connection_missing(self):
        self.assertFalse(_pam_allow_supply_user({}))

    def test_false_when_not_a_dict(self):
        self.assertFalse(_pam_allow_supply_user(None))


class TestResourceHasEphemeralJit(unittest.TestCase):
    @mock.patch('keepercommander.commands.tunnel_and_connections.get_resource_jit_settings')
    def test_true_when_create_ephemeral_set(self, mock_get_jit):
        mock_get_jit.return_value = {'createEphemeral': True}
        self.assertTrue(_resource_has_ephemeral_jit(object(), 'uid1'))

    @mock.patch('keepercommander.commands.tunnel_and_connections.get_resource_jit_settings')
    def test_false_when_create_ephemeral_false(self, mock_get_jit):
        mock_get_jit.return_value = {'createEphemeral': False}
        self.assertFalse(_resource_has_ephemeral_jit(object(), 'uid1'))

    @mock.patch('keepercommander.commands.tunnel_and_connections.get_resource_jit_settings')
    def test_false_when_no_jit_settings(self, mock_get_jit):
        mock_get_jit.return_value = None
        self.assertFalse(_resource_has_ephemeral_jit(object(), 'uid1'))

    @mock.patch('keepercommander.commands.tunnel_and_connections.get_resource_jit_settings')
    def test_false_on_read_error(self, mock_get_jit):
        mock_get_jit.side_effect = Exception('DAG unavailable')
        self.assertFalse(_resource_has_ephemeral_jit(object(), 'uid1'))


class _FakeRecord:
    def __init__(self, title):
        self.title = title


class _FakeParams:
    def __init__(self, record_cache):
        self.record_cache = record_cache


class TestResolveCredentialRecord(unittest.TestCase):
    def test_uid_hit_returns_uid_directly(self):
        params = _FakeParams({'abc123': {}})
        self.assertEqual(_resolve_credential_record(params, 'abc123'), 'abc123')

    def test_empty_token_returns_none(self):
        params = _FakeParams({})
        self.assertIsNone(_resolve_credential_record(params, ''))
        self.assertIsNone(_resolve_credential_record(params, None))

    @mock.patch('keepercommander.commands.tunnel_and_connections.try_resolve_path', return_value=None)
    @mock.patch('keepercommander.vault.KeeperRecord.load')
    def test_exact_title_match_returns_uid(self, mock_load, mock_resolve_path):
        params = _FakeParams({'uid-1': {}, 'uid-2': {}})

        def load_side_effect(_params, uid):
            return {'uid-1': _FakeRecord('My Server'), 'uid-2': _FakeRecord('Other Record')}[uid]

        mock_load.side_effect = load_side_effect
        self.assertEqual(_resolve_credential_record(params, 'My Server'), 'uid-1')

    @mock.patch('keepercommander.commands.tunnel_and_connections.try_resolve_path', return_value=None)
    @mock.patch('keepercommander.vault.KeeperRecord.load')
    def test_ambiguous_title_returns_none(self, mock_load, mock_resolve_path):
        params = _FakeParams({'uid-1': {}, 'uid-2': {}})
        mock_load.return_value = _FakeRecord('Duplicate Title')
        self.assertIsNone(_resolve_credential_record(params, 'Duplicate Title'))

    @mock.patch('keepercommander.commands.tunnel_and_connections.try_resolve_path', return_value=None)
    @mock.patch('keepercommander.vault.KeeperRecord.load', return_value=None)
    def test_no_match_returns_none(self, mock_load, mock_resolve_path):
        params = _FakeParams({'uid-1': {}})
        self.assertIsNone(_resolve_credential_record(params, 'Nonexistent'))


class TestEphemeralGatewayTimeoutMs(unittest.TestCase):
    def test_default_when_not_ephemeral(self):
        self.assertEqual(ephemeral_gateway_timeout_ms(False, default=30000), 30000)

    def test_bumped_when_ephemeral(self):
        self.assertEqual(ephemeral_gateway_timeout_ms(True, default=30000), 120000)

    @mock.patch.dict('os.environ', {'PAM_GATEWAY_OFFER_TIMEOUT_EPHEMERAL_MS': '45000'})
    def test_bump_respects_env_override(self):
        self.assertEqual(ephemeral_gateway_timeout_ms(True, default=30000), 45000)


class TestCredentialOverridePayloadFields(unittest.TestCase):
    def test_data_fields_for_user_supplied(self):
        # RDP-style override: username/password only, no key material.
        # Regression check that adding SSH's private_key/passphrase support
        # doesn't affect RDP's existing username/password-only case.
        fields = credential_override_data_fields('userSupplied', {'username': 'bob', 'password': 'secret'})
        self.assertEqual(fields, {'username': 'bob', 'password': 'secret'})

    def test_data_fields_include_private_key_and_passphrase_when_present(self):
        fields = credential_override_data_fields('userSupplied', {
            'username': 'bob',
            'password': '',
            'private_key': '-----BEGIN OPENSSH PRIVATE KEY-----...',
            'passphrase': 'key-passphrase',
        })
        self.assertEqual(fields, {
            'username': 'bob',
            'password': '',
            'private_key': '-----BEGIN OPENSSH PRIVATE KEY-----...',
            'passphrase': 'key-passphrase',
        })

    def test_data_fields_omit_private_key_and_passphrase_when_absent(self):
        fields = credential_override_data_fields('userSupplied', {'username': 'bob', 'password': 'secret'})
        self.assertNotIn('private_key', fields)
        self.assertNotIn('passphrase', fields)

    def test_data_fields_omit_private_key_and_passphrase_when_empty(self):
        fields = credential_override_data_fields('userSupplied', {
            'username': 'bob', 'password': 'secret', 'private_key': '', 'passphrase': '',
        })
        self.assertNotIn('private_key', fields)
        self.assertNotIn('passphrase', fields)

    def test_data_fields_empty_when_not_user_supplied(self):
        self.assertEqual(credential_override_data_fields(None, {'username': 'bob', 'password': 'secret'}), {})
        self.assertEqual(credential_override_data_fields('linked', {'username': 'bob', 'password': 'secret'}), {})

    def test_data_fields_empty_when_no_credential_data(self):
        self.assertEqual(credential_override_data_fields('userSupplied', None), {})

    def test_input_fields_for_user_supplied(self):
        self.assertEqual(
            credential_override_input_fields('userSupplied'),
            {'credentialType': 'userSupplied', 'allowSupplyUser': True},
        )

    def test_input_fields_empty_when_not_user_supplied(self):
        self.assertEqual(credential_override_input_fields(None), {})
        self.assertEqual(credential_override_input_fields('linked'), {})


if __name__ == '__main__':
    unittest.main()
