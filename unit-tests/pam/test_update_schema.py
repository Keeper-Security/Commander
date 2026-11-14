"""`update_schema`: raw import-JSON path -> vault target, and the drift guard against the import parsers."""
import logging
import re
import unittest
from pathlib import Path

from keepercommander.commands.pam_import import update_schema as us
from keepercommander.commands.pam_import.base import (
    DagSettingsObject,
    PamPortForwardSettings,
    PamRemoteBrowserSettings,
    PamSettingsFieldData,
)

BASE_PY = Path(us.__file__).with_name('base.py')

PROTOCOLS = ['rdp', 'ssh', 'vnc', 'telnet', 'kubernetes', 'http', 'sql-server', 'postgresql', 'mysql', 'mariadb',
             'oracle', 'mongodb', 'redis', 'elasticsearch', 'clickhouse', 'dynamodb']
SAMPLES = [True, 'sample', 5, 32, 96, 1920, 22, 30, 10, 1, 'Sample', '5', ['a', 'b'], 'en-us-qwerty', 'unix',
           'windows', 'ctrl-c', 'x11', 'utf-8', 'red-black', 'xterm', 'default', '1.2', 'yes', 'tls', 'plain', 'sjis',
           'clipboard', 'auto']

# Keys whose parsers accept only a few values, so the generic samples never change the output. (protocol, value,
# expected output key); the output is checked with the value given.
HINTS = {
    'backspace': ('ssh', '8', 'backspace'),
    'cursor': ('vnc', 'local', 'cursor'),
    'encodings': ('vnc', 'zrle', 'encodings'),
    'resize_method': ('rdp', 'reconnect', 'resizeMethod'),
    'protocol_version': ('sql-server', '7.4', 'protocolVersion'),
    'db_connection_method': ('postgresql', 'keeperDB', 'dbConnectionMethod'),
    'audio_bps': ('http', 16, 'audioBps'),
    'wol_mac_addr': ('ssh', 'aa:bb:cc:dd:ee:ff', 'wolMacAddr'),
    'wol_broadcast_addr': ('ssh', '1.1.1.1', 'wolBroadcastAddr'),
}
# Accepted by the parser but no sample made it visible in the output; only checked to still exist in the parser.
NOT_VISIBLE = {'drive_redirection_path', 'func_keys_and_keypad', 'session_persistence', 'disable_dynamic_resizing',
               'allow_url_manipulation'}
# reference keys (not output keys of the connection object) are checked by name only
REF_KEYS = set(us.CONNECTION_REFS) | set(us.SFTP_REFS)


def _connection(protocol, extra):
    """The vault connection dict the import builds for a raw connection (None when it does not load)."""
    # an RBI connection with no setting is "empty" and loads as None: it gets one seed key
    seed = {'allow_url_manipulation': True} if protocol == 'http' else {}
    data = {'connection': {'protocol': protocol, 'port': '1', **seed, **extra}}
    loader = PamRemoteBrowserSettings if protocol == 'http' else PamSettingsFieldData
    try:
        loaded = loader.load(data)
    except Exception:   # pylint: disable=broad-except
        return None
    if loaded is None or loaded.connection is None:
        return None
    try:
        return loaded.connection.to_record_dict()
    except Exception:   # pylint: disable=broad-except
        return None


def _changed(base, out):
    return {k for k in set(base) | set(out) if base.get(k) != out.get(k)}


def _literals():
    text = BASE_PY.read_text(encoding='utf-8')
    return set(re.findall(r'''["']([a-z][a-z0-9]*(?:_[a-z0-9]+)*)["']''', text))


class TestExplicitPaths(unittest.TestCase):
    def test_nested_keys_become_dotted_paths(self):
        raw = {'title': 'x', 'pam_settings': {'connection': {'port': '22', 'sftp': {'enable_sftp': True}}}}
        self.assertEqual(us.explicit_paths(raw),
                         ['pam_settings.connection.port', 'pam_settings.connection.sftp.enable_sftp', 'title'])

    def test_a_list_is_one_leaf_and_an_empty_dict_is_a_leaf(self):
        raw = {'users': [{'login': 'a'}], 'pam_settings': {'connection': {}, 'options': {'rotation': 'on'}}}
        self.assertEqual(us.explicit_paths(raw),
                         ['pam_settings.connection', 'pam_settings.options.rotation', 'users'])

    def test_a_key_written_with_null_is_still_explicit(self):
        self.assertEqual(us.explicit_paths({'notes': None}), ['notes'])

    def test_not_a_dict(self):
        self.assertEqual(us.explicit_paths('x'), [])
        self.assertEqual(us.explicit_paths({}), [])


class TestResolve(unittest.TestCase):
    def test_top_level_record_rows(self):
        self.assertEqual(us.resolve('title', 'pamMachine').scope, us.SCOPE_STANDARD)
        host = us.resolve('host', 'pamMachine')
        port = us.resolve('port', 'pamMachine')
        self.assertEqual((host.field, host.sub, port.field, port.sub), ('pamHostname', 'hostName', 'pamHostname', 'port'))
        self.assertEqual(us.resolve('operating_system', 'pamMachine').label, 'operatingSystem')
        self.assertEqual(us.resolve('otp', 'pamMachine').field, 'oneTimeCode')
        self.assertTrue(us.resolve('otp', 'pamUser').secret)

    def test_family_specific_rows(self):
        self.assertIsNone(us.resolve('url', 'pamMachine'))
        self.assertEqual(us.resolve('url', 'pamRemoteBrowser').field, 'rbiUrl')
        self.assertEqual(us.resolve('url', 'login').field, 'url')
        self.assertTrue(us.resolve('password', 'pamUser').secret)
        self.assertEqual(us.resolve('private_pem_key', 'pamUser').label, 'privatePEMKey')
        self.assertEqual(us.resolve('account_identifier', 'pamCloudResource').field, 'accountNumber')

    def test_identity_files_nested_and_legacy(self):
        for path in ('uid', 'type', 'folder_path'):
            self.assertEqual(us.resolve(path, 'pamMachine').kind, us.KIND_PROTECTED)
        self.assertEqual(us.resolve('attachments', 'pamMachine').kind, us.KIND_FILES)
        self.assertEqual(us.resolve('scripts', 'pamUser').kind, us.KIND_FILES)
        self.assertEqual(us.resolve('users', 'pamMachine').kind, us.KIND_NESTED)
        self.assertEqual(us.resolve('login', 'pamMachine').kind, us.KIND_IGNORED)   # legacy on a machine ...
        self.assertEqual(us.resolve('login', 'pamUser').kind, us.KIND_RECORD)       # ... a real field on a user

    def test_connection_keys_by_rule_and_by_row(self):
        t = us.resolve('pam_settings.connection.enable_touch', 'pamMachine', 'rdp')
        self.assertEqual((t.kind, t.field, t.sub, t.scope), (us.KIND_RECORD, 'pamSettings', 'connection.enableTouch', us.SCOPE_CUSTOM))
        self.assertEqual(us.resolve('pam_settings.connection.pod_name', 'pamMachine', 'kubernetes').sub, 'connection.pod')
        self.assertEqual(us.resolve('pam_settings.connection.default_database', 'pamDatabase', 'mysql').sub, 'connection.database')

    def test_protocol_dependent_rows(self):
        path = 'pam_settings.connection.ignore_server_cert'
        self.assertEqual(us.resolve(path, 'pamMachine', 'rdp').sub, 'connection.ignoreCert')
        self.assertEqual(us.resolve('pam_settings.connection.ignore_server_cert', 'pamRemoteBrowser', 'http').sub,
                         'connection.ignoreInitialSslCert')
        path = 'pam_settings.connection.ca_certificate'
        self.assertEqual(us.resolve(path, 'pamMachine', 'kubernetes').sub, 'connection.caCert')
        self.assertEqual(us.resolve(path, 'pamDatabase', 'sql-server').sub, 'connection.caCertificate')

    def test_rbi_connection_lives_in_its_own_field(self):
        t = us.resolve('pam_settings.connection.allow_url_manipulation', 'pamRemoteBrowser', 'http')
        self.assertEqual((t.field, t.sub, t.scope), ('pamRemoteBrowserSettings', 'connection.allowUrlManipulation', us.SCOPE_ANY))

    def test_sftp_and_port_forward(self):
        self.assertEqual(us.resolve('pam_settings.connection.sftp.sftp_upload_directory', 'pamMachine', 'rdp').sub,
                         'connection.sftp.sftpDirectory')
        self.assertEqual(us.resolve('pam_settings.connection.sftp.enable_sftp', 'pamMachine', 'ssh').sub,
                         'connection.sftp.enableSftp')
        self.assertEqual(us.resolve('pam_settings.port_forward.allow_keeper_db_proxy', 'pamDatabase').sub,
                         'portForward.allowKeeperDBProxy')
        self.assertEqual(us.resolve('pam_settings.port_forward.reuse_port', 'pamMachine').sub, 'portForward.reusePort')
        self.assertEqual(us.resolve('pam_settings.allow_supply_host', 'pamMachine').sub, 'allowSupplyHost')
        self.assertIsNone(us.resolve('pam_settings.port_forward.nope', 'pamMachine'))
        self.assertIsNone(us.resolve('pam_settings.port_forward', 'pamRemoteBrowser'))

    def test_references(self):
        self.assertEqual(us.resolve('pam_settings.connection.administrative_credentials', 'pamMachine').comparator,
                         'admin_credential')
        self.assertEqual(us.resolve('pam_settings.connection.launch_credentials', 'pamMachine').comparator,
                         'launch_credential')
        self.assertEqual(us.resolve('pam_settings.connection.autofill_credentials', 'pamRemoteBrowser').comparator,
                         'http_credentials')
        self.assertEqual(us.resolve('pam_settings.connection.sftp.sftp_user_credentials', 'pamMachine').comparator,
                         'sftp_user')

    def test_options_flags_jit_ai_workflow(self):
        t = us.resolve('pam_settings.options.tunneling', 'pamMachine')
        self.assertEqual((t.kind, t.comparator, t.key), (us.KIND_GRAPH, 'meta', 'allowedSettings.portForwards'))
        self.assertEqual(us.resolve('pam_settings.options.update_services', 'pamMachine').key, 'no_update_services')
        self.assertEqual(us.resolve('pam_settings.options.jit_settings.create_ephemeral', 'pamMachine').comparator,
                         'jit_settings')
        self.assertEqual(us.resolve('pam_settings.options.ai_settings.risk_levels', 'pamRemoteBrowser').comparator,
                         'ai_settings')
        self.assertEqual(us.resolve('pam_settings.options.workflow.approvals_needed', 'pamMachine').kind, us.KIND_API)
        self.assertEqual(us.resolve('pam_settings.connection.rotate_creds_on_session_termination', 'pamMachine').key,
                         'rotateOnTermination')

    def test_unsupported_for_rbi_and_owned_by_the_backend(self):
        self.assertEqual(us.resolve('pam_settings.options.jit_settings', 'pamRemoteBrowser').kind, us.KIND_IGNORED)
        self.assertEqual(us.resolve('pam_settings.options.update_services', 'pamRemoteBrowser').kind, us.KIND_IGNORED)
        self.assertEqual(us.resolve('pam_settings.options.locked', 'pamMachine').kind, us.KIND_IGNORED)
        self.assertEqual(us.resolve('pam_settings.options.resource', 'pamMachine').kind, us.KIND_IGNORED)

    def test_user_rotation_settings(self):
        t = us.resolve('rotation_settings.schedule.type', 'pamUser')
        self.assertEqual((t.kind, t.comparator, t.key), (us.KIND_API, 'rotation', 'schedule.type'))

    def test_unknown_keys_and_unknown_types(self):
        self.assertIsNone(us.resolve('no_such_key', 'pamMachine'))
        self.assertIsNone(us.resolve('pam_settings.connection.no_such_key', 'pamMachine', 'rdp'))
        self.assertIsNone(us.resolve('pam_settings.connection.sftp.nope', 'pamMachine', 'rdp'))
        self.assertIsNone(us.resolve('title', 'somethingElse'))

    def test_the_whole_connection_object(self):
        t = us.resolve('pam_settings.connection', 'pamMachine')
        self.assertEqual((t.field, t.sub), ('pamSettings', 'connection'))


class TestClassify(unittest.TestCase):
    def test_mapped_and_unmapped_paths(self):
        raw = {'type': 'pamMachine', 'title': 'm', 'host': 'h', 'bogus': 1,
               'pam_settings': {'connection': {'protocol': 'rdp', 'port': '3389', 'nope': 1}}}
        result = us.classify(raw)
        self.assertEqual(sorted(result.unmapped), ['bogus', 'pam_settings.connection.nope'])
        self.assertIn('pam_settings.connection.port', result.mapped)
        self.assertEqual(result.mapped['title'].scope, us.SCOPE_STANDARD)

    def test_protocol_is_taken_from_the_raw_item(self):
        raw = {'pam_settings': {'connection': {'protocol': 'kubernetes', 'ca_certificate': 'x'}}}
        result = us.classify(raw, 'pamMachine')
        self.assertEqual(result.mapped['pam_settings.connection.ca_certificate'].sub, 'connection.caCert')

    def test_unmapped_warning_text(self):
        self.assertEqual(us.unmapped_warning('x.y', 'M1'), '"M1": key "x.y" is not handled by update (ignored)')


class TestOverwriteRemovable(unittest.TestCase):
    def test_only_record_fields_and_never_identity_like_ones(self):
        self.assertTrue(us.removable_in_overwrite(us.resolve('operating_system', 'pamMachine')))
        self.assertTrue(us.removable_in_overwrite(us.resolve('pam_settings.connection.port', 'pamMachine', 'ssh')))
        self.assertFalse(us.removable_in_overwrite(us.resolve('title', 'pamMachine')))
        self.assertFalse(us.removable_in_overwrite(us.resolve('host', 'pamMachine')))
        self.assertFalse(us.removable_in_overwrite(us.resolve('password', 'pamUser')))
        self.assertFalse(us.removable_in_overwrite(us.resolve('pam_settings.options.rotation', 'pamMachine')))
        self.assertFalse(us.removable_in_overwrite(us.resolve('uid', 'pamMachine')))


class TestDriftGuard(unittest.TestCase):
    """The key lists must follow the import parsers: load them with and without each key and compare."""

    @classmethod
    def setUpClass(cls):
        logging.disable(logging.CRITICAL)
        cls.addClassCleanup(logging.disable, logging.NOTSET)
        cls.literals = _literals()

    def test_every_key_in_the_registry_is_still_in_the_parsers(self):
        stale = sorted(k for k in us.CONNECTION_KEYS | us.SFTP_KEYS | us.PORT_FORWARD_KEYS if k not in self.literals)
        self.assertEqual(stale, [], 'registry keys that no parser mentions any more')

    def test_every_key_the_parsers_accept_is_in_the_registry_with_the_right_output_key(self):
        problems = []
        seen = set()
        for protocol in PROTOCOLS:
            base = _connection(protocol, {})
            if base is None:
                problems.append(f'{protocol}: cannot be loaded')
                continue
            for key in sorted(self.literals):
                if key in ('protocol', 'port', 'allow_url_manipulation') or key in REF_KEYS:
                    continue
                for sample in SAMPLES:
                    out = _connection(protocol, {key: sample})
                    if out is None:
                        continue
                    changed = _changed(base, out)
                    if not changed:
                        continue
                    seen.add(key)
                    if key not in us.CONNECTION_KEYS:
                        problems.append(f'{protocol}: new connection key "{key}" -> {sorted(changed)} is not in CONNECTION_KEYS')
                    elif key != 'disable_dynamic_resizing' and changed != {us.connection_output_key(key, protocol)}:
                        problems.append(f'{protocol}: "{key}" changes {sorted(changed)}, schema says '
                                        f'"{us.connection_output_key(key, protocol)}"')
                    break
        self.assertEqual(problems, [])
        # sanity: the probe really found a lot (a broken harness would find nothing and pass)
        self.assertGreater(len(seen), 80)

    def test_keys_that_need_a_particular_value(self):
        for key, (protocol, value, expected) in HINTS.items():
            base = _connection(protocol, {})
            out = _connection(protocol, {key: value})
            self.assertEqual(_changed(base, out), {expected}, key)
            self.assertIn(key, us.CONNECTION_KEYS, key)
            self.assertEqual(us.connection_output_key(key, protocol), expected, key)

    def test_keys_that_are_accepted_but_not_visible_still_exist(self):
        for key in NOT_VISIBLE:
            self.assertIn(key, self.literals)
            self.assertIn(key, us.CONNECTION_KEYS)

    def test_sftp_keys(self):
        problems = []
        seen = set()
        for protocol in ('rdp', 'ssh', 'vnc'):
            base = _connection(protocol, {})
            for key in sorted(self.literals):
                for sample in SAMPLES:
                    out = _connection(protocol, {'sftp': {key: sample}})
                    if out is None:
                        continue
                    before, after = base.get('sftp') or {}, out.get('sftp') or {}
                    changed = _changed(before, after)
                    if not changed:
                        continue
                    seen.add(key)
                    if key not in us.SFTP_KEYS:
                        problems.append(f'new sftp key "{key}" -> {sorted(changed)}')
                    elif changed != {us.sftp_output_key(key)}:
                        problems.append(f'"{key}" changes {sorted(changed)}, schema says "{us.sftp_output_key(key)}"')
                    break
        self.assertEqual(problems, [])
        self.assertEqual(seen, set(us.SFTP_KEYS))

    def test_port_forward_keys(self):
        problems = []
        seen = set()
        base = PamPortForwardSettings.load({}).to_record_dict()
        for key in sorted(self.literals):
            for sample in SAMPLES:
                out = PamPortForwardSettings.load({key: sample}).to_record_dict()
                changed = _changed(base, out)
                if not changed:
                    continue
                seen.add(key)
                if key not in us.PORT_FORWARD_KEYS:
                    problems.append(f'new port_forward key "{key}" -> {sorted(changed)}')
                elif changed != {us.port_forward_output_key(key)}:
                    problems.append(f'"{key}" changes {sorted(changed)}, schema says "{us.port_forward_output_key(key)}"')
                break
        self.assertEqual(problems, [])
        self.assertEqual(seen, set(us.PORT_FORWARD_KEYS))

    def test_every_option_flag_of_the_parser_has_a_row(self):
        attrs = set(vars(DagSettingsObject()))
        raw_names = {'pam_resource': 'resource'}
        for attr in attrs:
            raw = raw_names.get(attr, attr)
            self.assertTrue(raw in us.OPTION_FLAGS or raw in us.OPTION_IGNORED, f'options.{raw} has no row')
        for flag in us.OPTION_FLAGS:
            self.assertIn(flag, {raw_names.get(a, a) for a in attrs}, f'options.{flag} is not parsed any more')


if __name__ == '__main__':
    unittest.main()
