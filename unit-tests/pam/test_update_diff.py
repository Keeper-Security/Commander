"""`update_diff`: what `pam project update` would change (pure functions, no server)."""
import json
import logging
import unittest
import unittest.mock

from keepercommander.commands.pam_import import update_diff as ud
from keepercommander.commands.pam_import import update_schema as us
from keepercommander.commands.pam_import.base import (
    DagJitSettingsObject,
    PamMachineObject,
    PamRemoteBrowserObject,
    PamUserObject,
)
from keepercommander.commands.pam_import.pam_record_build import _apply_pam_settings_fields, build_record_add_kwargs


def _field(type_, value, label=None):
    item = {'type': type_, 'value': [value] if value is not None else []}
    if label is not None:
        item['label'] = label
    return item


def vault_machine(**over):
    """A vault record JSON of a pamMachine as `get --format=json` shows it."""
    data = {
        'title': 'M1', 'notes': '', 'type': 'pamMachine',
        'fields': [
            _field('pamHostname', {'hostName': 'h1', 'port': '22'}),
            _field('text', 'linux', 'operatingSystem'),
            _field('checkbox', True, 'sslVerification'),
        ],
        'custom': [
            _field('pamSettings', {'allowSupplyHost': False,
                                   'portForward': {},
                                   'connection': {'protocol': 'ssh', 'port': '2222', 'recordingIncludeKeys': True}}),
        ],
    }
    data.update(over)
    return data


def load_machine(raw):
    return PamMachineObject.load(raw)


def diff(raw, current, **kw):
    obj = load_machine(raw)
    return ud.diff_record(raw, 'pamMachine', obj, current, **kw)


def paths(result, kind=None):
    return sorted(c.path for c in result.changes if kind in (None, c.kind))


class TestValues(unittest.TestCase):
    def test_same_ignores_whitespace_and_number_text_forms(self):
        self.assertTrue(ud.same(' a ', 'a'))
        self.assertTrue(ud.same('22', 22))
        self.assertTrue(ud.same({'a': ' x '}, {'a': 'x'}))
        self.assertFalse(ud.same('22', 23))

    def test_a_checkbox_is_not_a_number(self):
        self.assertFalse(ud.same(True, 1))
        self.assertFalse(ud.same(1, True))
        self.assertFalse(ud.same(False, 0))
        self.assertTrue(ud.same(True, True))

    def test_blank(self):
        for value in (None, '', [], {}):
            self.assertTrue(ud.is_blank(value))
        for value in (0, False, 'x', [0]):
            self.assertFalse(ud.is_blank(value))


class TestMerge(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def test_identical_record_has_no_changes(self):
        raw = {'type': 'pamMachine', 'title': 'M1', 'host': 'h1', 'port': '22', 'operating_system': 'linux',
               'ssl_verification': True,
               'pam_settings': {'connection': {'protocol': 'ssh', 'port': '2222'}}}
        result = diff(raw, vault_machine())
        self.assertEqual(result.changes, [])
        self.assertFalse(result.differs)

    def test_a_written_key_wins_and_shows_old_and_new(self):
        raw = {'type': 'pamMachine', 'pam_settings': {'connection': {'protocol': 'ssh', 'port': '22'}}}
        result = diff(raw, vault_machine())
        change, = result.changes
        self.assertEqual((change.kind, change.op, change.path, change.old, change.new),
                         (ud.KIND_RECORD, ud.OP_CHANGE, 'pamSettings.connection.port', '2222', '22'))

    def test_a_key_the_json_does_not_write_is_left_alone(self):
        # the loader would fill a default port; the vault keeps 2222 and recordingIncludeKeys
        raw = {'type': 'pamMachine', 'pam_settings': {'connection': {'protocol': 'ssh'}}}
        self.assertEqual(diff(raw, vault_machine()).changes, [])

    def test_a_missing_value_is_added(self):
        raw = {'type': 'pamMachine', 'instance_name': 'i-1'}
        result = diff(raw, vault_machine())
        change, = result.changes
        self.assertEqual((change.op, change.path, change.new), (ud.OP_ADD, 'text "instanceName"', 'i-1'))

    def test_host_and_port_are_two_keys_of_one_field(self):
        raw = {'type': 'pamMachine', 'host': 'h2'}
        change, = diff(raw, vault_machine()).changes
        self.assertEqual((change.path, change.old, change.new), ('pamHostname.hostName', 'h1', 'h2'))

    def test_title_and_notes(self):
        raw = {'type': 'pamMachine', 'title': 'Renamed', 'notes': 'new note'}
        result = diff(raw, vault_machine(notes='old note'))
        self.assertEqual(paths(result), ['notes', 'title'])

    def test_notes_are_hidden_but_the_title_is_not(self):
        raw = {'type': 'pamMachine', 'title': 'Renamed', 'notes': 'secret note'}
        result = diff(raw, vault_machine(notes='old'))
        by_path = {c.path: c for c in result.changes}
        self.assertEqual(by_path['notes'].shown(), (ud.HIDDEN, ud.HIDDEN))
        self.assertEqual(by_path['title'].shown(), ('M1', 'Renamed'))

    def test_checkbox_difference(self):
        raw = {'type': 'pamMachine', 'ssl_verification': False}
        change, = diff(raw, vault_machine()).changes
        self.assertEqual((change.op, change.old, change.new), (ud.OP_CHANGE, True, False))

    def test_unknown_key_is_a_warning_and_not_a_change(self):
        raw = {'type': 'pamMachine', 'colour': 'red', 'pam_settings': {'connection': {'protocol': 'ssh', 'nope': 1}}}
        result = diff(raw, vault_machine())
        self.assertEqual(result.changes, [])
        self.assertEqual(len(result.warnings), 2)
        self.assertTrue(all('is not handled by update' in w for w in result.warnings))

    def test_a_value_the_parser_rejects_is_a_warning(self):
        raw = {'type': 'pamMachine', 'pam_settings': {'connection': {'protocol': 'rdp', 'width': 'abc'}}}
        result = diff(raw, vault_machine())
        self.assertTrue(any('was not accepted by the import parser' in w and 'width' in w for w in result.warnings))

    def test_rbi_record(self):
        raw = {'type': 'pamRemoteBrowser', 'url': 'https://b',
               'pam_settings': {'connection': {'protocol': 'http', 'allow_url_manipulation': True}}}
        obj = PamRemoteBrowserObject.load(raw)
        current = {'title': 'R', 'notes': '', 'type': 'pamRemoteBrowser',
                   'fields': [_field('rbiUrl', 'https://a'),
                              _field('pamRemoteBrowserSettings',
                                     {'connection': {'protocol': 'http', 'allowUrlManipulation': False}})],
                   'custom': []}
        result = ud.diff_record(raw, 'pamRemoteBrowser', obj, current)
        by_path = {c.path: c for c in result.changes}
        self.assertEqual(by_path['rbiUrl'].new, 'https://b')
        self.assertEqual(by_path['pamRemoteBrowserSettings.connection.allowUrlManipulation'].new, True)


class TestPasswords(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        self.raw = {'type': 'pamUser', 'title': 'u1', 'login': 'root', 'password': 'NEW-SECRET'}
        self.obj = PamUserObject.load(self.raw)
        self.current = {'title': 'u1', 'notes': '', 'type': 'pamUser',
                        'fields': [_field('login', 'root'), _field('password', 'OLD-SECRET')], 'custom': []}

    def run_diff(self, **kw):
        return ud.diff_record(self.raw, 'pamUser', self.obj, self.current, **kw)

    def test_a_differing_password_is_only_counted_by_default(self):
        result = self.run_diff()
        self.assertEqual(result.changes, [])
        self.assertEqual((result.passwords_skipped, result.passwords_to_write), (1, 0))

    def test_with_the_flag_it_is_written_hidden_and_counted(self):
        result = self.run_diff(include_passwords=True, rotating=True)
        change, = result.changes
        self.assertTrue(change.secret and change.hidden)
        self.assertEqual(change.shown(), (ud.HIDDEN, ud.HIDDEN))
        self.assertNotIn('SECRET', repr(change.shown()))
        self.assertEqual((result.passwords_to_write, result.passwords_on_rotating, result.passwords_skipped), (1, 1, 0))

    def test_an_equal_password_is_not_counted(self):
        self.current['fields'][1] = _field('password', 'NEW-SECRET')
        result = self.run_diff(include_passwords=True)
        self.assertEqual((result.changes, result.passwords_to_write, result.passwords_skipped), ([], 0, 0))

    def test_omission_never_wipes_a_password_even_in_overwrite(self):
        raw = {'type': 'pamUser', 'title': 'u1', 'login': 'root'}
        obj = PamUserObject.load(raw)
        result = ud.diff_record(raw, 'pamUser', obj, self.current, mode=ud.MODE_OVERWRITE, include_passwords=True)
        self.assertEqual([c for c in result.changes if 'password' in c.path], [])


class TestOverwrite(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def test_extra_keys_in_the_settings_object_are_removed_and_defaults_added(self):
        raw = {'type': 'pamMachine', 'host': 'h1', 'port': '22', 'operating_system': 'linux', 'ssl_verification': True,
               'pam_settings': {'connection': {'protocol': 'ssh', 'port': '2222'}}}
        result = diff(raw, vault_machine(), mode=ud.MODE_OVERWRITE)
        removed = [c.path for c in result.changes if c.op == ud.OP_REMOVE]
        self.assertEqual(removed, ['pamSettings.connection.recordingIncludeKeys'])
        self.assertEqual(result.changes[0].old, True)

    def test_a_key_added_by_a_newer_vault_is_removed(self):
        current = vault_machine()
        current['custom'][0]['value'][0]['connection']['futureKey'] = 'x'
        raw = {'type': 'pamMachine', 'pam_settings': {'connection': {'protocol': 'ssh', 'port': '2222'}}}
        removed = {c.path for c in diff(raw, current, mode=ud.MODE_OVERWRITE).changes if c.op == ud.OP_REMOVE}
        self.assertIn('pamSettings.connection.futureKey', removed)

    def test_protected_and_reference_keys_are_never_removed(self):
        current = vault_machine()
        conn = current['custom'][0]['value'][0]['connection']
        conn.update({'locked': True, 'service_names': ['a'], 'userRecords': ['UID1'], 'launchRecordUid': 'UID2'})
        raw = {'type': 'pamMachine', 'pam_settings': {'connection': {'protocol': 'ssh', 'port': '2222'}}}
        removed = {c.path for c in diff(raw, current, mode=ud.MODE_OVERWRITE).changes if c.op == ud.OP_REMOVE}
        for key in ('locked', 'service_names', 'userRecords', 'launchRecordUid'):
            self.assertNotIn(f'pamSettings.connection.{key}', removed)

    def test_a_known_field_the_json_does_not_set_is_removed_but_not_title_or_host(self):
        raw = {'type': 'pamMachine'}
        removed = {c.path for c in diff(raw, vault_machine(), mode=ud.MODE_OVERWRITE).changes if c.op == ud.OP_REMOVE}
        self.assertEqual(removed, {'text "operatingSystem"', 'checkbox "sslVerification"'})

    def test_without_pam_settings_in_the_json_the_settings_object_is_left_alone(self):
        raw = {'type': 'pamMachine', 'host': 'h1'}
        removed = {c.path for c in diff(raw, vault_machine(), mode=ud.MODE_OVERWRITE).changes if c.op == ud.OP_REMOVE}
        self.assertFalse(any(p.startswith('pamSettings') for p in removed))

    def test_merge_never_removes(self):
        raw = {'type': 'pamMachine', 'pam_settings': {'connection': {'protocol': 'ssh', 'port': '2222'}}}
        self.assertEqual([c for c in diff(raw, vault_machine()).changes if c.op == ud.OP_REMOVE], [])


class TestCustomFields(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)
        self.raw = {'type': 'pamUser', 'title': 'u', 'login': 'l',
                    'custom': [{'label': 'Owner', 'value': 'ops'}, {'label': 'Team', 'value': 'x'}]}
        self.obj = PamUserObject.load(self.raw)
        self.current = {'title': 'u', 'notes': '', 'type': 'pamUser', 'fields': [_field('login', 'l')],
                        'custom': [_field('text', 'old', 'Owner'), _field('text', 'keep', 'Other'),
                                   _field('secret', 'tok', 'Token')]}

    def test_merge_changes_adds_and_keeps_the_rest(self):
        result = ud.diff_record(self.raw, 'pamUser', self.obj, self.current)
        self.assertEqual({(c.op, c.path) for c in result.changes},
                         {(ud.OP_CHANGE, 'custom "Owner"'), (ud.OP_ADD, 'custom "Team"')})

    def test_overwrite_removes_unlisted_custom_fields_but_not_secrets(self):
        result = ud.diff_record(self.raw, 'pamUser', self.obj, self.current, mode=ud.MODE_OVERWRITE)
        removed = [c.path for c in result.changes if c.op == ud.OP_REMOVE]
        self.assertEqual(removed, ['custom "Other"'])

    def test_labels_match_without_regard_to_case(self):
        self.current['custom'][0]['label'] = 'owner'
        self.current['custom'][0]['value'] = ['ops']
        result = ud.diff_record(self.raw, 'pamUser', self.obj, self.current)
        self.assertEqual([c.path for c in result.changes], ['custom "Team"'])


class TestMeta(unittest.TestCase):
    CURRENT = {'version': 1, 'rotateOnTermination': False, 'locked': True,
               'allowedSettings': {'connections': True, 'portForwards': False, 'rotation': True}}

    def test_flags_map_to_the_meta_keys(self):
        changes, warnings = ud.diff_meta({'connections': 'off', 'tunneling': 'on', 'graphical_session_recording': 'on'},
                                         None, self.CURRENT)
        self.assertEqual(warnings, [])
        got = {(c.op, c.path, c.new) for c in changes}
        self.assertEqual(got, {(ud.OP_CHANGE, 'meta.allowedSettings.connections', False),
                               (ud.OP_CHANGE, 'meta.allowedSettings.portForwards', True),
                               (ud.OP_ADD, 'meta.allowedSettings.sessionRecording', True)})

    def test_an_equal_flag_is_no_change_and_a_bool_is_on_or_off(self):
        self.assertEqual(ud.diff_meta({'connections': True, 'rotation': 'on'}, None, self.CURRENT), ([], []))

    def test_default_cannot_be_applied_through_the_router_so_it_is_a_warning_not_a_change(self):
        changes, warnings = ud.diff_meta({'rotation': 'default'}, None, self.CURRENT)
        self.assertEqual(changes, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn('meta.allowedSettings.rotation', warnings[0])
        self.assertIn('through the router', warnings[0])
        # a flag that is not set in the vault has nothing to reset: no warning
        self.assertEqual(ud.diff_meta({'sessionRecording': 'default'}, None, self.CURRENT), ([], []))

    def test_update_services_is_stored_inverted(self):
        (change,), _ = ud.diff_meta({'update_services': 'off'}, None, self.CURRENT)
        self.assertEqual((change.path, change.new), ('meta.no_update_services', True))
        self.assertEqual(ud.diff_meta({'update_services': 'on'}, None, {'no_update_services': False}), ([], []))

    def test_rotate_creds_on_session_termination(self):
        (change,), _ = ud.diff_meta({}, {'rotate_creds_on_session_termination': True}, self.CURRENT)
        self.assertEqual((change.path, change.old, change.new), ('meta.rotateOnTermination', False, True))

    def test_the_graph_side_of_overwrite_is_off_unless_asked_for(self):
        raw = {'connections': 'on'}
        self.assertEqual(ud.diff_meta(raw, None, self.CURRENT, mode=ud.MODE_OVERWRITE), ([], []))
        changes, warnings = ud.diff_meta(raw, None, self.CURRENT, mode=ud.MODE_OVERWRITE, graph_overwrite=True)
        self.assertEqual(changes, [])      # removals are not changes: the router cannot remove meta keys
        text = ' '.join(warnings)
        for key in ('portForwards', 'rotation', 'rotateOnTermination'):
            self.assertIn(key, text)
        self.assertNotIn('version', text)  # version, locked stay

    def test_no_current_meta(self):
        changes, warnings = ud.diff_meta({'connections': 'on'}, None, None)
        self.assertEqual(([(c.op, c.new) for c in changes], warnings), ([(ud.OP_ADD, True)], []))


class TestJit(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def test_only_the_written_keys_are_compared(self):
        raw = {'create_ephemeral': True, 'elevation_method': 'group'}
        wanted = DagJitSettingsObject.load(raw).to_dag_dict()
        current = {'createEphemeral': False, 'elevate': True, 'elevationMethod': 'group', 'baseDistinguishedName': 'dc=x'}
        changes, warnings = ud.diff_jit(raw, wanted, current)
        self.assertEqual([(c.op, c.path, c.old, c.new) for c in changes],
                         [(ud.OP_CHANGE, 'jit_settings.createEphemeral', False, True)])
        self.assertEqual(warnings, [])

    def test_unknown_key_warns_and_other_homes_do_not(self):
        raw = {'elevate': True, 'bogus': 1, 'pam_directory_record': 'D', 'default_elevation_time': '1h'}
        _, warnings = ud.diff_jit(raw, {'elevate': True}, {'elevate': True})
        self.assertEqual(len(warnings), 1)
        self.assertIn('bogus', warnings[0])

    def test_nothing_without_a_jit_section(self):
        self.assertEqual(ud.diff_jit(None, {}, {}), ([], []))


class TestNotComparedYet(unittest.TestCase):
    RAW = {'type': 'pamMachine', 'title': 'M',
           'pam_settings': {'options': {'ai_settings': {'risk_levels': {}}, 'workflow': {'a': 1}},
                            'connection': {'protocol': 'rdp', 'administrative_credentials': 'u',
                                           'launch_credentials': 'u'}}}

    def test_every_setting_has_a_comparator_now(self):
        self.assertEqual(ud.NOT_COMPARED_YET, {})
        self.assertEqual(ud.not_compared_warnings(self.RAW, 'pamMachine', 'M'), [])

    def test_the_mechanism_reports_once_per_kind_while_a_comparator_is_missing(self):
        registry = {'ai_settings': 'KeeperAI settings', 'workflow': 'workflow',
                    'admin_credential': 'administrative credential', 'launch_credential': 'launch credential'}
        with unittest.mock.patch.dict(ud.NOT_COMPARED_YET, registry):
            warnings = ud.not_compared_warnings(self.RAW, 'pamMachine', 'M')
        text = ' | '.join(warnings)
        for word in ('KeeperAI', 'workflow', 'administrative credential', 'launch credential'):
            self.assertIn(word, text)
        self.assertEqual(len(warnings), 4)

    def test_no_such_settings_no_warnings(self):
        self.assertEqual(ud.not_compared_warnings({'type': 'pamMachine', 'host': 'h'}, 'pamMachine'), [])


class TestDesiredValuesFollowTheBuilders(unittest.TestCase):
    """The desired value of every top-level record row equals what the record builder writes."""

    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def test_machine_rows_match_build_record_add_kwargs(self):
        raw = {'type': 'pamMachine', 'title': 'M', 'notes': 'n', 'host': ' h ', 'port': '22', 'ssl_verification': True,
               'operating_system': 'linux', 'instance_name': 'i', 'instance_id': 'id', 'provider_group': 'g',
               'provider_region': 'r', 'otp': 'otpauth://totp/x?secret=ABC',
               'pam_settings': {'allow_supply_host': True, 'port_forward': {'port': '2200'},
                                'connection': {'protocol': 'ssh', 'port': '22', 'command': 'ls'}}}
        obj = load_machine(raw)
        kwargs = build_record_add_kwargs(obj, 'FOLDER')
        _apply_pam_settings_fields(kwargs, obj, inserted_uids=set())
        written = {}
        for item in kwargs['fields']:
            name, _, value = item.partition('=')
            written[name] = value
        family = us.family_of('pamMachine')
        container = ud.settings_container(obj, family)
        checks = {
            'operating_system': 'f.text.operatingSystem', 'instance_name': 'f.text.instanceName',
            'instance_id': 'f.text.instanceId', 'provider_group': 'f.text.providerGroup',
            'provider_region': 'f.text.providerRegion', 'otp': 'f.oneTimeCode',
        }
        for path, key in checks.items():
            ok, value = ud.desired_value(obj, path, us.resolve(path, 'pamMachine'), family, container)
            self.assertTrue(ok, path)
            self.assertEqual(value, written[key], path)
        hostname = json.loads(written['f.pamHostname'].split('$JSON:', 1)[1])
        for path, key in (('host', 'hostName'), ('port', 'port')):
            ok, value = ud.desired_value(obj, path, us.resolve(path, 'pamMachine'), family, container)
            self.assertEqual(value, hostname[key], path)
        ok, value = ud.desired_value(obj, 'ssl_verification', us.resolve('ssl_verification', 'pamMachine'), family, container)
        self.assertEqual(str(value).lower(), written['f.checkbox.sslVerification'])
        settings = json.loads(written['c.pamSettings'].split('$JSON:', 1)[1])
        self.assertEqual(container, settings)


if __name__ == '__main__':
    unittest.main()
