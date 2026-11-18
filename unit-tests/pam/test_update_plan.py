"""`import_items` and `update_plan`: from the import JSON to a plan, with a fake vault state (no server)."""
import logging
import os
import tempfile
import unittest

from keepercommander.commands.pam_import import update_diff as ud
from keepercommander.commands.pam_import import update_plan as up
from keepercommander.commands.pam_import.import_items import KIND_NESTED_USER, KIND_RESOURCE, KIND_USER, load_items
from keepercommander.commands.pam_import.record_matcher import MatchRecord, RecordIndex
from keepercommander.commands.pam_import.vault_reader import CurrentEdge, GraphState, RecordState, VaultState
from keepercommander.keeper_dag.types import PamGraphId

CFG = 'C' * 22
M1 = 'MACH1' + 'A' * 17
U1 = 'USER1' + 'A' * 17
U2 = 'USER2' + 'A' * 17
IDLE_ROTATION = {'configuration_uid': CFG, 'resource_uid': M1, 'disabled': False, 'schedule': '', 'pwd_complexity': None}
META = {'version': 1, 'allowedSettings': {'connections': True}}


def _f(type_, value, label=None):
    item = {'type': type_, 'value': [value]}
    if label is not None:
        item['label'] = label
    return item


def machine_json(**over):
    data = {'type': 'pamMachine', 'title': 'M1', 'host': 'h1', 'port': '22', 'operating_system': 'linux',
            'pam_settings': {'options': {'connections': 'on'},
                             'connection': {'protocol': 'ssh', 'port': '22', 'administrative_credentials': 'admin1'}},
            'users': [{'type': 'pamUser', 'title': 'admin1', 'login': 'root', 'password': 'pw',
                       'rotation_settings': {'rotation': 'general', 'enabled': 'on',
                                             'schedule': {'type': 'on-demand'}}}]}
    data.update(over)
    return data


def vault_machine():
    return {'title': 'M1', 'notes': '', 'type': 'pamMachine',
            'fields': [_f('pamHostname', {'hostName': 'h1', 'port': '22'}), _f('text', 'linux', 'operatingSystem')],
            'custom': [_f('pamSettings', {'allowSupplyHost': False, 'portForward': {},
                                          'connection': {'protocol': 'ssh', 'port': '22', 'userRecords': [U1]}})]}


def vault_user(password='pw'):
    return {'title': 'admin1', 'notes': '', 'type': 'pamUser',
            'fields': [_f('login', 'root'), _f('password', password)], 'custom': []}


def index():
    return RecordIndex([MatchRecord(uid=M1, title='M1', record_type='pamMachine'),
                        MatchRecord(uid=U1, title='admin1', record_type='pamUser', login='root')])


def state(user=None, meta=META, rotation=IDLE_ROTATION, acl_admin=U1, linked=True, files=()):
    edges = [CurrentEdge(M1, CFG, 'link', None, None)] if linked else []
    if meta is not None:
        edges.append(CurrentEdge(M1, M1, 'data', 'meta', meta))
    if acl_admin:
        edges.append(CurrentEdge(acl_admin, M1, 'acl', None, {'is_admin': True}))
    graph = GraphState(PamGraphId.PAM.value, edges)
    return VaultState(
        config_uid=CFG, graphs={PamGraphId.PAM.value: graph},
        records={M1: RecordState(uid=M1, data=vault_machine(), files=list(files)),
                 U1: RecordState(uid=U1, data=user or vault_user(), rotation=rotation)})


class Quiet(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)


class TestLoadItems(Quiet):
    def test_resources_users_and_nested_users_are_paired_with_their_raw_dicts(self):
        pam_data = {'resources': [machine_json()],
                    'users': [{'type': 'pamUser', 'title': 'u2', 'login': 'x'}, {'title': 'web', 'url': 'https://x'}]}
        items, problems = load_items(pam_data, CFG)
        self.assertEqual(problems, [])
        kinds = [(i.kind, i.record_type, i.title) for i in items]
        self.assertEqual(kinds, [(KIND_USER, 'pamUser', 'u2'), (KIND_USER, 'login', 'web'),
                                 (KIND_RESOURCE, 'pamMachine', 'M1'), (KIND_NESTED_USER, 'pamUser', 'admin1')])
        nested = items[3]
        self.assertIs(nested.parent, items[2])
        self.assertEqual(nested.raw['login'], 'root')
        self.assertEqual(nested.obj.login, 'root')

    def test_unknown_resource_types_are_problems(self):
        items, problems = load_items({'resources': [{'type': 'pamToaster', 'title': 'x'}]}, CFG)
        self.assertEqual(items, [])
        self.assertIn('Incorrect record type "pamToaster"', problems[0])

    def test_every_resource_type_loads(self):
        types = ['pamMachine', 'pamDatabase', 'pamDirectory', 'pamRemoteBrowser', 'pamCloudResource']
        items, _ = load_items({'resources': [{'type': t, 'title': t} for t in types]}, CFG)
        self.assertEqual([i.record_type for i in items], types)

    def test_a_non_pam_user_type_in_a_machine_is_skipped_like_the_loader_does(self):
        raw = machine_json(users=[{'type': 'login', 'title': 'x'}, {'type': 'pamUser', 'title': 'ok', 'login': 'l'}])
        items, _ = load_items({'resources': [raw]}, CFG)
        nested = [i for i in items if i.kind == KIND_NESTED_USER]
        self.assertEqual([n.title for n in nested], ['ok'])


class TestMatching(Quiet):
    def test_items_are_matched_to_vault_uids(self):
        items, _ = load_items({'resources': [machine_json()]}, CFG)
        errors, missing = up.match_items(items, index(), config_uid=CFG)
        self.assertEqual((errors, missing), ([], []))
        self.assertEqual([i.uid for i in items], [M1, U1])

    def test_a_record_that_is_not_in_the_vault_is_an_error_with_the_extend_hint(self):
        items, _ = load_items({'resources': [machine_json(title='Nope', users=[])]}, CFG)
        errors, missing = up.match_items(items, index(), config_uid=CFG)
        self.assertEqual(missing, ['"Nope"'])
        self.assertIn('not found in the vault', errors[0])
        self.assertIn('pam project extend', up.missing_hint(missing))

    def test_the_missing_hint_is_capped(self):
        text = up.missing_hint([f'"r{i}"' for i in range(9)])
        self.assertIn('9 record(s)', text)
        self.assertIn('and 4 more', text)

    def test_type_mismatch_is_an_error(self):
        items, _ = load_items({'resources': [machine_json(type='pamDatabase', users=[])]}, CFG)
        errors, _ = up.match_items(items, index(), config_uid=CFG)
        self.assertIn('update never changes the type', errors[0])

    def test_two_items_with_the_same_title_are_one_duplicate_error(self):
        items, _ = load_items({'resources': [machine_json(users=[]), machine_json(users=[])]}, CFG)
        errors, _ = up.match_items(items, index(), config_uid=CFG)
        self.assertEqual(len(errors), 1)
        self.assertIn('Duplicate import records with same title "M1" in same scope (global)', errors[0])

    def test_the_duplicate_check_ignores_case_and_spaces(self):
        items, _ = load_items({'resources': [machine_json(users=[]), machine_json(title=' m1 ', users=[])]}, CFG)
        errors, _ = up.duplicate_title_errors(items)
        self.assertEqual(len(errors), 1)

    def test_an_explicit_uid_or_another_folder_path_is_not_a_duplicate(self):
        items, _ = load_items({'resources': [machine_json(users=[], uid=M1), machine_json(users=[])]}, CFG)
        self.assertEqual(up.duplicate_title_errors(items)[0], [])
        items, _ = load_items({'resources': [machine_json(users=[], folder_path='A'),
                                              machine_json(users=[], folder_path='B')]}, CFG)
        self.assertEqual(up.duplicate_title_errors(items)[0], [])

    def test_two_different_titles_that_hit_one_record_are_still_an_error(self):
        first = machine_json(users=[], uid=M1, title='First name')
        second = machine_json(users=[], uid=M1, title='Second name')
        items, _ = load_items({'resources': [first, second]}, CFG)
        errors, _ = up.match_items(items, index(), config_uid=CFG)
        self.assertIn('matches the same vault record', errors[0])

    def test_the_config_hook_rejects_a_record_of_another_configuration(self):
        items, _ = load_items({'resources': [machine_json()]}, CFG)
        errors, _ = up.match_items(items, index(), config_uid=CFG,
                                   config_of=lambda uid: 'OTHER' + 'A' * 17 if uid == U1 else None)
        self.assertEqual(len(errors), 1)
        self.assertIn('belongs to configuration ' + 'OTHER' + 'A' * 17 + ', not', errors[0])

    def test_a_valid_uid_in_the_json_wins_over_the_title(self):
        items, _ = load_items({'resources': [machine_json(title='Other name', uid=M1, users=[])]}, CFG)
        up.match_items(items, index(), config_uid=CFG)
        self.assertEqual(items[0].uid, M1)

    def test_the_write_permission_hook_blocks_a_record(self):
        items, _ = load_items({'resources': [machine_json(users=[])]}, CFG)
        errors, _ = up.match_items(items, index(), config_uid=CFG, can_write=lambda uid: False)
        self.assertIn('no write permission', errors[0])


class TestPlan(Quiet):
    SCOPE = [(M1, 'M1', 'pamMachine', ''), (U1, 'admin1', 'pamUser', 'root'), ('X' * 22, 'Other', 'pamMachine', '')]

    def build(self, raw=None, st=None, **kw):
        items, _ = load_items({'resources': [raw or machine_json()]}, CFG)
        return up.build_plan(items, index(), st or state(), config_uid=CFG, scope_records=self.SCOPE, **kw)

    def test_everything_identical(self):
        plan = self.build()
        self.assertEqual(plan.errors, [])
        self.assertEqual((len(plan.results), len(plan.changed), len(plan.identical)), (2, 0, 2))
        self.assertEqual(plan.not_in_json, [('X' * 22, 'Other', 'pamMachine')])

    def test_record_and_graph_changes_are_counted(self):
        raw = machine_json(operating_system='windows')
        raw['pam_settings']['options'] = {'connections': 'off'}
        plan = self.build(raw)
        machine = plan.results[0]
        self.assertEqual({(c.kind, c.path) for c in machine.changes},
                         {(ud.KIND_RECORD, 'text "operatingSystem"'),
                          (ud.KIND_GRAPH, 'meta.allowedSettings.connections')})
        self.assertEqual((machine.record_changes, machine.graph_changes), (1, 1))
        self.assertEqual((plan.record_changes, plan.graph_changes), (1, 1))

    def test_the_admin_credential_title_is_resolved_to_the_matched_user(self):
        plan = self.build(st=state(acl_admin=U2))
        machine = plan.results[0]
        self.assertIn('acl.is_admin', {c.path for c in machine.changes})
        self.assertTrue(any('administrative credential changes from' in w for w in machine.warnings))

    def test_unresolved_reference_is_a_warning(self):
        raw = machine_json()
        raw['pam_settings']['connection']['launch_credentials'] = 'ghost'
        plan = self.build(raw)
        self.assertTrue(any('could not be resolved' in w for w in plan.warnings))

    def test_nested_user_rotation_is_compared_with_the_parent_machine(self):
        plan = self.build(st=state(rotation=dict(IDLE_ROTATION, resource_uid='WRONG')))
        user = plan.results[1]
        self.assertTrue(any('owner (resource) differs' in w for w in user.warnings))
        self.assertEqual(user.graph_changes, 0)

    def test_a_password_difference_is_counted_not_written_by_default(self):
        plan = self.build(st=state(user=vault_user('OLD')))
        self.assertEqual((plan.passwords_skipped, plan.passwords_to_write), (1, 0))
        self.assertEqual(plan.results[1].changes, [])
        on = self.build(include_passwords=True, st=state(user=vault_user('OLD')))
        self.assertEqual((on.passwords_to_write, on.passwords_on_rotating), (1, 1))

    def test_missing_records_make_the_plan_not_ok_and_nothing_is_compared_for_them(self):
        plan = self.build(machine_json(title='Nope', users=[]))
        self.assertFalse(plan.ok)
        self.assertEqual(plan.results, [])
        self.assertTrue(any('pam project extend' in e for e in plan.errors))

    def test_an_unreadable_graph_is_a_warning_not_a_crash(self):
        st = state()
        st.graphs.clear()
        plan = self.build(st=st)
        self.assertTrue(any('PAM graph could not be read' in w for w in plan.warnings))


class TestLinkAndFiles(Quiet):
    SCOPE = TestPlan.SCOPE

    def build(self, raw=None, st=None, **kw):
        items, _ = load_items({'resources': [raw or machine_json(users=[])]}, CFG)
        return up.build_plan(items, index(), st or state(), config_uid=CFG, scope_records=self.SCOPE, **kw)

    def test_a_resource_not_linked_to_this_configuration_is_a_plan_error(self):
        plan = self.build(st=state(linked=False))
        self.assertFalse(plan.ok)
        self.assertTrue(any('not linked to this PAM configuration' in e for e in plan.errors))
        self.assertEqual(plan.results[0].changes, [])          # nothing is compared for it

    def test_a_linked_resource_is_fine(self):
        self.assertTrue(self.build().ok)

    def _file(self, tmp, name, size):
        path = os.path.join(tmp, name)
        with open(path, 'wb') as fh:
            fh.write(b'x' * size)
        return path

    def test_attachment_added_replaced_or_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            same = self._file(tmp, 'same.txt', 10)
            bigger = self._file(tmp, 'bigger.txt', 30)
            new = self._file(tmp, 'new.txt', 5)
            raw = machine_json(users=[], attachments=[same, {'file': bigger}], scripts=[{'file': new, 'script_command': 'sh'}])
            files = [{'name': 'same.txt', 'size': 10}, {'name': 'bigger.txt', 'size': 20}]
            plan = self.build(raw, st=state(files=files))
        got = {(c.op, c.path, c.old, c.new) for c in plan.results[0].changes}
        self.assertEqual(got, {(ud.OP_CHANGE, 'attachment "bigger.txt"', '20 bytes', '30 bytes'),
                               (ud.OP_ADD, 'script "new.txt"', None, '5 bytes')})

    def test_a_file_that_is_missing_on_this_computer_is_a_plan_error(self):
        plan = self.build(machine_json(users=[], attachments=['/no/such/file.bin']))
        self.assertTrue(any('not found on this computer' in e and 'no/such/file.bin' in e for e in plan.errors))

    def test_skip_files_reports_a_warning_and_ignores_missing_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = machine_json(users=[], attachments=['/no/such/file.bin', self._file(tmp, 'a.txt', 1)])
            plan = self.build(raw, skip_files=True)
        self.assertTrue(plan.ok)
        self.assertTrue(any('(--skip-attachments): 2 file(s)' in w for w in plan.warnings))
        self.assertEqual(plan.results[0].changes, [])

    def test_service_mode_disables_files_with_a_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = machine_json(users=[], attachments=[self._file(tmp, 'a.txt', 1)])
            plan = self.build(raw, service_mode=True)
        self.assertTrue(plan.ok)
        self.assertTrue(any('disabled in Service Mode - skipped 1 file(s)' in w for w in plan.warnings))
        self.assertEqual(plan.results[0].changes, [])

    def _script_state(self, name, command='', refs=(), size=5):
        machine = vault_machine()
        machine['fields'].append({'type': 'script', 'value': [{'fileRef': 'FILE1', 'command': command,
                                                                'recordRef': list(refs)}]})
        st = state(files=[{'record_uid': 'FILE1', 'name': name, 'size': size}])
        st.records[M1].data = machine
        return st

    def test_a_script_whose_file_matches_reports_its_other_differences_as_warnings(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self._file(tmp, 'run.sh', 5)
            raw = machine_json(users=[], scripts=[{'file': script, 'script_command': 'bash',
                                                    'additional_credentials': ['admin1']}])
            plan = self.build(raw, st=self._script_state('run.sh', command='sh', refs=()))
        machine = plan.results[0]
        self.assertEqual(machine.changes, [])                  # nothing is uploaded or changed
        text = ' | '.join(machine.warnings)
        self.assertIn('script "run.sh": command differs (vault "sh", JSON "bash")', text)
        self.assertIn('additional credentials differ (vault 0, JSON 1)', text)
        self.assertEqual(text.count('update does not upload a file again'), 2)

    def test_a_script_with_the_same_settings_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self._file(tmp, 'run.sh', 5)
            raw = machine_json(users=[], scripts=[{'file': script, 'script_command': 'sh',
                                                    'additional_credentials': ['admin1']}])
            plan = self.build(raw, st=self._script_state('run.sh', command='sh', refs=[U1]))
        self.assertEqual([w for w in plan.results[0].warnings if 'script' in w], [])

    def test_a_script_with_a_new_name_is_an_add_and_gets_no_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = self._file(tmp, 'other.sh', 5)
            raw = machine_json(users=[], scripts=[{'file': script, 'script_command': 'bash'}])
            plan = self.build(raw, st=self._script_state('run.sh', command='sh'))
        self.assertEqual([c.path for c in plan.results[0].changes], ['script "other.sh"'])
        self.assertEqual([w for w in plan.results[0].warnings if 'differs' in w], [])

    def test_no_files_no_noise(self):
        plan = self.build()
        self.assertEqual([w for w in plan.warnings if 'attachment' in w], [])


if __name__ == '__main__':
    unittest.main()
