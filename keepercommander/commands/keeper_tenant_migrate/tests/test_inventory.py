import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.inventory import (
    InventoryAssembler,
    _custom_fields_by_label,
    _field_first_value,
    _keeps,
    compute_counts,
    load_hsf_map,
    parse_nodes_csv,
    parse_record_file,
    parse_roles_dir,
    parse_shared_folders_json,
    parse_teams_csv,
    parse_users_csv,
    summarize_record,
)


class KeepsTests(unittest.TestCase):
    def test_no_prefix_keeps_everything(self):
        keep = _keeps('')
        self.assertTrue(keep('anything'))
        self.assertTrue(keep(''))

    def test_prefix_filters_by_startswith(self):
        keep = _keeps('MIGTEST-')
        self.assertTrue(keep('MIGTEST-Foo'))
        self.assertFalse(keep('Foo-MIGTEST'))
        self.assertFalse(keep(None))


class ParseNodesCsvTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        self.tmp.write('id,name,parent_node,isolated,user_count,team_count,role_count\n')
        self.tmp.write('101,"MIGTEST-Root","My company",false,5,2,1\n')
        self.tmp.write('102,"OtherNode","My company",true,0,0,0\n')
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_prefix_filters_nodes(self):
        out = parse_nodes_csv(self.tmp.name, _keeps('MIGTEST-'))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['name'], 'MIGTEST-Root')
        self.assertFalse(out[0]['isolated'])
        self.assertEqual(out[0]['user_count'], 5)

    def test_no_prefix_keeps_all_except_header(self):
        out = parse_nodes_csv(self.tmp.name, _keeps(''))
        self.assertEqual(len(out), 2)
        names = [n['name'] for n in out]
        self.assertIn('MIGTEST-Root', names)
        self.assertIn('OtherNode', names)


class ParseTeamsCsvTests(unittest.TestCase):
    def test_parses_teams_with_restrictions(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as t:
            t.write('uid1,"MIGTEST-Team-A","R W S","MIGTEST-Root",3,1\n')
            path = t.name
        try:
            out = parse_teams_csv(path, _keeps('MIGTEST-'))
        finally:
            os.unlink(path)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['restricts'], 'R W S')
        self.assertEqual(out[0]['user_count'], 3)


class ParseUsersCsvTests(unittest.TestCase):
    def test_splits_newline_separated_teams_and_aliases(self):
        hsf = {'alice@example.com': {'TeamA'}}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as t:
            t.write('"u1","alice@example.com","active","","MIGTEST-Root",2,"TeamA\nTeamB",1,"MIGTEST-Role","alt@example.com\nalice@example.com",true,"Engineer"\n')
            path = t.name
        try:
            out = parse_users_csv(path, 'MIGTEST-', hsf)
        finally:
            os.unlink(path)
        self.assertEqual(len(out), 1)
        u = out[0]
        self.assertEqual(u['teams'], ['TeamA', 'TeamB'])
        self.assertEqual(u['aliases'], ['alt@example.com'])  # self-alias removed
        self.assertTrue(u['2fa_enabled'])
        self.assertEqual(u['hide_shared_folders_teams'], ['TeamA'])


class ParseRolesDirTests(unittest.TestCase):
    def test_loads_role_json_files(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, 'role1.json'), 'w') as f:
                json.dump({
                    'id': 42,
                    'name': 'MIGTEST-Admin',
                    'node': 'MIGTEST-Root',
                    'default_role': False,
                    'managed_nodes': [{'privileges': ['a', 'b']}],
                    'enforcements': {'two_factor_required': True},
                    'users': ['u@x'],
                    'teams': [],
                }, f)
            out = parse_roles_dir(d, _keeps('MIGTEST-'))
        finally:
            import shutil
            shutil.rmtree(d)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]['name'], 'MIGTEST-Admin')
        self.assertEqual(out[0]['enforcements'], {'two_factor_required': True})


class LoadHsfMapTests(unittest.TestCase):
    def test_aggregates_team_names_per_user(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as t:
            t.write('Team1|alice@x.com\nTeam2|alice@x.com\nTeam1|bob@x.com\n')
            path = t.name
        try:
            m = load_hsf_map(path)
        finally:
            os.unlink(path)
        self.assertEqual(m['alice@x.com'], {'Team1', 'Team2'})
        self.assertEqual(m['bob@x.com'], {'Team1'})


class ParseSharedFoldersTests(unittest.TestCase):
    def test_picks_default_permission_fields(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as t:
            json.dump([
                {'shared_folder_uid': 'sf1', 'name': 'MIGTEST-SF',
                 'default_can_edit': True, 'default_can_share': False,
                 'users': [], 'teams': [], 'records': []},
                {'shared_folder_uid': 'sf2', 'name': 'Other', 'users': [], 'teams': [], 'records': []},
            ], t)
            path = t.name
        try:
            out = parse_shared_folders_json(path, _keeps('MIGTEST-'))
        finally:
            os.unlink(path)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]['default_can_edit'])


class SummarizeRecordTests(unittest.TestCase):
    def test_counts_attachments_and_excludes_owner_from_shares(self):
        rec = {
            'record_uid': 'r1',
            'title': 'MIGTEST-Rec',
            'type': 'login',
            'fields': [
                {'type': 'fileRef', 'value': ['f1', 'f2']},
                {'type': 'oneTimeCode', 'value': ['otpauth://totp/x?secret=abc']},
            ],
            'custom': [{'type': 'text', 'label': 'x', 'value': ['y']}],
            'user_permissions': [
                {'username': 'owner@x', 'owner': True},
                {'username': 'alice@x', 'owner': False, 'editable': True, 'shareable': False},
            ],
        }
        summary = summarize_record(rec)
        self.assertEqual(summary['attachment_count'], 2)
        self.assertEqual(summary['custom_field_count'], 1)
        self.assertTrue(summary['has_totp'])
        self.assertEqual(len(summary['direct_shares']), 1)
        self.assertEqual(summary['direct_shares'][0]['username'], 'alice@x')

    def test_handles_missing_lists(self):
        summary = summarize_record({'record_uid': 'r2', 'title': 'T'})
        self.assertEqual(summary['attachment_count'], 0)
        self.assertEqual(summary['direct_shares'], [])


class FieldFirstValueTests(unittest.TestCase):
    def test_returns_first_value_of_typed_field(self):
        fields = [{'type': 'login', 'value': ['alice@x']}]
        self.assertEqual(_field_first_value(fields, 'login'), 'alice@x')

    def test_returns_empty_for_missing_type(self):
        self.assertEqual(_field_first_value([], 'login'), '')


class CustomFieldsByLabelTests(unittest.TestCase):
    def test_builds_label_to_value_map(self):
        cf = [{'type': 'text', 'label': 'Env', 'value': ['prod']},
              {'type': 'text', 'label': 'Region', 'value': ['eu']}]
        self.assertEqual(_custom_fields_by_label(cf),
                         {'Env': 'prod', 'Region': 'eu'})

    def test_skips_empty_values(self):
        cf = [{'type': 'text', 'label': 'Empty', 'value': ['']},
              {'type': 'text', 'label': 'Real', 'value': ['x']}]
        self.assertEqual(_custom_fields_by_label(cf), {'Real': 'x'})

    def test_duplicate_label_suffixed(self):
        cf = [{'type': 'text', 'label': 'K', 'value': ['a']},
              {'type': 'text', 'label': 'K', 'value': ['b']}]
        out = _custom_fields_by_label(cf)
        self.assertEqual(out['K'], 'a')
        self.assertEqual(out['K#2'], 'b')


class SummarizeRecordFieldLevelTests(unittest.TestCase):
    def test_include_fields_captures_login_password_url_notes(self):
        rec = {
            'record_uid': 'r',
            'title': 'T',
            'type': 'login',
            'fields': [
                {'type': 'login', 'value': ['alice@x']},
                {'type': 'password', 'value': ['secret']},
                {'type': 'url', 'value': ['https://example.com']},
                {'type': 'oneTimeCode', 'value': ['otpauth://totp/X?secret=ABC']},
            ],
            'notes': 'some notes',
            'custom': [{'type': 'text', 'label': 'Env', 'value': ['prod']}],
            'user_permissions': [],
        }
        summary = summarize_record(rec, include_fields=True)
        self.assertEqual(summary['login'], 'alice@x')
        self.assertEqual(summary['password'], 'secret')
        self.assertEqual(summary['login_url'], 'https://example.com')
        self.assertEqual(summary['notes'], 'some notes')
        self.assertEqual(summary['totp_secret'], 'otpauth://totp/X?secret=ABC')
        self.assertEqual(summary['custom_fields'], {'Env': 'prod'})

    def test_default_excludes_field_data(self):
        rec = {
            'record_uid': 'r', 'title': 'T', 'type': 'login',
            'fields': [{'type': 'login', 'value': ['alice@x']},
                       {'type': 'password', 'value': ['secret']}],
            'custom': [], 'user_permissions': [],
        }
        summary = summarize_record(rec)
        self.assertNotIn('login', summary)
        self.assertNotIn('password', summary)


class ParseRecordFileTests(unittest.TestCase):
    def test_extracts_record_from_mixed_output(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as t:
            t.write('Some log preamble\n')
            t.write(json.dumps({'title': 'X', 'record_uid': 'u'}, indent=2))
            t.write('\n')
            path = t.name
        try:
            rec = parse_record_file(path)
        finally:
            os.unlink(path)
        self.assertEqual(rec['title'], 'X')


class ComputeCountsTests(unittest.TestCase):
    def test_aggregates_nested_counts(self):
        entities = {
            'nodes': [1, 2],
            'teams': [1],
            'roles': [
                {'enforcements': {'a': 1, 'b': 2},
                 'managed_nodes': [{'privileges': ['p1']}, {'privileges': ['p2', 'p3']}]},
            ],
            'users': [],
            'shared_folders': [{}],
            'records': [
                {'attachment_count': 2, 'direct_shares': [{}, {}]},
                {'attachment_count': 0, 'direct_shares': []},
            ],
        }
        counts = compute_counts(entities)
        self.assertEqual(counts['total_enforcements'], 2)
        self.assertEqual(counts['total_privileges'], 3)
        self.assertEqual(counts['attachments'], 2)
        self.assertEqual(counts['direct_shares'], 2)


class InventoryAssemblerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # minimal nodes.csv
        with open(os.path.join(self.tmp, 'nodes.csv'), 'w') as f:
            f.write('101,"MIGTEST-Root","My company",false,1,0,0\n')
        # teams.csv
        with open(os.path.join(self.tmp, 'teams.csv'), 'w') as f:
            f.write('t1,"MIGTEST-Team","","MIGTEST-Root",1,0\n')
        # users.csv — 12 columns
        with open(os.path.join(self.tmp, 'users.csv'), 'w') as f:
            f.write('u1,alice@x,active,,MIGTEST-Root,1,MIGTEST-Team,0,,,true,Eng\n')
        # shared_folders.json
        with open(os.path.join(self.tmp, 'shared_folders.json'), 'w') as f:
            json.dump([{'shared_folder_uid': 'sf1', 'name': 'MIGTEST-SF',
                        'users': [], 'teams': [], 'records': []}], f)
        # roles dir
        os.makedirs(os.path.join(self.tmp, 'roles'))
        with open(os.path.join(self.tmp, 'roles', 'r1.json'), 'w') as f:
            json.dump({'id': 1, 'name': 'MIGTEST-Role', 'node': 'MIGTEST-Root',
                       'enforcements': {}, 'managed_nodes': [], 'users': [], 'teams': []}, f)
        # records dir
        os.makedirs(os.path.join(self.tmp, 'records'))
        with open(os.path.join(self.tmp, 'records', 'rec1.json'), 'w') as f:
            f.write(json.dumps({'record_uid': 'rec1', 'title': 'MIGTEST-Rec', 'type': 'login',
                                'fields': [], 'custom': [], 'user_permissions': []}, indent=2))
        # hsf map
        with open(os.path.join(self.tmp, 'user_hsf_teams.txt'), 'w') as f:
            f.write('MIGTEST-Team|alice@x\n')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_build_produces_expected_counts(self):
        asm = InventoryAssembler(self.tmp, prefix='MIGTEST-', scope_node='MIGTEST-Root',
                                 source_user='admin@x', source_root='My company')
        inv = asm.build()
        self.assertEqual(inv['counts']['nodes'], 1)
        self.assertEqual(inv['counts']['teams'], 1)
        self.assertEqual(inv['counts']['users'], 1)
        self.assertEqual(inv['counts']['shared_folders'], 1)
        self.assertEqual(inv['counts']['roles'], 1)
        self.assertEqual(inv['counts']['records'], 1)
        self.assertEqual(inv['scope_node'], 'MIGTEST-Root')
        self.assertEqual(inv['source_root'], 'My company')
        # hsf propagated
        self.assertEqual(inv['entities']['users'][0]['hide_shared_folders_teams'], ['MIGTEST-Team'])

    def test_write_emits_sha256_sidecar(self):
        asm = InventoryAssembler(self.tmp, prefix='MIGTEST-')
        out = os.path.join(self.tmp, 'inventory.json')
        _, checksum = asm.write(out)
        self.assertTrue(os.path.exists(out + '.sha256'))
        with open(out + '.sha256') as f:
            sidecar = f.read().strip()
        self.assertEqual(sidecar, checksum)
        self.assertEqual(len(checksum), 64)


if __name__ == '__main__':
    unittest.main()
