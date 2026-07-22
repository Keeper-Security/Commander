#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# unit tests for NSF ACL share cache warmer
#

from unittest import TestCase, mock

from keepercommander.nested_share_folder import acl_cache
from keepercommander.params import KeeperParams


class TestNsfAclCache(TestCase):
    def setUp(self):
        self.params = KeeperParams()
        self.params.user = 'me@example.com'
        self.params.record_cache = {
            'R1': {'record_uid': 'R1'},
            'R2': {'record_uid': 'R2'},
        }

    def test_warm_nsf_folder_share_cache_batches_and_stores(self):
        fake_results = {
            'results': [
                {
                    'folder_uid': 'F1',
                    'success': True,
                    'accessors': [
                        {'accessor_uid': 'U1', 'username': 'a@x.com',
                         'access_type': 'AT_USER', 'role': 'VIEWER'},
                    ],
                },
                {
                    'folder_uid': 'F2',
                    'success': True,
                    'accessors': [],
                },
            ]
        }
        with mock.patch(
                'keepercommander.nested_share_folder.folder_api.get_folder_access_v3',
                return_value=fake_results) as m:
            acl_cache.warm_nsf_folder_share_cache(self.params, ['F1', 'F2', 'F1'])
            m.assert_called_once()
            args = m.call_args[0]
            self.assertEqual(set(args[1]), {'F1', 'F2'})

        self.assertEqual(
            self.params.nested_share_folder_share_cache['F1'][0]['username'],
            'a@x.com')
        self.assertEqual(self.params.nested_share_folder_share_cache['F2'], [])

        # Second warm is a no-op (already cached)
        with mock.patch(
                'keepercommander.nested_share_folder.folder_api.get_folder_access_v3') as m2:
            acl_cache.warm_nsf_folder_share_cache(self.params, ['F1', 'F2'])
            m2.assert_not_called()

    def test_warm_nsf_folder_share_cache_does_not_poison_on_failure(self):
        with mock.patch(
                'keepercommander.nested_share_folder.folder_api.get_folder_access_v3',
                side_effect=RuntimeError('boom')):
            acl_cache.warm_nsf_folder_share_cache(self.params, ['F1'])
        self.assertNotIn('F1', self.params.nested_share_folder_share_cache)

    def test_warm_nsf_folder_share_cache_paginates(self):
        pages = [
            {
                'results': [{'folder_uid': 'F1', 'success': True,
                             'accessors': [{'username': 'a@x.com'}]}],
                'has_more': True,
                'continuation_token': 111,
            },
            {
                'results': [{'folder_uid': 'F1', 'success': True,
                             'accessors': [{'username': 'b@x.com'}]}],
                'has_more': False,
            },
        ]
        with mock.patch(
                'keepercommander.nested_share_folder.folder_api.get_folder_access_v3',
                side_effect=pages) as m:
            acl_cache.warm_nsf_folder_share_cache(self.params, ['F1'])
            self.assertEqual(m.call_count, 2)
            self.assertEqual(m.call_args_list[1].kwargs.get('continuation_token'), 111)
        names = [a['username'] for a in self.params.nested_share_folder_share_cache['F1']]
        self.assertEqual(names, ['a@x.com', 'b@x.com'])

    def test_warm_nsf_record_share_cache_groups_by_record(self):
        fake = {
            'record_accesses': [
                {'record_uid': 'NR1', 'accessor_name': 'a@x.com', 'owner': False,
                 'access_type': 'AT_USER', 'access_role_type': 2},
                {'record_uid': 'NR1', 'accessor_name': 'me@example.com', 'owner': True,
                 'access_type': 'AT_USER', 'access_role_type': 6},
                {'record_uid': 'NR2', 'accessor_name': 'b@x.com', 'owner': False,
                 'access_type': 'AT_USER', 'access_role_type': 2},
            ],
            'forbidden_records': [],
        }
        with mock.patch(
                'keepercommander.nested_share_folder.record_api.get_record_accesses_v3',
                return_value=fake):
            acl_cache.warm_nsf_record_share_cache(self.params, ['NR1', 'NR2'])

        self.assertEqual(len(self.params.nested_share_record_share_cache['NR1']), 2)
        self.assertEqual(len(self.params.nested_share_record_share_cache['NR2']), 1)

    def test_warm_nsf_record_share_cache_does_not_poison_on_failure(self):
        with mock.patch(
                'keepercommander.nested_share_folder.record_api.get_record_accesses_v3',
                side_effect=RuntimeError('boom')):
            acl_cache.warm_nsf_record_share_cache(self.params, ['NR1'])
        self.assertNotIn('NR1', self.params.nested_share_record_share_cache)

    def test_warm_nsf_record_share_cache_stops_on_throttle(self):
        calls = []

        def boom(params, uids):
            calls.append(list(uids))
            raise RuntimeError('throttled: try again in 1 minute')

        with mock.patch(
                'keepercommander.nested_share_folder.record_api.get_record_accesses_v3',
                side_effect=boom):
            acl_cache.warm_nsf_record_share_cache(
                self.params, ['A1', 'A2', 'A3', 'A4', 'A5', 'A6', 'A7', 'A8', 'A9', 'A10', 'B1'])
        # First chunk fails with throttle → abort; do not keep calling for later chunks.
        self.assertEqual(len(calls), 1)
        self.assertNotIn('B1', self.params.nested_share_record_share_cache)

    def test_warm_classic_record_shares_delegates(self):
        with mock.patch('keepercommander.api.get_record_shares') as m:
            acl_cache.warm_classic_record_shares(self.params, ['R1', 'missing', 'R1'])
            m.assert_called_once()
            self.assertEqual(m.call_args[0][1], ['R1'])

    def test_clear_share_caches(self):
        acl_cache.ensure_share_caches(self.params)
        self.params.nested_share_folder_share_cache['F1'] = [{'x': 1}]
        self.params.nested_share_record_share_cache['R1'] = [{'y': 1}]
        acl_cache.clear_share_caches(self.params)
        self.assertEqual(self.params.nested_share_folder_share_cache, {})
        self.assertEqual(self.params.nested_share_record_share_cache, {})


class TestTreeShareFormatting(TestCase):
    def setUp(self):
        self.params = KeeperParams()
        self.params.user = 'me@example.com'
        self.params.nested_share_folders = {
            'F1': {'name': 'NSF One', 'owner_username': 'owner@x.com', 'parent_uid': None},
        }
        self.params.nested_share_folder_share_cache = {
            'F1': [
                {'access_type': 'AT_OWNER', 'username': 'owner@x.com', 'role': 'MANAGER'},
                {'access_type': 'AT_USER', 'username': 'bob@x.com', 'role': 'VIEWER'},
                {'access_type': 'AT_TEAM', 'accessor_uid': 'T1', 'role': 'SHARED_MANAGER'},
            ]
        }
        self.params.enterprise = {
            'teams': [{'team_uid': 'T1', 'name': 'Eng'}],
        }
        self.params.record_cache = {
            'R1': {
                'shares': {
                    'user_permissions': [
                        {'username': 'me@example.com', 'owner': True},
                        {'username': 'alice@x.com', 'editable': True, 'shareable': False},
                    ],
                    'shared_folder_permissions': [
                        {'shared_folder_uid': 'SF1', 'editable': False, 'reshareable': False},
                    ],
                }
            }
        }
        self.params.shared_folder_cache = {
            'SF1': {'shared_folder_uid': 'SF1', 'name': 'Team SF'},
        }
        self.params.nested_share_record_share_cache = {
            'NR1': [
                {'owner': True, 'accessor_name': 'owner@x.com', 'access_type': 'AT_USER',
                 'access_role_type': 6},
                {'owner': False, 'accessor_name': 'carol@x.com', 'access_type': 'AT_USER',
                 'access_role_type': 2},
            ]
        }

    def test_format_nsf_folder_share_info(self):
        from keepercommander.commands.folder import _nsf_folder_share_data
        data, text = _nsf_folder_share_data(self.params, 'F1')
        self.assertNotIn('owner:', text)
        self.assertIn('users:[owner@x.com:OW],[bob@x.com:VW]', text)
        self.assertIn('teams:[Eng:SM]', text)
        self.assertEqual(data['users'][0], {'email': 'owner@x.com', 'permissions': ['OW']})
        self.assertEqual(data['users'][1]['permissions'], ['VW'])
        self.assertNotIn('uid', data['teams'][0])
        data_v, _ = _nsf_folder_share_data(self.params, 'F1', include_uids=True)
        self.assertEqual(data_v['teams'][0].get('uid'), 'T1')

    def test_nsf_apps_not_listed_as_user_uids(self):
        from keepercommander.commands.folder import _nsf_folder_share_data
        self.params.nested_share_folder_share_cache['F1'].append({
            'access_type': 'AT_APPLICATION',
            'accessor_uid': 'fdHf2YtMAOKsWjJATodEGw',
            'role': 'CONTENT_MANAGER',
        })
        self.params.nested_share_folder_share_cache['F1'].append({
            'access_type': 'AT_USER',
            'accessor_uid': 'MK8op0lCPLtJyP4W2-dD1A',
            'username': None,
            'role': 'VIEWER',
        })
        data, text = _nsf_folder_share_data(self.params, 'F1')
        self.assertNotIn('fdHf2YtMAOKsWjJATodEGw', text)
        emails = [u.get('email') for u in data.get('users', [])]
        self.assertNotIn('MK8op0lCPLtJyP4W2-dD1A', emails)
        self.assertTrue(any(a.get('permissions') == ['CM'] for a in data.get('applications', [])))

    def test_tree_json_compact_share_entries(self):
        from keepercommander.commands.folder import _tree_json_dumps
        payload = {
            'share_permissions': {
                'users': [{'email': 'a@x.com', 'permissions': ['OW']}],
                'teams': [{'name': 'Eng', 'permissions': ['VW']}],
            }
        }
        text = _tree_json_dumps(payload)
        self.assertIn('{ "email": "a@x.com", "permissions": ["OW"] }', text)
        self.assertIn('{ "name": "Eng", "permissions": ["VW"] }', text)
        self.assertNotIn('"permissions": [\n', text)

    def test_format_classic_folder_share_ro_alignment(self):
        from keepercommander.commands.folder import _classic_folder_share_data
        sf = {
            'shared_folder_uid': 'SF1', 'name': 'Team SF',
            'users': [], 'teams': [],
            'default_manage_records': False, 'default_manage_users': False,
            'default_can_edit': False, 'default_can_share': False,
        }
        data, text = _classic_folder_share_data(self.params, sf)
        self.assertIn('default:RO', text)
        self.assertEqual(data['user_permissions'], [])
        self.assertEqual(data['record_permissions'], ['RO'])

    def test_format_classic_record_share_info(self):
        from keepercommander.commands.folder import _classic_record_share_data
        data, text = _classic_record_share_data(self.params, 'R1')
        self.assertIn('me@example.com:OW', text)
        self.assertIn('alice@x.com:CE', text)
        self.assertNotIn('folders:', text)
        self.assertNotIn('folders', data)
        self.assertEqual(data['users'][0]['permissions'], ['OW'])

    def test_format_nsf_record_share_info(self):
        from keepercommander.commands.folder import _nsf_record_share_data
        data, text = _nsf_record_share_data(self.params, 'NR1')
        self.assertIn('owner@x.com:OW', text)
        self.assertIn('carol@x.com:VW', text)
        self.assertEqual(data['users'][0]['email'], 'owner@x.com')
        self.assertEqual(data['users'][0]['permissions'], ['OW'])
        self.assertEqual(data['users'][1]['email'], 'carol@x.com')

    def test_nsf_record_prefers_direct_over_inherited(self):
        from keepercommander.commands.folder import _nsf_record_share_data
        self.params.nested_share_record_share_cache['NR1'] = [
            {'owner': True, 'accessor_name': 'owner@x.com', 'access_type': 'AT_USER',
             'access_role_type': 6, 'inherited': False},
            # Inherited folder role first in raw list — should lose to direct CT
            {'owner': False, 'accessor_name': 'carol@x.com', 'access_type': 'AT_USER',
             'access_role_type': 2, 'inherited': True},
            {'owner': False, 'accessor_name': 'carol@x.com', 'access_type': 'AT_USER',
             'access_role_type': 1, 'inherited': False},  # contributor
        ]
        data, text = _nsf_record_share_data(self.params, 'NR1')
        self.assertIn('carol@x.com:CT', text)
        self.assertNotIn('carol@x.com:VW', text)
        carol = [u for u in data['users'] if u.get('email') == 'carol@x.com']
        self.assertEqual(len(carol), 1)
        self.assertEqual(carol[0]['permissions'], ['CT'])

    def test_nsf_record_falls_back_to_folder_acl(self):
        from keepercommander.commands.folder import _nsf_record_share_data
        self.params.nested_share_record_share_cache = {}
        self.params.nested_share_folder_records = {'F1': {'NR_EMPTY'}}
        data, text = _nsf_record_share_data(self.params, 'NR_EMPTY')
        self.assertIn('owner@x.com:OW', text)
        self.assertIn('bob@x.com:VW', text)
        self.assertEqual(data['users'][0]['permissions'], ['OW'])

    def test_tree_json_and_ns_flag_warming(self):
        from keepercommander.commands.folder import formatted_tree
        from keepercommander.subfolder import UserFolderNode

        def walk(node):
            yield node
            for child in node.get('children') or []:
                yield from walk(child)

        root = UserFolderNode()
        root.uid = ''
        root.name = 'Root'
        root.type = '/'
        root.subfolders = []
        self.params.folder_cache = {}
        with mock.patch('keepercommander.nested_share_folder.acl_cache.warm_for_tree') as warm:
            formatted_tree(self.params, root, shares=True, nsf_shares=False)
            warm.assert_not_called()
            formatted_tree(self.params, root, shares=False, nsf_shares=True)
            warm.assert_called_once()
        with mock.patch('keepercommander.nested_share_folder.acl_cache.warm_for_tree'):
            payload = formatted_tree(self.params, root, shares=False, nsf_shares=True, fmt='json')
            payload_v = formatted_tree(
                self.params, root, shares=False, nsf_shares=True, fmt='json', verbose=True)
        self.assertIn('tree', payload)
        self.assertEqual(payload['tree']['path'], '/')
        self.assertEqual(payload['tree']['kind'], 'folder')
        nodes = list(walk(payload['tree']))
        self.assertTrue(any(i.get('kind') == 'nested_share_folder' for i in nodes))
        for item in nodes:
            self.assertIn('path', item)
            self.assertNotIn('source', item)
        nsf_items = [i for i in nodes if i.get('kind') == 'nested_share_folder']
        if nsf_items:
            self.assertNotIn('uid', nsf_items[0])
            self.assertTrue(nsf_items[0]['path'].startswith('/'))
            # Nested under root via children
            self.assertTrue(any(
                c.get('kind') == 'nested_share_folder'
                for c in (payload['tree'].get('children') or [])
            ))
        nodes_v = list(walk(payload_v['tree']))
        nsf_items_v = [i for i in nodes_v if i.get('kind') == 'nested_share_folder']
        if nsf_items_v:
            self.assertIn('uid', nsf_items_v[0])
            self.assertEqual(list(nsf_items_v[0].keys())[:3], ['name', 'path', 'uid'])
        self.assertIn('share_permissions_key', payload)
        self.assertIn('OW', payload['share_permissions_key']['nsf'])

    def test_tree_record_shares_with_s_and_ns_flags(self):
        from keepercommander.commands.folder import formatted_tree
        from keepercommander.record import Record
        from keepercommander.subfolder import NestedShareFolderNode, SharedFolderNode, UserFolderNode
        import keepercommander.nested_share_folder as nsf_mod

        def walk(node):
            yield node
            for child in node.get('children') or []:
                yield from walk(child)

        root = UserFolderNode()
        root.uid = ''
        root.name = 'Root'
        root.type = '/'
        root.subfolders = ['SF1']

        sf = SharedFolderNode()
        sf.uid = 'SF1'
        sf.name = 'Team SF'
        sf.type = 'shared_folder'
        sf.subfolders = []

        nsf_folder = NestedShareFolderNode()
        nsf_folder.uid = 'F1'
        nsf_folder.name = 'NSF One'
        nsf_folder.subfolders = []

        classic = Record()
        classic.record_uid = 'R1'
        classic.title = 'Classic Login'
        classic.record_type = 'login'

        nested = Record()
        nested.record_uid = 'NR1'
        nested.title = 'Nested Login'
        nested.record_type = 'login'

        self.params.folder_cache = {'SF1': sf, 'F1': nsf_folder}
        self.params.shared_folder_cache = {
            'SF1': {
                'shared_folder_uid': 'SF1', 'name': 'Team SF',
                'users': [{'username': 'bob@x.com', 'manage_users': False, 'manage_records': False}],
                'default_manage_records': False, 'default_manage_users': False,
                'default_can_edit': False, 'default_can_share': False,
            }
        }
        self.params.nested_share_records = {'NR1': {'record_uid': 'NR1'}}
        self.params.nested_share_folder_records = {'F1': {'NR1'}}
        self.params.subfolder_record_cache = {'SF1': {'R1'}, 'F1': set(), '': set()}

        # Drop any lazily cached warmer binding so the patch is used.
        nsf_mod.__dict__.pop('warm_for_tree', None)

        with mock.patch(
                'keepercommander.nested_share_folder.acl_cache.warm_for_tree') as warm, \
                mock.patch('keepercommander.commands.folder.api.get_record',
                           side_effect=lambda p, uid: {'R1': classic, 'NR1': nested}.get(uid)), \
                mock.patch('keepercommander.commands.folder.get_contained_record_uids',
                           side_effect=lambda p, uid, **kw: (
                               {'SF1': {'R1'}} if uid == 'SF1' else {uid or '': set()}
                           )):
            payload = formatted_tree(
                self.params, root, show_records=True, shares=True, nsf_shares=True, fmt='json')
            warm.assert_called_once()
            kwargs = warm.call_args.kwargs
            self.assertIn('R1', list(kwargs.get('classic_record_uids') or []))
            self.assertIn('NR1', list(kwargs.get('nsf_record_uids') or []))

        self.assertIn('tree', payload)
        records = [i for i in walk(payload['tree']) if i.get('kind') == 'record']
        by_name = {i['name']: i for i in records}
        self.assertIn('Classic Login', by_name)
        classic_item = by_name['Classic Login']
        self.assertEqual(classic_item.get('record_type'), 'login')
        self.assertIn('share_permissions', classic_item)
        self.assertEqual(classic_item['share_permissions']['users'][0]['permissions'], ['OW'])
        self.assertNotIn('folders', classic_item['share_permissions'])
        self.assertNotIn('children', classic_item)  # leaf: omit empty children

        nested_records = [i for i in walk(payload['tree']) if i.get('kind') == 'nested_record']
        nested_by_name = {i['name']: i for i in nested_records}
        self.assertIn('Nested Login', nested_by_name)
        nested_item = nested_by_name['Nested Login']
        self.assertIn('share_permissions', nested_item)
        self.assertEqual(nested_item['share_permissions']['users'][0]['permissions'], ['OW'])
        self.assertEqual(nested_item['share_permissions']['users'][1]['email'], 'carol@x.com')
        # Nested under NSF folder in the tree
        nsf_nodes = [i for i in walk(payload['tree']) if i.get('kind') == 'nested_share_folder']
        self.assertTrue(nsf_nodes)
        self.assertTrue(any(
            c.get('name') == 'Nested Login'
            for n in nsf_nodes for c in (n.get('children') or [])
        ))
