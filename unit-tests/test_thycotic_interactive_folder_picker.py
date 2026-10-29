import unittest
from unittest import mock
from keepercommander.importer.thycotic.thycotic import ThycoticImporter, ThycoticMixin

L1, L2, L3, L4 = 'Test_Folder_l1', r'Test_Folder_l1\Test_Folder_l2', \
    r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3', r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3\Test_Folder_l4'


def _folder(folder_id, name, parent=-1, with_path=True):
    folder = {'id': folder_id, 'folderName': name, 'parentFolderId': parent, 'inheritPermissions': True}
    if with_path:
        folder['folderPath'] = '\\' + name
    return folder


def _secret(secret_id, folder_id):
    return {'id': secret_id, 'name': f'secret-{secret_id}', 'items': [], 'folderId': folder_id, 'secretTemplateName': ''}


def _lookup(folder_id):
    return f'/v1/secrets/lookup?filter.folderId={folder_id}&filter.includeSubFolders=true&filter.includeRestricted=true'


TENANT_LOOKUP = '/v1/secrets/lookup?filter.includeRestricted=true'


class ParseChoiceTests(unittest.TestCase):
    def test_invalid_input_is_rejected(self):
        for choice, count in ((None, 5), (1, 5), (['1'], 5), (b'1', 5), ('', 5), ('   ', 5), ('A', 5),
                              ('0', 5), ('6', 5), ('99999999999', 5), ('3-1', 5), ('5-1', 5), ('1-6', 5),
                              (',', 5), ('-', 5), ('1-', 5), ('-1', 5), ('1--2', 5), ('1-2-3', 5), (' , ', 5),
                              ('1,', 5), ('1,,2', 5), ('1 2', 5), ('1.5', 5), ('+1', 5), ('1', 0), ('1', -1)):
            with self.subTest(choice=choice, count=count):
                self.assertIsNone(ThycoticMixin._parse_choice(choice, count))

    def test_valid_input_is_parsed(self):
        for choice, count, expected in (('1', 1, {1}), ('5', 5, {5}), (' 1 ', 5, {1}), ('01', 5, {1}),
                                        ('3-3', 5, {3}), ('  2 - 4 , 4  ', 4, {2, 3, 4}),
                                        ('1-3,2-4', 4, {1, 2, 3, 4}), ('2,1,1', 3, {1, 2})):
            with self.subTest(choice=choice):
                self.assertEqual(ThycoticMixin._parse_choice(choice, count), expected)


class SelectFoldersTests(unittest.TestCase):
    def setUp(self):
        self.folders = [_folder(1, 'a'), _folder(2, 'b'), _folder(3, 'c')]

    def test_blank_none_or_a_returns_all(self):
        for choice in ('', '   ', 'a', ' A ', None, 5):
            with self.subTest(choice=choice):
                self.assertIs(ThycoticMixin._select_folders(self.folders, choice), self.folders)

    def test_valid_choice_filters_in_list_order(self):
        for choice, expected in (('3,1', [0, 2]), ('2-3', [1, 2]), (' 2 , 3 ', [1, 2]), ('1-3', [0, 1, 2])):
            with self.subTest(choice=choice):
                self.assertEqual(ThycoticMixin._select_folders(self.folders, choice),
                                 [self.folders[i] for i in expected])

    def test_invalid_choice_returns_none(self):
        for folders, choice in ((self.folders, '0'), (self.folders, '4'), (self.folders, 'x'),
                                (self.folders, '1,,2'), ([], '1')):
            with self.subTest(folders=folders, choice=choice):
                self.assertIsNone(ThycoticMixin._select_folders(folders, choice))


class InteractiveFolderPickerTests(unittest.TestCase):
    def setUp(self):
        self.folders = [_folder(116, 'L3', parent=103), _folder(103, 'l2', parent=101),
                        _folder(101, 'l1'), _folder(108, 'l100', parent=101)]

    def _pick(self, folders, *inputs):
        with mock.patch('builtins.input', side_effect=inputs) as mocked_input, \
                mock.patch('builtins.print') as mocked_print:
            result = ThycoticMixin.interactive_folder_picker(folders)
        printed = [call.args[0] for call in mocked_print.call_args_list if call.args]
        return result, printed, mocked_input

    def assertPrinted(self, printed, text):
        self.assertTrue(any(text in line for line in printed), f'{text!r} not in {printed!r}')

    def test_non_list_or_empty_input_does_not_prompt(self):
        empty = []
        for folders, expected in ((None, None), ({101: self.folders[2]}, None), (tuple(self.folders), None),
                                  ('folders', None), (empty, empty)):
            with self.subTest(folders=folders), mock.patch('builtins.input') as mocked_input:
                self.assertIs(ThycoticMixin.interactive_folder_picker(folders), expected)
                mocked_input.assert_not_called()

    def test_choice_returns_folders_in_list_order(self):
        for inputs, expected in ((('',), self.folders), (('  a  ',), self.folders), (('A',), self.folders),
                                 (('1-4',), self.folders), (('4,1,2',), [self.folders[i] for i in (0, 1, 3)])):
            with self.subTest(inputs=inputs):
                self.assertEqual(self._pick(self.folders, *inputs)[0], expected)

    def test_invalid_entries_are_retried(self):
        for inputs, expected in ((('nope', '1,99', '2'), [self.folders[1]]), (('0', '5', 'a'), self.folders)):
            with self.subTest(inputs=inputs):
                result, printed, mocked_input = self._pick(self.folders, *inputs)
                self.assertEqual(result, expected)
                self.assertEqual(mocked_input.call_count, 3)
                self.assertEqual(len([line for line in printed if line.startswith('Invalid choice')]), 2)

    def test_interrupt_cancels_and_eof_imports_all(self):
        for inputs in ([KeyboardInterrupt], ['bad', KeyboardInterrupt]):
            with self.subTest(inputs=inputs), self.assertRaisesRegex(Exception, '^Import canceled$'):
                self._pick(self.folders, *inputs)
        self.assertIs(self._pick(self.folders, EOFError)[0], self.folders)

    def test_path_falls_back_to_name(self):
        for folder in ({'folderName': 'Bare'}, {'folderName': 'Bare', 'folderPath': None},
                       {'folderName': 'Bare', 'folderPath': ''}, _folder(116, 'Bare', parent=999, with_path=False)):
            with self.subTest(folder=folder):
                self.assertPrinted(self._pick([folder], '1')[1], '[1] Bare - Path -> Bare')

    def test_path_is_built_from_parents(self):
        raw = [_folder(101, 'Test_Folder_l1', with_path=False), _folder(103, 'Test_Folder_l2', parent=101, with_path=False),
               _folder(116, 'Test_Folder_L3', parent=103, with_path=False)]
        constructed = list(ThycoticMixin._construct_folders([dict(f) for f in raw]).values())
        for folders in (raw, constructed):
            with self.subTest(constructed=folders is constructed):
                self.assertPrinted(self._pick(folders, '1')[1],
                                   '[3] Test_Folder_L3 - Path -> Test_Folder_l1 / Test_Folder_l2 / Test_Folder_L3')
        self.assertIn('folderPath', raw[2])

    def test_cycles_and_self_parent_do_not_hang(self):
        _, printed, _ = self._pick([_folder(10, 'Self', parent=10, with_path=False),
                                    _folder(20, 'A', parent=21, with_path=False),
                                    _folder(21, 'B', parent=20, with_path=False)], '1')
        self.assertPrinted(printed, '[1] Self - Path -> Self')
        self.assertPrinted(printed, '[2] A - Path -> B / A')

    def test_malformed_and_duplicate_entries_are_still_listed(self):
        folders = [None, 'junk', {'id': 5}, {'id': 6, 'folderName': None}, _folder(7, 'Dup'), _folder(7, 'Dup2')]
        result, printed, _ = self._pick(folders, '1,4,6')
        self.assertEqual(result, [None, folders[3], folders[5]])
        for i in (1, 2, 3, 4):
            self.assertPrinted(printed, f'[{i}]  - Path -> ')
        self.assertPrinted(printed, '[6] Dup2 - Path -> Dup2')


class ExpandFolderIdsTests(unittest.TestCase):
    TREE = [_folder(101, 'l1'), _folder(103, 'l2', parent=101), _folder(108, 'l100', parent=101),
            _folder(116, 'L3', parent=103), _folder(117, 'l4', parent=116)]

    def test_expands_descendants(self):
        tree_dict = {f['id']: f for f in self.TREE}
        for folders, roots, expected in (
                (self.TREE, [103], {103, 116, 117}),                      # descendants, not siblings
                (tree_dict, [116], {116, 117}),                           # dict input
                (self.TREE, [117], {117}),                                # leaf
                (self.TREE, [999], {999}),                                # unknown root
                (self.TREE, [101, 101, 116], {101, 103, 108, 116, 117}),  # duplicate root and nested root
                (self.TREE, [None, 103], {103, 116, 117}),                # None root ignored
                (self.TREE, [None], set()),
                (self.TREE, ['101'], {'101'}),                            # string ids are not converted
                ({200: _folder(200, 'Mine', parent=1), 201: _folder(201, 'Sub', parent=200)}, [1], {1, 200, 201}),
                ([_folder(10, 'A', parent=10)], [10], {10}),              # self-parent
                ([_folder(10, 'A', parent=11), _folder(11, 'B', parent=10)], [10], {10, 11}),  # cycle
                ([_folder(101, 'l1'), _folder(103, 'l2', parent='101')], [101], {101}),        # string parent id
                ([None, 'junk', {'parentFolderId': 101}, {'id': None, 'parentFolderId': 101}] + self.TREE[:2],
                 [101], {101, 103}),                                      # malformed entries
        ):
            with self.subTest(roots=roots, folders=folders):
                self.assertEqual(ThycoticMixin.expand_folder_ids(folders, roots), expected)

    def test_empty_and_none_inputs_return_empty_set(self):
        for folders, roots in ((self.TREE, []), (self.TREE, None), ([], [101]), ({}, [101]), (None, [101]), (None, None)):
            with self.subTest(folders=folders, roots=roots):
                self.assertEqual(ThycoticMixin.expand_folder_ids(folders, roots), set())


class ConstructFoldersTests(unittest.TestCase):
    def test_non_list_and_empty_inputs_return_empty_dict(self):
        for folder_rs in (None, {}, {'error': 'bad'}, 'text', 5, [], (_folder(1, 'a'),)):
            with self.subTest(folder_rs=folder_rs):
                self.assertEqual(ThycoticMixin._construct_folders(folder_rs), {})

    def test_entries_are_normalised(self):
        folders = ThycoticMixin._construct_folders([
            None, 'junk', {'folderName': 'NoId'}, {'id': None, 'folderName': 'NullId'},  # skipped
            {'id': 5}, {'id': 6, 'folderName': None},                                     # defaults
            _folder(7, 'First'), _folder(7, 'Second'),                                    # duplicate keeps first
            dict(_folder(8, 'Shared'), inheritPermissions=False, extra='dropped'),
        ])
        self.assertEqual(set(folders), {5, 6, 7, 8})
        self.assertEqual(folders[5], {'id': 5, 'folderName': '', 'inheritPermissions': True,
                                      'parentFolderId': None, 'folderPath': ''})
        self.assertEqual(folders[6]['folderName'], '')
        self.assertEqual(folders[7]['folderName'], 'First')
        self.assertIs(folders[8]['inheritPermissions'], False)
        self.assertNotIn('extra', folders[8])

    def test_folder_paths(self):
        for raw, folder_id, expected in (
                ([_folder(101, 'l1'), _folder(103, 'l2', parent=101)], 103, 'l1\\l2'),
                ([_folder(1, 'Personal Folders'), _folder(200, 'Mine', parent=1)], 200, 'Mine'),
                ([_folder(10, 'Self', parent=10)], 10, 'Self'),
                ([_folder(20, 'A', parent=21), _folder(21, 'B', parent=20)], 20, 'B\\A'),
                ([_folder(20, 'A', parent=21), _folder(21, 'B', parent=20)], 21, 'A\\B'),
        ) + tuple(([_folder(101, 'l1'), _folder(103, 'l2', parent=p)], 103, 'l2') for p in (None, -1, 0, 1, 999, '101')):
            with self.subTest(raw=raw, folder_id=folder_id):
                self.assertEqual(ThycoticMixin._construct_folders(raw)[folder_id]['folderPath'], expected)


class GetFoldersTests(unittest.TestCase):
    def setUp(self):
        self.auth = mock.Mock()
        self.auth.thycotic_search.return_value = [
            _folder(101, 'Test_Folder_l1'), _folder(103, 'Test_Folder_l2', parent=101),
            _folder(116, 'Test_Folder_L3', parent=103), _folder(117, 'Test_Folder_l4', parent=116),
            _folder(108, 'Test_Folder_l100', parent=101), _folder(1, 'Personal Folders'),
        ]

    def test_load_folders_keeps_personal_and_get_folders_drops_it(self):
        for loader, expected in ((ThycoticMixin._load_folders, {1, 101, 103, 116, 117, 108}),
                                 (lambda auth: ThycoticMixin.get_folders(auth, skip_permissions=True),
                                  {101, 103, 116, 117, 108})):
            with self.subTest(expected=expected), mock.patch('builtins.input') as mocked_input:
                self.auth.thycotic_search.reset_mock()
                folders = loader(self.auth)
                mocked_input.assert_not_called()
                self.auth.thycotic_search.assert_called_once_with('/v1/folders')
                self.assertEqual(set(folders), expected)
                self.assertEqual(folders[117]['folderPath'], L4)

    def test_paths_are_built_when_source_omits_them(self):
        self.auth.thycotic_search.return_value = [
            _folder(101, 'Test_Folder_l1', with_path=False), _folder(103, 'Test_Folder_l2', parent=101, with_path=False),
            _folder(116, 'Test_Folder_L3', parent=103, with_path=False), _folder(1, 'Personal Folders', with_path=False)]
        self.assertEqual(ThycoticMixin.get_folders(self.auth, skip_permissions=True)[116]['folderPath'], L3)

    def test_odd_responses(self):
        for response, loaded, public in (
                (None, set(), set()), ([], set(), set()), ({'error': 'bad'}, set(), set()), ('text', set(), set()),
                ([_folder(1, 'Personal Folders')], {1}, set()),
                ([None, 'junk', {'folderName': 'NoId'}, _folder(1, 'P'), _folder(1, 'Dup')], {1}, set()),
                ([_folder(1, 'P'), _folder(200, 'Mine', parent=1)], {1, 200}, {200}),
        ):
            with self.subTest(response=response):
                self.auth.thycotic_search.return_value = response
                self.assertEqual(set(ThycoticMixin._load_folders(self.auth)), loaded)
                self.assertEqual(set(ThycoticMixin.get_folders(self.auth, skip_permissions=True)), public)

    def test_search_error_propagates(self):
        self.auth.thycotic_search.side_effect = RuntimeError('boom')
        for loader in (ThycoticMixin._load_folders, lambda auth: ThycoticMixin.get_folders(auth, skip_permissions=True)):
            with self.subTest(loader=loader), self.assertRaisesRegex(RuntimeError, 'boom'):
                loader(self.auth)


class ImportFolderSelectionTests(unittest.TestCase):
    def setUp(self):
        # Menu order matters: choice '3' must be Test_Folder_L3 (116), '6' is Personal Folders (1)
        self.raw_folders = [
            _folder(101, 'Test_Folder_l1'), _folder(103, 'Test_Folder_l2', parent=101),
            _folder(116, 'Test_Folder_L3', parent=103), _folder(117, 'Test_Folder_l4', parent=116),
            _folder(108, 'Test_Folder_l100', parent=101), _folder(1, 'Personal Folders'),
        ]

    def _import(self, choice, secrets, raw_folders=None, filter_folder=None, input_error=None, interactive=True,
                lookup=None):
        raw_folders = self.raw_folders if raw_folders is None else raw_folders
        secrets_by_id = {secret['id']: secret for secret in secrets}

        def search(endpoint):
            if endpoint == '/v1/folders':
                return raw_folders
            return [{'id': secret['id']} for secret in secrets] if lookup is None else lookup

        def entity(endpoint):
            return secrets_by_id[int(endpoint.rstrip('/').rsplit('/', 1)[-1])]

        def secret(endpoint):
            secret_data = entity(endpoint)
            return (secret_data, None) if secret_data else (None, ('N/A', 'Not found'))

        input_patch = mock.patch('builtins.input', side_effect=input_error,
                                 return_value=None if input_error is not None else choice)
        with mock.patch('keepercommander.importer.thycotic.thycotic.ThycoticAuth') as auth_cls, \
                mock.patch('keepercommander.importer.thycotic.thycotic.getpass.getpass', return_value='pw'), \
                mock.patch('keepercommander.importer.thycotic.thycotic.os.path.isfile', return_value=False), \
                mock.patch('keepercommander.importer.thycotic.thycotic.sys.stdin') as mocked_stdin, \
                input_patch as mocked_input, mock.patch('builtins.print'):
            mocked_stdin.isatty.return_value = interactive
            auth = auth_cls.return_value
            auth.thycotic_search.side_effect = search
            auth.thycotic_entity.side_effect = entity
            auth.thycotic_secret.side_effect = secret
            kwargs = {} if filter_folder is None else {'filter_folder': filter_folder}
            try:
                records = list(ThycoticImporter().do_import('user@thycotic.example', **kwargs))
            finally:
                self.last_endpoints = [call.args[0] for call in auth.thycotic_search.call_args_list]
        return records, mocked_input

    @staticmethod
    def _paths(records):
        return {record.title: record.folders[0].path if record.folders else None for record in records}

    def test_picked_folders(self):
        personal = self.raw_folders + [_folder(200, 'My_Stuff', parent=1)]
        for choice, secrets, raw, endpoints, paths in (
                ('3', [_secret(501, 117), _secret(502, 108), _secret(503, 116)], None, [_lookup(116)],
                 {'secret-501': L4, 'secret-502': None, 'secret-503': L3}),
                ('2,3', [_secret(501, 103), _secret(502, 117), _secret(503, 101), _secret(504, 108)], None,
                 [_lookup(103), _lookup(116)],
                 {'secret-501': L2, 'secret-502': L4, 'secret-503': None, 'secret-504': None}),
                ('6', [_secret(501, 200), _secret(502, 101), _secret(503, 1)], personal, [_lookup(1)],
                 {'secret-501': 'My_Stuff', 'secret-502': None, 'secret-503': None}),
                ('1-6', [_secret(501, 117)], None, [_lookup(i) for i in (101, 103, 116, 117, 108, 1)],
                 {'secret-501': L4}),
                ('5', [], None, [_lookup(108)], {}),
                ('1', [_secret(501, 300)], [_folder(300, 'Orphan', parent=999)], [_lookup(300)], {'secret-501': 'Orphan'}),
        ):
            with self.subTest(choice=choice):
                records, _ = self._import(choice, secrets, raw_folders=raw)
                self.assertEqual(self.last_endpoints, ['/v1/folders'] + endpoints)
                self.assertEqual(self._paths(records), paths)

    def test_imports_all_and_drops_personal(self):
        secrets = [_secret(501, 117), _secret(502, 1), _secret(503, 108), _secret(504, 999)]
        expected = {'secret-501': L4, 'secret-502': None, 'secret-503': r'Test_Folder_l1\Test_Folder_l100',
                    'secret-504': None}
        for label, kwargs, prompted in (('blank', {'choice': ''}, True), ('A', {'choice': 'A'}, True),
                                        ('a', {'choice': '  a  '}, True),
                                        ('eof', {'choice': None, 'input_error': EOFError}, True),
                                        ('non-interactive', {'choice': '3', 'interactive': False}, False)):
            with self.subTest(label):
                records, mocked_input = self._import(secrets=secrets, **kwargs)
                self.assertEqual(mocked_input.called, prompted)
                self.assertEqual(self.last_endpoints, ['/v1/folders', TENANT_LOOKUP])
                self.assertEqual(self._paths(records), expected)

    def test_no_folders_imports_all_without_prompting(self):
        for raw_folders in ([], None, {'error': 'bad'}, [None, 'junk']):
            with self.subTest(raw_folders=raw_folders):
                records, mocked_input = self._import('1', [_secret(501, 117)],
                                                     raw_folders=raw_folders if raw_folders is not None else [])
                mocked_input.assert_not_called()
                self.assertEqual(self.last_endpoints, ['/v1/folders', TENANT_LOOKUP])
                self.assertEqual(self._paths(records), {'secret-501': None})

    def test_non_list_secret_lookup_imports_nothing(self):
        for choice in ('', '3'):
            with self.subTest(choice=choice):
                self.assertEqual(self._import(choice, [_secret(501, 117)], lookup={'error': 'bad'})[0], [])

    def test_filter_folder_skips_the_picker(self):
        duplicate = self.raw_folders + [_folder(300, 'Test_Folder_L3')]
        for filter_folder, raw, endpoints, paths in (
                ('Test_Folder_L3', None, [_lookup(116)], {'secret-501': L4}),
                ('test_folder_l4', None, [_lookup(117)], {'secret-501': L4}),
                ('Personal Folders', None, [_lookup(1)], {'secret-501': None}),  # 117 is outside the subtree
                ('Test_Folder_L3', duplicate, [_lookup(116), _lookup(300)], {'secret-501': L4}),
                ('Does_Not_Exist', None, [], {}),
        ):
            with self.subTest(filter_folder=filter_folder, duplicate=raw is not None):
                records, mocked_input = self._import('3', [_secret(501, 117)], raw_folders=raw,
                                                     filter_folder=filter_folder)
                mocked_input.assert_not_called()
                self.assertEqual(self.last_endpoints, ['/v1/folders'] + endpoints)
                self.assertEqual(self._paths(records), paths)

    def test_keyboard_interrupt_cancels_before_secret_lookup(self):
        with self.assertRaisesRegex(Exception, '^Import canceled$'):
            self._import(None, [_secret(501, 117)], input_error=KeyboardInterrupt)
        self.assertEqual(self.last_endpoints, ['/v1/folders'])


class GetSecretIdsTests(unittest.TestCase):
    def setUp(self):
        self.auth = mock.Mock()

    def _endpoints(self):
        return [call.args[0] for call in self.auth.thycotic_search.call_args_list]

    def test_queries_each_folder_and_removes_duplicates(self):
        self.auth.thycotic_search.side_effect = [[{'id': 1}, {'id': 2}], [{'id': 2}, {'id': 3}], [{'id': 3}]]
        self.assertEqual(ThycoticMixin.get_secret_ids(self.auth, [103, 116, 116], 'filter.includeSubFolders=true'),
                         [1, 2, 3])
        self.assertEqual(self._endpoints(), [_lookup(103), _lookup(116), _lookup(116)])

    def test_no_usable_folder_ids_make_no_calls(self):
        for folder_ids in ([], None, (), [None]):
            with self.subTest(folder_ids=folder_ids):
                self.assertEqual(ThycoticMixin.get_secret_ids(self.auth, folder_ids, 'q'), [])
                self.auth.thycotic_search.assert_not_called()

    def test_query_encoding(self):
        for folder_ids, query, expected in (([5], '', '/v1/secrets/lookup?filter.folderId=5'),
                                            ([None, 5], None, '/v1/secrets/lookup?filter.folderId=5'),
                                            ([5], 'a=1&b=x y', '/v1/secrets/lookup?filter.folderId=5&a=1&b=x+y')):
            with self.subTest(query=query):
                self.auth.reset_mock()
                self.auth.thycotic_search.return_value = []
                ThycoticMixin.get_secret_ids(self.auth, folder_ids, query)
                self.auth.thycotic_search.assert_called_once_with(expected)

    def test_non_list_response_and_malformed_secrets_are_ignored(self):
        self.auth.thycotic_search.side_effect = [None, {'error': 'bad'}, 'text', [None, {}, {'id': None}, {'id': 7}]]
        self.assertEqual(ThycoticMixin.get_secret_ids(self.auth, [1, 2, 3, 4], ''), [7])

    def test_search_error_propagates(self):
        self.auth.thycotic_search.side_effect = RuntimeError('boom')
        with self.assertRaisesRegex(RuntimeError, 'boom'):
            ThycoticMixin.get_secret_ids(self.auth, [5], '')


if __name__ == '__main__':
    unittest.main()
