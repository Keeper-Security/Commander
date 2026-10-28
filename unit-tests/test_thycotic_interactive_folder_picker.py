import unittest
from unittest import mock
from keepercommander.importer.thycotic.thycotic import ThycoticImporter, ThycoticMixin




def _folder(folder_id, name, parent=-1, with_path=True):
    folder = {'id': folder_id, 'folderName': name, 'parentFolderId': parent, 'inheritPermissions': True}
    if with_path:
        folder['folderPath'] = '\\' + name
    return folder


class ParseChoiceTests(unittest.TestCase):
    def test_invalid_input_is_rejected(self):
        for choice, count in ((None, 5), ('', 5), ('A', 5), ('0', 5), ('6', 5), ('3-1', 5), ('1-6', 5),
                              ('1,', 5), ('1,,2', 5), ('1 2', 5), ('1.5', 5), ('+1', 5), ('1', 0)):
            with self.subTest(choice=choice, count=count):
                self.assertIsNone(ThycoticMixin._parse_choice(choice, count))

    def test_valid_input_is_parsed(self):
        for choice, count, expected in (('1', 1, {1}), ('5', 5, {5}), ('  2 - 4 , 4  ', 4, {2, 3, 4}),
                                        ('1-3,2-4', 4, {1, 2, 3, 4}), ('2,1,1', 3, {1, 2})):
            with self.subTest(choice=choice):
                self.assertEqual(ThycoticMixin._parse_choice(choice, count), expected)


    def test_non_string_choice_is_rejected(self):
        for choice in (1, ['1'], b'1'):
            with self.subTest(choice=choice):
                self.assertIsNone(ThycoticMixin._parse_choice(choice, 5))

    def test_whitespace_only_and_separator_only_input_is_rejected(self):
        for choice in ('   ', ',', '-', '1-', '-1', '1--2', '1-2-3', ' , '):
            with self.subTest(choice=choice):
                self.assertIsNone(ThycoticMixin._parse_choice(choice, 5))

    def test_negative_count_rejects_everything(self):
        self.assertIsNone(ThycoticMixin._parse_choice('1', -1))

    def test_single_value_range_is_accepted(self):
        self.assertEqual(ThycoticMixin._parse_choice('3-3', 5), {3})


class SelectFoldersTests(unittest.TestCase):
    def setUp(self):
        self.folders = [_folder(1, 'a'), _folder(2, 'b'), _folder(3, 'c')]

    def test_blank_or_a_returns_all(self):
        for choice in ('', '   ', 'a', ' A ', None):
            with self.subTest(choice=choice):
                self.assertIs(ThycoticMixin._select_folders(self.folders, choice), self.folders)

    def test_valid_choice_filters_in_list_order(self):
        self.assertEqual(ThycoticMixin._select_folders(self.folders, '3,1'), [self.folders[0], self.folders[2]])
        self.assertEqual(ThycoticMixin._select_folders(self.folders, '2-3'), self.folders[1:])

    def test_invalid_choice_returns_none(self):
        for choice in ('0', '4', 'x', '1,,2'):
            with self.subTest(choice=choice):
                self.assertIsNone(ThycoticMixin._select_folders(self.folders, choice))


class InteractiveFolderPickerTests(unittest.TestCase):
    def setUp(self):
        self.folders = [
            _folder(116, 'L3', parent=103),
            _folder(103, 'l2', parent=101),
            _folder(101, 'l1'),
            _folder(108, 'l100', parent=101),
        ]

    def _pick(self, folders, *inputs):
        with mock.patch('builtins.input', side_effect=inputs) as mocked_input, \
                mock.patch('builtins.print') as mocked_print:
            result = ThycoticMixin.interactive_folder_picker(folders)
        printed = [call.args[0] for call in mocked_print.call_args_list if call.args]
        return result, printed, mocked_input

    def test_non_list_returns_none(self):
        with mock.patch('builtins.input') as mocked_input:
            self.assertIsNone(ThycoticMixin.interactive_folder_picker({101: self.folders[2]}))
        mocked_input.assert_not_called()

    def test_blank_or_a_imports_all(self):
        for choice in ('', '  a  ', 'A'):
            with self.subTest(choice=choice):
                result, _, _ = self._pick(self.folders, choice)
                self.assertIs(result, self.folders)

    def test_selection_returns_numbered_rows_in_list_order(self):
        result, _, _ = self._pick(self.folders, '4,1,2')
        self.assertEqual(result, [self.folders[0], self.folders[1], self.folders[3]])

    def test_invalid_entries_are_retried(self):
        result, printed, mocked_input = self._pick(self.folders, 'nope', '1,99', '2')
        self.assertEqual(result, [self.folders[1]])
        self.assertEqual(mocked_input.call_count, 3)
        self.assertEqual(len([line for line in printed if line.startswith('Invalid choice')]), 2)

    def test_missing_folder_path_falls_back_to_name(self):
        folder = {'folderName': 'Bare'}
        _, printed, _ = self._pick([folder], '1')
        self.assertTrue(any('[1] Bare - Path -> Bare' in line for line in printed))

    def test_raw_folders_without_path_display_constructed_path(self):
        raw = [
            _folder(101, 'Test_Folder_l1', with_path=False),
            _folder(103, 'Test_Folder_l2', parent=101, with_path=False),
            _folder(116, 'Test_Folder_L3', parent=103, with_path=False),
        ]
        _, printed, _ = self._pick(raw, '1')
        self.assertTrue(any(
            '[3] Test_Folder_L3 - Path -> Test_Folder_l1 / Test_Folder_l2 / Test_Folder_L3' in line
            for line in printed
        ))
        self.assertIn('folderPath', raw[2])

    def test_constructed_folder_displays_formatted_path(self):
        constructed = list(ThycoticMixin._construct_folders([
            _folder(101, 'Test_Folder_l1'),
            _folder(103, 'Test_Folder_l2', parent=101),
            _folder(116, 'Test_Folder_L3', parent=103),
        ]).values())
        _, printed, _ = self._pick(constructed, '1')
        self.assertTrue(any(
            '[3] Test_Folder_L3 - Path -> Test_Folder_l1 / Test_Folder_l2 / Test_Folder_L3' in line
            for line in printed
        ))

    def test_keyboard_interrupt_cancels(self):
        with mock.patch('builtins.input', side_effect=KeyboardInterrupt), mock.patch('builtins.print'):
            with self.assertRaises(Exception) as ctx:
                ThycoticMixin.interactive_folder_picker([_folder(7, 'Bare')])
        self.assertEqual(str(ctx.exception), 'Import canceled')

    def test_eof_imports_all(self):
        folders = [_folder(7, 'Bare')]
        with mock.patch('builtins.input', side_effect=EOFError), mock.patch('builtins.print'):
            self.assertIs(ThycoticMixin.interactive_folder_picker(folders), folders)

    def test_none_returns_none(self):
        with mock.patch('builtins.input') as mocked_input:
            self.assertIsNone(ThycoticMixin.interactive_folder_picker(None))
        mocked_input.assert_not_called()

    def test_empty_list_returns_it_without_prompting(self):
        folders = []
        with mock.patch('builtins.input') as mocked_input, mock.patch('builtins.print'):
            self.assertIs(ThycoticMixin.interactive_folder_picker(folders), folders)
        mocked_input.assert_not_called()

    def test_none_or_empty_folder_path_falls_back_to_name(self):
        for folder_path in (None, ''):
            with self.subTest(folder_path=folder_path):
                _, printed, _ = self._pick([{'folderName': 'Bare', 'folderPath': folder_path}], '1')
                self.assertTrue(any('[1] Bare - Path -> Bare' in line for line in printed))

    def test_missing_or_none_folder_name_does_not_crash(self):
        folders = [{'id': 5}, {'id': 6, 'folderName': None}]
        result, printed, _ = self._pick(folders, '2')
        self.assertEqual(result, [folders[1]])
        self.assertTrue(any(line.startswith('  [1]  - Path -> ') for line in printed))

    def test_parent_missing_from_list_shows_only_own_name(self):
        _, printed, _ = self._pick([_folder(116, 'Orphan', parent=999, with_path=False)], '1')
        self.assertTrue(any('[1] Orphan - Path -> Orphan' in line for line in printed))

    def test_self_parent_and_cycle_do_not_hang(self):
        folders = [
            _folder(10, 'Self', parent=10, with_path=False),
            _folder(20, 'A', parent=21, with_path=False),
            _folder(21, 'B', parent=20, with_path=False),
        ]
        _, printed, _ = self._pick(folders, '1')
        self.assertTrue(any('[1] Self - Path -> Self' in line for line in printed))
        self.assertTrue(any('[2] A - Path -> B / A' in line for line in printed))

    def test_out_of_range_then_import_all(self):
        result, _, mocked_input = self._pick(self.folders, '0', '5', 'a')
        self.assertIs(result, self.folders)
        self.assertEqual(mocked_input.call_count, 3)

    def test_full_range_returns_every_folder(self):
        result, _, _ = self._pick(self.folders, '1-4')
        self.assertEqual(result, self.folders)

    def test_interrupt_after_invalid_entry_cancels(self):
        with mock.patch('builtins.input', side_effect=['bad', KeyboardInterrupt]), mock.patch('builtins.print'):
            with self.assertRaises(Exception) as ctx:
                ThycoticMixin.interactive_folder_picker(self.folders)
        self.assertEqual(str(ctx.exception), 'Import canceled')


class ExpandFolderIdsTests(unittest.TestCase):
    def test_includes_descendants_but_not_siblings(self):
        folders = [
            _folder(101, 'l1'),
            _folder(103, 'l2', parent=101),
            _folder(108, 'l100', parent=101),
            _folder(116, 'L3', parent=103),
            _folder(117, 'l4', parent=116),
        ]
        self.assertEqual(ThycoticMixin.expand_folder_ids(folders, [103]), {103, 116, 117})
        self.assertEqual(ThycoticMixin.expand_folder_ids({f['id']: f for f in folders}, [116]), {116, 117})

    def test_cycle_terminates(self):
        folders = [_folder(10, 'A', parent=11), _folder(11, 'B', parent=10)]
        self.assertEqual(ThycoticMixin.expand_folder_ids(folders, [10]), {10, 11})

    def test_root_id_not_in_folders_returns_only_itself(self):
        folders = [_folder(101, 'l1'), _folder(103, 'l2', parent=101)]
        self.assertEqual(ThycoticMixin.expand_folder_ids(folders, [999]), {999})

    def test_unknown_root_with_children_still_expands(self):
        # Personal Folders (id 1) is removed from the folder map, but its children must still be found
        folders = {200: _folder(200, 'Mine', parent=1), 201: _folder(201, 'Sub', parent=200)}
        self.assertEqual(ThycoticMixin.expand_folder_ids(folders, [1]), {1, 200, 201})

    def test_empty_and_none_inputs_return_empty_set(self):
        folders = [_folder(101, 'l1')]
        for folder_input, root_ids in ((folders, []), (folders, None), ([], [101]), ({}, [101]),
                                       (None, [101]), (None, None)):
            with self.subTest(folders=folder_input, root_ids=root_ids):
                self.assertEqual(ThycoticMixin.expand_folder_ids(folder_input, root_ids), set())

    def test_none_root_ids_are_ignored(self):
        folders = [_folder(101, 'l1'), _folder(103, 'l2', parent=101)]
        self.assertEqual(ThycoticMixin.expand_folder_ids(folders, [None, 101]), {101, 103})
        self.assertEqual(ThycoticMixin.expand_folder_ids(folders, [None]), set())

    def test_duplicate_roots_and_root_that_is_descendant(self):
        folders = [_folder(101, 'l1'), _folder(103, 'l2', parent=101), _folder(116, 'L3', parent=103)]
        self.assertEqual(ThycoticMixin.expand_folder_ids(folders, [101, 101, 116]), {101, 103, 116})

    def test_malformed_entries_are_skipped(self):
        folders = [None, 'junk', {'parentFolderId': 101}, {'id': None, 'parentFolderId': 101},
                   _folder(101, 'l1'), _folder(103, 'l2', parent=101)]
        self.assertEqual(ThycoticMixin.expand_folder_ids(folders, [101]), {101, 103})

    def test_leaf_root_returns_only_itself(self):
        folders = [_folder(101, 'l1'), _folder(103, 'l2', parent=101)]
        self.assertEqual(ThycoticMixin.expand_folder_ids(folders, [103]), {103})

    def test_self_parent_terminates(self):
        self.assertEqual(ThycoticMixin.expand_folder_ids([_folder(10, 'A', parent=10)], [10]), {10})


class ConstructFoldersTests(unittest.TestCase):
    def test_non_list_and_empty_inputs_return_empty_dict(self):
        for folder_rs in (None, {}, {'error': 'bad'}, 'text', 5, []):
            with self.subTest(folder_rs=folder_rs):
                self.assertEqual(ThycoticMixin._construct_folders(folder_rs), {})

    def test_entries_without_id_or_not_dicts_are_skipped(self):
        folders = ThycoticMixin._construct_folders([None, 'junk', {'folderName': 'NoId'},
                                                    {'id': None, 'folderName': 'NullId'}, _folder(101, 'l1')])
        self.assertEqual(set(folders), {101})

    def test_missing_optional_keys_get_defaults(self):
        folders = ThycoticMixin._construct_folders([{'id': 5}, {'id': 6, 'folderName': None}])
        self.assertEqual(folders[5], {'id': 5, 'folderName': '', 'inheritPermissions': True,
                                      'parentFolderId': None, 'folderPath': ''})
        self.assertEqual(folders[6]['folderName'], '')

    def test_duplicate_ids_keep_first(self):
        folders = ThycoticMixin._construct_folders([_folder(5, 'First'), _folder(5, 'Second')])
        self.assertEqual(folders[5]['folderName'], 'First')

    def test_unusual_parent_ids_do_not_extend_path(self):
        for parent in (None, -1, 0, 1, 999, '101'):
            with self.subTest(parent=parent):
                folders = ThycoticMixin._construct_folders([_folder(101, 'l1'), _folder(103, 'l2', parent=parent)])
                self.assertEqual(folders[103]['folderPath'], 'l2')

    def test_cycles_and_self_parent_terminate(self):
        folders = ThycoticMixin._construct_folders([
            _folder(10, 'Self', parent=10),
            _folder(20, 'A', parent=21),
            _folder(21, 'B', parent=20),
        ])
        self.assertEqual(folders[10]['folderPath'], 'Self')
        self.assertEqual(folders[20]['folderPath'], 'B\\A')
        self.assertEqual(folders[21]['folderPath'], 'A\\B')


class GetFoldersTests(unittest.TestCase):
    def setUp(self):
        self.auth = mock.Mock()
        self.auth.thycotic_search.return_value = [
            _folder(101, 'Test_Folder_l1'),
            _folder(103, 'Test_Folder_l2', parent=101),
            _folder(116, 'Test_Folder_L3', parent=103),
            _folder(117, 'Test_Folder_l4', parent=116),
            _folder(108, 'Test_Folder_l100', parent=101),
            _folder(1, 'Personal Folders'),
        ]

    def test_returns_dict_without_prompt_and_builds_paths(self):
        with mock.patch('builtins.input') as mocked_input:
            folders = ThycoticMixin.get_folders(self.auth, skip_permissions=True)
        mocked_input.assert_not_called()
        self.assertIsInstance(folders, dict)
        self.assertNotIn(1, folders)
        self.assertEqual(set(folders), {101, 103, 116, 117, 108})
        self.assertEqual(
            folders[117]['folderPath'],
            r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3\Test_Folder_l4',
        )

    def test_non_list_response_returns_empty(self):
        self.auth.thycotic_search.return_value = {'error': 'bad'}
        with mock.patch('builtins.input') as mocked_input:
            self.assertEqual(ThycoticMixin.get_folders(self.auth, skip_permissions=True), {})
        mocked_input.assert_not_called()

    def test_builds_paths_when_source_omits_folder_path(self):
        self.auth.thycotic_search.return_value = [
            _folder(101, 'Test_Folder_l1', with_path=False),
            _folder(103, 'Test_Folder_l2', parent=101, with_path=False),
            _folder(116, 'Test_Folder_L3', parent=103, with_path=False),
            _folder(1, 'Personal Folders', with_path=False),
        ]
        folders = ThycoticMixin.get_folders(self.auth, skip_permissions=True)
        self.assertIsInstance(folders, dict)
        self.assertNotIn(1, folders)
        self.assertEqual(
            folders[116]['folderPath'],
            r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3',
        )

    def test_none_and_empty_response_returns_empty(self):
        for response in (None, []):
            with self.subTest(response=response):
                self.auth.thycotic_search.return_value = response
                self.assertEqual(ThycoticMixin.get_folders(self.auth, skip_permissions=True), {})

    def test_only_personal_folder_returns_empty(self):
        self.auth.thycotic_search.return_value = [_folder(1, 'Personal Folders')]
        self.assertEqual(ThycoticMixin.get_folders(self.auth, skip_permissions=True), {})

    def test_child_of_personal_folder_has_own_name_as_path(self):
        self.auth.thycotic_search.return_value = [_folder(1, 'Personal Folders'), _folder(200, 'Mine', parent=1)]
        folders = ThycoticMixin.get_folders(self.auth, skip_permissions=True)
        self.assertEqual(folders[200]['folderPath'], 'Mine')

def _secret(secret_id, folder_id):
    return {
        'id': secret_id,
        'name': f'secret-{secret_id}',
        'items': [],
        'folderId': folder_id,
        'secretTemplateName': '',
    }

class ImportFolderSelectionTests(unittest.TestCase):
    def setUp(self):
        # Menu order matters: choice '3' must be Test_Folder_L3 (116)
        self.raw_folders = [
            _folder(101, 'Test_Folder_l1'),
            _folder(103, 'Test_Folder_l2', parent=101),
            _folder(116, 'Test_Folder_L3', parent=103),
            _folder(117, 'Test_Folder_l4', parent=116),
            _folder(108, 'Test_Folder_l100', parent=101),
            _folder(1, 'Personal Folders'),
        ]

    def _import(self, choice, secrets, raw_folders=None, filter_folder=None, input_error=None, interactive=True):
        raw_folders = self.raw_folders if raw_folders is None else raw_folders
        secrets_by_id = {secret['id']: secret for secret in secrets}

        def search(endpoint):
            if endpoint == '/v1/folders':
                return raw_folders
            return [{'id': secret['id']} for secret in secrets]

        def entity(endpoint):
            secret_id = int(endpoint.rstrip('/').rsplit('/', 1)[-1])
            return secrets_by_id[secret_id]
        input_patch = mock.patch(
            'builtins.input',
            side_effect=input_error if input_error is not None else None,
            return_value=None if input_error is not None else choice,
        )
        with mock.patch('keepercommander.importer.thycotic.thycotic.ThycoticAuth') as auth_cls, \
                mock.patch('keepercommander.importer.thycotic.thycotic.getpass.getpass', return_value='pw'), \
                mock.patch('keepercommander.importer.thycotic.thycotic.os.path.isfile', return_value=False), \
                mock.patch('keepercommander.importer.thycotic.thycotic.sys.stdin') as mocked_stdin, \
                input_patch as mocked_input, \
                mock.patch('builtins.print'):
            mocked_stdin.isatty.return_value = interactive
            auth = auth_cls.return_value
            auth.thycotic_search.side_effect = search
            auth.thycotic_entity.side_effect = entity
            kwargs = {}
            if filter_folder is not None:
                kwargs['filter_folder'] = filter_folder
            try:
                records = list(ThycoticImporter().do_import('user@thycotic.example', **kwargs))
            finally:
                self.last_endpoints = [call.args[0] for call in auth.thycotic_search.call_args_list]
        return records, auth, mocked_input

    @staticmethod
    def _path(record):
        if not record.folders:
            return None
        return record.folders[0].path

    def _paths(self, records):
        return {record.title: self._path(record) for record in records}

    def _endpoints(self, auth):
        return [call.args[0] for call in auth.thycotic_search.call_args_list]

    def test_picked_folder_keeps_descendants_and_full_path(self):
        secrets = [_secret(501, 117), _secret(502, 108), _secret(503, 116)]
        records, auth, _ = self._import('3', secrets)
        self.assertEqual(self._endpoints(auth), [
            '/v1/folders',
            '/v1/secrets/lookup?filter.folderId=116&filter.includeSubFolders=true',
        ])
        self.assertEqual(self._paths(records), {
            'secret-501': r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3\Test_Folder_l4',
            'secret-502': None,
            'secret-503': r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3',
        })

    def test_import_all_uses_secret_lookup_and_drops_personal(self):
        secrets = [_secret(501, 117), _secret(502, 1), _secret(503, 108)]
        for choice in ('', 'A', '  a  '):
            with self.subTest(choice=choice):
                records, auth, _ = self._import(choice, secrets)
                self.assertEqual(self._endpoints(auth), ['/v1/folders', '/v1/secrets/lookup'])
                self.assertEqual(self._paths(records), {
                    'secret-501': r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3\Test_Folder_l4',
                    'secret-502': None,
                    'secret-503': r'Test_Folder_l1\Test_Folder_l100',
                })

    def test_filter_folder_skips_the_picker_and_keeps_descendants(self):
        secrets = [_secret(501, 117), _secret(502, 108)]
        records, auth, mocked_input = self._import('3', secrets, filter_folder='Test_Folder_L3')
        mocked_input.assert_not_called()
        self.assertEqual(self._endpoints(auth), [
            '/v1/folders',
            '/v1/secrets/lookup?filter.folderId=116&filter.includeSubFolders=true',
        ])
        self.assertEqual(self._paths(records), {
            'secret-501': r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3\Test_Folder_l4',
            'secret-502': None,
        })

    def test_picking_parent_and_child_keeps_parent_subtree(self):
        secrets = [_secret(501, 103), _secret(502, 117), _secret(503, 101), _secret(504, 108)]
        records, auth, _ = self._import('2,3', secrets)
        self.assertEqual(self._endpoints(auth), [
            '/v1/folders',
            '/v1/secrets/lookup?filter.folderId=103&filter.includeSubFolders=true',
            '/v1/secrets/lookup?filter.folderId=116&filter.includeSubFolders=true',
        ])
        self.assertEqual(self._paths(records), {
            'secret-501': r'Test_Folder_l1\Test_Folder_l2',
            'secret-502': r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3\Test_Folder_l4',
            'secret-503': None,
            'secret-504': None,
        })

    def test_picking_personal_keeps_only_its_children(self):
        raw_folders = self.raw_folders + [_folder(200, 'My_Stuff', parent=1)]
        secrets = [_secret(501, 200), _secret(502, 101), _secret(503, 1)]
        records, auth, _ = self._import('6', secrets, raw_folders=raw_folders)
        self.assertEqual(self._endpoints(auth), [
            '/v1/folders',
            '/v1/secrets/lookup?filter.folderId=1&filter.includeSubFolders=true',
        ])
        self.assertEqual(self._paths(records), {
            'secret-501': 'My_Stuff',
            'secret-502': None,
            'secret-503': None,
        })

    def test_keyboard_interrupt_cancels_before_secret_lookup(self):
        with self.assertRaises(Exception) as ctx:
            self._import(None, [_secret(501, 117)], input_error=KeyboardInterrupt)
        self.assertEqual(str(ctx.exception), 'Import canceled')
        self.assertEqual(self.last_endpoints, ['/v1/folders'])

    def test_eof_imports_all(self):
        records, auth, _ = self._import(None, [_secret(501, 117)], input_error=EOFError)
        self.assertEqual(self._endpoints(auth), ['/v1/folders', '/v1/secrets/lookup'])
        self.assertEqual(len(records), 1)

    def test_non_interactive_imports_all_without_prompting(self):
        records, auth, mocked_input = self._import('3', [_secret(501, 117), _secret(502, 108)], interactive=False)
        mocked_input.assert_not_called()
        self.assertEqual(self._endpoints(auth), ['/v1/folders', '/v1/secrets/lookup'])
        self.assertEqual(len(records), 2)

    def test_filter_folder_not_found_imports_nothing(self):
        records, auth, mocked_input = self._import('', [_secret(501, 117)], filter_folder='Does_Not_Exist')
        mocked_input.assert_not_called()
        self.assertEqual(self._endpoints(auth), ['/v1/folders'])
        self.assertEqual(records, [])

    def test_filter_folder_is_case_insensitive(self):
        records, auth, _ = self._import('', [_secret(501, 117)], filter_folder='test_folder_l4')
        self.assertEqual(self._endpoints(auth), [
            '/v1/folders',
            '/v1/secrets/lookup?filter.folderId=117&filter.includeSubFolders=true',
        ])
        self.assertEqual(self._paths(records), {
            'secret-501': r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3\Test_Folder_l4',
        })

    def test_no_folders_imports_all_without_prompting(self):
        for raw_folders in ([], {'error': 'bad'}):
            with self.subTest(raw_folders=raw_folders):
                records, auth, mocked_input = self._import('1', [_secret(501, 117)], raw_folders=raw_folders)
                mocked_input.assert_not_called()
                self.assertEqual(self._endpoints(auth), ['/v1/folders', '/v1/secrets/lookup'])
                self.assertEqual(self._paths(records), {'secret-501': None})

    def test_secret_in_folder_missing_from_folder_list_has_no_path(self):
        records, _, _ = self._import('', [_secret(501, 999)])
        self.assertEqual(self._paths(records), {'secret-501': None})

    def test_picked_folder_with_no_secrets_imports_nothing(self):
        records, auth, _ = self._import('5', [])
        self.assertEqual(self._endpoints(auth), [
            '/v1/folders',
            '/v1/secrets/lookup?filter.folderId=108&filter.includeSubFolders=true',
        ])
        self.assertEqual(records, [])

    def test_folder_with_orphan_parent_is_offered_and_imported(self):
        raw_folders = [_folder(300, 'Orphan', parent=999)]
        records, auth, _ = self._import('1', [_secret(501, 300)], raw_folders=raw_folders)
        self.assertEqual(self._endpoints(auth), [
            '/v1/folders',
            '/v1/secrets/lookup?filter.folderId=300&filter.includeSubFolders=true',
        ])
        self.assertEqual(self._paths(records), {'secret-501': 'Orphan'})

class GetSecretIdsTests(unittest.TestCase):
    def setUp(self):
        self.auth = mock.Mock()

    def test_queries_each_folder_and_removes_duplicates(self):
        self.auth.thycotic_search.side_effect = [[{'id': 1}, {'id': 2}], [{'id': 2}, {'id': 3}]]
        ids = ThycoticMixin.get_secret_ids(self.auth, [103, 116], 'filter.includeSubFolders=true')
        self.assertEqual(ids, [1, 2, 3])
        self.assertEqual([call.args[0] for call in self.auth.thycotic_search.call_args_list], [
            '/v1/secrets/lookup?filter.folderId=103&filter.includeSubFolders=true',
            '/v1/secrets/lookup?filter.folderId=116&filter.includeSubFolders=true',
        ])

    def test_empty_query_has_no_trailing_ampersand(self):
        self.auth.thycotic_search.return_value = []
        ThycoticMixin.get_secret_ids(self.auth, [5], '')
        self.auth.thycotic_search.assert_called_once_with('/v1/secrets/lookup?filter.folderId=5')

    def test_no_folders_makes_no_calls(self):
        self.assertEqual(ThycoticMixin.get_secret_ids(self.auth, [], 'q'), [])
        self.auth.thycotic_search.assert_not_called()


    def test_none_folder_ids_make_no_calls(self):
        self.assertEqual(ThycoticMixin.get_secret_ids(self.auth, None, 'q'), [])
        self.auth.thycotic_search.assert_not_called()

    def test_none_folder_id_is_skipped(self):
        self.auth.thycotic_search.return_value = [{'id': 1}]
        self.assertEqual(ThycoticMixin.get_secret_ids(self.auth, [None, 5], None), [1])
        self.auth.thycotic_search.assert_called_once_with('/v1/secrets/lookup?filter.folderId=5')

    def test_non_list_response_and_malformed_secrets_are_ignored(self):
        self.auth.thycotic_search.side_effect = [None, {'error': 'bad'}, [None, {}, {'id': None}, {'id': 7}]]
        self.assertEqual(ThycoticMixin.get_secret_ids(self.auth, [1, 2, 3], ''), [7])

    def test_multi_param_query_is_encoded(self):
        self.auth.thycotic_search.return_value = []
        ThycoticMixin.get_secret_ids(self.auth, [5], 'a=1&b=x y')
        self.auth.thycotic_search.assert_called_once_with('/v1/secrets/lookup?filter.folderId=5&a=1&b=x+y')

if __name__ == '__main__':
    unittest.main()