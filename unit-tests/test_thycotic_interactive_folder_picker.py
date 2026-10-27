import unittest
from unittest import mock
from keepercommander.importer.thycotic.thycotic import ThycoticMixin


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
        folder = _folder(7, 'Bare', with_path=False)
        _, printed, _ = self._pick([folder], '1')
        self.assertTrue(any('[1] Bare - Path -> Bare' in line for line in printed))


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


class GetFoldersSelectionTests(unittest.TestCase):
    def setUp(self):
        # Menu order matters: choice '3' must be Test_Folder_L3 (116)
        self.auth = mock.Mock()
        self.auth.thycotic_search.return_value = [
            _folder(101, 'Test_Folder_l1'),
            _folder(103, 'Test_Folder_l2', parent=101),
            _folder(116, 'Test_Folder_L3', parent=103),
            _folder(117, 'Test_Folder_l4', parent=116),
            _folder(108, 'Test_Folder_l100', parent=101),
            _folder(1, 'Personal Folders'),
        ]

    def _load(self, choice):
        with mock.patch('builtins.input', return_value=choice), mock.patch('builtins.print'):
            return ThycoticMixin.get_folders(self.auth, skip_permissions=True)

    def test_picked_folder_keeps_descendants_and_full_path(self):
        folders, picked = self._load('3')
        self.assertEqual(picked, [116])
        self.assertEqual(set(folders), {116, 117})
        self.assertEqual(folders[117]['folderPath'], r'Test_Folder_l1\Test_Folder_l2\Test_Folder_L3\Test_Folder_l4')

    def test_import_all_keeps_every_folder_except_personal(self):
        folders, picked = self._load('')
        self.assertIsNone(picked)
        self.assertEqual(set(folders), {101, 103, 116, 117, 108})

    def test_filter_folder_and_non_interactive_skip_the_picker(self):
        for kwargs in ({'filter_folder': 'Test_Folder_L3'}, {'is_interactive': False}):
            with self.subTest(**kwargs), mock.patch('builtins.input') as mocked_input:
                folders, picked = ThycoticMixin.get_folders(self.auth, skip_permissions=True, **kwargs)
                mocked_input.assert_not_called()
                self.assertIsNone(picked)
                self.assertEqual(set(folders), {101, 103, 116, 117, 108})

    def test_non_list_response_returns_empty(self):
        self.auth.thycotic_search.return_value = {'error': 'bad'}
        with mock.patch('builtins.input') as mocked_input:
            self.assertEqual(ThycoticMixin.get_folders(self.auth, skip_permissions=True), ({}, None))
        mocked_input.assert_not_called()

    def test_picking_parent_and_child_keeps_parent_subtree(self):
        folders, picked = self._load('2,3')
        self.assertEqual(picked, [103, 116])
        self.assertEqual(set(folders), {103, 116, 117})

    def test_picking_personal_keeps_only_its_children(self):
        self.auth.thycotic_search.return_value.append(_folder(200, 'My_Stuff', parent=1))
        folders, picked = self._load('6')
        self.assertEqual(picked, [1])
        self.assertEqual(set(folders), {200})
        self.assertEqual(folders[200]['folderPath'], 'My_Stuff')


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


if __name__ == '__main__':
    unittest.main()
