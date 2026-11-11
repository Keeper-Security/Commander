import unittest
from keepercommander.commands.pam_import.delinea_import import DelineaImportOrchestrator, DelineaImportOptions


class TestSelectedFolders(unittest.TestCase):
    """Test folder selection by path prefix matching with comprehensive coverage."""

    def setUp(self):
        self.options = DelineaImportOptions(server='test.example.com')
        self.orchestrator = DelineaImportOrchestrator(None, None, self.options)

    def test_no_filter_returns_all_folders(self):
        """When no folders filter, all folders are selected."""
        folders = {
            1: {'folderName': 'Folder1', 'folderPath': 'Root/Folder1'},
            2: {'folderName': 'Folder2', 'folderPath': 'Root/Folder2'},
        }
        self.options.folders = []
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(sorted(result), [1, 2])

    def test_exact_name_match(self):
        """Folder matching by exact name."""
        folders = {
            1: {'folderName': 'DevSecrets', 'folderPath': 'Root/DevSecrets'},
            2: {'folderName': 'ProdSecrets', 'folderPath': 'Root/ProdSecrets'},
        }
        self.options.folders = ['DevSecrets']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [1])

    def test_path_prefix_match(self):
        """Folder matching by path prefix."""
        folders = {
            1: {'folderName': 'DB', 'folderPath': 'Root/Dev/DB'},
            2: {'folderName': 'DB', 'folderPath': 'Root/Prod/DB'},
            3: {'folderName': 'App', 'folderPath': 'Root/Dev/App'},
        }
        self.options.folders = ['Root/Dev']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(sorted(result), [1, 3])

    def test_case_insensitive_matching(self):
        """Path matching is case-insensitive."""
        folders = {
            1: {'folderName': 'DevSecrets', 'folderPath': 'ROOT/DEV/SECRETS'},
        }
        self.options.folders = ['root/dev/secrets']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [1])

    def test_backslash_path_conversion(self):
        """Windows backslash paths are converted to forward slashes."""
        folders = {
            1: {'folderName': 'Secrets', 'folderPath': 'Root\\Dev\\Secrets'},
        }
        self.options.folders = ['root/dev/secrets']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [1])

    def test_trailing_slash_normalization(self):
        """Trailing slashes are stripped for consistent matching."""
        folders = {
            1: {'folderName': 'Dev', 'folderPath': 'Root/Dev/'},
        }
        self.options.folders = ['root/dev']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [1])

    def test_multiple_prefix_filters(self):
        """Multiple folder prefixes are OR'd together."""
        folders = {
            1: {'folderName': 'Dev', 'folderPath': 'Root/Dev'},
            2: {'folderName': 'Staging', 'folderPath': 'Root/Staging'},
            3: {'folderName': 'Prod', 'folderPath': 'Root/Prod'},
        }
        self.options.folders = ['root/dev', 'root/staging']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(sorted(result), [1, 2])

    def test_partial_path_no_match(self):
        """Partial path match without trailing slash does not match subdirectories."""
        folders = {
            1: {'folderName': 'Secrets', 'folderPath': 'Root/Dev/Secrets'},
        }
        self.options.folders = ['root/de']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [])

    # === Edge Cases with Special Characters ===

    def test_spaces_in_folder_names(self):
        """Folder names with spaces are matched correctly."""
        folders = {
            1: {'folderName': 'Dev Secrets', 'folderPath': 'Root/Dev Secrets'},
            2: {'folderName': 'Prod Secrets', 'folderPath': 'Root/Prod Secrets'},
        }
        self.options.folders = ['root/dev secrets']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [1])

    def test_special_chars_in_paths(self):
        """Paths with special characters (@, -, _, #)."""
        folders = {
            1: {'folderName': 'Dev-Secrets_v2', 'folderPath': 'Root/Dev-Secrets_v2'},
            2: {'folderName': 'Prod@Main', 'folderPath': 'Root/Prod@Main'},
            3: {'folderName': 'DB#Backup', 'folderPath': 'Root/DB#Backup'},
        }
        self.options.folders = ['root/dev-secrets_v2', 'root/prod@main']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(sorted(result), [1, 2])

    def test_mixed_case_with_special_chars(self):
        """Mixed case with special characters."""
        folders = {
            1: {'folderName': 'DevDB-Prod_v2', 'folderPath': 'Root/DevDB-Prod_v2'},
        }
        self.options.folders = ['ROOT/DEVDB-PROD_V2']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [1])

    def test_leading_trailing_spaces_in_filter(self):
        """Leading/trailing spaces in filter prevent match (spaces not stripped by split)."""
        folders = {
            1: {'folderName': 'Dev', 'folderPath': 'Root/Dev'},
        }
        self.options.folders = ['  root/dev  ']
        result = self.orchestrator._selected_folders(folders)
        # Spaces prevent match because .casefold() doesn't strip them
        self.assertEqual(result, [])

    def test_empty_folder_name_and_path(self):
        """Folders with missing/empty names/paths are handled."""
        folders = {
            1: {'folderName': '', 'folderPath': ''},
            2: {'folderName': 'Dev', 'folderPath': 'Root/Dev'},
            3: {},
        }
        self.options.folders = ['root/dev']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [2])

    def test_dots_in_path(self):
        """Paths with dots (v1.0, config.yml pattern)."""
        folders = {
            1: {'folderName': 'v1.0', 'folderPath': 'Root/Apps/v1.0'},
            2: {'folderName': 'v2.0', 'folderPath': 'Root/Apps/v2.0'},
        }
        self.options.folders = ['root/apps/v1.0']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [1])

    def test_numeric_folder_names(self):
        """Numeric folder names."""
        folders = {
            1: {'folderName': '2024', 'folderPath': 'Root/Archives/2024'},
            2: {'folderName': '2023', 'folderPath': 'Root/Archives/2023'},
        }
        self.options.folders = ['root/archives/2024']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [1])

    def test_very_deep_path_nesting(self):
        """Very deep folder hierarchy."""
        folders = {
            1: {'folderName': 'Final', 'folderPath': 'L1/L2/L3/L4/L5/L6/L7/L8/Final'},
        }
        self.options.folders = ['l1/l2/l3/l4/l5']
        result = self.orchestrator._selected_folders(folders)
        self.assertEqual(result, [1])


if __name__ == '__main__':
    unittest.main()
