import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock

from keepercommander import utils
from keepercommander.commands.register import ShareFolderCommand


def folder_request(uid_bytes):
    return SimpleNamespace(sharedFolderUid=uid_bytes)


def folder_response(status):
    return SimpleNamespace(status=status)


class TestShareFolderStatusWarning(unittest.TestCase):
    def setUp(self):
        self.uid = b'\x01' * 16
        self.params = MagicMock()
        self.params.shared_folder_cache = {utils.base64_url_encode(self.uid): {'name': 'Finance'}}
        self.params.available_team_cache = []

    def _log(self, status):
        rss = SimpleNamespace(sharedFoldersUpdateV3Response=[folder_response(status)])
        with self.assertLogs(level='WARNING') as logs:
            ShareFolderCommand._log_share_update_results(self.params, [folder_request(self.uid)], rss)
        return '\n'.join(logs.output)

    def test_missing_manage_users_warns_with_readable_reason(self):
        output = self._log('NO_MANAGE_RECORDS_PRIVILEGE')
        self.assertIn("Shared folder 'Finance' was not updated", output)
        self.assertIn('Manage Users or Manage Records', output)

    def test_no_access_warns_with_readable_reason(self):
        output = self._log('NO_PERMISSION_TO_UPDATE')
        self.assertIn('you have no access to this shared folder', output)

    def test_unknown_status_falls_back_to_the_raw_status(self):
        output = self._log('SHARED_FOLDER_NO_ADMIN')
        self.assertIn('SHARED_FOLDER_NO_ADMIN', output)

    def test_folder_not_in_cache_uses_its_uid(self):
        self.params.shared_folder_cache = {}
        output = self._log('NO_PERMISSION_TO_UPDATE')
        self.assertIn(utils.base64_url_encode(self.uid), output)


if __name__ == '__main__':
    unittest.main()
