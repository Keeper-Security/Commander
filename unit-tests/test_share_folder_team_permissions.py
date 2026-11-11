import unittest
from unittest.mock import MagicMock

from keepercommander import utils
from keepercommander.commands.register import ShareFolderCommand


class TestShareFolderNewTeamPermissions(unittest.TestCase):
    """prepare_request for a team that isn't on the folder yet: 'off' must mean off."""

    def setUp(self):
        self.team_uid = utils.base64_url_encode(b'\x02' * 16)
        self.params = MagicMock()
        self.params.forbid_rsa = True
        self.params.key_cache = {self.team_uid: MagicMock(aes=b'\x03' * 32)}

    def _new_team_entry(self, manage_records, manage_users, default_on=False):
        curr_sf = {
            'shared_folder_uid': utils.base64_url_encode(b'\x01' * 16),
            'shared_folder_key_unencrypted': b'\x04' * 32,
            'default_manage_records': default_on,
            'default_manage_users': default_on,
            'teams': [],
        }
        kwargs = {'action': 'grant', 'manage_records': manage_records, 'manage_users': manage_users}
        rq = ShareFolderCommand.prepare_request(self.params, kwargs, curr_sf, [], [self.team_uid], [])
        self.assertEqual(len(rq.sharedFolderAddTeam), 1)
        return rq.sharedFolderAddTeam[0]

    def test_off_grants_no_manage_rights(self):
        to = self._new_team_entry('off', 'off', default_on=True)
        self.assertFalse(to.manageRecords)
        self.assertFalse(to.manageUsers)

    def test_on_grants_manage_rights(self):
        to = self._new_team_entry('on', 'on')
        self.assertTrue(to.manageRecords)
        self.assertTrue(to.manageUsers)

    def test_omitted_falls_back_to_folder_defaults(self):
        to = self._new_team_entry(None, None, default_on=True)
        self.assertTrue(to.manageRecords)
        self.assertTrue(to.manageUsers)
        to = self._new_team_entry(None, None, default_on=False)
        self.assertFalse(to.manageRecords)
        self.assertFalse(to.manageUsers)


if __name__ == '__main__':
    unittest.main()
