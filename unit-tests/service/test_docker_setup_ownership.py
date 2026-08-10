#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Contact: ops@keepersecurity.com
#

"""Service Docker / integration setup must only adopt owned folders, apps, and records."""

import json
import unittest
from unittest.mock import MagicMock, patch

from keepercommander.params import KeeperParams, RecordOwner
from keepercommander.service.docker.setup_base import DockerSetupBase


FOLDER_NAME = 'Commander Service Mode - Docker'
APP_NAME = 'Commander Service Mode - KSM App'
RECORD_NAME = 'Commander Service Mode Docker Config'


class TestDockerSetupOwnershipHelpers(unittest.TestCase):
    def test_is_owned_record(self):
        params = MagicMock(spec=KeeperParams)
        params.record_owner_cache = {
            'OWNED': RecordOwner(True, 'operator'),
            'SHARED': RecordOwner(False, 'attacker'),
        }
        self.assertTrue(DockerSetupBase._is_owned_record(params, 'OWNED'))
        self.assertFalse(DockerSetupBase._is_owned_record(params, 'SHARED'))
        self.assertFalse(DockerSetupBase._is_owned_record(params, 'MISSING'))
        self.assertFalse(DockerSetupBase._is_owned_record(params, ''))

    def test_is_owned_shared_folder(self):
        params = MagicMock(spec=KeeperParams)
        params.user = 'operator@corp.example'
        params.account_uid_bytes = b'op-uid'
        params.shared_folder_cache = {
            'OWNED_SF': {'owner_username': 'operator@corp.example'},
            'SHARED_SF': {'owner_username': 'mallory@corp.example'},
        }
        self.assertTrue(DockerSetupBase._is_owned_shared_folder(params, 'OWNED_SF'))
        self.assertFalse(DockerSetupBase._is_owned_shared_folder(params, 'SHARED_SF'))
        self.assertFalse(DockerSetupBase._is_owned_shared_folder(params, 'MISSING'))


class TestCreateSharedFolderOwnership(unittest.TestCase):
    def _folder(self, name):
        folder = MagicMock()
        folder.name = name
        return folder

    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    def test_reuses_owned_folder_when_squat_also_present(self, _printer):
        params = MagicMock(spec=KeeperParams)
        params.user = 'operator@corp.example'
        params.folder_cache = {
            'ATTACKER_SF': self._folder(FOLDER_NAME),
            'OWNED_SF': self._folder(FOLDER_NAME),
        }
        params.shared_folder_cache = {
            'ATTACKER_SF': {'owner_username': 'mallory@corp.example'},
            'OWNED_SF': {'owner_username': 'operator@corp.example'},
        }

        uid = DockerSetupBase()._create_shared_folder(params, FOLDER_NAME)
        self.assertEqual(uid, 'OWNED_SF')

    @patch('keepercommander.service.docker.setup_base.api.sync_down')
    @patch('keepercommander.service.docker.setup_base.FolderMakeCommand')
    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    def test_creates_when_only_non_owned_match(self, printer, mock_mkdir, _sync):
        params = MagicMock(spec=KeeperParams)
        params.user = 'operator@corp.example'
        params.folder_cache = {'ATTACKER_SF': self._folder(FOLDER_NAME)}
        params.shared_folder_cache = {
            'ATTACKER_SF': {'owner_username': 'mallory@corp.example'},
        }
        mock_mkdir.return_value.execute.return_value = 'NEW_OWNED_SF'

        uid = DockerSetupBase()._create_shared_folder(params, FOLDER_NAME)

        self.assertEqual(uid, 'NEW_OWNED_SF')
        mock_mkdir.return_value.execute.assert_called_once()
        printer.print_warning.assert_called()


class TestCreateConfigRecordOwnership(unittest.TestCase):
    @patch('keepercommander.service.docker.setup_base.api.get_record')
    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    def test_reuses_owned_record(self, _printer, mock_get):
        owned = MagicMock()
        owned.title = RECORD_NAME
        shared = MagicMock()
        shared.title = RECORD_NAME
        mock_get.side_effect = lambda _p, uid: shared if uid == 'SHARED_REC' else owned

        params = MagicMock(spec=KeeperParams)
        params.subfolder_record_cache = {'FOLDER': ['SHARED_REC', 'OWNED_REC']}
        params.record_owner_cache = {
            'SHARED_REC': RecordOwner(False, 'attacker'),
            'OWNED_REC': RecordOwner(True, 'operator'),
        }

        uid = DockerSetupBase()._create_config_record(params, RECORD_NAME, 'FOLDER')
        self.assertEqual(uid, 'OWNED_REC')

    @patch('keepercommander.service.docker.setup_base.api.sync_down')
    @patch('keepercommander.service.docker.setup_base.record_management.add_record_to_folder')
    @patch('keepercommander.service.docker.setup_base.vault.KeeperRecord.create')
    @patch('keepercommander.service.docker.setup_base.utils.generate_aes_key', return_value=b'k' * 32)
    @patch('keepercommander.service.docker.setup_base.utils.generate_uid', return_value='NEW_REC')
    @patch('keepercommander.service.docker.setup_base.api.get_record')
    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    def test_creates_when_only_non_owned_match(
        self, printer, mock_get, _uid, _key, mock_create, _add, _sync
    ):
        shared = MagicMock()
        shared.title = RECORD_NAME
        mock_get.return_value = shared

        created = MagicMock()
        created.record_uid = 'NEW_REC'
        mock_create.return_value = created

        params = MagicMock(spec=KeeperParams)
        params.subfolder_record_cache = {'FOLDER': ['SHARED_REC']}
        params.record_owner_cache = {'SHARED_REC': RecordOwner(False, 'attacker')}

        uid = DockerSetupBase()._create_config_record(params, RECORD_NAME, 'FOLDER')
        self.assertEqual(uid, 'NEW_REC')
        printer.print_warning.assert_called()


class TestFindOwnedKsmApp(unittest.TestCase):
    def _app_entry(self, uid, title):
        return {
            'record_uid': uid,
            'version': 5,
            'data_unencrypted': json.dumps({'title': title, 'type': 'app'}).encode('utf-8'),
        }

    @patch('keepercommander.commands.ksm.KSMCommand._app_record_from_cache_entry', side_effect=lambda r: r)
    def test_prefers_owned_when_squat_present(self, _from_cache):
        params = MagicMock(spec=KeeperParams)
        params.record_cache = {
            'ATTACKER_APP': self._app_entry('ATTACKER_APP', APP_NAME),
            'OWNED_APP': self._app_entry('OWNED_APP', APP_NAME),
        }
        params.record_owner_cache = {
            'ATTACKER_APP': RecordOwner(False, 'attacker'),
            'OWNED_APP': RecordOwner(True, 'operator'),
        }

        rec = DockerSetupBase._find_owned_ksm_app_by_title(params, APP_NAME)
        self.assertEqual(rec['record_uid'], 'OWNED_APP')

    @patch('keepercommander.commands.ksm.KSMCommand._app_record_from_cache_entry', side_effect=lambda r: r)
    def test_returns_none_for_non_owned_only(self, _from_cache):
        params = MagicMock(spec=KeeperParams)
        params.record_cache = {
            'ATTACKER_APP': self._app_entry('ATTACKER_APP', APP_NAME),
        }
        params.record_owner_cache = {
            'ATTACKER_APP': RecordOwner(False, 'attacker'),
        }

        self.assertIsNone(DockerSetupBase._find_owned_ksm_app_by_title(params, APP_NAME))


class TestCreateKsmAppOwnership(unittest.TestCase):
    @patch('keepercommander.service.docker.setup_base.api.sync_down')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.add_new_v5_app')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.get_app_record')
    @patch.object(DockerSetupBase, '_find_owned_ksm_app_by_title')
    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    def test_force_creates_when_squat_present(
        self, printer, mock_find_owned, mock_get_app, mock_add, _sync
    ):
        owned_after_create = {'record_uid': 'NEW_OWNED_APP'}
        mock_find_owned.side_effect = [None, owned_after_create]
        mock_get_app.return_value = {'record_uid': 'ATTACKER_APP'}

        uid = DockerSetupBase()._create_ksm_app(MagicMock(spec=KeeperParams), APP_NAME)

        self.assertEqual(uid, 'NEW_OWNED_APP')
        mock_add.assert_called_once()
        self.assertTrue(mock_add.call_args.kwargs.get('force_to_add'))
        printer.print_warning.assert_called()


class TestIntegrationFolderLookupOwnership(unittest.TestCase):
    def test_find_folder_uid_by_name_skips_non_owned(self):
        from keepercommander.service.commands.integrations.slack_app_setup import (
            SlackAppSetupCommand,
        )

        params = MagicMock(spec=KeeperParams)
        params.user = 'operator@corp.example'
        params.shared_folder_cache = {
            'ATTACKER_SF': {
                'name': FOLDER_NAME,
                'owner_username': 'mallory@corp.example',
            },
            'OWNED_SF': {
                'name': FOLDER_NAME,
                'owner_username': 'operator@corp.example',
            },
        }

        self.assertEqual(
            SlackAppSetupCommand()._find_folder_uid_by_name(params, FOLDER_NAME),
            'OWNED_SF',
        )

    def test_find_folder_uid_by_name_returns_none_for_squat_only(self):
        from keepercommander.service.commands.integrations.slack_app_setup import (
            SlackAppSetupCommand,
        )

        params = MagicMock(spec=KeeperParams)
        params.user = 'operator@corp.example'
        params.shared_folder_cache = {
            'ATTACKER_SF': {
                'name': FOLDER_NAME,
                'owner_username': 'mallory@corp.example',
            },
        }

        self.assertIsNone(
            SlackAppSetupCommand()._find_folder_uid_by_name(params, FOLDER_NAME)
        )


if __name__ == '__main__':
    unittest.main()
