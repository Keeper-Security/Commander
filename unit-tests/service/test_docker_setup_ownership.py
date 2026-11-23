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
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from keepercommander import utils
from keepercommander.error import CommandError, KeeperApiError
from keepercommander.params import KeeperParams, RecordOwner
from keepercommander.service.docker.setup_base import DockerSetupBase


FOLDER_NAME = 'Commander Service Mode - Docker'
APP_NAME = 'Commander Service Mode - KSM App'
RECORD_NAME = 'Commander Service Mode Docker Config'


def _params(**kwargs):
    params = MagicMock(spec=KeeperParams)
    params.user = kwargs.get('user', 'operator@corp.example')
    params.account_uid_bytes = kwargs.get('account_uid_bytes', b'op-uid')
    params.folder_cache = kwargs.get('folder_cache', {})
    params.shared_folder_cache = kwargs.get('shared_folder_cache', {})
    params.record_cache = kwargs.get('record_cache', {})
    params.record_owner_cache = kwargs.get('record_owner_cache', {})
    params.subfolder_record_cache = kwargs.get('subfolder_record_cache', {})
    return params


def _folder(name):
    folder = MagicMock()
    folder.name = name
    return folder


def _app_entry(uid, title):
    return {
        'record_uid': uid,
        'version': 5,
        'data_unencrypted': json.dumps({'title': title, 'type': 'app'}).encode('utf-8'),
    }


class TestOwnershipHelpers(unittest.TestCase):
    def test_is_owned_record(self):
        params = _params(record_owner_cache={
            'OWNED': RecordOwner(True, 'operator'),
            'SHARED': RecordOwner(False, 'attacker'),
        })
        self.assertTrue(DockerSetupBase._is_owned_record(params, 'OWNED'))
        self.assertFalse(DockerSetupBase._is_owned_record(params, 'SHARED'))
        self.assertFalse(DockerSetupBase._is_owned_record(params, 'MISSING'))
        self.assertFalse(DockerSetupBase._is_owned_record(params, ''))

    def test_is_owned_shared_folder_by_username(self):
        params = _params(shared_folder_cache={
            'OWNED_SF': {'owner_username': 'operator@corp.example'},
            'SHARED_SF': {'owner_username': 'mallory@corp.example'},
        })
        self.assertTrue(DockerSetupBase._is_owned_shared_folder(params, 'OWNED_SF'))
        self.assertFalse(DockerSetupBase._is_owned_shared_folder(params, 'SHARED_SF'))
        self.assertFalse(DockerSetupBase._is_owned_shared_folder(params, 'MISSING'))

    def test_is_owned_shared_folder_by_account_uid(self):
        account_uid = utils.base64_url_encode(b'op-uid')
        params = _params(
            account_uid_bytes=b'op-uid',
            shared_folder_cache={
                'OWNED_SF': {'owner_account_uid': account_uid},
                'SHARED_SF': {'owner_account_uid': utils.base64_url_encode(b'other')},
            },
        )
        self.assertTrue(DockerSetupBase._is_owned_shared_folder(params, 'OWNED_SF'))
        self.assertFalse(DockerSetupBase._is_owned_shared_folder(params, 'SHARED_SF'))

    def test_is_owned_shared_folder_requires_account_uid_bytes(self):
        params = _params(
            account_uid_bytes=None,
            shared_folder_cache={
                'SF': {'owner_account_uid': utils.base64_url_encode(b'op-uid')},
            },
        )
        # Without session account_uid_bytes, do not guess ownership from uid alone.
        self.assertFalse(DockerSetupBase._is_owned_shared_folder(params, 'SF'))


class TestCreateSharedFolderOwnership(unittest.TestCase):
    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    def test_reuses_owned_folder_when_squat_also_present(self, _printer):
        params = _params(
            folder_cache={
                'ATTACKER_SF': _folder(FOLDER_NAME),
                'OWNED_SF': _folder(FOLDER_NAME),
            },
            shared_folder_cache={
                'ATTACKER_SF': {'owner_username': 'mallory@corp.example'},
                'OWNED_SF': {'owner_username': 'operator@corp.example'},
            },
        )
        self.assertEqual(DockerSetupBase()._create_shared_folder(params, FOLDER_NAME), 'OWNED_SF')

    @patch('keepercommander.service.docker.setup_base.api.sync_down')
    @patch.object(DockerSetupBase, '_add_owned_shared_folder', return_value='NEW_OWNED_SF')
    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    def test_creates_owned_folder_despite_squat_same_name(self, printer, mock_add, _sync):
        params = _params(
            folder_cache={'ATTACKER_SF': _folder(FOLDER_NAME)},
            shared_folder_cache={
                'ATTACKER_SF': {'owner_username': 'mallory@corp.example'},
            },
        )

        uid = DockerSetupBase()._create_shared_folder(params, FOLDER_NAME)

        self.assertEqual(uid, 'NEW_OWNED_SF')
        mock_add.assert_called_once_with(params, FOLDER_NAME)
        printer.print_warning.assert_called()

    @patch('keepercommander.service.docker.setup_base.api.communicate')
    @patch('keepercommander.service.docker.setup_base.api.generate_record_uid', return_value='DIRECT_SF')
    def test_add_owned_shared_folder_sends_folder_add(self, _uid, mock_communicate):
        params = _params()
        params.data_key = b'd' * 32

        uid = DockerSetupBase._add_owned_shared_folder(params, FOLDER_NAME)

        self.assertEqual(uid, 'DIRECT_SF')
        mock_communicate.assert_called_once()
        request = mock_communicate.call_args[0][1]
        self.assertEqual(request['command'], 'folder_add')
        self.assertEqual(request['folder_type'], 'shared_folder')
        self.assertEqual(request['folder_uid'], 'DIRECT_SF')
        self.assertTrue(request['manage_users'])
        self.assertTrue(request['manage_records'])

    def test_add_owned_shared_folder_requires_name_and_data_key(self):
        from keepercommander.error import CommandError

        with self.assertRaises(CommandError):
            DockerSetupBase._add_owned_shared_folder(_params(), '  ')

        params = _params()
        params.data_key = None
        with self.assertRaises(CommandError):
            DockerSetupBase._add_owned_shared_folder(params, FOLDER_NAME)


class TestCreateConfigRecordOwnership(unittest.TestCase):
    @patch('keepercommander.service.docker.setup_base.api.get_record')
    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    def test_reuses_owned_record(self, _printer, mock_get):
        owned = MagicMock(title=RECORD_NAME)
        shared = MagicMock(title=RECORD_NAME)
        mock_get.side_effect = lambda _p, uid: shared if uid == 'SHARED_REC' else owned

        params = _params(
            subfolder_record_cache={'FOLDER': ['SHARED_REC', 'OWNED_REC']},
            record_owner_cache={
                'SHARED_REC': RecordOwner(False, 'attacker'),
                'OWNED_REC': RecordOwner(True, 'operator'),
            },
        )
        self.assertEqual(
            DockerSetupBase()._create_config_record(params, RECORD_NAME, 'FOLDER'),
            'OWNED_REC',
        )

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
        mock_get.return_value = MagicMock(title=RECORD_NAME)
        created = MagicMock(record_uid='NEW_REC')
        mock_create.return_value = created

        params = _params(
            subfolder_record_cache={'FOLDER': ['SHARED_REC']},
            record_owner_cache={'SHARED_REC': RecordOwner(False, 'attacker')},
        )

        uid = DockerSetupBase()._create_config_record(params, RECORD_NAME, 'FOLDER')
        self.assertEqual(uid, 'NEW_REC')
        printer.print_warning.assert_called()


class TestFindOwnedKsmApp(unittest.TestCase):
    def test_prefers_owned_when_squat_present(self):
        params = _params(
            record_cache={
                'ATTACKER_APP': _app_entry('ATTACKER_APP', APP_NAME),
                'OWNED_APP': _app_entry('OWNED_APP', APP_NAME),
            },
            record_owner_cache={
                'ATTACKER_APP': RecordOwner(False, 'attacker'),
                'OWNED_APP': RecordOwner(True, 'operator'),
            },
        )
        rec = DockerSetupBase._find_owned_ksm_app_by_title(params, APP_NAME)
        self.assertEqual(rec['record_uid'], 'OWNED_APP')

    def test_returns_none_for_non_owned_only(self):
        params = _params(
            record_cache={'ATTACKER_APP': _app_entry('ATTACKER_APP', APP_NAME)},
            record_owner_cache={'ATTACKER_APP': RecordOwner(False, 'attacker')},
        )
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
        mock_find_owned.side_effect = [None, {'record_uid': 'NEW_OWNED_APP'}]
        mock_get_app.return_value = {'record_uid': 'ATTACKER_APP'}

        uid = DockerSetupBase()._create_ksm_app(_params(), APP_NAME)

        self.assertEqual(uid, 'NEW_OWNED_APP')
        self.assertTrue(mock_add.call_args.kwargs.get('force_to_add'))
        printer.print_warning.assert_called()

    @patch('keepercommander.service.docker.setup_base.KSMCommand.get_app_record')
    @patch.object(DockerSetupBase, '_find_owned_ksm_app_by_title', return_value=None)
    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    def test_reuses_owned_app_from_get_app_record_fallback(
        self, _printer, _find_owned, mock_get_app
    ):
        mock_get_app.return_value = {'record_uid': 'OWNED_NSF_APP'}
        params = _params(record_owner_cache={
            'OWNED_NSF_APP': RecordOwner(True, 'operator'),
        })

        uid = DockerSetupBase()._create_ksm_app(params, APP_NAME)
        self.assertEqual(uid, 'OWNED_NSF_APP')


class TestCreateClientDevice(unittest.TestCase):
    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.get_app_info')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.add_client')
    @patch('keepercommander.service.docker.setup_base.uuid.uuid4')
    def test_duplicate_default_client_name_retries_with_unique_name(
        self, mock_uuid4, mock_add_client, mock_get_app_info, mock_printer
    ):
        mock_uuid4.return_value.hex = 'deadbeef01234567'
        mock_get_app_info.return_value = [SimpleNamespace(clients=[])]
        mock_add_client.side_effect = [
            KeeperApiError('duplicate_app_client_name', 'duplicate_app_client_name'),
            [{'config': 'generated-config'}],
        ]

        result = DockerSetupBase()._create_client_device(
            _params(), 'APP_UID', APP_NAME
        )

        self.assertEqual(result, 'generated-config')
        self.assertEqual(mock_add_client.call_count, 2)
        self.assertEqual(
            mock_add_client.call_args_list[0].kwargs['client_name'],
            'Commander Service Mode - KSM App Client',
        )
        self.assertEqual(
            mock_add_client.call_args_list[1].kwargs['client_name'],
            'Commander Service Mode - KSM App Client deadbeef',
        )
        mock_printer.print_warning.assert_called_once()
        mock_printer.print_success.assert_called_once_with(
            'Client device created successfully'
        )

    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.get_app_info')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.add_client')
    @patch('keepercommander.service.docker.setup_base.uuid.uuid4')
    def test_existing_default_client_uses_verified_unique_name(
        self, mock_uuid4, mock_add_client, mock_get_app_info, _mock_printer
    ):
        mock_uuid4.return_value.hex = 'deadbeef01234567'
        mock_get_app_info.return_value = [
            SimpleNamespace(clients=[
                SimpleNamespace(id='Commander Service Mode - KSM App Client')
            ])
        ]
        mock_add_client.return_value = [{'config': 'generated-config'}]

        result = DockerSetupBase()._create_client_device(
            _params(), 'APP_UID', APP_NAME
        )

        self.assertEqual(result, 'generated-config')
        mock_add_client.assert_called_once()
        self.assertEqual(
            mock_add_client.call_args.kwargs['client_name'],
            'Commander Service Mode - KSM App Client deadbeef',
        )

    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.get_app_info')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.add_client')
    def test_duplicate_response_with_visible_client_does_not_retry(
        self, mock_add_client, mock_get_app_info, _mock_printer
    ):
        client_name = 'Commander Service Mode - KSM App Client'
        mock_get_app_info.side_effect = [
            [SimpleNamespace(clients=[])],
            [SimpleNamespace(clients=[SimpleNamespace(id=client_name)])],
        ]
        mock_add_client.side_effect = KeeperApiError(
            'duplicate_app_client_name', 'duplicate_app_client_name'
        )

        with self.assertRaises(CommandError) as ctx:
            DockerSetupBase()._create_client_device(_params(), 'APP_UID', APP_NAME)

        self.assertIn('avoid creating a duplicate client device', ctx.exception.message)
        mock_add_client.assert_called_once()
        self.assertEqual(mock_get_app_info.call_count, 2)

    @patch('keepercommander.service.docker.setup_base.DockerSetupPrinter')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.get_app_info')
    @patch('keepercommander.service.docker.setup_base.KSMCommand.add_client')
    @patch('keepercommander.service.docker.setup_base.uuid.uuid4')
    def test_duplicate_on_retry_checks_state_and_stops(
        self, mock_uuid4, mock_add_client, mock_get_app_info, _mock_printer
    ):
        mock_uuid4.return_value.hex = 'deadbeef01234567'
        retry_name = 'Commander Service Mode - KSM App Client deadbeef'
        mock_get_app_info.side_effect = [
            [SimpleNamespace(clients=[])],
            [SimpleNamespace(clients=[])],
            [SimpleNamespace(clients=[SimpleNamespace(id=retry_name)])],
        ]
        mock_add_client.side_effect = [
            KeeperApiError('duplicate_app_client_name', 'duplicate_app_client_name'),
            KeeperApiError('duplicate_app_client_name', 'duplicate_app_client_name'),
        ]

        with self.assertRaises(CommandError) as ctx:
            DockerSetupBase()._create_client_device(_params(), 'APP_UID', APP_NAME)

        self.assertIn('exists after the retry', ctx.exception.message)
        client_names = [
            call.kwargs['client_name'] for call in mock_add_client.call_args_list
        ]
        self.assertEqual(
            client_names,
            ['Commander Service Mode - KSM App Client', retry_name],
        )
        self.assertEqual(mock_add_client.call_count, 2)
        self.assertEqual(mock_get_app_info.call_count, 3)


class TestIntegrationLookupOwnership(unittest.TestCase):
    def test_find_folder_uid_by_name_skips_non_owned(self):
        from keepercommander.service.commands.integrations.slack_app_setup import (
            SlackAppSetupCommand,
        )

        params = _params(shared_folder_cache={
            'ATTACKER_SF': {
                'name': FOLDER_NAME,
                'owner_username': 'mallory@corp.example',
            },
            'OWNED_SF': {
                'name': FOLDER_NAME,
                'owner_username': 'operator@corp.example',
            },
        })
        self.assertEqual(
            SlackAppSetupCommand()._find_folder_uid_by_name(params, FOLDER_NAME),
            'OWNED_SF',
        )

    def test_find_folder_uid_by_name_returns_none_for_squat_only(self):
        from keepercommander.service.commands.integrations.slack_app_setup import (
            SlackAppSetupCommand,
        )

        params = _params(shared_folder_cache={
            'ATTACKER_SF': {
                'name': FOLDER_NAME,
                'owner_username': 'mallory@corp.example',
            },
        })
        self.assertIsNone(
            SlackAppSetupCommand()._find_folder_uid_by_name(params, FOLDER_NAME)
        )

    @patch('keepercommander.service.commands.integrations.integration_setup_base.api.get_record')
    def test_find_record_in_folder_skips_non_owned(self, mock_get):
        from keepercommander.service.commands.integrations.slack_app_setup import (
            SlackAppSetupCommand,
        )

        owned = MagicMock(title=RECORD_NAME)
        shared = MagicMock(title=RECORD_NAME)
        mock_get.side_effect = lambda _p, uid: shared if uid == 'SHARED_REC' else owned

        params = _params(
            subfolder_record_cache={'FOLDER': ['SHARED_REC', 'OWNED_REC']},
            record_owner_cache={
                'SHARED_REC': RecordOwner(False, 'attacker'),
                'OWNED_REC': RecordOwner(True, 'operator'),
            },
        )
        self.assertEqual(
            SlackAppSetupCommand()._find_record_in_folder(params, 'FOLDER', RECORD_NAME),
            'OWNED_REC',
        )

    def test_gchat_find_folder_uid_by_name_skips_non_owned(self):
        from keepercommander.service.commands.integrations.gchat_app_setup import (
            GChatAppSetupCommand,
        )

        params = _params(shared_folder_cache={
            'ATTACKER_SF': {
                'name': FOLDER_NAME,
                'owner_username': 'mallory@corp.example',
            },
            'OWNED_SF': {
                'name': FOLDER_NAME,
                'owner_username': 'operator@corp.example',
            },
        })
        self.assertEqual(
            GChatAppSetupCommand()._find_folder_uid_by_name(params, FOLDER_NAME),
            'OWNED_SF',
        )

    def test_gchat_find_folder_uid_by_name_returns_none_for_squat_only(self):
        from keepercommander.service.commands.integrations.gchat_app_setup import (
            GChatAppSetupCommand,
        )

        params = _params(shared_folder_cache={
            'ATTACKER_SF': {
                'name': FOLDER_NAME,
                'owner_username': 'mallory@corp.example',
            },
        })
        self.assertIsNone(
            GChatAppSetupCommand()._find_folder_uid_by_name(params, FOLDER_NAME)
        )

    @patch('keepercommander.service.commands.integrations.integration_setup_base.api.get_record')
    def test_gchat_find_record_in_folder_skips_non_owned(self, mock_get):
        from keepercommander.service.commands.integrations.gchat_app_setup import (
            GChatAppSetupCommand,
        )

        owned = MagicMock(title=RECORD_NAME)
        shared = MagicMock(title=RECORD_NAME)
        mock_get.side_effect = lambda _p, uid: shared if uid == 'SHARED_REC' else owned

        params = _params(
            subfolder_record_cache={'FOLDER': ['SHARED_REC', 'OWNED_REC']},
            record_owner_cache={
                'SHARED_REC': RecordOwner(False, 'attacker'),
                'OWNED_REC': RecordOwner(True, 'operator'),
            },
        )
        self.assertEqual(
            GChatAppSetupCommand()._find_record_in_folder(params, 'FOLDER', RECORD_NAME),
            'OWNED_REC',
        )


if __name__ == '__main__':
    unittest.main()
