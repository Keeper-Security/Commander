import json
import unittest
from unittest import mock

from keepercommander.commands.pam_import.delinea_access import apply_secret_grants, locate_record_uid
from keepercommander.error import CommandError
from keepercommander.importer.thycotic.pam.models import (
    AccessGrant, FindingLog, Principal, PrincipalKind, SecretGrantTarget,
)


class Folder:
    def __init__(self, name):
        self.name = name
        self.parent_uid = None


def _params():
    params = mock.Mock()
    params.user = 'owner@example.com'
    params.folder_cache = {
        'users': Folder('Linux - Users'),
        'resources': Folder('Linux - Resources'),
    }
    params.nested_share_folders = {}
    params.subfolder_record_cache = {
        'users': ['user-rec'],
        'resources': ['host-rec'],
    }
    params.nested_share_folder_records = {}
    params.record_cache = {
        'user-rec': {'data_unencrypted': json.dumps({'title': 'prod-box'})},
        'host-rec': {'data_unencrypted': json.dumps({'title': 'box.example'})},
    }
    params.nested_share_record_data = {}
    return params


def _target(role='content-manager', email='ada@example.com', title='prod-box'):
    principal = Principal(PrincipalKind.USER, 3, 'ada', email)
    return SecretGrantTarget(100, title, 'Linux', [AccessGrant(principal, role)])


class DelineaSecretGrantTest(unittest.TestCase):
    def test_locate_prefers_the_users_folder(self):
        params = _params()
        params.record_cache['host-rec'] = {'data_unencrypted': json.dumps({'title': 'prod-box'})}
        self.assertEqual(locate_record_uid(params, 'Linux', 'prod-box'), 'user-rec')
        params = _params()
        self.assertEqual(locate_record_uid(params, 'Linux', 'box.example'), 'host-rec')
        self.assertIsNone(locate_record_uid(params, 'Linux', 'missing'))

    def test_classic_grant_uses_share_record_flags(self):
        params = _params()
        findings = FindingLog()
        request = object()
        with mock.patch('keepercommander.commands.pam_import.delinea_access.api.sync_down'), \
                mock.patch('keepercommander.commands.register.ShareRecordCommand.prep_request',
                           return_value=request) as prep, \
                mock.patch('keepercommander.commands.register.ShareRecordCommand.send_requests') as send:
            applied = apply_secret_grants(
                params, [_target(), _target(role='requestor', email='bea@example.com', title='missing')],
                False, lambda principal: principal.email, findings)
        self.assertEqual(applied, 1)
        prep.assert_called_once()
        kwargs = prep.call_args.args[1]
        self.assertEqual(kwargs['record'], 'user-rec')
        self.assertEqual(kwargs['email'], ['ada@example.com'])
        self.assertTrue(kwargs['can_edit'])
        self.assertFalse(kwargs['can_share'])
        send.assert_called_once()
        actions = [item.action for item in findings]
        self.assertIn('Imported record was not found', actions)

    def test_classic_failure_does_not_stop_the_next_grant(self):
        params = _params()
        params.record_cache['other'] = {'data_unencrypted': json.dumps({'title': 'other'})}
        params.subfolder_record_cache['users'] = ['user-rec', 'other']
        findings = FindingLog()
        second = SecretGrantTarget(
            2, 'other', 'Linux',
            [AccessGrant(Principal(PrincipalKind.USER, 4, 'bea', 'bea@example.com'), 'viewer')])
        with mock.patch('keepercommander.commands.pam_import.delinea_access.api.sync_down'), \
                mock.patch('keepercommander.commands.register.ShareRecordCommand.prep_request',
                           return_value=object()), \
                mock.patch('keepercommander.commands.register.ShareRecordCommand.send_requests',
                           side_effect=[CommandError('share', 'denied'), None]):
            applied = apply_secret_grants(
                params, [_target(), second], False, lambda principal: principal.email, findings)
        self.assertEqual(applied, 1)
        self.assertEqual(len(findings), 1)

    def test_classic_grant_also_shares_the_pam_resource(self):
        params = _params()
        findings = FindingLog()
        target = _target()
        target.resource_title = 'box.example'
        with mock.patch('keepercommander.commands.pam_import.delinea_access.api.sync_down'), \
                mock.patch('keepercommander.commands.register.ShareRecordCommand.prep_request',
                           return_value=object()) as prep, \
                mock.patch('keepercommander.commands.register.ShareRecordCommand.send_requests'):
            applied = apply_secret_grants(
                params, [target], False, lambda principal: principal.email, findings)
        self.assertEqual(applied, 2)
        shared = [call.args[1]['record'] for call in prep.call_args_list]
        self.assertEqual(shared, ['user-rec', 'host-rec'])

    def test_nsf_grant_uses_share_record_v3(self):
        params = _params()
        findings = FindingLog()
        with mock.patch('keepercommander.commands.pam_import.delinea_access.api.sync_down'), \
                mock.patch('keepercommander.nested_share_folder.record_api.share_record_v3',
                           return_value={'success': True}) as share:
            applied = apply_secret_grants(
                params, [_target(email='owner@example.com'), _target()],
                True, lambda principal: principal.email, findings)
        self.assertEqual(applied, 1)
        self.assertEqual(len(findings), 0)
        share.assert_called_once()
        self.assertEqual(share.call_args.args[1], 'user-rec')
        self.assertEqual(share.call_args.args[2], 'ada@example.com')


if __name__ == '__main__':
    unittest.main()
