"""Tests for `pam cloud generate-credentials` (PAMCloudGenerateCredentialsCommand)."""

import base64
import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

from keepercommander import crypto, vault
from keepercommander.commands.pam_cloud.pam_cloud_credentials import (
    PAMCloudGenerateCredentialsCommand,
)
from keepercommander.error import CommandError

MODULE = 'keepercommander.commands.pam_cloud.pam_cloud_credentials'


def _encrypt_for_sender(sender_public_key_b64, payload_dict):
    """Mirror the gateway's side of the ECIES round trip for a fake response."""
    pub_bytes = base64.urlsafe_b64decode(sender_public_key_b64 + '==')
    pub_key = crypto.load_ec_public_key(pub_bytes)
    encrypted = crypto.encrypt_ec(json.dumps(payload_dict).encode('utf-8'), pub_key)
    return base64.b64encode(encrypted).decode('ascii')


def _make_cloud_record(record_uid='res-uid-1', title='My AWS Resource'):
    record = vault.TypedRecord()
    record.record_uid = record_uid
    record.type_name = 'pamCloudResource'
    record.title = title
    return record


def _grant_response(inputs, provider='aws'):
    credential_record = {
        'record_type': 'pamUser',
        'title': 'Temporary AWS access token - alice@example.com',
        'fields': [
            {'type': 'login', 'value': 'alice@example.com'},
            {'type': 'password', 'value': ''},
            {'type': 'secret', 'label': 'privatePEMKey',
             'value': json.dumps({'accessKeyId': 'ASIAEXAMPLE', 'secretAccessKey': 'shh',
                                  'sessionToken': 'shh-too'})},
            {'type': 'text', 'label': 'Provider', 'value': provider},
        ],
        'notes': 'Short-lived AWS credentials. Do not share.',
    }
    encrypted_record = _encrypt_for_sender(inputs['senderPublicKey'], credential_record)
    return {
        'success': True,
        'provider': provider,
        'expiration': '2026-10-01T12:00:00+00:00',
        'encrypted_record': encrypted_record,
        'encrypted_revocation': 'opaque-blob-commander-never-touches',
    }


def _make_params(user='alice@example.com'):
    params = MagicMock()
    params.user = user
    return params


class TestPAMCloudGenerateCredentials(unittest.TestCase):

    def setUp(self):
        self.record = _make_cloud_record()
        self.resolve_patcher = patch(f'{MODULE}.resolve_pam_record', return_value=self.record)
        self.resolve_patcher.start()
        self.addCleanup(self.resolve_patcher.stop)

        self.config_patcher = patch(f'{MODULE}._resolve_config_uid', return_value='cfg-uid-1')
        self.config_patcher.start()
        self.addCleanup(self.config_patcher.stop)

        self.cmd = PAMCloudGenerateCredentialsCommand()

    def test_get_parser(self):
        parser = self.cmd.get_parser()
        self.assertIsNotNone(parser)
        self.assertEqual('pam cloud generate-credentials', parser.prog)

    def test_happy_path_masks_output_and_does_not_save_by_default(self):
        params = _make_params()

        def dispatch(_params, gateway_action, **_kw):
            self.assertEqual('rm-grant-temporary-access-token', gateway_action.action)
            self.assertEqual('alice@example.com', gateway_action.inputs['username'])
            self.assertEqual('res-uid-1', gateway_action.inputs['resourceUid'])
            self.assertEqual('cfg-uid-1', gateway_action.inputs['configurationUid'])
            return _grant_response(gateway_action.inputs)

        with patch(f'{MODULE}.dispatch_streamed_access_elevation_action', side_effect=dispatch), \
                patch(f'{MODULE}.create_record_in_folder') as mock_save:
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.cmd.execute(params, record='res-uid-1')

        output = buf.getvalue()
        self.assertIn('**********', output)
        self.assertNotIn('shh', output)
        self.assertIn('Not saved', output)
        mock_save.assert_not_called()

    def test_duration_seconds_forwarded(self):
        params = _make_params()
        captured = {}

        def dispatch(_params, gateway_action, **_kw):
            captured['inputs'] = gateway_action.inputs
            return _grant_response(gateway_action.inputs)

        with patch(f'{MODULE}.dispatch_streamed_access_elevation_action', side_effect=dispatch):
            with redirect_stdout(io.StringIO()):
                self.cmd.execute(params, record='res-uid-1', duration_seconds=7200)

        self.assertEqual(7200, captured['inputs']['durationSeconds'])

    def test_save_record_persists_pam_user_record(self):
        params = _make_params()

        def dispatch(_params, gateway_action, **_kw):
            return _grant_response(gateway_action.inputs)

        saved_records = []

        def fake_create_record_in_folder(_params, record, _folder_uid, command=None):
            record.record_uid = 'new-record-uid'
            saved_records.append(record)

        with patch(f'{MODULE}.dispatch_streamed_access_elevation_action', side_effect=dispatch), \
                patch(f'{MODULE}.resolve_access_user_save_folder', return_value='folder-uid'), \
                patch(f'{MODULE}.create_record_in_folder', side_effect=fake_create_record_in_folder), \
                patch.object(type(params), 'sync_data', create=True):
            buf = io.StringIO()
            with redirect_stdout(buf):
                self.cmd.execute(params, record='res-uid-1', save_record=True)

        self.assertEqual(1, len(saved_records))
        saved = saved_records[0]
        self.assertEqual('pamUser', saved.type_name)
        login_values = [f.get_default_value() for f in saved.fields if f.type == 'login']
        self.assertTrue(login_values)
        self.assertIn('new-record-uid', buf.getvalue())

    def test_gateway_failure_raises_command_error(self):
        params = _make_params()

        with patch(f'{MODULE}.dispatch_streamed_access_elevation_action',
                  return_value={'success': False, 'error': 'No elevation group or role found.'}):
            with self.assertRaises(CommandError):
                self.cmd.execute(params, record='res-uid-1')

    def test_wrong_record_type_raises_command_error(self):
        params = _make_params()
        bad_record = _make_cloud_record()
        bad_record.type_name = 'pamMachine'
        self.resolve_patcher.stop()
        with patch(f'{MODULE}.resolve_pam_record', return_value=bad_record):
            with self.assertRaises(CommandError):
                self.cmd.execute(params, record='res-uid-1')
        self.resolve_patcher.start()

    def test_record_not_found_raises_command_error(self):
        params = _make_params()
        self.resolve_patcher.stop()
        with patch(f'{MODULE}.resolve_pam_record', return_value=None):
            with self.assertRaises(CommandError):
                self.cmd.execute(params, record='does-not-exist')
        self.resolve_patcher.start()

    def test_missing_encrypted_record_raises_command_error(self):
        params = _make_params()
        with patch(f'{MODULE}.dispatch_streamed_access_elevation_action',
                  return_value={'success': True, 'provider': 'aws'}):
            with self.assertRaises(CommandError):
                self.cmd.execute(params, record='res-uid-1')


if __name__ == '__main__':
    unittest.main()
