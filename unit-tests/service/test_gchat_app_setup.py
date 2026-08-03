import json
import os
import tempfile
import unittest

from keepercommander.service.commands.integrations.gchat_app_setup import GChatAppSetupCommand
from keepercommander.service.docker import GChatConfig, GChatConstants


def _valid_service_account(**overrides):
    data = {
        'type': GChatConstants.SERVICE_ACCOUNT_TYPE,
        'project_id': 'my-gcp-project',
        'private_key': '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n',
        'client_email': 'bot@my-gcp-project.iam.gserviceaccount.com',
    }
    data.update(overrides)
    return data


class TestGChatAppSetupValidation(unittest.TestCase):
    def setUp(self):
        self.cmd = GChatAppSetupCommand()

    def test_command_naming(self):
        self.assertEqual(self.cmd.get_integration_name(), GChatConstants.INTEGRATION_NAME)
        self.assertEqual(self.cmd.get_integration_display_name(), GChatConstants.DISPLAY_NAME)
        self.assertEqual(self.cmd.get_command_name(), 'gchat-app-setup')
        self.assertEqual(self.cmd.get_record_env_key(), 'GCHAT_RECORD')
        self.assertEqual(self.cmd.get_docker_image(), 'keeper/gchat-app:latest')
        self.assertEqual(
            self.cmd.get_integration_config_marker_field(),
            GChatConstants.FIELD_SERVICE_ACCOUNT_JSON,
        )
        self.assertEqual(self.cmd.get_parser().prog, 'gchat-app-setup')

    def test_load_service_account_requires_path(self):
        data, error = self.cmd._load_service_account_json('')
        self.assertIsNone(data)
        self.assertIn('required', error.lower())

    def test_load_service_account_file_not_found(self):
        data, error = self.cmd._load_service_account_json('/tmp/does-not-exist-gchat.json')
        self.assertIsNone(data)
        self.assertIn('not found', error.lower())

    def test_load_service_account_rejects_inline_json(self):
        data, error = self.cmd._load_service_account_json(json.dumps(_valid_service_account()))
        self.assertIsNone(data)
        self.assertIn('not found', error.lower())

    def test_load_service_account_invalid_type(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
            json.dump(_valid_service_account(type='user'), handle)
            path = handle.name
        try:
            data, error = self.cmd._load_service_account_json(path)
        finally:
            os.unlink(path)
        self.assertIsNone(data)
        self.assertIn('service_account', error)

    def test_load_service_account_missing_fields(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
            json.dump({'type': 'service_account'}, handle)
            path = handle.name
        try:
            data, error = self.cmd._load_service_account_json(path)
        finally:
            os.unlink(path)
        self.assertIsNone(data)
        self.assertIn('missing', error.lower())

    def test_load_service_account_from_file(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
            json.dump(_valid_service_account(), handle)
            path = handle.name
        try:
            data, error = self.cmd._load_service_account_json(path)
        finally:
            os.unlink(path)
        self.assertIsNone(error)
        self.assertEqual(data['project_id'], 'my-gcp-project')

    def test_load_service_account_invalid_json_file(self):
        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as handle:
            handle.write('{not-json')
            path = handle.name
        try:
            data, error = self.cmd._load_service_account_json(path)
        finally:
            os.unlink(path)
        self.assertIsNone(data)
        self.assertIn('invalid service account json', error.lower())

    def test_normalize_subscription_short_id(self):
        value, error = self.cmd._normalize_subscription_id('keeper-chat-events')
        self.assertIsNone(error)
        self.assertEqual(value, 'keeper-chat-events')

    def test_normalize_subscription_full_resource_name(self):
        value, error = self.cmd._normalize_subscription_id(
            'projects/my-gcp-project/subscriptions/keeper-chat-events'
        )
        self.assertIsNone(error)
        self.assertEqual(value, 'keeper-chat-events')

    def test_normalize_subscription_missing(self):
        value, error = self.cmd._normalize_subscription_id('')
        self.assertIsNone(value)
        self.assertIn('required', error.lower())

    def test_normalize_subscription_invalid(self):
        value, error = self.cmd._normalize_subscription_id('ab')
        self.assertIsNone(value)
        self.assertIn('invalid', error.lower())

    def test_normalize_topic_full_resource_name(self):
        value, error = self.cmd._normalize_topic_id(
            'projects/my-gcp-project/topics/keeper-chat-topic'
        )
        self.assertIsNone(error)
        self.assertEqual(value, 'keeper-chat-topic')

    def test_normalize_topic_missing(self):
        value, error = self.cmd._normalize_topic_id('')
        self.assertIsNone(value)
        self.assertIn('required', error.lower())

    def test_space_id_validation(self):
        self.assertTrue(self.cmd._is_valid_space_id('spaces/AAAA'))
        self.assertFalse(self.cmd._is_valid_space_id('spaces/'))
        self.assertFalse(self.cmd._is_valid_space_id('AAAA'))
        self.assertFalse(self.cmd._is_valid_space_id(''))

    def test_build_record_custom_fields(self):
        config = GChatConfig(
            google_service_account_json='{"type":"service_account"}',
            google_project_id='my-gcp-project',
            google_subscription_id='keeper-chat-events',
            google_topic_id='keeper-chat-topic',
            chat_approvals_space_id='spaces/AAAA',
            chat_command_request_record_id='1',
            chat_command_request_folder_id='2',
            chat_command_one_time_share_id='3',
            pedm_enabled=True,
            pedm_polling_interval=60,
            device_approval_enabled=False,
            device_approval_polling_interval=120,
        )
        fields = {
            field.label: field.get_default_value()
            for field in self.cmd.build_record_custom_fields(config)
        }
        self.assertEqual(
            fields[GChatConstants.FIELD_SERVICE_ACCOUNT_JSON],
            '{"type":"service_account"}',
        )
        self.assertEqual(fields[GChatConstants.FIELD_PROJECT_ID], 'my-gcp-project')
        self.assertEqual(fields[GChatConstants.FIELD_SUBSCRIPTION_ID], 'keeper-chat-events')
        self.assertEqual(fields[GChatConstants.FIELD_TOPIC_ID], 'keeper-chat-topic')
        self.assertEqual(fields[GChatConstants.FIELD_APPROVALS_SPACE_ID], 'spaces/AAAA')
        self.assertEqual(fields[GChatConstants.FIELD_COMMAND_REQUEST_RECORD_ID], '1')
        self.assertEqual(fields[GChatConstants.FIELD_COMMAND_REQUEST_FOLDER_ID], '2')
        self.assertEqual(fields[GChatConstants.FIELD_COMMAND_ONE_TIME_SHARE_ID], '3')
        self.assertEqual(fields[GChatConstants.FIELD_PEDM_ENABLED], 'true')
        self.assertEqual(fields[GChatConstants.FIELD_PEDM_POLLING_INTERVAL], '60')
        self.assertEqual(fields[GChatConstants.FIELD_DEVICE_APPROVAL_ENABLED], 'false')


if __name__ == '__main__':
    unittest.main()
