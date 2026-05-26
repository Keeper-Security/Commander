"""Unit tests for the Commander CNAPP helper and command surface.

Strategy: every test patches `_post_request_to_router` so we can assert on what the
helper sends to krouter and feed deterministic responses back into the commands. We
deliberately stay one layer below the network — no socket calls, no real protobuf
encryption — but we exercise the real proto serializers so wire-format breakage
surfaces here.
"""
import base64
import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

# Pre-load `keepercommander.commands.record` before anything else from the
# `keepercommander.commands` package. There is a pre-existing record <-> ksm
# circular import that only resolves when `record` is loaded first; running this
# file in isolation (e.g. `pytest unit-tests/pam/test_cnapp.py`) would otherwise
# hit the cycle via `discoveryrotation -> ksm -> record -> ksm`.
import keepercommander.commands.record  # noqa: F401, E402 - intentional import-order guard

from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from keeper_secrets_manager_core.utils import bytes_to_base64  # noqa: E402

from keepercommander.commands.pam import cnapp_helper  # noqa: E402
from keepercommander.commands.pam import cnapp_commands  # noqa: E402
from keepercommander.error import CommandError  # noqa: E402
from keepercommander.proto import cnapp_pb2  # noqa: E402


# Sample 16-byte UIDs as base64url (the format Commander callers pass in).
NETWORK_UID = 'AAAAAAAAAAAAAAAAAAAAAA'  # 16 zero bytes
RECORD_UID = 'AQEBAQEBAQEBAQEBAQEBAQ'  # 16 0x01 bytes
CONFIG_RECORD_UID = 'AgICAgICAgICAgICAgICAg'


def _mock_params():
    """Minimal KeeperParams stand-in — the helpers only use it to drive the router_helper
    transport, which is mocked here, so a MagicMock is enough."""
    return MagicMock()


# ---------------------------------------------------------------------------
# cnapp_helper: enum parsing
# ---------------------------------------------------------------------------

class TestEnumParsing(unittest.TestCase):
    """provider_from_name and action_from_name must accept short or full names and
    reject unknown values with a helpful error listing valid options."""

    def test_provider_short_name(self):
        self.assertEqual(cnapp_helper.provider_from_name('wiz'), cnapp_pb2.CNAPP_PROVIDER_WIZ)

    def test_provider_full_name_case_insensitive(self):
        self.assertEqual(
            cnapp_helper.provider_from_name('cnapp_provider_wiz'),
            cnapp_pb2.CNAPP_PROVIDER_WIZ,
        )

    def test_provider_empty_returns_unspecified(self):
        self.assertEqual(cnapp_helper.provider_from_name(''), cnapp_pb2.CNAPP_PROVIDER_UNSPECIFIED)

    def test_provider_unknown_raises_with_valid_options(self):
        with self.assertRaises(ValueError) as ctx:
            cnapp_helper.provider_from_name('aws')
        self.assertIn('WIZ', str(ctx.exception).upper())

    def test_action_short_name(self):
        self.assertEqual(
            cnapp_helper.action_from_name('rotate_credentials'),
            cnapp_pb2.ROTATE_CREDENTIALS,
        )

    def test_action_hyphenated(self):
        # The CLI accepts hyphens (`--action remove-standing-privilege`) for ergonomics;
        # helper must normalize before resolving the enum.
        self.assertEqual(
            cnapp_helper.action_from_name('remove-standing-privilege'),
            cnapp_pb2.REMOVE_STANDING_PRIVILEGE,
        )

    def test_action_unknown_raises(self):
        with self.assertRaises(ValueError):
            cnapp_helper.action_from_name('teleport')

    def test_action_empty_returns_unspecified(self):
        self.assertEqual(cnapp_helper.action_from_name(''), cnapp_pb2.UNSPECIFIED)


# ---------------------------------------------------------------------------
# cnapp_helper: configuration endpoints
# ---------------------------------------------------------------------------

class TestConfigurationHelpers(unittest.TestCase):
    """Each helper must dispatch to the right krouter path with a correctly populated
    protobuf request and return the typed response."""

    def setUp(self):
        self.params = _mock_params()

    def _patch_post(self, return_value=None):
        return patch.object(cnapp_helper, '_post_request_to_router', return_value=return_value)

    def test_set_configuration_dispatches_with_full_payload(self):
        expected_response = cnapp_pb2.CnappConfiguration(
            clientId='abc', apiEndpointUrl='https://api.wiz.io')
        with self._patch_post(return_value=expected_response) as post:
            result = cnapp_helper.set_cnapp_configuration(
                self.params,
                network_uid=NETWORK_UID,
                provider=cnapp_pb2.CNAPP_PROVIDER_WIZ,
                client_id='abc',
                client_secret='secret',
                api_endpoint_url='https://api.wiz.io',
                cnapp_config_record_uid=CONFIG_RECORD_UID,
            )
        self.assertIs(result, expected_response)
        args, kwargs = post.call_args
        self.assertEqual(args[1], 'cnapp/configuration/set')
        rq = kwargs['rq_proto']
        self.assertEqual(rq.provider, cnapp_pb2.CNAPP_PROVIDER_WIZ)
        self.assertEqual(rq.clientId, 'abc')
        self.assertEqual(rq.clientSecret, 'secret')
        self.assertEqual(rq.apiEndpointUrl, 'https://api.wiz.io')
        self.assertEqual(len(rq.networkUid), 16)
        self.assertEqual(len(rq.cnappConfigRecordUid), 16)
        self.assertIs(kwargs['rs_type'], cnapp_pb2.CnappConfiguration)

    def test_set_configuration_omits_empty_secret_to_keep_existing(self):
        """Edge case: passing '' for client_secret on set must leave the field blank in
        the request so krouter can splice in the previously stored secret."""
        with self._patch_post() as post:
            cnapp_helper.set_cnapp_configuration(
                self.params,
                network_uid=NETWORK_UID,
                provider=cnapp_pb2.CNAPP_PROVIDER_WIZ,
                client_id='abc',
                client_secret='',
                api_endpoint_url='https://api.wiz.io',
                cnapp_config_record_uid=CONFIG_RECORD_UID,
            )
        rq = post.call_args.kwargs['rq_proto']
        self.assertEqual(rq.clientSecret, '')

    def test_test_configuration_dispatches_to_test_endpoint(self):
        with self._patch_post() as post:
            cnapp_helper.test_cnapp_configuration(
                self.params,
                network_uid=NETWORK_UID,
                provider=cnapp_pb2.CNAPP_PROVIDER_WIZ,
                client_id='abc',
                client_secret='secret',
                api_endpoint_url='https://api.wiz.io',
            )
        self.assertEqual(post.call_args.args[1], 'cnapp/configuration/test')
        # test endpoint never persists, so it must not require / send config record UID
        self.assertEqual(post.call_args.kwargs['rq_proto'].cnappConfigRecordUid, b'')

    def test_test_encrypter_sets_url(self):
        with self._patch_post() as post:
            cnapp_helper.test_cnapp_encrypter(self.params, url_base_encrypter='https://encr.local')
        rq = post.call_args.kwargs['rq_proto']
        self.assertEqual(post.call_args.args[1], 'cnapp/configuration/test-encrypter')
        self.assertEqual(rq.urlBaseEncrypter, 'https://encr.local')

    def test_read_configuration_uses_read_endpoint(self):
        with self._patch_post(return_value=cnapp_pb2.CnappConfiguration()) as post:
            cnapp_helper.read_cnapp_configuration(
                self.params, network_uid=NETWORK_UID, provider=cnapp_pb2.CNAPP_PROVIDER_WIZ)
        self.assertEqual(post.call_args.args[1], 'cnapp/configuration/read')
        self.assertIs(post.call_args.kwargs['rs_type'], cnapp_pb2.CnappConfiguration)

    def test_delete_configuration_uses_delete_endpoint(self):
        with self._patch_post() as post:
            cnapp_helper.delete_cnapp_configuration(self.params, network_uid=NETWORK_UID)
        self.assertEqual(post.call_args.args[1], 'cnapp/configuration/delete')
        self.assertEqual(len(post.call_args.kwargs['rq_proto'].networkUid), 16)


# ---------------------------------------------------------------------------
# cnapp_helper: queue endpoints
# ---------------------------------------------------------------------------

class TestQueueHelpers(unittest.TestCase):
    def setUp(self):
        self.params = _mock_params()

    def _patch_post(self, return_value=None):
        return patch.object(cnapp_helper, '_post_request_to_router', return_value=return_value)

    def test_list_queue_with_status_filter(self):
        items = cnapp_pb2.CnappQueueListResponse(
            items=[cnapp_pb2.CnappQueueItem(cnappQueueId=42)])
        with self._patch_post(return_value=items) as post:
            response = cnapp_helper.list_cnapp_queue(
                self.params, network_uid=NETWORK_UID, status_filter=1)
        self.assertEqual(post.call_args.args[1], 'cnapp/queue')
        self.assertEqual(post.call_args.kwargs['rq_proto'].statusFilter, 1)
        self.assertEqual(response.items[0].cnappQueueId, 42)

    def test_list_queue_defaults_to_all_status(self):
        with self._patch_post(return_value=cnapp_pb2.CnappQueueListResponse()) as post:
            cnapp_helper.list_cnapp_queue(self.params, network_uid=NETWORK_UID)
        self.assertEqual(post.call_args.kwargs['rq_proto'].statusFilter, 0)

    def test_associate_record_dispatches(self):
        with self._patch_post() as post:
            cnapp_helper.associate_cnapp_record(
                self.params, cnapp_queue_id=7, record_uid=RECORD_UID)
        rq = post.call_args.kwargs['rq_proto']
        self.assertEqual(post.call_args.args[1], 'cnapp/queue/associate')
        self.assertEqual(rq.cnappQueueId, 7)
        self.assertEqual(len(rq.recordUid), 16)

    def test_remediate_forwards_optional_fields(self):
        with self._patch_post(return_value=cnapp_pb2.CnappRemediateResponse()) as post:
            cnapp_helper.remediate_cnapp_queue_item(
                self.params,
                cnapp_queue_id=3,
                action_type=cnapp_pb2.ROTATE_CREDENTIALS,
                provider=cnapp_pb2.CNAPP_PROVIDER_WIZ,
                cnapp_config_record_uid=CONFIG_RECORD_UID,
                resource_ref=RECORD_UID,
                pwd_complexity='{"len":24}',
                controller_uid='gateway-1',
                message_uid=RECORD_UID,
                group_name='Admins',
            )
        rq = post.call_args.kwargs['rq_proto']
        self.assertEqual(post.call_args.args[1], 'cnapp/queue/remediate')
        self.assertEqual(rq.cnappQueueId, 3)
        self.assertEqual(rq.actionType, cnapp_pb2.ROTATE_CREDENTIALS)
        self.assertEqual(rq.provider, cnapp_pb2.CNAPP_PROVIDER_WIZ)
        self.assertEqual(rq.pwdComplexity, '{"len":24}')
        self.assertEqual(rq.controllerUid, 'gateway-1')
        self.assertEqual(rq.groupName, 'Admins')

    def test_remediate_minimal_fields(self):
        """No optional fields — only queueId and actionType must be set on the wire."""
        with self._patch_post(return_value=cnapp_pb2.CnappRemediateResponse()) as post:
            cnapp_helper.remediate_cnapp_queue_item(
                self.params, cnapp_queue_id=9, action_type=cnapp_pb2.ROTATE_CREDENTIALS)
        rq = post.call_args.kwargs['rq_proto']
        self.assertEqual(rq.cnappQueueId, 9)
        self.assertEqual(rq.provider, 0)
        self.assertEqual(rq.pwdComplexity, '')
        self.assertEqual(rq.controllerUid, '')
        self.assertEqual(rq.groupName, '')

    def test_set_status_with_reason(self):
        with self._patch_post(return_value=cnapp_pb2.CnappSetStatusResponse(cnappQueueStatusId=3)) as post:
            response = cnapp_helper.set_cnapp_queue_status(
                self.params, cnapp_queue_id=11, cnapp_queue_status_id=3, reason='Manually resolved')
        self.assertEqual(post.call_args.args[1], 'cnapp/queue/set-status')
        self.assertEqual(post.call_args.kwargs['rq_proto'].reason, 'Manually resolved')
        self.assertEqual(response.cnappQueueStatusId, 3)

    def test_delete_queue_item_dispatches(self):
        with self._patch_post() as post:
            cnapp_helper.delete_cnapp_queue_item(self.params, cnapp_queue_id=11)
        self.assertEqual(post.call_args.args[1], 'cnapp/queue/delete')
        self.assertEqual(post.call_args.kwargs['rq_proto'].cnappQueueId, 11)


# ---------------------------------------------------------------------------
# cnapp_helper: error propagation
# ---------------------------------------------------------------------------

class TestHelperErrorPropagation(unittest.TestCase):
    """The router layer raises on RRC_!=OK; helpers must NOT swallow those errors."""

    def test_set_configuration_propagates_router_error(self):
        params = _mock_params()
        with patch.object(cnapp_helper, '_post_request_to_router',
                          side_effect=Exception('Credential validation failed: Unauthorized')):
            with self.assertRaises(Exception) as ctx:
                cnapp_helper.set_cnapp_configuration(
                    params,
                    network_uid=NETWORK_UID,
                    provider=cnapp_pb2.CNAPP_PROVIDER_WIZ,
                    client_id='abc',
                    client_secret='bad',
                    api_endpoint_url='https://api.wiz.io',
                    cnapp_config_record_uid=CONFIG_RECORD_UID,
                )
            self.assertIn('Credential validation failed', str(ctx.exception))


# ---------------------------------------------------------------------------
# cnapp_commands: status resolver
# ---------------------------------------------------------------------------

class TestStatusResolver(unittest.TestCase):

    def test_numeric_passes_through(self):
        self.assertEqual(cnapp_commands._resolve_status('1'), 1)
        self.assertEqual(cnapp_commands._resolve_status(2), 2)

    def test_zero_is_all(self):
        self.assertEqual(cnapp_commands._resolve_status('0'), 0)
        self.assertEqual(cnapp_commands._resolve_status(None), 0)
        self.assertEqual(cnapp_commands._resolve_status(''), 0)

    def test_named_status_case_insensitive(self):
        self.assertEqual(cnapp_commands._resolve_status('PENDING'), 1)
        self.assertEqual(cnapp_commands._resolve_status('in_progress'), 2)
        self.assertEqual(cnapp_commands._resolve_status('Resolved'), 3)

    def test_unknown_status_raises_command_error(self):
        with self.assertRaises(CommandError):
            cnapp_commands._resolve_status('flapping')


# ---------------------------------------------------------------------------
# cnapp_commands: end-to-end (helpers patched)
# ---------------------------------------------------------------------------

class TestConfigCommands(unittest.TestCase):
    def setUp(self):
        self.params = _mock_params()

    def _capture_stdout(self):
        buf = io.StringIO()
        return buf, redirect_stdout(buf)

    def test_config_set_calls_helper_with_resolved_provider(self):
        with patch.object(cnapp_commands.cnapp_helper, 'set_cnapp_configuration',
                          return_value=cnapp_pb2.CnappConfiguration(clientId='abc',
                                                                    apiEndpointUrl='https://api.wiz.io',
                                                                    provider=cnapp_pb2.CNAPP_PROVIDER_WIZ)) as helper:
            buf, ctx = self._capture_stdout()
            with ctx:
                cnapp_commands.PAMCnappConfigSetCommand().execute(
                    self.params,
                    network_uid=NETWORK_UID,
                    provider='wiz',
                    client_id='abc',
                    client_secret='secret',
                    api_endpoint_url='https://api.wiz.io',
                    cnapp_config_record_uid=CONFIG_RECORD_UID,
                )
        helper.assert_called_once()
        kwargs = helper.call_args.kwargs
        self.assertEqual(kwargs['provider'], cnapp_pb2.CNAPP_PROVIDER_WIZ)
        self.assertEqual(kwargs['client_secret'], 'secret')
        self.assertIn('saved', buf.getvalue().lower())

    def test_config_set_blank_secret_passes_through(self):
        """Edge case: the CLI must forward an empty secret unchanged so krouter can
        keep the existing value."""
        with patch.object(cnapp_commands.cnapp_helper, 'set_cnapp_configuration',
                          return_value=cnapp_pb2.CnappConfiguration()) as helper:
            with redirect_stdout(io.StringIO()):
                cnapp_commands.PAMCnappConfigSetCommand().execute(
                    self.params,
                    network_uid=NETWORK_UID,
                    provider='wiz',
                    client_id='abc',
                    client_secret='',  # explicit
                    api_endpoint_url='https://api.wiz.io',
                    cnapp_config_record_uid=CONFIG_RECORD_UID,
                )
        self.assertEqual(helper.call_args.kwargs['client_secret'], '')

    def test_config_set_invalid_provider_raises(self):
        with self.assertRaises(ValueError):
            cnapp_commands.PAMCnappConfigSetCommand().execute(
                self.params,
                network_uid=NETWORK_UID,
                provider='bogus',
                client_id='abc',
                client_secret='secret',
                api_endpoint_url='https://api.wiz.io',
                cnapp_config_record_uid=CONFIG_RECORD_UID,
            )

    def test_config_test_prints_success(self):
        with patch.object(cnapp_commands.cnapp_helper, 'test_cnapp_configuration', return_value=None):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappConfigTestCommand().execute(
                    self.params,
                    network_uid=NETWORK_UID,
                    provider='wiz',
                    client_id='abc',
                    client_secret='secret',
                    api_endpoint_url='https://api.wiz.io',
                )
            self.assertIn('validated', buf.getvalue().lower())

    def test_config_test_propagates_helper_error(self):
        with patch.object(cnapp_commands.cnapp_helper, 'test_cnapp_configuration',
                          side_effect=Exception('Credential validation failed: bad')):
            with self.assertRaises(Exception):
                cnapp_commands.PAMCnappConfigTestCommand().execute(
                    self.params,
                    network_uid=NETWORK_UID,
                    provider='wiz',
                    client_id='abc',
                    client_secret='bad',
                    api_endpoint_url='https://api.wiz.io',
                )

    def test_config_test_encrypter_success(self):
        with patch.object(cnapp_commands.cnapp_helper, 'test_cnapp_encrypter', return_value=None) as helper:
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappConfigTestEncrypterCommand().execute(
                    self.params, url='https://encr.local')
            helper.assert_called_once_with(self.params, url_base_encrypter='https://encr.local')
            self.assertIn('reachable', buf.getvalue().lower())

    def test_config_read_table_format(self):
        config = cnapp_pb2.CnappConfiguration(
            clientId='abc',
            apiEndpointUrl='https://api.wiz.io',
            provider=cnapp_pb2.CNAPP_PROVIDER_WIZ,
        )
        with patch.object(cnapp_commands.cnapp_helper, 'read_cnapp_configuration', return_value=config):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappConfigReadCommand().execute(
                    self.params, network_uid=NETWORK_UID, provider='wiz', format='table')
            output = buf.getvalue()
            self.assertIn('CNAPP Configuration', output)
            self.assertIn('https://api.wiz.io', output)

    def test_config_read_json_format(self):
        config = cnapp_pb2.CnappConfiguration(
            clientId='abc',
            apiEndpointUrl='https://api.wiz.io',
            provider=cnapp_pb2.CNAPP_PROVIDER_WIZ,
        )
        with patch.object(cnapp_commands.cnapp_helper, 'read_cnapp_configuration', return_value=config):
            buf = io.StringIO()
            with redirect_stdout(buf):
                result = cnapp_commands.PAMCnappConfigReadCommand().execute(
                    self.params, network_uid=NETWORK_UID, provider='wiz', format='json')
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload['clientId'], 'abc')
            self.assertEqual(payload['provider'], 'CNAPP_PROVIDER_WIZ')
            self.assertEqual(payload['apiEndpointUrl'], 'https://api.wiz.io')
            self.assertIsNone(result, 'JSON output is the channel — no value returned to the REPL')

    def test_config_read_handles_none_response(self):
        with patch.object(cnapp_commands.cnapp_helper, 'read_cnapp_configuration', return_value=None):
            self.assertIsNone(cnapp_commands.PAMCnappConfigReadCommand().execute(
                self.params, network_uid=NETWORK_UID, provider='wiz', format='table'))

    def test_config_delete_success(self):
        with patch.object(cnapp_commands.cnapp_helper, 'delete_cnapp_configuration', return_value=None) as helper:
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappConfigDeleteCommand().execute(self.params, network_uid=NETWORK_UID)
            helper.assert_called_once_with(self.params, network_uid=NETWORK_UID)
            self.assertIn('deleted', buf.getvalue().lower())


class TestQueueCommands(unittest.TestCase):
    def setUp(self):
        self.params = _mock_params()

    def _queue_response(self, items=None, has_more=False):
        return cnapp_pb2.CnappQueueListResponse(items=items or [], hasMore=has_more)

    def _queue_item(self, queue_id=1, status_id=1, record_uid=b''):
        return cnapp_pb2.CnappQueueItem(
            cnappQueueId=queue_id,
            cnappProviderId=cnapp_pb2.CNAPP_PROVIDER_WIZ,
            cnappQueueStatusId=status_id,
            receivedAt=1700000000000,
            networkId=b'\x00' * 16,
            recordUid=record_uid,
        )

    def test_queue_list_empty(self):
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue',
                          return_value=self._queue_response()):
            buf = io.StringIO()
            with redirect_stdout(buf):
                result = cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status=0, format='table',
                    no_decrypt=True)
            self.assertIn('No CNAPP queue items', buf.getvalue())
            self.assertIsNone(result, 'queue list must not return the proto so the REPL does not dump bytes')

    def test_queue_list_with_items_table(self):
        item = self._queue_item(queue_id=99, status_id=2, record_uid=b'\x01' * 16)
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue',
                          return_value=self._queue_response([item])):
            buf = io.StringIO()
            with redirect_stdout(buf):
                result = cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status=0, format='table',
                    no_decrypt=True)
            output = buf.getvalue()
            self.assertIn('99', output)
            self.assertIn('IN_PROGRESS', output)
            self.assertIn('CNAPP_PROVIDER_WIZ', output)
            self.assertIsNone(result)

    def test_queue_list_filter_resolves_named_status(self):
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue',
                          return_value=self._queue_response()) as helper:
            with redirect_stdout(io.StringIO()):
                cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status='pending', format='table',
                    no_decrypt=True)
            self.assertEqual(helper.call_args.kwargs['status_filter'], 1)

    def test_queue_list_json_format(self):
        item = self._queue_item(queue_id=5, status_id=3, record_uid=b'\x02' * 16)
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue',
                          return_value=self._queue_response([item], has_more=True)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                result = cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status=0, format='json',
                    no_decrypt=True)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload['items'][0]['cnappQueueId'], 5)
            self.assertEqual(payload['items'][0]['cnappQueueStatusName'], 'RESOLVED')
            self.assertTrue(payload['hasMore'])
            self.assertEqual(payload['items'][0]['recordUid'],
                             bytes_to_base64(b'\x02' * 16))
            self.assertNotIn('payload', payload['items'][0],
                             'raw encrypted payload bytes must not leak into JSON output')
            self.assertIsNone(result, 'JSON output stream must not also return a value')

    def test_queue_list_warns_when_has_more(self):
        item = self._queue_item()
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue',
                          return_value=self._queue_response([item], has_more=True)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status=0, format='table',
                    no_decrypt=True)
            self.assertIn('More items', buf.getvalue())

    def test_queue_associate_success(self):
        with patch.object(cnapp_commands.cnapp_helper, 'associate_cnapp_record', return_value=None) as helper:
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappQueueAssociateCommand().execute(
                    self.params, cnapp_queue_id=12, record_uid=RECORD_UID)
            helper.assert_called_once_with(self.params, cnapp_queue_id=12, record_uid=RECORD_UID)
            self.assertIn('12', buf.getvalue())

    def test_queue_remediate_prints_response(self):
        response = cnapp_pb2.CnappRemediateResponse(
            actionType=cnapp_pb2.ROTATE_CREDENTIALS,
            result='Scheduled',
            cnappQueueStatusId=2,
        )
        with patch.object(cnapp_commands.cnapp_helper, 'remediate_cnapp_queue_item',
                          return_value=response):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappQueueRemediateCommand().execute(
                    self.params,
                    cnapp_queue_id=4,
                    action_type='rotate_credentials',
                    provider='wiz',
                )
            output = buf.getvalue()
            self.assertIn('ROTATE_CREDENTIALS', output)
            self.assertIn('IN_PROGRESS', output)
            self.assertIn('Scheduled', output)

    def test_queue_remediate_unsupported_action_propagates(self):
        with patch.object(cnapp_commands.cnapp_helper, 'remediate_cnapp_queue_item',
                          side_effect=Exception('Unsupported action type response code: RRC_BAD_REQUEST')):
            with self.assertRaises(Exception) as ctx:
                cnapp_commands.PAMCnappQueueRemediateCommand().execute(
                    self.params,
                    cnapp_queue_id=4,
                    action_type='jit_access',
                )
            self.assertIn('Unsupported', str(ctx.exception))

    def test_queue_remediate_invalid_action_name(self):
        with self.assertRaises(ValueError):
            cnapp_commands.PAMCnappQueueRemediateCommand().execute(
                self.params, cnapp_queue_id=1, action_type='nuke_everything')

    def test_queue_set_status_normalizes_named(self):
        response = cnapp_pb2.CnappSetStatusResponse(cnappQueueStatusId=3)
        with patch.object(cnapp_commands.cnapp_helper, 'set_cnapp_queue_status',
                          return_value=response) as helper:
            with redirect_stdout(io.StringIO()):
                cnapp_commands.PAMCnappQueueSetStatusCommand().execute(
                    self.params, cnapp_queue_id=8, status='resolved', reason='manual')
            kwargs = helper.call_args.kwargs
            self.assertEqual(kwargs['cnapp_queue_status_id'], 3)
            self.assertEqual(kwargs['reason'], 'manual')

    def test_queue_set_status_rejects_zero(self):
        with self.assertRaises(CommandError):
            cnapp_commands.PAMCnappQueueSetStatusCommand().execute(
                self.params, cnapp_queue_id=8, status=0)

    def test_queue_set_status_rejects_unknown_name(self):
        with self.assertRaises(CommandError):
            cnapp_commands.PAMCnappQueueSetStatusCommand().execute(
                self.params, cnapp_queue_id=8, status='snoozed')

    def test_queue_delete_success(self):
        with patch.object(cnapp_commands.cnapp_helper, 'delete_cnapp_queue_item',
                          return_value=None) as helper:
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappQueueDeleteCommand().execute(self.params, cnapp_queue_id=22)
            helper.assert_called_once_with(self.params, cnapp_queue_id=22)
            self.assertIn('22', buf.getvalue())

    def test_queue_delete_unknown_id_propagates_error(self):
        with patch.object(cnapp_commands.cnapp_helper, 'delete_cnapp_queue_item',
                          side_effect=Exception('Queue item not found: 99 Response code: RRC_BAD_REQUEST')):
            with self.assertRaises(Exception):
                cnapp_commands.PAMCnappQueueDeleteCommand().execute(self.params, cnapp_queue_id=99)


# ---------------------------------------------------------------------------
# Command tree wiring
# ---------------------------------------------------------------------------

class TestCommandTree(unittest.TestCase):
    """Sanity check that the cnapp commands are reachable via `pam cnapp ...`."""

    def test_pam_cnapp_subcommands(self):
        from keepercommander.commands.discoveryrotation import PAMControllerCommand
        pam = PAMControllerCommand()
        self.assertIn('cnapp', pam.subcommands)
        config = pam.subcommands['cnapp'].subcommands['config']
        queue = pam.subcommands['cnapp'].subcommands['queue']
        self.assertEqual(
            sorted(config.subcommands),
            ['delete', 'read', 'set', 'test', 'test-encrypter'],
        )
        self.assertEqual(
            sorted(queue.subcommands),
            ['associate', 'delete', 'list', 'remediate', 'set-status'],
        )


# ---------------------------------------------------------------------------
# Payload decryption — round-trip an AES-256-GCM envelope and decrypt it back
# ---------------------------------------------------------------------------

def _encrypt_cnapp_payload_for_test(plaintext_json, key):
    """Produce a CNAPP queue payload byte string the way the Encrypter would so we can
    exercise `_decrypt_cnapp_payload` end-to-end without mocking AES-GCM."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext_json.encode('utf-8'), None)
    enc_b64url = base64.urlsafe_b64encode(nonce + ciphertext).rstrip(b'=').decode('ascii')
    envelope = json.dumps({
        'encrypted_payload': enc_b64url,
        'alg': 'AES-256-GCM',
        'version': '1',
    }).encode('utf-8')
    envelope_b64url = base64.urlsafe_b64encode(envelope).rstrip(b'=').decode('ascii')
    return envelope_b64url.encode('utf-8')


class TestPayloadDecryption(unittest.TestCase):
    """`_decrypt_cnapp_payload` must round-trip the envelope produced by the customer
    Encrypter (UTF-8 base64url envelope wrapping nonce||ciphertext||tag)."""

    def setUp(self):
        self.key = os.urandom(32)
        self.plaintext = {
            'issue': {'id': 'wiz-001', 'severity': 'HIGH', 'created': '2026-05-01T00:00:00Z'},
            'resource': {'name': 'i-abc', 'type': 'EC2', 'cloudPlatform': 'AWS'},
            'control': {'name': 'Public S3', 'risks': ['data-exposure']},
            'tags': ['team:platform'],
        }

    def test_roundtrip(self):
        payload = _encrypt_cnapp_payload_for_test(json.dumps(self.plaintext), self.key)
        decrypted = cnapp_commands._decrypt_cnapp_payload(payload, self.key)
        self.assertEqual(decrypted['issue']['id'], 'wiz-001')
        self.assertEqual(decrypted['resource']['name'], 'i-abc')

    def test_wrong_key_raises(self):
        payload = _encrypt_cnapp_payload_for_test(json.dumps(self.plaintext), self.key)
        with self.assertRaises(Exception):
            cnapp_commands._decrypt_cnapp_payload(payload, os.urandom(32))

    def test_unsupported_alg_raises(self):
        envelope = json.dumps({'encrypted_payload': '', 'alg': 'ChaCha20', 'version': '1'}).encode('utf-8')
        payload = base64.urlsafe_b64encode(envelope).rstrip(b'=')
        with self.assertRaises(ValueError):
            cnapp_commands._decrypt_cnapp_payload(payload, self.key)

    def test_short_ciphertext_raises(self):
        envelope = json.dumps({
            'encrypted_payload': base64.urlsafe_b64encode(b'abc').rstrip(b'=').decode('ascii'),
            'alg': 'AES-256-GCM',
        }).encode('utf-8')
        payload = base64.urlsafe_b64encode(envelope).rstrip(b'=')
        with self.assertRaises(ValueError):
            cnapp_commands._decrypt_cnapp_payload(payload, self.key)


class TestKeyDecode(unittest.TestCase):
    """`_decode_aes_key` must accept both standard and url-safe base64, only when the
    decoded length is 16 or 32 bytes."""

    def test_standard_base64_32(self):
        raw = base64.b64encode(b'\x11' * 32).decode('ascii')
        self.assertEqual(cnapp_commands._decode_aes_key(raw), b'\x11' * 32)

    def test_urlsafe_base64_32(self):
        raw = base64.urlsafe_b64encode(b'\x22' * 32).decode('ascii')
        self.assertEqual(cnapp_commands._decode_aes_key(raw), b'\x22' * 32)

    def test_wrong_length_returns_none(self):
        raw = base64.b64encode(b'\x33' * 24).decode('ascii')
        self.assertIsNone(cnapp_commands._decode_aes_key(raw))

    def test_garbage_returns_none(self):
        self.assertIsNone(cnapp_commands._decode_aes_key('not base64 at all!!!'))
        self.assertIsNone(cnapp_commands._decode_aes_key(''))
        self.assertIsNone(cnapp_commands._decode_aes_key(None))


class TestQueueListDecryptionIntegration(unittest.TestCase):
    """End-to-end: `queue list` resolves the encrypter key via the vault record, decrypts
    each payload, and writes the human summary into the table cell."""

    def setUp(self):
        self.params = _mock_params()
        self.key = os.urandom(32)

    def _make_item(self, queue_id, plaintext):
        return cnapp_pb2.CnappQueueItem(
            cnappQueueId=queue_id,
            cnappProviderId=cnapp_pb2.CNAPP_PROVIDER_WIZ,
            cnappQueueStatusId=1,
            receivedAt=1700000000000,
            networkId=b'\x00' * 16,
            payload=_encrypt_cnapp_payload_for_test(json.dumps(plaintext), self.key),
        )

    def test_table_shows_decrypted_summary_when_key_resolves(self):
        items = [self._make_item(101, {
            'issue': {'id': 'wiz-999', 'severity': 'CRITICAL'},
            'control': {'name': 'Open SSH'},
            'resource': {'name': 'prod-db-1'},
        })]
        response = cnapp_pb2.CnappQueueListResponse(items=items)
        config = cnapp_pb2.CnappConfiguration(
            cnappConfigRecordUid=b'\xab' * 16,
            provider=cnapp_pb2.CNAPP_PROVIDER_WIZ,
        )
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue', return_value=response), \
             patch.object(cnapp_commands.cnapp_helper, 'read_cnapp_configuration', return_value=config), \
             patch.object(cnapp_commands, '_load_encrypter_key', return_value=self.key):
            buf = io.StringIO()
            with redirect_stdout(buf):
                result = cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status=0, format='table',
                    provider='wiz', config_record_uid=None, no_decrypt=False)
            output = buf.getvalue()
            self.assertIn('CRITICAL', output)
            self.assertIn('Open SSH', output)
            self.assertIn('prod-db-1', output)
            self.assertNotIn('<encrypted>', output, 'payload should have been decrypted')
            self.assertIsNone(result)

    def test_table_marks_encrypted_when_key_unavailable(self):
        items = [self._make_item(7, {'issue': {'id': 'x'}})]
        response = cnapp_pb2.CnappQueueListResponse(items=items)
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue', return_value=response), \
             patch.object(cnapp_commands.cnapp_helper, 'read_cnapp_configuration',
                          return_value=cnapp_pb2.CnappConfiguration()):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status=0, format='table',
                    provider='wiz', no_decrypt=False)
            output = buf.getvalue()
            self.assertIn('<encrypted>', output)
            self.assertIn('No encrypter key', output)

    def test_json_includes_decrypted_payload_and_no_raw_payload(self):
        plaintext = {'issue': {'id': 'wiz-42'}, 'resource': {'name': 'i-xyz'}}
        response = cnapp_pb2.CnappQueueListResponse(items=[self._make_item(42, plaintext)])
        config = cnapp_pb2.CnappConfiguration(cnappConfigRecordUid=b'\xcd' * 16,
                                              provider=cnapp_pb2.CNAPP_PROVIDER_WIZ)
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue', return_value=response), \
             patch.object(cnapp_commands.cnapp_helper, 'read_cnapp_configuration', return_value=config), \
             patch.object(cnapp_commands, '_load_encrypter_key', return_value=self.key):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status=0, format='json',
                    provider='wiz', no_decrypt=False)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload['items'][0]['decryptedPayload']['issue']['id'], 'wiz-42')
            self.assertNotIn('payload', payload['items'][0])

    def test_decrypt_failure_keeps_other_rows_and_reports(self):
        # Payload shape matters: `_decrypted_summary` picks `control.name` over
        # `issue.id`, so to assert the good row was rendered we use a payload where
        # the marker we look for is actually what surfaces in the table cell.
        good = self._make_item(1, {'issue': {'id': 'wiz-good'},
                                   'resource': {'name': 'good-resource'}})
        bad = cnapp_pb2.CnappQueueItem(
            cnappQueueId=2,
            cnappProviderId=cnapp_pb2.CNAPP_PROVIDER_WIZ,
            cnappQueueStatusId=1,
            payload=b'this-is-not-a-valid-envelope',
        )
        response = cnapp_pb2.CnappQueueListResponse(items=[good, bad])
        config = cnapp_pb2.CnappConfiguration(cnappConfigRecordUid=b'\xef' * 16,
                                              provider=cnapp_pb2.CNAPP_PROVIDER_WIZ)
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue', return_value=response), \
             patch.object(cnapp_commands.cnapp_helper, 'read_cnapp_configuration', return_value=config), \
             patch.object(cnapp_commands, '_load_encrypter_key', return_value=self.key):
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status=0, format='table',
                    provider='wiz', no_decrypt=False)
            output = buf.getvalue()
            self.assertIn('wiz-good', output)
            self.assertIn('good-resource', output)
            self.assertIn('<encrypted>', output)
            self.assertIn('failed to decrypt payload', output)

    def test_no_decrypt_flag_skips_key_lookup(self):
        items = [self._make_item(11, {'issue': {'id': 'x'}})]
        response = cnapp_pb2.CnappQueueListResponse(items=items)
        with patch.object(cnapp_commands.cnapp_helper, 'list_cnapp_queue', return_value=response), \
             patch.object(cnapp_commands, '_load_encrypter_key') as key_loader:
            buf = io.StringIO()
            with redirect_stdout(buf):
                cnapp_commands.PAMCnappQueueListCommand().execute(
                    self.params, network_uid=NETWORK_UID, status=0, format='table',
                    no_decrypt=True)
            key_loader.assert_not_called()
            self.assertNotIn('No encrypter key', buf.getvalue())


if __name__ == '__main__':
    unittest.main()
