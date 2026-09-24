import json
import unittest

from unittest import TestCase, mock
from flask import Flask
from keepercommander import params as params_module, vault
from keepercommander.subfolder import RootFolderNode, SharedFolderNode
from keepercommander.service.util.command_util import CommandExecutor
from keepercommander.service.util.exceptions import CommandExecutionError
from keepercommander.service.util.parse_keeper_response import parse_keeper_response
from keepercommander.service.util.protected_records import get_protected_record_uids

PROTECTED_TITLE = 'Commander Service Mode Config'
PROTECTED_UID = 'PROTECTED_CONFIG_UID'
NORMAL_UID = 'NORMAL_RECORD_UID'


def _record_cache_entry(uid, title):
    return {
        'record_uid': uid,
        'version': 2,
        'revision': 1,
        'client_modified_time': 0,
        'shared': False,
        'record_key_unencrypted': b'0' * 32,
        'data_unencrypted': json.dumps({'title': title}).encode('utf-8'),
    }


def _params_with_protected_and_normal_record():
    p = params_module.KeeperParams()
    p.service_mode = False
    p.record_cache = {
        PROTECTED_UID: _record_cache_entry(PROTECTED_UID, PROTECTED_TITLE),
        NORMAL_UID: _record_cache_entry(NORMAL_UID, 'My Normal Record'),
    }
    return p

class TestCommandAPI(TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.client = self.app.test_client()
            
        @self.app.route('/api/v1/executecommand', methods=['POST'])
        def execute_command():
            command = "ls"
            response, status_code = CommandExecutor.execute(command)
            return {'response': response}, status_code

    def test_validate_command(self):
        """Test command validation"""
        result, status_code = CommandExecutor.validate_command("")
        self.assertIsNotNone(result)
        self.assertEqual(status_code, 400)
        self.assertEqual(result["error"], "No command provided.")

        result = CommandExecutor.validate_command("ls")
        self.assertIsNone(result)

    def test_validate_session(self):
        """Test session validation"""
        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value=None):
            result, status_code = CommandExecutor.validate_session()
            self.assertEqual(status_code, 401)
            self.assertIn("No active session", result["error"])

        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value={"session": "active"}):
            result = CommandExecutor.validate_session()
            self.assertIsNone(result)

    @unittest.skip
    def test_command_execution_success(self):
        """Test successful command execution"""
        mock_params = {"session": "active"}
        test_command = "ls"
        expected_output = "Folder1\nFolder2\n"

        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value=mock_params), \
            mock.patch('keepercommander.cli.do_command', return_value=expected_output), \
            mock.patch('keepercommander.service.util.command_util.ConfigReader.read_config', return_value=None):

            response, status_code = CommandExecutor.execute(test_command)
            self.assertEqual(status_code, 200)
            self.assertIsNotNone(response)

    @unittest.skip
    def test_command_execution_failure(self):
        """Test command execution failure"""
        mock_params = {"session": "active"}
        test_command = "invalid_command"

        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value=mock_params), \
            mock.patch('keepercommander.cli.do_command', side_effect=Exception("Command failed")), \
            self.assertRaises(CommandExecutionError):
                
            CommandExecutor.execute(test_command)

    def test_response_encryption(self):
        """Test response encryption when key is present"""
        test_response = {"status": "success", "data": "test"}

        mock_key = "0" * 32

        with mock.patch('keepercommander.service.util.command_util.ConfigReader.read_config', return_value=mock_key):
            encrypted_response = CommandExecutor.encrypt_response(test_response)
            self.assertIsInstance(encrypted_response, bytes)
            self.assertGreater(len(encrypted_response), 0)

    def test_response_parsing(self):
        """Test response parsing for different commands"""

        ls_response = "# Folder UID\n1 folder1_uid folder1 rw\n# Record UID\n1 record1_uid login record1"
        parsed = parse_keeper_response("ls", ls_response)
        self.assertEqual(parsed["status"], "success")
        self.assertEqual(parsed["command"], "ls")
        self.assertIn("folders", parsed["data"])
        self.assertIn("records", parsed["data"])

        tree_response = "Root\n  Folder1\n    SubFolder1"
        parsed = parse_keeper_response("tree", tree_response)
        self.assertEqual(parsed["command"], "tree")
        self.assertIsInstance(parsed["data"], dict)
        self.assertIn("tree", parsed["data"])

    def test_capture_output(self):
        """Test command output capture"""
        test_command = "ls"
        expected_output = "test output"
        mock_params = {"session": "active"}

        with mock.patch('keepercommander.cli.do_command', return_value=expected_output):
            return_value, output, logs = CommandExecutor.capture_output_and_logs(mock_params, test_command)
            self.assertEqual(return_value, expected_output)

    @unittest.skip
    def test_integration_command_flow(self):
        """Test the complete command execution flow"""
        test_command = "ls"
        mock_params = {"session": "active"}
        expected_output = "# Folder UID\n1 folder1_uid folder1 rw"

        with mock.patch('keepercommander.service.util.command_util.get_current_params', return_value=mock_params), \
            mock.patch('keepercommander.cli.do_command', return_value=expected_output), \
            mock.patch('keepercommander.service.util.command_util.ConfigReader.read_config', return_value=None):

            response, status_code = CommandExecutor.execute(test_command)
            self.assertEqual(status_code, 200)
            self.assertIsNotNone(response)


class TestProtectedRecordCommandExecution(TestCase):
    """End-to-end proof, through CommandExecutor.execute, that Service Mode's own config record stays blocked while unrelated records work."""

    def _run(self, command, params=None):
        params = params or _params_with_protected_and_normal_record()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', '')
        ) as mock_capture:
            response, status_code = CommandExecutor.execute(command)
        return response, status_code, mock_capture, params

    def test_blocked_commands_never_reach_cli_dispatch(self):
        for command in (
            f'get {PROTECTED_UID}',
            f'get "{PROTECTED_TITLE}"',
            f'list {PROTECTED_UID}',
            f'search {PROTECTED_UID}',
            f'record-update --record {PROTECTED_UID} title=x',
            f'record-update --record={PROTECTED_UID} title=x',
            f'rm {PROTECTED_UID}',
            f'share-record {PROTECTED_UID} --email a@b.com',
            f'share-folder --record {PROTECTED_UID} -e a@b.com',
            f'share-folder --record={PROTECTED_UID} -e a@b.com',
            f'ls "{PROTECTED_TITLE}"',
            f'tree "{PROTECTED_TITLE}"',
            f'nsf-get {PROTECTED_UID}',
            # Not one of the commands anyone would think to curate a list around --
            # proves the check isn't gated by command name at all.
            f'keep-alive {PROTECTED_UID}',
        ):
            with self.subTest(command=command):
                response, status_code, mock_capture, _ = self._run(command)
                self.assertEqual(status_code, 403)
                self.assertEqual(response.get('status'), 'error')
                mock_capture.assert_not_called()

    def test_unrelated_record_commands_are_unaffected(self):
        for command in (
            f'get {NORMAL_UID}',
            f'list {NORMAL_UID}',
            f'search {NORMAL_UID}',
            f'record-update --record {NORMAL_UID} title=x',
            f'rm {NORMAL_UID}',
            f'share-record {NORMAL_UID} --email a@b.com',
        ):
            with self.subTest(command=command):
                response, status_code, mock_capture, _ = self._run(command)
                self.assertEqual(status_code, 200)
                mock_capture.assert_called_once()

    def test_record_cache_is_popped_during_dispatch_and_restored_after(self):
        params = _params_with_protected_and_normal_record()
        seen_during_call = {}

        def fake_capture(p, command):
            seen_during_call['keys'] = set(p.record_cache.keys())
            return 'ok', 'ok', ''

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(CommandExecutor, 'capture_output_and_logs', side_effect=fake_capture):
            response, status_code = CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertEqual(status_code, 200)
        self.assertNotIn(PROTECTED_UID, seen_during_call['keys'])
        self.assertIn(NORMAL_UID, seen_during_call['keys'])
        # Restored after the call returns -- the shared params singleton must
        # not stay permanently blind to its own config record.
        self.assertIn(PROTECTED_UID, params.record_cache)

    def test_record_cache_restored_even_if_dispatch_raises(self):
        params = _params_with_protected_and_normal_record()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', side_effect=CommandExecutionError('boom')
        ):
            response, status_code = CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertEqual(status_code, 400)
        self.assertIn(PROTECTED_UID, params.record_cache)

    def test_protected_record_check_runs_for_every_command(self):
        """The check is unconditional -- even a command with no known relationship
        to records (whoami) still triggers it, so no command can be missed."""
        params = _params_with_protected_and_normal_record()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', '')
        ), mock.patch(
            'keepercommander.service.util.command_util.get_protected_record_uids',
            wraps=get_protected_record_uids,
        ) as mock_get_uids:
            CommandExecutor.execute('whoami')
            mock_get_uids.assert_called_once()

    def test_sailpoint_handling_runs_before_the_record_cache_guard(self):
        """handle_command needs its OWN record visible to read its marker/capability fields.
        Safe because Layer B already blocks direct references, and _before_share only resolves exact cache keys."""
        params = _params_with_protected_and_normal_record()
        seen_during_handle_command = {}
        seen_during_dispatch = {}

        def fake_handle_command(p, command):
            seen_during_handle_command['keys'] = set(p.record_cache.keys())
            return command, None

        def fake_capture(p, command):
            seen_during_dispatch['keys'] = set(p.record_cache.keys())
            return 'ok', 'ok', ''

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.dict('os.environ', {'SAILPOINT_RECORD': PROTECTED_UID}), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.service.SailPointService.handle_command',
            side_effect=fake_handle_command,
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', side_effect=fake_capture,
        ):
            CommandExecutor.execute(f'get {NORMAL_UID}')

        # Unhidden for SailPoint's own gate -- it needs to read its own config record.
        self.assertIn(PROTECTED_UID, seen_during_handle_command['keys'])
        self.assertIn(NORMAL_UID, seen_during_handle_command['keys'])
        # Hidden again for the actual dispatched command -- an admin still can't reach it.
        self.assertNotIn(PROTECTED_UID, seen_during_dispatch['keys'])
        self.assertIn(NORMAL_UID, seen_during_dispatch['keys'])
        # Restored after the whole request completes.
        self.assertIn(PROTECTED_UID, params.record_cache)

    def test_other_protected_records_stay_hidden_from_sailpoint_handle_command(self):
        """Regression test: only SailPoint's own pinned UID is exempt from handle_command's guard;
        every other protected record (PROTECTED_UID standing in for e.g. Docker's) must stay hidden."""
        params = _params_with_protected_and_normal_record()
        seen_during_handle_command = {}

        def fake_handle_command(p, command):
            seen_during_handle_command['keys'] = set(p.record_cache.keys())
            return command, None

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.dict('os.environ', {'SAILPOINT_RECORD': 'sailpoint-own-uid'}), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.service.SailPointService.handle_command',
            side_effect=fake_handle_command,
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', ''),
        ):
            CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertNotIn(PROTECTED_UID, seen_during_handle_command['keys'])
        self.assertIn(NORMAL_UID, seen_during_handle_command['keys'])

    def test_direct_reference_to_protected_record_never_reaches_sailpoint_handle_command(self):
        """Layer B blocks a command that directly names the protected UID/title before
        SailPoint's handle_command ever runs, regardless of the record being unhidden for it."""
        params = _params_with_protected_and_normal_record()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.dict('os.environ', {'SAILPOINT_RECORD': 'sailpoint-uid'}), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.service.SailPointService.handle_command',
        ) as mock_handle_command, mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', ''),
        ) as mock_capture:
            response, status_code = CommandExecutor.execute(f'get {PROTECTED_UID}')

        self.assertEqual(status_code, 403)
        mock_handle_command.assert_not_called()
        mock_capture.assert_not_called()

    def test_sailpoint_marker_check_failure_denies_the_request(self):
        """A transient marker-read failure must deny the request, not silently skip SailPoint's gating."""
        params = _params_with_protected_and_normal_record()
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.dict('os.environ', {'SAILPOINT_RECORD': 'sailpoint-uid'}), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.service.SailPointService.record_has_marker',
            side_effect=RuntimeError('decrypt failed'),
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', ''),
        ) as mock_capture:
            response, status_code = CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertEqual(status_code, 500)
        mock_capture.assert_not_called()

    def test_sailpoint_own_record_stays_hidden_during_dispatch_when_another_record_is_also_protected(self):
        """Regression test: when a second protected record forces the outer (handle_command)
        guard to actually wrap record_cache, the inner (dispatch) guard must still hide
        SailPoint's own UID too, not silently no-op because the cache is no longer a plain dict."""
        sailpoint_uid = 'SAILPOINT_OWN_UID'
        params = params_module.KeeperParams()
        params.service_mode = False
        params.record_cache = {
            sailpoint_uid: _record_cache_entry(sailpoint_uid, 'Commander Service Mode SailPoint Config'),
            PROTECTED_UID: _record_cache_entry(PROTECTED_UID, PROTECTED_TITLE),
            NORMAL_UID: _record_cache_entry(NORMAL_UID, 'My Normal Record'),
        }
        seen_during_dispatch = {}

        def fake_capture(p, command):
            seen_during_dispatch['keys'] = set(p.record_cache.keys())
            return 'ok', 'ok', ''

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.dict('os.environ', {'SAILPOINT_RECORD': sailpoint_uid}), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.service.SailPointService.handle_command',
            side_effect=lambda p, command: (command, None),
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', side_effect=fake_capture,
        ):
            CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertNotIn(sailpoint_uid, seen_during_dispatch['keys'])
        self.assertNotIn(PROTECTED_UID, seen_during_dispatch['keys'])
        self.assertIn(NORMAL_UID, seen_during_dispatch['keys'])

    def test_other_protected_records_stay_hidden_during_sailpoint_after_command(self):
        """after_command follows the same rule as handle_command: SailPoint's own record stays
        visible (it writes the pending-entitlement queue there), every other protected record stays hidden."""
        sailpoint_uid = 'SAILPOINT_OWN_UID'
        params = params_module.KeeperParams()
        params.service_mode = False
        params.record_cache = {
            sailpoint_uid: _record_cache_entry(sailpoint_uid, 'Commander Service Mode SailPoint Config'),
            PROTECTED_UID: _record_cache_entry(PROTECTED_UID, PROTECTED_TITLE),
            NORMAL_UID: _record_cache_entry(NORMAL_UID, 'My Normal Record'),
        }
        seen_during_after_command = {}

        def fake_after_command(p, command, success=True):
            seen_during_after_command['keys'] = set(p.record_cache.keys())

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.dict('os.environ', {'SAILPOINT_RECORD': sailpoint_uid}), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.service.SailPointService.handle_command',
            side_effect=lambda p, command: (command, None),
        ), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.service.SailPointService.after_command',
            side_effect=fake_after_command,
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', ''),
        ):
            CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertIn(sailpoint_uid, seen_during_after_command['keys'])
        self.assertNotIn(PROTECTED_UID, seen_during_after_command['keys'])
        self.assertIn(NORMAL_UID, seen_during_after_command['keys'])


class TestSyncDownExemptionCommandExecution(TestCase):
    """slack-app-setup --sync-down must keep working for its OWN config record while every
    other protected record (including a different integration's) stays blocked."""

    SLACK_UID = 'SLACK_CONFIG_UID'
    GCHAT_UID = 'GCHAT_CONFIG_UID'

    def _params(self):
        p = params_module.KeeperParams()
        p.service_mode = False
        p.record_cache = {
            self.SLACK_UID: _record_cache_entry(self.SLACK_UID, 'Commander Service Mode Slack App Config'),
            self.GCHAT_UID: _record_cache_entry(self.GCHAT_UID, 'Commander Service Mode Google Chat App Config'),
            NORMAL_UID: _record_cache_entry(NORMAL_UID, 'My Normal Record'),
        }
        return p

    def _run(self, command, params, capture_side_effect=None):
        env = {'SLACK_RECORD': self.SLACK_UID, 'GCHAT_RECORD': self.GCHAT_UID}
        with mock.patch.dict('os.environ', env), mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs',
            side_effect=capture_side_effect, return_value=('ok', 'ok', '') if capture_side_effect is None else None,
        ) as mock_capture:
            response, status_code = CommandExecutor.execute(command)
        return response, status_code, mock_capture

    def test_get_slack_record_is_blocked(self):
        params = self._params()
        response, status_code, mock_capture = self._run(f'get {self.SLACK_UID}', params)
        self.assertEqual(status_code, 403)
        mock_capture.assert_not_called()

    def test_slack_sync_down_default_flow_is_not_blocked_and_sees_its_own_record(self):
        params = self._params()
        seen = {}

        def fake_capture(p, command):
            seen['keys'] = set(p.record_cache.keys())
            return 'ok', 'ok', ''

        response, status_code, mock_capture = self._run(
            'slack-app-setup --sync-down', params, capture_side_effect=fake_capture
        )
        self.assertEqual(status_code, 200)
        mock_capture.assert_called_once()
        self.assertIn(self.SLACK_UID, seen['keys'])         # not hidden for this one dispatch
        self.assertIn(self.GCHAT_UID, params.record_cache)  # untouched throughout

    def test_slack_sync_down_with_explicit_own_uid_is_not_blocked(self):
        params = self._params()
        response, status_code, mock_capture = self._run(
            f'slack-app-setup --sync-down -r {self.SLACK_UID}', params
        )
        self.assertEqual(status_code, 200)
        mock_capture.assert_called_once()

    def test_slack_sync_down_with_a_different_integrations_uid_is_still_blocked(self):
        params = self._params()
        response, status_code, mock_capture = self._run(
            f'slack-app-setup --sync-down -r {self.GCHAT_UID}', params
        )
        self.assertEqual(status_code, 403)
        mock_capture.assert_not_called()

    def test_slack_setup_without_sync_down_gets_no_exemption(self):
        """The main (non --sync-down) flow must not get the record cache exemption
        just because it names the record's own UID."""
        params = self._params()
        response, status_code, mock_capture = self._run(
            f'slack-app-setup --slack-record-name {self.SLACK_UID}', params
        )
        self.assertEqual(status_code, 403)
        mock_capture.assert_not_called()

    def test_gchat_sync_down_default_flow_is_not_blocked_and_sees_its_own_record(self):
        """Same as Slack's own-record flow, but for GChat -- proves the exemption isn't Slack-specific."""
        params = self._params()
        seen = {}

        def fake_capture(p, command):
            seen['keys'] = set(p.record_cache.keys())
            return 'ok', 'ok', ''

        response, status_code, mock_capture = self._run(
            'gchat-app-setup --sync-down', params, capture_side_effect=fake_capture
        )
        self.assertEqual(status_code, 200)
        mock_capture.assert_called_once()
        self.assertIn(self.GCHAT_UID, seen['keys'])
        self.assertIn(self.SLACK_UID, params.record_cache)

    def test_gchat_sync_down_with_a_different_integrations_uid_is_still_blocked(self):
        params = self._params()
        response, status_code, mock_capture = self._run(
            f'gchat-app-setup --sync-down -r {self.SLACK_UID}', params
        )
        self.assertEqual(status_code, 403)
        mock_capture.assert_not_called()


class TestTerraformRecordProtectionCommandExecution(TestCase):
    """Same UID-pinning protection Docker/Slack/GChat get, proven at the CommandExecutor.execute() boundary."""

    TERRAFORM_UID = 'TERRAFORM_CONFIG_UID'

    def _params(self):
        p = params_module.KeeperParams()
        p.service_mode = False
        p.record_cache = {
            self.TERRAFORM_UID: _record_cache_entry(self.TERRAFORM_UID, 'Commander Service Mode Terraform Config'),
            NORMAL_UID: _record_cache_entry(NORMAL_UID, 'My Normal Record'),
        }
        return p

    def _run(self, command, params):
        with mock.patch.dict('os.environ', {'TERRAFORM_RECORD': self.TERRAFORM_UID}), mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', '')
        ) as mock_capture:
            response, status_code = CommandExecutor.execute(command)
        return response, status_code, mock_capture

    def test_get_terraform_record_is_blocked(self):
        params = self._params()
        response, status_code, mock_capture = self._run(f'get {self.TERRAFORM_UID}', params)
        self.assertEqual(status_code, 403)
        mock_capture.assert_not_called()

    def test_share_record_on_terraform_record_is_blocked(self):
        params = self._params()
        response, status_code, mock_capture = self._run(
            f'share-record {self.TERRAFORM_UID} --email a@b.com', params
        )
        self.assertEqual(status_code, 403)
        mock_capture.assert_not_called()

    def test_normal_record_is_unaffected(self):
        params = self._params()
        response, status_code, mock_capture = self._run(f'get {NORMAL_UID}', params)
        self.assertEqual(status_code, 200)
        mock_capture.assert_called_once()


class TestProtectedFolderCommandExecution(TestCase):
    """The shared folder holding a protected config record must be just as unreachable
    as the record itself -- ls/tree/rndir/mv/share-folder all resolve folders through the
    same caches hide_from_folder_cache guards."""

    PROTECTED_FOLDER_UID = 'PROTECTED_FOLDER_UID'
    PROTECTED_FOLDER_TITLE = 'Commander Service Mode - Docker'
    NORMAL_FOLDER_UID = 'NORMAL_FOLDER_UID'

    def _params(self):
        p = params_module.KeeperParams()
        p.service_mode = False
        p.record_cache = {
            PROTECTED_UID: _record_cache_entry(PROTECTED_UID, PROTECTED_TITLE),
            NORMAL_UID: _record_cache_entry(NORMAL_UID, 'My Normal Record'),
        }
        p.root_folder = RootFolderNode()

        protected_node = SharedFolderNode()
        protected_node.uid = self.PROTECTED_FOLDER_UID
        protected_node.name = self.PROTECTED_FOLDER_TITLE
        normal_node = SharedFolderNode()
        normal_node.uid = self.NORMAL_FOLDER_UID
        normal_node.name = 'My Normal Folder'

        p.folder_cache = {self.PROTECTED_FOLDER_UID: protected_node, self.NORMAL_FOLDER_UID: normal_node}
        p.root_folder.subfolders = [self.PROTECTED_FOLDER_UID, self.NORMAL_FOLDER_UID]
        p.shared_folder_cache = {
            self.PROTECTED_FOLDER_UID: {'name_unencrypted': self.PROTECTED_FOLDER_TITLE},
            self.NORMAL_FOLDER_UID: {'name_unencrypted': 'My Normal Folder'},
        }
        p.subfolder_cache = {
            self.PROTECTED_FOLDER_UID: {'type': 'shared_folder', 'shared_folder_uid': self.PROTECTED_FOLDER_UID},
            self.NORMAL_FOLDER_UID: {'type': 'shared_folder', 'shared_folder_uid': self.NORMAL_FOLDER_UID},
        }
        p.subfolder_record_cache = {
            self.PROTECTED_FOLDER_UID: {PROTECTED_UID},
            self.NORMAL_FOLDER_UID: {NORMAL_UID},
        }
        return p

    def _run(self, command, params):
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', '')
        ) as mock_capture:
            response, status_code = CommandExecutor.execute(command)
        return response, status_code, mock_capture

    def test_blocked_folder_commands_never_reach_cli_dispatch(self):
        """Layer B's literal-token scan is UID-only for folders (by design -- see the plan);
        a title-only reference isn't caught here, it fails to resolve at all once Layer A
        hides the folder from folder_cache/shared_folder_cache, proven separately in
        TestHideFromFolderCache and test_folder_caches_hidden_during_dispatch_and_restored_after."""
        for command in (
            f'ls {self.PROTECTED_FOLDER_UID}',
            f'tree {self.PROTECTED_FOLDER_UID}',
            f'rndir {self.PROTECTED_FOLDER_UID} x',
            f'mv {self.PROTECTED_FOLDER_UID} /',
            f'share-folder {self.PROTECTED_FOLDER_UID} -e a@b.com',
        ):
            with self.subTest(command=command):
                params = self._params()
                response, status_code, mock_capture = self._run(command, params)
                self.assertEqual(status_code, 403)
                mock_capture.assert_not_called()

    def test_normal_folder_commands_are_unaffected(self):
        params = self._params()
        response, status_code, mock_capture = self._run(f'ls {self.NORMAL_FOLDER_UID}', params)
        self.assertEqual(status_code, 200)
        mock_capture.assert_called_once()

    def test_folder_caches_hidden_during_dispatch_and_restored_after(self):
        params = self._params()
        seen = {}

        def fake_capture(p, command):
            seen['folder_keys'] = set(p.folder_cache.keys())
            seen['subfolders'] = list(p.root_folder.subfolders)
            return 'ok', 'ok', ''

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(CommandExecutor, 'capture_output_and_logs', side_effect=fake_capture):
            response, status_code = CommandExecutor.execute(f'ls {self.NORMAL_FOLDER_UID}')

        self.assertEqual(status_code, 200)
        self.assertNotIn(self.PROTECTED_FOLDER_UID, seen['folder_keys'])
        self.assertIn(self.NORMAL_FOLDER_UID, seen['folder_keys'])
        self.assertNotIn(self.PROTECTED_FOLDER_UID, seen['subfolders'])

        self.assertIn(self.PROTECTED_FOLDER_UID, params.folder_cache)
        self.assertIn(self.PROTECTED_FOLDER_UID, params.root_folder.subfolders)


class TestSailPointFolderProtectionCommandExecution(TestCase):
    """Regression test: hide_from_folder_cache was imported and fed protected_folder_uids,
    but never actually invoked as a context manager, so a protected record's folder kept
    showing up in tree/ls even though the record itself was correctly hidden."""

    FOLDER_UID = 'PROTECTED_FOLDER_UID'
    RECORD_UID = 'PROTECTED_FOLDER_RECORD_UID'

    def _params(self):
        p = params_module.KeeperParams()
        p.service_mode = False
        p.record_cache = {
            self.RECORD_UID: _record_cache_entry(self.RECORD_UID, 'Commander Service Mode SailPoint Config'),
            NORMAL_UID: _record_cache_entry(NORMAL_UID, 'My Normal Record'),
        }
        p.root_folder = RootFolderNode()
        node = SharedFolderNode()
        node.uid = self.FOLDER_UID
        node.name = 'Commander Service Mode - SailPoint'
        p.folder_cache = {self.FOLDER_UID: node}
        p.root_folder.subfolders = [self.FOLDER_UID]
        p.shared_folder_cache = {self.FOLDER_UID: {'name_unencrypted': node.name}}
        p.subfolder_cache = {self.FOLDER_UID: {'type': 'shared_folder', 'shared_folder_uid': self.FOLDER_UID}}
        p.subfolder_record_cache = {self.FOLDER_UID: {self.RECORD_UID}}
        return p

    def test_folder_hidden_during_actual_dispatch(self):
        params = self._params()
        seen = {}

        def fake_capture(p, command):
            seen['folder_keys'] = set(p.folder_cache.keys())
            seen['subfolders'] = list(p.root_folder.subfolders)
            return 'ok', 'ok', ''

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.object(CommandExecutor, 'capture_output_and_logs', side_effect=fake_capture):
            CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertNotIn(self.FOLDER_UID, seen['folder_keys'])
        self.assertNotIn(self.FOLDER_UID, seen['subfolders'])
        self.assertIn(self.FOLDER_UID, params.folder_cache)
        self.assertIn(self.FOLDER_UID, params.root_folder.subfolders)

    def test_folder_hidden_during_sailpoint_handle_command_too(self):
        """Unlike the record, the folder has no reason to be visible to handle_command,
        so it must stay hidden for the whole request, not just the final dispatch."""
        params = self._params()
        seen = {}

        def fake_handle_command(p, command):
            seen['folder_keys'] = set(p.folder_cache.keys())
            return command, None

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch.dict('os.environ', {'SAILPOINT_RECORD': 'sailpoint-uid'}), mock.patch(
            'keepercommander.service.commands.integrations.sailpoint.service.SailPointService.handle_command',
            side_effect=fake_handle_command,
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', '')
        ):
            CommandExecutor.execute(f'get {NORMAL_UID}')

        self.assertNotIn(self.FOLDER_UID, seen['folder_keys'])


class TestReservedAttachmentCommandExecution(TestCase):
    """A record with an arbitrary, non-default title must still be blocked if it carries
    one of Commander's own reserved config-file attachments (config.json/service_config.json)."""

    ARBITRARY_UID = 'ARBITRARY_TITLED_RECORD_UID'

    def _params(self):
        p = params_module.KeeperParams()
        p.service_mode = False
        p.record_cache = {
            self.ARBITRARY_UID: _record_cache_entry(self.ARBITRARY_UID, 'My Totally Unrelated Title'),
            NORMAL_UID: _record_cache_entry(NORMAL_UID, 'My Normal Record'),
        }
        return p

    @staticmethod
    def _record_with_reserved_attachment(uid, title):
        record = vault.PasswordRecord()
        record.record_uid = uid
        record.title = title
        record.attachments = [vault.AttachmentFile({'id': f'{uid}_ATTA', 'name': 'config.json'})]
        return record

    @staticmethod
    def _plain_record(uid, title):
        record = vault.PasswordRecord()
        record.record_uid = uid
        record.title = title
        return record

    _TITLES = {ARBITRARY_UID: 'My Totally Unrelated Title', NORMAL_UID: 'My Normal Record'}

    def _run(self, command, params, reserved_uids=(ARBITRARY_UID,)):
        records = {
            uid: (
                self._record_with_reserved_attachment(uid, self._TITLES[uid])
                if uid in reserved_uids else self._plain_record(uid, self._TITLES[uid])
            )
            for uid in params.record_cache
        }
        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch(
            'keepercommander.vault.KeeperRecord.load', side_effect=lambda p, uid: records.get(uid)
        ), mock.patch.object(
            CommandExecutor, 'capture_output_and_logs', return_value=('ok', 'ok', '')
        ) as mock_capture:
            response, status_code = CommandExecutor.execute(command)
        return response, status_code, mock_capture

    def test_get_on_record_with_reserved_attachment_is_blocked(self):
        params = self._params()
        response, status_code, mock_capture = self._run(f'get {self.ARBITRARY_UID}', params)
        self.assertEqual(status_code, 403)
        mock_capture.assert_not_called()

    def test_file_report_omits_record_with_reserved_attachment(self):
        params = self._params()
        records = {
            self.ARBITRARY_UID: self._record_with_reserved_attachment(
                self.ARBITRARY_UID, self._TITLES[self.ARBITRARY_UID]
            ),
            NORMAL_UID: self._plain_record(NORMAL_UID, self._TITLES[NORMAL_UID]),
        }
        seen = {}

        def fake_capture(p, command):
            seen['keys'] = set(p.record_cache.keys())
            return 'ok', 'ok', ''

        with mock.patch(
            'keepercommander.service.core.globals.ensure_params_loaded', return_value=params
        ), mock.patch(
            'keepercommander.vault.KeeperRecord.load', side_effect=lambda p, uid: records.get(uid)
        ), mock.patch.object(CommandExecutor, 'capture_output_and_logs', side_effect=fake_capture):
            response, status_code = CommandExecutor.execute('file-report')

        self.assertEqual(status_code, 200)
        self.assertNotIn(self.ARBITRARY_UID, seen['keys'])
        self.assertIn(NORMAL_UID, seen['keys'])

    def test_record_without_reserved_attachment_is_unaffected(self):
        params = self._params()
        response, status_code, mock_capture = self._run(f'get {NORMAL_UID}', params, reserved_uids=())
        self.assertEqual(status_code, 200)
        mock_capture.assert_called_once()
