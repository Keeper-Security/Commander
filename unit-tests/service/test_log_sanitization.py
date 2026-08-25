from unittest import TestCase, mock

from keepercommander.service.decorators.logging import (
    SENSITIVE_FIELD_TYPES,
    sanitize_command_fields,
    sanitize_debug_data,
)
from keepercommander.service.decorators.api_logging import (
    _sanitize_nested_data,
    sanitize_password_in_command,
)
from keepercommander.service.util.command_util import CommandExecutor
from keepercommander.service.util.exceptions import CommandExecutionError
from keepercommander.service.util.request_validation import RequestValidator
from keepercommander.service.config.cli_handler import CommandHandler

SECRET_VALUE = "TopSecretValue123"


class TestSanitizeCommandFields(TestCase):
    """Table-driven coverage: every SENSITIVE_FIELD_TYPES entry must be masked
    whether it's a bare field, a labeled field, a custom (c.) field, or a
    field/custom (f./c.) field with a dotted label."""

    def _assert_masked(self, command):
        result = sanitize_command_fields(command)
        self.assertNotIn(SECRET_VALUE, result)
        self.assertIn('***', result)

    def test_bare_field(self):
        for field_type in sorted(SENSITIVE_FIELD_TYPES):
            with self.subTest(field_type=field_type):
                self._assert_masked(f'record-add -rt login -t x {field_type}={SECRET_VALUE} --force')

    def test_labeled_field(self):
        for field_type in sorted(SENSITIVE_FIELD_TYPES):
            with self.subTest(field_type=field_type):
                self._assert_masked(
                    f'record-update --uid=XYZ f.{field_type}.MyLabel={SECRET_VALUE} --force'
                )

    def test_custom_section_field(self):
        for field_type in sorted(SENSITIVE_FIELD_TYPES):
            with self.subTest(field_type=field_type):
                self._assert_masked(
                    f'record-update --uid=XYZ c.{field_type}.CustomLabel={SECRET_VALUE} --force'
                )

    def test_dotted_label_without_section_prefix(self):
        for field_type in sorted(SENSITIVE_FIELD_TYPES):
            with self.subTest(field_type=field_type):
                self._assert_masked(f'record-add -rt general -t x {field_type}.SubLabel={SECRET_VALUE} --force')

    def test_non_sensitive_field_untouched(self):
        # A field merely labeled with a sensitive-looking substring (not a
        # sensitive field TYPE) must not be masked or corrupted.
        result = sanitize_command_fields('record-add -rt login -t x c.text.MyLoginId=notasecret --force')
        self.assertIn('c.text.MyLoginId=notasecret', result)

    def test_label_containing_keyword_as_substring_not_corrupted(self):
        # Regression: password=[^\s]* without a word boundary used to eat into
        # "OldPassword", turning the label into "Oldpassword".
        result = sanitize_command_fields(f'record-update --uid=XYZ f.password.OldPassword={SECRET_VALUE} --force')
        self.assertIn('f.password.OldPassword=***', result)

    def test_quoted_value_with_spaces_fully_masked(self):
        result = sanitize_command_fields('record-add -rt bankCard -t x paymentCard="4111111111111111 04/2026 123" --force')
        self.assertNotIn('4111111111111111', result)
        self.assertNotIn('123', result)

    def test_malformed_quoting_falls_back_and_still_masks(self):
        result = sanitize_command_fields(f'record-add password="{SECRET_VALUE}')
        self.assertNotIn(SECRET_VALUE, result)


class TestFiledataSanitization(TestCase):
    """Keeper record field JSON shape: {"type": "password", "value": [...]}.
    The secret lives under `value`, not under a sensitively-named dict key."""

    def test_sensitive_type_value_shape_is_masked(self):
        filedata = [
            {"type": "login", "value": ["bob"]},
            {"type": "password", "value": [SECRET_VALUE]},
            {"type": "keyPair", "value": [{"publicKey": "pub", "privateKey": SECRET_VALUE}]},
            {"type": "paymentCard", "value": [{"cardNumber": "4111111111111111",
                                                "cardExpirationDate": "04/2026",
                                                "cardSecurityCode": "123"}]},
        ]
        sanitized = _sanitize_nested_data(filedata)
        dumped = str(sanitized)
        self.assertNotIn(SECRET_VALUE, dumped)
        self.assertNotIn('4111111111111111', dumped)
        self.assertNotIn('123', dumped)

    def test_non_sensitive_type_value_untouched(self):
        filedata = [{"type": "text", "value": ["not a secret"]}]
        sanitized = _sanitize_nested_data(filedata)
        self.assertEqual(sanitized, filedata)

    def test_sanitize_password_in_command_masks_command_and_filedata(self):
        payload = {
            "command": f'record-add -rt login -t x password={SECRET_VALUE} --force',
            "filedata": [{"type": "password", "value": [SECRET_VALUE]}],
        }
        sanitized = sanitize_password_in_command(payload)
        dumped = str(sanitized)
        self.assertNotIn(SECRET_VALUE, dumped)


class TestRequestValidationLogging(TestCase):
    """Regression: validate_and_escape_command must not log the raw command."""

    def test_debug_log_is_masked(self):
        command = f'record-add -rt login -t x password={SECRET_VALUE} --force'
        with mock.patch('keepercommander.service.util.request_validation.logger.debug') as mock_debug:
            escaped_command, error = RequestValidator.validate_and_escape_command({"command": command})

        self.assertIsNone(error)
        # The value returned for execution must remain intact...
        self.assertIn(SECRET_VALUE, escaped_command)
        # ...but nothing logged should contain it.
        mock_debug.assert_called_once()
        self.assertNotIn(SECRET_VALUE, mock_debug.call_args[0][0])


class TestCliHandlerLogging(TestCase):
    """Regression: execute_cli_command must not log the raw command or a raw exception message."""

    def test_error_path_masks_command_and_exception(self):
        command = f'record-add -rt login -t x password={SECRET_VALUE} --force'
        handler = CommandHandler()
        params = mock.Mock(service_mode=False)

        with mock.patch('keepercommander.cli.do_command',
                         side_effect=Exception(f"boom while handling password={SECRET_VALUE}")), \
             mock.patch('keepercommander.service.config.cli_handler.logger.debug') as mock_debug:
            result = handler.execute_cli_command(params, command)

        self.assertEqual(result, '')
        # debug_decorator logs a "Call:" line and CommandHandler logs the error;
        # none of them should contain the secret.
        for call in mock_debug.call_args_list:
            self.assertNotIn(SECRET_VALUE, call[0][0])


class TestCommandExecutorErrorLogging(TestCase):
    """Regression: CommandExecutor.execute must not leak secrets via str(exception)."""

    def test_command_execution_error_is_sanitized_in_logs(self):
        command = f'record-add -rt login -t x password={SECRET_VALUE} --force'

        with mock.patch('keepercommander.service.core.globals.ensure_params_loaded',
                         return_value=mock.Mock(service_mode=False)), \
             mock.patch('keepercommander.service.util.command_util.Verifycommand.validate_service_mode_restrictions',
                         return_value=None), \
             mock.patch('keepercommander.service.util.command_util.Verifycommand.validate_enterprise_user_add_role_force',
                         return_value=None), \
             mock.patch.object(CommandExecutor, 'capture_output_and_logs',
                                side_effect=CommandExecutionError(f"failed on password={SECRET_VALUE}")), \
             mock.patch('keepercommander.service.util.command_util.logger.error') as mock_error:
            response, status_code = CommandExecutor.execute(command)

        self.assertEqual(status_code, 400)
        mock_error.assert_called_once()
        self.assertNotIn(SECRET_VALUE, mock_error.call_args[0][0])


class TestRequestQueueErrorLogging(TestCase):
    """Regression: the queue worker's failure log must not leak secrets from str(exception)."""

    def test_process_request_failure_is_sanitized_in_logs(self):
        from datetime import datetime
        from keepercommander.service.core.request_queue import QueuedRequest, RequestStatus, queue_manager

        request = QueuedRequest(
            request_id='test-request-id',
            command=f'record-add -rt login -t x password={SECRET_VALUE} --force',
            status=RequestStatus.PROCESSING,
            created_at=datetime.now(),
        )

        with mock.patch.object(CommandExecutor, 'execute',
                                side_effect=Exception(f"boom password={SECRET_VALUE}")), \
             mock.patch('keepercommander.service.core.request_queue.logger.error') as mock_error, \
             mock.patch('keepercommander.service.core.request_queue.logger.info'):
            queue_manager._process_request(request)

        mock_error.assert_called_once()
        self.assertNotIn(SECRET_VALUE, mock_error.call_args[0][0])
