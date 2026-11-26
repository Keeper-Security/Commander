import datetime
import io
import logging
import os
import re
import tempfile
from pathlib import Path
from unittest import TestCase, mock

from keepercommander import cli
from keepercommander.__main__ import main, parser
from keepercommander.params import KeeperParams


def _resolved(argv):
    startup_opts, _ = parser.parse_known_args(argv)
    log_file, remaining = cli.extract_shell_log_file_arg(argv, startup_opts.command, startup_opts.options)
    opts, _ = parser.parse_known_args(remaining)
    opts.log_file = log_file
    return opts


def _close_log_files():
    cli.debug_manager._detach_log_files()


def _has_log_file():
    root = logging.getLogger()
    return any(getattr(h, cli.KEEPER_LOG_FILE_ATTR, False) for h in root.handlers)


class TestLogFileOption(TestCase):
    def test_absent_flag_does_not_enable_a_file(self):
        opts = _resolved(['shell'])
        self.assertIsNone(opts.log_file)
        self.assertEqual(opts.command, 'shell')

    def test_shell_bare_flag_uses_default_name(self):
        opts = _resolved(['shell', '--file'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, [])

    def test_shell_equals_form_uses_the_given_name(self):
        opts = _resolved(['shell', '--file=custom.log'])
        self.assertEqual(opts.log_file, 'custom.log')
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, [])

    def test_shell_equals_form_keeps_the_following_subcommand(self):
        opts = _resolved(['shell', '--file=session.log', 'login', 'user@example.com'])
        self.assertEqual(opts.log_file, 'session.log')
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, ['login', 'user@example.com'])

    def test_bare_flag_does_not_take_the_next_token_as_the_file_name(self):
        opts = _resolved(['shell', '--file', 'login', 'user@example.com'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, ['login', 'user@example.com'])

    def test_flag_before_shell_uses_the_default_and_keeps_the_subcommand(self):
        opts = _resolved(['--file', 'shell', 'login', 'user@example.com'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, ['login', 'user@example.com'])

    def test_empty_equals_form_uses_default_name(self):
        opts = _resolved(['shell', '--file='])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertEqual(opts.command, 'shell')

    def test_user_value_is_not_treated_as_the_command(self):
        opts = _resolved(['--user', 'user@example.com', 'shell', '--file=session.log'])
        self.assertEqual(opts.log_file, 'session.log')
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.user, 'user@example.com')

    def test_flag_on_a_non_shell_command_is_left_alone(self):
        log_file, remaining = cli.extract_shell_log_file_arg(
            ['import', '--file', 'https://metron.secretservercloud.com'], 'import'
        )
        self.assertIsNone(log_file)
        self.assertEqual(
            remaining,
            ['import', '--file', 'https://metron.secretservercloud.com'],
        )

    def test_last_flag_wins(self):
        opts = _resolved(['shell', '--file=a.log', '--file'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, [])

    def test_flag_without_a_command_is_kept_for_the_package_launcher(self):
        opts = _resolved(['--file=file1.log'])
        self.assertEqual(opts.log_file, 'file1.log')
        self.assertIsNone(opts.command)

    def test_bare_flag_without_a_command_uses_the_default_name(self):
        opts = _resolved(['--file'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertIsNone(opts.command)


    def test_bare_flag_followed_by_a_path_is_rejected(self):
        for argv in (['shell', '--file', 'my.log'],
                     ['shell', '--file', 'logs/session.txt'],
                     ['-', '--file', 'my.log'],
                     ['--file', 'my.log', 'shell']):
            with self.subTest(argv=argv):
                with self.assertRaises(cli.LogFileOptionError) as ctx:
                    _resolved(argv)
                self.assertIn('--file=' + argv[argv.index('--file') + 1], str(ctx.exception))

    def test_bare_flag_followed_by_a_path_without_a_command_is_rejected(self):
        # keeper.py --file my.log: the parser takes my.log as the command.
        with self.assertRaises(cli.LogFileOptionError):
            _resolved(['--file', 'my.log'])

    def test_bare_flag_before_an_existing_default_log_is_rejected(self):
        # Without the check keeper.log is the command and is run as a batch file.
        with self.assertRaises(cli.LogFileOptionError):
            _resolved(['--file', cli.DEFAULT_LOG_FILE])

    def test_error_message_explains_the_equals_form(self):
        with self.assertRaises(cli.LogFileOptionError) as ctx:
            _resolved(['shell', '--file', 'my.log'])
        message = str(ctx.exception)
        self.assertIn('--file=my.log', message)
        self.assertIn(cli.DEFAULT_LOG_FILE, message)

    def test_bare_flag_followed_by_an_alias_is_accepted(self):
        opts = _resolved(['shell', '--file', 'ls'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertEqual(opts.options, ['ls'])

    def test_bare_flag_followed_by_a_builtin_word_is_accepted(self):
        # debug is handled inside do_command and is not registered, but is not a path.
        opts = _resolved(['shell', '--file', 'debug'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertEqual(opts.options, ['debug'])

    def test_bare_flag_followed_by_an_option_is_accepted(self):
        opts = _resolved(['shell', '--file', '--debug'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertTrue(opts.debug)

    def test_non_shell_command_with_its_own_file_value_is_not_rejected(self):
        log_file, remaining = cli.extract_shell_log_file_arg(
            ['import', '--file', 'data.json'], 'import')
        self.assertIsNone(log_file)
        self.assertEqual(remaining, ['import', '--file', 'data.json'])

    def _split(self, argv):
        startup_opts, _ = parser.parse_known_args(argv)
        return cli.extract_shell_log_file_arg(argv, startup_opts.command, startup_opts.options)

    def test_subcommand_file_option_is_left_for_the_subcommand(self):
        log_file, remaining = self._split(['shell', 'import', '--file=data.json'])
        self.assertIsNone(log_file)
        self.assertEqual(remaining, ['shell', 'import', '--file=data.json'])

    def test_subcommand_bare_file_with_a_value_is_left_for_the_subcommand(self):
        log_file, remaining = self._split(['shell', 'debug', '--file', 'x.log'])
        self.assertIsNone(log_file)
        self.assertEqual(remaining, ['shell', 'debug', '--file', 'x.log'])

    def test_startup_flag_and_subcommand_flag_are_kept_apart(self):
        log_file, remaining = self._split(
            ['shell', '--file=session.log', 'import', '--file=data.json'])
        self.assertEqual(log_file, 'session.log')
        self.assertEqual(remaining, ['shell', 'import', '--file=data.json'])

    def test_main_option_value_is_not_taken_as_the_subcommand(self):
        opts = _resolved(['shell', '--user', 'user@example.com', '--file=session.log'])
        self.assertEqual(opts.log_file, 'session.log')
        self.assertEqual(opts.user, 'user@example.com')
        self.assertEqual(opts.options, [])

class TestLogFileHandler(TestCase):
    def setUp(self):
        self.root = logging.getLogger()
        self._old_level = self.root.level
        self._handler_levels = [(h, h.level) for h in self.root.handlers]

    def tearDown(self):
        logging.disable(logging.NOTSET)
        _close_log_files()
        for handler, level in self._handler_levels:
            handler.setLevel(level)
        self.root.setLevel(self._old_level)

    def test_records_are_written_to_the_file_and_the_console(self):
        stream = io.StringIO()
        console = logging.StreamHandler(stream)
        console.setFormatter(logging.Formatter('%(message)s'))
        self.root.addHandler(console)
        self.root.setLevel(logging.INFO)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                attached = cli.debug_manager.attach_log_file(os.path.join(tmp, 'keeper.log'))
                self.assertTrue(attached)
                logging.getLogger('keepercommander.api').info('sync complete')
                logging.getLogger('keepercommander.importer.thycotic').warning('export failed')

                console_text = stream.getvalue()
                self.assertIn('sync complete', console_text)
                self.assertIn('export failed', console_text)

                with open(attached, encoding='utf-8') as handle:
                    file_text = handle.read()
                self.assertIn('sync complete', file_text)
                self.assertIn('export failed', file_text)
                self.assertIn('keepercommander.api', file_text)
                self.assertLess(file_text.index('NEW SESSION STARTED'), file_text.index('sync complete'))

                cli.debug_manager.set_console_debug(True, batch_mode=False)
                self.assertEqual(console.level, logging.DEBUG)
                file_handler = next(h for h in self.root.handlers if getattr(h, cli.KEEPER_LOG_FILE_ATTR, False))
                self.assertEqual(file_handler.level, logging.NOTSET)
                _close_log_files()
        finally:
            self.root.removeHandler(console)

    def test_file_log_drops_console_color_codes(self):
        stream = io.StringIO()
        console = logging.StreamHandler(stream)
        console.setFormatter(logging.Formatter('%(message)s'))
        self.root.addHandler(console)
        self.root.setLevel(logging.INFO)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                attached = cli.debug_manager.attach_log_file(os.path.join(tmp, 'keeper.log'))
                logging.getLogger('keepercommander').info(
                    '\x1b[32mls\x1b[39m            List records'
                )
                logging.getLogger('keepercommander').info(
                    '\x1b[32mΓ£ô\x1b[39m Decrypted 75 records'
                )
                _close_log_files()
                with open(attached, encoding='utf-8') as handle:
                    file_text = handle.read()
                self.assertIn('ls            List records', file_text)
                self.assertIn('Γ£ô Decrypted 75 records', file_text)
                self.assertNotIn('\x1b', file_text)
                console_text = stream.getvalue()
                self.assertIn('\x1b[32mls\x1b[39m            List records', console_text)
        finally:
            self.root.removeHandler(console)

    def test_file_log_skips_blank_lines_that_space_the_console(self):
        stream = io.StringIO()
        console = logging.StreamHandler(stream)
        console.setFormatter(logging.Formatter('%(message)s'))
        self.root.addHandler(console)
        self.root.setLevel(logging.INFO)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                attached = cli.debug_manager.attach_log_file(os.path.join(tmp, 'keeper.log'))
                logging.getLogger('keepercommander').info('Quick Start:')
                logging.getLogger('keepercommander').info('')
                logging.getLogger('keepercommander').info('    ls            List records')
                _close_log_files()
                with open(attached, encoding='utf-8') as handle:
                    file_lines = handle.read().splitlines()
                self.assertTrue(any(line.endswith('Quick Start:') for line in file_lines))
                self.assertTrue(any(line.endswith('ls            List records') for line in file_lines))
                self.assertFalse(any(re.search(r'keepercommander:\s*$', line) for line in file_lines))
                console_lines = stream.getvalue().splitlines()
                self.assertEqual(console_lines, ['Quick Start:', '', '    ls            List records'])
        finally:
            self.root.removeHandler(console)

    def test_custom_file_appends_to_the_same_file(self):
        self.root.setLevel(logging.INFO)
        with tempfile.TemporaryDirectory() as tmp:
            original = os.path.join(tmp, 'custom.log')
            with open(original, 'w', encoding='utf-8') as handle:
                handle.write('previous contents\n')
            attached = cli.debug_manager.attach_log_file(original)
            logging.getLogger('keepercommander.api').info('sync complete')
            _close_log_files()

            self.assertTrue(os.path.samefile(attached, original))
            with open(original, encoding='utf-8') as handle:
                file_text = handle.read()
            self.assertIn('previous contents', file_text)
            self.assertIn('sync complete', file_text)
            self.assertLess(file_text.index('previous contents'), file_text.index('NEW SESSION STARTED'))
            self.assertLess(file_text.index('NEW SESSION STARTED'), file_text.index('sync complete'))
            self.assertRegex(
                file_text,
                r'==================== NEW SESSION STARTED AT : '
                r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2} ====================',
            )
            self.assertNotIn('already exists', file_text)
            self.assertEqual(os.listdir(tmp), ['custom.log'])

    def test_large_existing_file_stays_the_same_file(self):
        self.root.setLevel(logging.INFO)
        with tempfile.TemporaryDirectory() as tmp:
            original = os.path.join(tmp, 'custom.log')
            previous = 'x' * 200
            with open(original, 'w', encoding='utf-8') as handle:
                handle.write(previous)
            attached = cli.debug_manager.attach_log_file(original)
            logging.getLogger('keepercommander.api').info('sync complete')
            _close_log_files()

            self.assertTrue(os.path.samefile(attached, original))
            self.assertEqual(os.listdir(tmp), ['custom.log'])
            with open(original, encoding='utf-8') as handle:
                file_text = handle.read()
            self.assertTrue(file_text.startswith(previous))
            self.assertIn('NEW SESSION STARTED', file_text)
            self.assertIn('sync complete', file_text)

    def test_default_file_appends_to_the_same_file(self):
        self.root.setLevel(logging.INFO)
        with tempfile.TemporaryDirectory() as tmp:
            original = os.path.join(tmp, 'keeper.log')
            with open(original, 'w', encoding='utf-8') as handle:
                handle.write('previous contents\n')
            attached = cli.debug_manager.attach_log_file(original)
            logging.getLogger('keepercommander.api').info('sync complete')
            _close_log_files()
            with open(attached, encoding='utf-8') as handle:
                file_text = handle.read()
            self.assertIn('previous contents', file_text)
            self.assertIn('sync complete', file_text)
            self.assertLess(file_text.index('previous contents'), file_text.index('NEW SESSION STARTED'))
            self.assertLess(file_text.index('NEW SESSION STARTED'), file_text.index('sync complete'))
            self.assertNotIn('already exists', file_text)
            self.assertEqual(os.listdir(tmp), ['keeper.log'])

    def test_bare_file_name_is_created_in_the_current_directory(self):
        self.root.setLevel(logging.INFO)
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                attached = cli.debug_manager.attach_log_file('custom.log')
                logging.getLogger('keepercommander.api').info('stored in the current directory')
                _close_log_files()
            finally:
                os.chdir(cwd)
            self.assertTrue(os.path.samefile(attached, os.path.join(tmp, 'custom.log')))
            self.assertEqual(os.listdir(tmp), ['custom.log'])
            with open(attached, encoding='utf-8') as handle:
                file_text = handle.read()
            self.assertLess(file_text.index('NEW SESSION STARTED'), file_text.index('stored in the current directory'))

    def test_relative_path_with_folders_is_kept(self):
        self.root.setLevel(logging.INFO)
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, 'sub'))
            cwd = os.getcwd()
            os.chdir(os.path.join(tmp, 'sub'))
            try:
                attached = cli.debug_manager.attach_log_file(os.path.join('..', 'up.log'))
                _close_log_files()
            finally:
                os.chdir(cwd)
            self.assertTrue(os.path.samefile(attached, os.path.join(tmp, 'up.log')))

    def test_missing_directory_is_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, 'missing', 'nested', 'custom.log')
            attached = cli.debug_manager.attach_log_file(target)
            self.assertIsNotNone(attached)
            self.assertTrue(os.path.isdir(os.path.join(tmp, 'missing', 'nested')))
            logging.getLogger().warning('into the new folder')
            _close_log_files()
            with open(target, encoding='utf-8') as handle:
                self.assertIn('into the new folder', handle.read())

    def test_relative_missing_directory_is_created_in_the_current_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                attached = cli.debug_manager.attach_log_file(os.path.join('logs', 'debug.log'))
                _close_log_files()
            finally:
                os.chdir(cwd)
            self.assertTrue(os.path.samefile(attached, os.path.join(tmp, 'logs', 'debug.log')))

    def test_file_in_the_parent_path_logs_an_error_and_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, 'blocker.txt')
            with open(blocker, 'w', encoding='utf-8') as handle:
                handle.write('x')
            with self.assertLogs(level='ERROR') as captured:
                self.assertIsNone(cli.debug_manager.attach_log_file(
                    os.path.join(blocker, 'sub', 'custom.log')))
            self.assertIn('is not a directory', captured.output[0])
            self.assertFalse(_has_log_file())

    def test_unwritable_parent_of_a_missing_directory_creates_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch('keepercommander.cli.os.access', return_value=False):
                with self.assertLogs(level='ERROR') as captured:
                    self.assertIsNone(cli.debug_manager.attach_log_file(
                        os.path.join(tmp, 'missing', 'custom.log')))
            self.assertIn('No permission', captured.output[0])
            self.assertEqual(os.listdir(tmp), [])

    def test_directory_as_file_logs_an_error_and_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = os.path.join(tmp, 'dir.log')
            os.makedirs(folder)
            with self.assertLogs(level='ERROR') as captured:
                self.assertIsNone(cli.debug_manager.attach_log_file(folder))
            self.assertIn('is a directory', captured.output[0])

    def test_unwritable_directory_logs_an_error_and_returns_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch('keepercommander.cli.os.access', return_value=False):
                with self.assertLogs(level='ERROR') as captured:
                    self.assertIsNone(cli.debug_manager.attach_log_file(os.path.join(tmp, 'custom.log')))
            self.assertIn('No permission', captured.output[0])
            self.assertEqual(os.listdir(tmp), [])

    def test_session_start_line_has_the_local_offset_without_the_zone_name(self):
        line = cli._session_start_line()
        self.assertRegex(
            line,
            r'^=+ NEW SESSION STARTED AT : '
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2} =+$',
        )
        local = datetime.datetime.now().astimezone()
        if local.tzname():
            self.assertNotIn(local.tzname(), line)

    def test_existing_file_without_a_trailing_newline_keeps_the_marker_on_its_own_line(self):
        self.root.setLevel(logging.INFO)
        with tempfile.TemporaryDirectory() as tmp:
            original = os.path.join(tmp, 'custom.log')
            with open(original, 'w', encoding='utf-8', newline='\n') as handle:
                handle.write('previous contents')
            with mock.patch(
                'keepercommander.cli._session_start_line',
                return_value='==================== NEW SESSION STARTED AT : 2026-11-25T01:40:00+05:30 ====================',
            ):
                cli.debug_manager.attach_log_file(original)
                logging.getLogger('keepercommander.api').info('sync complete')
                _close_log_files()
            with open(original, encoding='utf-8') as handle:
                file_text = handle.read()
            marker = '==================== NEW SESSION STARTED AT : 2026-11-25T01:40:00+05:30 ===================='
            lines = file_text.splitlines()
            self.assertEqual(lines[0], 'previous contents')
            self.assertEqual(lines[1], marker)
            self.assertLess(file_text.index('NEW SESSION STARTED'), file_text.index('sync complete'))


class TestShellCommandDoesNotAttachLogFile(TestCase):
    def test_a_typed_command_keeps_file_and_does_not_open_a_log(self):
        seen = []

        class Dummy:
            def is_authorised(self):
                return False

            def execute_args(self, params, args, **kwargs):
                seen.append(args)

        cli.commands['dummy-log'] = Dummy()
        try:
            with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach:
                cli.do_command(
                    KeeperParams(),
                    'dummy-log --format=thycotic --file=custom.log https://metron.secretservercloud.com',
                )
            attach.assert_not_called()
            self.assertEqual(
                seen,
                ['--format=thycotic --file=custom.log https://metron.secretservercloud.com'],
            )
        finally:
            del cli.commands['dummy-log']



class TestLogFileMain(TestCase):
    def tearDown(self):
        logging.disable(logging.NOTSET)
        _close_log_files()

    def _run(self, argv, from_package=False):
        params = KeeperParams()
        with mock.patch('sys.argv', argv), \
                mock.patch('keepercommander.__main__.get_params_from_config', return_value=params), \
                mock.patch('keepercommander.cli.loop', return_value=0), \
                mock.patch('sys.exit'):
            main(from_package=from_package)
        return params

    def test_shell_default_file_keeps_the_subcommand(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='keeper.log') as attach:
            params = self._run(['keeper', 'shell', '--file', 'login', 'user@example.com'])
        attach.assert_called_once_with(cli.DEFAULT_LOG_FILE)
        self.assertEqual(params.commands, ['login user@example.com'])

    def test_shell_custom_file_is_not_forwarded_as_a_command(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='custom.log') as attach:
            params = self._run(['keeper', 'shell', '--file=custom.log', 'login', 'user@example.com'])
        attach.assert_called_once_with('custom.log')
        self.assertEqual(params.commands, ['login user@example.com'])

    def test_flag_before_shell_does_not_swallow_the_command(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='keeper.log') as attach:
            params = self._run(['keeper', '--file', 'shell', 'login', 'user@example.com'])
        attach.assert_called_once_with(cli.DEFAULT_LOG_FILE)
        self.assertEqual(params.commands, ['login user@example.com'])

    def test_non_shell_command_does_not_open_a_log_file(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach:
            params = self._run(['keeper', 'login', 'user@example.com', '--file=custom.log'])
        attach.assert_not_called()
        self.assertEqual(params.commands, ['login user@example.com --file=custom.log', 'q'])

    def test_keeper_py_without_the_shell_word_opens_the_named_file(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='file1.log') as attach:
            params = self._run(['keeper.py', '--file=file1.log'], from_package=True)
        attach.assert_called_once_with('file1.log')
        self.assertEqual(params.commands, [])

    def test_keeper_py_bare_flag_uses_the_default_file(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='keeper.log') as attach:
            self._run(['keeper.py', '--file'], from_package=True)
        attach.assert_called_once_with(cli.DEFAULT_LOG_FILE)

    def test_keeper_py_writes_the_named_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, 'file1.log')
            self._run(['keeper.py', '--file=' + log_path], from_package=True)
            _close_log_files()
            with open(log_path, encoding='utf-8') as handle:
                body = handle.read()
            self.assertIn('Logging to file:', body)
            self.assertIn('file1.log', body)

    def test_help_or_version_request_does_not_open_a_log_file(self):
        cases = (
            (['keeper', 'shell', '-h', '--file'], False),
            (['keeper', 'shell', '--help', '--file=custom.log'], False),
            (['keeper', 'shell', '--file', 'login', '-h'], False),
            (['keeper', '-', '-h', '--file'], False),
            (['keeper', 'shell', '--version', '--file'], False),
            (['keeper', '--version', 'shell', '--file=custom.log'], False),
            (['keeper.py', '-h', '--file'], True),
            (['keeper.py', '--version', '--file=custom.log'], True),
        )
        for argv, from_package in cases:
            with self.subTest(argv=argv):
                with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach, \
                        mock.patch('builtins.print'), \
                        mock.patch('keepercommander.__main__.show_brief_help'):
                    self._run(argv, from_package=from_package)
                attach.assert_not_called()

    def test_help_request_writes_no_session_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, 'session.log')
            with mock.patch('builtins.print'):
                self._run(['keeper', 'shell', '-h', '--file=' + log_path])
            _close_log_files()
            self.assertFalse(os.path.exists(log_path))

    def test_help_before_the_shell_command_still_opens_the_log_file(self):
        # keeper -h shell starts the shell: -h before the command is not a help request
        # for the shell, so the log must be opened like any other shell start.
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='keeper.log') as attach:
            self._run(['keeper', '-h', 'shell', '--file'])
        attach.assert_called_once_with(cli.DEFAULT_LOG_FILE)

    def test_keeper_py_help_after_another_flag_shows_the_brief_help(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach, \
                mock.patch('keepercommander.__main__.show_brief_help', side_effect=SystemExit) as brief, \
                mock.patch('keepercommander.cli.loop') as loop:
            with self.assertRaises(SystemExit):
                with mock.patch('sys.argv', ['keeper.py', '--debug', '--unknown', '-h', '--file']), \
                        mock.patch('keepercommander.__main__.get_params_from_config', return_value=KeeperParams()):
                    main(from_package=True)
        brief.assert_called_once_with()
        attach.assert_not_called()
        loop.assert_not_called()

    def test_shell_without_help_still_opens_the_log_file(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='keeper.log') as attach:
            self._run(['keeper', 'shell', '--debug', '--file'])
        attach.assert_called_once_with(cli.DEFAULT_LOG_FILE)

    def test_keeper_without_a_command_does_not_open_a_log_file(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach:
            self._run(['keeper', '--file=file1.log'])
        attach.assert_not_called()

    def test_main_writes_the_same_log_line_to_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, 'session.log')
            params = self._run(['keeper', 'shell', '--file=' + log_path])
            _close_log_files()
            self.assertEqual(params.commands, [])
            with open(log_path, encoding='utf-8') as handle:
                body = handle.read()
            self.assertIn('Logging to file:', body)
            self.assertIn('session.log', body)

    def _run_until_exit(self, argv, from_package=False):
        with mock.patch('sys.argv', argv), \
                mock.patch('keepercommander.__main__.get_params_from_config') as get_params, \
                mock.patch('keepercommander.cli.loop') as loop, \
                mock.patch('sys.exit', side_effect=SystemExit) as exit_mock, \
                mock.patch.object(cli.debug_manager, 'attach_log_file') as attach, \
                mock.patch('keepercommander.__main__.logging.error') as log_error:
            # main() resets the logging handlers, so the error call is patched directly.
            with self.assertRaises(SystemExit):
                main(from_package=from_package)
        return exit_mock, attach, loop, get_params, log_error

    def test_bare_flag_with_a_path_exits_with_an_error(self):
        exit_mock, attach, loop, get_params, log_error = self._run_until_exit(
            ['keeper', 'shell', '--file', 'my.log'])
        exit_mock.assert_called_once_with(1)
        attach.assert_not_called()
        loop.assert_not_called()
        get_params.assert_not_called()
        log_error.assert_called_once()
        self.assertIn('--file=my.log', str(log_error.call_args.args[1]))

    def test_keeper_py_bare_flag_with_a_path_does_not_run_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, cli.DEFAULT_LOG_FILE)
            with open(log_path, 'w', encoding='utf-8') as handle:
                handle.write('2026-01-01 00:00:00 INFO keepercommander.command: logout\n')
            exit_mock, attach, loop, _, _ = self._run_until_exit(
                ['keeper.py', '--file', log_path], from_package=True)
        exit_mock.assert_called_once_with(1)
        attach.assert_not_called()
        loop.assert_not_called()

    def test_subcommand_file_option_reaches_the_subcommand(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach:
            params = self._run(['keeper', 'shell', 'import', '--file=data.json'])
        attach.assert_not_called()
        self.assertEqual(params.commands, ['import --file=data.json'])


class TestCommandLogging(TestCase):
    def setUp(self):
        self.root = logging.getLogger()
        self._old_level = self.root.level
        self._handler_levels = [(h, h.level) for h in self.root.handlers]
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.tmp.name, 'commands.log')

    def tearDown(self):
        _close_log_files()
        for handler, level in self._handler_levels:
            handler.setLevel(level)
        self.root.setLevel(self._old_level)
        self.tmp.cleanup()

    def _body(self):
        _close_log_files()
        with open(self.log_path, encoding='utf-8') as handle:
            return handle.read()

    def test_command_is_written_to_the_file_only(self):
        stream = io.StringIO()
        console = logging.StreamHandler(stream)
        self.root.addHandler(console)
        try:
            cli.debug_manager.attach_log_file(self.log_path)
            cli.debug_manager.log_command('  list --format=json  ')
        finally:
            self.root.removeHandler(console)
        self.assertIn('INFO keepercommander.command: list --format\n', self._body())
        self.assertNotIn('list --format', stream.getvalue())

    def test_command_is_written_when_the_root_logger_is_at_warning(self):
        # Batch mode sets the root logger to WARNING; command lines are INFO.
        self.root.setLevel(logging.WARNING)
        cli.debug_manager.attach_log_file(self.log_path)
        cli.debug_manager.log_command('list')
        self.assertIn('INFO keepercommander.command: list\n', self._body())

    def test_command_logger_does_not_reach_the_root_handlers(self):
        self.assertFalse(logging.getLogger(cli.COMMAND_LOGGER_NAME).propagate)

    def test_commands_follow_the_newest_log_file(self):
        other_path = os.path.join(self.tmp.name, 'other.log')
        cli.debug_manager.attach_log_file(self.log_path)
        cli.debug_manager.log_command('first')
        cli.debug_manager.attach_log_file(other_path)
        cli.debug_manager.log_command('second')
        command_logger = logging.getLogger(cli.COMMAND_LOGGER_NAME)
        log_files = [h for h in command_logger.handlers if getattr(h, cli.KEEPER_LOG_FILE_ATTR, False)]
        self.assertEqual(len(log_files), 1)
        body = self._body()
        self.assertIn('first', body)
        self.assertNotIn('second', body)
        with open(other_path, encoding='utf-8') as handle:
            self.assertIn('INFO keepercommander.command: second\n', handle.read())

    def test_detached_log_file_is_not_reopened_by_a_command(self):
        cli.debug_manager.attach_log_file(self.log_path)
        cli.debug_manager._detach_log_files()
        os.remove(self.log_path)
        cli.debug_manager.log_command('list')
        self.assertFalse(os.path.exists(self.log_path))
        command_logger = logging.getLogger(cli.COMMAND_LOGGER_NAME)
        self.assertFalse(any(getattr(h, cli.KEEPER_LOG_FILE_ATTR, False) for h in command_logger.handlers))

    def test_console_debug_toggle_leaves_the_log_file_level_alone(self):
        cli.debug_manager.attach_log_file(self.log_path)
        file_handler = next(h for h in self.root.handlers
                            if getattr(h, cli.KEEPER_LOG_FILE_ATTR, False))
        cli.debug_manager.set_console_debug(True, False)
        self.assertEqual(file_handler.level, logging.NOTSET)
        cli.debug_manager.set_console_debug(False, True)
        self.assertEqual(file_handler.level, logging.NOTSET)

    def test_blank_command_is_not_written(self):
        cli.debug_manager.attach_log_file(self.log_path)
        cli.debug_manager.log_command('   ')
        self.assertNotIn('INFO keepercommander.command:', self._body())

    def test_no_log_file_means_nothing_is_written(self):
        cli.debug_manager.log_command('list')  # must not raise

    def test_user_inputs_in_the_command_are_not_written(self):
        cli.debug_manager.attach_log_file(self.log_path)
        cli.debug_manager.log_command('login user@example.com --password hunter2')
        cli.debug_manager.log_command('record-add -t x login=bob password="a b c"')
        body = self._body()
        self.assertIn('INFO keepercommander.command: login --password\n', body)
        self.assertIn('INFO keepercommander.command: record-add -t\n', body)
        for value in ('user@example.com', 'hunter2', 'login=bob', 'a b c'):
            self.assertNotIn(value, body)


class TestCommandWithoutInputs(TestCase):
    def test_option_values_are_dropped(self):
        self.assertEqual(cli.redact_command_for_log('list --format=json'), 'list --format')
        self.assertEqual(cli.redact_command_for_log('login u -p s3cret'), 'login -p')
        self.assertEqual(cli.redact_command_for_log('x --client-secret abc --token=def'),
                         'x --client-secret --token')

    def test_positional_arguments_and_fields_are_dropped(self):
        self.assertEqual(cli.redact_command_for_log("record-add -t T f.password='x y' title=t"),
                         'record-add -t')

    def test_quoted_value_that_looks_like_an_option_is_dropped(self):
        self.assertEqual(cli.redact_command_for_log('x --title "-a -b" --pw="q -z"'), 'x --title --pw')

    def test_unclosed_quote_is_dropped(self):
        self.assertEqual(cli.redact_command_for_log('x --title "a -b'), 'x --title')

    def test_words_after_double_dash_are_dropped(self):
        self.assertEqual(cli.redact_command_for_log('search -v -- -secret'), 'search -v')

    def test_batch_prefix_is_removed_from_the_name(self):
        self.assertEqual(cli.redact_command_for_log('@list -v'), 'list -v')

    def test_plain_command_is_unchanged(self):
        self.assertEqual(cli.redact_command_for_log('list'), 'list')
        self.assertEqual(cli.redact_command_for_log('  '), '')


class TestDebugFileUsesTheSameLog(TestCase):
    def setUp(self):
        self.root = logging.getLogger()
        self._old_level = self.root.level
        self._handler_levels = [(h, h.level) for h in self.root.handlers]

    def tearDown(self):
        _close_log_files()
        for handler, level in self._handler_levels:
            handler.setLevel(level)
        self.root.setLevel(self._old_level)

    def test_debug_file_writes_info_and_debug_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, 'debug.log')
            self.root.setLevel(logging.INFO)
            self.assertTrue(cli.debug_manager.process_command(['debug', '--file=' + log_path], False))
            logging.info('info line')
            logging.debug('debug line')
            _close_log_files()
            with open(log_path, encoding='utf-8') as handle:
                body = handle.read()
        self.assertIn('NEW SESSION STARTED AT', body)
        self.assertIn('info line', body)
        self.assertIn('debug line', body)

    def test_debug_file_creates_a_missing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, 'logs', 'debug.log')
            self.assertTrue(cli.debug_manager.process_command(['debug', '--file', target], False))
            logging.getLogger().debug('debug record in new folder')
            _close_log_files()
            with open(target, encoding='utf-8') as handle:
                self.assertIn('debug record in new folder', handle.read())

    def test_debug_file_bare_name_goes_to_the_current_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                cli.debug_manager.process_command(['debug', '--file', 'dbg.log'], False)
                _close_log_files()
                self.assertTrue(os.path.isfile(os.path.join(tmp, 'dbg.log')))
            finally:
                os.chdir(cwd)
