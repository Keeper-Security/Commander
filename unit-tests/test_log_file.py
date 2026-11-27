import datetime
import io
import logging
import os
import tempfile
from unittest import TestCase, mock

from keepercommander import cli
from keepercommander.__main__ import _extract_shell_log_file, main, parser
from keepercommander.params import KeeperParams


class _FixedDatetime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 11, 27, 14, 46, 35, tzinfo=tz)


def _read(path):
    cli.debug_manager._detach_log_file()
    with open(path, encoding='utf-8') as handle:
        return handle.read()


class TestLogFileOption(TestCase):
    def _parse(self, argv):
        log_file, remaining = _extract_shell_log_file(parser, argv)
        opts, _ = parser.parse_known_args(remaining)
        return log_file, opts, remaining

    def test_valid_shell_startup_forms(self):
        cases = (
            (['shell'], None, 'shell', []),
            (['shell', '--file'], cli.DEFAULT_LOG_FILE, 'shell', []),
            (['shell', '--file=custom.log'], 'custom.log', 'shell', []),
            (['shell', '--file=session.log', 'login', 'u@example.com'], 'session.log', 'shell', ['login', 'u@example.com']),
            (['shell', '--file', 'login', 'u@example.com'], cli.DEFAULT_LOG_FILE, 'shell', ['login', 'u@example.com']),
            (['--file', 'shell', 'login', 'u@example.com'], cli.DEFAULT_LOG_FILE, 'shell', ['login', 'u@example.com']),
            (['--user', 'u@example.com', 'shell', '--file=session.log'], 'session.log', 'shell', []),
            (['shell', '--user', 'u@example.com', '--file=session.log'], 'session.log', 'shell', []),
            (['--config', 'shell', 'shell', '--file=session.log'], 'session.log', 'shell', []),
            (['shell', '--file=a.log', '--file'], cli.DEFAULT_LOG_FILE, 'shell', []),
            (['shell', '--file', 'ls'], cli.DEFAULT_LOG_FILE, 'shell', ['ls']),
            (['shell', '--file', '--debug'], cli.DEFAULT_LOG_FILE, 'shell', []),
            (['--file=file1.log'], 'file1.log', None, []),
            (['--file'], cli.DEFAULT_LOG_FILE, None, []),
        )
        for argv, expected_file, expected_cmd, expected_opts in cases:
            with self.subTest(argv=argv):
                log_file, opts, _ = self._parse(argv)
                self.assertEqual(log_file, expected_file)
                self.assertEqual(opts.command, expected_cmd)
                self.assertEqual(opts.options, expected_opts)

    def test_non_shell_and_subcommand_flags_are_left_alone(self):
        cases = (
            (['import', '--file', 'https://example.com'], None, ['import', '--file', 'https://example.com']),
            (['import', '--file', 'data.json'], None, ['import', '--file', 'data.json']),
            (['shell', 'import', '--file=data.json'], None, ['shell', 'import', '--file=data.json']),
            (['shell', 'debug', '--file', 'x.log'], None, ['shell', 'debug', '--file', 'x.log']),
            (['shell', '--file=session.log', 'import', '--file=data.json'],
             'session.log', ['shell', 'import', '--file=data.json']),
        )
        for argv, expected_file, expected_remaining in cases:
            with self.subTest(argv=argv):
                self.assertEqual(_extract_shell_log_file(parser, argv), (expected_file, expected_remaining))

    def test_invalid_file_flag_forms_raise(self):
        for argv in (
            ['shell', '--file', 'my.log'],
            ['shell', '--file', 'logs/session.txt'],
            ['shell', '--file', 'debug'],
            ['-', '--file', 'my.log'],
            ['--file', 'my.log', 'shell'],
            ['--file', cli.DEFAULT_LOG_FILE],
            ['shell', '--file='],
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(ValueError) as ctx:
                    _extract_shell_log_file(parser, argv)
                self.assertIn(cli.DEFAULT_LOG_FILE, str(ctx.exception))


class LoggingTestCase(TestCase):
    def setUp(self):
        self.root = logging.getLogger()
        self._old_level = self.root.level
        self._handler_levels = [(h, h.level) for h in self.root.handlers]
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.root.setLevel(logging.INFO)

    def tearDown(self):
        logging.disable(logging.NOTSET)
        cli.debug_manager._detach_log_file()
        for handler, level in self._handler_levels:
            handler.setLevel(level)
        self.root.setLevel(self._old_level)
        self._tmp.cleanup()

    def console(self):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter('%(message)s'))
        self.root.addHandler(handler)
        self.addCleanup(self.root.removeHandler, handler)
        return stream


class TestLogFileHandler(LoggingTestCase):
    def test_records_reach_file_and_console_without_changing_file_level(self):
        stream = self.console()
        path = cli.debug_manager.attach_log_file(os.path.join(self.tmp, 'keeper.log'))
        logging.getLogger('keepercommander.api').info('\x1b[32mls\x1b[39m sync complete')
        logging.getLogger('keepercommander').warning('export failed')
        cli.debug_manager.set_console_debug(True, batch_mode=False)
        self.assertEqual(cli.debug_manager._log_file_handler.level, logging.NOTSET)

        self.assertIn('\x1b[32mls\x1b[39m sync complete', stream.getvalue())
        body = _read(path)
        self.assertRegex(
            body,
            r'^=+ NEW SESSION STARTED AT : \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2} =+\n',
        )
        self.assertIn('INFO keepercommander.api: \x1b[32mls\x1b[39m sync complete\n', body)
        self.assertIn('WARNING keepercommander: export failed\n', body)

    def test_existing_custom_file_appends_with_newline_before_marker(self):
        path = os.path.join(self.tmp, 'custom.log')
        with open(path, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write('previous contents')
        attached = cli.debug_manager.attach_log_file(path)
        logging.getLogger('keepercommander.api').info('sync complete')
        self.assertTrue(os.path.samefile(attached, path))
        lines = _read(path).splitlines()
        self.assertEqual(lines[0], 'previous contents')
        self.assertRegex(lines[1], r'^=+ NEW SESSION STARTED AT : .+ =+$')
        self.assertIn('sync complete', lines[-1])
        self.assertEqual(os.listdir(self.tmp), ['custom.log'])

    def test_existing_default_file_rotates_and_handles_collisions(self):
        default = os.path.join(self.tmp, 'keeper.log')
        with open(default, 'w', encoding='utf-8') as handle:
            handle.write('previous contents\n')
        open(os.path.join(self.tmp, 'keeper.2026-11-27.14-46-35.log'), 'w').close()

        with mock.patch('keepercommander.cli.datetime.datetime', _FixedDatetime):
            path = cli.debug_manager.attach_log_file(default)
        logging.getLogger('keepercommander.api').info('sync complete')
        self.assertEqual(os.path.basename(path), 'keeper.2026-11-27.14-46-35.1.log')
        self.assertEqual(_read(default), 'previous contents\n')
        self.assertIn('sync complete', _read(path))

    def test_missing_directory_and_directory_targets(self):
        nested_log = os.path.join(self.tmp, 'missing', 'nested', 'custom.log')
        self.assertIsNotNone(cli.debug_manager.attach_log_file(nested_log))
        logging.warning('into the new folder')
        self.assertIn('into the new folder', _read(nested_log))

        folder = os.path.join(self.tmp, 'dir.log')
        os.makedirs(folder)
        attached = cli.debug_manager.attach_log_file(folder)
        cli.debug_manager._detach_log_file()
        self.assertEqual(os.path.dirname(attached), os.path.realpath(folder))
        self.assertEqual(os.path.basename(attached), cli.DEFAULT_LOG_FILE)

    def test_failed_attach_logs_error_and_preserves_existing_log(self):
        first = cli.debug_manager.attach_log_file(os.path.join(self.tmp, 'first.log'))
        blocker = os.path.join(self.tmp, 'blocker.txt')
        open(blocker, 'w').close()
        with self.assertLogs(level='ERROR') as captured:
            self.assertIsNone(cli.debug_manager.attach_log_file(os.path.join(blocker, 'sub', 'bad.log')))
        self.assertTrue(captured.output)
        logging.info('still logging to first')
        self.assertIn('still logging to first', _read(first))

        with mock.patch('keepercommander.cli.os.makedirs', side_effect=PermissionError('No permission')), \
                self.assertLogs(level='ERROR') as captured:
            self.assertIsNone(cli.debug_manager.attach_log_file(os.path.join(self.tmp, 'blocked', 'x.log')))
        self.assertIn('No permission', captured.output[0])


class TestCommandAndDebugLogging(LoggingTestCase):
    def test_redact_command_for_log(self):
        cases = (
            ('list --format=json', 'list --format'),
            ('login u -p s3cret', 'login -p'),
            ("record-add -t T f.password='x y' title=t", 'record-add -t'),
            (r'x --title="secret\" -leaked" --pw="q -z"', 'x --title --pw'),
            ('x --title "a -b', 'x --title'),
            ('search -v -- -secret', 'search -v'),
            ('@list -v', 'list -v'),
            ('   ', ''),
            ('@', ''),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(cli.redact_command_for_log(raw), expected)

    def test_command_logged_to_file_only_even_in_batch_mode(self):
        stream = self.console()
        self.root.setLevel(logging.WARNING)
        path = cli.debug_manager.attach_log_file(os.path.join(self.tmp, 'commands.log'))
        cli.debug_manager.log_command('login user@example.com --password hunter2')
        cli.debug_manager.log_command('   ')
        body = _read(path)
        self.assertIn('INFO keepercommander.command: login --password\n', body)
        self.assertNotIn('hunter2', body)
        self.assertNotIn('login', stream.getvalue())

    def test_commands_follow_reattached_file_and_stop_when_detached(self):
        first = os.path.join(self.tmp, 'first.log')
        second = os.path.join(self.tmp, 'second.log')
        cli.debug_manager.attach_log_file(first)
        cli.debug_manager.log_command('first-cmd')
        cli.debug_manager.attach_log_file(second)
        cli.debug_manager.log_command('second-cmd')
        self.assertIn('first-cmd', _read(first))
        self.assertIn('second-cmd', _read(second))

        os.remove(second)
        cli.debug_manager.log_command('after-detach')
        self.assertFalse(os.path.exists(second))

    def test_debug_file_writes_debug_without_enabling_console_debug(self):
        stream = self.console()
        path = os.path.join(self.tmp, 'logs', 'debug.log')
        self.assertTrue(cli.debug_manager.process_command(['debug', '--file=' + path], False))
        logging.info('info line')
        logging.debug('debug line')
        body = _read(path)
        for text in ('NEW SESSION STARTED AT', 'info line', 'debug line'):
            self.assertIn(text, body)
        self.assertIn('info line', stream.getvalue())
        self.assertNotIn('debug line', stream.getvalue())

    def test_toggle_console_debug_turns_off_when_started_with_debug(self):
        self.console()
        self.root.setLevel(logging.DEBUG)
        self.assertFalse(cli.debug_manager.toggle_console_debug(False))

    def test_typed_command_keeps_file_flag(self):
        seen = []

        class Dummy:
            def is_authorised(self):
                return False

            def execute_args(self, params, args, **kwargs):
                seen.append(args)

        cli.commands['dummy-log'] = Dummy()
        try:
            with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach:
                cli.do_command(KeeperParams(), 'dummy-log --file=custom.log arg1')
            attach.assert_not_called()
            self.assertEqual(seen, ['--file=custom.log arg1'])
        finally:
            del cli.commands['dummy-log']


class TestLogFileMain(LoggingTestCase):
    def _run(self, argv, from_package=False):
        params = KeeperParams()
        with mock.patch('sys.argv', argv), \
                mock.patch('keepercommander.__main__.get_params_from_config', return_value=params), \
                mock.patch('keepercommander.cli.loop', return_value=0), \
                mock.patch('sys.exit'):
            main(from_package=from_package)
        return params

    def test_shell_and_package_launcher_attach_log_file(self):
        cases = (
            (['keeper', 'shell', '--file', 'login', 'u@example.com'], False, cli.DEFAULT_LOG_FILE, ['login u@example.com']),
            (['keeper', '--file', 'shell', 'login', 'u@example.com'], False, cli.DEFAULT_LOG_FILE, ['login u@example.com']),
            (['keeper', 'shell', '--file=custom.log', 'login', 'u@example.com'], False, 'custom.log', ['login u@example.com']),
            (['keeper', '-h', 'shell', '--file'], False, cli.DEFAULT_LOG_FILE, []),
            (['keeper.py', '--file=file1.log'], True, 'file1.log', []),
            (['keeper.py', '--file'], True, cli.DEFAULT_LOG_FILE, []),
        )
        for argv, from_package, expected_file, expected_cmds in cases:
            with self.subTest(argv=argv):
                with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value=expected_file) as attach:
                    params = self._run(argv, from_package=from_package)
                attach.assert_called_once_with(expected_file)
                self.assertEqual(params.commands, expected_cmds)

    def test_help_version_or_non_shell_does_not_open_log_file(self):
        cases = (
            (['keeper', 'login', 'u@example.com', '--file=custom.log'], False),
            (['keeper', 'shell', 'import', '--file=data.json'], False),
            (['keeper', '--file=file1.log'], False),
            (['keeper', 'shell', '-h', '--file'], False),
            (['keeper', 'shell', '--file', 'login', '-h'], False),
            (['keeper', '-', '-h', '--file'], False),
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

    def test_shell_writes_logging_announcement_to_file(self):
        log_path = os.path.join(self.tmp, 'session.log')
        self._run(['keeper', 'shell', '--file=' + log_path])
        self.assertIn('Logging to file:', _read(log_path))

    def test_bare_flag_with_path_exits_with_error(self):
        for argv, from_package in (
            (['keeper', 'shell', '--file', 'my.log'], False),
            (['keeper.py', '--file', cli.DEFAULT_LOG_FILE], True),
        ):
            with self.subTest(argv=argv):
                with mock.patch('sys.argv', argv), \
                        mock.patch('keepercommander.__main__.get_params_from_config') as get_params, \
                        mock.patch('keepercommander.cli.loop') as loop, \
                        mock.patch('sys.exit', side_effect=SystemExit) as exit_mock, \
                        mock.patch.object(cli.debug_manager, 'attach_log_file') as attach, \
                        mock.patch('keepercommander.__main__.logging.error'):
                    with self.assertRaises(SystemExit):
                        main(from_package=from_package)
                exit_mock.assert_called_once_with(1)
                attach.assert_not_called()
                get_params.assert_not_called()
                loop.assert_not_called()
