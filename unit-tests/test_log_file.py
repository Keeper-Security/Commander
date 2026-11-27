import io
import logging
import os
import tempfile
from unittest import TestCase, mock

from keepercommander import cli, file_logging
from keepercommander.__main__ import main, parser
from keepercommander.params import KeeperParams


def _split(argv):
    startup_opts = file_logging.parse_startup_command(parser, argv)
    return file_logging.extract_shell_log_file_arg(argv, startup_opts.command, startup_opts.options)


def _read(path):
    cli.debug_manager._detach_log_files()
    with open(path, encoding='utf-8') as handle:
        return handle.read()


class TestLogFileOption(TestCase):
    def test_equals_form_keeps_the_following_subcommand(self):
        self.assertEqual(_split(['shell', '--file=session.log', 'login', 'u@example.com']),
                         ('session.log', ['shell', 'login', 'u@example.com']))

    def test_bare_flag_does_not_take_the_next_token_as_the_file_name(self):
        for argv in (['shell', '--file', 'login'], ['--file', 'shell', 'login']):
            with self.subTest(argv=argv):
                self.assertEqual(_split(argv), (file_logging.DEFAULT_LOG_FILE, ['shell', 'login']))

    def test_flag_on_a_non_shell_command_is_left_alone(self):
        argv = ['import', '--file', 'https://metron.secretservercloud.com']
        self.assertEqual(_split(argv), (None, argv))

    def test_startup_flag_and_subcommand_flag_are_kept_apart(self):
        self.assertEqual(_split(['shell', '--file=session.log', 'import', '--file=data.json']),
                         ('session.log', ['shell', 'import', '--file=data.json']))

    def test_bare_flag_followed_by_a_path_is_rejected(self):
        for argv in (['shell', '--file', 'my.log'],
                     ['-', '--file', 'logs/session.txt'],
                     ['--file', 'my.log', 'shell'],
                     # Without a command the path would be run as a batch file.
                     ['--file', file_logging.DEFAULT_LOG_FILE]):
            with self.subTest(argv=argv):
                with self.assertRaises(file_logging.LogFileOptionError) as ctx:
                    _split(argv)
                self.assertIn('--file=' + argv[argv.index('--file') + 1], str(ctx.exception))


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
        cli.debug_manager._detach_log_files()
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
    def test_records_reach_the_file_and_the_console(self):
        stream = self.console()
        path = cli.debug_manager.attach_log_file(os.path.join(self.tmp, 'keeper.log'))
        logging.getLogger('keepercommander.api').info('\x1b[32mls\x1b[39m sync complete')
        logging.getLogger('keepercommander').warning('export failed')
        self.assertIn('\x1b[32mls\x1b[39m sync complete', stream.getvalue())
        body = _read(path)
        self.assertRegex(body, r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} INFO keepercommander\.api: '
                               r'\x1b\[32mls\x1b\[39m sync complete\n')
        self.assertIn('WARNING keepercommander: export failed\n', body)

    def test_existing_file_is_appended_after_a_session_marker(self):
        path = os.path.join(self.tmp, 'custom.log')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write('previous contents\n')
        cli.debug_manager.attach_log_file(path)
        logging.getLogger('keepercommander.api').info('sync complete')
        body = _read(path)
        self.assertRegex(body, r'^previous contents\n=+ NEW SESSION STARTED AT : '
                               r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2} =+\n')
        self.assertLess(body.index('NEW SESSION STARTED'), body.index('sync complete'))
        self.assertEqual(os.listdir(self.tmp), ['custom.log'])

    def test_existing_default_file_gets_a_new_timestamped_file(self):
        default = os.path.join(self.tmp, 'keeper.log')
        with open(default, 'w', encoding='utf-8') as handle:
            handle.write('previous contents\n')
        path = cli.debug_manager.attach_log_file(default)
        logging.getLogger('keepercommander.api').info('sync complete')
        self.assertRegex(os.path.basename(path),
                         r'^keeper\.\d{4}-\d{2}-\d{2}\.\d{2}-\d{2}-\d{2}\.log$')
        self.assertEqual(os.path.dirname(path), os.path.realpath(self.tmp))
        self.assertEqual(_read(default), 'previous contents\n')
        self.assertIn('sync complete', _read(path))
        self.assertNotIn('previous contents', _read(path))

    def test_missing_default_file_is_created_with_the_default_name(self):
        path = cli.debug_manager.attach_log_file(os.path.join(self.tmp, 'keeper.log'))
        self.assertEqual(os.path.basename(path), 'keeper.log')

    def test_timestamped_name_gets_a_suffix_when_already_taken(self):
        import datetime
        now = datetime.datetime(2026, 11, 27, 14, 46, 35)
        for name in ('keeper.log', 'keeper.2026-11-27.14-46-35.log'):
            open(os.path.join(self.tmp, name), 'w').close()
        path = cli.debug_manager._timestamped_default_log_file_path(
            os.path.join(self.tmp, 'keeper.log'), now=now)
        self.assertEqual(os.path.basename(path), 'keeper.2026-11-27.14-46-35.1.log')

    def test_missing_directory_is_created(self):
        path = os.path.join(self.tmp, 'missing', 'nested', 'custom.log')
        self.assertIsNotNone(cli.debug_manager.attach_log_file(path))
        logging.warning('into the new folder')
        self.assertIn('into the new folder', _read(path))

    def test_directory_target_writes_the_default_file_inside_it(self):
        nested = os.path.join(self.tmp, 'sub')
        os.mkdir(nested)
        cwd = os.getcwd()
        try:
            os.chdir(nested)
            for target, folder in (('./', nested), ('.', nested), ('../', self.tmp), ('..', self.tmp)):
                with self.subTest(target=target):
                    path = cli.debug_manager.attach_log_file(target)
                    cli.debug_manager._detach_log_files()
                    self.assertEqual(os.path.dirname(path), os.path.realpath(folder))
                    self.assertTrue(os.path.basename(path).startswith('keeper.'))
        finally:
            os.chdir(cwd)

    def test_missing_directory_with_trailing_separator_gets_the_default_file(self):
        path = cli.debug_manager.attach_log_file(os.path.join(self.tmp, 'new', ''))
        cli.debug_manager._detach_log_files()
        self.assertEqual(path, os.path.join(os.path.realpath(self.tmp), 'new', file_logging.DEFAULT_LOG_FILE))

    def test_unwritable_parent_logs_an_error_and_creates_nothing(self):
        with mock.patch('keepercommander.file_logging.os.access', return_value=False), \
                self.assertLogs(level='ERROR') as captured:
            self.assertIsNone(cli.debug_manager.attach_log_file(
                os.path.join(self.tmp, 'missing', 'custom.log')))
        self.assertIn('No permission', captured.output[0])
        self.assertEqual(os.listdir(self.tmp), [])


class TestCommandLogging(LoggingTestCase):
    def test_command_is_written_to_the_file_only_without_user_inputs(self):
        stream = self.console()
        path = cli.debug_manager.attach_log_file(os.path.join(self.tmp, 'commands.log'))
        cli.debug_manager.log_command("record-add -t T f.password='x y' --title=secret")
        self.assertIn('INFO keepercommander.command: record-add -t --title\n', _read(path))
        self.assertNotIn('record-add', stream.getvalue())
        self.assertNotIn('x y', _read(path))

    def test_command_is_written_when_the_root_logger_is_at_warning(self):
        # Batch mode sets the root logger to WARNING; command lines are INFO.
        self.root.setLevel(logging.WARNING)
        path = cli.debug_manager.attach_log_file(os.path.join(self.tmp, 'commands.log'))
        cli.debug_manager.log_command('list')
        self.assertIn('INFO keepercommander.command: list\n', _read(path))

    def test_debug_file_writes_info_and_debug_records(self):
        path = os.path.join(self.tmp, 'debug.log')
        self.assertTrue(cli.debug_manager.process_command(['debug', '--file=' + path], False))
        logging.info('info line')
        logging.debug('debug line')
        body = _read(path)
        for text in ('NEW SESSION STARTED AT', 'info line', 'debug line'):
            self.assertIn(text, body)


class TestLogFileMain(TestCase):
    def tearDown(self):
        logging.disable(logging.NOTSET)
        cli.debug_manager._detach_log_files()

    def _run(self, argv, from_package=False):
        params = KeeperParams()
        with mock.patch('sys.argv', argv), mock.patch('sys.exit'), \
                mock.patch('keepercommander.__main__.get_params_from_config', return_value=params), \
                mock.patch('keepercommander.cli.loop', return_value=0):
            main(from_package=from_package)
        return params

    def test_shell_writes_the_log_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'session.log')
            self.assertEqual(self._run(['keeper', 'shell', '--file=' + path]).commands, [])
            self.assertIn('Logging to file:', _read(path))

    def test_help_or_version_request_does_not_open_a_log_file(self):
        for argv, from_package in ((['keeper', 'shell', '-h', '--file'], False),
                                   (['keeper', 'shell', '--file', 'login', '-h'], False),
                                   (['keeper', '--version', 'shell', '--file=a.log'], False),
                                   (['keeper.py', '-h', '--file'], True)):
            with self.subTest(argv=argv):
                with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach, \
                        mock.patch('builtins.print'), \
                        mock.patch('keepercommander.__main__.show_brief_help'):
                    self._run(argv, from_package=from_package)
                attach.assert_not_called()

    def test_keeper_py_bare_flag_with_a_path_exits_without_running_it(self):
        with mock.patch('sys.argv', ['keeper.py', '--file', file_logging.DEFAULT_LOG_FILE]), \
                mock.patch('keepercommander.__main__.get_params_from_config'), \
                mock.patch('keepercommander.cli.loop') as loop, \
                mock.patch('sys.exit', side_effect=SystemExit) as exit_mock, \
                mock.patch.object(cli.debug_manager, 'attach_log_file') as attach, \
                mock.patch('keepercommander.__main__.logging.error'):
            with self.assertRaises(SystemExit):
                main(from_package=True)
        exit_mock.assert_called_once_with(1)
        attach.assert_not_called()
        loop.assert_not_called()
