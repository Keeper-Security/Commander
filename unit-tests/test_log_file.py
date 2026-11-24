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
    log_file, explicit, remaining = cli.split_output_file_tokens(argv)
    opts, _ = parser.parse_known_args(remaining)
    opts.log_file = log_file
    opts.log_file_explicit = explicit
    return opts


def _close_log_files():
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, '_keeper_log_file', False):
            root.removeHandler(handler)
            handler.close()


class TestLogFileOption(TestCase):
    def test_absent_flag_does_not_enable_a_file(self):
        opts = _resolved(['shell'])
        self.assertIsNone(opts.log_file)
        self.assertEqual(opts.command, 'shell')

    def test_shell_bare_flag_uses_default_name(self):
        opts = _resolved(['shell', '--output-file'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertFalse(opts.log_file_explicit)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, [])

    def test_shell_equals_form_uses_the_given_name(self):
        opts = _resolved(['shell', '--output-file=custom.log'])
        self.assertEqual(opts.log_file, 'custom.log')
        self.assertTrue(opts.log_file_explicit)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, [])

    def test_shell_equals_form_keeps_the_following_subcommand(self):
        opts = _resolved(['shell', '--output-file=session.log', 'login', 'user@example.com'])
        self.assertEqual(opts.log_file, 'session.log')
        self.assertTrue(opts.log_file_explicit)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, ['login', 'user@example.com'])

    def test_bare_flag_does_not_take_the_next_token_as_the_file_name(self):
        opts = _resolved(['shell', '--output-file', 'login', 'user@example.com'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertFalse(opts.log_file_explicit)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, ['login', 'user@example.com'])

    def test_flag_before_shell_uses_the_default_and_keeps_the_subcommand(self):
        opts = _resolved(['--output-file', 'shell', 'login', 'user@example.com'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, ['login', 'user@example.com'])

    def test_empty_equals_form_uses_default_name(self):
        opts = _resolved(['shell', '--output-file='])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertFalse(opts.log_file_explicit)
        self.assertEqual(opts.command, 'shell')

    def test_user_value_is_not_treated_as_the_command(self):
        opts = _resolved(['--user', 'user@example.com', 'shell', '--output-file=session.log'])
        self.assertEqual(opts.log_file, 'session.log')
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.user, 'user@example.com')

    def test_flag_on_a_non_shell_command_is_left_alone(self):
        log_file, explicit, remaining = cli.split_output_file_tokens(
            ['import', '--output-file', 'https://metron.secretservercloud.com']
        )
        self.assertIsNone(log_file)
        self.assertFalse(explicit)
        self.assertEqual(
            remaining,
            ['import', '--output-file', 'https://metron.secretservercloud.com'],
        )

    def test_last_flag_wins(self):
        opts = _resolved(['shell', '--output-file=a.log', '--output-file'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertFalse(opts.log_file_explicit)
        self.assertEqual(opts.command, 'shell')
        self.assertEqual(opts.options, [])

    def test_flag_without_a_command_is_kept_for_the_package_launcher(self):
        opts = _resolved(['--output-file=file1.log'])
        self.assertEqual(opts.log_file, 'file1.log')
        self.assertTrue(opts.log_file_explicit)
        self.assertIsNone(opts.command)

    def test_bare_flag_without_a_command_uses_the_default_name(self):
        opts = _resolved(['--output-file'])
        self.assertEqual(opts.log_file, cli.DEFAULT_LOG_FILE)
        self.assertFalse(opts.log_file_explicit)
        self.assertIsNone(opts.command)


class TestLogFileHandler(TestCase):
    def setUp(self):
        self.root = logging.getLogger()
        self._old_level = self.root.level
        self._handler_levels = [(h, h.level) for h in self.root.handlers]

    def tearDown(self):
        logging.disable(logging.NOTSET)
        for handler in list(self.root.handlers):
            if getattr(handler, '_keeper_log_file', False):
                self.root.removeHandler(handler)
                handler.close()
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
                file_handler = next(h for h in self.root.handlers if getattr(h, '_keeper_log_file', False))
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
            attached = cli.debug_manager.attach_log_file(original, explicit_name=True)
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
            attached = cli.debug_manager.attach_log_file(original, explicit_name=True)
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
            attached = cli.debug_manager.attach_log_file(original, explicit_name=False)
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

    def test_bare_file_name_is_created_in_the_logs_folder(self):
        self.root.setLevel(logging.INFO)
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch('keepercommander.cli.Path.cwd', return_value=Path(tmp)):
                attached = cli.debug_manager.attach_log_file('custom.log', explicit_name=True)
                logging.getLogger('keepercommander.api').info('stored in the logs folder')
                _close_log_files()
            self.assertEqual(
                os.path.normcase(os.path.abspath(attached)),
                os.path.normcase(str((Path(tmp) / 'logs' / 'custom.log').resolve())),
            )
            with open(attached, encoding='utf-8') as handle:
                file_text = handle.read()
            self.assertIn('stored in the logs folder', file_text)
            self.assertLess(file_text.index('NEW SESSION STARTED'), file_text.index('stored in the logs folder'))

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
                cli.debug_manager.attach_log_file(original, explicit_name=True)
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
    def test_a_typed_command_keeps_output_file_and_does_not_open_a_log(self):
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
                    'dummy-log --format=thycotic --output-file=custom.log https://metron.secretservercloud.com',
                )
            attach.assert_not_called()
            self.assertEqual(
                seen,
                ['--format=thycotic --output-file=custom.log https://metron.secretservercloud.com'],
            )
        finally:
            del cli.commands['dummy-log']



class TestLogFileMain(TestCase):
    def tearDown(self):
        logging.disable(logging.NOTSET)
        root = logging.getLogger()
        for handler in list(root.handlers):
            if getattr(handler, '_keeper_log_file', False):
                root.removeHandler(handler)
                handler.close()

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
            params = self._run(['keeper', 'shell', '--output-file', 'login', 'user@example.com'])
        attach.assert_called_once_with(cli.DEFAULT_LOG_FILE, explicit_name=False)
        self.assertEqual(params.commands, ['login user@example.com'])

    def test_shell_custom_file_is_not_forwarded_as_a_command(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='custom.log') as attach:
            params = self._run(['keeper', 'shell', '--output-file=custom.log', 'login', 'user@example.com'])
        attach.assert_called_once_with('custom.log', explicit_name=True)
        self.assertEqual(params.commands, ['login user@example.com'])

    def test_flag_before_shell_does_not_swallow_the_command(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='keeper.log') as attach:
            params = self._run(['keeper', '--output-file', 'shell', 'login', 'user@example.com'])
        attach.assert_called_once_with(cli.DEFAULT_LOG_FILE, explicit_name=False)
        self.assertEqual(params.commands, ['login user@example.com'])

    def test_non_shell_command_does_not_open_a_log_file(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach:
            params = self._run(['keeper', 'login', 'user@example.com', '--output-file=custom.log'])
        attach.assert_not_called()
        self.assertEqual(params.commands, ['login user@example.com --output-file=custom.log', 'q'])

    def test_keeper_py_without_the_shell_word_opens_the_named_file(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='file1.log') as attach:
            params = self._run(['keeper.py', '--output-file=file1.log'], from_package=True)
        attach.assert_called_once_with('file1.log', explicit_name=True)
        self.assertEqual(params.commands, [])

    def test_keeper_py_bare_flag_uses_the_default_file(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file', return_value='keeper.log') as attach:
            self._run(['keeper.py', '--output-file'], from_package=True)
        attach.assert_called_once_with(cli.DEFAULT_LOG_FILE, explicit_name=False)

    def test_keeper_py_writes_the_named_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, 'file1.log')
            self._run(['keeper.py', '--output-file=' + log_path], from_package=True)
            _close_log_files()
            with open(log_path, encoding='utf-8') as handle:
                body = handle.read()
            self.assertIn('Logging to file:', body)
            self.assertIn('file1.log', body)

    def test_keeper_without_a_command_does_not_open_a_log_file(self):
        with mock.patch.object(cli.debug_manager, 'attach_log_file') as attach:
            self._run(['keeper', '--output-file=file1.log'])
        attach.assert_not_called()

    def test_main_writes_the_same_log_line_to_the_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, 'session.log')
            params = self._run(['keeper', 'shell', '--output-file=' + log_path])
            _close_log_files()
            self.assertEqual(params.commands, [])
            with open(log_path, encoding='utf-8') as handle:
                body = handle.read()
            self.assertIn('Logging to file:', body)
            self.assertIn('session.log', body)