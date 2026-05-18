"""Minimal security regression tests for `connect` / `ssh`."""

import unittest
from types import SimpleNamespace
from unittest import mock

from keepercommander.commands import connect, connect_prompts as cp


def _record():
    return SimpleNamespace(record_uid='rec-1', title='Shared SSH', custom=[])


class TestGatesBlockOnDenial(unittest.TestCase):
    def test_execute_shell_does_not_run_subprocess_on_denial(self):
        inst = connect.BaseConnectCommand.__new__(connect.BaseConnectCommand)
        inst.command = 'bash -c "rm -rf /"'
        inst.run_at_the_end = []
        with mock.patch.object(connect.subprocess, 'run') as run, \
                mock.patch('builtins.input', return_value='n'):
            inst.execute_shell(record=_record(), stage='test')
        run.assert_not_called()

    def test_pre_and_post_do_not_run_subprocess_on_denial(self):
        cmd = connect.ConnectCommand.__new__(connect.ConnectCommand)
        cmd.command = ''
        cmd.run_at_the_end = []
        fields = {
            'connect:ssh:pre':  'bash -c "evil-pre"',
            'connect:ssh:post': 'bash -c "evil-post"',
        }
        with mock.patch.object(
                connect.BaseConnectCommand, 'get_custom_field',
                side_effect=lambda r, n: fields.get(n)), \
                mock.patch.object(
                connect.ConnectCommand, 'get_custom_field',
                side_effect=lambda r, n: fields.get(n)), \
                mock.patch.object(
                connect.BaseConnectCommand, 'get_command_string',
                side_effect=lambda p, r, t, tf, **kw: t), \
                mock.patch.object(
                connect.ConnectCommand, 'add_ssh_keys',
                side_effect=lambda *a, **kw: iter(())), \
                mock.patch.object(
                connect.ConnectCommand, 'add_environment_variables',
                side_effect=lambda *a, **kw: iter(())), \
                mock.patch.object(connect.subprocess, 'run') as run, \
                mock.patch('builtins.input', return_value='n'):
            cmd.connect_endpoint(SimpleNamespace(), 'ssh', _record())
        run.assert_not_called()

    def test_env_does_not_putenv_on_denial(self):
        with mock.patch.object(
                connect.ConnectCommand, 'get_fields_by_patters',
                return_value=[('connect:ssh:env:LD_PRELOAD', '/tmp/evil.so')]), \
                mock.patch.object(connect.os, 'putenv') as pe, \
                mock.patch('builtins.input', return_value='n'):
            list(connect.ConnectCommand.add_environment_variables(
                SimpleNamespace(), 'ssh', _record(), []))
        pe.assert_not_called()

    def test_ssh_keys_do_not_load_on_denial(self):
        with mock.patch.object(
                connect, 'try_extract_private_key',
                return_value=('PEMDATA', '')), \
                mock.patch.object(
                connect.ConnectCommand, 'get_fields_by_patters',
                return_value=[]), \
                mock.patch.object(connect, 'add_ssh_key') as ask, \
                mock.patch('builtins.input', return_value='n'):
            list(connect.ConnectCommand.add_ssh_keys(
                SimpleNamespace(), 'ssh', _record(), []))
        ask.assert_not_called()


class TestDefaultDeny(unittest.TestCase):
    def test_empty_input_is_no(self):
        with mock.patch('builtins.input', return_value=''):
            self.assertFalse(cp.read_yes_no())

    def test_eof_is_no(self):
        with mock.patch('builtins.input', side_effect=EOFError):
            self.assertFalse(cp.read_yes_no())

    def test_unrecognised_answer_is_no(self):
        for resp in ('n', 'N', 'no', 'maybe', '1', 'true', 'Y E S'):
            with mock.patch('builtins.input', return_value=resp):
                self.assertFalse(cp.read_yes_no(), resp)

    def test_yes_variants_are_yes(self):
        for resp in ('y', 'Y', 'yes', 'YES', '  y  '):
            with mock.patch('builtins.input', return_value=resp):
                self.assertTrue(cp.read_yes_no(), resp)


class TestSplitterDoesNotHidePayloads(unittest.TestCase):
    def test_quoted_semicolons_are_not_separators(self):
        self.assertEqual(
            cp.split_shell_statements('echo "a; b"; rm -rf /'),
            ['echo "a; b"', 'rm -rf /'],
        )


class TestRecordTextIsSanitized(unittest.TestCase):
    def test_ansi_escape_in_record_title_is_stripped(self):
        evil = 'Connect\x1b[2J\x1b[H<fake prompt>'
        self.assertEqual(cp._sanitize(evil), 'Connect[2J[H<fake prompt>')

    def test_other_controls_are_stripped(self):
        self.assertEqual(cp._sanitize('a\x00b\x07c\x7fd'), 'abcd')


if __name__ == '__main__':
    unittest.main()
