"""The usage line of a command shows the command's own name (Command.execute_args prog handling)."""
import argparse
import io
from contextlib import redirect_stdout
from unittest.mock import MagicMock

from keepercommander.commands.base import Command


def _command(prog):
    class _Cmd(Command):
        parser = argparse.ArgumentParser(prog=prog)
        parser.add_argument('--name', '-n', dest='name')

        def get_parser(self):
            return _Cmd.parser

        def execute(self, params, **kwargs):
            return None

    return _Cmd()


def _usage(cmd, **kwargs):
    params = MagicMock()
    params.environment_variables = {}
    out = io.StringIO()
    try:
        with redirect_stdout(out):
            cmd.execute_args(params, '-h', **kwargs)
    except SystemExit:
        pass
    return out.getvalue().splitlines()[0]


def test_group_sub_command_keeps_its_full_name():
    # the shell passes the first word typed ('pam') as `command` to the sub-command of a command group
    assert _usage(_command('pam project import'), command='pam').startswith('usage: pam project import ')


def test_alias_still_renames_the_usage():
    # a real alias (the parser belongs to 'clipboard-copy', the user typed 'find-password')
    assert _usage(_command('clipboard-copy'), command='find-password').startswith('usage: find-password ')


def test_same_name_and_no_command_are_unchanged():
    assert _usage(_command('record-add'), command='record-add').startswith('usage: record-add ')
    assert _usage(_command('delete-all')).startswith('usage: delete-all ')
