#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import argparse
import logging

from keepercommander import cli
from .base import raise_parse_exception, suppress_exit, Command


def register_commands(commands):
    commands['run-batch'] = RunBatchCommand()


def register_command_info(aliases, command_info):
    aliases['run'] = 'run-batch'
    command_info[run_batch_parser.prog] = run_batch_parser.description


run_batch_parser = argparse.ArgumentParser(prog='run-batch', description='Run batch of Commander commands from a file')
run_batch_parser.add_argument(
    '-d', '--delay', dest='delay', action='store', help='Delay between commands to prevent throttling'
)
run_batch_parser.add_argument(
    '-q', '--quiet', dest='quiet', action='store_true', help="Don't display batch file info"
)
run_batch_parser.add_argument(
    '-n', '--dry-run', dest='dry_run', action='store_true', help='Preview the commands that will be run'
)
run_batch_parser.add_argument(
    'batch-file-patterns', nargs='*', type=str, action='store', help='One or more batch files of Commander commands'
)
run_batch_parser.error = raise_parse_exception
run_batch_parser.exit = suppress_exit


class RunBatchCommand(Command):
    def get_parser(self):
        return run_batch_parser

    def execute(self, params, **kwargs):
        pass
