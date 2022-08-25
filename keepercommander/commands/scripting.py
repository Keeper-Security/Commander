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
import time
from glob import glob
from os.path import normpath

from .. import cli
from .base import raise_parse_exception, suppress_exit, Command


def register_commands(commands):
    commands['run-batch'] = RunBatchCommand()
    commands['sleep'] = SleepCommand()


def register_command_info(aliases, command_info):
    aliases['run'] = 'run-batch'
    command_info[run_batch_parser.prog] = run_batch_parser.description
    command_info[sleep_parser.prog] = sleep_parser.description


run_batch_parser = argparse.ArgumentParser(prog='run-batch', description='Run batch of Commander commands from a file')
run_batch_parser.add_argument(
    '-d', '--delay', dest='delay', type=int, action='store',
    help='Delay (in seconds) between commands to prevent throttling'
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


sleep_parser = argparse.ArgumentParser(
    prog='sleep', description='Sleep (in seconds) for adding delay between batch commands'
)
sleep_parser.add_argument(
    'sleep-duration', nargs='?', type=int, action='store', help='Sleep duration in seconds'
)
sleep_parser.error = raise_parse_exception
sleep_parser.exit = suppress_exit


class RunBatchCommand(Command):
    def get_parser(self):
        return run_batch_parser

    def execute(self, params, **kwargs):
        dry_run = kwargs.get('dry_run', False)
        command_delay = kwargs.get('delay') or 0
        quiet = kwargs.get('quiet', False)
        pattern_list = kwargs.get('batch-file-patterns', [])
        if len(pattern_list) == 0:
            logging.warning(f'Please specify one or more batch files to run')
            return

        if dry_run:
            print('The following files and commands would be run:')
        for pattern in pattern_list:
            for filepath in glob(pattern):
                filepath = normpath(filepath)
                if dry_run:
                    print(f'{filepath}:')
                elif not quiet:
                    logging.info(f'Running Keeper Commander batch file {filepath}...')

                with open(filepath) as f:
                    lines = f.readlines()
                    commands = [c.strip() for c in lines if not c.startswith('#')]
                    if len(commands) > 0:
                        if dry_run:
                            print('    ' + '\n    '.join(commands))
                        else:
                            cli.runcommands(params, commands=commands, command_delay=command_delay, quiet=quiet)
                    else:
                        if dry_run:
                            print('No commands')
                        else:
                            logging.warning(f'No commands to execute in batch file {filepath}')


class SleepCommand(Command):
    def get_parser(self):
        return sleep_parser

    def execute(self, params, **kwargs):
        sleep_duration = kwargs.get('sleep-duration')
        if sleep_duration is None:
            logging.warning(f'Please specify the sleep duration in seconds')
            return
        time.sleep(sleep_duration)
