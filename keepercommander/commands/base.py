#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#


import argparse
import shlex

from ..params import KeeperParams


def register_commands(commands, aliases, command_info):
    from .record import register_commands as record_commands, register_command_info as record_command_info
    record_commands(commands)
    record_command_info(aliases, command_info)

    from .folder import register_commands as folder_commands, register_command_info as folder_command_info
    folder_commands(commands)
    folder_command_info(aliases, command_info)

    from .register import register_commands as register_commands, register_command_info as register_command_info
    register_commands(commands)
    register_command_info(aliases, command_info)

    from .utils import register_commands as misc_commands, register_command_info as misc_command_info
    misc_commands(commands)
    misc_command_info(aliases, command_info)


def register_enterprise_commands(commands, aliases, command_info):
    from .enterprise import register_commands as enterprise_commands, register_command_info as enterprise_command_info
    enterprise_commands(commands)
    enterprise_command_info(aliases, command_info)


def user_choice(question, choice, default='', show_choice=True, multi_choice=False):
    choices = [ch.lower() if ch.upper() == default.upper() else ch.lower()  for ch in choice]

    result = ''
    while True:
        pr = question
        if show_choice:
            pr = pr + ' [' + '/'.join(choices) + ']'

        pr = pr + ': '
        result = input(pr)

        if len(result) == 0:
            return default

        if multi_choice:
            s1 = set([x.lower() for x in choices])
            s2 = set([x.lower() for x in result])
            if s2 < s1:
                return ''.join(s2)
            pass
        elif any(map(lambda x: x.upper() == result.upper(), choices)):
            return result

        print('Error: invalid input')


def raise_parse_exception(m):
    raise Exception(m)


def suppress_exit():
    raise Exception()


class Command:
    def execute(self, params, **kwargs):
        '''
        :type params: KeeperParams
        '''
        raise NotImplemented()

    def execute_args(self, params, args, **kwargs):
        try:
            parser = self.get_parser()
            d = {}
            d.update(kwargs)
            if parser is not None:
                opts = parser.parse_args(shlex.split(args))
                d.update(opts.__dict__)

            self.execute(params, **d)
        except Exception as e:
            print(e)

    def get_parser(self):
        '''
        :rtype: argparse.ArgumentParser
        '''
        return None

    def is_authorised(self):
        return True
