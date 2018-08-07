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
    from .record import register_commands as record_commands
    record_commands(commands, aliases, command_info)

    from .folder import register_commands as folder_commands
    folder_commands(commands, aliases, command_info)

    from .register import register_commands as register_commands
    register_commands(commands, aliases, command_info)

    from .utils import register_commands as misc_commands
    misc_commands(commands, aliases, command_info)

    command_info['shell'] = 'Use Keeper interactive shell'
    command_info['c'] = 'Clear the screen'
    command_info['h'] = 'Show command history'
    command_info['q'] = 'Quit'


def register_enterprise_commands(commands, aliases, command_info):
    from .enterprise import register_commands as enterprise_commands
    enterprise_commands(commands, aliases, command_info)


def unregister_enterprise_commands(commands, aliases, command_info):
    from .enterprise import unregister_commands as remove_enterprise_commands
    remove_enterprise_commands(commands, aliases, command_info)


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
