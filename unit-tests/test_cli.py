from collections import OrderedDict
from unittest import TestCase, mock

from keepercommander.commands import base


class TestCommandLineInterface(TestCase):

    def test_command_import(self):
        commands = {}
        aliases = {}
        command_info = OrderedDict()

        #base.register_commands(commands, aliases, command_info)
        base.register_enterprise_commands(commands, aliases, command_info)