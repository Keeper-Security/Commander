from collections import OrderedDict
import sys
from unittest import TestCase, mock

from keepercommander.commands import base


class TestCommandLineInterface(TestCase):

    def test_command_import(self):
        commands = {}
        aliases = {}
        command_info = OrderedDict()

        #base.register_commands(commands, aliases, command_info)
        base.register_enterprise_commands(commands, aliases, command_info)

    def test_normalize_output_param(self):
        saved_platform = sys.platform
        try:
            # simulate windows platform
            sys.platform = 'win32'
            s = base.normalize_output_param(r'command --output=d:\1\2\aaa')
            self.assertEqual(s, r'command --output=d:/1/2/aaa')

            s = base.normalize_output_param(r'command --output d:\1\2\aaa')
            self.assertEqual(s, r'command --output d:/1/2/aaa')

            s = base.normalize_output_param(r'command d:\1\2\aaa')
            self.assertEqual(s, r'command d:\1\2\aaa')

            s = base.normalize_output_param(r'command --output d:/1/2\ 3/aaa')
            self.assertEqual(s, r'command --output d:/1/2\ 3/aaa')

            # simulate osx platform
            sys.platform = 'darwin'
            s = base.normalize_output_param(r'command --output=d:\1\2\aaa')
            self.assertEqual(s, r'command --output=d:\1\2\aaa')            
        finally:
            sys.platform = saved_platform
