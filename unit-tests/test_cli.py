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

    def test_normalize_output_param(self):
        with mock.patch('sys.platform') as mock_os:
            mock_os.return_value = 'win_mock'
            s = base.normalize_output_param(r'command --output=d:\1\2\aaa')
            self.assertEqual(s, r'command --output=d:/1/2/aaa')

            s = base.normalize_output_param(r'command --output d:\1\2\aaa')
            self.assertEqual(s, r'command --output d:/1/2/aaa')

            s = base.normalize_output_param(r'command d:\1\2\aaa')
            self.assertEqual(s, r'command d:\1\2\aaa')

           s = base.normalize_output_param(r'command --output d:/1/2\ 3/aaa')
            self.assertEqual(s, r'command --output d:/1/2\ 3/aaa')

        with mock.patch('sys.platform') as mock_os:
            mock_os.return_value = 'mac_mock'
            s = base.normalize_output_param(r'command --output=d:\1\2\aaa')
            self.assertEqual(s, r'command --output=d:\1\2\aaa')
