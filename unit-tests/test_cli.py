from collections import OrderedDict
import sys
from unittest import TestCase, mock

from keepercommander.commands import base
from keepercommander.cli import do_command, read_command_with_continuation
from data_vault import get_connected_params


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

    def test_do_command_no_opts(self):
        params = get_connected_params()
        params.sync_data = False
        with mock.patch('keepercommander.commands.utils.ThisDeviceCommand.print_device_info') \
                as mock_print_dev:
            mock_print_dev.return_value = 'test device info'
            do_command(params, 'this-device')
            mock_print_dev.assert_called()

    def test_line_continuation(self):
        """Test that line continuation with backslash works correctly."""
        params = get_connected_params()
        
        # Mock input to simulate line continuation with varying whitespace
        input_lines = [
            'record-add -t "Test Record" \\',
            '  -rt login \\',  # Leading whitespace 
            '  login=testuser \\',  # Leading whitespace
            '  password=testpass'  # Final line with leading whitespace
        ]
        
        with mock.patch('builtins.input', side_effect=input_lines):
            result = read_command_with_continuation(None, params)
            expected = 'record-add -t "Test Record" -rt login login=testuser password=testpass'
            self.assertEqual(result, expected)

    def test_line_continuation_no_backslash(self):
        """Test that commands without line continuation work normally."""
        params = get_connected_params()
        
        with mock.patch('builtins.input', return_value='record-add -t "Simple Test" -rt login'):
            result = read_command_with_continuation(None, params)
            expected = 'record-add -t "Simple Test" -rt login'
            self.assertEqual(result, expected)

    def test_line_continuation_with_empty_lines(self):
        """Test that empty continuation lines are handled correctly."""
        params = get_connected_params()
        
        # Mock input with empty continuation lines
        input_lines = [
            'record-add -t "Test Record" \\',
            '  \\',  # Empty line with just backslash - should be skipped
            '  -rt login \\',
            'login=testuser'  # Final line without backslash
        ]
        
        with mock.patch('builtins.input', side_effect=input_lines):
            result = read_command_with_continuation(None, params)
            expected = 'record-add -t "Test Record" -rt login login=testuser'
            self.assertEqual(result, expected)

    def test_line_continuation_with_trailing_spaces(self):
        """Test that line continuation handles trailing spaces after backslash gracefully."""
        params = get_connected_params()
        
        # Mock input with trailing spaces after backslashes (common user error)
        input_lines = [
            'record-add -t "Gmail Account" -rt login \\ ',   # space after backslash
            '  login=john.doe@gmail.com \\  ',              # spaces after backslash
            '  password=SecurePass123 \\	',               # tab after backslash
            '  url=https://accounts.google.com'
        ]
        
        with mock.patch('builtins.input', side_effect=input_lines):
            result = read_command_with_continuation(None, params)
            expected = 'record-add -t "Gmail Account" -rt login login=john.doe@gmail.com password=SecurePass123 url=https://accounts.google.com'
            self.assertEqual(result, expected)
