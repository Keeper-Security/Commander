import glob
import os
import re
from unittest import TestCase

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class TestCommandHelpDescriptions(TestCase):
    def test_all_active_command_parsers_have_description(self):
        pattern = os.path.join(REPO_ROOT, 'keepercommander', 'commands', '**', '*.py')
        missing = []
        for path in sorted(glob.glob(pattern, recursive=True)):
            if os.path.basename(path) == 'discoveryrotation_v1.py':
                continue
            with open(path, encoding='utf-8') as f:
                text = f.read()
            for match in re.finditer(r'argparse\.ArgumentParser\(([^)]*)\)', text, re.S):
                args_str = match.group(1)
                if 'prog=' in args_str and 'description=' not in args_str:
                    line_no = text[:match.start()].count('\n') + 1
                    rel_path = os.path.relpath(path, REPO_ROOT)
                    missing.append(f'{rel_path}:{line_no}')
        self.assertEqual(
            missing,
            [],
            f'Command ArgumentParser definitions missing description=: {missing}',
        )
