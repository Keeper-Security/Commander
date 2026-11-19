import glob
import os
import re
import tempfile
from unittest import TestCase

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))


class TestCommandHelpAndSkill(TestCase):
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

    def test_keeper_commander_skill_md_exists_and_is_synced(self):
        skill_path = os.path.join(REPO_ROOT, '.agents', 'skills', 'keeper-commander', 'SKILL.md')
        resource_skill_path = os.path.join(REPO_ROOT, 'keepercommander', 'resources', 'SKILL.md')
        self.assertTrue(os.path.isfile(skill_path), f'Missing {skill_path}')
        self.assertTrue(os.path.isfile(resource_skill_path), f'Missing {resource_skill_path}')
        with open(skill_path, encoding='utf-8') as f:
            content = f.read()
        with open(resource_skill_path, encoding='utf-8') as f:
            resource_content = f.read()
        self.assertEqual(content, resource_content)
        self.assertTrue(content.startswith('---\nname: keeper-commander\n'))
        self.assertIn('description:', content)
        self.assertIn('keeper ai-setup --target copilot', content)
        self.assertIn('--format json', content)
        self.assertIn('enterprise-info', content)
        self.assertIn('allow_pam_rotation', content)
        self.assertIn('Safety Guardrails', content)

    def test_ai_setup_command_registered_in_utils(self):
        utils_path = os.path.join(REPO_ROOT, 'keepercommander', 'commands', 'utils.py')
        with open(utils_path, encoding='utf-8') as f:
            utils_src = f.read()
        self.assertIn("commands['ai-setup'] = AiSetupCommand()", utils_src)
        self.assertIn("prog='ai-setup'", utils_src)
        self.assertIn("choices=['m365-copilot', 'copilot', 'claude', 'cursor', 'agents', 'all']", utils_src)
        self.assertIn('Configure Keeper Commander for your AI Assistant:', utils_src)
