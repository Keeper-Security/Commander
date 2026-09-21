#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

import os
import unittest
from dataclasses import dataclass
from typing import Optional
from unittest import mock

from keepercommander.service.commands.integrations.gchat_app_setup import GChatAppSetupCommand
from keepercommander.service.commands.integrations.runtime_policy import apply_runtime_command_policy
from keepercommander.service.commands.integrations.sailpoint_app_setup import SailPointAppSetupCommand
from keepercommander.service.commands.integrations.slack_app_setup import SlackAppSetupCommand
from keepercommander.service.commands.terraform_app_setup import TerraformSetupConstants
from keepercommander.service.decorators.min_commander_version import TERRAFORM_DOCKER_ENV, TERRAFORM_DOCKER_ENV_LEGACY
from keepercommander.service.util.exceptions import ValidationError


@dataclass
class _Args:
    commands: Optional[str]


class TestApplyRuntimeCommandPolicy(unittest.TestCase):
    def test_noop_when_no_integration_env_var_set(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            args = _Args(commands='search,malicious-command')
            apply_runtime_command_policy(args)
        self.assertEqual(args.commands, 'search,malicious-command')

    def test_noop_when_commands_none(self):
        with mock.patch.dict(os.environ, {'SLACK_RECORD': 'uid-123'}, clear=True):
            args = _Args(commands=None)
            apply_runtime_command_policy(args)
        self.assertIsNone(args.commands)

    def test_empty_commands_normalizes_to_integration_default(self):
        # Matches compose-generation behavior: empty falls back to the integration's
        # own default allowlist rather than leaving the service with no commands.
        allowed = set(SlackAppSetupCommand().get_service_commands().split(','))
        with mock.patch.dict(os.environ, {'SLACK_RECORD': 'uid-123'}, clear=True):
            args = _Args(commands='')
            apply_runtime_command_policy(args)
        self.assertEqual(set(args.commands.split(',')), allowed)

    def test_slack_record_env_confines_to_slack_allowlist(self):
        allowed = set(SlackAppSetupCommand().get_service_commands().split(','))
        with mock.patch.dict(os.environ, {'SLACK_RECORD': 'uid-123'}, clear=True):
            args = _Args(commands='search,malicious-command,rm')
            apply_runtime_command_policy(args)
        self.assertEqual(set(args.commands.split(',')), allowed)
        self.assertNotIn('malicious-command', args.commands.split(','))
        self.assertNotIn('rm', args.commands.split(','))

    def test_gchat_record_env_confines_to_gchat_allowlist(self):
        allowed = set(GChatAppSetupCommand().get_service_commands().split(','))
        with mock.patch.dict(os.environ, {'GCHAT_RECORD': 'uid-456'}, clear=True):
            args = _Args(commands='download-attachment')
            apply_runtime_command_policy(args)
        self.assertEqual(set(args.commands.split(',')), allowed)

    def test_terraform_env_confines_to_terraform_allowlist(self):
        with mock.patch.dict(os.environ, {TERRAFORM_DOCKER_ENV: 'tf-record-uid'}, clear=True):
            args = _Args(commands=TerraformSetupConstants.SERVICE_COMMANDS + ',clipboard-copy')
            apply_runtime_command_policy(args)
        self.assertEqual(
            set(args.commands.split(',')), set(TerraformSetupConstants.SERVICE_COMMANDS_LIST)
        )

    def test_legacy_terraform_env_confines_to_terraform_allowlist(self):
        """A container upgraded without re-running terraform-app-setup still has the old
        KEEPER_TERRAFORM marker -- the startup sanitizer must not silently skip it."""
        with mock.patch.dict(os.environ, {TERRAFORM_DOCKER_ENV_LEGACY: '1'}, clear=True):
            args = _Args(commands=TerraformSetupConstants.SERVICE_COMMANDS + ',clipboard-copy')
            apply_runtime_command_policy(args)
        self.assertEqual(
            set(args.commands.split(',')), set(TerraformSetupConstants.SERVICE_COMMANDS_LIST)
        )

    def test_sailpoint_record_env_confines_to_sailpoint_allowlist(self):
        # Fallback path: applies even if SailPointService.maybe_enable() skipped sanitizing.
        allowed = set(SailPointAppSetupCommand().get_service_commands().split(','))
        with mock.patch.dict(os.environ, {'SAILPOINT_RECORD': 'uid-789'}, clear=True):
            args = _Args(commands='search,download-attachment,ksm')
            apply_runtime_command_policy(args)
        self.assertEqual(set(args.commands.split(',')), allowed)
        self.assertNotIn('download-attachment', args.commands.split(','))

    def test_multiple_integration_env_vars_raises(self):
        with mock.patch.dict(
            os.environ, {'SLACK_RECORD': 'uid-1', TERRAFORM_DOCKER_ENV: 'tf-record-uid'}, clear=True
        ):
            args = _Args(commands='search,malicious-command')
            with self.assertRaises(ValidationError):
                apply_runtime_command_policy(args)


if __name__ == '__main__':
    unittest.main()
