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

import unittest

from keepercommander.service.commands.integrations.command_policy import (
    default_allowlist,
    sanitize_commands,
)


class TestSanitizeCommands(unittest.TestCase):
    def test_strips_commands_outside_allowlist(self):
        result = sanitize_commands('search,get,malicious-command', allowed=['search', 'get'])
        self.assertEqual(set(result.split(',')), {'search', 'get'})

    def test_drops_banned_even_if_in_allowlist_and_input(self):
        result = sanitize_commands(
            'search,get,rm', allowed=['search', 'get', 'rm'], banned=['rm']
        )
        self.assertEqual(set(result.split(',')), {'search', 'get'})

    def test_force_includes_missing_allowed_entries(self):
        result = sanitize_commands('search', allowed=['search', 'get'])
        self.assertEqual(set(result.split(',')), {'search', 'get'})

    def test_empty_input_returns_full_allowlist_minus_banned(self):
        result = sanitize_commands('', allowed=['search', 'get', 'rm'], banned=['rm'])
        self.assertEqual(set(result.split(',')), {'search', 'get'})

    def test_case_insensitive_matching_preserves_original_casing(self):
        result = sanitize_commands('Search,GET', allowed=['search', 'get'])
        self.assertEqual(set(result.split(',')), {'Search', 'GET'})

    def test_whitespace_and_empty_tokens_are_ignored(self):
        result = sanitize_commands(' search , , get ', allowed=['search', 'get'])
        self.assertEqual(set(result.split(',')), {'search', 'get'})


class TestDefaultAllowlist(unittest.TestCase):
    def test_returns_full_allowlist_minus_banned(self):
        result = default_allowlist(['search', 'get', 'rm'], banned=['rm'])
        self.assertEqual(set(result.split(',')), {'search', 'get'})

    def test_no_banned_returns_full_allowlist(self):
        result = default_allowlist(['search', 'get'])
        self.assertEqual(set(result.split(',')), {'search', 'get'})


if __name__ == '__main__':
    unittest.main()
