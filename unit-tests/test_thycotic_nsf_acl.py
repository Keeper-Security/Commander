#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from keepercommander.importer.thycotic.nsf_acl import (
    thycotic_roles_to_nsf_role,
    thycotic_secret_role_to_nsf_role,
    is_lossy_folder_secret_pair,
    diff_secret_acl,
)


class TestThycoticNsfAclRoleMappings(unittest.TestCase):
    """Test role mappings from Delinea to NSF."""

    def test_folder_owner_secret_owner(self):
        """Owner folder + Owner secret → full-manager."""
        role = thycotic_roles_to_nsf_role('Owner', 'Owner')
        self.assertEqual(role, 'full-manager')

    def test_folder_owner_secret_edit(self):
        """Owner folder + Edit secret → full-manager."""
        role = thycotic_roles_to_nsf_role('Owner', 'Edit')
        self.assertEqual(role, 'full-manager')

    def test_folder_edit_secret_owner(self):
        """Edit folder + Owner secret → content-manager."""
        role = thycotic_roles_to_nsf_role('Edit', 'Owner')
        self.assertEqual(role, 'content-manager')

    def test_folder_edit_secret_edit(self):
        """Edit folder + Edit secret → content-manager."""
        role = thycotic_roles_to_nsf_role('Edit', 'Edit')
        self.assertEqual(role, 'content-manager')

    def test_folder_add_secret_secret_owner(self):
        """Add Secret folder + Owner secret → content-manager."""
        role = thycotic_roles_to_nsf_role('Add Secret', 'Owner')
        self.assertEqual(role, 'content-manager')

    def test_folder_owner_secret_view_lossy(self):
        """Owner folder + View secret → viewer (lossy)."""
        role = thycotic_roles_to_nsf_role('Owner', 'View')
        self.assertEqual(role, 'viewer')

    def test_folder_edit_secret_view_lossy(self):
        """Edit folder + View secret → viewer (lossy)."""
        role = thycotic_roles_to_nsf_role('Edit', 'View')
        self.assertEqual(role, 'viewer')

    def test_any_folder_secret_list(self):
        """Any folder + List secret → requestor."""
        role = thycotic_roles_to_nsf_role('Owner', 'List')
        self.assertEqual(role, 'requestor')

        role = thycotic_roles_to_nsf_role('View', 'List')
        self.assertEqual(role, 'requestor')

    def test_no_secret_access(self):
        """No secret access → None (no grant)."""
        role = thycotic_roles_to_nsf_role('Owner', None)
        self.assertIsNone(role)

        role = thycotic_roles_to_nsf_role(None, 'Owner')
        self.assertIsNone(role)

    def test_case_insensitive(self):
        """Role names should be case-insensitive."""
        role = thycotic_roles_to_nsf_role('owner', 'owner')
        self.assertEqual(role, 'full-manager')

        role = thycotic_roles_to_nsf_role('OWNER', 'OWNER')
        self.assertEqual(role, 'full-manager')


class TestThycoticSecretRoleMappings(unittest.TestCase):
    """Test secret-only role mappings."""

    def test_secret_list(self):
        """Secret List → requestor."""
        role = thycotic_secret_role_to_nsf_role('List')
        self.assertEqual(role, 'requestor')

    def test_secret_view(self):
        """Secret View → viewer."""
        role = thycotic_secret_role_to_nsf_role('View')
        self.assertEqual(role, 'viewer')

    def test_secret_edit(self):
        """Secret Edit → content-manager."""
        role = thycotic_secret_role_to_nsf_role('Edit')
        self.assertEqual(role, 'content-manager')

    def test_secret_owner(self):
        """Secret Owner → full-manager."""
        role = thycotic_secret_role_to_nsf_role('Owner')
        self.assertEqual(role, 'full-manager')

    def test_secret_none(self):
        """None input → None."""
        role = thycotic_secret_role_to_nsf_role(None)
        self.assertIsNone(role)


class TestLossyRoleDetection(unittest.TestCase):
    """Test detection of lossy role mappings."""

    def test_owner_folder_view_secret(self):
        """Owner folder + View secret is lossy."""
        is_lossy = is_lossy_folder_secret_pair('Owner', 'View')
        self.assertTrue(is_lossy)

    def test_edit_folder_view_secret(self):
        """Edit folder + View secret is lossy."""
        is_lossy = is_lossy_folder_secret_pair('Edit', 'View')
        self.assertTrue(is_lossy)

    def test_owner_folder_owner_secret(self):
        """Owner folder + Owner secret is not lossy."""
        is_lossy = is_lossy_folder_secret_pair('Owner', 'Owner')
        self.assertFalse(is_lossy)

    def test_view_folder_view_secret(self):
        """View folder + View secret is not lossy."""
        is_lossy = is_lossy_folder_secret_pair('View', 'View')
        self.assertFalse(is_lossy)

    def test_none_input(self):
        """None input is not lossy."""
        is_lossy = is_lossy_folder_secret_pair(None, 'View')
        self.assertFalse(is_lossy)

        is_lossy = is_lossy_folder_secret_pair('Owner', None)
        self.assertFalse(is_lossy)


class TestSecretAclDiff(unittest.TestCase):
    """Test ACL diffing for secret-only overrides."""

    def test_no_deltas(self):
        """No differences → empty list."""
        folder_roles = {'user1@example.com': 'viewer'}
        secret_roles = {'user1@example.com': 'viewer'}

        deltas = diff_secret_acl(folder_roles, secret_roles)
        self.assertEqual(len(deltas), 0)

    def test_secret_more_permissive(self):
        """Secret role more permissive → delta."""
        folder_roles = {'user1@example.com': 'viewer'}
        secret_roles = {'user1@example.com': 'content-manager'}

        deltas = diff_secret_acl(folder_roles, secret_roles)
        self.assertEqual(len(deltas), 1)
        self.assertIn(('user1@example.com', 'content-manager'), deltas)

    def test_secret_less_permissive(self):
        """Secret role less permissive → delta."""
        folder_roles = {'user1@example.com': 'content-manager'}
        secret_roles = {'user1@example.com': 'viewer'}

        deltas = diff_secret_acl(folder_roles, secret_roles)
        self.assertEqual(len(deltas), 1)
        self.assertIn(('user1@example.com', 'viewer'), deltas)

    def test_secret_only_user(self):
        """User only in secret roles → delta."""
        folder_roles = {}
        secret_roles = {'user2@example.com': 'viewer'}

        deltas = diff_secret_acl(folder_roles, secret_roles)
        self.assertEqual(len(deltas), 1)
        self.assertIn(('user2@example.com', 'viewer'), deltas)

    def test_multiple_deltas(self):
        """Multiple differences → multiple deltas."""
        folder_roles = {
            'user1@example.com': 'viewer',
            'user2@example.com': 'content-manager',
        }
        secret_roles = {
            'user1@example.com': 'content-manager',
            'user2@example.com': 'content-manager',
            'user3@example.com': 'viewer',
        }

        deltas = diff_secret_acl(folder_roles, secret_roles)
        self.assertEqual(len(deltas), 2)
        self.assertIn(('user1@example.com', 'content-manager'), deltas)
        self.assertIn(('user3@example.com', 'viewer'), deltas)


if __name__ == '__main__':
    unittest.main()
