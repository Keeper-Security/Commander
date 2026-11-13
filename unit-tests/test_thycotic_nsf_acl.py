#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from keepercommander.importer.thycotic.nsf_acl import (
    thycotic_roles_to_nsf_role,
    thycotic_secret_role_to_nsf_role,
    is_lossy_folder_secret_pair,
    diff_secret_acl,
    nsf_record_shares_for_secret_acl,
    parse_secret_inherit_permissions,
    secret_acl_differs_from_folder_rows,
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
        """Any folder + List secret → viewer (List has no Keeper UI equivalent)."""
        role = thycotic_roles_to_nsf_role('Owner', 'List')
        self.assertEqual(role, 'viewer')

        role = thycotic_roles_to_nsf_role('View', 'List')
        self.assertEqual(role, 'viewer')

        role = thycotic_roles_to_nsf_role('Edit', 'List')
        self.assertEqual(role, 'viewer')

    def test_no_secret_access(self):
        """No secret access → None (no grant)."""
        role = thycotic_roles_to_nsf_role('Owner', None)
        self.assertIsNone(role)

        role = thycotic_roles_to_nsf_role('Owner', '')
        self.assertIsNone(role)

    def test_case_insensitive(self):
        """Role names should be case-insensitive."""
        role = thycotic_roles_to_nsf_role('owner', 'owner')
        self.assertEqual(role, 'full-manager')

        role = thycotic_roles_to_nsf_role('OWNER', 'OWNER')
        self.assertEqual(role, 'full-manager')

    def test_view_folder_view_secret(self):
        """View folder + View secret → viewer."""
        role = thycotic_roles_to_nsf_role('View', 'View')
        self.assertEqual(role, 'viewer')

    def test_view_folder_edit_secret(self):
        """View folder + Edit secret → content-manager."""
        role = thycotic_roles_to_nsf_role('View', 'Edit')
        self.assertEqual(role, 'content-manager')

    def test_view_folder_owner_secret(self):
        """View folder + Owner secret → full-manager."""
        role = thycotic_roles_to_nsf_role('View', 'Owner')
        self.assertEqual(role, 'full-manager')

    def test_no_folder_access_with_secret(self):
        """No folder access role but has secret role → use secret role."""
        role = thycotic_roles_to_nsf_role(None, 'View')
        self.assertEqual(role, 'viewer')

        role = thycotic_roles_to_nsf_role('', 'Owner')
        self.assertEqual(role, 'full-manager')

    def test_no_secret_access_returns_none(self):
        """No secret access (None or empty) → None."""
        role = thycotic_roles_to_nsf_role('Owner', None)
        self.assertIsNone(role)

        role = thycotic_roles_to_nsf_role('Owner', '')
        self.assertIsNone(role)


class TestThycoticSecretRoleMappings(unittest.TestCase):
    """Test secret-only role mappings."""

    def test_secret_list(self):
        """Secret List → viewer (List has no Keeper UI equivalent)."""
        role = thycotic_secret_role_to_nsf_role('List')
        self.assertEqual(role, 'viewer')

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


class TestSecretInheritParsing(unittest.TestCase):

    def test_parse_inherit_false(self):
        self.assertFalse(parse_secret_inherit_permissions({'inheritPermissions': False}))

    def test_parse_inherit_true_default(self):
        self.assertTrue(parse_secret_inherit_permissions({}))

    def test_secret_acl_differs_when_priya_on_secret_only(self):
        folder_rows = [
            {'userId': 1, 'secretAccessRoleName': 'Owner'},
        ]
        secret_rows = [
            {'userId': 1, 'secretAccessRoleName': 'Owner'},
            {'userId': 2, 'secretAccessRoleName': 'View'},
        ]
        self.assertTrue(secret_acl_differs_from_folder_rows(secret_rows, folder_rows))

    def test_secret_acl_same_set(self):
        rows = [{'userId': 1, 'secretAccessRoleName': 'Owner'}]
        self.assertFalse(secret_acl_differs_from_folder_rows(rows, rows))


class TestSecretInheritBrokenRecordShares(unittest.TestCase):
    """Secret inheritPermissions=false → full secret ACL as record shares."""
    def test_broken_inherit_emits_all_secret_grants(self):
        secret_roles = {
            'owner@example.com': 'full-manager',
            'priya@example.com': 'viewer',
        }
        folder_roles = {'owner@example.com': 'full-manager'}
        shares = nsf_record_shares_for_secret_acl(
            secret_roles, folder_roles, secret_inherits_folder_permissions=False)
        self.assertEqual(len(shares), 2)
        self.assertIn(('priya@example.com', 'viewer'), shares)
        self.assertIn(('owner@example.com', 'full-manager'), shares)

    def test_broken_inherit_excludes_keeper_import_user_only(self):
        secret_roles = {
            'sarah.wilson@norvaledynamics.com': 'full-manager',
            'priya.sharma@norvaledynamics.com': 'full-manager',
            'matteo.rossi@norvaledynamics.com': 'viewer',
        }
        import_user = 'sarah.wilson@norvaledynamics.com'
        filtered = {
            e: r for e, r in secret_roles.items()
            if e.lower() != import_user.lower()
        }
        shares = nsf_record_shares_for_secret_acl(
            filtered, {}, secret_inherits_folder_permissions=False)
        self.assertIn(('priya.sharma@norvaledynamics.com', 'full-manager'), shares)
        self.assertIn(('matteo.rossi@norvaledynamics.com', 'viewer'), shares)
        self.assertFalse(any(e.lower() == import_user.lower() for e, _ in shares))

    def test_inheriting_secret_still_uses_deltas(self):
        secret_roles = {'priya@example.com': 'viewer'}
        folder_roles = {}
        shares = nsf_record_shares_for_secret_acl(
            secret_roles, folder_roles, secret_inherits_folder_permissions=True)
        self.assertEqual(shares, [('priya@example.com', 'viewer')])

    def test_inheriting_secret_no_delta_when_roles_match(self):
        secret_roles = {'user@example.com': 'viewer'}
        folder_roles = {'user@example.com': 'viewer'}
        shares = nsf_record_shares_for_secret_acl(
            secret_roles, folder_roles, secret_inherits_folder_permissions=True)
        self.assertEqual(shares, [])


class TestSecretAclOverrides(unittest.TestCase):
    """Test secret-level ACL override scenarios."""

    def test_secret_viewer_folder_content_manager(self):
        """Folder grants content-manager, secret grants viewer → delta."""
        folder_roles = {'user@example.com': 'content-manager'}
        secret_roles = {'user@example.com': 'viewer'}

        deltas = diff_secret_acl(folder_roles, secret_roles)
        self.assertEqual(len(deltas), 1)
        self.assertIn(('user@example.com', 'viewer'), deltas)

    def test_secret_content_manager_folder_viewer(self):
        """Folder grants viewer, secret grants content-manager → delta."""
        folder_roles = {'user@example.com': 'viewer'}
        secret_roles = {'user@example.com': 'content-manager'}

        deltas = diff_secret_acl(folder_roles, secret_roles)
        self.assertEqual(len(deltas), 1)
        self.assertIn(('user@example.com', 'content-manager'), deltas)

    def test_secret_full_manager_folder_viewer(self):
        """Folder grants viewer, secret grants full-manager → delta."""
        folder_roles = {'user@example.com': 'viewer'}
        secret_roles = {'user@example.com': 'full-manager'}

        deltas = diff_secret_acl(folder_roles, secret_roles)
        self.assertEqual(len(deltas), 1)
        self.assertIn(('user@example.com', 'full-manager'), deltas)

    def test_mixed_deltas_and_matches(self):
        """Some users match, some differ."""
        folder_roles = {
            'user1@example.com': 'viewer',
            'user2@example.com': 'content-manager',
            'user3@example.com': 'full-manager',
        }
        secret_roles = {
            'user1@example.com': 'viewer',  # match, no delta
            'user2@example.com': 'full-manager',  # differ, delta
            'user3@example.com': 'viewer',  # differ, delta
        }

        deltas = diff_secret_acl(folder_roles, secret_roles)
        self.assertEqual(len(deltas), 2)
        self.assertIn(('user2@example.com', 'full-manager'), deltas)
        self.assertIn(('user3@example.com', 'viewer'), deltas)


if __name__ == '__main__':
    unittest.main()
