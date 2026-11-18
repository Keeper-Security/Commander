#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from keepercommander.importer.thycotic.nsf_acl import (
    thycotic_secret_role_to_nsf_role,
    diff_secret_acl,
    nsf_record_shares_for_secret_acl,
    parse_secret_inherit_permissions,
    secret_acl_differs_from_folder_rows,
    thycotic_folder_role_to_nsf_role,
    folder_roles_by_email,
    record_roles_by_email,
)


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

    def test_unrecognized_folder_role_returns_none(self):
        """Unrecognized folder role should return None, not default."""
        role = thycotic_folder_role_to_nsf_role('UnknownRole')
        self.assertIsNone(role)

    def test_unrecognized_secret_role_returns_none(self):
        """Unrecognized secret role should return None, not default."""
        role = thycotic_secret_role_to_nsf_role('UnknownRole')
        self.assertIsNone(role)

    def test_folder_role_case_insensitive(self):
        """Folder role mapping is case-insensitive."""
        role1 = thycotic_folder_role_to_nsf_role('OWNER')
        role2 = thycotic_folder_role_to_nsf_role('owner')
        role3 = thycotic_folder_role_to_nsf_role('Owner')
        self.assertEqual(role1, 'full-manager')
        self.assertEqual(role2, 'full-manager')
        self.assertEqual(role3, 'full-manager')

    def test_broken_secret_role_returns_none(self):
        """Empty / unknown secret roles do not grant viewer."""
        self.assertIsNone(thycotic_secret_role_to_nsf_role(''))
        self.assertIsNone(thycotic_secret_role_to_nsf_role('   '))
        self.assertIsNone(thycotic_secret_role_to_nsf_role('NotARole'))


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

    def test_parse_enable_inherit_permissions_true(self):
        self.assertTrue(parse_secret_inherit_permissions({'enableInheritPermissions': True}))

    def test_parse_enable_inherit_permissions_false(self):
        self.assertFalse(parse_secret_inherit_permissions({'enableInheritPermissions': False}))

    def test_parse_enable_inherit_permissions_prefers_over_legacy(self):
        self.assertFalse(parse_secret_inherit_permissions({
            'enableInheritPermissions': False,
            'inheritPermissions': True,
        }))

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


USERS = {
    1: {'emailAddress': 'sarah@example.com'},
    2: {'emailAddress': 'priya@example.com'},
    3: {'emailAddress': 'david@example.com'},
    4: {'emailAddress': 'clint@example.com'},
}
GROUPS = {
    10: {'name': 'test_group', 'users': [3, 4]},
}


class TestEmailNormalization(unittest.TestCase):
    """Test email normalization and role weight handling."""

    def test_email_normalization_case_insensitive(self):
        """Email addresses should be normalized to lowercase."""
        perm_rows = [
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'Owner'},
        ]
        roles = folder_roles_by_email(perm_rows, USERS, {})
        # sarah@example.com should be stored as lowercase
        self.assertIn('sarah@example.com', roles)
        self.assertEqual(roles['sarah@example.com'], 'full-manager')

    def test_role_weight_higher_role_not_overwritten(self):
        """Higher-priority role should not be overwritten by lower-priority."""
        perm_rows = [
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'Owner'},  # full-manager (weight 3)
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'View'},   # viewer (weight 1)
        ]
        roles = folder_roles_by_email(perm_rows, USERS, {})
        # full-manager should be kept, not overwritten to viewer
        self.assertEqual(roles.get('sarah@example.com'), 'full-manager')

    def test_role_weight_lower_to_higher_upgrade(self):
        """Lower-priority role should be upgraded to higher-priority."""
        perm_rows = [
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'View'},   # viewer (weight 1)
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'Owner'},  # full-manager (weight 3)
        ]
        roles = folder_roles_by_email(perm_rows, USERS, {})
        # Should upgrade to full-manager
        self.assertEqual(roles.get('sarah@example.com'), 'full-manager')

    def test_role_weight_edit_not_overwritten_by_view(self):
        """Edit (content-manager) should not be overwritten by View (viewer)."""
        perm_rows = [
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'Edit'},   # content-manager
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'View'},   # viewer
        ]
        roles = folder_roles_by_email(perm_rows, USERS, {})
        self.assertEqual(roles.get('sarah@example.com'), 'content-manager')

    def test_role_weight_owner_not_overwritten_by_edit(self):
        """Owner (full-manager) should not be overwritten by Edit (content-manager)."""
        perm_rows = [
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'Owner'},  # full-manager
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'Edit'},   # content-manager
        ]
        roles = folder_roles_by_email(perm_rows, USERS, {})
        self.assertEqual(roles.get('sarah@example.com'), 'full-manager')

    def test_role_weight_multiple_users_correct_roles(self):
        """Different users should have their own correct roles."""
        perm_rows = [
            {'userId': 1, 'groupId': 0, 'folderAccessRoleName': 'Owner'},   # sarah: full-manager
            {'userId': 2, 'groupId': 0, 'folderAccessRoleName': 'Edit'},    # priya: content-manager
            {'userId': 3, 'groupId': 0, 'folderAccessRoleName': 'View'},    # david: viewer
        ]
        roles = folder_roles_by_email(perm_rows, USERS, {})
        self.assertEqual(roles.get('sarah@example.com'), 'full-manager')
        self.assertEqual(roles.get('priya@example.com'), 'content-manager')
        self.assertEqual(roles.get('david@example.com'), 'viewer')


class TestFolderOnlyRoleMapping(unittest.TestCase):
    """Keeper folder role comes from the Delinea folder permission only."""

    def test_folder_roles(self):
        self.assertEqual(thycotic_folder_role_to_nsf_role('Owner'), 'full-manager')
        self.assertEqual(thycotic_folder_role_to_nsf_role('Edit'), 'content-manager')
        self.assertEqual(thycotic_folder_role_to_nsf_role('Add Secret'), 'content-manager')
        self.assertEqual(thycotic_folder_role_to_nsf_role('View'), 'viewer')

    def test_folder_role_case_and_empty(self):
        self.assertEqual(thycotic_folder_role_to_nsf_role('  owner '), 'full-manager')
        self.assertIsNone(thycotic_folder_role_to_nsf_role(None))
        self.assertIsNone(thycotic_folder_role_to_nsf_role(''))

    def test_folder_roles_ignore_secret_role(self):
        rows = [
            {'userId': 2, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'View'},
            {'userId': 3, 'folderAccessRoleName': 'View', 'secretAccessRoleName': 'Owner'},
        ]
        roles = folder_roles_by_email(rows, USERS, GROUPS)
        self.assertEqual(roles, {'priya@example.com': 'full-manager', 'david@example.com': 'viewer'})

    def test_folder_group_members_and_user_row_wins(self):
        rows = [
            {'groupId': 10, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
            {'userId': 4, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'Owner'},
        ]
        roles = folder_roles_by_email(rows, USERS, GROUPS)
        self.assertEqual(roles, {'david@example.com': 'content-manager', 'clint@example.com': 'full-manager'})

    def test_group_higher_role_not_downgraded_by_direct_user(self):
        """Direct user View must not overwrite a group Owner grant."""
        rows = [
            {'groupId': 10, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'Owner'},
            {'userId': 3, 'folderAccessRoleName': 'View', 'secretAccessRoleName': 'View'},
        ]
        roles = folder_roles_by_email(rows, USERS, GROUPS)
        self.assertEqual(roles.get('david@example.com'), 'full-manager')
        self.assertEqual(roles.get('clint@example.com'), 'full-manager')

    def test_direct_user_equal_weight_beats_group(self):
        """On a tie, the direct user row wins over the group grant."""
        rows = [
            {'groupId': 10, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
            {'userId': 3, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
        ]
        roles = folder_roles_by_email(rows, USERS, GROUPS)
        self.assertEqual(roles.get('david@example.com'), 'content-manager')

    def test_folder_group_filtered_when_team_missing(self):
        rows = [{'groupId': 10, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'}]
        roles = folder_roles_by_email(rows, USERS, GROUPS, group_filter=lambda g: False)
        self.assertEqual(roles, {})

    def test_broken_folder_permission_rows_skipped(self):
        """Missing / unknown folder roles and empty principals are ignored."""
        rows = [
            {'userId': 2, 'folderAccessRoleName': 'NotARole'},
            {'userId': 0, 'groupId': 0, 'folderAccessRoleName': 'Owner'},
            {'userId': 2, 'folderAccessRoleName': 'Edit'},
        ]
        roles = folder_roles_by_email(rows, USERS, GROUPS)
        self.assertEqual(roles, {'priya@example.com': 'content-manager'})


class TestRecordRolesAndShares(unittest.TestCase):
    """Record role comes from the Delinea secret permission; shares only on differences."""

    def test_record_roles_from_secret_role(self):
        rows = [
            {'userId': 2, 'folderAccessRoleName': 'Add Secret', 'secretAccessRoleName': 'Owner'},
            {'userId': 3, 'secretAccessRoleName': 'List'},
        ]
        roles = record_roles_by_email(rows, USERS, GROUPS)
        self.assertEqual(roles, {'priya@example.com': 'full-manager', 'david@example.com': 'viewer'})

    def test_inherit_on_folder_owner_secret_view_gets_viewer_share(self):
        rows = [{'userId': 2, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'View'}]
        shares = nsf_record_shares_for_secret_acl(
            record_roles_by_email(rows, USERS, GROUPS), folder_roles_by_email(rows, USERS, GROUPS))
        self.assertEqual(shares, [('priya@example.com', 'viewer')])

    def test_inherit_on_folder_view_secret_owner_gets_full_manager_share(self):
        rows = [{'userId': 2, 'folderAccessRoleName': 'View', 'secretAccessRoleName': 'Owner'}]
        shares = nsf_record_shares_for_secret_acl(
            record_roles_by_email(rows, USERS, GROUPS), folder_roles_by_email(rows, USERS, GROUPS))
        self.assertEqual(shares, [('priya@example.com', 'full-manager')])

    def test_inherit_on_matching_roles_no_share(self):
        rows = [{'userId': 2, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'}]
        shares = nsf_record_shares_for_secret_acl(
            record_roles_by_email(rows, USERS, GROUPS), folder_roles_by_email(rows, USERS, GROUPS))
        self.assertEqual(shares, [])

    def test_inherit_off_uses_secret_rows(self):
        folder_rows = [
            {'userId': 2, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
            {'userId': 3, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
        ]
        secret_rows = [
            {'userId': 2, 'secretAccessRoleName': 'Owner'},
            {'userId': 3, 'secretAccessRoleName': 'Edit'},
        ]
        shares = nsf_record_shares_for_secret_acl(
            record_roles_by_email(secret_rows, USERS, GROUPS),
            folder_roles_by_email(folder_rows, USERS, GROUPS))
        self.assertEqual(shares, [('priya@example.com', 'full-manager')])

    def test_user_not_on_folder_gets_share(self):
        folder_rows = [{'userId': 3, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'List'}]
        secret_rows = [{'userId': 2, 'secretAccessRoleName': 'Owner'}]
        shares = nsf_record_shares_for_secret_acl(
            record_roles_by_email(secret_rows, USERS, GROUPS),
            folder_roles_by_email(folder_rows, USERS, GROUPS))
        self.assertEqual(shares, [('priya@example.com', 'full-manager')])

    def test_root_secret_shares_everyone(self):
        secret_rows = [
            {'userId': 2, 'secretAccessRoleName': 'Owner'},
            {'userId': 3, 'secretAccessRoleName': 'View'},
        ]
        shares = nsf_record_shares_for_secret_acl(record_roles_by_email(secret_rows, USERS, GROUPS), {})
        self.assertEqual(sorted(shares), [('david@example.com', 'viewer'), ('priya@example.com', 'full-manager')])

    def test_group_member_covered_by_team_no_duplicate(self):
        rows = [{'groupId': 10, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'}]
        shares = nsf_record_shares_for_secret_acl(
            record_roles_by_email(rows, USERS, GROUPS), folder_roles_by_email(rows, USERS, GROUPS))
        self.assertEqual(shares, [])

    def test_effective_folder_rows_walks_to_ancestor(self):
        from keepercommander.importer.thycotic.thycotic import ThycoticImporter
        parent_rows = [{'userId': 2, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'Owner'}]
        sub_rows = [{'userId': 3, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'List'}]
        folders = {
            1: {'id': 1, 'inheritPermissions': True, 'parentFolderId': None},
            2: {'id': 2, 'inheritPermissions': False, 'parentFolderId': 1, 'permissions': parent_rows},
            3: {'id': 3, 'inheritPermissions': True, 'parentFolderId': 2},
            4: {'id': 4, 'inheritPermissions': False, 'parentFolderId': 3, 'permissions': sub_rows},
        }
        self.assertIs(ThycoticImporter._effective_folder_rows(folders, 3), parent_rows)
        self.assertIs(ThycoticImporter._effective_folder_rows(folders, 4), sub_rows)
        self.assertEqual(ThycoticImporter._effective_folder_rows(folders, 1), [])
        self.assertEqual(ThycoticImporter._effective_folder_rows(folders, None), [])

    def test_effective_folder_rows_stops_on_empty_custom_acl(self):
        """inherit=False with an empty permissions list must not walk to the parent."""
        from keepercommander.importer.thycotic.thycotic import ThycoticImporter
        parent_rows = [{'userId': 2, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'Owner'}]
        folders = {
            2: {'id': 2, 'inheritPermissions': False, 'parentFolderId': 1, 'permissions': parent_rows},
            5: {'id': 5, 'inheritPermissions': False, 'parentFolderId': 2, 'permissions': []},
        }
        self.assertEqual(ThycoticImporter._effective_folder_rows(folders, 5), [])

    def test_import_user_excluded_before_diff(self):
        record_roles = {'sarah@example.com': 'full-manager', 'priya@example.com': 'viewer'}
        filtered = {e: r for e, r in record_roles.items() if e != 'sarah@example.com'}
        shares = nsf_record_shares_for_secret_acl(filtered, {})
        self.assertEqual(shares, [('priya@example.com', 'viewer')])


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
