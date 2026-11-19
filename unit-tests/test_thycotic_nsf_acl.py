#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import MagicMock, patch

from keepercommander.importer.importer import Record
from keepercommander.importer.thycotic.nsf_acl import (
    REVOKED_ACCESS_ACTION,
    thycotic_secret_role_to_nsf_role,
    diff_secret_acl,
    nsf_record_shares_for_secret_acl,
    parse_secret_inherit_permissions,
    revoked_folder_emails,
    secret_acl_differs_from_folder_rows,
    thycotic_folder_role_to_nsf_role,
    folder_roles_by_email,
    record_roles_by_email,
)
from keepercommander.importer.thycotic.thycotic import ThycoticImporter


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


class TestRevokedFolderEmails(unittest.TestCase):
    """Folder principals omitted from a non-inheriting secret ACL."""

    def test_revoked_when_user_removed_from_secret(self):
        folder = {'alice@example.com': 'full-manager', 'bob@example.com': 'viewer'}
        secret = {'bob@example.com': 'viewer'}
        self.assertEqual(revoked_folder_emails(folder, secret), ['alice@example.com'])

    def test_no_revocation_when_all_folder_members_present(self):
        folder = {'alice@example.com': 'full-manager'}
        secret = {'alice@example.com': 'viewer', 'bob@example.com': 'viewer'}
        self.assertEqual(revoked_folder_emails(folder, secret), [])

    def test_empty_secret_revokes_everyone_on_folder(self):
        folder = {'alice@example.com': 'full-manager', 'bob@example.com': 'viewer'}
        self.assertEqual(
            revoked_folder_emails(folder, {}),
            ['alice@example.com', 'bob@example.com'])

    def test_diff_secret_acl_does_not_emit_revocations(self):
        """Positive deltas only — removals are tracked separately."""
        folder = {'alice@example.com': 'full-manager'}
        secret = {}
        self.assertEqual(diff_secret_acl(folder, secret), [])
        self.assertEqual(revoked_folder_emails(folder, secret), ['alice@example.com'])


class TestApplyNsfSecretAclOrchestration(unittest.TestCase):
    """End-to-end ThycoticImporter._apply_nsf_secret_acl behavior."""

    def setUp(self):
        self.importer = ThycoticImporter()
        self.auth = MagicMock()

    def _apply(self, secret, folder_id, folders, secret_rows, users=None, groups=None, params=None):
        record = Record()
        record.title = secret.get('name') or 'secret'
        users = users or USERS
        groups = groups or GROUPS
        with patch.object(ThycoticImporter, 'get_user_lookup', return_value=users), \
                patch.object(ThycoticImporter, 'get_group_lookup', return_value=groups), \
                patch.object(self.importer, '_permission_rows_for_secret', return_value=secret_rows):
            self.importer._apply_nsf_secret_acl(
                record, secret, secret.get('id') or 1, folder_id, folders, users, self.auth,
                params=params)
        return record

    def test_revocation_warns_when_folder_owner_omitted_from_secret(self):
        """Alice Owner on folder; secret inherit OFF omits Alice → warn, no deny share."""
        parent_rows = [
            {'userId': 2, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'Owner'},
            {'userId': 3, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
        ]
        folders = {
            10: {
                'id': 10, 'folderPath': 'Finance', 'inheritPermissions': False,
                'parentFolderId': None, 'permissions': parent_rows,
            },
        }
        secret = {'id': 99, 'name': 'Executive Comp', 'enableInheritPermissions': False}
        secret_rows = [{'userId': 3, 'secretAccessRoleName': 'Edit'}]

        with self.assertLogs(level='WARNING') as logs:
            record = self._apply(secret, 10, folders, secret_rows)

        self.assertFalse(getattr(record, 'nsf_record_shares', None))
        self.assertEqual(len(self.importer._nsf_revoked_access), 1)
        secret_id, title, email, folder_role = self.importer._nsf_revoked_access[0]
        self.assertEqual((secret_id, title, email, folder_role),
                         (99, 'Executive Comp', 'priya@example.com', 'full-manager'))
        self.assertTrue(any('priya@example.com' in line for line in logs.output))
        self.assertIn(REVOKED_ACCESS_ACTION, ' '.join(logs.output))

    def test_implicit_inherit_break_uses_secret_rows_and_no_group_filter(self):
        """enableInheritPermissions True/omitted but ACL differs → secret_rows, expand groups."""
        folder_rows = [
            {'userId': 2, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
            {'groupId': 10, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
        ]
        folders = {
            10: {
                'id': 10, 'folderPath': 'Finance', 'inheritPermissions': False,
                'parentFolderId': None, 'permissions': folder_rows,
            },
        }
        # Flag says inherit ON (or omitted); secret ACL adds Owner for priya and omits group.
        secret = {'id': 50, 'name': 'Override', 'enableInheritPermissions': True}
        secret_rows = [
            {'userId': 2, 'secretAccessRoleName': 'Owner'},
            {'userId': 3, 'secretAccessRoleName': 'View'},
        ]
        params = MagicMock()
        params.user = 'importer@example.com'
        # Missing Keeper team → group excluded from folder_baseline only.
        self.importer._nsf_team_granted = lambda group, p: False

        record = self._apply(secret, 10, folders, secret_rows, params=params)
        shares = {(s.uid, s.role) for s in (record.nsf_record_shares or [])}
        # secret_rows used (Owner share for priya); group_filter=None so david from
        # secret user row is shared even though team is missing from folder baseline.
        self.assertIn(('priya@example.com', 'full-manager'), shares)
        self.assertIn(('david@example.com', 'viewer'), shares)
        # Team not on folder baseline → no revocation for group members via team.
        self.assertEqual(self.importer._nsf_revoked_access, [])

    def test_subfolder_missing_team_inherit_on_and_off(self):
        """Child inherits parent ACL; missing Keeper team filtered on inherit ON only."""
        parent_rows = [
            {'userId': 2, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'Owner'},
            {'groupId': 10, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
        ]
        folders = {
            1: {
                'id': 1, 'folderPath': 'Parent', 'inheritPermissions': False,
                'parentFolderId': None, 'permissions': parent_rows,
            },
            2: {
                'id': 2, 'folderPath': 'Parent\\Child', 'inheritPermissions': True,
                'parentFolderId': 1,
            },
        }
        params = MagicMock()
        params.user = ''
        self.importer._nsf_team_granted = lambda group, p: False

        # Inherit ON: record roles from folder rows with team filter → group members omitted.
        inherit_on = {'id': 1, 'name': 'Inherits', 'enableInheritPermissions': True}
        record_on = self._apply(inherit_on, 2, folders, secret_rows=[], params=params)
        # Folder Owner + secret Owner match → no share; group filtered out of both sides.
        self.assertFalse(getattr(record_on, 'nsf_record_shares', None))
        self.assertEqual(self.importer._nsf_revoked_access, [])

        # Inherit OFF: secret grants group member directly; group_filter=None.
        self.importer._nsf_revoked_access = []
        inherit_off = {'id': 2, 'name': 'Own ACL', 'enableInheritPermissions': False}
        secret_rows = [
            {'userId': 2, 'secretAccessRoleName': 'Owner'},
            {'userId': 3, 'secretAccessRoleName': 'Edit'},
        ]
        record_off = self._apply(inherit_off, 2, folders, secret_rows, params=params)
        shares = {(s.uid, s.role) for s in (record_off.nsf_record_shares or [])}
        # david has folder role only via missing team → baseline lacks david → direct share.
        self.assertIn(('david@example.com', 'content-manager'), shares)
        self.assertEqual(self.importer._nsf_revoked_access, [])

    def test_root_inherit_true_with_permissions_matches_yield_grants(self):
        """Root inheritPermissions=True is skipped by yield; baseline must also be empty."""
        rows = [
            {'userId': 2, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'Owner'},
        ]
        folders = {
            1: {
                'id': 1, 'folderPath': 'Rootish', 'inheritPermissions': True,
                'parentFolderId': None, 'permissions': rows,
            },
        }
        yielded = list(self.importer._yield_nsf_shared_folders(
            self.auth, folders, USERS, GROUPS))
        self.assertEqual(yielded, [])

        secret = {'id': 7, 'name': 'In root', 'enableInheritPermissions': True}
        # Secret inherits; folder_rows empty (no custom-ACL ancestor) → uses secret_rows.
        secret_rows = [{'userId': 2, 'secretAccessRoleName': 'Owner'}]
        record = self._apply(secret, 1, folders, secret_rows)
        shares = {(s.uid, s.role) for s in (record.nsf_record_shares or [])}
        # No folder baseline (matches yield) → every secret principal gets a direct share.
        self.assertEqual(shares, {('priya@example.com', 'full-manager')})
        self.assertEqual(self.importer._nsf_revoked_access, [])


class TestPamRevokedOverride(unittest.TestCase):
    def test_record_revoked_override_finding(self):
        from keepercommander.importer.thycotic.pam.models import FindingLog
        from keepercommander.importer.thycotic.pam.permission_mapper import PermissionMapper

        findings = FindingLog()
        mapper = PermissionMapper(USERS, GROUPS, findings)
        folder_rows = [
            {'userId': 2, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'Owner'},
            {'userId': 3, 'folderAccessRoleName': 'Edit', 'secretAccessRoleName': 'Edit'},
        ]
        secret_rows = [{'userId': 3, 'secretAccessRoleName': 'Edit'}]
        mapper.record_revoked_override(folder_rows, secret_rows, 'Executive Comp')
        items = list(findings)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].category, 'Secret permission')
        self.assertIn('priya@example.com', items[0].item)
        self.assertEqual(items[0].action, REVOKED_ACCESS_ACTION)


if __name__ == '__main__':
    unittest.main()
