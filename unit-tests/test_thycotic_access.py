"""Executable checks for what the Thycotic importer does with access data.

Fixtures follow field names published on the Secret Server REST API
(SecretPermissionSummary / folder permission rows): userId, groupId,
folderAccessRoleName, secretAccessRoleName, secretId, inheritPermissions.
No tenant is contacted.
"""

from unittest import TestCase, mock

from keepercommander.importer import imp_exp
from keepercommander.importer.importer import Folder, Record, RecordShare
from keepercommander.importer.thycotic import thycotic
from keepercommander.importer.thycotic.thycotic import parse_thycotic_import_target


def _folders():
    return [
        {
            'id': 1,
            'folderName': 'Root',
            'folderPath': '\\',
            'inheritPermissions': False,
            'parentFolderId': -1,
        },
        {
            'id': 10,
            'folderName': 'Apps',
            'folderPath': '\\Apps',
            'inheritPermissions': False,
            'parentFolderId': 1,
        },
        {
            'id': 11,
            'folderName': 'Child',
            'folderPath': '\\Apps\\Child',
            'inheritPermissions': False,
            'parentFolderId': 10,
        },
    ]


def _users():
    return [
        {'id': 5, 'emailAddress': 'owner@example.com', 'userName': 'owner', 'domainName': ''},
        {'id': 6, 'emailAddress': 'view@example.com', 'userName': 'view', 'domainName': ''},
    ]


class FakeAuth:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def thycotic_search(self, endpoint):
        self.calls.append(endpoint)
        for prefix, payload in self.routes:
            if endpoint == prefix or endpoint.startswith(prefix):
                return payload
        raise AssertionError('unexpected endpoint {0}'.format(endpoint))


class TestThycoticImportTarget(TestCase):
    def test_user_at_https_url_is_not_double_prefixed(self):
        username, host = parse_thycotic_import_target(
            'user@https://metron.secretservercloud.com/')
        self.assertEqual(username, 'user')
        self.assertEqual(host, 'https://metron.secretservercloud.com/')
        auth = thycotic.ThycoticAuth(host)
        self.assertEqual(auth.base_url, 'https://metron.secretservercloud.com/')
        self.assertNotIn('https://https://', auth.base_url + 'oauth2/token')

    def test_user_at_bare_host_gets_one_scheme(self):
        username, host = parse_thycotic_import_target('user@metron.secretservercloud.com')
        self.assertEqual(username, 'user')
        self.assertEqual(host, 'https://metron.secretservercloud.com')

    def test_full_url_leaves_username_empty(self):
        username, host = parse_thycotic_import_target('https://metron.secretservercloud.com/')
        self.assertEqual(username, '')
        self.assertEqual(host, 'https://metron.secretservercloud.com/')


class TestThycoticFolderAcl(TestCase):
    def test_single_user_permission_is_discarded(self):
        auth = FakeAuth([
            ('/v1/folders', _folders()),
            ('/v1/folder-permissions?filter.folderId=10', [{
                'userId': 5,
                'groupId': 0,
                'folderAccessRoleId': 1,
                'folderAccessRoleName': 'Owner',
                'secretAccessRoleId': 1,
                'secretAccessRoleName': 'Owner',
            }]),
            ('/v1/folder-permissions?filter.folderId=11', []),
        ])
        folders = thycotic.ThycoticMixin.get_folders(auth, skip_permissions=False)
        self.assertNotIn('permissions', folders[10])
        self.assertTrue(folders[10]['inheritPermissions'])

    def test_identical_child_acl_is_collapsed(self):
        parent_rows = [
            {
                'userId': 5, 'groupId': 0,
                'folderAccessRoleId': 3, 'folderAccessRoleName': 'Owner',
                'secretAccessRoleId': 3, 'secretAccessRoleName': 'Edit',
            },
            {
                'userId': 6, 'groupId': 0,
                'folderAccessRoleId': 4, 'folderAccessRoleName': 'View',
                'secretAccessRoleId': 4, 'secretAccessRoleName': 'View',
            },
        ]
        auth = FakeAuth([
            ('/v1/folders', _folders()),
            ('/v1/folder-permissions?filter.folderId=10', parent_rows),
            ('/v1/folder-permissions?filter.folderId=11', [dict(row) for row in parent_rows]),
        ])
        folders = thycotic.ThycoticMixin.get_folders(auth, skip_permissions=False)
        self.assertIn('permissions', folders[10])
        self.assertNotIn('permissions', folders[11])
        self.assertTrue(folders[11]['inheritPermissions'])

    def test_membership_maps_only_owner_and_edit(self):
        rows = [
            {
                'userId': 5, 'groupId': 0,
                'folderAccessRoleId': 3, 'folderAccessRoleName': 'Owner',
                'secretAccessRoleId': 3, 'secretAccessRoleName': 'Edit',
            },
            {
                'userId': 6, 'groupId': 0,
                'folderAccessRoleId': 4, 'folderAccessRoleName': 'View',
                'secretAccessRoleId': 5, 'secretAccessRoleName': 'List',
            },
            {
                'userId': 0, 'groupId': 0, 'groupName': 'Ops',
                'folderAccessRoleId': 2, 'folderAccessRoleName': 'Add Secret',
                'secretAccessRoleId': 4, 'secretAccessRoleName': 'View',
            },
        ]
        auth = FakeAuth([
            ('/v1/users', _users()),
            ('/v1/folders', [row for row in _folders() if row['id'] != 11]),
            ('/v1/folder-permissions?filter.folderId=10', rows),
            ('/v1/secrets/lookup', []),
        ])
        with mock.patch.object(thycotic.ThycoticMixin, 'connect_to_server', return_value=auth):
            shared = list(thycotic.ThycoticMembershipDownload().download_membership(None))

        self.assertEqual(len(shared), 1)
        by_name = {perm.name: perm for perm in shared[0].permissions}
        self.assertTrue(by_name['owner@example.com'].manage_users)
        self.assertTrue(by_name['owner@example.com'].manage_records)
        self.assertFalse(by_name['view@example.com'].manage_users)
        self.assertFalse(by_name['view@example.com'].manage_records)
        self.assertFalse(by_name['Ops'].manage_users)
        self.assertTrue(by_name['Ops'].manage_records)
        self.assertFalse(any('secret-permissions' in call for call in auth.calls))
        self.assertFalse(any(call.endswith('/share') or '/share' in call for call in auth.calls))


class TestThycoticSecretRecordPermissions(TestCase):
    def _download(self, secret, permission_rows):
        calls = []

        def search(self, endpoint):
            calls.append(endpoint)
            if endpoint.startswith('/v1/folders'):
                return _folders()
            if endpoint.startswith('/v1/folder-permissions'):
                return []
            if endpoint.startswith('/v1/groups'):
                return []
            if endpoint.startswith('/v1/users'):
                return _users()
            if endpoint.startswith('/v1/secrets/lookup'):
                return [{'id': secret['id']}]
            if endpoint.startswith('/v1/secret-permissions'):
                return permission_rows
            raise AssertionError(endpoint)

        def entity_impl(self, endpoint):
            calls.append(endpoint)
            if endpoint == '/v1/secrets/{0}'.format(secret['id']):
                return secret
            raise AssertionError(endpoint)

        auth = mock.Mock()
        auth.thycotic_search.side_effect = search.__get__(auth, type(auth))
        auth.thycotic_entity.side_effect = entity_impl.__get__(auth, type(auth))
        with mock.patch.object(thycotic.ThycoticMixin, 'connect_to_server', return_value=auth):
            downloaded = list(thycotic.ThycoticMembershipDownload().download_membership(None))
        records = [item for item in downloaded if getattr(item, 'shares', None)]
        return records, calls

    def _secret(self, inherit):
        return {
            'id': 100,
            'name': 'prod-db',
            'folderId': 10,
            'inheritPermissions': inherit,
        }

    def _shares(self, record):
        return {share.name: (share.can_edit, share.can_share) for share in record.shares or []}

    def test_broken_inheritance_maps_provisioned_email(self):
        records, calls = self._download(self._secret(False), [
            {'userId': 5, 'userName': 'owner-login', 'secretId': 100, 'secretAccessRoleName': 'View'},
            {'userId': 6, 'userName': 'view-login', 'secretId': 100, 'secretAccessRoleName': 'Owner'},
            {'groupId': 9, 'groupName': 'Ops', 'secretId': 100, 'secretAccessRoleName': 'Owner'},
        ])
        record = records[0]
        self.assertEqual(record.title, 'prod-db')
        self.assertEqual(record.folders[0].path, 'Apps')
        self.assertEqual(self._shares(record), {
            'owner@example.com': (False, False),
            'view@example.com': (True, True),
        })
        self.assertIn('/v1/secret-permissions?filter.secretId=100', calls)

    def test_edit_without_owner_cannot_share(self):
        records, _calls = self._download(self._secret(False), [
            {'userId': 6, 'userName': 'view-login', 'secretId': 100, 'secretAccessRoleName': 'Edit'},
        ])
        self.assertEqual(self._shares(records[0]), {
            'view@example.com': (True, False),
        })

    def test_view_and_list_are_read_only(self):
        records, _calls = self._download(self._secret(False), [
            {'userId': 6, 'userName': 'view-login', 'secretId': 100, 'secretAccessRoleName': 'List'},
            {'userId': 5, 'userName': 'owner-login', 'secretId': 100, 'secretAccessRoleName': 'View'},
        ])
        self.assertEqual(self._shares(records[0]), {
            'owner@example.com': (False, False),
            'view@example.com': (False, False),
        })

    def test_inheriting_secret_copies_folder_secret_roles(self):
        calls = []
        secret = self._secret(True)
        folder_rows = [
            {'userId': 5, 'groupId': 0, 'folderAccessRoleId': 3, 'secretAccessRoleId': 4, 'secretAccessRoleName': 'Edit'},
            {'userId': 6, 'groupId': 0, 'folderAccessRoleId': 4, 'secretAccessRoleId': 5, 'secretAccessRoleName': 'View'},
        ]

        def search(self, endpoint):
            calls.append(endpoint)
            if endpoint.startswith('/v1/folders'):
                return _folders()
            if endpoint.startswith('/v1/folder-permissions?filter.folderId=10'):
                return folder_rows
            if endpoint.startswith('/v1/folder-permissions'):
                return []
            if endpoint.startswith('/v1/users'):
                return _users()
            if endpoint.startswith('/v1/secrets/lookup'):
                return [{'id': secret['id']}]
            if endpoint.startswith('/v1/groups'):
                return []
            raise AssertionError(endpoint)

        def entity_impl(self, endpoint):
            if endpoint == '/v1/secrets/100':
                return secret
            raise AssertionError(endpoint)

        auth = mock.Mock()
        auth.thycotic_search.side_effect = search.__get__(auth, type(auth))
        auth.thycotic_entity.side_effect = entity_impl.__get__(auth, type(auth))
        with mock.patch.object(thycotic.ThycoticMixin, 'connect_to_server', return_value=auth):
            downloaded = list(thycotic.ThycoticMembershipDownload().download_membership(None))
        records = [item for item in downloaded if getattr(item, 'shares', None)]
        self.assertEqual(self._shares(records[0]), {
            'owner@example.com': (True, False),
            'view@example.com': (False, False),
        })
        self.assertNotIn('/v1/secret-permissions?filter.secretId=100', calls)

    def test_inheriting_secret_uses_secret_permissions_when_folder_acl_is_empty(self):
        records, calls = self._download(self._secret(True), [
            {'userId': 5, 'secretId': 100, 'secretAccessRoleName': 'Owner'},
        ])
        self.assertEqual(self._shares(records[0]), {
            'owner@example.com': (True, True),
        })
        self.assertIn('/v1/secret-permissions?filter.secretId=100', calls)

    def test_absent_inherit_flag_falls_back_to_folder_roles(self):
        calls = []
        secret = self._secret(True)
        del secret['inheritPermissions']
        folder_rows = [
            {'userId': 5, 'groupId': 0, 'folderAccessRoleId': 3, 'secretAccessRoleId': 3, 'secretAccessRoleName': 'Edit'},
            {'userId': 6, 'groupId': 0, 'folderAccessRoleId': 4, 'secretAccessRoleId': 4, 'secretAccessRoleName': 'View'},
        ]

        def search(self, endpoint):
            calls.append(endpoint)
            if endpoint.startswith('/v1/folders'):
                return _folders()
            if endpoint.startswith('/v1/folder-permissions?filter.folderId=10'):
                return folder_rows
            if endpoint.startswith('/v1/folder-permissions'):
                return []
            if endpoint.startswith('/v1/users'):
                return _users()
            if endpoint.startswith('/v1/secrets/lookup'):
                return [{'id': secret['id']}]
            if endpoint.startswith('/v1/secret-permissions'):
                return []
            if endpoint.startswith('/v1/groups'):
                return []
            raise AssertionError(endpoint)

        def entity_impl(self, endpoint):
            if endpoint == '/v1/secrets/100':
                return secret
            raise AssertionError(endpoint)

        auth = mock.Mock()
        auth.thycotic_search.side_effect = search.__get__(auth, type(auth))
        auth.thycotic_entity.side_effect = entity_impl.__get__(auth, type(auth))
        with mock.patch.object(thycotic.ThycoticMixin, 'connect_to_server', return_value=auth):
            downloaded = list(thycotic.ThycoticMembershipDownload().download_membership(None))
        records = [item for item in downloaded if getattr(item, 'shares', None)]
        self.assertEqual(self._shares(records[0]), {
            'owner@example.com': (True, False),
            'view@example.com': (False, False),
        })
        self.assertIn('/v1/secret-permissions?filter.secretId=100', calls)

    def test_missing_inherit_flag_still_pulls_secret_permissions(self):
        secret = self._secret(True)
        del secret['inheritPermissions']
        records, calls = self._download(secret, [
            {'userId': 5, 'userName': 'owner-login', 'secretId': 100, 'secretAccessRoleName': 'Edit'},
        ])
        self.assertEqual(self._shares(records[0]), {
            'owner@example.com': (True, False),
        })
        self.assertIn('/v1/secret-permissions?filter.secretId=100', calls)


class TestSecretSharesRequireExistingUsers(TestCase):
    def _record(self):
        record = Record()
        record.title = 'prod-db'
        folder = Folder()
        folder.path = 'Apps'
        record.folders = [folder]
        record.shares = [
            RecordShare('owner@example.com', True, True),
            RecordShare('missing@example.com', False, False),
        ]
        return record

    def test_users_are_loaded_before_the_grant(self):
        params = mock.Mock()
        params.enterprise = None
        order = []
        granted = []

        def load_users(target):
            order.append('users')
            target.enterprise = {'users': [{'email': 'owner@example.com'}]}

        def grant(target, records):
            order.append('grant')
            granted.extend(records)

        with mock.patch.object(imp_exp.api, 'query_enterprise', side_effect=load_users), \
                mock.patch.object(imp_exp.sync_down, 'sync_down', side_effect=lambda target: order.append('sync')), \
                mock.patch.object(imp_exp, 'locate_secret_share_records', side_effect=lambda target, records: records), \
                mock.patch.object(imp_exp, 'grant_imported_record_shares', side_effect=grant):
            imp_exp.apply_secret_share_records(params, [self._record()])

        self.assertEqual(order, ['users', 'sync', 'grant'])
        self.assertEqual([share.name for share in granted[0].shares], ['owner@example.com'])

    def test_failed_user_load_does_not_grant(self):
        params = mock.Mock()
        params.enterprise = None
        with mock.patch.object(imp_exp.api, 'query_enterprise', side_effect=RuntimeError('offline')), \
                mock.patch.object(imp_exp.sync_down, 'sync_down') as sync_down, \
                mock.patch.object(imp_exp, 'grant_imported_record_shares') as grant:
            imp_exp.apply_secret_share_records(params, [self._record()])
        sync_down.assert_not_called()
        grant.assert_not_called()
