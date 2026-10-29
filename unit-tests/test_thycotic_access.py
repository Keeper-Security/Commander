"""Executable checks for what the Thycotic importer does with access data.

Fixtures follow field names published on the Secret Server REST API
(SecretPermissionSummary / folder permission rows): userId, groupId,
folderAccessRoleName, secretAccessRoleName, secretId, inheritPermissions.
No tenant is contacted.
"""

from unittest import TestCase, mock

from keepercommander.importer import imp_exp
from keepercommander.importer.importer import Folder, Record, RecordShare, normalize_folder_path
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
        self.assertEqual(host, 'https://metron.secretservercloud.com')
        auth = thycotic.ThycoticAuth(host)
        self.assertEqual(auth.base_url, 'https://metron.secretservercloud.com/')
        self.assertNotIn('https://https://', auth.base_url + 'oauth2/token')

    def test_user_at_bare_host_gets_one_scheme(self):
        username, host = parse_thycotic_import_target('user@metron.secretservercloud.com')
        self.assertEqual(username, 'user')
        self.assertEqual(host, 'https://metron.secretservercloud.com/')

    def test_bare_tenant_keeps_username_and_cloud_host(self):
        username, host = parse_thycotic_import_target('user@acme')
        self.assertEqual(username, 'user')
        self.assertEqual(host, 'https://acme.secretservercloud.com/')

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


def _secret_auth(secrets, secret_permissions=None, folder_permissions=None, failing_secrets=(),
                 failing_endpoints=()):
    """Mock auth for iter_secret_shares. failing_* raise instead of returning."""
    auth = mock.Mock()
    auth.calls = []
    secret_permissions = secret_permissions or {}
    folder_permissions = folder_permissions or {}

    def search(endpoint):
        auth.calls.append(endpoint)
        for prefix in failing_endpoints:
            if endpoint.startswith(prefix):
                raise RuntimeError('boom')
        if endpoint.startswith('/v1/secrets/lookup'):
            return [{'id': secret['id']} for secret in secrets]
        if endpoint.startswith('/v1/secret-permissions?filter.secretId='):
            return secret_permissions.get(int(endpoint.rsplit('=', 1)[1]), [])
        if endpoint.startswith('/v1/folder-permissions?filter.folderId='):
            return folder_permissions.get(int(endpoint.rsplit('=', 1)[1]), [])
        if endpoint.startswith('/v1/users'):
            return _users()
        if endpoint.startswith('/v1/groups'):
            return []
        raise AssertionError(endpoint)

    def entity(endpoint):
        auth.calls.append(endpoint)
        secret_id = int(endpoint.rsplit('/', 1)[1])
        if secret_id in failing_secrets:
            raise RuntimeError('secret {0} unavailable'.format(secret_id))
        for secret in secrets:
            if secret['id'] == secret_id:
                return dict(secret)
        return None

    auth.thycotic_search.side_effect = search
    auth.thycotic_entity.side_effect = entity
    return auth


def _folder_map():
    return {row['id']: row for row in _folders()}


class TestExternalCallFailures(TestCase):
    def test_failed_secret_fetch_skips_only_that_secret(self):
        secrets = [
            {'id': 100, 'name': 'broken', 'folderId': 10, 'inheritPermissions': False},
            {'id': 101, 'name': 'ok', 'folderId': 10, 'inheritPermissions': False},
        ]
        auth = _secret_auth(secrets, secret_permissions={
            101: [{'userId': 5, 'secretId': 101, 'secretAccessRoleName': 'Owner'}],
        }, failing_secrets=(100,))
        with self.assertLogs(level='WARNING') as logs:
            records = list(thycotic.ThycoticMixin.iter_secret_shares(auth, _folder_map()))
        self.assertEqual([record.title for record in records], ['ok'])
        self.assertTrue(any('Secret 100 permissions skipped' in line for line in logs.output))
        self.assertTrue(any('1 secret(s) were skipped' in line for line in logs.output))

    def test_failed_secret_lookup_yields_nothing(self):
        auth = _secret_auth([], failing_endpoints=('/v1/secrets/lookup',))
        with self.assertLogs(level='WARNING'):
            records = list(thycotic.ThycoticMixin.iter_secret_shares(auth, _folder_map()))
        self.assertEqual(records, [])

    def test_failed_secret_permissions_falls_back_to_folder(self):
        secret = {'id': 100, 'name': 'prod-db', 'folderId': 10, 'inheritPermissions': False}
        auth = _secret_auth([secret], folder_permissions={
            10: [{'userId': 6, 'secretAccessRoleName': 'View'}],
        }, failing_endpoints=('/v1/secret-permissions',))
        with self.assertLogs(level='WARNING'):
            rows = thycotic.ThycoticMixin.permission_rows_for_secret(auth, _folder_map(), secret)
        self.assertEqual(rows, [{'userId': 6, 'secretAccessRoleName': 'View'}])

    def test_folder_permissions_are_fetched_once_per_folder(self):
        auth = _secret_auth([], folder_permissions={10: [{'userId': 5, 'secretAccessRoleName': 'Edit'}]})
        cache = {}
        for _ in range(3):
            rows = thycotic.ThycoticMixin.folder_permission_rows(auth, _folder_map(), 10, cache)
            self.assertEqual(len(rows), 1)
        self.assertEqual(auth.calls.count('/v1/folder-permissions?filter.folderId=10'), 1)

    def test_failed_folder_fetch_is_not_cached(self):
        auth = mock.Mock()
        auth.thycotic_search.side_effect = [
            RuntimeError('timeout'),
            [{'userId': 5, 'secretAccessRoleName': 'Edit'}],
        ]
        folders = {10: {'id': 10, 'parentFolderId': 0}}
        cache = {}
        self.assertEqual(thycotic.ThycoticMixin.folder_permission_rows(auth, folders, 10, cache), [])
        self.assertNotIn(10, cache)
        rows = thycotic.ThycoticMixin.folder_permission_rows(auth, folders, 10, cache)
        self.assertEqual(rows, [{'userId': 5, 'secretAccessRoleName': 'Edit'}])
        self.assertIn(10, cache)

    def test_failed_user_detail_fetch_skips_user(self):
        auth = mock.Mock()
        auth.thycotic_search.return_value = [
            {'id': 5, 'userName': 'no-email'},
            {'id': 6, 'userName': 'view', 'emailAddress': 'view@example.com'},
        ]
        auth.thycotic_entity.side_effect = RuntimeError('403')
        with self.assertLogs(level='WARNING'):
            users = thycotic.ThycoticImporter()._prepare_thycotic_users(auth)
        self.assertEqual([user['email'] for user in users], ['view@example.com'])

    def test_provisioned_emails_keep_user_list_when_detail_load_fails(self):
        auth = FakeAuth([('/v1/users', _users())])
        with mock.patch.object(thycotic.ThycoticImporter, '_prepare_thycotic_users',
                               side_effect=RuntimeError('offline')):
            emails = thycotic.ThycoticMixin.provisioned_emails(auth)
        self.assertEqual(emails[5], 'owner@example.com')
        self.assertEqual(emails[6], 'view@example.com')

    def test_user_fetch_failure_does_not_create_users(self):
        importer = thycotic.ThycoticImporter()
        with mock.patch.object(importer, '_prepare_thycotic_users', side_effect=RuntimeError('offline')), \
                mock.patch.object(importer, '_create_enterprise_users') as create:
            with self.assertLogs(level='WARNING'):
                importer._migrate_thycotic_users(mock.Mock(), mock.Mock())
        create.assert_not_called()


class TestCreateEnterpriseUsers(TestCase):
    def _run(self, users, existing=(), created=True):
        importer = thycotic.ThycoticImporter()
        with mock.patch.object(importer, '_load_existing_keeper_users',
                               return_value=list(existing)), \
                mock.patch.object(importer, '_create_keeper_user',
                                  return_value='uid' if created else None) as create:
            report = importer._create_enterprise_users(mock.Mock(), users)
        return report, create

    def _flags(self, report):
        return [(row['email'], row['flag']) for row in report['users']]

    def test_existing_user_matches_case_insensitively(self):
        report, create = self._run(
            [{'email': 'Owner@Example.com', 'username': 'owner'}],
            existing=[{'email': 'owner@example.com', 'status': 'invited'}])
        self.assertEqual(self._flags(report), [('Owner@Example.com', 'existing')])
        self.assertEqual(report['users'][0]['status'], 'invited')
        create.assert_not_called()

    def test_duplicate_emails_are_created_once(self):
        report, create = self._run([
            {'email': 'new@example.com', 'name': 'New'},
            {'email': 'NEW@example.com', 'name': 'New again'},
        ])
        self.assertEqual(self._flags(report), [('new@example.com', 'created')])
        create.assert_called_once()

    def test_invalid_email_is_skipped(self):
        report, create = self._run([{'email': 'not-an-email', 'username': 'bad'}, {'email': ''}])
        self.assertEqual([row['flag'] for row in report['users']], ['skipped', 'skipped'])
        create.assert_not_called()

    def test_failed_create_is_reported(self):
        report, _create = self._run([{'email': 'new@example.com'}], created=False)
        self.assertEqual(self._flags(report), [('new@example.com', 'failed')])
        self.assertEqual(report['users'][0]['reason'], 'user was not created')

    def test_name_falls_back_to_username_then_email(self):
        _report, create = self._run([
            {'email': 'a@example.com', 'username': 'alpha'},
            {'email': 'b@example.com'},
        ])
        names = [call.args[2] for call in create.call_args_list]
        self.assertEqual(names, ['alpha', 'b@example.com'])

    def test_non_dict_entries_are_ignored(self):
        report, create = self._run([None, 'x', 42, {'email': 'ok@example.com'}])
        self.assertEqual(self._flags(report), [('ok@example.com', 'created')])
        create.assert_called_once()

    def test_failed_keeper_user_load_still_creates(self):
        importer = thycotic.ThycoticImporter()
        params = mock.Mock()
        params.enterprise = None
        with mock.patch.object(thycotic.api, 'query_enterprise', side_effect=RuntimeError('offline')), \
                mock.patch.object(importer, '_create_keeper_user', return_value='uid') as create:
            with self.assertLogs(level='WARNING'):
                report = importer._create_enterprise_users(params, [{'email': 'new@example.com'}])
        self.assertEqual(self._flags(report), [('new@example.com', 'created')])
        create.assert_called_once()

    def test_create_keeper_user_swallows_command_errors(self):
        with mock.patch('keepercommander.commands.enterprise_create_user.CreateEnterpriseUserCommand') as command:
            command.return_value.execute.side_effect = RuntimeError('license full')
            with self.assertLogs(level='WARNING'):
                result = thycotic.ThycoticImporter()._create_keeper_user(mock.Mock(), 'a@example.com', 'A')
        self.assertIsNone(result)


class TestInvalidPermissionData(TestCase):
    emails = {5: 'owner@example.com', 6: 'view@example.com'}

    def _shares(self, rows, groups=None):
        shares = thycotic.ThycoticMixin.shares_from_secret_permissions(rows, self.emails, groups)
        return {share.name: (share.can_edit, share.can_share) for share in shares}

    def test_non_list_rows_give_no_shares(self):
        for rows in (None, {}, 'rows', 5):
            self.assertEqual(self._shares(rows), {})

    def test_non_dict_rows_and_unknown_roles_are_skipped(self):
        self.assertEqual(self._shares([
            None, 'row', 7,
            {'userId': 5, 'secretAccessRoleName': 'Approver'},
            {'userId': 5, 'secretAccessRoleName': None},
            {'userId': 6, 'secretAccessRoleName': ' view '},
        ]), {'view@example.com': (False, False)})

    def test_user_listed_twice_keeps_higher_role(self):
        self.assertEqual(self._shares([
            {'userId': 5, 'secretAccessRoleName': 'View'},
            {'userId': 5, 'secretAccessRoleName': 'Owner'},
            {'userId': 5, 'secretAccessRoleName': 'Edit'},
        ]), {'owner@example.com': (True, True)})

    def test_unknown_user_is_dropped(self):
        self.assertEqual(self._shares([{'userId': 99, 'secretAccessRoleName': 'Owner'}]), {})

    def test_string_user_id_matches(self):
        self.assertEqual(self._shares([{'userId': '6', 'secretAccessRoleName': 'Edit'}]),
                         {'view@example.com': (True, False)})

    def test_row_without_user_id_uses_email_in_row(self):
        self.assertEqual(self._shares([
            {'userId': 0, 'userName': ' ext@example.com ', 'secretAccessRoleName': 'Edit'},
        ]), {'ext@example.com': (True, False)})

    def test_group_row_expands_to_members(self):
        groups = {9: {'name': 'Ops', 'users': [5, 6, 99]}}
        self.assertEqual(self._shares([{'groupId': '9', 'secretAccessRoleName': 'View'}], groups), {
            'owner@example.com': (False, False),
            'view@example.com': (False, False),
        })

    def test_group_row_without_lookup_is_dropped(self):
        self.assertEqual(self._shares([{'groupId': 9, 'secretAccessRoleName': 'Owner'}]), {})

    def test_extract_user_email_edge_cases(self):
        extract = thycotic.ThycoticImporter._extract_user_email
        self.assertEqual(extract(None), '')
        self.assertEqual(extract(['a@example.com']), '')
        self.assertEqual(extract({'emailAddress': '  ', 'emailaddress': 'b@example.com'}), 'b@example.com')
        self.assertEqual(extract({'emailAddress': 5}), '')
        self.assertEqual(extract({'emailAddress': ' a@example.com '}), 'a@example.com')

    def test_application_accounts_are_skipped(self):
        auth = mock.Mock()
        auth.thycotic_search.return_value = [
            {'id': 5, 'emailAddress': 'app@example.com', 'isApplicationAccount': True},
            None,
            {'id': 6, 'userName': 'detail'},
        ]
        auth.thycotic_entity.return_value = {'isApplicationAccount': True, 'emailAddress': 'x@example.com'}
        self.assertEqual(thycotic.ThycoticImporter()._prepare_thycotic_users(auth), [])


class TestPermissionEdgeCases(TestCase):
    def test_folder_walk_stops_on_parent_cycle(self):
        auth = mock.Mock()
        auth.thycotic_search.return_value = []
        folders = {10: {'id': 10, 'parentFolderId': 11}, 11: {'id': 11, 'parentFolderId': 10}}
        self.assertEqual(thycotic.ThycoticMixin.folder_permission_rows(auth, folders, 10), [])
        self.assertEqual(auth.thycotic_search.call_count, 2)

    def test_folder_walk_uses_nearest_parent_with_rows(self):
        auth = _secret_auth([], folder_permissions={1: [{'userId': 5, 'secretAccessRoleName': 'Owner'}]})
        rows = thycotic.ThycoticMixin.folder_permission_rows(auth, _folder_map(), 11)
        self.assertEqual(rows, [{'userId': 5, 'secretAccessRoleName': 'Owner'}])

    def test_secret_without_folder_or_id_gives_no_rows(self):
        auth = _secret_auth([])
        self.assertEqual(thycotic.ThycoticMixin.permission_rows_for_secret(auth, {}, {}), [])
        self.assertEqual(thycotic.ThycoticMixin.permission_rows_for_secret(auth, {}, None), [])
        self.assertEqual(auth.calls, [])

    def test_secret_returned_as_non_dict_is_ignored(self):
        auth = _secret_auth([{'id': 100, 'name': 'x', 'folderId': 10}])
        auth.thycotic_entity.side_effect = None
        auth.thycotic_entity.return_value = ['not', 'a', 'secret']
        records = list(thycotic.ThycoticMixin.iter_secret_shares(auth, _folder_map()))
        self.assertEqual(records, [])

    def test_secret_without_name_is_not_yielded(self):
        secret = {'id': 100, 'name': '', 'folderId': 10, 'inheritPermissions': False}
        auth = _secret_auth([secret], secret_permissions={
            100: [{'userId': 5, 'secretAccessRoleName': 'Owner'}],
        })
        records = list(thycotic.ThycoticMixin.iter_secret_shares(auth, _folder_map()))
        self.assertEqual(records, [])

    def test_secret_in_unknown_folder_has_no_folder_path(self):
        secret = {'id': 100, 'name': 'loose', 'folderId': 404, 'inheritPermissions': False}
        auth = _secret_auth([secret], secret_permissions={
            100: [{'userId': 5, 'secretAccessRoleName': 'Edit'}],
        })
        records = list(thycotic.ThycoticMixin.iter_secret_shares(auth, _folder_map()))
        self.assertEqual(len(records), 1)
        self.assertFalse(records[0].folders)

    def test_folder_paths_match_across_separators(self):
        normalize = normalize_folder_path
        self.assertEqual(normalize('\\Apps\\Child'), normalize('Apps/Child/'))
        self.assertEqual(normalize(' /APPS/child '), 'apps\\child')
        self.assertEqual(normalize(None), '')
        self.assertEqual(normalize('\\'), '')

    def test_url_from_tenant_edge_cases(self):
        url = thycotic.ThycoticMixin.url_from_tenant
        self.assertEqual(url(None), '')
        self.assertEqual(url('   '), '')
        self.assertEqual(url('acme/'), 'https://acme.secretservercloud.com/')
        self.assertEqual(url('https://ss.example.com/'), 'https://ss.example.com')
        self.assertEqual(url('ss.example.com'), 'https://ss.example.com/')

    def test_import_target_without_host_is_rejected(self):
        self.assertIsNone(parse_thycotic_import_target('user@'))
        self.assertIsNone(parse_thycotic_import_target('user@   '))


def _share_record(title, *paths):
    record = Record()
    record.title = title
    record.folders = []
    for path in paths:
        folder = Folder()
        folder.path = path
        record.folders.append(folder)
    record.shares = [RecordShare('owner@example.com', True, True)]
    return record


class TestShareRecordsWithMultipleFolders(TestCase):
    def _download(self, downloaded, existing=None, **kwargs):
        import json as json_module
        import os
        import tempfile
        from types import SimpleNamespace
        from keepercommander.importer import commands
        from keepercommander.importer.json.json import KeeperJsonExporter

        directory = tempfile.mkdtemp()
        file_name = os.path.join(directory, 'membership.json')
        if existing:
            KeeperJsonExporter().do_export(file_name, existing)
        plugin = mock.Mock()
        plugin.download_membership.return_value = iter(downloaded)
        module = SimpleNamespace(MembershipDownload=lambda: plugin)
        with mock.patch.object(commands.importlib, 'import_module', return_value=module):
            commands.DownloadMembershipCommand().execute(
                mock.Mock(), source='thycotic', name=file_name, **kwargs)
        with open(file_name) as handle:
            return json_module.load(handle).get('records') or []

    def test_folder_prefix_applies_to_every_folder(self):
        records = self._download([_share_record('prod-db', 'Apps', 'Ops\\Db', '')], folder='Imported')
        self.assertEqual([folder.get('folder') for folder in records[0]['folders']],
                         ['Imported\\Apps', 'Imported\\Ops\\Db', 'Imported'])

    def test_empty_folder_path_becomes_prefix(self):
        records = self._download([_share_record('prod-db', '')], folder='Imported')
        self.assertEqual(records[0]['folders'], [{'folder': 'Imported'}])

    def test_existing_record_is_replaced_only_when_all_folders_match(self):
        existing = [
            _share_record('prod-db', 'Apps'),
            _share_record('prod-db', 'Apps', 'Ops'),
        ]
        records = self._download([_share_record('prod-db', 'Ops', 'apps/')], existing=existing)
        self.assertEqual(sorted(tuple(folder['folder'] for folder in record['folders']) for record in records),
                         [('Apps',), ('Ops', 'apps/')])


class TestLocateShareRecordsWithMultipleFolders(TestCase):
    def _params(self, folders):
        import json as json_module
        params = mock.Mock()
        params.record_cache = {}
        params.subfolder_record_cache = {}
        for folder_uid, (path, titles) in folders.items():
            params.subfolder_record_cache[folder_uid] = []
            for title in titles:
                record_uid = '{0}-{1}'.format(folder_uid, title)
                params.record_cache[record_uid] = {'data_unencrypted': json_module.dumps({'title': title})}
                params.subfolder_record_cache[folder_uid].append(record_uid)
        paths = {folder_uid: path for folder_uid, (path, _titles) in folders.items()}
        return params, paths

    def _locate(self, folders, records):
        params, paths = self._params(folders)
        with mock.patch.object(imp_exp, 'get_folder_path', side_effect=lambda _params, uid: paths[uid]):
            return imp_exp.locate_secret_share_records(params, records)

    def test_record_in_second_folder_is_found(self):
        located = self._locate({'f1': ('Apps', []), 'f2': ('Ops', ['prod-db'])},
                               [_share_record('prod-db', 'Apps', 'Ops')])
        self.assertEqual([record.uid for record in located], ['f2-prod-db'])

    def test_record_in_several_listed_folders_is_shared_in_each(self):
        located = self._locate({'f1': ('Apps', ['prod-db']), 'f2': ('Ops', ['prod-db'])},
                               [_share_record('prod-db', 'Apps', 'Ops', 'apps')])
        self.assertEqual(sorted(record.uid for record in located), ['f1-prod-db', 'f2-prod-db'])

    def test_record_in_no_listed_folder_names_every_folder(self):
        with self.assertLogs(level='WARNING') as logs:
            located = self._locate({'f1': ('Other', ['prod-db'])},
                                   [_share_record('prod-db', 'Apps', 'Ops')])
        self.assertEqual(located, [])
        self.assertTrue(any('"apps, ops"' in line for line in logs.output))


class TestThycoticUserReport(TestCase):
    def test_report_logs_counts_and_each_user(self):
        report = {'users': [
            {'email': 'a@example.com', 'flag': 'created'},
            {'email': 'b@example.com', 'flag': 'existing', 'status': 'invited'},
            {'email': 'bad', 'flag': 'skipped', 'reason': 'invalid email'},
            None,
        ]}
        with self.assertLogs(level='INFO') as logs:
            thycotic.ThycoticImporter()._print_thycotic_user_report(report)
        output = '\n'.join(logs.output)
        self.assertIn('created 1, existing 1, skipped 2, failed 0', output)
        self.assertIn('[existing] b@example.com (invited)', output)
        self.assertIn('[skipped] bad (invalid email)', output)

    def test_empty_report_logs_zero_counts(self):
        with self.assertLogs(level='INFO') as logs:
            thycotic.ThycoticImporter()._print_thycotic_user_report({})
        self.assertIn('created 0, existing 0, skipped 0, failed 0', '\n'.join(logs.output))


class TestCustomSecretRoles(TestCase):
    def _secret(self):
        return {'id': 100, 'name': 'prod-db', 'folderId': 10, 'inheritPermissions': False}

    def test_custom_role_is_warned_and_known_roles_still_shared(self):
        auth = _secret_auth([self._secret()], secret_permissions={100: [
            {'userId': 5, 'secretAccessRoleName': 'Owner'},
            {'userId': 6, 'secretAccessRoleName': 'Auditor'},
            {'groupId': 9, 'secretAccessRoleName': 'Rotator'},
        ]})
        with self.assertLogs(level='WARNING') as logs:
            records = list(thycotic.ThycoticMixin.iter_secret_shares(auth, _folder_map()))
        self.assertEqual([share.name for share in records[0].shares], ['owner@example.com'])
        output = '\n'.join(logs.output)
        self.assertIn('Secret "prod-db" (100): role(s) Auditor, Rotator cannot be mapped', output)
        self.assertIn('1 secret(s) have custom roles that were not shared', output)

    def test_secret_with_only_custom_roles_is_warned_and_not_yielded(self):
        auth = _secret_auth([self._secret()], secret_permissions={100: [
            {'userId': 5, 'secretAccessRoleName': 'Auditor'},
            {'userId': 6},
        ]})
        with self.assertLogs(level='WARNING') as logs:
            records = list(thycotic.ThycoticMixin.iter_secret_shares(auth, _folder_map()))
        self.assertEqual(records, [])
        self.assertIn('role(s) (unnamed), Auditor cannot be mapped', '\n'.join(logs.output))

    def test_standard_roles_log_no_custom_role_warning(self):
        auth = _secret_auth([self._secret()], secret_permissions={100: [
            {'userId': 5, 'secretAccessRoleName': 'Owner'},
            {'userId': 6, 'secretAccessRoleName': 'list'},
        ]})
        with mock.patch.object(thycotic.logging, 'warning') as warning:
            records = list(thycotic.ThycoticMixin.iter_secret_shares(auth, _folder_map()))
        self.assertEqual(len(records[0].shares), 2)
        warning.assert_not_called()


def _response(status, body=None, text='', headers=None, reason=''):
    import json as json_module
    rs = mock.Mock()
    rs.status_code = status
    rs.reason = reason
    rs.headers = headers or {}
    rs.text = text or ('' if body is None else json_module.dumps(body))
    if body is None:
        rs.json.side_effect = ValueError('Expecting value: line 1 column 1 (char 0)')
    else:
        rs.json.return_value = body
    return rs


class TestSecretServerErrorResponses(TestCase):
    def _auth(self):
        auth = thycotic.ThycoticAuth('https://ss.example.com')
        auth.access_token = 'token'
        auth.expires_in = 3600
        auth.last_login = 10 ** 12
        return auth

    def test_error_message_handles_json_and_non_json_bodies(self):
        message = thycotic.ThycoticAuth._error_message
        self.assertEqual(message(_response(403, {'message': 'Access denied'})), 'Access denied')
        self.assertEqual(message(_response(400, {'error': 'invalid_grant'}), 'error'), 'invalid_grant')
        self.assertEqual(message(_response(502, text='<html>Bad Gateway</html>', reason='Bad Gateway')),
                         'HTTP 502 Bad Gateway: <html>Bad Gateway</html>')
        self.assertEqual(message(_response(500, ['x'], reason='Internal Server Error')),
                         'HTTP 500 Internal Server Error: ["x"]')
        self.assertEqual(message(_response(504, reason='Gateway Timeout')), 'HTTP 504 Gateway Timeout: <empty>')

    def test_search_raises_readable_error_for_html_page(self):
        with mock.patch.object(thycotic.requests, 'get',
                               return_value=_response(502, text='<html>', reason='Bad Gateway')):
            with self.assertRaises(Exception) as ctx:
                self._auth().thycotic_search('/v1/users')
        self.assertEqual(str(ctx.exception), 'HTTP 502 Bad Gateway: <html>')

    def test_entity_returns_none_for_html_error(self):
        with mock.patch.object(thycotic.requests, 'get', return_value=_response(503, text='<html>')):
            with self.assertLogs(level='INFO') as logs:
                self.assertIsNone(self._auth().thycotic_entity('/v1/secrets/1'))
        self.assertTrue(any('returned 503' in line for line in logs.output))

    def test_login_with_non_json_400_raises_readable_error(self):
        auth = thycotic.ThycoticAuth('https://ss.example.com')
        on_totp = mock.Mock()
        with mock.patch.object(thycotic.requests, 'post',
                               return_value=_response(400, text='<html>', reason='Bad Request')):
            with self.assertRaises(Exception) as ctx:
                auth.authenticate('user', 'secret', on_totp=on_totp)
        self.assertEqual(str(ctx.exception), 'HTTP 400 Bad Request: <html>')
        on_totp.assert_not_called()

    def test_login_still_asks_for_totp(self):
        auth = thycotic.ThycoticAuth('https://ss.example.com')
        responses = [
            _response(400, {'error': 'Login failed: TOTP code required'}),
            _response(200, {'access_token': 'abc', 'expires_in': 1200, 'refresh_token': 'r'}),
        ]
        with mock.patch.object(thycotic.requests, 'post', side_effect=responses) as post:
            auth.authenticate('user', 'secret', on_totp=lambda: '123456')
        self.assertEqual(auth.access_token, 'abc')
        self.assertEqual(post.call_args.kwargs['data']['OTP'], '123456')

    def test_refresh_with_non_json_error_raises_readable_error(self):
        auth = self._auth()
        auth.refresh_token = 'r'
        with mock.patch.object(thycotic.requests, 'post',
                               return_value=_response(500, text='oops', reason='Internal Server Error')):
            with self.assertRaises(Exception) as ctx:
                auth.refresh_auth_token()
        self.assertEqual(str(ctx.exception), 'HTTP 500 Internal Server Error: oops')


class TestSecretServerRateLimit(TestCase):
    def _auth(self):
        auth = thycotic.ThycoticAuth('https://ss.example.com')
        auth.access_token = 'token'
        auth.expires_in = 3600
        auth.last_login = 10 ** 12
        return auth

    def _ok(self):
        return _response(200, {'records': [{'id': 1}], 'hasNext': False})

    def test_429_is_retried_with_retry_after(self):
        responses = [_response(429, headers={'Retry-After': '12'}), self._ok()]
        with mock.patch.object(thycotic.requests, 'get', side_effect=responses), \
                mock.patch.object(thycotic.time, 'sleep') as sleep:
            with self.assertLogs(level='WARNING') as logs:
                result = self._auth().thycotic_search('/v1/users')
        self.assertEqual(result, [{'id': 1}])
        sleep.assert_called_once_with(12)
        self.assertTrue(any('rate limit (attempt 1/3), retrying in 12 seconds' in line for line in logs.output))

    def test_backoff_grows_when_no_retry_after(self):
        responses = [_response(429), _response(429), _response(429), self._ok()]
        with mock.patch.object(thycotic.requests, 'get', side_effect=responses), \
                mock.patch.object(thycotic.time, 'sleep') as sleep:
            with self.assertLogs(level='WARNING'):
                self._auth().thycotic_search('/v1/users')
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 10, 20])

    def test_backoff_wins_over_small_retry_after_and_large_hint_is_capped(self):
        auth = self._auth()
        self.assertEqual(auth._throttle_wait(_response(429, headers={'Retry-After': '1'}), 2), 10)
        self.assertEqual(auth._throttle_wait(_response(429, headers={'Retry-After': '9999'}), 1), 300)
        self.assertEqual(auth._throttle_wait(_response(429, headers={'Retry-After': 'Wed, 21 Oct 2026 07:28:00 GMT'}), 1), 5)

    def test_gives_up_after_max_retries(self):
        responses = [_response(429, {'message': 'Too many requests'}) for _ in range(4)]
        with mock.patch.object(thycotic.requests, 'get', side_effect=responses) as get, \
                mock.patch.object(thycotic.time, 'sleep') as sleep:
            with self.assertLogs(level='WARNING'):
                with self.assertRaises(Exception) as ctx:
                    self._auth().thycotic_search('/v1/users')
        self.assertEqual(get.call_count, 4)
        self.assertEqual(sleep.call_count, 3)
        self.assertEqual(str(ctx.exception), 'Too many requests')

    def test_entity_and_attachment_fetch_also_retry(self):
        auth = self._auth()
        with mock.patch.object(thycotic.requests, 'get',
                               side_effect=[_response(429), _response(200, {'id': 7})]), \
                mock.patch.object(thycotic.time, 'sleep'):
            with self.assertLogs(level='WARNING'):
                self.assertEqual(auth.thycotic_entity('/v1/secrets/7'), {'id': 7})
        with mock.patch.object(thycotic.requests, 'get',
                               side_effect=[_response(429), _response(200, {})]) as get, \
                mock.patch.object(thycotic.time, 'sleep'):
            with self.assertLogs(level='WARNING'):
                self.assertEqual(auth.thycotic_get('/v1/secrets/7/fields/file').status_code, 200)
        self.assertTrue(get.call_args.kwargs['stream'])

    def test_other_errors_are_not_retried(self):
        with mock.patch.object(thycotic.requests, 'get', return_value=_response(403, {'message': 'denied'})) as get, \
                mock.patch.object(thycotic.time, 'sleep') as sleep:
            with self.assertRaises(Exception):
                self._auth().thycotic_search('/v1/users')
        get.assert_called_once()
        sleep.assert_not_called()


class TestSecretShareHelpers(TestCase):
    def test_folder_path_accepts_int_or_str_ids(self):
        folders = {10: {'folderPath': '\\Apps'}, '11': {'folderPath': '\\Ops'}}
        path = thycotic.ThycoticMixin._secret_folder_path
        self.assertEqual(path(folders, 10), '\\Apps')
        self.assertEqual(path(folders, '10'), '\\Apps')
        self.assertEqual(path(folders, '11'), '\\Ops')
        self.assertEqual(path(folders, 404), '')
        self.assertEqual(path(folders, None), '')
        self.assertEqual(path(None, 10), '')
        self.assertEqual(path({10: {'folderPath': None}}, 10), '')

    def test_share_record_without_folder(self):
        shares = [RecordShare('owner@example.com', True, True)]
        record = thycotic.ThycoticMixin._secret_share_record('prod-db', '', shares)
        self.assertEqual(record.title, 'prod-db')
        self.assertFalse(record.folders)
        self.assertIs(record.shares, shares)

    def test_unnamed_secret_does_not_load_groups(self):
        secret = {'id': 100, 'name': '', 'folderId': 10, 'inheritPermissions': False}
        auth = _secret_auth([secret], secret_permissions={100: [{'groupId': 9, 'secretAccessRoleName': 'Owner'}]})
        list(thycotic.ThycoticMixin.iter_secret_shares(auth, _folder_map()))
        self.assertFalse(any(call.startswith('/v1/groups') for call in auth.calls))
