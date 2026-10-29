import logging
import unittest
from types import SimpleNamespace
from unittest import mock

from keepercommander.importer.commands import import_parser
from keepercommander.importer.thycotic.thycotic import ThycoticImporter


class _QuietTestCase(unittest.TestCase):
    def setUp(self):
        self._patch('builtins.print')
        self._patch('keepercommander.importer.thycotic.thycotic.logging')
        self.log = self._mocks['logging']

    def _patch(self, target, **kwargs):
        patcher = mock.patch(target, **kwargs)
        name = target.rsplit('.', 1)[-1]
        self.__dict__.setdefault('_mocks', {})[name] = patcher.start()
        self.addCleanup(patcher.stop)

    def importer(self):
        return ThycoticImporter()


class TestExtractUserEmail(_QuietTestCase):
    def test_email_priority_and_edge_cases(self):
        cases = [
            ('emailAddress is used', {'emailAddress': 'biz@x.com', 'email': 'other@x.com'}, 'biz@x.com'),
            ('email is ignored', {'email': 'other@x.com'}, ''),
            ('blank emailAddress is empty', {'emailAddress': '   ', 'email': 'other@x.com'}, ''),
            ('keys are case-insensitive', {'EmailAddress': '  Biz@x.com '}, 'Biz@x.com'),
            ('non-string is ignored', {'emailAddress': 42, 'email': 'other@x.com'}, ''),
            ('no address', {'userName': 'bob'}, ''),
            ('None input', None, ''),
            ('list input', ['a@x.com'], ''),
        ]
        importer = self.importer()
        for name, user, expected in cases:
            with self.subTest(name):
                self.assertEqual(importer._extract_user_email(user), expected)


class TestPrepareThycoticUsers(_QuietTestCase):
    def _prepare(self, users, details=None):
        auth = mock.MagicMock()
        auth.thycotic_search.return_value = users
        auth.thycotic_entity.side_effect = details or (lambda endpoint: None)
        found = self.importer()._prepare_thycotic_users(auth)
        return found, auth

    def test_list_email_skips_detail_fetch(self):
        found, auth = self._prepare([
            {'id': 1, 'userName': 'a', 'displayName': 'Alice', 'emailAddress': 'a@x.com'},
        ])
        self.assertEqual(found, [{
            'id': 1, 'username': 'a', 'name': 'Alice', 'email': 'a@x.com',
        }])
        auth.thycotic_search.assert_called_once_with('/v1/users?filter.includeInactive=true')
        auth.thycotic_entity.assert_not_called()

    def test_missing_email_is_fetched_from_user_detail(self):
        found, auth = self._prepare(
            [{'id': 7, 'userName': 'b', 'displayName': ''}],
            details=lambda endpoint: {'emailAddress': 'b@x.com', 'displayName': 'Bob'},
        )
        self.assertEqual(found, [{
            'id': 7, 'username': 'b', 'name': 'Bob', 'email': 'b@x.com',
        }])
        auth.thycotic_entity.assert_called_once_with('/v1/users/7')

    def test_detail_fetch_failure_skips_only_that_user(self):
        def details(endpoint):
            if str(endpoint).endswith('/1'):
                raise RuntimeError('403 Forbidden')
            return {'emailAddress': 'ok@x.com', 'displayName': 'Ok'}

        found, _ = self._prepare(
            [
                {'id': 1, 'userName': 'bad'},
                {'id': 2, 'userName': 'ok', 'displayName': ''},
            ],
            details=details,
        )
        self.assertEqual([u['username'] for u in found], ['ok'])
        self.log.warning.assert_called()

    def test_application_accounts_are_omitted(self):
        found, auth = self._prepare([
            {'id': 1, 'userName': 'svc', 'emailAddress': 'svc@x.com', 'isApplicationAccount': True},
            {'id': 2, 'userName': 'ok', 'emailAddress': 'ok@x.com', 'isApplicationAccount': False},
        ])
        self.assertEqual([u['username'] for u in found], ['ok'])
        auth.thycotic_entity.assert_not_called()
        self.log.info.assert_called()

    def test_rows_without_usable_email_are_omitted(self):
        found, auth = self._prepare([
            {'userName': 'no-email-no-id'},
            {'id': '', 'userName': 'blank-id'},
            {'id': 3, 'userName': 'details-empty'},
            'not-a-dict',
            None,
        ])
        self.assertEqual(found, [])
        auth.thycotic_entity.assert_called_once_with('/v1/users/3')

    def test_inactive_users_are_included(self):
        found, _ = self._prepare([
            {'id': 1, 'userName': 'gone', 'displayName': 'Gone', 'emailAddress': 'gone@x.com', 'enabled': False},
        ])
        self.assertEqual(found[0]['email'], 'gone@x.com')

    def test_name_falls_back_to_username(self):
        found, _ = self._prepare([{'id': 1, 'userName': 'carol', 'emailAddress': 'c@x.com'}])
        self.assertEqual(found[0]['name'], 'carol')
        self.assertEqual(found[0]['username'], 'carol')


class TestLoadExistingKeeperUsers(_QuietTestCase):
    def setUp(self):
        super().setUp()
        self._patch('keepercommander.importer.thycotic.thycotic.api.query_enterprise')
        self.query = self._mocks['query_enterprise']

    def test_cached_enterprise_with_real_keeper_shape(self):
        params = SimpleNamespace(enterprise={'users': [
            {'username': ' Alice@X.com ', 'status': 'invited'},
            {'username': 'bob@x.com'},
            'junk',
        ]})
        users = self.importer()._load_existing_keeper_users(params)
        self.assertEqual(users, [
            {'email': 'Alice@X.com', 'status': 'invited'},
            {'email': 'bob@x.com', 'status': 'active'},
        ])
        self.query.assert_not_called()

    def test_enterprise_is_queried_when_not_loaded(self):
        params = SimpleNamespace(enterprise=None)
        self.query.side_effect = lambda p: setattr(p, 'enterprise', {'users': [{'email': 'a@x.com'}]})
        users = self.importer()._load_existing_keeper_users(params)
        self.assertEqual(users, [{'email': 'a@x.com', 'status': 'active'}])

    def test_query_failure_returns_empty_and_warns(self):
        self.query.side_effect = RuntimeError('not an admin')
        users = self.importer()._load_existing_keeper_users(SimpleNamespace(enterprise=None))
        self.assertEqual(users, [])
        self.log.warning.assert_called_once()


class TestCreateEnterpriseUsers(_QuietTestCase):
    def _run(self, users, existing=(), create_result='uid'):
        importer = self.importer()
        importer._load_existing_keeper_users = mock.MagicMock(return_value=list(existing))
        importer._create_keeper_user = mock.MagicMock(return_value=create_result)
        importer._create_enterprise_users(object(), users)
        return importer._create_keeper_user

    def test_creates_only_new_valid_users(self):
        create = self._run(
            [
                {'username': 'new', 'name': 'New User', 'email': 'new@x.com'},
                {'username': 'old', 'email': 'old@x.com'},
                {'username': 'bad', 'email': 'not-an-email'},
                {'username': 'blank', 'email': ''},
                {},
                '',
                None,
            ],
            existing=[{'email': 'old@x.com', 'status': 'locked'}],
        )
        create.assert_called_once_with(mock.ANY, 'new@x.com', 'New User')

    def test_existing_match_ignores_case(self):
        create = self._run(
            [{'username': 'john', 'email': 'John.Doe@Corp.com'}],
            existing=[{'email': 'john.doe@corp.com', 'status': 'active'}],
        )
        create.assert_not_called()

    def test_case_variant_duplicates_are_created_once(self):
        create = self._run([
            {'username': 'a1', 'email': 'A@corp.com'},
            {'username': 'a2', 'email': 'a@corp.com'},
        ])
        create.assert_called_once()

    def test_email_is_trimmed_and_name_falls_back_to_email(self):
        create = self._run([{'username': None, 'email': '  c@x.com  '}])
        create.assert_called_once_with(mock.ANY, 'c@x.com', 'c@x.com')

    def test_failed_create_is_not_retried(self):
        create = self._run(
            [{'username': 'f', 'email': 'f@x.com'}, {'username': 'f', 'email': 'f@x.com'}],
            create_result=None,
        )
        create.assert_called_once()


class TestCreateKeeperUser(_QuietTestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch('keepercommander.commands.enterprise_create_user.CreateEnterpriseUserCommand')
        self.command_cls = patcher.start()
        self.addCleanup(patcher.stop)

    def test_forwards_email_and_name(self):
        self.command_cls.return_value.execute.return_value = 'record-uid'
        params = object()
        self.assertEqual(self.importer()._create_keeper_user(params, 'a@x.com', 'Alice'), 'record-uid')
        self.command_cls.return_value.execute.assert_called_once_with(params, email='a@x.com', name='Alice')

    def test_error_returns_none_and_warns(self):
        self.command_cls.return_value.execute.side_effect = RuntimeError('reserved domain required')
        self.assertIsNone(self.importer()._create_keeper_user(object(), 'a@x.com', 'Alice'))
        self.log.warning.assert_called_once()


class TestMigrateDoesNotAbortImport(_QuietTestCase):
    def test_fetch_failure_is_logged_and_swallowed(self):
        importer = self.importer()
        auth = mock.MagicMock()
        auth.thycotic_search.side_effect = RuntimeError('401')
        importer._migrate_thycotic_users(auth, object())
        self.assertGreaterEqual(self.log.warning.call_count, 2)


class TestDoImportUserGate(_QuietTestCase):
    def _run(self, **kwargs):
        importer = self.importer()
        auth = mock.MagicMock()
        auth.thycotic_search.return_value = []
        params = mock.Mock()
        params.rest_context.proxies = None
        with mock.patch('keepercommander.importer.thycotic.thycotic.getpass.getpass', return_value='pw'), \
                mock.patch('keepercommander.importer.thycotic.thycotic.ThycoticAuth', return_value=auth), \
                mock.patch.object(ThycoticImporter, 'get_folders', return_value={}), \
                mock.patch.object(importer, '_migrate_thycotic_users') as migrate, \
                mock.patch.object(importer, '_preview_thycotic_users') as preview, \
                mock.patch('os.path.isfile', return_value=False):
            list(importer.do_import('user@secret.example.com', params=params, **kwargs))
        return migrate, preview

    def test_flag_provisions_users_before_secrets(self):
        migrate, preview = self._run(add_users=True)
        migrate.assert_called_once()
        preview.assert_not_called()

    def test_flag_absent_does_not_provision(self):
        migrate, preview = self._run()
        migrate.assert_not_called()
        preview.assert_not_called()

    def test_dry_run_prints_users_without_creating_them(self):
        migrate, preview = self._run(add_users=True, dry_run=True)
        migrate.assert_not_called()
        preview.assert_called_once()

    def test_preview_prints_fetched_users(self):
        importer = self.importer()
        importer._prepare_thycotic_users = mock.Mock(return_value=[
            {'username': 'a', 'email': 'a@x.com', 'name': 'Alice'},
        ])
        importer._create_enterprise_users = mock.Mock()
        importer._preview_thycotic_users(mock.Mock())
        printed = ' '.join(str(call) for call in self.log.info.call_args_list)
        self.assertIn('Thycotic users available to migrate', printed)
        self.assertIn('a@x.com', printed)
        self.assertIn('Alice', printed)
        importer._create_enterprise_users.assert_not_called()


class TestImportParser(unittest.TestCase):
    def test_flag_defaults_off_and_parses(self):
        off = import_parser.parse_args(['--format', 'thycotic', 'https://secret.example.com'])
        self.assertFalse(off.add_users)
        self.assertFalse(off.add_teams)
        on = import_parser.parse_args([
            '--format', 'thycotic', '--add-users', '--add-teams',
            'https://secret.example.com',
        ])
        self.assertTrue(on.add_users)
        self.assertTrue(on.add_teams)


class TestPrepareThycoticGroups(_QuietTestCase):
    def _groups(self, groups, members=None, users=None, user_error=None):
        auth = mock.MagicMock()

        def search(endpoint):
            endpoint = str(endpoint)
            if endpoint == '/v1/groups':
                return groups
            return (members or {}).get(endpoint, [])

        auth.thycotic_search.side_effect = search
        importer = self.importer()
        if user_error is not None:
            importer._prepare_thycotic_users = mock.Mock(side_effect=user_error)
        else:
            importer._prepare_thycotic_users = mock.Mock(return_value=users or [])
        found = importer._prepare_thycotic_groups(auth)
        return found, importer

    def test_uses_direct_members_and_skips_disabled(self):
        found, importer = self._groups(
            [
                {'id': 10, 'name': 'Admins', 'enabled': True, 'memberCount': 2},
                {'id': 11, 'name': 'Empty', 'enabled': True, 'memberCount': 0},
                {'id': 12, 'name': 'Disabled', 'enabled': False, 'memberCount': 1},
                {'id': 13, 'name': '  Nested ', 'enabled': True, 'memberCount': 1},
                {'name': 'no-id', 'memberCount': 1},
                'junk',
            ],
            members={
                '/v1/groups/10/users': [
                    {'userId': 1, 'groupId': 0},
                    {'userId': 2},
                    {'userId': 9},
                ],
                '/v1/groups/13/users': [{'groupId': 10, 'userId': 0}, {'userId': 2}],
            },
            users=[
                {'id': 1, 'email': 'a@x.com'},
                {'id': 2, 'email': 'b@x.com'},
            ],
        )
        importer._prepare_thycotic_users.assert_called_once_with(mock.ANY, quiet=True)
        self.assertEqual(
            [(g['name'], g['members']) for g in found],
            [
                ('Admins', ['a@x.com', 'b@x.com']),
                ('Empty', []),
                ('Nested', ['b@x.com']),
            ],
        )
        self.log.info.assert_called()

    def test_same_names_stay_separate_groups(self):
        found, _ = self._groups(
            [
                {'id': 1, 'name': 'Ops', 'memberCount': 1},
                {'id': 2, 'name': 'ops', 'memberCount': 1},
            ],
            members={
                '/v1/groups/1/users': [{'userId': 1}],
                '/v1/groups/2/users': [{'userId': 2}],
            },
            users=[{'id': 1, 'email': 'a@x.com'}, {'id': 2, 'email': 'B@x.com'}],
        )
        self.assertEqual(found, [
            {'id': 1, 'name': 'Ops', 'members': ['a@x.com']},
            {'id': 2, 'name': 'ops', 'members': ['B@x.com']},
        ])

    def test_member_fetch_failure_keeps_the_group(self):
        auth = mock.MagicMock()

        def search(endpoint):
            if str(endpoint) == '/v1/groups':
                return [{'id': 3, 'name': 'Ops', 'memberCount': 4}]
            raise RuntimeError('403')

        auth.thycotic_search.side_effect = search
        importer = self.importer()
        importer._prepare_thycotic_users = mock.Mock(return_value=[])
        found = importer._prepare_thycotic_groups(auth)
        self.assertEqual(found, [{'id': 3, 'name': 'Ops', 'members': []}])
        self.log.warning.assert_called()

    def test_user_lookup_failure_still_returns_groups(self):
        found, _ = self._groups(
            [{'id': 3, 'name': 'Ops', 'memberCount': 0}],
            user_error=RuntimeError('users down'),
        )
        self.assertEqual(found[0]['name'], 'Ops')
        self.log.warning.assert_called()


class TestLoadExistingKeeperTeams(_QuietTestCase):
    def setUp(self):
        super().setUp()
        self._patch('keepercommander.importer.thycotic.thycotic.api.query_enterprise')
        self.query = self._mocks['query_enterprise']

    def test_active_team_replaces_queued_team_of_the_same_name(self):
        params = SimpleNamespace(enterprise={
            'queued_teams': [{'name': 'Ops', 'team_uid': 'queued'}],
            'teams': [
                {'name': ' Ops ', 'team_uid': 'real', 'restrict_edit': False},
                {'name': 'Empty', 'team_uid': ''},
            ],
            'team_users': [
                {'team_uid': 'real', 'enterprise_user_id': 7},
                {'team_uid': 'real', 'enterprise_user_id': None},
                'junk',
            ],
            'queued_team_users': [{'team_uid': 'queued', 'users': [8, 0]}],
        })
        teams, members, error = self.importer()._load_existing_keeper_teams(params)
        self.assertEqual(error, '')
        self.assertEqual(teams['ops']['team_uid'], 'real')
        self.assertEqual(members, {'real': {7}, 'queued': {8}})
        self.query.assert_called_once()

    def test_query_failure_returns_error(self):
        self.query.side_effect = RuntimeError('not an admin')
        teams, members, error = self.importer()._load_existing_keeper_teams(SimpleNamespace(enterprise=None))
        self.assertEqual((teams, members, bool(error)), ({}, {}, True))


class TestBuildTeamAddRequest(_QuietTestCase):
    def _params(self, **extra):
        params = {
            'enterprise': {'unencrypted_tree_key': b'tree'},
            'data_key': b'data',
            'forbid_rsa': False,
        }
        params.update(extra)
        return SimpleNamespace(**params)

    def _patches(self):
        targets = {
            'keepercommander.importer.thycotic.thycotic.api.generate_record_uid': {'return_value': 'uid-1'},
            'keepercommander.importer.thycotic.thycotic.api.generate_aes_key': {'return_value': b'k' * 32},
            'keepercommander.crypto.encrypt_aes_v1': {'return_value': b'v1'},
            'keepercommander.crypto.encrypt_aes_v2': {'return_value': b'v2'},
            'keepercommander.crypto.generate_ec_key': {'return_value': ('ec-priv', 'ec-pub')},
            'keepercommander.crypto.unload_ec_private_key': {'return_value': b'ec-priv'},
            'keepercommander.crypto.unload_ec_public_key': {'return_value': b'ec-pub'},
            'keepercommander.crypto.generate_rsa_key': {'return_value': ('rsa-priv', 'rsa-pub')},
            'keepercommander.crypto.unload_rsa_private_key': {'return_value': b'rsa-priv'},
            'keepercommander.crypto.unload_rsa_public_key': {'return_value': b'rsa-pub'},
            'keepercommander.utils.base64_url_encode': {'side_effect': lambda value: 'b64-' + value.decode()},
        }
        started = {}
        for target, kwargs in targets.items():
            patcher = mock.patch(target, **kwargs)
            started[target.rsplit('.', 1)[-1]] = patcher.start()
            self.addCleanup(patcher.stop)
        return started

    def test_request_matches_enterprise_team_add(self):
        self._patches()
        request, team_key = self.importer()._build_team_add_request(self._params(), 'Admins', 9)
        self.assertEqual(team_key, b'k' * 32)
        self.assertEqual(request['command'], 'team_add')
        self.assertEqual(request['team_uid'], 'uid-1')
        self.assertEqual(request['team_name'], 'Admins')
        self.assertEqual(request['node_id'], 9)
        self.assertTrue(request['manage_only'])
        self.assertIn('public_key', request)
        self.assertIn('private_key', request)
        self.assertIn('ecc_public_key', request)

    def test_rsa_keys_omitted_when_forbidden(self):
        patched = self._patches()
        request, _ = self.importer()._build_team_add_request(self._params(forbid_rsa=True), 'Admins', 9)
        self.assertNotIn('public_key', request)
        self.assertNotIn('private_key', request)
        patched['generate_rsa_key'].assert_not_called()

    def test_missing_keys_raise(self):
        with self.assertRaises(ValueError):
            self.importer()._build_team_add_request(SimpleNamespace(enterprise={}, data_key=None), 'Admins', 9)


class TestAddTeamMembers(_QuietTestCase):
    def _params(self):
        return SimpleNamespace(enterprise={'users': [
            {'username': 'A@x.com', 'enterprise_user_id': 1, 'status': 'active'},
            {'username': 'b@x.com', 'enterprise_user_id': 2, 'status': 'invited'},
            {'username': 'c@x.com', 'enterprise_user_id': 3, 'status': 'active'},
        ]})

    def test_active_users_are_added_and_invited_users_are_queued(self):
        importer = self.importer()
        with mock.patch(
            'keepercommander.commands.enterprise.EnterpriseTeamCommand._create_add_user_request',
            return_value={'command': 'team_enterprise_user_add', 'enterprise_user_id': 1},
        ) as add_user, mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            return_value=[{'result': 'success'}, {'result': 'success'}],
        ) as batch:
            counts = importer._add_team_members(
                self._params(), 'uid', 'Ops', b'key',
                ['a@x.com', 'b@x.com', 'c@x.com', 'missing@x.com', ''],
                {3}, True,
            )
        self.assertEqual(counts, {'added': 1, 'queued': 1, 'already': 1, 'missing': 1, 'failed': 0})
        queued, active = batch.call_args[0][1]
        self.assertEqual(queued['command'], 'team_queue_user')
        self.assertEqual(queued['enterprise_user_id'], 2)
        self.assertEqual(active['command'], 'team_enterprise_user_add')
        add_user.assert_called_once()
        self.log.warning.assert_called()

    def test_queued_team_does_not_encrypt_a_team_key(self):
        importer = self.importer()
        with mock.patch(
            'keepercommander.commands.enterprise.EnterpriseTeamCommand._create_add_user_request',
        ) as add_user, mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            return_value=[{'result': 'success'}],
        ) as batch:
            counts = importer._add_team_members(
                self._params(), 'uid', 'Ops', None, ['a@x.com'], set(), False,
            )
        add_user.assert_not_called()
        self.assertEqual(batch.call_args[0][1][0]['command'], 'team_queue_user')
        self.assertEqual(counts['queued'], 1)

    def test_already_exists_response_counts_as_already_on_team(self):
        importer = self.importer()
        with mock.patch(
            'keepercommander.commands.enterprise.EnterpriseTeamCommand._create_add_user_request',
            return_value={'command': 'team_enterprise_user_add', 'enterprise_user_id': 1},
        ), mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            return_value=[{
                'result': 'fail',
                'message': 'The object you are trying to create already exists.',
            }],
        ):
            counts = importer._add_team_members(
                self._params(), 'uid', 'Ops', b'key', ['a@x.com'], set(), True,
            )
        self.assertEqual(counts, {'added': 0, 'queued': 0, 'already': 1, 'missing': 0, 'failed': 0})
        self.log.warning.assert_not_called()

    def test_missing_team_key_counts_as_failed(self):
        importer = self.importer()
        importer._load_team_key = mock.Mock(return_value=None)
        with mock.patch('keepercommander.importer.thycotic.thycotic.api.execute_batch') as batch:
            counts = importer._add_team_members(
                self._params(), 'uid', 'Ops', None, ['a@x.com'], set(), True,
            )
        batch.assert_not_called()
        self.assertEqual(counts['failed'], 1)
        self.log.warning.assert_called()


class TestCreateEnterpriseTeams(_QuietTestCase):
    def _importer(self, existing=None, error=''):
        importer = self.importer()
        importer._load_existing_keeper_teams = mock.Mock(return_value=(existing or {}, {}, error))
        importer._resolve_root_node_id = mock.Mock(return_value=5)
        importer._build_team_add_request = mock.Mock(
            return_value=({'command': 'team_add', 'team_uid': 'uid-1'}, b'key'))
        importer._add_team_members = mock.Mock(return_value={
            'added': 1, 'queued': 0, 'already': 0, 'missing': 0, 'failed': 0,
        })
        return importer

    def _params(self):
        return SimpleNamespace(enterprise={'unencrypted_tree_key': b'tree'}, data_key=b'data')

    def test_creates_a_team_then_adds_members(self):
        importer = self._importer()
        with mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            return_value=[{'result': 'success'}],
        ) as batch, mock.patch('keepercommander.importer.thycotic.thycotic.api.query_enterprise') as refresh:
            importer._create_enterprise_teams(self._params(), [
                {'name': 'Admins', 'members': [' a@x.com ']},
                {'name': 'admins', 'members': ['other@x.com']},
                {'name': '  ', 'members': ['x@x.com']},
                None,
            ])
        batch.assert_called_once()
        self.assertEqual(batch.call_args[0][1][0]['command'], 'team_add')
        refresh.assert_called_once()
        importer._add_team_members.assert_called_once_with(
            mock.ANY, 'uid-1', 'Admins', b'key', ['a@x.com'], set(), True)

    def test_existing_team_is_not_created_and_gains_missing_members(self):
        importer = self._importer(existing={
            'ops': {'name': 'Ops', 'team_uid': 'uid-ops', 'restrict_edit': False},
        })
        importer._load_existing_keeper_teams.return_value = (
            {'ops': {'name': 'Ops', 'team_uid': 'uid-ops', 'restrict_edit': False}},
            {'uid-ops': {4}},
            '',
        )
        with mock.patch('keepercommander.importer.thycotic.thycotic.api.execute_batch') as batch:
            importer._create_enterprise_teams(self._params(), [{'name': 'OPS', 'members': ['a@x.com']}])
        batch.assert_not_called()
        importer._build_team_add_request.assert_not_called()
        importer._add_team_members.assert_called_once_with(
            mock.ANY, 'uid-ops', 'Ops', None, ['a@x.com'], {4}, True)

    def test_failed_create_does_not_add_members(self):
        importer = self._importer()
        with mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            return_value=[{'result': 'fail', 'message': 'exists'}],
        ), mock.patch('keepercommander.importer.thycotic.thycotic.api.query_enterprise') as refresh:
            importer._create_enterprise_teams(self._params(), [{'name': 'Admins', 'members': ['a@x.com']}])
        importer._add_team_members.assert_not_called()
        refresh.assert_not_called()
        self.log.warning.assert_called()

    def test_loader_error_skips_team_creation(self):
        importer = self._importer(error='Failed to load existing Keeper teams')
        with mock.patch('keepercommander.importer.thycotic.thycotic.api.execute_batch') as batch:
            importer._create_enterprise_teams(self._params(), [{'name': 'Admins', 'members': []}])
        batch.assert_not_called()
        importer._add_team_members.assert_not_called()

    def test_missing_root_node_skips_create(self):
        importer = self._importer()
        importer._resolve_root_node_id.return_value = None
        with mock.patch('keepercommander.importer.thycotic.thycotic.api.execute_batch') as batch:
            importer._create_enterprise_teams(self._params(), [{'name': 'Admins', 'members': []}])
        batch.assert_not_called()
        self.log.warning.assert_called()


class TestMigrateTeamsDoesNotAbortImport(_QuietTestCase):
    def test_fetch_failure_is_logged_and_swallowed(self):
        importer = self.importer()
        auth = mock.MagicMock()
        auth.thycotic_search.side_effect = RuntimeError('401')
        importer._migrate_thycotic_teams(auth, object())
        self.assertGreaterEqual(self.log.warning.call_count, 2)


class TestDoImportTeamGate(_QuietTestCase):
    def _run(self, **kwargs):
        importer = self.importer()
        auth = mock.MagicMock()
        auth.thycotic_search.return_value = []
        params = mock.Mock()
        params.rest_context.proxies = None
        with mock.patch('keepercommander.importer.thycotic.thycotic.getpass.getpass', return_value='pw'), \
                mock.patch('keepercommander.importer.thycotic.thycotic.ThycoticAuth', return_value=auth), \
                mock.patch.object(ThycoticImporter, 'get_folders', return_value={}), \
                mock.patch.object(importer, '_migrate_thycotic_users') as migrate_users, \
                mock.patch.object(importer, '_preview_thycotic_users') as preview_users, \
                mock.patch.object(importer, '_migrate_thycotic_teams') as migrate_teams, \
                mock.patch.object(importer, '_preview_thycotic_teams') as preview_teams, \
                mock.patch('os.path.isfile', return_value=False):
            list(importer.do_import('user@secret.example.com', params=params, **kwargs))
        return migrate_users, preview_users, migrate_teams, preview_teams

    def test_flag_creates_teams(self):
        _, _, migrate, preview = self._run(add_teams=True)
        migrate.assert_called_once()
        preview.assert_not_called()

    def test_flag_absent_does_not_create_teams(self):
        _, _, migrate, preview = self._run()
        migrate.assert_not_called()
        preview.assert_not_called()

    def test_dry_run_prints_groups_without_creating_them(self):
        _, _, migrate, preview = self._run(add_teams=True, dry_run=True)
        migrate.assert_not_called()
        preview.assert_called_once()

    def test_users_are_provisioned_before_teams(self):
        importer = self.importer()
        order = []
        auth = mock.MagicMock()
        params = mock.Mock()
        params.rest_context.proxies = None
        with mock.patch('keepercommander.importer.thycotic.thycotic.getpass.getpass', return_value='pw'), \
                mock.patch('keepercommander.importer.thycotic.thycotic.ThycoticAuth', return_value=auth), \
                mock.patch.object(ThycoticImporter, 'get_folders', return_value={}), \
                mock.patch.object(importer, '_migrate_thycotic_users',
                                  side_effect=lambda *args, **kwargs: order.append('users')), \
                mock.patch.object(importer, '_migrate_thycotic_teams',
                                  side_effect=lambda *args, **kwargs: order.append('teams')), \
                mock.patch('os.path.isfile', return_value=False):
            list(importer.do_import(
                'user@secret.example.com', params=params,
                add_users=True, add_teams=True,
            ))
        self.assertEqual(order, ['users', 'teams'])

    def test_preview_prints_groups_without_creating_teams(self):
        importer = self.importer()
        importer._prepare_thycotic_groups = mock.Mock(return_value=[
            {'name': 'Ops', 'members': ['a@x.com']},
        ])
        importer._create_enterprise_teams = mock.Mock()
        importer._preview_thycotic_teams(mock.Mock())
        printed = ' '.join(str(call) for call in self.log.info.call_args_list)
        self.assertIn('Thycotic groups available to migrate', printed)
        self.assertIn('Ops', printed)
        self.assertIn('a@x.com', printed)
        importer._create_enterprise_teams.assert_not_called()


if __name__ == '__main__':
    logging.basicConfig()
    unittest.main()