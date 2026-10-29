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
        on = import_parser.parse_args([
            '--format', 'thycotic', '--add-users', 'https://secret.example.com',
        ])
        self.assertTrue(on.add_users)


if __name__ == '__main__':
    logging.basicConfig()
    unittest.main()