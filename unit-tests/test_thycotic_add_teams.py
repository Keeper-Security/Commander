import logging
import unittest
from types import SimpleNamespace
from unittest import mock

from keepercommander.commands.helpers.team import MissingTeamEncryptionKey
from keepercommander.importer.commands import import_parser
from keepercommander.importer.thycotic.thycotic import (
    TeamMemberCounts, ThycoticImporter, _TEAM_BATCH_SIZE,
)


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

    def test_member_fetch_failure_stops_preparation(self):
        auth = mock.MagicMock()
        error = RuntimeError('403')

        def search(endpoint):
            endpoint = str(endpoint)
            if endpoint == '/v1/groups':
                return [
                    {'id': 1, 'name': 'Admins', 'memberCount': 1},
                    {'id': 3, 'name': 'Ops', 'memberCount': 4},
                ]
            if endpoint == '/v1/groups/1/users':
                return [{'userId': 1}]
            raise error

        auth.thycotic_search.side_effect = search
        importer = self.importer()
        importer._prepare_thycotic_users = mock.Mock(return_value=[
            {'id': 1, 'email': 'a@x.com'},
        ])
        importer._create_enterprise_teams = mock.Mock()

        with self.assertRaises(Exception) as caught:
            importer._prepare_thycotic_groups(auth)
        self.assertIn('Ops', str(caught.exception))
        self.assertIn('403', str(caught.exception))
        self.assertIs(caught.exception.__cause__, error)

        importer._migrate_thycotic_teams(auth, object())
        importer._create_enterprise_teams.assert_not_called()
        self.log.warning.assert_any_call(
            'Continuing import without creating Keeper teams.',
        )
        fetch_failures = [
            call.args[1] for call in self.log.warning.call_args_list
            if call.args and call.args[0] == 'Failed to fetch Thycotic groups: %s'
        ]
        self.assertTrue(fetch_failures)
        self.assertIn('Ops', str(fetch_failures[-1]))
        self.assertIn('403', str(fetch_failures[-1]))

        importer._preview_thycotic_teams(auth)
        importer._create_enterprise_teams.assert_not_called()
        info = ' '.join(str(call.args[0]) for call in self.log.info.call_args_list)
        self.assertNotIn('Thycotic groups available to migrate', info)

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
                {'name': 'ops', 'team_uid': 'lower', 'restrict_edit': False},
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
        self.assertEqual(teams['Ops']['team_uid'], 'real')
        self.assertEqual(teams['ops']['team_uid'], 'lower')
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
            'keepercommander.commands.helpers.team.api.generate_record_uid': {'return_value': 'uid-1'},
            'keepercommander.commands.helpers.team.api.generate_aes_key': {'return_value': b'k' * 32},
            'keepercommander.commands.helpers.team.crypto.encrypt_aes_v1': {'return_value': b'v1'},
            'keepercommander.commands.helpers.team.crypto.encrypt_aes_v2': {'return_value': b'v2'},
            'keepercommander.commands.helpers.team.crypto.generate_ec_key': {'return_value': ('ec-priv', 'ec-pub')},
            'keepercommander.commands.helpers.team.crypto.unload_ec_private_key': {'return_value': b'ec-priv'},
            'keepercommander.commands.helpers.team.crypto.unload_ec_public_key': {'return_value': b'ec-pub'},
            'keepercommander.commands.helpers.team.crypto.generate_rsa_key': {'return_value': ('rsa-priv', 'rsa-pub')},
            'keepercommander.commands.helpers.team.crypto.unload_rsa_private_key': {'return_value': b'rsa-priv'},
            'keepercommander.commands.helpers.team.crypto.unload_rsa_public_key': {'return_value': b'rsa-pub'},
            'keepercommander.commands.helpers.team.utils.base64_url_encode': {
                'side_effect': lambda value: 'b64-' + value.decode()},
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
        with self.assertRaises(MissingTeamEncryptionKey) as caught:
            self.importer()._build_team_add_request(SimpleNamespace(enterprise={}, data_key=None), 'Admins', 9)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertEqual(str(caught.exception), 'Enterprise tree key or data key is not available')


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
        self.assertEqual(counts, TeamMemberCounts(added=1, queued=1, already=1, missing=1, failed=0))
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
        self.assertEqual(counts.queued, 1)

    def test_captured_success_counts_as_added_and_duplicate_comes_from_membership(self):
        importer = self.importer()
        captured = {
            'result': 'success',
            'result_code': '',
            'message': '',
            'command': 'team_enterprise_user_add',
            'revision': 4027138144,
        }
        queued_success = {
            'result': 'success',
            'result_code': '',
            'message': '',
            'command': 'team_queue_user',
            'revision': 4027138145,
        }
        with mock.patch(
            'keepercommander.commands.enterprise.EnterpriseTeamCommand._create_add_user_request',
            return_value={'command': 'team_enterprise_user_add', 'enterprise_user_id': 1},
        ), mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            side_effect=[
                [captured],
                [queued_success],
                [{
                    'result': 'fail',
                    'result_code': 'exists',
                    'message': 'The object you are trying to create already exists.',
                }],
                [{
                    'result': 'fail',
                    'message': 'The object you are trying to create already exists.',
                }],
            ],
        ) as batch:
            added = importer._add_team_members(
                self._params(), 'uid', 'Ops', b'key', ['a@x.com'], set(), True,
            )
            queued = importer._add_team_members(
                self._params(), 'uid', 'Ops', None, ['b@x.com'], set(), False,
            )
            coded_failure = importer._add_team_members(
                self._params(), 'uid', 'Ops', b'key', ['a@x.com'], set(), True,
            )
            message_failure = importer._add_team_members(
                self._params(), 'uid', 'Ops', b'key', ['a@x.com'], set(), True,
            )
            already = importer._add_team_members(
                self._params(), 'uid', 'Ops', b'key', ['a@x.com'], {1}, True,
            )
        self.assertEqual(added, TeamMemberCounts(added=1, queued=0, already=0, missing=0, failed=0))
        self.assertEqual(queued, TeamMemberCounts(added=0, queued=1, already=0, missing=0, failed=0))
        self.assertEqual(coded_failure, TeamMemberCounts(added=0, queued=0, already=0, missing=0, failed=1))
        self.assertEqual(message_failure, TeamMemberCounts(added=0, queued=0, already=0, missing=0, failed=1))
        self.assertEqual(already, TeamMemberCounts(added=0, queued=0, already=1, missing=0, failed=0))
        self.assertEqual(batch.call_count, 4)
        self.assertEqual(
            [call.args[0] for call in self.log.warning.call_args_list],
            [
                'Failed to add a member to team "%s": %s',
                'Failed to add a member to team "%s": %s',
            ],
        )

    def test_missing_team_key_counts_as_failed(self):
        importer = self.importer()
        importer._load_team_key = mock.Mock(return_value=None)
        with mock.patch('keepercommander.importer.thycotic.thycotic.api.execute_batch') as batch:
            counts = importer._add_team_members(
                self._params(), 'uid', 'Ops', None, ['a@x.com'], set(), True,
            )
        batch.assert_not_called()
        self.assertEqual(counts.failed, 1)
        self.log.warning.assert_called()

    def test_member_adds_are_chunked_and_counts_stay_aligned(self):
        self.assertEqual(_TEAM_BATCH_SIZE, 25)
        importer = self.importer()
        params = SimpleNamespace(enterprise={'users': [
            {'username': 'q1@x.com', 'enterprise_user_id': 11, 'status': 'invited'},
            {'username': 'q2@x.com', 'enterprise_user_id': 12, 'status': 'invited'},
            {'username': 'q3@x.com', 'enterprise_user_id': 13, 'status': 'invited'},
            {'username': 'q4@x.com', 'enterprise_user_id': 14, 'status': 'invited'},
            {'username': 'a1@x.com', 'enterprise_user_id': 21, 'status': 'active'},
            {'username': 'a2@x.com', 'enterprise_user_id': 22, 'status': 'active'},
            {'username': 'a3@x.com', 'enterprise_user_id': 23, 'status': 'active'},
        ]})

        def add_user(_params, _team_uid, _team_key, user, _role):
            return {
                'command': 'team_enterprise_user_add',
                'enterprise_user_id': user.get('enterprise_user_id'),
            }

        chunks = []

        def execute(_params, chunk):
            chunks.append(list(chunk))
            if len(chunks) == 1:
                return [
                    {'result': 'success', 'result_code': '', 'message': ''},
                    {'result': 'fail', 'result_code': 'exists', 'message': ''},
                ]
            if len(chunks) == 2:
                raise RuntimeError('timeout')
            if len(chunks) == 3:
                return [{'result': 'success'}]
            return [{'result': 'success'}]

        with mock.patch(
            'keepercommander.commands.enterprise.EnterpriseTeamCommand._create_add_user_request',
            side_effect=add_user,
        ), mock.patch(
            'keepercommander.importer.thycotic.thycotic._TEAM_BATCH_SIZE', 2,
        ), mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            side_effect=execute,
        ) as batch:
            counts = importer._add_team_members(
                params, 'uid', 'Ops', b'key',
                ['q1@x.com', 'a1@x.com', 'q2@x.com', 'q3@x.com', 'a2@x.com', 'q4@x.com', 'a3@x.com'],
                set(), True,
            )

        self.assertEqual(batch.call_count, 4)
        self.assertEqual(
            [[request['enterprise_user_id'] for request in chunk] for chunk in chunks],
            [[11, 12], [13, 14], [21, 22], [23]],
        )
        self.assertTrue(all(len(chunk) <= 2 for chunk in chunks))
        self.assertEqual(counts, TeamMemberCounts(added=2, queued=1, already=0, missing=0, failed=4))
        warnings = [call.args[0] for call in self.log.warning.call_args_list]
        self.assertEqual(warnings.count('Failed to add members to Keeper team "%s": %s'), 1)
        self.assertEqual(warnings.count('Failed to queue a member on team "%s": %s'), 1)
        self.assertEqual(warnings.count('Failed to add a member to team "%s": %s'), 1)


class TestCreateEnterpriseTeams(_QuietTestCase):
    def _importer(self, existing=None, error=''):
        importer = self.importer()
        importer._load_existing_keeper_teams = mock.Mock(return_value=(existing or {}, {}, error))
        importer._resolve_root_node_id = mock.Mock(return_value=5)
        importer._build_team_add_request = mock.Mock(
            return_value=({'command': 'team_add', 'team_uid': 'uid-1'}, b'key'))
        importer._add_team_members = mock.Mock(return_value=TeamMemberCounts(
            added=1, queued=0, already=0, missing=0, failed=0,
        ))
        return importer

    def _params(self):
        return SimpleNamespace(enterprise={'unencrypted_tree_key': b'tree'}, data_key=b'data')

    def test_creates_a_team_then_adds_members(self):
        importer = self._importer()
        with mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            return_value=[{'result': 'success'}, {'result': 'success'}],
        ) as batch:
            importer._create_enterprise_teams(self._params(), [
                {'name': 'Admins', 'members': [' a@x.com ']},
                {'name': 'admins', 'members': ['other@x.com']},
                {'name': ' Admins ', 'members': ['dup@x.com']},
                {'name': '  ', 'members': ['x@x.com']},
                None,
            ])
        batch.assert_called_once()
        created = batch.call_args[0][1]
        self.assertEqual([request['command'] for request in created], ['team_add', 'team_add'])
        self.assertEqual(
            [call.args[1] for call in importer._build_team_add_request.call_args_list],
            ['Admins', 'admins'],
        )
        self.assertEqual(
            [call.args[2] for call in importer._add_team_members.call_args_list],
            ['Admins', 'admins'],
        )
        self.assertEqual(importer._add_team_members.call_args_list[0].args[4], ['a@x.com'])
        self.assertEqual(importer._add_team_members.call_args_list[1].args[4], ['other@x.com'])

    def test_existing_team_is_not_created_and_gains_missing_members(self):
        importer = self._importer(existing={
            'Ops': {'name': 'Ops', 'team_uid': 'uid-ops', 'restrict_edit': False},
        })
        importer._load_existing_keeper_teams.return_value = (
            {'Ops': {'name': 'Ops', 'team_uid': 'uid-ops', 'restrict_edit': False}},
            {'uid-ops': {4}},
            '',
        )
        with mock.patch('keepercommander.importer.thycotic.thycotic.api.execute_batch') as batch:
            importer._create_enterprise_teams(self._params(), [{'name': ' Ops ', 'members': ['a@x.com']}])
        batch.assert_not_called()
        importer._build_team_add_request.assert_not_called()
        importer._add_team_members.assert_called_once_with(
            mock.ANY, 'uid-ops', 'Ops', None, ['a@x.com'], {4}, True)

    def test_case_distinct_group_is_created_beside_existing_team(self):
        importer = self._importer()
        importer._load_existing_keeper_teams.return_value = (
            {'Ops': {'name': 'Ops', 'team_uid': 'uid-ops', 'restrict_edit': False}},
            {'uid-ops': {4}},
            '',
        )
        with mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            return_value=[{'result': 'success'}],
        ) as batch:
            importer._create_enterprise_teams(self._params(), [
                {'name': 'ops', 'members': ['new@x.com']},
                {'name': 'Ops', 'members': ['old@x.com']},
            ])
        importer._build_team_add_request.assert_called_once_with(mock.ANY, 'ops', 5)
        self.assertEqual(len(batch.call_args[0][1]), 1)
        self.assertEqual(
            [(call.args[2], call.args[4]) for call in importer._add_team_members.call_args_list],
            [('ops', ['new@x.com']), ('Ops', ['old@x.com'])],
        )

    def test_team_creates_are_chunked_and_a_failed_chunk_does_not_stop_later_teams(self):
        importer = self._importer()
        names = ['TeamA', 'TeamB', 'TeamC', 'TeamD', 'TeamE']

        def build(_params, name, _node_id):
            return ({'command': 'team_add', 'team_uid': 'uid-' + name, 'team_name': name}, b'key')

        importer._build_team_add_request.side_effect = build
        chunks = []

        def execute(_params, chunk):
            chunks.append(list(chunk))
            if len(chunks) == 1:
                raise RuntimeError('timeout')
            if len(chunks) == 2:
                return [{'result': 'success'}]
            return [{'result': 'success'}]

        groups = [{'name': name, 'members': [name.lower() + '@x.com']} for name in names]
        with mock.patch(
            'keepercommander.importer.thycotic.thycotic._TEAM_BATCH_SIZE', 2,
        ), mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            side_effect=execute,
        ) as batch:
            importer._create_enterprise_teams(self._params(), groups)

        self.assertEqual(batch.call_count, 3)
        self.assertEqual(
            [[request['team_name'] for request in chunk] for chunk in chunks],
            [['TeamA', 'TeamB'], ['TeamC', 'TeamD'], ['TeamE']],
        )
        self.assertTrue(all(len(chunk) <= 2 for chunk in chunks))
        self.assertEqual(
            [(call.args[1], call.args[2], call.args[4]) for call in importer._add_team_members.call_args_list],
            [('uid-TeamC', 'TeamC', ['teamc@x.com']), ('uid-TeamE', 'TeamE', ['teame@x.com'])],
        )
        warnings = [call.args[0] for call in self.log.warning.call_args_list]
        self.assertEqual(warnings.count('Failed to create Keeper teams: %s'), 1)
        self.assertNotIn('Continuing import without creating Keeper teams.', warnings)
        self.assertEqual(warnings.count('\'%s\' team is not created: %s'), 3)

    def test_missing_encryption_key_stops_remaining_teams(self):
        importer = self._importer()

        def build(_params, name, _node_id):
            if name == 'Admins':
                raise MissingTeamEncryptionKey('Enterprise tree key or data key is not available')
            return ({'command': 'team_add', 'team_uid': 'uid-' + name, 'team_name': name}, b'key')

        importer._build_team_add_request.side_effect = build
        with mock.patch('keepercommander.importer.thycotic.thycotic.api.execute_batch') as batch:
            importer._create_enterprise_teams(self._params(), [
                {'name': 'Admins', 'members': ['a@x.com']},
                {'name': 'Ops', 'members': ['b@x.com']},
                {'name': 'Dev', 'members': ['c@x.com']},
            ])
        self.assertEqual(
            [call.args[1] for call in importer._build_team_add_request.call_args_list],
            ['Admins'],
        )
        batch.assert_not_called()
        importer._add_team_members.assert_not_called()
        self.assertEqual(self.log.warning.call_count, 1)
        warning_format, warning_error = self.log.warning.call_args.args
        self.assertEqual(warning_format, '%s')
        self.assertIsInstance(warning_error, MissingTeamEncryptionKey)
        self.assertEqual(str(warning_error), 'Enterprise tree key or data key is not available')

    def test_other_prepare_error_skips_only_that_team(self):
        importer = self._importer()

        def build(_params, name, _node_id):
            if name == 'Admins':
                raise ValueError('team uid could not be generated')
            return ({'command': 'team_add', 'team_uid': 'uid-' + name, 'team_name': name}, b'key')

        importer._build_team_add_request.side_effect = build
        with mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            return_value=[{'result': 'success'}],
        ) as batch:
            importer._create_enterprise_teams(self._params(), [
                {'name': 'Admins', 'members': ['a@x.com']},
                {'name': 'Ops', 'members': ['b@x.com']},
            ])
        self.assertEqual(
            [call.args[1] for call in importer._build_team_add_request.call_args_list],
            ['Admins', 'Ops'],
        )
        self.assertEqual(
            [request['team_name'] for request in batch.call_args[0][1]],
            ['Ops'],
        )
        importer._add_team_members.assert_called_once()
        self.assertEqual(importer._add_team_members.call_args.args[2], 'Ops')
        self.assertEqual(importer._add_team_members.call_args.args[4], ['b@x.com'])
        self.assertEqual(self.log.warning.call_count, 1)
        warning_format, team_name, warning_error = self.log.warning.call_args.args
        self.assertEqual(warning_format, 'Could not prepare Keeper team "%s": %s')
        self.assertEqual(team_name, 'Admins')
        self.assertIsInstance(warning_error, ValueError)
        self.assertNotIsInstance(warning_error, MissingTeamEncryptionKey)
        self.assertEqual(str(warning_error), 'team uid could not be generated')

    def test_failed_create_does_not_add_members(self):
        importer = self._importer()
        with mock.patch(
            'keepercommander.importer.thycotic.thycotic.api.execute_batch',
            return_value=[{'result': 'fail', 'message': 'exists'}],
        ):
            importer._create_enterprise_teams(self._params(), [{'name': 'Admins', 'members': ['a@x.com']}])
        importer._add_team_members.assert_not_called()
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


class TestImportParser(unittest.TestCase):
    def test_flag_defaults_off_and_parses(self):
        off = import_parser.parse_args(['--format', 'thycotic', 'https://secret.example.com'])
        self.assertFalse(off.add_teams)
        on = import_parser.parse_args([
            '--format', 'thycotic', '--add-users', '--add-teams',
            'https://secret.example.com',
        ])
        self.assertTrue(on.add_teams)


if __name__ == '__main__':
    logging.basicConfig()
    unittest.main()