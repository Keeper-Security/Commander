"""Phase 5 — email-remap / SSO / rate-limit integration coverage."""

import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.attachments import (
    AttachmentMigrator,
    FakeAttachmentClient,
)
from keepercommander.commands.keeper_tenant_migrate.shares import (
    FakeShareClient,
    ShareRestorer,
)
from keepercommander.commands.keeper_tenant_migrate.take_ownership import (
    FakeOwnershipClient,
    process_users,
)
from keepercommander.commands.keeper_tenant_migrate.users import (
    CATEGORY_UNKNOWN,
    FakeUserClient,
    UserRunner,
)


def _recording_sleeper():
    sleeps = []
    return sleeps, (lambda secs: sleeps.append(secs))


class UsersEmailRemapTests(unittest.TestCase):
    def test_invite_uses_remapped_email(self):
        client = FakeUserClient()
        runner = UserRunner(client, source_root='Src', target_root='Tgt',
                             default_node='N',
                             old_domain='acme.com', new_domain='acme.io')
        runner.run([{'email': 'alice@acme.com', 'full_name': 'A'}],
                    inventory={'entities': {'users': [
                        {'email': 'alice@acme.com', 'node': 'Src\\Dept',
                         'aliases': ['alice.alt@acme.com']}]}})
        invite_call = next(c for c in client.calls if c[0] == 'invite_user')
        self.assertEqual(invite_call[1][0], 'alice@acme.io')

    def test_aliases_are_remapped(self):
        client = FakeUserClient()
        runner = UserRunner(client, old_domain='acme.com', new_domain='acme.io')
        runner.run([{'email': 'alice@acme.com', 'full_name': 'A'}],
                    inventory={'entities': {'users': [
                        {'email': 'alice@acme.com',
                         'aliases': ['alice.alt@acme.com', 'alt@other.com']}]}})
        alias_calls = [c for c in client.calls if c[0] == 'add_user_alias']
        alias_args = [c[1] for c in alias_calls]
        # Primary alias domain remapped; non-matching alias untouched.
        self.assertIn(('alice@acme.io', 'alice.alt@acme.io'), alias_args)
        self.assertIn(('alice@acme.io', 'alt@other.com'), alias_args)


class UsersSsoPolicyTests(unittest.TestCase):
    def _runner(self, policy):
        return UserRunner(FakeUserClient(), sso_policy=policy), FakeUserClient()

    def test_invalid_policy_raises(self):
        with self.assertRaises(ValueError):
            UserRunner(FakeUserClient(), sso_policy='bogus')

    def test_skip_policy_blocks_sso_user_without_invite(self):
        client = FakeUserClient()
        runner = UserRunner(client, sso_policy='skip')
        results = runner.run(
            [{'email': 'sso@x', 'full_name': 'S'}],
            inventory={'entities': {'users': [
                {'email': 'sso@x', 'is_sso': True}]}})
        self.assertEqual(results[0].status, 'BLOCKED')
        self.assertEqual(results[0].category, CATEGORY_UNKNOWN)
        self.assertFalse(any(c[0] == 'invite_user' for c in client.calls))

    def test_warn_policy_still_invites(self):
        client = FakeUserClient()
        runner = UserRunner(client, sso_policy='warn')
        results = runner.run(
            [{'email': 'sso@x', 'full_name': 'S'}],
            inventory={'entities': {'users': [
                {'email': 'sso@x', 'sso_service_provider_id': 42}]}})
        self.assertEqual(results[0].status, 'YES')
        self.assertIn('SSO-provisioned', results[0].notes)

    def test_allow_policy_no_note_addition(self):
        client = FakeUserClient()
        runner = UserRunner(client, sso_policy='allow')
        results = runner.run(
            [{'email': 'sso@x', 'full_name': 'S'}],
            inventory={'entities': {'users': [
                {'email': 'sso@x', 'is_sso': True}]}})
        # allow proceeds with invite AND tags notes (since is_sso is true)
        self.assertEqual(results[0].status, 'YES')
        self.assertIn('SSO', results[0].notes)


class UsersRateLimitTests(unittest.TestCase):
    def test_delay_sleeps_between_users(self):
        sleeps, sleeper = _recording_sleeper()
        client = FakeUserClient()
        runner = UserRunner(client, delay=0.25, sleeper=sleeper)
        runner.run([{'email': 'a@x', 'full_name': 'A'},
                     {'email': 'b@x', 'full_name': 'B'}],
                    inventory={'entities': {'users': [
                        {'email': 'a@x'}, {'email': 'b@x'}]}})
        # one sleep per processed user
        self.assertEqual(sleeps, [0.25, 0.25])

    def test_batch_size_triggers_extra_pause(self):
        sleeps, sleeper = _recording_sleeper()
        client = FakeUserClient()
        runner = UserRunner(client, delay=0.1, batch_size=2, sleeper=sleeper)
        runner.run(
            [{'email': f'u{i}@x', 'full_name': f'U{i}'} for i in range(4)],
            inventory={'entities': {'users': [
                {'email': f'u{i}@x'} for i in range(4)]}})
        # 4 per-user sleeps + 2 batch-checkpoint sleeps (after user 2 and 4)
        self.assertEqual(len(sleeps), 6)


class SharesEmailRemapAndRateLimitTests(unittest.TestCase):
    def test_share_target_email_remapped(self):
        records = {'src1': {
            'user_permissions': [{'username': 'b@acme.com', 'editable': True}],
        }}
        captured = []

        def behavior(target_uid, email):
            captured.append(email)
            return 'OK'

        client = FakeShareClient(records=records, share_behavior=behavior)
        restorer = ShareRestorer(client, old_domain='acme.com',
                                  new_domain='acme.io')
        restorer.run([{'source_uid': 'src1', 'target_uid': 'tgt1'}])
        self.assertEqual(captured, ['b@acme.io'])

    def test_delay_and_batch_on_share_loop(self):
        records = {f'src{i}': {
            'user_permissions': [{'username': 'b@x', 'editable': False}],
        } for i in range(3)}
        sleeps, sleeper = _recording_sleeper()
        restorer = ShareRestorer(FakeShareClient(records=records),
                                  delay=0.1, batch_size=2, sleeper=sleeper)
        pairs = [{'source_uid': f'src{i}', 'target_uid': f'tgt{i}'}
                 for i in range(3)]
        restorer.run(pairs)
        # 3 per-record delays + 1 batch checkpoint (after #2)
        self.assertEqual(len(sleeps), 4)


class TakeOwnershipCrossDomainTests(unittest.TestCase):
    def test_admin_email_remapped(self):
        with tempfile.TemporaryDirectory() as d:
            backup = os.path.join(d, 'backups')
            report = os.path.join(d, 'report.csv')
            client = FakeOwnershipClient()
            users = [{'email': 'src@x', 'full_name': 'S',
                       'folder': 'MIGRATION-S', 'record_count': '0'}]
            sleeps, sleeper = _recording_sleeper()
            process_users(users, client, 'admin@acme.com',
                           backup_dir=backup, report_path=report,
                           sleep_seconds=0.0, sleeper=sleeper,
                           timestamp='t',
                           old_domain='acme.com', new_domain='acme.io')
            # ownership call took the remapped admin email
            ownership_call = next(c for c in client.calls if c[0] == 'ownership')
            self.assertEqual(ownership_call[2], 'admin@acme.io')

    def test_batch_size_adds_extra_pause(self):
        with tempfile.TemporaryDirectory() as d:
            backup = os.path.join(d, 'backups')
            report = os.path.join(d, 'report.csv')
            client = FakeOwnershipClient()
            users = [{'email': f'u{i}@x', 'full_name': f'U{i}',
                       'folder': f'MIGRATION-{i}', 'record_count': '0'}
                     for i in range(4)]
            sleeps, sleeper = _recording_sleeper()
            process_users(users, client, 'a@x',
                           backup_dir=backup, report_path=report,
                           sleep_seconds=0.1, sleeper=sleeper,
                           timestamp='t', batch_size=2)
            # 4 regular sleeps + 2 batch checkpoints
            self.assertEqual(len(sleeps), 6)


class AttachmentsRateLimitTests(unittest.TestCase):
    def test_delay_sleeps_between_records(self):
        sleeps, sleeper = _recording_sleeper()
        client = FakeAttachmentClient(downloads={'src1': [], 'src2': []})
        with tempfile.TemporaryDirectory() as stage:
            migrator = AttachmentMigrator(client, stage,
                                           delay=0.2, sleeper=sleeper)
            migrator.run([{'source_uid': 'src1', 'target_uid': 'tgt1'},
                           {'source_uid': 'src2', 'target_uid': 'tgt2'}])
        self.assertEqual(sleeps, [0.2, 0.2])

    def test_batch_pause(self):
        sleeps, sleeper = _recording_sleeper()
        client = FakeAttachmentClient(downloads={f'src{i}': []
                                                  for i in range(4)})
        with tempfile.TemporaryDirectory() as stage:
            migrator = AttachmentMigrator(client, stage, delay=0.1,
                                           batch_size=2, sleeper=sleeper)
            migrator.run([{'source_uid': f'src{i}', 'target_uid': f'tgt{i}'}
                           for i in range(4)])
        # 4 per-record delays + 2 batch checkpoints
        self.assertEqual(len(sleeps), 6)


class LiveInventorySsoCaptureTests(unittest.TestCase):
    def test_is_sso_propagated_on_user(self):
        from keepercommander.commands.keeper_tenant_migrate.live_inventory import build_user_entities
        ent = {
            'users': [
                {'username': 'sso@x', 'enterprise_user_id': 1, 'node_id': 1,
                 'sso_service_provider_id': 99, 'status': 'active'},
                {'username': 'reg@x', 'enterprise_user_id': 2, 'node_id': 1,
                 'status': 'active'},
            ],
            'teams': [], 'roles': [],
        }
        users = build_user_entities(ent, descendants=None,
                                     path_map={1: 'My company'},
                                     prefix='')
        by_email = {u['email']: u for u in users}
        self.assertTrue(by_email['sso@x']['is_sso'])
        self.assertFalse(by_email['reg@x']['is_sso'])
        self.assertEqual(by_email['sso@x']['sso_service_provider_id'], '99')

    def test_build_sso_config_captures_provider(self):
        from keepercommander.commands.keeper_tenant_migrate.live_inventory import build_sso_config
        ent = {
            'users': [{'sso_service_provider_id': 1},
                       {'is_sso': True},
                       {}],
            'sso_services': [
                {'name': 'Okta', 'sp_entity_id': 'urn:keeper:eu',
                 'sp_url': 'https://eu.../acs', 'scim_url': 'https://scim/.../',
                 'scim_bearer_token': 'redacted', 'is_active': True,
                 'node_id': 1},
            ],
        }
        cfg = build_sso_config(ent)
        self.assertEqual(len(cfg['providers']), 1)
        prov = cfg['providers'][0]
        self.assertEqual(prov['name'], 'Okta')
        self.assertEqual(prov['entity_id'], 'urn:keeper:eu')
        self.assertEqual(cfg['user_count_sso'], 2)
        # v1.2: scim/bridges are separate lists, not per-provider flags
        self.assertIn('scims', cfg)
        self.assertIn('bridges', cfg)


class ManualActionsSsoTests(unittest.TestCase):
    def test_sso_provider_emits_idp_reconfig_action(self):
        from keepercommander.commands.keeper_tenant_migrate.manual_actions import enumerate_actions
        inventory = {
            'entities': {
                'users': [
                    {'email': 'sso@x', 'is_sso': True, 'teams': [],
                     'roles': [], 'aliases': []},
                ],
                'records': [], 'shared_folders': [],
            },
            'sso_config': {
                'providers': [{'name': 'Okta',
                                 'entity_id': 'urn:keeper',
                                 'sp_url': 'https://src/acs',
                                 'scim_url': 'https://src/scim',
                                 'scim_token_present': True,
                                 'active': True}],
                'user_count_sso': 1,
            },
        }
        actions = enumerate_actions(inventory)
        sso_actions = [a for a in actions if 'SSO' in a['note']
                        or 'SCIM' in a['note']]
        self.assertGreaterEqual(len(sso_actions), 2)
        # The IdP re-configuration must be flagged as prerequisite
        self.assertTrue(
            any(a['phase'] == 'prerequisite' and 'IdP' in a['note']
                for a in sso_actions),
            'expected a prerequisite IdP reconfiguration action',
        )


class V12bSsoScimBridgeCaptureTests(unittest.TestCase):
    """v1.2: capture SCIM + bridges from top-level tables, surface them
    in manual-actions with tenant-specific re-configuration steps."""

    def test_scim_endpoints_captured_from_top_level_scims(self):
        from keepercommander.commands.keeper_tenant_migrate.live_inventory import build_sso_config
        ent = {
            'scims': [
                {'scim_id': 100, 'node_id': 1, 'status': 'active',
                 'last_synced': 1776597909000, 'role_prefix': 'SSO-',
                 'unique_groups': False},
                {'scim_id': 101, 'node_id': 2, 'status': 'pending',
                 'last_synced': 0, 'role_prefix': '',
                 'unique_groups': True},
            ],
        }
        cfg = build_sso_config(ent)
        self.assertEqual(len(cfg['scims']), 2)
        self.assertEqual(cfg['scims'][0]['scim_id'], 100)
        self.assertEqual(cfg['scims'][0]['status'], 'active')
        self.assertTrue(cfg['scims'][1]['unique_groups'])

    def test_bridges_captured_from_top_level_bridges(self):
        from keepercommander.commands.keeper_tenant_migrate.live_inventory import build_sso_config
        ent = {
            'bridges': [
                {'bridge_id': 200, 'node_id': 5, 'status': 'active',
                 'wan_ip_enforcement': '10.0.0.1',
                 'lan_ip_enforcement': '192.168.1.0/24'},
            ],
        }
        cfg = build_sso_config(ent)
        self.assertEqual(len(cfg['bridges']), 1)
        b = cfg['bridges'][0]
        self.assertEqual(b['bridge_id'], 200)
        self.assertEqual(b['wan_ip_enforcement'], '10.0.0.1')

    def test_manual_actions_emits_scim_prerequisite(self):
        from keepercommander.commands.keeper_tenant_migrate.manual_actions import enumerate_actions
        inventory = {
            'entities': {'users': [], 'records': [], 'shared_folders': []},
            'sso_config': {
                'providers': [],
                'scims': [{'scim_id': 1, 'node_id': 1,
                            'status': 'active', 'last_synced': 0}],
                'bridges': [],
                'user_count_sso': 0,
            },
        }
        actions = enumerate_actions(inventory)
        scim_actions = [a for a in actions if 'SCIM connector' in a['note']]
        self.assertEqual(len(scim_actions), 1)
        self.assertEqual(scim_actions[0]['phase'], 'prerequisite')
        # Action must mention rotating the bearer token (not carrying it)
        self.assertIn('token', scim_actions[0]['note'].lower())

    def test_manual_actions_emits_bridge_postmigration(self):
        from keepercommander.commands.keeper_tenant_migrate.manual_actions import enumerate_actions
        inventory = {
            'entities': {'users': [], 'records': [], 'shared_folders': []},
            'sso_config': {
                'providers': [],
                'scims': [],
                'bridges': [{'bridge_id': 200, 'status': 'active',
                              'wan_ip_enforcement': '10.0.0.1'}],
                'user_count_sso': 0,
            },
        }
        actions = enumerate_actions(inventory)
        bridge_actions = [a for a in actions if 'Bridge' in a['note']]
        self.assertEqual(len(bridge_actions), 1)
        self.assertEqual(bridge_actions[0]['phase'], 'post_migration')

    def test_no_sso_config_emits_no_sso_actions(self):
        from keepercommander.commands.keeper_tenant_migrate.manual_actions import enumerate_actions
        inventory = {
            'entities': {'users': [], 'records': [], 'shared_folders': []},
        }
        actions = enumerate_actions(inventory)
        # No SSO/SCIM/bridge actions when the source has no SSO config.
        sso_actions = [a for a in actions
                        if 'SSO' in a['note'] or 'SCIM' in a['note']
                        or 'Bridge' in a['note']]
        self.assertEqual(sso_actions, [])


if __name__ == '__main__':
    unittest.main()
