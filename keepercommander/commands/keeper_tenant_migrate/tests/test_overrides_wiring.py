"""Wiring tests: tenant-migrate structure --overrides path."""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from keepercommander.commands.keeper_tenant_migrate import nested_sf_plan
from keepercommander.commands.keeper_tenant_migrate.commands import StructureCommand


class StructureOverridesWiringTests(unittest.TestCase):
    """Round-trip: nested-sf-plan + overrides.yaml feed action_plan dispatch."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_inventory(self, vault_folders):
        path = os.path.join(self.tmp, 'inv.json')
        with open(path, 'w') as f:
            json.dump({
                'entities': {
                    'nodes': [], 'teams': [], 'roles': [], 'users': [],
                    'shared_folders': [],
                    'vault_folders': vault_folders,
                    'records': [],
                },
            }, f)
        return path

    def _patch_step_capture(self, captured):
        from keepercommander.commands.keeper_tenant_migrate import structure as struct_mod

        def fake(self, vfs, *, uid_map=None, promotion_plan=None,
                  action_plan=None, existing_target_names=None):
            captured['action_plan'] = action_plan
            return uid_map or {}

        return mock.patch.object(
            struct_mod.StructureRestore, 'step_vault_folders', fake)

    def _common_patches(self, audit_capture=None):
        patches = [
            mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commander_clients.'
                'CommanderStructureClient',
                return_value=mock.MagicMock()),
            mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commander_clients.sync_down'),
            mock.patch(
                'keepercommander.commands.keeper_tenant_migrate.commands._detect_target_root',
                return_value='Keeperdemo'),
        ]
        if audit_capture is None:
            patches.append(
                mock.patch(
                    'keepercommander.commands.keeper_tenant_migrate.audit.append_audit_event'))
        else:
            patches.append(
                mock.patch(
                    'keepercommander.commands.keeper_tenant_migrate.audit.append_audit_event',
                    side_effect=lambda log, ev: audit_capture.append(ev)))
        return patches

    def _stub_vfs(self):
        return [
            {'uid': 'sf-x', 'name': 'TopSF', 'type': 'shared_folder',
             'parent_uid': '', 'parent_chain': []},
            {'uid': 'sff-x', 'name': 'ChildA',
             'type': 'shared_folder_folder',
             'parent_uid': 'sf-x', 'parent_chain': ['sf-x']},
        ]

    def _write_plan(self, decisions, supports_true_nested=False,
                     tier='medium'):
        path = os.path.join(self.tmp, 'plan.json')
        with open(path, 'w') as f:
            json.dump({
                'decisions': decisions,
                'commander_supports_true_nested_sf': supports_true_nested,
                'tier': tier,
            }, f)
        return path

    def _write_overrides(self, body):
        path = os.path.join(self.tmp, 'overrides.yaml')
        with open(path, 'w') as f:
            f.write(body)
        return path

    def test_overrides_drive_action_plan(self):
        inv_path = self._write_inventory(self._stub_vfs())
        plan_path = self._write_plan([
            {'subfolder_uid': 'sff-x',
             'proposed_target_action': nested_sf_plan.ACTION_PRESERVE,
             'conflict_resolution': 'error'},
        ])
        ovr_path = self._write_overrides(
            'subfolders:\n  sff-x: promote-to-sibling\n')

        # Snapshot the on-disk plan to assert it's never mutated.
        with open(plan_path, 'rb') as f:
            plan_snapshot = f.read()

        captured = {}
        audit_events = []
        with self._patch_step_capture(captured):
            patches = self._common_patches(audit_events)
            for p in patches:
                p.start()
            try:
                cmd = StructureCommand()
                cmd._run(mock.MagicMock(),
                          {'inventory': inv_path,
                           'plan': '',
                           'steps': '11-11',
                           'nested_sf_plan': plan_path,
                           'overrides': ovr_path,
                           'accept_risk': False,
                           'scope_node': '',
                           'dry_run': False})
            finally:
                for p in patches:
                    p.stop()

        # User's choice drove dispatch.
        self.assertEqual(
            captured['action_plan']['sff-x']['proposed_target_action'],
            'promote-to-sibling')

        # Source plan file untouched on disk.
        with open(plan_path, 'rb') as f:
            self.assertEqual(f.read(), plan_snapshot)

        # Audit chain captured the override.
        ovr_summaries = [
            e for e in audit_events
            if e.get('subcommand') == 'structure'
            and 'overrides' in (e.get('summary') or {})]
        self.assertEqual(len(ovr_summaries), 1)
        ovr_payload = ovr_summaries[0]['summary']['overrides']
        self.assertEqual(ovr_payload['count'], 1)
        self.assertEqual(ovr_payload['entries'][0]['uid'], 'sff-x')
        self.assertEqual(ovr_payload['entries'][0]['after'],
                         'promote-to-sibling')

    def test_overrides_validation_error_aborts(self):
        inv_path = self._write_inventory(self._stub_vfs())
        plan_path = self._write_plan([
            {'subfolder_uid': 'sff-x',
             'proposed_target_action': nested_sf_plan.ACTION_PRESERVE},
        ])
        # Unknown UID — must fail validation, NOT raise a traceback.
        ovr_path = self._write_overrides(
            'subfolders:\n  unknown-uid: promote-to-sibling\n')

        captured = {}
        with self._patch_step_capture(captured):
            patches = self._common_patches()
            for p in patches:
                p.start()
            try:
                cmd = StructureCommand()
                with self.assertLogs(level='ERROR') as logs:
                    result = cmd._run(mock.MagicMock(),
                                       {'inventory': inv_path,
                                        'plan': '',
                                        'steps': '11-11',
                                        'nested_sf_plan': plan_path,
                                        'overrides': ovr_path,
                                        'accept_risk': False,
                                        'scope_node': '',
                                        'dry_run': False})
                self.assertIsNone(result)
                # Friendly error text was emitted (no Python traceback).
                joined = '\n'.join(logs.output)
                self.assertIn('unknown-uid', joined)
                self.assertNotIn('Traceback', joined)
            finally:
                for p in patches:
                    p.stop()
        # step_vault_folders never invoked.
        self.assertNotIn('action_plan', captured)

    def test_tier_override_without_accept_risk_aborts(self):
        inv_path = self._write_inventory(self._stub_vfs())
        plan_path = self._write_plan([], tier='medium')
        ovr_path = self._write_overrides('tier: large\n')

        captured = {}
        with self._patch_step_capture(captured):
            patches = self._common_patches()
            for p in patches:
                p.start()
            try:
                cmd = StructureCommand()
                with self.assertLogs(level='ERROR') as logs:
                    result = cmd._run(mock.MagicMock(),
                                       {'inventory': inv_path,
                                        'plan': '',
                                        'steps': '11-11',
                                        'nested_sf_plan': plan_path,
                                        'overrides': ovr_path,
                                        'accept_risk': False,
                                        'scope_node': '',
                                        'dry_run': False})
                self.assertIsNone(result)
                self.assertIn('--accept-risk',
                                '\n'.join(logs.output))
            finally:
                for p in patches:
                    p.stop()

    def test_tier_override_with_accept_risk_accepted(self):
        inv_path = self._write_inventory(self._stub_vfs())
        plan_path = self._write_plan([], tier='medium')
        ovr_path = self._write_overrides('tier: large\n')

        captured = {}
        with self._patch_step_capture(captured):
            patches = self._common_patches()
            for p in patches:
                p.start()
            try:
                cmd = StructureCommand()
                cmd._run(mock.MagicMock(),
                          {'inventory': inv_path,
                           'plan': '',
                           'steps': '11-11',
                           'nested_sf_plan': plan_path,
                           'overrides': ovr_path,
                           'accept_risk': True,
                           'scope_node': '',
                           'dry_run': False})
            finally:
                for p in patches:
                    p.stop()
        # No error → step ran. action_plan empty (no decisions in plan).
        self.assertEqual(captured.get('action_plan'), {})

    def test_overrides_without_nested_sf_plan_aborts(self):
        # --overrides only makes sense with --nested-sf-plan; omitting
        # the plan should fail loudly, not silently apply nothing.
        inv_path = self._write_inventory(self._stub_vfs())
        ovr_path = self._write_overrides(
            'subfolders:\n  abc: promote-to-sibling\n')

        captured = {}
        with self._patch_step_capture(captured):
            patches = self._common_patches()
            for p in patches:
                p.start()
            try:
                cmd = StructureCommand()
                with self.assertLogs(level='ERROR') as logs:
                    result = cmd._run(mock.MagicMock(),
                                       {'inventory': inv_path,
                                        'plan': '',
                                        'steps': '11-11',
                                        'nested_sf_plan': '',
                                        'overrides': ovr_path,
                                        'accept_risk': False,
                                        'scope_node': '',
                                        'dry_run': False})
                self.assertIsNone(result)
                self.assertIn('--nested-sf-plan not',
                                '\n'.join(logs.output))
            finally:
                for p in patches:
                    p.stop()


if __name__ == '__main__':
    unittest.main()
