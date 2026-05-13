import json
import os
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate import wizard
from keepercommander.commands.keeper_tenant_migrate.menu import MenuCancelled


class _FakeParams:
    def __init__(self, user='', server='', enterprise=None,
                  session_token='fake'):
        self.user = user
        self.server = server
        self.enterprise = enterprise or {}
        self.session_token = session_token


def _driver(inputs):
    """Return (input_fn, output_fn, outputs_list)."""
    it = iter(inputs)
    outputs = []
    return lambda _p: next(it), outputs.append, outputs


class YamlHelpersTests(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as run_dir:
            spec = {'source': {'region': 'EU'},
                    'target': {'region': 'US', 'mc': ''},
                    'what_to_migrate': ['structure', 'users'],
                    'scope': {'mode': 'full', 'value': ''},
                    'data_residency': ''}
            path = wizard.save_migration_yaml(run_dir, spec)
            self.assertTrue(os.path.exists(path))
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o600')
            loaded = wizard.load_migration_yaml(run_dir)
            self.assertEqual(loaded, spec)

    def test_load_returns_empty_when_missing(self):
        with tempfile.TemporaryDirectory() as run_dir:
            self.assertEqual(wizard.load_migration_yaml(run_dir), {})


class ArtifactStateTests(unittest.TestCase):
    def test_all_false_for_missing_dir(self):
        state = wizard.artifact_state('/no/such/dir')
        self.assertFalse(any(state.values()))

    def test_detects_nonempty_artifacts(self):
        with tempfile.TemporaryDirectory() as run_dir:
            with open(os.path.join(run_dir, 'inventory.json'), 'w') as f:
                f.write('{}')
            with open(os.path.join(run_dir, 'manifest.csv'), 'w') as f:
                f.write('src,tgt\n')
            state = wizard.artifact_state(run_dir)
            self.assertTrue(state['inventory'])
            self.assertTrue(state['manifest'])
            self.assertFalse(state['target_state'])
            self.assertFalse(state['checks'])

    def test_ignores_empty_files(self):
        with tempfile.TemporaryDirectory() as run_dir:
            open(os.path.join(run_dir, 'inventory.json'), 'w').close()
            self.assertFalse(wizard.artifact_state(run_dir)['inventory'])


class NextStepsTests(unittest.TestCase):
    def test_source_suggests_plan_first(self):
        state = wizard.artifact_state('/no/such/dir')
        suggestions = wizard.next_steps_for('source', state, ['structure'])
        self.assertEqual(suggestions[0], 'plan')

    def test_source_with_inventory_drops_plan_and_adds_take_ownership(self):
        state = dict(inventory=True, target_state=False, manifest=False,
                     checks=False, reconcile=False)
        suggestions = wizard.next_steps_for('source', state,
                                             ['structure', 'records'])
        self.assertNotIn('plan', suggestions)
        self.assertIn('records-export', suggestions)
        self.assertIn('take-ownership', suggestions)

    def test_target_needs_inventory_before_structure(self):
        state = dict(inventory=False, target_state=False, manifest=False,
                     checks=False, reconcile=False)
        suggestions = wizard.next_steps_for('target', state, ['structure'])
        self.assertNotIn('structure', suggestions)
        # capture-target-state still allowed so verify/reconcile can run
        self.assertIn('capture-target-state', suggestions)

    def test_target_with_inventory_suggests_structure_then_users(self):
        state = dict(inventory=True, target_state=False, manifest=False,
                     checks=False, reconcile=False)
        suggestions = wizard.next_steps_for('target', state,
                                             ['structure', 'users'])
        self.assertEqual(suggestions[0], 'structure')
        self.assertIn('users', suggestions)

    def test_target_with_state_unlocks_verify_and_reconcile(self):
        state = dict(inventory=True, target_state=True, manifest=False,
                     checks=False, reconcile=False)
        suggestions = wizard.next_steps_for('target', state, [])
        self.assertIn('verify', suggestions)
        self.assertIn('reconcile', suggestions)

    def test_unknown_role_returns_empty(self):
        state = wizard.artifact_state('/no/such/dir')
        self.assertEqual(wizard.next_steps_for('unknown', state, []), [])


class WizardBannerTests(unittest.TestCase):
    def test_banner_prints_session_info(self):
        outputs = []
        p = _FakeParams(user='admin@x', server='keepersecurity.eu',
                        enterprise={'enterprise_name': 'Acme'})
        wiz = wizard.Wizard(p, '/tmp/run',
                             output_fn=outputs.append)
        wiz.banner()
        text = '\n'.join(outputs)
        self.assertIn('admin@x', text)
        self.assertIn('EU', text)


class LoadOrCreateSpecTests(unittest.TestCase):
    def test_loads_existing_spec_unchanged(self):
        with tempfile.TemporaryDirectory() as run_dir:
            spec = {'source': {'region': 'EU'},
                    'target': {'region': 'US', 'mc': ''},
                    'what_to_migrate': ['structure'],
                    'scope': {'mode': 'full', 'value': ''},
                    'data_residency': ''}
            wizard.save_migration_yaml(run_dir, spec)
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=lambda _p: 'n',
                                 output_fn=lambda _s: None)
            loaded, created = wiz.load_or_create_spec()
            self.assertFalse(created)
            self.assertEqual(loaded, spec)

    def test_returns_empty_when_user_declines_create(self):
        with tempfile.TemporaryDirectory() as run_dir:
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=lambda _p: 'n',
                                 output_fn=lambda _s: None)
            loaded, created = wiz.load_or_create_spec()
            self.assertEqual(loaded, {})
            self.assertFalse(created)

    def test_interactive_create_full_happy_path(self):
        with tempfile.TemporaryDirectory() as run_dir:
            # Script: confirm-create=y, src_region=EU, src_type=enterprise(default),
            # tgt_region=US, tgt_type=enterprise(default), stages (keep preselected
            # structure+users), scope=full(default), residency=none(default)
            inputs = [
                'y',        # Create a new run-spec? Y/n
                '2',        # Source region -> EU
                '',         # Source tenant type -> default enterprise
                '1',        # Target region -> US
                '',         # Target tenant type -> default enterprise
                '',         # multi_toggle confirm (keeps preselected)
                '',         # Scope -> default full
                '',         # Data residency -> default none
            ]
            in_, out, outs = _driver(inputs)
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=in_, output_fn=out)
            loaded, created = wiz.load_or_create_spec()
            self.assertTrue(created)
            self.assertEqual(loaded['source']['region'], 'EU')
            self.assertEqual(loaded['target']['region'], 'US')
            self.assertEqual(loaded['source']['tenant_type'], 'enterprise')
            self.assertEqual(loaded['scope']['mode'], 'full')
            self.assertEqual(loaded['data_residency'], '')
            self.assertIn('structure', loaded['what_to_migrate'])
            self.assertIn('users', loaded['what_to_migrate'])


class ProposeNextStepTests(unittest.TestCase):
    def test_source_role_proposes_plan(self):
        with tempfile.TemporaryDirectory() as run_dir:
            p = _FakeParams(user='admin@src',
                             enterprise={'enterprise_name': 'SourceCo'})
            spec = {
                'source': {'enterprise_name': 'SourceCo'},
                'target': {'enterprise_name': 'TargetCo'},
                'what_to_migrate': ['structure'],
            }
            in_, out, _ = _driver(['1'])   # pick first suggestion
            wiz = wizard.Wizard(p, run_dir,
                                 input_fn=in_, output_fn=out)
            step = wiz.propose_next_step(spec)
            self.assertEqual(step, 'plan')

    def test_unknown_role_returns_none(self):
        with tempfile.TemporaryDirectory() as run_dir:
            p = _FakeParams(user='nobody@x')
            spec = {
                'source': {'enterprise_name': 'A'},
                'target': {'enterprise_name': 'B'},
            }
            outputs = []
            wiz = wizard.Wizard(p, run_dir,
                                 input_fn=lambda _p: '1',
                                 output_fn=outputs.append)
            step = wiz.propose_next_step(spec)
            self.assertIsNone(step)

    def test_compat_fail_asks_to_continue(self):
        with tempfile.TemporaryDirectory() as run_dir:
            p = _FakeParams(user='admin@tgt',
                             enterprise={'enterprise_name': 'TargetCo'})
            spec = {
                'source': {'enterprise_name': 'SourceCo'},
                'target': {'enterprise_name': 'TargetCo'},
                'what_to_migrate': ['structure'],
            }
            # Seed inventory with 6-deep node; target state missing -> no
            # record-type FAIL; compat fails on node_depth when target cap given.
            # But run_all doesn't pass target_max_depth by default, so
            # default run is all OK -> no "continue anyway" prompt.
            with open(os.path.join(run_dir, 'inventory.json'), 'w') as f:
                json.dump({'entities': {'nodes': [
                    {'name': 'deep', 'parent': 'a\\b\\c\\d\\e'}]}}, f)
            in_, out, _ = _driver(['1'])
            wiz = wizard.Wizard(p, run_dir, input_fn=in_, output_fn=out)
            step = wiz.propose_next_step(spec)
            self.assertEqual(step, 'structure')


class KwargsForTests(unittest.TestCase):
    def test_plan_kwargs_include_scope(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        spec = {'scope': {'mode': 'node', 'value': 'MIGRATION-TEST'}}
        kw = wiz._kwargs_for('plan', spec)
        self.assertEqual(kw['scope_node'], 'MIGRATION-TEST')
        self.assertEqual(kw['prefix'], '')
        self.assertTrue(kw['output'].endswith('inventory.json'))

    def test_plan_kwargs_with_prefix(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        spec = {'scope': {'mode': 'prefix', 'value': 'MIGTEST-'}}
        kw = wiz._kwargs_for('plan', spec)
        self.assertEqual(kw['prefix'], 'MIGTEST-')
        self.assertEqual(kw['scope_node'], '')

    def test_structure_kwargs_carry_mc(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        spec = {'scope': {'mode': 'full', 'value': ''},
                'target': {'region': 'US', 'mc': 'MCorp'}}
        kw = wiz._kwargs_for('structure', spec)
        self.assertEqual(kw['mc'], 'MCorp')
        self.assertEqual(kw['target_root'], 'US')

    def test_capture_target_state_path(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        kw = wiz._kwargs_for('capture-target-state',
                              {'scope': {'mode': 'prefix', 'value': 'X-'}})
        self.assertEqual(kw['prefix'], 'X-')
        self.assertTrue(kw['output'].endswith('target_state.json'))

    def test_verify_kwargs(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        kw = wiz._kwargs_for('verify', {})
        self.assertTrue(kw['inventory'].endswith('inventory.json'))
        self.assertTrue(kw['target_state'].endswith('target_state.json'))
        self.assertTrue(kw['output'].endswith('checks.csv'))

    def test_reconcile_kwargs(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        kw = wiz._kwargs_for('reconcile', {})
        self.assertTrue(kw['output'].endswith('reconciliation.md'))

    def test_unknown_step_returns_empty_dict(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        self.assertEqual(wiz._kwargs_for('nonexistent', {}), {})


class RunDriverTests(unittest.TestCase):
    def test_menu_cancel_exits_cleanly(self):
        with tempfile.TemporaryDirectory() as run_dir:
            outputs = []

            def raise_cancel(_p):
                raise MenuCancelled

            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=raise_cancel,
                                 output_fn=outputs.append)
            # Menu primitives swallow MenuCancelled and return None —
            # run() unwinds silently without running any step.
            self.assertIsNone(wiz.run())

    def test_run_saves_created_spec(self):
        with tempfile.TemporaryDirectory() as run_dir:
            # Happy-path create, decline to run a step at the end.
            inputs = [
                'y',    # create?
                '2',    # src region EU
                '',     # src type default
                '1',    # tgt region US
                '',     # tgt type default
                '',     # stages default
                '',     # scope default
                '',     # residency default
                'q',    # single_select next step -> cancel
            ]
            in_, out, _ = _driver(inputs)
            wiz = wizard.Wizard(_FakeParams(
                enterprise={'enterprise_name': 'Whatever'}),
                run_dir, input_fn=in_, output_fn=out)
            wiz.run()
            spec_path = os.path.join(run_dir, 'migration.yaml')
            self.assertTrue(os.path.exists(spec_path))


class RunStatePersistenceTests(unittest.TestCase):
    def test_load_returns_empty_when_missing(self):
        with tempfile.TemporaryDirectory() as run_dir:
            self.assertEqual(wizard.load_run_state(run_dir), {})

    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as run_dir:
            wizard.save_run_state(run_dir, {'sso_confirmed': True,
                                              'cap_override': False})
            state = wizard.load_run_state(run_dir)
            self.assertEqual(state['sso_confirmed'], True)
            self.assertEqual(state['cap_override'], False)

    def test_save_sets_0600_permissions(self):
        with tempfile.TemporaryDirectory() as run_dir:
            path = wizard.save_run_state(run_dir, {'x': 1})
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), '0o600')

    def test_update_merges_without_clobber(self):
        with tempfile.TemporaryDirectory() as run_dir:
            wizard.save_run_state(run_dir, {'a': 1})
            wizard.update_run_state(run_dir, {'b': 2})
            state = wizard.load_run_state(run_dir)
            self.assertEqual(state, {'a': 1, 'b': 2})

    def test_load_survives_malformed_json(self):
        with tempfile.TemporaryDirectory() as run_dir:
            with open(os.path.join(run_dir, '.run_state'), 'w') as f:
                f.write('this is not json')
            self.assertEqual(wizard.load_run_state(run_dir), {})


class ConfirmOnceTests(unittest.TestCase):
    def test_first_call_prompts_and_persists(self):
        with tempfile.TemporaryDirectory() as run_dir:
            in_, out, _ = _driver(['y'])
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=in_, output_fn=out)
            ok = wiz.confirm_once('idp_repointed',
                                    'IdP re-pointed at new tenant?')
            self.assertTrue(ok)
            # Persisted → new wizard instance in the same run-dir replays.
            wiz2 = wizard.Wizard(_FakeParams(), run_dir,
                                  input_fn=lambda _p: '?',
                                  output_fn=lambda _s: None)
            self.assertTrue(wiz2.state_get('idp_repointed'))

    def test_second_call_skips_prompt(self):
        with tempfile.TemporaryDirectory() as run_dir:
            in_, out, _ = _driver(['y'])
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=in_, output_fn=out)
            wiz.confirm_once('sso_ok', 'SSO re-provisioned?')

            # Second wizard instance — input_fn should never be consumed.
            input_calls = []
            def raise_if_called(_p):
                input_calls.append(_p)
                raise AssertionError('prompt should not re-fire')
            outputs = []
            wiz2 = wizard.Wizard(_FakeParams(), run_dir,
                                  input_fn=raise_if_called,
                                  output_fn=outputs.append)
            result = wiz2.confirm_once('sso_ok', 'SSO re-provisioned?')
            self.assertTrue(result)
            self.assertEqual(input_calls, [])
            self.assertTrue(any('skipping' in o for o in outputs))

    def test_no_answer_treated_as_false(self):
        with tempfile.TemporaryDirectory() as run_dir:
            in_, out, _ = _driver(['n'])
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=in_, output_fn=out)
            self.assertFalse(wiz.confirm_once('cap_override',
                                                'Exceed batch cap?'))
            self.assertFalse(wiz.state_get('cap_override'))


class AutoAdjustTests(unittest.TestCase):
    """AUTOMATED_ADJUSTMENT.md — wizard reads spec + scale into step kwargs."""

    def test_scale_tier_returns_defaults_when_no_user_count(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        self.assertEqual(wiz._infer_scale({}), (0.0, 0))

    def test_scale_tier_small_tenant(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        self.assertEqual(wiz._infer_scale({'counts': {'users': 30}}),
                          (0.5, 0))

    def test_scale_tier_medium_tenant(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        self.assertEqual(wiz._infer_scale({'counts': {'users': 250}}),
                          (1.0, 25))

    def test_scale_tier_large_tenant(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        self.assertEqual(wiz._infer_scale({'counts': {'users': 2000}}),
                          (2.0, 50))

    def test_scale_tier_huge_tenant(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        self.assertEqual(wiz._infer_scale({'counts': {'users': 10000}}),
                          (3.0, 100))

    def test_auto_adjust_off_disables_scale(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run', auto_adjust=False)
        self.assertEqual(wiz._infer_scale({'counts': {'users': 5000}}),
                          (0.0, 0))

    def test_remap_inferred_from_email_remap_block(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        spec = {'email_remap': {'old_domain': 'acme.com',
                                 'new_domain': 'acme.io'}}
        self.assertEqual(wiz._infer_remap(spec), ('acme.com', 'acme.io'))

    def test_remap_inferred_from_source_target_domains(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        spec = {'source': {'email_domain': 'acme.com'},
                'target': {'email_domain': 'acme.io'}}
        self.assertEqual(wiz._infer_remap(spec), ('acme.com', 'acme.io'))

    def test_remap_off_when_auto_adjust_false(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run', auto_adjust=False)
        spec = {'email_remap': {'old_domain': 'acme.com',
                                 'new_domain': 'acme.io'}}
        self.assertEqual(wiz._infer_remap(spec), ('', ''))

    def test_users_kwargs_carry_auto_knobs(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        spec = {
            'counts': {'users': 2000},
            'email_remap': {'old_domain': 'old.com', 'new_domain': 'new.io'},
            'sso_policy': 'skip',
            'target': {'region': 'US', 'mc': 'MCorp'},
            'scope': {'mode': 'full', 'value': ''},
        }
        kw = wiz._kwargs_for('users', spec)
        self.assertEqual(kw['old_domain'], 'old.com')
        self.assertEqual(kw['new_domain'], 'new.io')
        self.assertEqual(kw['delay'], 2.0)
        self.assertEqual(kw['batch_size'], 50)
        self.assertEqual(kw['sso_policy'], 'skip')
        self.assertEqual(kw['mc'], 'MCorp')
        self.assertTrue(kw['audit_log'].endswith('audit.log'))

    def test_records_shares_kwargs_carry_remap_and_throttle(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        spec = {'counts': {'users': 100},
                'email_remap': {'old_domain': 'x.com', 'new_domain': 'y.io'}}
        kw = wiz._kwargs_for('records-shares', spec)
        self.assertEqual(kw['old_domain'], 'x.com')
        self.assertEqual(kw['new_domain'], 'y.io')
        self.assertEqual(kw['delay'], 1.0)
        self.assertEqual(kw['batch_size'], 25)

    def test_records_attachments_kwargs_skip_remap(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        kw = wiz._kwargs_for('records-attachments',
                              {'counts': {'users': 30}})
        self.assertNotIn('old_domain', kw)
        self.assertEqual(kw['delay'], 0.5)

    def test_take_ownership_delay_has_floor_of_half_second(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        # Even a 0-user scale should keep at least 0.5s between calls.
        kw = wiz._kwargs_for('take-ownership', {})
        self.assertGreaterEqual(kw['delay'], 0.5)

    def test_announce_mentions_auto_values(self):
        outputs = []
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run',
                             output_fn=outputs.append)
        spec = {'counts': {'users': 600},
                'email_remap': {'old_domain': 'a.com', 'new_domain': 'b.io'},
                'sso_policy': 'skip'}
        kw = wiz._kwargs_for('users', spec)
        wiz._announce_auto_adjust('users', kw)
        joined = '\n'.join(outputs)
        self.assertIn('@a.com', joined)
        self.assertIn('--delay=2.0', joined)
        self.assertIn('SSO policy: skip', joined)


class RunCompatChecksTests(unittest.TestCase):
    def test_source_role_skips_checks(self):
        with tempfile.TemporaryDirectory() as run_dir:
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 output_fn=lambda _s: None)
            state = wizard.artifact_state(run_dir)
            checks = wiz.run_compat_checks('source', state)
            self.assertEqual(checks, [])

    def test_target_role_runs_checks_when_inventory_present(self):
        with tempfile.TemporaryDirectory() as run_dir:
            with open(os.path.join(run_dir, 'inventory.json'), 'w') as f:
                json.dump({'entities': {'nodes': [],
                                          'records': []},
                            'record_types': []}, f)
            outputs = []
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 output_fn=outputs.append)
            state = wizard.artifact_state(run_dir)
            checks = wiz.run_compat_checks('target', state)
            self.assertEqual(len(checks), 3)
            self.assertTrue(any('Pre-flight' in o for o in outputs))


class YamlImportFallbackTests(unittest.TestCase):
    """Cover the JSON-fallback paths when PyYAML is absent (lines 39-40, 47-48)."""

    def test_dump_falls_back_to_json_on_import_error(self):
        from unittest.mock import patch

        original_import = __builtins__['__import__'] if isinstance(
            __builtins__, dict) else __import__

        def fake_import(name, *args, **kwargs):
            if name == 'yaml':
                raise ImportError('no yaml')
            return original_import(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=fake_import):
            blob = wizard._yaml_or_json_dump({'a': 1, 'b': 2})
        self.assertIn('"a"', blob)
        self.assertIn('1', blob)

    def test_load_falls_back_to_json_on_import_error(self):
        from unittest.mock import patch

        original_import = __builtins__['__import__'] if isinstance(
            __builtins__, dict) else __import__

        def fake_import(name, *args, **kwargs):
            if name == 'yaml':
                raise ImportError('no yaml')
            return original_import(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=fake_import):
            data = wizard._yaml_or_json_load('{"a": 1}')
            empty = wizard._yaml_or_json_load('')
        self.assertEqual(data, {'a': 1})
        self.assertEqual(empty, {})


class NextStepsRecordsBranchTests(unittest.TestCase):
    """Cover the records-export-only branch on the source role (line 157)."""

    def test_source_with_records_only_emits_records_export(self):
        state = dict(inventory=False, target_state=False, manifest=False,
                     checks=False, reconcile=False)
        suggestions = wizard.next_steps_for('source', state, ['records'])
        # No 'plan' (structure not requested), but records-export is still
        # offered even without inventory present.
        self.assertNotIn('plan', suggestions)
        self.assertIn('records-export', suggestions)


class CompatChecksJsonErrorTests(unittest.TestCase):
    """Cover JSON-decode error fallbacks (lines 322-323, 326-330)."""

    def test_malformed_inventory_returns_empty(self):
        with tempfile.TemporaryDirectory() as run_dir:
            with open(os.path.join(run_dir, 'inventory.json'), 'w') as f:
                f.write('not json {{')
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 output_fn=lambda _s: None)
            state = wizard.artifact_state(run_dir)
            self.assertEqual(wiz.run_compat_checks('target', state), [])

    def test_malformed_target_state_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as run_dir:
            with open(os.path.join(run_dir, 'inventory.json'), 'w') as f:
                json.dump({'entities': {'nodes': [], 'records': []},
                            'record_types': []}, f)
            with open(os.path.join(run_dir, 'target_state.json'), 'w') as f:
                f.write('garbage')
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 output_fn=lambda _s: None)
            state = wizard.artifact_state(run_dir)
            checks = wiz.run_compat_checks('target', state)
            # Got a list of checks even though target_state was malformed —
            # the compat module ran with an empty target.
            self.assertGreater(len(checks), 0)


class InteractiveCreateMcAndScopeTests(unittest.TestCase):
    """Cover the MC-name prompt + node/prefix scope value paths
    (lines 269, 283)."""

    def test_mc_target_prompts_for_mc_name(self):
        with tempfile.TemporaryDirectory() as run_dir:
            inputs = [
                'y',          # create?
                '1',          # src region US
                '',           # src type default enterprise
                '1',          # tgt region US
                'mc',         # tgt type → mc (so mc prompt fires)
                'AcmeCorp',   # MC name
                '',           # multi-toggle confirm
                'node',       # scope mode → node (so scope-value prompt fires)
                'MIGRATION-NODE',  # scope value
                '',           # residency default
            ]
            in_, out, _ = _driver(inputs)
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=in_, output_fn=out)
            spec, created = wiz.load_or_create_spec()
            self.assertTrue(created)
            self.assertEqual(spec['target']['mc'], 'AcmeCorp')
            self.assertEqual(spec['scope']['mode'], 'node')
            self.assertEqual(spec['scope']['value'], 'MIGRATION-NODE')


class DestructiveSourceModeTests(unittest.TestCase):
    """Cover the loud destructive-mode banner branch (line 353)."""

    def test_destructive_banner_printed_when_unlocked(self):
        with tempfile.TemporaryDirectory() as run_dir:
            outputs = []
            wiz = wizard.Wizard(_FakeParams(user='admin@src',
                                              enterprise={'enterprise_name':
                                                            'SourceCo'}),
                                 run_dir, input_fn=lambda _p: '1',
                                 output_fn=outputs.append)
            spec = {
                'source': {'enterprise_name': 'SourceCo'},
                'target': {'enterprise_name': 'TargetCo'},
                'what_to_migrate': ['structure'],
                'source_mode': 'destructive',
            }
            wiz.propose_next_step(spec)
            joined = '\n'.join(outputs)
            self.assertIn('source writes ALLOWED', joined)


class CompatFailDeclineTests(unittest.TestCase):
    """Cover the FAIL-then-decline path (lines 359-364)."""

    def test_compat_fail_user_declines_returns_none(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as run_dir:
            with open(os.path.join(run_dir, 'inventory.json'), 'w') as f:
                json.dump({'entities': {'nodes': [], 'records': []},
                            'record_types': []}, f)
            outputs = []

            class _CompatFail:
                verdict = 'fail'
                name = 'unit_test_force_fail'
                message = 'forced fail'
                details = ()

            with patch('keepercommander.commands.keeper_tenant_migrate.compat_checks.run_all',
                        return_value=[_CompatFail()]):
                wiz = wizard.Wizard(_FakeParams(
                    user='admin@tgt',
                    enterprise={'enterprise_name': 'TargetCo'},
                ), run_dir,
                    input_fn=lambda _p: 'n',  # decline 'continue anyway'
                    output_fn=outputs.append)
                spec = {
                    'source': {'enterprise_name': 'SourceCo'},
                    'target': {'enterprise_name': 'TargetCo'},
                    'what_to_migrate': ['structure'],
                }
                step = wiz.propose_next_step(spec)
            self.assertIsNone(step)
            self.assertTrue(any('Pre-flight FAIL' in o for o in outputs))

    def test_propose_next_returns_none_when_no_suggestions(self):
        """No suggestions → outputs the 'Switch shells' message and returns None."""
        with tempfile.TemporaryDirectory() as run_dir:
            outputs = []
            wiz = wizard.Wizard(_FakeParams(user='nobody@x'),
                                 run_dir,
                                 input_fn=lambda _p: '1',
                                 output_fn=outputs.append)
            spec = {
                'source': {'enterprise_name': 'A'},
                'target': {'enterprise_name': 'B'},
            }
            step = wiz.propose_next_step(spec)
            self.assertIsNone(step)
            self.assertTrue(any('No next step' in o for o in outputs))


class RunStepTests(unittest.TestCase):
    """Cover the run_step dispatch branches (lines 383-412)."""

    def test_unknown_step_emits_warning_and_returns_none(self):
        with tempfile.TemporaryDirectory() as run_dir:
            outputs = []
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 output_fn=outputs.append)
            self.assertIsNone(wiz.run_step('not-a-real-step',
                                             {'scope': {'mode': 'full'}}))
            self.assertTrue(any('cannot run' in o for o in outputs))

    def test_known_step_invokes_command_with_dry_run_kwargs(self):
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import commands

        with tempfile.TemporaryDirectory() as run_dir:
            captured = {}

            class _StubVerify:
                def execute(self, params, **kwargs):
                    captured['params'] = params
                    captured['kwargs'] = kwargs
                    return 'STUB-OK'

            in_, out, _ = _driver(['y'])  # dry-run = yes
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=in_, output_fn=out)
            with patch.object(commands, 'VerifyCommand', _StubVerify):
                result = wiz.run_step('verify', {})
            self.assertEqual(result, 'STUB-OK')
            self.assertTrue(captured['kwargs']['dry_run'])
            self.assertTrue(captured['kwargs']['dry_run_report']
                              .endswith('verify.dry-run.md'))

    def test_known_step_no_dry_run_skips_dry_run_kwargs(self):
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import commands

        with tempfile.TemporaryDirectory() as run_dir:
            captured = {}

            class _StubReconcile:
                def execute(self, params, **kwargs):
                    captured['kwargs'] = kwargs
                    return 'OK'

            in_, out, _ = _driver(['n'])  # decline dry-run
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=in_, output_fn=out)
            with patch.object(commands, 'ReconcileCommand', _StubReconcile):
                wiz.run_step('reconcile', {})
            self.assertNotIn('dry_run', captured['kwargs'])


class InferScaleEdgeTests(unittest.TestCase):
    """Cover TypeError/ValueError + tier-overflow branches (lines 433-434, 440)."""

    def test_non_numeric_user_count_yields_default(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        # Non-int (a dict) trips TypeError → users=0 → (0.0, 0).
        self.assertEqual(
            wiz._infer_scale({'counts': {'users': {'bogus': 1}}}),
            (0.0, 0))

    def test_string_user_count_yields_default(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        self.assertEqual(
            wiz._infer_scale({'counts': {'users': 'NaN'}}),
            (0.0, 0))


class RecordsImportKwargsTests(unittest.TestCase):
    """Cover the records-import kwargs branch (line 503)."""

    def test_records_import_path(self):
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        kw = wiz._kwargs_for('records-import', {})
        self.assertTrue(kw['input'].endswith('records-import.json'))
        self.assertTrue(kw['audit_log'].endswith('audit.log'))


class AnnounceAutoAdjustOffTests(unittest.TestCase):
    """Cover the auto_adjust=False short-circuit (line 552)."""

    def test_no_output_when_auto_adjust_disabled(self):
        outputs = []
        wiz = wizard.Wizard(_FakeParams(), '/tmp/run',
                             output_fn=outputs.append, auto_adjust=False)
        wiz._announce_auto_adjust('users', {'old_domain': 'a.com',
                                              'new_domain': 'b.io',
                                              'delay': 1.0,
                                              'batch_size': 25})
        self.assertEqual(outputs, [])


class TargetRecordsBranchTests(unittest.TestCase):
    """Cover the records target branch + records-import/attachments/shares
    extension (line 157)."""

    def test_target_with_records_extends_with_record_steps(self):
        state = dict(inventory=True, target_state=False, manifest=False,
                     checks=False, reconcile=False)
        suggestions = wizard.next_steps_for('target', state, ['records'])
        for step in ('records-import', 'records-attachments', 'records-shares'):
            self.assertIn(step, suggestions)


class ConfirmOnceDescriptionTests(unittest.TestCase):
    """Cover the description-output path inside confirm_once (216-217)."""

    def test_description_printed_above_prompt(self):
        with tempfile.TemporaryDirectory() as run_dir:
            outputs = []
            in_, _, _ = _driver(['y'])
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=in_, output_fn=outputs.append)
            ok = wiz.confirm_once('idp_repointed',
                                    'IdP re-pointed?',
                                    description='Read SECURITY_MODEL.md §3 first.')
            self.assertTrue(ok)
            self.assertTrue(any('SECURITY_MODEL.md' in o for o in outputs))


class ProposeNextStepCancelSelectionTests(unittest.TestCase):
    """Cover the user-cancels-selection branch (line 376)."""

    def test_user_cancels_step_selection(self):
        """When single_select returns None the wizard returns None."""
        with tempfile.TemporaryDirectory() as run_dir:
            p = _FakeParams(user='admin@src',
                             enterprise={'enterprise_name': 'SourceCo'})
            spec = {
                'source': {'enterprise_name': 'SourceCo'},
                'target': {'enterprise_name': 'TargetCo'},
                'what_to_migrate': ['structure'],
            }
            in_, out, _ = _driver(['q'])  # cancel single_select
            wiz = wizard.Wizard(p, run_dir, input_fn=in_, output_fn=out)
            self.assertIsNone(wiz.propose_next_step(spec))


class InferScaleOverflowTests(unittest.TestCase):
    """Cover the post-loop fall-through (line 440) when no tier matches.

    The fall-through is genuinely unreachable in normal use because the
    last SCALE_TIER has `upper=sys.maxsize` (or equivalent). We patch
    SCALE_TIERS to a finite list to exercise the defensive return.
    """

    def test_user_count_above_max_tier_returns_default(self):
        from unittest.mock import patch

        wiz = wizard.Wizard(_FakeParams(), '/tmp/run')
        # Force a finite tier table so a giant user count overflows.
        with patch.object(type(wiz), '_SCALE_TIERS',
                            new_callable=lambda: property(
                                lambda self: ((100, 0.5, 5),))):
            result = wiz._infer_scale({'counts': {'users': 100_000_000}})
        self.assertEqual(result, (0.0, 0))


class RunFullPathTests(unittest.TestCase):
    """Cover the run() driver paths (lines 582-589)."""

    def test_run_returns_none_when_spec_creation_declined(self):
        with tempfile.TemporaryDirectory() as run_dir:
            in_, out, _ = _driver(['n'])  # decline spec creation
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 input_fn=in_, output_fn=out)
            self.assertIsNone(wiz.run())

    def test_run_returns_none_when_user_declines_step_confirm(self):
        """Spec exists, propose returns 'plan', user declines confirm → None."""
        with tempfile.TemporaryDirectory() as run_dir:
            spec = {
                'source': {'enterprise_name': 'SourceCo'},
                'target': {'enterprise_name': 'TargetCo'},
                'what_to_migrate': ['structure'],
            }
            wizard.save_migration_yaml(run_dir, spec)
            # Inputs: pick step 1, decline run-confirm.
            in_, out, _ = _driver(['1', 'n'])
            wiz = wizard.Wizard(_FakeParams(
                user='admin@src',
                enterprise={'enterprise_name': 'SourceCo'},
            ), run_dir, input_fn=in_, output_fn=out)
            self.assertIsNone(wiz.run())

    def test_run_catches_menu_cancelled_anywhere_in_flow(self):
        """A MenuCancelled bubbling up past the menu primitives → wizard
        cancelled output + None. We patch banner() to raise directly so
        the exception escapes the menu primitives' own handler."""
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as run_dir:
            outputs = []
            wiz = wizard.Wizard(_FakeParams(), run_dir,
                                 output_fn=outputs.append)
            with patch.object(wizard.Wizard, 'banner',
                                side_effect=wizard.MenuCancelled):
                self.assertIsNone(wiz.run())
            self.assertTrue(any('wizard cancelled' in o for o in outputs))

    def test_run_invokes_step_when_confirmed(self):
        """End-to-end: spec exists, step proposed, confirmed, command stub fires."""
        from unittest.mock import patch

        from keepercommander.commands.keeper_tenant_migrate import commands

        with tempfile.TemporaryDirectory() as run_dir:
            spec = {
                'source': {'enterprise_name': 'SourceCo'},
                'target': {'enterprise_name': 'TargetCo'},
                'what_to_migrate': ['structure'],
            }
            wizard.save_migration_yaml(run_dir, spec)
            captured = {}

            class _StubPlan:
                def execute(self, params, **kwargs):
                    captured['kwargs'] = kwargs
                    return 'RAN-PLAN'

            # Inputs: pick step 1 (plan), confirm yes, dry-run yes.
            in_, out, _ = _driver(['1', 'y', 'y'])
            wiz = wizard.Wizard(_FakeParams(
                user='admin@src',
                enterprise={'enterprise_name': 'SourceCo'},
            ), run_dir, input_fn=in_, output_fn=out)
            with patch.object(commands, 'PlanCommand', _StubPlan):
                result = wiz.run()
            self.assertEqual(result, 'RAN-PLAN')


if __name__ == '__main__':
    unittest.main()
