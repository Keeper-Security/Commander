"""Unit tests for just-in-time (JIT) support in `pam launch`.

All the shape-handling lives in ``keepercommander.commands.pam_launch.jit``;
these tests pin its public surface. The live end-to-end path is exercised by
``scripts/_acme_lab_pr_validation.py`` in the test-env repo.
"""

import sys
import unittest
from types import SimpleNamespace

# launch.py / terminal_connection.py pull in large transitive dep trees
# (WebRTC / router / Guacamole) that require Python >= 3.8. Matches the
# version-gated import pattern in test_pam_tunnel.py.
if sys.version_info >= (3, 8):
    from keepercommander.commands.pam_launch import jit
    from keepercommander.commands.pam_launch.jit import (
        JIT_MODE_BOTH,
        JIT_MODE_ELEVATION,
        JIT_MODE_EPHEMERAL,
        build_elevation_payload,
        build_ephemeral_payload,
        derive_jit_mode,
        load_jit_settings,
        normalize_jit_settings,
        provisions_credential,
    )

    def _record_with_pam_settings(pam_settings_value):
        """Build a record-like object exposing get_typed_field('pamSettings')."""
        field = SimpleNamespace(get_default_value=lambda _t=dict: pam_settings_value)
        return SimpleNamespace(
            get_typed_field=lambda name: field if name == 'pamSettings' else None,
            record_uid='r1',
        )


    class TestModeConstants(unittest.TestCase):
        def test_constants_are_distinct_non_empty_strings(self):
            values = [JIT_MODE_EPHEMERAL, JIT_MODE_ELEVATION, JIT_MODE_BOTH]
            self.assertEqual(len(set(values)), 3)
            for v in values:
                self.assertIsInstance(v, str)
                self.assertTrue(v)


    class TestNormalizeJitSettings(unittest.TestCase):
        def test_returns_none_for_non_dict(self):
            self.assertIsNone(normalize_jit_settings(None))
            self.assertIsNone(normalize_jit_settings('not-a-dict'))
            self.assertIsNone(normalize_jit_settings([]))

        def test_empty_dict_returns_none(self):
            self.assertIsNone(normalize_jit_settings({}))

        def test_camelcase_from_web_vault_dag(self):
            """Exact keys written by DagJitSettingsObject.to_dag_dict."""
            out = normalize_jit_settings({
                'createEphemeral': True,
                'elevate': True,
                'elevationMethod': 'group',
                'elevationString': 'wheel,sudo',
                'baseDistinguishedName': 'OU=JIT,DC=acme,DC=corp',
                'ephemeralAccountType': 'linux',
            })
            self.assertEqual(out, {
                'create_ephemeral': True,
                'elevate': True,
                'elevation_method': 'group',
                'elevation_string': 'wheel,sudo',
                'base_distinguished_name': 'OU=JIT,DC=acme,DC=corp',
                'ephemeral_account_type': 'linux',
            })

        def test_snake_case_passthrough(self):
            raw = {'create_ephemeral': True, 'ephemeral_account_type': 'linux'}
            self.assertEqual(normalize_jit_settings(raw), raw)

        def test_snake_case_wins_on_collision(self):
            """Pathological case: caller supplies both castings. Snake wins."""
            self.assertEqual(
                normalize_jit_settings({'createEphemeral': False, 'create_ephemeral': True}),
                {'create_ephemeral': True},
            )

        def test_unknown_keys_preserved(self):
            """New DAG fields must not be dropped by the normaliser."""
            out = normalize_jit_settings({'createEphemeral': True, 'futureField': 'x'})
            self.assertEqual(out, {'create_ephemeral': True, 'futureField': 'x'})


    class TestDeriveJitMode(unittest.TestCase):
        def test_none_for_non_dict(self):
            self.assertIsNone(derive_jit_mode(None))
            self.assertIsNone(derive_jit_mode('nope'))

        def test_none_when_no_flags(self):
            self.assertIsNone(derive_jit_mode({}))
            self.assertIsNone(derive_jit_mode({'elevation_method': 'group'}))
            self.assertIsNone(derive_jit_mode({'create_ephemeral': False, 'elevate': False}))

        def test_ephemeral_only(self):
            self.assertEqual(derive_jit_mode({'create_ephemeral': True}), JIT_MODE_EPHEMERAL)

        def test_elevation_only(self):
            self.assertEqual(derive_jit_mode({'elevate': True}), JIT_MODE_ELEVATION)

        def test_both(self):
            self.assertEqual(
                derive_jit_mode({'create_ephemeral': True, 'elevate': True}),
                JIT_MODE_BOTH,
            )

        def test_works_after_camelcase_normalisation(self):
            mode = derive_jit_mode(normalize_jit_settings({
                'createEphemeral': True, 'ephemeralAccountType': 'linux',
            }))
            self.assertEqual(mode, JIT_MODE_EPHEMERAL)


    class TestBuildEphemeralPayload(unittest.TestCase):
        def test_returns_empty_for_non_dict(self):
            self.assertEqual(build_ephemeral_payload(None), {})
            self.assertEqual(build_ephemeral_payload(42), {})

        def test_keeps_only_ephemeral_keys(self):
            payload = build_ephemeral_payload({
                'create_ephemeral': True,
                'ephemeral_account_type': 'linux',
                'base_distinguished_name': 'OU=JIT,DC=acme,DC=corp',
                'pam_directory_uid_ref': 'ref-uid',
                # Elevation keys must not leak into the ephemeral payload
                'elevate': True,
                'elevation_method': 'group',
                'elevation_string': 'wheel',
            })
            self.assertEqual(set(payload), {
                'create_ephemeral', 'ephemeral_account_type',
                'base_distinguished_name', 'pam_directory_uid_ref',
            })
            self.assertEqual(payload['ephemeral_account_type'], 'linux')

        def test_drops_empty_and_none_values(self):
            payload = build_ephemeral_payload({
                'create_ephemeral': True,
                'ephemeral_account_type': 'linux',
                'base_distinguished_name': '',
                'pam_directory_uid_ref': None,
            })
            self.assertEqual(set(payload), {'create_ephemeral', 'ephemeral_account_type'})


    class TestBuildElevationPayload(unittest.TestCase):
        def test_returns_empty_for_non_dict(self):
            self.assertEqual(build_elevation_payload(None), {})

        def test_keeps_only_elevation_keys(self):
            payload = build_elevation_payload({
                'elevate': True,
                'elevation_method': 'group',
                'elevation_string': 'wheel,sudo',
                # Ephemeral keys must not leak
                'create_ephemeral': True,
                'ephemeral_account_type': 'linux',
            })
            self.assertEqual(set(payload), {'elevate', 'elevation_method', 'elevation_string'})

        def test_drops_empty_strings(self):
            payload = build_elevation_payload({
                'elevate': True, 'elevation_method': 'role', 'elevation_string': '',
            })
            self.assertEqual(set(payload), {'elevate', 'elevation_method'})


    class TestPayloadDisjointness(unittest.TestCase):
        """For JIT_MODE_BOTH the gateway receives both payloads on the same
        inputs dict; they must not collide on any key."""

        def test_no_overlap(self):
            combined = {
                'create_ephemeral': True,
                'ephemeral_account_type': 'linux',
                'base_distinguished_name': 'OU=JIT,DC=acme,DC=corp',
                'pam_directory_uid_ref': 'ref',
                'elevate': True,
                'elevation_method': 'group',
                'elevation_string': 'wheel,sudo',
            }
            eph = build_ephemeral_payload(combined)
            elev = build_elevation_payload(combined)
            self.assertFalse(set(eph) & set(elev))


    class TestLoadJitSettings(unittest.TestCase):
        """DAG wins over typed-field; typed-field fallback when DAG empty."""

        def setUp(self):
            self._orig = jit._dag_jit_settings

        def tearDown(self):
            jit._dag_jit_settings = self._orig

        def _stub_dag(self, result):
            jit._dag_jit_settings = lambda p, uid: result

        def test_none_when_nothing(self):
            self._stub_dag(None)
            self.assertIsNone(load_jit_settings(params=SimpleNamespace(), record_uid='r1'))

        def test_none_when_no_inputs(self):
            """No record and no uid => can't look anything up."""
            self.assertIsNone(load_jit_settings(params=SimpleNamespace()))

        def test_typed_field_happy_path(self):
            self._stub_dag(None)
            expected = {'create_ephemeral': True, 'ephemeral_account_type': 'linux'}
            record = _record_with_pam_settings({'options': {'jit_settings': expected}})
            self.assertEqual(load_jit_settings(params=SimpleNamespace(), record=record), expected)

        def test_dag_wins_when_both_present(self):
            dag_result = {'create_ephemeral': True, 'ephemeral_account_type': 'domain'}
            self._stub_dag(dag_result)
            record = _record_with_pam_settings({'options': {'jit_settings': {
                'create_ephemeral': True, 'ephemeral_account_type': 'linux',
            }}})
            self.assertEqual(load_jit_settings(params=SimpleNamespace(), record=record), dag_result)

        def test_non_dict_typed_field_ignored(self):
            self._stub_dag(None)
            record = _record_with_pam_settings({'options': {'jit_settings': 'bogus'}})
            self.assertIsNone(load_jit_settings(params=SimpleNamespace(), record=record))

        def test_record_uid_derived_from_record(self):
            """record.record_uid is used when record_uid kwarg omitted."""
            seen = {}
            jit._dag_jit_settings = lambda p, uid: seen.setdefault('uid', uid) or None
            record = _record_with_pam_settings({'options': {}})
            load_jit_settings(params=SimpleNamespace(), record=record)
            self.assertEqual(seen['uid'], 'r1')


    class TestProvisionsCredential(unittest.TestCase):
        """--jit ephemeral/both let the gateway provision the credential and
        therefore bypass the pre-flight credential check in pam_launch.launch.
        Everything else (jit_flag=False, elevation-only, jit_mode=None) must
        still take the regular path."""

        def test_ephemeral_with_flag(self):
            self.assertTrue(provisions_credential(True, JIT_MODE_EPHEMERAL))

        def test_both_with_flag(self):
            self.assertTrue(provisions_credential(True, JIT_MODE_BOTH))

        def test_elevation_with_flag_still_needs_cred(self):
            self.assertFalse(provisions_credential(True, JIT_MODE_ELEVATION))

        def test_none_mode_with_flag(self):
            self.assertFalse(provisions_credential(True, None))

        def test_flag_off_regardless_of_mode(self):
            """A record with JIT configured but launched without --jit must
            still go through the normal credential checks."""
            for mode in (JIT_MODE_EPHEMERAL, JIT_MODE_BOTH, JIT_MODE_ELEVATION, None):
                self.assertFalse(
                    provisions_credential(False, mode),
                    f'--jit flag off should never bypass cred check (mode={mode})',
                )

        def test_falsey_flag_coerced(self):
            """Defensive: 0 / '' / None are all falsey and must not bypass."""
            for flag in (0, '', None):
                self.assertFalse(provisions_credential(flag, JIT_MODE_EPHEMERAL))


if __name__ == '__main__':
    unittest.main()
