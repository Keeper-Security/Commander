import json
import os
import stat
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.tenant_profile import (
    ProfileError,
    REGION_TO_SERVER,
    TenantProfile,
    load_registry,
    save_registry,
)


class ValidationTests(unittest.TestCase):
    def test_requires_name(self):
        with self.assertRaises(ProfileError):
            TenantProfile(name='').validate()

    def test_rejects_bad_region(self):
        with self.assertRaises(ProfileError):
            TenantProfile(name='p', region='WRONG').validate()

    def test_accepts_each_valid_region(self):
        for r in REGION_TO_SERVER.keys():
            p = TenantProfile(name='p', region=r)
            p.validate()

    def test_rejects_bad_stage_in_what_to_migrate(self):
        with self.assertRaises(ProfileError):
            TenantProfile(name='p',
                          what_to_migrate=['structure', 'not-a-stage']).validate()

    def test_rejects_bad_scope_mode(self):
        with self.assertRaises(ProfileError):
            TenantProfile(name='p',
                          scope={'mode': 'banana'}).validate()

    def test_valid_scope_modes_pass(self):
        for mode in ('full', 'node', 'prefix'):
            TenantProfile(name='p', scope={'mode': mode}).validate()

    def test_mc_requires_mc_field(self):
        with self.assertRaises(ProfileError):
            TenantProfile(name='p', tenant_type='mc').validate()


class EffectiveServerRegionTests(unittest.TestCase):
    def test_region_resolves_to_server(self):
        p = TenantProfile(name='p', region='EU')
        self.assertEqual(p.effective_server, 'keepersecurity.eu')

    def test_server_resolves_to_region(self):
        p = TenantProfile(name='p', server='keepersecurity.jp')
        self.assertEqual(p.effective_region, 'JP')

    def test_explicit_server_wins_over_region(self):
        p = TenantProfile(name='p', region='EU', server='custom.host')
        self.assertEqual(p.effective_server, 'custom.host')


class RegistryRoundtripTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, 'profiles.yaml')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_empty_registry_when_absent(self):
        self.assertEqual(load_registry(self.path), {})

    def test_save_and_reload(self):
        src = TenantProfile(
            name='acme-prod',
            tenant_type='enterprise',
            region='EU',
            data_residency='EU',
            compliance_tags=['gdpr'],
            what_to_migrate=['structure', 'users'],
            scope={'mode': 'prefix', 'value': 'MIGTEST-'},
            run_dir='/tmp/run-x',
        )
        tgt = TenantProfile(
            name='acme-mc',
            tenant_type='mc',
            region='EU',
            mc='Customer Inc.',
            parent_msp='acme-msp',
        )
        save_registry({'acme-prod': src, 'acme-mc': tgt}, self.path)
        reloaded = load_registry(self.path)
        self.assertEqual(reloaded['acme-prod'].region, 'EU')
        self.assertEqual(reloaded['acme-prod'].data_residency, 'EU')
        self.assertEqual(reloaded['acme-mc'].mc, 'Customer Inc.')

    def test_save_sets_0600(self):
        TenantProfile(name='p').validate()  # sanity
        save_registry({'p': TenantProfile(name='p')}, self.path)
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_from_dict_accepts_full_spec(self):
        d = {'name': 'p', 'region': 'US',
             'what_to_migrate': ['structure'], 'run_dir': '/tmp/r'}
        p = TenantProfile.from_dict(d)
        self.assertEqual(p.name, 'p')
        self.assertEqual(p.what_to_migrate, ['structure'])
        self.assertEqual(p.run_dir, '/tmp/r')


if __name__ == '__main__':
    unittest.main()
