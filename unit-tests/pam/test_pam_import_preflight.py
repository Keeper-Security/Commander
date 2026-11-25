"""Dry-run pre-flight: problems the live Step 2 would only hit after records exist (preflight.py)."""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

from keepercommander.commands.pam_import import preflight
from keepercommander.commands.pam_import.base import (
    PamCloudResourceObject,
    PamMachineObject,
    PamRemoteBrowserObject,
    PamRotationParams,
    PamUserObject,
    SaasConfigurationObject,
)

CFG = 'bU2LVM6LjX_hmCoSMDA7vg'
MACH = 'dU2LVM6LjX_hmCoSMDA7vx'


def _user(title='u1', rotation=None, tag='new', **rs):
    data = {'type': 'pamUser', 'title': title, 'login': title, 'password': 'p'}
    if rotation:
        data['rotation_settings'] = dict({'rotation': rotation}, **rs)
    u = PamUserObject.load(data, PamRotationParams(configUid=CFG, profiles={}))
    u.uid = ('U' * 21) + title[-1]
    u._extend_tag = tag
    return u


def _machine(users=None, tag='new', uid=MACH, title='M1'):
    m = PamMachineObject.load({'type': 'pamMachine', 'title': title, 'host': 'h', 'operating_system': 'windows'})
    m.uid = uid
    m._extend_tag = tag
    m.users = users or []
    return m


def _run(users=(), resources=(), extend=False, tdag=None, cfg=CFG, **patches):
    with patch.object(preflight, 'resolve_saas_config_uid', return_value=patches.get('saas', 'S' * 22)), \
         patch.object(preflight, 'resolve_service_resource_uids', side_effect=patches.get('svc', lambda p, r, res, t: list(r))), \
         patch.object(preflight, '_record_type_missing', side_effect=patches.get('missing', lambda p, n: False)):
        return preflight.collect_preflight_warnings(MagicMock(), list(users), list(resources), cfg, extend, tdag)


class TestSaas:
    def test_nested_saas_user_is_reported(self):
        nested = _user('n1', 'saas', saas_config='cfg')
        msgs = _run(resources=[_machine([nested])])
        assert any('global users[]' in m and 'n1' in m for m in msgs)

    def test_unresolved_saas_config_is_reported(self):
        msgs = _run(users=[_user('g1', 'saas', saas_config='missing')], saas='')
        assert any('saas_config "missing"' in m and 'skipped' in m for m in msgs)

    def test_resolved_saas_config_is_quiet(self):
        assert _run(users=[_user('g1', 'saas', saas_config='ok')]) == []

    def test_existing_saas_user_is_ignored(self):
        assert _run(users=[_user('g1', 'saas', saas_config='x', tag='existing')], saas='') == []


class TestServiceAccounts:
    def test_unresolved_service_resources_are_reported(self):
        user = _user('svc', 'general', service_resources=['a', 'b'])
        msgs = _run(resources=[_machine([user])], svc=lambda p, r, res, t: ['only-one'])
        assert any('1 of 2 service_resources' in m for m in msgs)

    def test_all_resolved_is_quiet(self):
        user = _user('svc', 'general', service_resources=['a'])
        assert _run(resources=[_machine([user])]) == []


class TestRecordTypes:
    def test_cloud_and_saas_record_types_missing(self):
        cloud = PamCloudResourceObject.load({'type': 'pamCloudResource', 'url': 'https://x.example',
                                             'pam_settings': {'connection': {'protocol': 'http', 'autofill_credentials': 'u'}}})
        cloud.uid = MACH
        cfg = SaasConfigurationObject.load({'title': 'c', 'saas_type': 'Okta'})
        cfg.uid = 'C' * 22
        msgs = _run(users=[cfg], resources=[cloud], missing=lambda p, n: True, cfg='')
        assert any('"pamCloudResource" is not available' in m for m in msgs)
        assert any('"saasConfiguration" is not available' in m for m in msgs)

    def test_types_present_is_quiet(self):
        cloud = PamCloudResourceObject.load({'type': 'pamCloudResource', 'url': 'https://x.example',
                                             'pam_settings': {'connection': {'protocol': 'http', 'autofill_credentials': 'u'}}})
        cloud.uid = MACH
        assert _run(resources=[cloud], cfg='') == []

    def test_cloud_needs_an_idp_capable_configuration(self):
        cloud = PamCloudResourceObject.load({'type': 'pamCloudResource', 'url': 'https://x.example',
                                             'pam_settings': {'connection': {'protocol': 'http', 'autofill_credentials': 'u'}}})
        cloud.uid = MACH

        def cfg_record(rtype, idp=None):
            rec = MagicMock()
            rec.record_type = rtype
            field = MagicMock()
            field.value = [idp] if idp else []
            rec.get_typed_field.return_value = field
            return rec

        with patch.object(preflight.vault.KeeperRecord, 'load', return_value=cfg_record('pamNetworkConfiguration')):
            msgs = _run(resources=[cloud])
        assert any('IdP' in m and 'pamNetworkConfiguration' in m for m in msgs)
        with patch.object(preflight.vault.KeeperRecord, 'load', return_value=cfg_record('pamAwsConfiguration')):
            assert _run(resources=[cloud]) == []
        with patch.object(preflight.vault.KeeperRecord, 'load', return_value=cfg_record('pamNetworkConfiguration', 'IDPUID')):
            assert _run(resources=[cloud]) == []


class TestIamRotation:
    def _cfg(self, rtype):
        rec = MagicMock()
        rec.record_type = rtype
        return rec

    def test_global_iam_user_needs_a_cloud_or_idp_configuration(self):
        iam = _user('i1', 'iam_user')
        with patch.object(preflight.vault.KeeperRecord, 'load', return_value=self._cfg('pamNetworkConfiguration')):
            msgs = _run(users=[iam])
        assert any('iam_user' in m and '"i1"' in m and 'cloud / IdP' in m and 'pamNetworkConfiguration' in m
                   for m in msgs)

    def test_supported_configuration_types_are_quiet(self):
        iam = _user('i1', 'iam_user')
        for rtype in ('pamAwsConfiguration', 'pamAzureConfiguration', 'pamGcpConfiguration',
                      'pamDomainConfiguration', 'pamOktaConfiguration'):
            with patch.object(preflight.vault.KeeperRecord, 'load', return_value=self._cfg(rtype)):
                assert _run(users=[iam]) == [], rtype

    def test_other_rotations_existing_users_and_unknown_configuration_are_quiet(self):
        with patch.object(preflight.vault.KeeperRecord, 'load', return_value=self._cfg('pamNetworkConfiguration')):
            assert _run(users=[_user('s1', 'scripts_only'), _user('g1', 'general')]) == []
            assert _run(users=[_user('i1', 'iam_user', tag='existing')]) == []
        with patch.object(preflight.vault.KeeperRecord, 'load', return_value=None):
            assert _run(users=[_user('i1', 'iam_user')]) == []
        with patch.object(preflight.vault.KeeperRecord, 'load') as load:     # import into a NEW configuration
            assert _run(users=[_user('i1', 'iam_user')], cfg='') == []
        load.assert_not_called()

    def test_nested_iam_user_is_reported(self):
        msgs = _run(resources=[_machine([_user('n1', 'iam_user')])])
        assert any('global users[]' in m and 'n1' in m and 'iam_user' in m for m in msgs)


class TestNestedScriptsOnly:
    def test_nested_scripts_only_user_is_reported_global_one_is_not(self):
        msgs = _run(resources=[_machine([_user('n1', 'scripts_only')])])
        assert any('scripts_only' in m and 'n1' in m and 'general' in m for m in msgs)
        assert _run(users=[_user('g1', 'scripts_only')]) == []


class TestExtendExistingMachines:
    def _tdag(self, in_config=True, admin='ADMINUID'):
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = in_config
        tdag.check_if_resource_has_admin.return_value = admin
        return tdag

    def test_missing_admin_with_rotating_new_user(self):
        mach = _machine([_user('r1', 'general')], tag='existing', title='B1-M9')
        msgs = _run(resources=[mach], extend=True, tdag=self._tdag(admin=False))
        assert any('B1-M9' in m and 'no admin credential' in m and 'r1' in m for m in msgs)

    def test_existing_admin_is_quiet(self):
        mach = _machine([_user('r1', 'general')], tag='existing')
        assert _run(resources=[mach], extend=True, tdag=self._tdag()) == []

    def test_no_rotation_needs_no_admin(self):
        mach = _machine([_user('plain')], tag='existing')
        assert _run(resources=[mach], extend=True, tdag=self._tdag(admin=False)) == []

    def test_machine_not_in_config(self):
        mach = _machine([_user('r1', 'general')], tag='existing')
        msgs = _run(resources=[mach], extend=True, tdag=self._tdag(in_config=False))
        assert any('not linked to the PAM configuration' in m for m in msgs)

    def test_import_mode_and_new_machines_skip_the_graph_checks(self):
        mach = _machine([_user('r1', 'general')], tag='new')
        assert _run(resources=[mach], extend=True, tdag=self._tdag(admin=False)) == []
        existing = _machine([_user('r1', 'general')], tag='existing')
        assert _run(resources=[existing], extend=False, tdag=self._tdag(admin=False)) == []


def _rbi(options=None, tag='new', cls=PamRemoteBrowserObject):
    r = cls.load({'type': 'pamRemoteBrowser', 'title': 'R1', 'url': 'https://x.example',
                  'pam_settings': {'options': options or {}, 'connection': {'protocol': 'http'}}})
    r.uid = 'R' * 22
    r._extend_tag = tag
    return r


class TestKeeperAiOnPamConfiguration:
    """The 'ai_threat_detection on the PAM configuration' reminder is now a real check against the configuration."""

    def _tdag(self, state):
        tdag = MagicMock()
        tdag.get_resource_setting.return_value = state
        return tdag

    def test_warns_when_the_configuration_has_ai_off_or_unset(self):
        for state in ('off', 'default', ''):
            msgs = _run(resources=[_rbi({'ai_threat_detection': 'on'})], tdag=self._tdag(state))
            assert any('"R1"' in m and 'ai_threat_detection' in m for m in msgs), state

    def test_quiet_when_the_configuration_has_ai_on(self):
        tdag = self._tdag('on')
        assert _run(resources=[_rbi({'ai_threat_detection': 'on'})], tdag=tdag) == []
        tdag.get_resource_setting.assert_called_once_with(CFG, 'allowedSettings', 'aiEnabled')

    def test_quiet_when_ai_is_not_requested_existing_resource_or_no_graph(self):
        tdag = self._tdag('off')
        assert _run(resources=[_rbi({'connections': 'on'})], tdag=tdag) == []
        assert _run(resources=[_rbi({'ai_threat_detection': 'on'}, tag='existing')], tdag=tdag) == []
        assert _run(resources=[_rbi({'ai_threat_detection': 'on'})], tdag=None) == []

    def test_cloud_resource_is_covered_too(self):
        msgs = _run(resources=[_rbi({'ai_threat_detection': 'on'}, cls=PamCloudResourceObject)], tdag=self._tdag('off'))
        assert any('ai_threat_detection' in m for m in msgs)

    def test_simulate_loads_the_graph_for_an_import_with_an_existing_configuration(self):
        from keepercommander.commands.pam_import.batch_pipeline import BatchPamImportEngine
        engine = BatchPamImportEngine.__new__(BatchPamImportEngine)
        engine.params = MagicMock()
        engine.params.record_cache = {}
        engine.project = {}
        engine.users = []
        engine.resources = [_rbi({'ai_threat_detection': 'on'})]
        engine.users_folder_uid = engine.resources_folder_uid = 'F'
        engine.pam_cfg_uid = CFG
        engine.extend_mode = False
        with patch.object(BatchPamImportEngine, 'build_plan', return_value=[]),              patch.object(BatchPamImportEngine, '_plan_deferred_links_for_tiers', return_value=[]),              patch.object(BatchPamImportEngine, '_project_record_link_counts', return_value={}),              patch('keepercommander.commands.pam_import.batch_pipeline.plan_deferred_refs_for_tiers', return_value=[]),              patch('keepercommander.commands.pam_import.batch_pipeline.load_graph_for_preflight',
                   return_value=self._tdag('off')) as load:
            plan = engine.simulate()
        load.assert_called_once()
        assert any('ai_threat_detection' in m for m in plan['preflight_warnings'])
        with patch.object(BatchPamImportEngine, 'build_plan', return_value=[]),              patch.object(BatchPamImportEngine, '_plan_deferred_links_for_tiers', return_value=[]),              patch.object(BatchPamImportEngine, '_project_record_link_counts', return_value={}),              patch('keepercommander.commands.pam_import.batch_pipeline.plan_deferred_refs_for_tiers', return_value=[]),              patch('keepercommander.commands.pam_import.batch_pipeline.load_graph_for_preflight', return_value=None):
            plan = engine.simulate()
        assert any('KeeperAI check' in m and 'skipped' in m for m in plan['preflight_warnings'])


class TestRobustness:
    def test_never_raises(self):
        with patch.object(preflight, '_collect', side_effect=RuntimeError('boom')):
            msgs = preflight.collect_preflight_warnings(MagicMock(), [], [], CFG, False)
        assert msgs and 'boom' in msgs[0]

    def test_graph_loader_returns_none_on_failure(self):
        with patch('keepercommander.commands.pam_import.preflight.vault', create=True):
            with patch('keepercommander.commands.tunnel.port_forward.tunnel_helpers.get_keeper_tokens',
                       side_effect=RuntimeError('no session')):
                assert preflight.load_graph_for_preflight(MagicMock(), CFG) is None


class TestSimulateIntegration:
    def test_simulate_reports_preflight_and_reads_the_graph_only_for_extend_with_new_users(self):
        from keepercommander.commands.pam_import.batch_pipeline import BatchPamImportEngine
        mach = _machine([_user('r1', 'general')], tag='existing', title='B1-M9')
        engine = BatchPamImportEngine.__new__(BatchPamImportEngine)
        engine.params = MagicMock()
        engine.params.record_cache = {}
        engine.project = {}
        engine.users = []
        engine.resources = [mach]
        engine.users_folder_uid = engine.resources_folder_uid = 'F'
        engine.pam_cfg_uid = CFG
        engine.extend_mode = True
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.check_if_resource_has_admin.return_value = False
        with patch.object(BatchPamImportEngine, 'build_plan', return_value=[]), \
             patch.object(BatchPamImportEngine, '_plan_deferred_links_for_tiers', return_value=[]), \
             patch.object(BatchPamImportEngine, '_project_record_link_counts', return_value={}), \
             patch('keepercommander.commands.pam_import.batch_pipeline.plan_deferred_refs_for_tiers', return_value=[]), \
             patch('keepercommander.commands.pam_import.batch_pipeline.load_graph_for_preflight', return_value=tdag) as load:
            plan = engine.simulate()
        load.assert_called_once()
        assert any('B1-M9' in m and 'no admin credential' in m for m in plan['preflight_warnings'])

    def test_import_mode_never_loads_the_graph(self):
        from keepercommander.commands.pam_import.batch_pipeline import BatchPamImportEngine
        engine = BatchPamImportEngine.__new__(BatchPamImportEngine)
        engine.params = MagicMock()
        engine.params.record_cache = {}
        engine.project = {}
        engine.users = []
        engine.resources = [_machine([_user('r1', 'general')], tag='new')]
        engine.users_folder_uid = engine.resources_folder_uid = 'F'
        engine.pam_cfg_uid = ''
        engine.extend_mode = False
        with patch.object(BatchPamImportEngine, 'build_plan', return_value=[]), \
             patch.object(BatchPamImportEngine, '_plan_deferred_links_for_tiers', return_value=[]), \
             patch.object(BatchPamImportEngine, '_project_record_link_counts', return_value={}), \
             patch('keepercommander.commands.pam_import.batch_pipeline.plan_deferred_refs_for_tiers', return_value=[]), \
             patch('keepercommander.commands.pam_import.batch_pipeline.load_graph_for_preflight') as load:
            plan = engine.simulate()
        load.assert_not_called()
        assert plan['preflight_warnings'] == []


class TestExtendLookupsSeeNewAndExistingMachines:
    """In extend the lookups must cover (a) machines/configs being ADDED in the same JSON, (b) machines already in the
    vault but not in the JSON. The real resolvers are used here (only the vault search is mocked)."""

    NEW_MACH = 'eU2LVM6LjX_hmCoSMDA7vx'

    def _svc_user(self, refs):
        return _user('svc', 'general', service_resources=refs)

    def _run_real(self, users, resources, vault_records=(), extend=True, tdag=None):
        with patch('keepercommander.vault_extensions.find_records', return_value=list(vault_records)) as find, \
             patch.object(preflight, '_record_type_missing', return_value=False):
            msgs = preflight.collect_preflight_warnings(MagicMock(), users, resources, CFG, extend, tdag)
        return msgs, find

    def test_service_resource_that_is_a_new_machine_in_the_same_extend(self):
        existing = _machine([self._svc_user(['New-Win-01'])], tag='existing', title='B1-M1')
        new_machine = _machine([], tag='new', uid=self.NEW_MACH, title='New-Win-01')
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.check_if_resource_has_admin.return_value = 'ADMIN'
        msgs, find = self._run_real([], [existing, new_machine], tdag=tdag)
        assert msgs == []
        find.assert_not_called()          # found in the extend JSON, no vault search needed

    def test_service_resource_that_is_an_existing_vault_machine_not_in_the_json(self):
        existing = _machine([self._svc_user(['Old-Win-01'])], tag='existing', title='B1-M1')
        vault_machine = MagicMock(record_uid='O' * 22, title='Old-Win-01')
        vault_machine.get_typed_field.return_value.get_default_value.return_value = 'windows'
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.check_if_resource_has_admin.return_value = 'ADMIN'
        msgs, find = self._run_real([], [existing], vault_records=[vault_machine], tdag=tdag)
        assert msgs == []
        find.assert_called_once()

    def test_unknown_service_resource_is_reported(self):
        existing = _machine([self._svc_user(['Nope'])], tag='existing', title='B1-M1')
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        tdag.check_if_resource_has_admin.return_value = 'ADMIN'
        msgs, _ = self._run_real([], [existing], vault_records=[], tdag=tdag)
        assert any('1 of 1 service_resources' in m for m in msgs)

    def test_saas_config_defined_as_new_in_the_same_extend(self):
        cfg = SaasConfigurationObject.load({'title': 'New AWS keys', 'saas_type': 'AWS Access Key'})
        cfg.uid = 'C' * 22
        cfg._extend_tag = 'new'
        saas_user = _user('g1', 'saas', saas_config='New AWS keys')
        msgs, find = self._run_real([cfg, saas_user], [])
        assert not any('saas_config' in m for m in msgs)
        find.assert_not_called()

    def test_saas_config_that_already_exists_in_the_vault(self):
        saas_user = _user('g1', 'saas', saas_config='Old keys')
        vault_cfg = MagicMock(record_uid='V' * 22, title='Old keys', record_type='saasConfiguration')
        msgs, find = self._run_real([saas_user], [], vault_records=[vault_cfg])
        assert not any('saas_config' in m for m in msgs)
        find.assert_called_once()

    def test_unknown_saas_config_is_reported(self):
        saas_user = _user('g1', 'saas', saas_config='Ghost')
        msgs, _ = self._run_real([saas_user], [], vault_records=[])
        assert any('saas_config "Ghost"' in m for m in msgs)

    def test_new_machine_in_extend_is_not_looked_up_in_the_graph(self):
        """New machines do not exist in the PAM graph yet: no graph lookup, no false 'no admin' warning."""
        new_machine = _machine([_user('r1', 'general')], tag='new', title='Brand-New')
        tdag = MagicMock()
        tdag.check_if_resource_has_admin.return_value = False
        msgs, _ = self._run_real([], [new_machine], tdag=tdag)
        assert msgs == []
        tdag.check_if_resource_has_admin.assert_not_called()
