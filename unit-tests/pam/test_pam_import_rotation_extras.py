"""Rotation extras of `pam project import/extend` (plan D:\\WORK\\tasks\\ppie.kc\\ppie-dag-flags-plan.md):

- pamUser rotation_settings.service_resources / update_services (service accounts, controls_services)
- rotation: saas + saas_config, SaaS configuration records (saasConfiguration / legacy login with "SaaS Type")
"""
import logging
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(__file__))

import keepercommander.vault as vault
from keepercommander.commands.pam_import import batch_step2
from keepercommander.commands.pam_import.base import (
    LoginUserObject,
    PamMachineObject,
    PamRotationParams,
    PamRotationSettingsObject,
    PamUserObject,
    SaasConfigurationObject,
)
from keepercommander.commands.pam_import.pam_record_build import build_record_add_kwargs

CONFIG_UID = 'bU2LVM6LjX_hmCoSMDA7vg'
MACH_UID = 'dU2LVM6LjX_hmCoSMDA7vx'
MACH2_UID = 'eU2LVM6LjX_hmCoSMDA7vx'
USER_UID = 'OYNvVgpPPJBrVfYOIRtdag'
SAAS_UID = 'sU2LVM6LjX_hmCoSMDA7vs'


def _rot(data, config_uid=CONFIG_UID):
    return PamRotationSettingsObject.load(data, PamRotationParams(configUid=config_uid, profiles={}))


# ---------------------------------------------------------------------------
# rotation_settings parsing
# ---------------------------------------------------------------------------
class TestRotationSettingsParsing:
    def test_saas_needs_saas_config_and_points_at_the_pam_config(self, caplog):
        rs = _rot({'rotation': 'saas', 'saas_config': ' AWS keys '})
        assert rs.rotation == 'saas'
        assert rs.saas_config == 'AWS keys'
        assert rs.resource == CONFIG_UID
        with caplog.at_level(logging.ERROR):
            assert _rot({'rotation': 'saas'}).saas_config == ''
        assert any('saas_config' in r.message for r in caplog.records)

    def test_service_resources_default_update_services_on(self):
        rs = _rot({'rotation': 'general', 'service_resources': ['WinSrv-01', MACH_UID]})
        assert rs.service_resources == ['WinSrv-01', MACH_UID]
        assert rs.update_services is True

    def test_explicit_update_services_off(self):
        rs = _rot({'rotation': 'general', 'service_resources': 'WinSrv-01', 'update_services': False})
        assert rs.service_resources == ['WinSrv-01']
        assert rs.update_services is False

    def test_empty_list_is_kept_and_not_given_is_none(self):
        assert _rot({'rotation': 'general', 'service_resources': []}).service_resources == []
        rs = _rot({'rotation': 'general'})
        assert rs.service_resources is None and rs.update_services is None

    def test_invalid_service_resources_type(self, caplog):
        with caplog.at_level(logging.ERROR):
            rs = _rot({'rotation': 'general', 'service_resources': {'a': 1}})
        assert rs.service_resources is None
        assert any('service_resources' in r.message for r in caplog.records)

    def test_not_applicable_to_saas(self, caplog):
        with caplog.at_level(logging.WARNING):
            rs = _rot({'rotation': 'saas', 'saas_config': 'x', 'service_resources': ['m'], 'update_services': True})
        assert rs.service_resources is None and rs.update_services is None
        assert any('do not apply to saas' in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# SaaS configuration records
# ---------------------------------------------------------------------------
class TestSaasConfigurationObject:
    def test_fields_are_hidden_by_default_and_types_can_be_overridden(self):
        cfg = SaasConfigurationObject.load({
            'title': 'AWS keys', 'saas_type': 'AWS Access Key', 'active': True,
            'fields': {'AWS Secret Access Key': 'sekret', 'AWS Region': {'value': 'us-east-1', 'type': 'text'}}})
        by_label = {f['label']: f for f in cfg.custom}
        assert cfg.type == 'saasConfiguration'
        assert by_label['SaaS Type'] == {'type': 'text', 'label': 'SaaS Type', 'value': 'AWS Access Key'}
        assert by_label['Active']['value'] == 'TRUE'
        assert by_label['AWS Secret Access Key']['type'] == 'secret'          # Web Vault "Hidden Field"
        assert by_label['AWS Region']['type'] == 'text'

    def test_inactive_and_missing_type(self, caplog):
        with caplog.at_level(logging.WARNING):
            cfg = SaasConfigurationObject.load({'title': 't', 'active': False})
        assert cfg.custom[-1] == {'type': 'text', 'label': 'Active', 'value': 'FALSE'} or \
            {'type': 'text', 'label': 'Active', 'value': 'FALSE'} in cfg.custom
        msgs = ' '.join(r.message for r in caplog.records)
        assert 'saas_type' in msgs and 'not active' in msgs

    def test_record_add_kwargs(self):
        cfg = SaasConfigurationObject.load({'title': 'cfg', 'saas_type': 'Okta', 'fields': {'Token': 'tok'}})
        args = build_record_add_kwargs(cfg, 'FOLDERUID')
        assert args['record_type'] == 'saasConfiguration'
        assert 'c.text.SaaS Type=Okta' in args['fields']
        assert 'c.text.Active=TRUE' in args['fields']
        assert 'c.secret.Token=tok' in args['fields']

    def test_legacy_login_custom_fields_and_has_saas_type(self):
        login = LoginUserObject.load({'type': 'login', 'title': 'old cfg', 'login': 'u', 'password': 'p',
                                      'custom': [{'type': 'text', 'label': 'SaaS Type', 'value': 'Okta'}]})
        assert login.has_saas_type()
        assert 'c.text.SaaS Type=Okta' in build_record_add_kwargs(login, 'F')['fields']
        assert not LoginUserObject.load({'type': 'login', 'title': 'plain'}).has_saas_type()


# ---------------------------------------------------------------------------
# saas_config resolution
# ---------------------------------------------------------------------------
def _vault_rec(uid, title, rtype, saas_type=None):
    rec = MagicMock()
    rec.record_uid, rec.title, rec.record_type = uid, title, rtype
    field = MagicMock()
    field.label = 'SaaS Type'
    field.get_default_value.return_value = saas_type or ''
    rec.custom = [field] if saas_type is not None else []
    return rec


class TestResolveSaasConfig:
    def test_import_saas_configuration_by_title(self):
        cfg = SaasConfigurationObject.load({'title': 'AWS keys', 'saas_type': 'AWS Access Key'})
        cfg.uid = SAAS_UID
        assert batch_step2.resolve_saas_config_uid(MagicMock(), 'AWS keys', [cfg]) == SAAS_UID

    def test_import_legacy_login_needs_saas_type(self, caplog):
        good = LoginUserObject.load({'type': 'login', 'title': 'old', 'custom': [
            {'type': 'text', 'label': 'SaaS Type', 'value': 'Okta'}]})
        good.uid = SAAS_UID
        assert batch_step2.resolve_saas_config_uid(MagicMock(), 'old', [good]) == SAAS_UID
        bad = LoginUserObject.load({'type': 'login', 'title': 'plain'})
        bad.uid = 'xxxxxxxxxxxxxxxxxxxxxx'
        with caplog.at_level(logging.ERROR):
            assert batch_step2.resolve_saas_config_uid(MagicMock(), 'plain', [bad]) == ''
        assert any('SaaS Type' in r.message for r in caplog.records)

    def test_vault_lookup_accepts_saasconfiguration_and_login_with_type(self):
        recs = [_vault_rec(SAAS_UID, 'cfg', 'saasConfiguration')]
        with patch('keepercommander.vault_extensions.find_records', return_value=recs):
            assert batch_step2.resolve_saas_config_uid(MagicMock(), 'cfg', []) == SAAS_UID
        recs = [_vault_rec(SAAS_UID, 'cfg', 'login', saas_type='Okta')]
        with patch('keepercommander.vault_extensions.find_records', return_value=recs):
            assert batch_step2.resolve_saas_config_uid(MagicMock(), 'cfg', []) == SAAS_UID

    def test_vault_login_without_saas_type_and_not_found_and_ambiguous(self, caplog):
        with caplog.at_level(logging.ERROR):
            with patch('keepercommander.vault_extensions.find_records',
                       return_value=[_vault_rec(SAAS_UID, 'cfg', 'login')]):
                assert batch_step2.resolve_saas_config_uid(MagicMock(), 'cfg', []) == ''
            with patch('keepercommander.vault_extensions.find_records', return_value=[]):
                assert batch_step2.resolve_saas_config_uid(MagicMock(), 'cfg', []) == ''
            two = [_vault_rec(SAAS_UID, 'cfg', 'saasConfiguration'), _vault_rec('zzzzzzzzzzzzzzzzzzzzzz', 'cfg', 'saasConfiguration')]
            with patch('keepercommander.vault_extensions.find_records', return_value=two):
                assert batch_step2.resolve_saas_config_uid(MagicMock(), 'cfg', []) == ''
        assert len(caplog.records) == 3


# ---------------------------------------------------------------------------
# Step 2: global SaaS users
# ---------------------------------------------------------------------------
def _user(rotation, nested=False, tag='new', **rs):
    user = PamUserObject.load({'type': 'pamUser', 'title': 'u1', 'login': 'u1', 'password': 'p',
                               'rotation_settings': dict({'rotation': rotation}, **rs)},
                              PamRotationParams(configUid=CONFIG_UID, profiles={}))
    user.uid = USER_UID
    user._extend_tag = tag
    return user


class TestGlobalSaasStep:
    def _run(self, users, exists=False, resolved=SAAS_UID):
        prc = MagicMock()
        with patch.object(batch_step2, '_rotation_exists', return_value=exists), \
             patch.object(batch_step2, 'resolve_saas_config_uid', return_value=resolved), \
             patch.object(batch_step2, 'call_with_throttle_retry', side_effect=lambda fn, **kw: fn()):
            batch_step2.run_step2_global_saas(MagicMock(), prc, users, CONFIG_UID)
        return prc

    def test_saas_user_sends_the_web_vault_shape(self):
        prc = self._run([_user('saas', saas_config='cfg', enabled='on',
                               schedule={'type': 'cron', 'cron': '30 18 * * *'})])
        kwargs = prc.execute.call_args.kwargs
        assert kwargs['rotation_profile'] == 'saas'
        assert kwargs['saas_config_uid'] == SAAS_UID
        assert kwargs['saas_in_request'] is True
        assert kwargs['record_name'] == USER_UID and kwargs['config'] == CONFIG_UID
        assert kwargs['enable'] is True and kwargs['schedule_cron_data'] == ['30 18 * * *']
        assert 'resource' not in kwargs      # noop + resource is a router error

    def test_skips_other_profiles_existing_users_existing_rotation_and_unresolved_config(self):
        assert not self._run([_user('iam_user')]).execute.called           # iam_user / scripts_only: unchanged
        assert not self._run([_user('scripts_only')]).execute.called
        assert not self._run([_user('saas', saas_config='cfg', tag='existing')]).execute.called
        assert not self._run([_user('saas', saas_config='cfg')], exists=True).execute.called
        assert not self._run([_user('saas', saas_config='cfg')], resolved='').execute.called


class TestGlobalProfileStep:
    """iam_user / scripts_only of global users were resolved but never sent before this pass."""

    def _run(self, users, exists=False):
        prc = MagicMock()
        with patch.object(batch_step2, '_rotation_exists', return_value=exists),              patch.object(batch_step2, 'call_with_throttle_retry', side_effect=lambda fn, **kw: fn()):
            batch_step2.run_step2_global_profile_rotations(MagicMock(), prc, users, CONFIG_UID)
        return prc

    def test_iam_user_and_scripts_only_use_the_rotation_profile(self):
        for profile in ('iam_user', 'scripts_only'):
            prc = self._run([_user(profile, enabled='on', schedule={'type': 'on-demand'})])
            kwargs = prc.execute.call_args.kwargs
            assert kwargs['rotation_profile'] == profile
            assert kwargs['record_name'] == USER_UID and kwargs['config'] == CONFIG_UID
            assert kwargs['enable'] is True and kwargs['on_demand'] is True
            assert 'resource' not in kwargs and 'saas_config_uid' not in kwargs

    def test_skips_saas_general_existing_users_and_existing_rotation(self):
        assert not self._run([_user('saas', saas_config='cfg')]).execute.called      # saas has its own pass
        assert not self._run([_user('general')]).execute.called
        assert not self._run([_user('iam_user', tag='existing')]).execute.called
        assert not self._run([_user('iam_user')], exists=True).execute.called
        assert not self._run([MagicMock()]).execute.called                            # not a PamUserObject

    def test_user_without_rotation_is_untouched(self):
        user = PamUserObject.load({'type': 'pamUser', 'title': 'u1', 'login': 'u1', 'password': 'p'},
                                  PamRotationParams(configUid=CONFIG_UID, profiles={}))
        user.uid = USER_UID
        assert not self._run([user]).execute.called


class TestNestedSaasIsSkipped:
    def test_nested_saas_user_is_neither_linked_nor_rotated(self, caplog):
        mach = MagicMock(uid=MACH_UID, title='M1', type='pamMachine', _extend_tag='new', users=[_user('saas', saas_config='c')],
                         pam_settings=None)
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        prc = MagicMock()
        with patch.object(batch_step2, '_run_step2_machine'), patch.object(batch_step2, '_apply_rotation') as apply_rot, \
             patch.object(batch_step2, 'get_admin_credential', return_value=''), \
             patch.object(batch_step2, 'get_launch_credential', return_value=''), \
             patch.object(batch_step2, '_apply_machine_allowed_settings'), caplog.at_level(logging.WARNING):
            batch_step2.run_step2_full(MagicMock(), tdag, mach, CONFIG_UID, prc, 'UF', 'RF')
        apply_rot.assert_not_called()
        tdag.link_user_to_resource.assert_not_called()
        assert any('global users[]' in r.message for r in caplog.records)


class TestNestedIamIsSkipped:
    PROFILE = 'iam_user'

    def _run_nested(self, extend):
        mach = MagicMock(uid=MACH_UID, title='M1', type='pamMachine', _extend_tag='existing' if extend else 'new',
                         users=[_user(self.PROFILE)], pam_settings=None)
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        with patch.object(batch_step2, '_run_step2_machine'), patch.object(batch_step2, '_apply_rotation') as apply_rot,              patch.object(batch_step2, 'get_admin_credential', return_value=''),              patch.object(batch_step2, 'get_launch_credential', return_value=''),              patch.object(batch_step2, '_apply_machine_allowed_settings'),              patch.object(batch_step2, 'call_with_throttle_retry'):
            if extend:
                batch_step2.run_step2_extend_existing(MagicMock(), tdag, mach, CONFIG_UID, MagicMock())
            else:
                batch_step2.run_step2_full(MagicMock(), tdag, mach, CONFIG_UID, MagicMock(), 'UF', 'RF')
        return apply_rot, tdag

    def test_nested_iam_user_is_neither_linked_nor_rotated(self, caplog):
        for extend in (False, True):
            with caplog.at_level(logging.WARNING):
                apply_rot, tdag = self._run_nested(extend)
            apply_rot.assert_not_called()
            tdag.link_user_to_resource.assert_not_called()
        assert sum(self.PROFILE in r.message and 'global users[]' in r.message for r in caplog.records) == 2


class TestNestedScriptsOnlyIsSkipped(TestNestedIamIsSkipped):
    PROFILE = 'scripts_only'

    def test_message_points_to_general_for_machine_scripts(self, caplog):
        with caplog.at_level(logging.WARNING):
            self._run_nested(False)
        assert any('general' in r.message and "scripts of the machine" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# service accounts
# ---------------------------------------------------------------------------
def _machine(uid, title, os_name='windows'):
    m = PamMachineObject.load({'type': 'pamMachine', 'title': title, 'host': 'h', 'operating_system': os_name})
    m.uid = uid
    return m


class TestServiceAccounts:
    def test_resolve_by_title_uid_and_os_warning(self, caplog):
        win, lin = _machine(MACH_UID, 'WinSrv-01'), _machine(MACH2_UID, 'LinSrv', 'linux')
        with caplog.at_level(logging.WARNING):
            uids = batch_step2.resolve_service_resource_uids(MagicMock(), ['WinSrv-01', MACH2_UID], [win, lin], 'svc')
        assert uids == [MACH_UID, MACH2_UID]
        assert any('not Windows' in r.message for r in caplog.records)

    def test_resolve_falls_back_to_the_vault_and_skips_unknown(self, caplog):
        vault_machine = MagicMock(record_uid=MACH_UID, title='Old-01')
        vault_machine.get_typed_field.return_value.get_default_value.return_value = 'windows'
        with patch('keepercommander.vault_extensions.find_records', side_effect=[[vault_machine], []]), \
                caplog.at_level(logging.WARNING):
            uids = batch_step2.resolve_service_resource_uids(MagicMock(), ['Old-01', 'nope'], [], 'svc')
        assert uids == [MACH_UID]
        assert any('"nope"' in r.message for r in caplog.records)

    def test_first_rotation_is_queued_without_service_args(self):
        user = _user('general', service_resources=['WinSrv-01'])
        mach = MagicMock(uid=MACH_UID, title='M1', type='pamMachine', _extend_tag='new', users=[user], pam_settings=None)
        tdag = MagicMock()
        tdag.resource_belongs_to_config.return_value = True
        queue = []
        with patch.object(batch_step2, '_run_step2_machine'), patch.object(batch_step2, '_apply_rotation') as apply_rot, \
             patch.object(batch_step2, '_rotation_exists', return_value=False), \
             patch.object(batch_step2, 'get_admin_credential', return_value=''), \
             patch.object(batch_step2, 'get_launch_credential', return_value=''), \
             patch.object(batch_step2, '_apply_machine_allowed_settings'):
            batch_step2.run_step2_full(MagicMock(), tdag, mach, CONFIG_UID, MagicMock(), 'UF', 'RF',
                                       service_queue=queue)
        apply_rot.assert_called_once()
        assert 'service_uids' not in apply_rot.call_args.kwargs
        assert queue == [(user, mach)]

    def test_apply_last_sends_service_resources_and_update_services(self):
        user = _user('general', service_resources=['WinSrv-01'], update_services=False)
        mach = MagicMock(uid=MACH_UID, title='M1')
        win = _machine(MACH2_UID, 'WinSrv-01')
        with patch.object(batch_step2, '_apply_rotation') as apply_rot, \
             patch.object(batch_step2, 'get_admin_credential', return_value='ADM'):
            batch_step2.apply_service_rotations(MagicMock(), MagicMock(), [(user, mach)], [win], CONFIG_UID)
        kwargs = apply_rot.call_args.kwargs
        assert kwargs['service_uids'] == [MACH2_UID] and kwargs['update_services'] is False

    def test_nothing_resolved_nothing_sent(self):
        user = _user('general', service_resources=['ghost'])
        with patch.object(batch_step2, '_apply_rotation') as apply_rot, \
             patch('keepercommander.vault_extensions.find_records', return_value=[]):
            batch_step2.apply_service_rotations(MagicMock(), MagicMock(), [(user, MagicMock(uid=MACH_UID))], [], CONFIG_UID)
        apply_rot.assert_not_called()

    def test_apply_rotation_forwards_service_args_to_the_command(self):
        user = _user('general', service_resources=['x'])
        prc = MagicMock()
        with patch.object(batch_step2, 'call_with_throttle_retry', side_effect=lambda fn, **kw: fn()):
            batch_step2._apply_rotation(MagicMock(), prc, user, MagicMock(uid=MACH_UID), 'ADM', CONFIG_UID,
                                        service_uids=[MACH2_UID], update_services=True)
        kwargs = prc.execute.call_args.kwargs
        assert kwargs['service_resource_uids'] == [MACH2_UID] and kwargs['update_services'] is True
        assert kwargs['resource'] == MACH_UID


# ---------------------------------------------------------------------------
# `pam rotation set` request (command level)
# ---------------------------------------------------------------------------
from keepercommander.commands.discoveryrotation import PAMCreateRecordRotationCommand  # noqa: E402
from keepercommander.error import CommandError  # noqa: E402,F401


def _command_mocks():
    mock_params = MagicMock()
    mock_params.rest_context.server_key_id = 8
    mock_params.session_token = 'tok'
    mock_params.record_rotation_cache = {}
    mock_params.nested_share_records = {}
    typed = MagicMock(spec=vault.TypedRecord)
    typed.record_type = 'pamUser'
    typed.record_uid = USER_UID
    typed.title = 'u1'
    typed.record_key = b'\x00' * 16
    cfg = MagicMock(spec=vault.TypedRecord)
    cfg.record_uid = CONFIG_UID
    cfg.record_type = 'pamAwsConfiguration'
    cfg.version = 6
    res_field = MagicMock()
    res_field.value = [{'resourceRef': [MACH_UID]}]
    cfg.get_typed_field.return_value = res_field
    return mock_params, typed, cfg


class TestRotationCommandRequest(unittest.TestCase):
    def setUp(self):
        self.command = PAMCreateRecordRotationCommand()

    @patch('keepercommander.commands.discoveryrotation.api.sync_down')
    @patch('keepercommander.commands.discoveryrotation.router_set_record_rotation_information')
    @patch('keepercommander.vault_extensions.find_records')
    @patch('keepercommander.commands.discoveryrotation.resolve_pam_record')
    @patch('keepercommander.vault.KeeperRecord.load')
    @patch('keepercommander.commands.discoveryrotation.get_keeper_tokens')
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @patch('keepercommander.rest_api.SERVER_PUBLIC_KEYS', {8: ec.generate_private_key(ec.SECP256R1()).public_key()})
    def test_general_rotation_carries_service_resources_and_update_services(
            self, mock_dag_cls, mock_tokens, mock_load, mock_resolve, mock_find, mock_router, _sync):
        params, typed, cfg = _command_mocks()
        mock_load.return_value = typed
        mock_find.return_value = [cfg]
        mock_resolve.side_effect = lambda p, ident, rec_type=None: typed if ident == USER_UID else cfg if ident == CONFIG_UID else None
        user_dag, cfg_dag = MagicMock(), MagicMock()
        user_dag.linking_dag.has_graph = False
        cfg_dag.linking_dag.has_graph = True
        cfg_dag.get_all_owners.return_value = []
        cfg_dag.resource_belongs_to_config.return_value = False
        cfg_dag.user_belongs_to_resource.return_value = False
        cfg_dag.get_resource_uid.return_value = None
        cfg_dag.record.record_uid = CONFIG_UID
        mock_dag_cls.side_effect = [user_dag, cfg_dag]
        mock_tokens.return_value = (b'token', b'encrypted_key', b'transmission_key')

        self.command.execute(params, record_name=USER_UID, config=CONFIG_UID, force=True, silent=True,
                             service_resource_uids=[MACH2_UID], update_services=False)
        rq = mock_router.call_args.args[1]
        from keepercommander import utils
        assert list(rq.serviceResources.uids) == [utils.base64_url_decode(MACH2_UID)]
        assert rq.updateServices is False

    @patch('keepercommander.commands.discoveryrotation.api.sync_down')
    @patch('keepercommander.commands.discoveryrotation.router_set_record_rotation_information')
    @patch('keepercommander.vault_extensions.find_records')
    @patch('keepercommander.commands.discoveryrotation.resolve_pam_record')
    @patch('keepercommander.vault.KeeperRecord.load')
    @patch('keepercommander.commands.discoveryrotation.get_keeper_tokens')
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @patch('keepercommander.rest_api.SERVER_PUBLIC_KEYS', {8: ec.generate_private_key(ec.SECP256R1()).public_key()})
    def test_general_rotation_without_service_args_leaves_the_fields_unset(
            self, mock_dag_cls, mock_tokens, mock_load, mock_resolve, mock_find, mock_router, _sync):
        params, typed, cfg = _command_mocks()
        mock_load.return_value = typed
        mock_find.return_value = [cfg]
        mock_resolve.side_effect = lambda p, ident, rec_type=None: typed if ident == USER_UID else cfg if ident == CONFIG_UID else None
        user_dag, cfg_dag = MagicMock(), MagicMock()
        user_dag.linking_dag.has_graph = False
        cfg_dag.linking_dag.has_graph = True
        cfg_dag.get_all_owners.return_value = []
        cfg_dag.resource_belongs_to_config.return_value = False
        cfg_dag.user_belongs_to_resource.return_value = False
        cfg_dag.get_resource_uid.return_value = None
        cfg_dag.record.record_uid = CONFIG_UID
        mock_dag_cls.side_effect = [user_dag, cfg_dag]
        mock_tokens.return_value = (b'token', b'encrypted_key', b'transmission_key')

        self.command.execute(params, record_name=USER_UID, config=CONFIG_UID, force=True, silent=True)
        rq = mock_router.call_args.args[1]
        assert not rq.HasField('serviceResources')
        assert not rq.HasField('updateServices')


class TestSaasRotationCommandRequest(unittest.TestCase):
    """`rotation_profile=saas` from the import: saasConfiguration travels in set_record_rotation (Web Vault / router
    shape); the DAG-only link_saas_user write is skipped. The CLI (no saas_in_request) keeps link_saas_user."""

    def setUp(self):
        self.command = PAMCreateRecordRotationCommand()

    def _run(self, **extra):
        params, typed, cfg = _command_mocks()
        saas = MagicMock(spec=vault.TypedRecord)
        saas.record_uid = SAAS_UID
        saas.record_type = 'saasConfiguration'
        saas_type = MagicMock()
        saas_type.label = 'SaaS Type'
        saas.custom = [saas_type]
        dag = MagicMock()
        dag.linking_dag.has_graph = True
        dag.record.record_uid = CONFIG_UID
        dag.link_saas_user.return_value = True
        patches = [
            patch('keepercommander.commands.discoveryrotation.api.sync_down'),
            patch('keepercommander.commands.discoveryrotation.router_set_record_rotation_information'),
            patch('keepercommander.vault_extensions.find_records', return_value=[cfg]),
            patch('keepercommander.commands.discoveryrotation.resolve_pam_record',
                  side_effect=lambda p, ident, rec_type=None: typed if ident == USER_UID else cfg if ident == CONFIG_UID else None),
            patch('keepercommander.vault.KeeperRecord.load',
                  side_effect=lambda p, uid: saas if uid == SAAS_UID else typed if uid == USER_UID else cfg),
            patch('keepercommander.commands.discoveryrotation.get_keeper_tokens', return_value=(b't', b'k', b'x')),
            patch('keepercommander.commands.discoveryrotation.TunnelDAG', return_value=dag),
            patch('keepercommander.rest_api.SERVER_PUBLIC_KEYS', {8: ec.generate_private_key(ec.SECP256R1()).public_key()}),
        ]
        mocks = [p.start() for p in patches]
        try:
            self.command.execute(params, record_name=USER_UID, config=CONFIG_UID, force=True, silent=True,
                                 rotation_profile='saas', saas_config_uid=SAAS_UID, **extra)
        finally:
            for p in patches:
                p.stop()
        return mocks[1], dag

    def test_import_sends_saas_configuration_in_the_request_and_skips_link_saas_user(self):
        router, dag = self._run(saas_in_request=True)
        rq = router.call_args.args[1]
        from keepercommander import utils
        assert rq.noop is True
        assert rq.saasConfiguration == utils.base64_url_decode(SAAS_UID)
        assert rq.resourceUid == b''
        dag.link_saas_user.assert_not_called()

    def test_cli_path_is_unchanged(self):
        router, dag = self._run()
        rq = router.call_args.args[1]
        assert rq.noop is True
        assert not rq.HasField('saasConfiguration')
        dag.link_saas_user.assert_called_once()


class TestSaasConfigurationFolderPath:
    """folder_path on pam_data.saas_configurations[] must be collected like the one on global users."""

    DATA = {'resources': [], 'users': [{'type': 'pamUser', 'title': 'u', 'folder_path': 'Res/A'}],
            'saas_configurations': [{'title': 'cfg', 'saas_type': 'Okta', 'folder_path': 'Res/ABTest'},
                                    {'title': 'no-path', 'saas_type': 'Okta'}]}

    def test_import_collects_the_saas_configuration_path(self):
        from keepercommander.commands.pam_import.edit import PAMProjectImportCommand
        paths = PAMProjectImportCommand._collect_pam_folder_paths(self.DATA)
        assert 'Res/ABTest' in paths and 'Res/A' in paths

    def test_saas_configuration_object_keeps_its_folder_path(self):
        cfg = SaasConfigurationObject.load(self.DATA['saas_configurations'][0])
        assert cfg.folder_path == 'Res/ABTest'
