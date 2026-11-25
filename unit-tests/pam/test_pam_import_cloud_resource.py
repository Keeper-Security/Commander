"""pamCloudResource ("PAM Cloud") in `pam project import/extend` (plan D:\\WORK\\tasks\\ppie.kc\\ppie-dag-flags-plan.md).

Record template: rbiUrl (required), accountNumber labelled pamCloudResourceAccountIdentifier, pamRemoteBrowserSettings,
trafficEncryptionSeed, fileRef. Settings follow the Web Vault cloud modal (Connection / JIT / KeeperAI / Workflow).
"""
import logging
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

from keepercommander.commands.pam_import import batch_step2
from keepercommander.commands.pam_import.base import (
    PAM_IMPORT_RESOURCE_TYPES,
    PAM_RESOURCES_RECORD_TYPES,
    PamCloudResourceObject,
    PamRemoteBrowserObject,
    parse_command_options,
)
from keepercommander.commands.pam_import.pam_record_build import _rbi_settings_json, build_record_add_kwargs
from keepercommander.keeper_dag.types import RefType

RES_UID = 'AAAAAAAAAAAAAAAAAAAAAA'
CFG_UID = 'BBBBBBBBBBBBBBBBBBBBBB'


def _cloud(**over):
    data = {
        'type': 'pamCloudResource', 'title': 'AWS Console', 'url': 'https://console.aws.amazon.com/',
        'pam_settings': {
            'options': {'connections': 'on', 'remote_browser_isolation': 'on', 'graphical_session_recording': 'on'},
            'connection': {'protocol': 'http', 'autofill_credentials': 'svc-user'},
        },
    }
    data.update(over)
    return PamCloudResourceObject.load(data)


class TestLoad:
    def test_basic(self):
        obj = _cloud(account_identifier=' 0oa1b2c3 ')
        assert obj.type == 'pamCloudResource'
        assert isinstance(obj, PamRemoteBrowserObject)          # reuses every RBI code path
        assert obj.rbiUrl == 'https://console.aws.amazon.com/'
        assert obj.accountIdentifier == '0oa1b2c3'
        assert obj.rbi_settings.connection.to_record_dict()['protocol'] == 'http'

    def test_default_title_uses_the_cloud_prefix(self):
        obj = PamCloudResourceObject.load({'type': 'pamCloudResource', 'url': 'https://acme.okta.com/home'})
        assert obj.title == 'PAM Cloud - acme.okta.com'

    def test_connection_block_is_always_present_with_http_protocol(self):
        obj = PamCloudResourceObject.load({'type': 'pamCloudResource', 'title': 't', 'url': 'https://x.example'})
        assert obj.rbi_settings is not None
        assert obj.rbi_settings.connection.to_record_dict() == {'protocol': 'http'}
        fld = _rbi_settings_json(obj, inserted_uids=set())
        assert fld and '"protocol": "http"' in fld

    def test_missing_url_is_an_error(self, caplog):
        with caplog.at_level(logging.ERROR):
            PamCloudResourceObject.load({'type': 'pamCloudResource', 'title': 't'})
        assert any('rbiUrl' in r.message for r in caplog.records)

    def test_jit_keeps_cloud_keys_and_drops_the_ones_that_do_not_apply(self, caplog):
        with caplog.at_level(logging.WARNING):
            obj = _cloud(account_identifier='x', pam_settings={
                'options': {'jit_settings': {
                    'create_ephemeral': False, 'elevate': True, 'elevation_method': 'role', 'elevation_string': 'R',
                    'default_elevation_time': '1d', 'use_idp_elevation': True, 'ephemeral_account_type': 'linux',
                    'base_distinguished_name': 'DC=x', 'pam_directory_record': 'AD'}},
                'connection': {'protocol': 'http', 'autofill_credentials': 'svc'}})
        jit = obj.jit_settings
        assert jit.elevate and jit.elevation_method == 'role' and jit.elevation_string == 'R'
        assert jit.default_elevation_time_ms == 86_400_000
        assert jit.use_idp_elevation is None and not jit.ephemeral_account_type
        assert not jit.base_distinguished_name and not jit.pam_directory_record
        blob = jit.to_dag_dict()
        for key in ('useIDPElevation', 'ephemeralAccountType', 'defaultElevationTime'):
            assert key not in blob
        assert any('not used for pamCloudResource' in r.message for r in caplog.records)

    def test_warnings(self, caplog):
        with caplog.at_level(logging.WARNING):
            PamCloudResourceObject.load({'type': 'pamCloudResource', 'title': 'Okta app', 'url': 'https://acme.okta.com',
                                         'pam_settings': {'options': {'jit_settings': {'create_ephemeral': True}},
                                                          'connection': {'protocol': 'http', 'autofill_credentials': 'u'}}})
        msgs = ' '.join(r.message for r in caplog.records)
        assert 'ignored at launch' in msgs                     # autofill + create_ephemeral
        assert 'elevate + elevation_string' in msgs            # ephemeral without permissions
        assert 'account_identifier is missing' in msgs         # Okta URL without identifier

    def test_no_launch_credential_warns(self, caplog):
        with caplog.at_level(logging.WARNING):
            PamCloudResourceObject.load({'type': 'pamCloudResource', 'title': 'x', 'url': 'https://console.aws.amazon.com'})
        assert any('launch credential' in r.message for r in caplog.records)

    def test_aws_console_needs_no_account_identifier(self, caplog):
        with caplog.at_level(logging.WARNING):
            _cloud()
        assert not any('account_identifier' in r.message for r in caplog.records)

    def test_keeperai_warnings_are_reported(self, caplog):
        with caplog.at_level(logging.WARNING):
            _cloud(pam_settings={'options': {'ai_threat_detection': 'on'},
                                 'connection': {'protocol': 'http', 'autofill_credentials': 'svc'}})
        assert any('KeeperAI' in r.message for r in caplog.records)


class TestRecordAndTypes:
    def test_import_accepts_the_type_but_export_list_is_unchanged(self):
        assert 'pamCloudResource' in PAM_IMPORT_RESOURCE_TYPES
        assert 'pamCloudResource' not in PAM_RESOURCES_RECORD_TYPES      # exporter does not handle it yet

    def test_record_add_kwargs(self):
        obj = _cloud(account_identifier='0oa1b2c3')
        args = build_record_add_kwargs(obj, 'FOLDER')
        assert args['record_type'] == 'pamCloudResource'
        assert 'rbiUrl=https://console.aws.amazon.com/' in args['fields']
        assert 'f.accountNumber.pamCloudResourceAccountIdentifier=0oa1b2c3' in args['fields']

    def test_no_account_number_field_without_identifier(self):
        args = build_record_add_kwargs(_cloud(), 'FOLDER')
        assert not any('accountNumber' in f for f in args['fields'])

    def test_rbi_record_is_unchanged(self):
        rbi = PamRemoteBrowserObject.load({'type': 'pamRemoteBrowser', 'title': 'r', 'url': 'https://x.example'})
        assert rbi.type == 'pamRemoteBrowser'
        assert not any('accountNumber' in f for f in build_record_add_kwargs(rbi, 'F').get('fields', []))
        assert PamRemoteBrowserObject.load({'type': 'pamRemoteBrowser', 'url': 'https://acme.example/x'}).title == 'PAM RBI - acme.example'


class TestStep2:
    def _run(self, obj):
        obj.uid = RES_UID
        params = MagicMock()
        params.account_uid_bytes = b'\x01' * 16
        tdag = MagicMock()
        with patch('keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch'), \
             patch.object(batch_step2, 'apply_workflow'), \
             patch.object(batch_step2, 'set_resource_keeper_ai_settings', return_value=True) as set_ai, \
             patch.object(batch_step2, 'set_resource_jit_settings', return_value=True) as set_jit:
            batch_step2._run_step2_rbi(params, tdag, obj, CFG_UID)
        return tdag, set_ai, set_jit

    def test_meta_follows_the_cloud_modal(self):
        obj = _cloud(pam_settings={
            'options': {'remote_browser_isolation': 'on', 'graphical_session_recording': 'on',
                        'jit_settings': {'elevate': True, 'elevation_string': 'G', 'default_elevation_time': '2h'}},
            'connection': {'protocol': 'http', 'autofill_credentials': 'svc'}})
        tdag, _, set_jit = self._run(obj)
        kwargs = tdag.set_resource_allowed.call_args.kwargs
        assert kwargs['connections'] is True and 'remote_browser_isolation' not in kwargs
        assert kwargs['session_recording'] is True
        assert kwargs['default_elevation_time'] == 7_200_000
        assert kwargs['v_type'] == RefType.PAM_BROWSER and kwargs['meta_version'] == 1
        assert 'rotate_on_termination' not in kwargs and 'update_services' not in kwargs

    def test_jit_blob_is_written_on_the_deferred_graph(self):
        obj = _cloud(pam_settings={
            'options': {'jit_settings': {'create_ephemeral': True, 'elevate': True, 'elevation_string': 'G'}},
            'connection': {'protocol': 'http'}})
        tdag, _, set_jit = self._run(obj)
        set_jit.assert_called_once()
        call = set_jit.call_args
        assert call.args[1] == RES_UID and call.args[3] == CFG_UID and call.kwargs['graph'] is tdag.linking_dag
        assert call.args[2]['createEphemeral'] is True and call.args[2]['elevationString'] == 'G'

    def test_keeperai_is_written_for_cloud_too(self):
        ai = {'risk_levels': {'critical': {'ai_session_terminate': True}}}
        obj = _cloud(pam_settings={'options': {'ai_threat_detection': 'on', 'ai_settings': ai},
                                   'connection': {'protocol': 'http', 'autofill_credentials': 'svc'}})
        tdag, set_ai, _ = self._run(obj)
        set_ai.assert_called_once()
        assert tdag.set_resource_allowed.call_args.kwargs['ai_enabled'] is True

    def test_plain_rbi_keeps_remote_browser_isolation_and_gets_no_jit(self):
        rbi = PamRemoteBrowserObject.load({'type': 'pamRemoteBrowser', 'title': 'r', 'url': 'https://x.example',
                                           'pam_settings': {'options': {'remote_browser_isolation': 'on'},
                                                            'connection': {'protocol': 'http', 'allow_supply_user': False}}})
        tdag, _, set_jit = self._run(rbi)
        kwargs = tdag.set_resource_allowed.call_args.kwargs
        assert kwargs['remote_browser_isolation'] is True and kwargs['connections'] is True
        assert 'default_elevation_time' not in kwargs
        set_jit.assert_not_called()

    def test_parse_command_options_never_adds_machine_flags_for_cloud(self):
        obj = _cloud()
        args = parse_command_options(obj, False)
        for key in ('rotate_on_termination', 'default_elevation_time', 'update_services'):
            assert key not in args


class TestAccountIdentifierFieldAssignment:
    """The record-add spec for account_identifier must land in the template's own accountNumber field (label
    pamCloudResourceAccountIdentifier), not create a new custom field, and must not warn."""

    def _template_record(self):
        from keepercommander import vault
        rec = vault.TypedRecord()
        rec.type_name = 'pamCloudResource'
        for t, label in (('rbiUrl', None), ('accountNumber', 'pamCloudResourceAccountIdentifier'),
                         ('pamRemoteBrowserSettings', None), ('trafficEncryptionSeed', None), ('fileRef', None)):
            rec.fields.append(vault.TypedField.new_field(t, None, label))
        return rec

    def test_spec_fills_the_template_field(self):
        from keepercommander.commands.record_edit import RecordAddCommand
        obj = _cloud(account_identifier='0oa1b2c3d4e5F6g7h8i9')
        specs = [f for f in build_record_add_kwargs(obj, 'F')['fields'] if 'accountNumber' in f]
        assert specs == ['f.accountNumber.pamCloudResourceAccountIdentifier=0oa1b2c3d4e5F6g7h8i9']
        cmd = RecordAddCommand()
        problems = []
        cmd.on_warning = problems.append
        cmd.on_error = problems.append
        rec = self._template_record()
        cmd.assign_typed_fields(rec, [cmd.parse_field(s) for s in specs])
        field = next(f for f in rec.fields if f.type == 'accountNumber')
        assert field.value == ['0oa1b2c3d4e5F6g7h8i9']
        assert field.label == 'pamCloudResourceAccountIdentifier'
        assert rec.custom == []
        assert problems == []


class TestMetaEdgeIsWrittenLast:
    """The DAG library has no path awareness: the record's current content is the DATA edge written LAST. For RBI /
    cloud resources the meta edge must therefore come after jit_settings / ai_settings, otherwise Commander readers
    (`pam connection ai --show`, ...) see the ai_settings blob as the resource meta (Q3 QA run: everything 'default')."""

    def _order(self, obj):
        from unittest.mock import MagicMock, patch
        obj.uid = RES_UID
        params = MagicMock()
        params.account_uid_bytes = b'\x01' * 16
        calls = []
        tdag = MagicMock()
        tdag.set_resource_allowed.side_effect = lambda **kw: calls.append('meta')
        with patch('keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch'), \
             patch.object(batch_step2, 'apply_workflow'), \
             patch.object(batch_step2, 'set_resource_keeper_ai_settings',
                          side_effect=lambda *a, **k: calls.append('ai') or True), \
             patch.object(batch_step2, 'set_resource_jit_settings',
                          side_effect=lambda *a, **k: calls.append('jit') or True):
            batch_step2._run_step2_rbi(params, tdag, obj, CFG_UID)
        return calls

    def test_rbi_with_ai(self):
        ai = {'risk_levels': {'critical': {'ai_session_terminate': True}}}
        rbi = PamRemoteBrowserObject.load({'type': 'pamRemoteBrowser', 'title': 'r', 'url': 'https://x.example',
                                           'pam_settings': {'options': {'ai_threat_detection': 'on', 'ai_settings': ai},
                                                            'connection': {'protocol': 'http', 'allow_supply_user': False}}})
        assert self._order(rbi) == ['ai', 'meta']

    def test_cloud_with_jit_and_ai(self):
        ai = {'risk_levels': {'low': {'ai_session_terminate': False}}}
        obj = _cloud(pam_settings={'options': {'ai_settings': ai, 'jit_settings': {'elevate': True, 'elevation_string': 'G'}},
                                   'connection': {'protocol': 'http', 'autofill_credentials': 'svc'}})
        assert self._order(obj) == ['jit', 'ai', 'meta']

    def test_meta_only(self):
        assert self._order(_cloud()) == ['meta']
