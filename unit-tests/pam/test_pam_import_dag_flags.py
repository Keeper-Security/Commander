"""DAG-only flags in `pam project import/extend` (plan D:\\WORK\\tasks\\ppie.kc\\ppie-dag-flags-plan.md).

Covers:
- pam_settings.connection.rotate_creds_on_session_termination -> DAG meta `rotateOnTermination`
- pam_settings.options.jit_settings.default_elevation_time (duration string -> ms, plaintext meta edge)
- pam_settings.options.jit_settings.use_idp_elevation (encrypted jit_settings blob)
- pam_settings.options.update_services -> DAG meta `no_update_services`
- TunnelDAG.set_resource_allowed(default_elevation_time=, update_services=) for the legacy and Layer-B writes
"""
import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from keepercommander.commands.pam_import.base import (
    DagJitSettingsObject,
    DagSettingsObject,
    PamMachineObject,
    PamRemoteBrowserObject,
    PamSettingsFieldData,
    parse_command_options,
)
from keepercommander.commands.pam._layer_b import clear_layer_b_feature_cache
from keepercommander.proto import pam_pb2

RESOURCE_UID_STR = 'AAAAAAAAAAAAAAAAAAAAAA'
CONFIG_UID_STR = 'BBBBBBBBBBBBBBBBBBBBBB'
TEST_ROUTER_URL = 'http://test-krouter'

MIN_MS = 300_000
MAX_MS = 31_536_000_000


@pytest.fixture(autouse=True)
def _stub_router(monkeypatch):
    monkeypatch.setattr('keepercommander.commands.pam.router_helper.get_router_url', lambda params: TEST_ROUTER_URL)
    clear_layer_b_feature_cache()
    yield
    clear_layer_b_feature_cache()


# ---------------------------------------------------------------------------
# jit_settings.default_elevation_time / use_idp_elevation
# ---------------------------------------------------------------------------
class TestElevationTime:
    @pytest.mark.parametrize('value,expected', [
        ('1d', 86_400_000),
        ('8h', 28_800_000),
        ('90m', 5_400_000),
        ('5m', MIN_MS),
        ('30', 1_800_000),          # a bare number means minutes
        (' 2H ', 7_200_000),        # case / whitespace tolerant
        ('365d', MAX_MS),
    ])
    def test_valid(self, value, expected):
        assert DagJitSettingsObject.parse_elevation_time(value) == expected

    @pytest.mark.parametrize('value', [
        '1h30m',        # combined units are not supported
        '4m',           # below 5 minutes
        '366d',         # above 1 year
        '0d', '-5m', 'abc', '', None, True,
    ])
    def test_invalid_or_out_of_range(self, value):
        assert DagJitSettingsObject.parse_elevation_time(value) is None

    def test_load_stores_ms_and_keeps_it_out_of_the_encrypted_blob(self):
        jit = DagJitSettingsObject.load({'elevate': True, 'elevation_string': 'G', 'default_elevation_time': '2h'})
        assert jit.default_elevation_time_ms == 7_200_000
        blob = jit.to_dag_dict()
        assert 'defaultElevationTime' not in blob
        assert 'useIDPElevation' not in blob

    def test_default_elevation_time_alone_makes_a_valid_object(self):
        jit = DagJitSettingsObject.load({'default_elevation_time': '1d'})
        assert jit is not None and jit.default_elevation_time_ms == 86_400_000

    def test_invalid_time_is_skipped_with_warning(self, caplog):
        with caplog.at_level(logging.WARNING):
            jit = DagJitSettingsObject.load({'elevate': True, 'default_elevation_time': '1h30m'})
        assert jit.default_elevation_time_ms is None
        assert any('default_elevation_time' in r.message for r in caplog.records)

    def test_use_idp_elevation_only_written_when_given(self):
        assert 'useIDPElevation' not in DagJitSettingsObject.load({'elevate': True}).to_dag_dict()
        on = DagJitSettingsObject.load({'elevate': True, 'use_idp_elevation': True}).to_dag_dict()
        off = DagJitSettingsObject.load({'elevate': True, 'use_idp_elevation': False}).to_dag_dict()
        assert on['useIDPElevation'] is True
        assert off['useIDPElevation'] is False


# ---------------------------------------------------------------------------
# options.update_services
# ---------------------------------------------------------------------------
class TestUpdateServicesOption:
    @pytest.mark.parametrize('value,expected', [
        ('on', 'on'), ('off', 'off'), ('ON', 'on'), (True, 'on'), (False, 'off'), ('default', 'default'),
    ])
    def test_values(self, value, expected):
        opts = DagSettingsObject.load({'update_services': value})
        assert opts.update_services.value == expected

    def test_missing_or_invalid_is_none(self):
        assert DagSettingsObject.load({}).update_services is None
        assert DagSettingsObject.load({'update_services': 'maybe'}).update_services is None

    def test_locked_in_json_is_ignored_like_any_unknown_key(self):
        opts = DagSettingsObject.load({'locked': True, 'rotation': 'on'})
        assert not hasattr(opts, 'locked')       # the member stays commented out in the class
        assert opts.rotation.value == 'on'


# ---------------------------------------------------------------------------
# connection.rotate_creds_on_session_termination
# ---------------------------------------------------------------------------
def _settings(connection=None, jit=None, options=None, **extra):
    data = {'connection': connection if connection is not None else {'protocol': 'ssh', 'launch_credentials': 'u1',
                                                                    'rotate_creds_on_session_termination': True}}
    data['options'] = dict(options or {})
    if jit is not None:
        data['options']['jit_settings'] = jit
    data.update(extra)
    return PamSettingsFieldData.load(data)


class TestRotateOnTermination:
    def test_parsed_from_connection_and_not_a_connection_field(self):
        ps = _settings()
        assert ps.rotate_on_termination is True
        assert ps.effective_rotate_on_termination() is True
        assert not hasattr(ps.connection, 'rotate_creds_on_session_termination')

    def test_false_is_written_too(self):
        ps = _settings(connection={'protocol': 'ssh', 'launch_credentials': 'u1',
                                   'rotate_creds_on_session_termination': False})
        assert ps.effective_rotate_on_termination() is False

    def test_absent_means_not_given(self):
        ps = _settings(connection={'protocol': 'ssh'})
        assert ps.rotate_on_termination is None
        assert ps.effective_rotate_on_termination() is None

    def test_ignored_without_connection_protocol(self):
        ps = PamSettingsFieldData.load({'connection': {'rotate_creds_on_session_termination': True}})
        assert ps.effective_rotate_on_termination() is None
        assert any('needs pam_settings.connection' in m for m in ps.dag_flag_warnings())

    def test_ignored_while_create_ephemeral_is_on(self):
        ps = _settings(jit={'create_ephemeral': True})
        assert ps.effective_rotate_on_termination() is None
        assert any('create_ephemeral' in m for m in ps.dag_flag_warnings())

    def test_warns_without_launch_credentials_but_still_writes(self):
        ps = _settings(connection={'protocol': 'ssh', 'rotate_creds_on_session_termination': True})
        assert ps.effective_rotate_on_termination() is True
        assert any('LAUNCH' in m for m in ps.dag_flag_warnings())

    def test_no_warning_when_all_good(self):
        assert _settings().dag_flag_warnings() == []


# ---------------------------------------------------------------------------
# parse_command_options (what reaches TunnelDAG.set_resource_allowed)
# ---------------------------------------------------------------------------
def _machine(**ps):
    return PamMachineObject.load({'type': 'pamMachine', 'title': 'M1', 'host': 'h', 'pam_settings': ps})


class TestParseCommandOptions:
    def test_machine_passes_the_new_flags(self):
        mach = _machine(
            options={'connections': 'on', 'update_services': 'off',
                     'jit_settings': {'elevate': True, 'elevation_string': 'G', 'default_elevation_time': '1d'}},
            connection={'protocol': 'ssh', 'launch_credentials': 'u1', 'rotate_creds_on_session_termination': True})
        args = parse_command_options(mach, False)
        assert args['rotate_on_termination'] is True
        assert args['default_elevation_time'] == 86_400_000
        assert args['update_services'] is False
        assert args['connections'] is True

    def test_nothing_added_when_not_given(self):
        args = parse_command_options(_machine(options={'connections': 'on'}, connection={'protocol': 'ssh'}), False)
        for key in ('rotate_on_termination', 'default_elevation_time', 'update_services'):
            assert key not in args

    def test_flags_work_without_options_block(self):
        mach = _machine(connection={'protocol': 'ssh', 'launch_credentials': 'u1',
                                    'rotate_creds_on_session_termination': True})
        assert parse_command_options(mach, False)['rotate_on_termination'] is True

    def test_not_added_in_tunnel_edit_mode(self):
        mach = _machine(options={'connections': 'on'},
                        connection={'protocol': 'ssh', 'rotate_creds_on_session_termination': True})
        assert 'rotate_on_termination' not in parse_command_options(mach, True)

    def test_rbi_never_gets_the_machine_flags(self):
        rbi = PamRemoteBrowserObject.load({
            'type': 'pamRemoteBrowser', 'title': 'R1', 'url': 'https://x.example',
            'pam_settings': {'options': {'connections': 'on', 'update_services': 'off'},
                             'connection': {'protocol': 'http', 'rotate_creds_on_session_termination': True}}})
        args = parse_command_options(rbi, False)
        for key in ('rotate_on_termination', 'default_elevation_time', 'update_services'):
            assert key not in args


# ---------------------------------------------------------------------------
# TunnelDAG.set_resource_allowed writes
# ---------------------------------------------------------------------------
def _build_tg():
    from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG

    tg = TunnelDAG.__new__(TunnelDAG)
    tg.params = MagicMock()
    tg.record = MagicMock()
    tg.record.record_uid = CONFIG_UID_STR
    tg.linking_dag = MagicMock()
    resource_vertex = MagicMock()
    resource_vertex.vertex_type = 'PAM_MACHINE'
    tg.linking_dag.get_vertex.return_value = resource_vertex
    return tg, resource_vertex


class TestSetResourceAllowedMetaFlags:
    def test_legacy_write_carries_elevation_time_and_no_update_services(self):
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        tg, vertex = _build_tg()
        with patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch.object(type(tg), '_defer_saves', True, create=True), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource') as cr:
            tg.set_resource_allowed(RESOURCE_UID_STR, connections='on', meta_version=1,
                                    default_elevation_time=7_200_000, update_services=False,
                                    rotate_on_termination=True)
        cr.assert_not_called()
        written = vertex.add_data.call_args.kwargs['content']
        assert written['defaultElevationTime'] == 7_200_000
        assert written['no_update_services'] is True
        assert written['rotateOnTermination'] is True
        assert written['version'] == 1

    def test_update_services_true_writes_explicit_false_flag(self):
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        tg, vertex = _build_tg()
        with patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch.object(type(tg), '_defer_saves', True, create=True):
            tg.set_resource_allowed(RESOURCE_UID_STR, meta_version=1, update_services=True)
        assert vertex.add_data.call_args.kwargs['content']['no_update_services'] is False

    def test_layer_b_sends_elevation_time_in_meta_and_update_services_field(self):
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        tg, _ = _build_tg()
        captured = {}
        with patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource',
                   side_effect=lambda params, rq: captured.setdefault('rq', rq)):
            tg.set_resource_allowed(RESOURCE_UID_STR, connections='on', meta_version=1,
                                    default_elevation_time=3_600_000, update_services=False)
        rq = captured['rq']
        assert isinstance(rq, pam_pb2.PAMResourceConfig)
        assert rq.updateServices is False
        meta = rq.meta.decode()
        assert 'defaultElevationTime' in meta and '3600000' in meta
        assert 'no_update_services' not in meta       # travels in the dedicated field

    def test_unchanged_values_do_not_dirty_the_edge(self):
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        tg, vertex = _build_tg()
        existing = {'version': 1, 'allowedSettings': {}, 'rotateOnTermination': False,
                    'defaultElevationTime': 7_200_000, 'no_update_services': True}
        with patch.object(tg_mod, 'get_vertex_content', return_value=existing), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource') as cr:
            tg.set_resource_allowed(RESOURCE_UID_STR, meta_version=1,
                                    default_elevation_time=7_200_000, update_services=False)
        cr.assert_not_called()
        vertex.add_data.assert_not_called()

    def test_locked_is_never_a_parameter(self):
        import inspect
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG
        assert 'locked' not in inspect.signature(TunnelDAG.set_resource_allowed).parameters


# ---------------------------------------------------------------------------
# RBI (pamRemoteBrowser) KeeperAI - reference: `pam connection ai`
# ---------------------------------------------------------------------------
AI_JSON = {'risk_levels': {'critical': {'ai_session_terminate': True, 'activities': {'allow': ['a'], 'deny': ['b']}},
                          'low': {'ai_session_terminate': False}}}


def _rbi(options=None, connection=None):
    ps = {'options': options if options is not None else {}, 'connection': connection if connection is not None else {'protocol': 'http', 'allow_supply_user': False}}
    return PamRemoteBrowserObject.load({'type': 'pamRemoteBrowser', 'title': 'R1', 'url': 'https://x.example',
                                        'pam_settings': ps})


class TestRbiKeeperAi:
    def test_ai_settings_are_parsed_for_rbi(self):
        rbi = _rbi(options={'ai_threat_detection': 'on', 'ai_settings': AI_JSON})
        assert rbi.rbi_settings.ai_settings is not None
        d = rbi.rbi_settings.ai_settings.to_dag_dict(user_id='uid')
        assert d and 'riskLevels' in d

    def test_ai_flags_reach_set_resource_allowed_for_rbi(self):
        rbi = _rbi(options={'connections': 'on', 'ai_threat_detection': 'on', 'ai_terminate_session_on_detection': 'off'})
        args = parse_command_options(rbi, False)
        assert args['ai_enabled'] is True
        assert args['ai_session_terminate'] is False

    def test_jit_is_still_never_read_for_rbi(self):
        rbi = _rbi(options={'jit_settings': {'elevate': True, 'default_elevation_time': '1d'}})
        assert not hasattr(rbi.rbi_settings, 'jit_settings')    # the member stays commented out in the class
        assert 'default_elevation_time' not in parse_command_options(rbi, False)

    def test_warnings_when_prerequisites_are_off(self):
        from keepercommander.commands.pam_import.base import rbi_keeperai_warnings
        rbi = _rbi(options={'ai_threat_detection': 'on'})
        msgs = rbi_keeperai_warnings(rbi.rbi_settings)
        assert any('graphical_session_recording' in m for m in msgs)
        assert any('recording_include_keys' in m for m in msgs)
        assert not any('PAM configuration' in m for m in msgs)    # that part moved to the dry-run pre-flight

    def test_warning_when_ai_settings_without_ai_threat_detection(self):
        from keepercommander.commands.pam_import.base import rbi_keeperai_warnings
        rbi = _rbi(options={'graphical_session_recording': 'on', 'ai_settings': AI_JSON},
                   connection={'protocol': 'http', 'recording_include_keys': True})
        msgs = rbi_keeperai_warnings(rbi.rbi_settings)
        assert any("not 'on'" in m for m in msgs)
        assert not any('graphical_session_recording' in m for m in msgs)

    def test_no_warnings_when_ai_not_requested(self):
        from keepercommander.commands.pam_import.base import rbi_keeperai_warnings
        assert rbi_keeperai_warnings(_rbi(options={'connections': 'on'}).rbi_settings) == []
        assert rbi_keeperai_warnings(None) == []

    def test_step2_rbi_writes_ai_settings_on_the_deferred_graph(self):
        from keepercommander.commands.pam_import import batch_step2

        rbi = _rbi(options={'connections': 'on', 'ai_threat_detection': 'on', 'ai_settings': AI_JSON})
        rbi.uid = RESOURCE_UID_STR
        params = MagicMock()
        params.account_uid_bytes = b'\x01' * 16
        tdag = MagicMock()
        with patch('keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch'), \
             patch.object(batch_step2, 'apply_workflow'), \
             patch.object(batch_step2, 'set_resource_keeper_ai_settings', return_value=True) as set_ai:
            batch_step2._run_step2_rbi(params, tdag, rbi, CONFIG_UID_STR)

        kwargs = tdag.set_resource_allowed.call_args.kwargs
        assert kwargs['ai_enabled'] is True and kwargs['meta_version'] == 1
        set_ai.assert_called_once()
        call = set_ai.call_args
        assert call.args[1] == RESOURCE_UID_STR and call.args[3] == CONFIG_UID_STR
        assert call.kwargs['graph'] is tdag.linking_dag
        assert 'riskLevels' in call.args[2]

    def test_step2_rbi_without_ai_settings_does_not_touch_the_ai_edge(self):
        from keepercommander.commands.pam_import import batch_step2

        rbi = _rbi(options={'connections': 'on'})
        rbi.uid = RESOURCE_UID_STR
        with patch('keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch'), \
             patch.object(batch_step2, 'apply_workflow'), \
             patch.object(batch_step2, 'set_resource_keeper_ai_settings') as set_ai:
            batch_step2._run_step2_rbi(MagicMock(), MagicMock(), rbi, CONFIG_UID_STR)
        set_ai.assert_not_called()


# ---------------------------------------------------------------------------
# pamDirectory links: domain users get belongs_to; JIT domain without admin warns
# ---------------------------------------------------------------------------
class TestDirectoryLinks:
    def _user(self, rotation=False):
        user = MagicMock()
        user.uid = 'UUUUUUUUUUUUUUUUUUUUUU'
        user.rotation_settings = MagicMock() if rotation else None
        return user

    def test_plain_directory_user_is_linked_with_belongs_to(self):
        from keepercommander.commands.pam_import import batch_step2
        tdag = MagicMock()
        tdag.user_belongs_to_resource.return_value = False
        mach = MagicMock(type='pamDirectory', uid=RESOURCE_UID_STR)
        batch_step2._link_nested_user(tdag, self._user(), mach, admin_uid=None)
        tdag.link_user_to_resource.assert_called_once_with(
            'UUUUUUUUUUUUUUUUUUUUUU', RESOURCE_UID_STR, is_admin=False, belongs_to=True)

    def test_plain_machine_user_is_still_skipped(self):
        from keepercommander.commands.pam_import import batch_step2
        tdag = MagicMock()
        mach = MagicMock(type='pamMachine', uid=RESOURCE_UID_STR)
        batch_step2._link_nested_user(tdag, self._user(), mach, admin_uid=None)
        tdag.link_user_to_resource.assert_not_called()

    def test_directory_user_not_linked_twice(self):
        from keepercommander.commands.pam_import import batch_step2
        tdag = MagicMock()
        tdag.user_belongs_to_resource.return_value = True
        mach = MagicMock(type='pamDirectory', uid=RESOURCE_UID_STR)
        batch_step2._link_nested_user(tdag, self._user(), mach, admin_uid=None)
        tdag.link_user_to_resource.assert_not_called()

    def test_rotation_user_on_directory_keeps_the_existing_path(self):
        from keepercommander.commands.pam_import import batch_step2
        tdag = MagicMock()
        tdag.user_belongs_to_resource.return_value = False
        mach = MagicMock(type='pamDirectory', uid=RESOURCE_UID_STR)
        batch_step2._link_nested_user(tdag, self._user(rotation=True), mach, admin_uid=None)
        tdag.link_user_to_resource.assert_called_once()
        assert tdag.link_user_to_resource.call_args.kwargs == {'is_admin': False, 'belongs_to': True}

    def _jit_setup(self, directory_admin):
        from keepercommander.commands.pam_import import batch_step2
        directory = MagicMock(type='pamDirectory', uid='DDDDDDDDDDDDDDDDDDDDDD', title='AD1')
        mach = MagicMock(uid=RESOURCE_UID_STR, type='pamMachine', _extend_tag='new')
        mach.pam_settings.jit_settings.pam_directory_uid = directory.uid
        tdag = MagicMock()
        tdag.linking_dag.get_vertex.return_value = MagicMock(**{'has.return_value': False})
        return batch_step2, directory, mach, tdag

    def test_jit_domain_without_directory_admin_warns(self, caplog):
        batch_step2, directory, mach, tdag = self._jit_setup(None)
        with patch.object(batch_step2, 'get_admin_credential', return_value=''), caplog.at_level(logging.WARNING):
            assert batch_step2.add_jit_domain_links(tdag, [directory, mach]) is True
        assert any('AD1' in r.message and 'administrative_credentials' in r.message for r in caplog.records)

    def test_jit_domain_with_directory_admin_does_not_warn(self, caplog):
        batch_step2, directory, mach, tdag = self._jit_setup('admin')
        with patch.object(batch_step2, 'get_admin_credential', return_value='ADMINUID'), caplog.at_level(logging.WARNING):
            batch_step2.add_jit_domain_links(tdag, [directory, mach])
        assert not any('administrative_credentials' in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# DATA edge order for machines: meta LAST (the DAG library is not path aware)
# ---------------------------------------------------------------------------
class TestMachineMetaEdgeIsWrittenLast:
    """The record's current content is the DATA edge written last. The meta edge must therefore come after
    jit_settings / ai_settings, otherwise `pam connection ai --show` and other Commander readers see the ai_settings
    blob as the resource meta and report every allowed setting as 'default' (seen in the Q3 QA run)."""

    def _order(self, **ps):
        from keepercommander.commands.pam_import import batch_step2
        mach = _machine(**ps)
        mach.uid = RESOURCE_UID_STR
        calls = []
        params = MagicMock()
        params.account_uid_bytes = b'\x01' * 16
        tdag = MagicMock()
        with patch('keepercommander.commands.pam_import.tunnel_setup.apply_tunnel_setup_batch'), \
             patch.object(batch_step2, 'apply_workflow'), \
             patch.object(batch_step2, '_apply_machine_allowed_settings',
                          side_effect=lambda *a, **k: calls.append('meta')), \
             patch.object(batch_step2, 'set_resource_keeper_ai_settings',
                          side_effect=lambda *a, **k: calls.append('ai') or True), \
             patch.object(batch_step2, 'set_resource_jit_settings',
                          side_effect=lambda *a, **k: calls.append('jit') or True):
            batch_step2._run_step2_machine(params, tdag, mach, 'CFG', None)
        return calls

    AI = {'risk_levels': {'critical': {'ai_session_terminate': True}}}

    def test_jit_and_ai_before_meta(self):
        order = self._order(options={'connections': 'on', 'ai_threat_detection': 'on', 'ai_settings': self.AI,
                                     'jit_settings': {'elevate': True, 'elevation_string': 'G'}},
                            connection={'protocol': 'ssh'})
        assert order == ['jit', 'ai', 'meta']

    def test_ai_only(self):
        assert self._order(options={'ai_settings': self.AI}, connection={'protocol': 'ssh'}) == ['ai', 'meta']

    def test_meta_only(self):
        assert self._order(options={'connections': 'on'}, connection={'protocol': 'ssh'}) == ['meta']


class TestMetaReaderIsPathCorrect:
    """get_vertex_content / get_resource_setting must return the newest `meta` edge even when a jit_settings /
    ai_settings DATA edge was written after it (DAG library is not path aware; `pam connection ai --show` printed
    'default' for such resources)."""

    @staticmethod
    def _edge(path, version, content, edge_type=None):
        from keepercommander.keeper_dag import EdgeType
        e = MagicMock()
        e.edge_type = edge_type or EdgeType.DATA
        e.path = path
        e.version = version
        e.content_as_dict = content
        return e

    def _vertex(self, edges, last):
        v = MagicMock()
        v.edges = edges
        v.content_as_dict = last
        return v

    def test_meta_wins_over_a_later_ai_edge(self):
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import get_vertex_content
        meta = {'allowedSettings': {'aiEnabled': True}}
        ai = {'riskLevels': {}}
        v = self._vertex([self._edge('meta', 0, {'allowedSettings': {}}), self._edge('meta', 1, meta),
                          self._edge('ai_settings', 2, ai)], last=ai)
        assert get_vertex_content(v) == meta

    def test_falls_back_to_last_edge_when_no_meta_path(self):
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import get_vertex_content
        legacy = {'allowedSettings': {'connections': True}}
        v = self._vertex([self._edge(None, 0, legacy)], last=legacy)
        assert get_vertex_content(v) == legacy
        assert get_vertex_content(None) is None

    def test_ignores_non_data_edges_on_meta_path(self):
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import get_vertex_content
        from keepercommander.keeper_dag import EdgeType
        meta = {'allowedSettings': {'aiEnabled': True}}
        v = self._vertex([self._edge('meta', 1, meta), self._edge('meta', 5, {'x': 1}, EdgeType.ACL)], last=None)
        assert get_vertex_content(v) == meta

    def test_get_resource_setting_reads_meta_not_the_ai_blob(self):
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG
        meta = {'allowedSettings': {'aiEnabled': True, 'aiSessionTerminate': False}}
        v = self._vertex([self._edge('meta', 1, meta), self._edge('ai_settings', 2, {'riskLevels': {}})],
                         last={'riskLevels': {}})
        tdag = TunnelDAG.__new__(TunnelDAG)
        tdag.linking_dag = MagicMock()
        tdag.linking_dag.get_vertex.return_value = v
        assert tdag.get_resource_setting(RESOURCE_UID_STR, 'allowedSettings', 'aiEnabled') == 'on'
        assert tdag.get_resource_setting(RESOURCE_UID_STR, 'allowedSettings', 'aiSessionTerminate') == 'off'


class TestSetResourceAllowedWhenAiBlobIsTheLastEdge:
    """A resource whose newest DATA edge is `ai_settings` / `jit_settings` must still be edited from its real
    `meta` (flags kept, no blob keys copied into meta)."""

    META = {'version': 1, 'rotateOnTermination': True,
            'allowedSettings': {'connections': True, 'aiEnabled': True, 'aiSessionTerminate': True}}
    AI_BLOB = {'version': 'v1.0.0', 'riskLevels': {'low': {'aiSessionTerminate': False}}}

    def _tg(self):
        from keepercommander.keeper_dag import EdgeType
        tg, vertex = _build_tg()

        def edge(path, version, content):
            e = MagicMock()
            e.edge_type = EdgeType.DATA
            e.path = path
            e.version = version
            e.content_as_dict = content
            return e

        vertex.edges = [edge('meta', 1, dict(self.META)), edge('ai_settings', 2, dict(self.AI_BLOB))]
        vertex.content_as_dict = dict(self.AI_BLOB)       # what the path-unaware property returns
        return tg, vertex

    def test_legacy_write_keeps_existing_flags_and_rotate_on_termination(self):
        tg, vertex = self._tg()
        with patch.object(type(tg), '_defer_saves', True, create=True):
            tg.set_resource_allowed(RESOURCE_UID_STR, session_recording='on')
        written = vertex.add_data.call_args.kwargs['content']
        assert written['allowedSettings'] == {'connections': True, 'aiEnabled': True, 'aiSessionTerminate': True,
                                              'sessionRecording': True}
        assert written['rotateOnTermination'] is True
        assert written['version'] == 1
        assert 'riskLevels' not in written

    def test_reset_to_default_removes_only_that_flag(self):
        tg, vertex = self._tg()
        with patch.object(type(tg), '_defer_saves', True, create=True):
            tg.set_resource_allowed(RESOURCE_UID_STR, connections='default')
        written = vertex.add_data.call_args.kwargs['content']
        assert written['allowedSettings'] == {'aiEnabled': True, 'aiSessionTerminate': True}
        assert 'riskLevels' not in written

    def test_check_if_resource_allowed_reads_meta(self):
        tg, _ = self._tg()
        assert tg.check_if_resource_allowed(RESOURCE_UID_STR, 'connections') is True


class TestJitCommandRefreshesMeta:
    def test_set_refreshes_meta_after_the_jit_write(self):
        from keepercommander.commands.tunnel_and_connections import PAMConnectionJitCommand
        calls = []
        with patch('keepercommander.commands.pam_import.keeper_ai_settings.get_resource_jit_settings',
                   return_value={}), \
             patch('keepercommander.commands.pam_import.keeper_ai_settings.set_resource_jit_settings',
                   side_effect=lambda *a, **k: calls.append('jit') or True), \
             patch('keepercommander.commands.pam_import.keeper_ai_settings.refresh_meta_to_latest',
                   side_effect=lambda *a, **k: calls.append('meta') or True):
            PAMConnectionJitCommand()._do_set(MagicMock(), {'elevate': 'on'}, RESOURCE_UID_STR, CONFIG_UID_STR)
        assert calls == ['jit', 'meta']

    def test_failed_write_does_not_refresh(self):
        from keepercommander.commands.tunnel_and_connections import PAMConnectionJitCommand
        from keepercommander.error import CommandError
        with patch('keepercommander.commands.pam_import.keeper_ai_settings.get_resource_jit_settings',
                   return_value={}), \
             patch('keepercommander.commands.pam_import.keeper_ai_settings.set_resource_jit_settings',
                   return_value=False), \
             patch('keepercommander.commands.pam_import.keeper_ai_settings.refresh_meta_to_latest') as refresh:
            with pytest.raises(CommandError):
                PAMConnectionJitCommand()._do_set(MagicMock(), {'elevate': 'on'}, RESOURCE_UID_STR, CONFIG_UID_STR)
        refresh.assert_not_called()
