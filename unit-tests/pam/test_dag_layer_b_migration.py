"""
Layer-B migration regression tests (plan §13.5 / task #25).

Covers the migrated write functions in `pam_import/keeper_ai_settings.py`:
- `set_resource_keeper_ai_settings` (AI risk-level settings, ai_settings edge)
- `set_resource_jit_settings` (JIT elevation settings, jit_settings edge)

Each function verifies:
- Primary path calls `router_configure_resource` with the correct `PAMResourceConfig`
  proto fields (`recordUid`, `networkUid`, and either `keeperAiSettings` or `jitSettings`).
- On `RRC_NOT_ALLOWED*` + `KEEPER_DAG_LB_FALLBACK` ON, fallback to the legacy
  DAG-write path fires.
- Strict mode (`KEEPER_DAG_LB_FALLBACK=0`) propagates the error as a `False` return
  (consistent with the legacy semantics — log + return False).
- Input validation paths (bad settings, missing record key) return early without
  calling configure_resource.
"""
import json
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes

sys.path.insert(0, os.path.dirname(__file__))

from keepercommander.commands.pam._layer_b import RouterResponseError, clear_layer_b_feature_cache
from keepercommander.commands.pam_import import keeper_ai_settings as ai_mod
from keepercommander.proto import pam_pb2, router_pb2


RESOURCE_UID_STR = 'AAAAAAAAAAAAAAAAAAAAAA'  # 16-byte base64-urlsafe (22 chars)
CONFIG_UID_STR = 'BBBBBBBBBBBBBBBBBBBBBB'
RECORD_KEY = b'\x01' * 32

TEST_ROUTER_URL = 'http://test-krouter'


@pytest.fixture(autouse=True)
def _stub_router_url_and_clear_cache(monkeypatch):
    """Stub `get_router_url` so the Layer-B feature-disabled cache has a stable
    host key without touching `params.rest_context`. Also clears the cache between
    tests so a previous test's marking doesn't bleed into the next."""
    monkeypatch.setattr(
        'keepercommander.commands.pam.router_helper.get_router_url',
        lambda params: TEST_ROUTER_URL,
    )
    clear_layer_b_feature_cache()
    yield
    clear_layer_b_feature_cache()


def _patch_inputs(monkeypatch=None):
    """Mock the shared input-resolution helper so each test starts from a known good state."""
    return patch.object(
        ai_mod,
        '_resolve_resource_settings_inputs',
        return_value=(RECORD_KEY, CONFIG_UID_STR),
    )


def _mock_params():
    p = MagicMock()
    p.session_token = 'token'
    return p


# --------------------------------------------------------------------------- #
# AI settings migration                                                        #
# --------------------------------------------------------------------------- #


class TestSetResourceKeeperAiSettingsMigration:

    def test_happy_path_calls_configure_resource_with_correct_proto(self):
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq
            return None

        with _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'CIPHER_BYTES'), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=_capture):
            ok = ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'critical'}, config_uid=CONFIG_UID_STR
            )
        assert ok is True
        rq = captured['rq']
        assert isinstance(rq, pam_pb2.PAMResourceConfig)
        # 22-char base64-urlsafe -> 16 bytes
        assert len(rq.recordUid) == 16
        assert len(rq.networkUid) == 16
        assert rq.keeperAiSettings == b'CIPHER_BYTES'
        # Critical: must NOT be set on jitSettings field
        assert rq.jitSettings == b''

    def test_happy_path_bundles_current_meta_so_krouter_persists_ai_edge(self):
        """Regression: krouter's configure_resource only writes a settings edge
        when it loads loopEdges, which it does only for requests carrying
        meta/jit/connection (UserRest.kt:497). A keeperAiSettings-only request
        leaves loopEdges null and the ai_settings write is silently dropped. The
        Web Vault always sends meta alongside AI settings; Commander must mirror
        that by bundling the resource's current meta in the same request."""
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq
            return None

        meta_dict = {'version': 1, 'allowedSettings': {'aiEnabled': True}, 'rotateOnTermination': False}
        with _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'CIPHER_BYTES'), \
             patch.object(ai_mod, 'get_resource_settings', return_value=meta_dict) as meta_mock, \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=_capture):
            ok = ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'critical'}, config_uid=CONFIG_UID_STR
            )
        assert ok is True
        rq = captured['rq']
        assert rq.keeperAiSettings == b'CIPHER_BYTES'
        # The fix: meta must be present so krouter fetches loopEdges and persists
        # the ai_settings edge. Without it the write is a silent no-op.
        assert rq.meta == json.dumps(meta_dict).encode()
        # meta is read from the resource's current 'meta' DATA edge.
        meta_mock.assert_called_once()
        assert meta_mock.call_args.args[2] == 'meta'

    def test_permission_denied_with_fallback_enabled_calls_legacy(self):
        legacy_called = {'count': 0}

        def _legacy(*args, **kwargs):
            legacy_called['count'] += 1
            return True

        err = RouterResponseError(13, 'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'CIPHER'), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err), \
             patch.object(ai_mod, '_set_resource_keeper_ai_settings_legacy', side_effect=_legacy):
            ok = ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'high'}, config_uid=CONFIG_UID_STR
            )
        assert ok is True
        assert legacy_called['count'] == 1, 'legacy fallback was not invoked'

    def test_permission_denied_with_fallback_disabled_returns_false(self):
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '0'}), \
             _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'CIPHER'), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err), \
             patch.object(ai_mod, '_set_resource_keeper_ai_settings_legacy') as legacy_mock:
            ok = ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'low'}, config_uid=CONFIG_UID_STR
            )
        assert ok is False
        legacy_mock.assert_not_called()

    def test_non_permission_error_returns_false_without_fallback(self):
        """A generic server error (not a permission denial) doesn't fall back; returns False."""
        err = RouterResponseError(99, 'RRC_GENERAL_ERROR', 'something broke')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'CIPHER'), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err), \
             patch.object(ai_mod, '_set_resource_keeper_ai_settings_legacy') as legacy_mock:
            ok = ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'low'}, config_uid=CONFIG_UID_STR
            )
        assert ok is False
        legacy_mock.assert_not_called()

    def test_bad_input_returns_false_without_calling_configure_resource(self):
        with patch.object(ai_mod, '_resolve_resource_settings_inputs', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource') as call_mock:
            ok = ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {}, config_uid=CONFIG_UID_STR
            )
        assert ok is False
        call_mock.assert_not_called()


# --------------------------------------------------------------------------- #
# JIT settings migration                                                       #
# --------------------------------------------------------------------------- #


class TestSetResourceJitSettingsMigration:

    def test_happy_path_calls_configure_resource_with_jit_field(self):
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'JIT_CIPHER'), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=_capture):
            ok = ai_mod.set_resource_jit_settings(
                _mock_params(), RESOURCE_UID_STR, {'elevate': True}, config_uid=CONFIG_UID_STR
            )
        assert ok is True
        rq = captured['rq']
        assert isinstance(rq, pam_pb2.PAMResourceConfig)
        assert rq.jitSettings == b'JIT_CIPHER'
        # JIT migration must NOT populate the AI-settings field
        assert rq.keeperAiSettings == b''

    def test_permission_denied_with_fallback_enabled_calls_legacy(self):
        legacy_called = {'count': 0}

        def _legacy(*args, **kwargs):
            legacy_called['count'] += 1
            return True

        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'JIT_CIPHER'), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err), \
             patch.object(ai_mod, '_set_resource_jit_settings_legacy', side_effect=_legacy):
            ok = ai_mod.set_resource_jit_settings(
                _mock_params(), RESOURCE_UID_STR, {'elevate': True}, config_uid=CONFIG_UID_STR
            )
        assert ok is True
        assert legacy_called['count'] == 1

    @pytest.mark.parametrize('bad_settings, allow_empty', [
        ('not a dict', False),
        (None, False),
        ({}, False),  # empty dict + allow_empty=False short-circuits
    ])
    def test_bad_input_short_circuits_before_configure_resource(self, bad_settings, allow_empty):
        with patch('keepercommander.commands.pam.router_helper.router_configure_resource') as call_mock:
            ok = ai_mod.set_resource_jit_settings(
                _mock_params(), RESOURCE_UID_STR, bad_settings,
                config_uid=CONFIG_UID_STR, allow_empty=allow_empty,
            )
        assert ok is False
        call_mock.assert_not_called()

    def test_empty_settings_allowed_when_flag_set(self):
        """allow_empty=True lets empty settings reach configure_resource (used for resets)."""
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b''), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=_capture):
            ok = ai_mod.set_resource_jit_settings(
                _mock_params(), RESOURCE_UID_STR, {}, config_uid=CONFIG_UID_STR, allow_empty=True,
            )
        assert ok is True
        assert captured['rq'].jitSettings == b''


# --------------------------------------------------------------------------- #
# Domain-dir migration                                                         #
# --------------------------------------------------------------------------- #


DIR_UID_STR = 'CCCCCCCCCCCCCCCCCCCCCC'  # 22-char base64-urlsafe -> 16 bytes


class TestSetResourceDomainDirMigration:

    def test_happy_path_sends_domain_uid_in_proto(self):
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with _patch_inputs(), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=_capture):
            ok = ai_mod.set_resource_domain_dir(
                _mock_params(), RESOURCE_UID_STR, DIR_UID_STR, config_uid=CONFIG_UID_STR
            )
        assert ok is True
        rq = captured['rq']
        assert isinstance(rq, pam_pb2.PAMResourceConfig)
        assert len(rq.recordUid) == 16
        assert len(rq.networkUid) == 16
        assert len(rq.domainUid) == 16
        # Must NOT leak into unrelated fields
        assert rq.adminUid == b''
        assert rq.jitSettings == b''

    def test_permission_denied_with_fallback_enabled_calls_legacy(self):
        legacy_called = {'count': 0}

        def _legacy(*args, **kwargs):
            legacy_called['count'] += 1
            return True

        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             _patch_inputs(), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err), \
             patch.object(ai_mod, '_set_resource_domain_dir_legacy', side_effect=_legacy):
            ok = ai_mod.set_resource_domain_dir(
                _mock_params(), RESOURCE_UID_STR, DIR_UID_STR, config_uid=CONFIG_UID_STR
            )
        assert ok is True
        assert legacy_called['count'] == 1

    def test_permission_denied_with_fallback_disabled_returns_false(self):
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '0'}), \
             _patch_inputs(), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err), \
             patch.object(ai_mod, '_set_resource_domain_dir_legacy') as legacy_mock:
            ok = ai_mod.set_resource_domain_dir(
                _mock_params(), RESOURCE_UID_STR, DIR_UID_STR, config_uid=CONFIG_UID_STR
            )
        assert ok is False
        legacy_mock.assert_not_called()


# --------------------------------------------------------------------------- #
# TunnelGraph.edit_tunneling_config migration                                  #
# --------------------------------------------------------------------------- #


class TestTunnelGraphEditTunnelingConfigMigration:
    """Verify the migration of TunnelGraph.edit_tunneling_config to
    `configure_network_graph`. The configuration record's allowedSettings
    belong on the network endpoint, not configure_resource — the latter
    bypasses per-feature enforcement checks for RBI / rotation / connections
    that the network endpoint enforces server-side.

    Policy: `configure_network_graph` honors `KEEPER_DAG_LB_FALLBACK` the
    same way `configure_resource` does — strict by default, opt INTO legacy
    fallback by setting the env var.
    """

    @staticmethod
    def _build_tg(monkeypatch=None):
        """Construct a TunnelDAG without going through __init__ (which needs network setup)."""
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG

        tg = TunnelDAG.__new__(TunnelDAG)
        tg.params = MagicMock()
        tg.record = MagicMock()
        tg.record.record_uid = RESOURCE_UID_STR
        tg.linking_dag = MagicMock()
        config_vertex = MagicMock()
        config_vertex.vertex_type = 'PAM_NETWORK'
        config_vertex.get_content = MagicMock(return_value={'allowedSettings': {}})
        tg.linking_dag.get_vertex.return_value = config_vertex
        return tg, config_vertex

    def test_happy_path_sends_allowed_settings_via_network_graph(self):
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, config_vertex = self._build_tg()
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with patch.object(tg_mod, 'get_vertex_content', return_value={'allowedSettings': {}}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph', side_effect=_capture):
            tg.edit_tunneling_config(connections='on', session_recording='off')

        rq = captured.get('rq')
        assert rq is not None, 'router_configure_network_graph was not called'
        assert isinstance(rq, router_pb2.PAMNetworkConfigurationRequest)
        # recordUid is the config record UID (16 bytes from 22-char b64url)
        assert len(rq.recordUid) == 16
        # networkSettings.allowedSettings carries the inner allowed-settings JSON
        allowed_bytes = rq.networkSettings.allowedSettings
        assert allowed_bytes, 'networkSettings.allowedSettings empty'
        as_str = allowed_bytes.decode()
        assert 'connections' in as_str
        assert 'sessionRecording' in as_str
        # No resource/rotation sub-requests on a settings-only call
        assert len(rq.resources) == 0
        assert len(rq.rotations) == 0

    def test_no_changes_skips_configure_network_graph(self):
        """When nothing is dirty, the migration must NOT call configure_network_graph."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, _ = self._build_tg()
        with patch.object(tg_mod, 'get_vertex_content', return_value={'allowedSettings': {}}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph') as cng_mock:
            tg.edit_tunneling_config()  # all args None -> nothing dirty
        cng_mock.assert_not_called()

    def test_permission_denied_with_fallback_enabled_invokes_legacy_save(self):
        """KEEPER_DAG_LB_FALLBACK=1 + RRC denial → legacy DAG-write fires."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, config_vertex = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value={'allowedSettings': {}}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph', side_effect=err):
            tg.edit_tunneling_config(connections='on')
        config_vertex.add_data.assert_called_once()
        tg.linking_dag.save.assert_called_once()

    def test_permission_denied_with_strict_mode_propagates(self):
        """KEEPER_DAG_LB_FALLBACK=0 (default) + RRC denial → propagate, no legacy."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, config_vertex = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '0'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value={'allowedSettings': {}}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph', side_effect=err):
            with pytest.raises(RouterResponseError):
                tg.edit_tunneling_config(connections='on')
        config_vertex.add_data.assert_not_called()
        tg.linking_dag.save.assert_not_called()

    def test_non_permission_error_propagates(self):
        """Transient / generic server errors never trigger downgrade,
        regardless of env value."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, config_vertex = self._build_tg()
        err = RouterResponseError(99, 'RRC_GENERAL_ERROR', 'broken')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value={'allowedSettings': {}}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph', side_effect=err):
            with pytest.raises(RouterResponseError):
                tg.edit_tunneling_config(connections='on')
        config_vertex.add_data.assert_not_called()

    def test_http_404_with_fallback_enabled_caches_and_short_circuits(self):
        """KEEPER_DAG_LB_FALLBACK=1 + HTTP 404 → fall back + mark cache.
        Subsequent calls within TTL skip the new API entirely."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        from keepercommander.commands.pam._layer_b import is_layer_b_feature_disabled
        from keepercommander.error import KeeperApiError

        tg, config_vertex = self._build_tg()
        err = KeeperApiError(404, 'Not Found')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value={'allowedSettings': {}}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph', side_effect=err) as cng_mock:
            tg.edit_tunneling_config(connections='on')
            assert cng_mock.call_count == 1
            assert is_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_network_graph')

            tg.edit_tunneling_config(tunneling='on')
            assert cng_mock.call_count == 1, 'new API should NOT have been hit a second time'
        assert config_vertex.add_data.call_count == 2

    def test_http_404_with_strict_mode_propagates(self):
        """KEEPER_DAG_LB_FALLBACK=0 (default) + HTTP 404 → propagate. No
        legacy write, no cache marking."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        from keepercommander.commands.pam._layer_b import is_layer_b_feature_disabled
        from keepercommander.error import KeeperApiError

        tg, config_vertex = self._build_tg()
        err = KeeperApiError(404, 'Not Found')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '0', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value={'allowedSettings': {}}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph', side_effect=err):
            with pytest.raises(Exception):  # KeeperApiError
                tg.edit_tunneling_config(connections='on')
        config_vertex.add_data.assert_not_called()
        assert is_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_network_graph') is False

    def test_rrc_code_does_not_mark_cache(self):
        """RRC permission codes fall back per-call (when env=1) but do NOT
        mark the cache. Tenant admins can flip features mid-session."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        from keepercommander.commands.pam._layer_b import is_layer_b_feature_disabled

        tg, config_vertex = self._build_tg()
        err = RouterResponseError(9, 'RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED', 'feature off')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value={'allowedSettings': {}}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph', side_effect=err) as cng_mock:
            tg.edit_tunneling_config(connections='on')
            tg.edit_tunneling_config(tunneling='on')
            assert cng_mock.call_count == 2
            assert is_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_network_graph') is False
        assert config_vertex.add_data.call_count == 2


# --------------------------------------------------------------------------- #
# TunnelGraph.link_user_to_resource(is_admin=True) migration                   #
# (The headline credential-linking security target.)                           #
# --------------------------------------------------------------------------- #


USER_UID_STR = 'DDDDDDDDDDDDDDDDDDDDDD'   # 22-char base64-urlsafe -> 16 bytes
TARGET_RES_UID_STR = 'EEEEEEEEEEEEEEEEEEEEEE'


class TestTunnelGraphLinkUserToResourceMigration:
    """Verify TunnelGraph.link_user_to_resource(is_admin=True) -> configure_resource.

    Other flag combinations (belongs_to alone, is_launch_credential without is_admin)
    must stay on the legacy path because PAMResourceConfig doesn't carry those flags
    independently from adminUid.
    """

    @staticmethod
    def _build_tg():
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG

        tg = TunnelDAG.__new__(TunnelDAG)
        tg.params = MagicMock()
        tg.record = MagicMock()
        tg.record.record_uid = CONFIG_UID_STR
        tg.linking_dag = MagicMock()
        # Resource exists in the graph and "belongs to" the config (precondition).
        resource_vertex = MagicMock()
        tg.linking_dag.get_vertex.return_value = resource_vertex
        # Mark the resource as belonging to the config so the early-out doesn't fire.
        tg.resource_belongs_to_config = MagicMock(return_value=True)
        # No existing launch credentials by default (admin-only case).
        tg.get_launch_credentials = MagicMock(return_value=[])
        return tg, resource_vertex

    def test_is_admin_true_routes_to_configure_resource(self):
        """is_admin=True triggers a configure_resource POST with the right adminUid.

        With no existing launch credentials (a valid pamMachine state — admin only),
        connectUsers is sent as an EMPTY-but-present wrapper so krouter still flips
        is_admin on the existing edge (UserRest.kt:295-318) rather than no-opping
        (UserRest.kt:331-341)."""
        tg, _ = self._build_tg()
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with patch('keepercommander.commands.pam.router_helper.router_configure_resource',
                   side_effect=_capture), \
             patch.object(tg, 'link_user') as link_user_mock:
            result = tg.link_user_to_resource(USER_UID_STR, TARGET_RES_UID_STR, is_admin=True)

        assert result is None
        rq = captured.get('rq')
        assert rq is not None, 'router_configure_resource was not called'
        assert isinstance(rq, pam_pb2.PAMResourceConfig)
        # adminUid must be the user being linked
        assert len(rq.adminUid) == 16
        # recordUid is the resource
        assert len(rq.recordUid) == 16
        # networkUid is the config (the TunnelGraph's record)
        assert len(rq.networkUid) == 16
        # connectUsers wrapper must be PRESENT (so krouter takes the flip-on-existing
        # branch) but empty here (no launch creds to preserve).
        assert rq.HasField('connectUsers')
        assert len(rq.connectUsers.uids) == 0
        # Critical: legacy link_user must NOT be called when configure_resource succeeded
        link_user_mock.assert_not_called()

    def test_is_admin_true_preserves_existing_launch_creds_in_connect_users(self):
        """When the resource already has launch credentials, they ride in connectUsers
        so krouter sets is_admin WITHOUT clearing them (replacement semantics)."""
        tg, _ = self._build_tg()
        tg.get_launch_credentials = MagicMock(return_value=[USER_UID_STR.replace('D', 'F')])
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with patch('keepercommander.commands.pam.router_helper.router_configure_resource',
                   side_effect=_capture), \
             patch.object(tg, 'link_user'):
            tg.link_user_to_resource(USER_UID_STR, TARGET_RES_UID_STR, is_admin=True)

        rq = captured['rq']
        assert len(rq.adminUid) == 16
        assert len(rq.connectUsers.uids) == 1            # existing launch cred preserved
        assert len(rq.connectUsers.uids[0]) == 16
        # admin is NOT the launch cred (distinct users)
        assert bytes(rq.adminUid) != bytes(rq.connectUsers.uids[0])

    def test_is_admin_true_with_fallback_invokes_legacy_link_user_on_denial(self):
        """RRC_NOT_ALLOWED with fallback ON -> legacy link_user runs."""
        tg, resource_vertex = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource',
                   side_effect=err), \
             patch.object(tg, 'link_user') as link_user_mock:
            tg.link_user_to_resource(USER_UID_STR, TARGET_RES_UID_STR, is_admin=True, belongs_to=True)
        # Legacy link_user invoked with original args
        link_user_mock.assert_called_once()
        args, kwargs = link_user_mock.call_args
        assert args[0] == USER_UID_STR
        # source_vertex should be the resource_vertex (positional arg 1)
        assert args[1] is resource_vertex

    def test_is_admin_true_strict_mode_raises_no_legacy(self):
        """RRC_NOT_ALLOWED with fallback OFF -> RouterResponseError propagates."""
        tg, _ = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '0'}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource',
                   side_effect=err), \
             patch.object(tg, 'link_user') as link_user_mock:
            with pytest.raises(RouterResponseError):
                tg.link_user_to_resource(USER_UID_STR, TARGET_RES_UID_STR, is_admin=True)
        link_user_mock.assert_not_called()

    def test_is_admin_false_or_none_stays_on_legacy_path(self):
        """When is_admin is not True (None/False), configure_resource must NOT be invoked."""
        tg, _ = self._build_tg()
        with patch('keepercommander.commands.pam.router_helper.router_configure_resource') as cr_mock, \
             patch.object(tg, 'link_user') as link_user_mock:
            tg.link_user_to_resource(USER_UID_STR, TARGET_RES_UID_STR, belongs_to=True)
        cr_mock.assert_not_called()
        link_user_mock.assert_called_once()

    def test_non_permission_error_raises_no_legacy(self):
        """Generic RouterResponseError (not permission-denied) propagates; legacy doesn't run."""
        tg, _ = self._build_tg()
        err = RouterResponseError(99, 'RRC_GENERAL_ERROR', 'broken')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource',
                   side_effect=err), \
             patch.object(tg, 'link_user') as link_user_mock:
            with pytest.raises(RouterResponseError):
                tg.link_user_to_resource(USER_UID_STR, TARGET_RES_UID_STR, is_admin=True)
        link_user_mock.assert_not_called()

    def test_resource_not_in_config_returns_false_early(self):
        """When resource doesn't belong to config, return False without touching configure_resource."""
        tg, _ = self._build_tg()
        tg.resource_belongs_to_config = MagicMock(return_value=False)
        with patch('keepercommander.commands.pam.router_helper.router_configure_resource') as cr_mock, \
             patch.object(tg, 'link_user') as link_user_mock:
            result = tg.link_user_to_resource(USER_UID_STR, TARGET_RES_UID_STR, is_admin=True)
        assert result is False
        cr_mock.assert_not_called()
        link_user_mock.assert_not_called()


class TestTunnelGraphGetLaunchCredentials:
    """get_launch_credentials enumerates is_launch_credential ACL edges on a resource."""

    @staticmethod
    def _make_user_vertex(uid, acl_content):
        uv = MagicMock()
        uv.uid = uid
        edge = MagicMock()
        edge.content_as_dict = acl_content
        uv.get_edge.return_value = edge
        return uv

    def _build_tg(self, user_vertices):
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG
        tg = TunnelDAG.__new__(TunnelDAG)
        tg.linking_dag = MagicMock()
        resource_vertex = MagicMock()
        resource_vertex.has_vertices.return_value = user_vertices
        tg.linking_dag.get_vertex.return_value = resource_vertex
        return tg

    def test_returns_only_launch_credential_users(self):
        uv_launch = self._make_user_vertex('LAUNCH_UID', {'belongs_to': True, 'is_launch_credential': True})
        uv_admin = self._make_user_vertex('ADMIN_UID', {'is_admin': True})
        uv_plain = self._make_user_vertex('PLAIN_UID', {'belongs_to': True})
        tg = self._build_tg([uv_launch, uv_admin, uv_plain])
        assert tg.get_launch_credentials('RES') == ['LAUNCH_UID']

    def test_returns_empty_when_no_resource_vertex(self):
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG
        tg = TunnelDAG.__new__(TunnelDAG)
        tg.linking_dag = MagicMock()
        tg.linking_dag.get_vertex.return_value = None
        assert tg.get_launch_credentials('RES') == []


# --------------------------------------------------------------------------- #
# TunnelGraph is_iam_user migration via set_record_rotation (no fallback)     #
# --------------------------------------------------------------------------- #


class TestTunnelGraphIamUserMigration:
    """is_iam_user link is permission-checked by calling
    set_record_rotation(recordUid=user_uid, noop=False) with NO resourceUid
    and NO saasConfiguration. Server enforces edit-access on the pamUser
    record. NO legacy fallback - errors must propagate so an unauthorized link
    is never written.
    """

    @staticmethod
    def _build_tg():
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG

        tg = TunnelDAG.__new__(TunnelDAG)
        tg.params = MagicMock()
        tg.params.record_rotation_cache = {}
        tg.record = MagicMock()
        tg.record.record_uid = CONFIG_UID_STR
        tg.linking_dag = MagicMock()
        config_vertex = MagicMock()
        tg.linking_dag.get_vertex.return_value = config_vertex
        return tg, config_vertex

    def test_link_user_to_config_calls_set_record_rotation_with_noop(self):
        """link_user_to_config() permission-checks via set_record_rotation BEFORE
        the legacy DAG write."""
        tg, _ = self._build_tg()
        captured = {}

        def _capture(params, rq, *args, **kwargs):
            captured['rq'] = rq

        with patch('keepercommander.commands.pam.router_helper.router_set_record_rotation_information',
                   side_effect=_capture), \
             patch.object(tg, 'link_user') as link_user_mock:
            tg.link_user_to_config(USER_UID_STR)

        rq = captured.get('rq')
        assert rq is not None, 'router_set_record_rotation_information was not called'
        assert isinstance(rq, router_pb2.RouterRecordRotationRequest)
        # recordUid is the pamUser record (the target of the permission check)
        assert len(rq.recordUid) == 16
        assert rq.configurationUid == url_safe_str_to_bytes(CONFIG_UID_STR)
        # noop=False is what triggers the is_iam_user write server-side
        assert rq.noop is False
        # NO resourceUid, NO saasConfiguration — these would change the semantics
        assert rq.resourceUid == b''
        assert rq.saasConfiguration == b''
        # After permission check succeeds, the legacy link_user mutation still runs
        link_user_mock.assert_called_once()

    def test_link_user_to_config_passes_revision_from_rotation_cache(self):
        """When pamUser already has rotation metadata, KeeperApp requires matching revision."""
        tg, _ = self._build_tg()
        tg.params.record_rotation_cache = {
            USER_UID_STR: {'revision': 3, 'configuration_uid': CONFIG_UID_STR},
        }
        captured = {}

        def _capture(params, rq, *args, **kwargs):
            captured['rq'] = rq

        with patch('keepercommander.commands.pam.router_helper.router_set_record_rotation_information',
                   side_effect=_capture), \
             patch.object(tg, 'link_user'):
            tg.link_user_to_config(USER_UID_STR)

        rq = captured.get('rq')
        assert rq is not None
        assert rq.revision == 3
        assert rq.resourceUid == b''

    def test_link_user_to_config_clears_stale_resource_uid_from_rotation_cache(self):
        """IAM permission-check must not send cached resource_uid (non-IAM semantics)."""
        tg, _ = self._build_tg()
        tg.params.record_rotation_cache = {
            USER_UID_STR: {
                'revision': 2,
                'configuration_uid': CONFIG_UID_STR,
                'resource_uid': 'AAAAAAAAAAAAAAAAAAAAAA',
            },
        }
        captured = {}

        def _capture(params, rq, *args, **kwargs):
            captured['rq'] = rq

        with patch('keepercommander.commands.pam.router_helper.router_set_record_rotation_information',
                   side_effect=_capture), \
             patch.object(tg, 'link_user'):
            tg.link_user_to_config(USER_UID_STR)

        rq = captured.get('rq')
        assert rq is not None
        assert rq.revision == 2
        assert rq.resourceUid == b''

    def test_link_user_to_config_no_fallback_on_permission_denial(self):
        """If set_record_rotation fails (permission denied), DO NOT fall back to
        the legacy DAG write - propagate so the unauthorized link is never
        written. Don't need legacy for iam_user."""
        tg, _ = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        # Even with KEEPER_DAG_LB_FALLBACK=1, the iam_user path does not consult it.
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             patch('keepercommander.commands.pam.router_helper.router_set_record_rotation_information',
                   side_effect=err), \
             patch.object(tg, 'link_user') as link_user_mock:
            with pytest.raises(RouterResponseError):
                tg.link_user_to_config(USER_UID_STR)
        # Critical: legacy link_user did NOT run
        link_user_mock.assert_not_called()

    def test_link_user_to_config_with_options_iam_user_true_permission_checks(self):
        """link_user_to_config_with_options(is_iam_user=True) routes through
        set_record_rotation BEFORE the local ACL mutation. is_admin and
        belongs_to combinations don't disable the iam_user permission check."""
        tg, config_vertex = self._build_tg()
        # User vertex stub
        user_vertex = MagicMock()
        user_vertex.vertex_type = None  # forces the vertex_type set path
        # First call: config_vertex (record_uid). Second call: user_vertex.
        tg.linking_dag.get_vertex.side_effect = [config_vertex, user_vertex]
        config_vertex.has.return_value = False  # no existing ACL -> bare write
        captured = {}

        def _capture(params, rq, *args, **kwargs):
            captured['rq'] = rq

        with patch('keepercommander.commands.pam.router_helper.router_set_record_rotation_information',
                   side_effect=_capture):
            tg.link_user_to_config_with_options(USER_UID_STR, is_iam_user=True, belongs_to=True)

        rq = captured.get('rq')
        assert rq is not None
        assert isinstance(rq, router_pb2.RouterRecordRotationRequest)
        assert rq.configurationUid == url_safe_str_to_bytes(CONFIG_UID_STR)
        assert rq.resourceUid == b''
        assert rq.noop is False

    def test_link_user_to_config_with_options_iam_user_not_true_skips_set_rotation(self):
        """When is_iam_user is None/False, set_record_rotation must NOT be called.
        Only is_iam_user=True triggers the permission check."""
        tg, config_vertex = self._build_tg()
        user_vertex = MagicMock()
        user_vertex.vertex_type = None
        tg.linking_dag.get_vertex.side_effect = [config_vertex, user_vertex]
        config_vertex.has.return_value = False

        with patch('keepercommander.commands.pam.router_helper.router_set_record_rotation_information') as srr_mock:
            # belongs_to=True alone, no iam_user
            tg.link_user_to_config_with_options(USER_UID_STR, belongs_to=True)
        srr_mock.assert_not_called()


# --------------------------------------------------------------------------- #
# Layer-B feature-disabled cache: end-to-end behavior at the call sites       #
# --------------------------------------------------------------------------- #


class TestLayerBFeatureDisabledCache:
    """End-to-end behavior of the (host, endpoint) cache at Layer-B call sites.

    Policy: ONLY HTTP 404 marks the cache. RRC permission codes (per-user OR
    tenant-level) fall back per-call but never mark the cache, because tenant
    admins can flip features mid-session and per-user denials depend on caller
    context.
    """

    def test_rrc_codes_never_mark_cache(self):
        """Neither RRC_NOT_ALLOWED nor RRC_NOT_ALLOWED_*_NOT_ENABLED marks the
        cache — they all fall back per-call when fallback is on, and propagate
        when fallback is off, but never poison the cache."""
        from keepercommander.commands.pam._layer_b import is_layer_b_feature_disabled

        for code in ('RRC_NOT_ALLOWED',
                     'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED',
                     'RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED'):
            err = RouterResponseError(13, code, 'denied')
            with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}), \
                 _patch_inputs(), \
                 patch.object(ai_mod, 'encrypt_aes', return_value=b'CIPHER'), \
                 patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err), \
                 patch.object(ai_mod, '_set_resource_keeper_ai_settings_legacy', return_value=True):
                ai_mod.set_resource_keeper_ai_settings(
                    _mock_params(), RESOURCE_UID_STR, {'level': 'high'}, config_uid=CONFIG_UID_STR
                )
            assert not is_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_resource'), \
                f'{code} should NOT mark the cache'
            clear_layer_b_feature_cache()

    def test_http_404_marks_cache_and_short_circuits(self):
        """HTTP 404 (endpoint not deployed) marks the cache; subsequent calls
        skip the new API entirely. Requires KEEPER_DAG_LB_FALLBACK=1 for
        configure_resource (mature endpoint — strict by default)."""
        from keepercommander.commands.pam._layer_b import is_layer_b_feature_disabled
        from keepercommander.error import KeeperApiError

        err = KeeperApiError(404, 'Not Found')
        legacy_calls = {'count': 0}

        def _legacy(*args, **kwargs):
            legacy_calls['count'] += 1
            return True

        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}), \
             _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'CIPHER'), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err) as cr_mock, \
             patch.object(ai_mod, '_set_resource_keeper_ai_settings_legacy', side_effect=_legacy):
            # First call: hits new API, gets 404, falls back, marks cache.
            ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'high'}, config_uid=CONFIG_UID_STR
            )
            assert cr_mock.call_count == 1
            assert is_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_resource')

            # Second call within TTL: cache hit, skip new API entirely.
            ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'critical'}, config_uid=CONFIG_UID_STR
            )
            assert cr_mock.call_count == 1, 'new API should NOT have been hit a second time'
        assert legacy_calls['count'] == 2, 'legacy path should run both times'

    def test_strict_mode_no_fallback_on_rrc(self):
        """With KEEPER_DAG_LB_FALLBACK unset (strict default), RRC denials on
        mature endpoints propagate (return False) — no legacy fallback. This
        is the security-relevant default."""
        env_without = {k: v for k, v in os.environ.items() if k != 'KEEPER_DAG_LB_FALLBACK'}
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        with patch.dict(os.environ, env_without, clear=True), \
             _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'CIPHER'), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err), \
             patch.object(ai_mod, '_set_resource_keeper_ai_settings_legacy') as legacy_mock:
            ok = ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'high'}, config_uid=CONFIG_UID_STR
            )
        assert ok is False
        legacy_mock.assert_not_called()

    def test_cache_ttl_zero_disables_caching(self):
        """KEEPER_DAG_LB_FEATURE_CACHE_TTL=0 disables the cache entirely; every
        call hits the new API even after a tenant-level denial."""
        err = RouterResponseError(9, 'RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED', 'pam off')

        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '0'}), \
             _patch_inputs(), \
             patch.object(ai_mod, 'encrypt_aes', return_value=b'CIPHER'), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err) as cr_mock, \
             patch.object(ai_mod, '_set_resource_keeper_ai_settings_legacy', return_value=True):
            ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'a'}, config_uid=CONFIG_UID_STR
            )
            ai_mod.set_resource_keeper_ai_settings(
                _mock_params(), RESOURCE_UID_STR, {'level': 'b'}, config_uid=CONFIG_UID_STR
            )
            # With cache disabled, BOTH calls hit the new API.
            assert cr_mock.call_count == 2


# --------------------------------------------------------------------------- #
# TunnelGraph.set_resource_allowed migration (Phase 2d)                       #
# --------------------------------------------------------------------------- #


class TestTunnelGraphSetResourceAllowedMigration:
    """`set_resource_allowed` writes a record's `meta` JSON (allowedSettings +
    optional rotateOnTermination/version) for either a resource (is_config=False)
    or the PAM Configuration record itself (is_config=True). Migrated to:
      - is_config=False -> configure_resource(meta=...)
      - is_config=True  -> configure_network_graph(networkSettings.allowedSettings=...)
    Same fallback policy as edit_tunneling_config: strict by default; env=1
    opts INTO legacy fallback.
    """

    @staticmethod
    def _build_tg():
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG

        tg = TunnelDAG.__new__(TunnelDAG)
        tg.params = MagicMock()
        tg.record = MagicMock()
        # self.record.record_uid is the CONFIG UID per TunnelDAG.__init__.
        tg.record.record_uid = CONFIG_UID_STR
        tg.linking_dag = MagicMock()
        resource_vertex = MagicMock()
        # Start with no existing content so `dirty` becomes True for any setting.
        resource_vertex.vertex_type = 'PAM_MACHINE'
        tg.linking_dag.get_vertex.return_value = resource_vertex
        return tg, resource_vertex

    def test_resource_happy_path_uses_configure_resource(self):
        """is_config=False with a setting flips -> configure_resource(meta=...)
        carrying the full meta JSON. recordUid is the resource, networkUid is
        the config."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, _ = self._build_tg()
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=_capture):
            tg.set_resource_allowed(RESOURCE_UID_STR, connections='on', rotation='on')

        rq = captured.get('rq')
        assert rq is not None, 'router_configure_resource was not called'
        assert isinstance(rq, pam_pb2.PAMResourceConfig)
        # recordUid is the resource, networkUid is the config
        assert len(rq.recordUid) == 16
        assert len(rq.networkUid) == 16
        assert rq.recordUid != rq.networkUid
        # meta carries the full JSON shape that legacy would write
        meta_str = rq.meta.decode()
        assert 'allowedSettings' in meta_str
        assert 'connections' in meta_str
        assert 'rotation' in meta_str

    def test_config_happy_path_uses_configure_network_graph(self):
        """is_config=True flips the call to configure_network_graph with the
        inner allowedSettings dict (matches edit_tunneling_config's shape)."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, _ = self._build_tg()
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph', side_effect=_capture):
            tg.set_resource_allowed(CONFIG_UID_STR, is_config=True,
                                    connections='on', rotation='on', remote_browser_isolation='on')

        rq = captured.get('rq')
        assert rq is not None, 'router_configure_network_graph was not called'
        assert isinstance(rq, router_pb2.PAMNetworkConfigurationRequest)
        # recordUid is the config record
        assert len(rq.recordUid) == 16
        # networkSettings.allowedSettings carries the INNER allowed-settings dict
        as_str = rq.networkSettings.allowedSettings.decode()
        assert 'connections' in as_str
        assert 'rotation' in as_str
        assert 'remoteBrowserIsolation' in as_str
        # No resource/rotation sub-lists on a settings-only call
        assert len(rq.resources) == 0
        assert len(rq.rotations) == 0

    def test_no_changes_skips_both_endpoints(self):
        """When nothing flips (all args None), neither endpoint is called."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, resource_vertex = self._build_tg()
        existing = {'allowedSettings': {'connections': True}}
        with patch.object(tg_mod, 'get_vertex_content', return_value=existing), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource') as cr_mock, \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph') as cng_mock:
            tg.set_resource_allowed(RESOURCE_UID_STR)  # all flags None
        cr_mock.assert_not_called()
        cng_mock.assert_not_called()
        resource_vertex.add_data.assert_not_called()

    def test_resource_permission_denied_with_fallback_invokes_legacy(self):
        """env=1 + RRC denial on configure_resource -> legacy add_data + save runs."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, resource_vertex = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err):
            tg.set_resource_allowed(RESOURCE_UID_STR, connections='on')
        resource_vertex.add_data.assert_called_once()
        tg.linking_dag.save.assert_called_once()

    def test_resource_strict_mode_propagates(self):
        """env unset (strict) + RRC denial -> propagate, no legacy write."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        env_without = {k: v for k, v in os.environ.items() if k != 'KEEPER_DAG_LB_FALLBACK'}
        tg, resource_vertex = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        with patch.dict(os.environ, env_without, clear=True), \
             patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err):
            with pytest.raises(RouterResponseError):
                tg.set_resource_allowed(RESOURCE_UID_STR, connections='on')
        resource_vertex.add_data.assert_not_called()
        tg.linking_dag.save.assert_not_called()

    def test_config_permission_denied_with_fallback_invokes_legacy(self):
        """is_config=True + env=1 + RRC denial on configure_network_graph
        -> legacy add_data + save runs (same shape as edit_tunneling_config)."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, resource_vertex = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_network_graph', side_effect=err):
            tg.set_resource_allowed(CONFIG_UID_STR, is_config=True, rotation='on')
        resource_vertex.add_data.assert_called_once()
        tg.linking_dag.save.assert_called_once()

    def test_meta_version_v1_payload_shape(self):
        """meta_version=1 sends the versioned meta payload (version + allowedSettings
        + rotateOnTermination) instead of the bare dict."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import RESOURCE_META_VERSION_V1

        tg, _ = self._build_tg()
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=_capture):
            tg.set_resource_allowed(RESOURCE_UID_STR, connections='on',
                                    meta_version=RESOURCE_META_VERSION_V1,
                                    rotate_on_termination=True)

        rq = captured.get('rq')
        assert rq is not None
        meta = json.loads(rq.meta.decode())
        assert meta.get('version') == RESOURCE_META_VERSION_V1
        assert meta.get('rotateOnTermination') is True
        assert meta.get('allowedSettings', {}).get('connections') is True

    def test_pam_remote_browser_settings_uses_resource_endpoint(self):
        """When called with a non-standard allowed_settings_name (RBI case),
        the migration still uses configure_resource(meta=...) — server's
        mergeJson handles the custom meta key. The full meta JSON carries
        the custom key, not 'allowedSettings'."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, _ = self._build_tg()
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=_capture):
            tg.set_resource_allowed(RESOURCE_UID_STR,
                                    remote_browser_isolation='on',
                                    allowed_settings_name='pamRemoteBrowserSettings')

        rq = captured.get('rq')
        assert rq is not None
        meta = json.loads(rq.meta.decode())
        # Custom key, NOT 'allowedSettings'
        assert 'pamRemoteBrowserSettings' in meta
        assert meta['pamRemoteBrowserSettings'].get('remoteBrowserIsolation') is True
        assert 'allowedSettings' not in meta

    def test_http_404_falls_back_and_caches(self):
        """env=1 + HTTP 404 on configure_resource -> fall back to legacy + mark
        cache. Subsequent calls within TTL skip the new API."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        from keepercommander.commands.pam._layer_b import is_layer_b_feature_disabled
        from keepercommander.error import KeeperApiError

        tg, resource_vertex = self._build_tg()
        err = KeeperApiError(404, 'Not Found')
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err) as cr_mock:
            tg.set_resource_allowed(RESOURCE_UID_STR, connections='on')
            assert cr_mock.call_count == 1
            assert is_layer_b_feature_disabled(TEST_ROUTER_URL, 'configure_resource')
            # Second call: cache short-circuits, new API NOT hit.
            tg.set_resource_allowed(RESOURCE_UID_STR, tunneling='on')
            assert cr_mock.call_count == 1
        assert resource_vertex.add_data.call_count == 2


# --------------------------------------------------------------------------- #
# TunnelGraph.upgrade_resource_meta_to_v1 migration (Phase 2e)                #
# --------------------------------------------------------------------------- #


class TestTunnelGraphUpgradeResourceMetaToV1Migration:
    """`upgrade_resource_meta_to_v1` writes a versioned resource meta payload
    {version: 1, allowedSettings: {...}, rotateOnTermination: bool} so the
    Vault reads ACL launch credentials. Migrated to configure_resource(meta=...)
    -- same shape as set_resource_allowed(meta_version=1). Server's mergeJson
    honors the version field with `oldMetaVersion <= newMetaVersion` upgrade
    check (UserRest.kt configureResourceGraph).
    """

    @staticmethod
    def _build_tg(existing_content=None):
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG

        tg = TunnelDAG.__new__(TunnelDAG)
        tg.params = MagicMock()
        tg.record = MagicMock()
        tg.record.record_uid = CONFIG_UID_STR
        tg.linking_dag = MagicMock()
        resource_vertex = MagicMock()
        tg.linking_dag.get_vertex.return_value = resource_vertex
        return tg, resource_vertex

    def test_already_v1_skips_both_endpoints(self):
        """If the existing meta already has version >= 1, the upgrade is a no-op."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import RESOURCE_META_VERSION_V1

        tg, resource_vertex = self._build_tg()
        existing = {'version': RESOURCE_META_VERSION_V1, 'allowedSettings': {}}
        with patch.object(tg_mod, 'get_vertex_content', return_value=existing), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource') as cr_mock:
            tg.upgrade_resource_meta_to_v1(RESOURCE_UID_STR)
        cr_mock.assert_not_called()
        resource_vertex.add_data.assert_not_called()

    def test_v0_upgrade_uses_configure_resource(self):
        """No version or version=0 -> upgrade to v1 via configure_resource(meta=...).
        The proto's meta carries a VERSION-ONLY payload (empty allowedSettings)."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import RESOURCE_META_VERSION_V1

        tg, _ = self._build_tg()
        existing = {'allowedSettings': {'connections': True}}  # no version
        captured = {}

        def _capture(params, rq):
            captured['rq'] = rq

        with patch.object(tg_mod, 'get_vertex_content', return_value=existing), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=_capture):
            tg.upgrade_resource_meta_to_v1(RESOURCE_UID_STR)

        rq = captured.get('rq')
        assert rq is not None, 'router_configure_resource was not called'
        assert isinstance(rq, pam_pb2.PAMResourceConfig)
        # recordUid is the resource, networkUid is the config
        assert len(rq.recordUid) == 16
        assert len(rq.networkUid) == 16
        assert rq.recordUid != rq.networkUid
        # meta bumps version only; allowedSettings is sent EMPTY so krouter's
        # deep-merge preserves the server's existing flags (connections stays True)
        # rather than re-asserting a possibly-stale in-memory snapshot.
        meta = json.loads(rq.meta.decode())
        assert meta.get('version') == RESOURCE_META_VERSION_V1
        assert meta['allowedSettings'] == {}

    def test_no_resource_vertex_returns_early(self):
        """If get_vertex returns None, no write at all."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, _ = self._build_tg()
        tg.linking_dag.get_vertex.return_value = None
        with patch.object(tg_mod, 'get_vertex_content', return_value=None), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource') as cr_mock:
            tg.upgrade_resource_meta_to_v1(RESOURCE_UID_STR)
        cr_mock.assert_not_called()

    def test_permission_denied_with_fallback_invokes_legacy(self):
        """env=1 + RRC denial -> legacy add_data + save runs."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        tg, resource_vertex = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED', 'denied')
        existing = {'allowedSettings': {}}
        with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}), \
             patch.object(tg_mod, 'get_vertex_content', return_value=existing), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err):
            tg.upgrade_resource_meta_to_v1(RESOURCE_UID_STR)
        resource_vertex.add_data.assert_called_once()
        tg.linking_dag.save.assert_called_once()

    def test_strict_mode_propagates(self):
        """env unset (strict) + RRC denial -> propagate, no legacy."""
        from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg_mod

        env_without = {k: v for k, v in os.environ.items() if k != 'KEEPER_DAG_LB_FALLBACK'}
        tg, resource_vertex = self._build_tg()
        err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
        existing = {'allowedSettings': {}}
        with patch.dict(os.environ, env_without, clear=True), \
             patch.object(tg_mod, 'get_vertex_content', return_value=existing), \
             patch('keepercommander.commands.pam.router_helper.router_configure_resource', side_effect=err):
            with pytest.raises(RouterResponseError):
                tg.upgrade_resource_meta_to_v1(RESOURCE_UID_STR)
        resource_vertex.add_data.assert_not_called()
