"""
Tests for ``TunnelDAG.set_launch_credentials`` — the unified Layer-B path that
collapses (clear + link + meta-upgrade) into a single permission-checked
configure_resource call.

Behavior matrix:

| Case                              | configure_resource sent? | connectUsers.uids       | meta has version=1? | local link_user(belongs_to=True) follow-up? |
| --------------------------------- | ------------------------ | ----------------------- | ------------------- | ------------------------------------------- |
| set, Layer-B enabled, success     | yes                      | [launch_uid bytes]      | yes                 | yes (preserve legacy parity)                |
| clear, Layer-B enabled, success   | yes                      | []                      | yes                 | no (no launch user to mark)                 |
| set, Layer-B feature-disabled     | no                       | n/a                     | n/a                 | legacy fallback (link+clear+meta)           |
| set, Layer-B RRC_NOT_ALLOWED + FB | yes (then fall back)     | n/a                     | n/a                 | legacy fallback                             |
| set, RRC_NOT_ALLOWED + FB off     | yes (raises)             | n/a                     | n/a                 | none — exception propagates                 |
"""
import importlib
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))

# Pre-warm the circular-import chain (same pattern as other Layer-B tests).
importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')

from keepercommander.commands.tunnel.port_forward.TunnelGraph import (  # noqa: E402
    TunnelDAG, RESOURCE_META_VERSION_V1,
)
from keepercommander.commands.pam._layer_b import RouterResponseError  # noqa: E402


RESOURCE_UID = 'AAAAAAAAAAAAAAAAAAAAAA'   # 22-char base64url, decodes to 16 bytes
NETWORK_UID  = 'BBBBBBBBBBBBBBBBBBBBBB'
LAUNCH_UID   = 'CCCCCCCCCCCCCCCCCCCCCC'


# --------------------------------------------------------------------------- #
# Test fixture: build a minimal TunnelDAG-shaped object without going through  #
# the full constructor (which requires a live KeeperParams + DAG connection). #
# --------------------------------------------------------------------------- #


def _make_tdag(initial_meta=None):
    """
    Construct a TunnelDAG-shaped object directly (bypassing __init__) and
    populate just the attributes that `set_launch_credentials` touches.

    `initial_meta` is the current `meta` content the resource vertex returns
    via `get_vertex_content`. None means a brand-new (version-0) resource.
    """
    tdag = TunnelDAG.__new__(TunnelDAG)
    tdag.params = MagicMock()
    tdag.params.config = {'server': 'krouter.test'}
    tdag.record = MagicMock()
    tdag.record.record_uid = NETWORK_UID

    # Resource vertex mock: get_vertex_content returns initial_meta.
    resource_vertex = MagicMock()
    resource_vertex.content_as_dict = initial_meta

    # linking_dag.get_vertex(uid) -> resource_vertex
    tdag.linking_dag = MagicMock()
    tdag.linking_dag.get_vertex.return_value = resource_vertex

    # Spy/track link_user follow-up calls so the SET success path is observable.
    tdag.link_user = MagicMock()
    # Spy/track legacy fallback methods.
    tdag.clear_launch_credential_for_resource = MagicMock()
    tdag.link_user_to_resource = MagicMock()
    tdag.upgrade_resource_meta_to_v1 = MagicMock()
    return tdag, resource_vertex


# --------------------------------------------------------------------------- #
# Layer-B happy paths                                                          #
# --------------------------------------------------------------------------- #


def test_set_path_builds_proto_with_launch_uid_and_meta_v1():
    """SET path: connectUsers.uids has the launch_uid; meta has version=1."""
    tdag, _ = _make_tdag(initial_meta=None)

    captured = {}

    def _capture(params, rq):
        captured['rq'] = rq
        return None

    with patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=False), \
         patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='krouter.test'), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource',
               side_effect=_capture):
        tdag.set_launch_credentials(RESOURCE_UID, launch_uid=LAUNCH_UID)

    rq = captured['rq']
    assert len(rq.recordUid) == 16
    assert len(rq.networkUid) == 16
    assert list(rq.connectUsers.uids) == [bytes(rq.connectUsers.uids[0])]
    assert len(rq.connectUsers.uids) == 1
    assert len(rq.connectUsers.uids[0]) == 16  # decoded launch_uid
    meta = json.loads(rq.meta.decode())
    assert meta['version'] == RESOURCE_META_VERSION_V1
    # belongs_to=True follow-up fires only for SET path.
    tdag.link_user.assert_called_once()
    args, kwargs = tdag.link_user.call_args
    assert args[0] == LAUNCH_UID
    assert kwargs.get('belongs_to') is True
    # No legacy fallback paths invoked.
    tdag.clear_launch_credential_for_resource.assert_not_called()
    tdag.link_user_to_resource.assert_not_called()
    tdag.upgrade_resource_meta_to_v1.assert_not_called()


def test_clear_path_builds_proto_with_empty_uids():
    """CLEAR path: connectUsers wrapper is set but uids is empty; meta upgraded."""
    tdag, _ = _make_tdag(initial_meta={'allowedSettings': {'connections': True}})

    captured = {}

    def _capture(params, rq):
        captured['rq'] = rq
        return None

    with patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=False), \
         patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='krouter.test'), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource',
               side_effect=_capture):
        tdag.set_launch_credentials(RESOURCE_UID, launch_uid=None)

    rq = captured['rq']
    # Wrapper present (hasConnectUsers()==true server-side), uids list empty.
    assert len(rq.connectUsers.uids) == 0
    meta = json.loads(rq.meta.decode())
    assert meta['version'] == RESOURCE_META_VERSION_V1
    assert meta['allowedSettings'] == {'connections': True}
    # CLEAR path doesn't do a belongs_to follow-up.
    tdag.link_user.assert_not_called()


def test_set_path_preserves_existing_meta_fields():
    """The meta-upgrade carries existing allowedSettings / rotateOnTermination."""
    initial = {
        'version': 0,
        'allowedSettings': {'connections': True, 'rotation': False},
        'rotateOnTermination': True,
    }
    tdag, _ = _make_tdag(initial_meta=initial)

    captured = {}

    def _capture(params, rq):
        captured['rq'] = rq

    with patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=False), \
         patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='krouter.test'), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource',
               side_effect=_capture):
        tdag.set_launch_credentials(RESOURCE_UID, launch_uid=LAUNCH_UID)

    meta = json.loads(captured['rq'].meta.decode())
    assert meta['version'] == RESOURCE_META_VERSION_V1
    assert meta['allowedSettings'] == {'connections': True, 'rotation': False}
    assert meta['rotateOnTermination'] is True


# --------------------------------------------------------------------------- #
# Feature-disabled fallback (no Layer-B attempt at all)                        #
# --------------------------------------------------------------------------- #


def test_set_path_feature_disabled_uses_legacy_sequence():
    """When Layer-B is feature-disabled, fall straight through to legacy 3-op path."""
    tdag, _ = _make_tdag(initial_meta=None)

    with patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=True), \
         patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='krouter.test'), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource') as mock_cr:
        tdag.set_launch_credentials(RESOURCE_UID, launch_uid=LAUNCH_UID)
        mock_cr.assert_not_called()

    tdag.clear_launch_credential_for_resource.assert_called_once_with(
        RESOURCE_UID, exclude_user_uid=LAUNCH_UID,
    )
    tdag.link_user_to_resource.assert_called_once()
    args, kwargs = tdag.link_user_to_resource.call_args
    assert args[0] == LAUNCH_UID
    assert kwargs.get('is_launch_credential') is True
    assert kwargs.get('belongs_to') is True
    tdag.upgrade_resource_meta_to_v1.assert_called_once_with(RESOURCE_UID)


def test_clear_path_feature_disabled_uses_legacy_sequence():
    """CLEAR path under feature-disabled: clear (no exclusion) + meta upgrade, no link."""
    tdag, _ = _make_tdag(initial_meta=None)

    with patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=True), \
         patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='krouter.test'), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource') as mock_cr:
        tdag.set_launch_credentials(RESOURCE_UID, launch_uid=None)
        mock_cr.assert_not_called()

    tdag.clear_launch_credential_for_resource.assert_called_once_with(
        RESOURCE_UID, exclude_user_uid=None,
    )
    tdag.link_user_to_resource.assert_not_called()
    tdag.upgrade_resource_meta_to_v1.assert_called_once_with(RESOURCE_UID)


# --------------------------------------------------------------------------- #
# RRC_NOT_ALLOWED fallback behavior                                            #
# --------------------------------------------------------------------------- #


def test_set_path_rrc_not_allowed_falls_back_when_env_enabled():
    """On RRC_NOT_ALLOWED with KEEPER_DAG_LB_FALLBACK on, fall through to legacy."""
    tdag, _ = _make_tdag(initial_meta=None)

    err = RouterResponseError(403, 'RRC_NOT_ALLOWED', 'denied')

    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': 'true'}), \
         patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=False), \
         patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='krouter.test'), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource',
               side_effect=err):
        tdag.set_launch_credentials(RESOURCE_UID, launch_uid=LAUNCH_UID)

    tdag.clear_launch_credential_for_resource.assert_called_once()
    tdag.link_user_to_resource.assert_called_once()
    tdag.upgrade_resource_meta_to_v1.assert_called_once()
    # Success path's belongs_to=True follow-up was NOT taken (we never reached it).
    tdag.link_user.assert_not_called()


def test_set_path_rrc_not_allowed_raises_when_env_disabled():
    """On RRC_NOT_ALLOWED with fallback OFF, the exception propagates (strict mode)."""
    tdag, _ = _make_tdag(initial_meta=None)

    err = RouterResponseError(403, 'RRC_NOT_ALLOWED', 'denied')

    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': 'false'}), \
         patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=False), \
         patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='krouter.test'), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource',
               side_effect=err):
        with pytest.raises(RouterResponseError):
            tdag.set_launch_credentials(RESOURCE_UID, launch_uid=LAUNCH_UID)

    # No fallback or follow-up writes.
    tdag.clear_launch_credential_for_resource.assert_not_called()
    tdag.link_user_to_resource.assert_not_called()
    tdag.upgrade_resource_meta_to_v1.assert_not_called()
    tdag.link_user.assert_not_called()


# --------------------------------------------------------------------------- #
# Edge cases                                                                   #
# --------------------------------------------------------------------------- #


def test_missing_resource_vertex_is_no_op():
    """If the resource vertex doesn't exist locally, set_launch_credentials returns silently."""
    tdag, _ = _make_tdag(initial_meta=None)
    tdag.linking_dag.get_vertex.return_value = None

    with patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=False), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource') as mock_cr:
        tdag.set_launch_credentials(RESOURCE_UID, launch_uid=LAUNCH_UID)
        mock_cr.assert_not_called()

    tdag.link_user.assert_not_called()
    tdag.clear_launch_credential_for_resource.assert_not_called()
    tdag.upgrade_resource_meta_to_v1.assert_not_called()
