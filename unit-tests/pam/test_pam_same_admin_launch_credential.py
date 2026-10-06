"""
Regression test: `pam project extend` / `pam project import` lose the
Administrative Credential when admin and launch are the SAME pamUser.

Mechanism: extend/import's TunnelDAG is loaded once and goes stale after the
admin is written via krouter (configure_resource). The final launch link then
goes down the legacy link_user() path, finds no local ACL edge, and writes a
fresh edge containing only {belongs_to, is_launch_credential} -- no is_admin --
which replaces the edge krouter just wrote.

Fix: use TunnelDAG.set_launch_credentials(..., admin_uid=...), whose follow-up
local write carries is_admin when admin == launch.
"""
import importlib
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))
importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')

from keepercommander.commands.tunnel.port_forward.TunnelGraph import TunnelDAG  # noqa: E402

RESOURCE_UID = 'AAAAAAAAAAAAAAAAAAAAAA'
NETWORK_UID = 'BBBBBBBBBBBBBBBBBBBBBB'
SHARED_USER_UID = 'CCCCCCCCCCCCCCCCCCCCCC'   # same pamUser for admin + launch


def _make_stale_tdag():
    """TunnelDAG whose in-memory graph has the resource vertex but NO ACL edge
    from the user to the resource (i.e. stale after krouter wrote the admin)."""
    tdag = TunnelDAG.__new__(TunnelDAG)
    tdag.params = MagicMock()
    tdag.record = MagicMock()
    tdag.record.record_uid = NETWORK_UID

    resource_vertex = MagicMock(name='resource_vertex')
    resource_vertex.has.return_value = False          # stale: no local ACL edge
    user_vertex = MagicMock(name='user_vertex')

    def _get_vertex(uid):
        return {RESOURCE_UID: resource_vertex, SHARED_USER_UID: user_vertex}.get(uid)

    tdag.linking_dag = MagicMock()
    tdag.linking_dag.get_vertex.side_effect = _get_vertex
    tdag.resource_belongs_to_config = MagicMock(return_value=True)
    return tdag, resource_vertex, user_vertex


def _written_acl_content(user_vertex):
    user_vertex.belongs_to.assert_called_once()
    return user_vertex.belongs_to.call_args.kwargs['content']


def test_extend_launch_link_drops_is_admin_on_stale_graph():
    """Documents the bug: link_user_to_resource on a stale graph drops is_admin."""
    tdag, _, user_vertex = _make_stale_tdag()
    tdag.link_user_to_resource(SHARED_USER_UID, RESOURCE_UID,
                               is_launch_credential=True, belongs_to=True)
    content = _written_acl_content(user_vertex)
    assert content == {'belongs_to': True, 'is_launch_credential': True}
    assert 'is_admin' not in content
    tdag.linking_dag.save.assert_called_once()


def test_set_launch_credentials_keeps_is_admin_on_stale_graph():
    """Fix: same stale graph, admin == launch -> is_admin preserved."""
    tdag, _, user_vertex = _make_stale_tdag()
    captured = {}
    with patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=False), \
         patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='krouter.test'), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource',
               side_effect=lambda p, rq: captured.setdefault('rq', rq)):
        tdag.set_launch_credentials(RESOURCE_UID, launch_uid=SHARED_USER_UID, admin_uid=SHARED_USER_UID)

    rq = captured['rq']
    assert len(rq.connectUsers.uids) == 1
    assert bytes(rq.adminUid) == bytes(rq.connectUsers.uids[0])   # admin + launch in ONE request
    content = _written_acl_content(user_vertex)
    assert content == {'belongs_to': True, 'is_launch_credential': True, 'is_admin': True}


def test_set_launch_credentials_without_admin_leaves_admin_unset():
    """`admin_uid or None` guard: no admin -> no adminUid sent, no is_admin written."""
    tdag, _, user_vertex = _make_stale_tdag()
    captured = {}
    with patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=False), \
         patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='krouter.test'), \
         patch('keepercommander.commands.pam.router_helper.router_configure_resource',
               side_effect=lambda p, rq: captured.setdefault('rq', rq)):
        tdag.set_launch_credentials(RESOURCE_UID, launch_uid=SHARED_USER_UID, admin_uid=("" or None))
    assert not captured['rq'].HasField('adminUid')
    assert 'is_admin' not in _written_acl_content(user_vertex)
