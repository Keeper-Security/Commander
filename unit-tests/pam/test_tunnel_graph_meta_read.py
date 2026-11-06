"""
Unit tests for ``get_vertex_content`` / ``TunnelDAG.set_resource_allowed``.

A PAM resource vertex can carry several DATA edges (``meta``, ``jit_settings``,
``ai_settings``). ``vertex.content_as_dict`` returns the newest DATA edge of ANY path (the
TunnelDAG graph is not path-aware), so after ``pam connection jit`` the resource's "meta"
was read as the JIT settings. ``pam tunnel edit --keeper-proxy off`` then sent that to
``configure_resource`` as the meta, without a ``version``, and krouter answered
"Decreasing the version of a resource is not allowed".

These tests use the real DAG classes with a mocked connection (no network).
"""
import importlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))

skip_tests = False
skip_reason = ""
try:
    importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')
    from keepercommander.keeper_dag import DAG
    from keepercommander.keeper_dag.types import EdgeType, RefType
    from keepercommander.commands.tunnel.port_forward import TunnelGraph as tg
except ImportError as e:  # pragma: no cover
    skip_tests = True
    skip_reason = f"Cannot import TunnelGraph: {e}"

RESOURCE_UID = 'B' * 22
META = {
    'allowedSettings': {'connections': True, 'portForwards': True},
    'rotateOnTermination': False,
    'version': 1,
}
JIT = {'createEphemeral': False, 'elevate': True, 'elevationMethod': 'group', 'elevationString': 'g'}
AI = {'version': 'v1.0.0', 'riskLevels': {}}


def _new_dag():
    conn = mock.MagicMock(use_read_protobuf=False, use_write_protobuf=False)
    return DAG(conn=conn, key_bytes=os.urandom(32), graph_id=0)


def _resource_vertex(dag, edges):
    """Resource vertex linked to the root, with DATA edges added in the given order."""
    vertex = dag.add_vertex(uid=RESOURCE_UID, vertex_type=RefType.PAM_MACHINE)
    vertex.belongs_to(dag.get_root, EdgeType.LINK)
    for path, content in edges:
        vertex.add_data(content=content, path=path, needs_encryption=False)
    return vertex


@unittest.skipIf(skip_tests, skip_reason)
class TestGetVertexContent(unittest.TestCase):

    def test_meta_wins_over_newer_jit_settings(self):
        vertex = _resource_vertex(_new_dag(), [('meta', META), ('jit_settings', JIT)])
        self.assertEqual(tg.get_vertex_content(vertex), META)

    def test_meta_wins_over_newer_ai_settings(self):
        vertex = _resource_vertex(_new_dag(), [('meta', META), ('jit_settings', JIT), ('ai_settings', AI)])
        self.assertEqual(tg.get_vertex_content(vertex), META)

    def test_no_meta_edge_does_not_fall_back_to_another_path(self):
        vertex = _resource_vertex(_new_dag(), [('jit_settings', JIT)])
        self.assertIsNone(tg.get_vertex_content(vertex))

    def test_legacy_meta_without_path_is_still_read(self):
        vertex = _resource_vertex(_new_dag(), [(None, META), ('jit_settings', JIT)])
        self.assertEqual(tg.get_vertex_content(vertex), META)

    def test_explicit_path(self):
        vertex = _resource_vertex(_new_dag(), [('meta', META), ('jit_settings', JIT)])
        self.assertEqual(tg.get_vertex_content(vertex, path='jit_settings'), JIT)

    def test_none_vertex(self):
        self.assertIsNone(tg.get_vertex_content(None))


@unittest.skipIf(skip_tests, skip_reason)
class TestSetResourceAllowedWithJitSettings(unittest.TestCase):

    def _tunnel_dag(self, edges):
        dag = _new_dag()
        _resource_vertex(dag, edges)
        tdag = tg.TunnelDAG.__new__(tg.TunnelDAG)
        tdag.params = mock.MagicMock()
        tdag.record = mock.MagicMock(record_uid='C' * 22)
        tdag.linking_dag = dag
        return tdag

    def _run(self, tdag, **kwargs):
        """Run set_resource_allowed with Layer-B mocked; return the configure_resource mock."""
        with mock.patch('keepercommander.commands.pam.router_helper.router_configure_resource') as configure, \
                mock.patch('keepercommander.commands.pam.router_helper.get_router_url', return_value='https://router'), \
                mock.patch('keepercommander.commands.pam._layer_b.is_layer_b_feature_disabled', return_value=False):
            tdag.set_resource_allowed(resource_uid=RESOURCE_UID, **kwargs)
        return configure

    def test_noop_edit_sends_nothing_when_jit_settings_is_newest_edge(self):
        # `pam tunnel edit --keeper-proxy off` calls set_resource_allowed with every setting None.
        # Before the fix the JIT content was mistaken for the meta, gained an empty
        # allowedSettings, and was sent without a version (-> RRC_BAD_REQUEST).
        tdag = self._tunnel_dag([('meta', META), ('jit_settings', JIT)])
        configure = self._run(tdag)
        configure.assert_not_called()

    def test_changed_setting_sends_meta_not_jit_settings(self):
        tdag = self._tunnel_dag([('meta', META), ('jit_settings', JIT)])
        configure = self._run(tdag, tunneling=False, meta_version=tg.RESOURCE_META_VERSION_V1)
        configure.assert_called_once()
        request = configure.call_args[0][1]
        import json
        sent = json.loads(request.meta.decode())
        self.assertEqual(sent['version'], tg.RESOURCE_META_VERSION_V1)
        self.assertFalse(sent['allowedSettings']['portForwards'])
        self.assertTrue(sent['allowedSettings']['connections'])
        for jit_key in JIT:
            self.assertNotIn(jit_key, sent)


if __name__ == '__main__':
    unittest.main()
