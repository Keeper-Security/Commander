#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""The reader of the current vault state (`pam project update`).

Graphs are built and read back through the local fake GraphSync engine, so the edges really go through save, sync
(arrival order) and load, like on the server.
"""

import json
import logging
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import keepercommander.commands.record  # noqa: F401

from keepercommander import crypto, utils
from keepercommander.commands.pam_debug.graph_edges import (
    EXCLUDE_EDGE_TYPES, EdgeIndex, collect_graph_entry, decode_edge_local, edge_to_dict,
)
from keepercommander.commands.pam_debug.record_state import file_refs, rotation_info
from keepercommander.commands.pam_import import vault_reader, workflow_apply
from keepercommander.commands.pam_import.vault_reader import (
    CurrentEdge, GraphState, build_graph_state, load_with_raw, read_vault_state,
)
from keepercommander.keeper_dag import DAG, EdgeType
from keepercommander.keeper_dag.connection.local import Connection as LocalConnection
from keepercommander.keeper_dag.edge import DAGEdge
from keepercommander.keeper_dag.types import RefType
from keepercommander.proto import workflow_pb2

LOGGER = logging.getLogger('vault-reader-test')


def _params(**kw):
    return SimpleNamespace(record_cache=kw.pop('record_cache', {}), nested_share_records={},
                           nested_share_record_data={}, record_rotation_cache=kw.pop('rotation', {}), **kw)


class Graph:
    """A small PAM-like graph: config (root) <- machine <- user (ACL), saved through the local engine."""

    def __init__(self, tmpdir):
        self.key = os.urandom(32)
        self.conn = LocalConnection(db_dir=tmpdir, logger=LOGGER, use_read_protobuf=False, use_write_protobuf=False)
        self.dag = DAG(conn=self.conn, key_bytes=self.key, graph_id=0, auto_save=False, logger=LOGGER)
        self.root = self.dag.get_vertex(self.dag.uid) or self.dag.add_vertex(
            name='cfg', uid=self.dag.uid, vertex_type=RefType.PAM_NETWORK)
        self.machine = self.dag.add_vertex(name='machine', vertex_type=RefType.PAM_MACHINE)
        self.machine.belongs_to_root(EdgeType.LINK)
        self.user = self.dag.add_vertex(name='user', vertex_type=RefType.PAM_USER)

    def data(self, vertex, path, content):
        vertex.add_data(content=content, path=path, needs_encryption=False)

    def delete_data(self, vertex, path):
        """A DELETION edge for a DATA path (the library's own edge.delete() does nothing for such a path)."""
        version, _ = vertex.get_highest_edge_version(head_uid=vertex.uid)
        vertex.edges.append(DAGEdge(vertex=vertex, edge_type=EdgeType.DELETION, head_uid=vertex.uid,
                                    version=version + 1, path=path))

    def save(self):
        self.dag.save()

    def read(self, params=None):
        dag = DAG(conn=self.conn, key_bytes=self.key, graph_id=0, auto_save=False, logger=LOGGER)
        raw = load_with_raw(dag)
        return dag, raw, build_graph_state(0, raw, dag, params or _params())


class TestCurrentEdgeRule:

    def test_newest_data_wins_and_a_still_current_path_is_not_lost_to_the_active_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = Graph(tmp)
            g.data(g.machine, 'meta', {'version': 1, 'allowedSettings': {'connections': True}})
            g.data(g.machine, 'jit_settings', {'create_ephemeral': True})
            g.save()
            g.data(g.machine, 'meta', {'version': 1, 'allowedSettings': {'connections': False}})
            g.save()

            dag, _, state = g.read()

            # The library marks the (still current) jit_settings edge as inactive after meta was rewritten ...
            loaded_jit = [e for e in dag.get_vertex(g.machine.uid).edges if e.path == 'jit_settings'][0]
            assert loaded_jit.active is False
            # ... but it is the current edge of its path, and meta is the rewritten one.
            assert state.data(g.machine.uid, 'jit_settings') == {'create_ephemeral': True}
            assert state.data(g.machine.uid, 'meta') == {'version': 1, 'allowedSettings': {'connections': False}}
            assert sorted(state.data_paths(g.machine.uid)) == ['jit_settings', 'meta']

    def test_a_deletion_that_arrived_last_means_absent_although_the_loaded_version_is_lower(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = Graph(tmp)
            g.data(g.machine, 'meta', {'version': 1})
            g.data(g.machine, 'jit_settings', {'create_ephemeral': True})
            g.save()
            g.delete_data(g.machine, 'jit_settings')
            g.save()

            dag, _, state = g.read()

            edges = {(e.edge_type, e.path): e for e in dag.get_vertex(g.machine.uid).edges if e.path}
            # the library versions the DELETION below the data it deletes (it processes non-DATA edges first)
            assert edges[(EdgeType.DELETION, 'jit_settings')].version < edges[(EdgeType.DATA, 'jit_settings')].version
            # the arrival order is what counts
            assert state.data(g.machine.uid, 'jit_settings') is None
            assert 'jit_settings' not in state.data_paths(g.machine.uid)
            assert state.data(g.machine.uid, 'meta') == {'version': 1}

    def test_data_added_again_after_a_deletion_is_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = Graph(tmp)
            g.data(g.machine, 'jit_settings', {'n': 1})
            g.save()
            g.delete_data(g.machine, 'jit_settings')
            g.save()
            g.data(g.machine, 'jit_settings', {'n': 2})
            g.save()

            _, _, state = g.read()

            assert state.data(g.machine.uid, 'jit_settings') == {'n': 2}

    def test_acl_and_link_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = Graph(tmp)
            g.user.belongs_to(g.machine, EdgeType.ACL, content={'is_admin': True})
            g.save()
            g.user.belongs_to(g.machine, EdgeType.ACL, content={'is_admin': False, 'belongs_to': True})
            g.save()

            _, _, state = g.read()

            acl = state.edge(g.user.uid, g.machine.uid)
            assert (acl.edge_type, acl.contents) == ('acl', {'is_admin': False, 'belongs_to': True})
            link = state.edge(g.machine.uid, g.root.uid)
            assert link.edge_type == 'link'
            # both ends see the ACL
            assert acl in state.edges_of(g.user.uid) and acl in state.edges_of(g.machine.uid)
            assert state.edges_of_type(g.machine.uid, 'acl') == [acl]

    def test_graph_state_lookups_on_an_unknown_vertex_are_empty(self):
        state = GraphState(0, [CurrentEdge('a', 'b', 'link', None)])
        assert state.edges_of('zzz') == [] and state.data('zzz', 'meta') is None and state.edge('a', 'zzz') is None
        assert len(state) == 1


class TestLocalDecoding:

    def test_data_edge_encrypted_with_the_record_key_is_decrypted_without_a_network_call(self):
        key = os.urandom(32)
        payload = {'create_ephemeral': True, 'elevate': False}
        nonce = os.urandom(12)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        encrypted = nonce + AESGCM(key).encrypt(nonce, json.dumps(payload).encode(), None)

        class Edge:
            content = encrypted
            edge_type = EdgeType.DATA
            path = 'jit_settings'

            @property
            def content_as_dict(self):
                raise ValueError('not json')   # the graph keychain could not decrypt it

        edge = Edge()
        params = _params(record_cache={'RES': {'record_key_unencrypted': key}})

        with patch('keepercommander.commands.pam_debug.graph_edges.get_resource_settings',
                   side_effect=AssertionError('must not reload the graph')):
            assert decode_edge_local(edge, 'RES', params) == payload

    def test_undecodable_content_gives_a_marker_not_an_exception(self):
        class Edge:
            content = b'\xff\xfe\x00binary'
            edge_type = EdgeType.DATA
            path = 'x'

            @property
            def content_as_dict(self):
                raise ValueError

            @property
            def content_as_str(self):
                raise ValueError

        assert decode_edge_local(Edge(), 'RES', _params()).startswith('<raw_hex:')


class TestRecordState:

    def test_rotation_info_parses_the_schedule_and_decrypts_the_complexity(self):
        key = os.urandom(32)
        rules = {'length': 20, 'caps': 2}
        blob = utils.base64_url_encode(crypto.encrypt_aes_v2(json.dumps(rules).encode(), key))
        params = _params(
            record_cache={'U1': {'record_key_unencrypted': key}},
            rotation={'U1': {'configuration_uid': 'CFG', 'resource_uid': 'RES', 'disabled': False,
                             'schedule': json.dumps([{'type': 'CRON', 'cron': '0 0 * * *'}]),
                             'pwd_complexity': blob, 'last_rotation': 5, 'last_rotation_status': 1, 'revision': 9}})

        info = rotation_info(params, 'U1')

        assert info['configuration_uid'] == 'CFG' and info['resource_uid'] == 'RES'
        assert info['schedule'] == [{'type': 'CRON', 'cron': '0 0 * * *'}]
        assert info['pwd_complexity'] == rules
        assert info['disabled'] is False
        assert rotation_info(params, 'NOPE') is None

    def test_rotation_info_survives_an_undecryptable_complexity(self):
        params = _params(rotation={'U1': {'schedule': 'not json', 'pwd_complexity': 'AAAA', 'disabled': True}})
        info = rotation_info(params, 'U1')
        assert info['pwd_complexity'] is None and info['schedule'] == 'not json' and info['disabled'] is True

    def test_file_refs_from_fileref_fields_and_scripts(self):
        data = {'fields': [{'type': 'fileRef', 'value': ['F1', 'F2']},
                           {'type': 'script', 'value': [{'fileRef': 'F3', 'command': 'x'}, {'command': 'y'}]},
                           {'type': 'login', 'value': ['bob']}],
                'custom': [{'type': 'fileRef', 'value': ['F1', 'F4']}]}
        assert file_refs(data) == ['F1', 'F2', 'F3', 'F4']
        assert file_refs({}) == []


class TestReadVaultState:

    def _loader(self, graph):
        return lambda graph_id: (graph.read()[0], graph.read()[1])

    def test_reads_graphs_records_files_rotation_and_only_the_requested_workflows(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = Graph(tmp)
            g.data(g.machine, 'meta', {'version': 1})
            g.save()
            params = _params(rotation={'M1': {'schedule': '[]', 'configuration_uid': 'CFG'}})
            record_data = {'M1': {'title': 'web', 'type': 'pamMachine',
                                  'fields': [{'type': 'script', 'value': [{'fileRef': 'F1'}]}]},
                           'M2': {'title': 'db', 'type': 'pamDatabase'}}
            workflow_calls = []

            def fake_workflow(_params, uid, title=''):
                workflow_calls.append((uid, title))
                return {'parameters': {'approvals_needed': 1}}

            with patch.object(vault_reader, 'record_json', side_effect=lambda p, uid: (record_data[uid], [])), \
                    patch.object(vault_reader, 'file_record_info',
                                 return_value={'record_uid': 'F1', 'name': 'a.sh', 'size': 7, 'last_modified': 1}), \
                    patch.object(vault_reader, 'read_workflow_config', side_effect=fake_workflow):
                state = read_vault_state(params, 'CFG', ['M1', 'M2', 'M1'], dag_loader=self._loader(g),
                                         graph_ids=(0,), workflow_uids=['M1'])

            assert state.errors == []
            assert list(state.records) == ['M1', 'M2']
            assert state.records['M1'].title == 'web' and state.records['M1'].record_type == 'pamMachine'
            assert state.records['M1'].files == [{'record_uid': 'F1', 'name': 'a.sh', 'size': 7, 'last_modified': 1}]
            assert state.records['M1'].rotation['configuration_uid'] == 'CFG'
            assert state.records['M2'].rotation is None
            assert state.graphs[0].data(g.machine.uid, 'meta') == {'version': 1}
            # one router call, for the resource asked for, with its title
            assert workflow_calls == [('M1', 'web')]
            assert state.workflows == {'M1': {'parameters': {'approvals_needed': 1}}}

    def test_failures_are_listed_not_raised(self):
        params = _params()

        def broken_loader(graph_id):
            raise RuntimeError('boom')

        with patch.object(vault_reader, 'record_json', return_value=({'title': 't'}, [])), \
                patch.object(vault_reader, 'read_workflow_config', side_effect=RuntimeError('router down')):
            state = read_vault_state(params, 'CFG', ['M1'], dag_loader=broken_loader, graph_ids=(0,),
                                     workflow_uids=['M1'])

        assert state.graphs == {}
        assert any('could not be read: boom' in e for e in state.errors)
        assert any('workflow of M1 could not be read: router down' in e for e in state.errors)
        assert state.records['M1'].title == 't'

    def test_missing_configuration_record_is_an_error(self):
        with patch.object(vault_reader, 'load_pam_record', return_value=None), \
                patch.object(vault_reader, 'record_json', return_value=({}, [])):
            state = read_vault_state(_params(), 'CFG', [], graph_ids=(0,))
        assert any('PAM configuration record CFG could not be loaded' in e for e in state.errors)

    def test_missing_file_record_is_reported_on_the_record(self):
        record_data = {'fields': [{'type': 'fileRef', 'value': ['GONE']}]}
        with patch.object(vault_reader, 'record_json', return_value=(record_data, [])), \
                patch.object(vault_reader, 'file_record_info', return_value=None):
            state = vault_reader.read_record_state(_params(), 'M1')
        assert state.files == [] and state.errors[0]['stage'] == 'file_record'


class TestReadWorkflowConfig:

    def test_returns_the_config_as_a_dict_and_none_when_there_is_none(self):
        uid = utils.generate_uid()
        config = workflow_pb2.WorkflowConfig()
        config.parameters.resource.CopyFrom(
            workflow_apply.ProtobufRefBuilder.record_ref(utils.base64_url_decode(uid), 'web'))

        with patch.object(workflow_apply, '_post_with_throttle_retry', return_value=config) as post:
            result = workflow_apply.read_workflow_config(MagicMock(), uid, 'web')
        assert 'parameters' in result and result['parameters']['resource']['name'] == 'web'
        assert post.call_args[0][1] == 'read_workflow_config'

        with patch.object(workflow_apply, '_post_with_throttle_retry', return_value=workflow_pb2.WorkflowConfig()):
            assert workflow_apply.read_workflow_config(MagicMock(), uid, 'web') is None
        with patch.object(workflow_apply, '_post_with_throttle_retry', return_value=None):
            assert workflow_apply.read_workflow_config(MagicMock(), uid, 'web') is None


class TestDumpHelpers:
    """The graph helpers the dump now shares with the reader."""

    def _graph(self, tmp):
        g = Graph(tmp)
        g.data(g.machine, 'meta', {'version': 1})
        g.data(g.machine, 'jit_settings', {'create_ephemeral': True})
        g.user.belongs_to(g.machine, EdgeType.ACL, content={'is_admin': True})
        g.save()
        g.data(g.machine, 'meta', {'version': 2})
        g.delete_data(g.machine, 'jit_settings')
        g.save()
        return g

    def test_index_returns_what_the_old_full_scan_returned_in_the_same_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = self._graph(tmp)
            dag, _, _ = g.read()
            index = EdgeIndex(dag)
            for uid in [v.uid for v in dag.all_vertices]:
                old_scan = []
                for vertex in dag.all_vertices:
                    for edge in (vertex.edges or []):
                        if not edge or edge.edge_type in EXCLUDE_EDGE_TYPES:
                            continue
                        if vertex.uid != uid and edge.head_uid != uid:
                            continue
                        old_scan.append((vertex.uid, edge))
                assert list(index.edges_for(uid)) == old_scan
            assert len(index) == sum(1 for v in dag.all_vertices for e in v.edges
                                     if e and e.edge_type not in EXCLUDE_EDGE_TYPES)

    def test_deletion_edges_are_left_out_of_the_dump_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = self._graph(tmp)
            dag, _, _ = g.read()
            assert all(edge.edge_type not in EXCLUDE_EDGE_TYPES for _, edge in EdgeIndex(dag).all_edges())
            assert any(edge.edge_type in EXCLUDE_EDGE_TYPES for _, edge in EdgeIndex(dag, True).all_edges())

    def test_dump_entry_has_the_version_of_every_edge(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = self._graph(tmp)
            dag, _, _ = g.read()
            entry = collect_graph_entry(dag, g.machine.uid, _params(), 'CFG')
            assert entry['vertex_active'] is True
            metas = [e for e in entry['edges'] if e['path'] == 'meta']
            assert len(metas) == 2 and all(isinstance(e['version'], int) for e in entry['edges'])
            assert sorted(e['version'] for e in metas) == [e['version'] for e in sorted(metas, key=lambda x: x['version'])]
            assert {e['contents']['version'] for e in metas} == {1, 2}
            assert set(entry['edges'][0]) == {'head', 'tail', 'edge_type', 'path', 'version', 'active', 'contents'}

    def test_a_vertex_that_is_not_in_the_graph_gives_an_empty_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = self._graph(tmp)
            dag, _, _ = g.read()
            assert collect_graph_entry(dag, 'NOT-A-VERTEX-UID-----', _params(), 'CFG') == {}

    def test_edge_to_dict_decodes_acl_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = self._graph(tmp)
            dag, _, _ = g.read()
            acl = [e for v in dag.all_vertices for e in v.edges if e.edge_type == EdgeType.ACL][0]
            as_dict = edge_to_dict(acl, g.user.uid, _params(), 'CFG')
            assert as_dict['edge_type'] == 'acl' and as_dict['contents'] == {'is_admin': True}


def _item(tail, head, edge_type, path=None):
    """A raw sync item as the library receives it (only the fields the reader looks at)."""
    return SimpleNamespace(ref=SimpleNamespace(value=tail),
                           parentRef=SimpleNamespace(value=head) if head else None,
                           type=edge_type, path=path)


class TestOrderingRules:
    """The arrival-order bookkeeping on synthetic sync items (no graph needed)."""

    NO_VERTICES = SimpleNamespace(all_vertices=[])

    def _state(self, *items):
        return build_graph_state(0, list(items), self.NO_VERTICES, _params())

    def test_last_item_per_coordinate_wins_whatever_the_type(self):
        state = self._state(_item('u', 'm', 'link'), _item('u', 'm', 'acl'))
        assert state.edge('u', 'm').edge_type == 'acl'

    def test_deletion_then_new_edge_is_present_and_new_edge_then_deletion_is_absent(self):
        present = self._state(_item('m', None, 'data', 'x'), _item('m', None, 'deletion', 'x'),
                              _item('m', None, 'data', 'x'))
        absent = self._state(_item('m', None, 'data', 'x'), _item('m', None, 'deletion', 'x'))
        assert present.edge('m', 'm', 'x') is not None and absent.edge('m', 'm', 'x') is None

    def test_a_data_item_has_no_parent_and_the_head_is_the_tail(self):
        state = self._state(_item('m', None, 'data', 'meta'))
        assert state.edge('m', 'm', 'meta').edge_type == 'data'
        assert state.data_paths('m') == ['meta']

    def test_paths_are_separate_coordinates(self):
        state = self._state(_item('m', None, 'data', 'meta'), _item('m', None, 'data', 'jit_settings'),
                            _item('m', None, 'deletion', 'meta'))
        assert state.edge('m', 'm', 'meta') is None and state.edge('m', 'm', 'jit_settings') is not None

    def test_a_denial_sits_next_to_the_normal_edge_and_does_not_replace_it(self):
        state = self._state(_item('u', 'm', 'acl'), _item('u', 'm', 'denial'))
        assert state.edge('u', 'm').edge_type == 'acl'
        assert sorted(e.edge_type for e in state.edges_of('u')) == ['acl', 'denial']

    def test_undenial_takes_the_denial_away_and_deletion_removes_edge_and_denial(self):
        undone = self._state(_item('u', 'm', 'denial'), _item('u', 'm', 'undenial'))
        deleted = self._state(_item('u', 'm', 'link'), _item('u', 'm', 'denial'), _item('u', 'm', 'deletion'))
        assert undone.edges_of('u') == [] and deleted.edges_of('u') == []

    def test_an_acl_without_a_set_flag_counts_as_deleted(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = Graph(tmp)
            g.user.belongs_to(g.machine, EdgeType.ACL, content={'is_admin': True, 'belongs_to': True})
            g.save()
            g.user.belongs_to(g.machine, EdgeType.ACL, content={'is_admin': False, 'belongs_to': False})
            g.save()
            _, _, state = g.read()
            assert state.edge(g.user.uid, g.machine.uid) is None

    def test_an_acl_with_one_set_flag_stays(self):
        with tempfile.TemporaryDirectory() as tmp:
            g = Graph(tmp)
            g.user.belongs_to(g.machine, EdgeType.ACL, content={'is_admin': False, 'belongs_to': True})
            g.save()
            _, _, state = g.read()
            assert state.edge(g.user.uid, g.machine.uid).contents == {'is_admin': False, 'belongs_to': True}
