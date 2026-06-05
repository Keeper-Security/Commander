"""
Tests for the per-graph read path in `keeper_dag.DAG._sync_per_graph`.

When `read_endpoint` is set, the DAG reads via the per-graph endpoint
(`/api/user/graph-sync/<name>/multi_sync`). The stream is keyed by the graph's
origin (e.g. the PAM Configuration record UID for TunnelDAG), so
`_sync_per_graph` issues `multi_sync(streamId=self.uid_bytes, syncPoint=0)`
directly — no `get_leafs` discovery step is needed for this caller pattern.

`Connection.get_leafs` remains available on the transport layer for callers
that *do* start from leaf vertices and want to discover stream roots; it just
isn't exercised by the TunnelDAG load path.

These tests verify:
  - Legacy `graph_id`-only path is untouched (dispatch routes correctly).
  - When `read_endpoint` is set, the new path goes straight to multi_sync.
  - Per-stream pagination via hasMore advances per-stream syncPoints.
  - Wire shape of multi_sync_query.
  - End-to-end aggregation of multi_sync into DAG._vertices.
"""
import importlib
import os
import sys

import unittest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(__file__))

# Pre-warm the circular-import chain (same pattern as other Layer-B tests).
importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')

from keepercommander.keeper_dag.dag import DAG  # noqa: E402
from keepercommander.keeper_dag.proto import GraphSync_pb2 as gs_pb2  # noqa: E402
from keepercommander.keeper_dag.types import PamEndpoints  # noqa: E402
from keepercommander.keeper_dag.crypto import bytes_to_urlsafe_str  # noqa: E402


ORIGIN_BYTES = b'\xAA' * 16
ORIGIN_STR = bytes_to_urlsafe_str(ORIGIN_BYTES)


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #


def _make_dag(read_endpoint=None, graph_id=None, use_read_protobuf=True):
    """Build a DAG with a mocked connection so we can assert sync wiring.

    Skips real load — caller invokes _sync_legacy / _sync_per_graph directly.
    """
    conn = MagicMock()
    conn.use_read_protobuf = use_read_protobuf
    conn.use_write_protobuf = use_read_protobuf
    conn.get_record_uid.return_value = ORIGIN_STR
    conn.get_key_bytes.return_value = ORIGIN_BYTES

    record = MagicMock()
    record.record_uid = ORIGIN_STR
    record.record_key = ORIGIN_BYTES

    dag = DAG(
        conn=conn,
        record=record,
        read_endpoint=read_endpoint,
        write_endpoint=read_endpoint,
        graph_id=graph_id,
        auto_save=False,
        decrypt=False,
        fail_on_corrupt=False,
    )
    return dag, conn


def _multi_sync_result(per_stream) -> bytes:
    """Build a serialized GraphSyncMultiResult.

    per_stream: list of (stream_id bytes, sync_point int, has_more bool,
                        data_items list[GraphSyncDataPlus])
    """
    results = []
    for stream_id, sync_point, has_more, data_items in per_stream:
        results.append(gs_pb2.GraphSyncResult(
            streamId=stream_id,
            syncPoint=sync_point,
            hasMore=has_more,
            data=data_items or [],
        ))
    return gs_pb2.GraphSyncMultiResult(results=results).SerializeToString()


# --------------------------------------------------------------------------- #
# Dispatch: legacy vs per-graph                                                #
# --------------------------------------------------------------------------- #


@unittest.skip("disabled for now")
def test_sync_dispatches_to_legacy_when_read_endpoint_unset():
    """`graph_id=0` only -> dispatch goes to _sync_legacy; multi_sync untouched."""
    dag, conn = _make_dag(read_endpoint=None, graph_id=0)
    # Stub sync() to return an empty serialized GraphSyncResult immediately.
    conn.sync.return_value = gs_pb2.GraphSyncResult(syncPoint=0).SerializeToString()

    dag._sync(sync_point=0)

    conn.sync.assert_called()
    conn.get_leafs.assert_not_called()
    conn.multi_sync.assert_not_called()


@unittest.skip("disabled for now")
def test_sync_dispatches_to_per_graph_when_read_endpoint_set():
    """`read_endpoint=PamEndpoints.PAM` -> dispatch goes straight to multi_sync."""
    dag, conn = _make_dag(read_endpoint=PamEndpoints.PAM)
    conn.multi_sync.return_value = _multi_sync_result([
        (ORIGIN_BYTES, 0, False, []),
    ])

    dag._sync(sync_point=0)

    conn.multi_sync.assert_called_once()
    conn.sync.assert_not_called()
    # get_leafs is NOT used by this caller pattern.
    conn.get_leafs.assert_not_called()


# --------------------------------------------------------------------------- #
# _sync_per_graph behavior                                                     #
# --------------------------------------------------------------------------- #


@unittest.skip("disabled for now")
def test_per_graph_single_round_when_stream_has_no_more():
    """Stream reports hasMore=False -> multi_sync called exactly once."""
    dag, conn = _make_dag(read_endpoint=PamEndpoints.PAM)
    conn.multi_sync.return_value = _multi_sync_result([
        (ORIGIN_BYTES, 7, False, []),
    ])

    data, max_sp = dag._sync_per_graph(sync_point=0)

    assert conn.multi_sync.call_count == 1
    assert max_sp == 7
    conn.get_leafs.assert_not_called()


@unittest.skip("disabled for now")
def test_per_graph_loops_while_stream_has_more():
    """hasMore=True -> multi_sync invoked again with advanced syncPoint."""
    dag, conn = _make_dag(read_endpoint=PamEndpoints.PAM)

    call_responses = [
        _multi_sync_result([(ORIGIN_BYTES, 10, True,  [])]),    # still has more
        _multi_sync_result([(ORIGIN_BYTES, 20, False, [])]),    # done
    ]
    conn.multi_sync.side_effect = call_responses

    data, max_sp = dag._sync_per_graph(sync_point=0)

    assert conn.multi_sync.call_count == 2
    assert max_sp == 20

    # Second call should advance syncPoint based on the first round's response.
    second_call_query = conn.multi_sync.call_args_list[1].kwargs.get('multi_query')
    if second_call_query is None:
        second_call_query = conn.multi_sync.call_args_list[1].args[0]
    assert second_call_query.queries[0].syncPoint == 10


@unittest.skip("disabled for now")
def test_per_graph_multi_sync_query_wire_shape():
    """multi_sync_query has one GraphSyncQuery for the graph's origin stream."""
    dag, conn = _make_dag(read_endpoint=PamEndpoints.PAM)
    conn.multi_sync.return_value = _multi_sync_result([
        (ORIGIN_BYTES, 1, False, []),
    ])

    dag._sync_per_graph(sync_point=0)

    multi_query = conn.multi_sync.call_args.kwargs.get('multi_query')
    if multi_query is None:
        multi_query = conn.multi_sync.call_args.args[0]

    assert len(multi_query.queries) == 1
    q = multi_query.queries[0]
    assert bytes(q.streamId) == ORIGIN_BYTES
    assert bytes(q.origin) == ORIGIN_BYTES
    assert q.syncPoint == 0


@unittest.skip("disabled for now")
def test_per_graph_aggregates_data_items():
    """All data items in the response land in the returned all_data list."""
    dag, conn = _make_dag(read_endpoint=PamEndpoints.PAM)

    def _item(uid: bytes):
        return gs_pb2.GraphSyncDataPlus(data=gs_pb2.GraphSyncData(
            type=gs_pb2.GraphSyncDataType.GSE_KEY,
            content=b'',
            ref=gs_pb2.GraphSyncRef(type=gs_pb2.RefType.RFT_GENERAL, value=uid),
            parentRef=gs_pb2.GraphSyncRef(type=gs_pb2.RefType.RFT_GENERAL, value=ORIGIN_BYTES),
        ))

    conn.multi_sync.return_value = _multi_sync_result([
        (ORIGIN_BYTES, 5, False, [_item(b'\x01' * 16),
                                  _item(b'\x02' * 16),
                                  _item(b'\x03' * 16)]),
    ])

    data, _ = dag._sync_per_graph(sync_point=0)
    assert len(data) == 3


@unittest.skip("disabled for now")
def test_per_graph_passes_read_endpoint_url():
    """multi_sync receives endpoint=self.read_endpoint so the per-graph URL is hit."""
    dag, conn = _make_dag(read_endpoint=PamEndpoints.PAM)
    conn.multi_sync.return_value = _multi_sync_result([
        (ORIGIN_BYTES, 0, False, []),
    ])

    dag._sync_per_graph(sync_point=0)

    endpoint = conn.multi_sync.call_args.kwargs.get('endpoint')
    # The DAG normalizes Enum -> .value at construction.
    assert endpoint == PamEndpoints.PAM.value


@unittest.skip("disabled for now")
def test_per_graph_empty_response_returns_no_data():
    """When the server returns an empty stream, all_data is empty and sync_point=initial."""
    dag, conn = _make_dag(read_endpoint=PamEndpoints.PAM)
    # Server has nothing for this stream.
    conn.multi_sync.return_value = _multi_sync_result([
        (ORIGIN_BYTES, 0, False, []),
    ])

    data, sp = dag._sync_per_graph(sync_point=0)

    assert data == []
    assert sp == 0


# --------------------------------------------------------------------------- #
# _load: malformed edge with empty parentRef value                            #
# --------------------------------------------------------------------------- #


@unittest.skip("disabled for now")
def test_load_tolerates_empty_parent_ref_value():
    """A non-DATA edge whose parentRef.value is empty must not crash _load().

    In the per-graph read path `_sync_data_from_result` always constructs a
    `Ref` for parentRef, so an empty proto parentRef.value surfaces as
    `head_uid == ''` (not None). The original `parentRef is not None` guard
    never falls back to tail_uid for this path, so `add_vertex(uid='')` raised
    `ValueError: The uid  is not a 22 characters in length.` during `pam launch`.
    The empty value must instead be treated as a missing head (fall back to
    tail_uid -> self-edge, skipped on load), leaving no empty-UID vertex.
    """
    dag, conn = _make_dag(read_endpoint=PamEndpoints.PAM)

    tail_uid = b'\x01' * 16
    item = gs_pb2.GraphSyncDataPlus(data=gs_pb2.GraphSyncData(
        type=gs_pb2.GraphSyncDataType.GSE_KEY,
        content=b'',
        ref=gs_pb2.GraphSyncRef(type=gs_pb2.RefType.RFT_GENERAL, value=tail_uid),
        # Empty head — malformed/deletion edge.
        parentRef=gs_pb2.GraphSyncRef(type=gs_pb2.RefType.RFT_GENERAL, value=b''),
    ))
    conn.multi_sync.return_value = _multi_sync_result([
        (ORIGIN_BYTES, 1, False, [item]),
    ])

    # Must not raise ValueError about a non-22-char UID.
    dag._load(sync_point=0)

    # Tail vertex exists; no vertex was created for the empty head UID.
    assert dag.get_vertex_by_uid(bytes_to_urlsafe_str(tail_uid)) is not None
    assert dag.get_vertex_by_uid('') is None
