"""
Shared protobuf fixture builders for DAG / graph-sync tests.

Builders use the actual proto schemas so a wire-format change breaks tests at the
right place. Imported by:
- test_dag_graph_sync_endpoints.py (Layer A)
- test_dag_layer_b.py (Layer B configure_resource / set_record_rotation, when added)
"""
from typing import Iterable, Optional

from keepercommander.keeper_dag.proto import GraphSync_pb2 as gs_pb2
from keepercommander.keeper_dag.types import PamEndpoints


# Graphs covered by the new per-graph routing. The five values match
# /api/user/graph-sync/<token>/<verb> exactly.
ALL_GRAPHS = [
    (PamEndpoints.PAM, 'pam'),
    (PamEndpoints.DISCOVERY_RULES, 'discovery_rules'),
    (PamEndpoints.DISCOVERY_JOBS, 'discovery_jobs'),
    (PamEndpoints.INFRASTRUCTURE, 'infrastructure'),
    (PamEndpoints.SERVICE_LINKS, 'service_links'),
]

ALL_VERBS = ['add_data', 'sync', 'multi_sync', 'get_leafs']


def make_sync_query(stream_id: bytes = b'\x00' * 16,
                    origin: bytes = b'\x00' * 16,
                    sync_point: int = 0,
                    max_count: int = 0) -> gs_pb2.GraphSyncQuery:
    return gs_pb2.GraphSyncQuery(
        streamId=stream_id,
        origin=origin,
        syncPoint=sync_point,
        maxCount=max_count,
    )


def make_multi_sync_query(queries: Optional[Iterable[gs_pb2.GraphSyncQuery]] = None) -> gs_pb2.GraphSyncMultiQuery:
    if queries is None:
        queries = [make_sync_query()]
    return gs_pb2.GraphSyncMultiQuery(queries=list(queries))


def make_add_data_request(origin_ref: Optional[gs_pb2.GraphSyncRef] = None,
                          data: Optional[Iterable[gs_pb2.GraphSyncData]] = None) -> gs_pb2.GraphSyncAddDataRequest:
    if origin_ref is None:
        origin_ref = gs_pb2.GraphSyncRef(value=b'\x00' * 16)
    if data is None:
        data = []
    return gs_pb2.GraphSyncAddDataRequest(origin=origin_ref, data=list(data))


def make_leafs_query(vertices: Optional[Iterable[bytes]] = None) -> gs_pb2.GraphSyncLeafsQuery:
    if vertices is None:
        vertices = [b'\x00' * 16]
    return gs_pb2.GraphSyncLeafsQuery(vertices=list(vertices))


def proto_for_verb(verb: str):
    """Return a builder function for the proto type that verb expects."""
    return {
        'add_data':   make_add_data_request,
        'sync':       make_sync_query,
        'multi_sync': make_multi_sync_query,
        'get_leafs':  make_leafs_query,
    }[verb]
