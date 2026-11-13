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

"""Read the CURRENT state of PAM records and their graph settings, for `pam project update`.

What is read, and where it lives:

* the record JSON (typed / custom fields, notes) and the file records it refers to (name, size, time);
* the graph (PAM and service-links) edges: links, ACLs, ``meta`` / ``jit_settings`` / ``ai_settings`` DATA edges;
* the rotation settings (vault cache, not the graph);
* the workflow configuration (router API, one call per resource, so only for the resources asked for).

Design points (found by reading the library and the server, 2026-11-13):

* THE CURRENT EDGE IS THE LAST ONE THE SERVER SENT for a coordinate (tail, head, path); a last ``DELETION`` /
  ``UNDENIAL`` means absent. The loaded graph model cannot be used for this: it assigns versions in processing
  order (all non-DATA edges first, then all DATA edges), so the ``DELETION`` of a data path gets a LOWER version
  than the data it deletes, and its ``active`` flag is not path-aware (a rewrite of ``meta`` marks a still-current
  ``jit_settings`` as inactive). The server returns edges ordered by sync point (arrival order), so the raw order
  is captured while the graph loads.
* Settings encrypted with the resource's own record key are decrypted locally; nothing here reloads a graph per
  resource.
* Everything is indexed once and read many times.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from ...keeper_dag import DAG, EdgeType
from ...keeper_dag.types import GRAPH_ID_TO_ENDPOINT, PamGraphId
from ..pam_debug import get_connection
from ..pam_debug.graph_edges import EXCLUDE_EDGE_TYPES, decode_edge_local, decrypt_acl_pwd_complexity
from ..pam_debug.record_state import file_record_info, file_refs, record_json, rotation_info
from .record_loader import load_pam_record
from .workflow_apply import read_workflow_config

# The graphs `update` needs: the PAM graph (links, ACLs, meta, jit / ai settings) and the service links.
DEFAULT_GRAPH_IDS = (PamGraphId.PAM.value, PamGraphId.SERVICE_LINKS.value)


@dataclass(frozen=True)
class CurrentEdge:
    """One CURRENT edge of a graph with its decoded contents (None for a link, or when it cannot be decoded)."""
    tail: str
    head: str
    edge_type: str
    path: Optional[str]
    contents: Any = None


class GraphState:
    """The current edges of one graph, indexed by vertex UID. Build once, query many times."""

    def __init__(self, graph_id: int, edges: Iterable[CurrentEdge] = ()):
        self.graph_id = graph_id
        # (tail, head, path, is_filter) -> edge. A DENIAL does not replace the normal edge at its coordinate.
        self._all: Dict[Tuple[str, str, Optional[str], bool], CurrentEdge] = {}
        self._edges: Dict[Tuple[str, str, Optional[str]], CurrentEdge] = {}
        self._by_uid: Dict[str, List[CurrentEdge]] = {}
        for edge in edges:
            is_filter = edge.edge_type == EdgeType.DENIAL.value
            self._all[(edge.tail, edge.head, edge.path, is_filter)] = edge
            if not is_filter:
                self._edges[(edge.tail, edge.head, edge.path)] = edge
        for edge in self._all.values():
            self._by_uid.setdefault(edge.tail, []).append(edge)
            if edge.head != edge.tail:
                self._by_uid.setdefault(edge.head, []).append(edge)

    def __len__(self) -> int:
        return len(self._all)

    def edge(self, tail: str, head: str, path: Optional[str] = None) -> Optional[CurrentEdge]:
        return self._edges.get((tail, head, path or None))

    def edges_of(self, uid: str) -> List[CurrentEdge]:
        """Every current edge that has *uid* as tail or head."""
        return list(self._by_uid.get(uid, ()))

    def edges_of_type(self, uid: str, edge_type: str) -> List[CurrentEdge]:
        return [e for e in self._by_uid.get(uid, ()) if e.edge_type == edge_type]

    def data(self, uid: str, path: str) -> Any:
        """The contents of the DATA edge of *uid* at *path* (``meta``, ``jit_settings`` ...), or None when absent."""
        edge = self._edges.get((uid, uid, path))
        return edge.contents if edge is not None and edge.edge_type == EdgeType.DATA.value else None

    def data_paths(self, uid: str) -> List[str]:
        return [e.path for e in self._by_uid.get(uid, ())
                if e.edge_type == EdgeType.DATA.value and e.tail == uid and e.head == uid and e.path]


def load_with_raw(dag: DAG, sync_point: int = 0) -> list:
    """Load *dag* and return the raw sync items in the order the server sent them (arrival order)."""
    raw: list = []
    original = dag._sync   # pylint: disable=protected-access

    def capturing(sync_point: int = 0):
        data, max_point = original(sync_point=sync_point)
        raw.extend(data)
        return data, max_point

    dag._sync = capturing   # pylint: disable=protected-access
    try:
        dag.load(sync_point=sync_point)
    finally:
        del dag._sync
    return raw


def _coordinate(item) -> Tuple[str, str, Optional[str]]:
    tail = item.ref.value
    head = item.parentRef.value if (item.parentRef is not None and item.parentRef.value) else tail
    return tail, head, (item.path or None)


def build_graph_state(graph_id: int, raw_items: Iterable, dag: DAG, params) -> GraphState:
    """The current edges of a loaded graph.

    The LAST raw item per coordinate (tail, head, path) is the current one; if it is a ``DELETION`` the edge is
    absent (and so is an ACL with no set flag). A ``DENIAL`` is kept next to the normal edge. Contents are decoded
    from the loaded graph's edge of the same coordinate and type.
    """
    # Same bookkeeping as the server and the Web Vault: a coordinate (tail, head, path) holds ONE current edge,
    # the last one that arrived. A DELETION removes whatever is there (a denial too). A DENIAL is a filter edge: it
    # sits next to the normal edge and does not replace it; an UNDENIAL takes the denial away.
    last_type: Dict[Tuple[str, str, Optional[str]], EdgeType] = {}
    denials: Dict[Tuple[str, str, Optional[str]], EdgeType] = {}
    for item in raw_items:
        coordinate = _coordinate(item)
        edge_type = EdgeType.find_enum(item.type)
        if edge_type == EdgeType.DENIAL:
            denials[coordinate] = edge_type
        elif edge_type == EdgeType.UNDENIAL:
            denials.pop(coordinate, None)
        else:
            last_type[coordinate] = edge_type
            if edge_type == EdgeType.DELETION:
                denials.pop(coordinate, None)

    loaded: Dict[Tuple[str, str, Optional[str], EdgeType], Any] = {}
    for vertex in dag.all_vertices:
        for edge in (vertex.edges or []):
            if edge:
                loaded[(vertex.uid, edge.head_uid, edge.path or None, edge.edge_type)] = edge

    current: List[CurrentEdge] = []
    wanted = [(coordinate, edge_type) for coordinate, edge_type in last_type.items()
              if edge_type not in EXCLUDE_EDGE_TYPES]
    wanted += list(denials.items())
    for (tail, head, path), edge_type in wanted:
        edge = loaded.get((tail, head, path, edge_type))
        contents = decode_edge_local(edge, tail, params) if edge is not None else None
        if edge_type == EdgeType.ACL:
            decrypt_acl_pwd_complexity(contents, head, tail, params)
            # The Web Vault treats an ACL without a single set flag as deleted (that is how a user is unlinked).
            if isinstance(contents, dict) and not any(contents.values()):
                continue
        current.append(CurrentEdge(tail=tail, head=head, edge_type=edge_type.value, path=path, contents=contents))
    return GraphState(graph_id, current)


def make_dag_loader(params, config_record, conn=None) -> Callable[[int], Tuple[DAG, list]]:
    """A loader ``graph_id -> (dag, raw items)`` for the graphs of the PAM configuration *config_record*."""
    connection = conn if conn is not None else get_connection(params)

    def load(graph_id: int):
        endpoint = GRAPH_ID_TO_ENDPOINT[graph_id]
        dag = DAG(conn=connection, record=config_record, read_endpoint=endpoint, write_endpoint=endpoint,
                  fail_on_corrupt=False, logger=logging)
        return dag, load_with_raw(dag)

    return load


@dataclass
class RecordState:
    uid: str
    data: dict = field(default_factory=dict)          # the record as `get --format=json` shows it
    rotation: Optional[dict] = None                   # rotation settings from the vault cache
    files: List[dict] = field(default_factory=list)   # name / size / time of the file records it refers to
    errors: List[dict] = field(default_factory=list)

    @property
    def title(self) -> str:
        return self.data.get('title') or ''

    @property
    def record_type(self) -> str:
        return self.data.get('type') or ''


@dataclass
class VaultState:
    config_uid: str
    graphs: Dict[int, GraphState] = field(default_factory=dict)
    records: Dict[str, RecordState] = field(default_factory=dict)
    workflows: Dict[str, Optional[dict]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)   # graph / workflow reads that failed (PLAN errors)


def read_record_state(params, record_uid: str) -> RecordState:
    data, errors = record_json(params, record_uid)
    files = []
    for file_uid in file_refs(data):
        info = file_record_info(params, file_uid)
        if info is None:
            errors.append({'stage': 'file_record', 'message': f'File record {file_uid} could not be loaded.'})
        else:
            files.append(info)
    return RecordState(uid=record_uid, data=data, rotation=rotation_info(params, record_uid), files=files,
                       errors=errors)


def read_vault_state(params, config_uid: str, record_uids: Iterable[str], *,
                     dag_loader: Optional[Callable[[int], Tuple[DAG, list]]] = None,
                     graph_ids: Iterable[int] = DEFAULT_GRAPH_IDS,
                     workflow_uids: Iterable[str] = ()) -> VaultState:
    """Read the current state of *record_uids* (and the graphs of the PAM configuration *config_uid*).

    ``workflow_uids`` are the only resources whose workflow is read (one router call each); the others are not
    touched. A graph or workflow that cannot be read does not raise: it is listed in ``VaultState.errors`` so the
    caller can report it with the other plan errors.
    """
    state = VaultState(config_uid=config_uid)

    if dag_loader is None:
        config_record = load_pam_record(params, config_uid)
        if config_record is None:
            state.errors.append(f'PAM configuration record {config_uid} could not be loaded; graph data is unavailable.')
        else:
            dag_loader = make_dag_loader(params, config_record)

    if dag_loader is not None:
        for graph_id in graph_ids:
            try:
                dag, raw = dag_loader(graph_id)
                state.graphs[graph_id] = build_graph_state(graph_id, raw, dag, params)
            except Exception as err:   # pylint: disable=broad-except
                logging.debug('Graph %s could not be read: %s', graph_id, err, exc_info=True)
                state.errors.append(f'graph {PamGraphId(graph_id).name} could not be read: {err}')

    for record_uid in dict.fromkeys(record_uids):
        state.records[record_uid] = read_record_state(params, record_uid)

    for record_uid in dict.fromkeys(workflow_uids):
        title = state.records[record_uid].title if record_uid in state.records else ''
        try:
            state.workflows[record_uid] = read_workflow_config(params, record_uid, title)
        except Exception as err:   # pylint: disable=broad-except
            state.errors.append(f'workflow of {record_uid} could not be read: {err}')

    return state
