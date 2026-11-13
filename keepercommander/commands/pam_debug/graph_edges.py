"""Decode the edges of a loaded graph (DAG) for `pam action debug dump` and for the `pam project update` reader.

Moved out of ``dump.py`` so that both use ONE implementation:

* ``extract_edge_contents`` / ``decrypt_acl_pwd_complexity`` / ``edge_to_dict``: turn an edge into plain data
  (decrypted content, version, path).
* ``EdgeIndex``: the edges of a graph indexed by vertex UID, built ONCE. The dump used to scan every vertex and
  every edge of the graph for every record (about 4x10^8 steps for a 15,000 record project).
"""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Dict, Iterator, List, Optional, Tuple

from ...keeper_dag import EdgeType
from ...keeper_dag.crypto import decrypt_aes
from ...nested_share_folder.common import get_record_from_cache, get_record_key
from ..pam_import.keeper_ai_settings import get_resource_settings

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...keeper_dag.dag import DAG as DAGType

# DELETION means the edge is absent; UNDENIAL cancels a DENIAL (treated as absent)
EXCLUDE_EDGE_TYPES = frozenset({EdgeType.DELETION, EdgeType.UNDENIAL})


class EdgeIndex:
    """The edges of one loaded graph, indexed by vertex UID (as tail or head). Build once, query many times."""

    def __init__(self, dag: 'DAGType', include_excluded: bool = False):
        self._edges: List[Tuple[str, object]] = []      # (tail_uid, edge) in graph order
        self._by_uid: Dict[str, List[int]] = {}
        for vertex in dag.all_vertices:
            tail_uid = vertex.uid
            for edge in (vertex.edges or []):
                if not edge:
                    continue
                if not include_excluded and edge.edge_type in EXCLUDE_EDGE_TYPES:
                    continue
                position = len(self._edges)
                self._edges.append((tail_uid, edge))
                self._by_uid.setdefault(tail_uid, []).append(position)
                head_uid = edge.head_uid
                if head_uid != tail_uid:
                    self._by_uid.setdefault(head_uid, []).append(position)

    def __len__(self) -> int:
        return len(self._edges)

    def edges_for(self, uid: str) -> Iterator[Tuple[str, object]]:
        """(tail_uid, edge) of every edge that has *uid* as tail or head, in graph order."""
        for position in sorted(self._by_uid.get(uid, ())):
            yield self._edges[position]

    def all_edges(self) -> Iterator[Tuple[str, object]]:
        return iter(self._edges)


def extract_edge_contents(edge, tail_uid: str, params: 'KeeperParams', config_uid: str):
    """Attempt to return edge content as a serialisable value.

    For most edges the DAG's built-in decryption (decrypt=True default) is
    sufficient and content_as_dict works straight away.

    DATA edges encrypted directly with the vertex owner's record key
    (jit_settings, ai_settings pattern) are not covered by the normal
    vertex-keychain flow.  get_resource_settings() handles these correctly:
    it loads the graph keyed on the resource record's own key and also
    handles base64-encoded encrypted content.  It is only called when the
    fast content_as_dict path has already failed, to avoid unnecessary
    network round trips.

    config_uid is the PAM configuration that owns the DAG being traversed -
    passed from the caller so records not in the rotation cache are still
    handled correctly.
    """
    if edge.content is None:
        return None

    # Happy path: DAG already decrypted it.
    try:
        return edge.content_as_dict
    except Exception:
        pass

    # Fallback for DATA edges whose content the DAG keychain could not decrypt
    # (e.g. jit_settings / ai_settings encrypted with the resource's own record key).
    if edge.edge_type == EdgeType.DATA and edge.path and config_uid:
        try:
            result = get_resource_settings(params, tail_uid, edge.path, config_uid)
            if result is not None:
                return result
        except Exception:
            pass

    # Last resort: return as plain string (non-JSON content, e.g. a path label).
    # content_as_str can silently return bytes when .decode() fails, so check the type.
    try:
        s = edge.content_as_str
        if isinstance(s, str):
            return s
    except Exception:
        pass

    # All decode/decrypt attempts failed but content exists - return the first
    # 40 bytes as hex so the caller can tell there IS data vs truly absent.
    raw = edge.content
    if isinstance(raw, (bytes, str)):
        raw_bytes = raw if isinstance(raw, bytes) else raw.encode('latin-1', errors='replace')
        snippet = raw_bytes[:40].hex()
        truncated = len(raw_bytes) > 40
        return f'<raw_hex:{snippet}{"..." if truncated else ""}>'
    return None


def decode_edge_local(edge, tail_uid: str, params: 'KeeperParams'):
    """Decode the contents of an edge WITHOUT any network call.

    Like ``extract_edge_contents`` but the settings DATA edges encrypted with the resource's own record key
    (``jit_settings``, ``ai_settings``) are decrypted here, from the record key in the vault cache, instead of
    reloading the whole graph per resource (``get_resource_settings``). That is what a reader of thousands of
    resources needs. An edge that cannot be decoded gives its text or a ``<raw_hex:...>`` marker, as in the dump.
    """
    if edge.content is None:
        return None

    try:
        return edge.content_as_dict
    except Exception:
        pass

    if edge.edge_type == EdgeType.DATA:
        raw = edge.content
        if isinstance(raw, str):
            try:
                raw = base64.urlsafe_b64decode(raw + '==')
            except Exception:
                raw = None
        key = None
        try:
            key = get_record_key(params, tail_uid, raise_on_missing=False)
        except Exception:
            pass
        if isinstance(raw, bytes) and key and len(raw) >= 12:
            try:
                return json.loads(decrypt_aes(raw, key).decode('utf-8'))
            except Exception:
                pass

    try:
        text = edge.content_as_str
        if isinstance(text, str):
            return text
    except Exception:
        pass

    raw = edge.content
    if isinstance(raw, (bytes, str)):
        raw_bytes = raw if isinstance(raw, bytes) else raw.encode('latin-1', errors='replace')
        return f'<raw_hex:{raw_bytes[:40].hex()}{"..." if len(raw_bytes) > 40 else ""}>'
    return None


def decrypt_acl_pwd_complexity(contents, head_uid: str, tail_uid: str, params: 'KeeperParams') -> None:
    """Decrypt ``rotation_settings.pwd_complexity`` of an ACL edge in place.

    The field is AES-GCM encrypted with the owning record's key and base64-encoded.
    """
    if not isinstance(contents, dict):
        return
    rotation_settings = contents.get('rotation_settings')
    if not isinstance(rotation_settings, dict):
        return
    pwd_complexity_enc = rotation_settings.get('pwd_complexity')
    if not (pwd_complexity_enc and isinstance(pwd_complexity_enc, str)):
        return
    for uid in (head_uid, tail_uid):
        raw_rec = get_record_from_cache(params, uid) or {}
        rec_key = raw_rec.get('record_key_unencrypted')
        if not rec_key:
            try:
                rec_key = get_record_key(params, uid, raise_on_missing=False)
            except Exception:
                rec_key = None
        if not rec_key:
            continue
        try:
            enc_bytes = base64.b64decode(pwd_complexity_enc)
            rotation_settings['pwd_complexity'] = json.loads(decrypt_aes(enc_bytes, rec_key).decode('utf-8'))
            break
        except Exception:
            pass


def edge_to_dict(edge, tail_uid: str, params: 'KeeperParams', config_uid: str) -> dict:
    """One edge as plain data: head / tail, type, path, version, active flag and the decoded contents."""
    head_uid = edge.head_uid
    contents = extract_edge_contents(edge, tail_uid, params, config_uid)
    if edge.edge_type == EdgeType.ACL:
        decrypt_acl_pwd_complexity(contents, head_uid, tail_uid, params)
    edge_type_str = edge.edge_type.value if hasattr(edge.edge_type, 'value') else str(edge.edge_type)
    return {
        'head': head_uid,
        'tail': tail_uid,
        'edge_type': edge_type_str,
        'path': edge.path,
        'version': getattr(edge, 'version', 0),
        'active': edge.active,
        'contents': contents,
    }


def collect_edges_for_record(dag: 'DAGType', record_uid: str, params: 'KeeperParams', config_uid: str,
                             index: Optional[EdgeIndex] = None) -> List[dict]:
    """Return all non-deleted edges that reference record_uid as head or tail.

    Inactive edges (active=False) are included - they may represent settings
    that exist in the graph but have been superseded or are pending deletion.
    The 'active' and 'version' fields in each output dict let the caller tell the versions apart.
    DELETION and UNDENIAL edges are still excluded (bookkeeping, not data).
    """
    if index is None:
        index = EdgeIndex(dag)
    return [edge_to_dict(edge, tail_uid, params, config_uid) for tail_uid, edge in index.edges_for(record_uid)]


def collect_graph_entry(dag: 'DAGType', record_uid: str, params: 'KeeperParams', config_uid: str,
                        index: Optional[EdgeIndex] = None) -> dict:
    """Build the per-graph entry for record_uid.

    Returns a dict with zero or more of:
      "vertex_active": bool   - record_uid exists as a vertex in this graph
      "edges": [...]          - active, non-deleted edges referencing record_uid

    Returns an empty dict when the record has no presence in the graph at all,
    signalling the caller to omit this graph from the output.
    """
    entry: dict = {}

    # Check whether record_uid is itself a vertex in this graph (including lone vertices).
    vertex = dag.get_vertex(record_uid)
    if vertex is not None:
        entry['vertex_active'] = vertex.active

    edges = collect_edges_for_record(dag, record_uid, params, config_uid, index)
    if edges:
        entry['edges'] = edges

    return entry
