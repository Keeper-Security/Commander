from __future__ import annotations
import argparse
import base64
import datetime
import json
import logging
import pathlib
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from ..base import Command, FolderMixin
from ...subfolder import get_folder_uids
from ... import vault, api
from ...keeper_dag import DAG, EdgeType
from ...keeper_dag.types import PamGraphId
from ..pam_import.keeper_ai_settings import get_resource_settings
from ...keeper_dag.crypto import decrypt_aes
from . import get_connection

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...keeper_dag.dag import DAG as DAGType


ALL_GRAPH_IDS = [g.value for g in PamGraphId]

# DELETION means the edge is absent; UNDENIAL cancels a DENIAL (treated as absent)
_EXCLUDE_EDGE_TYPES = frozenset({EdgeType.DELETION, EdgeType.UNDENIAL})


class PAMDebugDumpCommand(Command):
    parser = argparse.ArgumentParser(prog='pam action debug dump')
    parser.add_argument('folder_uid', action='store',
                        help='Folder UID or path. Use empty string for the root folder.')
    parser.add_argument('--recursive', '-r', required=False, dest='recursive', action='store_true',
                        help='Include records in all subfolders.')
    parser.add_argument('--save-as', '-s', required=True, dest='save_as', action='store',
                        help='Output file path to save JSON results.')

    def get_parser(self):
        return PAMDebugDumpCommand.parser

    def execute(self, params: 'KeeperParams', **kwargs):
        folder_uid_arg = kwargs.get('folder_uid', '')
        recursive = kwargs.get('recursive', False)
        save_as = kwargs.get('save_as')

        def _write_result(data: list) -> None:
            p = pathlib.Path(save_as)
            if p.exists():
                counter = 1
                while True:
                    candidate = p.parent / f'{p.stem}.{counter}{p.suffix}'
                    if not candidate.exists():
                        p = candidate
                        break
                    counter += 1
            with open(p, 'w', encoding='utf-8') as fh:
                fh.write(json.dumps(data, indent=2))
            logging.info('Saved %d record(s) to %s', len(data), p)

        # 1. Resolve folder UID(s) from UID or path
        folder_uids = get_folder_uids(params, folder_uid_arg)
        if not folder_uids:
            logging.warning('Cannot resolve folder: %r', folder_uid_arg)
            _write_result([])
            return

        # 2. Collect records with folder context
        # record_uid → (folder_uid, folder_parent_uid)
        record_folder_map: Dict[str, Tuple[str, str]] = {}

        if recursive:
            def _on_folder(f):
                f_uid = f.uid or ''
                f_parent_uid = getattr(f, 'parent_uid', None) or ''
                for rec_uid in params.subfolder_record_cache.get(f_uid, set()):
                    if rec_uid not in record_folder_map:
                        record_folder_map[rec_uid] = (f_uid, f_parent_uid)

            for fuid in folder_uids:
                FolderMixin.traverse_folder_tree(params, fuid, _on_folder)
        else:
            for fuid in folder_uids:
                if fuid:
                    folder_node = params.folder_cache.get(fuid)
                    f_parent_uid = getattr(folder_node, 'parent_uid', None) or '' if folder_node else ''
                else:
                    # root folder has no parent
                    f_parent_uid = ''
                for rec_uid in params.subfolder_record_cache.get(fuid, set()):
                    if rec_uid not in record_folder_map:
                        record_folder_map[rec_uid] = (fuid, f_parent_uid)

        if not record_folder_map:
            _write_result([])
            return

        # 3. Filter by version, then group valid records by config_uid.
        # Supported versions: 3 (typed), 5 (KSM App/Gateway), 6 (PAM Configuration).
        # Versions 1–2/4 are legacy/attachment records; skip with a warning.
        config_to_records: Dict[str, List[str]] = {}
        record_config_map: Dict[str, Optional[str]] = {}
        valid_uids: List[str] = []  # passed version filter, in discovery order

        for rec_uid in record_folder_map:
            rec = params.record_cache.get(rec_uid)
            if rec is None:
                logging.warning('skipping record %s version unknown - not in record cache', rec_uid)
                continue

            version = rec.get('version')
            if version is None or version <= 2:
                logging.warning(
                    'skipping record %s version %s - PAM records have version >= 3',
                    rec_uid, version
                )
                continue

            valid_uids.append(rec_uid)

            # v6 PAM Configuration records ARE their own graph root — no rotation-cache entry exists for them.
            if version == 6:
                config_to_records.setdefault(rec_uid, []).append(rec_uid)
                record_config_map[rec_uid] = rec_uid
                continue

            rotation = params.record_rotation_cache.get(rec_uid)
            if rotation is not None:
                config_uid = rotation.get('configuration_uid')
                if config_uid:
                    config_to_records.setdefault(config_uid, []).append(rec_uid)
                    record_config_map[rec_uid] = config_uid
                    continue

            logging.debug('Record %s not found in rotation cache; rotation config unavailable, ', rec_uid)
            record_config_map[rec_uid] = None

        if not valid_uids:
            _write_result([])
            return

        # 4. Load all 5 DAGs once per config_uid
        # keyed by (config_uid, graph_id)
        dag_cache: Dict[Tuple[str, int], Optional['DAGType']] = {}
        conn = get_connection(params)

        for config_uid in config_to_records:
            config_record = vault.KeeperRecord.load(params, config_uid)
            if config_record is None:
                logging.error('Configuration record %s not found; skipping graph load.', config_uid)
                for graph_id in ALL_GRAPH_IDS:
                    dag_cache[(config_uid, graph_id)] = None
                continue

            for graph_id in ALL_GRAPH_IDS:
                try:
                    dag = DAG(conn=conn, record=config_record, graph_id=graph_id,
                              fail_on_corrupt=False, logger=logging)
                    dag.load(sync_point=0)
                    dag_cache[(config_uid, graph_id)] = dag
                except Exception as err:
                    logging.error('Failed to load graph %d for config %s: %s', graph_id, config_uid, err)
                    dag_cache[(config_uid, graph_id)] = None

        # 5. Build per-record output
        result = []

        for rec_uid in valid_uids:
            folder_uid, folder_parent_uid = record_folder_map[rec_uid]
            rec = params.record_cache[rec_uid]  # guaranteed present after step 3
            version = rec.get('version')
            shared = rec.get('shared', False)
            revision = rec.get('revision', 0)

            client_modified_time = None
            cmt = rec.get('client_modified_time')
            if isinstance(cmt, (int, float)):
                client_modified_time = datetime.datetime.fromtimestamp(int(cmt / 1000)).isoformat()

            metadata = {
                'uid': rec_uid,
                'folder_uid': folder_uid,
                'folder_uid_parent': folder_parent_uid,
                'version': version,
                'shared': shared,
                'client_modified_time': client_modified_time,
                'revision': revision,
            }

            # data — same structure as `get --format=json`
            data = {}
            try:
                r = api.get_record(params, rec_uid)
                if r:
                    raw = rec.get('data_unencrypted', b'{}')
                    data = json.loads(raw.decode() if isinstance(raw, bytes) else raw)
                    if r.notes:
                        data['notes'] = r.notes
            except Exception as err:
                logging.warning('Could not build data for record %s: %s', rec_uid, err)

            # graph_sync — dict keyed by config_uid, then by graph name.
            # A record may be referenced by more than one PAM Configuration; we query
            # every already-loaded DAG so cross-config references are captured.
            # Inner value may contain:
            #   "vertex_active": bool  — present when the record UID is a vertex in that graph
            #   "edges": [...]         — present only when there are active, non-deleted edges
            # Config/graph keys are omitted when the record has no presence there.
            graph_sync: Dict[str, Dict[str, dict]] = {}
            for (c_uid, graph_id), dag in dag_cache.items():
                if dag is None:
                    continue
                try:
                    graph_entry = _collect_graph_entry(dag, rec_uid, params, c_uid)
                    if graph_entry:
                        graph_name = PamGraphId(graph_id).name
                        graph_sync.setdefault(c_uid, {})[graph_name] = graph_entry
                except Exception as err:
                    logging.warning('Error collecting graph data for record %s graph %d config %s: %s',
                                    rec_uid, graph_id, c_uid, err)

            result.append({
                'uid': rec_uid,
                'metadata': metadata,
                'data': data,
                'graph_sync': graph_sync,
            })

        _write_result(result)


def _collect_graph_entry(dag: 'DAGType', record_uid: str, params: 'KeeperParams',
                         config_uid: str) -> dict:
    """Build the per-graph entry for record_uid.

    Returns a dict with zero or more of:
      "vertex_active": bool   — record_uid exists as a vertex in this graph
      "edges": [...]          — active, non-deleted edges referencing record_uid

    Returns an empty dict when the record has no presence in the graph at all,
    signalling the caller to omit this graph from the output.
    """
    entry: dict = {}

    # Check whether record_uid is itself a vertex in this graph (including lone vertices).
    vertex = dag.get_vertex(record_uid)
    if vertex is not None:
        entry['vertex_active'] = vertex.active

    edges = _collect_edges_for_record(dag, record_uid, params, config_uid)
    if edges:
        entry['edges'] = edges

    return entry


def _collect_edges_for_record(dag: 'DAGType', record_uid: str, params: 'KeeperParams',
                               config_uid: str) -> List[dict]:
    """Return all non-deleted edges that reference record_uid as head or tail.

    Inactive edges (active=False) are included — they may represent settings
    that exist in the graph but have been superseded or are pending deletion.
    The 'active' field in each output dict lets the caller distinguish them.
    DELETION and UNDENIAL edges are still excluded (bookkeeping, not data).
    """
    edges_out = []
    for vertex in dag.all_vertices:
        tail_uid = vertex.uid
        for edge in (vertex.edges or []):
            if not edge:
                continue
            if edge.edge_type in _EXCLUDE_EDGE_TYPES:
                continue
            head_uid = edge.head_uid
            if tail_uid != record_uid and head_uid != record_uid:
                continue

            contents = _extract_edge_contents(edge, tail_uid, params, config_uid)

            # ACL edges may carry a rotation_settings.pwd_complexity field that is
            # AES-GCM encrypted with the owning record's key and base64-encoded.
            # Decrypt it in-place so callers see the plaintext complexity rules.
            if edge.edge_type == EdgeType.ACL and isinstance(contents, dict):
                rotation_settings = contents.get('rotation_settings')
                if isinstance(rotation_settings, dict):
                    pwd_complexity_enc = rotation_settings.get('pwd_complexity')
                    if pwd_complexity_enc and isinstance(pwd_complexity_enc, str):
                        for uid in (head_uid, tail_uid):
                            raw_rec = params.record_cache.get(uid) or {}
                            rec_key = raw_rec.get('record_key_unencrypted')
                            if not rec_key:
                                continue
                            try:
                                enc_bytes = base64.b64decode(pwd_complexity_enc)
                                rotation_settings['pwd_complexity'] = json.loads(
                                    decrypt_aes(enc_bytes, rec_key).decode('utf-8')
                                )
                                break
                            except Exception:
                                pass

            edge_type_str = edge.edge_type.value if hasattr(edge.edge_type, 'value') else str(edge.edge_type)
            edges_out.append({
                'head': head_uid,
                'tail': tail_uid,
                'edge_type': edge_type_str,
                'path': edge.path,
                'active': edge.active,
                'contents': contents,
            })
    return edges_out


def _extract_edge_contents(edge, tail_uid: str, params: 'KeeperParams', config_uid: str):
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

    config_uid is the PAM configuration that owns the DAG being traversed —
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

    # All decode/decrypt attempts failed but content exists — return the first
    # 40 bytes as hex so the caller can tell there IS data vs truly absent.
    raw = edge.content
    if isinstance(raw, (bytes, str)):
        raw_bytes = raw if isinstance(raw, bytes) else raw.encode('latin-1', errors='replace')
        snippet = raw_bytes[:40].hex()
        truncated = len(raw_bytes) > 40
        return f'<raw_hex:{snippet}{"..." if truncated else ""}>'
    return None
