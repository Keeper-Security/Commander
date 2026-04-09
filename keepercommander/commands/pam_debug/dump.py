from __future__ import annotations
import argparse
import base64
import datetime
import json
import logging
import pathlib
import re
from typing import AbstractSet, Dict, List, Optional, Set, Tuple, TYPE_CHECKING

from ..base import Command, FolderMixin
from ..pam.router_helper import get_dag_leafs
from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens
from ...subfolder import (
    get_folder_uids,
    SharedFolderFolderNode,
    SharedFolderNode,
)
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

# Keep in sync with RecordGetCommand.include_dag valid_record_types (record.py).
_PAM_ROUTER_RESOLVE_TYPES = frozenset({
    'pamDatabase', 'pamDirectory', 'pamMachine', 'pamUser', 'pamRemoteBrowser',
})

# DELETION means the edge is absent; UNDENIAL cancels a DENIAL (treated as absent)
_EXCLUDE_EDGE_TYPES = frozenset({EdgeType.DELETION, EdgeType.UNDENIAL})


def _resolve_pam_configuration_uid_via_router(
    params: 'KeeperParams',
    encrypted_session_token: bytes,
    encrypted_transmission_key: bytes,
    record_uid: str,
) -> Optional[str]:
    """Return PAM configuration UID from KRouter get_leafs, or None. Logs failures at debug only."""
    try:
        rs = get_dag_leafs(params, encrypted_session_token, encrypted_transmission_key, record_uid)
        if not rs:
            return None
        first = rs[0]
        if not isinstance(first, dict):
            return None
        val = first.get('value', '') or ''
        return val if val else None
    except Exception as ex:
        logging.debug('get_dag_leafs failed for %s: %s', record_uid, ex)
        return None


_PAM_CONFIGURATION_TYPE = re.compile(r'pam.+Configuration', re.IGNORECASE)


def _eligible_shared_folder_roots_for_root_fallback(
    params: 'KeeperParams', folder_uids: AbstractSet[Optional[str]],
) -> Set[str]:
    """Shared-folder UIDs for which we may attach pam*Configuration records from that folder's vault root.

    Includes: dump target is a subfolder inside a shared folder, or the shared folder node itself
    (v6 configs often sit on the shared-folder root, not in subfolders).
    """
    roots: Set[str] = set()
    for fuid in folder_uids:
        if not fuid:
            continue
        node = params.folder_cache.get(fuid)
        if isinstance(node, SharedFolderFolderNode):
            suid = getattr(node, 'shared_folder_uid', None) or ''
            if suid:
                roots.add(suid)
        elif isinstance(node, SharedFolderNode):
            roots.add(node.uid)
    return roots


def _shared_folder_uid_containing_folder(params: 'KeeperParams', folder_uid: str) -> Optional[str]:
    """Walk parents from folder_uid to the enclosing shared-folder scope UID."""
    node = params.folder_cache.get(folder_uid)
    while node:
        if isinstance(node, SharedFolderFolderNode):
            return getattr(node, 'shared_folder_uid', None) or None
        if isinstance(node, SharedFolderNode):
            return node.uid
        pid = getattr(node, 'parent_uid', None) or ''
        if not pid:
            break
        node = params.folder_cache.get(pid)
    return None


def _v6_pam_configuration_uids_in_folder(params: 'KeeperParams', folder_uid: str) -> List[str]:
    """v6 typed records at folder_uid whose type matches pam*Configuration (vault root of a shared folder)."""
    out: List[str] = []
    for rec_uid in params.subfolder_record_cache.get(folder_uid, set()):
        raw = params.record_cache.get(rec_uid)
        if not raw or raw.get('version') != 6:
            continue
        kr = vault.KeeperRecord.load(params, rec_uid)
        if kr and _PAM_CONFIGURATION_TYPE.search(kr.record_type or ''):
            out.append(rec_uid)
    return out


def _apply_shared_folder_root_config_fallback(
    params: 'KeeperParams',
    sf_roots: Set[str],
    record_folder_map: Dict[str, Tuple[str, str]],
    valid_uids: List[str],
    config_to_records: Dict[str, List[str]],
    record_config_map: Dict[str, Optional[str]],
    record_config_source_map: Dict[str, Optional[str]],
) -> None:
    """Use a sole v6 pam*Configuration at shared-folder root when dump scope is that shared folder."""
    if not sf_roots:
        return

    configs_by_sf: Dict[str, List[str]] = {}
    for sf_root in sf_roots:
        cfgs = _v6_pam_configuration_uids_in_folder(params, sf_root)
        if cfgs:
            configs_by_sf[sf_root] = cfgs
        if len(cfgs) > 1:
            logging.warning(
                'PAM debug dump: %d pam*Configuration records at shared folder %s root; cannot pick one '
                'automatically for shared_folder_folder dumps',
                len(cfgs),
                sf_root,
            )

    for rec_uid in valid_uids:
        if record_config_map.get(rec_uid):
            continue
        kr = vault.KeeperRecord.load(params, rec_uid)
        if not kr or kr.record_type not in _PAM_ROUTER_RESOLVE_TYPES:
            continue
        folder_uid = record_folder_map[rec_uid][0]
        rec_sf = _shared_folder_uid_containing_folder(params, folder_uid)
        if not rec_sf or rec_sf not in sf_roots:
            continue
        candidates = configs_by_sf.get(rec_sf, [])
        if len(candidates) == 1:
            cfg = candidates[0]
            config_to_records.setdefault(cfg, []).append(rec_uid)
            record_config_map[rec_uid] = cfg
            record_config_source_map[rec_uid] = 'shared_folder_root'


def _pam_config_unresolved_reason(
    params: 'KeeperParams',
    rec_uid: str,
    folder_uid: str,
    record_config_map: Dict[str, Optional[str]],
    eligible_sf_roots: Set[str],
    resolve_online: bool,
    sf_uid: Optional[str],
    root_cfgs: List[str],
) -> Optional[str]:
    """Why pam_config_uid is null; None when resolved."""
    if record_config_map.get(rec_uid):
        return None
    kr = vault.KeeperRecord.load(params, rec_uid)
    if not kr or kr.record_type not in _PAM_ROUTER_RESOLVE_TYPES:
        return 'not_pam_graph_resource_type'
    if not sf_uid:
        return 'online_resolution_failed' if resolve_online else 'not_in_shared_folder'
    if sf_uid not in eligible_sf_roots:
        return 'dump_scope_excludes_shared_folder_root_fallback'
    if len(root_cfgs) == 0:
        return 'no_pam_configuration_at_shared_folder_root'
    if len(root_cfgs) > 1:
        return 'ambiguous_pam_configuration_at_shared_folder_root'
    # Exactly one pam*Configuration at root and dump scope includes this SF — should be resolved offline.
    return 'online_resolution_failed' if resolve_online else 'unexpected_unresolved'


class PAMDebugDumpCommand(Command):
    parser = argparse.ArgumentParser(prog='pam action debug dump')
    parser.add_argument('folder_uid', action='store',
                        help='Folder UID or path. Use empty string for the root folder.')
    parser.add_argument('--recursive', '-r', required=False, dest='recursive', action='store_true',
                        help='Include records in all subfolders.')
    parser.add_argument('--save-as', '-s', required=True, dest='save_as', action='store',
                        help='Output file path to save JSON results.')
    parser.add_argument(
        '--resolve-online', '-o',
        required=False,
        dest='resolve_online',
        action='store_true',
        help=(
            'Contact KRouter (online) to resolve the PAM Configuration UID for resources when it cannot '
            'be resolved locally (graph_sync would be empty) - ex. a shared PAM resource '
            'where the Configuration record is not shared or not in the local vault.'
        ),
    )

    def get_parser(self):
        return PAMDebugDumpCommand.parser

    def execute(self, params: 'KeeperParams', **kwargs):
        folder_uid_arg = kwargs.get('folder_uid', '')
        recursive = kwargs.get('recursive', False)
        save_as = kwargs.get('save_as')
        resolve_online = kwargs.get('resolve_online', False)

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
        record_config_source_map: Dict[str, Optional[str]] = {}
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

            # v6 PAM Configuration records ARE their own graph root - no rotation-cache entry exists for them.
            if version == 6:
                config_to_records.setdefault(rec_uid, []).append(rec_uid)
                record_config_map[rec_uid] = rec_uid
                record_config_source_map[rec_uid] = 'v6_configuration'
                continue

            rotation = params.record_rotation_cache.get(rec_uid)
            if rotation is not None:
                config_uid = rotation.get('configuration_uid')
                if config_uid:
                    config_to_records.setdefault(config_uid, []).append(rec_uid)
                    record_config_map[rec_uid] = config_uid
                    record_config_source_map[rec_uid] = 'rotation_cache'
                    continue

            logging.debug('Record %s not found in rotation cache; rotation config unavailable, ', rec_uid)
            record_config_map[rec_uid] = None
            record_config_source_map[rec_uid] = None

        if not valid_uids:
            _write_result([])
            return

        eligible_sf_roots = _eligible_shared_folder_roots_for_root_fallback(params, folder_uids)

        # 3a. Shared-folder dumps: v6 pam*Configuration often lives on shared-folder root, not subfolders
        _apply_shared_folder_root_config_fallback(
            params,
            eligible_sf_roots,
            record_folder_map,
            valid_uids,
            config_to_records,
            record_config_map,
            record_config_source_map,
        )

        # 3b. Optional KRouter lookup for PAM resources still missing configuration_uid
        if resolve_online:
            to_resolve = []
            for rec_uid in valid_uids:
                if record_config_map.get(rec_uid):
                    continue
                kr = vault.KeeperRecord.load(params, rec_uid)
                if kr and kr.record_type in _PAM_ROUTER_RESOLVE_TYPES:
                    to_resolve.append(rec_uid)
            if to_resolve:
                est, etk, _ = get_keeper_tokens(params)
                for rec_uid in to_resolve:
                    config_uid = _resolve_pam_configuration_uid_via_router(params, est, etk, rec_uid)
                    if config_uid:
                        config_to_records.setdefault(config_uid, []).append(rec_uid)
                        record_config_map[rec_uid] = config_uid
                        record_config_source_map[rec_uid] = 'router'

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

            # data - same structure as `get --format=json`
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

            # graph_sync - dict keyed by config_uid, then by graph name.
            # A record may be referenced by more than one PAM Configuration; we query
            # every already-loaded DAG so cross-config references are captured.
            # Inner value may contain:
            #   "vertex_active": bool  - present when the record UID is a vertex in that graph
            #   "edges": [...]         - present only when there are active, non-deleted edges
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

            sf_uid = _shared_folder_uid_containing_folder(params, folder_uid)
            root_cfgs = _v6_pam_configuration_uids_in_folder(params, sf_uid) if sf_uid else []
            unresolved = _pam_config_unresolved_reason(
                params,
                rec_uid,
                folder_uid,
                record_config_map,
                eligible_sf_roots,
                resolve_online,
                sf_uid,
                root_cfgs,
            )

            result.append({
                'uid': rec_uid,
                'pam_config_uid': record_config_map.get(rec_uid),
                'pam_config_uid_source': record_config_source_map.get(rec_uid),
                'pam_config_unresolved_reason': unresolved,
                'metadata': metadata,
                'data': data,
                'graph_sync': graph_sync,
            })

        _write_result(result)


def _collect_graph_entry(dag: 'DAGType', record_uid: str, params: 'KeeperParams',
                         config_uid: str) -> dict:
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

    edges = _collect_edges_for_record(dag, record_uid, params, config_uid)
    if edges:
        entry['edges'] = edges

    return entry


def _collect_edges_for_record(dag: 'DAGType', record_uid: str, params: 'KeeperParams',
                               config_uid: str) -> List[dict]:
    """Return all non-deleted edges that reference record_uid as head or tail.

    Inactive edges (active=False) are included - they may represent settings
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
