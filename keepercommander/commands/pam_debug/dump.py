from __future__ import annotations
import argparse
import datetime
import json
import logging
import pathlib
import sys
from typing import TYPE_CHECKING, Iterable

from ..base import Command, FolderMixin
from ...subfolder import get_folder_uids
from ... import vault
from ...keeper_dag import DAG
from ...keeper_dag.types import GRAPH_ID_TO_ENDPOINT, PamGraphId
from ...nested_share_folder.common import get_record_from_cache
from ..pam.vault_target import resolve_pam_folder_uid
from ..pam_import.nsf_helpers import get_folder_record_uids
from ...error import CommandError
from . import get_connection, load_pam_record
from .graph_edges import EdgeIndex, collect_graph_entry
from .record_state import record_json, rotation_info

if TYPE_CHECKING:
    from ...params import KeeperParams


ALL_GRAPH_IDS = [g.value for g in PamGraphId]
MAX_SERVICE_MODE_DUMP_RECORDS = 1000
MAX_SERVICE_MODE_DUMP_CONFIGS = 20


class PAMDebugDumpCommand(Command):
    parser = argparse.ArgumentParser(
        prog='pam action debug dump',
        description='Dump folder records and GraphSync data as JSON.')
    parser.add_argument('folder_uid', action='store',
                        help='Folder UID or path. Use empty string for the root folder.')
    parser.add_argument('--recursive', '-r', required=False, dest='recursive', action='store_true',
                        help='Include records in all subfolders.')
    parser.add_argument('--format', choices=['json'],
                        help='Emit JSON to stdout (or the Service Mode API response).')
    parser.add_argument('--save-as', '-s', required=False, dest='save_as', action='store',
                        help='Output file path to save JSON results.')

    def get_parser(self):
        return PAMDebugDumpCommand.parser

    def execute(self, params: 'KeeperParams', **kwargs):
        folder_uid_arg = kwargs.get('folder_uid', '')
        recursive = kwargs.get('recursive', False)
        save_as = kwargs.get('save_as')
        output_format = kwargs.get('format')

        from ...importer.imp_exp import is_export_restricted
        if is_export_restricted(params):
            raise CommandError(
                'pam action debug dump',
                'PAM debug dump is disabled by enterprise export restrictions.',
            )

        if getattr(params, 'service_mode', False):
            if save_as is not None or output_format != 'json':
                raise CommandError(
                    'pam action debug dump',
                    'Service Mode allows only JSON output in the API response; '
                    'do not specify --save-as/-s.',
                )
            folder_cache = getattr(params, 'folder_cache', {}) or {}
            nsf_folders = getattr(params, 'nested_share_folders', {}) or {}
            if folder_uid_arg not in folder_cache and folder_uid_arg not in nsf_folders:
                raise CommandError(
                    'pam action debug dump',
                    'Service Mode requires a visible folder UID.',
                )
        elif save_as is None and output_format != 'json':
            raise CommandError(
                'pam action debug dump',
                'Specify --save-as/-s FILE or --format=json.',
            )

        def _write_result(rows: Iterable[dict]) -> None:
            def _write_json_array(stream) -> int:
                encoder = json.JSONEncoder(indent=2)
                count = 0
                stream.write('[')
                for row in rows:
                    stream.write('\n' if count == 0 else ',\n')
                    at_line_start = True
                    for chunk in encoder.iterencode(row):
                        for part in chunk.splitlines(keepends=True):
                            if at_line_start:
                                stream.write('  ')
                            stream.write(part)
                            at_line_start = part.endswith('\n')
                    count += 1
                if count:
                    stream.write('\n')
                stream.write(']\n')
                return count

            if save_as is None:
                _write_json_array(sys.stdout)
                return

            p = pathlib.Path(save_as)
            if p.exists():
                counter = 1
                while True:
                    candidate = p.parent / f'{p.stem}.{counter}{p.suffix}'
                    if not candidate.exists():
                        p = candidate
                        break
                    counter += 1
            data = list(rows)
            with open(p, 'w', encoding='utf-8') as fh:
                json.dump(data, fh, indent=2)
            logging.info('Saved %d record(s) to %s', len(data), p)

        # 1. Resolve folder UID(s) from UID or path (classic + NSF)
        folder_uids = get_folder_uids(params, folder_uid_arg)
        if not folder_uids:
            resolved = resolve_pam_folder_uid(params, folder_uid_arg)
            if resolved:
                folder_uids = {resolved}
            elif folder_uid_arg in getattr(params, 'nested_share_folders', {}):
                folder_uids = {folder_uid_arg}
        if not folder_uids:
            logging.warning('Cannot resolve folder: %r', folder_uid_arg)
            _write_result([])
            return

        # 2. Collect records with folder context
        # record_uid → (folder_uid, folder_parent_uid)
        record_folder_map: dict[str, tuple[str, str]] = {}

        def _folder_parent_uid(f_uid: str) -> str:
            if not f_uid:
                return ''
            folder_node = params.folder_cache.get(f_uid)
            if folder_node is not None:
                return getattr(folder_node, 'parent_uid', None) or ''
            nsf = getattr(params, 'nested_share_folders', {}).get(f_uid) or {}
            return nsf.get('parent_uid') or ''

        if recursive:
            def _on_folder(f):
                f_uid = f.uid or ''
                f_parent_uid = getattr(f, 'parent_uid', None) or ''
                for rec_uid in get_folder_record_uids(params, f_uid):
                    if rec_uid not in record_folder_map:
                        record_folder_map[rec_uid] = (f_uid, f_parent_uid)

            for fuid in folder_uids:
                FolderMixin.traverse_folder_tree(params, fuid, _on_folder)
                # NSF folders may not yet be reconstructed into folder_cache nodes;
                # walk nested_share_folders children as a fallback.
                nsf_folders = getattr(params, 'nested_share_folders', {}) or {}
                if fuid in nsf_folders or any(v.get('parent_uid') == fuid for v in nsf_folders.values()):
                    stack = [fuid]
                    seen = set()
                    while stack:
                        current = stack.pop()
                        if not current or current in seen:
                            continue
                        seen.add(current)
                        for rec_uid in get_folder_record_uids(params, current):
                            if rec_uid not in record_folder_map:
                                record_folder_map[rec_uid] = (current, _folder_parent_uid(current))
                        for child_uid, child in nsf_folders.items():
                            if child.get('parent_uid') == current and child_uid not in seen:
                                stack.append(child_uid)
        else:
            for fuid in folder_uids:
                f_parent_uid = _folder_parent_uid(fuid)
                for rec_uid in get_folder_record_uids(params, fuid):
                    if rec_uid not in record_folder_map:
                        record_folder_map[rec_uid] = (fuid, f_parent_uid)

        if not record_folder_map:
            _write_result([])
            return

        if (getattr(params, 'service_mode', False)
                and len(record_folder_map) > MAX_SERVICE_MODE_DUMP_RECORDS):
            raise CommandError(
                'pam action debug dump',
                f'Service Mode PAM debug dumps are limited to '
                f'{MAX_SERVICE_MODE_DUMP_RECORDS} folder records. '
                'Use a smaller folder scope or omit --recursive.',
            )

        # 3. Filter by version, then group valid records by config_uid.
        # Supported versions: 3 (typed), 5 (KSM App/Gateway), 6 (PAM Configuration).
        # Versions 1–2/4 are legacy/attachment records; skip with a warning.
        config_to_records: dict[str, list[str]] = {}
        record_configs: dict[str, set[str]] = {}
        valid_uids: list[str] = []  # passed version filter, in discovery order
        unavailable_record_uids: list[str] = []

        for rec_uid in record_folder_map:
            rec = get_record_from_cache(params, rec_uid)
            if rec is None:
                loaded = load_pam_record(params, rec_uid)
                if loaded is None:
                    logging.warning('skipping record %s version unknown - not in record cache', rec_uid)
                    unavailable_record_uids.append(rec_uid)
                    continue
                version = getattr(loaded, 'version', None)
                rec = {'version': version, 'revision': 0, 'shared': False}
            else:
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
                record_configs.setdefault(rec_uid, set()).add(rec_uid)
                continue

            rotation = params.record_rotation_cache.get(rec_uid)
            config_uid = rotation.get('configuration_uid') if rotation else None

            # Two fallback tiers when rotation cache has no entry (e.g. records that
            # are only linked via launch-credential / ACL, never rotated):
            #   1. Local vault scan of `pamResources.resourceRef`.
            #   2. krouter `/api/user/graph-sync/pam/get_leafs` — same call WV uses;
            #      finds the stream root even when the local resourceRef is missing.
            if not config_uid:
                from ..tunnel.port_forward.tunnel_helpers import (
                    get_config_uid_from_local_vault,
                    get_config_uid_via_pam_link,
                )
                config_uid = (
                    get_config_uid_from_local_vault(params, rec_uid)
                    or get_config_uid_via_pam_link(params, rec_uid)
                )

            if config_uid:
                config_to_records.setdefault(config_uid, []).append(rec_uid)
                record_configs.setdefault(rec_uid, set()).add(config_uid)
                continue

            logging.debug('Record %s: no rotation entry, no local vault config, '
                          'no krouter leafs match; graph data unavailable.', rec_uid)
            record_configs.setdefault(rec_uid, set())

        unavailable_folders = sorted({
            record_folder_map[uid][0] for uid in unavailable_record_uids
        })

        if not valid_uids:
            if getattr(params, 'service_mode', False):
                _write_result(_build_unavailable_rows(unavailable_folders))
            else:
                _write_result([])
            return

        if (getattr(params, 'service_mode', False)
                and len(config_to_records) > MAX_SERVICE_MODE_DUMP_CONFIGS):
            raise CommandError(
                'pam action debug dump',
                f'Service Mode PAM debug dumps are limited to '
                f'{MAX_SERVICE_MODE_DUMP_CONFIGS} PAM configurations. '
                'Use a smaller folder scope or omit --recursive.',
            )

        # 4. Load all 5 DAGs once per config_uid
        # keyed by (config_uid, graph_id)
        dag_cache: dict[tuple[str, int], 'DAG | None'] = {}
        # The edges of each loaded graph indexed by vertex UID, built once (not scanned per record).
        edge_indexes: dict[tuple[str, int], EdgeIndex] = {}
        graph_load_errors: dict[tuple[str, int], dict] = {}
        config_load_errors: dict[str, dict] = {}
        conn = get_connection(params)

        for config_uid in config_to_records:
            config_record = load_pam_record(params, config_uid)
            if config_record is None:
                logging.error('Configuration record %s not found; skipping graph load.', config_uid)
                config_load_errors[config_uid] = {
                    'stage': 'graph_sync',
                    'config_uid': config_uid,
                    'message': 'PAM configuration record could not be loaded.',
                }
                for graph_id in ALL_GRAPH_IDS:
                    dag_cache[(config_uid, graph_id)] = None
                continue

            for graph_id in ALL_GRAPH_IDS:
                try:
                    endpoint = GRAPH_ID_TO_ENDPOINT[graph_id]
                    dag = DAG(conn=conn, record=config_record,
                              read_endpoint=endpoint, write_endpoint=endpoint,
                              fail_on_corrupt=False, logger=logging)
                    dag.load(sync_point=0)
                    dag_cache[(config_uid, graph_id)] = dag
                    edge_indexes[(config_uid, graph_id)] = EdgeIndex(dag)
                except Exception as err:
                    logging.error('Failed to load graph %d for config %s: %s', graph_id, config_uid, err)
                    dag_cache[(config_uid, graph_id)] = None
                    graph_load_errors[(config_uid, graph_id)] = {
                        'stage': 'graph_sync',
                        'config_uid': config_uid,
                        'graph': PamGraphId(graph_id).name,
                        'message': 'Graph data could not be loaded.',
                    }

        # 5. Build per-record output
        def _build_row(rec_uid: str) -> dict:
            folder_uid, folder_parent_uid = record_folder_map[rec_uid]
            rec = get_record_from_cache(params, rec_uid) or {}
            nsf_meta = getattr(params, 'nested_share_records', {}).get(rec_uid) or {}
            version = rec.get('version') or nsf_meta.get('version')
            shared = rec.get('shared', nsf_meta.get('shared', False))
            revision = rec.get('revision', nsf_meta.get('revision', 0))

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

            # data - same structure as `get --format=json` (classic + NSF)
            data, record_errors = record_json(params, rec_uid)

            # graph_sync - dict keyed by config_uid, then by graph name.
            # A record may be referenced by more than one PAM Configuration; we query
            # every already-loaded DAG so cross-config references are captured.
            # Inner value may contain:
            #   "vertex_active": bool  - present when the record UID is a vertex in that graph
            #   "edges": [...]         - present only when there are active, non-deleted edges
            # Config/graph keys are omitted when the record has no presence there.
            graph_sync: dict[str, dict[str, dict]] = {}
            configs_for_record = record_configs.get(rec_uid, set())
            if not configs_for_record:
                record_errors.append({
                    'stage': 'graph_sync',
                    'message': 'No PAM configuration could be resolved; graph data is unavailable.',
                })

            for (c_uid, graph_id), dag in dag_cache.items():
                if dag is None:
                    if c_uid in configs_for_record:
                        error = (config_load_errors.get(c_uid)
                                 or graph_load_errors.get((c_uid, graph_id)))
                        if error and error not in record_errors:
                            record_errors.append(error)
                    continue
                try:
                    graph_entry = collect_graph_entry(dag, rec_uid, params, c_uid,
                                                      edge_indexes.get((c_uid, graph_id)))
                    if graph_entry:
                        graph_name = PamGraphId(graph_id).name
                        graph_sync.setdefault(c_uid, {})[graph_name] = graph_entry
                except Exception as err:
                    logging.warning('Error collecting graph data for record %s graph %d config %s: %s',
                                    rec_uid, graph_id, c_uid, err)
                    record_errors.append({
                        'stage': 'graph_sync',
                        'config_uid': c_uid,
                        'graph': PamGraphId(graph_id).name,
                        'message': 'Graph data could not be collected for this record.',
                    })

            row = {
                'uid': rec_uid,
                'metadata': metadata,
                'data': data,
                'graph_sync': graph_sync,
            }
            # Rotation settings live in the vault cache, not in the graph.
            rotation = rotation_info(params, rec_uid)
            if rotation:
                row['rotation'] = rotation
            if record_errors:
                row['errors'] = record_errors
            return row

        def _iter_rows():
            for uid in valid_uids:
                yield _build_row(uid)
            if getattr(params, 'service_mode', False):
                yield from _build_unavailable_rows(unavailable_folders)

        _write_result(_iter_rows())


def _build_unavailable_rows(folder_uids: Iterable[str]):
    """Return anonymous error rows so Service Mode never echoes a hidden UID."""
    for folder_uid in folder_uids:
        yield {
            'uid': None,
            'metadata': {
                'uid': None,
                'folder_uid': folder_uid,
                'folder_uid_parent': None,
                'version': None,
                'shared': None,
                'client_modified_time': None,
                'revision': None,
            },
            'data': {},
            'graph_sync': {},
            'errors': [{
                'stage': 'record_data',
                'message': 'One or more folder records could not be loaded.',
            }],
        }
