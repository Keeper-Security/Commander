"""Batch PAM import/extend engine — Step 0b through Step 2 pipeline."""
from __future__ import annotations

import logging
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from itertools import chain
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from ... import api, utils, vault
from ...display import bcolors
from ...importer import imp_exp
from ...proto import record_pb2
from ...record_management import add_record_to_folder
from ...recordv3 import RecordV3
from ..pam._layer_b import clear_layer_b_feature_cache, set_layer_b_force_legacy
from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens
from ..tunnel.port_forward.TunnelGraph import TunnelDAG
from .base import (
    LoginUserObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamMachineObject,
    PamRemoteBrowserObject,
    PamUserObject,
    get_sftp_attribute,
)
from .batch_attachments import run_step_1c_for_objects
from .batch_nsf import (
    execute_nsf_records_add_with_retry,
    sync_down_after_batch,
    typed_record_to_nsf_record_add,
)
from .batch_step2 import (
    add_jit_domain_links,
    apply_service_rotations,
    run_step2_extend_existing,
    run_step2_full,
    run_step2_global_profile_rotations,
    run_step2_global_saas,
)
from .preflight import collect_preflight_warnings, keeperai_resources, load_graph_for_preflight
from .record_loader import iter_accessible_record_uids
from .throttle_retry import (
    IMPORT_ON_EXHAUSTED,
    ChunkedAddError,
    call_with_throttle_retry,
    execute_records_add_with_retry,
    rest_fail_on_throttle,
)
from .rotation_throttle import RotationThrottle
from .pam_record_build import PamObject, pam_object_to_typed_record
from ..pam.vault_target import is_nested_share_folder

PamResource = Union[
    PamMachineObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamRemoteBrowserObject,
]


from .deferred_refs import (
    DeferredChannelAUpdate,
    DeferredRefUpdate,
    MAX_NUMBER_OF_RECORD_LINKS,
    apply_deferred_ref_updates,
    linked_keys_for_channel_a_refs,
    plan_deferred_refs_for_tiers,
)


@dataclass
class CreationTier:
    name: str
    objects: List[PamObject] = field(default_factory=list)


@dataclass
class BatchFailureSummary:
    failures: List[Tuple[str, str, str]] = field(default_factory=list)
    successes: List[str] = field(default_factory=list)


PAM_DAG_SAVE_BATCH_COUNT = 50
# Mid-flush every N resources during Step 2 (0 = one final save only).
# End-only flush of ~1300 resources was 500'ing on add_data even at
# discovery's chunk size of 200; mid-flush + smaller packets is safer.
# keeper-dag chunks each save() at PAM_DAG_SAVE_BATCH_COUNT.
PAM_DAG_FLUSH_EVERY = 100
PAM_DAG_SAVE_BATCH_COUNT_MIN = 10
# Emit '.' each resource; print the running count every N resources.
_STEP2_PROGRESS_MILESTONE = 100

_TIER_STATUS_LABELS = {
    'tier0_global_users': 'User records',
    'tier1_nested_users': 'User records',
    'resources': 'Resource records',
}

# Preferred summary order when reprinting both Step 1a status lines.
_RECORD_STATUS_LABEL_ORDER = ('User records', 'Resource records')


class _Step2DotProgress:
    """Multiline stderr progress for Step 2 DAG setup::

        Setting up DAG (0/520)...................................................................100 7m left
        Setting up DAG (100/520)...................................................................200 5m left
        ...
        Setting up DAG (500/520)....................520

    ETA (time left at current speed) is appended after milestone numbers when
    ``total >= milestone`` (100+).
    """

    def __init__(self, total: int = 0, milestone: int = _STEP2_PROGRESS_MILESTONE):
        self.total = max(0, int(total or 0))
        self.milestone = max(1, milestone)
        self.count = 0
        self._started = False
        self._ended_with_number = False
        self._t0: Optional[float] = None

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._t0 = time.monotonic()
        self._begin_line(0)

    def _begin_line(self, completed: int) -> None:
        if self.total > 0:
            prefix = f'Setting up DAG ({completed}/{self.total})'
        else:
            prefix = 'Setting up DAG'
        print(prefix, file=sys.stderr, end='', flush=True)
        self._ended_with_number = False

    @staticmethod
    def _format_eta(seconds: float) -> str:
        """Compact remaining-time label, e.g. ``1h56m left``, ``32m left``, ``45s left``."""
        sec = max(0, int(round(seconds)))
        if sec >= 3600:
            hours, rem = divmod(sec, 3600)
            minutes = rem // 60
            if minutes:
                return f'{hours}h{minutes}m left'
            return f'{hours}h left'
        if sec >= 60:
            minutes = sec // 60
            return f'{minutes}m left'
        return f'{sec}s left'

    def _eta_suffix(self) -> str:
        """Estimated time left at current speed; empty when not applicable."""
        if self.total < self.milestone or self._t0 is None:
            return ''
        remaining = self.total - self.count
        if remaining <= 0:
            return ''
        elapsed = time.monotonic() - self._t0
        if elapsed <= 0 or self.count <= 0:
            return ''
        eta = remaining * (elapsed / self.count)
        return f' {self._format_eta(eta)}'

    def tick(self) -> None:
        self.start()
        self.count += 1
        at_milestone = self.count % self.milestone == 0
        at_end = self.total > 0 and self.count >= self.total

        if at_milestone or at_end:
            print(str(self.count), file=sys.stderr, end='', flush=True)
            if at_milestone and not at_end:
                print(self._eta_suffix(), file=sys.stderr, end='', flush=True)
                print(file=sys.stderr, flush=True)
                self._begin_line(self.count)
            else:
                self._ended_with_number = True
        else:
            print('.', file=sys.stderr, end='', flush=True)
            self._ended_with_number = False

    def finish(self, ok: bool = True) -> None:
        if not self._started:
            return
        if self.count and not self._ended_with_number:
            print(str(self.count), file=sys.stderr, end='', flush=True)
            self._ended_with_number = True
        suffix = ' done' if ok else ' failed'
        if self.total and self.count != self.total:
            print(
                f'{suffix} ({self.count}/{self.total} resource(s))',
                file=sys.stderr, flush=True,
            )
        else:
            print(f'{suffix} ({self.count} resource(s))', file=sys.stderr, flush=True)


class _RecordAddProgress:
    """Stderr progress for Step 1a vault adds.

    Announces the total, then after each API chunk prints the cumulative count
    separated by ``...`` (no batch-size change — ticks follow ``records_add``
    chunk results, typically up to 999)::

        User records (2500)...999...1998...2500
    """

    def __init__(self, label: str, total: int = 0):
        self.label = label or 'record'
        self.total = max(0, int(total or 0))
        self.count = 0
        self._started = False
        self._finished = False

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        prefix = (
            f'{self.label} ({self.total})...'
            if self.total > 0 else f'{self.label}...'
        )
        print(prefix, file=sys.stderr, end='', flush=True)

    def tick_n(self, n: int) -> None:
        if n <= 0:
            return
        self.start()
        prev = self.count
        self.count += int(n)
        # Prefix already ends with "..."; separate later chunks with "..." only.
        if prev > 0:
            print('...', file=sys.stderr, end='', flush=True)
        print(str(self.count), file=sys.stderr, end='', flush=True)

    def finish(self, ok: bool = True) -> None:
        if not self._started or self._finished:
            return
        self._finished = True
        if ok:
            print(file=sys.stderr, flush=True)
        else:
            print(' failed', file=sys.stderr, flush=True)


def _print_record_add_status(label: str, success_count: int) -> None:
    """Match ``report_statuses`` column layout on stdout/logging."""
    logging.info('%-18s %-15s %d', label, 'success', success_count)


def configure_batch_tdag(tdag: TunnelDAG) -> None:
    """Deferred graph flush with chunked add_data (``save_batch_count``)."""
    tdag.linking_dag.auto_save = False
    tdag.linking_dag.save_batch_count = PAM_DAG_SAVE_BATCH_COUNT
    tdag.defer_saves(True)


# What a failed graph add_data looks like once the connection layer has given up (it already re-sends the same
# payload 5 times, 10 s apart, with a 30 s timeout per attempt): an HTTP status of a server / gateway fault, or a
# timeout / dropped connection. A request that takes the server longer than the client timeout fails on the client
# while the server may still commit it, so timeouts are retried with a smaller batch just like 5xx.
_GRAPH_ADD_DATA_RETRYABLE = (
    '500', '502', '503', '504',
    'timed out', 'timeout', 'time-out',
    'connection reset', 'connection aborted', 'connectionreset', 'connectionaborted', 'remotedisconnected',
    'connection error',
)


def _is_graph_add_data_server_error(err: BaseException) -> bool:
    """True for a graph add_data failure worth retrying with a smaller batch: KRouter / load balancer 5xx,
    a client or gateway timeout, or a dropped connection."""
    from ...keeper_dag.exceptions import DAGConnectionException

    msg = str(err).lower()
    if not isinstance(err, DAGConnectionException) and 'add_data' not in msg:
        return False
    return any(token in msg for token in _GRAPH_ADD_DATA_RETRYABLE)


def flush_deferred_graph(tdag: TunnelDAG, params, *, label: str = 'graph flush') -> None:
    """Save deferred DAG edges with throttle retry and 5xx batch-size backoff.

    On add_data HTTP 5xx, halves ``save_batch_count`` (floor
    ``PAM_DAG_SAVE_BATCH_COUNT_MIN``) and retries ``save()``. ``DAG.save`` clears
    ``edge.modified`` only after the batch that carries the edge was accepted, so
    the retry sends exactly the edges that were not accepted yet (the failed batch
    and every batch after it), never the ones that already went through.
    """
    while True:
        started = time.monotonic()
        try:
            call_with_throttle_retry(
                tdag.linking_dag.save,
                label=label,
                fail_on_throttle=rest_fail_on_throttle(params),
                on_exhausted=IMPORT_ON_EXHAUSTED,
            )
            return
        except Exception as err:
            if not _is_graph_add_data_server_error(err):
                raise
            current = int(getattr(tdag.linking_dag, 'save_batch_count', 0) or 0)
            if current <= PAM_DAG_SAVE_BATCH_COUNT_MIN:
                raise
            new_count = max(PAM_DAG_SAVE_BATCH_COUNT_MIN, current // 2)
            # The elapsed time includes the connection layer's own retries; the message names the cause
            # (HTTP status or timeout). Both are what is needed to tell a timeout from a lock or pool problem.
            logging.warning(
                '%s: add_data failed after %.1f s with save_batch_count=%d; '
                'retrying with save_batch_count=%d: %s',
                label, time.monotonic() - started, current, new_count, err,
            )
            tdag.linking_dag.save_batch_count = new_count


def _layer_b_fallback_enabled() -> bool:
    raw = os.environ.get('KEEPER_DAG_LB_FALLBACK', '').strip().lower()
    return raw in ('1', 'true', 'yes', 'on')


def assign_uids(objects: Iterable[PamObject], *, only_new: bool = False) -> None:
    for obj in objects:
        if only_new and getattr(obj, '_extend_tag', 'new') == 'existing':
            continue
        if not (isinstance(obj.uid, str) and RecordV3.is_valid_ref_uid(obj.uid)):
            obj.uid = utils.generate_uid()
            obj._uid_generated = True
        if hasattr(obj, 'users') and isinstance(obj.users, list):
            for usr in obj.users:
                if only_new and getattr(usr, '_extend_tag', 'new') == 'existing':
                    continue
                if not (isinstance(usr.uid, str) and RecordV3.is_valid_ref_uid(usr.uid)):
                    usr.uid = utils.generate_uid()
                    usr._uid_generated = True


def assign_record_keys(
    objects: Iterable[PamObject],
    record_keys: Dict[str, bytes],
    *,
    only_new: bool = False,
) -> None:
    for obj in objects:
        if only_new and getattr(obj, '_extend_tag', 'new') == 'existing':
            continue
        if obj.uid and obj.uid not in record_keys:
            record_keys[obj.uid] = utils.generate_aes_key()
        if hasattr(obj, 'users') and isinstance(obj.users, list):
            for usr in obj.users:
                if only_new and getattr(usr, '_extend_tag', 'new') == 'existing':
                    continue
                if usr.uid and usr.uid not in record_keys:
                    record_keys[usr.uid] = utils.generate_aes_key()


def _collect_create_objects(
    users: List[PamObject],
    resources: List[PamResource],
    *,
    only_new: bool,
) -> List[PamObject]:
    out: List[PamObject] = []
    for obj in users:
        if only_new and getattr(obj, '_extend_tag', 'new') == 'existing':
            continue
        out.append(obj)
    for res in resources:
        if only_new and getattr(res, '_extend_tag', 'new') == 'existing':
            continue
        out.append(res)
        for usr in getattr(res, 'users', []) or []:
            if only_new and getattr(usr, '_extend_tag', 'new') == 'existing':
                continue
            out.append(usr)
    return out


def _uid_in_vault(params, uid: str) -> bool:
    if uid in getattr(params, 'record_cache', {}):
        return True
    if uid in getattr(params, 'nested_share_records', {}):
        return True
    if uid in getattr(params, 'nested_share_record_data', {}):
        return True
    return False


def _resource_deps(res: PamResource, uid_index: Dict[str, PamObject]) -> Set[str]:
    deps: Set[str] = set()
    ps = getattr(res, 'pam_settings', None)
    conn = getattr(ps, 'connection', None) if ps else None
    if conn:
        uids = getattr(conn, 'userRecordUid', None)
        if uids and isinstance(uids, list):
            deps.update(u for u in uids if u)
        sftp_res = get_sftp_attribute(res, 'sftpResourceUid')
        if sftp_res:
            deps.add(sftp_res)
        sftp_user = get_sftp_attribute(res, 'sftpUserUid')
        if sftp_user:
            deps.add(sftp_user)
    if isinstance(res, PamRemoteBrowserObject):
        rbi = getattr(res, 'rbi_settings', None)
        rconn = getattr(rbi, 'connection', None) if rbi else None
        # edit/extend resolve autofill → httpCredentialsUid as a one-element list
        # (ConnectionSettingsHTTP.to_record_dict later stores a single string).
        hc = getattr(rconn, 'httpCredentialsUid', None) if rconn else None
        if isinstance(hc, list):
            deps.update(u for u in hc if isinstance(u, str) and u)
        elif isinstance(hc, str) and hc:
            deps.add(hc)
    return {d for d in deps if d in uid_index}


def build_creation_plan(
    users: List[PamObject],
    resources: List[PamResource],
    *,
    only_new: bool = False,
) -> List[CreationTier]:
    """Tier 0 global users → Tier 1 nested pamUsers → Tier 2+ resources (topo sort)."""
    uid_index: Dict[str, PamObject] = {}
    for u in users:
        if u.uid:
            uid_index[u.uid] = u
    for res in resources:
        if res.uid:
            uid_index[res.uid] = res
        for nu in getattr(res, 'users', []) or []:
            if nu.uid:
                uid_index[nu.uid] = nu

    tier0: List[PamObject] = []
    for u in users:
        if only_new and getattr(u, '_extend_tag', 'new') == 'existing':
            continue
        tier0.append(u)

    tier1: List[PamObject] = []
    for res in resources:
        for nu in getattr(res, 'users', []) or []:
            if only_new and getattr(nu, '_extend_tag', 'new') == 'existing':
                continue
            if isinstance(nu, PamUserObject):
                tier1.append(nu)

    tier_resources: List[PamResource] = []
    for res in resources:
        if only_new and getattr(res, '_extend_tag', 'new') == 'existing':
            continue
        tier_resources.append(res)

    res_uids = {r.uid for r in tier_resources}
    graph: Dict[str, Set[str]] = defaultdict(set)
    in_degree: Dict[str, int] = {r.uid: 0 for r in tier_resources}

    for res in tier_resources:
        for dep in _resource_deps(res, uid_index):
            # Ignore self-refs (e.g. sftp_resource pointing at the same machine title).
            if dep in res_uids and dep != res.uid:
                graph[dep].add(res.uid)
                in_degree[res.uid] += 1

    ordered: List[PamResource] = []
    queue: List[PamResource] = [
        r for r in tier_resources if in_degree[r.uid] == 0
    ]
    queue.sort(key=lambda r: 0 if (getattr(r, 'type', '') or '').lower() == 'pamdirectory' else 1)

    while queue:
        res = queue.pop(0)
        ordered.append(res)
        for child_uid in graph.get(res.uid, ()):
            in_degree[child_uid] -= 1
            if in_degree[child_uid] == 0:
                child = next(x for x in tier_resources if x.uid == child_uid)
                queue.append(child)
        queue.sort(key=lambda r: 0 if (getattr(r, 'type', '') or '').lower() == 'pamdirectory' else 1)

    if len(ordered) != len(tier_resources):
        raise ValueError(
            'Circular dependency detected among PAM resources (e.g. sftpResourceUid cycle). Import aborted.',
        )

    resource_tiers: List[CreationTier] = []
    if ordered:
        resource_tiers.append(CreationTier(name='resources', objects=list(ordered)))

    tiers: List[CreationTier] = []
    if tier0:
        tiers.append(CreationTier(name='tier0_global_users', objects=tier0))
    if tier1:
        tiers.append(CreationTier(name='tier1_nested_users', objects=tier1))
    tiers.extend(resource_tiers)
    return tiers


def _populate_linked_keys(record, obj, record_keys: Dict[str, bytes], inserted_uids: Set[str]) -> None:
    del inserted_uids  # only refs on record matter for Channel A linked_keys
    linked = linked_keys_for_channel_a_refs(record, record_keys)
    if linked:
        record.linked_keys = linked



# Failure kinds stored on ``obj._batch_fail_kind`` by ``_parse_batch_results``.
_FAIL_MISSING = 'missing'   # no status in the response (chunk lost / not answered)
_FAIL_EXISTS = 'exists'     # RS_RECORD_EXISTS
_FAIL_ERROR = 'error'       # any other server-reported status

# Extra passes (sync_down + re-send of records still absent from the vault).
MAX_TIER_RECONCILE_PASSES = 3


def _mark_failed(obj, kind: str, reason: str) -> None:
    obj._batch_vault_status = 'failed'
    obj._batch_fail_kind = kind
    obj._batch_fail_reason = reason


def _parse_batch_results(
    params,
    objects: List[PamObject],
    results: List[record_pb2.RecordModifyResult],
    *,
    extend_mode: bool,
) -> BatchFailureSummary:
    summary = BatchFailureSummary()
    result_by_uid = {
        utils.base64_url_encode(r.record_uid): r for r in results if r.record_uid
    }
    for obj in objects:
        uid = obj.uid
        title = getattr(obj, 'title', '') or ''
        rs = result_by_uid.get(uid)
        if rs is None:
            summary.failures.append((uid, title, 'missing from response'))
            _mark_failed(obj, _FAIL_MISSING, 'missing from response')
            continue
        status = rs.status
        if status == record_pb2.RS_SUCCESS:
            summary.successes.append(uid)
            obj._batch_vault_status = 'created'
        elif status == record_pb2.RS_RECORD_EXISTS and extend_mode:
            if _uid_in_vault(params, uid):
                summary.successes.append(uid)
                obj._batch_vault_status = 'created'
            else:
                summary.failures.append((uid, title, 'RS_RECORD_EXISTS'))
                _mark_failed(obj, _FAIL_EXISTS, 'RS_RECORD_EXISTS')
        else:
            reason = imp_exp.record_status_to_str(status)
            summary.failures.append((uid, title, reason))
            _mark_failed(
                obj, _FAIL_EXISTS if status == record_pb2.RS_RECORD_EXISTS else _FAIL_ERROR, reason,
            )
    return summary


def _summarize_tier(objects: List[PamObject]) -> BatchFailureSummary:
    """Rebuild a summary from the per-object vault status."""
    summary = BatchFailureSummary()
    for obj in objects:
        if getattr(obj, '_batch_vault_status', '') == 'created':
            summary.successes.append(obj.uid)
        else:
            summary.failures.append((
                obj.uid,
                getattr(obj, 'title', '') or '',
                getattr(obj, '_batch_fail_reason', '') or 'unknown',
            ))
    return summary


def _print_failure_summary(summary: BatchFailureSummary, tier_name: str) -> None:
    if summary.failures:
        logging.error(f'Batch Step 1a failures in {tier_name}:')
        for uid, title, status in summary.failures:
            logging.error(f'  FAILED  {title!r} ({uid}): {status}')
    if summary.successes:
        logging.warning(
            f'Batch Step 1a partial success in {tier_name}: '
            f'{len(summary.successes)} succeeded, {len(summary.failures)} failed',
        )


class BatchPamImportEngine:
    """Shared batch pipeline for pam project import and extend."""

    def __init__(
        self,
        params,
        project: dict,
        users: List[PamObject],
        resources: List[PamResource],
        *,
        users_folder_uid: str,
        resources_folder_uid: str,
        pam_cfg_uid: str,
        extend_mode: bool = False,
    ):
        self.params = params
        self.project = project
        self.users = users
        self.resources = resources
        self.users_folder_uid = users_folder_uid
        self.resources_folder_uid = resources_folder_uid
        self.pam_cfg_uid = pam_cfg_uid
        self.extend_mode = extend_mode
        self.record_keys: Dict[str, bytes] = {}
        self.deferred_refs: List[DeferredRefUpdate] = []
        self.deferred_links: List[DeferredChannelAUpdate] = []
        # Step 2 (DAG/configuration) errors; records are in the vault by then.
        self.dag_errors: List[str] = []
        # Step 1b/1c errors (ref patches, attachments, scripts) on records that do exist.
        self.vault_update_errors: List[str] = []

    def _resolve_folder(self, obj: PamObject) -> str:
        """Route vault creates using pre-stamped ``resolved_folder_uid`` when set.

        Import/extend stamp that field before the engine runs:
        - Explicit ``folder_path`` from JSON → mapped folder UID
        - Unspecified: ``pamUser`` / ``login`` → Users; resource types → Resources
        """
        resolved = getattr(obj, 'resolved_folder_uid', None)
        if resolved:
            return resolved
        if isinstance(obj, (LoginUserObject, PamUserObject)):
            return self.users_folder_uid
        return self.resources_folder_uid

    def build_plan(self) -> List[CreationTier]:
        return build_creation_plan(
            self.users, self.resources, only_new=self.extend_mode,
        )

    def _plan_deferred_links_for_tiers(self, tiers: List[CreationTier], inserted: Set[str]) -> List[DeferredChannelAUpdate]:
        deferred: List[DeferredChannelAUpdate] = []
        ins = set(inserted)
        for tier in tiers:
            for obj in tier.objects:
                uid = getattr(obj, 'uid', '')
                if not uid:
                    continue
                try:
                    pam_object_to_typed_record(
                        self.params, obj, self._resolve_folder(obj),
                        record_key=self.record_keys.get(uid),
                        inserted_uids=ins,
                        deferred_links_out=deferred,
                    )
                except ValueError:
                    continue
            ins.update(getattr(o, 'uid', '') for o in tier.objects if getattr(o, 'uid', ''))
        return deferred

    def _project_record_link_counts(
        self,
        tiers: List[CreationTier],
        inserted: Set[str],
    ) -> Dict[str, int]:
        """Count typed *Ref UIDs per record (Channel A only — not pamSettings JSON)."""
        from ... import vault_extensions

        counts: Dict[str, int] = defaultdict(int)
        ins = set(inserted)
        for tier in tiers:
            for obj in tier.objects:
                uid = getattr(obj, 'uid', '')
                if not uid:
                    continue
                deferred_links: List[DeferredChannelAUpdate] = []
                try:
                    record = pam_object_to_typed_record(
                        self.params, obj, self._resolve_folder(obj),
                        record_key=self.record_keys.get(uid),
                        inserted_uids=ins,
                        deferred_links_out=deferred_links,
                    )
                except ValueError:
                    continue
                refs = set(vault_extensions.extract_typed_record_refs(record))
                for item in deferred_links:
                    if item.record_uid == uid:
                        refs.add(item.ref_uid)
                counts[uid] = len(refs)
            ins.update(getattr(o, 'uid', '') for o in tier.objects if getattr(o, 'uid', ''))
        return dict(counts)

    def simulate(self) -> dict:
        tiers = self.build_plan()
        inserted = set(
            uid for uid in self.params.record_cache.keys()
            if RecordV3.is_valid_ref_uid(uid)
        )
        planned_deferred = plan_deferred_refs_for_tiers(tiers, inserted)
        planned_links = self._plan_deferred_links_for_tiers(tiers, inserted)
        projected_link_counts = self._project_record_link_counts(tiers, inserted)
        link_count_warnings = [
            {
                'record_uid': uid,
                'projected_links': count,
                'limit': MAX_NUMBER_OF_RECORD_LINKS,
            }
            for uid, count in projected_link_counts.items()
            if count > MAX_NUMBER_OF_RECORD_LINKS
        ]
        for item in link_count_warnings:
            logging.warning(
                f'Dry-run: record {item["record_uid"]} projects '
                f'{item["projected_links"]} typed record_links (limit {item["limit"]})',
            )
        dispatch = []
        for res in self.resources:
            tag = getattr(res, '_extend_tag', 'new')
            if tag == 'existing':
                nested_new = [
                    u.uid for u in (getattr(res, 'users', []) or [])
                    if getattr(u, '_extend_tag', 'new') == 'new'
                ]
                if nested_new:
                    dispatch.append({
                        'resource': res.uid,
                        'step2': 'run_step2_extend_existing',
                        'new_users': nested_new,
                    })
                else:
                    dispatch.append({'resource': res.uid, 'step2': 'skip'})
            else:
                dispatch.append({'resource': res.uid, 'step2': 'run_step2_full'})

        # Pre-flight: problems the live Step 2 would only hit after the records exist (see preflight.py).
        # Extend reads the PAM graph once (read-only) to look at existing machines that receive new users.
        tdag = None
        needs_machine_graph = self.extend_mode and bool(self.pam_cfg_uid) and any(
            getattr(r, '_extend_tag', 'new') == 'existing'
            and any(getattr(u, '_extend_tag', 'new') == 'new' for u in (getattr(r, 'users', None) or []))
            for r in self.resources)
        # KeeperAI on a new RBI / cloud resource: the PAM configuration must have ai_threat_detection on
        needs_ai_graph = bool(self.pam_cfg_uid) and bool(keeperai_resources(self.resources))
        needs_graph = needs_machine_graph or needs_ai_graph
        if needs_graph:
            tdag = load_graph_for_preflight(self.params, self.pam_cfg_uid)
        preflight = collect_preflight_warnings(
            self.params, self.users, self.resources, self.pam_cfg_uid, self.extend_mode, tdag)
        if needs_graph and tdag is None:
            skipped = []
            if needs_machine_graph:
                skipped.append('the admin / link checks for existing machines')
            if needs_ai_graph:
                skipped.append('the KeeperAI check of the PAM configuration')
            preflight.append(f'could not read the PAM graph: {" and ".join(skipped)} {"was" if len(skipped) == 1 else "were"} skipped')
        for msg in preflight:
            logging.warning(f'Dry-run preflight: {msg}')
        return {
            'preflight_warnings': preflight,
            'tiers': [{'name': t.name, 'count': len(t.objects), 'uids': [o.uid for o in t.objects]} for t in tiers],
            'step2_dispatch': dispatch,
            'deferred_ref_count': len(planned_deferred),
            'deferred_refs': [
                {
                    'record_uid': d.record_uid,
                    'settings_field': d.settings_field,
                    'json_path': list(d.json_path),
                }
                for d in planned_deferred
            ],
            'deferred_link_count': len(planned_links),
            'deferred_links': [
                {
                    'record_uid': d.record_uid,
                    'ref_uid': d.ref_uid,
                    'field_type': d.field_type,
                }
                for d in planned_links
            ],
            'projected_link_counts': projected_link_counts,
            'link_count_warnings': link_count_warnings,
            'import_tail': self._plan_import_tail(),
        }

    def _plan_import_tail(self) -> dict:
        """Post–Step 2 import-only tail (not batched); reported in dry-run."""
        if self.extend_mode:
            return {'applies': False, 'reason': 'extend_mode'}
        pce = (self.project.get('pam_config') or {}).get('pam_config_object')
        if pce is None:
            return {
                'applies': False,
                'pam_config_scripts': False,
                'domain_admin_link': False,
            }
        scripts = getattr(getattr(pce, 'scripts', None), 'scripts', None) or []
        cred_scripts = any(getattr(s, 'record_refs', None) for s in scripts)
        domain_admin = (
            getattr(pce, 'environment', None) == 'domain'
            and bool(getattr(pce, 'admin_credential_ref', None))
        )
        return {
            'applies': cred_scripts or domain_admin,
            'pam_config_scripts': cred_scripts,
            'domain_admin_link': domain_admin,
        }

    def _layer_b_hygiene(self) -> None:
        clear_layer_b_feature_cache()
        if _layer_b_fallback_enabled():
            logging.warning(
                'KEEPER_DAG_LB_FALLBACK is enabled; PAM batch import/extend may use '
                'legacy DAG writes for JIT/AI/domain on denial/404 — slower and '
                'rollout-only. Unset for production batch runs.',
            )

    def run(self) -> bool:
        """Execute full batch pipeline. Returns False on abort."""
        self._layer_b_hygiene()
        only_new = self.extend_mode
        assign_record_keys(
            _collect_create_objects(self.users, self.resources, only_new=only_new),
            self.record_keys,
            only_new=only_new,
        )
        tiers = self.build_plan()
        inserted_uids: Set[str] = {
            uid for uid in iter_accessible_record_uids(self.params)
            if RecordV3.is_valid_ref_uid(uid)
        }

        # Aggregate Step 1a totals by status label so progress spans tier0+tier1
        # users under one ``User records (N)...`` line.
        totals_by_label: Dict[str, int] = defaultdict(int)
        for tier in tiers:
            label = _TIER_STATUS_LABELS.get(tier.name, 'record')
            totals_by_label[label] += len(tier.objects)

        progress_by_label: Dict[str, _RecordAddProgress] = {}
        success_by_label: Dict[str, int] = {}
        remaining_by_label = dict(totals_by_label)

        for tier in tiers:
            label = _TIER_STATUS_LABELS.get(tier.name, 'record')
            if label not in progress_by_label and totals_by_label.get(label, 0) > 0:
                progress_by_label[label] = _RecordAddProgress(
                    label, total=totals_by_label[label],
                )
                # Announce immediately — before protobuf build / first API batch.
                progress_by_label[label].start()
            progress = progress_by_label.get(label)
            if not self._execute_tier_1a(tier, inserted_uids, progress=progress):
                if progress is not None:
                    progress.finish(ok=False)
                failed = sum(
                    1 for o in tier.objects
                    if getattr(o, '_batch_vault_status', '') != 'created'
                )
                later = tiers[tiers.index(tier) + 1:]
                self._print_missing_records_summary(
                    failed, sum(len(t.objects) for t in later),
                )
                return False
            created = sum(
                1 for o in tier.objects
                if getattr(o, '_batch_vault_status', '') == 'created'
            )
            success_by_label[label] = success_by_label.get(label, 0) + created
            remaining_by_label[label] = max(0, remaining_by_label.get(label, 0) - len(tier.objects))
            inserted_uids.update(
                o.uid for o in tier.objects
                if getattr(o, '_batch_vault_status', '') == 'created'
            )
            # Close progress + print success when this label's tiers are done.
            if remaining_by_label.get(label, 0) == 0 and progress is not None:
                progress.finish(ok=True)
                if label == 'Resource records':
                    # After resources, reprint user subtotal (if any) then resources.
                    for prior in _RECORD_STATUS_LABEL_ORDER:
                        if prior in success_by_label:
                            _print_record_add_status(prior, success_by_label[prior])
                else:
                    _print_record_add_status(label, success_by_label.get(label, 0))

        # Records are all in the vault; failures to complete them (refs, attachments,
        # scripts) are tracked, not fatal -- ``pam project update`` adds the missing parts.
        if self.deferred_refs or self.deferred_links:
            self._apply_deferred_ref_updates()

        self._execute_step_1c()

        try:
            self._execute_step_2()
        except Exception as err:
            # Setup failure (tokens / graph load); records are already in the vault.
            self.dag_errors.append(f'Step 2 setup: {err}')
            logging.error(f'Batch Step 2 setup failed: {err}', exc_info=True)
        self._print_dag_error_summary()
        return True

    def _execute_tier_1a(
        self,
        tier: CreationTier,
        inserted_uids: Set[str],
        progress: Optional[_RecordAddProgress] = None,
    ) -> bool:
        classic_pbs = []
        classic_objects: List[PamObject] = []
        nsf_pbs = []
        nsf_objects: List[PamObject] = []
        for obj in tier.objects:
            folder_uid = self._resolve_folder(obj)
            rk = self.record_keys.get(obj.uid)
            record = pam_object_to_typed_record(
                self.params, obj, folder_uid,
                record_key=rk,
                inserted_uids=inserted_uids,
                deferred_out=self.deferred_refs,
                deferred_links_out=self.deferred_links,
            )
            _populate_linked_keys(record, obj, self.record_keys, inserted_uids)
            if is_nested_share_folder(self.params, folder_uid):
                pb = typed_record_to_nsf_record_add(self.params, record, folder_uid)
                if pb:
                    nsf_pbs.append(pb)
                    nsf_objects.append(obj)
            else:
                pb = add_record_to_folder(self.params, record, folder_uid, pb_only=True)
                if pb:
                    classic_pbs.append(pb)
                    classic_objects.append(obj)

        if not classic_pbs and not nsf_pbs:
            return True

        # Progress owns the status line; suppress per-chunk report_statuses.
        status_type = None if progress is not None else _TIER_STATUS_LABELS.get(
            tier.name, 'record',
        )
        on_chunk = progress.tick_n if progress is not None else None
        pb_by_uid = {o.uid: pb for o, pb in zip(classic_objects, classic_pbs)}
        pb_by_uid.update({o.uid: pb for o, pb in zip(nsf_objects, nsf_pbs)})
        nsf_uids = {o.uid for o in nsf_objects}
        tier_objects: List[PamObject] = classic_objects + nsf_objects

        results, send_err = self._send_records_add(
            classic_objects, nsf_objects, pb_by_uid, tier.name, status_type, on_chunk,
        )
        _parse_batch_results(self.params, tier_objects, results, extend_mode=self.extend_mode)
        if send_err is not None:
            logging.warning(
                f'Step 1a tier {tier.name}: batch error ({send_err}); reconciling against the vault',
            )
        summary = _summarize_tier(tier_objects)

        # A record is either fully in the vault or not (atomic write), so after any
        # failure sync_down and see what actually landed; only records still absent
        # are re-sent.
        for attempt in range(MAX_TIER_RECONCILE_PASSES + 1):
            if not summary.failures:
                break
            sync_down_after_batch(self.params, self.project)
            retry = self._reconcile_tier_failures(tier_objects)
            summary = _summarize_tier(tier_objects)
            if not summary.failures or not retry or attempt == MAX_TIER_RECONCILE_PASSES:
                break
            logging.warning(
                f'Step 1a tier {tier.name}: re-sending {len(retry)} record(s) missing from the '
                f'vault (pass {attempt + 1}/{MAX_TIER_RECONCILE_PASSES})',
            )
            r_results, send_err = self._send_records_add(
                [o for o in retry if o.uid not in nsf_uids],
                [o for o in retry if o.uid in nsf_uids],
                pb_by_uid, tier.name, status_type, on_chunk,
            )
            _parse_batch_results(self.params, retry, r_results, extend_mode=self.extend_mode)
            summary = _summarize_tier(tier_objects)

        if summary.failures:
            _print_failure_summary(summary, tier.name)
            return False
        sync_down_after_batch(self.params, self.project)
        return True

    def _reconcile_tier_failures(self, tier_objects: List[PamObject]) -> List[PamObject]:
        """Mark failed records that are actually in the vault as created.

        Returns the records that must be re-sent (no answer and not in the vault).
        Records the server rejected with an explicit error are never re-sent.
        """
        retry: List[PamObject] = []
        for obj in tier_objects:
            if getattr(obj, '_batch_vault_status', '') == 'created':
                continue
            kind = getattr(obj, '_batch_fail_kind', _FAIL_ERROR)
            in_vault = _uid_in_vault(self.params, obj.uid)
            ours = (
                self.extend_mode
                or getattr(obj, '_uid_generated', False)
                or kind == _FAIL_MISSING
            )
            if in_vault and kind != _FAIL_ERROR and ours:
                obj._batch_vault_status = 'created'
                obj._batch_fail_kind = ''
            elif not in_vault and kind == _FAIL_MISSING:
                retry.append(obj)
        return retry

    def _send_records_add(self, classic_objs, nsf_objs, pb_by_uid, tier_name, status_type, on_chunk):
        """Send classic then NSF adds; returns ``(results, first_error_or_None)``.

        Chunks accepted before an error are kept in ``results``; the rest show up as
        "missing from response" and are reconciled by the caller.
        """
        results: list = []
        err: Optional[BaseException] = None
        groups = (
            (classic_objs, execute_records_add_with_retry, f'Step 1a tier {tier_name}'),
            (nsf_objs, execute_nsf_records_add_with_retry, f'Step 1a NSF tier {tier_name}'),
        )
        for objs, fn, label in groups:
            if not objs or err is not None:
                continue
            try:
                results.extend(fn(
                    self.params, [pb_by_uid[o.uid] for o in objs],
                    label=label, status_type=status_type, on_chunk=on_chunk,
                ))
            except ChunkedAddError as e:
                results.extend(e.results)
                err = e.cause
        return results, err

    def _apply_deferred_ref_updates(self) -> bool:
        """Step 1b. Returns False if some updates failed (recorded in ``vault_update_errors``)."""
        try:
            summary = apply_deferred_ref_updates(
                self.params,
                self.deferred_refs,
                self.deferred_links,
                record_keys=self.record_keys,
                extend_mode=self.extend_mode,
            )
        except Exception as err:
            self.vault_update_errors.append(f'Step 1b deferred ref updates: {err}')
            logging.error(f'Batch Step 1b failed: {err}', exc_info=True)
            return False
        for uid, reason in summary.warnings:
            logging.warning(f'  SKIPPED  {uid}: {reason}')
            self.vault_update_errors.append(f'Step 1b skipped {uid}: {reason}')
        if summary.failures:
            logging.error('Batch Step 1b deferred ref update failures:')
            for uid, reason in summary.failures:
                logging.error(f'  FAILED  {uid}: {reason}')
                self.vault_update_errors.append(f'Step 1b {uid}: {reason}')
            return False
        if self.deferred_refs or self.deferred_links:
            logging.info(
                f'Step 1b applied {len(self.deferred_refs)} Channel B patch(es) '
                f'and {len(self.deferred_links)} Channel A link(s)',
            )
        return True

    def _execute_step_1c(self) -> bool:
        """Batch attachment/script uploads after vault rows exist (files_add + parallel PUTs)."""
        objects = [
            obj for obj in _collect_create_objects(self.users, self.resources, only_new=self.extend_mode)
            if getattr(obj, '_batch_vault_status', '') == 'created'
        ]
        if not objects:
            return True
        try:
            summary = run_step_1c_for_objects(
                self.params, objects, self.users, self.resources,
                record_keys=self.record_keys,
            )
        except Exception as err:
            self.vault_update_errors.append(f'Step 1c attachments/scripts: {err}')
            logging.error(f'Batch Step 1c failed: {err}', exc_info=True)
            return False
        for uid, reason in summary.warnings:
            logging.warning(f'  Step 1c warning  {uid}: {reason}')
            self.vault_update_errors.append(f'Step 1c skipped {uid}: {reason}')
        if summary.failures:
            logging.error('Batch Step 1c attachment/script failures:')
            for uid, reason in summary.failures:
                logging.error(f'  FAILED  {uid}: {reason}')
                self.vault_update_errors.append(f'Step 1c {uid}: {reason}')
            return False
        if summary.uploaded_count:
            logging.info(f'Step 1c uploaded {summary.uploaded_count} file(s) via batch pipeline')
        return True

    def _execute_step_2(self) -> bool:
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(
            self.params,
        )
        tdag = TunnelDAG(
            self.params,
            encrypted_session_token,
            encrypted_transmission_key,
            self.pam_cfg_uid,
            True,
            transmission_key=transmission_key,
        )
        configure_batch_tdag(tdag)
        # Rotation / TunnelDAG helpers create their own graphs without
        # _defer_saves; force legacy Layer-B for the whole Step 2 so a KRouter
        # configure_resource 5xx cannot abort the import mid-run.
        set_layer_b_force_legacy(True)
        from ..discoveryrotation import PAMCreateRecordRotationCommand
        prc = PAMCreateRecordRotationCommand()
        rotation_throttle = RotationThrottle()

        new_resources = [
            r for r in self.resources
            if getattr(r, '_extend_tag', 'new') != 'existing'
        ]
        existing_resources = [
            r for r in self.resources
            if getattr(r, '_extend_tag', 'new') == 'existing'
        ]

        progress = _Step2DotProgress(total=len(new_resources) + len(existing_resources))
        progress.start()
        ok = False
        processed = 0
        # (user, machine) pairs with service_resources: their rotation is re-sent after the final graph flush
        service_queue: list = []

        # All records are in the vault at this point, so DAG/configuration errors are
        # tracked and counted instead of aborting; run() prints the recovery hint.
        def _dag_error(what: str, err: BaseException) -> None:
            self.dag_errors.append(f'{what}: {err}')
            logging.error(f'Batch Step 2: {what} failed: {err}', exc_info=True)

        def _maybe_mid_flush() -> None:
            nonlocal processed
            processed += 1
            if PAM_DAG_FLUSH_EVERY <= 0 or processed % PAM_DAG_FLUSH_EVERY != 0:
                return
            try:
                flush_deferred_graph(
                    tdag, self.params, label=f'Step 2 graph flush @{processed}',
                )
            except Exception as err:
                _dag_error(f'graph flush after resource {processed}', err)

        try:
            for mach in new_resources:
                progress.tick()
                try:
                    run_step2_full(
                        self.params, tdag, mach, self.pam_cfg_uid, prc,
                        self.users_folder_uid, self.resources_folder_uid,
                        rotation_throttle=rotation_throttle,
                        service_queue=service_queue,
                    )
                except Exception as err:
                    _dag_error(f'configuration of {getattr(mach, "title", "") or mach.uid}', err)
                _maybe_mid_flush()

            for mach in existing_resources:
                progress.tick()
                try:
                    run_step2_extend_existing(
                        self.params, tdag, mach, self.pam_cfg_uid, prc,
                        rotation_throttle=rotation_throttle,
                        service_queue=service_queue,
                    )
                except Exception as err:
                    _dag_error(f'configuration of {getattr(mach, "title", "") or mach.uid}', err)
                _maybe_mid_flush()

            try:
                # rotation: saas for new GLOBAL users (needs the SaaS configuration records created in Step 1)
                run_step2_global_saas(
                    self.params, prc, self.users, self.pam_cfg_uid,
                    rotation_throttle=rotation_throttle,
                )
            except Exception as err:
                _dag_error('SaaS rotation', err)

            try:
                # rotation: iam_user / scripts_only for new GLOBAL users (never applied before this pass)
                run_step2_global_profile_rotations(
                    self.params, prc, self.users, self.pam_cfg_uid,
                    rotation_throttle=rotation_throttle,
                )
            except Exception as err:
                _dag_error('IAM / scripts-only rotation', err)

            try:
                if add_jit_domain_links(tdag, self.resources):
                    logging.debug('JIT domain LINK edges queued on deferred tdag')
            except Exception as err:
                _dag_error('JIT domain links', err)

            if progress.count:
                print(' flushing...', file=sys.stderr, end='', flush=True)
            try:
                flush_deferred_graph(tdag, self.params, label='Step 2 graph flush')
            except Exception as err:
                _dag_error('final graph flush', err)
            try:
                # service accounts last: after the flush nothing can overwrite the controls_services ACL flag
                apply_service_rotations(
                    self.params, prc, service_queue, self.resources, self.pam_cfg_uid,
                    rotation_throttle=rotation_throttle,
                )
            except Exception as err:
                _dag_error('service accounts', err)
            ok = not self.dag_errors
        finally:
            set_layer_b_force_legacy(False)
            progress.finish(ok=ok)

        try:
            sync_down_after_batch(self.params, self.project)
        except Exception as err:
            logging.warning(f'Batch Step 2: post-import sync_down failed: {err}')
        self.params.sync_data = True
        return True

    def _follow_up_command(self, command: str) -> str:
        """``pam project <command> --config=<uid> --filename=<file>`` or '' when there is no input file
        (e.g. ``--sample-data``). Inline JSON input gets a placeholder file name."""
        opts = (self.project or {}).get('options') or {}
        file_name = str(opts.get('file_name') or '')
        if not file_name or not self.pam_cfg_uid:
            return ''
        if file_name.lstrip().startswith(('{', '[')):
            file_name = '<import_extend.json>'
        return f'pam project {command} --config={self.pam_cfg_uid} --filename={file_name}'

    def _print_missing_records_summary(self, failed: int, not_attempted: int) -> None:
        """Tell the operator how to add the records that did not make it into the vault."""
        parts = [f'{failed} record(s) could not be created in the vault']
        if not_attempted:
            parts.append(f'{not_attempted} more were not attempted')
        msg = f'{bcolors.WARNING}{"; ".join(parts)}.'
        cmd = self._follow_up_command('extend')
        if cmd:
            msg += (f' Fix the errors above, then run: {cmd} to add the missing records '
                    f'(records already in the vault are skipped), followed by '
                    f'{self._follow_up_command("update")} to complete their configuration.')
        print(msg + bcolors.ENDC, file=sys.stderr)

    def _print_dag_error_summary(self) -> None:
        """Tell the operator how to finish configuration after Step 2 errors."""
        if not (self.dag_errors or self.vault_update_errors):
            return
        found = []
        if self.vault_update_errors:
            found.append(f'{len(self.vault_update_errors)} record update error(s) '
                         f'(references, attachments or scripts)')
        if self.dag_errors:
            found.append(f'{len(self.dag_errors)} PAM configuration (DAG) error(s)')
        msg = (f'{bcolors.WARNING}All records were created in the vault, but '
               f'{" and ".join(found)} occurred.')
        cmd = self._follow_up_command('update')
        if cmd:
            msg += f' Please run: {cmd}'
        print(msg + bcolors.ENDC, file=sys.stderr)
        for label, errors in (('Record update', self.vault_update_errors), ('DAG', self.dag_errors)):
            for line in errors[:20]:
                logging.warning(f'  {label} error: {line}')
            if len(errors) > 20:
                logging.warning(f'  ... and {len(errors) - 20} more {label} errors (see log)')
