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

"""Writes the RECORD-FIELD changes of an ``UpdatePlan`` (order of work step 5, record side).

What the re-send test showed (QA 2026-11-19, ``2-batching-plan.md`` item 0): a record update carries the revision the
record was read at; the server answers PER RECORD, applies the others, and answers ``out of sync`` for a record that
changed meanwhile (including one that a first, half-failed attempt already wrote) without applying it twice. So:

* the changes are applied to a COPY of the freshly loaded record and sent in chunks (``vault/records_update`` for
  classic records, ``vault/records/v3/update`` for Nested Share Folder records);
* a record that answers ``out of sync`` is re-read, compared AGAIN (``UpdatePlan.rediff``) and sent once more with
  what still differs - a record the first attempt wrote shows no difference any more;
* PASSWORD rule of that retry (owner, 2026-11-12): a password is written again only if it was scheduled in the
  original plan AND the vault password is still the one that was read; otherwise it is skipped with a warning;
* any other status is an APPLY error: reported, the run goes on, ``update`` is run again to finish.

Files (attachments / scripts) are not written here.
"""

from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import update_schema as us
from .deferred_refs import _build_typed_record_update_pb
from .update_diff import Change, KIND_RECORD, OP_ADD, OP_CHANGE, OP_REMOVE
from .update_plan import ItemResult, UpdatePlan
from ... import api, utils, vault, vault_extensions
from ...proto import record_pb2


@dataclass
class RecordWriteReport:
    applied: List[str] = field(default_factory=list)      # "<title>: record fields (n)"
    errors: List[str] = field(default_factory=list)       # APPLY errors; the run went on
    warnings: List[str] = field(default_factory=list)     # for example a password skipped on the retry


def record_field_changes(result: ItemResult) -> List[Change]:
    """The changes that are record FIELDS (not files, not graph)."""
    return [c for c in result.changes
            if c.kind == KIND_RECORD and c.target is not None and c.target.kind == us.KIND_RECORD]


# --------------------------------------------------------------------------------------------------------------
# applying a change to a TypedRecord
# --------------------------------------------------------------------------------------------------------------

def _label_ok(candidate: Any, label: str) -> bool:
    return not label or (getattr(candidate, 'label', '') or '').casefold() == label.casefold()


def find_typed_field(record: vault.TypedRecord, target: us.Target) -> Tuple[Optional[list], Optional[Any]]:
    """(the list the field is in, the field) of *target*, looked up like ``update_diff.find_field``."""
    pools = {us.SCOPE_TYPED: (record.fields,), us.SCOPE_CUSTOM: (record.custom,),
             us.SCOPE_ANY: (record.fields, record.custom)}.get(target.scope, ())
    for pool in pools:
        for candidate in pool:
            if candidate.type == target.field and _label_ok(candidate, target.label):
                return pool, candidate
    return None, None


def _set_path(container: Dict[str, Any], parts: List[str], value: Any) -> None:
    node = container
    for part in parts[:-1]:
        child = node.get(part)
        if not isinstance(child, dict):
            child = {}
            node[part] = child
        node = child
    node[parts[-1]] = value


def _remove_path(container: Dict[str, Any], parts: List[str]) -> bool:
    node = container
    for part in parts[:-1]:
        node = node.get(part)
        if not isinstance(node, dict):
            return False
    return node.pop(parts[-1], _MISSING) is not _MISSING


_MISSING = object()


def apply_change(record: vault.TypedRecord, change: Change) -> bool:
    """Apply one record-field change to *record*; False when there was nothing to do (the record has no such field)."""
    target = change.target
    if target.scope == us.SCOPE_STANDARD:
        if target.field == 'title':
            record.title = change.new if change.new is not None else record.title
            return change.new is not None
        if target.field == 'notes':
            record.notes = change.new or ''
            return True
        return False
    pool, fld = find_typed_field(record, target)
    if change.op == OP_REMOVE:
        if fld is None:
            return False
        if target.sub:
            current = fld.value[0] if isinstance(fld.value, list) and fld.value else None
            return _remove_path(current, target.sub.split('.')) if isinstance(current, dict) else False
        if pool is record.custom:
            record.custom.remove(fld)
        else:
            fld.value = []
        return True
    if fld is None:
        if target.scope == us.SCOPE_TYPED:
            return False                                  # the record type has no such field (the planner warned)
        fld = vault.TypedField.new_field(target.field, [], target.label or None)
        record.custom.append(fld)
    if target.sub:
        if not (isinstance(fld.value, list) and fld.value and isinstance(fld.value[0], dict)):
            fld.value = [{}]
        _set_path(fld.value[0], target.sub.split('.'), change.new)
    else:
        fld.value = [change.new]
    return True


def apply_changes_to_record(record: vault.TypedRecord, changes: List[Change]) -> int:
    """Apply *changes* to *record* (in place); returns how many were applied."""
    return sum(1 for change in changes if apply_change(record, change))


# --------------------------------------------------------------------------------------------------------------
# sending
# --------------------------------------------------------------------------------------------------------------

@dataclass
class _Prepared:
    result: ItemResult
    pb: record_pb2.RecordUpdate
    nsf: bool
    count: int


def _default_is_nsf(params) -> Callable[[str], bool]:
    from ..pam.vault_target import is_pam_nsf_record
    return lambda uid: is_pam_nsf_record(params, uid)


def _default_load(params) -> Callable[[str, bool], Optional[vault.TypedRecord]]:
    from .record_loader import load_pam_record

    def load(uid: str, nsf: bool):
        record = load_pam_record(params, uid) if nsf else vault.KeeperRecord.load(params, uid)
        return record if isinstance(record, vault.TypedRecord) else None
    return load


def _default_send(params) -> Callable[[List[record_pb2.RecordUpdate], bool], list]:
    from .batch_nsf import execute_nsf_records_update_with_retry
    from .throttle_retry import execute_records_update_with_retry

    def send(pbs, nsf):
        if nsf:
            return execute_nsf_records_update_with_retry(params, pbs, label='update NSF records', status_type='update record')
        return execute_records_update_with_retry(params, pbs, label='update records', status_type='update record')
    return send


def _default_reread(params) -> Callable[[List[str]], Dict[str, Any]]:
    from .nsf_helpers import refresh_stale_nsf_records, sync_down_preserving_nsf_keys
    from .vault_reader import read_record_state

    def reread(uids):
        sync_down_preserving_nsf_keys(params)
        refresh_stale_nsf_records(params, uids)
        return {uid: read_record_state(params, uid) for uid in uids}
    return reread


def _prepare(params, result: ItemResult, changes: List[Change], is_nsf, load) -> Optional[_Prepared]:
    uid = result.uid
    nsf = is_nsf(uid)
    existing = load(uid, nsf)
    if existing is None:
        raise ValueError('the record could not be loaded')
    record = copy.deepcopy(existing)
    if nsf:
        from ...nested_share_folder.common import get_record_key, get_record_revision
        existing.revision = record.revision = get_record_revision(params, uid, existing.revision or 0)
        if not record.record_key:
            record.record_key = existing.record_key = get_record_key(params, uid, raise_on_missing=False)
        if not record.record_key:
            raise ValueError('the record key is not available')
    count = apply_changes_to_record(record, changes)
    if not count:
        return None
    if vault_extensions.extract_typed_record_data(record) == vault_extensions.extract_typed_record_data(existing):
        return None
    return _Prepared(result, _build_typed_record_update_pb(params, record, existing), nsf, count)


def _send_all(prepared: List[_Prepared], send) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Send classic and NSF records separately; returns ({uid: status entry}, {uid: error text of a failed call})."""
    statuses: Dict[str, Any] = {}
    failed: Dict[str, str] = {}
    for nsf in (False, True):
        group = [p for p in prepared if p.nsf == nsf]
        if not group:
            continue
        try:
            for entry in send([p.pb for p in group], nsf):
                if entry.record_uid:
                    statuses[utils.base64_url_encode(entry.record_uid)] = entry
        except Exception as err:    # pylint: disable=broad-except
            logging.debug('record update call failed: %s', err, exc_info=True)
            text = str(err).strip().splitlines()[0][:300] if str(err).strip() else err.__class__.__name__
            for p in group:
                failed[p.result.uid] = text
    return statuses, failed


def _retry_changes(original: ItemResult, fresh: ItemResult, report: RecordWriteReport) -> List[Change]:
    """The record-field changes to send again, with the PASSWORD rule of the retry."""
    original_secrets = {c.path: c for c in record_field_changes(original) if c.secret}
    keep: List[Change] = []
    for change in record_field_changes(fresh):
        if change.secret:
            before = original_secrets.get(change.path)
            if before is None:
                continue                                   # a password is never newly scheduled by a retry
            if before.old != change.old:
                report.warnings.append(f'{fresh.title or fresh.uid}: the password in the vault changed while the update '
                                       'ran (rotation?); it was NOT written - run update again to see the difference')
                continue
        keep.append(change)
    return keep


def apply_records(params, plan: UpdatePlan, *, is_nsf: Optional[Callable[[str], bool]] = None,
                  load: Optional[Callable] = None, send: Optional[Callable] = None,
                  reread: Optional[Callable] = None) -> RecordWriteReport:
    """Write the record-field changes of every item of *plan*. The callables are the vault calls (replaceable in tests)."""
    from ...importer.imp_exp import record_status_to_str

    is_nsf = is_nsf or _default_is_nsf(params)
    load = load or _default_load(params)
    send = send or _default_send(params)
    reread = reread or _default_reread(params)
    report = RecordWriteReport()

    pending: List[Tuple[ItemResult, List[Change]]] = [
        (r, record_field_changes(r)) for r in plan.results if record_field_changes(r)]
    originals = {r.uid: r for r, _ in pending}
    for attempt in (1, 2):
        if not pending:
            break
        prepared: List[_Prepared] = []
        for result, changes in pending:
            label = result.title or result.uid
            try:
                item = _prepare(params, result, changes, is_nsf, load)
            except Exception as err:    # pylint: disable=broad-except
                logging.debug('preparing %s failed: %s', result.uid, err, exc_info=True)
                report.errors.append(f'{label}: record fields were not written: {err}')
                continue
            if item is not None:
                prepared.append(item)
        if not prepared:
            break
        statuses, failed = _send_all(prepared, send)
        out_of_sync: List[_Prepared] = []
        for p in prepared:
            label = p.result.title or p.result.uid
            entry = statuses.get(p.result.uid)
            if p.result.uid in failed:
                report.errors.append(f'{label}: record fields were not written: {failed[p.result.uid]}')
            elif entry is None:
                report.errors.append(f'{label}: record fields were not written: no answer from the server')
            elif entry.status == record_pb2.RS_SUCCESS:
                report.applied.append(f'{label}: record fields ({p.count})')
            elif entry.status == record_pb2.RS_OUT_OF_SYNC:
                out_of_sync.append(p)
            else:
                report.errors.append(f'{label}: record fields were not written: {record_status_to_str(entry.status)}')
        if not out_of_sync:
            break
        if attempt == 2 or plan.rediff is None:
            for p in out_of_sync:
                report.errors.append(f'{p.result.title or p.result.uid}: the record changed while the update ran '
                                     '(out of sync); run update again')
            break
        uids = [p.result.uid for p in out_of_sync]
        try:
            fresh = plan.rediff(reread(uids))
        except Exception as err:        # pylint: disable=broad-except
            logging.debug('re-read after out of sync failed: %s', err, exc_info=True)
            for p in out_of_sync:
                report.errors.append(f'{p.result.title or p.result.uid}: out of sync and the record could not be '
                                     f'read again: {err}')
            break
        pending = []
        for uid in uids:
            again = fresh.get(uid)
            if again is None or not again.compared:
                continue
            changes = _retry_changes(originals[uid], again, report)
            if changes:
                pending.append((again, changes))
            else:
                report.applied.append(f'{again.title or uid}: record fields (already up to date)')
    return report
