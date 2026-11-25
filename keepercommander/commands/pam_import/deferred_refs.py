"""Step 1b — deferred ref updates (Channel B pamSettings JSON + Channel A record_links)."""
from __future__ import annotations

import copy
import itertools
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ... import api, crypto, utils, vault
from ...importer import imp_exp
from .throttle_retry import execute_records_update_with_retry
from ...proto import record_pb2
from ...security_audit import attach_security_data
from ... import vault_extensions
from ...recordv3 import RecordV3
from ..pam.vault_target import is_pam_nsf_record
from .batch_nsf import execute_nsf_records_update_with_retry, sync_down_after_batch
from .record_loader import load_pam_record
from .base import (
    PamDatabaseObject,
    PamDirectoryObject,
    PamMachineObject,
    PamRemoteBrowserObject,
    PamSettingsFieldData,
)

PamResource = Union[
    PamMachineObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamRemoteBrowserObject,
]


MAX_NUMBER_OF_RECORD_LINKS = 100


@dataclass
class DeferredRefUpdate:
    """Channel B — patch embedded JSON ref into pamSettings / pamRemoteBrowserSettings."""

    record_uid: str
    settings_field: str  # pamSettings | pamRemoteBrowserSettings
    json_path: Tuple[str, ...]
    value: Any


@dataclass
class DeferredChannelAUpdate:
    """Channel A — typed recordRef or script recordRef to add at Step 1b."""

    record_uid: str
    ref_uid: str
    field_type: str  # recordRef | script
    field_label: Optional[str] = None
    script_index: Optional[int] = None


def extract_channel_a_refs(record: vault.TypedRecord) -> Set[str]:
    """Typed *Ref and script recordRef UIDs (for linked_keys / record_links)."""
    refs: Set[str] = set()
    for field in itertools.chain(record.fields, record.custom):
        if field.type in {'fileRef', 'addressRef', 'cardRef', 'recordRef'}:
            if not isinstance(field.value, list):
                continue
            for ref in field.value:
                if isinstance(ref, str) and ref.strip():
                    refs.add(ref.strip())
        elif field.type == 'script' and isinstance(field.value, list):
            for script in field.value:
                if not isinstance(script, dict):
                    continue
                for ref in script.get('recordRef') or []:
                    if isinstance(ref, str) and ref.strip():
                        refs.add(ref.strip())
    return refs


@dataclass
class DeferredRefApplySummary:
    failures: List[Tuple[str, str]] = None  # (record_uid, reason)
    warnings: List[Tuple[str, str]] = None  # (record_uid, reason) — skipped unresolved refs

    def __post_init__(self):
        if self.failures is None:
            self.failures = []
        if self.warnings is None:
            self.warnings = []


def _target_uids_from_deferral(item: DeferredRefUpdate) -> List[str]:
    value = item.value
    if isinstance(value, list):
        return [u for u in value if isinstance(u, str) and u.strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _uid_in_accessible_vault(params, uid: str) -> bool:
    """True when *uid* is present in classic or NSF record caches."""
    if not uid:
        return False
    if uid in (getattr(params, 'record_cache', None) or {}):
        return True
    if uid in (getattr(params, 'nested_share_records', None) or {}):
        return True
    if uid in (getattr(params, 'nested_share_record_data', None) or {}):
        return True
    return False


def _filter_applicable_channel_a(
    params,
    items: List[DeferredChannelAUpdate],
) -> Tuple[List[DeferredChannelAUpdate], List[Tuple[str, str]]]:
    applicable: List[DeferredChannelAUpdate] = []
    warnings: List[Tuple[str, str]] = []
    for item in items:
        if not _uid_in_accessible_vault(params, item.ref_uid):
            reason = f'target uid not in vault: {item.ref_uid}'
            logging.warning(
                f'Step 1b skipping Channel A ref on {item.record_uid} '
                f'({item.field_type} → {item.ref_uid}): {reason}',
            )
            warnings.append((item.record_uid, reason))
            continue
        applicable.append(item)
    return applicable, warnings


def collect_channel_a_deferrals(
    record: vault.TypedRecord,
    record_uid: str,
    inserted_uids: Set[str],
    deferred: List[DeferredChannelAUpdate],
) -> None:
    """Strip typed/script recordRef targets not yet in vault; queue for Step 1b."""
    if not record_uid:
        return
    for field in itertools.chain(record.fields, record.custom):
        if field.type == 'recordRef' and isinstance(field.value, list):
            kept: List[str] = []
            for ref in field.value:
                if not isinstance(ref, str) or not ref.strip():
                    continue
                ref = ref.strip()
                if _uid_ready(ref, inserted_uids):
                    kept.append(ref)
                else:
                    deferred.append(DeferredChannelAUpdate(
                        record_uid=record_uid,
                        ref_uid=ref,
                        field_type='recordRef',
                        field_label=field.label,
                    ))
            field.value = kept
        elif field.type == 'script' and isinstance(field.value, list):
            for idx, script in enumerate(field.value):
                if not isinstance(script, dict):
                    continue
                refs = script.get('recordRef')
                if not isinstance(refs, list):
                    continue
                kept_refs: List[str] = []
                for ref in refs:
                    if not isinstance(ref, str) or not ref.strip():
                        continue
                    ref = ref.strip()
                    if _uid_ready(ref, inserted_uids):
                        kept_refs.append(ref)
                    else:
                        deferred.append(DeferredChannelAUpdate(
                            record_uid=record_uid,
                            ref_uid=ref,
                            field_type='script',
                            field_label=field.label,
                            script_index=idx,
                        ))
                script['recordRef'] = kept_refs


def _find_typed_field(
    record: vault.TypedRecord,
    field_type: str,
    field_label: Optional[str],
) -> Optional[vault.TypedField]:
    for field in itertools.chain(record.fields, record.custom):
        if field.type != field_type:
            continue
        if field_label is None or field.label == field_label:
            return field
    return None


def _apply_channel_a_to_record(
    record: vault.TypedRecord,
    items: List[DeferredChannelAUpdate],
) -> bool:
    modified = False
    for item in items:
        if item.field_type == 'recordRef':
            field = _find_typed_field(record, 'recordRef', item.field_label)
            if not field:
                field = vault.TypedField.new_field('recordRef', [], item.field_label or '')
                record.fields.append(field)
            values = list(field.value or [])
            if item.ref_uid not in values:
                values.append(item.ref_uid)
                field.value = values
                modified = True
        elif item.field_type == 'script':
            field = _find_typed_field(record, 'script', item.field_label)
            if not field or not isinstance(field.value, list):
                continue
            idx = item.script_index
            if idx is None or idx < 0 or idx >= len(field.value):
                continue
            script = field.value[idx]
            if not isinstance(script, dict):
                continue
            refs = list(script.get('recordRef') or [])
            if item.ref_uid not in refs:
                refs.append(item.ref_uid)
                script['recordRef'] = refs
                modified = True
    return modified


def linked_keys_for_channel_a_refs(
    record: vault.TypedRecord,
    record_keys: Dict[str, bytes],
) -> Dict[str, bytes]:
    """Pre-populate linked_keys for Channel A refs present on the record."""
    linked: Dict[str, bytes] = {}
    for ref_uid in extract_channel_a_refs(record):
        if ref_uid in record_keys:
            linked[ref_uid] = record_keys[ref_uid]
    return linked


def _filter_applicable_deferrals(
    params,
    items: List[DeferredRefUpdate],
) -> Tuple[List[DeferredRefUpdate], List[Tuple[str, str]]]:
    """Drop deferrals whose target UIDs are still missing from vault; return warnings."""
    applicable: List[DeferredRefUpdate] = []
    warnings: List[Tuple[str, str]] = []
    for item in items:
        targets = _target_uids_from_deferral(item)
        missing = [t for t in targets if not _uid_in_accessible_vault(params, t)]
        if missing:
            reason = f'target uid(s) not in vault: {", ".join(missing)}'
            logging.warning(
                f'Step 1b skipping deferred ref on {item.record_uid} '
                f'({item.settings_field} {"/".join(item.json_path)}): {reason}',
            )
            warnings.append((item.record_uid, reason))
            continue
        applicable.append(item)
    return applicable, warnings


def _uid_ready(uid: str, inserted_uids: Set[str]) -> bool:
    return bool(uid and uid in inserted_uids)


def _queue_if_deferred(
    deferred: List[DeferredRefUpdate],
    *,
    record_uid: str,
    settings_field: str,
    json_path: Tuple[str, ...],
    value: Any,
    inserted_uids: Set[str],
    ref_uids: List[str],
) -> bool:
    """Return True if queued (stripped from create); False if refs already available."""
    if not ref_uids:
        return False
    if all(_uid_ready(u, inserted_uids) for u in ref_uids):
        return False
    deferred.append(DeferredRefUpdate(
        record_uid=record_uid,
        settings_field=settings_field,
        json_path=json_path,
        value=copy.deepcopy(value),
    ))
    return True


def collect_connection_deferrals(
    record_uid: str,
    settings_field: str,
    connection: dict,
    inserted_uids: Set[str],
    deferred: List[DeferredRefUpdate],
) -> dict:
    """Return connection dict safe for Step 1a create; queue stripped refs for Step 1b."""
    connection = copy.deepcopy(connection or {})
    user_records = connection.get('userRecords')
    if isinstance(user_records, list) and user_records:
        if _queue_if_deferred(
            deferred,
            record_uid=record_uid,
            settings_field=settings_field,
            json_path=('connection', 'userRecords'),
            value=user_records,
            inserted_uids=inserted_uids,
            ref_uids=[u for u in user_records if isinstance(u, str)],
        ):
            connection.pop('userRecords', None)

    sftp = connection.get('sftp')
    if isinstance(sftp, dict):
        sftp = copy.deepcopy(sftp)
        for key in ('sftpResourceUid', 'sftpUserUid'):
            uid = sftp.get(key)
            if isinstance(uid, str) and uid.strip():
                if _queue_if_deferred(
                    deferred,
                    record_uid=record_uid,
                    settings_field=settings_field,
                    json_path=('connection', 'sftp', key),
                    value=uid.strip(),
                    inserted_uids=inserted_uids,
                    ref_uids=[uid.strip()],
                ):
                    sftp.pop(key, None)
        if sftp:
            connection['sftp'] = sftp
        elif 'sftp' in connection:
            connection.pop('sftp', None)

    http_uid = connection.get('httpCredentialsUid')
    if isinstance(http_uid, list):
        http_uid = next(
            (u.strip() for u in http_uid if isinstance(u, str) and u.strip()),
            '',
        )
        if http_uid:
            connection['httpCredentialsUid'] = http_uid
        else:
            connection.pop('httpCredentialsUid', None)
            http_uid = None
    if isinstance(http_uid, str) and http_uid.strip():
        if _queue_if_deferred(
            deferred,
            record_uid=record_uid,
            settings_field=settings_field,
            json_path=('connection', 'httpCredentialsUid'),
            value=http_uid.strip(),
            inserted_uids=inserted_uids,
            ref_uids=[http_uid.strip()],
        ):
            connection.pop('httpCredentialsUid', None)

    return connection


def collect_embedded_deferrals_for_object(
    obj: PamResource,
    inserted_uids: Set[str],
    deferred: List[DeferredRefUpdate],
) -> None:
    """Inspect resolved in-memory object; append deferrals for refs not yet in vault."""
    if isinstance(obj, PamRemoteBrowserObject):
        rbi = getattr(obj, 'rbi_settings', None)
        conn_obj = getattr(rbi, 'connection', None) if rbi else None
        if not conn_obj:
            return
        full = conn_obj.to_record_dict() or {}
        _ = collect_connection_deferrals(
            obj.uid, 'pamRemoteBrowserSettings', full, inserted_uids, deferred,
        )
        return

    ps = getattr(obj, 'pam_settings', None)
    if not ps or not isinstance(ps, PamSettingsFieldData):
        return
    conn_obj = getattr(ps, 'connection', None)
    if not conn_obj:
        return
    full = conn_obj.to_record_dict() or {}
    _ = collect_connection_deferrals(obj.uid, 'pamSettings', full, inserted_uids, deferred)


def _ensure_settings_root(field: vault.TypedField) -> dict:
    if not field.value or not isinstance(field.value, list) or not field.value:
        field.value = [{}]
    root = field.value[0]
    if not isinstance(root, dict):
        field.value[0] = {}
        root = field.value[0]
    return root


def _connection_dict(settings_root: dict) -> dict:
    connection = settings_root.get('connection')
    if not isinstance(connection, dict):
        connection = {}
        settings_root['connection'] = connection
    return connection


def _sftp_dict(connection: dict) -> dict:
    sftp = connection.get('sftp')
    if not isinstance(sftp, dict):
        sftp = {}
        connection['sftp'] = sftp
    return sftp


def apply_user_records_to_settings(settings_root: dict, uids: Any) -> None:
    """Patch pamSettings connection.userRecords (mirrors ``set_user_record_uid`` → ``to_record_dict``)."""
    connection = _connection_dict(settings_root)
    if isinstance(uids, list):
        cleaned = [u.strip() for u in uids if isinstance(u, str) and u.strip()]
        if cleaned:
            connection['userRecords'] = cleaned
    elif isinstance(uids, str) and uids.strip():
        connection['userRecords'] = [uids.strip()]


def apply_sftp_resource_uid_to_settings(settings_root: dict, uid: str) -> None:
    """Patch connection.sftp.sftpResourceUid (mirrors ``set_sftp_uid(..., 'sftpResourceUid', ...)``)."""
    if not (isinstance(uid, str) and uid.strip() and RecordV3.is_valid_ref_uid(uid.strip())):
        return
    _sftp_dict(_connection_dict(settings_root))['sftpResourceUid'] = uid.strip()


def apply_sftp_user_uid_to_settings(settings_root: dict, uid: str) -> None:
    """Patch connection.sftp.sftpUserUid (mirrors ``set_sftp_uid(..., 'sftpUserUid', ...)``)."""
    if not (isinstance(uid, str) and uid.strip() and RecordV3.is_valid_ref_uid(uid.strip())):
        return
    _sftp_dict(_connection_dict(settings_root))['sftpUserUid'] = uid.strip()


def apply_http_credentials_uid_to_settings(settings_root: dict, uid: str) -> None:
    """Patch connection.httpCredentialsUid (mirrors HTTP ``to_record_dict``)."""
    if isinstance(uid, str) and uid.strip():
        _connection_dict(settings_root)['httpCredentialsUid'] = uid.strip()


_DEFERRED_REF_APPLIERS = {
    ('connection', 'userRecords'): apply_user_records_to_settings,
    ('connection', 'sftp', 'sftpResourceUid'): apply_sftp_resource_uid_to_settings,
    ('connection', 'sftp', 'sftpUserUid'): apply_sftp_user_uid_to_settings,
    ('connection', 'httpCredentialsUid'): apply_http_credentials_uid_to_settings,
}


def _set_nested(root: dict, path: Tuple[str, ...], value: Any) -> None:
    node = root
    for key in path[:-1]:
        child = node.get(key)
        if not isinstance(child, dict):
            child = {}
            node[key] = child
        node = child
    node[path[-1]] = copy.deepcopy(value)


def _apply_deferred_ref_item(settings_root: dict, item: DeferredRefUpdate) -> None:
    applier = _DEFERRED_REF_APPLIERS.get(item.json_path)
    if applier:
        applier(settings_root, item.value)
    else:
        _set_nested(settings_root, item.json_path, item.value)


def _apply_deferrals_to_record(
    record: vault.TypedRecord,
    items: List[DeferredRefUpdate],
) -> bool:
    modified = False
    by_field: Dict[str, List[DeferredRefUpdate]] = defaultdict(list)
    for item in items:
        by_field[item.settings_field].append(item)

    for field_name, field_items in by_field.items():
        field = record.get_typed_field(field_name)
        if not field:
            field = vault.TypedField.new_field(field_name, [{}], '')
            if field_name in ('pamSettings', 'pamRemoteBrowserSettings'):
                record.custom.append(field)
            else:
                record.fields.append(field)
        root = _ensure_settings_root(field)
        for item in field_items:
            _apply_deferred_ref_item(root, item)
            modified = True
    return modified


def _build_typed_record_update_pb(
    params,
    record: vault.TypedRecord,
    existing_record: vault.TypedRecord,
) -> record_pb2.RecordUpdate:
    """Build RecordUpdate protobuf for batch vault/records_update (Step 1b)."""
    record_uid_bytes = utils.base64_url_decode(record.record_uid)
    ru = record_pb2.RecordUpdate()
    ru.record_uid = record_uid_bytes
    ru.client_modified_time = utils.current_milli_time()
    ru.revision = existing_record.revision
    ru = attach_security_data(params, record, ru)

    data = vault_extensions.extract_typed_record_data(record)
    json_data = api.get_record_data_json_bytes(data)
    ru.data = crypto.encrypt_aes_v2(json_data, record.record_key)

    existing_refs = extract_channel_a_refs(existing_record) | vault_extensions.extract_typed_record_refs(existing_record)
    refs = extract_channel_a_refs(record) | vault_extensions.extract_typed_record_refs(record)
    new_refs = refs.difference(existing_refs)
    if len(refs) > MAX_NUMBER_OF_RECORD_LINKS:
        logging.warning(
            f'Step 1b record {record.record_uid} projects {len(refs)} typed refs '
            f'(limit {MAX_NUMBER_OF_RECORD_LINKS}); truncating record_links_add',
        )
        room = MAX_NUMBER_OF_RECORD_LINKS - len(existing_refs)
        if room <= 0:
            new_refs = set()
        else:
            new_refs = set(sorted(new_refs)[:room])
    for ref in new_refs:
        ref_record_key = None
        if record.linked_keys and ref in record.linked_keys:
            ref_record_key = record.linked_keys[ref]
        if not ref_record_key:
            ref_record = vault.KeeperRecord.load(params, ref)
            if ref_record:
                ref_record_key = ref_record.record_key
        if ref_record_key:
            link = record_pb2.RecordLink()
            link.record_uid = utils.base64_url_decode(ref)
            link.record_key = crypto.encrypt_aes_v2(ref_record_key, record.record_key)
            ru.record_links_add.append(link)
    for ref in existing_refs.difference(refs):
        ru.record_links_remove.append(utils.base64_url_decode(ref))

    if params.enterprise_ec_key:
        audit_data = vault_extensions.extract_audit_data(record)
        if audit_data:
            ru.audit.version = 0
            ru.audit.data = crypto.encrypt_ec(
                json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key,
            )
    return ru


def _attach_linked_keys(
    record: vault.TypedRecord,
    items: List[DeferredChannelAUpdate],
    record_keys: Optional[Dict[str, bytes]],
) -> None:
    if not record_keys:
        return
    linked = dict(record.linked_keys or {})
    for item in items:
        key = record_keys.get(item.ref_uid)
        if key:
            linked[item.ref_uid] = key
    if linked:
        record.linked_keys = linked


def apply_deferred_ref_updates(
    params,
    deferred_refs: List[DeferredRefUpdate],
    deferred_links: Optional[List[DeferredChannelAUpdate]] = None,
    *,
    record_keys: Optional[Dict[str, bytes]] = None,
    extend_mode: bool = False,
) -> DeferredRefApplySummary:
    """Step 1b — patch Channel B JSON refs and Channel A record_links after all 1a tiers."""
    summary = DeferredRefApplySummary()
    deferred_links = deferred_links or []
    if not deferred_refs and not deferred_links:
        return summary

    by_record_b: Dict[str, List[DeferredRefUpdate]] = defaultdict(list)
    for item in deferred_refs:
        by_record_b[item.record_uid].append(item)
    by_record_a: Dict[str, List[DeferredChannelAUpdate]] = defaultdict(list)
    for item in deferred_links:
        by_record_a[item.record_uid].append(item)

    all_uids = set(by_record_b.keys()) | set(by_record_a.keys())
    update_pbs: List[record_pb2.RecordUpdate] = []
    update_uids: List[str] = []

    for record_uid in all_uids:
        if not RecordV3.is_valid_ref_uid(record_uid):
            summary.failures.append((record_uid, 'invalid record uid'))
            continue
        loaded = load_pam_record(params, record_uid)
        if not loaded or not isinstance(loaded, vault.TypedRecord):
            summary.failures.append((record_uid, 'record not found in vault'))
            continue
        try:
            existing = loaded
            record = copy.deepcopy(loaded)
            if not record.record_key:
                from ...nested_share_folder.common import get_record_key
                record.record_key = get_record_key(
                    params, record_uid, raise_on_missing=False,
                )
            if not record.record_key:
                summary.failures.append((record_uid, 'record key not found'))
                continue
            modified = False
            b_items = by_record_b.get(record_uid, [])
            applicable_b: List[DeferredRefUpdate] = []
            if b_items:
                applicable_b, b_warnings = _filter_applicable_deferrals(params, b_items)
                summary.warnings.extend(b_warnings)
                if applicable_b and _apply_deferrals_to_record(record, applicable_b):
                    modified = True
            a_items = by_record_a.get(record_uid, [])
            applicable_a: List[DeferredChannelAUpdate] = []
            if a_items:
                applicable_a, a_warnings = _filter_applicable_channel_a(params, a_items)
                summary.warnings.extend(a_warnings)
                if applicable_a:
                    _attach_linked_keys(record, applicable_a, record_keys)
                    if _apply_channel_a_to_record(record, applicable_a):
                        modified = True
                    else:
                        modified = True
            if not (modified or applicable_b or applicable_a):
                continue
            update_pbs.append(_build_typed_record_update_pb(params, record, existing))
            update_uids.append(record_uid)
        except Exception as err:
            logging.error(f'Step 1b prepare failed for {record_uid}: {err}', exc_info=True)
            summary.failures.append((record_uid, str(err)))

    if summary.failures:
        return summary

    if update_pbs:
        classic_pbs: List[record_pb2.RecordUpdate] = []
        classic_uids: List[str] = []
        nsf_pbs: List[record_pb2.RecordUpdate] = []
        nsf_uids: List[str] = []
        for pb, uid in zip(update_pbs, update_uids):
            if is_pam_nsf_record(params, uid):
                nsf_pbs.append(pb)
                nsf_uids.append(uid)
            else:
                classic_pbs.append(pb)
                classic_uids.append(uid)

        if classic_pbs:
            results = execute_records_update_with_retry(
                params, classic_pbs, label='Step 1b deferred refs',
            )
            parse_summary = parse_deferred_update_results(params, classic_uids, results)
            summary.failures.extend(parse_summary.failures)
        if nsf_pbs and not summary.failures:
            results = execute_nsf_records_update_with_retry(
                params, nsf_pbs, label='Step 1b NSF deferred refs',
            )
            parse_summary = parse_deferred_update_results(params, nsf_uids, results)
            summary.failures.extend(parse_summary.failures)

    if summary.failures:
        return summary

    sync_down_after_batch(params)
    return summary


def plan_deferred_refs_for_tiers(
    tiers,
    initial_inserted: Set[str],
) -> List[DeferredRefUpdate]:
    """Dry-run helper: simulate deferrals accumulated across tier order."""
    deferred: List[DeferredRefUpdate] = []
    inserted = set(initial_inserted)
    for tier in tiers:
        for obj in tier.objects:
            if isinstance(obj, (PamMachineObject, PamDatabaseObject, PamDirectoryObject, PamRemoteBrowserObject)):
                collect_embedded_deferrals_for_object(obj, inserted, deferred)
        inserted.update(getattr(o, 'uid', '') for o in tier.objects if getattr(o, 'uid', ''))
    return deferred


def parse_deferred_update_results(
    params,
    record_uids: List[str],
    results: List[record_pb2.RecordModifyStatus],
) -> DeferredRefApplySummary:
    """Optional batch path — parse per-record update statuses."""
    summary = DeferredRefApplySummary()
    by_uid = {utils.base64_url_encode(r.record_uid): r for r in results if r.record_uid}
    for uid in record_uids:
        rs = by_uid.get(uid)
        if rs is None:
            summary.failures.append((uid, 'missing from update response'))
        elif rs.status != record_pb2.RS_SUCCESS:
            summary.failures.append((uid, imp_exp.record_status_to_str(rs.status)))
    return summary
