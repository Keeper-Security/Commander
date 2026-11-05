"""NSF-aware batch vault writes for PAM import/extend Step 1a / 1b."""
from __future__ import annotations

import json
import logging
from typing import Callable, List, Optional

from ... import crypto, utils, vault, vault_extensions
from ...nested_share_folder.common import get_folder_key
from ...nested_share_folder.record_api import create_record_data_v3, record_add_v3, record_update_v3
from ...proto import record_pb2
from ...recordv3 import RecordV3
from .throttle_retry import (
    IMPORT_ON_EXHAUSTED,
    call_with_throttle_retry,
    chunked_with_retry,
    rest_fail_on_throttle,
)


def project_uses_nsf(params, project: Optional[dict] = None) -> bool:
    """True when import/extend is targeting Nested Share Folders."""
    if project and (project.get('options') or {}).get('use_nsf') is True:
        return True
    nsf_folders = getattr(params, 'nested_share_folders', None) or {}
    return bool(nsf_folders)


def sync_down_after_batch(params, project: Optional[dict] = None) -> None:
    """Sync vault; preserve NSF folder keys when NSF is in play."""
    if project_uses_nsf(params, project):
        from .nsf_helpers import sync_down_preserving_nsf_keys
        sync_down_preserving_nsf_keys(params)
    else:
        from ... import api
        api.sync_down(params)


def typed_record_to_nsf_record_add(params, record: vault.TypedRecord, folder_uid: str):
    """Build ``record.v3.RecordAdd`` for ``vault/records/v3/add`` into an NSF folder."""
    if not record.record_uid:
        record.record_uid = utils.generate_uid()
    if not RecordV3.is_valid_ref_uid(record.record_uid):
        raise ValueError(f'Invalid record UID for NSF add: {record.record_uid!r}')
    if not record.record_key:
        record.record_key = utils.generate_aes_key()

    folder_key = get_folder_key(params, folder_uid, raise_on_missing=True)
    data = vault_extensions.extract_typed_record_data(record)
    ra = create_record_data_v3(
        record_uid=record.record_uid,
        record_key=record.record_key,
        data=data,
        folder_uid=folder_uid,
        folder_key=folder_key,
        data_key=params.data_key,
        client_modified_time=utils.current_milli_time(),
    )

    refs = vault_extensions.extract_typed_record_refs(record)
    for ref in refs:
        ref_record_key = None
        if record.linked_keys:
            ref_record_key = record.linked_keys.get(ref)
        if not ref_record_key:
            ref_record = vault.KeeperRecord.load(params, ref)
            if ref_record:
                ref_record_key = ref_record.record_key
        if not ref_record_key:
            continue
        link = record_pb2.RecordLink()
        link.record_uid = utils.base64_url_decode(ref)
        link.record_key = crypto.encrypt_aes_v2(ref_record_key, record.record_key)
        ra.recordLinks.append(link)

    if params.enterprise_ec_key:
        audit_data = vault_extensions.extract_audit_data(record)
        if audit_data:
            ra.audit.version = 0
            ra.audit.data = crypto.encrypt_ec(
                json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key,
            )
    return ra


def execute_nsf_records_add_with_retry(
    params,
    records,
    *,
    label: str = 'records/v3/add',
    status_type: Optional[str] = 'record',
    on_chunk: Optional[Callable[[int], None]] = None,
    on_exhausted=IMPORT_ON_EXHAUSTED,
):
    """Chunked ``vault/records/v3/add`` with per-chunk throttle retry (raises ``ChunkedAddError``)."""
    from ...importer.imp_exp import record_status_to_str, report_statuses

    results = chunked_with_retry(
        params, records, lambda chunk: list(record_add_v3(params, chunk).records),
        label=label, on_chunk=on_chunk, on_exhausted=on_exhausted,
    )
    if status_type:
        report_statuses(status_type, (record_status_to_str(x.status) for x in results))
    return results


def execute_nsf_records_update_with_retry(
    params,
    records: List[record_pb2.RecordUpdate],
    *,
    label: str = 'records/v3/update',
    status_type: str = 'record',
    on_exhausted=IMPORT_ON_EXHAUSTED,
):
    """Chunked ``vault/records/v3/update`` with outer throttle retry."""
    from ...importer.imp_exp import record_status_to_str, report_statuses

    def _run():
        rs_record = []
        remaining = list(records)
        while remaining:
            chunk = remaining[:999]
            remaining = remaining[999:]
            rs = record_update_v3(params, chunk)
            rs_record.extend(rs.records)
        if status_type:
            report_statuses(status_type, (record_status_to_str(x.status) for x in rs_record))
        return rs_record

    return call_with_throttle_retry(
        _run,
        label=label,
        fail_on_throttle=rest_fail_on_throttle(params),
        on_exhausted=on_exhausted,
    )
