"""Step 1c — batched file uploads (files_add + parallel PUTs + records_update)."""
from __future__ import annotations

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Tuple

import requests

from ... import api, crypto, utils, vault
from ...error import KeeperApiError
from ...importer.encryption_reader import EncryptionReader
from ...importer import imp_exp
from .throttle_retry import (
    IMPORT_ON_EXHAUSTED,
    call_with_throttle_retry,
    execute_records_update_with_retry,
    raise_if_http_throttled,
    rest_fail_on_throttle,
)
from ...proto import record_pb2
from .base import PamScriptObject, resolve_script_creds
from .pam_record_build import PamObject
from .deferred_refs import _build_typed_record_update_pb, linked_keys_for_channel_a_refs

FILES_ADD_CHUNK = 300
UPLOAD_MAX_WORKERS = 12
IV_LEN = 12
GCM_TAG_LEN = 16
MAX_FILE_BYTES = 100 * 2 ** 20

UploadKind = Literal['attachment', 'script']


@dataclass
class PendingUpload:
    parent_uid: str
    file_path: str
    name: str
    size: int
    kind: UploadKind
    script: Optional[PamScriptObject] = None


@dataclass
class _UploadSlot:
    pending: PendingUpload
    file_uid: bytes
    file_key: bytes


@dataclass
class _UploadSuccess:
    pending: PendingUpload
    file_uid: str
    file_key: bytes


@dataclass
class BatchAttachmentSummary:
    failures: List[Tuple[str, str]] = field(default_factory=list)
    warnings: List[Tuple[str, str]] = field(default_factory=list)
    uploaded_count: int = 0


def _collect_script_uploads(parent_uid: str, script_list: List[PamScriptObject]) -> List[PendingUpload]:
    """Collect rotation script file uploads for one parent record."""
    pending: List[PendingUpload] = []
    if not parent_uid or not script_list:
        return pending
    for script in script_list:
        if not isinstance(script, PamScriptObject) or not script.file:
            continue
        if not script.validate():
            logging.warning(f'Step 1c script file not found (skipped): {script.file}')
            continue
        path = os.path.abspath(os.path.expanduser(script.file))
        size = os.path.getsize(path)
        if size == 0 or size > MAX_FILE_BYTES:
            logging.warning(f'Step 1c script file size invalid (skipped): {script.file}')
            continue
        pending.append(PendingUpload(
            parent_uid=parent_uid,
            file_path=path,
            name=os.path.basename(path),
            size=size,
            kind='script',
            script=script,
        ))
    return pending


def collect_pending_uploads(obj: PamObject) -> List[PendingUpload]:
    """Collect attachment files and rotation script files for one created record."""
    pending: List[PendingUpload] = []
    parent_uid = getattr(obj, 'uid', '') or ''
    if not parent_uid:
        return pending

    attachments = getattr(obj, 'attachments', None)
    files = attachments.attachments if attachments and hasattr(attachments, 'attachments') else []
    if isinstance(files, list):
        for item in files:
            if not item or not getattr(item, 'file', None):
                continue
            path = os.path.abspath(os.path.expanduser(item.file))
            if not os.path.isfile(path):
                logging.warning(f'Step 1c attachment not found (skipped): {item.file}')
                continue
            size = os.path.getsize(path)
            if size == 0 or size > MAX_FILE_BYTES:
                logging.warning(f'Step 1c attachment size invalid (skipped): {item.file}')
                continue
            pending.append(PendingUpload(
                parent_uid=parent_uid,
                file_path=path,
                name=os.path.basename(path),
                size=size,
                kind='attachment',
            ))

    scripts_obj = getattr(obj, 'scripts', None)
    script_list = scripts_obj.scripts if scripts_obj and hasattr(scripts_obj, 'scripts') else []
    if isinstance(script_list, list):
        pending.extend(_collect_script_uploads(parent_uid, script_list))
    return pending


def collect_config_script_uploads(
    pam_cfg_uid: str,
    scripts: List[PamScriptObject],
) -> List[PendingUpload]:
    """Collect pamConfiguration import-tail scripts (resolved recordRef cred targets only)."""
    cred_scripts = [
        s for s in scripts
        if isinstance(s, PamScriptObject) and s.record_refs
    ]
    return _collect_script_uploads(pam_cfg_uid, cred_scripts)


def _put_encrypted_file(params, url: str, parameters: str, file_path: str, file_key: bytes, success_status: int) -> bool:
    def _upload_once() -> bool:
        form_params = json.loads(parameters)
        with open(file_path, 'rb') as src:
            with EncryptionReader.get_buffered_reader(src, file_key) as encrypted_src:
                form_files = {'file': (os.path.basename(file_path), encrypted_src, 'application/octet-stream')}
                response = requests.post(
                    url,
                    data=form_params,
                    files=form_files,
                    proxies=params.rest_context.proxies,
                    verify=params.rest_context.certificate_check,
                )
        raise_if_http_throttled(response)
        expected = form_params.get('success_action_status')
        if expected is not None:
            if str(response.status_code) != str(expected):
                raise KeeperApiError('upload_failed', f'PUT status {response.status_code}')
            return True
        if response.status_code != success_status:
            raise KeeperApiError('upload_failed', f'PUT status {response.status_code}')
        return True

    return call_with_throttle_retry(
        _upload_once,
        label=os.path.basename(file_path),
        fail_on_throttle=rest_fail_on_throttle(params),
        on_exhausted=IMPORT_ON_EXHAUSTED,
    )


def _files_add_chunk(params, slots: List[_UploadSlot]) -> record_pb2.FilesAddResponse:
    rq = record_pb2.FilesAddRequest()
    rq.client_time = utils.current_milli_time()
    for slot in slots:
        file_data = {
            'name': slot.pending.name,
            'size': slot.pending.size,
            'title': slot.pending.name,
            'lastModified': api.current_milli_time(),
            'type': 'application/octet-stream',
        }
        rf = record_pb2.File()
        rf.record_uid = slot.file_uid
        rf.record_key = crypto.encrypt_aes_v2(slot.file_key, params.data_key)
        rf.data = crypto.encrypt_aes_v2(json.dumps(file_data).encode('utf-8'), slot.file_key)
        rf.fileSize = IV_LEN + slot.pending.size + GCM_TAG_LEN
        rq.files.append(rf)
    return call_with_throttle_retry(
        lambda: api.communicate_rest(
            params, rq, 'vault/files_add', rs_type=record_pb2.FilesAddResponse,
        ),
        label='files_add',
        fail_on_throttle=rest_fail_on_throttle(params),
        on_exhausted=IMPORT_ON_EXHAUSTED,
    )


def _parallel_puts(
    params,
    work: List[Tuple[_UploadSlot, record_pb2.FileAddStatus]],
    *,
    max_workers: int,
) -> Tuple[List[_UploadSuccess], List[Tuple[str, str]]]:
    successes: List[_UploadSuccess] = []
    failures: List[Tuple[str, str]] = []

    def _task(item: Tuple[_UploadSlot, record_pb2.FileAddStatus]) -> Tuple[str, Optional[_UploadSuccess], Optional[str]]:
        slot, fres = item
        if fres.status != record_pb2.FA_SUCCESS:
            return ('fail', None, f'files_add status {fres.status}')
        try:
            _put_encrypted_file(
                params, fres.url, fres.parameters,
                slot.pending.file_path, slot.file_key, fres.success_status_code,
            )
        except Exception as err:
            return ('fail', None, str(err))
        return ('ok', _UploadSuccess(
            slot.pending,
            utils.base64_url_encode(fres.record_uid),
            slot.file_key,
        ), None)

    workers = min(max_workers, max(1, len(work)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_task, w): w for w in work}
        for fut in as_completed(futures):
            slot, _ = futures[fut]
            status, success, reason = fut.result()
            if status == 'ok' and success:
                successes.append(success)
            else:
                failures.append((slot.pending.parent_uid, reason or 'upload failed'))
    return successes, failures


def _apply_uploads_to_record(
    record: vault.TypedRecord,
    uploads: List[_UploadSuccess],
) -> None:
    attachment_uids: List[str] = []
    for item in uploads:
        if item.pending.kind == 'attachment':
            attachment_uids.append(item.file_uid)

    if attachment_uids:
        field = record.get_typed_field('fileRef')
        if not field:
            field = vault.TypedField.new_field('fileRef', [], '')
            record.fields.append(field)
        values = list(field.value or [])
        for uid in attachment_uids:
            if uid not in values:
                values.append(uid)
        field.value = values

    script_uploads = [u for u in uploads if u.pending.kind == 'script']
    if script_uploads:
        script_field = next((f for f in record.fields if f.type == 'script'), None)
        if not script_field:
            script_field = vault.TypedField.new_field('script', [], 'rotationScripts')
            record.fields.append(script_field)
        if not isinstance(script_field.value, list):
            script_field.value = []
        for item in script_uploads:
            script = item.pending.script
            entry = {
                'fileRef': item.file_uid,
                'recordRef': list(script.record_refs) if script and script.record_refs else [],
                'command': script.script_command if script and script.script_command else '',
            }
            script_field.value.append(entry)


def execute_batch_attachments(
    params,
    pending: List[PendingUpload],
    *,
    record_keys: Optional[Dict[str, bytes]] = None,
    max_workers: int = UPLOAD_MAX_WORKERS,
) -> BatchAttachmentSummary:
    """Run global files_add (300/chunk), parallel PUTs, batch records_update."""
    summary = BatchAttachmentSummary()
    if not pending:
        return summary

    filtered: List[PendingUpload] = []
    for item in pending:
        if item.parent_uid not in params.record_cache:
            summary.warnings.append((item.parent_uid, f'parent record missing for {item.name}'))
            continue
        filtered.append(item)

    successes_by_parent: Dict[str, List[_UploadSuccess]] = {}
    for chunk_start in range(0, len(filtered), FILES_ADD_CHUNK):
        chunk = filtered[chunk_start:chunk_start + FILES_ADD_CHUNK]
        slots: List[_UploadSlot] = []
        for item in chunk:
            slots.append(_UploadSlot(
                pending=item,
                file_uid=utils.base64_url_decode(utils.generate_uid()),
                file_key=utils.generate_aes_key(),
            ))

        try:
            files_add_rs = _files_add_chunk(params, slots)
        except Exception as err:
            logging.error(f'Step 1c files_add failed: {err}', exc_info=True)
            for slot in slots:
                summary.failures.append((slot.pending.parent_uid, str(err)))
            return summary

        uid_to_slot = {slot.file_uid: slot for slot in slots}
        work: List[Tuple[_UploadSlot, record_pb2.FileAddResult]] = []
        for fres in files_add_rs.files:
            slot = uid_to_slot.get(fres.record_uid)
            if slot:
                work.append((slot, fres))

        chunk_successes, chunk_failures = _parallel_puts(params, work, max_workers=max_workers)
        summary.failures.extend(chunk_failures)
        summary.uploaded_count += len(chunk_successes)
        for item in chunk_successes:
            successes_by_parent.setdefault(item.pending.parent_uid, []).append(item)

    if summary.failures:
        return summary

    if not successes_by_parent:
        return summary

    update_pbs: List[record_pb2.RecordUpdate] = []
    update_uids: List[str] = []
    for parent_uid, items in successes_by_parent.items():
        existing = vault.KeeperRecord.load(params, parent_uid)
        if not existing or not isinstance(existing, vault.TypedRecord):
            summary.failures.append((parent_uid, 'record not found for fileRef patch'))
            continue
        try:
            record = vault.KeeperRecord.load(params, parent_uid)
            if not record or not isinstance(record, vault.TypedRecord):
                summary.failures.append((parent_uid, 'record not found for fileRef patch'))
                continue
            _apply_uploads_to_record(record, items)
            keys = dict(record_keys or {})
            for item in items:
                keys[item.file_uid] = item.file_key
            linked = linked_keys_for_channel_a_refs(record, keys)
            if linked:
                record.linked_keys = linked
            update_pbs.append(_build_typed_record_update_pb(params, record, existing))
            update_uids.append(parent_uid)
        except Exception as err:
            logging.error(f'Step 1c patch prepare failed for {parent_uid}: {err}', exc_info=True)
            summary.failures.append((parent_uid, str(err)))

    if summary.failures:
        return summary

    if update_pbs:
        results = execute_records_update_with_retry(params, update_pbs, label='Step 1c fileRef patch')
        by_uid = {utils.base64_url_encode(r.record_uid): r for r in results if r.record_uid}
        for uid in update_uids:
            rs = by_uid.get(uid)
            if rs is None:
                summary.failures.append((uid, 'missing from update response'))
            elif rs.status != record_pb2.RS_SUCCESS:
                summary.failures.append((uid, imp_exp.record_status_to_str(rs.status)))

    if summary.failures:
        return summary

    api.sync_down(params)
    return summary


def run_step_1c_for_objects(
    params,
    objects: List[PamObject],
    users: List[PamObject],
    resources: List[PamObject],
    *,
    record_keys: Optional[Dict[str, bytes]] = None,
    max_workers: int = UPLOAD_MAX_WORKERS,
) -> BatchAttachmentSummary:
    """Resolve script creds, collect uploads, execute batch attachment pipeline."""
    for obj in objects:
        resolve_script_creds(obj, users, resources)

    pending: List[PendingUpload] = []
    for obj in objects:
        pending.extend(collect_pending_uploads(obj))
    return execute_batch_attachments(
        params, pending, record_keys=record_keys, max_workers=max_workers,
    )


def run_import_tail_config_scripts(
    params,
    pam_cfg_uid: str,
    scripts: List[PamScriptObject],
    *,
    max_workers: int = UPLOAD_MAX_WORKERS,
) -> BatchAttachmentSummary:
    """Batch-upload pamConfiguration cred scripts after engine.run() (import/extend tail).

    Failures are returned in the summary for the caller to log; import tail does not
    abort the overall import when the main batch engine already succeeded.
    """
    pending = collect_config_script_uploads(pam_cfg_uid, scripts)
    if not pending:
        return BatchAttachmentSummary()
    return execute_batch_attachments(params, pending, max_workers=max_workers)
