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

"""Writes the FILE changes of an ``UpdatePlan``: attachments and rotation script files (order of work step 5).

The planner compares a file by name and size (the vault keeps no content hash): a new name is ADDED, the same name
with another size is REPLACED, the same name and size is left alone. Files are never removed.

* ADD: the file is uploaded (the same batched ``files_add`` + upload + record patch the import uses, so a script
  file is flagged ``is_script`` and linked to the record) and its reference is appended to the ``fileRef`` field, or
  its entry (file, command, additional credentials) to the ``script`` field.
* REPLACE: the new file is uploaded and its reference TAKES THE PLACE of the old one, in the same position. The old
  file record is not deleted: it stays in the vault without a reference (update never deletes a record).

Runs after the record fields were written (the records are read again first, so the patch carries their new
revision). A record whose upload or patch fails is reported as an APPLY error and the others are still written;
``update`` is run again to finish (the files that were uploaded for the failed record stay unreferenced).
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Dict, List, Optional

from . import update_schema as us
from .batch_attachments import MAX_FILE_BYTES, BatchAttachmentSummary, PendingUpload
from .update_apply import ApplyReport
from .update_diff import KIND_RECORD
from .update_plan import FileWork, ItemResult, UpdatePlan


def file_changes(result: ItemResult) -> list:
    """The changes of *result* that are attachment / script files."""
    return [c for c in result.changes
            if c.kind == KIND_RECORD and c.target is not None and c.target.kind == us.KIND_FILES]


def _pending_for(result: ItemResult, report: ApplyReport) -> List[PendingUpload]:
    """The uploads of one record; a file that is gone, empty or too big since the plan is an error for the record."""
    label = result.title or result.uid
    pending: List[PendingUpload] = []
    for change in file_changes(result):
        work: Optional[FileWork] = change.data
        if work is None:
            continue
        try:
            size = os.path.getsize(work.path)
        except OSError:
            report.errors.append(f'{label}: {work.kind} "{work.name}" was not written: the file is not readable')
            return []
        if size == 0 or size > MAX_FILE_BYTES:
            report.errors.append(f'{label}: {work.kind} "{work.name}" was not written: the file is empty or larger '
                                 f'than {MAX_FILE_BYTES // 2 ** 20} MB')
            return []
        pending.append(PendingUpload(parent_uid=result.uid, file_path=work.path, name=work.name, size=size,
                                     kind=work.kind, script=work.script, replaces=work.old_uid))
    return pending


def _default_execute(params) -> Callable[[List[PendingUpload]], BatchAttachmentSummary]:
    from .batch_attachments import execute_batch_attachments
    from .nsf_helpers import sync_down_preserving_nsf_keys

    def execute(pending):
        # the record fields were just written: bring the caches up to date, or the patch carries an old revision
        sync_down_preserving_nsf_keys(params)
        return execute_batch_attachments(params, pending, partial=True)
    return execute


def apply_files(params, plan: UpdatePlan, *,
                execute: Optional[Callable[[List[PendingUpload]], BatchAttachmentSummary]] = None) -> ApplyReport:
    """Upload the files of every item of *plan* and patch their records. *execute* is the batch run (replaceable in tests)."""
    report = ApplyReport()
    pending: List[PendingUpload] = []
    counts: Dict[str, int] = {}
    titles: Dict[str, str] = {}
    for result in plan.results:
        if not file_changes(result):
            continue
        titles[result.uid] = result.title or result.uid
        items = _pending_for(result, report)
        if items:
            pending.extend(items)
            counts[result.uid] = len(items)
    if not pending:
        return report
    try:
        summary = (execute or _default_execute(params))(pending)
    except Exception as err:    # pylint: disable=broad-except
        logging.debug('file upload failed: %s', err, exc_info=True)
        text = str(err).strip().splitlines()[0][:300] if str(err).strip() else err.__class__.__name__
        for uid in counts:
            report.errors.append(f'{titles[uid]}: files were not written: {text}')
        return report
    failed: Dict[str, List[str]] = {}
    for uid, reason in list(summary.failures) + list(summary.warnings):
        failed.setdefault(uid, []).append(reason)
    for uid, count in counts.items():
        if uid in failed:
            report.errors.append(f'{titles[uid]}: files were not written: {"; ".join(dict.fromkeys(failed[uid]))}')
        else:
            report.applied.append(f'{titles[uid]}: files ({count})')
    return report
