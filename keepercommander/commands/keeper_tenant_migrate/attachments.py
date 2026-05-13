"""Attachment migration between tenants (port of 05c_migrate_attachments.sh).

Takes a manifest of (source_uid, target_uid) pairs. For each pair, downloads
every attachment from the source record to a staging directory, then uploads
each file to the target record.

Output model:
  {
    'total': int, 'pass': int, 'fail': int, 'skip': int,
    'per_record': [
        {'source_uid': ..., 'target_uid': ..., 'status': 'PASS'|'FAIL'|'SKIP',
         'files_uploaded': int, 'files_failed': int, 'errors': [...]},
        ...
    ]
  }
"""

import csv
import logging
import os
import time


def load_manifest(manifest_path):
    """Read a manifest CSV with at least source_uid,target_uid columns.

    Uses the defensive CSV reader to strip a leading BOM (Excel's
    default save) + validate the header contains both required
    columns. Avoids the "silent zero pairs" failure mode.
    """
    from .csv_utils import read_csv_dictreader
    _, rows = read_csv_dictreader(
        manifest_path,
        required_columns=('source_uid', 'target_uid'),
    )
    pairs = []
    for row in rows:
        src = (row.get('source_uid') or '').strip()
        tgt = (row.get('target_uid') or '').strip()
        if src and tgt:
            pairs.append({'source_uid': src, 'target_uid': tgt})
    return pairs


class AttachmentClient:
    """Protocol covering every cross-tenant attachment operation."""

    def download_attachments(self, source_uid, out_dir):
        """Download all attachments of source_uid into out_dir.

        Returns list[str] of absolute file paths that were downloaded (empty
        list = no attachments). Implementations must NOT raise for "no
        attachments"; instead return [].
        """
        raise NotImplementedError

    def upload_attachment(self, target_uid, file_path):
        """Return True on success, False on failure.

        Bug 56 / v1.6 fileRef extension: implementations MAY also expose
        `upload_attachment_with_uid(target_uid, file_path)` returning
        (True, target_file_uid) so the manager can persist a
        source_file_uid → target_file_uid map for fileRef rewrite. Pure
        bool return is preserved for back-compat with pre-v1.6 callers.
        """
        raise NotImplementedError

    def list_record_file_uids(self, source_uid):
        """Return [str] file UIDs attached to a SOURCE record. Used at
        download time to capture source-side file UIDs so they can be
        paired with target-side UIDs after upload (fileRef remap).

        Default implementation returns [] — fileRef remap then
        gracefully degrades to leaving source UIDs in place. Subclasses
        with real Commander API access override.
        """
        return []


class FakeAttachmentClient(AttachmentClient):
    """In-memory client used in tests. Drives behavior from a per-uid script."""

    def __init__(self, downloads=None, upload_fail_paths=None,
                 source_file_uids=None, target_file_uids=None):
        """
        downloads: dict[source_uid] -> list of (basename, contents_bytes) for
                   files that download_attachments should stage.
        upload_fail_paths: set of file paths (or basenames) whose upload should
                           return False.
        source_file_uids: dict[source_record_uid] -> list[file_uid] for
                          fileRef remap testing.
        target_file_uids: dict[file_path] -> target_file_uid that
                          upload_attachment_with_uid should return.
        """
        self.downloads = downloads or {}
        self.upload_fail_paths = upload_fail_paths or set()
        self.source_file_uids = source_file_uids or {}
        self.target_file_uids = target_file_uids or {}
        self.calls = []

    def download_attachments(self, source_uid, out_dir):
        self.calls.append(('download_attachments', (source_uid, out_dir)))
        files = self.downloads.get(source_uid, [])
        written = []
        for basename, contents in files:
            path = os.path.join(out_dir, basename)
            with open(path, 'wb') as f:
                f.write(contents)
            written.append(path)
        return written

    def upload_attachment(self, target_uid, file_path):
        self.calls.append(('upload_attachment', (target_uid, file_path)))
        return (file_path not in self.upload_fail_paths
                and os.path.basename(file_path) not in self.upload_fail_paths)

    def upload_attachment_with_uid(self, target_uid, file_path):
        # Bug 56 / v1.6 — return (ok, target_file_uid) so the manager
        # can pair against source file UIDs for fileRef remap.
        ok = self.upload_attachment(target_uid, file_path)
        return ok, self.target_file_uids.get(file_path) or self.target_file_uids.get(
            os.path.basename(file_path), '')

    def list_record_file_uids(self, source_uid):
        return list(self.source_file_uids.get(source_uid, []))


_STAGING_MANIFEST_NAME = 'staging.json'


def _resync_between_files(client):
    """Force a sync-down on the client's params so sequential uploads
    to the same record don't hit RS_OUT_OF_SYNC. Clients that don't
    carry a `.params` attribute are silently skipped (FakeAttachmentClient
    in tests)."""
    params = getattr(client, 'params', None)
    if params is None:
        return
    try:
        from keepercommander import api
        api.sync_down(params)
    except Exception:                          # noqa: BLE001
        # Best-effort — if sync fails, let the next upload surface
        # the error rather than abort the whole flow.
        pass


def _staging_path_for(source_uid, staging_dir):
    return os.path.join(staging_dir, source_uid)


def _load_staging_manifest(staging_dir):
    """Read staging.json at the root of `staging_dir`. Empty dict on
    missing — the download phase may never have run."""
    path = os.path.join(staging_dir, _STAGING_MANIFEST_NAME)
    if not os.path.exists(path):
        return {}
    import json
    with open(path) as f:
        return json.load(f) or {}


def _save_staging_manifest(staging_dir, manifest):
    """Persist {source_uid: [filename, ...]} at the root of staging_dir.

    Two-phase separation: the source-side download writes THIS file,
    the target-side upload reads it. No source session needed on the
    target side — everything the upload needs is on disk.
    """
    import json
    os.makedirs(staging_dir, exist_ok=True)
    path = os.path.join(staging_dir, _STAGING_MANIFEST_NAME)
    with open(path, 'w') as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    # Staging files can carry customer attachment blobs — keep the
    # index 0600 to match the per-file chmod convention.
    os.chmod(path, 0o600)
    return path


class AttachmentDownloader:
    """Phase 1 of the two-phase attachments flow — runs on the SOURCE
    shell. Downloads every attachment for each source_uid into
    `<staging_dir>/<source_uid>/` and writes a JSON index of filenames.

    The target-phase `AttachmentUploader` reads that index + files and
    doesn't need access to the source session."""

    def __init__(self, client, staging_dir, *, delay=0.0, batch_size=0,
                  sleeper=time.sleep):
        from .backoff import Retry
        self.client = client
        self.staging_dir = staging_dir
        self.delay = max(0.0, float(delay or 0))
        self.batch_size = max(0, int(batch_size or 0))
        self.sleeper = sleeper
        self._retry = Retry(delay=self.delay, sleeper=sleeper)

    def download_one(self, source_uid):
        rec_dir = _staging_path_for(source_uid, self.staging_dir)
        os.makedirs(rec_dir, exist_ok=True)
        files = self.client.download_attachments(source_uid, rec_dir) or []
        # Bug 56 / v1.6 — capture source-side file UIDs alongside the
        # filenames so the upload phase can pair them with target-side
        # file UIDs (fileRef remap). Best-effort: clients without
        # list_record_file_uids return [], pre-v1.6 callsite.
        source_file_uids = []
        try:
            source_file_uids = self.client.list_record_file_uids(source_uid) or []
        except Exception:                              # noqa: BLE001
            source_file_uids = []
        # Record basename + absolute path — the target side will resolve
        # relative to the staging_dir path it was given.
        return {
            'source_uid': source_uid,
            'count': len(files),
            'files': [os.path.basename(f) for f in files],
            'source_file_uids': source_file_uids,
        }

    def run(self, source_uids):
        os.makedirs(self.staging_dir, exist_ok=True)
        manifest = _load_staging_manifest(self.staging_dir)
        per_record = []
        for i, uid in enumerate(source_uids, start=1):
            r = self._retry.call(
                lambda uid=uid: self.download_one(uid),
                op_label=f'att-dl:{uid}',
            )
            per_record.append(r)
            # Bug 56 (v1.6) — extend the per-record manifest entry
            # from a flat list[filename] to a structured dict carrying
            # filenames + source file UIDs. Reader normalizes either
            # shape so older staging dirs (pre-v1.6) still upload.
            if r.get('source_file_uids'):
                manifest[r['source_uid']] = {
                    'files': r['files'],
                    'source_file_uids': r['source_file_uids'],
                }
            else:
                manifest[r['source_uid']] = r['files']
            logging.info('Attachments downloaded %s: %d file(s)',
                         uid, r['count'])
            if self.delay and self.sleeper:
                self.sleeper(self.delay)
            if (self.batch_size and i % self.batch_size == 0
                    and self.sleeper):
                logging.info('Batch checkpoint: %d records downloaded '
                             '— pause', i)
                self.sleeper(max(self.delay * 2, 1.0))
        _save_staging_manifest(self.staging_dir, manifest)
        return {
            'total': len(per_record),
            'total_files': sum(r['count'] for r in per_record),
            'per_record': per_record,
        }


class AttachmentUploader:
    """Phase 2 — runs on the TARGET shell. Reads the staging dir
    populated by AttachmentDownloader + a pairing manifest
    (source_uid → target_uid), uploads each pre-downloaded file to the
    target record."""

    def __init__(self, client, staging_dir, *, delay=0.0, batch_size=0,
                  sleeper=time.sleep,
                  checkpoint=None, resume=False, force_restart=False):
        from .backoff import Retry
        self.client = client
        self.staging_dir = staging_dir
        self.delay = max(0.0, float(delay or 0))
        self.batch_size = max(0, int(batch_size or 0))
        self.sleeper = sleeper
        self._retry = Retry(delay=self.delay, sleeper=sleeper)
        self._index = _load_staging_manifest(staging_dir)
        self.checkpoint = checkpoint
        self.resume = resume
        self.force_restart = force_restart

    def upload_one(self, source_uid, target_uid):
        # File list from staging manifest; fall back to directory listing
        # if the manifest is empty (backward compat with pre-v1.2 runs).
        # Bug 56 / v1.6 — manifest entries can be either a flat
        # list[filename] (legacy) or a dict {files, source_file_uids}
        # (v1.6+). Normalize.
        entry = self._index.get(source_uid, None)
        rec_dir = _staging_path_for(source_uid, self.staging_dir)
        files = None
        source_file_uids = []
        if isinstance(entry, dict):
            files = entry.get('files')
            source_file_uids = entry.get('source_file_uids') or []
        elif isinstance(entry, list):
            files = entry
        if files is None:
            if not os.path.isdir(rec_dir):
                return {'source_uid': source_uid, 'target_uid': target_uid,
                        'status': 'SKIP', 'files_uploaded': 0,
                        'files_failed': 0, 'errors': [],
                        'uploaded_files': [], 'file_uid_pairs': []}
            files = sorted(os.listdir(rec_dir))
        if not files:
            return {'source_uid': source_uid, 'target_uid': target_uid,
                    'status': 'SKIP', 'files_uploaded': 0,
                    'files_failed': 0, 'errors': [],
                    'uploaded_files': [], 'file_uid_pairs': []}
        supports_uid_capture = hasattr(
            self.client, 'upload_attachment_with_uid')
        uploaded, failed = 0, 0
        errors, uploaded_files, file_uid_pairs = [], [], []
        for i, fn in enumerate(files):
            abs_path = os.path.join(rec_dir, fn)
            if not os.path.isfile(abs_path):
                failed += 1
                errors.append(f'missing staged file: {fn}')
                continue
            # Commander's client cache holds a record revision number
            # that Keeper's API checks on mutating calls. The first
            # upload to a record bumps that revision server-side; the
            # client cache is NOT automatically refreshed, so a
            # sequential second upload hits RS_OUT_OF_SYNC. Force a
            # sync_down between files on the same record. The between-
            # record delay happens in run() on top of this.
            if i > 0:
                _resync_between_files(self.client)
            if supports_uid_capture:
                ok, target_file_uid = self.client.upload_attachment_with_uid(
                    target_uid, abs_path)
            else:
                ok = self.client.upload_attachment(target_uid, abs_path)
                target_file_uid = ''
            if ok:
                uploaded += 1
                uploaded_files.append({'target_uid': target_uid,
                                        'file_name': fn})
                # Pair source_file_uid by index when both lists are
                # ordered correspondingly. When source UID list is
                # shorter, leave the trailing files unpaired (fileRef
                # remap will skip them; record's reference stays
                # source-side which is the safe pre-v1.6 behavior).
                if i < len(source_file_uids) and target_file_uid:
                    file_uid_pairs.append({
                        'source_file_uid': source_file_uids[i],
                        'target_file_uid': target_file_uid,
                        'file_name': fn,
                    })
            else:
                failed += 1
                errors.append(f'upload failed: {fn}')
        return {
            'source_uid': source_uid,
            'target_uid': target_uid,
            'status': 'FAIL' if failed else 'PASS',
            'files_uploaded': uploaded,
            'files_failed': failed,
            'errors': errors,
            'uploaded_files': uploaded_files,
            'file_uid_pairs': file_uid_pairs,
        }

    def run(self, pairs):
        pairs = list(pairs)
        input_sha = None
        start = 1
        if self.checkpoint is not None:
            from .checkpoint import hash_rows
            input_sha = hash_rows(pairs)
            start = self.checkpoint.resume_from(
                pairs, resume=self.resume, force_restart=self.force_restart,
            )
            if start > 1:
                logging.info('att-upload: resuming at %d/%d', start, len(pairs))

        per_record = []
        for _ in range(start - 1):
            per_record.append({
                'status': 'SKIP', 'files_uploaded': 0, 'files_failed': 0,
                'resumed': True,
            })

        for i, p in enumerate(pairs, start=1):
            if i < start:
                continue
            r = self._retry.call(
                lambda p=p: self.upload_one(p['source_uid'], p['target_uid']),
                op_label=f'att-ul:{p["source_uid"]}→{p["target_uid"]}',
            )
            per_record.append(r)
            logging.info('Attachments uploaded %s → %s: %s (%d/%d)',
                         p['source_uid'], p['target_uid'], r['status'],
                         r['files_uploaded'],
                         r['files_uploaded'] + r['files_failed'])
            if self.checkpoint is not None and input_sha:
                self.checkpoint.mark_done(i, input_sha256=input_sha)
            if self.delay and self.sleeper:
                self.sleeper(self.delay)
            if (self.batch_size and i % self.batch_size == 0
                    and self.sleeper):
                logging.info('Batch checkpoint: %d records uploaded — '
                             'pause', i)
                self.sleeper(max(self.delay * 2, 1.0))
        if self.checkpoint is not None:
            self.checkpoint.clear()
        # Bug 56 / v1.6 — collapse per-record file_uid_pairs into a
        # flat source_file_uid → target_file_uid map for downstream
        # records-references-rewrite consumption. Empty when the
        # client doesn't capture target file UIDs (pre-v1.6 path).
        file_uid_map = {}
        for r in per_record:
            for pair in r.get('file_uid_pairs') or []:
                src = pair.get('source_file_uid')
                tgt = pair.get('target_file_uid')
                if src and tgt:
                    file_uid_map[src] = tgt
        return {
            'total': len(per_record),
            'pass': sum(1 for r in per_record if r['status'] == 'PASS'),
            'fail': sum(1 for r in per_record if r['status'] == 'FAIL'),
            'skip': sum(1 for r in per_record
                        if r['status'] == 'SKIP' and not r.get('resumed')),
            'resumed': sum(1 for r in per_record if r.get('resumed')),
            'per_record': per_record,
            'file_uid_map': file_uid_map,
        }


class AttachmentMigrator:
    """Backward-compatible single-session flow (download + upload
    through the same client in one pass). Use when the admin DOES
    have simultaneous access to source + target records (e.g. via a
    cross-tenant shared folder). For independent shells use the
    Downloader + Uploader classes directly."""

    def __init__(self, client, staging_dir, *, delay=0.0, batch_size=0,
                 sleeper=time.sleep):
        from .backoff import Retry
        self.client = client
        self.staging_dir = staging_dir
        self.delay = max(0.0, float(delay or 0))
        self.batch_size = max(0, int(batch_size or 0))
        self.sleeper = sleeper
        self._retry = Retry(delay=self.delay, sleeper=sleeper)

    def migrate_one(self, source_uid, target_uid):
        rec_dir = os.path.join(self.staging_dir, source_uid)
        os.makedirs(rec_dir, exist_ok=True)

        files = self.client.download_attachments(source_uid, rec_dir)
        if not files:
            return {'source_uid': source_uid, 'target_uid': target_uid,
                    'status': 'SKIP', 'files_uploaded': 0,
                    'files_failed': 0, 'errors': []}

        uploaded = 0
        failed = 0
        errors = []
        uploaded_files = []   # {target_uid, file_name} — consumed by the audit emitter
        for f in files:
            if self.client.upload_attachment(target_uid, f):
                uploaded += 1
                uploaded_files.append({'target_uid': target_uid,
                                        'file_name': os.path.basename(f)})
            else:
                failed += 1
                errors.append(f'upload failed: {os.path.basename(f)}')

        return {
            'source_uid': source_uid,
            'target_uid': target_uid,
            'status': 'FAIL' if failed else 'PASS',
            'files_uploaded': uploaded,
            'files_failed': failed,
            'errors': errors,
            'uploaded_files': uploaded_files,
        }

    def run(self, pairs):
        per_record = []
        for i, p in enumerate(pairs, start=1):
            r = self._retry.call(
                lambda p=p: self.migrate_one(p['source_uid'], p['target_uid']),
                op_label=f'att:{p["source_uid"]}→{p["target_uid"]}',
            )
            per_record.append(r)
            logging.info('Attachments %s → %s: %s (%d/%d)',
                         p['source_uid'], p['target_uid'], r['status'],
                         r['files_uploaded'],
                         r['files_uploaded'] + r['files_failed'])
            if self.delay and self.sleeper:
                self.sleeper(self.delay)
            if (self.batch_size and i % self.batch_size == 0
                    and self.sleeper):
                logging.info('Batch checkpoint: %d attachment records — '
                             'pause', i)
                self.sleeper(max(self.delay * 2, 1.0))

        summary = {
            'total': len(per_record),
            'pass': sum(1 for r in per_record if r['status'] == 'PASS'),
            'fail': sum(1 for r in per_record if r['status'] == 'FAIL'),
            'skip': sum(1 for r in per_record if r['status'] == 'SKIP'),
            'per_record': per_record,
        }
        return summary
