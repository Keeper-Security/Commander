"""Direct record share restoration (port of 05d_restore_direct_shares.sh).

Parses user_permissions[] from each source record, then for each non-owner
user issues share-record on the target with matching can_edit/can_share flags.

Bug 20 split: `extract_shares` (source-side) dumps shares to a JSON
manifest; `ShareApplier` (target-side) reads the JSON and applies the
grants. This mirrors records-attachments-download / -upload and lets
operators carry shares across the cross-tenant boundary that the
single-session ShareRestorer can't bridge.
"""

import json
import logging
import os
import time

from .attachments import load_manifest  # reuse same CSV format
from .email_remap import remap_email

EXTRACT_MANIFEST_VERSION = 1


def extract_direct_shares(source_record):
    """Given a parsed source-record dict, return list of share specs (non-owner).

    Each spec: {'username': str, 'editable': bool, 'shareable': bool,
                'share_admin': bool}
    """
    out = []
    for up in source_record.get('user_permissions', []) or []:
        if not isinstance(up, dict):
            continue
        if up.get('owner'):
            continue
        username = (up.get('username') or '').strip()
        if not username:
            continue
        out.append({
            'username': username,
            'editable': bool(up.get('editable', False)),
            'shareable': bool(up.get('shareable', False)),
            'share_admin': bool(up.get('share_admin', False)),
        })
    return out


class ShareClient:
    """Protocol covering every cross-tenant share operation."""

    def get_record_json(self, source_uid):
        """Return the source record's JSON as a dict, or None if not found."""
        raise NotImplementedError

    def share_record(self, target_uid, email, editable, shareable):
        """Grant share on target_uid to email with given flags.

        Returns one of: 'OK', 'PENDING_INVITATION', 'USER_NOT_FOUND', 'FAIL'.
        'PENDING_INVITATION' is the cross-tenant case (Keeper sends an
        invite email and the share activates on acceptance).
        """
        raise NotImplementedError


class FakeShareClient(ShareClient):
    def __init__(self, records=None, share_behavior=None):
        """
        records: dict[source_uid] -> parsed record dict.
        share_behavior: callable(target_uid, email) -> one of the result codes.
                        Defaults to always returning 'OK'.
        """
        self.records = records or {}
        self._behavior = share_behavior or (lambda *_a: 'OK')
        self.calls = []

    def get_record_json(self, source_uid):
        self.calls.append(('get_record_json', (source_uid,)))
        return self.records.get(source_uid)

    def share_record(self, target_uid, email, editable, shareable):
        self.calls.append(('share_record', (target_uid, email, editable, shareable)))
        return self._behavior(target_uid, email)


def extract_shares(client, pairs, *, old_domain='', new_domain=''):
    """Source-side phase of the Bug 20 split.

    For each (source_uid, target_uid) pair, fetch the source record's
    direct shares (Bug 19's lazy fetch makes this work), apply email
    remap, and accumulate a per-pair record:

        {
          'source_uid': str, 'target_uid': str, 'title': str,
          'shares': [{'username': remapped_email,
                      'editable': bool, 'shareable': bool}, ...]
        }

    Pairs whose source record has no non-owner shares emit an entry with
    `'shares': []` so the apply phase can audit-skip with the same UIDs.
    """
    out = []
    pairs = list(pairs)
    for p in pairs:
        src_uid = p.get('source_uid', '')
        tgt_uid = p.get('target_uid', '')
        if not src_uid or not tgt_uid:
            continue
        rec = client.get_record_json(src_uid) or {}
        title = rec.get('title', '') or p.get('title', '')
        shares = []
        for spec in extract_direct_shares(rec):
            email = remap_email(spec['username'], old_domain, new_domain)
            shares.append({
                'username': email,
                'editable': bool(spec.get('editable', False)),
                'shareable': bool(spec.get('shareable', False)),
            })
        out.append({
            'source_uid': src_uid,
            'target_uid': tgt_uid,
            'title': title,
            'shares': shares,
        })
    return out


def write_extract_manifest(path, entries):
    """Persist `extract_shares` output to a JSON file with mode 0600.

    The manifest carries a small `_meta` block so the apply phase can
    sanity-check it (version + entry count). Returns the absolute path.
    """
    payload = {
        '_meta': {
            'version': EXTRACT_MANIFEST_VERSION,
            'count': len(entries),
        },
        'entries': list(entries),
    }
    with open(path, 'w') as f:
        json.dump(payload, f, indent=2)
    os.chmod(path, 0o600)
    return os.path.abspath(path)


def read_extract_manifest(path):
    """Return the entries list from a manifest written by
    `write_extract_manifest`. Validates `_meta.version`.
    """
    with open(path) as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError(f'extract manifest {path!r}: not a JSON object')
    meta = payload.get('_meta') or {}
    version = meta.get('version')
    if version != EXTRACT_MANIFEST_VERSION:
        raise ValueError(
            f'extract manifest {path!r}: unsupported version {version!r} '
            f'(expected {EXTRACT_MANIFEST_VERSION})')
    entries = payload.get('entries') or []
    if not isinstance(entries, list):
        raise ValueError(f'extract manifest {path!r}: entries must be a list')
    return entries


class ShareApplier:
    """Target-side phase of the Bug 20 split.

    Reads `extract_shares`-shaped entries and calls `share_record` on the
    target session for each grant. Mirrors `ShareRestorer.run` for
    counters, audit-grant emission, and checkpoint resume — minus the
    extract loop which already happened source-side.
    """

    def __init__(self, client, *, skip_missing_users=False,
                 delay=0.0, batch_size=0, sleeper=time.sleep,
                 checkpoint=None, resume=False, force_restart=False):
        from .backoff import Retry
        self.client = client
        self.skip_missing_users = skip_missing_users
        self.delay = max(0.0, float(delay or 0))
        self.batch_size = max(0, int(batch_size or 0))
        self.sleeper = sleeper
        self._retry = Retry(delay=self.delay, sleeper=sleeper)
        self.checkpoint = checkpoint
        self.resume = resume
        self.force_restart = force_restart

    def apply_one(self, entry):
        target_uid = entry.get('target_uid', '')
        source_uid = entry.get('source_uid', '')
        shares = entry.get('shares') or []
        if not target_uid:
            return {'source_uid': source_uid, 'target_uid': target_uid,
                    'status': 'SKIP', 'applied': 0, 'failed': 0,
                    'errors': ['no target_uid in entry']}
        if not shares:
            return {'source_uid': source_uid, 'target_uid': target_uid,
                    'status': 'SKIP', 'applied': 0, 'failed': 0, 'errors': []}

        applied = 0
        failed = 0
        errors = []
        grants = []
        for spec in shares:
            email = (spec.get('username') or '').strip()
            if not email:
                continue
            code = self.client.share_record(
                target_uid, email,
                bool(spec.get('editable', False)),
                bool(spec.get('shareable', False)),
            )
            if code in ('OK', 'PENDING_INVITATION'):
                applied += 1
                grants.append({'target_uid': target_uid, 'email': email})
            elif code == 'USER_NOT_FOUND':
                if not self.skip_missing_users:
                    failed += 1
                    errors.append(f'user not found: {email}')
            else:
                failed += 1
                errors.append(f'share failed: {email}')

        return {
            'source_uid': source_uid,
            'target_uid': target_uid,
            'status': 'FAIL' if failed else 'PASS',
            'applied': applied,
            'failed': failed,
            'errors': errors,
            'grants': grants,
        }

    def run(self, entries):
        entries = list(entries)
        input_sha = None
        start = 1
        if self.checkpoint is not None:
            from .checkpoint import hash_rows
            input_sha = hash_rows(entries)
            start = self.checkpoint.resume_from(
                entries, resume=self.resume,
                force_restart=self.force_restart,
            )
            if start > 1:
                logging.info('records-shares-apply: resuming at entry '
                             '%d/%d (checkpoint present)',
                             start, len(entries))

        per_record = []
        for _ in range(start - 1):
            per_record.append({'status': 'SKIP', 'applied': 0, 'failed': 0,
                                'resumed': True})

        for i, entry in enumerate(entries, start=1):
            if i < start:
                continue
            per_record.append(self._retry.call(
                lambda e=entry: self.apply_one(e),
                op_label=(
                    f'share-apply:{entry.get("source_uid", "")}'
                    f'→{entry.get("target_uid", "")}'),
            ))
            if self.checkpoint is not None and input_sha:
                self.checkpoint.mark_done(i, input_sha256=input_sha)
            if self.delay and self.sleeper:
                self.sleeper(self.delay)
            if (self.batch_size and i % self.batch_size == 0
                    and self.sleeper):
                logging.info('Batch checkpoint: %d entries processed — '
                             'pause', i)
                self.sleeper(max(self.delay * 2, 1.0))
        for r in per_record:
            if r.get('resumed'):
                continue
            logging.info('Apply %s → %s: %s (%d applied, %d failed)',
                         r['source_uid'], r['target_uid'], r['status'],
                         r['applied'], r['failed'])

        if self.checkpoint is not None:
            self.checkpoint.clear()

        return {
            'total': len(per_record),
            'pass': sum(1 for r in per_record if r['status'] == 'PASS'),
            'fail': sum(1 for r in per_record if r['status'] == 'FAIL'),
            'skip': sum(1 for r in per_record
                        if r['status'] == 'SKIP' and not r.get('resumed')),
            'resumed': sum(1 for r in per_record if r.get('resumed')),
            'per_record': per_record,
        }


class ShareRestorer:
    def __init__(self, client, *, skip_missing_users=False,
                 old_domain='', new_domain='',
                 delay=0.0, batch_size=0, sleeper=time.sleep,
                 checkpoint=None, resume=False, force_restart=False):
        from .backoff import Retry
        self.client = client
        self.skip_missing_users = skip_missing_users
        self.old_domain = old_domain
        self.new_domain = new_domain
        self.delay = max(0.0, float(delay or 0))
        self.batch_size = max(0, int(batch_size or 0))
        self.sleeper = sleeper
        self._retry = Retry(delay=self.delay, sleeper=sleeper)
        # Optional checkpoint for resumable runs. None → no-op.
        self.checkpoint = checkpoint
        self.resume = resume
        self.force_restart = force_restart

    def _remap(self, email):
        return remap_email(email, self.old_domain, self.new_domain)

    def restore_one(self, source_uid, target_uid):
        src_rec = self.client.get_record_json(source_uid)
        if not src_rec:
            return {'source_uid': source_uid, 'target_uid': target_uid,
                    'status': 'SKIP', 'applied': 0, 'failed': 0, 'errors': []}

        specs = extract_direct_shares(src_rec)
        if not specs:
            return {'source_uid': source_uid, 'target_uid': target_uid,
                    'status': 'SKIP', 'applied': 0, 'failed': 0, 'errors': []}

        applied = 0
        failed = 0
        errors = []
        grants = []   # {target_uid, email} pairs — consumed by the audit emitter
        for spec in specs:
            target_email = self._remap(spec['username'])
            code = self.client.share_record(
                target_uid, target_email,
                spec['editable'], spec['shareable'],
            )
            if code in ('OK', 'PENDING_INVITATION'):
                applied += 1
                grants.append({'target_uid': target_uid, 'email': target_email})
            elif code == 'USER_NOT_FOUND':
                if not self.skip_missing_users:
                    failed += 1
                    errors.append(f'user not found: {target_email}')
            else:
                failed += 1
                errors.append(f'share failed: {target_email}')

        return {
            'source_uid': source_uid,
            'target_uid': target_uid,
            'status': 'FAIL' if failed else 'PASS',
            'applied': applied,
            'failed': failed,
            'errors': errors,
            'grants': grants,
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
                logging.info('records-shares: resuming at pair %d/%d '
                             '(checkpoint present)', start, len(pairs))

        per_record = []
        # Pre-populate skipped-by-resume entries so summary counts stay accurate.
        for _ in range(start - 1):
            per_record.append({'status': 'SKIP', 'applied': 0, 'failed': 0,
                               'resumed': True})

        for i, p in enumerate(pairs, start=1):
            if i < start:
                continue
            per_record.append(self._retry.call(
                lambda p=p: self.restore_one(p['source_uid'], p['target_uid']),
                op_label=f'share:{p["source_uid"]}→{p["target_uid"]}',
            ))
            if self.checkpoint is not None and input_sha:
                self.checkpoint.mark_done(i, input_sha256=input_sha)
            if self.delay and self.sleeper:
                self.sleeper(self.delay)
            if (self.batch_size and i % self.batch_size == 0
                    and self.sleeper):
                logging.info('Batch checkpoint: %d record-shares processed — '
                             'pause', i)
                self.sleeper(max(self.delay * 2, 1.0))
        for r in per_record:
            if r.get('resumed'):
                continue
            logging.info('Shares %s → %s: %s (%d applied, %d failed)',
                         r['source_uid'], r['target_uid'], r['status'],
                         r['applied'], r['failed'])

        # Clear checkpoint on stage completion.
        if self.checkpoint is not None:
            self.checkpoint.clear()

        return {
            'total': len(per_record),
            'pass': sum(1 for r in per_record if r['status'] == 'PASS'),
            'fail': sum(1 for r in per_record if r['status'] == 'FAIL'),
            'skip': sum(1 for r in per_record
                        if r['status'] == 'SKIP' and not r.get('resumed')),
            'resumed': sum(1 for r in per_record if r.get('resumed')),
            'per_record': per_record,
        }
