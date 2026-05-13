"""Hash-based audit for transferred artifacts + append-only audit log.

Three primitives:

  1. Per-file `SHA256SUMS.txt` manifests — standard `sha256sum -c` format,
     so ops can verify backups + exports with a single shell command even
     years later.

  2. `append_audit_event(log_path, event)` — JSON-lines log of every
     mutating operation (subcommand, input hashes, output hashes, summary
     counters). Each event carries a `prev_hash` field that chains to the
     preceding line → tamper-evident: flipping any prior line invalidates
     every downstream hash.

  3. `verify_audit_log(log_path)` — walks the chain, returns (ok, first
     broken line). Same trust model as `gate.py`'s signed checkpoint —
     we assume an attacker can read but not swap entries undetected.

Why bother in a migration tool:

  - Customer compliance teams routinely ask "prove the records you moved
    are identical to what was on the source". SHA256SUMS.txt on the
    records-export dir answers that.
  - Audit-log chain lets support reconstruct exactly what the admin did,
    in what order, against which inventory, across re-runs and resumes.
  - Zero cost when not used: `audit-verify` is a separate subcommand that
    customers invoke only when they want the proof.
"""

import contextlib
import datetime
import errno
import hashlib
import json
import logging
import os
import tempfile

# fcntl is POSIX-only; on Windows we degrade to a no-op lock with a
# warning. See _audit_lock() below.
try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:
    _HAS_FCNTL = False


@contextlib.contextmanager
def _audit_lock(path):
    """Exclusive POSIX flock around a sidecar file `<path>.lock`.

    Why: SEC-3 fix 2026-05-08. Without a lock, two concurrent
    `append_audit_event` calls compute the same `prev_hash` from the
    same tail line and both append events claiming the same predecessor.
    `verify_audit_log` rejects the chain — but only after the fact.
    Realistic triggers: parallel auto-migrate stages, a manual
    subcommand running while a prior process is still finishing,
    or two operators sharing a run-dir.

    On non-POSIX platforms (Windows lacks fcntl), we log a warning and
    proceed without locking — the caller is expected to serialise
    audit-writing externally on those hosts.
    """
    if not _HAS_FCNTL:
        logging.warning(
            'audit_lock: fcntl not available on this platform; '
            'serialise audit-writing externally to avoid chain branches.'
        )
        yield
        return
    lock_path = path + '.lock'
    os.makedirs(os.path.dirname(os.path.abspath(lock_path)) or '.',
                exist_ok=True)
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


_SHA256SUMS_FILENAME = 'SHA256SUMS.txt'


def sha256_of_file(path, chunk_size=1 << 16):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(chunk_size), b''):
            h.update(chunk)
    return h.hexdigest()


def sha256_of_bytes(data):
    return hashlib.sha256(data).hexdigest()


def write_sha256sums(directory, *, filename=_SHA256SUMS_FILENAME,
                     exclude=(), relative=True):
    """Walk `directory`, hash each regular file, emit a checksum manifest.

    Output format matches GNU coreutils `sha256sum`:
        <hash>  <path>
    one per line, sorted by path for reproducibility.

    `exclude` — iterable of path patterns to skip. Matches against the
    file's RELATIVE path from `directory` (not just basename), so an
    entry 'audit.log' skips the top-level `audit.log` only — a nested
    `attachments/audit.log` is still hashed. Use 'foo/audit.log' or
    '*audit.log' (with fnmatch) to target nested files explicitly.

    For backwards compatibility, exclude entries WITHOUT a path
    separator ALSO match any file with that exact basename at any depth
    (preserves the v1.0 semantics for `('audit.log',)` callers). Log a
    DEBUG line when the basename-match fires for a nested file so
    anyone chasing integrity-check behavior can see what happened.

    Symlinks are NEVER hashed (their target could change independently
    of the manifest) — we log a WARNING per symlink so the operator
    knows an on-disk entry was skipped.

    `relative` — True: record paths relative to `directory`; False: record
    absolute paths.
    """
    import fnmatch
    exclude = set(exclude) | {filename}
    # Partition exclude entries: strict (has separator / glob) vs
    # basename (legacy).
    strict_excludes = {e for e in exclude if '/' in e or '\\' in e or '*' in e or '?' in e}
    basename_excludes = exclude - strict_excludes
    out = os.path.join(directory, filename)
    entries = []
    symlinks_skipped = []
    for root, _, files in os.walk(directory):
        for name in sorted(files):
            abs_path = os.path.join(root, name)
            rel = os.path.relpath(abs_path, directory)
            # Strict excludes — exact relative-path OR fnmatch glob.
            if rel in strict_excludes or any(
                    fnmatch.fnmatch(rel, pat) for pat in strict_excludes):
                continue
            # Basename-legacy excludes.
            if name in basename_excludes:
                if os.path.dirname(rel):
                    logging.debug(
                        "write_sha256sums: basename exclude %r also "
                        "skipped nested file %r — pass '%s' as a strict "
                        "relative-path exclude to disambiguate",
                        name, rel, rel,
                    )
                continue
            if os.path.islink(abs_path):
                symlinks_skipped.append(rel)
                continue
            entries.append((rel if relative else abs_path,
                              sha256_of_file(abs_path)))
    for sl in symlinks_skipped:
        logging.warning('write_sha256sums: symlink skipped (target not '
                         'hashed): %s', sl)
    entries.sort(key=lambda e: e[0])
    with open(out, 'w') as f:
        for rel, digest in entries:
            f.write(f'{digest}  {rel}\n')
    os.chmod(out, 0o600)
    return out


def verify_sha256sums(directory, *, filename=_SHA256SUMS_FILENAME):
    """Return ({'ok': [rel,...], 'missing': [rel,...], 'mismatch': [rel,...]}).

    Raises FileNotFoundError if the manifest is absent.
    """
    manifest = os.path.join(directory, filename)
    if not os.path.exists(manifest):
        raise FileNotFoundError(f'no sha256sums manifest at {manifest!r}')
    result = {'ok': [], 'missing': [], 'mismatch': []}
    with open(manifest) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line or '  ' not in line:
                continue
            expected, rel = line.split('  ', 1)
            abs_path = os.path.join(directory, rel)
            if not os.path.exists(abs_path):
                result['missing'].append(rel)
                continue
            actual = sha256_of_file(abs_path)
            (result['ok'] if actual == expected else result['mismatch']).append(rel)
    return result


# ─── append-only audit log with prev-hash chaining ──────────────────────────


_GENESIS_HASH = '0' * 64


def _event_signature(event):
    """Deterministic hash of an event dict — used as the next prev_hash."""
    without_hash = {k: v for k, v in event.items() if k != 'signature'}
    return hashlib.sha256(
        json.dumps(without_hash, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()


class AuditChainCorrupt(Exception):
    """Raised when the audit log's tail line is malformed/unreadable.

    SEC-3 fix 2026-05-08. Pre-fix, _last_signature silently returned
    GENESIS on JSONDecodeError — which means a crash mid-write left a
    partial last line, and the next append_audit_event then started a
    fresh chain rooted at GENESIS. Tamper-evidence collapsed silently.
    Pre-fix an attacker could also append garbage as the last line to
    force a chain reset.

    Post-fix: malformed last line is treated as fatal. The operator
    must manually inspect + repair the log before appending — the
    chain's integrity is the property the docs claim, and silent
    auto-recovery from corruption defeats it.
    """


def _last_signature(log_path):
    """Read the last line's signature.

    Returns GENESIS_HASH for a non-existent or empty log (legitimate
    fresh start). Raises AuditChainCorrupt for any other failure mode
    (truncated last line, JSON parse error, missing 'signature' key).

    The corruption-fails-closed semantics replace the prior silent
    return-of-GENESIS path. See AuditChainCorrupt docstring above.
    """
    if not os.path.exists(log_path):
        return _GENESIS_HASH
    last = None
    with open(log_path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if not last:
        return _GENESIS_HASH
    try:
        parsed = json.loads(last)
    except json.JSONDecodeError as e:
        raise AuditChainCorrupt(
            f'audit-log tail at {log_path!r} is malformed JSON '
            f'(decode error: {e}); refusing to silently reset the chain. '
            f'Inspect the file and either restore from backup or truncate '
            f'the malformed tail before re-appending.'
        ) from e
    sig = parsed.get('signature')
    if not sig:
        raise AuditChainCorrupt(
            f'audit-log tail at {log_path!r} is JSON but missing the '
            f'"signature" field; chain cannot be extended without it. '
            f'Inspect the file and restore the field or truncate the '
            f'malformed tail before re-appending.'
        )
    return sig


def append_audit_event(log_path, event):
    """Append a JSON-line event to `log_path` chained to the previous line.

    The caller supplies {subcommand, inputs, outputs, summary, ...};
    this function adds {timestamp, prev_hash, signature}. Returns the
    full event dict that was written.

    Idempotent: re-running on the same inputs produces a new event (the
    timestamp differs), but any tampering with an earlier line
    invalidates the chain.

    SEC-3 fix 2026-05-08: write is now atomic (write to temp file in
    the same directory, fsync, close, then append-via-os-replace-style
    coalesce by re-reading the existing file + temp into a new file
    and os.replacing) and protected by an exclusive flock so concurrent
    callers don't branch the chain. Power-loss durability + chain
    integrity guarantee that the docstring already promises.
    """
    log_path = os.path.abspath(log_path)
    log_dir = os.path.dirname(log_path) or '.'
    os.makedirs(log_dir, exist_ok=True)

    with _audit_lock(log_path):
        # _last_signature is now fail-closed on corruption (raises
        # AuditChainCorrupt). The lock ensures we serialise
        # tail-readers against tail-writers — concurrent appends now
        # produce a chain, not a branch.
        prev = _last_signature(log_path)
        full = dict(event)
        full['timestamp'] = datetime.datetime.utcnow().strftime(
            '%Y-%m-%dT%H:%M:%SZ'
        )
        full['prev_hash'] = prev
        full['signature'] = _event_signature(full)

        line = json.dumps(full, sort_keys=True) + '\n'
        # Atomic append pattern: write existing-content + new-line to
        # a temp file in the same dir (so os.replace is atomic on
        # POSIX), fsync, then os.replace over the original. A crash
        # at any point leaves either the old file (no event written)
        # or the new file (event durably written) — never a partial
        # last line.
        existing = b''
        if os.path.exists(log_path):
            with open(log_path, 'rb') as f:
                existing = f.read()
        # Use a tempfile in the same dir so os.replace is on the same
        # filesystem and therefore atomic.
        fd, tmp_path = tempfile.mkstemp(prefix='.audit-', suffix='.tmp',
                                         dir=log_dir)
        try:
            os.write(fd, existing)
            os.write(fd, line.encode('utf-8'))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.chmod(tmp_path, 0o600)
        try:
            os.replace(tmp_path, log_path)
        except OSError:
            # Best-effort cleanup if replace failed.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        # Belt-and-braces: fsync the directory so the rename itself
        # is durable across power loss.
        try:
            dir_fd = os.open(log_dir, os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except (OSError, AttributeError):
            # O_DIRECTORY isn't on every platform; not fatal.
            pass
    return full


def verify_audit_log(log_path):
    """Walk the chain. Returns (ok: bool, broken_line_no: int|None).

    Line numbers are 1-based so they match grep/less output.

    Fails closed when the file exists but contains zero verifiable
    events. Pre-fix (2026-05-10) this returned ``(True, None)`` for:
      - empty files (0 bytes)
      - all-whitespace files
      - files of only blank lines
      - files of only ASCII control separators (``\\x1c``..``\\x1f``)
        which Python's ``str.strip()`` removes (``str.isspace()``
        treats them as whitespace)

    The pre-fix behaviour was a fail-open: a consumer asking "is the
    audit chain valid?" got ``True`` when there was nothing to
    validate. That hides crashes mid-write, attacker truncations, and
    file-replacement-with-garbage attempts. Same property class as
    an audit-log fail-open class surfaced via property-based testing
    (paramiko-5 trial branch, 2026-05-10). Symmetric defensive fix
    applied here.
    """
    if not os.path.exists(log_path):
        return False, 0

    prev = _GENESIS_HASH
    verified_count = 0
    with open(log_path) as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                event = json.loads(raw)
            except json.JSONDecodeError:
                return False, lineno

            # Chain check
            if event.get('prev_hash') != prev:
                return False, lineno

            # Signature check
            expected = _event_signature(event)
            if event.get('signature') != expected:
                return False, lineno

            prev = event['signature']
            verified_count += 1

    if verified_count == 0:
        # File existed but contained zero verifiable events. Fail
        # closed — the caller cannot trust an empty/whitespace-only
        # audit log as "verified". Use line 0 to signal "no line"
        # (chain-break linenos start at 1).
        return False, 0

    return True, None


def hash_directory_tree(directory, *, exclude=()):
    """Return a deterministic hash of every regular file in `directory`.

    Used to summarize an artifact set in a single 64-char digest for the
    audit-log event. Algorithm: hash of concatenated
    `<rel-path>\\0<file-hash>` pairs in sort order.
    """
    exclude = set(exclude) | {_SHA256SUMS_FILENAME}
    h = hashlib.sha256()
    entries = []
    for root, _, files in os.walk(directory):
        for name in sorted(files):
            if name in exclude:
                continue
            abs_path = os.path.join(root, name)
            if os.path.islink(abs_path):
                continue
            rel = os.path.relpath(abs_path, directory)
            entries.append((rel, sha256_of_file(abs_path)))
    for rel, digest in sorted(entries):
        h.update(rel.encode())
        h.update(b'\x00')
        h.update(digest.encode())
        h.update(b'\n')
    return h.hexdigest()


def hash_verify_receipt(checks, *, counts=None, source_counts=None,
                        target_counts=None):
    """Deterministic hash of a verify-run's consistency report.

    Feeds `phase_entity_counts` + `phase_records` + `phase_roles` + `phase_teams`
    output (list of Check objects) plus the raw source/target count dicts
    into a single digest. That digest lands in the audit-log event;
    tampering with a later-surfaced CSV/Markdown report will no longer
    match the on-chain receipt.

    `checks`: iterable of dicts (or Check objects exposing .phase/.severity/
        .message/.detail). Order is canonicalized by sort — same inputs
        always yield the same hash.
    """
    def _normalize(c):
        if isinstance(c, dict):
            sev = c.get('severity', '')
            if hasattr(sev, 'value'):
                sev = sev.value
            return {
                'phase': c.get('phase', ''),
                'severity': sev,
                'message': c.get('message', ''),
                'detail': c.get('detail', ''),
            }
        # Object-style (validate.Check): .phase, .severity (enum), .message, .detail
        sev = getattr(c, 'severity', '')
        sev = sev.value if hasattr(sev, 'value') else str(sev)
        return {
            'phase': getattr(c, 'phase', '') or '',
            'severity': sev,
            'message': getattr(c, 'message', '') or '',
            'detail': getattr(c, 'detail', '') or '',
        }

    payload = {
        'counts': counts or {},
        'source_counts': source_counts or {},
        'target_counts': target_counts or {},
        'checks': sorted(
            [_normalize(c) for c in (checks or [])],
            key=lambda e: (e['phase'], e['message']),
        ),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    ).hexdigest()
