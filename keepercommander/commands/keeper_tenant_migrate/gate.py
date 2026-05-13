"""Point-of-no-return gate — authorize destructive operations via a
signed checkpoint file.

Port of migration_scripts/07_point_of_no_return.sh, modernized:
  - Reads the validator's checks.csv instead of parsing Markdown grades.
  - Reads the reconciliation Markdown for a secondary presence check.
  - Requires explicit YES token from the caller (no TTY prompt — caller
    owns UX).
  - Writes a JSON checkpoint with sha256 self-signature and timestamp.
  - Downstream `decommission` refuses to run unless the checkpoint
    exists, is intact, and is fresh (< MAX_AGE_HOURS).

Checkpoint file format:
    {
        "timestamp": "2026-04-18T18:00:00Z",
        "checks_path": "/.../checks.csv",
        "checks_summary": {"PASS": ..., "FAIL": ..., "SKIP": ..., "WARN": ...},
        "reconcile_path": "/.../reconciliation.md",
        "signature": "<sha256 of the rest of the file>"
    }
"""

import csv
import datetime
import hashlib
import json
import os


MAX_CHECKPOINT_AGE_HOURS = 72


class GateError(Exception):
    pass


def _summarize_checks_csv(path):
    """Return {PASS: n, FAIL: n, SKIP: n, WARN: n} from a validator CSV."""
    counts = {'PASS': 0, 'FAIL': 0, 'SKIP': 0, 'WARN': 0}
    with open(path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sev = (row.get('severity') or '').strip().upper()
            if sev in counts:
                counts[sev] += 1
    return counts


def _canonical_body(data):
    """Serialize checkpoint body (everything except signature) for hashing."""
    without_sig = {k: v for k, v in data.items() if k != 'signature'}
    return json.dumps(without_sig, sort_keys=True, separators=(',', ':')).encode()


def _sign(data):
    return hashlib.sha256(_canonical_body(data)).hexdigest()


def evaluate(checks_csv, reconcile_md=None, confirm_token=''):
    """Run the gate checks. Raises GateError on failure.

    Returns a checkpoint dict (unsigned) on success. Caller picks where to
    persist it (typically next to checks.csv).
    """
    if not checks_csv or not os.path.exists(checks_csv):
        raise GateError(f'checks CSV not found: {checks_csv!r}')

    counts = _summarize_checks_csv(checks_csv)

    if counts['FAIL'] > 0:
        raise GateError(f"checks.csv has {counts['FAIL']} FAIL — migration not "
                        f"verified complete")

    if reconcile_md and not os.path.exists(reconcile_md):
        raise GateError(f'reconciliation report not found: {reconcile_md!r}')

    if confirm_token != 'YES':
        raise GateError(
            "explicit confirmation missing — pass --confirm YES to acknowledge "
            "destructive next-step authorization"
        )

    return {
        'timestamp': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        'checks_path': os.path.abspath(checks_csv),
        'checks_summary': counts,
        'reconcile_path': os.path.abspath(reconcile_md) if reconcile_md else '',
    }


def write_checkpoint(checkpoint, output_path):
    """Sign + write the checkpoint atomically; chmod 0600."""
    checkpoint = dict(checkpoint)
    checkpoint['signature'] = _sign(checkpoint)
    with open(output_path, 'w') as f:
        json.dump(checkpoint, f, indent=2, sort_keys=True)
    os.chmod(output_path, 0o600)
    return checkpoint


def read_checkpoint(path, *, max_age_hours=MAX_CHECKPOINT_AGE_HOURS):
    """Load + validate a checkpoint. Returns the dict on success. Raises
    GateError if the file is missing, tampered, or expired.
    """
    if not os.path.exists(path):
        raise GateError(f'no checkpoint at {path!r}')
    with open(path) as f:
        data = json.load(f)

    signature = data.get('signature')
    if not signature:
        raise GateError('checkpoint missing signature field')
    expected = _sign(data)
    if signature != expected:
        raise GateError('checkpoint signature mismatch — file was modified')

    ts_str = data.get('timestamp', '')
    try:
        # HIGH-2 fix 2026-05-08: parse as tz-aware UTC. The 'Z' suffix
        # denotes UTC by convention, but strptime can't read it as a
        # tz marker without manual replace(). Pre-fix the result was
        # a naive datetime, and the comparison below used utcnow()
        # which is also naive — both work in the happy path but do
        # not catch tz confusion (NTP step, wrong clock setting,
        # parsed-as-local-by-mistake).
        ts = datetime.datetime.strptime(
            ts_str, '%Y-%m-%dT%H:%M:%SZ'
        ).replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        raise GateError(f'invalid checkpoint timestamp: {ts_str!r}')

    # HIGH-2 fix: tz-aware now() against tz-aware ts.
    now = datetime.datetime.now(datetime.timezone.utc)
    age = now - ts

    # HIGH-2 fix: clamp negative ages with a loud, blocking error.
    # Pre-fix `if age.total_seconds() > max_age_hours * 3600:` allowed
    # negative ages to silently pass — a checkpoint that claims to be
    # from the future authorized destructive ops like `decommission`.
    # Causes: NTP step backwards on the operator host, wrong system
    # clock, or a tampered checkpoint where the attacker bumped the
    # timestamp forward. None of those should authorize a write.
    if age.total_seconds() < 0:
        raise GateError(
            f'checkpoint timestamp {ts_str!r} is in the future relative '
            f'to current UTC clock — age = {age.total_seconds():.1f}s. '
            f'Possible causes: NTP step backwards, wrong system clock, '
            f'or tampered checkpoint. Refusing to authorize until clock '
            f'is fixed and checkpoint is re-issued.'
        )

    if age.total_seconds() > max_age_hours * 3600:
        raise GateError(
            f'checkpoint expired: age {age} exceeds {max_age_hours}h max'
        )

    return data
