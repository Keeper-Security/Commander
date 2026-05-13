"""Path-B vault transfer: pull entire source-user vaults into the admin.

Port of migration_scripts/02b_transfer_user_vaults.sh. For each
READY_TRANSFER user in a readiness-report CSV, the admin runs
`transfer-user EMAIL --target-user ADMIN -f`. Commander auto-locks the
source user and moves the whole vault (not just shared folders) to the
admin account.

Constraints from the bash reference:
  - Filter rows where `migration_path` contains 'READY_TRANSFER'.
  - Skip users that match the admin email (can't transfer to yourself).
  - Sync-down after each transfer so subsequent reads see the new records.
  - Write a report with one row per processed user.

Post-transfer record export is handled separately by `records-export`
(which reads the admin's vault post-sync). Keeping transfer and export
in separate steps gives cleaner error surfaces.
"""

import csv
import logging
import time


class TransferUserClient:
    """Protocol: a single operation that relocates a user's vault."""

    def transfer_user_vault(self, email, target_admin):
        """Return True on success, False on failure.

        Commander's `transfer-user` auto-locks the source user as part of
        the transfer per transfer_account.py source comments.
        """
        raise NotImplementedError

    def sync_down(self):
        """Refresh the admin's record cache post-transfer."""
        raise NotImplementedError


class FakeTransferUserClient(TransferUserClient):
    def __init__(self, fail_for=()):
        self.calls = []
        self.fail_for = set(fail_for)

    def transfer_user_vault(self, email, target_admin):
        self.calls.append(('transfer', email, target_admin))
        return email not in self.fail_for

    def sync_down(self):
        self.calls.append(('sync_down',))
        return True


def load_ready_transfer_users(readiness_csv):
    """Yield {email, name} rows whose migration_path mentions READY_TRANSFER."""
    from .csv_utils import read_csv_dictreader
    _, rows = read_csv_dictreader(
        readiness_csv,
        required_columns=('email', 'migration_path'),
    )
    for row in rows:
        path = (row.get('migration_path') or '').upper()
        if 'READY_TRANSFER' not in path:
            continue
        email = (row.get('email') or '').strip()
        if not email:
            continue
        yield {
            'email': email,
            'name': (row.get('name') or '').strip(),
            'transfer_status': (row.get('transfer_status') or '').strip(),
        }


def process_users(users, client, admin_email, report_path,
                  *, sleep_seconds=2.0, sleeper=time.sleep, dry_run=False,
                  checkpoint=None, resume=False, force_restart=False):
    """Run transfer-user for each row; write per-user report. Returns summary.

    `dry_run`: skip the CSV (no false-positive "SUCCESS" rows). Driver still
    loops so wrapped DryRun client records every would-be call for the
    caller to classify.
    """
    total = 0
    transferred = 0
    skipped = 0
    errors = 0
    rows = []

    admin_lower = (admin_email or '').lower()

    if dry_run:
        for user in users:
            total += 1
            email = user['email']
            if email.lower() == admin_lower:
                skipped += 1
                continue
            client.transfer_user_vault(email, admin_email)
            client.sync_down()
        return {'total': total, 'transferred': 0, 'skipped': skipped,
                'errors': 0, 'rows': [], 'dry_run': True}

    users = list(users)
    input_sha = None
    start = 1
    if checkpoint is not None:
        from .checkpoint import hash_rows
        keyed = [(u.get('email', '') or '').lower() for u in users]
        input_sha = hash_rows(keyed)
        start = checkpoint.resume_from(
            keyed, resume=resume, force_restart=force_restart,
        )
        if start > 1:
            logging.info('transfer-user: resuming at row %d/%d',
                         start, len(users))

    import os.path as _op
    mode = 'a' if (start > 1 and _op.exists(report_path)) else 'w'
    with open(report_path, mode, newline='') as f:
        writer = csv.writer(f)
        if mode == 'w':
            writer.writerow(['email', 'name', 'transfer_status',
                             'vault_transferred', 'status', 'notes'])

        for idx, user in enumerate(users, start=1):
            if idx < start:
                total += 1
                continue
            total += 1
            email = user['email']

            if email.lower() == admin_lower:
                skipped += 1
                row = [email, user['name'], user['transfer_status'],
                       'SELF', 'SKIPPED',
                       'Admin account — vault already owned']
                writer.writerow(row)
                rows.append(row)
                logging.info('%s is admin; skip transfer-user', email)
                continue

            # HIGH-7 fix 2026-05-08: pre-fix client.transfer_user_vault
            # was called bare. transient errors (HTTP 429 / network blip
            # / session expired) propagated up out of the loop, aborting
            # before the row's checkpoint mark_done ran. On --resume the
            # row looked untouched even though transfer-user is
            # non-idempotent (per backoff.py:Retry docstring) and the
            # source user may have been partially auto-locked.
            #
            # Now: catch any exception around the call, mark the row as
            # ERROR with diagnostic notes (transient or not — the
            # operator must verify either way because the call is
            # non-idempotent), advance the checkpoint so --resume
            # skips it, continue to the next row.
            try:
                ok = client.transfer_user_vault(email, admin_email)
            except Exception as e:                          # noqa: BLE001
                errors += 1
                status, notes, flag = 'FAILED', (
                    f'transfer-user raised {type(e).__name__}: {e!r} — '
                    f'source user may be partially auto-locked. '
                    f'transfer-user is NON-IDEMPOTENT (see backoff.py'
                    f':Retry) so --resume cannot safely retry; manual '
                    f'review required (verify source user lock state '
                    f'and target vault completeness for {email}).'
                ), 'NO'
                row = [email, user['name'], user['transfer_status'],
                       flag, status, notes]
                writer.writerow(row)
                rows.append(row)
                logging.error('%s → %s (caught %s)',
                              email, status, type(e).__name__)
                # HIGH-7: persist checkpoint so --resume skips this row.
                # Operator handles via the manual-review path.
                if checkpoint is not None and input_sha:
                    checkpoint.mark_done(idx, input_sha256=input_sha)
                continue

            if ok:
                transferred += 1
                status, notes, flag = 'SUCCESS', (
                    'Vault transferred + user auto-locked'), 'YES'
                if sleep_seconds:
                    sleeper(sleep_seconds)
                # Post-transfer sync so admin cache picks up new records
                client.sync_down()
            else:
                errors += 1
                status, notes, flag = 'FAILED', (
                    'transfer-user returned failure — check logs'), 'NO'

            row = [email, user['name'], user['transfer_status'],
                   flag, status, notes]
            writer.writerow(row)
            rows.append(row)
            logging.info('%s → %s', email, status)

            if checkpoint is not None and input_sha:
                checkpoint.mark_done(idx, input_sha256=input_sha)

    if checkpoint is not None:
        checkpoint.clear()

    return {
        'total': total,
        'transferred': transferred,
        'skipped': skipped,
        'errors': errors,
        'rows': rows,
    }
