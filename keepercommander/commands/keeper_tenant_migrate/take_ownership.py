"""Path-A ownership transfer: move source-user folders to admin before export.

Port of migration_scripts/02_take_ownership.sh. For each READY user in a
verification-report CSV, the admin:
  1. Exports the user's MIGRATION-* folder as a JSON backup (belt-and-
     suspenders — if ownership transfer goes wrong, the data is still
     recoverable).
  2. Issues `share-record -e ADMIN -a owner -R -f FOLDER` to transfer
     ownership of the folder and all records within.

Constraints (same as the bash reference):
  - Only processes rows with status == 'READY'.
  - Aborts the ownership step for a row if the backup fails.
  - 0.5s sleep between rows to be gentle on the throttle.

Produces:
  - BACKUP_DIR/<safe_email>_<ts>.json per row where a backup succeeded.
  - ownership_report.csv with one row per processed user.

All writes on the CURRENT session (source tenant — the admin must be
logged in there, with visibility into the MIGRATION-* folders).
"""

import csv
import logging
import os
import time

from .email_remap import remap_email


class OwnershipClient:
    """Protocol covering the two operations this module needs."""

    def export_folder_json(self, folder_path, output_path):
        raise NotImplementedError

    def take_folder_ownership(self, folder_path, new_owner_email):
        raise NotImplementedError


class FakeOwnershipClient(OwnershipClient):
    """In-memory client used by tests."""

    def __init__(self, export_fail_for=(), ownership_fail_for=()):
        self.calls = []
        self.export_fail_for = set(export_fail_for)
        self.ownership_fail_for = set(ownership_fail_for)

    def export_folder_json(self, folder_path, output_path):
        self.calls.append(('export', folder_path, output_path))
        if folder_path in self.export_fail_for:
            return False
        # Write a stub file so callers can verify side effect
        with open(output_path, 'w') as f:
            f.write('{"stub": true}')
        return True

    def take_folder_ownership(self, folder_path, new_owner_email):
        self.calls.append(('ownership', folder_path, new_owner_email))
        return folder_path not in self.ownership_fail_for


def _sanitize_for_filename(email):
    """Turn an email into a filename-safe string WITHOUT collision risk.

    Naïve `non-alnum → _` loses every non-ASCII character, so
    `陈伟@x.com` and `张三@x.com` would both become `__________` and
    overwrite each other's backup. We keep Unicode letters/digits
    (Python's str.isalnum() treats them as alnum) and suffix with a
    short content-derived hash so two emails that sanitize to the
    same prefix still produce distinct filenames.
    """
    import hashlib
    prefix = ''.join(c if c.isalnum() else '_' for c in email)
    suffix = hashlib.sha256(email.encode('utf-8')).hexdigest()[:8]
    return f'{prefix}_{suffix}'


def load_ready_users(verification_csv):
    """Yield {email, full_name, folder, record_count} for rows with status=READY."""
    from .csv_utils import read_csv_dictreader
    _, rows = read_csv_dictreader(
        verification_csv,
        required_columns=('email', 'status'),
    )
    for row in rows:
        if (row.get('status') or '').strip().upper() != 'READY':
            continue
        email = (row.get('email') or '').strip()
        folder = (row.get('expected_folder') or '').strip()
        if not email or not folder:
            continue
        yield {
            'email': email,
            'full_name': (row.get('full_name') or '').strip(),
            'folder': folder,
            'record_count': (row.get('record_count') or '').strip(),
        }


def process_users(users, client, admin_email, backup_dir, report_path,
                  *, sleep_seconds=0.5, sleeper=time.sleep, timestamp='',
                  dry_run=False, old_domain='', new_domain='',
                  batch_size=0,
                  checkpoint=None, resume=False, force_restart=False):
    """Run backup + ownership transfer for each user. Writes report_path CSV.

    `dry_run`: when True, the CSV is suppressed entirely so operators can't
    mistake a dry-run output for evidence of a completed transfer. Driver
    still walks the full loop (via DryRun-wrapped client) so counters
    accumulate; classification happens in the caller.

    Returns a summary dict {total, backups, ownerships, errors, rows}.
    """
    if not dry_run:
        os.makedirs(backup_dir, exist_ok=True)

    # Admin email lives on the TARGET tenant in cross-domain runs — remap
    # so `share-record -e ADMIN` hits the account that actually exists.
    admin_email = remap_email(admin_email, old_domain, new_domain)

    rows = []
    total = 0
    backups_created = 0
    ownerships_taken = 0
    errors = 0

    # In dry-run we skip the live CSV entirely — caller renders a Markdown
    # plan instead. The summary dict is still returned so callers can log.
    if dry_run:
        # CSV suppressed — operators must not see a 'SUCCESS' report for a
        # transfer that didn't happen. Driver still drives the (wrapped)
        # client so callers can classify_plan() the recorded ops. The
        # wrapped client is expected to be a DryRun that intercepts writes;
        # a non-wrapped live client would actually perform backups here,
        # so pass dry_run=True only with a DryRun-wrapped client.
        backup_dir_safe = backup_dir if os.path.isdir(backup_dir) else '/tmp'
        for user in users:
            total += 1
            dummy_path = os.path.join(backup_dir_safe, f'__dry_run_{total}__.json')
            client.export_folder_json(user['folder'], dummy_path)
            client.take_folder_ownership(user['folder'], admin_email)
        return {'total': total, 'backups': 0, 'ownerships': 0,
                'errors': 0, 'rows': [], 'dry_run': True}

    users = list(users)
    input_sha = None
    start = 1
    if checkpoint is not None:
        from .checkpoint import hash_rows
        keyed = [(u.get('email', ''), u.get('folder', '')) for u in users]
        input_sha = hash_rows(keyed)
        start = checkpoint.resume_from(
            keyed, resume=resume, force_restart=force_restart,
        )
        if start > 1:
            logging.info('take-ownership: resuming at row %d/%d',
                         start, len(users))

    # On resume we open the report in append mode so prior rows survive.
    mode = 'a' if (start > 1 and os.path.exists(report_path)) else 'w'
    with open(report_path, mode, newline='') as f:
        writer = csv.writer(f)
        if mode == 'w':
            writer.writerow(['email', 'full_name', 'folder', 'backup_created',
                             'ownership_taken', 'record_count',
                             'status', 'notes'])

        for idx, user in enumerate(users, start=1):
            if idx < start:
                total += 1  # Count resumed rows toward the total for parity
                continue
            total += 1
            backup_file = os.path.join(
                backup_dir,
                f'{_sanitize_for_filename(user["email"])}_{timestamp}.json',
            )
            backup_ok = client.export_folder_json(user['folder'], backup_file)

            if not backup_ok:
                errors += 1
                row = [user['email'], user['full_name'], user['folder'],
                       'NO', 'NO', user['record_count'], 'FAILED',
                       'Backup failed, skipping ownership transfer']
                writer.writerow(row)
                rows.append(row)
                logging.warning('Backup failed for %s; skipping ownership',
                                user['email'])
                continue
            backups_created += 1

            owner_ok = client.take_folder_ownership(user['folder'], admin_email)
            if owner_ok:
                ownerships_taken += 1
                status, notes = 'SUCCESS', 'Ownership transferred successfully'
            else:
                errors += 1
                status, notes = 'FAILED', 'Ownership transfer failed, check logs'

            row = [user['email'], user['full_name'], user['folder'],
                   'YES', 'YES' if owner_ok else 'NO', user['record_count'],
                   status, notes]
            writer.writerow(row)
            rows.append(row)
            logging.info('%s → %s (%s)', user['email'], status, notes)

            if checkpoint is not None and input_sha:
                checkpoint.mark_done(idx, input_sha256=input_sha)

            if sleep_seconds:
                sleeper(sleep_seconds)
            if batch_size and total % batch_size == 0:
                logging.info('Batch checkpoint: %d transfers processed', total)
                if sleeper:
                    sleeper(max(sleep_seconds * 2, 1.0))

    if checkpoint is not None:
        checkpoint.clear()

    return {
        'total': total,
        'backups': backups_created,
        'ownerships': ownerships_taken,
        'errors': errors,
        'rows': rows,
    }
