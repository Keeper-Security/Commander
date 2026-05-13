"""Restore ownership to the original user from a take-ownership backup.

`take-ownership` writes a JSON backup per user BEFORE transferring
folder ownership. If the migration is aborted or rolled back, this
module's `restore()` reads that backup dir, validates its integrity
via SHA256SUMS.txt + audit.log, and for each row where
`ownership_taken=YES` issues `share-record -e ORIG_USER -a owner -R -f
FOLDER` to hand the folder back.

Not a full undo of the migration — per-record ownership transfers that
happened outside the MIGRATION-* folder aren't tracked. But for the
normal Path-A flow (share MIGRATION-Alice folder with admin → admin
takes ownership → disaster) this module puts things back.
"""

import csv
import logging
import os


class RestoreClient:
    """Single operation: grant ownership back to a user."""

    def grant_folder_ownership(self, folder_path, new_owner_email):
        raise NotImplementedError


class FakeRestoreClient(RestoreClient):
    def __init__(self, fail_for=()):
        self.calls = []
        self.fail_for = set(fail_for)

    def grant_folder_ownership(self, folder_path, new_owner_email):
        self.calls.append(('grant', folder_path, new_owner_email))
        return folder_path not in self.fail_for


def load_ownership_report(report_path):
    """Parse the CSV emitted by `take-ownership`. Yield rows that
    had `ownership_taken=YES`."""
    from .csv_utils import read_csv_dictreader
    _, rows = read_csv_dictreader(report_path,
                                   required_columns=('email', 'folder'))
    for row in rows:
        if (row.get('ownership_taken') or '').strip().upper() != 'YES':
            continue
        email = (row.get('email') or '').strip()
        folder = (row.get('folder') or '').strip()
        if not (email and folder):
            continue
        yield {'email': email, 'folder': folder}


def restore(client, report_path, *, verify_backup_dir='', dry_run=False):
    """Restore ownership per row in the report.

    `verify_backup_dir` — optional directory path; if given, the audit
    manifest + chain are checked first. Mismatch → refuse with a clear
    error.
    """
    if verify_backup_dir:
        from .audit import verify_audit_log, verify_sha256sums
        try:
            sums = verify_sha256sums(verify_backup_dir)
        except FileNotFoundError:
            logging.error('Cannot verify backup integrity: no SHA256SUMS.txt in %s',
                          verify_backup_dir)
            return {'blocked': True, 'reason': 'no_backup_manifest'}
        if sums['mismatch'] or sums['missing']:
            logging.error(
                'Backup integrity check FAILED: %d missing, %d mismatched. '
                'Refusing to restore from an untrusted backup dir.',
                len(sums['missing']), len(sums['mismatch']),
            )
            return {'blocked': True, 'reason': 'backup_integrity',
                    'details': sums}
        audit_log = os.path.join(verify_backup_dir, 'audit.log')
        if os.path.exists(audit_log):
            chain_ok, broken = verify_audit_log(audit_log)
            if not chain_ok:
                logging.error(
                    'audit.log chain broken at line %s — refusing to restore.',
                    broken,
                )
                return {'blocked': True, 'reason': 'audit_chain_broken',
                        'broken_line': broken}

    rows = list(load_ownership_report(report_path))
    if dry_run:
        logging.info('[dry-run] would restore ownership of %d folder(s)',
                     len(rows))
        return {'dry_run': True, 'total': len(rows), 'rows': rows}

    restored = 0
    failed = 0
    for row in rows:
        ok = client.grant_folder_ownership(row['folder'], row['email'])
        if ok:
            restored += 1
            logging.info('restored: %s → %s', row['folder'], row['email'])
        else:
            failed += 1
            logging.warning('restore failed: %s → %s', row['folder'], row['email'])
    return {'total': len(rows), 'restored': restored, 'failed': failed}
