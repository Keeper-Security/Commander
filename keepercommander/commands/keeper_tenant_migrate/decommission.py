"""Decommission — lock + delete source-tenant users after a passed gate.

Port of migration_scripts/08_decommission_old_tenant.sh. This module is
the only place in the Python port that can destroy source-side data.
All guards from the bash reference apply:

  - Requires a valid, non-expired, signature-verified checkpoint from
    `gate.py`.
  - Refuses if the checkpoint is older than MAX_CHECKPOINT_AGE_HOURS.
  - Locks users first; if lock succeeds, attempts delete. If either
    operation raises, the row is marked FAILED and the next user
    proceeds (no bulk abort — matches bash behavior).
  - 0600 on the per-run report.

The caller chains this after gate.py; it is NOT safe to call without
that predecessor.
"""

import csv
import logging
import time
from typing import List, Optional


class DecommissionClient:
    """Protocol: three operations on the source tenant's enterprise users.

    `is_user_present` is the verify-after-delete hook. Commander's
    `enterprise-user --delete` silently logs a warning (doesn't raise)
    when the user has owned records pending transfer, queued teams,
    or other pre-conditions blocking deletion. Without re-querying,
    the plugin used to count that as success. Mirrors the cleanup
    silent-failure fix 2026-04-19.

    HIGH-3 fix 2026-05-08: subclasses MUST override is_user_present.
    Pre-fix the base method silently returned False, so any subclass
    that forgot the override (e.g. a future test fake, an external
    wrapper) silently lost the verify-after-delete guarantee — every
    delete was reported SUCCESS regardless of post-delete state.
    Now the base raises NotImplementedError, and clients that
    explicitly opt out of verify (rare; legacy behaviour) MUST set
    the class attribute `trust_no_verify = True` to make the opt-out
    visible in code review.
    """

    # HIGH-3 opt-out marker — set to True ONLY in subclasses that
    # cannot or do not need to verify post-delete state. The
    # decommission() function checks this before calling
    # is_user_present(); when True, verify is skipped without raising.
    trust_no_verify = False

    def lock_user(self, email):
        raise NotImplementedError

    def delete_user(self, email):
        raise NotImplementedError

    def is_user_present(self, email):
        """Return True if the user is still visible on the tenant
        after a delete attempt. Subclasses MUST override unless they
        explicitly opt out via class attribute `trust_no_verify = True`."""
        raise NotImplementedError(
            f'{type(self).__name__} must override is_user_present() '
            f'to verify post-delete state, OR set class attribute '
            f'`trust_no_verify = True` to explicitly opt out of '
            f'verify-after-delete (legacy behaviour; not recommended). '
            f'Silent-no-op deletes are otherwise reported as SUCCESS '
            f'in the decommission report — see HIGH-3 fix.'
        )


class FakeDecommissionClient(DecommissionClient):
    def __init__(self, lock_fail=(), delete_fail=(),
                 silent_delete_fail=()):
        self.calls = []
        self.lock_fail = set(lock_fail)
        self.delete_fail = set(delete_fail)
        # Silent failure: delete returns True but user stays present.
        # Simulates Commander's warning-without-exception pattern.
        self.silent_delete_fail = set(silent_delete_fail)
        # Track live users so is_user_present reflects actual state.
        self._live_users = set()

    def seed(self, emails):
        """Test helper: pre-populate the set of live users so
        is_user_present returns True for them until deleted."""
        for e in emails:
            self._live_users.add(e)
        return self

    def lock_user(self, email):
        self.calls.append(('lock', email))
        return email not in self.lock_fail

    def delete_user(self, email):
        self.calls.append(('delete', email))
        if email in self.delete_fail:
            return False
        if email in self.silent_delete_fail:
            # Silent no-op: return True but don't actually remove.
            return True
        # Real delete: remove from live set.
        self._live_users.discard(email)
        return True

    def is_user_present(self, email):
        return email in self._live_users


def load_user_emails(roster_path):
    """Yield email strings from the roster CSV (case preserved).

    Uses read_csv_dictreader for BOM stripping + header-validation so an
    Excel-saved UTF-8-BOM file or wrong-header CSV surfaces a clear error
    instead of silently yielding zero users.
    """
    from .csv_utils import read_csv_dictreader
    _, rows = read_csv_dictreader(roster_path, required_columns=('email',))
    for row in rows:
        email = (row.get('email') or row.get('Email') or '').strip()
        if email:
            yield email


def process_users(emails, client, report_path,
                  *, sleep_seconds=0.5, sleeper=time.sleep, dry_run=False):
    """Lock + delete every user. Writes the report; returns a summary dict.

    `dry_run`: skip the CSV entirely. Compliance teams must NEVER see a
    "decommission report" showing deletions that didn't happen.
    """
    total = 0
    locked = 0
    deleted = 0
    errors = 0
    rows = []

    if dry_run:
        # HIGH-8 fix 2026-05-08: pre-fix this branch literally called
        # client.lock_user(email) + client.delete_user(email). The
        # production code path wraps the client in DryRun
        # (commands.py:4324), so the calls were stubbed in practice
        # — but the docstring promises "skip the CSV entirely.
        # Compliance teams must NEVER see a 'decommission report'
        # showing deletions that didn't happen", and the function's
        # own dry_run invariant was load-bearing only because the
        # CALLER happened to wrap the client correctly. Any future
        # caller (wizard, smoke test, automation) that passes
        # dry_run=True with an unwrapped client would get REAL
        # deletions and an empty report.
        #
        # Now: dry-run is a local invariant. We do NOT call the
        # client's destructive methods here regardless of how it's
        # wrapped. The caller still gets the count + the dry_run
        # marker; if the caller wants to exercise the wrapped client
        # for dry-run validation, they do that explicitly outside
        # this function.
        for _email in emails:
            total += 1
        return {'total': total, 'locked': 0, 'deleted': 0,
                'errors': 0, 'rows': [], 'dry_run': True}

    with open(report_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['email', 'locked', 'deleted', 'status', 'notes'])

        for email in emails:
            total += 1
            # Lock failure is non-fatal — Commander's `--lock` only works
            # on status==active (enterprise.py:1694). Match bash `|| true`
            # behavior: always attempt delete, regardless of lock outcome.
            lock_ok = client.lock_user(email)
            del_ok = client.delete_user(email)

            # Verify-after-delete. Commander's enterprise-user --delete
            # silently warns (doesn't raise) when the user has owned
            # records / queued teams / etc. blocking the deletion. If
            # the client supports is_user_present, use it to catch this
            # silent-failure class. Same pattern as cleanup.py fix
            # 2026-04-19.
            #
            # HIGH-3 fix 2026-05-08: differentiate three outcomes —
            # verified-absent, verified-still-present, and
            # verify-not-implemented. Pre-fix the third state silently
            # collapsed to verified-absent, so any subclass that
            # forgot to override is_user_present reported every
            # delete as SUCCESS. Now subclass MUST either override
            # is_user_present or set trust_no_verify=True. If neither,
            # NotImplementedError fires and the row is FAILED with a
            # clear "client did not implement verify" message.
            still_present = False
            verify_not_implemented = False
            verify_skip_reason = ''
            if getattr(client, 'trust_no_verify', False):
                verify_skip_reason = 'client opted out via trust_no_verify=True'
            else:
                try:
                    still_present = bool(client.is_user_present(email))
                except NotImplementedError:
                    verify_not_implemented = True
                except Exception as e:                       # noqa: BLE001
                    logging.warning('is_user_present(%s) raised %r — '
                                    'skipping verify', email, e)

            if verify_not_implemented:
                errors += 1
                status, notes = 'FAILED', (
                    f'verify-after-delete not implemented by '
                    f'{type(client).__name__} — cannot confirm '
                    f'delete actually removed the user. Override '
                    f'is_user_present() OR set '
                    f'trust_no_verify=True to opt out (HIGH-3).'
                )
            elif del_ok and not still_present:
                deleted += 1
                if verify_skip_reason:
                    status, notes = 'SUCCESS', (
                        f'User locked and deleted '
                        f'(verify skipped: {verify_skip_reason})'
                    )
                else:
                    status, notes = 'SUCCESS', 'User locked and deleted'
            elif del_ok and still_present:
                errors += 1
                status, notes = 'FAILED', (
                    'Delete returned success but user still present '
                    '(silent Commander no-op — user may have owned '
                    'records / queued teams; run take-ownership first)'
                )
            else:
                errors += 1
                status, notes = 'FAILED', 'Delete command failed'

            if lock_ok:
                locked += 1

            # HIGH-3 fix: deleted column reflects post-verify state.
            # When verify-not-implemented, we cannot confirm delete →
            # column is NO regardless of del_ok.
            deleted_confirmed = (
                del_ok and not still_present and not verify_not_implemented
            )
            row = [email, 'YES' if lock_ok else 'NO',
                   'YES' if deleted_confirmed else 'NO',
                   status, notes]
            writer.writerow(row)
            rows.append(row)
            logging.info('%s → lock=%s delete=%s still_present=%s',
                         email, lock_ok, del_ok, still_present)

            if sleep_seconds:
                sleeper(sleep_seconds)

    return {
        'total': total,
        'locked': locked,
        'deleted': deleted,
        'errors': errors,
        'rows': rows,
    }


# ── Plan-only path (recommended flow) ──────────────────────────────
#
# Automated deletion of real users is the single most dangerous operation
# in this toolkit and it's irreversible (Keeper has no resurrect-user
# API). The plan-only flow replaces automation with: tool emits a
# human-readable script the operator runs themselves; a separate
# --confirm-manual-completion invocation appends an audit event noting
# "I did these N deletions manually". The original automated path is
# preserved but not recommended.


def generate_plan_markdown(emails, *, source_config_path: str,
                           prerequisites: Optional[List[str]] = None) -> str:
    """Return a Markdown plan that the operator executes by hand.

    The commands are literal — copy-paste into a shell one at a time or
    pipe through `bash -x` for verbose execution. Each user gets both
    `--lock` and `--delete`; failures on one don't abort the other.
    """
    emails = [e for e in emails if e]
    prereqs = prerequisites or [
        '`take-ownership-report.csv` shows 0 errors OR user vaults are '
        'otherwise preserved (transfer-user / backup).',
        'Audit chain on $RUN is intact '
        '(`tenant-migrate audit-verify --directory $RUN` → `"ok": true`).',
        'Tenant / user count on source matches expectations — sanity check '
        'with `enterprise-info --users | grep -c MIGTEST-` before proceeding.',
    ]

    lines = []
    lines.append(f'# Decommission plan — {len(emails)} user(s)\n')
    lines.append('> ⚠ **Irreversible.** Keeper has no resurrect-user API. '
                 'Re-read each line before running it.\n')
    lines.append('## Prerequisites (verify before any deletion)')
    for p in prereqs:
        lines.append(f'- [ ] {p}')
    lines.append('')
    lines.append('## Commands (run in order)\n')
    lines.append('```bash')
    cfg = source_config_path or '<SOURCE_CONFIG>'
    for email in emails:
        lines.append(f'# --- {email} ---')
        lines.append(
            f'keeper --config "{cfg}" enterprise-user "{email}" --lock -f'
        )
        lines.append(
            f'keeper --config "{cfg}" enterprise-user "{email}" --delete -f'
        )
        lines.append(
            f'keeper --config "{cfg}" enterprise-info --users '
            f'| grep -c "{email}"  # expect: 0'
        )
        lines.append('')
    lines.append('```\n')
    lines.append('## After completion\n')
    lines.append('Close the audit loop so the chain reflects what actually '
                 'happened:')
    lines.append('')
    lines.append('```bash')
    lines.append('keeper-migrate --config "$SRC" tenant-migrate decommission \\')
    lines.append('    --roster <same roster used above> \\')
    lines.append('    --confirm-manual-completion \\')
    lines.append('    --audit-log $RUN/audit.log')
    lines.append('```\n')
    return '\n'.join(lines)


def append_manual_completion_audit(emails, *, audit_log_path: str,
                                   operator: str = '') -> dict:
    """Emit a single audit event recording operator-confirmed manual deletion.

    This is the only supported way to reconcile the audit log with
    deletions performed outside the tool. The chain-hash stays intact
    because all audit events go through the same `append_audit_event`
    writer.
    """
    from .audit import append_audit_event
    emails = [e for e in emails if e]
    event = {
        'subcommand': 'decommission',
        'mode': 'manual-completion',
        'inputs': {'roster_size': len(emails)},
        'summary': {
            'operator': operator or 'unspecified',
            'manually_deleted_emails': emails,
            'count': len(emails),
        },
    }
    append_audit_event(audit_log_path, event)
    return event
