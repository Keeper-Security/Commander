"""Arbitrary-point rollback using the tamper-evident audit log.

The audit log is already the source-of-truth for every mutating
subcommand we run. `undo` reads it BACKWARDS from the newest entry
down to (and optionally excluding) a chosen event, and invokes an
inverse operation for each reversible event.

Not every event is reversible:

  - `users` (invite): inverse = `lock-user` + `delete-user` (the
    delete happens only if `--hard` is passed; by default we just lock).
  - `structure` (node/team/role/SF create): inverse = delete matching
    entity by name. We only undo entities whose UID we recorded in the
    audit event's `summary.created_entities` block.
  - `take-ownership`: inverse = `take-ownership-restore` against the
    report CSV that was captured under `outputs`.
  - `records-import`: NOT reversible automatically — we emit a manual
    action instead: the admin must delete the imported records by UID.
  - `records-attachments`, `records-shares`: reverse each pair by
    deleting attachments / revoking shares.
  - `cleanup`, `decommission`: NOT reversible (entities were deleted).
    We emit manual actions referencing the pre-delete SHA256SUMS.txt
    backup so the admin knows which dump to restore from.

Safety
------

- Chain verify first. If the log is tampered we refuse to proceed.
- Dry-run default: `undo` lists every inverse op before executing.
- `--up-to EVENT_ID` stops BEFORE that event (that event stays done).
- `--up-to LATEST` (default) processes every event → full rollback.
- `--execute` flag is required to actually mutate; otherwise we stop
  after printing the inverse plan.

Client protocol
---------------

`UndoClient` abstracts the destructive calls so tests drive the planner
without a live session. The real client is a thin wrapper around
Commander.
"""

from __future__ import annotations

import logging
from typing import Iterator, List, Optional

from .audit_export import read_audit_events
from .audit import verify_audit_log


IRREVERSIBLE = 'irreversible'
REVERSIBLE = 'reversible'
MANUAL = 'manual'


class UndoPlan:
    __slots__ = ('event', 'kind', 'ops', 'notes')

    def __init__(self, event, kind, ops=None, notes=''):
        self.event = event
        self.kind = kind          # reversible | manual | irreversible
        self.ops = ops or []       # list of (verb, args) tuples for reversible
        self.notes = notes


class UndoClient:
    def lock_user(self, email: str) -> bool:
        raise NotImplementedError

    def delete_user(self, email: str) -> bool:
        raise NotImplementedError

    def delete_node(self, name: str) -> bool:
        raise NotImplementedError

    def delete_team(self, name: str) -> bool:
        raise NotImplementedError

    def delete_role(self, name: str) -> bool:
        raise NotImplementedError

    def delete_shared_folder(self, uid: str) -> bool:
        raise NotImplementedError

    def revoke_record_share(self, target_uid: str, email: str) -> bool:
        raise NotImplementedError

    def delete_attachment(self, record_uid: str, file_name: str) -> bool:
        raise NotImplementedError


class FakeUndoClient(UndoClient):
    def __init__(self, fail_ops=()):
        self.calls: list = []
        self.fail_ops = set(fail_ops)

    def _record(self, op, args):
        self.calls.append((op, args))
        return op not in self.fail_ops

    def lock_user(self, email):
        return self._record('lock_user', (email,))

    def delete_user(self, email):
        return self._record('delete_user', (email,))

    def delete_node(self, name):
        return self._record('delete_node', (name,))

    def delete_team(self, name):
        return self._record('delete_team', (name,))

    def delete_role(self, name):
        return self._record('delete_role', (name,))

    def delete_shared_folder(self, uid):
        return self._record('delete_shared_folder', (uid,))

    def revoke_record_share(self, target_uid, email):
        return self._record('revoke_record_share', (target_uid, email))

    def delete_attachment(self, record_uid, file_name):
        return self._record('delete_attachment', (record_uid, file_name))


def _invert_event(event: dict, *, hard: bool) -> UndoPlan:
    """Return an UndoPlan describing how to reverse a single event."""
    sub = (event.get('subcommand') or '').lower()
    summary = event.get('summary') or {}
    outputs = event.get('outputs') or {}

    if sub == 'users':
        emails = summary.get('invited_emails') or []
        ops = []
        for e in emails:
            ops.append(('lock_user', (e,)))
            if hard:
                ops.append(('delete_user', (e,)))
        return UndoPlan(event, REVERSIBLE, ops,
                         notes=f'{len(emails)} user(s) will be '
                               f'{"locked+deleted" if hard else "locked only"}')

    if sub == 'structure':
        created = summary.get('created_entities') or {}
        ops = []
        # Reverse order across kinds: SFs first (depend on nodes),
        # then roles/teams, then nodes.
        for uid in created.get('shared_folders', []) or []:
            ops.append(('delete_shared_folder', (uid,)))
        for name in created.get('roles', []) or []:
            ops.append(('delete_role', (name,)))
        for name in created.get('teams', []) or []:
            ops.append(('delete_team', (name,)))
        # Nodes: reverse iteration order so children are deleted
        # before parents. Bug 18 — the audit log records nodes in
        # creation order (topological, parents-before-children).
        # Iterating forward made the parent delete fire first; the
        # server rejected it with "must first delete or move the
        # objects on this node" because the child was still attached.
        # Reversing yields deepest-first deletion.
        for name in reversed(created.get('nodes', []) or []):
            ops.append(('delete_node', (name,)))
        return UndoPlan(event, REVERSIBLE, ops,
                         notes=f'{len(ops)} entity(ies) will be deleted')

    if sub == 'take-ownership':
        report = outputs.get('report_output') or outputs.get('report_path')
        return UndoPlan(
            event, MANUAL, [],
            notes=(f'Run `tenant-migrate take-ownership-restore '
                   f'--report {report}` to return folders to original users.')
            if report else 'Report path not captured — restore manually.'
        )

    if sub == 'records-import':
        record_uids = summary.get('imported_uids') or []
        return UndoPlan(
            event, MANUAL, [],
            notes=(f'{len(record_uids)} record(s) imported. '
                   'Delete by UID on target — automated rollback cannot '
                   'distinguish target-native records from imported ones.'),
        )

    # Bug 45 — Bug 20 split records-shares into extract (source-side,
    # produces JSON manifest, no target writes) + apply (target-side,
    # actually grants shares). The grants live in the apply event's
    # `share_grants` summary, same shape as the legacy single-session
    # `records-shares` event. Undo must invert apply (revoke each
    # grant). Extract is read-only with respect to target. Same fix
    # for records-attachments-download (read-only) and -upload (the
    # actual writes).
    if sub in ('records-shares', 'records-shares-apply'):
        pairs = summary.get('share_grants') or []
        ops = [('revoke_record_share', (p['target_uid'], p['email']))
               for p in pairs if isinstance(p, dict)]
        return UndoPlan(event, REVERSIBLE, ops,
                         notes=f'Revoke {len(ops)} share grant(s)')

    if sub == 'records-shares-extract':
        return UndoPlan(event, REVERSIBLE, [],
                         notes='Source-side extract only — no target '
                               'state to revert.')

    if sub in ('records-attachments', 'records-attachments-upload'):
        uploads = summary.get('uploaded') or summary.get('uploaded_files') or []
        ops = [('delete_attachment', (u['target_uid'], u['file_name']))
               for u in uploads if isinstance(u, dict)
               and u.get('target_uid') and u.get('file_name')]
        return UndoPlan(event, REVERSIBLE, ops,
                         notes=f'Delete {len(ops)} uploaded attachment(s)')

    if sub == 'records-attachments-download':
        return UndoPlan(event, REVERSIBLE, [],
                         notes='Source-side download only — no target '
                               'state to revert.')

    if sub == 'records-references-rewrite':
        # Bug 33 (v1.5.1) — references rewrite mutates structured field
        # values in-place on target records. Reverting requires the
        # before-image, which the audit summary doesn't carry (would
        # double the audit log size for a comparatively rare flow).
        # Operators that need to roll back run records-import again
        # from the source bundle, which restores source-shaped UIDs
        # before the rewrite re-runs.
        rewritten = (event.get('summary') or {}).get('rewritten_uids') or []
        return UndoPlan(event, MANUAL, [],
                         notes=(f'{len(rewritten)} record(s) had embedded '
                                f'UIDs remapped — re-import from source '
                                f'bundle to restore source-shaped values.'))

    if sub in ('cleanup', 'decommission'):
        return UndoPlan(event, IRREVERSIBLE, [],
                         notes=('Entities already deleted. Restore from the '
                                'pre-delete SHA256SUMS backup dir if one exists.'))

    # Read-only subcommands
    if sub in ('plan', 'records-export', 'verify', 'reconcile',
                'capture-target-state', 'session', 'self-test'):
        return UndoPlan(event, REVERSIBLE, [],
                         notes='Read-only — nothing to undo.')

    return UndoPlan(event, MANUAL, [],
                     notes=f'Unknown subcommand {sub!r} — manual review.')


def plan_undo(log_path: str, *, up_to_signature: Optional[str] = None,
               hard: bool = False) -> List[UndoPlan]:
    """Read the audit log, walk backwards, return the list of UndoPlans.

    `up_to_signature` — if given, plans STOP at the event with that
    signature (that event itself is NOT undone — it's the "resume
    from here" marker). None → plan every event.

    Caller must verify the chain first; this helper trusts the log.
    """
    events = list(read_audit_events(log_path))
    plans: List[UndoPlan] = []
    for ev in reversed(events):
        if up_to_signature and ev.get('signature') == up_to_signature:
            break
        plans.append(_invert_event(ev, hard=hard))
    return plans


class ManualActionRequired(Exception):
    """Raised by an undo client method to signal that the operation
    cannot be performed automatically and the operator must act
    manually. The execute_plans loop catches this separately from
    generic Exception and tallies it as `manual` rather than `failed`,
    so compliance teams reading the undo summary see an accurate
    "X operations need human follow-up" count rather than a
    misleading "X operations failed" tally that hides the real
    structure.

    Pre-HIGH-5 fix 2026-05-08, the only way for a client method to
    say "needs manual intervention" was to return False, which was
    counted as a failure with no escalation path — operators reading
    the summary couldn't distinguish "Commander rejected the call"
    from "Commander can't do this; do it yourself in the web UI".
    Raising this exception now makes the distinction explicit.
    """


def execute_plans(plans: List[UndoPlan], client: UndoClient) -> dict:
    """Run every reversible op in order. Returns a summary dict."""
    reversed_count = 0
    failed_count = 0
    manual_count = 0
    irreversible_count = 0
    for p in plans:
        if p.kind == MANUAL:
            manual_count += 1
            logging.info('undo[manual]: %s', p.notes)
            continue
        if p.kind == IRREVERSIBLE:
            irreversible_count += 1
            logging.warning('undo[irreversible]: %s', p.notes)
            continue
        for verb, args in p.ops:
            fn = getattr(client, verb, None)
            if fn is None:
                failed_count += 1
                logging.error('undo: client has no method %s', verb)
                continue
            try:
                ok = fn(*args)
            except ManualActionRequired as e:
                # HIGH-5 fix 2026-05-08: client signals "needs human
                # follow-up" via this exception, distinct from a
                # genuine failure. Tally as manual, not failed.
                manual_count += 1
                logging.warning('undo[%s] requires manual action: %s',
                                verb, e)
                continue
            except Exception as e:                         # noqa: BLE001
                logging.error('undo[%s] raised: %r', verb, e)
                failed_count += 1
                continue
            if ok:
                reversed_count += 1
                logging.info('undo[%s]: %s', verb, args)
            else:
                failed_count += 1
                logging.warning('undo[%s] failed: %s', verb, args)
    return {
        'reversed': reversed_count,
        'failed': failed_count,
        'manual': manual_count,
        'irreversible': irreversible_count,
        'total_plans': len(plans),
    }


def run(log_path: str, client: UndoClient, *,
         up_to_signature: Optional[str] = None,
         hard: bool = False, execute: bool = False) -> dict:
    """Top-level entry. Verifies chain, builds plans, optionally executes."""
    chain_ok, broken_line = verify_audit_log(log_path)
    if not chain_ok:
        logging.error('audit.log chain broken at line %s — refusing to undo.',
                      broken_line)
        return {'ok': False, 'reason': 'chain_broken',
                'broken_line': broken_line}

    plans = plan_undo(log_path, up_to_signature=up_to_signature, hard=hard)
    logging.info('undo: %d event(s) to reverse', len(plans))
    for p in plans:
        logging.info('  [%s] %s: %s',
                     p.kind, (p.event.get('subcommand') or ''), p.notes)

    if not execute:
        return {'ok': True, 'executed': False, 'plans': plans,
                 'count': len(plans)}

    summary = execute_plans(plans, client)
    return {'ok': True, 'executed': True, 'plans': plans,
             'summary': summary}
