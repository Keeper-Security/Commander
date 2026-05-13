"""Shared-folder membership reconciliation — the drip-feed after
user activation.

When `users` (invite) runs, most target users sit in `pending_invite`
for days/weeks until they accept. Their cryptographic key doesn't
exist yet, so `structure`'s SF-membership step silently skips them —
pending users can't be SF members in Keeper's model. When they finally
accept and their key materializes, nothing goes back to wire them up.

`shared-folders-reconcile` closes that loop. On each run it sweeps
the delta between *expected* (source inventory) and *actual* (live
target) SF memberships, applies the ones now possible (user has
become active), and reports on what's still pending. Idempotent and
cron-able — running against a fully-settled target is a no-op.

Add-only by design. A permission that disappeared from source after
the inventory was captured is NOT honored — the tool is driven by the
frozen snapshot, not a diff. Removal would require a `--prune` opt-in
(not yet implemented).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Optional

from .email_remap import remap_email


# ── Client protocol ─────────────────────────────────────────────────

class SFReconcileClient:
    """Every operation the reconciler performs against the target."""

    def list_sf_memberships(self) -> dict:
        """Return {sf_name: set(email_lowercase)} for every SF on target."""
        raise NotImplementedError

    def list_user_statuses(self) -> dict:
        """Return {email_lowercase: status_string}. Status values include
        'active' (key available, can be SF member), 'pending' /
        'invited' (no key yet), 'locked', 'expired', 'unknown'."""
        raise NotImplementedError

    def add_user_to_sf(self, sf_name: str, email: str) -> str:
        """Grant membership. Return code:
        'OK'              — added
        'ALREADY_MEMBER'  — already in SF (idempotent, treat as OK)
        'SF_NOT_FOUND'    — SF doesn't exist on target
        'USER_NOT_FOUND'  — no such user (pending or typo)
        'FAIL'            — unexpected
        """
        raise NotImplementedError

    def remove_user_from_sf(self, sf_name: str, email: str) -> str:
        """Optional — only used when the caller opts into --prune.
        Return code:
        'OK'              — removed
        'NOT_MEMBER'      — already not in SF (idempotent, treat as OK)
        'SF_NOT_FOUND'    — SF doesn't exist
        'FAIL'            — unexpected

        Default returns 'FAIL' so clients that don't support prune can
        opt out without accidentally permitting removals."""
        return 'FAIL'


class FakeSFReconcileClient(SFReconcileClient):
    def __init__(self, *, memberships=None, statuses=None, behavior=None,
                 remove_behavior=None):
        """
        memberships : dict[sf_name] -> set(email)
        statuses    : dict[email]   -> status string
        behavior    : callable(sf_name, email) -> result code (default OK,
                      also mutates the memberships dict on success)
        remove_behavior : callable(sf_name, email) -> code for removals.
                          Default: OK + mutate (remove from memberships).
        """
        self._memberships = {k: set(v) for k, v in (memberships or {}).items()}
        self._statuses = {k.lower(): v for k, v in (statuses or {}).items()}
        self._behavior = behavior
        self._remove_behavior = remove_behavior
        self.calls = []

    def list_sf_memberships(self):
        return {k: set(v) for k, v in self._memberships.items()}

    def list_user_statuses(self):
        return dict(self._statuses)

    def add_user_to_sf(self, sf_name, email):
        self.calls.append(('add', sf_name, email))
        if self._behavior:
            code = self._behavior(sf_name, email)
        else:
            code = 'OK'
        if code == 'OK':
            self._memberships.setdefault(sf_name, set()).add(email.lower())
        return code

    def remove_user_from_sf(self, sf_name, email):
        self.calls.append(('remove', sf_name, email))
        if self._remove_behavior:
            code = self._remove_behavior(sf_name, email)
        else:
            code = 'OK'
        if code == 'OK':
            self._memberships.setdefault(sf_name, set()).discard(email.lower())
        return code


# ── Planning ────────────────────────────────────────────────────────

@dataclass
class ReconcileItem:
    email: str
    sf_name: str
    reason: str = ''


@dataclass
class ReconcilePlan:
    to_apply: list[ReconcileItem] = field(default_factory=list)
    pending: list[ReconcileItem] = field(default_factory=list)
    errors: list[ReconcileItem] = field(default_factory=list)
    # Memberships present on target but NOT in source inventory.
    # Only populated when plan_reconciliation is called with prune=True.
    # Reconciler removes these only when its prune flag is also True.
    to_prune: list[ReconcileItem] = field(default_factory=list)
    user_counts: dict = field(default_factory=dict)


def _inventory_shared_folders(inventory: Mapping) -> list:
    """Read shared_folders from either layout.

    Real `plan`-produced inventory nests under `entities`:
      {entities: {shared_folders: [...]}}
    Test fixtures + legacy compat tests use the top-level shape:
      {shared_folders: [...]}
    Accept both; prefer entities.* when present (authoritative).
    """
    entities = inventory.get('entities')
    if isinstance(entities, dict) and entities.get('shared_folders'):
        return entities.get('shared_folders') or []
    return inventory.get('shared_folders') or []


def _expected_memberships(inventory: Mapping, *,
                          old_domain: str, new_domain: str
                          ) -> dict[str, set[str]]:
    """Return {sf_name: set(email_lowercase_remapped)} from source inventory.
    Each row in an SF's `users` / `members` list carries the source email;
    optional domain remap reflects what it becomes on target.

    Rejects entries that don't look like emails (no '@') — defensive
    against malformed inventories that an attacker or broken tooling
    might feed in. Valid-but-unknown emails are still forwarded; only
    obviously-wrong strings are filtered.
    """
    out: dict[str, set[str]] = {}
    for sf in _inventory_shared_folders(inventory):
        if not isinstance(sf, dict):
            continue
        name = (sf.get('name') or '').strip()
        if not name:
            continue
        members = sf.get('users') or sf.get('members') or []
        for m in members:
            if isinstance(m, str):
                email = m
            elif isinstance(m, dict):
                email = m.get('username') or m.get('email') or ''
            else:
                continue
            email = (email or '').strip().lower()
            if not email or '@' not in email:
                continue
            out.setdefault(name, set()).add(
                remap_email(email, old_domain, new_domain).lower()
            )
    return out


def plan_reconciliation(inventory: Mapping,
                        client: SFReconcileClient,
                        *,
                        old_domain: str = '',
                        new_domain: str = '',
                        prune: bool = False,
                        ) -> ReconcilePlan:
    """Classify every (user, sf) pair the inventory expects but target lacks.

    Categories:
      - apply        : user is active on target AND SF exists → can add now
      - skip-pending : user not yet active → wait for next run
      - error        : SF doesn't exist on target (nothing to add into)
      - to_prune     : (prune=True only) user on target but NOT in the
                       source inventory — the explicit removal list

    prune: OFF by default. When True, populates to_prune with
    memberships that exist on target but are absent from the source
    inventory for that SF. The caller (Reconciler) removes them only
    when its prune flag is also True. Decoupling plan from apply lets
    a dry-run preview what prune would remove before committing.
    """
    expected = _expected_memberships(inventory,
                                     old_domain=old_domain,
                                     new_domain=new_domain)
    actual = client.list_sf_memberships()
    statuses = client.list_user_statuses()

    active_total = sum(1 for s in statuses.values()
                       if (s or '').lower() == 'active')
    pending_total = sum(1 for s in statuses.values()
                        if (s or '').lower() in ('pending', 'invited'))

    plan = ReconcilePlan()
    plan.user_counts = {
        'active': active_total,
        'pending_or_invited': pending_total,
        'target_total': len(statuses),
    }

    for sf_name, expected_members in sorted(expected.items()):
        if sf_name not in actual:
            # SF missing on target — every expected member is an error.
            for email in sorted(expected_members):
                plan.errors.append(ReconcileItem(
                    email=email, sf_name=sf_name,
                    reason=f'shared folder not found on target: {sf_name!r}',
                ))
            continue

        already = actual[sf_name]
        for email in sorted(expected_members):
            if email in already:
                continue   # already a member — nothing to do
            status = (statuses.get(email) or '').lower()
            if status == 'active':
                plan.to_apply.append(ReconcileItem(
                    email=email, sf_name=sf_name,
                ))
            else:
                plan.pending.append(ReconcileItem(
                    email=email, sf_name=sf_name,
                    reason=f'user status: {status or "unknown"}',
                ))

    # Prune analysis — only when caller explicitly asked. Walk SFs that
    # appear in BOTH inventory and target; for each, list memberships
    # on target that aren't in the inventory for that SF.
    #
    # Scoped intentionally: only SFs present in the source inventory
    # are considered for pruning. An SF that exists on target but not
    # in the inventory is outside the migration's scope and its
    # memberships must not be touched.
    if prune:
        for sf_name, expected_members in sorted(expected.items()):
            if sf_name not in actual:
                continue
            target_members = actual[sf_name]
            extras = target_members - expected_members
            for email in sorted(extras):
                plan.to_prune.append(ReconcileItem(
                    email=email, sf_name=sf_name,
                    reason='on target but absent from source inventory',
                ))

    return plan


# ── Execution ───────────────────────────────────────────────────────

class SFReconciler:
    def __init__(self, client: SFReconcileClient, *,
                 delay: float = 0.0, batch_size: int = 0,
                 sleeper=time.sleep,
                 checkpoint=None, resume=False, force_restart=False,
                 prune: bool = False):
        from .backoff import Retry
        self.client = client
        self.delay = max(0.0, float(delay or 0))
        self.batch_size = max(0, int(batch_size or 0))
        self.sleeper = sleeper
        self._retry = Retry(delay=self.delay, sleeper=sleeper)
        self.checkpoint = checkpoint
        self.resume = resume
        self.force_restart = force_restart
        # Destructive removal of target memberships absent from source
        # inventory. OFF by default — reconcile is add-only by spec.
        self.prune = prune

    def run(self, plan: ReconcilePlan) -> dict:
        to_apply = list(plan.to_apply)
        input_sha = None
        start = 1
        if self.checkpoint is not None:
            from .checkpoint import hash_rows
            # Hash only the apply list — pending items are environmental
            # (depend on activation state, not planned work).
            keyed = [(i.sf_name, i.email) for i in to_apply]
            input_sha = hash_rows(keyed)
            start = self.checkpoint.resume_from(
                keyed, resume=self.resume, force_restart=self.force_restart,
            )

        applied: list[ReconcileItem] = []
        errors: list[ReconcileItem] = []
        resumed = 0

        for i, item in enumerate(to_apply, start=1):
            if i < start:
                resumed += 1
                continue
            code = self._retry.call(
                lambda it=item: self.client.add_user_to_sf(it.sf_name, it.email),
                op_label=f'sf-reconcile:{item.sf_name}→{item.email}',
            )
            if code in ('OK', 'ALREADY_MEMBER'):
                applied.append(item)
                # HIGH-4 fix 2026-05-08: only advance the checkpoint
                # for SUCCESSFUL rows. Pre-fix mark_done(i) ran
                # unconditionally after both success AND failure
                # branches, so errored rows were persistently
                # skipped on --resume. Operator's only escape was
                # --force-restart, which then re-applied every OK
                # row from scratch — wasted work + throttle budget.
                # Now: failed rows stay un-checkpointed so --resume
                # picks them up; OK rows advance.
                if self.checkpoint is not None and input_sha:
                    self.checkpoint.mark_done(i, input_sha256=input_sha)
            else:
                errors.append(ReconcileItem(
                    email=item.email, sf_name=item.sf_name,
                    reason=code,
                ))
                # HIGH-4: do NOT mark_done on failure. The row stays
                # active in the checkpoint so --resume retries it.
            if self.delay and self.sleeper:
                self.sleeper(self.delay)
            if (self.batch_size and i % self.batch_size == 0
                    and self.sleeper):
                logging.info('Reconcile batch: %d processed — pause', i)
                self.sleeper(max(self.delay * 2, 1.0))

        # --prune: remove target memberships that the inventory doesn't
        # list. Opt-in on both the plan AND the reconciler. A planner
        # that called plan_reconciliation(prune=True) may still pass
        # the plan to a non-prune reconciler — the to_prune list is
        # only consumed when self.prune is True.
        pruned: list[ReconcileItem] = []
        prune_errors: list[ReconcileItem] = []
        if self.prune:
            for item in plan.to_prune:
                code = self._retry.call(
                    lambda it=item: self.client.remove_user_from_sf(
                        it.sf_name, it.email,
                    ),
                    op_label=f'sf-reconcile-prune:{item.sf_name}→{item.email}',
                )
                if code in ('OK', 'NOT_MEMBER'):
                    pruned.append(item)
                else:
                    prune_errors.append(ReconcileItem(
                        email=item.email, sf_name=item.sf_name,
                        reason=f'prune failed: {code}',
                    ))
                if self.delay and self.sleeper:
                    self.sleeper(self.delay)

        if self.checkpoint is not None:
            self.checkpoint.clear()

        return {
            'applied': applied,
            'pending': plan.pending,          # pass through untouched
            'errors': plan.errors + errors + prune_errors,
            'resumed': resumed,
            'pruned': pruned,
            'user_counts': plan.user_counts,
            'total_planned_apply': len(to_apply),
            'total_planned_prune': len(plan.to_prune),
        }


# ── Rendering ───────────────────────────────────────────────────────

def render_report(plan: ReconcilePlan, run: Optional[dict] = None) -> str:
    lines = ['## Shared-folder reconciliation\n']

    uc = plan.user_counts or (run or {}).get('user_counts') or {}
    active = uc.get('active', 0)
    pending = uc.get('pending_or_invited', 0)
    total = uc.get('target_total', 0)
    pct = (100 * active / total) if total else 0
    lines.append('### Activation progress')
    lines.append(
        f'- {active} / {total} target users active ({pct:.0f}%), '
        f'{pending} pending'
    )
    lines.append('')

    if run is not None:
        applied = run.get('applied', [])
        errs = run.get('errors', [])
        resumed = run.get('resumed', 0)
        lines.append(f'### Applied this run ({len(applied)})')
        if not applied:
            lines.append('- (nothing to apply — all expected memberships '
                         'already in place for active users)')
        else:
            for it in applied:
                lines.append(f'- {it.email}   → {it.sf_name}')
        if resumed:
            lines.append(f'- (skipped {resumed} items from prior checkpoint)')
        lines.append('')

        if errs:
            lines.append(f'### Errors ({len(errs)})')
            for it in errs:
                lines.append(f'- {it.email}   → {it.sf_name} — {it.reason}')
            lines.append('')
    else:
        lines.append(f'### Would apply ({len(plan.to_apply)})')
        for it in plan.to_apply:
            lines.append(f'- {it.email}   → {it.sf_name}')
        lines.append('')

    pend = plan.pending if run is None else run.get('pending') or plan.pending
    if pend:
        # Group by user so the "still-pending" list reads per-person.
        by_user: dict[str, list[str]] = {}
        for it in pend:
            by_user.setdefault(it.email, []).append(it.sf_name)
        lines.append(f'### Still pending (user not yet active) — {len(by_user)}')
        for email, sfs in sorted(by_user.items()):
            lines.append(f'- {email}   → expected in {len(sfs)} SF(s): '
                         f'{", ".join(sorted(sfs))}')
        lines.append('')

    return '\n'.join(lines)


def load_inventory(path: str) -> dict:
    import json
    with open(path) as f:
        return json.load(f)
