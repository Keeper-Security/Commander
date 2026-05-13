"""User creation + per-user node / team / role / alias / hsf placement.

Port of 03b_create_users_new_tenant.sh. Consumes:
  - roster: list of dicts with at least 'email', 'full_name' (+ optional
    'department', 'migration_folder_name')
  - inventory: full inventory dict (entities.users[]) for per-user details
  - transition_plan: list of rows from transition.categorize() (may be empty)

Plus a `UserClient` protocol covering every target-side write. A FakeClient
implementation mirrors the FakeClient in structure.py — tests never touch a
live tenant.
"""

import logging
import time

from .email_remap import remap_email
from .helpers.node_paths import leaf_of


CATEGORY_A = 'A'          # NEW — invite
CATEGORY_B = 'B'          # PERSONAL_ACCOUNT conflict (detected at invite time)
CATEGORY_C = 'C'          # OTHER_ENTERPRISE conflict (detected at invite time)
CATEGORY_D = 'D'          # ALREADY_IN_TARGET — skip invite
CATEGORY_E = 'E'          # PENDING_INVITE — extend consent
CATEGORY_UNKNOWN = 'UNKNOWN'

# Error-string fragments that, if seen in the invite stderr/stdout, reclassify
# the user into Category B or C (pre-invite we can't tell them apart).
PERSONAL_CONFLICT_MARKERS = ('already registered', 'personal keeper',
                             'consumer vault')
ENTERPRISE_CONFLICT_MARKERS = ('already enterprise', 'different company',
                               'another tenant')


def _contains_any(text, markers):
    t = (text or '').lower()
    return any(m in t for m in markers)


def detect_invite_conflict_category(invite_output):
    """Return 'B', 'C', or '' based on invite-command output."""
    if _contains_any(invite_output, PERSONAL_CONFLICT_MARKERS):
        return CATEGORY_B
    if _contains_any(invite_output, ENTERPRISE_CONFLICT_MARKERS):
        return CATEGORY_C
    return ''


def remap_user_node(src_node, source_root, target_root, default_node=''):
    """Return the --node leaf to use for a user, or default_node as fallback."""
    if not src_node:
        return default_node
    if src_node == source_root:
        return target_root or default_node
    leaf = leaf_of(src_node)
    if leaf in (source_root, target_root):
        return default_node
    return leaf or default_node


def _index_inventory_users(inventory):
    """Build {email_lower: inventory_user_dict} for quick lookup."""
    out = {}
    if not inventory:
        return out
    for u in inventory.get('entities', {}).get('users', []) or []:
        email = (u.get('email') or '').strip().lower()
        if email:
            out[email] = u
    return out


def _index_queued_team_membership(inventory):
    """Build {email_lower: [team_name, ...]} of queued memberships that
    need approval after the user accepts the tenant invite."""
    out = {}
    if not inventory:
        return out
    for t in inventory.get('entities', {}).get('teams', []) or []:
        team_name = (t.get('name') or '').strip()
        if not team_name:
            continue
        for qu in t.get('queued_users') or []:
            if isinstance(qu, dict):
                email = (qu.get('username') or qu.get('email') or '').strip()
            elif isinstance(qu, str):
                email = qu.strip()
            else:
                continue
            key = email.lower()
            if key:
                out.setdefault(key, []).append(team_name)
    return out


def _index_transition_plan(plan_rows):
    """Build {email_lower: transition_row}."""
    out = {}
    for row in plan_rows or []:
        email = (row.get('source_email') or '').strip().lower()
        if email:
            out[email] = row
    return out


class UserClient:
    """Protocol for all target-side writes performed during user creation."""

    def user_exists(self, email):
        raise NotImplementedError

    def invite_user(self, email, full_name, node, job_title=''):
        """Return (success: bool, output: str). `output` is parsed for B/C conflict markers."""
        raise NotImplementedError

    def extend_user_invite(self, email):
        raise NotImplementedError

    def set_user_job_title(self, email, job_title):
        raise NotImplementedError

    def add_user_alias(self, email, alias_email):
        raise NotImplementedError

    def add_user_team(self, email, team_name, hsf_on=False):
        raise NotImplementedError

    def add_user_role(self, email, role_name):
        raise NotImplementedError

    def approve_team_queue_user(self, email, team_name):
        """Approve a previously-queued user onto the team (Commander
        queues team adds that happen before the user's tenant invite
        is accepted). Returns True on success."""
        raise NotImplementedError

    def list_team_names(self):
        """Return the set of team names present on target. Used by
        UserRunner to gate add_user_team calls against teams that
        weren't created (preceding `structure` stage failed silently
        or was skipped)."""
        raise NotImplementedError

    def list_role_names(self):
        """Mirror of list_team_names, for the role-add gate."""
        raise NotImplementedError


class FakeUserClient(UserClient):
    def __init__(self, existing_users=(), invite_behavior=None,
                 fail_on=None, existing_teams=(), existing_roles=()):
        """
        existing_users: set/iterable of lowercase emails already on target.
        invite_behavior: callable(email) -> (success, output) to customize invite.
        fail_on: set of operation names that should fail (return False).
        existing_teams / existing_roles: iterables of names already on
            target — feed the gate. Empty (default) leaves the gate OFF.
        """
        self.existing = {e.lower() for e in existing_users}
        self._invite_behavior = invite_behavior
        self.fail_on = fail_on or set()
        self.existing_teams = set(existing_teams)
        self.existing_roles = set(existing_roles)
        self.calls = []

    def _record(self, op, args):
        self.calls.append((op, args))
        return op not in self.fail_on

    def user_exists(self, email):
        self.calls.append(('user_exists', (email,)))
        return email.lower() in self.existing

    def invite_user(self, email, full_name, node, job_title=''):
        self.calls.append(('invite_user', (email, full_name, node, job_title)))
        if self._invite_behavior:
            return self._invite_behavior(email)
        return ('invite_user' not in self.fail_on), 'ok'

    def extend_user_invite(self, email):
        return self._record('extend_user_invite', (email,))

    def set_user_job_title(self, email, job_title):
        return self._record('set_user_job_title', (email, job_title))

    def add_user_alias(self, email, alias_email):
        return self._record('add_user_alias', (email, alias_email))

    def add_user_team(self, email, team_name, hsf_on=False):
        return self._record('add_user_team', (email, team_name, hsf_on))

    def add_user_role(self, email, role_name):
        return self._record('add_user_role', (email, role_name))

    def approve_team_queue_user(self, email, team_name):
        return self._record('approve_team_queue_user', (email, team_name))

    def list_team_names(self):
        return set(self.existing_teams)

    def list_role_names(self):
        return set(self.existing_roles)


class UserCreationResult:
    __slots__ = ('email', 'status', 'category', 'notes', 'assignments')

    def __init__(self, email, status, category, notes='', assignments=None):
        self.email = email
        self.status = status              # YES | EXISTS | EXTENDED | CONFLICT_B/C | BLOCKED | FAILED
        self.category = category          # A/B/C/D/E/UNKNOWN
        self.notes = notes
        self.assignments = assignments or {'teams': [], 'roles': [], 'aliases': [],
                                           'job_title': False, 'team_queue_approved': []}
        # Backfill for older callers that don't pre-populate the new key
        self.assignments.setdefault('team_queue_approved', [])

    def is_placeable(self):
        return self.status in ('YES', 'EXISTS', 'EXTENDED')


class UserRunner:
    """Create/invite users and apply their per-user placement settings."""

    def __init__(self, client, *, source_root='My company', target_root='Root',
                 default_node='', old_domain='', new_domain='',
                 delay=0.0, batch_size=0, sleeper=time.sleep,
                 sso_policy='warn',
                 checkpoint=None, resume=False, force_restart=False):
        from .backoff import Retry
        self.client = client
        self.source_root = source_root
        self.target_root = target_root
        self.default_node = default_node or target_root
        self.old_domain = old_domain
        self.new_domain = new_domain
        self.delay = max(0.0, float(delay or 0))
        self.batch_size = max(0, int(batch_size or 0))
        self.sleeper = sleeper
        if sso_policy not in ('allow', 'warn', 'skip'):
            raise ValueError(
                f'sso_policy must be allow|warn|skip, got {sso_policy!r}')
        self.sso_policy = sso_policy
        # One retry per user on transient errors; a second hit escalates
        # to SafeguardBlocked so the runner aborts instead of hammering
        # a rate-limited tenant.
        self._retry = Retry(delay=self.delay, sleeper=sleeper)
        # Optional resumable-loop checkpoint. None → no-op (legacy behavior).
        self.checkpoint = checkpoint
        self.resume = resume
        self.force_restart = force_restart
        # Lazy cache for the team/role precondition gate. Populated on
        # first need (one list call each) and re-used for the rest of
        # the run. Mirrors the created_*/gate_active idiom in
        # StructureRestore (see .context/dependency-gates.md). When the
        # client doesn't implement list_*_names (e.g. legacy fakes),
        # the gate is silently disabled — no behavior regression.
        self._target_teams = None
        self._target_roles = None

    def _remap(self, email):
        return remap_email(email, self.old_domain, self.new_domain)

    def _team_present(self, team_name):
        """Lazy-load + check target's team set. Returns True when the
        team exists OR the client doesn't implement list_team_names
        (gate disabled). Rename caveat: source-side `users.teams`
        references the original team name; if `dedupe_team_names`
        renamed the team during structure-stage create, this returns
        False — same as today's call would also fail."""
        if self._target_teams is None:
            try:
                self._target_teams = self.client.list_team_names() or set()
            except (NotImplementedError, AttributeError):
                self._target_teams = set()
                return True  # gate stays off when client lacks the method
        if not self._target_teams:
            return True       # empty set → backwards-compat (gate off)
        return team_name in self._target_teams

    def _role_present(self, role_name):
        """Mirror of _team_present for the role-add gate."""
        if self._target_roles is None:
            try:
                self._target_roles = self.client.list_role_names() or set()
            except (NotImplementedError, AttributeError):
                self._target_roles = set()
                return True
        if not self._target_roles:
            return True
        return role_name in self._target_roles

    def _decide_category(self, plan_row):
        if plan_row:
            return plan_row.get('category', '')
        return ''

    def _create_or_extend(self, email, full_name, node, job_title, category):
        """Perform the A/B/C/D/E/UNKNOWN handling and return a UserCreationResult."""
        if category == CATEGORY_D:
            return UserCreationResult(email, 'EXISTS', CATEGORY_D,
                                      notes='Transition plan: already in target')

        if category == CATEGORY_E:
            ok = self.client.extend_user_invite(email)
            if ok:
                return UserCreationResult(email, 'EXTENDED', CATEGORY_E,
                                          notes='Pending invite — extended')
            return UserCreationResult(email, 'FAILED', CATEGORY_E,
                                      notes='E extend failed — manual investigation')

        if category == CATEGORY_UNKNOWN:
            return UserCreationResult(email, 'BLOCKED', CATEGORY_UNKNOWN,
                                      notes='Transition plan UNKNOWN — manual resolution required')

        # Category A (or empty/missing) — default invite flow
        if self.client.user_exists(email):
            return UserCreationResult(email, 'EXISTS', CATEGORY_D,
                                      notes='User already exists on target')

        ok, out = self.client.invite_user(email, full_name, node, job_title)
        if ok:
            return UserCreationResult(email, 'YES', CATEGORY_A,
                                      notes='User invited')
        conflict = detect_invite_conflict_category(out)
        if conflict == CATEGORY_B:
            return UserCreationResult(email, 'CONFLICT_B', CATEGORY_B,
                                      notes='Personal Keeper account conflict')
        if conflict == CATEGORY_C:
            return UserCreationResult(email, 'CONFLICT_C', CATEGORY_C,
                                      notes='User in another enterprise')
        return UserCreationResult(email, 'FAILED', CATEGORY_A,
                                  notes='Invite failed')

    def _apply_placement(self, result, source_user):
        """Apply job_title, aliases, teams (+hsf), roles to a placeable user."""
        if not result.is_placeable() or not source_user:
            return

        job_title = source_user.get('job_title', '').strip()
        if result.status == 'EXISTS' and job_title:
            if self.client.set_user_job_title(result.email, job_title):
                result.assignments['job_title'] = True

        for alias in source_user.get('aliases') or []:
            a = (alias or '').strip()
            remapped = self._remap(a)
            if remapped and self.client.add_user_alias(result.email, remapped):
                result.assignments['aliases'].append(remapped)

        hsf_teams = set(source_user.get('hide_shared_folders_teams') or [])
        for team in source_user.get('teams') or []:
            t = (team or '').strip()
            if not t:
                continue
            if not self._team_present(t):
                result.assignments.setdefault('teams_skipped', []).append(t)
                continue
            ok = self.client.add_user_team(result.email, t, hsf_on=(t in hsf_teams))
            if ok:
                result.assignments['teams'].append(t)

        for role in source_user.get('roles') or []:
            r = (role or '').strip()
            if not r:
                continue
            if not self._role_present(r):
                result.assignments.setdefault('roles_skipped', []).append(r)
                continue
            if self.client.add_user_role(result.email, r):
                result.assignments['roles'].append(r)

    def run(self, roster, inventory=None, transition_plan=None):
        """Main entry. Returns list[UserCreationResult]."""
        inv_index = _index_inventory_users(inventory)
        plan_index = _index_transition_plan(transition_plan)
        queued_index = _index_queued_team_membership(inventory)

        roster = list(roster)
        input_sha = None
        start = 1
        if self.checkpoint is not None:
            from .checkpoint import hash_rows
            keyed = [(r.get('email') or '').strip().lower() for r in roster]
            input_sha = hash_rows(keyed)
            start = self.checkpoint.resume_from(
                keyed, resume=self.resume, force_restart=self.force_restart,
            )
            if start > 1:
                logging.info('users: resuming at row %d/%d (checkpoint present)',
                             start, len(roster))

        results = []
        # Pre-populate a placeholder for each resumed-over row so the caller
        # can still line up roster rows with result indices.
        for _ in range(start - 1):
            results.append(UserCreationResult(
                '', 'RESUMED', CATEGORY_UNKNOWN,
                notes='skipped by checkpoint (prior run)',
            ))

        processed = 0
        for idx, entry in enumerate(roster, start=1):
            if idx < start:
                continue
            email_src = (entry.get('email') or '').strip()
            if not email_src:
                continue
            # Roster emails key into inventory/plan under the SOURCE domain.
            # Lookup first, then remap for the invite call.
            src_lower = email_src.lower()
            src = inv_index.get(src_lower, {})
            plan_row = plan_index.get(src_lower, {})

            # SSO-provisioned users can't be manually invited — the IdP
            # must re-provision them on the new tenant via SCIM. Flag or
            # skip per policy.
            is_sso = bool(src.get('is_sso') or src.get('sso_service_provider_id'))

            email = self._remap(email_src)
            full_name = (entry.get('full_name') or '').strip()

            if is_sso and self.sso_policy == 'skip':
                result = UserCreationResult(
                    email, 'BLOCKED', CATEGORY_UNKNOWN,
                    notes='SSO-provisioned — re-provision via IdP SCIM, '
                          'not manual invite')
                results.append(result)
                continue

            if is_sso and self.sso_policy == 'warn':
                logging.warning(
                    'SSO-provisioned user %s — invite will proceed but IdP '
                    'must re-target SAML/SCIM to new tenant', email)

            node = remap_user_node(
                src.get('node', ''), self.source_root, self.target_root,
                default_node=self.default_node,
            )
            job_title = src.get('job_title', '').strip()
            category = self._decide_category(plan_row)

            # Each user is an independent unit. The invite step itself
            # is NOT idempotent (sends an email every time Commander
            # reaches the endpoint) — retrying a throttled invite could
            # produce a second invite email. Placement / team / role
            # assignments ARE idempotent. We split the two phases:
            #   1. _create_or_extend — idempotent=False (no auto-retry)
            #   2. _apply_placement + approve_team_queue_user — normal retry
            try:
                result = self._retry.call(
                    lambda: self._create_or_extend(
                        email, full_name, node, job_title, category),
                    op_label=f'user-invite:{email}',
                    idempotent=False,
                )
            except BaseException:                          # noqa: BLE001
                # A transient that exhausted the (zero) retry budget lands
                # here as SafeguardBlocked; anything else is a real bug.
                # Re-raise to abort the whole run rather than silently skip.
                raise
            if is_sso:
                result.notes = (result.notes + ' | SSO-provisioned').strip(' |')
            self._retry.call(
                lambda: self._apply_placement(result, src),
                op_label=f'user-placement:{email}',
            )
            # Approve queued team memberships when the invite just
            # succeeded. SOURCE email is the queue key; REMAPPED email
            # is what the target recognizes.
            if result.is_placeable():
                for team_name in queued_index.get(src_lower, []):
                    if self._retry.call(
                            lambda tn=team_name: self.client.approve_team_queue_user(
                                result.email, tn),
                            op_label=f'team-approve:{team_name}'):
                        result.assignments['team_queue_approved'].append(team_name)

            results.append(result)
            logging.info('User %s → status=%s category=%s',
                         email, result.status, result.category)

            if self.checkpoint is not None and input_sha:
                self.checkpoint.mark_done(idx, input_sha256=input_sha)

            processed += 1
            if self.delay and self.sleeper:
                self.sleeper(self.delay)
            if (self.batch_size and processed % self.batch_size == 0
                    and self.sleeper):
                logging.info('Batch checkpoint: %d users processed — '
                             'sync-down pause', processed)
                self.sleeper(max(self.delay * 2, 1.0))

        if self.checkpoint is not None:
            self.checkpoint.clear()
        return results
