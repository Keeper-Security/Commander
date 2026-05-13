"""Menu-driven migration wizard — runs per shell, coordinates via run-dir.

Flow (single shell, one invocation):

  1. Load or create the run spec in <run_dir>/migration.yaml
  2. Detect the current session's role (source | target | unknown) by
     comparing params against the spec's source/target entries
  3. Show what step is next for that role given what's already on disk
  4. Run the chosen step by invoking the existing subcommand class

The wizard NEVER authenticates on the admin's behalf — each shell must
already be logged in (via `keeper login`). The wizard reads `params`.

All prompts use menu.py primitives; tests drive them with injected
input/output functions so no TTY is required.
"""

import json
import logging
import os
from typing import Any, Dict, Optional

from .menu import (
    MenuCancelled,
    multi_toggle,
    prompt_choice,
    prompt_text,
    prompt_yes_no,
    single_select,
)
from .session import detect_session, detect_session_role, format_session_banner
from .tenant_profile import REGIONS, SCOPE_MODES, STAGES, TENANT_TYPES


def _yaml_or_json_dump(data):
    try:
        import yaml
        return yaml.safe_dump(data, sort_keys=True, default_flow_style=False)
    except ImportError:
        return json.dumps(data, indent=2, sort_keys=True)


def _yaml_or_json_load(text):
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except ImportError:
        return json.loads(text) if text.strip() else {}


def load_run_state(run_dir):
    """Return `<run_dir>/.run_state` as a dict, or {} when absent.

    `.run_state` is a small JSON file where the wizard stores the
    confirmed choices that must NOT be re-prompted across re-runs — IdP
    re-point confirmation, batch-cap override acknowledgement, etc. A
    missing or malformed file means "no state yet" (return empty dict).
    """
    path = os.path.join(run_dir, '.run_state')
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_run_state(run_dir, state):
    """Write `<run_dir>/.run_state` as 0600 JSON. Caller owns mkdir."""
    os.makedirs(run_dir, exist_ok=True)
    path = os.path.join(run_dir, '.run_state')
    with open(path, 'w') as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.chmod(path, 0o600)
    return path


def update_run_state(run_dir, updates):
    """Merge `updates` into the existing state and persist. Returns the
    full state dict after update."""
    state = load_run_state(run_dir)
    state.update(updates)
    save_run_state(run_dir, state)
    return state


def load_migration_yaml(run_dir):
    """Return the migration dict if present, empty dict otherwise."""
    path = os.path.join(run_dir, 'migration.yaml')
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return _yaml_or_json_load(f.read())


def save_migration_yaml(run_dir, spec):
    """Write migration spec. Creates run_dir if missing; 0600."""
    os.makedirs(run_dir, exist_ok=True)
    path = os.path.join(run_dir, 'migration.yaml')
    with open(path, 'w') as f:
        f.write(_yaml_or_json_dump(spec))
    os.chmod(path, 0o600)
    return path


# ─── Artifact-state helpers — what's already in the run-dir? ────────────────


def artifact_state(run_dir):
    """Return which migration artifacts are already present.

    Used by the wizard to propose the next step. Every key maps to True
    when the file exists and is non-empty.
    """
    if not os.path.isdir(run_dir):
        return {'inventory': False, 'target_state': False, 'manifest': False,
                'checks': False, 'reconcile': False}
    def _p(fn):
        fp = os.path.join(run_dir, fn)
        return os.path.exists(fp) and os.path.getsize(fp) > 0
    return {
        'inventory': _p('inventory.json'),
        'target_state': _p('target_state.json'),
        'manifest': _p('manifest.csv'),
        'checks': _p('checks.csv'),
        'reconcile': _p('reconciliation.md'),
    }


SOURCE_STEPS = ('plan', 'records-export', 'take-ownership')
TARGET_STEPS = ('structure', 'users', 'records-import', 'records-attachments',
                'records-shares', 'capture-target-state', 'verify', 'reconcile')


def next_steps_for(role, state, what_to_migrate):
    """Suggest ordered next steps. Drops steps whose artifacts already exist
    and steps the spec says we don't need."""
    suggestions = []
    if role == 'source':
        if 'structure' in what_to_migrate or not what_to_migrate:
            if not state['inventory']:
                suggestions.append('plan')
        if 'records' in what_to_migrate:
            suggestions.append('records-export')
        if 'structure' in what_to_migrate or 'records' in what_to_migrate:
            if state['inventory']:
                suggestions.append('take-ownership')
    elif role == 'target':
        if state['inventory']:
            if 'structure' in what_to_migrate or not what_to_migrate:
                suggestions.append('structure')
            if 'users' in what_to_migrate or not what_to_migrate:
                suggestions.append('users')
            if 'records' in what_to_migrate:
                suggestions.extend(['records-import', 'records-attachments',
                                     'records-shares'])
        # Always allow capture-target-state so verify/reconcile can run
        suggestions.append('capture-target-state')
        if state['target_state']:
            suggestions.append('verify')
            suggestions.append('reconcile')
    return suggestions


# ─── Wizard driver ───────────────────────────────────────────────────────────


class Wizard:
    """State machine: loads/creates migration.yaml, routes to next step.

    `input_fn` / `output_fn` are injectable for tests. When None, the
    default input()/print() is used.

    `auto_adjust` (default True) enables the AUTOMATED_ADJUSTMENT.md
    policy: remap inferred from spec, rate-limit knobs scaled from
    user count, sso_policy passed through. Set False to make every
    step run with explicit per-call kwargs only.
    """

    def __init__(self, params, run_dir, *,
                 input_fn=None, output_fn=None,
                 auto_adjust=True):
        self.params = params
        self.run_dir = run_dir
        self.input_fn = input_fn
        self.output_fn = output_fn or (lambda s: print(s, flush=True))
        self.auto_adjust = auto_adjust
        self.run_state = load_run_state(run_dir)

    # ── .run_state helpers ───────────────────────────────────────────────

    def state_get(self, key, default=None):
        return self.run_state.get(key, default)

    def state_set(self, key, value):
        """Merge a single key into the persisted run state."""
        self.run_state[key] = value
        update_run_state(self.run_dir, {key: value})

    def confirm_once(self, key, title, description=''):
        """Ask yes/no ONCE per run-dir — subsequent wizard invocations
        with the same key skip the prompt and return the prior answer.
        Returns True/False (None on cancel → treated as False for safety).

        `description` is printed above the prompt. Used for IdP re-point
        confirmation, batch-cap override, etc.
        """
        prior = self.state_get(key)
        if prior is not None:
            self.output_fn(f'  (skipping {title}: confirmed previously '
                           f'as {"yes" if prior else "no"})')
            return bool(prior)
        if description:
            self.output_fn('')
            self.output_fn(description)
        ans = prompt_yes_no(title, default_yes=False, **self._kw())
        answered = bool(ans)   # None → treat as rejected
        self.state_set(key, answered)
        return answered

    def _kw(self):
        return {'input_fn': self.input_fn, 'output_fn': self.output_fn}

    # Step 1 ---------------------------------------------------------------

    def banner(self):
        self.output_fn('')
        self.output_fn('╔══════════════════════════════════════════════════════════════╗')
        self.output_fn('║  Keeper Tenant Migration Wizard                             ║')
        self.output_fn('╚══════════════════════════════════════════════════════════════╝')
        ctx = detect_session(self.params)
        for line in format_session_banner(ctx).splitlines():
            self.output_fn(line)

    # Step 2 ---------------------------------------------------------------

    def load_or_create_spec(self):
        spec = load_migration_yaml(self.run_dir)
        if spec:
            self.output_fn(f'  run-spec found at {self.run_dir}/migration.yaml')
            return spec, False

        self.output_fn('')
        self.output_fn(f'  no run-spec at {self.run_dir}/migration.yaml')
        create = prompt_yes_no('Create a new run-spec?',
                                default_yes=True, **self._kw())
        if not create:
            return {}, False
        return self._interactive_create_spec(), True

    def _interactive_create_spec(self):
        """Walk the admin through the fields needed to describe both
        tenants + what to migrate. Returns a spec dict ready to save."""
        self.output_fn('')
        self.output_fn('  ── Source tenant ──')
        src_region = prompt_choice('Source region', list(REGIONS), **self._kw())
        src_type = prompt_choice('Source tenant type', list(TENANT_TYPES),
                                  default='enterprise', **self._kw())

        self.output_fn('')
        self.output_fn('  ── Target tenant ──')
        tgt_region = prompt_choice('Target region', list(REGIONS), **self._kw())
        tgt_type = prompt_choice('Target tenant type', list(TENANT_TYPES),
                                  default='enterprise', **self._kw())
        tgt_mc = ''
        if tgt_type == 'mc':
            tgt_mc = prompt_text('MC name or ID (passed to switch-to-mc)',
                                  **self._kw()) or ''

        self.output_fn('')
        stages = list(STAGES)
        sel = multi_toggle('What to migrate? (space to toggle, Enter to confirm)',
                            stages, preselected=[0, 1],   # structure + users by default
                            **self._kw())
        what_to_migrate = [stages[i] for i in (sel or [])]

        scope_mode = prompt_choice('Scope', list(SCOPE_MODES),
                                    default='full', **self._kw())
        scope_value = ''
        if scope_mode in ('node', 'prefix'):
            scope_value = prompt_text(
                'Node name' if scope_mode == 'node' else 'Title prefix',
                **self._kw()) or ''

        self.output_fn('')
        residency = prompt_choice(
            'Data residency pin (blocks cross-region moves)',
            ['none'] + list(REGIONS), default='none', **self._kw())
        if residency == 'none':
            residency = ''

        return {
            'run_dir': self.run_dir,
            'source': {'region': src_region or '', 'tenant_type': src_type or 'enterprise'},
            'target': {'region': tgt_region or '', 'tenant_type': tgt_type or 'enterprise',
                       'mc': tgt_mc},
            'what_to_migrate': what_to_migrate,
            'scope': {'mode': scope_mode or 'full', 'value': scope_value},
            'data_residency': residency,
            # Source-tenant write posture. Default read_only — destructive
            # ops on source (cleanup, decommission, take-ownership,
            # transfer-user) refuse to run until this is flipped to
            # 'destructive' AND --confirm-source-destructive is passed
            # AND --expected-tenant-name matches. See SECURITY_MODEL.md.
            'source_mode': 'read_only',
        }

    # Step 3 ---------------------------------------------------------------

    def run_compat_checks(self, role, state):
        """When role=target and both inventory + target_state exist, run
        the pre-flight compat checks and print verdicts. Returns the list
        of CompatCheck results (empty when not applicable)."""
        if role != 'target' or not state['inventory']:
            return []
        from . import compat_checks
        try:
            with open(os.path.join(self.run_dir, 'inventory.json')) as f:
                src_inv = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        tgt_state = {}
        if state['target_state']:
            try:
                with open(os.path.join(self.run_dir, 'target_state.json')) as f:
                    tgt_state = json.load(f)
            except (OSError, json.JSONDecodeError):
                tgt_state = {}
        checks = compat_checks.run_all(src_inv, tgt_state)
        self.output_fn('')
        self.output_fn('  ── Pre-flight compatibility checks ──')
        for c in checks:
            icon = {'ok': '✓', 'warn': '⚠', 'fail': '✗'}.get(c.verdict, '·')
            self.output_fn(f'    {icon} {c.name}: {c.message}')
            for d in c.details:
                self.output_fn(f'        {d}')
        return checks

    def propose_next_step(self, spec):
        role = detect_session_role(self.params, spec)
        state = artifact_state(self.run_dir)

        self.output_fn('')
        self.output_fn(f'  Detected role: {role}')
        self.output_fn(f'  Artifacts present: '
                       f'{", ".join(k for k, v in state.items() if v) or "(none)"}')
        # Loud banner if source-destructive ops are unlocked.
        src_mode = (spec or {}).get('source_mode') or 'read_only'
        if role == 'source':
            if src_mode == 'destructive':
                self.output_fn('  ⚠ source_mode=destructive — source writes ALLOWED')
            else:
                self.output_fn('  source_mode=read_only — source writes blocked')

        checks = self.run_compat_checks(role, state)
        if any(c.verdict == 'fail' for c in checks):
            self.output_fn('')
            self.output_fn('  Pre-flight FAIL — resolve blockers before proceeding.')
            go_on = prompt_yes_no('Continue anyway?',
                                   default_yes=False, **self._kw())
            if not go_on:
                return None

        suggestions = next_steps_for(role, state,
                                      spec.get('what_to_migrate') or [])
        if not suggestions:
            self.output_fn('  No next step available for this role. '
                           'Switch shells or run a subcommand directly.')
            return None

        self.output_fn('')
        idx = single_select('Next step', suggestions, **self._kw())
        if idx is None:
            return None
        return suggestions[idx]

    # Step 4 — run the chosen step ----------------------------------------

    def run_step(self, step_name, spec):
        """Invoke the underlying subcommand class. Caller owns the outcome."""
        from . import commands

        cmd_map = {
            'plan': commands.PlanCommand,
            'records-export': commands.RecordsExportCommand,
            'take-ownership': commands.TakeOwnershipCommand,
            'structure': commands.StructureCommand,
            'users': commands.UsersCommand,
            'records-import': commands.RecordsImportCommand,
            'records-attachments': commands.RecordsAttachmentsCommand,
            'records-shares': commands.RecordsSharesCommand,
            'capture-target-state': commands.CaptureTargetStateCommand,
            'verify': commands.VerifyCommand,
            'reconcile': commands.ReconcileCommand,
        }
        cls = cmd_map.get(step_name)
        if not cls:
            self.output_fn(f'  wizard cannot run {step_name!r} yet')
            return None

        kwargs = self._kwargs_for(step_name, spec)
        self._announce_auto_adjust(step_name, kwargs)
        dry = prompt_yes_no('Dry-run first? (recommended)',
                             default_yes=True, **self._kw())
        if dry:
            kwargs['dry_run'] = True
            kwargs['dry_run_report'] = os.path.join(
                self.run_dir, f'{step_name}.dry-run.md')
        self.output_fn(f'  running {step_name}' + (' (dry-run)' if dry else ''))
        return cls().execute(self.params, **kwargs)

    # ── Auto-adjustment helpers (AUTOMATED_ADJUSTMENT.md) ────────────────

    # Delay/batch tiers — single source of truth in estimate.py so the
    # wizard-suggested throttle matches the pre-flight estimate exactly.
    @property
    def _SCALE_TIERS(self):
        from .estimate import SCALE_TIERS
        # Drop the label — wizard only needs (upper, delay, batch).
        return tuple((upper, delay, batch) for upper, delay, batch, _ in SCALE_TIERS)

    def _infer_scale(self, spec):
        """Return (delay, batch_size) inferred from spec.counts.users.
        None count → (0.0, 0) — the caller keeps the subcommand's own
        default. Exposed for tests."""
        if not self.auto_adjust:
            return (0.0, 0)
        counts = (spec or {}).get('counts') or {}
        try:
            users = int(counts.get('users') or 0)
        except (TypeError, ValueError):
            users = 0
        if users <= 0:
            return (0.0, 0)
        for upper, delay, batch in self._SCALE_TIERS:
            if users <= upper:
                return (delay, batch)
        return (0.0, 0)

    def _infer_remap(self, spec):
        """Return (old_domain, new_domain) for this run. Returns ('','')
        when auto-adjust is off OR the spec doesn't pin a pair."""
        if not self.auto_adjust:
            return ('', '')
        from .email_remap import infer_domains_from_spec
        return infer_domains_from_spec(spec or {})

    def _infer_sso_policy(self, spec):
        return (spec or {}).get('sso_policy') or 'warn'

    def _kwargs_for(self, step_name, spec):
        """Map the spec's fields (+ auto-adjust policy) to the step's
        argparse kwargs."""
        scope = spec.get('scope') or {}
        scope_node = scope.get('value', '') if scope.get('mode') == 'node' else ''
        prefix = scope.get('value', '') if scope.get('mode') == 'prefix' else ''
        common = {'output': os.path.join(self.run_dir, 'inventory.json')}
        audit_log = os.path.join(self.run_dir, 'audit.log')
        old_domain, new_domain = self._infer_remap(spec)
        delay, batch_size = self._infer_scale(spec)
        sso_policy = self._infer_sso_policy(spec)

        if step_name == 'plan':
            return {
                'output': common['output'],
                'scope_node': scope_node,
                'prefix': prefix,
                'target_user': '', 'target_root': '',
                'include_fields': False, 'skip_hsf_scrape': False,
            }
        if step_name == 'capture-target-state':
            return {
                'output': os.path.join(self.run_dir, 'target_state.json'),
                'include_fields': False, 'prefix': prefix,
            }
        if step_name == 'structure':
            return {
                'inventory': os.path.join(self.run_dir, 'inventory.json'),
                'plan': None,
                'source_root': 'My company',
                'target_root': (spec.get('target') or {}).get('region') or '',
                'scope_node': scope_node,
                'steps': '0-12',
                'mc': (spec.get('target') or {}).get('mc', ''),
                'audit_log': audit_log,
            }
        if step_name == 'users':
            return {
                'inventory': os.path.join(self.run_dir, 'inventory.json'),
                'roster': os.path.join(self.run_dir, 'roster.csv'),
                'source_root': 'My company',
                'target_root': (spec.get('target') or {}).get('region') or '',
                'default_node': '',
                'mc': (spec.get('target') or {}).get('mc', ''),
                'old_domain': old_domain, 'new_domain': new_domain,
                'delay': delay, 'batch_size': batch_size,
                'sso_policy': sso_policy,
                'audit_log': audit_log,
            }
        if step_name == 'records-import':
            return {
                'input': os.path.join(self.run_dir, 'records-import.json'),
                'audit_log': audit_log,
            }
        if step_name == 'records-attachments':
            return {
                'manifest': os.path.join(self.run_dir, 'manifest.csv'),
                'staging_dir': os.path.join(self.run_dir, 'attachments'),
                'delay': delay, 'batch_size': batch_size,
                'audit_log': audit_log,
            }
        if step_name == 'records-shares':
            return {
                'manifest': os.path.join(self.run_dir, 'manifest.csv'),
                'skip_missing_users': False,
                'old_domain': old_domain, 'new_domain': new_domain,
                'delay': delay, 'batch_size': batch_size,
                'audit_log': audit_log,
            }
        if step_name == 'take-ownership':
            return {
                'verification_report': os.path.join(self.run_dir,
                                                      'verification.csv'),
                'backup_dir': os.path.join(self.run_dir, 'take_ownership_backups'),
                'report_output': os.path.join(self.run_dir, 'ownership_report.csv'),
                'old_domain': old_domain, 'new_domain': new_domain,
                'delay': max(delay, 0.5),       # keep the proven 0.5s floor
                'batch_size': batch_size,
            }
        if step_name == 'verify':
            return {
                'inventory': os.path.join(self.run_dir, 'inventory.json'),
                'target_state': os.path.join(self.run_dir, 'target_state.json'),
                'output': os.path.join(self.run_dir, 'checks.csv'),
                'audit_log': audit_log,
            }
        if step_name == 'reconcile':
            return {
                'inventory': os.path.join(self.run_dir, 'inventory.json'),
                'target_state': os.path.join(self.run_dir, 'target_state.json'),
                'output': os.path.join(self.run_dir, 'reconciliation.md'),
            }
        # Fallback — caller can override before execute
        return {}

    def _announce_auto_adjust(self, step_name, kwargs):
        """Print a short banner with the auto-chosen knobs so the operator
        can see them before confirming."""
        if not self.auto_adjust:
            return
        lines = []
        if kwargs.get('old_domain') and kwargs.get('new_domain'):
            lines.append(f'  Email remap: @{kwargs["old_domain"]} → '
                         f'@{kwargs["new_domain"]} (auto)')
        if kwargs.get('delay') or kwargs.get('batch_size'):
            lines.append(f'  Rate limit: --delay={kwargs.get("delay", 0)} '
                         f'--batch-size={kwargs.get("batch_size", 0)} (auto)')
        if step_name == 'users' and kwargs.get('sso_policy') and \
           kwargs['sso_policy'] != 'allow':
            lines.append(f'  SSO policy: {kwargs["sso_policy"]} (auto)')
        for line in lines:
            self.output_fn(line)

    # Driver --------------------------------------------------------------

    def run(self):
        try:
            self.banner()
            spec, created = self.load_or_create_spec()
            if created:
                save_migration_yaml(self.run_dir, spec)
                self.output_fn(f'  saved: {self.run_dir}/migration.yaml')
            if not spec:
                return None

            step = self.propose_next_step(spec)
            if not step:
                return None

            confirm = prompt_yes_no(f'Run {step}?', default_yes=False, **self._kw())
            if not confirm:
                return None

            return self.run_step(step, spec)
        except MenuCancelled:
            self.output_fn('  wizard cancelled')
            return None
