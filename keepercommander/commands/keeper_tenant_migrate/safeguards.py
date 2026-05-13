"""Safeguards for destructive operations.

Three defensive checks that sit between the user's `--confirm YES` and
the actual destructive call:

  1. expect_tenant(params, expected_name)
     Confirms params.enterprise['enterprise_name'] matches what the user
     typed in `--expected-tenant-name`. Prevents running `decommission`
     against the wrong tenant when an admin has multiple sessions.

  2. enforce_batch_cap(count, cap, override_flag)
     Refuses to proceed when a mutating call would touch more than `cap`
     rows unless the override flag was explicitly set. Defends against
     a bad manifest / roster that accidentally targets thousands.

  3. production_tenant_warning(name)
     Heuristic: if the tenant name contains none of the sandbox
     keywords (test/demo/sandbox/staging/migtest/mc-), surface a WARN
     log line. Doesn't block — advisory only.

All three are composable: call them in order, short-circuit if any
raises `SafeguardBlocked`. Tested with synthetic params + without any
Commander dependency.
"""

import logging


class DestructiveCommandMisconfigured(Exception):
    """Raised at class definition time when a Command that writes
    destructively fails to declare itself as such. Caught by the unit
    test registry; also fires at import if the subclass forgets to set
    `SUBCOMMAND`.
    """


class SafeguardBlocked(Exception):
    """Raised when a destructive op is refused by a safeguard check."""


SANDBOX_KEYWORDS = ('test', 'demo', 'sandbox', 'staging', 'migtest',
                    'keeperdemo', 'dev', 'qa')


SOURCE_MODE_READ_ONLY = 'read_only'
SOURCE_MODE_DESTRUCTIVE = 'destructive'
SOURCE_MODES = (SOURCE_MODE_READ_ONLY, SOURCE_MODE_DESTRUCTIVE)


def enforce_source_mode(params, run_spec, *, confirm_flag=False,
                         expected_tenant_name='',
                         subcommand=''):
    """Four-layer interlock that refuses source-tenant writes unless
    every guard is deliberately satisfied.

    Fires ONLY when the current session matches the run-spec's SOURCE
    tenant. If the session is the target (or we can't tell), this is a
    no-op — destructive ops on target are governed by the existing
    per-command safeguards (expect_tenant, batch_cap, production warn,
    confirm_interactive).

    The four layers, all checked in order:

      1. `run_spec['source_mode'] == 'destructive'`
         Default in migration.yaml is 'read_only'. Flipping this is a
         deliberate file edit.
      2. `confirm_flag` is True
         Every source-destructive subcommand takes
         --confirm-source-destructive; wizard threads it explicitly.
      3. `expected_tenant_name` non-empty and matches the session
         The tenant-name safeguard is MANDATORY for source-destructive
         ops (normally optional).
      4. `expected_tenant_name` also matches `spec.source.enterprise_name`
         if that's set in the spec — prevents "I typed the name right
         but pointed at the wrong spec" class of mistake.

    Raises SafeguardBlocked when any layer fails. Returns True when the
    op is authorized. Emits a dedicated audit event `source_mode_authorized`
    via the caller (append_audit_event(... subcommand='source_mode_authorized'))
    — this function doesn't touch audit.log directly so callers control
    ordering.
    """
    from .session import detect_session_role

    role = detect_session_role(params, run_spec or {})
    if role == 'target':
        # Target-side: this interlock doesn't apply. Target writes are
        # governed by per-command safeguards (expect_tenant, batch_cap,
        # production_tenant_warning, confirm_interactive).
        return True
    if role == 'unknown':
        # Session matches BOTH source and target in the run-spec, OR
        # neither — we cannot safely classify. For destructive contexts
        # (signaled by a non-empty `subcommand` — the destructive
        # wrappers in commands.py always pass it), fail CLOSED. The
        # operator must tighten the spec (source.enterprise_name /
        # target.enterprise_name / .user) before re-running. For
        # non-destructive callers (empty subcommand: tests, scope
        # probes, etc.) preserve the historical no-op behavior.
        #
        # Rationale: 'unknown' was previously a silent pass-through —
        # safeguards.py:86-88 short-circuited with `if role != 'source':
        # return True`. That fails OPEN exactly when the operator's
        # spec is ambiguous about which tenant they are talking to,
        # which is the wrong direction for an interlock around
        # destructive writes. SEC-1 fix 2026-05-08.
        if subcommand:
            raise SafeguardBlocked(
                f'session-role classification returned "unknown" — the '
                f'spec matches both source and target (or neither) and '
                f'this is a destructive op ({subcommand}). Refusing to '
                f'authorize. Tighten run-spec.source.enterprise_name / '
                f'target.enterprise_name (or .user) so detect_session_role '
                f'can return a definite "source" or "target", then re-run.'
            )
        return True

    # Layer 1 — spec says read_only
    mode = (run_spec or {}).get('source_mode') or SOURCE_MODE_READ_ONLY
    if mode not in SOURCE_MODES:
        raise SafeguardBlocked(
            f'invalid source_mode={mode!r} in run-spec; '
            f'must be one of {SOURCE_MODES}'
        )
    if mode == SOURCE_MODE_READ_ONLY:
        raise SafeguardBlocked(
            f'source tenant is in read_only mode — refusing '
            f'{subcommand or "destructive op"}. Edit migration.yaml '
            f'and set source_mode: destructive to authorize, then re-run '
            f'with --confirm-source-destructive.'
        )

    # Layer 2 — CLI confirmation flag
    if not confirm_flag:
        raise SafeguardBlocked(
            'source tenant is in destructive mode but --confirm-source-'
            'destructive was not passed. Both the spec AND the CLI flag '
            'must agree before a source-destructive op proceeds.'
        )

    # Layer 3 — tenant-name gate is mandatory here
    if not expected_tenant_name:
        raise SafeguardBlocked(
            'source-destructive ops require --expected-tenant-name. '
            'Pass the exact source enterprise_name from the spec.'
        )
    expect_tenant(params, expected_tenant_name)

    # Layer 4 — spec's source.enterprise_name (if set) must match
    spec_source_name = ((run_spec or {}).get('source') or {}).get(
        'enterprise_name', '')
    if spec_source_name and \
       spec_source_name.strip().lower() != expected_tenant_name.strip().lower():
        raise SafeguardBlocked(
            f'--expected-tenant-name={expected_tenant_name!r} disagrees '
            f'with spec.source.enterprise_name={spec_source_name!r}. '
            f'Fix whichever is wrong before proceeding.'
        )

    logging.warning(
        '⚠ SOURCE-DESTRUCTIVE op authorized: subcommand=%s tenant=%s',
        subcommand or '?', expected_tenant_name,
    )
    return True


def expect_tenant(params, expected_name):
    """Confirm the session is attached to the tenant the caller expects.

    `expected_name` is typically passed from a --expected-tenant-name
    CLI arg. Case-insensitive exact match against
    params.enterprise['enterprise_name'].

    Empty expected_name disables the check (default — backward compat).

    Raises SafeguardBlocked on mismatch.
    """
    if not expected_name:
        return True
    ent = getattr(params, 'enterprise', None) or {}
    current = (ent.get('enterprise_name') or '').strip()
    if current.lower() != expected_name.strip().lower():
        raise SafeguardBlocked(
            f"tenant-name mismatch: session is {current!r} but "
            f"--expected-tenant-name={expected_name!r}. Refusing to proceed."
        )
    return True


def require_tenant_assertion(params, expected_name, skip_check=False,
                              *, subcommand=''):
    """Mandatory tenant-name check on destructive subcommands.

    Added after a red-team test 2026-04-20 proved that a polluted
    config.json (correct filename, wrong credentials inside) silently
    aimed destructive ops at the WRONG tenant. A filename operators
    trust for the tenant identity is not a safe proxy — the session
    must match what the operator THINKS it points at.

    Three code paths:

      1. `skip_check=True` — explicit opt-out for CI / automation
         that already pre-validated the session elsewhere. Logs a
         WARNING so the bypass is visible in audit.
      2. `expected_name=''` and `skip_check=False` — raises
         SafeguardBlocked with a message pointing at the root-cause
         (polluted config file).
      3. `expected_name` non-empty — delegates to expect_tenant
         for case-insensitive exact match, raising on mismatch.
    """
    if skip_check:
        current = ((getattr(params, 'enterprise', None) or {})
                   .get('enterprise_name') or '').strip()
        logging.warning(
            '⚠ %s: tenant-name check SKIPPED — session currently points '
            'at %r. Caller asserted this is intentional via '
            '--skip-tenant-check.',
            subcommand or 'destructive op', current,
        )
        return True

    if not expected_name:
        current = ((getattr(params, 'enterprise', None) or {})
                   .get('enterprise_name') or '').strip() or '(unknown)'
        raise SafeguardBlocked(
            f'{subcommand or "destructive op"} refuses to proceed '
            f'without a tenant assertion. Session currently points at '
            f'{current!r}. Pass --expected-tenant-name to verify, or '
            f'--skip-tenant-check if you have pre-validated the session '
            f'by other means. (This guard was added after a 2026-04-20 '
            f'red-team test caught a polluted config.json aiming writes '
            f'at the wrong tenant.)'
        )

    return expect_tenant(params, expected_name)


def enforce_batch_cap(count, cap, override=False,
                     *, entity_label='rows'):
    """Block when count would exceed `cap` unless override is explicitly set.

    Used by decommission + cleanup to require a thinking pause before
    touching an unexpectedly-large set. Default cap=50 — tune per call.
    """
    if count <= cap:
        return True
    if override:
        logging.warning(
            'batch-cap override: %s %s > %d (user override granted)',
            count, entity_label, cap,
        )
        return True
    raise SafeguardBlocked(
        f'refusing to touch {count} {entity_label} (cap={cap}). '
        f'Pass --override-batch-cap if this is really intentional.'
    )


def production_tenant_warning(params):
    """Emit a WARN-level log if the tenant name looks production-ish.

    Pure advisory — never blocks. Triggers for any enterprise_name that
    doesn't contain one of the sandbox keywords.
    """
    ent = getattr(params, 'enterprise', None) or {}
    name = (ent.get('enterprise_name') or '').strip()
    if not name:
        return False
    lower = name.lower()
    if any(kw in lower for kw in SANDBOX_KEYWORDS):
        return False
    logging.warning(
        '⚠ tenant name %r contains no sandbox keyword %s — '
        'destructive ops on this tenant WILL affect production data.',
        name, SANDBOX_KEYWORDS,
    )
    return True


def preflight_destructive(params, *, expected_tenant='',
                           batch_count=0, batch_cap=50,
                           override_batch=False,
                           entity_label='rows'):
    """Chain all three checks. Returns None on success, raises on block."""
    expect_tenant(params, expected_tenant)
    enforce_batch_cap(batch_count, batch_cap, override=override_batch,
                      entity_label=entity_label)
    production_tenant_warning(params)


# ─── High-visibility banners ─────────────────────────────────────────────────


_BANNER_TOP = '╔══════════════════════════════════════════════════════════════╗'
_BANNER_BOT = '╚══════════════════════════════════════════════════════════════╝'
_BANNER_MID = '╠══════════════════════════════════════════════════════════════╣'


def _emit_banner(level, title, lines, logger=None):
    """Emit a 3-line-minimum framed banner at `level` severity.

    `lines` is a list of body strings — one per row of the banner.
    """
    log = logger or logging.getLogger()
    log.log(level, _BANNER_TOP)
    log.log(level, f'║  {title:<58}║')
    log.log(level, _BANNER_MID)
    for line in lines:
        log.log(level, f'║  {line:<58}║')
    log.log(level, _BANNER_BOT)


# Severity levels are re-exported as integers so callers don't have to
# import logging + this module both.
ERROR_LEVEL = logging.ERROR
WARN_LEVEL = logging.WARNING


# Destructive verbs per subcommand — used to generate clear messages.
DESTRUCTIVE_DESCRIPTIONS = {
    'decommission': {
        'verb': 'LOCK + DELETE',
        'what': 'source-tenant users',
        'reversibility': 'IRREVERSIBLE — source user data is permanently lost',
    },
    'cleanup': {
        'verb': 'DELETE',
        'what': 'teams / roles / nodes matching the prefix',
        'reversibility': 'IRREVERSIBLE — re-create via `structure` if needed',
    },
    'transfer-user': {
        'verb': 'AUTO-LOCK + TRANSFER',
        'what': 'entire source-user vaults into the admin account',
        'reversibility': ('source users cannot log in after transfer until '
                          'unlocked manually; vault data is MOVED not copied'),
    },
}

MODIFYING_DESCRIPTIONS = {
    'structure': {
        'verb': 'CREATE',
        'what': 'nodes / teams / roles / enforcements / SF membership',
        'reversibility': 'reversible via `cleanup --prefix`',
    },
    'users': {
        'verb': 'INVITE + PLACE',
        'what': 'users on the current (target) tenant',
        'reversibility': ('reversible via enterprise-user --delete; pending '
                          'invites can be revoked'),
    },
    'take-ownership': {
        'verb': 'TRANSFER OWNERSHIP',
        'what': 'MIGRATION-* folders from source users to the admin',
        'reversibility': ('reversible via manual share-record -a owner from '
                          'admin back to user; JSON backup retained'),
    },
    'records-import': {
        'verb': 'IMPORT',
        'what': 'record data into the current (target) tenant',
        # `cleanup` calls `rm --purge` on Commander >= v17.2.14 (KC-625).
        # On older Commander, plain `rm` already hard-deletes. Manual
        # `rm` without `--purge` on v17.2.14+ only unlinks per-user.
        'reversibility': 'reversible via `cleanup` (purges for all users)',
    },
    'records-attachments': {
        'verb': 'UPLOAD',
        'what': 'attachments to target records',
        'reversibility': 'reversible via `delete-attachment`',
    },
    'records-shares': {
        'verb': 'GRANT',
        'what': 'record shares on the target tenant',
        'reversibility': 'reversible via `share-record -a revoke`',
    },
}


def banner_destructive(subcommand, *, details=None, logger=None):
    """Emit the red ⚠ DESTRUCTIVE banner at ERROR level (so it survives
    --quiet). `details` is a list of extra body lines the caller can
    append (e.g. "on {count} users", "tenant={name}")."""
    spec = DESTRUCTIVE_DESCRIPTIONS.get(subcommand)
    if not spec:
        return
    body = [
        f'⚠ DESTRUCTIVE: {spec["verb"]} {spec["what"]}',
        f'  {spec["reversibility"]}',
    ]
    if details:
        body.extend('  ' + d for d in details)
    body.append('  Run with --dry-run first to preview. No grace period.')
    _emit_banner(ERROR_LEVEL,
                 f'⚠  tenant-migrate {subcommand}  ⚠',
                 body, logger=logger)


def banner_modifying(subcommand, *, details=None, logger=None):
    """Emit the yellow ⚠ MODIFYING banner at WARNING level. Softer tone
    for CREATE-class ops that still change target-tenant state."""
    spec = MODIFYING_DESCRIPTIONS.get(subcommand)
    if not spec:
        return
    body = [
        f'ℹ MODIFYING: {spec["verb"]} {spec["what"]}',
        f'  {spec["reversibility"]}',
    ]
    if details:
        body.extend('  ' + d for d in details)
    _emit_banner(WARN_LEVEL,
                 f'tenant-migrate {subcommand}',
                 body, logger=logger)


def banner_for(subcommand, *, dry_run=False, details=None, logger=None):
    """One-stop helper: pick banner_destructive / banner_modifying and
    skip entirely when dry_run=True (no destruction to warn about)."""
    if dry_run:
        return
    if subcommand in DESTRUCTIVE_DESCRIPTIONS:
        banner_destructive(subcommand, details=details, logger=logger)
    elif subcommand in MODIFYING_DESCRIPTIONS:
        banner_modifying(subcommand, details=details, logger=logger)


# ─── Interactive yes / no / cancel confirmation ──────────────────────────────


# Accepted tokens at the interactive prompt (case-insensitive).
# Ctrl+C / EOF is handled separately via KeyboardInterrupt — no need
# for a distinct "cancel" word; "no" already means "don't proceed".
YES_TOKENS = frozenset({'yes', 'y'})
NO_TOKENS = frozenset({'no', 'n', ''})       # empty = default to NO


def confirm_interactive(title, description,
                         *, input_fn=None, output_fn=None,
                         auto_yes=False, auto_no=False,
                         require_interactive=True):
    """Prompt the user for yes / no.

    `title`       — short headline (e.g. 'CONFIRM decommission')
    `description` — multi-line narrative shown before the prompt;
                    include specific counts, names, consequences.

    Accepted inputs (case-insensitive):
        yes / y                       → returns True
        no / n / <empty — just Enter> → returns False
        anything else                 → re-prompts (up to 3 tries)
        Ctrl+C / EOF                  → returns False (logged as interrupt)

    `auto_yes`/`auto_no` bypass the prompt (for CI / --yes).
    `require_interactive` — when True (default), no TTY + no auto_*
    returns False with a clear 'interactive confirmation required' log.
    Callers that set this False can run headless with default=NO.

    Returns True only if the user explicitly confirmed. Default is NO.
    """
    import sys

    if auto_yes and auto_no:
        raise ValueError('auto_yes and auto_no are mutually exclusive')
    if auto_yes:
        logging.warning('[auto-yes] skipping interactive confirmation for %r', title)
        return True
    if auto_no:
        logging.info('[auto-no] rejecting %r without prompt', title)
        return False

    in_ = input_fn or input
    out = output_fn or (lambda s: print(s, flush=True))

    # No TTY → we can't safely prompt. Refuse by default so automated
    # runs don't silently proceed.
    if require_interactive and not sys.stdin.isatty():
        logging.error(
            'interactive confirmation required for %r but stdin is not a TTY. '
            'Pass --yes for automated runs, --dry-run for previews.', title,
        )
        return False

    out('')
    out('━' * 62)
    out(f'  {title}')
    out('━' * 62)
    for line in description.splitlines():
        out(f'  {line}')
    out('')
    out('  Accept one of:')
    out('    yes / y          → proceed with the action')
    out('    no / n / <Enter> → reject and exit without changes')
    out('')
    for _ in range(3):
        try:
            raw = in_('  > ').strip().lower()
        except (EOFError, KeyboardInterrupt):
            out('')
            logging.info('%s cancelled via interrupt', title)
            return False
        if raw in YES_TOKENS:
            return True
        if raw in NO_TOKENS:
            return False
        out(f'  Unrecognized input {raw!r}. Type yes or no.')
    # Three bad attempts → default reject (safer).
    logging.warning('%s rejected after 3 invalid inputs', title)
    return False
