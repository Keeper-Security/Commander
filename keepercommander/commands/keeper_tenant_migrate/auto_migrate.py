"""Unified auto-migrate — single-command customer-friendly UX.

Commander holds one session per shell. The existing subcommands honor
that: an operator runs one shell per tenant and ferries files between
them. That works for power users + CI but is unreasonable for customers.

`auto-migrate` collapses the two-shell pattern into one command:

    keeper-migrate --config /path/source.json tenant-migrate auto-migrate \\
        --target-user admin@target.io [--target-server EU] \\
        --scope-node MIGRATION-TEST-NODE --prefix MIGTEST- \\
        --run-dir /tmp/run

The plugin authenticates the source session from `--config`, then
interactively (or via `--target-config`) obtains the target session
in-process. Both `KeeperParams` objects live simultaneously — Commander's
SDK allows it; only its shell REPL assumes one at a time.

Pipeline stages (in canonical order):

    1. plan                         — source reads
    2. estimate                     — local, informational
    3. capture-target-state         — target reads
    4. structure                    — target writes
    5. users                        — target writes
    6. records-export               — source reads
    7. convert                      — local transform
    8. records-import               — target writes
    9. records-manifest             — target reads + match
    10. records-attachments-download — source reads
    11. records-attachments-upload   — target writes
    12. records-shares-extract      — source reads
    13. records-shares-apply        — target writes
    14. shared-folders-reconcile    — target writes
    14. verify                      — local compare
    15. reconcile                   — local report
    16. audit-verify                — integrity check

Defaults to `--dry-run` — no target writes until `--live` is passed.
Every destructive stage still flows through the existing 4-layer
interlock (`--source-read-only`, `source_mode`, `expect_tenant`,
`enforce_batch_cap`) so the convenience wrapper does not loosen any
safety rail.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Optional


# ── Stage catalog ───────────────────────────────────────────────────

STAGE_PLAN = 'plan'
STAGE_ESTIMATE = 'estimate'
STAGE_CAPTURE_TARGET = 'capture-target-state'
STAGE_STRUCTURE = 'structure'
STAGE_USERS = 'users'
STAGE_RECORDS_EXPORT = 'records-export'
STAGE_CONVERT = 'convert'
STAGE_RECORDS_IMPORT = 'records-import'
STAGE_RECORDS_MANIFEST = 'records-manifest'
STAGE_ATT_DOWNLOAD = 'records-attachments-download'
STAGE_ATT_UPLOAD = 'records-attachments-upload'
# Bug 33 (v1.5.2) — slots between att-upload and shares-extract.
# Records and attachments must already be on target so the rewriter has
# their target UIDs to substitute; shares come after so any share grants
# on the now-rewritten target records use the correct (post-rewrite)
# field values.
# Bug 70 (v1.6.4) — Commander's `convert-all` upgrades v2 records to
# v3 typed-record format on the live tenant. Without this, records
# imported from a legacy source land on target as v2 and the typed-
# field API used by references-rewrite (`load_field_values`) fails
# to deserialize them → load_failures → references-rewrite halt.
# Stage runs after attachments-upload (records + attachments are
# both on target) and before references-rewrite (which needs them
# loadable via the typed API). Default: --skip when no v2 records
# detected; else convert-all with --force --include-attachments.
STAGE_RECORDS_CONVERT_TO_V3 = 'records-convert-to-v3'

STAGE_RECORDS_REFERENCES_REWRITE = 'records-references-rewrite'
STAGE_RECORDS_SHARES_EXTRACT = 'records-shares-extract'
STAGE_RECORDS_SHARES_APPLY = 'records-shares-apply'
STAGE_SF_RECONCILE = 'shared-folders-reconcile'
STAGE_VERIFY = 'verify'
STAGE_RECONCILE = 'reconcile'
STAGE_AUDIT_VERIFY = 'audit-verify'


CANONICAL_STAGES = [
    STAGE_PLAN,
    STAGE_ESTIMATE,
    STAGE_CAPTURE_TARGET,
    STAGE_STRUCTURE,
    STAGE_USERS,
    STAGE_RECORDS_EXPORT,
    STAGE_CONVERT,
    STAGE_RECORDS_IMPORT,
    STAGE_RECORDS_MANIFEST,
    STAGE_ATT_DOWNLOAD,
    STAGE_ATT_UPLOAD,
    STAGE_RECORDS_CONVERT_TO_V3,
    STAGE_RECORDS_REFERENCES_REWRITE,
    STAGE_RECORDS_SHARES_EXTRACT,
    STAGE_RECORDS_SHARES_APPLY,
    STAGE_SF_RECONCILE,
    STAGE_VERIFY,
    STAGE_RECONCILE,
    STAGE_AUDIT_VERIFY,
]


# Stage → which session runs it. Drives the source-read-only rail.
STAGE_PHASE: dict = {
    STAGE_PLAN:              'source',
    STAGE_ESTIMATE:          'local',
    STAGE_CAPTURE_TARGET:    'target',
    STAGE_STRUCTURE:         'target',
    STAGE_USERS:             'target',
    STAGE_RECORDS_EXPORT:    'source',
    STAGE_CONVERT:           'local',
    STAGE_RECORDS_IMPORT:    'target',
    STAGE_RECORDS_MANIFEST:  'target',
    STAGE_ATT_DOWNLOAD:      'source',
    STAGE_ATT_UPLOAD:        'target',
    STAGE_RECORDS_CONVERT_TO_V3: 'target',
    STAGE_RECORDS_REFERENCES_REWRITE: 'target',
    STAGE_RECORDS_SHARES_EXTRACT: 'source',
    STAGE_RECORDS_SHARES_APPLY:   'target',
    STAGE_SF_RECONCILE:      'target',
    STAGE_VERIFY:            'local',
    STAGE_RECONCILE:         'local',
    STAGE_AUDIT_VERIFY:      'target',
}


# ── Safety: session pair ────────────────────────────────────────────

@dataclass
class SessionPair:
    """Holds both params objects + metadata. Enforces source != target
    at construction so operator errors (same config used twice) don't
    silently let target-writes hit the source tenant.

    `source_params` must already be authenticated (from --config).
    `target_params` is either loaded from --target-config or logged in
    interactively via attach_interactive_target().
    """
    source_params: object
    target_params: Optional[object] = None
    # Captured at verify-time so debug logs + safety checks don't
    # have to walk the enterprise dict each time.
    source_tenant_name: str = ''
    target_tenant_name: str = ''

    def verify_distinct(self):
        """Refuse if both params land on the same tenant name. Protects
        against the foot-gun of passing the same config as source AND
        target — every 'target' write would be a source write."""
        if not self.target_params:
            return
        src = self._tenant_name(self.source_params)
        tgt = self._tenant_name(self.target_params)
        self.source_tenant_name = src
        self.target_tenant_name = tgt
        if src and tgt and src == tgt:
            raise ValueError(
                f'source and target sessions are the same tenant '
                f'({src!r}); auto-migrate refuses to continue. '
                f'Check --config vs --target-config paths.'
            )

    @staticmethod
    def _tenant_name(params) -> str:
        ent = getattr(params, 'enterprise', None) or {}
        return (ent.get('enterprise_name') or '').strip()


def attach_vault_record_target(session_pair: SessionPair, *,
                                record_uid: str,
                                server_override: str = ''):
    """Bootstrap the target session from a Keeper record in the SOURCE
    vault.

    Real customer pattern: the admin's source vault often already
    contains the target tenant's admin credentials (e.g., 'Keeper MSP
    demo console' login record). Rather than re-entering the master
    password interactively, auto-migrate can fetch it once from the
    source vault and log into the target in-process.

    Safety:
      - The source session MUST already be authenticated — this
        function reads from source_params.record_cache (local
        decrypt, no network round-trip for the password).
      - The password is held only as long as api.login() needs it,
        then wiped from the target params.
      - If the record isn't in the source cache / has no password
        field, fail cleanly with a clear message rather than
        prompting or silently falling back.

    server_override: override the login record's URL-derived server
    (useful when the stored URL points at the console UI, not an
    API endpoint).
    """
    from keepercommander import api
    from keepercommander.params import KeeperParams

    src = session_pair.source_params
    rec = api.get_record(src, record_uid)
    if rec is None:
        raise ValueError(
            f'target-vault-record {record_uid!r} not found in source '
            f'vault. Run sync-down on the source session first.'
        )

    login = (getattr(rec, 'login', '') or '').strip()
    password = getattr(rec, 'password', '') or ''
    url = (getattr(rec, 'login_url', '') or '').strip()

    if not login or not password:
        raise ValueError(
            f'target-vault-record {record_uid!r} is missing login or '
            f'password. Record must be a standard login-type record.'
        )

    # Derive server from the record's URL unless overridden.
    # Default to keepersecurity.com; EU/AU/CA/JP/GOV each have their
    # own hosts and Commander cares which one we log into.
    server = server_override
    if not server:
        if 'keepersecurity.eu' in url:
            server = 'keepersecurity.eu'
        elif 'keepersecurity.com.au' in url:
            server = 'keepersecurity.com.au'
        elif 'keepersecurity.ca' in url:
            server = 'keepersecurity.ca'
        elif 'keepersecurity.jp' in url:
            server = 'keepersecurity.jp'
        elif 'govcloud.keepersecurity.us' in url:
            server = 'govcloud.keepersecurity.us'
        else:
            server = 'keepersecurity.com'

    tgt = KeeperParams(config_filename='')
    tgt.auto_login = False
    tgt.sync_data = True
    tgt.user = login
    tgt.server = server
    tgt.password = password

    logging.info('auto-migrate: authenticating target %s@%s (via source '
                 'vault record %s)', login, server, record_uid)
    # SEC-4 fix 2026-05-08: any exception from api.login /
    # query_enterprise / sync_down (bad password, MFA decline,
    # throttle, network) previously left tgt.password set on the
    # long-lived KeeperParams. try/finally guarantees the password
    # is zeroed regardless of outcome.
    try:
        api.login(tgt)
        api.query_enterprise(tgt, True)
        api.sync_down(tgt)
    finally:
        tgt.password = ''
        password = ''   # also zero the local

    session_pair.target_params = tgt
    session_pair.verify_distinct()
    return tgt


def attach_interactive_target(session_pair: SessionPair, *,
                              user: str, server: str = '',
                              prompt_fn: Optional[Callable] = None):
    """Log into the target tenant in-process.

    `prompt_fn(msg) -> password`: defaults to getpass.getpass so the
    master password never shows in argv or environment. Tests inject
    a deterministic callable.

    Commander handles MFA / Duo via its own internal prompts when
    `api.login()` is called interactively.
    """
    from getpass import getpass

    from keepercommander import api
    from keepercommander.params import KeeperParams

    tgt = KeeperParams(config_filename='')
    tgt.auto_login = False
    tgt.sync_data = True
    tgt.user = user
    tgt.server = server or 'keepersecurity.com'

    # Master password flow — never accept a password via CLI arg.
    prompt = prompt_fn or (
        lambda m: getpass(m)   # noqa: E731 — deliberate lambda for DI
    )
    pw = prompt(f'Master password for {user}: ')
    tgt.password = pw

    logging.info('auto-migrate: authenticating target tenant %s@%s',
                 user, tgt.server)
    # SEC-4 fix 2026-05-08: any exception from api.login / query_enterprise
    # / sync_down previously left tgt.password set on the long-lived
    # KeeperParams AND left `pw` alive in the traceback frame. try/finally
    # zeroes both regardless of outcome — the session token is what we
    # need from here on.
    try:
        api.login(tgt)
        api.query_enterprise(tgt, True)
        api.sync_down(tgt)
    finally:
        tgt.password = ''
        pw = ''

    session_pair.target_params = tgt
    session_pair.verify_distinct()
    return tgt


def attach_config_target(session_pair: SessionPair, *, config_path: str):
    """Load target params from a pre-authenticated config.json.
    Mirrors the harness's run_rehearsal.py pattern."""
    import json

    from keepercommander import api
    from keepercommander.params import KeeperParams

    if not os.path.isfile(config_path):
        raise FileNotFoundError(
            f'target config not found: {config_path}'
        )

    tgt = KeeperParams(config_filename=config_path)
    tgt.auto_login = False
    tgt.sync_data = True
    with open(config_path) as f:
        saved = json.load(f)
    tgt.user = saved.get('user', '')
    tgt.server = saved.get('server', '')
    tgt.device_token = saved.get('device_token')
    tgt.clone_code = saved.get('clone_code')
    tgt.device_private_key = saved.get('private_key')

    # HIGH-6 fix 2026-05-08: pre-login distinctness pre-flight.
    # Pre-fix this function called api.login(tgt) → query_enterprise →
    # sync_down BEFORE the post-hoc session_pair.verify_distinct().
    # If src and tgt configs accidentally point at the same tenant
    # (typo, copy-paste, wrong config file selected), the misdirected
    # login + enterprise read + record cache populate had already
    # executed against the wrong tenant by the time verify_distinct
    # raised — no rollback for the side-effecting reads.
    #
    # Now compare saved user/server to source's user/server BEFORE
    # api.login so the misdirection is caught at zero side-effect cost.
    src_params = session_pair.source_params
    src_user = (getattr(src_params, 'user', '') or '').strip().lower()
    src_server = (getattr(src_params, 'server', '') or '').strip().lower()
    tgt_user = (tgt.user or '').strip().lower()
    tgt_server = (tgt.server or '').strip().lower()
    if src_user and tgt_user and src_user == tgt_user \
            and src_server == tgt_server:
        raise ValueError(
            f'target config at {config_path!r} points at the same '
            f'tenant as the source session (user={src_user!r}, '
            f'server={src_server!r}). Pick a different target config — '
            f'a same-tenant target would cause writes to be applied '
            f'to the source. Refusing to call api.login(target) until '
            f'this is resolved.'
        )

    api.login(tgt)
    api.query_enterprise(tgt, True)
    api.sync_down(tgt)

    session_pair.target_params = tgt
    # HIGH-6: keep the post-hoc enterprise-name verify_distinct() too,
    # in case user/server collide with different enterprise names
    # (rare but possible — e.g. distinct tenants where one operator
    # reuses an email across them).
    session_pair.verify_distinct()
    return tgt


# ── Run configuration ───────────────────────────────────────────────

@dataclass
class RunConfig:
    run_dir: str
    scope_node: str = ''
    prefix: str = ''
    target_root: str = ''
    mc: str = ''

    # Target auth — exactly one must be set (validated externally).
    target_user: str = ''
    target_server: str = ''
    target_config: str = ''
    target_vault_record: str = ''   # Bootstrap from source vault record

    # Safety
    dry_run: bool = True    # default: dry-run
    yes: bool = False       # bypass interactive confirms
    expected_source_tenant: str = ''
    expected_target_tenant: str = ''
    source_read_only: bool = True   # honored regardless — a --no-read-only
                                    #  flag would be its own big decision

    # Behavior
    only_stages: list = field(default_factory=list)   # [] = all
    skip_stages: list = field(default_factory=list)
    resume: bool = False
    force_restart: bool = False
    old_domain: str = ''
    new_domain: str = ''
    include_fields: bool = False
    sso_policy: str = 'warn'

    # Throttle config (v1.4.0 — response to 90-min structure stage on
    # real-world tenant). Single --delay forces every stage to wait at
    # the slowest pace required by the slowest stage; per-stage override
    # lets each stage run at its natural QPS ceiling.
    #
    # `delay` is the legacy unified knob; non-zero wins when a specific
    # per-stage delay is unset. Sensible defaults per stage when user
    # passes neither:
    #   structure      — 3.0s (enforcements loop is the bottleneck)
    #   records import — 1.0s (bulk batch endpoint)
    #   attachments    — 0.5s (I/O bound, many short calls)
    #   shares         — 3.0s (one share-record per pair, heavily throttled)
    delay: float = 0.0
    delay_structure: float = 0.0       # 0 → derive from delay or default
    delay_records: float = 0.0
    delay_attachments: float = 0.0
    delay_shares: float = 0.0
    # Jitter: add random.uniform(0, jitter) to every inter-call sleep so
    # calls don't align with Commander's 30s throttle-backoff wave. 0.5s
    # jitter is enough to desynchronize without meaningfully slowing
    # throughput. Set to 0 to disable.
    jitter: float = 0.5
    # Yield budget: every N API calls, insert a 2s pause so the admin's
    # browser session has a window to claim rate-limit quota. Default 0
    # (disabled); 20 is a good starting value for long-running stages.
    reserve_quota_every: int = 0
    reserve_quota_seconds: float = 2.0

    # Adaptive throttle (v1.4.0 — ports `_throttle_helpers.sh::kc_call`
    # into commander_clients._call). Grows inter-call delay on observed
    # Commander throttle events and decays after clean runs. Applies
    # globally to every SDK call. Coexists with the per-stage delays
    # above as a floor — adaptive raises the effective delay when the
    # tenant is under pressure, never lowers it below the static floor.
    adaptive_throttle: bool = True
    adaptive_base_delay: float = 2.0
    adaptive_max_delay: float = 30.0
    adaptive_success_reset: int = 20
    adaptive_step: float = 1.0
    # calls_per_minute > 0 overrides adaptive_base_delay with
    #   base_delay = max(0, 60/cpm - AVG_CALL_LATENCY_SEC)
    # Operator-facing knob for "I want at most N API calls/min against
    # this tenant". 0 means use adaptive_base_delay directly. Feeds
    # both the estimator and the throttle at run time.
    calls_per_minute: float = 0.0
    # Token bucket — bounds per-tenant burst behavior, which the
    # post-call sleep alone cannot do. Roles + enforcements + managed
    # node privileges each trigger a burst of N sequential `_call`s
    # inside structure's step loops; capacity caps how many fire
    # back-to-back before the bucket gates the next one. Calibrated
    # from 2026-04-22 observations.
    burst_capacity: int = 3
    # cluster_window (seconds) — when a throttle hit lands within this
    # many seconds of the previous hit, use exponential (double)
    # growth on current_delay instead of linear (+step). Default 120s
    # because Commander's own 60s internal backoff spaces hits apart;
    # 30s was dead code in practice.
    cluster_window: float = 120.0
    # Decay cooldown — minimum seconds between last throttle and
    # first decay. Prevents oscillation where 20 clean calls drops
    # delay, next call throttles, delay re-climbs, 20 more clean
    # calls drops it again, …forever. 60s matches Commander's
    # internal backoff cycle.
    decay_cooldown: float = 60.0
    # Bucket refill decays only every Nth success_reset window —
    # keeps burst cap conservative while the delay relaxes. 3 means
    # bucket needs 60 consecutive clean calls before refill ticks up.
    bucket_decay_every_n_windows: int = 3

    batch_size: int = 0
    source_folder_uids: list = field(default_factory=list)

    # Bug 49 — records-manifest pairing strategy. Default-False keeps
    # the manifest strict (skip duplicate-title pairs). Operators of
    # tenants with duplicate titles (where the source has multiple
    # records with the same title and so does target) opt in via
    # `--allow-ambiguous` to enable positional pairing — first source
    # with first target. Use only when source/target order is known
    # to align (e.g. fresh target imported in-order from source).
    allow_ambiguous: bool = False

    # Bug 68 (v1.6.2) — chunked records-import for heavily-throttled
    # tenants. 0 = legacy single-pass import; >0 = chunk into N-record
    # batches with `import_chunk_delay` seconds between chunks.
    # Mirrors pam-import's natural pacing.
    import_chunk_size: int = 0
    import_chunk_delay: float = 2.0


@dataclass
class StageResult:
    name: str
    status: str          # PASS / FAIL / SKIP
    seconds: float = 0.0
    detail: str = ''
    result: object = None   # subcommand-returned dict (informational)


# ── Orchestration ───────────────────────────────────────────────────

def effective_stages(cfg: RunConfig) -> list:
    """Apply --only-stages / --skip-stages to produce the ordered list
    of stages to run. `--only-stages` takes precedence."""
    if cfg.only_stages:
        allowed = set(cfg.only_stages)
        return [s for s in CANONICAL_STAGES if s in allowed]
    skip = set(cfg.skip_stages)
    return [s for s in CANONICAL_STAGES if s not in skip]


def validate_config(cfg: RunConfig):
    """Pre-flight checks that are cheaper than running the pipeline.
    Returns None on success; raises ValueError on bad config."""
    auth_sources = sum([
        bool(cfg.target_user),
        bool(cfg.target_config),
        bool(cfg.target_vault_record),
    ])
    if auth_sources != 1:
        raise ValueError(
            'auto-migrate requires exactly one of --target-user, '
            '--target-config, or --target-vault-record (got %d)'
            % auth_sources,
        )

    if not cfg.run_dir:
        raise ValueError('auto-migrate requires --run-dir')

    bad_only = [s for s in cfg.only_stages if s not in CANONICAL_STAGES]
    if bad_only:
        raise ValueError(
            f'--only-stages contains unknown stage(s): {bad_only!r}. '
            f'Valid stages: {CANONICAL_STAGES}'
        )
    bad_skip = [s for s in cfg.skip_stages if s not in CANONICAL_STAGES]
    if bad_skip:
        raise ValueError(
            f'--skip-stages contains unknown stage(s): {bad_skip!r}. '
            f'Valid stages: {CANONICAL_STAGES}'
        )


# Stage functions — each takes (sessions, cfg) and returns StageResult.
# Implementations live at the bottom of the file so the public API
# (run, stage catalog, config) is readable first.

def run(sessions: SessionPair, cfg: RunConfig) -> dict:
    """Execute the full pipeline. Returns a summary dict with one
    StageResult per run stage."""
    validate_config(cfg)
    os.makedirs(cfg.run_dir, exist_ok=True)

    # Phase 2 Audit 3 #4 fix: --expected-source-tenant /
    # --expected-target-tenant were previously parsed and stored on
    # cfg but never enforced. Audit-3 surfaced this as a MEDIUM gap
    # because operators were passing them expecting a hard guard.
    # Enforce here, after verify_distinct() has populated the
    # canonical tenant names. Fail-CLOSED rather than warn-only.
    if cfg.expected_source_tenant and sessions.source_tenant_name and \
            cfg.expected_source_tenant != sessions.source_tenant_name:
        raise ValueError(
            f'auto-migrate: --expected-source-tenant '
            f'{cfg.expected_source_tenant!r} does not match the source '
            f'session tenant {sessions.source_tenant_name!r}. Refusing to '
            f'continue. Check --config / --expected-source-tenant.'
        )
    if cfg.expected_target_tenant and sessions.target_tenant_name and \
            cfg.expected_target_tenant != sessions.target_tenant_name:
        raise ValueError(
            f'auto-migrate: --expected-target-tenant '
            f'{cfg.expected_target_tenant!r} does not match the target '
            f'session tenant {sessions.target_tenant_name!r}. Refusing to '
            f'continue. Check --target-config / --expected-target-tenant.'
        )

    # Apply adaptive-throttle config before any SDK call fires. New
    # throttle instances (one per tenant) will pick up these defaults
    # the first time commander_clients._call sees each params object.
    from .throttle import AdaptiveThrottle
    from .estimate import AVG_CALL_LATENCY_SEC
    effective_base = float(cfg.adaptive_base_delay)
    bucket_refill = 0.5   # 30 cpm default
    if cfg.calls_per_minute and cfg.calls_per_minute > 0:
        # Seconds/call target from cpm, minus the observed Commander
        # round-trip latency (since the throttle adds sleep AFTER the
        # call returns — the round-trip is already part of the budget).
        per_call = 60.0 / float(cfg.calls_per_minute)
        effective_base = max(0.0, per_call - AVG_CALL_LATENCY_SEC)
        bucket_refill = float(cfg.calls_per_minute) / 60.0
    # Floor on bucket refill — when clustering pushes refill down,
    # never below 1/6th of the starting rate (i.e. cpm/6), and never
    # above bucket_refill itself (avoids ValueError at very low cpm).
    bucket_min_refill = min(max(0.01, bucket_refill / 6.0), bucket_refill)
    AdaptiveThrottle.reset_registry()
    AdaptiveThrottle.configure_defaults(
        enabled=bool(cfg.adaptive_throttle),
        base_delay=effective_base,
        max_delay=float(cfg.adaptive_max_delay),
        success_reset=int(cfg.adaptive_success_reset),
        step=float(cfg.adaptive_step),
        jitter=float(cfg.jitter),
        cluster_window=float(cfg.cluster_window),
        decay_cooldown=float(cfg.decay_cooldown),
        bucket_decay_every_n_windows=int(cfg.bucket_decay_every_n_windows),
        bucket_capacity=int(cfg.burst_capacity),
        bucket_refill_per_sec=bucket_refill,
        bucket_min_refill_per_sec=bucket_min_refill,
    )
    cpm_note = (f' (from --calls-per-minute {cfg.calls_per_minute:g})'
                if cfg.calls_per_minute else '')
    logging.warning(
        'adaptive-throttle: %s — base=%.2fs%s max=%.1fs reset@%d '
        'clean calls step=%.1fs jitter=%.1fs cluster_window=%.0fs '
        'decay_cooldown=%.0fs bucket_decay=%d windows',
        'on' if cfg.adaptive_throttle else 'off',
        effective_base, cpm_note, cfg.adaptive_max_delay,
        cfg.adaptive_success_reset, cfg.adaptive_step, cfg.jitter,
        cfg.cluster_window, cfg.decay_cooldown,
        cfg.bucket_decay_every_n_windows,
    )
    logging.warning(
        'token-bucket: capacity=%d refill=%.3f tok/s (%.1f cpm) '
        'min_refill=%.3f tok/s',
        cfg.burst_capacity, bucket_refill, bucket_refill * 60.0,
        bucket_min_refill,
    )

    stages = effective_stages(cfg)
    logging.info('auto-migrate: %d stage(s) to run: %s',
                 len(stages), ', '.join(stages))

    results: list = []
    for name in stages:
        fn = _STAGE_DISPATCH.get(name)
        if fn is None:
            results.append(StageResult(
                name=name, status='SKIP',
                detail='no dispatcher (stage not implemented)',
            ))
            continue
        start = time.monotonic()
        try:
            r = fn(sessions, cfg)
        except Exception as e:                         # noqa: BLE001
            elapsed = time.monotonic() - start
            logging.error('auto-migrate: stage %r raised %r — '
                          'halting pipeline', name, e, exc_info=True)
            results.append(StageResult(
                name=name, status='FAIL', seconds=elapsed,
                detail=f'{type(e).__name__}: {e}',
            ))
            break
        r.seconds = time.monotonic() - start
        results.append(r)
        if r.status == 'FAIL':
            logging.error('auto-migrate: stage %r FAILED: %s — halting',
                          name, r.detail)
            break

    counts = {'PASS': 0, 'FAIL': 0, 'SKIP': 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    # Bug 71 (v1.6.5) — final categorized summary. Shows per-stage
    # PASS/FAIL/SKIP with details, plus a roll-up of post-structure
    # SKIPs from skip_audit.csv (operator-facing reasons per category).
    # Always emitted; --debug just makes it more verbose.
    logging.warning('=== auto-migrate summary ===')
    for r in results:
        logging.warning('  %-30s %-4s %6.1fs  %s',
                         r.name, r.status, r.seconds, r.detail)
    logging.warning('  counts: PASS=%d FAIL=%d SKIP=%d',
                     counts['PASS'], counts['FAIL'], counts['SKIP'])
    # SKIP audit roll-up if available
    try:
        import os as _os
        sa_path = _os.path.join(cfg.run_dir, 'skip_audit.csv')
        if _os.path.isfile(sa_path):
            from .skip_audit import audit_structure_results, summarize_audit
            sa_rows = audit_structure_results(sa_path)
            sa_counts = summarize_audit(sa_rows)
            logging.warning('=== structure SKIP categorization ===')
            for cat in ('by-design', 'bug-pending', 'source-quality',
                        'target-capability', 'cascade', 'unknown'):
                n = sa_counts.get(cat, 0)
                if n:
                    logging.warning('  %-20s %d', cat, n)
            if sa_counts.get('unknown', 0) > 0:
                logging.warning('  ⚠ %d UNKNOWN SKIP(s) — likely a new '
                                 'plugin bug; investigate', sa_counts['unknown'])
                for r in sa_rows:
                    if r.get('audit_category') == 'unknown':
                        logging.warning('    [%s] %s — %s',
                                         r.get('category'),
                                         r.get('name'),
                                         r.get('notes'))
    except Exception as _e:                              # noqa: BLE001
        logging.debug('skip_audit roll-up unavailable: %s', _e)

    throttle_snapshot = AdaptiveThrottle.registry_snapshot()
    for tenant, state in throttle_snapshot.items():
        logging.info(
            'adaptive-throttle[%s] summary: %d events, peak %.1fs '
            '(current %.1fs), total sleep %.1fs',
            tenant, state['throttle_events'],
            state['current_delay'], state['current_delay'],
            state['total_sleep_seconds'],
        )

    return {
        'stages': results,
        'counts': counts,
        'source_tenant': sessions.source_tenant_name,
        'target_tenant': sessions.target_tenant_name,
        'run_dir': cfg.run_dir,
        'dry_run': cfg.dry_run,
        'adaptive_throttle': throttle_snapshot,
    }


# ── Stage implementations ──────────────────────────────────────────
#
# Each stage wraps an existing subcommand's Command class. Stages that
# are destructive on target gate on cfg.dry_run; that cascades to the
# wrapped subcommand's own --dry-run support where available.


def _path(cfg: RunConfig, *parts) -> str:
    return os.path.join(cfg.run_dir, *parts)


def _s_plan(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import PlanCommand
    out = _path(cfg, 'inventory.json')
    PlanCommand().execute(
        sessions.source_params,
        output=out,
        scope_node=cfg.scope_node, prefix=cfg.prefix,
        target_user='', target_root=cfg.target_root,
        include_fields=cfg.include_fields, skip_hsf_scrape=False,
    )
    return StageResult(STAGE_PLAN, 'PASS', detail=f'inventory={out}')


def _s_estimate(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import EstimateCommand
    inv = _path(cfg, 'inventory.json')
    if not os.path.isfile(inv):
        return StageResult(STAGE_ESTIMATE, 'SKIP',
                            detail='no inventory.json — plan must pass first')
    EstimateCommand().execute(
        sessions.source_params,
        inventory=inv, output='', output_json='',
        tier_driver='auto',
        calls_per_minute=float(cfg.calls_per_minute or 0.0),
    )
    return StageResult(STAGE_ESTIMATE, 'PASS')


def _s_capture_target(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import CaptureTargetStateCommand
    out = _path(cfg, 'target_state.json')
    CaptureTargetStateCommand().execute(
        sessions.target_params,
        output=out, include_fields=False,
        prefix=cfg.prefix, mc=cfg.mc,
    )
    return StageResult(STAGE_CAPTURE_TARGET, 'PASS',
                        detail=f'target_state={out}')


# Per-stage default delays — chosen from 2026-04-20 full-tenant live
# observations (60+ min on structure, throttle-bound). Structure and
# shares both make N × M sequential API calls and fall over under any
# aggressive pacing; attachments is I/O-heavy but each call is small.
_DEFAULT_DELAY_BY_STAGE = {
    STAGE_STRUCTURE:      3.0,
    STAGE_USERS:          2.0,
    STAGE_RECORDS_IMPORT: 1.0,
    STAGE_ATT_DOWNLOAD:   0.5,
    STAGE_ATT_UPLOAD:     0.5,
    # references-rewrite is N×update_record — same per-call shape as
    # records-shares (target-side mutation per record). Use the same
    # 1.0s default; operators can override with --delay-records.
    STAGE_RECORDS_REFERENCES_REWRITE: 1.0,
    STAGE_RECORDS_SHARES_EXTRACT: 1.0,
    STAGE_RECORDS_SHARES_APPLY:   3.0,
    STAGE_SF_RECONCILE:   2.0,
}


def _effective_delay(cfg: RunConfig, stage_name: str) -> float:
    """Resolve the delay for a specific stage.

    Precedence (first non-zero wins):
      1. Per-stage explicit override (cfg.delay_structure etc.)
      2. Unified cfg.delay
      3. Per-stage default from _DEFAULT_DELAY_BY_STAGE
      4. 0.0 (unknown stage — fail open, trust Commander's internal
         throttle retry).
    """
    # Per-stage override.
    override_key = {
        STAGE_STRUCTURE: 'delay_structure',
        STAGE_RECORDS_IMPORT: 'delay_records',
        STAGE_RECORDS_MANIFEST: 'delay_records',
        STAGE_ATT_DOWNLOAD: 'delay_attachments',
        STAGE_ATT_UPLOAD: 'delay_attachments',
        STAGE_RECORDS_SHARES_EXTRACT: 'delay_shares',
        STAGE_RECORDS_SHARES_APPLY: 'delay_shares',
    }.get(stage_name)
    if override_key:
        override_val = getattr(cfg, override_key, 0.0) or 0.0
        if override_val > 0:
            return override_val
    # Unified legacy knob.
    if (cfg.delay or 0.0) > 0:
        return float(cfg.delay)
    # Built-in default.
    return _DEFAULT_DELAY_BY_STAGE.get(stage_name, 0.0)


def _s_structure(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    if cfg.dry_run:
        return _s_dry_stage(sessions, cfg, STAGE_STRUCTURE)
    from .commands import StructureCommand
    counters = StructureCommand().execute(
        sessions.target_params,
        plan=None, inventory=_path(cfg, 'inventory.json'),
        source_root='', target_root=cfg.target_root,
        scope_node=cfg.scope_node, steps='0-12',
        mc=cfg.mc,
        # Throttle controls plumbed through to StructureRestore — set
        # per-stage default for structure unless the user overrode
        # explicitly via cfg.delay_structure / cfg.delay.
        delay=_effective_delay(cfg, STAGE_STRUCTURE),
        jitter=cfg.jitter,
        reserve_quota_every=cfg.reserve_quota_every,
        reserve_quota_seconds=cfg.reserve_quota_seconds,
        run_dir=cfg.run_dir,
    )
    # Inspect StructureRestore.counters — silent-PASS when any per-entity
    # create returned False was the 2026-04-22 bug. FAIL loudly so the
    # pipeline halts and the operator sees the counter breakdown.
    if isinstance(counters, dict):
        failed = int(counters.get('FAILED', 0) or 0)
        succeeded = int(counters.get('SUCCESS', 0) or 0)
        skipped = int(counters.get('SKIPPED', 0) or 0)
        detail = (f'SUCCESS={succeeded} SKIPPED={skipped} FAILED={failed}')
        if failed > 0:
            return StageResult(STAGE_STRUCTURE, 'FAIL', detail=detail)
        return StageResult(STAGE_STRUCTURE, 'PASS', detail=detail)
    return StageResult(STAGE_STRUCTURE, 'PASS')


def _s_users(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    return StageResult(
        STAGE_USERS, 'SKIP',
        detail='users invite is high-risk (sends real emails) and '
               'requires an explicit roster CSV — use '
               '`tenant-migrate users` as a separate step after '
               'auto-migrate completes.',
    )


def _s_records_export(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import RecordsExportCommand
    out_dir = _path(cfg, 'records_export')
    # Pass run_dir so the audit-chain event lands at <run_dir>/audit.log
    # (top-level, per cmd's published contract) instead of inside
    # records_export/. Pre-fix this fragmented the chain — see
    # phase2-audit-emission-followup-2026-05-11.md.
    kwargs = {'output_dir': out_dir, 'run_dir': cfg.run_dir,
              'prefix': cfg.prefix}
    if cfg.source_folder_uids:
        kwargs['folder_uids'] = list(cfg.source_folder_uids)
    RecordsExportCommand().execute(sessions.source_params, **kwargs)
    return StageResult(STAGE_RECORDS_EXPORT, 'PASS',
                        detail=f'output={out_dir}')


def _s_convert(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import ConvertCommand
    in_dir = _path(cfg, 'records_export')
    out = _path(cfg, 'records_import.json')
    if not os.path.isdir(in_dir):
        return StageResult(STAGE_CONVERT, 'SKIP',
                            detail='no records_export dir')
    ConvertCommand().execute(
        sessions.source_params,
        input_dir=in_dir, output=out,
        compliance_csv=None, sf_json=None,
        include_sf=False, split_by_type=False,
    )
    return StageResult(STAGE_CONVERT, 'PASS', detail=f'bundle={out}')


def _s_records_import(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    if cfg.dry_run:
        return _s_dry_stage(sessions, cfg, STAGE_RECORDS_IMPORT)
    from .commands import RecordsImportCommand
    bundle = _path(cfg, 'records_import.json')
    if not os.path.isfile(bundle):
        return StageResult(STAGE_RECORDS_IMPORT, 'SKIP',
                            detail='no bundle — convert must pass first')
    # Bug 46 — pre-fix this discarded the return value and always
    # marked PASS, so a partial import (some records landed, others
    # failed) didn't halt the pipeline. Now: inspect ok/partial and
    # convert to FAIL when records-import reports trouble.
    result = RecordsImportCommand().execute(
        sessions.target_params, input=bundle, run_dir=cfg.run_dir,
        dry_run=False, record_type='', permissions='N',
        chunk_size=cfg.import_chunk_size,
        chunk_delay=cfg.import_chunk_delay,
    ) or {}
    if result.get('blocked'):
        return StageResult(STAGE_RECORDS_IMPORT, 'FAIL',
                            detail=f'blocked: {result.get("reason", "?")}')
    if not result.get('ok', True):
        detail = f'partial={result.get("partial", False)}'
        if result.get('reason'):
            detail += f', {result["reason"]}'
        return StageResult(STAGE_RECORDS_IMPORT, 'FAIL', detail=detail)
    imported = len(result.get('imported_uids') or [])
    return StageResult(STAGE_RECORDS_IMPORT, 'PASS',
                        detail=f'imported={imported}')


def _s_records_manifest(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import RecordsManifestCommand
    source_dir = _path(cfg, 'records_export')
    if not os.path.isdir(source_dir):
        return StageResult(STAGE_RECORDS_MANIFEST, 'SKIP',
                            detail='no records_export dir')
    out = _path(cfg, 'manifest.csv')
    # Bug 49 — pass `allow_ambiguous` through so duplicate-title
    # records can be positionally paired when the operator opts in.
    # Default-False preserves prior strict behavior.
    RecordsManifestCommand().execute(
        sessions.target_params, source_dir=source_dir,
        output=out, run_dir=cfg.run_dir,
        allow_ambiguous=cfg.allow_ambiguous,
    )
    return StageResult(STAGE_RECORDS_MANIFEST, 'PASS',
                        detail=f'manifest={out}')


def _s_att_download(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import RecordsAttachmentsDownloadCommand
    export_dir = _path(cfg, 'records_export')
    if not os.path.isdir(export_dir):
        return StageResult(STAGE_ATT_DOWNLOAD, 'SKIP',
                            detail='no records_export dir')
    # Build the uid list from exported records (same as the harness)
    uids_file = _path(cfg, 'source_uids.txt')
    import glob
    import json as _json
    uids = []
    for fn in sorted(glob.glob(os.path.join(export_dir, '*.json'))):
        base = os.path.basename(fn)
        if base in ('combined_export.json', 'import_manifest.csv',
                    'all_records.csv', 'SHA256SUMS.txt'):
            continue
        try:
            with open(fn) as f:
                rec = _json.load(f)
            uid = rec.get('record_uid') or rec.get('uid')
            if uid:
                uids.append(uid)
        except (OSError, _json.JSONDecodeError):
            continue
    with open(uids_file, 'w') as f:
        f.write('\n'.join(uids))

    staging = _path(cfg, 'attachments_staging')
    os.makedirs(staging, exist_ok=True)
    RecordsAttachmentsDownloadCommand().execute(
        sessions.source_params,
        source_uids=uids_file, staging_dir=staging,
        delay=_effective_delay(cfg, STAGE_ATT_DOWNLOAD),
        batch_size=cfg.batch_size,
    )
    return StageResult(STAGE_ATT_DOWNLOAD, 'PASS',
                        detail=f'staging={staging}')


def _s_att_upload(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    if cfg.dry_run:
        return _s_dry_stage(sessions, cfg, STAGE_ATT_UPLOAD)
    from .commands import RecordsAttachmentsUploadCommand
    manifest = _path(cfg, 'manifest.csv')
    staging = _path(cfg, 'attachments_staging')
    if not (os.path.isfile(manifest) and os.path.isdir(staging)):
        return StageResult(STAGE_ATT_UPLOAD, 'SKIP',
                            detail='missing manifest or staging dir')
    # Bug 46 — check fail count and convert to FAIL when uploads
    # didn't all succeed.
    result = RecordsAttachmentsUploadCommand().execute(
        sessions.target_params,
        manifest=manifest, staging_dir=staging,
        delay=_effective_delay(cfg, STAGE_ATT_UPLOAD),
        batch_size=cfg.batch_size,
        run_dir=cfg.run_dir, resume=cfg.resume,
        force_restart=cfg.force_restart,
    ) or {}
    if result.get('blocked'):
        return StageResult(STAGE_ATT_UPLOAD, 'FAIL',
                            detail=f'blocked: {result.get("reason", "?")}')
    fails = int(result.get('fail') or 0)
    passes = int(result.get('pass') or 0)
    if fails:
        return StageResult(STAGE_ATT_UPLOAD, 'FAIL',
                            detail=f'pass={passes} fail={fails}')
    return StageResult(STAGE_ATT_UPLOAD, 'PASS',
                        detail=f'uploaded={passes}')


def _s_records_convert_to_v3(sessions: SessionPair,
                               cfg: RunConfig) -> StageResult:
    """Bug 70 (v1.6.4) — run Commander's `convert-all` to upgrade any
    v2 records on target to v3 typed-record format.

    Why this stage exists: rehearsal-12 had references-rewrite halt
    on `load_failures=10`. Investigation showed those 10 records
    were legacy v2 records on target (left from prior rehearsals or
    imported from a pre-typed-record source). The typed-field API
    (`load_field_values`) used by references-rewrite can't
    deserialize v2 records → load fails → stage halts. Running
    `convert-all` post-import upgrades them in-place so the
    references-rewrite loader sees v3 everywhere.

    Idempotent: convert-all skips records that are already v3, so
    repeat runs no-op cleanly.
    """
    if cfg.dry_run:
        return _s_dry_stage(sessions, cfg, STAGE_RECORDS_CONVERT_TO_V3)
    try:
        from keepercommander.commands.convert import ConvertAllCommand
        from keepercommander import api
        api.sync_down(sessions.target_params)
        # --force skips the interactive confirmation; --include-attachments
        # covers attachment-bearing records (legacy `general` records often
        # have one). Default record type 'login' matches Commander's
        # built-in default.
        ConvertAllCommand().execute(sessions.target_params, force=True,
                                     include_attachments=True,
                                     record_type='login')
    except ImportError:
        return StageResult(STAGE_RECORDS_CONVERT_TO_V3, 'SKIP',
                            detail='convert-all unavailable in this Commander version')
    except Exception as e:                              # noqa: BLE001
        # Convert errors are non-fatal — references-rewrite has its
        # own load-failure tolerance (Bug 69). Log and pass.
        import logging
        logging.warning('convert-all raised %s: %s — continuing',
                         type(e).__name__, e)
        return StageResult(STAGE_RECORDS_CONVERT_TO_V3, 'SKIP',
                            detail=f'{type(e).__name__}: {e}')
    return StageResult(STAGE_RECORDS_CONVERT_TO_V3, 'PASS',
                        detail='target v2 records upgraded to v3')


def _s_records_references_rewrite(sessions: SessionPair,
                                    cfg: RunConfig) -> StageResult:
    """Bug 33 (v1.5.2) — rewrite source-record UIDs embedded in target
    record field values to their target equivalents.

    Runs on the TARGET session, after records-import + att-upload have
    populated target's record cache and the manifest is on disk.
    Idempotent: a re-run after a partial pass only persists records
    whose embedded UIDs still resolve to a different target.

    SKIP cases:
    - manifest.csv missing — records pipeline didn't reach manifest
      step; nothing to remap against.
    - manifest empty — no source/target pairs to drive the rewrite.

    FAIL is reserved for blocked (rate limit) or per-record persist
    failures. ``refs_unknown`` is informational, not a fail signal —
    a record may legitimately point at a source UID that the manifest
    doesn't carry (split-flow, ambiguous title, intentionally skipped).
    """
    if cfg.dry_run:
        return _s_dry_stage(sessions, cfg, STAGE_RECORDS_REFERENCES_REWRITE)
    from .commands import RecordsReferencesRewriteCommand
    manifest = _path(cfg, 'manifest.csv')
    if not os.path.isfile(manifest):
        return StageResult(STAGE_RECORDS_REFERENCES_REWRITE, 'SKIP',
                            detail='no manifest.csv (records pipeline incomplete)')
    result = RecordsReferencesRewriteCommand().execute(
        sessions.target_params,
        manifest=manifest,
        run_dir=cfg.run_dir,
        dry_run=False,
    ) or {}
    if result.get('blocked'):
        return StageResult(STAGE_RECORDS_REFERENCES_REWRITE, 'FAIL',
                            detail=f'blocked: {result.get("reason", "?")}')
    persist_fails = int(result.get('persist_failures') or 0)
    load_fails = int(result.get('load_failures') or 0)
    inspected = int(result.get('records_inspected') or 0)
    rewritten = int(result.get('records_rewritten') or 0)
    remapped = int(result.get('refs_remapped') or 0)
    # Bug 69 (v1.6.4) — load_failures are typically source-data-
    # quality signals (legacy/corrupted records on target that fail
    # to decrypt), not migration code bugs. Pre-fix these halted
    # the pipeline at any non-zero count; rehearsal-12 hit 10
    # decrypt-failed legacy records and FAILed the whole stage with
    # 1068 of 1078 records successfully processed. Now: only
    # persist_failures FAIL the stage; load_failures emit a WARNING
    # in the detail and proceed. A tolerance threshold (>50% of
    # inspected) still escalates to FAIL — that's a real systemic
    # issue, not an isolated decrypt error.
    if persist_fails:
        return StageResult(
            STAGE_RECORDS_REFERENCES_REWRITE, 'FAIL',
            detail=f'persist_fail={persist_fails} (load_fail={load_fails})')
    if load_fails and inspected and load_fails > inspected * 0.5:
        return StageResult(
            STAGE_RECORDS_REFERENCES_REWRITE, 'FAIL',
            detail=f'load_fail={load_fails} of {inspected} (>50% — '
                    'systemic load issue, not legacy data quality)')
    detail = f'inspected={inspected} rewritten={rewritten} refs_remapped={remapped}'
    if load_fails:
        detail += (f' WARN: load_fail={load_fails} (legacy/corrupted '
                    'records on target — operator should audit)')
    return StageResult(STAGE_RECORDS_REFERENCES_REWRITE, 'PASS',
                        detail=detail)


def _s_records_shares_extract(sessions: SessionPair,
                               cfg: RunConfig) -> StageResult:
    """Bug 20 + Bug 29 — source-side share extract for cross-tenant
    auto-migrate. Replaces the old single-session records-shares which
    silently SKIPped against target params."""
    if cfg.dry_run:
        return _s_dry_stage(sessions, cfg, STAGE_RECORDS_SHARES_EXTRACT)
    from .commands import RecordsSharesExtractCommand
    manifest = _path(cfg, 'manifest.csv')
    if not os.path.isfile(manifest):
        return StageResult(STAGE_RECORDS_SHARES_EXTRACT, 'SKIP',
                            detail='no manifest')
    output = _path(cfg, 'shares_extract.json')
    RecordsSharesExtractCommand().execute(
        sessions.source_params,
        manifest=manifest, output=output, run_dir=cfg.run_dir,
        old_domain=cfg.old_domain, new_domain=cfg.new_domain,
    )
    return StageResult(STAGE_RECORDS_SHARES_EXTRACT, 'PASS',
                        detail=f'manifest={output}')


def _s_records_shares_apply(sessions: SessionPair,
                             cfg: RunConfig) -> StageResult:
    """Bug 20 + Bug 29 — target-side share apply.

    Skipped when the extract step didn't produce a manifest (no source
    direct shares, or extract phase ran without input).
    """
    if cfg.dry_run:
        return _s_dry_stage(sessions, cfg, STAGE_RECORDS_SHARES_APPLY)
    from .commands import RecordsSharesApplyCommand
    extract_path = _path(cfg, 'shares_extract.json')
    if not os.path.isfile(extract_path):
        return StageResult(STAGE_RECORDS_SHARES_APPLY, 'SKIP',
                            detail='no extract manifest')
    RecordsSharesApplyCommand().execute(
        sessions.target_params,
        input=extract_path,
        skip_missing_users=True,
        delay=_effective_delay(cfg, STAGE_RECORDS_SHARES_APPLY),
        batch_size=cfg.batch_size,
        run_dir=cfg.run_dir, resume=cfg.resume,
        force_restart=cfg.force_restart,
    )
    return StageResult(STAGE_RECORDS_SHARES_APPLY, 'PASS')


def _s_sf_reconcile(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import SharedFoldersReconcileCommand
    inv = _path(cfg, 'inventory.json')
    if not os.path.isfile(inv):
        return StageResult(STAGE_SF_RECONCILE, 'SKIP',
                            detail='no inventory')
    SharedFoldersReconcileCommand().execute(
        sessions.target_params,
        inventory=inv, report='',
        dry_run=cfg.dry_run,
        old_domain=cfg.old_domain, new_domain=cfg.new_domain,
        delay=_effective_delay(cfg, STAGE_SF_RECONCILE),
        batch_size=cfg.batch_size,
        run_dir=cfg.run_dir, resume=cfg.resume,
        force_restart=cfg.force_restart,
        prune=False,   # safe default — auto-migrate never prunes
    )
    return StageResult(STAGE_SF_RECONCILE, 'PASS')


def _recapture_target_state(sessions: SessionPair, cfg: RunConfig) -> str:
    """Refresh target_state.json so verify/reconcile see the post-write
    tenant, not the stale snapshot taken before structure ran. Returns
    the path to the refreshed file.
    """
    from .commands import CaptureTargetStateCommand
    out = _path(cfg, 'target_state.json')
    CaptureTargetStateCommand().execute(
        sessions.target_params,
        output=out, include_fields=False,
        prefix=cfg.prefix, mc=cfg.mc,
    )
    return out


def _s_verify(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import VerifyCommand
    inv = _path(cfg, 'inventory.json')
    if not os.path.isfile(inv):
        return StageResult(STAGE_VERIFY, 'SKIP', detail='missing inventory')
    # Re-capture post-write. The initial capture runs pre-structure and
    # would make verify a comparison against yesterday's target state.
    ts = _recapture_target_state(sessions, cfg)
    checks_path = _path(cfg, 'checks.csv')
    VerifyCommand().execute(
        sessions.target_params,
        inventory=inv, target_state=ts,
        output=checks_path, run_dir=cfg.run_dir,
    )
    # Inspect checks.csv — silent-PASS on missing entities was the
    # 2026-04-22 bug. Count FAIL rows explicitly.
    fail_rows = 0
    if os.path.isfile(checks_path):
        import csv
        with open(checks_path, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if (row.get('severity') or '').upper() == 'FAIL':
                    fail_rows += 1
    if fail_rows > 0:
        return StageResult(STAGE_VERIFY, 'FAIL',
                            detail=f'{fail_rows} check(s) FAIL — see '
                                    f'{os.path.basename(checks_path)}')
    return StageResult(STAGE_VERIFY, 'PASS',
                        detail=f'checks.csv: 0 FAIL')


def _s_reconcile(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import ReconcileCommand
    inv = _path(cfg, 'inventory.json')
    ts = _path(cfg, 'target_state.json')
    # _s_verify already re-captures target_state; if verify was skipped
    # (or run in a different order), refresh here too — idempotent and
    # cheap.
    if not os.path.isfile(inv):
        return StageResult(STAGE_RECONCILE, 'SKIP', detail='missing inventory')
    if not os.path.isfile(ts):
        ts = _recapture_target_state(sessions, cfg)
    report_path = _path(cfg, 'reconciliation.md')
    result = ReconcileCommand().execute(
        sessions.target_params,
        inventory=inv, target_state=ts,
        output=report_path,
    )
    # ReconcileCommand returns {'summary': {total_expected, total_found,
    # total_missing, success_pct}, 'deltas': {...}}. Silent-PASS on
    # missing entities was the 2026-04-22 bug — fail loudly.
    summary = (result or {}).get('summary', {}) if isinstance(result, dict) else {}
    if summary:
        expected = int(summary.get('total_expected', 0) or 0)
        found = int(summary.get('total_found', 0) or 0)
        missing = int(summary.get('total_missing', 0) or 0)
        detail = (f'expected={expected} found={found} missing={missing}')
        if missing > 0:
            return StageResult(STAGE_RECONCILE, 'FAIL', detail=detail)
        return StageResult(STAGE_RECONCILE, 'PASS', detail=detail)
    return StageResult(STAGE_RECONCILE, 'PASS')


def _s_audit_verify(sessions: SessionPair, cfg: RunConfig) -> StageResult:
    from .commands import AuditVerifyCommand
    AuditVerifyCommand().execute(
        sessions.target_params, directory=cfg.run_dir,
    )
    return StageResult(STAGE_AUDIT_VERIFY, 'PASS')


def _s_dry_stage(sessions: SessionPair, cfg: RunConfig,
                 name: str) -> StageResult:
    """Placeholder for target-write stages when --dry-run is active.
    The underlying subcommand's --dry-run path emits its own report;
    this just records the skip in the auto-migrate summary."""
    return StageResult(name, 'SKIP',
                        detail='dry-run (pass --live to execute)')


_STAGE_DISPATCH = {
    STAGE_PLAN:              _s_plan,
    STAGE_ESTIMATE:          _s_estimate,
    STAGE_CAPTURE_TARGET:    _s_capture_target,
    STAGE_STRUCTURE:         _s_structure,
    STAGE_USERS:             _s_users,
    STAGE_RECORDS_EXPORT:    _s_records_export,
    STAGE_CONVERT:           _s_convert,
    STAGE_RECORDS_IMPORT:    _s_records_import,
    STAGE_RECORDS_MANIFEST:  _s_records_manifest,
    STAGE_ATT_DOWNLOAD:      _s_att_download,
    STAGE_ATT_UPLOAD:        _s_att_upload,
    STAGE_RECORDS_CONVERT_TO_V3: _s_records_convert_to_v3,
    STAGE_RECORDS_REFERENCES_REWRITE: _s_records_references_rewrite,
    STAGE_RECORDS_SHARES_EXTRACT: _s_records_shares_extract,
    STAGE_RECORDS_SHARES_APPLY:   _s_records_shares_apply,
    STAGE_SF_RECONCILE:      _s_sf_reconcile,
    STAGE_VERIFY:            _s_verify,
    STAGE_RECONCILE:         _s_reconcile,
    STAGE_AUDIT_VERIFY:      _s_audit_verify,
}
