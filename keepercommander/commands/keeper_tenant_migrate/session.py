"""Session context detection — who am I, which tenant, which role?

The wizard runs in whichever shell the admin launched. It needs to know:
  - which Keeper user is logged in (`params.user`)
  - which region / enterprise that session is scoped to
  - whether this session is the SOURCE or TARGET of an in-progress run
    (if a run-spec + run-dir are available)

`detect_session(params)` returns a plain dict — no Commander dependency
for callers that already have `params`.

`detect_session_role(params, run_spec)` compares the session's
user/enterprise against the run-spec entries; returns 'source',
'target', or 'unknown'.

All pure functions — tests drive with a stub `params` object.
"""

from typing import Any, Dict, Optional


def _keeper_dc_for_server(server: str) -> str:
    """Duplicated from commands.py — kept pure to avoid a circular import."""
    if not server:
        return ''
    s = server.lower()
    if '.jp' in s:
        return 'JP'
    if '.eu' in s:
        return 'EU'
    if '.com.au' in s:
        return 'AU'
    if 'govcloud' in s:
        return 'GOV'
    if '.ca' in s:
        return 'CA'
    if 'keepersecurity' in s:
        return 'US'
    return ''


def detect_session(params) -> Dict[str, Any]:
    """Return {user, server, region, enterprise_name, is_msp, mc_count,
    session_token_present} for the current Commander session."""
    ent = getattr(params, 'enterprise', None) or {}
    server = getattr(params, 'server', '') or ''
    mc_count = len(ent.get('managed_companies', []) or [])
    return {
        'user': getattr(params, 'user', '') or '',
        'server': server,
        'region': _keeper_dc_for_server(server),
        'enterprise_name': ent.get('enterprise_name', '') or '',
        'is_msp': mc_count > 0 or bool(ent.get('msp_tree_key')),
        'mc_count': mc_count,
        'session_token_present': bool(getattr(params, 'session_token', '')),
    }


def detect_session_role(params, run_spec, *, source_name: str = '',
                         target_name: str = '') -> str:
    """Return 'source' | 'target' | 'unknown' by matching the session
    against the spec's tenant entries.

    If `source_name` / `target_name` are given they point at entries in
    a registry the caller has already loaded. Otherwise the spec itself
    is compared against the current session (useful when migration.yaml
    holds a single-sided spec like `source: {...}`).
    """
    ctx = detect_session(params)
    cur_user = ctx['user'].lower()
    cur_ent = ctx['enterprise_name'].lower()
    cur_region = ctx['region']

    # If we have no signal at all (no user, no enterprise, no region),
    # we can't classify.
    if not (cur_user or cur_ent or cur_region):
        return 'unknown'

    def _match(spec_side: Dict[str, Any]) -> bool:
        if not spec_side:
            return False
        # Match by any of: expected enterprise name, expected region + tenant_type
        enterprise_hint = (spec_side.get('enterprise_name') or '').lower()
        if enterprise_hint and enterprise_hint == cur_ent:
            return True
        region_hint = (spec_side.get('region') or '').upper()
        if region_hint and region_hint == cur_region:
            # region match is weaker — combine with tenant_type if present
            if spec_side.get('tenant_type') and ctx['is_msp']:
                return spec_side['tenant_type'] in ('msp', 'mc')
            if spec_side.get('tenant_type') == 'enterprise' and not ctx['is_msp']:
                return True
            # If no tenant-type hint, region alone counts
            if not spec_side.get('tenant_type'):
                return True
        user_hint = (spec_side.get('user') or '').lower()
        if user_hint and user_hint == cur_user:
            return True
        return False

    if isinstance(run_spec, dict):
        src_hit = _match(run_spec.get('source') or {})
        tgt_hit = _match(run_spec.get('target') or {})
        # Ambiguity guard: when a session matches BOTH sides (e.g.
        # source.region=EU and target.region=EU without distinguishing
        # enterprise_name / user hints), returning 'source' silently
        # would cause `enforce_source_mode` to block legitimate target
        # writes — or worse, bypass it. Refuse to classify in that
        # case so callers are forced to tighten the spec.
        if src_hit and tgt_hit:
            import logging
            logging.warning(
                "session matches BOTH source and target in run-spec — "
                "tighten source.enterprise_name / target.enterprise_name "
                "or .user to disambiguate; treating as 'unknown'."
            )
            return 'unknown'
        if src_hit:
            return 'source'
        if tgt_hit:
            return 'target'

    return 'unknown'


def format_session_banner(ctx: Dict[str, Any]) -> str:
    """Human-readable one-screen summary of detect_session() output."""
    if not ctx.get('session_token_present'):
        return '  ✗ No active session — log in with `keeper login` first.'
    lines = []
    lines.append('  Commander session')
    lines.append(f"    user:            {ctx['user']}")
    lines.append(f"    region:          {ctx['region'] or '?'} "
                 f"({ctx['server'] or '?'})")
    lines.append(f"    enterprise:      {ctx['enterprise_name'] or '—'}")
    if ctx['is_msp']:
        lines.append(f"    role:            MSP with {ctx['mc_count']} MC(s)")
    else:
        lines.append(f"    role:            enterprise")
    return '\n'.join(lines)
