"""Direct-API enforcement setter — bypass Commander's CLI parser.

Port of migration_scripts/enforcement_direct_api.py. Some enforcement
types (`json`, `jsonarray`, any not listed in Commander's ENFORCEMENTS
dict) can't be expressed through `enterprise-role --enforcement KEY:VALUE`
because the CLI parser rejects them before they ever reach the API.

This module calls `role_enforcement_add/update/remove` directly via
`api.communicate`, the same path Commander uses internally.

It's opt-in and composable: `structure.step_enforcements` keeps using
the CLI path for everything the CLI can handle; callers drop down here
only for the types that the CLI refuses.
"""

import json
import logging


# Enforcement type categories (from Commander's constants.ENFORCEMENTS):
#   json                 — single JSON-object payload
#   jsonarray            — array-of-JSON-objects payload
#   two_factor_duration  — server-side keyword set ("login", "12_hours",
#                          "24_hours", "30_days", "forever") but live
#                          source data carries the internal storage
#                          format ("0,12,24"). The CLI parser ACCEPTS
#                          the string but the server REJECTS it with
#                          'expects "login", "12_hours", ...'. The
#                          direct API stores the raw value as-is, so
#                          round-tripping internal-format values
#                          succeeds via this path. (Live-verified
#                          2026-04-27 against MSP target.)
#   record_types         — JSON-encoded `{"std":[...], "ent":[...]}`
#                          referencing record type IDs. The CLI parser
#                          rejects the dict shape ('expected format:
#                          KEY:[VALUE]'). Direct API handles the JSON
#                          payload, BUT the IDs may be cross-tenant
#                          (especially `ent`, the enterprise types).
#                          Routed here so at least the std-only case
#                          works; ent-id translation is a separate
#                          follow-up.
UNSUPPORTED_CLI_TYPES = frozenset({
    'json', 'jsonarray', 'two_factor_duration',
})
# `record_types` is back on the CLI path: Commander's CLI parser
# expects comma-separated NAMES and translates to IDs internally.
# Source-side capture stores the post-translation IDs as JSON. We
# convert IDs → names via `record_types_value_to_names()` before
# sending so the CLI can re-translate them on target. See
# structure.py step_enforcements for the routing.


def unsupported_cli_keys():
    """Return the set of enforcement keys the CLI cannot handle."""
    try:
        from keepercommander.constants import ENFORCEMENTS
    except ImportError:
        return set()
    return {k for k, t in ENFORCEMENTS.items() if t in UNSUPPORTED_CLI_TYPES}


def is_cli_unsupported(key):
    """True if `key` is a known unsupported type OR unknown entirely
    (Commander may have added it post-release)."""
    try:
        from keepercommander.constants import ENFORCEMENTS
    except ImportError:
        return False
    etype = ENFORCEMENTS.get(key.lower(), '')
    return etype in UNSUPPORTED_CLI_TYPES or etype == ''


def resolve_role_id(params, role_name):
    """Find role_id by displayname or by numeric id; case-insensitive."""
    ent = getattr(params, 'enterprise', None) or {}
    for role in ent.get('roles') or []:
        data = role.get('data', {}) or {}
        display = (data.get('displayname') or role.get('name') or '').lower()
        if display == (role_name or '').lower():
            return role.get('role_id')
        if str(role.get('role_id')) == str(role_name):
            return role.get('role_id')
    return None


def _existing_enforcement(params, role_id, key):
    for re in (getattr(params, 'enterprise', {}) or {}).get('role_enforcements') or []:
        if re.get('role_id') == role_id:
            return re.get('enforcements', {}).get(key)
    return None


def _build_request(role_id, key, value, existing):
    """Choose the right server command + body based on existence + value."""
    rq = {'role_id': role_id, 'enforcement': key}

    if isinstance(value, bool):
        if not value:
            # remove: server doesn't read `value`
            rq['command'] = 'role_enforcement_remove'
        else:
            # Bug 48 (v1.5.3 + v1.5.5) — BOOLEAN-typed enforcements
            # require an explicit `value` field on the wire. v1.5.3
            # set `rq['value']='true'` (string) matching Commander's
            # SIMPLE-phase comment but the rehearsal-7 live run still
            # got rejected with `value=null` on
            # ALLOW_CAN_EDIT_EXTERNAL_SHARES. Tracing Commander source:
            # the SIMPLE-phase path (`enterprise.py:2580-2586`) OMITS
            # the value field for booleans (likely the source of the
            # `value=null` rejection in the first place); the BULK
            # `enforcement_add` path (`enterprise.py:2799-2817`) sends
            # `rq['value']=v` where `v` is Python bool `True`. Match
            # the BULK path: send Python `True` (bool), not string
            # `'true'`. The SDK's communicate path serializes bools
            # to JSON `true` / `false`, which is what the server
            # expects per BOOLEAN valueType.
            rq['command'] = ('role_enforcement_update' if existing
                              else 'role_enforcement_add')
            rq['value'] = True
    else:
        rq['command'] = 'role_enforcement_update' if existing else 'role_enforcement_add'
        if isinstance(value, (dict, list)):
            rq['value'] = json.dumps(value)
        elif isinstance(value, (int, float)):
            rq['value'] = str(value)
        else:
            rq['value'] = str(value)
    return rq


def set_enforcement(params, role_id, key, value, communicator=None):
    """Send role_enforcement_{add,update,remove} via api.communicate.

    `communicator`: optional callable(params, rq) → dict response. Injected
    for tests; defaults to `keepercommander.api.communicate`.
    """
    if communicator is None:
        from keepercommander import api
        communicator = api.communicate

    existing = _existing_enforcement(params, role_id, key)
    rq = _build_request(role_id, key, value, existing)
    try:
        rs = communicator(params, rq)
    except Exception as e:                             # noqa: BLE001
        return False, f'communicate raised: {e!r}'
    if isinstance(rs, dict) and rs.get('result') == 'success':
        return True, 'OK'
    return False, (rs.get('message') if isinstance(rs, dict) else str(rs))


def set_role_enforcements_direct(params, role_name, enforcements,
                                  *, communicator=None):
    """Set every key/value via direct API. Returns per-key result map.

    `enforcements`: {key: value} dict. Only unsupported-CLI keys should be
    passed here — caller is responsible for routing.
    """
    role_id = resolve_role_id(params, role_name)
    if role_id is None:
        return {key: (False, f'role {role_name!r} not found') for key in enforcements}

    results = {}
    for key, value in enforcements.items():
        ok, msg = set_enforcement(params, role_id, key, value,
                                   communicator=communicator)
        results[key] = (ok, msg)
        logging.info('  %s %s.%s: %s',
                     '✓' if ok else '✗', role_name, key, msg)
    return results


def record_types_value_to_names(value, params=None, communicator=None):
    """Convert a `record_types`-shaped enforcement value to the
    comma-separated NAMES form Commander's CLI expects.

    Live-tenant inventory captures `restrict_record_types` as the
    post-translation JSON `{"std":[<ids>],"ent":[<ids>]}` (Commander
    enterprise.py:2463-2507 — names → IDs at write time). On
    re-import, the CLI parser expects NAMES and re-translates. The
    raw IDs round-tripped via direct API or CLI both fail.

    Resolution path:
      1. If `value` is already a string without `{`, treat as already-
         names (idempotent passthrough).
      2. Parse JSON; collect `std` + `ent` IDs.
      3. Fetch target's `record_types` table via `vault/get_record_types`
         (same endpoint Commander uses) and build an id → name map.
      4. Return ','.join(names) for IDs we resolved. IDs we couldn't
         resolve (target-tenant-missing enterprise types) come back
         as the literal `<unknown:<id>>` token so the operator sees
         what's missing instead of silently dropping.

    `params`/`communicator` are injected for tests; production uses
    `keepercommander.api.communicate_rest` against `params`.
    """
    # Already in CLI-acceptable form
    if isinstance(value, str) and '{' not in value:
        return value
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError):
        return value
    if not isinstance(parsed, dict):
        return value
    std_ids = list(parsed.get('std') or [])
    ent_ids = list(parsed.get('ent') or [])
    if not (std_ids or ent_ids):
        # Empty enforcement — Commander treats as 'all' (cleared).
        # Keep the keyword to make the intent visible.
        return 'all'

    # Fetch the lookup table. Defer keepercommander imports so unit
    # tests can stub out `communicator`.
    id_to_name = {}
    try:
        if communicator is None:
            from keepercommander import api
            from keepercommander.proto import record_pb2
            rq = record_pb2.RecordTypesRequest()
            rq.standard = True
            rq.user = True
            rq.enterprise = True
            rs = api.communicate_rest(
                params, rq, 'vault/get_record_types',
                rs_type=record_pb2.RecordTypesResponse)
            for rti in rs.recordTypes:
                try:
                    rto = json.loads(rti.content)
                    name = rto.get('$id')
                    if name:
                        id_to_name[rti.recordTypeId] = name
                except (TypeError, ValueError):
                    pass
        else:
            id_to_name = communicator() or {}
    except Exception:                                  # noqa: BLE001
        # Probe failed (offline / proto unavailable). Fall back to
        # passing the raw value through; Commander will reject it,
        # but at least we don't crash the migration.
        return value

    names = []
    for rid in std_ids + ent_ids:
        n = id_to_name.get(rid)
        names.append(n if n else f'<unknown:{rid}>')
    return ','.join(names)


def partition_enforcements(enforcements):
    """Split an enforcement dict into (cli_supported, direct_api_only).

    Used by structure.step_enforcements to route each key to the right path.
    """
    try:
        from keepercommander.constants import ENFORCEMENTS
    except ImportError:
        return dict(enforcements), {}

    cli = {}
    direct = {}
    for key, value in enforcements.items():
        etype = ENFORCEMENTS.get(key.lower(), '')
        if etype in UNSUPPORTED_CLI_TYPES or etype == '':
            direct[key] = value
        else:
            cli[key] = value
    return cli, direct
