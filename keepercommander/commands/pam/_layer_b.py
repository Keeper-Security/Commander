"""
Layer-B (permission-checked configure_resource / set_record_rotation /
configure_network_graph) fallback infrastructure. Isolated in its own module so
it can be imported without triggering the pre-existing circular import in
`pam/router_helper.py` -> `gateway_helper` -> `commands.utils` -> `ksm` ->
`record` -> `ksm`.

Hosts:
- `RouterResponseError` — raised by `_post_request_to_router` on non-OK
  `RouterResponseCode`. Subclass of Exception for backward compat.
- `should_fallback_on_layer_b_error()` — the per-endpoint fallback decision.
- `(host, endpoint)` cache — marked only on HTTP 404 (endpoint not deployed
  on this krouter build). RRC permission codes are NOT cached because tenant
  admins can flip features and per-user denials are call-specific.

Policy (default semantics):

| Endpoint                  | HTTP 404                     | RRC denial                          | Transient (5xx, conn) |
|---------------------------|------------------------------|-------------------------------------|-----------------------|
| configure_resource        | propagate (env=1 → fallback) | propagate (env=1 → fallback)        | propagate             |
| set_record_rotation       | propagate                    | propagate (no fallback ever)        | propagate             |
| configure_network_graph   | propagate (env=1 → fallback) | propagate (env=1 → fallback)        | propagate             |

All three Layer-B endpoints honor the same env-var policy. The
`_LB_ALWAYS_DOWNGRADE_ENDPOINTS` frozenset is preserved (empty) as scaffolding
for future endpoints whose rollout window genuinely needs an unconditional
auto-downgrade safety net.

Env-var opt-in (`KEEPER_DAG_LB_FALLBACK=1`) extends "fall back on 404 + RRC"
to every endpoint — use during the rollout of any future new endpoint that
isn't worth adding to the always-downgrade set.
"""
import os
import threading
import time
from typing import Optional


class RouterResponseError(Exception):
    """Raised when krouter responds with a non-OK `RouterResponseCode`.

    Carries `.response_code` (int) and `.response_code_name` (str) so callers
    can branch on specific failure modes — most importantly, the permission-denial
    codes that drive the Layer-B fallback policy.
    """
    def __init__(self, response_code: int, response_code_name: str, message: str):
        super().__init__(f'{message} Response code: {response_code_name}')
        self.response_code = response_code
        self.response_code_name = response_code_name


# Codes that warrant fallback when fallback is in effect. Includes the per-user
# RRC_NOT_ALLOWED — when this fires under fallback, the legacy DAG-write reopens
# the credential-link gap for that single call. That's the documented trade-off
# of enabling fallback during rollout.
_LB_PERMISSION_DENIED_CODES = frozenset({
    'RRC_NOT_ALLOWED',
    'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED',
    'RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED',
})


# Per-endpoint override: endpoints listed here always allow auto-downgrade
# (404 + RRC) regardless of KEEPER_DAG_LB_FALLBACK. Used for endpoints whose
# krouter rollout window is long (DEV → QA → PROD → GovCloud) so Commander
# has to work against both upgraded and not-yet-upgraded krouters in the field.
#
# **When to ADD an endpoint:** during the rollout of a new krouter endpoint
# that ships incrementally across environments. Add here so Commander gracefully
# falls back to legacy DAG-write on krouters that haven't received the update.
#
# **When to REMOVE an endpoint:** once it's deployed to every production
# krouter AND the Vault is using it in anger. After removal, denials propagate
# loudly and per-feature enforcement checks fire by default.
_LB_ALWAYS_DOWNGRADE_ENDPOINTS = frozenset({
    # Currently empty — kept as scaffolding for future endpoints whose krouter
    # rollout window genuinely needs unconditional auto-downgrade (e.g. an
    # endpoint that ships incrementally across DEV → QA → PROD → GovCloud and
    # Commander has to keep working against all of them at once). To use:
    # add the endpoint name as a string here.
    #
    # `configure_network_graph` was a candidate during its initial rollout
    # (krouter release/1.7.1+, Vault adoption still in progress) — leaving
    # the example below as a template:
    #
    #     'configure_network_graph',
})


def _layer_b_fallback_enabled() -> bool:
    """Whether KEEPER_DAG_LB_FALLBACK env var opts INTO legacy fallback.

    **Default OFF (strict mode)** — the mature Layer-B endpoints
    (`configure_resource`, `set_record_rotation`) are deployed everywhere;
    denials are real and should propagate so the caller sees them.

    Set to '1' / 'true' / 'yes' / 'on' to opt INTO fallback during the rollout
    of a new endpoint that isn't (yet) on `_LB_ALWAYS_DOWNGRADE_ENDPOINTS`.
    Endpoints on that set auto-downgrade regardless of this flag.
    """
    raw = os.environ.get("KEEPER_DAG_LB_FALLBACK", "").strip().lower()
    return raw in ('1', 'true', 'yes', 'on')


def _feature_cache_ttl_sec() -> int:
    """TTL (seconds) for the (host, endpoint) feature-disabled cache.

    Default 300s (5 min). `KEEPER_DAG_LB_FEATURE_CACHE_TTL=0` disables caching
    entirely (every call hits the new API). Negative or non-integer → 0.
    """
    raw = os.environ.get("KEEPER_DAG_LB_FEATURE_CACHE_TTL", "300").strip()
    try:
        ttl = int(raw)
        return ttl if ttl > 0 else 0
    except ValueError:
        return 0


_feature_cache_lock = threading.Lock()
# (host, endpoint) -> epoch seconds at which the cache entry expires.
_feature_cache = {}  # type: dict


def mark_layer_b_feature_disabled(host: Optional[str], endpoint: Optional[str]) -> None:
    """Remember that (host, endpoint) reported HTTP 404 (endpoint not deployed).

    Subsequent `is_layer_b_feature_disabled(host, endpoint)` calls return True
    until the TTL expires, letting callers skip the new API entirely.

    Only HTTP 404 marks the cache — RRC tenant-level codes are NOT cached
    because admins can flip features mid-session; per-user RRC_NOT_ALLOWED is
    NEVER cached because the answer is per-call.
    """
    ttl = _feature_cache_ttl_sec()
    if ttl <= 0 or not host or not endpoint:
        return
    with _feature_cache_lock:
        _feature_cache[(host, endpoint)] = time.time() + ttl


def is_layer_b_feature_disabled(host: Optional[str], endpoint: Optional[str]) -> bool:
    """True if a recent call to (host, endpoint) returned HTTP 404 AND the
    TTL has not yet expired."""
    if not host or not endpoint:
        return False
    if _feature_cache_ttl_sec() <= 0:
        return False
    now = time.time()
    with _feature_cache_lock:
        expiry = _feature_cache.get((host, endpoint))
        if expiry is None:
            return False
        if expiry <= now:
            _feature_cache.pop((host, endpoint), None)
            return False
        return True


def clear_layer_b_feature_cache() -> None:
    """Test helper — wipe the (host, endpoint) cache."""
    with _feature_cache_lock:
        _feature_cache.clear()


def _is_http_404(err: Exception) -> bool:
    """KeeperApiError carries the HTTP status code as `result_code` (or as a
    leading "404:" in str(err) on older paths)."""
    code = getattr(err, 'result_code', None)
    if isinstance(code, int) and code == 404:
        return True
    if isinstance(code, str) and code == '404':
        return True
    return str(err).startswith('404')


def _fallback_allowed(endpoint: Optional[str]) -> bool:
    """Per-endpoint policy: True if this endpoint allows legacy fallback right
    now. Always-downgrade endpoints return True regardless of env var; others
    follow KEEPER_DAG_LB_FALLBACK."""
    if endpoint and endpoint in _LB_ALWAYS_DOWNGRADE_ENDPOINTS:
        return True
    return _layer_b_fallback_enabled()


def should_fallback_on_layer_b_error(err: Exception, host: Optional[str] = None, endpoint: Optional[str] = None) -> bool:
    """Return True iff `err` warrants legacy fallback for this endpoint.

    Decision matrix (see module docstring for full policy table):
    - HTTP 404 on always-downgrade endpoint → fall back + mark cache.
    - HTTP 404 on other endpoint with env var on → fall back + mark cache.
    - HTTP 404 on other endpoint with env var off → propagate (strict).
    - RRC permission code on always-downgrade endpoint → fall back (no cache).
    - RRC permission code on other endpoint with env var on → fall back (no cache).
    - RRC permission code on other endpoint with env var off → propagate.
    - Transient errors (5xx, connection, unrelated exceptions) → propagate.

    The (host, endpoint) cache is marked ONLY on 404; tenant-level RRC codes
    are not cached because admins can flip features at runtime.
    """
    fallback_active = _fallback_allowed(endpoint)

    # HTTP 404 → endpoint not deployed on this krouter build.
    if _is_http_404(err):
        if fallback_active:
            mark_layer_b_feature_disabled(host, endpoint)
            return True
        return False

    if not fallback_active:
        return False

    # RRC permission codes
    if isinstance(err, RouterResponseError):
        return err.response_code_name in _LB_PERMISSION_DENIED_CODES

    # Transitional: legacy paths may still raise plain Exception with the code
    # embedded in str(err).
    msg = str(err)
    return any(code in msg for code in _LB_PERMISSION_DENIED_CODES)
