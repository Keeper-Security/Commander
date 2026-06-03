"""
Layer-B fallback decision tests (plan §13.8 T2 / task #29).

Covers the KEEPER_DAG_LB_FALLBACK env-var-controlled fallback policy:
- Default (env unset) → fallback enabled.
- Truthy values ('1', 'true', 'yes', 'on') → fallback enabled.
- Falsy values ('0', 'false', 'no', 'off', '') → strict mode (no fallback).
- Only RRC_NOT_ALLOWED / RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED warrant fallback.
- Non-permission errors (other RRC codes, generic exceptions) never trigger fallback.
- Backward compat: legacy generic Exception with the code string in its message is recognized.
"""
import os
from unittest.mock import patch

import pytest

from keepercommander.commands.pam._layer_b import (
    RouterResponseError,
    _layer_b_fallback_enabled,
    should_fallback_on_layer_b_error,
)


# --------------------------------------------------------------------------- #
# RouterResponseError                                                          #
# --------------------------------------------------------------------------- #


def test_router_response_error_is_exception_subclass():
    """Existing `except Exception:` handlers must still catch this."""
    err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
    assert isinstance(err, Exception)


def test_router_response_error_carries_code_and_message():
    err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
    assert err.response_code == 13
    assert err.response_code_name == 'RRC_NOT_ALLOWED'
    assert 'denied' in str(err)
    assert 'RRC_NOT_ALLOWED' in str(err)


# --------------------------------------------------------------------------- #
# Env var parsing                                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('value', ['1', 'true', 'TRUE', 'True', 'yes', 'YES', 'on', 'ON'])
def test_fallback_enabled_for_truthy_env(value):
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': value}):
        assert _layer_b_fallback_enabled() is True


@pytest.mark.parametrize('value', ['0', 'false', 'FALSE', 'False', 'no', 'NO', 'off', 'OFF', ''])
def test_fallback_disabled_for_falsy_env(value):
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': value}):
        assert _layer_b_fallback_enabled() is False


def test_fallback_default_when_env_unset():
    """Default OFF (strict mode). Mature endpoints (configure_resource,
    set_record_rotation) are deployed everywhere — denials are real and should
    propagate. Set KEEPER_DAG_LB_FALLBACK=1 only to opt INTO legacy fallback
    during the rollout of a new endpoint not on the always-downgrade list."""
    env_without = {k: v for k, v in os.environ.items() if k != 'KEEPER_DAG_LB_FALLBACK'}
    with patch.dict(os.environ, env_without, clear=True):
        assert _layer_b_fallback_enabled() is False


# --------------------------------------------------------------------------- #
# Fallback decision logic                                                      #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('code_name', [
    'RRC_NOT_ALLOWED',
    'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED',
    'RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED',
])
def test_fallback_on_permission_denied_when_enabled(code_name):
    err = RouterResponseError(13, code_name, 'denied')
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}):
        assert should_fallback_on_layer_b_error(err) is True


@pytest.mark.parametrize('code_name', [
    'RRC_NOT_ALLOWED',
    'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED',
    'RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED',
])
def test_no_fallback_on_permission_denied_when_disabled(code_name):
    err = RouterResponseError(13, code_name, 'denied')
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '0'}):
        assert should_fallback_on_layer_b_error(err) is False


@pytest.mark.parametrize('code_name', ['RRC_OK', 'RRC_BAD_REQUEST', 'RRC_GENERAL_ERROR', 'RRC_TIMEOUT'])
def test_no_fallback_on_non_permission_codes(code_name):
    """Only permission-denial codes trigger fallback; other errors propagate."""
    err = RouterResponseError(99, code_name, 'something broke')
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}):
        assert should_fallback_on_layer_b_error(err) is False


def test_no_fallback_on_unrelated_exception():
    """Generic exceptions (network errors, value errors, etc.) never trigger fallback."""
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}):
        assert should_fallback_on_layer_b_error(ValueError('nope')) is False
        assert should_fallback_on_layer_b_error(KeyError('missing')) is False
        assert should_fallback_on_layer_b_error(RuntimeError('boom')) is False


def test_fallback_recognizes_legacy_exception_with_code_in_message():
    """Backward compat: pre-RouterResponseError code paths still surface as fallback-worthy."""
    legacy = Exception('something failed Response code: RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED')
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1'}):
        assert should_fallback_on_layer_b_error(legacy) is True


def test_legacy_message_match_respects_disabled_flag():
    """Even with the legacy message pattern, disabled flag wins."""
    legacy = Exception('denied Response code: RRC_NOT_ALLOWED')
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '0'}):
        assert should_fallback_on_layer_b_error(legacy) is False


# --------------------------------------------------------------------------- #
# Feature-disabled cache: HTTP 404 + per-code marking behavior                 #
# --------------------------------------------------------------------------- #


from keepercommander.commands.pam._layer_b import (
    clear_layer_b_feature_cache,
    is_layer_b_feature_disabled,
    mark_layer_b_feature_disabled,
    _feature_cache_ttl_sec,
)
from keepercommander.error import KeeperApiError


@pytest.fixture(autouse=True)
def _clear_cache_between_tests():
    clear_layer_b_feature_cache()
    yield
    clear_layer_b_feature_cache()


def test_cache_miss_when_unmarked():
    assert is_layer_b_feature_disabled('http://host', 'ep') is False


def test_cache_hit_after_marking():
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}):
        mark_layer_b_feature_disabled('http://host', 'configure_resource')
        assert is_layer_b_feature_disabled('http://host', 'configure_resource') is True


def test_cache_isolated_per_host_endpoint():
    """Different host or endpoint pairs are independent cache keys."""
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}):
        mark_layer_b_feature_disabled('http://host-a', 'configure_resource')
        assert is_layer_b_feature_disabled('http://host-a', 'configure_resource') is True
        # Different host: not cached
        assert is_layer_b_feature_disabled('http://host-b', 'configure_resource') is False
        # Same host, different endpoint: not cached
        assert is_layer_b_feature_disabled('http://host-a', 'set_record_rotation') is False


def test_cache_ttl_zero_disables_marking():
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '0'}):
        mark_layer_b_feature_disabled('http://host', 'ep')
        # TTL=0 means caching disabled entirely
        assert is_layer_b_feature_disabled('http://host', 'ep') is False


def test_cache_ttl_negative_treated_as_disabled():
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '-5'}):
        assert _feature_cache_ttl_sec() == 0


def test_cache_ttl_garbage_treated_as_disabled():
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FEATURE_CACHE_TTL': 'not-a-number'}):
        assert _feature_cache_ttl_sec() == 0


def test_cache_entry_expires():
    """A cache entry past its expiry is treated as a miss and evicted."""
    import time
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '1'}):
        mark_layer_b_feature_disabled('http://host', 'ep')
        assert is_layer_b_feature_disabled('http://host', 'ep') is True
        # Sleep slightly longer than TTL
        time.sleep(1.1)
        assert is_layer_b_feature_disabled('http://host', 'ep') is False


def test_http_404_triggers_fallback_and_cache():
    """An older krouter without the new endpoint returns HTTP 404. The decision
    function should fall back AND mark the cache so we don't keep round-tripping."""
    err = KeeperApiError(404, 'Not Found')
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}):
        assert should_fallback_on_layer_b_error(err, host='http://host', endpoint='configure_network_graph') is True
        assert is_layer_b_feature_disabled('http://host', 'configure_network_graph') is True


def test_rrc_not_allowed_per_user_does_not_cache():
    """Per-user RRC_NOT_ALLOWED falls back per-call but must NOT poison the cache
    (the answer depends on which user/record, not on the host)."""
    err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}):
        assert should_fallback_on_layer_b_error(err, host='http://host', endpoint='configure_resource') is True
        # Cache MUST NOT be poisoned by a per-user denial
        assert is_layer_b_feature_disabled('http://host', 'configure_resource') is False


@pytest.mark.parametrize('code_name', [
    'RRC_NOT_ALLOWED',
    'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED',
    'RRC_NOT_ALLOWED_PAM_CONFIG_FEATURES_NOT_ENABLED',
])
def test_rrc_codes_never_mark_cache(code_name):
    """RRC codes (per-user OR tenant-level) fall back per-call but never mark
    the (host, endpoint) cache. Only HTTP 404 marks the cache. Reasoning:
    tenant admins can flip features at runtime, so a tenant-level denial isn't
    a stable signal; per-user denials depend on caller context."""
    err = RouterResponseError(8, code_name, 'denied')
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}):
        assert should_fallback_on_layer_b_error(err, host='http://host', endpoint='configure_resource') is True
        # Cache MUST NOT be marked — only 404 marks the cache.
        assert is_layer_b_feature_disabled('http://host', 'configure_resource') is False


def test_marking_without_host_or_endpoint_is_noop():
    """When host or endpoint is missing, marking silently no-ops so callers that
    don't have routing context (e.g. legacy paths) don't crash."""
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}):
        mark_layer_b_feature_disabled(None, 'ep')
        mark_layer_b_feature_disabled('http://host', None)
        mark_layer_b_feature_disabled('', '')
        # No exceptions raised, and the cache has no entries
        assert is_layer_b_feature_disabled('http://host', 'ep') is False


# --------------------------------------------------------------------------- #
# Per-endpoint always-downgrade policy (mechanism + strict default behavior)  #
# --------------------------------------------------------------------------- #


def _env_without_fallback():
    return {k: v for k, v in os.environ.items() if k != 'KEEPER_DAG_LB_FALLBACK'}


def test_always_downgrade_set_currently_empty():
    """`_LB_ALWAYS_DOWNGRADE_ENDPOINTS` is intentionally empty — all three
    Layer-B endpoints (configure_resource, set_record_rotation,
    configure_network_graph) honor `KEEPER_DAG_LB_FALLBACK` uniformly. The
    frozenset is preserved as scaffolding for future endpoints whose rollout
    window needs an unconditional auto-downgrade safety net. If this test
    fails (the set became non-empty), double-check the addition is intentional
    and update the module docstring + this test."""
    from keepercommander.commands.pam._layer_b import _LB_ALWAYS_DOWNGRADE_ENDPOINTS
    assert _LB_ALWAYS_DOWNGRADE_ENDPOINTS == frozenset(), (
        f'_LB_ALWAYS_DOWNGRADE_ENDPOINTS is no longer empty: '
        f'{set(_LB_ALWAYS_DOWNGRADE_ENDPOINTS)}'
    )


def test_always_downgrade_mechanism_works_when_endpoint_added(monkeypatch):
    """Verify the always-downgrade mechanism via a hypothetical future endpoint.
    When an endpoint IS on the list, 404 and RRC denials fall back even with
    KEEPER_DAG_LB_FALLBACK unset (strict default)."""
    import keepercommander.commands.pam._layer_b as lb
    monkeypatch.setattr(lb, '_LB_ALWAYS_DOWNGRADE_ENDPOINTS', frozenset({'hypothetical_endpoint'}))

    with patch.dict(os.environ, _env_without_fallback(), clear=True):
        # 404 → fall back + cache
        assert should_fallback_on_layer_b_error(
            KeeperApiError(404, 'Not Found'),
            host='http://host', endpoint='hypothetical_endpoint'
        ) is True
        # RRC denial → fall back (no cache)
        assert should_fallback_on_layer_b_error(
            RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied'),
            host='http://host', endpoint='hypothetical_endpoint'
        ) is True


def test_always_downgrade_scoping(monkeypatch):
    """Per-endpoint policy is scoped — an endpoint on the always-downgrade
    list must NOT affect the decision for any other endpoint."""
    import keepercommander.commands.pam._layer_b as lb
    monkeypatch.setattr(lb, '_LB_ALWAYS_DOWNGRADE_ENDPOINTS', frozenset({'hypothetical_endpoint'}))

    err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
    with patch.dict(os.environ, _env_without_fallback(), clear=True):
        # hypothetical_endpoint: falls back (on the list)
        assert should_fallback_on_layer_b_error(err, host='h', endpoint='hypothetical_endpoint') is True
        # All real endpoints: propagate (none on the list, env unset)
        for ep in ('configure_resource', 'set_record_rotation', 'configure_network_graph'):
            assert should_fallback_on_layer_b_error(err, host='h', endpoint=ep) is False, (
                f'{ep} should propagate in strict mode'
            )


def test_configure_resource_strict_on_404_when_env_unset():
    """Mature endpoint `configure_resource`: 404 propagates when env var is
    unset (strict default). Opt INTO fallback by setting KEEPER_DAG_LB_FALLBACK=1."""
    err = KeeperApiError(404, 'Not Found')
    with patch.dict(os.environ, _env_without_fallback(), clear=True):
        assert should_fallback_on_layer_b_error(
            err, host='http://host', endpoint='configure_resource'
        ) is False


def test_configure_resource_falls_back_on_404_when_env_on():
    """Opt-in path: KEEPER_DAG_LB_FALLBACK=1 makes 404 fall back for
    `configure_resource` too."""
    err = KeeperApiError(404, 'Not Found')
    with patch.dict(os.environ, {'KEEPER_DAG_LB_FALLBACK': '1', 'KEEPER_DAG_LB_FEATURE_CACHE_TTL': '300'}):
        assert should_fallback_on_layer_b_error(
            err, host='http://host', endpoint='configure_resource'
        ) is True
        # 404 marks the cache regardless of which endpoint
        assert is_layer_b_feature_disabled('http://host', 'configure_resource') is True


def test_configure_resource_strict_on_rrc_when_env_unset():
    """Mature endpoint, RRC denial: propagates when env var is unset. This is
    the security-relevant default — denials are real and should not silently
    fall back to a legacy write that bypasses the check."""
    err = RouterResponseError(13, 'RRC_NOT_ALLOWED', 'denied')
    with patch.dict(os.environ, _env_without_fallback(), clear=True):
        assert should_fallback_on_layer_b_error(
            err, host='http://host', endpoint='configure_resource'
        ) is False


def test_transient_errors_never_downgrade(monkeypatch):
    """5xx, ConnectionError, generic exceptions never trigger downgrade for
    any endpoint — including any future always-downgrade entries. Transient
    failures propagate so an operator notices (and the existing requests-level
    retry handles intermittent blips)."""
    import keepercommander.commands.pam._layer_b as lb
    monkeypatch.setattr(lb, '_LB_ALWAYS_DOWNGRADE_ENDPOINTS', frozenset({'hypothetical_endpoint'}))

    transient = [
        KeeperApiError(500, 'Internal Server Error'),
        KeeperApiError(503, 'Service Unavailable'),
        ConnectionError('connection refused'),
        TimeoutError('read timeout'),
        RuntimeError('something else'),
    ]
    with patch.dict(os.environ, _env_without_fallback(), clear=True):
        for err in transient:
            for ep in ('hypothetical_endpoint', 'configure_resource',
                      'set_record_rotation', 'configure_network_graph'):
                assert should_fallback_on_layer_b_error(
                    err, host='http://host', endpoint=ep
                ) is False, f'{type(err).__name__} should not trigger downgrade on {ep}'
