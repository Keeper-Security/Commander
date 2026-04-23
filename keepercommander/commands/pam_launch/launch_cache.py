#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
# Keeper Commander — PAM launch "optimistic" cache.
#
# ``pam launch`` pre-phase work (TunnelDAG build + find_gateway + optional
# online probe) is ~2.3s of HTTP round-trips per launch on a fresh session
# (see the ``pam-launch:execute`` checkpoints). Almost all of that resolves
# to values that rarely change across launches of the same record: the
# DAG-linked launch credential UID, the gateway UID, and the config UID.
#
# This module holds an in-memory cache keyed by ``record_uid`` and exposes a
# "hit + background-refresh" flow:
#
#   1. On cache HIT, ``pam launch`` uses the cached values immediately and
#      spawns a daemon thread that rebuilds the DAG + re-resolves the
#      gateway. The background thread updates the cache for the NEXT launch
#      if any value changed (e.g. rotated credential, reassigned gateway).
#      Stale-hit cost: one failing launch; the refresh repopulates in
#      parallel so the retry sees fresh data.
#
#   2. On cache MISS (first launch of a record in this Commander session),
#      the existing sequential flow runs and the resolved values are stored.
#
# Scope is deliberately in-memory / session-scoped: no on-disk persistence,
# no explicit TTL. Closing Commander drops the cache. This matches Web
# Vault's behavior (each page load re-resolves) and avoids stale-on-disk
# headaches across version upgrades.

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Dict, Optional

_LOG = logging.getLogger(__name__)

# Cache value fields:
#   dag_linked_uid:  Optional[str]   — DAG-resolved launch credential UID, or None
#   config_uid:      Optional[str]   — PAM configuration record UID
#   gateway_uid:     str             — Gateway (controller) UID, base64-url encoded
#   gateway_name:    str             — Controller display name (for user-facing logs)
#   timestamp:       float           — monotonic ``time.time()`` when populated/refreshed
_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_LOCK = threading.Lock()

# Single in-flight refresh per record — avoids N threads hitting the same
# endpoints when several launches fire back-to-back on the same record.
_REFRESHING: Dict[str, bool] = {}

_CACHE_VALUE_KEYS = ('dag_linked_uid', 'config_uid', 'gateway_uid')


def get(record_uid: str) -> Optional[Dict[str, Any]]:
    """Return a shallow copy of the cache entry for ``record_uid``, or None.

    Returns a copy so callers can safely mutate the dict (e.g. add
    ``gateway_proto=None``) without disturbing the shared cache state.
    """
    with _CACHE_LOCK:
        entry = _CACHE.get(record_uid)
        if entry is None:
            return None
        return dict(entry)


def put(record_uid: str, entry: Dict[str, Any]) -> None:
    """Insert / overwrite the cache entry for ``record_uid``.

    ``entry`` must carry ``dag_linked_uid`` (may be None), ``config_uid``,
    ``gateway_uid``, and ``gateway_name``. ``timestamp`` is set here.
    """
    with _CACHE_LOCK:
        stored = dict(entry)
        stored['timestamp'] = time.time()
        _CACHE[record_uid] = stored


def invalidate(record_uid: str) -> None:
    """Drop the cache entry for ``record_uid`` (e.g. after a launch failure
    that clearly indicates stale cache)."""
    with _CACHE_LOCK:
        _CACHE.pop(record_uid, None)


def _entries_differ(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """True if any of the load-bearing fields differ between two entries."""
    return any(a.get(k) != b.get(k) for k in _CACHE_VALUE_KEYS)


def spawn_refresh(record_uid: str, fetch_fn: Callable[[], Optional[Dict[str, Any]]]) -> None:
    """Spawn a daemon thread that calls ``fetch_fn()`` and, if it returns a
    new entry dict, updates the cache for the NEXT launch.

    ``fetch_fn`` should perform the full fresh resolution (TunnelDAG build +
    find_gateway) and return a dict with ``dag_linked_uid`` / ``config_uid``
    / ``gateway_uid`` / ``gateway_name``, or None if resolution failed (e.g.
    transient network error). A single in-flight refresh per record is
    enforced — concurrent launches on the same record share one refresh.
    """
    with _CACHE_LOCK:
        if _REFRESHING.get(record_uid):
            _LOG.debug('pam-launch cache: refresh already in-flight for %s, skipping', record_uid)
            return
        _REFRESHING[record_uid] = True

    def _run_refresh() -> None:
        try:
            fresh = fetch_fn()
            if not fresh:
                _LOG.debug('pam-launch cache: refresh returned no entry for %s', record_uid)
                return
            old = get(record_uid)
            put(record_uid, fresh)
            if old is not None and _entries_differ(old, fresh):
                _LOG.info(
                    'pam-launch cache: refreshed %s — values changed '
                    '(dag_linked_uid=%s→%s, gateway_uid=%s→%s)',
                    record_uid,
                    old.get('dag_linked_uid'), fresh.get('dag_linked_uid'),
                    old.get('gateway_uid'), fresh.get('gateway_uid'),
                )
            else:
                _LOG.debug('pam-launch cache: refreshed %s (no change)', record_uid)
        except Exception as e:
            # Background refresh must never crash the main launch. Log and move on.
            _LOG.debug('pam-launch cache: refresh failed for %s: %s', record_uid, e)
        finally:
            with _CACHE_LOCK:
                _REFRESHING.pop(record_uid, None)

    t = threading.Thread(
        target=_run_refresh,
        daemon=True,
        name=f'pam-launch-cache-refresh-{record_uid[:8] if record_uid else "?"}',
    )
    t.start()
