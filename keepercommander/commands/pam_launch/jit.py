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
"""Single source of truth for `pam launch` JIT (just-in-time) access.

JIT settings describe whether a PAM launch should ask the Gateway to provision an
ephemeral account, elevate the linked user's privileges for the session, or both.
They are authored in one of two places:

1.  **Web Vault UI (authoritative):** an encrypted DATA edge on the resource vertex
    in the DAG with path ``jit_settings``. Keys are camelCase
    (``createEphemeral``, ``elevate``, ``ephemeralAccountType``, ``elevationMethod``,
    ``elevationString``, ``baseDistinguishedName``). Written by
    ``DagJitSettingsObject.to_dag_dict`` in
    ``commands/pam_import/base.py`` and by the Web Vault UI.

2.  **Declarative (`pam env apply`) mirror:** a snake_case block under
    ``pamSettings.options.jit_settings`` on the record's typed field. Produced from
    ``keeper-pam-declarative/manifests/pam-environment.v1.schema.json`` §
    ``$defs.jit_settings``.

The two shapes are normalised here to snake_case so the rest of ``pam_launch``
(validation rules, payload builders, dispatch) only has to reason about one dict.

Public API
----------
* :data:`JIT_MODE_EPHEMERAL`, :data:`JIT_MODE_ELEVATION`, :data:`JIT_MODE_BOTH` — mode constants.
* :func:`normalize_jit_settings` — camelCase|snake_case → snake_case dict.
* :func:`derive_jit_mode` — snake_case dict → one of the mode constants or ``None``.
* :func:`load_jit_settings` — DAG-first, typed-field-fallback loader.
* :func:`build_ephemeral_payload`, :func:`build_elevation_payload` — gateway wire
  projections for the ``jitSettings`` / ``jitElevation`` fields respectively.

No mutable module state. All functions are pure except :func:`load_jit_settings`,
which performs the DAG read.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

__all__ = [
    'JIT_MODE_EPHEMERAL',
    'JIT_MODE_ELEVATION',
    'JIT_MODE_BOTH',
    'normalize_jit_settings',
    'derive_jit_mode',
    'load_jit_settings',
    'build_ephemeral_payload',
    'build_elevation_payload',
    'provisions_credential',
]

# ---- Mode constants -------------------------------------------------------

JIT_MODE_EPHEMERAL = 'ephemeral'
JIT_MODE_ELEVATION = 'elevation'
JIT_MODE_BOTH = 'both'


# ---- Key aliases ----------------------------------------------------------
# Only list keys that actually differ between the two storage shapes.
# Source: DagJitSettingsObject.to_dag_dict in commands/pam_import/base.py.
_CAMEL_TO_SNAKE = {
    'createEphemeral': 'create_ephemeral',
    'ephemeralAccountType': 'ephemeral_account_type',
    'elevationMethod': 'elevation_method',
    'elevationString': 'elevation_string',
    'baseDistinguishedName': 'base_distinguished_name',
}

_EPHEMERAL_KEYS = (
    'create_ephemeral',
    'ephemeral_account_type',
    'base_distinguished_name',
    # pam_directory_uid_ref is accepted in the declarative mirror only; the DAG JSON
    # does not carry it — the pamDirectory linkage is stored as a separate DAG LINK.
    'pam_directory_uid_ref',
)
_ELEVATION_KEYS = (
    'elevate',
    'elevation_method',
    'elevation_string',
)


# ---- Normalisation --------------------------------------------------------

def normalize_jit_settings(raw: Any) -> Optional[Dict[str, Any]]:
    """Accept DAG camelCase or declarative snake_case; return snake_case dict.

    Two-pass so snake_case always wins on the (pathological) collision where a
    caller supplies both casings for the same field — that's the shape the rest
    of ``pam_launch`` expects. Returns ``None`` for non-dict or empty inputs.
    """
    if not isinstance(raw, dict):
        return None
    out = {_CAMEL_TO_SNAKE[k]: v for k, v in raw.items() if k in _CAMEL_TO_SNAKE}
    out.update((k, v) for k, v in raw.items() if k not in _CAMEL_TO_SNAKE)
    return out or None


# ---- Mode derivation ------------------------------------------------------

def derive_jit_mode(jit_settings: Optional[Dict[str, Any]]) -> Optional[str]:
    """Return one of :data:`JIT_MODE_*` or ``None`` for a normalised JIT dict."""
    if not isinstance(jit_settings, dict):
        return None
    create_ephemeral = bool(jit_settings.get('create_ephemeral'))
    elevate = bool(jit_settings.get('elevate'))
    if create_ephemeral and elevate:
        return JIT_MODE_BOTH
    if create_ephemeral:
        return JIT_MODE_EPHEMERAL
    if elevate:
        return JIT_MODE_ELEVATION
    return None


# ---- Credential semantics -------------------------------------------------

def provisions_credential(jit_flag: bool, jit_mode: Optional[str]) -> bool:
    """True when an active --jit launch will get its credential from the gateway.

    In ``ephemeral`` and ``both`` modes the Gateway provisions a short-lived
    account, so pre-existing credentials on the record are not required.
    ``elevation`` mode still needs a linked credential (elevation is applied on
    top of it) and therefore returns ``False``. When ``--jit`` was not passed
    this predicate is always ``False`` — normal credential validation applies.
    """
    return bool(jit_flag) and jit_mode in (JIT_MODE_EPHEMERAL, JIT_MODE_BOTH)


# ---- Loader ---------------------------------------------------------------

def _typed_field_jit_settings(record: Any) -> Optional[Dict[str, Any]]:
    """Read jit_settings from the pamSettings typed field (declarative mirror)."""
    if not record:
        return None
    get_field = getattr(record, 'get_typed_field', None)
    if not callable(get_field):
        return None
    field = get_field('pamSettings')
    if field is None or not hasattr(field, 'get_default_value'):
        return None
    value = field.get_default_value(dict)
    if not isinstance(value, dict):
        return None
    options = value.get('options')
    if not isinstance(options, dict):
        return None
    return normalize_jit_settings(options.get('jit_settings'))


def _dag_jit_settings(params: Any, record_uid: Optional[str]) -> Optional[Dict[str, Any]]:
    """Read jit_settings from the DAG (Web Vault authoritative storage)."""
    if params is None or not record_uid:
        return None
    # Lazy import — commands/pam_import pulls DAG / protobuf dependencies that
    # we don't want to import on every pam launch, only when JIT is in play.
    from ..pam_import.keeper_ai_settings import get_resource_jit_settings
    try:
        raw = get_resource_jit_settings(params, record_uid)
    except Exception as exc:  # pragma: no cover - defensive
        logging.debug('pam launch: DAG jit_settings lookup failed for %s (%s)',
                      record_uid, exc)
        return None
    return normalize_jit_settings(raw)


def load_jit_settings(
    params: Any = None,
    record: Any = None,
    record_uid: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return the snake_case JIT settings for a record, preferring the DAG.

    Lookup order:
      1. DAG DATA edge ``jit_settings`` on the resource vertex (Web Vault UI).
      2. ``pamSettings.options.jit_settings`` on the record's typed field
         (``pam env apply`` mirror).

    Either ``record`` or ``record_uid`` is sufficient; providing both lets the
    function reach both storage locations in one call.
    """
    uid = record_uid or getattr(record, 'record_uid', None)
    dag = _dag_jit_settings(params, uid)
    if dag:
        return dag
    return _typed_field_jit_settings(record)


# ---- Gateway wire-format payloads -----------------------------------------

def _project(jit_settings: Any, keys) -> Dict[str, Any]:
    """Return ``{k: v for k in keys if v is not empty}``. Internal."""
    if not isinstance(jit_settings, dict):
        return {}
    payload: Dict[str, Any] = {}
    for k in keys:
        v = jit_settings.get(k)
        if v in (None, ''):
            continue
        payload[k] = v
    return payload


def build_ephemeral_payload(jit_settings: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Project the ephemeral-relevant subset for the gateway ``jitSettings`` field.

    Empty / ``None`` values are dropped so the payload stays minimal. Key names
    match the declarative schema verbatim (snake_case); if the gateway ever
    requires camelCase on the wire, this function is the one place to change.
    """
    return _project(jit_settings, _EPHEMERAL_KEYS)


def build_elevation_payload(jit_settings: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Project the elevation-relevant subset for the gateway ``jitElevation`` field."""
    return _project(jit_settings, _ELEVATION_KEYS)
