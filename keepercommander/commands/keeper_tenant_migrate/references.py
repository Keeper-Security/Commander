"""Bug 33 (v1.5.0 — data layer) — recursive walker + remapper for inter-record
UID references buried inside structured field values.

Records of PAM-flavoured types carry source-record UID references in their
field values that the migration's per-record copy doesn't remap:

  - ``pamRemoteBrowserSettings.connection.httpCredentialsUid`` — UID of the
    credentials record holding login/password used by the remote-browser
    session.
  - ``pamSettings.connection.httpCredentialsUid`` — same idea, plain PAM.
  - ``script.value[].recordRef`` — list of UIDs of records referenced by a
    script step.
  - top-level ``recordRef`` field values — generic cross-record links.
  - ``pamUserUid`` / ``pamConfigurationUid`` / ``targetRecord`` —
    discovered-rotation references between PAM resource and the controller
    record(s).

Pre-Bug-33 these UIDs were copied verbatim. Source record A landed on
target with a NEW UID, but its embedded reference still pointed at the
SOURCE UID of record B. The target tenant has no record with that UID,
so RBI/PAM rotation/script flows fail at first use.

This module is the pure-data layer. The walker / remapper take a value
tree and a ``source_uid → target_uid`` map and emit either a list of
references found or a transformed copy. The subcommand that drives them
(``records-references-rewrite``) and the auto-migrate stage that runs
that subcommand are added in follow-up releases (v1.5.1, v1.5.2).

File-UID references (``fileRef`` inside ``script.value[]`` or attachment-
backed structured fields) require capturing target file UIDs during
attachment upload — the staging manifest doesn't track them today. They
are intentionally NOT included in ``REF_KEYS`` here; that scope is filed
for v1.6.

Design constraints:

  * No Commander imports. Pure-Python so the whole module is unit-testable
    against synthetic fixtures.
  * No mutation of the input value. ``remap_uid_refs`` returns a new
    structure; callers compare for equality to know whether a record
    needs updating.
  * Cycle-safe via a visited set keyed on ``id(node)`` for dict/list
    children. PAM record values are not normally self-referential but
    Commander field values are operator-editable JSON.
  * Unknown UIDs (in ``REF_KEYS`` positions but absent from the map) are
    left in place. Callers can query the residual list afterwards to
    decide whether the migration is "complete enough" or needs a manual
    follow-up record import.
"""

from __future__ import annotations

from typing import Any, Iterator, Mapping, Set, Tuple


# Keys whose VALUES carry record UIDs and must be remapped from
# source-tenant UIDs to target-tenant UIDs after migration.
#
# Discovery method: 2026-04-28 EU-source full-vault scan plus inspection
# of Commander's PAM record-type schemas. New keys will surface as we
# exercise less-common record types — add them here, tests in
# tests/test_references.py will pick up the change automatically because
# ``test_ref_keys_registry_is_lowercased`` enforces the contract.
RECORD_REF_KEYS: Set[str] = {
    'httpCredentialsUid',
    'recordRef',
    'pamUserUid',
    'pamConfigurationUid',
    'targetRecord',
    'controllerUid',  # discovered-rotation controller record
    'resourceRef',    # PAM resource record link
}


# Bug 56 / v1.6 fileRef extension — keys whose values are FILE UIDs.
# These live in a separate namespace from record UIDs (Commander uses
# different UID generators for files vs records). Walker + remapper
# accept either map at runtime; callers pass FILE_REF_KEYS when they
# want to remap file UIDs and RECORD_REF_KEYS for record UIDs.
FILE_REF_KEYS: Set[str] = {
    'fileRef',  # attachment reference inside structured record fields
}


def walk_uid_refs(
    value: Any,
    ref_keys: Set[str] = RECORD_REF_KEYS,
) -> Iterator[Tuple[str, str]]:
    """Yield ``(key_name, uid)`` pairs for every UID reference found
    anywhere inside ``value``.

    ``value`` may be any JSON-shaped structure: dict, list, str, number,
    bool, None. Non-JSON containers are ignored. Whenever we see a key
    in ``ref_keys`` whose value is a string, that string is yielded as a
    UID. Whenever we see a key in ``ref_keys`` whose value is a list,
    each list item that's a string is yielded.

    The yield is a flat stream of ``(key, uid)`` tuples — the path of
    where the reference lives in the structure is intentionally NOT
    surfaced. Callers that need to update the location use
    ``remap_uid_refs``; callers that just want to enumerate refs (audit,
    pre-flight) use this.
    """
    seen: Set[int] = set()
    yield from _walk(value, ref_keys, seen)


def _walk(value, ref_keys, seen):
    if isinstance(value, Mapping):
        node_id = id(value)
        if node_id in seen:
            return
        seen.add(node_id)
        for k, v in value.items():
            if k in ref_keys:
                if isinstance(v, str) and v:
                    yield (k, v)
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str) and item:
                            yield (k, item)
            # Recurse regardless of key — refs can be nested under
            # non-ref keys (e.g. ``connection.httpCredentialsUid``).
            yield from _walk(v, ref_keys, seen)
    elif isinstance(value, list):
        node_id = id(value)
        if node_id in seen:
            return
        seen.add(node_id)
        for item in value:
            yield from _walk(item, ref_keys, seen)


def remap_uid_refs(
    value: Any,
    uid_map: Mapping[str, str],
    ref_keys: Set[str] = RECORD_REF_KEYS,
) -> Tuple[Any, dict]:
    """Return ``(new_value, stats)`` — a deep copy of ``value`` with every
    UID found under a key in ``ref_keys`` rewritten according to ``uid_map``.

    ``stats`` is a dict with three counters:

      * ``remapped``: number of UID strings that were substituted.
      * ``unknown``: number of UID strings under a ref key that have no
        entry in ``uid_map`` (left in place).
      * ``empty``: number of UID slots that were empty/None (unchanged).

    UIDs that the map maps to themselves count as ``remapped`` only if
    they were strictly different in the input — identical-value lookups
    are no-ops and don't bump the counter, so ``stats['remapped'] > 0``
    is a reliable "this record needs to be persisted" signal.

    The input is not mutated. Cycle-safe — repeated subgraphs are walked
    once, but the output preserves structure (no shared references).
    """
    stats = {'remapped': 0, 'unknown': 0, 'empty': 0}
    seen: dict = {}
    new = _remap(value, uid_map, ref_keys, stats, seen)
    return new, stats


def _remap(value, uid_map, ref_keys, stats, seen):
    if isinstance(value, Mapping):
        node_id = id(value)
        if node_id in seen:
            return seen[node_id]
        out: dict = {}
        seen[node_id] = out
        for k, v in value.items():
            if k in ref_keys:
                out[k] = _remap_ref_value(v, uid_map, stats)
            else:
                out[k] = _remap(v, uid_map, ref_keys, stats, seen)
        return out
    if isinstance(value, list):
        node_id = id(value)
        if node_id in seen:
            return seen[node_id]
        out_list: list = []
        seen[node_id] = out_list
        for item in value:
            out_list.append(_remap(item, uid_map, ref_keys, stats, seen))
        return out_list
    return value


def _remap_ref_value(v, uid_map, stats):
    if isinstance(v, str):
        return _remap_one(v, uid_map, stats)
    if isinstance(v, list):
        # Lists of UIDs: ``recordRef`` field values, ``script.value[]``
        # fragments. Non-string items pass through untouched.
        return [_remap_one(item, uid_map, stats) if isinstance(item, str)
                else item
                for item in v]
    return v


def _remap_one(uid, uid_map, stats):
    if not uid:
        stats['empty'] += 1
        return uid
    target = uid_map.get(uid)
    if target is None:
        stats['unknown'] += 1
        return uid
    if target != uid:
        stats['remapped'] += 1
    return target


def needs_rewrite(value: Any, uid_map: Mapping[str, str],
                   ref_keys: Set[str] = RECORD_REF_KEYS) -> bool:
    """Quick yes/no — does any UID reference in ``value`` resolve to a
    different target UID? Cheaper than ``remap_uid_refs`` because it
    short-circuits on the first mismatched ref.
    """
    for _key, uid in walk_uid_refs(value, ref_keys):
        target = uid_map.get(uid)
        if target is not None and target != uid:
            return True
    return False
