"""Bug 33 (v1.5.1) — driver for the references rewrite step.

Reads a records manifest CSV produced by the migration's standard
``records-manifest`` step (``source_uid,target_uid,title``), connects to
the target tenant, walks each migrated record's structured field values
for keys in :data:`references.RECORD_REF_KEYS`, substitutes any
source-tenant UID that has a known target counterpart, and persists the
update.

The walker / remapper pure-data primitives live in :mod:`references`
(v1.5.0). This module is the side-effecting layer: load record →
inspect → apply → persist → log.

Auto-migrate stage wiring lives in v1.5.2 (filed). This module + the
subcommand built on top of it (``records-references-rewrite``) are
operator-runnable today.

The :class:`RecordReferenceClient` protocol lets tests substitute a
fake without pulling in Commander's vault module. The real client
(``CommanderRecordReferenceClient`` in :mod:`commander_clients`) loads
the v3 record via ``vault.KeeperRecord.load`` and persists via
``record_management.update_record``.
"""

from __future__ import annotations

import csv
import logging
from typing import Any, Iterable, List, Mapping, Optional, Protocol

from .references import (
    FILE_REF_KEYS,
    RECORD_REF_KEYS,
    needs_rewrite,
    remap_uid_refs,
)


logger = logging.getLogger(__name__)


class RecordReferenceClient(Protocol):
    """Minimal record-update protocol used by the rewriter.

    ``load_field_values(record_uid)`` returns the list of TypedField
    structures (or equivalent dicts) for the given record on the target
    tenant. Each field is expected to expose a mutable ``value`` list.

    ``persist(record_uid, fields, custom_fields)`` writes the modified
    field values back to the target tenant. Returns True on success,
    False on failure (caller treats False as a per-record FAIL — the run
    continues).
    """

    def load_field_values(self, record_uid: str) -> Optional['LoadedRecord']:
        ...

    def persist(self, record_uid: str, loaded: 'LoadedRecord') -> bool:
        ...


class LoadedRecord:
    """Plain-dict view of a target record's fields.

    The real Commander client materializes a ``vault.TypedRecord`` and
    wraps it; tests can construct one directly. The rewriter mutates the
    ``fields`` and ``custom`` lists in place — they are lists of dicts,
    each with a ``value`` key whose contents are walkable by the
    references module.
    """

    __slots__ = ('record_uid', 'record_type', 'fields', 'custom', '_native')

    def __init__(self, record_uid: str, record_type: str,
                 fields: List[dict], custom: List[dict],
                 _native: Any = None):
        self.record_uid = record_uid
        self.record_type = record_type
        self.fields = fields
        self.custom = custom
        # Real client uses this slot to hold the underlying TypedRecord
        # so persist() can mutate its `value` lists. Tests leave it None.
        self._native = _native


def load_manifest_pairs(manifest_path: str) -> List[dict]:
    """Read a records manifest CSV; return only the unambiguous
    one-to-one pairs (rows that have ``source_uid`` AND ``target_uid``).

    Multi-source / multi-target rows from
    ``manifest.write_manifest_csv`` are skipped — they live in the
    ambiguous bucket and need operator review before any rewrite is
    safe.
    """
    pairs = []
    with open(manifest_path, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            src = (row.get('source_uid') or '').strip()
            tgt = (row.get('target_uid') or '').strip()
            if src and tgt:
                pairs.append({'source_uid': src, 'target_uid': tgt,
                              'title': (row.get('title') or '').strip()})
    return pairs


def build_uid_map(pairs: Iterable[Mapping[str, str]]) -> dict:
    """Build the ``source_uid → target_uid`` map consumed by the
    references remapper. Skips empty UIDs and identity rows (src == tgt).
    """
    out = {}
    for p in pairs:
        src = (p.get('source_uid') or '').strip()
        tgt = (p.get('target_uid') or '').strip()
        if src and tgt:
            out[src] = tgt
    return out


# Result-aggregation shape for the subcommand; keeps run reports
# stable when we add fields in v1.5.2.
def _empty_result():
    return {
        'records_inspected': 0,
        'records_with_refs': 0,
        'records_rewritten': 0,
        'refs_remapped': 0,
        'refs_unknown': 0,
        'refs_empty': 0,
        'persist_failures': 0,
        'load_failures': 0,
        'rewritten_uids': [],   # for audit / undo manifest
        'failed_uids': [],
    }


class ReferencesRewriter:
    """Drive the references-rewrite pass over a list of (src, tgt) pairs.

    Every method is idempotent given the same target state — re-running
    after a partial run only persists records whose UIDs still resolve
    differently. Records whose embedded UIDs all already point at target
    UIDs (because the rewrite ran successfully on a previous pass) get
    counted in ``records_inspected`` but skipped without a persist call.
    """

    def __init__(self, client: RecordReferenceClient,
                  ref_keys: Optional[set] = None,
                  file_uid_map: Optional[Mapping[str, str]] = None):
        self.client = client
        # Bug 56 / v1.6 — accept FILE_REF_KEYS in the same registry by
        # default; record-only callers can override.
        self.ref_keys = ref_keys or (RECORD_REF_KEYS | FILE_REF_KEYS)
        # File-UID map captured from the attachments-upload stage. Empty
        # when no fileRef-bearing records or pre-v1.6 manifest format.
        self.file_uid_map = dict(file_uid_map or {})

    def run(self, pairs: Iterable[Mapping[str, str]]) -> dict:
        result = _empty_result()
        uid_map = build_uid_map(pairs)
        # Bug 56 / v1.6 — combine record-UID + file-UID maps so the
        # remapper sees both namespaces. UIDs are universally unique
        # across record vs file generators in Keeper, so flat-merging
        # is safe (no key collisions).
        combined_map = dict(uid_map)
        combined_map.update(self.file_uid_map)
        if not combined_map:
            logger.info('references-rewrite: empty uid_map — nothing to do')
            return result

        for p in pairs:
            target_uid = (p.get('target_uid') or '').strip()
            if not target_uid:
                continue
            result['records_inspected'] += 1

            loaded = self.client.load_field_values(target_uid)
            if loaded is None:
                result['load_failures'] += 1
                result['failed_uids'].append(target_uid)
                logger.warning('references-rewrite: load failed for %s',
                                target_uid)
                continue

            stats = self._rewrite_one(loaded, combined_map)
            if stats['has_refs']:
                result['records_with_refs'] += 1
            result['refs_remapped'] += stats['remapped']
            result['refs_unknown'] += stats['unknown']
            result['refs_empty'] += stats['empty']

            if stats['remapped'] == 0:
                continue
            ok = self.client.persist(target_uid, loaded)
            if ok:
                result['records_rewritten'] += 1
                result['rewritten_uids'].append(target_uid)
            else:
                result['persist_failures'] += 1
                result['failed_uids'].append(target_uid)
                logger.warning('references-rewrite: persist failed for %s',
                                target_uid)
        return result

    def _rewrite_one(self, loaded: LoadedRecord, uid_map: Mapping[str, str]):
        """Walk + remap every TypedField on the record. Mutates the
        ``value`` lists in-place inside ``loaded`` so the client's
        ``persist`` sees the new values.

        Returns ``{has_refs, remapped, unknown, empty}``.
        """
        has_refs = False
        agg = {'remapped': 0, 'unknown': 0, 'empty': 0}
        for field in (loaded.fields or []) + (loaded.custom or []):
            value = field.get('value')
            if value is None:
                continue
            # ``value`` is a list per Commander's TypedField shape; each
            # item may itself be a dict / list / scalar.
            if not isinstance(value, list):
                continue
            new_value = []
            field_changed = False
            for item in value:
                # Cheap pre-check: skip items without any ref key.
                refs = list(_walk_with_refkeys(item, self.ref_keys))
                if refs:
                    has_refs = True
                if not refs or not needs_rewrite(item, uid_map, self.ref_keys):
                    new_value.append(item)
                    # Even if we don't rewrite, count empties/unknowns
                    # so the operator sees the residual gaps.
                    for _, uid in refs:
                        if not uid:
                            agg['empty'] += 1
                        elif uid_map.get(uid) is None:
                            agg['unknown'] += 1
                    continue
                remapped_item, item_stats = remap_uid_refs(
                    item, uid_map, self.ref_keys)
                agg['remapped'] += item_stats['remapped']
                agg['unknown'] += item_stats['unknown']
                agg['empty'] += item_stats['empty']
                new_value.append(remapped_item)
                if item_stats['remapped'] > 0:
                    field_changed = True
            if field_changed:
                field['value'] = new_value
        return {'has_refs': has_refs, **agg}


def _walk_with_refkeys(value, ref_keys):
    """Inline walker — returns the (key, uid) list. Imported lazily here
    to avoid a circular import at module load time when references.py is
    extended in future releases.
    """
    from .references import walk_uid_refs
    return walk_uid_refs(value, ref_keys)
