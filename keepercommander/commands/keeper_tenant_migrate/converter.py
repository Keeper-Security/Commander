import csv
import glob
import json
import logging
import os
from collections import defaultdict
from datetime import datetime

from .references import (
    FILE_REF_KEYS,
    RECORD_REF_KEYS,
    walk_uid_refs,
)


SKIP_BASENAMES = {
    'combined_export.json',
    'import_manifest.csv',
    'all_records.csv',
    'SHA256SUMS.txt',
}

TOP_LEVEL_V3_TYPES = {'login', 'password', 'url', 'note'}
CUSTOM_FIELD_SKIP_V3_TYPES = {'oneTimeCode', 'fileRef'}


def extract_field_value(fields, field_type):
    if not isinstance(fields, list):
        return ''
    for f in fields:
        if isinstance(f, dict) and f.get('type') == field_type:
            values = f.get('value', [])
            if isinstance(values, list) and values:
                return values[0] if len(values) == 1 else values
            return values
    return ''


def _coerce_last_modified(cmt):
    if isinstance(cmt, (int, float)):
        return int(cmt) * 1000 if cmt < 1e12 else int(cmt)
    try:
        dt = datetime.fromisoformat(str(cmt).replace('Z', '+00:00'))
        return int(dt.timestamp() * 1000)
    except (ValueError, TypeError):
        return None


def _build_custom_key(ftype, label, existing):
    """Build a Commander custom-field key in the documented `$type:label`
    format (`importer/json/json.py:51-58`).

    Bug 39 — pre-fix this emitted `$type:type` for fields without labels
    (or labels matching the type). Commander's importer parses
    `$type:type` as `field.type=type, field.label=type`, putting an
    explicit redundant label on the field. Source records typically
    have empty labels — round-tripping should produce empty labels on
    target. Fix: emit just `$type` for unlabeled / redundantly-labelled
    fields. Commander's importer parses `$type` (no colon) as
    `field.type=type, field.label=''` (json.py:56-58).

    Collision suffix: when multiple unlabeled fields of the same type
    occur, the second+ get `$type:2`, `$type:3`, …. Commander then
    treats those numeric suffixes as labels — disambiguates the fields
    on target while staying within Commander's own format.
    """
    if label and label != ftype:
        key = f'${ftype}:{label}'
    else:
        key = f'${ftype}'
    base_key = key
    suffix = 1
    while key in existing:
        suffix += 1
        key = f'{base_key}:{suffix}'
    return key


def convert_v3_record(rec):
    fields = rec.get('fields', [])
    custom = rec.get('custom', [])

    login = extract_field_value(fields, 'login')
    password = extract_field_value(fields, 'password')
    url = extract_field_value(fields, 'url')
    totp = extract_field_value(fields, 'oneTimeCode')
    notes = rec.get('notes', '')

    # Bug 34 — Commander's KeeperJsonImporter reads the record type from
    # `$type` (json.py:36-37), and its exporter writes `$type` (line 320).
    # Pre-fix we emitted `type` instead — Commander silently ignored it
    # and every record imported as `login` regardless of source. Fix:
    # emit `$type` to match the importer's expected key. The internal
    # source-record key remains `type` (that's the v3 export shape),
    # only the import-bundle output key changes.
    import_rec = {
        'title': rec.get('title', ''),
        '$type': rec.get('type') or 'login',
    }

    cmt = rec.get('client_modified_time')
    if cmt:
        lm = _coerce_last_modified(cmt)
        if lm is not None:
            import_rec['last_modified'] = lm

    if login:
        import_rec['login'] = login if isinstance(login, str) else str(login)
    if password:
        import_rec['password'] = password if isinstance(password, str) else str(password)
    if url:
        import_rec['login_url'] = url if isinstance(url, str) else str(url)
    if notes:
        import_rec['notes'] = notes

    custom_fields = {}

    if totp:
        # Bug 39 — was `$oneTimeCode:oneTimeCode` (redundant label).
        # Commander's importer parses `$type` (no colon) as an unlabeled
        # field of that type. Source TOTP fields have no label, so
        # round-trip should produce no label on target.
        custom_fields['$oneTimeCode'] = totp if isinstance(totp, str) else str(totp)

    for f in fields:
        if not isinstance(f, dict):
            continue
        ftype = f.get('type', '')
        if ftype in TOP_LEVEL_V3_TYPES or ftype in CUSTOM_FIELD_SKIP_V3_TYPES:
            continue
        values = f.get('value', [])
        if not values or (isinstance(values, list) and not any(values)):
            continue
        key = _build_custom_key(ftype, f.get('label', ftype), custom_fields)
        if isinstance(values, list) and len(values) == 1:
            custom_fields[key] = values[0]
        else:
            custom_fields[key] = values

    for cf in custom:
        if not isinstance(cf, dict):
            continue
        ftype = cf.get('type', 'text')
        label = cf.get('label', ftype)
        values = cf.get('value', [])
        if not values or (isinstance(values, list) and not any(values)):
            continue
        key = _build_custom_key(ftype, label, custom_fields)
        if isinstance(values, list) and len(values) == 1:
            custom_fields[key] = values[0]
        else:
            custom_fields[key] = values

    if custom_fields:
        import_rec['custom_fields'] = custom_fields

    return import_rec


_REF_FIELD_TYPES = RECORD_REF_KEYS | FILE_REF_KEYS


def extract_record_dependencies(rec):
    """Return the set of source-record UIDs that ``rec`` references.

    Bug 87 — Commander's records import accepts records in array order; if
    record A references record B (e.g. ``script.fileRef`` points at B's
    UID) and A is imported before B, the dependency is unresolved at
    import time. Topologically pre-sorting source records so referenced
    records arrive first lets every record's embedded refs resolve
    against an already-present target row.

    Two reference shapes exist in v3 records:

      1. ``{"type": "fileRef", "value": ["UID1", "UID2"]}`` — the field's
         own ``type`` is the ref key; UIDs live directly in ``value``.
      2. ``{"type": "script", "value": [{"fileRef": "UID", "recordRef":
         ["UID"]}]}`` — UIDs live nested under ref-key dict entries
         INSIDE the value items (the standard ``walk_uid_refs`` shape).

    Both shapes are extracted; the union is returned.
    """
    deps = set()
    own_uid = rec.get('record_uid', '')
    for f in (rec.get('fields') or []) + (rec.get('custom') or []):
        if not isinstance(f, dict):
            continue
        ftype = f.get('type', '')
        value = f.get('value')
        if ftype in _REF_FIELD_TYPES:
            # Shape 1 — field type IS the ref key, value lists are UIDs.
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item:
                        deps.add(item)
        if isinstance(value, (list, dict)):
            # Shape 2 — recurse for nested ref keys (script values, etc.).
            for _key, uid in walk_uid_refs(value, _REF_FIELD_TYPES):
                if uid:
                    deps.add(uid)
    deps.discard(own_uid)
    return deps


def topological_sort_records(source_records):
    """Sort ``source_records`` so referenced records precede referencing
    ones. Stable-on-ties: records with no dependency edges keep their
    incoming order. Cycles fall back to incoming order for the cycle
    members (with a warning) — Commander's importer is the final
    authority on cyclic-ref handling.

    Returns the reordered list. Records whose deps point at UIDs not in
    the source set are kept in incoming order relative to records they
    don't depend on (the missing dep is treated as an external ref).
    """
    indexed = list(enumerate(source_records))
    uid_to_idx = {}
    for idx, rec in indexed:
        uid = rec.get('record_uid', '')
        if uid and uid not in uid_to_idx:
            uid_to_idx[uid] = idx

    deps = {}
    for idx, rec in indexed:
        rec_deps = extract_record_dependencies(rec)
        # Restrict to deps that name a record in the same source set;
        # external refs can't influence ordering.
        deps[idx] = {uid_to_idx[d] for d in rec_deps if d in uid_to_idx}

    # Kahn's algorithm with stable ordering: at each step pick the
    # lowest-index ready node so records with no deps preserve their
    # incoming order.
    in_degree = defaultdict(int)
    reverse = defaultdict(set)
    for idx, dep_idxs in deps.items():
        for d in dep_idxs:
            if d != idx:
                reverse[d].add(idx)
                in_degree[idx] += 1

    ready = sorted(idx for idx, _ in indexed if in_degree[idx] == 0)
    ordered = []
    while ready:
        nxt = ready.pop(0)
        ordered.append(nxt)
        for dependent in sorted(reverse[nxt]):
            in_degree[dependent] -= 1
            if in_degree[dependent] == 0:
                # Insert maintaining sort order
                lo, hi = 0, len(ready)
                while lo < hi:
                    mid = (lo + hi) // 2
                    if ready[mid] < dependent:
                        lo = mid + 1
                    else:
                        hi = mid
                ready.insert(lo, dependent)

    if len(ordered) < len(indexed):
        # Cycle: append remaining records in incoming order, log a warning.
        remaining = [idx for idx, _ in indexed if idx not in set(ordered)]
        logging.warning(
            'topological_sort_records: %d records in cyclic dependencies '
            '(falling back to incoming order for: %s)',
            len(remaining),
            ', '.join((indexed[i][1].get('record_uid') or f'idx={i}')
                      for i in remaining[:5]),
        )
        ordered.extend(remaining)

    return [indexed[i][1] for i in ordered]


def load_folder_mappings(compliance_csv, sf_json):
    record_to_sf = {}
    sf_uid_to_name = {}

    if sf_json and os.path.exists(sf_json):
        with open(sf_json) as f:
            sfs = json.load(f)
        if isinstance(sfs, list):
            for sf in sfs:
                uid = sf.get('shared_folder_uid', sf.get('uid', ''))
                name = sf.get('name', '')
                if uid and name:
                    sf_uid_to_name[uid] = name

    if compliance_csv and os.path.exists(compliance_csv):
        with open(compliance_csv) as f:
            reader = csv.DictReader(f)
            for row in reader:
                sf_uid = row.get('Shared Folder UID', '').strip()
                record_uids = row.get('Record UID', '').strip()
                if sf_uid and record_uids:
                    for ruid in record_uids.split('\n'):
                        ruid = ruid.strip()
                        if ruid and sf_uid in sf_uid_to_name:
                            record_to_sf[ruid] = sf_uid_to_name[sf_uid]

    return record_to_sf, sf_uid_to_name


class RecordConverter:
    def __init__(self, include_sf=False, split_by_type=False):
        self.include_sf = include_sf
        self.split_by_type = split_by_type

    def load_directory(self, input_dir):
        records = []
        skipped = 0
        for f in sorted(glob.glob(os.path.join(input_dir, '*.json'))):
            if os.path.basename(f) in SKIP_BASENAMES:
                continue
            try:
                with open(f) as fh:
                    rec = json.load(fh)
            except (OSError, json.JSONDecodeError):
                skipped += 1
                continue
            if 'title' in rec:
                records.append(rec)
            else:
                skipped += 1
        return records, skipped

    def convert(self, source_records, record_to_sf):
        # Bug 87 — pre-sort by inter-record UID dependencies so records
        # referenced (script.fileRef, recordRef, pamUserUid, …) by other
        # records arrive in the import bundle ahead of their referrers.
        # Without this, Commander's importer can reject a record whose
        # embedded ref points at a source UID that hasn't yet been seen
        # this batch (or the post-import references-rewrite pass can't
        # rewrite a ref because the dependent record was never created).
        source_records = topological_sort_records(source_records)
        import_records = []
        folder_assigned = 0
        for rec in source_records:
            import_rec = convert_v3_record(rec)
            uid = rec.get('record_uid', '')
            # Folder resolution priority:
            #   1. Per-record folder info captured at export time (new in
            #      v1.1 — covers user-folder hierarchy as well as SF
            #      placement). The `folders` key on the source record is
            #      a list of {path, shared_folder_uid} dicts.
            #   2. Shared-folder assignment from an external compliance
            #      CSV (pre-1.1 path, still supported for callers that
            #      don't have source-side `records-export` output).
            folders_from_rec = rec.get('folders') or []
            import_folders = []
            for f in folders_from_rec:
                path = (f.get('path') or '').strip()
                if not path:
                    continue
                if f.get('shared_folder_uid'):
                    # Shared folder — name is the last path segment when
                    # the SF maps via the compliance CSV, otherwise use
                    # the whole path as the SF name.
                    import_folders.append({
                        'shared_folder': path,
                        'can_edit': True,
                        'can_share': True,
                    })
                else:
                    # User/personal folder — Commander import treats
                    # `folder` as the path under My Vault.
                    import_folders.append({'folder': path})
            if import_folders:
                import_rec['folders'] = import_folders
                folder_assigned += 1
            elif uid in record_to_sf:
                import_rec['folders'] = [{
                    'shared_folder': record_to_sf[uid],
                    'can_edit': True,
                    'can_share': True,
                }]
                folder_assigned += 1
            import_records.append(import_rec)
        return import_records, folder_assigned

    def _build_sf_section(self, sf_uid_to_name):
        if not self.include_sf or not sf_uid_to_name:
            return []
        return [{
            'path': name,
            'manage_users': True,
            'manage_records': True,
            'can_edit': True,
            'can_share': True,
        } for name in sorted(set(sf_uid_to_name.values()))]

    def write(self, import_records, sf_section, output_path):
        if self.split_by_type:
            return self._write_split(import_records, sf_section, output_path)
        output = {'records': import_records}
        if sf_section:
            output['shared_folders'] = sf_section
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        # Bundle contains plaintext record bodies — owner-only.
        os.chmod(output_path, 0o600)
        return [output_path]

    @staticmethod
    def _sanitize_for_filename(name):
        """Replace filesystem-unsafe characters in a record-type name.

        Real source vaults expose record types whose names came from
        imported file MIME types (`image/png`, `application/json`,
        `application/x-sh`, …) and from operator-named enterprise
        templates that may contain spaces or punctuation. Bug 30 — pre-
        sanitization, `os.path.join('.', f'foo_application/json.json')`
        treated the `/` as a directory separator and the open() call
        failed with FileNotFoundError.

        Strategy: keep alnum + `-_.`, replace everything else (including
        space, /, \\, :, etc.) with `_`. The original type is preserved
        in the per-file `--record-type` argument inside the batch file.
        """
        out = []
        for ch in (name or ''):
            if ch.isalnum() or ch in ('-', '_', '.'):
                out.append(ch)
            else:
                out.append('_')
        sanitized = ''.join(out).strip('._') or 'untyped'
        return sanitized

    def _write_split(self, import_records, sf_section, output_path):
        by_type = defaultdict(list)
        for rec in import_records:
            # Records have already been converted to import-bundle shape
            # (`$type` per Bug 34 fix); read it back for bucketing.
            by_type[rec.get('$type', 'login')].append(rec)

        output_dir = os.path.dirname(output_path) or '.'
        base_name = os.path.splitext(os.path.basename(output_path))[0]
        batch_lines = []
        written = []
        used_filenames = set()

        for rtype, recs in sorted(by_type.items()):
            slug = self._sanitize_for_filename(rtype)
            # Defensive: two distinct types could collide post-
            # sanitization (e.g. `image/png` and `image_png`). Add a
            # numeric suffix on collision so each file is unique.
            file_slug = slug
            n = 2
            while file_slug in used_filenames:
                file_slug = f'{slug}_{n}'
                n += 1
            used_filenames.add(file_slug)
            type_file = os.path.join(output_dir, f'{base_name}_{file_slug}.json')
            type_output = {'records': recs}
            if sf_section:
                type_output['shared_folders'] = sf_section
            with open(type_file, 'w') as f:
                json.dump(type_output, f, indent=2)
            os.chmod(type_file, 0o600)
            # Record type goes into the batch verbatim — Commander's
            # `--record-type` accepts any string the original record
            # carried. Filename is sanitized; argument value isn't.
            batch_lines.append(
                f'import --format json --record-type "{rtype}" -s -p A '
                f'"{type_file}"')
            written.append(type_file)
            logging.info('  %s (file: %s): %d records → %s',
                         rtype, file_slug, len(recs), type_file)

        batch_file = os.path.join(output_dir, f'{base_name}_import.batch')
        with open(batch_file, 'w') as f:
            f.write('\n'.join(batch_lines) + '\n')
        os.chmod(batch_file, 0o600)
        written.append(batch_file)
        logging.info('Batch file: %s (%d commands). Run: keeper run-batch %s --delay 2',
                     batch_file, len(batch_lines), batch_file)
        return written

    def run(self, input_dir, output_path, compliance_csv=None, sf_json=None):
        source_records, skipped = self.load_directory(input_dir)
        logging.info('Loaded %d records, skipped %d', len(source_records), skipped)

        record_to_sf, sf_uid_to_name = load_folder_mappings(compliance_csv, sf_json)
        import_records, folder_assigned = self.convert(source_records, record_to_sf)
        sf_section = self._build_sf_section(sf_uid_to_name)

        written = self.write(import_records, sf_section, output_path)
        logging.info('Converted %d records (%d with folder assignments)',
                     len(import_records), folder_assigned)
        return {
            'records': len(import_records),
            'folder_assigned': folder_assigned,
            'skipped_files': skipped,
            'written': written,
        }
