#!/usr/bin/env python3
"""Field-level JSON diff for compliance A/B test results.

Compares after/ vs before/ JSON files and reports:
  - Row count differences
  - Field value differences within matching rows
  - Missing/extra rows

Usage: python3 tests/compliance/diff.py <results_dir>
  results_dir should contain after/ and before/ subdirectories with t*.json files.
"""
import json
import os
import sys
from pathlib import Path


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def row_key(row, headers):
    """Build a hashable key from scalar identity fields."""
    def _hashable(v):
        if isinstance(v, list):
            return tuple(sorted(str(x) for x in v))
        return v

    if isinstance(row, dict):
        # Use only scalar identity fields for keying (skip list fields like team_uid)
        id_fields = ['record_uid', 'shared_folder_uid', 'team_uid', 'email', 'vault_owner']
        parts = tuple(_hashable(row.get(k)) for k in id_fields if k in row and not isinstance(row.get(k), list))
        if parts:
            return parts
        return tuple((k, _hashable(v)) for k, v in sorted(row.items()))
    if isinstance(row, (list, tuple)):
        return tuple(_hashable(x) for x in row[:2])
    return (row,)


def _normalize(v):
    """Normalize a value for comparison (sort lists so ordering doesn't matter)."""
    if isinstance(v, list):
        return sorted(v, key=str)
    return v


def diff_rows(before_row, after_row, headers=None):
    """Compare two rows field by field, return list of (field, before_val, after_val)."""
    diffs = []
    if isinstance(before_row, dict) and isinstance(after_row, dict):
        all_keys = sorted(set(list(before_row.keys()) + list(after_row.keys())))
        for k in all_keys:
            bv = before_row.get(k)
            av = after_row.get(k)
            if _normalize(bv) != _normalize(av):
                diffs.append((k, bv, av))
    elif isinstance(before_row, (list, tuple)) and isinstance(after_row, (list, tuple)):
        max_len = max(len(before_row), len(after_row))
        for i in range(max_len):
            bv = before_row[i] if i < len(before_row) else None
            av = after_row[i] if i < len(after_row) else None
            if bv != av:
                field = headers[i] if headers and i < len(headers) else f'[{i}]'
                diffs.append((field, bv, av))
    return diffs


def compare_file(before_path, after_path):
    """Compare two JSON result files. Returns (status, summary, details)."""
    before = load_json(before_path)
    after = load_json(after_path)

    if before is None and after is None:
        return 'ERR', 'both files failed to parse', []
    if before is None:
        return 'ERR', 'before file failed to parse', []
    if after is None:
        return 'ERR', 'after file failed to parse', []

    if not isinstance(before, list) or not isinstance(after, list):
        if before == after:
            return 'OK', 'identical objects', []
        return 'DIFF', 'object-level diff', []

    if len(before) == 0 and len(after) == 0:
        return 'OK', 'rows: 0', []

    # Index rows by key for field-level comparison
    before_keyed = {}
    after_keyed = {}
    for r in before:
        before_keyed.setdefault(row_key(r, None), []).append(r)
    for r in after:
        after_keyed.setdefault(row_key(r, None), []).append(r)

    details = []
    field_diffs = 0
    rows_only_before = 0
    rows_only_after = 0

    all_keys = sorted(set(list(before_keyed.keys()) + list(after_keyed.keys())),
                       key=lambda k: str(k))

    for key in all_keys:
        b_rows = before_keyed.get(key, [])
        a_rows = after_keyed.get(key, [])
        pairs = max(len(b_rows), len(a_rows))
        for i in range(pairs):
            br = b_rows[i] if i < len(b_rows) else None
            ar = a_rows[i] if i < len(a_rows) else None
            if br is None:
                rows_only_after += 1
                if len(details) < 10:
                    details.append(f'  + after only: {_abbrev(ar)}')
            elif ar is None:
                rows_only_before += 1
                if len(details) < 10:
                    details.append(f'  - before only: {_abbrev(br)}')
            else:
                rd = diff_rows(br, ar)
                if rd:
                    field_diffs += 1
                    if len(details) < 10:
                        key_str = _abbrev_key(key)
                        for field, bv, av in rd[:3]:
                            details.append(f'  ~ {key_str} [{field}]: {bv} -> {av}')

    row_count_match = len(before) == len(after)
    has_diffs = field_diffs > 0 or rows_only_before > 0 or rows_only_after > 0

    if not has_diffs:
        return 'OK', f'rows: {len(after)}', []

    parts = [f'rows: {len(before)}->{len(after)}']
    if field_diffs:
        parts.append(f'{field_diffs} field diff(s)')
    if rows_only_before:
        parts.append(f'{rows_only_before} removed')
    if rows_only_after:
        parts.append(f'{rows_only_after} added')

    status = 'DIFF' if not row_count_match or field_diffs > 0 or rows_only_before > 0 else 'DIFF'
    return status, ', '.join(parts), details


def _abbrev(obj, maxlen=80):
    s = json.dumps(obj, default=str)
    return s if len(s) <= maxlen else s[:maxlen - 3] + '...'


def _abbrev_key(key):
    parts = [str(v) for v in key if v is not None]
    s = '/'.join(parts)
    return s[:40] if len(s) > 40 else s


def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <results_dir>')
        sys.exit(1)

    results_dir = Path(sys.argv[1])
    after_dir = results_dir / 'after'
    before_dir = results_dir / 'before'

    if not after_dir.is_dir():
        print(f'ERROR: No after/ directory at {after_dir}')
        sys.exit(1)
    if not before_dir.is_dir():
        print(f'ERROR: No before/ directory at {before_dir}')
        sys.exit(1)

    any_diff = False
    after_files = sorted(after_dir.glob('t*.json'))

    for af in after_files:
        fname = af.name
        bf = before_dir / fname
        if not bf.exists():
            print(f'  [SKIP]  {fname} -- no baseline')
            continue

        status, summary, details = compare_file(str(bf), str(af))
        tag = f'[{status}]'
        print(f'  {tag:8s} {fname} -- {summary}')
        for d in details:
            print(d)
        if status == 'DIFF':
            any_diff = True

    # Check for new files
    for af in after_files:
        bf = before_dir / af.name
        if not bf.exists():
            data = load_json(str(af))
            rows = len(data) if isinstance(data, list) else '?'
            print(f'  [NEW]   {af.name} -- rows: {rows} (no baseline)')

    print()
    if any_diff:
        print('Some tests differ -- review above.')
        sys.exit(1)
    else:
        print('All comparable tests match.')


if __name__ == '__main__':
    main()
