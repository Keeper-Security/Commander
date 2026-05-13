"""Defensive CSV loading — detect BOM, validate header, never fail silent.

All loaders in the plugin (roster, manifest, readiness report, target-user
CSV) previously used `csv.DictReader(open(path, newline=''))` directly.
That fails silently in three cases:

  1. BOM-prefixed UTF-8 (Excel saves this by default) — `\ufeffemail`
     becomes the first header name, so `row.get('email')` always returns
     None and every user is "missing" → migration reports zero users
     with no error.

  2. Wrong header (e.g. `user_email` instead of `email`) — DictReader
     happily maps to the wrong key, loader yields empty strings, loop
     filters them out, reports "0 users, all green."

  3. Trailing-whitespace header (`'email '` vs `'email'`) — same mis-mapping.

`open_csv_with_bom_strip()` opens the file with `utf-8-sig` so the BOM
is consumed automatically. `validate_header()` compares the parsed
header to an expected set and raises `CSVHeaderError` with a specific
message when it differs — no more silent empty iterations.
"""

import csv


class CSVHeaderError(ValueError):
    """Header doesn't match the expected set. Not the same as
    a missing file — that should surface as FileNotFoundError from
    the caller."""


def read_csv_dictreader(path, *, required_columns=()):
    """Open a CSV file with BOM stripping + case-insensitive header
    validation. Returns (header_list, list_of_dict_rows).

    `required_columns`: iterable — the loader raises CSVHeaderError when
    none of them appear in the parsed header (case-insensitive).
    Empty/falsy required_columns disables the check.
    """
    # utf-8-sig silently strips a leading BOM if present; otherwise
    # identical to utf-8.
    with open(path, encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        header = reader.fieldnames or []
        # Normalize whitespace for tolerance (but keep original casing in
        # the returned header list — callers that care can .strip() downstream).
        normalized_header = {(c or '').strip().lower() for c in header}
        if required_columns:
            required_lower = {c.lower() for c in required_columns}
            if not (normalized_header & required_lower):
                raise CSVHeaderError(
                    f'CSV header {header!r} has none of the required columns '
                    f'{list(required_columns)!r} — file was probably saved with '
                    f'wrong schema or a non-UTF-8 encoding.'
                )
        rows = [
            {(k or '').strip(): (v.strip() if isinstance(v, str) else v)
             for k, v in row.items()}
            for row in reader
        ]
    return header, rows
