"""Chunked record-import runner.

Splits a Commander record-import JSON bundle into fixed-size record
chunks, writes each chunk to a temp file, calls the supplied
`RecordImportCommand`-like object once per chunk, sleeps a
configurable delay between chunks. The temp files are cleaned in a
`finally` so a partial run leaves no debris.

Why split out
-------------
Originally a private helper inside `commands.py` (`_run_chunked_import`,
introduced as Bug 68 in v1.6.2). Lifted into its own module in v1.6.8
(B2) so:
  - The chunked-import logic has a clean public API (`run_chunked_import`)
    that other consumers can import without taking a dependency on
    `commands.py` (which pulls in argparse + every subcommand).
  - The benchmark harness (B3) and stress fixture (B4) can drive the
    runner directly.
  - The Commander team — if interested — can adopt the runner as a
    reference implementation for chunked import without inheriting
    the whole plugin.

Usage
-----
```python
from keepercommander.commands.keeper_tenant_migrate.bulk_records import run_chunked_import
from keepercommander.importer.commands import RecordImportCommand

with open('bundle.json') as f:
    bundle = json.load(f)

run_chunked_import(
    cmd=RecordImportCommand(),
    params=params,
    base_kwargs={'format': 'json', 'shared': True, 'permissions': 'N'},
    bundle=bundle,
    chunk_size=200,
    chunk_delay=2.0,
)
```

The `cmd` argument is duck-typed: anything with an
`execute(params, **kwargs)` method that accepts `name=<path>` works.
The runner does not import `keepercommander` directly; consumers wire
in whatever import command they want.

Shared folders
--------------
Commander's import command creates shared folders during the FIRST
chunk only; subsequent chunks reference them by the folder UIDs/paths
embedded in the records they carry. The runner enforces this by
attaching `bundle['shared_folders']` only to chunk #1.

Logging
-------
Each chunk emits a WARNING log line at start so a tail-following
operator can see progress in real time even when the run is hours
long. The throttle module's `THROTTLE_LOG_MARKER` is unrelated — the
runner's own log lines are not parsed by anything; they exist only
for human consumption.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
import time
from typing import Any, Mapping


def run_chunked_import(*, cmd: Any, params: Any, base_kwargs: Mapping[str, Any],
                       bundle: Mapping[str, Any],
                       chunk_size: int, chunk_delay: float) -> None:
    """Drive `cmd.execute(params, **kwargs)` once per `chunk_size`-sized
    slice of `bundle['records']`, with `chunk_delay` seconds between
    chunks.

    Raises whatever `cmd.execute` raises — caller decides whether the
    partial-import state warrants a retry, a reconcile, or a halt.
    """
    if chunk_size <= 0:
        raise ValueError(f'chunk_size must be > 0; got {chunk_size!r}')
    if chunk_delay < 0:
        raise ValueError(f'chunk_delay must be >= 0; got {chunk_delay!r}')

    records = bundle.get('records') or []
    folders = bundle.get('shared_folders') or []
    total = len(records)
    chunks = [records[i:i + chunk_size]
              for i in range(0, total, chunk_size)]
    logging.warning('records-import: chunked mode — %d chunks of <=%d '
                    'records, %.1fs delay between',
                    len(chunks), chunk_size, chunk_delay)

    tmpdir = tempfile.mkdtemp(prefix='keeper_records_chunks_')
    try:
        for i, chunk in enumerate(chunks, start=1):
            chunk_bundle: dict = {'records': chunk}
            # Shared folders ride only on chunk #1; subsequent chunks
            # reference the folders Commander already created during
            # the first chunk.
            if i == 1 and folders:
                chunk_bundle['shared_folders'] = folders
            chunk_path = os.path.join(tmpdir, f'chunk_{i:04d}.json')
            with open(chunk_path, 'w') as _f:
                json.dump(chunk_bundle, _f)
            # Plaintext record bodies on disk — owner-only even though
            # the parent tmpdir is 0o700.
            os.chmod(chunk_path, 0o600)
            kw = dict(base_kwargs)
            kw['name'] = chunk_path
            logging.warning('records-import: chunk %d/%d (%d records)',
                            i, len(chunks), len(chunk))
            cmd.execute(params, **kw)
            if i < len(chunks):
                time.sleep(chunk_delay)
    finally:
        try:
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:                           # noqa: BLE001
            pass
