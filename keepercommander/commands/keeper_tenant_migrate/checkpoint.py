"""Per-stage checkpoint + resume for loop-over-N subcommands.

Context
-------
`records-import`, `records-attachments-upload`, `records-shares`, and
`users` all iterate over a manifest and issue one mutating call per row.
At scale (500+ rows), a single transient failure mid-run meant a full
restart, duplicating every successful operation.

This module provides a narrow checkpoint protocol:

1. Before the loop, compute SHA-256 of the input manifest.
2. On each successful iteration, persist
   `{stage, input_sha256, last_index, started_at, updated_at}`
   atomically to `$RUN/checkpoints/<stage>.json`.
3. On re-run:
   - If the checkpoint is missing → start fresh at index 1.
   - If the checkpoint's `input_sha256` matches the current manifest
     AND `--resume` is set → skip to `last_index + 1`.
   - If the SHA differs → refuse unless `--force-restart` is given.
4. On successful stage completion → delete the checkpoint.

The "only clear on success" rule means a stale checkpoint file signals
an incomplete prior run: the operator can inspect it and decide whether
to resume or restart.

Per-row idempotency is a separate concern — `Checkpoint` assumes each
row is safe to re-apply OR that the caller handles duplicates via an
"already exists?" probe. The audit log (chained, appended before the
checkpoint is updated) stays intact across the gap.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Iterable, Optional


class CheckpointMismatchError(Exception):
    """Raised when an existing checkpoint doesn't match the current input."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def _hash_rows(rows: Iterable[Any]) -> str:
    """Stable SHA-256 over the row list. Rows are JSON-serialized in a
    deterministic form so re-running the same file yields the same hash.
    """
    h = hashlib.sha256()
    for r in rows:
        h.update(json.dumps(r, sort_keys=True, separators=(',', ':')).encode())
        h.update(b'\n')
    return h.hexdigest()


def _atomic_write(path: str, payload: dict) -> None:
    """Write + rename — never leave a partial checkpoint behind."""
    d = os.path.dirname(path) or '.'
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.ckpt-', dir=d)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Checkpoint:
    """A single stage's checkpoint file.

    Typical usage from a loop-runner::

        ckpt = Checkpoint('records-shares', run_dir)
        start = ckpt.resume_from(rows, resume=True, force_restart=False)

        for i, row in enumerate(rows, start=1):
            if i < start:
                continue                      # already done in prior run
            do_work(row)
            ckpt.mark_done(i)

        ckpt.clear()                          # success — stage complete

    Parameters
    ----------
    stage : str
        Short identifier — used as the filename. Must match the argparse
        subcommand name (records-import / records-shares / …).
    run_dir : str
        The run directory ($RUN). Checkpoints live in
        `$RUN/checkpoints/<stage>.json`.
    """

    def __init__(self, stage: str, run_dir: str):
        if not stage:
            raise ValueError('stage is required')
        self.stage = stage
        self.path = os.path.join(run_dir or '.', 'checkpoints',
                                 f'{stage}.json')

    # ── State I/O ───────────────────────────────────────────────────

    def load(self) -> Optional[dict]:
        if not os.path.exists(self.path):
            return None
        try:
            with open(self.path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logging.warning('checkpoint at %s unreadable (%s) — ignoring',
                            self.path, e)
            return None

    def clear(self) -> None:
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass

    def mark_done(self, index: int, *,
                  input_sha256: str,
                  extra: Optional[dict] = None) -> None:
        """Persist progress after a successful iteration.

        input_sha256: SHA-256 of the full input manifest. Included on
        every write so the checkpoint is self-describing even if a
        `started_at` entry is clobbered by a crash in the middle of the
        open().
        """
        existing = self.load() or {}
        payload = {
            'stage': self.stage,
            'input_sha256': input_sha256,
            'last_index': int(index),
            'started_at': existing.get('started_at') or _now_iso(),
            'updated_at': _now_iso(),
        }
        if extra:
            payload['extra'] = extra
        _atomic_write(self.path, payload)

    # ── Resume planning ─────────────────────────────────────────────

    def resume_from(self, rows: Iterable[Any], *,
                    resume: bool, force_restart: bool) -> int:
        """Return the 1-based index the loop should start from.

        - Returns 1 when no checkpoint exists OR resume is False.
        - Returns `last_index + 1` when a valid checkpoint matches.
        - Raises CheckpointMismatchError when a checkpoint exists but
          the input SHA differs AND force_restart is False — the caller
          must pass `--force-restart` explicitly to wipe partial state.
        - Returns 1 (after clearing) when force_restart is True.
        """
        rows = list(rows)
        input_sha = _hash_rows(rows)

        if force_restart:
            self.clear()
            return 1

        state = self.load()
        if state is None:
            return 1

        if not resume:
            # Stale checkpoint but caller hasn't opted into resume. Warn
            # and run from the top so the caller sees any divergence in
            # outputs rather than silently skipping rows.
            logging.warning(
                'checkpoint %s exists (last_index=%s) but --resume not set '
                '— running from the top; pass --resume to pick up or '
                '--force-restart to clear.',
                self.path, state.get('last_index'),
            )
            return 1

        if state.get('input_sha256') != input_sha:
            raise CheckpointMismatchError(
                f'checkpoint {self.path!r} was produced from a different '
                f'input manifest (sha mismatch). Pass --force-restart to '
                f'clear the checkpoint, or restore the original input.'
            )

        last = int(state.get('last_index') or 0)
        logging.info('Resuming %s from index %d (checkpoint: %s)',
                     self.stage, last + 1, self.path)
        return last + 1


# ── Convenience: snapshot the input ─────────────────────────────────

def hash_rows(rows: Iterable[Any]) -> str:
    """Public wrapper — stable SHA-256 of a row list."""
    return _hash_rows(rows)
