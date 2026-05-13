"""End-to-end migration orchestrator (port of run_migration.sh).

Sequences phase runs with checkpoints, gates, and resume support. The bash
orchestrator's 13 numbered phases collapse into 7 logical stages here:

  plan       → capture source inventory + user transition plan
  users      → invite/extend users on target + per-user placement
  structure  → restore nodes/teams/roles/enforcements/SFs
  records    → convert + import records, attachments, direct shares
  verify     → field-level validation against frozen inventory
  reconcile  → Markdown report of what migrated vs what's missing
  gate       → point-of-no-return confirmation before any source destruction

Each stage is a callable accepting a shared OrchestratorContext; stages can
be skipped (--phase N / --end-phase N), paused at gates, or resumed from
the last completed checkpoint.
"""

import json
import logging
import os
from datetime import datetime


class Stage:
    PLAN = 'plan'
    USERS = 'users'
    STRUCTURE = 'structure'
    RECORDS = 'records'
    VERIFY = 'verify'
    RECONCILE = 'reconcile'
    GATE = 'gate'


# Canonical ordering used by phase/end-phase flags.
STAGE_ORDER = [
    Stage.PLAN,
    Stage.USERS,
    Stage.STRUCTURE,
    Stage.RECORDS,
    Stage.VERIFY,
    Stage.RECONCILE,
    Stage.GATE,
]


class Status:
    PASSED = 'PASSED'
    SKIPPED = 'SKIPPED'
    FAILED = 'FAILED'
    PAUSED = 'PAUSED'
    BLOCKED = 'BLOCKED'
    AUTHORIZED = 'AUTHORIZED'


class Checkpoint:
    """File-backed state so --resume can pick up after a mid-run exit.

    Matches the bash script's .migration_state format:
        PHASE=<stage>
        STATUS=<status>
        TIMESTAMP=<iso8601>
    """

    def __init__(self, path):
        self.path = path

    def read(self):
        if not os.path.exists(self.path):
            return None
        out = {}
        with open(self.path) as f:
            for line in f:
                if '=' in line:
                    k, v = line.rstrip().split('=', 1)
                    out[k] = v
        return out

    def write(self, phase, status):
        with open(self.path, 'w') as f:
            f.write(f'PHASE={phase}\n')
            f.write(f'STATUS={status}\n')
            f.write(f'TIMESTAMP={datetime.utcnow().isoformat()}Z\n')


def choose_stage_range(start_stage, end_stage):
    """Return the subset of STAGE_ORDER delimited by [start_stage, end_stage]."""
    if start_stage and start_stage not in STAGE_ORDER:
        raise ValueError(f'Unknown start stage: {start_stage}')
    if end_stage and end_stage not in STAGE_ORDER:
        raise ValueError(f'Unknown end stage: {end_stage}')
    start_idx = STAGE_ORDER.index(start_stage) if start_stage else 0
    end_idx = STAGE_ORDER.index(end_stage) + 1 if end_stage else len(STAGE_ORDER)
    if start_idx > end_idx:
        raise ValueError(f'start={start_stage} is after end={end_stage}')
    return STAGE_ORDER[start_idx:end_idx]


def compute_resume_stage(checkpoint_state):
    """Return the stage to resume from given a parsed checkpoint state dict."""
    if not checkpoint_state:
        return STAGE_ORDER[0]
    last_stage = checkpoint_state.get('PHASE', '')
    last_status = checkpoint_state.get('STATUS', '')
    if last_stage not in STAGE_ORDER:
        return STAGE_ORDER[0]
    # Successful/skipped/authorized stages are done — advance to the next.
    if last_status in (Status.PASSED, Status.SKIPPED, Status.AUTHORIZED):
        idx = STAGE_ORDER.index(last_stage)
        return STAGE_ORDER[idx + 1] if idx + 1 < len(STAGE_ORDER) else None
    # FAILED / PAUSED / BLOCKED — re-run the same stage
    return last_stage


class OrchestratorContext:
    """Mutable dict-like container shared across all stages."""

    def __init__(self, **kwargs):
        self.state = dict(kwargs)
        self.stage_results = []

    def get(self, key, default=None):
        return self.state.get(key, default)

    def set(self, key, value):
        self.state[key] = value

    def record(self, stage, status, notes=''):
        self.stage_results.append({
            'stage': stage, 'status': status, 'notes': notes,
            'at': datetime.utcnow().isoformat() + 'Z',
        })


class Orchestrator:
    """Sequences stages with checkpoint persistence.

    `stages` maps a stage name to a callable(ctx) → status. Callables may
    return any of the Status values; only PASSED / SKIPPED / AUTHORIZED
    advance the checkpoint. PAUSED / FAILED / BLOCKED stop the run.

    Stages not in the map are recorded as SKIPPED.
    """

    def __init__(self, stages, checkpoint_path, *, auto_confirm=False):
        self.stages = stages
        self.checkpoint = Checkpoint(checkpoint_path)
        self.auto_confirm = auto_confirm

    def resolve_start(self, start_stage=None, resume=False):
        if resume:
            cp = self.checkpoint.read()
            resumed = compute_resume_stage(cp)
            if resumed is None:
                logging.info('All stages already completed — nothing to do.')
                return None
            return resumed
        return start_stage or STAGE_ORDER[0]

    def run(self, ctx, start_stage=None, end_stage=None, resume=False):
        effective_start = self.resolve_start(start_stage, resume=resume)
        if effective_start is None:
            return ctx
        to_run = choose_stage_range(effective_start, end_stage)
        logging.info('Orchestrator running stages: %s', to_run)

        for stage in to_run:
            fn = self.stages.get(stage)
            if fn is None:
                ctx.record(stage, Status.SKIPPED, 'no handler registered')
                self.checkpoint.write(stage, Status.SKIPPED)
                continue
            try:
                status = fn(ctx) or Status.PASSED
            except Exception as exc:                       # noqa: BLE001 — orchestrator needs to catch
                logging.exception('Stage %s raised', stage)
                ctx.record(stage, Status.FAILED, f'exception: {exc!r}')
                self.checkpoint.write(stage, Status.FAILED)
                return ctx
            ctx.record(stage, status)
            self.checkpoint.write(stage, status)
            if status in (Status.PAUSED, Status.FAILED, Status.BLOCKED):
                logging.info('Stage %s returned %s — stopping', stage, status)
                return ctx
        return ctx

    def save_state(self, ctx, output_dir):
        """Dump ctx.stage_results to JSON for post-run inspection."""
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, 'orchestrator_results.json')
        with open(path, 'w') as f:
            json.dump(ctx.stage_results, f, indent=2)
        return path
