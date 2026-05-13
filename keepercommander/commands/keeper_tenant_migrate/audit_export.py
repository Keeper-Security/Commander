"""SIEM-ready export of the tamper-evident audit log.

The plugin already records every mutating subcommand into
`<run_dir>/audit.log` as chained JSON lines (see `audit.py`). Security
teams want those events in their SIEM's native dialect — this module
formats each event without touching the chain.

Supported formats
-----------------

  - `json-lines` — pass-through; one event per line, identical to
    the source log (minus the chain fields, which are SIEM noise).
  - `syslog`     — RFC-5424 structured messages with app-name
    `keeper-tenant-migrate`.
  - `cef`        — ArcSight Common Event Format.

Every line carries the event's original `signature` field in the
structured-data section so the SIEM record can be cross-referenced
against the source audit.log for integrity checks later.
"""

from __future__ import annotations

import json
import os
import socket
from typing import Iterator, List


SUPPORTED_FORMATS = ('json-lines', 'syslog', 'cef')


def read_audit_events(log_path: str) -> Iterator[dict]:
    """Yield each parsed JSON event. Skips blank lines; raises on
    malformed JSON so bad logs aren't silently truncated."""
    if not os.path.exists(log_path):
        return
    with open(log_path, encoding='utf-8') as f:
        for lineno, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                yield json.loads(raw)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f'{log_path}:{lineno} malformed JSON — {e}'
                ) from None


def _severity_from(event: dict) -> int:
    """Map subcommand → syslog severity. Destructive ops are warnings;
    read-only and reconcile are informational."""
    sub = (event.get('subcommand') or '').lower()
    if sub in ('cleanup', 'decommission', 'take-ownership', 'transfer-user',
                'records-import', 'users', 'structure'):
        return 4   # warning
    if sub in ('verify', 'reconcile', 'plan', 'records-export',
                'capture-target-state', 'session', 'self-test'):
        return 6   # informational
    return 5       # notice — default


def to_jsonlines(events: Iterator[dict]) -> Iterator[str]:
    """Emit JSON lines stripped of chain-only fields."""
    for ev in events:
        out = dict(ev)
        out.pop('prev_hash', None)
        yield json.dumps(out, sort_keys=True)


def _rfc5424_ts(ts: str) -> str:
    """Keeper's audit timestamps are `2026-04-18T12:34:56Z`. RFC 5424
    wants `2026-04-18T12:34:56.000000+00:00`. Accept either and pass."""
    if not ts:
        return '-'
    if ts.endswith('Z'):
        return ts[:-1] + '.000000+00:00'
    return ts


def to_syslog(events: Iterator[dict], *, hostname: str = '') -> Iterator[str]:
    """RFC 5424 lines. PRI = facility(1=user)*8 + severity."""
    host = hostname or socket.gethostname() or '-'
    app = 'keeper-tenant-migrate'
    for ev in events:
        sev = _severity_from(ev)
        pri = 1 * 8 + sev
        ts = _rfc5424_ts(ev.get('timestamp') or '')
        msgid = (ev.get('subcommand') or '-')[:32] or '-'
        sig = (ev.get('signature') or '-')[:16]
        sd = f'[ktm@32473 sig="{sig}"]'
        summary = json.dumps(
            {k: ev.get(k) for k in ('summary', 'inputs', 'outputs') if k in ev},
            sort_keys=True,
            separators=(',', ':'),
        )
        yield f'<{pri}>1 {ts} {host} {app} - {msgid} {sd} {summary}'


def _default_version() -> str:
    """Resolve the toolkit version at call-time so SIEM events always
    carry the currently-installed version. Bug 35 — pre-fix this was
    hardcoded to '1.1.0' and drifted multiple releases behind."""
    try:
        from . import __version__
        return __version__
    except ImportError:
        return 'unknown'


def to_cef(events: Iterator[dict], *, vendor: str = 'Keeper',
            product: str = 'TenantMigrate',
            version: str = '') -> Iterator[str]:
    """ArcSight CEF 0 lines."""
    if not version:
        version = _default_version()
    for ev in events:
        sub = ev.get('subcommand') or 'unknown'
        sig_id = (ev.get('signature') or '').replace('|', '_')[:16]
        sev = _severity_from(ev)
        # CEF scales 0..10 — syslog sev 4 (warn) → 7, sev 6 (info) → 3
        cef_sev = {4: 7, 5: 5, 6: 3}.get(sev, 5)
        header = f'CEF:0|{vendor}|{product}|{version}|{sub}|{sub}|{cef_sev}'
        ext_parts = []
        ts = ev.get('timestamp') or ''
        if ts:
            ext_parts.append(f'rt={ts}')
        summary = ev.get('summary') or {}
        if isinstance(summary, dict):
            for k, v in sorted(summary.items()):
                if isinstance(v, (int, str, bool, float)):
                    # CEF extensions escape | and =
                    val = str(v).replace('\\', '\\\\').replace('=', '\\=')
                    val = val.replace('|', '\\|')
                    ext_parts.append(f'cs_{k}={val}')
        ext_parts.append(f'signatureId={sig_id}')
        yield header + '|' + ' '.join(ext_parts)


def export(log_path: str, output_path: str, fmt: str,
            *, hostname: str = '') -> dict:
    """Read audit.log, write formatted lines to output_path (0600).
    Returns {written, format, output_path}."""
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(
            f'format must be one of {SUPPORTED_FORMATS}; got {fmt!r}')
    events = list(read_audit_events(log_path))
    if fmt == 'json-lines':
        lines = to_jsonlines(iter(events))
    elif fmt == 'syslog':
        lines = to_syslog(iter(events), hostname=hostname)
    else:
        lines = to_cef(iter(events))

    with open(output_path, 'w', encoding='utf-8') as f:
        count = 0
        for line in lines:
            f.write(line + '\n')
            count += 1
    os.chmod(output_path, 0o600)
    return {'written': count, 'format': fmt, 'output_path': output_path}
