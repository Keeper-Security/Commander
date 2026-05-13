"""Email-domain remapping for cross-domain migrations.

When an enterprise moves tenants the email domain often changes too
(acme.com → acme.io, internal → public). Every downstream step that
keys off email — user invite, record share, ownership — must use the
NEW domain or it will fail silently (USER_NOT_FOUND on target).

This module is intentionally tiny and pure so every subcommand can apply
the same remap without a new dependency on Commander.

Usage
-----

    from .email_remap import remap_email

    new = remap_email('alice@acme.com', 'acme.com', 'acme.io')
    # → 'alice@acme.io'

    # Pass-through when no remap requested:
    remap_email('alice@acme.com', '', '')     # 'alice@acme.com'
    remap_email('alice@other.com', 'acme.com', 'acme.io')  # unchanged

The helpers preserve case on the local part (so `Admin@Acme.com`
becomes `Admin@acme.io`) and lower-case the matched domain. Non-matching
rows pass through untouched — callers should warn if they expected a
match, but this module never raises.
"""

from __future__ import annotations

import logging
from typing import Iterable, List, Tuple


def _split(email: str) -> Tuple[str, str]:
    if not email or '@' not in email:
        return (email or '', '')
    local, _, domain = email.rpartition('@')
    return local, domain


def remap_email(email: str, old_domain: str, new_domain: str) -> str:
    """Return email with its domain replaced if it matches old_domain.

    Blank old/new → pass-through. Case-insensitive domain match.
    Preserves local-part case.
    """
    if not (old_domain and new_domain):
        return email
    local, domain = _split(email)
    if not local:
        return email
    if domain.lower() != old_domain.lower():
        return email
    return f'{local}@{new_domain.lower()}'


def remap_many(emails: Iterable[str], old_domain: str,
                new_domain: str) -> List[str]:
    """Remap a sequence of addresses, preserving order."""
    return [remap_email(e, old_domain, new_domain) for e in emails]


def remap_rows(rows: Iterable[dict], field: str,
                old_domain: str, new_domain: str) -> List[dict]:
    """Return rows with `row[field]` remapped. Leaves other fields alone
    and emits a NEW list of NEW dicts so callers can compare before/after.
    """
    out = []
    for row in rows or []:
        new_row = dict(row)
        if field in new_row:
            before = new_row[field]
            new_row[field] = remap_email(before, old_domain, new_domain)
            if before != new_row[field]:
                new_row[f'_{field}_original'] = before
        out.append(new_row)
    return out


def validate_domain(domain: str) -> str:
    """Return '' if the string looks like a plausible domain, else an
    error message. Used by CLI flag validators / wizard prompts."""
    if not domain:
        return ''
    if '@' in domain or ' ' in domain:
        return f'domain must not contain @ or whitespace: {domain!r}'
    if '.' not in domain:
        return f'domain must contain at least one dot: {domain!r}'
    return ''


def summarize_remap(old_domain: str, new_domain: str,
                     sample_emails: Iterable[str]) -> dict:
    """Preview what a remap would do against a sample — for dry-run
    reports and wizard banners."""
    matched, unchanged = 0, 0
    examples = []
    for e in sample_emails or []:
        new = remap_email(e, old_domain, new_domain)
        if new != e:
            matched += 1
            if len(examples) < 5:
                examples.append(f'{e} → {new}')
        else:
            unchanged += 1
    return {
        'old_domain': old_domain,
        'new_domain': new_domain,
        'matched': matched,
        'unchanged': unchanged,
        'examples': examples,
    }


def infer_domains_from_spec(spec: dict) -> Tuple[str, str]:
    """Derive (old_domain, new_domain) from a run-spec, or ('','') when
    the spec doesn't pin them. Wizard sets these explicitly under the
    `email_remap` key; we also accept per-side defaults shaped like
    source.email_domain / target.email_domain."""
    remap = (spec or {}).get('email_remap') or {}
    if remap.get('old_domain') and remap.get('new_domain'):
        return remap['old_domain'], remap['new_domain']
    src = ((spec or {}).get('source') or {}).get('email_domain') or ''
    tgt = ((spec or {}).get('target') or {}).get('email_domain') or ''
    if src and tgt and src.lower() != tgt.lower():
        return src, tgt
    return '', ''


def log_remap_banner(old_domain: str, new_domain: str):
    """Emit an INFO banner so every wrapped step shows the remap in play."""
    if not (old_domain and new_domain):
        return
    logging.info('Email-domain remap active: @%s → @%s', old_domain, new_domain)
