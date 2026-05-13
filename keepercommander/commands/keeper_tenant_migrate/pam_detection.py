"""Detect PAM-related records in a source inventory + export dir.

PAM (Privileged Access Manager) records don't survive a tenant
migration cleanly: the underlying rotation configuration, gateway
registration, and agent tokens are tenant-scoped. We don't attempt to
migrate them — but we MUST tell the admin which records need manual
re-configuration on the new tenant, or rotation silently breaks.

Detection surfaces
------------------

  - Record type starts with `pam` (pamMachine, pamDatabase,
    pamDirectory, pamRemoteBrowser, pamNetworkConfiguration, …)
  - Any field type starting with `pam` (pamHostname, pamResources,
    pamRemoteBrowserSettings, pamSettings, …)
  - A record whose `custom_fields` label contains the substring
    'pam_' or 'rotation' — catches legacy login-typed records that
    admins retrofitted into PAM workflows.

The detector is intentionally liberal: false positives show up in
manual-actions as "review this record", which is cheaper than missing
a rotation that silently breaks post-migration.
"""

from __future__ import annotations

from typing import Dict, Iterable, List


PAM_RECORD_TYPE_PREFIXES = ('pam',)
PAM_FIELD_TYPE_PREFIXES = ('pam',)
PAM_LABEL_KEYWORDS = ('pam_', 'rotation', 'pam-')


def _record_is_pam(rec: Dict) -> bool:
    """Return True when any PAM signal trips on `rec`."""
    rt = (rec.get('type') or '').lower()
    if any(rt.startswith(p) for p in PAM_RECORD_TYPE_PREFIXES):
        return True

    for f in rec.get('fields', []) or []:
        if not isinstance(f, dict):
            continue
        ftype = (f.get('type') or '').lower()
        if any(ftype.startswith(p) for p in PAM_FIELD_TYPE_PREFIXES):
            return True

    # Custom-field labels — catches records with hand-rolled PAM metadata
    cf = rec.get('custom_fields') or {}
    if isinstance(cf, dict):
        for label in cf.keys():
            lbl = str(label).lower()
            if any(kw in lbl for kw in PAM_LABEL_KEYWORDS):
                return True
    # Legacy shape: custom[] array of {label,value}
    for entry in rec.get('custom', []) or []:
        if isinstance(entry, dict):
            lbl = str(entry.get('label', '') or '').lower()
            if any(kw in lbl for kw in PAM_LABEL_KEYWORDS):
                return True

    return False


def detect_pam_records(records: Iterable[Dict]) -> List[Dict]:
    """Return [{uid, title, type, reason}, ...] for every PAM-flavored
    record. `reason` helps the admin see why it was flagged."""
    out = []
    for rec in records or []:
        if not _record_is_pam(rec):
            continue
        reasons = []
        rt = (rec.get('type') or '').lower()
        if any(rt.startswith(p) for p in PAM_RECORD_TYPE_PREFIXES):
            reasons.append(f'record_type={rec.get("type")}')
        for f in rec.get('fields', []) or []:
            if isinstance(f, dict):
                ftype = (f.get('type') or '').lower()
                if any(ftype.startswith(p) for p in PAM_FIELD_TYPE_PREFIXES):
                    reasons.append(f'field_type={f.get("type")}')
                    break
        cf = rec.get('custom_fields') or {}
        if isinstance(cf, dict):
            for label in cf.keys():
                lbl = str(label).lower()
                if any(kw in lbl for kw in PAM_LABEL_KEYWORDS):
                    reasons.append(f'custom_label={label}')
                    break
        out.append({
            'uid': rec.get('uid') or rec.get('record_uid') or '',
            'title': rec.get('title') or '',
            'type': rec.get('type') or '',
            'reason': '; '.join(sorted(set(reasons))) or 'unknown',
        })
    return out


def summarize_pam_impact(inventory: Dict) -> Dict:
    """Return a high-level summary for the manual-actions checklist."""
    records = (inventory or {}).get('entities', {}).get('records') or []
    flagged = detect_pam_records(records)
    type_counts: Dict[str, int] = {}
    for r in flagged:
        type_counts[r['type'] or '(untyped)'] = \
            type_counts.get(r['type'] or '(untyped)', 0) + 1
    return {
        'total_flagged': len(flagged),
        'by_type': type_counts,
        'records': flagged,
    }
