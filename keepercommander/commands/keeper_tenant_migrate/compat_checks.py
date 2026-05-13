"""Pre-flight compatibility checks — catch migration blockers EARLY.

Three checks the wizard runs before committing to a destructive phase:

  1. node_depth_compat(source_tree, target_tenant_max_depth=None)
     Source may have nodes nested 6-levels deep; target's enterprise
     plan may cap at 4. We compute source max depth and compare.

  2. record_type_compat(source_record_types, target_record_types)
     Source records may reference a custom record_type that doesn't
     exist on target. Without loading it first, import silently forces
     every such record to 'login'.

  3. attachment_size_survey(records, cap_bytes=100 * 1024 * 1024)
     Walks source records' attachment list and flags any file >= cap.
     Commander's upload-attachment rejects these; pre-flight warning
     lets the admin decide (split, skip, or approve).

Each check returns a CompatCheck with verdict ok | warn | fail and
structured detail the wizard can render.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


OK = 'ok'
WARN = 'warn'
FAIL = 'fail'


@dataclass
class CompatCheck:
    name: str
    verdict: str               # ok | warn | fail
    message: str
    details: List[str] = field(default_factory=list)


# ─── 1. Node-depth compatibility ─────────────────────────────────────────────


def _count_depth(path: str) -> int:
    """Node paths use backslash — depth is segment count minus 1."""
    if not path:
        return 0
    return path.count('\\')


def max_node_depth(nodes: List[Dict[str, Any]]) -> int:
    """Walk a node list; return deepest depth. Accepts either the
    live_inventory shape (parent = path string) or plan-dir shape
    (parent_id = int, parent_node = path string)."""
    if not nodes:
        return 0
    max_depth = 0
    for n in nodes:
        parent = n.get('parent') or n.get('parent_node') or ''
        depth = _count_depth(parent) + 1  # +1 because n itself is a level below its parent path
        if depth > max_depth:
            max_depth = depth
    return max_depth


def node_depth_compat(source_nodes: List[Dict[str, Any]],
                       target_max_depth: Optional[int] = None) -> CompatCheck:
    """Report the deepest source node path vs target's tolerance.

    `target_max_depth` None → report source depth only, verdict=ok.
    """
    depth = max_node_depth(source_nodes)
    if target_max_depth is None:
        return CompatCheck(
            name='node_depth',
            verdict=OK,
            message=f'source max node depth: {depth}',
            details=[f'{depth} levels (no target limit supplied)'],
        )
    if depth <= target_max_depth:
        return CompatCheck(
            name='node_depth',
            verdict=OK,
            message=f'source depth {depth} ≤ target limit {target_max_depth}',
        )
    return CompatCheck(
        name='node_depth',
        verdict=FAIL,
        message=f'source depth {depth} > target limit {target_max_depth}',
        details=[
            'Target tenant cannot contain nodes at this depth. '
            'Either flatten the source subtree or re-parent the deepest nodes.'
        ],
    )


# ─── 2. Record-type compatibility ───────────────────────────────────────────


def _rt_ids(record_types: List[Any]) -> set:
    out = set()
    for rt in record_types or []:
        if isinstance(rt, dict):
            content = rt.get('content') or rt
            if isinstance(content, dict):
                rt_id = content.get('$id') or rt.get('name')
                if rt_id:
                    out.add(rt_id)
    return out


def record_type_compat(source_record_types: List[Any],
                        target_record_types: List[Any]) -> CompatCheck:
    """Return FAIL when source references a type missing from target."""
    src = _rt_ids(source_record_types)
    tgt = _rt_ids(target_record_types)
    missing = sorted(src - tgt)
    if not missing:
        return CompatCheck(
            name='record_types',
            verdict=OK,
            message=f'all {len(src)} source record types present on target',
        )
    return CompatCheck(
        name='record_types',
        verdict=FAIL,
        message=f'{len(missing)} record type(s) missing on target',
        details=[
            f'missing: {", ".join(missing)}',
            'Run `tenant-migrate structure --steps 0` on the target to '
            'load custom record types BEFORE attempting record import.',
        ],
    )


# ─── 3. Attachment size survey ──────────────────────────────────────────────


DEFAULT_ATTACHMENT_CAP_BYTES = 100 * 1024 * 1024   # Commander's default limit


def attachment_size_survey(records: List[Dict[str, Any]],
                            *,
                            cap_bytes: int = DEFAULT_ATTACHMENT_CAP_BYTES
                            ) -> CompatCheck:
    """Scan records for attachments >= cap_bytes. Returns WARN when any
    are over the limit — upload will fail for them.

    `records` expects the live_inventory / inventory shape: each rec
    may carry an optional `attachments: [{id, name, size}]` list. When
    absent we emit an OK verdict rather than a false-positive warning.
    """
    offenders = []
    inspected = 0
    for rec in records or []:
        for att in rec.get('attachments') or []:
            inspected += 1
            try:
                size = int(att.get('size') or 0)
            except (TypeError, ValueError):
                size = 0
            if size >= cap_bytes:
                offenders.append({
                    'record_title': rec.get('title', ''),
                    'file_name': att.get('name', ''),
                    'size_mb': round(size / (1024 * 1024), 1),
                })
    if not inspected:
        return CompatCheck(
            name='attachment_size',
            verdict=OK,
            message='no attachments inspected — records lack size metadata',
        )
    if not offenders:
        return CompatCheck(
            name='attachment_size',
            verdict=OK,
            message=f'all {inspected} attachments under '
                    f'{cap_bytes // (1024 * 1024)}MB cap',
        )
    details = [
        f'{o["record_title"]!r} → {o["file_name"]!r} ({o["size_mb"]}MB)'
        for o in offenders[:20]
    ]
    if len(offenders) > 20:
        details.append(f'…and {len(offenders) - 20} more')
    return CompatCheck(
        name='attachment_size',
        verdict=WARN,
        message=f'{len(offenders)} attachment(s) over '
                f'{cap_bytes // (1024 * 1024)}MB cap — will fail upload',
        details=details,
    )


# ─── Convenience: run all three ─────────────────────────────────────────────


def run_all(source_inventory: Dict[str, Any],
            target_state: Dict[str, Any],
            *,
            target_max_depth: Optional[int] = None,
            attachment_cap_bytes: int = DEFAULT_ATTACHMENT_CAP_BYTES
            ) -> List[CompatCheck]:
    """Invoke each check against a loaded inventory + target_state dict."""
    entities = (source_inventory or {}).get('entities') or {}
    return [
        node_depth_compat(entities.get('nodes') or [],
                          target_max_depth=target_max_depth),
        record_type_compat(
            (source_inventory or {}).get('record_types') or [],
            (target_state or {}).get('record_types') or [],
        ),
        attachment_size_survey(entities.get('records') or [],
                                cap_bytes=attachment_cap_bytes),
    ]
