"""Compliance + data-residency checks across source/target profiles.

Pure functions — given two `TenantProfile` objects, decide whether the
migration is:
  ALLOW           — same region, no residency tags that block it
  WARN            — cross-region but neither side pins residency
  BLOCKED         — residency tag forbids leaving the region
  OVERRIDE        — the user opted in via a `--override-data-residency`
                    flag; we log the compliance-event level but proceed.

Audit stamps derived here are embedded into every audit-log event in
commands.py so compliance can replay the decision trail post-hoc.
"""

from dataclasses import dataclass
from typing import List, Optional


ALLOW = 'ALLOW'
WARN = 'WARN'
BLOCKED = 'BLOCKED'
OVERRIDE = 'OVERRIDE'


@dataclass
class ComplianceDecision:
    verdict: str                  # ALLOW | WARN | BLOCKED | OVERRIDE
    source_region: str
    target_region: str
    source_residency: str
    target_residency: str
    reasons: List[str]            # human-readable diagnostic lines
    audit_tags: List[str]         # union of compliance_tags from both sides
    cross_region: bool            # shortcut for audit log


def evaluate(source_profile, target_profile, *, override: bool = False) -> ComplianceDecision:
    """Return a decision for a source→target migration.

    `override` corresponds to the caller's `--override-data-residency`
    flag — when True, what would otherwise be BLOCKED becomes OVERRIDE
    with both sides' tags preserved in the audit stamps.
    """
    src_region = (source_profile.effective_region or '').strip().upper()
    tgt_region = (target_profile.effective_region or '').strip().upper()
    src_residency = (source_profile.data_residency or '').strip().upper()
    tgt_residency = (target_profile.data_residency or '').strip().upper()
    tags = sorted(set(source_profile.compliance_tags or []) |
                   set(target_profile.compliance_tags or []))
    reasons = []
    cross_region = bool(src_region and tgt_region and src_region != tgt_region)

    # Rule 1 — data_residency is an absolute block unless overridden.
    residency_violation = False
    if src_residency and tgt_region and src_residency != tgt_region:
        residency_violation = True
        reasons.append(
            f'source requires data_residency={src_residency} but target is in {tgt_region}'
        )
    if tgt_residency and src_region and tgt_residency != src_region:
        residency_violation = True
        reasons.append(
            f'target requires data_residency={tgt_residency} but source is in {src_region}'
        )

    if residency_violation:
        if override:
            reasons.append('OVERRIDE flag set — proceeding under operator liability')
            return ComplianceDecision(
                verdict=OVERRIDE,
                source_region=src_region, target_region=tgt_region,
                source_residency=src_residency, target_residency=tgt_residency,
                reasons=reasons, audit_tags=tags, cross_region=cross_region,
            )
        return ComplianceDecision(
            verdict=BLOCKED,
            source_region=src_region, target_region=tgt_region,
            source_residency=src_residency, target_residency=tgt_residency,
            reasons=reasons, audit_tags=tags, cross_region=cross_region,
        )

    # Rule 2 — cross-region without residency pin is WARN.
    if cross_region:
        reasons.append(
            f'cross-region migration: source={src_region} target={tgt_region}. '
            'Confirm your legal/compliance team has approved the transfer.'
        )
        return ComplianceDecision(
            verdict=WARN,
            source_region=src_region, target_region=tgt_region,
            source_residency=src_residency, target_residency=tgt_residency,
            reasons=reasons, audit_tags=tags, cross_region=True,
        )

    # Rule 3 — same region or undetermined → ALLOW.
    return ComplianceDecision(
        verdict=ALLOW,
        source_region=src_region, target_region=tgt_region,
        source_residency=src_residency, target_residency=tgt_residency,
        reasons=reasons, audit_tags=tags, cross_region=False,
    )


def format_decision(decision: ComplianceDecision) -> str:
    """Human-readable banner for the wizard / log."""
    lines = [f'Compliance: {decision.verdict}']
    lines.append(f'  source: {decision.source_region or "?"} '
                 f'(residency: {decision.source_residency or "none"})')
    lines.append(f'  target: {decision.target_region or "?"} '
                 f'(residency: {decision.target_residency or "none"})')
    for r in decision.reasons:
        lines.append(f'  - {r}')
    if decision.audit_tags:
        lines.append(f'  tags: {", ".join(decision.audit_tags)}')
    return '\n'.join(lines)
