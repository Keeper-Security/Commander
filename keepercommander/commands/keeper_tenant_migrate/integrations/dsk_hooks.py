"""Stable Python API for downstream consumers of tenant-migration run-dirs.

This module exposes typed access to the canonical artifacts produced by
`keepercommander.commands.keeper_tenant_migrate` — inventory, manifest, audit chain, transition
state, vault sharing, compliance evidence. Any consumer (compliance
tooling, SIEM ingestor, declarative-SDK consumer, drift watcher) can
import from here without duplicating what the migration tool already
produces.

Stability promise: signatures here are versioned by `keepercommander.commands.keeper_tenant_migrate`'s
own SemVer. Breaking changes (renaming a function, removing it, or
changing its signature) require a deprecation alias landing alongside
the rename, with downstream consumers notified before the breaking
release ships.

Run-dir layout these helpers expect (per `OUTPUT_CONTRACT.md` v1.0):

    <run-dir>/
    ├── inventory.json           # full source-tenant state (inventory.py)
    ├── manifest.csv             # source_uid → target_uid pairing (manifest.py)
    ├── manifest.csv.sha256      # v1.1+ integrity sidecar
    ├── records_import.json      # bundled import payload (auto_migrate.py)
    ├── records_export/          # per-record JSON files (<source_uid>.json)
    ├── audit.log                # HMAC-chained operation log (audit.py prev_hash)
    └── SHA256SUMS.txt           # full-tree integrity manifest (audit.py)
"""
from __future__ import annotations

import errno
import json
import logging
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Dict, Iterator, List, Optional, Tuple

from .. import audit as _audit
from .. import manifest as _manifest_mod  # cmd's manifest writers
from .. import transition as _transition

logger = logging.getLogger(__name__)


# ─── Trust-boundary helpers ──────────────────────────────────────────────────
#
# DSK's `dsk/cli/cmd_import_from_keepercmd.py:_safe_open` uses
# O_NOFOLLOW + stat-check to refuse to read symlinked / non-regular
# input artifacts. Mirror that discipline here so DSK consumers of
# dsk_hooks get the same trust-boundary guarantees regardless of which
# import boundary they cross.


class UnsafeArtifactError(IOError):
    """Raised when a run-dir artifact violates the safe-read trust
    boundary (symlink, non-regular file, oversized, unreadable)."""


_DEFAULT_MAX_ARTIFACT_BYTES = 256 * 1024 * 1024  # 256 MiB; matches DSK default class


def _max_artifact_bytes() -> int:
    """Per-run override via ``KCM_HOOK_MAX_ARTIFACT_BYTES`` env var.

    Default ``256 * 1024 * 1024`` (256 MiB) matches DSK's ceiling for
    symmetric trust-boundary behaviour.
    """
    raw = os.environ.get("KCM_HOOK_MAX_ARTIFACT_BYTES", "")
    if not raw.strip():
        return _DEFAULT_MAX_ARTIFACT_BYTES
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_MAX_ARTIFACT_BYTES


def _safe_open(
    path: Path,
    mode: str = "r",
    *,
    encoding: Optional[str] = "utf-8",
    newline: Optional[str] = None,
) -> IO[Any]:
    """Open a run-dir artifact after symlink + regular-file + size checks.

    Refuses to follow symlinks (``O_NOFOLLOW``); refuses non-regular
    files; refuses files exceeding ``KCM_HOOK_MAX_ARTIFACT_BYTES``.

    Raises ``UnsafeArtifactError`` when the path violates any of those
    invariants. Other ``OSError`` paths (permission denied etc.) are
    re-raised as ``UnsafeArtifactError`` for a single exception class
    DSK consumers can catch.
    """
    if not set(mode) & {"r"}:
        raise ValueError("_safe_open is read-only; use cmd writers for output")
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EMLINK}:
            raise UnsafeArtifactError(
                f"{Path(path).name} is a symlink; refusing to read"
            ) from exc
        raise UnsafeArtifactError(
            f"{Path(path).name} unreadable: {type(exc).__name__}"
        ) from exc

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafeArtifactError(
                f"{Path(path).name} is not a regular file; refusing to read"
            )
        max_bytes = _max_artifact_bytes()
        if st.st_size > max_bytes:
            raise UnsafeArtifactError(
                f"{Path(path).name} is {st.st_size} bytes, exceeding "
                f"KCM_HOOK_MAX_ARTIFACT_BYTES={max_bytes}"
            )
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            logger.warning(
                "run-dir artifact %s is group/world-writable; continuing with warning",
                path,
            )
    except Exception:
        os.close(fd)
        raise

    if "b" in mode:
        return open(fd, mode, closefd=True)
    return open(fd, mode, encoding=encoding, newline=newline, closefd=True)


def _read_json_safe(path: Path) -> Any:
    """Read + parse a JSON artifact via :func:`_safe_open`."""
    with _safe_open(path) as fh:
        return json.load(fh)


# ─── Discovery ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RunDirArtifacts:
    """Stable view of files cmd produces in a run-dir.

    All `Path` attributes for required files exist when this dataclass is
    constructed by :func:`discover_run_dir`; optional sidecar attributes may
    be ``None`` for older v1.0 run-dirs.

    Integrity is NOT verified by this dataclass. Use
    :func:`verify_run_dir_integrity` before consuming the contents.
    """

    run_dir: Path
    inventory_json: Path
    manifest_csv: Path
    records_import_json: Path
    records_export_dir: Path
    audit_log: Path
    sha256sums_txt: Path
    manifest_csv_sha256: Optional[Path] = None  # v1.1+ optional
    sha256sums_minisig: Optional[Path] = None  # not produced by cmd today; reserved

    def required(self) -> List[Path]:
        """Return the always-required artifact paths (no optional sidecars)."""
        return [
            self.inventory_json, self.manifest_csv, self.records_import_json,
            self.records_export_dir, self.audit_log, self.sha256sums_txt,
        ]


_REQUIRED_FILE_NAMES = ("inventory.json", "manifest.csv", "records_import.json",
                        "audit.log", "SHA256SUMS.txt")
_REQUIRED_DIR_NAMES = ("records_export",)
_OPTIONAL_FILE_NAMES = {
    "manifest_csv_sha256": "manifest.csv.sha256",
    "sha256sums_minisig": "SHA256SUMS.txt.minisig",
}


def discover_run_dir(run_dir: Path | str) -> RunDirArtifacts:
    """Discover cmd-produced artifacts in a run-dir.

    Use this as the entry point for DSK adopt. Validates that every
    required artifact exists; raises ``FileNotFoundError`` listing all
    missing paths if any are absent.

    Optional sidecars (``manifest.csv.sha256``, ``SHA256SUMS.txt.minisig``)
    are returned when present; otherwise the corresponding attributes are
    ``None``. cmd does not currently produce ``SHA256SUMS.txt.minisig``;
    that attribute is reserved for forward-compatibility.

    Parameters
    ----------
    run_dir
        Path to the keeperCMD run-dir (the directory containing
        ``inventory.json``).

    Returns
    -------
    RunDirArtifacts
        Frozen dataclass with paths to every artifact DSK adopt expects.

    Raises
    ------
    FileNotFoundError
        If `run_dir` doesn't exist OR any of the required files/dirs is missing.
    """
    rd = Path(run_dir).resolve()
    if not rd.is_dir():
        raise FileNotFoundError(f"run_dir is not a directory: {rd}")

    missing: List[str] = []
    for name in _REQUIRED_FILE_NAMES:
        if not (rd / name).is_file():
            missing.append(name)
    for name in _REQUIRED_DIR_NAMES:
        if not (rd / name).is_dir():
            missing.append(name + "/")
    if missing:
        raise FileNotFoundError(
            f"run_dir {rd} is missing required artifacts: " + ", ".join(missing)
        )

    optionals: Dict[str, Optional[Path]] = {}
    for attr, fname in _OPTIONAL_FILE_NAMES.items():
        p = rd / fname
        optionals[attr] = p if p.is_file() else None

    return RunDirArtifacts(
        run_dir=rd,
        inventory_json=rd / "inventory.json",
        manifest_csv=rd / "manifest.csv",
        records_import_json=rd / "records_import.json",
        records_export_dir=rd / "records_export",
        audit_log=rd / "audit.log",
        sha256sums_txt=rd / "SHA256SUMS.txt",
        manifest_csv_sha256=optionals["manifest_csv_sha256"],
        sha256sums_minisig=optionals["sha256sums_minisig"],
    )


# ─── Integrity ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class IntegrityReport:
    """Result of `verify_run_dir_integrity`. ``ok`` is the AND of all
    individual checks that ran."""

    sha256sums_ok: bool
    audit_chain_ok: bool
    manifest_csv_sidecar_ok: Optional[bool]  # None if sidecar not present
    minisig_ok: Optional[bool]  # None if minisig not present (current cmd default)
    errors: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """True if every check that RAN passed (None entries don't count)."""
        return (
            self.sha256sums_ok
            and self.audit_chain_ok
            and (self.manifest_csv_sidecar_ok is not False)
            and (self.minisig_ok is not False)
        )


def verify_run_dir_integrity(
    run_dir: Path | str,
    *,
    require_minisig: bool = False,
) -> IntegrityReport:
    """Verify run-dir integrity using cmd's existing primitives.

    Runs:
      * ``audit.verify_sha256sums(run_dir)`` — full-tree SHA256SUMS check
      * ``audit.verify_audit_log(run_dir/audit.log)`` — HMAC-chain integrity
      * ``manifest.csv.sha256`` sidecar check (if sidecar present, v1.1+)
      * minisig check (only if ``require_minisig=True`` AND minisig present)

    cmd does not currently produce ``SHA256SUMS.txt.minisig``. The
    `require_minisig=False` default is the documented fallback per the
    R6.3 audit; pass ``True`` to fail-closed if cmd grows minisig
    signing in a future release.

    Returns
    -------
    IntegrityReport
        ``ok`` is True if every check that ran passed.
    """
    artifacts = discover_run_dir(run_dir)
    errors: List[str] = []

    sha256sums_ok = True
    try:
        result = _audit.verify_sha256sums(str(artifacts.run_dir))
        # cmd's verify_sha256sums returns a dict, doesn't raise on mismatch.
        if result.get("mismatch"):
            sha256sums_ok = False
            errors.append(
                "SHA256SUMS mismatch on: " + ", ".join(sorted(result["mismatch"]))
            )
        if result.get("missing"):
            sha256sums_ok = False
            errors.append(
                "SHA256SUMS missing files: " + ", ".join(sorted(result["missing"]))
            )
    except Exception as e:  # FileNotFoundError on absent manifest etc.
        sha256sums_ok = False
        errors.append(f"SHA256SUMS verification failed: {type(e).__name__}: {e}")

    audit_chain_ok = True
    try:
        _audit.verify_audit_log(str(artifacts.audit_log))
    except _audit.AuditChainCorrupt as e:
        audit_chain_ok = False
        errors.append(f"audit.log chain corrupt: {e}")
    except Exception as e:
        audit_chain_ok = False
        errors.append(f"audit.log verify error: {type(e).__name__}: {e}")

    manifest_csv_sidecar_ok: Optional[bool] = None
    if artifacts.manifest_csv_sha256 is not None:
        manifest_csv_sidecar_ok = _verify_csv_sidecar(
            artifacts.manifest_csv, artifacts.manifest_csv_sha256, errors
        )

    minisig_ok: Optional[bool] = None
    if artifacts.sha256sums_minisig is not None:
        minisig_ok = False
        errors.append(
            "SHA256SUMS.txt.minisig present but cmd-side minisig support "
            "is not yet implemented; see R6.3 trust-boundary review."
        )
    elif require_minisig:
        minisig_ok = False
        errors.append("require_minisig=True but no SHA256SUMS.txt.minisig found")

    return IntegrityReport(
        sha256sums_ok=sha256sums_ok,
        audit_chain_ok=audit_chain_ok,
        manifest_csv_sidecar_ok=manifest_csv_sidecar_ok,
        minisig_ok=minisig_ok,
        errors=tuple(errors),
    )


def _verify_csv_sidecar(
    csv_path: Path, sidecar_path: Path, errors: List[str]
) -> bool:
    """Helper for v1.1+ ``manifest.csv.sha256`` sidecar check."""
    try:
        expected = sidecar_path.read_text(encoding="utf-8").strip().split()[0]
        actual = _audit.sha256_of_file(str(csv_path))
        if expected.lower() != actual.lower():
            errors.append(
                f"manifest.csv.sha256 mismatch: expected {expected[:16]}…, "
                f"actual {actual[:16]}…"
            )
            return False
        return True
    except Exception as e:
        errors.append(f"manifest.csv sidecar read error: {type(e).__name__}: {e}")
        return False


# ─── Audit chain ────────────────────────────────────────────────────────


def get_audit_chain_tail(run_dir: Path | str) -> Dict[str, Any]:
    """Return the last event from cmd's HMAC-chained audit log.

    DSK can use the returned event's ``signature`` as the ``prev_hash`` for
    new events appended to the same chain — extending cmd's tamper-evident
    audit forward through the Day 1+ DSK lifecycle.

    Returns
    -------
    dict
        The last audit event with at least ``timestamp``, ``event``,
        ``prev_hash``, and ``signature`` keys (per ``audit.py`` schema).
        Returns ``{}`` if the audit log is empty.
    """
    artifacts = discover_run_dir(run_dir)
    last_sig = _audit._last_signature(str(artifacts.audit_log))
    if last_sig is None:
        return {}
    last_line = ""
    with _safe_open(artifacts.audit_log) as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                last_line = stripped
    if not last_line:
        return {}
    return json.loads(last_line)


# ─── Transition / users ────────────────────────────────────────────


def get_users_transition_table(
    run_dir: Path | str,
) -> List[Dict[str, Any]]:
    """Return cmd's user-transition table as typed dicts.

    Uses ``transition.load_source_users_from_inventory`` against
    ``inventory.json``. Each entry has at least ``email`` and the per-user
    fields cmd's transition pipeline tracks (status, roles, teams, etc.).

    Note: a richer table including target-side categorization is built by
    ``transition.categorize`` when the operator runs the transition stage.
    That output is in the run-dir's ``users_transition.csv`` if present;
    DSK should prefer the inventory-derived table for adopt-time use.
    """
    artifacts = discover_run_dir(run_dir)
    return _transition.load_source_users_from_inventory(str(artifacts.inventory_json))


def get_transition_baseline(run_dir: Path | str) -> Dict[str, Dict[str, Any]]:
    """Drift-watch baseline keyed by source-user email.

    Returns ``{email: {status, roles, teams, ...}}`` for every source user
    in the inventory. DSK ``drift-watch`` can compare current target state
    against this baseline to flag transitions that didn't complete (users
    invited but not activated, etc.).
    """
    rows = get_users_transition_table(run_dir)
    return {
        (row.get("email") or "").strip().lower(): row
        for row in rows
        if row.get("email")
    }


# ─── Validators ─────────────────────────────────────────────────────────


def validate_run_dir_for_adopt(
    run_dir: Path | str,
    *,
    target_state: Optional[Dict[str, Any]] = None,
    target_label: str = "(adopt-time)",
) -> List[Any]:
    """Run cmd validation against a run-dir.

    Two modes — chosen by whether ``target_state`` is supplied:

    * **Adopt-time (default, target_state=None)**: returns inventory-only
      checks — basic shape + ref-graph integrity for the source tenant.
      No source-vs-target comparison. Safe to call before a live target
      exists. Faster.

    * **Verify-time (target_state=<dict>)**: runs the full 9-phase
      validator framework comparing source-vs-target. cmd's existing
      ``Validator(ctx).run()`` is invoked.

    DSK adopt should refuse to ingest if any ``FAIL`` rows are returned.

    Note: cmd's ``tenant-migrate verify`` subcommand currently exits 0
    even when ``checks.csv`` has FAIL rows (silent-failure bug; fix on
    branch ``fix/verify-nonzero-on-fail-rows``). DSK should rely on the
    structured ``Check`` list returned here, NOT on cmd's verify exit
    code, to be robust against pre-fix cmd installs.
    """
    artifacts = discover_run_dir(run_dir)
    inventory = _read_json_safe(artifacts.inventory_json)

    if target_state is None:
        return _inventory_only_checks(inventory)

    from ..validate import ValidationContext, Validator
    ctx = ValidationContext(
        inventory=inventory,
        target_state=target_state,
        target_label=target_label,
        params=None,
    )
    return Validator(ctx).run()


def _inventory_only_checks(inventory: Dict[str, Any]) -> List[Any]:
    """Source-side validation that doesn't require a target state.

    Yields ``Check`` objects for: required top-level keys present;
    counts dict matches actual entity-list lengths; basic ref-graph
    integrity (roles[*].node references exist in nodes[]).
    """
    from ..validate import Check, Severity
    out: List[Check] = []

    if not isinstance(inventory, dict):
        out.append(Check("inventory_only", Severity.FAIL,
                         f"inventory is not a dict: {type(inventory).__name__}", ""))
        return out

    entities = inventory.get("entities") or {}
    counts = inventory.get("counts") or {}

    if not entities:
        out.append(Check("inventory_only", Severity.FAIL,
                         "inventory has no entities dict", ""))
        return out

    for kind in ("nodes", "teams", "roles", "users", "shared_folders", "records"):
        items = entities.get(kind)
        if items is None:
            out.append(Check(f"entities_present:{kind}", Severity.SKIP,
                             f"entities[{kind!r}] absent (older inventory schema)", ""))
            continue
        if not isinstance(items, list):
            out.append(Check(f"entities_shape:{kind}", Severity.FAIL,
                             f"entities[{kind!r}] is not a list: "
                             f"{type(items).__name__}", ""))
            continue
        out.append(Check(f"entities_present:{kind}", Severity.PASS,
                         f"{len(items)} {kind}", ""))

        if kind in counts:
            expected = counts[kind]
            if isinstance(expected, int) and expected != len(items):
                out.append(Check(f"counts_match:{kind}", Severity.FAIL,
                                 f"counts[{kind!r}]={expected} but "
                                 f"len(entities[{kind!r}])={len(items)}", ""))

    node_names = {
        n.get("name") for n in entities.get("nodes") or []
        if isinstance(n.get("name"), str)
    }
    dangling_role_nodes = [
        r.get("name") for r in entities.get("roles") or []
        if r.get("node") and r.get("node") not in node_names
    ]
    if dangling_role_nodes:
        out.append(Check("ref_graph:roles_node", Severity.WARN,
                         f"{len(dangling_role_nodes)} role(s) reference a "
                         "node not in entities.nodes "
                         f"(first: {dangling_role_nodes[0]!r})", ""))
    else:
        out.append(Check("ref_graph:roles_node", Severity.PASS,
                         "every role's node ref resolves", ""))

    return out


# ─── Enterprise state ──────────────────────────────────────────────────


@dataclass(frozen=True)
class EnterpriseState:
    """Typed view of the source-tenant enterprise structure.

    Mirrors what cmd's ``structure.py`` would port to a target tenant —
    nodes / teams / roles / role-team memberships / role-user
    memberships. DSK ``models_enterprise`` consumers can build a
    Pydantic manifest from these lists without re-deriving from raw
    inventory JSON.
    """

    nodes: List[Dict[str, Any]]
    teams: List[Dict[str, Any]]
    roles: List[Dict[str, Any]]
    role_team_memberships: List[Dict[str, Any]]  # [{role: ..., team: ...}]
    role_user_memberships: List[Dict[str, Any]]  # [{role: ..., user_email: ...}]


def get_enterprise_state(run_dir: Path | str) -> EnterpriseState:
    """Return the typed enterprise state from a run-dir's
    ``inventory.json``.

    Memberships are derived from each role's ``teams`` and ``users``
    lists (heterogeneous shapes per `structure.py:770-775` are
    normalized to plain strings here).
    """
    artifacts = discover_run_dir(run_dir)
    inv = _read_json_safe(artifacts.inventory_json)
    entities = inv.get("entities") or {}
    role_team: List[Dict[str, Any]] = []
    role_user: List[Dict[str, Any]] = []
    for role in entities.get("roles") or []:
        rname = role.get("name")
        for entry in role.get("teams") or []:
            tname = (
                entry.get("team_name") or entry.get("name")
                if isinstance(entry, dict)
                else entry
            )
            if rname and tname:
                role_team.append({"role": rname, "team": tname})
        for entry in role.get("users") or []:
            uemail = (
                entry.get("email") or entry.get("user_email")
                if isinstance(entry, dict)
                else entry
            )
            if rname and uemail:
                role_user.append({"role": rname, "user_email": uemail})
    return EnterpriseState(
        nodes=list(entities.get("nodes") or []),
        teams=list(entities.get("teams") or []),
        roles=list(entities.get("roles") or []),
        role_team_memberships=role_team,
        role_user_memberships=role_user,
    )


# ─── Vault sharing state ───────────────────────────────────────────────


@dataclass(frozen=True)
class VaultSharingState:
    """Typed view of shared-folder + record-sharing state.

    DSK ``models_vault_sharing`` consumers build a sharing manifest from
    these lists. Doesn't include actual record contents — only the
    sharing graph (who has access to which SF / record).
    """

    shared_folders: List[Dict[str, Any]]
    sf_user_memberships: List[Dict[str, Any]]
    sf_team_memberships: List[Dict[str, Any]]
    record_direct_shares: List[Dict[str, Any]]


def get_vault_sharing_state(run_dir: Path | str) -> VaultSharingState:
    """Return the typed vault-sharing state from
    ``inventory.json``.

    Builds:
      * SF list (with default flags + record refs)
      * SF.users[*].username flattened as ``[{sf_uid, user_email, ...}]``
      * SF.teams[*] flattened (heterogeneous shape normalized)
      * record-level direct shares (``records[*].direct_shares[*]``)
    """
    artifacts = discover_run_dir(run_dir)
    inv = _read_json_safe(artifacts.inventory_json)
    entities = inv.get("entities") or {}
    sfs = entities.get("shared_folders") or []
    sf_users: List[Dict[str, Any]] = []
    sf_teams: List[Dict[str, Any]] = []
    for sf in sfs:
        uid = sf.get("uid")
        for user in sf.get("users") or []:
            if isinstance(user, dict) and user.get("username"):
                sf_users.append({"sf_uid": uid, **user})
        for team in sf.get("teams") or []:
            if isinstance(team, dict):
                tname = team.get("team_name") or team.get("name")
                if tname:
                    sf_teams.append({"sf_uid": uid, "team_name": tname,
                                     **{k: v for k, v in team.items()
                                        if k not in ("team_name", "name")}})
            elif isinstance(team, str) and team:
                sf_teams.append({"sf_uid": uid, "team_name": team})
    direct: List[Dict[str, Any]] = []
    for rec in entities.get("records") or []:
        ruid = rec.get("uid")
        for s in rec.get("direct_shares") or []:
            if isinstance(s, dict) and s.get("username"):
                direct.append({"record_uid": ruid, **s})
    return VaultSharingState(
        shared_folders=list(sfs),
        sf_user_memberships=sf_users,
        sf_team_memberships=sf_teams,
        record_direct_shares=direct,
    )


# ─── Compliance evidence export ────────────────────────────────────────


def get_compliance_evidence(
    run_dir: Path | str,
    *,
    fmt: str = "cef",
    output_path: Path | str | None = None,
    hostname: str = "",
) -> Path:
    """Export cmd's audit chain as compliance evidence.

    Wraps ``audit_export.export``. Reads ``audit.log`` from the run-dir,
    formats events as CEF / json-lines / syslog, writes to
    ``output_path`` (0600 perms) — defaults to
    ``<run_dir>/compliance-evidence.<fmt>`` when ``output_path`` is
    None.

    Parameters
    ----------
    run_dir
        keeperCMD run-dir containing ``audit.log``.
    fmt
        One of ``cef`` (ArcSight CEF), ``json-lines``, ``syslog``.
    output_path
        Destination file. Defaults to a sibling of ``audit.log``.
    hostname
        For ``syslog`` format only; ignored otherwise.

    Returns
    -------
    Path
        The output file's resolved path.
    """
    from .. import audit_export as _audit_export
    artifacts = discover_run_dir(run_dir)
    if output_path is None:
        ext = {"cef": "cef", "json-lines": "ndjson",
               "syslog": "syslog"}.get(fmt, "txt")
        output_path = artifacts.run_dir / f"compliance-evidence.{ext}"
    out = Path(output_path)
    _audit_export.export(
        log_path=str(artifacts.audit_log),
        output_path=str(out),
        fmt=fmt,
        hostname=hostname,
    )
    return out


# ─── Static health checks ───────────────────────────────────────────────


@dataclass(frozen=True)
class HealthCheck:
    """One result from `run_static_health_checks`.

    `status` is one of `"PASS"`, `"SKIP"`, `"FAIL"`.
    """

    name: str
    status: str
    detail: str


_STATIC_CHECK_NAMES = ("commander_imports", "parser_dests")


def run_static_health_checks() -> List[HealthCheck]:
    """Run cmd's params-independent invariants.

    Subset of ``selftest.run`` — only the checks that don't require a
    live Commander session. DSK ``dsk doctor`` can embed these to
    verify cmd is installed, importable, and has the expected argparse
    shape — without needing a live tenant login.

    Returns
    -------
    list[HealthCheck]
        One entry per static check (currently 2: commander_imports +
        parser_dests). Status is PASS/SKIP/FAIL.
    """
    from .. import selftest as _selftest
    results: List[HealthCheck] = []
    name_to_fn = dict(_selftest.CHECKS)
    for name in _STATIC_CHECK_NAMES:
        fn = name_to_fn.get(name)
        if fn is None:
            results.append(HealthCheck(name, "SKIP",
                                       f"check {name!r} not present in this cmd version"))
            continue
        try:
            # Static checks don't read params; pass None.
            check = fn(None)
        except Exception as e:  # noqa: BLE001
            results.append(HealthCheck(name, "FAIL", f"uncaught: {e!r}"))
            continue
        results.append(HealthCheck(check.name, check.status, check.detail))
    return results


# ─── MSP / MC context ──────────────────────────────────────────────────


@dataclass(frozen=True)
class MspState:
    """Typed view of MSP / Managed-Company structure from a run-dir.

    cmd's lane on the MSP front. DSK ``models_msp`` consumers can build
    a manifest from this without re-deriving from inventory JSON.

    Fields
    ------
    is_msp_run
        ``True`` when the run-dir's source tenant is itself an MSP
        (vs. an enterprise being migrated INTO an MSP-owned MC). Derived
        from ``inventory.tenant_type`` / ``inventory.is_msp`` markers cmd
        emits when the source has MSP signals.
    source_msp_name
        Name of the MSP tenant cmd inventoried (when ``is_msp_run``
        True), else empty string.
    target_mc_uid
        Target MC UID if the run-dir was produced by ``auto-migrate
        --target-config <...> --mc <UID>``; else empty string.
    managed_companies
        List of ``{uid, name, node_count, user_count}`` dicts for any
        MCs the inventory captured. Empty when source isn't an MSP.
    """

    is_msp_run: bool
    source_msp_name: str
    target_mc_uid: str
    managed_companies: List[Dict[str, Any]] = field(default_factory=list)


def get_msp_context_state(run_dir: Path | str) -> MspState:
    """Return the typed MSP / MC structure from a run-dir's
    ``inventory.json`` + ``migration.yaml``.

    cmd has the MSP/MC handling logic in ``mc_context.py`` + ``--mc``
    flag set on most subcommands. This hook surfaces just the STATE
    that's persisted in the run-dir; live-session MC switching is a
    Commander-runtime concern, not a run-dir concern.
    """
    artifacts = discover_run_dir(run_dir)
    inv = _read_json_safe(artifacts.inventory_json)

    # MSP signal: inventory.tenant_type, inventory.is_msp, or the
    # presence of a managed_companies entity list. cmd's auto-migrate
    # captures these into the run-dir; older inventories may lack them.
    tenant_type = (inv.get("tenant_type") or "").lower()
    is_msp_run = bool(
        inv.get("is_msp")
        or tenant_type in {"msp", "managed_service_provider"}
        or (inv.get("entities") or {}).get("managed_companies")
    )
    source_msp_name = (
        inv.get("msp_name")
        or inv.get("tenant_name")
        or ""
    ) if is_msp_run else ""

    target_mc_uid = ""
    spec_path = artifacts.run_dir / "migration.yaml"
    if spec_path.is_file():
        try:
            with _safe_open(spec_path) as f:
                import yaml as _yaml  # late import (PyYAML is optional)
                spec = _yaml.safe_load(f.read()) or {}
                target_mc_uid = (
                    (spec.get("target") or {}).get("mc_uid")
                    or (spec.get("target") or {}).get("mc")
                    or ""
                )
        except Exception:  # PyYAML missing or spec malformed
            target_mc_uid = ""

    mcs: List[Dict[str, Any]] = []
    for mc in (inv.get("entities") or {}).get("managed_companies") or []:
        mcs.append({
            "uid": mc.get("uid") or mc.get("mc_uid"),
            "name": mc.get("name") or mc.get("mc_name") or "",
            "node_count": mc.get("node_count", 0),
            "user_count": mc.get("user_count", 0),
        })

    return MspState(
        is_msp_run=is_msp_run,
        source_msp_name=str(source_msp_name).strip(),
        target_mc_uid=str(target_mc_uid).strip(),
        managed_companies=mcs,
    )


# ─── SIEM streaming (I18 deeper) ─────────────────────────────────────────────


def stream_compliance_evidence_for_siem(
    run_dir: Path | str,
    *,
    fmt: str = "cef",
    hostname: str = "",
) -> Iterator[str]:
    """[I18-streaming] Yield compliance-evidence events one at a time
    in the requested format.

    Generator variant of :func:`get_compliance_evidence` for live-
    streaming to SIEM platforms (Chronicle, Splunk, etc.). Use when you
    don't want to materialize a single output file — yield-and-forward
    integrations match SIEM ingestion patterns better than
    write-then-read.

    Parameters
    ----------
    run_dir
        keeperCMD run-dir containing ``audit.log``.
    fmt
        One of ``"cef"`` (ArcSight CEF), ``"json-lines"`` (NDJSON),
        ``"syslog"`` (RFC 5424).
    hostname
        For ``"syslog"`` format only.

    Yields
    ------
    str
        One formatted event per audit-log entry; caller controls
        delivery (HTTP POST / Kafka produce / Splunk HEC / etc.).
    """
    from .. import audit_export as _audit_export
    artifacts = discover_run_dir(run_dir)
    events = _audit_export.read_audit_events(str(artifacts.audit_log))
    if fmt == "json-lines":
        yield from _audit_export.to_jsonlines(events)
    elif fmt == "syslog":
        yield from _audit_export.to_syslog(events, hostname=hostname)
    elif fmt == "cef":
        yield from _audit_export.to_cef(events)
    else:
        raise ValueError(
            f"fmt must be one of 'cef' | 'json-lines' | 'syslog'; got {fmt!r}"
        )


# ─── Keeper-product dependency map ─────────────────────────────────────


@dataclass(frozen=True)
class ProductDependencyMap:
    """Which Keeper products a run-dir's data REQUIRES.

    Useful for absorption-PR reviewers + DSK consumers planning
    transitions (when DSK drops a domain, consumers using that domain
    look up which Keeper product the data should flow to instead).

    Each list contains string identifiers — high-level Keeper-product
    names rather than DSK domain file names. Conservative: only entries
    we're confident about based on data Bob can verify cmd-side.
    """

    requires_pam: bool  # any pamConfig / pamMachine / pamUser records
    requires_msp: bool  # MSP-tenant signal
    requires_enterprise: bool  # nodes/teams/roles present (always true for non-trivial runs)
    requires_shared_folders: bool
    requires_records: bool
    notes: List[str] = field(default_factory=list)


_PAM_RECORD_TYPES = frozenset({
    "pamConfig", "pamDatabase", "pamDirectory",
    "pamMachine", "pamRemoteBrowser", "pamSshKey", "pamUser",
})


def list_keeper_product_dependencies(
    run_dir: Path | str,
) -> ProductDependencyMap:
    """Inspect a run-dir's inventory + records to identify which
    Keeper products its data REQUIRES.

    Conservative scan — only emits flags Bob can verify cmd-side. The
    output is the cmd-side answer to "what Keeper products does my
    migration touch?"; useful when DSK drops a domain and consumers
    need to know whether their data uses the replacement product.

    Examples of what this DOES detect (and emits flags for):
        - PAM record types in the records list → ``requires_pam=True``
        - MSP tenant signal in inventory → ``requires_msp=True``
        - Non-empty enterprise structure → ``requires_enterprise=True``

    What this does NOT detect (out of cmd's lane):
        - Whether the run uses Keeper Terraform Provider, K8s ESO, MCP,
          KEPM, CSPM, SIEM, SCIM — cmd has no data on these
        - Whether AI policies / agents / tokens are referenced
        - Whether the customer uses any Keeper integration adapter
    """
    artifacts = discover_run_dir(run_dir)
    inv = _read_json_safe(artifacts.inventory_json)
    entities = inv.get("entities") or {}
    notes: List[str] = []

    record_types_present: set = set()
    for rec in entities.get("records") or []:
        rt = rec.get("record_type") or rec.get("type")
        if isinstance(rt, str) and rt:
            record_types_present.add(rt)

    requires_pam = bool(record_types_present & _PAM_RECORD_TYPES)
    if requires_pam:
        pam_count = sum(1 for r in entities.get("records") or []
                        if (r.get("record_type") or r.get("type")) in _PAM_RECORD_TYPES)
        notes.append(
            f"{pam_count} PAM record(s) present "
            "(types: " + ", ".join(sorted(record_types_present & _PAM_RECORD_TYPES)) + ")"
        )

    msp_state = get_msp_context_state(run_dir)
    if msp_state.is_msp_run:
        notes.append(
            f"MSP tenant signal in inventory ({msp_state.source_msp_name!r})"
        )

    nodes = entities.get("nodes") or []
    teams = entities.get("teams") or []
    roles = entities.get("roles") or []
    requires_enterprise = bool(nodes or teams or roles)

    sfs = entities.get("shared_folders") or []
    requires_shared_folders = bool(sfs)

    records = entities.get("records") or []
    requires_records = bool(records)

    return ProductDependencyMap(
        requires_pam=requires_pam,
        requires_msp=msp_state.is_msp_run,
        requires_enterprise=requires_enterprise,
        requires_shared_folders=requires_shared_folders,
        requires_records=requires_records,
        notes=notes,
    )


# ─── MC scoping ─────────────────────────────────────────────────────────
# I8 is a flag-passthrough on the DSK shim side; cmd's mc_context.py
# already handles the live-session switching. No glue needed in this
# module — DSK calls cmd's existing flag set.


# ─── Decommission orchestration ─────────────────────────────────────────
# I6 is a DSK-side orchestration concern (manifest TTLs trigger cmd's
# decommission verb). cmd already exposes the verb via console-script
# `keeper-migrate tenant-migrate decommission --plan-only --max-age-hours N`.
# A future hook here would expose `decommission.process_users()` for
# in-process invocation; deferred until DSK signals readiness.


# ─── Module metadata ─────────────────────────────────────────────────────────


__all__ = [
    "UnsafeArtifactError",
    "RunDirArtifacts",
    "IntegrityReport",
    "EnterpriseState",
    "VaultSharingState",
    "HealthCheck",
    "MspState",
    "ProductDependencyMap",
    "discover_run_dir",
    "verify_run_dir_integrity",
    "get_audit_chain_tail",
    "get_users_transition_table",
    "get_transition_baseline",
    "validate_run_dir_for_adopt",
    "get_enterprise_state",
    "get_vault_sharing_state",
    "get_compliance_evidence",
    "run_static_health_checks",
    "get_msp_context_state",
    "stream_compliance_evidence_for_siem",
    "list_keeper_product_dependencies",
]
