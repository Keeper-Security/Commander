#!/usr/bin/env python3
"""
esxi_pam_import.py — Phase 6 Stage 3 — direct ESXi → Keeper PAM import.

Reads a discovery state file produced by `onboard_esxi.py discover` and
creates Keeper PAM records (pamMachine + pamUser + optional pamRemoteBrowser)
**without** going through KCM. Closes audit Gap A from
`.context/findings/d10-esxi-import-coverage.md` row 4 — operators who don't
run a KCM Docker stack now have a complete pipeline.

Mirrors `keeper pam project kcm-import`'s option surface where it makes sense
(--name / --config / --groups / --exclude-groups / --list-groups / --dry-run
/ --output / --yes / --auto-throttle / --write-chunk-size / --target).

PREREQUISITE: a fresh `keeper login` session in the same shell. Same auth
contract as the Phase 5 building-block scripts (see `_keeper_session.py`).

SECURITY: the `keeper record-add` subprocess pattern from
`bootstrap_vault_records.py` is reused. Audit-tag stamping (`phase6:<--target>`
prefix in the `notes` field) gates `--rollback`, which removes only records
this run created.

LIVE-VERIFY STATUS (Phase 6 Stage 3g): the typed-field shape for
pamMachine/pamUser/pamRemoteBrowser via `keeper record-add -rt <type>` is
based on Commander RC 18 schemas + bootstrap_vault_records' precedent for
`-rt login`, but has not been verified live as of this commit (the live
ec2-se environment was not reachable during Phase 6 execution). See
`.context/topics/esxi-pam-import-shape.md` § "Known unknowns the live verify
must close" for the specific shapes that need confirmation. If 3g surfaces
a record-add limitation, the planner shape is decoupled from the writer —
swap the writer to Commander's `update_record` Python-API (path used by
`kcm_pam_post_link.py`) and tests stay green.

Usage:
    # Dry-run (default) — show what would be created
    uv run python scripts/esxi_pam_import.py \\
        --state ~/.cache/onboard-esxi/<host>.state.json

    # Actually create records (creates a NEW pamConfig named X)
    uv run python scripts/esxi_pam_import.py \\
        --state ~/.cache/onboard-esxi/<host>.state.json \\
        --name "ESXi-Phase6-PAM" --execute --target demolab:ec2-se

    # Extend an existing pamConfig
    uv run python scripts/esxi_pam_import.py \\
        --state ~/.cache/onboard-esxi/<host>.state.json \\
        --config "ESXi-Phase6-PAM" --execute

    # Inspect the plan as JSON
    uv run python scripts/esxi_pam_import.py \\
        --state ~/.cache/onboard-esxi/<host>.state.json \\
        --json --output /tmp/plan.json

    # Rollback (uses the state file's execution log)
    uv run python scripts/esxi_pam_import.py \\
        --state ~/.cache/onboard-esxi/<host>.state.json \\
        --rollback
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import logging
import os
import random
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("esxi-pam-import")

KEEPER_BIN = os.environ.get("KEEPER_BIN", "keeper")

# System ESXi accounts excluded from pamUser emission unless operator opts in.
_SYSTEM_USERS = ("dcui", "vpxuser")

# Phase 8.12: ESXi accounts excluded from share-emission targets by
# default. dcui + vpxuser are ESXi system accounts with no human
# Keeper user counterpart; sharing to "dcui@<domain>" would always
# fail at the API. `root` is the ESXi superuser; the operator usually
# IS root in vault terms, and self-sharing is either a no-op or
# refused by Keeper. Mirrors `feedback_dont_rotate_esxi_root.md`'s
# rotation-side DENY_TARGETS philosophy: operator can opt back in
# via `--share-include-system-users` for tenants that DO have human
# accounts named root/dcui/vpxuser (rare).
_SHARE_DENY_PRINCIPALS = frozenset(("dcui", "vpxuser", "root"))

# Audit-tag pattern: 1-64 alphanumerics + dot/underscore/dash/slash/colon.
_TARGET_TAG_RE = re.compile(r"^[a-zA-Z0-9][\w./:-]{0,63}$")

# DoS guard for state-file reads — parity with onboard_esxi._load_state's cap.
_MAX_STATE_FILE_BYTES = 16 * 1024 * 1024

# Per-record subprocess timeout for `keeper record-add` / `keeper rm`. Bumped
# from the original 30s after Phase 6.5 live verifies repeatedly hit the
# limit on a single record per run (kvmcrk demo tenant + ~13 records). 60s
# absorbs the observed slow path; tunable via env var for ops with even
# slower tenants.
_PER_RECORD_TIMEOUT_SECS = int(os.environ.get("ESXI_PAM_IMPORT_TIMEOUT", "60"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _validate_uid(label: str, value: str) -> str:
    """Phase 8.14d: argparse type for Keeper-style UIDs (22-char url-safe
    base64). Raises argparse.ArgumentTypeError on bad input so the operator
    sees a clean message rather than a downstream API error mid-batch."""
    if not (20 <= len(value) <= 25) or not re.match(r"^[A-Za-z0-9_-]+$", value):
        raise argparse.ArgumentTypeError(
            f"--{label} {value!r} doesn't look like a Keeper UID "
            f"(expected url-safe base64, length 20-25; got {len(value)} chars)"
        )
    return value


def _resolve_share_mode_from_folder_from(folder_from: str, share_mode: str) -> str:
    """Phase 8.19.6: --folder-from is the new operator-facing flag.
    'user' is an alias for --share-mode folder. 'role' is reserved
    for a future shared-folder-API phase and raises NotImplementedError
    with concrete next-step guidance for operators who need it today.
    'none' (default) leaves --share-mode untouched."""
    if folder_from == "none":
        return share_mode
    if folder_from == "user":
        return "folder"
    if folder_from == "role":
        raise NotImplementedError(
            "--folder-from role requires shared-folder API integration "
            "(per-role shared folders + member assignment from ESXi "
            "permissions). Deferred to a future phase. Operator manual "
            "workaround: run with --folder-from user (per-user personal "
            "folders) and create role-named shared folders manually in "
            "Web Vault, then move records as needed. Track progress in "
            "TODOs."
        )
    raise RuntimeError(f"invalid folder_from {folder_from!r}")


def parse_vm_record_type(spec: Optional[str]) -> Dict[str, str]:
    """Phase 8.19.4: parse `--vm-record-type vmname=pamDatabase,vm2=pamDirectory`
    into {vm_name: record_type}. Empty/None → empty dict. Same syntax
    family as --user-map. Validates record_type strings later in
    build_plan against the allowed set."""
    if not spec:
        return {}
    out: Dict[str, str] = {}
    for raw in spec.split(","):
        entry = raw.strip()
        if not entry:
            continue
        if "=" not in entry:
            raise RuntimeError(
                f"--vm-record-type entry {entry!r} has no '=' separator; "
                "expected '<vm-name>=<pamMachine|pamDatabase|pamDirectory|pamRemoteBrowser>'"
            )
        key, _, val = entry.partition("=")
        key = key.strip()
        val = val.strip()
        if not key or not val:
            raise RuntimeError(
                f"--vm-record-type entry {entry!r} has empty vm-name or record-type"
            )
        out[key] = val
    return out


def parse_user_map(spec: Optional[str]) -> Dict[str, str]:
    """Phase 8.9: parse `--user-map alice=alice@x.com,bob=bob@y.com`
    into {esxi_principal: keeper_email}. Empty/None → empty dict.

    Whitespace around '=' and ',' is tolerated; empty entries are
    silently skipped. Raises RuntimeError on malformed entries so the
    operator catches typos before the run starts."""
    if not spec:
        return {}
    out: Dict[str, str] = {}
    for raw in spec.split(","):
        entry = raw.strip()
        if not entry:
            continue
        if "=" not in entry:
            raise RuntimeError(
                f"--user-map entry {entry!r} has no '=' separator; "
                "expected '<esxi-principal>=<keeper-email>'"
            )
        key, _, val = entry.partition("=")
        key = key.strip()
        val = val.strip()
        if not key or not val:
            raise RuntimeError(
                f"--user-map entry {entry!r} has empty principal or email"
            )
        out[key] = val
    return out


def resolve_keeper_identity(
    esxi_principal: str,
    user_map: Dict[str, str],
    user_domain: Optional[str],
) -> Optional[str]:
    """Phase 8.9: ESXi principal → Keeper email, or None if no rule applies.

    Resolution order: explicit map first (operator's source of truth),
    then `<principal>@<user-domain>` if a domain is configured. If
    neither matches, return None — the caller decides whether that's
    skip/fail/invite per --missing-users.

    Group principals (when discovery sets `is_group=True`) currently
    get the same treatment as users — the operator can map a group
    name to a Keeper team email or skip via --user-map omission. A
    future revision may grow group-specific resolution."""
    if esxi_principal in user_map:
        return user_map[esxi_principal]
    if user_domain:
        # Strip any leading "domain\\" or "@..." artefact some pyvmomi
        # principal forms carry (e.g. "ESXi\\alice"). Keep the local
        # part only.
        local = esxi_principal
        if "\\" in local:
            local = local.rsplit("\\", 1)[-1]
        if "@" in local:
            local = local.split("@", 1)[0]
        return f"{local}@{user_domain}"
    return None


# Phase 8.19.5: ESXi role hierarchy for --minimum-role filtering.
# Keys are the canonical lower-case role names ESXi uses; values are
# the threshold rank (higher = more privileged). A user with a role
# at rank >= the threshold passes the filter. Custom roles default to
# rank=1 (treated as "vm-user" tier) so they're not silently dropped.
_ESXI_ROLE_RANK = {
    "admin": 3, "administrator": 3,
    "virtualmachineuser": 1, "virtualmachinepoweruser": 1, "vm-user": 1,
    "readonly": 0, "noaccess": 0, "no-access": 0,
}
_ROLE_THRESHOLD_FOR_FLAG = {
    "admin": 3,
    "vm-user": 1,
    "readonly": 0,
}


def _role_rank(role: str) -> int:
    """Phase 8.19.5: map an ESXi role name to a numeric rank for
    --minimum-role filtering. Unknown / custom roles → 1 (vm-user
    tier) by default — operator can use --share-include-system-users
    or explicit --user-map to refine."""
    return _ESXI_ROLE_RANK.get((role or "").strip().lower().replace(" ", ""), 1)


def vm_access_map(
    permissions: List[Dict[str, Any]],
    exclude_principals: Optional[set] = None,
    minimum_role: str = "vm-user",
) -> Dict[str, List[Tuple[str, str]]]:
    """Phase 8.9: derive {vm_name: [(principal, role), ...]} from the
    flat permissions list emitted by discover_permissions(). Only VM
    entities are considered; host/datastore/network grants are out of
    scope for VM sharing.

    Phase 8.12: `exclude_principals` filters out ESXi system accounts
    that have no human Keeper user counterpart. Defaults to
    `_SHARE_DENY_PRINCIPALS` (dcui, vpxuser, root) — matches the
    rotation-side DENY_TARGETS philosophy. Pass an empty set to
    include all principals (--share-include-system-users CLI flag).

    Sorts each VM's principal list deterministically so plan output is
    stable across runs."""
    if exclude_principals is None:
        exclude_principals = _SHARE_DENY_PRINCIPALS
    threshold = _ROLE_THRESHOLD_FOR_FLAG.get(minimum_role, 1)
    out: Dict[str, List[Tuple[str, str]]] = {}
    for perm in permissions or []:
        if perm.get("entity_type") != "VirtualMachine":
            continue
        vm_name = perm.get("entity_name") or ""
        if not vm_name:
            # entity_moid present but VM not in this discovery snapshot
            # (e.g., recently deleted) — skip rather than emit a record
            # for a phantom resource.
            continue
        principal = perm.get("principal") or ""
        if not principal or principal in exclude_principals:
            continue
        role = perm.get("role") or ""
        # Phase 8.19.5: apply --minimum-role filter. ReadOnly users
        # would see records but couldn't actually launch into them;
        # default threshold (vm-user) excludes them.
        if _role_rank(role) < threshold:
            continue
        out.setdefault(vm_name, []).append((principal, role))
    for vm in out:
        out[vm] = sorted(set(out[vm]))
    return out


_SENSITIVE_ROW_KEYS_FOR_PERSIST = frozenset({
    # Phase 8.24 S3: principal→email + post-create custom field values
    # (Full Name, ESXi Role, Access Mode, Shell Access) reconstruct
    # the org's ESXi RBAC map cross-referenced to Keeper identities.
    # Not needed for --rollback (which only reads row["uid"]).
    "share_user_map",
    "post_create_custom_fields",
})


def _strip_sensitive_from_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Phase 8.24 S3: return a copy of plan with sensitive per-row keys
    removed. rows[] entries are shallow-copied; other keys untouched."""
    if not isinstance(plan, dict):
        return plan
    out = dict(plan)
    rows = plan.get("rows") or []
    out["rows"] = [
        {k: v for k, v in r.items() if k not in _SENSITIVE_ROW_KEYS_FOR_PERSIST}
        for r in rows
    ]
    return out


def _strip_sensitive_from_execution(execution: Dict[str, Any]) -> Dict[str, Any]:
    """Phase 8.24 S3: mirror for the execution log."""
    if not isinstance(execution, dict):
        return execution
    out = dict(execution)
    rows = execution.get("rows") or []
    out["rows"] = [
        {k: v for k, v in r.items() if k not in _SENSITIVE_ROW_KEYS_FOR_PERSIST}
        for r in rows
    ]
    return out


def _atomic_write_state(path: str, state: Dict[str, Any]) -> None:
    """Atomic state-file write — temp + rename, mode 0o600.

    Mirrors `onboard_esxi._save_state`. Phase 6 red-team review M1+M2:
    a crash mid-write must not corrupt the state file that holds the
    only record of created UIDs (used by --rollback).
    """
    import tempfile

    dirname = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=dirname, prefix=os.path.basename(path) + ".", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(state, fp, indent=2, sort_keys=True)
            fp.write("\n")
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _validate_target(value: str) -> str:
    if not _TARGET_TAG_RE.match(value):
        raise argparse.ArgumentTypeError(
            f"invalid --target tag {value!r}: must match {_TARGET_TAG_RE.pattern} "
            f"(e.g. 'demolab:ec2-se', 'keeper:internal')"
        )
    return value


def load_state(path: str) -> Dict[str, Any]:
    """Load a state file written by `onboard_esxi.py discover`. Validates
    the discovery section is present; raises RuntimeError otherwise."""
    if not os.path.isfile(path):
        raise RuntimeError(f"state file not found: {path}")
    size = os.stat(path).st_size
    if size > _MAX_STATE_FILE_BYTES:
        raise RuntimeError(
            f"state file {path} is {size} bytes, refusing to load (cap {_MAX_STATE_FILE_BYTES})."
        )
    with open(path, "r", encoding="utf-8") as fp:
        state = json.load(fp)
    if not state.get("discovery"):
        raise RuntimeError(
            f"state file {path} has no discovery section; run `onboard_esxi.py discover` first."
        )
    return state


def _eligible_users(host_info: Dict[str, Any], include_root: bool) -> List[str]:
    """Return non-system ESXi user IDs (login names) eligible for pamUser
    emission. Always skips dcui / vpxuser. Root is skipped unless explicitly
    opted in (--include-root) — operators rarely want to rotate root."""
    users = host_info.get("users") or []
    out: List[str] = []
    for u in users:
        login = u.get("id") or u.get("login") or u.get("username")
        if not login:
            continue
        if login in _SYSTEM_USERS:
            continue
        if login == "root" and not include_root:
            continue
        out.append(login)
    return sorted(set(out))


# Phase 8.19.1: adopt upstream protocol tables instead of redefining
# locally. Avoids drift when upstream adds protocols (e.g. new DB
# engines). Memory: feedback_audit_upstream_first.md.
try:
    from keepercommander.commands.pam_import.kcm_import import (
        PROTOCOL_DEFAULT_PORTS as _UPSTREAM_PROTOCOL_DEFAULT_PORTS,
    )
    from keepercommander.commands.pam_import.kcm_import import (  # type: ignore
        PROTOCOL_TYPE_MAP as _UPSTREAM_PROTOCOL_TYPE_MAP,
    )
except ImportError:  # pragma: no cover — keepercommander always present in venv
    _UPSTREAM_PROTOCOL_TYPE_MAP = {
        "http": "pamRemoteBrowser",
        "mysql": "pamDatabase",
        "postgres": "pamDatabase",
        "sql-server": "pamDatabase",
    }
    _UPSTREAM_PROTOCOL_DEFAULT_PORTS = {
        "ssh": "22", "rdp": "3389", "vnc": "5900", "telnet": "23",
        "mysql": "3306", "postgresql": "5432", "sql-server": "1433",
        "kubernetes": "443",
    }

# Public alias retained for back-compat with phase 8.14 callers.
# Source-of-truth is the upstream import above.
_PROTOCOL_DEFAULT_PORT = _UPSTREAM_PROTOCOL_DEFAULT_PORTS

# Routing rule: upstream maps select special types; everything else
# (ssh/rdp/vnc/telnet/kubernetes/...) → pamMachine.
def _record_type_for_protocol(protocol: str) -> str:
    """Phase 8.19.4: route a discovered/declared protocol to a PAM
    record_type. Mirrors `kcm_import.PROTOCOL_TYPE_MAP.get(protocol,
    'pamMachine')`. http→pamRemoteBrowser, mysql/postgres/sql-server
    → pamDatabase, default → pamMachine."""
    return _UPSTREAM_PROTOCOL_TYPE_MAP.get((protocol or "").lower(), "pamMachine")


_GUEST_PROTOCOL_MAP = {
    # Mirrors esxi_kcm_sync._get_protocols_for_guest — substring match
    # against `vm.guest_id + " " + vm.guest_full_name` lower-cased. The
    # FIRST matching key wins (so order matters: more-specific before
    # generic). Each value is the connection.protocol per Keeper PAM's
    # ConnectionProtocol enum (ssh / rdp / vnc — pamMachine-allowed
    # values; kubernetes / telnet are valid too but not auto-derivable).
    "windows": "rdp",
    "win": "rdp",
    "linux": "ssh",
    "ubuntu": "ssh",
    "debian": "ssh",
    "centos": "ssh",
    "rhel": "ssh",
    "fedora": "ssh",
    "suse": "ssh",
    "oracle": "ssh",
    "freebsd": "ssh",
}


def _derive_protocol_for_vm(vm: Dict[str, Any], default: str = "ssh") -> str:
    """Phase 8.14a: pick a connection.protocol for a VM pamMachine.

    Mirrors esxi_kcm_sync._get_protocols_for_guest's substring-match
    semantics but returns ONE protocol (pamMachine.connection.protocol
    is scalar). Returns `default` (ssh) when no match. Operator can
    override globally via the --vm-protocol-default CLI flag."""
    guest_blob = (
        (vm.get("guest_id") or "")
        + " "
        + (vm.get("guest_full_name") or "")
    ).lower()
    for key, proto in _GUEST_PROTOCOL_MAP.items():
        if key in guest_blob:
            return proto
    return default


def _eligible_vms(host_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return VM dicts eligible for pamMachine emission.

    Skips VMs without a name (corrupt discovery row). Powered-off VMs and
    VMs without an IP are KEPT — operators want them as addressable PAM
    records even when not currently running, with a placeholder hostname
    that flags the missing IP. Mirrors esxi_kcm_sync's _create_vm_connections
    which also keeps powered-off / no-IP VMs.

    Returned dicts are sorted by `name` for deterministic plan output."""
    vms = host_info.get("vms") or []
    out: List[Dict[str, Any]] = []
    for vm in vms:
        name = vm.get("name")
        if not name:
            continue
        out.append(vm)
    return sorted(out, key=lambda v: v.get("name", ""))


def _filter_groups(
    rows: List[Dict[str, Any]], include: Optional[List[str]], exclude: Optional[List[str]]
) -> List[Dict[str, Any]]:
    """Apply --groups / --exclude-groups wildcards against each row's `host`
    field (single-host scope per state file in Phase 6, but the wildcard
    matching API mirrors kcm-import for consistency)."""
    if not include and not exclude:
        return rows

    def match(host: str, patterns: List[str]) -> bool:
        for pat in patterns:
            pat = pat.strip()
            if not pat:
                continue
            # Glob → regex: only `*` is special.
            re_pat = "^" + re.escape(pat).replace(r"\*", ".*") + "$"
            if re.match(re_pat, host):
                return True
        return False

    out = []
    for row in rows:
        host = row.get("host", "")
        if include and not match(host, include):
            continue
        if exclude and match(host, exclude):
            continue
        out.append(row)
    return out


def build_plan(
    state: Dict[str, Any],
    *,
    rbi_mode: str = "from-state",
    include_root: bool = False,
    include_vms: bool = True,
    user_map: Optional[Dict[str, str]] = None,
    user_domain: Optional[str] = None,
    share_include_system_users: bool = False,
    vm_protocol_default: str = "ssh",
    target: Optional[str] = None,
    groups: Optional[List[str]] = None,
    exclude_groups: Optional[List[str]] = None,
    host_record_type: str = "pamMachine",
    vm_record_type_overrides: Optional[Dict[str, str]] = None,
    share_scope: str = "permissions",
    minimum_role: str = "vm-user",
    include_host_share: str = "by-permissions",
    vm_primary_user: str = "dominant-permission",
) -> Dict[str, Any]:
    """Build the import plan from a state file. rbi_mode='from-state' reads
    state['discovery']['options']['rbi'] (set by onboard_esxi.py discover);
    explicit values override.

    include_vms=True (Phase 8.8): emit one pamMachine per VM discovered on
    the host. Defaults ON because the project objective is "VMs as usable
    PAM records." Set False (CLI: `--skip-vms`) for the historical
    host-only behaviour.

    user_map / user_domain (Phase 8.9): when set, each VM row gets a
    `share_with` list of resolved Keeper emails, derived from
    host_info.permissions filtered to that VM. Empty list when no
    permission grants exist for the VM. The actual share_record calls
    happen in execute_plan; build_plan just plans them."""
    host_info = state["discovery"].get("esxi_host_info") or {}
    host = state.get("host") or host_info.get("hostname") or "unknown"
    version = host_info.get("version") or "unknown"
    discovered_at = state["discovery"].get("discovered_at") or "unknown"

    # Resolve RBI mode.
    if rbi_mode == "from-state":
        rbi_mode = (state["discovery"].get("options") or {}).get("rbi") or "none"
    if rbi_mode not in ("none", "per-host", "per-user"):
        raise RuntimeError(f"invalid rbi_mode {rbi_mode!r}")

    audit_note = (
        (f"phase6:{target} ; imported by esxi_pam_import.py @ {_now_iso()} (discovered_at={discovered_at})")
        if target
        else (f"imported by esxi_pam_import.py @ {_now_iso()} (discovered_at={discovered_at})")
    )

    if host_record_type not in ("pamMachine", "pamRemoteBrowser", "both"):
        raise RuntimeError(
            f"invalid host_record_type {host_record_type!r}; expected one of "
            "{'pamMachine', 'pamRemoteBrowser', 'both'}"
        )

    vm_record_type_overrides = dict(vm_record_type_overrides or {})
    _ALLOWED_VM_RT = {"pamMachine", "pamDatabase", "pamDirectory", "pamRemoteBrowser"}
    for vname, rt in vm_record_type_overrides.items():
        if rt not in _ALLOWED_VM_RT:
            raise RuntimeError(
                f"invalid --vm-record-type override for {vname!r}: {rt!r}; "
                f"must be one of {sorted(_ALLOWED_VM_RT)}"
            )
    if share_scope not in ("permissions", "all"):
        raise RuntimeError(
            f"invalid share_scope {share_scope!r}; expected 'permissions' or 'all'"
        )
    if minimum_role not in _ROLE_THRESHOLD_FOR_FLAG:
        raise RuntimeError(
            f"invalid minimum_role {minimum_role!r}; expected one of "
            f"{sorted(_ROLE_THRESHOLD_FOR_FLAG)}"
        )
    if include_host_share not in ("always", "by-permissions", "never"):
        raise RuntimeError(
            f"invalid include_host_share {include_host_share!r}; expected one of "
            "{'always', 'by-permissions', 'never'}"
        )
    if vm_primary_user not in ("dominant-permission", "broadcast", "none"):
        raise RuntimeError(
            f"invalid vm_primary_user {vm_primary_user!r}; expected one of "
            "{'dominant-permission', 'broadcast', 'none'}"
        )

    # Phase 8.20: warnings list mirrors kcm_import._build_import_report
    # pattern. Each entry is a human-readable string describing a
    # "configured what we could, here's what needs operator follow-up"
    # condition. Memory: reference_kcm_import_report_pattern.md.
    warnings: List[str] = []

    rows: List[Dict[str, Any]] = []

    # 1. pamMachine — exactly one per host.
    # Phase 8.7.3: include pamSettings (empty connection scaffold). The
    # `trafficEncryptionSeed` field is populated post-create via
    # update_record (Phase 8.17 — CLI rejects the field from argv).
    # Phase 8.19.2: emit protocol="ssh" + port=22 for the host so Web
    # Vault has a launchable target. Default per upstream
    # PROTOCOL_DEFAULT_PORTS["ssh"]; ESXi always exposes SSH (operator
    # may have it disabled, but the record is still launchable once
    # re-enabled). Operator override via --host-protocol planned for
    # 8.19.3 alongside pamRemoteBrowser host emission.
    host_protocol = "ssh"
    host_port = _PROTOCOL_DEFAULT_PORT.get(host_protocol, "22")
    pam_settings_val = "$JSON:" + json.dumps({
        "allowSupplyHost": False,
        "portForward": {"reusePort": True, "port": host_port},
        "connection": {
            "protocol": host_protocol,
            "port": host_port,
            "allowSupplyUser": True,
            "userRecords": [],  # filled in by Phase 8.16's two-pass splice
        },
    })
    # Phase 8.22: discrete labeled custom fields instead of notes blob.
    # Mirrors kcm-import's c.text.<label>= pattern (kcm_import.py:3196-
    # 3296). Each piece of metadata is its own field with a
    # human-readable label visible in Web Vault. Notes is reduced to a
    # short audit-trail footer.
    host_custom_fields: Dict[str, str] = {}
    if version and version != "unknown":
        host_custom_fields["ESXi Version"] = version
    if host_info.get("vendor") and host_info.get("model"):
        host_custom_fields["Hardware"] = f"{host_info['vendor']} {host_info['model']}"
    if host_info.get("service_tag"):
        host_custom_fields["Service Tag"] = str(host_info["service_tag"])
    if host_info.get("bios_version"):
        host_custom_fields["BIOS Version"] = str(host_info["bios_version"])
    if host_info.get("cpu_cores"):
        host_custom_fields["CPU"] = f"{host_info['cpu_cores']} cores"
    if host_info.get("memory_gb"):
        host_custom_fields["RAM"] = f"{host_info['memory_gb']} GB"
    if host_info.get("license_name"):
        host_custom_fields["License"] = str(host_info["license_name"])
    if host_info.get("ip_address") and host_info["ip_address"] != host:
        host_custom_fields["Management IP"] = str(host_info["ip_address"])
    host_notes = audit_note

    host_fields = {
        "pamHostname": "$JSON:" + json.dumps({"hostName": host, "port": host_port}),
        "pamSettings": pam_settings_val,
        "operatingSystem": f"VMware ESXi {version}" if version != "unknown" else "VMware ESXi",
        "instanceName": host,
        "providerGroup": "VMware ESXi",
        "notes": host_notes,
    }
    # Phase 8.22 + 8.24 S1: labeled custom fields moved OFF the CLI
    # argv (was `c.text.<label>=<value>` per field). Values such as
    # Service Tag, License key, Management IP were ps-visible
    # system-wide for ~70s per record. Post-create update_record path
    # bypasses argv entirely (same pattern as Phase 8.23.1 pamUser).
    # Phase 8.19.5: compute host-level share principals per
    # --include-host-share. 'always' shares with every (filtered) user
    # in the tenant; 'by-permissions' shares only with users who have
    # an ESXi role on the host entity itself; 'never' leaves the host
    # un-shared (operator owns it). Identity-bound records (pamUser,
    # per-user pamRemoteBrowser) are unaffected — they remain 1:1.
    # Compute share_excludes + access_map here (hoisted from below) so
    # the host emission can use them.
    user_map = user_map or {}
    share_excludes = set() if share_include_system_users else _SHARE_DENY_PRINCIPALS
    access_map = (
        vm_access_map(
            host_info.get("permissions") or [],
            exclude_principals=share_excludes,
            minimum_role=minimum_role,
        )
        if include_vms else {}
    )

    host_share_principals: List[str] = []
    if include_host_share != "never":
        threshold = _ROLE_THRESHOLD_FOR_FLAG[minimum_role]
        if include_host_share == "always":
            # Same set as universal share, even if scope=permissions.
            seen: set = set()
            for principals in access_map.values():
                for p, _r in principals:
                    if p not in seen:
                        seen.add(p)
                        host_share_principals.append(p)
            for perm in host_info.get("permissions") or []:
                principal = perm.get("principal") or ""
                if not principal or principal in share_excludes:
                    continue
                if _role_rank(perm.get("role") or "") < threshold:
                    continue
                if principal not in seen:
                    seen.add(principal)
                    host_share_principals.append(principal)
        else:  # by-permissions: only users with a role on the host entity
            for perm in host_info.get("permissions") or []:
                if perm.get("entity_type") not in ("HostSystem", "Folder"):
                    continue
                principal = perm.get("principal") or ""
                if not principal or principal in share_excludes:
                    continue
                if _role_rank(perm.get("role") or "") < threshold:
                    continue
                if principal not in host_share_principals:
                    host_share_principals.append(principal)

    host_share_user_map: Dict[str, str] = {}
    host_share_with: List[str] = []
    for principal in host_share_principals:
        resolved = resolve_keeper_identity(principal, user_map, user_domain)
        host_share_user_map[principal] = resolved or ""
        if resolved and resolved not in host_share_with:
            host_share_with.append(resolved)

    # Phase 8.23: compute host primary principal. Host has no
    # per-VM access_map entries — its perms come from
    # host_info.permissions filtered to HostSystem/Folder entities.
    # Apply the same dominant-permission/broadcast/none logic.
    host_perm_entries: List[Tuple[str, str]] = []
    for perm in host_info.get("permissions") or []:
        if perm.get("entity_type") not in ("HostSystem", "Folder"):
            continue
        principal = perm.get("principal") or ""
        if not principal or principal in share_excludes:
            continue
        role = perm.get("role") or ""
        if _role_rank(role) < _ROLE_THRESHOLD_FOR_FLAG[minimum_role]:
            continue
        host_perm_entries.append((principal, role))
    if vm_primary_user == "none":
        host_primary_principals: List[str] = []
    elif vm_primary_user == "broadcast":
        host_primary_principals = list(host_share_principals)
    else:  # dominant-permission
        if host_perm_entries:
            ranked = sorted(
                host_perm_entries,
                key=lambda x: (-_role_rank(x[1]), x[0]),
            )
            host_primary_principals = [ranked[0][0]]
        else:
            host_primary_principals = []

    if host_record_type in ("pamMachine", "both"):
        rows.append(
            {
                "type": "pamMachine",
                "title": host,
                "host": host,
                "fields": host_fields,
                # Phase 8.24 S1: labels go through post-create update_record
                # (no argv leak via `ps`).
                "post_create_custom_fields": dict(host_custom_fields),
                "share_principals": list(host_share_principals),
                "share_with": list(host_share_with),
                "share_user_map": dict(host_share_user_map),
                "primary_principals": host_primary_principals,
            }
        )

    # Phase 8.19.3: optionally emit a host-level pamRemoteBrowser for
    # WebUI access (no per-user credential binding — operator supplies
    # at session start). Distinct from the per-user RBIs that
    # rbi_mode='per-user' creates: those are credential-bound to a
    # specific pamUser; this is a generic shared WebUI launcher.
    if host_record_type in ("pamRemoteBrowser", "both"):
        host_rbi_settings = "$JSON:" + json.dumps({
            "connection": {
                "protocol": "http",
                "ignoreInitialSslCert": True,
                # No httpCredentialsUid — operator supplies creds.
            },
        })
        rows.append({
            "type": "pamRemoteBrowser",
            "title": f"{host} WebUI",
            "host": host,
            "fields": {
                "rbiUrl": f"https://{host}/",
                "pamRemoteBrowserSettings": host_rbi_settings,
                "notes": (
                    f"ESXi WebUI launcher; operator supplies credentials. "
                    f"{audit_note}"
                ),
            },
            # Phase 8.19.5: host RBI follows --include-host-share too.
            "share_principals": list(host_share_principals),
            "share_with": list(host_share_with),
            "share_user_map": dict(host_share_user_map),
        })

    # 1b. pamMachine per VM (Phase 8.8) — one per discovered guest, even if
    # powered off or without an IP. The project objective is "VMs as usable
    # PAM records, with all associations necessary, even if no password for
    # the connections" — so pamMachines for VMs are emitted with empty
    # pamSettings.connection (no protocol committed; operator picks at
    # connection time) and no admin credential link. Hostname is the VM's
    # IP when known, else a `<UPDATE-IP-FOR-{name}>` placeholder that
    # mirrors esxi_kcm_sync's no-IP fallback. Folder routing puts these
    # under `<project> - Resources` automatically (_TYPE_TO_FOLDER_KIND).
    #
    # Phase 8.9: derive per-VM access from host_info.permissions and
    # resolve each ESXi principal to a Keeper email via user_map +
    # user_domain. Each VM row carries a `share_with` list (Keeper emails)
    # AND a `share_principals` list (the ESXi-side principals, retained
    # for diagnostics + the "missing-users fail/invite" decision in
    # execute_plan). Either may be empty.
    # Phase 8.19.5: with --share-scope all, every (filtered) user gets
    # every resource. Build the universal-share principal list once.
    universal_share_principals: List[Tuple[str, str]] = []
    if share_scope == "all":
        seen = set()
        for principals in access_map.values():
            for p, role in principals:
                if p not in seen:
                    seen.add(p)
                    universal_share_principals.append((p, role))
        # Also include host-permission principals (admin etc. who may
        # not have any per-VM grant).
        for perm in host_info.get("permissions") or []:
            if perm.get("entity_type") in ("HostSystem", "Folder"):
                principal = perm.get("principal") or ""
                if not principal or principal in share_excludes:
                    continue
                role = perm.get("role") or ""
                if _role_rank(role) < _ROLE_THRESHOLD_FOR_FLAG[minimum_role]:
                    continue
                if principal not in seen:
                    seen.add(principal)
                    universal_share_principals.append((principal, role))
    if include_vms:
        for vm in _eligible_vms(host_info):
            vm_name = vm["name"]
            ip = vm.get("ip_address") or ""
            guest_hostname = vm.get("hostname") or ""
            guest_os = vm.get("guest_full_name") or vm.get("guest_id") or "unknown"
            power_state = vm.get("power_state") or "unknown"
            uuid = vm.get("uuid") or ""

            clean_name = vm_name.replace(" ", "-").replace("_", "-")
            pam_hostname = ip or f"<UPDATE-IP-FOR-{clean_name}>"
            if not ip:
                warnings.append(
                    f"VM {vm_name!r}: placeholder pamHostname "
                    f"'<UPDATE-IP-FOR-{clean_name}>'. VMware Tools "
                    "didn't report an IP at discovery (VM powered off "
                    "or tools not running). Power-cycle the VM or set "
                    "a static IP / DNS, then update pamHostname.hostName "
                    "manually in Web Vault."
                )

            # Phase 8.22: discrete labeled custom fields. Web Vault
            # shows each piece with a human-readable label instead of
            # a blob-string notes field. Notes is reduced to the audit
            # footer + status warnings ("VM POWERED OFF", "NO IP set").
            vm_custom_fields: Dict[str, str] = {}
            vm_custom_fields["Host"] = host
            vm_custom_fields["Guest OS"] = guest_os
            vm_custom_fields["Power State"] = power_state
            if vm.get("num_cpu"):
                vm_custom_fields["vCPU"] = f"{vm['num_cpu']}"
            if vm.get("memory_mb"):
                vm_custom_fields["Memory"] = f"{vm['memory_mb']} MB"
            if vm.get("hardware_version"):
                vm_custom_fields["Hardware Version"] = str(vm["hardware_version"])
            if vm.get("tools_status") and vm["tools_status"] != "unknown":
                vm_custom_fields["VMware Tools"] = str(vm["tools_status"])
            if vm.get("datastore"):
                vm_custom_fields["Datastore"] = str(vm["datastore"])
            if vm.get("folder"):
                vm_custom_fields["vSphere Folder"] = str(vm["folder"])
            if guest_hostname:
                vm_custom_fields["Guest Hostname"] = guest_hostname
            if vm.get("annotation"):
                vm_custom_fields["Description"] = str(vm["annotation"])[:200]

            vm_notes_parts: List[str] = []
            if not ip:
                vm_notes_parts.append(
                    "NO IP — set static IP / DNS or power on + re-discover"
                )
            if "poweredOff" in power_state:
                vm_notes_parts.append("VM was POWERED OFF at discovery")
            vm_notes_parts.append(audit_note)
            vm_notes = "; ".join(vm_notes_parts)

            # Phase 8.19.5: --share-scope all → universal principal
            # list (everyone gets every VM); 'permissions' (default) →
            # per-VM grants from ESXi permissions.
            if share_scope == "all":
                principals = [p for p, _r in universal_share_principals]
            else:
                principals = [p for p, _r in access_map.get(vm_name, [])]

            # Phase 8.23: compute primary principals for this VM —
            # the pamUser(s) whose UIDs go into pamSettings.connection
            # .userRecords (which the gateway/Launch UI uses as
            # autofill candidates). Decoupled from share_principals
            # (who can SEE the record) so the Launch picker can show
            # one canonical owner per VM while broader access still
            # works via record-share.
            vm_perm_principals = access_map.get(vm_name, [])
            if vm_primary_user == "none":
                primary_principals: List[str] = []
            elif vm_primary_user == "broadcast":
                primary_principals = list(principals)
            else:  # "dominant-permission" (default)
                if vm_perm_principals:
                    ranked = sorted(
                        vm_perm_principals,
                        key=lambda x: (-_role_rank(x[1]), x[0]),
                    )
                    primary_principals = [ranked[0][0]]
                else:
                    primary_principals = []

            share_with: List[str] = []
            # Phase 8.10: also retain per-principal email mapping so the
            # folder-share pass can group records by ESXi principal AND
            # know which Keeper email gets the resulting folder share.
            # share_with is a deduped list (one record-share per email);
            # share_user_map keeps the unmasked principal→email mapping.
            share_user_map: Dict[str, str] = {}
            for principal in principals:
                resolved = resolve_keeper_identity(principal, user_map, user_domain)
                share_user_map[principal] = resolved or ""
                if resolved and resolved not in share_with:
                    share_with.append(resolved)

            # Phase 8.14a: per-VM pamSettings with connection.protocol
            # derived from guest OS + portForward.reusePort=true so the
            # gateway can route launches and tunneling. Matches upstream
            # ConnectionSettings*.to_record_dict() shape (per d22 audit).
            vm_protocol = _derive_protocol_for_vm(vm, default=vm_protocol_default)
            vm_port = _PROTOCOL_DEFAULT_PORT.get(vm_protocol, "")
            # Phase 8.16: VMs are LAUNCHABLE on demand via
            # connection.allowSupplyUser=true — the gateway prompts the
            # operator for VM-internal credentials at launch time when
            # userRecords is empty/insufficient. Without this flag, click-
            # Launch on a vault record fails with "no credentials"
            # because we don't discover VM-side creds (d22/8.14b finding).
            # userRecords also gets spliced post-creation in execute_plan
            # (Phase 8.16 splice — mirrors Phase 6.6 httpCredentialsUid)
            # to pre-link the ESXi-host pamUsers that have access to this
            # VM per the discovered permission expansion. Operator can
            # then either: (a) supply creds at launch, OR (b) edit the
            # pre-linked pamUser's password / private key post-import.
            vm_pam_settings_val = "$JSON:" + json.dumps({
                "allowSupplyHost": False,
                "portForward": {"port": vm_port, "reusePort": True} if vm_port else {"reusePort": True},
                "connection": {
                    "protocol": vm_protocol,
                    "port": vm_port,
                    "allowSupplyUser": True,
                    # userRecords spliced post-creation in execute_plan
                },
            })

            # Phase 8.14f: populate the typed fields the pamMachine schema
            # exposes. pamHostname now includes port (default per protocol);
            # operatingSystem / instanceName / instanceId carry the metadata
            # that previously got buried in `notes`. Operators reading the
            # record see structured fields instead of a long stringified
            # notes blob.
            pam_hostname_val = "$JSON:" + json.dumps({
                "hostName": pam_hostname,
                "port": vm_port,
            })

            vm_fields = {
                "pamHostname": pam_hostname_val,
                "pamSettings": vm_pam_settings_val,
                "notes": vm_notes,
            }
            if guest_os and guest_os != "unknown":
                vm_fields["operatingSystem"] = guest_os
            if vm_name:
                vm_fields["instanceName"] = vm_name
            if uuid:
                vm_fields["instanceId"] = uuid
            # providerGroup keys this resource as ESXi-derived (vs cloud
            # providers like AWS/Azure where this slot would carry their
            # native account/group metadata). Constant by design.
            vm_fields["providerGroup"] = "VMware ESXi"
            # Phase 8.22 + 8.24 S1: labeled custom fields routed through
            # post_create_custom_fields (consumed by the post-create
            # update_record path) instead of c.text.* argv. Avoids
            # ps-visible exposure of Service Tag / License / Management IP.

            # Phase 8.19.4: route VM to record_type via upstream
            # PROTOCOL_TYPE_MAP. http→pamRemoteBrowser, mysql/postgres/
            # sql-server→pamDatabase, default→pamMachine. Operator can
            # override per-VM via --vm-record-type vmname=pamDatabase
            # (handled by vm_record_type_overrides dict).
            vm_record_type = vm_record_type_overrides.get(
                vm_name, _record_type_for_protocol(vm_protocol)
            )
            rows.append(
                {
                    "type": vm_record_type,
                    "title": f"{host} :: {vm_name}",
                    "host": host,
                    "vm": vm_name,
                    "fields": vm_fields,
                    # Phase 8.24 S1: labels via post-create (off-argv).
                    "post_create_custom_fields": dict(vm_custom_fields),
                    "share_principals": principals,
                    "share_with": share_with,
                    "share_user_map": share_user_map,
                    "vm_protocol": vm_protocol,
                    # Phase 8.23: subset used for userRecords / DAG link.
                    "primary_principals": primary_principals,
                }
            )

    # 2. pamUser — one per non-system user.
    # Phase 8.14c: pamHostname REMOVED from pamUser. Per upstream schema
    # in keepercommander.commands.pam_import.base.PamUserObject (lines
    # 980-1064), pamUser fields are: login, password, privatePEMKey,
    # distinguishedName, connectDatabase, managed, oneTimeCode. NO
    # pamHostname. Setting that field made pamUsers carry a phantom
    # hostname that confused downstream pam_user_to_dict (Phase 8.5
    # fix `5d68ccd` already warned about this misinterpretation).
    # The pamUser → pamMachine association is via DAG edge created by
    # configure_rotation.py / wire_rotation_graph, NOT a hostname field.
    users = _eligible_users(host_info, include_root=include_root)
    # Phase 8.15.7: build login → full ESXi user dict lookup so pamUser
    # notes can carry full_name / role / access_mode / shell_access from
    # discovery (was previously throwing this away).
    user_info_by_login: Dict[str, Dict[str, Any]] = {}
    for u_dict in (host_info.get("users") or []):
        login = u_dict.get("id") or u_dict.get("login") or u_dict.get("username")
        if login:
            user_info_by_login[login] = u_dict

    for u in users:
        info = user_info_by_login.get(u, {})
        # Phase 8.22 / 8.23.1: pamUser custom fields. Commander's
        # `keeper record-add` CLI parses c.text.* labels with spaces
        # fine for pamMachine but breaks for pamUser (verified live
        # 2026-05-11: rc=0 but record never persisted, stdout shows
        # `argument --folder: expected one argument`). Mirroring
        # the trafficEncryptionSeed Phase 8.17 pattern: emit the
        # labeled fields via in-process update_record AFTER creation
        # by passing a `post_create_custom_fields` row attribute
        # that execute_plan consumes. CLI argv stays simple → record
        # creation succeeds → post-create update adds the labeled
        # fields without going through argparse.
        user_post_create_custom: Dict[str, str] = {}
        if info.get("role"):
            user_post_create_custom["ESXi Role"] = str(info["role"])
        if info.get("full_name"):
            user_post_create_custom["Full Name"] = str(info["full_name"])
        if info.get("access_mode") and info["access_mode"] != "unknown":
            user_post_create_custom["Access Mode"] = str(info["access_mode"])
        if info.get("shell_access") is not None:
            user_post_create_custom["Shell Access"] = (
                "yes" if info["shell_access"] else "no"
            )

        rows.append(
            {
                "type": "pamUser",
                "title": f"{host} :: {u}",
                "host": host,
                "user": u,
                "fields": {
                    "login": u,
                    "password": "",
                    "notes": audit_note,
                },
                "post_create_custom_fields": user_post_create_custom,
            }
        )

    # 3. pamRemoteBrowser — per-host or per-user, or none.
    #
    # Phase 6.5 (2026-05-05): Commander RC 18's `keeper record-add` rejects
    # the naive shape `pamRemoteBrowserSettings='{...}'` with "Unsupported
    # field type" (S3 stop condition fired live during Stage 3g v2).
    # The correct shape is two fields:
    #   - `rbiUrl=<url>`                    (scalar string)
    #   - `pamRemoteBrowserSettings=$JSON:{"connection":{"protocol":"http"}}`
    # The `$JSON:` prefix is Commander's signal to parse the value as a
    # JSON-typed field. Connection at minimum needs `protocol: "http"`;
    # `httpCredentialsUid` is wired by `kcm_pam_post_link.py` post-import
    # (mirrors the kcm-routed pipeline's separation — operator runs
    # post-link after esxi_pam_import to wire autofill credentials).
    # Pattern matches `PamRemoteBrowserObject.create_record` in
    # keepercommander.commands.pam_import.base (Commander RC 18+).
    rbi_url = f"https://{host}/"
    # Phase 8.7.8: ESXi self-signed cert is the norm; without
    # ignoreInitialSslCert=true, RBI's headless browser refuses to load
    # the host UI on first-run (cert chain validation). httpCredentialsUid
    # is spliced per-row by _splice_http_credentials_uid as a single
    # string (NOT a list) — matches upstream's ConnectionSettingsHTTP.to_record_dict
    # contract at pam_import/base.py:2348-2355 which writes uids[0] only.
    # autofillConfiguration is intentionally left unset — the form selectors
    # for ESXi 8 host UI vary by minor version; operators populate via a
    # post-create patch once empirically tested in Web Vault. Format reference:
    #   [{"page": "*.host", "username-field": "#user", "password-field": "#pass", "submit": "button"}]
    rbi_settings = "$JSON:" + json.dumps({
        "connection": {
            "protocol": "http",
            "ignoreInitialSslCert": True,
        }
    })
    if rbi_mode == "per-host":
        rows.append(
            {
                "type": "pamRemoteBrowser",
                "title": f"{host} WebUI",
                "host": host,
                "fields": {
                    "rbiUrl": rbi_url,
                    "pamRemoteBrowserSettings": rbi_settings,
                    "notes": audit_note,
                },
            }
        )
    elif rbi_mode == "per-user":
        for u in users:
            rows.append(
                {
                    "type": "pamRemoteBrowser",
                    "title": f"{host} WebUI - {u}",
                    "host": host,
                    "user": u,
                    "fields": {
                        "rbiUrl": rbi_url,
                        "pamRemoteBrowserSettings": rbi_settings,
                        # httpCredentialsUid is wired post-create by
                        # kcm_pam_post_link.py — matches by title pattern
                        # `<host> WebUI - <user>` against the just-created
                        # pamUser records. Spec drift acknowledged in
                        # `.context/topics/esxi-pam-import-shape.md`.
                        "notes": audit_note,
                    },
                }
            )

    rows = _filter_groups(rows, groups, exclude_groups)

    # Phase 8.16: reorder rows so pamUsers come BEFORE VM pamMachines.
    # The per-row execute_plan loop processes rows in this order, captures
    # each pamUser's UID in pamuser_uids, then VM rows can splice
    # userRecords from those UIDs (mirrors the Phase 6.6 httpCredentialsUid
    # splice for pamRemoteBrowsers). Without this reordering the VM rows
    # would fire BEFORE pamUsers exist and userRecords would always be
    # empty — breaking kcm-import-style launchability.
    # Phase 8.19.4: VM-derived rows can now be pamMachine, pamDatabase,
    # or pamDirectory (router via PROTOCOL_TYPE_MAP). All "vm in r"
    # rows go in the same VM bucket regardless of their pamX type.
    _RESOURCE_TYPES = ("pamMachine", "pamDatabase", "pamDirectory")
    host_rows = [
        r for r in rows
        if r["type"] in _RESOURCE_TYPES and "vm" not in r
        and not r["title"].endswith("WebUI")  # phase 8.19.3 host-RBI is host-row
    ]
    user_rows = [r for r in rows if r["type"] == "pamUser"]
    vm_rows = [r for r in rows if r["type"] in _RESOURCE_TYPES and "vm" in r]
    rbi_rows = [r for r in rows if r["type"] == "pamRemoteBrowser"]
    rows = host_rows + user_rows + vm_rows + rbi_rows

    # Phase 8.20: surface unresolved share principals as warnings so
    # operator sees them in the final report (not just per-row logs).
    unresolved_principals: List[str] = []
    for r in rows:
        for principal, email in (r.get("share_user_map") or {}).items():
            if not email and principal not in unresolved_principals:
                unresolved_principals.append(principal)
    if unresolved_principals:
        warnings.append(
            f"Unresolved share principals (no Keeper email): "
            f"{sorted(set(unresolved_principals))}. Re-run with "
            f"--user-map principal=email@keeper to wire them, or "
            f"--user-domain example.com for a global suffix."
        )

    # ESXi-specific operator follow-up (always-on standing reminders).
    warnings.append(
        "pamUser records have EMPTY passwords by design — ESXi doesn't "
        "expose stored hashes. Add credentials in vault per user, or run "
        "rotation to generate fresh passwords via the gateway."
    )
    warnings.append(
        "ESXi SSH should be DISABLED in production for reduced attack "
        "surface. Re-enable on-demand for rotation runs only."
    )

    return {
        "host": host,
        "rbi_mode": rbi_mode,
        "target": target,
        "rows": rows,
        "summary": _plan_summary(rows),
        "warnings": warnings,
    }


def _plan_summary(rows: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["type"]] = counts.get(r["type"], 0) + 1
    counts["total"] = len(rows)
    return counts


def build_import_report(
    plan: Dict[str, Any],
    execution: Dict[str, Any],
    pam_config_uid: Optional[str] = None,
    extra_warnings: Optional[List[str]] = None,
) -> str:
    """Phase 8.20: kcm-import-style structured report.
    Mirrors `keepercommander.commands.pam_import.kcm_import.
    PAMProjectKCMImportCommand._build_import_report` shape. Single
    source of truth for "what happened + what operator must do next".
    Memory: reference_kcm_import_report_pattern.md."""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = (execution or {}).get("rows", [])
    ok = [r for r in rows if r.get("result") == "ok"]
    failed = [r for r in rows if r.get("result") == "failed"]
    pam_config_uid = pam_config_uid or "(none — pass --link-pam-config-uid)"

    # Per-type breakdown
    type_counts: Dict[str, Dict[str, int]] = {}
    for r in rows:
        t = r.get("type") or "?"
        status = "ok" if r.get("result") == "ok" else "err"
        type_counts.setdefault(t, {}).setdefault(status, 0)
        type_counts[t][status] = type_counts[t].get(status, 0) + 1

    # Merge warnings from plan + extras (from execute_plan)
    warnings = list(plan.get("warnings") or [])
    if extra_warnings:
        warnings.extend(extra_warnings)

    # Phase 8.24 D5: branch the header on completion state so aborted
    # runs don't print a "Complete" header — was visually misleading
    # when execute_plan exited early on --missing-users fail or session
    # expiry.
    complete = (execution or {}).get("complete", True)
    header = (
        f" ESXi PAM Import Complete — {plan.get('host', '?')}"
        if complete
        else f" ESXi PAM Import — ABORTED (partial) — {plan.get('host', '?')}"
    )
    lines = [
        "",
        "=" * 60,
        header,
        "=" * 60,
        "",
        f" Timestamp:      {ts}",
        f" Host:           {plan.get('host', '?')}",
        f" RBI mode:       {plan.get('rbi_mode', '?')}",
        f" Target:         {plan.get('target') or '(none)'}",
        f" pamConfig UID:  {pam_config_uid}",
        "",
        " IMPORT RESULTS",
        " " + "-" * 40,
        f"   Planned:    {len(rows)} records",
        f"   Created:    {len(ok)}",
        f"   Failed:     {len(failed)}",
    ]

    if type_counts:
        lines.extend([
            "",
            " RECORD BREAKDOWN",
            " " + "-" * 40,
            f"   {'Type':<22} {'OK':>5} {'Err':>5}",
        ])
        for t in sorted(type_counts):
            ok_n = type_counts[t].get("ok", 0)
            er_n = type_counts[t].get("err", 0)
            lines.append(f"   {t:<22} {ok_n:>5} {er_n:>5}")

    if failed:
        lines.extend(["", " FAILED RECORDS", " " + "-" * 40])
        for r in failed:
            title = (r.get("title") or "?")[:40]
            # Phase 8.24 B1: failure entries use "stderr"; some paths also
            # carry "error" (post-create runners). Read both to avoid the
            # "— ?" placeholder bug.
            err = (r.get("stderr") or r.get("error") or "?")[:60]
            lines.append(f"   ERR  {r.get('type','?'):<20} {title}  — {err}")

    if warnings:
        lines.extend(["", " WARNINGS", " " + "-" * 40])
        for w in warnings:
            lines.append(f"   - {w}")

    lines.extend([
        "",
        " WHAT TO DO NEXT",
        " " + "-" * 40,
        "",
        "   1. VERIFY GATEWAY IS ONLINE",
        "      Web Vault: PAM Configurations → click the linked",
        f"      pamConfig ({pam_config_uid}). Gateway badge must be",
        "      green (Connected). If red, restart the gateway docker",
        "      container or check controllerUid wiring.",
        "",
        "   2. RESOLVE PLACEHOLDER pamHostname",
        "      Powered-off VMs got '<UPDATE-IP-FOR-<name>>' placeholders.",
        "      Power-cycle the VM or set a static IP / DNS, then update",
        "      pamHostname.hostName manually in Web Vault.",
        "",
        "   3. ADD MISSING CREDENTIALS",
        "      pamUser records have EMPTY passwords by design — ESXi",
        "      doesn't expose stored hashes. Two paths:",
        "        a. Add credentials manually in vault per pamUser.",
        "        b. Run rotation to generate fresh passwords via the",
        "           gateway: scripts/configure_rotation.py --state ...",
        "",
        "   4. WIRE UNRESOLVED SHARE PRINCIPALS",
        "      ESXi principals without a Keeper email mapping won't",
        "      receive shares. Re-run with:",
        "        --user-map alice=alice@example.com,bob=bob@example.com",
        "      OR --user-domain example.com for global suffix.",
        "",
        "   5. ENABLE ESXi SSH FOR ROTATION",
        "      ESXi SSH should be DISABLED in production. Re-enable",
        "      on-demand for rotation runs only. Disable again after.",
        "",
        "   6. TEST A LAUNCH",
        "      Click Launch on any per-VM pamMachine. Should autofill",
        "      credentials from the linked pamUser via DAG edge.",
        "      If 'required record not found' — pamUser→resource DAG",
        "      edge missing; check execution log's user_resource_links",
        "      key per row.",
        "",
        "   7. CLEAN UP (when done)",
        "      scripts/esxi_pam_import.py --state <state-file> --rollback",
        "      reverses all UIDs created in this run.",
        "",
        "=" * 60,
        "",
    ])
    return "\n".join(lines)


def format_plan_table(plan: Dict[str, Any]) -> str:
    lines = [
        f"Host:      {plan['host']}",
        f"RBI mode:  {plan['rbi_mode']}",
        f"Target:    {plan.get('target') or '(none)'}",
        "Summary:   " + ", ".join(f"{k}={v}" for k, v in sorted(plan["summary"].items())),
        "",
        f"{'#':>3}  {'Type':<18} {'Title':<60}",
        f"{'-' * 3}  {'-' * 18} {'-' * 60}",
    ]
    for i, r in enumerate(plan["rows"], 1):
        lines.append(f"{i:>3}  {r['type']:<18} {r['title']:<60}")
    return "\n".join(lines) + "\n"


def format_plan_csv(plan: Dict[str, Any]) -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["#", "type", "title", "host", "user"])
    for i, r in enumerate(plan["rows"], 1):
        w.writerow([i, r["type"], r["title"], r.get("host", ""), r.get("user", "")])
    return out.getvalue()


def _build_record_add_argv(row: Dict[str, Any], folder: Optional[str]) -> List[str]:
    """Translate one plan row into a `keeper record-add` argv. Mirrors
    bootstrap_vault_records.keeper_record_add_login's positional convention
    (typed field= args first, --folder LAST)."""
    argv = [KEEPER_BIN, "--batch-mode", "record-add", "-t", row["title"], "-rt", row["type"]]
    for k, v in (row.get("fields") or {}).items():
        argv.append(f"{k}={v}")
    if folder:
        argv.extend(["--folder", folder])
    return argv


def _splice_vm_user_records(row: Dict[str, Any], pamuser_uids: Dict[str, str]) -> Dict[str, Any]:
    """Phase 8.16: return a shallow copy of `row` (a VM pamMachine) with
    `pamSettings.connection.userRecords` populated from the pamUser UIDs
    of the ESXi-host users who have access to this VM (per Phase 8.11
    expansion in `share_principals`).

    Mirrors `_splice_http_credentials_uid` for pamRemoteBrowser. Called
    from execute_plan AFTER pamUsers are created (rows reordered in
    build_plan to make this possible). Without this, VM pamMachines have
    empty userRecords → click-Launch in vault has no creds and falls
    back to the `connection.allowSupplyUser=true` interactive prompt.
    With this, the VM is "ready to launch" against any of the linked
    pamUsers (operator picks at launch time).

    Idempotent: if userRecords is already populated, our UIDs prepend
    to the existing list and dedupe.
    """
    if row.get("type") != "pamMachine" or not row.get("vm"):
        return row
    fields = dict(row.get("fields") or {})
    settings_raw = fields.get("pamSettings", "")
    if not settings_raw.startswith("$JSON:"):
        return row

    # Phase 8.23: prefer primary_principals (controlled by
    # --vm-primary-user) over share_principals. share_principals is
    # "who can SEE this record" — much broader than "whose creds
    # autofill at Launch." When primary_principals is explicitly set
    # (even to []) by build_plan, use it; legacy callers without the
    # key fall through to share_principals for backwards compat.
    if "primary_principals" in row:
        principals = row.get("primary_principals") or []
    else:
        principals = row.get("share_principals") or []
    if not principals:
        return row

    # Resolve pamUser UIDs from principals via the host-keyed cache
    host = row.get("host", "")
    resolved: List[str] = []
    for principal in principals:
        key = f"{host} :: {principal}"
        uid = pamuser_uids.get(key)
        if uid and uid not in resolved:
            resolved.append(uid)

    if not resolved:
        # No pamUsers were created for the principals (filtered out, or
        # creation failed) — leave userRecords empty; allowSupplyUser
        # still enables interactive cred entry at launch time.
        return row

    body = settings_raw[len("$JSON:") :]
    try:
        decoded = json.loads(body)
    except json.JSONDecodeError:
        return row
    conn = decoded.setdefault("connection", {})
    existing = conn.get("userRecords") or []
    if isinstance(existing, str):
        existing = [existing]
    # New UIDs first, then existing (de-duplicated).
    merged: List[str] = []
    for u in resolved + list(existing):
        if u not in merged:
            merged.append(u)
    conn["userRecords"] = merged
    fields["pamSettings"] = "$JSON:" + json.dumps(decoded)
    out = dict(row)
    out["fields"] = fields
    return out


def _splice_http_credentials_uid(row: Dict[str, Any], pamuser_uid: str) -> Dict[str, Any]:
    """Phase 6.6 + 8.7.8: return a shallow copy of `row` with the matching
    pamUser's UID injected into the pamRemoteBrowserSettings
    `connection.httpCredentialsUid` field, so RBI sessions on this
    pamRemoteBrowser autofill the per-user credentials.

    Phase 8.7.8 corrected the value SHAPE: previously written as a list
    (`["UID"]`) but upstream's ConnectionSettingsHTTP.to_record_dict at
    `pam_import/base.py:2348-2355` writes a single string (`uids[0]`).
    Web Vault's RBI launch path may handle either, but matching upstream's
    canonical shape eliminates ambiguity. We now write a single string.
    """
    fields = dict(row.get("fields") or {})
    settings_raw = fields.get("pamRemoteBrowserSettings", "")
    # The planner emits with `$JSON:` prefix so Commander parses as JSON.
    # Strip the prefix, decode, mutate, re-encode, restore prefix.
    if not settings_raw.startswith("$JSON:"):
        # Belt-and-braces: don't break if a future planner change drops the
        # prefix — operator can still post-link manually.
        return row
    body = settings_raw[len("$JSON:") :]
    try:
        decoded = json.loads(body)
    except json.JSONDecodeError:
        return row
    conn = decoded.setdefault("connection", {})
    # Phase 8.7.8: write as single string per upstream convention. If an
    # existing value is somehow a list (legacy records, manual edits),
    # we collapse to first non-empty element + pamuser_uid takes precedence.
    existing = conn.get("httpCredentialsUid")
    if isinstance(existing, list):
        existing = next((u for u in existing if u), None)
    # pamuser_uid wins; existing is preserved only if pamuser_uid is empty.
    conn["httpCredentialsUid"] = pamuser_uid or existing or ""
    if not conn["httpCredentialsUid"]:
        conn.pop("httpCredentialsUid", None)
    fields["pamRemoteBrowserSettings"] = "$JSON:" + json.dumps(decoded)
    out = dict(row)
    out["fields"] = fields
    return out


# Phase 8.7 type-to-folder routing: which subfolder each record type
# lives in when `users_folder` + `resources_folder` are provided. Mirrors
# the upstream kcm-import convention (see pam_import/edit.py:283-290).
_TYPE_TO_FOLDER_KIND = {
    "pamUser": "users",
    "pamMachine": "resources",
    "pamRemoteBrowser": "resources",
    "pamDirectory": "users",
    "pamDatabase": "resources",
}


def _find_folder_by_name(params, name: str, parent_uid: Optional[str]) -> Optional[str]:
    """Search folder_cache + shared_folder_cache for a folder named `name`
    whose parent_uid matches the provided `parent_uid` (empty string and
    None both mean vault root)."""
    for cache in ("folder_cache", "shared_folder_cache"):
        d = getattr(params, cache, {}) or {}
        for fuid, fdata in d.items():
            fname = fdata.get("name_unencrypted") if isinstance(fdata, dict) else getattr(fdata, "name", "")
            fparent = fdata.get("parent_uid") if isinstance(fdata, dict) else getattr(fdata, "parent_uid", None)
            if fname == name and (fparent or "") == (parent_uid or ""):
                return fuid
    return None


def _create_user_folder_under(params, name: str, parent_uid: Optional[str]) -> Optional[str]:
    """Create a user folder named `name` under `parent_uid` (or vault root).
    Temporarily sets params.current_folder so FolderMakeCommand resolves
    the path under the right base. Restores current_folder on exit.

    Returns the new folder's UID, or None on failure.
    """
    from keepercommander import api
    from keepercommander.commands.folder import FolderMakeCommand

    saved_cf = getattr(params, "current_folder", "") or ""
    try:
        if parent_uid:
            params.current_folder = parent_uid
        else:
            params.current_folder = ""  # vault root
        FolderMakeCommand().execute(params, folder=name, user_folder=True)
        api.sync_down(params)
        return _find_folder_by_name(params, name, parent_uid)
    except Exception as exc:  # noqa: BLE001
        log.error("Failed to create folder %r under parent=%r: %s", name, parent_uid, exc)
        return None
    finally:
        params.current_folder = saved_cf


def resolve_or_create_project_folders(
    params,
    project_name: str,
    *,
    parent_folder_uid: Optional[str] = None,
    create_if_missing: bool = True,
) -> Tuple[Optional[str], Optional[str]]:
    """Resolve a 3-level folder structure mirroring upstream kcm-import's
    `--name PROJECT` shape (Phase 8.7.1):

        [parent_folder_uid or vault root]/
        └── <project_name>/                         (wrapper folder)
            ├── <project_name> - Users               pamUser, pamDirectory
            └── <project_name> - Resources           pamMachine, pamRemoteBrowser, pamDatabase

    Returns `(users_folder_uid, resources_folder_uid)` — the LEAF folder
    UIDs. The wrapper UID is intentional internal scaffolding.

    Either return value may be None if `create_if_missing=False` and
    the folder doesn't exist. With `create_if_missing=True`, missing
    folders are created as user folders. Existing folders are reused
    (idempotent re-runs).
    """
    from keepercommander import api

    api.sync_down(params)

    # 1. Resolve or create the wrapper folder under parent_folder_uid.
    wrapper_uid = _find_folder_by_name(params, project_name, parent_folder_uid)
    if not wrapper_uid:
        if not create_if_missing:
            return None, None
        wrapper_uid = _create_user_folder_under(params, project_name, parent_folder_uid)
        if not wrapper_uid:
            return None, None

    # 2. Resolve or create the two children under the wrapper.
    target_users = f"{project_name} - Users"
    target_resources = f"{project_name} - Resources"

    users_uid = _find_folder_by_name(params, target_users, wrapper_uid)
    resources_uid = _find_folder_by_name(params, target_resources, wrapper_uid)

    if not create_if_missing:
        return users_uid, resources_uid

    if not users_uid:
        users_uid = _create_user_folder_under(params, target_users, wrapper_uid)
    if not resources_uid:
        resources_uid = _create_user_folder_under(params, target_resources, wrapper_uid)

    return users_uid, resources_uid


def _default_share_runner(params, record_uid: str, email: str) -> Tuple[bool, str]:
    """Phase 8.9 default share runner. In-process Commander API call to
    share a record with a Keeper user. Returns (success, message).

    Tests inject their own runner via execute_plan's `_share_runner` to
    avoid hitting the real API. Production callers pass None and get
    this default — which uses the active params + the Commander RC18
    share-record path.

    Phase 8.9 live-test L3 fix (2026-05-09):
    - Class is `ShareRecordCommand` in `keepercommander.commands.register`
      (NOT `RecordShareCommand` in `commands.record`)
    - `email` kwarg is a LIST, not a single string (parser uses repeatable -e)
    - sync_down BEFORE every share call: records are created via
      subprocess in a different Commander instance, so our in-process
      `params.record_cache` doesn't know about them. Without sync_down,
      ShareRecordCommand falls into broad-search path that errors on
      "'NoneType' object has no attribute 'subfolders'". Cost is a
      few seconds per share but correctness wins.

    The Commander module path may shift in future RCs; we wrap the
    import in try/except so a change in upstream surfaces as an
    actionable error rather than a generic ImportError partway through
    a batch."""
    try:
        from keepercommander import api  # type: ignore
        from keepercommander.commands.register import ShareRecordCommand  # type: ignore
    except ImportError as exc:
        return False, f"Commander ShareRecordCommand import failed: {exc}"
    try:
        # Phase 8.9 L3 fix: refresh params' record_cache so it knows
        # about records just created via the per-row subprocess.
        api.sync_down(params)
        cmd = ShareRecordCommand()
        # action='grant' adds the user; default permission is read.
        # `email` MUST be a list per share_record_parser; passing a
        # bare string makes Commander iterate over chars.
        cmd.execute(params, record=record_uid, email=[email], action="grant")
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _generate_traffic_encryption_seed() -> str:
    """Phase 8.17: produce a 32-byte base64-encoded random seed matching
    the shape of working pamMachines on demo2 (verified against
    `K2qMH-F1ET_Em1dJ6QgGRQ` aka POC-in-a-Box SSH machine which has
    seed='Eu7tb5d+7ebGlfXXMZr5SayS4XGgi+zpUJqhQOq9DBk=' — 32 bytes b64-
    encoded gives 44 chars + '='). Web Vault hides the Launch button
    when this field is empty, so it's mandatory for launchable records.
    """
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _default_traffic_seed_runner(params, machine_uid: str, seed_value: str) -> Tuple[bool, str]:
    """Phase 8.17 default runner: in-process update_record to populate
    pamMachine.trafficEncryptionSeed (CLI rejects this field per Phase
    8.7.6 finding — registry-not-exposed). Web Vault Launch button is
    gated on this field being non-empty.

    Tests inject their own runner via execute_plan's
    `_traffic_seed_runner` to avoid the real API.
    """
    try:
        from keepercommander import api, record_management, vault
    except ImportError as exc:
        return False, f"keepercommander update_record import failed: {exc}"
    try:
        api.sync_down(params)
        rec = vault.KeeperRecord.load(params, machine_uid)
        if rec is None:
            return False, f"record {machine_uid} not found in vault"
        # Find the existing trafficEncryptionSeed field (schema slot is
        # always present on pamMachine; we just populate the value).
        for f in rec.fields:
            if (getattr(f, "type", "") or "").lower() == "trafficencryptionseed":
                f.value = [seed_value]
                break
        else:
            return False, f"no trafficEncryptionSeed field found on {machine_uid}"
        # Phase 8.24 D4: retry-with-jitter (vault-bound).
        _retry_with_jitter(lambda: record_management.update_record(params, rec))
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _default_pam_config_link_runner(
    params, pam_config_uid: str, machine_uid: str
) -> Tuple[bool, str]:
    """Phase 8.14d default pamConfig-link runner. Calls
    `_keeper_session.wire_rotation_graph(params, pam_config_uid,
    machine_uid)` with no admin/rotation user — produces only the
    `set_resource_allowed(meta_version=1)` DAG edge that links
    pamMachine into pamConfig with all permissions enabled. Without
    this, even shared records can't be launched (gateway has no
    routing edge to the pamMachine).

    Tests inject their own runner via execute_plan's
    `_pam_config_link_runner` to avoid the real DAG API."""
    try:
        from _keeper_session import wire_rotation_graph
    except ImportError as exc:
        return False, f"Cannot import wire_rotation_graph helper: {exc}"
    try:
        # Phase 8.24 D4: retry-with-jitter (gateway-bound DAG op).
        _retry_with_jitter(
            lambda: wire_rotation_graph(
                params,
                config_uid=pam_config_uid,
                resource_uid=machine_uid,
                admin_uid=None,         # rotation-specific; out of scope here
                rotation_user_uid=None,  # rotation-specific; out of scope here
            )
        )
        return True, ""
    except Exception as exc:
        return False, str(exc)


def _extract_user_uids_from_row_fields(fields: Dict[str, Any]) -> List[str]:
    """Phase 8.21: pull the pamUser UIDs out of a row's emitted fields.
    For pamMachine/pamDatabase/pamDirectory: pamSettings.connection
    .userRecords (list). For pamRemoteBrowser: pamRemoteBrowserSettings
    .connection.httpCredentialsUid (single string).

    The fields may be `$JSON:`-prefixed strings (pre-emission) or
    already-parsed dicts (post-emission). Tolerates both."""
    out: List[str] = []

    def _coerce(raw):
        if raw is None:
            return None
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, str):
            if raw.startswith("$JSON:"):
                raw = raw[len("$JSON:"):]
            try:
                return json.loads(raw)
            except Exception:
                return None
        if isinstance(raw, list) and raw:
            return _coerce(raw[0])
        return None

    settings = _coerce(fields.get("pamSettings"))
    if settings:
        conn = settings.get("connection") or {}
        for uid in conn.get("userRecords") or []:
            if isinstance(uid, str) and uid and uid not in out:
                out.append(uid)

    rb_settings = _coerce(fields.get("pamRemoteBrowserSettings"))
    if rb_settings:
        conn = rb_settings.get("connection") or {}
        u = conn.get("httpCredentialsUid")
        if isinstance(u, str) and u and u not in out:
            out.append(u)
    return out


# Phase 8.24 D4: errors that should NEVER retry. Auth failures will
# persist; cancellation must propagate immediately.
_NON_RETRYABLE_EXC_TYPES = (KeyboardInterrupt, SystemExit)
_NON_RETRYABLE_SUBSTRINGS = (
    "401", "403", "Unauthorized", "Forbidden",
    "session", "expired", "auth",  # Commander session-stale signals
)


def _retry_with_jitter(fn, attempts: int = 3, base_delay: float = 1.0):
    """Phase 8.24 D4 + validation hardening: retry helper for
    gateway-bound DAG ops. Transient 5xx / throttle errors leave DAG
    edges unset (record exists but Launch button hidden). Three
    attempts at 1s + 3s + 9s + jitter; total ~13s worst case.

    Skip retry for non-retryable categories: KeyboardInterrupt / SystemExit
    propagate immediately; auth-class errors (401/403/session-expired)
    will fail again on retry and just burn API quota. All other
    Exceptions are retried."""
    last_exc = None
    for i in range(attempts):
        try:
            return fn()
        except _NON_RETRYABLE_EXC_TYPES:
            raise
        except Exception as exc:
            msg = str(exc).lower()
            if any(s.lower() in msg for s in _NON_RETRYABLE_SUBSTRINGS):
                raise
            last_exc = exc
            if i < attempts - 1:
                delay = base_delay * (3 ** i) + random.uniform(0, base_delay)
                time.sleep(delay)
    raise last_exc  # type: ignore[misc]


def _default_user_resource_link_runner(
    params, pam_config_uid: str, resource_uid: str, user_uids: List[str]
) -> Tuple[bool, str, int]:
    """Phase 8.21 default user→resource DAG link runner. For each
    pamUser UID, fires `tdag.link_user_to_resource(user_uid,
    resource_uid, belongs_to=True)` so Web Vault's Launch dialog
    finds linked credentials. Without this, Launch shows "required
    record not found" even when pamSettings.connection.userRecords
    has the same UIDs (the field is autofill-hint; the DAG edge is
    source-of-truth for "what creds can use this resource").

    Mirrors upstream `pam_import/edit.py:854` which fires this for
    the admin pamUser at import time. We extend it to ALL share
    targets so multi-user resources work too.

    Returns (success, error-message, edges-wired-count).

    Tests inject their own runner via execute_plan's
    `_user_resource_link_runner` to avoid the real DAG API."""
    if not user_uids:
        return True, "", 0
    try:
        from keepercommander.commands.discoveryrotation import (  # type: ignore
            get_keeper_tokens,
        )
        from keepercommander.commands.tunnel.port_forward.TunnelGraph import (  # type: ignore
            TunnelDAG,
        )
    except ImportError as exc:
        return False, f"Cannot import TunnelDAG primitive: {exc}", 0
    try:
        est, etk, tk = get_keeper_tokens(params)
        tdag = TunnelDAG(params, est, etk, pam_config_uid,
                         is_config=True, transmission_key=tk)
    except Exception as exc:
        return False, f"TunnelDAG init failed: {exc}", 0
    wired = 0
    for user_uid in user_uids:
        try:
            # Phase 8.24 D4: gateway-bound DAG ops get retry-with-jitter
            # to survive transient 5xx / throttle. Without this each
            # transient error leaves the edge un-wired → silent
            # "required record not found" at Launch time.
            _retry_with_jitter(
                lambda uu=user_uid: tdag.link_user_to_resource(
                    uu, resource_uid, belongs_to=True
                )
            )
            wired += 1
        except Exception as exc:
            log.warning(
                "    link_user_to_resource(%s -> %s) failed after retries: %s",
                user_uid, resource_uid, exc,
            )
    return True, "", wired


def _default_folder_share_runner(
    params,
    parent_folder_uid: Optional[str],
    principal_name: str,
    record_uids: List[str],
) -> Tuple[bool, str, Optional[str]]:
    """Phase 8.10 / Phase 8.13 redesign default folder-organization
    runner. Creates a PERSONAL sub-folder named after `principal_name`
    under `parent_folder_uid` and MOVES each record in `record_uids`
    into it. Returns (success, message, folder_uid).

    NOTE: This is operator-side VISUAL ORGANIZATION, not access
    control. Recipients see records via record-share (--share-mode
    record path runs first). The folder is a personal folder in the
    operator's vault — recipients don't see the folder itself.

    Why move instead of link: live-test L4 confirmed Keeper's
    FolderMoveCommand has no `link` flag — it MOVES, not LINKS. The
    original folder-share design tried to link records into multiple
    shared folders; that's not supported. The redesign uses move
    semantics, which means a VM record can only be in ONE per-user
    folder. Multi-principal VMs are handled at the orchestration
    layer (execute_plan): they stay in Resources and don't get moved.

    Reuses the same pattern as Phase 8.7's
    `_create_user_folder_under` (params.current_folder context) since
    `mkdir` takes a path-style folder argument, not a parent_uid kwarg.

    Tests inject their own runner via execute_plan's
    `_folder_share_runner` to avoid the real API."""
    try:
        from keepercommander import api  # type: ignore
        from keepercommander.commands.folder import (  # type: ignore
            FolderMakeCommand,
            FolderMoveCommand,
        )
    except ImportError as exc:
        return False, f"Commander folder command import failed: {exc}", None

    # Phase 8.24 S2 + validation hardening: allowlist regex (was a
    # denylist of /, \, .. — missed NUL, control chars, leading dot,
    # Unicode lookalikes like U+2025/U+FF0E, right-to-left override).
    # Allow only `[A-Za-z0-9._@-]` and strip leading dots + trim.
    safe_principal = re.sub(r"[^A-Za-z0-9._@\-]", "_", principal_name or "")
    safe_principal = safe_principal.lstrip(".").strip()[:64]
    if not safe_principal:
        return False, f"principal_name {principal_name!r} sanitized to empty string", None

    saved_cf = getattr(params, "current_folder", "") or ""
    try:
        # mkdir treats `folder` as a path resolved relative to
        # current_folder. Set parent context, create, restore.
        api.sync_down(params)
        params.current_folder = parent_folder_uid or ""
        FolderMakeCommand().execute(params, folder=safe_principal, user_folder=True)
        api.sync_down(params)
        # Find the freshly-created folder by name + parent
        folder_uid = _find_folder_by_name(params, safe_principal, parent_folder_uid)
        if not folder_uid:
            return False, f"could not resolve newly-created folder {safe_principal!r} under parent {parent_folder_uid!r}", None
        # Move records into it. Restore current_folder first so mv's
        # src-path resolution can find records anywhere.
        params.current_folder = saved_cf
        mv = FolderMoveCommand()
        for rec_uid in record_uids:
            mv.execute(params, src=rec_uid, dst=folder_uid)
        return True, "", folder_uid
    except Exception as exc:
        return False, str(exc), None
    finally:
        params.current_folder = saved_cf


def execute_plan(
    plan: Dict[str, Any],
    *,
    folder: Optional[str],
    yes: bool,
    chunk_size: int,
    chunk_delay: float,
    dry_run: bool = False,
    _runner=None,
    # Upstream-port: row-aware in-process record creator. When set, used
    # in place of the subprocess `_runner`. Takes (params, row, folder_uid)
    # and returns (rc, stdout, stderr) compatible with the existing
    # _extract_uid scan. The in-process path closes Phase 8.24 S1 (no
    # argv at all) and avoids feedback_keeper_cli_lockout.md (no nested
    # `keeper` subprocess from inside the REPL session).
    _record_creator=None,
    _persist_cb=None,
    users_folder: Optional[str] = None,
    resources_folder: Optional[str] = None,
    params=None,
    missing_users: str = "skip",
    no_share: bool = False,
    share_mode: str = "record",
    link_pam_config_uid: Optional[str] = None,
    populate_traffic_seed: bool = True,
    _share_runner=None,
    _folder_share_runner=None,
    _pam_config_link_runner=None,
    _traffic_seed_runner=None,
    _user_resource_link_runner=None,
) -> Dict[str, Any]:
    """Walk plan['rows'] and create each record. Returns an execution log
    suitable for persisting back into the state file for --rollback.

    Folder routing:
      - If `users_folder` AND `resources_folder` are both set, records are
        routed by type per `_TYPE_TO_FOLDER_KIND` (Phase 8.7 split).
      - Else `folder` is used for all records (legacy single-folder mode).

    `_runner` is an injection seam for tests — defaults to subprocess.run.
    `_persist_cb`, if supplied, is called as `_persist_cb(execution_dict)`
    after every successful record-add so a SIGKILL mid-batch leaves the
    state file accurate up to the last completed row (Phase 6 review:
    blue-team H1 + red-team L2). Production callers wire this to a
    closure that calls `_atomic_write_state` against the operator's
    state file.
    """
    runner = _runner or _default_runner

    if not dry_run and not yes:
        log.warning(
            "--execute without --yes: tool will proceed but a real "
            "operator deployment should set --yes for non-interactive "
            "audit clarity."
        )

    log_entries: List[Dict[str, Any]] = []
    chunk_pauses = 0
    successful_in_chunk = 0
    # Phase 6.6 inline httpCredentialsUid wiring: as pamUser rows are
    # successfully created we capture their UIDs by `(host, user)` key.
    # When a later pamRemoteBrowser row for the same user comes through,
    # we inject httpCredentialsUid into its pamRemoteBrowserSettings so
    # the RBI session can autofill from the matching pamUser. Mirrors
    # the spec doc's "post-link semantics" intent — pam-only does NOT
    # need a separate kcm_pam_post_link step. Closes the spec-vs-code
    # drift documented in d14 § "Inline httpCredentialsUid wiring".
    pamuser_uids: Dict[str, str] = {}

    for idx, row in enumerate(plan["rows"], 1):
        # If this is a pamRemoteBrowser row for a user we've already
        # created, splice the httpCredentialsUid into its connection
        # JSON before building argv. Per-host RBIs (no row['user']) and
        # rows whose pamUser failed earlier get no autofill wiring.
        if row["type"] == "pamRemoteBrowser" and row.get("user"):
            user_key = f"{row.get('host', '')} :: {row['user']}"
            paired_uid = pamuser_uids.get(user_key)
            if paired_uid:
                row = _splice_http_credentials_uid(row, paired_uid)
        # Phase 8.16: splice connection.userRecords on VM pamMachines.
        # Rows are reordered in build_plan so pamUsers come first;
        # by the time a VM row is processed, pamuser_uids has the
        # ESXi-host pamUser UIDs needed to populate userRecords.
        if row["type"] == "pamMachine" and row.get("vm"):
            row = _splice_vm_user_records(row, pamuser_uids)
        # Phase 8.7: route by type when both per-kind folders are set.
        if users_folder and resources_folder:
            kind = _TYPE_TO_FOLDER_KIND.get(row["type"])
            row_folder = users_folder if kind == "users" else resources_folder
        else:
            row_folder = folder
        # Upstream-port: if a row-aware in-process creator was injected,
        # use it instead of building argv + subprocess-ing. The creator
        # gets (params, row, folder_uid) and returns the same
        # (rc, stdout, stderr) shape so the rest of the loop is unchanged.
        if _record_creator is not None and not dry_run:
            argv = None  # not used on this path
        else:
            argv = _build_record_add_argv(row, row_folder)
        if dry_run:
            log_entries.append(
                {
                    "idx": idx,
                    "type": row["type"],
                    "title": row["title"],
                    "result": "dry-run",
                    "argv_len": len(argv) if argv is not None else 0,
                }
            )
            continue
        if _record_creator is not None:
            rc, stdout, stderr = _record_creator(params, row, row_folder)
        else:
            rc, stdout, stderr = runner(argv, timeout=_PER_RECORD_TIMEOUT_SECS)
        if rc == 0:
            uid = _extract_uid(stdout + " " + stderr)
            entry = {
                "idx": idx,
                "type": row["type"],
                "title": row["title"],
                "result": "ok",
                "uid": uid,
                "exit_code": 0,
            }
            # Phase 8.24 D1: append entry to log_entries IMMEDIATELY so
            # a SIGKILL or uncaught exception in the post-create steps
            # (share, pamConfig link, traffic seed, user-resource link,
            # custom fields) leaves the UID visible to --rollback.
            # Post-create steps mutate `entry` in-place (dict is mutable);
            # the persist callback at end-of-chunk captures the latest
            # state. Was: appended at line ~2223 AFTER all post-create
            # had run — leaving a crash window where the vault has the
            # record but state.json doesn't.
            log_entries.append(entry)

            # Phase 8.9: per-record share — the access mechanism for
            # recipients. Phase 8.13 redesign: folder mode ALSO does
            # record-share (it's the only path that delivers access);
            # the post-creation folder pass adds operator-side visual
            # organization on top. So record-share fires for both
            # 'record' and 'folder' modes (was 'record' or 'both' pre-8.13).
            do_record_share = (
                not no_share
                and share_mode in ("record", "folder")
            )
            shares_to_attempt = (row.get("share_with") or []) if do_record_share else []
            if shares_to_attempt and uid and not dry_run:
                share_runner = _share_runner or _default_share_runner
                share_results: List[Dict[str, Any]] = []
                for email in shares_to_attempt:
                    ok, msg = share_runner(params, uid, email)
                    share_results.append({
                        "email": email,
                        "ok": ok,
                        "error": msg if not ok else "",
                    })
                    if ok:
                        log.info("    shared %s with %s", uid, email)
                    else:
                        if missing_users == "fail":
                            # Phase 8.24 D1+validation: entry was already
                            # appended after UID extraction (line ~2091).
                            # Just attach share_results and abort. The
                            # earlier double-append produced duplicate rows
                            # → rollback would attempt rm twice.
                            entry["shares"] = share_results
                            log.error(
                                "share_record(%s, %s) failed: %s — aborting "
                                "per --missing-users=fail", uid, email, msg
                            )
                            return {
                                "executed_at": _now_iso(),
                                "dry_run": dry_run,
                                "rows": log_entries,
                                "chunk_pauses": chunk_pauses,
                                "complete": False,
                                "aborted_on": "share_failure",
                            }
                        elif missing_users == "invite":
                            log.warning(
                                "share_record(%s, %s) failed: %s — invite "
                                "mode not yet implemented; treating as skip",
                                uid, email, msg,
                            )
                        else:  # skip
                            log.warning(
                                "share_record(%s, %s) failed: %s — continuing "
                                "(--missing-users=skip)", uid, email, msg
                            )
                entry["shares"] = share_results

            # Phase 8.14d / 8.18 / 8.19.4: pamConfig DAG link for ANY
            # launchable resource type. Without this, even shared records
            # can't be launched — gateway has no routing edge from
            # pamConfig to the resource. Resource types per upstream
            # PAM_RESOURCES_RECORD_TYPES (base.py:34).
            if (
                link_pam_config_uid
                and row["type"] in ("pamMachine", "pamDatabase", "pamDirectory", "pamRemoteBrowser")
                and uid
                and not dry_run
            ):
                pam_config_runner = (
                    _pam_config_link_runner or _default_pam_config_link_runner
                )
                ok, msg = pam_config_runner(params, link_pam_config_uid, uid)
                entry["pam_config_link"] = {"ok": ok, "error": msg if not ok else ""}
                if ok:
                    log.info("    linked %s to pamConfig %s", uid, link_pam_config_uid)
                else:
                    log.warning(
                        "    pamConfig link for %s failed: %s — record exists "
                        "but gateway can't route launches to it. Re-run "
                        "configure_rotation.py later to wire DAG.", uid, msg,
                    )

            # Phase 8.17 / 8.18.1 / 8.19.4: populate trafficEncryptionSeed
            # for any resource type that needs it. Web Vault gates Launch
            # button on this being non-empty. Per upstream
            # PAM_RESOURCES_RECORD_TYPES, all 4 launchable types share
            # the same field requirement.
            if (
                populate_traffic_seed
                and row["type"] in ("pamMachine", "pamDatabase", "pamDirectory", "pamRemoteBrowser")
                and uid
                and not dry_run
            ):
                seed_runner = (_traffic_seed_runner or _default_traffic_seed_runner)
                seed_value = _generate_traffic_encryption_seed()
                ok, msg = seed_runner(params, uid, seed_value)
                entry["traffic_seed"] = {"ok": ok, "error": msg if not ok else ""}
                if ok:
                    log.info("    populated trafficEncryptionSeed on %s", uid)
                else:
                    log.warning(
                        "    trafficEncryptionSeed update on %s failed: %s — "
                        "record exists but Launch button will be hidden in "
                        "Web Vault until field is populated.", uid, msg,
                    )

            # Phase 8.21: link pamUser(s) → resource via DAG edge.
            # Without this, Web Vault's Launch dialog shows "required
            # record not found" because connection.userRecords is just
            # an autofill hint; the DAG edge is what tells the gateway
            # "these pamUsers can authenticate to this resource."
            # Source of user UIDs:
            #   pamRemoteBrowser → pamRemoteBrowserSettings.connection.httpCredentialsUid (1 user)
            #   pamMachine / pamDatabase / pamDirectory → pamSettings.connection.userRecords (N users)
            # Mirrors upstream pam_import/edit.py:854 admin-user link
            # but extended to ALL share targets so multi-user resources
            # work too.
            if (
                link_pam_config_uid
                and row["type"] in ("pamMachine", "pamDatabase", "pamDirectory", "pamRemoteBrowser")
                and uid
                and not dry_run
            ):
                user_uids = _extract_user_uids_from_row_fields(row.get("fields") or {})
                if user_uids:
                    user_link_runner = (
                        _user_resource_link_runner or _default_user_resource_link_runner
                    )
                    ok, msg, wired = user_link_runner(
                        params, link_pam_config_uid, uid, user_uids
                    )
                    entry["user_resource_links"] = {
                        "ok": ok, "error": msg if not ok else "",
                        "wired": wired, "attempted": len(user_uids),
                    }
                    if ok and wired:
                        log.info(
                            "    wired %d pamUser→resource DAG edge(s) on %s",
                            wired, uid,
                        )
                    elif not ok:
                        log.warning(
                            "    pamUser→resource DAG wiring failed on %s: %s — "
                            "Launch button may show 'required record not found'. "
                            "Manual fix: tdag.link_user_to_resource for each "
                            "pamUser UID in this resource's userRecords.",
                            uid, msg,
                        )

            # Phase 8.23.1: emit labeled custom fields for records that
            # can't take them via record-add CLI (pamUser specifically).
            # Same in-process update_record pattern as Phase 8.17
            # trafficEncryptionSeed. The CLI's argparse trips on
            # c.text.<labels-with-spaces> for pamUser; this post-create
            # path bypasses argparse entirely.
            post_create_custom = row.get("post_create_custom_fields") or {}
            if post_create_custom and uid and not dry_run:
                try:
                    from keepercommander import api as _api  # type: ignore
                    from keepercommander import record_management as _rm
                    from keepercommander import vault as _vault
                    _api.sync_down(params)
                    rec = _vault.KeeperRecord.load(params, uid)
                    custom_list = list(getattr(rec, "custom", []) or [])
                    for label, value in post_create_custom.items():
                        # match by label (skip duplicates if rerun)
                        if any(getattr(c, "label", None) == label for c in custom_list):
                            continue
                        # Construct a TypedField-shaped custom field.
                        # Use new_field classmethod (verified-correct shape;
                        # the raw __init__ takes a dict not field_type kwargs).
                        from keepercommander.vault import TypedField  # type: ignore
                        custom_list.append(TypedField.new_field(
                            "text", [value], field_label=label,
                        ))
                    rec.custom = custom_list
                    _rm.update_record(params, rec)
                    entry["custom_fields_added"] = len(post_create_custom)
                    log.info(
                        "    added %d custom labeled field(s) on %s",
                        len(post_create_custom), uid,
                    )
                except Exception as exc:
                    # Phase 8.24 B2: surface to main()'s post_create_warnings
                    entry["custom_fields_error"] = str(exc)
                    log.warning(
                        "    post-create custom fields on %s failed: %s — "
                        "record exists but labeled fields not populated.",
                        uid, exc,
                    )

            # Phase 8.24 D1: entry was already appended above (right
            # after UID extraction). Post-create steps mutated it
            # in-place. Just bump the chunk counter + log.
            successful_in_chunk += 1
            log.info("[%d/%d] created %s %s (uid=%s)", idx, len(plan["rows"]), row["type"], row["title"], uid)
            # Phase 6.6: capture pamUser UID so a later pamRemoteBrowser
            # row for the same user gets httpCredentialsUid wired inline.
            if row["type"] == "pamUser" and uid and row.get("user"):
                user_key = f"{row.get('host', '')} :: {row['user']}"
                pamuser_uids[user_key] = uid
            if uid is None:
                # Phase 6 review M6: rc=0 but UID extraction returned None.
                # Don't silently persist a row that --rollback can't act on.
                log.warning(
                    "[%d/%d] %s %s: rc=0 but no 22-char UID found in output; "
                    "--rollback will skip this row. Snippet: %s",
                    idx,
                    len(plan["rows"]),
                    row["type"],
                    row["title"],
                    (stdout + " " + stderr).strip()[:200],
                )
        else:
            # Phase 6 review M5: synthetic exit codes from _default_runner
            # need surfacing — operator should see "binary missing" or
            # "timeout" called out, not a generic "rc=127".
            kind = {127: "keeper-binary-missing", 124: "subprocess-timeout"}.get(rc)
            log_entries.append(
                {
                    "idx": idx,
                    "type": row["type"],
                    "title": row["title"],
                    "result": "failed",
                    "exit_code": rc,
                    "failure_kind": kind,
                    "stderr": (stderr or stdout).strip()[:400],
                }
            )
            log.error(
                "[%d/%d] FAILED %s %s: rc=%d%s %s",
                idx,
                len(plan["rows"]),
                row["type"],
                row["title"],
                rc,
                f" ({kind})" if kind else "",
                (stderr or stdout).strip()[:200],
            )
        # Phase 6 review H1+L2: persist after every row so SIGKILL
        # mid-batch leaves --rollback with the UIDs created so far.
        if _persist_cb is not None:
            _persist_cb(
                {
                    "executed_at": _now_iso(),
                    "dry_run": dry_run,
                    "rows": list(log_entries),
                    "chunk_pauses": chunk_pauses,
                    "complete": False,
                }
            )
        # Chunk-pacing for MSP / cross-org rate limiters (mirrors
        # bootstrap_vault_records' --write-chunk-size logic).
        if chunk_size > 0 and successful_in_chunk >= chunk_size and idx < len(plan["rows"]):
            time.sleep(chunk_delay)
            chunk_pauses += 1
            successful_in_chunk = 0

    # Phase 8.10 + 8.13 redesign: folder-organization pass. Operator-side
    # visual grouping of VMs by exclusive principal. Recipient access is
    # already wired via record-share above (--share-mode "folder" runs
    # both passes; the folder pass is purely cosmetic in the operator's
    # vault). Multi-principal VMs stay in Resources because Keeper's
    # `mv` doesn't support folder-link semantics.
    folder_shares: List[Dict[str, Any]] = []
    do_folder_share = (
        not no_share
        and share_mode == "folder"
        and not dry_run
    )
    if do_folder_share:
        # Step 1: walk created VM rows, partition into exclusive vs shared.
        # exclusive_by_principal[alice] = [uid_of_VMs_only_alice_can_access]
        exclusive_by_principal: Dict[str, List[str]] = {}
        entries_by_idx = {e["idx"]: e for e in log_entries}
        for plan_idx, row in enumerate(plan["rows"], 1):
            if not row.get("vm"):
                continue
            entry = entries_by_idx.get(plan_idx)
            if not entry or entry.get("result") != "ok" or not entry.get("uid"):
                continue
            principals = row.get("share_principals") or []
            # Multi-principal VMs stay in Resources — moving would
            # force-pick one owner. Single-principal VMs are eligible
            # for folder-grouping.
            if len(principals) != 1:
                continue
            principal = principals[0]
            exclusive_by_principal.setdefault(principal, []).append(entry["uid"])

        # Step 2: per principal with exclusive VMs, create a personal
        # sub-folder under Resources and move the VMs into it.
        folder_share_runner = _folder_share_runner or _default_folder_share_runner
        for principal, uids in sorted(exclusive_by_principal.items()):
            ok, msg, folder_uid = folder_share_runner(
                params,
                resources_folder,
                principal,
                uids,
            )
            folder_shares.append({
                "principal": principal,
                "folder_uid": folder_uid,
                "record_count": len(uids),
                "ok": ok,
                "error": msg if not ok else "",
            })
            if ok:
                log.info(
                    "folder-organize: created '%s' (%d VMs moved from Resources)",
                    principal, len(uids),
                )
            else:
                if missing_users == "fail":
                    log.error(
                        "folder-organize for %r failed: %s — aborting per "
                        "--missing-users=fail. Records remain in Resources; "
                        "rollback by UID still works.", principal, msg,
                    )
                    return {
                        "executed_at": _now_iso(),
                        "dry_run": dry_run,
                        "rows": log_entries,
                        "folder_shares": folder_shares,
                        "chunk_pauses": chunk_pauses,
                        "complete": False,
                        "aborted_on": "folder_organize_failure",
                    }
                else:
                    log.warning(
                        "folder-organize for %r failed: %s — continuing "
                        "(--missing-users=%s); records remain in Resources.",
                        principal, msg, missing_users,
                    )

    out = {
        "executed_at": _now_iso(),
        "dry_run": dry_run,
        "rows": log_entries,
        "chunk_pauses": chunk_pauses,
        "complete": True,
    }
    if folder_shares:
        out["folder_shares"] = folder_shares
    return out


def _default_runner(argv: List[str], timeout: int) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired as e:
        return 124, "", str(e)


def _extract_uid(text: str) -> Optional[str]:
    """Phase 8.24 D7 + validation hardening: strictly anchored UID scan.
    `keeper record-add` prints the new record's UID as the sole token
    on its own line. Adversarial input (a VM whose name happens to be
    22 url-safe chars) could otherwise be matched as the UID, poisoning
    state.json. The legacy fallback (scan-any-token) was removed after
    validation surfaced it reintroduces the original attack on
    Commander versions whose output isn't strictly single-line."""
    for line in text.splitlines():
        tok = line.strip()
        if len(tok) == 22 and all(c.isalnum() or c in "_-" for c in tok):
            return tok
    return None


def execute_rollback(
    state: Dict[str, Any],
    *,
    yes: bool,
    audit_tag_override: Optional[str] = None,
    skip_audit_check: bool = False,
    _runner=None,
) -> Dict[str, Any]:
    """Remove records created by the last --execute run. Looks at
    state['pam_import']['execution']['rows'] for UIDs to delete.

    Phase 6 review M4: distinguishes "operator never ran --execute" from
    "operator ran --execute but no successful creates" — both used to
    return zeros with the same warning. `state["pam_import"]` absence
    now returns `not_run=True` so main() can map it to a distinct exit
    code (6, validation/usage error).

    Phase 6 review L1: `keeper rm` interactive mode prompts on stdin,
    which would hang under non-interactive callers. We always pass
    `--force`; refuse rollback without `--yes` so the operator
    explicitly opts in to non-interactive deletion.

    Deletion subcommand is `keeper rm` (NOT `keeper record-rm` — that
    name doesn't exist; an earlier code path silently no-op'd because
    Commander's argparse showed help on the unknown subcommand).
    Verified live during Stage 3g cleanup 2026-05-05.
    """
    runner = _runner or _default_runner

    if "pam_import" not in state:
        log.error(
            "no pam_import section in state file — --execute was never "
            "run for this state file. Nothing to roll back."
        )
        return {"rolled_back": 0, "failed": 0, "skipped_missing_uid": 0, "not_run": True}

    if not yes:
        log.error(
            "--rollback requires --yes (non-interactive deletion via "
            "`keeper rm -f`); without --yes the subprocess would block "
            "on a confirmation prompt."
        )
        return {"rolled_back": 0, "failed": 0, "skipped_missing_uid": 0, "refused_no_yes": True}

    last = state["pam_import"].get("execution") or {}
    rows = [r for r in (last.get("rows") or []) if r.get("result") == "ok"]
    folder_shares = last.get("folder_shares") or []
    if not rows and not folder_shares:
        log.warning("execute log present but contains zero successful creates; nothing to roll back.")
        return {"rolled_back": 0, "failed": 0, "skipped_missing_uid": 0}

    # Phase 8.24 D3 + validation hardening: audit-tag verification.
    # Match the `phase6:<target>` prefix that build_plan inserts into
    # each record's notes (substring on bare target could collide with
    # unrelated records sharing the prefix).
    # F2 hardening: prefer the operator-typed --audit-tag argv over
    # state.json's plan.target. argv lives outside the tampered state
    # an attacker can't reach via state-file write alone.
    audit_tag = None
    if audit_tag_override:
        audit_tag = f"phase6:{audit_tag_override}"
    else:
        plan_block = state.get("pam_import", {}).get("plan") or {}
        plan_target = plan_block.get("target")
        if plan_target:
            audit_tag = f"phase6:{plan_target}"

    # Fail-CLOSED: if no audit tag is available AND operator hasn't
    # explicitly opted-out via --rollback-skip-audit-check, refuse the
    # rollback. A tampered state.json that nullifies plan.target would
    # otherwise silently skip the check.
    if not audit_tag and not skip_audit_check:
        log.error(
            "rollback refused: no audit tag available (state.json's "
            "plan.target is missing and --audit-tag was not passed). "
            "Re-run with --audit-tag <value> (typed; must match the "
            "--target value of the original --execute run) OR with "
            "--rollback-skip-audit-check (accepts risk of tampered "
            "state.json nuking arbitrary records)."
        )
        return {"rolled_back": 0, "failed": 0, "skipped_missing_uid": 0, "refused_no_audit_tag": True}

    rolled_back = 0
    failed = 0
    skipped = 0
    deletions: List[Dict[str, Any]] = []
    for row in rows:
        uid = row.get("uid")
        if not uid:
            skipped += 1
            continue
        # Phase 8.24 D3 + validation hardening: verify the record's
        # notes contain the audit tag before deleting. `--rollback-
        # skip-audit-check` fully bypasses (operator opt-out, accepts
        # risk of tampered state.json nuking arbitrary records).
        if audit_tag and not skip_audit_check:
            verify_argv = [KEEPER_BIN, "--batch-mode", "get", uid]
            vrc, vstdout, vstderr = runner(verify_argv, timeout=30)
            if vrc != 0 or audit_tag not in (vstdout or ""):
                skipped += 1
                deletions.append({
                    "uid": uid, "title": row.get("title"),
                    "result": "skipped-audit-mismatch",
                })
                log.warning(
                    "rollback skipped %s (%s): audit tag %r not in record "
                    "notes (record may have been edited or state.json tampered)",
                    uid, row.get("title"), audit_tag,
                )
                continue
        # Always pass -f now that --yes is required upfront.
        # Subcommand is `rm` (positional UIDs); `--purge` would force-
        # delete for all users + share admins but requires the operator
        # to be a share admin — leaving it off so single-tenant rollback
        # works without elevated perms. Operator can re-run with --purge
        # via Web Vault if needed.
        argv = [KEEPER_BIN, "rm", "-f", uid]
        rc, stdout, stderr = runner(argv, timeout=_PER_RECORD_TIMEOUT_SECS)
        if rc == 0:
            rolled_back += 1
            deletions.append({"uid": uid, "title": row.get("title"), "result": "deleted"})
            log.info("rolled back %s (%s)", uid, row.get("title"))
        else:
            failed += 1
            deletions.append(
                {
                    "uid": uid,
                    "title": row.get("title"),
                    "result": "failed",
                    "stderr": (stderr or stdout).strip()[:200],
                }
            )
            log.error("rollback failed for %s: %s", uid, (stderr or stdout).strip()[:200])

    # Phase 8.24 D2: unwind operator-side folders created by
    # _default_folder_share_runner. Without this, principal-named
    # folders persist in the operator's vault and become attack surface
    # (a malicious vCenter principal name becomes a permanent folder).
    folders_removed = 0
    folders_failed = 0
    for fs in folder_shares:
        folder_uid = fs.get("folder_uid")
        if not folder_uid:
            continue
        # Use folder rmdir; identical permissioning to record rm.
        argv = [KEEPER_BIN, "rmdir", "-f", folder_uid]
        rc, stdout, stderr = runner(argv, timeout=_PER_RECORD_TIMEOUT_SECS)
        if rc == 0:
            folders_removed += 1
            log.info("rolled back folder %s (%s)", folder_uid, fs.get("principal", "?"))
        else:
            folders_failed += 1
            log.warning(
                "folder rollback failed for %s: %s",
                folder_uid, (stderr or stdout).strip()[:200],
            )

    return {
        "rolled_back": rolled_back,
        "failed": failed,
        "skipped_missing_uid": skipped,
        "deletions": deletions,
        "folders_removed": folders_removed,
        "folders_failed": folders_failed,
    }


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="esxi_pam_import.py",
        description=("Phase 6 Stage 3 — direct ESXi → Keeper PAM import (no KCM Docker stack required)."),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--state", required=True, help="discovery state file from `onboard_esxi.py discover`")

    # Phase 6 Stage 3d — kcm-import option parity.
    mutex = p.add_mutually_exclusive_group()
    mutex.add_argument(
        "--name", default=None, help="create a NEW pamConfig with this name (mutex with --config)"
    )
    mutex.add_argument(
        "--config", default=None, help="extend an EXISTING pamConfig with this name (mutex with --name)"
    )

    p.add_argument(
        "--groups",
        default=None,
        help="comma-separated include filter for hosts (wildcards: 'kvm*,esxi-prod*')",
    )
    p.add_argument("--exclude-groups", default=None, help="comma-separated exclude filter for hosts")
    p.add_argument(
        "--list-groups", action="store_true", help="list hosts that would be planned and exit (no writes)"
    )
    p.add_argument(
        "--include-root",
        action="store_true",
        help="include the ESXi `root` user as a pamUser "
        "(default: skip — operators rarely want to rotate root)",
    )
    p.add_argument(
        "--skip-vms",
        action="store_true",
        help="do NOT emit a pamMachine per discovered VM "
        "(default: emit — Phase 8.8). Use when only the ESXi host itself "
        "should land in PAM and VMs are managed elsewhere.",
    )
    # Phase 8.9 — share VM pamMachines with Keeper users matching ESXi
    # principals. Discovery captures `host_info.permissions` (list of
    # ESXiPermission grants); identity resolution maps ESXi user → Keeper
    # email; share emission calls keepercommander.api.share_record.
    p.add_argument(
        "--user-map",
        default=None,
        help="comma-separated ESXi → Keeper identity mapping (Phase 8.9). "
        "e.g. 'alice=alice@example.com,bob=bob@corp.com'. Takes precedence "
        "over --user-domain when both are set.",
    )
    p.add_argument(
        "--user-domain",
        default=None,
        help="default domain for ESXi-user → Keeper-user resolution (Phase 8.9). "
        "If --user-map doesn't list a principal, fall back to "
        "'<principal>@<user-domain>'. Without either flag, no sharing happens.",
    )
    p.add_argument(
        "--missing-users",
        choices=("skip", "fail", "invite"),
        default="skip",
        help="behaviour when a resolved Keeper user is not in the vault "
        "(Phase 8.9). 'skip' (default): warn and continue, record stays "
        "with operator only. 'fail': abort the run — useful on first runs "
        "to catch typos in --user-map. 'invite': enterprise-tenant only — "
        "send a Keeper invitation to the resolved email (NOT YET IMPLEMENTED; "
        "falls back to 'skip' with a warning).",
    )
    p.add_argument(
        "--no-share",
        action="store_true",
        help="kill switch: skip Keeper share_record calls entirely (Phase 8.9). "
        "Useful for dry-runs and for tenants where sharing isn't desired.",
    )
    p.add_argument(
        "--share-mode",
        choices=("record", "folder"),
        default="record",
        help="how to organize per-user VM access (Phase 8.10, redesigned "
        "in Phase 8.13 after L4 live-test surfaced that Keeper's mv has "
        "no link semantics). "
        "'record' (default): per-VM record-level share. Records stay in "
        "the flat Resources folder. Recipients see VMs in 'Shared with me'. "
        "'folder': record-shares fire identically PLUS a folder pass — "
        "for each principal whose ONLY VMs are exclusive to them, create "
        "an operator-side personal sub-folder named after the principal "
        "and MOVE the exclusive VMs into it. Multi-principal VMs stay "
        "in Resources. Recipient access is still via record-share; the "
        "folder structure is operator-side visual organization. "
        "Ignored when --no-share is set.",
    )
    p.add_argument(
        "--share-include-system-users",
        action="store_true",
        help="include ESXi system accounts (dcui, vpxuser, root) as "
        "share targets (Phase 8.12). Default excludes them — they have "
        "no human Keeper user counterpart and sharing fails at the API. "
        "Use only on tenants where these names are bound to real human "
        "Keeper users (rare).",
    )
    p.add_argument(
        "--vm-protocol-default",
        choices=("ssh", "rdp", "vnc", "telnet", "kubernetes"),
        default="ssh",
        help="default `connection.protocol` for VM pamMachines when guest "
        "OS doesn't match a known type (Phase 8.14a). Per-VM derivation "
        "from guest_id picks ssh/rdp/vnc automatically; this flag is the "
        "fallback when guest_id is empty or unrecognised.",
    )
    p.add_argument(
        "--host-record-type",
        choices=("pamMachine", "pamRemoteBrowser", "both"),
        default="pamMachine",
        help="Phase 8.19.3: what record(s) the ESXi host itself becomes. "
        "'pamMachine' (default) emits one SSH-protocol pamMachine for the host. "
        "'pamRemoteBrowser' emits a generic WebUI RBI (operator-supplied creds). "
        "'both' emits both. Per-user RBIs (controlled by --rbi-mode) are "
        "independent of this flag.",
    )
    p.add_argument(
        "--vm-record-type",
        default=None,
        help="Phase 8.19.4: per-VM override for record_type. Syntax: "
        "'vmname=pamDatabase,othervm=pamDirectory'. Without this flag, "
        "VM record_type is derived from the protocol via upstream "
        "PROTOCOL_TYPE_MAP (http→pamRemoteBrowser, mysql/postgres/"
        "sql-server→pamDatabase, default→pamMachine). Allowed values: "
        "pamMachine, pamDatabase, pamDirectory, pamRemoteBrowser.",
    )
    p.add_argument(
        "--share-scope",
        choices=("permissions", "all"),
        default="permissions",
        help="Phase 8.19.5: WHAT goes into each user's shares. "
        "'permissions' (default): each user gets only the VMs they "
        "have ESXi access to (per role + minimum-role filter). "
        "'all': every (filtered) user gets every VM resource. "
        "Identity-bound records (pamUser, per-user pamRemoteBrowser) "
        "are unaffected — always 1:1 owner.",
    )
    p.add_argument(
        "--minimum-role",
        choices=("admin", "vm-user", "readonly"),
        default="vm-user",
        help="Phase 8.19.5 / 8.24 D6: minimum ESXi role a user must "
        "have to appear in resource shares. 'admin' (strict): ESXi "
        "admins only. 'vm-user' (DEFAULT, recommended): admins + "
        "VirtualMachineUser. 'readonly' (permissive): all users with "
        "any role — note that ReadOnly users would see records they "
        "can't actually launch into.",
    )
    p.add_argument(
        "--include-host-share",
        choices=("always", "by-permissions", "never"),
        default="by-permissions",
        help="Phase 8.19.5: whether the ESXi host record(s) get shared. "
        "'always': share host record with every (filtered) user. "
        "'by-permissions' (default): share only with users who have a "
        "role on the host entity itself. 'never': operator owns the "
        "host record(s); no share.",
    )
    p.add_argument(
        "--vm-primary-user",
        choices=("dominant-permission", "broadcast", "none"),
        default="dominant-permission",
        help="Phase 8.23: which pamUser(s) the VM's Launch button "
        "picks by default (autofill creds). 'dominant-permission' "
        "(default): pick the highest-ESXi-role user per VM (tie-break "
        "alphabetical); one Launch-button default per VM. "
        "'broadcast': every share-with user is a valid Launch creds "
        "candidate (multi-option picker). 'none': empty userRecords; "
        "operator supplies creds at Launch via allowSupplyUser. "
        "Decoupled from --share-scope: sharing = who SEES; "
        "primary-user = whose creds AUTOFILL.",
    )
    p.add_argument(
        "--folder-from",
        choices=("none", "user", "role"),
        default="none",
        help="Phase 8.19.6: how to organise records into folders. "
        "'none' (default): no auto-folder. Use --auto-folder + "
        "--share-mode for explicit control. "
        "'user': equivalent to --share-mode folder — per-user personal "
        "folders containing exclusively-owned records (operator-side "
        "organization; recipients see records via record-share). "
        "'role': folder per ESXi role (Admin / VirtualMachineUser / "
        "etc.) with users as members — requires shared-folder API "
        "(deferred; raises NotImplementedError today with operator "
        "manual-setup guidance).",
    )
    p.add_argument(
        "--no-traffic-seed",
        action="store_true",
        help="suppress the post-creation update_record that populates "
        "pamMachine.trafficEncryptionSeed (Phase 8.17). Web Vault hides "
        "the Launch button when this field is empty, so the default ON "
        "is correct for launchable records. Use --no-traffic-seed only "
        "if the operator wants to set the seed manually post-import or "
        "if the in-process update_record path errors on this tenant.",
    )
    p.add_argument(
        "--link-pam-config-uid",
        default=None,
        type=lambda v: _validate_uid("link-pam-config-uid", v),
        help="UID of the pamConfig record that owns the gateway routing "
        "for these resources (Phase 8.14d). When set, after each "
        "pamMachine is created, the toolchain wires a DAG edge "
        "`pamConfig → pamMachine` via `set_resource_allowed` with "
        "rotation/connections/tunneling/session_recording/typescript_"
        "recording/remote_browser_isolation all enabled. Without this, "
        "the gateway has no route to launch sessions against the "
        "imported records — recipients see them but Launch fails. "
        "Operator-supplied (no name lookup); resolve the UID via "
        "`scripts/list_pam_configs.py` first.",
    )
    p.add_argument(
        "--rbi",
        choices=("from-state", "none", "per-host", "per-user"),
        default="from-state",
        help="override RBI mode (default: read from state file)",
    )
    p.add_argument(
        "--folder",
        default=None,
        help="shared-folder path or UID for created records "
        "(recommended: a dedicated test folder so cleanup is "
        "`keeper rm --folder` on the folder, not per record)",
    )
    p.add_argument(
        "--target",
        type=_validate_target,
        default=None,
        help="audit tag stamped into every record's notes field; "
        "gates --rollback. Convention <owner>:<scope> "
        "(e.g. 'demolab:ec2-se')",
    )

    # Phase 8.7 — Users/Resources folder split. Three modes:
    # (1) --auto-folder PROJECT: resolve or create `PROJECT - Users` +
    #     `PROJECT - Resources` and route by type.
    # (2) --users-folder UID + --resources-folder UID: operator-supplied UIDs.
    # (3) Neither: legacy single --folder behaviour.
    # Mutex enforcement: validated in main() — argparse mutex groups can't
    # hold "both A AND B vs C" cleanly, so we hand-roll the check.
    p.add_argument(
        "--auto-folder",
        default=None,
        metavar="PROJECT",
        help="auto-create or reuse the kcm-import-style 3-level structure "
             "`<PROJECT>/`, `<PROJECT>/<PROJECT> - Users`, "
             "`<PROJECT>/<PROJECT> - Resources` and route pamUser → Users, "
             "pamMachine + pamRemoteBrowser → Resources. Mutex with "
             "--users-folder / --resources-folder / --folder.",
    )
    p.add_argument(
        "--auto-folder-parent",
        default=None,
        metavar="UID",
        help="optional parent folder UID under which the --auto-folder "
             "structure is created. Default: vault root. Lets operators "
             "nest projects (e.g. all ESXi projects under one parent).",
    )
    p.add_argument(
        "--users-folder",
        default=None,
        help="UID of the folder pamUser/pamDirectory records go into "
             "(Phase 8.7 split). Pair with --resources-folder.",
    )
    p.add_argument(
        "--resources-folder",
        default=None,
        help="UID of the folder pamMachine/pamRemoteBrowser/pamDatabase "
             "records go into (Phase 8.7 split). Pair with --users-folder.",
    )

    p.add_argument("--execute", action="store_true", help="actually create records (default: dry-run)")
    p.add_argument("--yes", action="store_true", help="non-interactive batch mode (suppresses confirmation)")
    p.add_argument(
        "--rollback",
        action="store_true",
        help="delete records this run created (uses state's execution log + audit tag)",
    )
    p.add_argument(
        "--audit-tag",
        default=None,
        help="Phase 8.24 D3 hardening: operator-provided audit tag for "
        "--rollback. When set, the rollback path uses THIS value (typed "
        "into argv) as the audit-tag check instead of reading "
        "state.json's plan.target. Mitigates the 'tampered state.json "
        "→ arbitrary keeper rm' pivot. Use the same value you passed "
        "via --target on the original --execute run.",
    )
    p.add_argument(
        "--rollback-skip-audit-check",
        action="store_true",
        help="Phase 8.24 D3 escape hatch: bypass audit-tag verification "
        "on rollback. Use only when the records were created without a "
        "--target tag OR when `keeper get` is failing for non-auth "
        "reasons (rate-limit, network). Operator accepts the risk that "
        "a tampered state.json could nuke arbitrary records.",
    )

    # Plan output formats.
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="emit the plan as JSON to stdout")
    out.add_argument("--csv", action="store_true", help="emit the plan as CSV to stdout")
    p.add_argument(
        "--output",
        default=None,
        help="write plan output to this file instead of stdout (works with --json / --csv / table)",
    )

    # Throttling.
    p.add_argument(
        "--auto-throttle",
        action="store_true",
        help="enable adaptive throttling (placeholder for parity "
        "with kcm-import; today --write-chunk-* is the actual "
        "throttle)",
    )
    p.add_argument(
        "--write-chunk-size",
        type=int,
        default=0,
        help="pace record-add by sleeping --write-chunk-delay after every N successful creates",
    )
    p.add_argument("--write-chunk-delay", type=float, default=0.0, help="seconds to sleep between chunks")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_argparser().parse_args(argv)

    try:
        state = load_state(args.state)
    except RuntimeError as exc:
        log.error(str(exc))
        return 7

    if args.rollback:
        result = execute_rollback(
            state,
            yes=args.yes,
            audit_tag_override=args.audit_tag,
            skip_audit_check=args.rollback_skip_audit_check,
        )
        # Phase 6 review M4 + L1 — distinct exit codes.
        if result.get("not_run"):
            return 6  # never-ran: usage error
        if result.get("refused_no_yes"):
            return 6  # refused without --yes: usage error
        log.info(
            "rollback summary: %d rolled back / %d failed / %d skipped (missing uid)",
            result["rolled_back"],
            result["failed"],
            result["skipped_missing_uid"],
        )
        return 0 if result["failed"] == 0 else 5

    try:
        user_map = parse_user_map(args.user_map)
    except RuntimeError as exc:
        log.error("%s", exc)
        return 6

    plan = build_plan(
        state,
        rbi_mode=args.rbi,
        include_root=args.include_root,
        include_vms=not args.skip_vms,
        user_map=user_map,
        user_domain=args.user_domain,
        share_include_system_users=args.share_include_system_users,
        vm_protocol_default=args.vm_protocol_default,
        target=args.target,
        groups=(args.groups.split(",") if args.groups else None),
        exclude_groups=(args.exclude_groups.split(",") if args.exclude_groups else None),
        host_record_type=args.host_record_type,
        vm_record_type_overrides=parse_vm_record_type(args.vm_record_type),
        share_scope=args.share_scope,
        minimum_role=args.minimum_role,
        include_host_share=args.include_host_share,
        vm_primary_user=args.vm_primary_user,
    )

    if args.list_groups:
        # Single-host scope today; print the host(s) the planner would touch.
        hosts = sorted(set(r.get("host", "") for r in plan["rows"]))
        for h in hosts:
            print(h)
        return 0

    if args.json:
        body = json.dumps(plan, indent=2, sort_keys=True) + "\n"
    elif args.csv:
        body = format_plan_csv(plan)
    else:
        body = format_plan_table(plan)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fp:
            fp.write(body)
        log.info("plan written to %s", args.output)
    else:
        sys.stdout.write(body)

    # Phase 8.7 — folder-flag validation runs BEFORE the dry-run early
    # return so operator gets immediate feedback on invalid combinations
    # without having to re-run with --execute.
    users_folder_uid = args.users_folder
    resources_folder_uid = args.resources_folder
    if bool(users_folder_uid) != bool(resources_folder_uid):
        log.error("--users-folder and --resources-folder must be set together")
        return 2
    if args.auto_folder and (users_folder_uid or resources_folder_uid or args.folder):
        log.error("--auto-folder is mutually exclusive with --folder / --users-folder / --resources-folder")
        return 2
    if (users_folder_uid or resources_folder_uid) and args.folder:
        log.error("--users-folder/--resources-folder and --folder are mutually exclusive")
        return 2

    if not args.execute:
        log.info(
            "dry-run: %d row(s) would be created. Re-run with --execute to apply.", plan["summary"]["total"]
        )
        if args.auto_folder:
            parent_label = args.auto_folder_parent or "<vault root>"
            log.info("--auto-folder %r: would resolve or create 3-level "
                     "structure under %s — wrapper '%s/' + "
                     "'%s/%s - Users' + '%s/%s - Resources'",
                     args.auto_folder, parent_label,
                     args.auto_folder, args.auto_folder, args.auto_folder,
                     args.auto_folder, args.auto_folder)
        elif users_folder_uid and resources_folder_uid:
            log.info("--users-folder %s + --resources-folder %s: "
                     "rows will be type-routed (pamUser → users, "
                     "pamMachine/pamRemoteBrowser → resources)",
                     users_folder_uid, resources_folder_uid)
        return 0

    # Live --execute path: resolve --auto-folder if set.
    if args.auto_folder:
        from _keeper_session import load_session
        params = load_session()
        users_folder_uid, resources_folder_uid = resolve_or_create_project_folders(
            params, args.auto_folder,
            parent_folder_uid=args.auto_folder_parent,
            create_if_missing=True,
        )
        if not users_folder_uid or not resources_folder_uid:
            log.error("--auto-folder failed to resolve/create folders for %r "
                      "(parent=%r)", args.auto_folder, args.auto_folder_parent)
            return 4
        log.info("--auto-folder %r resolved: Users=%s, Resources=%s "
                 "(parent=%s)", args.auto_folder, users_folder_uid,
                 resources_folder_uid, args.auto_folder_parent or "<vault root>")

    # Execute.
    # Phase 6 review H1+L2: incremental persist after every row so a
    # SIGKILL mid-batch leaves --rollback with the UIDs created so far.
    state.setdefault("pam_import", {})["plan"] = plan

    def _persist_cb(execution: Dict[str, Any]) -> None:
        # Phase 8.24 S3: strip sensitive fields from the persisted plan +
        # execution log. share_user_map (principal→email) and
        # post_create_custom_fields (Full Name / Role / Access Mode)
        # together reconstruct the org's ESXi RBAC map cross-referenced to
        # Keeper identities — a richer target than the vault itself for an
        # operator-box compromise. The data is computed on-the-fly each
        # run; nothing downstream (--rollback, --rb-resume) reads it from
        # disk, so dropping it is loss-less.
        execution = _strip_sensitive_from_execution(execution)
        state["pam_import"]["execution"] = execution
        if "plan" in state.get("pam_import", {}):
            state["pam_import"]["plan"] = _strip_sensitive_from_plan(
                state["pam_import"]["plan"]
            )
        _atomic_write_state(args.state, state)

    # Phase 8.9 + 8.14d: load Commander session when sharing OR pamConfig
    # linking is requested. The share_record API and the wire_rotation_graph
    # DAG primitive both need an authenticated `params`; the legacy
    # subprocess path (record-add) doesn't.
    share_params = None
    plan_has_shares = any(r.get("share_with") for r in plan["rows"])
    needs_session = (
        (plan_has_shares and not args.no_share)
        or args.link_pam_config_uid
        or not args.no_traffic_seed  # Phase 8.17: seed update needs session
    )
    if needs_session:
        try:
            from _keeper_session import load_session
            share_params = load_session()
        except Exception as exc:
            log.error(
                "share path or --link-pam-config-uid requires an active "
                "Keeper session (loaded via _keeper_session.load_session()); "
                "failed: %s. Re-run with --no-share + omit "
                "--link-pam-config-uid to bypass, or `! keeper login` "
                "to refresh the session.", exc
            )
            return 3

        # Guardrail (memory: reference_keeper_pam_dag_contract.md):
        # --link-pam-config-uid MUST point at a real pamConfig type, not
        # a KSM Application or other record. Wiring DAG to the wrong
        # type silently succeeds but produces non-launchable records.
        if args.link_pam_config_uid:
            try:
                from keepercommander import api, vault  # type: ignore
                # load_session() doesn't sync_down — cache may be empty.
                api.sync_down(share_params)
                rec = vault.KeeperRecord.load(share_params, args.link_pam_config_uid)
                rt = (getattr(rec, "record_type", "") or "").strip()
                _PAM_CONFIG_TYPES = {
                    "pamNetworkConfiguration",
                    "pamAwsConfiguration",
                    "pamAzureConfiguration",
                    "pamConfig",  # legacy
                }
                if rt not in _PAM_CONFIG_TYPES:
                    log.error(
                        "--link-pam-config-uid %s is record_type=%r — NOT a "
                        "pamConfig. Valid types: %s. Common confusion: "
                        "record_type='app' is a KSM Application, not a "
                        "pamConfig. Find real pamConfigs with: keeper "
                        "search --record-type pamNetworkConfiguration",
                        args.link_pam_config_uid, rt or "(unknown)",
                        sorted(_PAM_CONFIG_TYPES),
                    )
                    return 3
            except Exception as exc:
                log.error(
                    "Could not validate --link-pam-config-uid %s: %s",
                    args.link_pam_config_uid, exc,
                )
                return 3

    result = execute_plan(
        plan,
        folder=args.folder,
        yes=args.yes,
        chunk_size=args.write_chunk_size,
        chunk_delay=args.write_chunk_delay,
        dry_run=False,
        _persist_cb=_persist_cb,
        users_folder=users_folder_uid,
        resources_folder=resources_folder_uid,
        params=share_params,
        missing_users=args.missing_users,
        no_share=args.no_share,
        share_mode=_resolve_share_mode_from_folder_from(args.folder_from, args.share_mode),
        link_pam_config_uid=args.link_pam_config_uid,
        populate_traffic_seed=not args.no_traffic_seed,
    )
    # Final write — flips complete=True.
    # Phase 8.24 S3 + validation hardening: also strip on the
    # post-execute final write (not just incremental persist_cb).
    state["pam_import"]["execution"] = _strip_sensitive_from_execution(result)
    if "plan" in state.get("pam_import", {}):
        state["pam_import"]["plan"] = _strip_sensitive_from_plan(
            state["pam_import"]["plan"]
        )
    _atomic_write_state(args.state, state)
    failed = sum(1 for r in result["rows"] if r["result"] == "failed")
    ok = sum(1 for r in result["rows"] if r["result"] == "ok")
    log.info(
        "execute summary: %d ok / %d failed / %d total (%d chunk pauses)",
        ok,
        failed,
        len(result["rows"]),
        result["chunk_pauses"],
    )

    # Phase 8.20 + 8.24 B2: print the structured kcm-import-style report.
    # Collect half-success post-create failures (records created but a
    # downstream wiring step failed) and surface them as warnings — without
    # this the operator sees "all green" on a run with broken DAG state.
    post_create_warnings: List[str] = []
    for r in result.get("rows", []):
        title = r.get("title", "?")
        for key in ("pam_config_link", "traffic_seed", "user_resource_links"):
            sub = r.get(key) or {}
            if sub and sub.get("ok") is False:
                post_create_warnings.append(
                    f"{key} failed on {title}: {sub.get('error') or 'unknown'}"
                )
        if r.get("custom_fields_error"):
            post_create_warnings.append(
                f"post-create custom fields failed on {title}: {r['custom_fields_error']}"
            )
    report = build_import_report(
        plan,
        result,
        pam_config_uid=args.link_pam_config_uid,
        extra_warnings=post_create_warnings or None,
    )
    print(report)

    if failed and ok:
        return 5
    if failed and not ok:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())


# =============================================================================
# In-process record creator — replaces `keeper record-add` subprocess
# =============================================================================
#
# The standalone tool uses subprocess `keeper record-add` to create records.
# From within the Commander REPL we use the in-process API: construct a
# `vault.TypedRecord`, populate its fields from our row dict, then call
# `record_management.add_record_to_folder(params, record, folder_uid)`.
#
# This closes Phase 8.24 S1 by construction — no argv at all means nothing
# `ps`-visible. It also avoids `feedback_keeper_cli_lockout.md` (no nested
# `keeper` subprocess from inside the REPL's authenticated session).


def _create_record_in_process(
    params, row: Dict[str, Any], folder_uid: Optional[str],
) -> Tuple[Optional[str], str, str]:
    """In-process replacement for the subprocess `keeper record-add` path.

    Returns the runner-compatible (rc, stdout, stderr) tuple so the
    existing execute_plan loop can consume it unchanged. rc=0 + uid
    embedded in stdout (one token per line) → upstream's _extract_uid
    picks it up.

    Field translation:
      - `c.text.<label>` keys → custom TypedField (type='text', label=<label>)
      - `$JSON:<json>` string values → parsed to dict/list, set as field value[0]
      - everything else → typed field whose type name is the dict key
    """
    try:
        from ... import vault, record_management  # type: ignore
    except ImportError as exc:
        return 1, "", f"vault/record_management import failed: {exc}"

    fields = row.get("fields") or {}
    rec = vault.TypedRecord()
    rec.type_name = row.get("type") or "pamMachine"
    rec.title = row.get("title") or ""

    for key, value in fields.items():
        if key == "notes":
            rec.notes = str(value)
            continue

        if key.startswith("c.text."):
            label = key[len("c.text."):]
            rec.custom.append(
                vault.TypedField.new_field(
                    "text", [value] if not isinstance(value, list) else value,
                    field_label=label,
                )
            )
            continue

        # $JSON: prefix → parse to native dict/list
        if isinstance(value, str) and value.startswith("$JSON:"):
            try:
                parsed = json.loads(value[len("$JSON:"):])
            except Exception as exc:
                return 1, "", f"failed to parse $JSON: for {key!r}: {exc}"
            rec.fields.append(
                vault.TypedField.new_field(key, [parsed])
            )
            continue

        # Plain typed field
        wrapped = value if isinstance(value, list) else [value]
        rec.fields.append(vault.TypedField.new_field(key, wrapped))

    try:
        record_management.add_record_to_folder(params, rec, folder_uid=folder_uid)
    except Exception as exc:
        return 1, "", f"add_record_to_folder failed: {exc}"

    uid = rec.record_uid or ""
    if not uid:
        return 1, "", "record created but record_uid was not assigned"

    # Match the subprocess output shape: UID on its own line so the
    # existing _extract_uid (which now requires line-only tokens per
    # Phase 8.24 D7) picks it up unchanged.
    stdout = f"created in-process\n{uid}\n"
    return 0, stdout, ""


def execute_rollback_in_process(
    params,
    state: Dict[str, Any],
    *,
    yes: bool,
    audit_tag_override: Optional[str] = None,
    skip_audit_check: bool = False,
) -> Dict[str, Any]:
    """In-process rollback for the upstream Command. Mirrors the
    standalone tool's `execute_rollback` but uses `api.delete_record`
    + `vault.KeeperRecord.load` instead of subprocessing `keeper rm`
    and `keeper get` (closes the same lockout-risk vector S1/L1
    closed for record creation).

    Returns the same shape as the standalone tool's execute_rollback.
    """
    try:
        from ... import api, vault  # type: ignore
        from ..folder import FolderRemoveCommand  # type: ignore
    except ImportError as exc:
        return {"rolled_back": 0, "failed": 0, "skipped_missing_uid": 0,
                "deletions": [], "import_error": str(exc)}

    if "pam_import" not in state:
        return {"rolled_back": 0, "failed": 0, "skipped_missing_uid": 0,
                "not_run": True}
    if not yes:
        return {"rolled_back": 0, "failed": 0, "skipped_missing_uid": 0,
                "refused_no_yes": True}

    last = state["pam_import"].get("execution") or {}
    rows = [r for r in (last.get("rows") or []) if r.get("result") == "ok"]
    folder_shares = last.get("folder_shares") or []
    if not rows and not folder_shares:
        return {"rolled_back": 0, "failed": 0, "skipped_missing_uid": 0,
                "deletions": []}

    # Audit-tag: prefer operator argv over state.json (per Phase 8.24 D3).
    audit_tag = None
    if audit_tag_override:
        audit_tag = f"phase6:{audit_tag_override}"
    else:
        plan_block = state.get("pam_import", {}).get("plan") or {}
        plan_target = plan_block.get("target")
        if plan_target:
            audit_tag = f"phase6:{plan_target}"
    if not audit_tag and not skip_audit_check:
        return {"rolled_back": 0, "failed": 0, "skipped_missing_uid": 0,
                "refused_no_audit_tag": True}

    rolled_back = 0
    failed = 0
    skipped = 0
    deletions: List[Dict[str, Any]] = []
    api.sync_down(params)

    for row in rows:
        uid = row.get("uid")
        if not uid:
            skipped += 1
            continue
        # Audit-tag verify via in-process load (no subprocess).
        if audit_tag and not skip_audit_check:
            try:
                rec = vault.KeeperRecord.load(params, uid)
                notes = getattr(rec, "notes", "") or ""
                if audit_tag not in notes:
                    skipped += 1
                    deletions.append({"uid": uid, "title": row.get("title"),
                                      "result": "skipped-audit-mismatch"})
                    continue
            except Exception as exc:
                skipped += 1
                deletions.append({"uid": uid, "title": row.get("title"),
                                  "result": "skipped-load-failed",
                                  "error": str(exc)})
                continue
        try:
            api.delete_record(params, uid)
            rolled_back += 1
            deletions.append({"uid": uid, "title": row.get("title"),
                              "result": "deleted"})
        except Exception as exc:
            failed += 1
            deletions.append({"uid": uid, "title": row.get("title"),
                              "result": "failed", "error": str(exc)})

    # Folder unwind — per Phase 8.24 D2. Use in-process FolderRemoveCommand.
    folders_removed = 0
    folders_failed = 0
    for fs in folder_shares:
        folder_uid = fs.get("folder_uid")
        if not folder_uid:
            continue
        try:
            FolderRemoveCommand().execute(params, force=True, quiet=True,
                                          pattern=[folder_uid])
            folders_removed += 1
        except Exception:
            folders_failed += 1

    return {
        "rolled_back": rolled_back,
        "failed": failed,
        "skipped_missing_uid": skipped,
        "deletions": deletions,
        "folders_removed": folders_removed,
        "folders_failed": folders_failed,
    }


# =============================================================================
# Upstream Commander integration — `pam project esxi-import`
# =============================================================================
#
# The Command class below wraps the existing module-level functions (build_plan,
# execute_plan, build_import_report, _retry_with_jitter, etc.) so the same
# logic that powers the standalone `jlima8900/esxi-pam-rotation` tool surfaces
# inside the Keeper Commander REPL as `pam project esxi-import`.
#
# Status: read-only path (discovery + plan + report) is wired end-to-end.
# Apply path (record creation + DAG wiring) raises NotImplementedError;
# the subprocess `keeper record-add` runner inside execute_plan must be
# replaced with in-process `record_management.add_record_to_folder` calls
# (no subprocess from inside the REPL — would trip lockout risk per
# feedback_keeper_cli_lockout.md). See PORT_STATUS.md for the remaining work.

import os as _os

from ..base import Command  # type: ignore  # noqa: E402
from ...error import CommandError  # type: ignore  # noqa: E402


class PAMProjectESXiImportCommand(Command):
    """`pam project esxi-import` — discover a VMware ESXi host and
    import its inventory (host + VMs + local users) as Keeper PAM
    records. Mirrors `pam project kcm-import` design and reporting.

    See `pam_import/ESXI_IMPORT.md` for the operator guide."""

    parser = argparse.ArgumentParser(
        prog="pam project esxi-import",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Discover an ESXi host via SOAP/pyvmomi and create "
        "pamMachine + pamUser + pamRemoteBrowser records.",
        epilog="""
Examples:
  # Dry-run preview against an ESXi host (no vault writes)
  pam project esxi-import \\
      --host esxi-01.example.com --user root --password-env ESXI_PWD \\
      --pam-config-uid <UID> --dry-run

  # Apply (creates records + wires DAG + writes labeled custom fields)
  ESXI_PWD='...' pam project esxi-import \\
      --host esxi-01.example.com --user root --password-env ESXI_PWD \\
      --pam-config-uid <UID> --auto-folder "ESXi - esxi-01" \\
      --target "ops:esxi-01" --yes

  # Roll back the previous run
  pam project esxi-import --rollback \\
      --state-file ~/.cache/commander/pam_import/esxi-01.example.com.state.json \\
      --audit-tag "ops:esxi-01" --yes

Operator-option matrix and full semantics:
  keepercommander/commands/pam_import/ESXI_IMPORT.md
""",
    )
    # Discovery target
    parser.add_argument("--host", help="ESXi host FQDN or IP")
    parser.add_argument("--user", help="ESXi user (read access to inventory)")
    parser.add_argument(
        "--password-env",
        dest="password_env",
        help="env var holding the ESXi password (never pass on argv)",
    )
    # PAM wiring
    parser.add_argument(
        "--pam-config-uid",
        dest="pam_config_uid",
        help="UID of the pamNetworkConfiguration (required for apply)",
    )
    # Record-shape flags (Phase 8.19+)
    parser.add_argument(
        "--host-record-type",
        choices=("pamMachine", "pamRemoteBrowser", "both"),
        default="pamMachine",
    )
    parser.add_argument("--vm-record-type", default=None,
                        help="per-VM record_type override: vm1=pamDatabase,...")
    parser.add_argument(
        "--share-scope", choices=("permissions", "all"), default="permissions",
    )
    parser.add_argument(
        "--minimum-role",
        choices=("admin", "vm-user", "readonly"),
        default="vm-user",
    )
    parser.add_argument(
        "--include-host-share",
        choices=("always", "by-permissions", "never"),
        default="by-permissions",
    )
    parser.add_argument(
        "--vm-primary-user",
        choices=("dominant-permission", "broadcast", "none"),
        default="dominant-permission",
    )
    parser.add_argument(
        "--folder-from", choices=("none", "user", "role"), default="none",
    )
    parser.add_argument(
        "--rbi-mode", choices=("none", "per-host", "per-user"), default="none",
    )
    parser.add_argument(
        "--user-map", default=None,
        help="esxi-principal=keeper-email,...",
    )
    parser.add_argument("--user-domain", default=None)
    parser.add_argument("--target", default=None,
                        help="audit tag stamped into record notes")
    parser.add_argument("--auto-folder", default=None)
    parser.add_argument("--folder", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true")
    # Rollback path
    parser.add_argument("--rollback", action="store_true")
    parser.add_argument("--state-file", default=None,
                        help="for --rollback: path to the state file written "
                             "by a prior apply run")
    parser.add_argument("--audit-tag", default=None,
                        help="for --rollback: operator-typed audit tag "
                             "(defeats tampered-state pivot)")
    parser.add_argument("--rollback-skip-audit-check", action="store_true")

    def get_parser(self):
        return PAMProjectESXiImportCommand.parser

    def execute(self, params, **kwargs):
        """Discover → plan → (dry-run: print + return) / (apply: TODO).

        Apply path is not yet wired to in-process record creation;
        operators who need apply today should use the standalone
        `jlima8900/esxi-pam-rotation` tool until PORT_STATUS.md's
        remaining items land."""
        host = kwargs.get("host")
        user = kwargs.get("user")
        password_env = kwargs.get("password_env")
        pam_config_uid = kwargs.get("pam_config_uid")
        rollback = kwargs.get("rollback", False)

        if rollback:
            state_file = kwargs.get("state_file")
            if not state_file:
                raise CommandError("esxi-import",
                    "--rollback requires --state-file <path>")
            try:
                state = load_state(state_file)
            except RuntimeError as exc:
                raise CommandError("esxi-import", str(exc))
            result = execute_rollback_in_process(
                params, state,
                yes=kwargs.get("yes", False),
                audit_tag_override=kwargs.get("audit_tag"),
                skip_audit_check=kwargs.get("rollback_skip_audit_check", False),
            )
            if result.get("refused_no_yes"):
                raise CommandError("esxi-import",
                    "--rollback requires --yes (non-interactive deletion)")
            if result.get("refused_no_audit_tag"):
                raise CommandError("esxi-import",
                    "rollback refused: no audit tag available. Re-run with "
                    "--audit-tag <value> (must match --target of the original "
                    "apply run) OR --rollback-skip-audit-check.")
            if result.get("not_run"):
                raise CommandError("esxi-import",
                    "state file has no pam_import section — apply was never run")
            print(f"rollback summary: {result['rolled_back']} rolled back / "
                  f"{result['failed']} failed / "
                  f"{result['skipped_missing_uid']} skipped (missing uid or "
                  f"audit-tag mismatch); folders: "
                  f"{result.get('folders_removed', 0)} removed / "
                  f"{result.get('folders_failed', 0)} failed")
            return

        if not host or not user or not password_env:
            raise CommandError(
                "esxi-import",
                "--host, --user, and --password-env are required for apply. "
                "Run with --help for the full operator matrix.",
            )

        # Pull ESXi password from env (never argv).
        esxi_password = _os.environ.get(password_env or "")
        if not esxi_password:
            raise CommandError(
                "esxi-import",
                f"env var {password_env!r} is unset or empty. "
                "Export it before invoking the command "
                "(e.g. `export ESXI_PWD=...`).",
            )

        # Discover (conditional pyvmomi import inside the discovery module).
        try:
            from .esxi_discovery import ESXiDiscovery, PYVMOMI_AVAILABLE  # type: ignore
        except ImportError as exc:
            raise CommandError(
                "esxi-import",
                f"esxi_discovery module import failed: {exc}",
            )
        if not PYVMOMI_AVAILABLE:
            raise CommandError(
                "esxi-import",
                "pyvmomi is required for ESXi discovery. "
                "Install with: pip install 'keepercommander[esxi]' "
                "or pip install pyvmomi",
            )

        discovery = ESXiDiscovery()
        try:
            host_info = discovery.discover_all(host, user, esxi_password)
        except Exception as exc:
            raise CommandError("esxi-import",
                f"discovery against {host}:443 failed: {exc}")
        finally:
            try:
                discovery.disconnect()
            except Exception:
                pass

        # Build the in-memory state shape that build_plan expects.
        state = {
            "host": host,
            "discovery": {
                "esxi_host_info": discovery.to_dict(host_info),
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "options": {"rbi": kwargs.get("rbi_mode", "none")},
            },
        }

        try:
            user_map = parse_user_map(kwargs.get("user_map"))
            vm_record_type_overrides = parse_vm_record_type(
                kwargs.get("vm_record_type"))
        except RuntimeError as exc:
            raise CommandError("esxi-import", str(exc))

        plan = build_plan(
            state,
            rbi_mode=kwargs.get("rbi_mode", "none"),
            user_map=user_map,
            user_domain=kwargs.get("user_domain"),
            target=kwargs.get("target"),
            host_record_type=kwargs.get("host_record_type", "pamMachine"),
            vm_record_type_overrides=vm_record_type_overrides,
            share_scope=kwargs.get("share_scope", "permissions"),
            minimum_role=kwargs.get("minimum_role", "vm-user"),
            include_host_share=kwargs.get("include_host_share", "by-permissions"),
            vm_primary_user=kwargs.get("vm_primary_user", "dominant-permission"),
        )

        # Always print the plan table — operator-visible audit.
        print(format_plan_table(plan))

        if plan.get("warnings"):
            print("\nWARNINGS")
            print("-" * 40)
            for w in plan["warnings"]:
                print(f"  - {w}")
            print()

        dry_run = kwargs.get("dry_run", False)
        if dry_run:
            print("\n(--dry-run) no vault changes made.")
            return

        if not pam_config_uid:
            raise CommandError(
                "esxi-import",
                "--pam-config-uid is required for apply. "
                "Re-run with --pam-config-uid <UID> or --dry-run "
                "to preview without creating records.",
            )

        # Apply path: in-process record creator + existing post-create
        # runners. The Phase 8.21+ post-create steps (pamConfig DAG link,
        # trafficEncryptionSeed update, user-resource link, custom
        # labeled fields) already use in-process APIs and accept `params`
        # — they work unchanged with the REPL session.
        # Pre-warm sync so caches are hot for the DAG ops downstream.
        try:
            from ... import api as _api  # type: ignore
            _api.sync_down(params)
        except Exception as exc:
            log.warning("pre-execute sync_down failed: %s", exc)

        # Validate the pam_config_uid is a real pamConfig before writing.
        # (Same guardrail Phase 8.24 enforces in the standalone tool.)
        try:
            from ... import vault as _vault  # type: ignore
            rec = _vault.KeeperRecord.load(params, pam_config_uid)
            rt = (getattr(rec, "record_type", "") or getattr(rec, "type_name", "") or "").strip()
            _PAM_CONFIG_TYPES = {
                "pamNetworkConfiguration", "pamAwsConfiguration",
                "pamAzureConfiguration", "pamConfig",
            }
            if rt not in _PAM_CONFIG_TYPES:
                raise CommandError(
                    "esxi-import",
                    f"--pam-config-uid {pam_config_uid} is record_type={rt!r} "
                    f"— NOT a pamConfig. Valid types: {sorted(_PAM_CONFIG_TYPES)}. "
                    f"Find real pamConfigs: pam config list",
                )
        except CommandError:
            raise
        except Exception as exc:
            raise CommandError("esxi-import",
                f"Could not validate --pam-config-uid {pam_config_uid}: {exc}")

        result = execute_plan(
            plan,
            folder=kwargs.get("folder"),
            yes=kwargs.get("yes", False),
            chunk_size=0,
            chunk_delay=0.0,
            params=params,
            _record_creator=_create_record_in_process,
            missing_users=kwargs.get("missing_users", "skip"),
            no_share=kwargs.get("no_share", False),
            share_mode=kwargs.get("share_mode", "record"),
            link_pam_config_uid=pam_config_uid,
            populate_traffic_seed=True,
        )

        # Build the kcm-import-style report. Same shape as the standalone
        # tool — operator gets the same WHAT-TO-DO-NEXT guidance.
        post_create_warnings: List[str] = []
        for r in result.get("rows", []):
            title = r.get("title", "?")
            for key in ("pam_config_link", "traffic_seed", "user_resource_links"):
                sub = r.get(key) or {}
                if sub and sub.get("ok") is False:
                    post_create_warnings.append(
                        f"{key} failed on {title}: {sub.get('error') or 'unknown'}"
                    )
            if r.get("custom_fields_error"):
                post_create_warnings.append(
                    f"post-create custom fields failed on {title}: "
                    f"{r['custom_fields_error']}"
                )
        report = build_import_report(
            plan, result, pam_config_uid=pam_config_uid,
            extra_warnings=post_create_warnings or None,
        )
        print(report)
