"""Pre-flight validation of ``pam_settings.port_forward`` (Keeper proxy gates, local port).

Runs on the raw import JSON (``pam_data``) before anything is written to the vault
(app / folders / records / DAG): ``pam project import`` and ``pam project extend``.
Collects ALL problems in one pass so the user can fix the file in one go.

Rules mirror the Web Vault (``modal-common.ts`` / ``field-data-pam-settings.ts``):
- KeeperDB Proxy applies to MySQL, MariaDB, PostgreSQL, SQL Server, Oracle and DynamoDB
  (MongoDB is not in the Vault list); KeeperRDP Proxy to RDP; KeeperSSH Proxy to SSH.
- A proxy gate needs a launch credential, unless the user supplies it (``allow_supply_host``
  / ``connection.allow_supply_user``) or an ephemeral JIT account is created.
- ``use_specified_local_port`` needs ``local_port``.
The legacy ``connection.allowKeeperDBProxy`` location is rejected (the gate lives in ``port_forward``).
"""

from __future__ import annotations

import logging
import re
from typing import List, Optional, Tuple

from ... import utils

# Protocols (ConnectionProtocol values) each proxy gate applies to - same as the Web Vault
KEEPER_DB_PROXY_PROTOCOLS = ("mysql", "mariadb", "postgresql", "sql-server", "oracle", "dynamodb")
KEEPER_RDP_PROXY_PROTOCOLS = ("rdp",)
KEEPER_SSH_PROXY_PROTOCOLS = ("ssh",)

# (import JSON key, protocols the gate applies to, label)
_GATES = (
    ("allow_keeper_db_proxy", KEEPER_DB_PROXY_PROTOCOLS, "KeeperDB Proxy"),
    ("allow_keeper_rdp_proxy", KEEPER_RDP_PROXY_PROTOCOLS, "KeeperRDP Proxy"),
    ("allow_keeper_ssh_proxy", KEEPER_SSH_PROXY_PROTOCOLS, "KeeperSSH Proxy"),
)

_PORT_FORWARD_KEYS = (
    "port", "reuse_port", "use_specified_local_port", "local_port",
    "allow_keeper_db_proxy", "allow_keeper_rdp_proxy", "allow_keeper_ssh_proxy",
)

_RESOURCE_TYPES = ("pammachine", "pamdatabase", "pamdirectory")  # pamRemoteBrowser has no pam_settings


def _norm_key(key) -> str:
    """allowKeeperDBProxy / allow_keeper_db_proxy -> allowkeeperdbproxy"""
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _is_true(value) -> bool:
    return utils.value_to_boolean(value) is True


def _has_launch_credentials(value) -> bool:
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(isinstance(x, str) and x.strip() for x in value)
    return False


def _valid_port(value) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 1 <= value <= 65535
    if isinstance(value, str):
        v = value.strip()
        return v.isascii() and v.isdigit() and 1 <= int(v) <= 65535
    return False


def validate_resource_port_forward(resource: dict, label: str = "") -> Tuple[List[str], List[str]]:
    """Validate one pam_data.resources[] entry. Returns (errors, warnings)."""
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(resource, dict):
        return errors, warnings
    rtype = str(resource.get("type", "") or "").strip().lower()
    if rtype not in _RESOURCE_TYPES:
        return errors, warnings
    title = str(resource.get("title", "") or "").strip()
    label = label or (f'"{title}" ({resource.get("type")})' if title else str(resource.get("type")))

    ps = resource.get("pam_settings")
    ps = ps if isinstance(ps, dict) else {}
    conn = ps.get("connection")
    conn = conn if isinstance(conn, dict) else {}
    pf = ps.get("port_forward")
    pf = pf if isinstance(pf, dict) else {}
    opts = ps.get("options")
    opts = opts if isinstance(opts, dict) else {}

    # Legacy location: the gate moved from connection to port_forward (Web Vault reads port_forward only)
    for key in conn:
        if _norm_key(key) == "allowkeeperdbproxy":
            errors.append(
                f"{label}: pam_settings.connection.{key} is not supported - the KeeperDB Proxy gate moved to "
                f"pam_settings.port_forward.allow_keeper_db_proxy (use it there)")

    protocol = str(conn.get("protocol", "") or "").strip().lower()
    enabled_gates = [(k, protos, name) for k, protos, name in _GATES if _is_true(pf.get(k))]

    for key, protos, name in enabled_gates:
        if not protocol:
            errors.append(f"{label}: port_forward.{key} requires pam_settings.connection.protocol "
                          f"({', '.join(protos)})")
        elif protocol not in protos:
            errors.append(f"{label}: port_forward.{key} ({name}) is not supported for protocol "
                          f'"{protocol}" - it applies to: {", ".join(protos)}')

    if enabled_gates:
        jit = opts.get("jit_settings")
        jit = jit if isinstance(jit, dict) else {}
        # DynamoDB hides ephemeral JIT in the Vault, so it cannot satisfy the credential requirement
        ephemeral = _is_true(jit.get("create_ephemeral")) and protocol != "dynamodb"
        supplied = (_is_true(ps.get("allow_supply_host"))
                    or _is_true(conn.get("allow_supply_user"))
                    or ephemeral
                    or _has_launch_credentials(conn.get("launch_credentials")))
        if not supplied:
            keys = ", ".join(f"port_forward.{k}" for k, _, _ in enabled_gates)
            errors.append(f"{label}: {keys} requires a launch credential - set "
                          f"pam_settings.connection.launch_credentials (or allow_supply_user / allow_supply_host, "
                          f"or jit_settings.create_ephemeral)")

    if _is_true(pf.get("use_specified_local_port")) and not _valid_port(pf.get("local_port")) \
            and pf.get("local_port") in (None, ""):
        errors.append(f"{label}: port_forward.use_specified_local_port requires port_forward.local_port")
    if pf.get("local_port") not in (None, "") and not _valid_port(pf.get("local_port")):
        errors.append(f'{label}: port_forward.local_port "{pf.get("local_port")}" is not a valid port number (1-65535)')

    # Settings are still stored (like the Vault toggle OFF then ON), just not effective
    tunneling = str(opts.get("tunneling", "") or "").strip().lower()
    if tunneling == "off" and any(pf.get(k) not in (None, "") for k in _PORT_FORWARD_KEYS):
        warnings.append(f'{label}: port_forward settings are stored but not effective - options.tunneling is "off"')

    return errors, warnings


def validate_port_forward_data(pam_data) -> Tuple[List[str], List[str]]:
    """Validate all pam_data.resources[]. Returns (errors, warnings); touches nothing."""
    errors: List[str] = []
    warnings: List[str] = []
    resources = pam_data.get("resources") if isinstance(pam_data, dict) else None
    if not isinstance(resources, list):
        return errors, warnings
    for idx, res in enumerate(resources):
        e, w = validate_resource_port_forward(res, label=_resource_label(res, idx))
        errors.extend(e)
        warnings.extend(w)
    return errors, warnings


def _resource_label(res, idx: int) -> str:
    if isinstance(res, dict):
        title = str(res.get("title", "") or "").strip()
        rtype = str(res.get("type", "") or "").strip()
        if title:
            return f'resources[{idx}] "{title}"' + (f" ({rtype})" if rtype else "")
    return f"resources[{idx}]"


def preflight_port_forward(pam_data, command: str = "pam project import",
                           colors: Optional[object] = None) -> bool:
    """Print warnings/errors for the whole file. Returns False if the command must abort.

    Call before any vault write (also in dry-run).
    """
    fail = getattr(colors, "FAIL", "")
    warn = getattr(colors, "WARNING", "")
    end = getattr(colors, "ENDC", "")
    errors, warnings = validate_port_forward_data(pam_data)
    for msg in warnings:
        logging.warning(f"{warn}{msg}{end}")
    if errors:
        print(f"{fail}{command}: {len(errors)} port_forward validation error(s) in the import JSON:{end}")
        for msg in errors:
            print(f"{fail}  - {msg}{end}")
        print(f"{fail}Aborting. No changes made to vault.{end}")
        return False
    return True
