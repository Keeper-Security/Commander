#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import re
from typing import Dict, Optional, Tuple

from .constants import FALLBACK_PLATFORM_MAP

# Keyword → mapping for custom/renamed CyberArk platforms (e.g. "Custom-WinDomain" → RDP).
# Matched against platformId and account name; first match wins. Database patterns
# are checked before generic Windows/Unix to avoid false positives.
_PLATFORM_KEYWORD_MAP: Tuple[Tuple[str, dict], ...] = (
    # Databases first (most specific). pam_settings.connection.protocol accepts
    # sql-server, postgresql, mysql; Oracle/MongoDB use protocol=None.
    ("oracle",     {"record_type": "pamDatabase", "rotation": "general", "protocol": None,         "port": "1521",  "database_type": "oracle"}),
    ("postgres",   {"record_type": "pamDatabase", "rotation": "general", "protocol": "postgresql", "port": "5432",  "database_type": "postgresql"}),
    ("mysql",      {"record_type": "pamDatabase", "rotation": "general", "protocol": "mysql",      "port": "3306",  "database_type": "mysql"}),
    ("mariadb",    {"record_type": "pamDatabase", "rotation": "general", "protocol": "mysql",      "port": "3306",  "database_type": "mariadb"}),
    ("mssql",      {"record_type": "pamDatabase", "rotation": "general", "protocol": "sql-server", "port": "1433",  "database_type": "mssql"}),
    ("sqlserver",  {"record_type": "pamDatabase", "rotation": "general", "protocol": "sql-server", "port": "1433",  "database_type": "mssql"}),
    ("mongo",      {"record_type": "pamDatabase", "rotation": "general", "protocol": None,         "port": "27017", "database_type": "mongodb"}),
    # Windows (RDP)
    ("windomain",  {"record_type": "pamMachine",  "rotation": "general", "protocol": "rdp",       "port": "3389"}),
    ("windows",    {"record_type": "pamMachine",  "rotation": "general", "protocol": "rdp",       "port": "3389"}),
    ("rdp",        {"record_type": "pamMachine",  "rotation": "general", "protocol": "rdp",       "port": "3389"}),
    ("win",        {"record_type": "pamMachine",  "rotation": "general", "protocol": "rdp",       "port": "3389"}),
    # Web / login
    ("website",    {"record_type": "login",       "rotation": None,      "protocol": None,        "port": None}),
    ("webapp",     {"record_type": "login",       "rotation": None,      "protocol": None,        "port": None}),
    # *nix / network device (SSH)
    ("unix",       {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",       "port": "22"}),
    ("linux",      {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",       "port": "22"}),
    ("ssh",        {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",       "port": "22"}),
    ("cisco",      {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",       "port": "22"}),
    ("juniper",    {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",       "port": "22"}),
    ("paloalto",   {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",       "port": "22"}),
    ("f5",         {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",       "port": "22"}),
    ("checkpoint", {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",       "port": "22"}),
)


def _guess_platform_mapping(platform_id: str, raw_name: str) -> Optional[dict]:
    """Map unknown/custom platformIds to a record type via keyword scan.

    Returns a mapping dict on match, or None (caller uses FALLBACK_PLATFORM_MAP).
    """
    haystack = f"{platform_id or ''}\n{raw_name or ''}".lower()
    if not haystack.strip():
        return None
    for keyword, mapping in _PLATFORM_KEYWORD_MAP:
        if keyword in haystack:
            return dict(mapping)
    return None


# CyberArk auto-generated account names typically start with one of these
# system category prefixes (e.g. "Operating System-UnixSSH-10.0.0.1-root").
# Stripping them before the platformId strip yields cleaner record titles.
_CATEGORY_PREFIX_RE = re.compile(
    r"^(Operating System|Database|Network Device|Cloud Service|Website|"
    r"Application|Security Appliance|Generic)-",
    re.IGNORECASE,
)

# Port-related keys in platformAccountProperties (case-insensitive lookup).
_PORT_PROPERTY_KEYS = (
    "Port", "port", "PORT",
    "PSMSSHPort", "PSMSshPort", "PSMServerPort", "PSMRDPPort",
    "SSHPort", "RDPPort", "TelnetPort",
    "SQLPort", "DBPort", "DatabasePort",
    "ConnectionPort", "ServicePort", "TargetPort",
)


def _split_host_port(address: str) -> Tuple[str, str]:
    """Split a host[:port] string. Returns (host, port) where port is "" when absent.

    Handles bracketed IPv6 ("[::1]:22"), bare IPv6 (no port), and trims
    accidental whitespace. Non-numeric trailing values are ignored so that
    addresses like "host:22 (primary)" don't pollute the port.
    """
    if not isinstance(address, str):
        return "", ""
    s = address.strip()
    if not s:
        return "", ""
    # Bracketed IPv6 — "[::1]" or "[::1]:22"
    if s.startswith("["):
        end = s.find("]")
        if end > 0:
            host = s[1:end]
            tail = s[end + 1:]
            if tail.startswith(":") and tail[1:].split()[0].isdigit():
                return host, tail[1:].split()[0]
            return host, ""
    # Bare IPv6 (2+ colons) — leave intact, no port
    if s.count(":") > 1:
        return s, ""
    # host:port
    if ":" in s:
        host, _, port = s.partition(":")
        port = port.split()[0]
        if port.isdigit():
            return host, port
    return s, ""


def _extract_port(props: dict, address: str, mapping_default: str) -> Tuple[str, str]:
    """Resolve the port for a CyberArk account, with provenance for debugging.

    Resolution order:
      1. Known port-related keys in ``platformAccountProperties`` (case-insensitive,
         specific keys first — see _PORT_PROPERTY_KEYS).
      2. Port embedded in the account ``address`` (e.g. "host:2222").
      3. Platform-map default (e.g. SSH→22, RDP→3389).
      4. Empty string.

    Returns ``(port, source)`` where source identifies which path matched so
    callers can log it once per account.
    """
    if isinstance(props, dict) and props:
        # Direct hit on the canonical keys (fast path, preserves casing in source).
        for key in _PORT_PROPERTY_KEYS:
            val = props.get(key)
            if val not in (None, ""):
                return str(val).strip(), f"props.{key}"
        # Case-insensitive fallback for tenants with bespoke casing.
        lowered = {str(k).lower(): k for k in props.keys()}
        for key in _PORT_PROPERTY_KEYS:
            actual = lowered.get(key.lower())
            if actual and props.get(actual) not in (None, ""):
                return str(props[actual]).strip(), f"props.{actual}"
    _, embedded = _split_host_port(address)
    if embedded:
        return embedded, "address"
    if mapping_default:
        return str(mapping_default).strip(), "platform-map"
    return "", "none"


# SystemType (from /Platforms list) → mapping. CyberArk classifies every
# platform by its SystemType field, regardless of how the platformId was
# renamed; using it bypasses keyword guessing entirely for tenants whose
# platform list we've cached.
_SYSTEM_TYPE_MAP: Dict[str, dict] = {
    "windows":     {"record_type": "pamMachine",  "rotation": "general", "protocol": "rdp",        "port": "3389"},
    "unixdistro":  {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",        "port": "22"},
    "unix":        {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",        "port": "22"},
    "linux":       {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",        "port": "22"},
    "appliance":   {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",        "port": "22"},
    "network":     {"record_type": "pamMachine",  "rotation": "general", "protocol": "ssh",        "port": "22"},
    "oracledb":    {"record_type": "pamDatabase", "rotation": "general", "protocol": None,         "port": "1521",  "database_type": "oracle"},
    "mssqlserver": {"record_type": "pamDatabase", "rotation": "general", "protocol": "sql-server", "port": "1433",  "database_type": "mssql"},
    "mysql":       {"record_type": "pamDatabase", "rotation": "general", "protocol": "mysql",      "port": "3306",  "database_type": "mysql"},
    "mariadb":     {"record_type": "pamDatabase", "rotation": "general", "protocol": "mysql",      "port": "3306",  "database_type": "mariadb"},
    "postgresql":  {"record_type": "pamDatabase", "rotation": "general", "protocol": "postgresql", "port": "5432",  "database_type": "postgresql"},
    "mongodb":     {"record_type": "pamDatabase", "rotation": "general", "protocol": None,         "port": "27017", "database_type": "mongodb"},
    # Generic "database" SystemType: assume MSSQL since it's the most common in
    # CyberArk Windows-centric tenants. Tenants with other DBs should use
    # --platform-map or rely on platformId keyword guess to override.
    "database":    {"record_type": "pamDatabase", "rotation": "general", "protocol": "sql-server", "port": "1433",  "database_type": "mssql"},
    "website":     {"record_type": "login",       "rotation": None,      "protocol": None,        "port": None},
    "webapp":      {"record_type": "login",       "rotation": None,      "protocol": None,        "port": None},
}


def _port_from_platform_details(details: dict) -> str:
    """Extract a port from the Platforms detail endpoint payload.

    The platform's default port lives under various keys depending on the
    CyberArk version: ``Details.Properties.Required[].Name=="Port"`` with
    DefaultValue, ``Details.UI.PSMServer.Port``, or simply
    ``Details.Properties.Port``. We probe in that order.
    """
    if not isinstance(details, dict):
        return ""
    d = details.get("Details") if isinstance(details.get("Details"), dict) else details
    if not isinstance(d, dict):
        return ""
    props = d.get("Properties") if isinstance(d.get("Properties"), dict) else {}
    # Newer Privilege Cloud: Required/Optional lists of {Name, DefaultValue}
    for bucket in ("Required", "Optional"):
        entries = props.get(bucket) if isinstance(props, dict) else None
        if isinstance(entries, list):
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("Name", "")).lower() in ("port", "sshport", "rdpport", "sqlport", "dbport"):
                    val = entry.get("DefaultValue") or entry.get("Value")
                    if val not in (None, ""):
                        return str(val).strip()
    # Older self-hosted PVWA flattens it
    for key in ("Port", "port", "PSMServerPort", "RDPPort", "SSHPort"):
        if isinstance(props, dict) and props.get(key) not in (None, ""):
            return str(props[key]).strip()
    ui = d.get("UI") if isinstance(d.get("UI"), dict) else {}
    for sub in (ui.get("PSMServer"), ui.get("ConnectionDetails")):
        if isinstance(sub, dict) and sub.get("Port") not in (None, ""):
            return str(sub["Port"]).strip()
    return ""
