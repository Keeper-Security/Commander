#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# CyberArk → KeeperPAM import: PVWA client, account mapper, safe folder mapper
#

import copy
import csv
import fnmatch
import io
import ipaddress
import logging
import math
import re
import socket
import time
from os import environ, path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

import requests
from html import escape as _html_escape
from prompt_toolkit import HTML, print_formatted_text, prompt
from prompt_toolkit.shortcuts import button_dialog
from prompt_toolkit.styles import Style


def _esc(text) -> str:
    """Escape HTML-significant characters and strip control/ANSI sequences
    for safe use in prompt_toolkit HTML()."""
    s = re.sub(r'[\x00-\x1f\x7f]', '', str(text))  # strip control chars + ANSI
    return _html_escape(s, quote=False)

# Valid CyberArk logon types for self-hosted PVWA (case-insensitive check)
VALID_LOGON_TYPES = {"cyberark", "ldap", "radius", "windows"}

# System safes excluded from migration by default.
# These are internal CyberArk safes that do not contain user-managed accounts.
# Override with --include-system-safes flag.
SYSTEM_SAFES = {
    "System", "VaultInternal", "Notification Engine", "SharedAuth_Internal",
    "PVWAUserPrefs", "PVWAConfig", "PVWAReports", "PVWATaskDefinitions",
    "PVWAPrivateUserPrefs", "PVWAPublicData", "PVWATicketingSystem",
    "AccountsFeed", "PSM", "xRay", "PIMSuRecordings", "xRay_Config",
    "AccountsFeedAcc", "PasswordManager_Pending", "PasswordManagerShared",
    "PasswordManager_workspace", "PasswordManager_ADInternal",
    # Additional system safes found in real environments
    "PasswordManager", "SCIM Config", "PSMSessions", "PSMUnmanagedSessionAccounts",
    "PSMLiveSessions", "PSMNotifications", "PSMRecordings",
}

# Maximum safe name length for Keeper shared folder names
MAX_SAFE_NAME_LENGTH = 28

# Maximum total records per fetch operation (prevent OOM from malicious API)
MAX_FETCH_RECORDS = 50000


# Default CyberArk platformId → KeeperPAM record mapping
DEFAULT_PLATFORM_MAP = {
    # NIX
    "UnixSSH":         {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",        "port": "22"},
    "UnixSSHKey":      {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",        "port": "22"},
    "UnixSSHKeys":     {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",        "port": "22"},
    # Windows
    "WinDomain":       {"record_type": "pamMachine", "rotation": "general", "protocol": "rdp",        "port": "3389"},
    "WinLocalAccount": {"record_type": "pamMachine", "rotation": "general", "protocol": "rdp",        "port": "3389"},
    "WinServerLocal":  {"record_type": "pamMachine", "rotation": "general", "protocol": "rdp",        "port": "3389"},
    "WinDesktopLocal": {"record_type": "pamMachine", "rotation": "general", "protocol": "rdp",        "port": "3389"},
    # Database
    "Oracle":          {"record_type": "pamDatabase", "rotation": "general", "protocol": "sql-server",   "port": "1521"},
    "MySQL":           {"record_type": "pamDatabase", "rotation": "general", "protocol": "mysql",       "port": "3306"},
    "MSSql":           {"record_type": "pamDatabase", "rotation": "general", "protocol": "mssql",       "port": "1433"},
    "PostgreSQL":      {"record_type": "pamDatabase", "rotation": "general", "protocol": "postgresql",  "port": "5432"},
    # Network devices — SSH-managed
    "PaloAltoNetworks":    {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "CiscoIOS":            {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "CiscoIOSEnable":      {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "CiscoASA":            {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "JuniperJunos":        {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "F5BigIP":             {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    "CheckPointGAIA":      {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    # CyberArk internal — service accounts, import as pamMachine/SSH
    "CyberArk":            {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh",    "port": "22"},
    # Web — login record, NOT pamMachine
    "BusinessWebsite": {"record_type": "login", "rotation": None, "protocol": None, "port": None},
}

# Fallback mapping for accounts with empty or unknown platformId
FALLBACK_PLATFORM_MAP = {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh", "port": "22"}


class RecordKind:
    """PVWA returns multiple record-bearing entities under different
    endpoints. Each maps to a different Keeper record-type and goes
    through a different mapper. Discriminated at import time off the
    PVWA payload shape rather than the endpoint, so a single
    exported-JSON file can carry mixed kinds.

    STATE: only ACCOUNT is implemented. APPLICATION and API_TOKEN are
    stubs awaiting real PVWA samples (Prathamesh deliverable #2).
    """
    ACCOUNT = "account"          # /Accounts (current — pamMachine/pamDatabase/login)
    APPLICATION = "application"  # /Applications (Application Identity Manager)
    API_TOKEN = "api_token"      # custom platform / non-account credential


def discriminate_record_kind(payload: dict) -> str:
    """Return the RecordKind for a PVWA payload.

    Discriminators below are best-guess from spec; will be refined
    when real samples land. Order matters: APPLICATION and API_TOKEN
    are checked before ACCOUNT so they win when their distinguishing
    field is present.
    """
    if not isinstance(payload, dict):
        return RecordKind.ACCOUNT
    if "AppID" in payload:
        return RecordKind.APPLICATION
    if payload.get("platformType") == "Application":
        return RecordKind.API_TOKEN
    return RecordKind.ACCOUNT


# CyberArk auto-generated account names typically start with one of these
# system category prefixes (e.g. "Operating System-UnixSSH-10.0.0.1-root").
# Stripping them before the platformId strip yields cleaner record titles.
_CATEGORY_PREFIX_RE = re.compile(
    r"^(Operating System|Database|Network Device|Cloud Service|Website|"
    r"Application|Security Appliance|Generic)-",
    re.IGNORECASE,
)


class CyberArkPVWAClient:
    """Handles authentication and API calls to CyberArk PVWA."""

    DELAY = 0.025
    TIMEOUT = 10
    ENDPOINTS = {
        "accounts": "Accounts",
        "account_password": "Accounts/{account_id}/Password/Retrieve",
        "logon": "Auth/{type}/Logon",
        "safes": "Safes",
    }

    def __init__(self, pvwa_host, verify_ssl=True):
        host, query_params = self._normalize_host(pvwa_host)
        self.pvwa_host = host
        self.query_params = query_params
        # SSL verification: always True for Privilege Cloud.
        # For self-hosted: default True, caller can disable with verify_ssl=False.
        if self.pvwa_host.endswith(".cyberark.cloud"):
            self.verify_ssl = True
        else:
            self.verify_ssl = verify_ssl
            if not verify_ssl:
                logging.warning("SSL certificate verification is disabled for self-hosted PVWA. "
                                "This is insecure and vulnerable to man-in-the-middle attacks.")
        self.auth_token = None
        self._validate_host(self.pvwa_host)

    @staticmethod
    def _normalize_host(filename):
        """Normalize PVWA host — same logic as existing CyberArkImporter (PR #1423).
        Returns (host, query_params) tuple.

        Accepted formats:
          - 'pvwa.company.com'                        → self-hosted, used as-is
          - 'tenant.cyberark.cloud'                   → tenant.privilegecloud.cyberark.cloud
          - 'tenant.privilegecloud.cyberark.cloud'    → already correct, no rewrite
          - 'https://tenant.cyberark.cloud'           → strips https, rewrites
          - 'https://pvwa.company.com?safe=MySafe'    → query param extracted
        """
        pvwa_host = filename.removeprefix("https://").removeprefix("http://").rstrip("/")
        query_params = {}
        if "?" in pvwa_host:
            pvwa_host, query_string = pvwa_host.split("?", 1)
            if "=" in query_string:
                query_params = dict(parse_qsl(query_string))
            else:
                query_params["search"] = query_string
        # Rewrite *.cyberark.cloud to *.privilegecloud.cyberark.cloud
        # but skip if already has .privilegecloud. subdomain
        if (pvwa_host.endswith(".cyberark.cloud")
                and ".privilegecloud." not in pvwa_host):
            pvwa_host = f"{pvwa_host.split('.')[0]}.privilegecloud.cyberark.cloud"
        return pvwa_host, query_params

    @staticmethod
    def _validate_host(host):
        """Validate that the PVWA host is not targeting internal/private addresses (SSRF protection)."""
        # Strip port if present
        hostname = host.split(":")[0] if ":" in host else host
        # Reject obviously dangerous hostnames
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1", ""):
            raise ValueError(f"PVWA host '{host}' targets a local address and is not allowed")
        # Validate hostname format (alphanumeric, dots, hyphens only)
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', hostname):
            raise ValueError(f"PVWA host '{hostname}' contains invalid characters")
        # Check IP literals against private ranges
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                raise ValueError(f"PVWA host '{host}' is a private/reserved IP and is not allowed")
            return
        except ValueError as e:
            if "is not allowed" in str(e):
                raise
            # Not an IP literal — resolve hostname and check all IPs
            pass
        # DNS resolution check — reject if hostname resolves to private IP
        try:
            resolved_ips = socket.getaddrinfo(hostname, None)
            for family, _, _, _, sockaddr in resolved_ips:
                ip_str = sockaddr[0]
                addr = ipaddress.ip_address(ip_str)
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                    raise ValueError(
                        f"PVWA host '{hostname}' resolves to private/reserved IP "
                        f"{ip_str} and is not allowed (SSRF protection)")
        except socket.gaierror:
            # Cannot resolve — will fail at connection time, not a security issue
            pass

    def _get_url(self, endpoint):
        return f"https://{self.pvwa_host}/PasswordVault/API/{self.ENDPOINTS[endpoint]}"

    MAX_RETRIES = 3

    def logoff(self):
        """Log off from CyberArk PVWA. Best-effort — failures are silently ignored."""
        if not self.auth_token:
            return
        try:
            base = self._get_url("safes").rsplit("/Safes", 1)[0]
            requests.post(
                f"{base}/Auth/Logoff",
                headers={"Authorization": self.auth_token, "Content-Type": "application/json"},
                timeout=self.TIMEOUT,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
        except Exception:
            pass  # Best-effort logoff
        self.auth_token = None

    def _get(self, url, params=None):
        """GET with automatic retry on HTTP 429 (rate limit). Redirects disabled."""
        response = None
        for attempt in range(self.MAX_RETRIES):
            response = requests.get(
                url,
                headers={"Authorization": self.auth_token, "Content-Type": "application/json"},
                params=params,
                timeout=self.TIMEOUT,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
            if response.status_code != 429:
                return response
            try:
                retry_after = int(response.headers.get("Retry-After", 2 ** (attempt + 1)))
            except (ValueError, TypeError):
                retry_after = 2 ** (attempt + 1)  # fallback on non-numeric header
            retry_after = min(retry_after, 60)
            logging.warning('Rate limited (429) — retrying in %ds (attempt %d/%d)',
                            retry_after, attempt + 1, self.MAX_RETRIES)
            time.sleep(retry_after)
        return response

    @staticmethod
    def _discover_identity_endpoint(tenant_subdomain: str) -> Optional[str]:
        """Resolve tenant subdomain to identity endpoint via CyberArk platform discovery.

        Uses the same discovery service as ark-sdk-python:
        https://platform-discovery.cyberark.cloud/api/identity-endpoint/{subdomain}

        Returns the identity host (e.g. 'abc1234.id.cyberark.cloud') or None on failure.
        Falls back silently — caller uses the manually constructed URL.
        """
        try:
            response = requests.get(
                f"https://platform-discovery.cyberark.cloud/api/identity-endpoint/{tenant_subdomain}",
                timeout=5,
            )
            if response.status_code == 200:
                data = response.json()
                # Response format: {"identity_user_portal": {"api": "https://..."}}
                identity_url = (data.get("identity_user_portal", {}).get("api", "")
                                or data.get("identity", {}).get("api", ""))
                if identity_url:
                    host = identity_url.removeprefix("https://").removeprefix("http://").rstrip("/")
                    if host:
                        return host
        except (requests.RequestException, ValueError, KeyError):
            logging.debug("Platform discovery unavailable for tenant '%s' — using fallback",
                          tenant_subdomain)
        return None

    def authenticate(self) -> bool:
        """Authenticate to CyberArk PVWA. Returns True on success."""
        if self.pvwa_host.endswith(".cyberark.cloud"):
            return self._auth_privilege_cloud()
        else:
            return self._auth_self_hosted()

    def _auth_privilege_cloud(self) -> bool:
        """Authenticate to CyberArk Privilege Cloud via OAuth2 service account.

        Tenant ID formats accepted (aligned with cyberark_portal discovery):
          - 'abc1234'          → abc1234.id.cyberark.cloud (short subdomain ID)
          - 'mycompany'        → mycompany.cyberark.cloud (named tenant)
          - 'abc1234.id'       → abc1234.id.cyberark.cloud (already qualified)
          - 'https://...'      → extracted hostname used directly
          - 'tenant.my.idaptive.app' → tenant.my.idaptive.app (legacy Idaptive)
        """
        id_tenant_raw = environ.get("KEEPER_CYBERARK_ID_TENANT") or prompt("CyberArk Identity Tenant ID: ")
        id_tenant_raw = id_tenant_raw.strip()
        # Strip https:// prefix if present
        if id_tenant_raw.startswith("https://"):
            id_tenant_raw = id_tenant_raw[len("https://"):]
        if id_tenant_raw.startswith("http://"):
            id_tenant_raw = id_tenant_raw[len("http://"):]
        id_tenant_raw = id_tenant_raw.rstrip("/")

        # Determine the identity host for OAuth2
        if "." in id_tenant_raw:
            # Already has dots — could be 'abc1234.id', 'tenant.my.idaptive.app',
            # or 'tenant.cyberark.cloud'. Use as-is for the identity host.
            id_host = id_tenant_raw
            # But for the OAuth2 URL we need *.cyberark.cloud domain
            if id_tenant_raw.endswith(".my.idaptive.app"):
                # Legacy Idaptive — extract subdomain for cyberark.cloud OAuth2
                id_host = id_tenant_raw.split(".")[0] + ".id.cyberark.cloud"
                logging.info("Legacy Idaptive tenant detected, using %s for OAuth2", id_host)
            elif not id_tenant_raw.endswith(".cyberark.cloud"):
                # Has dots but not a known domain — treat first part as tenant
                id_host = id_tenant_raw.split(".")[0] + ".cyberark.cloud"
        else:
            # Simple name — apply subdomain ID detection
            id_tenant = id_tenant_raw
            if re.match(r"^[A-Za-z]{3}\d{4}$", id_tenant):
                id_tenant += ".id"
            id_host = f"{id_tenant}.cyberark.cloud"

        # Validate the base portion (before first dot)
        base_part = id_host.split(".")[0]
        if not re.match(r'^[a-zA-Z0-9]+$', base_part):
            print_formatted_text(HTML("<ansired>Invalid tenant ID format</ansired>"))
            return False

        # Platform discovery — resolve tenant to correct identity endpoint
        # (ark-sdk-python pattern: platform-discovery.cyberark.cloud)
        discovered_host = self._discover_identity_endpoint(base_part)
        if discovered_host:
            id_host = discovered_host
            logging.info("Platform discovery resolved tenant to %s", id_host)

        client_id = environ.get("KEEPER_CYBERARK_USERNAME") or prompt("CyberArk service user name: ")
        client_secret = environ.get("KEEPER_CYBERARK_PASSWORD") or prompt(
            "CyberArk service user password: ", is_password=True
        )
        oauth2_url = f"https://{id_host}/oauth2/platformtoken"
        logging.info("Authenticating to Privilege Cloud via %s", oauth2_url)
        try:
            response = requests.post(
                oauth2_url,
                data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret},
                timeout=self.TIMEOUT,
            )
        except requests.RequestException as e:
            print_formatted_text(HTML(f"OAuth2 request <ansired>failed</ansired>: connection error"))
            logging.debug(f"OAuth2 connection error: {type(e).__name__}")
            return False
        if response.status_code != 200:
            print_formatted_text(HTML(
                f"OAuth2 authorization token request <ansired>failed</ansired> with status code <b>{response.status_code}</b>"
            ))
            return False
        try:
            self.auth_token = f"Bearer {response.json()['access_token']}"
        except (KeyError, ValueError) as e:
            print_formatted_text(HTML("<ansired>Failed to parse OAuth2 response</ansired>"))
            return False
        print_formatted_text(HTML("Log on <ansigreen>successful</ansigreen>"))
        return True

    def _auth_self_hosted(self) -> bool:
        login_type = environ.get("KEEPER_CYBERARK_LOGON_TYPE") or prompt(
            "CyberArk logon type (Cyberark, LDAP, RADIUS or Windows): "
        )
        # Validate login_type to prevent URL path injection (case-insensitive)
        if login_type.lower() not in VALID_LOGON_TYPES:
            print_formatted_text(HTML(
                f"<ansired>Invalid logon type</ansired>: must be one of Cyberark, LDAP, RADIUS, Windows"
            ))
            return False
        username = environ.get("KEEPER_CYBERARK_USERNAME") or prompt("CyberArk username: ")
        password = environ.get("KEEPER_CYBERARK_PASSWORD") or prompt("CyberArk password: ", is_password=True)
        try:
            response = requests.post(
                self._get_url("logon").format(type=login_type),
                json={"username": username, "password": password},
                timeout=self.TIMEOUT,
                verify=self.verify_ssl,
            )
        except requests.RequestException as e:
            print_formatted_text(HTML(f"CyberArk Log on <ansired>failed</ansired>: connection error"))
            logging.debug(f"Logon connection error: {type(e).__name__}")
            return False
        if response.status_code != 200:
            print_formatted_text(HTML(
                f"CyberArk Log on <ansired>failed</ansired> with status code <b>{response.status_code}</b>"
            ))
            return False
        # CyberArk's Logon endpoint returns the token as a JSON string.
        # Use json() for proper quote/escape handling rather than strip('"').
        try:
            token = response.json()
        except ValueError:
            token = response.text.strip('"')
        self.auth_token = token if isinstance(token, str) else ""
        print_formatted_text(HTML("Log on <ansigreen>successful</ansigreen>"))
        return True

    def _paginate(self, url: str, params: Optional[dict] = None,
                  items_key: str = "value", limit: int = 100,
                  filter_fn=None) -> List[dict]:
        """Generic paginated fetch following nextLink (ark-sdk-python pattern).

        Follows the server's nextLink URL for subsequent pages instead of
        manually incrementing offset — more robust against API changes.
        """
        results = []
        page_params = dict(params or {}, limit=str(limit), offset="0")
        next_url = url
        while True:
            time.sleep(self.DELAY)
            response = self._get(next_url, params=page_params)
            if response.status_code != 200:
                logging.debug('Paginated fetch failed: %s status %d', next_url, response.status_code)
                break
            try:
                data = response.json()
            except (ValueError, KeyError):
                break
            batch = data.get(items_key, [])
            if filter_fn:
                batch = [item for item in batch if filter_fn(item)]
            results.extend(batch)
            if len(results) >= MAX_FETCH_RECORDS:
                logging.warning('Pagination cap reached (%d) — truncating', MAX_FETCH_RECORDS)
                break
            # Follow nextLink if present, otherwise check batch size
            next_link = data.get("nextLink")
            if next_link:
                # Validate nextLink origin before following. A compromised or
                # malicious PVWA could point pagination at an attacker host
                # to exfiltrate the auth_token via the Authorization header.
                try:
                    base_host = urlparse(url).netloc
                    next_host = urlparse(next_link).netloc
                except ValueError:
                    logging.warning('Invalid nextLink URL — stopping pagination')
                    break
                if next_host and next_host != base_host:
                    logging.warning('nextLink points to a different host (%s vs %s) — '
                                    'stopping pagination to avoid token leakage',
                                    next_host, base_host)
                    break
                # nextLink is a full URL — use it directly, no params needed
                next_url = next_link
                page_params = {}
            else:
                # No nextLink and batch smaller than limit = last page
                raw_count = len(data.get(items_key, []))
                if raw_count < limit:
                    break
                # No nextLink but full page — fallback to manual offset
                current_offset = int(page_params.get("offset", "0"))
                page_params = dict(params or {}, limit=str(limit),
                                   offset=str(current_offset + limit))
                next_url = url
        return results

    def fetch_safes(self) -> List[dict]:
        """Fetch list of safes from PVWA or local sources."""
        safes_file = environ.get("KEEPER_CYBERARK_SAFES_PATH", "safes.txt")
        if path.isfile(safes_file):
            with open(safes_file, "r", encoding="utf-8") as f:
                names = [line.strip() for line in f if line.strip()]
            if not names:
                print_formatted_text(HTML(f"Safes file <ansired>{_esc(safes_file)}</ansired> is empty"))
                return []
            print_formatted_text(HTML(f"Safes from file <i>{_esc(safes_file)}</i>: <b>{_esc(', '.join(names))}</b>"))
            return [{"safeName": n} for n in names]
        elif "KEEPER_CYBERARK_SAFES" in environ:
            names = [x.strip() for x in environ["KEEPER_CYBERARK_SAFES"].split(",") if x.strip()]
            print_formatted_text(HTML(f"Safes from environment variable KEEPER_CYBERARK_SAFES: <b>{_esc(', '.join(names))}</b>"))
            return [{"safeName": n} for n in names]
        else:
            user_input = prompt(
                "CyberArk safes as a comma-separated list (leave empty to get safes from the server): "
            )
            names = [x.strip() for x in user_input.split(",") if x.strip()]
            if names:
                return [{"safeName": n} for n in names]
            # Fetch from server — now with pagination
            print_formatted_text(HTML("Getting safes from the server..."))
            safes = self._paginate(self._get_url("safes"), limit=200)
            if not safes:
                print_formatted_text(HTML(f"No Safes on server <ansired>{_esc(self.pvwa_host)}</ansired>"))
            return safes

    def fetch_safe_members(self, safe_url_id: str) -> List[dict]:
        """Fetch members of a safe. Returns list of member dicts.

        Excludes predefined system members (Master, Batch, etc.) by default.
        """
        # Validate safe_url_id to prevent URL path injection
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_. -]*$', safe_url_id):
            logging.warning('Invalid safe URL ID format: %s — skipping member fetch',
                            re.sub(r'[^a-zA-Z0-9_. -]', '?', safe_url_id))
            return []
        url = f"{self._get_url('safes')}/{safe_url_id}/Members"
        return self._paginate(
            url, limit=100,
            filter_fn=lambda m: not m.get("isPredefinedUser", False),
        )

    def fetch_users(self) -> List[dict]:
        """Fetch all vault users. Excludes component users (CPM, PSM, etc.)."""
        base = self._get_url('safes').rsplit('/Safes', 1)[0]
        return self._paginate(
            f"{base}/Users",
            params={"componentUser": "false"},
            items_key="Users",
            limit=100,
        )

    def fetch_user_groups(self) -> List[dict]:
        """Fetch all vault user groups."""
        base = self._get_url('safes').rsplit('/Safes', 1)[0]
        return self._paginate(f"{base}/UserGroups", limit=100)

    def fetch_master_policy(self) -> Optional[dict]:
        """Fetch the CyberArk Master Policy settings.

        Returns the policy dict or None if the API is not accessible (403/404).
        Graceful failure — Master Policy is optional for migration.
        """
        try:
            base = self._get_url("safes").rsplit("/Safes", 1)[0]
            response = self._get(f"{base}/Policy/MasterPolicy")
            if response.status_code == 200:
                try:
                    return response.json()
                except (ValueError, KeyError):
                    logging.debug('Master Policy response not valid JSON')
                    return None
            logging.debug('Master Policy not accessible: status %d',
                          response.status_code)
        except requests.RequestException as e:
            logging.debug('Master Policy fetch error: %s', type(e).__name__)
        return None

    def fetch_accounts(self, safe_names: List[str], query_params: Optional[dict] = None,
                       state_filter: Optional[List[str]] = None) -> Dict[str, List[dict]]:
        """Fetch accounts for given safes with pagination. Returns {safe_name: [account_dicts]}."""
        result = {}
        base_params = query_params or self.query_params or {}
        for safe in safe_names:
            params = dict(base_params, filter=f"safeName eq {safe}")
            accounts = self._paginate(
                self._get_url("accounts"), params=params,
                limit=1000,  # CyberArk max for accounts endpoint
            )
            if not accounts:
                print_formatted_text(HTML(f"<ansiyellow>No accounts in safe {_esc(safe)}</ansiyellow>"))
                continue
            # Apply state filter if provided
            if state_filter:
                state_filter_lower = [s.lower() for s in state_filter]
                accounts = [
                    a for a in accounts
                    if (a.get("secretManagement", {}).get("status", "").lower() in state_filter_lower
                        or not a.get("secretManagement", {}).get("status"))
                ]
            result[safe] = accounts
            print_formatted_text(HTML(f"Found <b>{len(accounts)}</b> accounts in safe <b>{_esc(safe)}</b>"))
        return result

    def fetch_account_details(self, account_id: str) -> Optional[dict]:
        """Fetch single account details including linkedAccounts.

        LinkedAccounts (logonAccount, reconcileAccount, enableAccount) are
        only available via the single-account GET, not the list endpoint.
        Returns the full account dict or None on failure.
        """
        # Validate account_id format (alphanumeric + underscore only)
        if not re.match(r'^[a-zA-Z0-9_]+$', account_id):
            logging.warning('Invalid account ID format: %s — skipping detail fetch',
                            re.sub(r'[^a-zA-Z0-9_]', '?', account_id))
            return None
        try:
            response = self._get(f"{self._get_url('accounts')}/{account_id}")
            if response.status_code == 200:
                return response.json()
            logging.debug('Account detail fetch failed for %s: status %d',
                          account_id, response.status_code)
        except requests.RequestException as e:
            logging.debug('Account detail fetch error for %s: %s',
                          account_id, type(e).__name__)
        return None

    def retrieve_password(self, account_id: str, account_name: str = "",
                          safe_name: str = "", skip_all: Optional[dict] = None) -> Optional[str]:
        """Retrieve password for an account. Returns password string or None."""
        if skip_all is None:
            skip_all = {}
        # Validate account_id format before URL interpolation
        if not re.match(r'^[a-zA-Z0-9_]+$', str(account_id)):
            logging.warning('Invalid account ID for password retrieval: %s',
                            re.sub(r'[^a-zA-Z0-9_]', '?', str(account_id)))
            return None
        retry = True
        while retry is True:
            try:
                response = requests.post(
                    self._get_url("account_password").format(account_id=account_id),
                    headers={"Authorization": self.auth_token, "Content-Type": "application/json"},
                    json={
                        "reason": "Keeper Commander Import",
                        # Include ticketing params if configured — some CyberArk policies
                        # require a ticket ID for credential retrieval (ark-sdk-python pattern)
                        **({"TicketingSystemName": environ["KEEPER_CYBERARK_TICKETING_SYSTEM"]}
                           if "KEEPER_CYBERARK_TICKETING_SYSTEM" in environ else {}),
                        **({"TicketId": environ["KEEPER_CYBERARK_TICKET_ID"]}
                           if "KEEPER_CYBERARK_TICKET_ID" in environ else {}),
                    },
                    timeout=self.TIMEOUT,
                    verify=self.verify_ssl,
                )
            except requests.RequestException as e:
                logging.debug('Password retrieval network error for %s: %s',
                              account_id, type(e).__name__)
                return None
            if response.status_code == 200:
                # Password endpoint returns a JSON string; parse properly
                # to avoid edge cases in embedded quotes or escapes.
                try:
                    pw = response.json()
                except ValueError:
                    pw = response.text.strip('"')
                return pw if isinstance(pw, str) else None
            elif 400 <= response.status_code < 500:
                try:
                    error = response.json()
                except ValueError:
                    error = {"ErrorCode": "UNKNOWN", "ErrorMessage": "Non-JSON error response"}
                error_code = error.get("ErrorCode")
                if error_code in skip_all:
                    return None
                retry = button_dialog(
                    title=f"{response.status_code}",
                    text=HTML(
                        f"Error {_esc(error_code)}: <ansired>{_esc(error.get('ErrorMessage', ''))}</ansired>\n"
                        f"Account <i>{_esc(account_name)}</i> with ID <i>{_esc(account_id)}</i> in Safe <i>{_esc(safe_name)}</i>"
                    ),
                    buttons=[("Retry", True), ("Skip", False), ("Skip All", None)],
                    style=Style.from_dict({"dialog": "bg:ansiblack"}),
                ).run()
                if retry is None:
                    skip_all[error_code] = True
                    return None
                if retry is False:
                    return None
            else:
                print_formatted_text(HTML(f"Password retrieval <ansired>aborted</ansired> (status {response.status_code})"))
                return None
        return None


class ApplicationMapper:
    """Maps PVWA Applications (Application Identity Manager) to Keeper records.

    STUB. The mapping target and field translation are placeholders
    pending Prathamesh's /Applications sample. When the sample lands:
      1. Confirm Keeper target record_type (likely 'login' or new
         'pamApplication' — check with platform team).
      2. Fill `_field_map` with PVWA → Keeper field translations
         (AppID, AccessPermittedFrom, AccessPermittedTo, ExpirationDate,
         per-app authentication-method serialization).
      3. Replace the NotImplementedError in `map_application` with
         the real mapping logic.
      4. Drop a real `tests/fixtures/cyberark_application_sample.json`
         in place of the placeholder fixture.

    Until then the import driver skips applications with a warning
    rather than raising, so existing /Accounts imports stay
    unaffected.
    """

    TARGET_RECORD_TYPE = "login"  # PLACEHOLDER — confirm with platform team

    _field_map = {
        # "PVWA_field": "keeper_field",  # filled when sample arrives
    }

    def __init__(self, client: 'CyberArkPVWAClient'):
        self._client = client

    def map_application(self, payload: dict) -> dict:
        raise NotImplementedError(
            "ApplicationMapper.map_application awaiting PVWA "
            "/Applications sample (Prathamesh blocker #2). Until "
            "then, applications are skipped with a warning."
        )


class AccountMapper:
    """Maps CyberArk accounts to KeeperPAM record dicts matching pam project import JSON schema."""

    def __init__(self, platform_map_override: Optional[dict] = None):
        self.platform_map = copy.deepcopy(DEFAULT_PLATFORM_MAP)
        if platform_map_override:
            self.platform_map.update(platform_map_override)
        self.unmapped_platforms = {}  # platformId → count

    def map_account(self, account: dict, password: Optional[str] = None,
                    safe_name: str = "") -> Optional[dict]:
        """Convert a CyberArk account dict → pam_data record dict.

        Returns None if the platformId is completely unknown and has no default.
        """
        platform_id = account.get("platformId", "")
        mapping = self.platform_map.get(platform_id) if platform_id else None

        if mapping is None:
            # Empty or unknown platform — use fallback, track for report
            label = platform_id if platform_id else "(empty)"
            self.unmapped_platforms[label] = self.unmapped_platforms.get(label, 0) + 1
            mapping = dict(FALLBACK_PLATFORM_MAP)
            if platform_id:
                logging.warning("Unknown platformId '%s' for account '%s' "
                                "— defaulting to pamMachine/SSH. Use --platform-map to override.",
                                platform_id, account.get("name", ""))
            else:
                logging.info("Empty platformId for account '%s' — defaulting to pamMachine/SSH.",
                             account.get("name", ""))

        record_type = mapping.get("record_type", "pamMachine")
        props = account.get("platformAccountProperties", {}) or {}

        # Extract fields
        address = account.get("address", "")
        user_name = account.get("userName", "")

        # Build title: strip CyberArk category and platform prefixes; when the
        # resulting name is still long (e.g. the CPM policy name is embedded
        # rather than the platformId), fall back to {address}-{userName}.
        raw_name = account.get("name", "")
        stripped = _CATEGORY_PREFIX_RE.sub("", raw_name)
        if platform_id:
            stripped = re.sub(rf"^.*{re.escape(platform_id)}[\-_ ]", "", stripped)
        if len(stripped) > 40 and address and user_name:
            title = f"{address}-{user_name}"
        else:
            title = stripped
        logon_domain = props.get("LogonDomain", "")
        login = f"{logon_domain}\\{user_name}" if logon_domain and user_name else user_name
        url = props.get("URL", "")
        item_name = props.get("ItemName", "")
        port = props.get("Port", mapping.get("port", ""))

        if record_type == "login":
            # BusinessWebsite → login record (not pamMachine)
            record = {
                "type": "login",
                "title": item_name or title,
                "login": login,
                "password": password or "",
            }
            if url:
                record["url"] = url
            return record

        if record_type in ("pamMachine", "pamDatabase"):
            secret_type_check = account.get("secretType", "password").lower()
            # No target host and no SSH key material → route to login. A
            # pamMachine without a host can never be reached by the gateway,
            # so the credential is more useful as a standalone login record.
            # SSH keys keep pamMachine semantics even without an address so
            # the private_pem_key field is preserved.
            if not address and secret_type_check != "key":
                note = (f"CyberArk platform: {platform_id}\n"
                        "No address — imported as login (not pamMachine)"
                        if platform_id else
                        "CyberArk account had no address — imported as login")
                return {
                    "type": "login",
                    "title": title or raw_name,
                    "login": login,
                    "password": password or "",
                    "notes": note,
                }
            # Build pamUser nested inside the resource
            user_record = {
                "type": "pamUser",
                "title": f"{login}@{title}" if login else f"user@{title}",
                "login": login,
                "password": password or "",
            }
            # SSH key detection: check platform name OR secretType field from API
            # (ark-sdk-python uses secretType: "key" for any platform with SSH keys)
            platform_id = account.get("platformId", "")
            secret_type = account.get("secretType", "password").lower()
            is_ssh_key = (platform_id in ("UnixSSHKey", "UnixSSHKeys")
                          or secret_type == "key")
            if is_ssh_key and password:
                # CyberArk exports SSH keys with \r\r\n line endings (a PVWA
                # artifact); normalize to \n so OpenSSH libraries accept the PEM.
                user_record["private_pem_key"] = password.replace("\r\r\n", "\n")
                user_record["password"] = ""
            # Map Database property for database platforms (MSSql, MySQL, Oracle, PostgreSQL)
            database_name = props.get("Database", "")
            if database_name and record_type == "pamDatabase":
                user_record["connect_database"] = database_name
            # Map DistinguishedName for Active Directory accounts
            dn = props.get("DistinguishedName", "") or props.get("distinguishedName", "")
            if dn:
                user_record["distinguished_name"] = dn
            # Rotation settings — derive from CyberArk secretManagement state
            secret_mgmt = account.get("secretManagement", {})
            cpm_enabled = secret_mgmt.get("automaticManagementEnabled", True)
            if mapping.get("rotation"):
                user_record["rotation_settings"] = {
                    "rotation": mapping["rotation"],
                    "enabled": "on" if cpm_enabled else "off",
                    "schedule": {"type": "on-demand"},
                }
                reason = secret_mgmt.get("manualManagementReason", "")
                if not cpm_enabled:
                    existing = user_record.get("notes", "")
                    line = f"CyberArk CPM disabled: {reason}"
                    user_record["notes"] = f"{existing}\n{line}".strip()
                cpm_status = secret_mgmt.get("status", "")
                if cpm_status and cpm_status.lower() == "failure":
                    existing = user_record.get("notes", "")
                    line = f"CyberArk CPM status: FAILURE ({reason})"
                    user_record["notes"] = f"{existing}\n{line}".strip()
            if password:
                user_record["managed"] = True

            resource_title = title or address or raw_name
            resource = {
                "type": record_type,
                "title": resource_title,
                "host": address,
                "port": str(port) if port else "",
                "users": [user_record],
            }
            # Map LogonDomain → domain_name on resource (Windows AD domain)
            if logon_domain and record_type == "pamMachine":
                resource["domain_name"] = logon_domain
            if mapping.get("protocol"):
                resource["pam_settings"] = {
                    "options": {
                        "rotation": "on" if cpm_enabled else "off",
                        "connections": "on",
                        "tunneling": "off",
                        "graphical_session_recording": "off",
                    },
                    "connection": {
                        "protocol": mapping["protocol"],
                        "port": str(port) if port else "",
                        "launch_credentials": user_record["title"],
                    }
                }
            return resource

        logging.warning('Unsupported record_type "%s" for platform "%s" — account skipped',
                        record_type, account.get("platformId", "Unknown"))
        return None

    def is_incomplete(self, account: dict) -> Tuple[bool, str]:
        """Check if a CyberArk account is missing required fields for PAM import."""
        reasons = []
        if not account.get("address"):
            reasons.append("missing address/host")
        if not account.get("userName"):
            reasons.append("missing userName")
        if reasons:
            return True, "; ".join(reasons)
        return False, ""


class MasterPolicyMapper:
    """Maps CyberArk Master Policy rules to Keeper PAM Configuration settings."""

    DEFAULTS = {
        "connections": "on",
        "rotation": "on",
        "tunneling": "on",
        "graphical_session_recording": "off",
        "text_session_recording": "off",
        # Keeper-specific features that have no CyberArk Master Policy
        # equivalent — default off so a CyberArk migration doesn't silently
        # enable RBI or AI threat detection on customers who didn't opt in.
        # PamConfigEnvironment defaults RBI to "on", so we set explicitly.
        "remote_browser_isolation": "off",
        "ai_threat_detection": "off",
        "ai_terminate_session_on_detection": "off",
    }

    @staticmethod
    def map_policy(policy_data: Optional[dict]) -> Tuple[dict, List[dict]]:
        """Map Master Policy to PAM config settings.

        Returns (pam_config_updates, unmapped_items).
        """
        if not policy_data or not isinstance(policy_data, dict):
            return dict(MasterPolicyMapper.DEFAULTS), []

        config = dict(MasterPolicyMapper.DEFAULTS)
        unmapped = []

        # Extract rules
        policy_obj = policy_data.get("Policy", policy_data)
        if not isinstance(policy_obj, dict):
            return dict(MasterPolicyMapper.DEFAULTS), []
        rules = {}
        for rule in (policy_obj.get("Rules") or []):
            if isinstance(rule, dict):
                rules[rule.get("RuleName", "")] = rule.get("Active", False)

        # RecordAndSaveSessionActivity → session recording
        if rules.get("RecordAndSaveSessionActivity"):
            config["graphical_session_recording"] = "on"
            config["text_session_recording"] = "on"

        # AllowEPVTransparentConnections → connections
        if rules.get("AllowEPVTransparentConnections"):
            config["connections"] = "on"
        elif "AllowEPVTransparentConnections" in rules:
            config["connections"] = "off"

        # SafeAuditRetention → UNMAPPED
        for rule in (policy_obj.get("Rules") or []):
            if isinstance(rule, dict) and rule.get("RuleName") == "SafeAuditRetention":
                val = rule.get("Value")
                if val is not None:
                    unmapped.append({
                        "category": "Master Policy",
                        "item": f"SafeAuditRetention = {val} days",
                        "action": "Configure audit retention at vault level in Admin Console",
                    })

        # UNMAPPED policy features
        unmapped_rules = {
            "RequireDualControlPasswordAccessApproval": (
                "Dual control approval",
                "Use ticketing integration (ServiceNow/Jira) for approval workflows"
            ),
            "EnforceCheckinCheckoutExclusiveAccess": (
                "Exclusive checkout",
                "Use time-limited record sharing in KeeperPAM"
            ),
            "EnforceOnetimePasswordAccess": (
                "One-time password access",
                "Enable post-use rotation in KeeperPAM rotation settings"
            ),
        }
        for rule_name, (label, action) in unmapped_rules.items():
            if rules.get(rule_name):
                unmapped.append({
                    "category": "Master Policy",
                    "item": f"{label} = Active",
                    "action": action,
                })

        return config, unmapped


class UserTeamMatcher:
    """Matches CyberArk vault users and groups to Keeper users and teams.

    CyberArk users are matched by email (personalDetails.email).
    CyberArk groups are matched by name (groupName).
    Manual overrides via --user-map JSON file.
    Unmatched identities are collected for the ca_users_to_provision.csv report.
    """

    def __init__(self, keeper_users: List[dict] = None,
                 keeper_teams: List[dict] = None,
                 user_map_override: Optional[Dict[str, str]] = None):
        """Initialize matcher.

        Args:
            keeper_users: list of Keeper user dicts with 'username'/'email' keys
            keeper_teams: list of Keeper team dicts with 'name' key
            user_map_override: dict mapping CyberArk username → Keeper email
        """
        # Build lookup tables
        self._user_emails = set()  # lowercase Keeper user emails
        if keeper_users:
            for u in keeper_users:
                email = u.get('email', '') or u.get('username', '')
                if email:
                    self._user_emails.add(email.lower())

        self._team_names = set()  # lowercase Keeper team names
        if keeper_teams:
            for t in keeper_teams:
                name = t.get('name', '') or t.get('team_name', '')
                if name:
                    self._team_names.add(name.lower())

        self._overrides = {}
        if user_map_override:
            self._overrides = {
                str(k).lower(): str(v).lower()
                for k, v in user_map_override.items()
            }

        self.unmatched = []  # list of unmatched member dicts for CSV

    def match_user(self, cyberark_username: str,
                   cyberark_email: str = '',
                   cyberark_groups: str = '') -> Optional[str]:
        """Try to match a CyberArk user to a Keeper user.

        Returns the matched Keeper email or None if not found.
        """
        # Check manual override first
        override = self._overrides.get(cyberark_username.lower())
        if override and override in self._user_emails:
            return override

        # Match by email
        if cyberark_email and cyberark_email.lower() in self._user_emails:
            return cyberark_email.lower()

        # Match by username (might be an email)
        if '@' in cyberark_username and cyberark_username.lower() in self._user_emails:
            return cyberark_username.lower()

        # Not found
        self.unmatched.append({
            'cyberark_username': cyberark_username,
            'cyberark_email': cyberark_email,
            'cyberark_groups': cyberark_groups,
            'keeper_match_found': 'no',
            'keeper_email': '',
            'suggested_action': 'provision_user',
        })
        return None

    def match_team(self, cyberark_group_name: str) -> Optional[str]:
        """Try to match a CyberArk group to a Keeper team.

        Returns the matched Keeper team name or None if not found.
        """
        if cyberark_group_name.lower() in self._team_names:
            return cyberark_group_name
        # Not found
        self.unmatched.append({
            'cyberark_username': cyberark_group_name,
            'cyberark_email': '',
            'cyberark_groups': '(group)',
            'keeper_match_found': 'no',
            'keeper_email': '',
            'suggested_action': 'create_team',
        })
        return None

    def generate_csv(self) -> str:
        """Generate ca_users_to_provision.csv content from unmatched identities.

        Returns CSV as a string (no file I/O — caller writes to file/attachment).
        Uses csv.writer for proper quoting and escaping (prevents formula injection).
        """
        if not self.unmatched:
            return ''
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow(['cyberark_username', 'cyberark_email', 'cyberark_groups',
                         'keeper_match_found', 'keeper_email', 'suggested_action'])
        for row in self.unmatched:
            # Sanitize formula-triggering prefixes (=, +, -, @, \t, \r).
            # Strip leading whitespace first — spreadsheet apps often ignore
            # it when parsing formulas, so " =cmd()" would bypass a naive
            # first-char check.
            def _sanitize(val):
                s = str(val).lstrip()
                if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
                    s = "'" + s  # prefix with single quote to neutralize
                return s
            writer.writerow([
                _sanitize(row.get('cyberark_username', '')),
                _sanitize(row.get('cyberark_email', '')),
                _sanitize(row.get('cyberark_groups', '')),
                row.get('keeper_match_found', 'no'),
                row.get('keeper_email', ''),
                row.get('suggested_action', ''),
            ])
        return output.getvalue().strip()


class PermissionMapper:
    """Maps CyberArk safe member permissions to Keeper shared folder permission tiers.

    CyberArk has 24 granular boolean permissions per safe member (ark-sdk-python).
    Keeper has 4 permission levels: manage_users, manage_records, can_edit, can_share.

    Mapping tiers (cumulative):
      Tier 1 (view):   useAccounts + retrieveAccounts + listAccounts
      Tier 2 (edit):   + addAccounts + updateAccountContent + updateAccountProperties
                        + renameAccounts + deleteAccounts
      Tier 3 (manage): + manageSafe + manageSafeMembers + viewSafeMembers

    Mapped but not tier-affecting (absorbed into higher tiers):
      viewAuditLog, backupSafe, unlockAccounts,
      initiateCPMAccountManagementOperations, specifyNextAccountContent,
      createFolders, deleteFolders, moveAccountsAndFolders

    UNMAPPED permissions (no Keeper equivalent — logged in report):
      accessWithoutConfirmation, requestsAuthorizationLevel1/2
    """

    # All 24 CyberArk permissions from ark-sdk-python ArkPCloudSafeMemberPermissions
    ALL_PERMISSIONS = {
        # Tier 1 — View
        "useAccounts", "retrieveAccounts", "listAccounts",
        # Tier 2 — Edit
        "addAccounts", "updateAccountContent", "updateAccountProperties",
        "renameAccounts", "deleteAccounts",
        # Tier 3 — Manage
        "manageSafe", "manageSafeMembers", "viewSafeMembers",
        # Absorbed into tiers (not tier-determining but tracked)
        "viewAuditLog", "backupSafe", "unlockAccounts",
        "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
        "createFolders", "deleteFolders", "moveAccountsAndFolders",
        # Unmapped — no Keeper equivalent
        "accessWithoutConfirmation",
        "requestsAuthorizationLevel1", "requestsAuthorizationLevel2",
        # CyberArk 13+ additions
        "isExpiredMembershipEnable", "isReadOnly",
    }

    # Permissions that have no Keeper equivalent
    UNMAPPED_PERMISSIONS = {
        "accessWithoutConfirmation",
        "requestsAuthorizationLevel1",
        "requestsAuthorizationLevel2",
    }

    @staticmethod
    def map_permissions(perms: dict) -> dict:
        """Map CyberArk permission booleans to Keeper shared folder permissions.

        Returns dict with keys: manage_users, manage_records, can_edit, can_share.
        """
        if not isinstance(perms, dict):
            return {"manage_users": False, "manage_records": False,
                    "can_edit": False, "can_share": False}

        # Tier 1: View — can list and use accounts
        has_view = (perms.get("useAccounts", False)
                    and perms.get("listAccounts", False))

        # Tier 2: Edit — can modify account content
        has_edit = (has_view
                    and perms.get("addAccounts", False)
                    and (perms.get("updateAccountContent", False)
                         or perms.get("updateAccountProperties", False)))

        # Tier 3: Manage — full safe administration
        has_manage = (has_edit
                      and perms.get("manageSafe", False)
                      and perms.get("manageSafeMembers", False))

        return {
            "manage_users": has_manage,
            "manage_records": has_edit or has_manage,
            "can_edit": has_edit or has_manage,
            "can_share": has_manage,
        }

    @staticmethod
    def get_unmapped_permissions(perms: dict) -> List[str]:
        """Return list of CyberArk permissions that have no Keeper equivalent."""
        if not isinstance(perms, dict):
            return []
        return [
            p for p in PermissionMapper.UNMAPPED_PERMISSIONS
            if perms.get(p, False)
        ]

    @staticmethod
    def map_member(member: dict) -> dict:
        """Map a CyberArk safe member to a Keeper shared folder permission entry.

        Returns dict with: name, member_type ('user'|'team'), permissions dict,
        unmapped list, and the raw memberName for matching.
        """
        name = member.get("memberName", "")
        member_type = member.get("memberType", "User")
        perms = member.get("permissions", {})

        # Warn on unexpected member types (CyberArk currently uses "User" and "Group")
        if member_type not in ("User", "Group"):
            logging.warning('Unexpected member type "%s" for member "%s" — treating as user',
                            member_type, name)

        keeper_perms = PermissionMapper.map_permissions(perms)
        unmapped = PermissionMapper.get_unmapped_permissions(perms)

        return {
            "name": name,
            "member_type": "team" if member_type == "Group" else "user",
            "permissions": keeper_perms,
            "unmapped_permissions": unmapped,
        }


class SafeFolderMapper:
    """Maps CyberArk Safe names to Keeper folder paths with deduplication."""

    def __init__(self, mode: str = "flat"):
        self.mode = mode
        self._seen = {}  # sanitized name → count (for dedup)
        self._cache = {}  # raw safe name → resolved folder path

    def map_safe(self, safe_name: str, project_name: str) -> str:
        """Returns folder_path for use in pam_data extend JSON.

        Deduplicates colliding names with #N suffix (e.g. 'Safe #2').
        """
        if self.mode == "flat":
            return ""
        # Return cached result if already mapped (same safe = same folder)
        if safe_name in self._cache:
            return self._cache[safe_name]

        if self.mode == "exact":
            sanitized = safe_name
        elif self.mode == "ksm":
            sanitized = re.sub(r"[^\w\s\-]", "", safe_name)
            sanitized = re.sub(r"\s+", " ", sanitized).strip()
        else:
            sanitized = safe_name

        # Deduplicate: if two safes sanitize to the same name, add #N suffix
        if sanitized in self._seen:
            self._seen[sanitized] += 1
            suffix = f" #{self._seen[sanitized]}"
            if self.mode == "ksm":
                max_base = MAX_SAFE_NAME_LENGTH - len(suffix)
                result = f"{sanitized[:max_base]}{suffix}"
            else:
                result = f"{sanitized}{suffix}"
        else:
            self._seen[sanitized] = 1
            result = sanitized[:MAX_SAFE_NAME_LENGTH] if self.mode == "ksm" else sanitized

        self._cache[safe_name] = result
        return result


class AdaptiveThrottler:
    """Adaptive rate limiter for batched vault writes."""

    def __init__(self, base_delay: float = 0.5, max_delay: float = 5.0, batch_size: int = 100):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.batch_size = batch_size
        self.current_delay = base_delay
        self._recent_errors = 0
        self._recent_successes = 0

    def record_response(self, duration_ms: float, success: bool):
        if success:
            self._recent_successes += 1
            self._recent_errors = max(0, self._recent_errors - 1)
            if duration_ms < 1000 and self.current_delay > self.base_delay:
                self.current_delay = max(self.base_delay, self.current_delay * 0.8)
        else:
            self._recent_errors += 1
            self.current_delay = min(self.max_delay, self.current_delay * 1.5)

    def wait(self):
        if self.current_delay > 0:
            time.sleep(self.current_delay)

def exclude_system_safes(safes: List[dict], include_system: bool = False) -> List[dict]:
    """Remove CyberArk system/internal safes from the list.

    System safes (VaultInternal, PVWAConfig, etc.) don't contain
    user-managed accounts and should be excluded from migration.
    Override with include_system=True (--include-system-safes flag).
    """
    if include_system:
        return safes
    before = len(safes)
    system_lower = {s.lower() for s in SYSTEM_SAFES}
    filtered = [s for s in safes if s.get("safeName", "").lower() not in system_lower]
    excluded = before - len(filtered)
    if excluded > 0:
        logging.info('Excluded %d system safe(s) from migration', excluded)
    return filtered


def apply_safe_filter(safes: List[dict], include: Optional[str] = None,
                      exclude: Optional[str] = None) -> List[dict]:
    """Filter safes by --safes (include) and --exclude-safes patterns.

    Patterns are comma-separated and support glob matching.
    """
    if include:
        patterns = [p.strip() for p in include.split(",") if p.strip()]
        safes = [s for s in safes if any(fnmatch.fnmatch(s["safeName"], p) for p in patterns)]
    if exclude:
        patterns = [p.strip() for p in exclude.split(",") if p.strip()]
        safes = [s for s in safes if not any(fnmatch.fnmatch(s["safeName"], p) for p in patterns)]
    return safes


def sanitize_safe_name(name: str) -> str:
    """Sanitize a CyberArk safe name for use as a Keeper folder name.

    - Strip/replace characters not allowed in folder names
    - Truncate to MAX_SAFE_NAME_LENGTH
    - Handle dedup by appending suffix if needed
    """
    # Strip control characters (null bytes, newlines, etc.)
    safe = re.sub(r'[\x00-\x1f\x7f]', '', name)
    # Strip path separators
    safe = safe.replace('/', '_').replace('\\', '_').replace('..', '_')
    # Remove leading/trailing whitespace
    safe = safe.strip()
    # Truncate to max length
    if len(safe) > MAX_SAFE_NAME_LENGTH:
        safe = safe[:MAX_SAFE_NAME_LENGTH].rstrip()
    return safe or 'Unnamed-Safe'


def deduplicate_safe_names(safes: List[dict]) -> Dict[str, str]:
    """Build a mapping of safeUrlId → sanitized folder name, deduplicating collisions.

    Returns dict: { safeUrlId: "FolderName" }
    """
    name_map = {}  # safeUrlId → sanitized name
    seen = {}      # sanitized name → count

    for safe in safes:
        url_id = safe.get("safeUrlId", safe.get("safeName", ""))
        raw_name = safe.get("safeName", url_id)
        sanitized = sanitize_safe_name(raw_name)

        if sanitized in seen:
            seen[sanitized] += 1
            suffix = f" #{seen[sanitized]}"
            # Trim base name to fit suffix within MAX_SAFE_NAME_LENGTH
            max_base = MAX_SAFE_NAME_LENGTH - len(suffix)
            sanitized = f"{sanitized[:max_base]}{suffix}"
        else:
            seen[sanitized] = 1

        name_map[url_id] = sanitized

    return name_map


def resolve_linked_accounts(client: 'CyberArkPVWAClient',
                            account: dict) -> List[dict]:
    """Resolve linked accounts (logon, reconcile, enable) for an account.

    Fetches the full account details to get linkedAccounts, then fetches
    each linked account and maps it as a pamUser record.

    Returns list of pamUser dicts with role annotations.
    """
    account_id = account.get("id", "")
    details = client.fetch_account_details(account_id)
    if not details:
        return []

    linked = details.get("linkedAccounts") or {}
    if not isinstance(linked, dict):
        logging.warning('Unexpected linkedAccounts type: %s for account %s',
                        type(linked).__name__, account_id)
        return []
    result = []

    for role, link_data in linked.items():
        if not isinstance(link_data, dict) or not link_data.get("id"):
            continue
        role_name = role.replace("Account", "").lower()  # logonAccount → logon

        # Fetch the linked account's password
        linked_id = link_data["id"]
        # Validate linked account ID format (same check as fetch_account_details)
        if not re.match(r'^[a-zA-Z0-9_]+$', str(linked_id)):
            logging.warning('Invalid linked account ID: %s — skipping',
                            re.sub(r'[^a-zA-Z0-9_]', '?', str(linked_id)))
            continue
        linked_name = link_data.get("name", "")
        linked_safe = link_data.get("safeName", account.get("safeName", ""))
        # Note: skip_all dict not passed here — linked account password
        # failures don't share the "Skip All" state with the main loop.
        # This is acceptable since linked accounts are typically few per resource.
        password = client.retrieve_password(linked_id, linked_name, linked_safe)

        # Build pamUser record for the linked account
        user_title = f"{linked_name} ({role_name} account)"
        linked_user = {
            "type": "pamUser",
            "title": user_title,
            "login": link_data.get("userName", linked_name),
            "password": password or "",
            "notes": f"CyberArk role: {role_name} account\n"
                     f"Linked to: {account.get('name', account_id)}\n"
                     f"Source safe: {linked_safe}",
            "_ca_role": role_name,  # Internal: logon, reconcile, or enable
        }
        result.append(linked_user)
        logging.info('Resolved linked %s account: %s', role_name, user_title)

    return result


def pick_launch_credentials(linked_users: List[dict]) -> Optional[str]:
    """Pick which linked account populates Keeper's launch_credentials slot.

    CyberArk PSM uses the logonAccount to establish the initial connection
    (e.g. SSH as a less-privileged service account), then switches (sudo/su)
    to the target account. Keeper's launch_credentials is the connection
    credential, so the logon account is its natural fit when present.

    Returns the logon account's title, or None if no logon is linked.
    """
    for lu in linked_users:
        if lu.get("_ca_role") == "logon":
            return lu.get("title")
    return None


def pick_admin_credentials(linked_users: List[dict]) -> Tuple[Optional[str], Optional[str]]:
    """Pick which linked account populates Keeper's administrative_credentials slot.

    CyberArk has three linked-account roles (logon, reconcile, enable) but
    Keeper resources have only one administrative_credentials slot. Reconcile
    is preferred because it is the account CyberArk CPM uses for password
    rotation recovery — the most common privileged-management path. Enable
    is used as a fallback when no reconcile account is linked.

    Returns (title, role) of the chosen account, or (None, None) if none present.
    """
    for lu in linked_users:
        if lu.get("_ca_role") == "reconcile":
            return lu.get("title"), "reconcile"
    for lu in linked_users:
        if lu.get("_ca_role") == "enable":
            return lu.get("title"), "enable"
    return None, None


def detect_dual_account(account: dict) -> Optional[Dict[str, str]]:
    """Detect if an account is part of a dual-account/rotational group.

    CyberArk dual accounts have VirtualUserName and/or GroupPlatformID
    in their platformAccountProperties.

    Returns dict of custom fields to add, or None if not a dual account.
    """
    if not isinstance(account, dict):
        return None
    props = account.get("platformAccountProperties") or {}
    virtual_user = props.get("VirtualUserName", "")
    group_platform = props.get("GroupPlatformID", "")
    index = props.get("Index", "")

    if not virtual_user and not group_platform:
        return None

    fields = {}
    if virtual_user:
        fields["ca_virtual_username"] = virtual_user
    if group_platform:
        fields["ca_dual_account_group"] = group_platform
    if index:
        fields["ca_dual_account_index"] = index

    return fields


def build_shared_folder_permissions(safe_member_map: Dict[str, List[dict]],
                                    user_team_matcher: Optional['UserTeamMatcher'] = None,
                                    ) -> dict:
    """Aggregate safe member permissions into Keeper shared folder permission format.

    Merges permissions across all safes — if a user appears in multiple safes,
    they get the highest permission tier across all of them.

    Returns dict with 'shared_folder_resources' and 'shared_folder_users' keys
    matching the format expected by edit.py get_folder_permissions().
    """
    if not safe_member_map:
        return {}

    # Aggregate: for each member, take the highest permission across safes
    member_perms = {}  # (name, member_type) → highest permissions dict
    for safe_id, members in safe_member_map.items():
        for m in members:
            name = m.get("name", "")
            mtype = m.get("member_type", "user")
            perms = m.get("permissions", {})
            key = (name.lower(), mtype)

            if key not in member_perms:
                member_perms[key] = {"name": name, "member_type": mtype, "permissions": dict(perms)}
            else:
                # Merge — take the more permissive value for each field
                existing = member_perms[key]["permissions"]
                for field in ("manage_users", "manage_records", "can_edit", "can_share"):
                    if perms.get(field, False):
                        existing[field] = True

    # Build permission entries, matching to Keeper users/teams if possible
    permission_entries = []
    for (name_lower, mtype), entry in member_perms.items():
        name = entry["name"]
        perms = entry["permissions"]

        # Try to match to a Keeper user or team
        matched_name = None
        if user_team_matcher:
            if mtype == "user":
                matched_name = user_team_matcher.match_user(name)
            elif mtype == "team":
                matched_name = user_team_matcher.match_team(name)

        if not matched_name:
            continue  # Skip unmatched — they'll appear in the CSV report

        perm_entry = {
            "name": matched_name,
            "manage_users": perms.get("manage_users", False),
            "manage_records": perms.get("manage_records", False),
        }
        permission_entries.append(perm_entry)

    if not permission_entries:
        return {}

    # Both shared folders get the same permission set (resources and users folders)
    folder_perms = {
        "manage_users": True,
        "manage_records": True,
        "can_edit": True,
        "can_share": True,
        "permissions": permission_entries,
    }
    return {
        "shared_folder_resources": dict(folder_perms),
        "shared_folder_users": dict(folder_perms),
    }


def validate_import_data(resources: List[dict], users: List[dict]) -> List[str]:
    """Pre-import validation. Returns list of warning strings."""
    warnings = []

    # Resources missing host/address
    for r in resources:
        if not r.get("host"):
            warnings.append(f'Resource "{r.get("title", "?")}" has no host/address')

    # Nested users missing password (will be created without credentials)
    no_pw = []
    for r in resources:
        for u in r.get("users", []):
            if not u.get("password") and not u.get("private_pem_key"):
                no_pw.append(u.get("title", "?"))
    # External users missing password
    for u in users:
        if not u.get("password") and not u.get("private_pem_key"):
            no_pw.append(u.get("title", "?"))
    if no_pw:
        warnings.append(f'{len(no_pw)} user(s) have no password or SSH key '
                        f'— will be created without credentials')

    # External (unnested) users without resource linkage
    if users:
        warnings.append(f'{len(users)} standalone login record(s) not linked to a resource')

    # Rotation enabled but no password (rotation will fail)
    for r in resources:
        for u in r.get("users", []):
            rs = u.get("rotation_settings", {})
            if (rs.get("enabled") == "on"
                    and not u.get("password")
                    and not u.get("private_pem_key")):
                warnings.append(
                    f'User "{u.get("title", "?")}" has rotation enabled but '
                    f'no password/key — rotation will fail until credentials are set')

    return warnings


def build_import_json(project_name: str, gateway_name: Optional[str],
                      resources: List[dict], users: List[dict],
                      safe_member_map: Optional[Dict[str, List[dict]]] = None,
                      user_team_matcher: Optional['UserTeamMatcher'] = None,
                      master_policy_config: Optional[dict] = None,
                      ) -> dict:
    """Build the pam project import JSON from mapped records."""
    mp = master_policy_config or {}
    pam_config = {
        "environment": "local",
        "title": f"{project_name} Configuration",
        "connections": mp.get("connections", "on"),
        "rotation": mp.get("rotation", "on"),
        "tunneling": mp.get("tunneling", "on"),
        "graphical_session_recording": mp.get("graphical_session_recording", "off"),
        "text_session_recording": mp.get("text_session_recording", "off"),
        # Keeper-specific features set explicitly so PamConfigEnvironment
        # doesn't fall back to its on/off defaults that don't match the
        # CyberArk migration intent.
        "remote_browser_isolation": mp.get("remote_browser_isolation", "off"),
        "ai_threat_detection": mp.get("ai_threat_detection", "off"),
        "ai_terminate_session_on_detection": mp.get("ai_terminate_session_on_detection", "off"),
        "default_rotation_schedule": {"type": "on-demand"},
    }
    if gateway_name:
        pam_config["gateway_name"] = gateway_name

    result = {
        "project": project_name,
        "pam_configuration": pam_config,
        "pam_data": {
            "resources": resources,
            "users": users,
        },
    }

    # Wire safe member permissions into shared folder structure
    if safe_member_map:
        sf_perms = build_shared_folder_permissions(safe_member_map, user_team_matcher)
        if sf_perms:
            result.update(sf_perms)

    return result


def build_extend_json(resources: List[dict], users: List[dict]) -> dict:
    """Build the pam project extend JSON (pam_data only)."""
    return {
        "pam_data": {
            "resources": resources,
            "users": users,
        }
    }


def strip_credentials(data: dict):
    """Remove passwords from import JSON for safe --output without --include-credentials."""
    pam_data = data.get("pam_data", {})
    for user in pam_data.get("users", []):
        if "password" in user:
            user["password"] = "***"
    for resource in pam_data.get("resources", []):
        for user in resource.get("users", []):
            if "password" in user:
                user["password"] = "***"


def format_duration(seconds: float) -> str:
    """Format seconds as 'Xm Ys'. Handles negative, inf, nan."""
    if math.isnan(seconds) or math.isinf(seconds):
        return "N/A"
    seconds = max(0, min(seconds, 999999))  # clamp to ~11.5 days max
    m = int(seconds) // 60
    s = int(seconds) % 60
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def build_report(project_name: str, safes_processed: int, total_accounts: int,
                 resource_counts: Dict[str, Dict[str, int]],
                 platform_counts: Dict[str, Dict[str, Any]],
                 skipped: List[dict], incomplete_count: int,
                 duration: float, project_result: Optional[dict] = None,
                 unmapped_platforms: Optional[Dict[str, int]] = None,
                 unmapped_items: Optional[List[dict]] = None,
                 server: str = '') -> str:
    """Build structured post-import report matching the spec."""
    lines = []
    lines.append('=' * 60)
    lines.append(f' CyberArk PAM → KeeperPAM Migration Report')
    lines.append(f' {project_name}')
    lines.append('=' * 60)
    lines.append('')

    # Source summary
    lines.append(' SOURCE SUMMARY')
    lines.append(' ' + '-' * 40)
    if server:
        lines.append(f'   Server:           {server}')
    lines.append(f'   Safes processed:  {safes_processed}')
    lines.append(f'   Accounts found:   {total_accounts}')
    lines.append('')

    # Project assets
    if project_result:
        lines.append(' PROJECT ASSETS')
        lines.append(' ' + '-' * 40)
        gw = project_result.get("gateway", {})
        if gw:
            gw_token = gw.get('gateway_token', '')
            lines.append(f'   Gateway:    {gw.get("gateway_name", "N/A")} ({gw.get("gateway_uid", "N/A")})')
        ksm = project_result.get("ksm_app", {})
        if ksm:
            lines.append(f'   KSM App:    {ksm.get("app_uid", "N/A")}')
        config = project_result.get("config_uid", "")
        if config:
            lines.append(f'   Config UID: {config}')
        folders = project_result.get("folders", {})
        if folders:
            lines.append(f'   Resources:  {folders.get("resources_folder", "N/A")} ({folders.get("resources_folder_uid", "N/A")})')
            lines.append(f'   Users:      {folders.get("users_folder", "N/A")} ({folders.get("users_folder_uid", "N/A")})')
        lines.append('')

    # Import results
    lines.append(' IMPORT RESULTS')
    lines.append(' ' + '-' * 40)
    if not resource_counts:
        resource_counts = {}
    total_ok = total_skip = total_err = 0
    for rtype in ("pamMachine", "pamDatabase", "pamUser", "login"):
        counts = resource_counts.get(rtype, {"ok": 0, "skip": 0, "err": 0})
        lines.append(f'   {rtype:18s} {counts["ok"]:>4d} ok  {counts["skip"]:>4d} skip  {counts["err"]:>4d} err')
        total_ok += counts["ok"]
        total_skip += counts["skip"]
        total_err += counts["err"]
    lines.append(f'   {"TOTAL":18s} {total_ok:>4d} ok  {total_skip:>4d} skip  {total_err:>4d} err')
    lines.append(f'   Duration:   {format_duration(duration)}')
    lines.append('')

    # Platform mapping
    if platform_counts:
        lines.append(' PLATFORM MAPPING')
        lines.append(' ' + '-' * 40)
        for pid, info in sorted(platform_counts.items()):
            rotation = info.get("rotation", "N/A")
            count = info.get("count", 0)
            marker = ""
            if unmapped_platforms and pid in unmapped_platforms:
                marker = " ← use --platform-map"
                rotation = "UNMAPPED"
            lines.append(f'   {pid:20s} → {rotation:12s} ({count} accounts){marker}')
        lines.append('')

    # Skipped accounts
    if skipped:
        password_failed = sum(1 for s in (skipped or []) if s.get("reason") == "password retrieval failed")
        cpm_disabled = sum(1 for s in (skipped or []) if s.get("reason") == "CPM disabled")
        lines.append(' SKIPPED ACCOUNTS')
        lines.append(' ' + '-' * 40)
        if cpm_disabled:
            lines.append(f'   Manual mgmt (CPM disabled):  {cpm_disabled}')
        if password_failed:
            lines.append(f'   Password retrieval failed:   {password_failed}')
        if incomplete_count:
            lines.append(f'   Incomplete (missing fields): {incomplete_count}')
        lines.append('')

    # UNMAPPED section
    if unmapped_items:
        lines.append(' UNMAPPED — REQUIRES MANUAL ACTION')
        lines.append(' ' + '-' * 40)
        by_category = {}  # type: Dict[str, List[dict]]
        for item in unmapped_items:
            cat = item.get("category", "Other")
            by_category.setdefault(cat, []).append(item)
        for cat, items in sorted(by_category.items()):
            lines.append(f'   {cat}:')
            for item in items:
                lines.append(f'     {item.get("item", "")}')
                lines.append(f'       Action: {item.get("action", "")}')
            lines.append('')

    # Gateway deployment
    gw_token = ''
    if project_result:
        gw_token = project_result.get("gateway", {}).get("gateway_token", "")
    if gw_token:
        lines.append(' GATEWAY DEPLOYMENT')
        lines.append(' ' + '-' * 40)
        lines.append(f'   Access Token: {gw_token}')
        lines.append('')
        lines.append(f'   docker run -d --name keeper-gateway \\')
        lines.append(f'     -e GATEWAY_CONFIG="{gw_token}" \\')
        lines.append(f'     -e ACCEPT_EULA=Y --shm-size=2g \\')
        lines.append(f'     --restart unless-stopped keeper/gateway:latest')
        lines.append('')

    # Next steps
    lines.append(' NEXT STEPS')
    lines.append(' ' + '-' * 40)
    lines.append(f'   1. Review UNMAPPED section — action each item')
    lines.append(f'   2. Verify: pam gateway list')
    lines.append(f'   3. Cleanup: pam project cyberark-cleanup --name "{project_name}"')
    lines.append('')

    # Command (redacted)
    lines.append(' COMMAND (redacted)')
    lines.append(' ' + '-' * 40)
    cmd = f'pam project cyberark-import {server}'
    if project_name:
        cmd += f' --name "{project_name}"'
    lines.append(f'   {cmd}')
    lines.append('')
    lines.append('=' * 60)

    return "\n".join(lines)
