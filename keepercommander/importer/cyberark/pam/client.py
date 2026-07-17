#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import copy
import csv
import fnmatch
import io
import ipaddress
import json
import logging
import math
import re
import sys
from os import environ, path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlparse

import requests as _requests_module

from .constants import MAX_FETCH_RECORDS, VALID_LOGON_TYPES, IDENTITY_LOGIN_SUCCESS
from .ui import _esc


def _facade():
    """Return the public facade module (supports unittest @patch targets)."""
    return sys.modules['keepercommander.importer.cyberark.cyberark_pam']


class _FacadeAttr:
    """Lazy proxy so ``@patch('...cyberark_pam.requests')`` affects this module."""

    __slots__ = ('_name',)

    def __init__(self, name: str):
        self._name = name

    def _target(self):
        return getattr(_facade(), self._name)

    def __getattr__(self, item):
        return getattr(self._target(), item)

    def __call__(self, *args, **kwargs):
        return self._target()(*args, **kwargs)


requests = _FacadeAttr('requests')
socket = _FacadeAttr('socket')
time = _FacadeAttr('time')
HTML = _FacadeAttr('HTML')
print_formatted_text = _FacadeAttr('print_formatted_text')
prompt = _FacadeAttr('prompt')
button_dialog = _FacadeAttr('button_dialog')
Style = _FacadeAttr('Style')


class CyberArkPVWAClient:
    """Handles authentication and API calls to CyberArk PVWA."""

    DELAY = 0.025
    TIMEOUT = 10
    # CyberArk Identity out-of-band (push / SMS / email) MFA polling settings.
    IDENTITY_OOB_POLL_INTERVAL = 2     # seconds between push-notification polls
    IDENTITY_OOB_POLL_TIMEOUT = 120    # give up on an unanswered push after this many seconds
    ENDPOINTS = {
        "accounts": "Accounts",
        "account_password": "Accounts/{account_id}/Password/Retrieve",
        "logon": "Auth/{type}/Logon",
        "safes": "Safes",
        "platforms": "Platforms",
        "platform_details": "Platforms/{platform_id}",
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
        hostname = host.split(":")[0] if ":" in host else host
        if hostname in ("localhost", "127.0.0.1", "0.0.0.0", "::1", ""):
            raise ValueError(f"PVWA host '{host}' targets a local address and is not allowed")
        # Validate hostname format (alphanumeric, dots, hyphens only)
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$', hostname):
            raise ValueError(f"PVWA host '{hostname}' contains invalid characters")
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                raise ValueError(f"PVWA host '{host}' is a private/reserved IP and is not allowed")
            return
        except ValueError as e:
            if "is not allowed" in str(e):
                raise
            pass
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
        except (_requests_module.RequestException, ValueError, KeyError):
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
        """Authenticate to CyberArk Privilege Cloud (ISPSS).

        Two methods are supported:
          1. Service account — OAuth2 ``client_credentials`` against
             ``/oauth2/platformtoken`` (non-interactive, no MFA).
          2. Interactive user login with MFA / 2FA via the CyberArk Identity
             ``StartAuthentication`` / ``AdvanceAuthentication`` flow.

        Both produce a Bearer token that the Privilege Cloud REST API accepts.
        The method is selected via the ``KEEPER_CYBERARK_AUTH_METHOD`` env var
        (``service`` / ``interactive``) or an interactive prompt.
        """
        id_host = self._resolve_identity_host()
        if not id_host:
            return False
        if self._choose_cloud_auth_method() == "interactive":
            return self._auth_privilege_cloud_interactive(id_host)
        return self._auth_privilege_cloud_service(id_host)

    def _resolve_identity_host(self) -> Optional[str]:
        """Resolve the CyberArk Identity host for the configured tenant.

        Tenant ID formats accepted (aligned with cyberark_portal discovery):
          - 'abc1234'          → abc1234.id.cyberark.cloud (short subdomain ID)
          - 'mycompany'        → mycompany.cyberark.cloud (named tenant)
          - 'abc1234.id'       → abc1234.id.cyberark.cloud (already qualified)
          - 'https://...'      → extracted hostname used directly
          - 'tenant.my.idaptive.app' → tenant.my.idaptive.app (legacy Idaptive)
        """
        id_tenant_raw = environ.get("KEEPER_CYBERARK_ID_TENANT") or prompt("CyberArk Identity Tenant ID: ")
        id_tenant_raw = id_tenant_raw.strip()
        if id_tenant_raw.startswith("https://"):
            id_tenant_raw = id_tenant_raw[len("https://"):]
        if id_tenant_raw.startswith("http://"):
            id_tenant_raw = id_tenant_raw[len("http://"):]
        id_tenant_raw = id_tenant_raw.rstrip("/")

        if "." in id_tenant_raw:
           
            id_host = id_tenant_raw
            # But for the OAuth2 URL we need *.cyberark.cloud domain
            if id_tenant_raw.endswith(".my.idaptive.app"):
                # Legacy Idaptive — extract subdomain for cyberark.cloud OAuth2
                id_host = id_tenant_raw.split(".")[0] + ".id.cyberark.cloud"
                logging.info("Legacy Idaptive tenant detected, using %s for OAuth2", id_host)
            elif not id_tenant_raw.endswith(".cyberark.cloud"):
                id_host = id_tenant_raw.split(".")[0] + ".cyberark.cloud"
        else:
            id_tenant = id_tenant_raw
            if re.match(r"^[A-Za-z]{3}\d{4}$", id_tenant):
                id_tenant += ".id"
            id_host = f"{id_tenant}.cyberark.cloud"

        # Validate the base portion (before first dot)
        base_part = id_host.split(".")[0]
        if not re.match(r'^[a-zA-Z0-9]+$', base_part):
            print_formatted_text(HTML("<ansired>Invalid tenant ID format</ansired>"))
            return None

        # Platform discovery — resolve tenant to correct identity endpoint
        discovered_host = self._discover_identity_endpoint(base_part)
        if discovered_host:
            id_host = discovered_host
            logging.info("Platform discovery resolved tenant to %s", id_host)
        return id_host

    @staticmethod
    def _choose_cloud_auth_method() -> str:
        """Return 'service' or 'interactive' for Privilege Cloud authentication.
        """
        method = (environ.get("KEEPER_CYBERARK_AUTH_METHOD") or "").strip().lower()
        if method in ("interactive", "identity", "user", "mfa", "2fa", "up"):
            return "interactive"
        if method in ("service", "service_account", "oauth", "oauth2", "client_credentials"):
            return "service"
        print_formatted_text(HTML(
            "\nCyberArk Privilege Cloud authentication method:\n"
            "  <b>[1]</b> Service account (OAuth2 client credentials)\n"
            "  <b>[2]</b> User login with MFA / 2FA (CyberArk Identity)"
        ))
        try:
            choice = prompt("Select authentication method [1/2] (default 1): ").strip()
        except (EOFError, KeyboardInterrupt):
            return "service"
        return "interactive" if choice == "2" else "service"

    def _auth_privilege_cloud_service(self, id_host: str) -> bool:
        """Authenticate to Privilege Cloud via OAuth2 service account (no MFA)."""
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
        except _requests_module.RequestException as e:
            print_formatted_text(HTML(f"OAuth2 request <ansired>failed</ansired>: connection error"))
            logging.debug(f"OAuth2 connection error: {type(e).__name__}")
            return False
        if response.status_code != 200:
            print_formatted_text(HTML(
                f"OAuth2 authorization token request <ansired>failed</ansired> with status code <b>{response.status_code}</b>"
            ))
            print_formatted_text(HTML(
                "<ansiyellow>Tip:</ansiyellow> the OAuth2 client-credentials flow only works for "
                "CyberArk <b>service accounts</b>. To sign in as a regular user with MFA / 2FA, "
                "re-run and choose authentication method <b>2</b> "
                "(or set <i>KEEPER_CYBERARK_AUTH_METHOD=interactive</i>)."
            ))
            return False
        try:
            self.auth_token = f"Bearer {response.json()['access_token']}"
        except (KeyError, ValueError):
            print_formatted_text(HTML("<ansired>Failed to parse OAuth2 response</ansired>"))
            print_formatted_text(HTML(
                "<ansiyellow>Tip:</ansiyellow> the OAuth2 client-credentials flow only works for "
                "CyberArk <b>service accounts</b>. To sign in as a regular user with MFA / 2FA, "
                "re-run and choose authentication method <b>2</b> "
                "(or set <i>KEEPER_CYBERARK_AUTH_METHOD=interactive</i>)."
            ))
            return False
        print_formatted_text(HTML("Log on <ansigreen>successful</ansigreen>"))
        return True

    def _auth_privilege_cloud_interactive(self, id_host: str) -> bool:
        """Authenticate to Privilege Cloud as an interactive user with MFA / 2FA.
        """
        identity_base_url = f"https://{id_host}"
        tenant_name = id_host.split(".")[0]
        username = environ.get("KEEPER_CYBERARK_USERNAME") or prompt("CyberArk username: ")

        headers = {"X-IDAP-NATIVE-CLIENT": "true"}
        start_payload = {"TenantId": tenant_name, "User": username, "Version": "1.0"}
        identity_base_url, result = self._start_identity_authentication(
            identity_base_url, start_payload, headers,
        )
        if result is None:
            return False

        if result.get("IdpRedirectUrl") or result.get("IdpRedirectShortUrl"):
            print_formatted_text(HTML(
                "<ansired>This account signs in through SSO / an external identity provider</ansired>, "
                "which the interactive importer does not support. Use a CyberArk service account "
                "(authentication method <b>1</b>) instead."
            ))
            return False

        session_id = result.get("SessionId")
        challenges = result.get("Challenges") or []
        if not session_id or not challenges:
            print_formatted_text(HTML("<ansired>Unexpected authentication response from CyberArk Identity</ansired>"))
            logging.debug("StartAuthentication result missing SessionId/Challenges")
            return False

        password = environ.get("KEEPER_CYBERARK_PASSWORD")
        advance_result = None
        for challenge in challenges:
            mechanisms = challenge.get("Mechanisms") or []
            if not mechanisms:
                continue
            mechanism = self._select_identity_mechanism(mechanisms)
            if mechanism is None:
                return False
            advance_result = self._answer_identity_mechanism(
                identity_base_url, tenant_name, session_id, mechanism, password=password,
            )
            if advance_result is None:
                return False
            if advance_result.get("Summary") == IDENTITY_LOGIN_SUCCESS:
                break

        if not advance_result or advance_result.get("Summary") != IDENTITY_LOGIN_SUCCESS:
            summary = (advance_result or {}).get("Summary") or "unknown"
            print_formatted_text(HTML(
                f"<ansired>Authentication did not complete successfully</ansired> (status: {_esc(summary)})"
            ))
            return False

        token = advance_result.get("Token")
        if not token:
            print_formatted_text(HTML("<ansired>CyberArk Identity did not return a session token</ansired>"))
            return False
        self.auth_token = f"Bearer {token}"
        print_formatted_text(HTML("Log on <ansigreen>successful</ansigreen>"))
        return True

    def _start_identity_authentication(self, identity_base_url: str, start_payload: dict,
                                         headers: dict) -> Tuple[Optional[str], Optional[dict]]:
        """POST ``/Security/StartAuthentication``, following HTTP and pod redirects.
        """
        url = f"{identity_base_url}/Security/StartAuthentication"
        for _ in range(4):
            try:
                response = requests.post(
                    url, json=start_payload, headers=headers,
                    timeout=self.TIMEOUT, allow_redirects=False,
                )
            except _requests_module.RequestException:
                print_formatted_text(HTML("Authentication request <ansired>failed</ansired>: connection error"))
                logging.debug("StartAuthentication connection error", exc_info=True)
                return None, None

            if response.status_code in (301, 302, 303, 307, 308):
                redirect_url = response.headers.get("Location", "")
                if redirect_url:
                    parsed = urlparse(urljoin(identity_base_url, redirect_url))
                    if parsed.hostname:
                        identity_base_url = f"https://{parsed.hostname}"
                        url = f"{identity_base_url}/Security/StartAuthentication"
                        logging.info(
                            "StartAuthentication redirected; retrying on %s", identity_base_url,
                        )
                        continue
                print_formatted_text(HTML(
                    f"Authentication <ansired>failed</ansired> with redirect status "
                    f"<b>{response.status_code}</b> and no usable Location header"
                ))
                return None, None

            result = self._identity_result(response)
            if result is None:
                return None, None

            pod = result.get("PodFqdn")
            if pod:
                identity_base_url = f"https://{pod}"
                url = f"{identity_base_url}/Security/StartAuthentication"
                logging.info("CyberArk Identity redirected to preferred pod %s", pod)
                continue

            return identity_base_url, result

        print_formatted_text(HTML(
            "<ansired>Too many redirects while starting CyberArk Identity authentication</ansired>"
        ))
        return None, None

    @staticmethod
    def _identity_result(response) -> Optional[dict]:
        """Parse a CyberArk Identity API response, returning its ``Result`` dict.
        """
        if response.status_code != 200:
            print_formatted_text(HTML(
                f"Authentication <ansired>failed</ansired> with status code <b>{response.status_code}</b>"
            ))
            return None
        try:
            body = response.json()
        except ValueError:
            print_formatted_text(HTML("<ansired>Failed to parse authentication response</ansired>"))
            return None
        if body.get("success") is False:
            msg = body.get("Message") or body.get("MessageID") or "authentication failed"
            print_formatted_text(HTML(f"<ansired>{_esc(msg)}</ansired>"))
            return None
        return body.get("Result") or {}

    @staticmethod
    def _select_identity_mechanism(mechanisms: List[dict]) -> Optional[dict]:
        """Prompt the user to pick an MFA mechanism when more than one is offered."""
        if len(mechanisms) == 1:
            return mechanisms[0]
        print_formatted_text(HTML("Select an authentication method:"))
        for i, m in enumerate(mechanisms, 1):
            label = m.get("PromptSelectMech") or m.get("Name") or f"Option {i}"
            print_formatted_text(HTML(f"  <b>[{i}]</b> {_esc(label)}"))
        while True:
            try:
                choice = prompt(f"Enter option number (1-{len(mechanisms)}): ").strip()
            except (EOFError, KeyboardInterrupt):
                return None
            try:
                idx = int(choice)
            except ValueError:
                continue
            if 1 <= idx <= len(mechanisms):
                return mechanisms[idx - 1]

    def _answer_identity_mechanism(self, identity_base_url: str, tenant_name: str,
                                   session_id: str, mechanism: dict,
                                   password: Optional[str] = None) -> Optional[dict]:
        """Drive one CyberArk Identity challenge mechanism to completion.
        """
        url = f"{identity_base_url}/Security/AdvanceAuthentication"
        headers = {"X-IDAP-NATIVE-CLIENT": "true"}
        name = mechanism.get("Name") or ""
        mech_id = mechanism.get("MechanismId")
        answer_type = (mechanism.get("AnswerType") or "").lower()
        prompt_label = (mechanism.get("PromptSelectMech")
                        or mechanism.get("PromptMechChosen") or name)
        base = {"TenantId": tenant_name, "SessionId": session_id, "MechanismId": mech_id}

        def _post(body: dict) -> Optional[dict]:
            try:
                resp = requests.post(url, json=body, headers=headers, timeout=self.TIMEOUT)
            except _requests_module.RequestException as e:
                print_formatted_text(HTML("Authentication request <ansired>failed</ansired>: connection error"))
                logging.debug("AdvanceAuthentication connection error: %s", type(e).__name__)
                return None
            return self._identity_result(resp)

        # Text answer — password (UP) or a typed code (OTP / authenticator).
        if name == "UP" or answer_type == "text":
            if name == "UP":
                answer = password or prompt("CyberArk password: ", is_password=True)
            else:
                answer = prompt(f"{prompt_label}: ")
            return _post(dict(base, Action="Answer", Answer=answer))

        result = _post(dict(base, Action="StartOOB"))
        if result is None:
            return None
        if result.get("Summary") == IDENTITY_LOGIN_SUCCESS:
            return result
        print_formatted_text(HTML(
            f"Out-of-band authentication started via <b>{_esc(prompt_label)}</b>."
        ))
        try:
            code = prompt(
                "Approve the request on your device then press Enter, "
                "or type the code you received: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if code:
            return _post(dict(base, Action="Answer", Answer=code))
        # No code entered — poll for a push approval.
        waited = 0
        while waited < self.IDENTITY_OOB_POLL_TIMEOUT:
            time.sleep(self.IDENTITY_OOB_POLL_INTERVAL)
            waited += self.IDENTITY_OOB_POLL_INTERVAL
            result = _post(dict(base, Action="Poll"))
            if result is None:
                return None
            if result.get("Summary") != "OobPending":
                return result
        print_formatted_text(HTML("<ansired>Timed out waiting for out-of-band approval</ansired>"))
        return result

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
        except _requests_module.RequestException as e:
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

    def fetch_platforms(self) -> List[dict]:
        """Fetch platform definitions from PVWA ``GET /Platforms``.
        """
        # _paginate already handles "value"; try that first, then fall back to
        # the explicitly-keyed response shape.
        platforms = self._paginate(self._get_url("platforms"),
                                   items_key="Platforms", limit=200)
        if platforms:
            return platforms
        # Fallback: some tenants/versions paginate under "value"
        return self._paginate(self._get_url("platforms"), limit=200)

    def fetch_platform_details(self, platform_id: str) -> Optional[dict]:
        """Fetch the full platform definition (ConnectionComponents, Properties).
        """
        if not platform_id or not re.match(r'^[A-Za-z0-9_\-]+$', str(platform_id)):
            return None
        try:
            url = self._get_url("platform_details").format(platform_id=platform_id)
            resp = self._get(url)
            if resp.status_code == 200:
                try:
                    body = resp.json()
                except (ValueError, KeyError):
                    logging.debug('Platform detail response not valid JSON for %s',
                                  platform_id)
                    return None
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    try:
                        logging.debug(
                            'Platform detail raw response for %s:\n%s',
                            platform_id,
                            json.dumps(body, indent=2, sort_keys=True),
                        )
                    except (TypeError, ValueError):
                        pass
                return body
            logging.debug('Platform detail fetch failed for %s: status %d',
                          platform_id, resp.status_code)
        except (_requests_module.RequestException, ValueError) as e:
            logging.debug('Platform detail fetch error for %s: %s',
                          platform_id, type(e).__name__)
        return None

    @staticmethod
    def _encode_safe_path(safe_url_id: str) -> Optional[str]:
        """Normalize and URL-encode a CyberArk safe identifier for path use.

        Validates *before* any percent-decoding so encoded separators
        (``%2f``, ``%5c``, ``%2e%2e``) cannot bypass the path-traversal
        guards.
        """
        if not safe_url_id or not isinstance(safe_url_id, str):
            return None
        s = safe_url_id.strip()
        if not s or len(s) > 200:
            return None
        # Reject raw and percent-encoded path separators / traversal before
        # any decoding so crafted inputs cannot slip through unquote().
        lower = s.lower()
        if (
            any(ch in s for ch in ("/", "\\", "\x00"))
            or s in ("..", ".")
            or "%2f" in lower
            or "%5c" in lower
            or "%00" in lower
            or "%2e%2e" in lower
        ):
            logging.warning(
                'Safe URL ID rejected (contains path separator/traversal): %s',
                re.sub(r'[^A-Za-z0-9_. \-%]', '?', s),
            )
            return None
        try:
            decoded = unquote(s)
        except (TypeError, ValueError):
            decoded = s
        if (
            any(ch in decoded for ch in ("/", "\\", "\x00"))
            or decoded in ("..", ".")
            or ".." in decoded
        ):
            logging.warning(
                'Safe URL ID rejected after decode (contains separator/traversal): %s',
                re.sub(r'[^A-Za-z0-9_. \-%]', '?', s),
            )
            return None
        return quote(decoded, safe='')

    def fetch_safe_members(self, safe_url_id: str) -> List[dict]:
        """Fetch members of a safe. Returns list of member dicts.

        Excludes predefined system members. Safe names with spaces, unicode,
        or pre-encoded characters are normalized via ``_encode_safe_path``.
        """
        encoded = self._encode_safe_path(safe_url_id)
        if encoded is None:
            return []
        url = f"{self._get_url('safes')}/{encoded}/Members"
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

    _PLATFORM_ID_RE = re.compile(r'^[A-Za-z0-9_\-]{1,80}$')

    def _fetch_platform_policy(self, platform_id: str, suffix: str,
                               label: str) -> Optional[dict]:
        """Shared GET helper for the ``/api/platforms/{id}/<suffix>/`` family.

        """
        if not platform_id or not self._PLATFORM_ID_RE.match(str(platform_id)):
            logging.debug('Skipping %s fetch for invalid platformId: %s',
                          label, re.sub(r'[^A-Za-z0-9_\-]', '?', str(platform_id)))
            return None
        url = (f"https://{self.pvwa_host}/api/platforms/"
               f"{platform_id}/{suffix}/")
        try:
            response = self._get(url)
        except _requests_module.RequestException as e:
            logging.debug('Platform %s fetch error for %s: %s',
                          label, platform_id, type(e).__name__)
            return None
        if response.status_code == 200:
            try:
                data = response.json()
            except (ValueError, KeyError):
                logging.debug('Platform %s response not valid JSON for %s',
                              label, platform_id)
                return None
            if isinstance(data, dict) and data:
                logging.debug('Platform %s fetched for %s', label, platform_id)
                try:
                    logging.debug('Platform %s raw response for %s:\n%s',
                                  label, platform_id,
                                  json.dumps(data, indent=2, sort_keys=True))
                except (TypeError, ValueError):
                    logging.debug('Platform %s raw response for %s '
                                  '(unserializable)', label, platform_id)
                return data
        else:
            logging.debug('Platform %s not accessible for %s: status %d',
                          label, platform_id, response.status_code)
        return None

    def fetch_platform_rotation_policy(self, platform_id: str) -> Optional[dict]:
        """``GET /api/platforms/{platformId}/rotation-policy/``.
        """
        return self._fetch_platform_policy(
            platform_id, "rotation-policy", "rotation-policy")

    def fetch_platform_secrets_policy(self, platform_id: str) -> Optional[dict]:
        """``GET /api/platforms/{platformId}/secrets-policy/``.

        """
        return self._fetch_platform_policy(
            platform_id, "secrets-policy", "secrets-policy")

    def fetch_platform_workflows_policy(self, platform_id: str) -> Optional[dict]:
        """``GET /api/platforms/{platformId}/workflows-policy/``.

        """
        return self._fetch_platform_policy(
            platform_id, "workflows-policy", "workflows-policy")

    # CyberArk policy IDs are case-sensitive; the legacy PVWA UI .asmx
    # service expects them quoted. Validation regex defined above.
    def fetch_platform_session_monitoring(self, platform_id: str) -> Optional[dict]:
        """Resolve the platform's session-monitoring rules from the legacy
        PVWA admin-UI ``.asmx`` web-service.

        """
        if not platform_id or not self._PLATFORM_ID_RE.match(str(platform_id)):
            return None


        url = (f"https://{self.pvwa_host}/PasswordVault/services/"
               f"PoliciesMgt.asmx/GetPolicyRulesSessionMonitoring")
        params = {
            "platformId": f'"{platform_id}"',
            "page": 1, "start": 0, "limit": 100,
        }
        try:
            response = self._get(url, params=params)
        except _requests_module.RequestException as e:
            logging.debug('Platform session-monitoring (.asmx) fetch error for %s: %s',
                          platform_id, type(e).__name__)
            return None
        if response.status_code != 200:
            logging.debug('Platform session-monitoring (.asmx) for %s: status %d',
                          platform_id, response.status_code)
            return None
        try:
            data = response.json()
        except (ValueError, KeyError):
            logging.debug('Platform session-monitoring (.asmx) response not valid JSON for %s',
                          platform_id)
            return None
        if isinstance(data, dict) and data:
            logging.debug('Platform session-monitoring fetched for %s (.asmx)',
                          platform_id)
            try:
                logging.debug('Platform session-monitoring raw response for %s (.asmx):\n%s',
                              platform_id, json.dumps(data, indent=2, sort_keys=True))
            except (TypeError, ValueError):
                pass
            return data
        return None

    def fetch_master_policy(self) -> Optional[dict]:
        """Fetch the CyberArk Master Policy settings.
    
        """
        # ISPSS APIs sit at the root of the privilegecloud host (not under
        # /PasswordVault/API/), so build a separate base for them.
        ispss_base = f"https://{self.pvwa_host}"
        legacy_base = self._get_url("safes").rsplit("/Safes", 1)[0]
        # Trailing slash on the ISPSS endpoint matches the docs guidance
        # ("If the URL includes a dot, add a forward slash at the end").
        endpoints = (
            f"{ispss_base}/api/platforms/master-rotation-policy/",
            f"{legacy_base}/Policies/1",
            f"{legacy_base}/Policy/MasterPolicy",
        )
        for url in endpoints:
            try:
                response = self._get(url)
            except _requests_module.RequestException as e:
                logging.debug('Master Policy fetch error at %s: %s',
                              url, type(e).__name__)
                continue
            if response.status_code == 200:
                try:
                    data = response.json()
                except (ValueError, KeyError):
                    logging.debug('Master Policy response not valid JSON at %s', url)
                    continue
                if isinstance(data, dict) and data:
                    # Log the source URL at DEBUG — helps operators tell which
                    # deployment path was taken when verbose logging is on.
                    logging.debug('Master Policy fetched from %s', url)
                    try:
                        logging.debug('Master Policy raw response from %s:\n%s',
                                      url, json.dumps(data, indent=2, sort_keys=True))
                    except (TypeError, ValueError):
                        logging.debug('Master Policy raw response from %s (unserializable)', url)
                    return data
            else:
                logging.debug('Master Policy not accessible at %s: status %d',
                              url, response.status_code)
        return None

   
    _MASTER_POLICY_ONLY_KEYS = frozenset({
        "changeIntervalExceptionsCount", "verifyIntervalExceptionsCount",
    })

    @staticmethod
    def _looks_like_base_master_policy(data: Any) -> bool:
        return (isinstance(data, dict)
                and any(k in data for k in
                        CyberArkPVWAClient._MASTER_POLICY_ONLY_KEYS)
                and "exceptions" not in data
                and "value" not in data)

    def fetch_master_rotation_policy_exceptions(self) -> Optional[Any]:
        """``GET /api/platforms/master-rotation-policy/exceptions/``.

        """
        url = (f"https://{self.pvwa_host}"
               f"/api/platforms/master-rotation-policy/exceptions/")
        try:
            response = self._get(url)
        except _requests_module.RequestException as e:
            logging.debug('Master rotation policy exceptions fetch error: %s',
                          type(e).__name__)
            return None
        if response.status_code != 200:
            logging.debug(
                'Master rotation policy exceptions not accessible: status %d',
                response.status_code,
            )
            return None
        try:
            data = response.json()
        except (ValueError, KeyError):
            logging.debug(
                'Master rotation policy exceptions response not valid JSON',
            )
            return None
        if not data:
            return None
        try:
            raw_json = json.dumps(data, indent=2, sort_keys=True)
        except (TypeError, ValueError):
            raw_json = repr(data)
        logging.debug('CyberArk master-rotation-policy exceptions:\n%s', raw_json)
        if self._looks_like_base_master_policy(data):
            logging.debug(
                "This tenant's /master-rotation-policy/exceptions/ endpoint "
                "returned the base policy object (not a per-platform "
                "exceptions list) — falling back to the per-platform "
                "rotation-policy check for each imported account's platform."
            )
            return None
        return data

    def fetch_master_session_monitoring(self) -> Optional[dict]:
        """Fetch global session-monitoring rules (master policy level).

        """
        url = (f"https://{self.pvwa_host}/PasswordVault/services/"
               f"PoliciesMgt.asmx/GetPolicyRulesSessionMonitoring")
        # Empty platformId — the global / master-level rule set. Quoted
        # form (``""``) matches what the PVWA UI sends; unquoted form is
        # rejected by the .asmx parser on some self-hosted builds.
        params = {
            "platformId": '""',
            "page": 1, "start": 0, "limit": 100,
        }
        try:
            response = self._get(url, params=params)
        except _requests_module.RequestException as e:
            logging.debug('Master session-monitoring (.asmx) fetch error: %s',
                          type(e).__name__)
            return None
        if response.status_code != 200:
            logging.debug('Master session-monitoring (.asmx) status %d',
                          response.status_code)
            return None
        try:
            data = response.json()
        except (ValueError, KeyError):
            logging.error('Master session-monitoring (.asmx) response not valid JSON')
            return None
        if isinstance(data, dict) and data:
            logging.debug('Master session-monitoring fetched (.asmx)')
            try:
                logging.debug('Master session-monitoring raw response (.asmx):\n%s',
                              json.dumps(data, indent=2, sort_keys=True))
            except (TypeError, ValueError):
                pass
            return data
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

    def fetch_account_dependents(self, account_id: str) -> List[dict]:
        """Fetch dependents (Windows services, scheduled tasks, IIS app pools)
        attached to a CyberArk account.

        Privilege Cloud exposes this under the lowercase ISPSS REST surface at
        ``GET /api/accounts/{accountId}/account-dependents`` (sibling of the
        ``/api/platforms/{id}/rotation-policy/`` endpoints already used here).
        Self-hosted PVWA still serves the older
        ``/PasswordVault/API/Accounts/{id}/Dependents`` path, so we try the
        Privilege Cloud URL first and fall back to PVWA on 404 / 405.

        """
        if not re.match(r'^[a-zA-Z0-9_]+$', str(account_id)):
            logging.warning('Invalid account ID for dependents fetch: %s',
                            re.sub(r'[^a-zA-Z0-9_]', '?', str(account_id)))
            return []

        candidate_urls = [
            f"https://{self.pvwa_host}/api/accounts/{account_id}/account-dependents",
            f"{self._get_url('accounts')}/{account_id}/Dependents",
        ]
        response = None
        used_url = ""
        for url in candidate_urls:
            try:
                response = self._get(url)
            except _requests_module.RequestException as e:
                logging.debug('Dependents fetch error for %s @ %s: %s',
                              account_id, url, type(e).__name__)
                response = None
                continue
            if response is None:
                continue
            if response.status_code == 200:
                used_url = url
                break
            if response.status_code in (404, 405):
                logging.debug('Dependents endpoint not available at %s '
                              '(status %d) — trying fallback', url,
                              response.status_code)
                continue
            logging.debug('Dependents fetch returned %d for account %s @ %s',
                          response.status_code, account_id, url)
            return []

        if response is None or response.status_code != 200:
            return []

        try:
            data = response.json()
        except ValueError:
            logging.debug('Dependents response for %s is not JSON', account_id)
            return []
        if isinstance(data, dict):
            items = (data.get("value") or data.get("Dependencies")
                     or data.get("dependents") or data.get("dependencies")
                     or data.get("accountDependents")
                     or data.get("items") or [])
        elif isinstance(data, list):
            items = data
        else:
            items = []
        items = [d for d in items if isinstance(d, dict)]
        if items:
            logging.debug('Fetched %d dependent(s) for account %s via %s',
                          len(items), account_id, used_url)
            try:
                logging.debug(
                    'CyberArk dependents (raw) for account %s:\n%s',
                    account_id,
                    json.dumps(items, indent=2, sort_keys=True),
                )
            except (TypeError, ValueError):
                logging.debug(
                    'CyberArk dependents (raw) for account %s: %r',
                    account_id, items,
                )
        return items

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
        except _requests_module.RequestException as e:
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
                        **({"TicketingSystemName": environ["KEEPER_CYBERARK_TICKETING_SYSTEM"]}
                           if "KEEPER_CYBERARK_TICKETING_SYSTEM" in environ else {}),
                        **({"TicketId": environ["KEEPER_CYBERARK_TICKET_ID"]}
                           if "KEEPER_CYBERARK_TICKET_ID" in environ else {}),
                    },
                    timeout=self.TIMEOUT,
                    verify=self.verify_ssl,
                )
            except _requests_module.RequestException as e:
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

