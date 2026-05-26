import asyncio
import json
import logging
import os
import re
import requests
import stat
import tempfile
import warnings
from contextlib import contextmanager
from http import HTTPStatus
from os import environ, path
from prompt_toolkit import HTML, print_formatted_text, prompt
from prompt_toolkit.shortcuts import button_dialog, ProgressBar
from prompt_toolkit.styles import Style
from tabulate import tabulate
from time import sleep
from typing import List
from urllib.parse import parse_qsl
from urllib3.exceptions import InsecureRequestWarning

# Self-hosted PVWAs often use a private CA; verify=False is intentional there.
warnings.simplefilter("ignore", InsecureRequestWarning)


from ... import api, crypto, utils
from ...commands.enterprise_common import EnterpriseCommand
from ...constants import EMAIL_PATTERN
from ..importer import (
    BaseDownloadMembership,
    BaseImporter,
    Permission,
    Record,
    RecordField,
    SharedFolder,
    Team,
)


class _ExecutorShutdownLogFilter(logging.Filter):
    """Drop the harmless ``Executor shutdown has been called`` records.
    """

    _NEEDLE = "Executor shutdown has been called"

    def filter(self, record):  # noqa: D401 - logging.Filter API
        try:
            if self._NEEDLE in record.getMessage():
                return False
            exc_info = record.exc_info
            if exc_info and exc_info[1] is not None and self._NEEDLE in str(exc_info[1]):
                return False
        except Exception:
            # Never let the filter itself break logging.
            return True
        return True


@contextmanager
def _suppress_progressbar_executor_noise():
    """Silence the harmless ``Executor shutdown has been called`` tracebacks.
    """

    def _filter_handler(loop, context):
        exc = context.get("exception")
        message = context.get("message", "") or ""
        if isinstance(exc, RuntimeError) and "Executor shutdown" in str(exc):
            return
        if "Executor shutdown" in message:
            return
        loop.default_exception_handler(context)

    previous_handler = None
    loop = None
    log_filter = _ExecutorShutdownLogFilter()
    asyncio_logger = logging.getLogger("asyncio")
    asyncio_logger.addFilter(log_filter)
    try:
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            previous_handler = loop.get_exception_handler()
            loop.set_exception_handler(_filter_handler)
        yield
    finally:
        if loop is not None:
            loop.set_exception_handler(previous_handler)
        asyncio_logger.removeFilter(log_filter)


# CyberArk user types that identify non-human / service accounts.
_SERVICE_ACCOUNT_USER_TYPES = frozenset(
    t.lower()
    for t in (
        "Built-InAdmins",
        "CyberArkServiceUser",
        "SaaSSRV",
        "AppProvider",
        "CPM",
        "PVWAGWAccounts",
        "PVWAGWUser",
        "PSM",
        "PSMUser",
        "PSMAppUser",
        "PSMGWUser",
        "NotificationEngine",
        "ENE",
        "AIMAccount",
        "AIMWebService",
    )
)

# Strings that identify non-human / service accounts in ``userType`` and ``source``.
_SERVICE_ACCOUNT_SUBSTRINGS = (
    "service",
    "component",
    "gateway",
    "appuser",
    "appprovider",
    "psm",
    "cpm",
    "pvwa",
    "telemetry",
)


def _is_service_account_user(user):
    """Heuristically decide whether a CyberArk user dict is a service account.

    Accepts either the normalised dict produced by
    :meth:`CyberArkImporter.fetch_cyberark_users` (lowercase keys) or the raw
    PVWA payload (PascalCase keys), so it is safe to call from any code path.
    """

    if not isinstance(user, dict):
        return False

    if user.get("componentUser") is True or user.get("ComponentUser") is True:
        return True

    user_type = (
        user.get("type")
        or user.get("userType")
        or user.get("UserType")
        or ""
    )
    source = user.get("source") or user.get("Source") or ""

    user_type_lc = str(user_type).strip().lower()
    source_lc = str(source).strip().lower()

    if user_type_lc and user_type_lc in _SERVICE_ACCOUNT_USER_TYPES:
        return True
    if source_lc and source_lc in _SERVICE_ACCOUNT_USER_TYPES:
        return True

    for needle in _SERVICE_ACCOUNT_SUBSTRINGS:
        if needle in user_type_lc or needle in source_lc:
            return True


    username = (user.get("username") or user.get("UserName") or "").strip()
    if username.endswith("$"):
        return True

    return False


class PermissionMapper:
    """Maps CyberArk safe member permissions to Keeper shared folder permission tiers.

    """

    ALL_PERMISSIONS = {
        "useAccounts", "retrieveAccounts", "listAccounts",
        "addAccounts", "updateAccountContent", "updateAccountProperties",
        "renameAccounts", "deleteAccounts",
        "manageSafe", "manageSafeMembers", "viewSafeMembers",
        "viewAuditLog", "backupSafe", "unlockAccounts",
        "initiateCPMAccountManagementOperations", "specifyNextAccountContent",
        "createFolders", "deleteFolders", "moveAccountsAndFolders",
        "accessWithoutConfirmation",
        "requestsAuthorizationLevel1", "requestsAuthorizationLevel2",
        "isExpiredMembershipEnable", "isReadOnly",
    }

    UNMAPPED_PERMISSIONS = {
        "accessWithoutConfirmation",
        "requestsAuthorizationLevel1",
        "requestsAuthorizationLevel2",
    }

    @staticmethod
    def map_permissions(perms):
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
    def get_unmapped_permissions(perms):
        """Return list of CyberArk permissions that have no Keeper equivalent."""
        if not isinstance(perms, dict):
            return []
        return [
            p for p in PermissionMapper.UNMAPPED_PERMISSIONS
            if perms.get(p, False)
        ]

    @staticmethod
    def map_member(member):
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


class CyberArkImporter(BaseImporter):
    # Delay between requests to avoid hitting the API rate limits
    DELAY = 0.025
    # CyberArk REST API endpoints (relative to the base URL)
    ENDPOINTS = {
        "accounts": "Accounts",
        "account_password": "Accounts/{account_id}/Password/Retrieve",
        "logon": "Auth/{type}/Logon",
        "safes": "Safes",
        "user_groups": "UserGroups",
        "user_group": "UserGroups/{group_id}",
        "users": "Users",
        "user": "Users/{user_id}",
    }
    # Request timeout in seconds
    TIMEOUT = 10

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
       
        self._client_cert = None
        self._tmp_cert_files = []
        # ``verify`` value used for every PVWA request. Defaults to False (self-hosted PVWAs typically use a private CA), but can be overridden by the ``_CYBERARK_CA_BUNDLE`` env var to point at a CA file/dir.
        self._verify_tls = False

    @classmethod
    def get_url(cls, pvwa_host, endpoint):
        return f"https://{pvwa_host}/PasswordVault/API/{cls.ENDPOINTS[endpoint]}"

    def _load_p12_client_cert(self, p12_path, p12_password):
        """Convert a PKCS#12 bundle to a temporary PEM cert+key pair for ``requests``.

        ``requests`` does not accept ``.p12``/``.pfx`` files directly — it needs
        a PEM certificate and a PEM private key. We use the ``cryptography``
        library (already a Commander dependency) to decrypt the P12 in memory
        and then write the cert chain and unencrypted private key to two
        temporary files. The files are tracked on ``self._tmp_cert_files`` so
        that ``do_import`` can delete them when the import finishes.

        Returns the ``(certfile, keyfile)`` tuple on success or ``None`` on
        any failure (bad path, wrong passphrase, malformed P12, missing private
        key, etc.) — the caller logs and aborts in that case.
        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import pkcs12
        except ImportError as e:
            print_formatted_text(
                HTML(
                    "<ansired>cryptography package is required for P12 client certificates</ansired>: "
                    f"{e}"
                )
            )
            return None
        try:
            with open(p12_path, "rb") as fh:
                p12_bytes = fh.read()
        except OSError as e:
            print_formatted_text(
                HTML(f"<ansired>Could not read P12 file</ansired> <b>{p12_path}</b>: {e}")
            )
            return None
        password_bytes = p12_password.encode("utf-8") if p12_password else None
        try:
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                p12_bytes, password_bytes
            )
        except ValueError as e:
            print_formatted_text(
                HTML(
                    "<ansired>Failed to decode P12 bundle</ansired> — check the file "
                    f"and passphrase: {e}"
                )
            )
            return None
        if private_key is None or cert is None:
            print_formatted_text(
                HTML(
                    "<ansired>P12 bundle is missing a private key or certificate</ansired>; "
                    "client-certificate authentication requires both."
                )
            )
            return None

       
        cert_fd, cert_path = tempfile.mkstemp(prefix="ca_pvwa_", suffix=".pem")
        key_fd, key_path = tempfile.mkstemp(prefix="ca_pvwa_", suffix=".key.pem")
        try:
            with os.fdopen(cert_fd, "wb") as cf:
                cf.write(cert.public_bytes(serialization.Encoding.PEM))
                for extra in additional_certs or []:
                    cf.write(extra.public_bytes(serialization.Encoding.PEM))
            with os.fdopen(key_fd, "wb") as kf:
                kf.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            try:
                os.chmod(cert_path, stat.S_IRUSR | stat.S_IWUSR)
                os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
            except OSError:
                pass
        except OSError as e:
            print_formatted_text(
                HTML(f"<ansired>Failed to materialise P12 to PEM</ansired>: {e}")
            )
            for p in (cert_path, key_path):
                try:
                    os.remove(p)
                except OSError:
                    pass
            return None

        self._tmp_cert_files.extend([cert_path, key_path])
        return cert_path, key_path

    def _cleanup_tmp_cert_files(self):
        """Delete every temporary PEM file written by ``_load_p12_client_cert``."""
        for p in self._tmp_cert_files:
            try:
                os.remove(p)
            except OSError:
                pass
        self._tmp_cert_files = []
        self._client_cert = None

    def _maybe_configure_client_cert(self, pvwa_host):
        """Prompt for / load a P12 client cert when targeting a self-hosted PVWA.
        """
        if pvwa_host.endswith(".cyberark.cloud"):
            self._verify_tls = True
            return True
        
        ca_bundle = environ.get("_CYBERARK_CA_BUNDLE")
        if ca_bundle:
            if not path.isfile(ca_bundle) and not path.isdir(ca_bundle):
                print_formatted_text(
                    HTML(
                        f"<ansired>_CYBERARK_CA_BUNDLE</ansired> points to <b>{ca_bundle}</b> "
                        "which does not exist; falling back to verify=False."
                    )
                )
            else:
                self._verify_tls = ca_bundle

        p12_path = environ.get("_CYBERARK_CLIENT_CERT_P12")
        if p12_path is None:
            try:
                entered = prompt(
                    "CyberArk PVWA client certificate P12 path (leave empty if none): "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                return False
            p12_path = entered or None
        if not p12_path:
            return True
        if not path.isfile(p12_path):
            print_formatted_text(
                HTML(f"<ansired>P12 file not found</ansired>: <b>{p12_path}</b>")
            )
            return False
        p12_password = environ.get("_CYBERARK_CLIENT_CERT_PASSWORD")
        if p12_password is None:
            p12_password = prompt("P12 passphrase: ", is_password=True)
        cert_tuple = self._load_p12_client_cert(p12_path, p12_password)
        if cert_tuple is None:
            return False
        self._client_cert = cert_tuple
        print_formatted_text(
            HTML("Loaded PVWA client certificate from <b>P12</b> — using mutual TLS.")
        )
        return True

    def get_response(self, url, authorization_token, query_params):
        """GET helper that surfaces connection errors as a graceful warning instead of a stack trace.

        Returns the ``requests.Response`` on success, or ``None`` if the request could not be sent
        (DNS failure, connection refused, timeout, etc.). Callers should treat ``None`` the same as
        a non-200 response and stop processing.
        """
        try:
            return requests.get(
                url,
                headers={
                    "Authorization": authorization_token,
                    "Content-Type": "application/json",
                },
                params=query_params,
                timeout=self.TIMEOUT,
                cert=self._client_cert,
                verify=self._verify_tls,
            )
        except requests.exceptions.RequestException as e:
            print_formatted_text(
                HTML(f"Request to <b>{url}</b> <ansired>failed</ansired>: {e}")
            )
            return None

    @staticmethod
    def _extract_user_email(user):
        """Return the best available email for a CyberArk user dict, or empty string."""
        internet = user.get("internet") or user.get("Internet") or {}
        for key in ("businessEmail", "homeEmail", "otherEmail"):
            value = internet.get(key)
            if value and str(value).strip():
                return str(value).strip()
        # Some endpoints (e.g. Get logged on user) expose a flat Email field.
        for key in ("email", "Email"):
            value = user.get(key)
            if value and str(value).strip():
                return str(value).strip()
        return ""

    def fetch_cyberark_users(self, pvwa_host, authorization_token, fetch_groups_membership=False):
        """Fetch all CyberArk vault users (excluding component / service accounts).

        Returns a list of dicts:
        ``{"id", "username", "email", "type", "source", "groups_membership"}``
        — empty list on any error.
        """
        include_component = environ.get("_CYBERARK_INCLUDE_COMPONENT_USERS", "").lower() in (
            "1", "true", "yes",
        )
        query_params = {"ExtendedDetails": "True"}
        if not include_component:
            # CyberArk's documented filter - drops CPM/PSM/PVWA/AppProvider/etc.
            query_params["componentUser"] = "false"
        sleep(self.DELAY)
        response = self.get_response(
            self.get_url(pvwa_host, "users"),
            authorization_token,
            query_params,
        )
        if response is None:
            return []
        if response.status_code != 200:
            print_formatted_text(
                HTML(
                    f"Getting users from server {pvwa_host} <ansired>failed</ansired> "
                    f"with status <b>{response.status_code}</b>"
                )
            )
            return []
        try:
            payload = response.json()
        except ValueError:
            print_formatted_text(HTML("<ansired>Users response was not valid JSON</ansired>"))
            return []

        # CyberArk returns users under "Users" (PAM Self-Hosted) or "value" (Privilege Cloud)
        users = payload.get("Users") or payload.get("value") or []
        if not isinstance(users, list) or not users:
            return []

        # Optional username filter
        filter_env = environ.get("_CYBERARK_USERS_FILTER") or ""
        username_filter = {x.strip().lower() for x in filter_env.split(",") if x.strip()}

        result = []
        for u in users:
            username = u.get("username") or u.get("UserName") or ""
            if username_filter and username.lower() not in username_filter:
                continue
            user_id = u.get("id") or u.get("ID")
            user_type = u.get("userType") or u.get("UserType") or ""
            source = u.get("source") or u.get("Source") or ""
            email = self._extract_user_email(u)
            groups_membership = u.get("groupsMembership") or []

            
            need_detail = (not email) or (fetch_groups_membership and not groups_membership)
            if need_detail and user_id is not None:
                sleep(self.DELAY)
                detail = self.get_response(
                    self.get_url(pvwa_host, "user").format(user_id=user_id),
                    authorization_token,
                    {},
                )
                if detail is not None and detail.status_code == 200:
                    try:
                        detail_json = detail.json()
                    except ValueError:
                        detail_json = {}
                    if not email:
                        email = self._extract_user_email(detail_json)
                    if fetch_groups_membership and not groups_membership:
                        groups_membership = detail_json.get("groupsMembership") or []

            result.append(
                {
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "type": user_type,
                    "source": source,
                    "groups_membership": groups_membership,
                }
            )
        return result

    def fetch_all_safes(self, pvwa_host, authorization_token, safes_filter=None):
        """Return full safe objects from PVWA (not just names).

        ``safes_filter`` is an optional set of safe names to restrict the result.
        """
        safes_file = environ.get("_CYBERARK_SAFES_PATH", "safes.txt")
        if path.isfile(safes_file):
            with open(safes_file, "r", encoding="utf-8") as f:
                names = [line.strip() for line in f if line.strip()]
            return [{"safeName": n, "safeUrlId": n} for n in names]
        if "_CYBERARK_SAFES" in environ:
            names = [x.strip() for x in environ.get("_CYBERARK_SAFES").split(",") if x.strip()]
            return [{"safeName": n, "safeUrlId": n} for n in names]

        safes = []
        offset = 0
        limit = 200
        while True:
            sleep(self.DELAY)
            response = self.get_response(
                self.get_url(pvwa_host, "safes"),
                authorization_token,
                {"offset": offset, "limit": limit},
            )
            if response is None or response.status_code != 200:
                break
            try:
                payload = response.json()
            except ValueError:
                break
            chunk = payload.get("value") or []
            safes.extend(chunk)
            count = payload.get("count", len(safes))
            offset += len(chunk)
            if offset >= count or not chunk:
                break

        if safes_filter:
            safes = [
                s for s in safes
                if s.get("safeName") in safes_filter or s.get("safeUrlId") in safes_filter
            ]
        return safes

    def fetch_safe_members(self, pvwa_host, authorization_token, safe_url_id):
        """Fetch all members of a CyberArk safe (excluding predefined system members)."""
        if not safe_url_id:
            return []
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_. -]*$", safe_url_id):
            logging.warning("Invalid safe URL ID format: %s — skipping member fetch", safe_url_id)
            return []
        url = f"{self.get_url(pvwa_host, 'safes')}/{safe_url_id}/Members"
        members = []
        offset = 0
        limit = 100
        while True:
            sleep(self.DELAY)
            response = self.get_response(
                url, authorization_token, {"offset": offset, "limit": limit},
            )
            if response is None or response.status_code != 200:
                break
            try:
                payload = response.json()
            except ValueError:
                break
            chunk = payload.get("value") or []
            for m in chunk:
                if not m.get("isPredefinedUser"):
                    members.append(m)
            count = payload.get("count", 0)
            offset += len(chunk)
            if offset >= count or not chunk:
                break
        return members

    def print_cyberark_users(self, pvwa_host, authorization_token, users=None):
        """Print a table of CyberArk users and their emails (no Keeper changes).
        """
        if users is None:
            print_formatted_text(HTML("\nFetching CyberArk Users..."))
            users = self.fetch_cyberark_users(pvwa_host, authorization_token)
        if not users:
            print_formatted_text(HTML("<ansiyellow>No users returned by CyberArk</ansiyellow>"))
            return

        rows = []
        users_missing_email = []
        for u in users:
            user_id = u.get("id")
            username = u.get("username") or ""
            email = u.get("email") or ""
            if not email:
                users_missing_email.append(username or str(user_id))
            rows.append(
                {
                    "ID": user_id if user_id is not None else "",
                    "Username": username,
                    "Email": email,
                    "Type": u.get("type") or "",
                    "Source": u.get("source") or "",
                }
            )

        if not rows:
            logging.debug("CyberArk users: no users matched the filter")
            return

        logging.debug(
            "CyberArk Users (%d — informational only, NOT imported to Keeper):\n%s",
            len(rows),
            tabulate(rows, headers="keys"),
        )

        if users_missing_email:
            preview = ", ".join(users_missing_email[:20]) + (
                "..." if len(users_missing_email) > 20 else ""
            )
            logging.debug(
                "%d CyberArk user(s) had no email: %s",
                len(users_missing_email),
                preview,
            )

        # Optional CSV dump for downstream tooling.
        out_path = environ.get("_CYBERARK_USERS_PATH")
        if out_path:
            try:
                import csv
                with open(out_path, "w", encoding="utf-8", newline="") as f:
                    writer = csv.DictWriter(f, fieldnames=["ID", "Username", "Email", "Type", "Source"])
                    writer.writeheader()
                    writer.writerows(rows)
                print_formatted_text(HTML(f"Wrote user list to <b>{out_path}</b>"))
            except OSError as e:
                print_formatted_text(
                    HTML(f"<ansired>Failed to write users CSV to {out_path}:</ansired> {e}")
                )

    def do_import(self, filename, **kwargs):
        try:
            return self._do_import_inner(filename, **kwargs)
        finally:
            self._cleanup_tmp_cert_files()

    def _authenticate_pvwa(self, filename):
        """Authenticate to a CyberArk PVWA and return session details.

        Returns ``(pvwa_host, authorization_token, query_params)`` on success,
        or ``None`` if authentication failed or was cancelled.
        """
        pvwa_host = filename.removeprefix("https://")
        query_params = {}
        if "?" in pvwa_host:
            pvwa_host, query_string = pvwa_host.split("?", 1)
            if "=" in query_string:
                query_params = dict(parse_qsl(query_string))
            else:
                query_params["search"] = query_string
        if not self._maybe_configure_client_cert(pvwa_host):
            return None
        if pvwa_host.endswith(".cyberark.cloud"):
            pvwa_host = f"{pvwa_host.split('.')[0]}.privilegecloud.cyberark.cloud"
            self._verify_tls = True
            id_tenant = environ.get("_CYBERARK_ID_TENANT") or prompt("CyberArk Identity Tenant ID: ")
            if re.match(r"^[A-Za-z]{3}\d{4}$", id_tenant):
                id_tenant += ".id"
            client_id = environ.get("_CYBERARK_USERNAME") or prompt("CyberArk service user name: ")
            client_secret = environ.get("_CYBERARK_PASSWORD") or prompt(
                "CyberArk service user password: ", is_password=True
            )
            token_url = f"https://{id_tenant}.cyberark.cloud/oauth2/platformtoken"
            try:
                response = requests.post(
                    token_url,
                    data={
                        "grant_type": "client_credentials",
                        "client_id": client_id,
                        "client_secret": client_secret,
                    },
                    timeout=self.TIMEOUT,
                )
            except requests.exceptions.ConnectionError as e:
                print_formatted_text(
                    HTML(
                        "OAuth2 authorization token request <ansired>failed</ansired>: "
                        f"could not connect to <b>{id_tenant}.cyberark.cloud</b>.\n"
                        "Verify the CyberArk Identity Tenant ID is correct (check the CyberArk Identity "
                        "Admin Portal URL — the first label of the hostname is your tenant ID) and that "
                        "your machine has network/DNS access to it."
                    )
                )
                print_formatted_text(HTML(f"<ansired>Details:</ansired> {e}"))
                return None
            except requests.exceptions.RequestException as e:
                print_formatted_text(
                    HTML(f"OAuth2 authorization token request <ansired>failed</ansired>: {e}")
                )
                return None
            if response.status_code != 200:
                print_formatted_text(
                    HTML(
                        f"OAuth2 authorization token request <ansired>failed</ansired> with status code <b>{response.status_code}</b>"
                    )
                )
                try:
                    print_formatted_text(HTML(f"<ansired>Response:</ansired> {response.text[:500]}"))
                except Exception:
                    pass
                return None
            try:
                access_token = response.json()["access_token"]
            except (ValueError, KeyError) as e:
                print_formatted_text(
                    HTML(f"OAuth2 response did not contain an access_token: <ansired>{e}</ansired>")
                )
                return None
            authorization_token = f"Bearer {access_token}"
        else:
            login_type = environ.get("_CYBERARK_LOGON_TYPE") or prompt(
                "CyberArk logon type (Cyberark, LDAP, RADIUS or Windows): "
            )
            username = environ.get("_CYBERARK_USERNAME") or prompt("CyberArk username: ")
            password = environ.get("_CYBERARK_PASSWORD") or prompt("CyberArk password: ", is_password=True)
            try:
                response = requests.post(
                    self.get_url(pvwa_host, "logon").format(type=login_type),
                    json={"username": username, "password": password},
                    timeout=self.TIMEOUT,
                    verify=self._verify_tls,
                    cert=self._client_cert,
                )
            except requests.exceptions.ConnectionError as e:
                print_formatted_text(
                    HTML(
                        f"CyberArk Log on <ansired>failed</ansired>: could not connect to <b>{pvwa_host}</b>.\n"
                        "Verify the PVWA hostname is correct and reachable from this machine."
                    )
                )
                print_formatted_text(HTML(f"<ansired>Details:</ansired> {e}"))
                return None
            except requests.exceptions.RequestException as e:
                print_formatted_text(HTML(f"CyberArk Log on <ansired>failed</ansired>: {e}"))
                return None
            if response.status_code != 200:
                print_formatted_text(
                    HTML(f"CyberArk Log on <ansired>failed</ansired> with status code <b>{response.status_code}</b>")
                )
                return None
            authorization_token = response.text.strip('"')
        print_formatted_text(HTML("Log on <ansigreen>successful</ansigreen>"))
        return pvwa_host, authorization_token, query_params

    def _do_import_inner(self, filename, **kwargs):
        auth = self._authenticate_pvwa(filename)
        if auth is None:
            return
        pvwa_host, authorization_token, query_params = auth
        # Get a list of safes, either from a file, the environment variable _CYBERARK_SAFES, or from the API
        safes_file = environ.get("_CYBERARK_SAFES_PATH", "safes.txt")
        if path.isfile(safes_file):
            with open(safes_file, "r", encoding="utf-8") as f:
                safes = [line.strip() for line in f if line.strip()]
                if len(safes) == 0:
                    print_formatted_text(HTML(f"Safes file <ansired>{safes_file}</ansired> is empty"))
                    return
                print_formatted_text(HTML(f"Safes from file <i>{safes_file}</i>: <b>{', '.join(safes)}</b>"))
        elif "_CYBERARK_SAFES" in environ:
            safes = [x.strip() for x in environ.get("_CYBERARK_SAFES").split(",") if x.strip()]
            print_formatted_text(HTML(f"Safes from environment variable _CYBERARK_SAFES: <b>{', '.join(safes)}</b>"))
        else:
            safes = [
                x.strip()
                for x in prompt(
                    "CyberArk safes as a comma-separated list (leave empty to get safes from the server): "
                ).split(",")
                if x.strip()
            ]
            if len(safes) == 0:
                print_formatted_text(HTML("Getting safes from the server..."))
                response = self.get_response(self.get_url(pvwa_host, "safes"), authorization_token, {})
                if response is None:
                    return
                if response.status_code != 200:
                    print_formatted_text(
                        HTML(
                            f"Getting safes from server {pvwa_host} <ansired>failed</ansired> with status <b>{response.status_code}</b>"
                        )
                    )
                    return
                safes = [x["safeName"] for x in response.json().get("value", [])]
                if len(safes) == 0:
                    print_formatted_text(HTML(f"No Safes on server <ansired>{pvwa_host}</ansired>"))
                    return
                print_formatted_text(HTML(f"Safes: <b>{', '.join(safes)}</b>"))
        # Get the accounts out of each safe
        for safe in safes:
            sleep(self.DELAY)
            response = self.get_response(
                self.get_url(pvwa_host, "accounts"), authorization_token, query_params | {"filter": f"safeName eq {safe}"}
            )
            if response is None:
                print_formatted_text(HTML(f"<ansiyellow>Skipping safe {safe} due to network error</ansiyellow>"))
                continue
            if response.status_code != 200:
                print_formatted_text(
                    HTML(
                        f"<ansiyellow>Skipping safe {safe}: status <b>{response.status_code}</b></ansiyellow>"
                    )
                )
                continue
            count = response.json().get("count", 0)
            if count == 0:
                print_formatted_text(HTML(f"<ansiyellow>No accounts in safe {safe}</ansiyellow>"))
                continue
            accounts = response.json().get("value", [])
            print_formatted_text(
                HTML(f"Importing <b>{len(accounts)}</b> accounts from safe {safe}:\n"),
                tabulate([{"ID": x["id"], "Safe": x["safeName"], "Account": x["name"]} for x in accounts], headers="keys"),
                end="\n\n",
            )
            with _suppress_progressbar_executor_noise(), ProgressBar() as pb:
                skip_all = {}
                skipped_accounts = []
                for r in pb(accounts, total=len(accounts)):
                    folder = SharedFolder()
                    folder.domain = r["safeName"]
                    record = Record()
                    record.folders = [folder]
                    record.title = re.sub(rf"^.*{re.escape(r['platformId'])}[\-_ ]", "", r["name"])
                    record.type = "Password"
                    if "userName" in r:
                        record.type = "login"
                        record.login = r["userName"]
                        if "address" in r:
                            record.type = "serverCredentials"
                            if r["platformAccountProperties"].get("LogonDomain"):
                                record.login = r["platformAccountProperties"]["LogonDomain"] + "\\" + r["userName"]
                    if "address" in r:
                        record.fields.append(RecordField("host", value={"hostName": r["address"]}))
                    if r["platformAccountProperties"].get("URL"):
                        record.title = r["platformAccountProperties"]["ItemName"]
                        record.login_url = r["platformAccountProperties"]["URL"]
                    retry = True
                    while retry is True:
                        try:
                            response = requests.post(
                                self.get_url(pvwa_host, "account_password").format(account_id=r["id"]),
                                headers={
                                    "Authorization": authorization_token,
                                    "Content-Type": "application/json",
                                },
                                json={"reason": " Commander Import"},
                                timeout=self.TIMEOUT,
                                verify=True if pvwa_host.endswith(".cyberark.cloud") else self._verify_tls,
                                cert=None if pvwa_host.endswith(".cyberark.cloud") else self._client_cert,
                            )
                        except requests.exceptions.RequestException as e:
                            print_formatted_text(
                                HTML(
                                    f"\n<ansired>Network error</ansired> retrieving password for "
                                    f"<i>{r['name']}</i> in safe <i>{r['safeName']}</i>: {e}"
                                )
                            )
                            skipped_accounts.append(
                                {
                                    "ID": r["id"],
                                    "Safe": r["safeName"],
                                    "Account": r["name"],
                                    "Status": "N/A",
                                    "Error": "NetworkError",
                                    "Message": str(e),
                                }
                            )
                            retry = False
                            continue
                        if response.status_code == 200:
                            record.password = response.text.strip('"')
                            retry = False
                            yield record
                        elif 400 <= response.status_code <= 500:
                            error = response.json()
                            if error.get('ErrorCode') in skip_all:
                                retry = False
                            else:
                                retry = button_dialog(
                                    title=f"{HTTPStatus(response.status_code).phrase} ({response.status_code})",
                                    text=HTML(
                                        "Error "
                                        f"{error.get('ErrorCode')}: <ansired>{error.get('ErrorMessage')}</ansired>\n"
                                        "Account "
                                        f"<i>{r['name']}</i> with ID <i>{r['id']}</i> in Safe <i>{r['safeName']}</i>"
                                    ),
                                    buttons=[("Retry", True), ("Skip", False), ("Skip All", None)],
                                    style=Style.from_dict({"dialog": "bg:ansiblack"}),
                                ).run()
                                if retry is None:
                                    skip_all[error.get('ErrorCode')] = True
                                    retry = False
                            if retry is False:
                                skipped_accounts.append(
                                    {
                                        "ID": r["id"],
                                        "Safe": r["safeName"],
                                        "Account": r["name"],
                                        "Status": response.status_code,
                                        "Error": error.get("ErrorCode"),
                                        "Message": error.get("ErrorMessage"),
                                    }
                                )
                        else:
                            print_formatted_text(HTML("\nImport <ansired>aborted</ansired>"))
                            return
                print_formatted_text(HTML(f"\nImported safe <b>{safe}</b>"))
                if len(skipped_accounts) > 0:
                    print_formatted_text(
                        HTML(f"\nSkipped <b>{len(skipped_accounts)}</b> Accounts:\n"),
                        tabulate(skipped_accounts, headers="keys"),
                        end="\n\n"
                    )

        # Fetch CyberArk users once and reuse them for printing AND user creation later.
        cyberark_users = []
        will_create_users = environ.get("_CYBERARK_SKIP_CREATE_USERS", "").lower() not in ("1", "true", "yes")
        will_print_users = environ.get("_CYBERARK_SKIP_USERS_LIST", "").lower() not in ("1", "true", "yes")
        if will_print_users or will_create_users:
            print_formatted_text(HTML("\nFetching CyberArk Users..."))
           
            cyberark_users = self.fetch_cyberark_users(
                pvwa_host, authorization_token,
                fetch_groups_membership=will_create_users,
            )

        # Print CyberArk users with their usernames and emails (no Keeper users are created here).
        if environ.get("_CYBERARK_SKIP_USERS_LIST", "").lower() not in ("1", "true", "yes"):
            self.print_cyberark_users(pvwa_host, authorization_token, users=cyberark_users)

        # Import CyberArk User Groups as Keeper Enterprise Teams + Roles, then optionally
        # create Keeper users (using their real CyberArk business emails) and
        # assign them to the matching Keeper Roles.
        if environ.get("_CYBERARK_SKIP_TEAMS", "").lower() not in ("1", "true", "yes"):
            self.import_user_groups(
                pvwa_host, authorization_token, kwargs.get("params"),
                cyberark_users=cyberark_users,
            )

        print_formatted_text(HTML("\nImport <ansigreen>completed</ansigreen>"))

    def import_user_groups(self, pvwa_host, authorization_token, params, cyberark_users=None):
        """Fetch CyberArk User Groups and create them as Keeper Enterprise Teams.

        This mirrors the ``enterprise-team --add`` command flow: for each
        CyberArk user group we build a ``team_add`` request (with a freshly
        generated team UID, AES team key, EC key pair and — if RSA is
        permitted — an RSA key pair) and submit them as a single batch via
        ``api.execute_batch``.
        """
        if params is None:
            print_formatted_text(
                HTML(
                    "<ansired>Cannot create Keeper Teams:</ansired> Keeper session is not "
                    "available to the importer (no <i>params</i>)."
                )
            )
            return
        if not getattr(params, "enterprise", None):
            print_formatted_text(
                HTML(
                    "<ansired>Cannot create Keeper Teams:</ansired> the logged-in account "
                    "is not an enterprise admin (no enterprise data loaded)."
                )
            )
            return

        # Determine which groups to import (similar pattern to safes)
        groups_filter = None
        groups_file = environ.get("_CYBERARK_GROUPS_PATH", "groups.txt")
        if path.isfile(groups_file):
            with open(groups_file, "r", encoding="utf-8") as f:
                groups_filter = {line.strip() for line in f if line.strip()}
                if groups_filter:
                    print_formatted_text(
                        HTML(f"User groups from file <i>{groups_file}</i>: <b>{', '.join(sorted(groups_filter))}</b>")
                    )
        elif "_CYBERARK_GROUPS" in environ:
            groups_filter = {x.strip() for x in environ.get("_CYBERARK_GROUPS").split(",") if x.strip()}
            if groups_filter:
                print_formatted_text(
                    HTML(
                        "User groups from environment variable _CYBERARK_GROUPS: "
                        f"<b>{', '.join(sorted(groups_filter))}</b>"
                    )
                )

        print_formatted_text(HTML("\nFetching CyberArk User Groups..."))
        sleep(self.DELAY)
        response = self.get_response(
            self.get_url(pvwa_host, "user_groups"),
            authorization_token,
            {"includeMembers": "True"},
        )
        if response is None:
            return
        if response.status_code != 200:
            print_formatted_text(
                HTML(
                    f"Getting user groups from server {pvwa_host} <ansired>failed</ansired> "
                    f"with status <b>{response.status_code}</b>"
                )
            )
            return
        groups = response.json().get("value", [])
        if groups_filter:
            groups = [g for g in groups if g.get("groupName") in groups_filter or g.get("name") in groups_filter]
        if not groups:
            print_formatted_text(HTML("<ansiyellow>No user groups to import</ansiyellow>"))
            return

        
        try:
            api.query_enterprise(params)
        except Exception as e:
            logging.debug("Pre-team-add enterprise refresh failed: %s", e)

        
        existing_team_names = set()
        for team in params.enterprise.get("teams", []) or []:
            if team.get("name"):
                existing_team_names.add(team["name"].lower())
        for team in params.enterprise.get("queued_teams", []) or []:
            if team.get("name"):
                existing_team_names.add(team["name"].lower())

        # Determine the target node id (same default as enterprise-team --add):
        # the first user-root node when no --node was specified.
        node_id = None
        for nid in params.enterprise.get("user_root_nodes", []) or []:
            node_id = nid
            break
        if node_id is None:
            # Fall back to the first node in the tree (root has parent_id=0)
            for n in params.enterprise.get("nodes", []) or []:
                if not n.get("parent_id"):
                    node_id = n["node_id"]
                    break
        if node_id is None:
            print_formatted_text(
                HTML(
                    "<ansired>Cannot create Keeper Teams:</ansired> no root node found in the "
                    "enterprise tree."
                )
            )
            return

        print_formatted_text(
            HTML(f"Importing <b>{len(groups)}</b> user groups as Keeper Teams (members not provisioned):\n"),
            tabulate(
                [
                    {
                        "ID": g.get("id"),
                        "Name": g.get("groupName") or g.get("name"),
                        "CyberArk Members": len(g.get("members") or []),
                    }
                    for g in groups
                ],
                headers="keys",
            ),
            end="\n\n",
        )

        request_batch = []
        request_team_names = []  # parallel list for reporting per-batch results
        skipped_existing = []
        for g in groups:
            group_id = g.get("id")
            group_name = g.get("groupName") or g.get("name")
            if not group_name:
                continue
            members = g.get("members") or []
            # Some CyberArk versions return members only via the per-group detail endpoint
            if not members and group_id is not None:
                sleep(self.DELAY)
                detail = self.get_response(
                    self.get_url(pvwa_host, "user_group").format(group_id=group_id),
                    authorization_token,
                    {"includeMembers": "True"},
                )
                if detail is not None and detail.status_code == 200:
                    members = detail.json().get("members") or []

            
            member_names = [
                m.get("username") or m.get("userName") or str(m.get("id") or m.get("userId") or "")
                for m in members
            ]
            member_names = [n for n in member_names if n]
            logging.debug(
                "Team %s (CyberArk group id %s) - %d CyberArk member(s), not imported as users%s",
                group_name,
                group_id,
                len(member_names),
                (": " + ", ".join(member_names)) if member_names else "",
            )

            if group_name.lower() in existing_team_names:
                skipped_existing.append(group_name)
                continue

            # Build a team_add request - same shape as EnterpriseTeamCommand.execute
            team_uid = api.generate_record_uid()
            team_key = api.generate_aes_key()
            encrypted_team_key = crypto.encrypt_aes_v2(team_key, params.enterprise["unencrypted_tree_key"])
            rq = {
                "command": "team_add",
                "team_uid": team_uid,
                "team_name": group_name,
                "restrict_edit": False,
                "restrict_share": False,
                "restrict_view": False,
                "node_id": node_id,
                "team_key": utils.base64_url_encode(crypto.encrypt_aes_v1(team_key, params.data_key)),
                "encrypted_team_key": utils.base64_url_encode(encrypted_team_key),
                "manage_only": True,
            }
            ec_private_key, ec_public_key = crypto.generate_ec_key()
            encrypted_ec_private_key = crypto.encrypt_aes_v2(
                crypto.unload_ec_private_key(ec_private_key), team_key
            )
            rq["ecc_private_key"] = utils.base64_url_encode(encrypted_ec_private_key)
            rq["ecc_public_key"] = utils.base64_url_encode(crypto.unload_ec_public_key(ec_public_key))
            if not getattr(params, "forbid_rsa", False):
                rsa_private_key, rsa_public_key = crypto.generate_rsa_key()
                encrypted_rsa_private_key = crypto.encrypt_aes_v1(
                    crypto.unload_rsa_private_key(rsa_private_key), team_key
                )
                rq["public_key"] = utils.base64_url_encode(crypto.unload_rsa_public_key(rsa_public_key))
                rq["private_key"] = utils.base64_url_encode(encrypted_rsa_private_key)

            request_batch.append(rq)
            request_team_names.append(group_name)
            # Track locally so duplicates within the same run are also skipped
            existing_team_names.add(group_name.lower())

        if skipped_existing:
            print_formatted_text(
                HTML(
                    f"\n<ansiyellow>Skipped {len(skipped_existing)} group(s) that already exist as "
                    f"Keeper Teams:</ansiyellow> {', '.join(skipped_existing)}"
                )
            )

        if not request_batch:
            print_formatted_text(HTML("\nNo new Keeper Teams to create."))
        else:
            try:
                responses = api.execute_batch(params, request_batch)
            except Exception as e:
                print_formatted_text(HTML(f"\n<ansired>Failed to create Keeper Teams:</ansired> {e}"))
                responses = []

            created = 0
            failed = []
            for team_name, rs in zip(request_team_names, responses or []):
                result = (rs or {}).get("result")
                if result == "success":
                    created += 1
                else:
                    failed.append(
                        {
                            "Team": team_name,
                            "Code": (rs or {}).get("result_code"),
                            "Message": (rs or {}).get("message"),
                        }
                    )

            print_formatted_text(
                HTML(f"\nCreated <ansigreen>{created}</ansigreen> of <b>{len(request_batch)}</b> Keeper Teams")
            )
            if failed:
                print_formatted_text(
                    HTML("\n<ansired>Some teams could not be created:</ansired>\n"),
                    tabulate(failed, headers="keys"),
                    end="\n\n",
                )

        # Also create a Keeper Enterprise Role for each user group (mirrors enterprise-role --add)
        if environ.get("_CYBERARK_SKIP_ROLES", "").lower() not in ("1", "true", "yes"):
            self._create_keeper_roles(groups, params, node_id)

        # Provision Keeper users (using their real CyberArk business emails)
        # and assign them to matching Roles.
        if environ.get("_CYBERARK_SKIP_CREATE_USERS", "").lower() not in ("1", "true", "yes"):
            if cyberark_users is None:
                print_formatted_text(HTML("\nFetching CyberArk Users for provisioning..."))
                cyberark_users = self.fetch_cyberark_users(
                    pvwa_host, authorization_token, fetch_groups_membership=True,
                )
            self._create_keeper_users_and_assign_roles(groups, cyberark_users, params, node_id)

    def _create_keeper_roles(self, groups, params, node_id):
        """Create one Keeper Enterprise Role per CyberArk user group.

        Mirrors the ``enterprise-role --add`` command flow: allocates a fresh
        enterprise id for each new role, encrypts ``{"displayname": <name>}``
        with the enterprise tree key, and submits a ``role_add`` request per
        role via ``api.communicate`` (one-by-one so a single failure does not
        hide the others — matching ``EnterpriseRoleCommand``'s behavior, which
        also logs each error individually).


        """
        
        try:
            api.query_enterprise(params)
        except Exception as e:
            print_formatted_text(
                HTML(f"\n<ansiyellow>Warning: could not refresh enterprise data before role creation: {e}</ansiyellow>")
            )

        if not getattr(params, "enterprise", None):
            print_formatted_text(
                HTML(
                    "\n<ansired>Cannot create Keeper Roles:</ansired> enterprise data is "
                    "not available (are you logged in as an enterprise administrator?)."
                )
            )
            return

        tree_key = params.enterprise.get("unencrypted_tree_key")
        if not tree_key:
            print_formatted_text(
                HTML(
                    "\n<ansired>Cannot create Keeper Roles:</ansired> enterprise tree key is "
                    "not available."
                )
            )
            return

        # Build a lookup of existing role display names (case-insensitive)
        existing_role_names = set()
        for r in params.enterprise.get("roles", []) or []:
            display = (r.get("data") or {}).get("displayname") or ""
            if display:
                existing_role_names.add(display.lower())

        new_role_names = []
        skipped_existing = []
        seen_in_batch = set()
        for g in groups:
            group_name = g.get("groupName") or g.get("name")
            if not group_name:
                continue
            key = group_name.lower()
            if key in existing_role_names or key in seen_in_batch:
                skipped_existing.append(group_name)
                continue
            seen_in_batch.add(key)
            new_role_names.append(group_name)

        if skipped_existing:
            print_formatted_text(
                HTML(
                    f"\n<ansiyellow>Skipped {len(skipped_existing)} group(s) that already exist as "
                    f"Keeper Roles:</ansiyellow> {', '.join(skipped_existing)}"
                )
            )

        if not new_role_names:
            print_formatted_text(HTML("\nNo new Keeper Roles to create."))
            return

        print_formatted_text(
            HTML(f"\nCreating <b>{len(new_role_names)}</b> Keeper Roles...")
        )

        created = 0
        failed = []
        for role_name in new_role_names:
            # Allocate a role id (one call per role - same as EnterpriseRoleCommand).
            try:
                role_id = EnterpriseCommand.get_enterprise_id(params)
            except Exception as e:
                logging.exception("Failed to allocate role id for '%s'", role_name)
                failed.append({"Role": role_name, "Code": "id-alloc", "Message": str(e)})
                continue
            if not role_id:
                failed.append({"Role": role_name, "Code": "id-alloc", "Message": "no id returned"})
                continue

            data = json.dumps({"displayname": role_name}).encode("utf-8")
            rq = {
                "command": "role_add",
                "role_id": role_id,
                "node_id": node_id,
                "encrypted_data": utils.base64_url_encode(crypto.encrypt_aes_v1(data, tree_key)),
                "visible_below": False,
                "new_user_inherit": False,
                "role_name": role_name,
            }

            try:
                rs = api.communicate(params, rq)
            except Exception as e:
                logging.exception("role_add request failed for '%s'", role_name)
                failed.append({"Role": role_name, "Code": "exception", "Message": str(e)})
                continue

            if (rs or {}).get("result") == "success":
                created += 1
            else:
                failed.append(
                    {
                        "Role": role_name,
                        "Code": (rs or {}).get("result_code") or "unknown",
                        "Message": (rs or {}).get("message") or "no message",
                    }
                )

        print_formatted_text(
            HTML(f"\nCreated <ansigreen>{created}</ansigreen> of <b>{len(new_role_names)}</b> Keeper Roles")
        )
        if failed:
            print_formatted_text(
                HTML("\n<ansired>Some roles could not be created:</ansired>\n"),
                tabulate(failed, headers="keys"),
                end="\n\n",
            )

        # Refresh enterprise data so the new roles appear in subsequent commands
        # (mirrors EnterpriseRoleCommand which calls query_enterprise after role_add).
        if created > 0:
            try:
                api.query_enterprise(params, force=True)
            except Exception as e:
                logging.debug("Post-role-add enterprise refresh failed: %s", e)

    # Default domains to reject (the email's domain, not the username).
    
    DEFAULT_EMAIL_DOMAIN_BLOCKLIST = ("cyberark.cloud", "cyberark.com", "id.cyberark.cloud")

    @classmethod
    def _is_valid_cyberark_user_email(cls, email):
        """Return True if ``email`` looks like a real, non-CyberArk-internal mailbox."""
        if not email:
            return False
        # Must match Keeper's email regex.
        if not re.match(EMAIL_PATTERN, email):
            return False
        # Block emails whose DOMAIN matches the blocklist. We deliberately ignore
        
        try:
            domain = email.split("@", 1)[1].strip().lower()
        except IndexError:
            return False
        blocklist_env = environ.get("_CYBERARK_USER_EMAIL_DOMAIN_BLOCKLIST")
        if blocklist_env is not None:
            blocked = {x.strip().lower() for x in blocklist_env.split(",") if x.strip()}
        else:
            blocked = set(cls.DEFAULT_EMAIL_DOMAIN_BLOCKLIST)
        for bad in blocked:
            if domain == bad or domain.endswith("." + bad):
                return False
        return True

    def _create_keeper_users_and_assign_roles(self, groups, cyberark_users, params, node_id):
        """Provision Keeper Enterprise users from valid CyberArk users and add them to matching Roles.
        """
        if not cyberark_users:
            print_formatted_text(HTML("\n<ansiyellow>No CyberArk users available - skipping user creation.</ansiyellow>"))
            return
        if params is None or not getattr(params, "enterprise", None):
            print_formatted_text(
                HTML(
                    "\n<ansired>Cannot create Keeper users:</ansired> the logged-in account "
                    "is not an enterprise admin (no enterprise data loaded)."
                )
            )
            return

        
        accepted = []  # list of dicts: {cyberark_username, cyberark_email, keeper_email, displayname, groups_membership}
        rejected = []  # list of dicts: {Username, Email, Reason}
        seen_emails = {}  # lowercase business email -> index in ``accepted``
        for u in cyberark_users:
            cyberark_username = u.get("username") or ""
            cyberark_email = u.get("email") or ""
            if not self._is_valid_cyberark_user_email(cyberark_email):
                if not cyberark_email:
                    reason = "no email"
                elif not re.match(EMAIL_PATTERN, cyberark_email):
                    reason = "invalid email format"
                else:
                    reason = "email domain is in CyberArk-internal blocklist"
                rejected.append({"Username": cyberark_username, "Email": cyberark_email, "Reason": reason})
                continue

            email_key = cyberark_email.strip().lower()
            existing_idx = seen_emails.get(email_key)
            if existing_idx is not None:
               
                primary = accepted[existing_idx]
                for g in (u.get("groups_membership") or []):
                    if g not in primary["groups_membership"]:
                        primary["groups_membership"].append(g)
                rejected.append(
                    {
                        "Username": cyberark_username,
                        "Email": cyberark_email,
                        "Reason": (
                            f"duplicate of CyberArk user '{primary['cyberark_username']}' "
                            "(same business email)"
                        ),
                    }
                )
                continue

            seen_emails[email_key] = len(accepted)
            accepted.append(
                {
                    "cyberark_username": cyberark_username,
                    "cyberark_email": cyberark_email,                       
                    "keeper_email": cyberark_email,
                    "displayname": cyberark_username or cyberark_email,
                    "groups_membership": list(u.get("groups_membership") or []),
                }
            )

        if rejected:
            print_formatted_text(
                HTML(f"\n<ansiyellow>Skipped {len(rejected)} CyberArk user(s) (invalid for Keeper provisioning):</ansiyellow>\n"),
                tabulate(rejected, headers="keys"),
                end="\n\n",
            )

        if not accepted:
            print_formatted_text(HTML("\nNo CyberArk users were eligible for Keeper provisioning."))
            return

        # Show the mapping so it's auditable.
        print_formatted_text(
            HTML(f"\nProvisioning <b>{len(accepted)}</b> Keeper user(s):\n"),
            tabulate(
                [
                    {
                        "CyberArk Username": a["cyberark_username"],
                        "CyberArk Email": a["cyberark_email"],
                        "Keeper Email": a["keeper_email"],
                    }
                    for a in accepted
                ],
                headers="keys",
            ),
            end="\n\n",
        )

        # Refresh enterprise so we see current users + roles before checking for duplicates.
        try:
            api.query_enterprise(params)
        except Exception as e:
            logging.debug("Pre-user-invite enterprise refresh failed: %s", e)

        # Build a lookup of existing users so we don't try to invite the same email twice.
        existing_user_by_email = {}
        for u in (params.enterprise.get("users") or []):
            uname = (u.get("username") or "").lower()
            if uname:
                existing_user_by_email[uname] = u

        # Determine the target node (root node) for new invitations.
        invite_node_id = None
        for nid in params.enterprise.get("user_root_nodes", []) or []:
            invite_node_id = nid
            break
        if invite_node_id is None:
            for n in params.enterprise.get("nodes", []) or []:
                if not n.get("parent_id"):
                    invite_node_id = n["node_id"]
                    break
        if invite_node_id is None:
            print_formatted_text(
                HTML(
                    "\n<ansired>Cannot invite Keeper users:</ansired> no root node found in "
                    "the enterprise tree."
                )
            )
            return

        tree_key = params.enterprise.get("unencrypted_tree_key")
        if not tree_key:
            print_formatted_text(
                HTML(
                    "\n<ansired>Cannot invite Keeper users:</ansired> enterprise tree key is "
                    "not available."
                )
            )
            return

        # Build the enterprise_user_add batch (mirrors enterprise-user --add / --invite).
        users_to_invite = []  # list of accepted entries that need a new invite
        users_to_resend = []  # accepted entries whose Keeper account is still 'invited'
        skipped_existing = []  # accepted entries whose Keeper account already exists
        for a in accepted:
            keeper_email = a["keeper_email"]
            existing = existing_user_by_email.get(keeper_email.lower())
            if existing is None:
                users_to_invite.append(a)
            elif existing.get("status") == "invited":
                users_to_resend.append((a, existing))
            else:
                skipped_existing.append(keeper_email)

        # Allocate one enterprise id per new invitation.
        new_user_ids = []
        if users_to_invite:
            try:
                new_user_ids = EnterpriseCommand.get_enterprise_ids(params, len(users_to_invite))
            except Exception as e:
                print_formatted_text(
                    HTML(f"\n<ansired>Failed to allocate user ids:</ansired> {e}")
                )
                return
            if not new_user_ids or any(uid is None for uid in new_user_ids[: len(users_to_invite)]):
                print_formatted_text(
                    HTML(
                        "\n<ansired>Could not allocate enterprise ids for all users.</ansired> "
                        "Aborting user invitation."
                    )
                )
                return

        request_batch = []
        request_descriptions = []  # parallel: (email, "invited"/"resent") for reporting
        for i, a in enumerate(users_to_invite):
            displayname = a["displayname"] or a["keeper_email"]
            encrypted_data = utils.base64_url_encode(
                crypto.encrypt_aes_v1(
                    json.dumps({"displayname": displayname}).encode("utf-8"),
                    tree_key,
                )
            )
            rq = {
                "command": "enterprise_user_add",
                "enterprise_user_id": new_user_ids[i],
                "node_id": invite_node_id,
                "encrypted_data": encrypted_data,
                "enterprise_user_username": a["keeper_email"],
            }
            request_batch.append(rq)
            request_descriptions.append((a["keeper_email"], "invited"))

        for a, existing in users_to_resend:
            rq = {
                "command": "resend_enterprise_invite",
                "enterprise_user_id": existing["enterprise_user_id"],
            }
            request_batch.append(rq)
            request_descriptions.append((a["keeper_email"], "resent"))

        if skipped_existing:
            print_formatted_text(
                HTML(
                    f"\n<ansiyellow>{len(skipped_existing)} user(s) already exist in Keeper "
                    f"- skipping invitation but will still assign roles:</ansiyellow> "
                    f"{', '.join(skipped_existing)}"
                )
            )

        if not request_batch:
            print_formatted_text(HTML("\nNo new Keeper invitations to send."))
        else:
            try:
                responses = api.execute_batch(params, request_batch)
            except Exception as e:
                print_formatted_text(HTML(f"\n<ansired>Failed to send invitations:</ansired> {e}"))
                responses = []

            invited = 0
            resent = 0
            failed_users = []
            for (email, action), rs in zip(request_descriptions, responses or []):
                if (rs or {}).get("result") == "success":
                    if action == "invited":
                        invited += 1
                    else:
                        resent += 1
                else:
                    failed_users.append(
                        {
                            "Email": email,
                            "Action": action,
                            "Code": (rs or {}).get("result_code") or "unknown",
                            "Message": (rs or {}).get("message") or "no message",
                        }
                    )

            if invited:
                print_formatted_text(
                    HTML(f"\nInvited <ansigreen>{invited}</ansigreen> new Keeper user(s)")
                )
            if resent:
                print_formatted_text(
                    HTML(f"Resent invitation to <ansigreen>{resent}</ansigreen> previously-invited user(s)")
                )
            if failed_users:
                print_formatted_text(
                    HTML("\n<ansired>Some invitations failed:</ansired>\n"),
                    tabulate(failed_users, headers="keys"),
                    end="\n\n",
                )

        # Refresh enterprise data so newly invited users + the roles we just made are in cache.
        try:
            api.query_enterprise(params, force=True)
        except Exception as e:
            logging.debug("Pre-role-assignment enterprise refresh failed: %s", e)

        # Build lookups from the freshest enterprise state.
        user_id_by_email = {}
        for u in params.enterprise.get("users", []) or []:
            uname = (u.get("username") or "").lower()
            if uname:
                user_id_by_email[uname] = u.get("enterprise_user_id")

        role_id_by_name = {}
        for r in params.enterprise.get("roles", []) or []:
            display = ((r.get("data") or {}).get("displayname") or "").strip().lower()
            if display and display not in role_id_by_name:
                # If multiple roles share a name (across nodes) we just use the first one,
                # matching how `enterprise-role` warns about ambiguity. For our case roles
                # were just created at the root node so collisions are unlikely.
                role_id_by_name[display] = r.get("role_id")

        # Existing role-user assignments so we don't re-add (avoids spurious failures).
        existing_role_users = {(x.get("role_id"), x.get("enterprise_user_id"))
                               for x in (params.enterprise.get("role_users") or [])}

        
        groups_by_cyberark_username = {}
        for g in groups or []:
            group_name = g.get("groupName") or g.get("name") or ""
            if not group_name:
                continue
            for m in g.get("members") or []:
                m_username = (m.get("username") or m.get("userName") or "").strip().lower()
                if not m_username:
                    continue
                groups_by_cyberark_username.setdefault(m_username, []).append(group_name)

        # Build the role_user_add batch.
        request_batch = []
        request_descriptions = []  # parallel: (keeper_email, role_name) for reporting
        assignments_skipped = []  # already a member
        assignments_unmappable = []  # no role for that group name
        users_without_groups = []  # accepted user but not in any CyberArk group

        for a in accepted:
            keeper_email = a["keeper_email"]
            cyberark_username = a["cyberark_username"]
            enterprise_user_id = user_id_by_email.get(keeper_email.lower())
            if not enterprise_user_id:
                # User creation must have failed (e.g. domain not reserved). Skip role assignment.
                continue
           
            their_groups = []
            for gm in a.get("groups_membership") or []:
                gname = (gm.get("groupName") or "").strip()
                if gname:
                    their_groups.append(gname)
            if not their_groups:
                their_groups = list(groups_by_cyberark_username.get(cyberark_username.lower(), []))
            if not their_groups:
                users_without_groups.append(keeper_email)
                continue
            # Deduplicate while preserving order.
            seen = set()
            their_groups = [g for g in their_groups if not (g.lower() in seen or seen.add(g.lower()))]
            for group_name in their_groups:
                role_id = role_id_by_name.get(group_name.strip().lower())
                if not role_id:
                    assignments_unmappable.append({"User": keeper_email, "Group": group_name})
                    continue
                if (role_id, enterprise_user_id) in existing_role_users:
                    assignments_skipped.append({"User": keeper_email, "Role": group_name})
                    continue
                request_batch.append(
                    {
                        "command": "role_user_add",
                        "role_id": role_id,
                        "enterprise_user_id": enterprise_user_id,
                    }
                )
                request_descriptions.append((keeper_email, group_name))
                existing_role_users.add((role_id, enterprise_user_id))

        if assignments_skipped:
            print_formatted_text(
                HTML(
                    f"\n<ansiyellow>Skipped {len(assignments_skipped)} role assignment(s) "
                    f"that already exist.</ansiyellow>"
                )
            )
        if assignments_unmappable:
            print_formatted_text(
                HTML(
                    f"\n<ansiyellow>{len(assignments_unmappable)} role assignment(s) could not "
                    "find a matching Keeper Role by name:</ansiyellow>\n"
                ),
                tabulate(assignments_unmappable, headers="keys"),
                end="\n\n",
            )
        if users_without_groups:
            print_formatted_text(
                HTML(
                    f"\n<ansiyellow>{len(users_without_groups)} user(s) were not a member of "
                    f"any CyberArk group:</ansiyellow> {', '.join(users_without_groups)}"
                )
            )

        if not request_batch:
            print_formatted_text(HTML("\nNo new role assignments to send."))
            return

        try:
            responses = api.execute_batch(params, request_batch)
        except Exception as e:
            print_formatted_text(HTML(f"\n<ansired>Failed to assign users to roles:</ansired> {e}"))
            return

        added = 0
        failed_assignments = []
        for (email, role_name), rs in zip(request_descriptions, responses or []):
            if (rs or {}).get("result") == "success":
                added += 1
            else:
                failed_assignments.append(
                    {
                        "User": email,
                        "Role": role_name,
                        "Code": (rs or {}).get("result_code") or "unknown",
                        "Message": (rs or {}).get("message") or "no message",
                    }
                )

        print_formatted_text(
            HTML(f"\nAssigned <ansigreen>{added}</ansigreen> of <b>{len(request_batch)}</b> user-to-role memberships")
        )
        if failed_assignments:
            print_formatted_text(
                HTML("\n<ansired>Some role assignments failed:</ansired>\n"),
                tabulate(failed_assignments, headers="keys"),
                end="\n\n",
            )

        # Final refresh so subsequent commands see the new memberships.
        try:
            api.query_enterprise(params, force=True)
        except Exception as e:
            logging.debug("Post-role-assignment enterprise refresh failed: %s", e)


class CyberArkMembershipDownload(CyberArkImporter, BaseDownloadMembership):
    """Download CyberArk safe and user-group membership for ``download-membership``.

    Maps CyberArk Safes → Keeper ``SharedFolder`` objects (with per-member
    ``Permission`` entries) and CyberArk User Groups → Keeper ``Team`` objects.
    """

    @staticmethod
    def _resolve_pvwa_host():
        """Prompt for (or read from env) the PVWA hostname / URL."""
        host = environ.get("_CYBERARK_PVWA_HOST")
        if host:
            return host
        try:
            entered = prompt(
                "CyberArk PVWA hostname or URL (e.g. pvwa.example.com or https://tenant.cyberark.cloud): "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        return entered or None

    @staticmethod
    def _build_user_email_lookup(cyberark_users):
        """Map CyberArk username (lowercase) → best available email."""
        lookup = {}
        for u in cyberark_users or []:
            username = (u.get("username") or "").strip()
            email = (u.get("email") or "").strip()
            if username and email:
                lookup[username.lower()] = email
        return lookup

    @staticmethod
    def _build_service_account_username_set(cyberark_users):
        """Return the set of lowercase usernames that are service accounts.
        """
        return {
            (u.get("username") or "").strip().lower()
            for u in (cyberark_users or [])
            if (u.get("username") or "").strip() and _is_service_account_user(u)
        }

    @staticmethod
    def _member_permission_name(member, user_email_lookup):
        """Return the Keeper permission ``name`` for a CyberArk safe member."""
        member_name = (member.get("memberName") or "").strip()
        member_type = member.get("memberType", "User")
        if member_type == "Group":
            return member_name
        email = user_email_lookup.get(member_name.lower())
        return email or member_name

    def download_membership(self, params, **kwargs):
        folders_only = kwargs.get("folders_only") is True
       
        include_service_accounts = environ.get(
            "_CYBERARK_INCLUDE_COMPONENT_USERS", ""
        ).lower() in ("1", "true", "yes")
        pvwa_input = self._resolve_pvwa_host()
        if not pvwa_input:
            print_formatted_text(HTML("<ansired>PVWA hostname is required</ansired>"))
            return

        try:
            auth = self._authenticate_pvwa(pvwa_input)
            if auth is None:
                return
            pvwa_host, authorization_token, _query_params = auth

            print_formatted_text(HTML("\nFetching CyberArk users for email resolution..."))
            cyberark_users = self.fetch_cyberark_users(pvwa_host, authorization_token)
            user_email_lookup = self._build_user_email_lookup(cyberark_users)
            service_account_usernames = (
                set()
                if include_service_accounts
                else self._build_service_account_username_set(cyberark_users)
            )

            groups_filter = None
            groups_file = environ.get("_CYBERARK_GROUPS_PATH", "groups.txt")
            if path.isfile(groups_file):
                with open(groups_file, "r", encoding="utf-8") as f:
                    groups_filter = {line.strip() for line in f if line.strip()}
            elif "_CYBERARK_GROUPS" in environ:
                groups_filter = {
                    x.strip() for x in environ.get("_CYBERARK_GROUPS").split(",") if x.strip()
                }

            safes_filter = None
            safes_file = environ.get("_CYBERARK_SAFES_PATH", "safes.txt")
            if path.isfile(safes_file):
                with open(safes_file, "r", encoding="utf-8") as f:
                    safes_filter = {line.strip() for line in f if line.strip()}
            elif "_CYBERARK_SAFES" in environ:
                safes_filter = {x.strip() for x in environ.get("_CYBERARK_SAFES").split(",") if x.strip()}

            print_formatted_text(HTML("\nFetching CyberArk Safes..."))
            safes = self.fetch_all_safes(pvwa_host, authorization_token, safes_filter=safes_filter)
            if not safes:
                print_formatted_text(HTML("<ansiyellow>No safes returned by CyberArk</ansiyellow>"))
            else:
                print_formatted_text(
                    HTML(f"Downloading membership for <b>{len(safes)}</b> safe(s)...")
                )

            sf_group_ids = set()
            for safe in safes:
                safe_name = safe.get("safeName") or safe.get("safeUrlId") or ""
                safe_url_id = safe.get("safeUrlId") or safe.get("safeName") or ""
                if not safe_name:
                    continue

                members = self.fetch_safe_members(pvwa_host, authorization_token, safe_url_id)
                if not members:
                    continue

                shared_folder = SharedFolder()
                shared_folder.uid = str(safe.get("id") or safe_url_id)
                shared_folder.path = safe_name
                shared_folder.permissions = []

                skipped_service = 0
                for member in members:
                    member_type = member.get("memberType", "User")
                    member_name = (member.get("memberName") or "").strip()
                    # Skip non-human safe members (gateway/service/component users).
                    # Groups are kept — group membership is filtered separately below.
                    if (
                        not include_service_accounts
                        and member_type != "Group"
                        and member_name
                        and (
                            member_name.lower() in service_account_usernames
                            or _is_service_account_user(member)
                        )
                    ):
                        skipped_service += 1
                        continue

                    perm_name = self._member_permission_name(member, user_email_lookup)
                    if not perm_name:
                        continue
                    keeper_perms = PermissionMapper.map_permissions(member.get("permissions") or {})
                    perm = Permission()
                    perm.name = perm_name
                    perm.manage_users = keeper_perms.get("manage_users", False)
                    perm.manage_records = keeper_perms.get("manage_records", False)
                    shared_folder.permissions.append(perm)
                    if member_type == "Group":
                        sf_group_ids.add(perm_name)

                if skipped_service:
                    logging.debug(
                        "Safe %s: skipped %d service-account member(s)",
                        safe_name,
                        skipped_service,
                    )

                if shared_folder.permissions:
                    yield shared_folder

            if folders_only:
                return

            print_formatted_text(HTML("\nFetching CyberArk User Groups..."))
            sleep(self.DELAY)
            response = self.get_response(
                self.get_url(pvwa_host, "user_groups"),
                authorization_token,
                {"includeMembers": "True"},
            )
            if response is None:
                return
            if response.status_code != 200:
                print_formatted_text(
                    HTML(
                        f"Getting user groups <ansired>failed</ansired> with status "
                        f"<b>{response.status_code}</b>"
                    )
                )
                return

            groups = response.json().get("value", [])
            if groups_filter:
                groups = [
                    g for g in groups
                    if g.get("groupName") in groups_filter or g.get("name") in groups_filter
                ]

            if not sf_group_ids:
                return

            for g in groups:
                group_id = g.get("id")
                group_name = g.get("groupName") or g.get("name") or ""
                if not group_name or group_name not in sf_group_ids:
                    continue

                members = g.get("members") or []
                if not members and group_id is not None:
                    sleep(self.DELAY)
                    detail = self.get_response(
                        self.get_url(pvwa_host, "user_group").format(group_id=group_id),
                        authorization_token,
                        {"includeMembers": "True"},
                    )
                    if detail is not None and detail.status_code == 200:
                        members = detail.json().get("members") or []

                emails = []
                for m in members:
                    username = (m.get("username") or m.get("userName") or "").strip()
                    if not username:
                        continue
                    # Skip service-account members of the group as well.
                    if (
                        not include_service_accounts
                        and (
                            username.lower() in service_account_usernames
                            or _is_service_account_user(m)
                        )
                    ):
                        continue
                    email = user_email_lookup.get(username.lower()) or self._extract_user_email(m)
                    if email:
                        emails.append(email)
                    elif username:
                        emails.append(username)

                if not emails:
                    continue

                team = Team()
                team.uid = str(group_id) if group_id is not None else group_name
                team.name = group_name
                team.members = list(dict.fromkeys(emails))
                yield team

        finally:
            self._cleanup_tmp_cert_files()
