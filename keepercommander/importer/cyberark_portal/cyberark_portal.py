import base64
import hashlib
import re
from http import HTTPStatus
from http.server import HTTPServer, BaseHTTPRequestHandler
from os import environ
from time import sleep
from urllib.parse import urlparse, parse_qs
import logging
import uuid
import requests
import threading
import webbrowser
from prompt_toolkit import HTML, print_formatted_text, prompt
from tabulate import tabulate


from ..importer import BaseImporter, Folder, Record, RecordField
import secrets
import string


_SHARING_FIELD_NAMES = (
    "IsShared",
    "Shared",
    "IsOwner",
    "Owner",
    "OwnerLogin",
    "OwnerEmail",
    "OwnerDisplayName",
    "SharedBy",
    "SharedByName",
    "SharedByDisplayName",
    "SharedWith",
    "SharedWithCount",
    "SharingCount",
    "ShareCount",
    "AdminTag",
    "IsAdminCreated",
    "IsAdminAssigned",
    "Permission",
    "Permissions",
    "EffectivePermissions",
    "ItemPermissions",
    "AccessLevel",
    "AccessRights",
    "Role",
    "Roles",
    "AssignedRoles",
    "StartTime",
    "EndTime",
)


def _format_sharing_value(value):
    """Render a sharing/access value for display in a Keeper text field."""
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        parts = []
        for v in value:
            if isinstance(v, dict):
                # Prefer human-readable names if available
                name = (v.get("Name") or v.get("DisplayName") or v.get("PrincipalName")
                        or v.get("UserName") or v.get("Login") or v.get("Email")
                        or v.get("ID") or "")
                perm = v.get("Permission") or v.get("Right") or v.get("AccessLevel") or ""
                if name and perm:
                    parts.append(f"{name} ({perm})")
                elif name:
                    parts.append(str(name))
                else:
                    parts.append(str(v))
            elif v is not None and v != "":
                parts.append(str(v))
        return ", ".join(parts)
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items() if v not in (None, "", False))
    return str(value)


def _collect_sharing_fields(item, prefix=""):
    """Return a list of (label, value) tuples for sharing/access metadata
    present on the given item dict. ``prefix`` is prepended to labels for
    nested contexts (e.g. folder-level sharing on a record).
    """
    out = []
    if not isinstance(item, dict):
        return out
    for key in _SHARING_FIELD_NAMES:
        if key not in item:
            continue
        v = item.get(key)
        if v in (None, "", [], {}):
            continue
        formatted = _format_sharing_value(v)
        if not formatted or formatted in ("no", "0"):
            # Skip explicit false/empty signals so we don't clutter records
            # with negative facts.
            continue
        label = f"{prefix}{key}" if prefix else key
        out.append((label, formatted))
    return out


class CyberArkPortalImporter(BaseImporter):
    """CyberArk Portal Importer
    This importer enables users to import Applications and SecuredItems from the CyberArk User Portal.
    If the User is authenticated via SSO, it will use OAuth2 with PKCE for authorization.
    Otherwise it will attempt to authenticate using the CyberArk Identity API.
    After successful authentication, it creates a Keeper record for each Application,
    and Secured Item in the user's portal.

    The API documentation can be found at
    https://api-docs.cyberark.com/docs/identity-api-reference/

    Yields:
        Keeper login type records for Applications and Passwords and secure note records for SecuredItems.
    """

    LOOP_DELAY = 0.025  # Use quarter millisecond delay between requests to avoid hitting the API rate limits
    TIMEOUT = 10  # Wait up to 10 seconds for CyberArk API requests

    @staticmethod
    def get_url(identity_base_url, endpoint):
        return f'{identity_base_url.rstrip("/")}/{endpoint.lstrip("/").rstrip("/")}'

    def _try_get_json(self, identity_base_url, endpoint, authentication_token, *,
                      params=None, payload=None, method="POST",
                      missing_endpoint_cache=None, quiet_statuses=(404, 403, 501)):
        """Best-effort call to a CyberArk Identity endpoint that may or may
        not be available on a given tenant.

        """
        url = self.get_url(identity_base_url, endpoint)
        if missing_endpoint_cache is not None and endpoint in missing_endpoint_cache:
            return None
        try:
            if method == "GET":
                response = requests.get(
                    url,
                    headers={"Authorization": f"Bearer {authentication_token}"},
                    params=params,
                    timeout=self.TIMEOUT,
                )
            else:
                response = requests.post(
                    url,
                    headers={"Authorization": f"Bearer {authentication_token}"},
                    params=params,
                    json=payload if payload is not None else {},
                    timeout=self.TIMEOUT,
                )
        except requests.RequestException as e:
            logging.debug(f"Sharing endpoint {endpoint} request failed: {e}")
            return None

        if response.status_code in quiet_statuses:
            if missing_endpoint_cache is not None and endpoint not in missing_endpoint_cache:
                missing_endpoint_cache.add(endpoint)
                logging.debug(
                    f"CyberArk Identity endpoint {endpoint} not available on this tenant "
                    f"(HTTP {response.status_code}); skipping sharing details for this resource type."
                )
            return None
        if response.status_code != HTTPStatus.OK:
            logging.debug(
                f"Sharing endpoint {endpoint} returned HTTP {response.status_code}: {response.text[:200]}"
            )
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        if isinstance(body, dict) and body.get("success") is False:
            logging.debug(
                f"Sharing endpoint {endpoint} reported failure: {body.get('Message') or body.get('MessageID')}"
            )
            return None
        if isinstance(body, dict) and "Result" in body:
            return body.get("Result")
        return body

    def _fetch_app_sharing(self, identity_base_url, authentication_token, app_key,
                           missing_endpoint_cache):
        """Try several CyberArk Identity endpoints that may surface app
        sharing info. Returns a dict (possibly empty) of sharing metadata.
        """
        if not app_key:
            return {}
        # /UPRest/GetAppByKey returns the same record as in GetUPData but
        # some tenants include extra sharing/owner fields here.
        result = self._try_get_json(
            identity_base_url,
            f"/UPRest/GetAppByKey?appkey={app_key}",
            authentication_token,
            missing_endpoint_cache=missing_endpoint_cache,
        )
        if isinstance(result, dict):
            return result
        return {}

    def _fetch_secured_item_sharing(self, identity_base_url, authentication_token,
                                    item_key, missing_endpoint_cache):
        """Best-effort fetch of per-secured-item sharing details.
        """
        if not item_key:
            return {}
        candidates = (
            f"/UPRest/GetSecuredItemShareInfo?sItemKey={item_key}",
            f"/UPRest/GetSecuredItem?sItemKey={item_key}",
        )
        for endpoint in candidates:
            result = self._try_get_json(
                identity_base_url, endpoint, authentication_token,
                missing_endpoint_cache=missing_endpoint_cache,
            )
            if isinstance(result, dict) and result:
                return result
        return {}

    def _fetch_folders(self, identity_base_url, authentication_token,
                       missing_endpoint_cache):
        """Fetch the user's CyberArk Identity folders (a.k.a. Collections).
        """
        candidates = (
            "/UPRest/GetCollectionList",
            "/UPRest/GetCollections",
            "/UPRest/GetFolders",
        )
        for endpoint in candidates:
            result = self._try_get_json(
                identity_base_url, endpoint, authentication_token,
                missing_endpoint_cache=missing_endpoint_cache,
            )
            if result is None:
                continue
            # Different endpoints can return slightly different shapes; we
            # normalize a few common ones.
            if isinstance(result, list):
                return [f for f in result if isinstance(f, dict)]
            if isinstance(result, dict):
                for key in ("Collections", "Folders", "Results"):
                    items = result.get(key)
                    if isinstance(items, list):
                        return [f for f in items if isinstance(f, dict)]
        return []

    @staticmethod
    def _build_folder_index(folders):
        """Build a mapping item_key -> list[folder_dict] for every secured
        item / app that's listed as a member of any folder.
        """
        index = {}
        for folder in folders:
            if not isinstance(folder, dict):
                continue
            member_keys = []
            for k in ("AppKeys", "SecuredItemKeys", "ItemKeys"):
                v = folder.get(k)
                if isinstance(v, list):
                    member_keys.extend(str(x) for x in v if x)
            for k in ("Items", "Members"):
                v = folder.get(k)
                if isinstance(v, list):
                    for member in v:
                        if isinstance(member, dict):
                            mk = (member.get("AppKey") or member.get("ItemKey")
                                  or member.get("Key") or member.get("ID")
                                  or member.get("_RowKey"))
                            if mk:
                                member_keys.append(str(mk))
                        elif member:
                            member_keys.append(str(member))
            for mk in member_keys:
                index.setdefault(mk, []).append(folder)
        return index

    @staticmethod
    def _folder_display_name(folder):
        return (folder.get("Name") or folder.get("DisplayName")
                or folder.get("Title") or folder.get("CollectionName")
                or folder.get("ID") or "")

    def _apply_sharing_and_folders(self, *, record, item, item_key, folder_index,
                                   identity_base_url, authentication_token,
                                   missing_endpoint_cache, item_kind):
        """Attach sharing/access metadata and folder placement to ``record``.
        """
        # 1) Surface sharing fields already on the bulk-response item.
        for label, value in _collect_sharing_fields(item):
            record.fields.append(RecordField(type="text", label=f"CyberArk {label}", value=value))

        # 2) Best-effort per-item fetch for richer sharing details.
        detail = {}
        if item_kind == "app":
            detail = self._fetch_app_sharing(
                identity_base_url, authentication_token, item_key, missing_endpoint_cache,
            )
        elif item_kind == "secured_item":
            detail = self._fetch_secured_item_sharing(
                identity_base_url, authentication_token, item_key, missing_endpoint_cache,
            )
        if detail:
            # Avoid duplicating labels we already wrote from the bulk response.
            already = {f.label for f in record.fields if f.label}
            for label, value in _collect_sharing_fields(detail):
                full_label = f"CyberArk {label}"
                if full_label in already:
                    continue
                record.fields.append(RecordField(type="text", label=full_label, value=value))
                already.add(full_label)

        # 3) Folder placement + folder-level sharing.
        if folder_index and item_key:
            owning_folders = folder_index.get(str(item_key)) or []
            if owning_folders:
                record.folders = []
                folder_share_lines = []
                for f in owning_folders:
                    fname = self._folder_display_name(f)
                    if not fname:
                        continue
                    rec_folder = Folder()
                    rec_folder.path = fname
                    # Map CyberArk's coarse folder permissions onto Keeper's
                    perm = (f.get("Permission") or f.get("AccessLevel")
                            or f.get("EffectivePermission") or "")
                    perm_lower = str(perm).lower()
                    if perm_lower in ("owner", "manage"):
                        rec_folder.can_edit = True
                        rec_folder.can_share = True
                    elif perm_lower in ("edit", "modify", "write"):
                        rec_folder.can_edit = True
                        rec_folder.can_share = False
                    elif perm_lower in ("view", "read"):
                        rec_folder.can_edit = False
                        rec_folder.can_share = False
                    record.folders.append(rec_folder)

                    fshare = _collect_sharing_fields(f, prefix=f"Folder[{fname}] ")
                    folder_share_lines.extend(f"{label}: {value}" for label, value in fshare)

                if folder_share_lines:
                    record.fields.append(
                        RecordField(
                            type="text",
                            label="CyberArk Folder Sharing",
                            value="\n".join(folder_share_lines),
                        )
                    )

    @staticmethod
    def discover_identity_url(tenant_name):
        """Discover the actual CyberArk Identity URL for a tenant.

        Probes candidate URLs in order and returns the first reachable identity
        endpoint.  For tenants that use legacy Idaptive (*.my.idaptive.app) the
        portal at *.cyberark.cloud redirects to the identity login page, so we
        extract the identity host from that redirect.

        See https://docs.cyberark.com/identity/latest/en/content/getstarted/tenant-url-domains.htm
        """
        default_url = f'https://{tenant_name}.id.cyberark.cloud'

        try:
            requests.head(default_url, timeout=5)
            return default_url
        except requests.exceptions.ConnectionError:
            logging.debug(f"{default_url} is not reachable, attempting auto-discovery")
        except requests.exceptions.RequestException:
            logging.debug(f"{default_url} request failed, attempting auto-discovery")

        portal_url = f'https://{tenant_name}.cyberark.cloud'
        try:
            resp = requests.get(portal_url, timeout=10, allow_redirects=False)
            if resp.status_code in (301, 302, 303, 307, 308):
                redirect_url = resp.headers.get('Location', '')
                parsed = urlparse(redirect_url)
                identity_host = parsed.hostname
                if identity_host:
                    discovered = f'https://{identity_host}'
                    logging.info(f"Auto-discovered identity URL: {discovered} (via redirect from {portal_url})")
                    return discovered
        except requests.exceptions.ConnectionError:
            logging.debug(f"{portal_url} is also not reachable")
        except requests.exceptions.RequestException as e:
            logging.debug(f"{portal_url} request failed: {e}")

        logging.warning(
            f"Could not auto-discover identity URL for tenant '{tenant_name}'. "
            f"Falling back to {default_url}. "
            f"You can also pass the full identity URL directly, e.g.: "
            f"import --format=cyberark_portal https://YOUR_TENANT.my.idaptive.app"
        )
        return default_url

    def do_import(self, filename, **kwargs):
        name = filename.removeprefix("https://").removeprefix("http://")
        host_part = name.split("/")[0]

        if "." in host_part:
            identity_base_url = f'https://{host_part}'
            tenant_name = host_part.split(".")[0]
        else:
            # Bare tenant name (e.g. "eqrworld") — run discovery
            tenant_name = host_part
            identity_base_url = self.discover_identity_url(tenant_name)

        logging.info(f"Using CyberArk Identity URL: {identity_base_url}")

        username = environ.get("KEEPER_CYBERARK_USERNAME") or prompt("CyberArk User Portal username: ")

        start_auth_payload = {
            "TenantId": tenant_name,
            "Version": "1.0",
            "User": username,
        }

        response = requests.post(
            self.get_url(identity_base_url, "/Security/StartAuthentication"),
            json=start_auth_payload,
            timeout=self.TIMEOUT,
            allow_redirects=False,
        )

       
        if response.status_code in (301, 302, 303, 307, 308):
            redirect_url = response.headers.get('Location', '')
            if redirect_url:
                identity_host = urlparse(redirect_url).hostname
                if identity_host:
                    identity_base_url = f'https://{identity_host}'
                    logging.info(f"StartAuthentication redirected; retrying on discovered identity URL: {identity_base_url}")
                    response = requests.post(
                        self.get_url(identity_base_url, "/Security/StartAuthentication"),
                        json=start_auth_payload,
                        timeout=self.TIMEOUT,
                        allow_redirects=False,
                    )

        if response.status_code != HTTPStatus.OK:
            logging.error(f"Error starting authentication (HTTP {response.status_code}): {response.text[:500]}")
            return
        start_auth_result = response.json().get("Result")
        logging.debug(f"Authentication Result: {start_auth_result}")

        # https://docs.cyberark.com/identity/latest/en/content/developer/authentication/adaptive-mfa-overview.htm#Ha
        redirect = start_auth_result.get("PodFqdn")
        if redirect:
            identity_base_url = f'https://{redirect}'
            print_formatted_text(
                HTML(f"Redirecting to preferred tenant URL: <ansigreen>{redirect}</ansigreen>")
            )
            response = requests.post(
                self.get_url(identity_base_url, "/Security/StartAuthentication"),
                json=start_auth_payload,
                timeout=self.TIMEOUT,
                allow_redirects=False,
            )
            if response.status_code != HTTPStatus.OK:
                logging.error(f"Error starting authentication on {redirect}: {response.text[:500]}")
                return
            start_auth_result = response.json().get("Result")
            logging.debug(f"Authentication Result (redirected): {start_auth_result}")

        if start_auth_result.get("IdpRedirectUrl"):

            class OAuth2Callback:
                """OAuth2 authorization callback
                Handles the callback for SSO users that trigger the authentication flow based on their username.
                CyberArk will redirect the user to it with an authorization code after successful authentication.
                The authorization code is then exchanged for an access token.
                If Commander is running on a remote machine then the callback will not be received.
                In that case, the user can manually enter the authorization code.
                It will be the "code" query parameter of the URL in the address bar of the local browser.
                """

                CLIENT_ID = environ.get("KEEPER_CYBERARK_OAUTH2_CLIENT_ID", str(uuid.uuid4()))
                CODE_VERIFIER = "".join(
                    secrets.choice(string.ascii_letters + string.digits + "-._~") for _ in range(64)
                )
                HTTP_PORT = 38389
                REDIRECT_URI = environ.get("KEEPER_CYBERARK_OAUTH2_REDIRECT_URI", f"http://localhost:{HTTP_PORT}")
                TIMEOUT = 30  # Wait up to 30 seconds for an OAuth2 authorization code callback

                @classmethod
                def get_challenge(cls):
                    """
                    Generate a code challenge based on the code_verifier for PKCE.
                    """
                    return (
                        base64.urlsafe_b64encode(hashlib.sha256(cls.CODE_VERIFIER.encode()).digest())
                        .decode()
                        .rstrip("=")
                    )

                class Handler(BaseHTTPRequestHandler):
                    CODE_HOLDER = {"code": None}  # thread-safe storage for OAuth2 authorization code

                    def fail(self, message, text):
                        self.send_error(400, message, explain=text)

                    def success(self):
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(
                            b"""<html>
                                <body>
                                    <h2>Authentication successful.</h2>
                                    <p>This window will close in one minute or you may close it now.</p>
                                    <script>setTimeout(function() { window.close(); }, 60000);</script>
                                </body>
                            </html>"""
                        )

                    def do_GET(self):
                        query_params = parse_qs(urlparse(self.path).query)
                        if "code" in query_params:
                            self.CODE_HOLDER["code"] = query_params["code"][0]
                            self.success()
                        elif "error" in query_params and "error_description" in query_params:
                            self.fail(query_params["error"][0], query_params["error_description"][0])
                        else:
                            self.fail(
                                "Missing authorization code", "There is no &quot;code&quot; query parameter in the URL."
                            )

                    def log_message(self, format, *args):
                        logging.debug(format % args)

                @classmethod
                def get_code(cls):
                    return OAuth2Callback.Handler.CODE_HOLDER["code"]

                @classmethod
                def set_code(cls, code):
                    OAuth2Callback.Handler.CODE_HOLDER["code"] = code

                @classmethod
                def handle_callback(cls):
                    HTTPServer(("localhost", cls.HTTP_PORT), cls.Handler).handle_request()

                def __init__(self):
                    self.thread = threading.Thread(target=self.handle_callback)

                def start(self):
                    self.thread.start()

                def complete(self):
                    """
                    Wait for the OAuth2 code callback to come via HTTP GET with the code query parameter.
                    If the callback times out, either because Commander is running on a remote machine
                    or the user closed the browser window, then prompt the user to enter the code or quit.
                    """
                    self.thread.join(timeout=self.TIMEOUT)
                    if self.thread.is_alive():
                        logging.warning(
                            f"Timed out waiting for the OAuth2 code callback on {self.REDIRECT_URI} after {self.TIMEOUT} seconds."
                        )
                        self.set_code(
                            prompt("Enter the OAuth2 authorization code or ctrl+c to cancel: ", is_password=True)
                        )

            # Start listening for the callback then initiate the OAuth2 authorization request
            callback = OAuth2Callback()
            callback.start()
            response = requests.post(
                self.get_url(identity_base_url, "/OAuth2/Authorize/KeeperCommander"),
                data={
                    "response_type": "code",
                    "redirect_uri": OAuth2Callback.REDIRECT_URI,
                    "client_id": OAuth2Callback.CLIENT_ID,
                    "code_challenge": OAuth2Callback.get_challenge(),
                    "code_challenge_method": "S256",
                    "scope": "UPData",
                },
                timeout=CyberArkPortalImporter.TIMEOUT,
                allow_redirects=False,
            )

            if response.status_code == 302:
                logging.info(f"Opening {response.next.url}")
                webbrowser.open(response.next.url)
                callback.complete()

            # The user did not quit so the code has been received or entered by the user
            response = requests.post(
                self.get_url(identity_base_url, "/OAuth2/Token/KeeperCommander"),
                data={
                    "grant_type": "authorization_code",
                    "redirect_uri": OAuth2Callback.REDIRECT_URI,
                    "client_id": OAuth2Callback.CLIENT_ID,
                    "code_verifier": OAuth2Callback.CODE_VERIFIER,
                    "code": callback.get_code(),
                },
                timeout=CyberArkPortalImporter.TIMEOUT,
            )

            if response.status_code != HTTPStatus.OK:
                logging.error(
                    f"HTTP {HTTPStatus(response.status_code).phrase} error exchanging OAuth2 code for token: {response.text}"
                )
                return
            token_data = response.json()
            authentication_token = token_data["access_token"]  # Save the token before munging it!

            if "access_token" not in token_data:
                logging.error(f"Unexpected response from token exchange: {token_data}")
                return
            else:
                # Obfuscate or mask the access_token in the output
                if len(authentication_token) > 12:
                    token_data["access_token"] = authentication_token[:6] + "..." + authentication_token[-6:]
                else:
                    token_data["access_token"] = "***"
                logging.debug(f"Token Data: {token_data}")
        else:
            # Perform authentication using the CyberArk Identity API starting with password
            password_operation = {
                "MechanismId": start_auth_result["Challenges"][0]["Mechanisms"][0]["MechanismId"],
                "Action": "Answer",
                "Answer": environ.get("KEEPER_CYBERARK_PASSWORD")
                or prompt("CyberArk Identity Portal password: ", is_password=True),
            }
            session_id = start_auth_result.get("SessionId")
            advance_auth_request = {
                "TenantId": tenant_name,
                "SessionId": session_id,
            }

            if len(start_auth_result["Challenges"]) > 1:
                challenge_mechs = list(start_auth_result["Challenges"][1]["Mechanisms"])
                # Use a batch-operation to send the password and start OOB authentication in one request
                advance_auth_request["MultipleOperations"] = [
                    password_operation,
                    {
                        "MechanismId": challenge_mechs[0]["MechanismId"],
                        "Action": "StartOOB",
                    },
                ]
            else:
                challenge_mechs = []
                advance_auth_request |= password_operation

            logging.debug(f"Advance Authentication Request: {advance_auth_request}")
            response = requests.post(
                self.get_url(identity_base_url, "/Security/AdvanceAuthentication"),
                json=advance_auth_request,
                timeout=self.TIMEOUT,
            )

            if response.status_code != HTTPStatus.OK:
                logging.error(
                    f"HTTP {HTTPStatus(response.status_code).phrase} error advancing authentication: {response.text}"
                )
                return
            advance_auth_result = response.json().get("Result")

            if not advance_auth_result.get("Summary") in ["OobPending", "LoginSuccess"]:
                logging.error(
                    f"Unexpected authentication summary: {advance_auth_result.get('Summary')}, response: {response.text}"
                )
                return
            logging.debug(f"Advance Authentication Result: {advance_auth_result}")

            # Iterate through the challenge mechanisms until we get a successful login or run out of mechanisms
            while challenge_mechs and advance_auth_result.get("Summary") == "OobPending":
                response = requests.post(
                    self.get_url(identity_base_url, "/Security/AdvanceAuthentication"),
                    json={
                        "TenantId": tenant_name,
                        "SessionId": session_id,
                        "MechanismId": challenge_mechs[0]["MechanismId"],
                        "Action": "Answer",
                        "Answer": prompt(f"Authentication code from {challenge_mechs[0]['PromptSelectMech']}: "),
                    },
                    timeout=self.TIMEOUT,
                )

                if response.status_code != HTTPStatus.OK:
                    logging.error(
                        f"HTTP {HTTPStatus(response.status_code).phrase} error advancing authentication: {response.text}"
                    )
                    return
                advance_auth_result = response.json().get("Result")

                if advance_auth_result.get("Summary") != "OobPending":
                    challenge_mechs = challenge_mechs[1:]
                elif advance_auth_result.get("Summary") == "LoginSuccess":
                    break

            if advance_auth_result.get("Summary") != "LoginSuccess":
                logging.error(
                    f"Unexpected authentication summary: {advance_auth_result.get('Summary')}, response: {response.text}"
                )
                return
            authentication_token = advance_auth_result.get("Token")

        print_formatted_text(HTML("Authentication <ansigreen>successful</ansigreen>"))

        # Get all the application data (except the password, of course) in one API call
        response = requests.post(
            self.get_url(identity_base_url, "/UPRest/GetUPData"),
            headers={"Authorization": f"Bearer {authentication_token}"},
            json={},
            timeout=self.TIMEOUT,
        )

        if response.status_code != HTTPStatus.OK:
            logging.error(f"HTTP {HTTPStatus(response.status_code).phrase} error getting UP data: {response.text}")
            return
        apps = response.json()["Result"]["Apps"]

       
        missing_endpoint_cache = set()
        folders = self._fetch_folders(identity_base_url, authentication_token, missing_endpoint_cache)
        folder_index = self._build_folder_index(folders) if folders else {}
        if folders:
            print_formatted_text(
                HTML(f"Discovered <b>{len(folders)}</b> CyberArk folder(s) for the current user."),
                end="\n\n",
            )

        if len(apps) > 0:
            print_formatted_text(
                HTML(f"Importing <b>{len(apps)}</b> Applications:\n"),
                tabulate(
                    [{"Application": app["Name"], "Username": app.get("Username", "")} for app in apps],
                    headers="keys",
                    maxcolwidths=[48, 32],
                ),
                end="\n\n",
            )

            for app in apps:
                sleep(self.LOOP_DELAY)
                app_key = app["AppKey"]
                record = Record()
                record.title = app["Name"]
                record.type = "login"
                record.login = app.get("Username", "")
                record.login_url = app.get("Url", "")
                record.notes = app.get("Notes", "")

                if app.get("IsTotpSet"):
                    record.notes += "The CyberArk Application had a TOTP that Keeper could not access to import."

                if app.get("Tags"):
                    record.fields.append(
                        RecordField(type="text", label="Tags", value=", ".join(str(tag) for tag in app["Tags"]))
                    )

                self._apply_sharing_and_folders(
                    record=record,
                    item=app,
                    item_key=app_key,
                    folder_index=folder_index,
                    identity_base_url=identity_base_url,
                    authentication_token=authentication_token,
                    missing_endpoint_cache=missing_endpoint_cache,
                    item_kind="app",
                )

                response = requests.post(
                    self.get_url(identity_base_url, f"/UPRest/GetMCFA?appkey={app_key}"),
                    headers={"Authorization": f"Bearer {authentication_token}"},
                    json={},
                    timeout=self.TIMEOUT,
                )

                if response.status_code != HTTPStatus.OK:
                    logging.error(
                        f"HTTP {response.status_code} ({HTTPStatus(response.status_code).phrase}) error getting password for app {app_key}: {response.text}"
                    )
                    continue
                elif not response.json().get("Result"):
                    logging.warning(f"No password found for app {app_key}; response: {response.text}")
                else:
                    record.password = response.json()["Result"].get("p", "")

                yield record

        response = requests.post(
            self.get_url(identity_base_url, "/UPRest/GetSecuredItemsData"),
            headers={"Authorization": f"Bearer {authentication_token}"},
            json={},
            timeout=self.TIMEOUT,
        )

        if response.status_code != HTTPStatus.OK:
            logging.error(
                f"HTTP {HTTPStatus(response.status_code).phrase} error getting secured items data: {response.text}"
            )
            return
        secured_items = response.json()["Result"]["SecuredItems"]

        if len(secured_items) > 0:
            print_formatted_text(
                HTML(f"Importing <b>{len(secured_items)}</b> Secured Items:\n"),
                tabulate([{"Name": item["Name"]} for item in secured_items], headers="keys"),
                end="\n\n",
            )

            for item in secured_items:
                sleep(self.LOOP_DELAY)
                item_key = item["ItemKey"]
                record = Record()
                record.title = item["Name"]

                if item.get("Tags"):
                    record.fields.append(
                        RecordField(type="text", label="Tags", value=", ".join(str(tag) for tag in item["Tags"]))
                    )

                self._apply_sharing_and_folders(
                    record=record,
                    item=item,
                    item_key=item_key,
                    folder_index=folder_index,
                    identity_base_url=identity_base_url,
                    authentication_token=authentication_token,
                    missing_endpoint_cache=missing_endpoint_cache,
                    item_kind="secured_item",
                )

                response = requests.post(
                    self.get_url(identity_base_url, f"/UPRest/GetCredsForSecuredItem?sItemKey={item_key}"),
                    headers={"Authorization": f"Bearer {authentication_token}"},
                    json={},
                    timeout=self.TIMEOUT,
                )

                if response.status_code != HTTPStatus.OK:
                    logging.error(
                        f"HTTP {response.status_code} ({HTTPStatus(response.status_code).phrase}) error getting notes for item {item_key}: {response.text}"
                    )
                    continue
                elif not response.json().get("Result"):
                    logging.warning(f"No notes found for secured item {item_key}; response: {response.text}")
                else:
                    itemData = response.json()["Result"]
                    if item["SecuredItemType"] == "Password":
                        record.type = "login"
                        if item.get("IsUsernameSet", False):
                            record.login = itemData["u"]
                        if item.get("IsPasswordSet", False):
                            record.password = itemData["p"]
                    else:
                        record.type = "encryptedNotes"
                    record.fields.append(RecordField(type="note", value=itemData["n"]))

                yield record

        print_formatted_text(HTML("Import <ansigreen>complete</ansigreen>"))
