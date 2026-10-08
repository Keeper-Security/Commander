"""Interactive Microsoft Entra sign-in for a CLI: OAuth 2.0 authorization code flow with PKCE.

The user signs in (including any MFA prompt) in their own browser and Entra redirects back to a
short-lived loopback listener on this machine, which redeems the code for an access token. No
password or MFA code ever passes through Commander. The app registration needs the
``http://localhost`` redirect under "Mobile and desktop applications" and public client flows
enabled.
"""
import base64
import hashlib
import http.server
import json
import logging
import secrets
import threading
import time
import urllib.parse
import webbrowser

import requests

from keepercommander.error import CommandError


logger = logging.getLogger(__name__)

COMMAND = 'pam-cloud-generate-credentials'
DEFAULT_AUTHORITY = 'https://login.microsoftonline.com'
SIGN_IN_TIMEOUT_SECONDS = 300


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def pkce_pair():
    """Return (code_verifier, code_challenge) for the S256 method."""
    verifier = _b64url(secrets.token_bytes(32))
    return verifier, _b64url(hashlib.sha256(verifier.encode('ascii')).digest())


def build_authorize_url(authority, tenant_id, client_id, redirect_uri, scope, state, code_challenge, login_hint=None):
    query = {
        'client_id': client_id,
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'response_mode': 'query',
        'scope': scope,
        'state': state,
        'code_challenge': code_challenge,
        'code_challenge_method': 'S256',
    }
    if login_hint:
        query['login_hint'] = login_hint
    return f'{authority}/{urllib.parse.quote(tenant_id, safe="")}/oauth2/v2.0/authorize?' \
           + urllib.parse.urlencode(query)


def token_claims(token):
    """Return the claims of a JWT without verifying it (it came straight from Entra over TLS)."""
    try:
        segment = token.split('.')[1]
        return json.loads(base64.urlsafe_b64decode(segment + '=' * (-len(segment) % 4)))
    except Exception:
        return {}


def signed_in_identities(claims):
    return {str(claims[key]).strip().lower()
            for key in ('upn', 'unique_name', 'preferred_username', 'email') if claims.get(key)}


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        params = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).items()}
        if 'code' in params or 'error' in params:
            self.server.result = params
            body = 'Sign-in complete. You can close this window and return to Keeper Commander.'
        else:
            body = 'Waiting for sign-in.'
        payload = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def _wait_for_redirect(server, timeout):
    server.result = None
    server.timeout = 1
    deadline = time.monotonic() + timeout
    while server.result is None and time.monotonic() < deadline:
        server.handle_request()
    return server.result


def sign_in(tenant_id, client_id, scope, login_hint, authority=DEFAULT_AUTHORITY,
            timeout=SIGN_IN_TIMEOUT_SECONDS, open_browser=webbrowser.open):
    """Sign `login_hint` in through the system browser and return the token response dict.

    Raises CommandError if the sign-in is cancelled, times out, fails, or completes as a
    different user than `login_hint`.
    """
    server = http.server.HTTPServer(('127.0.0.1', 0), _CallbackHandler)
    try:
        redirect_uri = f'http://localhost:{server.server_port}'
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(16)
        url = build_authorize_url(authority, tenant_id, client_id, redirect_uri, f'{scope} openid profile',
                                  state, challenge, login_hint)

        print('Opening your browser to sign in to Microsoft. If it does not open, visit:')
        print(f'  {url}')
        try:
            open_browser(url)
        except Exception as e:
            logger.debug('Could not open a browser: %r', e)

        result = _wait_for_redirect(server, timeout)
    finally:
        server.server_close()

    if result is None:
        raise CommandError(COMMAND, 'The Microsoft sign-in was not completed in time.')
    if result.get('state') != state:
        raise CommandError(COMMAND, 'The Microsoft sign-in response did not match the request.')
    if 'error' in result:
        raise CommandError(COMMAND, f'Microsoft sign-in failed: {result.get("error_description") or result["error"]}')

    try:
        response = requests.post(
            f'{authority}/{urllib.parse.quote(tenant_id, safe="")}/oauth2/v2.0/token',
            data={
                'grant_type': 'authorization_code',
                'client_id': client_id,
                'code': result['code'],
                'redirect_uri': redirect_uri,
                'code_verifier': verifier,
                'scope': f'{scope} openid profile',
            },
            timeout=30)
        token = response.json()
    except (requests.RequestException, ValueError) as e:
        raise CommandError(COMMAND, f'Could not redeem the Microsoft sign-in: {type(e).__name__}')

    if response.status_code != 200 or not token.get('access_token'):
        description = (token.get('error_description') or token.get('error') or 'unknown error').splitlines()[0]
        raise CommandError(COMMAND, f'Microsoft rejected the sign-in: {description}')

    expected = (login_hint or '').strip().lower()
    identities = signed_in_identities(token_claims(token.get('id_token') or token['access_token']))
    if expected and expected not in identities:
        raise CommandError(COMMAND, f'The sign-in was completed as a different user than {login_hint}.')
    return token
