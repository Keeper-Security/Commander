#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Contact: ops@keepersecurity.com
#

"""
OAuth Helper Module for Email Providers

Provides OAuth 2.0 authentication flows for Gmail and Microsoft 365 email providers.
Supports desktop flow (browser-based) and manual token entry.
"""

from __future__ import annotations
import logging
import requests
import secrets
import threading
import webbrowser
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for OAuth callback."""

    def log_message(self, format, *args):
        """Suppress logging of HTTP requests."""
        pass

    def do_GET(self):
        """Handle GET request for OAuth callback."""
        query_components = parse_qs(urlparse(self.path).query)

        # Extract authorization code and state
        code = query_components.get('code', [None])[0]
        state = query_components.get('state', [None])[0]
        error = query_components.get('error', [None])[0]

        # Store in server instance
        self.server.oauth_code = code  # type: ignore
        self.server.oauth_state = state  # type: ignore
        self.server.oauth_error = error  # type: ignore

        # Send response to browser
        if code:
            response_html = """
            <html>
            <head><title>Authentication Successful</title></head>
            <body>
                <h1>✓ Authentication Successful</h1>
                <p>You can close this window and return to Keeper Commander.</p>
            </body>
            </html>
            """
            self.send_response(200)
        else:
            response_html = f"""
            <html>
            <head><title>Authentication Failed</title></head>
            <body>
                <h1>✗ Authentication Failed</h1>
                <p>Error: {error or 'Unknown error'}</p>
                <p>Please return to Keeper Commander and try again.</p>
            </body>
            </html>
            """
            self.send_response(400)

        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(response_html.encode())


class OAuthFlowHandler(ABC):
    """Base class for OAuth 2.0 flows."""

    @abstractmethod
    def get_authorization_url(self, redirect_uri: str, state: str) -> str:
        """
        Get the authorization URL for the user to visit.

        Args:
            redirect_uri: OAuth callback URL
            state: Random state parameter for CSRF protection

        Returns:
            Authorization URL
        """
        pass

    @abstractmethod
    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> Dict[str, str]:
        """
        Exchange authorization code for access/refresh tokens.

        Args:
            code: Authorization code from OAuth callback
            redirect_uri: OAuth callback URL (must match)

        Returns:
            Dictionary with 'access_token', 'refresh_token', 'expiry' (ISO 8601)
        """
        pass

    @abstractmethod
    def refresh_tokens(self, refresh_token: str) -> Dict[str, str]:
        """
        Refresh OAuth tokens using refresh token.

        Args:
            refresh_token: Refresh token from previous authorization

        Returns:
            Dictionary with new 'access_token', 'refresh_token' (if new), 'expiry'
        """
        pass


class GoogleOAuthFlow(OAuthFlowHandler):
    """Google OAuth 2.0 flow for Gmail API."""

    SCOPES = ['https://www.googleapis.com/auth/gmail.send']
    AUTH_URI = 'https://accounts.google.com/o/oauth2/v2/auth'
    TOKEN_URI = 'https://oauth2.googleapis.com/token'

    def __init__(self, client_id: str, client_secret: str):
        """
        Initialize Google OAuth flow.

        Args:
            client_id: Google OAuth client ID
            client_secret: Google OAuth client secret
        """
        self.client_id = client_id
        self.client_secret = client_secret

    def get_authorization_url(self, redirect_uri: str, state: str) -> str:
        """Get Google authorization URL."""
        params = {
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': ' '.join(self.SCOPES),
            'state': state,
            'access_type': 'offline',  # Request refresh token
            'prompt': 'consent'  # Force consent to get refresh token
        }
        return f"{self.AUTH_URI}?{urlencode(params)}"

    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> Dict[str, str]:
        """Exchange authorization code for tokens."""
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code'
        }

        response = requests.post(self.TOKEN_URI, data=data)
        response.raise_for_status()
        token_data = response.json()

        # Calculate expiry time
        expires_in = token_data.get('expires_in', 3600)
        expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        return {
            'access_token': token_data['access_token'],
            'refresh_token': token_data.get('refresh_token', ''),
            'expiry': expiry.isoformat()
        }

    def refresh_tokens(self, refresh_token: str) -> Dict[str, str]:
        """Refresh Google OAuth tokens."""
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token'
        }

        response = requests.post(self.TOKEN_URI, data=data)
        response.raise_for_status()
        token_data = response.json()

        # Calculate new expiry
        expires_in = token_data.get('expires_in', 3600)
        expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        result = {
            'access_token': token_data['access_token'],
            'expiry': expiry.isoformat()
        }

        # Google may return a new refresh token
        if 'refresh_token' in token_data:
            result['refresh_token'] = token_data['refresh_token']
        else:
            # Keep the old refresh token
            result['refresh_token'] = refresh_token

        return result


class MicrosoftOAuthFlow(OAuthFlowHandler):
    """Microsoft OAuth 2.0 flow for Microsoft Graph API."""

    SCOPES = ['https://graph.microsoft.com/Mail.Send']

    def __init__(self, client_id: str, client_secret: str, tenant_id: str = 'common'):
        """
        Initialize Microsoft OAuth flow.

        Args:
            client_id: Azure AD application ID
            client_secret: Azure AD application secret
            tenant_id: Tenant ID ('common', 'organizations', 'consumers', or specific tenant)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant_id = tenant_id
        self.auth_uri = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize'
        self.token_uri = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'

    def get_authorization_url(self, redirect_uri: str, state: str) -> str:
        """Get Microsoft authorization URL."""
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': redirect_uri,
            'response_mode': 'query',
            'scope': ' '.join(self.SCOPES) + ' offline_access',  # offline_access for refresh token
            'state': state
        }
        return f"{self.auth_uri}?{urlencode(params)}"

    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> Dict[str, str]:
        """Exchange authorization code for tokens."""
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': code,
            'redirect_uri': redirect_uri,
            'grant_type': 'authorization_code',
            'scope': ' '.join(self.SCOPES) + ' offline_access'
        }

        response = requests.post(self.token_uri, data=data)
        response.raise_for_status()
        token_data = response.json()

        # Calculate expiry time
        expires_in = token_data.get('expires_in', 3600)
        expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        return {
            'access_token': token_data['access_token'],
            'refresh_token': token_data.get('refresh_token', ''),
            'expiry': expiry.isoformat()
        }

    def refresh_tokens(self, refresh_token: str) -> Dict[str, str]:
        """Refresh Microsoft OAuth tokens."""
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token',
            'scope': ' '.join(self.SCOPES) + ' offline_access'
        }

        response = requests.post(self.token_uri, data=data)
        response.raise_for_status()
        token_data = response.json()

        # Calculate new expiry
        expires_in = token_data.get('expires_in', 3600)
        expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        result = {
            'access_token': token_data['access_token'],
            'expiry': expiry.isoformat()
        }

        # Microsoft may return a new refresh token
        if 'refresh_token' in token_data:
            result['refresh_token'] = token_data['refresh_token']
        else:
            # Keep the old refresh token
            result['refresh_token'] = refresh_token

        return result


def start_local_callback_server(port: int = 8080) -> Tuple[HTTPServer, str]:
    """
    Start local HTTP server to receive OAuth callback.

    Args:
        port: Port number for callback server (default 8080)

    Returns:
        Tuple of (server, redirect_uri)
    """
    server = HTTPServer(('localhost', port), OAuthCallbackHandler)
    server.oauth_code = None  # type: ignore
    server.oauth_state = None  # type: ignore
    server.oauth_error = None  # type: ignore

    redirect_uri = f'http://localhost:{port}/oauth/callback'
    return server, redirect_uri


def wait_for_oauth_callback(server: HTTPServer, timeout: int = 300) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Wait for OAuth callback on local server.

    Args:
        server: HTTP server instance from start_local_callback_server()
        timeout: Maximum seconds to wait (default 300 = 5 minutes)

    Returns:
        Tuple of (code, state, error)
    """
    # Handle requests until we get a callback or timeout
    server.timeout = 1  # 1 second timeout per request
    start_time = datetime.now()

    while True:
        server.handle_request()

        # Check if we got the callback
        if hasattr(server, 'oauth_code') and (server.oauth_code or server.oauth_error):  # type: ignore
            return server.oauth_code, server.oauth_state, server.oauth_error  # type: ignore

        # Check timeout
        if (datetime.now() - start_time).total_seconds() > timeout:
            return None, None, 'Timeout waiting for OAuth callback'


def open_browser_for_oauth(url: str) -> bool:
    """
    Open system browser to OAuth authorization URL.

    Args:
        url: Authorization URL to open

    Returns:
        True if browser was opened successfully
    """
    try:
        webbrowser.open(url)
        return True
    except Exception as e:
        logging.error(f"Failed to open browser: {e}")
        return False

def redact_sensitive_url_params(url: str, params_to_redact: list = None) -> str:
    """
    Redact sensitive query parameters from a URL for safe console output.

    Args:
        url: The URL to redact
        params_to_redact: List of parameter names to redact (default: ['client_id', 'client_secret'])

    Returns:
        URL with sensitive parameters replaced by [REDACTED]
    """
    if params_to_redact is None:
        params_to_redact = ['client_id', 'client_secret']

    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)

    # Redact sensitive parameters
    for param in params_to_redact:
        if param in query:
            query[param] = ['[REDACTED]']

    # Reconstruct URL with redacted parameters
    redacted_query = urlencode(query, doseq=True)
    redacted_url = urlunparse(parsed_url._replace(query=redacted_query))

    return redacted_url

def perform_interactive_oauth(flow: OAuthFlowHandler, port: int = 8080) -> Dict[str, str]:
    """
    Perform interactive OAuth flow with browser.

    Args:
        flow: OAuth flow handler (GoogleOAuthFlow or MicrosoftOAuthFlow)
        port: Port for local callback server

    Returns:
        Dictionary with 'access_token', 'refresh_token', 'expiry'

    Raises:
        Exception: If OAuth flow fails
    """
    # Start local server
    server, redirect_uri = start_local_callback_server(port)
    state = secrets.token_urlsafe(32)

    # Get authorization URL
    auth_url = flow.get_authorization_url(redirect_uri, state)

    # Redact sensitive parameters before printing
    safe_auth_url = redact_sensitive_url_params(auth_url)

    print(f"\nOpening browser for authorization...")
    print(f"If browser doesn't open automatically, visit: {safe_auth_url}\n")

    # Open browser (use original URL with all parameters)
    if not open_browser_for_oauth(auth_url):
        print(f"Please manually open this URL in your browser:\n{safe_auth_url}\n")

    # Wait for callback
    print("Waiting for authorization...")
    code, returned_state, error = wait_for_oauth_callback(server)

    # Close server
    server.server_close()

    # Check for errors
    if error:
        raise Exception(f"OAuth failed: {error}")

    if not code:
        raise Exception("No authorization code received")

    if returned_state != state:
        raise Exception("State mismatch - possible CSRF attack")

    # Exchange code for tokens
    print("Exchanging authorization code for tokens...")
    tokens = flow.exchange_code_for_tokens(code, redirect_uri)

    print("✓ OAuth authentication successful!")
    return tokens
