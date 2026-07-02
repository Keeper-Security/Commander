from __future__ import annotations
import argparse
import json
import os
from typing import TYPE_CHECKING

import requests

from ..base import Command
from ...display import bcolors

if TYPE_CHECKING:
    from ...params import KeeperParams


class PAMDebugKRouterCommand(Command):
    """`pam action debug krouter` — show the connected krouter build version.

    Calls krouter's unauthenticated `GET /healthcheck` endpoint and prints the
    `version` field. Useful for verifying which krouter build a Commander
    session is talking to (e.g. to confirm whether a newly-shipped Layer-B
    endpoint such as `configure_network_graph` has been deployed to the
    tenant's krouter, or to compare against the floor version required by the
    PR description).
    """

    parser = argparse.ArgumentParser(
        prog='pam action debug krouter',
        description='Show the connected krouter build version (calls /healthcheck).'
    )
    parser.add_argument('--url', '-u', required=False, dest='url', action='store',
                        help='Override the krouter base URL. Defaults to the URL Commander would normally use '
                             '(KROUTER_URL env var, else derived from params.rest_context.server_base).')
    parser.add_argument('--timeout', '-t', required=False, dest='timeout', type=float, default=10.0,
                        help='HTTP timeout in seconds (default: 10).')
    parser.add_argument('--raw', '-r', required=False, dest='raw', action='store_true',
                        help='Print the raw healthcheck response body instead of formatted output.')

    def get_parser(self):
        return PAMDebugKRouterCommand.parser

    def execute(self, params: KeeperParams, **kwargs):
        url = kwargs.get('url')
        if not url:
            from ..pam.router_helper import get_router_url
            url = get_router_url(params)
        url = url.rstrip('/') + '/healthcheck'

        timeout = kwargs.get('timeout') or 10.0
        raw = bool(kwargs.get('raw'))

        try:
            rs = requests.get(url, verify=params.ssl_verify, timeout=timeout)
            rs.raise_for_status()
        except requests.exceptions.SSLError as err:
            print(f"{bcolors.FAIL}SSL verification failed: {err}{bcolors.ENDC}")
            print('  Set VERIFY_SSL=FALSE or KEEPER_SSL_CERT_FILE=none to bypass SSL verification.')
            return
        except requests.exceptions.ConnectionError as err:
            print(f"{bcolors.FAIL}Cannot reach krouter at {url}: {err}{bcolors.ENDC}")
            return
        except requests.exceptions.Timeout:
            print(f"{bcolors.FAIL}Timed out after {timeout}s connecting to {url}.{bcolors.ENDC}")
            return
        except requests.exceptions.HTTPError as err:
            status = err.response.status_code if err.response is not None else '?'
            body = err.response.text if err.response is not None else ''
            print(f"{bcolors.FAIL}HTTP {status} from {url}: {body!r}{bcolors.ENDC}")
            return

        if raw:
            print(rs.text)
            return

        try:
            data = rs.json()
        except ValueError:
            print(f"{bcolors.FAIL}Non-JSON response from {url}: {rs.text!r}{bcolors.ENDC}")
            return

        version = data.get('version') or '<unknown>'
        print(f"{bcolors.OKGREEN}krouter version : {version}{bcolors.ENDC}")
        print(f"  URL           : {url}")
        extras = {k: v for k, v in data.items() if k != 'version'}
        if extras:
            print(f"  Extras        : {json.dumps(extras)}")
