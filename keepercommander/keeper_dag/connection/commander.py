from __future__ import annotations
import logging
from . import ConnectionBase
from ..exceptions import DAGConnectionException
from ..crypto import bytes_to_base64
from ..utils import value_to_boolean
import os
import requests
import time

try:  # pragma: no cover
    from keepercommander import crypto, utils, rest_api
except ImportError:  # pragma: no cover
    raise Exception("Please install the keepercommander module to use the Commander connection.")

from typing import Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from keepercommander.params import KeeperParams
    from keepercommander.vault import KeeperRecord
    Content = Union[str, bytes, dict]
    QueryValue = Union[list, dict, str, float, int, bool]
    Logger = Union[logging.RootLogger, logging.Logger]


class Connection(ConnectionBase):

    def __init__(self, params: KeeperParams, encrypted_transmission_key: Optional[bytes] = None,
                 encrypted_session_token: Optional[bytes] = None, verify_ssl: bool = True, is_ws: bool = False,
                 logger: Optional[Logger] = None):

        super().__init__(is_device=False, logger=logger)
        self.params = params
        self.verify_ssl = verify_ssl
        self.is_ws = is_ws
        self.encrypted_transmission_key = encrypted_transmission_key if encrypted_transmission_key else None
        self.encrypted_session_token = encrypted_session_token if encrypted_session_token else None

        if self.encrypted_transmission_key is None or self.encrypted_session_token is None:
            self.get_keeper_tokens()

    @staticmethod
    def get_record_uid(record: KeeperRecord) -> str:
        return record.record_uid

    @staticmethod
    def get_key_bytes(record: KeeperRecord) -> bytes:
        return record.record_key

    @property
    def hostname(self) -> str:
        # The host is connect.keepersecurity.com, connect.dev.keepersecurity.com, etc.
        # Append "connect" in front of host used for Commander.
        configured_host = f'connect.{self.params.config.get("server")}'

        # In GovCloud environments, the router service is not under the govcloud subdomain
        if '.govcloud.' in configured_host:
            configured_host = configured_host.replace('.govcloud.', '.')

        return os.environ.get("ROUTER_HOST", configured_host)

    @property
    def dag_server_url(self) -> str:

        # Allow override of the URL. If not set, get the hostname from the config.
        hostname = os.environ.get("KROUTER_URL", self.hostname)
        if hostname.startswith('ws') or hostname.startswith('http'):
            return hostname

        use_ssl = value_to_boolean(os.environ.get("USE_SSL", True))
        if self.is_ws is True:
            prot_pref = 'ws'
        else:
            prot_pref = 'http'
        if use_ssl is True:
            prot_pref += "s"

        return f'{prot_pref}://{hostname}'

    def get_keeper_tokens(self):
        transmission_key = utils.generate_aes_key()
        server_public_key = rest_api.SERVER_PUBLIC_KEYS[self.params.rest_context.server_key_id]

        if self.params.rest_context.server_key_id < 7:
            self.encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
        else:
            self.encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)
        self.encrypted_session_token = crypto.encrypt_aes_v2(
            utils.base64_url_decode(self.params.session_token), transmission_key)

    def rest_call_to_router(self, http_method: str, endpoint: str,
                            payload_json: Optional[Union[bytes, str]] = None,
                            retry: int = 5,
                            retry_wait: float = 10,
                            throttle_inc_factor: float = 1.5,
                            timeout: Optional[int] = None) -> str:
        if payload_json is not None and isinstance(payload_json, bytes) is False:
            payload_json = payload_json.encode()

        if endpoint.startswith("/") is False:
            endpoint = "/" + endpoint

        url = self.dag_server_url + endpoint

        attempt = 0
        while True:
            try:
                attempt += 1
                self.logger.debug(f"DAG web service call to {url} [{attempt}/{retry}]")
                response = requests.request(
                    method=http_method,
                    url=url,
                    verify=self.verify_ssl,
                    headers={
                        'TransmissionKey': bytes_to_base64(self.encrypted_transmission_key),
                        'Authorization': f'KeeperUser {bytes_to_base64(self.encrypted_session_token)}'
                    },
                    data=payload_json,
                    timeout=timeout
                )
                self.logger.debug(f"response status: {response.status_code}")
                response.raise_for_status()
                return response.text

            except requests.exceptions.HTTPError as http_err:
                err_msg = f"{http_err.response.status_code}, {http_err.response.text}"

                if http_err.response.status_code == 429:
                    attempt -= 1
                    retry_wait *= throttle_inc_factor
                    self.logger.warning("the connection to the graph service is being throttled, "
                                        f"increasing the delay between retry: {retry_wait} seconds.")

            except Exception as err:
                err_msg = str(err)

            self.logger.info(f"call to DAG web service had a problem: {err_msg}.")
            if attempt >= retry:
                raise DAGConnectionException(f"Call to DAG web service {url}, after {retry} "
                                             f"attempts, failed!: {err_msg}")

            self.logger.info(f"will retry call after {retry_wait} seconds.")
            time.sleep(retry_wait)
