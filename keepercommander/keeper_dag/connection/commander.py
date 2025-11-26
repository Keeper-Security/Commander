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
    from ... import crypto, utils, rest_api
except ImportError:  # pragma: no cover
    raise Exception("Please install the keepercommander module to use the Commander connection.")

from typing import Optional, Union, Dict, Tuple, Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ...params import KeeperParams
    from ...vault import KeeperRecord
    Content = Union[str, bytes, dict]
    QueryValue = Union[list, dict, str, float, int, bool]
    Logger = Union[logging.RootLogger, logging.Logger]


class Connection(ConnectionBase):

    def __init__(self,
                 params: KeeperParams,
                 verify_ssl: bool = True,
                 is_ws: bool = False,
                 logger: Optional[Logger] = None,
                 log_transactions: Optional[bool] = False,
                 log_transactions_dir: Optional[str] = None,
                 use_read_protobuf: bool = False,
                 use_write_protobuf: bool = False,
                 **kwargs):

        # Commander uses /api/user; hence is_device=False
        super().__init__(is_device=False,
                         logger=logger,
                         log_transactions=log_transactions,
                         log_transactions_dir=log_transactions_dir,
                         use_read_protobuf=use_read_protobuf,
                         use_write_protobuf=use_write_protobuf)

        self.params = params
        self.verify_ssl = value_to_boolean(os.environ.get("VERIFY_SSL", verify_ssl))
        self.is_ws = is_ws

        # Deprecated; setting this will override the per-transaction values.
        self.transmission_key = kwargs.get("transmission_key")
        self.dep_encrypted_transmission_key = kwargs.get("encrypted_transmission_key")
        self.dep_encrypted_session_token = kwargs.get("encrypted_session_token")

    @staticmethod
    def get_record_uid(record: KeeperRecord) -> str:
        return record.record_uid

    @staticmethod
    def get_key_bytes(record: KeeperRecord) -> bytes:
        return record.record_key

    @property
    def hostname(self) -> str:
        # The host is connect.keepersecurity.com, connect.dev.keepersecurity.com, etc. Append "connect" in front
        # of host used for Commander.
        configured_host = f'connect.{self.params.config.get("server")}'
        
        # In GovCloud environments, the router service is not under the govcloud subdomain
        if 'govcloud.' in configured_host:
            # "connect.govcloud.keepersecurity.com" -> "connect.keepersecurity.com"
            configured_host = configured_host.replace('govcloud.', '')
            
        return os.environ.get("ROUTER_HOST", configured_host)

    @property
    def dag_server_url(self) -> str:

        # Allow override of the URL. If not set, get the hostname from the config.
        hostname = os.environ.get("KROUTER_URL", self.hostname)
        if hostname.startswith('ws') or hostname.startswith('http'):
            return hostname

        use_ssl = value_to_boolean(os.environ.get("USE_SSL", True))
        if self.is_ws:
            prot_pref = 'ws'
        else:
            prot_pref = 'http'
        if use_ssl is True:
            prot_pref += "s"

        return f'{prot_pref}://{hostname}'

    # deprecated
    def get_keeper_tokens(self):
        self.transmission_key = utils.generate_aes_key()
        server_public_key = rest_api.SERVER_PUBLIC_KEYS[self.params.rest_context.server_key_id]

        if self.params.rest_context.server_key_id < 7:
            self.dep_encrypted_transmission_key = crypto.encrypt_rsa(self.transmission_key, server_public_key)
        else:
            self.dep_encrypted_transmission_key = crypto.encrypt_ec(self.transmission_key, server_public_key)
        self.dep_encrypted_session_token = crypto.encrypt_aes_v2(
            utils.base64_url_decode(self.params.session_token), self.transmission_key)

    def payload_and_headers(self, payload: Any) -> Tuple[Union[str, bytes], Dict]:

        # If the dep_encrypted_transmission_key, use the set value over the generated ones.
        if self.dep_encrypted_transmission_key is not None:
            encrypted_transmission_key = self.dep_encrypted_transmission_key
            encrypted_session_token = self.dep_encrypted_session_token

        # This is what we want to use; it's different for each call.
        else:
            # Create a new transmission key
            self.transmission_key = utils.generate_aes_key()
            self.logger.debug(f"transmission key is {self.transmission_key}")
            # self.params.rest_context.transmission_key = self.transmission_key
            server_public_key = rest_api.SERVER_PUBLIC_KEYS[self.params.rest_context.server_key_id]

            if self.params.rest_context.server_key_id < 7:
                encrypted_transmission_key = crypto.encrypt_rsa(self.transmission_key, server_public_key)
            else:
                encrypted_transmission_key = crypto.encrypt_ec(self.transmission_key, server_public_key)
            encrypted_session_token = crypto.encrypt_aes_v2(
                utils.base64_url_decode(self.params.session_token), self.transmission_key)

        # We need the transmission_key for protobuf sync since it returns values encrypted with the transmission_key.
        if self.transmission_key is None:
            raise DAGConnectionException("The transmission key has not been set. If setting encrypted_transmission_key "
                                         "and encrypted_session_token, also set transmission_key to 32 bytes. "
                                         "Setting the encrypted_transmission_key and encrypted_session_token is "
                                         "deprecated.")

        payload, headers = super().payload_and_headers(payload)

        headers["TransmissionKey"] = bytes_to_base64(encrypted_transmission_key)
        headers["Authorization"] = f'KeeperUser {bytes_to_base64(encrypted_session_token)}'

        return payload, headers

    def rest_call_to_router(self,
                            http_method: str,
                            endpoint: str,
                            agent: str,
                            payload: Optional[Union[str, bytes]] = None,
                            retry: int = 5,
                            retry_wait: float = 10,
                            throttle_inc_factor: float = 1.5,
                            timeout: Optional[int] = None,
                            headers: Optional[Dict] = None) -> Optional[bytes]:

        if timeout is None or timeout == 0:
            timeout = Connection.TIMEOUT

        if isinstance(payload, str):
            payload = payload.encode()

        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint

        url = self.dag_server_url + endpoint

        if headers is None:
            headers = {}

        attempt = 0
        while True:
            try:
                attempt += 1
                self.logger.debug(f"graph web service call to {url} [{attempt}/{retry}]")
                response = requests.request(
                    method=http_method,
                    url=url,
                    verify=self.verify_ssl,
                    headers={
                        **headers,
                        'User-Agent': agent
                    },
                    data=payload,
                    timeout=timeout
                )
                self.logger.debug(f"response status: {response.status_code}")
                response.raise_for_status()
                return response.content

            except requests.exceptions.HTTPError as http_err:

                msg = http_err.response.reason
                try:
                    content = http_err.response.content.decode()
                    if content is not None and content != "":
                        msg = "; " + content
                except (Exception,):
                    pass

                err_msg = f"{http_err.response.status_code}, {msg}"

                if http_err.response.status_code == 429:
                    attempt -= 1
                    retry_wait *= throttle_inc_factor
                    self.logger.warning("the connection to the graph service is being throttled, "
                                        f"increasing the delay between retry: {retry_wait} seconds.")

            except Exception as err:
                err_msg = str(err)

            self.logger.info(f"call to graph web service {url} had a problem: {err_msg}")
            if attempt >= retry:
                self.logger.error(f"call to graph web service {url}, after {retry} "
                                  f"attempts, failed!: {err_msg}")
                raise DAGConnectionException(f"Call to graph web service {url}, after {retry} "
                                             f"attempts, failed!: {err_msg}")

            self.logger.info(f"will retry call after {retry_wait} seconds.")
            time.sleep(retry_wait)
