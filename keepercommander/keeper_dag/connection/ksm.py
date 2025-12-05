from __future__ import annotations
from . import ConnectionBase
from ..utils import value_to_boolean
from ..exceptions import DAGException, DAGConnectionException

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_private_key

try:  # pragma: no cover
    from keeper_secrets_manager_core import utils
    from keeper_secrets_manager_core.configkeys import ConfigKeys
    from keeper_secrets_manager_core.storage import InMemoryKeyValueStorage, KeyValueStorage
    from keeper_secrets_manager_core.utils import url_safe_str_to_bytes, bytes_to_base64, generate_random_bytes
except ImportError:  # pragma: no cover
    raise Exception("Please install the keeper_secrets_manager_core module to use the Ksm connection.")

import logging
import json
import os
import requests
import time
from typing import Union, Optional, Tuple, Dict, Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from keeper_secrets_manager_core.storage import KeyValueStorage
    from keeper_secrets_manager_core.dto.dtos import Record
    KsmConfig = Union[dict, str, KeyValueStorage]
    Content = Union[str, bytes, dict]
    QueryValue = Union[list, dict, str, float, int, bool]
    Logger = Union[logging.RootLogger, logging.Logger]


class Connection(ConnectionBase):

    KEEPER_CLIENT = 'ms16.5.0'

    def __init__(self,
                 config: Union[str, dict, KeyValueStorage],
                 verify_ssl: bool = None,
                 logger: Optional[Logger] = None,
                 log_transactions: Optional[bool] = None,
                 log_transactions_dir: Optional[str] = None,
                 use_read_protobuf: bool = False,
                 use_write_protobuf: bool = False):

        # KSM uses /api/device; hence is_device=True
        super().__init__(is_device=True,
                         logger=logger,
                         log_transactions=log_transactions,
                         log_transactions_dir=log_transactions_dir,
                         use_read_protobuf=use_read_protobuf,
                         use_write_protobuf=use_write_protobuf)

        if self.use_read_protobuf:
            self.logger.info("KSM cannot use protobuf for reading the graph, using JSON.")
            self.use_read_protobuf = False
        if self.use_write_protobuf:
            self.logger.info("KSM cannot use protobuf for writing to the graph, using JSON.")
            self.use_read_protobuf = False

        if InMemoryKeyValueStorage.is_base64(config):
            config = utils.base64_to_string(config)
        if isinstance(config, str):
            try:
                config = json.loads(config)
            except json.JSONDecodeError as err:
                raise DAGException(f"The configuration JSON could not be decoded: {err}")

        if isinstance(config, dict) is False and isinstance(config, KeyValueStorage) is False:
            raise DAGException("The configuration is not a dictionary.")

        if verify_ssl is None:
            verify_ssl = value_to_boolean(os.environ.get("VERIFY_SSL", "TRUE"))

        self.config = config
        self.verify_ssl = verify_ssl
        self._signature = None
        self._challenge_str = None

    def close(self):
        super().close()
        if hasattr(self, "config"):
            self.config = None
            del self.config

    @staticmethod
    def get_record_uid(record: Record) -> str:
        return record.uid

    @staticmethod
    def get_key_bytes(record: Record) -> bytes:
        return record.record_key_bytes

    def get_config_value(self, key: ConfigKeys) -> str:
        if isinstance(self.config, KeyValueStorage):
            return self.config.get(key)
        else:
            return self.config.get(key.value)

    @property
    def hostname(self) -> str:
        return os.environ.get("ROUTER_HOST", self.get_config_value(ConfigKeys.KEY_HOSTNAME))

    @property
    def client_id(self) -> str:
        return self.get_config_value(ConfigKeys.KEY_CLIENT_ID)

    @property
    def private_key(self) -> str:
        return self.get_config_value(ConfigKeys.KEY_PRIVATE_KEY)

    @property
    def app_key(self) -> str:
        return self.get_config_value(ConfigKeys.KEY_APP_KEY)

    def router_url_from_ksm_config(self) -> str:
        hostname = self.hostname
        # In GovCloud environments, the router service is not under the govcloud subdomain
        if 'govcloud.' in hostname:
            hostname = hostname.replace('govcloud.', '')
        return f'connect.{hostname}'

    def ws_router_url_from_ksm_config(self, is_ws: bool = False) -> str:

        router_host = self.router_url_from_ksm_config()

        kpam_router_ssl_enabled_env = value_to_boolean(os.environ.get("USE_SSL", True))

        if is_ws:
            prot_pref = 'ws'
        else:
            prot_pref = 'http'

        if not kpam_router_ssl_enabled_env:
            return f'{prot_pref}://{router_host}'
        else:
            return f'{prot_pref}s://{router_host}'

    def http_router_url_from_ksm_config_or_env(self) -> str:

        router_host_from_env = os.getenv("KROUTER_URL")
        if router_host_from_env:
            router_http_host = router_host_from_env
        else:
            router_http_host = self.ws_router_url_from_ksm_config()

        return router_http_host.replace('ws', 'http')

    def authenticate(self,
                     agent: str,
                     refresh: bool = False,
                     retry: int = 5,
                     retry_wait: float = 10.0,
                     throttle_inc_factor: float = 1.5,
                     timeout: Optional[int] = None) -> Tuple[str, str]:

        if self._signature is None or refresh is True:

            self.logger.debug(f"signature is blank or needs to be refresh {refresh}")

            if timeout is None or timeout == 0:
                timeout = Connection.TIMEOUT

            router_http_host = self.http_router_url_from_ksm_config_or_env()
            url = f'{router_http_host}/api/device/get_challenge'

            self._signature = None

            attempt = 0
            while True:
                try:
                    attempt += 1
                    response = requests.get(url,
                                            verify=self.verify_ssl,
                                            timeout=timeout,
                                            headers={
                                                "User-Agent": agent
                                            })
                    response.raise_for_status()

                    self._challenge_str = response.text
                    if self._challenge_str is None or self._challenge_str == "":
                        raise Exception("Challenge text is blank. Cannot authenticate into the DAG web service.")

                    private_key_der_bytes = url_safe_str_to_bytes(self.private_key)
                    client_id_bytes = url_safe_str_to_bytes(self.client_id)

                    self.logger.debug('adding challenge to the signature before connecting to the router')
                    challenge_bytes = url_safe_str_to_bytes(self._challenge_str)
                    client_id_bytes = client_id_bytes + challenge_bytes

                    pk = load_der_private_key(private_key_der_bytes, password=None)
                    sig = pk.sign(client_id_bytes, ec.ECDSA(hashes.SHA256()))

                    self._signature = bytes_to_base64(sig)
                    break

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
                        retry_wait *= throttle_inc_factor
                        attempt -= 1
                        self.logger.warning(
                            "the connection to the graph service, for authentication, is being throttled; "
                            f"increasing delay between retry: {retry_wait} seconds")

                except Exception as err:
                    err_msg = str(err)

                self.logger.info(f"call to challenge had a problem: {err_msg}.")
                if attempt >= retry:
                    raise DAGConnectionException(f"Call to challenge {url}, after {retry} "
                                                 f"attempts, failed!: {err_msg}")

                self.logger.info(f"will retry call after {retry_wait} seconds.")
                time.sleep(retry_wait)

        return self._signature, self._challenge_str

    def payload_and_headers(self, payload: Any) -> Tuple[Union[str, bytes], Dict]:

        # Make sure the transmission_key is None.
        # This acts as a flag to indicate if we need to decrypt the response.
        self.transmission_key = None

        payload, headers = super().payload_and_headers(payload)

        return payload, headers

    def rest_call_to_router(self,
                            http_method: str,
                            endpoint: str,
                            agent: str,
                            payload: Optional[Union[str, bytes]] = None,
                            retry: int = 5,
                            retry_wait: float = 10.0,
                            throttle_inc_factor: float = 1.5,
                            timeout: Optional[int] = None,
                            headers: Optional[Dict] = None) -> Optional[bytes]:

        if timeout is None or timeout == 0:
            timeout = Connection.TIMEOUT

        if headers is None:
            headers = {}

        if isinstance(payload, str):
            payload = payload.encode()

        router_host = self.http_router_url_from_ksm_config_or_env()
        url = router_host + endpoint

        refresh = False
        attempt = 0
        while True:

            attempt += 1

            # Keep authenticate outside the call router try.
            # This is to prevent too many retries.
            # For example, 3 retry of the auth, 3 retry of the request, will be 9 retries.
            signature, challenge_str = self.authenticate(refresh=refresh, agent=agent)
            headers = {
                **headers,
                "Signature": signature,
                "ClientVersion": Connection.KEEPER_CLIENT,
                "Authorization": f'KeeperDevice {self.client_id}',
                "Challenge": challenge_str,
                "User-Agent": agent
            }
            self.logger.debug(f'connecting with headers: {headers}')

            try:
                self.logger.debug(f"DAG web service call to {url} [{attempt}/{retry}]")
                response = requests.request(
                    method=http_method,
                    url=url,
                    data=payload,
                    verify=self.verify_ssl,
                    timeout=timeout,
                    headers=headers,
                )

                self.logger.debug(f"response status: {response.status_code}")

                # If we get a 401 Unauthorized, and we have not yet refreshed,
                #  refresh the signature.
                if response.status_code == 401 and refresh is False:
                    self.logger.debug("rest call was Unauthorized")

                    # The attempt didn't count.
                    # We get one refresh, then it becomes an exception.
                    refresh = True
                    attempt -= 1
                    continue

                response.raise_for_status()
                return response.content

            # Handle errors outside of requests
            except requests.exceptions.HTTPError as http_err:

                err_msg = f"{http_err.response.status_code}, {http_err.response.reason}, {http_err.response.content}"
                content = http_err.response.reason

                if http_err.response.status_code == 429:
                    retry_wait *= throttle_inc_factor
                    attempt -= 1
                    self.logger.warning("the connection to the graph service is being throttled, "
                                        f"increasing the delay between retry: {retry_wait} seconds.")

            except Exception as err:
                err_msg = str(err)
                content = None

            self.logger.info(f"call to graph web service had a problem: {err_msg}, {content}")
            if attempt >= retry:
                self.logger.info(f"payload: {payload}")
                raise DAGConnectionException(f"Call to graph web service {url}, after {retry} "
                                             f"attempts, failed!: {err_msg}: {content} : {payload}")

            self.logger.info(f"will retry call after {retry_wait} seconds.")
            time.sleep(retry_wait)
