from __future__ import annotations
from . import ConnectionBase
from ..utils import value_to_boolean
from ..exceptions import DAGException, DAGConnectionException
from ..types import (JitSettings, AiSettings, Meta, ConnectionSettingsBase, NetworkSettings, NetworkResource,
                     NetworkRotation)
from ..crypto import encrypt_aes
from ..__version__ import __version__

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
import base64
import os
import requests
import time
from pydantic import BaseModel
from typing import Union, Optional, Tuple, Dict, Any, List, TYPE_CHECKING

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
        return self.get_router_host(self.hostname)

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
                err_msg = "no error message"
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
                    response.close()
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

    def configure_resource(self,
                           record: Record,
                           configuration_record_uid: str,
                           connection_user_uids: Optional[List[str]] = None,
                           admin_user_record_uid: Optional[str] = None,
                           connection_settings: Optional[ConnectionSettingsBase] = None,
                           jit_settings: Optional[JitSettings] = None,
                           ai_settings: Optional[AiSettings] = None,
                           domain_uid: Optional[str] = None,
                           meta: Optional[Meta] = None,
                           update_services: Optional[bool] = False,
                           agent: Optional[str] = None):
        """
        Configure a resource in the PAM graph.

        After creating a V3 record in the Vault, this method is called to configure that record in hte PAM graph.

        `jit_settings` should be an instance of JitSettings.
        It will also take JSON and a python dictionary for that model.

        `connection_settings` should be a child instance of ConnectionSettingsBase.
        It will also take JSON and a python dictionary for that model.

        `meta` should be an instance of Meta.
        It will also take JSON and a python dictionary for that model.

        `ai_settings` should be an instance of AiSettings.
        It will also take JSON and a python dictionary for that model.

        :param record: A pamMachine, pamDatabase, or pamDirectory record.
        :param configuration_record_uid: The configuration record uid the resource should be connected to.
        :param connection_user_uids: List of user UID connected to this resource.
        :param admin_user_record_uid: The user UID of the administrator of the resource.
        :param connection_settings: Instance of ConnectionSettings.
        :param jit_settings: Instance of JitSettings.
        :param ai_settings: Instance of AiSettings.
        :param domain_uid: Indicated this resource connects to a domain.
        :param meta: Meta information stored on the DATA edge.
        :param update_services: Allow rotation to update services on this resource.
        :param agent: A custom HTTP agent. Shows up in Data Dog.
        :return:
        """

        if record is None:
            raise Exception("Record is None. Cannot set_record_rotation.")

        # only configure resources.
        if record.type not in ["pamMachine", "pamDatabase", "pamDirectory"]:
            raise ValueError(f"Cannot configure resources on {record.uid}. Record type is {record.type}.")

        if jit_settings is not None:
            if isinstance(jit_settings, JitSettings):
                jit_settings = jit_settings.model_dump_json()
            elif isinstance(jit_settings, str):
                try:
                    json.loads(jit_settings)
                except Exception as err:
                    raise ValueError(f"The jit_settings is not JSON: {err}")
            elif isinstance(jit_settings, dict):
                jit_settings = json.dumps(jit_settings)
            else:
                raise ValueError("Unknown structure for jit_settings")
            jit_settings = base64.b64encode(encrypt_aes(jit_settings.encode(), record.record_key_bytes)).decode()

        if connection_settings is not None:
            self.logger.debug("currently, the Vault reads connection_settings from the record, not the graph.")
            if isinstance(connection_settings, ConnectionSettingsBase):
                connection_settings = connection_settings.model_dump_json()
            elif isinstance(connection_settings, str):
                try:
                    json.loads(connection_settings)
                except Exception as err:
                    raise ValueError(f"The connection_settings is not JSON: {err}")
            elif isinstance(connection_settings, dict):
                connection_settings = json.dumps(connection_settings)
            else:
                raise ValueError("Unknown structure for connection_settings")

        if meta is not None:
            if isinstance(meta, Meta):
                meta = meta.model_dump_json()
            elif isinstance(meta, str):
                try:
                    json.loads(meta)
                except Exception as err:
                    raise ValueError(f"The meta is not JSON: {err}")
            elif isinstance(meta, dict):
                meta = json.dumps(meta)
            else:
                raise ValueError("Unknown structure for meta")

        if ai_settings is not None:
            if isinstance(ai_settings, AiSettings):
                ai_settings = ai_settings.model_dump_json()
            elif isinstance(ai_settings, str):
                try:
                    json.loads(ai_settings)
                except Exception as err:
                    raise ValueError(f"The ai_settings is not JSON: {err}")
            elif isinstance(ai_settings, dict):
                ai_settings = json.dumps(ai_settings)
            else:
                raise ValueError("Unknown structure for ai_settings")
            ai_settings = base64.b64encode(encrypt_aes(ai_settings.encode(), record.record_key_bytes)).decode()

        if agent is None:
            agent = f"keeper-dag/{__version__}"

        endpoint = self._endpoint("configure_resource")
        self.logger.debug(f"endpoint {endpoint}")

        try:
            payload = dict(
                recordUid=record.uid,
                networkUid=configuration_record_uid,
                adminUid=admin_user_record_uid,
                meta=meta,
                connectionSettings=connection_settings,
                connectUsers=connection_user_uids,
                domainUid=domain_uid,
                jitSettings=jit_settings,
                updateServices=update_services,
                keeperAiSettings=ai_settings
            )

            print(json.dumps(payload))

            payload, headers = self.payload_and_headers(payload)
            self.rest_call_to_router(http_method="POST",
                                     endpoint=endpoint,
                                     payload=payload,
                                     headers=headers,
                                     agent=agent)
        except Exception as err:
            raise DAGException(f"Could not configure resource for {record.uid}: {err}")

    def set_record_rotation(self,
                            record: Record,
                            configuration_record_uid: str,
                            schedule: Optional[dict | str] = None,
                            resource_uid: Optional[str] = None,
                            pwd_complexity: Optional[dict] = None,
                            disabled: bool = False,
                            remote_address: Optional[str] = None,
                            noop: bool = False,
                            saas_configuration_uid: Optional[str] = None,
                            update_services: bool = False,
                            service_resource_uids: Optional[List[str]] = None,
                            service_names: Optional[List] = None,
                            agent: Optional[str] = None):

        """
        Set the rotation setting on a PAM User record.

        The `schedule` can either be a dictionary or JSON.
        The `pwd_complexity` can either be a dictionary or JSON.

        The service names is a list of resource UID and names.
        The resource UID should be found in the `service_resource_uids` list.
        For example,

        Examples:
            service_names = [
                {
                    "resource_uid": "ztcAMLHaIU_uUK6lYK0GNw",
                    "names": [
                        {
                            "type": "service",
                            "items": [{"name": "Service Name", "via_discovery": True}]
                        }
                    ]
                }
            ]

        `names` can also be a list of `UserAclServiceNames` from `discovery-common`.

        :param record: The PAM User record to set rotation settings.
        :param configuration_record_uid: The configuration record UID.
        :param schedule: If set, password rotation will happen on a schedule.
        :param resource_uid: If set, the user will belong to this resource.
        :param pwd_complexity: The complexity of the password.
        :param disabled: Is True, rotation will not be allowed.
        :param remote_address: The IP address of the machine making the request.
        :param noop: If True, user account are not updated during rotations.
        :param saas_configuration_uid: If set, this user is used on a remote SaaS.
        :param update_services: If True, if the user  is used for a services,
                                those services password will also be rotated.
        :param service_resource_uids: A list of resource UID where this user is used for a service.
        :param service_names: List of dictionaries containing the resource UID, from service_resource_uids, and
                              and and a base64, encrypted, JSON.
        :param agent: A custom HTTP agent. Shows up in Data Dog.
        :return:
        """

        if record is None:
            raise Exception("Record is None. Cannot set_record_rotation.")

        # Only set the rotation setting on PAM User records.
        if record.type != "pamUser":
            raise ValueError(f"Cannot set the rotation setting on {record.uid}. Record type is {record.type}.")

        if schedule is None:
            schedule = ""
        else:
            if isinstance(schedule, dict):
                schedule = json.dumps(schedule)
            if isinstance(schedule, str):
                try:
                    json.loads(schedule)
                except Exception as err:
                    raise ValueError(f"The schedules is not JSON: {err}")

        if pwd_complexity is None:
            pwd_complexity = {}
        if isinstance(pwd_complexity, dict):
            pwd_complexity = json.dumps(pwd_complexity)
        if isinstance(pwd_complexity, str):
            pwd_complexity = pwd_complexity.encode()
        if not isinstance(pwd_complexity, bytes):
            raise ValueError("The complexity is not a dictionary, string or bytes.")
        pwd_complexity = base64.b64encode(encrypt_aes(pwd_complexity, record.record_key_bytes)).decode()

        if agent is None:
            agent = f"keeper-dag/{__version__}"

        endpoint = self._endpoint("set_record_rotation")
        self.logger.debug(f"endpoint {endpoint}")

        try:
            payload = dict(
                recordUid=record.uid,
                revision=record.revision,
                networkUid=configuration_record_uid,
                disabled=disabled,
                schedules=schedule,
                pwdComplexity=pwd_complexity,
                remoteAddress=remote_address,
                noop=noop,
                updateServices=update_services
            )
            if resource_uid is not None:
                payload["resourceUid"] = resource_uid
            if saas_configuration_uid is not None:
                payload["saasConfiguration"] = saas_configuration_uid
            if service_resource_uids is not None and isinstance(service_resource_uids, list):
                payload["serviceResources"] = service_resource_uids
            if service_names is not None:
                if not isinstance(service_names, list):
                    raise ValueError("service_names should be a list of objects that contain the resourceUID and name.")

                payload["serviceNames"] = []

                for item in service_names:

                    name = item.get("names")
                    if isinstance(name, BaseModel):
                        name = name.model_dump()
                    elif isinstance(name, str):
                        try:
                            name = json.loads(name)
                        except (Exception,):
                            raise ValueError("The name is not JSON.")
                    elif isinstance(name, list):
                        name = json.dumps(name)
                    else:
                        raise ValueError(f"The name is not a list, string or pydantic model.")
                    name = base64.b64encode(encrypt_aes(name.encode(), record.record_key_bytes)).decode()

                    payload["serviceNames"].append(
                        {
                            "names": name,
                            "resourceUid": item.get("resource_uid")
                        }
                    )

            payload, headers = self.payload_and_headers(payload)

            print(payload)

            self.rest_call_to_router(http_method="POST",
                                     endpoint=endpoint,
                                     payload=payload,
                                     headers=headers,
                                     agent=agent)
        except Exception as err:
            raise DAGException(f"Could not set the record's rotation setting for {record.uid}: {err}")

    def configure_network_graph(self,
                                configuration_record_uid: str,
                                network_settings: Optional[NetworkSettings] = None,
                                resources:  Optional[List[NetworkResource]] = None,
                                rotations: Optional[List[NetworkRotation]] = None,
                                agent: Optional[str] = None):

        """
        Bulk configure network/configuraton.

        :param configuration_record_uid: The UID of the configuration record.
        :param network_settings: Instance of NetworkSettings
        :param resources:
        :param rotations:
        :param agent:
        :return:
        """

        if agent is None:
            agent = f"keeper-dag/{__version__}"

        endpoint = self._endpoint("configure_network_graph")
        self.logger.debug(f"endpoint {endpoint}")

        try:
            payload: Dict[str, Any] = {
                "recordUid": configuration_record_uid
            }

            if network_settings is not None:
                if isinstance(network_settings, NetworkSettings):
                    network_settings = network_settings.model_dump()
                elif isinstance(network_settings, str):
                    try:
                        network_settings = json.loads(network_settings)
                    except Exception as err:
                        raise ValueError(f"The network_settings is not JSON: {err}")
                else:
                    raise ValueError("Unknown structure for network_settings")

                payload["networkSettings"] = network_settings

            if resources is not None:

                if not isinstance(resources, list):
                    raise ValueError("resources is not a list")

                encoded_resources = []
                for item in resources:
                    item.networkUid = configuration_record_uid

                    # If we have meta, make sure its JSON
                    if item.meta:
                        if isinstance(item.meta, Meta):
                            item.meta = item.meta.encode()
                        elif isinstance(item.meta, dict):
                            item.meta = json.dumps(item.meta)
                        elif isinstance(item.meta, str):
                            try:
                                json.loads(item.meta)
                            except Exception as err:
                                raise ValueError(f"The meta for {item.recordUid} is not JSON: {err}")

                    # If we have connectionSettings, make sure its JSON
                    if item.connectionSettings:
                        if isinstance(item.connectionSettings, ConnectionSettingsBase):
                            item.connectionSettings = item.connectionSettings.encode()
                        elif isinstance(item.connectionSettings, dict):
                            item.connectionSettings = json.dumps(item.connectionSettings)
                        elif isinstance(item.connectionSettings, str):
                            try:
                                json.loads(item.connectionSettings)
                            except Exception as err:
                                raise ValueError(f"The connectionSettings for {item.recordUid} is not JSON: {err}")

                    # For jitSettings we need the encrypted JSON as Base64.
                    # We cannot encrypt in here since we don't have the record key bytes.
                    if item.jitSettings:
                        if isinstance(item.jitSettings, str):
                            try:
                                json.loads(item.jitSettings)
                                raise ValueError(f"The jitSettings for {item.recordUid} is JSON, "
                                                 "should be base64 str.")
                            except (Exception,):
                                pass
                        else:
                            raise ValueError(f"The jitSettings for {item.recordUid} is not a base64 str.")

                    # For keeperAiSettings we need the encrypted JSON as Base64.
                    # We cannot encrypt in here since we don't have the record key bytes.
                    if item.keeperAiSettings:
                        if isinstance(item.keeperAiSettings, str):
                            try:
                                json.loads(item.keeperAiSettings)
                                raise ValueError(f"The keeperAiSettings for {item.recordUid} is JSON, "
                                                 "should be base64 str.")
                            except (Exception,):
                                pass
                        else:
                            raise ValueError(f"The keeperAiSettings for {item.recordUid} is not a base64 str.")

                    encoded_resources.append(item.model_dump(exclude_none=True))
                payload["resources"] = encoded_resources

            if rotations is not None:

                if not isinstance(rotations, list):
                    raise ValueError("rotations is not a list")

                encoded_rotations = []
                for item in rotations:
                    item.networkUid = configuration_record_uid

                    if item.schedule:
                        if isinstance(item.schedule, str):
                            try:
                                json.loads(item.schedule)
                            except (Exception,):
                                raise ValueError(f"The schedule for {item.recordUid} is not valid JSON.")
                        else:
                            raise ValueError(f"The schedule for {item.recordUid} is not JSON.")

                    encoded_rotations.append(item.model_dump(exclude_none=True))

                payload["rotations"] = encoded_rotations

            payload, headers = self.payload_and_headers(payload)

            print(payload)

            self.rest_call_to_router(http_method="POST",
                                     endpoint=endpoint,
                                     payload=payload,
                                     headers=headers,
                                     agent=agent)
        except Exception as err:
            raise DAGException(f"Could not configure network graph for {configuration_record_uid}: {err}")




