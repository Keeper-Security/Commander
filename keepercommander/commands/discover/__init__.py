from __future__ import annotations
import logging
import os

from ..base import Command
from ..pam.config_facades import PamConfigurationRecordFacade
from ..pam.router_helper import get_response_payload
from ..pam.gateway_helper import get_all_gateways
from ..ksm import KSMCommand
from ... import utils, vault_extensions
from ... import vault
from ...proto import APIRequest_pb2
from ...crypto import encrypt_aes_v2, decrypt_aes_v2
from ...display import bcolors
from ...discovery_common.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from ...utils import value_to_boolean
import json
import base64
import re

from typing import List, Optional, Union, Callable, Tuple, Any, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...vault import KeeperRecord, ApplicationRecord
    from ...proto import pam_pb2


class MultiConfigurationException(Exception):
    """
    If the gateway has multiple configuration
    """
    def __init__(self, items: List[Dict]):
        super().__init__()
        self.items = items

    def print_items(self):
        for item in self.items:
            record = item["configuration_record"]  # type: KeeperRecord
            print(f" * {record.record_uid} - {record.title}")


class GatewayContext:

    """
    Context for a gateway and a configuration.

    In the configuration record, the gateway is selected.
    This means multiple configuration can use the same gateway.
    Commander is gateway centric, we need to treat gateway and configuration as a `primary key`

    Since we get the configuration record from the vault, go through each of them and see if that gateway
      is only used by one configuration.
    If it is, then that gateway and configuration pair are used.
    If there are multiple configuration, we need to throw an MultiConfigurationException.

    """

    def __init__(self, configuration: KeeperRecord, facade: PamConfigurationRecordFacade,
                 gateway: pam_pb2.PAMController, application: ApplicationRecord):
        self.configuration = configuration
        self.facade = facade
        self.gateway = gateway
        self.application = application
        self._shared_folders = None

    @staticmethod
    def all_gateways(params: KeeperParams):
        return get_all_gateways(params)

    @staticmethod
    def get_configuration_records(params) -> List[KeeperRecord]:

        """
        Get PAM configuration records.

        The default it to find all the record version 6 records.
        If the environment variable `PAM_RECORD_TYPE_MATCH` is set to a true value, the search will use both record
          versions 3 and 6, and then check the record type.
        """

        configuration_list = []
        if value_to_boolean(os.environ.get("PAM_RECORD_TYPE_MATCH")):
            for record in list(vault_extensions.find_records(params, record_version=iter([3, 6]))):
                if re.search(r"pam.+Configuration", record.record_type):
                    configuration_list.append(record)
        else:
            configuration_list = list(vault_extensions.find_records(params, record_version=6))
        return configuration_list

    @classmethod
    def find_gateway(cls, params: KeeperParams, find_func: Callable, gateways: Optional[List] = None) \
            -> Tuple[Optional[GatewayContext], Any]:

        """
        Populate the context from matching using the function passed in.
        The function needs to return a non-None value to be considered a positive match.

        """

        if gateways is None:
            gateways = GatewayContext.all_gateways(params)

        configuration_records = cls.get_configuration_records(params)
        for configuration_record in configuration_records:

            payload = find_func(
                configuration_record=configuration_record
            )
            if payload is not None:
                return GatewayContext.from_configuration_uid(
                    params=params,
                    configuration_uid=configuration_record.record_uid,
                    gateways=gateways
                ), payload

        return None, None

    @staticmethod
    def from_configuration_uid(params: KeeperParams, configuration_uid: str, gateways: Optional[List] = None) \
            -> Optional[GatewayContext]:

        """
        Populate context using the configuration UID.

        From the configuration record, get the gateway from the settings.

        """

        if gateways is None:
            gateways = GatewayContext.all_gateways(params)

        configuration_record = vault.KeeperRecord.load(params, configuration_uid)
        if not isinstance(configuration_record, vault.TypedRecord):
            print(f'{bcolors.FAIL}PAM Configuration [{configuration_uid}] is not available.{bcolors.ENDC}')
            return None

        configuration_facade = PamConfigurationRecordFacade()
        configuration_facade.record = configuration_record

        gateway_uid = configuration_facade.controller_uid
        gateway = next((x for x in gateways
                        if utils.base64_url_encode(x.controllerUid) == gateway_uid),
                       None)

        if gateway is None:
            return None

        application_id = utils.base64_url_encode(gateway.applicationUid)
        application = KSMCommand.get_app_record(params, application_id)

        return GatewayContext(
            configuration=configuration_record,
            facade=configuration_facade,
            gateway=gateway,
            application=application
        )

    @staticmethod
    def from_gateway(params: KeeperParams, gateway: str, configuration_uid: Optional[str] = None) \
            -> Optional[GatewayContext]:

        """
        Populate context use the gateway, and optional configuration UID.

        This will scan all configuration to find which ones use this gateway.
        If there are multiple ones, a MultiConfigurationException is thrown.
        If there is only one gateway, then that gateway is used.

        """
        # Get all the PAM configuration records in the Vault; configurations are version 6
        configuration_records = GatewayContext.get_configuration_records(params=params)

        if configuration_uid:
            logging.debug(f"find the gateway with configuration record {configuration_uid}")

        # You get this if the user has not setup any PAM related records.
        if len(configuration_records) == 0:
            print(f"{bcolors.FAIL}Cannot find any PAM configuration records in the Vault{bcolors.ENDC}")
            return None

        all_gateways = get_all_gateways(params)
        found_items = []
        for configuration_record in configuration_records:

            logging.debug(f"checking configuration record {configuration_record.title}")

            # Load the configuration record and get the gateway_uid from the facade.
            configuration_record = vault.KeeperRecord.load(params, configuration_record.record_uid)
            configuration_facade = PamConfigurationRecordFacade()
            configuration_facade.record = configuration_record

            configuration_gateway_uid = configuration_facade.controller_uid
            if configuration_gateway_uid is None:
                logging.debug(f" * configuration {configuration_record.title} does not have a gateway set, skipping.")
                continue

            # Get the gateway for this configuration
            found_gateway = next((x for x in all_gateways if utils.base64_url_encode(x.controllerUid) ==
                                  configuration_gateway_uid), None)
            if found_gateway is None:
                logging.debug(f" * configuration does not use desired gateway")
                continue

            # If the configuration_uid was passed in, and we find it, just set the found items to this
            #   configuration and stop checking for more.
            if configuration_uid is not None and configuration_uid == configuration_record.record_uid:
                logging.debug(f" * configuration record uses this gateway and matches desire configuration, "
                              "skipping the rest")
                found_items = [{
                    "configuration_facade": configuration_facade,
                    "configuration_record": configuration_record,
                    "gateway": found_gateway
                }]
                break

            if (utils.base64_url_encode(found_gateway.controllerUid) == gateway or
                    found_gateway.controllerName.lower() == gateway.lower()):
                logging.debug(f" * configuration record uses this gateway")
                found_items.append({
                    "configuration_facade": configuration_facade,
                    "configuration_record": configuration_record,
                    "gateway": found_gateway
                })

            if len(found_items) > 1:
                logging.debug(f"found {len(found_items)} configurations using this gateway")
                raise MultiConfigurationException(
                    items=found_items
                )

        if len(found_items) == 1:
            found_gateway = found_items[0]["gateway"]
            configuration_record = found_items[0]["configuration_record"]
            configuration_facade = found_items[0]["configuration_facade"]

            application_id = utils.base64_url_encode(found_gateway.applicationUid)
            application = KSMCommand.get_app_record(params, application_id)
            if application is None:
                logging.debug(f"cannot find application for gateway {gateway}, skipping.")

            if (utils.base64_url_encode(found_gateway.controllerUid) == gateway or
                    found_gateway.controllerName.lower() == gateway.lower()):
                return GatewayContext(
                    configuration=configuration_record,
                    facade=configuration_facade,
                    gateway=found_gateway,
                    application=application
                )

        return None

    @property
    def gateway_uid(self) -> str:
        return utils.base64_url_encode(self.gateway.controllerUid)

    @property
    def configuration_uid(self) -> str:
        return self.configuration.record_uid

    @property
    def gateway_name(self) -> str:
        return self.gateway.controllerName

    @property
    def default_shared_folder_uid(self) -> str:
        return self.facade.folder_uid

    def is_gateway(self, request_gateway: str) -> bool:
        if request_gateway is None or self.gateway_name is None:
            return False
        return (request_gateway == utils.base64_url_encode(self.gateway.controllerUid) or
                request_gateway.lower() == self.gateway_name.lower())

    def get_shared_folders(self, params: KeeperParams) -> List[dict]:
        if self._shared_folders is None:
            self._shared_folders = []
            application_uid = utils.base64_url_encode(self.gateway.applicationUid)
            app_info = KSMCommand.get_app_info(params, application_uid)
            for info in app_info:
                if info.shares is None:
                    continue
                for shared in info.shares:
                    uid_str = utils.base64_url_encode(shared.secretUid)
                    shared_type = APIRequest_pb2.ApplicationShareType.Name(shared.shareType)
                    if shared_type == 'SHARE_TYPE_FOLDER':
                        if uid_str not in params.shared_folder_cache:
                            continue
                        cached_shared_folder = params.shared_folder_cache[uid_str]
                        self._shared_folders.append({
                            "uid": uid_str,
                            "name": cached_shared_folder.get('name_unencrypted'),
                            "folder": cached_shared_folder
                        })
        return self._shared_folders

    def decrypt(self, cipher_base64: bytes) -> dict:
        ciphertext = base64.b64decode(cipher_base64.decode())
        return json.loads(decrypt_aes_v2(ciphertext, self.configuration.record_key))

    def encrypt(self, data: dict) -> str:
        json_data = json.dumps(data)
        ciphertext = encrypt_aes_v2(json_data.encode(), self.configuration.record_key)
        return base64.b64encode(ciphertext).decode()

    def encrypt_str(self, data: Union[bytes, str]) -> str:
        if isinstance(data, str):
            data = data.encode()
        ciphertext = encrypt_aes_v2(data, self.configuration.record_key)
        return base64.b64encode(ciphertext).decode()


class PAMGatewayActionDiscoverCommandBase(Command):

    """
    The discover command base.

    Contains static methods to get the configuration record, get and update the discovery store. These are methods
    used by multiple discover actions.
    """

    # If the discovery data field does not exist, or the field contains no values, use the template to init the
    # field.

    STORE_LABEL = "discoveryKey"
    FIELD_MAPPING = {
        "pamHostname": {
            "type": "dict",
            "field_input": [
                {"key": "hostName", "prompt": "Hostname"},
                {"key": "port", "prompt": "Port"}
            ],
            "field_format": [
                {"key": "hostName", "label": "Hostname"},
                {"key": "port", "label": "Port"},
            ]
        },
        "alternativeIPs": {
            "type": "csv",
        },
        "privatePEMKey": {
            "type": "multiline",
        },
        "operatingSystem": {
            "type": "choice",
            "values": ["linux", "macos", "windows", "cisco_ios_xe"]
        }
    }

    type_name_map = {
        PAM_USER: "PAM Users",
        PAM_MACHINE: "PAM Machines",
        PAM_DATABASE: "PAM Databases",
        PAM_DIRECTORY: "PAM Directories",
    }

    @staticmethod
    def get_response_data(router_response: dict) -> Optional[dict]:

        if router_response is None:
            return None

        response = router_response.get("response")
        logging.debug(f"Router Response: {response}")
        payload = get_response_payload(router_response)
        return payload.get("data")

    @staticmethod
    def _gr(msg):
        return f"{bcolors.OKGREEN}{msg}{bcolors.ENDC}"

    @staticmethod
    def _bl(msg):
        return f"{bcolors.OKBLUE}{msg}{bcolors.ENDC}"

    @staticmethod
    def _h(msg):
        return f"{bcolors.HEADER}{msg}{bcolors.ENDC}"

    @staticmethod
    def _b(msg):
        return f"{bcolors.BOLD}{msg}{bcolors.ENDC}"

    @staticmethod
    def _f(msg):
        return f"{bcolors.FAIL}{msg}{bcolors.ENDC}"

    @staticmethod
    def _p(msg):
        return msg

    @staticmethod
    def _n(record_type):
        return PAMGatewayActionDiscoverCommandBase.type_name_map.get(record_type, "PAM Configuration")


def multi_conf_msg(gateway: str, err: MultiConfigurationException):
    print("")
    print(f"{bcolors.FAIL}Found multiple configuration records for gateway {gateway}.{bcolors.ENDC}")
    print("")
    print(f"Please use the --configuration-uid parameter to select the configuration.")
    print(f"Available configurations are: ")
    err.print_items()
    print("")