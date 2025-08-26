from __future__ import annotations
import logging
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
import json
import base64

from typing import List, Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...vault import KeeperRecord, ApplicationRecord
    from ...proto import pam_pb2


class GatewayContext:
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
    def from_configuration_uid(params: KeeperParams, configuration_uid: str, gateways: Optional[List] = None):

        if gateways is None:
            gateways = GatewayContext.all_gateways(params)

        configuration_record = vault.KeeperRecord.load(params, configuration_uid)
        if not isinstance(configuration_record, vault.TypedRecord):
            print(f'{bcolors.FAIL}PAM Configuration [{configuration_uid}] is not available.{bcolors.ENDC}')
            return

        configuration_facade = PamConfigurationRecordFacade()
        configuration_facade.record = configuration_record

        gateway_uid = configuration_facade.controller_uid
        gateway = next((x for x in gateways
                        if utils.base64_url_encode(x.controllerUid) == gateway_uid),
                       None)

        if gateway is None:
            return

        application_id = utils.base64_url_encode(gateway.applicationUid)
        application = KSMCommand.get_app_record(params, application_id)

        return GatewayContext(
            configuration=configuration_record,
            facade=configuration_facade,
            gateway=gateway,
            application=application
        )

    @staticmethod
    def from_gateway(params: KeeperParams, gateway: str):
        # Get all the PAM configuration records
        configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))
        if len(configuration_records) == 0:
            print(f"{bcolors.FAIL}Cannot find any PAM configuration records in the Vault{bcolors.ENDC}")

        all_gateways = get_all_gateways(params)

        for record in configuration_records:

            logging.debug(f"checking configuration record {record.title}")

            # Load the configuration record and get the gateway_uid from the facade.
            configuration_record = vault.KeeperRecord.load(params, record.record_uid)
            configuration_facade = PamConfigurationRecordFacade()
            configuration_facade.record = configuration_record

            configuration_gateway_uid = configuration_facade.controller_uid
            if configuration_gateway_uid is None:
                logging.debug(f"configuration {configuration_record.title} does not have a gateway set, skipping.")
                continue

            # Get the gateway for this configuration
            found_gateway = next((x for x in all_gateways if utils.base64_url_encode(x.controllerUid) ==
                                  configuration_gateway_uid), None)
            if found_gateway is None:
                logging.debug(f"cannot find gateway for configuration {configuration_record.title}, skipping.")
                continue

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
        ciphertext = base64.b64decode(cipher_base64)
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
            "values": ["linux", "macos", "windows"]
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
