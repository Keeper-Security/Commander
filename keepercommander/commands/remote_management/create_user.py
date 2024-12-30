from __future__ import annotations
import argparse
import logging
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from keepercommander.discovery_common.rm_types import (RmAwsUserAddMeta, RmAzureUserAddMeta, RmMySQLUserAddMeta,
                                                       RmLinuxUserAddMeta, RmOpenLdapUserAddMeta, RmAdUserAddMeta,
                                                       RmUser)
from ..pam.pam_dto import GatewayAction
from ..pam.router_helper import router_send_action_to_gateway
from ...proto import pam_pb2
from ...display import bcolors
from ... import vault
from ...utils import value_to_boolean
from ...crypto import encrypt_aes_v2
import base64
import json
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...vault import TypedRecord


class GatewayActionRmCreateUserCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 user: str,
                 password: Optional[str] = None,
                 resource_uid: Optional[str] = None,
                 meta: Optional[str] = None):

        self.configurationUid = configuration_uid
        self.user = user
        self.password = password
        self.resourceUid = resource_uid
        self.meta = meta

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionRmCreateUserCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionRmCreateUserCommandInputs, conversation_id=None):
        super().__init__('rm-create-user', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class RmCreateUserCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-rm-user-add')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')

    parser.add_argument('--user', required=True, dest='user', action='store',
                        help='User Name')
    parser.add_argument('--password', '-p', required=False, dest='password', action='store',
                        help='Password')

    parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                        help='Resource UID')

    @staticmethod
    def get_meta_user_class(params: KeeperParams,
                            configuration_record_uid: str,
                            resource_record_uid: Optional[str] = None):
        record_uid = configuration_record_uid
        if resource_record_uid is not None:
            record_uid = resource_record_uid

        record = vault.TypedRecord.load(params, record_uid)  # type: Optional[TypedRecord]

        meta_provider_map = {
            "pamAwsConfiguration": RmAwsUserAddMeta,
            "pamAzureConfiguration": RmAzureUserAddMeta,
        }

        meta_class = meta_provider_map.get(record.record_type)
        if meta_class is not None:
            return meta_class

        lookup = {}
        for field in record.fields:
            key = field.label
            if key is None or key == "":
                key = field.type
            value = field.value
            if len(value) > 0:
                value = value[0]
            lookup[key] = value

        if record.record_type == "pamDatabase":
            database_type = lookup.get("databaseType")
            if database_type == "mysql":
                return RmMySQLUserAddMeta
            elif database_type == "mariadb":
                return RmMySQLUserAddMeta
            raise Exception("Database type was not set on the database record.")
        elif record.record_type == "pamMachine":
            operating_system = lookup.get("operatingSystem")
            if operating_system == "linux":
                return RmLinuxUserAddMeta
            raise Exception("Operating system was not set on the machine record.")
        elif record.record_type == "pamDirectory":
            directory_type = lookup.get("directoryType")
            if directory_type == "openldap":
                return RmOpenLdapUserAddMeta
            elif directory_type == "ad":
                return RmAdUserAddMeta
            raise Exception("Directory type was not set on the directory record.")

        return None

    def get_parser(self):
        return RmCreateUserCommand.parser

    @staticmethod
    def meta_info(meta_class) -> List[dict]:

        data = []
        for attr_name in meta_class.model_fields:
            default = meta_class.model_fields[attr_name].default
            data_type = "str"
            is_array = meta_class.model_fields[attr_name].annotation.__name__ == "List"
            required = meta_class.model_fields[attr_name].annotation.__name__ == "Optional"
            if meta_class.model_fields[attr_name].annotation == bool:
                data_type = "bool"
            else:
                for item in list(meta_class.model_fields[attr_name].annotation.__args__):
                    data_type_name = item.__name__
                    if data_type_name != "NoneType":
                        data_type = data_type_name
            data.append({
                "name": attr_name,
                "data_type": data_type,
                "required": required,
                "is_array": is_array,
                "value": default
            })

        return sorted(data, key=lambda x: x["name"])

    @staticmethod
    def meta_menu(meta_info_data) -> List[dict]:
        print("")
        print(f"{bcolors.HEADER}Meta data is available for this record type.{bcolors.ENDC}")
        while True:
            for item in meta_info_data:
                print(f" {bcolors.BOLD}*{bcolors.ENDC} {item['name']} = {item['value']} ")
            print("")
            action = input("[A]ccept, [E]dit >").lower()
            if action == "a":
                return meta_info_data
            if action == "e":
                attr_name = input("Attribute >")
                value = input("Value >")
                for item in meta_info_data:
                    if item["name"] == attr_name:
                        if item["is_array"] is True:
                            new_value = []
                            for v in value.split(","):
                                new_value.append(v.strip())
                            value = new_value
                        elif item["data_type"] == "bool":
                            value = value_to_boolean(value)
                        item["value"] = value
                print("")

    @staticmethod
    def meta_data(meta_info: List[dict], meta_class, key: bytes):
        kwargs = {}
        for item in meta_info:
            kwargs[item['name']] = item['value']
        meta = meta_class(**kwargs)
        meta_json = meta.model_dump_json()
        meta_json_enc = encrypt_aes_v2(meta_json.encode(), key)
        return base64.b64encode(meta_json_enc).decode()

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        configuration_record = vault.TypedRecord.load(params, gateway_context.configuration_uid)

        try:
            meta_class = self.get_meta_user_class(
                params=params,
                configuration_record_uid=configuration_record.record_uid,
                resource_record_uid=kwargs.get('resource_uid')
            )
        except Exception as err:
            print(f"{bcolors.FAIL}{err}{bcolors.ENDC}")
            return

        meta_data = None
        if meta_class is not None:

            meta_info = self.meta_info(meta_class)
            self.meta_menu(meta_info)
            meta_data = self.meta_data(meta_info, meta_class, configuration_record.record_key)

        action_inputs = GatewayActionRmCreateUserCommandInputs(
            configuration_uid=gateway_context.configuration_uid,
            resource_uid=kwargs.get('resource_uid'),
            user=kwargs.get('user'),
            password=kwargs.get('password'),
            meta=meta_data
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionRmCreateUserCommand(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_context.gateway_uid
        )

        print("")

        data = self.get_response_data(router_response)
        if data is None:
            raise Exception("The router returned a failure.")
        elif data.get("success") is False:
            error = data.get("error")
            print(f"{bcolors.FAIL}Could not create user: {error}{bcolors.ENDC}")
            return

        user_json = gateway_context.decrypt(data.get("data"))
        user = RmUser.model_validate(user_json)

        print(f"{bcolors.OKGREEN}User created successfully{bcolors.ENDC}")
        print("")
        print(f"{bcolors.BOLD}Id{bcolors.ENDC}: {user.id}")
        print(f"{bcolors.BOLD}User{bcolors.ENDC}: {user.name}")
        print(f"{bcolors.BOLD}Distinguished Name{bcolors.ENDC}: {user.dn}")
        print(f"{bcolors.BOLD}Connect Database{bcolors.ENDC}: {user.connect_database}")
        print(f"{bcolors.BOLD}Password{bcolors.ENDC}: {user.password}")
        print(f"{bcolors.BOLD}Private Key{bcolors.ENDC}: {'Yes' if user.private_key is not None else 'No'}")
        print("")

