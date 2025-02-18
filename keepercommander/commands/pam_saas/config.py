from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from ... import api, subfolder, utils, crypto, vault, vault_extensions
from ...proto import record_pb2
from . import get_gateway_saas_schema
from ...utils import value_to_boolean
from ...error import KeeperApiError
import json
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionSaasConfigCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-saas-info')

    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--list', '-l', required=False, dest='do_list', action='store_true',
                        help='List available SaaS types for gateway.')
    parser.add_argument('--config-type', '-t', required=False, dest='saas_type', action='store',
                        help='Create SaaS config of this type.')
    parser.add_argument('--shared-folder-uid', '-s', required=False, dest='shared_folder_uid',
                        action='store', help='Shared folder to store SaaS configuration.')

    def get_parser(self):
        return PAMActionSaasConfigCommand.parser

    @staticmethod
    def get_input(field):
        print(f"{bcolors.BOLD}{field.get('label')}{bcolors.ENDC}")
        print(f"Description: {field.get('desc')}")

        while True:
            prompt = "Enter value"
            if field.get("default_value") is not None:
                prompt += f" (Enter for default valuue '{field.get('default_value')}')"
            prompt += " > "
            value = input(prompt)
            if value is None and field.get('default_value') is not None:
                value= field.get('default_value')
            if value is not None:
                break
            if field.get('required', False) is False:
                break

            print(f"{bcolors.FAIL}This field is required.")

        print("")

        return [value]

    def execute(self, params: KeeperParams, **kwargs):

        do_list = kwargs.get("do_list", False)  # type: bool
        gateway = kwargs.get("gateway")  # type: str
        saas_type = kwargs.get("saas_type")   # type: str

        print("")

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        shared_folder_uid = kwargs.get("shared_folder_uid")  # type: Optional[str]
        if shared_folder_uid is None:
            shared_folder_uid = gateway_context.default_shared_folder_uid

        schema_res = get_gateway_saas_schema(params, gateway_context)
        if schema_res is None:
            return

        if do_list is True:
            print("Available SaaS rotation on the gateway:")
            for item in schema_res.get('data'):
                print(f"  * {item.get('name')}")
            return

        saas_schema = next((x for x in schema_res.get('data') if x.get('id') == saas_type), None)
        if saas_schema is None:
            print(f"{bcolors.FAIL}Cannot find the SaaS rotation type {saas_type}.")
            return

        custom_fields = [
            vault.TypedField.new_field(
                field_type="text",
                field_label="SaaS Type",
                field_value=[saas_type]
            ),
            vault.TypedField.new_field(
                field_type="text",
                field_label="Active",
                field_value=["TRUE"]
            )
        ]

        # Do require first
        for item in saas_schema.get("schema", []):
            if item.get("required", False) is True:
                continue
            value = self.get_input(item)
            if value is not None:
                field_args = {
                    "field_type": "secret" if item.get("type") == "secret" else "text",
                    "field_label": item.get("label"),
                    "field_value": value
                }
                record_field = vault.TypedField.new_field(**field_args)
                record_field.required = True
                custom_fields.append(record_field)

        # Do optional
        for item in saas_schema.get("schema", []):
            if item.get("required", False) is False:
                continue
            value = self.get_input(item)
            if value is not None:
                field_args = {
                    "field_type": "secret" if item.get("type") == "secret" else "text",
                    "field_label": item.get("label"),
                    "field_value": value
                }
                record_field = vault.TypedField.new_field(**field_args)
                record_field.required = False
                custom_fields.append(record_field)

        print("")
        while True:
            title = input("Title for the SaaS configuration record > ")
            if title != "":
                break
            print(f"{bcolors.FAIL}Require a record title.")

        record = vault.TypedRecord()
        record.type_name = "login"
        record.record_uid = utils.generate_uid()
        record.record_key = utils.generate_aes_key()
        record.title = title

        for item in custom_fields:
            record.custom.append(item)

        folder = params.folder_cache.get(shared_folder_uid)
        folder_key = None  # type: Optional[bytes]
        if isinstance(folder, subfolder.SharedFolderFolderNode):
            shared_folder_uid = folder.shared_folder_uid
        elif isinstance(folder, subfolder.SharedFolderNode):
            shared_folder_uid = folder.uid
        else:
            shared_folder_uid = None
        if shared_folder_uid and shared_folder_uid in params.shared_folder_cache:
            shared_folder = params.shared_folder_cache.get(shared_folder_uid)
            folder_key = shared_folder.get('shared_folder_key_unencrypted')

        add_record = record_pb2.RecordAdd()
        add_record.record_uid = utils.base64_url_decode(record.record_uid)
        add_record.record_key = crypto.encrypt_aes_v2(record.record_key, params.data_key)
        add_record.client_modified_time = utils.current_milli_time()
        add_record.folder_type = record_pb2.user_folder
        if folder:
            add_record.folder_uid = utils.base64_url_decode(folder.uid)
            if folder.type == 'shared_folder':
                add_record.folder_type = record_pb2.shared_folder
            elif folder.type == 'shared_folder_folder':
                add_record.folder_type = record_pb2.shared_folder_folder
            if folder_key:
                add_record.folder_key = crypto.encrypt_aes_v2(record.record_key, folder_key)

        data = vault_extensions.extract_typed_record_data(record)
        json_data = api.get_record_data_json_bytes(data)
        add_record.data = crypto.encrypt_aes_v2(json_data, record.record_key)

        if params.enterprise_ec_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                add_record.audit.version = 0
                add_record.audit.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

        rq = record_pb2.RecordsAddRequest()
        rq.client_time = utils.current_milli_time()
        rq.records.append(add_record)
        rs = api.communicate_rest(params, rq, 'vault/records_add', rs_type=record_pb2.RecordsModifyResponse)
        record_rs = next((x for x in rs.records if utils.base64_url_encode(x.record_uid) == record.record_uid), None)
        if record_rs:
            if record_rs.status != record_pb2.RS_SUCCESS:
                raise KeeperApiError(record_rs.status, rs.message)
        record.revision = rs.revision
        if record.linked_keys:
            for file_uid in record.linked_keys:
                params.queue_audit_event(
                    'file_attachment_uploaded', record_uid=record.record_uid, attachment_id=file_uid)

        shared_folders = gateway_context.get_shared_folders(params)
        name = next((x.get("name") for x in shared_folders if x.get("uid") == shared_folder_uid), None)
        if name is None:
            name = shared_folder_uid

        print("")
        print(f"{bcolors.OKGREEN}Record {record.record_uid} created in shared folder '{name}'{bcolors.ENDC}")
        print("")
