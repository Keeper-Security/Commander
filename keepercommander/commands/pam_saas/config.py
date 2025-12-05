from __future__ import annotations
import argparse
from ..pam.pam_dto import GatewayAction
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from . import get_plugins_map, make_script_signature, SaasCatalog, get_field_input
from ... import api, subfolder, utils, crypto, vault, vault_extensions, attachment, record_management
from ...proto import record_pb2
from ...api import get_records_add_request, sync_down
from ...error import KeeperApiError
from tempfile import TemporaryDirectory
import os
import json
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...vault import TypedRecord


class GatewayActionSaasConfigCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 plugin_code: str,
                 gateway_context: GatewayContext,
                 languages: Optional[List[str]] = None,
                 ):

        if languages is None:
            languages = ["en_US"]

        self.configurationUid = configuration_uid
        self.pluginCodeEnv = gateway_context.encrypt_str(plugin_code)
        self.languages = languages

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionSaasListCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionSaasConfigCommandInputs, conversation_id=None):
        super().__init__('saas-list', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class PAMActionSaasConfigCommand(PAMGatewayActionDiscoverCommandBase):

    parser = argparse.ArgumentParser(prog='pam action saas install')

    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--list', '-l', required=False, dest='do_list', action='store_true',
                        help='List available SaaS rotations.')

    # parser.add_argument('--search', '-s', required=False, dest='search', action='store',
    #                    help='Search for plugin.')

    parser.add_argument('--plugin', '-p', required=False, dest='plugin', action='store',
                        help='Plugin name')

    parser.add_argument('--info', required=False, dest='do_info', action='store_true',
                        help='Get information about a plugin or plugins being used.')
    parser.add_argument('--create', '-c', required=False, dest='do_create', action='store_true',
                        help='Create a SaaS Plugin config record.')
    parser.add_argument('--update-config-uid', '-u', required=False, dest='do_update', action='store',
                        help='Update an existing SaaS configuration.')

    parser.add_argument('--shared-folder-uid', '-s', required=False, dest='shared_folder_uid',
                        action='store', help='Shared folder to store SaaS configuration.')

    def get_parser(self):
        return PAMActionSaasConfigCommand.parser

    @staticmethod
    def _show_list(plugins: dict[str, SaasCatalog]):

        sorted_catalog = {}  # type: dict[str, SaasCatalog]
        if plugins:
            sorted_catalog = dict(sorted(plugins.items(), key=lambda i: i[1].name))

        sort_results = {
            "custom": {"title": "Custom", "using": [], "not_using": [], "color": bcolors.WARNING},
            "catalog": {"title": "Catalog", "using": [], "not_using": [], "color": bcolors.OKGREEN},
            "builtin": {"title": "Builtin", "using": [], "not_using": [], "color": bcolors.OKBLUE},
        }

        print("")
        print(f"{bcolors.HEADER}Available SaaS Plugins{bcolors.ENDC}")
        for _, plugin in sorted_catalog.items():
            plugin_type = plugin.type
            status = "using" if len(plugin.used_by) is True else "not_using"
            sort_results[plugin_type][status].append(plugin)

        for plugin_type in ["custom", "catalog", "builtin"]:
            for status in ["not_using", "using"]:
                color = sort_results[plugin_type]["color"]
                title = sort_results[plugin_type]["title"]
                for plugin in sort_results[plugin_type][status]:
                    summary = plugin.summary or "No description available"
                    name = plugin.name
                    desc = f" ({color}{title}"
                    if status == "using":
                        desc += f"{bcolors.BOLD}, Using{color}"
                    desc += f"{bcolors.ENDC})"
                    row = f" * {name}{desc} - {summary}"
                    print(row)

    @staticmethod
    def _show_plugin_info(plugin: SaasCatalog):
        print("")
        print(f"{bcolors.HEADER}{plugin.name}{bcolors.ENDC}")
        print(f"{bcolors.BOLD}  Type{bcolors.ENDC}: {plugin.type}")
        if plugin.author and plugin.email:
            print(f"{bcolors.BOLD}  Author{bcolors.ENDC}: {plugin.author} ({plugin.email})")
        elif plugin.author:
            print(f"{bcolors.BOLD}  Author{bcolors.ENDC}: {plugin.author}")
        print(f"{bcolors.BOLD}  Summary{bcolors.ENDC}: {plugin.summary or 'No description available'}")
        if plugin.readme:
            print(f"{bcolors.BOLD}  Documents{bcolors.ENDC}: {plugin.readme}")
        print("")
        print(f"  {bcolors.HEADER}Fields{bcolors.ENDC}")
        req_field = []
        opt_field = []
        for field in plugin.fields:
            if field.required:
                req_field.append(f"   * {bcolors.FAIL}Required{bcolors.ENDC}: {field.label} - "
                                 f"{field.desc}")
            else:
                opt_field.append(f"   * Optional: {field.label} - {field.desc}")
        for item in req_field:
            print(item)
        for item in opt_field:
            print(item)
        print("")

    @staticmethod
    def _create_config(params: KeeperParams,
                       plugin: SaasCatalog,
                       shared_folder_uid: str,
                       plugin_code_bytes: Optional[bytes] = None):

        custom_fields = [
            vault.TypedField.new_field(
                field_type="text",
                field_label="SaaS Type",
                field_value=[plugin.name]
            ),
            vault.TypedField.new_field(
                field_type="text",
                field_label="Active",
                field_value=["TRUE"]
            )
        ]

        for is_required in [True, False]:
            for item in plugin.fields:
                if item.required is is_required:
                    print("")
                    value = get_field_input(item)
                    if value is not None:
                        field_type = item.type
                        if field_type in ["url", "int", "number", "bool", "enum"]:
                            field_type = "text"

                        field_args = {
                            "field_type": field_type,
                            "field_label": item.label,
                            "field_value": value
                        }
                        record_field = vault.TypedField.new_field(**field_args)
                        # if item.is_secret:
                        #    record_field.privacyScreen = True

                        record_field.required = True
                        custom_fields.append(record_field)

        print("")
        while True:
            title = input("Title for the SaaS configuration record> ")
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

        rq = get_records_add_request(params)
        rq.records.append(add_record)
        rs = api.communicate_rest(params, rq, 'vault/records_add', rs_type=record_pb2.RecordsModifyResponse)
        record_rs = next((x for x in rs.records if utils.base64_url_encode(x.record_uid) == record.record_uid), None)
        if record_rs:
            if record_rs.status != record_pb2.RS_SUCCESS:
                raise KeeperApiError(record_rs.status, rs.message)
        record.revision = rs.revision

        params.sync_data = True

        # If this is not a built-in or custom script, we need to attach it to the config record.
        if plugin_code_bytes is not None and plugin.file_name:

            with TemporaryDirectory() as temp_dir:
                sync_down(params)

                existing_record = vault.TypedRecord.load(params, record.record_uid)  # type: TypedRecord
                if existing_record is None:
                    print(f"{bcolors.FAIL}Could not load the config record {record.record_uid} to attach script.")
                    return

                temp_file = os.path.join(temp_dir, plugin.file_name)
                with open(temp_file, "wb") as fh:
                    fh.write(plugin_code_bytes)
                    fh.close()
                task = attachment.FileUploadTask(temp_file)
                task.title = f"{plugin.name} Script"
                task.mime_type = "text/x-python"

                if plugin.file_sig:
                    script_signature = make_script_signature(plugin_code_bytes)
                    if script_signature != plugin.file_sig:
                        raise ValueError("The plugin signature in catalog does not match what was downloaded.")

                attachment.upload_attachments(params, existing_record, [task])

                record.fields = [
                    vault.TypedField.new_field(
                        field_type="fileRef",
                        field_value=list(existing_record.linked_keys.keys()))
                ]

                record_management.update_record(params, existing_record)
                params.sync_data = True

        print("")
        print(f"{bcolors.OKGREEN}Created SaaS configuration record with UID of {record.record_uid}{bcolors.ENDC}")
        print("")
        print("Assign this configuration to a user using the following command.")
        print(f"  {bcolors.OKGREEN}pam action saas add -c {record.record_uid} -u <PAM User Record UID>{bcolors.ENDC}")
        print(f"  See {bcolors.OKGREEN}pam action saas add --help{bcolors.ENDC} for more information.")

    def execute(self, params: KeeperParams, **kwargs):

        do_list = kwargs.get("do_list", False)  # type: bool
        do_info = kwargs.get("do_info", False)  # type: bool
        do_create = kwargs.get("do_create", False)  # type: bool
        do_update = kwargs.get("do_update", False)  # type: bool
        shared_folder_uid = kwargs.get("shared_folder_uid")  # type: str

        use_plugin = kwargs.get("plugin")  # type: Optional[str]
        gateway = kwargs.get("gateway")  # type: str

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print("")
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        plugins = get_plugins_map(
            params=params,
            gateway_context=gateway_context
        )

        if do_list:
            self._show_list(plugins)
        elif use_plugin is not None:

            if use_plugin not in plugins:
                print("")
                print(f"{bcolors.FAIL}Cannot find '{use_plugin}' in the catalog.{bcolors.ENDC}")
                return

            plugin = plugins[use_plugin]

            if do_info:
                self._show_plugin_info(plugin=plugin)

            elif do_create:

                shared_folders = gateway_context.get_shared_folders(params)
                if shared_folder_uid is None:
                    if len(shared_folders) == 1:
                        shared_folder_uid = shared_folders[0].get("uid")
                    else:
                        print("")
                        print(f"{bcolors.FAIL}Multiple shared folders found. "
                              f"Please use '-s' to select a shared folder.{bcolors.ENDC}")
                if next((x for x in shared_folders if x.get("uid") == shared_folder_uid), None) is None:
                    print("")
                    print(f"{bcolors.FAIL}The shared folder is not part of the gateway application.{bcolors.ENDC}")
                    return

                # For catalog plugins, we need to download the python file from GitHub.
                plugin_code_bytes = None
                if plugin.type == "catalog" and plugin.file:
                    res = utils.ssl_aware_get(plugin.file)
                    if res.ok is False:
                        print("")
                        print(f"{bcolors.FAIL}Could download the script from GitHub.{bcolors.ENDC}")
                        return
                    plugin_code_bytes = res.content

                self._create_config(
                    params=params,
                    plugin=plugin,
                    shared_folder_uid=shared_folder_uid,
                    plugin_code_bytes=plugin_code_bytes)
            elif do_update:
                pass
            else:
                PAMActionSaasConfigCommand.parser.print_help()
        else:
            if do_update:
                pass
            else:
                PAMActionSaasConfigCommand.parser.print_help()
