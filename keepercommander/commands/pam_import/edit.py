#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2025 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

from __future__ import annotations
import argparse
import json
import logging
import os.path

from itertools import chain
from typing import Any, Dict, Optional, List, Union

from .keeper_ai_settings import set_resource_jit_settings, set_resource_keeper_ai_settings, refresh_meta_to_latest, refresh_link_to_config_to_latest
from .base import (
    PAM_RESOURCES_RECORD_TYPES,
    PROJECT_IMPORT_JSON_TEMPLATE,
    PamConfigEnvironment,
    PamUserObject,
    LoginUserObject,
    PamMachineObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamRemoteBrowserObject,
    PamRotationParams,
    add_pam_scripts,
    find_external_user,
    find_user,
    get_admin_credential,
    get_sftp_attribute,
    is_admin_external,
    parse_command_options,
    resolve_domain_admin,
    resolve_script_creds,
    set_sftp_uid,
    set_user_record_uid
)
from ..base import Command
from ..ksm import KSMCommand
from ..pam import gateway_helper
from ..pam.config_helper import pam_configurations_get_all
from ..recordv3 import RecordAddCommand
from ..record_edit import RecordUploadAttachmentCommand
from ..tunnel.port_forward.TunnelGraph import TunnelDAG
from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens
from ... import api, crypto, utils, vault, record_management
from ...display import bcolors
from ...error import CommandError
from ...importer import imp_exp
from ...importer.importer import SharedFolder, Permission
from ...keeper_dag import EdgeType
from ...params import LAST_FOLDER_UID, LAST_SHARED_FOLDER_UID
from ...proto import record_pb2, APIRequest_pb2, enterprise_pb2
from ...recordv3 import RecordV3
from ...subfolder import BaseFolderNode


class PAMProjectImportCommand(Command):
    parser = argparse.ArgumentParser(prog="pam project import")
    parser.add_argument("--name", "-n", required=False, dest="project_name", action="store", help="Project name.")
    parser.add_argument("--filename", "-f", required=False, dest="file_name", action="store", help="File to load import data from.")
    parser.add_argument("--dry-run", "-d", required=False, dest="dry_run", action="store_true", default=False, help="Test import without modifying vault.")
    parser.add_argument("--sample-data", "-s", required=False, dest="sample_data", action="store_true", default=False, help="Generate sample data.")
    parser.add_argument("--show-template", "-t", required=False, dest="show_template", action="store_true", default=False, help="Print JSON template required for manual import.")
    # parser.add_argument("--force", "-e", required=False, dest="force", action="store_true", default=False, help="Force data import (re/configure later)")
    parser.add_argument("--output", "-o", required=False, dest="output", action="store", choices=["token", "base64", "json"], default="base64", help="Output format (token: one-time token, config: base64/json)")

    def get_parser(self):
        return PAMProjectImportCommand.parser

    def get_extra_args(self, excluded, **kwargs):
        # Get long option name from variable name
        def get_option_name(var_name):
            for action in self.parser._actions:
                if var_name in action.dest:  # Check if variable matches destination name
                    if action.option_strings and isinstance(action.option_strings, list):
                        return action.option_strings[0]  # Prefer long name
            return var_name

        excluded = [excluded] if isinstance(excluded, str) else excluded
        excluded = [] if not isinstance(excluded, list) else excluded

        args, _ = self.parser.parse_known_args()
        args = vars(args)  # default values here - get actual from kwargs
        extras = [f"{get_option_name(key)}={kwargs.get(key, value)}" 
                  for i, (key, value) in enumerate(args.items())
                  if key not in excluded and kwargs.get(key, value) != value]
        return extras

    def execute(self, params, **kwargs):
        # Create objects in following order:
        # Shared Folder, KSM Application, Gateway/Controller,
        # PAM Configuration, Records or Examples (if needed).

        project = {"options": {}, "data": {}, "folders": {}, "ksm_app": {}, "gateway": {}, "pam_config": {}}
        project["options"]["project_name"] = kwargs.get("project_name", "") or ""
        project["options"]["file_name"] = kwargs.get("file_name", "") or ""
        project["options"]["dry_run"] = kwargs.get("dry_run", False)
        project["options"]["sample_data"] = kwargs.get("sample_data", False)
        project["options"]["show_template"] = kwargs.get("show_template", False)
        project["options"]["force"] = kwargs.get("force", False)
        project["options"]["output"] = kwargs.get("output", "") or ""

        # --show-template|-t is highest priority
        if project["options"]["show_template"] is True:
            print(PROJECT_IMPORT_JSON_TEMPLATE)
            extra = self.get_extra_args(["show_template"], **kwargs)
            if extra: 
                logging.warning(f"{bcolors.WARNING}Warning: --show-template|-t overrides all other options {extra}{bcolors.ENDC}")
            return

        # --sample-data|-s is highest priority after --show-template|-t
        # and resets all other options (--show-template|-t is already processed)
        if project["options"]["sample_data"] is True:
            if not project["options"]["project_name"]:
                project["options"]["project_name"] = "Discovery Playground"
            project["options"]["file_name"] = ""
            # project["options"]["dry_run"] = False  # dry-run is allowed
            extra = self.get_extra_args(["sample_data", "dry_run"], **kwargs)
            if extra: 
                logging.warning(f"{bcolors.WARNING}Warning: --sample-data|-s overrides other options {extra}{bcolors.ENDC}")

        if project["options"]["sample_data"] is False:
            if project["options"]["file_name"] == "":
                print("the following arguments are required: --filename/-f")
                return

            if project["options"]["file_name"] != "" and os.path.isfile(project["options"]["file_name"]):
                with open(project["options"]["file_name"], encoding="utf-8") as f:
                    project["data"] = json.load(f)

        # Verify min required entries - project name, etc.
        # Project name from command line overrides project name from JSON file
        # to allow importing same JSON multiple times - creating different projects
        if project["options"]["project_name"] == "":
            project["options"]["project_name"] = project["data"].get("project", "") or ""
        if project["options"]["project_name"] == "":
            logging.warning(f"{bcolors.FAIL}Project name is required{bcolors.ENDC} - ex. "
                            f"""command-line option: {bcolors.OKBLUE}--name="Project 1"{bcolors.ENDC} or """
                            f"""JSON property: {bcolors.OKGREEN}"project"{bcolors.ENDC}: "Project 1" """)
            return

        if project["options"].get("dry_run", False) is True:
            print("[DRY RUN] No changes will be made. This is a simulation only.")

        # 1. Create Shared Folder for the Project (incl. parent folders)
        api.sync_down(params)
        project["folders"] = self.process_folders(params, project)

        # 2. Create KSM Application
        project["ksm_app"] = self.process_ksm_app(params, project)

        # 3. Create Gateway/Controller
        project["gateway"] = self.process_gateway(params, project)

        # Create PAM Configuration
        project["pam_config"] = self.process_pam_config(params, project)

        # 5. Create Examples (if needed)
        project["options"]["sample_data"] = project["options"]["sample_data"] or project["data"].get("options", {}).get("generate_sample_data", False) or False
        if project["options"]["sample_data"] == True:
            self.generate_sample_data(params, project)
        else:
            self.process_data(params, project)

        if project["options"].get("dry_run", False) is True:
            print("[DRY RUN COMPLETE] No changes were made. All actions were validated but not executed.")
            return

        res = {
            "access_token": project["gateway"].get("gateway_token", ""),
            "device_uid": project["gateway"].get("gateway_uid", ""),
            "shared_folder_resources_uid": project["folders"].get("resources_folder_uid", ""),
            "shared_folder_users_uid": project["folders"].get("users_folder_uid", ""),
            "note": "Ensure that the team or users have role permission to access connections or tunnels"
        }
        print(json.dumps(res, indent=2))
        print("Follow the official Keeper documentation on how to use "
              "the access_token during a Gateway install or reconfiguration: "
              "https://docs.keeper.io/en/keeperpam/privileged-access-manager/getting-started/gateways")

    PAM_ROOT_FOLDER_NAME = "PAM Environments"

    def process_folders(self, params, project: dict) -> dict:
        res = {
            "root_folder_target": self.PAM_ROOT_FOLDER_NAME,
            "root_folder": "",
            "root_folder_uid": "",
            "project_folder_target": project["options"]["project_name"],
            "project_folder": "",
            "project_folder_uid": "",
            "resources_folder": f"""{project["options"]["project_name"]} - Resources""",
            "resources_folder_uid": "",
            "users_folder": f"""{project["options"]["project_name"]} - Users""",
            "users_folder_uid": ""
        }

        # Project structure:
        # PAM Environments > Project 1 (shared) > Resources - All except PAMUser: Machine, DB, Directory, Browser
        # PAM Environments > Project 1 (shared) > Users - PAMUser ONLY: All other types go into Resources

        # if project["data"].get("tool_version", "") != "": # CLI generated export else: # Manually generated import file

        # FolderListCommand().execute(params, folders_only=True, pattern="/")
        folders = self.find_folders(params, "", res["root_folder_target"], False)
        if folders:
            # select first non-root non-shared sub/folder
            folders = [x for x in folders if x.type == x.UserFolderType]
            if len(folders) > 1:
                logging.warning(f"""Multiple user folders ({len(folders)}) match folder name "{res["root_folder_target"]}" """
                                f" using first match with UID: {bcolors.OKGREEN}{folders[0].uid}{bcolors.ENDC}")
                folders = folders[:1]
        res["root_folder"] = res["root_folder_target"]
        if folders:
            res["root_folder_uid"] = str(folders[0].uid)
        elif project["options"].get("dry_run", False) is not True:
            # FolderMakeCommand().execute(params, user_folder=True, folder=f"""/{res["root_folder_target"]}""")
            fuid = self.create_subfolder(params, res["root_folder_target"])
            res["root_folder_uid"] = fuid

        # find available project folder - incr. numeric suffix until distinct name found
        res["project_folder"] = res["project_folder_target"]
        if res["root_folder_uid"]:
            START_INDEX: int = 1
            n: int = START_INDEX
            while True:
                folder_name = res["project_folder_target"] if n <= START_INDEX else f"""{res["project_folder_target"]} #{n}"""
                folders = self.find_folders(params, res["root_folder_uid"], folder_name, False)
                folders = [x for x in folders if x.type == x.UserFolderType]
                n += 1
                if len(folders) > 0:
                    continue
                res["project_folder"] = folder_name
                if project["options"].get("dry_run", False) is not True:
                    # FolderMakeCommand().execute(params, shared_folder=True, folder=f"""/{res["root_folder"]}/{res["project_folder"]}""")
                    fuid = self.create_subfolder(params, folder_name=res["project_folder"], parent_uid=res["root_folder_uid"])
                    res["project_folder_uid"] = fuid

                    puid = res["project_folder_uid"]
                    sfn = project["data"].get("shared_folder_resources", None)
                    fname = sfn["folder_name"] if isinstance(sfn, dict) and isinstance(sfn.get("folder_name", None), str) else ""
                    fname = fname.strip() or f"""{res["project_folder"]} - Resources"""
                    fperm, rperm = self.get_folder_permissions(users_folder=False, data=project["data"])
                    fuid = self.create_subfolder(params, folder_name=fname, parent_uid=puid, permissions=fperm)
                    res["resources_folder_uid"] = fuid

                    sfn = project["data"].get("shared_folder_users", None)
                    fname = sfn["folder_name"] if isinstance(sfn, dict) and isinstance(sfn.get("folder_name", None), str) else ""
                    fname = fname.strip() or f"""{res["project_folder"]} - Users"""
                    fperm, uperm = self.get_folder_permissions(users_folder=True, data=project["data"])
                    fuid = self.create_subfolder(params, folder_name=fname, parent_uid=puid, permissions=fperm)
                    res["users_folder_uid"] = fuid

                    # add users and teams
                    self.verify_users_and_teams(params, rperm + uperm)
                    self.add_folder_permissions(params, res["resources_folder_uid"], rperm)
                    self.add_folder_permissions(params, res["users_folder_uid"], uperm)
                break

        if project["options"].get("dry_run", False) is True:
            if res["root_folder_uid"]:
                print(f"""Will use existing PAM root folder: {res["root_folder_uid"]} {res["root_folder"]}""")
            else:
                print(f"""Will create new PAM root folder: {res["root_folder_target"]}""")
            print(f"""Will create new Project folder: {res["project_folder"]}""")
        else:
            api.sync_down(params)

        return res

    def process_ksm_app(self, params, project: dict) -> dict:
        res = {
            "app_name_target": "",
            "app_name": "",
            "app_uid": ""
        }

        res["app_name_target"] = self.get_property(project["data"], "pam_configuration", "ksm_app_name", "")
        if not res["app_name_target"]:
            res["app_name_target"] = project["options"]["project_name"] + " Application"

        # Get KSM App names list
        app_titles = set()
        rs = api.communicate_rest(params, None, "vault/get_applications_summary",
                                  rs_type=APIRequest_pb2.GetApplicationsSummaryResponse)  # pylint: disable=E1101
        if isinstance(rs, APIRequest_pb2.GetApplicationsSummaryResponse):  # pylint: disable=E1101
            for x in rs.applicationSummary:  # type: ignore
                app_record = vault.KeeperRecord.load(params, utils.base64_url_encode(x.appRecordUid))
                if isinstance(app_record, vault.ApplicationRecord):
                    app_titles.add(app_record.title)

        # Find unique KSM App Name
        n = 1
        app_name = res["app_name_target"]
        while app_name in app_titles:
            n += 1
            app_name = f"""{res["app_name_target"]} #{n}"""
        res["app_name"] = app_name

        if project["options"].get("dry_run", False) is True:
            print(f"""Will create new KSM application: {res["app_name"]}""")
            return res

        # Create KSM App
        res["app_uid"] = self.create_ksm_app(params, res["app_name"])
        for sf_uid in [project["folders"].get("resources_folder_uid", ""),
                       project["folders"].get("users_folder_uid", "")]:
            if sf_uid.strip():
                KSMCommand().execute(params,
                                     command=("secret", "add"),
                                     app=res["app_uid"],
                                     secret=[sf_uid], editable=True)

        api.sync_down(params)
        return res

    def process_gateway(self, params, project: dict) -> dict:
        res = {
            "gateway_name_target": "",
            "gateway_name": "",
            "gateway_token": "",  # one-time token or config-b64
            "gateway_device_token": "",
            "gateway_uid": ""
        }

        res["gateway_name_target"] = self.get_property(project["data"], "pam_configuration", "gateway_name", "")
        if not res["gateway_name_target"]:
            res["gateway_name_target"] = project["options"]["project_name"] + " Gateway"

        # Find unique Gateway name
        n = 1
        gws = gateway_helper.get_all_gateways(params)
        gw_names = [x.controllerName for x in gws]
        gw_name = res["gateway_name_target"]
        while gw_name in gw_names:
            n += 1
            gw_name = f"""{res["gateway_name_target"]} #{n}"""
        res["gateway_name"] = gw_name

        if project["options"].get("dry_run", False) is True:
            print(f"""Will create new Gateway: {res["gateway_name"]}""")
            return res

        # Create new Gateway - PAMCreateGatewayCommand()
        token_format = None if project["options"]["output"] == "token" else "b64"
        ksm_app_uid = project["ksm_app"]["app_uid"]
        gw = self.create_gateway(
            params,
            gateway_name=res["gateway_name"],
            ksm_app=ksm_app_uid,
            config_init=token_format)

        if token_format is None:
            res["gateway_token"] = gw[0].get("oneTimeToken", "") if gw and gw_names else ""  # OTT
        else:
            res["gateway_token"] = gw[0].get("config", "") if gw and gw_names else ""  # Config
            if project["options"]["output"] == "json":
                res["gateway_token"] = json.loads(utils.base64_url_decode(res["gateway_token"]))
        res["gateway_device_token"] = gw[0].get("deviceToken", "") if gw and gw_names else ""

        # controller_uid is not returned by vault/app_client_add
        gws = gateway_helper.get_all_gateways(params)
        gw_names = [x.controllerUid for x in gws if x.deviceToken == res["gateway_device_token"]]
        res["gateway_uid"] = utils.base64_url_encode(gw_names[0]) if gw_names else ""
        # gateway_helper.remove_gateway(params, utils.base64_url_decode(res["gateway_uid"]))

        api.sync_down(params)
        return res

    def process_pam_config(self, params, project: dict) -> dict:
        from ..discoveryrotation import PAMConfigurationNewCommand
        res:Dict[str, Any] = {
            "pam_config_name_target": "",
            "pam_config_name": "",
            "pam_config_uid": ""
        }

        res["pam_config_name_target"] = self.get_property(project["data"], "pam_configuration", "title", "")
        if not res["pam_config_name_target"]:
            res["pam_config_name_target"] = project["options"]["project_name"] + " Configuration"

        # Find unique PAM Configuration name
        n = 1
        pams = pam_configurations_get_all(params)
        pam_names = [json.loads(x.get("data_unencrypted", "{}")).get("title", "") for x in pams]
        pam_name = res["pam_config_name_target"]
        while pam_name in pam_names:
            n += 1
            pam_name = f"""{res["pam_config_name_target"]} #{n}"""
        res["pam_config_name"] = pam_name

        if project["options"].get("dry_run", False) is True:
            print(f"""Will create new PAM Configuration: {res["pam_config_name"]}""")
            return res

        # Create new PAM Configuration/Environment: PamConfigEnvironment
        args = {
            "gateway": project["gateway"].get("gateway_uid", ""),
            "gateway_uid": project["gateway"].get("gateway_uid", ""),
            "shared_folder_uid": project["folders"].get("users_folder_uid", "")
        }
        pam_cfg = project["data"].get("pam_configuration", {})
        pce = PamConfigEnvironment("", pam_cfg, args["gateway_uid"], args["shared_folder_uid"])
        pce.title = res["pam_config_name"]  # adjusted title
        if project["options"].get("sample_data", False):
            # -s | --sample-data option overrides json data
            args.update({
                "config_type": "local",
                "environment": "local",
                "title": res["pam_config_name"],
                "port_mapping": ["2222=ssh"],
                # "network_cidr": "192.168.1.0/24",
                "network_id": "discovery-net",
                "connections": "on",
                "tunneling": "on",
                "rotation": "on",
                "remotebrowserisolation": "on",
                "recording": "on",
                "typescriptrecording": "on",
                "ai_threat_detection": "off",
                "ai_terminate_session_on_detection": "off"
            })
        else:
            if pce.port_mapping: args["port_mapping"] = pce.port_mapping
            args.update({
                "config_type": pce.environment,
                "environment": pce.environment,
                "title": pce.title,
                "connections": pce.connections,
                "tunneling": pce.tunneling,
                "rotation": pce.rotation,
                "remotebrowserisolation": pce.remote_browser_isolation,
                "recording": pce.graphical_session_recording,
                "typescriptrecording": pce.text_session_recording,
                "ai_threat_detection": pce.ai_threat_detection,
                "ai_terminate_session_on_detection": pce.ai_terminate_session_on_detection
            })

            if pce.environment == "local":
                if pce.network_cidr: args["network_cidr"] = pce.network_cidr
                if pce.network_id: args["network_id"] = pce.network_id
            elif pce.environment == "aws":
                if pce.aws_id: args["aws_id"] = pce.aws_id
                if pce.aws_access_key_id: args["access_key_id"] = pce.aws_access_key_id
                if pce.aws_secret_access_key: args["access_secret_key"] = pce.aws_secret_access_key
                if pce.aws_region_names: args["region_names"] = pce.aws_region_names
            elif pce.environment == "azure":
                if pce.az_entra_id: args["azure_id"] = pce.az_entra_id
                if pce.az_client_id: args["client_id"] = pce.az_client_id
                if pce.az_client_secret: args["client_secret"] = pce.az_client_secret
                if pce.az_subscription_id: args["subscription_id"] = pce.az_subscription_id
                if pce.az_tenant_id: args["tenant_id"] = pce.az_tenant_id
                if pce.az_resource_groups: args["resource_groups"] = pce.az_resource_groups
            elif pce.environment == "domain":
                if pce.dom_domain_id: args["domain_id"] = pce.dom_domain_id
                if pce.dom_hostname: args["domain_hostname"] = pce.dom_hostname
                if pce.dom_port: args["domain_port"] = pce.dom_port
                if pce.dom_use_ssl is not None: args["domain_use_ssl"] = pce.dom_use_ssl
                if pce.dom_scan_dc_cidr is not None: args["domain_scan_dc_cidr"] = pce.dom_scan_dc_cidr
                if pce.dom_network_cidr: args["domain_network_cidr"] = pce.dom_network_cidr
                if pce.admin_credential_ref:
                    args["domain_administrative_credential"] = pce.admin_credential_ref
                    args["force_domain_admin"] = True  # add now - ACL link later
                if pce.dom_administrative_credential:  # to be resolved later
                    res["pam_config_object"] = pce
            elif pce.environment == "gcp":
                if pce.gcp_id: args["gcp_id"] = pce.gcp_id
                if pce.gcp_service_account_key: args["service_account_key"] = pce.gcp_service_account_key
                if pce.gcp_google_admin_email: args["google_admin_email"] = pce.gcp_google_admin_email
                if pce.gcp_region_names: args["region_names"] = pce.gcp_region_names
            elif pce.environment == "oci":
                if pce.oci_id: args["oci_id"] = pce.oci_id
                if pce.oci_admin_id: args["oci_admin_id"] = pce.oci_admin_id
                if pce.oci_admin_public_key: args["oci_admin_public_key"] = pce.oci_admin_public_key
                if pce.oci_admin_private_key: args["oci_admin_private_key"] = pce.oci_admin_private_key
                if pce.oci_tenancy: args["oci_tenancy"] = pce.oci_tenancy
                if pce.oci_region: args["oci_region"] = pce.oci_region

            if pce.default_rotation_schedule: args["default_schedule"] = pce.default_rotation_schedule

        res["pam_config_uid"] = PAMConfigurationNewCommand().execute(params, **args)
        api.sync_down(params)

        # add scripts and attachments after record create
        if pce.attachments:
            files = [x.file for x in pce.attachments.attachments if x.file]
            if files:
                ruac = RecordUploadAttachmentCommand()
                ruac.execute(params, record=res["pam_config_uid"], file=files)
        if pce.scripts:
            no_admin_creds = [x for x in pce.scripts.scripts if not x.additional_credentials]
            if no_admin_creds:
                api.sync_down(params)
                add_pam_scripts(params, res["pam_config_uid"], no_admin_creds)
            # if additional_credentials present - wait for UIDs...
            if any(x.additional_credentials for x in pce.scripts.scripts):
                res["pam_config_object"] = pce

        return res

    def generate_sample_data(self, params, project: dict):
        if project["options"].get("dry_run", False) is True:
            print("Will generate sample data here...")
            return

        # self.generate_simple_content_data(params, project)
        self.generate_discovery_playground_data(params, project)

    def generate_discovery_playground_data(self, params, project: dict):
        """ Generate data that works with discovery-playground docker setup """
        from ..tunnel_and_connections import PAMTunnelEditCommand
        from ..discoveryrotation import PAMCreateRecordRotationCommand

        # PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC0bH13XfBiKcej3/W"\
        # "mnc7GYbx+B+hmfYTaDFqfJ/vEGy3HTSz2t5nDb3+S1clBcCmse5FzEA7aXC3cZXurGBH"\
        # "irz2Ud8wCL2t95cJnrkzfft7lsILnchm0J0Y0TyDW42gLj1JWh/E5qQyUxF0F6xEBKcy"\
        # "5cYwlgtkBcrkF1xdpuTKTMBg+xjB9XSlvLv+4rwZ448tvyILuw4DcIZDWjNxn1v+a/43"\
        # "ybhUNjGdd6zeR1ZdfB6O209VU1V0zTNS/jGsKPDK03vmJ1j42S/ZyNZ16CKDmsixhSVI"\
        # "aZ+qNOQx4eF6l/cavX+LAm94jPFZSsjr3BdE6jOZhJN+XWBmIpYd9 linuxuser@local"

        PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\\n"\
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\\n"\
        "NhAAAAAwEAAQAAAQEAtGx9d13wYinHo9/1pp3OxmG8fgfoZn2E2gxanyf7xBstx00s9reZ\\n"\
        "w29/ktXJQXAprHuRcxAO2lwt3GV7qxgR4q89lHfMAi9rfeXCZ65M337e5bCC53IZtCdGNE\\n"\
        "8g1uNoC49SVofxOakMlMRdBesRASnMuXGMJYLZAXK5BdcXabkykzAYPsYwfV0pby7/uK8G\\n"\
        "eOPLb8iC7sOA3CGQ1ozcZ9b/mv+N8m4VDYxnXes3kdWXXwejttPVVNVdM0zUv4xrCjwytN\\n"\
        "75idY+Nkv2cjWdegig5rIsYUlSGmfqjTkMeHhepf3Gr1/iwJveIzxWUrI69wXROozmYSTf\\n"\
        "l1gZiKWHfQAAA8j5NtJt+TbSbQAAAAdzc2gtcnNhAAABAQC0bH13XfBiKcej3/Wmnc7GYb\\n"\
        "x+B+hmfYTaDFqfJ/vEGy3HTSz2t5nDb3+S1clBcCmse5FzEA7aXC3cZXurGBHirz2Ud8wC\\n"\
        "L2t95cJnrkzfft7lsILnchm0J0Y0TyDW42gLj1JWh/E5qQyUxF0F6xEBKcy5cYwlgtkBcr\\n"\
        "kF1xdpuTKTMBg+xjB9XSlvLv+4rwZ448tvyILuw4DcIZDWjNxn1v+a/43ybhUNjGdd6zeR\\n"\
        "1ZdfB6O209VU1V0zTNS/jGsKPDK03vmJ1j42S/ZyNZ16CKDmsixhSVIaZ+qNOQx4eF6l/c\\n"\
        "avX+LAm94jPFZSsjr3BdE6jOZhJN+XWBmIpYd9AAAAAwEAAQAAAQAEs0DV5iOxgviGKEfC\\n"\
        "syC9+7GiSa8M7UWTop4nwEearvSTcrGME3HIU035AGQrHFkEx8rpuvTc5mlBcRlc9mMQGA\\n"\
        "c1wdf8N8nU/UvO6w3Qn4IyBjx0YbB4VRkxZ3a2pZtbyO+MFopUhlCWfY98BhXEa7DY8ebR\\n"\
        "p798fkWCRYpNtDyja2m0zrFo6Kp0PusmAXWnu5z4SLgpdNKIaz+6AX+vQpv2QTTpunzGUr\\n"\
        "XvhlLpLhK5sOPhR88VuddNKJFZi7SzNUC3DW66NdtU8jVeTKOgOB8fdvzwkX5AgAFpj/cr\\n"\
        "MmbS5GpkrKpVjkWXfTxAit+S1Ykg/ay6po4y8s9RHjsxAAAAgQCPof49LmwUJuBiheAklQ\\n"\
        "fcxCv4CnGvT926FueqADuN2g85R8EjOQ7qB0xtZckIflyqMnCVEiA9D6m8LUtEAmB9nC2x\\n"\
        "5Iz+uNByfadxthAgQXBc1qCm8Q0CCwKGE4LzshugdJap5d4i5sOM8pvNb9lo81LjXjzBw9\\n"\
        "3aNR5cPxH1uwAAAIEA8An6rWHpq494jjWdbyKI65qgBAIuIHTGxhonze5q0mYQSkor9R3k\\n"\
        "0w1ZPzOI8U78qpzGmL7hKa5QT5SOYsTffb8ofYTky0Agbqo1Ax8JK4+JytC8u6Pjc4G1U/\\n"\
        "3Njxu2aPT0xEsIxdVdDqT0sbrY3Cmn2PPr1MWM2xYb/PS2l2UAAACBAMBruM9OswMXmJ6/\\n"\
        "MClr0X9JfqWSNMKvOEYnoCmroGnjNBbf+66U9a6ecDSXNF8EMCG1pDSVHwtTIb2vUUEnwW\\n"\
        "MxQ33Xl8pUHmP94FqD8wrhZta/YRWzPeQs6LOBGoAFoSJBhALIhjlj48HW1TqtAJ+TuiGU\\n"\
        "4nTd/dKHHH5aNmo5AAAAD2xpbnV4dXNlckBsb2NhbAECAw==\\n"\
        "-----END OPENSSH PRIVATE KEY-----"

        project_name = project["options"]["project_name"]
        users_folder_uid = project["folders"]["users_folder_uid"]
        resources_folder_uid = project["folders"]["resources_folder_uid"]
        pam_config_uid = project["pam_config"]["pam_config_uid"]

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_config_uid, True,
                         transmission_key=transmission_key)
        # if not tdag.check_tunneling_enabled_config(enable_connections=True):
        #     logging.warning(f"{bcolors.WARNING}Warning: {bcolors.ENDC} Connections are disabled by PAM Configuration!")
        # Fix: Rotation is disabled by the PAM configuration.
        tdag.set_resource_allowed(pam_config_uid, is_config=True, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)

        command = RecordAddCommand()
        pte = PAMTunnelEditCommand()

        # when NOOP rotation is added to PAMCreateRecordRotationCommand...
        # # create_noop_rotation_records
        # json_data = """{
        #     "type": "pamUser",
        #     "title": "#project_name# - NOOP Rotation User",
        #     "fields": [
        #         {"type": "login", "required": true, "value": ["noop"]},
        #         {"type": "password", "value": ["noop"]}
        #     ],
        #     "custom": [
        #         {"type": "text", "label": "NOOP", "value": [ "True" ] }
        #     ]}""".replace("#project_name#", project_name)
        # #       {"type": "script", "label": "rotationScripts", "value": [
        # #           {
        # #               "command": "pwsh.exe",
        # #               "fileRef": "D:/Download/00params.ps1",
        # #               "recordRef": []
        # #           },
        # #           {
        # #               "command": "cmd.exe",
        # #               "fileRef": "D:/Download/00params.bat",
        # #               "recordRef": []
        # #           }
        # #       ]}
        # rotation_user_uid = command.execute(params, folder = users_folder_uid, data = json_data)
        # # TO: Extract scripts from JSON: remove from record data and add after record creation
        # # NB! add_credential must be empty - NOOP records do not need additional resources
        # # RRC_BAD_REQUEST - Noop and resource cannot be both assigned
        # PAMScriptAddCommand().execute(params, record=rotation_user_uid, script="D:/Download/00params.ps1", script_command="pwsh.exe", add_credential="")
        # PAMScriptAddCommand().execute(params, record=rotation_user_uid, script="D:/Download/00params.bat", script_command="cmd.exe", add_credential="")
        # tdag.set_resource_allowed(pam_config_uid, is_config=True, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)
        # tdag.link_resource_to_config(rotation_user_uid)
        # api.sync_down(params)
        # PAMCreateRecordRotationCommand().execute(params, record_name=rotation_user_uid,
        #                                          config=pam_config_uid, noop=True,
        #                                          on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)

        # create_mysql_records
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - MySQL Admin User",
            "fields": [
                {"type": "login", "required": true, "value": ["root"]},
                {"type": "password", "value": ["z@ggz?y|w#I_NFCW!41"]}
            ]}""".replace("#project_name#", project_name)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - MySQL Rotation User",
            "fields": [
                {"type": "login", "required": true, "value": ["sqluser"]},
                {"type": "password", "value": ["alpine"]}
            ]}""".replace("#project_name#", project_name)
        # ,"custom": [{"type": "text", "label": "NOOP", "value": [ "True" ] }]
        rotation_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamDatabase",
            "title": "#project_name# - MySQL Database",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "db-mysql-1","port": "3306"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "mysql",
                        "database": "salesdb",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        database_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)

        # Database Machine -> Config -> Enable connections/portForwards/set trafficEncryptionSeed
        tdag.link_resource_to_config(database_machine_uid)
        pte.execute(params, record=database_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        tdag.set_resource_allowed(resource_uid=database_machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)

        # bugfix: Apparently PAMCreateRecordRotationCommand do not create the links
        # Links: User -> Database Machine
        tdag.link_user_to_resource(admin_user_uid, database_machine_uid, True, True)
        tdag.link_user_to_resource(rotation_user_uid, database_machine_uid, False, True)
        # PAMCreateRecordRotationCommand().execute(params, record_name=admin_user_uid,admin=admin_user_uid,config=pam_config_uid, resource=database_machine_uid,on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)
        PAMCreateRecordRotationCommand().execute(params, record_name=rotation_user_uid,
                                                 admin=admin_user_uid,
                                                 config=pam_config_uid, resource=database_machine_uid,
                                                 on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)

        # create_ssh_with_password_records
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - SSH Admin with Password",
            "fields": [
                {"type": "login", "required": true, "value": ["linuxuser"]},
                {"type": "password", "value": ["alpine"]}
            ]}""".replace("#project_name#", project_name)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamMachine",
            "title": "#project_name# - SSH Machine with Password Access",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "server-ssh-with-pwd-1","port": "2222"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "ssh",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        ssh_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)

        # Machine -> Config -> Enable connections/portForwards/set trafficEncryptionSeed
        tdag.link_resource_to_config(ssh_machine_uid)
        pte.execute(params, record=ssh_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        # if tdag.check_if_resource_allowed(ssh_machine_uid, "connections") != True:
        tdag.set_resource_allowed(resource_uid=ssh_machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)

        # Admin User -> Machine; Admin User -> Rotation
        tdag.link_user_to_resource(admin_user_uid, ssh_machine_uid, True, True)
        PAMCreateRecordRotationCommand().execute(params, record_name=admin_user_uid,
                                                 admin=admin_user_uid,
                                                 config=pam_config_uid, resource=ssh_machine_uid,
                                                 on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)

        # create_ssh_with_private_key_records
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - SSH Admin with Private Key",
            "fields": [
                {"type": "login", "required": true, "value": ["linuxuser"]},
                {"type": "password", "value": []},
                {"type": "secret", "label": "privatePEMKey", "value": ["#private_key#"]}
            ]}""".replace("#project_name#", project_name).replace("#private_key#", PRIVATE_KEY)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamMachine",
            "title": "#project_name# - SSH Machine with Private Key Access",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "server-ssh-with-key-1","port": "2222"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "ssh",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        ssh_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)

        # Machine -> Config -> Enable connections/portForwards/set trafficEncryptionSeed
        tdag.link_resource_to_config(ssh_machine_uid)
        pte.execute(params, record=ssh_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        tdag.set_resource_allowed(resource_uid=ssh_machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)

        # Admin User -> Machine; Admin User -> Rotation
        tdag.link_user_to_resource(admin_user_uid, ssh_machine_uid, True, True)
        PAMCreateRecordRotationCommand().execute(params, record_name=admin_user_uid,
                                                 admin=admin_user_uid,
                                                 config=pam_config_uid, resource=ssh_machine_uid,
                                                 on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)

        # create_vnc_records
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - VNC Admin",
            "fields": [
                {"type": "login", "required": true, "value": ["vncuser"]},
                {"type": "password", "value": ["alpine"]}
            ]}""".replace("#project_name#", project_name)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamMachine",
            "title": "#project_name# - VNC Machine",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "server-vnc","port": "5901"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "vnc",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)

        # Machine -> Config -> Enable connections/portForwards/set trafficEncryptionSeed
        tdag.link_resource_to_config(machine_uid)
        pte.execute(params, record=machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        tdag.set_resource_allowed(resource_uid=machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)

        # Admin User -> Machine; Admin User
        tdag.link_user_to_resource(admin_user_uid, machine_uid, True, True)

        # create_rdp_records
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - RDP User",
            "fields": [
                {"type": "login", "required": true, "value": ["linuxuser"]},
                {"type": "password", "value": ["alpine"]}
            ]}""".replace("#project_name#", project_name)
        user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - RDP Admin",
            "fields": [
                {"type": "login", "required": true, "value": ["root"]},
                {"type": "password", "value": ["rootpassword"]}
            ]}""".replace("#project_name#", project_name)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamMachine",
            "title": "#project_name# - RDP Machine",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "server-rdp","port": "3389"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "rdp",
                        "security": "any",
                        "ignoreCert": true,
                        "resizeMethod": "display-update",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)

        # Machine -> Config -> Enable connections/portForwards/set trafficEncryptionSeed
        tdag.link_resource_to_config(machine_uid)
        pte.execute(params, record=machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        tdag.set_resource_allowed(resource_uid=machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)

        # Admin User -> Machine; User -> Machine
        tdag.link_user_to_resource(admin_user_uid, machine_uid, True, True)
        tdag.link_user_to_resource(user_uid, machine_uid, False, True)

        # create_rbi_record
        json_data = """{
            "type": "pamRemoteBrowser",
            "title": "#project_name# - Bing Remote Browser",
            "fields": [
                {"type": "rbiUrl", "required": true, "value": ["https://bing.com"]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "pamRemoteBrowserSettings", "value": [{
                    "connection": {
                        "protocol": "http",
                        "allowUrlManipulation": true,
                        "userRecords": []
                    }
                }]}
            ]}""".replace("#project_name#", project_name)
        rbi_uid = command.execute(params, folder=resources_folder_uid, data=json_data)
        tdag.link_resource_to_config(rbi_uid)
        pte.execute(params, record=rbi_uid, config=pam_config_uid,
                    enable_rotation=False, enable_connections=True, enable_tunneling=False,
                    enable_typescripts_recording=False, enable_connections_recording=True)
        # bugfix: Edit command not always populates correctly everything
        tdag.set_resource_allowed(resource_uid=rbi_uid, rotation=False, connections=True, tunneling=False, session_recording=True, typescript_recording=False, remote_browser_isolation=True)

        # Additional discovery-playground resources: postgres, mariadb, mssql, mongodb, telnet
        # create_postgresql_records
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - PostgreSQL Admin User",
            "fields": [
                {"type": "login", "required": true, "value": ["postgres"]},
                {"type": "password", "value": ["postgres"]}
            ]}""".replace("#project_name#", project_name)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamDatabase",
            "title": "#project_name# - PostgreSQL Database",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "db-postgres-1","port": "5432"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "databaseType", "value": ["postgresql"]},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "postgresql",
                        "database": "postgresql",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        database_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)
        tdag.link_resource_to_config(database_machine_uid)
        pte.execute(params, record=database_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        tdag.set_resource_allowed(resource_uid=database_machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)
        tdag.link_user_to_resource(admin_user_uid, database_machine_uid, True, True)
        PAMCreateRecordRotationCommand().execute(params, record_name=admin_user_uid,
                                                 admin=admin_user_uid,
                                                 config=pam_config_uid, resource=database_machine_uid,
                                                 on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)

        # create_mariadb_records
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - MariaDB Admin User",
            "fields": [
                {"type": "login", "required": true, "value": ["root"]},
                {"type": "password", "value": ["z@ggz?y|w#I_NFCW!41"]}
            ]}""".replace("#project_name#", project_name)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - MariaDB Rotation User",
            "fields": [
                {"type": "login", "required": true, "value": ["max"]},
                {"type": "password", "value": ["maxpass"]}
            ]}""".replace("#project_name#", project_name)
        rotation_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamDatabase",
            "title": "#project_name# - MariaDB Database",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "db-mariadb-1","port": "3306"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "databaseType", "value": ["mariadb"]},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "mysql",
                        "database": "mydb",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        database_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)
        tdag.link_resource_to_config(database_machine_uid)
        pte.execute(params, record=database_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        tdag.set_resource_allowed(resource_uid=database_machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)
        tdag.link_user_to_resource(admin_user_uid, database_machine_uid, True, True)
        tdag.link_user_to_resource(rotation_user_uid, database_machine_uid, False, True)
        PAMCreateRecordRotationCommand().execute(params, record_name=rotation_user_uid,
                                                 admin=admin_user_uid,
                                                 config=pam_config_uid, resource=database_machine_uid,
                                                 on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)

        # create_mssql_records
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - Microsoft SQL Server Admin User",
            "fields": [
                {"type": "login", "required": true, "value": ["sa"]},
                {"type": "password", "value": ["password"]}
            ]}""".replace("#project_name#", project_name)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamDatabase",
            "title": "#project_name# - Microsoft SQL Server Database",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "db-mssql","port": "1433"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "databaseType", "value": ["mssql"]},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "sql-server",
                        "database": "master",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        database_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)
        tdag.link_resource_to_config(database_machine_uid)
        pte.execute(params, record=database_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        tdag.set_resource_allowed(resource_uid=database_machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)
        tdag.link_user_to_resource(admin_user_uid, database_machine_uid, True, True)
        PAMCreateRecordRotationCommand().execute(params, record_name=admin_user_uid,
                                                 admin=admin_user_uid,
                                                 config=pam_config_uid, resource=database_machine_uid,
                                                 on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)

        # create_mongodb_records - protocol not supported yet, so only RBI currently available
        # MongoDB Wire Protocol is a simple socket-based, request-response style protocol over TCP/IP socket
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - MongoDB Admin User",
            "fields": [
                {"type": "login", "required": true, "value": ["root"]},
                {"type": "password", "value": ["root_password"]}
            ]}""".replace("#project_name#", project_name)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - MongoDB Rotation User",
            "fields": [
                {"type": "login", "required": true, "value": ["user1"]},
                {"type": "password", "value": ["user1pwd"]}
            ]}""".replace("#project_name#", project_name)
        rotation_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamDatabase",
            "title": "#project_name# - MongoDB Database",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "db-mongo","port": "27017"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "databaseType", "value": ["mongodb"]},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "http",
                        "database": "mydatabase",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        database_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)
        tdag.link_resource_to_config(database_machine_uid)
        pte.execute(params, record=database_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        tdag.set_resource_allowed(resource_uid=database_machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)
        tdag.link_user_to_resource(admin_user_uid, database_machine_uid, True, True)
        tdag.link_user_to_resource(rotation_user_uid, database_machine_uid, False, True)
        PAMCreateRecordRotationCommand().execute(params, record_name=rotation_user_uid,
                                                 admin=admin_user_uid,
                                                 config=pam_config_uid, resource=database_machine_uid,
                                                 on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)

        # create_telnet_records
        json_data = """{
            "type": "pamUser",
            "title": "#project_name# - Telnet Admin",
            "fields": [
                {"type": "login", "required": true, "value": ["user"]},
                {"type": "password", "value": ["user1pwd"]}
            ]}""".replace("#project_name#", project_name)
        admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data)

        json_data = """{
            "type": "pamMachine",
            "title": "#project_name# - Telnet Machine",
            "fields": [
                {"type": "pamHostname", "required": true, "value": [{"hostName": "server-telnet","port": "23"}]},
                {"type": "trafficEncryptionSeed", "value": []},
                {"type": "pamSettings", "value": [{
                    "connection": {
                        "protocol": "telnet",
                        "userRecords": ["#admin_user_uid#"]
                    },
                    "portForward": { "reusePort": true }
                }]}
            ]}""".replace("#project_name#", project_name).replace("#admin_user_uid#", admin_user_uid)
        ssh_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)
        tdag.link_resource_to_config(ssh_machine_uid)
        pte.execute(params, record=ssh_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True, enable_tunneling=True)
        tdag.set_resource_allowed(resource_uid=ssh_machine_uid, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)
        tdag.link_user_to_resource(admin_user_uid, ssh_machine_uid, True, True)
        PAMCreateRecordRotationCommand().execute(params, record_name=admin_user_uid,
                                                 admin=admin_user_uid,
                                                 config=pam_config_uid, resource=ssh_machine_uid,
                                                 on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)

        api.sync_down(params)

    # def generate_simple_content_data(self, params, project: dict):
    #     """ Generate one Connection and one Tunnel """
    #     from ..tunnel_and_connections import PAMTunnelEditCommand
    #     from ..discoveryrotation import PAMCreateRecordRotationCommand
    #     users_folder_uid = project["folders"]["users_folder_uid"]
    #     command = RecordAddCommand()
    #     json_data = """{
    #         "type": "pamUser",
    #         "title": "Admin User",
    #         "fields": [{"type": "login", "value": ["administrator"]}]}"""
    #     admin_user_uid = command.execute(params, folder=users_folder_uid, data=json_data, generate=True)

    #     json_data = """{
    #         "type": "pamUser",
    #         "title": "Rotation User",
    #         "fields": [{"type": "login", "value": ["user1"]}]}"""
    #     rotation_user_uid = command.execute(params, folder=users_folder_uid, data=json_data, generate=True)

    #     resources_folder_uid = project["folders"]["resources_folder_uid"]
    #     json_data = """{
    #         "type": "pamMachine",
    #         "title": "Tunnel Machine1",
    #         "fields": [
    #             {"type": "pamHostname", "value": [{"hostName": "127.0.0.1","port": "22"}]},
    #             {"type": "trafficEncryptionSeed", "value": []},
    #             {"type": "pamSettings", "value": [{"portForward": {}}]}
    #         ]}"""

    #     port_forward_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)

    #     json_data = """{
    #         "type": "pamMachine",
    #         "title": "Connection Machine1",
    #         "fields": [
    #             {"type": "pamHostname", "value": [{"hostName": "127.0.0.1","port": "443"}]},
    #             {"type": "trafficEncryptionSeed", "value": []},
    #             {"type": "pamSettings", "value": [
    #                 {"connection":
    #                     {"protocol": "rdp", "ignore-cert": true, "security": "any", "userRecords": ["#admin_user_uid#"]}
    #                 }
    #             ]}
    #         ]}""".replace("#admin_user_uid#", admin_user_uid)
    #     connection_machine_uid = command.execute(params, folder=resources_folder_uid, data=json_data)

    #     pam_config_uid = project["pam_config"]["pam_config_uid"]
    #     encrypted_session_token, encrypted_transmission_key, _ =get_keeper_tokens(params)
    #     tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_config_uid, True)
    #     pte = PAMTunnelEditCommand()
    #     # Fix: Rotation is disabled by the PAM configuration.
    #     tdag.set_resource_allowed(pam_config_uid, is_config=True, rotation=True, connections=True, tunneling=True, session_recording=True, typescript_recording=True, remote_browser_isolation=True)

    #     # Connection Machine -> Config -> Enable Connections/set trafficEncryptionSeed
    #     tdag.link_resource_to_config(connection_machine_uid)
    #     pte.execute(params, record=connection_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_connections=True)
    #     # PortForward Machine -> Config -> Enable PortForwards/set trafficEncryptionSeed
    #     tdag.link_resource_to_config(port_forward_machine_uid)
    #     pte.execute(params, record=port_forward_machine_uid, config=pam_config_uid, admin=admin_user_uid, enable_tunneling=True)

    #     # bugfix: Apparently PAMCreateRecordRotationCommand do not create the links
    #     # Admin User -> Connection Machine
    #     tdag.link_user_to_resource(admin_user_uid, connection_machine_uid, True, True)
    #     # Rotation User -> Connection Machine
    #     tdag.link_user_to_resource(rotation_user_uid, connection_machine_uid, False, True)

    #     PAMCreateRecordRotationCommand().execute(params, record_name=rotation_user_uid,
    #                                              admin=admin_user_uid,
    #                                              config=pam_config_uid, resource=connection_machine_uid,
    #                                              on_demand=True, pwd_complexity="20,4,4,4,4", enable=True, force=True)
    #     api.sync_down(params)

    def get_folder_permissions(self, users_folder: bool, data: dict):
        folder_name = "shared_folder_users" if users_folder else "shared_folder_resources"
        uperm = []
        # defaults - used only if no permissions set at all
        fperm = { "manage_records": True, "manage_users": True,  "can_edit": True, "can_share": True }
        # fperm = { "manage_records": True, "manage_users": False, "can_edit": True, "can_share": False }

        sfu = data.get(folder_name, None)
        if isinstance(sfu, dict):
            perm = {
                "manage_users": sfu.get("manage_users", None),
                "manage_records": sfu.get("manage_records", None),
                "can_edit": sfu.get("can_edit", None),
                "can_share": sfu.get("can_share", None)
            }
            # if at least one permission is set - all default values change to False
            # i.e. any permisson not explicitly set will default to False
            changes = any(map(lambda x: x is not None, perm.values()))
            if changes:
                fperm = {
                    "manage_users": True if str(perm["manage_users"]).upper() == "TRUE" else False,
                    "manage_records": True if str(perm["manage_records"]).upper() == "TRUE" else False,
                    "can_edit": True if str(perm["can_edit"]).upper() == "TRUE" else False,
                    "can_share": True if str(perm["can_share"]).upper() == "TRUE" else False
                }

            perms = sfu.get("permissions", [])
            if isinstance(perms, list):
                for item in perms:
                    if isinstance(item, dict):
                        uid = item.get("uid", None)
                        name = item.get("name", None)
                        manage_users = True if str(item.get("manage_users", None)).upper() == "TRUE" else False
                        manage_records = True if str(item.get("manage_records", None)).upper() == "TRUE" else False
                        if uid is None and name is None:
                            logging.warning("Incorrect permissions - both (team) uid and (user) name cannot be empty (skipped)")
                        else:
                            uperm.append({"uid": uid, "name": name, "manage_users": manage_users, "manage_records": manage_records})
        return fperm, uperm

    def add_folder_permissions(self, params, folder_uid: str, permissions: list):
        if permissions:
            shf = SharedFolder()
            shf.uid = folder_uid # type: ignore
            shf.path = imp_exp.get_folder_path(params, folder_uid) # type: ignore
            shf.permissions = []
            for perm in permissions:
                if any(map(lambda x: x is not None, perm.values())):
                    p = Permission()
                    p.uid = perm.get("uid", None)
                    p.name = perm.get("name", None)
                    p.manage_users = perm.get("manage_users", None)
                    p.manage_records = perm.get("manage_records", None)
                    shf.permissions.append(p)
            imp_exp.import_user_permissions(params, [shf], full_sync=True)

            # # Do not use ShareFolderCommand - Legacy: 1) add user to folder /uses defaults only/ 2) grant 3) revoke
            # # ShareFolderCommand will automatically resolve uid, username or team
            # args = { "folder": folder_uid, "force": True, "user": [user] }
            # ShareFolderCommand().execute(params, **args)
            # api.sync_down(params)

            # # these merge with folder defaults (skipped/False may still default to True)
            # # hence the two step process: 1) grant 2) revoke
            # manage_records=perm.get("manage_records", False)
            # manage_users=perm.get("manage_users", False)

            # args["action"] = "grant"
            # args["manage_records"] = True if manage_records == True else False
            # args["manage_users"] = True if manage_users == True else False
            # ShareFolderCommand().execute(params, **args)

            # args["action"] = "revoke"
            # args["manage_records"] = True if manage_records == False else False
            # args["manage_users"] = True if manage_users == False else False
            # ShareFolderCommand().execute(params, **args)

    def create_subfolder(self, params, folder_name:str, parent_uid:str="", permissions:Optional[Dict]=None):
        """ Creates subfolder inside parent folder:
        either `user folder`, `shared folder` or `shared folder folder`.
        If `parent_uid == ""` then creates subfolder in root folder.
        If `permissions` is not None then creates `shared folder`.
        If `permissions` is None then creates `user folder` or `shared folder folder`
        depending on parent folder type.
        Note: Currently not possible to create sf inside another sf (throws)
        """

        name = str(folder_name or "").strip()
        base_folder = params.folder_cache.get(parent_uid, None) or params.root_folder

        shared_folder = True if permissions else False
        user_folder = True if not permissions else False  # uf or sff (split later)
        folder_uid = api.generate_record_uid()
        request: Dict[str, Any] = {
            "command": "folder_add",
            "folder_type": "user_folder",
            "folder_uid": folder_uid
            }

        if shared_folder:
            if base_folder.type in {BaseFolderNode.RootFolderType, BaseFolderNode.UserFolderType}:
                request["folder_type"] = "shared_folder"
                for perm in ["manage_users", "manage_records", "can_share", "can_edit"]:
                    if permissions and permissions.get(perm, False) == True:
                        request[perm] = True
            else:
                raise CommandError("pam", "Shared folders cannot be nested")
        elif user_folder:
            if base_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                request["folder_type"] = "shared_folder_folder"
            else:
                request["folder_type"] = "user_folder"

        if request.get("folder_type") is None:
            if base_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                request["folder_type"] = "shared_folder_folder"

        folder_key = os.urandom(32)
        encryption_key = params.data_key
        if request["folder_type"] == "shared_folder_folder":
            sf_uid = base_folder.shared_folder_uid if base_folder.type == BaseFolderNode.SharedFolderFolderType else base_folder.uid
            sf = params.shared_folder_cache[sf_uid]
            encryption_key = sf["shared_folder_key_unencrypted"]
            request["shared_folder_uid"] = sf_uid

        request["key"] = utils.base64_url_encode(crypto.encrypt_aes_v1(folder_key, encryption_key))
        if base_folder.type not in {BaseFolderNode.RootFolderType, BaseFolderNode.SharedFolderType}:
            request["parent_uid"] = base_folder.uid

        if request["folder_type"] == "shared_folder":
            request["name"] = utils.base64_url_encode(crypto.encrypt_aes_v1(name.encode("utf-8"), folder_key))
        data_dict = {"name": name}
        data = json.dumps(data_dict)
        request["data"] = utils.base64_url_encode(crypto.encrypt_aes_v1(data.encode("utf-8"), folder_key))

        api.communicate(params, request)
        api.sync_down(params)
        params.environment_variables[LAST_FOLDER_UID] = folder_uid
        if request["folder_type"] == "shared_folder":
            params.environment_variables[LAST_SHARED_FOLDER_UID] = folder_uid
        return folder_uid

    def get_property(self, data: dict, obj: str, property: str, default: str):
        data = data or {}
        dic = data.get(obj, {}) or {}
        prop = dic.get(property, default) or default
        return prop

    def find_folders(self, params, parent_uid:str, folder:str, is_shared_folder:bool) -> List[BaseFolderNode]:
        result: List[BaseFolderNode] = []
        folders = params.folder_cache if params and params.folder_cache else {}
        if not isinstance(folders, dict):
            return result

        puid = parent_uid if parent_uid else None # root folder parent uid is set to None
        matches = {k: v for k, v in folders.items() if v.parent_uid == puid and v.name == folder}
        result = [v for k, v in matches.items() if
                  (is_shared_folder and v.type == BaseFolderNode.SharedFolderType) or
                  (not is_shared_folder and v.type == BaseFolderNode.UserFolderType)]
        return result

    def create_ksm_app(self, params, app_name) -> str:
        app_record_data = {
            "title": app_name,
            "type": "app"
        }

        data_json = json.dumps(app_record_data)
        record_key_unencrypted = utils.generate_aes_key()
        record_key_encrypted = crypto.encrypt_aes_v2(record_key_unencrypted, params.data_key)

        app_record_uid_str = api.generate_record_uid()
        app_record_uid = utils.base64_url_decode(app_record_uid_str)

        data = data_json.decode("utf-8") if isinstance(data_json, bytes) else data_json
        data = api.pad_aes_gcm(data)

        rdata = bytes(data, "utf-8") # type: ignore
        rdata = crypto.encrypt_aes_v2(rdata, record_key_unencrypted)

        ra = record_pb2.ApplicationAddRequest()  # pylint: disable=E1101
        ra.app_uid = app_record_uid # type: ignore
        ra.record_key = record_key_encrypted # type: ignore
        ra.client_modified_time = api.current_milli_time() # type: ignore
        ra.data = rdata # type: ignore

        api.communicate_rest(params, ra, "vault/application_add")
        api.sync_down(params)
        return app_record_uid_str

    def create_gateway(
        self, params, gateway_name, ksm_app, config_init, ott_expire_in_min=5
    ):
        token = KSMCommand.add_client(
            params,
            app_name_or_uid=ksm_app,
            count=1,
            unlock_ip=True,
            first_access_expire_on=ott_expire_in_min,
            access_expire_in_min=None,  # None=Never, int = num of min
            client_name=gateway_name,
            config_init=config_init,
            silent=True,
            client_type=enterprise_pb2.DISCOVERY_AND_ROTATION_CONTROLLER)  # pylint: disable=E1101
        api.sync_down(params)

        return token

    def verify_users_and_teams(self, params, users_and_teams):
        api.load_available_teams(params)
        for item in users_and_teams:
            name = item.get("name", "")
            teams = [] 
            # do not use params.team_cache:
            for team in params.available_team_cache or []:
                team = api.Team(team_uid=team.get("team_uid", ""), name=team.get("team_name", ""))
                if name == team.team_uid or name.casefold() == team.name.casefold():
                    teams.append(team)
            users = []
            for user in params.enterprise.get("users", []):
                # if user["node_id"] not in node_scope: continue
                # skip: node_id, status, lock, tfa_enabled, account_share_expiration
                usr = {
                    "id": user.get("enterprise_user_id", "") or "",
                    "username": user.get("username", "") or "",
                    "name": user.get("data", {}).get("displayname", "") or ""
                }
                if name in usr.values(): users.append(usr)

            teams_users = teams + users
            num_found = len(teams_users)
            if num_found == 0:
                logging.warning(f"""Team/User: {bcolors.WARNING}"{name}"{bcolors.ENDC} - not found (skipped).""")
            elif num_found > 1:
                logging.warning(f"""Multiple matches ({num_found}) for team/user: {bcolors.WARNING}"{name}"{bcolors.ENDC} found (skipped).""")
                if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
                    msg = ""
                    for x in teams_users:
                        msg += "\n" + (f"team_uid: {x.team_uid}, name: {x.name}" if isinstance(x, api.Team) else str(x))
                    logging.debug(f"Matches from team/user lookup: {msg}")


    def process_data(self, params, project):
        """Process project data (JSON)"""
        from ..tunnel_and_connections import PAMTunnelEditCommand
        from ..discoveryrotation import PAMCreateRecordRotationCommand

        # users section is mostly RBI login users, but occasional "disconnected"
        # PAM User (ex. NOOP rotation) requires explicit record type to be set
        # also for shared users b/n ssh, vnc, rdp on same host (one pamMachine each)
        users = []
        resources = []
        # errors = 0  # --force option overrides (allows later setup)

        print("Started parsing import data...")
        pam_data = (project["data"].get("pam_data")
                    if "data" in project and isinstance(project["data"], dict)
                    else {})
        pam_data = pam_data if isinstance(pam_data, dict) else {}
        rotation_profiles = (pam_data.get("rotation_profiles")
                            if "rotation_profiles" in pam_data and isinstance(pam_data["rotation_profiles"], dict)
                            else {})
        rotation_profiles = rotation_profiles if isinstance(rotation_profiles, dict) else {}
        pam_cfg_uid = project["pam_config"]["pam_config_uid"]
        rotation_params = PamRotationParams(configUid=pam_cfg_uid, profiles=rotation_profiles)

        shfres = project["folders"].get("resources_folder_uid", "")
        shfusr = project["folders"].get("users_folder_uid", "")

        usrs = pam_data["users"] if "users" in pam_data and isinstance(pam_data["users"], list) else []
        rsrs = pam_data["resources"] if "resources" in pam_data and isinstance(pam_data["resources"], list) else []

        for user in usrs:
            rt = str(user.get("type", "")) if isinstance(user, dict) else ""
            rt = next((x for x in ("login", "pamUser") if x.lower() == rt.lower()), rt)
            if rt not in ("login", "pamUser") and isinstance(user, dict):
                pam_keys = ("private_pem_key", "distinguished_name", "connect_database", "managed", "scripts", "rotation_settings")
                if "url" in user: rt = "login"  # RBI login record
                elif any(key in user for key in pam_keys): rt = "pamUser"
            rt = next((x for x in ("login", "pamUser") if x.lower() == rt.lower()), "login")
            # If not found default to "login" which can be changed later

            if rt == "login":
                usr = LoginUserObject.load(user)
            else:
                usr = PamUserObject.load(user)
            if usr:
                users.append(usr)

        # each machine has its own users list of pamUser
        for machine in rsrs:
            rt = str(machine.get("type", "")).strip() if isinstance(machine, dict) else ""
            if rt.lower() not in (x.lower() for x in PAM_RESOURCES_RECORD_TYPES):
                prefix = "Incorrect " if rt else "Missing "
                title = str(machine.get("title", "")).strip() if isinstance(machine, dict) else ""
                logging.error(f"""{prefix} record type "{rt}" - should be one of {PAM_RESOURCES_RECORD_TYPES}, "{title}" record skipped.""")
                continue

            obj = None
            rt = rt.lower()
            if rt == "pamDatabase".lower():
                obj = PamDatabaseObject.load(machine, rotation_params)
            elif rt == "pamDirectory".lower():
                obj = PamDirectoryObject.load(machine, rotation_params)
            elif rt == "pamMachine".lower():
                obj = PamMachineObject.load(machine, rotation_params)
            elif rt == "pamRemoteBrowser".lower():
                obj = PamRemoteBrowserObject.load(machine, rotation_params)
            else:
                logging.warning(f"""Skipping unknown resource type "{rt}" """)

            if obj:
                resources.append(obj)

        # generate record UIDs used for DAG links
        for obj in chain(resources, users):
            # preserve any valid UID from JSON otherwise generate new UID
            if not(isinstance(obj.uid, str) and RecordV3.is_valid_ref_uid(obj.uid)):
                obj.uid = utils.generate_uid()
            if hasattr(obj, "users") and isinstance(obj.users, list):
                for usr in obj.users:
                    if not(isinstance(usr.uid, str) and RecordV3.is_valid_ref_uid(usr.uid)):
                        usr.uid = utils.generate_uid()

        # resolve linked object UIDs (machines and users)
        # pam_settings.connection.administrative_credentials must reference
        # one of its own users[] -> userRecords["admin_user_record_UID"]
        machines = [x for x in resources if not isinstance(x, PamRemoteBrowserObject)]
        pam_directories = [x for x in machines if (getattr(x, "type", "") or "").lower() == "pamdirectory"]
        for mach in resources:
            if not mach: continue
            admin_cred = get_admin_credential(mach)
            sftp_user = get_sftp_attribute(mach, "sftpUser")
            sftp_res = get_sftp_attribute(mach, "sftpResource")

            # sftpResourceUid could reference any machine (except RBI)
            if sftp_res:
                ruids = [x for x in machines if getattr(x, "title", None) == sftp_res]
                ruids = ruids or [x for x in machines if getattr(x, "login", None) == sftp_res]
                if len(ruids) != 1:
                    logging.warning(f"{bcolors.WARNING}{len(ruids)} matches found for sftpResource in {mach.title}.{bcolors.ENDC} ")
                ruid = getattr(ruids[0], "uid", "") if ruids else ""
                if ruid:
                    set_sftp_uid(mach, "sftpResourceUid", ruid)

            # sftpUserUid could reference any user (except RBI)
            if sftp_user:
                ruids = find_user(mach, users, sftp_user)  # try local user first
                ruids = ruids or find_user(machines, users, sftp_user)  # global search
                if len(ruids) != 1:
                    logging.warning(f"{bcolors.WARNING}{len(ruids)} matches found for sftpUser in {mach.title}.{bcolors.ENDC} ")
                ruid = getattr(ruids[0], "uid", "") if ruids else ""
                if ruid:
                    set_sftp_uid(mach, "sftpUserUid", ruid)

            # userRecordUid could reference local or users[] - resolved from userRecords
            if admin_cred:
                is_external = False
                ruids = find_user(mach, users, admin_cred)
                if not ruids:  # search all pamDirectory for external AD admin user
                    ruids = find_external_user(mach, machines, admin_cred)
                    is_external = True
                if len(ruids) != 1:
                    logging.warning(f"{bcolors.WARNING}{len(ruids)} matches found for userRecords in {mach.title}.{bcolors.ENDC} ")
                ruid = getattr(ruids[0], "uid", "") if ruids else ""
                if ruid:
                    set_user_record_uid(mach, ruid, is_external)

            # jit_settings.pam_directory_record -> pam_directory_uid (pamDirectory in pam_data.resources by title)
            # RBI has rbi_settings only (no pam_settings.jit_settings)
            ps = getattr(mach, "pam_settings", None)
            jit = getattr(ps, "jit_settings", None) if ps else None
            if jit and getattr(jit, "pam_directory_record", None):
                ref = (jit.pam_directory_record or "").strip()
                if ref:
                    matches = [x for x in pam_directories if getattr(x, "title", None) == ref]
                    if len(matches) > 1:
                        logging.warning(f"{bcolors.WARNING}Multiple pamDirectory matches for jit_settings.pam_directory_record '{ref}' in {getattr(mach, 'title', mach)}; using first.{bcolors.ENDC}")
                    if len(matches) == 0:
                        logging.error(f"jit_settings.pam_directory_record '{ref}' for '{getattr(mach, 'title', mach)}': no pamDirectory record found in pam_data.resources. Match by title.")
                    else:
                        jit.pam_directory_uid = matches[0].uid

            # resolve machine PRS creds: additional_credentials[] -> recordRef[]
            resolve_script_creds(mach, users, resources)

            # resolve users PRS creds and user.rotation_settings.resource
            if hasattr(mach, "users") and isinstance(mach.users, list):
                for usr in mach.users:
                    if (usr and hasattr(usr, "rotation_settings") and usr.rotation_settings
                        and hasattr(usr.rotation_settings, "rotation")
                        and usr.rotation_settings.rotation):
                        if usr.rotation_settings.rotation == "general":
                            usr.rotation_settings.resourceUid = mach.uid
                            # rotation_settings.resource is always owner machine (uid)
                        elif usr.rotation_settings.rotation in ("iam_user", "scripts_only"):
                            usr.rotation_settings.resourceUid = pam_cfg_uid
                            # rotation_settings.resource is always pam config uid here
                    # resolve machine users PRS creds additional_credentials[] -> recordRef[]
                    resolve_script_creds(usr, users, resources)

            # RBI autofill_credentials -> httpCredentialsUid (rt:login/pamUser)
            if (hasattr(mach, "rbi_settings") and
                hasattr(mach.rbi_settings, "connection") and
                hasattr(mach.rbi_settings.connection, "protocol") and
                str(mach.rbi_settings.connection.protocol.value).lower() == "http"):
                if (hasattr(mach.rbi_settings.connection, "httpCredentials")
                    and mach.rbi_settings.connection.httpCredentials):
                    cred = mach.rbi_settings.connection.httpCredentials
                    cred = str(cred[0]) if isinstance(cred, list) else str(cred)

                    # RBI resources do not own any users - search global users[]
                    # connection.userRecords[] not used by RBI
                    matches = [x for x in users if getattr(x, "title", None) == cred]
                    matches = matches or [x for x in users if getattr(x, "login", None) == cred]
                    if len(matches) != 1:
                        logging.warning(f"{bcolors.WARNING}{len(matches)} matches found for RBI record {mach.title}.{bcolors.ENDC} ")
                    uid = getattr(matches[0], "uid", "") if matches else ""
                    if uid:
                        mach.rbi_settings.connection.httpCredentialsUid = [uid]

        for usr in users:
            # resolve user.rotation_settings.resource - "iam_user", "scripts_only"
            if (usr and hasattr(usr, "rotation_settings") and usr.rotation_settings
                and hasattr(usr.rotation_settings, "rotation")
                and usr.rotation_settings.rotation):
                if usr.rotation_settings.rotation == "general":
                    # rotation_settings.resource is always owner machine (uid)
                    logging.warning(f"This user {usr.title} belongs to its own machine users list (consider removal from global users list)")
                    resource = getattr(usr.rotation_settings, "resource", "")
                    if resource:
                        ruids = [x for x in machines if getattr(x, "title", None) == resource]
                        ruids = ruids or [x for x in machines if getattr(x, "login", None) == resource]
                        if ruids:
                            usr.rotation_settings.resourceUid = ruids[0].uid
                elif usr.rotation_settings.rotation in ("iam_user", "scripts_only"):
                    usr.rotation_settings.resourceUid = pam_cfg_uid
                    # rotation_settings.resource is always pam config uid here
            # resolve users PRS additional_credentials[] -> recordRef[]
            resolve_script_creds(usr, users, resources)

        # resolve PAM Config PRS additional_credentials[] -> recordRef[]
        pce = project["pam_config"].get("pam_config_object")
        if pce and pce.scripts and pce.scripts.scripts:
            resolve_script_creds(pce, users, resources)

        # resolve domain admin if Domain PAM Config
        # Domain users are the equivalent to cloud users, IAM/Azure users. The parent of the pamUser is the configuration record.
        # The user does not belong to a machine, database or directory resource.
        # so check global users[] only
        if pce and pce.environment == "domain" and pce.dom_administrative_credential:
            resolve_domain_admin(pce, users)
        # only resolve here - create after machine and user creation

        # dry run
        if project["options"].get("dry_run", False) is True:
            print("Will import file data here...")
            return

        # if errors > 0:
        #     logging.warning(f"{bcolors.WARNING}{errors} errors found.{bcolors.ENDC} ")
        #     if project["options"]["force"] is True:
        #         print("Starting data import (--force option present)")
        #     else:
        #         print("Exiting. If you want to continue use --force option")
        #         return
        print("Started importing data...")

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_cfg_uid, True,
                         transmission_key=transmission_key)
        pte = PAMTunnelEditCommand()
        prc = PAMCreateRecordRotationCommand()

        pdelta = 10  # progress delta (update progress stats every pdelta items)
        msg = "Start data processing "
        msg += f" {len(resources)} resources" if resources else ""
        msg += f" {len(users)} external users" if users else ""
        msg += " - This could take a while..." if len(resources) + len(users) > 0 else ""
        logging.warning(msg)

        # Create records
        if users:
            logging.warning(f"Processing external users: {len(users)}")
            for n, user in enumerate(users):  # standalone users
                user.create_record(params, shfusr)
                if n % pdelta == 0: print(f"{n}/{len(users)}")
            print(f"{len(users)}/{len(users)}\n")

        # we need pamDirectory first in case AD Admin user is used in Local pamMachine
        resources.sort(key=lambda r: r.type != "pamDirectory")
        if resources: logging.warning(f"Processing resources: {len(resources)}")
        for n, mach in enumerate(resources):
            if n % pdelta == 0: print(f"{n}/{len(resources)}")
            # Machine - create machine first to avoid error:
            # Resource <UID> does not belong to the configuration
            admin_uid = get_admin_credential(mach, True)
            mach.create_record(params, shfres)
            tdag.link_resource_to_config(mach.uid)
            if isinstance(mach, PamRemoteBrowserObject): # RBI
                args = parse_command_options(mach, True)
                pte.execute(params, config=pam_cfg_uid, silent=True, **args)
                args = parse_command_options(mach, False)
                # bugfix: RBI=True also needs connections=True to enable RBI (in web vault)
                if args.get("remote_browser_isolation", False) is True:
                    args["connections"] = True
                tdag.set_resource_allowed(**args)
            else: # machine/db/directory
                args = parse_command_options(mach, True)
                if admin_uid: args["admin"] = admin_uid
                pte.execute(params, config=pam_cfg_uid, silent=True, **args)
                if admin_uid and is_admin_external(mach):
                    tdag.link_user_to_resource(admin_uid, mach.uid, is_admin=True, belongs_to=False)
                args = parse_command_options(mach, False)
                tdag.set_resource_allowed(**args)

                # After setting allowedSettings, save JIT settings if present
                # JIT settings don't apply to RBI records (only machine/db/directory); RBI has rbi_settings, no pam_settings.jit_settings
                ps = getattr(mach, "pam_settings", None)
                jit = getattr(ps, "jit_settings", None) if ps else None
                ai = getattr(ps, "ai_settings", None) if ps else None
                if jit:
                    jit_dag_dict = jit.to_dag_dict()
                    if jit_dag_dict:  # Only save if not empty
                        set_resource_jit_settings(params, mach.uid, jit_dag_dict, pam_cfg_uid)

                # After setting allowedSettings, save AI settings if present
                # AI settings don't apply to RBI records (only machine/db/directory)
                if ai:
                    user_id = ""
                    if getattr(params, "account_uid_bytes", None):
                        user_id = utils.base64_url_encode(params.account_uid_bytes)
                    elif getattr(params, "user", ""):
                        user_id = params.user
                    ai_dag_dict = ai.to_dag_dict(user_id=user_id)
                    if ai_dag_dict:  # Only save if not empty
                        set_resource_keeper_ai_settings(params, mach.uid, ai_dag_dict, pam_cfg_uid)

                # Web vault UI visualizer shows only latest and meta is most wanted path.
                # Note: DAG may take a while to sync in web vault
                # Dummy update to meta so it is latest among DATA (after jit/ai).
                if jit or ai:
                    refresh_meta_to_latest(params, mach.uid, pam_cfg_uid)
                # Bump LINK to config only when AI is present (AI adds the encryption KEY).
                if ai:
                    refresh_link_to_config_to_latest(params, mach.uid, pam_cfg_uid)

            # Machine - create its users (if any)
            users = getattr(mach, "users", [])
            users = users if isinstance(users, list) else []
            for user in users:
                if (isinstance(user, PamUserObject) and user.rotation_settings and
                    user.rotation_settings.rotation.lower() == "general"):
                    user.rotation_settings.resourceUid = mach.uid # DAG only
                user.create_record(params, shfusr)
                if isinstance(user, PamUserObject):  # rotation setup
                    tdag.link_user_to_resource(user.uid, mach.uid, admin_uid==user.uid, True)
                    if user.rotation_settings:
                        args = {"force": True, "config": pam_cfg_uid, "record_name": user.uid, "admin": admin_uid, "resource": mach.uid}
                        enabled = user.rotation_settings.enabled # on|off|default
                        key = {"on": "enable", "off": "disable"}.get(enabled, "")
                        if key: args[key] = True
                        # args["schedule_config"] = True  # Schedule from Configuration
                        schedule_type = user.rotation_settings.schedule.type if user.rotation_settings.schedule and user.rotation_settings.schedule.type else ""
                        if schedule_type == "on-demand":
                            args["on_demand"] = True
                        elif schedule_type == "cron":
                            if user.rotation_settings.schedule.cron:
                                args["schedule_cron_data"] = user.rotation_settings.schedule.cron
                            else:
                                logging.warning(f"{bcolors.WARNING}schedule.type=cron but schedule.cron is empty (skipped){bcolors.ENDC} ")
                        if user.rotation_settings.password_complexity:
                            args["pwd_complexity"]=user.rotation_settings.password_complexity
                        prc.execute(params, silent=True, **args)
        if resources: print(f"{len(resources)}/{len(resources)}\n")

        # link machine -> pamDirectory (LINK, path=domain) for jit_settings.pam_directory_uid
        # RBI has rbi_settings only (no pam_settings.jit_settings)
        jit_domain_links_added = False
        for mach in resources:
            ps = getattr(mach, "pam_settings", None)
            jit = getattr(ps, "jit_settings", None) if ps else None
            if not (mach and jit):
                continue
            dir_uid = getattr(jit, "pam_directory_uid", None)
            if not dir_uid:
                continue
            dag = tdag.linking_dag
            machine_vertex = dag.get_vertex(mach.uid)
            dir_vertex = dag.get_vertex(dir_uid)
            if machine_vertex and dir_vertex:
                machine_vertex.belongs_to(dir_vertex, EdgeType.LINK, path="domain", content={})
                jit_domain_links_added = True
        if jit_domain_links_added:
            tdag.linking_dag.save()

        # add scripts with resolved additional credentials - owner records must exist
        if pce and pce.scripts and pce.scripts.scripts:
            refs = [x for x in pce.scripts.scripts if x.record_refs]
            if refs:
                api.sync_down(params)
                add_pam_scripts(params, pam_cfg_uid, refs)

        # PAM Domain Config - update domain admin creds
        if pce and pce.environment == "domain":
            if pce.admin_credential_ref:
                pcuid = project["pam_config"].get("pam_config_uid")
                pcrec = vault.KeeperRecord.load(params, pcuid) if pcuid else None
                if pcrec and isinstance(pcrec, vault.TypedRecord) and pcrec.version == 6:
                    if pcrec.record_type == "pamDomainConfiguration":
                        prf = pcrec.get_typed_field('pamResources')
                        if not prf:
                            prf = vault.TypedField.new_field('pamResources', {})
                            pcrec.fields.append(prf)
                        prf.value = prf.value or [{}]
                        if isinstance(prf.value[0], dict):
                            prf.value[0]["adminCredentialRef"] = pce.admin_credential_ref
                            record_management.update_record(params, pcrec)
                            tdag.link_user_to_config_with_options(pce.admin_credential_ref, is_admin='on')
                        else:
                            logging.error(f"Unable to add adminCredentialRef - bad pamResources field in PAM Config {pcuid}")
            else:
                logging.debug(f"Unable to resolve domain admin '{pce.dom_administrative_credential}' for PAM Domain configuration.")

        logging.debug("Done processing project data.")
