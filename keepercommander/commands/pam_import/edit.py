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

from .batch_pipeline import BatchPamImportEngine, assign_uids
from .batch_nsf import sync_down_after_batch
from .import_tail import run_import_tail
from .playground import compute_network_id as _pg_compute_network_id
from .port_forward_validation import preflight_port_forward
from .workflow_apply import validate_workflow_principals
from .base import (
    PAM_IMPORT_RESOURCE_TYPES,
    PAM_RESOURCES_RECORD_TYPES,
    PROJECT_IMPORT_JSON_TEMPLATE,
    PamConfigEnvironment,
    PamUserObject,
    LoginUserObject,
    SaasConfigurationObject,
    PamMachineObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamCloudResourceObject,
    PamRemoteBrowserObject,
    PamRotationParams,
    add_pam_scripts,
    find_external_user,
    find_user,
    get_admin_credential,
    get_launch_credential,
    get_sftp_attribute,
    mark_local_users_allowing_empty_password_for_external_admin,
    resolve_domain_admin,
    resolve_script_creds,
    set_launch_record_uid,
    set_sftp_uid,
    set_user_record_uid
)
from ..base import Command
from ..ksm import KSMCommand
from ..nested_share_folder.helpers import ROOT_FOLDER_UID as NSF_ROOT_FOLDER_UID
from ..pam import gateway_helper
from ..pam.config_helper import pam_configurations_get_all
from ..pam.vault_target import (
    grant_pam_folder_permissions,
    is_nested_share_folder,
)
from ..record_edit import RecordUploadAttachmentCommand
from ..tunnel.port_forward.TunnelGraph import TunnelDAG
from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens
from ... import api, crypto, utils, vault
from ... import enterprise as _enterprise_module
from ...display import bcolors
from ...error import CommandError
from ...importer import imp_exp
from ...importer.importer import SharedFolder, Permission
from ...params import LAST_FOLDER_UID, LAST_SHARED_FOLDER_UID
from ...proto import record_pb2, APIRequest_pb2, enterprise_pb2
from ...recordv3 import RecordV3
from ...subfolder import BaseFolderNode, NestedShareFolderNode


class PAMProjectImportCommand(Command):
    parser = argparse.ArgumentParser(prog="pam project import")
    parser.add_argument("--name", "-n", required=False, dest="project_name", action="store", help="Project name.")
    parser.add_argument("--filename", "-f", required=False, dest="file_name", action="store", help="File to load import data from.")
    parser.add_argument("--dry-run", "-d", required=False, dest="dry_run", action="store_true", default=False, help="Test import without modifying vault.")
    parser.add_argument("--sample-data", "-s", required=False, dest="sample_data", action="store_true", default=False, help="Generate sample data.")
    parser.add_argument("--show-template", "-t", required=False, dest="show_template", action="store_true", default=False, help="Print JSON template required for manual import.")
    parser.add_argument("--nsf", required=False, dest="use_nsf", action="store_true", default=False, help="Create project folders and records in Nested Share Folders.")
    # parser.add_argument("--force", "-e", required=False, dest="force", action="store_true", default=False, help="Force data import (re/configure later)")
    parser.add_argument("--output", "-o", required=False, dest="output", action="store", choices=["token", "base64", "json", "k8s"], default="base64", help="Output format (token: one-time token, config: base64/json/k8s)")

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
        project["options"]["use_nsf"] = kwargs.get("use_nsf", False)
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
            # --name and --dry-run are honored with -s; NSF flag is orthogonal.
            extra = self.get_extra_args(["sample_data", "dry_run", "project_name", "use_nsf"], **kwargs)
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

        # pre-flight: validate port_forward (Keeper proxy gates etc.) before ANY vault write
        # (app / folders / records / DAG) - runs in dry-run too
        if project["options"]["sample_data"] is False:
            _pam_data = project["data"].get("pam_data") if isinstance(project["data"], dict) else None
            if not preflight_port_forward(_pam_data, "pam project import", bcolors):
                return

        # Initialize the caches
        api.sync_down(params)

        # Populate params.enterprise (users/teams caches)
        # Only if JSON has per-user / per-team permissions on the shared folders
        def _has_perms(section_key):
            section = project["data"].get(section_key) if isinstance(project["data"], dict) else None
            perms = section.get("permissions") if isinstance(section, dict) else None
            return isinstance(perms, list) and len(perms) > 0

        def _has_safe_folder_perms():
            # Per-safe folders may carry their own permission lists.
            # Any non-empty ``permissions`` array means we need enterprise
            # data to resolve the principals before creating folders.
            data = project["data"] if isinstance(project["data"], dict) else {}
            sf = data.get("safe_folders") if isinstance(data, dict) else None
            if not isinstance(sf, list):
                return False
            for entry in sf:
                if not isinstance(entry, dict):
                    continue
                perms = entry.get("permissions")
                if isinstance(perms, list) and len(perms) > 0:
                    return True
            return False

        needs_enterprise_data = (
            not project["options"]["dry_run"]
            and not project["options"]["sample_data"]
            and (_has_perms("shared_folder_users")
                 or _has_perms("shared_folder_resources")
                 or _has_safe_folder_perms())
        )
        if not params.enterprise and needs_enterprise_data:
            try:
                _enterprise_module.query_enterprise(params)
            except Exception as e:
                logging.debug("query_enterprise failed: %s", e)
            if not params.enterprise:
                logging.warning(
                    f"{bcolors.FAIL}pam project import requires an enterprise admin "
                    f"account with permission to access users and teams {bcolors.ENDC} "
                    "Your account is either not part of an enterprise or lacks the required role enforcement."
                )
                return

        # 1. Create Shared Folder for the Project (incl. parent folders)
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
            # --sample-data output is limited to the two file lines (compose path
            # + seccomp URL), already printed above - or the dry-run preview.
            # Skip the usual JSON result / docs note.
            return
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

    @staticmethod
    def _pam_folder_types(use_nsf=False):
        types = {BaseFolderNode.UserFolderType}
        if use_nsf:
            types.add(BaseFolderNode.NestedShareFolderType)
        return types

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
            "users_folder_uid": "",
            # Optional folder_path → folder UID map (safe_folders layout).
            "safe_folder_map": {},
            "safe_folders": [],
        }

        # Project structure:
        # PAM Environments > Project 1 (shared) > Resources - All except PAMUser: Machine, DB, Directory, Browser
        # PAM Environments > Project 1 (shared) > Users - PAMUser ONLY: All other types go into Resources

        # if project["data"].get("tool_version", "") != "": # CLI generated export else: # Manually generated import file

        data = project["data"] if isinstance(project.get("data"), dict) else {}
        safe_folders_def = data.get("safe_folders") if isinstance(data, dict) else None
        use_safe_layout = (
            isinstance(safe_folders_def, list)
            and any(isinstance(x, dict) and x.get("name") for x in safe_folders_def)
        )

        # FolderListCommand().execute(params, folders_only=True, pattern="/")
        use_nsf = project["options"].get("use_nsf", False) is True
        allowed_types = self._pam_folder_types(use_nsf)
        folders = self.find_folders(params, "", res["root_folder_target"], False)
        if folders:
            # select first non-root non-shared sub/folder
            folders = [x for x in folders if x.type in allowed_types]
            if use_nsf:
                folders = [x for x in folders if is_nested_share_folder(params, x.uid)]
            else:
                folders = [x for x in folders if not is_nested_share_folder(params, x.uid)]
            if len(folders) > 1:
                logging.warning(f"""Multiple user folders ({len(folders)}) match folder name "{res["root_folder_target"]}" """
                                f" using first match with UID: {bcolors.OKGREEN}{folders[0].uid}{bcolors.ENDC}")
                folders = folders[:1]
        res["root_folder"] = res["root_folder_target"]
        if folders:
            res["root_folder_uid"] = str(folders[0].uid)
        elif project["options"].get("dry_run", False) is not True:
            # FolderMakeCommand().execute(params, user_folder=True, folder=f"""/{res["root_folder_target"]}""")
            fuid = self.create_subfolder(params, res["root_folder_target"], use_nsf=use_nsf)
            res["root_folder_uid"] = fuid

        # find available project folder - incr. numeric suffix until distinct name found
        res["project_folder"] = res["project_folder_target"]
        if res["root_folder_uid"]:
            START_INDEX: int = 1
            n: int = START_INDEX
            while True:
                folder_name = res["project_folder_target"] if n <= START_INDEX else f"""{res["project_folder_target"]} #{n}"""
                folders = self.find_folders(params, res["root_folder_uid"], folder_name, False)
                folders = [x for x in folders if x.type in allowed_types]
                n += 1
                if len(folders) > 0:
                    continue
                res["project_folder"] = folder_name
                if project["options"].get("dry_run", False) is not True:
                    # FolderMakeCommand().execute(params, shared_folder=True, folder=f"""/{res["root_folder"]}/{res["project_folder"]}""")
                    fuid = self.create_subfolder(params, folder_name=res["project_folder"], parent_uid=res["root_folder_uid"], use_nsf=use_nsf)
                    res["project_folder_uid"] = fuid

                    puid = res["project_folder_uid"]
                    if use_safe_layout:
                        self._create_safe_folders(params, project, puid, res, safe_folders_def)
                    else:
                        sfn = project["data"].get("shared_folder_resources", None)
                        fname = sfn["folder_name"] if isinstance(sfn, dict) and isinstance(sfn.get("folder_name", None), str) else ""
                        fname = fname.strip() or f"""{res["project_folder"]} - Resources"""
                        fperm, rperm = self.get_folder_permissions(users_folder=False, data=project["data"])
                        fuid = self.create_subfolder(params, folder_name=fname, parent_uid=puid, permissions=fperm, use_nsf=use_nsf)
                        res["resources_folder"] = fname
                        res["resources_folder_uid"] = fuid

                        sfn = project["data"].get("shared_folder_users", None)
                        fname = sfn["folder_name"] if isinstance(sfn, dict) and isinstance(sfn.get("folder_name", None), str) else ""
                        fname = fname.strip() or f"""{res["project_folder"]} - Users"""
                        fperm, uperm = self.get_folder_permissions(users_folder=True, data=project["data"])
                        fuid = self.create_subfolder(params, folder_name=fname, parent_uid=puid, permissions=fperm, use_nsf=use_nsf)
                        res["users_folder"] = fname
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
                print(f"""Will create new {"NSF " if use_nsf else ""}PAM root folder: {res["root_folder_target"]}""")
            print(f"""Will create new {"NSF " if use_nsf else ""}Project folder: {res["project_folder"]}""")
            if use_safe_layout:
                safe_names = [str(x.get("name") or "").strip()
                              for x in safe_folders_def if isinstance(x, dict)]
                safe_names = [n for n in safe_names if n]
                print(f"Will create {len(safe_names) + 1} shared folders under project "
                      f"(one per safe + 1 admin Config folder)")
                for n in safe_names:
                    print(f"  • {n}")
        else:
            if use_nsf:
                from .nsf_helpers import sync_down_preserving_nsf_keys
                sync_down_preserving_nsf_keys(params)
            else:
                api.sync_down(params)

        return res

    def _create_safe_folders(self, params, project: dict, project_folder_uid: str,
                             res: dict, safe_folders_def: list) -> None:
        """Create per-safe shared folders and the admin-only Config folder.

        Fills ``res["safe_folder_map"]`` so process_data can route by ``folder_path``.
        Config folder UID is also stored in the legacy resources/users slots.
        """
        safe_folder_map: dict = {}
        safe_folder_records: list = []
        use_nsf = project["options"].get("use_nsf", False) is True

        # Default folder-level permissions for safe folders.
        default_fperm = {
            "manage_users": True,
            "manage_records": True,
            "can_edit": True,
            "can_share": True,
        }

        # Collect all user/team permission entries across safes so we can
        # verify them up-front in a single batch (process_data does the
        # same for legacy mode).
        all_user_perms: list = []
        for entry in safe_folders_def:
            if not isinstance(entry, dict):
                continue
            folder_name = str(entry.get("name") or "").strip()
            if not folder_name:
                continue
            fperm = dict(default_fperm)
            for key in ("manage_users", "manage_records", "can_edit", "can_share"):
                if key in entry:
                    fperm[key] = bool(entry.get(key))

            uperm: list = []
            perm_list = entry.get("permissions") if isinstance(entry.get("permissions"), list) else []
            for item in perm_list:
                if not isinstance(item, dict):
                    continue
                uid_ = item.get("uid", None)
                name_ = item.get("name", None)
                if uid_ is None and name_ is None:
                    logging.warning(
                        "Safe folder '%s' permission entry missing both uid and name (skipped)",
                        folder_name,
                    )
                    continue
                uperm.append({
                    "uid": uid_,
                    "name": name_,
                    "manage_users": True if str(item.get("manage_users", False)).upper() == "TRUE" else False,
                    "manage_records": True if str(item.get("manage_records", False)).upper() == "TRUE" else False,
                })
            all_user_perms.extend(uperm)
            safe_folder_records.append({
                "name": folder_name,
                "safe_name": str(entry.get("safe_name") or folder_name),
                "fperm": fperm,
                "uperm": uperm,
            })

        # Admin-only "Config" folder that holds the PAM Configuration v6
        # record. Cannot live in any safe folder, or the safe's members
        # would gain access to the central config record.
        config_folder_name = f"""{res["project_folder"]} - Config"""

        # Verify principals once (avoids one round-trip per safe).
        if all_user_perms:
            self.verify_users_and_teams(params, all_user_perms)

        if use_nsf:
            self._create_safe_folders_nsf_batch(
                params, project_folder_uid, res, safe_folder_records,
                config_folder_name, safe_folder_map,
            )
            return

        config_uid = self.create_subfolder(
            params, folder_name=config_folder_name,
            parent_uid=project_folder_uid, permissions=dict(default_fperm),
            use_nsf=False,
        )
        res["resources_folder"] = config_folder_name
        res["users_folder"] = config_folder_name
        res["resources_folder_uid"] = config_uid
        res["users_folder_uid"] = config_uid
        res["config_folder_uid"] = config_uid
        res["config_folder"] = config_folder_name

        # Create one shared folder per safe under the project wrapper and
        # apply its specific permission set. Inside each safe folder,
        # create two organizational subfolders named
        # ``{safe} - Resources`` (for the asset records) and
        # ``{safe} - Users`` (for the credential records) so the
        # imported records mirror the legacy two-folder split, but with
        # the access boundary still drawn at the per-safe level. The
        # subfolders inherit the safe's permission set automatically
        # because they're ``shared_folder_folder`` children — we don't
        # need to re-attach permissions per subfolder. Prefixing the
        # subfolder names with the safe name keeps them
        # self-identifying in the Keeper UI even when listed flat.
        for record in safe_folder_records:
            folder_uid = self.create_subfolder(
                params, folder_name=record["name"],
                parent_uid=project_folder_uid, permissions=record["fperm"],
                use_nsf=False,
            )
            # Top-level lookup key (no slash) maps to the safe folder
            # itself for callers that still emit ``folder_path = "<safe>"``
            # (e.g. older versions of the importer or hand-written JSON).
            safe_folder_map[record["name"]] = folder_uid

            res_sub_name = f"{record['name']} - Resources"
            usr_sub_name = f"{record['name']} - Users"
            res_sub_uid = self.create_subfolder(
                params, folder_name=res_sub_name, parent_uid=folder_uid,
                use_nsf=False,
            )
            usr_sub_uid = self.create_subfolder(
                params, folder_name=usr_sub_name, parent_uid=folder_uid,
                use_nsf=False,
            )
            safe_folder_map[f"{record['name']}/{res_sub_name}"] = res_sub_uid
            safe_folder_map[f"{record['name']}/{usr_sub_name}"] = usr_sub_uid

            res["safe_folders"].append({
                "name": record["name"],
                "safe_name": record["safe_name"],
                "uid": folder_uid,
                "resources_subfolder": res_sub_name,
                "resources_subfolder_uid": res_sub_uid,
                "users_subfolder": usr_sub_name,
                "users_subfolder_uid": usr_sub_uid,
            })
            if record["uperm"]:
                self.add_folder_permissions(params, folder_uid, record["uperm"])

        res["safe_folder_map"] = safe_folder_map

    def _create_safe_folders_nsf_batch(self, params, project_folder_uid: str,
                                      res: dict, safe_folder_records: list,
                                      config_folder_name: str,
                                      safe_folder_map: dict) -> None:
        """Create Config + per-safe NSF folders via batched folder_add_v3.

        Two layers (parents must exist before children):
          1. Config folder + each safe folder under the project
          2. ``{safe} - Resources`` / ``{safe} - Users`` under each safe
        """
        from .nsf_helpers import create_nsf_folders_batch

        # Layer 1: config + safe wrappers (same parent)
        layer1_specs = [
            {"name": config_folder_name, "parent_uid": project_folder_uid},
        ]
        for record in safe_folder_records:
            layer1_specs.append({
                "name": record["name"],
                "parent_uid": project_folder_uid,
            })

        layer1 = create_nsf_folders_batch(
            params, layer1_specs, sync=False, command='pam-project-import',
        )
        config_uid = layer1[0]["folder_uid"]
        res["resources_folder"] = config_folder_name
        res["users_folder"] = config_folder_name
        res["resources_folder_uid"] = config_uid
        res["users_folder_uid"] = config_uid
        res["config_folder_uid"] = config_uid
        res["config_folder"] = config_folder_name

        safe_uids: list = []
        for i, record in enumerate(safe_folder_records):
            folder_uid = layer1[i + 1]["folder_uid"]
            safe_uids.append(folder_uid)
            safe_folder_map[record["name"]] = folder_uid

        # Layer 2: Resources / Users children under each safe
        layer2_specs: list = []
        layer2_meta: list = []  # (safe_index, kind, sub_name)
        for i, record in enumerate(safe_folder_records):
            res_sub_name = f"{record['name']} - Resources"
            usr_sub_name = f"{record['name']} - Users"
            parent_uid = safe_uids[i]
            layer2_specs.append({"name": res_sub_name, "parent_uid": parent_uid})
            layer2_meta.append((i, "resources", res_sub_name))
            layer2_specs.append({"name": usr_sub_name, "parent_uid": parent_uid})
            layer2_meta.append((i, "users", usr_sub_name))

        layer2 = []
        if layer2_specs:
            layer2 = create_nsf_folders_batch(
                params, layer2_specs, sync=True, command='pam-project-import',
            )
        else:
            # Config-only project: still need one sync after layer 1.
            from .nsf_helpers import sync_down_preserving_nsf_keys
            sync_down_preserving_nsf_keys(params)

        # Assemble maps / safe_folders entries
        by_safe: dict = {
            i: {"resources_uid": None, "users_uid": None,
                "resources_name": None, "users_name": None}
            for i in range(len(safe_folder_records))
        }
        for result, (safe_i, kind, sub_name) in zip(layer2, layer2_meta):
            uid = result["folder_uid"]
            parent_name = safe_folder_records[safe_i]["name"]
            safe_folder_map[f"{parent_name}/{sub_name}"] = uid
            if kind == "resources":
                by_safe[safe_i]["resources_uid"] = uid
                by_safe[safe_i]["resources_name"] = sub_name
            else:
                by_safe[safe_i]["users_uid"] = uid
                by_safe[safe_i]["users_name"] = sub_name

        for i, record in enumerate(safe_folder_records):
            folder_uid = safe_uids[i]
            info = by_safe[i]
            res["safe_folders"].append({
                "name": record["name"],
                "safe_name": record["safe_name"],
                "uid": folder_uid,
                "resources_subfolder": info["resources_name"],
                "resources_subfolder_uid": info["resources_uid"],
                "users_subfolder": info["users_name"],
                "users_subfolder_uid": info["users_uid"],
            })
            if record["uperm"]:
                self.add_folder_permissions(params, folder_uid, record["uperm"])

        res["safe_folder_map"] = safe_folder_map

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

        # Create KSM App and share Resources/Users folders (classic SF or NSF).
        # KSMCommand routes NSF folder UIDs through grant_folder_access_to_application_v3.
        use_nsf = project["options"].get("use_nsf", False) is True
        from .nsf_helpers import (collect_nsf_subtree_uids, grant_nsf_folders_to_ksm_app,
                                  restore_nsf_folder_keys, snapshot_nsf_folder_keys,
                                  sync_down_preserving_nsf_keys)
        preserved = snapshot_nsf_folder_keys(params) if use_nsf else None
        res["app_uid"] = self.create_ksm_app(params, res["app_name"])
        if preserved is not None:
            # create_ksm_app sync_down clears NSF caches; restore before NSF secret share.
            restore_nsf_folder_keys(params, preserved)

        # The KSM app must have access to every shared folder containing
        # PAM records. Standard layout emits exactly two folders (Resources +
        # Users). Safe-folders layout emits one folder per safe entry plus
        # the admin Config folder; collect them all here (dedup'd in case
        # the same UID surfaces twice — e.g. config == resources when
        # resources_folder_uid mirrors the config folder).
        sf_uids_to_grant = []
        seen_sf_uids = set()

        def _add_sf(sf_uid: str):
            sf_uid = (sf_uid or "").strip()
            if not sf_uid or sf_uid in seen_sf_uids:
                return
            seen_sf_uids.add(sf_uid)
            sf_uids_to_grant.append(sf_uid)

        folders = project["folders"]
        # NSF folder keys are per-folder: a child does not inherit the parent's
        # AT_APPLICATION grant the way a classic shared_folder_folder does. Grant
        # the whole project subtree so records in any descendant (safe-mode
        # "{safe} - Resources"/"- Users" subfolders included) stay GW-visible.
        # The global "PAM Environments" root is deliberately excluded - it is a
        # container shared across projects and holds no records.
        if use_nsf and folders.get("project_folder_uid", ""):
            for nsf_uid in collect_nsf_subtree_uids(params, folders["project_folder_uid"]):
                _add_sf(nsf_uid)
        _add_sf(folders.get("resources_folder_uid", ""))
        _add_sf(folders.get("users_folder_uid", ""))
        _add_sf(folders.get("config_folder_uid", ""))
        for entry in folders.get("safe_folders", []) or []:
            if isinstance(entry, dict):
                _add_sf(entry.get("uid", ""))
                if use_nsf:
                    # Classic safe subfolders are shared_folder_folder children and
                    # inherit the safe's key; NSF ones need their own grant.
                    _add_sf(entry.get("resources_subfolder_uid", ""))
                    _add_sf(entry.get("users_subfolder_uid", ""))

        if use_nsf:
            grant_nsf_folders_to_ksm_app(params, res["app_uid"], sf_uids_to_grant, editable=True)
        else:
            for sf_uid in sf_uids_to_grant:
                KSMCommand().execute(params,
                                     command=("secret", "add"),
                                     app=res["app_uid"],
                                     secret=[sf_uid], editable=True)

        if use_nsf or any(is_nested_share_folder(params, uid)
                          for uid in (project["folders"].get("resources_folder_uid", ""),
                                      project["folders"].get("users_folder_uid", ""))
                          if uid):
            sync_down_preserving_nsf_keys(params)
        else:
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
        use_nsf = project["options"].get("use_nsf", False) is True
        from .nsf_helpers import restore_nsf_folder_keys, snapshot_nsf_folder_keys, sync_down_preserving_nsf_keys
        preserved = snapshot_nsf_folder_keys(params) if use_nsf else None
        output_fmt = project["options"]["output"]
        # --sample-data ignores --output: the deliverable is always the generated
        # docker-compose.yaml, which embeds the base64 gateway config (GATEWAY_CONFIG),
        # so force config_init="b64".
        is_sample = project["options"].get("sample_data", False)
        if is_sample:
            token_format = "b64"
        else:
            token_format = None if output_fmt == "token" else ("k8s" if output_fmt == "k8s" else "b64")
        ksm_app_uid = project["ksm_app"]["app_uid"]
        gw = self.create_gateway(
            params,
            gateway_name=res["gateway_name"],
            ksm_app=ksm_app_uid,
            config_init=token_format)
        if preserved is not None:
            restore_nsf_folder_keys(params, preserved)

        config_raw = gw[0].get("config", "") if gw else ""  # base64 config (if config_init set)
        if is_sample:
            res["gateway_token"] = config_raw  # --output ignored; config lives in docker-compose.yaml
        elif token_format is None:
            res["gateway_token"] = gw[0].get("oneTimeToken", "") if gw else ""  # OTT
        else:
            res["gateway_token"] = config_raw  # Config
            if output_fmt == "json":
                res["gateway_token"] = json.loads(utils.base64_url_decode(config_raw))
            # k8s: config is already Kubernetes Secret YAML string; base64: keep as-is
        # base64 config for the sample-data docker-compose GATEWAY_CONFIG
        res["gateway_config_b64"] = config_raw
        res["gateway_device_token"] = gw[0].get("deviceToken", "") if gw else ""

        # controller_uid is not returned by vault/app_client_add
        # Look it up via get_all_gateways but invalidate_gateway_cache first
        gateway_helper.invalidate_gateway_cache()
        gws = gateway_helper.get_all_gateways(params)
        gw_names = [x.controllerUid for x in gws if x.deviceToken == res["gateway_device_token"]]
        res["gateway_uid"] = utils.base64_url_encode(gw_names[0]) if gw_names else ""
        # gateway_helper.remove_gateway(params, utils.base64_url_decode(res["gateway_uid"]))

        if use_nsf:
            sync_down_preserving_nsf_keys(params)
        else:
            api.sync_down(params)
        return res

    def process_pam_config(self, params, project: dict) -> dict:
        # Local import to avoid circular import with discoveryrotation
        from ..discoveryrotation import PAMConfigurationNewCommand
        res:Dict[str, Any] = {
            "pam_config_name_target": "",
            "pam_config_name": "",
            "pam_config_uid": ""
        }

        res["pam_config_name_target"] = self.get_property(project["data"], "pam_configuration", "title", "")
        if not res["pam_config_name_target"]:
            res["pam_config_name_target"] = project["options"]["project_name"] + " Configuration"

        # Find unique PAM Configuration name (classic record_cache + NSF caches)
        n = 1
        pams = pam_configurations_get_all(params)
        pam_names = {json.loads(x.get("data_unencrypted", "{}")).get("title", "") for x in pams}
        for uid, nsf_rec in (getattr(params, 'nested_share_records', None) or {}).items():
            if nsf_rec.get('version') != 6:
                continue
            dj = ((getattr(params, 'nested_share_record_data', None) or {})
                  .get(uid, {}).get('data_json') or {})
            title = dj.get('title') or ''
            if title:
                pam_names.add(title)
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
        # For --sample-data the JSON body is empty, so pass "local" as default_env
        default_env = "local" if project["options"].get("sample_data", False) else ""
        pce = PamConfigEnvironment(default_env, pam_cfg, args["gateway_uid"], args["shared_folder_uid"])
        pce.title = res["pam_config_name"]  # adjusted title
        if project["options"].get("sample_data", False):
            # -s | --sample-data option overrides json data
            args.update({
                "config_type": "local",
                "environment": "local",
                "title": res["pam_config_name"],
                "port_mapping": ["2222=ssh"],
                # "network_cidr": "192.168.1.0/24",
                # network_id must match the docker-compose network name (playground.py)
                "network_id": _pg_compute_network_id(project["options"]["project_name"]),
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

            if pce.identity_provider_uid: args["identity_provider_uid"] = pce.identity_provider_uid

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
                if pce.dom_user_match: args["domain_user_match"] = pce.dom_user_match
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

            # `default_schedule` for PAMConfigurationNewCommand is a CRON string (or absent for
            # on-demand). PamConfigEnvironment normalizes it into a dict ({"type": "ON_DEMAND"} or
            # {"type": "CRON", "cron": "...", "tz": "..."}), so unpack back into the expected form
            # — passing the dict through causes AttributeError: 'dict' object has no attribute 'strip'
            # inside validate_cron_expression().
            sched = pce.default_rotation_schedule
            if isinstance(sched, dict):
                sched_type = str(sched.get("type", "")).lower().replace("_", "-")
                if sched_type == "cron":
                    cron_expr = str(sched.get("cron", "") or "").strip()
                    if cron_expr:
                        args["default_schedule"] = cron_expr
                # on-demand / ON_DEMAND → omit args["default_schedule"] → server defaults to On-Demand
            elif isinstance(sched, str) and sched.strip():
                args["default_schedule"] = sched.strip()

        res["pam_config_uid"] = PAMConfigurationNewCommand().execute(params, **args)
        users_folder_uid = project["folders"].get("users_folder_uid", "")
        if project["options"].get("use_nsf", False) is True or is_nested_share_folder(params, users_folder_uid):
            from .nsf_helpers import sync_down_preserving_nsf_keys
            sync_down_preserving_nsf_keys(params)
        else:
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
        # All sample-data logic (records + credentials + docker-compose) lives
        # in playground.py; this method just orchestrates it.
        from .playground import PlaygroundSession, COMPOSE_FILENAME, SECCOMP_URL
        session = PlaygroundSession(params, project)
        if project["options"].get("dry_run", False) is True:
            intended = os.path.abspath(os.path.join(os.getcwd(), COMPOSE_FILENAME))
            plan = session.simulate()
            print(json.dumps(plan, indent=2))
            print("[DRY RUN] Would generate discovery-playground sample records "
                  "via BatchPamImportEngine "
                  "(MySQL, SSH, VNC, RDP, RBI, PostgreSQL, MariaDB, MSSQL, "
                  "Telnet, OpenLDAP) with freshly generated credentials.")
            print(f"[DRY RUN] Would write docker-compose to: {intended}")
            print(f"[DRY RUN] Seccomp profile: {SECCOMP_URL}")
            print("[DRY RUN COMPLETE] No vault/DAG writes.")
            return

        if not session.create_all_records():
            print(f"{bcolors.FAIL}Sample-data import aborted due to batch vault/DAG failure.{bcolors.ENDC}")
            return
        gateway_config_b64 = project["gateway"].get("gateway_config_b64", "")
        compose_yaml = session.build_compose(gateway_config_b64)
        session.save_compose_and_seccomp(compose_yaml)

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
            if is_nested_share_folder(params, folder_uid):
                grant_pam_folder_permissions(params, folder_uid, permissions, command='pam-project-import')
                api.sync_down(params)
                return

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

    def create_subfolder(self, params, folder_name:str, parent_uid:str="", permissions:Optional[Dict]=None,
                         use_nsf: bool=False):
        """ Creates subfolder inside parent folder:
        either `user folder`, `shared folder` or `shared folder folder`.
        If `parent_uid == ""` then creates subfolder in root folder.
        If `permissions` is not None then creates `shared folder`.
        If `permissions` is None then creates `user folder` or `shared folder folder`
        depending on parent folder type.
        Note: Currently not possible to create sf inside another sf (throws)
        """

        name = str(folder_name or "").strip()
        if use_nsf or is_nested_share_folder(params, parent_uid):
            from .nsf_helpers import create_nsf_folders_batch
            results = create_nsf_folders_batch(
                params,
                [{"name": name, "parent_uid": parent_uid or None}],
                sync=True,
                command='pam',
            )
            folder_uid = results[0]["folder_uid"]
            params.environment_variables[LAST_FOLDER_UID] = folder_uid
            return folder_uid

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
        if not is_shared_folder:
            seen = {v.uid for v in result}
            nsf_folders = getattr(params, 'nested_share_folders', None) or {}
            for uid, nsf in nsf_folders.items():
                if uid in seen or nsf.get('name') != folder:
                    continue
                nsf_parent = self._nsf_effective_parent_uid(nsf, nsf_folders, folders)
                if nsf_parent == puid:
                    nsf_folder = NestedShareFolderNode()
                    nsf_folder.uid = uid
                    nsf_folder.name = nsf.get('name')
                    nsf_folder.parent_uid = nsf_parent
                    result.append(nsf_folder)
                    seen.add(uid)
        return result

    @staticmethod
    def _nsf_effective_parent_uid(nsf: dict, nsf_folders: dict, folder_cache: dict) -> Optional[str]:
        """Normalize an NSF folder's parent to ``None`` when the folder sits at the root.

        A root-level NSF can be reported three ways: ``None`` (no ``parentUid`` was
        ever sent - both Commander and the Web Vault omit it on create), the server's
        drive-root sentinel UID, or - after ``normalize_parent_uid`` - the string
        ``'root'``. ``sync_down.prepare_folder_tree`` reconciles this on the
        ``folder_cache`` node but leaves ``params.nested_share_folders`` untouched, so
        matching on the raw value there misses roots and duplicates them instead.
        Mirrors the same predicate used by ``tree``/``ls`` in commands/folder.py.
        """
        nsf_parent = nsf.get('parent_uid') or None
        if not nsf_parent:
            return None
        if nsf_parent in (NSF_ROOT_FOLDER_UID, 'root'):
            return None
        if nsf_parent not in nsf_folders and nsf_parent not in folder_cache:
            # Parent resolves to no known folder, so it cannot be a real parent.
            return None
        return nsf_parent

    @staticmethod
    def _collect_pam_folder_paths(pam_data: dict) -> list:
        """Unique non-empty folder_path values from resources, nested users, and global users."""
        paths = set()
        for r in pam_data.get("resources") or []:
            if not isinstance(r, dict):
                continue
            fp = r.get("folder_path")
            if isinstance(fp, str) and fp.strip():
                paths.add(fp.strip())
            for u in r.get("users") or []:
                if not isinstance(u, dict):
                    continue
                ufp = u.get("folder_path")
                if isinstance(ufp, str) and ufp.strip():
                    paths.add(ufp.strip())
        # global users and SaaS configuration records (pam_data.saas_configurations[]) are created the same way
        for u in list(pam_data.get("users") or []) + list(pam_data.get("saas_configurations") or []):
            if not isinstance(u, dict):
                continue
            fp = u.get("folder_path")
            if isinstance(fp, str) and fp.strip():
                paths.add(fp.strip())
        return sorted(paths)

    def _find_child_folder(self, params, parent_uid: str, name: str):
        """Find any child folder (shared / user / shared-folder-folder / NSF) by name."""
        folders = params.folder_cache if params and params.folder_cache else {}
        if isinstance(folders, dict):
            for v in folders.values():
                if getattr(v, "parent_uid", None) == parent_uid and getattr(v, "name", None) == name:
                    return v
        for uid, nsf in getattr(params, "nested_share_folders", {}).items():
            if (nsf.get("parent_uid") or None) == parent_uid and nsf.get("name") == name:
                nsf_folder = NestedShareFolderNode()
                nsf_folder.uid = uid
                nsf_folder.name = nsf.get("name")
                nsf_folder.parent_uid = nsf.get("parent_uid")
                return nsf_folder
        return None

    def _materialize_folder_paths(self, params, project: dict, pam_data: dict) -> dict:
        """Build folder_path → UID map; create nested folders for explicit paths.

        Starts from ``safe_folder_map`` (per-safe layout) and project Resources/Users
        roots. Any ``folder_path`` in pam_data that is not yet mapped is walked and
        missing segments are created under the matching root. Unresolvable roots
        are left unmapped so stamping falls back to type defaults.
        """
        from .extend import split_folder_path

        folders = project.get("folders") or {}
        path_map = dict(folders.get("safe_folder_map") or {})
        path_map.update(folders.get("path_to_folder_uid") or {})

        for name_key, uid_key in (
            ("resources_folder", "resources_folder_uid"),
            ("users_folder", "users_folder_uid"),
            ("config_folder", "config_folder_uid"),
        ):
            name = (folders.get(name_key) or "").strip()
            uid = folders.get(uid_key) or ""
            if name and uid:
                path_map.setdefault(name, uid)

        for sf in folders.get("safe_folders") or []:
            if not isinstance(sf, dict):
                continue
            name = (sf.get("name") or "").strip()
            uid = sf.get("uid") or ""
            if name and uid:
                path_map.setdefault(name, uid)

        paths = self._collect_pam_folder_paths(pam_data)
        dry_run = project.get("options", {}).get("dry_run", False) is True
        use_nsf = project.get("options", {}).get("use_nsf", False) is True
        created = 0

        for path in paths:
            if path in path_map:
                continue
            parts = split_folder_path(path)
            if not parts:
                continue
            parent_uid = None
            cumulative = ""
            for i, part in enumerate(parts):
                cumulative = part if i == 0 else f"{cumulative}/{part}"
                if cumulative in path_map:
                    parent_uid = path_map[cumulative]
                    continue
                if i == 0:
                    logging.warning(
                        'folder_path "%s": root folder "%s" not found among project '
                        "folders; records with this path use type-based Users/Resources defaults",
                        path, part,
                    )
                    break
                child = self._find_child_folder(params, parent_uid, part)
                if child is not None:
                    path_map[cumulative] = child.uid
                    parent_uid = child.uid
                    continue
                if dry_run:
                    new_uid = api.generate_record_uid()
                else:
                    new_uid = self.create_subfolder(
                        params, part, parent_uid, use_nsf=use_nsf,
                    )
                path_map[cumulative] = new_uid
                parent_uid = new_uid
                created += 1

        if created and not dry_run:
            # Plain sync_down drops NSF folder keys; batch helper preserves them when NSF is in play.
            sync_down_after_batch(params, project)

        folders["path_to_folder_uid"] = path_map
        return path_map

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
        # Explicit folder_path → UID map (safe_folder_map + nested paths under
        # Resources/Users). Type defaults apply only when folder_path is unset.
        folder_path_map = self._materialize_folder_paths(params, project, pam_data)

        def _resolve_folder_uid(obj, default_uid: str) -> str:
            fp = getattr(obj, "folder_path", None) or ""
            fp = fp.strip() if isinstance(fp, str) else ""
            if not fp:
                return default_uid
            return folder_path_map.get(fp) or default_uid

        usrs = pam_data["users"] if "users" in pam_data and isinstance(pam_data["users"], list) else []
        rsrs = pam_data["resources"] if "resources" in pam_data and isinstance(pam_data["resources"], list) else []

        for user in usrs:
            rt = str(user.get("type", "")) if isinstance(user, dict) else ""
            rt = next((x for x in ("login", "pamUser", "saasConfiguration") if x.lower() == rt.lower()), rt)
            if rt not in ("login", "pamUser", "saasConfiguration") and isinstance(user, dict):
                pam_keys = ("private_pem_key", "distinguished_name", "connect_database", "managed", "scripts", "rotation_settings")
                if "url" in user: rt = "login"  # RBI login record
                elif any(key in user for key in pam_keys): rt = "pamUser"
            rt = next((x for x in ("login", "pamUser", "saasConfiguration") if x.lower() == rt.lower()), "login")
            # If not found default to "login" which can be changed later

            if rt == "login":
                usr = LoginUserObject.load(user)
            elif rt == "saasConfiguration":
                usr = SaasConfigurationObject.load(user)
            else:
                usr = PamUserObject.load(user)
            if usr:
                users.append(usr)

        # SaaS configuration records (regular vault records, rotation: saas) - created with the other global users
        saas_cfgs = pam_data.get("saas_configurations") if isinstance(pam_data.get("saas_configurations"), list) else []
        for cfg in saas_cfgs:
            if isinstance(cfg, dict):
                usr = SaasConfigurationObject.load(cfg)
                if usr:
                    users.append(usr)

        # each machine has its own users list of pamUser
        for machine in rsrs:
            rt = str(machine.get("type", "")).strip() if isinstance(machine, dict) else ""
            if rt.lower() not in (x.lower() for x in PAM_IMPORT_RESOURCE_TYPES):
                prefix = "Incorrect " if rt else "Missing "
                title = str(machine.get("title", "")).strip() if isinstance(machine, dict) else ""
                logging.error(f"""{prefix} record type "{rt}" - should be one of {PAM_IMPORT_RESOURCE_TYPES}, "{title}" record skipped.""")
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
            elif rt == "pamCloudResource".lower():
                obj = PamCloudResourceObject.load(machine, rotation_params)
            else:
                logging.warning(f"""Skipping unknown resource type "{rt}" """)

            if obj:
                resources.append(obj)

        assign_uids(chain(resources, users), only_new=False)

        # Detect and reject duplicate UIDs to prevent graph ambiguity
        _all_assigned_uids: list[str] = []
        for _obj in chain(resources, users):
            _all_assigned_uids.append(_obj.uid)
            if hasattr(_obj, 'users') and isinstance(_obj.users, list):
                for _usr in _obj.users:
                    _all_assigned_uids.append(_usr.uid)
        _seen_uids: set[str] = set()
        _duplicate_uids: list[str] = []
        for _uid in _all_assigned_uids:
            if _uid in _seen_uids:
                _duplicate_uids.append(_uid)
            _seen_uids.add(_uid)
        if _duplicate_uids:
            print(
                f"{bcolors.FAIL}pam project import: duplicate uid values detected in import JSON: "
                f"{', '.join(sorted(set(_duplicate_uids)))}. "
                f"Each resource and user must have a unique uid. Import aborted.{bcolors.ENDC}"
            )
            return

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

            # launch_credentials: resolve to pamUser UID for pamMachine, pamDatabase, pamDirectory (not RBI)
            launch_cred = get_launch_credential(mach)
            if launch_cred and not isinstance(mach, PamRemoteBrowserObject):
                ruids = find_user(mach, users, launch_cred)
                if not ruids:
                    ruids = find_external_user(mach, machines, launch_cred)
                if len(ruids) != 1:
                    logging.warning(f"{bcolors.WARNING}{len(ruids)} matches found for launch_credentials in {mach.title}.{bcolors.ENDC} ")
                ruid = getattr(ruids[0], "uid", "") if ruids else ""
                if ruid:
                    set_launch_record_uid(mach, ruid)

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
                    if (isinstance(mach, PamCloudResourceObject) and matches
                            and not isinstance(matches[0], PamUserObject)):
                        # the Gateway standalone launch actions read the credential through the PAM record types only
                        logging.warning(f"{bcolors.WARNING}PAM Cloud {mach.title}: autofill_credentials '{cred}' is not a "
                                        f"pamUser - use a pamUser record (not resolved).{bcolors.ENDC}")
                        matches = []
                    uid = getattr(matches[0], "uid", "") if matches else ""
                    if uid:
                        mach.rbi_settings.connection.httpCredentialsUid = [uid]

        # Local users on machines/databases/directories with external AD admin may have empty passwords (AD rotates them).
        mark_local_users_allowing_empty_password_for_external_admin(resources)

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

        # Stamp resolved_folder_uid for batch routing.
        # Explicit folder_path from import JSON wins (via folder_path_map).
        # When unspecified: pamUser/login → Users; resource types → Resources.
        for user in users:
            user.resolved_folder_uid = _resolve_folder_uid(user, shfusr)
        for mach in resources:
            mach.resolved_folder_uid = _resolve_folder_uid(mach, shfres)
            for user in getattr(mach, "users", None) or []:
                user.resolved_folder_uid = _resolve_folder_uid(user, shfusr)

        # pre-flight: validate workflow team UIDs before any vault writes (runs in dry-run too)
        validate_workflow_principals(params, resources)

        # dry run — simulate batch plan without vault writes
        if project["options"].get("dry_run", False) is True:
            engine = BatchPamImportEngine(
                params, project, users, resources,
                users_folder_uid=shfusr,
                resources_folder_uid=shfres,
                pam_cfg_uid=pam_cfg_uid,
                extend_mode=False,
            )
            plan = engine.simulate()
            print(json.dumps(plan, indent=2))
            print("[DRY RUN COMPLETE] No vault/DAG writes.")
            return

        print("Started importing data...")

        engine = BatchPamImportEngine(
            params, project, users, resources,
            users_folder_uid=shfusr,
            resources_folder_uid=shfres,
            pam_cfg_uid=pam_cfg_uid,
            extend_mode=False,
        )
        if not engine.run():
            print(f"{bcolors.FAIL}Import aborted due to batch vault/DAG failure.{bcolors.ENDC}")
            return

        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_cfg_uid, True,
                         transmission_key=transmission_key)

        # Import tail: config cred scripts, then domain admin (NSF-aware).
        run_import_tail(
            params, pam_cfg_uid, pce, tdag,
            project_options=project.get("options") or {},
            users_folder_uid=(project.get("folders") or {}).get("users_folder_uid", ""),
        )

        logging.debug("Done processing project data.")
