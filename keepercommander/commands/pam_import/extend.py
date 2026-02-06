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
import re

from itertools import chain
from typing import Any, Dict, Optional, List

from ...loginv3 import CommonHelperMethods
url_safe_str_to_bytes = CommonHelperMethods.url_safe_str_to_bytes

from .base import (
    PAM_RESOURCES_RECORD_TYPES,
    PamUserObject,
    LoginUserObject,
    PamBaseMachineParser,
    PamMachineObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamRemoteBrowserObject,
    PamRotationParams,
    PamRotationSettingsObject,
    add_pam_scripts,
    find_external_user,
    find_user,
    get_admin_credential,
    get_sftp_attribute,
    is_admin_external,
    parse_command_options,
    resolve_script_creds,
    set_sftp_uid,
    set_user_record_uid
)
from ..base import Command
from ..ksm import KSMCommand
from ..pam import gateway_helper
from ..pam.config_helper import configuration_controller_get
from ..tunnel.port_forward.TunnelGraph import TunnelDAG
from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens
from ... import api, crypto, utils, vault, vault_extensions
from ...display import bcolors
from ...error import CommandError
from ...params import LAST_FOLDER_UID, LAST_SHARED_FOLDER_UID
from ...proto import APIRequest_pb2, enterprise_pb2, pam_pb2, record_pb2
from ...recordv3 import RecordV3
from ...subfolder import BaseFolderNode

def split_folder_path(path: str) -> list[str]:
    """Split folder path using path deilmiter / (escape: / -> //)"""

    # Escape char / confusion: a///b -> [a/]/[b] or [a]/[/b]
    # Escape char ` or ^ (since \ is hard to put in strings and JSON)
    # ...yet again a``/b -> [a`/b] or [a`]/[b]

    # Note: using / as escape char and path delimiter: / <-> //
    placeholder = "\x00"  # unlikely to appear in folder names
    tmp = path.replace("//", placeholder).rstrip("/")
    parts = tmp.split("/")  # split on remaining single slashes
    res = [part.replace(placeholder, "/") for part in parts]

    # check for bad path (odd number of slashes): a///b or a/////b etc.
    if re.search(r"(?<!/)/(?://)+(?!/)", path):
        logging.warning(f"""Dangerous folder path "{path}" - make sure """
                        f"it is properly parsed (and correct it accordingly) {res}")
    return res

def process_folder_paths(folder_paths, ksm_shared_folders):
    """Process folder paths to separate good from bad paths and update folder trees.

    Args:
        folder_paths: List of folder path strings to process
        ksm_shared_folders: List of KSM shared folder dictionaries with folder_tree

    Returns:
        Tuple of (good_paths, bad_paths)
    """
    good_paths = []
    bad_paths = []

    # Build a mapping of shared folder names to their data
    sf_name_map = {shf['name']: shf for shf in ksm_shared_folders}

    # Process paths to build dependency graph
    path_dependencies = {}  # Maps path to its parsed parts
    for path in folder_paths:
        parts = split_folder_path(path)
        path_dependencies[path] = parts

    # Identify root folders in shared folders
    root_folders = set()
    for path, parts in path_dependencies.items():
        if parts and parts[0] in sf_name_map:
            root_folders.add(parts[0])

    # Resolve dependencies and classify paths
    iterations = 0
    processed_paths = set()
    max_iterations = len(folder_paths) * 2  # Prevent infinite loops

    while len(processed_paths) < len(folder_paths) and iterations < max_iterations:
        iterations += 1
        for path, parts in path_dependencies.items():
            if path in processed_paths:
                continue

            if not parts:
                bad_paths.append((path, "Empty path"))
                processed_paths.add(path)
                continue

            # Check if root exists in shared folders
            root = parts[0]
            if root not in sf_name_map:
                # Check if this could be a partial path that appears in multiple places
                possible_parents = []
                for existing_path, existing_parts in path_dependencies.items():
                    if existing_path != path:
                        # Check if this path could be a continuation of an existing path
                        # ex. "sub1/sub2" could be under "sf1/sub1" or "sf2/sub1"
                        if len(existing_parts) > 0 and existing_parts[-1] == root:
                            possible_parents.append(existing_path)

                if len(possible_parents) > 1:
                    # Ambiguous: this partial path could belong to multiple locations
                    bad_paths.append((path, f"Ambiguous: '{root}' appears in multiple locations {possible_parents}"))
                    processed_paths.add(path)
                elif len(possible_parents) == 1:
                    # This is a dependent path that needs parent to exist first
                    # Wait for parent to be processed (don't mark as processed yet)
                    pass
                else:
                    # No possible parents found - truly a bad path
                    bad_paths.append((path, f"Root folder '{root}' not found in shared folders"))
                    processed_paths.add(path)
            else:
                # Check for ambiguous paths (multiple possible locations)
                matching_roots = []
                for sf_name in sf_name_map:
                    if path.startswith(sf_name + "/") or path == sf_name:
                        matching_roots.append(sf_name)

                if len(matching_roots) > 1:
                    bad_paths.append((path, f"Ambiguous: maps to multiple roots {matching_roots}"))
                else:
                    good_paths.append((path, parts))
                processed_paths.add(path)

    # Add paths to the corresponding folder trees
    for path, parts in good_paths:
        if parts and parts[0] in sf_name_map:
            shf = sf_name_map[parts[0]]
            current_level = shf['folder_tree']

            # Navigate/create the folder structure
            for _, folder_name in enumerate(parts[1:], 1):
                if folder_name not in current_level:
                    current_level[folder_name] = {
                        'uid': '',  # Empty UID for new folders
                        'name': folder_name,
                        'subfolders': {}
                    }
                current_level = current_level[folder_name]['subfolders']

    return good_paths, bad_paths

def build_tree_recursive(params, folder_uid: str):
    """Recursively build tree for a folder and its subfolders"""
    tree = {}
    folder = params.folder_cache.get(folder_uid)
    if not folder:
        return tree

    for subfolder_uid in folder.subfolders:
        subfolder = params.folder_cache.get(subfolder_uid)
        if subfolder:
            folder_name = subfolder.name or ''
            tree[folder_name] = {
                'uid': subfolder.uid,
                'name': folder_name,
                'subfolders': build_tree_recursive(params, subfolder.uid)
            }

    return tree

class PAMProjectExtendCommand(Command):
    parser = argparse.ArgumentParser(prog="pam project extend")
    parser.add_argument("--config", "-c", required=True, dest="config", action="store", help="PAM Configuration UID or Title")
    parser.add_argument("--filename", "-f", required=True, dest="file_name", action="store", help="File to load import data from.")
    parser.add_argument("--dry-run", "-d", required=False, dest="dry_run", action="store_true", default=False, help="Test import without modifying vault.")

    def get_parser(self):
        return PAMProjectExtendCommand.parser

    def execute(self, params, **kwargs):
        dry_run = kwargs.get("dry_run", False) is True
        file_name = str(kwargs.get("file_name") or "")
        config_name = str(kwargs.get("config") or "")

        api.sync_down(params)

        configuration = None
        if config_name in params.record_cache:
            configuration = vault.KeeperRecord.load(params, config_name)
        else:
            l_name = config_name.casefold()
            for c in vault_extensions.find_records(params, record_version=6):
                if c.title.casefold() == l_name:
                    configuration = c
                    break

        if not (configuration and isinstance(configuration, vault.TypedRecord) and configuration.version == 6):
            raise CommandError("pam project extend", f"""PAM configuration not found: "{config_name}" """)

        if not (file_name != "" and os.path.isfile(file_name)):
            raise CommandError("pam project extend", f"""PAM Import JSON file not found: "{file_name}" """)

        data = {}
        try:
            with open(file_name, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}

        pam_data = data.get("pam_data") if isinstance(data, dict) else {}
        pam_data = pam_data if isinstance(pam_data, dict) else {}
        users =  pam_data["users"] if isinstance(pam_data.get("users"), list) else []
        resources = pam_data["resources"] if isinstance(pam_data.get("resources"), list) else []
        if not (resources or users):
            raise CommandError("pam project extend", f"""PAM data missing - file "{file_name}" """
                               """must be a valid JSON ex. {"pam_data": {"resources": [], "users":[]}} """)

        has_extra_keys = any(key != "pam_data" for key in data) if isinstance(data, dict) else False
        if has_extra_keys:
            logging.warning(f"{bcolors.WARNING}WARNING: Import JSON contains extra data - "
                            f"""`extend` command uses only "pam_data": {{ }} {bcolors.ENDC}""")

        if dry_run:
            print("[DRY RUN] No changes will be made. This is a simulation only.")

        # Find Controller/Gateway/App from PAM Configuration
        controller = configuration_controller_get(params, url_safe_str_to_bytes(configuration.record_uid))
        if not (controller and isinstance(controller, pam_pb2.PAMController) and controller.controllerUid): # pylint: disable=no-member
            raise CommandError("pam project extend", f"{bcolors.FAIL}"
                               f"Gateway UID not found for configuration {configuration.record_uid}.")

        ksmapp_uid = None
        gateway_uid = utils.base64_url_encode(controller.controllerUid)
        all_gateways = gateway_helper.get_all_gateways(params)
        found_gateways = list(filter(lambda g: g.controllerUid == controller.controllerUid, all_gateways))
        if found_gateways and found_gateways[0]:
            ksmapp_uid = utils.base64_url_encode(found_gateways[0].applicationUid)
        if ksmapp_uid is None:
            raise CommandError("pam project extend", f"{bcolors.FAIL}"
                               f"KSM APP UID not found for Gateway {gateway_uid}.")
        ksm_app_record = vault.KeeperRecord.load(params, ksmapp_uid)
        if not (ksm_app_record and isinstance(ksm_app_record, vault.ApplicationRecord) and ksm_app_record.version == 5):
            raise CommandError("pam project extend", f"""PAM KSM Application record not found: "{ksmapp_uid}" """)

        # Find KSM Application shared folders
        ksm_shared_folders = self.get_app_shared_folders(params, ksmapp_uid)
        if not ksm_shared_folders:
            raise CommandError("pam project extend", f""" No shared folders found for KSM Application: "{ksmapp_uid}" """)

        if dry_run:
            print(f"[DRY RUN] Will use PAM Configuration: {configuration.record_uid}  {configuration.title}")
            print(f"[DRY RUN] Will use PAM Gateway:       {gateway_uid}  {controller.controllerName}")
            print(f"[DRY RUN] Will use KSM Application:   {ksmapp_uid}  {ksm_app_record.title}")
            print(f"[DRY RUN] Total shared folders found for the KSM App: {len(ksm_shared_folders)}")
            for shf in ksm_shared_folders:
                uid, name, permissions = shf.get("uid"), shf.get("name"), shf.get("permissions")
                print(f"""[DRY RUN] Found shared folder: {uid} "{name}" ({permissions})""")

        for shf in ksm_shared_folders:
            shf['folder_tree'] = build_tree_recursive(params, shf['uid'])

        # NB! Extract all paths first to resolve inner dependencies for partial paths
        # TODO: parse from data JSON
        folder_paths = ["gwapp", "gwapp/folder", "gwapp/f2", "gwapp/f3/f4/f5",
                        "gwapp///bad", "bad", "gw/bad", "f7/bad",
                        "f6/good", "gwapp_/f6",
                        "gwapp/f7", "gwapp_/f7"]

        # Process folder paths and update folder trees
        good_paths, bad_paths = process_folder_paths(folder_paths, ksm_shared_folders)

        if dry_run:
            print(f"[DRY RUN] Processed {len(folder_paths)} folder paths:")
            print(f"[DRY RUN]   - Good paths: {len(good_paths)}")
            for path, _ in good_paths:
                print(f"[DRY RUN]     ✓ {path}")
            print(f"[DRY RUN]   - Bad paths: {len(bad_paths)}")
            for path, reason in bad_paths:
                print(f"[DRY RUN]     ✗ {path}: {reason}")

        folder_trees = [shf['folder_tree'] for shf in ksm_shared_folders]

        if dry_run:
            print("[DRY RUN COMPLETE] No changes were made. All actions were validated but not executed.")

    def get_app_shared_folders(self, params, ksm_app_uid: str) -> list[dict]:
        ksm_shared_folders = []

        try:
            app_info_list = KSMCommand.get_app_info(params, ksm_app_uid)
            if app_info_list and len(app_info_list) > 0:
                app_info = app_info_list[0]
                shares = [x for x in app_info.shares if x.shareType == APIRequest_pb2.SHARE_TYPE_FOLDER] # pylint: disable=no-member
                for share in shares:
                    folder_uid = utils.base64_url_encode(share.secretUid)
                    if folder_uid in params.shared_folder_cache:
                        cached_sf = params.shared_folder_cache[folder_uid]
                        folder_name = cached_sf.get('name_unencrypted', 'Unknown')
                        is_editable = share.editable if hasattr(share, 'editable') else False

                        ksm_shared_folders.append({
                            'uid': folder_uid,
                            'name': folder_name,
                            'editable': is_editable,
                            'permissions': "Editable" if is_editable else "Read-Only"
                        })
        except Exception as e:
            logging.error(f"Could not retrieve KSM application shares: {e}")

        return ksm_shared_folders

    def process_folders(self, params, project: dict) -> dict:
        res = {}
        # FolderListCommand().execute(params, folders_only=True, pattern="/")
        # TODO folders = self.find_folders(params, res["root_folder_uid"], folder_name, False)
        # TODO folders = [x for x in folders if x.type == x.UserFolderType]
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
            # TODO: fuid = self.create_subfolder(params, folder_name=res["project_folder"], parent_uid=res["root_folder_uid"])
            fuid = self.create_subfolder(params, res["root_folder_target"])
            res["root_folder_uid"] = fuid
        api.sync_down(params)
        return res

    def create_subfolder(self, params, folder_name:str, parent_uid:str="", permissions:Optional[Dict]=None):
        # TODO: only need create_folder|force_folders(self, params, path)

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
        pce = project["pam_config"].get("pam_config_object", None)
        if pce and pce.scripts and pce.scripts.scripts:
            resolve_script_creds(pce, users, resources)
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

        encrypted_session_token, encrypted_transmission_key, _ = get_keeper_tokens(params)
        tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_cfg_uid, True)
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

        # add scripts with resolved additional credentials - owner records must exist
        if pce and pce.scripts and pce.scripts.scripts:
            refs = [x for x in pce.scripts.scripts if x.record_refs]
            if refs:
                api.sync_down(params)
                add_pam_scripts(params, pam_cfg_uid, refs)

        logging.debug("Done processing project data.")

