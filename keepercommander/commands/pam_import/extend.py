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


def _collect_path_to_uid_from_tree(path_prefix: str, tree: dict, path_to_uid: dict, only_existing: bool) -> None:
    """Walk folder tree and fill path_to_uid. path_prefix e.g. 'gwapp', tree is shf['folder_tree'].
    If only_existing, only add when node['uid'] is non-empty."""
    for name, node in (tree or {}).items():
        path = f"{path_prefix}/{name}" if path_prefix else name
        uid = (node or {}).get("uid") or ""
        if only_existing and not uid:
            continue
        if uid:
            path_to_uid[path] = uid
        subfolders = (node or {}).get("subfolders") or {}
        if subfolders:
            _collect_path_to_uid_from_tree(path, subfolders, path_to_uid, only_existing)


def _count_existing_and_new_paths(ksm_shared_folders: list, good_paths: list) -> tuple:
    """Return (x_count, y_count, existing_paths_set, new_nodes_list).
    existing_paths_set = set of full paths that exist (all segments have uid).
    new_nodes_list = list of (full_path, parent_path, segment_name, node_ref) for each node with uid '', sorted by path (parent before child)."""
    sf_name_map = {shf["name"]: shf for shf in ksm_shared_folders}
    existing_paths = set()
    new_nodes_list = []  # (full_path, parent_path, segment_name, node_dict)

    for path, parts in good_paths:
        if not parts or parts[0] not in sf_name_map:
            continue
        root_name = parts[0]
        if len(parts) == 1:
            existing_paths.add(path)
            continue
        tree = sf_name_map[root_name].get("folder_tree") or {}
        current = tree
        prefix = root_name
        parent_path = root_name
        for i in range(1, len(parts)):
            name = parts[i]
            path_so_far = f"{prefix}/{name}" if prefix else name
            node = current.get(name) if isinstance(current, dict) else None
            if not node:
                break
            uid = node.get("uid") or ""
            if uid:
                existing_paths.add(path_so_far)
                parent_path = path_so_far
            else:
                new_nodes_list.append((path_so_far, parent_path, name, node))
                parent_path = path_so_far
            current = node.get("subfolders") or {}
            prefix = path_so_far

    # Dedupe new nodes by path and sort so parent before child
    seen = set()
    deduped = []
    for item in new_nodes_list:
        if item[0] not in seen:
            seen.add(item[0])
            deduped.append(item)
    deduped.sort(key=lambda x: (x[0].count("/"), x[0]))
    x_count = len(existing_paths)
    y_count = len(deduped)
    return (x_count, y_count, existing_paths, deduped)


def _collect_all_folder_uids_under_ksm(ksm_shared_folders: list) -> set:
    """Return set of all folder UIDs (shared folder roots + all descendants) under KSM app."""
    out = set()
    for shf in ksm_shared_folders:
        out.add(shf["uid"])
        tree = shf.get("folder_tree") or {}

        def walk(t):
            for name, node in (t or {}).items():
                uid = (node or {}).get("uid")
                if uid:
                    out.add(uid)
                walk((node or {}).get("subfolders") or {})

        walk(tree)
    return out


def _get_ksm_app_record_uids(params, ksm_shared_folders: list) -> set:
    """Return set of all record UIDs in any folder shared to the KSM app."""
    folder_uids = _collect_all_folder_uids_under_ksm(ksm_shared_folders)
    record_uids = set()
    subfolder_record_cache = getattr(params, "subfolder_record_cache", None) or {}
    for fuid in folder_uids:
        if fuid in subfolder_record_cache:
            record_uids.update(subfolder_record_cache[fuid])
    return record_uids


def _get_records_in_folder(params, folder_uid: str):
    """Return list of (record_uid, title, record_type) for records in folder_uid.
    record_type from record for autodetect (e.g. pamUser, pamMachine, login)."""
    subfolder_record_cache = getattr(params, "subfolder_record_cache", None) or {}
    result = []
    for ruid in subfolder_record_cache.get(folder_uid, []):
        try:
            rec = vault.KeeperRecord.load(params, ruid)
            title = getattr(rec, "title", "") or ""
            rtype = ""
            if hasattr(rec, "record_type"):
                rtype = getattr(rec, "record_type", "") or ""
            result.append((ruid, title, rtype))
        except Exception:
            pass
    return result


def _get_all_ksm_app_records(params, ksm_shared_folders: list) -> list:
    """Return list of (record_uid, title, record_type) for every record in any folder under KSM app."""
    folder_uids = _collect_all_folder_uids_under_ksm(ksm_shared_folders)
    out = []
    for fuid in folder_uids:
        out.extend(_get_records_in_folder(params, fuid))
    return out


def _folder_uids_under_shf(shf: dict) -> set:
    """Return set of folder UIDs under this shared folder (root + all descendants from folder_tree)."""
    out = {shf.get("uid")}
    tree = shf.get("folder_tree") or {}

    def walk(t):
        for name, node in (t or {}).items():
            uid = (node or {}).get("uid")
            if uid:
                out.add(uid)
            walk((node or {}).get("subfolders") or {})

    walk(tree)
    return out


def _is_resource_type(obj) -> bool:
    """True if object is a PAM resource (machine, database, directory, remote browser)."""
    t = (getattr(obj, "type", None) or "").lower()
    return t in ("pammachine", "pamdatabase", "pamdirectory", "pamremotebrowser")


def _record_identifier(obj, fallback_login: str = "") -> str:
    """Return identifier for error messages: uid if present, else title, else login (for users)."""
    uid = getattr(obj, "uid_imported", None) or getattr(obj, "uid", None)
    if uid and isinstance(uid, str) and RecordV3.is_valid_ref_uid(uid):
        return f'uid "{uid}"'
    title = getattr(obj, "title", None) or ""
    if title:
        return f'"{title}"'
    login = getattr(obj, "login", None) or fallback_login
    return f'login "{login}"' if login else "record"


def _has_autogenerated_title(obj) -> bool:
    """True if obj has title set by base.py when missing in JSON. base.py uses:
    pamUser -> PAM User - {login}; pamMachine -> PAM Machine - {login};
    pamDatabase -> PAM Database - {databaseId}; pamDirectory -> PAM Directory - {domainName};
    pamRemoteBrowser (RBI) -> PAM RBI - {hostname from rbiUrl}."""
    rtype = (getattr(obj, "type", None) or "").lower()
    title = (getattr(obj, "title", None) or "").strip()
    login = (getattr(obj, "login", None) or "").strip()
    if rtype == "pamuser" and login and title == f"PAM User - {login}":
        return True
    if rtype == "pammachine" and login and title == f"PAM Machine - {login}":
        return True
    database_id = (getattr(obj, "databaseId", None) or "").strip()
    if rtype == "pamdatabase" and database_id and title == f"PAM Database - {database_id}":
        return True
    domain_name = (getattr(obj, "domainName", None) or "").strip()
    if rtype == "pamdirectory" and domain_name and title == f"PAM Directory - {domain_name}":
        return True
    if rtype == "pamremotebrowser" and getattr(obj, "rbiUrl", None) and title.startswith("PAM RBI - "):
        return True
    return False


def _vault_title_matches_import(vault_title: str, import_title: str) -> bool:
    """True if vault record title matches import title verbatim (both already in same form, e.g. from base.py)."""
    return (vault_title or "").strip() == (import_title or "").strip()


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
            shf["folder_tree"] = build_tree_recursive(params, shf["uid"])

        project = {
            "data": {"pam_data": pam_data},
            "options": {"dry_run": dry_run},
            "ksm_shared_folders": ksm_shared_folders,
            "folders": {},
            "pam_config": {"pam_config_uid": configuration.record_uid, "pam_config_object": None},
            "error_count": 0,
        }

        self.process_folders(params, project)
        self.map_records(params, project)
        if project.get("error_count", 0) == 0:
            has_new_no_path = False
            for o in chain(project.get("mapped_resources", []), project.get("mapped_users", [])):
                if getattr(o, "_extend_tag", None) == "new" and not (getattr(o, "folder_path", None) or "").strip():
                    has_new_no_path = True
                    break
            if not has_new_no_path:
                for mach in project.get("mapped_resources", []):
                    if hasattr(mach, "users") and isinstance(mach.users, list):
                        for u in mach.users:
                            if getattr(u, "_extend_tag", None) == "new" and not (getattr(u, "folder_path", None) or "").strip():
                                has_new_no_path = True
                                break
                    if has_new_no_path:
                        break
            if has_new_no_path:
                self.autodetect_folders(params, project)

        err_count = project.get("error_count", 0)
        new_count = project.get("new_record_count", 0)
        if err_count > 0:
            print(f"{err_count} errors; aborting. No changes made to vault.")
            print("Use --dry-run option to see detailed error messages.")
            return
        if new_count == 0:
            print("Nothing to update")
            return

        path_to_folder_uid = (project.get("folders") or {}).get("path_to_folder_uid") or {}
        res_folder_uid = (project.get("folders") or {}).get("resources_folder_uid", "")
        usr_folder_uid = (project.get("folders") or {}).get("users_folder_uid", "")

        for o in chain(project.get("mapped_resources", []), project.get("mapped_users", [])):
            if getattr(o, "_extend_tag", None) != "new":
                continue
            fp = (getattr(o, "folder_path", None) or "").strip()
            o.resolved_folder_uid = path_to_folder_uid.get(fp) or (res_folder_uid if _is_resource_type(o) else usr_folder_uid)
        for mach in project.get("mapped_resources", []):
            if hasattr(mach, "users") and isinstance(mach.users, list):
                for u in mach.users:
                    if getattr(u, "_extend_tag", None) != "new":
                        continue
                    fp = (getattr(u, "folder_path", None) or "").strip()
                    u.resolved_folder_uid = path_to_folder_uid.get(fp) or usr_folder_uid

        if dry_run:
            print("[DRY RUN COMPLETE] No changes were made. All actions were validated but not executed.")
            return
        self.process_data(params, project)

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
        """Step 1: Parse folder_paths from pam_data, build tree, process paths, optionally create new folders.
        Fills project['folders'] with path_to_folder_uid, good_paths, bad_paths; updates project['error_count']."""
        data = project.get("data") or {}
        pam_data = data.get("pam_data") or {}
        resources = pam_data.get("resources") or []
        users = pam_data.get("users") or []
        options = project.get("options") or {}
        dry_run = options.get("dry_run", False) is True
        ksm_shared_folders = project.get("ksm_shared_folders") or []
        folders_out = project.get("folders") or {}
        project["folders"] = folders_out

        # Collect unique folder_paths from resources, nested machine.users[], and top-level users (raw dicts)
        folder_paths_set = set()
        for r in resources:
            if isinstance(r, dict):
                if r.get("folder_path"):
                    folder_paths_set.add((r["folder_path"],))
                for nested in r.get("users") or []:
                    if isinstance(nested, dict) and nested.get("folder_path"):
                        folder_paths_set.add((nested["folder_path"],))
        for u in users:
            if isinstance(u, dict) and u.get("folder_path"):
                folder_paths_set.add((u["folder_path"],))
        folder_paths = list(set(fp[0] for fp in folder_paths_set))

        good_paths, bad_paths = process_folder_paths(folder_paths, ksm_shared_folders)

        path_to_folder_uid = {}
        has_errors = bool(bad_paths)
        for shf in ksm_shared_folders:
            name = shf.get("name") or ""
            if name:
                path_to_folder_uid[name] = shf["uid"]
            _collect_path_to_uid_from_tree(
                name,
                shf.get("folder_tree") or {},
                path_to_folder_uid,
                only_existing=has_errors,
            )

        x_count, y_count, existing_paths_set, new_nodes_list = _count_existing_and_new_paths(
            ksm_shared_folders, good_paths
        )

        # Pre-generate UIDs for new folders (same as records: known before create). Fills path_to_folder_uid
        # so dry run and map_records can resolve folder_path for all good paths.
        for full_path, _parent_path, _name, node in new_nodes_list:
            if not (node or {}).get("uid"):
                uid = api.generate_record_uid()
                node["uid"] = uid
                path_to_folder_uid[full_path] = uid

        step1_errors = [(path, reason) for path, reason in bad_paths]
        if step1_errors:
            project["error_count"] = project.get("error_count", 0) + len(step1_errors)

        # Folder path printing: dry run always; normal run only if errors or Y > 0
        print_paths = dry_run or step1_errors or y_count > 0
        if print_paths:
            prefix = "[DRY RUN] " if dry_run else ""
            print(f"{prefix}Processed {len(folder_paths)} folder paths:")
            print(f"{prefix}  - Good paths: {len(good_paths)}")
            for path, _ in good_paths:
                tag = "existing" if path in existing_paths_set else "new"
                if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
                    print(f"{prefix}    [{tag}] {path}")
                else:
                    print(f"{prefix}    ✓ {path}")
            print(f"{prefix}  - Bad paths: {len(bad_paths)}")
            for path, reason in bad_paths:
                print(f"{prefix}    ✗ {path}: {reason}")
            if step1_errors:
                print(f"Total: {len(step1_errors)} errors")

        if not dry_run and not step1_errors and new_nodes_list:
            sf_name_map = {shf["name"]: shf for shf in ksm_shared_folders}
            for full_path, parent_path, name, node in new_nodes_list:
                parent_uid = path_to_folder_uid.get(parent_path, "")
                if not parent_uid and parent_path in sf_name_map:
                    parent_uid = sf_name_map[parent_path]["uid"]
                new_uid = self.create_subfolder(params, name, parent_uid, folder_uid=node.get("uid"))
                node["uid"] = new_uid
                path_to_folder_uid[full_path] = new_uid
            api.sync_down(params)

        existing_msg = f"{x_count} existing folders (skipped)" if x_count else "0 existing folders"
        if dry_run:
            print(f"[DRY RUN] {existing_msg}, {y_count} new folders to be created")
        else:
            print(f"{existing_msg}, {y_count} new folders created")

        if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
            for path, _ in good_paths:
                tag = "existing" if path in existing_paths_set else "new"
                print(f"  [DEBUG] [{tag}] {path}")

        folders_out["path_to_folder_uid"] = path_to_folder_uid
        folders_out["good_paths"] = good_paths
        folders_out["bad_paths"] = bad_paths
        folders_out["folder_stats_x"] = x_count
        folders_out["folder_stats_y"] = y_count
        return folders_out

    def map_records(self, params, project: dict) -> tuple:
        """Step 2: Parse resources/users, tag existing vs new, set obj.uid; collect errors.
        Returns (resources, users, step2_errors, new_record_count). Updates project['error_count']."""
        data = project.get("data") or {}
        pam_data = data.get("pam_data") or {}
        path_to_folder_uid = (project.get("folders") or {}).get("path_to_folder_uid") or {}
        ksm_shared_folders = project.get("ksm_shared_folders") or []
        options = project.get("options") or {}
        dry_run = options.get("dry_run", False) is True

        rotation_profiles = pam_data.get("rotation_profiles") or {}
        if not isinstance(rotation_profiles, dict):
            rotation_profiles = {}
        pam_cfg_uid = (project.get("pam_config") or {}).get("pam_config_uid", "")
        rotation_params = PamRotationParams(configUid=pam_cfg_uid, profiles=rotation_profiles)

        usrs = pam_data.get("users") or []
        rsrs = pam_data.get("resources") or []
        users = []
        resources = []

        for user in usrs:
            rt = str(user.get("type", "")) if isinstance(user, dict) else ""
            rt = next((x for x in ("login", "pamUser") if x.lower() == rt.lower()), rt)
            if rt not in ("login", "pamUser") and isinstance(user, dict):
                pam_keys = ("private_pem_key", "distinguished_name", "connect_database", "managed", "scripts", "rotation_settings")
                if user.get("url"): rt = "login"
                elif any(k in user for k in pam_keys): rt = "pamUser"
            rt = next((x for x in ("login", "pamUser") if x.lower() == rt.lower()), "login")
            if rt == "login":
                usr = LoginUserObject.load(user)
            else:
                usr = PamUserObject.load(user)
            if usr:
                users.append(usr)

        for machine in rsrs:
            rt = str(machine.get("type", "")).strip() if isinstance(machine, dict) else ""
            if rt.lower() not in (x.lower() for x in PAM_RESOURCES_RECORD_TYPES):
                title = str(machine.get("title", "")).strip() if isinstance(machine, dict) else ""
                logging.error(f"Incorrect record type \"{rt}\" - should be one of {PAM_RESOURCES_RECORD_TYPES}, \"{title}\" record skipped.")
                continue
            obj = None
            rtl = rt.lower()
            if rtl == "pamdatabase":
                obj = PamDatabaseObject.load(machine, rotation_params)
            elif rtl == "pamdirectory":
                obj = PamDirectoryObject.load(machine, rotation_params)
            elif rtl == "pammachine":
                obj = PamMachineObject.load(machine, rotation_params)
            elif rtl == "pamremotebrowser":
                obj = PamRemoteBrowserObject.load(machine, rotation_params)
            if obj:
                resources.append(obj)

        for obj in chain(resources, users):
            if not (isinstance(getattr(obj, "uid", None), str) and RecordV3.is_valid_ref_uid(obj.uid)):
                obj.uid = utils.generate_uid()
            if hasattr(obj, "users") and isinstance(obj.users, list):
                for usr in obj.users:
                    if not (isinstance(getattr(usr, "uid", None), str) and RecordV3.is_valid_ref_uid(usr.uid)):
                        usr.uid = utils.generate_uid()

        ksm_app_uids = _get_ksm_app_record_uids(params, ksm_shared_folders)
        all_ksm_records = _get_all_ksm_app_records(params, ksm_shared_folders)
        good_paths = (project.get("folders") or {}).get("good_paths") or []
        good_paths_set = {p for p, _ in good_paths}
        step2_errors = []

        def _scope_key(obj, good_paths_set):
            # Scope by folder only if path is good (exists or to be created); else "global".
            # "Global" means: SHF shared to KSM App; for users → autodetected users folder (or single
            # folder for both); for resources → autodetected resources folder (or same single folder).
            # 0 or 3+ autodetected folders is an error anyway. Users are never scoped by machine.
            fp = (getattr(obj, "folder_path", None) or "").strip()
            if fp and fp in good_paths_set:
                return fp
            return "global"

        seen_scope_title = {}  # (scope_key, title) -> list of (ident, machine_suffix) for error message
        for o in chain(resources, users):
            scope = _scope_key(o, good_paths_set)
            title = (getattr(o, "title", None) or "").strip()
            if title:
                key = (scope, title)
                ident = _record_identifier(o)
                seen_scope_title.setdefault(key, []).append((ident, ""))
        for mach in resources:
            if hasattr(mach, "users") and isinstance(mach.users, list):
                for u in mach.users:
                    scope = _scope_key(u, good_paths_set)
                    title = (getattr(u, "title", None) or "").strip()
                    if title:
                        key = (scope, title)
                        ident = _record_identifier(u)
                        suffix = f' (nested on machine "{getattr(mach, "title", "")}")'
                        seen_scope_title.setdefault(key, []).append((ident, suffix))

        for (scope, title), idents in seen_scope_title.items():
            if len(idents) > 1:
                scope_msg = f"folder {scope}" if scope != "global" else "global"
                step2_errors.append(
                    f'ERROR: Duplicate import records with same title "{title}" in same scope ({scope_msg}). '
                    f'Add explicit "title" in JSON to disambiguate.'
                )

        def resolve_one(obj, parent_machine=None):
            ident = _record_identifier(obj)
            machine_suffix = ""
            if parent_machine:
                mt = getattr(parent_machine, "title", None) or ""
                mu = getattr(parent_machine, "uid", None) or ""
                machine_suffix = f' user on machine "{mt}"' if mt else f" user on machine <{mu}>"

            uid_imp = getattr(obj, "uid_imported", None)
            if uid_imp and isinstance(uid_imp, str) and RecordV3.is_valid_ref_uid(uid_imp):
                if uid_imp not in ksm_app_uids:
                    step2_errors.append(f'uid "{uid_imp}" not found in KSM app for record {ident}{machine_suffix}')
                    return
                obj.uid = uid_imp
                obj._extend_tag = "existing"
                return

            folder_path = getattr(obj, "folder_path", None) or ""
            title = (getattr(obj, "title", None) or "").strip()
            login = (getattr(obj, "login", None) or "").strip()

            if folder_path:
                folder_uid = path_to_folder_uid.get(folder_path)
                if not folder_uid:
                    if folder_path in good_paths_set:
                        obj._extend_tag = "new"
                        return
                    step2_errors.append(f'folder_path "{folder_path}" could not be resolved for record {ident}{machine_suffix}')
                    return
                if not title and not login:
                    obj._extend_tag = "new"
                    return
                recs = _get_records_in_folder(params, folder_uid)
                matches = [r for r in recs if _vault_title_matches_import(r[1], title)]
                if len(matches) == 0:
                    obj._extend_tag = "new"
                    return
                if len(matches) == 1:
                    obj.uid = matches[0][0]
                    obj._extend_tag = "existing"
                    return
                step2_errors.append(f'Multiple matches for record {ident} in folder "{folder_path}"; add folder_path to disambiguate{machine_suffix}')
                return

            if not title and not login:
                obj._extend_tag = "new"
                return
            matches = [r for r in all_ksm_records if _vault_title_matches_import(r[1], title)]
            if len(matches) == 0:
                obj._extend_tag = "new"
                return
            if len(matches) == 1:
                obj.uid = matches[0][0]
                obj._extend_tag = "existing"
                return
            step2_errors.append(f'Multiple matches for record {ident}; add folder_path to disambiguate{machine_suffix}')

        for obj in resources:
            resolve_one(obj, None)
        for obj in users:
            resolve_one(obj, None)
        for mach in resources:
            if hasattr(mach, "users") and isinstance(mach.users, list):
                for usr in mach.users:
                    resolve_one(usr, mach)

        autogenerated_titles = []
        for o in chain(resources, users):
            if _has_autogenerated_title(o):
                autogenerated_titles.append(getattr(o, "title", None) or "")
        for mach in resources:
            if hasattr(mach, "users") and isinstance(mach.users, list):
                for u in mach.users:
                    if _has_autogenerated_title(u):
                        autogenerated_titles.append(getattr(u, "title", None) or "")
        if autogenerated_titles:
            print(
                f"{bcolors.WARNING}Warning: {len(autogenerated_titles)} record(s) have autogenerated titles "
                f"(e.g. PAM User/Machine/Database/Directory/RBI - <field>). Add \"title\" in import JSON to set an explicit record title.{bcolors.ENDC}"
            )
            if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
                for t in autogenerated_titles:
                    print(f"  [DEBUG] autogenerated title: {t}")

        machines = [x for x in resources if not isinstance(x, PamRemoteBrowserObject)]
        pam_directories = [x for x in machines if (getattr(x, "type", "") or "").lower() == "pamdirectory"]
        for mach in resources:
            if not mach:
                continue
            admin_cred = get_admin_credential(mach)
            sftp_user = get_sftp_attribute(mach, "sftpUser")
            sftp_res = get_sftp_attribute(mach, "sftpResource")
            if sftp_res:
                ruids = [x for x in machines if getattr(x, "title", None) == sftp_res]
                ruids = ruids or [x for x in machines if getattr(x, "login", None) == sftp_res]
                if len(ruids) == 1 and getattr(ruids[0], "uid", ""):
                    set_sftp_uid(mach, "sftpResourceUid", ruids[0].uid)
            if sftp_user:
                ruids = find_user(mach, users, sftp_user) or find_user(machines, users, sftp_user)
                if len(ruids) == 1 and getattr(ruids[0], "uid", ""):
                    set_sftp_uid(mach, "sftpUserUid", ruids[0].uid)
            if admin_cred:
                ruids = find_user(mach, users, admin_cred)
                is_external = False
                if not ruids:
                    ruids = find_external_user(mach, machines, admin_cred)
                    is_external = True
                if len(ruids) == 1 and getattr(ruids[0], "uid", ""):
                    set_user_record_uid(mach, ruids[0].uid, is_external)
            if mach.pam_settings and getattr(mach.pam_settings, "jit_settings", None):
                jit = mach.pam_settings.jit_settings
                ref = getattr(jit, "pam_directory_record", None) or ""
                if ref and isinstance(ref, str) and ref.strip():
                    matches = [x for x in pam_directories if getattr(x, "title", None) == ref.strip()]
                    if len(matches) == 1:
                        jit.pam_directory_uid = matches[0].uid
            resolve_script_creds(mach, users, resources)
            if hasattr(mach, "users") and isinstance(mach.users, list):
                for usr in mach.users:
                    if usr and hasattr(usr, "rotation_settings") and usr.rotation_settings:
                        rot = getattr(usr.rotation_settings, "rotation", None)
                        if rot == "general":
                            usr.rotation_settings.resourceUid = mach.uid
                        elif rot in ("iam_user", "scripts_only"):
                            usr.rotation_settings.resourceUid = pam_cfg_uid
                    resolve_script_creds(usr, users, resources)
            if hasattr(mach, "rbi_settings") and getattr(mach.rbi_settings, "connection", None):
                conn = mach.rbi_settings.connection
                if getattr(conn, "protocol", None) and str(getattr(conn.protocol, "value", "") or "").lower() == "http":
                    creds = getattr(conn, "httpCredentials", None)
                    if creds:
                        cred = str(creds[0]) if isinstance(creds, list) else str(creds)
                        matches = [x for x in users if getattr(x, "title", None) == cred]
                        matches = matches or [x for x in users if getattr(x, "login", None) == cred]
                        if len(matches) == 1 and getattr(matches[0], "uid", ""):
                            mach.rbi_settings.connection.httpCredentialsUid = [matches[0].uid]
        for usr in users:
            if usr and hasattr(usr, "rotation_settings") and usr.rotation_settings:
                rot = getattr(usr.rotation_settings, "rotation", None)
                if rot in ("iam_user", "scripts_only"):
                    usr.rotation_settings.resourceUid = pam_cfg_uid
                elif rot == "general":
                    res = getattr(usr.rotation_settings, "resource", "") or ""
                    if res:
                        ruids = [x for x in machines if getattr(x, "title", None) == res]
                        ruids = ruids or [x for x in machines if getattr(x, "login", None) == res]
                        if ruids:
                            usr.rotation_settings.resourceUid = ruids[0].uid
            resolve_script_creds(usr, users, resources)

        if step2_errors:
            project["error_count"] = project.get("error_count", 0) + len(step2_errors)

        x_count = sum(1 for o in chain(resources, users) if getattr(o, "_extend_tag", None) == "existing")
        for mach in resources:
            if hasattr(mach, "users") and isinstance(mach.users, list):
                x_count += sum(1 for u in mach.users if getattr(u, "_extend_tag", None) == "existing")
        y_count = 0
        for o in chain(resources, users):
            if getattr(o, "_extend_tag", None) == "new":
                y_count += 1
        for mach in resources:
            if hasattr(mach, "users") and isinstance(mach.users, list):
                y_count += sum(1 for u in mach.users if getattr(u, "_extend_tag", None) == "new")

        existing_rec_msg = f"{x_count} existing records (skipped)" if x_count else "0 existing records"
        total_line = f"{existing_rec_msg}, {y_count} new records to be created"
        for err in step2_errors:
            print(f"  {err}")
        if step2_errors:
            print(f"Total: {len(step2_errors)} errors")

        if dry_run:
            for o in chain(resources, users):
                tag = getattr(o, "_extend_tag", "?")
                path = getattr(o, "folder_path", "") or "autodetect"
                otype = getattr(o, "type", "") or ""
                label = getattr(o, "title", None) or getattr(o, "login", None) or ""
                uid_suffix = f"\tuid={getattr(o, 'uid', '')}" if tag == "existing" else ""
                print(f"  [DRY RUN] [{tag}]  folder={path}\trecord={otype}: {label}{uid_suffix}")
            for mach in resources:
                if hasattr(mach, "users") and isinstance(mach.users, list):
                    for u in mach.users:
                        tag = getattr(u, "_extend_tag", "?")
                        path = getattr(u, "folder_path", "") or "autodetect"
                        utype = getattr(u, "type", "") or ""
                        label = getattr(u, "title", None) or getattr(u, "login", None) or ""
                        uid_suffix = f"\tuid={getattr(u, 'uid', '')}" if tag == "existing" else ""
                        print(f"  [DRY RUN] [{tag}]  folder={path}\trecord={utype}: {label} (nested on {getattr(mach, 'title', '')}){uid_suffix}")
            print(f"[DRY RUN] {total_line}")
        else:
            if logging.getLogger().getEffectiveLevel() <= logging.DEBUG:
                for o in chain(resources, users):
                    tag = getattr(o, "_extend_tag", "?")
                    path = getattr(o, "folder_path", "") or "autodetect"
                    otype = getattr(o, "type", "") or ""
                    label = getattr(o, "title", None) or getattr(o, "login", None) or ""
                    uid_suffix = f"\tuid={getattr(o, 'uid', '')}" if tag == "existing" else ""
                    print(f"  [DEBUG] [{tag}]  folder={path}\trecord={otype}: {label}{uid_suffix}")
                for mach in resources:
                    if hasattr(mach, "users") and isinstance(mach.users, list):
                        for u in mach.users:
                            tag = getattr(u, "_extend_tag", "?")
                            path = getattr(u, "folder_path", "") or "autodetect"
                            utype = getattr(u, "type", "") or ""
                            label = getattr(u, "title", None) or getattr(u, "login", None) or ""
                            uid_suffix = f"\tuid={getattr(u, 'uid', '')}" if tag == "existing" else ""
                            print(f"  [DEBUG] [{tag}]  folder={path}\trecord={utype}: {label} (nested on {getattr(mach, 'title', '')}){uid_suffix}")
            print(total_line)

        project["mapped_resources"] = resources
        project["mapped_users"] = users
        project["new_record_count"] = y_count
        return (resources, users, step2_errors, y_count)

    def autodetect_folders(self, params, project: dict) -> list:
        """Step 3: Autodetect resources_folder_uid and users_folder_uid when new records have no folder_path.
        Call only when error_count==0 and there are records with no uid and no folder_path (tagged new).
        Returns list of step3 errors; updates project['folders'] with resources_folder_uid/users_folder_uid on success."""
        step3_errors = []
        folders_out = project.get("folders") or {}
        ksm_shared_folders = project.get("ksm_shared_folders") or []
        subfolder_record_cache = getattr(params, "subfolder_record_cache", None) or {}

        new_no_path = []
        for o in chain(project.get("mapped_resources", []), project.get("mapped_users", [])):
            if getattr(o, "_extend_tag", None) == "new":
                if not (getattr(o, "folder_path", None) or "").strip():
                    new_no_path.append(o)
        for mach in project.get("mapped_resources", []):
            if hasattr(mach, "users") and isinstance(mach.users, list):
                for u in mach.users:
                    if getattr(u, "_extend_tag", None) == "new" and not (getattr(u, "folder_path", None) or "").strip():
                        new_no_path.append(u)
        if not new_no_path:
            return step3_errors

        shf_list = [(shf["uid"], shf.get("name") or "") for shf in ksm_shared_folders]
        if len(shf_list) == 1:
            folders_out["resources_folder_uid"] = shf_list[0][0]
            folders_out["users_folder_uid"] = shf_list[0][0]
            print("Warning: Using single shared folder for both resources and users (best practice: separate).")
            return step3_errors

        if len(shf_list) == 2:
            names = [n for _, n in shf_list]
            r_idx = next((i for i, n in enumerate(names) if n.endswith(" - Resources") or n.endswith("- Resources")), -1)
            u_idx = next((i for i, n in enumerate(names) if n.endswith(" - Users") or n.endswith("- Users")), -1)
            if r_idx >= 0 and u_idx >= 0 and r_idx != u_idx:
                folders_out["resources_folder_uid"] = shf_list[r_idx][0]
                folders_out["users_folder_uid"] = shf_list[u_idx][0]
                return step3_errors

        non_empty = []
        for shf in ksm_shared_folders:
            uids = _folder_uids_under_shf(shf)
            if any(subfolder_record_cache.get(fuid) for fuid in uids):
                non_empty.append(shf)
        if len(non_empty) == 0:
            step3_errors.append("Autodetect: no folders contain records; cannot assign resources/users folders.")
            project["error_count"] = project.get("error_count", 0) + len(step3_errors)
            for e in step3_errors:
                print(f"  {e}")
            print(f"Total: {len(step3_errors)} errors")
            return step3_errors
        if len(non_empty) == 1:
            folders_out["resources_folder_uid"] = non_empty[0]["uid"]
            folders_out["users_folder_uid"] = non_empty[0]["uid"]
            print("Warning: Using single non-empty folder for both resources and users.")
            return step3_errors
        if len(non_empty) == 2:
            res_uid = users_uid = None
            for shf in non_empty:
                uids = _folder_uids_under_shf(shf)
                for fuid in uids:
                    recs = _get_records_in_folder(params, fuid)
                    if not recs:
                        continue
                    for ruid, _title, rtype in recs:
                        rtype = (rtype or "").lower()
                        if rtype in ("pamuser", "login"):
                            users_uid = shf["uid"]
                            break
                        if rtype in ("pammachine", "pamdatabase", "pamdirectory", "pamremotebrowser"):
                            res_uid = shf["uid"]
                            break
                    if users_uid is not None or res_uid is not None:
                        break
                if users_uid is not None and res_uid is not None:
                    break
            if res_uid is not None and users_uid is not None:
                folders_out["resources_folder_uid"] = res_uid
                folders_out["users_folder_uid"] = users_uid
                return step3_errors
            step3_errors.append("Autodetect: could not determine which folder is resources vs users.")
        else:
            step3_errors.append("Autodetect: three or more non-empty folders; add folder_path to disambiguate.")
        project["error_count"] = project.get("error_count", 0) + len(step3_errors)
        for e in step3_errors:
            print(f"  {e}")
        if step3_errors:
            print(f"Total: {len(step3_errors)} errors")
        return step3_errors

    def create_subfolder(self, params, folder_name:str, parent_uid:str="", permissions:Optional[Dict]=None, folder_uid:Optional[str]=None):
        # folder_uid: if provided, create folder with this UID (same as records with pre-generated uid).

        name = str(folder_name or "").strip()
        base_folder = params.folder_cache.get(parent_uid, None) or params.root_folder

        shared_folder = True if permissions else False
        user_folder = True if not permissions else False  # uf or sff (split later)
        if not folder_uid:
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
        """Extend: only create records tagged new; use resolved_folder_uid; for existing machines only add new users."""
        if project.get("options", {}).get("dry_run", False) is True:
            return
        from ..tunnel_and_connections import PAMTunnelEditCommand
        from ..discoveryrotation import PAMCreateRecordRotationCommand

        resources = project.get("mapped_resources") or []
        users = project.get("mapped_users") or []
        pam_cfg_uid = (project.get("pam_config") or {}).get("pam_config_uid", "")
        shfres = (project.get("folders") or {}).get("resources_folder_uid", "")
        shfusr = (project.get("folders") or {}).get("users_folder_uid", "")
        pce = (project.get("pam_config") or {}).get("pam_config_object")

        print("Started importing data...")
        encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
        tdag = TunnelDAG(params, encrypted_session_token, encrypted_transmission_key, pam_cfg_uid, True,
                         transmission_key=transmission_key)
        pte = PAMTunnelEditCommand()
        prc = PAMCreateRecordRotationCommand()
        pdelta = 10

        new_users = [u for u in users if getattr(u, "_extend_tag", None) == "new"]
        if new_users:
            logging.warning(f"Processing external users: {len(new_users)}")
            for n, user in enumerate(new_users):
                folder_uid = getattr(user, "resolved_folder_uid", None) or shfusr
                user.create_record(params, folder_uid)
                if n % pdelta == 0:
                    print(f"{n}/{len(new_users)}")
            print(f"{len(new_users)}/{len(new_users)}\n")

        resources_sorted = sorted(resources, key=lambda r: (getattr(r, "type", "") or "").lower() != "pamdirectory")
        new_resources = [r for r in resources_sorted if getattr(r, "_extend_tag", None) == "new"]
        existing_resources = [r for r in resources_sorted if getattr(r, "_extend_tag", None) == "existing"]
        if new_resources:
            logging.warning(f"Processing resources: {len(new_resources)}")
        for n, mach in enumerate(new_resources):
            if n % pdelta == 0:
                print(f"{n}/{len(new_resources)}")
            folder_uid = getattr(mach, "resolved_folder_uid", None) or shfres
            admin_uid = get_admin_credential(mach, True)
            mach.create_record(params, folder_uid)
            tdag.link_resource_to_config(mach.uid)
            if isinstance(mach, PamRemoteBrowserObject):
                args = parse_command_options(mach, True)
                pte.execute(params, config=pam_cfg_uid, silent=True, **args)
                args = parse_command_options(mach, False)
                if args.get("remote_browser_isolation", False) is True:
                    args["connections"] = True
                tdag.set_resource_allowed(**args)
            else:
                args = parse_command_options(mach, True)
                if admin_uid:
                    args["admin"] = admin_uid
                pte.execute(params, config=pam_cfg_uid, silent=True, **args)
                if admin_uid and is_admin_external(mach):
                    tdag.link_user_to_resource(admin_uid, mach.uid, is_admin=True, belongs_to=False)
                args = parse_command_options(mach, False)
                tdag.set_resource_allowed(**args)
            mach_users = getattr(mach, "users", []) or []
            for user in mach_users:
                if getattr(user, "_extend_tag", None) != "new":
                    continue
                rs = getattr(user, "rotation_settings", None)
                if isinstance(user, PamUserObject) and rs and (getattr(rs, "rotation", "") or "").lower() == "general":
                    rs.resourceUid = mach.uid
                ufolder = getattr(user, "resolved_folder_uid", None) or shfusr
                user.create_record(params, ufolder)
                if isinstance(user, PamUserObject):
                    tdag.link_user_to_resource(user.uid, mach.uid, admin_uid == user.uid, True)
                    if rs:
                        args = {"force": True, "config": pam_cfg_uid, "record_name": user.uid, "admin": admin_uid, "resource": mach.uid}
                        enabled = getattr(rs, "enabled", "")
                        key = {"on": "enable", "off": "disable"}.get(enabled, "")
                        if key:
                            args[key] = True
                        schedule = getattr(rs, "schedule", None)
                        schedule_type = getattr(schedule, "type", "") if schedule else ""
                        if schedule_type == "on-demand":
                            args["on_demand"] = True
                        elif schedule_type == "cron" and schedule and getattr(schedule, "cron", None):
                            args["schedule_cron_data"] = rs.schedule.cron
                        if getattr(rs, "password_complexity", None):
                            args["pwd_complexity"] = rs.password_complexity
                        prc.execute(params, silent=True, **args)
        if new_resources:
            print(f"{len(new_resources)}/{len(new_resources)}\n")

        for mach in existing_resources:
            mach_users = getattr(mach, "users", []) or []
            admin_uid = get_admin_credential(mach, True)
            for user in mach_users:
                if getattr(user, "_extend_tag", None) != "new":
                    continue
                rs = getattr(user, "rotation_settings", None)
                if isinstance(user, PamUserObject) and rs and (getattr(rs, "rotation", "") or "").lower() == "general":
                    rs.resourceUid = mach.uid
                ufolder = getattr(user, "resolved_folder_uid", None) or shfusr
                user.create_record(params, ufolder)
                if isinstance(user, PamUserObject):
                    tdag.link_user_to_resource(user.uid, mach.uid, admin_uid == user.uid, True)
                    if rs:
                        args = {"force": True, "config": pam_cfg_uid, "record_name": user.uid, "admin": admin_uid, "resource": mach.uid}
                        enabled = getattr(rs, "enabled", "")
                        key = {"on": "enable", "off": "disable"}.get(enabled, "")
                        if key:
                            args[key] = True
                        schedule = getattr(rs, "schedule", None)
                        schedule_type = getattr(schedule, "type", "") if schedule else ""
                        if schedule_type == "on-demand":
                            args["on_demand"] = True
                        elif schedule_type == "cron" and schedule and getattr(schedule, "cron", None):
                            args["schedule_cron_data"] = rs.schedule.cron
                        if getattr(rs, "password_complexity", None):
                            args["pwd_complexity"] = rs.password_complexity
                        prc.execute(params, silent=True, **args)

        if pce and getattr(pce, "scripts", None) and getattr(pce.scripts, "scripts", None):
            refs = [x for x in pce.scripts.scripts if getattr(x, "record_refs", None)]
            if refs:
                api.sync_down(params)
                add_pam_scripts(params, pam_cfg_uid, refs)
        logging.debug("Done processing project data.")
        return

