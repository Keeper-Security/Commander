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
import itertools
import json
import logging
from typing import List, Set

from .base import PAM_CONFIG_TYPES, PAM_RESOURCES_RECORD_TYPES
from ..base import Command
from ..pam.config_facades import PamConfigurationRecordFacade
from .nsf_helpers import get_folder_record_uids
from .record_loader import iter_accessible_record_uids, load_pam_record
from ... import vault
from ...display import bcolors
from ...recordv3 import RecordV3
from ...subfolder import find_folders as find_record_folders


_RECORD_TYPE_TO_ENV = {
    "pamNetworkConfiguration": "local",
    "pamAwsConfiguration": "aws",
    "pamAzureConfiguration": "azure",
    "pamDomainConfiguration": "domain",
    "pamGcpConfiguration": "gcp",
    "pamOciConfiguration": "oci",
}

_DAG_KEY_TO_JSON = {
    "connections": "connections",
    "portForwards": "tunneling",
    "rotation": "rotation",
    "remoteBrowserIsolation": "remote_browser_isolation",
    "sessionRecording": "graphical_session_recording",
    "typescriptRecording": "text_session_recording",
    "aiEnabled": "ai_threat_detection",
    "aiSessionTerminate": "ai_terminate_session_on_detection",
}

# Field label / type (casefold) -> import JSON key
_RESOURCE_FIELD_MAP = {
    "operatingsystem": "operating_system",
    "instancename": "instance_name",
    "instanceid": "instance_id",
    "providergroup": "provider_group",
    "providerregion": "provider_region",
    "databaseid": "database_id",
    "databasetype": "database_type",
    "domainname": "domain_name",
    "directoryid": "directory_id",
    "directorytype": "directory_type",
    "usermatch": "user_match",
    "sslverification": "ssl_verification",
    "usessl": "use_ssl",
}

_USER_RECORD_TYPES = ("pamUser", "login")
_PAM_ROOT_FOLDER_NAME = "pam environments"

_DEFAULT_ALLOWED_SETTINGS = {
    "connections": "on",
    "rotation": "on",
    "tunneling": "on",
    "remote_browser_isolation": "on",
    "graphical_session_recording": "off",
    "text_session_recording": "off",
    "ai_threat_detection": "off",
    "ai_terminate_session_on_detection": "off",
}


class PAMProjectExportCommand(Command):
    """Export a PAM project to JSON for re-import via pam project import."""

    parser = argparse.ArgumentParser(prog="pam project export")
    parser.add_argument(
        "--project-uid", "-p",
        required=True, dest="project_uid", action="store",
        help="PAM configuration record UID to export.",
    )
    parser.add_argument(
        "--output", "-o",
        required=False, dest="output", action="store",
        help="File path to write JSON output (default: print to stdout).",
    )

    def get_parser(self):
        return PAMProjectExportCommand.parser

    def execute(self, params, **kwargs):
        project_uid = (kwargs.get("project_uid") or "").strip()
        output_file = (kwargs.get("output") or "").strip()

        if not project_uid:
            logging.warning(f"{bcolors.FAIL}--project-uid is required{bcolors.ENDC}")
            return

        config_record = load_pam_record(params, project_uid)
        if not config_record:
            logging.warning(
                f"{bcolors.FAIL}PAM configuration '{project_uid}' not found in vault{bcolors.ENDC}"
            )
            return
        if not isinstance(config_record, vault.TypedRecord):
            logging.warning(
                f"{bcolors.FAIL}Record '{project_uid}' is not a TypedRecord{bcolors.ENDC}"
            )
            return
        if config_record.version != 6 or config_record.record_type not in PAM_CONFIG_TYPES:
            logging.warning(
                f"{bcolors.FAIL}Record '{project_uid}' is not a PAM configuration "
                f"(version 6 / known PAM config type required){bcolors.ENDC}"
            )
            return

        facade = PamConfigurationRecordFacade()
        facade.record = config_record

        allowed_settings, dag_resource_uids = self._load_dag_context(params, project_uid)
        resource_uids, folder_user_uids, resources_folder_uid, users_folder_uid = (
            self._discover_project_record_uids(
                params, facade, project_uid, dag_resource_uids
            )
        )
        resources_list, top_level_users = self._build_resources_and_users(
            params, resource_uids, extra_user_uids=folder_user_uids
        )

        result = {
            "tool_version": "commander-export-1.0",
            "project": config_record.title,
            "shared_folder_users": self._export_folder_permissions(params, users_folder_uid),
            "shared_folder_resources": self._export_folder_permissions(params, resources_folder_uid),
            "pam_configuration": {
                "environment": _RECORD_TYPE_TO_ENV.get(config_record.record_type, "local"),
                "title": config_record.title,
                **{k: allowed_settings.get(k, v) for k, v in _DEFAULT_ALLOWED_SETTINGS.items()},
            },
            "pam_data": {
                "resources": resources_list,
                "users": top_level_users,
            },
        }

        output_json = json.dumps(result, indent=2, sort_keys=True)
        if not output_file:
            if any(u.get("password") for u in top_level_users):
                logging.warning(
                    f"{bcolors.WARNING}Export includes passwords; treat output as sensitive.{bcolors.ENDC}"
                )
            return output_json

        try:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(output_json)
        except OSError as exc:
            logging.warning(
                f"{bcolors.FAIL}Failed to write export file '{output_file}': {exc}{bcolors.ENDC}"
            )
            return
        print(f"{bcolors.OKGREEN}PAM project exported to: {output_file}{bcolors.ENDC}")

    def _discover_project_record_uids(self, params, facade, config_uid, dag_resource_uids):
        """Merge resourceRef + DAG + folder-tree UIDs under the project wrapper."""
        resource_uids: List[str] = []
        seen_resources: Set[str] = set()

        def add_resource(uid: str) -> None:
            if not uid or uid == config_uid or uid in seen_resources:
                return
            seen_resources.add(uid)
            resource_uids.append(uid)

        for uid in facade.resource_ref or []:
            add_resource(uid)
        for uid in dag_resource_uids or []:
            add_resource(uid)

        resources_folder_uid, users_folder_uid, scan_roots = self._resolve_project_folders(
            params, facade.folder_uid, config_uid
        )

        folder_user_uids: List[str] = []
        seen_users: Set[str] = set()
        for root_uid in scan_roots:
            for rec_uid, rtype in self._iter_folder_record_types(params, root_uid):
                if not rec_uid or rec_uid == config_uid:
                    continue
                if rtype in PAM_RESOURCES_RECORD_TYPES:
                    add_resource(rec_uid)
                elif rtype in _USER_RECORD_TYPES and rec_uid not in seen_users:
                    seen_users.add(rec_uid)
                    folder_user_uids.append(rec_uid)

        return resource_uids, folder_user_uids, resources_folder_uid, users_folder_uid

    @staticmethod
    def _is_pam_content_folder_name(name: str) -> bool:
        n = (name or "").casefold()
        return (
            n.endswith(" - resources") or n.endswith(" resources")
            or n.endswith(" - users") or n.endswith(" users")
        )

    @staticmethod
    def _is_resources_folder_name(name: str) -> bool:
        n = (name or "").casefold()
        return n.endswith(" - resources") or n.endswith(" resources")

    @staticmethod
    def _is_users_folder_name(name: str) -> bool:
        n = (name or "").casefold()
        return n.endswith(" - users") or n.endswith(" users")

    def _project_wrapper_uid(self, params, folder_uid):
        """Project folder for folder_uid; never returns the PAM Environments root."""
        if not folder_uid:
            return ""
        parent_uid = self._folder_parent_uid(params, folder_uid)
        if not parent_uid:
            return folder_uid
        parent_name = (self._folder_name(params, parent_uid) or "").casefold()
        if parent_name == _PAM_ROOT_FOLDER_NAME:
            return folder_uid
        return parent_uid

    def _resolve_project_folders(self, params, folder_uid, config_uid):
        """Return (resources_folder_uid, users_folder_uid, scan_roots).

        Collects all descendant *Resources* / *Users* folders under the project
        wrapper (covers legacy and nested safe-mode). Never walks PAM Environments.
        """
        folder_uid = (folder_uid or "").strip()
        anchors: List[str] = []
        if folder_uid:
            anchors.append(folder_uid)
        else:
            anchors.extend(uid for uid in (find_record_folders(params, config_uid) or []) if uid)

        resources_folder_uid = ""
        users_folder_uid = folder_uid
        scan_roots: List[str] = []
        seen_roots: Set[str] = set()

        def add_scan_root(uid: str) -> None:
            if uid and uid not in seen_roots:
                seen_roots.add(uid)
                scan_roots.append(uid)

        for anchor in anchors:
            add_scan_root(anchor)
            project_uid = self._project_wrapper_uid(params, anchor)
            if not project_uid:
                continue

            for fuid in self._iter_descendant_folders(params, project_uid):
                name = self._folder_name(params, fuid) or ""
                if not self._is_pam_content_folder_name(name):
                    continue
                add_scan_root(fuid)
                if self._is_resources_folder_name(name) and not resources_folder_uid:
                    resources_folder_uid = fuid
                elif self._is_users_folder_name(name):
                    users_folder_uid = fuid

            if not resources_folder_uid:
                resources_folder_uid = users_folder_uid or anchor

        return resources_folder_uid or "", users_folder_uid or "", scan_roots

    def _iter_descendant_folders(self, params, folder_uid):
        """Yield every folder UID under folder_uid (not including folder_uid)."""
        if not folder_uid:
            return
        seen: Set[str] = set()
        stack = list(self._child_folder_uids(params, folder_uid))
        while stack:
            fuid = stack.pop()
            if not fuid or fuid in seen:
                continue
            seen.add(fuid)
            yield fuid
            stack.extend(self._child_folder_uids(params, fuid))

    def _load_dag_context(self, params, config_uid):
        """Load allowed settings and linked resource UIDs from TunnelDAG (best-effort)."""
        allowed = dict(_DEFAULT_ALLOWED_SETTINGS)
        resource_uids: List[str] = []
        try:
            from ...keeper_dag import EdgeType
            from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens
            from ..tunnel.port_forward.TunnelGraph import TunnelDAG, get_vertex_content

            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            tmp_dag = TunnelDAG(
                params, encrypted_session_token, encrypted_transmission_key,
                config_uid, is_config=True, transmission_key=transmission_key,
            )
            tmp_dag.linking_dag.load()
            vertex = tmp_dag.linking_dag.get_vertex(config_uid)
            if not vertex:
                return allowed, resource_uids

            content = get_vertex_content(vertex) or {}
            dag_allowed = content.get("allowedSettings") or {}
            for dag_key, json_key in _DAG_KEY_TO_JSON.items():
                if dag_key in dag_allowed:
                    allowed[json_key] = "on" if dag_allowed[dag_key] else "off"

            for child in vertex.has_vertices(EdgeType.LINK):
                uid = getattr(child, "uid", None)
                if uid:
                    resource_uids.append(uid)
        except Exception as exc:
            logging.debug("PAMProjectExportCommand: DAG context unavailable: %s", exc)
        return allowed, resource_uids

    def _iter_folder_record_types(self, params, folder_uid):
        """Yield (uid, record_type) for records under folder_uid (recursive)."""
        if not folder_uid:
            return
        seen_folders: Set[str] = set()
        stack = [folder_uid]
        while stack:
            fuid = stack.pop()
            if not fuid or fuid in seen_folders:
                continue
            seen_folders.add(fuid)
            for rec_uid in get_folder_record_uids(params, fuid):
                rec = load_pam_record(params, rec_uid)
                if not rec:
                    continue
                yield rec_uid, (getattr(rec, "record_type", None) or "")
            stack.extend(self._child_folder_uids(params, fuid))

    @staticmethod
    def _folder_parent_uid(params, folder_uid):
        folder = (getattr(params, "folder_cache", None) or {}).get(folder_uid)
        if folder and getattr(folder, "parent_uid", None):
            return folder.parent_uid
        nsf = getattr(params, "nested_share_folders", None) or {}
        return (nsf.get(folder_uid) or {}).get("parent_uid") or ""

    @staticmethod
    def _folder_name(params, folder_uid):
        folder = (getattr(params, "folder_cache", None) or {}).get(folder_uid)
        if folder and getattr(folder, "name", None):
            return folder.name
        nsf = getattr(params, "nested_share_folders", None) or {}
        name = (nsf.get(folder_uid) or {}).get("name")
        if name:
            return name
        sf = (getattr(params, "shared_folder_cache", None) or {}).get(folder_uid) or {}
        return sf.get("name_unencrypted") or ""

    @staticmethod
    def _child_folder_uids(params, folder_uid):
        children: List[str] = []
        folder = (getattr(params, "folder_cache", None) or {}).get(folder_uid)
        if folder:
            children.extend(getattr(folder, "subfolders", None) or [])
        for fuid, info in (getattr(params, "nested_share_folders", None) or {}).items():
            if (info.get("parent_uid") or "") == folder_uid:
                children.append(fuid)
        seen: Set[str] = set()
        out: List[str] = []
        for uid in children:
            if uid and uid not in seen:
                seen.add(uid)
                out.append(uid)
        return out

    def _export_folder_permissions(self, params, folder_uid):
        """Import-compatible shared_folder_* dict, or {} when permissions are unknown."""
        if not folder_uid:
            return {}
        sf = (getattr(params, "shared_folder_cache", None) or {}).get(folder_uid)
        if not isinstance(sf, dict):
            # NSF / non-classic folders: do not invent defaults that would change ACL on re-import.
            return {}
        return self._permissions_from_classic_sf(sf)

    @staticmethod
    def _permissions_from_classic_sf(sf):
        result = {
            "manage_users": bool(sf.get("default_manage_users")),
            "manage_records": bool(sf.get("default_manage_records")),
            "can_edit": bool(sf.get("default_can_edit")),
            "can_share": bool(sf.get("default_can_share")),
            "permissions": [],
        }
        for user in sf.get("users") or []:
            if not isinstance(user, dict):
                continue
            name = (user.get("username") or "").strip()
            if not name:
                continue
            result["permissions"].append({
                "name": name,
                "manage_users": bool(user.get("manage_users")),
                "manage_records": bool(user.get("manage_records")),
            })
        for team in sf.get("teams") or []:
            if not isinstance(team, dict):
                continue
            name = (team.get("name") or "").strip()
            uid = (team.get("team_uid") or "").strip()
            if not name and not uid:
                continue
            entry = {
                "manage_users": bool(team.get("manage_users")),
                "manage_records": bool(team.get("manage_records")),
            }
            if name:
                entry["name"] = name
            if uid:
                entry["uid"] = uid
            result["permissions"].append(entry)
        return result

    def _build_resources_and_users(self, params, resource_uids, extra_user_uids=None):
        """Build pam_data.resources and deduplicated pam_data.users."""
        resources_list = []
        top_level_users = []
        seen_user_uids: Set[str] = set()
        title_to_uid = self._build_user_title_index(params)

        for res_uid in resource_uids:
            res_record = load_pam_record(params, res_uid)
            if not res_record or not isinstance(res_record, vault.TypedRecord):
                logging.debug("Export: skipping resource UID %s (not found or not TypedRecord)", res_uid)
                continue
            if res_record.record_type not in PAM_RESOURCES_RECORD_TYPES:
                logging.debug(
                    "Export: skipping record %s with type '%s' (not a PAM resource type)",
                    res_uid, res_record.record_type,
                )
                continue

            pam_settings_dict = self._extract_pam_settings(res_record)
            resource_user_entries = []
            for usr_uid in self._extract_user_uids(pam_settings_dict, title_to_uid):
                user_obj = self._load_user_obj(params, usr_uid)
                if user_obj is None:
                    continue
                resource_user_entries.append({
                    "uid": usr_uid,
                    "type": user_obj["type"],
                    "title": user_obj["title"],
                    "login": user_obj["login"],
                })
                if usr_uid not in seen_user_uids:
                    seen_user_uids.add(usr_uid)
                    top_level_users.append(user_obj)

            resources_list.append(
                self._load_resource_obj(res_record, pam_settings_dict, resource_user_entries)
            )

        for usr_uid in extra_user_uids or []:
            if usr_uid in seen_user_uids:
                continue
            user_obj = self._load_user_obj(params, usr_uid)
            if user_obj is None:
                continue
            seen_user_uids.add(usr_uid)
            top_level_users.append(user_obj)

        return resources_list, top_level_users

    @staticmethod
    def _extract_pam_settings(res_record):
        field = res_record.get_typed_field("pamSettings")
        if not field or not isinstance(field.value, list) or not field.value:
            return {}
        first = field.value[0]
        return dict(first) if isinstance(first, dict) else {}

    def _load_resource_obj(self, res_record, pam_settings_dict, resource_user_entries):
        obj = {
            "uid": res_record.record_uid,
            "type": res_record.record_type,
            "title": res_record.title,
            "pam_settings": pam_settings_dict,
            "users": resource_user_entries,
        }
        if res_record.notes:
            obj["notes"] = res_record.notes

        host_field = res_record.get_typed_field("pamHostname")
        if host_field:
            raw = host_field.get_default_value()
            if isinstance(raw, dict):
                host = raw.get("hostName")
                port = raw.get("port")
                if host:
                    obj["host"] = str(host)
                if port is not None and str(port) != "":
                    obj["port"] = str(port)

        for field in itertools.chain(
            getattr(res_record, "fields", None) or [],
            getattr(res_record, "custom", None) or [],
        ):
            label = (getattr(field, "label", None) or "").strip()
            ftype = (getattr(field, "type", None) or "").strip()
            key = (
                _RESOURCE_FIELD_MAP.get(label.casefold())
                or _RESOURCE_FIELD_MAP.get(ftype.casefold())
            )
            if not key or key in obj:
                continue
            raw = field.get_default_value() if hasattr(field, "get_default_value") else None
            if raw is None or raw == "":
                continue
            if ftype == "checkbox" or isinstance(raw, bool) or key in ("ssl_verification", "use_ssl"):
                obj[key] = bool(raw)
            else:
                obj[key] = str(raw)

        return obj

    def _build_user_title_index(self, params):
        index = {}
        for uid in iter_accessible_record_uids(params):
            try:
                rec = load_pam_record(params, uid)
            except Exception as exc:
                logging.debug("Export: title index skip UID %s: %s", uid, exc)
                continue
            if not rec or not isinstance(rec, vault.TypedRecord):
                continue
            if rec.record_type not in _USER_RECORD_TYPES or not rec.title:
                continue
            index.setdefault(rec.title.strip().lower(), uid)
        return index

    def _extract_user_uids(self, pam_settings_dict, title_to_uid=None):
        user_uids: List[str] = []
        title_to_uid = title_to_uid or {}
        conn = pam_settings_dict.get("connection") or {}
        if isinstance(conn, dict):
            for uid in conn.get("userRecords") or []:
                if uid and uid not in user_uids:
                    user_uids.append(uid)
            for key in ("launch_credentials", "administrative_credentials"):
                ref = conn.get(key)
                if not isinstance(ref, str) or not ref:
                    continue
                if RecordV3.is_valid_ref_uid(ref):
                    if ref not in user_uids:
                        user_uids.append(ref)
                    continue
                resolved = title_to_uid.get(ref.strip().lower())
                if resolved and resolved not in user_uids:
                    user_uids.append(resolved)
        for key in ("adminRef", "adminCredentialRef"):
            uid = pam_settings_dict.get(key)
            if uid and uid not in user_uids:
                user_uids.append(uid)
        return user_uids

    def _load_user_obj(self, params, usr_uid):
        usr_record = load_pam_record(params, usr_uid)
        if not usr_record or not isinstance(usr_record, vault.TypedRecord):
            logging.debug("Export: user UID %s not found or not TypedRecord", usr_uid)
            return None
        if usr_record.record_type not in _USER_RECORD_TYPES:
            logging.debug(
                "Export: skipping UID %s with type '%s' (not a PAM user type)",
                usr_uid, usr_record.record_type,
            )
            return None

        login = ""
        login_field = usr_record.get_typed_field("login")
        if login_field:
            raw = login_field.get_default_value()
            login = str(raw) if raw is not None else ""

        obj = {
            "uid": usr_uid,
            "type": usr_record.record_type,
            "title": usr_record.title,
            "login": login,
        }
        if usr_record.notes:
            obj["notes"] = usr_record.notes
        pwd_field = usr_record.get_typed_field("password")
        if pwd_field:
            raw = pwd_field.get_default_value()
            if raw is not None and str(raw) != "":
                obj["password"] = str(raw)
        return obj
