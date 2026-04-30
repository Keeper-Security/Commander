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

from .base import (
    PAM_RESOURCES_RECORD_TYPES,
    PAM_CONFIG_TYPES,
    PAM_ENVIRONMENT_TYPES,
)
from ..base import Command
from ..pam.config_facades import PamConfigurationRecordFacade
from ... import vault
from ...display import bcolors


# Maps v6 record_type -> environment name used by pam project import
_RECORD_TYPE_TO_ENV = {
    "pamNetworkConfiguration": "local",
    "pamAwsConfiguration": "aws",
    "pamAzureConfiguration": "azure",
    "pamDomainConfiguration": "domain",
    "pamGcpConfiguration": "gcp",
    "pamOciConfiguration": "oci",
}

# Maps DAG allowedSettings keys -> JSON keys used in PROJECT_IMPORT_JSON_TEMPLATE
_DAG_KEY_TO_JSON = {
    "connections":          "connections",
    "portForwards":         "tunneling",
    "rotation":             "rotation",
    "remoteBrowserIsolation": "remote_browser_isolation",
    "sessionRecording":     "graphical_session_recording",
    "typescriptRecording":  "text_session_recording",
    "aiEnabled":            "ai_threat_detection",
    "aiSessionTerminate":   "ai_terminate_session_on_detection",
}


class PAMProjectExportCommand(Command):
    """Export a PAM project to a JSON document that can be re-imported via pam project import."""

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

    # ------------------------------------------------------------------
    # Public execute
    # ------------------------------------------------------------------

    def execute(self, params, **kwargs):
        project_uid = (kwargs.get("project_uid") or "").strip()
        output_file = (kwargs.get("output") or "").strip()

        if not project_uid:
            logging.warning(f"{bcolors.FAIL}--project-uid is required{bcolors.ENDC}")
            return

        # 1. Load PAM configuration record (v6)
        config_record = vault.KeeperRecord.load(params, project_uid)
        if not config_record:
            logging.warning(
                f"{bcolors.FAIL}PAM configuration '{project_uid}' not found in vault{bcolors.ENDC}"
            )
            return
        if config_record.version != 6:
            logging.warning(
                f"{bcolors.FAIL}Record '{project_uid}' (version {config_record.version}) "
                f"is not a PAM configuration — version 6 required{bcolors.ENDC}"
            )
            return
        if not isinstance(config_record, vault.TypedRecord):
            logging.warning(
                f"{bcolors.FAIL}Record '{project_uid}' is not a TypedRecord{bcolors.ENDC}"
            )
            return

        # 2. Determine environment
        environment = _RECORD_TYPE_TO_ENV.get(config_record.record_type, "local")

        # 3. Get resource UIDs from pamResources.resourceRef
        facade = PamConfigurationRecordFacade()
        facade.record = config_record
        resource_uids = list(facade.resource_ref or [])

        # 4. Try to read connection/rotation/tunneling settings from DAG (best-effort)
        allowed_settings = self._get_allowed_settings(params, project_uid)

        # 5. Walk resources and gather users
        resources_list, top_level_users = self._build_resources_and_users(params, resource_uids)

        # 6. Assemble result dict
        result = {
            "tool_version": "commander-export-1.0",
            "project": config_record.title,
            "shared_folder_users": {},
            "shared_folder_resources": {},
            "pam_configuration": {
                "environment": environment,
                "title": config_record.title,
                "connections":                      allowed_settings.get("connections",                      "on"),
                "rotation":                         allowed_settings.get("rotation",                         "on"),
                "tunneling":                        allowed_settings.get("tunneling",                        "on"),
                "remote_browser_isolation":         allowed_settings.get("remote_browser_isolation",         "on"),
                "graphical_session_recording":      allowed_settings.get("graphical_session_recording",      "off"),
                "text_session_recording":           allowed_settings.get("text_session_recording",           "off"),
                "ai_threat_detection":              allowed_settings.get("ai_threat_detection",              "off"),
                "ai_terminate_session_on_detection": allowed_settings.get("ai_terminate_session_on_detection", "off"),
            },
            "pam_data": {
                "resources": resources_list,
                "users": top_level_users,
            },
        }

        output_json = json.dumps(result, indent=2, sort_keys=True)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as fh:
                fh.write(output_json)
            print(f"{bcolors.OKGREEN}PAM project exported to: {output_file}{bcolors.ENDC}")
            return

        return output_json

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_allowed_settings(self, params, config_uid):
        """Return on/off dict for tunneling config, falling back to safe defaults."""
        defaults = {
            "connections": "on",
            "rotation": "on",
            "tunneling": "on",
            "remote_browser_isolation": "on",
            "graphical_session_recording": "off",
            "text_session_recording": "off",
            "ai_threat_detection": "off",
            "ai_terminate_session_on_detection": "off",
        }
        try:
            from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens
            from ..tunnel.port_forward.TunnelGraph import TunnelDAG, get_vertex_content

            encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
            tmp_dag = TunnelDAG(
                params, encrypted_session_token, encrypted_transmission_key,
                config_uid, is_config=True, transmission_key=transmission_key,
            )
            tmp_dag.linking_dag.load()
            vertex = tmp_dag.linking_dag.get_vertex(config_uid)
            content = get_vertex_content(vertex) if vertex else None
            dag_allowed = (content or {}).get("allowedSettings") or {}
            for dag_key, json_key in _DAG_KEY_TO_JSON.items():
                if dag_key in dag_allowed:
                    defaults[json_key] = "on" if dag_allowed[dag_key] else "off"
        except Exception as exc:
            logging.debug("PAMProjectExportCommand: could not load DAG allowed settings: %s", exc)
        return defaults

    def _build_resources_and_users(self, params, resource_uids):
        """Walk resource UIDs and collect resources + deduplicated top-level users.

        Two linking strategies are supported:

        1. Standard: ``pam_settings.connection.userRecords[]`` and
           top-level ``adminRef`` / ``adminCredentialRef`` carry user UIDs.
        2. Title-based (e.g. KCM imports — see PR #1942): the resource
           record references users by **title** in
           ``pam_settings.connection.{launch,administrative}_credentials``
           (e.g. ``"KCM User - prod-db"``) without a userRecords list. We
           resolve those by scanning the project's vault for pamUser /
           login records with matching titles.
        """
        resources_list = []
        top_level_users = []
        seen_user_uids = set()

        # Pre-build a lookup of (record_type, title.lower()) -> uid for fallback resolution
        title_to_uid = self._build_user_title_index(params)

        for res_uid in resource_uids:
            res_record = vault.KeeperRecord.load(params, res_uid)
            if not res_record or not isinstance(res_record, vault.TypedRecord):
                logging.debug("Export: skipping resource UID %s (not found or not TypedRecord)", res_uid)
                continue
            if res_record.record_type not in PAM_RESOURCES_RECORD_TYPES:
                logging.debug(
                    "Export: skipping record %s with type '%s' (not a PAM resource type)",
                    res_uid, res_record.record_type,
                )
                continue

            # Extract raw pamSettings payload (keep as-is for round-trip fidelity)
            pam_settings_dict = {}
            pam_settings_field = res_record.get_typed_field("pamSettings")
            if (
                pam_settings_field
                and isinstance(pam_settings_field.value, list)
                and pam_settings_field.value
                and isinstance(pam_settings_field.value[0], dict)
            ):
                pam_settings_dict = dict(pam_settings_field.value[0])

            # Gather user UIDs referenced by this resource
            resource_user_entries = []
            user_uids_for_resource = self._extract_user_uids(pam_settings_dict, title_to_uid)

            for usr_uid in user_uids_for_resource:
                user_obj = self._load_user_obj(params, usr_uid)
                if user_obj is None:
                    continue
                resource_user_entries.append({"uid": usr_uid, "type": user_obj["type"], "title": user_obj["title"], "login": user_obj["login"]})
                if usr_uid not in seen_user_uids:
                    seen_user_uids.add(usr_uid)
                    top_level_users.append(user_obj)

            resources_list.append({
                "uid": res_uid,
                "type": res_record.record_type,
                "title": res_record.title,
                "pam_settings": pam_settings_dict,
                "users": resource_user_entries,
            })

        return resources_list, top_level_users

    def _build_user_title_index(self, params):
        """Index every pamUser / login record by lowercased title for title-based linking."""
        index = {}
        record_cache = getattr(params, "record_cache", {}) or {}
        for uid in record_cache:
            try:
                rec = vault.KeeperRecord.load(params, uid)
            except Exception:
                continue
            if not rec or not isinstance(rec, vault.TypedRecord):
                continue
            if rec.record_type not in ("pamUser", "login"):
                continue
            if rec.title:
                index.setdefault(rec.title.strip().lower(), uid)
        return index

    def _extract_user_uids(self, pam_settings_dict, title_to_uid=None):
        """Return all user record UIDs referenced inside a pamSettings dict.

        Falls back to title-based resolution against ``title_to_uid`` when
        the record stores a title (e.g. KCM-imported records, PR #1942)
        instead of a UID in launch_credentials / administrative_credentials.
        """
        user_uids = []
        title_to_uid = title_to_uid or {}
        conn = pam_settings_dict.get("connection") or {}
        if isinstance(conn, dict):
            for uid in (conn.get("userRecords") or []):
                if uid and uid not in user_uids:
                    user_uids.append(uid)
            # KCM-style title references (PR #1942 schema)
            for key in ("launch_credentials", "administrative_credentials"):
                ref = conn.get(key)
                if not isinstance(ref, str) or not ref:
                    continue
                # If it already looks like a UID, accept as-is
                if len(ref) == 22 and "/" not in ref and " " not in ref:
                    if ref not in user_uids:
                        user_uids.append(ref)
                    continue
                # Otherwise treat as a title and resolve against the index
                resolved = title_to_uid.get(ref.strip().lower())
                if resolved and resolved not in user_uids:
                    user_uids.append(resolved)
        # Some record types also reference admin via adminRef / adminCredentialRef at top level
        for key in ("adminRef", "adminCredentialRef"):
            uid = pam_settings_dict.get(key)
            if uid and uid not in user_uids:
                user_uids.append(uid)
        return user_uids

    def _load_user_obj(self, params, usr_uid):
        """Load a pamUser/login record and return a plain dict, or None on failure."""
        usr_record = vault.KeeperRecord.load(params, usr_uid)
        if not usr_record or not isinstance(usr_record, vault.TypedRecord):
            logging.debug("Export: user UID %s not found or not TypedRecord", usr_uid)
            return None
        login_field = usr_record.get_typed_field("login")
        login = ""
        if login_field:
            raw = login_field.get_default_value()
            login = str(raw) if raw is not None else ""
        return {
            "uid": usr_uid,
            "type": usr_record.record_type,
            "title": usr_record.title,
            "login": login,
        }
