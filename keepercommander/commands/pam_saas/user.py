from __future__ import annotations
import argparse
import json
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from ... import vault
from . import get_plugins_map
from ...utils import value_to_boolean
from ...discovery_common.record_link import RecordLink
from ...discovery_common.constants import PAM_USER
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionSaasUserCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action saas user')

    parser.add_argument('--user-record-uid', '-u', required=True, dest='user_uid', action='store',
                        help='The UID of the User record')
    parser.add_argument('--format', dest='format', action='store', choices=['text', 'json'],
                        default='text', help='Output format (text, json)')

    def get_parser(self):
        return PAMActionSaasUserCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        user_uid = kwargs.get("user_uid")  # type: str
        format_type = kwargs.get("format") or "text"
        as_json = format_type == "json"

        def _fail(message: str):
            if as_json:
                print(json.dumps({"user": None, "message": message}, indent=2))
            else:
                print("")
                print(self._f(message))

        if not as_json:
            print("")

        # Check to see if the record exists.
        user_record = vault.KeeperRecord.load(params, user_uid)  # type: Optional[TypedRecord]
        if user_record is None:
            _fail("The user record does not exists.")
            return

        # Make sure this user is a PAM User.
        if user_record.record_type != PAM_USER:
            _fail("The user record is not a PAM User.")
            return

        record_rotation = params.record_rotation_cache.get(user_record.record_uid)
        if record_rotation is not None:
            configuration_uid = record_rotation.get("configuration_uid")
        else:
            _fail("The user record does not have any rotation settings.")
            return

        if configuration_uid is None:
            _fail("The user record does not have the configuration record set in the rotation settings.")
            return

        gateway_context = GatewayContext.from_configuration_uid(params, configuration_uid)

        if gateway_context is None:
            _fail("The user record does not have the set gateway")
            return

        plugins = get_plugins_map(params, gateway_context)

        record_link = RecordLink(record=gateway_context.configuration, params=params, fail_on_corrupt=False)
        user_vertex = record_link.get_record_link(user_uid)
        if user_vertex is None:
            _fail("Cannot find the user in the record link graph.")
            return

        result = {
            "user": {
                "uid": user_record.record_uid,
                "title": user_record.title,
            },
            "parents": [],
        }

        if not as_json:
            print(self._h(user_record.title))

        # User's can have multiple ACL edges to different parents.
        # One of those ACL edges, in the rotation settings, may a populated saas_record_uid_list
        for parent_vertex in user_vertex.belongs_to_vertices():

            # Check to see if the record exists.
            parent_record = vault.KeeperRecord.load(params, parent_vertex.uid)  # type: Optional[TypedRecord]
            if parent_record is None:
                parent_entry = {
                    "uid": parent_vertex.uid,
                    "title": None,
                    "record_type": None,
                    "message": "Parent record does not exist. The record may have been deleted, "
                               "however the relationship still exists.",
                    "saas_configs": [],
                }
                result["parents"].append(parent_entry)
                if not as_json:
                    print(self._f(f"* Parent record UID {parent_vertex.uid} does not exists."))
                    print("   The record may have been deleted, however the relationship still exists.")
                    print("")
                continue

            parent_entry = {
                "uid": parent_record.record_uid,
                "title": parent_record.title,
                "record_type": parent_record.record_type,
                "saas_configs": [],
            }

            if not as_json:
                print(self._b(f" * {parent_record.title}, {parent_record.record_type}"))
                print("")

            acl = record_link.get_acl(user_uid, parent_vertex.uid)
            if acl is not None and acl.rotation_settings is not None:
                saas_record_uid_list = acl.rotation_settings.saas_record_uid_list
                if saas_record_uid_list is None or len(saas_record_uid_list) == 0:
                    message = "The user does not have any SaaS service rotations."
                    parent_entry["message"] = message
                    result["parents"].append(parent_entry)
                    if as_json:
                        print(json.dumps(result, indent=2))
                    else:
                        print(f"{bcolors.WARNING}    {message}{bcolors.ENDC}")
                    return

                for config_record_uid in saas_record_uid_list:
                    config_record = vault.KeeperRecord.load(params, config_record_uid)  # type: Optional[TypedRecord]
                    if config_record is None:
                        missing = {
                            "uid": config_record_uid,
                            "title": None,
                            "message": "Record no longer exists.",
                        }
                        parent_entry["saas_configs"].append(missing)
                        if not as_json:
                            print(f"{bcolors.WARNING} * Record UID {config_record_uid} not longer exists."
                                  f"{bcolors.ENDC}")
                        continue

                    if not as_json:
                        print(self._gr(f"   {config_record.title}"))

                    plugin_name = "<Not Set>"
                    saas_type_field = next((x for x in config_record.custom if x.label == "SaaS Type"), None)
                    if (saas_type_field is not None and saas_type_field.value is not None
                            and len(saas_type_field.value) > 0):
                        plugin_name = saas_type_field.value[0]

                    plugin = plugins.get(plugin_name)
                    supported = plugin is not None

                    is_active = True
                    rotation_active_field = next((x for x in config_record.custom if x.label == "Active"),
                                                 None)

                    if (rotation_active_field is not None and rotation_active_field.value is not None
                            and len(rotation_active_field.value) > 0):
                        is_active = value_to_boolean(rotation_active_field.value[0])
                        if is_active is None:
                            is_active = True

                    fields = {}
                    if plugin is not None:
                        for field in plugin.fields:
                            value = next((x.value for x in config_record.custom if x.label == field.label), None)
                            if value is not None:
                                if len(value) > 0:
                                    value = value[0]
                                else:
                                    value = None
                            field_info = {
                                "value": value,
                                "default": False,
                                "set": value is not None,
                            }
                            if value is None and field.default_value is not None:
                                field_info["value"] = field.default_value
                                field_info["default"] = True
                                field_info["set"] = False
                            fields[field.label] = field_info

                    saas_entry = {
                        "uid": config_record.record_uid,
                        "title": config_record.title,
                        "saas_type": plugin_name,
                        "supported": supported,
                        "active": bool(is_active),
                        "fields": fields,
                    }
                    parent_entry["saas_configs"].append(saas_entry)

                    if not as_json:
                        display_plugin = plugin_name
                        if not supported:
                            display_plugin += " (" + self._f("Not Supported") + ")"
                        rotation_active = self._gr("Active") if is_active else self._f("Inactive")
                        print(f"     {bcolors.BOLD}SaaS Type{bcolors.ENDC}: {display_plugin}")
                        print(f"     {bcolors.BOLD}Config Record UID{bcolors.ENDC}: {config_record.record_uid}")
                        print(f"     {bcolors.BOLD}Active{bcolors.ENDC}: {rotation_active}")

                        if plugin is not None:
                            for field in plugin.fields:
                                field_info = fields[field.label]
                                value = field_info["value"]
                                if not field_info["set"] and field_info["default"]:
                                    value = f"{value} ({bcolors.OKBLUE}Default{bcolors.ENDC})"
                                elif not field_info["set"]:
                                    value = f"{bcolors.FAIL}Not Set{bcolors.ENDC}"
                                print(f"     {bcolors.BOLD}{field.label}{bcolors.ENDC}: {value}")
                        print("")

            result["parents"].append(parent_entry)

        if as_json:
            print(json.dumps(result, indent=2))
