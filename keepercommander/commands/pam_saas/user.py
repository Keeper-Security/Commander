from __future__ import annotations
import argparse
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

    def get_parser(self):
        return PAMActionSaasUserCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        user_uid = kwargs.get("user_uid")  # type: str

        print("")

        # Check to see if the record exists.
        user_record = vault.KeeperRecord.load(params, user_uid)  # type: Optional[TypedRecord]
        if user_record is None:
            print(self._f("The user record does not exists."))
            return

        # Make sure this user is a PAM User.
        if user_record.record_type != PAM_USER:
            print(self._f("The user record is not a PAM User."))
            return

        record_rotation = params.record_rotation_cache.get(user_record.record_uid)
        if record_rotation is not None:
            configuration_uid = record_rotation.get("configuration_uid")
        else:
            print(self._f("The user record does not have any rotation settings."))
            return

        if configuration_uid is None:
            print(self._f("The user record does not have the configuration record set in the rotation settings."))
            return

        gateway_context = GatewayContext.from_configuration_uid(params, configuration_uid)

        if gateway_context is None:
            print(self._f("The user record does not have the set gateway"))
            return

        plugins = get_plugins_map(params, gateway_context)

        record_link = RecordLink(record=gateway_context.configuration, params=params, fail_on_corrupt=False)
        user_vertex = record_link.get_record_link(user_uid)
        if user_vertex is None:
            print(self._f("Cannot find the user in the record link graph."))
            return

        print(self._h(user_record.title))

        missing_configs = []

        # User's can have multiple ACL edges to different parents.
        # One of those ACL edges, in the rotation settings, may a populated saas_record_uid_list
        for parent_vertex in user_vertex.belongs_to_vertices():

            # Check to see if the record exists.
            parent_record = vault.KeeperRecord.load(params, parent_vertex.uid)  # type: Optional[TypedRecord]
            if parent_record is None:
                print(self._f(f"* Parent record UID {parent_vertex.uid} does not exists."))
                print("   The record may have been deleted, however the relationship still exists.")
                print("")
                continue

            print(self._b(f" * {parent_record.title}, {parent_record.record_type}"))
            print("")

            acl = record_link.get_acl(user_uid, parent_vertex.uid)
            if acl is not None and acl.rotation_settings is not None:
                saas_record_uid_list = acl.rotation_settings.saas_record_uid_list
                if saas_record_uid_list is None or len(saas_record_uid_list) == 0:
                    print(f"{bcolors.WARNING}    The user does not have any SaaS service rotations.{bcolors.ENDC}")
                    return

                for config_record_uid in saas_record_uid_list:
                    config_record = vault.KeeperRecord.load(params, config_record_uid)  # type: Optional[TypedRecord]
                    if config_record is None:
                        print(f"{bcolors.WARNING} * Record UID {config_record_uid} not longer exists.{bcolors.ENDC}")
                        continue
                    print(self._gr(f"   {config_record.title}"))

                    plugin_name = "<Not Set>"
                    saas_type_field = next((x for x in config_record.custom if x.label == "SaaS Type"), None)
                    if (saas_type_field is not None and saas_type_field.value is not None
                            and len(saas_type_field.value) > 0):
                        plugin_name = saas_type_field.value[0]

                    plugin = plugins.get(plugin_name)

                    # This might have been a valid plugin, or the name is mistyped, so it's not supported.
                    if plugin is None:
                        plugin_name += " (" + self._f("Not Supported") + ")"

                    rotation_active = self._gr("Active")
                    rotation_active_field = next((x for x in config_record.custom if x.label == "Active"),
                                                 None)

                    if (rotation_active_field is not None and rotation_active_field.value is not None
                            and len(rotation_active_field.value) > 0):
                        is_active = value_to_boolean(rotation_active_field.value[0])
                        if is_active is False:
                            rotation_active = self._f("Inactive")

                    print(f"     {bcolors.BOLD}SaaS Type{bcolors.ENDC}: {plugin_name}")
                    print(f"     {bcolors.BOLD}Config Record UID{bcolors.ENDC}: {config_record.record_uid}")
                    print(f"     {bcolors.BOLD}Active{bcolors.ENDC}: {rotation_active}")

                    if plugin is not None:

                        for field in plugin.fields:
                            value = next((x.value for x in config_record.custom if x.label == field.label), None)
                            if value is not None:
                                if len(value) > 0:
                                    value = value[0]
                                else:
                                    value = None
                            if value is None:
                                if field.default_value is not None:
                                    value = f"{field.default_value} ({bcolors.OKBLUE}Default{bcolors.ENDC})"
                                else:
                                    value = f"{bcolors.FAIL}Not Set{bcolors.ENDC}"
                            print(f"     {bcolors.BOLD}{field.label}{bcolors.ENDC}: {value}")
                    print("")
