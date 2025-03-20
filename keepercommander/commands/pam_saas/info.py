from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from ... import vault
from . import get_gateway_saas_schema
from ...utils import value_to_boolean
from keepercommander.discovery_common.record_link import RecordLink
from keepercommander.discovery_common.constants import PAM_USER
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionSaasInfoCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-saas-info')

    parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                        help='The UID of the User record')

    def get_parser(self):
        return PAMActionSaasInfoCommand.parser

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

        schema_res = get_gateway_saas_schema(params, gateway_context)
        if schema_res is None:
            return

        record_link = RecordLink(record=gateway_context.configuration, params=params, fail_on_corrupt=False)
        user_vertex = record_link.get_record_link(user_uid)
        if user_vertex is None:
            print(self._f("Cannot find the user in the record link graph."))
            return

        print(self._h(user_record.title))

        for parent_vertex in user_vertex.belongs_to_vertices():

            # Check to see if the record exists.
            parent_record = vault.KeeperRecord.load(params, parent_vertex.uid)  # type: Optional[TypedRecord]
            if parent_record is None:
                print(self._f(f"  Parent record UID {parent_vertex.uid} does not exists."))
                continue

            print(self._b(f" * {parent_record.title}, {parent_record.record_type}"))
            print("")

            acl = record_link.get_acl(user_uid, parent_vertex.uid)
            if acl is not None and acl.rotation_settings is not None:
                saas_record_uid_list = acl.rotation_settings.saas_record_uid_list
                if saas_record_uid_list is None or len(saas_record_uid_list) == 0:
                    print(f"{bcolors.WARNING}    The user does not have any SaaS service rotations.{bcolors.ENDC}")
                    return
                for record_uid in saas_record_uid_list:
                    config_record = vault.KeeperRecord.load(params, record_uid)  # type: Optional[TypedRecord]
                    if config_record is None:
                        print(f"{bcolors.WARNING} * Record UID {record_uid} not longer exists.{bcolors.ENDC}")
                        continue
                    print(self._gr(f"   {config_record.title}"))

                    saas_type = "Unknown"
                    saas_type_field = next((x for x in config_record.custom if x.label == "SaaS Type"), None)
                    if (saas_type_field is not None and saas_type_field.value is not None
                            and len(saas_type_field.value) > 0):
                        saas_type = saas_type_field.value[0]

                    saas_schema = next((x for x in schema_res.get('data') if x.get('id') == saas_type), None)
                    rotation_active = self._gr("Active")
                    rotation_active_field = next((x for x in config_record.custom if x.label == "Active"),
                                                 None)
                    if (rotation_active_field is not None and rotation_active_field.value is not None
                            and len(rotation_active_field.value) > 0):
                        is_active = value_to_boolean(rotation_active_field.value[0])
                        if is_active is False:
                            rotation_active = self._f("Inactive")

                    print(f"     {bcolors.BOLD}SaaS Type{bcolors.ENDC}: {saas_type}")
                    print(f"     {bcolors.BOLD}Config Record UID{bcolors.ENDC}: {config_record.record_uid}")
                    print(f"     {bcolors.BOLD}Active{bcolors.ENDC}: {rotation_active}")
                    schema = saas_schema.get("schema")

                    # If a custom plugin, they might have removed it.
                    if schema is None:
                        print(f"     {bcolors.FAIL}Cannot find schema for plugin.{bcolors.ENDC}")
                        continue

                    for field in schema:
                        label = field.get("label")
                        value = next((x.value for x in config_record.custom if x.label == label), None)
                        if value is not None:
                            value = value[0]
                        default = ""
                        if value is None and field.get("default_value") is not None:
                            default = f" (default: {field.get('default_value')})"
                        print(f"     {bcolors.BOLD}{label}{bcolors.ENDC}: {value}{default}")
                    print("")
