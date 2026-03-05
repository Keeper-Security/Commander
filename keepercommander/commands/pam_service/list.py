from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ...display import bcolors
from ... import vault
from ...discovery_common.user_service import UserService
from ...discovery_common.record_link import RecordLink
from ...discovery_common.constants import PAM_MACHINE
from ...discovery_common.types import UserData, MachineData
from ...keeper_dag import EdgeType
from ... import __version__
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionServiceListCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action service list')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')
    parser.add_argument('--by-machine', '-m', required=False, dest='do_by_machine', action='store_true',
                        help='List by machine')

    def get_parser(self):
        return PAMActionServiceListCommand.parser

    def _by_user(self, params: KeeperParams, record_link: RecordLink, user_service: UserService):
        service_map = {}
        for resource_vertex in record_link.dag.get_root.has_vertices(edge_type=EdgeType.LINK):

            resource_record = vault.KeeperRecord.load(params, resource_vertex.uid)  # type: Optional[TypedRecord]
            if resource_record is None or resource_record.record_type != PAM_MACHINE:
                continue

            resource_active = True
            user_data_edge = resource_vertex.get_data()
            if user_data_edge is not None:
                user_data = user_data_edge.content_as_object(MachineData)
                resource_active = not user_data.rotation_settings.no_update_services

            user_vertices = user_service.get_user_vertices(resource_vertex.uid)
            if len(user_vertices) > 0:
                for user_vertex in user_vertices:
                    user_record = vault.KeeperRecord.load(params, user_vertex.uid)  # type: Optional[TypedRecord]
                    if user_record is None:
                        continue
                    acl = user_service.get_acl(resource_record.record_uid, user_record.record_uid)
                    if acl is None or acl.rotation_settings is None or not acl.rotation_settings.controls_services:
                        continue

                    user_active = True
                    user_data_edge = user_vertex.get_data()
                    if user_data_edge is not None:
                        user_data = user_data_edge.content_as_object(UserData)
                        user_active = not user_data.rotation_settings.no_update_services

                    if user_record.record_uid not in service_map:
                        service_map[user_record.record_uid] = {
                            "title": user_record.title,
                            "active": user_active,
                            "machines": []
                        }
                    text = f"{resource_record.title} ({resource_record.record_uid})"
                    if not resource_active:
                        text += f" : {bcolors.FAIL}Disabled{bcolors.ENDC}"
                    service_map[user_record.record_uid]["machines"].append(text)

        print("")
        printed_something = False
        print(self._h("User Mapping"))
        for user_uid in service_map:
            user = service_map[user_uid]
            printed_something = True
            active_text = ""
            if not user['active']:
                active_text = f" {bcolors.FAIL}Disabled{bcolors.ENDC}"
            print(f"  {self._b(user['title'])} ({user_uid}){active_text}")
            for machine in user["machines"]:
                print(f"    * {machine}")
            print("")
        if not printed_something:
            print(f"  {bcolors.FAIL}There are no service mappings.{bcolors.ENDC}")

    def _by_machine(self, params: KeeperParams, record_link: RecordLink, user_service: UserService):
        service_map = {}
        for resource_vertex in record_link.dag.get_root.has_vertices(edge_type=EdgeType.LINK):
            resource_record = vault.KeeperRecord.load(params, resource_vertex.uid)  # type: Optional[TypedRecord]
            if resource_record is None or resource_record.record_type != PAM_MACHINE:
                continue

            resource_active = True
            user_data_edge = resource_vertex.get_data()
            if user_data_edge is not None:
                user_data = user_data_edge.content_as_object(MachineData)
                resource_active = not user_data.rotation_settings.no_update_services

            user_vertices = user_service.get_user_vertices(resource_vertex.uid)
            if len(user_vertices) > 0:
                for user_vertex in user_vertices:
                    user_record = vault.KeeperRecord.load(params, user_vertex.uid)  # type: Optional[TypedRecord]
                    if user_record is None:
                        continue
                    acl = user_service.get_acl(resource_record.record_uid, user_record.record_uid)
                    if acl is None or acl.rotation_settings is None or not acl.rotation_settings.controls_services:
                        continue

                    user_active = True
                    user_data_edge = user_vertex.get_data()
                    if user_data_edge is not None:
                        user_data = user_data_edge.content_as_object(UserData)
                        user_active = not user_data.rotation_settings.no_update_services

                    if user_record.record_uid not in service_map:
                        service_map[resource_record.record_uid] = {
                            "title": resource_record.title,
                            "active": resource_active,
                            "users": []
                        }
                    text = f"{user_record.title} ({user_record.record_uid})"
                    if not user_active:
                        text += f" : {bcolors.FAIL}Disabled{bcolors.ENDC}"
                    service_map[resource_record.record_uid]["users"].append(text)

        print("")
        printed_something = False
        print(self._h("Machine Mapping"))
        for resource_uid in service_map:
            user = service_map[resource_uid]
            printed_something = True
            active_text = ""
            if not user['active']:
                active_text = f" {bcolors.FAIL}Disabled{bcolors.ENDC}"
            print(f"  {self._b(user['title'])} ({resource_uid}){active_text}")
            for user in user["users"]:
                print(f"    * {user}")
            print("")
        if not printed_something:
            print(f"  {bcolors.FAIL}There are no service mappings.{bcolors.ENDC}")

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")

        try:
            gateway_context = GatewayContext.from_gateway(params=params,
                                                          gateway=gateway,
                                                          configuration_uid=kwargs.get('configuration_uid'))
            if gateway_context is None:
                print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.{bcolors.ENDC}")
                return
        except MultiConfigurationException as err:
            multi_conf_msg(gateway, err)
            return

        record_link = RecordLink(record=gateway_context.configuration,
                                 params=params,
                                 fail_on_corrupt=False,
                                 agent=f"Cmdr/{__version__}")

        # This will trigger the migration.
        user_service = UserService(record=gateway_context.configuration,
                                   record_linking=record_link,
                                   params=params,
                                   fail_on_corrupt=False,
                                   agent=f"Cmdr/{__version__}")

        if kwargs.get("do_by_machine"):
            self._by_machine(params=params,
                             record_link=record_link,
                             user_service=user_service)
        else:
            self._by_user(params=params,
                          record_link=record_link,
                          user_service=user_service)
