from __future__ import annotations
import argparse
import json
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
    parser.add_argument('--format', dest='format', action='store', choices=['table', 'json'],
                        default='table', help='Output format (table, json)')

    def get_parser(self):
        return PAMActionServiceListCommand.parser

    def _collect_by_user(self, params: KeeperParams, record_link: RecordLink, user_service: UserService):
        service_map = {}
        for resource_vertex in record_link.dag.get_root.has_vertices(edge_type=EdgeType.LINK):

            resource_record = vault.KeeperRecord.load(params, resource_vertex.uid)  # type: Optional[TypedRecord]
            if resource_record is None or resource_record.record_type != PAM_MACHINE:
                continue

            resource_active = True
            user_data_edge = resource_vertex.get_data()
            if user_data_edge is not None:
                user_data = user_data_edge.content_as_object(MachineData)
                resource_active = not user_data.no_update_services

            user_vertices = user_service.get_user_vertices(resource_vertex.uid)
            if len(user_vertices) > 0:
                for user_vertex in user_vertices:
                    user_record = vault.KeeperRecord.load(params, user_vertex.uid)  # type: Optional[TypedRecord]
                    if user_record is None:
                        continue
                    acl = user_service.get_acl(resource_record.record_uid, user_record.record_uid)
                    if acl is None or not acl.controls_services:
                        continue

                    user_active = True
                    user_data_edge = user_vertex.get_data()
                    if user_data_edge is not None:
                        user_data = user_data_edge.content_as_object(UserData)
                        user_active = not user_data.no_update_services

                    if user_record.record_uid not in service_map:
                        service_map[user_record.record_uid] = {
                            "title": user_record.title,
                            "uid": user_record.record_uid,
                            "active": user_active,
                            "machines": []
                        }
                    service_map[user_record.record_uid]["machines"].append({
                        "title": resource_record.title,
                        "uid": resource_record.record_uid,
                        "active": resource_active,
                    })
        return service_map

    def _collect_by_machine(self, params: KeeperParams, record_link: RecordLink, user_service: UserService):
        service_map = {}
        for resource_vertex in record_link.dag.get_root.has_vertices(edge_type=EdgeType.LINK):
            resource_record = vault.KeeperRecord.load(params, resource_vertex.uid)  # type: Optional[TypedRecord]
            if resource_record is None or resource_record.record_type != PAM_MACHINE:
                continue

            resource_active = True
            user_data_edge = resource_vertex.get_data()
            if user_data_edge is not None:
                user_data = user_data_edge.content_as_object(MachineData)
                resource_active = not user_data.no_update_services

            user_vertices = user_service.get_user_vertices(resource_vertex.uid)
            if len(user_vertices) > 0:
                for user_vertex in user_vertices:
                    user_record = vault.KeeperRecord.load(params, user_vertex.uid)  # type: Optional[TypedRecord]
                    if user_record is None:
                        continue
                    acl = user_service.get_acl(resource_record.record_uid, user_record.record_uid)
                    if acl is None or not acl.controls_services:
                        continue

                    user_active = True
                    user_data_edge = user_vertex.get_data()
                    if user_data_edge is not None:
                        user_data = user_data_edge.content_as_object(UserData)
                        user_active = not user_data.no_update_services

                    if resource_record.record_uid not in service_map:
                        service_map[resource_record.record_uid] = {
                            "title": resource_record.title,
                            "uid": resource_record.record_uid,
                            "active": resource_active,
                            "users": []
                        }
                    service_map[resource_record.record_uid]["users"].append({
                        "title": user_record.title,
                        "uid": user_record.record_uid,
                        "active": user_active,
                    })
        return service_map

    def _print_by_user(self, service_map):
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
                text = f"{machine['title']} ({machine['uid']})"
                if not machine['active']:
                    text += f" : {bcolors.FAIL}Disabled{bcolors.ENDC}"
                print(f"    * {text}")
            print("")
        if not printed_something:
            print(f"  {bcolors.FAIL}There are no service mappings.{bcolors.ENDC}")

    def _print_by_machine(self, service_map):
        print("")
        printed_something = False
        print(self._h("Machine Mapping"))
        for resource_uid in service_map:
            resource = service_map[resource_uid]
            printed_something = True
            active_text = ""
            if not resource['active']:
                active_text = f" {bcolors.FAIL}Disabled{bcolors.ENDC}"
            print(f"  {self._b(resource['title'])} ({resource_uid}){active_text}")
            for user in resource["users"]:
                text = f"{user['title']} ({user['uid']})"
                if not user['active']:
                    text += f" : {bcolors.FAIL}Disabled{bcolors.ENDC}"
                print(f"    * {text}")
            print("")
        if not printed_something:
            print(f"  {bcolors.FAIL}There are no service mappings.{bcolors.ENDC}")

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway", "none_set")
        format_type = kwargs.get('format') or 'table'

        try:
            gateway_context = GatewayContext.from_gateway(params=params,
                                                          gateway=gateway,
                                                          configuration_uid=kwargs.get('configuration_uid'))
            if gateway_context is None:
                message = f'Could not find the gateway configuration for {gateway}.'
                if format_type == 'json':
                    print(json.dumps({'message': message}, indent=2))
                else:
                    print(f"{bcolors.FAIL}{message}{bcolors.ENDC}")
                return
        except MultiConfigurationException as err:
            if format_type == 'json':
                configs = []
                for item in (err.items or []):
                    record = item.get('configuration_record')
                    if record is not None:
                        configs.append({
                            'uid': getattr(record, 'record_uid', ''),
                            'title': getattr(record, 'title', ''),
                        })
                print(json.dumps({
                    'message': f'Found multiple configuration records for gateway {gateway}.',
                    'configurations': configs,
                }, indent=2))
            else:
                multi_conf_msg(gateway, err)
            return

        record_link = RecordLink(record=gateway_context.configuration,
                                 params=params,
                                 fail_on_corrupt=False,
                                 agent=f"Cmdr/{__version__}",
                                 use_per_graph_endpoints=False)

        # This will trigger the migration.
        user_service = UserService(record=gateway_context.configuration,
                                   record_linking=record_link,
                                   params=params,
                                   fail_on_corrupt=False,
                                   agent=f"Cmdr/{__version__}")

        by_machine = bool(kwargs.get("do_by_machine"))
        if by_machine:
            service_map = self._collect_by_machine(params=params,
                                                   record_link=record_link,
                                                   user_service=user_service)
        else:
            service_map = self._collect_by_user(params=params,
                                                record_link=record_link,
                                                user_service=user_service)

        if format_type == 'json':
            payload = {
                'gateway': gateway_context.gateway_name,
                'gateway_uid': gateway_context.gateway_uid,
                'configuration_uid': gateway_context.configuration_uid,
                'group_by': 'machine' if by_machine else 'user',
                'mappings': list(service_map.values()),
            }
            print(json.dumps(payload, indent=2))
            return

        if by_machine:
            self._print_by_machine(service_map)
        else:
            self._print_by_user(service_map)
