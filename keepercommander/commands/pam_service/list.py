from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ...display import bcolors
from ... import vault
from ...discovery_common.user_service import UserService
from ...discovery_common.constants import PAM_MACHINE
from ...keeper_dag import EdgeType
from ... import __version__
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionServiceListCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-service-list')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')

    def get_parser(self):
        return PAMActionServiceListCommand.parser

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

        user_service = UserService(record=gateway_context.configuration, params=params, fail_on_corrupt=False,
                                   agent=f"Cmdr/{__version__}")

        service_map = {}
        for resource_vertex in user_service.dag.get_root.has_vertices(edge_type=EdgeType.LINK):
            resource_record = vault.KeeperRecord.load(params, resource_vertex.uid)  # type: Optional[TypedRecord]
            if resource_record is None or resource_record.record_type != PAM_MACHINE:
                continue
            user_vertices = user_service.get_user_vertices(resource_vertex.uid)
            if len(user_vertices) > 0:
                for user_vertex in user_vertices:
                    user_record = vault.KeeperRecord.load(params, user_vertex.uid)  # type: Optional[TypedRecord]
                    if user_record is None:
                        continue
                    acl = user_service.get_acl(resource_record.record_uid, user_record.record_uid)
                    if acl is None or (acl.is_service is False and acl.is_task is False):
                        continue
                    if user_record.record_uid not in service_map:
                        service_map[user_record.record_uid] = {
                            "title": user_record.title,
                            "machines": []
                        }
                    text = f"{resource_record.title} ({resource_record.record_uid}) :"
                    comma = ""
                    if acl.is_service:
                        text += f" {bcolors.OKGREEN}Services{bcolors.ENDC}"
                        comma = ","
                    if acl.is_task:
                        text += f"{comma} {bcolors.OKGREEN}Scheduled Tasks{bcolors.ENDC}"
                    if acl.is_iis_pool:
                        text += f"{comma} {bcolors.OKGREEN}IIS Pools{bcolors.ENDC}"
                    service_map[user_record.record_uid]["machines"].append(text)

        print("")
        printed_something = False
        print(self._h("User Mapping"))
        for user_uid in service_map:
            user = service_map[user_uid]
            printed_something = True
            print(f"  {self._b(user['title'])} ({user_uid})")
            for machine in user["machines"]:
                print(f"    * {machine}")
            print("")
        if not printed_something:
            print(f"  {bcolors.FAIL}There are no service mappings.{bcolors.ENDC}")
