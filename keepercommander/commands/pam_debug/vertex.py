from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ...display import bcolors
from ...discovery_common.infrastructure import Infrastructure
from ...discovery_common.types import DiscoveryObject
from ...discovery_common.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from ...keeper_dag import EdgeType
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class PAMDebugVertexCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action debug info')

    type_name_map = {
        PAM_USER: "PAM User",
        PAM_MACHINE: "PAM Machine",
        PAM_DATABASE: "PAM Database",
        PAM_DIRECTORY: "PAM Directory",
    }

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')

    parser.add_argument('--vertex', '-i', required=True, dest='vertex_uid', action='store',
                        help='Vertex in infrastructure graph')

    def get_parser(self):
        return PAMDebugVertexCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        debug_level = kwargs.get("debug_level", False)

        configuration_uid = kwargs.get('configuration_uid')
        try:
            gateway_context = GatewayContext.from_gateway(params=params,
                                                          gateway=gateway,
                                                          configuration_uid=configuration_uid)
            if gateway_context is None:
                print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.{bcolors.ENDC}")
                return
        except MultiConfigurationException as err:
            multi_conf_msg(gateway, err)
            return

        infra = Infrastructure(record=gateway_context.configuration, params=params, fail_on_corrupt=False,
                               debug_level=debug_level)
        infra.load()

        vertex_uid = kwargs.get("vertex_uid")
        vertex = infra.dag.get_vertex(vertex_uid)
        if vertex is None:
            print(f"{bcolors.FAIL}Could not find the vertex in the graph for {gateway}.")
            return

        content = DiscoveryObject.get_discovery_object(vertex)
        missing_since = "NA"
        if content.missing_since_ts is not None:
            missing_since = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(content.missing_since_ts))

        print(self._h("Discovery Object Information"))
        print(f"  {self._b('Vertex UID')}: {content.uid}")
        print(f"  {self._b('Object ID')}: {content.id}")
        print(f"  {self._b('Record UID')}: {content.record_uid}")
        print(f"  {self._b('Parent Record UID')}: {content.parent_record_uid}")
        print(f"  {self._b('Shared Folder UID')}: {content.shared_folder_uid}")
        print(f"  {self._b('Record Type')}: {content.record_type}")
        print(f"  {self._b('Object Type')}: {content.object_type_value}")
        print(f"  {self._b('Ignore Object')}: {content.ignore_object}")
        print(f"  {self._b('Rule Engine Result')}: {content.action_rules_result}")
        print(f"  {self._b('Name')}: {content.name}")
        print(f"  {self._b('Generated Title')}: {content.title}")
        print(f"  {self._b('Generated Description')}: {content.description}")
        print(f"  {self._b('Missing Since')}: {missing_since}")
        print(f"  {self._b('Discovery Notes')}:")
        for note in content.notes:
            print(f" * {note}")
        if content.error is not None:
            print(f"{bcolors.FAIL}    Error: {content.error}{bcolors.ENDC}")
            if content.stacktrace is not None:
                print(f"{bcolors.FAIL}    Stack Trace:{bcolors.ENDC}")
                print(f"{bcolors.FAIL}{content.stacktrace}{bcolors.ENDC}")
        print("")
        print(f"{bcolors.HEADER}Record Type Specifics{bcolors.ENDC}")

        if content.record_type == PAM_USER:
            print(f"  {self._b('User')}: {content.item.user}")
            print(f"  {self._b('DN')}: {content.item.dn}")
            print(f"  {self._b('Database')}: {content.item.database}")
            print(f"  {self._b('Active')}: {content.item.active}")
            print(f"  {self._b('Expired')}: {content.item.expired}")
            print(f"  {self._b('Source')}: {content.item.source}")
        elif content.record_type == PAM_MACHINE:
            print(f"  {self._b('Host')}: {content.item.host}")
            print(f"  {self._b('IP')}: {content.item.ip}")
            print(f"  {self._b('Port')}: {content.item.port}")
            print(f"  {self._b('Operating System')}: {content.item.os}")
            print(f"  {self._b('Provider Region')}: {content.item.provider_region}")
            print(f"  {self._b('Provider Group')}: {content.item.provider_group}")
            print(f"  {self._b('Is the Gateway')}: {content.item.is_gateway}")
            print(f"  {self._b('Allows Admin')}: {content.item.allows_admin}")
            print(f"  {self._b('Admin Reason')}: {content.item.admin_reason}")
            print("")
            # If facts are not set, inside discover may not have been performed for the machine.
            if content.item.facts.id is not None and content.item.facts.name is not None:
                print(f"  {self._b('Machine Name')}: {content.item.facts.name}")
                print(f"  {self._b('Machine ID')}: {content.item.facts.id.machine_id}")
                print(f"  {self._b('Product ID')}: {content.item.facts.id.product_id}")
                print(f"  {self._b('Board Serial')}: {content.item.facts.id.board_serial}")
                print(f"  {self._b('Directories')}:")
                if content.item.facts.directories is not None and len(content.item.facts.directories) > 0:
                    for directory in content.item.facts.directories:
                        print(f"    * Directory Domain: {directory.domain}")
                        print(f"      Software: {directory.software}")
                        print(f"      Login Format: {directory.login_format}")
                else:
                    print("    Machines is not using any directories.")

                print("")
                print(f"  {self._b('Services')} (Non Builtin Users):")
                if len(content.item.facts.services) > 0:
                    for service in content.item.facts.services:
                        print(f"    * {service.name} = {service.user}")
                else:
                    print("    Machines has no services that are using non-builtin users.")

                print(f"  {self._b('Scheduled Tasks')} (Non Builtin Users)")
                if len(content.item.facts.tasks) > 0:
                    for task in content.item.facts.tasks:
                        print(f"    * {task.name} = {task.user}")
                else:
                    print("    Machines has no schedules tasks that are using non-builtin users.")

                print(f"  {self._b('IIS Pools')} (Non Builtin Users)")
                if len(content.item.facts.iis_pools) > 0:
                    for iis_pool in content.item.facts.iis_pools:
                        print(f"    * {iis_pool.name} = {iis_pool.user}")
                else:
                    print("    Machines has no IIS Pools that are using non-builtin users.")

            else:
                print(f"{bcolors.FAIL}    Machine facts are not set. Discover inside may not have been "
                      f"performed.{bcolors.ENDC}")
        elif content.record_type == PAM_DATABASE:
            print(f"  {self._b('Host')}: {content.item.host}")
            print(f"  {self._b('IP')}: {content.item.ip}")
            print(f"  {self._b('Port')}: {content.item.port}")
            print(f"  {self._b('Database Type')}: {content.item.type}")
            print(f"  {self._b('Database')}: {content.item.database}")
            print(f"  {self._b('Use SSL')}: {content.item.use_ssl}")
            print(f"  {self._b('Provider Region')}: {content.item.provider_region}")
            print(f"  {self._b('Provider Group')}: {content.item.provider_group}")
            print(f"  {self._b('Allows Admin')}: {content.item.allows_admin}")
            print(f"  {self._b('Admin Reason')}: {content.item.admin_reason}")
        elif content.record_type == PAM_DIRECTORY:
            print(f"  {self._b('Host')}: {content.item.host}")
            print(f"  {self._b('IP')}: {content.item.ip}")
            print(f"  {self._b('Port')}: {content.item.port}")
            print(f"  {self._b('Directory Type')}: {content.item.type}")
            print(f"  {self._b('Use SSL')}: {content.item.use_ssl}")
            print(f"  {self._b('Provider Region')}: {content.item.provider_region}")
            print(f"  {self._b('Provider Group')}: {content.item.provider_group}")
            print(f"  {self._b('Allows Admin')}: {content.item.allows_admin}")
            print(f"  {self._b('Admin Reason')}: {content.item.admin_reason}")

        print("")
        print(self._h("Belongs To Vertices (Parents)"))
        vertices = vertex.belongs_to_vertices()
        for vertex in vertices:
            content = DiscoveryObject.get_discovery_object(vertex)
            print(f"  * {content.description} ({vertex.uid})")
            for edge_type in [EdgeType.LINK, EdgeType.ACL, EdgeType.KEY, EdgeType.DELETION]:
                edge = vertex.get_edge(vertex, edge_type=edge_type)
                if edge is not None:
                    print(f"    . {edge_type}, active: {edge.active}")

        if len(vertices) == 0:
            print(f"{bcolors.FAIL}  Does not belong to anyone{bcolors.ENDC}")

        print("")
        print(f"{bcolors.HEADER}Vertices Belonging To (Children){bcolors.ENDC}")
        vertices = vertex.has_vertices()
        for vertex in vertices:
            content = DiscoveryObject.get_discovery_object(vertex)
            print(f"  * {content.description} ({vertex.uid})")
            for edge_type in [EdgeType.LINK, EdgeType.ACL, EdgeType.KEY, EdgeType.DELETION]:
                edge = vertex.get_edge(vertex, edge_type=edge_type)
                if edge is not None:
                    print(f"    . {edge_type}, active: {edge.active}")
        if len(vertices) == 0:
            print(f"  Does not have any children.")

        print("")
