from __future__ import annotations
import argparse
import os
from . import PAMGatewayActionDiscoverCommandBase
from ...display import bcolors
from ... import vault
from discovery_common.infrastructure import Infrastructure
from discovery_common.record_link import RecordLink
from discovery_common.types import UserAcl, DiscoveryObject
from keeper_dag import EdgeType
from importlib.metadata import version
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMGatewayActionDiscoverDebugCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-discover-command-debug')

    # The record to base everything on.
    parser.add_argument('--record-uid', '-i', required=False, dest='record_uid', action='store',
                        help='Keeper record UID.')

    # What to do
    parser.add_argument('--info', required=False, dest='info_flag',
                        action='store_true', help='Display information about the record.')
    parser.add_argument('--belongs-to', required=False, dest='belongs_to_flag',
                        action='store_true', help='Connect the record to the parent record.')
    parser.add_argument('--disconnect', required=False, dest='disconnect_flag',
                        action='store_true', help='Disconnect the record to the parent record.')
    parser.add_argument('--render', required=False, dest='render_flag', action='store_true',
                        help='Render graphs.')
    parser.add_argument('--version', required=False, dest='version_flag', action='store_true',
                       help='Get module versions.')

    # For --belongs-to and --disconnect
    parser.add_argument('--parent-record-uid', '-p', required=False, dest='parent_record_uid',
                        action='store', help='The parent record UID.')

    # For the info command
    parser.add_argument('--render-all-edges', required=False, dest='render_all_edges',
                        action='store_false', help='Render graphs.')
    parser.add_argument('--graph-dir',  required=False, dest='graph_dir', action='store',
                        help='Directory to save graphs.')
    parser.add_argument('--infra-graph-name',  required=False, dest='infra_name', action='store',
                        default="infra_graph", help='Infrastructure graph name.')
    parser.add_argument('--rl-graph-name',  required=False, dest='rl_name', action='store',
                        default="record_linking_graph", help='Record linking graph name.')
    parser.add_argument('--graph-type', '-gt', required=False, choices=['dot', 'twopi', 'patchwork'],
                        dest='graph_type', default="dot", action='store', help='The render graph type.')

    def get_parser(self):
        return PAMGatewayActionDiscoverDebugCommand.parser

    @staticmethod
    def _versions():
        print("")
        print(f"{bcolors.BOLD}keeper-dag version:{bcolors.ENDC} {version('keeper-dag')}")
        print(f"{bcolors.BOLD}discovery-common version:{bcolors.ENDC} {version('discovery-common')}")
        print("")

    @staticmethod
    def _show_info(params: KeeperParams, configuration_record: TypedRecord, record: TypedRecord):

        infra = Infrastructure(record=configuration_record, params=params)
        record_link = RecordLink(record=configuration_record, params=params)

        print("")
        print(f"{bcolors.BOLD}Configuration UID:{bcolors.ENDC} {configuration_record.record_uid}")
        print(f"{bcolors.BOLD}Configuration Key Bytes Hex:{bcolors.ENDC} {configuration_record.record_key.hex()}")
        print("")
        try:
            discovery_vertices = infra.dag.search_content({"record_uid": record.record_uid})
            if len(discovery_vertices) > 0:

                if len(discovery_vertices) > 1:
                    print(f"{bcolors.FAIL}Found multiple vertices with the record UID of "
                          f"{record.record_uid}{bcolors.ENDC}")
                    for vertex in discovery_vertices:
                        print(f" * Infrastructure Vertex UID: {vertex.uid}")
                    print("")

                discovery_vertex = discovery_vertices[0]
                content = DiscoveryObject.get_discovery_object(discovery_vertex)

                print(f"{bcolors.HEADER}Discovery Object Information{bcolors.ENDC}")
                print(f"Vertex UID: {content.uid}")
                print(f"Record UID: {content.record_uid}")
                print(f"Parent Record UID: {content.parent_record_uid}")
                print(f"Shared Folder UID: {content.shared_folder_uid}")
                print(f"Record Type: {content.record_type}")
                print(f"Object Type: {content.object_type_value}")
                print(f"Ignore Object: {content.ignore_object}")
                print(f"Rule Engine Result: {content.action_rules_result}")
                print(f"Discovery ID: {content.id}")
                print(f"Discovery Name: {content.name}")
                print(f"Discovery Title: {content.title}")
                print(f"Discovery Description: {content.description}")
                print(f"Discovery Notes:")
                for note in content.notes:
                    print(f" * {note}")
                if content.error is not None:
                    print(f"{bcolors.FAIL}Error: {content.error}{bcolors.ENDC}")
                    if content.stacktrace is not None:
                        print(f"{bcolors.FAIL}Stack Trace:{bcolors.ENDC}")
                        print(f"{bcolors.FAIL}{content.stacktrace}{bcolors.ENDC}")
                print("")
                print(f"{bcolors.HEADER}Record Type Specifics{bcolors.ENDC}")

                item_dict = content.item
                for k, v in item_dict.__dict__.items():
                    print(f"{k} = {v}")

                print("")
                print(f"{bcolors.HEADER}Belongs To Vertices{bcolors.ENDC}")
                vertices = discovery_vertex.belongs_to_vertices()
                for vertex in vertices:
                    content = DiscoveryObject.get_discovery_object(vertex)
                    print(f" * {content.description} ({vertex.uid})")
                    for edge_type in [EdgeType.LINK, EdgeType.ACL, EdgeType.KEY, EdgeType.DELETION]:
                        edge = discovery_vertex.get_edge(vertex, edge_type=edge_type)
                        if edge is not None:
                            print(f"    . {edge_type}, active: {edge.active}")

                if len(vertices) == 0:
                    print(f"{bcolors.FAIL}  Does not belong to anyone{bcolors.ENDC}")

                print("")
                print(f"{bcolors.HEADER}Vertices Belonging To{bcolors.ENDC}")
                vertices = discovery_vertex.has_vertices()
                for vertex in vertices:
                    content = DiscoveryObject.get_discovery_object(vertex)
                    print(f" * {content.description} ({vertex.uid})")
                    for edge_type in [EdgeType.LINK, EdgeType.ACL, EdgeType.KEY, EdgeType.DELETION]:
                        edge = vertex.get_edge(discovery_vertex, edge_type=edge_type)
                        if edge is not None:
                            print(f"    . {edge_type}, active: {edge.active}")
                if len(vertices) == 0:
                    print(f"  Does not have any children.")

                print("")
            else:
                print(f"{bcolors.FAIL}Could not find infrastructure vertex.{bcolors.ENDC}")
        except Exception as err:
            print(f"{bcolors.FAIL}Could not get information on infrastructure: {err}{bcolors.ENDC}")

        record_vertex = record_link.dag.get_vertex(record.record_uid)
        if record_vertex is not None:
            print(f"{bcolors.HEADER}Record Linking{bcolors.ENDC}")
            for parent_vertex in record_vertex.belongs_to_vertices():

                description = "Unknown"
                discovery_vertices = infra.dag.search_content({"record_uid": parent_vertex.uid})
                if len(discovery_vertices) > 0:
                    content = DiscoveryObject.get_discovery_object(discovery_vertices[0])
                    description = content.description
                acl_edge = record_vertex.get_edge(parent_vertex, EdgeType.ACL)
                if acl_edge is not None:
                    acl_content = acl_edge.content_as_object(UserAcl)
                    print(f" * ACL to {description} ({parent_vertex.uid})")
                    print(f"   . belongs_to = {acl_content.belongs_to}")
                    print(f"   . is_admin = {acl_content.is_admin}")
                link_edge = record_vertex.get_edge(parent_vertex, EdgeType.LINK)
                if link_edge is not None:
                    print(f" * LINK to {description} ({parent_vertex.uid})")
        else:
            print(f"{bcolors.FAIL}Cannot find in record linking.{bcolors.ENDC}")

    @staticmethod
    def _render(params: KeeperParams,
                configuration_record: TypedRecord,
                infra_name: str = "infra_name", rl_name: str = "record_link_graph",
                graph_type: str = "dot", graph_dir: str = None, render_all_edges: bool = False):

        if graph_dir is None:
            graph_dir = os.environ.get("HOME", os.environ.get("PROFILENAME", "."))

        print(f"Loading graphs for controller {configuration_record.record_uid}.")

        infra = Infrastructure(record=configuration_record, params=params)
        record_link = RecordLink(record=configuration_record, params=params)

        print("")
        try:
            filename = os.path.join(graph_dir, f"{infra_name}.dot")
            infra.to_dot(
                graph_type=graph_type,
                show_only_active_vertices=False,
                show_only_active_edges=render_all_edges
            ).render(filename)
            print(f"Infrastructure graph rendered to {filename}")
        except Exception as err:
            print(f"{bcolors.FAIL}Could not generate infrastructure graph: {err}{bcolors.ENDC}")
            raise err

        try:
            filename = os.path.join(graph_dir, f"{rl_name}.dot")
            record_link.to_dot(
                graph_type=graph_type,
                show_only_active_vertices=False,
                show_only_active_edges=render_all_edges
            ).render(filename)
            print(f"Record linking graph rendered to {filename}")
        except Exception as err:
            print(f"{bcolors.FAIL}Could not generate record linking graph: {err}{bcolors.ENDC}")
            raise err

        filename = os.path.join(graph_dir, f"infra_raw.dot")
        with open(filename, "w") as fh:
            fh.write(str(infra.dag.to_dot()))
            fh.close()

        filename = os.path.join(graph_dir, f"record_linking_raw.dot")
        with open(filename, "w") as fh:
            fh.write(str(record_link.dag.to_dot()))
            fh.close()

    def execute(self, params, **kwargs):

        info_flag = kwargs.get("info_flag", False)
        belongs_to_flag = kwargs.get("belongs_to_flag", False)
        disconnect_flag = kwargs.get("disconnect_flag", False)
        render_flag = kwargs.get("render_flag", False)
        version_flag = kwargs.get("version_flag", False)

        record_uid = kwargs.get("record_uid")
        configuration_record = None
        if record_uid is not None:
            record = vault.KeeperRecord.load(params, record_uid)  # type: Optional[TypedRecord]
            if record is None:
                print(f"{bcolors.FAIL}Record does not exists.{bcolors.ENDC}")
                return

            configuration_record = record
            if record.record_type in ["pamUser", "pamMachine", "pamDatabase", "pamDirectory"]:
                record_rotation = params.record_rotation_cache.get(record_uid)
                if record_rotation is None:
                    print(f"{bcolors.FAIL}Record does not have rotation settings.{bcolors.ENDC}")
                    return

                controller_uid = record_rotation.get("configuration_uid")
                if controller_uid is None:
                    print(f"{bcolors.FAIL}Record does not have the PAM Configuration set.{bcolors.ENDC}")
                    return

                configuration_record = vault.KeeperRecord.load(params, controller_uid)  # type: Optional[TypedRecord]

        if version_flag is True:
            self._versions()
        if render_flag is True:
            self._render(
                params=params,
                configuration_record=configuration_record,
                infra_name=kwargs.get("infra_name"),
                rl_name=kwargs.get("rl_name"),
                graph_type=kwargs.get("graph_type"),
                graph_dir=kwargs.get("graph_dir"),
                render_all_edges=kwargs.get("render_all_edges"),
            )
        if info_flag is True:
            self._show_info(
                params=params,
                configuration_record=configuration_record,
                record=record
            )

