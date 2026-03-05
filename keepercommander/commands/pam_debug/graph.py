from __future__ import annotations
from . import get_connection
import argparse
import logging
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ...display import bcolors
from ... import vault
from ...discovery_common.infrastructure import Infrastructure
from ...discovery_common.record_link import RecordLink
from ...discovery_common.jobs import Jobs
from ...discovery_common.constants import (PAM_USER, PAM_DIRECTORY, PAM_MACHINE, PAM_DATABASE, VERTICES_SORT_MAP,
                                           DIS_INFRA_GRAPH_ID, RECORD_LINK_GRAPH_ID, DIS_JOBS_GRAPH_ID)
from ...discovery_common.types import (DiscoveryObject, DiscoveryUser, DiscoveryDirectory, DiscoveryMachine,
                                       DiscoveryDatabase, JobContent, ServiceAcl)
from ...discovery_common.dag_sort import sort_infra_vertices
from ...keeper_dag import DAG
from ...keeper_dag.connection.commander import Connection as CommanderConnection
from ...keeper_dag.connection.local import Connection as LocalConnection
from ...keeper_dag.types import GRAPH_ID_TO_ENDPOINT, PamEndpoints
from ...keeper_dag.vertex import DAGVertex
from ...keeper_dag.edge import DAGEdge, EdgeType
from typing import Optional, Union, TYPE_CHECKING

Connection = Union[CommanderConnection, LocalConnection]
if TYPE_CHECKING:
    from ...params import KeeperParams


class PAMDebugGraphCommand(PAMGatewayActionDiscoverCommandBase):

    NO_RECORD = "NO RECORD"
    OTHER = "OTHER"

    parser = argparse.ArgumentParser(prog='pam action debug graph')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')
    parser.add_argument('--configuration-uid', "-c", required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')

    parser.add_argument('--type', '-t', required=True, choices=['infra', 'rl', 'jobs'],
                        dest='graph_type', action='store', help='Graph type', default='infra')
    parser.add_argument('--raw', required=False, dest='raw', action='store_true',
                        help='Render raw graph. Will render corrupt graphs.')

    parser.add_argument('--list', required=False, dest='do_text_list', action='store_true',
                        help='List items in a list.')

    parser.add_argument('--render', required=False, dest='do_render', action='store_true',
                        help='Render a graph')
    parser.add_argument('--file', '-f', required=False, dest='filepath', action='store',
                        default="keeper_graph", help='Base name for the graph file.')
    parser.add_argument('--format', required=False, choices=['raw', 'dot', 'twopi', 'patchwork'],
                        dest='format', default="dot", action='store', help='The format of the graph.')
    parser.add_argument('--debug-gs-level', required=False, dest='debug_level', action='store',
                        help='GraphSync debug level. Default is 0', type=int, default=0)

    mapping = {
        PAM_USER: {"order": 1, "sort": "_sort_name", "item": DiscoveryUser, "key": "user"},
        PAM_DIRECTORY: {"order": 1, "sort": "_sort_name", "item": DiscoveryDirectory, "key": "host_port"},
        PAM_MACHINE: {"order": 2, "sort": "_sort_host", "item": DiscoveryMachine, "key": "host"},
        PAM_DATABASE: {"order": 3, "sort": "_sort_host", "item": DiscoveryDatabase, "key": "host_port"},
    }

    graph_id_map = {
        "infra": DIS_INFRA_GRAPH_ID,
        "rl": RECORD_LINK_GRAPH_ID,
        "jobs": DIS_JOBS_GRAPH_ID
    }

    def get_parser(self):
        return PAMDebugGraphCommand.parser

    def _do_text_list_infra(self, params: KeeperParams, gateway_context: GatewayContext, debug_level: int = 0,
                            indent: int = 0):

        infra = Infrastructure(record=gateway_context.configuration, params=params, logger=logging,
                               debug_level=debug_level, use_per_graph_endpoints=False)
        infra.load(sync_point=0)

        try:
            configuration = infra.get_root.has_vertices()[0]
        except (Exception,):
            print(f"{bcolors.FAIL}Could not find the configuration in the infrastructure graph. "
                  f"Has discovery been run for this gateway?{bcolors.ENDC}")

            return

        line_start = {
            0: "",
            1: "* ",
            2: "- ",
        }

        color_func = {
            0: self._h,
            1: self._gr,
            2: self._p,
            3: self._b
        }

        def _handle(current_vertex: DAGVertex, indent: int = 0, last_record_type: Optional[str] = None):

            if not current_vertex.active:
                return

            pad = ""
            if indent > 0:
                pad = "".ljust(4 * indent, ' ')

            text = ""
            ls = line_start.get(indent, "  ")
            cf = color_func.get(indent, self._p)

            if not current_vertex.active:
                text += f"{pad}{current_vertex.uid} " + self._f("(Inactive)")
            elif not current_vertex.corrupt:
                current_content = DiscoveryObject.get_discovery_object(current_vertex)
                if current_content.record_uid is None:
                    text += f"{pad}{ls}{current_vertex.uid}; {current_content.title} does not have a record."
                else:
                    record = vault.KeeperRecord.load(params, current_content.record_uid)  # type: Optional[TypedRecord]
                    if record is not None:
                        text += f"{pad}{ls}" + cf(f"{current_vertex.uid}; {record.title}; {record.record_uid}")
                    else:
                        text += f"{pad}{ls}" + cf(f"{current_vertex.uid}; {current_content.title}; " +
                                                  self._f("have record uid, record does not exists, "
                                                          "might have to sync."))
            else:
                text += f"{pad}{current_vertex.uid} " + self._f("(Corrupt)")

            print(text)

            record_type_to_vertices_map = sort_infra_vertices(current_vertex)
            # Process the record type by their map order in ascending order.

            # Sort the record types by their order in the constant.
            # 'order' is an int.
            for record_type in sorted(record_type_to_vertices_map, key=lambda i: VERTICES_SORT_MAP[i]['order']):
                for vertex in record_type_to_vertices_map[record_type]:
                    if last_record_type is None or last_record_type != record_type:
                        if indent == 0:
                            print(f"{pad}  {self._b(self._n(record_type))}")
                        last_record_type = record_type

                    _handle(vertex, indent=indent+1)

        print("")
        _handle(configuration, indent=indent)
        print("")

    def _do_text_list_rl(self, params: KeeperParams, gateway_context: GatewayContext, debug_level: int = 0,
                         indent: int = 0):

        print("")

        pad = ""
        if indent > 0:
            pad = "".ljust(4 * indent, ' ')

        record_link = RecordLink(record=gateway_context.configuration,
                                 params=params,
                                 logger=logging,
                                 debug_level=debug_level, use_per_graph_endpoints=False)
        configuration = record_link.dag.get_root
        
        record = vault.KeeperRecord.load(params, configuration.uid)  # type: Optional[TypedRecord]
        if record is None:
            print(self._f("Configuration record does not exists."))
            return
        
        print(self._h(f"{pad}{record.record_type}, {record.title}, {record.record_uid}"))

        if configuration.has_data:
            try:
                data = configuration.content_as_dict
                print(f"{pad}  . data")
                for k, v in data.items():
                    print(f"{pad}    + {k} = {v}")
            except Exception as err:
                print(f"{pad}    ! data not JSON: {err}")

        def _group(configuration_vertex: DAGVertex) -> dict:

            group = {
                PAM_USER: [],
                PAM_DIRECTORY: [],
                PAM_DATABASE: [],
                PAM_MACHINE: [],
                PAMDebugGraphCommand.NO_RECORD: [],
                PAMDebugGraphCommand.OTHER: []
            }

            for vertex in configuration_vertex.has_vertices():
                record = vault.KeeperRecord.load(params, vertex.uid)  # type: Optional[TypedRecord]
                if record is None:
                    group[PAMDebugGraphCommand.NO_RECORD].append({
                        "v": vertex
                    })
                    continue
                rt = record.record_type
                if rt not in group:
                    rt = PAMDebugGraphCommand.OTHER
                group[rt].append({
                    "v": vertex,
                    "r": record
                })

            return group
        
        group = _group(configuration)
        
        for record_type in [PAM_USER, PAM_DIRECTORY, PAM_MACHINE, PAM_DATABASE]:
            if len(group[record_type]) > 0:
                print(f"{pad}  " + self._b(self._n(record_type)))
                for item in group[record_type]:
                    vertex = item.get("v")  # type: DAGVertex
                    record = item.get("r")  # type: TypedRecord
                    text = self._gr(f"{record.title}; {record.record_uid}")
                    if not vertex.active:
                        text += " " + self._f("Inactive")
                    print(f"{pad}    * {text}")

                    # These are cloud users
                    if record_type == PAM_USER:
                        acl = record_link.get_acl(vertex.uid, configuration.uid)
                        if acl is None:
                            print(f"{pad}      {self._f('missing ACL')}")
                        else:
                            if acl.is_iam_user:
                                print(f"{pad}      . is IAM user")
                            if acl.is_admin:
                                print(f"{pad}        . is the {self._b('Admin')}")
                            if acl.belongs_to:
                                print(f"{pad}      . belongs to this resource")
                            else:
                                print(f"{pad}      . looks like directory user")

                            if acl.rotation_settings:
                                if acl.rotation_settings.noop:
                                    print(f"{pad}      . is a NOOP")
                                if acl.rotation_settings.disabled:
                                    print(f"{pad}      . rotation is disabled")

                                if (acl.rotation_settings.saas_record_uid_list is not None
                                        and len(acl.rotation_settings.saas_record_uid_list) > 0):
                                    print(f"{pad}      . has SaaS rotation: "
                                          f"{acl.rotation_settings.saas_record_uid_list[0]}")

                        continue

                    if vertex.has_data:
                        try:
                            data = vertex.content_as_dict
                            print(f"{pad}      . data")
                            for k, v in data.items():
                                print(f"{pad}        + {k} = {v}")
                        except Exception as err:
                            print(f"{pad}        ! data not JSON: {err}")

                    children = vertex.has_vertices()
                    if len(children) > 0:
                        bad = []
                        for child in children:
                            child_record = vault.KeeperRecord.load(params, child.uid)  # type: Optional[TypedRecord]
                            if child_record is None:
                                if child.active:
                                    bad.append(self._f(f"- Record UID {child.uid} does not exists."))
                                continue
                            else:
                                print(f"{pad}      - {child_record.title}; {child_record.record_uid}")
                                acl = record_link.get_acl(child.uid, vertex.uid)
                                if acl is None:
                                    print(f"{pad}        {self._f('missing ACL')}")
                                else:
                                    if acl.is_admin:
                                        print(f"{pad}        . is the {self._b('Admin')}")
                                    if acl.belongs_to:
                                        print(f"{pad}        . belongs to this resource")
                                    else:
                                        print(f"{pad}        . looks like directory user")

                                if child.has_data:
                                    try:
                                        data = child.content_as_dict
                                        print(f"{pad}        . data")
                                        for k, v in data.items():
                                            print(f"{pad}          + {k} = {v}")
                                    except Exception as err:
                                        print(f"{pad}          ! data not JSON: {err}")
                        for i in bad:
                            print(f"{pad}      " + i)

        if len(group[PAMDebugGraphCommand.OTHER]) > 0:
            print(f"{pad}  " + self._b("Other PAM Types"))
            for item in group[PAMDebugGraphCommand.OTHER]:
                vertex = item.get("v")  # type: DAGVertex
                record = item.get("r")  # type: TypedRecord
                text = self._gr(f"{record.record_type}; {record.title}; {record.record_uid}")
                if not vertex.active:
                    text += " " + self._f("Inactive")
                print(f"{pad}    * {text}")

        if len(group[PAMDebugGraphCommand.NO_RECORD]) > 0:

            # TODO: Check the infra graph for information
            print(f"{pad}  " + self._b(self._n("In Graph, No Vault Record")))
            for item in group[PAMDebugGraphCommand.NO_RECORD]:
                vertex = item.get("v")  # type: DAGVertex
                print(f"{pad}    * {vertex.uid}")

    def _do_text_list_service(self, params: KeeperParams, gateway_context: GatewayContext, debug_level: int = 0,
                              indent: int = 0):

        pad = ""
        if indent > 0:
            pad = "".ljust(2 * indent, ' ')

        record_link = RecordLink(record=gateway_context.configuration, params=params, logger=logging,
                                 debug_level=debug_level,
                                 use_per_graph_endpoints=False)
        configuration = record_link.dag.get_root

        machine_dict = {}

        # New user/service mapping using PAM graph
        for resource_vertex in configuration.has_vertices():
            if not resource_vertex.active:
                continue

            machine_record = vault.KeeperRecord.load(params, resource_vertex.uid)  # type: Optional[TypedRecord]
            if machine_record is None or machine_record.record_type != PAM_MACHINE:
                continue

            if machine_record is not None:
                machine_name = f"{machine_record.title}, {machine_record.record_uid}"
            else:
                machine_name = self._f(f"Record vertex {resource_vertex.uid} has no record.")

            for user_vertex in resource_vertex.has_vertices():
                if not user_vertex.active:
                    continue

                user_record = vault.KeeperRecord.load(params, user_vertex.uid)  # type: Optional[TypedRecord]
                acl = record_link.get_acl(parent_record_uid=resource_vertex.uid, record_uid=user_vertex.uid)
                if (acl is not None
                    and acl.rotation_settings is not None
                    and hasattr(acl.rotation_settings, "controls_services")
                        and acl.rotation_settings.controls_services):

                    if resource_vertex.uid not in machine_dict:
                        machine_dict[resource_vertex.uid] = {
                            "machine_name": machine_name,
                            "users": []
                        }

                    if user_record is not None:
                        user_name = f"{user_record.title}, {user_record.record_uid}"
                    else:
                        user_name = self._f(f"Record vertex {user_vertex.uid} has no record.")

                    machine_dict[resource_vertex.uid]["users"].append(user_name)

        # Old user/service mapping using graph 13.
        dag = DAG(conn=record_link.conn, graph_id=13, record=gateway_context.configuration)
        if dag.has_graph:
            for us_machine_vertex in dag.get_root.has_vertices():
                if not us_machine_vertex.active:
                    continue

                machine_record = vault.KeeperRecord.load(params, us_machine_vertex.uid)  # type: Optional[TypedRecord]
                if machine_record is not None:
                    machine_name = f"{machine_record.title}, {machine_record.record_uid}"
                else:
                    machine_name = self._f(f"Record vertex {us_machine_vertex.uid} has no record.")

                for us_user_vertex in us_machine_vertex.has_vertices():
                    if not us_user_vertex.active:
                        continue
                    acl_edge = us_user_vertex.get_edge(us_machine_vertex, edge_type=EdgeType.ACL)
                    if acl_edge is None:
                        continue
                    service_acl = acl_edge.content_as_object(ServiceAcl)
                    if service_acl is None:
                        continue

                    user_record = vault.KeeperRecord.load(params, us_user_vertex.uid)  # type: Optional[TypedRecord]

                    if us_machine_vertex.uid not in machine_dict:
                        machine_dict[us_machine_vertex.uid] = {
                            "machine_name": machine_name,
                            "users": []
                        }

                    types = []
                    if service_acl.is_service:
                        types.append("Services")
                    if service_acl.is_task:
                        types.append("Tasks")
                    if service_acl.is_iis_pool:
                        types.append("IIS Pool")
                    text = ""
                    if len(types) > 0:
                        text = "(" + ", ".join(types) + ")"

                    if user_record is not None:
                        user_name = f"OLD: {user_record.title}, {user_record.record_uid}, {text}"
                    else:
                        user_name = self._f(f"OLD: Record vertex {us_user_vertex.uid} has no record.")

                    machine_dict[us_machine_vertex.uid]["users"].append(user_name)
        else:
            logging.debug("no old user service graph")

        for machine in machine_dict.values():
            print(f"{pad}{machine['machine_name']}")
            for user in machine["users"]:
                print(f"{pad}  * {user}")

    def _do_text_list_jobs(self, params: KeeperParams, gateway_context: GatewayContext, debug_level: int = 0,
                           indent: int = 0):

        infra = Infrastructure(record=gateway_context.configuration, params=params, logger=logging,
                               debug_level=debug_level, fail_on_corrupt=False, use_per_graph_endpoints=False)
        infra.load(sync_point=0)

        pad = ""
        if indent > 0:
            pad = "".ljust(2 * indent, ' ') + "* "

        conn = get_connection(params)
        graph_sync = DAG(conn=conn, record=gateway_context.configuration, logger=logging, debug_level=debug_level,
                         read_endpoint=PamEndpoints.DISCOVERY_JOBS,
                         write_endpoint=PamEndpoints.DISCOVERY_JOBS)
        graph_sync.load(0)
        configuration = graph_sync.get_root
        vertices = configuration.has_vertices()
        if len(vertices) == 0:
            print(self._f("The jobs graph has not been initialized. Only has root vertex."))
            return

        vertex = vertices[0]
        if not vertex.has_data:
            print(self._f("The job vertex does not contain any data"))
            return

        current_json = vertex.content_as_str
        if current_json is None:
            print(self._f("The current job vertex content is None"))
            return

        content = JobContent.model_validate_json(current_json)
        print(f"{pad}{self._b('Active Job ID')}: {content.active_job_id}")
        print("")
        print(f"{pad}{self._h('History')}")
        print("")
        for job in content.job_history:
            print(f"{pad}  --------------------------------------")
            print(f"{pad}  Job Id: {job.job_id}")
            print(f"{pad}  Started: {job.start_ts_str}")
            print(f"{pad}  Ended: {job.end_ts_str}")
            print(f"{pad}  Duration: {job.duration_sec_str}")
            print(f"{pad}  Infra Sync Point: {job.sync_point}")
            if job.success:
                print(f"{pad}  Status: {self._gr('Success')}")
            else:
                print(f"{pad}  Status: {self._f('Fail')}")
            if job.error is not None:
                print(f"{pad}  Error: {self._gr(job.error)}")

            print("")

            if job.delta is None:
                print(f"{pad}{self._f('The job is missing a delta, never finished discovery.')}")
            else:
                if len(job.delta.added) > 0:
                    print(f"{pad}  {self._h('Added')}")
                    for added in job.delta.added:
                        vertex = infra.dag.get_vertex(added.uid)
                        if vertex is None:
                            print(f"{pad}  * Vertex {added.uid} does not exists.")
                        else:
                            if not vertex.active:
                                print(f"{pad}  * Vertex {added.uid} is inactive.")
                            elif vertex.corrupt:
                                print(f"{pad}  * Vertex {added.uid} is corrupt.")
                            else:
                                content = DiscoveryObject.get_discovery_object(vertex)
                                print(f"{pad}  * {content.description}; Record UID: {content.record_uid}")
                    print("")

                if len(job.delta.changed) > 0:
                    print(f"{pad}  {self._h('Changed')}")
                    for changed in job.delta.changed:
                        vertex = infra.dag.get_vertex(changed.uid)
                        if vertex is None:
                            print(f"{pad}  * Vertex {changed.uid} does not exists.")
                        else:
                            if not vertex.active:
                                print(f"{pad}  * Vertex {changed.uid} is inactive.")
                            elif vertex.corrupt:
                                print(f"{pad}  * Vertex {changed.uid} is corrupt.")
                            else:
                                content = DiscoveryObject.get_discovery_object(vertex)
                                print(f"{pad}  * {content.description}; Record UID: {content.record_uid}")
                                if changed.changes is not None:
                                    for k, v in changed.changes.items():
                                        print(f"{pad}    {k} = {v}")
                    print("")

                if len(job.delta.deleted) > 0:
                    print(f"{pad}  {self._h('Deleted')}")
                    for deleted in job.delta.deleted:
                        print(f"{pad}  * Removed vertex {deleted.uid}.")
                    print("")

    def _do_render_infra(self, params: KeeperParams, gateway_context: GatewayContext, filepath: str, graph_format: str,
                         debug_level: int = 0):

        infra = Infrastructure(record=gateway_context.configuration, params=params, logger=logging,
                               debug_level=debug_level, use_per_graph_endpoints=False)
        infra.load(sync_point=0)

        print("")
        dot_instance = infra.to_dot(
            graph_type=graph_format if graph_format != "raw" else "dot",
            show_only_active_vertices=False,
            show_only_active_edges=False
        )
        if graph_format == "raw":
            print(dot_instance)
        else:
            try:
                dot_instance.render(filepath)
                print(f"Infrastructure graph rendered to {self._gr(filepath)}")
            except Exception as err:
                print(self._f(f"Could not generate graph: {err}"))
                raise err
        print("")

    def _do_render_rl(self, params: KeeperParams, gateway_context: GatewayContext, filepath: str, graph_format: str,
                      debug_level: int = 0):

        rl = RecordLink(record=gateway_context.configuration,
                        params=params,
                        logger=logging,
                        debug_level=debug_level, use_per_graph_endpoints=False)

        print("")
        dot_instance = rl.to_dot(
            graph_type=graph_format if graph_format != "raw" else "dot",
            show_only_active_vertices=False,
            show_only_active_edges=False
        )
        if graph_format == "raw":
            print(dot_instance)
        else:
            try:
                dot_instance.render(filepath)
                print(f"Record linking graph rendered to {self._gr(filepath)}")
            except Exception as err:
                print(self._f(f"Could not generate graph: {err}"))
                raise err
        print("")

    def _do_render_jobs(self, params: KeeperParams, gateway_context: GatewayContext, filepath: str,
                        graph_format: str, debug_level: int = 0):

        jobs = Jobs(record=gateway_context.configuration, params=params, logger=logging, debug_level=debug_level,
                    use_per_graph_endpoints=False)

        print("")
        dot_instance = jobs.dag.to_dot()
        if graph_format == "raw":
            print(dot_instance)
        else:
            try:
                dot_instance.render(filepath)
                print(f"Job graph rendered to {self._gr(filepath)}")
            except Exception as err:
                print(self._f(f"Could not generate graph: {err}"))
                raise err
        print("")

    def _do_raw_text_list(self, params: KeeperParams, gateway_context: GatewayContext, graph_id: int = 0,
                          debug_level: int = 0):

        logging.debug(f"loading graph id {graph_id}, for record uid {gateway_context.configuration.record_uid}")

        conn = get_connection(params=params)
        endpoint = GRAPH_ID_TO_ENDPOINT[graph_id]
        dag = DAG(conn=conn, record=gateway_context.configuration,
                  read_endpoint=endpoint, write_endpoint=endpoint,
                  fail_on_corrupt=False, logger=logging, debug_level=debug_level)
        dag.load(sync_point=0)
        print("")
        if dag.is_corrupt is True:
            print(f"{bcolors.FAIL}The graph is corrupt at Vertex UIDs: {', '.join(dag.corrupt_uids)}")
            print("")

        logging.debug("DAG DOT -------------------------------")
        logging.debug(str(dag.to_dot()))
        logging.debug("DAG DOT -------------------------------")

        line_start = {
            0: "",
            1: "* ",
            2: "- ",
            3: ". ",
        }

        color_func = {
            0: self._h,
            1: self._gr,
            2: self._bl,
            3: self._p
        }

        def _handle(current_vertex: DAGVertex, last_vertex: Optional[DAGVertex] = None, indent: int = 0):

            pad = ""
            if indent > 0:
                pad = "".ljust(4 * indent, ' ')

            ls = line_start.get(indent, "  ")
            cf = color_func.get(indent, self._p)
            text = f"{pad}{ls}{cf(current_vertex.uid)}"

            edge_types = []
            if last_vertex is not None:
                for edge in current_vertex.edges:  # type: DAGEdge
                    if not edge.active:
                        continue
                    if edge.head_uid == last_vertex.uid:
                        edge_types.append(edge.edge_type.value)
            if len(edge_types) > 0:
                text += f"; edges: {', '.join(edge_types)}"

            if not current_vertex.active:
                text += " " + self._f("Inactive")
            if current_vertex.corrupt:
                text += " " + self._f("Corrupt")

            print(text)

            if not current_vertex.active:
                logging.debug(f"vertex {current_vertex.uid} is not active, will not get children.")
                return

            vertices = current_vertex.has_vertices()
            if len(vertices) == 0:
                logging.debug(f"vertex {current_vertex.uid} does not have any children.")
                return

            for vertex in vertices:
                _handle(vertex, current_vertex, indent=indent + 1)

        print("")
        _handle(dag.get_root)
        print("")

    def _do_raw_render_graph(self, params: KeeperParams, gateway_context: GatewayContext, filepath: str,
                             graph_format: str, graph_id: int = 0, debug_level: int = 0):

        conn = get_connection(params=params)
        endpoint = GRAPH_ID_TO_ENDPOINT[graph_id]
        dag = DAG(conn=conn, record=gateway_context.configuration,
                  read_endpoint=endpoint, write_endpoint=endpoint,
                  fail_on_corrupt=False, logger=logging, debug_level=debug_level)
        dag.load(sync_point=0)
        dot = dag.to_dot(graph_format=graph_format)
        if graph_format == "raw":
            print(dot)
        else:
            try:
                dot.render(filepath)
                print(f"Graph rendered to {self._gr(filepath)}")
            except Exception as err:
                print(self._f(f"Could not generate graph: {err}"))
                raise err

        print("")

    def do_list(self, params: KeeperParams, gateway_context: GatewayContext, graph_type: str, debug_level: int = 0,
                indent: int = 0):
        list_func = getattr(self, f"_do_text_list_{graph_type}")
        list_func(params=params,
                  gateway_context=gateway_context,
                  debug_level=debug_level,
                  indent=indent)

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        raw = kwargs.get("raw", False)
        graph_type = kwargs.get("graph_type")
        do_text_list = kwargs.get("do_text_list")
        do_render = kwargs.get("do_render")
        debug_level = int(kwargs.get("debug_level", 0))

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

        if raw:
            if do_text_list:
                self._do_raw_text_list(params=params,
                                       gateway_context=gateway_context,
                                       graph_id=PAMDebugGraphCommand.graph_id_map.get(graph_type),
                                       debug_level=debug_level)
            if do_render:
                filepath = kwargs.get("filepath")
                graph_format = kwargs.get("format")
                self._do_raw_render_graph(params=params,
                                          gateway_context=gateway_context,
                                          filepath=filepath,
                                          graph_format=graph_format,
                                          graph_id=PAMDebugGraphCommand.graph_id_map.get(graph_type),
                                          debug_level=debug_level)
        else:
            if do_text_list:
                self.do_list(
                    params=params,
                    gateway_context=gateway_context,
                    graph_type=graph_type,
                    debug_level=debug_level
                )
            if do_render:
                filepath = kwargs.get("filepath")
                graph_format = kwargs.get("format")
                render_func = getattr(self, f"_do_render_{graph_type}")
                render_func(params=params,
                            gateway_context=gateway_context,
                            filepath=filepath,
                            graph_format=graph_format,
                            debug_level=debug_level)
