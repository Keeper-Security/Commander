from __future__ import annotations
import logging
from .constants import USER_SERVICE_GRAPH_ID, PAM_MACHINE, PAM_USER
from .utils import get_connection, user_in_lookup, user_check_list
from .types import DiscoveryObject, ServiceAcl, FactsNameUser
from .infrastructure import Infrastructure

from keepercommander.keeper_dag import DAG, EdgeType
import importlib
from typing import Any, Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from keepercommander.keeper_dag.vertex import DAGVertex
    from keepercommander.keeper_dag.edge import DAGEdge


class UserService:

    def __init__(self, record: Any, logger: Optional[Any] = None, history_level: int = 0,
                 debug_level: int = 0, fail_on_corrupt: bool = True, log_prefix: str = "GS Services/Tasks",
                 save_batch_count: int = 200,
                 **kwargs):

        self.conn = get_connection(**kwargs)

        # This will either be a KSM Record, or Commander KeeperRecord
        self.record = record
        self._dag = None
        if logger is None:
            logger = logging.getLogger()
        self.logger = logger
        self.log_prefix = log_prefix
        self.history_level = history_level
        self.debug_level = debug_level
        self.fail_on_corrupt = fail_on_corrupt
        self.save_batch_count = save_batch_count

        self.auto_save = False
        self.last_sync_point = -1

    @property
    def dag(self) -> DAG:
        if self._dag is None:

            self._dag = DAG(conn=self.conn, record=self.record, graph_id=USER_SERVICE_GRAPH_ID,
                            auto_save=False, logger=self.logger, history_level=self.history_level,
                            debug_level=self.debug_level, name="Discovery Service/Tasks",
                            fail_on_corrupt=self.fail_on_corrupt, log_prefix=self.log_prefix,
                            save_batch_count=self.save_batch_count)

            self._dag.load(sync_point=0)

        return self._dag

    @property
    def has_graph(self) -> bool:
        return self.dag.has_graph

    def reload(self):
        self._dag.load(sync_point=0)

    def get_record_link(self, uid: str) -> DAGVertex:
        return self.dag.get_vertex(uid)

    @staticmethod
    def get_record_uid(discovery_vertex: DAGVertex) -> str:
        """
        Get the record UID from the vertex

        """
        data = discovery_vertex.get_data()
        if data is None:
            raise Exception(f"The discovery vertex {discovery_vertex.uid} does not have a DATA edge. "
                            "Cannot get record UID.")
        content = DiscoveryObject.get_discovery_object(discovery_vertex)
        if content.record_uid is not None:
            return content.record_uid
        raise Exception(f"The discovery vertex {discovery_vertex.uid} data does not have a populated record UID.")

    def belongs_to(self, resource_uid: str, user_uid: str, acl: Optional[ServiceAcl] = None,
                   resource_name: Optional[str] = None, user_name: Optional[str] = None):

        """
        Link vault records using record UIDs.

        If a link already exists, no additional link will be created.
        """

        # Get thr record vertices.
        # If a vertex does not exist, then add the vertex using the record UID
        resource_vertex = self.dag.get_vertex(resource_uid)
        if resource_vertex is None:
            self.logger.debug(f"adding resource vertex for record UID {resource_uid} ({resource_name})")
            resource_vertex = self.dag.add_vertex(uid=resource_uid, name=resource_name)

        user_vertex = self.dag.get_vertex(user_uid)
        if user_vertex is None:
            self.logger.debug(f"adding user vertex for record UID {user_uid} ({user_name})")
            user_vertex = self.dag.add_vertex(uid=user_uid, name=user_name)

        self.logger.debug(f"user {user_vertex.uid} controls services on  {resource_vertex.uid}")

        edge_type = EdgeType.LINK
        if acl is not None:
            edge_type = EdgeType.ACL

        user_vertex.belongs_to(resource_vertex, edge_type=edge_type, content=acl)

    def disconnect_from(self, resource_uid: str, user_uid: str):
        resource_vertex = self.dag.get_vertex(resource_uid)
        user_vertex = self.dag.get_vertex(user_uid)
        user_vertex.disconnect_from(resource_vertex)

    def get_acl(self, resource_uid, user_uid) -> Optional[ServiceAcl]:

        """
        Get the service/task ACL between a resource and the user.

        """

        resource_vertex = self.dag.get_vertex(resource_uid)
        user_vertex = self.dag.get_vertex(user_uid)
        if resource_vertex is None or user_vertex is None:
            self.logger.debug(f"there is no acl between {resource_uid} and {user_uid}")
            return ServiceAcl()

        acl_edge = user_vertex.get_edge(resource_vertex, edge_type=EdgeType.ACL)  # type: DAGEdge
        if acl_edge is None:
            return None

        return acl_edge.content_as_object(ServiceAcl)

    def resource_has_link(self, resource_uid) -> bool:
        """
        Is this resource linked to the configuration?
        """

        resource_vertex = self.dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return False
        link_edge = resource_vertex.get_edge(self.dag.get_root, edge_type=EdgeType.LINK)  # type: DAGEdge
        return link_edge is not None

    def get_resource_vertices(self, user_uid: str) -> List[DAGVertex]:

        """
        Get the resource vertices where the user is used for a service or task.

        """

        user_vertex = self.dag.get_vertex(user_uid)
        if user_vertex is None:
            return []
        return user_vertex.belongs_to_vertices()

    def get_user_vertices(self, resource_uid: str) -> List[DAGVertex]:

        """
        Get the user vertices that control a service or task on this machine.

        """
        resource_vertex = self.dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return []
        return resource_vertex.has_vertices()

    @staticmethod
    def delete(vertex: DAGVertex):
        if vertex is not None:
            vertex.delete()

    def save(self):
        if self.dag.has_graph is True:
            self.logger.debug("saving the service user.")
            self.dag.save(delta_graph=False)
        else:
            self.logger.debug("the service user graph does not contain any data, was not saved.")

    def to_dot(self, graph_format: str = "svg", show_version: bool = True, show_only_active_vertices: bool = True,
               show_only_active_edges: bool = True, graph_type: str = "dot"):

        try:
            mod = importlib.import_module("graphviz")
        except ImportError:
            raise Exception("Cannot to_dot(), graphviz module is not installed.")

        dot = getattr(mod, "Digraph")(comment=f"DAG for Services/Tasks", format=graph_format)

        if graph_type == "dot":
            dot.attr(rankdir='RL')
        elif graph_type == "twopi":
            dot.attr(layout="twopi")
            dot.attr(ranksep="10")
            dot.attr(ratio="auto")
        else:
            dot.attr(layout=graph_type)

        self.logger.debug(f"have {len(self.dag.all_vertices)} vertices")
        for v in self.dag.all_vertices:
            if show_only_active_vertices is True and v.active is False:
                continue

            tooltip = ""

            for edge in v.edges:

                color = "grey"
                style = "solid"

                # To reduce the number of edges, only show the active edges
                if edge.active is True:
                    color = "black"
                    style = "bold"
                elif show_only_active_edges is True:
                    continue

                # If the vertex is not active, gray out the DATA edge
                if edge.edge_type == EdgeType.DATA and v.active is False:
                    color = "grey"

                if edge.edge_type == EdgeType.DELETION:
                    style = "dotted"

                edge_tip = ""
                if edge.edge_type == EdgeType.ACL and v.active is True:
                    content = edge.content_as_dict
                    if content.get("is_service") is True:
                        color = "red"
                    if content.get("is_task") is True:
                        if color == "red":
                            color = "purple"
                        else:
                            color = "blue"

                    tooltip += f"TO {edge.head_uid}\\n"
                    for k, val in content.items():
                        tooltip += f" * {k}={val}\\n"
                    tooltip += f"--------------------\\n\\n"

                label = DAG.EDGE_LABEL.get(edge.edge_type)
                if label is None:
                    label = "UNK"
                if edge.path is not None and edge.path != "":
                    label += f"\\npath={edge.path}"
                if show_version is True:
                    label += f"\\nv={edge.version}"

                # tail, head (arrow side), label, ...
                dot.edge(v.uid, edge.head_uid, label, style=style, fontcolor=color, color=color, tooltip=edge_tip)

            shape = "ellipse"
            fillcolor = "white"
            color = "black"
            if v.active is False:
                fillcolor = "grey"

            label = f"uid={v.uid}"
            dot.node(v.uid, label, color=color, fillcolor=fillcolor, style="filled", shape=shape, tooltip=tooltip)

        return dot

    def _connect_service_users(self,
                               infra_resource_content: DiscoveryObject,
                               infra_resource_vertex: DAGVertex,
                               services: List[FactsNameUser]):

        self.logger.debug(f"processing services for {infra_resource_content.description} ({infra_resource_vertex.uid})")

        # We don't care about the name of the service, we just need a list users.
        lookup = {}
        for service in services:
            lookup[service.user.lower()] = True

        for infra_user_vertex in infra_resource_vertex.has_vertices():
            infra_user_content = DiscoveryObject.get_discovery_object(infra_user_vertex)
            if infra_user_content.record_uid is None:
                continue
            if user_in_lookup(
                    lookup=lookup,
                    user=infra_user_content.item.user,
                    name=infra_user_content.name,
                    source=infra_user_content.item.source):
                self.logger.debug(f"  * found user for service: {infra_user_content.item.user}")
                acl = self.get_acl(infra_resource_content.record_uid, infra_user_content.record_uid)
                if acl is None:
                    acl = ServiceAcl()
                acl.is_service = True
                self.belongs_to(
                    resource_uid=infra_resource_content.record_uid,
                    resource_name=infra_resource_content.uid,
                    user_uid=infra_user_content.record_uid,
                    user_name=infra_user_content.uid,
                    acl=acl)

    def _connect_task_users(self,
                            infra_resource_content: DiscoveryObject,
                            infra_resource_vertex: DAGVertex,
                            tasks: List[FactsNameUser]):

        self.logger.debug(f"processing tasks for {infra_resource_content.description} ({infra_resource_vertex.uid})")

        # We don't care about the name of the tasks, we just need a list users.
        lookup = {}
        for task in tasks:
            lookup[task.user.lower()] = True

        for infra_user_vertex in infra_resource_vertex.has_vertices():
            infra_user_content = DiscoveryObject.get_discovery_object(infra_user_vertex)
            if infra_user_content.record_uid is None:
                continue
            if user_in_lookup(
                    lookup=lookup,
                    user=infra_user_content.item.user,
                    name=infra_user_content.name,
                    source=infra_user_content.item.source):
                self.logger.debug(f"  * found user for task: {infra_user_content.item.user}")
                acl = self.get_acl(infra_resource_content.record_uid, infra_user_content.record_uid)
                if acl is None:
                    acl = ServiceAcl()
                acl.is_task = True
                self.belongs_to(
                    resource_uid=infra_resource_content.record_uid,
                    resource_name=infra_resource_content.uid,
                    user_uid=infra_user_content.record_uid,
                    user_name=infra_user_content.uid,
                    acl=acl)

    def _validate_users(self,
                        infra_resource_content: DiscoveryObject,
                        infra_resource_vertex: DAGVertex):

        """
        This method will check to see if a resource's users' ACL edges are still valid.

        """

        self.logger.debug(f"validate existing user service edges to see if still valid to "
                          f"{infra_resource_content.name}")

        service_lookup = {}
        for service in infra_resource_content.item.facts.services:
            service_lookup[service.user.lower()] = True

        task_lookup = {}
        for task in infra_resource_content.item.facts.tasks:
            task_lookup[task.user.lower()] = True

        # Get the user service resource vertex.
        # If it does not exist, then we cannot validate users.
        user_service_resource_vertex = self.dag.get_vertex(infra_resource_content.record_uid)
        if user_service_resource_vertex is None:
            return

        infra_dag = infra_resource_vertex.dag

        for user_service_user_vertex in user_service_resource_vertex.has_vertices():
            acl_edge = user_service_user_vertex.get_edge(
                user_service_resource_vertex, edge_type=EdgeType.ACL)  # type: DAGEdge
            if acl_edge is None:
                self.logger.info(f"User record {user_service_user_vertex.uid} does not have an ACL edge to "
                                 f"{user_service_resource_vertex.uid} for user services.")
                continue

            found_service_acl = False
            found_task_acl = False
            changed = False

            acl = acl_edge.content_as_object(ServiceAcl)

            user = infra_dag.search_content({"record_type": PAM_USER, "record_uid": user_service_user_vertex.uid})
            infra_user_content = None
            found_user = len(user) > 0
            if found_user is True:
                infra_user_vertex = user[0]
                if infra_user_vertex.active is False:
                    found_user = False
                else:
                    infra_user_content = DiscoveryObject.get_discovery_object(infra_user_vertex)

            if found_user is False:
                self.disconnect_from(user_service_resource_vertex.uid, user_service_user_vertex.uid)
                continue

            check_list = user_check_list(
                user=infra_user_content.item.user,
                name=infra_user_content.name,
                source=infra_user_content.item.source
            )

            if acl.is_service is True:
                for check_user in check_list:
                    if check_user in service_lookup:
                        found_service_acl = True
                        break
                if found_service_acl is False:
                    acl.is_service = False
                    changed = True

            if acl.is_task is True:
                for check_user in check_list:
                    if check_user in task_lookup:
                        found_task_acl = True
                        break
                if found_task_acl is False:
                    acl.is_task = False
                    changed = True

            if found_service_acl is True or found_task_acl is True and changed is True:
                self.logger.debug(f"user {user_service_user_vertex.uid}(US) to {user_service_resource_vertex.uid} updated")
                self.belongs_to(user_service_resource_vertex.uid, user_service_user_vertex.uid, acl)
            elif found_service_acl is False and found_task_acl is False:
                self.logger.debug(f"user {user_service_user_vertex.uid}(US) to {user_service_resource_vertex.uid} disconnected")
                self.disconnect_from(user_service_resource_vertex.uid, user_service_user_vertex.uid)

        self.logger.debug(f"DONE validate existing user")

    def run(self, infra: Optional[Infrastructure] = None, **kwargs):

        self.logger.debug("")
        self.logger.debug("##########################################################################################")
        self.logger.debug("# MAP USER TO MACHINE FOR SERVICE/TASKS")
        self.logger.debug("")

        # If an instance of Infrastructure is not passed in.
        if infra is None:

            # Get ksm from the connection.
            # However, this might be a local connection, so check first.
            # Local connections don't need ksm.
            if hasattr(self.conn, "ksm") is True:
                kwargs["ksm"] = getattr(self.conn, "ksm")

            # Get the entire infrastructure graph; sync point = 0
            infra = Infrastructure(record=self.record, **kwargs)
            infra.load()

        # Work ourselves to the configuration vertex.
        infra_root_vertex = infra.get_root
        infra_config_vertex = infra_root_vertex.has_vertices()[0]

        # For the user service, the root vertex is the equivalent to the infrastructure configuration vertex.
        user_service_config_vertex = self.dag.get_root

        # Find all the resources that are machines.
        for infra_resource_vertex in infra_config_vertex.has_vertices():
            if infra_resource_vertex.active is False or infra_resource_vertex.has_data is False:
                continue
            infra_resource_content = DiscoveryObject.get_discovery_object(infra_resource_vertex)
            if infra_resource_content.record_type == PAM_MACHINE:

                # Check the user on the resource if they still are part of a service or task.
                self._validate_users(infra_resource_content, infra_resource_vertex)

                # Do we have services or tasks that are run as a user with a password?
                if infra_resource_content.item.facts.has_services_or_tasks is True:

                    # If the resource does not exist in the user service graph, add a vertex and link it to the
                    #  user service root/configuration vertex.
                    user_service_resource_vertex = self.dag.get_vertex(infra_resource_content.record_uid)
                    if user_service_resource_vertex is None:
                        user_service_resource_vertex = self.dag.add_vertex(uid=infra_resource_content.record_uid,
                                                                           name=infra_resource_content.description)
                    if user_service_config_vertex.has(user_service_resource_vertex) is False:
                        user_service_resource_vertex.belongs_to_root(EdgeType.LINK)

                    # Do we have services that are run as a user with a password?
                    if infra_resource_content.item.facts.has_services is True:
                        self._connect_service_users(
                            infra_resource_content,
                            infra_resource_vertex,
                            infra_resource_content.item.facts.services)

                    # Do we have tasks that are run as a user with a password?
                    if infra_resource_content.item.facts.has_tasks is True:
                        self._connect_task_users(
                            infra_resource_content,
                            infra_resource_vertex,
                            infra_resource_content.item.facts.tasks)

        self.save()
