from __future__ import annotations
import logging
import os

from .constants import PAM_MACHINE, PAM_USER, PAM_DIRECTORY, DOMAIN_USER_CONFIGS
from .utils import get_connection, make_agent, split_user_and_domain, value_to_boolean
from .types import DiscoveryObject, ServiceAcl, NormalizedRecord
from .infrastructure import Infrastructure
from .record_link import RecordLink
from ..keeper_dag import DAG, EdgeType
from ..keeper_dag.types import PamGraphId
import importlib
from typing import Any, Optional, List, Callable, Dict, TYPE_CHECKING

if TYPE_CHECKING:
    from ..keeper_dag.vertex import DAGVertex
    from ..keeper_dag.edge import DAGEdge


class UserService:

    def __init__(self, record: Any, logger: Optional[Any] = None, history_level: int = 0,
                 debug_level: int = 0, fail_on_corrupt: bool = True, log_prefix: str = "GS Services/Tasks",
                 save_batch_count: int = 200, agent: Optional[str] = None,
                 **kwargs):

        # Keep these for other graphs
        self._params = kwargs.get("params")
        self._ksm = kwargs.get("ksm")

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

        self.agent = make_agent("user_service")
        if agent is not None:
            self.agent += "; " + agent

        self.auto_save = False
        self.last_sync_point = -1

        self.directory_user_cache: Optional[Dict[str, Dict]] = None

        # Mapping that use to keep track of what relationship have been update.
        self.cleanup_mapping = {}

        self.insecure_debug = value_to_boolean(os.environ.get("INSECURE_DEBUG", False))
        self.log_finer_level = 0
        try:
            self.log_finer_level = int(os.environ.get("KEEPER_GATEWAY_SERVICE_LOG_FINER_LEVEL", 0))
        except (Exception,):
            pass

    def debug(self, msg, level: int = 0, secret: bool = False):
        if self.log_finer_level >= level:
            if secret:
                if self.insecure_debug:
                    self.logger.debug(msg)
            else:
                self.logger.debug(msg)

    @property
    def dag(self) -> DAG:
        if self._dag is None:

            self._dag = DAG(conn=self.conn,
                            record=self.record,
                            graph_id=PamGraphId.SERVICE_LINKS,
                            auto_save=False,
                            logger=self.logger,
                            history_level=self.history_level,
                            debug_level=self.debug_level,
                            name="Discovery Services",
                            fail_on_corrupt=self.fail_on_corrupt,
                            log_prefix=self.log_prefix,
                            save_batch_count=self.save_batch_count,
                            agent=self.agent)

            self._dag.load(sync_point=0)

            # If an empty graph, call root get create a vertex.
            _ = self._dag.get_root

        return self._dag

    def close(self):
        """
        Clean up resources held by this UserService instance.
        Releases the DAG instance and connection to prevent memory leaks.
        """

        self._dag = None
        self.conn = None
        self._params = None
        self._ksm = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup."""
        self.close()
        return False

    def __del__(self):
        self.close()

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

    def belongs_to(self,
                   resource_uid: str,
                   user_uid: str, acl: Optional[ServiceAcl] = None,
                   resource_name: Optional[str] = None,
                   user_name: Optional[str] = None):

        """
        Link vault records using record UIDs.

        If a link already exists, no additional link will be created.
        """

        if resource_uid is None:
            self.debug("resource_uid is blank, do not connect")
            return
        if user_uid is None:
            self.debug("user_uid is blank, do not connect")
            return

        # Get thr record vertices.
        # If a vertex does not exist, then add the vertex using the record UID
        resource_vertex = self.dag.get_vertex(resource_uid)
        if resource_vertex is None:
            self.debug(f"adding resource vertex for record UID {resource_uid} ({resource_name})")
            resource_vertex = self.dag.add_vertex(uid=resource_uid, name=resource_name)

        user_vertex = self.dag.get_vertex(user_uid)
        if user_vertex is None:
            self.debug(f"adding user vertex for record UID {user_uid} ({user_name})")
            user_vertex = self.dag.add_vertex(uid=user_uid, name=user_name)

        self.debug(f"user {user_vertex.uid} controls services on {resource_vertex.uid}")

        edge_type = EdgeType.LINK
        if acl is not None:
            edge_type = EdgeType.ACL

        self.debug(f"Connect {user_vertex.uid} to {resource_vertex.uid}")
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
            if resource_vertex is None:
                self.debug("The resource vertex does not exists get; return default ACL")
            if user_vertex is None:
                self.debug("The user vertex does not exists get; return default ACL")
            return ServiceAcl()

        acl_edge = user_vertex.get_edge(resource_vertex, edge_type=EdgeType.ACL)  # type: DAGEdge
        if acl_edge is None:
            self.debug(f"ACL does not exists between resource {resource_uid} and user {user_vertex} doesn't "
                       "exist; return None")
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
        if self.dag.has_graph:
            self.debug("saving the service user.")
            self.dag.save(delta_graph=False)
        else:
            self.debug("the service user graph does not contain any data, was not saved.")

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

        self.debug(f"have {len(self.dag.all_vertices)} vertices")
        for v in self.dag.all_vertices:
            if show_only_active_vertices is True and v.active is False:
                continue

            tooltip = ""

            for edge in v.edges:

                color = "grey"
                style = "solid"

                # To reduce the number of edges, only show the active edges
                if edge.active:
                    color = "black"
                    style = "bold"
                elif show_only_active_edges:
                    continue

                # If the vertex is not active, gray out the DATA edge
                if edge.edge_type == EdgeType.DATA and v.active is False:
                    color = "grey"

                if edge.edge_type == EdgeType.DELETION:
                    style = "dotted"

                edge_tip = ""
                if edge.edge_type == EdgeType.ACL and v.active is True:
                    content = edge.content_as_dict
                    red = "00"
                    green = "00"
                    blue = "00"
                    if content.get("is_service"):
                        red = "FF"
                    if content.get("is_task"):
                        blue = "FF"
                    if content.get("is_iis_pool"):
                        green = "FF"
                    if red == "FF" and blue == "FF" and green == "FF":
                        color = "#808080"
                    else:
                        color = f"#{red}{green}{blue}"
                        style = "bold"

                    tooltip += f"TO {edge.head_uid}\\n"
                    for k, val in content.items():
                        tooltip += f" * {k}={val}\\n"
                    tooltip += f"--------------------\\n\\n"

                label = DAG.EDGE_LABEL.get(edge.edge_type)
                if label is None:
                    label = "UNK"
                if edge.path is not None and edge.path != "":
                    label += f"\\npath={edge.path}"
                if show_version:
                    label += f"\\nv={edge.version}"

                # tail, head (arrow side), label, ...
                dot.edge(v.uid, edge.head_uid, label, style=style, fontcolor=color, color=color, tooltip=edge_tip)

            shape = "ellipse"
            fillcolor = "white"
            color = "black"
            if not v.active:
                fillcolor = "grey"

            label = f"uid={v.uid}"
            dot.node(v.uid, label, color=color, fillcolor=fillcolor, style="filled", shape=shape, tooltip=tooltip)

        return dot

    def _init_cleanup_user_mapping(self):

        """
        Create of mapping of existing user services to see what was updated.

        This is the basically graph in dictionary format with the update flag set to False.
        """

        self.cleanup_mapping = {}
        for user_service_machine in self.dag.get_root.has_vertices():
            if user_service_machine.uid not in self.cleanup_mapping:
                self.cleanup_mapping[user_service_machine.uid] = {}
            for user_service_user in user_service_machine.has_vertices():
                self.cleanup_mapping[user_service_machine.uid][user_service_user.uid] = False

    def _user_is_used(self, machine_record_uid: str, user_record_uid: str):

        """
        Flag the user exists for a machine.
        """

        if machine_record_uid in self.cleanup_mapping and user_record_uid in self.cleanup_mapping[machine_record_uid]:
            self.cleanup_mapping[machine_record_uid][user_record_uid] = True

    def _cleanup_users(self):

        """
        Disconnect all users from machines that are not used.
        """

        self.debug("cleaning up unused user service relationships")

        did_something = False
        for machine_record_uid in self.cleanup_mapping:
            for user_record_uid in self.cleanup_mapping[machine_record_uid]:
                if not self.cleanup_mapping[machine_record_uid][user_record_uid]:
                    self.debug(f" * disconnect user {user_record_uid} from machine {machine_record_uid}")
                    did_something = True
                    self.disconnect_from(machine_record_uid, user_record_uid)
        if not did_something:
            self.debug(f"  nothing to cleanup")

    @staticmethod
    def _get_local_users_from_record(record_lookup_func: Callable,
                                     rl_machine_vertex: DAGVertex) -> Dict[str, str]:

        # Get the local users
        user_records: Dict[str, str] = {}

        for rl_user_vertex in rl_machine_vertex.has_vertices():
            record = record_lookup_func(rl_user_vertex.uid, allow_sm=False)  # type: NormalizedRecord
            if record and record.record_type == PAM_USER:
                user = record.get_user()
                if user is not None:
                    user, domain = split_user_and_domain(user.lower())
                    if domain is not None:
                        user += "@" + domain
                    user_records[user] = record.record_uid

        return user_records

    @staticmethod
    def _get_local_users_from_infra(record_lookup_func: Callable,
                                    infra_machine_vertex: DAGVertex) -> Dict[str, str]:

        user_records: Dict[str, str] = {}
        for infra_user_vertex in infra_machine_vertex.has_vertices():
            user_content = DiscoveryObject.get_discovery_object(infra_user_vertex)
            if user_content.record_type != PAM_USER or user_content.record_uid is None:
                continue
            if record_lookup_func(user_content.record_uid, allow_sm=False):
                user, domain = split_user_and_domain(user_content.item.user.lower())
                if domain is not None:
                    user += "@" + domain
                user_records[user] = user_content.record_uid

        return user_records

    def _get_directory_users_from_conf_record(self,
                                              record_linking: RecordLink,
                                              domain_name: str,
                                              record_lookup_func: Callable) -> Dict[str, str]:

        user_records: Dict[str, str] = {}

        # check if a PAM configuration that support having users (Azure, Domain Controller)
        # We need to get the normalized record of the configuration record.
        configuration_record = record_lookup_func(
            self.conn.get_record_uid(self.record), allow_sm=False)  # type: NormalizedRecord
        if configuration_record.record_type in DOMAIN_USER_CONFIGS:
            # The Domain Controller record will have the domain; Azure record will not.
            config_domain_name = configuration_record.get_value(label="pamdomainid")

            # If the domain name is not set, or it is, and we match the one that machine is joined to.
            if config_domain_name is None or config_domain_name.lower() == domain_name:
                config_vertex = record_linking.dag.get_vertex(configuration_record.record_uid)
                for child_vertex in config_vertex.has_vertices():
                    user_record = record_lookup_func(child_vertex.uid, allow_sm=False)  # type: NormalizedRecord
                    if not user_record:
                        # self.debug(f"      * record uid {child_vertex.uid} not found")
                        continue
                    if user_record.record_type != PAM_USER:
                        # self.debug(f"      * record uid {child_vertex.uid} is not PAM User")
                        continue
                    user, domain = split_user_and_domain(user_record.get_user().lower())
                    if domain is None:
                        domain = domain_name
                    user += "@" + domain
                    user_records[user] = user_record.record_uid
            else:
                self.debug(f"      domain name {config_domain_name} does not match {domain_name}")
        else:
            self.debug("      configuration type does not allow AD users")

        return user_records

    def _get_directory_users_from_conf_infra(self,
                                             infra: Infrastructure,
                                             domain_name: str,
                                             record_lookup_func: Callable) -> Dict[str, str]:

        user_records: Dict[str, str] = {}

        config_vertex = infra.get_configuration
        config_context = DiscoveryObject.get_discovery_object(config_vertex)
        if config_context.record_type in DOMAIN_USER_CONFIGS:
            for config_domain_name in config_context.item.info.get("domains", []):
                if config_domain_name != domain_name:
                    self.debug(f"      domain name {config_domain_name} does not match {domain_name}")
                    continue
                for child_vertex in config_vertex.has_vertices():
                    child_context = DiscoveryObject.get_discovery_object(child_vertex)
                    if child_context.record_type == PAM_USER and record_lookup_func(child_context.record_uid,
                                                                                    allow_sm=False):
                        user, domain = split_user_and_domain(child_context.item.user.lower())
                        if domain is None:
                            domain = domain_name
                        user += "@" + domain
                        user_records[user] = child_context.record_uid

        return user_records

    def _get_directory_users_from_records(self,
                                          record_linking: RecordLink,
                                          domain_name: str,
                                          record_lookup_func: Callable) -> Dict[str, str]:

        user_records: Dict[str, str] = {}

        # From the record linking graph, check each record connected to the configuration to see if it is a
        # PAM directory record.
        for rl_resource_vertex in record_linking.dag.get_root.has_vertices():
            directory_record = record_lookup_func(rl_resource_vertex.uid, allow_sm=False)  # type: NormalizedRecord
            if directory_record and directory_record.record_type == PAM_DIRECTORY:
                record_domain_name = directory_record.get_value(label="domainName")
                if record_domain_name is None:
                    self.logger.warning(f"    record uid {rl_resource_vertex.uid} is a directory, but the "
                                        "Domain Name is not set.")
                    continue
                if record_domain_name.lower() == domain_name:
                    self.debug(f"    record uid {rl_resource_vertex.uid} matches the domain name")
                    for rl_user_vertex in rl_resource_vertex.has_vertices():
                        user_record = record_lookup_func(rl_user_vertex.uid, allow_sm=False)  # type: NormalizedRecord
                        if user_record is None or user_record.record_type != PAM_USER:
                            continue

                        # Get the directory users, format the username to be user@domain
                        user = user_record.get_user()
                        if user is not None:
                            user, domain = split_user_and_domain(user.lower())
                            if domain is None:
                                domain = domain_name
                            user += "@" + domain
                            user_records[user] = user_record.record_uid
                        else:
                            self.debug(f"  ! record uid {rl_user_vertex.uid} has a blank user")

        return user_records

    @staticmethod
    def _get_directory_users_from_infra(infra_machine_vertex: DAGVertex,
                                        domain_name: str,
                                        record_lookup_func: Callable) -> Dict[str, str]:

        user_records: Dict[str, str] = {}

        configuration_vertex = infra_machine_vertex.belongs_to_vertices()[0]
        for resource_vertex in configuration_vertex.has_vertices():
            if not resource_vertex.has_data:
                continue
            resource_content = DiscoveryObject.get_discovery_object(resource_vertex)
            if resource_content.record_type != PAM_DIRECTORY or resource_content.name.lower() != domain_name:
                continue
            for user_vertex in resource_vertex.has_vertices():
                if not user_vertex.has_data:
                    continue
                user_content = DiscoveryObject.get_discovery_object(user_vertex)
                if user_content.record_type != PAM_USER and user_content.record_uid is None:
                    continue
                if record_lookup_func(user_content.record_uid, allow_sm=False):

                    # Format the username to be user@domain
                    user, domain = split_user_and_domain(user_content.item.user.lower())
                    if domain is None:
                        domain = domain_name
                    user += "@" + domain
                    user_records[user] = user_content.record_uid
        return user_records

    def _get_users(self,
                   infra: Infrastructure,
                   infra_machine_content: DiscoveryObject,
                   infra_machine_vertex: DAGVertex,
                   record_linking: RecordLink,
                   record_lookup_func: Callable) -> Dict[str, str]:

        """
        Get local and directory users for machine.

        The return values will be a dictionary of record_uid to username.

        It will first check the records linking graph. Then check the infrastructure graph.
        """

        self.debug(f"  getting users for {infra_machine_content.name}, {infra_machine_content.record_uid}")

        # Get the domain name that the machine it joined to.
        # Only accept the first one; we are Windows, only allow one domain.
        domain_name = None
        for directory in infra_machine_content.item.facts.directories:
            if directory.domain is not None:
                domain_name = directory.domain.lower()
                self.debug(f"  machine is joined to {domain_name}")
                break

        # Keep separate dictionaries since we are going to cache the directory users by domain name.
        # { "user": "record uid", ... }
        local_user_records: Dict[str, str] = {}
        directory_user_records: Dict[str, str] = {}

        using_directory_user_cache = False
        if domain_name:
            # Once we get directory users for a domain name, they will not change.
            # Cache them so we don't have to get them again.
            if self.directory_user_cache is not None:
                directory_user_records = self.directory_user_cache.get(domain_name)
                self.debug(f"  using directory user cache for {domain_name}, "
                           f"{len(directory_user_records)} users")
                using_directory_user_cache = True

        ###########################

        # Find the users using the record linking graph.
        self.debug(f"   getting users from record linking", level=1)
        record_link_vertex = record_linking.dag.get_vertex(infra_machine_content.record_uid)
        if record_link_vertex is None:
            self.debug("    record uid {machine_record_uid} does not exist in the Vault.", level=1)
        else:

            # Get the local users from records
            self.debug("    getting local users from records", level=1)
            user_records = self._get_local_users_from_record(rl_machine_vertex=record_link_vertex,
                                                             record_lookup_func=record_lookup_func)
            self.debug(f"      * found {len(user_records)} local users from records", level=1)
            local_user_records = {**local_user_records, **user_records}

            if not using_directory_user_cache and domain_name is not None:

                self.debug("    getting directory users from the configuration record", level=1)
                user_records = self._get_directory_users_from_conf_record(record_linking=record_linking,
                                                                          domain_name=domain_name,
                                                                          record_lookup_func=record_lookup_func)

                self.debug(f"        * found {len(user_records)} directory users records from "
                           "the configuration record", level=1)
                directory_user_records = {**directory_user_records, **user_records}

                self.debug("    getting directory users from directory records", level=1)
                user_records = self._get_directory_users_from_records(record_linking=record_linking,
                                                                      domain_name=domain_name,
                                                                      record_lookup_func=record_lookup_func)
                self.debug(f"        * found {len(user_records)} directory users from records for {domain_name}",
                           level=1)

                directory_user_records = {**directory_user_records, **user_records}

        ####################

        # Find the users via infrastructure graph

        self.debug(f"  getting users from infrastructure", level=1)
        self.debug("    getting local users from infrastructure", level=1)
        user_records = self._get_local_users_from_infra(infra_machine_vertex=infra_machine_vertex,
                                                        record_lookup_func=record_lookup_func)
        self.debug(f"      * found {len(user_records)} local users from graph", level=1)
        local_user_records = {**user_records, **local_user_records}

        if not using_directory_user_cache and domain_name is not None:

            self.debug("    getting directory users from configuration infrastructure", level=1)
            user_records = self._get_directory_users_from_conf_infra(infra=infra,
                                                                     domain_name=domain_name,
                                                                     record_lookup_func=record_lookup_func)
            self.debug(f"      * found {len(user_records)} directory users from configuration for {domain_name}",
                       level=1)
            directory_user_records = {**user_records, **directory_user_records}

            # -------------

            self.debug("    getting directory users from directory infrastructure", level=1)
            user_records = self._get_directory_users_from_infra(infra_machine_vertex=infra_machine_vertex,
                                                                domain_name=domain_name,
                                                                record_lookup_func=record_lookup_func)
            self.debug(f"      * found {len(user_records)} directory users from graph for {domain_name}", level=1)
            directory_user_records = {**user_records, **directory_user_records}

        # If we were not using the directory cache, cache them.
        if domain_name is not None and not using_directory_user_cache:
            if self.directory_user_cache is None:
                self.directory_user_cache = {}
            self.directory_user_cache[domain_name] = directory_user_records

        all_record = {**directory_user_records, **local_user_records}

        self.debug(f"  total union of users count {len(all_record.keys())}")

        return all_record

    def _connect_users_to_services(self,
                                   infra: Infrastructure,
                                   infra_machine_content: DiscoveryObject,
                                   infra_machine_vertex: DAGVertex,
                                   record_linking: RecordLink,
                                   record_lookup_func: Callable,
                                   strict: bool = False):

        domain_name = None
        for directory in infra_machine_content.item.facts.directories:
            if directory.domain is not None:
                domain_name = directory.domain.lower()
                break

        # Add mapping from user to machine, that control services.
        for service_type in ["service", "task", "iis_pool"]:
            self.debug("-" * 40)
            self.debug(f"processing {service_type}s for {infra_machine_content.name} "
                       f"({infra_machine_vertex.uid})")

            # We don't care about the name of the service, we just need a list users.
            service_users = []
            for service_user in getattr(infra_machine_content.item.facts, f"{service_type}s"):
                self.debug(f"  * {service_type}: {service_user.name} ({service_user.user})", secret=True)
                user = service_user.user.lower()
                if not strict:
                    user, domain = split_user_and_domain(user)
                    service_users.append(user)
                    if domain is not None and domain != ".":
                        service_users.append(user + "@" + domain)
                        service_users.append(user + "@" + domain.split(".")[0])
                    if domain_name is not None:
                        service_users.append(user + "@" + domain_name)
                        service_users.append(user + "@" + domain_name.split(".")[0])

                else:
                    service_users.append(user)

            service_users = list(set(service_users))

            if len(service_users) == 0:
                self.debug(f"  no users control {service_type}s, skipping.")
                continue

            users = self._get_users(infra=infra,
                                    infra_machine_content=infra_machine_content,
                                    infra_machine_vertex=infra_machine_vertex,
                                    record_linking=record_linking,
                                    record_lookup_func=record_lookup_func)

            if self.log_finer_level >= 2 and self.insecure_debug:
                for k, v in users.items():
                    self.debug(f"> {k} = {v}")

            self.debug(f"users to check: {service_users}", secret=True)
            for service_user in service_users:
                self.debug(f"  * {service_user}", secret=True)
                if service_user in users:
                    record_uid = users[service_user]
                    self.debug(f"    found user {service_user} for {service_type}", secret=True)
                    acl = self.get_acl(infra_machine_content.record_uid, record_uid)
                    if acl is None:
                        acl = ServiceAcl()
                    acl_attr = "is_" + service_type

                    # Flag the user was found; don't disconnect
                    self._user_is_used(machine_record_uid=infra_machine_content.record_uid,
                                       user_record_uid=record_uid)

                    # Only update if the attribute is currently False; reduce edges.
                    if getattr(acl, acl_attr) is False:
                        setattr(acl, acl_attr, True)
                        self.belongs_to(resource_uid=infra_machine_content.record_uid,
                                        user_uid=record_uid,
                                        acl=acl)

    def _get_resource_info(self,
                           record_uid: str,
                           infra: Infrastructure,
                           record_lookup_func: Callable,
                           record_types: Optional[List[str]] = None) -> Optional[NormalizedRecord]:

        """
        Find a resource, or user, in the Vault or in the Infrastructure graph.

        This will return a NormalizedRecord record.
        This doesn't mean the

        """

        # Check the record first; return a NormalizedRecord
        record = record_lookup_func(record_uid, allow_sm=False)  # type: NormalizedRecord
        if record is not None:
            self.debug(f"  resource is {record.title}")
            if record_types is not None and record.record_type not in record_types:
                self.debug(f"  not correct record type: {record.record_type}")
                return None
            return record
        else:
            self.debug("  not in Vault")

        infra_vertices = infra.dag.search_content({"record_uid": record_uid})
        if not len(infra_vertices):
            self.debug("  not in infrastructure graph")
            return None

        for vertex in infra_vertices:
            if vertex.active:
                content = DiscoveryObject.get_discovery_object(vertex)
                record = NormalizedRecord(
                    record_uid=record_uid,
                    record_type=content.record_type,
                    title=content.title,
                    record_exists=False
                )
                for field in content.fields:
                    record.fields.append(field)

                return record

        return None

    def run_user(self):
        pass

    def run_full(self,
                 record_lookup_func: Callable,
                 infra: Optional[Infrastructure] = None,
                 record_linking: Optional[RecordLink] = None,
                 **kwargs):
        """
        Map users to services on machines.

        This is driven by the record linking graph.

        :param infra: Instance of Infrastructure graph.
        :param record_linking: Instance of the Record Linking graph.
        :param record_lookup_func: A function that will return a record by record id. Returns a normalize record.
        """

        self.debug("")
        self.debug("##########################################################################################")
        self.debug("# MAP USER TO MACHINE FOR SERVICES")
        self.debug("")

        # Load fresh

        created_infra = False
        created_record_linking = False

        try:

            # Make of map of the current user to machine relationship.
            self._init_cleanup_user_mapping()

            if not infra:
                infra = Infrastructure(record=self.record, logger=self.logger, ksm=self._ksm, params=self._params)
                infra.load(sync_point=0)
                created_infra = True

            if not record_linking:
                record_linking = RecordLink(record=self.record, logger=self.logger, ksm=self._ksm, params=self._params)
                created_record_linking = True

            # The PAM Configuration record is the root vertex of the PAM/record linking graph.
            rl_configuration_vertex = record_linking.dag.get_root

            # At this level the vertex will either be a resource or a cloud user.
            for rl_resource_vertex in rl_configuration_vertex.has_vertices():

                self.debug(f"checking record {rl_resource_vertex.uid}")

                # This will get machine from the records or from infrastructure graph.
                # The results is a NormalizedRecord.
                machine_record = self._get_resource_info(record_uid=rl_resource_vertex.uid,
                                                         infra=infra,
                                                         record_lookup_func=record_lookup_func,
                                                         record_types=[PAM_MACHINE])

                if machine_record is None:
                    self.debug("  could not find record")
                    continue

                if machine_record.record_type != PAM_MACHINE:
                    self.debug("  record is not PAM Machine")
                    continue

                self.debug(f"  checking machine {machine_record.title}")

                # Since the facts hold information about services, get those from the infrastructure graph.
                infra_machine_vertex = infra.find_content({"record_uid": machine_record.record_uid})
                if not infra_machine_vertex:
                    self.debug("  could not find machine in the infrastructure graph, skipping")
                    continue
                if not infra_machine_vertex.has_data:
                    self.debug("  machine has no data yet, skipping")
                    continue

                infra_machine_content = DiscoveryObject.get_discovery_object(infra_machine_vertex)

                # The `services` are currently on Windows machine, skip any machine that is not running Windows.
                if infra_machine_content.item.os != "windows":
                    self.debug("  machine is not Windows, skipping")
                    continue

                # Do we have services, tasks, iis_pools that are run as a user with a password?
                if not infra_machine_content.item.facts.has_service_items:
                    self.debug("  machine has no user controlled services, skipping")
                    continue

                user_service_machine_vertex = self.dag.get_vertex(infra_machine_content.record_uid)

                # If the resource does not exist in the user service graph, add a vertex and link it to the
                #  user service root/configuration vertex.
                if user_service_machine_vertex is None:
                    user_service_machine_vertex = self.dag.add_vertex(uid=infra_machine_content.record_uid,
                                                                      name=infra_machine_content.name)

                # If the UserService resource vertex is not connect to root, connect it.
                if not self.dag.get_root.has(user_service_machine_vertex):
                    user_service_machine_vertex.belongs_to_root(EdgeType.LINK)

                self.debug("-" * 40)
                self._connect_users_to_services(
                    infra=infra,
                    infra_machine_content=infra_machine_content,
                    infra_machine_vertex=infra_machine_vertex,
                    record_linking=record_linking,
                    record_lookup_func=record_lookup_func)
                self.debug("-" * 40)

            # Disconnect any users not used.
            # TODO - Handle this better.
            #        If a machine is off, or we cannot connect, we might disconnect users.
            #        This needs more testing.
            # self._cleanup_users()

            self.save()

        except Exception as err:
            self.logger.error(f"could not map users to services: {err}")
            raise err

        finally:
            if created_infra:
                infra.close()
            if created_record_linking:
                record_linking.close()
