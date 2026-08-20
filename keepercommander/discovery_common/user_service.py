from __future__ import annotations
import logging
import os

from .constants import PAM_MACHINE, PAM_USER, PAM_DIRECTORY, DOMAIN_USER_CONFIGS
from .utils import get_connection, make_agent, split_user_and_domain, value_to_boolean
from .types import (DiscoveryObject, ServiceAcl, NormalizedRecord, UserAcl, UserAclServiceNames,
                    UserAclServiceNamesItem, ServiceEnum)
from .infrastructure import Infrastructure
from .record_link import RecordLink
from ..keeper_dag import DAG, EdgeType
from ..keeper_dag.types import PamGraphId
import importlib
from typing import Any, Optional, List, Callable, Dict, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..keeper_dag.vertex import DAGVertex
    from ..keeper_dag.edge import DAGEdge


class UserService:

    """
    Map when a user's password is rotated, which machine services need to also be changed.

    In Windows, services, scheduled tasks, iis pool, etc. require the password for the user that service will be run as.
    When a user's password is changed, each of these services need have their password changed.

    We store the map in the PAM graph, in the rotation settings, `controls_services`.
    When a user's password is changed, each ACL edge connected to user will be checked.
    If `controls_services` is True, the machine will be logged in and each service will be checked to see if this
      user controls them.
    If the user does, then the password on the service is changed.

    This used to be stored in graph 13, but has been moved the PAM graph.
    A migration is run to moved items from the old graph and placed in the PAM graph.

    """

    def __init__(self,
                 record_linking: RecordLink,
                 record: Any,
                 record_lookup_func: Callable,
                 logger: Optional[Any] = None,
                 history_level: int = 0,
                 debug_level: int = 0,
                 fail_on_corrupt: bool = True,
                 log_prefix: str = "GS Services",
                 save_batch_count: int = 200,
                 agent: Optional[str] = None,
                 use_per_graph_endpoints: bool = False,
                 context: Optional[Dict] = None,
                 **kwargs):

        # Keep these for other graphs
        self._params = kwargs.get("params")
        self._ksm = kwargs.get("ksm")
        self.record_linking = record_linking
        self.record_lookup_func = record_lookup_func
        self.service_graph = None
        self.did_migration = False

        if context is None:
            context = {}
            if self._params is not None:
                context["params"] = self._params
        self.context = context

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
        # self.use_per_graph_endpoints = use_per_graph_endpoints
        self.use_per_graph_endpoints = False

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

        self._infra = None

        self._migrate()

    def debug(self, msg, level: int = 0, secret: bool = False):
        if self.log_finer_level >= level:
            if secret:
                if self.insecure_debug:
                    self.logger.debug(msg)
            else:
                self.logger.debug(msg)

    @property
    def record_key_bytes(self) -> bytes:
        # The KSM Record exposes record_key_bytes; the Commander KeeperRecord exposes record_key.
        if hasattr(self.record, "record_key_bytes"):
            return self.record.record_key_bytes
        return self.record.record_key

    @property
    def infra(self):

        if self._infra is None:
            self._infra = Infrastructure(record=self.record, logger=self.logger, ksm=self._ksm, params=self._params)
            self._infra.load(sync_point=0)
        return self._infra

    def _migrate(self):

        """
        Migrate items from the old user service graph to the PAM graph.
        """

        self.debug("perform user service graph migration")

        self.service_graph = DAG(conn=self.conn,
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

        # Cannot add service names via migration. Not enough data in graph to perform it.

        # First migration - ServiceACL
        # If still using the service_graph, migrate to the PAM graph.
        # Add a generic label per service type being used.
        self.service_graph.load(sync_point=0)
        updated_service_graph = False
        if self.service_graph.has_graph and len(self.service_graph.get_root.has_vertices()) > 0:
            self.logger.debug("migrate from user service graph")
            for s_resource_vertex in self.service_graph.get_root.has_vertices():
                for s_user_vertex in s_resource_vertex.has_vertices():
                    acl_edge = s_user_vertex.get_edge(s_resource_vertex, edge_type=EdgeType.ACL)
                    if acl_edge is not None:

                        service_acl = acl_edge.content_as_object(ServiceAcl)  # type: ServiceAcl
                        if service_acl.is_used:
                            self.logger.debug(f"  * {s_resource_vertex.uid} <- {s_user_vertex.uid}")

                            record = self.record_lookup_func(s_user_vertex.uid, context=self.context)
                            user_acl = self.record_linking.get_acl(s_user_vertex.uid, s_resource_vertex.uid)
                            if user_acl is None:
                                user_acl = UserAcl.default()

                            if record is not None:

                                # Set via_discovery=True so that discovery will remove these and replace with
                                # real services, tasks, and IIS pools.

                                if service_acl.is_service:
                                    self.add_service_name(acl=user_acl,
                                                          service_type=ServiceEnum.service,
                                                          service_name="Unknown Service(s)",
                                                          record_key_bytes=record.record_key_bytes,
                                                          via_discovery=True)
                                    self.logger.debug(f"    - user controls service")

                                if service_acl.is_task:
                                    self.add_service_name(acl=user_acl,
                                                          service_type=ServiceEnum.task,
                                                          service_name="Unknown Task(s)",
                                                          record_key_bytes=record.record_key_bytes,
                                                          via_discovery=True)
                                    self.logger.debug(f"    - user controls task")

                                if service_acl.is_iis_pool:
                                    self.add_service_name(acl=user_acl,
                                                          service_type=ServiceEnum.iis_pool,
                                                          service_name="Unknown IIS Pool(s)",
                                                          record_key_bytes=record.record_key_bytes,
                                                          via_discovery=True)
                                    self.logger.debug(f"    - user controls iis pool")
                            else:
                                self.logger.debug(f"    !! could not find user record UID {s_user_vertex.uid}")
                                user_acl.controls_services = True

                            # set_acl also links the resource to the root; without that link the
                            # migrated vertices would not survive a save/load of the graph.
                            self.set_acl(resource_uid=s_resource_vertex.uid, user_uid=s_user_vertex.uid, acl=user_acl)
                    s_user_vertex.delete()
                s_resource_vertex.delete()
                updated_service_graph = True
                self.did_migration = True

        # Second Migration - UserACL
        # If migrated to the PAM graph, and there are no service_names, add a generic label for all services.
        for resource_vertex in self.record_linking.dag.get_root.has_vertices():
            for user_vertex in resource_vertex.has_vertices():
                user_acl = self.record_linking.get_acl(record_uid=user_vertex.uid,
                                                       parent_record_uid=resource_vertex.uid)
                if user_acl:
                    # If the user controls services and the names are blank
                    if user_acl.controls_services and (user_acl.service_names is None
                                                       or user_acl.service_names == ""):
                        record = self.record_lookup_func(user_vertex.uid, context=self.context)
                        if record:
                            self.logger.debug(f"  * {resource_vertex.uid} <- {user_vertex.uid}; add placeholder")
                            self.did_migration = True
                            self.add_service_name(acl=user_acl,
                                                  service_type=ServiceEnum.service,
                                                  service_name="Unknown Service, Task, or IIS Pools",
                                                  record_key_bytes=record.record_key_bytes,
                                                  via_discovery=True)
                            self.record_linking.belongs_to(user_vertex.uid, resource_vertex.uid, acl=user_acl)

        if self.did_migration:
            if updated_service_graph:
                self.service_graph.save()
            self.record_linking.save()
            self.debug("  items were migrated")
        else:
            self.debug("  no items to migrated")

    def close(self):
        """
        Clean up resources held by this UserService instance.
        Releases the DAG instance and connection to prevent memory leaks.
        """

        self._dag = None
        self.conn = None
        self._params = None
        self._ksm = None
        self._infra = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup."""
        self.close()
        return False

    def __del__(self):
        self.close()

    def get_record_link(self, uid: str) -> Optional[DAGVertex]:
        return self.record_linking.dag.get_vertex(uid)

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

    def set_acl(self,
                resource_uid: str,
                user_uid: str,
                acl: UserAcl,
                resource_name: Optional[str] = None,
                user_name: Optional[str] = None):

        """
        Update the record linking ACL with control_services
        """

        if resource_uid is None:
            self.debug("resource_uid is blank, do not connect")
            return
        if user_uid is None:
            self.debug("user_uid is blank, do not connect")
            return

        # Get thr record vertices.
        # If a vertex does not exist, then add the vertex using the record UID
        resource_vertex = self.record_linking.dag.get_vertex(resource_uid)
        if resource_vertex is None:
            self.debug(f"adding resource vertex for record UID {resource_uid} ({resource_name})")
            resource_vertex = self.record_linking.dag.add_vertex(uid=resource_uid, name=resource_name)

        user_vertex = self.record_linking.dag.get_vertex(user_uid)
        if user_vertex is None:
            self.debug(f"adding user vertex for record UID {user_uid} ({user_name})")
            user_vertex = self.record_linking.dag.add_vertex(uid=user_uid, name=user_name)

        self.debug(f"user {user_vertex.uid} controls services on {resource_vertex.uid}")
        user_vertex.belongs_to(resource_vertex, edge_type=EdgeType.ACL, content=acl)

        link_exists = resource_vertex.get_edge(self.record_linking.dag.get_root, EdgeType.LINK)
        if link_exists is None:
            self.debug(f"  * no link to configuration, adding.")
            resource_vertex.belongs_to_root(edge_type=EdgeType.LINK)

    def disconnect_from(self, resource_uid: str, user_uid: str):
        resource_vertex = self.record_linking.dag.get_vertex(resource_uid)
        if resource_vertex is not None:
            user_vertex = self.record_linking.dag.get_vertex(user_uid)
            if user_vertex is not None:
                user_vertex.disconnect_from(resource_vertex)

    def get_acl(self, resource_uid, user_uid) -> Optional[UserAcl]:

        """
        Get the user ACL from the record linking graph.
        """
        return self.record_linking.get_acl(user_uid, resource_uid)

    def resource_has_link(self, resource_uid) -> bool:
        """
        Is this resource linked to the configuration?
        """

        resource_vertex = self.record_linking.dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return False
        link_edge = resource_vertex.get_edge(self.record_linking.dag.get_root, edge_type=EdgeType.LINK)  # type: DAGEdge
        return link_edge is not None

    def get_resource_vertices(self, user_uid: str) -> List[DAGVertex]:

        """
        Get the resource vertices where the user controls a service.
        """

        user_vertex = self.record_linking.dag.get_vertex(user_uid)
        if user_vertex is None:
            return []
        resource_vertices = []
        for resource_vertex in user_vertex.belongs_to_vertices():
            user_acl = self.record_linking.get_acl(user_uid, resource_vertex.uid)
            if user_acl:
                if user_acl.controls_services:
                    resource_vertices.append(resource_vertex)
        return resource_vertices

    def get_user_vertices(self, resource_uid: str) -> List[DAGVertex]:

        """
        Get the user vertices that control a service or task on this machine.

        """
        resource_vertex = self.record_linking.dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return []
        user_vertices = []
        for user_vertex in resource_vertex.has_vertices():
            user_acl = self.record_linking.get_acl(user_vertex.uid, resource_uid)
            if user_acl:
                if user_acl.controls_services:
                    user_vertices.append(user_vertex)
        return user_vertices

    @staticmethod
    def delete(vertex: DAGVertex):
        if vertex is not None:
            vertex.delete()

    def save(self):
        self.record_linking.save()

    def to_dot(self, graph_format: str = "svg", graph_type: str = "dot"):

        try:
            mod = importlib.import_module("graphviz")
        except ImportError:
            raise Exception("Cannot to_dot(), graphviz module is not installed.")

        dot = getattr(mod, "Digraph")(comment=f"DAG for Services", format=graph_format)

        if graph_type == "dot":
            dot.attr(rankdir='RL')
        elif graph_type == "twopi":
            dot.attr(layout="twopi")
            dot.attr(ranksep="10")
            dot.attr(ratio="auto")
        else:
            dot.attr(layout=graph_type)

        # This will get all the resources (and cloud users)
        for resource_vertex in self.record_linking.dag.get_root.has_vertices():
            if not resource_vertex.active:
                continue

            plotted_resource = False
            for user_vertex in resource_vertex.has_vertices():
                acl = self.record_linking.get_acl(user_vertex.uid, resource_vertex.uid)
                if acl is None or not acl.controls_services:
                    continue

                if not plotted_resource:
                    dot.edge(resource_vertex.uid, self.record_linking.dag.get_root.uid)
                    dot.node(resource_vertex.uid)
                    plotted_resource = True

                dot.edge(user_vertex.uid, resource_vertex.uid)
                dot.node(user_vertex.uid)

        return dot

    def _get_local_users_from_record(self, rl_machine_vertex: DAGVertex) -> Dict[str, str]:

        # Get the local users
        user_records: Dict[str, str] = {}

        for rl_user_vertex in rl_machine_vertex.has_vertices():
            record = self.record_lookup_func(rl_user_vertex.uid,
                                             context=self.context,
                                             allow_sm=False)  # type: NormalizedRecord
            if record and record.record_type == PAM_USER:
                user = record.get_user()
                if user is not None:
                    user, domain = split_user_and_domain(user.lower())
                    if domain is not None:
                        user += "@" + domain
                    user_records[user] = record.record_uid
                alt_user = record.get_alt_user()
                if alt_user is not None:
                    alt_user, domain = split_user_and_domain(alt_user.lower())
                    if domain is not None:
                        alt_user += "@" + domain
                    user_records[alt_user] = record.record_uid

        return user_records

    def _get_local_users_from_infra(self, infra_machine_vertex: DAGVertex) -> Dict[str, str]:

        user_records: Dict[str, str] = {}
        for infra_user_vertex in infra_machine_vertex.has_vertices():
            user_content = DiscoveryObject.get_discovery_object(infra_user_vertex)
            if user_content.record_type != PAM_USER or user_content.record_uid is None:
                continue
            if self.record_lookup_func(user_content.record_uid, context=self.context, allow_sm=False):
                user, domain = split_user_and_domain(user_content.item.user.lower())
                if domain is not None:
                    user += "@" + domain
                user_records[user] = user_content.record_uid

        return user_records

    def _get_directory_users_from_conf_record(self,
                                              domain_name: str,
                                              netbios: Optional[str] = None) -> Dict[str, str]:

        user_records: Dict[str, str] = {}

        # check if a PAM configuration that support having users (Azure, Domain Controller)
        # We need to get the normalized record of the configuration record.
        configuration_record = self.record_lookup_func( self.conn.get_record_uid(self.record),
                                                        context=self.context,
                                                        allow_sm=False)  # type: NormalizedRecord
        if configuration_record.record_type in DOMAIN_USER_CONFIGS:
            # The Domain Controller record will have the domain; Azure record will not.
            config_domain_name = configuration_record.get_value(label="pamdomainid")

            # If the domain name is not set, or it is, and we match the one that machine is joined to.
            if (config_domain_name is None
                    or (config_domain_name.lower() == domain_name or config_domain_name.lower() == netbios)):
                config_vertex = self.record_linking.dag.get_vertex(configuration_record.record_uid)
                for child_vertex in config_vertex.has_vertices():
                    user_record = self.record_lookup_func(child_vertex.uid,
                                                          context=self.context,
                                                          allow_sm=False)  # type: NormalizedRecord
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

                    alt_user = user_record.get_alt_user()
                    if alt_user is not None:
                        alt_user, domain = split_user_and_domain(alt_user.lower())
                        if domain is None:
                            domain = domain_name
                        alt_user += "@" + domain
                        user_records[alt_user] = user_record.record_uid
            else:
                self.debug(f"      domain name {config_domain_name} does not match {domain_name}")
        else:
            self.debug("      configuration type does not allow AD users")

        return user_records

    def _get_directory_users_from_conf_infra(self,
                                             infra: Infrastructure,
                                             domain_name: str,
                                             netbios: Optional[str] = None) -> Dict[str, str]:

        user_records: Dict[str, str] = {}

        config_vertex = infra.get_configuration
        config_context = DiscoveryObject.get_discovery_object(config_vertex)
        if config_context.record_type in DOMAIN_USER_CONFIGS:
            for config_domain_name in config_context.item.info.get("domains", []):
                if (config_domain_name.lower() == domain_name or
                        (netbios is not None and config_domain_name.lower() != netbios.lower())):
                    self.debug(f"      domain name {config_domain_name} MATCHED {domain_name}/{netbios}")
                    for child_vertex in config_vertex.has_vertices():
                        child_context = DiscoveryObject.get_discovery_object(child_vertex)
                        if child_context.record_type == PAM_USER and self.record_lookup_func(child_context.record_uid,
                                                                                             context=self.context,
                                                                                             allow_sm=False):
                            user, domain = split_user_and_domain(child_context.item.user.lower())
                            if domain is None:
                                domain = domain_name
                            user += "@" + domain
                            user_records[user] = child_context.record_uid
                else:
                    self.debug(f"      domain name {config_domain_name} does not match {domain_name}/{netbios}")
                    continue

        return user_records

    def _get_directory_users_from_records(self,
                                          domain_name: str) -> Dict[str, str]:

        user_records: Dict[str, str] = {}

        # From the record linking graph, check each record connected to the configuration to see if it is a
        # PAM directory record.
        for rl_resource_vertex in self.record_linking.dag.get_root.has_vertices():
            directory_record = self.record_lookup_func(rl_resource_vertex.uid,
                                                       context=self.context,
                                                       allow_sm=False)  # type: NormalizedRecord
            if directory_record and directory_record.record_type == PAM_DIRECTORY:
                record_domain_name = directory_record.get_value(label="domainName")
                if record_domain_name is None:
                    self.logger.warning(f"    record uid {rl_resource_vertex.uid} is a directory, but the "
                                        "Domain Name is not set.")
                    continue
                if record_domain_name.lower() == domain_name:
                    self.debug(f"    record uid {rl_resource_vertex.uid} matches the domain name")
                    for rl_user_vertex in rl_resource_vertex.has_vertices():
                        user_record = self.record_lookup_func(rl_user_vertex.uid,
                                                              context=self.context,
                                                              allow_sm=False)  # type: NormalizedRecord
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

                        alt_user = user_record.get_alt_user()
                        if alt_user is not None:
                            alt_user, domain = split_user_and_domain(alt_user.lower())
                            if domain is not None:
                                alt_user += "@" + domain
                            user_records[alt_user] = user_record.record_uid

        return user_records

    def _get_directory_users_from_infra(self,
                                        infra_machine_vertex: DAGVertex,
                                        domain_name: str) -> Dict[str, str]:

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
                if self.record_lookup_func(user_content.record_uid, context=self.context, allow_sm=False):

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
                   netbios: Optional[str] = None,
                   domain_name: Optional[str] = None) -> Dict[str, str]:

        """
        Get local and directory users for machine.

        The return values will be a dictionary of record_uid to username.

        It will first check the records linking graph. Then check the infrastructure graph.
        """

        self.debug(f"    getting users for {infra_machine_content.name}, {infra_machine_content.record_uid}")

        if netbios is not None:
            netbios = netbios.lower()
            self.debug(f"  machine is joined to {netbios} netbios")

        if domain_name is not None:
            domain_name = domain_name.lower()
            self.debug(f"  machine is joined to {domain_name} domain name")

        # Keep separate dictionaries since we are going to cache the directory users by domain name.
        # { "user": "record uid", ... }
        local_user_records: Dict[str, str] = {}
        directory_user_records: Dict[str, str] = {}

        using_directory_user_cache = False
        if domain_name:
            # Once we get directory users for a domain name, they will not change.
            # Cache them so we don't have to get them again.
            if self.directory_user_cache is not None:
                directory_user_records = self.directory_user_cache.get(domain_name, {})
                if directory_user_records is not None and len(directory_user_records) > 0:
                    self.debug(f"    using directory user cache for {domain_name}, "
                               f"{len(directory_user_records)} users")
                    using_directory_user_cache = True
                # If directory_user_records is None, make sure it's an empty dictionary.
                # We might try to merge dictionaries; we don't want it None.
                else:
                    directory_user_records = {}

        ###########################

        # Find the users using the record linking graph.
        self.debug(f"      getting users from record linking", level=1)
        record_link_vertex = self.record_linking.dag.get_vertex(infra_machine_content.record_uid)
        if record_link_vertex is None:
            self.debug("    record uid {machine_record_uid} does not exist in the Vault.", level=1)
        else:

            # Get the local users from records
            self.debug("        getting local users from records", level=1)
            user_records = self._get_local_users_from_record(rl_machine_vertex=record_link_vertex)
            self.debug(f"         * found {len(user_records)} local users from records", level=1)
            local_user_records = {**local_user_records, **user_records}

            if not using_directory_user_cache and domain_name is not None:

                self.debug("    getting directory users from the configuration record", level=1)
                user_records = self._get_directory_users_from_conf_record(domain_name=domain_name,
                                                                          netbios=netbios)

                self.debug(f"          * found {len(user_records)} directory users records from "
                           "the configuration record", level=1)
                directory_user_records = {**directory_user_records, **user_records}

                self.debug("      getting directory users from directory records", level=1)
                user_records = self._get_directory_users_from_records(domain_name=domain_name)
                self.debug(f"      * found {len(user_records)} directory users from records for {domain_name}",
                           level=1)

                directory_user_records = {**directory_user_records, **user_records}

        ####################

        # Find the users via infrastructure graph

        self.debug(f"    getting users from infrastructure", level=1)
        self.debug("       getting local users from infrastructure", level=1)
        user_records = self._get_local_users_from_infra(infra_machine_vertex=infra_machine_vertex)
        self.debug(f"         * found {len(user_records)} local users from graph", level=1)
        local_user_records = {**user_records, **local_user_records}

        if not using_directory_user_cache and domain_name is not None:

            self.debug("      getting directory users from configuration infrastructure", level=1)
            user_records = self._get_directory_users_from_conf_infra(infra=infra,
                                                                     domain_name=domain_name)
            self.debug(f"        * found {len(user_records)} directory users from configuration for {domain_name}",
                       level=1)
            directory_user_records = {**user_records, **directory_user_records}

            # -------------

            self.debug("      getting directory users from directory infrastructure", level=1)
            user_records = self._get_directory_users_from_infra(infra_machine_vertex=infra_machine_vertex,
                                                                domain_name=domain_name)
            self.debug(f"        * found {len(user_records)} directory users from graph for {domain_name}",
                       level=1)
            directory_user_records = {**user_records, **directory_user_records}

        # If we were not using the directory cache, cache them.
        if domain_name is not None and not using_directory_user_cache:
            if self.directory_user_cache is None:
                self.directory_user_cache = {}
            self.directory_user_cache[domain_name] = directory_user_records

        all_record = {**directory_user_records, **local_user_records}

        self.debug(f"    total union of users count {len(all_record.keys())}")

        return all_record

    @staticmethod
    def clear_discovery_service_names(acl: UserAcl, record_key_bytes: bytes):

        """
        Remove all the service names added by discovery from the list.
        """

        new_service_names = []
        for service_names in acl.get_service_names(record_key_bytes):
            service_names.items = [item for item in service_names.items if not item.via_discovery]
            if service_names.items:
                new_service_names.append(service_names)
        acl.set_service_names(new_service_names, record_key_bytes)

    @staticmethod
    def add_service_name(acl: UserAcl,
                         service_type: ServiceEnum,
                         service_name: str,
                         record_key_bytes: bytes,
                         via_discovery: bool = False):

        all_service_names = acl.get_service_names(record_key_bytes)

        service_names = None
        for name in all_service_names:
            if name.type == service_type:
                service_names = name
                break

        if service_names is None:
            service_names = UserAclServiceNames(type=service_type)
            all_service_names.append(service_names)

        for item in service_names.items:
            if item.name.lower() == service_name.lower():
                return

        service_names.items.append(
            UserAclServiceNamesItem(
                name=service_name,
                via_discovery=via_discovery)
        )

        acl.set_service_names(all_service_names, record_key_bytes)

        if len(all_service_names) > 0:
            acl.controls_services = True

    @staticmethod
    def remove_service_name(acl: UserAcl,
                            record_key_bytes: bytes,
                            service_type: Optional[ServiceEnum] = None,
                            service_name: Optional[str] = None):

        # Without a service type, clear all the service names for all types.
        if service_type is None:
            acl.service_names = ""
            return

        all_service_names = acl.get_service_names(record_key_bytes)

        new_service_names = []
        for service_names in all_service_names:
            if service_names.type == service_type:
                # Without a service name, remove all the items for this service type.
                if service_name is None:
                    continue
                service_names.items = [item for item in service_names.items
                                       if item.name.lower() != service_name.lower()]
                if not service_names.items:
                    continue
            new_service_names.append(service_names)

        if len(new_service_names) == 0:
            acl.controls_services = False

        acl.set_service_names(new_service_names, record_key_bytes)

    def _connect_users_to_machine_services(self,
                                           infra: Infrastructure,
                                           infra_machine_content: DiscoveryObject,
                                           infra_machine_vertex: DAGVertex,
                                           strict: bool = False,
                                           domain_name: Optional[str] = None,
                                           netbios: Optional[str] = None):

        if domain_name is None:
            for directory in infra_machine_content.item.facts.directories:
                if directory.domain is not None:
                    domain_name = directory.domain.lower()
                    break

        # Try to get the netbios from the configuration.
        if netbios is None:
            configuration_vertex = infra.get_configuration
            if configuration_vertex is None:
                self.debug("cannot get the configuration vertex")
                return
            config_object = DiscoveryObject.get_discovery_object(configuration_vertex)
            if config_object.record_type in DOMAIN_USER_CONFIGS:
                if hasattr(config_object.item, "info"):
                    netbios = config_object.item.info.get("netbios")

        # We don't want to keep update the ACL in the graph, it will make a lot of edges.
        # Update the cache, then update the graph at the end.
        acl_cache: Dict[str, Tuple] = {}
        acl_md5_cache: Dict[str, str] = {}

        # These are the user available on a machine.
        users = self._get_users(infra=infra,
                                infra_machine_content=infra_machine_content,
                                infra_machine_vertex=infra_machine_vertex,
                                netbios=netbios,
                                domain_name=domain_name)

        if self.log_finer_level >= 2 and self.insecure_debug:
            for k, v in users.items():
                self.debug(f"      > {k} = {v}")

        # Add mapping from user to machine, that control services.
        for service_type in [ServiceEnum.service, ServiceEnum.task, ServiceEnum.iis_pool,
                             ServiceEnum.com, ServiceEnum.dcom, ServiceEnum.com_plus, ServiceEnum.scom]:
            self.debug("-" * 40)
            self.debug(f"processing {service_type.value}s for {infra_machine_content.name} "
                       f"({infra_machine_vertex.uid})")

            # Get the pair of name of the service and the user that controls it.
            # This is from discovery.
            if hasattr(infra_machine_content.item.facts, f"{service_type.value}s"):
                service_pairs = getattr(infra_machine_content.item.facts, f"{service_type.value}s")
            else:
                service_pairs = getattr(infra_machine_content.item.facts, f"{service_type.value}es")

            if len(service_pairs) == 0:
                self.debug("  no users control this type of service, skipping")
                continue

            for service_pair in service_pairs:
                self.debug(f"  * {service_type.value}: {service_pair.name} ({service_pair.user})", secret=True)

                user = service_pair.user.lower()

                service_users = []
                if not strict:
                    user, domain = split_user_and_domain(user)
                    if user is not None:
                        service_users.append(user)
                        if domain is not None and domain != ".":
                            service_users.append(user + "@" + domain)
                            service_users.append(user + "@" + domain.split(".")[0])
                        if domain_name is not None:
                            service_users.append(user + "@" + domain_name)
                            service_users.append(user + "@" + domain_name.split(".")[0])

                else:
                    service_users.append(user)

                # de-dup the list
                service_users = list(set(service_users))

                if len(service_users) == 0:
                    self.debug(f"    no users control {service_type.value}s, skipping.")
                    continue

                self.debug(f"    users to check: {service_users}", secret=True)
                for service_user in service_users:
                    self.debug(f"    . {service_user}", secret=True)
                    if service_user in users:
                        record_uid = users[service_user]
                        self.debug(f"      found user {service_user} for {service_type.value}", secret=True)

                        # Get the ACL edge from the cache.
                        # If not there load it from the graph.
                        # If not in the graph, create it, and cache it for the next time.
                        acl, record_key_bytes = acl_cache.get(record_uid, (None, None))
                        if acl is None:
                            acl = self.get_acl(infra_machine_content.record_uid, record_uid)
                            if acl is None:
                                acl = UserAcl.default()
                            record = self.record_lookup_func(record_uid, context=self.context)  # type: NormalizedRecord
                            record_key_bytes = record.record_key_bytes
                            acl_cache[record_uid] = (acl, record_key_bytes)
                            acl_md5_cache[record_uid] = acl.md5(record_key_bytes)

                            # Remove all the items marked as discovery.
                            self.clear_discovery_service_names(acl, record_key_bytes)

                        acl.controls_services = True
                        self.add_service_name(acl,
                                              service_name=service_pair.name,
                                              service_type=service_type,
                                              record_key_bytes=record_key_bytes,
                                              via_discovery=True)

        # Update the ACL for the machine.
        for record_uid, acl_tuple in acl_cache.items():
            new_acl, record_key_bytes = acl_tuple
            if new_acl.md5(record_key_bytes) != acl_md5_cache[record_uid]:
                self.set_acl(resource_uid=infra_machine_content.record_uid,
                             user_uid=record_uid,
                             acl=new_acl)
        acl_cache.clear()
        acl_md5_cache.clear()

    def _get_resource_info(self,
                           record_uid: str,
                           infra: Infrastructure,
                           record_types: Optional[List[str]] = None) -> Optional[NormalizedRecord]:

        """
        Find a resource, or user, in the Vault or in the Infrastructure graph.

        This will return a NormalizedRecord record.
        This doesn't mean the

        """

        # Check the record first; return a NormalizedRecord
        record = self.record_lookup_func(record_uid, context=self.context, allow_sm=False)  # type: NormalizedRecord
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
                 infra: Optional[Infrastructure] = None,
                 domain_name: Optional[str] = None,
                 netbios: Optional[str] = None,
                 **kwargs):
        """
        Map users to services on machines.

        This is driven by the record linking graph.

        :param infra: Instance of Infrastructure graph.
        :param domain_name: Domain name if there is a directory (i.e. example.com)
        :param netbios: NetBIOS of the domain controller (i.e. EXMAPLE)
        """

        self.debug("")
        self.debug("##########################################################################################")
        self.debug("# MAP USER TO MACHINE FOR SERVICES")
        self.debug("")

        # Load fresh

        created_infra = False

        try:
            if not infra:
                infra = Infrastructure(record=self.record, logger=self.logger, ksm=self._ksm, params=self._params)
                infra.load(sync_point=0)
                created_infra = True

            # The PAM Configuration record is the root vertex of the PAM/record linking graph.
            rl_configuration_vertex = self.record_linking.dag.get_root

            # At this level the vertex will either be a resource or a cloud user.
            for rl_resource_vertex in rl_configuration_vertex.has_vertices():

                self.debug(f"checking record {rl_resource_vertex.uid}")

                # This will get machine from the records or from infrastructure graph.
                # The results is a NormalizedRecord.
                machine_record = self._get_resource_info(record_uid=rl_resource_vertex.uid,
                                                         infra=infra,
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

                user_service_machine_vertex = self.record_linking.dag.get_vertex(infra_machine_content.record_uid)

                # If the resource does not exist in the user service graph, add a vertex and link it to the
                #  user service root/configuration vertex.
                if user_service_machine_vertex is None:
                    user_service_machine_vertex = self.record_linking.dag.add_vertex(
                        uid=infra_machine_content.record_uid,
                        name=infra_machine_content.name)

                # If the UserService resource vertex is not connect to root, connect it.
                if not self.record_linking.dag.get_root.has(user_service_machine_vertex):
                    user_service_machine_vertex.belongs_to_root(EdgeType.LINK)

                self.debug("-" * 40)
                self._connect_users_to_machine_services(
                    infra=infra,
                    infra_machine_content=infra_machine_content,
                    infra_machine_vertex=infra_machine_vertex,
                    domain_name=domain_name,
                    netbios=netbios)
                self.debug("-" * 40)

            self.save()

        except Exception as err:
            self.logger.error(f"could not map users to services: {err}")
            raise err

        finally:
            if created_infra:
                infra.close()
