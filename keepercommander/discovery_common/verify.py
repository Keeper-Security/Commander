from __future__ import annotations
import logging
from .infrastructure import Infrastructure
from .record_link import RecordLink
from .user_service import UserService
from .constants import PAM_MACHINE, PAM_DIRECTORY
from .utils import get_connection
from .types import DiscoveryObject
from ..keeper_dag import EdgeType
from ..keeper_dag.edge import DAGEdge
import re
import sys
from typing import Any, Optional, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from ..keeper_dag.vertex import DAGVertex


class Verify:

    """
    Check the graphs to make sure they are correct.

    This class will try to find problems with the graph, and then try to fix them, if flagged to do so.
    Checks are:

    * Check if the user services and task graph matches what Discovery found for the machine.
    * Check if the infrastructure graph has actual record for the record UID stored in the content.

    """

    USER_SERVICE = "User Service/Task Mapping"
    COLOR_RESET = "reset"
    OK = "ok"
    FAIL = "fail"
    UNK = "unk"
    TITLE = "title"

    def __init__(self, record: Any, logger: Optional[Any] = None, debug_level: int = 0,
                 output: Optional = None, colors: Optional[dict] = None, **kwargs):

        if output is None:
            output = sys.stderr
        self.output = output

        if colors is None:
            colors = {}
        self.colors = colors

        self.conn = get_connection(**kwargs)

        self.record = record

        # Load all the Infrastructure graph, starting at sync point 0
        self.infra = Infrastructure(record=record, logger=logger, debug_level=debug_level, fail_on_corrupt=False,
                                    **kwargs)
        self.infra.load(sync_point=0)

        self.record_link = RecordLink(record=record, logger=logger, debug_level=debug_level, fail_on_corrupt=False,
                                      **kwargs)
        self.user_service = UserService(record=record, logger=logger, debug_level=debug_level, fail_on_corrupt=False,
                                        **kwargs)

        if logger is None:
            logger = logging.getLogger()
        self.logger = logger
        self.debug_level = debug_level
        self.logger.debug(f"configuration uid is {self.conn.get_record_uid(record)}")

    def _msg(self, msg, color_name="NONE"):
        print(f"{self.colors.get(color_name, '')}{msg}{self.colors.get(Verify.COLOR_RESET, '')}", file=self.output)

    def run(self, fix: bool = False, lookup_record_func: Optional[Callable] = None):

        self.verify_infra_dag_connections(fix=fix)
        self.verify_user_service(fix=fix)
        if lookup_record_func is not None:
            self.verify_record_exists(fix=fix, lookup_record_func=lookup_record_func)

    @staticmethod
    def _split_user(user: str, hostname: Optional[str] = None, host: Optional[str] = None):
        domain = None
        if "\\" in user:
            domain, user = user.split("\\", 1)
            if domain == ".":
                domain = None
        elif "@" in user:
            user, domain = user.split("@", 1)
        if domain is not None and hostname is not None:
            domain = domain.lower()

            # Don't use IP addresses
            if re.match(r'\d+\.\d+.\d+\.\d+', host) is not None:
                host = None

            if hostname is not None:
                hostname = hostname.lower()
                if domain == hostname:
                    domain = None
                elif domain == hostname.split(".")[0]:
                    domain = None

            if host is not None:
                host = host.lower()
                if domain == host:
                    domain = None
                elif domain == host.split(".")[0]:
                    domain = None

        return user, domain

    def _find_infra_user_vertex(self, resource_vertex: DAGVertex, user: str, domain: Optional[str] = None) -> (
            Optional)[DAGVertex]:

        user = user.lower()
        resource_content = DiscoveryObject.get_discovery_object(resource_vertex)

        # If the domain is None, assume it a local user.
        if domain is None:
            self.logger.debug("    no domain, assume local user")
            for user_vertex in resource_vertex.has_vertices():
                content = DiscoveryObject.get_discovery_object(user_vertex)
                self.logger.debug(f"    * {content.name}, {content.item.user}")
                if content.name.lower() == user:
                    self.logger.debug("        MATCH")
                    return user_vertex
                hostname = None
                if resource_content.record_type == PAM_MACHINE:
                    hostname = resource_content.item.facts.name
                child_user, child_domain = self._split_user(
                    user=content.item.user,
                    hostname=hostname,
                    host=resource_content.item.host)
                if user == child_user and child_domain is None:
                    self.logger.debug("        MATCH")
                    return user_vertex
            return None

        self.logger.debug("    has domain, assume directory user")

        configuration_vertex = self.infra.get_configuration
        for vertex in configuration_vertex.has_vertices():
            content = DiscoveryObject.get_discovery_object(vertex)
            if content.record_type != PAM_DIRECTORY:
                continue
            if content.name.lower() == domain.lower():
                for user_vertex in vertex.has_vertices():
                    user_content = DiscoveryObject.get_discovery_object(user_vertex)
                    if user_content.name.lower() == user or user_content.item.user.lower() == user:
                        return user_vertex

        return None

    def _fix_user_service_acl(self, resource_content: DiscoveryObject, user_vertex: DAGVertex, acl_type: str,
                              fix: bool = False) -> bool:

        user_content = DiscoveryObject.get_discovery_object(user_vertex)
        user_record_uid = user_content.record_uid
        if user_record_uid is not None:
            acl = self.user_service.get_acl(resource_content.record_uid, user_record_uid)
            if acl is not None:
                flag = getattr(acl, acl_type)
                if flag is False:

                    self._msg(f"   - user {user_content.name}, {user_record_uid} is "
                              f"missing an ACL type {acl_type} to "
                              f"machine {resource_content.name}")
                    if fix is True:
                        self._msg(f"     added {acl_type} to the ACL between "
                                  f"user {user_content.name}, {user_record_uid} and "
                                  f"machine {resource_content.name}", color_name=Verify.OK)
                        setattr(acl, acl_type, True)
                        self.user_service.belongs_to(resource_content.record_uid, user_record_uid, acl=acl)
                        return True
                    else:
                        self._msg(f"     not fixing user", color_name=Verify.FAIL)
                else:
                    self.logger.debug(f"user service ACL does have is_service as True")
            else:
                self.logger.debug(f"there is no ACL between the user and the resource")
        else:
            self.logger.debug(f"use does not have a record yet")

        return False

    def _get_infra_configuration(self):

        # Check to make sure the user service graph exists.
        # The "UserService" instance should do this, but we want to make sure.
        if self.user_service.dag.has_graph is False:
            self.logger.debug("the user service graph contains no data")
            configuration_vertex = self.user_service.dag.get_root
            if configuration_vertex.uid != self.conn.get_record_uid(self.record):
                raise Exception("The user service graph root/con does not match ")

        return self.infra.get_configuration

    def verify_user_service(self, fix: bool = False):

        """

        """

        # STEP 1 - Make sure UserService graph matches Infrastructure

        self._msg("\nChecking if user service/task graph matches infrastructure.\n\n", color_name="title")

        were_fixes = False

        infra_configuration = self._get_infra_configuration()
        for resource_vertex in infra_configuration.has_vertices():

            resource_content = DiscoveryObject.get_discovery_object(resource_vertex)

            if resource_content.record_type != PAM_MACHINE or resource_content.record_uid is None:
                self._msg(f" * Machine {resource_content.name} does not have record UID, yet.",
                          color_name=Verify.UNK)
                continue

            user_service_resource_vertex = self.user_service.dag.get_vertex(resource_content.record_uid)
            if user_service_resource_vertex is None:
                self._msg(f" * Machine {resource_content.name} does not have a vertex in the user service graph")
                if fix is True:
                    user_service_resource_vertex = self.user_service.dag.add_vertex(resource_content.record_uid)

                    record_uid = self.conn.get_record_uid(self.record)
                    self.user_service.belongs_to(record_uid, resource_content.record_uid, acl=None)

                    self._msg(f"   added vertex for machine {resource_content.name}, and linked "
                              " to configuration.", color_name=Verify.OK)
                else:
                    self._msg(f"   not fixing, skip this resource.", color_name=Verify.FAIL)
                    continue

            if self.user_service.resource_has_link(resource_content.record_uid) is False:
                self._msg(f" * Machine {resource_content.name} is not linked to the configuration.")

                if fix is True:
                    user_service_resource_vertex.belongs_to(self.user_service.dag.get_root, edge_type=EdgeType.LINK)
                    self._msg(f"   linking machine {resource_content.name} to the configuration",
                              color_name=Verify.OK)
                else:
                    self._msg(f"   not fixing, skip this resource.", color_name=Verify.FAIL)
                    continue

            self.logger.debug(f"found machine: {resource_content.name}, {resource_content.record_uid}")

            for item in resource_content.item.facts.services:
                user, domain = self._split_user(item.user,
                                                hostname=resource_content.item.facts.name,
                                                host=resource_content.item.host)
                self.logger.debug(f"found service: {item.name}, {user}, {domain}")
                user_vertex = self._find_infra_user_vertex(resource_vertex, user, domain)
                if user_vertex is not None:
                    if self._fix_user_service_acl(resource_content, user_vertex, "is_service", fix=fix) is True:
                        were_fixes = True
                else:
                    self.logger.debug(f"could not find user for the service on the machine")

            for item in resource_content.item.facts.tasks:
                user, domain = self._split_user(item.user,
                                                hostname=resource_content.item.facts.name,
                                                host=resource_content.item.host)
                self.logger.debug(f"  found task: {item.name}, {user}, {domain}")
                user_vertex = self._find_infra_user_vertex(resource_vertex, user, domain)
                if user_vertex is not None:
                    if self._fix_user_service_acl(resource_content, user_vertex, "is_task", fix=fix) is True:
                        were_fixes = True
                else:
                    self.logger.debug(f"    could not find user for the service on the machine")

        if were_fixes is True:
            self._msg("\nSaving fixed user service/task graph.\n\n", color_name=Verify.OK)
            self.user_service.save()

    def verify_record_exists(self, lookup_record_func: Callable, fix: bool = False):
        """
        This will verify that a record exists for infrastructure content.
        """

        self._msg("\nChecking if infrastructure records exist.\n\n", color_name=Verify.TITLE)

        infra_configuration = self._get_infra_configuration()

        def _check(vertex: DAGVertex, indent: int = 0) -> bool:

            fixes = False
            pad = "".ljust(4 * indent, ' ')

            if not vertex.active:
                return False
            if vertex.has_data is True:
                content = DiscoveryObject.get_discovery_object(vertex)

                self._msg(f"{pad}* {content.record_uid or 'NA'}, {content.title}", color_name="title")

                if content.record_uid is not None:
                    record = lookup_record_func(content.record_uid)
                    if record is None:
                        self._msg(f"{pad}  did not have a record.", color_name="fail")
                        if fix is True:
                            content.record_uid = None
                            vertex.add_data(content)
                            self._msg(f"{pad}  remove record uid from graph.", color_name=Verify.OK)
                            fixes = True
                else:
                    self._msg(f"{pad}  has no record uid.", color_name="unk")

            for next_vertex in vertex.has_vertices():
                if next_vertex.uid == vertex.uid:
                    self._msg(f"{pad}  * this vertex loops to itself!", color_name=Verify.FAIL)
                    continue
                edge_type = next_vertex.get_highest_edge_version(vertex.uid)
                if edge_type != EdgeType.DELETION:
                    if _check(next_vertex,  indent=indent + 1) is True:
                        fixes = True

            return fixes

        were_fixes = _check(infra_configuration, indent=0)

        if were_fixes is True:
            self._msg("\nSaving fixed record uids in infrastructure graph.\n\n", color_name=Verify.OK)
            self.infra.save(delta_graph=False)

    def verify_infra_dag_connections(self, fix: bool = False):

        self._msg("\nChecking if infrastructure vertex refs loop.\n", color_name=Verify.TITLE)

        def _check(vertex: DAGVertex, indent: int = 0):
            pad = "".ljust(4 * indent, ' ')

            fixes = False

            text = ""
            if vertex.active is False:
                text += f"(Inactive) "
            elif vertex.corrupt is True:
                text += f"{self.colors.get(Verify.FAIL)}Corrupt{self.colors.get(Verify.COLOR_RESET, '')}"
            elif vertex.has_data is True:
                content = DiscoveryObject.get_discovery_object(vertex)
                text += content.title

            self._msg(f"{pad}checking {vertex.uid}; {text}")
            for edge in vertex.edges:  # type: DAGEdge
                if edge.edge_type == EdgeType.DATA:
                    self._msg(f"{pad}  * found data edge")
                else:
                    self._msg(f"{pad}  * edge {edge.edge_type} to {edge.head_uid} (parent/belongs_to)")
                    if edge.head_uid == vertex.uid:
                        if edge.edge_type == EdgeType.DELETION:
                            self._msg(f"{pad}  * found DELETION of DATA edge")
                            continue
                        self._msg(f"{pad}  * vertex as a non-DATA edge looping to self", color_name=Verify.FAIL)
                        if fix is True:
                            self._msg(f"{pad}  * deleting key", color_name=Verify.OK)
                            fixes = True
                            edge.delete()

            # Get all the child vertices, allow self ref, so we can delete it if not already deleted.
            for next_vertex in vertex.has_vertices(allow_self_ref=True):
                if next_vertex.uid == vertex.uid:
                    version, edge = next_vertex.get_highest_edge_version(vertex.uid)
                    if edge.edge_type == EdgeType.DELETION:
                        continue
                    else:
                        self._msg(f"{pad}    * next vertex references itself", color_name=Verify.FAIL)
                        if fix is True:
                            self._msg(f"{pad}    * delete this reference", color_name=Verify.OK)
                            fixes = True
                            edge.delete()
                        else:
                            self._msg(f"{pad}  * not fixing, however skipping to prevent loop",
                                      color_name=Verify.FAIL)
                            continue

                self._msg(f"{pad}  next vertex is {next_vertex.uid}")
                if _check(next_vertex, indent + 1) is True:
                    fixes = True

            return fixes

        configuration = self.infra.get_configuration
        were_fixes = _check(configuration, 0)

        if were_fixes is True:
            self._msg("\nSaving graph vertices references.\n\n", color_name=Verify.OK)
            self.infra.save(delta_graph=False)
