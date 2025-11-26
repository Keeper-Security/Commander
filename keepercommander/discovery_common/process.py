from __future__ import annotations
import logging
import os
from .constants import PAM_DIRECTORY, PAM_USER, VERTICES_SORT_MAP, LOCAL_USER
from .jobs import Jobs
from .infrastructure import Infrastructure
from .record_link import RecordLink
from .user_service import UserService
from .rule import Rules
from .types import (DiscoveryObject, DiscoveryUser, RecordField, RuleActionEnum, UserAcl,
                    PromptActionEnum, PromptResult, BulkRecordAdd, BulkRecordConvert, BulkProcessResults,
                    DirectoryInfo, NormalizedRecord)
from .utils import value_to_boolean, split_user_and_domain
from .dag_sort import sort_infra_vertices
from ..keeper_dag import EdgeType
from ..keeper_dag.crypto import bytes_to_urlsafe_str
import hashlib
from typing import Any, Callable, List, Optional, Union, TYPE_CHECKING


if TYPE_CHECKING:
    from ..keeper_dag.vertex import DAGVertex
    DirectoryResult = Union[DirectoryInfo, List]
    DirectoryUserResult = Union[NormalizedRecord, DAGVertex]


class QuitException(Exception):
    """
    This exception used when the user wants to stop processing of the results, before the end.
    """
    pass


class UserNotFoundException(Exception):
    """
    We could not find the user.
    """
    pass


class DirectoryNotFoundException(Exception):
    """
    We could not find the directory.
    """
    pass


class NoDiscoveryDataException(Exception):
    """
    This exception is thrown when there is no discovery data.
    This is not an error.
    There is just nothing to do.
    """
    pass


class Process:
    # Warn when bulk record lists exceed this size (potential memory issue)
    BULK_LIST_WARNING_THRESHOLD = 10000
    # Hard limit for bulk record lists (safety mechanism)
    BULK_LIST_MAX_SIZE = 50000

    def __init__(self, record: Any, job_id: str, logger: Optional[Any] = None, debug_level: int = 0, **kwargs):
        self.job_id = job_id
        self.record = record

        env_debug_level = os.environ.get("PROCESS_GS_DEBUG_LEVEL")
        if env_debug_level is not None:
            debug_level = int(env_debug_level)

        # Remember what passed in a kwargs
        self.passed_kwargs = kwargs

        self.jobs = Jobs(record=record, logger=logger, debug_level=debug_level, **kwargs)
        self.job = self.jobs.get_job(self.job_id)

        # These are lazy load, so the graph is not loaded here.
        self.infra = Infrastructure(record=record, logger=logger,
                                    debug_level=debug_level,
                                    fail_on_corrupt=False,
                                    **kwargs)
        self.record_link = RecordLink(record=record, logger=logger, debug_level=debug_level, **kwargs)
        self.user_service = UserService(record=record, logger=logger, debug_level=debug_level, **kwargs)

        # This is the root UID for all graphs; get it from one of them.
        self.configuration_uid = self.jobs.dag.uid

        if logger is None:
            logger = logging.getLogger()
        self.logger = logger
        self.debug_level = debug_level

        self.logger.debug(f"discovery process is using configuration uid {self.configuration_uid}")

    def close(self):
        """
        Clean up resources held by this Process instance.
        Releases all DAG instances and connections to prevent memory leaks.
        """

        if self.jobs:
            self.jobs.close()
            self.jobs = None
        if self.infra:
            self.infra.close()
            self.infra = None
        if self.record_link:
            self.record_link.close()
            self.record_link = None
        if self.user_service:
            self.user_service.close()
            self.user_service = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup."""
        self.close()
        return False

    def __del__(self):
        self.close()

    @staticmethod
    def get_key_field(record_type: str) -> str:
        return VERTICES_SORT_MAP.get(record_type)["key"]

    @staticmethod
    def set_user_based_ids(configuration_uid: str, content: DiscoveryObject, parent_vertex: Optional[DAGVertex] = None):

        if configuration_uid is None:
            raise ValueError("The configuration UID is None when trying to create an id and UID for user.")

        if content.item.user is None:
            raise Exception("The user name is blank. Cannot make an ID for the user.")

        parent_content = DiscoveryObject.get_discovery_object(parent_vertex)
        object_id = content.item.user
        if "\\" in content.item.user:
            # Remove the domain name from the user.
            # [0] will be the domain, [1] will be the user.
            object_id = object_id.split("\\")[1]
        if parent_content.record_type == PAM_DIRECTORY:
            domain = parent_content.name
            if object_id.endswith(domain) is False:
                object_id += f"@{domain}"
        else:
            object_id += parent_content.id

        content.id = object_id

        uid = configuration_uid + content.object_type_value + object_id
        m = hashlib.sha256()
        m.update(uid.lower().encode())

        content.uid = bytes_to_urlsafe_str(m.digest()[:16])

    def populate_admin_content_ids(self, content: DiscoveryObject, parent_vertex: Optional[DAGVertex] = None):

        """
        Populate the id and uid attributes for content.
        """

        return self.set_user_based_ids(self.configuration_uid, content, parent_vertex)

    def get_keys_for_vertex(self, vertex: DAGVertex) -> List[str]:
        """
        For the vertex
        :param vertex:
        :return:
        """

        content = DiscoveryObject.get_discovery_object(vertex)
        key_field = self.get_key_field(content.record_type)
        keys = []
        if key_field == "host_port":
            if content.item.port is not None:
                if content.item.host is not None:
                    keys.append(f"{content.item.host}:{content.item.port}".lower())
                if content.item.ip is not None:
                    keys.append(f"{content.item.ip}:{content.item.port}".lower())
        elif key_field == "host":
            if content.item.host is not None:
                keys.append(content.item.host.lower())
            if content.item.ip is not None:
                keys.append(content.item.ip.lower())
        elif key_field == "user":
            if content.parent_record_uid is not None:
                if content.item.user is not None:
                    keys.append(f"{content.parent_record_uid}:{content.item.user}".lower())
                if content.item.dn is not None:
                    keys.append(f"{content.parent_record_uid}:{content.item.dn}".lower())
        return keys

    def _update_with_record_uid(self, record_cache: dict, current_vertex: DAGVertex):

        # If the current vertex is not active, then return.
        # It won't have a DATA edge.
        if current_vertex.active is False:
            return

        for vertex in current_vertex.has_vertices():

            # Skip if the vertex is not active.
            # It won't have a DATA edge.
            if vertex.active is False or vertex.has_data is False:
                continue

            # Don't worry about "item" class type
            content = DiscoveryObject.get_discovery_object(vertex)

            # If we are ignoring the object, then skip.
            if content.action_rules_result == RuleActionEnum.IGNORE.value or content.ignore_object is True:
                continue
            elif content.record_uid is not None:
                cache_keys = self.get_keys_for_vertex(vertex)
                for key in cache_keys:

                    # If we find an item in the cache, update the vertex with the record UID
                    if key in record_cache.get(content.record_type):
                        content.record_uid = record_cache.get(content.record_type).get(key)
                        vertex.add_data(content)
                        break

            # Process the vertices that belong to the current vertex.
            self._update_with_record_uid(
                record_cache=record_cache,
                current_vertex=vertex,
            )

    @staticmethod
    def _prepare_record(record_prepare_func: Callable,
                        bulk_add_records: List[BulkRecordAdd],
                        content: DiscoveryObject,
                        parent_content: DiscoveryObject,
                        vertex: DAGVertex,
                        context: Optional[Any] = None) -> DiscoveryObject:
        """
        Prepare a record to be added.

        :param record_prepare_func:
        :param bulk_add_records:
        :param content:
        :param parent_content:
        :param vertex:
        :param context:
        :return:
        """

        record_to_be_added, record_uid = record_prepare_func(
            content=content,
            context=context
        )
        if record_to_be_added is None:
            raise Exception("Did not get prepare record.")
        if record_uid is None:
            raise Exception("The prepared record did not contain a record UID.")

        parent_record_uid = parent_content.record_uid
        if parent_content.object_type_value == "providers":
            parent_record_uid = None
        bulk_add_records.append(
            BulkRecordAdd(
                title=content.title,
                record=record_to_be_added,
                record_type=content.record_type,
                record_uid=record_uid,
                parent_record_uid=parent_record_uid,
                shared_folder_uid=content.shared_folder_uid
            )
        )

        content.record_uid = record_uid
        content.parent_record_uid = parent_content.record_uid
        vertex.add_data(content)

        return content

    def _default_acl(self,
                     discovery_vertex: DAGVertex,
                     content: DiscoveryObject,
                     discovery_parent_vertex: DAGVertex) -> UserAcl:
        # Check to see if this user already belongs to another record vertex, or belongs to this one.
        belongs_to = False
        is_admin = False
        is_iam_user = False

        parent_content = DiscoveryObject.get_discovery_object(discovery_parent_vertex)

        # User record the already exists.
        # This means the vertex has a record UID, doesn't mean it exists in the vault.
        # It may have been added during this processing.
        if content.record_exists is False:
            belongs_to = True

            # Is this user the admin for the resource?
            if parent_content.access_user is not None:
                # If this user record's user matches the user that was used to log into the parent resource,
                #   then this user is the admin for the parent resource.
                if parent_content.access_user.user == content.item.user:
                    is_admin = True

        # User record does not exist.
        else:
            belongs_to_record_vertex = self.record_link.acl_has_belong_to_vertex(discovery_vertex)

            # If the user doesn't belong to any other vertex, it will be long the parent resource.
            if belongs_to_record_vertex is None:
                self.logger.debug("  user vertex does not belong to another resource vertex")
                belongs_to = True

            else:
                parent_record_vertex = self.record_link.get_record_uid(discovery_parent_vertex)
                if parent_record_vertex is not None:
                    if belongs_to_record_vertex == parent_record_vertex:
                        self.logger.debug("  user vertex already belongs to the parent resource vertex")
                        belongs_to = True
                else:
                    self.logger.debug("  user vertex does not belong to any other resource vertex")

        # If the parent resource is a provider, then this user is an IAM user.
        if parent_content.object_type_value == "providers":
            is_iam_user = True

        acl = UserAcl.default()
        acl.belongs_to = belongs_to
        acl.is_admin = is_admin
        acl.is_iam_user = is_iam_user

        return acl

    def _directory_exists(self, domain: str, directory_info_func: Callable, context: Any) -> Optional[DirectoryResult]:

        """
        This method will find the directory in the Infrastructure graph or in the Vault.

        If the domain contains more than one DC, the domain will be split and the full DC will be search and then
          the first DC.
        For example, if EXAMPLE.COM is passed in for the domain, EXAMPLE.COM and EXAMPLE will be searched for.

        The Infrastructure graph will be searched first.
        If nothing is found, the Vault will be searched.

        If the directory is found in the graph, a list if directory vertices will be returned.
        If the directory is found in the Vault, a DirectoryInfo instance will be returned.
        If nothing is found, None is returned.

        The returned results can be passed to the _find_directory_user method.

        """

        domains = [domain]
        if "." in domains:
            domains.append(domain.split(".")[0])

        self.logger.debug(f"search for directories: {', '.join(domains)}")

        # Some providers provider directory type services.
        # They can also provide mulitple domains
        provider_vertices = self.infra.dag.search_content({
            "record_type": ["pamAzureConfiguration", "pamDomainConfiguration"],
        }, ignore_case=True)
        found_provider_directories = []
        for provider_vertex in provider_vertices:
            content = DiscoveryObject.get_discovery_object(provider_vertex)
            found = False
            for domain in domains:
                for provider_domain in content.item.info.get("domains", []):
                    if domain.lower() in provider_domain.lower():
                        found = True
                        break
                if found is True:
                    break
            if found is True:
                found_provider_directories.append(provider_vertex)
        if len(found_provider_directories) > 0:
            return found_provider_directories

        # Check the graph first.
        # `search_content` does an "is in" type match; so subdomains should match a full domain
        # pamDomainConfiguration is an edge case because it's name in the record is the domain name.
        for domain_name in domains:
            directories = self.infra.dag.search_content({
                "record_type": ["pamDirectory", "pamDomainConfiguration"],
                "name": domain_name
            }, ignore_case=True)

            self.logger.debug(f"found {len(directories)} directories in the graph")

            # If we found directories, return the list of directory vertices.
            if len(directories) > 0:
                # Return vertices
                return directories

        # Check the vault secondly.
        for domain_name in domains:
            info = directory_info_func(domain=domain_name, skip_users=False, context=context)
            if info is not None:
                # If we found directories in the Vault, then return directory info
                # This will be an instance of DirectoryInfo
                return info

        return None

    def _find_directory_user(self,
                             results: DirectoryResult,
                             record_lookup_func: Callable,
                             context: Any,
                             find_user: Optional[str] = None,
                             find_dn: Optional[str] = None) -> Optional[DirectoryUserResult]:

        # If the passed in results were a DirectoryInfo then check the Vault for users.
        if isinstance(results, DirectoryInfo) is True:
            self.logger.debug("search for directory user from vault records")
            self.logger.debug(f"have {len(results.directory_user_record_uids)} users")
            for user_record_id in results.directory_user_record_uids:
                record = record_lookup_func(record_uid=user_record_id, context=context)  # type: NormalizedRecord
                if record is not None:
                    found = None
                    self.logger.debug(f"find user {find_user}, dn {find_dn}")
                    if find_user is not None:
                        found = record.find_user(find_user)
                    if found is None and find_dn is not None:
                        found = record.find_dn(find_dn)
                    return found
            return None

        # Else it was a list of directory vertices, check its children for the users.
        else:
            self.logger.debug("search for directory user from the graph")
            for directory_vertex in results:  # type: DAGVertex
                for user_vertex in directory_vertex.has_vertices():
                    user_content = DiscoveryObject.get_discovery_object(user_vertex)

                    # We should only have pamUser vertices.
                    if user_content.record_type != PAM_USER:
                        self.logger.debug(f"in find directory user, a vertex {user_vertex.uid} was not a pamUser, "
                                          f"was {user_content.record_type}.")
                        continue

                    found_vertex = None
                    if find_user is not None:
                        user, domain = split_user_and_domain(find_user)
                        if user_content.item.user.lower() == user.lower():
                            found_vertex = user_vertex
                        elif user_content.item.user.lower() == find_user.lower():
                            found_vertex = user_vertex
                    elif find_dn is not None:
                        if user_content.item.dn.lower() == find_dn.lower():
                            found_vertex = user_vertex

                    if found_vertex is not None:
                        return found_vertex
        return None

    def _record_link_directory_users(self,
                                     directory_vertex: DAGVertex,
                                     directory_content: DiscoveryObject,
                                     directory_info_func: Callable,
                                     context: Optional[Any] = None):

        """
        Link user record to directory when adding a new directory.

        When adding a new directory, there may be other directories for the same domain.
        We need to link existing directory users, of the same domain, to this new directory.

        """

        self.logger.debug(f"resource is directory; connect users to this directory for {directory_vertex.uid}")

        record_link = context.get("record_link")  # type: RecordLink

        # Get the directory user record UIDs from the vault that belong to directories using the same domain.
        directory_info = directory_info_func(
            domain=directory_content.name,
            context=context
        )  # type: DirectoryInfo
        if directory_info is None:
            self.logger.debug("there were no directory record for this domain")
            directory_info = DirectoryInfo()

        user_record_uids = directory_info.directory_user_record_uids

        self.logger.debug(f"found {len(directory_info.directory_user_record_uids)} users"
                          f"from {len(directory_info.directory_record_uids)} directories.")

        # Check our current discovery data.
        # This is a delta, it will not contain discovery from prior runs.
        # This will only contain objects in this run.
        # Make sure the object is a directory and the domain is the same.
        # Also make sure there is a record UID; it might not be added yet.
        self.logger.debug("finding directories in discovery vertices")
        for parent_vertex in directory_vertex.belongs_to_vertices():
            self.logger.debug(f"find directories under {parent_vertex.uid}")
            for other_directory_vertex in parent_vertex.has_vertices():
                if other_directory_vertex.uid == directory_vertex.uid:
                    self.logger.debug("  skip this directory, it's the current one")
                    continue
                other_directory_content = DiscoveryObject.get_discovery_object(other_directory_vertex)
                self.logger.debug(f"{other_directory_content.record_type}, {other_directory_content.name}, "
                                  f"{other_directory_content.uid}, {other_directory_content.record_uid}")
                if (other_directory_content.record_type == PAM_DIRECTORY
                        and other_directory_content.name == directory_content.name
                        and other_directory_content.record_uid is not None):
                    self.logger.debug(f"check {other_directory_content.uid} for users")
                    for user_vertex in other_directory_vertex.has_vertices():
                        user_content = DiscoveryObject.get_discovery_object(user_vertex)
                        self.logger.debug(f" * {user_vertex.uid}, {user_content.record_uid}")
                        if user_content.record_uid is not None and user_content.record_uid not in user_record_uids:
                            user_record_uids.append(user_content.record_uid)
                        del user_content
                del other_directory_content

        self.logger.debug(f"found {len(user_record_uids)} user to connect to directory")

        # Make sure there is a link from the user record to the directory record.
        # We also might need to make a KEY edge from the user to the directory if one does not exist.
        for record_uid in user_record_uids:
            if record_link.get_acl(record_uid,  directory_content.record_uid) is None:
                record_link.belongs_to(record_uid, directory_content.record_uid, acl=UserAcl.default())

            # Check if the user vertex has a KEY edge to the directory_vertex.
            found_vertices = directory_vertex.dag.search_content({"record_uid": record_uid})
            if len(found_vertices) == 1:
                user_vertex = found_vertices[0]
                if user_vertex.get_edge(directory_vertex, EdgeType.KEY) is None:
                    self.logger.debug(f"adding a KEY edge from the user {user_vertex.uid} to {directory_vertex.uid}")
                    user_vertex.belongs_to(directory_vertex, EdgeType.KEY)
            else:
                self.logger.debug("could not find user vertex")

    def _record_link_user_to_directories(self,
                                         directory_vertex: DAGVertex,
                                         directory_content: DiscoveryObject,
                                         user_content: DiscoveryObject,
                                         directory_info_func: Callable,
                                         context: Optional[Any] = None):

        """
        Connect a user to all the directories for a domain.

        Directories may be in the vault or in the discovery graph.
        The first step is to get all vault directories.

        """

        self.logger.debug("resource is directory and we are a user; handle record links to others")

        record_link = context.get("record_link")  # type: RecordLink

        # Get the directory user record UIDs from the vault that belong to directories using the same domain.
        # We can skip getting directory users.
        directory_record_uids = []
        directory_info = directory_info_func(
            domain=directory_content.name,
            skip_users=True,
            context=context
        )  # type: DirectoryInfo
        if directory_info is not None:
            directory_record_uids = directory_info.directory_record_uids

        self.logger.debug(f"found {len(directory_record_uids)} directories in records.")

        # Check our current discovery data.
        # This is a delta, it will not contain discovery from prior runs.
        # This will only contain objects in this run.
        # Make sure the object is a directory and the domain is the same.
        # Also make sure there is a record UID; it might not be added yet.
        for parent_vertex in directory_vertex.belongs_to_vertices():
            self.logger.debug("finding directories in discovery vertices")
            for child_vertex in parent_vertex.has_vertices():
                try:
                    other_directory_content = DiscoveryObject.get_discovery_object(child_vertex)
                    self.logger.debug(f"{other_directory_content.record_type}, {other_directory_content.name}, "
                                      f"{directory_content.name}, {other_directory_content.record_uid}")
                    if (other_directory_content.record_type != PAM_DIRECTORY or
                            other_directory_content.name != directory_content.name):
                        continue
                    if (other_directory_content.record_uid is not None and
                            other_directory_content.record_uid not in directory_record_uids):
                        self.logger.debug(f" * adding {other_directory_content.record_uid}")
                        directory_record_uids.append(other_directory_content.record_uid)
                except Exception as err:
                    self.logger.debug(f"could not link user to directory {directory_content.name}: {err}")

        self.logger.debug(f"found {len(directory_record_uids)} directories in records and discovery data.")

        for directory_record_uid in directory_record_uids:
            if record_link.get_acl(user_content.record_uid, directory_record_uid) is None:
                record_link.belongs_to(user_content.record_uid, directory_record_uid, acl=UserAcl.default())

    def _find_admin_directory_user(self,
                                   domain: str,
                                   admin_acl: UserAcl,
                                   directory_info_func: Callable,
                                   record_lookup_func: Callable,
                                   context: Any,
                                   user: Optional[str] = None,
                                   dn: Optional[str] = None) -> Optional[str]:

        # Check any directories for the domain exist.
        results = self._directory_exists(domain=domain,
                                         directory_info_func=directory_info_func,
                                         context=context)

        if results is not None:
            # Find the user (clean of domain) or DN in the found directories.
            directory_user = self._find_directory_user(results=results,
                                                       record_lookup_func=record_lookup_func,
                                                       context=context,
                                                       find_user=user,
                                                       find_dn=dn)
            if directory_user is not None:

                # If we got a normalized record, then a Vault record exists.
                # No need to create a record, just link, belongs_to is False
                # Since we are using records, just the belongs_to method instead of
                #   discovery_belongs_to.
                if isinstance(directory_user, NormalizedRecord) is True:
                    admin_acl.belongs_to = False
                    return directory_user.record_uid
                else:
                    admin_content = DiscoveryObject.get_discovery_object(directory_user)

                    # If not a PAM User, then this is bad.
                    if admin_content.record_type != PAM_USER:
                        self.logger.warning(
                            f"found record type {admin_content.record_type} instead of "
                            f"pamUser for record UID {admin_content.record_uid}")
                        return None

                    # If the record UID exists, then connect the directory user to the
                    #   resource.
                    if admin_content.record_uid is not None:
                        admin_acl.belongs_to = False
                        return admin_content.record_uid
            else:
                raise UserNotFoundException(f"Could not find the directory user in domain {domain}")
        else:
            raise DirectoryNotFoundException(f"Could not find the directory for domain {domain}")

    def _process_auto_add_level(self,
                                current_vertex: DAGVertex,
                                bulk_add_records: List[BulkRecordAdd],
                                bulk_convert_records: List[BulkRecordConvert],
                                record_lookup_func: Callable,
                                record_prepare_func: Callable,
                                directory_info_func: Callable,
                                record_cache: dict,
                                smart_add: bool = False,
                                add_all: bool = False,
                                context: Optional[Any] = None):

        """
        This method will add items to the bulk_add_records queue to be added by the client.

        Items are added because:
          * Smart Add is enabled, and the resource was logged into with credentials.
          * The rule engine flagged an item as ADD

        :param current_vertex: The current/parent discovery vertex.
        :param bulk_add_records: List of records to be added.
        :param bulk_convert_records: List of existing records to be covert to this gateway.
        :params record_lookup_func: A function to lookup records to see if they exist.
        :param record_prepare_func: Function to convert content into an unsaved record.
        :param directory_info_func: Function to lookup directories.
        :param record_cache:
        :param smart_add: Add the resource record if the admin exists.
        :param add_all: Just add the record. This is not the params from Commander.
        :param context: Client context; could be anything.
        :return:
        """

        if current_vertex.active is False:
            self.logger.debug(f"vertex {current_vertex.uid} is not active, skip")
            return

        # Check if this vertex has a record.
        # We cannot add child vertices to a vertex that does not have a record.
        current_content = current_vertex.content_as_object(DiscoveryObject)
        if current_content.record_uid is None:
            self.logger.debug(f"vertex {current_content.uid} does not have a record id")
            return

        self.logger.debug(f"Current Vertex: {current_content.record_type}, {current_vertex.uid}, "
                          f"{current_content.name}, smart add {smart_add}, add all {add_all}")

        # Sort all the vertices under the current vertex.
        # Return a dictionary where the record type is the key.
        # The value will be an array of vertices of the specific record type.
        record_type_to_vertices_map = sort_infra_vertices(current_vertex, logger=self.logger)

        # Process the record type by their map order in ascending order.
        for record_type in sorted(record_type_to_vertices_map, key=lambda i: VERTICES_SORT_MAP[i]['order']):
            self.logger.debug(f"  processing {record_type}")
            for vertex in record_type_to_vertices_map[record_type]:

                content = DiscoveryObject.get_discovery_object(vertex)
                self.logger.debug(f"    child vertex {vertex.uid}, {content.name}")

                # If we are going to add an admin user, this is the default ACL
                # This is for the smart add feature
                admin_acl = UserAcl.default()
                admin_acl.is_admin = True

                # This ACL is None for resource, and populated for users.
                default_acl = None
                if content.record_type == PAM_USER:
                    default_acl = self._default_acl(
                        discovery_vertex=vertex,
                        content=content,
                        discovery_parent_vertex=current_vertex)

                # Check for a vault record, if it exists.
                # Default to the DAG content.
                # Check the bulk_add_records list, to make sure it is not in the list of record we are about to add.
                # We are doing this because the record might be an active directory user, that we have
                #  not created a record for yet, however it might have been assigned a record UID from a prior prompt.

                existing_record = content.record_exists
                if record_lookup_func is not None:
                    check_the_vault = True
                    for item in bulk_add_records:
                        if item.record_uid == content.record_uid:
                            self.logger.debug(f"    record is in the bulk add list, do not check the vault if exists")
                            check_the_vault = False
                            break
                    if check_the_vault is True:
                        existing_record = record_lookup_func(record_uid=content.record_uid, context=context) is not None
                        self.logger.debug(f"    record exists in the vault: {existing_record}")
                else:
                    self.logger.debug(f"    record lookup function not defined, record existing: {existing_record}")

                # Determine if we are going to add the item.
                # If the item has a record UID already, we don't need to add.
                add_record = False
                add_all_users = False
                if content.record_exists is False:

                    #################################################################################################
                    #
                    # RULE ENGINE ADD

                    if content.action_rules_result == RuleActionEnum.ADD.value:
                        self.logger.debug(f"    vertex {vertex.uid} had an ADD result for the rule engine, auto add")
                        add_record = True

                    #################################################################################################
                    #
                    # SMART ADD

                    # If we are using smart add and the there was an admin user, add it.
                    elif smart_add is True and content.access_user is not None and content.record_type != PAM_USER:
                        self.logger.debug(f"    resource has credentials, and using smart add")
                        add_record = True
                        add_all_users = True

                    #################################################################################################
                    #
                    # ADD ALL FLAG (not Commander's)

                    # If add_all is set, then add it.
                    # This is normally used with smart_add to add the resource's users.
                    elif add_all is True:
                        # If the current content/parent is not a Directory
                        #   and the content is a User and the source is not 'local' user,
                        #   then don't add the user.
                        # We don't want an AD user to belongs_to a machine.
                        if (current_content.record_type != PAM_DIRECTORY
                                and content.record_type == PAM_USER
                                and content.item.source != LOCAL_USER):
                            add_record = False
                        else:
                            self.logger.debug(f"    items is a user, add all is True, adding record")
                            add_record = True

                if add_record is True:

                    # If we can create an admin user record, then the admin_user_record_uid will be populated.
                    admin_user_record_uid = None
                    admin_content = None
                    admin_vertex = None

                    # If this is a resource, then auto add the admin user if one exists.
                    # In this scenario ...
                    #   There is a rule to auto add.
                    #   A credential was passed to discovery and it worked.
                    #   Along with the resource, auto create the admin user.
                    # First we need to make sure the current record type is a resource and logged in.
                    if smart_add is True and content.access_user is not None:

                        # Get the username and DN.
                        # Lowercase them for the comparison.
                        access_username_and_domain = content.access_user.user
                        access_username = access_username_and_domain
                        access_domain = None
                        if access_username_and_domain is not None:
                            access_username_and_domain = access_username_and_domain.lower()
                            access_username, access_domain = split_user_and_domain(access_username_and_domain)

                        # We want to pay attention to the admin source.
                        # The users from the user list might not contain a source.
                        # For example, Linux PAM that are remote users will not have a domain in their username.
                        admin_source = content.access_user.source

                        # If the admin source is the current directory name, then it local to the resource (directory).
                        if content.record_type == PAM_DIRECTORY and content.name == admin_source:
                            self.logger.debug("    change source to local for directory user")
                            admin_source = LOCAL_USER

                        access_dn = content.access_user.dn
                        if access_dn is not None:
                            access_dn = access_dn.lower()

                        # Go through the users to find the administrative user.
                        found_user_in_discovery_user_list = False
                        for user_vertex in vertex.has_vertices():

                            user_content = DiscoveryObject.get_discovery_object(user_vertex)
                            if user_content.record_type != PAM_USER:
                                continue

                            # Get the user from the content.
                            # We want to use the full username and also one without the domain, if there is a domain.
                            user_and_domain = user_content.item.user
                            user = user_and_domain
                            domain = None
                            if user_and_domain is not None:
                                user_and_domain = user_and_domain.lower()
                                user, domain = split_user_and_domain(user_and_domain)
                                if user is None:
                                    continue

                            # Get the dn, if it exists.
                            dn = user_content.item.dn
                            if dn is not None:
                                dn = dn.lower()

                            if (access_username_and_domain == user_and_domain
                                    or access_username_and_domain == user
                                    or access_username == user
                                    or access_dn == dn):

                                self.logger.debug("    access user matches the current user")
                                self.logger.debug(f"    access user source is {user_content.item.source}")

                                # If the user has a record UID, it has already been created.
                                # This means the record already belongs to another resource, so belongs_to is False.
                                if user_content.record_uid is not None:
                                    self.logger.debug("    user has a record uid, add this user as admin")
                                    admin_acl.belongs_to = False
                                    admin_user_record_uid = user_content.record_uid
                                    found_user_in_discovery_user_list = True
                                    break

                                # Is this user a local user?
                                # If so prepare a record and link it. Since its local belongs_to is True
                                if admin_source == LOCAL_USER or admin_source is None:

                                    self.logger.debug("    user is new local user, add this user as admin")
                                    admin_acl.belongs_to = True
                                    admin_content = user_content
                                    admin_vertex = user_vertex
                                    found_user_in_discovery_user_list = True
                                    break

                                # The user is a remote user.
                                else:
                                    self.logger.debug("    check directory for remote user")
                                    domain = content.access_user.source
                                    if content.record_type == PAM_DIRECTORY:
                                        domain = content.name

                                    try:
                                        admin_user_record_uid = self._find_admin_directory_user(
                                            domain=domain,
                                            admin_acl=admin_acl,
                                            directory_info_func=directory_info_func,
                                            record_lookup_func=record_lookup_func,
                                            context=context,
                                            user=access_username,
                                            dn=access_dn
                                        )
                                        self.logger.debug("     found directory user for admin")
                                        found_user_in_discovery_user_list = True
                                    except (DirectoryNotFoundException, UserNotFoundException) as err:
                                        # Not an error.
                                        # Just could not find the directory or directory user.
                                        self.logger.debug(f"     did not find the directory user: {err}")

                        self.logger.debug("done checking user list")

                        # If the user_record_uid is None, and it's a domain user, and we didn't find a user
                        #   then there is chance that it's dirctory user not picked up while getting users in
                        #   discovery.
                        # This is similar to the remote user code above, except the access user was not found in
                        #   the user list.
                        if (found_user_in_discovery_user_list is False and admin_user_record_uid is None
                                and access_domain is not None):
                            self.logger.debug("could not find admin user in the user list, "
                                              "attempt to find in directory")
                            try:
                                admin_user_record_uid = self._find_admin_directory_user(
                                    domain=access_domain,
                                    admin_acl=admin_acl,
                                    directory_info_func=directory_info_func,
                                    record_lookup_func=record_lookup_func,
                                    context=context,
                                    user=access_username,
                                    dn=access_dn
                                )
                            except (DirectoryNotFoundException, UserNotFoundException):
                                # Not an error.
                                # Just could not find the directory or directory user.
                                pass

                    # Create the record if we are not using smart add.
                    # If we are using smart add, only added if we could make an admin record.
                    if smart_add is False or (smart_add is True
                                              and (admin_user_record_uid is not None or admin_content is not None)):

                        self.logger.debug(f"adding resource record, smart add {smart_add}")
                        # The record could be a resource or user record.
                        self._prepare_record(
                            record_prepare_func=record_prepare_func,
                            bulk_add_records=bulk_add_records,
                            content=content,
                            parent_content=current_content,
                            vertex=vertex,
                            context=context
                        )
                        if content.record_uid is None:
                            raise Exception(f"the record uid is blank for {content.description} after prepare")

                        # For a resource, the ACL will be None.
                        # It will a UserAcl if a user.
                        self.record_link.belongs_to(content.record_uid, current_content.record_uid, acl=default_acl)

                        # user_record_uid will only be populated if using smart add.
                        # Link the admin user to the resource.
                        if admin_user_record_uid is not None or admin_content is not None:

                            if admin_content is not None:
                                self.logger.debug("the admin record does not exists, create it")

                                # Create the local admin here since we need the resource record added.
                                self._prepare_record(
                                    record_prepare_func=record_prepare_func,
                                    bulk_add_records=bulk_add_records,
                                    content=admin_content,
                                    parent_content=content,
                                    vertex=admin_vertex,
                                    context=context
                                )
                                if admin_content.record_uid is None:
                                    raise Exception(f"the record uid is blank for {admin_content.description} "
                                                    "after prepare")

                                admin_user_record_uid = admin_content.record_uid

                            self.logger.debug("connecting admin user to resource")
                            self.record_link.belongs_to(admin_user_record_uid, content.record_uid, acl=admin_acl)

                # If the record type is a PAM User, we don't need to go deeper.
                # In the future we might need to change if PAM User becomes a branch and not a leaf.
                # This is for safety reasons
                if content.record_type != PAM_USER:
                    # Process the vertices that belong to the current vertex.

                    next_smart_add = smart_add
                    if add_all_users is True:
                        add_all = True
                    if add_all is True:
                        self.logger.debug("turning off smart add since add_all is enabled")
                        next_smart_add = False
                    self.logger.debug(f"smart add = {next_smart_add}, add all = {add_all}")

                    self._process_auto_add_level(
                        current_vertex=vertex,
                        bulk_add_records=bulk_add_records,
                        bulk_convert_records=bulk_convert_records,
                        record_lookup_func=record_lookup_func,
                        record_prepare_func=record_prepare_func,
                        directory_info_func=directory_info_func,
                        record_cache=record_cache,

                        # Use the value of smart_add if add_all is False.
                        # If add_all is True, we don't have to run it through the logic, we are going add a record.
                        smart_add=next_smart_add,

                        # If we could access a resource, add all it's users.
                        add_all=add_all_users,
                        context=context
                    )

            self.logger.debug(f"  finished auto add processing {record_type}")
        self.logger.debug(f"  Finished auto add current Vertex: {current_vertex.uid}, {current_content.name}")

    def _process_level(self,
                       current_vertex: DAGVertex,
                       bulk_add_records: List[BulkRecordAdd],
                       bulk_convert_records: List[BulkRecordConvert],
                       record_lookup_func: Callable,
                       prompt_func: Callable,
                       prompt_admin_func: Callable,
                       record_prepare_func: Callable,
                       directory_info_func: Callable,
                       record_cache: dict,
                       item_count: int = 0,
                       items_left: int = 0,
                       indent: int = 0,
                       context: Optional[Any] = None):

        """
        This method will walk the user through discovery delta objects.

        At this point, we only have the delta objects from the graph.
        We do not have the full graph.

        :param current_vertex: The current/parent discovery vertex.
        :param bulk_add_records: List of records to be added.
        :param bulk_convert_records: List of existing records to be covert to this gateway.
        :param prompt_func: Function to call for user prompt.
        :param record_prepare_func: Function to convert content into an unsaved record.
        :param indent: Amount to indent text.
        :param context: Client context; could be anything.
        :return:
        """

        if current_vertex.active is False:
            self.logger.debug(f"vertex {current_vertex.uid} is not active, skip")
            return

        # Check if this vertex has a record.
        # We cannot add child vertices to a vertex that does not have a record.
        current_content = current_vertex.content_as_object(DiscoveryObject)
        if current_content.record_uid is None:
            self.logger.debug(f"vertex {current_content.uid} does not have a record id")
            return

        self.logger.debug(f"Current Vertex: {current_content.record_type}, {current_vertex.uid}, "
                          f"{current_content.name}")

        # Sort all the vertices under the current vertex.
        # Return a dictionary where the record type is the key.
        # The value will be an array of vertices of the specific record type.
        record_type_to_vertices_map = sort_infra_vertices(current_vertex, logger=self.logger)

        # Process the record type by their map order in ascending order.
        for record_type in sorted(record_type_to_vertices_map, key=lambda i: VERTICES_SORT_MAP[i]['order']):
            self.logger.debug(f"  processing {record_type}")
            for vertex in record_type_to_vertices_map[record_type]:

                content = DiscoveryObject.get_discovery_object(vertex)
                self.logger.debug(f"    child vertex {vertex.uid}, {content.name}")

                default_acl = None
                if content.record_type == PAM_USER:
                    default_acl = self._default_acl(
                        discovery_vertex=vertex,
                        content=content,
                        discovery_parent_vertex=current_vertex)

                # Check for a vault record, if it exists.
                # Default to the DAG content.
                # Check the bulk_add_records list, to make sure it is not in the list of record we are about to add.
                # We are doing this because the record might be an active directory user, that we have
                #  not created a record for yet, however it might have been assigned a record UID from a prior prompt.

                existing_record = content.record_exists
                if record_lookup_func is not None:
                    check_the_vault = True
                    for item in bulk_add_records:
                        if item.record_uid == content.record_uid:
                            self.logger.debug(f"    record is in the bulk add list, do not check the vault if exists")
                            check_the_vault = False
                            break
                    if check_the_vault is True:
                        existing_record = record_lookup_func(record_uid=content.record_uid, context=context) is not None
                        self.logger.debug(f"    record exists in the vault: {existing_record}")
                else:
                    self.logger.debug(f"    record lookup function not defined, record existing: {existing_record}")

                # If we have a record UID, the record exists; we don't need to prompt the user.
                # If a user, we do want to make sure an ACL exists between this user and the resource.
                if existing_record is True:
                    self.logger.debug(f"    record already exists.")
                    # Don't continue since we might want to recurse into its children.

                # If the rule engine result is to ignore this object, then continue.
                # This normally would not happen since discovery wouldn't add the object.
                # However, make sure we skip any object where the rule engine action is to ignore the object.
                elif content.action_rules_result == RuleActionEnum.IGNORE.value:
                    self.logger.debug(f"    vertex {vertex.uid} had a IGNORE result for the rule engine, "
                                      "skip processing")
                    # If the rule engine result is to ignore this object, then continue.
                    continue

                # If this flag is set, the user set the ignore_object flag when prompted.
                elif content.ignore_object is True:
                    self.logger.debug(f"    vertex {vertex.uid} was flagged as ignore, skip processing")
                    # If the ignore_object flag is set, then continue.
                    continue

                # If the record doesn't exist, then prompt the user.
                else:
                    self.logger.debug(f"    vertex {vertex.uid} had an PROMPT result, prompt user")

                    # For user record, check if the resource record has an admin.
                    # If not, prompt the user if they want to add this user as the admin.
                    # The returned ACL will have the is_admin flag set to True if they do.
                    resource_has_admin = False
                    if content.record_type == PAM_USER:
                        resource_has_admin = (self.record_link.get_admin_record_uid(current_content.record_uid)
                                              is not None)
                        self.logger.debug(f"resource has an admin is {resource_has_admin}")

                    # If the current resource does not allow an admin, then it has and admin, it's just controlled by
                    #   us.
                    # This is going to be a resource record, or a configuration record.
                    if hasattr(current_content.item, "allows_admin") is True:
                        if current_content.item.allows_admin is False:
                            self.logger.debug(f"resource allows an admin is {current_content.item.allows_admin}")
                            resource_has_admin = True
                    else:
                        self.logger.debug(f"resource type {current_content.record_type} does not have "
                                          "allows_admin attr")

                    result = prompt_func(
                        vertex=vertex,
                        parent_vertex=current_vertex,
                        content=content,
                        acl=default_acl,
                        resource_has_admin=resource_has_admin,
                        indent=indent,
                        item_count=item_count,
                        items_left=items_left,
                        context=context)  # type: PromptResult

                    if result.action == PromptActionEnum.IGNORE:
                        self.logger.debug(f"    vertex {vertex.uid} is being ignored from prompt")
                        result.content.ignore_object = True

                        action_rule_item = Rules.make_action_rule_from_content(
                            content=result.content,
                            action=RuleActionEnum.IGNORE
                        )

                        # Add a rule to ignore this object when doing future discovery.
                        rules = Rules(record=self.record, **self.passed_kwargs)
                        rules.add_rule(action_rule_item)

                        # Even though we are ignoring the object, we will still add it to the infrastructure graph.
                        # This is user selected ignored, not from the rule engine.
                        # vertex.belongs_to(current_vertex, EdgeType.KEY)
                        vertex.add_data(result.content)

                    elif result.action == PromptActionEnum.ADD:
                        self.logger.debug(f"    vertex {vertex.uid} is being added from prompt")

                        # Use the content from the prompt.
                        # The user may have modified it.
                        content = result.content
                        acl = result.acl

                        # The record could be a resource or user record.
                        # The content
                        self._prepare_record(
                            record_prepare_func=record_prepare_func,
                            bulk_add_records=bulk_add_records,
                            content=content,
                            parent_content=current_content,
                            vertex=vertex,
                            context=context
                        )

                        # Update the DATA edge for this vertex.
                        # vertex.add_data(content)

                        # Make a record link.
                        # The acl will be None if not a pamUser.
                        self.record_link.discovery_belongs_to(vertex, current_vertex, acl)

                        # If the object is NOT a pamUser and the resource allows an admin.
                        # Prompt the user to create an admin.
                        should_prompt_for_admin = True
                        self.logger.debug(f"    added record type was {content.record_type}")
                        if (content.record_type != PAM_USER and content.item.allows_admin is True and
                                prompt_admin_func is not None):

                            # This block checks to see if the admin is a directory user that exists.
                            # We don't want to prompt the user for an admin if we have one already.
                            if content.access_user is not None and content.access_user.user is not None:

                                self.logger.debug("    for this resource, credentials were provided.")
                                self.logger.error(f"    {content.access_user.user}, {content.access_user.dn}, "
                                                  f"{content.access_user.password}")

                                # Check if this user is a directory users, first check the source.
                                # If local, check the username incase the domain in part of the username.
                                source = content.access_user.source
                                if content.record_type == PAM_DIRECTORY:
                                    source = content.name
                                elif source == LOCAL_USER:
                                    _, domain = split_user_and_domain(content.access_user.user)
                                    if domain is not None:
                                        source = domain

                                if source != LOCAL_USER:
                                    self.logger.debug("    admin was not a local user, "
                                                      f"find user in directory {source}, if exists.")

                                    acl = UserAcl.default()
                                    acl.is_admin = True
                                    admin_record_uid = None

                                    try:
                                        admin_record_uid = self._find_admin_directory_user(
                                            domain=source,
                                            admin_acl=acl,
                                            directory_info_func=directory_info_func,
                                            record_lookup_func=record_lookup_func,
                                            context=context,
                                            user=content.access_user.user,
                                            dn=content.access_user.dn
                                        )
                                    except DirectoryNotFoundException:
                                        self.logger.debug(f"    directory {source} was not found for admin user")
                                    except UserNotFoundException:
                                        self.logger.debug(f"    directory user was not found in directory {source}")
                                    if admin_record_uid is not None:
                                        self.logger.debug("    found directory user admin, connect to resource")
                                        self.record_link.belongs_to(admin_record_uid, content.record_uid, acl=acl)
                                        should_prompt_for_admin = False
                                    else:
                                        self.logger.debug("    did not find the directory user for the admin, "
                                                          "prompt the user")

                            if should_prompt_for_admin is True:
                                self.logger.debug(f"    prompt for admin user")
                                self._process_admin_user(
                                    resource_vertex=vertex,
                                    resource_content=content,
                                    bulk_add_records=bulk_add_records,
                                    bulk_convert_records=bulk_convert_records,
                                    record_lookup_func=record_lookup_func,
                                    directory_info_func=directory_info_func,
                                    prompt_admin_func=prompt_admin_func,
                                    record_prepare_func=record_prepare_func,
                                    indent=indent,
                                    context=context
                                )

                    items_left -= 1

                # If the record type is a PAM User, we don't need to go deeper.
                # In the future we might need to change if PAM User becomes a branch and not a leaf.
                # This is for safety reasons
                if content.record_type != PAM_USER:
                    # Process the vertices that belong to the current vertex.
                    self._process_level(
                        current_vertex=vertex,
                        bulk_add_records=bulk_add_records,
                        bulk_convert_records=bulk_convert_records,
                        record_lookup_func=record_lookup_func,
                        prompt_func=prompt_func,
                        prompt_admin_func=prompt_admin_func,
                        record_prepare_func=record_prepare_func,
                        directory_info_func=directory_info_func,
                        record_cache=record_cache,
                        indent=indent + 1,
                        item_count=item_count,
                        items_left=items_left,
                        context=context
                    )
            self.logger.debug(f"  finished processing {record_type}")
        self.logger.debug(f"  Finished current Vertex: {current_vertex.uid}, {current_content.name}")

    def _process_admin_user(self,
                            resource_vertex: DAGVertex,
                            resource_content: DiscoveryObject,
                            bulk_add_records: List[BulkRecordAdd],
                            bulk_convert_records: List[BulkRecordConvert],
                            record_lookup_func: Callable,
                            directory_info_func: Callable,
                            prompt_admin_func: Callable,
                            record_prepare_func: Callable,
                            indent: int = 0,
                            context: Optional[Any] = None):

        # Find the record UID that admins this resource.
        # If it is None, there is a user vertex that has an ACL with is_admin with a true value.
        record_uid = self.record_link.get_record_uid(resource_vertex)
        admin = self.record_link.get_admin_record_uid(record_uid)
        if admin is None:

            # If the access_user is None, create an empty one.
            # We will need this below when adding values to the fields.
            if resource_content.access_user is None:
                resource_content.access_user = DiscoveryUser()

            # Initialize a discovery object for the admin user.
            # The PLACEHOLDER will be replaced after the admin user prompt.

            values = {}
            for field in ["user", "password", "private_key", "dn", "database"]:
                value = getattr(resource_content.access_user, field)
                if value is None:
                    value = []
                else:
                    value = [value]
                values[field] = value

            managed = [False]
            if resource_content.access_user.managed is not None:
                managed = [resource_content.access_user.managed]

            admin_content = DiscoveryObject(
                uid="PLACEHOLDER",
                object_type_value="users",
                parent_record_uid=resource_content.record_uid,
                record_type=PAM_USER,
                id="PLACEHOLDER",
                name="PLACEHOLDER",
                description=resource_content.description + ", Administrator",
                title=resource_content.title + ", Administrator",
                item=DiscoveryUser(
                    user="PLACEHOLDER"
                ),
                fields=[
                    RecordField(type="login", label="login", value=values["user"], required=True),
                    RecordField(type="password", label="password", value=values["password"], required=False),
                    RecordField(type="secret", label="privatePEMKey", value=values["private_key"], required=False),
                    RecordField(type="text", label="distinguishedName", value=values["dn"], required=False),
                    RecordField(type="text", label="connectDatabase", value=values["database"], required=False),
                    RecordField(type="checkbox", label="managed", value=managed, required=False),
                ]
            )

            admin_acl = UserAcl.default()
            admin_acl.is_admin = True

            # Prompt to add an admin user to this resource.
            # We are not passing an ACL instance.
            # We'll make it based on if the user is adding a new record or linking to an existing record.
            admin_result = prompt_admin_func(
                parent_vertex=resource_vertex,
                content=admin_content,
                acl=admin_acl,
                bulk_convert_records=bulk_convert_records,
                indent=indent,
                context=context
            )

            # If the action is to ADD, replace the PLACEHOLDER data.
            if admin_result.action == PromptActionEnum.ADD:
                self.logger.debug("adding admin user")

                source = "local"
                if resource_content.record_type == PAM_DIRECTORY:
                    source = resource_content.name

                admin_record_uid = admin_result.record_uid

                if admin_record_uid is None:
                    admin_content = admin_result.content

                    # With the result, we can fill in information in the object item.
                    admin_content.item.user = admin_content.get_field_value("login")
                    admin_content.item.password = admin_content.get_field_value("password")
                    admin_content.item.private_key = admin_content.get_field_value("privatePEMKey")
                    admin_content.item.dn = admin_content.get_field_value("distinguishedName")
                    admin_content.item.database = admin_content.get_field_value("connectDatabase")
                    admin_content.item.managed = value_to_boolean(
                        admin_content.get_field_value("managed")) or False
                    admin_content.item.source = source
                    admin_content.name = admin_content.item.user

                    self.logger.debug(f"added admin user from content")

                    if admin_content.item.user is None or admin_content.item.user == "":
                        raise ValueError("The user name is missing or is blank. Cannot create the administrator user.")

                    if admin_content.name is not None:
                        admin_content.description = (resource_content.description + ", User " +
                                                     admin_content.name)

                    # We need to populate the id and uid of the content, now that we have data in the content.
                    self.populate_admin_content_ids(admin_content, resource_vertex)

                    ad_user, ad_domain = split_user_and_domain(admin_content.item.user)
                    if ad_domain is not None and  admin_content.item.source == LOCAL_USER:
                        self.logger.debug("The admin is an directory user, but the source is set to a local user")

                        found_admin_record_uid = None
                        try:
                            found_admin_record_uid = self._find_admin_directory_user(
                                domain=ad_domain,
                                admin_acl=admin_acl,
                                directory_info_func=directory_info_func,
                                record_lookup_func=record_lookup_func,
                                context=context,
                                user=admin_content.item.user,
                                dn=admin_content.item.dn
                            )
                        except DirectoryNotFoundException:
                            self.logger.debug(f"    directory {source} was not found for admin user")
                        except UserNotFoundException:
                            self.logger.debug(f"    directory user was not found in directory {source}")

                        if found_admin_record_uid is not None:
                            self.logger.debug("    found directory user admin, connect to resource")
                            found_admin_vertices = self.infra.dag.search_content({"record_uid": found_admin_record_uid})
                            if len(found_admin_vertices) == 1:
                                found_admin_vertices[0].belongs_to(resource_vertex, edge_type=EdgeType.KEY)
                            self.record_link.belongs_to(found_admin_record_uid, resource_content.record_uid,
                                                        acl=admin_acl)
                            return

                    # Does an admin vertex already exist for this user?
                    # This most likely user on the gateway, since without a resource record users can be discovered.
                    # If we did find it, get the content for the admin; we really want any existing record uid.
                    admin_vertex = self.infra.dag.get_vertex(admin_content.uid)
                    if admin_vertex is not None and admin_vertex.active is True and admin_vertex.has_data is True:
                        self.logger.debug("admin exists in the graph")
                        found_content = DiscoveryObject.get_discovery_object(admin_vertex)
                        admin_record_uid = found_content.record_uid
                    else:
                        self.logger.debug("admin does not exists in the graph")

                    # If there is a record UID for the admin user, connect it.
                    if admin_record_uid is not None:
                        self.logger.debug("the admin has a record UID")

                        # If the admin record does not belong to another resource, make this resource its owner.
                        if self.record_link.get_parent_record_uid(admin_record_uid) is None:
                            self.logger.debug("the admin does not belong to another resourse, "
                                              "setting it belong to this resource")
                            admin_acl.belongs_to = True

                        admin_vertex.belongs_to(resource_vertex, edge_type=EdgeType.KEY)
                        self.record_link.belongs_to(admin_record_uid, resource_content.record_uid, acl=admin_acl)
                    else:
                        if admin_vertex is None:
                            self.logger.debug("creating an entry in the graph for the admin")
                            admin_vertex = self.infra.dag.add_vertex(uid=admin_content.uid,
                                                                     name=admin_content.description)

                        # Since this record does not exist, it will belong to the resource,
                        admin_acl.belongs_to = True

                        # Connect the user vertex to the resource vertex.
                        # We need to add a KEY edge for the admin content stored on the DATA edge.
                        admin_vertex.belongs_to(resource_vertex, edge_type=EdgeType.KEY)
                        admin_vertex.add_data(admin_content)

                        # The record will be a user record; admin_acl will not be None
                        self._prepare_record(
                            record_prepare_func=record_prepare_func,
                            bulk_add_records=bulk_add_records,
                            content=admin_content,
                            parent_content=resource_content,
                            vertex=admin_vertex,
                            context=context
                        )

                        self.record_link.discovery_belongs_to(admin_vertex, resource_vertex, acl=admin_acl)

                else:
                    self.logger.debug("add admin user from existing record")

                    # If this is NOT existing directory user, we want to convert the record rotation setting to
                    #   work with this gateway/controller.
                    # If it is a directory user, we just want link this record; no conversion.
                    if admin_result.is_directory_user is False:

                        self.logger.debug("the admin user is NOT a directory user, convert record's rotation settings")

                        # This is a pamUser record that may need to have the controller set.
                        # Add it to this queue to make sure the protobuf items are current.
                        parent_record_uid = resource_content.record_uid
                        if resource_content.object_type_value == "providers":
                            parent_record_uid = None

                        bulk_convert_records.append(
                            BulkRecordConvert(
                                record_uid=admin_record_uid,
                                parent_record_uid=parent_record_uid
                            )
                        )

                        # If this user record does not belong to another resource, make it belong to this one.
                        record_vertex = self.record_link.acl_has_belong_to_record_uid(admin_record_uid)
                        if record_vertex is None:
                            admin_acl.belongs_to = True

                        # There is _prepare_record, the record exists.
                        # Needs to add to records linking.
                    else:
                        self.logger.debug("the admin user is a directory user")

                    # Link the record UIDs.
                    # We might not have this user in discovery data.
                    # It might not belong to the resource; if so, it cannot be rotated.
                    # It only has is_admin in the ACL.
                    self.record_link.belongs_to(
                        admin_record_uid,
                        record_uid,
                        acl=admin_acl
                    )

    def _get_count(self, current_vertex: DAGVertex) -> int:

        """
        Get the number of vertices that have not been converted to record.

        This will recurse down the graph.
        To be counted, the current vertex being evaluated, must ...

        * not have record UID.
        * not be ignored either by flag or rule.
        * not be auto added.

        To recurse down, the current vertex being evaluated, must ...

        * have a record UID
        * not be ignored either by flag or rule.

        """

        count = 0

        for vertex in current_vertex.has_vertices():
            if vertex.active is False:
                continue
            content = DiscoveryObject.get_discovery_object(vertex)

            # Add this record to the count, if no record UID, not ignoring, and we are not auto adding or
            #  ignoring from rules.
            if (content.record_uid is None
                    and content.ignore_object is False
                    and content.action_rules_result != "add"
                    and content.action_rules_result != "ignore"):
                count += 1

            # Go deeper if there is a record UID, and we are not ignoring, and the rule result is not to ignore.
            if (
                    content.record_uid is not None
                    and content.ignore_object is False
                    and content.action_rules_result != "ignore"):
                count += self._get_count(vertex)

        return count

    @property
    def no_items_left(self):
        return self._get_count(self.infra.get_root) == 0

    def run(self,
            prompt_func: Callable,
            record_prepare_func: Callable,
            smart_add: bool = False,
            record_lookup_func: Optional[Callable] = None,
            record_create_func: Optional[Callable] = None,
            record_convert_func: Optional[Callable] = None,
            prompt_confirm_add_func: Optional[Callable] = None,
            prompt_admin_func: Optional[Callable] = None,
            auto_add_result_func: Optional[Callable] = None,
            directory_info_func: Optional[Callable] = None,
            context: Optional[Any] = None,
            record_cache: Optional[dict] = None,
            force_quit: bool = False
            ) -> BulkProcessResults:
        """
        Process the discovery results.

        :param record_cache: A dictionary of record types to keys to record UID.
        :param prompt_func: Function to call when the user needs to make a decision about an object.
        :param smart_add: If we have resource cred, add the resource and the users.
        :param record_lookup_func: Function to look up a record by UID.
        :param record_prepare_func: Function to call to prepare a record to be created.
        :param record_create_func: Function to call to save the prepared records.
        :param record_convert_func: Function to convert record to use this gateway.
        :param prompt_confirm_add_func: Function to call if quiting and record have been added to queue.
        :param prompt_admin_func: Function to prompt user for admin.
        :param auto_add_result_func: Function to call after auto adding. Provided records to bulk add.
        :param directory_info_func: Function to get users of a directory from vault records.
        :param context: Context passed to the prompt and add function. These could be objects that are not in the scope
                        of the function.
        :param force_quit: Used for testing. Throw a Quit exception after processing.
        :return:
        """
        sync_point = self.job.sync_point
        if sync_point is None:
            raise Exception("The job does not have a sync point for the graph.")

        # Get the root vertex, which has nothing we care about.
        # But from the root, get the configuration vertex.
        # There will be only one.
        self.logger.debug(f"loading the graph at sync point {sync_point}")
        self.infra.load(sync_point=sync_point)
        if self.infra.has_discovery_data is False:
            raise NoDiscoveryDataException("There is no discovery data to process.")

        # If the graph is corrupted, delete the bad vertices.
        #
        if self.infra.dag.is_corrupt is True:
            self.logger.debug("the graph is corrupt, deleting vertex")
            for uid in self.infra.dag.corrupt_uids:
                vertex = self.infra.dag.get_vertex(uid)
                vertex.delete()
            self.infra.dag.corrupt_uids = []
            self.logger.info("fixed the corrupted vertices")

        root = self.infra.get_root
        configuration = root.has_vertices()[0]

        # If we have a record cache, attempt to find vertices where the content does not have the record UID set and
        #   then update them with cached records from the vault.
        # This is done incase someone has manually created a record after discovery has been done.
        if record_cache is not None:
            self._update_with_record_uid(
                record_cache=record_cache,
                current_vertex=configuration,
            )

        # Store records that to be created and record where their protobuf settings need to be updated.
        bulk_add_records = []  # type: List[BulkRecordAdd]
        bulk_convert_records = []  # type: List[BulkRecordConvert]

        should_add_records = True
        bulk_process_results = None

        # Pass an empty
        if context is None:
            context = {}

        # We need record linking and infra graphs in the context.
        # We are adding admin users to check existing admin relationships and to see if AD user.
        context["record_link"] = self.record_link
        context["infra"] = self.infra

        try:

            self.logger.debug("# ####################################################################################")
            self.logger.debug("# AUTO ADD ITEMS")
            self.logger.debug("#")
            self.logger.debug(f"smart add = {smart_add}")

            # Process the auto add entries first.
            # There are no prompts.
            self._process_auto_add_level(
                current_vertex=configuration,
                bulk_add_records=bulk_add_records,
                bulk_convert_records=bulk_convert_records,
                smart_add=smart_add,
                record_lookup_func=record_lookup_func,
                record_prepare_func=record_prepare_func,
                directory_info_func=directory_info_func,
                record_cache=record_cache,
                context=context)

            # If set, give the client a list of record that will be added.
            # Can be used for displaying how many record are auto added.
            if auto_add_result_func is not None:
                auto_add_result_func(bulk_add_records=bulk_add_records)

            self.logger.debug("# ####################################################################################")
            self.logger.debug("# PROMPT USER ITEMS")
            self.logger.debug("#")

            # This is the total number of items that processing needs to process.
            # We start with items_left equal to item_count.
            item_count = self._get_count(configuration)

            self._process_level(
                current_vertex=configuration,
                bulk_add_records=bulk_add_records,
                bulk_convert_records=bulk_convert_records,
                record_lookup_func=record_lookup_func,
                prompt_func=prompt_func,
                prompt_admin_func=prompt_admin_func,
                record_prepare_func=record_prepare_func,
                directory_info_func=directory_info_func,
                record_cache=record_cache,
                indent=0,
                item_count=item_count,
                items_left=item_count,
                context=context)

            # This mainly for testing.
            # If throw and quit exception, so we can prompt the user.
            if force_quit is True:
                raise QuitException()

        except QuitException:
            should_add_records = False

            # If we have record ready to be created, and the confirm prompt function was set, ask the user if they want
            # to add the records.
            if (len(bulk_add_records) > 0 and prompt_confirm_add_func is not None and
                    prompt_confirm_add_func(bulk_add_records) is True):
                should_add_records = True

            modified_count = len(self.infra.dag.modified_edges)
            self.logger.debug(f"quiting and there are {modified_count} modified edges.")

        # If we don't have a create function, then there is no way to add record.
        if record_create_func is None:
            should_add_records = False

        # We should add the record, and a method was passed in to create them; then add the records.
        if should_add_records is True:

            self.logger.debug("# ####################################################################################")
            self.logger.debug("# CREATE NEW RECORD")
            self.logger.debug("#")

            # Save new records.
            bulk_process_results = record_create_func(
                bulk_add_records=bulk_add_records,
                context=context
            )
            self.logger.debug("# ####################################################################################")

            self.logger.debug("# ####################################################################################")
            self.logger.debug("# CONVERT EXISTING RECORD")
            self.logger.debug("#")

            # Update existing record to use this gateway.
            record_convert_func(
                bulk_convert_records=bulk_convert_records,
                context=context
            )
            self.logger.debug("# ####################################################################################")
        else:

            self.logger.debug("# ####################################################################################")
            self.logger.debug("# ROLLBACK GRAPH")
            self.logger.debug("#")

            for record in bulk_add_records:
                vertices = self.infra.dag.search_content({"record_uid": record.record_uid})
                for vertex in vertices:
                    self.logger.debug(f" * {record.title}, flagged")
                    vertex.skip_save = True
            for record in bulk_convert_records:
                vertices = self.infra.dag.search_content({"record_uid": record.record_uid})
                for vertex in vertices:
                    self.logger.debug(f" * {record.title}, flagged")
                    vertex.skip_save = True

            self.logger.debug("# ####################################################################################")

        self.logger.debug("# ####################################################################################")
        self.logger.debug("# Save INFRASTRUCTURE graph")
        self.logger.debug("#")

        # Disable delta save.
        self.logger.debug(f"saving additions from process run")
        self.infra.save(delta_graph=False)
        self.logger.debug("# ####################################################################################")

        # Save the record linking, only if we added records.
        # This will be the additions and any changes to ACL.
        if should_add_records is True:

            self.logger.debug("# ####################################################################################")
            self.logger.debug("# Save RECORD LINKING graph")
            self.logger.debug("#")

            self.logger.debug(f"save additions from record linking ")
            self.record_link.save()
            self.logger.debug("# ####################################################################################")

            # Map user to service/task on a machine
            self.user_service.run(infra=self.infra)

        return bulk_process_results
