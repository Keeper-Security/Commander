from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from ... import vault, vault_extensions
from ...discovery_common.infrastructure import Infrastructure
from ...discovery_common.record_link import RecordLink
from ...discovery_common.user_service import UserService
from ...discovery_common.types import UserAcl, DiscoveryObject
from ...discovery_common.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from ...keeper_dag import EdgeType
import time
import re
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMDebugInfoCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-debug-info')

    type_name_map = {
        PAM_USER: "PAM User",
        PAM_MACHINE: "PAM Machine",
        PAM_DATABASE: "PAM Database",
        PAM_DIRECTORY: "PAM Directory",
    }

    # The record to base everything on.
    parser.add_argument('--record-uid', '-i', required=True, dest='record_uid', action='store',
                        help='Keeper PAM record UID.')

    def get_parser(self):
        return PAMDebugInfoCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        record_uid = kwargs.get("record_uid")
        record = vault.KeeperRecord.load(params, record_uid)  # type: Optional[TypedRecord]
        if record is None:
            print(f"{bcolors.FAIL}Record does not exists.{bcolors.ENDC}")
            return

        if record.record_type not in ["pamUser", "pamMachine", "pamDatabase", "pamDirectory"]:
            if re.search(r'^pam.*Configuration$', record.record_type) is None:
                print(f"{bcolors.FAIL}The record is a {record.record_type}. This is not a PAM record.{bcolors.ENDC}")
                return

        resource_uid = None
        controller_uid = None

        record_rotation = params.record_rotation_cache.get(record_uid)

        # Rotation setting don't exist, check each configuration for an active record.
        if record_rotation is None:
            print(f"{bcolors.WARNING}PAM record does not have protobuf rotation settings, "
                  f"checking all configurations.{bcolors.ENDC}")

            configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))
            if len(configuration_records) == 0:
                print(f"{bcolors.FAIL}Cannot find any PAM configuration records in the Vault{bcolors.ENDC}")

            for configuration_record in configuration_records:
                record_link = RecordLink(record=configuration_record, params=params)
                record_vertex = record_link.dag.get_vertex(record.record_uid)
                if record_vertex is not None and record_vertex.active is True:
                    controller_uid = configuration_record.record_uid
                    break
            if controller_uid is None:
                print(f"{bcolors.FAIL}Could not find the record in any record linking graph; "
                      f"checked all configuration records.{bcolors.ENDC}")
                return

        # Else just get information from the rotation settings
        else:

            controller_uid = record_rotation.get("configuration_uid")
            if controller_uid is None:
                print(f"{bcolors.FAIL}Record does not have the PAM Configuration set.{bcolors.ENDC}")
                return

            resource_uid = record_rotation.get("resource_uid")

        configuration_record = vault.KeeperRecord.load(params, controller_uid)  # type: Optional[TypedRecord]
        if configuration_record is None:
            print(f"{bcolors.FAIL}The configuration record {controller_uid} does not exist.{bcolors.ENDC}")
            return

        gateway_context = GatewayContext.from_configuration_uid(params, controller_uid)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway for configuration record.{controller_uid}{bcolors.ENDC}")
            return

        infra = Infrastructure(record=configuration_record, params=params)
        infra.load()
        record_link = RecordLink(record=configuration_record, params=params)
        user_service = UserService(record=configuration_record, params=params)

        print("")
        print(self._h("Record Information"))
        print(f"  {self._b('Record UID')}: {record_uid}")
        print(f"  {self._b('Record Title')}: {record.title}")
        print(f"  {self._b('Record Type')}: {record.record_type}")
        print(f"  {self._b('Configuration UID')}: {configuration_record.record_uid}")
        print(f"  {self._b('Configuration Key Bytes Hex')}: {configuration_record.record_key.hex()}")
        if resource_uid is not None:
            print(f"  {self._b('Resource UID')}: {resource_uid}")

        if gateway_context is not None:
            print(f"  {self._b('Gateway Name')}: {gateway_context.gateway_name}")
            print(f"  {self._b('Gateway UID')}: {gateway_context.gateway_uid}")
        else:
            print(f"  {self._f('Cannot get gateway information. Gateway may not be up.')}")
        print("")

        def _print_field(f):
            if f.type == "password":
                display_value = f"{bcolors.OKGREEN}Password is set{bcolors.ENDC}"
                if f.value == 0 or len(f.value) == 0:
                    display_value = f"{bcolors.WARNING}Password IS NOT set{bcolors.ENDC}"
                print(f"   * Type: {f.type}, Label: {f.label or bcolors.OKBLUE + 'NO LABEL' + bcolors.ENDC}, "
                      f"Value(s): {display_value}")
            elif f.label == "privatePEMKey":
                display_value = f"{bcolors.OKGREEN}Private Key is set{bcolors.ENDC}"
                if field.value == 0 or len(f.value) == 0:
                    display_value = f"{bcolors.WARNING}Private Key IS NOT set{bcolors.ENDC}"
                print(f"   * Type: {f.type}, Label: {f.label or bcolors.OKBLUE + 'NO LABEL' + bcolors.ENDC}, "
                      f"Value(s): {display_value}")
            elif f.type == "secret":
                display_value = f"{bcolors.OKGREEN}Secret value is set{bcolors.ENDC}"
                if field.value == 0 or len(f.value) == 0:
                    display_value = f"Secret value IS NOT set"
                print(f"   * Type: {f.type}, Label: {f.label or bcolors.OKBLUE + 'NO LABEL' + bcolors.ENDC}, "
                      f"Value(s): {display_value}")
            else:
                print(f"   * Type: {f.type}, Label: {f.label or bcolors.OKBLUE + 'NO LABEL' + bcolors.ENDC}, "
                      f"Value(s): {f.value}")

        print(self._h("Fields"))
        print(self._b("  Record Type Fields"))
        if record.fields is not None and len(record.fields) > 0:
            for field in record.fields:
                _print_field(field)
        else:
            print(f"{bcolors.FAIL}    Record does not have record type fields!{bcolors.ENDC}")
        print("")
        print(self._b("  Custom Fields"))
        if record.custom is not None and len(record.custom) > 0:
            for field in record.custom:
                _print_field(field)
        else:
            print("    Record does not have custom fields.")
        print("")

        discovery_vertices = infra.dag.search_content({"record_uid": record.record_uid})
        record_vertex = record_link.dag.get_vertex(record.record_uid)

        if record_vertex is not None:
            print(self._h("Record Linking"))
            record_parent_vertices = record_vertex.belongs_to_vertices()
            print(self._b("  Parent Records"))
            if len(record_parent_vertices) > 0:
                for record_parent_vertex in record_parent_vertices:

                    parent_record = vault.KeeperRecord.load(params,
                                                            record_parent_vertex.uid)  # type: Optional[TypedRecord]
                    if parent_record is None:
                        print(f"{bcolors.FAIL}   * Parent record {record_parent_vertex.uid} "
                              f"does not exists.{bcolors.ENDC}")
                        continue

                    acl_edge = record_vertex.get_edge(record_parent_vertex, EdgeType.ACL)
                    if acl_edge is not None:
                        acl_content = acl_edge.content_as_object(UserAcl)  # type: UserAcl
                        print(f"    * ACL to {self._n(parent_record.record_type)}; {parent_record.title}; "
                              f"{record_parent_vertex.uid}")
                        if acl_content.is_admin is True:
                            print(f"      . Is {self._gr('Admin')}")
                        if acl_content.belongs_to is True:
                            print(f"      . Belongs")
                        else:
                            print(f"      . Is {self._bl('Remote user')}")

                        if acl_content.rotation_settings is None:
                            print(f"{bcolors.FAIL}      . There are no rotation settings!{bcolors.ENDC}")
                        else:
                            if (acl_content.rotation_settings.schedule is None
                                    or acl_content.rotation_settings.schedule == ""):
                                print(f"      . No Schedule")
                            else:
                                print(f"      . Schedule = {acl_content.rotation_settings.get_schedule()}")

                            if (acl_content.rotation_settings.pwd_complexity is None
                                    or acl_content.rotation_settings.pwd_complexity == ""):
                                print(f"      . No Password Complexity")
                            else:
                                key_bytes = record.record_key
                                print(f"      . Password Complexity = "
                                      f"{acl_content.rotation_settings.get_pwd_complexity(key_bytes)}")
                            print(f"      . Disabled = {acl_content.rotation_settings.disabled}")
                            print(f"      . NOOP = {acl_content.rotation_settings.noop}")
                            print(f"      . SaaS Config Records = {acl_content.rotation_settings.saas_record_uid_list}")

                    elif record.record_type == PAM_USER:
                        print(f"{bcolors.FAIL}    * PAM User has NO acl!!!!!!{bcolors.ENDC}")

                    link_edge = record_vertex.get_edge(record_parent_vertex, EdgeType.LINK)
                    if link_edge is not None:
                        print(f"    * LINK to {self._n(parent_record.record_type)}; {parent_record.title}; "
                              f"{record_parent_vertex.uid}")
            else:
                # This really should not happen
                print(f"{bcolors.FAIL}   Record does not have a parent record.{bcolors.ENDC}")
            print("")

            record_child_vertices = record_vertex.has_vertices()
            print(self._b("  Child Records"))
            if len(record_child_vertices) > 0:
                for record_child_vertex in record_child_vertices:
                    child_record = vault.KeeperRecord.load(params,
                                                           record_child_vertex.uid)  # type: Optional[TypedRecord]

                    if child_record is None:
                        print(f"{bcolors.FAIL}    * Child record {record_child_vertex.uid} "
                              f"does not exists.{bcolors.ENDC}")
                        continue

                    acl_edge = record_child_vertex.get_edge(record_vertex, EdgeType.ACL)
                    link_edge = record_child_vertex.get_edge(record_vertex, EdgeType.LINK)
                    if acl_edge is not None:
                        acl_content = acl_edge.content_as_object(UserAcl)
                        print(f"    * ACL from {self._n(child_record.record_type)}; {child_record.title}; "
                              f"{record_child_vertex.uid}")
                        if acl_content.is_admin is True:
                            print(f"      . Is {self._gr('Admin')}")
                        if acl_content.belongs_to is True:
                            print(f"      . Belongs")
                        else:
                            print(f"      . Is {self._bl('Remote user')}")
                    elif link_edge is not None:
                        print(f"    * LINK from {self._n(child_record.record_type)}; {child_record.title}; "
                              "{record_child_vertex.uid}")
                    else:
                        for edge in record_vertex.edges:  # List[DAGEdge]
                            print(f"    * {self._f(edge.edge_type)}?")

            else:
                # This is OK
                print(f"    Record does not have any children.")
            print("")

        else:
            print(f"{bcolors.FAIL}Cannot find record in record linking.{bcolors.ENDC}")

        # Only PAM User and PAM Machine can have services and tasks.
        # This is really only Windows machines.
        if record.record_type == PAM_USER or record.record_type == PAM_MACHINE:

            # Get the user to service/task vertex.
            user_service_vertex = user_service.dag.get_vertex(record_uid)

            if user_service_vertex is not None:

                # If the record is a PAM User
                if record.record_type == PAM_USER:

                    user_results = {
                        "is_task": [],
                        "is_service": []
                    }

                    # Get a list of all the resources the user is the username/password on service/task.
                    for us_machine_vertex in user_service.get_resource_vertices(record_uid):

                        # Get the resource record
                        us_machine_record = (
                            vault.KeeperRecord.load(params, us_machine_vertex.uid))  # type: Optional[TypedRecord]

                        acl = user_service.get_acl(us_machine_vertex.uid, user_service_vertex.uid)
                        for attr in ["is_task", "is_service"]:
                            value = getattr(acl, attr)
                            if value is True:

                                # If the resource record does not exist.
                                if us_machine_record is None:

                                    # Default the title to Unknown (in red).
                                    # See if we have an infrastructure vertex with this record UID.
                                    # If we do have it, use the title inside the first vertex's data content.
                                    title = self._f("Unknown")
                                    infra_resource_vertices = infra.dag.search_content(
                                        {"record_uid": us_machine_vertex.uid})
                                    if len(infra_resource_vertices) > 0:
                                        infra_resource_vertex = infra_resource_vertices[0]
                                        if infra_resource_vertex.has_data is True:
                                            content = DiscoveryObject.get_discovery_object(infra_resource_vertex)
                                            title = content.title

                                    user_results[attr].append(f"  * Record {us_machine_vertex.uid}, "
                                                              f"{title} does not exists.")

                                # Record exists; just use information from the record.
                                else:
                                    user_results[attr].append(f"  * {us_machine_record.title}, "
                                                              f"{us_machine_vertex.uid}")

                    print(f"{bcolors.HEADER}Service on Machines{bcolors.ENDC}")
                    if len(user_results["is_service"]) > 0:
                        for service in user_results["is_service"]:
                            print(service)
                    else:
                        print("  PAM User is not used for any services.")
                    print("")

                    print(f"{bcolors.HEADER}Scheduled Tasks on Machines{bcolors.ENDC}")
                    if len(user_results["is_task"]) > 0:
                        for task in user_results["is_task"]:
                            print(task)
                    else:
                        print("  PAM User is not used for any scheduled tasks.")
                    print("")

                # If the record is a PAM Machine
                else:
                    user_results = {
                        "is_task": [],
                        "is_service": []
                    }

                    # Get the users that are used for tasks/services on this machine.
                    for us_user_vertex in user_service.get_user_vertices(record_uid):

                        us_user_record = vault.KeeperRecord.load(params,
                                                                 us_user_vertex.uid)  # type: Optional[TypedRecord]
                        acl = user_service.get_acl(user_service_vertex.uid, us_user_vertex.uid)
                        for attr in ["is_task", "is_service"]:
                            value = getattr(acl, attr)
                            if value is True:

                                # If the user record does not exist.
                                if us_user_record is None:

                                    # Default the title to Unknown (in red).
                                    # See if we have an infrastructure vertex with this record UID.
                                    # If we do have it, use the title inside the first vertex's data content.
                                    title = self._f("Unknown")
                                    infra_resource_vertices = infra.dag.search_content(
                                        {"record_uid": us_user_vertex.uid})
                                    if len(infra_resource_vertices) > 0:
                                        infra_resource_vertex = infra_resource_vertices[0]
                                        if infra_resource_vertex.has_data is True:
                                            content = DiscoveryObject.get_discovery_object(infra_resource_vertex)
                                            title = content.title

                                    user_results[attr].append(f"  * Record {us_user_vertex.uid}, "
                                                              f"{title} does not exists.")

                                # Record exists; just use information from the record.
                                else:
                                    user_results[attr].append(f"  * {us_user_record.title}, "
                                                              f"{us_user_vertex.uid}")

                    print(f"{bcolors.HEADER}Users that are used for Services{bcolors.ENDC}")
                    if len(user_results["is_service"]) > 0:
                        for service in user_results["is_service"]:
                            print(service)
                    else:
                        print("  Machine does not use any non-builtin users for services.")
                    print("")

                    print(f"{bcolors.HEADER}Users that are used for Scheduled Tasks{bcolors.ENDC}")
                    if len(user_results["is_task"]) > 0:
                        for task in user_results["is_task"]:
                            print(task)
                    else:
                        print("  Machine does not use any non-builtin users for scheduled tasks.")
                    print("")
            else:
                print(self._f("There are no services or schedule tasks associated with this record."))
                print("")
        try:
            if len(discovery_vertices) == 0:
                print(f"{bcolors.FAIL}Could not find any discovery infrastructure vertices for "
                      f"{record.record_uid}{bcolors.ENDC}")
            elif len(discovery_vertices) > 0:

                if len(discovery_vertices) > 1:
                    print(f"{bcolors.FAIL}Found multiple vertices with the record UID of "
                          f"{record.record_uid}{bcolors.ENDC}")
                    for vertex in discovery_vertices:
                        print(f" * Infrastructure Vertex UID: {vertex.uid}")
                    print("")

                discovery_vertex = discovery_vertices[0]
                content = DiscoveryObject.get_discovery_object(discovery_vertex)

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

                if record.record_type == PAM_USER:
                    print(f"  {self._b('User')}: {content.item.user}")
                    print(f"  {self._b('DN')}: {content.item.dn}")
                    print(f"  {self._b('Database')}: {content.item.database}")
                    print(f"  {self._b('Active')}: {content.item.active}")
                    print(f"  {self._b('Expired')}: {content.item.expired}")
                    print(f"  {self._b('Source')}: {content.item.source}")
                elif record.record_type == PAM_MACHINE:
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
                    else:
                        print(f"{bcolors.FAIL}    Machine facts are not set. Discover inside may not have been "
                              f"performed.{bcolors.ENDC}")
                elif record.record_type == PAM_DATABASE:
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
                elif record.record_type == PAM_DIRECTORY:
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
                vertices = discovery_vertex.belongs_to_vertices()
                for vertex in vertices:
                    content = DiscoveryObject.get_discovery_object(vertex)
                    print(f"  * {content.description} ({vertex.uid})")
                    for edge_type in [EdgeType.LINK, EdgeType.ACL, EdgeType.KEY, EdgeType.DELETION]:
                        edge = discovery_vertex.get_edge(vertex, edge_type=edge_type)
                        if edge is not None:
                            print(f"    . {edge_type}, active: {edge.active}")

                if len(vertices) == 0:
                    print(f"{bcolors.FAIL}  Does not belong to anyone{bcolors.ENDC}")

                print("")
                print(f"{bcolors.HEADER}Vertices Belonging To (Children){bcolors.ENDC}")
                vertices = discovery_vertex.has_vertices()
                for vertex in vertices:
                    content = DiscoveryObject.get_discovery_object(vertex)
                    print(f"  * {content.description} ({vertex.uid})")
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
