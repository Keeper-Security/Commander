from __future__ import annotations
import logging
import argparse
import json
import os.path

from keeper_secrets_manager_core.utils import url_safe_str_to_bytes
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ..pam.router_helper import router_get_connected_gateways, router_set_record_rotation_information
from ... import api, subfolder, utils, crypto, vault, vault_extensions
from ...display import bcolors
from ...proto import router_pb2, record_pb2
from discovery_common.jobs import Jobs
from discovery_common.process import Process, QuitException, NoDiscoveryDataException
from discovery_common.types import (DiscoveryObject, UserAcl, PromptActionEnum, PromptResult,
                                    BulkRecordAdd, BulkRecordConvert, BulkProcessResults, BulkRecordSuccess,
                                    BulkRecordFail, DirectoryInfo)
from pydantic import BaseModel
from typing import Optional, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...vault import TypedRecord
    from keeper_dag.vertex import DAGVertex
    from discovery_common.record_link import RecordLink


def _h(value: str) -> str:
    return f"{bcolors.HEADER}{value}{bcolors.ENDC}"


def _b(value: str) -> str:
    return f"{bcolors.BOLD}{value}{bcolors.ENDC}"


def _f(value: str) -> str:
    return f"{bcolors.FAIL}{value}{bcolors.ENDC}"


def _ok(value: str) -> str:
    return f"{bcolors.OKGREEN}{value}{bcolors.ENDC}"


# This is used for the admin user search
class AdminSearchResult(BaseModel):
    record: Any
    is_directory_user: bool
    is_pam_user: bool


class PAMGatewayActionDiscoverResultProcessCommand(PAMGatewayActionDiscoverCommandBase):

    """
    Process the discovery data
    """

    parser = argparse.ArgumentParser(prog='dr-discover-command-process')
    parser.add_argument('--job-id', '-j', required=True, dest='job_id', action='store',
                        help='Discovery job to process.')
    parser.add_argument('--add-all', required=False, dest='add_all', action='store_true',
                        help='Add record when prompted.')

    def get_parser(self):
        return PAMGatewayActionDiscoverResultProcessCommand.parser

    @staticmethod
    def _is_directory_user(record_type: str) -> bool:
        # pamAzureConfiguration has tenant users what are like a directory.
        return (record_type == "pamDirectory" or
                record_type == "pamAzureConfiguration")

    @staticmethod
    def _get_shared_folder(params: KeeperParams, pad: str, gateway_context: GatewayContext) -> str:
        while True:
            shared_folders = gateway_context.get_shared_folders(params)
            index = 0
            for folder in shared_folders:
                print(f"{pad}* {_h(str(index+1))} - {folder.get('uid')}  {folder.get('name')}")
                index += 1
            selected = input(f"{pad}Enter number of the shared folder>")
            try:
                return shared_folders[int(selected) - 1].get("uid")
            except ValueError:
                print(f"{pad}{_f('Input was not a number.')}")

    @staticmethod
    def get_field_values(record: TypedRecord, field_type: str) -> List[str]:
        return next(
            (f.value
             for f in record.fields
             if f.type == field_type),
            None
        )

    def get_keys_by_record(self, params: KeeperParams, gateway_context: GatewayContext,
                           record: TypedRecord) -> List[str]:
        """
        For the record, get the values of fields that are key for this record type.

        :param params:
        :param gateway_context:
        :param record:
        :return:
        """

        key_field = Process.get_key_field(record.record_type)
        keys = []
        if key_field == "host_port":
            values = self.get_field_values(record, "pamHostname")
            if len(values) == 0:
                return []

            host = values[0].get("hostName")
            port = values[0].get("port")
            if port is not None:
                if host is not None:
                    keys.append(f"{host}:{port}".lower())

        elif key_field == "host":
            values = self.get_field_values(record, "pamHostname")
            if len(values) == 0:
                return []

            host = values[0].get("hostName")
            if host is not None:
                keys.append(host.lower())

        elif key_field == "user":

            # This is user protobuf values.
            # We could make this also use record linking if we stop using protobuf.

            record_rotation = params.record_rotation_cache.get(record.record_uid)
            if record_rotation is not None:
                controller_uid = record_rotation.get("configuration_uid")
                if controller_uid is None or controller_uid != gateway_context.configuration_uid:
                    return []

                resource_uid = record_rotation.get("resource_uid")
                # If the resource uid is None, the Admin Cred Record has not been set.
                if resource_uid is None:
                    return []

                values = self.get_field_values(record, "login")
                if len(values) == 0:
                    return []

                keys.append(f"{resource_uid}:{values[0]}".lower())

        return keys

    def _build_record_cache(self, params: KeeperParams, gateway_context: GatewayContext) -> dict:

        """
        Make a lookup cache for all the records.

        This is used to flag discovered items as existing if the record has already been added. This is used to
        prevent duplicate records being added.
        """

        logging.debug(f"building the PAM record cache")

        # Make a cache of existing record by the criteria per record type
        cache = {
            "pamUser": {},
            "pamMachine": {},
            "pamDirectory": {},
            "pamDatabase": {}
        }

        # Set all the PAM Records
        records = list(vault_extensions.find_records(params, "pam*"))
        for record in records:
            # If the record type is not part of the cache, skip the record
            if record.record_type not in cache:
                continue

            # Load the full record
            record = vault.TypedRecord.load(params, record.record_uid)  # type: Optional[TypedRecord]

            cache_keys = self.get_keys_by_record(
                params=params,
                gateway_context=gateway_context,
                record=record
            )
            if len(cache_keys) == 0:
                continue

            for cache_key in cache_keys:
                cache[record.record_type][cache_key] = record.record_uid

        return cache

    def _edit_record(self, content: DiscoveryObject, pad: str, editable: List[str]) -> bool:

        edit_label = input(f"{pad}Enter 'title' or the name of the {_ok('Label')} to edit, RETURN to cancel> ")

        # Just pressing return exits the edit
        if edit_label == "":
            return False

        # If the "title" is entered, then edit the title of the record.
        if edit_label.lower() == "title":
            new_title = input(f"{pad}Enter new title> ")
            content.title = new_title

        # If a field label is entered, and it's in the list of editable fields, then allow the user to edit.
        elif edit_label in editable:
            new_value = None
            if edit_label in self.FIELD_MAPPING:
                type_hint = self.FIELD_MAPPING[edit_label].get("type")
                if type_hint == "dict":
                    field_input_format = self.FIELD_MAPPING[edit_label].get("field_input")
                    new_value = {}
                    for field in field_input_format:
                        new_value[field.get('key')] = input(f"{pad}Enter {field_input_format.get('prompt')} value> ")
                elif type_hint == "multiline":
                    new_value = input(f"{pad}Enter {edit_label} value> ")
                    new_values = map(str.strip, new_value.split(','))
                    new_value = "\n".join(new_values)
            else:
                new_value = input(f"{pad}Enter new value> ")

                # Is the value a path to a file, i.e., a private key file.
                if os.path.exists(new_value) is True:
                    with open(new_value, "r") as fh:
                        new_value = fh.read()
                        fh.close()

            for edit_field in content.fields:
                if edit_field.label == edit_label:
                    edit_field.value = [new_value]

        # Else, the label they entered cannot be edited.
        else:
            print(
                f"{pad}{_f('The field is not editable.')}")
            return False

        return True

    @staticmethod
    def _auto_add_preprocess(vertex: DAGVertex, content: DiscoveryObject, parent_vertex: DAGVertex,
                             acl: Optional[UserAcl] = None) -> Optional[PromptResult]:
        """
        This is client side check if we should skip prompting the user.

        The checks are
        * A directory with the same domain already has a record.

        """

        _ = vertex
        _ = acl

        # Check if the directory for a domain exists.
        # From the parent, find any directory objects.
        # If they already have a record UID, don't prompt about this one.
        # Once a directory for the domain exists, the user should not be prompted about this domain anymore.
        if content.record_type == "pamDirectory":
            for v in parent_vertex.has_vertices():
                other_content = DiscoveryObject.get_discovery_object(v)
                if other_content.record_uid is not None and other_content.name == content.name:
                    return PromptResult(action=PromptActionEnum.SKIP)
        return None

    def _prompt_display_fields(self, content: DiscoveryObject, pad: str) -> List[str]:

        editable = []
        for field in content.fields:
            has_editable = False
            if field.label in ["login", "password", "distinguishedName", "alternativeIPs", "database",
                               "privatePEMKey", "connectDatabase"]:
                editable.append(field.label)
                has_editable = True
            value = field.value
            if len(value) > 0:
                value = value[0]
                if field.label in self.FIELD_MAPPING:
                    type_hint = self.FIELD_MAPPING[field.label].get("type")
                    formatted_value = []
                    if type_hint == "dict":
                        field_input_format = self.FIELD_MAPPING[field.label].get("field_format")
                        for format_field in field_input_format:
                            formatted_value.append(f"{format_field.get('label')}: "
                                                   f"{value.get(format_field.get('key'))}")
                    elif type_hint == "multiline":
                        formatted_value.append(", ".join(value.split("\n")))
                    value = ", ".join(formatted_value)
            else:
                if has_editable is True:
                    value = f"{bcolors.FAIL}MISSING{bcolors.ENDC}"
                else:
                    value = f"{bcolors.OKBLUE}None{bcolors.ENDC}"

            color = bcolors.HEADER
            if has_editable is True:
                color = bcolors.OKGREEN

            rows = str(value).split("\n")
            if len(rows) > 1:
                value = rows[0] + _b(f"... {len(rows)} rows.")

            print(f"{pad}  "
                  f"{color}Label:{bcolors.ENDC} {field.label}, "
                  f"{_h('Type:')} {field.type}, "
                  f"{_h('Value:')} {value}")

        if len(content.notes) > 0:
            print("")
            for note in content.notes:
                print(f"{pad}* {note}")

        return editable

    @staticmethod
    def _prompt_display_relationships(vertex: DAGVertex, content: DiscoveryObject, pad: str):

        if vertex is None:
            return

        if content.record_type == "pamUser":
            belongs_to = []
            for v in vertex.belongs_to_vertices():
                resource_content = DiscoveryObject.get_discovery_object(v)
                belongs_to.append(resource_content.name)
            count = len(belongs_to)
            print("")
            print(f"{pad}This user is found on {count} resource{'s' if count > 1 else ''}")

    def _prompt(self,
                content: DiscoveryObject,
                acl: UserAcl,
                vertex: Optional[DAGVertex] = None,
                parent_vertex: Optional[DAGVertex] = None,
                resource_has_admin: bool = True,
                item_count: int = 0,
                items_left: int = 0,
                indent: int = 0,
                context: Optional[Any] = None) -> PromptResult:

        if context is None:
            raise Exception("Context not set for processing the discovery results")

        parent_content = DiscoveryObject.get_discovery_object(parent_vertex)

        print("")

        params = context.get("params")
        gateway_context = context.get("gateway_context")
        dry_run = context.get("dry_run")
        auto_add = context.get("auto_add")

        # If auto add is True, there are sometime we don't want to add the object.
        # If we get a result, we want to return it.
        # Skip the prompt.
        if auto_add is True and vertex is not None:
            result = self._auto_add_preprocess(vertex, content, parent_vertex, acl)
            if result is not None:
                return result

        # If the record type is a pamUser, then include parent description.
        if content.record_type == "pamUser" and parent_vertex is not None:
            parent_pad = ""
            if indent - 1 > 0:
                parent_pad = "".ljust(2 * indent, ' ')

            print(f"{parent_pad}{_h(parent_content.description)}")

        pad = ""
        if indent > 0:
            pad = "".ljust(2 * indent, ' ')

        print(f"{pad}{_h(content.description)}")

        show_current_object = True
        while show_current_object is True:
            print(f"{pad}{bcolors.HEADER}Record Title:{bcolors.ENDC} {content.title}")

            logging.debug(f"Fields: {content.fields}")

            # Display the fields and return a list of fields are editable.
            editable = self._prompt_display_fields(content=content, pad=pad)
            if vertex is not None:
                self._prompt_display_relationships(vertex=vertex, content=content, pad=pad)

            while True:

                shared_folder_uid = content.shared_folder_uid
                if shared_folder_uid is None:
                    shared_folder_uid = gateway_context.default_shared_folder_uid

                count_prompt = ""
                if item_count > 0:
                    count_prompt = f"{bcolors.HEADER}[{item_count - items_left + 1}/{item_count}]{bcolors.ENDC}"
                edit_add_prompt = f"{count_prompt} ({_b('E')})dit, ({_b('A')})dd, "
                if dry_run is True:
                    edit_add_prompt = ""
                shared_folders = gateway_context.get_shared_folders(params)
                if len(shared_folders) > 1 and dry_run is False:
                    folder_name = next((x['name']
                                        for x in shared_folders
                                        if x['uid'] == shared_folder_uid),
                                       None)
                    edit_add_prompt = f"{count_prompt} ({_b('E')})dit, "\
                                      f"({_b('A')})dd to {folder_name}, "\
                                      f"Add to ({_b('F')})older, "
                prompt = f"{edit_add_prompt}({_b('S')})kip, ({_b('I')})gnore, ({_b('Q')})uit"

                command = "a"
                if auto_add is False:
                    command = input(f"{pad}{prompt}> ").lower()
                if (command == "a" or command == "f") and dry_run is False:

                    print(f"{pad}{bcolors.OKGREEN}Adding record to save queue.{bcolors.ENDC}")
                    print("")

                    if command == "f":
                        shared_folder_uid = self._get_shared_folder(params, pad, gateway_context)

                    content.shared_folder_uid = shared_folder_uid

                    if content.record_type == "pamUser" and resource_has_admin is False:
                        while True:
                            yn = input(f"{parent_content.description} does not have an administrator. "
                                       "Do you want to make this user the administrator? [Y/N]> ").lower()
                            if yn == "":
                                continue
                            if yn[0] == "n":
                                break
                            if yn[1] == "y":
                                acl.is_admin = True
                                break

                    return PromptResult(
                        action=PromptActionEnum.ADD,
                        acl=acl,
                        content=content
                    )

                elif command == "e" and dry_run is False:
                    self._edit_record(content, pad, editable)
                    break

                elif command == "i":
                    return PromptResult(
                        action=PromptActionEnum.IGNORE,
                        acl=acl,
                        content=content
                    )

                elif command == "s":
                    print(f"{pad}{bcolors.OKBLUE}Skipping record{bcolors.ENDC}")

                    return PromptResult(
                        action=PromptActionEnum.SKIP,
                        acl=acl,
                        content=content
                    )
                elif command == "q":
                    raise QuitException()
            print()

    def _find_user_record(self, params: KeeperParams, context: Optional[Any] = None) -> Optional[TypedRecord]:

        gateway_context = context.get("gateway_context")  # type: GatewayContext
        record_link = context.get("record_link")  # type: RecordLink

        # Get the latest records
        params.sync_data = True

        # Make a list of all records in the shared folders.
        # We will use this to check if a selected user is in the shared folders.
        shared_record_uids = []
        for shared_folder in gateway_context.get_shared_folders(params):
            folder = shared_folder.get("folder")
            if "records" in folder:
                for record in folder["records"]:
                    shared_record_uids.append(record.get("record_uid"))

        logging.debug(f"shared folders record uid {shared_record_uids}")

        while True:
            user_search = input("Enter an user to search for [ENTER/RETURN to quit]> ")
            if user_search == "":
                return None

            # Search for record with the search string.
            # Currently, this only works with TypedRecord, version 3.
            user_record = list(vault_extensions.find_records(
                params,
                search_str=user_search,
                record_version=3
            ))
            if len(user_record) == 0:
                print(f"{bcolors.FAIL}Could not find any record.{bcolors.ENDC}")

            # Find usable admin records.
            admin_search_results = []  # type: List[AdminSearchResult]
            for record in user_record:

                user_record = vault.KeeperRecord.load(params, record.record_uid)
                if user_record.record_type == "pamUser":

                    # Does the record exist in the gateway shared folder?
                    # We want to filter our other gateway's pamUser, or it will get overwhelming.
                    if user_record.record_uid not in shared_record_uids:
                        logging.debug(f"pamUser {record.title}, {user_record.record_uid} not in shared "
                                      "folder, skip")
                        continue

                    # # If a pamUser, make sure the user is part of our configuration
                    # record_rotation = params.record_rotation_cache.get(record.record_uid)
                    # if record_rotation is not None:
                    #     configuration_uid = record_rotation.get("configuration_uid")
                    #     if configuration_uid is None or configuration_uid == "":
                    #         logging.debug(f"pamUser {record.title}, {record.record_uid} does not have a controller, "
                    #                       "skip")
                    #         continue
                    #     if configuration_uid != gateway_context.configuration_uid:
                    #         logging.debug(f"pamUser {record.title}, {record.record_uid} controller is not this "
                    #                       " controller, skip")
                    #         continue
                    # else:
                    #     logging.debug(f"pamUser {record.title}, {record.record_uid} does not have a rotation
                    #     settings.")

                    # If the record does not exist in the record linking, it's orphaned; accept it
                    # If it does exist, then check if it belonged to a directory.
                    # Very unlikely a user that belongs to a database or another machine can be used.

                    record_vertex = record_link.get_record_link(user_record.record_uid)
                    is_directory_user = False
                    if record_vertex is not None:
                        parent_record_uid = record_link.get_parent_record_uid(user_record.record_uid)
                        parent_record = vault.TypedRecord.load(params, parent_record_uid)  # type: Optional[TypedRecord]
                        if parent_record is not None:
                            is_directory_user = self._is_directory_user(parent_record.record_type)
                            if is_directory_user is False:
                                logging.debug(f"pamUser parent for {user_record.title}, "
                                              "{user_record.record_uid} is not a directory, skip")
                                continue

                        else:
                            logging.debug(f"pamUser {user_record.title}, {user_record.record_uid} does not have record "
                                          "linking vertex.")
                    else:
                        logging.debug(f"pamUser {user_record.title}, {user_record.record_uid} does not have record "
                                      "linking vertex.")

                    admin_search_results.append(
                        AdminSearchResult(
                            record=user_record,
                            is_directory_user=is_directory_user,
                            is_pam_user=True
                        )
                    )

                # Else this is a non-PAM record.
                # Make sure it has a login, password, private key
                else:
                    logging.debug(f"{record.record_uid} is not a pamUser")
                    login_field = next((x for x in record.fields if x.type == "login"), None)
                    password_field = next((x for x in record.fields if x.type == "password"), None)
                    private_key_field = next((x for x in record.fields if x.type == "keyPair"), None)

                    if login_field is not None and (password_field is not None or private_key_field is not None):
                        admin_search_results.append(
                            AdminSearchResult(
                                record=record,
                                is_directory_user=False,
                                is_pam_user=False
                            )
                        )
                    else:
                        logging.debug(f"{record.title} is missing full credentials, skip")

            user_index = 1

            admin_search_results = sorted(admin_search_results,
                                          key=lambda x: x.is_pam_user,
                                          reverse=True)

            has_local_user = False
            for admin_search_result in admin_search_results:
                is_local_user = False
                if admin_search_result.record.record_type != "pamUser":
                    has_local_user = True
                    is_local_user = True

                print(f"{bcolors.HEADER}[{user_index}] {bcolors.ENDC}"
                      f"{_b('* ') if is_local_user is True else ''}"
                      f"{admin_search_result.record.title} "
                      f'{"(Directory User)" if admin_search_result.is_directory_user is True else ""}')
                user_index += 1

            if has_local_user is True:
                print(f"{bcolors.BOLD}* Not a PAM User record. "
                      f"A PAM User would be generated from this record.{bcolors.ENDC}")

            select = input("Enter line number of user record to use, enter/return to refind the search, "
                           f"or {_b('Q')} to quit search. > ").lower()
            if select == "":
                continue
            elif select[0] == "q":
                return None
            else:
                try:
                    return admin_search_results[int(select) - 1].record  # type: TypedRecord
                except IndexError:
                    print(f"{bcolors.FAIL}Entered row index does not exists.{bcolors.ENDC}")
                    continue

    @staticmethod
    def _handle_admin_record_from_record(record: TypedRecord, content: DiscoveryObject, indent: int = 0,
                                         context: Optional[Any] = None) -> Optional[PromptResult]:

        params = context.get("param")  # type: KeeperParams
        gateway_context = context.get("gateway_context")  # type: GatewayContext

        # Is this a pamUser record?
        # Return the record UID and set its ACL to be the admin.
        if record.record_type == "pamUser":
            return PromptResult(
                action=PromptActionEnum.ADD,
                acl=UserAcl(is_admin=True),
                record_uid=record.record_uid,
            )

        # If we are here, this was not a pamUser
        # We need to duplicate the record.
        # But confirm first

        # Get fields from the old record.
        # Copy them into the fields.
        login_field = next((x for x in record.fields if x.type == "login"), None)
        password_field = next((x for x in record.fields if x.type == "password"), None)
        private_key_field = next((x for x in record.fields if x.type == "keyPair"), None)

        content.set_field_value("login", login_field.value)
        if password_field is not None:
            content.set_field_value("password", password_field.value)
        if private_key_field is not None:
            value = private_key_field.value
            if value is not None and len(value) > 0:
                value = value[0]
                private_key = value.get("privateKey")
                if private_key is not None:
                    content.set_field_value("private_key", private_key)

        # Check if we have more than one shared folder.
        # If we have one, confirm about adding the user.
        # If multiple shared folders, allow user to select which one.
        shared_folders = gateway_context.get_shared_folders(params)
        if len(shared_folders) == 0:
            while True:
                yn = input(f"Create a PAM User record from {record.title}? [Y/N]>").lower()
                if yn == "":
                    continue
                elif yn[0] == "n":
                    return None
                elif yn[0] == "y":
                    content.shared_folder_uid = gateway_context.default_shared_folder_uid
        else:
            folder_name = next((x['name']
                                for x in shared_folders
                                if x['uid'] == gateway_context.default_shared_folder_uid),
                               None)
            while True:
                afq = input(f"({_b('A')})dd user to {folder_name}, "
                            f"Add user to ({_b('F')})older, "
                            f"({_b('Q')})uit >").lower()
                if afq == "":
                    continue
                if afq[0] == "a":
                    content.shared_folder_uid = gateway_context.default_shared_folder_uid
                    break
                elif afq[0] == "f":
                    shared_folder_uid = PAMGatewayActionDiscoverResultProcessCommand._get_shared_folder(
                        params, "", gateway_context)
                    if shared_folder_uid is not None:
                        content.shared_folder_uid = shared_folder_uid
                        break

        return PromptResult(
            action=PromptActionEnum.ADD,
            acl=UserAcl(is_admin=True),
            content=content,
            note=f"This record replaces record {record.title} ({record.record_uid}). "
                 "The password on that record will not be rotated."
        )

    def _prompt_admin(self, parent_vertex: DAGVertex, content: DiscoveryObject, acl: UserAcl,
                      indent: int = 0, context: Optional[Any] = None) -> PromptResult:

        if content is None:
            raise Exception("The admin content was not passed in to prompt the user.")

        params = context.get("params")

        parent_content = DiscoveryObject.get_discovery_object(parent_vertex)

        print("")
        while True:

            print(f"{bcolors.BOLD}{parent_content.description} does not have an administrator user.{bcolors.ENDC}")

            action = input("Would you like to "
                           f"({_b('A')})dd new administrator user, "
                           f"({_b('F')})ind an existing admin, or "
                           f"({_b('S')})kip add? > ").lower()

            if action == "":
                continue

            if action[0] == 'a':
                prompt_result = self._prompt(
                    vertex=None,
                    parent_vertex=parent_vertex,
                    content=content,
                    acl=acl,
                    context=context,
                    indent=indent + 2
                )
                login = content.get_field_value("login")
                if login is None or login == "":
                    print("")
                    print(f"{bcolors.FAIL}A value is needed for the login field.{bcolors.ENDC}")
                    continue

                print(f"{bcolors.OKGREEN}Adding admin record to save queue.{bcolors.ENDC}")
                return prompt_result
            elif action[0] == 'f':
                record = self._find_user_record(params, context=context)
                if record is not None:
                    admin_prompt_result = self._handle_admin_record_from_record(
                        record=record,
                        content=content,
                        context=context
                    )
                    if admin_prompt_result is not None:
                        if admin_prompt_result.action == PromptActionEnum.ADD:
                            print(f"{bcolors.OKGREEN}Adding admin record to save queue.{bcolors.ENDC}")
                        return admin_prompt_result
            elif action[0] == 's':
                return PromptResult(
                    action=PromptActionEnum.SKIP
                )
            print("")

    @staticmethod
    def _prompt_confirm_add(bulk_add_records: List[BulkRecordAdd]):

        """
        If we quit, we want to ask the user if they want to add record for discovery objects that they selected
        for addition.
        """

        print("")
        count = len(bulk_add_records)
        if count == 1:
            msg = (f"{bcolors.BOLD}There is 1 record queued to be added to your vault. "
                   f"Do you wish to add it? [Y/N]> {bcolors.ENDC}")
        else:
            msg = (f"{bcolors.BOLD}There are {count} records queue to be added to your vault. "
                   f"Do you wish to add them? [Y/N]> {bcolors.ENDC}")
        while True:
            yn = input(msg).lower()
            if yn == "":
                continue
            if yn[0] == "y":
                return True
            elif yn[0] == "n":
                return False
            print(f"{bcolors.FAIL}Did not get 'Y' or 'N'{bcolors.ENDC}")

    @staticmethod
    def _prepare_record(content: DiscoveryObject, context: Optional[Any] = None) -> (Any, str):

        """
        Prepare the Vault record side.

        It's not created here.
        It will be created at the end of the processing run in bulk.
        We to build a record to get a record UID.

        :params content: The discovery object instance.
        :params context: Optionally, it will contain information set from the run() method.
        :returns: Returns an unsaved Keeper record instance.
        """

        params = context.get("params")

        # DEFINE V3 RECORD

        # Create an instance of a vault record to structure the data
        record = vault.TypedRecord()
        record.type_name = content.record_type
        record.record_uid = utils.generate_uid()
        record.record_key = utils.generate_aes_key()
        record.title = content.title
        for field in content.fields:
            field_args = {
                "field_type": field.type,
                "field_value": field.value
            }
            if field.type != field.label:
                field_args["field_label"] = field.label
            record_field = vault.TypedField.new_field(**field_args)
            record_field.required = field.required
            record.fields.append(record_field)

        folder = params.folder_cache.get(content.shared_folder_uid)
        folder_key = None  # type: Optional[bytes]
        if isinstance(folder, subfolder.SharedFolderFolderNode):
            shared_folder_uid = folder.shared_folder_uid
        elif isinstance(folder, subfolder.SharedFolderNode):
            shared_folder_uid = folder.uid
        else:
            shared_folder_uid = None
        if shared_folder_uid and shared_folder_uid in params.shared_folder_cache:
            shared_folder = params.shared_folder_cache.get(shared_folder_uid)
            folder_key = shared_folder.get('shared_folder_key_unencrypted')

        # DEFINE PROTOBUF FOR RECORD

        record_add_protobuf = record_pb2.RecordAdd()
        record_add_protobuf.record_uid = utils.base64_url_decode(record.record_uid)
        record_add_protobuf.record_key = crypto.encrypt_aes_v2(record.record_key, params.data_key)
        record_add_protobuf.client_modified_time = utils.current_milli_time()
        record_add_protobuf.folder_type = record_pb2.user_folder
        if folder:
            record_add_protobuf.folder_uid = utils.base64_url_decode(folder.uid)
            if folder.type == 'shared_folder':
                record_add_protobuf.folder_type = record_pb2.shared_folder
            elif folder.type == 'shared_folder_folder':
                record_add_protobuf.folder_type = record_pb2.shared_folder_folder
            if folder_key:
                record_add_protobuf.folder_key = crypto.encrypt_aes_v2(record.record_key, folder_key)

        data = vault_extensions.extract_typed_record_data(record)
        json_data = api.get_record_data_json_bytes(data)
        record_add_protobuf.data = crypto.encrypt_aes_v2(json_data, record.record_key)

        # refs = vault_extensions.extract_typed_record_refs(record)
        # for ref in refs:
        #     ref_record_key = None  # type: Optional[bytes]
        #     if record.linked_keys:
        #         ref_record_key = record.linked_keys.get(ref)
        #     if not ref_record_key:
        #         ref_record = vault.KeeperRecord.load(params, ref)
        #         if ref_record:
        #             ref_record_key = ref_record.record_key
        #
        #     if ref_record_key:
        #         link = record_pb2.RecordLink()
        #         link.record_uid = utils.base64_url_decode(ref)
        #         link.record_key = crypto.encrypt_aes_v2(ref_record_key, record.record_key)
        #         add_record.record_links.append(link)

        if params.enterprise_ec_key:
            audit_data = vault_extensions.extract_audit_data(record)
            if audit_data:
                record_add_protobuf.audit.version = 0
                record_add_protobuf.audit.data = crypto.encrypt_ec(
                    json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

        return record_add_protobuf, record.record_uid

    @classmethod
    def _create_records(cls, bulk_add_records: List[BulkRecordAdd], context: Optional[Any] = None) -> (
            BulkProcessResults):

        if len(bulk_add_records) == 1:
            print("Adding the record to the Vault ...")
        else:
            print(f"Adding {len(bulk_add_records)} records to the Vault ...")

        params = context.get("params")
        gateway_context = context.get("gateway_context")

        build_process_results = BulkProcessResults()

        # STEP 1 - Batch add new records

        # Generate a list of RecordAdd instance.
        # In BulkRecordAdd they will be the record instance.
        record_add_list = [r.record for r in bulk_add_records]  # type: List[record_pb2.RecordAdd]

        records_per_request = 999

        add_results = []  # type: List[record_pb2.RecordModifyResult]
        logging.debug("adding record in batches")
        while record_add_list:
            logging.debug(f"* adding batch")
            rq = record_pb2.RecordsAddRequest()
            rq.client_time = utils.current_milli_time()
            rq.records.extend(record_add_list[:records_per_request])
            record_add_list = record_add_list[records_per_request:]
            rs = api.communicate_rest(params, rq, 'vault/records_add', rs_type=record_pb2.RecordsModifyResponse)
            add_results.extend(rs.records)

        logging.debug(f"add_result: {add_results}")

        if len(add_results) != len(bulk_add_records):
            logging.debug(f"attempted to batch add {len(bulk_add_records)} record(s), "
                          f"only have {len(add_results)} results.")

        # STEP 3 - Add rotation settings.
        # Use the list we passed in, find the results, and add if the additions were successful.

        # For the records passed in to be created.
        for bulk_record in bulk_add_records:
            # Grab the type Keeper record instance, and title from that record.
            pb_add_record = bulk_record.record
            title = bulk_record.title

            rotation_disabled = False

            # Find the result for this record.
            result = None
            for x in add_results:
                logging.debug(f"{pb_add_record.record_uid} vs {x.record_uid}")
                if pb_add_record.record_uid == x.record_uid:
                    result = x
                    break

            # If we didn't get a result, then don't add the rotation settings.
            if result is None:
                build_process_results.failure.append(
                    BulkRecordFail(
                        title=title,
                        error="No status on addition to Vault. Cannot determine if added or not."
                    )
                )
                logging.debug(f"Did not get a result when adding record {title}")
                continue

            # Check if addition failed. If it did fail, don't add the rotation settings.
            success = (result.status == record_pb2.RecordModifyResult.DESCRIPTOR.values_by_name['RS_SUCCESS'].number)
            status = record_pb2.RecordModifyResult.DESCRIPTOR.values_by_number[result.status].name

            if success is False:
                build_process_results.failure.append(
                    BulkRecordFail(
                        title=title,
                        error=status
                    )
                )
                logging.debug(f"Had problem adding record for {title}: {status}")
                continue

            rq = router_pb2.RouterRecordRotationRequest()
            rq.recordUid = url_safe_str_to_bytes(bulk_record.record_uid)
            rq.revision = 0

            # Set the gateway/configuration that this record should be connected.
            rq.configurationUid = url_safe_str_to_bytes(gateway_context.configuration_uid)

            # Only set the resource if the record type is a PAM User.
            # Machines, databases, and directories have a login/password in the record that indicates who the admin is.
            if bulk_record.record_type == "pamUser":
                rq.resourceUid = url_safe_str_to_bytes(bulk_record.parent_record_uid)

            # Right now, the schedule and password complexity are not set. This would be part of a rule engine.
            rq.schedule = ''
            rq.pwdComplexity = b''
            rq.disabled = rotation_disabled

            router_set_record_rotation_information(params, rq)

            build_process_results.success.append(
                BulkRecordSuccess(
                    title=title,
                    record_uid=bulk_record.record_uid
                )
            )

        params.sync_data = True

        return build_process_results

    @classmethod
    def _convert_records(cls, bulk_convert_records: List[BulkRecordConvert], context: Optional[Any] = None):

        params = context.get("params")
        gateway_context = context.get("gateway_context")

        for bulk_convert_record in bulk_convert_records:

            record = vault.KeeperRecord.load(params, bulk_convert_record.record_uid)

            rotation_disabled = False

            rq = router_pb2.RouterRecordRotationRequest()
            rq.recordUid = url_safe_str_to_bytes(bulk_convert_record.record_uid)
            record_rotation_revision = params.record_rotation_cache.get(bulk_convert_record.record_uid)
            rq.revision = record_rotation_revision.get('revision') if record_rotation_revision else 0

            # Set the gateway/configuration that this record should be connected.
            rq.configurationUid = url_safe_str_to_bytes(gateway_context.configuration_uid)

            # Only set the resource if the record type is a PAM User.
            # Machines, databases, and directories have a login/password in the record that indicates who the admin is.
            if record.record_type == "pamUser":
                rq.resourceUid = url_safe_str_to_bytes(bulk_convert_record.parent_record_uid)
            else:
                rq.resourceUid = None

            # Right now, the schedule and password complexity are not set. This would be part of a rule engine.
            rq.schedule = ''
            rq.pwdComplexity = b''
            rq.disabled = rotation_disabled

            router_set_record_rotation_information(params, rq)

        params.sync_data = True

    @staticmethod
    def _get_directory_info(domain: str,
                            skip_users: bool = False,
                            context: Optional[Any] = None) -> Optional[DirectoryInfo]:
        """
        Get information about this record from the vault records.

        """

        params = context.get("params")
        gateway_context = context.get("gateway_context")

        directory_info = DirectoryInfo()

        # Find the all directory records, in for this gateway, that have a domain that matches what we are looking for.
        for directory_record in vault_extensions.find_records(params, record_type="pamDirectory"):
            directory_record = vault.TypedRecord.load(params,
                                                      directory_record.record_uid)  # type: Optional[TypedRecord]

            info = params.record_rotation_cache.get(directory_record.record_uid)
            if info is None:
                continue

            # Make sure this user is part of this gateway.
            if info.get("configuration_uid") != gateway_context.configuration_uid:
                continue

            domain_field = directory_record.get_typed_field("text", label="domainName")
            if len(domain_field.value) == 0 or domain_field.value[0] == "":
                continue

            if domain_field.value[0].lower() != domain.lower():
                continue

            directory_info.directory_record_uids.append(directory_record.record_uid)

        if directory_info.has_directories is True and skip_users is False:

            for user_record in vault_extensions.find_records(params, record_type="pamUser"):
                info = params.record_rotation_cache.get(user_record.record_uid)
                if info is None:
                    continue

                if info.get("resource_uid") is None or info.get("resource_uid") == "":
                    continue

                # If the user's belongs to a directory, and add it to the directory user list.
                if info.get("resource_uid") in info.directory_record_uids:
                    directory_info.directory_user_record_uids.append(user_record.record_uid)

        return directory_info

    def execute(self, params: KeeperParams, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        job_id = kwargs.get("job_id")
        auto_add = kwargs.get("add_all", False)

        # Right now, keep dry_run False. We might add it back in.
        dry_run = kwargs.get("dry_run", False)

        configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))
        for configuration_record in configuration_records:

            gateway_context = GatewayContext.from_configuration_uid(params, configuration_record.record_uid)
            if gateway_context is None:
                continue

            record_cache = self._build_record_cache(
                params=params,
                gateway_context=gateway_context
            )

            # Get the current job.
            # There can only be one active job.
            # This will give us the sync point for the delta
            jobs = Jobs(record=configuration_record, params=params)
            job_item = jobs.current_job
            if job_item is None:
                continue

            # If this is not the job we are looking for, continue to the next gateway.
            if job_item.job_id != job_id:
                continue

            if job_item.end_ts is None:
                print(f'{bcolors.FAIL}Discovery job is currently running. Cannot process.{bcolors.ENDC}')
                return
            if job_item.success is False:
                print(f'{bcolors.FAIL}Discovery job failed. Cannot process.{bcolors.ENDC}')
                return

            process = Process(
                record=configuration_record,
                job_id=job_item.job_id,
                params=params,
                logger=logging
            )

            if dry_run is True:
                if auto_add is True:
                    logging.debug("dry run has been set, disable auto add.")
                    auto_add = False

                print(f"{bcolors.HEADER}The DRY RUN flag has been set. The rule engine will not add any records. "
                      f"You will not be prompted to edit or add records.{bcolors.ENDC}")
                print("")

            if auto_add is True:
                print(f"{bcolors.HEADER}The AUTO ADD flag has been set. All found items will be added.{bcolors.ENDC}")
                print("")

            try:
                results = process.run(
                    # Prompt user the about adding records
                    prompt_func=self._prompt,

                    # Prompt user for an admin for a resource
                    prompt_admin_func=self._prompt_admin,

                    # If quit, confirm if the user wants to add records
                    prompt_confirm_add_func=self._prompt_confirm_add,

                    # Prepare records and place in queue; does not add record to vault
                    record_prepare_func=self._prepare_record,

                    # Add record to the vault, protobuf, and record-linking graph
                    record_create_func=self._create_records,

                    # This function will take existing pamUser record and make them belong to this
                    #  gateway.
                    record_convert_func=self._convert_records,

                    # A function to get directory users
                    directory_info_func=self._get_directory_info,

                    # Provides a cache of the record key to record UID.
                    record_cache=record_cache,

                    # Commander-specific context.
                    # Record link will be added by Process run as "record_link"
                    context={
                        "params": params,
                        "gateway_context": gateway_context,
                        "dry_run": dry_run,
                        "auto_add": auto_add
                    }
                )

                logging.debug(f"Results: {results}")

                print("")
                if results is not None and results.num_results > 0:
                    print(f"{bcolors.OKGREEN}Successfully added {results.success_count} "
                          f"record{'s' if results.success_count != 1 else ''}.{bcolors.ENDC}")
                    if results.has_failures is True:
                        print(f"{bcolors.FAIL}There were {results.failure_count} "
                              f"failure{'s' if results.failure_count != 1 else ''}.{bcolors.ENDC}")
                        for fail in results.failure:
                            print(f" * {fail.title}: {fail.error}")
                else:
                    print(f"{bcolors.FAIL}No records have been added.{bcolors.ENDC}")

            except NoDiscoveryDataException:
                print(f"{bcolors.OKGREEN}All items have been added for this discovery job.{bcolors.ENDC}")

            except Exception as err:
                print(f"{bcolors.FAIL}Could not process discovery: {err}{bcolors.ENDC}")
                raise err

            return

        print(f"{bcolors.HEADER}Could not find the Discovery job.{bcolors.ENDC}")
        print("")
