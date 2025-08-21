from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase
from ...display import bcolors
from ... import vault
from ...proto import router_pb2
from ...sync_down import sync_down
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes
from ..pam.router_helper import router_set_record_rotation_information
from ...discovery_common.record_link import RecordLink
from ...discovery_common.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from ...discovery_common.types import UserAcl, UserAclRotationSettings
import re
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMDebugRotationSettingsCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-debug-rotation')

    # The record to base everything on.
    parser.add_argument('--user-record-uid', '-i', required=True, dest='user_record_uid', action='store',
                        help='PAM user record UID.')
    parser.add_argument('--configuration-record-uid', '-c', required=False,
                        dest='configuration_record_uid', action='store', help='PAM configuration record UID.')
    parser.add_argument('--resource-record-uid', '-r', required=False,
                        dest='resource_record_uid',  action='store', help='PAM resource record UID.')
    parser.add_argument('--noop', required=False, dest='noop', action='store_true',
                        help='User is part of a No Operation.')
    parser.add_argument('--force', required=False, dest='force', action='store_true',
                        help='Force reset of the rotation settings.')
    parser.add_argument('--dry-run', required=False, dest='dry_run', action='store_true',
                        help='Do not create or update anything.')

    def get_parser(self):
        return PAMDebugRotationSettingsCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        user_record_uid = kwargs.get("user_record_uid")
        resource_record_uid = kwargs.get("resource_record_uid")
        configuration_record_uid = kwargs.get("configuration_record_uid")
        noop = kwargs.get("noop", False)
        force = kwargs.get("force", False)
        dry_run = kwargs.get("dry_run", False)

        print("")

        user_record = vault.KeeperRecord.load(params, user_record_uid)  # type: Optional[TypedRecord]
        if user_record is None:
            print(f"{bcolors.FAIL}The PAM user record does not exists.{bcolors.ENDC}")
            return

        if user_record.record_type != PAM_USER:
            print(f"{bcolors.FAIL}The PAM user record is a {PAM_USER}. "
                  f"The record is {user_record.record_type}{bcolors.ENDC}")
            return

        record_rotation = params.record_rotation_cache.get(user_record_uid)
        if record_rotation is None:
            print(f"{bcolors.WARNING}The protobuf rotation settings are missing. Attempting to create.{bcolors.ENDC}")

            if configuration_record_uid is None:
                print(f"{bcolors.FAIL}Cannot determine PAM configuration, please set the "
                      f"-c, --configuration-record-uid parameter for this command.{bcolors.ENDC}")
                return

            configuration_record = vault.KeeperRecord.load(params,
                                                           configuration_record_uid)  # type: Optional[TypedRecord]
            if configuration_record is None:
                print(f"{bcolors.FAIL}Configuration record does not exists.{bcolors.ENDC}")
                return

            if re.search(r'^pam.*Configuration$', configuration_record.record_type) is None:
                print(
                    f"{bcolors.FAIL}The configuration record is not a configuration record. "
                    f"It's {configuration_record.record_type} record.{bcolors.ENDC}")
                return

            if resource_record_uid is None:
                while True:
                    yn = input("The resource record UID was not set. "
                               "This user does not belongs to a machine, database, or directory; "
                               "It's an IAM, Azure, or Domain Controller user? [Y/N]").lower()
                    if yn == "n":
                        print(f"{bcolors.FAIL}Since a resource is needed, please set --resource-record-uid, -r "
                              f"parameter for the this command.{bcolors.ENDC}")
                        return
                    elif yn == "y":
                        break

            if resource_record_uid is not None:

                resource_record = vault.KeeperRecord.load(params,
                                                          resource_record_uid)  # type: Optional[TypedRecord]
                if resource_record is None:
                    print(f"{bcolors.FAIL}The resource record does not exists.{bcolors.ENDC}")
                    return

                if resource_record.record_type not in [PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY]:
                    print(f"{bcolors.FAIL}The resource is NOT a "
                          f"{PAM_MACHINE}, {PAM_DATABASE}, or {PAM_DIRECTORY} record. "
                          f"It's a {resource_record.record_type}.{bcolors.ENDC}")
                    return

            parent_uid = resource_record_uid or configuration_record_uid

            # Create rotation settings for the pamUser.
            rq = router_pb2.RouterRecordRotationRequest()
            rq.recordUid = url_safe_str_to_bytes(user_record_uid)
            rq.revision = 0
            rq.configurationUid = url_safe_str_to_bytes(configuration_record_uid)
            rq.resourceUid = url_safe_str_to_bytes(parent_uid)
            rq.schedule = ''
            rq.pwdComplexity = b''
            rq.disabled = False

            if dry_run is False:
                router_set_record_rotation_information(params, rq)

                params.sync_data = True
                sync_down(params)

                record_rotation = params.record_rotation_cache.get(user_record_uid)
                if record_rotation is None:
                    print(f"{bcolors.FAIL}Protobuf rotation settings did not create.{bcolors.ENDC}")
                    return
            else:
                print(f"{bcolors.OKBLUE}DRY RUN: Would have created the protobuf rotation settings.{bcolors.ENDC}")
                record_rotation = {
                    "configuration_uid": configuration_record_uid,
                    "resource_uid": resource_record_uid
                }

        configuration_record_uid = record_rotation.get("configuration_uid")
        if configuration_record_uid is None:
            print(f"{bcolors.FAIL}Record does not have the PAM Configuration set.{bcolors.ENDC}")
            return

        print(f"{bcolors.BOLD}Configuration Record UID{bcolors.ENDC}: {configuration_record_uid}")

        configuration_record = vault.KeeperRecord.load(params,
                                                       configuration_record_uid)  # type: Optional[TypedRecord]
        if configuration_record is None:
            print(f"{bcolors.FAIL}Configuration record does not exists.{bcolors.ENDC}")
            return

        resource_record_uid = record_rotation.get("resource_uid")
        if resource_record_uid is not None:

            print(f"{bcolors.BOLD}Resource Record UID{bcolors.ENDC}: {resource_record_uid}")

            resource_record = vault.KeeperRecord.load(params,
                                                      resource_record_uid)  # type: Optional[TypedRecord]
            if resource_record is None:
                print(f"{bcolors.FAIL}The resource record does not exists.{bcolors.ENDC}")
                return

            if resource_record.record_type not in [PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY]:
                print(f"{bcolors.FAIL}The resource is a {PAM_MACHINE}, {PAM_DATABASE}, or {PAM_DIRECTORY} record. "
                      f"It's a {resource_record.record_type}.{bcolors.ENDC}")
                return

        record_link = RecordLink(record=configuration_record, params=params)

        parent_uid = resource_record_uid or configuration_record_uid
        parent_vertex = record_link.get_record_link(parent_uid)
        if parent_vertex is None:
            parent_type = "configuration"
            if resource_record_uid is not None:
                parent_type = "resource"
            print(f"{bcolors.FAIL}Could not find the parent linking vertex for the {parent_type}.{bcolors.ENDC}")
            return

        print(f"{bcolors.BOLD}User Record UID{bcolors.ENDC}: {user_record_uid}")

        user_vertex = record_link.get_record_link(user_record_uid)
        if user_vertex is None:
            print(f"{bcolors.WARNING}The user vertex is missing; creating.{bcolors.ENDC}")
            record_link.dag.add_vertex(uid=user_record_uid)

        user_acl = record_link.get_acl(user_record_uid, parent_uid)
        if user_acl is None:
            print(f"{bcolors.WARNING}No ACL exists between the user and the parent; creating.{bcolors.ENDC}")
            user_acl = UserAcl.default()
            user_acl.belongs_to = True

        print("")
        if user_acl.rotation_settings is not None:
            if (force is False and (
                    user_acl.rotation_settings.schedule != ""
                    or user_acl.rotation_settings.pwd_complexity != ""
                    or (user_acl.rotation_settings.saas_record_uid_list is not None
                        and len(user_acl.rotation_settings.saas_record_uid_list) != 0))):
                print(f"{bcolors.FAIL}{user_acl.model_dump_json(indent=4)}{bcolors.ENDC}")
                print(f"{bcolors.FAIL}Rotation settings exist in graph, use --force to reset.{bcolors.ENDC}")
                return

        # Reset the rotation settings.
        user_acl.rotation_settings = UserAclRotationSettings()
        user_acl.rotation_settings.noop = noop
        if resource_record_uid is None:
            user_acl.is_iam_user = True

        # Connect the user to the parent (configuration or resource)
        record_link.belongs_to(user_record_uid, parent_uid, acl=user_acl)

        # If parent is not a configuration, make sure there is a LINK from the resource to the configuration.
        if parent_uid != configuration_record_uid:
            if record_link.get_parent_record_uid(parent_uid) is None:
                print(f"{bcolors.WARNING}Resource record has no LINK to configuration record; "
                      f"creating.{bcolors.ENDC}")
                record_link.belongs_to(configuration_record_uid, parent_uid)

        if dry_run is False:
            record_link.save()

            print(f"{bcolors.OKGREEN}{user_acl.model_dump_json(indent=4)}{bcolors.ENDC}")
            print(f"{bcolors.OKGREEN}Updated the ACL for the user.{bcolors.ENDC}")
        else:
            print(f"{bcolors.OKBLUE}DRY RUN: Would have created this ACL.")
            print(f"{bcolors.OKBLUE}{user_acl.model_dump_json(indent=4)}{bcolors.ENDC}")
