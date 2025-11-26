from __future__ import annotations
import argparse
import logging
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, PAM_USER
from ...display import bcolors
from ... import vault
from ...discovery_common.record_link import RecordLink
from ...discovery_common.types import UserAcl
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMDebugACLCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-debug-acl')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID.')

    parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                        help='User UID.')
    parser.add_argument('--parent-uid', '-r', required=True, dest='parent_uid', action='store',
                        help='Resource or Configuration UID.')
    parser.add_argument('--debug-gs-level', required=False, dest='debug_level', action='store',
                        help='GraphSync debug level. Default is 0', type=int, default=0)

    def get_parser(self):
        return PAMDebugACLCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        user_uid = kwargs.get("user_uid")
        parent_uid = kwargs.get("parent_uid")
        debug_level = int(kwargs.get("debug_level", 0))

        print("")

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        record_link = RecordLink(record=gateway_context.configuration,
                                 params=params,
                                 logger=logging,
                                 debug_level=debug_level)

        user_record = vault.KeeperRecord.load(params, user_uid)  # type: Optional[TypedRecord]
        if user_record is None:
            print(f"{bcolors.FAIL}The user record does not exists.{bcolors.ENDC}")
            return

        print(f"{bcolors.BOLD}The user record is {user_record.title}{bcolors.ENDC}")

        if user_record.record_type != PAM_USER:
            print(f"{bcolors.FAIL}The user record is not a PAM User record.{bcolors.ENDC}")
            return

        parent_record = vault.KeeperRecord.load(params, parent_uid)  # type: Optional[TypedRecord]
        if parent_record is None:
            print(f"{bcolors.FAIL}The parent record does not exists.{bcolors.ENDC}")
            return

        print(f"{bcolors.BOLD}The parent record is {parent_record.title}{bcolors.ENDC}")

        if parent_record.record_type.startswith("pam") is False:
            print(f"{bcolors.FAIL}The parent record is not a PAM record.{bcolors.ENDC}")
            return

        if parent_record.record_type == PAM_USER:
            print(f"{bcolors.FAIL}The parent record cannot be a PAM User record.{bcolors.ENDC}")
            return

        parent_is_config = parent_record.record_type.endswith("Configuration")

        # Get the ACL between the user and the parent.
        # It might not exist.
        acl_exists = True
        acl = record_link.get_acl(user_uid, parent_uid)
        if acl is None:
            print("No existing ACL, creating an ACL.")
            acl = UserAcl()
            acl_exists = False

        # Make sure the ACL for cloud user is set.
        if parent_is_config is True:
            print("Is an IAM user.")
            acl.is_iam_user = True

        rl_parent_vertex = record_link.dag.get_vertex(parent_uid)
        if rl_parent_vertex is None:
            print("Parent record linking vertex did not exists, creating one.")
            rl_parent_vertex = record_link.dag.add_vertex(parent_uid)

        rl_user_vertex = record_link.dag.get_vertex(user_uid)
        if rl_user_vertex is None:
            print("User record linking vertex did not exists, creating one.")
            rl_user_vertex = record_link.dag.add_vertex(user_uid)

        has_admin_uid = record_link.get_admin_record_uid(parent_uid)
        if has_admin_uid is not None:
            print("Parent record already has an admin.")
        else:
            print("Parent record does not have an admin.")

        belongs_to_vertex = record_link.acl_has_belong_to_record_uid(user_uid)
        if belongs_to_vertex is None:
            print("User record does not belong to any resource, or provider.")
        else:
            if belongs_to_vertex.active is False:
                print("User record belongs to an inactive parent.")
            else:
                print("User record belongs to another record.")

        print("")

        while True:
            res = input(f"Does this user belong to {parent_record.title} Y/N >").lower()
            if res == "y":
                acl.belongs_to = True
                break
            elif res == "n":
                acl.belongs_to = False
                break

        if has_admin_uid is None:
            while True:
                res = input(f"Is this user the admin of {parent_record.title} Y/N >").lower()
                if res == "y":
                    acl.is_admin = True
                    break
                elif res == "n":
                    acl.is_admin = False
                    break

        try:
            record_link.belongs_to(user_uid, parent_uid, acl=acl)
            record_link.save()
            print(f"{bcolors.OKGREEN}Updated/added ACL between {user_record.title} and "
                  f"{parent_record.title}{bcolors.ENDC}")
        except Exception as err:
            print(f"{bcolors.FAIL}Could not update ACL: {err}{bcolors.ENDC}")
