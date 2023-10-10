from __future__ import annotations
import argparse
import logging

from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from .job_status import PAMGatewayActionDiscoverJobStatusCommand
from ..pam.router_helper import router_send_action_to_gateway, print_router_response, router_get_connected_gateways
from ..pam.user_facade import PamUserRecordFacade
from ..pam.pam_dto import GatewayActionDiscoverJobStartInputs, GatewayActionDiscoverJobStart, GatewayAction
from ... import vault_extensions
from ... import vault
from ...proto import pam_pb2
from ...display import bcolors
from discovery_common.jobs import Jobs
from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams


class PAMGatewayActionDiscoverJobStartCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-discover-start-command')
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name of UID.')
    parser.add_argument('--resource', '-r', required=False, dest='resource_uid', action='store',
                        help='UID of the resource record. Set to discover specific resource.')
    parser.add_argument('--lang', required=False, dest='language', action='store', default="en",
                        help='Language')
    parser.add_argument('--skip-machine-dir-users', required=False, dest='include_machine_dir_users',
                        action='store_false', default=True, help='Include directory users found on the machine.')
    parser.add_argument('--inc-azure-aadds', required=False, dest='include_azure_aadds',
                        action='store_true', help='Include Azure Active Directory Domain Service.')
    parser.add_argument('--skip-rules', required=False, dest='skip_rules',
                        action='store_true', help='Skip running the rule engine.')
    parser.add_argument('--skip-machines', required=False, dest='skip_machines',
                        action='store_true', help='Skip discovering machines.')
    parser.add_argument('--skip-databases', required=False, dest='skip_databases',
                        action='store_true', help='Skip discovering databases.')
    parser.add_argument('--skip-directories', required=False, dest='skip_directories',
                        action='store_true', help='Skip discovering directories.')
    parser.add_argument('--skip-cloud-users', required=False, dest='skip_cloud_users',
                        action='store_true', help='Skip discovering cloud users.')

    def get_parser(self):
        return PAMGatewayActionDiscoverJobStartCommand.parser

    @staticmethod
    def make_protobuf_user_map(params: KeeperParams, gateway_context: GatewayContext) -> List[dict]:
        """
        Make a user map for PAM Users.

        The map is used to find existing records.
        Since KSM cannot read the rotation settings using protobuf,
          it cannot match a vault record to a discovered users.
        This map will map a login/DN and parent UID to a record UID.
        """

        user_map = []
        for record in vault_extensions.find_records(params, record_type="pamUser"):
            user_record = vault.KeeperRecord.load(params, record.record_uid)
            user_facade = PamUserRecordFacade()
            user_facade.record = user_record

            info = params.record_rotation_cache.get(user_record.record_uid)
            if info is None:
                continue

            # Make sure this user is part of this gateway.
            if info.get("configuration_uid") != gateway_context.configuration_uid:
                continue

            # If the user Admin Cred Record (i.e., parent) is blank, skip the mapping item
            # This will be a UID string, not 16 bytes.
            if info.get("resource_uid") is None or info.get("resource_uid") == "":
                continue

            user_map.append({
                "user": user_facade.login if user_facade.login != "" else None,
                "dn": user_facade.distinguishedName if user_facade.distinguishedName != "" else None,
                "record_uid": user_record.record_uid,
                "parent_record_uid": info.get("resource_uid")
            })

        logging.debug(f"found {len(user_map)} user map items")

        return user_map

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        # Load the configuration record and get the gateway_uid from the facade.
        gateway = kwargs.get('gateway')

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        jobs = Jobs(record=gateway_context.configuration, params=params)
        current_job_item = jobs.current_job
        if current_job_item is not None:
            if current_job_item.is_running is True:
                print("")
                print(f"{bcolors.FAIL}An discovery job is currently running. "
                      f"Cannot start another until it is finished.{bcolors.ENDC}")
                print(f"To check the status, use the command "
                      f"'{bcolors.OKGREEN}pam action discover status{bcolors.ENDC}'.")
                print(f"To stop and remove the current job, use the command "
                      f"'{bcolors.OKGREEN}pam action discover remove -j {current_job_item.job_id}'.")
                return

            print(f"{bcolors.FAIL}An active discovery job exists for this gateway.{bcolors.ENDC}")
            print("")
            status = PAMGatewayActionDiscoverJobStatusCommand()
            status.execute(params=params)
            print("")

            yn = input("Do you wish to remove the active discovery job and run a new one [Y/N]>").lower()
            while True:
                if yn[0] == "y":
                    jobs.cancel(current_job_item.job_id)
                    break
                elif yn[0] == "n":
                    print(f"{bcolors.FAIL}Not starting a discovery job.{bcolors.ENDC}")
                    return

        action_inputs = GatewayActionDiscoverJobStartInputs(
            configuration_uid=gateway_context.configuration_uid,
            resource_uid=kwargs.get('resource_uid'),
            user_map=gateway_context.encrypt(
                self.make_protobuf_user_map(
                    params=params,
                    gateway_context=gateway_context
                )
            ),

            shared_folder_uid=gateway_context.default_shared_folder_uid,
            language=kwargs.get('language'),

            # Settings
            include_machine_dir_users=kwargs.get('include_machine_dir_users', True),
            include_azure_aadds=kwargs.get('include_azure_aadds', False),
            skip_rules=kwargs.get('skip_rules', False),
            skip_machines=kwargs.get('skip_machines', False),
            skip_databases=kwargs.get('skip_databases', False),
            skip_directories=kwargs.get('skip_directories', False),
            skip_cloud_users=kwargs.get('skip_cloud_users', False)
        )

        conversation_id = GatewayAction.generate_conversation_id()
        router_response = router_send_action_to_gateway(
            params=params,
            gateway_action=GatewayActionDiscoverJobStart(
                inputs=action_inputs,
                conversation_id=conversation_id),
            message_type=pam_pb2.CMT_GENERAL,
            is_streaming=False,
            destination_gateway_uid_str=gateway_context.gateway_uid
        )

        data = self.get_response_data(router_response)
        if data is None:
            print(f"{bcolors.FAIL}The router returned a failure.{bcolors.ENDC}")
            return

        if "has been queued" in data.get("Response", ""):

            print("")
            print("The discovery job is currently running.")
            print(f"To check the status, use the command '{bcolors.OKGREEN}pam action discover status{bcolors.ENDC}'.")
            print(f"To stop and remove the current job, use the command "
                  f"'{bcolors.OKGREEN}pam action discover remove -j <Job ID>'.")
        else:
            print_router_response(router_response, conversation_id)
