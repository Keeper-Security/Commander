from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ...display import bcolors
from ... import vault
from ...discovery_common.record_link import RecordLink
from ...discovery_common.constants import PAM_USER, PAM_MACHINE
from ...discovery_common.types import MachineData, UserData
from ...keeper_dag.types import EdgeType
from ... import __version__
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionServiceEnableCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action service enable')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')

    parser.add_argument('--machine-uid', '-m', required=False, dest='machine_uid', action='store',
                        help='The UID of the Windows Machine record to disable.')
    parser.add_argument('--user-uid', '-u', required=False, dest='user_uid', action='store',
                        help='The UID of the User record to disable.')

    def get_parser(self):
        return PAMActionServiceEnableCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        machine_uid = kwargs.get("machine_uid")
        user_uid = kwargs.get("user_uid")

        print("")

        if machine_uid is None and user_uid is None:
            print(f"{bcolors.FAIL}Either --machine-uid or --user-uid are required. Both are missing.{bcolors.ENDC}")
            print(f"{bcolors.FAIL}  Use --machine-uid to disable service password "
                  "rotation on the machine.{bcolors.ENDC}")
            print(f"{bcolors.FAIL}  Use --user-uid to disable service password rotation for this user.{bcolors.ENDC}")
            return

        if machine_uid is not None and user_uid is not None:
            print(f"{bcolors.FAIL}Both --machine-uid and --user-uid are set; only set one.{bcolors.ENDC}")
            print(f"{bcolors.FAIL}  Use --machine-uid to disable service password "
                  "rotation on the machine.{bcolors.ENDC}")
            print(f"{bcolors.FAIL}  Use --user-uid to disable service password rotation for this user.{bcolors.ENDC}")
            return

        try:
            gateway_context = GatewayContext.from_gateway(params=params,
                                                          gateway=gateway,
                                                          configuration_uid=kwargs.get('configuration_uid'))
            if gateway_context is None:
                print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.{bcolors.ENDC}")
                return
        except MultiConfigurationException as err:
            multi_conf_msg(gateway, err)
            return

        if gateway_context is None:
            print(f"  {self._f('Cannot get gateway information. Gateway may not be up.')}")
            return

        record_link = RecordLink(record=gateway_context.configuration,
                                 params=params,
                                 fail_on_corrupt=False,
                                 agent=f"Cmdr/{__version__}")

        ###############

        if machine_uid is not None:

            # Check to see if the record exists.
            machine_record = vault.KeeperRecord.load(params, machine_uid)  # type: Optional[TypedRecord]
            if machine_record is None:
                print(self._f("The machine record does not exists."))
                return

            # Make sure the record is a PAM Machine.
            if machine_record.record_type != PAM_MACHINE:
                print(self._f("The machine record is not a PAM Machine."))
                return

            # Make sure this machine is linked to the configuration record.
            machine_vertex = record_link.get_record_link(machine_record.record_uid)
            if machine_vertex is None:
                print(self._f("The machine record does not exists in the graph."))
                return

            # Edges from provider and machine might be wrong.
            # Should be a LINK edge, could be an ACL edge.
            if (machine_vertex.get_edge(record_link.dag.get_root, edge_type=EdgeType.LINK) is None and
                    machine_vertex.get_edge(record_link.dag.get_root, edge_type=EdgeType.ACL) is None):
                print(self._f("The machine record does not belong to this gateway."))
                return

            # Make sure we are setting up a Windows machine.
            # Linux and Mac do not use passwords in services and cron jobs; no need to link.
            os_field = next((x for x in machine_record.fields if x.label == "operatingSystem"), None)
            if os_field is None:
                print(self._f("Cannot find the operating system field in this record."))
                return
            os_type = None
            if len(os_field.value) > 0:
                os_type = os_field.value[0]
            if os_type is None:
                print(self._f("The operating system field of the machine record is blank."))
                return
            if os_type != "windows":
                print(self._f("The operating system is not Windows. "
                              "PAM can only rotate the services and scheduled task password on Windows."))
                return

            data_edge = machine_vertex.get_data()
            if data_edge is None:
                machine_data = MachineData()
            else:
                machine_data = data_edge.content_as_object(MachineData)

            if machine_data.rotation_settings.no_update_services:
                machine_data.rotation_settings.no_update_services = False
                machine_vertex.add_data(machine_data.model_dump_json(), needs_encryption=False, path="meta")
                record_link.save()

            print(
                self._gr(
                    "Success: Machine will allow services password to be changed during rotation."
                )
            )
        else:
            # Check to see if the record exists.
            user_record = vault.KeeperRecord.load(params, user_uid)  # type: Optional[TypedRecord]
            if user_record is None:
                print(self._f("The user record does not exists."))
                return

            # Make sure this user is a PAM User.
            if user_record.record_type != PAM_USER:
                print(self._f("The user record is not a PAM User."))
                return

            # Get the user service vertex.
            # If it doesn't exist, create one.
            user_vertex = record_link.dag.get_vertex(user_record.record_uid)
            if user_vertex is None:
                if user_vertex is None:
                    print(self._f("The machine record does not exists in the graph."))
                    return

            data_edge = user_vertex.get_data()
            if data_edge is None:
                user_data = UserData()
            else:
                user_data = data_edge.content_as_object(UserData)
            if user_data.rotation_settings.no_update_services:
                user_data.rotation_settings.no_update_services = False
                user_vertex.add_data(user_data.model_dump_json(), needs_encryption=False, path="meta")
                record_link.save()

            print(
                self._gr(
                    "Success: When rotating the user's password, service passwords will be changed, if applicable."
                )
            )
