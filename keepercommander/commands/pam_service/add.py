from __future__ import annotations
import argparse
import logging
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ...display import bcolors
from ... import vault
from ...discovery_common.user_service import UserService
from ...discovery_common.record_link import RecordLink
from ...discovery_common.constants import PAM_USER, PAM_MACHINE
from ...discovery_common.types import UserAcl
from ...keeper_dag.types import RefType, EdgeType
from ... import __version__
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionServiceAddCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action service add')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID, if gateway has multiple.')

    parser.add_argument('--machine-uid', '-m', required=True, dest='machine_uid', action='store',
                        help='The UID of the Windows Machine record')
    parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                        help='The UID of the User record')

    def get_parser(self):
        return PAMActionServiceAddCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        machine_uid = kwargs.get("machine_uid")
        user_uid = kwargs.get("user_uid")

        print("")

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
        user_service = UserService(record=gateway_context.configuration,
                                   record_linking=record_link,
                                   params=params,
                                   fail_on_corrupt=False,
                                   agent=f"Cmdr/{__version__}")

        ###############

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
        machine_rl = record_link.get_record_link(machine_record.record_uid)
        if machine_rl is None:
            print(self._f("The machine record does not exists in the graph."))
            return

        # Edges from provider and machine might be wrong.
        # Should be a LINK edge, could be an ACL edge.
        if (machine_rl.get_edge(record_link.dag.get_root, edge_type=EdgeType.LINK) is None and
                machine_rl.get_edge(record_link.dag.get_root, edge_type=EdgeType.ACL) is None):
            print(self._f("The machine record does not belong to this gateway."))
            return

        ###############

        # Check to see if the record exists.
        user_record = vault.KeeperRecord.load(params, user_uid)  # type: Optional[TypedRecord]
        if user_record is None:
            print(self._f("The user record does not exists."))
            return

        # Make sure this user is a PAM User.
        if user_record.record_type != PAM_USER:
            print(self._f("The user record is not a PAM User."))
            return

        record_rotation = params.record_rotation_cache.get(user_record.record_uid)
        if record_rotation is not None:
            controller_uid = record_rotation.get("configuration_uid")
            if controller_uid is None or controller_uid != gateway_context.configuration_uid:
                print(self._f("The user record does not belong to this gateway. Cannot use this user."))
                return
        else:
            print(self._f("The user record does not have any rotation settings."))
            return

        ########

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

        # Get the machine service vertex.
        # If it doesn't exist, create one.
        machine_vertex = record_link.dag.get_vertex(machine_record.record_uid)
        if machine_vertex is None:
            machine_vertex = record_link.dag.add_vertex(
                uid=machine_record.record_uid,
                name=machine_record.title,
                vertex_type=RefType.PAM_MACHINE)

        # Get the user service vertex.
        # If it doesn't exist, create one.
        user_vertex = record_link.dag.get_vertex(user_record.record_uid)
        if user_vertex is None:
            user_vertex = record_link.dag.add_vertex(
                uid=user_record.record_uid,
                name=user_record.title,
                vertex_type=RefType.PAM_USER)

        # Get the existing service ACL and set the proper attribute.
        # If one does not exist, create a default ACL
        acl = user_service.get_acl(machine_vertex.uid, user_vertex.uid)
        if acl is None:
            acl = UserAcl.default()

        if not acl.rotation_settings.controls_services:
            acl.rotation_settings.controls_services = True

            # Make sure the machine has a LINK connection to the configuration.
            if not record_link.dag.get_root.has(machine_vertex):
                machine_vertex.belongs_to_root(edge_type=EdgeType.LINK)

            # Add our new ACL edge between the machine and the yser.
            user_service.set_acl(resource_uid=machine_vertex.uid,
                                 user_uid=user_vertex.uid,
                                 acl=acl)

            record_link.save()
        else:
            logging.debug("user already set to control services on this machine.")

        print(
            self._gr(
                "Success: When the user's password is rotated, service passwords, "
                "on this machine, will also be changed."
            )
        )
