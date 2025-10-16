from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from ... import vault
from ...discovery_common.user_service import UserService
from ...discovery_common.record_link import RecordLink
from ...discovery_common.constants import PAM_USER, PAM_MACHINE
from ...discovery_common.types import ServiceAcl
from ...keeper_dag.types import RefType, EdgeType
from ... import __version__
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionServiceAddCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-service-add')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID')

    parser.add_argument('--machine-uid', '-m', required=True, dest='machine_uid', action='store',
                        help='The UID of the Windows Machine record')
    parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                        help='The UID of the User record')
    parser.add_argument('--type', '-t', required=True, choices=['service', 'task', 'iis'], dest='type',
                        action='store', help='Relationship to add [service, task, iis]')

    def get_parser(self):
        return PAMActionServiceAddCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        gateway = kwargs.get("gateway")
        machine_uid = kwargs.get("machine_uid")
        user_uid = kwargs.get("user_uid")
        rel_type = kwargs.get("type")

        print("")

        gateway_context = GatewayContext.from_gateway(params, gateway)
        if gateway_context is None:
            print(f"{bcolors.FAIL}Could not find the gateway configuration for {gateway}.")
            return

        if gateway_context is None:
            print(f"  {self._f('Cannot get gateway information. Gateway may not be up.')}")
            return

        user_service = UserService(record=gateway_context.configuration, params=params, fail_on_corrupt=False,
                                   agent=f"Cmdr/{__version__}")
        record_link = RecordLink(record=gateway_context.configuration, params=params, fail_on_corrupt=False,
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
        machine_vertex = user_service.get_record_link(machine_record.record_uid)
        if machine_vertex is None:
            machine_vertex = user_service.dag.add_vertex(
                uid=machine_record.record_uid,
                name=machine_record.title,
                vertex_type=RefType.PAM_MACHINE)

        # Get the user service vertex.
        # If it doesn't exist, create one.
        user_vertex = user_service.get_record_link(user_record.record_uid)
        if user_vertex is None:
            user_vertex = user_service.dag.add_vertex(
                uid=user_record.record_uid,
                name=user_record.title,
                vertex_type=RefType.PAM_USER)

        # Get the existing service ACL and set the proper attribute.
        acl = user_service.get_acl(machine_vertex.uid, user_vertex.uid)
        if acl is None:
            acl = ServiceAcl()
        if rel_type == "service":
            acl.is_service = True
        elif rel_type == "task":
            acl.is_task = True
        else:
            acl.is_iis_pool = True

        # Make sure the machine has a LINK connection to the configuration.
        if not user_service.dag.get_root.has(machine_vertex):
            user_service.belongs_to(gateway_context.configuration_uid, machine_vertex.uid)

        # Add our new ACL edge between the machine and the yser.
        user_service.belongs_to(machine_vertex.uid, user_vertex.uid, acl=acl)

        user_service.save()

        if rel_type == "service":
            print(
                self._gr(
                    f"Success: Services running on this machine, using this user, will be updated and restarted after "
                    "password rotation."
                )
            )
        elif rel_type == "task":
            print(
                self._gr(
                    f"Success: Scheduled tasks running on this machine, using this user, will be updated after "
                    "password rotation."
                )
            )
        else:
            print(
                self._gr(
                    f"Success: IIS pools running on this machine, using this user, will be updated after "
                    "password rotation."
                )
            )
