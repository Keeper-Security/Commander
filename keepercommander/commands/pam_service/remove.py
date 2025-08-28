from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ... import vault
from ...discovery_common.constants import PAM_USER, PAM_MACHINE
from ...discovery_common.user_service import UserService
from ...display import bcolors
from ... import __version__
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionServiceRemoveCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-service-remove')

    # The record to base everything on.
    parser.add_argument('--gateway', '-g', required=True, dest='gateway', action='store',
                        help='Gateway name or UID')

    parser.add_argument('--machine-uid', '-m', required=True, dest='machine_uid', action='store',
                        help='The UID of the Windows Machine record')
    parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                        help='The UID of the User record')
    parser.add_argument('--type', '-t', required=True, choices=['service', 'task', 'iis'], dest='type',
                        action='store', help='Relationship to remove [service, task, iis]')

    def get_parser(self):
        return PAMActionServiceRemoveCommand.parser

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

        machine_record = vault.KeeperRecord.load(params, machine_uid)  # type: Optional[TypedRecord]
        if machine_record is None:
            print(self._f("The machine record does not exists."))
            return

        if machine_record.record_type != PAM_MACHINE:
            print(self._f("The machine record is not a PAM Machine."))
            return

        user_record = vault.KeeperRecord.load(params, user_uid)  # type: Optional[TypedRecord]
        if user_record is None:
            print(self._f("The user record does not exists."))
            return

        if user_record.record_type != PAM_USER:
            print(self._f("The user record is not a PAM User."))
            return

        machine_vertex = user_service.get_record_link(machine_record.record_uid)
        if machine_vertex is None:
            print(self._f(f"The machine does not exist in the mapping."))
            return

        user_vertex = user_service.get_record_link(user_record.record_uid)
        if user_vertex is None:
            print(self._f(f"The user does not exist in the mapping."))
            return

        acl = user_service.get_acl(machine_vertex.uid, user_vertex.uid)
        if acl is None:
            print(f"{bcolors.WARNING}The user did not control any services, "
                  f"scheduled tasks, or IIS pools on the machine.{bcolors.ENDC}")
            return

        if rel_type == "service":
            acl.is_service = False
        elif rel_type == "task":
            acl.is_task = False
        else:
            acl.is_iis_pool = False

        if user_service.dag.get_root.has(machine_vertex) is False:
            user_service.belongs_to(gateway_context.configuration_uid, machine_vertex.uid)

        user_service.belongs_to(machine_vertex.uid, user_vertex.uid, acl=acl)
        user_service.save()

        if rel_type == "service":
            print(
                self._gr(
                    "Success: Services running on this machine will no longer have their password changed when this "
                    "user's password is rotated."
                )
            )
        elif rel_type == "task":
            print(
                self._gr(
                    "Success: Scheduled tasks running on this machine will no longer have their password changed "
                    "when this user's password is rotated."
                )
            )
        else:
            print(
                self._gr(
                    "Success: IIP pools running on this machine will no longer have their password changed "
                    "when this user's password is rotated."
                )
            )
