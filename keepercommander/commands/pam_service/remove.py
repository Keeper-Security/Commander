from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext, MultiConfigurationException, multi_conf_msg
from ... import vault
from ...discovery_common.constants import PAM_USER, PAM_MACHINE
from ...discovery_common.user_service import UserService
from ...discovery_common.record_link import RecordLink
from ...display import bcolors
from ... import __version__
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionServiceRemoveCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action service remove')

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
        return PAMActionServiceRemoveCommand.parser

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

        machine_vertex = record_link.dag.get_vertex(machine_record.record_uid)
        if machine_vertex is None:
            print(self._f(f"The machine does not exist in the mapping."))
            return

        user_vertex = record_link.dag.get_vertex(user_record.record_uid)
        if user_vertex is None:
            print(self._f(f"The user does not exist in the mapping."))
            return

        acl = user_service.get_acl(machine_vertex.uid, user_vertex.uid)
        if acl is None or acl.rotation_settings is None:
            print(f"{bcolors.WARNING}The user did not control any services, "
                  f"scheduled tasks, or IIS pools on the machine.{bcolors.ENDC}")
            return

        if acl.rotation_settings.controls_services:
            acl.rotation_settings.controls_services = False

            user_service.set_acl(resource_uid=machine_vertex.uid,
                                 user_uid=user_vertex.uid,
                                 acl=acl)
            record_link.save()

        print(
            self._gr(
                "Success: When the user's password is rotated, service passwords will NOT be changed on this machine."
            )
        )
