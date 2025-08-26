from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ...display import bcolors
from ... import vault
from ...discovery_common.record_link import RecordLink
from ...discovery_common.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from ...discovery_common.types import UserAclRotationSettings
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionSaasRemoveCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action saas remove')

    parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                        help='The UID of the User record')
    parser.add_argument('--config-record-uid', '-c', required=True, dest='config_record_uid',
                        action='store', help='The UID of the record that has SaaS configuration')
    parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                        help='The UID of the Resource record, if needed.')

    def get_parser(self):
        return PAMActionSaasRemoveCommand.parser

    def execute(self, params: KeeperParams, **kwargs):

        user_uid = kwargs.get("user_uid")  # type: str
        resource_uid = kwargs.get("resource_uid")  # type: str
        config_record_uid = kwargs.get("config_record_uid")   # type: str

        print("")

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
            configuration_uid = record_rotation.get("configuration_uid")
        else:
            print(self._f("The user record does not have any rotation settings."))
            return

        if configuration_uid is None:
            print(self._f("The user record does not have the configuration record set in the rotation settings."))
            return

        gateway_context = GatewayContext.from_configuration_uid(params, configuration_uid)

        if gateway_context is None:
            print(self._f("The user record does not have the set gateway"))
            return

        # Don't check config record
        # Just accept the record UID; the record might not exist anymore.

        parent_uid = gateway_context.configuration_uid

        # Not sure if SaaS type rotation should be limited to NOOP rotation.
        # Allow a resource record to be used.
        if resource_uid is not None:
            # Check to see if the record exists.
            resource_record = vault.KeeperRecord.load(params, resource_uid)  # type: Optional[TypedRecord]
            if resource_record is None:
                print(self._f("The resource record does not exists."))
                return

            # Make sure this user is a PAM User.
            if user_record.record_type in [PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY]:
                print(self._f("The resource record does not have the correct record type."))
                return

            parent_uid = resource_uid

        record_link = RecordLink(record=gateway_context.configuration, params=params, fail_on_corrupt=False)
        acl = record_link.get_acl(user_uid, parent_uid)
        if acl is None:
            if resource_uid is not None:
                print(self._f("There is no relationship between the user and the resource record."))
            else:
                print(self._f("There is no relationship between the user and the configuration record."))
            return

        if acl.rotation_settings is None:
            acl.rotation_settings = UserAclRotationSettings()

        if resource_uid is not None and acl.rotation_settings.noop is True:
            print(self._f("The rotation is flagged as No Operation, however you passed in a resource record. "
                          "This combination is not allowed."))
            return

        # If there is a resource record, it not NOOP.
        # If there is NO resource record, it is NOOP.
        acl.rotation_settings.noop = resource_uid is None

        # PyCharm didn't like appending directly, so do this stupid thing.
        record_uid_list = acl.rotation_settings.saas_record_uid_list

        # Check if the SaaS config is being used by this user.
        if config_record_uid not in record_uid_list:
            print(f"{bcolors.WARNING}The SaaS configuration record is not being used by "
                  f"this user record.{bcolors.ENDC}")
            return

        record_uid_list.remove(config_record_uid)
        acl.rotation_settings.saas_record_uid_list = record_uid_list

        record_link.belongs_to(user_uid, parent_uid, acl)
        record_link.save()

        print(self._gr("Remove the SaaS service rotation from the user record."))
