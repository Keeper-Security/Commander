from __future__ import annotations
import argparse
from ..discover import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ... import vault
from . import get_plugins_map
from ...discovery_common.record_link import RecordLink
from ...discovery_common.constants import PAM_USER, PAM_MACHINE, PAM_DATABASE, PAM_DIRECTORY
from ...discovery_common.types import UserAclRotationSettings
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ...vault import TypedRecord
    from ...params import KeeperParams


class PAMActionSaasAddCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam action saas add')

    parser.add_argument('--user-uid', '-u', required=True, dest='user_uid', action='store',
                        help='The UID of the User record')
    parser.add_argument('--config-record-uid', '-c', required=True, dest='config_record_uid',
                        action='store', help='The UID of the record that has SaaS configuration')
    parser.add_argument('--resource-uid', '-r', required=False, dest='resource_uid', action='store',
                        help='The UID of the Resource record, if needed.')

    def get_parser(self):
        return PAMActionSaasAddCommand.parser

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

        plugins = get_plugins_map(params, gateway_context)
        if plugins is None:
            return

        # Check to see if the config record exists.
        config_record = vault.KeeperRecord.load(params, config_record_uid)  # type: Optional[TypedRecord]
        if config_record is None:
            print(self._f("The SaaS configuration record does not exists."))
            return

        # Make sure this config is a Login record.

        if config_record.record_type != "login":
            print(self._f("The SaaS configuration record is not a Login record."))
            return

        plugin_name_field = next((x for x in config_record.custom if x.label == "SaaS Type"), None)
        if plugin_name_field is None:
            print(self._f("The SaaS configuration record is missing the custom field label 'SaaS Type'"))
            return

        plugin_name = None
        if plugin_name_field.value is not None and len(plugin_name_field.value) > 0:
            plugin_name = plugin_name_field.value[0]

        if plugin_name is None:
            print(self._f("The SaaS configuration record's custom field label 'SaaS Type' does not have a value."))
            return

        if plugin_name not in plugins:
            print(self._f("The SaaS configuration record's custom field label 'SaaS Type' is not supported by the "
                          "gateway or the value is not correct."))
            return

        plugin = plugins[plugin_name]

        # Make sure the SaaS configuration record has correct custom fields.
        missing_fields = []
        for field in plugin.fields:
            if field.required is True and field.default_value is None:
                found = next((x for x in config_record.custom if x.label == field.label), None)
                if not found:
                    missing_fields.append(field.label.strip())

        if len(missing_fields) > 0:
            print(self._f("The SaaS configuration record is missing the following required custom fields: "
                          f'{", ".join(missing_fields)}'))
            return

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
        # However, if this is an IAM User, don't set the NOOP
        if acl.is_iam_user is False:
            acl.rotation_settings.noop = resource_uid is None

        # PyCharm didn't like appending directly, so do this stupid thing.
        record_uid_list = acl.rotation_settings.saas_record_uid_list

        # Make sure we are not re-adding the same SaaS config.
        if config_record_uid in record_uid_list:
            print(self._f("The SaaS configuration record is already being used for this user."))
            return

        record_uid_list.append(config_record_uid)
        acl.rotation_settings.saas_record_uid_list = record_uid_list

        record_link.belongs_to(user_uid, parent_uid, acl=acl)
        record_link.save()

        print(self._gr(f"Added {plugin_name} rotation to the user record."))
        print("")
