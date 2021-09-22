#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
RAW_FIELDS = ('created', 'audit_event_type', 'username', 'ip_address', 'keeper_version', 'geo_location')
MISC_FIELDS = (
    'to_username', 'from_username', 'record_uid', 'shared_folder_uid',
    'node', 'role_id', 'team_uid', 'channel', 'status'
)


class LookupType:
    """Helper class for looking up fields given the uid"""
    uid: str
    fields: tuple
    attrs: tuple
    method: str

    def __init__(self, uid: str, fields: tuple, attrs: tuple, method: str):
        self.uid = uid
        self.fields = fields
        self.attrs = attrs
        self.method = method

    @staticmethod
    def lookup_type_from_field_name(field_name: str):
        uid_name = fields_to_uid_name[field_name]
        return lookup_types[uid_name]

    def init_fields(self, init_value: str) -> dict:
        return dict.fromkeys(self.fields, init_value)

    def field_attrs(self) -> zip:
        return zip(self.fields, self.attrs)


lookup_types = {
    'record_uid': LookupType(
        uid='record_uid',
        fields=('record_title', 'record_url'),
        attrs=('title', 'login_url'),
        method='resolve_record_lookup'
    ),
    'shared_folder_uid': LookupType(
        uid='shared_folder_uid',
        fields=('shared_folder_title',),
        attrs=('name',),
        method='resolve_shared_folder_lookup'
    ),
    'team_uid': LookupType(
        uid='team_uid', fields=('team_title',), attrs=('name',), method='resolve_team_lookup'
    ),
    'role_id': LookupType(
        uid='role_id', fields=('role_title',), attrs=('displayname',), method='resolve_role_lookup'
    ),
    'node': LookupType(
        uid='node', fields=('node_title',), attrs=('displayname',), method='resolve_node_lookup'
    ),
}

fields_to_uid_name = {}

for k, v in lookup_types.items():
    for f in v.fields:
        fields_to_uid_name[f] = k
