#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import getpass
import logging
from urllib.parse import urlsplit

from ..importer import BaseImporter, Folder, Record, RecordField
from .attachment import ManageEngineAttachment
from .restapi import RestAPI


RECORD_TO_IMPORT_RESOURCE_FIELD = {
    'title': 'RESOURCE NAME',
    'login_url': 'RESOURCE URL',
    'notes': 'RESOURCE DESCRIPTION'
}
RECORD_TO_IMPORT_ACCOUNT_FIELD = {
    'title': 'ACCOUNT NAME',
    'login': 'ACCOUNT NAME',
    'login_url': 'RESOURCE URL',
    'notes': 'DESCRIPTION'
}


def get_new_record(resource_info, field_map, account_info=None):
    record = Record()
    record.type = 'file' if resource_info.get('RESOURCE TYPE') == 'File Store' else 'serverCredentials'
    if account_info:
        folder = Folder()
        folder_suffix = 'files' if resource_info.get('RESOURCE TYPE') == 'File Store' else 'accounts'
        folder.path = f"{resource_info['RESOURCE NAME']} {folder_suffix}"
        record.folders = [folder]

    for record_field, import_field in field_map.items():
        if account_info:
            if record_field == 'login' and resource_info.get('RESOURCE TYPE') == 'File Store':
                # File in File Store doesn't have a login
                continue
            else:
                field_value = account_info.get(import_field, resource_info.get(import_field))
        else:
            field_value = resource_info.get(import_field)
        if field_value and field_value != 'N/A':
            setattr(record, record_field, field_value)

    host = resource_info.get('DNS NAME')
    if host and host != 'N/A':
        host_field = RecordField(type='host', value={'hostName': host})
        record.fields.append(host_field)
    return record


class ManageEngineImporter(BaseImporter):
    def __init__(self):
        super(ManageEngineImporter, self).__init__()

    def do_import(self, name, **kwargs):
        url = urlsplit(name)
        token = getpass.getpass(prompt='Token: ')
        rest_api = RestAPI(url.hostname, url.port, token, url.scheme)

        resources = rest_api.resources() or []
        for resource in resources:
            resource_info = rest_api.resource_info(resource)
            if resource_info is None:
                logging.warning(f"Couldn't import {resource}")
                continue
            resource_record = get_new_record(resource_info, RECORD_TO_IMPORT_RESOURCE_FIELD)
            resource_type = resource_info.get('RESOURCE TYPE')
            if resource_type:
                resource_type_field = RecordField(type='text', label='Resource type', value=resource_type)
                resource_record.fields.append(resource_type_field)
            yield resource_record

            accounts = rest_api.resource_accounts(resource_info) or []
            for account in accounts:
                account_info = rest_api.account_info(account)
                if account_info is None:
                    logging.warning(f"Couldn't import {account}")
                    continue
                account_info.update(account)
                account_record = get_new_record(resource_info, RECORD_TO_IMPORT_ACCOUNT_FIELD, account_info)
                if resource_info['RESOURCE TYPE'] == 'File Store':
                    file_attachment_kwargs = rest_api.get_file_attachment_kwargs(account)
                    attachment = ManageEngineAttachment(account_info['PASSWORD STATUS'], file_attachment_kwargs)
                    account_record.attachments = [attachment]
                else:
                    account_record.password = rest_api.get_password(account)
                yield account_record
