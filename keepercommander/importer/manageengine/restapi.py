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
import json
import logging
import sys
from collections import namedtuple
from urllib.parse import urlunsplit

import requests
import urllib3


DEFAULT_FILE_REASON = {'operation': {'Details': {'REASON': 'Import into Keeper'}}}
DEFAULT_BASE_PATH = '/restapi/json/v1'
PKI_BASE_PATH = '/api/pki/restapi'
URL_PATHS = dict(
    all_resources='resources',
    resource_accounts='resources/{resource_id}/accounts',
    resource_account='resources/{resource_id}/accounts/{account_id}',
    resource_account_password='resources/{resource_id}/accounts/{account_id}/password',
    resource_account_file='resources/{resource_id}/accounts/{account_id}/downloadfile',
)
API_DOC_NUMBERS = {
    1: 'all_resources',
    2: 'resource_accounts',
    3: 'resource_account',
    4: 'resource_account_password',
    20: 'resource_account_file',
}


if sys.version_info < (3, 7):
    Url = namedtuple('Url', ['scheme', 'netloc', 'path', 'query', 'fragment'])
    Url.__new__.__defaults__ = ('', '', '')
else:
    Url = namedtuple('Url', ['scheme', 'netloc', 'path', 'query', 'fragment'], defaults=('', '', ''))
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RestAPI:
    def __init__(self, host, port, token, scheme='https'):
        self.base_url = Url(scheme=scheme, netloc=f'{host}:{port}')
        self.token = token

    def get_request_kwargs(self, path_key=None, api_num=1, ids={}, base_path=DEFAULT_BASE_PATH):
        if path_key is None:
            path_key = API_DOC_NUMBERS[api_num]
        try:
            path = URL_PATHS[path_key].format(**ids)
        except KeyError:
            logging.warning(f'Incorrect parameters for import API')
            return None

        url = self.base_url._replace(path=f'{base_path}/{path}')
        url_text = urlunsplit(url)

        if self.token:
            headers = {'AUTHTOKEN': self.token}
            return dict(url=url_text, headers=headers, verify=False)
        else:
            logging.warning(f"Invalid token for connection to {urlunsplit(self.base_url)}")
            return None

    def get_rest_data(self, *args, **kwargs):
        request_kwargs = self.get_request_kwargs(*args, **kwargs)
        if request_kwargs is None:
            return None

        try:
            response = requests.get(**request_kwargs)
        except Exception as e:
            logging.warning(f"Can't connect to ManageEngine server {urlunsplit(self.base_url)}")
            return None

        if response.text:
            try:
                raw_data = json.loads(response.text)
            except json.decoder.JSONDecodeError:
                logging.warning(f"Can't parse import JSON with status code {response.status_code}:\n{response.text}")
                return None
        else:
            logging.warning(f"Failed to get response from ManageEngine connection.")
            return None

        operation = raw_data.get('operation', {})
        result = operation.get('result')
        if result and result.get('status') == 'Success':
            return operation.get('Details')
        else:
            message = f": {result['message']}" if 'message' in result else '.'
            logging.warning(f'Connection to ManageEngine server failed{message}')
            return None

    def resources(self):
        return self.get_rest_data('all_resources')

    def resource_info(self, resource):
        return self.get_rest_data('resource_accounts', ids={'resource_id': resource['RESOURCE ID']})

    def resource_accounts(self, resource):
        resource_id = resource.get('RESOURCE ID')
        if resource_id:
            if 'ACCOUNT LIST' in resource:
                account_list = resource['ACCOUNT LIST']
            else:
                account_list = self.resource_info(resource_id)['ACCOUNT LIST']
        else:
            logging.warning('Invalid resource missing resource id.')
            account_list = []

        for account in account_list:
            # needed for self.account_info to have the needed ID for rest API call
            account['RESOURCE ID'] = resource_id
            yield account

    @staticmethod
    def get_account_ids(account):
        return {k.lower().replace(' ', '_'): v for k, v in account.items() if k.endswith(' ID')}

    def account_info(self, account):
        ids = self.get_account_ids(account)
        return self.get_rest_data('resource_account', ids=ids)

    def get_password(self, account):
        ids = self.get_account_ids(account)
        response = self.get_rest_data('resource_account_password', ids=ids)
        if isinstance(response, dict):
            return response.get('PASSWORD')
        else:
            account_name = account.get('ACCOUNT NAME')
            logging.warning(f"Couldn't get password for account '{account_name}'")
            return None

    def get_file_attachment_kwargs(self, account):
        ids = self.get_account_ids(account)
        return self.get_request_kwargs('resource_account_file', ids=ids)
