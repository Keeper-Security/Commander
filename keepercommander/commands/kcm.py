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
import argparse
import base64
import hashlib
import hmac
import json
import logging
import webbrowser
from time import time
from urllib.parse import urlencode

from .base import Command, raise_parse_exception, suppress_exit
from keepercommander import api
from keepercommander.crypto import encrypt_aes_v1
from keepercommander.subfolder import try_resolve_path

import requests


GLYPTODON_AUTH_DELTA = 600000  # 10 minutes in milliseconds
DEFAULT_PROTOCOL_PORTS = {
    'ssh': '22',
    'rdp': '3389'
}


def register_commands(commands):
    commands['kcm'] = KCMCommand()


def register_command_info(aliases, command_info):
    command_info[kcm_parser.prog] = kcm_parser.description


kcm_parser = argparse.ArgumentParser(prog='kcm', description='Create Keeper Connection Manager (KCM) connections')
kcm_parser.add_argument(
    '-j', '--json-auth', dest='json_auth', action='store', help='Record with key for Encrypted JSON Authentication'
)
kcm_parser.add_argument(
    '-t', '--test', dest='test', action='store_true', help='Test KCM connection'
)
kcm_parser.add_argument(
    'connection-records', type=str, action='store', nargs="*", help='Records with KCM connection credentials'
)
kcm_parser.error = raise_parse_exception
kcm_parser.exit = suppress_exit


def find_folder_record(params, base_folder, record_name, v3_enabled):
    folder_uid = base_folder.uid
    if folder_uid in params.subfolder_record_cache:
        for uid in params.subfolder_record_cache[folder_uid]:
            rv = params.record_cache[uid].get('version') if params.record_cache and uid in params.record_cache else None
            if rv == 4 or rv == 5:
                continue  # skip fileRef and application records - they use file-report command
            if not v3_enabled and rv in (3, 4):
                continue  # skip record types when not enabled
            r = api.get_record(params, uid)
            if r.title.lower() == record_name.lower():
                return r

    return None


def get_folder(params, folder_path):
    folder = params.folder_cache.get(params.current_folder, params.root_folder)
    rs = try_resolve_path(params, folder_path)
    if rs is not None:
        folder, name = rs
        if len(name) > 0:
            return None
    return folder


def get_record(params, record_path):
    folder = None
    name = None
    if record_path:
        rs = try_resolve_path(params, record_path)
        if rs is not None:
            folder, name = rs

    if folder is None or name is None:
        return None

    if name in params.record_cache:
        return api.get_record(params, name)
    else:
        return find_folder_record(params, folder, name, v3_enabled=True)


def get_connections(params, connection_records):
    connections = {}
    for connection_path in connection_records:
        conn = get_record(params, connection_path)
        connection = {'parameters': {'username': conn.login, 'password': conn.password}}
        for f in conn.custom_fields:
            if ':' in f['name']:
                ftype, ftitle = f['name'].split(':', 1)
                if ftype == 'host':
                    connection['parameters']['hostname'] = f['value'].get('hostName')
                    connection['parameters']['port'] = f['value'].get('port')
                elif ftype == 'text' and ftitle.lower() == 'protocol':
                    connection['protocol'] = f['value']

        if not connection.get('protocol'):
            logging.warning(f'Custom field "Protocol" is missing for record {conn.title}')
            return None
        if not connection['parameters'].get('hostname'):
            logging.warning(f'Hostname is missing for record {conn.title}')
            return None
        if not connection['parameters'].get('port'):
            default_port = DEFAULT_PROTOCOL_PORTS.get(connection['protocol'].lower())
            if default_port:
                connection['parameters']['port'] = default_port
            else:
                logging.warning(f'Port is missing for record {conn.title}')
                return None

        connections[conn.title] = connection

    if len(connection_records) == 0:
        logging.warning('Please specify a KCM connection record')
        return None

    return connections


def create_json_auth(glyptodon_secret, auth_dict):
    json_auth = (json.dumps(auth_dict) + '\n').encode()
    unencrypted_result = hmac.new(glyptodon_secret, json_auth, hashlib.sha256).digest() + json_auth
    encrypted_result = encrypt_aes_v1(unencrypted_result, glyptodon_secret, iv=bytes.fromhex('0' * 32))[16:]
    return base64.b64encode(encrypted_result)


def test_kcm_connection(data_dict, glyptodon_url):
    auth_response = json.loads(requests.post(f'{glyptodon_url}/api/tokens', data=data_dict).text)
    logging.info(f'Successful KCM connection for user "{auth_response["username"]}"')


class KCMCommand(Command):
    def get_parser(self):
        return kcm_parser

    def execute(self, params, **kwargs):
        has_record_type_setting = params.settings and isinstance(params.settings.get('record_types_enabled'), bool)
        v3_enabled = params.settings.get('record_types_enabled') if has_record_type_setting else False
        if not v3_enabled:
            logging.warning(f"Record types are needed for KCM connections")
            return

        json_auth_path = kwargs.get('json_auth')
        if json_auth_path:
            json_auth = get_record(params, json_auth_path)
            if json_auth:
                logging.info(f'Found JSON auth record {json_auth.title}')
                glyptodon_user = json_auth.login
                glyptodon_url = json_auth.login_url
                glyptodon_secret = bytes.fromhex(json_auth.password)
            else:
                logging.warning(f"Can't find JSON auth record {json_auth_path}")
                return
        else:
            logging.warning('Authentication is required. Provide JSON auth record with --json-auth option')
            return

        connection_records = kwargs.get('connection-records')
        connections = get_connections(params, connection_records)
        if connections is None:
            return

        auth_dict = {
            'username': glyptodon_user,
            'expires': str(int(time()) * 1000 + GLYPTODON_AUTH_DELTA),
            'connections': connections
        }
        data_dict = {'data': create_json_auth(glyptodon_secret, auth_dict)}

        if kwargs.get('test'):
            test_kcm_connection(data_dict, glyptodon_url)
            return

        webbrowser.open_new(f'{glyptodon_url}?{urlencode(data_dict)}')
