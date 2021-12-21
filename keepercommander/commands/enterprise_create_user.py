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

import argparse
import json
import logging
import re

from .. import api, crypto
from .base import RecordMixin, raise_parse_exception, suppress_exit
from .enterprise import EnterpriseCommand
from ..loginv3 import LoginV3API
from ..constants import EMAIL_PATTERN
from .. import utils
from ..record import Record
from ..params import KeeperParams
from ..proto import enterprise_pb2 as enterprise_proto


def register_commands(commands):
    commands['create-user'] = CreateEnterpriseUserCommand()


def register_command_info(_, command_info):
    command_info['create-user'] = 'Create Enterprise User'


register_parser = argparse.ArgumentParser(prog='create-user', description='Creates enterprise user')
register_parser.add_argument('--name', dest='name', action='store', help='user name')
register_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
register_parser.add_argument('--record', dest='record', action='store', help='record title or record UID to store the passwords')
register_parser.add_argument('email', action='append', help='email')
register_parser.error = raise_parse_exception
register_parser.exit = suppress_exit


class CreateEnterpriseUserCommand(EnterpriseCommand, RecordMixin):
    def get_parser(self):
        return register_parser

    def execute(self, params, **kwargs):
        node_name = kwargs.get('node')
        nodes = list(self.resolve_nodes(params, node_name))
        if len(nodes) == 0:
            logging.warning('Node \"%s\" is not found', node_name)
            return
        if len(nodes) > 1:
            logging.warning('More than one nodes \"%s\" are found', node_name)
            return

        node_id = nodes[0]['node_id']
        emails = kwargs.get('email', [])
        email_pattern = re.compile(EMAIL_PATTERN)

        added_accounts = {}
        for email in emails:
            match = email_pattern.match(email)
            if not match:
                logging.warning('"%s" appears not a valid email address. Skipping.', email)
                continue

            verification_code = ''
            try:
                data = {'displayname': email}
                rq = {
                    'command': 'enterprise_user_add',
                    'enterprise_user_id': EnterpriseCommand.get_enterprise_id(params),
                    'enterprise_user_username': email,
                    'encrypted_data': api.encrypt_aes(json.dumps(data).encode('utf-8'), params.enterprise['unencrypted_tree_key']),
                    'node_id': node_id,
                    'suppress_email_invite': True
                }

                rs = api.communicate(params, rq)
                verification_code = rs['verification_code']
            except Exception as e:
                logging.error(e)
            if not verification_code:
                logging.warning('Failed to add account "%s" to enterprise. Skipping.', email)
                continue

            password = utils.generate_uid()
            try:
                LoginV3API.create_user(params, email, password, verification_code)
                added_accounts[email] = password
                logging.info(f"User \"{email}\" successfully provisioned.\n" +
                             "The user must reset their Master Password upon first login.")
            except Exception as e:
                logging.error(e)
                logging.warning('Failed to create account "%s". Skipping.', email)

        if len(added_accounts) == 0:
            logging.info('No users created.')
            return

        record_name = kwargs.get('record') or 'Enterprise User Passwords'
        record_uid = next(self.resolve_records(params, record_name), None)
        if record_uid:
            record = api.get_record(params, record_uid)
        else:
            record = Record()
            record.title = record_name
        for name, value in added_accounts.items():
            record.set_field(name, value)

        try:
            if record.record_uid:
                api.update_record(params, record, silent=True)
            else:
                api.add_record(params, record, silent=True)
        except Exception as e:
            logging.info('Record store error: %s', e)

        param1 = KeeperParams()
        param1.server = params.server
        param1.device_token = params.device_token or params.config.get('device_token', '')
        param1.device_private_key = params.device_private_key or params.config.get('private_key', '')
        for email in added_accounts:
            param1.user = email
            param1.password = added_accounts[email]
            param1.data_key = b''
            try:
                api.login(param1)
                rq = enterprise_proto.EnterpriseUserDataKey()
                rq.userEncryptedDataKey = crypto.encrypt_ec(param1.data_key, params.enterprise_ec_key)
                api.communicate_rest(param1, rq, 'enterprise/set_enterprise_user_data_key')
                logging.info(f'{email} is logged out')
            except Exception as e:
                logging.warning(e)

            try:
                rq = {
                    'command': 'set_master_password_expire',
                    'email': email
                }
                api.communicate(params, rq)
            except Exception as e:
                pass

        api.query_enterprise(params)
