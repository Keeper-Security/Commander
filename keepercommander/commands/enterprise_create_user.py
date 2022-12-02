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
from typing import Optional
from urllib.parse import urlunparse

from .base import RecordMixin, raise_parse_exception, suppress_exit, try_resolve_path
from .enterprise import EnterpriseCommand
from .register import OneTimeShareCreateCommand
from .. import api, crypto, utils, generator, rest_api, vault, record_management, vault_extensions
from ..constants import EMAIL_PATTERN
from ..loginv3 import LoginV3API
from ..params import KeeperParams
from ..proto import enterprise_pb2


def register_commands(commands):
    commands['create-user'] = CreateEnterpriseUserCommand()


def register_command_info(_, command_info):
    command_info['create-user'] = 'Create Enterprise User'


register_parser = argparse.ArgumentParser(prog='create-user', description='Creates enterprise user')
register_parser.add_argument('--name', dest='name', action='store', help='user name')
register_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
register_parser.add_argument('--folder', dest='folder', action='store', help='folder name or UID to store password record')
register_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='print verbose information')
register_parser.add_argument('email', help='email')
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

        email = kwargs.get('email')
        if not email:
            logging.warning('Email parameter is required..')

        node_id = nodes[0]['node_id']
        emails = kwargs.get('email', [])
        email_pattern = re.compile(EMAIL_PATTERN)

        rq = enterprise_pb2.EnterpriseUsersProvisionRequest()
        rq.clientVersion = rest_api.CLIENT_VERSION
        tree_key = params.enterprise['unencrypted_tree_key']
        name = kwargs.get('name') or ''

        match = email_pattern.match(email)
        if not match:
            logging.warning('"%s" appears not a valid email address. Skipping.', email)
            return

        displayname = name if len(emails) == 1 else ''
        data = {'displayname': displayname or email}
        user_data = json.dumps(data).encode('utf-8')
        user_password = generator.generate(20)
        user_data_key = utils.generate_aes_key()
        rsa_private_key, rsa_public_key = crypto.generate_rsa_key()
        rsa_private = crypto.unload_rsa_private_key(rsa_private_key)
        rsa_public = crypto.unload_rsa_public_key(rsa_public_key)

        ec_private_key, ec_public_key = crypto.generate_ec_key()
        ec_private = crypto.unload_ec_private_key(ec_private_key)
        ec_public = crypto.unload_ec_public_key(ec_public_key)

        enterprise_user_id = EnterpriseCommand.get_enterprise_id(params)

        user_rq = enterprise_pb2.EnterpriseUsersProvision()
        user_rq.enterpriseUserId = enterprise_user_id
        user_rq.username = email
        user_rq.nodeId = node_id
        user_rq.encryptedData = utils.base64_url_encode(crypto.encrypt_aes_v1(user_data, tree_key))
        user_rq.keyType = enterprise_pb2.ENCRYPTED_BY_DATA_KEY
        user_rq.enterpriseUsersDataKey = crypto.encrypt_ec(user_data_key, params.enterprise_ec_key)
        user_rq.authVerifier = utils.create_auth_verifier(user_password, crypto.get_random_bytes(16), 100000)
        user_rq.encryptionParams = utils.create_encryption_params(user_password, crypto.get_random_bytes(16), 100000, user_data_key)
        user_rq.rsaPublicKey = rsa_public
        user_rq.rsaEncryptedPrivateKey = crypto.encrypt_aes_v1(rsa_private, user_data_key)
        user_rq.eccPublicKey = ec_public
        user_rq.eccEncryptedPrivateKey = crypto.encrypt_aes_v2(ec_private, user_data_key)
        user_rq.encryptedDeviceToken = LoginV3API.get_device_id(params)
        user_rq.encryptedClientKey = crypto.encrypt_aes_v1(utils.generate_aes_key(), user_data_key)

        rq.users.append(user_rq)

        rs = api.communicate_rest(params, rq, 'enterprise/enterprise_user_provision',
                                  rs_type=enterprise_pb2.EnterpriseUsersProvisionResponse)
        for user_rs in rs.results:
            if user_rs.code and user_rs.code not in ['success', 'ok']:
                email_provisioning_doc = 'https://docs.keeper.io/enterprise-guide/user-and-team-provisioning/email-auto-provisioning'
                logging.warning('Failed to auto-create account "%s".\n'
                                'Creating user accounts without email verification is only permitted on reserved domains.\n' +
                                'To reserve a domain please contact Keeper support. Learn more about domain reservation here:\n%s',
                                email, email_provisioning_doc)
                return

        login_facade = vault_extensions.LoginFacade()
        ots_command = OneTimeShareCreateCommand()
        records = []

        folder_uid = None
        folder_name = kwargs.get('folder')
        if folder_name:
            folder_uid = self.resolve_folder(params, folder_name)

        keeper_url = urlunparse(('https', params.server, '/vault', None, None, f'email/{email}'))
        record = vault.TypedRecord()
        login_facade.assign_record(record)
        login_facade.title = f'Keeper Account: {email}'
        login_facade.login = email
        login_facade.password = user_password
        login_facade.url = keeper_url
        login_facade.notes = 'The user is required to change their Master Password upon login.'
        record_management.add_record_to_folder(params, record, folder_uid=folder_uid)
        api.sync_down(params)
        records.append(record)
        ots_url = ots_command.execute(params, record=record.record_uid, share_name=f'{email}: Master Password', expire='7d')
        if ots_url:
            record.custom.append(vault.TypedField.new_field('url', ots_url, 'One-Time Share'))
            record_management.update_record(params, record)
            api.sync_down(params)

        if kwargs.get('verbose') is True:
            print(f'The account {login_facade.login} has been created. Login details below:')
            print(f'{"Vault Login URL:":>24s} {login_facade.url}')
            print(f'{"Email:":>24s} {login_facade.login}')
            if name:
                print(f'{"Name:":>24s} {name}')
            if len(nodes) > 0:
                node_name = (nodes[0].get('data') or {}).get('displayname') or ''
                if node_name:
                    print(f'{"Node:":>24s} {node_name}')
            print(f'{"Master Password:":>24s} {login_facade.password}')
            if ots_url:
                print(f'{"One-Time Share Link:":>24s} {ots_url}')
            print(f'{"Note:":>24s} {login_facade.notes}')
        else:
            logging.info('User \"%s\" credentials are stored to record \"%s\"', login_facade.login, login_facade.title)

    @staticmethod
    def resolve_folder(params, folder_name):    # type: (KeeperParams, str) -> Optional[str]
        if not folder_name:
            return

        if folder_name in params.folder_cache:
            return folder_name
        else:
            rs = try_resolve_path(params, folder_name)
            if rs is not None:
                folder, record_name = rs
                if folder and not record_name:
                    if folder.uid:
                        return folder.uid
