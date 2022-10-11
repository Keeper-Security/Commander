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
from typing import Tuple, Dict, Iterator, Union

from .base import RecordMixin, raise_parse_exception, suppress_exit, try_resolve_path
from .enterprise import EnterpriseCommand
from .. import api, crypto, utils, generator, rest_api, vault, record_management
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

        rq = enterprise_pb2.EnterpriseUsersProvisionRequest()
        rq.clientVersion = rest_api.CLIENT_VERSION
        tree_key = params.enterprise['unencrypted_tree_key']
        added_accounts = {}    # type: Dict[int, Tuple[str, str]]
        for email in emails:
            match = email_pattern.match(email)
            if not match:
                logging.warning('"%s" appears not a valid email address. Skipping.', email)
                continue

            displayname = kwargs.get('name', email)
            data = {'displayname': displayname}
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

            added_accounts[enterprise_user_id] = (email, user_password)

        if len(added_accounts) > 0:
            rs = api.communicate_rest(params, rq, 'enterprise/enterprise_user_provision',
                                      rs_type=enterprise_pb2.EnterpriseUsersProvisionResponse)
            for user_rs in rs.results:
                enterprise_user_id = user_rs.enterpriseUserId
                if user_rs.code and user_rs.code not in ['success', 'ok']:
                    username, _ = added_accounts.pop(enterprise_user_id, ('', ''))
                    logging.warning('Failed to add account "%s" to enterprise. %s.', username, user_rs.message)
                else:
                    username, _ = added_accounts.get(enterprise_user_id, ('', ''))
                    logging.info(f"User \"{username}\" successfully provisioned.\n" +
                                 "The user must reset their Master Password upon first login.")

        if len(added_accounts) == 0:
            logging.info('No users created.')
            return

        record_name = kwargs.get('record') or 'Enterprise User Passwords'
        record = next(self.resolve_records(params, record_name), None)
        if not record:
            record = vault.TypedRecord()
            record.type_name = 'encryptedNotes'
            record.title = record_name
            record.fields.append(vault.TypedField.new_field('note', 'This record is used to store temporary passwords of provisioned users.'))

        if isinstance(record, vault.PasswordRecord):
            record.custom.extend((vault.CustomField.new_field(username, password) for username, password in added_accounts.values()))
        elif isinstance(record, vault.TypedRecord):
            record.custom.extend((vault.TypedField.new_field(field_type='secret', field_value=password, field_label=username)
                                  for username, password in added_accounts.values()))
        try:
            if record.record_uid:
                record_management.update_record(params, record, skip_extra=True)
            else:
                record_management.add_record_to_folder(params, record)
            params.sync_data = True
        except Exception as e:
            logging.info('Record store error: %s', e)

    @staticmethod
    def resolve_records(params, record_name):
        # type: (KeeperParams, str) -> Iterator[Union[vault.PasswordRecord, vault.KeeperRecord]]
        if not record_name:
            return

        if record_name in params.record_cache:
            r = vault.KeeperRecord.load(params, record_name)
            if isinstance(r, (vault.PasswordRecord, vault.KeeperRecord)):
                yield r
        else:
            rs = try_resolve_path(params, record_name)
            if rs is not None:
                folder, record_name = rs
                if folder is not None and record_name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = vault.KeeperRecord.load(params, uid)
                            if isinstance(r, (vault.PasswordRecord, vault.KeeperRecord)):
                                if r and r.title.casefold() == record_name.casefold():
                                    yield r
