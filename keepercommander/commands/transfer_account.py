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

from typing import Optional

from .. import api, crypto, utils
from ..error import CommandError
from .base import suppress_exit, raise_parse_exception, user_choice
from .enterprise_common import EnterpriseCommand
from ..display import bcolors

transfer_user_parser = argparse.ArgumentParser(prog='transfer-user|tu', description='Transfer user account(s).')
transfer_user_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
transfer_user_parser.add_argument('--target-user', dest='target_user', action='store', help='email to transfer user(s) to')
transfer_user_parser.add_argument('email', type=str, nargs='+', help='User Email or ID. Can be repeated.')
transfer_user_parser.error = raise_parse_exception
transfer_user_parser.exit = suppress_exit


class EnterpriseTransferUserCommand(EnterpriseCommand):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return transfer_user_parser

    def execute(self, params, **kwargs):
        user_lookup = {}
        if 'users' in params.enterprise:
            for u in params.enterprise['users']:
                user_lookup[str(u['enterprise_user_id'])] = u

                if 'username' in u:
                    user_lookup[u['username'].lower()] = u
                else:
                    logging.debug('WARNING: username is missing from the user id=%s, obj=%s', u['enterprise_user_id'], u)

        target_user = kwargs['target_user']
        if not target_user:
            raise CommandError('transfer-user', 'Target user is missing')
        target_user = target_user.lower()
        if target_user not in user_lookup:
            raise CommandError('transfer-user', f'Target user {target_user} not found')

        target_user = user_lookup[target_user]['username']
        target_public_key = self.get_public_key(params, target_user)
        if not target_public_key:
            raise CommandError('transfer-user', f'Failed to get user {target_user} public key')

        matched_users = []
        unmatched_emails = set()
        if 'email' in kwargs:
            for email in kwargs['email']:
                email = email.lower()
                if email in user_lookup:
                    user = user_lookup[email]
                    username = user['username']
                    if username != target_user:
                        if user['status'] == 'active':
                            matched_users.append(user)
                        else:
                            logging.warning('%s: Cannot transfer pending users. Skipping...', username)
                    else:
                        logging.warning('%s: Cannot transfer account to self. Skipping...', target_user)

                else:
                    unmatched_emails.add(email)

        for username in unmatched_emails:
            logging.warning('%s: User not found. Skipping...', username)

        if len(matched_users) == 0:
            logging.warning('No user accounts to transfer')
            return

        if not kwargs.get('force', False):
            answer = user_choice(
                bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                'This action cannot be undone.\n\n' +
                f'Do you want to proceed with transferring {len(matched_users)} account(s)?', 'yn', 'n')
            if answer.lower() != 'y':
                return

        lock_rq = []
        for user in matched_users:
            lock = user.get('lock', 0)
            if lock != 1:
                lock_rq.append({
                    'command': 'enterprise_user_lock',
                    'enterprise_user_id': user['enterprise_user_id'],
                    'lock': 'locked'
                })
        if len(lock_rq) > 0:
            logging.info('Locking active users.')
            api.execute_batch(params, lock_rq)

        for user in matched_users:
            username = user['username']
            rq = {
                'command': 'pre_account_transfer',
                'target_username': username,
            }
            logging.warning('Transferring %s account...', username)
            try:
                rs = api.communicate(params, rq)
                tree_key = params.enterprise['unencrypted_tree_key']
                role_key = None
                if 'role_key' in rs:
                    role_key = utils.base64_url_decode(rs['role_key'])
                    role_key = crypto.decrypt_rsa(role_key, params.rsa_key)
                elif 'role_key_id' in rs:
                    role_key_id = rs['role_key_id']
                    if 'role_keys2' in params.enterprise:
                        key2 = next((x for x in params.enterprise['role_keys2'] if x['role_id'] == role_key_id), None)
                        if key2:
                            role_key = utils.base64_url_decode(key2['role_key'])
                            role_key = crypto.decrypt_aes_v2(role_key, tree_key)
                if not role_key:
                    raise Exception('Cannot resolve Account Transfer role key')
                role_private_key = utils.base64_url_decode(rs['role_private_key']) if 'role_private_key' in rs else None
                role_private_key = crypto.decrypt_aes_v1(role_private_key, role_key)
                role_private_key = crypto.load_rsa_private_key(role_private_key)
                transfer_key = utils.base64_url_decode(rs['transfer_key'])
                transfer_key = crypto.decrypt_rsa(transfer_key, role_private_key)
                user_rsa_private_key = utils.base64_url_decode(rs['user_private_key']) if 'user_private_key' in rs else None
                if user_rsa_private_key:
                    user_rsa_private_key = crypto.decrypt_aes_v1(user_rsa_private_key, transfer_key)
                    user_rsa_private_key = crypto.load_rsa_private_key(user_rsa_private_key)
                user_ecc_private_key = utils.base64_url_decode(rs['user_ecc_private_key']) if 'user_ecc_private_key' in rs else None
                if user_ecc_private_key:
                    user_ecc_private_key = crypto.decrypt_aes_v2(user_ecc_private_key, transfer_key)
                    user_ecc_private_key = crypto.load_ec_private_key(user_ecc_private_key)

                rqt = {
                    'command': 'transfer_and_delete_user',
                    'from_user': username,
                    'to_user': target_user
                }
                if 'record_keys' in rs:
                    rqt['record_keys'] = []
                    rqt['corrupted_record_keys'] = []
                    for rk in rs['record_keys']:
                        record_uid = rk['record_uid']
                        try:
                            record_key = utils.base64_url_decode(rk['record_key'])
                            record_key_type = rk.get('record_key_type', 1)
                            if record_key_type == 1:
                                record_key = crypto.decrypt_aes_v1(record_key, transfer_key)
                            elif record_key_type == 2:
                                record_key = crypto.decrypt_rsa(record_key, user_rsa_private_key)
                            elif record_key_type == 3:
                                record_key = crypto.decrypt_aes_v2(record_key, transfer_key)
                            elif record_key_type == 3:
                                record_key = crypto.decrypt_ec(record_key, user_ecc_private_key)
                            else:
                                raise Exception(f'Unsupported record key type')

                            rqt['record_keys'].append({
                                'record_uid': record_uid,
                                'record_key': utils.base64_url_encode(crypto.encrypt_rsa(record_key, target_public_key))
                            })
                        except Exception as e:
                            logging.debug('Corrupted record key: %s: %s', record_uid, e)
                            rqt['corrupted_record_keys'].append(rk)

                if 'shared_folder_keys' in rs:
                    rqt['shared_folder_keys'] = []
                    rqt['corrupted_shared_folder_keys'] = []
                    for sfk in rs['shared_folder_keys']:
                        shared_folder_uid = sfk['shared_folder_uid']
                        try:
                            shared_folder_key = utils.base64_url_decode(sfk['shared_folder_key'])
                            shared_folder_key_type = sfk.get('shared_folder_key_type', 1)
                            if shared_folder_key_type == 1:
                                shared_folder_key = crypto.decrypt_aes_v1(shared_folder_key, transfer_key)
                            elif shared_folder_key_type == 2:
                                shared_folder_key = crypto.decrypt_rsa(shared_folder_key, user_rsa_private_key)
                            elif shared_folder_key_type == 3:
                                shared_folder_key = crypto.decrypt_aes_v2(shared_folder_key, transfer_key)
                            elif shared_folder_key_type == 4:
                                shared_folder_key = crypto.decrypt_ec(shared_folder_key, user_ecc_private_key)
                            else:
                                raise Exception(f'Unsupported shared folder key type')

                            rqt['shared_folder_keys'].append({
                                'shared_folder_uid': shared_folder_uid,
                                'shared_folder_key': utils.base64_url_encode(crypto.encrypt_rsa(shared_folder_key, target_public_key)),
                            })
                        except Exception as e:
                            logging.debug('Corrupted shared folder key: %s: %s', shared_folder_uid, e)
                            rqt['corrupted_shared_folder_keys'].append(sfk)

                if 'team_keys' in rs:
                    rqt['team_keys'] = []
                    rqt['corrupted_team_keys'] = []
                    for tk in rs['team_keys']:
                        team_uid = tk['team_uid']
                        try:
                            team_key = utils.base64_url_decode(tk['team_key'])
                            team_key_type = tk.get('team_key_type', 1)
                            if team_key_type == 1:
                                team_key = crypto.decrypt_aes_v1(team_key, transfer_key)
                            elif team_key_type == 2:
                                team_key = crypto.decrypt_rsa(team_key, user_rsa_private_key)
                            elif team_key_type == 3:
                                team_key = crypto.decrypt_aes_v2(team_key, transfer_key)
                            elif team_key_type == 4:
                                team_key = crypto.decrypt_ec(team_key, user_ecc_private_key)
                            else:
                                raise Exception(f'Unsupported team key type')
                            rqt['team_keys'].append({
                                'team_uid': team_uid,
                                'team_key': utils.base64_url_encode(crypto.encrypt_rsa(team_key, target_public_key)),
                            })
                        except Exception as e:
                            logging.debug('Corrupted team key: %s: %s', team_uid, e)
                            rqt['corrupted_team_keys'].append(tk)

                if 'user_folder_keys' in rs:
                    rqt['user_folder_keys'] = []
                    rqt['corrupted_user_folder_keys'] = []
                    folder_key = utils.generate_aes_key()
                    folder_data = json.dumps({
                        'name': f'Transfer from {username}'
                    }).encode('utf-8')
                    folder_data = crypto.encrypt_aes_v1(folder_data, folder_key)
                    rqt['user_folder_transfer'] = {
                        'transfer_folder_uid': utils.generate_uid(),
                        'transfer_folder_key': utils.base64_url_encode(crypto.encrypt_rsa(folder_key, target_public_key)),
                        'transfer_folder_data': utils.base64_url_encode(folder_data)
                    }
                    for ufk in rs['user_folder_keys']:
                        user_folder_uid = ufk['user_folder_uid']
                        try:
                            user_folder_key = utils.base64_url_decode(ufk['user_folder_key'])
                            user_folder_key_type = ufk.get('user_folder_key_type', 1)
                            if user_folder_key_type == 1:
                                user_folder_key = crypto.decrypt_aes_v1(user_folder_key, transfer_key)
                            elif user_folder_key_type == 2:
                                user_folder_key = crypto.decrypt_rsa(user_folder_key, user_rsa_private_key)
                            elif user_folder_key_type == 3:
                                user_folder_key = crypto.decrypt_aes_v2(user_folder_key, transfer_key)
                            elif user_folder_key_type == 4:
                                user_folder_key = crypto.decrypt_ec(user_folder_key, user_ecc_private_key)
                            else:
                                raise Exception(f'Unsupported user folder key type')
                            rqt['user_folder_keys'].append({
                                'user_folder_uid': user_folder_uid,
                                'user_folder_key': utils.base64_url_encode(crypto.encrypt_rsa(user_folder_key, target_public_key)),
                            })
                        except Exception as e:
                            logging.debug('Corrupted user folder key: %s: %s', user_folder_uid, e)
                            rqt['corrupted_user_folder_keys'].append(ufk)

                api.communicate(params, rqt)
                logging.info('%s: account is transferred', username)
                if 'record_keys' in rqt:
                    rec_num = len(rqt['record_keys'])
                    if rec_num > 0:
                        logging.info(f'{"Records":>16} : {rec_num}')
                if 'shared_folder_keys' in rqt:
                    sf_num = len(rqt['shared_folder_keys'])
                    if sf_num > 0:
                        logging.info(f'{"SharedFolders":>16} : {sf_num}')

            except Exception as e:
                logging.warning('Failed to transfer %s account: %s', username, e)

        api.query_enterprise(params)
