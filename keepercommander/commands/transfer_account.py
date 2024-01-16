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
import os
import json
import logging

from typing import Optional

from .. import api, crypto, utils
from ..params import KeeperParams
from .base import suppress_exit, raise_parse_exception, user_choice
from .enterprise_common import EnterpriseCommand
from ..display import bcolors

transfer_user_parser = argparse.ArgumentParser(prog='transfer-user', description='Transfer user account(s).')
transfer_user_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for confirmation')
transfer_user_parser.add_argument('--target-user', dest='target_user', action='store', help='email to transfer user(s) to')
transfer_user_parser.add_argument('email', type=str, nargs='+', metavar="user@company.com OR @filename",
                                  help='User account email/ID or File containing account mappings. Use @filename to indicate using mapping file. ' +
                                       'File content: from_account -> to_account')
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

        transfer_map = {}
        skipped_emails = set()

        def verify_user(username):   # type: (str) -> Optional[str]
            username = username.lower().strip()
            if username in skipped_emails:
                return None
            if username in user_lookup:
                enterprise_user = user_lookup[username]
                if enterprise_user['status'] == 'active':
                    return enterprise_user['username']
                else:
                    logging.warning('\"%s\" is a pending account. Skipping...', username)
                    return None
            else:
                logging.warning('\"%s\" is not a known user account. Skipping...', username)
                return None

        target_user = kwargs['target_user']
        if target_user:
            target_user = verify_user(target_user)

        if 'email' in kwargs:
            for email in kwargs['email']:   # type: str
                if email.startswith('@'):
                    filename = email[1:]
                    if os.path.exists(filename):
                        with open(filename, 'r') as f:
                            lines = f.readlines()
                        for line in lines:
                            line = line.strip()
                            if not line:
                                continue
                            if line[0] in {'#', ';', '-'}:
                                continue
                            p = line.partition('->')
                            if p[1] != '->':
                                p = line.partition('<-')
                                if p[1] != '<-':
                                    p = line.partition('=')
                                    if p[1] != '=':
                                        p = line.partition(' ')
                            if p[2]:
                                user1 = verify_user(p[0])
                                if user1:
                                    user2 = verify_user(p[2])
                                    if user2:
                                        if p[1] == '<-':
                                            from_user = user2
                                            to_user = user1
                                        else:
                                            from_user = user1
                                            to_user = user2
                                        if to_user not in transfer_map:
                                            transfer_map[to_user] = set()
                                        transfer_map[to_user].add(from_user)
                            else:
                                logging.warning('File \"%s\": invalid mapping \"line\". Skipping...', filename)
                    else:
                        logging.warning('File \"%s\" does not exist. Skipping...', filename)
                else:
                    email = verify_user(email)
                    if email and target_user:
                        if target_user not in transfer_map:
                            transfer_map[target_user] = set()
                        transfer_map[target_user].add(email)

        if len(transfer_map) == 0:
            logging.warning('No user accounts to transfer')
            return

        targets = set()
        sources = set()
        for target in transfer_map:
            targets.add(target)
            sources.update(transfer_map[target])
        to_delete = targets.intersection(sources)
        if len(to_delete) > 0:
            for email in to_delete:
                logging.warning('User account \"%s\" appears as both source and target for account transfer', email)
                if email in transfer_map:
                    del transfer_map[email]
            for target in list(transfer_map.keys()):
                transfer_map[target].difference_update(to_delete)
                if len(transfer_map[target]) == 0:
                    del transfer_map[target]

        if len(transfer_map) == 0:
            logging.warning('No user accounts to transfer')
            return

        sources.clear()
        to_delete.clear()
        for target in transfer_map:
            targets = transfer_map[target].intersection(sources)
            if len(targets) > 0:
                to_delete.update(targets)
            sources.update(transfer_map[target])

        if len(to_delete) > 0:
            for email in to_delete:
                logging.warning('User account \"%s\" cannot be moved to multiple targets.', email)
            for target in list(transfer_map.keys()):
                transfer_map[target].difference_update(to_delete)
                if len(transfer_map[target]) == 0:
                    del transfer_map[target]

        if len(transfer_map) == 0:
            logging.warning('No user accounts to transfer')
            return

        targets.clear()
        sources.clear()
        for target in transfer_map:
            targets.add(target)
            sources.update(transfer_map[target])

        if not kwargs.get('force', False):
            answer = user_choice(
                bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                'This action cannot be undone.\n\n' +
                f'Do you want to proceed with transferring {len(sources)} account(s)?', 'yn', 'n')
            if answer.lower() != 'y':
                return

        lock_rq = []
        for email in sources:
            user = user_lookup[email]
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

        public_keys = {}
        for target_user in list(transfer_map.keys()):
            target_public_key = self.get_public_key(params, target_user)
            if target_public_key:
                public_keys[target_user] = target_public_key
            else:
                logging.warning('Failed to get user \"%s\" public key', target_user)
                del transfer_map[target_user]

        for target_user in transfer_map:
            target_public_key = public_keys[target_user]
            for email in transfer_map[target_user]:
                logging.info('Transferring %s account to %s ...', email, target_user)
                self.transfer_user_account(params, email, target_user, target_public_key)

        api.query_enterprise(params)
        params.sync_data = True

    @staticmethod
    def transfer_user_account(params, username, target_user, target_public_key):
        # type: (KeeperParams, str, str, any) -> bool
        rq = {
            'command': 'pre_account_transfer',
            'target_username': username,
        }
        try:
            rs = api.communicate(params, rq)
            tree_key = params.enterprise['unencrypted_tree_key']
            role_key = None
            if 'role_key' in rs:
                role_key = utils.base64_url_decode(rs['role_key'])
                role_key = crypto.decrypt_rsa(role_key, params.rsa_key2)
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
                        elif record_key_type == 4:
                            record_key = crypto.decrypt_ec(record_key, user_ecc_private_key)
                        elif record_key_type == 0:
                            record_key = transfer_key
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
            result = True
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
            result = False
            logging.warning('Failed to transfer %s account: %s', username, e)

        return result

