import argparse
import logging
import sys
from typing import Optional, List

from keepercommander import api, utils, crypto
from keepercommander.__main__ import get_params_from_config
from keepercommander.proto import folder_pb2

parser = argparse.ArgumentParser(description='Add user to shared folder')
parser.add_argument('--config', dest='config', action='store', help='Config file to use')
parser.add_argument('--debug', dest='debug', action='store_true', help='Enables debug logging')
parser.add_argument('--teams', dest='teams', action='store_true', help='Load teams')
parser.add_argument('-p', '--manage-records', dest='manage_records', action='store', choices=['on', 'off'],
                    help='account permission: can manage records.')
parser.add_argument('-o', '--manage-users', dest='manage_users', action='store',  choices=['on', 'off'],
                    help='account permission: can manage users.')
parser.add_argument('--add', dest='add', action='append', help='Users to add to a shared folder.')
parser.add_argument('--remove', dest='remove', action='append', help='Users to remove from shared folder.')
parser.add_argument('shared_folder', help='Shared Folder UID')
opts, flags = parser.parse_known_args(sys.argv[1:])

logging.basicConfig(level=logging.DEBUG if opts.debug is True else logging.WARNING, format='%(message)s')

my_params = get_params_from_config(opts.config or '')

api.login(my_params)
if not my_params.session_token:
    exit(1)

shared_folder_uid = opts.shared_folder
team_uids = []   # type: List[str]
shared_folder_key = None   # type: Optional[bytes]
can_manage_users = False

if opts.teams is True:
    sd_rq = {
        'command': 'sync_down',
        'includes': ['teams', 'explicit']
    }
    sd_rs = api.communicate(my_params, sd_rq)
    for team in sd_rs.get('teams', []):
        if 'shared_folder_keys' in team:
            sf_key = next((x for x in team['shared_folder_keys'] if x['shared_folder_uid'] == shared_folder_uid), None)
            if sf_key:
                team_uids.append(team['team_uid'])
                if not shared_folder_key:
                    encrypted_key = utils.base64_url_decode(team['team_key'])
                    team_key_type = team['team_key_type']
                    try:
                        if team_key_type == 1:
                            team_key = crypto.decrypt_aes_v1(encrypted_key, my_params.data_key)
                        elif team_key_type == 2:
                            team_key = crypto.decrypt_rsa(encrypted_key, my_params.rsa_key2)
                        elif team_key_type == 3:
                            team_key = crypto.decrypt_aes_v2(encrypted_key, my_params.data_key)
                        elif team_key_type == 4:
                            team_key = crypto.decrypt_ec(encrypted_key, my_params.ecc_key)
                        else:
                            continue
                    except:
                        continue
                    encrypted_key = utils.base64_url_decode(sf_key['shared_folder_key'])
                    key_type = sf_key['key_type']
                    try:
                        if key_type == 1:
                            shared_folder_key = crypto.decrypt_aes_v1(encrypted_key, team_key)
                        elif key_type == 2:
                            if 'team_private_key' in team:
                                encrypted_rsa_key = utils.base64_url_decode(team['team_private_key'])
                                rsa_key = crypto.load_rsa_private_key(crypto.decrypt_aes_v1(encrypted_rsa_key, team_key))
                                shared_folder_key = crypto.decrypt_rsa(encrypted_key, rsa_key)
                        elif key_type == 3:
                            shared_folder_key = crypto.decrypt_aes_v2(encrypted_key, team_key)
                        elif key_type == 4:
                            if 'team_ecc_private_key' in team:
                                encrypted_ec_key = utils.base64_url_decode(team['team_ecc_private_key'])
                                ec_key = crypto.load_ec_private_key(crypto.decrypt_aes_v2(encrypted_ec_key, team_key))
                                shared_folder_key = crypto.decrypt_ec(encrypted_key, ec_key)
                    except:
                        continue

sf_rq = {
    'shared_folder_uid': shared_folder_uid
}
if len(team_uids) > 0:
    sf_rq['team_uid'] = team_uids[0]
rq = {
    'command': 'get_shared_folders',
    'shared_folders': [sf_rq],
    'include': ['sfheaders', 'sfusers', 'sfteams']
}
sf_rs = api.communicate(my_params, rq)
if len(sf_rs['shared_folders']) == 0:
    raise ValueError(f'Shared folder UID "{shared_folder_uid}" not found')

shared_folder_info = sf_rs['shared_folders'][0]
if not shared_folder_key:
    if 'shared_folder_key' in shared_folder_info:
        encrypted_key = utils.base64_url_decode(shared_folder_info['shared_folder_key'])
        key_type = shared_folder_info["key_type"]
        if key_type == 1:
            shared_folder_key = crypto.decrypt_aes_v1(encrypted_key, my_params.data_key)
        elif key_type == 2:
            shared_folder_key = crypto.decrypt_rsa(encrypted_key, my_params.rsa_key2)
        elif key_type == 3:
            shared_folder_key = crypto.decrypt_aes_v2(encrypted_key, my_params.data_key)
        elif key_type == 4:
            shared_folder_key = crypto.decrypt_ec(encrypted_key, my_params.ecc_key)

if not shared_folder_key:
    raise ValueError(f'Key cannot be resolved: shared folder UID "{shared_folder_uid}"')

team_uid = None   # type: Optional[str]
permissions = next((x for x in shared_folder_info.get('users', []) if x['username'] == my_params.user and x.get('manage_users') is True), None)
if permissions and len(team_uids) > 0:
    permissions = next((x for x in shared_folder_info.get('teams', []) if x['team_uid'] in team_uids and x.get('manage_users') is True), None)
    if permissions:
        team_uid = permissions['team_uid']

existing_users = set()
if isinstance(shared_folder_info.get('users'), list):
    existing_users.update((x.get('username').lower() for x in shared_folder_info['users']))

users_to_add = []
if hasattr(opts, 'add'):
    if isinstance(opts.add, list):
        for email in opts.add:
            email = email.lower()
            if email in existing_users:
                logging.warning('Add user "%s": already belongs to the shared folder', email)
            else:
                users_to_add.append(email)

users_to_remove = []
if hasattr(opts, 'remove'):
    if isinstance(opts.remove, list):
        for email in opts.remove:
            email = email.lower()
            if email in existing_users:
                users_to_remove.append(email)
            else:
                logging.warning('Remove user "%s": does not belongs to the shared folder', email)

if len(users_to_add) > 0:
    public_keys = {x: None for x in users_to_add}
    api.load_user_public_keys(my_params, users_to_add, False)

manage_users = None
manage_records = None
if opts.manage_users:
    manage_users = opts.manage_users == 'on'
if opts.manage_records:
    manage_records = opts.manage_records == 'on'

rq = folder_pb2.SharedFolderUpdateV3Request()
rq.sharedFolderUid = utils.base64_url_decode(opts.shared_folder)
rq.forceUpdate = True

for user in users_to_add:
    arq = folder_pb2.SharedFolderUpdateUser()
    arq.username = user
    if isinstance(manage_users, bool):
        arq.manageUsers = folder_pb2.BOOLEAN_TRUE if manage_users else folder_pb2.BOOLEAN_FALSE
    if isinstance(manage_records, bool):
        arq.manageRecords = folder_pb2.BOOLEAN_TRUE if manage_records else folder_pb2.BOOLEAN_FALSE
    public_keys = my_params.key_cache.get(user)
    if public_keys and public_keys.rsa:
        user_rsa_key = crypto.load_rsa_public_key(public_keys.rsa)
        arq.sharedFolderKey = crypto.encrypt_rsa(shared_folder_key, user_rsa_key)
        rq.sharedFolderAddUser.append(arq)
    else:
        logging.warning('Add user "%s": User public key is not available', user)

for user in users_to_remove:
    rq.sharedFolderRemoveUser.append(user)

rs = api.communicate_rest(my_params, rq, 'vault/shared_folder_update_v3', rs_type=folder_pb2.SharedFolderUpdateV3Response)
for add_status in rs.sharedFolderAddUserStatus:
    if add_status.status != 'success':
        logging.warning(f'Failed to add user {add_status.username} to shared folder: {add_status.status}')
for remove_status in rs.sharedFolderRemoveUserStatus:
    if remove_status.status != 'success':
        logging.warning(f'Failed to add user {remove_status.username} to shared folder: {remove_status.status}')
