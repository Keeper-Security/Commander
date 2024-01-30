import argparse
import logging
import os
import sys

from keepercommander.__main__ import get_params_from_config
from keepercommander import api, utils, crypto, error
from keepercommander.proto import folder_pb2

parser = argparse.ArgumentParser(description='Add user to shared folder')
parser.add_argument('--debug', action='store_true', help='Enables debug logging')
parser.add_argument('-p', '--manage-records', dest='manage_records', action='store', choices=['on', 'off'],
                    help='account permission: can manage records.')
parser.add_argument('-o', '--manage-users', dest='manage_users', action='store',  choices=['on', 'off'],
                    help='account permission: can manage users.')
parser.add_argument('--add', dest='add', action='append', help='Users to add to a shared folder.')
parser.add_argument('--remove', dest='remove', action='append', help='Users to remove from shared folder.')
parser.add_argument('shared_folder', help='Shared Folder UID')
opts, flags = parser.parse_known_args(sys.argv[1:])

logging.basicConfig(level=logging.DEBUG if opts.debug is True else logging.WARNING, format='%(message)s')

my_params = get_params_from_config('')

api.login(my_params)
if not my_params.session_token:
    exit(1)

shared_folder_uid = opts.shared_folder

sf_rq = {
    'command': 'get_shared_folders',
    'shared_folders': [
        {
            'shared_folder_uid': shared_folder_uid
        }
    ],
    'include': ['sfheaders', 'sfusers']
}

sf_rs = api.communicate(my_params, sf_rq)
if len(sf_rs['shared_folders']) == 0:
    raise ValueError(f'Shared folder UID "{shared_folder_uid}" not found')

shared_folder_info = sf_rs['shared_folders'][0]
shared_folder_key = utils.base64_url_decode(shared_folder_info['shared_folder_key'])
shared_folder_key = crypto.decrypt_aes_v1(shared_folder_key, my_params.data_key)

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
