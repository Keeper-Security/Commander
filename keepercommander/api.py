#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2017 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
import base64
import collections
import re
import getpass
import time
import os
import hashlib
import logging
import urllib.parse

from . import rest_api, APIRequest_pb2 as proto, loginv3
from .subfolder import UserFolderNode, SharedFolderNode, SharedFolderFolderNode, RootFolderNode
from .record import Record
from .shared_folder import SharedFolder
from .team import Team
from .error import AuthenticationError, CommunicationError, CryptoError, KeeperApiError
from .params import KeeperParams, LAST_RECORD_UID
from .display import bcolors

from Cryptodome import Random
from Cryptodome.Hash import SHA256

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_v1_5


current_milli_time = lambda: int(round(time.time() * 1000))


# PKCS7 padding helpers
BS = 16
pad_binary = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
unpad_binary = lambda s: s[0:-s[-1]]
unpad_char = lambda s: s[0:-ord(s[-1])]


def run_command(params, request):
    # type: (KeeperParams, dict) -> dict
    if 'client_version' not in request:
        request['client_version'] = rest_api.CLIENT_VERSION

    return rest_api.v2_execute(params.rest_context, request)


def derive_key(password, salt, iterations):
    # type: (str, bytes, int) -> bytes
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, 32)


def auth_verifier(password, salt, iterations):
    derived_key = derive_key(password, salt, iterations)
    derived_key = hashlib.sha256(derived_key).digest()
    au_ver = base64.urlsafe_b64encode(derived_key)
    return au_ver.decode().rstrip('=')


warned_on_fido_package = False
install_fido_package_warning = 'You can use Security Key with Commander:\n' +\
                               'Install fido2 package ' + bcolors.OKGREEN +\
                               '\'pip install fido2\'' + bcolors.ENDC


def login(params):
    # type: (KeeperParams) -> None

    if params.login_v3:
        logging.info('Logging in to Keeper Commander')
        loginv3.LoginV3Flow.login(params)
        return

    logging.info("Logging in...")

    global should_cancel_u2f
    global u2f_response
    global warned_on_fido_package

    success = False
    store_config = False

    while not success:
        if not params.auth_verifier:
            if not params.user or not params.password:
                return

            logging.debug('No auth verifier, sending pre-auth request')
            try:
                pre_login_rs = rest_api.pre_login(params.rest_context, params.user)
                auth_params = get_correct_salt(pre_login_rs.salt)
                params.iterations = auth_params.iterations
                params.salt = auth_params.salt
                params.auth_verifier = auth_verifier(params.password, params.salt, params.iterations)
            except KeeperApiError as e:
                params.auth_verifier = None
                if e.result_code == 'user_does_not_exist':
                    email = params.user
                    params.user = ''
                    params.password = ''
                    raise AuthenticationError('User account [{0}] not found.'.format(email))
                raise

        rq = {
            'command': 'login',
            'include': ['keys', 'license', 'settings', 'enforcements', 'is_enterprise_admin'],
            'version': 2,
            'auth_response': params.auth_verifier,
            'username': params.user.lower(),
            'platform_device_token': base64.urlsafe_b64encode(params.rest_context.device_id).decode('utf-8').rstrip('=')
        }

        if params.enterprise_id > 0:
            rq['enterprise_id'] = params.enterprise_id

        if params.mfa_token:
            rq['2fa_token'] = params.mfa_token
            rq['2fa_type'] = params.mfa_type or 'device_token'
            if params.mfa_type == 'one_time':
                expire_token = params.config.get('device_token_expiration') or False
                expire_days = 0 if expire_token else 9999
                rq['device_token_expire_days'] = expire_days

        rq['client_version'] = rest_api.LEGACY_CLIENT_VERSION   # this login only supports up to v14 clients.

        response_json = run_command(params, rq)

        if 'device_token' in response_json:
            logging.debug('params.mfa_token=%s', params.mfa_token)
            params.mfa_token = response_json['device_token']
            params.mfa_type = 'device_token'
            if response_json.get('dt_scope') == 'expiration':
                store_config = True
                params.config['mfa_token'] = params.mfa_token

        if 'keys' in response_json:
            keys = response_json['keys']
            if 'encryption_params' in keys:
                params.data_key = decrypt_encryption_params(keys['encryption_params'], params.password)
            elif 'encrypted_data_key' in keys:
                encrypted_data_key = base64.urlsafe_b64decode(keys['encrypted_data_key'])
                key = rest_api.derive_key_v2('data_key', params.password, params.salt, params.iterations)
                params.data_key = rest_api.decrypt_aes(encrypted_data_key, key)

            params.rsa_key = decrypt_rsa_key(keys['encrypted_private_key'], params.data_key)

        if 'session_token' in response_json:
            params.session_token = response_json['session_token']

        if response_json['result_code'] == 'auth_success' and response_json['result'] == 'success':
            success = True
            logging.debug('Auth Success')
            store_config = not params.config or params.config.get('user') != params.user

            params.session_token = response_json['session_token']

            device_id = base64.urlsafe_b64encode(params.rest_context.device_id).decode('utf-8').rstrip('=')
            if params.config.get('device_id') != device_id:
                store_config = True
                params.config['device_id'] = device_id
                url1 = urllib.parse.urlsplit(params.server)
                url2 = urllib.parse.urlsplit(params.rest_context.server_base)
                if url1.netloc != url2.netloc:
                    params.config['server'] = params.rest_context.server_base

            params.license = response_json.get('license')
            params.enforcements = response_json.get('enforcements')
            if params.enforcements:
                if 'logout_timer_desktop' in params.enforcements:
                    logout_timer = params.enforcements['logout_timer_desktop']
                    if logout_timer > 0:
                        if params.logout_timer == 0 or logout_timer < params.logout_timer:
                            params.logout_timer = logout_timer
            params.settings = response_json.get('settings')

            if response_json.get('is_enterprise_admin'):
                query_enterprise(params)
                query_msp(params)

            params.sync_data = True
            params.prepare_commands = True

            if store_config:    # save token to config file if the file exists
                params.config['user'] = params.user

                if params.config_filename:
                    try:
                        with open(params.config_filename, 'w') as f:
                            json.dump(params.config, f, ensure_ascii=False, indent=2)
                            logging.info('Updated %s', params.config_filename)
                    except Exception as e:
                        logging.debug('Unable to update %s. %s', params.config_filename, e)

        elif response_json['result_code'] in ['need_totp', 'invalid_device_token', 'invalid_totp']:
            try:
                params.mfa_token = ''
                params.mfa_type = 'one_time'

                if 'u2f_challenge' in response_json:
                    try:
                        from .yubikey import u2f_authenticate
                        challenge = json.loads(response_json['u2f_challenge'])
                        u2f_request = challenge['authenticateRequests']
                        u2f_response = u2f_authenticate(u2f_request)
                        if u2f_response:
                            signature = json.dumps(u2f_response)
                            params.mfa_token = signature
                            params.mfa_type = 'u2f'
                    except ImportError as e:
                        logging.error(e)
                        if not warned_on_fido_package:
                            logging.warning(install_fido_package_warning)
                            warned_on_fido_package = True
                    except Exception as e:
                        logging.error(e)

                while not params.mfa_token:
                    try:
                        params.mfa_token = getpass.getpass(prompt='Two-Factor Code: ', stream=None)
                    except KeyboardInterrupt as e:
                        print('')
                        params.clear_session()
                        return

            except (EOFError, KeyboardInterrupt, SystemExit):
                return

        elif response_json['result_code'] == 'auth_expired':
            try:
                params.password = ''
                params.auth_verifier = None
                logging.warning(response_json['message'])
                if not change_master_password(params):
                    raise AuthenticationError('')
            finally:
                params.session_token = None

        elif response_json['result_code'] == 'auth_expired_transfer':
            share_account_to = response_json['settings']['share_account_to']
            logging.warning(response_json['message'])
            try:
                if not accept_account_transfer_consent(params, share_account_to):
                    raise AuthenticationError('')
            finally:
                params.session_token = None

        elif response_json['result_code'] == 'auth_failed':
            params.password = ''
            params.auth_verifier = None
            raise AuthenticationError('Authentication failed.')

        elif response_json['result_code']:
            raise KeeperApiError(response_json['result_code'], response_json['message'])

        else:
            raise CommunicationError('Unknown problem')


def change_master_password(params):
    user_params = rest_api.get_new_user_params(params.rest_context, params.user)
    try:
        while True:
            print('')
            print('Please choose a new Master Password.')
            password = getpass.getpass(prompt='... {0:>24}: '.format('Master Password'), stream=None).strip()
            if not password:
                raise KeyboardInterrupt()
            password2 = getpass.getpass(prompt='... {0:>24}: '.format('Re-Enter Password'), stream=None).strip()

            if password == password2:
                failed_rules = []
                for desc, regex in zip(user_params.passwordMatchDescription, user_params.passwordMatchRegex):
                    pattern = re.compile(regex)
                    if not re.match(pattern, password):
                        failed_rules.append(desc)
                if len(failed_rules) == 0:
                    auth_salt = os.urandom(16)
                    data_salt = os.urandom(16)
                    rq = {
                        'command': 'change_master_password',
                        'auth_verifier': create_auth_verifier(password, auth_salt, params.iterations),
                        'encryption_params': create_encryption_params(password, data_salt, params.iterations, params.data_key)
                    }
                    communicate(params, rq)
                    params.password = password
                    params.salt = auth_salt
                    logging.info('Password changed')
                    return True
                else:
                    for rule in failed_rules:
                        logging.warning(rule)
            else:
                logging.warning('Passwords do not match.')
    except KeyboardInterrupt:
        logging.info('Canceled')

    return False


def accept_account_transfer_consent(params, share_account_to):
    print('')
    answer = input('Do you accept Account Transfer policy? Accept/C(ancel): ')
    answer = answer.lower()
    if answer.lower() == 'accept':
        for role in share_account_to:
            public_key = RSA.importKey(base64.urlsafe_b64decode(role['public_key'] + '=='))
            transfer_key = encrypt_rsa(params.data_key, public_key)
            request = {
                'command': 'share_account',
                'to_role_id': role['role_id'],
                'transfer_key': transfer_key
            }
            communicate(params, request)
        return True
    else:
        logging.info('Canceled')

    return False


def decrypt_aes_plain(data: bytes, key: bytes):
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=data[:12])
    return cipher.decrypt_and_verify(data[12:-16], data[-16:])


def decrypt_aes(data, key):
    # type: (str, bytes) -> bytes
    decoded_data = base64.urlsafe_b64decode(data + '==')
    iv = decoded_data[:16]
    ciphertext = decoded_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


def decrypt_data(data, key):
    # type: (str, bytes) -> bytes
    return unpad_binary(decrypt_aes(data, key))


def encrypt_aes_plain(data: bytes, key: bytes):
    iv = os.urandom(12)
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    enc_data, tag = cipher.encrypt_and_digest(data)
    return iv + enc_data + tag


def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad_binary(data))
    return (base64.urlsafe_b64encode(encrypted_data).decode()).rstrip('=')


def encrypt_aes_key(key_to_encrypt, encryption_key):
    iv = os.urandom(16)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(key_to_encrypt)
    return (base64.urlsafe_b64encode(encrypted_data).decode()).rstrip('=')


def encrypt_rsa_plain(data, rsa_key):
    cipher = PKCS1_v1_5.new(rsa_key)
    return cipher.encrypt(data)


def encrypt_rsa(data, rsa_public_key):
    cipher = PKCS1_v1_5.new(rsa_public_key)
    encrypted_data = cipher.encrypt(data)
    return (base64.urlsafe_b64encode(encrypted_data).decode('utf-8')).rstrip('=')


def decrypt_rsa(data, rsa_private_key):
    decoded_key = base64.urlsafe_b64decode(data + '==')
    # some keys might come shorter due to stripping leading 0's
    if 250 < len(decoded_key) < 256:
        decoded_key = bytearray(256 - len(decoded_key)) + decoded_key
    dsize = SHA256.digest_size
    sentinel = Random.new().read(15 + dsize)
    cipher = PKCS1_v1_5.new(rsa_private_key)
    return cipher.decrypt(decoded_key, sentinel)


def decrypt_rsa_key(encrypted_private_key, data_key):
    """ Decrypt the RSA private key
    PKCS1 formatted private key, which is described by the ASN.1 type:
    RSAPrivateKey ::= SEQUENCE {
          version           Version,
          modulus           INTEGER,  -- n
          publicExponent    INTEGER,  -- e
          privateExponent   INTEGER,  -- d
          prime1            INTEGER,  -- p
          prime2            INTEGER,  -- q
          exponent1         INTEGER,  -- d mod (p-1)
          exponent2         INTEGER,  -- d mod (q-1)
          coefficient       INTEGER,  -- (inverse of q) mod p
          otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }
    """
    return RSA.importKey(decrypt_data(encrypted_private_key, data_key))


def merge_lists_on_value(list1, list2, field_name):
    d = {x[field_name]: x for x in list1}
    d.update({x[field_name]: x for x in list2})
    return [x for x in d.values()]


def sync_down(params):
    """Sync full or partial data down to the client"""

    params.sync_data = False

    if params.revision == 0:
        logging.info('Syncing...')

    rq = {
        'command': 'sync_down',
        'revision': params.revision or 0,
        'include': ['sfheaders', 'sfrecords', 'sfusers', 'teams', 'folders']
    }
    response_json = communicate(params, rq)

    check_convert_to_folders = False

    def delete_record_key(rec_uid):
        if rec_uid in params.record_cache:
            record = params.record_cache[rec_uid]
            if 'record_key_unencrypted' in record:
                del record['record_key_unencrypted']
                if 'data_unencrypted' in record:
                    del record['data_unencrypted']
                if 'extra_unencrypted' in record:
                    del record['extra_unencrypted']

    def delete_shared_folder_key(sf_uid):
        if sf_uid in params.shared_folder_cache:
            shared_folder = params.shared_folder_cache[sf_uid]
            if 'shared_folder_key_unencrypted' in shared_folder:
                del shared_folder['shared_folder_key_unencrypted']
                if 'records' in shared_folder:
                    for sfr in shared_folder['records']:
                        record_uid = sfr['record_uid']
                        if record_uid not in params.meta_data_cache:
                            delete_record_key(record_uid)

    def delete_team_key(team_uid):
        if team_uid in params.team_cache:
            team = params.team_cache[team_uid]
            if 'team_key_unencrypted' in team:
                del team['team_key_unencrypted']
                if 'shared_folder_keys' in team:
                    for sfk in team['shared_folder_keys']:
                        delete_shared_folder_key(sfk['shared_folder_uid'])

    params.available_team_cache = None
    if 'full_sync' in response_json:
        if response_json['full_sync']:
            if params.debug: print('Full Sync response')
            check_convert_to_folders = True
            params.record_cache.clear()
            params.meta_data_cache.clear()
            params.shared_folder_cache.clear()
            params.team_cache.clear()
            params.available_team_cache = None
            params.non_shared_data_cache.clear()
            params.subfolder_cache.clear()
            params.subfolder_record_cache.clear()
            params.record_history.clear()

    if 'revision' in response_json:
        logging.debug('Getting revision %d', params.revision)
        params.revision = response_json['revision']

    if 'removed_records' in response_json:
        logging.debug('Processing removed records')
        for record_uid in response_json['removed_records']:
            # remove record metadata
            if record_uid in params.meta_data_cache:
                del params.meta_data_cache[record_uid]
            # delete record key
            delete_record_key(record_uid)
            # remove record from user folders
            for folder_uid in params.subfolder_record_cache:
                if record_uid in params.subfolder_record_cache[folder_uid]:
                    if folder_uid in params.subfolder_cache:
                        folder = params.subfolder_cache[folder_uid]
                        if folder.get('type') == 'user_folder':
                            params.subfolder_record_cache[folder_uid].remove(record_uid)
                    elif folder_uid == '':
                        params.subfolder_record_cache[folder_uid].remove(record_uid)

    if 'removed_teams' in response_json:
        logging.debug('Processing removed teams')
        for team_uid in response_json['removed_teams']:
            delete_team_key(team_uid)
            # remove team from shared folder
            for shared_folder_uid in params.shared_folder_cache:
                shared_folder = params.shared_folder_cache[shared_folder_uid]
                if 'teams' in shared_folder:
                    shared_folder['teams'] = [x for x in shared_folder['teams'] if x['team_uid'] != team_uid]
            if team_uid in params.team_cache:
                del params.team_cache[team_uid]

    if 'removed_shared_folders' in response_json:
        logging.debug('Processing removed shared folders')
        for sf_uid in response_json['removed_shared_folders']:
            if sf_uid in params.shared_folder_cache:
                delete_shared_folder_key(sf_uid)
                if sf_uid in params.subfolder_record_cache:
                    del params.subfolder_record_cache[sf_uid]
                shared_folder = params.shared_folder_cache[sf_uid]
                if 'shared_folder_key' in shared_folder:
                    del shared_folder['shared_folder_key']
                if 'key_type' in shared_folder:
                    del shared_folder['key_type']
                if 'users' in shared_folder:
                    shared_folder['users'] = [x for x in shared_folder['users'] if x['username'] != params.user]

    if 'user_folders_removed' in response_json:
        for ufr in response_json['user_folders_removed']:
            f_uid = ufr['folder_uid']
            if f_uid in params.subfolder_cache:
                del params.subfolder_cache[f_uid]
            if f_uid in params.subfolder_record_cache:
                del params.subfolder_record_cache[f_uid]

    if 'shared_folder_folder_removed' in response_json:
        for sffr in response_json['shared_folder_folder_removed']:
            f_uid = sffr['folder_uid'] if 'folder_uid' in sffr else sffr['shared_folder_uid']
            if f_uid in params.subfolder_cache:
                del params.subfolder_cache[f_uid]
            if f_uid in params.subfolder_record_cache:
                del params.subfolder_record_cache[f_uid]

    if 'user_folder_shared_folders_removed' in response_json:
        for ufsfr in response_json['user_folder_shared_folders_removed']:
            f_uid = ufsfr['shared_folder_uid']
            if f_uid in params.subfolder_cache:
                del params.subfolder_cache[f_uid]
            if f_uid in params.subfolder_record_cache:
                del params.subfolder_record_cache[f_uid]

    if 'user_folders_removed_records' in response_json:
        for ufrr in response_json['user_folders_removed_records']:
            f_uid = ufrr.get('folder_uid') or ''
            if f_uid in params.subfolder_record_cache:
                rs = params.subfolder_record_cache[f_uid]
                r_uid = ufrr['record_uid']
                if r_uid in rs:
                    rs.remove(r_uid)

    if 'shared_folder_folder_records_removed' in response_json:
        for sfrrr in response_json['shared_folder_folder_records_removed']:
            f_uid = sfrrr['folder_uid'] if 'folder_uid' in sfrrr else sfrrr['shared_folder_uid']
            if f_uid in params.subfolder_record_cache:
                rs = params.subfolder_record_cache[f_uid]
                r_uid = sfrrr['record_uid']
                if r_uid in rs:
                    rs.remove(r_uid)

    if 'non_shared_data' in response_json:
        for non_shared_data in response_json['non_shared_data']:
            if 'data' in non_shared_data and non_shared_data['data']:
                try:
                    decrypted_data = decrypt_data(non_shared_data['data'], params.data_key)
                    non_shared_data['data_unencrypted'] = decrypted_data
                    params.non_shared_data_cache[non_shared_data['record_uid']] = non_shared_data
                except:
                    logging.debug('Non-shared data for record %s could not be decrypted', non_shared_data['record_uid'])

    # convert record keys from RSA to AES-256
    if 'record_meta_data' in response_json:
        logging.debug('Processing record_meta_data')
        for meta_data in response_json['record_meta_data']:
            try:
                if 'record_key' not in meta_data:
                    # old record that doesn't have a record key so make one
                    logging.debug('...no record key.  creating...')
                    # store as b64 encoded string
                    # note: decode() converts bytestream (b') to string
                    # note2: remove == from the end
                    meta_data['record_key_unencrypted'] = os.urandom(32)
                    meta_data['record_key'] = encrypt_aes(meta_data['record_key_unencrypted'], params.data_key)
                    meta_data['record_key_type'] = 1
                    # temporary flag for decryption routine below
                    meta_data['old_record_flag'] = True
                    meta_data['is_converted_record_type'] = True

                elif meta_data['record_key_type'] == 2:
                    logging.debug('Converting RSA-encrypted key')
                    # decrypt the type2 key using their RSA key
                    unencrypted_key = decrypt_rsa(meta_data['record_key'], params.rsa_key)
                    if len(unencrypted_key) == 32:
                        meta_data['record_key_unencrypted'] = unencrypted_key
                        meta_data['record_key'] = encrypt_aes(meta_data['record_key_unencrypted'], params.data_key)
                        meta_data['record_key_type'] = 1
                        meta_data['is_converted_record_type'] = True

                elif meta_data['record_key_type'] == 1:
                    meta_data['record_key_unencrypted'] = decrypt_data(meta_data['record_key'], params.data_key)
            except Exception as e:
                logging.debug('Decryption error: %s', e)

            # add to local cache
            if 'record_key_unencrypted' in meta_data:
                params.meta_data_cache[meta_data['record_uid']] = meta_data
            else:
                logging.error('Could not decrypt meta data key: %s', meta_data['record_uid'])

    if 'teams' in response_json:
        for team in response_json['teams']:
            if team['team_key_type'] == 2:
                team['team_key_unencrypted'] = decrypt_rsa(team['team_key'], params.rsa_key)
            else:
                team['team_key_unencrypted'] = decrypt_data(team['team_key'], params.data_key)
            team['team_private_key_unencrypted'] = decrypt_rsa_key(team['team_private_key'], team['team_key_unencrypted'])

            if 'removed_shared_folders' in team:
                for sf_uid in team['removed_shared_folders']:
                    delete_shared_folder_key(sf_uid)
            params.team_cache[team['team_uid']] = team

    if 'shared_folders' in response_json:
        logging.debug('Processing shared_folders')
        for shared_folder in response_json['shared_folders']:
            shared_folder_uid = shared_folder['shared_folder_uid']

            if shared_folder_uid in params.shared_folder_cache and shared_folder.get('full_sync'):
                logging.debug('Shared Folder full sync: %s', shared_folder_uid)
                del params.shared_folder_cache[shared_folder_uid]

            if shared_folder_uid in params.shared_folder_cache:
                delete_shared_folder_key(shared_folder_uid)

                # incremental shared folder upgrade
                existing_sf = params.shared_folder_cache[shared_folder_uid]

                if ('records_removed' in shared_folder) and ('records' in existing_sf):
                    rrs = set(shared_folder['records_removed'])
                    existing_sf['records'] = [record for record in existing_sf['records'] if record['record_uid'] not in rrs]

                if ('users_removed' in shared_folder) and ('users' in existing_sf):
                    urs = set(shared_folder['users_removed'])
                    existing_sf['users'] = [user for user in existing_sf['users'] if user['username'] not in urs]

                if ('teams_removed' in shared_folder) and ('teams' in existing_sf):
                    trs = set(shared_folder['teams_removed'])
                    existing_sf['teams'] = [team for team in existing_sf['teams'] if team['team_uid'] not in trs]

                if 'records' in shared_folder:
                    existing_records = existing_sf['records'] if 'records' in existing_sf else []
                    existing_sf['records'] = merge_lists_on_value(existing_records, shared_folder['records'], 'record_uid')

                if 'users' in shared_folder:
                    existing_users = existing_sf['users'] if 'users' in existing_sf else ''
                    existing_sf['users'] = merge_lists_on_value(existing_users, shared_folder['users'], 'username')

                if 'teams' in shared_folder:
                    existing_teams = existing_sf['teams'] if 'teams' in existing_sf else ''
                    existing_sf['teams'] = merge_lists_on_value(existing_teams, shared_folder['teams'], 'team_uid')

                existing_sf['revision'] = shared_folder['revision']
                if 'manage_records' in shared_folder:
                    existing_sf['manage_records'] = shared_folder['manage_records']
                if 'manage_users' in shared_folder:
                    existing_sf['manage_users'] = shared_folder['manage_users']
                if 'is_account_folder' in shared_folder:
                    existing_sf['is_account_folder'] = shared_folder['is_account_folder']
                if 'name' in shared_folder:
                    existing_sf['name'] = shared_folder['name']
            else:
                params.shared_folder_cache[shared_folder_uid] = shared_folder

    if 'records' in response_json:
        logging.debug('Processing records')
        for record in response_json['records']:
            params.record_cache[record['record_uid']] = record

    # process team keys
    for team_uid in params.team_cache:
        team = params.team_cache[team_uid]
        for sf_key in team['shared_folder_keys']:
            if 'shared_folder_key_unencrypted' not in sf_key:
                try:
                    if sf_key['key_type'] == 2:
                        sf_key['shared_folder_key_unencrypted'] = decrypt_rsa(sf_key['shared_folder_key'], team['team_private_key_unencrypted'])
                    else:
                        sf_key['shared_folder_key_unencrypted'] = decrypt_data(sf_key['shared_folder_key'], team['team_key_unencrypted'])
                except Exception as e:
                    logging.debug('Decryption error: %s', e)

    # process shared folder keys
    sf_to_delete = []
    for shared_folder_uid in params.shared_folder_cache:
        shared_folder = params.shared_folder_cache[shared_folder_uid]
        if 'shared_folder_key_unencrypted' not in shared_folder:
            if 'shared_folder_key' in shared_folder:
                try:
                    if shared_folder['key_type'] == 2:
                        shared_folder['shared_folder_key_unencrypted'] = decrypt_rsa(shared_folder['shared_folder_key'], params.rsa_key)
                    else:
                        shared_folder['shared_folder_key_unencrypted'] = decrypt_data(shared_folder['shared_folder_key'], params.data_key)
                except Exception as e:
                    logging.debug('Decryption error: %s', e)
            else:
                if 'teams' in shared_folder:
                    teams_to_remove = set()
                    for to in shared_folder['teams']:
                        team_uid = to['team_uid']
                        if team_uid in params.team_cache:
                            team = params.team_cache[team_uid]
                            if 'shared_folder_keys' in team:
                                sfk = [x for x in team['shared_folder_keys'] if x['shared_folder_uid'] == shared_folder_uid]
                                if len(sfk) > 0:
                                    if 'shared_folder_key_unencrypted' in sfk[0]:
                                        shared_folder['shared_folder_key_unencrypted'] = sfk[0]['shared_folder_key_unencrypted']
                                        break
                        else:
                            teams_to_remove.add(team_uid)
                        if len(teams_to_remove) > 0:
                            shared_folder['teams'] = [x for x in shared_folder['teams'] if x['team_uid'] not in teams_to_remove]

            if 'shared_folder_key_unencrypted' in shared_folder:
                try:
                    shared_folder['name_unencrypted'] = decrypt_data(shared_folder['name'], shared_folder['shared_folder_key_unencrypted']).decode('utf-8')
                except Exception as e:
                    logging.debug('Shared folder %s name decryption error: %s', shared_folder_uid, e)
                    shared_folder['name_unencrypted'] = shared_folder_uid
                if 'records' in shared_folder:
                    for sfr in shared_folder['records']:
                        if 'record_key_unencrypted' not in sfr:
                            try:
                                sfr['record_key_unencrypted'] = decrypt_data(sfr['record_key'], shared_folder['shared_folder_key_unencrypted'])
                            except Exception as e:
                                logging.debug('Shared folder %s record key decryption error: %s', shared_folder_uid, e)

            else:
                sf_to_delete.append(shared_folder_uid)

    if len(sf_to_delete) > 0:
        for shared_folder_uid in sf_to_delete:
            logging.debug('Delete shared folder with unresolved key: %s', shared_folder_uid)
            del params.shared_folder_cache[shared_folder_uid]
            if shared_folder_uid in params.subfolder_cache:
                del params.subfolder_cache[shared_folder_uid]

    # process record keys
    records_to_delete = []
    for record_uid in params.record_cache:
        record = params.record_cache[record_uid]
        record_key = record.get('record_key_unencrypted')
        if not record_key:
            if record_uid in params.meta_data_cache:
                meta_data = params.meta_data_cache[record_uid]
                record_key = meta_data['record_key_unencrypted']
                record['record_key_unencrypted'] = record_key
                if meta_data.get('old_record_flag'):
                    record_key = params.data_key

            if 'record_key_unencrypted' not in record:
                for shared_folder_uid in params.shared_folder_cache:
                    shared_folder = params.shared_folder_cache[shared_folder_uid]
                    if 'records' in shared_folder:
                        recs = [x['record_key_unencrypted'] for x in shared_folder['records'] if x['record_uid'] == record_uid and 'record_key_unencrypted' in x]
                        if len(recs) > 0:
                            record_key = recs[0]
                            record['record_key_unencrypted'] = record_key
                            break

            if record_key:
                try:
                    record['data_unencrypted'] = decrypt_data(record['data'], record_key) if 'data' in record else b'{}'
                    record['extra_unencrypted'] = decrypt_data(record['extra'], record_key) if 'extra' in record else b'{}'
                except Exception as e:
                    logging.debug('Record %s data/extra decryption error: %s', record_uid, e)
            else:
                records_to_delete.append(record_uid)

    for record_uid in records_to_delete:
        params.record_cache.pop(record_uid)

    # decrypt user folders
    if 'user_folders' in response_json:
        check_convert_to_folders = False
        for uf in response_json['user_folders']:
            encrypted_key = uf['user_folder_key']
            if uf['key_type'] == 2:
                uf['folder_key_unencrypted'] = decrypt_rsa(encrypted_key, params.rsa_key)
            else:
                uf['folder_key_unencrypted'] = decrypt_data(encrypted_key, params.data_key)
            params.subfolder_cache[uf['folder_uid']] = uf

    # decrypt shared folder folders
    if 'shared_folder_folders' in response_json:
        check_convert_to_folders = False
        for sff in response_json['shared_folder_folders']:
            encrypted_key = sff['shared_folder_folder_key']
            sf_uid = sff['shared_folder_uid']
            if sf_uid in params.shared_folder_cache:
                sf = params.shared_folder_cache[sf_uid]
                sff['folder_key_unencrypted'] = decrypt_data(encrypted_key, sf['shared_folder_key_unencrypted'])
                params.subfolder_cache[sff['folder_uid']] = sff

    if 'user_folder_shared_folders' in response_json:
        check_convert_to_folders = False
        for ufsf in response_json['user_folder_shared_folders']:
            ufsf['type'] = 'shared_folder'
            sf_uid = ufsf['shared_folder_uid']
            if sf_uid in params.shared_folder_cache:
                params.subfolder_cache[sf_uid] = ufsf

    if 'user_folder_records' in response_json:
        for ufr in response_json['user_folder_records']:
            fuid = ufr.get('folder_uid') or ''
            if fuid not in params.subfolder_record_cache:
                params.subfolder_record_cache[fuid] = set()
            record_uid = ufr['record_uid']
            if record_uid in params.record_cache:
                params.subfolder_record_cache[fuid].add(record_uid)

    if 'shared_folder_folder_records' in response_json:
        for sffr in response_json['shared_folder_folder_records']:
            key = sffr['folder_uid'] if 'folder_uid' in sffr else sffr['shared_folder_uid']
            if key not in params.subfolder_record_cache:
                params.subfolder_record_cache[key] = set()
            record_uid = sffr['record_uid']
            if record_uid in params.record_cache:
                params.subfolder_record_cache[key].add(record_uid)

    if 'sharing_changes' in response_json:
        for sharing_change in response_json['sharing_changes']:
            record_uid = sharing_change['record_uid']
            if record_uid in params.record_cache:
                record = params.record_cache[record_uid]
                record['shared'] = sharing_change['shared']
    for record in params.record_cache.values():
        if 'shares' in record:
            del record['shares']

    prepare_folder_tree(params)

    if 'pending_shares_from' in response_json:
        params.pending_share_requests.update(response_json['pending_shares_from'])

    try:
        if check_convert_to_folders:
            rq = {
                'command': 'check_flag',
                'flag': 'folders'
            }
            rs = communicate(params, rq)
            if rs['result'] == 'success':
                if not rs['value']:
                    if convert_to_folders(params):
                        params.revision = 0
                        sync_down(params)
                        return
    except:
        pass

    if 'full_sync' in response_json:
        logging.info('Decrypted [%s] record(s)', len(params.record_cache))


def convert_to_folders(params):
    folders = {}

    for uid in params.record_cache:
        if uid in params.meta_data_cache:
            rec = get_record(params, uid)
            if len(rec.folder) > 0:
                key = rec.folder.lower()
                if key not in folders:
                    folder_key = os.urandom(32)
                    data = {'name': rec.folder}
                    folders[key] = {
                        'folder_uid': generate_record_uid(),
                        'data': encrypt_aes(json.dumps(data).encode('utf-8'), folder_key),
                        'folder_key': encrypt_aes(folder_key, params.data_key),
                        'records': []
                    }
                folders[key]['records'].append(uid)

    if len(folders) > 0:
        rq = {
            'command': 'convert_to_folders',
            'folders': [],
            'records': []
        }
        for f in folders.values():
            rq['folders'].append({
                'folder_uid': f['folder_uid'],
                'data': f['data'],
                'folder_key': f['folder_key']
            })
            for ruid in f['records']:
                rq['records'].append({
                    'folder_uid': f['folder_uid'],
                    'record_uid': ruid
                })
        rs = communicate(params, rq)
        return rs['result'] == 'success'

    return False


def create_auth_verifier(password, salt, iterations):
    # type: (str, bytes, int) -> str

    derived_key = derive_key(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    auth_ver = b'\x01' + enc_iter + salt + derived_key
    return loginv3.CommonHelperMethods.bytes_to_url_safe_str(auth_ver)


def create_encryption_params(password, salt, iterations, data_key):
    # type: (str, bytes, int, bytes) -> str

    derived_key = derive_key(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    enc_iv = os.urandom(16)
    cipher = AES.new(derived_key, AES.MODE_CBC, enc_iv)
    enc_data_key = cipher.encrypt(data_key + data_key)
    enc_params = b'\x01' + enc_iter + salt + enc_iv + enc_data_key
    return loginv3.CommonHelperMethods.bytes_to_url_safe_str(enc_params)


def decrypt_encryption_params(encryption_params, password):
    """ Decrypt the data key returned by the server 
    Format:
    1 byte: Version number (currently only 1)
    3 bytes: Iterations, unsigned integer, big endian
    16 bytes: salt
    80 bytes: encrypted data key (broken down further below)
        16 bytes: IV
        64 bytes: ciphertextIn
    Key for encrypting the data key: 
        PBKDF2_with_HMAC_SHA256(iterations, salt, master password, 256-bit)
    Encryption method: 256-bit AES, CBC mode, no padding
    Verification: the decrypted ciphertext should contain two 32 byte values, 
        identical to each other.
    """
    if not encryption_params:
        raise CryptoError('Invalid encryption params: empty')

    decoded_encryption_params = base64.urlsafe_b64decode(encryption_params+'==')

    if len(decoded_encryption_params) != 100:
        raise CryptoError('Invalid encryption params: bad params length')

    version = int.from_bytes(decoded_encryption_params[0:1], byteorder='big', signed=False)
    iterations = int.from_bytes(decoded_encryption_params[1:4], byteorder='big', signed=False)
    if iterations < 1000:
        raise CryptoError('Invalid encryption parameters: iterations too low')

    salt = decoded_encryption_params[4:20]
    encrypted_data_key = decoded_encryption_params[20:100]

    key = derive_key(password, salt, iterations)
    cipher = AES.new(key, AES.MODE_CBC, encrypted_data_key[:16])
    decrypted_data_key = cipher.decrypt(encrypted_data_key[16:])

    # validate the key is formatted correctly
    if len(decrypted_data_key) != 64:
        raise CryptoError('Invalid data key length')

    if decrypted_data_key[:32] != decrypted_data_key[32:]:
        raise CryptoError('Invalid data key: failed mirror verification')

    logging.debug('Decrypted data key with success.')

    # save the encryption params 
    return decrypted_data_key[:32]


def decrypt_data_key(params: KeeperParams, encrypted_data_key):

    encrypted_data_key_len = len(encrypted_data_key)

    # [12 bytes: nonce / iv]
    # [32 bytes: ciphertext]
    # [16 bytes: auth - tag]

    if encrypted_data_key_len != 60:
        raise CryptoError('Invalid encryption params: Encrypted data key was unexpected length ' + str(encrypted_data_key_len))

    decryption_key = rest_api.derive_key_v2('data_key', params.password, params.salt, params.iterations)

    return rest_api.decrypt_aes(encrypted_data_key, decryption_key)


def get_record(params,record_uid):
    """Return the referenced record cache"""
    record_uid = record_uid.strip()

    if not record_uid:
        logging.warning('No record UID provided')
        return

    if not params.record_cache:
        logging.warning('No record cache.  Sync down first.')
        return

    if not record_uid in params.record_cache:
        logging.warning('Record UID not found.')
        return

    cached_rec = params.record_cache[record_uid]
    rec = Record()

    try:
        data = json.loads(cached_rec['data_unencrypted'].decode('utf-8'))
        rec = Record(record_uid)
        extra = None
        if 'extra_unencrypted' in cached_rec:
            extra = json.loads(cached_rec['extra_unencrypted'].decode('utf-8'))
        rec.load(data, revision=cached_rec['revision'], extra=extra)
        if not resolve_record_view_path(params, record_uid):
            rec.mask_password()
    except:
        logging.error('**** Error decrypting record %s', record_uid)

    return rec


def is_shared_folder(params,shared_folder_uid):
    shared_folder_uid = shared_folder_uid.strip()

    if not shared_folder_uid:
        return False

    if not params.shared_folder_cache:
        return False

    if shared_folder_uid not in params.shared_folder_cache:
        return False

    return True


def is_team(params,team_uid):
    team_uid = team_uid.strip()

    if not team_uid:
        return False

    if not params.team_cache:
        return False

    if team_uid not in params.team_cache:
        return False

    return True 


def get_shared_folder(params,shared_folder_uid):
    """Return the referenced shared folder"""
    shared_folder_uid = shared_folder_uid.strip()

    if not shared_folder_uid:
        logging.warning('No shared folder UID provided')
        return None

    if not params.shared_folder_cache:
        logging.warning('No shared folder cache.  Sync down first.')
        return None

    if shared_folder_uid not in params.shared_folder_cache:
        logging.warning('Shared folder UID not found.')
        return None

    cached_sf = params.shared_folder_cache[shared_folder_uid]

    logging.debug('Cached Shared Folder: ' + str(cached_sf))

    sf = SharedFolder(shared_folder_uid)
    sf.load(cached_sf, cached_sf['revision'])

    return sf


def load_user_public_keys(params, emails):  # type: (KeeperParams, list) -> None
    emails_to_load = [x for x in emails if x.lower() not in params.key_cache]
    if not emails_to_load:
        return
    rq = {
        'command': 'public_keys',
        'key_owners': emails
    }
    rs = communicate(params, rq)
    if 'public_keys' in rs:
        for pk in rs['public_keys']:
            if 'public_key' in pk:
                email = pk['key_owner']
                public_key = base64.urlsafe_b64decode(pk['public_key'] + '==')
                try:
                    params.key_cache[email] = RSA.importKey(public_key)
                except Exception as e:
                    logging.debug(e)


def load_team_keys(params, team_uids):          # type: (KeeperParams, list) -> None
    uids_to_load = [x for x in team_uids if x not in params.key_cache]
    if not uids_to_load:
        return
    rq = {
        'command': 'team_get_keys',
        'teams': uids_to_load
    }
    rs = communicate(params, rq)
    if 'keys' in rs:
        for tk in rs['keys']:
            if 'key' in tk:
                team_uid = tk['team_uid']
                try:
                    if tk['type'] == 1:
                        params.key_cache[team_uid] = decrypt_data(tk['key'], params.data_key)
                    elif tk['type'] == 2:
                        params.key_cache[team_uid] = decrypt_rsa(tk['key'], params.rsa_key)
                    elif tk['type'] == 3:
                        public_key = base64.urlsafe_b64decode(tk['key'] + '==')
                        params.key_cache[team_uid] = RSA.importKey(public_key)
                except Exception as e:
                    logging.debug(e)


def load_available_teams(params):
    if params.available_team_cache is not None:
        return

    rq = {
        'command': 'get_available_teams'
    }
    try:
        rs = communicate(params, rq)
        params.available_team_cache = rs.get('teams')
        for t in params.available_team_cache:
            team_uid = t['team_uid']
            if team_uid in params.team_cache:
                team = params.team_cache[team_uid]
                if 'team_key_unencrypted' in team:
                    params.key_cache[team_uid] = team['team_key_unencrypted']

    except Exception as e:
        logging.debug(e)


def get_team(params,team_uid):
    """Return the referenced team """
    team_uid = team_uid.strip()

    if not team_uid:
        logging.warning('No team UID provided')
        return

    if not params.team_cache:
        logging.warning('No team cache.  Sync down first.')
        return

    if team_uid not in params.team_cache:
        logging.warning('Team UID not found.')
        return

    cached_team = params.team_cache[team_uid]

    logging.debug('Cached Team: %s', cached_team)

    team = Team(team_uid)
    team.load(cached_team)

    return team


def search_records(params, searchstring):
    """Search for string in record contents 
       and return array of Record objects """

    logging.debug('Searching for %s', searchstring)
    p = re.compile(searchstring.lower())
    search_results = []

    for record_uid in params.record_cache:
        rec = get_record(params, record_uid)
        target = rec.to_lowerstring()
        if p.search(target):
            search_results.append(rec)
            
    return search_results


def search_shared_folders(params, searchstring):
    """Search shared folders """

    logging.debug('Searching for %s', searchstring)
    p = re.compile(searchstring.lower())

    search_results = [] 

    for shared_folder_uid in params.shared_folder_cache:

        logging.debug('Getting Shared Folder UID: %s', shared_folder_uid)
        sf = get_shared_folder(params, shared_folder_uid)
        target = sf.to_lowerstring()

        if p.search(target):
            logging.debug('Search success')
            search_results.append(sf)
     
    return search_results


def search_teams(params, searchstring):
    """Search teams """

    logging.debug('Searching for %s', searchstring)
    p = re.compile(searchstring.lower())

    search_results = [] 

    for team_uid in params.team_cache:

        logging.debug('Getting Team UID: %s', team_uid)
        team = get_team(params, team_uid)

        target = team.to_lowerstring()

        if p.search(target):
            logging.debug('Search success')
            search_results.append(team)
     
    return search_results


def prepare_record(params, record):
    """ Prepares the Record() object to be sent to the Keeper Cloud API
        by serializing and encrypting it in the proper JSON format used for
        transmission.  If the record has no UID, one is generated and the
        encrypted record key is sent to the server.  If this record was
        converted from RSA to AES we send the new record key. If the record
        is in a shared folder, must send shared folder UID for edit permission.
    """

    # build a record dict for upload
    record_object = {
        'version': 2,
        'client_modified_time': current_milli_time()
    }

    if not record.record_uid:
        logging.debug('Generated Record UID: %s', record.record_uid)
        record.record_uid = generate_record_uid()

    record_object['record_uid'] = record.record_uid

    data = {}
    extra = {}
    udata = {}
    unencrypted_key = None
    if record.record_uid in params.record_cache:
        path = resolve_record_write_path(params, record.record_uid)
        if path:
            record_object.update(path)
        else:
            logging.error('You do not have edit permissions on this record')
            return None

        rec = params.record_cache[record.record_uid]

        data.update(json.loads(rec['data_unencrypted'].decode('utf-8')))
        if data.get('secret2') != record.password:
            params.queue_audit_event('record_password_change', record_uid=record.record_uid)

        if 'extra' in rec:
            extra.update(json.loads(rec['extra_unencrypted'].decode('utf-8')))
        if 'udata' in rec:
            udata.update(rec['udata'])
        unencrypted_key = rec['record_key_unencrypted']
        record_object['revision'] = rec['revision']
        if record.record_uid in params.meta_data_cache and params.meta_data_cache[record.record_uid].get('is_converted_record_type'):
            logging.debug('Converted record sends record key')
            record_object['record_key'] = encrypt_aes(unencrypted_key, params.data_key)
    else:
        logging.debug('Generated record key')
        unencrypted_key = os.urandom(32)
        record_object['record_key'] = encrypt_aes(unencrypted_key, params.data_key)
        record_object['revision'] = 0

    data['title'] = record.title
    data['folder'] = record.folder
    data['secret1'] = record.login
    data['secret2'] = record.password
    data['link'] = record.login_url
    data['notes'] = record.notes
    data['custom'] = record.custom_fields

    record_object['data'] = encrypt_aes(json.dumps(data).encode('utf-8'), unencrypted_key)
    record_object['extra'] = encrypt_aes(json.dumps(extra).encode('utf-8'), unencrypted_key)
    record_object['udata'] = udata

    try:
        if params.license and 'account_type' in params.license:
            if record.password and params.license['account_type'] == 2:
                for record_uid in params.record_cache:
                    if record_uid != record.record_uid:
                        rec = get_record(params, record_uid)
                        if rec.password == record.password:
                            params.queue_audit_event('reused_password', record_uid=record.record_uid)
                            break
    except:
        pass

    return record_object


def communicate_rest(params, request, endpoint):
    api_request_payload = proto.ApiRequestPayload()
    api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(params.session_token + '==')
    api_request_payload.payload = request.SerializeToString()
    rs = None
    try:
        rs = rest_api.execute_rest(params.rest_context, endpoint, api_request_payload)
    except Exception as e:
        raise KeeperApiError('Rest API', str(e))
    if type(rs) == bytes:
        return rs
    elif type(rs) == dict:
        raise KeeperApiError(rs['error'], rs['message'])
    raise KeeperApiError('Error', endpoint)


def communicate(params, request):
    # type: (KeeperParams, dict) -> dict

    def authorize_request(rq):
        rq['client_time'] = current_milli_time()
        rq['locale'] = 'en_US'
        rq['device_id'] = 'Commander'
        rq['session_token'] = params.session_token
        rq['username'] = params.user.lower()

    if not params.session_token:
        login(params)

    authorize_request(request)
    logging.debug('payload: %s', request)

    response_json = run_command(params, request)

    if response_json['result_code'] == 'auth_failed':
        logging.debug('Re-authorizing.')
        login(params)
        if not params.session_token:
            return response_json
        authorize_request(request)
        response_json = run_command(params, request)
    if response_json['result'] != 'success':
        if response_json['result_code']:
            if response_json['result_code'] == 'auth_failed':
                params.clear_session()
            else:
                raise KeeperApiError(response_json['result_code'], response_json['message'])

    return response_json


def execute_batch(params, requests):
    # type: (KeeperParams, [dict]) -> [dict]
    responses = []
    if not requests:
        return responses

    chunk_size = 80
    queue = requests.copy()
    while len(queue) > 0:
        chunk = queue[:chunk_size]
        queue = queue[chunk_size:]

        rq = {
            'command': 'execute',
            'requests': chunk
        }
        try:
            rs = communicate(params, rq)
            if 'results' in rs:
                results = rs['results']  # type: list
                if len(results) > 0:
                    responses.extend(results)
                    if params.debug:
                        pos = len(results) - 1
                        req = chunk[pos]
                        res = results[pos]
                        if res['result'] != 'success':
                            logging.info('execute failed: command %s: %s)', req.get('command'), res.get('message'))
                    if len(results) < len(chunk):
                        queue = chunk[len(results):] + queue

        except Exception as e:
            logging.error(e)
        if len(chunk) > 50:
            time.sleep(5)

    return responses


def update_record(params, record, **kwargs):
    """ Push a record update to the cloud. 
        Takes a Record() object, converts to record JSON
        and pushes to the Keeper cloud API
    """
    record_rq = prepare_record(params, record)
    if record_rq is None:
        return

    request = {
        'command': 'record_update',
        'update_records': [record_rq]
    }
    response_json = communicate(params, request)

    new_revision = 0
    if 'update_records' in response_json:
        for info in response_json['update_records']:
            if info['record_uid'] == record.record_uid:
                if info['status'] == 'success':
                    new_revision = response_json['revision']

    if new_revision == 0:
        logging.error('Error: Revision not updated')
        return False

    if new_revision == record_rq['revision']:
        logging.error('Error: Revision did not change')
        return False

    if not kwargs.get('silent'):
        logging.info('Update record successful for record_uid=%s, revision=%d, new_revision=%s',
                     record_rq['record_uid'], record_rq['revision'], new_revision)

    record_rq['revision'] = new_revision

    # sync down the data which updates the caches
    sync_down(params)

    return True


def add_record(params, record):
    # type: (KeeperParams, Record) -> bool

    new_record = prepare_record(params, record)
    request = {
        'command': 'record_update',
        'add_records': [new_record]
    }
    response_json = communicate(params, request)

    if response_json['result'] == 'success':
        new_revision = 0
        if 'add_records' in response_json:
            for info in response_json['add_records']:
                if info['record_uid'] == record.record_uid:
                    if info['status'] == 'success':
                        new_revision = response_json['revision']

        if new_revision == 0:
            logging.error('Error: Revision not updated')
            return False

        if new_revision == new_record['revision']:
            logging.error('Error: Revision did not change')
            return False

        logging.info('New record successful for record_uid=%s, revision=%d, new_revision=%d',
                     new_record['record_uid'], new_record['revision'], new_revision)

        new_record['revision'] = new_revision

        # update record UID
        record.record_uid = new_record['record_uid']

        # sync down the data which updates the caches
        sync_down(params)
        params.environment_variables[LAST_RECORD_UID] = record.record_uid
        return True


def delete_record(params, record_uid):
    """ Delete a record """  
    request = {
        'command': 'record_update',
        'delete_records': [record_uid]
    }
    _ = communicate(params, request)
    logging.info('Record deleted with success')
    sync_down(params)
    return True


def store_non_shared_data(params, record_uid, data):
    # type: (KeeperParams, str, dict) -> None
    if record_uid not in params.record_cache:
        logging.error('Record UID %s does not exist.', record_uid)
        return

    ur = resolve_record_access_path(params, record_uid)
    ur['non_shared_data'] = encrypt_aes(json.dumps(data).encode('utf-8'), params.data_key)
    ur['client_modified_time'] = current_milli_time()
    ur['version'] = 2
    if record_uid in params.non_shared_data_cache:
        ur['revision'] = params.non_shared_data_cache[record_uid]['revision']
    else:
        ur['revision'] = 0

    request = {
        'command': 'record_update',
        'update_records': [ur]
    }
    _ = communicate(params, request)
    sync_down(params)


def generate_record_uid():
    """ Generate url safe base 64 16 byte uid """
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('=')


def generate_aes_key():
    return os.urandom(32)


def prepare_folder_tree(params):
    # type: (KeeperParams) -> None
    params.folder_cache = {}
    params.root_folder = RootFolderNode()

    for sf in params.subfolder_cache.values():
        if sf['type'] == 'user_folder':
            uf = UserFolderNode()
            uf.uid = sf['folder_uid']
            uf.parent_uid = sf.get('parent_uid')
            try:
                data = json.loads(decrypt_data(sf['data'], sf['folder_key_unencrypted']).decode())
            except Exception as e:
                logging.debug('Error decrypting user folder name. Folder UID: %s. Error: %s', uf.uid, e)
                data = {}
            uf.name = data['name'] if 'name' in data else uf.uid
            params.folder_cache[uf.uid] = uf

        elif sf['type'] == 'shared_folder_folder':
            sff = SharedFolderFolderNode()
            sff.uid = sf['folder_uid']
            sff.shared_folder_uid = sf['shared_folder_uid']
            sff.parent_uid = sf.get('parent_uid') or sff.shared_folder_uid
            try:
                data = json.loads(decrypt_data(sf['data'], sf['folder_key_unencrypted']).decode())
            except Exception as e:
                logging.debug('Error decrypting shared folder folder name. Folder UID: %s. Error: %s', sff.uid, e)
                data = {}
            sff.name = data['name'] if 'name' in data else sff.uid
            params.folder_cache[sff.uid] = sff

        elif sf['type'] == 'shared_folder':
            shf = SharedFolderNode()
            shf.uid = sf['shared_folder_uid']
            shf.parent_uid = sf.get('folder_uid')
            folder = params.shared_folder_cache.get(shf.uid)
            if folder is not None:
                shf.name = folder['name_unencrypted']
            params.folder_cache[shf.uid] = shf

    for f in params.folder_cache.values():
        parent_folder = params.folder_cache.get(f.parent_uid) if f.parent_uid else params.root_folder
        if parent_folder:
            parent_folder.subfolders.append(f.uid)


def resolve_record_permission_path(params, record_uid, permission):
    # type: (KeeperParams, str, str) -> dict or None

    for ap in enumerate_record_access_paths(params, record_uid):
        if ap.get(permission):
            path = {
                'record_uid': record_uid
            }
            if 'shared_folder_uid' in ap:
                path['shared_folder_uid'] = ap['shared_folder_uid']
            if 'team_uid' in ap:
                path['team_uid'] = ap['team_uid']
            return path

    return None


def resolve_record_write_path(params, record_uid):
    # type: (KeeperParams, str) -> dict or None
    return resolve_record_permission_path(params, record_uid, 'can_edit')


def resolve_record_share_path(params, record_uid):
    # type: (KeeperParams, str) -> dict or None
    return resolve_record_permission_path(params, record_uid, 'can_share')


def resolve_record_view_path(params, record_uid):
    # type: (KeeperParams, str) -> dict or None
    return resolve_record_permission_path(params, record_uid, 'can_view')


def resolve_record_access_path(params, record_uid, path=None):
    # type: (KeeperParams, str, dict or None) -> dict
    best_path = None

    for ap in enumerate_record_access_paths(params, record_uid):
        use_this_path = False
        if not best_path:
            use_this_path = True
        else:
            if not best_path.get('can_edit') and ap.get('can_edit'):
                use_this_path = True
            elif not best_path.get('can_share') and ap.get('can_share'):
                use_this_path = True
            elif not best_path.get('can_view') and ap.get('can_view'):
                use_this_path = True

        if use_this_path:
            best_path = ap
            if best_path.get('can_edit') and best_path.get('can_share') and best_path.get('can_view'):
                break

    if path is None:
        path = {}

    if best_path:
        path['record_uid'] = best_path['record_uid']
        if 'shared_folder_uid' in best_path:
            path['shared_folder_uid'] = best_path['shared_folder_uid']
        if 'team_uid' in best_path:
            path['team_uid'] = best_path['team_uid']

    return path


def enumerate_record_access_paths(params, record_uid):
    # type: (KeeperParams, str) -> collections.Iterable[dict]

    if record_uid in params.meta_data_cache:
        rmd = params.meta_data_cache[record_uid]
        yield {
            'record_uid': record_uid,
            'can_edit': rmd.get('can_edit') or False,
            'can_share': rmd.get('can_share') or False,
            'can_view': True
        }

    for sf_uid in params.shared_folder_cache:
        sf = params.shared_folder_cache[sf_uid]
        if 'records' in sf:
            sfrs = [x for x in sf['records'] if x['record_uid'] == record_uid]
            if len(sfrs) > 0:
                sfr = sfrs[0]
                can_edit = sfr['can_edit']
                can_share = sfr['can_share']
                if 'key_type' in sf:
                    yield {
                        'record_uid': record_uid,
                        'shared_folder_uid': sf_uid,
                        'can_edit': can_edit,
                        'can_share': can_share,
                        'can_view': True
                    }
                else:
                    if 'teams' in sf:
                        for sf_team in sf['teams']:
                            team_uid = sf_team['team_uid']
                            if team_uid in params.team_cache:
                                team = params.team_cache[team_uid]
                                yield {
                                    'record_uid': record_uid,
                                    'shared_folder_uid': sf_uid,
                                    'team_uid': team_uid,
                                    'can_edit': can_edit and not team['restrict_edit'],
                                    'can_share': can_share and not team['restrict_share'],
                                    'can_view': not team['restrict_view']
                                }


def get_record_shares(params, record_uids):

    def need_share_info(record_uid):
        if record_uid in params.record_cache:
            rec = params.record_cache[record_uid]
            return rec.get('shared') and 'shares' not in rec
        return False

    uids = [x for x in record_uids if need_share_info(x)]

    while len(uids) > 0:
        records = []
        rq = {
            'command': 'get_records',
            'include': ['shares'],
            'records': records,
            'client_time': current_milli_time()
        }
        while len(records) < 100 and len(uids) > 0:
            uid = uids.pop()
            params.record_cache[uid]['shares'] = {}
            ro = resolve_record_access_path(params, uid)
            records.append(ro)
        try:
            rs = communicate(params, rq)
            if 'records' in rs:
                for r in rs['records']:
                    record_uid = r['record_uid']
                    rec = params.record_cache[record_uid]
                    if 'user_permissions' in r:
                        rec['shares']['user_permissions'] = r['user_permissions']
                    if 'shared_folder_permissions' in r:
                        rec['shares']['shared_folder_permissions'] = r['shared_folder_permissions']

        except Exception as e:
            logging.error(e)


def query_msp(params):
    def fix_data(d):
        idx = d.rfind(b'}')
        if idx < len(d) - 1:
            d = d[:idx+1]
        return d

    request = {
        'command': 'get_enterprise_data',
        'include': ['managed_companies']
    }

    try:
        response = communicate(params, request)
        if response['result'] == 'success':
            if 'key_type_id' in response:
                tree_key = None
                if response['key_type_id'] == 1:
                    tree_key = decrypt_data(response['tree_key'], params.data_key)
                elif response['key_type_id'] == 2:
                    tree_key = decrypt_rsa(response['tree_key'], params.rsa_key)
                if not tree_key is None:
                    tree_key = tree_key[:32]
                    response['unencrypted_tree_key'] = tree_key
                    if 'managed_companies' in response:
                        for mc in response['managed_companies']:
                            mc['data'] = {}
                            if 'encrypted_data' in mc:
                                try:
                                    data = decrypt_data(mc['encrypted_data'], tree_key)
                                    data = fix_data(data)
                                    mc['data'] = json.loads(data.decode('utf-8'))
                                except Exception as e:
                                    pass
                        if params.enterprise:
                            params.enterprise['managed_companies'] = response['managed_companies']
    except:
        pass


def query_enterprise(params):
    def fix_data(d):
        idx = d.rfind(b'}')
        if idx < len(d) - 1:
            d = d[:idx+1]
        return d

    request = {
        'command': 'get_enterprise_data',
        'include': ['nodes', 'users', 'teams', 'team_users', 'roles', 'role_enforcements', 'role_privileges',
                    'role_users', 'managed_nodes', 'role_keys', 'licenses', 'queued_teams', 'queued_team_users',
                    'licenses', 'keys']
    }
    try:
        response = communicate(params, request)
        if response['result'] == 'success':
            if 'key_type_id' in response:
                tree_key = None
                if response['key_type_id'] == 1:
                    tree_key = decrypt_data(response['tree_key'], params.data_key)  # old AES
                elif response['key_type_id'] == 2:
                    if params.enterprise_id > 0:

                        decoded_data = base64.urlsafe_b64decode(response['tree_key'] + '==')

                        tree_key = rest_api.decrypt_aes(decoded_data, params.msp_tree_key)  # new AES
                        # tree_key = decrypt_data(response['tree_key'], msp_tree_key)
                    else:
                        tree_key = decrypt_rsa(response['tree_key'], params.rsa_key) # old RSA
                if not tree_key is None:
                    tree_key = tree_key[:32]
                    response['unencrypted_tree_key'] = tree_key
                    if 'nodes' in response:
                        for node in response['nodes']:
                            node['data'] = {}
                            if 'encrypted_data' in node:
                                try:
                                    data = decrypt_data(node['encrypted_data'], tree_key)
                                    data = fix_data(data)
                                    node['data'] = json.loads(data.decode('utf-8'))
                                except Exception as e:
                                    pass
                    if 'users' in response:
                        for user in response['users']:
                            user['data'] = {}
                            if 'encrypted_data' in user:
                                try:
                                    data = decrypt_data(user['encrypted_data'], tree_key)
                                    data = fix_data(data)
                                    user['data'] = json.loads(data.decode('utf-8'))
                                except Exception as e:
                                    pass
                    if 'roles' in response:
                        for role in response['roles']:
                            role['data'] = {}
                            if 'encrypted_data' in role:
                                try:
                                    data = decrypt_data(role['encrypted_data'], tree_key)
                                    data = fix_data(data)
                                    role['data'] = json.loads(data.decode('utf-8'))
                                except Exception as e:
                                    pass

                    params.enterprise = response
    except Exception as e:
        logging.debug(e)
        params.enterprise = None


def login_and_get_mc_params_login_v3(params: KeeperParams, mc_id):

    resp = loginv3.LoginV3API.loginToMc(params.rest_context, params.session_token, mc_id)

    mc_params = KeeperParams(server=params.server, device_id=params.rest_context.device_id)

    mc_params.config = params.config
    mc_params.auth_verifier = params.auth_verifier
    mc_params.mfa_token = params.mfa_token
    mc_params.salt = params.salt
    mc_params.iterations = params.iterations
    mc_params.user = params.user
    mc_params.password = params.password
    mc_params.enterprise_id = mc_id
    mc_params.session_token = params.session_token
    mc_params.login_v3 = params.login_v3
    mc_params.data_key = params.data_key

    mc_params.session_token = loginv3.CommonHelperMethods.bytes_to_url_safe_str(resp.encryptedSessionToken)
    mc_params.msp_tree_key = params.enterprise['unencrypted_tree_key']

    query_enterprise(mc_params)

    return mc_params


def login_and_get_mc_params(params, mc_id):

    mc_params = KeeperParams(server=params.server, device_id=params.rest_context.device_id)

    mc_params.config = params.config
    mc_params.auth_verifier = params.auth_verifier
    mc_params.mfa_token = params.mfa_token
    mc_params.salt = params.salt
    mc_params.iterations = params.iterations
    mc_params.user = params.user
    mc_params.password = params.password
    mc_params.enterprise_id = mc_id
    mc_params.msp_tree_key = params.enterprise['unencrypted_tree_key']
    mc_params.session_token = None

    login(mc_params)
    query_enterprise(mc_params)

    return mc_params


def get_correct_salt(salts):
    if len(salts) > 1:
        salt = next((s for s in salts if s.name.lower() == 'alternate'), salts[0])
    else:
        salt = salts[0]
    return salt
