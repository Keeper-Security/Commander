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

import sys
import json
import requests
import base64
import re
import getpass
import time
import os
import hashlib

from .subfolder import UserFolderNode, SharedFolderNode, SharedFolderFolderNode, RootFolderNode
from . import generator, plugin_manager
from .record import Record
from .shared_folder import SharedFolder
from .team import Team
from .error import AuthenticationError, CommunicationError, CryptoError, KeeperApiError
from .commands.base import user_choice
from .params import KeeperParams

from Cryptodome import Random
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_v1_5

# Client version match required for server calls
CLIENT_VERSION = 'c13.0.0'
current_milli_time = lambda: int(round(time.time() * 1000))

# PKCS7 padding helpers 
BS = 16
pad_binary = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
unpad_binary = lambda s: s[0:-s[-1]]
unpad_char = lambda s: s[0:-ord(s[-1])]


is_interactive_mode = False


def print_info(info, end_line=True):
    if is_interactive_mode:
        if end_line:
            print(info)
        else:
            print(info, end='', flush=True)


def print_error(error):
    print(error, file=sys.stderr)


def run_command(params, request):
    request['client_version'] = CLIENT_VERSION
    try:
        r = requests.post(params.server, json=request)
        return r.json()
    except:
        print('Communication error')
        raise CommunicationError(sys.exc_info()[0])


def derive_key(password, salt, iterations):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, 32)


def auth_verifier(password, salt, iterations):
    derived_key = derive_key(password, salt, iterations)
    derived_key = hashlib.sha256(derived_key).digest()
    au_ver = base64.urlsafe_b64encode(derived_key)
    return au_ver.decode().rstrip('=')


def auth_verifier_old(password, salt, iterations):
    derived_key = derive_key(password, salt, iterations)
    au_ver = base64.urlsafe_b64encode(derived_key)
    return au_ver.decode().rstrip('=')


def login(params, attempt=0):
    """Login to the server and get session token"""
    
    if not params.auth_verifier:
        if params.debug:
            print('No auth verifier, sending pre-auth request')

        payload = {
               'command':'login', 
               'include':['keys'],
               'version':2, 
               'client_version':CLIENT_VERSION,
               'username':params.user
              }

        try:
            r = requests.post(params.server, json=payload)
        except:
            print('Comm error during login')
            raise CommunicationError(sys.exc_info()[0])

        if params.debug:
            debug_response(params, payload, r)

        rs = r.json()
        if not 'salt' in rs:
            result_code = rs['result_code']

            if result_code == 'Failed_to_find_user':
                email = params.user
                params.user = ''
                params.password = ''
                raise AuthenticationError('User account [{0}] not found.'.format(email))

            if result_code == 'invalid_client_version':
                raise AuthenticationError(r.json()['message'])

            if result_code == 'auth_failed':
                raise AuthenticationError('Pre-auth failed.')

            if result_code == 'region_redirect':
                params.server = 'https://{0}/api/v2/'.format(rs['region_host'])
                if attempt < 5:
                    login(params, attempt + 1)
                    return

            raise AuthenticationError('Error code: {0}'.format(result_code))

        # server doesn't include == at the end, but the module expects it
        params.salt = base64.urlsafe_b64decode(r.json()['salt']+'==')
        params.iterations = r.json()['iterations']

        tmp_auth_verifier = derive_key(params.password, params.salt, params.iterations)
        tmp_auth_verifier = hashlib.sha256(tmp_auth_verifier).digest()
        tmp_auth_verifier = base64.urlsafe_b64encode(tmp_auth_verifier)

        # converts bytestream (b') to string 
        params.auth_verifier = tmp_auth_verifier.decode().rstrip('=')

        if params.debug:
            print('<<< Auth Verifier:['+str(params.auth_verifier)+']')


    success = False
    while not success:

        payload = {
            'command':'login',
            'include':['keys', 'license'],
            'version':2,
            'auth_response':params.auth_verifier,
            'client_version':CLIENT_VERSION,
            'username':params.user
        }
        if params.mfa_token:
            payload['2fa_token'] = params.mfa_token
            payload['2fa_type'] = params.mfa_type
            if (params.mfa_type == 'one_time'):
                try:
                    expire_token = params.config['device_token_expiration']
                except:
                    expire_token = False
                expire_days = 30 if expire_token else 9999
                payload['device_token_expire_days'] = expire_days

        try:
            r = requests.post(params.server, json=payload)
        except:
            raise CommunicationError(sys.exc_info()[0])

        response_json = r.json()

        if params.debug:
            debug_response(params, payload, r)

        if (
            response_json['result_code'] == 'auth_success' and 
            response_json['result'] == 'success'
            ):
            if params.debug: print('Auth Success')

            if 'session_token' in response_json:
                params.session_token = response_json['session_token']

            if 'device_token' in response_json:
                params.mfa_token = response_json['device_token']
                params.config['mfa_type'] = 'device_token'
                params.config['mfa_token'] = params.mfa_token 
                if params.debug: print('params.mfa_token=' + params.mfa_token)

                # save token to config file if the file exists
                try:
                    with open(params.config_filename, 'w') as f:
                        json.dump(params.config, f, ensure_ascii=False, indent=2)
                        print('Updated mfa_token in ' + params.config_filename)
                except:
                    if params.debug: print('Unable to update mfa_token') 

            if params.mfa_token:
                params.mfa_type = 'device_token'
            else:
                params.mfa_type = ''

            if 'keys' in response_json:
                if 'encrypted_private_key' in response_json['keys']:
                    params.encrypted_private_key = \
                        response_json['keys']['encrypted_private_key']
                else:
                    raise CommunicationError('Encrypted private ' + \
                      'key not found. You are probably using the wrong server.')

                if 'encryption_params' in response_json['keys']:
                    params.encryption_params = \
                        response_json['keys']['encryption_params']
                else:
                    print('Encryption parameters not found.')

                decrypt_data_key(params)
                decrypt_private_key(params)

            else:
                print('Hmm... keys not provided in login response.')

            if 'license' in response_json:
                params.license = response_json['license']

            params.sync_data = True
            query_enterprise(params)
            params.prepare_commands = True
            success = True

        elif ( response_json['result_code'] == 'need_totp' or
               response_json['result_code'] == 'invalid_device_token' or
               response_json['result_code'] == 'invalid_totp'):
            try:
                params.mfa_token = '' 
                params.mfa_type = 'one_time'

                while not params.mfa_token:
                    try:
                        params.mfa_token = getpass.getpass(prompt='Two-Factor Code: ', stream=None)
                    except (KeyboardInterrupt):
                        print('Cancelled')
                        raise

            except (EOFError, KeyboardInterrupt, SystemExit):
                return 
                
        elif response_json['result_code'] == 'auth_failed':
            params.password = ''
            raise AuthenticationError('Authentication failed.')

        elif response_json['result_code'] == 'throttled':
            raise AuthenticationError(response_json['message'])

        elif response_json['result_code']:
            raise AuthenticationError(response_json['result_code'])

        else:
            raise CommunicationError('Unknown problem')


def test_rsa(params):
    """Unit test to validate our RSA encryption/decryption"""
    if params.debug: print('RSA encryption test routine for ' + params.user)
    public_key = get_user_key(params, params.user)

    if params.debug: print('Public key: ' + str(public_key))
    if params.debug: print('RSA Private Key (Bytes): ' + str(params.private_key))
    if params.debug: print('RSA Private Key (Object): ' + str(params.rsa_key))

    record_key = os.urandom(32)
    if params.debug: print('Record key: ' + str(record_key))

    h = SHA256.new(record_key)
    public_rsa_key = RSA.importKey(base64.urlsafe_b64decode(public_key))
    cipher = PKCS1_v1_5.new(public_rsa_key)
    encrypted_record_key = cipher.encrypt(record_key)
    if params.debug: print('Encrypted record key: ' + str(encrypted_record_key))

    encoded_encrypted_record_key = base64.urlsafe_b64encode(encrypted_record_key).decode().rstrip('=')
    if params.debug: print('base64 encoded encrypted record key: ' + str(encoded_encrypted_record_key))

    decrypted_key = decrypt_rsa(encoded_encrypted_record_key, params.rsa_key)
    if params.debug: print('decrypted key: ' + str(decrypted_key))

    if record_key == decrypted_key:
        print('RSA encryption test successful')
    else:
        print('RSA encryption test failed')


def test_aes(params):
    """Unit test to validate our AES encryption/decryption"""
    if params.debug: print('AES-256 encryption test routine for ' + params.user)

    record_key = os.urandom(32)
    data_key = os.urandom(32)

    if params.debug: print('Record key: ' + str(record_key))
    if params.debug: print('Data key: ' + str(data_key))

    iv = os.urandom(16)
    cipher = AES.new(data_key, AES.MODE_CBC, iv)
    encrypted_record_key = iv + cipher.encrypt(pad_binary(record_key))
    if params.debug: print('Encrypted record key: ' + str(encrypted_record_key))

    encoded_encrypted_record_key = base64.urlsafe_b64encode(encrypted_record_key).decode().rstrip('=')
    if params.debug: print('base64 encoded encrypted record key: ' + str(encoded_encrypted_record_key))

    decoded_key = base64.urlsafe_b64decode(encoded_encrypted_record_key + '==')
    iv = decoded_key[:16]
    ciphertext = decoded_key[16:]
    cipher = AES.new(data_key, AES.MODE_CBC, iv)
    decrypted_key = cipher.decrypt(ciphertext)[:32]
    if params.debug: print('decrypted key: ' + str(decrypted_key))

    if record_key == decrypted_key:
        print('AES-256 encryption test successful')
    else:
        print('AES-256 encryption test failed')


def decrypt_record_key(encrypted_record_key, encryption_key):
    decoded_key = base64.urlsafe_b64decode(encrypted_record_key + '==')
    iv = decoded_key[:16]
    ciphertext = decoded_key[16:]
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    unencrypted_key = cipher.decrypt(ciphertext)[:32]
    return unencrypted_key


def shared_folders_containing_record(params, record_uid):
    def contains_record(shared_folder):
        if not 'records' in shared_folder:
            return False
        if not shared_folder['records']:
            return False
        return any(record['record_uid'] == record_uid for record in shared_folder['records'])

    shared_folder_uids = []
    for shared_folder_uid in params.shared_folder_cache:
        shared_folder = params.shared_folder_cache[shared_folder_uid]
        if contains_record(shared_folder):
           shared_folder_uids.append(shared_folder_uid)

    return shared_folder_uids


def delete_shared_folder(params, shared_folder_uid):
    shared_folder = params.shared_folder_cache[shared_folder_uid]
    if 'records' in shared_folder:
        for record in shared_folder['records']:
            record_uid = record['record_uid']
            if not params.record_cache[record_uid]['owner'] and len(shared_folders_containing_record(params, record_uid)) == 1:
                del params.record_cache[record_uid]
    del params.shared_folder_cache[shared_folder_uid]


def is_local_shared_folder(shared_folder):
    return shared_folder['manage_records'] and shared_folder['manage_users']


def decrypt_aes(data, key):
    decoded_data = base64.urlsafe_b64decode(data + '==')
    iv = decoded_data[:16]
    ciphertext = decoded_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


def encrypt_aes(data, key):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad_binary(data))
    return (base64.urlsafe_b64encode(encrypted_data).decode()).rstrip('=')


def encrypt_rsa(data, rsa_key):
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted_data = cipher.encrypt(data)
    return (base64.urlsafe_b64encode(encrypted_data).decode()).rstrip('=')


def decrypt_rsa(data, rsa_key):
    decoded_key = base64.urlsafe_b64decode(data + '==')
    # some keys might come shorter due to stripping leading 0's
    if 250 < len(decoded_key) < 256:
        decoded_key = bytearray(256 - len(decoded_key)) + decoded_key
    dsize = SHA256.digest_size
    sentinel = Random.new().read(15 + dsize)
    cipher = PKCS1_v1_5.new(rsa_key)
    return cipher.decrypt(decoded_key, sentinel)


def decrypt_data(data, key):
    return unpad_binary(decrypt_aes(data, key))


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
    decoded_private_key = base64.urlsafe_b64decode(encrypted_private_key + '==')
    iv = decoded_private_key[:16]
    ciphertext = decoded_private_key[16:]
    cipher = AES.new(data_key, AES.MODE_CBC, iv)
    decrypted_private_key = cipher.decrypt(ciphertext)
    private_key = unpad_binary(decrypted_private_key)
    rsa_key = RSA.importKey(private_key)
    return decrypted_private_key, private_key, rsa_key


def merge_lists_on_value(list1, list2, field_name):
    d = {x[field_name]: x for x in list1}
    d.update({x[field_name]: x for x in list2})
    return [x for x in d.values()]


def sync_down(params):
    """Sync full or partial data down to the client"""

    if not params.server:
        raise CommunicationError('No server provided')

    if not params.user:
        raise CommunicationError('No username provided')

    params.sync_data = False

    if params.revision == 0:
        print_info('Syncing...')

    def make_json(params):
        return {
               'include':[
                   'sfheaders',
                   'sfrecords',
                   'sfusers',
                   'teams',
                   'folders'
               ],
               'revision':params.revision,
               'client_time':current_milli_time(),
               'device_id':'Commander', 
               'device_name':'Commander', 
               'command':'sync_down', 
               'protocol_version':1, 
               'client_version':CLIENT_VERSION,
               'session_token':params.session_token,
               'username':params.user
        }
        
    if not params.session_token:
        try:
            login(params)
        except:
            raise
            
    payload = make_json(params)
    response_json = communicate(params, payload)

    if response_json['result_code'] == 'auth_failed':
        if params.debug: print('Re-authorizing.')

        try:
            login(params)
        except:
            raise

        payload = make_json(params)
        response_json = communicate(params, payload)

    check_convert_to_folders = False

    def delete_record_key(params, record_uid):
        if record_uid in params.record_cache:
            if 'record_key_unencrypted' in params.record_cache[record_uid]:
                del params.record_cache[record_uid]['record_key_unencrypted']

    def delete_shared_folder_key(params, shared_folder_uid):
        if shared_folder_uid in params.shared_folder_cache:
            shared_folder = params.shared_folder_cache[shared_folder_uid]
            if 'shared_folder_key_unencrypted' in shared_folder:
                del shared_folder['shared_folder_key_unencrypted']
                if 'records' in shared_folder:
                    for sfr in shared_folder['records']:
                        record_uid = sfr['record_uid']
                        if record_uid not in params.meta_data_cache:
                            delete_record_key(params, record_uid)

    def delete_team_key(params, team_uid):
        if team_uid in params.team_cache:
            team = params.team_cache[team_uid]
            if 'team_key_unencrypted' in team:
                del team['team_key_unencrypted']
                if 'shared_folder_keys' in team:
                    for sfk in team['shared_folder_keys']:
                        delete_shared_folder_key(params, sfk['shared_folder_uid'])


    if response_json['result'] == 'success':

        if 'full_sync' in response_json:
            if response_json['full_sync']:
                if params.debug: print('Full Sync response')
                check_convert_to_folders = True
                params.record_cache = {}  
                params.meta_data_cache = {}  
                params.shared_folder_cache = {}
                params.team_cache = {}
                params.non_shared_data_cache = {}
                params.subfolder_cache = {}
                params.subfolder_record_cache = {}

        if 'revision' in response_json:
            params.revision = response_json['revision']
            if params.debug: print('Getting revision ' + str(params.revision))

        if 'removed_records' in response_json:
            if params.debug: print_info('Processing removed records')
            for record_uid in response_json['removed_records']:
                # remove record metadata
                if record_uid in params.meta_data_cache:
                    del params.meta_data_cache[record_uid]
                # delete record key
                delete_record_key(params, record_uid)
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
            if params.debug: print_info('Processing removed teams')
            for team_uid in response_json['removed_teams']:
                delete_team_key(params, team_uid)
                # remove team from shared folder
                for shared_folder_uid in params.shared_folder_cache:
                    shared_folder = params.shared_folder_cache[shared_folder_uid]
                    if 'teams' in shared_folder:
                        shared_folder['teams'] = [x for x in shared_folder['teams'] if x['team_uid'] != team_uid]
                if team_uid in params.team_cache:
                    del params.team_cache[team_uid]

        if 'removed_shared_folders' in response_json:
            if params.debug: print_info('Processing removed shared folders')
            for sf_uid in response_json['removed_shared_folders']:
                if sf_uid in params.shared_folder_cache:
                    delete_shared_folder_key(params, sf_uid)
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
                try:
                    decrypted_data = decrypt_data(non_shared_data['data'], params.data_key)
                    params.non_shared_data_cache[non_shared_data['record_uid']] = json.loads(decrypted_data.decode('utf-8'))
                except:
                    if params.debug:
                        print('Non-shared data for record ' + non_shared_data['record_uid'] + ' could not be decrypted')

        # convert record keys from RSA to AES-256
        if 'record_meta_data' in response_json:
            if params.debug: print_info('Processing record_meta_data')
            for meta_data in response_json['record_meta_data']:

                if 'record_key' not in meta_data:
                    # old record that doesn't have a record key so make one
                    if params.debug: print_info('...no record key.  creating...')
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
                    if params.debug: print_info('Converting RSA-encrypted key')
                    # decrypt the type2 key using their RSA key
                    unencrypted_key = decrypt_rsa(meta_data['record_key'], params.rsa_key)
                    if len(unencrypted_key) == 32:
                        meta_data['record_key_unencrypted'] = unencrypted_key
                        meta_data['record_key'] = encrypt_aes(meta_data['record_key_unencrypted'], params.data_key)
                        meta_data['record_key_type'] = 1
                        meta_data['is_converted_record_type'] = True

                elif meta_data['record_key_type'] == 1:
                    meta_data['record_key_unencrypted'] = decrypt_data(meta_data['record_key'], params.data_key)

                # add to local cache
                if 'record_key_unencrypted' in meta_data:
                    if params.debug: print_info('Adding meta data to cache for ' + meta_data['record_uid'])
                    params.meta_data_cache[meta_data['record_uid']] = meta_data
                else:
                    print_error('Could not decrypt meta data key: ' + meta_data['record_uid'])

        if 'teams' in response_json:
            for team in response_json['teams']:
                if team['team_key_type'] == 2:
                    team['team_key_unencrypted'] = decrypt_rsa(team['team_key'], params.rsa_key)
                else:
                    team['team_key_unencrypted'] = decrypt_data(team['team_key'], params.data_key)
                _, _, team['team_private_key_unencrypted'] = decrypt_rsa_key(team['team_private_key'], team['team_key_unencrypted'])

                if 'removed_shared_folders' in team:
                    for sf_uid in team['removed_shared_folders']:
                        delete_shared_folder_key(params, sf_uid)
                params.team_cache[team['team_uid']] = team

        if 'shared_folders' in response_json:
            if params.debug: print_info('Processing shared_folders')
            for shared_folder in response_json['shared_folders']:
                shared_folder_uid = shared_folder['shared_folder_uid']

                if shared_folder_uid in params.shared_folder_cache and shared_folder.get('full_sync'):
                    if params.debug: print_info('Shared Folder full sync: ' + shared_folder_uid)
                    del params.shared_folder_cache[shared_folder_uid]

                if shared_folder_uid in params.shared_folder_cache:
                    delete_shared_folder_key(params, shared_folder_uid)

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
            if params.debug: print_info('Processing records')
            for record in response_json['records']:
                params.record_cache[record['record_uid']] = record

        # process team keys
        for team_uid in params.team_cache:
            team = params.team_cache[team_uid]
            for sf_key in team['shared_folder_keys']:
                if 'shared_folder_key_unencrypted' not in sf_key:
                    if sf_key['key_type'] == 2:
                        sf_key['shared_folder_key_unencrypted'] = decrypt_rsa(sf_key['shared_folder_key'], team['team_private_key_unencrypted'])
                    else:
                        sf_key['shared_folder_key_unencrypted'] = decrypt_data(sf_key['shared_folder_key'], team['team_key_unencrypted'])

        # process shared folder keys
        sf_to_delete = []
        for shared_folder_uid in params.shared_folder_cache:
            shared_folder = params.shared_folder_cache[shared_folder_uid]
            if 'shared_folder_key_unencrypted' not in shared_folder:
                if 'shared_folder_key' in shared_folder:
                    if shared_folder['key_type'] == 2:
                        shared_folder['shared_folder_key_unencrypted'] = decrypt_rsa(shared_folder['shared_folder_key'], params.rsa_key)
                    else:
                        shared_folder['shared_folder_key_unencrypted'] = decrypt_data(shared_folder['shared_folder_key'], params.data_key)
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
                    shared_folder['name_unencrypted'] = decrypt_data(shared_folder['name'], shared_folder['shared_folder_key_unencrypted']).decode('utf-8')
                    if 'records' in shared_folder:
                        for sfr in shared_folder['records']:
                            if 'record_key_unencrypted' not in sfr:
                                sfr['record_key_unencrypted'] = decrypt_data(sfr['record_key'], shared_folder['shared_folder_key_unencrypted'])
                else:
                    sf_to_delete.append(shared_folder_uid)

        if len(sf_to_delete) > 0:
            for shared_folder_uid in sf_to_delete:
                if params.debug: print_info('Delete shared folder with unresolved key: ' + shared_folder_uid)
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
                    record['data_unencrypted'] = decrypt_data(record['data'], record_key) if 'data' in record else b'{}'
                    record['extra_unencrypted'] = decrypt_data(record['extra'], record_key) if 'extra' in record else b'{}'
                else:
                    records_to_delete.append(record_uid)

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
            # Not doing anything with this yet
            for sharing_change in response_json['sharing_changes']:
                record_uid = sharing_change['record_uid']


        prepare_folder_tree(params)

        if params.debug:
            print('--- Meta Data Cache: ' + str(params.meta_data_cache))
            print('--- Record Cache: ' + str(params.record_cache))
            print('--- Folders Cache: ' + str(params.shared_folder_cache))

        if 'pending_shares_from' in response_json:
            accepted = False
            for user in response_json['pending_shares_from']:
                print('Note: You have pending share request(s) from ' + user)
                answer = user_choice('Do you want to accept these requests?', 'yn', 'n')
                rq = {
                    'command': 'accept_share' if answer == 'y' else 'cancel_share',
                    'from_email': user
                }
                try:
                    rs = communicate(params, rq)
                    if rs['result'] == 'success':
                        accepted = accepted or answer == 'y'
                except:
                    pass
            if accepted:
                sync_down(params)
                return

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
            if len(params.record_cache) == 1:
                print_info('Decrypted [1] Record')
            else:
                print_info('Decrypted [{0}] Records'.format(len(params.record_cache)))

    else :
        if response_json['result_code'] == 'auth_failed':
            raise CommunicationError('Authentication Failed: Check email, password or Two-Factor code.')
        else:            
            raise CommunicationError('Unknown comm problem')


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


def decrypt_data_key(params):
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
    if not params.encryption_params:
        raise CryptoError('Invalid encryption params: empty')

    decoded_encryption_params = base64.urlsafe_b64decode(
        params.encryption_params+'==')

    if len(decoded_encryption_params) != 100:
        raise CryptoError('Invalid encryption params: bad params length')

    version = int.from_bytes(decoded_encryption_params[0:1], 
                              byteorder='big', signed=False)
    iterations = int.from_bytes(decoded_encryption_params[1:4], 
                                 byteorder='big', signed=False)
    salt = decoded_encryption_params[4:20]
    encrypted_data_key = decoded_encryption_params[20:100]
    iv = encrypted_data_key[0:16]
    ciphertext = encrypted_data_key[16:80]

    if iterations < 1000:
        raise CryptoError('Invalid encryption parameters: iterations too low')

    # generate cipher key from master password and encryption params
    key = derive_key(params.password, salt, iterations)

    # decrypt the <encrypted data key>
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data_key = cipher.decrypt(ciphertext)

    # validate the key is formatted correctly
    if len(decrypted_data_key) != 64:
        raise CryptoError('Invalid data key length')

    if decrypted_data_key[:32] != decrypted_data_key[32:]:
        raise CryptoError('Invalid data key: failed mirror verification')

    if params.debug: print('Decrypted data key with success.')

    # save the encryption params 
    params.data_key = decrypted_data_key[:32]


def decrypt_private_key(params):
    decrypted_private_key, params.private_key, params.rsa_key = decrypt_rsa_key(params.encrypted_private_key, params.data_key)
    if params.debug: print('RSA key: ' + str(decrypted_private_key))
    if params.debug: print('base64 RSA key: ' + str(params.private_key))


def rotate_password(params, record_uid):
    """ Rotate the password for the specified record """
    record = get_record(params, record_uid)

    # generate a new password with any specified rules
    rules = record.get("cmdr:rules")
    if rules:
        if params.debug: print("Rules found for record")
        new_password = generator.generateFromRules(rules)
    else:
        if params.debug: print("No rules, just generate")
        new_password = generator.generate()

    # execute rotation plugin associated with this record
    plugin_name = record.get("cmdr:plugin")
    if plugin_name:
        # Some plugins might need to change the password in the process of rotation
        # f.e. windows plugin gets rid of certain characters.
        plugin = plugin_manager.get_plugin(plugin_name)
        if plugin:
            if hasattr(plugin, "adjust"):
                new_password = plugin.adjust(new_password)

            print("Rotating with plugin " + str(plugin_name))
            success = plugin.rotate(record, new_password)
            if success:
                if params.debug:
                    print("Password rotation is successful for \"{0}\".".format(plugin_name))
            else:
                print("Password rotation failed for \"{0}\".".format(plugin_name))
                return False
        else:
            return False
    else:
        print("Password rotated " + new_password)
        record.password = new_password

    if update_record(params, record):
        new_record = get_record(params, record_uid)
        print('Rotation successful for record_uid=' + \
            str(new_record.record_uid) + ', revision=' + \
            str(new_record.revision))

    return True

def check_edit_permission(params, record_uid):
    """Check record and shared folders for edit permission"""
    cached_rec = params.record_cache[record_uid]

    if 'data' in cached_rec:
        data = json.loads(cached_rec['data'].decode('utf-8'))
    else: data = {}

    if 'extra' in cached_rec:
        extra = json.loads(cached_rec['extra'].decode('utf-8'))
    else: extra = {}

    can_edit = False
    if 'can_edit' in cached_rec:
        if params.debug: print('Edit permissions found in record')
        can_edit = True

    if not can_edit:
        for shared_folder_uid in params.shared_folder_cache:
            shared_folder = params.shared_folder_cache[shared_folder_uid]
            if 'records' in shared_folder:
                sf_records = shared_folder['records']
                for sf_record in sf_records:
                    if 'record_uid' in sf_record:
                        if sf_record['record_uid'] == record_uid:
                            if 'can_edit' in sf_record:
                                can_edit = True
                                if params.debug:
                                    print('Edit permissions found in folder')
                                break

    if not can_edit:
        print('You do not have permissions to edit this record.')
        return False

def get_record(params,record_uid):    
    """Return the referenced record cache"""
    record_uid = record_uid.strip()

    if not record_uid:
        print('No record UID provided')
        return

    if not params.record_cache:
        print('No record cache.  Sync down first.')
        return

    if not record_uid in params.record_cache:
        print('Record UID not found.')
        return

    cached_rec = params.record_cache[record_uid]
    if params.debug: print('Cached rec: ' + str(cached_rec))

    rec = Record()

    try:
        data = json.loads(cached_rec['data_unencrypted'].decode('utf-8'))
        rec = Record(record_uid)
        extra = None
        if 'extra_unencrypted' in cached_rec:
            extra = json.loads(cached_rec['extra_unencrypted'].decode('utf-8'))
        rec.load(data, revision=cached_rec['revision'], extra=extra)
    except:
        print('**** Error decrypting record ' + str(record_uid))

    return rec

def is_shared_folder(params,shared_folder_uid):
    shared_folder_uid = shared_folder_uid.strip()

    if not shared_folder_uid:
        return False

    if not params.shared_folder_cache:
        return False

    if not shared_folder_uid in params.shared_folder_cache:
        return False

    return True


def is_team(params,team_uid):
    team_uid = team_uid.strip()

    if not team_uid:
        return False

    if not params.team_cache:
        return False

    if not team_uid in params.team_cache:
        return False

    return True 


def get_shared_folder(params,shared_folder_uid):
    """Return the referenced shared folder"""
    shared_folder_uid = shared_folder_uid.strip()

    if not shared_folder_uid:
        print('No shared folder UID provided')
        return None

    if not params.shared_folder_cache:
        print('No shared folder cache.  Sync down first.')
        return None

    if not shared_folder_uid in params.shared_folder_cache:
        print('Shared folder UID not found.')
        return None

    cached_sf = params.shared_folder_cache[shared_folder_uid]

    if params.debug: print('Cached Shared Folder: ' + str(cached_sf))

    sf = SharedFolder(shared_folder_uid)
    sf.load(cached_sf, cached_sf['revision'])

    return sf


def get_team(params,team_uid):
    """Return the referenced team """
    team_uid = team_uid.strip()

    if not team_uid:
        print('No team UID provided')
        return

    if not params.team_cache:
        print('No team cache.  Sync down first.')
        return

    if not team_uid in params.team_cache:
        print('Team UID not found.')
        return

    cached_team = params.team_cache[team_uid]

    if params.debug: print('Cached Team: ' + str(cached_team))

    team = Team(team_uid)
    team.load(cached_team)

    return team


def get_user_key(params, username):
    ''' Return the public RSA key for the given username '''

    if params.debug: print('Getting public key for user=' + username)

    request = make_request(params, 'public_keys')
    users = []
    users.append(username)
    request['key_owners'] = users
    response_json = communicate(params, request)
    if response_json['result'] != 'success':
        print('Error: unable to retreive public keys for ' + username)
        return False

    returned_key = b''
    for public_key in response_json['public_keys']:
        if 'public_key' in public_key:
            if public_key['key_owner'] == username:
                returned_key = public_key['public_key']

    if returned_key == b'':
        print('Error: unable to locate public key for ' + username)
    else:
        if params.debug: 
            print('Retrieved public key for user: ' + str(returned_key))

    returned_key = returned_key.rstrip('=')
    returned_key = returned_key + '='

    return returned_key


def get_encrypted_sf_key_from_team(params, team_uid, shared_folder_key):
    ''' Return an encrypted shared folder key based on a team UID ''' 

    if params.debug: print('Getting key object for Team UID=' + team_uid)
    
    request = make_request(params, 'team_get_keys')
    team_uids = [] 
    team_uids.append(team_uid)
    request['teams'] = team_uids
    response_json = communicate(params, request)
    if response_json['result'] != 'success':
        print('Error: unable to retreive key for Team UID=' + team_uid)
        return False

    encrypted_sf_key = b''
    for key in response_json['keys']:
        if 'result_code' in key:
            if key['result_code'] == 'doesnt_exist':
                if 'team_uid' in key:
                    print('Error: team UID ' + key['team_uid'] + 'does not exist')
                    break 

        if 'key' in key:
            if key['team_uid'] == team_uid:
                if params.debug: print('Found match for team key: ' + str(key['key']))

                if key['type'] == 1:
                    if params.debug: print('Team key encrypted with user data key')
                    team_key = decrypt_data(key['key'], params.data_key)

                    if params.debug: print('Encrypting SF key with Team Key')
                    iv = os.urandom(16)
                    cipher = AES.new(team_key, AES.MODE_CBC, iv)
                    encrypted_sf_key = iv + cipher.encrypt(pad_binary(shared_folder_key))

                elif key['type'] == 2:
                    if params.debug: print('Key encrypted with RSA pulic key')
                    team_key = decrypt_rsa(key['key'], params.rsa_key)

                    if params.debug: print('Encrypting SF key with Team Key')
                    iv = os.urandom(16)
                    cipher = AES.new(team_key, AES.MODE_CBC, iv)
                    encrypted_sf_key = iv + cipher.encrypt(pad_binary(shared_folder_key))

                elif key['type'] == 3:
                    if params.debug: print('Encrypting SF key with Public Key')
                    rsa_key = RSA.importKey(base64.urlsafe_b64decode(key['key']))
                    if params.debug: print('RSA Key: ' + str(rsa_key))
                    cipher = PKCS1_v1_5.new(rsa_key)
                    encrypted_sf_key = cipher.encrypt(shared_folder_key)

                else:
                    if params.debug: print('Invalid key type')

    if params.debug: print('Encrypted shared folder key: ' + str(encrypted_sf_key))
    return encrypted_sf_key 


def search_records(params, searchstring):
    """Search for string in record contents 
       and return array of Record objects """

    if not params.record_cache:
        print('No record cache.  Sync down first.')
        return

    if params.debug and searchstring: print('Searching for ' + searchstring)
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

    if not params.shared_folder_cache:
        print('No shared folder.  Sync down first.')
        return

    if params.debug and searchstring: print('Searching for ' + searchstring)
    p = re.compile(searchstring.lower())

    search_results = [] 

    for shared_folder_uid in params.shared_folder_cache:

        if params.debug: print('Getting Shared Folder UID: ' + shared_folder_uid)
        sf = get_shared_folder(params, shared_folder_uid)

        if params.debug: print('sf: ' + str(sf))
        target = sf.to_lowerstring()

        if params.debug: print('Lowercase: ' + str(target))

        if p.search(target):
            if params.debug: print('Search success')
            search_results.append(sf)
     
    return search_results


def search_teams(params, searchstring):
    """Search teams """

    if not params.team_cache:
        print('No teams.  Sync down first.')
        return

    if params.debug and searchstring: print('Searching for ' + searchstring)
    p = re.compile(searchstring.lower())

    search_results = [] 

    for team_uid in params.team_cache:

        if params.debug: print('Getting Team UID: ' + team_uid)
        team = get_team(params, team_uid)

        if params.debug: print('team: ' + str(team))
        target = team.to_lowerstring()

        if params.debug: print('Lowercase: ' + str(target))

        if p.search(target):
            if params.debug: print('Search success')
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
        if params.debug: print('Generated Record UID: ' + record.record_uid)
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
            print_error('You do not have edit permissions on this record')
            return None

        rec = params.record_cache[record.record_uid]
        data.update(json.loads(rec['data_unencrypted'].decode('utf-8')))
        if 'extra' in rec:
            extra.update(json.loads(rec['extra_unencrypted'].decode('utf-8')))
        if 'udata' in rec:
            udata.update(rec['udata'])
        unencrypted_key = rec['record_key_unencrypted']
        record_object['revision'] = rec['revision']
        if record.record_uid in params.meta_data_cache and params.meta_data_cache[record.record_uid].get('is_converted_record_type'):
            if params.debug: print('Converted record sends record key')
            record_object['record_key'] = encrypt_aes(unencrypted_key, params.data_key)
    else:
        if params.debug: print('Generated record key')
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

    return record_object


def make_request(params, command):
        return {
               'device_id':'Commander',
               'device_name':'Commander',
               'command':command,
               'protocol_version':1,
               'client_version':CLIENT_VERSION,
        }


def communicate(params, request):

    def authorize_request():
        request['client_time'] = current_milli_time()
        request['locale'] = 'en_US'
        request['client_version'] = CLIENT_VERSION
        request['device_id'] = 'Commander'
        request['session_token'] = params.session_token
        request['username'] = params.user

    if not params.session_token:
        try:
            login(params)
        except:
            raise

    authorize_request()
    if params.debug: print('payload: ' + str(request))

    try:
        r = requests.post(params.server, json=request)
    except:
        raise CommunicationError(sys.exc_info()[0])

    response_json = r.json()

    if params.debug:
        debug_response(params, request, r)

    if response_json['result_code'] == 'auth_failed':
        if params.debug: print('Re-authorizing.')

        try:
            login(params)
        except:
            raise

        authorize_request()

        try:
            r = requests.post(params.server, json=request)
        except:
            print('Comm error during re-auth')
            raise CommunicationError(sys.exc_info()[0])

        response_json = r.json()

        if params.debug:
            debug_response(params, request, r)

    if response_json['result'] != 'success':
        if response_json['result_code']:
            raise KeeperApiError(response_json['result_code'], response_json['message'])

    return response_json


def update_record(params, record, **kwargs):
    """ Push a record update to the cloud. 
        Takes a Record() object, converts to record JSON
        and pushes to the Keeper cloud API
    """
    update_record = prepare_record(params, record)
    if update_record is None:
        return

    request = make_request(params, 'record_update')
    request['update_records'] = [update_record]

    response_json = communicate(params, request)

    if response_json['result'] == 'success':
        new_revision = 0
        if 'update_records' in response_json:
            for info in response_json['update_records']:
                if info['record_uid'] == record.record_uid:
                    if info['status'] == 'success':
                        new_revision = response_json['revision']

        if new_revision == 0:
            print('Error: Revision not updated')
            return False

        if new_revision == update_record['revision']:
            print('Error: Revision did not change')
            return False

        if not kwargs.get('silent'):
            print('New record successful for record_uid={0}, revision={1}, new_revision={2}'
                  .format(update_record['record_uid'], update_record['revision'], new_revision))

        update_record['revision'] = new_revision

        # sync down the data which updates the caches
        sync_down(params)

        return True
    else:
        print('Record push failed')
        return False


def add_record(params, record):
    """    Create a new Keeper record 
    :type params: KeeperParams 
    :type record: Record
    :rtype: bool
    """

    new_record = prepare_record(params, record)
    request = make_request(params, 'record_update')
    request['add_records'] = [new_record]

    response_json = communicate(params, request)

    if response_json['result'] == 'success':
        new_revision = 0
        if 'add_records' in response_json:
            for info in response_json['add_records']:
                if info['record_uid'] == record.record_uid:
                    if info['status'] == 'success':
                        new_revision = response_json['revision']

        if new_revision == 0:
            print('Error: Revision not updated')
            return False

        if new_revision == new_record['revision']:
            print('Error: Revision did not change')
            return False

        print('New record successful for record_uid=' + \
            str(new_record['record_uid']) + ', revision=' + \
            str(new_record['revision']), ', new_revision=' + \
            str(new_revision))

        new_record['revision'] = new_revision

        # update record UID
        record.record_uid = new_record['record_uid']

        # sync down the data which updates the caches
        sync_down(params)
        return True

def delete_record(params, record_uid):
    """ Delete a record """  
    request = make_request(params, 'record_update')
    delete_records = []
    delete_records.append(record_uid)
    request['delete_records'] = delete_records
    response_json = communicate(params, request)
    if response_json['result'] != 'success':
        print('Error: Record not deleted')
        return False

    print('Record deleted with success')
    sync_down(params)
    return True


def debug_response(params, payload, response):
    print('')
    print('>>> Request server:[' + params.server + ']')
    print('>>> Request JSON:[' + json.dumps(payload) + ']')
    print('')
    print('<<< Response Code:[' + str(response.status_code) + ']')
    print('<<< Response Headers:[' + str(response.headers) + ']')
    if response.text:
        print('<<< Response content:[' + str(response.text) + ']')
    print('<<< Response content:[' + json.dumps(response.json(), 
        sort_keys=True, indent=4) + ']')
    if params.session_token:
        print('<<< Session Token:['+str(params.session_token)+']')


def generate_record_uid():
    """ Generate url safe base 64 16 byte uid """
    return base64.urlsafe_b64encode(
        os.urandom(16)).decode().rstrip('=')


def generate_aes_key():
    return os.urandom(32)


def prepare_folder_tree(params):
    '''
    :type params: KeeperParams
    '''
    params.folder_cache = {}
    params.root_folder = RootFolderNode()

    for sf in params.subfolder_cache.values():
        if sf['type'] == 'user_folder':
            uf = UserFolderNode()
            uf.uid = sf['folder_uid']
            uf.parent_uid = sf.get('parent_uid')
            data = json.loads(decrypt_data(sf['data'], sf['folder_key_unencrypted']).decode())
            uf.name = data['name'] if 'name' in data else uf.uid
            params.folder_cache[uf.uid] = uf

        elif sf['type'] == 'shared_folder_folder':
            sff = SharedFolderFolderNode()
            sff.uid = sf['folder_uid']
            sff.shared_folder_uid = sf['shared_folder_uid']
            sff.parent_uid = sf.get('parent_uid') or sff.shared_folder_uid
            data = json.loads(decrypt_data(sf['data'], sf['folder_key_unencrypted']).decode())
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


def get_record_permissions(params, record_uids):
    to_get = []
    for uid in record_uids:
        if uid in params.record_cache:
            r = params.record_cache[uid]
            shared = r.get('shared')
            if shared and 'permissions' not in r:
                ro = resolve_record_access_path(params, uid)
                to_get.append(ro)

    if len(to_get) > 0:
        rq = {
            'command': 'get_records',
            'records': to_get
        }


def resolve_record_write_path(params, record_uid):
    path = {
        'record_uid': record_uid
    }

    if record_uid in params.meta_data_cache:
        rmd = params.meta_data_cache[record_uid]
        if rmd['can_edit']:
            return path

    #shared through shared folder
    for sf in params.shared_folder_cache.values():
        if 'records' in sf:
            for ro in sf['records']:
                if ro['record_uid'] == record_uid:
                    if ro['can_edit']:
                        if 'key_type' in sf:
                            path['shared_folder_uid'] = sf['shared_folder_uid']
                            return path
                        elif 'teams' in sf: #check team
                            for to in sf['teams']:
                                if to['manage_records']:
                                    team = params.team_cache[to['team_uid']]
                                    if not team['restrict_edit']:
                                        path['shared_folder_uid'] = sf['shared_folder_uid']
                                        path['team_uid'] = team['team_uid']
                                        return
    return None


def resolve_record_share_path(params, record_uid):
    path = {
        'record_uid': record_uid
    }

    if record_uid in params.meta_data_cache:
        rmd = params.meta_data_cache[record_uid]
        if rmd['can_share']:
            return path

    #shared through shared folder
    for sf in params.shared_folder_cache.values():
        if 'records' in sf:
            for ro in sf['records']:
                if ro['record_uid'] == record_uid:
                    if ro['can_share']:
                        if 'key_type' in sf:
                            path['shared_folder_uid'] = sf['shared_folder_uid']
                            return path
                        elif 'teams' in sf: #check team
                            for to in sf['teams']:
                                if to['manage_records']:
                                    team = params.team_cache[to['team_uid']]
                                    if not team['restrict_share']:
                                        path['shared_folder_uid'] = sf['shared_folder_uid']
                                        path['team_uid'] = team['team_uid']
                                        return
    return None


def resolve_record_access_path(params, record_uid, path=None):
    if path is None:
        path = {}

    path['record_uid'] = record_uid
    if not record_uid in params.meta_data_cache: #shared through shared folder
        for sf_uid in params.shared_folder_cache:
            sf = params.shared_folder_cache[sf_uid]
            if 'records' in sf:
                if any(sfr['record_uid'] == record_uid for sfr in sf['records']):
                    if not 'key_type' in sf:
                        if 'teams' in sf:
                            for team in sf['teams']:
                                path['shared_folder_uid'] = sf_uid
                                path['team_uid'] = team['team_uid']
                    else:
                        path['shared_folder_uid'] = sf_uid
                        break
    return path


def get_record_shares(params, record_uids):

    def need_share_info(record_uid):
        if record_uid in params.record_cache:
            rec = params.record_cache[record_uid]
            return rec.get('shared') and 'shares' not in rec
        return False

    uids = [x for x in record_uids if need_share_info(x)]
    if len(uids) > 0:
        records = []
        rq = {
            'command': 'get_records',
            'include': ['shares'],
            'records': records,
            'client_time': current_milli_time()
        }
        for uid in uids:
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
            print(e)


def query_enterprise(params):
    def fix_data(data):
        idx = data.rfind(b'}')
        if idx < len(data) - 1:
            data = data[:idx+1]
        return data

    request = {
        'command': 'get_enterprise_data',
        'include': ['nodes', 'users', 'teams', 'team_users', 'roles', 'role_enforcements', 'role_privileges',
                    'role_users', 'managed_nodes', 'role_keys']
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
    except:
        params.enterprise = None
