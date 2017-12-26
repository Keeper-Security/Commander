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
from keepercommander import generator
import datetime
from keepercommander import plugin_manager, params
from keepercommander.record import Record
from keepercommander.shared_folder import SharedFolder
from keepercommander.team import Team
from keepercommander.error import AuthenticationError, CommunicationError, CryptoError
from Cryptodome import Random
from Cryptodome.Hash import SHA256, HMAC, SHA
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_v1_5

# Client version match required for server calls
CLIENT_VERSION = 'c10.1.0'
current_milli_time = lambda: int(round(time.time() * 1000))

# PKCS7 padding helpers 
BS = 16
pad_binary = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
unpad_binary = lambda s : s[0:-s[-1]]
unpad_char = lambda s : s[0:-ord(s[-1])]

def login(params):
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

        if not 'salt' in r.json():
            result_code = r.json()['result_code']

            if result_code == 'Failed_to_find_user':
                raise AuthenticationError('User account [' + \
                    str(params.user) + '] not found.')

            if result_code == 'invalid_client_version':
                raise AuthenticationError(r.json()['message'])

            if result_code == 'auth_failed':
                raise AuthenticationError('Pre-auth failed.')

        # server doesn't include == at the end, but the module expects it
        params.salt = base64.urlsafe_b64decode(r.json()['salt']+'==')
        params.iterations = r.json()['iterations']
    
        prf = lambda p,s: HMAC.new(p,s,SHA256).digest()
        tmp_auth_verifier = base64.urlsafe_b64encode(
            PBKDF2(params.password, params.salt, 
                32, params.iterations, prf))

        # converts bytestream (b') to string 
        params.auth_verifier = tmp_auth_verifier.decode().rstrip('=')

        if params.debug:
            print('<<< Auth Verifier:['+str(params.auth_verifier)+']')


    success = False
    while not success:

        if params.mfa_token:
            payload = {
                   'command':'login', 
                   'include':['keys'],
                   'version':2, 
                   'auth_response':params.auth_verifier,
                   'client_version':CLIENT_VERSION,
                   '2fa_token':params.mfa_token,
                   '2fa_type':params.mfa_type, 
                   'username':params.user
                  }
            if (params.mfa_type == 'one_time'):
                try:
                    expire_token = params.config['device_token_expiration']
                except:
                    expire_token = False
                expire_days = 30 if expire_token else 9999
                payload['device_token_expire_days'] = expire_days

        else:
            payload = {
                   'command':'login', 
                   'include':['keys'],
                   'version':2, 
                   'auth_response':params.auth_verifier,
                   'client_version':CLIENT_VERSION,
                   'username':params.user
                  }

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
                        json.dump(params.config, f, ensure_ascii=False)
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

            success = True

        elif ( response_json['result_code'] == 'need_totp' or
               response_json['result_code'] == 'invalid_device_token' or
               response_json['result_code'] == 'invalid_totp'):
            try:
                params.mfa_token = '' 
                params.mfa_type = 'one_time'

                while not params.mfa_token:
                    try:
                        params.mfa_token = getpass.getpass(
                            prompt='Two-Factor Code: ', stream=None)
                    except (KeyboardInterrupt):
                        print('Cancelled')
                        raise

            except (EOFError, KeyboardInterrupt, SystemExit):
                return 
                
        elif response_json['result_code'] == 'auth_failed':
            raise AuthenticationError('Authentication failed.')

        elif response_json['result_code'] == 'throttled':
            raise AuthenticationError(response_json['message'])

        elif response_json['result_code']:
            raise AuthenticationError(response_json['result_code'])

        else:
            raise CommunicationError('Unknown problem')


def decrypt_record_key(encrypted_record_key, shared_folder_key):
    decoded_key = base64.urlsafe_b64decode(encrypted_record_key + '==')
    iv = decoded_key[:16]
    ciphertext = decoded_key[16:]
    cipher = AES.new(shared_folder_key, AES.MODE_CBC, iv)
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


def decrypt_rsa(data, rsa_key):
    decoded_key = base64.urlsafe_b64decode(data + '==')
    # some keys might come shorter due to stripping leading 0's
    if 250 < len(decoded_key) < 256:
        decoded_key = bytearray(256 - len(decoded_key)) + decoded_key
    dsize = SHA.digest_size
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

    print('Syncing...')

    def make_json(params):
        return {
               'include':[
                   'sfheaders',
                   'sfrecords',
                   'sfusers',
                   'sfteams',
                   'teams'
               ],
               'revision':params.revision,
               'client_time':current_milli_time(),
               'device_id':'Commander', 
               'device_name':'Commander', 
               'command':'sync_down', 
               'protocol_version':1, 
               'client_version':CLIENT_VERSION,
               '2fa_token':params.mfa_token,
               '2fa_type':params.mfa_type, 
               'session_token':params.session_token, 
               'username':params.user
        }
        
    if not params.session_token:
        try:
            login(params)
        except:
            raise
            
    payload = make_json(params)
    
    try:
        r = requests.post(params.server, json=payload)
    except:
        raise CommunicationError(sys.exc_info()[0])

    response_json = r.json()

    if response_json['result_code'] == 'auth_failed':
        if params.debug: print('Re-authorizing.')

        try:
            login(params)
        except:
            raise

        payload = make_json(params)

        try:
            r = requests.post(params.server, json=payload)
        except:
            print('Comm error after re-authorizing')
            raise CommunicationError(sys.exc_info()[0])

        response_json = r.json()


    if params.debug:
        debug_response(params, payload, r)

    if response_json['result'] == 'success':

        if 'full_sync' in response_json:
            if response_json['full_sync']:
                if params.debug: print('Full Sync response')
                params.record_cache = {}  
                params.meta_data_cache = {}  
                params.shared_folder_cache = {}
                params.team_cache = {}
                params.non_shared_data_cache = {}

        if 'revision' in response_json:
            params.revision = response_json['revision']
            if params.debug: print('Getting revision ' + str(params.revision))

        if 'removed_records' in response_json:
            if params.debug: print('Processing removed records')
            for uid in response_json['removed_records']:
                del params.meta_data_cache[uid]
                is_in_sf = False
                record = params.record_cache[uid]
                for shared_folder_uid in params.shared_folder_cache:
                    shared_folder = params.shared_folder_cache[shared_folder_uid]
                    if 'records' not in shared_folder:
                        continue
                    for sf_record in shared_folder['records']:
                        if 'record_uid' not in sf_record:
                            continue
                        if sf_record['record_uid'] == uid and 'record_key' in sf_record and 'shared_folder_key' in shared_folder:
                            del record['can_edit']
                            del record['can_share']
                            del record['owner']
                            record['record_key'] = sf_record['record_key']
                            record['record_key_unencrypted'] = decrypt_record_key(sf_record['record_key'], shared_folder['shared_folder_key'])
                            record['record_key_type'] = 1
                            is_in_sf = True
                            break
                    if is_in_sf:
                        break
                if not is_in_sf:
                    del params.record_cache[uid]

        if 'removed_teams' in response_json:
            if params.debug: print('Processing removed teams')
            for team_uid in response_json['removed_teams']:
                team = params.team_cache[team_uid]
                if 'shared_folder_keys' not in team:
                    continue
                for sf_key in team['shared_folder_keys']:
                    sf_uid = sf_key['shared_folder_uid']
                    shared_folder = params.shared_folder_cache[sf_uid]
                    if not shared_folder or 'teams' not in shared_folder:
                        continue
                    # some teams are left in the folder, do not delete
                    if any([team['team_uid'] != team_uid for team in shared_folder['teams']]):
                        continue
                    delete_shared_folder(params, sf_uid)

                del params.team_cache[team_uid]

        if 'removed_shared_folders' in response_json:
            if params.debug: print('Processing removed shared folders')
            for uid in response_json['removed_shared_folders']:
                shared_folder = params.shared_folder_cache[uid]
                if 'teams' in shared_folder and len(shared_folder['teams']) > 0 and is_local_shared_folder(shared_folder):
                    del shared_folder['manage_records']
                    del shared_folder['manage_users']
                else:
                    delete_shared_folder(params, uid)

        # convert record keys from RSA to AES-256
        if 'record_meta_data' in response_json:
            if params.debug: print('Processing record_meta_data')
            for meta_data in response_json['record_meta_data']:

                if params.debug: print('meta data: ' + str(meta_data))

                if 'record_key' not in meta_data:
                    # old record that doesn't have a record key so make one
                    if params.debug: print('...no record key.  creating...')
                    unencrypted_key = os.urandom(32)
                    iv = os.urandom(16)
                    cipher = AES.new(params.data_key, AES.MODE_CBC, iv)
                    type1key = iv + cipher.encrypt(pad_binary(unencrypted_key))

                    if params.debug: print('generated key=' + str(type1key))

                    # store as b64 encoded string
                    # note: decode() converts bytestream (b') to string
                    # note2: remove == from the end 
                    meta_data['record_key'] = \
                        (base64.urlsafe_b64encode(
                            type1key).decode()).rstrip('=')
                    meta_data['record_key_type'] = 1

                    # temporary flag for decryption routine below
                    meta_data['old_record_flag'] = True 

                if meta_data['record_key_type'] == 2:
                    if params.debug: print('Converting RSA-encrypted key')
                    # decrypt the type2 key using their RSA key
                    unencrypted_key = decrypt_rsa(meta_data['record_key'], params.rsa_key)

                    if len(unencrypted_key) != 32:
                        raise CryptoError('Invalid record key length')

                    if params.debug: 
                        print('Before: ' + str(meta_data['record_key'])) 
                        print('After: ' + str(unencrypted_key)) 

                    # re-encrypt as type1 key with user's data key
                    iv = os.urandom(16)
                    cipher = AES.new(params.data_key, AES.MODE_CBC, iv)
                    type1key = iv + cipher.encrypt(pad_binary(unencrypted_key))

                    # store as b64 encoded string
                    # note: decode() converts bytestream (b') to string
                    # note2: remove == from the end 
                    meta_data['record_key'] = \
                        (base64.urlsafe_b64encode(
                            type1key).decode()).rstrip('=')
                    meta_data['record_key_type'] = 1 
                    meta_data['is_converted_record_type'] = True 

                    if params.debug: 
                        print('encrypted record key: ' + str(type1key)) 
                        print('base64: ' + str(meta_data['record_key'])) 

                # add to local cache
                if params.debug: print('Adding meta data to cache for ' + meta_data['record_uid'])
                params.meta_data_cache[meta_data['record_uid']] = meta_data

        if 'non_shared_data' in response_json:
            for non_shared_data in response_json['non_shared_data']:
                try:
                    decrypted_data = decrypt_data(non_shared_data['data'], params.data_key)
                    params.non_shared_data_cache[non_shared_data['record_uid']] = json.loads(decrypted_data.decode('utf-8'))
                except:
                    if params.debug:
                        print('Non-shared data for record ' + non_shared_data['record_uid'] + ' could not be decrypted')

        if 'teams' in response_json:
            for team in response_json['teams']:
                if team['team_key_type'] == 2:
                    team['team_key'] = decrypt_rsa(team['team_key'], params.rsa_key)
                else:
                    team['team_key'] = decrypt_data(team['team_key'], params.data_key)
                decrypted_private_key, private_key, team['team_private_key'] = decrypt_rsa_key(team['team_private_key'], team['team_key'])
                params.team_cache[team['team_uid']] = team

                for sf_key in team['shared_folder_keys']:
                    if sf_key['key_type'] == 2:
                        sf_key['shared_folder_key'] = decrypt_rsa(sf_key['shared_folder_key'], team['team_private_key'])
                    else:
                        sf_key['shared_folder_key'] = decrypt_data(sf_key['shared_folder_key'], team['team_key'])

                    if not sf_key['shared_folder_uid'] in params.shared_folder_cache:
                        params.shared_folder_cache[sf_key['shared_folder_uid']] = {
                            'shared_folder_key': sf_key['shared_folder_key']
                        }

                if 'removed_shared_folders' in team:
                    for sf_uid in team.removed_shared_folders:
                        shared_folder = params.shared_folder_cache[sf_uid]
                        if not shared_folder:
                            continue
                        if 'teams' not in shared_folder:
                            del params.shared_folder_cache[sf_uid]
                            continue
                        # First delete the team from the Shared Folder
                        shared_folder['teams'] = [sf_team for sf_team in shared_folder['teams'] if sf_team['team_uid'] != team['team_uid']]
                        if is_local_shared_folder(shared_folder):
                            continue
                        in_team = any([sf_team for sf_team in shared_folder['teams'] if sf_team['team_uid'] in params.team_cache])
                        if not in_team:
                            del params.shared_folder_cache[sf_uid]

        if 'shared_folders' in response_json:
            if params.debug: print('Processing shared_folders')
            if params.debug: print(str(response_json['shared_folders']))

            for shared_folder in response_json['shared_folders']:

                if 'shared_folder_key' in shared_folder:
                    shared_folder_key = shared_folder['shared_folder_key']
                    if shared_folder['key_type'] == 1:
                        if params.debug: print('decrypt folder key with data_key')
                        if params.debug: print(str(shared_folder_key))
                        if params.debug: print(str(params.data_key))
                        shared_folder['shared_folder_key'] = decrypt_data(shared_folder_key, params.data_key)
                    if shared_folder['key_type'] == 2:
                        if params.debug: print('decrypt folder key with RSA key')
                        shared_folder['shared_folder_key'] = decrypt_rsa(shared_folder_key, params.rsa_key)
                else:
                    sf = params.shared_folder_cache[shared_folder['shared_folder_uid']]
                    if sf and 'shared_folder_key' in sf:
                        shared_folder['shared_folder_key'] = sf['shared_folder_key']
                    else:
                        # Fail case.  No Shared Folder key anywhere.
                        continue

                if len(shared_folder['shared_folder_key']) != 32:
                    raise CryptoError('Invalid folder key length')
                    
                # decrypt the folder name
                shared_folder['name'] = decrypt_data(shared_folder['name'], shared_folder['shared_folder_key']).decode('utf-8')
                if params.debug: print('Folder name: ' + str(shared_folder['name']))

                process_changes = False
                if shared_folder['shared_folder_uid'] in params.shared_folder_cache:
                    if params.debug: print('Shared folder exists in local cache') 

                    if 'full_sync' in shared_folder:
                        if shared_folder['full_sync'] == False:
                            if params.debug: print('Process individual changes') 
                            process_changes = True
                    else:
                        if params.debug: print('No full sync specified, so process individual changes') 
                        process_changes = True

                if process_changes:
                    existing_sf = params.shared_folder_cache[shared_folder['shared_folder_uid']]

                    if 'records_removed' in shared_folder:
                        existing_sf['records'] = [record for record in existing_sf['records']
                                                if record['record_uid'] not in shared_folder['records_removed']]
                        for record_uid in shared_folder['records_removed']:
                            if record_uid not in params.meta_data_cache:
                                del params.record_cache[record_uid]
                        del shared_folder['records_removed']

                    if 'users_removed' in shared_folder:
                        existing_sf['users'] = [user for user in existing_sf['users']
                                                if user['username'] not in shared_folder['users_removed']]
                        del shared_folder['users_removed']

                    if 'teams_removed' in shared_folder:
                        existing_sf['teams'] = [team for team in existing_sf['teams']
                                                if team['team_uid'] not in shared_folder['teams_removed']]
                        del shared_folder['teams_removed']

                    if 'records' in shared_folder:
                        merged_records = merge_lists_on_value(existing_sf['records'], shared_folder['records'], 'record_uid')
                        if params.debug: print("merged_records = " + str(merged_records))
                        existing_sf['records'] = merged_records

                    if 'users' in shared_folder:
                        merged_users = merge_lists_on_value(existing_sf['users'], shared_folder['users'], 'username')
                        if params.debug: print("merged_users = " + str(merged_users))
                        existing_sf['users'] = merged_users

                    if 'teams' in shared_folder:
                        merged_teams = merge_lists_on_value(existing_sf['teams'], shared_folder['teams'], 'team_uid')
                        if params.debug: print("merged_teams = " + str(merged_teams))
                        existing_sf['teams'] = merged_teams

                    existing_sf['name'] = shared_folder['name']

                else: 
                    if params.debug: print('Shared folder does not exist in local cache') 
                    params.shared_folder_cache[shared_folder['shared_folder_uid']] = shared_folder

        # decrypt record keys
        if 'records' in response_json:
            if params.debug: print('Processing records')
            for record in response_json['records']:
                record_uid = record['record_uid']

                if params.debug: 
                    print('Looking for record key on ' + str(record_uid))

                if record_uid in params.meta_data_cache:
                    # merge meta data into record
                    record.update(params.meta_data_cache[record_uid])
                   
                unencrypted_key = ''
                if 'record_key' in record:
                    # decrypt record key with my data key
                    if params.debug: print('Record: ' + str(record))
                    unencrypted_key = decrypt_data(record['record_key'], params.data_key)[:32]
                    if params.debug:
                        print('...unencrypted_key=' + str(unencrypted_key))
                else: 
                    # If record has no record_key, look in a shared folder
                    for shared_folder_uid in params.shared_folder_cache:
                        shared_folder = params.shared_folder_cache[shared_folder_uid]
                        if 'records' not in shared_folder:
                            continue
                        sf_records = shared_folder['records']
                        for sf_record in sf_records:
                            if 'record_uid' in sf_record and sf_record['record_uid'] == record_uid and 'record_key' in sf_record:
                                sf_rec_key = sf_record['record_key']
                                record['record_key'] = sf_rec_key
                                unencrypted_key = decrypt_aes(sf_rec_key, shared_folder['shared_folder_key'])[:32]

                if unencrypted_key:
                    if len(unencrypted_key) != 32:
                        raise CryptoError('Invalid record key length')
                    # save the decrypted key in record_key_unencrypted
                    record['record_key_unencrypted'] = unencrypted_key
                else:
                    raise CryptoError('No record key found')

                if params.debug: 
                    print('Got record key: ' + str(unencrypted_key))

                ''' Decrypt the record data and extra... '''

                if ('old_record_flag' in record) and record['old_record_flag']:
                    # special case for super old records that are encrypted
                    # with the data key. no extra exists for these.
                    if params.debug: print('Old record type...')
                    record['data'] = decrypt_data(record['data'], params.data_key)
                    record['record_key_type'] = 1

                elif 'data' in record:
                    # encrypted with record key
                    if params.debug: print('Got data')
                    record['data'] = decrypt_data(record['data'], record['record_key_unencrypted'])
                else:
                    if params.debug: print('No data')
                    record['data'] = b'{}' 
    
                if 'extra' in record:
                    if params.debug: print('Got extra')
                    record['extra'] = decrypt_data(record['extra'], record['record_key_unencrypted'])
                else:
                    if params.debug: print('No extra')
                    record['extra'] = b'{}' 

                # Store the record in the cache
                if params.debug: 
                    print('record is dict: ' + str(isinstance(record, dict)))
                    print('params.record_cache is dict: ' + \
                        str(isinstance(params.record_cache, dict)))
                    print('record is ' + str(record))

                params.record_cache[record_uid] = record 


        if 'pending_shares_from' in response_json:
            print('Note: You have pending share requests.')

        if 'sharing_changes' in response_json:
            for sharing_change in response_json['sharing_changes']:
                record_uid = sharing_change['record_uid']
                if record_uid in params.record_cache:
                    params.record_cache[record_uid].shared = sharing_change['shared']

        if params.debug:
            print('--- Meta Data Cache: ' + str(params.meta_data_cache))
            print('--- Record Cache: ' + str(params.record_cache))
            print('--- Folders Cache: ' + str(params.shared_folder_cache))

        if len(params.record_cache) == 1:
            print('Decrypted [1] Record')
        else:
            print('Decrypted [' + \
                str(len(params.record_cache)) + '] Records')

    else :
        if response_json['result_code'] == 'auth_failed':
            raise CommunicationError('Authentication Failed. ' + \
                'Check email, password or Two-Factor code.')
        else:            
            raise CommunicationError('Unknown comm problem')

def num_folders_with_record(record_uid):
    counter = 0

    for shared_folder in params.shared_folder_cache:
        if 'records' in shared_folder:
            for record in shared_folder['records']:
                if 'record_uid' in record:
                    if record['record_uid'] == record_uid:
                        counter += 1

    return counter

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
    prf = lambda p,s: HMAC.new(p,s,SHA256).digest()
    key = PBKDF2(params.password, salt, 32, iterations, prf)

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

def append_notes(params, record_uid):
    """ Append some notes to an existing record """
    record = get_record(params, record_uid)

    notes = input("... Notes to append: ")
    record.notes += notes
    return update_record(params, record)

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

    found_shared_folder_uid = ''
    if can_edit == False:
        for shared_folder_uid in params.shared_folder_cache:
            shared_folder = params.shared_folder_cache[shared_folder_uid]
            sf_key = shared_folder['shared_folder_key']
            if 'records' in shared_folder:
                sf_records = shared_folder['records']
                for sf_record in sf_records:
                    if 'record_uid' in sf_record:
                        if sf_record['record_uid'] == record_uid:
                            found_shared_folder_uid = shared_folder_uid
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
        data = json.loads(cached_rec['data'].decode('utf-8')) 
        rec = Record(record_uid)
        rec.load(data,cached_rec['revision'])
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
        return

    if not params.shared_folder_cache:
        print('No shared folder cache.  Sync down first.')
        return

    if not shared_folder_uid in params.shared_folder_cache:
        print('Shared folder UID not found.')
        return

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
                    h = SHA.new(shared_folder_key)
                    rsa_key = RSA.importKey(base64.urlsafe_b64decode(key['key']))
                    if params.debug: print('RSA Key: ' + str(rsa_key))
                    cipher = PKCS1_v1_5.new(rsa_key)
                    encrypted_sf_key = cipher.encrypt(shared_folder_key+h.digest())

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

    if searchstring != '': print('Searching for ' + searchstring)
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

    if searchstring != '': print('Searching for ' + searchstring)
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

    if searchstring != '': print('Searching for ' + searchstring)
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

def prepare_record(params, record, shared_folder_uid=''):
    """ Prepares the Record() object to be sent to the Keeper Cloud API
        by serializing and encrypting it in the proper JSON format used for
        transmission.  If the record has no UID, one is generated and the
        encrypted record key is sent to the server.  If this record was
        converted from RSA to AES we send the new record key. If the record
        is in a shared folder, must send shared folder UID for edit permission.
    """
    needs_record_key = False
    if not record.record_uid:
        record.record_uid = generate_record_uid()
        if params.debug: print('Generated Record UID: ' + record.record_uid)
        needs_record_key = True

    if params.debug: print('Needs record key = ' + str(needs_record_key))

    # initialize data and extra
    data = {}
    extra = {}
    udata = []

    data['title'] = record.title
    data['folder'] = record.folder
    data['secret1'] = record.login
    data['secret2'] = record.password
    data['link'] = record.login_url
    data['notes'] = record.notes
    data['custom'] = record.custom_fields

    # Convert the data and extra dictionary to string object
    # with double quotes instead of single quotes
    data_serialized = json.dumps(data)
    extra_serialized = json.dumps(extra)

    if params.debug: print('Dictionary: ' + str(data))
    if params.debug: print('Serialized: : ' + str(data_serialized))

    if needs_record_key:
        unencrypted_key = os.urandom(32)
        if params.debug: print('Generated a key=' + str(unencrypted_key))
    else:
        unencrypted_key = \
                params.record_cache[record.record_uid]['record_key_unencrypted']

    # Create encrypted record key
    iv = os.urandom(16)
    cipher = AES.new(params.data_key, AES.MODE_CBC, iv)
    type1key = iv + cipher.encrypt(pad_binary(unencrypted_key))
    encoded_type1key = (base64.urlsafe_b64encode(
                               type1key).decode()).rstrip('=')
    if params.debug: print('Encoded=' + str(encoded_type1key))

    # Encrypt data with record key
    iv = os.urandom(16)
    cipher = AES.new(unencrypted_key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad_binary(data_serialized.encode()))

    # Encrypt extra with record key
    iv = os.urandom(16)
    cipher = AES.new(unencrypted_key, AES.MODE_CBC, iv)
    encrypted_extra = iv + cipher.encrypt(pad_binary(extra_serialized.encode()))

    if params.debug: print('encrypted_data: ' + str(encrypted_data))
    if params.debug: print('encrypted_extra: ' + str(encrypted_extra))

    # note: decode() converts bytestream (b') to string
    encoded_data = base64.urlsafe_b64encode(encrypted_data).decode().rstrip('=')
    encoded_extra = base64.urlsafe_b64encode(encrypted_extra).decode().rstrip('=')

    if params.debug: print('encoded_data: ' + str(encoded_data))
    if params.debug: print('encoded_extra: ' + str(encoded_extra))

    modified_time = int(round(time.time()))
    modified_time_milli = modified_time * 1000 

    # build a record dict for upload
    new_record = {}
    new_record['record_uid'] = record.record_uid
    new_record['version'] = 2
    new_record['data'] = encoded_data
    new_record['extra'] = encoded_extra
    new_record['udata'] = udata
    new_record['client_modified_time'] = modified_time_milli
    new_record['revision'] = 0

    shared_folder_uids = shared_folders_containing_record(params, record.record_uid)
    if( len(shared_folder_uids) > 0 ):
        new_record['shared_folder_uid'] = shared_folder_uids[0] 

    if record.record_uid in params.record_cache:
        if 'revision' in params.record_cache[record.record_uid]:
            new_record['revision'] = params.record_cache[record.record_uid]['revision']
        if 'is_converted_record_type' in params.record_cache[record.record_uid]:
            if params.debug: print('Converted record sends record key')
            new_record['record_key'] = encoded_type1key

    if needs_record_key:
        new_record['record_key'] = encoded_type1key

    if shared_folder_uid:
        new_record['shared_folder_uid'] = shared_folder_uid

    if params.debug: print('new_record: ' + str(new_record))
    return new_record


def prepare_shared_folder(params, shared_folder):
    """ Prepares the SharedFolder() object to be sent to the Keeper Cloud API
        by serializing and encrypting it in the proper JSON format used for
        transmission.  If the record has no UID, one is generated and the
        encrypted record key is sent to the server.  If this record was
        converted from RSA to AES we send the new record key. If the record
        is in a shared folder, must send shared folder UID for edit permission.
    """
    if params.debug: print('prepare_shared_folder')

    needs_sf_key = False
    if not shared_folder.shared_folder_uid:
        shared_folder.shared_folder_uid = generate_record_uid()
        if params.debug: print('Generated Shared Folder UID: ' + shared_folder.shared_folder_uid)
        needs_sf_key = True

    # build a shared folder dict for upload
    new_sf = {}
    new_sf['name'] = shared_folder.name 
    new_sf['shared_folder_uid'] = shared_folder.shared_folder_uid 
    new_sf['operation'] = 'add' 
    new_sf['revision'] = 0 
    new_sf['default_can_edit'] = shared_folder.default_can_edit 
    new_sf['default_can_share'] = shared_folder.default_can_share 
    new_sf['default_manage_records'] = shared_folder.default_manage_records 
    new_sf['default_manage_users'] = shared_folder.default_manage_users 
    new_sf['add_records'] = shared_folder.records 
    new_sf['add_teams'] = shared_folder.teams 
    new_sf['add_users'] = shared_folder.users 

    if needs_sf_key:
        shared_folder_key = os.urandom(32)
        if params.debug: print('Generated new SF key=' + str(shared_folder_key))
    else:
        shared_folder_key = \
                params.shared_folder_cache[shared_folder.shared_folder_uid]['shared_folder_key']

    for t in new_sf['add_teams']:
        # encrypt shared folder key with team public key  
        if params.debug: print('Getting encrypted SF key for Team UID=' + str(t['team_uid']))
        encrypted_sf_key = get_encrypted_sf_key_from_team(params, t['team_uid'], shared_folder_key)
        t['shared_folder_key'] = base64.urlsafe_b64encode(encrypted_sf_key).decode().rstrip('=')
        if params.debug: print('Encrypted shared folder key=' + str(t['shared_folder_key']))

    for u in new_sf['add_users']:
        if u['username'] == params.user:
            # this is me, so encrypt shared folder key with data key
            if params.debug: print('Encrypt SF key with data key')
            iv = os.urandom(16)
            cipher = AES.new(params.data_key, AES.MODE_CBC, iv)
            encrypted_sf_key = iv + cipher.encrypt(pad_binary(shared_folder_key))
        else:
            # encrypt shared folder key with user's public key
            if params.debug: print('Encrypt SF key with public key')
            public_key = get_user_key(params, u['username'])
            h = SHA.new(shared_folder_key)
            rsa_key = RSA.importKey(base64.urlsafe_b64decode(public_key))
            cipher = PKCS1_v1_5.new(rsa_key)
            encrypted_sf_key = cipher.encrypt(shared_folder_key+h.digest())
        u['shared_folder_key'] = base64.urlsafe_b64encode(encrypted_sf_key).decode().rstrip('=') 
        if params.debug: print('Encrypted shared folder key from user=' + str(u['shared_folder_key']))

    for r in new_sf['add_records']:
        if params.debug: print('encrypt record key with the shared folder key')
        iv = os.urandom(16)
        cipher = AES.new(shared_folder_key, AES.MODE_CBC, iv)
        record_uid = r['record_uid']

        if record_uid in params.record_cache:
            if params.debug: print('Found record in cache: ' + str(params.record_cache[record_uid]))
            record_key = params.record_cache[record_uid]['record_key_unencrypted'] 
            type1key = iv + cipher.encrypt(pad_binary(record_key))
            encoded_type1key = (base64.urlsafe_b64encode(
                                   type1key).decode()).rstrip('=')
            r['record_key'] = encoded_type1key
            if params.debug: print('Encrypted record key=' + str(r['record_key']))
        else:
            print('Error: No record found in cache with UID='+record_uid)

    if params.debug: print('Encrypt folder name with shared folder key')
    if params.debug: print('Encrypting SF name=' + str(shared_folder.name))
    if params.debug: print('Encoded: ' + str(shared_folder.name.encode()))

    iv = os.urandom(16)
    cipher = AES.new(shared_folder_key, AES.MODE_CBC, iv)
    encrypted_name = iv + cipher.encrypt(pad_binary(shared_folder.name.encode()))

    if params.debug: print('encrypted shared folder name: ' + str(encrypted_name))
    new_sf['name'] = base64.urlsafe_b64encode(encrypted_name).decode().rstrip('=') 

    return new_sf


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
        request['2fa_token'] = params.mfa_token
        request['2fa_type'] = params.mfa_type
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
            raise CommunicationError('Unexpected problem: ' + \
                response_json['result_code'])

    return response_json

def update_record(params, record):
    """ Push a record update to the cloud. 
        Takes a Record() object, converts to record JSON
        and pushes to the Keeper cloud API
    """
    print("Pushing update...")
    update_record = prepare_record(params, record)
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

        print('New record successful for record_uid=' + \
            str(update_record['record_uid']) + ', revision=' + \
            str(update_record['revision']), ', new_revision=' + \
            str(new_revision))

        update_record['revision'] = new_revision

        # sync down the data which updates the caches
        sync_down(params)

        return True
    else:
        print('Record push failed')
        return False

def add_record(params, record):
    """ Create a new Keeper record """

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
