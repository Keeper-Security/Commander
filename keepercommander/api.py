#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2016 Keeper Security Inc.
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
from keepercommander.error import AuthenticationError, CommunicationError, CryptoError
from Crypto import Random
from Crypto.Hash import SHA256, HMAC, SHA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5

# Client version match required for server calls
CLIENT_VERSION = 'c9.0.0'
current_milli_time = lambda: int(round(time.time() * 1000))

# PKCS7 padding helpers 
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
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
            if r.json()['result_code'] == 'Failed_to_find_user':
                raise AuthenticationError('User account [' + \
                    str(params.user) + '] not found.')

            if r.json()['result_code'] == 'auth_failed':
                raise AuthenticationError('Pre-auth failed.')

        # server doesn't include == at the end, but the module expects it
        params.salt = base64.urlsafe_b64decode(r.json()['salt']+'==')
        params.iterations = r.json()['iterations']
    
        prf = lambda p,s: HMAC.new(p,s,SHA256).digest()
        tmp_auth_verifier = base64.urlsafe_b64encode(
            PBKDF2(params.password, params.salt, 
                32, params.iterations, prf))

        # converts bytestream (b') to string 
        params.auth_verifier = tmp_auth_verifier.decode()

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
                # save token to config file
                params.config['mfa_type'] = 'device_token'
                params.config['mfa_token'] = params.mfa_token 
                try:
                    with open(params.config_filename, 'w') as f:
                        json.dump(params.config, f, ensure_ascii=False)
                        print('Updated mfa_token in ' + params.config_filename)
                except:
                    print('Unable to update mfa_token') 

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

def sync_down(params):
    """Sync full or partial data down to the client"""

    if not params.server:
        raise CommunicationError('No server provided')

    if not params.user:
        raise CommunicationError('No username provided')

    print('Downloading records...')

    def make_json(params):
        return {
               'include':[
                   'sfheaders',
                   'sfrecords',
                   'sfusers',
                   'sfteams'
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

        if 'revision' in response_json:
            params.revision = response_json['revision']
            if params.debug: print('Getting revision ' + str(params.revision))
    
        if 'removed_records' in response_json:
            if params.debug: print('Processing removed records')
            for uid in response_json['removed_records']:
                del params.record_cache[uid]
    
        if 'removed_shared_folders' in response_json:
            if params.debug: print('Processing removed shared folders')
            for shared_folder in response_json['removed_shared_folders']:
                if 'records' in shared_folder:
                    for record in shared_folder['records']: 
                        if 'record_uid' in record:
                            record_uid = record['record_uid']
                            if record_uid in params.record_cache:
                                if not params.record_cache[record_uid]['owner']:
                                    if num_folders_with_record(record_uid) == 1:
                                        del params.record_cache[record_uid]
            for uid in response_json['removed_shared_folders']:
                del params.shared_folder_cache[uid]

        # convert record keys from RSA to AES-256
        if 'record_meta_data' in response_json:
            if params.debug: print('Processing record_meta_data')
            for meta_data in response_json['record_meta_data']:

                if params.debug: print('meta data: ' + str(meta_data))

                if not 'record_key' in meta_data: 
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
                            type1key).decode()).rstrip('==')
                    meta_data['record_key_type'] = 1

                    # temporary flag for decryption routine below
                    meta_data['old_record_flag'] = True 

                if meta_data['record_key_type'] == 2:
                    if params.debug: print('Converting RSA-encrypted key')

                    # decrypt the type2 key using their RSA key
                    decoded_key = base64.urlsafe_b64decode(
                        meta_data['record_key'] +'==')
                    dsize = SHA.digest_size
                    sentinel = Random.new().read(15+dsize)
                    cipher = PKCS1_v1_5.new(params.rsa_key)
                    unencrypted_key = cipher.decrypt(decoded_key, sentinel)

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
                            type1key).decode()).rstrip('==')
                    meta_data['record_key_type'] = 1 

                    if params.debug: 
                        print('encrypted record key: ' + str(type1key)) 
                        print('base64: ' + str(meta_data['record_key'])) 

                # add to local cache
                if params.debug: print('Adding meta data to cache')
                params.meta_data_cache[meta_data['record_uid']] = meta_data
    

        # decrypt shared folder keys and folder name
        if 'shared_folders' in response_json:
            if params.debug: print('Processing shared_folders')
            for shared_folder in response_json['shared_folders']:
                decoded_key = base64.urlsafe_b64decode(
                    shared_folder['shared_folder_key'] +'==')

                if shared_folder['key_type'] == 1:
                    # decrypt folder key with data_key 
                    iv = decoded_key[:16]
                    ciphertext = decoded_key[16:]
                    cipher = AES.new(params.data_key, AES.MODE_CBC, iv)
                    unencrypted_key = unpad_binary(cipher.decrypt(ciphertext))

                if shared_folder['key_type'] == 2:
                    # decrypt folder key with RSA key
                    dsize = SHA.digest_size
                    sentinel = Random.new().read(15+dsize)
                    cipher = PKCS1_v1_5.new(params.rsa_key)
                    unencrypted_key = cipher.decrypt(decoded_key, sentinel)

                if params.debug: 
                    print('Type=' + str(shared_folder['key_type']) + \
                        ' Record Key: ' + str(unencrypted_key))

                if len(unencrypted_key) != 32:
                    raise CryptoError('Invalid folder key length')
                    
                # save the decrypted key
                shared_folder['shared_folder_key'] = unencrypted_key

                # decrypt the folder name
                decoded_folder_name = base64.urlsafe_b64decode(
                    shared_folder['name'] +'==')
                iv = decoded_folder_name[:16]
                ciphertext = decoded_folder_name[16:]
                cipher = AES.new(unencrypted_key, AES.MODE_CBC, iv)
                folder_name = unpad_binary(cipher.decrypt(ciphertext))

                if params.debug: print('Folder name: ' + str(folder_name))
                shared_folder['name'] = folder_name

                # add to local cache
                params.shared_folder_cache[shared_folder['shared_folder_uid']] \
                    = shared_folder


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
                    record_key = record['record_key']
                    decoded_key = base64.urlsafe_b64decode(record_key+'==')
                    iv = decoded_key[:16]
                    ciphertext = decoded_key[16:]
                    cipher = AES.new(params.data_key, AES.MODE_CBC, iv)
                    unencrypted_key = cipher.decrypt(ciphertext)[:32]
                    if params.debug: 
                        print('...unencrypted_key=' + str(unencrypted_key))
                else: 
                    # If record has no record_key, look in a shared folder
                    for shared_folder_uid in params.shared_folder_cache:
                        shared_folder = \
                            params.shared_folder_cache[shared_folder_uid]
                        sf_key = shared_folder['shared_folder_key']
                        if 'records' in shared_folder:
                            sf_records = shared_folder['records']
                            for sf_record in sf_records:
                                if 'record_uid' in sf_record:
                                    if sf_record['record_uid'] == record_uid:
                                        if 'record_key' in sf_record:
                                            sf_rec_key = sf_record['record_key']
                                            record['record_key'] = sf_rec_key

                                            decoded_key = \
                                                base64.urlsafe_b64decode(
                                                sf_rec_key +'==')
                                             
                                            iv = decoded_key[:16]
                                            ciphertext = decoded_key[16:]
                                            cipher = AES.new(sf_key, \
                                                AES.MODE_CBC, iv)
                                            unencrypted_key = \
                                                cipher.decrypt(ciphertext)[:32]

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
                    decoded_data = \
                        base64.urlsafe_b64decode(record['data'] +'==')
                    iv = decoded_data[:16]
                    ciphertext = decoded_data[16:]
                    cipher = AES.new(params.data_key, AES.MODE_CBC, iv)
                    record['data'] = unpad_binary(cipher.decrypt(ciphertext))
                    record['record_key_type'] = 1 

                elif 'data' in record:
                    # encrypted with record key
                    if params.debug: print('Got data')
                    decoded_data = \
                        base64.urlsafe_b64decode(record['data'] +'==')
                    iv = decoded_data[:16]
                    ciphertext = decoded_data[16:]
                    cipher = AES.new(record['record_key_unencrypted'], \
                        AES.MODE_CBC, iv)
                    record['data'] = unpad_binary(cipher.decrypt(ciphertext))
                else:
                    if params.debug: print('No data')
                    record['data'] = b'{}' 
    
                if 'extra' in record:
                    if params.debug: print('Got extra')
                    decoded_extra = \
                        base64.urlsafe_b64decode(record['extra'] +'==')
                    iv = decoded_extra[:16]
                    ciphertext = decoded_extra[16:]
                    cipher = AES.new(\
                        record['record_key_unencrypted'], AES.MODE_CBC, iv)
                    record['extra'] = unpad_binary(cipher.decrypt(ciphertext))
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

        if params.debug:
            print('--- Meta Data Cache: ' + str(params.meta_data_cache))
            print('--- Record Cache: ' + str(params.record_cache))
            print('--- Folders Cache: ' + str(params.shared_folder_cache))

        if len(params.record_cache) == 1:
            print('Downloaded & Decrypted [1] Record')
        else:
            print('Downloaded & Decrypted [' + \
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
    decoded_private_key = base64.urlsafe_b64decode(
        params.encrypted_private_key+'==')

    iv = decoded_private_key[:16]
    ciphertext = decoded_private_key[16:]
    cipher = AES.new(params.data_key, AES.MODE_CBC, iv)
    decrypted_private_key = cipher.decrypt(ciphertext)
    params.private_key = unpad_binary(decrypted_private_key)

    if params.debug: print('RSA key: ' + str(decrypted_private_key))
    if params.debug: print('base64 RSA key: ' + str(params.private_key))

    params.rsa_key = RSA.importKey(params.private_key)
   
    if params.debug: 
        print('RSA private key: ' + str(params.private_key))

def rotate_password(params, record_uid):
    """ Rotate the password for the specified record UID """

    record_uid = record_uid.strip()

    if not record_uid:
        print('No record UID provided')
        return False

    if not params.record_cache:
        print('No record cache.  Sync down first.')
        return False

    if not record_uid in params.record_cache:
        print('Record UID not found.')
        return False

    # get the record object
    cached_rec = params.record_cache[record_uid]

    # extract data and extra from record
    if 'data' in cached_rec:
        data = json.loads(cached_rec['data'].decode('utf-8')) 
    else: data = {}

    if 'extra' in cached_rec:
        extra = json.loads(cached_rec['extra'].decode('utf-8')) 
    else: extra = {}

    # check for edit permissions
    can_edit = False
    if 'can_edit' in cached_rec:
        if params.debug: print('Edit permissions found in record')
        can_edit = True

    # If record permission not there, check shared folders
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

    if not params.server:
        raise CommunicationError('No server provided')

    if not params.user:
        raise CommunicationError('No username provided')

    # save previous password
    if params.debug: print('Data: ' + str(data))
    if params.debug: print('Extra: ' + str(extra))

    # generate friendly datestamp
    modified_time = int(round(time.time()))
    modified_time_milli = modified_time * 1000 
    datestamp = datetime.datetime.fromtimestamp(
        modified_time).strftime('%Y-%m-%d %H:%M:%S')

    # Backup old password in a custom field
    custom_dict = {}
    custom_dict['name'] = 'cmdr:Rotation @ '+str(datestamp)
    custom_dict['value'] = data['secret2']
    custom_dict['type'] = 'text' 

    # serialize this dict
    serialized = json.dumps(custom_dict)

    # load as json
    custom_dict_json = json.loads(serialized)

    # Append to the current structure
    data['custom'].append(custom_dict_json)
    
    if params.debug: 
        print('Old password: ' + str(data['secret2']))

    # load the data into a record object for convenience
    record_object = Record()
    record_object.load(data)

    # generate a new password with any specified rules
    rules = record_object.get("cmdr:rules")
    if rules:
        new_password = generator.generateFromRules(rules)
    else:
        new_password = generator.generate()

    # execute rotation plugin associated with this record
    plugin_name = record_object.get("cmdr:plugin")
    if plugin_name:
        # Some plugins might need to change the password in the process of rotation
        # f.e. windows plugin gets rid of certain characters.
        plugin = plugin_manager.get_plugin(plugin_name)
        if plugin:
            if hasattr(plugin, "adjust"):
                new_password = plugin.adjust(new_password)

            print("Rotating with plugin " + str(plugin_name))
            success = plugin.rotate(record_object, new_password)
            if success:
                if params.debug:
                    print("Password rotation is successful for \"{0}\".".format(plugin_name))
            else:
                print("Password rotation failed for \"{0}\".".format(plugin_name))
                return False
        else:
            return False
    else:
        return False

    data['secret2'] = record_object.password

    if params.debug: 
        print('New password: ' + str(data['secret2']))

    if params.debug: 
        print('New record data: ' + str(data))

    # Update the record cache with the cleartext data
    if params.debug: print('data is ' + str(isinstance(data, dict)))
    if params.debug: print('params.record_cache is ' + \
        str(isinstance(params.record_cache, dict)))

    # convert dict back to json then encode it 
    params.record_cache[record_uid]['data'] = json.dumps(data).encode()

    if params.debug: 
        print('New record: ' + str(params.record_cache[record_uid]))
        print('Data: ' + str(data))
        print('Extra: ' + str(extra))

    # Convert the data and extra dictionary to string object
    # with double quotes instead of single quotes
    data_serialized = json.dumps(data)
    extra_serialized = json.dumps(extra)

    if params.debug: print('data_serialized: ' + str(data_serialized))
    if params.debug: print('extra_serialized: ' + str(extra_serialized))

    # encrypt data and extra
    if not 'record_key_unencrypted' in params.record_cache[record_uid]:
        if plugin_name: 
            print('Plugin updated password to: ' + new_password)
        raise CryptoError('No record_key_unencrypted found for ' + record_uid)

    if not 'record_key' in params.record_cache[record_uid]:
        if plugin_name: 
            print('Plugin updated password to: ' + new_password)
        raise CryptoError('No record_key found for ' + record_uid)

    record_key_unencrypted = \
        params.record_cache[record_uid]['record_key_unencrypted']
    iv = os.urandom(16)
    cipher = AES.new(record_key_unencrypted, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad(data_serialized))

    iv = os.urandom(16)
    cipher = AES.new(record_key_unencrypted, AES.MODE_CBC, iv)
    encrypted_extra = iv + cipher.encrypt(pad(extra_serialized))

    if params.debug: print('encrypted_data: ' + str(encrypted_data))
    if params.debug: print('encrypted_extra: ' + str(encrypted_extra))

    # note: decode() converts bytestream (b') to string
    encoded_data = base64.urlsafe_b64encode(encrypted_data).decode()
    encoded_extra = base64.urlsafe_b64encode(encrypted_extra).decode()

    if params.debug: print('encoded_data: ' + str(encoded_data))
    if params.debug: print('encoded_extra: ' + str(encoded_extra))

    # build a record object
    new_record = {}
    new_record['record_uid'] = record_uid
    new_record['version'] = 2 
    new_record['data'] = encoded_data
    new_record['extra'] = encoded_extra
    new_record['client_modified_time'] = modified_time_milli
    new_record['revision'] = params.record_cache[record_uid]['revision']
    if found_shared_folder_uid:
        new_record['shared_folder_uid'] = found_shared_folder_uid

    if 'udata' in params.record_cache[record_uid]:
        new_record['udata'] = params.record_cache[record_uid]['udata']
        
    if params.debug: print('new_record: ' + str(new_record))

    # create updated records
    update_records = []
    update_records.append(new_record)

    def make_json(params, update_records):
        return {
               'client_time':current_milli_time(),
               'device_id':'Commander', 
               'device_name':'Commander', 
               'command':'record_update', 
               'update_records':update_records,
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
            if plugin_name: 
                print('Plugin updated password to: ' + new_password)
            raise
            
    payload = make_json(params, update_records)

    if params.debug: print('payload: ' + str(payload))
    
    try:
        r = requests.post(params.server, json=payload)
    except:
        if plugin_name: 
            print('Plugin updated password to: ' + new_password)
        raise CommunicationError(sys.exc_info()[0])

    response_json = r.json()

    if params.debug:
        debug_response(params, payload, r)

    if response_json['result_code'] == 'auth_failed':
        if params.debug: print('Re-authorizing.')

        try:
            login(params)
        except:
            if plugin_name: 
                print('Plugin updated password to: ' + new_password)
            raise

        payload = make_json(params, update_records)

        try:
            r = requests.post(params.server, json=payload)
        except:
            print('Comm error during re-auth')
            if plugin_name: 
                print('Plugin updated password to: ' + new_password)
            raise CommunicationError(sys.exc_info()[0])
    
        response_json = r.json()
    
        if params.debug:
            debug_response(params, payload, r)

    if response_json['result'] == 'success':
        new_revision = 0
        if 'update_records' in response_json:
            for info in response_json['update_records']:
                if info['record_uid'] == record_uid:
                    if info['status'] == 'success':
                        # all records in the transaction get the 
                        # same revision.  this just checks 100% success
                        new_revision = response_json['revision']
             
        if new_revision == 0:
            print('Error: Revision not updated')
            if plugin_name: 
                print('Plugin updated password to: ' + new_password)
            return False

        if new_revision == new_record['revision']:
            print('Error: Revision did not change')
            if plugin_name: 
                print('Plugin updated password to: ' + new_password)
            return False

        print('Rotation successful for record_uid=' + \
            str(new_record['record_uid']) + ', revision=' + \
            str(new_record['revision']), ', new_revision=' + \
            str(new_revision))

        # update local cache
        params.record_cache[record_uid]['revision'] = new_revision

    else :
        if response_json['result_code']:
            if plugin_name: 
                print('Plugin updated password to: ' + new_password)
            raise CommunicationError('Unexpected problem: ' + \
                response_json['result_code'])

    return True

def get_record(params,record_uid):    
    """Return the referenced record"""
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

    if params.debug: print('Cached Rec: ' + str(cached_rec))
    data = json.loads(cached_rec['data'].decode('utf-8')) 

    rec = Record(record_uid)
    rec.load(data,cached_rec['revision'])

    return rec

def search_records(params, searchstring):
    """Search and display folders/titles/uids"""

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

def prepare_record(params, record, shared_folder_uid=''):
    ''' Prepares the record to be sent to the Keeper server
    :return: record encrypted and ready to be included into record_update json
    '''
    if not record.record_uid:
        record.record_uid = generate_record_uid()

    if params.debug: print('record UID: ' + record.record_uid)

    if record.record_uid in params.record_cache:
        raise Exception('Record UID already exists.')

    # generate friendly datestamp
    modified_time = int(round(time.time()))
    modified_time_milli = modified_time * 1000
    datestamp = datetime.datetime.fromtimestamp(
        modified_time).strftime('%Y-%m-%d %H:%M:%S')

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

    # generate a record key
    unencrypted_key = os.urandom(32)
    iv = os.urandom(16)
    cipher = AES.new(params.data_key, AES.MODE_CBC, iv)
    type1key = iv + cipher.encrypt(pad_binary(unencrypted_key))
    encoded_type1key = (base64.urlsafe_b64encode(
                           type1key).decode()).rstrip('==')

    if params.debug: print('generated key=' + str(type1key))
    if params.debug: print('encoded=' + str(encoded_type1key))

    # encrypt data with record key
    iv = os.urandom(16)
    cipher = AES.new(unencrypted_key, AES.MODE_CBC, iv)
    encrypted_data = iv + cipher.encrypt(pad(data_serialized))

    # encrypt extra with record key
    iv = os.urandom(16)
    cipher = AES.new(unencrypted_key, AES.MODE_CBC, iv)
    encrypted_extra = iv + cipher.encrypt(pad(extra_serialized))

    if params.debug: print('encrypted_data: ' + str(encrypted_data))
    if params.debug: print('encrypted_extra: ' + str(encrypted_extra))

    # note: decode() converts bytestream (b') to string
    encoded_data = base64.urlsafe_b64encode(encrypted_data).decode()
    encoded_extra = base64.urlsafe_b64encode(encrypted_extra).decode()

    if params.debug: print('encoded_data: ' + str(encoded_data))
    if params.debug: print('encoded_extra: ' + str(encoded_extra))

    # build a record object
    new_record = {}
    new_record['record_uid'] = record.record_uid
    new_record['version'] = 2
    new_record['data'] = encoded_data
    new_record['extra'] = encoded_extra
    new_record['udata'] = udata
    new_record['client_modified_time'] = modified_time_milli
    new_record['revision'] = 0
    new_record['record_key'] = encoded_type1key
    if shared_folder_uid:
        new_record['shared_folder_uid'] = shared_folder_uid

    if params.debug: print('new_record: ' + str(new_record))

    return new_record

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
        request['2fa_token'] = params.mfa_token,
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


def add_record(params):
    """ Create a new record with passed-in data or interactively.
        The shared folder UID is also optional 
    """
    record = Record()
    if not record.title:
        while not record.title:
            record.title = input("... Title (req'd): ")
        record.folder = input("... Folder: ")
        record.login = input("... Login: ")
        record.password = input("... Password: ")
        record.login_url = input("... Login URL: ")
        record.notes = input("... Notes: ")
        while True:
            custom_dict = {}
            custom_dict['name'] = input("... Custom Field Name : ") 
            if not custom_dict['name']:
                break

            custom_dict['value'] = input("... Custom Field Value : ") 
            custom_dict['type'] = 'text' 
            record.custom_fields.append(custom_dict)

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
                        # all records in the transaction get the
                        # same revision.  this just checks 100% success
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

        # sync down the data which updates the caches
        sync_down(params)

        return True

def debug_response(params, payload, response):
    print('')
    print('>>> Request server:[' + params.server + ']')
    print('>>> Request JSON:[' + str(payload) + ']')
    print('')
    print('<<< Response Code:[' + str(response.status_code) + ']')
    print('<<< Response Headers:[' + str(response.headers) + ']')
    if response.text:
        print('<<< Response content:[' + str(response.text) + ']')
    print('<<< Response content:[' + json.dumps(response.json(), 
        sort_keys=True, indent=4) + ']')
    if params.session_token:
        print('<<< Session Token:['+str(params.session_token)+']')

def generate_random_records(params, num):
    """ Create a randomized set of Keeper records 
    from loremipsum import get_sentences

    for i in [0:num]:
        sentences_list = get_sentences(5)

        r = Record()
        r.title = sentences_list[0]
        r.folder = sentences_list[1]
        r.login = sentences_list[2]
        r.password = sentences_list[3]
        r.login_url = sentences_list[4]
        r.notes = sentences_list[5]
        r.custom_fields[0] = sentences_list[6]

    return
    """

def generate_record_uid():
    """ Generate url safe base 64 16 byte uid """
    return base64.urlsafe_b64encode(
        os.urandom(16)).decode().rstrip('==') 
