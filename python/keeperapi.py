import sys
import json
import requests
import base64
import getpass
import time
import os
from keepererror import AuthenticationError
from keepererror import CommunicationError
from keepererror import CryptoError
from Crypto import Random
from Crypto.Hash import SHA256, HMAC, SHA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_v1_5

CLIENT_VERSION = 'c9.0.0'
current_milli_time = lambda: int(round(time.time() * 1000))

# PKCS7 padding helpers for our private key
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad_binary = lambda s : s[0:-s[-1]]
unpad_char = lambda s : s[0:-ord(s[-1])]

def login(params):
    """Login to the server and get session token"""
    
    if not params.salt:
        payload = {'command':'account_summary',
                   'include':['license','settings','group','keys'],
                   'client_version':CLIENT_VERSION,
                   'username':params.email}

        try:
            r = requests.post(params.server, json=payload)
        except:
            raise CommunicationError(sys.exc_info()[0])

        if params.debug:
            print('')
            print('>>> Request server:[' + params.server + ']')
            print('>>> Request JSON:[' + str(payload) + ']')
            print('')
            print('<<< Response Code:[' + str(r.status_code) + ']')
            print('<<< Response Headers:[' + str(r.headers) + ']')
            print('<<< Response content:[' + str(r.text) + ']')

        if not 'salt' in r.json():
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
                   'username':params.email
                  }

        else:
            payload = {
                   'command':'login', 
                   'version':2, 
                   'auth_response':params.auth_verifier,
                   'client_version':CLIENT_VERSION,
                   'username':params.email
                  }

        try:
            r = requests.post(params.server, json=payload)
        except:
            raise CommunicationError(sys.exc_info()[0])

        response_json = r.json()

        if params.debug:
            print('')
            print('>>> Request server:[' + params.server + ']')
            print('>>> Request JSON:[' + str(payload) + ']')
            print('')
            print('<<< Response Code:[' + str(r.status_code) + ']')
            print('<<< Response Headers:[' + str(r.headers) + ']')
            print('<<< Response content:[' + json.dumps(response_json, 
                sort_keys=True, indent=4) + ']')
            print('<<< Session Token:['+str(params.session_token)+']')

        if (
            response_json['result_code'] == 'auth_success' and 
            response_json['result'] == 'success'
            ):
            if params.debug: print('Auth Success')

            if 'session_token' in response_json:
                params.session_token = response_json['session_token']

            if 'device_token' in response_json:
                params.mfa_token = response_json['device_token']
                print('----> Device token: ' + str(params.mfa_token))

            if params.mfa_token:
                params.mfa_type = 'device_token'

            if 'keys' in response_json:
                params.encrypted_private_key = \
                    response_json['keys']['encrypted_private_key']
                params.encryption_params = \
                    response_json['keys']['encryption_params']

                decrypt_data_key(params)
                decrypt_private_key(params)

            success = True

        elif ( response_json['result_code'] == 'need_totp' or
               response_json['result_code'] == 'invalid_device_token' or
               response_json['result_code'] == 'invalid_totp'):
            try:
                params.mfa_token = '' 
                params.mfa_type = 'one_time'

                while not params.mfa_token:
                    params.mfa_token = getpass.getpass(
                        prompt='2FA Code: ', stream=None)

            except (KeyboardInterrupt, SystemExit):
                return 
                
        elif response_json['result_code'] == 'auth_failed':
            raise AuthenticationError(response_json['result_code'])

        elif response_json['result_code'] == 'throttled':
            raise AuthenticationError(response_json['message'])

        elif response_json['result_code']:
            raise AuthenticationError(response_json['result_code'])

        else:
            raise CommunicationError('Unknown problem')

def sync_down(params):
    """Sync full or partial data down to the client"""

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
               'username':params.email
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
        raise CommunicationError(sys.exc_info()[0])

    response_json = r.json()

    if params.debug:
        print('')
        print('>>> Request server:[' + params.server + ']')
        print('>>> Request JSON:[' + str(payload) + ']')
        print('')
        print('<<< Response Code:[' + str(r.status_code) + ']')
        print('<<< Response Headers:[' + str(r.headers) + ']')
        print('<<< Response content:[' + json.dumps(response_json, 
            sort_keys=True, indent=4) + ']')

    if response_json['result'] == 'success':

        if 'full_sync' in response_json:
            if response_json['full_sync']:
                if params.debug: print('Full Sync response')
                params.record_cache = {}  
                params.meta_data_cache = {}  
                params.shared_folder_cache = {}  

        if 'revision' in response_json:
            params.revision = response_json['revision']
    
        if 'removed_records' in response_json:
            for uid in response_json['removed_records']:
                del params.record_cache[uid]
    
        if 'removed_shared_folders' in response_json:
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
            for meta_data in response_json['record_meta_data']:
                if meta_data['record_key_type'] == 2:
                    if params.debug: 
                        print('Converting RSA-encrypted key')

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
                    type1key = iv + cipher.encrypt(unencrypted_key)

                    # store as b64 encoded string
                    # note: decode() converts bytestream (b') to string
                    meta_data['record_key'] = \
                        base64.urlsafe_b64encode(type1key).decode()
                    meta_data['record_key_type'] = 1 

                    if params.debug: 
                        print('encrypted record key: ' + str(type1key)) 
                        print('base64: ' + str(meta_data['record_key'])) 

                # add to local cache
                params.meta_data_cache[meta_data['record_uid']] = meta_data
    

        # decrypt shared folder keys and folder name
        if 'shared_folders' in response_json:
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

                    # save the decrypted key
                    record['record_key'] = unencrypted_key
                else:
                    raise CryptoError('No record key found')


                if params.debug: print('Got record key: ' + str(unencrypted_key))

                # decrypt record data and extra with record key
                decoded_data = base64.urlsafe_b64decode(record['data'] +'==')
                iv = decoded_data[:16]
                ciphertext = decoded_data[16:]
                cipher = AES.new(record['record_key'], AES.MODE_CBC, iv)
                record['data'] = unpad_binary(cipher.decrypt(ciphertext))

                decoded_extra = base64.urlsafe_b64decode(record['extra'] +'==')
                iv = decoded_extra[:16]
                ciphertext = decoded_extra[16:]
                cipher = AES.new(record['record_key'], AES.MODE_CBC, iv)
                record['extra'] = unpad_binary(cipher.decrypt(ciphertext))

                # Store the record in the cache
                params.record_cache[record_uid] = record 

        if 'pending_shares_from' in response_json:
            print('Note: You have pending share requests.')

        if params.debug:
            print('--- Meta Data Cache: ' + str(params.meta_data_cache))
            print('--- Record Cache: ' + str(params.record_cache))
            print('--- Folders Cache: ' + str(params.shared_folder_cache))

        if len(params.record_cache) == 1:
            print('-> Cached 1 record')
        else:
            print('-> Cached ' + str(len(params.record_cache)) + ' records')

    else :
        raise CommunicationError('Unknown problem')

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
    

def display_folders_titles_uids(json_to_show):
    pass
