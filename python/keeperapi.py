import sys
import json
import requests
import base64
import getpass
import time
from keepererror import AuthenticationError
from keepererror import CommunicationError
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto import Random

VERSION = '0.1'
USER_AGENT = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) ' + 
             'AppleWebKit/537.36 (KHTML, like Gecko) ' + 
             'Chrome/40.0.2214.111 Safari/537.36')
LANGUAGE = 'en'
COUNTRY = 'US'
HEADERS = {'user-agent': USER_AGENT}

current_milli_time = lambda: int(round(time.time() * 1000))

def login(params):
    """Login to the server and get session token"""
    
    if not params.salt:
        payload = {'command':'account_summary',
                   'include':['license','settings','group','keys'],
                   'language':LANGUAGE,
                   'country':COUNTRY,
                   'Keeper-Agent':'Commander',
                   'username':params.email}

        try:
            r = requests.post(params.server, headers=HEADERS, json=payload)             
        except:
            raise CommunicationError(sys.exc_info()[0])
                                                                                    
        if params.debug:                                                              
            print('')
            print('>>> Request server:[' + params.server + ']')                          
            print('>>> Request headers:[' + str(HEADERS) + ']')                        
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

        # converts b'xxxx' to xxxx
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
                   'language':LANGUAGE,
                   'country':COUNTRY, 
                   'Keeper-Agent':'Commander',
                   '2fa_token':params.mfa_token,
                   '2fa_type':params.mfa_type, 
                   'username':params.email
                  }

        else:
            payload = {
                   'command':'login', 
                   'version':2, 
                   'auth_response':params.auth_verifier,
                   'language':LANGUAGE,
                   'country':COUNTRY, 
                   'Keeper-Agent':'Commander',
                   'username':params.email
                  }

        try:
            r = requests.post(params.server, headers=HEADERS, json=payload)             
        except:
            raise CommunicationError(sys.exc_info()[0])

        response_json = r.json()

        if params.debug:                                                              
            print('')
            print('>>> Request server:[' + params.server + ']')                          
            print('>>> Request headers:[' + str(HEADERS) + ']')                        
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

            if params.debug: params.dump() 

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

def list(params):
    if not params.session_token:
        try:
            login(params)
        except:
            raise
            
    payload = {
               'include':[
                   'sfheaders',
                   'sfrecords',
                   'sfusers',
                   'sfteams'
               ],
               'revision':0,
               'client_time':current_milli_time(),
               'device_id':'Commander', 
               'device_name':'Commander', 
               'command':'sync_down', 
               'protocol_version':1, 
               'language':LANGUAGE,
               'country':COUNTRY, 
               'Keeper-Agent':'Commander',
               '2fa_token':params.mfa_token,
               '2fa_type':params.mfa_type, 
               'session_token':params.session_token, 
               'username':params.email
              }

    try:
        r = requests.post(params.server, headers=HEADERS, json=payload)        
    except:
        raise CommunicationError(sys.exc_info()[0])

    response_json = r.json()

    if params.debug:                                                         
        print('')
        print('>>> Request server:[' + params.server + ']')
        print('>>> Request headers:[' + str(HEADERS) + ']')
        print('>>> Request JSON:[' + str(payload) + ']')
        print('')
        print('<<< Response Code:[' + str(r.status_code) + ']')
        print('<<< Response Headers:[' + str(r.headers) + ']')
        print('<<< Response content:[' + json.dumps(response_json, 
            sort_keys=True, indent=4) + ']')

    if response_json['result'] == 'success':
        success, json_to_show = decrypt_data(response_json)
        if success:
            print('Data retrieved and decrypted.')
            display_folders_titles_uids()
    else :
        raise CommunicationError('Unknown problem')

def decrypt_data_key(params):
    """ Decrypt the data key and private key returned by the server """
    decoded_private_key = base64.urlsafe_b64decode(
        params.encrypted_private_key+'==')
    decoded_encryption_params = base64.urlsafe_b64decode(
        params.encryption_params+'==')
    print('Decoded private key: ' + str(decoded_private_key))
    print('Decoded encryption params: ' + str(decoded_encryption_params))

def decrypt_data(json_to_decrypt):
    if not json:
        return False

    if not 'private_key' in json_to_decrypt:
        print('Unable to decrypt: no private key provided.')
        return False

    print('Decrypting private_key')
    json_to_decrypt['private_key']

    if 'shared_folders' in json_to_decrypt:
        pass

    if 'records' in json_to_decrypt:
        pass

    if 'non_shared_data' in json_to_decrypt:
        pass

    if 'record_meta_data' in json_to_decrypt:
        pass

    if 'pending_shares_from' in json_to_decrypt:
        if json_to_decrypt['pending_shares_from']:
            print('FYI: You have pending share requests.')

def display_folders_titles_uids(json_to_show):
    pass
