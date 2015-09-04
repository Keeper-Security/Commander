import sys
import json
import requests
import base64
import getpass
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

def login(params):
    """Login to the server and get session token"""
    
    myheaders = {'user-agent': USER_AGENT}
    validate(params)
    
    if not params.salt:
        if params.debug: print('Getting salt & iterations from server')

        payload = {'command':'account_summary',                                                 
                   'include':['license','settings','group','keys'],
                   'language':LANGUAGE,                                               
                   'country':COUNTRY,                                                 
                   'Keeper-Agent':'Commander',
                   'username':params.email}                                           

        try:
            r = requests.post(params.server, headers=myheaders, json=payload)             
                                                                                    
            # server doesn't include == at the end, but the module expects it
            params.salt = base64.urlsafe_b64decode(r.json()['salt']+'==')
            params.iterations = r.json()['iterations']
    
            prf = lambda p,s: HMAC.new(p,s,SHA256).digest()
            tmp_auth_verifier = base64.urlsafe_b64encode(
                PBKDF2(params.password, params.salt, 
                    32, params.iterations, prf))
    
            # converts b'xxxx' to xxxx
            params.auth_verifier = tmp_auth_verifier.decode()
    
            if params.debug: print('Generated auth verifier: ' + 
                str(params.auth_verifier))

            if params.debug:                                                              
                print('>>> Request server:[' + params.server + ']')                          
                print('>>> Request headers:[' + str(myheaders) + ']')                        
                print('>>> Request JSON:[' + str(payload) + ']')                             
                print('')
                print('<<< Response Code:[' + str(r.status_code) + ']')                      
                print('<<< Response Headers:[' + str(r.headers) + ']')                       
                print('<<< Response content:[' + str(r.text) + ']')                          
                print('<<< Auth Verifier:['+str(params.auth_verifier)+']')                          

        except:
            raise CommunicationError(sys.exc_info()[0])


    success = False
    while not success:

        if params.mfa_token:
            payload = {
                   'command':'login', 
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
            r = requests.post(params.server, headers=myheaders, json=payload)             
        except:
            raise CommunicationError(sys.exc_info()[0])

        response_json = r.json()

        if params.debug:                                                              
            print('>>> Request server:[' + params.server + ']')                          
            print('>>> Request headers:[' + str(myheaders) + ']')                        
            print('>>> Request JSON:[' + str(payload) + ']')                             
            print('')
            print('<<< Response Code:[' + str(r.status_code) + ']')                      
            print('<<< Response Headers:[' + str(r.headers) + ']')                       
            print('<<< Response content:[' + str(r.text) + ']')                          
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

            if params.mfa_token:
                params.mfa_type = 'device_token'

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
            

def validate(params):
    if not params.server:
        print('Error: server is not defined.')
        sys.exit()

    if not params.email:
        print('Error: email is not defined.')
        sys.exit()

    if not params.password:
        print('Error: password is not defined.')
        sys.exit()
