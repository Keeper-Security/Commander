import sys
import json
import requests
import base64
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

    # Check basic required fields
    validate(params)
    
    # get salt from the server
    if not params.salt:
        if params.debug: print('Getting salt & iterations from server')

        payload = {'command':'account_summary',                                                 
                   'include':['license','settings','group','keys'],
                   'language':LANGUAGE,                                               
                   'country':COUNTRY,                                                 
                   'Keeper-Agent':'Commander',
                   'username':params.email}                                           

        r = requests.post(params.server, headers=myheaders, json=payload)             
                                                                                    
        if params.debug:                                                              
            print('Request server:  [' + params.server + ']')                          
            print('Request headers: [' + str(myheaders) + ']')                        
            print('Request JSON:    [' + str(payload) + ']')                             
            print('Response Code:   [' + str(r.status_code) + ']')                      
            print('Response Headers:[' + str(r.headers) + ']')                       
            print('Response content:[' + str(r.text) + ']')                          

        # server doesn't include == at the end, but this module expects it
        params.salt = base64.urlsafe_b64decode(r.json()['salt']+'==')
        params.iterations = r.json()['iterations']

        if params.debug: print('Got salt = '+str(params.salt))
        if params.debug: print('Got iterations = '+str(params.iterations))

        prf = lambda p,s: HMAC.new(p,s,SHA256).digest()
        tmp_auth_verifier = base64.urlsafe_b64encode(
            PBKDF2(params.password, params.salt, 
                32, params.iterations, prf))

        # converts b'xxxx' to xxxx
        params.auth_verifier = tmp_auth_verifier.decode()

        if params.debug: print('Generated auth verifier: ' + 
            str(params.auth_verifier))

    payload = {'command':'login', 
               'version':2, 
               'auth_response':params.auth_verifier,
               'language':LANGUAGE,
               'country':COUNTRY, 
               'Keeper-Agent':'Commander',
               'mfa_token':params.mfa_token,
               'mfa_type':params.mfa_type, 
               'username':params.email}

    r = requests.post(params.server, headers=myheaders, json=payload)             
    response_json = r.json()

    if response_json['result_code'] == 'auth_success' and response_json['result'] == 'success':
        if params.debug: print('Auth Success')
        params.session_token = response_json['session_token']

    if params.debug:                                                              
        print('Request server:  [' + params.server + ']')                          
        print('Request headers: [' + str(myheaders) + ']')                        
        print('Request JSON:    [' + str(payload) + ']')                             
        print('Response Code:   [' + str(r.status_code) + ']')                      
        print('Response Headers:[' + str(r.headers) + ']')                       
        print('Response content:[' + str(r.text) + ']')                          
        print('Session Token:   [' + str(params.session_token) + ']')                          

def gen_salt():
        # probably wrong TBD
        return base64.b64encode(Random.new().read(16)).decode('utf-8')

def list(params):
    if params.debug:
        print('== List ==')

    if not params.session_token:
        login(params)

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
