#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2015 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

class KeeperParams:
    """Defines the input parameters for the session"""

    def __init__(self,config_filename='',config={}, server='',
                 email='',password='',mfa_token='',
                 mfa_type='',command='',session_token='',
                 salt='',iterations='',encrypted_private_key='',
                 encryption_params='',data_key='',private_key='',
                 revision=0, rsa_key='', auth_verifier='',
                 record_cache={}, meta_data_cache={}, shared_folder_cache={},
                 debug=False):
        self.config_filename = config_filename
        self.config = config
        self.auth_verifier = auth_verifier 
        self.server = server 
        self.email = email 
        self.password = password 
        self.mfa_token = mfa_token 
        self.mfa_type = mfa_type 
        self.command = command 
        self.session_token = session_token 
        self.salt = salt 
        self.iterations = iterations 
        self.encrypted_private_key = encrypted_private_key
        self.encryption_params = encryption_params
        self.data_key = data_key
        self.private_key = private_key
        self.revision = revision
        self.record_cache = record_cache
        self.meta_data_cache = meta_data_cache
        self.shared_folder_cache = shared_folder_cache
        self.rsa_key = rsa_key
        self.debug = debug

    def logout(self):
        self.mfa_token = '' 
        self.session_token = '' 

    def dump(self):
        if self.server:
            print ('>> Server: ' + self.server)

        if self.email:
            print ('>> Email: ' + self.email)

        if self.password:
            print ('>> Password: ' + self.password)

        if self.mfa_token:
            print ('>> 2FA token: ' + self.mfa_token)

        if self.mfa_type:
            print ('>> 2FA type: ' + self.mfa_type)

        if self.command:
            print ('>> Command: ' + self.command)

        if self.session_token:
            print ('>> Session Token: ' + str(self.session_token))

        if self.salt:
            print ('>> Salt: ' + str(self.salt))

        if self.iterations:
            print ('>> Iterations: ' + str(self.iterations))

        if self.encrypted_private_key:
            print ('>> Encrypted Priv Key: ' + str(self.encrypted_private_key))

        if self.encryption_params:
            print ('>> Encryption Params: ' + str(self.encryption_params))

        if self.data_key:
            print ('>> Data Key: ' + str(self.data_key))

        if self.private_key:
            print ('>> Private Key: ' + str(self.private_key))

        if self.rsa_key:
            print ('>> RSA Key: ' + str(self.rsa_key))

        if self.debug:
            print ('>> Debug: ' + str(self.debug))


