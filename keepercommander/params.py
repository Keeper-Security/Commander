#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#


class KeeperParams:
    """ Global storage of data during the session """

    def __init__(self,config_filename='',config={}, server='https://keepersecurity.com/api/v2/',
                 user='',password='',mfa_token='',
                 mfa_type='device_token',command='',commands=[],plugins=[],
                 session_token='',salt='',iterations='',
                 encrypted_private_key='', encryption_params='',
                 data_key='',private_key='',
                 revision=0, rsa_key='', auth_verifier='',
                 record_cache={}, meta_data_cache={}, shared_folder_cache={},
                 team_cache = {}, subfolder_cache={}, debug=False, timedelay=0):
        self.config_filename = config_filename
        self.config = config
        self.auth_verifier = auth_verifier 
        self.server = server 
        self.user = user
        self.password = password 
        self.mfa_token = mfa_token 
        self.mfa_type = mfa_type 
        self.command = command 
        self.commands = commands 
        self.plugins = plugins 
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
        self.team_cache = team_cache
        self.subfolder_cache = subfolder_cache
        self.subfolder_record_cache = {}
        self.root_folder = None
        self.current_folder = None
        self.folder_cache = {}
        self.rsa_key = rsa_key
        self.debug = debug
        self.timedelay = timedelay
        self.sync_data = True
        self.license = None
        self.enterprise = None
        self.prepare_commands = False
        self.batch_mode = False

    def clear_session(self):
        self.auth_verifier = ''
        self.user = ''
        self.password = ''
        self.mfa_type = 'device_token'
        self.mfa_token = ''
        self.command = ''
        self.commands.clear()
        self.session_token = ''
        self.salt = ''
        self.iterations = 0
        self.encrypted_private_key = ''
        self.encryption_params = ''
        self.data_key = b''
        self.private_key = ''
        self.revision = 0
        self.record_cache.clear()
        self.meta_data_cache.clear()
        self.shared_folder_cache.clear()
        self.team_cache.clear()
        self.subfolder_cache .clear()
        self.subfolder_record_cache.clear()
        if self.folder_cache:
            self.folder_cache.clear()

        self.root_folder = None
        self.current_folder = None
        self.sync_data = True
        self.license = None
        self.enterprise = None
        self.prepare_commands = True
        self.batch_mode = False
