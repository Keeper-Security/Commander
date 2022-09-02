#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#

import warnings
from urllib3.exceptions import InsecureRequestWarning

from urllib.parse import urlparse, urlunparse
from datetime import datetime


LAST_RECORD_UID = 'last_record_uid'
LAST_SHARED_FOLDER_UID = 'last_shared_folder_uid'
LAST_FOLDER_UID = 'last_folder_uid'
LAST_TEAM_UID = 'last_team_uid'


class RestApiContext:
    def __init__(self, server='https://keepersecurity.com/api/v2/', locale='en_US', device_id=None):
        self.server_base = server
        self.transmission_key = None
        self.__server_key_id = 1
        self.locale = locale
        self.__device_id = device_id
        self.__store_server_key = False
        self.proxies = None
        self._certificate_check = True
        self._fail_on_throttle = False

    def __get_server_base(self):
        return self.__server_base

    def __set_server_base(self, value):    # type: (str) -> None
        if not value.startswith('http'):
            value = 'https://' + value
        p = urlparse(value)
        self.__server_base = urlunparse((p.scheme or 'https', p.netloc, '/api/rest/', None, None, None))

    def __get_server_key_id(self):
        return self.__server_key_id

    def __set_server_key_id(self, key_id):
        self.__server_key_id = key_id
        self.__store_server_key = True

    def __get_device_id(self):
        return self.__device_id

    def __set_device_id(self, device_id):
        self.__device_id = device_id
        self.__store_server_key = True

    def __get_store_server_key(self):
        return self.__store_server_key

    def set_proxy(self, proxy_server):
        if proxy_server:
            self.proxies = {
                'http': proxy_server,
                'https': proxy_server
            }
        else:
            self.proxies = None

    def get_certificate_check(self):
        return self._certificate_check

    def set_certificate_check(self, value):
        if isinstance(value, bool):
            self._certificate_check = value
            if value:
                warnings.simplefilter('default', InsecureRequestWarning)
            else:
                warnings.simplefilter('ignore', InsecureRequestWarning)

    def get_fail_on_throttle(self):
        return self._fail_on_throttle

    server_base = property(__get_server_base, __set_server_base)
    device_id = property(__get_device_id, __set_device_id)
    server_key_id = property(__get_server_key_id, __set_server_key_id)
    store_server_key = property(__get_store_server_key)
    certificate_check = property(get_certificate_check, set_certificate_check)
    fail_on_throttle = property(get_fail_on_throttle)


class KeeperParams:
    """ Global storage of data during the session """

    def __init__(self, config_filename='', config=None, server='keepersecurity.com', device_id=None):
        self.config_filename = config_filename
        self.config = config or {}
        self.auth_verifier = None
        self.__server = server
        self.user = ''
        self.password = ''
        self.mfa_token = ''
        self.mfa_type = 'device_token'
        self.commands = []
        self.plugins = []
        self.session_token = None
        self.salt = None
        self.iterations = 0
        self.data_key = None
        self.client_key = None
        self.rsa_key = None
        self.ecc_key = None
        self.enterprise_ec_key = None
        self.revision = 0
        self.record_cache = {}
        self.meta_data_cache = {}
        self.shared_folder_cache = {}
        self.team_cache = {}
        self.key_cache = {}    # team or user
        self.available_team_cache = None
        self.subfolder_cache = {}
        self.subfolder_record_cache = {}
        self.root_folder = None
        self.current_folder = None
        self.folder_cache = {}
        self.debug = False
        self.timedelay = 0
        self.sync_data = True
        self.license = None
        self.settings = None
        self.enforcements = None
        self.enterprise = None
        self.automators = None
        self.enterprise_loader = None
        self.enterprise_id = 0
        self.msp_tree_key = None
        self.prepare_commands = False
        self.batch_mode = False
        self.__rest_context = RestApiContext(server=server, device_id=device_id)
        self.pending_share_requests = set()
        self.environment_variables = {}
        self.record_history = {}        # type: dict[str, (list[dict], int)]
        self.event_queue = []
        self.logout_timer = 0
        self.clone_code = None
        self.device_token = None
        self.device_private_key = None
        self.account_uid_bytes = None
        self.session_token_bytes = None
        self.record_type_cache = {}  # RT definitions only
        self.breach_watch = None
        self.breach_watch_records = None
        self.sso_login_info = None
        self.__proxy = None
        self.ssh_agent = None

    def clear_session(self):
        self.auth_verifier = None
        self.user = ''
        self.password = ''
        self.mfa_type = 'device_token'
        self.mfa_token = ''
        self.commands.clear()
        self.session_token = None
        self.salt = None
        self.iterations = 0
        self.data_key = None
        self.client_key = None
        self.rsa_key = None
        self.ecc_key = None
        self.enterprise_ec_key = None
        self.revision = 0
        self.record_cache.clear()
        self.meta_data_cache.clear()
        self.shared_folder_cache.clear()
        self.team_cache.clear()
        self.available_team_cache = None
        self.key_cache.clear()
        self.subfolder_cache .clear()
        self.subfolder_record_cache.clear()
        if self.folder_cache:
            self.folder_cache.clear()

        self.root_folder = None
        self.current_folder = None
        self.sync_data = True
        self.license = None
        self.settings = None
        self.enforcements = None
        self.enterprise = None
        self.automators = None
        self.enterprise_loader = None
        self.enterprise_id = 0
        self.msp_tree_key = None
        self.prepare_commands = True
        self.batch_mode = False
        self.pending_share_requests.clear()
        self.environment_variables.clear()
        self.record_history.clear()
        self.event_queue.clear()
        self.logout_timer = self.config.get('logout_timer') or 0
        self.clone_code = None
        self.device_token = None
        self.device_private_key = None
        self.account_uid_bytes = None
        self.session_token_bytes = None
        self.record_type_cache = {}
        self.breach_watch = None
        self.breach_watch_records = None
        self.sso_login_info = None
        if self.ssh_agent:
            self.ssh_agent.close()
            self.ssh_agent = None

    def __get_rest_context(self):   # type: () -> RestApiContext
        return self.__rest_context

    def __get_server(self):
        return self.__server

    def __set_server(self, value):
        self.__server = value
        self.__rest_context.server_base = value

    def __get_proxy(self):
        return self.__proxy

    def __set_proxy(self, value):
        self.__proxy = value
        self.__rest_context.set_proxy(self.__proxy)

    def queue_audit_event(self, name, **kwargs):
        # type: (str, ...) -> None
        if self.license and 'account_type' in self.license:
            if self.license['account_type'] == 2:
                self.event_queue.append({
                    'audit_event_type': name,
                    'inputs': {x: kwargs[x] for x in kwargs if x in {'record_uid', 'file_format', 'attachment_id', 'to_username'}}
                })

    proxy = property(__get_proxy, __set_proxy)
    server = property(__get_server, __set_server)
    rest_context = property(__get_rest_context)

    def get_share_account_timestamp(self):
        if self.settings and 'share_account_to' in self.settings and 'must_perform_account_share_by' in self.settings:
            return datetime.fromtimestamp(int(self.settings['must_perform_account_share_by']) // 1000)
        else:
            return None
