#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#
import threading
import warnings
from datetime import datetime
from typing import Dict, NamedTuple, Optional, List, Set
from urllib.parse import urlparse, urlunparse

from urllib3.exceptions import InsecureRequestWarning

LAST_RECORD_UID = 'last_record_uid'
LAST_SHARED_FOLDER_UID = 'last_shared_folder_uid'
LAST_FOLDER_UID = 'last_folder_uid'
LAST_TEAM_UID = 'last_team_uid'


class PublicKeys(NamedTuple):
    rsa: bytes = b''
    ec: bytes = b''
    aes: bytes = b''


class RecordOwner(NamedTuple):
    owner: bool
    account_uid: str


class RestApiContext:
    def __init__(self, server='https://keepersecurity.com/api/v2/', locale='en_US'):
        self.server_base = server
        self.transmission_key = None
        self.__server_key_id = 7
        self.locale = locale
        self.__store_server_key = False
        self.proxies = None
        self._certificate_check = True
        self.fail_on_throttle = False

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

    @property
    def certificate_check(self):
        return self._certificate_check

    @certificate_check.setter
    def certificate_check(self, value):
        if isinstance(value, bool):
            self._certificate_check = value
            if value:
                warnings.simplefilter('default', InsecureRequestWarning)
            else:
                warnings.simplefilter('ignore', InsecureRequestWarning)

    server_base = property(__get_server_base, __set_server_base)
    server_key_id = property(__get_server_key_id, __set_server_key_id)
    store_server_key = property(__get_store_server_key)


class KeeperParams:
    """ Global storage of data during the session """

    def __init__(self, config_filename='', config=None, server='keepersecurity.com'):
        self.config_filename = config_filename
        self.config = config or {}
        self.auth_verifier = None
        self.__server = server
        self.user = ''
        self.password = ''
        self.commands = []
        self.plugins = []
        self.session_token = None
        self.data_key = None
        self.client_key = None
        self.rsa_key = None
        self.rsa_key2 = None
        self.ecc_key = None
        self.enterprise_ec_key = None
        self.enterprise_rsa_key = None
        self.revision = 0
        self.sync_down_token = None    # type: Optional[bytes]
        self.record_cache = {}
        self.meta_data_cache = {}
        self.non_shared_data_cache = {}
        self.shared_folder_cache = {}
        self.team_cache = {}
        self.record_link_cache = {}
        self.record_rotation_cache = {}
        self.record_owner_cache = {}   # type: Dict[str, RecordOwner]
        self.key_cache = {}            # type: Dict[str, PublicKeys]
        self.available_team_cache = None
        self.user_cache = {}
        self.subfolder_cache = {}
        self.subfolder_record_cache = {}   # type: Dict[str, Set[str]]
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
        self.is_enterprise_admin = False
        self.enterprise_loader = None
        self.enterprise_id = 0
        self.msp_tree_key = None
        self.prepare_commands = False
        self.batch_mode = False
        self.__rest_context = RestApiContext(server=server)
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
        self.breach_watch_records = {}
        self.breach_watch_security_data = {}
        self.sso_login_info = None
        self.__proxy = None
        self.ssh_agent = None
        self.unmask_all = False
        self.ws = None
        self.tunnel_threads = {}
        self.tunnel_threads_queue = {} # add ability to tail tunnel process
        # TODO check if it can be deleted
        self.salt = None
        self.iterations = 0


    def clear_session(self):
        self.auth_verifier = None
        self.user = ''
        self.password = ''
        self.commands.clear()
        self.session_token = None
        self.salt = None
        self.iterations = 0
        self.data_key = None
        self.client_key = None
        self.rsa_key = None
        self.rsa_key2 = None
        self.ecc_key = None
        self.enterprise_ec_key = None
        self.enterprise_rsa_key = None
        self.revision = 0
        self.sync_down_token = None
        self.record_cache.clear()
        self.meta_data_cache.clear()
        self.non_shared_data_cache.clear()
        self.shared_folder_cache.clear()
        self.team_cache.clear()
        self.record_link_cache.clear()
        self.record_rotation_cache.clear()
        self.record_owner_cache.clear()
        self.available_team_cache = None
        self.key_cache.clear()
        self.subfolder_cache .clear()
        self.subfolder_record_cache.clear()
        if self.folder_cache:
            self.folder_cache.clear()
        self.user_cache.clear()
        self.root_folder = None
        self.current_folder = None
        self.sync_data = True
        self.license = None
        self.settings = None
        self.enforcements = None
        self.is_enterprise_admin = False
        self.enterprise = None
        self.automators = None
        self.enterprise_loader = None
        self.enterprise_id = 0
        self.msp_tree_key = None
        self.prepare_commands = True
        self.pending_share_requests.clear()
        self.environment_variables.clear()
        self.record_history.clear()
        self.event_queue.clear()
        self.account_uid_bytes = None
        self.session_token_bytes = None
        self.record_type_cache = {}
        self.breach_watch = None
        self.breach_watch_records = {}
        self.breach_watch_security_data = {}
        self.sso_login_info = None
        self.ws = None
        if self.ssh_agent:
            self.ssh_agent.close()
            self.ssh_agent = None
        self.tunnel_threads.clear()
        self.tunnel_threads_queue = {}

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
        if isinstance(self.settings, dict):
            share_account_to = self.settings.get('share_account_to')
            must_perform_account_share_by = self.settings.get('must_perform_account_share_by')
            if isinstance(share_account_to, list) and len(share_account_to) > 0 and must_perform_account_share_by:
                if isinstance(must_perform_account_share_by, str):
                    if must_perform_account_share_by.isnumeric():
                        must_perform_account_share_by = int(must_perform_account_share_by)
                if isinstance(must_perform_account_share_by, int) and must_perform_account_share_by > 0:
                    return datetime.fromtimestamp(must_perform_account_share_by // 1000)
        return None
