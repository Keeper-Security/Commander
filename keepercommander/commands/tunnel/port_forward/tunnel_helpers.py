import base64
import enum
import json
import logging
import os
import secrets
import socket
import string
import sys
import time
import ssl
import asyncio

from keeper_secrets_manager_core.utils import string_to_bytes, bytes_to_string, url_safe_str_to_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from keeper_secrets_manager_core.utils import bytes_to_base64, base64_to_bytes
from ....proto import pam_pb2

from ....commands.base import FolderMixin
from ....commands.pam.pam_dto import GatewayAction, GatewayActionWebRTCSession
from ....commands.pam.router_helper import router_get_relay_access_creds, get_dag_leafs, \
    get_router_ws_url, router_send_action_to_gateway
from ....display import bcolors
from ....error import CommandError
from ....subfolder import try_resolve_path
from .... import crypto, utils, rest_api, api

# Import the websockets library for async WebSocket communication
# Support both websockets 15.0.1+ (asyncio) and legacy 11.0.3 (sync) versions
try:
    # Try websockets 15.0.1+ asyncio implementation first
    from websockets.asyncio.client import connect as websockets_connect
    from websockets.exceptions import ConnectionClosed, InvalidURI, InvalidHandshake
    WEBSOCKETS_VERSION = "asyncio"
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    try:
        # Fallback to websockets 11.0.3 legacy implementation
        from websockets import connect as websockets_connect
        from websockets.exceptions import ConnectionClosed, InvalidURI, InvalidHandshake
        WEBSOCKETS_VERSION = "legacy"
        WEBSOCKETS_AVAILABLE = True
    except ImportError:
        WEBSOCKETS_AVAILABLE = False
        websockets_connect = None
        ConnectionClosed = None
        WEBSOCKETS_VERSION = None
        print("websockets library not available - install with: pip install websockets", file=sys.stderr)

# Constants
NONCE_LENGTH = 12
MAIN_NONCE_LENGTH = 16
SYMMETRIC_KEY_LENGTH = RANDOM_LENGTH = 32
READ_TIMEOUT = 1.5
KRELAY_URL = 'KRELAY_SERVER'
GATEWAY_TIMEOUT = int(os.getenv('GATEWAY_TIMEOUT')) if os.getenv('GATEWAY_TIMEOUT') else 30000
VERIFY_SSL = bool(os.environ.get("VERIFY_SSL", "TRUE") == "TRUE")

# ICE candidate buffering - store until SDP answer is received

# Global conversation key management for multiple concurrent tunnels
import threading
_CONVERSATION_KEYS_LOCK = threading.Lock()
_GLOBAL_CONVERSATION_KEYS = {}  # conversationId -> symmetric_key mapping

# Global tunnel session management by tube_id
_TUNNEL_SESSIONS_LOCK = threading.Lock()
_GLOBAL_TUNNEL_SESSIONS = {}  # tube_id -> TunnelSession mapping

# NOTE: Global WebSocket variables removed! Each tunnel now has its own dedicated WebSocket.
# - _ACTIVE_WEBSOCKET_THREAD removed - each tunnel has tunnel_session.websocket_thread
# - _WEBSOCKET_READY_EVENT removed - each tunnel has tunnel_session.websocket_ready_event
# - _WEBSOCKET_THREAD_LOCK removed - no longer needed with dedicated WebSockets
# - _WEBSOCKET_REGISTRATION_LOCK removed - no contention with dedicated WebSockets


class CloseConnectionReason:
    """
    Represents a structured close reason for WebRTC tunnel connections.
    Provides categorization and backward compatibility with legacy outcome strings.
    """
    
    # Close reason codes with their properties
    REASONS = {
        0: {"name": "Normal", "critical": False, "user_initiated": True, "retryable": False},
        1: {"name": "Error", "critical": True, "user_initiated": False, "retryable": True},
        2: {"name": "Timeout", "critical": False, "user_initiated": False, "retryable": True},
        4: {"name": "ServerRefuse", "critical": True, "user_initiated": False, "retryable": True},
        5: {"name": "Client", "critical": False, "user_initiated": True, "retryable": False},
        6: {"name": "Unknown", "critical": False, "user_initiated": False, "retryable": False},
        7: {"name": "InvalidInstruction", "critical": True, "user_initiated": False, "retryable": False},
        8: {"name": "GuacdRefuse", "critical": True, "user_initiated": False, "retryable": True},
        9: {"name": "ConnectionLost", "critical": False, "user_initiated": False, "retryable": True},
        10: {"name": "ConnectionFailed", "critical": True, "user_initiated": False, "retryable": True},
        11: {"name": "TunnelClosed", "critical": False, "user_initiated": True, "retryable": False},
        12: {"name": "AdminClosed", "critical": False, "user_initiated": True, "retryable": False},
        13: {"name": "ErrorRecording", "critical": True, "user_initiated": False, "retryable": False},
        14: {"name": "GuacdError", "critical": True, "user_initiated": False, "retryable": False},
        15: {"name": "AIClosed", "critical": False, "user_initiated": False, "retryable": False},
        16: {"name": "AddressResolutionFailed", "critical": True, "user_initiated": False, "retryable": True},
        17: {"name": "DecryptionFailed", "critical": True, "user_initiated": False, "retryable": False},
        18: {"name": "ConfigurationError", "critical": True, "user_initiated": False, "retryable": False},
        19: {"name": "ProtocolError", "critical": True, "user_initiated": False, "retryable": False},
        20: {"name": "UpstreamClosed", "critical": False, "user_initiated": False, "retryable": True},
    }
    
    # Legacy outcome mapping for backward compatibility
    LEGACY_OUTCOMES = {
        "normal": 0,
        "success": 0,
        "completed": 0,
        "tube_closed": 0,  # User-initiated tube closure (pam tunnel stop)
        "error": 1,
        "failed": 1,
        "failure": 1,
        "timeout": 2,
        "timed_out": 2,
        "server_refuse": 4,
        "server_refused": 4,
        "client": 5,
        "client_closed": 5,
        "user_closed": 5,
        "unknown": 6,
        "invalid_instruction": 7,
        "guacd_refuse": 8,
        "connection_lost": 9,
        "connection_failed": 10,
        "tunnel_closed": 11,
        "admin_closed": 12,
        "error_recording": 13,
        "recording_error": 13,
        "guacd_error": 14,
        "ai_closed": 15,
        "address_resolution_failed": 16,
        "dns_failed": 16,
        "decryption_failed": 17,
        "configuration_error": 18,
        "config_error": 18,
        "protocol_error": 19,
        "upstream_closed": 20,
    }
    
    def __init__(self, code, name=None):
        self.code = code
        self._reason_info = self.REASONS.get(code, self.REASONS[6])  # Default to Unknown
        self.name = name or self._reason_info["name"]
    
    @classmethod
    def from_code(cls, code):
        """Create CloseConnectionReason from numeric code"""
        if code in cls.REASONS:
            return cls(code)
        else:
            logging.warning(f"Unknown close reason code: {code}, defaulting to Unknown")
            return cls(6)  # Unknown
    
    @classmethod
    def from_legacy_outcome(cls, outcome):
        """Create CloseConnectionReason from legacy outcome string"""
        if not outcome or not isinstance(outcome, str):
            return cls(6)  # Unknown
        
        # Try direct mapping first
        outcome_lower = outcome.lower().strip()
        code = cls.LEGACY_OUTCOMES.get(outcome_lower)
        
        if code is not None:
            return cls(code)
        
        # Try partial matching for common variations
        for legacy_key, legacy_code in cls.LEGACY_OUTCOMES.items():
            if legacy_key in outcome_lower or outcome_lower in legacy_key:
                return cls(legacy_code)
        
        # Default to Unknown
        logging.warning(f"Unknown legacy outcome: '{outcome}', defaulting to Unknown")
        return cls(6)
    
    def is_critical(self):
        """Returns True if this is a critical failure requiring immediate attention"""
        return self._reason_info["critical"]
    
    def is_user_initiated(self):
        """Returns True if this was initiated by user action"""
        return self._reason_info["user_initiated"]
    
    def is_retryable(self):
        """Returns True if this failure is potentially retryable"""
        return self._reason_info["retryable"]

class TunnelSession:
    """Container for tunnel session state organized by tube_id"""
    def __init__(self, tube_id, conversation_id, gateway_uid, symmetric_key,
                 offer_sent=False, host=None, port=None,
                 record_title=None, record_uid=None, target_host=None, target_port=None):
        self.tube_id = tube_id
        self.conversation_id = conversation_id
        self.gateway_uid = gateway_uid
        self.symmetric_key = symmetric_key
        self.offer_sent = offer_sent
        self.host = host
        self.port = port
        self.record_title = record_title
        self.record_uid = record_uid
        self.target_host = target_host
        self.target_port = target_port
        self.buffered_ice_candidates = []
        self.creation_time = time.time()
        self.last_activity = time.time()
        # Per-tunnel WebSocket management
        self.websocket_thread = None
        self.websocket_ready_event = None
        self.websocket_stop_event = None
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()

def register_tunnel_session(tube_id, session):
    """Register a tunnel session by tube_id (thread-safe)"""
    with _TUNNEL_SESSIONS_LOCK:
        _GLOBAL_TUNNEL_SESSIONS[tube_id] = session
        logging.debug(f"Registered tunnel session for tube: {tube_id}")
        logging.debug(f"Total active tunnel sessions: {len(_GLOBAL_TUNNEL_SESSIONS)}")

def get_tunnel_session(tube_id):
    """Get a tunnel session by tube_id (thread-safe)"""
    with _TUNNEL_SESSIONS_LOCK:
        return _GLOBAL_TUNNEL_SESSIONS.get(tube_id)

def unregister_tunnel_session(tube_id):
    """Remove a tunnel session by tube_id (thread-safe)"""
    with _TUNNEL_SESSIONS_LOCK:
        if tube_id in _GLOBAL_TUNNEL_SESSIONS:
            session = _GLOBAL_TUNNEL_SESSIONS[tube_id]
            del _GLOBAL_TUNNEL_SESSIONS[tube_id]
            logging.debug(f"Unregistered tunnel session for tube: {tube_id}")
            logging.debug(f"Remaining active tunnel sessions: {len(_GLOBAL_TUNNEL_SESSIONS)}")
            return session
        return None

def get_all_tunnel_sessions():
    """Get all active tunnel sessions (thread-safe)"""
    with _TUNNEL_SESSIONS_LOCK:
        return dict(_GLOBAL_TUNNEL_SESSIONS)

def clear_all_tunnel_sessions():
    """Clear all tunnel sessions (thread-safe)"""
    with _TUNNEL_SESSIONS_LOCK:
        count = len(_GLOBAL_TUNNEL_SESSIONS)
        _GLOBAL_TUNNEL_SESSIONS.clear()
        logging.debug(f"Cleared {count} tunnel sessions")

def register_conversation_key(conversation_id, symmetric_key):
    """Register an encryption key for a conversation ID (thread-safe)"""
    with _CONVERSATION_KEYS_LOCK:
        _GLOBAL_CONVERSATION_KEYS[conversation_id] = symmetric_key
        logging.debug(f"Registered conversation key for: {conversation_id}")
        logging.debug(f"Total registered conversations: {len(_GLOBAL_CONVERSATION_KEYS)}")

def unregister_conversation_key(conversation_id):
    """Remove an encryption key for a conversation ID (thread-safe)"""
    with _CONVERSATION_KEYS_LOCK:
        if conversation_id in _GLOBAL_CONVERSATION_KEYS:
            del _GLOBAL_CONVERSATION_KEYS[conversation_id]
            logging.debug(f"Unregistered conversation key for: {conversation_id}")
            logging.debug(f"Remaining registered conversations: {len(_GLOBAL_CONVERSATION_KEYS)}")

def get_conversation_key(conversation_id):
    """Get an encryption key for a conversation ID (thread-safe)"""
    with _CONVERSATION_KEYS_LOCK:
        return _GLOBAL_CONVERSATION_KEYS.get(conversation_id)

def get_all_conversation_ids():
    """Get all registered conversation IDs (thread-safe)"""
    with _CONVERSATION_KEYS_LOCK:
        return list(_GLOBAL_CONVERSATION_KEYS.keys())

def clear_all_conversation_keys():
    """Clear all conversation keys (thread-safe)"""
    with _CONVERSATION_KEYS_LOCK:
        count = len(_GLOBAL_CONVERSATION_KEYS)
        _GLOBAL_CONVERSATION_KEYS.clear()
        logging.debug(f"Cleared {count} conversation keys")

def get_conversation_status():
    """Get current conversation key status for debugging (thread-safe)"""
    with _CONVERSATION_KEYS_LOCK:
        active_conversations = len(_GLOBAL_CONVERSATION_KEYS)
        conversation_ids = list(_GLOBAL_CONVERSATION_KEYS.keys())
    
    # Get tunnel session info to count active WebSockets
    with _TUNNEL_SESSIONS_LOCK:
        active_websockets = sum(1 for session in _GLOBAL_TUNNEL_SESSIONS.values() 
                               if session.websocket_thread and session.websocket_thread.is_alive())
        total_tunnels = len(_GLOBAL_TUNNEL_SESSIONS)
    
    return {
        "active_conversations": active_conversations,
        "conversation_ids": conversation_ids,
        "active_websockets": active_websockets,
        "total_tunnels": total_tunnels
    }


# Tunnel helper functions
def get_or_create_tube_registry(params):
    """Get or create the tube registry instance, storing it on params for reuse"""
    try:
        from keeper_pam_webrtc_rs import PyTubeRegistry, initialize_logger

        # Initialize logger (Rust lib handles re-initialization gracefully)
        # Match current debug state (not just initial --debug flag)
        current_is_debug = logging.getLogger().level <= logging.DEBUG
        log_level = logging.getLogger().getEffectiveLevel()
        initialize_logger(
            logger_name="keeper-pam-webrtc-rs",
            verbose=current_is_debug,  # Use current state, matches debug toggles
            level=log_level
        )

        # Reuse existing registry or create new one
        if not hasattr(params, 'tube_registry') or params.tube_registry is None:
            params.tube_registry = PyTubeRegistry()
        return params.tube_registry
    except ImportError:
        logging.error("Rust WebRTC library (keeper_pam_webrtc_rs) not available")
        return None
    except Exception as e:
        logging.error(f"Failed to create tube registry: {e}")
        return None


def cleanup_tube_registry(params):
    """Clean up the tube registry and all active tubes"""
    if hasattr(params, 'tube_registry') and params.tube_registry is not None:
        try:
            params.tube_registry.cleanup_all()
            params.tube_registry = None
        except Exception as e:
            logging.warning(f"Error cleaning up tube registry: {e}")
    
    # Also clear all conversation keys when cleaning up everything
    clear_all_conversation_keys()


class SocketNotConnectedException(Exception):
    pass


class CloseConnectionReasons(enum.IntEnum):
    Normal = 0
    Error = 1
    Timeout = 2
    ServerRefuse = 4
    Client = 5
    Unknown = 6
    InvalidInstruction = 7
    GuacdRefuse = 8
    ConnectionLost = 9
    ConnectionFailed = 10
    TunnelClosed = 11
    AdminClosed = 12
    ErrorRecording = 13
    GuacdError = 14
    AIClosed = 15
    AddressResolutionFailed = 16
    DecryptionFailed = 17
    ConfigurationError = 18
    ProtocolError = 19
    UpstreamClosed = 20


class ConversationType(enum.Enum):
    TUNNEL = "tunnel"
    SSH = "ssh"
    RDP = "rdp"
    VNC = "vnc"
    HTTP = "http"
    KUBERNETES = "kubernetes"
    TELNET = "telnet"
    MYSQL = "mysql"
    SQLSERVER = "sql-server"
    POSTGRESQL = "postgresql"


def generate_random_bytes(pass_length=RANDOM_LENGTH):  # type: (int) -> bytes
    # Generate random bytes without worrying about character decoding
    random_bytes = secrets.token_bytes(pass_length)

    # Filter out non-printable bytes using a list comprehension
    printable_bytes = [byte for byte in random_bytes if
                       byte in string.printable.encode('utf-8') and byte not in b'\n\r']

    # Convert the list of bytes back to bytes
    filtered_bytes = bytes(printable_bytes)
    if len(filtered_bytes) < pass_length:
        # If the length of the filtered bytes is less than the requested length, call the function recursively
        # to generate more bytes
        return filtered_bytes + generate_random_bytes(pass_length - len(filtered_bytes))

    return filtered_bytes


def find_open_port(tried_ports: list, start_port=49152, end_port=65535, preferred_port=None, host="127.0.0.1"):
    """
    Find an open port in the range [start_port, end_port].
    The default range is from 49,152 to 65,535, which are the "ephemeral ports" or "dynamic ports."
    :param tried_ports: A list of ports that have already been tried.
    :param start_port: The starting port number.
    :param end_port: The ending port number.
    :param preferred_port: A preferred port to check first.
    :param host: The host to check for open ports.
    :return: An open port number or None if no port is found.
    """
    if host is None:
        host = '127.0.0.1'
    if preferred_port and preferred_port not in tried_ports:
        if is_port_open(host, preferred_port):
            time.sleep(0.1)  # Short delay to ensure port release
            return preferred_port
        else:
            raise CommandError("Tunnel Start", f"Port {preferred_port} is already in use.")

    for port in range(start_port, end_port + 1):
        if port not in tried_ports and is_port_open(host, port):
            time.sleep(0.1)  # Short delay to ensure port release
            return port

    return None


def is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Enable SO_REUSEADDR to allow binding to ports in TIME_WAIT state
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
        except OSError:
            return False
        except Exception as e:
            import logging
            logging.error(f"Error while checking port {port}: {e}")
            return False


def tunnel_encrypt(symmetric_key: AESGCM, data: bytes):
    """ Encrypts data using the symmetric key """
    nonce = os.urandom(NONCE_LENGTH)  # 12-byte nonce for AES-GCM
    encrypted_data = symmetric_key.encrypt(nonce, data, None)
    return bytes_to_base64(nonce + encrypted_data)


def tunnel_decrypt(symmetric_key: AESGCM, encrypted_data: str):
    """ Decrypts data using the symmetric key """
    mixed_data = base64_to_bytes(encrypted_data)

    if len(mixed_data) <= NONCE_LENGTH:
        return None
    nonce = mixed_data[:NONCE_LENGTH]
    encrypted_data = mixed_data[NONCE_LENGTH:]

    try:
       return symmetric_key.decrypt(nonce, encrypted_data, None)
    except Exception as e:
        import logging
        logging.error(f'Error decrypting data: {e}')
        return None


def get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid):
    # try to get config from dag
    try:
        rs = get_dag_leafs(params, encrypted_session_token, encrypted_transmission_key, record_uid)
        # response: "[{\"type\":\"rec\",\"value\":\"Jagbt2dxrft_91FovB5dwg\",\"name\":null}]"
        if not rs:
            return None
        else:
            return rs[0].get('value', '')
    except Exception as e:
        print(f"{bcolors.FAIL}Error getting configuration: {e}{bcolors.ENDC}")
    return None


def get_keeper_tokens(params):
    transmission_key = generate_random_bytes(32)
    server_public_key = rest_api.SERVER_PUBLIC_KEYS[params.rest_context.server_key_id]

    if params.rest_context.server_key_id < 7:
        encrypted_transmission_key = crypto.encrypt_rsa(transmission_key, server_public_key)
    else:
        encrypted_transmission_key = crypto.encrypt_ec(transmission_key, server_public_key)
    encrypted_session_token = crypto.encrypt_aes_v2(
        utils.base64_url_decode(params.session_token), transmission_key)

    return encrypted_session_token, encrypted_transmission_key, transmission_key


def get_config_uid_from_record(params, vault, record_uid):
    record = vault.KeeperRecord.load(params, record_uid)
    if not isinstance(record, vault.TypedRecord):
        raise CommandError('', f"{bcolors.FAIL}Record {record_uid} not found.{bcolors.ENDC}")
    record_type = record.record_type
    if record_type not in "pamMachine pamDatabase pamDirectory pamRemoteBrowser".split():
        raise CommandError('', f"{bcolors.FAIL}This record's type is not supported for tunnels. "
                            f"Tunnels are only supported on pamMachine, pamDatabase, pamDirectory, "
                            f"and pamRemoteBrowser records{bcolors.ENDC}")

    encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
    existing_config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
    return existing_config_uid


def get_gateway_uid_from_record(params, vault, record_uid):
    gateway_uid = ''
    pam_config_uid = get_config_uid_from_record(params, vault, record_uid)
    if pam_config_uid:
        record = vault.KeeperRecord.load(params, pam_config_uid)
        if record:
            field = record.get_typed_field('pamResources')
            value = field.get_default_value(dict)
            if value:
                gateway_uid = value.get('controllerUid', '') or ''

    return gateway_uid


def create_rust_webrtc_settings(params, host, port, target_host, target_port, socks, nonce, ):
    """Create WebRTC settings for the Rust implementation"""
    # Get relay server configuration
    relay_url = 'krelay.' + params.server
    krelay_url = os.getenv('KRELAY_URL')
    if krelay_url:
        relay_url = krelay_url

    response = router_get_relay_access_creds(params=params, expire_sec=60000000)
    if response is None:
        raise CommandError('Tunnel Start', 'Error getting relay access credentials')

    return {
        "turn_only": False,
        "relay_url": relay_url,
        "stun_url": f"stun:{relay_url}:3478",
        "turn_url": f"turn:{relay_url}:3478",
        "turn_username": response.username,
        "turn_password": response.password,
        "conversationType": "tunnel",
        "local_listen_addr": f"{host}:{port}",
        "target_host": target_host,
        "target_port": target_port,
        "socks_mode": socks,
        "callback_token": bytes_to_base64(nonce)
    }


def remove_field(record, field): # type: (vault.TypedRecord, vault.TypedField) -> bool
    # Since TypedRecord.get_typed_field scans both fields[] and custom[]
    # we need corresponding remove field lookup
    fld = next((x for x in record.fields if field.type == x.type and
                (not field.label or
                (x.label and field.label.casefold() == x.label.casefold()))), None)
    if fld is not None:
        record.fields.remove(field)
        return True

    fld = next((x for x in record.custom if field.type == x.type and
                (not field.label or
                (x.label and field.label.casefold() == x.label.casefold()))), None)
    if fld is not None:
        record.custom.remove(field)
        return True

    return False

def resolve_record(params, name):
    record_uid = None
    if name in params.record_cache:
        record_uid = name  # unique record UID
    else:
        # lookup unique folder/record path
        rs = try_resolve_path(params, name)
        if rs is not None:
            folder, name = rs
            if folder is not None and name is not None:
                folder_uid = folder.uid or ''
                if folder_uid in params.subfolder_record_cache:
                    for uid in params.subfolder_record_cache[folder_uid]:
                        r = api.get_record(params, uid)
                        if r.title.lower() == name.lower():
                            record_uid = uid
                            break
    if not record_uid:
        # lookup unique record title
        records = []
        for uid in params.record_cache:
            data_json = params.record_cache[uid].get("data_unencrypted", "{}") or {}
            data = json.loads(data_json)
            if "pamMachine" == str(data.get("type", "")):
                title = data.get('title', '') or ''
                if title.lower() == name.lower():
                    records.append(uid)
        uniq_recs = len(set(records))
        if uniq_recs > 1:
            print(f"{bcolors.FAIL}Multiple PAM Machine records match title '{name}' - "
                  f"specify unique record path/name.{bcolors.ENDC}")
        elif records:
            record_uid = records[0]
    return record_uid

def resolve_folder(params, name):
    folder_uid = ''
    if name:
        # lookup unique folder path
        folder_uid = FolderMixin.resolve_folder(params, name)
        # lookup unique folder name/uid
        if not folder_uid and name != '/':
            folders = []
            for fkey in params.subfolder_cache:
                data_json = params.subfolder_cache[fkey].get('data_unencrypted', '{}') or {}
                data = json.loads(data_json)
                fname = data.get('name', '') or ''
                if fname == name:
                    folders.append(fkey)
            uniq_items = len(set(folders))
            if uniq_items > 1:
                print(f"{bcolors.FAIL}Multiple folders match '{name}' - specify unique "
                        f"folder name or use folder UID (or omit --folder parameter to create "
                        f"PAM User record in same folder as PAM Machine record).{bcolors.ENDC}")
                folders = []
            folder_uid = folders[0] if folders else ''
    return folder_uid

def resolve_pam_config(params, record_uid, pam_config_option):
    # PAM Config lookup - Legacy PAM Machine will have associated PAM Config
    # only if it is set up for rotation - otherwise PAM Config must be provided
    encrypted_session_token, encrypted_transmission_key, transmission_key = get_keeper_tokens(params)
    pamcfg_rec = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
    if not pamcfg_rec and not pam_config_option:
        print(f"{bcolors.FAIL}Unable to find PAM Config associated with record '{record_uid}' "
            "- please provide PAM Config with --configuration|-c option. "
            "(Note: Legacy PAM Machine is linked to PAM Config only if "
            f"the machine is set up for rotation).{bcolors.ENDC}")
        return None

    pamcfg_cmd = ''
    if pam_config_option:
        pam_uids = []
        for uid in params.record_cache:
            if params.record_cache[uid].get('version', 0) == 6:
                r = api.get_record(params, uid)
                if r.record_uid == pam_config_option or r.title.lower() == pam_config_option.lower():
                    pam_uids.append(uid)
        uniq_recs = len(set(pam_uids))
        if uniq_recs > 1:
            print(f"{bcolors.FAIL}Multiple PAM Config records match '{pam_config_option}' - "
                    f"specify unique record UID/Title.{bcolors.ENDC}")
        elif pam_uids:
            pamcfg_cmd = pam_uids[0]
        elif not pamcfg_rec:
            print(f"{bcolors.FAIL}Unable to find PAM Configuration '{pam_config_option}'.{bcolors.ENDC}")

    # PAM Config set on command line overrides the PAM Machine associated PAM Config
    pam_config_uid = pamcfg_cmd or pamcfg_rec or ""
    if pamcfg_cmd and pamcfg_rec and pamcfg_cmd != pamcfg_rec:
        print(f"{bcolors.WARNING}PAM Config associated with record '{record_uid}' "
            "is different from PAM Config set with --configuration|-c option. "
            f"Using the configuration from command line option.{bcolors.ENDC}")

    return pam_config_uid


# Direct WebSocket handler - no stored state
async def connect_websocket_with_fallback(ws_endpoint, headers, ssl_context, tube_registry, timeout, ready_event=None, stop_event=None):
    """
    Connect to WebSocket with backward compatibility for both websockets 15.0.1+ and 11.0.3
    Handles parameter name differences between versions
    
    Args:
        ws_endpoint: WebSocket URL
        headers: Connection headers
        ssl_context: SSL context for secure connections
        tube_registry: PyTubeRegistry instance
        timeout: Maximum time to listen for messages
        ready_event: threading.Event to signal when connected
        stop_event: threading.Event to signal when to close
    """
    # Base connection parameters that work across versions
    base_kwargs = {
        "ping_interval": 20,
        "ping_timeout": 20,
        "close_timeout": 30
    }
    
    if WEBSOCKETS_VERSION == "asyncio":
        # websockets 15.0.1+ uses additional_headers and ssl_context/ssl parameters
        connect_kwargs = {
            **base_kwargs,
            "additional_headers": headers
        }
        
        # Try ssl_context parameter first, fallback to ssl if not supported
        if ssl_context:
            try:
                async with websockets_connect(ws_endpoint, ssl_context=ssl_context, **connect_kwargs) as websocket:
                    logging.debug("WebSocket connection established with ssl_context parameter")
                    # Signal ready event immediately after connection
                    if ready_event:
                        ready_event.set()
                        logging.debug("WebSocket ready event signaled")
                    await handle_websocket_messages(websocket, tube_registry, timeout, stop_event)
                    return
            except TypeError as e:
                if "ssl_context" in str(e):
                    logging.debug("ssl_context parameter not supported, trying with ssl parameter")
                    async with websockets_connect(ws_endpoint, ssl=ssl_context, **connect_kwargs) as websocket:
                        logging.debug("WebSocket connection established with ssl parameter")
                        # Signal ready event immediately after connection
                        if ready_event:
                            ready_event.set()
                            logging.debug("WebSocket ready event signaled")
                        await handle_websocket_messages(websocket, tube_registry, timeout, stop_event)
                        return
                else:
                    raise
        else:
            async with websockets_connect(ws_endpoint, **connect_kwargs) as websocket:
                logging.info("WebSocket connection established")
                # Signal ready event immediately after connection
                if ready_event:
                    ready_event.set()
                    logging.debug("WebSocket ready event signaled")
                await handle_websocket_messages(websocket, tube_registry, timeout, stop_event)
                
    elif WEBSOCKETS_VERSION == "legacy":
        # websockets 11.0.3 uses extra_headers and ssl parameters
        connect_kwargs = {
            **base_kwargs,
            "extra_headers": headers
        }
        
        if ssl_context:
            async with websockets_connect(ws_endpoint, ssl=ssl_context, **connect_kwargs) as websocket:
                logging.info("WebSocket connection established (legacy)")
                # Signal ready event immediately after connection
                if ready_event:
                    ready_event.set()
                    logging.debug("WebSocket ready event signaled")
                await handle_websocket_messages(websocket, tube_registry, timeout, stop_event)
        else:
            async with websockets_connect(ws_endpoint, **connect_kwargs) as websocket:
                logging.info("WebSocket connection established (legacy)")
                # Signal ready event immediately after connection
                if ready_event:
                    ready_event.set()
                    logging.debug("WebSocket ready event signaled")
                await handle_websocket_messages(websocket, tube_registry, timeout, stop_event)
    else:
        raise Exception("No compatible websockets version available")


# NOTE: signal_websocket_ready() function removed - no longer needed.
# Each tunnel's ready_event is now signaled directly in connect_websocket_with_fallback()


async def handle_websocket_responses(params, tube_registry, timeout=60, gateway_uid=None, ready_event=None, stop_event=None):
    """
    Direct WebSocket handler that connects, listens for responses, and routes them to Rust.
    Uses global conversation key store to support multiple concurrent tunnels.
    
    Args:
        params: KeeperParams instance
        tube_registry: PyTubeRegistry instance
        timeout: Maximum time to listen for messages (seconds)
        gateway_uid: Gateway UID (optional, for filtering)
        ready_event: threading.Event to signal when WebSocket is connected
        stop_event: threading.Event to signal when WebSocket should close
    """
    if not WEBSOCKETS_AVAILABLE:
        raise Exception("WebSocket library not available - install with: pip install websockets")

    # Get WebSocket URL for client listening
    connect_ws_endpoint = get_router_ws_url(params)
    ws_endpoint = connect_ws_endpoint + "/api/user/client"

    logging.debug(f"Connecting to WebSocket: {ws_endpoint}")

    # Prepare headers using the same pattern as HTTP
    encrypted_session_token, encrypted_transmission_key, _ = get_keeper_tokens(params)
    headers = {
        'TransmissionKey': bytes_to_base64(encrypted_transmission_key),
        'Authorization': f'KeeperUser {bytes_to_base64(encrypted_session_token)}',
    }

    # Set up SSL context
    ssl_context = None
    if ws_endpoint.startswith('wss://'):
        ssl_context = ssl.create_default_context()
        if not VERIFY_SSL:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
    
    # Connect and handle messages with backward compatibility
    # Handle parameter differences between websockets versions
    await connect_websocket_with_fallback(ws_endpoint, headers, ssl_context, tube_registry, timeout, ready_event, stop_event)


async def handle_websocket_messages(websocket, tube_registry, timeout, stop_event=None):
    """Handle WebSocket message processing
    
    Args:
        websocket: WebSocket connection
        tube_registry: PyTubeRegistry instance
        timeout: Maximum time to listen for messages
        stop_event: threading.Event to signal when to stop listening
    """
        
    # Listen for messages with timeout
    try:
        start_time = time.time()
        while time.time() - start_time < timeout:
            # Check if stop event is set (tunnel closed)
            if stop_event and stop_event.is_set():
                logging.debug("WebSocket stop event received, closing connection")
                break
                
            try:
                # Wait for a message with short timeout to allow checking stop event and overall timeout
                message_text = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                logging.debug(f"WebSocket received: {message_text[:200]}...")

                # Parse response - can be an array or single object
                response_data = json.loads(message_text)
                if isinstance(response_data, list):
                    # Handle an array of responses
                    for response_item in response_data:
                        route_message_to_rust(response_item, tube_registry)
                elif isinstance(response_data, dict):
                    # Handle a single response object
                    route_message_to_rust(response_data, tube_registry)
                else:
                    logging.warning(f"Unexpected WebSocket message format: {type(response_data)}")

            except asyncio.TimeoutError:
                # No message received within 1 second, continue loop to check stop event and overall timeout
                continue
            except ConnectionClosed:
                logging.info("WebSocket connection closed")
                break

    except Exception as e:
        logging.error(f"Error in WebSocket message handling: {e}")
    finally:
        logging.debug("WebSocket handler completed")


def route_message_to_rust(response_item, tube_registry):
    """Route a single message to Rust - decrypt it first using the conversation's key"""
    try:
        conversation_id = response_item.get('conversationId')
        logging.debug(f"Processing WebSocket message for conversation: {conversation_id}")
        
        if not conversation_id:
            logging.debug("No conversationId in response, skipping")
            return
        
        # Get the symmetric key for this conversation from global store
        symmetric_key = get_conversation_key(conversation_id)
        
        if not symmetric_key:
            logging.debug(f"No encryption key found for conversation: {conversation_id}")
            logging.debug(f"Registered conversations: {get_all_conversation_ids()}")
            return
        
        logging.debug(f"Found encryption key for conversation: {conversation_id}")
        
        # Decrypt the message payload
        encrypted_payload = response_item.get('payload', '')
        logging.debug(f"Processing payload for conversation {conversation_id}, payload length: {len(encrypted_payload) if encrypted_payload else 0}")
        
        if encrypted_payload:
            # Parse the payload JSON string first
            try:
                payload_data = json.loads(encrypted_payload)
                logging.debug(f"Successfully parsed payload JSON for {conversation_id}")
                logging.debug(f"Payload is_ok: {payload_data.get('is_ok')}, progress_status: {payload_data.get('progress_status')}")
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse payload as JSON: {e}")
                logging.error(f"Raw payload: {encrypted_payload[:200]}...")
                return
            
            # Handle different types of responses
            if payload_data.get('is_ok') and payload_data.get('data'):
                data_field = payload_data.get('data', '')
                
                # Check if this is a plain text acknowledgment (not encrypted)
                if isinstance(data_field, str) and (
                    "ice candidate" in data_field.lower() or
                    "buffered" in data_field.lower() or
                    "connected" in data_field.lower() or
                    "disconnected" in data_field.lower() or
                    "error" in data_field.lower() or
                    data_field.endswith(conversation_id)  # Plain text responses often end with conversation ID
                ):
                    logging.debug(f"Received plain text acknowledgment: {data_field}")
                    return
                
                # Check if this is just a buffered acknowledgment (these sometimes have invalid base64)
                if "buffered" in data_field.lower():
                    logging.debug(f"Received buffered acknowledgment: {data_field}")
                    return
                    
                logging.debug("Detected SDP answer response - processing...")
                # This looks like an SDP answer response
                encrypted_data = data_field
                if encrypted_data:
                    logging.debug(f"Found encrypted data, length: {len(encrypted_data)}")
                    # Decrypt the SDP answer
                    try:
                        decrypted_data = tunnel_decrypt(symmetric_key, encrypted_data)
                    except Exception as e:
                        # If decryption fails, it might be a plain text response
                        logging.debug(f"Decryption failed, might be plain text: {e}")
                        logging.debug(f"Data content: {encrypted_data[:100]}...")
                        return
                    if decrypted_data:
                        data_text = bytes_to_string(decrypted_data).replace("'", '"')
                        logging.debug(f"Successfully decrypted data for {conversation_id}, length: {len(data_text)}")
                        
                        # Check if this is a simple JSON-encoded acknowledgment string
                        try:
                            parsed_text = json.loads(data_text)
                            if isinstance(parsed_text, str) and parsed_text.lower() in [
                                "connected", "disconnected", "error", "success", "ok", "acknowledged"
                            ]:
                                logging.debug(f"Received JSON-encoded acknowledgment: {parsed_text}")
                                return
                        except (json.JSONDecodeError, TypeError):
                            pass  # Not a simple JSON string, continue with normal processing
                        
                        data_json = json.loads(data_text)
                        if "answer" in data_json:
                            answer_sdp = data_json.get('answer')

                            if answer_sdp:
                                logging.debug(f"Found SDP answer, sending to Rust for conversation: {conversation_id}")
                                # Send decrypted SDP answer to Rust

                                # Try to find tube ID - gateway may have converted URL-safe base64 to standard
                                tube_id = tube_registry.tube_id_from_connection_id(conversation_id)
                                if not tube_id:
                                    # Try URL-safe version (convert + to -, / to _, remove =)
                                    url_safe_conversation_id = conversation_id.replace('+', '-').replace('/', '_').rstrip('=')
                                    tube_id = tube_registry.tube_id_from_connection_id(url_safe_conversation_id)
                                    if tube_id:
                                        logging.debug(f"Found tube using URL-safe conversion: {url_safe_conversation_id}")
                                
                                if not tube_id:
                                    logging.error(f"No tube ID found for conversation: {conversation_id} (also tried URL-safe version)")
                                    return

                                tube_registry.set_remote_description(tube_id, answer_sdp, is_answer=True)
                                logging.debug("Connection state: SDP answer received, connecting...")

                                # Send any buffered local ICE candidates now that we have the answer
                                session = get_tunnel_session(tube_id)
                                if session and session.buffered_ice_candidates:
                                    logging.debug(f"Sending {len(session.buffered_ice_candidates)} buffered ICE candidates after answer")
                                    # Need to get the signal handler to send candidates
                                    # Since we're in the routing function, we need to find the handler
                                    #  is stored in the session for this purpose
                                    if hasattr(session, 'signal_handler') and session.signal_handler:
                                        for candidate in session.buffered_ice_candidates:
                                            session.signal_handler._send_ice_candidate_immediately(candidate, tube_id)
                                        session.buffered_ice_candidates.clear()
                                    else:
                                        logging.warning(f"No signal handler found for tube {tube_id} to send buffered candidates")
                        elif "offer" in data_json or (data_json.get("type") == "offer"):
                            # Gateway is sending us an ICE restart offer
                            offer_sdp = data_json.get('sdp') or data_json.get('offer')

                            if offer_sdp:
                                logging.info(f"Received ICE restart offer from Gateway for conversation: {conversation_id}")

                                tube_id = tube_registry.tube_id_from_connection_id(conversation_id)
                                if not tube_id:
                                    logging.error(f"No tube ID for conversation: {conversation_id}")
                                    return

                                # Get session to check if trickle ICE is enabled
                                session = get_tunnel_session(tube_id)
                                if not session:
                                    logging.error(f"No tunnel session found for tube {tube_id}")
                                    return

                                # ICE restart requires trickle ICE mode - check via signal_handler
                                if hasattr(session, 'signal_handler') and session.signal_handler:
                                    if not session.signal_handler.trickle_ice:
                                        logging.warning(f"ICE restart offer ignored - trickle ICE not enabled for tube {tube_id}")
                                        return
                                else:
                                    logging.warning(f"Cannot verify trickle ICE status for tube {tube_id} - no signal handler")
                                    return

                                logging.debug("Connection state: ICE restart offer received from Gateway...")

                                try:
                                    # Apply the offer from Gateway
                                    tube_registry.set_remote_description(tube_id, offer_sdp, is_answer=False)
                                    logging.debug(f"Applied ICE restart offer for tube {tube_id}")

                                    # Generate answer
                                    answer_sdp = tube_registry.create_answer(tube_id)

                                    if answer_sdp:
                                        logging.info(f"Generated ICE restart answer for tube {tube_id}")

                                        # Get session to access symmetric key and other info
                                        session = get_tunnel_session(tube_id)
                                        if not session:
                                            logging.error(f"No tunnel session found for tube {tube_id}")
                                            return

                                        # Prepare answer payload
                                        answer_payload = {
                                            "type": "answer",
                                            "sdp": answer_sdp,
                                            "ice_restart": True
                                        }

                                        # Encrypt the answer
                                        string_data = json.dumps(answer_payload)
                                        bytes_data = string_to_bytes(string_data)
                                        encrypted_data = tunnel_encrypt(session.symmetric_key, bytes_data)

                                        # Get signal handler from session
                                        if hasattr(session, 'signal_handler') and session.signal_handler:
                                            signal_handler = session.signal_handler

                                            # Send answer back to Gateway via HTTP POST
                                            logging.debug(f"Sending ICE restart answer to Gateway for tube {tube_id}")

                                            router_response = router_send_action_to_gateway(
                                                params=signal_handler.params,
                                                destination_gateway_uid_str=session.gateway_uid,
                                                gateway_action=GatewayActionWebRTCSession(
                                                    conversation_id=session.conversation_id,
                                                    inputs={
                                                        "recordUid": signal_handler.record_uid,
                                                        'kind': 'ice_restart_answer',
                                                        'base64Nonce': signal_handler.base64_nonce,
                                                        'conversationType': 'tunnel',
                                                        "data": encrypted_data,
                                                        "trickleICE": signal_handler.trickle_ice,
                                                    }
                                                ),
                                                message_type=pam_pb2.CMT_CONNECT,
                                                is_streaming=signal_handler.trickle_ice,  # Streaming only for trickle ICE
                                                gateway_timeout=GATEWAY_TIMEOUT
                                            )

                                            logging.info(f"ICE restart answer sent for tube {tube_id}")
                                            print(f"{bcolors.OKGREEN}ICE restart answer sent successfully{bcolors.ENDC}")
                                        else:
                                            logging.error(f"No signal handler found for tube {tube_id} to send answer")
                                    else:
                                        logging.error(f"Failed to generate ICE restart answer for tube {tube_id}")
                                        print(f"{bcolors.FAIL}Failed to generate ICE restart answer{bcolors.ENDC}")

                                except Exception as e:
                                    logging.error(f"Error handling ICE restart offer for tube {tube_id}: {e}")
                                    print(f"{bcolors.FAIL}Error processing ICE restart offer: {e}{bcolors.ENDC}")
                            else:
                                logging.warning(f"Received offer message without SDP data for conversation: {conversation_id}")
                        elif "candidates" in data_json:
                            # Try to find tube ID - gateway may have converted URL-safe base64 to standard
                            tube_id = tube_registry.tube_id_from_connection_id(conversation_id)
                            if not tube_id:
                                # Try URL-safe version (convert + to -, / to _, remove =)
                                url_safe_conversation_id = conversation_id.replace('+', '-').replace('/', '_').rstrip('=')
                                tube_id = tube_registry.tube_id_from_connection_id(url_safe_conversation_id)
                                if tube_id:
                                    logging.debug(f"Found tube using URL-safe conversion: {url_safe_conversation_id}")
                            
                            if not tube_id:
                                logging.error(f"No tube ID found for conversation: {conversation_id} (also tried URL-safe version)")
                                return
                            # Handle ICE candidates from gateway (always array format)
                            candidates_list = data_json.get('candidates', [])
                            candidate_count = len(candidates_list)
                            logging.debug(f"Received {candidate_count} ICE candidates from gateway for {conversation_id}")
                            
                            # Gateway sends candidates in consistent format, pass them directly to Rust
                            for candidate in candidates_list:
                                logging.debug(f"Forwarding candidate to Rust: {candidate[:100]}...")  # Log first 100 chars
                                tube_registry.add_ice_candidate(tube_id, candidate)

                            logging.debug(f"Connection state: received {candidate_count} ICE candidate(s)...")
                        else:
                            logging.warning(f"No known field found in decrypted data {decrypted_data}")
                    else:
                        logging.error("Failed to decrypt data")
                else:
                    logging.warning("No 'data' field found in response")
            
            # Handle error responses
            elif (payload_data.get('errors') is not None and
                  payload_data.get('errors') != [] and
                  payload_data.get('errors') != ['']):
                errors = payload_data.get('errors', [''])
                logging.error(f"Gateway returned errors for {conversation_id}: {errors}")

            elif payload_data.get('data', '') == '':
                logging.debug("Empty data field an acknowledgment, no action needed")
            elif payload_data.get('data') and "ice candidate added" in payload_data.get('data').lower():
                logging.debug("Received ice candidate added")
            else:
                logging.warning(f"Unhandled payload type for {conversation_id}: {payload_data}")
        else:
            logging.warning(f"No encrypted payload in message for conversation: {conversation_id}")
            
    except Exception as e:
        logging.error(f"Error routing message to Rust: {e}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")


def start_websocket_listener(params, tube_registry, timeout=60, gateway_uid=None, tunnel_session=None):
    """
    Start WebSocket listener in a background thread.
    
    Creates a DEDICATED WebSocket for the provided tunnel_session.
    Each tunnel gets its own independent WebSocket connection.
    
    Args:
        params: KeeperParams instance
        tube_registry: PyTubeRegistry instance
        timeout: Maximum time to listen for messages (seconds)
        gateway_uid: Gateway UID (optional)
        tunnel_session: TunnelSession instance for dedicated WebSocket (required)
    
    Returns:
        (thread, is_reused) tuple - is_reused is always False (each tunnel gets its own WebSocket)
    """
    if tunnel_session is None:
        raise ValueError("tunnel_session is required for dedicated WebSocket architecture")
    
    logging.debug(f"Creating dedicated WebSocket for tunnel {tunnel_session.tube_id}")
    
    # Create per-tunnel events
    tunnel_session.websocket_ready_event = threading.Event()
    tunnel_session.websocket_stop_event = threading.Event()
    
    # Start a dedicated WebSocket listener thread for this tunnel
    def run_dedicated_websocket():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(handle_websocket_responses(
                params, tube_registry, timeout, gateway_uid,
                ready_event=tunnel_session.websocket_ready_event,
                stop_event=tunnel_session.websocket_stop_event
            ))
        except Exception as e:
            logging.error(f"Dedicated WebSocket listener error for tunnel {tunnel_session.tube_id}: {e}")
        finally:
            loop.close()
            logging.debug(f"Dedicated WebSocket closed for tunnel {tunnel_session.tube_id}")
    
    tunnel_session.websocket_thread = threading.Thread(
        target=run_dedicated_websocket,
        daemon=True,
        name=f"WebSocket-{tunnel_session.tube_id[:8]}"
    )
    tunnel_session.websocket_thread.start()
    logging.debug(f"Dedicated WebSocket listener started for tunnel {tunnel_session.tube_id}")
    return (tunnel_session.websocket_thread, False)  # Never reused - each tunnel gets its own



# Simplified tunnel entrance for compatibility with existing code
class SimpleRustTunnelEntrance:
    """Simple compatibility wrapper for Rust-based tunnels"""

    def __init__(self, conversation_id, host, port, record_uid):
        self.conversation_id = conversation_id
        self.host = host
        self.port = port
        self.record_uid = record_uid

        # Create a compatibility object that mimics the old WebRTCConnection
        self.pc = SimpleRustPCCompat(conversation_id, record_uid)


# Simple compatibility object to replace the old WebRTCConnection interface
class SimpleRustPCCompat:
    """Simple compatibility wrapper to mimic old WebRTCConnection interface"""

    def __init__(self, conversation_id, record_uid):
        self.endpoint_name = conversation_id
        self.record_uid = record_uid
        self.conversation_id = conversation_id


# Callback handler class for WebRTC signals
class TunnelSignalHandler:
    """
    Signal handler for WebRTC tunnel events with HTTP sending and WebSocket receiving.
    
    Features immediate ICE candidate sending:
    - Sends ICE candidates immediately as they arrive from Rust
    - Always sends candidates in {"candidates": [candidate]} array format for gateway consistency
    - Maintains consistent protocol with gateway expectations
    """

    def __init__(self, params, record_uid, gateway_uid, symmetric_key, base64_nonce, conversation_id, tube_registry, tube_id=None, trickle_ice=False, websocket_router=None):
        self.params = params
        self.record_uid = record_uid
        self.gateway_uid = gateway_uid
        self.symmetric_key = symmetric_key
        self.base64_nonce = base64_nonce
        self.conversation_id = conversation_id
        self.tube_registry = tube_registry
        self.tube_id = tube_id
        self.trickle_ice = trickle_ice
        self.connection_success_shown = False  # Track if we've shown success messages
        self.host = None  # Will be set later when the socket is ready
        self.port = None
        self.websocket_router = websocket_router  # For key cleanup
        self.offer_sent = False  # Track if offer has been sent to gateway
        self.buffered_ice_candidates = []  # Buffer ICE candidates until offer is sent
        
        # WebSocket routing is handled automatically - no setup needed
        if trickle_ice and not WEBSOCKETS_AVAILABLE:
            raise Exception("Trickle ICE requires WebSocket support - install with: pip install websockets")

    def signal_from_rust(self, response: dict):
        """Signal callback to handle Rust events and gateway communication"""
        signal_kind = response.get('kind', '')
        tube_id = response.get('tube_id', '')
        data = response.get('data', '')
        conversation_id_from_signal = response.get('conversation_id', '')

        logging.debug(f"Received signal: kind={signal_kind}, tube_id={tube_id}, conversation_id={conversation_id_from_signal}")

        # Get the tunnel session for this tube
        session = get_tunnel_session(tube_id) if tube_id else None
        if session:
            session.update_activity()

        # Handle local connection state changes
        if signal_kind == 'connection_state_changed':
            new_state = data.lower()
            logging.debug(f"Connection state changed for tube {tube_id}: {new_state}")

            # Detailed logging for specific states
            if new_state == 'disconnected':
                logging.warning(f"Connection disconnected for tube {tube_id} - ICE restart may be attempted by Rust")

            elif new_state == 'failed':
                logging.error(f"Connection failed for tube {tube_id} - ICE restart may be attempted by Rust")

            elif new_state == 'connected':
                logging.debug(f"Connection established/restored for tube {tube_id}")

                if not self.connection_success_shown:
                    self.connection_success_shown = True

                    # Get tunnel session for record details
                    if session:
                        print(f"\n{bcolors.OKGREEN}Connection established successfully.{bcolors.ENDC}")

                        # Display record title if available
                        if session.record_title:
                            print(f"{bcolors.OKBLUE}Record:{bcolors.ENDC} {session.record_title}")

                        # Display remote target
                        if session.target_host and session.target_port:
                            print(f"{bcolors.OKBLUE}Remote:{bcolors.ENDC} {session.target_host}:{session.target_port}")

                        # Display local listening address
                        if session.host and session.port:
                            print(f"{bcolors.OKBLUE}Local:{bcolors.ENDC} {session.host}:{session.port}")

                        # Display conversation ID
                        if session.conversation_id:
                            print(f"{bcolors.OKBLUE}Conversation ID:{bcolors.ENDC} {session.conversation_id}")

                        print()  # Empty line for readability

                    # Flush any buffered ICE candidates now that we're connected
                    if session and session.buffered_ice_candidates:
                        logging.debug(f"Flushing {len(session.buffered_ice_candidates)} buffered ICE candidates")
                        for candidate in session.buffered_ice_candidates:
                            self._send_ice_candidate_immediately(candidate, tube_id)
                        session.buffered_ice_candidates.clear()

            elif new_state == "connecting":
                logging.debug(f"Connection in progress for tube {tube_id}")

            elif new_state == "closed":
                logging.info(f"Connection closed for tube {tube_id}")

            else:
                logging.debug(f"Connection state for tube {tube_id}: {new_state}")

            return  # Local event, no gateway response needed

        elif signal_kind == 'channel_closed':
            conversation_id_from_signal = conversation_id_from_signal or self.conversation_id
            logging.info(f"Received 'channel_closed' signal for conversation '{conversation_id_from_signal}' of tube '{tube_id}'.")

            # Check if the tunnel session exists and is already closed
            session = get_tunnel_session(tube_id) if tube_id else None
            if session:
                # For now, we don't have a tunnel_closed flag in TunnelSession like the gateway,
                # but we could add it if needed for preventing redundant handling
                pass

            try:
                data_json = json.loads(data) if data else {}
                
                # Try to get structured close reason first
                close_reason = None
                if "close_reason" in data_json:
                    reason_code = data_json["close_reason"].get("code")
                    if reason_code is not None:
                        close_reason = CloseConnectionReason.from_code(reason_code)
                        logging.info(f"  Structured close reason: {close_reason.name} (code: {reason_code})")
                
                # Fallback to old string-based outcome for backward compatibility
                if close_reason is None:
                    outcome = data_json.get("outcome", "unknown")
                    close_reason = CloseConnectionReason.from_legacy_outcome(outcome)
                    logging.info(f"  Legacy outcome: '{outcome}' -> {close_reason.name}")
                
                # Handle based on reason type
                if close_reason.is_critical():
                    logging.error(f"Critical failure in tunnel '{tube_id}': {close_reason.name}. Stopping session immediately.")
                    print(f"{bcolors.FAIL}Tunnel closed due to critical failure: {close_reason.name}{bcolors.ENDC}")
                    
                elif close_reason.is_user_initiated():
                    logging.info(f"User-initiated closure of tunnel '{tube_id}': {close_reason.name}.")
                    print(f"{bcolors.OKBLUE}Tunnel closed: {close_reason.name}{bcolors.ENDC}")
                    
                elif close_reason.is_retryable():
                    logging.warning(f"Retryable failure in tunnel '{tube_id}': {close_reason.name}.")
                    print(f"{bcolors.WARNING}Tunnel closed with retryable error: {close_reason.name}{bcolors.ENDC}")
                    
                else:
                    logging.info(f"Tunnel '{tube_id}' closed with reason: {close_reason.name}.")
                    print(f"{bcolors.OKBLUE}Tunnel closed: {close_reason.name}{bcolors.ENDC}")

            except (json.JSONDecodeError, KeyError) as e:
                logging.error(f"Failed to parse close reason: {e}. Defaulting to critical handling.")
                print(f"{bcolors.FAIL}Tunnel closed due to unknown error{bcolors.ENDC}")

            # Clean up the tunnel session when channel closes
            if tube_id:
                # Get session before unregistering to access signal handler
                session = get_tunnel_session(tube_id)
                if session:
                    # Cleanup signal handler (conversation keys)
                    if hasattr(session, 'signal_handler') and session.signal_handler:
                        session.signal_handler.cleanup()
                        logging.debug(f"Cleaned up conversation keys for closed tunnel {tube_id}")
                    
                    # Stop dedicated WebSocket if this tunnel has one
                    if session.websocket_stop_event and session.websocket_thread:
                        logging.debug(f"Stopping dedicated WebSocket for tunnel {tube_id}")
                        session.websocket_stop_event.set()  # Signal WebSocket to close
                        # Give it a moment to close gracefully
                        session.websocket_thread.join(timeout=2.0)
                        if session.websocket_thread.is_alive():
                            logging.warning(f"Dedicated WebSocket for tunnel {tube_id} did not close in time")
                        else:
                            logging.debug(f"Dedicated WebSocket closed for tunnel {tube_id}")
                
                unregister_tunnel_session(tube_id)
            return  # Local event, no gateway response needed

        elif signal_kind == 'error':
            error_msg = data if data else 'Unknown error'
            logging.error(f"Tunnel error for {tube_id}: {error_msg}")
            print(f"{bcolors.FAIL}Tunnel error: {error_msg}{bcolors.ENDC}")
            # Clean up on error as well
            if tube_id and data.lower() in ["failed", "closed"]:
                # Get session before unregistering to access signal handler
                session = get_tunnel_session(tube_id)
                if session:
                    # Cleanup signal handler (conversation keys)
                    if hasattr(session, 'signal_handler') and session.signal_handler:
                        session.signal_handler.cleanup()
                        logging.debug(f"Cleaned up conversation keys for failed tunnel {tube_id}")
                    
                    # Stop dedicated WebSocket if this tunnel has one
                    if session.websocket_stop_event and session.websocket_thread:
                        logging.debug(f"Stopping dedicated WebSocket for failed tunnel {tube_id}")
                        session.websocket_stop_event.set()  # Signal WebSocket to close
                        # Give it a moment to close gracefully
                        session.websocket_thread.join(timeout=2.0)
                        if session.websocket_thread.is_alive():
                            logging.warning(f"Dedicated WebSocket for tunnel {tube_id} did not close in time")
                        else:
                            logging.debug(f"Dedicated WebSocket closed for failed tunnel {tube_id}")
                
                unregister_tunnel_session(tube_id)
            return  # Local event, no gateway response needed

        # Handle ICE candidates - use session to check if offer is sent AND WebSocket is ready
        elif signal_kind == 'icecandidate':
            logging.debug(f"Received ICE candidate for tube {tube_id}")

            # Check if we should buffer this candidate
            should_buffer = False
            if session:
                # Buffer if offer not sent yet
                if not session.offer_sent:
                    should_buffer = True
                    logging.debug(f"Buffering ICE candidate - offer not yet sent for tube {tube_id}")
                # Also buffer if WebSocket is not ready yet (even if offer was sent)
                elif session.websocket_ready_event and not session.websocket_ready_event.is_set():
                    should_buffer = True
                    logging.debug(f"Buffering ICE candidate - WebSocket not ready yet for tube {tube_id}")

            if should_buffer:
                session.buffered_ice_candidates.append(data)
            else:
                # Send the candidate immediately (but still in array format for gateway consistency)
                self._send_ice_candidate_immediately(data, tube_id)
            return
        elif signal_kind == 'ice_restart_request':
            logging.info(f"Received ICE restart request for tube {tube_id}")

            # ICE restart requires trickle ICE mode
            if not self.trickle_ice:
                logging.warning(f"ICE restart request ignored - trickle ICE not enabled for tube {tube_id}")
                return

            try:
                # Execute ICE restart through your tube registry
                restart_sdp = self.tube_registry.restart_ice(tube_id)

                if restart_sdp:
                    logging.info(f"ICE restart successful for tube {tube_id}")
                    self._send_restart_offer(restart_sdp, tube_id)
                else:
                    logging.error(f"ICE restart failed for tube {tube_id}")

            except Exception as e:
                logging.error(f"ICE restart error for tube {tube_id}: {e}")

            return  # Local event, no gateway response needed

        elif signal_kind == 'ice_restart_offer':
            # Rust initiated ICE restart and generated offer (e.g., network change detected)
            # We need to send this offer to Gateway and get an answer
            logging.info(f"Received ice_restart_offer from Rust for tube {tube_id}")

            # ICE restart requires trickle ICE mode
            if not self.trickle_ice:
                logging.warning(f"ICE restart offer ignored - trickle ICE not enabled for tube {tube_id}")
                return

            offer_sdp = data  # Already base64 encoded from Rust

            if not offer_sdp:
                logging.error(f"Empty ICE restart offer received for tube {tube_id}")
                return

            # Send the offer to Gateway
            self._send_restart_offer(offer_sdp, tube_id)
            return

        # Unknown signal type
        else:
            logging.debug(f"Unknown signal type: {signal_kind}")
    
    def _send_ice_candidate_immediately(self, candidate_data, tube_id=None):
        """Send a single ICE candidate immediately via HTTP POST to /send_controller_message
        
        Always sends candidates as {"candidates": [candidate]} array format for gateway consistency.
        This matches the gateway expectation: action_inputs['data'].get('candidates')
        """
        try:
            # Always use array format for consistency with gateway expectations
            # Gateway expects: action_inputs['data'].get('candidates') and iterates: for candidate in ice_candidates
            candidates_payload = {"candidates": [candidate_data]}
            string_data = json.dumps(candidates_payload)
            bytes_data = string_to_bytes(string_data)
            encrypted_data = tunnel_encrypt(self.symmetric_key, bytes_data)

            logging.debug(f"Sending ICE candidate to gateway immediately")

            # Send an ICE candidate via HTTP POST with streamResponse=True
            router_response = router_send_action_to_gateway(
                params=self.params,
                destination_gateway_uid_str=self.gateway_uid,
                gateway_action=GatewayActionWebRTCSession(
                    conversation_id=self.conversation_id,
                    inputs={
                        "recordUid": self.record_uid,
                        'kind': 'icecandidate',
                        'base64Nonce': self.base64_nonce,
                        'conversationType': 'tunnel',
                        "data": encrypted_data,
                        "trickleICE": self.trickle_ice,
                    }
                ),
                message_type=pam_pb2.CMT_CONNECT,
                is_streaming=self.trickle_ice,  # Streaming only for trickle ICE
                gateway_timeout=GATEWAY_TIMEOUT
            )
            
            if self.trickle_ice:
                logging.debug("ICE candidate sent via HTTP POST - response expected via WebSocket")
            else:
                logging.debug("ICE candidate sent via HTTP POST")
                
        except Exception as e:
            # Check if this is a gateway offline error (RRC_CONTROLLER_DOWN) or bad state error (RRC_BAD_STATE)
            error_str = str(e)
            is_gateway_offline = 'RRC_CONTROLLER_DOWN' in error_str
            is_bad_state = 'RRC_BAD_STATE' in error_str

            if is_gateway_offline:
                # Gateway is offline - this is expected if gateway is down, log at debug level
                logging.debug(f"Gateway offline when sending ICE candidate: {e}")
            elif is_bad_state:
                # Bad state - transient during WebSocket startup, log at debug level
                logging.debug(f"Bad state when sending ICE candidate: {e}")
            else:
                # Other errors - log at error level and print to console
                logging.error(f"Failed to send ICE candidate via HTTP: {e}")
                print(f"{bcolors.WARNING}Failed to send ICE candidate: {e}{bcolors.ENDC}")

    def _send_restart_offer(self, restart_sdp, tube_id):
        """Send ICE restart offer via HTTP POST to /send_controller_message with encryption

        Similar to _send_ice_candidate_immediately but sends an offer instead of candidates.
        """
        try:
            # Format as offer payload for gateway
            offer_payload = {
                "type": "offer",
                "sdp": restart_sdp,
                "ice_restart": True  # Flag to indicate this is an ICE restart offer
            }
            string_data = json.dumps(offer_payload)
            bytes_data = string_to_bytes(string_data)
            encrypted_data = tunnel_encrypt(self.symmetric_key, bytes_data)

            logging.debug(f"Sending ICE restart offer to gateway for tube {tube_id}")

            # Send ICE restart offer via HTTP POST with streamResponse=True
            router_response = router_send_action_to_gateway(
                params=self.params,
                destination_gateway_uid_str=self.gateway_uid,
                gateway_action=GatewayActionWebRTCSession(
                    conversation_id=self.conversation_id,
                    inputs={
                        "recordUid": self.record_uid,
                        'kind': 'ice_restart_offer',  # New kind for ICE restart
                        'base64Nonce': self.base64_nonce,
                        'conversationType': 'tunnel',
                        "data": encrypted_data,
                        "trickleICE": self.trickle_ice,
                    }
                ),
                message_type=pam_pb2.CMT_CONNECT,
                is_streaming=self.trickle_ice,  # Streaming only for trickle ICE
                gateway_timeout=GATEWAY_TIMEOUT
            )

            if self.trickle_ice:
                logging.info(f"ICE restart offer sent via HTTP POST for tube {tube_id} - response expected via WebSocket")
            else:
                logging.info(f"ICE restart offer sent via HTTP POST for tube {tube_id}")
            print(f"{bcolors.OKGREEN}ICE restart offer sent successfully{bcolors.ENDC}")

        except Exception as e:
            # Check if this is a gateway offline error (RRC_CONTROLLER_DOWN) or bad state error (RRC_BAD_STATE)
            error_str = str(e)
            is_gateway_offline = 'RRC_CONTROLLER_DOWN' in error_str
            is_bad_state = 'RRC_BAD_STATE' in error_str

            if is_gateway_offline:
                # Gateway is offline - this is expected if gateway is down, log at debug level
                logging.debug(f"Gateway offline when sending ICE restart offer for tube {tube_id}: {e}")
            elif is_bad_state:
                # Bad state - transient during WebSocket startup, log at debug level
                logging.debug(f"Bad state when sending ICE restart offer for tube {tube_id}: {e}")
            else:
                # Other errors - log at error level and print to console
                logging.error(f"Failed to send ICE restart offer for tube {tube_id}: {e}")
                print(f"{bcolors.FAIL}Failed to send ICE restart offer: {e}{bcolors.ENDC}")

    def cleanup(self):
        """Cleanup resources"""
        # Close the tube in Rust registry if it exists
        if self.tube_id and self.tube_registry:
            try:
                logging.debug(f"Closing tube {self.tube_id} in cleanup")
                self.tube_registry.close_tube(self.tube_id, reason=CloseConnectionReasons.Error)
                logging.debug(f"Tube {self.tube_id} closed successfully")
            except Exception as e:
                # Tube might not exist yet or already closed
                logging.debug(f"Could not close tube {self.tube_id} during cleanup: {e}")

        # Unregister conversation key from global store
        if self.conversation_id:
            unregister_conversation_key(self.conversation_id)
            # Also unregister the standard base64 version
            standard_conversation_id = self.conversation_id.replace('-', '+').replace('_', '/')
            padding_needed = (4 - len(standard_conversation_id) % 4) % 4
            if padding_needed:
                standard_conversation_id += '=' * padding_needed
            if standard_conversation_id != self.conversation_id:
                unregister_conversation_key(standard_conversation_id)
        logging.debug("TunnelSignalHandler cleaned up")

def start_rust_tunnel(params, record_uid, gateway_uid, host, port,
                      seed, target_host, target_port, socks, trickle_ice=True, record_title=None, allow_supply_host=False):
    """
    Start a tunnel using Rust WebRTC with trickle ICE via HTTP POST and WebSocket responses.
    
    This function uses a global WebSocket architecture that supports multiple concurrent tunnels.
    Messages are routed to Rust based on conversationId using a shared global key store.
    The endpoint table is displayed ONLY when both the local socket AND WebRTC connection are ready.
    
    Architecture:
        - Shared WebSocket listener handles multiple tunnels simultaneously
        - Global conversation key store: conversationId → symmetric_key mapping
        - Message flow: WebSocket → decrypt with a conversation key → send to Rust
        - Signal handler shows endpoint table only when fully connected
        - Multiple tunnels can run concurrently
    
    Display flow:
        1. "Establishing a tunnel with trickle ICE between Commander and Gateway..."
        2. "Creating WebRTC offer and setting up local listener..."
        4. "Sending offer to gateway..."
        5. "Offer sent to gateway"
        6. "Connection state: gathering candidates..."
        7. Real-time state updates:
           - "sending ICE candidates..."
           - "SDP answer received, connecting..."
           - "exchanging ICE candidates..."
           - "connected"
        8. Shows endpoint table with listening address (ONLY when fully ready)
        9. "Tunnel is ready for traffic"
    
    Multi-tunnel Support:
        - Each tunnel gets its own conversation ID and encryption key
        - Single shared WebSocket connection handles all tunnel communications
        - Automatic key registration/cleanup per tunnel
        - Concurrent tunnels work independently
    
    Usage:
        # Start tunnel (shows endpoint table only when truly ready)
        result = start_rust_tunnel(params, record_uid, gateway_uid, host, port, seed, target_host, target_port, socks)
        
        If result["success"]:
            # Global WebSocket router automatically handles all responses
            # Endpoint table shown only when both socket and WebRTC are ready
            
            # Multiple tunnels can be started concurrently
            result2 = start_rust_tunnel(params, record_uid2, gateway_uid2, host2, port2, ...)
    
    Returns:
        dict: {
            "success": bool,
            "tube_id": str,
            "entrance": SimpleRustTunnelEntrance,
            "signal_handler": TunnelSignalHandler,
            "websocket_thread": Thread,
            "conversation_id": str,
            "tube_registry": PyTubeRegistry,
            "status": "connecting"
        }
    """
    logging.debug("Establishing tunnel with trickle ICE between Commander and Gateway. Please wait...")

    try:
        # Symmetric key generation for tunnel encryption
        if isinstance(seed, str):
            seed = base64_to_bytes(seed)
        # Generate 128-bit (16-byte) random nonce
        nonce = os.urandom(MAIN_NONCE_LENGTH)
        # Derive the encryption key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SYMMETRIC_KEY_LENGTH,  # 256-bit key
            salt=nonce,
            info=b"KEEPER_TUNNEL_ENCRYPT_AES_GCM_128",
            backend=default_backend()
        ).derive(seed)
        symmetric_key = AESGCM(hkdf)

        # Get tube registry and set server mode
        tube_registry = get_or_create_tube_registry(params)
        if not tube_registry:
            return {"success": False, "error": "Rust WebRTC library not available"}

        tube_registry.set_server_mode(True)

        conversation_id_original = GatewayAction.generate_conversation_id()
        conversation_id_bytes = url_safe_str_to_bytes(conversation_id_original)
        conversation_id = base64.b64encode(conversation_id_bytes).decode('utf-8')

        base64_nonce = bytes_to_base64(nonce)

        # Create WebRTC settings for the Rust implementation
        webrtc_settings = create_rust_webrtc_settings(
            params, host, port, target_host, target_port, socks, nonce
        )

        # Register the encryption key in the global conversation store
        # IMPORTANT: Gateway may convert URL-safe base64 to standard base64 and add padding
        # Register both versions to handle the conversion:
        # - URL-safe: uses - and _ (e.g., "2srIxfCAsQAEWGmH-52yzw")
        # - Standard: uses + and / with = padding (e.g., "2srIxfCAsQAEWGmH+52yzw==")
        register_conversation_key(conversation_id_original, symmetric_key)
        
        # Also register the standard base64 version that gateway might return
        # Convert URL-safe base64 to standard base64
        standard_conversation_id = conversation_id_original.replace('-', '+').replace('_', '/')
        # Add padding if needed
        padding_needed = (4 - len(standard_conversation_id) % 4) % 4
        if padding_needed:
            standard_conversation_id += '=' * padding_needed
        if standard_conversation_id != conversation_id_original:
            register_conversation_key(standard_conversation_id, symmetric_key)
            logging.debug(f"Registered both URL-safe and standard base64 conversation IDs")

        # Create a temporary tunnel session BEFORE creating the tube so ICE candidates can be buffered immediately
        import uuid
        temp_tube_id = str(uuid.uuid4())
        
        # Pre-create tunnel session with temporary ID to buffer early ICE candidates
        tunnel_session = TunnelSession(
            tube_id=temp_tube_id,
            conversation_id=conversation_id_original,  # Use original, not base64 encoded
            gateway_uid=gateway_uid,
            symmetric_key=symmetric_key,
            offer_sent=False,
            host=host,
            port=port,
            record_title=record_title,
            record_uid=record_uid,
            target_host=target_host,
            target_port=target_port
        )
        
        # Register the temporary session so ICE candidates can be buffered immediately
        register_tunnel_session(temp_tube_id, tunnel_session)
        
        # Create the tube to get the WebRTC offer with trickle ICE
        logging.debug("Creating WebRTC offer with trickle ICE gathering")
        
        # Create signal handler for Rust events
        signal_handler = TunnelSignalHandler(
            params=params,
            record_uid=record_uid,
            gateway_uid=gateway_uid,
            symmetric_key=symmetric_key,
            base64_nonce=base64_nonce,
            conversation_id=conversation_id_original,  # Use original, not base64 encoded
            tube_registry=tube_registry,
            tube_id=temp_tube_id,  # Use temp ID initially
            trickle_ice=trickle_ice,
        )

        # Store signal handler reference so we can send buffered candidates later
        tunnel_session.signal_handler = signal_handler
        
        logging.debug(f"{bcolors.OKBLUE}Creating WebRTC offer and setting up local listener...{bcolors.ENDC}")
        
        offer = tube_registry.create_tube(
            conversation_id=conversation_id_original,  # Use original, not base64 encoded
            settings=webrtc_settings,
            trickle_ice=trickle_ice,  # Use trickle ICE for real-time candidate exchange
            callback_token=webrtc_settings["callback_token"],
            ksm_config="",
            krelay_server="krelay." + params.server,
            client_version="Commander-Python",
            offer=None,  # Let Rust create the offer
            signal_callback=signal_handler.signal_from_rust
        )

        if not offer or 'tube_id' not in offer or 'offer' not in offer:
            error_msg = "Failed to create tube"
            if offer:
                error_msg = offer.get('error', error_msg)
            # Clean up temporary session on failure
            unregister_tunnel_session(temp_tube_id)
            return {"success": False, "error": error_msg}

        commander_tube_id = offer['tube_id']
        
        # Update both signal handler and tunnel session with real tube ID
        signal_handler.tube_id = commander_tube_id
        signal_handler.host = host  # Store for later endpoint display
        signal_handler.port = port
        tunnel_session.tube_id = commander_tube_id
        
        # Get the actual listening address from Rust (source of truth)
        if 'actual_local_listen_addr' in offer and offer['actual_local_listen_addr']:
            rust_addr = offer['actual_local_listen_addr']
            try:
                if ':' in rust_addr:
                    rust_host, rust_port = rust_addr.rsplit(':', 1)
                    tunnel_session.host = rust_host
                    tunnel_session.port = int(rust_port)
                    signal_handler.host = rust_host
                    signal_handler.port = int(rust_port)
                    logging.debug(f"Using actual Rust listening address: {rust_host}:{rust_port}")
            except Exception as e:
                logging.warning(f"Failed to parse Rust address '{rust_addr}': {e}")
        
        # Unregister temporary session and register with real tube ID
        unregister_tunnel_session(temp_tube_id)
        register_tunnel_session(commander_tube_id, tunnel_session)
        
        logging.debug(f"Registered encryption key for conversation: {conversation_id_original}")
        logging.debug(f"Expecting WebSocket responses for conversation ID: {conversation_id_original}")
        
        # Start DEDICATED WebSocket listener for this tunnel
        # Each tunnel gets its own WebSocket connection - no sharing, no contention!
        websocket_thread, is_websocket_reused = start_websocket_listener(
            params, tube_registry, timeout=300, gateway_uid=gateway_uid, 
            tunnel_session=tunnel_session  # Pass tunnel_session for dedicated WebSocket
        )
        
        # Wait for WebSocket to establish connection before sending streaming requests
        # The router requires an active WebSocket connection for is_streaming=True
        if trickle_ice:
            # For trickle ICE, we MUST wait for WebSocket to be ready
            max_wait = 15.0  # Maximum wait time in seconds (increased for slow networks)
            
            # Use the tunnel's dedicated ready event (not global)
            if tunnel_session.websocket_ready_event:
                logging.debug(f"Waiting for dedicated WebSocket to connect (max {max_wait}s)...")
                websocket_ready = tunnel_session.websocket_ready_event.wait(timeout=max_wait)
                if not websocket_ready:
                    logging.error(f"Dedicated WebSocket did not become ready within {max_wait}s")
                    signal_handler.cleanup()
                    unregister_tunnel_session(commander_tube_id)
                    return {"success": False, "error": "WebSocket connection timeout"}
                logging.debug("Dedicated WebSocket connection established and ready for streaming")
                
                # DEDICATED WebSocket: No mutex needed! Each tunnel has its own connection.
                # Backend registration is independent - no contention, no delays needed.
                # Just a small delay to ensure backend is ready (much shorter than before)
                backend_registration_delay = float(os.getenv('WEBSOCKET_BACKEND_DELAY', '0.5'))
                logging.debug(f"Dedicated WebSocket: Waiting {backend_registration_delay}s for backend to register conversation {conversation_id_original}...")
                time.sleep(backend_registration_delay)
                logging.debug("Backend conversation registration delay complete")
            else:
                logging.error("No WebSocket ready event available for tunnel")
                signal_handler.cleanup()
                unregister_tunnel_session(commander_tube_id)
                return {"success": False, "error": "WebSocket event not initialized"}
        else:
            # For non-trickle ICE, WebSocket is optional (just for monitoring)
            # Give it a moment to start but don't block
            time.sleep(0.5)
            logging.debug("Non-trickle ICE: WebSocket optional, proceeding")
        
        # Verify the session was stored correctly
        stored_session = get_tunnel_session(commander_tube_id)
        if stored_session:
            logging.debug(f"Verified tunnel session stored: tube={commander_tube_id}, host={stored_session.host}, port={stored_session.port}")
        else:
            logging.error(f"Failed to store tunnel session for tube: {commander_tube_id}")
        
        # Send offer to gateway via HTTP POST with streamResponse=true
        logging.debug(f"{bcolors.OKBLUE}Sending offer for {conversation_id_original} to gateway...{bcolors.ENDC}")
        
        # Prepare the offer data
        data = {"offer": offer.get("offer")}

        # If allowSupplyHost is enabled, include the target host and port in the payload
        if allow_supply_host:
            data["host"] = {
                "hostName": target_host,
                "port": target_port
            }
            logging.debug(f"Including user-supplied host in payload: {target_host}:{target_port}")

        string_data = json.dumps(data)
        bytes_data = string_to_bytes(string_data)
        encrypted_data = tunnel_encrypt(symmetric_key, bytes_data)

        # Send offer via HTTP POST with retry logic for RRC_BAD_STATE
        # CRITICAL: For trickle ICE, use is_streaming=True (response via WebSocket)
        #           For non-trickle ICE, use is_streaming=False (response via HTTP)
        max_retries = int(os.getenv('TUNNEL_START_RETRIES', '2'))
        retry_delay = float(os.getenv('TUNNEL_RETRY_DELAY', '1.5'))
        
        for attempt in range(max_retries + 1):
            try:
                if attempt > 0:
                    logging.debug(f"Retry attempt {attempt}/{max_retries} after {retry_delay}s delay...")
                    time.sleep(retry_delay)
                
                router_response = router_send_action_to_gateway(
                    params=params,
                    destination_gateway_uid_str=gateway_uid,
                    gateway_action=GatewayActionWebRTCSession(
                        conversation_id = conversation_id_original,
                        inputs={
                            "recordUid": record_uid,
                            "tubeId": commander_tube_id,
                            'kind': 'start',
                            'base64Nonce': base64_nonce,
                            'conversationType': 'tunnel',
                            "data": encrypted_data,
                            "trickleICE": trickle_ice,
                        }
                    ),
                    message_type=pam_pb2.CMT_CONNECT,
                    is_streaming=trickle_ice,  # Streaming only for trickle ICE
                    gateway_timeout=GATEWAY_TIMEOUT
                )
                
                # Success! Break out of retry loop
                logging.debug(f"{bcolors.OKGREEN}Offer sent to gateway{bcolors.ENDC}")
                
                # Mark offer as sent in both signal handler and session
                signal_handler.offer_sent = True
                tunnel_session.offer_sent = True
                break  # Success - exit retry loop
                
            except Exception as e:
                error_msg = str(e)
                is_bad_state = "RRC_BAD_STATE" in error_msg
                is_last_attempt = (attempt == max_retries)
                
                if is_bad_state and not is_last_attempt:
                    # Retryable error and we have attempts left - this is expected during WebSocket startup
                    logging.debug(f"RRC_BAD_STATE on attempt {attempt + 1}/{max_retries + 1} - WebSocket backend may need more time")
                    logging.debug(f"Will retry in {retry_delay}s...")
                    continue  # Retry
                else:
                    # Fatal error or out of retries
                    if is_bad_state and is_last_attempt:
                        logging.error(f"RRC_BAD_STATE persists after {max_retries} retries")
                        logging.error("This may indicate network issues or backend problems")
                    
                    logging.error(f"Failed to send offer via HTTP: {error_msg}")
                    
                    # Cleanup on final failure
                    logging.debug(f"Cleaning up failed tunnel {commander_tube_id}")

                    # Stop the WebSocket if it was started
                    if tunnel_session.websocket_stop_event and tunnel_session.websocket_thread:
                        logging.debug(f"Stopping WebSocket for failed tunnel {commander_tube_id}")
                        tunnel_session.websocket_stop_event.set()
                        tunnel_session.websocket_thread.join(timeout=2.0)
                        if tunnel_session.websocket_thread.is_alive():
                            logging.warning(f"WebSocket for tunnel {commander_tube_id} did not close in time")

                    if not is_bad_state:
                        # Non-retryable error - cleanup immediately
                        signal_handler.cleanup()
                    else:
                        # RRC_BAD_STATE after all retries - cleanup but log it
                        logging.debug("Cleaning up after RRC_BAD_STATE exhausted retries")
                        signal_handler.cleanup()

                    unregister_tunnel_session(commander_tube_id)
                    return {"success": False, "error": f"Failed to send offer via HTTP: {e}"}
        
        # Continue with the rest of the flow after successful offer send
        # Trickle ICE: Response comes via WebSocket (HTTP response is empty)
        # Non-trickle ICE: Response comes via HTTP (contains SDP answer)
        
        # For non-trickle ICE, process the HTTP response (contains SDP answer)
        if not trickle_ice and router_response:
            logging.debug("Non-trickle ICE: Processing SDP answer from HTTP response")
            try:
                # router_response is a dict with 'response' key containing the gateway payload
                gateway_payload = router_response.get('response', {})
                
                # The response has nested structure: response -> payload (JSON string) -> data (encrypted)
                payload_str = gateway_payload.get('payload')
                if payload_str:
                    payload_json = json.loads(payload_str)
                    logging.debug(f"Non-trickle ICE: Parsed payload JSON, keys: {payload_json.keys()}")
                    
                    encrypted_answer = payload_json.get('data')
                    if encrypted_answer:
                        # Decrypt the answer using the tunnel's symmetric key
                        decrypted_answer = tunnel_decrypt(symmetric_key, encrypted_answer)
                        answer_data = json.loads(decrypted_answer)
                        
                        if 'answer' in answer_data:
                            answer_sdp = answer_data['answer']
                            logging.debug(f"Non-trickle ICE: Received SDP answer via HTTP, setting in Rust")
                            tube_registry.set_remote_description(commander_tube_id, answer_sdp, is_answer=True)
                            logging.debug("Non-trickle ICE: SDP answer set successfully")
                        else:
                            logging.error(f"Non-trickle ICE: No 'answer' field in decrypted data: {answer_data}")
                    else:
                        logging.error(f"Non-trickle ICE: No 'data' field in payload JSON: {payload_json}")
                else:
                    logging.error(f"Non-trickle ICE: No 'payload' field in gateway response: {gateway_payload}")
            except Exception as e:
                logging.error(f"Non-trickle ICE: Failed to process HTTP response: {e}")
                import traceback
                logging.error(f"Traceback: {traceback.format_exc()}")
        
        # Send any buffered ICE candidates that arrived before offer was sent (trickle ICE only)
        if trickle_ice and tunnel_session.buffered_ice_candidates:
            # Ensure WebSocket backend is fully ready before flushing candidates
            # The backend might need a bit more time after the offer succeeds
            if tunnel_session.websocket_ready_event and not tunnel_session.websocket_ready_event.is_set():
                logging.debug(f"Waiting for WebSocket to be ready before flushing ICE candidates...")
                websocket_ready = tunnel_session.websocket_ready_event.wait(timeout=5.0)
                if not websocket_ready:
                    logging.warning(f"WebSocket not ready after 5s, flushing candidates anyway")

            logging.debug(f"Flushing {len(tunnel_session.buffered_ice_candidates)} buffered ICE candidates after offer sent")
            for candidate in tunnel_session.buffered_ice_candidates:
                signal_handler._send_ice_candidate_immediately(candidate, commander_tube_id)
            tunnel_session.buffered_ice_candidates.clear()

        # Create an entrance object that can be used to monitor connection status
        entrance = SimpleRustTunnelEntrance(
            conversation_id=conversation_id_original,  # Use original, not base64 encoded
            host=host,
            port=port,
            record_uid=record_uid
        )

        logging.debug(f"{bcolors.OKBLUE}Connection state: {bcolors.ENDC}gathering candidates...")

        return {
            "success": True,
            "tube_id": commander_tube_id,
            "entrance": entrance,
            "signal_handler": signal_handler,
            "websocket_thread": websocket_thread,
            "conversation_id": conversation_id_original,  # Use original, not base64 encoded
            "tube_registry": tube_registry,
            "status": "connecting"  # Indicates async connection in progress
        }

    except Exception as e:
        logging.error(f"Error in start_rust_tunnel: {e}")
        # Clean up if needed
        if 'conversation_id_original' in locals() and conversation_id_original:
            unregister_conversation_key(conversation_id_original)
            # Also clean up standard base64 version
            standard_conversation_id = conversation_id_original.replace('-', '+').replace('_', '/')
            padding_needed = (4 - len(standard_conversation_id) % 4) % 4
            if padding_needed:
                standard_conversation_id += '=' * padding_needed
            if standard_conversation_id != conversation_id_original:
                unregister_conversation_key(standard_conversation_id)
        if 'signal_handler' in locals():
            signal_handler.cleanup()
        return {"success": False, "error": f"Failed to establish tunnel: {e}"}


def check_tunnel_connection_status(tube_registry, tube_id, timeout=None):
    """
    Check the connection status of a tunnel tube.
    
    Args:
        tube_registry: The PyTubeRegistry instance
        tube_id: The tube ID to check
        timeout: Optional timeout in seconds to wait for connection (None = no waiting)
    
    Returns:
        dict: {
            "connected": bool,
            "state": str,
            "error": str (if any)
        }
    """
    if not tube_registry or not tube_id:
        return {"connected": False, "state": "unknown", "error": "Invalid tube registry or ID"}
    
    try:
        if timeout is None:
            # Check the current state
            state = tube_registry.get_connection_state(tube_id)
            return {
                "connected": state.lower() == "connected",
                "state": state,
                "error": None
            }
        else:
            # Wait for connection with timeout
            max_wait_time = timeout
            check_interval = 0.5
            
            for i in range(int(max_wait_time / check_interval)):
                try:
                    state = tube_registry.get_connection_state(tube_id)
                    logging.debug(f"Connection state check {i+1}: {state}")
                    
                    if state.lower() == "connected":
                        return {"connected": True, "state": state, "error": None}
                    elif state.lower() in ["failed", "closed", "disconnected"]:
                        return {"connected": False, "state": state, "error": f"Connection failed with state: {state}"}
                    
                    time.sleep(check_interval)
                except Exception as e:
                    if "not found" in str(e).lower():
                        return {"connected": False, "state": "not_found", "error": "Tube was removed from registry"}
                    else:
                        logging.warning(f"Could not check connection state: {e}")
                        time.sleep(check_interval)
            
            # Timeout reached
            try:
                final_state = tube_registry.get_connection_state(tube_id)
                return {"connected": False, "state": final_state, "error": f"Connection timed out after {max_wait_time} seconds"}
            except Exception as e:
                if "not found" in str(e).lower():
                    return {"connected": False, "state": "not_found", "error": "Tube was removed from registry"}
                else:
                    return {"connected": False, "state": "unknown", "error": f"Connection verification failed: {e}"}
                    
    except Exception as e:
        return {"connected": False, "state": "error", "error": str(e)}


def wait_for_tunnel_connection(tunnel_result, timeout=30, show_progress=True):
    """
    Wait for a tunnel to establish connection, with optional progress display.
    
    Args:
        tunnel_result: Result dict from start_rust_tunnel
        timeout: Maximum time to wait in seconds
        show_progress: Whether to show progress messages
    
    Returns:
        dict: Connection status result
    """
    if not tunnel_result.get("success"):
        return {"connected": False, "error": "Tunnel initiation failed"}
    
    tube_registry = tunnel_result.get("tube_registry")
    tube_id = tunnel_result.get("tube_id")
    
    if not tube_registry or not tube_id:
        return {"connected": False, "error": "Invalid tunnel result - missing registry or tube ID"}
    
    if show_progress:
        print(f"{bcolors.OKBLUE}Waiting for tunnel connection (timeout: {timeout}s)...{bcolors.ENDC}")
    
    result = check_tunnel_connection_status(tube_registry, tube_id, timeout)
    
    if show_progress:
        if result["connected"]:
            # Success messages are now shown by the signal handler when connection establishes
            logging.debug("Tunnel connection wait completed successfully")
        else:
            error_msg = result.get("error", "Unknown error")
            print(f"{bcolors.FAIL}Tunnel connection failed: {error_msg}{bcolors.ENDC}")
    
    return result