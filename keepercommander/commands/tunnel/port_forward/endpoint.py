import asyncio
import enum
import json
import logging
import os
import secrets
import socket
import string
import struct
import time
from datetime import datetime
from typing import Optional, Dict

from aiortc import RTCPeerConnection, RTCSessionDescription, RTCConfiguration, RTCIceServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from keepercommander.keeper_dag import DAG, EdgeType
from keepercommander.keeper_dag.connection.commander import Connection
from keepercommander.keeper_dag.types import RefType
from keepercommander.keeper_dag.vertex import DAGVertex
from keeper_secrets_manager_core.utils import bytes_to_base64, base64_to_bytes, bytes_to_string, string_to_bytes

from keepercommander import crypto, utils, rest_api
from keepercommander.commands.pam.pam_dto import GatewayActionWebRTCSession
from keepercommander.commands.pam.router_helper import router_get_relay_access_creds, router_send_action_to_gateway, \
    get_dag_leafs
from keepercommander.display import bcolors
from keepercommander.error import CommandError
from keepercommander.params import KeeperParams
from keepercommander.proto import pam_pb2
from keepercommander.vault import PasswordRecord

logging.getLogger('aiortc').setLevel(logging.WARNING)
logging.getLogger('aioice').setLevel(logging.WARNING)

READ_TIMEOUT = 10
NONCE_LENGTH = 12
MAIN_NONCE_LENGTH = 16
SYMMETRIC_KEY_LENGTH = RANDOM_LENGTH = 32
MESSAGE_MAX = 5

# Protocol constants
CONTROL_MESSAGE_NO_LENGTH = 2
CLOSE_CONNECTION_REASON_LENGTH = 1
TIME_STAMP_LENGTH = 8
CONNECTION_NO_LENGTH = DATA_LENGTH = PORT_LENGTH = 4
TERMINATOR = b';'
PROTOCOL_LENGTH = CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + CONTROL_MESSAGE_NO_LENGTH + len(TERMINATOR)
KRELAY_URL = 'KRELAY_SERVER'
GATEWAY_TIMEOUT = int(os.getenv('GATEWAY_TIMEOUT')) if os.getenv('GATEWAY_TIMEOUT') else 30000

# WebRTC constant values
# 16 MiB max https://viblast.com/blog/2015/2/25/webrtc-bufferedamount/, so we will use 14.4 MiB or 90% of the max,
# because in some cases if the max is reached the channel will close
BUFFER_THRESHOLD = 134217728 * .90
# 16 Kbytes max https://viblast.com/blog/2015/2/5/webrtc-data-channel-message-size/,
# so we will use the max minus bytes for the protocol
BUFFER_TRUNCATION_THRESHOLD = 16000 - PROTOCOL_LENGTH


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


class ConnectionNotFoundException(Exception):
    pass


class ControlMessage(enum.IntEnum):
    Ping = 1
    Pong = 2
    OpenConnection = 101
    CloseConnection = 102
    ConnectionOpened = 103
    SendEOF = 104


def make_control_message(message_no, data=None):
    data = data if data is not None else b''
    buffer = int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big')
    # Add timestamp
    timestamp_ms = int(datetime.now().timestamp() * 1000)
    buffer += int.to_bytes(timestamp_ms, TIME_STAMP_LENGTH, byteorder='big')
    length = CONTROL_MESSAGE_NO_LENGTH + len(data)
    buffer += int.to_bytes(length, DATA_LENGTH, byteorder='big')
    buffer += int.to_bytes(message_no, CONTROL_MESSAGE_NO_LENGTH, byteorder='big')
    buffer += data + TERMINATOR
    return buffer


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


def find_open_port(tried_ports: [], start_port=49152, end_port=65535, preferred_port=None, host="127.0.0.1"):
    """
    Find an open port in the range [start_port, end_port].
    The default range is from 49152 to 65535, which are the "ephemeral ports" or "dynamic ports.".
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
            s.bind((host, port))
            return True
        except OSError:
            return False
        except Exception as e:
            logging.error(f"Error while checking port {port}: {e}")
            return False


def tunnel_encrypt(symmetric_key: AESGCM, data: bytes):
    """ Encrypts data using the symmetric key """
    # Compress the data
    nonce = os.urandom(NONCE_LENGTH)  # 12-byte nonce for AES-GCM
    encrypted_data = symmetric_key.encrypt(nonce, data, None)
    return bytes_to_base64(nonce + encrypted_data)


def tunnel_decrypt(symmetric_key: AESGCM, encrypted_data: str):
    """ Decrypts data using the symmetric key """

    mixed_data = base64_to_bytes(encrypted_data)
    # Data may be compressed and base64 encoded

    if len(mixed_data) <= NONCE_LENGTH:
        return None
    nonce = mixed_data[:NONCE_LENGTH]
    encrypted_data = mixed_data[NONCE_LENGTH:]

    try:
       return symmetric_key.decrypt(nonce, encrypted_data, None)
    except Exception as e:
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


class TunnelDAG:
    def __init__(self, params, encrypted_session_token, encrypted_transmission_key, record_uid: str, is_config=False):
        config_uid = None
        if not is_config:
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
        if not config_uid:
            config_uid = record_uid
        self.record = PasswordRecord()
        self.record.record_uid = config_uid
        self.record.record_key = generate_random_bytes(32)
        self.encrypted_session_token = encrypted_session_token
        self.encrypted_transmission_key = encrypted_transmission_key
        self.conn = Connection(params=params, encrypted_transmission_key=self.encrypted_transmission_key,
                               encrypted_session_token=self.encrypted_session_token
                               )
        self.linking_dag = DAG(conn=self.conn, record=self.record, graph_id=0)
        try:
            self.linking_dag.load()
        except Exception as e:
            logging.debug(f"Error loading config: {e}")

    def get_vertex_content(self, vertex):
        return_content = None
        if vertex is None:
            return return_content
        try:
            return_content = vertex.content_as_dict
        except Exception as e:
            logging.debug(f"Error getting vertex content: {e}")
            return_content = None
        return return_content

    def resource_belongs_to_config(self, resource_uid):
        if not self.linking_dag.has_graph:
            return False
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        return resource_vertex and config_vertex.has(resource_vertex, EdgeType.LINK)

    def user_belongs_to_config(self, user_uid):
        if not self.linking_dag.has_graph:
            return False
        user_vertex = self.linking_dag.get_vertex(user_uid)
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        res_content = False
        if user_vertex and config_vertex and config_vertex.has(user_vertex, EdgeType.ACL):
            acl_edge = user_vertex.get_edge(config_vertex, EdgeType.ACL)
            _content = acl_edge.content_as_dict
            res_content = _content.get('belongs_to', False) if _content else False
        return res_content

    def check_tunneling_enabled_config(self, enable_connections=None, enable_tunneling=None,
                                       enable_rotation=None, enable_session_recording=None,
                                       enable_typescript_recording=None, remote_browser_isolation=None):
        if not self.linking_dag.has_graph:
            return False
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        content = self.get_vertex_content(config_vertex)
        if content is None or not content.get('allowedSettings'):
            return False

        allowed_settings = content['allowedSettings']
        if enable_connections and not allowed_settings.get("connections"):
            return False
        if enable_tunneling and not allowed_settings.get("portForwards"):
            return False
        if enable_rotation and not allowed_settings.get("rotation"):
            return False
        if allowed_settings.get("connections") and allowed_settings["connections"]:
            if enable_session_recording and not allowed_settings.get("sessionRecording"):
                return False
            if enable_typescript_recording and not allowed_settings.get("typescriptRecording"):
                return False
        if remote_browser_isolation and not allowed_settings.get("remoteBrowserIsolation"):
            return False
        return True

    @staticmethod
    def _convert_allowed_setting(value):
        """Converts on/off/default|any to True/False/None"""
        if value is None or isinstance(value, bool):
            return value
        return {"on": True, "off": False}.get(str(value).lower(), None)

    def edit_tunneling_config(self, connections=None, tunneling=None,
                              rotation=None, session_recording=None,
                              typescript_recording=None,
                              remote_browser_isolation=None):
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            config_vertex = self.linking_dag.add_vertex(uid=self.record.record_uid, vertex_type=RefType.PAM_NETWORK)

        if config_vertex.vertex_type != RefType.PAM_NETWORK:
            config_vertex.vertex_type = RefType.PAM_NETWORK
        content = self.get_vertex_content(config_vertex)
        if content and content.get('allowedSettings'):
            allowed_settings = dict(content['allowedSettings'])
            del content['allowedSettings']
            content = {'allowedSettings': allowed_settings}

        if content is None:
            content = {'allowedSettings': {}}
        if 'allowedSettings' not in content:
            content['allowedSettings'] = {}

        allowed_settings = content['allowedSettings']
        dirty = False

        # When no value in allowedSettings: client will substitute with default
        # rotation defaults to True, everything else defaults to False

        # switching to 3-state on/off/default: on/true, off/false
        # None = Keep existing, 'default' = Reset to default (remove from dict)
        if connections is not None:
            connections = self._convert_allowed_setting(connections)
            if connections != allowed_settings.get("connections", None):
                dirty = True
                if connections is None:
                    allowed_settings.pop("connections", None)
                else:
                    allowed_settings["connections"] = connections

        if tunneling is not None:
            tunneling = self._convert_allowed_setting(tunneling)
            if tunneling != allowed_settings.get("portForwards", None):
                dirty = True
                if tunneling is None:
                    allowed_settings.pop("portForwards", None)
                else:
                    allowed_settings["portForwards"] = tunneling

        if rotation is not None:
            rotation = self._convert_allowed_setting(rotation)
            if rotation != allowed_settings.get("rotation", None):
                dirty = True
                if rotation is None:
                    allowed_settings.pop("rotation", None)
                else:
                    allowed_settings["rotation"] = rotation

        if session_recording is not None:
            session_recording = self._convert_allowed_setting(session_recording)
            if session_recording != allowed_settings.get("sessionRecording", None):
                dirty = True
                if session_recording is None:
                    allowed_settings.pop("sessionRecording", None)
                else:
                    allowed_settings["sessionRecording"] = session_recording

        if typescript_recording is not None:
            typescript_recording = self._convert_allowed_setting(typescript_recording)
            if typescript_recording != allowed_settings.get("typescriptRecording", None):
                dirty = True
                if typescript_recording is None:
                    allowed_settings.pop("typescriptRecording", None)
                else:
                    allowed_settings["typescriptRecording"] = typescript_recording

        if remote_browser_isolation is not None:
            remote_browser_isolation = self._convert_allowed_setting(remote_browser_isolation)
            if remote_browser_isolation != allowed_settings.get("remoteBrowserIsolation", None):
                dirty = True
                if remote_browser_isolation is None:
                    allowed_settings.pop("remoteBrowserIsolation", None)
                else:
                    allowed_settings["remoteBrowserIsolation"] = remote_browser_isolation

        if dirty:
            config_vertex.add_data(content=content, path='meta', needs_encryption=False)
            self.linking_dag.save()

    def get_all_owners(self, uid):
        owners = []
        if self.linking_dag.has_graph:
            vertex = self.linking_dag.get_vertex(uid)
            if vertex:
                owners = [owner.uid for owner in vertex.belongs_to_vertices()]
        return owners

    def user_belongs_to_resource(self, user_uid, resource_uid):
        user_vertex = self.linking_dag.get_vertex(user_uid)
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        res_content = False
        if user_vertex and resource_vertex and resource_vertex.has(user_vertex, EdgeType.ACL):
            acl_edge = user_vertex.get_edge(resource_vertex, EdgeType.ACL)
            _content = acl_edge.content_as_dict
            res_content = _content.get('belongs_to', False) if _content else False
        return res_content

    def get_resource_uid(self, user_uid):
        if not self.linking_dag.has_graph:
            return None
        resources = self.get_all_owners(user_uid)
        if len(resources) > 0:
            for resource in resources:
                if self.user_belongs_to_resource(user_uid, resource):
                    return resource
        return None

    def link_resource_to_config(self, resource_uid):
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            config_vertex = self.linking_dag.add_vertex(uid=self.record.record_uid)

        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            resource_vertex = self.linking_dag.add_vertex(uid=resource_uid)

        if not config_vertex.has(resource_vertex, EdgeType.LINK):
            resource_vertex.belongs_to(config_vertex, EdgeType.LINK)
            self.linking_dag.save()

    def link_user_to_config(self, user_uid):
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            config_vertex = self.linking_dag.add_vertex(uid=self.record.record_uid)
        self.link_user(user_uid, config_vertex, belongs_to=True, is_iam_user=True)

    def link_user_to_resource(self, user_uid, resource_uid, is_admin=None, belongs_to=None):
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None or not self.resource_belongs_to_config(resource_uid):
            print(f"{bcolors.FAIL}Resource {resource_uid} does not belong to the configuration{bcolors.ENDC}")
            return False
        self.link_user(user_uid, resource_vertex, is_admin, belongs_to)

    def link_user(self, user_uid, source_vertex: DAGVertex, is_admin=None, belongs_to=None, is_iam_user=None):

        user_vertex = self.linking_dag.get_vertex(user_uid)
        if user_vertex is None:
            user_vertex = self.linking_dag.add_vertex(uid=user_uid, vertex_type=RefType.PAM_USER)

        content = {}
        dirty = False
        if belongs_to is not None:
            content["belongs_to"] = bool(belongs_to)
        if is_admin is not None:
            content["is_admin"] = bool(is_admin)
        if is_iam_user is not None:
            content["is_iam_user"] = bool(is_iam_user)

        if user_vertex.vertex_type != RefType.PAM_USER:
            user_vertex.vertex_type = RefType.PAM_USER

        if source_vertex.has(user_vertex, EdgeType.ACL):
            acl_edge = user_vertex.get_edge(source_vertex, EdgeType.ACL)
            existing_content = acl_edge.content_as_dict
            for key in existing_content:
                if key not in content:
                    content[key] = existing_content[key]
            if content != existing_content:
                dirty = True

            if dirty:
                user_vertex.belongs_to(source_vertex, EdgeType.ACL, content=content)
                # user_vertex.add_data(content=content, needs_encryption=False)
                self.linking_dag.save()
        else:
            user_vertex.belongs_to(source_vertex, EdgeType.ACL, content=content)
            self.linking_dag.save()

    def get_all_admins(self):
        if not self.linking_dag.has_graph:
            return []
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            return []
        admins = []
        for user_vertex in config_vertex.has_vertices(EdgeType.ACL):
            acl_edge = user_vertex.get_edge(config_vertex, EdgeType.ACL)
            if acl_edge:
                content = acl_edge.content_as_dict
                if content.get('is_admin'):
                    admins.append(user_vertex.uid)
        return admins

    def check_if_resource_has_admin(self, resource_uid):
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return False
        for user_vertex in resource_vertex.has_vertices(EdgeType.ACL):
            acl_edge = user_vertex.get_edge(resource_vertex, EdgeType.ACL)
            if acl_edge:
                content = acl_edge.content_as_dict
                if content.get('is_admin'):
                    return user_vertex.uid
        return False

    def check_if_resource_allowed(self, resource_uid, setting):
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        content = self.get_vertex_content(resource_vertex)
        return content.get('allowedSettings', {}).get(setting, False) if content else False

    def set_resource_allowed(self, resource_uid, tunneling=None, connections=None, rotation=None,
                             session_recording=None, typescript_recording=None, remote_browser_isolation=None,
                             allowed_settings_name='allowedSettings', is_config=False,
                             v_type: RefType=str(RefType.PAM_MACHINE)):
        v_type = RefType(v_type)
        allowed_ref_types = [RefType.PAM_MACHINE, RefType.PAM_DATABASE, RefType.PAM_DIRECTORY, RefType.PAM_BROWSER]
        if v_type not in allowed_ref_types:
            # default to machine
            v_type = RefType.PAM_MACHINE

        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            resource_vertex = self.linking_dag.add_vertex(uid=resource_uid, vertex_type=v_type)

        if resource_vertex.vertex_type not in allowed_ref_types:
            resource_vertex.vertex_type = v_type
        if is_config:
            resource_vertex.vertex_type = RefType.PAM_NETWORK
        dirty = False
        content = self.get_vertex_content(resource_vertex)
        if content is None:
            content = {allowed_settings_name: {}}
            dirty = True
        if allowed_settings_name not in content:
            content[allowed_settings_name] = {}
            dirty = True

        settings = content[allowed_settings_name]

        # When no value in allowedSettings: client will substitute with default
        # rotation defaults to True, everything else defaults to False

        # switching to 3-state on/off/default: on/true, off/false
        # None = Keep existing, 'default' = Reset to default (remove from dict)
        if connections is not None:
            connections = self._convert_allowed_setting(connections)
            if connections != settings.get("connections", None):
                dirty = True
                if connections is None:
                    settings.pop("connections", None)
                else:
                    settings["connections"] = connections

        if tunneling is not None:
            tunneling = self._convert_allowed_setting(tunneling)
            if tunneling != settings.get("portForwards", None):
                dirty = True
                if tunneling is None:
                    settings.pop("portForwards", None)
                else:
                    settings["portForwards"] = tunneling

        if rotation is not None:
            rotation = self._convert_allowed_setting(rotation)
            if rotation != settings.get("rotation", None):
                dirty = True
                if rotation is None:
                    settings.pop("rotation", None)
                else:
                    settings["rotation"] = rotation

        if session_recording is not None:
            session_recording = self._convert_allowed_setting(session_recording)
            if session_recording != settings.get("sessionRecording", None):
                dirty = True
                if session_recording is None:
                    settings.pop("sessionRecording", None)
                else:
                    settings["sessionRecording"] = session_recording

        if typescript_recording is not None:
            typescript_recording = self._convert_allowed_setting(typescript_recording)
            if typescript_recording != settings.get("typescriptRecording", None):
                dirty = True
                if typescript_recording is None:
                    settings.pop("typescriptRecording", None)
                else:
                    settings["typescriptRecording"] = typescript_recording

        if remote_browser_isolation is not None:
            remote_browser_isolation = self._convert_allowed_setting(remote_browser_isolation)
            if remote_browser_isolation != settings.get("remoteBrowserIsolation", None):
                dirty = True
                if remote_browser_isolation is None:
                    settings.pop("remoteBrowserIsolation", None)
                else:
                    settings["remoteBrowserIsolation"] = remote_browser_isolation

        if dirty:
            resource_vertex.add_data(content=content, path='meta', needs_encryption=False)
            self.linking_dag.save()

    def is_tunneling_config_set_up(self, resource_uid):
        if not self.linking_dag.has_graph:
            return False
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        return resource_vertex and config_vertex and config_vertex in resource_vertex.belongs_to_vertices()

    def remove_from_dag(self, uid):
        if not self.linking_dag.has_graph:
            return True

        vertex = self.linking_dag.get_vertex(uid)
        if vertex is None:
            return True

        vertex.delete()
        self.linking_dag.save(confirm=True)

    def print_tunneling_config(self, record_uid, pam_settings=None, config_uid=None):
        if not pam_settings and not config_uid:
            return
        self.linking_dag.load()
        vertex = self.linking_dag.get_vertex(record_uid)
        content = self.get_vertex_content(vertex)
        config_id = config_uid if config_uid else pam_settings.value[0].get('configUid') if pam_settings else None
        if content and content.get('allowedSettings'):
            allowed_settings = content['allowedSettings']
            print(f"{bcolors.OKGREEN}Settings configured for {record_uid}{bcolors.ENDC}")
            # connections = f"{bcolors.OKBLUE}Enabled" if allowed_settings.get('connections') else \
            #     f"{bcolors.WARNING}Disabled"
            port_forwarding = f"{bcolors.OKBLUE}Enabled" if allowed_settings.get('portForwards') else \
                f"{bcolors.WARNING}Disabled"
            rotation = f"{bcolors.WARNING}Disabled" if (allowed_settings.get('rotation') and not allowed_settings['rotation']) else f"{bcolors.OKBLUE}Enabled"
            print(f"{bcolors.OKGREEN}\tRotation: {rotation}{bcolors.ENDC}")
            # print(f"{bcolors.OKGREEN}\tConnections: {connections}{bcolors.ENDC}")
            # if config_id == record_uid:
            #     rbi = f"{bcolors.OKBLUE}Enabled" if allowed_settings.get('remoteBrowserIsolation') else \
            #         f"{bcolors.WARNING}Disabled"
            #     print(f"{bcolors.OKGREEN}\tRemote Browser Isolation: {rbi}{bcolors.ENDC}")
            print(f"{bcolors.OKGREEN}\tTunneling: {port_forwarding}{bcolors.ENDC}")
            # if allowed_settings.get('connections'):
            #     if allowed_settings.get('sessionRecording'):
            #         print(f"{bcolors.OKGREEN}\tSession Recording: {bcolors.OKBLUE}Enabled{bcolors.ENDC}")
            #     else:
            #         print(f"{bcolors.OKGREEN}\tSession Recording: {bcolors.WARNING}Disabled{bcolors.ENDC}")
            #     if allowed_settings.get('typescriptRecording'):
            #         print(f"{bcolors.OKGREEN}\tTypescript Recording: {bcolors.OKBLUE}Enabled{bcolors.ENDC}")
            #     else:
            #         print(f"{bcolors.OKGREEN}\tTypescript Recording: {bcolors.WARNING}Disabled{bcolors.ENDC}")
            # admin_uid = self.check_if_resource_has_admin(record_uid)
            # if admin_uid:
            #     print(f"{bcolors.OKGREEN}\tAdmin: {bcolors.OKBLUE}{admin_uid}{bcolors.ENDC}")

            print(f"{bcolors.OKGREEN}Configuration: {config_id} {bcolors.ENDC}")
            if config_id is not None:
                config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
                config_content = self.get_vertex_content(config_vertex)
                if config_content and config_content.get('allowedSettings'):
                    config_allowed_settings = config_content['allowedSettings']
                    # config_connections = f"{bcolors.OKBLUE}Enabled" if config_allowed_settings.get('connections') else \
                    #     f"{bcolors.WARNING}Disabled"
                    #
                    # config_rbi = f"{bcolors.OKBLUE}Enabled" if config_allowed_settings.get('remoteBrowserIsolation') else \
                    #     f"{bcolors.WARNING}Disabled"
                    config_port_forwarding = f"{bcolors.OKBLUE}Enabled" if (
                        config_allowed_settings.get('portForwards')) else \
                        f"{bcolors.WARNING}Disabled"
                    config_rotation = f"{bcolors.WARNING}Disabled" if (config_allowed_settings.get('rotation') and
                                                                       not config_allowed_settings['rotation']) else \
                        f"{bcolors.OKBLUE}Enabled"
                    print(f"{bcolors.OKGREEN}\tRotation: {config_rotation}{bcolors.ENDC}")
                    # print(f"{bcolors.OKGREEN}\tConnections: {config_connections}{bcolors.ENDC}")
                    # print(f"{bcolors.OKGREEN}\tRemote Browser Isolation: {config_rbi}{bcolors.ENDC}")
                    print(f"{bcolors.OKGREEN}\tTunneling: {config_port_forwarding}{bcolors.ENDC}")
                    #
                    # if config_allowed_settings.get('connections') and config_allowed_settings['connections']:
                    #     if config_allowed_settings.get('sessionRecording'):
                    #         print(f"{bcolors.OKGREEN}\tSession Recording: {bcolors.OKBLUE}Enabled{bcolors.ENDC}")
                    #     else:
                    #         print(f"{bcolors.OKGREEN}\tSession Recording: {bcolors.WARNING}Disabled{bcolors.ENDC}")
                    #     if config_allowed_settings.get('typescriptRecording'):
                    #         print(f"{bcolors.OKGREEN}\tTypescript Recording: {bcolors.OKBLUE}Enabled{bcolors.ENDC}")
                    #     else:
                    #         print(f"{bcolors.OKGREEN}\tTypescript Recording: {bcolors.WARNING}Disabled{bcolors.ENDC}")


class WebRTCConnection:
    def __init__(self, params: KeeperParams, record_uid, gateway_uid, symmetric_key,
                 print_ready_event: asyncio.Event, kill_server_event: asyncio.Event,
                 logger: Optional[logging.Logger] = None, server='keepersecurity.com'):

        self._pc = None
        self.web_rtc_queue = asyncio.Queue()
        self.closed = False
        self.data_channel = None
        self.print_ready_event = print_ready_event
        self.logger = logger
        self.endpoint_name = "Starting..."
        self.params = params
        self.record_uid = record_uid
        self.gateway_uid = gateway_uid
        self.symmetric_key = symmetric_key
        self.kill_server_event = kill_server_event
        # Using Keeper's STUN and TURN servers
        self.relay_url = 'krelay.' + server
        self.time_diff = datetime.now() - datetime.now()
        krelay_url = os.getenv(KRELAY_URL)
        if krelay_url:
            self.relay_url = krelay_url
        self.logger.debug(f'Using relay server: {self.relay_url}')
        try:
            self.peer_ice_config()
            self.setup_data_channel()
            self.setup_event_handlers()
        except Exception as e:
            raise Exception(f'Error setting up WebRTC connection: {e}')

    async def attempt_reconnect(self):
        # backoff retry logic
        if self.retry_count < self.max_retries:
            await asyncio.sleep(self.retry_delay)  # Wait before retrying
            await self.ice_restart()
            self.retry_count += 1
            self.retry_delay *= 2  # Double the delay for the next retry if needed
        else:
            self.logger.error('Maximum reconnection attempts reached, stopping retries.')
            await self.close_webrtc_connection()

    async def ice_restart(self):
        self.peer_ice_config(ice_restart=True)
        self.setup_data_channel()
        self.setup_event_handlers()
        await self.signal_channel('reconnect', base64_nonce=bytes_to_base64(generate_random_bytes(MAIN_NONCE_LENGTH)))

    async def signal_channel(self, kind: str, base64_nonce: str):

        # make webRTC sdp offer
        try:
            if kind == 'start':
                offer = await self.make_offer()
            else:
                raise Exception(f'Invalid kind: {kind}')
        except socket.gaierror as e:
            if 'nodename nor servname provided, or not known' in str(e):
                print(
                    f"{bcolors.WARNING}Error connecting to relay server {self.relay_url}: {e}")
            else:
                print(
                    f"{bcolors.WARNING}Please upgrade Commander to the latest version to use this feature...{e}"
                    f"{bcolors.ENDC}")
            return
        except Exception as e:
            raise Exception(f'Error making WebRTC offer: {e}')
        data = {"offer": bytes_to_base64(offer)}
        string_data = json.dumps(data)
        bytes_data = string_to_bytes(string_data)
        encrypted_data = tunnel_encrypt(self.symmetric_key, bytes_data)
        self.logger.debug("-->. SEND START MESSAGE OVER REST TO GATEWAY")
        '''
            'inputs': {
                'recordUid': record_uid,            <-- the PAM resource record UID with Network information (REQUIRED)
                'conversationType': [
                    'tunnel', 'vnc', 'rdp', 'ssh', 'telnet', 'kubernetes', 
                    'mysql', 'postgresql', 'sql-server', 'http']       <-- What type of conversation is this (REQUIRED)
                'kind': ['start', 'disconnect'],                                     <-- What command to run (REQUIRED)
                'conversations': [List of conversations to disconnect],                <-- (Only for kind = disconnect)
                'base64Nonce': base64Nonce,                     <-- Random nonce to prevent replay attacks (REQUIRED)

                'data': {                                       <-- All data is encrypted with symmetric key (REQUIRED)
                    'offer': encrypted_WebRTC_sdp_offer,        <-- WebRTC SDP offer, base64 encoded
                }
            }
        '''
        router_response = router_send_action_to_gateway(
            params=self.params,
            destination_gateway_uid_str=self.gateway_uid,
            gateway_action=GatewayActionWebRTCSession(
                inputs={
                    "recordUid": self.record_uid,
                    'kind': kind,
                    'base64Nonce': base64_nonce,
                    'conversationType': 'tunnel',
                    "data": encrypted_data,
                }
            ),
            message_type=pam_pb2.CMT_CONNECT,
            is_streaming=False,
            gateway_timeout=GATEWAY_TIMEOUT
        )
        if not router_response:
            self.kill_server_event.set()
            return
        gateway_response = router_response.get('response', {})
        if not gateway_response:
            raise Exception(f"Error getting response from the Gateway: {router_response}")
        self.endpoint_name = gateway_response.get('conversationId', )
        try:
            payload = json.loads(gateway_response.get('payload', None))
            if not payload:
                raise Exception(f"Error getting payload from the Gateway response: {gateway_response}")
        except Exception as e:
            raise Exception(f"Error getting payload from the Gateway response: {e}")

        if payload.get('is_ok', False) is False or payload.get('progress_status') == 'Error':
            raise Exception(f"Gateway response: {payload.get('data')}")

        data = payload.get('data', None)
        if not data:
            raise Exception(f"Error getting data from the Gateway response payload: {payload}")

        # decrypt the sdp answer
        try:
            data = tunnel_decrypt(self.symmetric_key, data)
        except Exception as e:
            raise Exception(f'Error decrypting WebRTC answer from data: {data}\nError: {e}')
        try:
            if isinstance(data, bytes):
                data = bytes_to_string(data).replace("'", '"')
            data = json.loads(data)
        except Exception as e:
            raise Exception(f'Error loading WebRTC answer from data: {data}\nError: {e}')
        if not data.get('answer'):
            raise Exception(f"Error getting answer from the Gateway response data: {data}")
        try:
            answer = base64_to_bytes(data.get('answer'))
        except Exception as e:
            raise Exception(f'Error decoding WebRTC answer from data: {data}\nError: {e}')
        await self.accept_answer(answer)

        self.logger.debug("starting private tunnel")

    def peer_ice_config(self, ice_restart=False):
        if ice_restart and self._pc:
            asyncio.create_task(self._pc.close())
            self._pc = None
        response = router_get_relay_access_creds(params=self.params, expire_sec=60000000)
        if response is None:
            raise Exception("Error getting relay access credentials")
        if hasattr(response, "serverTime"):
            self.time_diff = datetime.now() - datetime.fromtimestamp(response.serverTime/1000)
        stun_url = f"stun:{self.relay_url}:3478"
        # Create an RTCIceServer instance for the STUN server
        stun_server = RTCIceServer(urls=stun_url)
        # Define the TURN server URL and credentials
        turn_url_udp = f"turn:{self.relay_url}:3478"
        # Create an RTCIceServer instance for the TURN server with credentials
        turn_server_udp = RTCIceServer(urls=turn_url_udp, username=response.username, credential=response.password)
        # Create a new RTCConfiguration with both STUN and TURN servers
        config = RTCConfiguration(iceServers=[stun_server, turn_server_udp])

        self._pc = RTCPeerConnection(config)

    async def make_offer(self):
        offer = await self._pc.createOffer()
        await self._pc.setLocalDescription(offer)
        return self._pc.localDescription.sdp.encode('utf-8')

    async def accept_answer(self, answer):
        if isinstance(answer, bytes):
            answer = bytes_to_string(answer)
        await self._pc.setRemoteDescription(RTCSessionDescription(answer, "answer"))

    def setup_data_channel(self):
        self.data_channel = self._pc.createDataChannel("control", ordered=True)

    def setup_event_handlers(self):
        self.data_channel.on("open", self.on_data_channel_open)
        self.data_channel.on("message", self.on_data_channel_message)
        self._pc.on("datachannel", self.on_data_channel)
        self._pc.on("connectionstatechange", self.on_connection_state_change)

    def on_data_channel_open(self):
        self.print_ready_event.set()
        buffer = make_control_message(ControlMessage.Ping, b'')
        self.send_message(buffer)
        self.logger.debug(f'Endpoint {self.endpoint_name}: Data channel opened')

    def on_data_channel_message(self, message):
        self.web_rtc_queue.put_nowait(message)

    def on_data_channel(self, channel):
        channel.on("open", self.on_data_channel_open)
        channel.on("error", self.on_data_channel_error)
        channel.on("message", self.on_data_channel_message)

    def on_connection_state_change(self):
        self.logger.debug(f'Endpoint {self.endpoint_name}: Connection State has changed: {self._pc.connectionState}')
        if self._pc.connectionState == "connected":
            # Connection is established, you can now send/receive data
            pass
        elif self._pc.connectionState in "disconnected failed".split():
            asyncio.create_task(self.attempt_reconnect())
        elif self._pc.connectionState == "closed":
            # Handle disconnection or failure here
            asyncio.get_event_loop().create_task(self.close_webrtc_connection())
            pass

    def is_data_channel_open(self):
        return (self.data_channel is not None and self.data_channel.readyState == "open"
                and self._pc.connectionState == "connected")

    def on_data_channel_error(self, error):
        self.logger.error(f'Endpoint {self.endpoint_name}: Data channel error: {error}')

    # Example usage of state check in a method
    def send_message(self, message):
        if self.is_data_channel_open():
            try:
                self.data_channel.send(message)
            except Exception as e:
                self.logger.error(f'Endpoint {self.endpoint_name}: Error sending message: {e}')
        else:
            self.logger.error(f'Endpoint {self.endpoint_name}: Data channel is not open.')

    async def close_webrtc_connection(self):
        if self.closed:
            return
        # Close the data channel
        if self.data_channel:
            try:
                self.data_channel.close()
                self.logger.error(f'Endpoint {self.endpoint_name}: Data channel closed')
            except Exception as e:
                self.logger.error(f'Endpoint {self.endpoint_name}: Error closing data channel: {e}')

        self.data_channel = None

        # Close the peer connection
        if self._pc:
            await self._pc.close()
            self.logger.error(f'Endpoint {self.endpoint_name}: Peer connection closed')

        # Clear the asyncio queue
        if self.web_rtc_queue:
            while not self.web_rtc_queue.empty():
                self.web_rtc_queue.get_nowait()
            self.web_rtc_queue = None

        # Reset instance variables
        self.data_channel = None
        self._pc = None
        self.kill_server_event.set()

        # Set the closed flag
        self.closed = True

    """
    This class is used to set up the tunnel entrance. This is used for the signaling phase and control messages.

    API calls offer/answer are encrypted using a shared secret derived from a key out of the record and the gateway's 
        own key.
    This tunnel is used to send control messages to the gateway: Ping, Pong, CloseConnection
    and ShareWebRTCDescription.
      There isn't a need for open connection because we send a start command in the discoveryrotation.py file.
      There is one connection or channel, 0 for control messages. We have the ability to add more channels if needed


    The tunnel uses WebRTC to connect to a peer on the gateway.

    The flow is as follows:
                                The pre tunnel (KRouter API calls/Signaling Phase)
       0. User enters a command to start a tunnel
       1. Commander sends a request to the KRouter API to get TURN server credentials
       2. Commander: makes a WebRTC peer, makes and offer, and sets its setLocalDescription.
       3. Commander sends tunnel start action to the gateway through krouter with offer encrypted using the shared 
            secret
       4. The Gateway gets that offer decrypts it with the shared secret and sets its setRemoteDescription, makes an 
            API call to krouter for TURN server credentials and makes an answer and sets its setLocalDescription.
       5. The gateway returns the answer encrypted using the shared secret in the response to the tunnel start action
        5.5 The Gateway sets up a tunnel exit
       6. Commander decrypts the answer and sets its setRemoteDescription to the answer it got from the gateway 
        6.5 The Commander sets up a tunnel entrance
       7 The two peers connect using STUN and TURN servers. If a direct connection can be made then the TURN server 
            is not used.

                                Setting up the tunnel
       8. Commander sets up a local server that listens for connections to a local port that the user has provided or a 
            random port if none is provided.
       9. Commander sends a ping message through the tunnel entrance to the tunnel exit
       10. The Gateway: receives the ping message and sends a pong message back establishing the
          connection
       11. Commander waits for a client to connect to the local server. Both sides wait for a set timeout to receive 
            data if the timeout is reached then a ping is sent. After 3 pings with no pongs the tunnel is closed.

                                User connects to the target
       12. Client connects to the tunnel's local server (localhost:[PORT].
       13. Tunnel Entrance (In Commander) sends an open connection message to the WebRTC connection and listens
            to the client forwarding on any data
       14. Tunnel Exit (On The Gateway): receives the open connection message and connects to the target
           host and port sending any data back to the WebRTC connection
       15. The session goes on until the CloseConnection message is sent, or the outer tunnel is closed.
       16. The User can repeat steps 12-16 as many times as they want

                              User closes the tunnel
       17. The User closes the tunnel and everything is cleaned up, and we can start back at step 1
    """


class ConnectionInfo:
    def __init__(self, reader: Optional[asyncio.StreamReader], writer: Optional[asyncio.StreamWriter],
                 message_counter: int, ping_time: Optional[float], to_tunnel_task: Optional[asyncio.Task],
                 start_time: datetime):
        self.reader = reader
        self.writer = writer
        self.message_counter = message_counter
        self.ping_time = ping_time
        self.to_tunnel_task = to_tunnel_task
        self.start_time = start_time
        self.transfer_latency_sum = 0
        self.transfer_latency_count = 0
        self.receive_latency_sum = 0
        self.receive_latency_count = 0
        self.transfer_size = 0
        self.receive_size = 0


class TunnelEntrance:
    """
    This class is used to forward data between a WebRTC connection and a connection to a target.
    Connection 0 is reserved for control messages. All other connections are for when a client connects
    This tunnel uses four control messages: Ping, Pong, OpenConnection and CloseConnection
    Data is broken into three parts: connection number, [message number], and data
    message number is only used in control messages. (if the connection number is 0 then there is a message number)
    """

    def __init__(self,
                 host,  # type: str
                 port,  # type: int
                 pc,  # type: WebRTCConnection
                 print_ready_event,  # type: asyncio.Event
                 logger=None,  # type: logging.Logger
                 connect_task=None,  # type: asyncio.Task
                 kill_server_event=None,  # type: asyncio.Event
                 target_host=None,  # type: Optional[str]
                 target_port=None  # type: Optional[int]
                 ):  # type: (...) -> None
        self.closing = False
        self.to_local_task = None
        self._ping_attempt = 0
        self.host = host
        self.target_host = target_host
        self.target_port = target_port
        self.server = None
        self.connection_no = 1
        self.connections: Dict[int, ConnectionInfo] = {0: ConnectionInfo(None, None, 0, None, None, datetime.now())}
        self._port = port
        self.logger = logger
        self.is_connected = True
        self.reader_task = asyncio.create_task(self.start_reader())
        self.kill_server_event = kill_server_event
        self.pc = pc
        self.print_ready_event = print_ready_event
        self.connect_task = connect_task
        self.eof_sent = False

    @property
    def port(self):
        return self._port

    async def send_to_web_rtc(self, data):
        if self.pc.is_data_channel_open():
            sleep_count = 0
            while (self.pc.data_channel is not None and
                   self.pc.data_channel.bufferedAmount >= BUFFER_THRESHOLD and
                   not self.kill_server_event.is_set() and
                   self.pc.is_data_channel_open()):
                self.logger.debug(f"{bcolors.WARNING}Buffered amount is too high ({sleep_count * 100}) "
                                  f"{self.pc.data_channel.bufferedAmount}{bcolors.ENDC}")
                await asyncio.sleep(sleep_count)
                sleep_count += .01

            try:
                self.pc.send_message(data)
            except Exception as e:
                self.logger.error(f'Endpoint {self.pc.endpoint_name}: Error sending message: {e}')
                await asyncio.sleep(0.1)
            # Yield control back to the event loop for other tasks to execute
            await asyncio.sleep(0)

        else:
            if self.print_ready_event.is_set():
                self.logger.error(f'Endpoint {self.pc.endpoint_name}: Data channel is not open. Data not sent.')
            if self.connection_no > 1:
                self.kill_server_event.set()

    async def send_control_message(self, message_no, data=None):  # type: (ControlMessage, Optional[bytes]) -> None
        """
        Packet structure
         Control Message Packets
               [CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + CONTROL_MESSAGE_NO_LENGTH + DATA]
        """
        buffer = make_control_message(message_no, data)
        try:
            self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Sending Control command {message_no} '
                              f'len: {len(buffer)} to tunnel.')
            self.connections[0].transfer_size += len(buffer)
            await self.send_to_web_rtc(buffer)
        except Exception as e:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while sending control message: {e}")

    def update_stats(self, connection_no, data_size, timestamp):
        """
        Update the transfer stats for the connection
        :param connection_no:
        :param data_size:
        :param timestamp:
        :return:
        """
        c = self.connections.get(connection_no)
        if c:
            dt = datetime.fromtimestamp(timestamp/1000)
            c.receive_size += data_size
            td = datetime.now() - self.pc.time_diff - dt
            # Convert timedelta to total milliseconds
            td_milliseconds = (td.days * 24 * 60 * 60 + td.seconds) * 1000 + td.microseconds / 1000
            c.receive_latency_sum += td_milliseconds
            c.receive_latency_count += 1

    def report_stats(self, connection_no: int):
        """
        Report the stats for the connection
        :return:
        """
        con = self.connections.get(connection_no)
        if con:
            average_receive_latency = "Not Available"
            if con.receive_latency_count > 0:
                average_receive_latency = con.receive_latency_sum / con.receive_latency_count

            average_transfer_latency = "Not Available"
            if con.transfer_latency_count > 0:
                average_transfer_latency = con.transfer_latency_sum / con.transfer_latency_count
            self.logger.info(f"Endpoint {self.pc.endpoint_name}: Connection {connection_no} Stats:"
                             f"\n\tTransferred {con.transfer_size} bytes"
                             f"\n\tTransfer Latency Average: {average_transfer_latency} ms"
                             f"\n\tReceive Latency Average: {average_receive_latency} ms"
                             f"\n\tReceived {con.receive_size} bytes")

    async def process_control_message(self, message_no, data):  # type: (ControlMessage, Optional[bytes]) -> None
        if message_no == ControlMessage.CloseConnection:
            self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received close connection request')
            if data and len(data) >= CONNECTION_NO_LENGTH:
                target_connection_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                reason = CloseConnectionReasons.Unknown
                if len(data) > CONNECTION_NO_LENGTH:
                    reason_int = int.from_bytes(data[CONNECTION_NO_LENGTH:], byteorder='big')
                    reason = CloseConnectionReasons(reason_int)
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Closing Connection {target_connection_no}' +
                                      (f'Reason: {reason}' if reason else ''))
                else:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Closing Connection {target_connection_no}')
                if target_connection_no == 0:
                    self.logger.info(f'Endpoint {self.pc.endpoint_name}: Received close Tunnel connection request.')
                    self.kill_server_event.set()
                else:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Closing connection '
                                      f'{target_connection_no}')
                    await self.close_connection(target_connection_no, reason)
        elif message_no == ControlMessage.Pong:
            self._ping_attempt = 0
            self.is_connected = True
            if len(data) >= CONNECTION_NO_LENGTH:
                con_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                if con_no in self.connections:
                    self.connections[con_no].message_counter = 0
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received pong request')
                    if con_no != 0:
                        self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received ACK for {con_no}')
                    if self.connections[con_no].ping_time is not None:
                        time_now = time.perf_counter()
                        # from the time the ping was sent to the time the pong was received
                        latency = time_now - self.connections[con_no].ping_time

                        if self.connections[con_no].receive_latency_count > 0:
                            receive_latency_average = (self.connections[con_no].receive_latency_sum /
                                                       self.connections[con_no].receive_latency_count)
                            t_latency = self._round_trip_latency[-1] - receive_latency_average
                            self.connections[con_no].transfer_latency_sum += t_latency
                            self.connections[con_no].transfer_latency_count += 1
                        self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Round trip latency: {latency} ms')
                        self.connections[con_no].ping_time = None
            else:
                self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received pong request')
                if self.connections[0].ping_time is not None:
                    time_now = time.perf_counter()
                    # from the time the ping was sent to the time the pong was received
                    latency = time_now - self.connections[0].ping_time
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Round trip latency: {latency} ms')
                    self.connections[0].ping_time = None

        elif message_no == ControlMessage.Ping:
            if len(data) >= CONNECTION_NO_LENGTH:
                con_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                if con_no in self.connections:
                    await self.send_control_message(ControlMessage.Pong, int.to_bytes(con_no, CONNECTION_NO_LENGTH,
                                                                                      byteorder='big'))
                    if len(data[:CONNECTION_NO_LENGTH]) >= TIME_STAMP_LENGTH:
                        self.connections[con_no].transfer_latency_sum += int.from_bytes(data[CONNECTION_NO_LENGTH:
                                                                                             CONNECTION_NO_LENGTH +
                                                                                             TIME_STAMP_LENGTH],
                                                                                        byteorder='big')
                        self.connections[con_no].transfer_latency_count += 1

                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Received Ping for {con_no}')
                    if con_no != 0 and self.logger.level == logging.DEBUG:
                        self.report_stats(0)
                    if self.logger.level == logging.DEBUG:
                        # print the stats
                        self.report_stats(con_no)
                else:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Connection {con_no} for Ping not found')
            else:
                self.logger.debug(f'Endpoint {self.endpoint_name}: Received Ping request')
                await self.send_control_message(ControlMessage.Pong, int.to_bytes(0, CONNECTION_NO_LENGTH,
                                                                                  byteorder='big'))
        elif message_no == ControlMessage.ConnectionOpened:
            if len(data) >= CONNECTION_NO_LENGTH:
                connection_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Starting reader for connection "
                                  f"{connection_no}")
                # If it is a socks connection then we need to signal the client that the connection is open
                if isinstance(self, SOCKS5Server):
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Socks Connection {connection_no} opened')
                    # Send a success response back to the client
                    response = b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                    self.connections[connection_no].writer.write(response)
                    await self.connections[connection_no].writer.drain()
                try:
                    self.connections[connection_no].to_tunnel_task = asyncio.create_task(
                        self.forward_data_to_tunnel(connection_no))  # From current connection to WebRTC connection
                    self.logger.debug(
                        f"Endpoint {self.pc.endpoint_name}: Started reader for connection {connection_no}")
                except ConnectionNotFoundException as e:
                    self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Connection {connection_no} not found: {e}")
                except Exception as e:
                    self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error in forwarding data task: {e}")
            else:
                self.logger.error(f"Endpoint {self.pc.endpoint_name}: Invalid open connection message")
        elif message_no == ControlMessage.SendEOF:
            if len(data) >= CONNECTION_NO_LENGTH:
                con_no = int.from_bytes(data[:CONNECTION_NO_LENGTH], byteorder='big')
                if con_no in self.connections:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Sending EOF to {con_no}')
                    self.connections[con_no].writer.write_eof()
                else:
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: EOF for Connection {con_no} not found')
        else:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name} Unknown tunnel control message: {message_no}')

    async def forward_data_to_local(self):
        """
        Forward data from WebRTC connection to the appropriate local connection based on connection_no.
        Packet structure
         Control Packets [CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + CONTROL_MESSAGE_NO_LENGTH + DATA]
         Data Packets [CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + DATA]
        """
        self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Forwarding data to local...")
        buff = b''
        while not self.kill_server_event.is_set():
            if self.pc.closed:
                self.kill_server_event.set()
                break
            while len(buff) >= CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH:
                connection_no = int.from_bytes(buff[:CONNECTION_NO_LENGTH], byteorder='big')
                time_stamp = int.from_bytes(
                    buff[CONNECTION_NO_LENGTH:CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH], byteorder='big')
                length = int.from_bytes(
                    buff[CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH:
                         CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH], byteorder='big')
                if len(buff) >= CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length + len(TERMINATOR):
                    if (buff[(CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length):
                        (CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length + len(TERMINATOR))] !=
                            TERMINATOR):
                        self.logger.warning(f'Endpoint {self.pc.endpoint_name}: Invalid terminator')
                        # if we don't have a valid terminator then we don't know where the message ends or begins
                        self.kill_server_event.set()
                        break
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Buffer data received data')
                    send_data = (buff[CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH:
                                 CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length])
                    self.update_stats(connection_no, len(send_data) + CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH +
                                      DATA_LENGTH, time_stamp)
                    buff = buff[CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length + len(TERMINATOR):]

                    if connection_no == 0:
                        # This is a control message
                        control_m = ControlMessage(int.from_bytes(send_data[:CONTROL_MESSAGE_NO_LENGTH],
                                                                  byteorder='big'))

                        send_data = send_data[CONTROL_MESSAGE_NO_LENGTH:]

                        await self.process_control_message(control_m, send_data)
                    else:
                        if connection_no not in self.connections:
                            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Connection not found: "
                                              f"{connection_no}")
                            continue

                        try:
                            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Forwarding data to "
                                              f"local for connection {connection_no} ({len(send_data)})")
                            self.connections[connection_no].writer.write(send_data)
                            await self.connections[connection_no].writer.drain()
                            # Yield control back to the event loop for other tasks to execute
                            await asyncio.sleep(0)
                        except Exception as ex:
                            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while forwarding "
                                              f"data to local: {ex}")

                            # Yield control back to the event loop for other tasks to execute
                            await asyncio.sleep(0)
                else:
                    self.logger.debug(
                        f"Endpoint {self.pc.endpoint_name}: Buffer is too short {len(buff)} need "
                        f"{CONNECTION_NO_LENGTH + TIME_STAMP_LENGTH + DATA_LENGTH + length + len(TERMINATOR)}")
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
                    break
            if self.kill_server_event.is_set():
                break
            try:
                data = await asyncio.wait_for(self.pc.web_rtc_queue.get(), READ_TIMEOUT)
            except asyncio.TimeoutError as et:
                if self._ping_attempt > 3:
                    if self.is_connected:
                        self.kill_server_event.set()
                    raise et
                self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Tunnel reader timed out')
                if self.is_connected and self.pc.is_data_channel_open():
                    self.logger.debug(f'Endpoint {self.pc.endpoint_name}: Send ping request')

                    buffer = int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big')
                    if self.connections[0].receive_latency_count > 0:
                        receive_latency_average = int(self.connections[0].receive_latency_sum /
                                                      self.connections[0].receive_latency_count)
                        buffer += int.to_bytes(receive_latency_average, TIME_STAMP_LENGTH, byteorder='big')
                    await self.send_control_message(ControlMessage.Ping, buffer)

                    if self.logger.level == logging.DEBUG:
                        # print the stats
                        for c in self.connections.keys():
                            self.report_stats(c)
                    self._ping_attempt += 1
                continue
            self.pc.web_rtc_queue.task_done()
            if not data or not self.is_connected:
                self.logger.info(f"Endpoint {self.pc.endpoint_name}: Exiting forward data to local")
                break
            elif len(data) == 0:
                # Yield control back to the event loop for other tasks to execute
                await asyncio.sleep(0)
                continue
            elif isinstance(data, bytes):
                self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Got data from WebRTC connection "
                                  f"{len(data)} bytes")
                buff += data
            else:
                # Yield control back to the event loop for other tasks to execute
                await asyncio.sleep(0)

        self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Exiting forward data successfully.")

        self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Closing tunnel")
        await self.stop_server(CloseConnectionReasons.Normal)

    async def start_reader(self):  # type: () -> None
        """
        Transfer data from WebRTC connection to local connections.
        """
        failed = False
        try:
            # From WebRTC server to local connections
            self.to_local_task = asyncio.create_task(self.forward_data_to_local())

            # Send hello world open connection message
            await self.send_control_message(ControlMessage.Ping, int.to_bytes(0, CONNECTION_NO_LENGTH, byteorder='big'))
            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Sent ping message to WebRTC connection")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while establishing WebRTC connection: {e}")
            failed = True
        finally:
            if failed:
                self.kill_server_event.set()
                self.is_connected = False
            return

    async def forward_data_to_tunnel(self, con_no):
        """
        Forward data from the given connection to the WebRTC connection
        """
        while not self.kill_server_event.is_set():
            c = self.connections.get(con_no)
            if c is None or not self.is_connected:
                break
            try:
                data = await c.reader.read(BUFFER_TRUNCATION_THRESHOLD)
            except Exception as e:
                self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Connection '{con_no}' read failed: {e}")
                break
            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Forwarding {len(data)} "
                              f"bytes to tunnel for connection {con_no}")
            if not data:
                self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Connection {con_no} no data")
                break
            if isinstance(data, bytes):
                if c.reader.at_eof() and len(data) == 0:
                    if not self.eof_sent:
                        await self.send_control_message(ControlMessage.SendEOF,
                                                        int.to_bytes(con_no, CONNECTION_NO_LENGTH,
                                                                     byteorder='big'))
                        self.eof_sent = True
                    # Yield control back to the event loop for other tasks to execute
                    await asyncio.sleep(0)
                    continue
                else:
                    self.eof_sent = False
                    buffer = int.to_bytes(con_no, CONNECTION_NO_LENGTH, byteorder='big')
                    # Add timestamp
                    timestamp_ms = int(datetime.now().timestamp() * 1000)
                    buffer += int.to_bytes(timestamp_ms, TIME_STAMP_LENGTH, byteorder='big')
                    buffer += int.to_bytes(len(data), DATA_LENGTH, byteorder='big') + data + TERMINATOR
                    self.connections[con_no].transfer_size += len(buffer)
                    await self.send_to_web_rtc(buffer)

                    self.logger.debug(
                        f'Endpoint {self.pc.endpoint_name}: buffer size: {self.pc.data_channel.bufferedAmount}'
                        f', time since start: {datetime.now() - c.start_time}')

                    c.message_counter += 1
                    if (c.message_counter >= MESSAGE_MAX and
                            self.pc.data_channel.bufferedAmount > BUFFER_TRUNCATION_THRESHOLD):
                        c.ping_time = time.perf_counter()

                        ping_buffer = int.to_bytes(con_no, CONNECTION_NO_LENGTH, byteorder='big')
                        if self.connections[0].receive_latency_count > 0:
                            receive_latency_average = int(self.connections[0].receive_latency_sum /
                                                          self.connections[0].receive_latency_count)
                            ping_buffer += int.to_bytes(receive_latency_average, TIME_STAMP_LENGTH,
                                                        byteorder='big')
                        await self.send_control_message(ControlMessage.Ping, ping_buffer)
                        self._ping_attempt += 1
                        wait_count = 0
                        while c.message_counter >= MESSAGE_MAX:
                            await asyncio.sleep(wait_count)
                            wait_count += .1
                    elif (c.message_counter >= MESSAGE_MAX and
                          self.pc.data_channel.bufferedAmount <= BUFFER_TRUNCATION_THRESHOLD):
                        c.message_counter = 0

            else:
                # Yield control back to the event loop for other tasks to execute
                await asyncio.sleep(0)

        if con_no not in self.connections:
            raise ConnectionNotFoundException(f"Connection {con_no} not found")

        # Send close connection message with con_no
        buff = int.to_bytes(con_no, CONNECTION_NO_LENGTH, byteorder='big')
        buff += int.to_bytes(CloseConnectionReasons.Normal.value, CLOSE_CONNECTION_REASON_LENGTH, byteorder='big')
        await self.send_control_message(ControlMessage.CloseConnection, buff)
        await self.close_connection(con_no, CloseConnectionReasons.Normal)

    async def handle_connection(self, reader, writer):  # type: (asyncio.StreamReader, asyncio.StreamWriter) -> None
        """
        This is called when a client connects to the local port starting a new session.
        """
        connection_no = self.connection_no
        self.connection_no += 1
        self.connections[connection_no] = ConnectionInfo(reader, writer, 0, None, None, datetime.now())
        self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Created local connection {connection_no}")

        # Send open connection message with con_no. this is required to be sent to start the connection
        await self.send_control_message(ControlMessage.OpenConnection,
                                        int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big'))

    async def start_server(self):  # type: (...) -> None
        """
        This server is used to listen for client connections to the local port.
        """
        if self.server:
            return
        if not self._port:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: No open ports found for local server")
            self.kill_server_event.set()
            return

        try:
            self.server = await asyncio.start_server(self.handle_connection, family=socket.AF_INET, host=self.host,
                                                     port=self._port)
            async with self.server:
                await self.server.serve_forever()
        except ConnectionRefusedError as er:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Connection Refused while starting server: {er}")
        except OSError as er:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: OS Error while starting server: {er}")
        except Exception as e:
            self.logger.error(f"Endpoint {self.pc.endpoint_name}: Error while starting server: {e}")
        finally:
            if self.server is not None:
                self.server.close()
                try:
                    await asyncio.wait_for(self.server.wait_closed(), timeout=5.0)
                except asyncio.TimeoutError:
                    self.logger.warning(
                        f"Endpoint {self.pc.endpoint_name}: Timed out while trying to close server")
            self.kill_server_event.set()
            return

    async def stop_server(self, reason: CloseConnectionReasons):
        if self.closing:
            return

        self.closing = True
        if len(self.connections) > 1:
            for i in range(1, len(self.connections)):
                await self.close_connection(i, reason)

        try:
            buffer = int.to_bytes(0, CONNECTION_NO_LENGTH)
            buffer += int.to_bytes(reason.value, CLOSE_CONNECTION_REASON_LENGTH, byteorder='big')
            await self.send_control_message(ControlMessage.CloseConnection, buffer)
            await self.close_connection(0, reason)
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception sending Close connection {ex}')

        if self.kill_server_event is not None:
            if not self.kill_server_event.is_set():
                self.kill_server_event.set()
        try:
            # close aiortc data channel
            await self.pc.close_webrtc_connection()
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception closing data channel {ex}')

        try:
            self.server.close()
            await asyncio.wait_for(self.server.wait_closed(), timeout=5.0)
            self.server = None
        except asyncio.TimeoutError:
            self.logger.warning(
                f"Endpoint {self.pc.endpoint_name}: Timed out while trying to close server")
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception closing server {ex}')

        try:
            if self.connect_task is not None:
                self.connect_task.cancel()
        finally:
            self.logger.info(f"Endpoint {self.pc.endpoint_name}: Tunnel stopped")

    async def close_connection(self, connection_no, reason: CloseConnectionReasons):
        # print the stats
        self.report_stats(connection_no)
        try:
            buffer = int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big')
            buffer += int.to_bytes(reason.value, CLOSE_CONNECTION_REASON_LENGTH, byteorder='big')
            await self.send_control_message(ControlMessage.CloseConnection, buffer)
        except Exception as ex:
            self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception sending Close connection {ex}')

        if connection_no in self.connections.keys() and connection_no != 0:
            try:
                self.connections[connection_no].writer.close()
                # Wait for it to actually close.
                await asyncio.wait_for(self.connections[connection_no].writer.wait_closed(), timeout=5.0)
            except asyncio.TimeoutError:
                self.logger.warning(
                    f"Endpoint {self.pc.endpoint_name}: Timed out while trying to close connection "
                    f"{connection_no}")
            except Exception as ex:
                self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception closing connection {ex}')

            try:
                # clean up reader
                if self.connections[connection_no].reader is not None:
                    self.connections[connection_no].reader.feed_eof()
                    self.connections[connection_no].reader = None
            except Exception as ex:
                self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception closing reader {ex}')

            if connection_no in self.connections:
                try:
                    if self.connections[connection_no].to_tunnel_task is not None:
                        self.connections[connection_no].to_tunnel_task.cancel()
                except Exception as ex:
                    self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception canceling tasks {ex}')
                try:
                    del self.connections[connection_no]
                except Exception as ex:
                    self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception deleting connection {ex}')
            self.logger.info(f"Endpoint {self.pc.endpoint_name}: Closed connection {connection_no}")
        elif connection_no == 0:
            self.logger.info(f"Endpoint {self.pc.endpoint_name}: Closed control connection")
            try:
                del self.connections[connection_no]
            except Exception as ex:
                self.logger.warning(f'Endpoint {self.pc.endpoint_name}: hit exception deleting connection {ex}')
        else:
            self.logger.debug(f"Endpoint {self.pc.endpoint_name}: Connection {connection_no} not found")


class SOCKS5Server(TunnelEntrance):
    def __init__(self,
                 host,  # type: str
                 port,  # type: int
                 pc,  # type: WebRTCConnection
                 print_ready_event,  # type: asyncio.Event
                 logger=None,  # type: logging.Logger
                 connect_task=None,  # type: asyncio.Task
                 kill_server_event=None,  # type: asyncio.Event
                 target_host=None,  # type: Optional[str]
                 target_port=None  # type: Optional[int]
                 ):  # type: (...) -> None
        super().__init__(host, port, pc, print_ready_event, logger, connect_task, kill_server_event, target_host,
                         target_port)
        # Credentials for authentication
        # self.valid_username = os.getenv('SOCKS5_USERNAME', 'defaultuser')
        # self.valid_password = os.getenv('SOCKS5_PASSWORD', 'defaultpass')
        # if self.valid_username == 'defaultuser' or self.valid_password == 'defaultpass':
        #     self.logger.warning("Default SOCKS5 credentials are being used. "
        #                    "Please set SOCKS5_USERNAME and SOCKS5_PASSWORD environment variables.")

    # async def username_password_authenticate(self, reader, writer):
    #     # Username/Password Authentication (RFC 1929)
    #     try:
    #         auth_version_bytes = await reader.readexactly(1)
    #         auth_version = ord(auth_version_bytes)
    #         if auth_version != 1:  # Should be 0x01 for username/password auth
    #             return False
    #
    #         username_length_bytes = await reader.readexactly(1)
    #         username_length = ord(username_length_bytes)
    #         username = await reader.readexactly(username_length)
    #         username = username.decode()
    #
    #         password_length_bytes = await reader.readexactly(1)
    #         password_length = ord(password_length_bytes)
    #         password = await reader.readexactly(password_length)
    #         password = password.decode()
    #     except asyncio.IncompleteReadError:
    #         # Handle the case where the client disconnects or sends incomplete data
    #         return False
    #
    #     # Verify username and password
    #     if username == self.valid_username and password == self.valid_password:
    #         writer.write(b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00')  # Authentication succeeded
    #         await writer.drain()
    #         return True
    #     else:
    #         writer.write(b'\x01\x01\x00\x01\x00\x00\x00\x00\x00\x00')  # Authentication failed
    #         await writer.drain()
    #         return False

    async def handle_connection(self, reader, writer):  # type: (asyncio.StreamReader, asyncio.StreamWriter) -> None
        """
        This is called when a client connects to the local port starting a new session.
        This extends the base handle_connection method to handle SOCKS5 connections.
        """
        async def quick_close(reason: bytes):
            writer.write(reason)  # Network unreachable
            writer.close()
            await writer.wait_closed()

        connection_no = self.connection_no
        self.connection_no += 1
        self.connections[connection_no] = ConnectionInfo(reader, writer, 0, None, None, datetime.now())

        # Only allow connections from localhost
        client_host, client_port = writer.get_extra_info('peername')
        if client_host != '127.0.0.1':
            self.logger.warning(f"Connection from {client_host}:{client_port} rejected")
            await quick_close(b'\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')  # Connection not allowed
            return

        # Initial greeting and authentication method negotiation
        # SOCKS5, 2 authentication methods, No Auth and Username/Password
        # supported_methods = [0x00, 0x02]
        supported_methods = [0x00]
        # Wait for the client's authentication method request
        client_greeting = await reader.read(2)
        socks_version, n_methods = client_greeting

        if socks_version not in [0x05, 0x04]:  # SOCKS5 or SOCKS4
            self.logger.error("Invalid SOCKS version")
            await quick_close(b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00')  # Unsupported version
            return

        method_ids = await reader.readexactly(n_methods)
        # Decide which method to use (prefer No Auth if available)
        if 0x00 in method_ids and 0x00 in supported_methods:
            selected_method = 0x00  # No Authentication Required
        # elif 0x02 in method_ids and 0x02 in supported_methods:
        #     selected_method = 0x02  # Username/Password
        else:
            selected_method = 0xff  # No acceptable methods

        # Send the selected method back to the client
        writer.write(struct.pack("!BB", socks_version, selected_method))
        await writer.drain()

        # Proceed based on the selected method
        if selected_method == 0x00:
            # No further authentication needed
            pass
        # elif selected_method == 0x02:
        #     # Perform username/password authentication
        #     auth_success = await self.username_password_authenticate(reader, writer)
        #     if not auth_success:
        #         self.logger.error("Authentication failed")
        #         writer.close()
        #         await writer.wait_closed()
        #         return
        else:
            # No acceptable method found, close the connection
            self.logger.error("No acceptable authentication method found")
            await quick_close(b'\x05\xFF\x00\x01\x00\x00\x00\x00\x00\x00')  # No acceptable methods
            return

        # Read the connection request
        data = await reader.read(4)
        if len(data) != 4:
            self.logger.error("Invalid connection request")
            await quick_close(b'\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')  # Command not supported
            return

        version, cmd, reserved, address_type = struct.unpack('!BBBB', data)

        if cmd != 1:  # 1 for CONNECT
            self.logger.error("Unsupported command")
            await quick_close(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')  # Command not supported
            return

        # # Pseudo-code for handling a BIND command
        # if cmd == 2:  # BIND
        #     # bind_address and bind_port are from the client request
        #     external_socket = await bind_and_listen(bind_address, bind_port)
        #     server_reply_address, server_reply_port = external_socket.getsockname()
        #     # Send server's chosen address and port back to the client
        #     send_bind_reply_to_client(server_reply_address, server_reply_port)
        #     # Wait for an external connection
        #     external_conn, external_addr = await external_socket.accept()
        #     # Notify client of the external connection details
        #     notify_client_of_external_connection(external_addr)
        #     # Proceed to relay data between client and external connection

        # # Pseudo-code for handling a UDP ASSOCIATE command
        # if cmd == 3:  # UDP ASSOCIATE
        #     # client's address and port are what?
        #     udp_socket = await allocate_udp_port()
        #     socks_server_udp_address, socks_server_udp_port = udp_socket.getsockname()
        #     # Send SOCKS server's UDP address and port back to the client
        #     send_udp_associate_reply_to_client(socks_server_udp_address, socks_server_udp_port)
        #     # Listen for UDP datagrams from the client and relay them accordingly
        #     while True:
        #         data, addr = await udp_socket.recvfrom()
        #         if is_datagram_for_client(data):
        #             relay_datagram_to_final_destination(data, addr)
        #         else:
        #             relay_datagram_to_client(data, addr)

        if address_type == 1:  # IPv4
            address = await reader.readexactly(4)
            tunnel_host = '.'.join(str(byte) for byte in address)
        elif address_type == 3:  # Domain name
            domain_length = ord(await reader.readexactly(1))
            tunnel_host = await reader.readexactly(domain_length)
            tunnel_host = tunnel_host.decode()
        elif address_type == 4:  # IPv6
            address = await reader.readexactly(16)
            tunnel_host = ':'.join(str(byte) for byte in address)
        else:
            self.logger.error("Unsupported address type")
            await quick_close(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')  # Address type not supported
            return

        tunnel_port = int.from_bytes(await reader.readexactly(2), 'big')

        # Send open connection message with con_no. this is required to be sent to start the connection
        data = int.to_bytes(connection_no, CONNECTION_NO_LENGTH, byteorder='big')
        tunnel_host_bytes = tunnel_host.encode()
        data += int.to_bytes(len(tunnel_host_bytes), CONNECTION_NO_LENGTH, byteorder='big')
        data += tunnel_host_bytes
        data += int.to_bytes(tunnel_port, PORT_LENGTH, byteorder='big')
        await self.send_control_message(ControlMessage.OpenConnection, data)
