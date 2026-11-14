#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Where does a key of the import JSON live in the vault?  (`pam project update`)

Pure data and small functions; no I/O. For one raw item (a resource or a user of the import / extend JSON) this
module answers:

* ``explicit_paths(raw)`` - the dotted paths the user WROTE. `update` compares the desired state only at these
  paths, so a JSON without ``port`` never resets the port in the vault (the loaders fill in defaults, so the loaded
  object cannot tell "written" from "defaulted").
* ``resolve(path, record_type, protocol)`` - the ``Target`` of one path: a record field, a graph item, an API
  object, a reference to another record, a file, or "protected / ignored".
* ``classify(raw, record_type)`` - all of that for one item, plus the paths that are not known (``unmapped``): the
  caller warns ``key X is not handled by update`` and never silently ignores them.
* ``removable_in_overwrite(target)`` - what ``--mode overwrite`` may remove (kept as a separate, conservative
  list; the final rule is a deferred owner decision).

How the table was built (spike 3c, 2026-11-13, see the plan): about 90% of the connection keys map by one rule
(``snake_case`` -> ``camelCase``), the rest are the explicit rows below. The key lists are checked against the
import parsers by ``unit-tests/pam/test_update_schema.py``, which loads the parsers with and without each key and
compares the output; a new import option without a row here makes that test fail.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

# Target kinds
KIND_RECORD = 'record'        # a field of the vault record
KIND_GRAPH = 'graph'          # an edge of the PAM graph (meta / jit_settings / ai_settings ...)
KIND_API = 'api'              # an object kept by a router API (rotation, workflow)
KIND_REF = 'ref'              # a reference to another record (credentials), stored as UIDs
KIND_FILES = 'files'          # attachments / scripts (file records; own rules)
KIND_NESTED = 'nested'        # nested records (``users``): each is diffed as a record of its own
KIND_PROTECTED = 'protected'  # identity / owned by something else: never changed by update
KIND_IGNORED = 'ignored'      # accepted by the import and deliberately not used (legacy or unsupported)

# Record fields live in these places of the record JSON
SCOPE_STANDARD = 'standard'   # title, notes
SCOPE_TYPED = 'typed'         # "fields"
SCOPE_CUSTOM = 'custom'       # "custom"
SCOPE_ANY = 'any'             # typed or custom, looked up by field type (the record type template decides)

RESOURCE_TYPES = ('pamMachine', 'pamDatabase', 'pamDirectory')
RBI_TYPES = ('pamRemoteBrowser', 'pamCloudResource')
USER_TYPES = ('pamUser',)
LOGIN_TYPES = ('login', 'saasConfiguration')

FAMILY_RESOURCE = 'resource'
FAMILY_RBI = 'rbi'
FAMILY_USER = 'user'
FAMILY_LOGIN = 'login'


@dataclass(frozen=True)
class Target:
    """What one raw path maps to."""
    kind: str
    field: str = ''          # RECORD: 'title' / 'notes', or the typed / custom field TYPE ('text', 'pamHostname' ...)
    label: str = ''          # RECORD: the field label ('operatingSystem' ...), '' when the type is enough
    sub: str = ''            # RECORD: dotted path inside a JSON-valued field ('connection.port')
    scope: str = SCOPE_TYPED
    comparator: str = ''     # GRAPH / API / REF: the name update_diff dispatches on
    key: str = ''            # GRAPH / API: key inside the compared object ('allowedSettings.portForwards')
    secret: bool = False     # value is never printed (passwords, keys, OTP seeds)
    note: str = ''

    @property
    def writable(self) -> bool:
        return self.kind in (KIND_RECORD, KIND_GRAPH, KIND_API, KIND_REF)


@dataclass
class Classification:
    mapped: Dict[str, Target]
    unmapped: List[str]


# --------------------------------------------------------------------------------------------------------------
# explicit paths
# --------------------------------------------------------------------------------------------------------------

def explicit_paths(raw: Any, prefix: str = '') -> List[str]:
    """Dotted paths of the keys written in *raw* (a dict). A list is ONE leaf; an empty dict is a leaf too.

    ``{"pam_settings": {"connection": {"port": "22"}}}`` -> ``['pam_settings.connection.port']``
    """
    if not isinstance(raw, dict):
        return [prefix] if prefix else []
    if not raw:
        return [prefix] if prefix else []
    paths: List[str] = []
    for key, value in raw.items():
        path = f'{prefix}.{key}' if prefix else str(key)
        if isinstance(value, dict) and value:
            paths.extend(explicit_paths(value, path))
        else:
            paths.append(path)
    return sorted(paths)


# --------------------------------------------------------------------------------------------------------------
# naming
# --------------------------------------------------------------------------------------------------------------

def camel(name: str) -> str:
    """``enable_touch`` -> ``enableTouch`` (the rule the import code follows for almost every key)."""
    head, *rest = name.split('_')
    return head + ''.join(part[:1].upper() + part[1:] for part in rest)


def family_of(record_type: str) -> Optional[str]:
    if record_type in RESOURCE_TYPES:
        return FAMILY_RESOURCE
    if record_type in RBI_TYPES:
        return FAMILY_RBI
    if record_type in USER_TYPES:
        return FAMILY_USER
    if record_type in LOGIN_TYPES:
        return FAMILY_LOGIN
    return None


# --------------------------------------------------------------------------------------------------------------
# top-level rows of the record (source of truth: pam_record_build._machine_kwargs / _rbi_kwargs / _pam_user_kwargs)
# --------------------------------------------------------------------------------------------------------------

def _std(field_name: str) -> Target:
    return Target(KIND_RECORD, field=field_name, scope=SCOPE_STANDARD)


def _text(label: str) -> Target:
    return Target(KIND_RECORD, field='text', label=label)


def _typed(field_type: str, label: str = '', **kwargs) -> Target:
    return Target(KIND_RECORD, field=field_type, label=label, **kwargs)


_IDENTITY = Target(KIND_PROTECTED, note='identity of the record; update never changes it')
_FILES = Target(KIND_FILES, note='file records: replaced only by the file rules (name + size), see --skip-attachments')

COMMON_ROWS: Dict[str, Target] = {
    'title': _std('title'),
    'notes': _std('notes'),
    'otp': _typed('oneTimeCode', secret=True),
    'uid': _IDENTITY,
    'type': _IDENTITY,
    'folder_path': Target(KIND_PROTECTED, note='location of the record; update never moves a record'),
    'attachments': _FILES,
    'scripts': _FILES,
}

RESOURCE_ROWS: Dict[str, Target] = {
    'host': _typed('pamHostname', sub='hostName'),
    'port': _typed('pamHostname', sub='port'),
    'ssl_verification': _typed('checkbox', 'sslVerification'),
    'operating_system': _text('operatingSystem'),
    'instance_name': _text('instanceName'),
    'instance_id': _text('instanceId'),
    'provider_group': _text('providerGroup'),
    'provider_region': _text('providerRegion'),
    # pamDatabase
    'use_ssl': _typed('checkbox', 'useSSL'),
    'database_id': _text('databaseId'),
    'database_type': _typed('databaseType'),
    # pamDirectory
    'domain_name': _text('domainName'),
    'alternative_ips': _typed('multiline', 'alternativeIPs'),
    'directory_id': _text('directoryId'),
    'directory_type': _typed('directoryType'),
    'user_match': _text('userMatch'),
    'users': Target(KIND_NESTED, note='nested pamUser records: each one is diffed as a record of its own'),
    # legacy format: the import parses these and ignores them (use users[] instead)
    'login': Target(KIND_IGNORED, note='legacy: create a pamUser in users[] instead'),
    'password': Target(KIND_IGNORED, note='legacy: create a pamUser in users[] instead'),
    'private_pem_key': Target(KIND_IGNORED, note='legacy: create a pamUser in users[] instead'),
}

RBI_ROWS: Dict[str, Target] = {
    'url': _typed('rbiUrl'),
    'account_identifier': _typed('accountNumber', 'pamCloudResourceAccountIdentifier'),
    'users': Target(KIND_NESTED, note='nested records: each one is diffed as a record of its own'),
}

USER_ROWS: Dict[str, Target] = {
    'login': _typed('login'),
    'password': _typed('password', secret=True),
    'private_pem_key': _typed('secret', 'privatePEMKey', secret=True),
    'distinguished_name': _text('distinguishedName'),
    'connect_database': _text('connectDatabase'),
    'managed': _typed('checkbox', 'managed'),
    'custom': Target(KIND_RECORD, field='text', scope=SCOPE_CUSTOM,
                     note='list of {label, value} custom text fields; compared by label'),
}

LOGIN_ROWS: Dict[str, Target] = {
    'login': _typed('login'),
    'password': _typed('password', secret=True),
    'url': _typed('url'),
    'custom': Target(KIND_RECORD, field='text', scope=SCOPE_CUSTOM,
                     note='list of {label, value} custom text fields; compared by label'),
}

FAMILY_ROWS: Dict[str, Dict[str, Target]] = {
    FAMILY_RESOURCE: RESOURCE_ROWS,
    FAMILY_RBI: RBI_ROWS,
    FAMILY_USER: USER_ROWS,
    FAMILY_LOGIN: LOGIN_ROWS,
}

# --------------------------------------------------------------------------------------------------------------
# pam_settings.connection (resources: custom field `pamSettings`; RBI: field `pamRemoteBrowserSettings`)
# --------------------------------------------------------------------------------------------------------------

# Every raw key the connection parsers accept (all protocols, RBI `http` included). Checked by the drift test.
CONNECTION_KEYS = frozenset('''
accept_language allow_file_downloads allow_file_uploads allow_supply_user allow_url_manipulation
allowed_resource_url_patterns allowed_url_patterns audio_bps audio_channels audio_sample_rate audio_servername
autofill_targets backspace ca_certificate cef_log_level cert_fingerprints cert_tofu client_certificate client_key
client_name clipboard_encoding color_depth color_scheme command compress_level console console_audio container
cursor db_connection_method default_database destination_host destination_port disable_audio
disable_authentication disable_bitmap_caching disable_cert_hostname_verification disable_copy disable_csv_export
disable_csv_import disable_display_resize disable_download disable_dynamic_resizing disable_gfx
disable_glyph_caching disable_offscreen_caching disable_paste disable_server_input disable_upload disable_webauthn
dpi drive_redirection_name drive_redirection_path enable_audio enable_audio_input enable_desktop_composition
enable_font_smoothing enable_full_window_drag enable_menu_animations enable_printing enable_theming enable_touch
enable_wallpaper enable_webgl encodings exec_command font_name font_size force_encryption force_lossless
func_keys_and_keypad height ignore_server_cert initial_program load_balance_info locale login_failure_regex
login_success_regex namespace normalize_clipboard password_regex pod_name port preconnection_blob preconnection_id
printer_name protocol protocol_version public_host_key quality_level read_only recording_exclude_mouse
recording_exclude_output recording_exclude_touch recording_include_clipboard recording_include_keys remote_app
remote_app_args remote_app_dir resize_method scrollback security server_alive_interval server_layout
session_persistence static_channels suppress_js_dialogs swap_red_blue terminal_type timeout timezone use_ssl
username_regex width wol_broadcast_addr wol_mac_addr wol_send_packet wol_udp_port wol_wait_time
'''.split())

# Keys inside the nested `connection.sftp` object.
SFTP_KEYS = frozenset('''
enable_sftp sftp_disable_download sftp_disable_upload sftp_keepalive_interval sftp_root_directory sftp_timeout
sftp_upload_directory
'''.split())

# Reference keys: titles / logins of other records in the import JSON, stored as UIDs (and, for the administrative
# and launch credentials, as flags on the ACL edges of the graph).
CONNECTION_REFS: Dict[str, Target] = {
    'administrative_credentials': Target(KIND_REF, comparator='admin_credential',
                                         note='record: connection.userRecords; graph: is_admin on the ACL edge'),
    'launch_credentials': Target(KIND_REF, comparator='launch_credential',
                                 note='graph: is_launch_credential on the ACL edge (single slot)'),
    'autofill_credentials': Target(KIND_REF, comparator='http_credentials',
                                   note='record: connection.httpCredentialsUid (single slot)'),
}
SFTP_REFS: Dict[str, Target] = {
    'sftp_resource': Target(KIND_REF, comparator='sftp_resource',
                            note='record: connection.sftp.sftpResourceUid'),
    'sftp_user_credentials': Target(KIND_REF, comparator='sftp_user',
                                    note='record: connection.sftp.sftpUserUid (single slot)'),
}

# raw key -> output key, when it is NOT camelCase(raw key). A dict value depends on the protocol
# ('' = every other protocol). Found by the spike; kept honest by the drift test.
CONNECTION_RENAMES: Dict[str, Any] = {
    'autofill_targets': 'autofillConfiguration',
    'ca_certificate': {'kubernetes': 'caCert', '': 'caCertificate'},
    'client_certificate': 'clientCert',
    'default_database': 'database',
    'destination_host': 'destHost',
    'destination_port': 'destPort',
    'disable_authentication': 'disableAuth',
    'disable_dynamic_resizing': 'resizeMethod',      # legacy alias of resize_method
    'ignore_server_cert': {'http': 'ignoreInitialSslCert', '': 'ignoreCert'},
    'pod_name': 'pod',
    'public_host_key': 'hostKey',
    'use_ssl': 'useSSL',
}
SFTP_RENAMES: Dict[str, str] = {
    'sftp_upload_directory': 'sftpDirectory',
    'sftp_keepalive_interval': 'sftpServerAliveInterval',
}

PORT_FORWARD_KEYS = frozenset('''
port reuse_port use_specified_local_port local_port allow_keeper_db_proxy allow_keeper_rdp_proxy
allow_keeper_ssh_proxy
'''.split())
PORT_FORWARD_RENAMES: Dict[str, str] = {
    'allow_keeper_db_proxy': 'allowKeeperDBProxy',
    'allow_keeper_rdp_proxy': 'allowKeeperRDPProxy',
    'allow_keeper_ssh_proxy': 'allowKeeperSSHProxy',
}


def connection_output_key(raw_key: str, protocol: str = '') -> str:
    """The key of the vault ``connection`` object a raw connection key is written to."""
    rename = CONNECTION_RENAMES.get(raw_key)
    if isinstance(rename, dict):
        return rename.get(protocol, rename.get('', camel(raw_key)))
    return rename if rename else camel(raw_key)


def sftp_output_key(raw_key: str) -> str:
    return SFTP_RENAMES.get(raw_key) or camel(raw_key)


def port_forward_output_key(raw_key: str) -> str:
    return PORT_FORWARD_RENAMES.get(raw_key) or camel(raw_key)


# --------------------------------------------------------------------------------------------------------------
# pam_settings.options (graph / API)
# --------------------------------------------------------------------------------------------------------------

# options.<flag> (on | off | default) -> key of the resource `meta` edge (source: base.parse_command_options)
OPTION_FLAGS: Dict[str, Tuple[str, str]] = {
    # flag: (meta key, note)
    'rotation': ('allowedSettings.rotation', ''),
    'connections': ('allowedSettings.connections', ''),
    'tunneling': ('allowedSettings.portForwards', ''),
    'remote_browser_isolation': ('allowedSettings.remoteBrowserIsolation', ''),
    'graphical_session_recording': ('allowedSettings.sessionRecording', ''),
    'text_session_recording': ('allowedSettings.typescriptRecording', ''),
    'ai_threat_detection': ('allowedSettings.aiEnabled', ''),
    'ai_terminate_session_on_detection': ('allowedSettings.aiSessionTerminate', ''),
    'update_services': ('no_update_services', 'inverted: update_services on == no_update_services false'),
}
# `locked` is owned by the back-end (see base.DagSettingsObject); `resource` names the configuration (external).
OPTION_IGNORED = {
    'resource': 'the PAM configuration the resource belongs to; update never moves a resource',
    'locked': 'owned by the back-end (KeeperAI session lock); never read or written by import / extend / update',
}


def _connection_row(rest: List[str], family: str, protocol: str) -> Optional[Target]:
    """``rest`` = the path below ``pam_settings.connection`` (may be empty: the whole object)."""
    field_type, scope, root = (
        ('pamSettings', SCOPE_CUSTOM, 'connection') if family == FAMILY_RESOURCE
        else ('pamRemoteBrowserSettings', SCOPE_ANY, 'connection'))
    if not rest:
        return Target(KIND_RECORD, field=field_type, sub=root, scope=scope, note='the whole connection object')
    key = rest[0]
    if key == 'sftp':
        if len(rest) == 1:
            return Target(KIND_RECORD, field=field_type, sub=f'{root}.sftp', scope=scope, note='the whole sftp object')
        if len(rest) > 2:
            return None
        sub = rest[1]
        if sub in SFTP_REFS:
            return SFTP_REFS[sub]
        if sub in SFTP_KEYS:
            return Target(KIND_RECORD, field=field_type, sub=f'{root}.sftp.{sftp_output_key(sub)}', scope=scope)
        return None
    if len(rest) > 1:
        return None
    if key == 'rotate_creds_on_session_termination' and family == FAMILY_RESOURCE:
        return Target(KIND_GRAPH, comparator='meta', key='rotateOnTermination',
                      note='read from the connection dict, stored in the resource meta, not in the record')
    if key in CONNECTION_REFS:
        return CONNECTION_REFS[key]
    if key in CONNECTION_KEYS:
        return Target(KIND_RECORD, field=field_type, sub=f'{root}.{connection_output_key(key, protocol)}', scope=scope)
    return None


def _options_row(rest: List[str], family: str) -> Optional[Target]:
    """``rest`` = the path below ``pam_settings.options``."""
    if not rest:
        return Target(KIND_GRAPH, comparator='meta', note='the whole options object')
    key = rest[0]
    if key in OPTION_IGNORED and len(rest) == 1:
        return Target(KIND_IGNORED, note=OPTION_IGNORED[key])
    if key in OPTION_FLAGS and len(rest) == 1:
        meta_key, note = OPTION_FLAGS[key]
        if key == 'update_services' and family == FAMILY_RBI:
            return Target(KIND_IGNORED, note='update_services does not apply to remote browsers')
        return Target(KIND_GRAPH, comparator='meta', key=meta_key, note=note)
    if key == 'jit_settings':
        if family == FAMILY_RBI:
            return Target(KIND_IGNORED, note='jit_settings is not supported for remote browsers')
        return Target(KIND_GRAPH, comparator='jit_settings', key='.'.join(rest[1:]))
    if key == 'ai_settings':
        return Target(KIND_GRAPH, comparator='ai_settings', key='.'.join(rest[1:]))
    if key == 'workflow':
        return Target(KIND_API, comparator='workflow', key='.'.join(rest[1:]))
    return None


def _pam_settings_row(rest: List[str], family: str, protocol: str) -> Optional[Target]:
    if not rest:
        return None
    head = rest[0]
    if head == 'connection':
        return _connection_row(rest[1:], family, protocol)
    if head == 'options':
        return _options_row(rest[1:], family)
    if family == FAMILY_RESOURCE:
        if head == 'allow_supply_host' and len(rest) == 1:
            return Target(KIND_RECORD, field='pamSettings', sub='allowSupplyHost', scope=SCOPE_CUSTOM)
        if head == 'port_forward':
            if len(rest) == 1:
                return Target(KIND_RECORD, field='pamSettings', sub='portForward', scope=SCOPE_CUSTOM,
                              note='the whole port_forward object')
            if len(rest) == 2 and rest[1] in PORT_FORWARD_KEYS:
                return Target(KIND_RECORD, field='pamSettings', scope=SCOPE_CUSTOM,
                              sub=f'portForward.{port_forward_output_key(rest[1])}')
    return None


# --------------------------------------------------------------------------------------------------------------
# resolution
# --------------------------------------------------------------------------------------------------------------

def resolve(path: str, record_type: str, protocol: str = '') -> Optional[Target]:
    """The ``Target`` of the raw *path* of an item of *record_type*, or None when update does not know the key."""
    family = family_of(record_type)
    if family is None:
        return None
    if path in COMMON_ROWS:
        return COMMON_ROWS[path]
    rows = FAMILY_ROWS[family]
    if path in rows:
        return rows[path]
    parts = path.split('.')
    if family in (FAMILY_RESOURCE, FAMILY_RBI) and parts[0] == 'pam_settings':
        return _pam_settings_row(parts[1:], family, protocol)
    if family == FAMILY_USER and parts[0] == 'rotation_settings':
        return Target(KIND_API, comparator='rotation', key='.'.join(parts[1:]),
                      note='rotation settings of the user: compared through the rotation cache')
    return None


def protocol_of(raw: Dict[str, Any]) -> str:
    """The connection protocol written in the raw item ('' when none)."""
    try:
        protocol = raw['pam_settings']['connection']['protocol']
    except (KeyError, TypeError):
        return ''
    return str(protocol).lower() if isinstance(protocol, str) else ''


def classify(raw: Dict[str, Any], record_type: str = '') -> Classification:
    """Map every explicit path of *raw* to its target; unknown paths are returned in ``unmapped``."""
    rtype = record_type or (raw.get('type') if isinstance(raw, dict) and isinstance(raw.get('type'), str) else '')
    protocol = protocol_of(raw) if isinstance(raw, dict) else ''
    mapped: Dict[str, Target] = {}
    unmapped: List[str] = []
    for path in explicit_paths(raw):
        target = resolve(path, rtype, protocol)
        if target is None:
            unmapped.append(path)
        else:
            mapped[path] = target
    return Classification(mapped=mapped, unmapped=unmapped)


def unmapped_warning(path: str, title: str = '') -> str:
    who = f'"{title}": ' if title else ''
    return f'{who}key "{path}" is not handled by update (ignored)'


# --------------------------------------------------------------------------------------------------------------
# overwrite
# --------------------------------------------------------------------------------------------------------------

# PROVISIONAL (the final `overwrite` rule - Rule A / Rule B - is a deferred owner decision). Kept apart from the
# mapping on purpose, so changing it does not touch the mapping. Only RECORD fields can be removed, and never
# these: the title and the host / port (a resource without them is broken).
_NEVER_REMOVED_FIELDS = ('title', 'pamHostname', 'rbiUrl')


def removable_in_overwrite(target: Target) -> bool:
    """May ``--mode overwrite`` remove this value when it is absent from the JSON?"""
    if target.kind != KIND_RECORD:
        return False
    if target.field in _NEVER_REMOVED_FIELDS:
        return False
    return not target.secret


def describe(target: Target) -> str:
    """Short text for the report: where the value lives."""
    if target.kind == KIND_RECORD:
        if target.scope == SCOPE_STANDARD:
            return target.field
        text = target.field + (f' "{target.label}"' if target.label else '')
        return f'{text}.{target.sub}' if target.sub else text
    if target.kind in (KIND_GRAPH, KIND_API):
        return f'{target.comparator}.{target.key}' if target.key else target.comparator
    if target.kind == KIND_REF:
        return f'reference ({target.comparator})'
    return target.kind
