#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""Registry mapping MCP capabilities to the tools they expose.

A *capability* is the unit the human toggles on/off (mirrors the "Allowed Tools" cards in
the vault AI-Access UI). Each capability registers one MCP *tool* with a JSON-Schema
input definition and a handler from :mod:`tools`. High-risk PAM capabilities default to
disabled and support guardrails.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Dict, List

from . import tools


@dataclass
class Capability:
    name: str
    title: str
    description: str
    tool_name: str
    input_schema: Dict
    handler: Callable
    high_risk: bool = False
    # Whether record/folder scope applies to this capability.
    scoped: bool = False
    # Guardrail keys this capability understands (for display/validation).
    guardrail_keys: List[str] = field(default_factory=list)


def _object(properties, required=None):
    schema = {'type': 'object', 'properties': properties}
    if required:
        schema['required'] = required
    return schema


# Ordered so help/status output is stable and grouped (Vault → KSM → PAM).
CAPABILITIES = OrderedDict()  # type: Dict[str, Capability]


def _register(cap):  # type: (Capability) -> None
    CAPABILITIES[cap.name] = cap


# ----- Vault / Secrets -----
_register(Capability(
    name='search_records',
    title='Search records',
    description='Search and list vault records the user has allowed.',
    tool_name='search_records',
    input_schema=_object({
        'query': {'type': 'string', 'description': 'Optional search text; omit to list all in-scope records.'},
        'limit': {'type': 'integer', 'description': 'Maximum results to return (default 50).'},
    }),
    handler=tools.search_records,
    scoped=True,
))

_register(Capability(
    name='read_secret',
    title='Read secrets',
    description="Read field values from records in folders you've allowed.",
    tool_name='read_secret',
    input_schema=_object({
        'record': {'type': 'string', 'description': 'Record UID or title.'},
        'field': {'type': 'string', 'description': 'Optional field-name filter (substring).'},
    }, required=['record']),
    handler=tools.read_secret,
    scoped=True,
))

_register(Capability(
    name='create_record',
    title='Create secrets',
    description='Save new records — passwords, API keys, notes — into the vault.',
    tool_name='create_record',
    input_schema=_object({
        'title': {'type': 'string'},
        'record_type': {'type': 'string', 'description': 'Record type (default "login").'},
        'folder': {'type': 'string', 'description': 'Destination folder UID (must be in scope).'},
        'notes': {'type': 'string'},
        'fields': {'type': 'array', 'items': {'type': 'string'},
                   'description': 'Field tokens, e.g. ["login=user@example.com", "password=..."].'},
    }, required=['title']),
    handler=tools.create_record,
    scoped=True,
))

_register(Capability(
    name='update_record',
    title='Update secrets',
    description='Update existing records.',
    tool_name='update_record',
    input_schema=_object({
        'record': {'type': 'string', 'description': 'Record UID or title.'},
        'title': {'type': 'string'},
        'notes': {'type': 'string'},
        'fields': {'type': 'array', 'items': {'type': 'string'}},
    }, required=['record']),
    handler=tools.update_record,
    scoped=True,
))

_register(Capability(
    name='share_record',
    title='Share a record',
    description='Control record sharing and one-time shares.',
    tool_name='share_record',
    input_schema=_object({
        'record': {'type': 'string', 'description': 'Record UID or title.'},
        'email': {'type': 'string', 'description': 'Target user (omit for one-time share).'},
        'action': {'type': 'string', 'enum': ['grant', 'revoke', 'owner'], 'description': 'Default "grant".'},
        'can_edit': {'type': 'boolean'},
        'can_share': {'type': 'boolean'},
        'one_time': {'type': 'boolean', 'description': 'Create a one-time share link instead.'},
        'name': {'type': 'string', 'description': 'One-time share name.'},
        'expire': {'type': 'string', 'description': 'One-time share expiration (e.g. 1d).'},
    }, required=['record']),
    handler=tools.share_record,
    scoped=True,
))

_register(Capability(
    name='share_folder',
    title='Share a folder',
    description='Control shared-folder permissions.',
    tool_name='share_folder',
    input_schema=_object({
        'folder': {'type': 'string', 'description': 'Shared folder UID.'},
        'email': {'type': 'string'},
        'action': {'type': 'string', 'enum': ['grant', 'revoke'], 'description': 'Default "grant".'},
        'can_edit': {'type': 'boolean'},
    }, required=['folder']),
    handler=tools.share_folder,
    scoped=True,
))

# ----- KSM -----
_register(Capability(
    name='ksm_manage_app',
    title='Control Secrets Manager applications',
    description='Create KSM apps and clients and manage access to applications and secrets.',
    tool_name='ksm_manage_app',
    input_schema=_object({
        'action': {'type': 'string', 'enum': ['app-create', 'client-add', 'share']},
        'name': {'type': 'string', 'description': 'App name (app-create).'},
        'app': {'type': 'string', 'description': 'App name or UID (client-add, share).'},
        'secret': {'type': 'string', 'description': 'Record/folder UID to share (share).'},
    }, required=['action']),
    handler=tools.ksm_manage_app,
))

# ----- PAM (high-risk; default disabled, guardrail-aware) -----
_register(Capability(
    name='pam_rotate',
    title='Execute KeeperPAM credential rotations',
    description='Rotate stored credentials on PAM resources, machines, and databases.',
    tool_name='pam_rotate',
    input_schema=_object({
        'record_uid': {'type': 'string'},
        'dry_run': {'type': 'boolean'},
    }, required=['record_uid']),
    handler=tools.pam_rotate,
    high_risk=True,
    guardrail_keys=['dry_run_only'],
))

_register(Capability(
    name='pam_launch_session',
    title='Launch sessions and tunnels',
    description='Open KeeperPAM sessions and encrypted tunnels to remote resources. '
                'Supports the just-in-time access-request workflow via reason/ticket.',
    tool_name='pam_launch_session',
    input_schema=_object({
        'record_uid': {'type': 'string'},
        'host': {'type': 'string'},
        'reason': {'type': 'string', 'description': 'JIT access-request reason.'},
        'ticket': {'type': 'string', 'description': 'JIT access-request ticket reference.'},
    }, required=['record_uid']),
    handler=tools.pam_launch_session,
    high_risk=True,
    guardrail_keys=['host_allowlist'],
))

_register(Capability(
    name='pam_exec_command',
    title='Execute remote commands on a PAM machine',
    description='Run shell commands on PAM machines via the gateway, with full gateway-side '
                'auditing. Requires the "pam action exec" command in this Commander build.',
    tool_name='pam_exec_command',
    input_schema=_object({
        'record_uid': {'type': 'string'},
        'command': {'type': 'string'},
        'host': {'type': 'string'},
    }, required=['record_uid', 'command']),
    handler=tools.pam_exec_command,
    high_risk=True,
    guardrail_keys=['host_allowlist'],
))

_register(Capability(
    name='pam_db_query',
    title='Execute database queries on a PAM database',
    description='Run read or write queries against PAM-managed databases via the gateway, with '
                'full gateway-side auditing. Requires the "pam action query" command in this build.',
    tool_name='pam_db_query',
    input_schema=_object({
        'record_uid': {'type': 'string'},
        'query': {'type': 'string'},
    }, required=['record_uid', 'query']),
    handler=tools.pam_db_query,
    high_risk=True,
))


def capability_names():  # type: () -> List[str]
    return list(CAPABILITIES.keys())


def get_capability(name):  # type: (str) -> Capability
    return CAPABILITIES.get(name)
