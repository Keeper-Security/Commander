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
"""Persistence and model for MCP access configuration.

The configuration (master toggle, per-capability grants/scope/guardrails, and the list
of approved client agents) is stored as JSON inside a dedicated Keeper vault record.

SECURITY BOUNDARY: the MCP server reads this record at startup but the tools it exposes
are forbidden from reading, modifying, sharing, or deleting it (the record UID is added
to a deny-set). Only interactive, human-authenticated ``mcp`` management commands write
to it. This prevents an agent from escalating its own privileges.
"""

import datetime
import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .. import utils, vault, record_management, vault_extensions
from ..params import KeeperParams

# Well-known title of the vault record that stores MCP configuration.
CONFIG_RECORD_TITLE = 'Keeper Commander MCP Access'
# Custom field (type=secret) label that holds the JSON document.
CONFIG_FIELD_LABEL = 'mcp_config'
# Schema version of the JSON document, for forward-compatible migrations.
CONFIG_SCHEMA_VERSION = 1


def _now():  # type: () -> datetime.datetime
    return datetime.datetime.now(datetime.timezone.utc)


def hash_token(token):  # type: (str) -> str
    """Return the SHA-256 hex digest of a client token. Only the hash is persisted."""
    return hashlib.sha256(token.strip().encode('utf-8')).hexdigest()


@dataclass
class CapabilityGrant:
    """A globally-enabled capability with optional scope and guardrails."""
    enabled: bool = False
    # scope: {'folders': [uid, ...], 'records': [uid, ...]} — empty/absent means unscoped.
    scope: Dict[str, List[str]] = field(default_factory=dict)
    # guardrails: capability-specific constraints, e.g. {'dry_run_only': True}.
    guardrails: Dict[str, object] = field(default_factory=dict)

    def to_dict(self):
        d = {'enabled': self.enabled}
        if self.scope:
            d['scope'] = self.scope
        if self.guardrails:
            d['guardrails'] = self.guardrails
        return d

    @classmethod
    def from_dict(cls, d):  # type: (dict) -> CapabilityGrant
        d = d or {}
        return cls(
            enabled=bool(d.get('enabled', False)),
            scope=dict(d.get('scope') or {}),
            guardrails=dict(d.get('guardrails') or {}),
        )


@dataclass
class MCPClient:
    """An approved AI client agent ("Connected Agent")."""
    client_id: str
    name: str
    token_hash: str
    created: str
    expiration: Optional[str] = None   # ISO timestamp; None == never expires
    revoked: bool = False
    # Per-client capability subset (list of capability names). None == inherit globally-enabled.
    grants: Optional[List[str]] = None

    def is_expired(self):  # type: () -> bool
        if not self.expiration:
            return False
        try:
            exp = datetime.datetime.fromisoformat(self.expiration)
        except ValueError:
            return True
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=datetime.timezone.utc)
        return _now() > exp

    def is_active(self):  # type: () -> bool
        return not self.revoked and not self.is_expired()

    def to_dict(self):
        return {
            'client_id': self.client_id,
            'name': self.name,
            'token_hash': self.token_hash,
            'created': self.created,
            'expiration': self.expiration,
            'revoked': self.revoked,
            'grants': self.grants,
        }

    @classmethod
    def from_dict(cls, d):  # type: (dict) -> MCPClient
        return cls(
            client_id=d.get('client_id') or uuid.uuid4().hex,
            name=d.get('name') or '',
            token_hash=d.get('token_hash') or '',
            created=d.get('created') or _now().isoformat(),
            expiration=d.get('expiration'),
            revoked=bool(d.get('revoked', False)),
            grants=d.get('grants'),
        )


@dataclass
class MCPConfig:
    """In-memory representation of the MCP access configuration."""
    enabled: bool = False
    capabilities: Dict[str, CapabilityGrant] = field(default_factory=dict)
    clients: List[MCPClient] = field(default_factory=list)
    # UID of the vault record this config was loaded from (None if not yet persisted).
    # This is the self-protection boundary used by the server's deny-set.
    config_record_uid: Optional[str] = None

    # ----- serialization -----
    def to_json(self):  # type: () -> str
        doc = {
            'version': CONFIG_SCHEMA_VERSION,
            'enabled': self.enabled,
            'capabilities': {name: grant.to_dict() for name, grant in self.capabilities.items()},
            'clients': [c.to_dict() for c in self.clients],
        }
        return json.dumps(doc, indent=2)

    @classmethod
    def from_json(cls, text):  # type: (str) -> MCPConfig
        doc = json.loads(text) if text else {}
        caps = {name: CapabilityGrant.from_dict(val)
                for name, val in (doc.get('capabilities') or {}).items()}
        clients = [MCPClient.from_dict(c) for c in (doc.get('clients') or [])]
        return cls(enabled=bool(doc.get('enabled', False)), capabilities=caps, clients=clients)

    # ----- client lookups -----
    def find_client(self, identifier):  # type: (str) -> Optional[MCPClient]
        """Find a client by client_id or (case-insensitive) name."""
        for c in self.clients:
            if c.client_id == identifier or c.name.casefold() == identifier.casefold():
                return c
        return None

    def validate_token(self, token):  # type: (str) -> Optional[MCPClient]
        """Constant-time match of a presented token against active clients."""
        if not token:
            return None
        presented = hash_token(token)
        for c in self.clients:
            if c.token_hash and hmac.compare_digest(presented, c.token_hash) and c.is_active():
                return c
        return None

    def effective_capabilities(self, client):  # type: (MCPClient) -> Dict[str, CapabilityGrant]
        """Capabilities that are globally enabled AND granted to this client."""
        result = {name: grant for name, grant in self.capabilities.items() if grant.enabled}
        if client.grants is not None:
            allowed = {g.strip() for g in client.grants}
            result = {name: grant for name, grant in result.items() if name in allowed}
        return result


# --------------------------------------------------------------------------------------
# Vault record persistence
# --------------------------------------------------------------------------------------

def _find_config_record_uid(params):  # type: (KeeperParams) -> Optional[str]
    """Return the UID of the dedicated config record, matched by exact title."""
    for record in vault_extensions.find_records(params, CONFIG_RECORD_TITLE):
        if record.title == CONFIG_RECORD_TITLE:
            return record.record_uid
    return None


def load_config(params):  # type: (KeeperParams) -> MCPConfig
    """Load MCP configuration from the dedicated vault record.

    Returns a default (disabled, empty) config if no record exists yet. Always sets
    ``config_record_uid`` when a record is present so the server can self-protect.
    """
    record_uid = _find_config_record_uid(params)
    if not record_uid:
        return MCPConfig()

    record = vault.KeeperRecord.load(params, record_uid)
    config = MCPConfig()
    if isinstance(record, vault.TypedRecord):
        field_obj = record.get_typed_field('secret', CONFIG_FIELD_LABEL)
        text = field_obj.get_default_value(str) if field_obj else None
        if text:
            try:
                config = MCPConfig.from_json(text)
            except (ValueError, json.JSONDecodeError) as e:
                logging.warning('MCP config record "%s" is corrupted: %s', record_uid, e)
    config.config_record_uid = record_uid
    return config


def save_config(params, config):  # type: (KeeperParams, MCPConfig) -> str
    """Persist MCP configuration to the dedicated vault record, creating it if needed.

    Returns the record UID. Updates ``config.config_record_uid`` in place.
    """
    record_uid = config.config_record_uid or _find_config_record_uid(params)
    payload = config.to_json()

    if record_uid:
        record = vault.KeeperRecord.load(params, record_uid)
        if not isinstance(record, vault.TypedRecord):
            raise Exception(f'MCP config record {record_uid} is not a typed record')
        existing = record.get_typed_field('secret', CONFIG_FIELD_LABEL)
        if existing:
            existing.value = [payload]
        else:
            record.custom.append(vault.TypedField.new_field('secret', payload, CONFIG_FIELD_LABEL))
        record_management.update_record(params, record)
    else:
        record = vault.KeeperRecord.create(params, 'login')
        record.record_uid = utils.generate_uid()
        record.record_key = utils.generate_aes_key()
        record.title = CONFIG_RECORD_TITLE
        record.type_name = 'login'
        record.custom.append(vault.TypedField.new_field('secret', payload, CONFIG_FIELD_LABEL))
        record_management.add_record_to_folder(params, record)
        record_uid = record.record_uid

    from .. import api
    params.sync_data = True
    api.sync_down(params)
    config.config_record_uid = record_uid
    return record_uid


def new_client_token():  # type: () -> str
    """Generate a fresh client token (reuses the service-mode key generator)."""
    from ..service.util.api_key import generate_api_key
    return generate_api_key()
