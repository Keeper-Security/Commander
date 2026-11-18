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

"""The items of an import JSON as `pam project update` needs them: the RAW dict of each item next to the object
the import parsers built from it.

`update` compares only the keys the user wrote, so it needs both: the raw item says what was written, the loaded
object holds the parsed, validated values. The type dispatch below is the one ``extend.map_records`` uses (kept
in step by ``unit-tests/pam/test_import_items.py``); this module does no I/O and creates no UIDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .base import (
    PAM_IMPORT_RESOURCE_TYPES,
    LoginUserObject,
    PamCloudResourceObject,
    PamDatabaseObject,
    PamDirectoryObject,
    PamMachineObject,
    PamRemoteBrowserObject,
    PamRotationParams,
    PamUserObject,
    SaasConfigurationObject,
)

KIND_RESOURCE = 'resource'
KIND_USER = 'user'
KIND_NESTED_USER = 'nested_user'

_USER_TYPES = ('login', 'pamUser', 'saasConfiguration')


@dataclass
class ImportItem:
    raw: Dict[str, Any]
    obj: Any
    kind: str
    parent: Optional['ImportItem'] = None
    record_type: str = ''
    # filled in by the matcher
    uid: str = ''
    status: str = ''
    message: str = ''
    children: List['ImportItem'] = field(default_factory=list)

    @property
    def title(self) -> str:
        return (getattr(self.obj, 'title', None) or self.raw.get('title') or '').strip()

    @property
    def login(self) -> str:
        return (getattr(self.obj, 'login', None) or '').strip()

    @property
    def ident(self) -> str:
        """Short text naming the item in messages: title, else login, else the uid / type."""
        label = self.title or self.login or str(self.raw.get('uid') or '') or self.record_type
        return f'"{label}"'


def user_type_of(user: Any) -> str:
    """The record type of a user item the way ``extend`` decides it (an explicit type, else guessed from keys)."""
    rt = str(user.get('type', '')) if isinstance(user, dict) else ''
    rt = next((x for x in _USER_TYPES if x.lower() == rt.lower()), rt)
    if rt not in _USER_TYPES and isinstance(user, dict):
        pam_keys = ('private_pem_key', 'distinguished_name', 'connect_database', 'managed', 'scripts', 'rotation_settings')
        if user.get('url'):
            rt = 'login'
        elif any(k in user for k in pam_keys):
            rt = 'pamUser'
    return next((x for x in _USER_TYPES if x.lower() == rt.lower()), 'login')


def _load_user(raw: Dict[str, Any], rotation_params: PamRotationParams) -> Any:
    rt = user_type_of(raw)
    if rt == 'login':
        return LoginUserObject.load(raw)
    if rt == 'saasConfiguration':
        return SaasConfigurationObject.load(raw)
    return PamUserObject.load(raw, rotation_params)


def _load_resource(raw: Dict[str, Any], rotation_params: PamRotationParams) -> Any:
    rt = str(raw.get('type', '')).strip().lower()
    loaders = {
        'pamdatabase': PamDatabaseObject, 'pamdirectory': PamDirectoryObject, 'pammachine': PamMachineObject,
        'pamremotebrowser': PamRemoteBrowserObject, 'pamcloudresource': PamCloudResourceObject,
    }
    cls = loaders.get(rt)
    return cls.load(raw, rotation_params) if cls else None


def load_items(pam_data: Dict[str, Any], pam_cfg_uid: str = '') -> tuple:
    """(items, problems): every resource, user and nested user of ``pam_data`` as an :class:`ImportItem`.

    ``problems`` are texts for items that cannot be used (an unknown resource type); the others are returned.
    """
    problems: List[str] = []
    profiles = pam_data.get('rotation_profiles') if isinstance(pam_data.get('rotation_profiles'), dict) else {}
    rotation_params = PamRotationParams(configUid=pam_cfg_uid, profiles=profiles)
    items: List[ImportItem] = []

    for raw in (pam_data.get('users') if isinstance(pam_data.get('users'), list) else []):
        if not isinstance(raw, dict):
            continue
        obj = _load_user(raw, rotation_params)
        if obj:
            items.append(ImportItem(raw, obj, KIND_USER, record_type=getattr(obj, 'type', '') or user_type_of(raw)))
    for raw in (pam_data.get('saas_configurations') if isinstance(pam_data.get('saas_configurations'), list) else []):
        if isinstance(raw, dict):
            obj = SaasConfigurationObject.load(raw)
            if obj:
                items.append(ImportItem(raw, obj, KIND_USER, record_type='saasConfiguration'))

    for raw in (pam_data.get('resources') if isinstance(pam_data.get('resources'), list) else []):
        if not isinstance(raw, dict):
            continue
        rt = str(raw.get('type', '')).strip()
        if rt.lower() not in (x.lower() for x in PAM_IMPORT_RESOURCE_TYPES):
            problems.append(f'Incorrect record type "{rt}" - should be one of {PAM_IMPORT_RESOURCE_TYPES}, '
                            f'"{str(raw.get("title", "")).strip()}" record skipped.')
            continue
        obj = _load_resource(raw, rotation_params)
        if not obj:
            continue
        resource = ImportItem(raw, obj, KIND_RESOURCE, record_type=getattr(obj, 'type', '') or rt)
        items.append(resource)
        # nested users: the loader keeps only pamUser items, in order
        nested_objs = list(getattr(obj, 'users', None) or [])
        for nested_raw in (raw.get('users') if isinstance(raw.get('users'), list) else []):
            if not isinstance(nested_raw, dict):
                continue
            if str(nested_raw.get('type') or 'pamUser').lower() != 'pamuser':
                continue
            if not nested_objs:
                break
            child = ImportItem(nested_raw, nested_objs.pop(0), KIND_NESTED_USER, parent=resource,
                               record_type='pamUser')
            resource.children.append(child)
            items.append(child)
    return items, problems
