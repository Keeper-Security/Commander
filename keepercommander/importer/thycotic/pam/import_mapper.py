#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

"""Map fetched Secret Server details onto a ``pam project import`` document (CyberArk safe-folder layout)."""

import copy
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from ...cyberark.pam.safe_folder_mapper import SafeFolderMapper
from .crosswalk import DEFAULT_CROSSWALK, FALLBACK_MAPPING
from .models import ChangerMapping
from .rotation_mapper import RotationMapper
from .secret_mapper import (
    DOMAIN_SLUGS, HOST_SLUGS, LOGIN_SLUGS, PASSWORD_SLUGS, PORT_SLUGS, PRIVATE_KEY_SLUGS, SecretMapper,
)

_RESOURCE_ORDER = {'pamDirectory': 0, 'pamMachine': 1, 'pamDatabase': 2}

# Built-in template ids, so a renamed Windows Account still maps to pamMachine.
_TEMPLATE_IDS = {
    6001: 'active directory account',
    6003: 'windows account',
    6007: 'unix account (ssh)',
    6008: 'unix account (telnet)',
}


@dataclass
class _Account:
    secret_id: int
    privileged_id: Optional[int]
    user: dict
    resource: dict
    folder_name: str = ''


class _Titles:
    def __init__(self):
        self._used = set()

    def take(self, name: str, secret_id: int) -> str:
        base = (name or '').strip() or f'Secret {secret_id}'
        if base.casefold() not in self._used:
            self._used.add(base.casefold())
            return base
        titled = f'{base} #{secret_id}'
        self._used.add(titled.casefold())
        return titled


def build_pam_import(folders: List[dict], project: str = 'Delinea Migration') -> dict:
    """Build the Keeper PAM import document from ``folder_secret_details()``."""
    secrets = list(_iter_secrets(folders))
    secrets.extend(_admin_secrets(secrets))
    titles = _Titles()
    accounts = [_account(secret, titles) for secret in secrets]
    accounts = [account for account in accounts if account is not None]
    resources = _merge(accounts)
    _apply_credentials(resources, accounts)
    safe_folders = _apply_safe_folders(resources, accounts, project or 'Delinea Migration')
    resources.sort(key=lambda resource: (_RESOURCE_ORDER.get(resource.get('type'), 9), resource.get('title') or ''))
    return {
        'project': project or 'Delinea Migration',
        'pam_configuration': {
            'environment': 'local',
            'connections': 'on',
            'rotation': 'on',
            'graphical_session_recording': 'on',
        },
        'pam_data': {'resources': resources, 'users': []},
        'safe_folders': safe_folders,
    }


def _iter_secrets(folders: Iterable[dict]) -> Iterable[dict]:
    seen = set()
    for folder in folders or []:
        folder_name = (folder or {}).get('folderName') or ''
        for secret in (folder or {}).get('secrets') or []:
            if not isinstance(secret, dict) or secret.get('id') is None or secret['id'] in seen:
                continue
            seen.add(secret['id'])
            stamped = dict(secret)
            stamped['_folder_name'] = folder_name
            yield stamped


def _admin_secrets(secrets: List[dict]) -> List[dict]:
    """Privileged accounts that were not themselves listed in a folder."""
    known = {secret['id'] for secret in secrets}
    added = []
    for secret in secrets:
        privileged_id = _privileged_id(secret)
        items = secret.get('administrativeCredentials')
        if privileged_id is None or privileged_id in known or not isinstance(items, list) or not items:
            continue
        known.add(privileged_id)
        login = SecretMapper.item_value({'items': items}, LOGIN_SLUGS)
        admin = {'items': items}
        if not SecretMapper.item_value(admin, HOST_SLUGS) and not SecretMapper.item_value(admin, DOMAIN_SLUGS):
            # No host / domain: place it on the resource it administers instead of dropping it.
            target = [item for item in secret.get('items') or []
                      if item.get('slug') in HOST_SLUGS + DOMAIN_SLUGS + PORT_SLUGS]
            admin = {'items': list(items) + target, 'secretTemplateId': secret.get('secretTemplateId'),
                     'secretTemplateName': secret.get('secretTemplateName')}
        added.append({
            **admin,
            'id': privileged_id,
            'name': login or f'Admin {privileged_id}',
            'autoChangeEnabled': False,
            'autoChangeSchedule': None,
            'privilegedAccountSecretId': None,
            'administrativeCredentials': None,
            '_folder_name': secret.get('_folder_name') or '',
        })
    return added


def _account(secret: dict, titles: _Titles) -> Optional[_Account]:
    mapping = _mapping_for(secret)
    if mapping.record_type not in ('pamDirectory', 'pamMachine', 'pamDatabase'):
        return None
    host = SecretMapper.item_value(secret, HOST_SLUGS)
    domain = SecretMapper.item_value(secret, DOMAIN_SLUGS)
    port = SecretMapper.item_value(secret, PORT_SLUGS)
    resource_name = domain if mapping.record_type == 'pamDirectory' and domain else host or secret.get('name') or ''
    resource_title = titles.take(resource_name, secret['id'])
    user_title = titles.take(secret.get('name') or '', secret['id'])
    user = _user(secret, mapping, user_title, domain)
    resource = _resource(mapping, resource_title, host, domain, port, secret)
    resource['users'] = [user]
    return _Account(secret['id'], _privileged_id(secret), user, resource, secret.get('_folder_name') or '')


def _user(secret: dict, mapping: ChangerMapping, title: str, domain: str) -> dict:
    login = SecretMapper.item_value(secret, LOGIN_SLUGS)
    if mapping.record_type == 'pamDirectory' and domain and login and '@' not in login and '\\' not in login:
        login = f'{login}@{domain}'
    user = {'type': 'pamUser', 'title': title, 'login': login}
    password = SecretMapper.item_value(secret, PASSWORD_SLUGS)
    private_key = SecretMapper.item_value(secret, PRIVATE_KEY_SLUGS)
    if password:
        user['password'] = password
    if private_key:
        user['private_pem_key'] = private_key
    rotation = _rotation_settings(secret, mapping)
    if rotation:
        user['rotation_settings'] = rotation
    return user


def _rotation_settings(secret: dict, mapping: ChangerMapping) -> Optional[dict]:
    if not mapping.rotation:
        return None
    enabled = bool(secret.get('autoChangeEnabled'))
    schedule = {'type': 'on-demand'}

    if enabled:
        cron = RotationMapper.schedule_to_cron(secret.get('autoChangeSchedule'))
        if cron:
            schedule = {'type': 'cron', 'cron': cron}
    return {
        'rotation': mapping.rotation,
        'enabled': 'on' if enabled else 'off',
        'schedule': schedule,
    }


def _resource(mapping: ChangerMapping, title: str, host: str, domain: str, port: str, secret: dict) -> dict:
    record_type = mapping.record_type
    resource = {'type': record_type, 'title': title, 'host': host or domain or title}
    protocol = mapping.protocol
    connection_port = port or mapping.port
    if record_type == 'pamDirectory':
        resource['host'] = domain or host or title
        resource['domain_name'] = resource['host']
        resource['directory_type'] = mapping.directory_type
        resource['port'] = port or mapping.port or '636'
        resource['use_ssl'] = str(resource['port']) == '636'
        if mapping.directory_type == 'active_directory':
            protocol = 'rdp'
            connection_port = '3389'
    elif record_type == 'pamMachine' and (mapping.operating_system or '').casefold() == 'windows':
        resource['port'] = '5986'
        resource['ssl_verification'] = True
        resource['operating_system'] = 'Windows'
        protocol = 'rdp'
        connection_port = port or '3389'
    elif record_type == 'pamMachine':
        resource['port'] = port or mapping.port or '22'
        if mapping.operating_system:
            resource['operating_system'] = mapping.operating_system
        connection_port = resource['port']
    elif record_type == 'pamDatabase':
        resource['port'] = port or mapping.port
        if mapping.database_type:
            resource['database_type'] = mapping.database_type
        connection_port = resource['port']
    resource['pam_settings'] = _pam_settings(protocol, connection_port, bool(secret.get('autoChangeEnabled')))
    return resource


def _pam_settings(protocol: Optional[str], port: str, rotation_enabled: bool) -> dict:
    settings = {
        'options': {
            'rotation': 'on' if rotation_enabled else 'off',
            'connections': 'on' if protocol else 'off',
            'tunneling': 'on' if protocol == 'rdp' else 'off',
            'graphical_session_recording': 'on' if protocol == 'rdp' else 'off',
        },
    }
    if protocol:
        connection = {'protocol': protocol, 'port': str(port or '')}
        if protocol == 'rdp':
            connection['security'] = 'any'
            connection['ignore_server_cert'] = True
        settings['connection'] = connection
    else:
        settings['connection'] = {}
    return settings


def _mapping_for(secret: dict) -> ChangerMapping:
    template_key = _TEMPLATE_IDS.get(secret.get('secretTemplateId'))
    if template_key:
        return DEFAULT_CROSSWALK[template_key]
    labels = [secret.get('secretTemplateName') or '', secret.get('name') or '']
    for label in labels:
        mapping = DEFAULT_CROSSWALK.get(label.casefold().strip())
        if mapping:
            return mapping
    for label in labels:
        folded = label.casefold()
        for key, mapping in DEFAULT_CROSSWALK.items():
            if key and key in folded:
                return mapping
    return _mapping_from_items(secret)


@dataclass(frozen=True)
class _SecretSignals:
    """Normalized item values used to infer a password changer."""
    host: str
    domain: str
    port: str
    name: str
    has_private_key: bool

    @classmethod
    def from_secret(cls, secret: dict) -> '_SecretSignals':
        return cls(
            host=SecretMapper.item_value(secret, HOST_SLUGS).casefold(),
            domain=SecretMapper.item_value(secret, DOMAIN_SLUGS).casefold(),
            port=SecretMapper.item_value(secret, PORT_SLUGS).strip(),
            name=(secret.get('name') or '').casefold(),
            has_private_key=bool(SecretMapper.item_value(secret, PRIVATE_KEY_SLUGS)),
        )


_Predicate = Callable[[_SecretSignals], bool]


def _always(_: _SecretSignals) -> bool:
    return True


@dataclass(frozen=True)
class _ChangerRule:
    """Matches when ``when`` holds and, if hints are set, any port / name term / host term / ``hint`` matches."""
    crosswalk_key: str
    when: _Predicate = _always
    ports: Tuple[str, ...] = ()
    name_terms: Tuple[str, ...] = ()
    host_terms: Tuple[str, ...] = ()
    hint: Optional[_Predicate] = None

    def matches(self, s: _SecretSignals) -> bool:
        if not self.when(s):
            return False
        if not (self.ports or self.name_terms or self.host_terms or self.hint):
            return True
        return (s.port in self.ports
                or any(term in s.name for term in self.name_terms)
                or any(term in s.host for term in self.host_terms)
                or bool(self.hint and self.hint(s)))


def _domain_only(s: _SecretSignals) -> bool:
    return bool(s.domain) and not s.host


def _has_host(s: _SecretSignals) -> bool:
    return bool(s.host)


# First match wins; order matters.
_CHANGER_RULES: Tuple[_ChangerRule, ...] = (
    _ChangerRule('unix account (ssh key rotation)', when=lambda s: s.has_private_key),
    _ChangerRule('sql server account', ports=('1433',), name_terms=('sql server',)),
    _ChangerRule('mysql account', ports=('3306',), name_terms=('mysql',)),
    _ChangerRule('postgresql account', ports=('5432',), name_terms=('postgres',)),
    _ChangerRule('oracle account', ports=('1521',), name_terms=('oracle',)),
    _ChangerRule('openldap account', when=_domain_only, name_terms=('ldap',)),
    _ChangerRule('active directory account', when=_domain_only),
    _ChangerRule('windows account', when=_has_host, ports=('3389', '5985', '5986'),
                 name_terms=('windows',), host_terms=('windows',), hint=lambda s: bool(s.domain)),
    _ChangerRule('unix account (ssh)', when=_has_host),
)


def _mapping_from_items(secret: dict) -> ChangerMapping:
    signals = _SecretSignals.from_secret(secret)
    for rule in _CHANGER_RULES:
        if rule.matches(signals):
            return DEFAULT_CROSSWALK[rule.crosswalk_key]
    return FALLBACK_MAPPING


def _merge(accounts: List[_Account]) -> List[dict]:
    merged: Dict[tuple, dict] = {}
    order: List[dict] = []
    for account in accounts:
        resource = account.resource
        if resource['type'] == 'pamDirectory':
            key = ('pamDirectory', (resource.get('domain_name') or '').casefold())
        else:
            host = (resource.get('host') or '').casefold()
            key = (resource['type'], host, str(resource.get('port') or '')) if host else ('secret', account.secret_id)
        current = merged.get(key)
        if current is None:
            merged[key] = resource
            order.append(resource)
            continue
        current.setdefault('users', []).extend(resource.get('users') or [])
        account.resource = current
    for resource in order:
        users = resource.get('users') or []
        enabled = any((user.get('rotation_settings') or {}).get('enabled') == 'on' for user in users)
        options = ((resource.get('pam_settings') or {}).get('options') or {})
        if options:
            options['rotation'] = 'on' if enabled else 'off'
    return order


def _apply_credentials(resources: List[dict], accounts: List[_Account]) -> None:
    """Launch credential is the secret's own login; administrative credential is its privileged account."""
    _nest_privileged_users(accounts)
    by_secret = {account.secret_id: account for account in accounts}
    for resource in resources:
        users = resource.get('users') or []
        if not users:
            continue
        owners = [account for account in accounts if account.resource is resource]
        chosen = next((account for account in owners if account.privileged_id), None)
        launch = chosen.user['title'] if chosen else users[0]['title']
        admin_title = launch
        if chosen and chosen.privileged_id:
            admin = by_secret.get(chosen.privileged_id)
            if admin:
                admin_title = admin.user['title']
        connection = resource.setdefault('pam_settings', {}).setdefault('connection', {})
        connection['launch_credentials'] = launch
        connection['administrative_credentials'] = admin_title


def _nest_privileged_users(accounts: List[_Account]) -> None:
    by_secret = {account.secret_id: account for account in accounts}
    for account in accounts:
        if not account.privileged_id or account.privileged_id == account.secret_id:
            continue
        admin = by_secret.get(account.privileged_id)
        if admin is None:
            continue
        users = account.resource.setdefault('users', [])
        titles = [user.get('title') for user in users]
        login_at = next((index for index, user in enumerate(users) if user is account.user), None)
        if login_at is None:
            continue
        if admin.user['title'] in titles:
            admin_at = titles.index(admin.user['title'])
            if admin_at == login_at + 1:
                continue
            admin_user = users.pop(admin_at)
            login_at = next(index for index, user in enumerate(users) if user is account.user)
            users.insert(login_at + 1, admin_user)
            continue
        users.insert(login_at + 1, copy.deepcopy(admin.user))


def _apply_safe_folders(resources: List[dict], accounts: List[_Account], project: str) -> List[dict]:
    """One safe per folder: resources in ``{safe}/{safe} - Resources``, users in ``{safe}/{safe} - Users``."""
    mapper = SafeFolderMapper('safe')
    for resource in resources:
        owners = [account for account in accounts if account.resource is resource]
        folder_name = next((account.folder_name for account in owners if account.folder_name), '')
        if not folder_name:
            folder_name = resource.get('title') or 'Secrets'
        safe = mapper.map_safe(folder_name, project)
        resource['folder_path'] = f'{safe}/{safe} - Resources'
        for user in resource.get('users') or []:
            user['folder_path'] = f'{safe}/{safe} - Users'
    safe_folders = []
    for raw, resolved in mapper.iter_mapped():
        safe_folders.append({
            'name': resolved,
            'safe_name': raw,
            'manage_users': True,
            'manage_records': True,
            'can_edit': True,
            'can_share': True,
            'permissions': [],
        })
    return safe_folders


def _privileged_id(secret: dict) -> Optional[int]:
    value = secret.get('privilegedAccountSecretId')
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None