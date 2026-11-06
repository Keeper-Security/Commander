
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

import logging
from typing import Dict, Iterable, List, Optional

from ..thycotic import ThycoticAuth, ThycoticMixin


# Secret Server uses -1 when a secret has no secret policy attached.
UNASSIGNED_POLICY_ID = -1

ENDPOINTS = {
    'folder': '/v1/folders/{id}',
    'folder_permissions': '/v1/folder-permissions?filter.folderId={id}',
    'secrets_lookup': '/v1/secrets/lookup?filter.folderId={id}',
    'secret': '/v1/secrets/{id}',
    'secret_settings': '/v1/secrets/{id}/settings',
    'secret_rpc': '/v1/secrets/secret-detail/{id}/rpc',
    'rpc_script_secrets': '/v3/secrets/{id}/rpc-script-secrets',
    'secret_permissions': '/v1/secret-permissions?filter.secretId={id}',
    'secret_policy': '/v2/secret-policy/{id}',
    'secret_templates': '/v1/secret-templates?filter.includeSecretCount=true',
    'secret_template': '/v1/secret-templates/{id}',
    'password_types': '/v1/remote-password-changing/password-types',
    'password_type': '/v1/remote-password-changing/password-types/{id}',
    'password_requirement': '/v1/password-requirements/{id}',
    'sites': '/v1/distributed-engine/sites',
}


class DelineaPamClient:
    """Read-only Secret Server REST access for the PAM import.

    Composes ``ThycoticAuth`` (OAuth2, paging, retries) and ``ThycoticMixin``
    (folders, users, groups). Lookups that are shared across secrets are cached.
    """

    def __init__(self, auth: ThycoticAuth):
        self.auth = auth
        self._cache: Dict[str, Dict[int, Optional[dict]]] = {}
        self._all_folders: Optional[Dict[int, dict]] = None
        self._folders: Optional[Dict[int, dict]] = None
        self._users: Optional[Dict[int, dict]] = None
        self._groups: Optional[Dict[int, dict]] = None
        self._password_types: Optional[Dict[int, dict]] = None
        self._sites: Optional[Dict[int, dict]] = None
        self._secret_details: Dict[int, Optional[dict]] = {}
        self._secrets: Dict[int, Optional[dict]] = {}

    @classmethod
    def connect(cls, server: str, proxy: Optional[dict] = None) -> Optional['DelineaPamClient']:
        auth = ThycoticMixin.connect_to_server(server)
        if not auth:
            return None
        auth.proxy = proxy
        return cls(auth)

    def _get(self, key: str, entity_id: int) -> Optional[dict]:
        bucket = self._cache.setdefault(key, {})
        if entity_id not in bucket:
            bucket[entity_id] = self.auth.thycotic_entity(
                ENDPOINTS[key].format(id=entity_id))
        return bucket[entity_id]

    def _list(self, key: str, entity_id: Optional[int] = None) -> List[dict]:
        return self.auth.thycotic_search(ENDPOINTS[key].format(id=entity_id))

    def _folder_index(self) -> Dict[int, dict]:
        """Every folder from ``GET /v1/folders``, including the personal root (id 1)."""
        if self._all_folders is None:
            self._all_folders = ThycoticMixin._load_folders(self.auth) or {}
        return self._all_folders

    def folders(self) -> Dict[int, dict]:
        """Folder id to ``{id, folderName, folderPath, inheritPermissions, parentFolderId}``.

        The personal-folders root (id 1) is omitted, matching the rest of the importer.
        """
        if self._folders is None:
            shared = dict(self._folder_index())
            shared.pop(1, None)
            self._folders = shared
        return self._folders

    def folder(self, folder_id: int) -> Optional[dict]:
        """FolderModel: ``inheritSecretPolicy``, ``secretPolicyId``, ``secretTemplates[]``."""
        return self._get('folder', folder_id)

    def users(self) -> Dict[int, dict]:
        if self._users is None:
            self._users = ThycoticMixin.get_user_lookup(self.auth) or {}
        return self._users

    def groups(self) -> Dict[int, dict]:
        if self._groups is None:
            self._groups = ThycoticMixin.get_group_lookup(self.auth) or {}
        return self._groups

    def folder_permissions(self, folder_id: int) -> List[dict]:
        """Rows with ``userId``/``groupId``, ``folderAccessRoleName``, ``secretAccessRoleName``."""
        return self._list('folder_permissions', folder_id)

    @staticmethod
    def _secret_name(row: dict) -> str:
        """Lookup rows name the secret in ``value``; some tenants send ``name``."""
        for key in ('value', 'name', 'secretName'):
            name = row.get(key)
            if name:
                return str(name)
        return ''

    def secrets_lookup(self, folder_id: int) -> List[dict]:
        """``GET /v1/secrets/lookup?filter.folderId={folder_id}``.

        Returns ``{'id', 'name'}`` for each secret directly in that folder.
        Subfolders are not included, so a later pass over every folder does not
        list the same secret twice.
        """
        found: List[dict] = []
        seen = set()
        for row in self._list('secrets_lookup', folder_id):
            if not isinstance(row, dict) or row.get('id') is None or row['id'] in seen:
                continue
            seen.add(row['id'])
            found.append({'id': row['id'], 'name': self._secret_name(row)})
        return found

    def folder_secrets(self) -> List[dict]:
        """Load every folder, then the secrets in each one.

        1. ``GET /v1/folders``
        2. For each folder, ``GET /v1/secrets/lookup?filter.folderId={folderId}``

        Each result is the folder (``id``, ``folderName``, ``folderPath``) plus
        ``secrets``, a list of ``{'id', 'name'}``.
        """
        folders = self._folder_index()
        logging.info('Loaded %d folders from Secret Server', len(folders))
        results: List[dict] = []
        for folder_id in sorted(folders):
            folder = folders[folder_id]
            secrets = self.secrets_lookup(folder_id)
            logging.info('Folder %s (%s): %d secrets', folder_id,
                         folder.get('folderPath') or folder.get('folderName') or '', len(secrets))
            results.append({
                'id': folder_id,
                'folderName': folder.get('folderName') or '',
                'folderPath': folder.get('folderPath') or '',
                'secrets': secrets,
            })
        return results

    def secret_ids(self, folder_ids: Iterable[int]) -> List[int]:
        ids: List[int] = []
        for folder_id in folder_ids:
            ids.extend(secret['id'] for secret in self.secrets_lookup(folder_id))
        return ids

    def secret(self, secret_id: int) -> Optional[dict]:
        """SecretModel including ``items`` (field values) and RPC / launcher flags."""
        if secret_id not in self._secrets:
            self._secrets[secret_id] = self.auth.thycotic_entity(
                ENDPOINTS['secret'].format(id=secret_id))
        return self._secrets[secret_id]

    @staticmethod
    def _positive_secret_id(value) -> Optional[int]:
        """A Secret Server id. ``-1``, ``0``, and empty mean no secret is assigned."""
        if isinstance(value, bool) or isinstance(value, float):
            return None
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, str) and value.strip().isdigit() and int(value.strip()) > 0:
            return int(value.strip())
        return None

    @staticmethod
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() == 'true'
        if isinstance(value, (int, float)):
            return value != 0
        return False

    @classmethod
    def extract_secret_detail(cls, secret: dict, secret_id: int, name: str = '') -> dict:
        """Fields read from ``GET /v1/secrets/{id}`` for PAM mapping.

        ``secretPolicyId`` is left as ``-1`` when Secret Server reports no policy.
        ``items`` is the credential field list (username, password, and the rest).
        """
        policy_id = secret.get('secretPolicyId', UNASSIGNED_POLICY_ID)
        if policy_id is None:
            policy_id = UNASSIGNED_POLICY_ID
        items = secret.get('items')
        return {
            'id': secret.get('id', secret_id),
            'name': name or secret.get('name') or '',
            'secretTemplateId': secret.get('secretTemplateId'),
            'siteId': secret.get('siteId'),
            'autoChangeEnabled': cls._as_bool(secret.get('autoChangeEnabled')),
            'secretPolicyId': policy_id,
            'items': items if isinstance(items, list) else [],
            'autoChangeSchedule': None,
            'privilegedAccountSecretId': None,
            'administrativeCredentials': None,
        }

    def secret_detail(self, secret_id: int, name: str = '') -> Optional[dict]:
        """``GET /v1/secrets/{id}`` and return the PAM fields. Cached per secret id."""
        if secret_id not in self._secret_details:
            raw = self.secret(secret_id)
            if not isinstance(raw, dict):
                logging.warning('Secret %s (%s) could not be read', secret_id, name or '')
                self._secret_details[secret_id] = None
            else:
                detail = self.extract_secret_detail(raw, secret_id, name)
                policy = 'unassigned' if detail['secretPolicyId'] == UNASSIGNED_POLICY_ID else detail['secretPolicyId']
                logging.info('Secret %s (%s): template %s, site %s, rotation %s, policy %s',
                             secret_id, detail['name'], detail['secretTemplateId'],
                             detail['siteId'], detail['autoChangeEnabled'], policy)
                self._secret_details[secret_id] = detail
                if detail['autoChangeEnabled']:
                    self._apply_rpc(detail)
        return self._secret_details[secret_id]

    def rpc_script_secrets(self, secret_id: int) -> Optional[dict]:
        """``GET /v3/secrets/{id}/rpc-script-secrets``."""
        payload = self.auth.thycotic_entity(ENDPOINTS['rpc_script_secrets'].format(id=secret_id))
        return payload if isinstance(payload, dict) else None

    def _apply_rpc(self, detail: dict) -> None:
        """When rotation is on, read the schedule and the privileged account's items."""
        secret_id = detail['id']
        rpc = self.rpc_script_secrets(secret_id)
        if rpc is None:
            logging.warning('Secret %s (%s): RPC script secrets could not be read',
                            secret_id, detail.get('name') or '')
            return
        schedule = rpc.get('autoChangeSchedule')
        privileged_id = self._positive_secret_id(rpc.get('privilegedAccountSecretId'))
        detail['autoChangeSchedule'] = schedule
        detail['privilegedAccountSecretId'] = privileged_id
        logging.info('Secret %s (%s): schedule %s, privileged secret %s',
                     secret_id, detail.get('name') or '',
                     'set' if schedule is not None else 'none', privileged_id)
        if privileged_id is None:
            return
        admin = self.secret(privileged_id)
        if not isinstance(admin, dict):
            logging.warning('Secret %s (%s): administrative secret %s could not be read',
                            secret_id, detail.get('name') or '', privileged_id)
            return
        items = admin.get('items')
        detail['administrativeCredentials'] = items if isinstance(items, list) else []

    def folder_secret_details(self) -> List[dict]:
        """Folder list from ``folder_secrets``, with each secret replaced by its detail fields.

        A secret that cannot be read is left out of that folder. The same id is
        requested once even if more than one folder lists it. When
        ``autoChangeEnabled`` is true, ``GET /v3/secrets/{id}/rpc-script-secrets``
        adds ``autoChangeSchedule`` and ``privilegedAccountSecretId``. A privileged
        id is then read with ``GET /v1/secrets/{id}`` and its ``items`` are stored
        as ``administrativeCredentials``.
        """
        folders = self.folder_secrets()
        for folder in folders:
            details = []
            for summary in folder['secrets']:
                detail = self.secret_detail(summary['id'], summary.get('name') or '')
                if detail:
                    details.append(detail)
            folder['secrets'] = details
        return folders

    def to_pam_import(self, project: str = 'Delinea Migration') -> dict:
        """Fetch folders, secrets, and RPC data, then build the Keeper PAM import document."""
        from .import_mapper import build_pam_import
        return build_pam_import(self.folder_secret_details(), project)

    def secret_settings(self, secret_id: int) -> Optional[dict]:
        """``expirationDayInterval``, ``rdpLauncherSettings``, ``sshLauncherSettings``."""
        return self.auth.thycotic_entity(ENDPOINTS['secret_settings'].format(id=secret_id))

    def secret_rpc(self, secret_id: int) -> Optional[dict]:
        """SecretDetailRpcModel; ``None`` on servers that don't expose it (pre-11.7)."""
        return self.auth.thycotic_entity(ENDPOINTS['secret_rpc'].format(id=secret_id))

    def secret_permissions(self, secret_id: int) -> List[dict]:
        return self._list('secret_permissions', secret_id)

    def secret_policy(self, policy_id: int) -> Optional[dict]:
        """SecretPolicyDetailModelV2: ``rpcItems``, ``launcherItems``, ``securityItems``, ``generalItems``."""
        return self._get('secret_policy', policy_id)

    def secret_templates(self) -> List[dict]:
        return self._list('secret_templates')

    def secret_template(self, template_id: int) -> Optional[dict]:
        return self._get('secret_template', template_id)

    def password_types(self) -> Dict[int, dict]:
        if self._password_types is None:
            self._password_types = {x['passwordTypeId']: x for x in self._list('password_types')
                                    if 'passwordTypeId' in x}
        return self._password_types

    def password_type(self, password_type_id: int) -> Optional[dict]:
        """Changer detail: ``customPort``, ``windowsCustomPorts``, ``isWeb``, ``runnerType``."""
        return self._get('password_type', password_type_id)

    def password_requirement(self, requirement_id: int) -> Optional[dict]:
        return self._get('password_requirement', requirement_id)

    def sites(self) -> Dict[int, dict]:
        if self._sites is None:
            self._sites = {x['siteId']: x for x in self._list(
                'sites') if 'siteId' in x}
        return self._sites