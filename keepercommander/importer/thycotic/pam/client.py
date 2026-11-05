#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from typing import Dict, Iterable, List, Optional

from ..thycotic import ThycoticAuth, ThycoticMixin


ENDPOINTS = {
    'folder': '/v1/folders/{id}',
    'folder_permissions': '/v1/folder-permissions?filter.folderId={id}',
    'secrets_lookup': '/v1/secrets/lookup?filter.folderId={id}',
    'secret': '/v1/secrets/{id}',
    'secret_settings': '/v1/secrets/{id}/settings',
    'secret_rpc': '/v1/secrets/secret-detail/{id}/rpc',
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
        self._folders: Optional[Dict[int, dict]] = None
        self._users: Optional[Dict[int, dict]] = None
        self._groups: Optional[Dict[int, dict]] = None
        self._password_types: Optional[Dict[int, dict]] = None
        self._sites: Optional[Dict[int, dict]] = None

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

    def folders(self) -> Dict[int, dict]:
        """Folder id to ``{id, folderName, folderPath, inheritPermissions, parentFolderId}``."""
        if self._folders is None:
            self._folders = ThycoticMixin.get_folders(
                self.auth, skip_permissions=True) or {}
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

    def secret_ids(self, folder_ids: Iterable[int]) -> List[int]:
        ids: List[int] = []
        for folder_id in folder_ids:
            ids.extend(x['id'] for x in self._list(
                'secrets_lookup', folder_id) if 'id' in x)
        return ids

    def secret(self, secret_id: int) -> Optional[dict]:
        """SecretModel including ``items`` (field values) and RPC / launcher flags."""
        return self.auth.thycotic_entity(ENDPOINTS['secret'].format(id=secret_id))

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
