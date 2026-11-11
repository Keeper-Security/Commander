#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from typing import Dict, Iterable, List, Optional

from ....constants import DELINEA_PAM_ENDPOINTS
from ..thycotic import ThycoticAuth, ThycoticMixin

# Secret Server uses -1 when a secret has no secret policy attached.
UNASSIGNED_POLICY_ID = -1

ENDPOINTS = DELINEA_PAM_ENDPOINTS


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

    def secrets_for_template(self, template_id: int, take: int) -> List[dict]:
        """Up to *take* secret summaries for one template.

        One page only. ``thycotic_search`` would page the whole template.
        Summaries carry ``id`` and ``name``; field values come from ``secret``.
        """
        if take <= 0:
            return []
        data = self.auth.thycotic_entity(
            f'/v1/secrets?filter.secretTemplateId={int(template_id)}&take={int(take)}')
        records = data.get('records') if isinstance(data, dict) else None
        if not isinstance(records, list):
            return []
        return [x for x in records if isinstance(x, dict)][:take]

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
