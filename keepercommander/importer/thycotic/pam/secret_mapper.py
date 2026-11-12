#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Set

from .client import DelineaPamClient
from .crosswalk import Crosswalk
from .launcher_mapper import LauncherMapper
from .models import ChangerMapping, FindingLog, RotationPolicy, RotationState, _positive
from .policy import SecretPolicyResolver
from .rotation_mapper import RotationMapper

HOST_SLUGS = ('machine', 'server', 'host', 'ip-address---host-name')
LOGIN_SLUGS = ('username',)
PASSWORD_SLUGS = ('password',)
PORT_SLUGS = ('port',)
DOMAIN_SLUGS = ('domain',)
PRIVATE_KEY_SLUGS = ('private-key',)


def resources_path(folder_name: str) -> str:
    return f'{folder_name}/{folder_name} - Resources'


def users_path(folder_name: str) -> str:
    return f'{folder_name}/{folder_name} - Users'


@dataclass
class MappedSecret:
    secret_id: int
    title: str
    rotation: RotationPolicy
    mapping: Optional[ChangerMapping]
    resource: Optional[dict] = None
    login: Optional[dict] = None
    references: Set[int] = field(default_factory=set)


class SecretMapper:
    """Builds ``pam project import`` records from Delinea secrets.

    A mapped secret becomes a resource with one nested ``pamUser``, or a
    top-level ``login`` when the changer is unmapped. Privileged and connect-as
    secrets are referenced by title and emitted once by ``map_reference`` as
    top-level ``pamUser`` records without ``folder_path`` (admin-only Config folder).
    """

    def __init__(self, client: DelineaPamClient, resolver: SecretPolicyResolver, crosswalk: Crosswalk,
                 rotation: RotationMapper, launcher: LauncherMapper, findings: FindingLog):
        self.client = client
        self.resolver = resolver
        self.crosswalk = crosswalk
        self.rotation = rotation
        self.launcher = launcher
        self.findings = findings
        self._titles: Dict[int, str] = {}
        self._used_titles: Set[str] = set()

    def map_secret(self, secret: dict, folder_name: str) -> MappedSecret:
        """Map one secret routed to the shared folder *folder_name*.

        Steps: ``client.secret_settings``; ``resolver.policy_for``;
        ``rotation.resolve``; ``crosswalk.resolve`` (unmapped yields a Finding
        and a ``login`` in ``users_path``). Otherwise the resource is titled by
        its host and carries ``host`` / ``port`` from the ``*_SLUGS`` items (falling back to the
        mapping port), ``database_type`` / ``directory_type`` /
        ``operating_system`` from the mapping, ``folder_path`` =
        ``resources_path``, ``pam_settings`` from ``launcher.pam_settings``
        and ``users`` = [the ``pamUser`` with ``login`` / ``password`` /
        ``private_pem_key``, ``rotation_settings`` from
        ``RotationMapper.to_rotation_settings`` and ``folder_path`` = ``users_path``].
        ``launch_credentials`` / ``administrative_credentials`` default to the
        user's own title and are replaced by ``title_for`` of the connect-as /
        privileged secret, whose ids go to ``references``.
        """
        secret_id = _positive(secret.get('id')) or 0
        name = str(secret.get('name') or secret_id)
        settings = _dict(self._call(self.client.secret_settings, secret_id))
        policy = self.resolver.policy_for(secret)
        rotation = self.rotation.resolve(secret, settings)
        mapping = self._mapping(rotation)
        user_title = self.title_for(secret_id, name)
        login = self.item_value(secret, LOGIN_SLUGS)
        password = self.item_value(secret, PASSWORD_SLUGS)
        private_key = self.item_value(secret, PRIVATE_KEY_SLUGS)

        if mapping is None or mapping.record_type == 'login':
            if mapping is None:
                self.findings.add(
                    'Password changer', rotation.changer_name or name,
                    'No Keeper mapping; imported as a login')
            record = {
                'type': 'login',
                'title': user_title,
                'login': login,
                'password': password,
                'folder_path': users_path(folder_name),
            }
            return MappedSecret(secret_id=secret_id, title=user_title, rotation=rotation,
                                mapping=mapping, login=record)

        host = self.item_value(secret, HOST_SLUGS)
        port = self.item_value(secret, PORT_SLUGS) or mapping.port or ''
        if port != mapping.port:
            mapping = replace(mapping, port=port)
        if not host:
            self.findings.add('Host', name, 'No host field; the resource cannot be connected')

        launch_title = user_title
        admin_title = user_title
        references: Set[int] = set()
        connect_as = self.launcher.connect_as_secret_id(secret, settings, policy)
        if connect_as and connect_as != secret_id:
            references.add(connect_as)
            launch_title = self.title_for(connect_as, self._secret_name(connect_as))
        if rotation.admin_secret_id and rotation.admin_secret_id != secret_id:
            references.add(rotation.admin_secret_id)
            admin_title = self.title_for(rotation.admin_secret_id, self._secret_name(rotation.admin_secret_id))

        pam_user = {
            'type': 'pamUser',
            'title': user_title,
            'login': login,
            'password': password,
            'folder_path': users_path(folder_name),
        }
        if private_key:
            pam_user['private_pem_key'] = private_key
        rotation_settings = RotationMapper.to_rotation_settings(rotation, mapping)
        if rotation_settings:
            pam_user['rotation_settings'] = rotation_settings

        resource = {
            'type': mapping.record_type,
            'title': host or name,
            'host': host,
            'port': port,
            'folder_path': resources_path(folder_name),
            'users': [pam_user],
        }
        if mapping.database_type:
            resource['database_type'] = mapping.database_type
        if mapping.directory_type:
            resource['directory_type'] = mapping.directory_type
        if mapping.operating_system:
            resource['operating_system'] = mapping.operating_system
        domain = self.item_value(secret, DOMAIN_SLUGS)
        if domain:
            resource['domain_name'] = domain
        pam_settings = self.launcher.pam_settings(
            secret, settings, policy, mapping,
            rotation.state is RotationState.ENABLED, launch_title, admin_title)
        if pam_settings:
            resource['pam_settings'] = pam_settings
        return MappedSecret(secret_id=secret_id, title=user_title, rotation=rotation,
                            mapping=mapping, resource=resource, references=references)

    def map_reference(self, secret: dict) -> dict:
        """Top-level ``pamUser`` for a privileged or connect-as secret (no rotation, no ``folder_path``)."""
        secret_id = _positive(secret.get('id')) or 0
        name = str(secret.get('name') or secret_id)
        record = {
            'type': 'pamUser',
            'title': self.title_for(secret_id, name),
            'login': self.item_value(secret, LOGIN_SLUGS),
            'password': self.item_value(secret, PASSWORD_SLUGS),
        }
        private_key = self.item_value(secret, PRIVATE_KEY_SLUGS)
        if private_key:
            record['private_pem_key'] = private_key
        return record

    def _mapping(self, rotation: RotationPolicy) -> Optional[ChangerMapping]:
        detail = None
        if rotation.changer_id:
            detail = self._call(self.client.password_type, rotation.changer_id)
        name = rotation.changer_name
        if isinstance(detail, dict) and not name:
            name = str(detail.get('name') or detail.get('passwordTypeName') or '')
        return self.crosswalk.resolve(name, detail if isinstance(detail, dict) else None)

    def _secret_name(self, secret_id: int) -> str:
        secret = self._call(self.client.secret, secret_id)
        if isinstance(secret, dict) and secret.get('name'):
            return str(secret['name'])
        return f'Secret {secret_id}'

    @staticmethod
    def _call(method, entity_id: int):
        if entity_id <= 0:
            return None
        try:
            return method(entity_id)
        except Exception:
            return None

    def title_for(self, secret_id: int, name: str) -> str:
        """Stable, unique record title; repeated names get `` #<secret id>``."""
        title = self._titles.get(secret_id)
        if title is None:
            title = name if name.casefold(
            ) not in self._used_titles else f'{name} #{secret_id}'
            self._titles[secret_id] = title
            self._used_titles.add(title.casefold())
        return title

    @staticmethod
    def item_value(secret: dict, slugs: tuple) -> str:
        for item in secret.get('items') or []:
            if item.get('slug') in slugs and item.get('itemValue'):
                return str(item['itemValue'])
        return ''

    @staticmethod
    def merge_resources(resources: List[dict]) -> List[dict]:
        """Combine resources that share (type, host, port, folder_path) into one with all users."""
        merged: Dict[tuple, dict] = {}
        for res in resources:
            key = (
                res.get('type'),
                (res.get('host') or '').casefold(),
                str(res.get('port') or ''),
                res.get('folder_path')
            )
            if key[1] and key in merged:
                merged[key].setdefault('users', []).extend(
                    res.get('users') or [])
            else:
                merged[key if key[1] else (id(res),)] = res
        return list(merged.values())


def _dict(value) -> Optional[dict]:
    return value if isinstance(value, dict) else None