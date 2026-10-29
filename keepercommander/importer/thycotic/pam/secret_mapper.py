#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .client import DelineaPamClient
from .crosswalk import Crosswalk
from .launcher_mapper import LauncherMapper
from .models import ChangerMapping, FindingLog, RotationPolicy
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
        raise NotImplementedError

    def map_reference(self, secret: dict) -> dict:
        """Top-level ``pamUser`` for a privileged or connect-as secret (no rotation, no ``folder_path``)."""
        raise NotImplementedError

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
