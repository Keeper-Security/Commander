#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""SCIM coexistence helpers for SailPoint Service Mode."""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Set

from ..... import api
from .....params import KeeperParams

_ALL_PSEUDO_USER = '@all'


class SailPointScimGuard:
    """Detect SCIM-managed users/nodes and block identity stomps."""

    @staticmethod
    def ensure_enterprise(params: KeeperParams) -> None:
        if not params.enterprise:
            api.query_enterprise(params)

    @staticmethod
    def _scim_node_ids(params: KeeperParams) -> Set[int]:
        nodes: Set[int] = set()
        for scim in params.enterprise.get('scims') or []:
            node_id = scim.get('node_id')
            if node_id:
                nodes.add(int(node_id))
        for node in params.enterprise.get('nodes') or []:
            if node.get('scim_id'):
                nodes.add(int(node['node_id']))
        return nodes

    @staticmethod
    def _node_parents(params: KeeperParams) -> Dict[int, Optional[int]]:
        return {
            int(n['node_id']): (int(n['parent_id']) if n.get('parent_id') else None)
            for n in params.enterprise.get('nodes') or []
        }

    @staticmethod
    def _walk_ancestors(node_id: int, parents: Dict[int, Optional[int]]) -> Iterable[int]:
        current: Optional[int] = node_id
        seen = set()
        while current and current not in seen:
            yield current
            seen.add(current)
            parent = parents.get(current)
            current = parent if parent != current else None

    @classmethod
    def is_scim_managed_node(cls, params: KeeperParams, node_id: Optional[int]) -> bool:
        cls.ensure_enterprise(params)
        if not node_id or not params.enterprise:
            return False
        scim_nodes = cls._scim_node_ids(params)
        if not scim_nodes:
            return False
        parents = cls._node_parents(params)
        return any(n in scim_nodes for n in cls._walk_ancestors(int(node_id), parents))

    @staticmethod
    def _normalize(value: Any) -> str:
        return str(value).strip().lower() if isinstance(value, str) else ''

    @classmethod
    def _build_user_lookup(cls, params: KeeperParams) -> Dict[str, Any]:
        """Mirrors EnterpriseUserCommand's own lookup: id, username, then aliases."""
        lookup: Dict[str, Any] = {}
        for user in params.enterprise.get('users') or []:
            if 'enterprise_user_id' in user:
                lookup[str(user['enterprise_user_id']).strip()] = user
            username = cls._normalize(user.get('username'))
            if username:
                lookup[username] = user
        for alias in params.enterprise.get('user_aliases') or []:
            username = cls._normalize(alias.get('username'))
            if username and username not in lookup:
                user_id = str(alias.get('enterprise_user_id')).strip()
                if user_id in lookup:
                    lookup[username] = lookup[user_id]
        return lookup

    @classmethod
    def _is_all_pseudo_user(cls, identifier: str) -> bool:
        return cls._normalize(identifier) == _ALL_PSEUDO_USER

    @classmethod
    def find_user(cls, params: KeeperParams, identifier: str) -> Optional[Dict[str, Any]]:
        cls.ensure_enterprise(params)
        if not params.enterprise:
            return None
        target = cls._normalize(identifier)
        if not target:
            return None
        return cls._build_user_lookup(params).get(target)

    @classmethod
    def is_scim_managed_user(cls, params: KeeperParams, identifier: str) -> bool:
        user = cls.find_user(params, identifier)
        if not user:
            return False
        return cls.is_scim_managed_node(params, user.get('node_id'))

    @classmethod
    def is_scim_managed_identifier(cls, params: KeeperParams, identifier: str) -> bool:
        """Like is_scim_managed_user, but '@all' matches if any user is SCIM-managed."""
        if not cls._is_all_pseudo_user(identifier):
            return cls.is_scim_managed_user(params, identifier)
        cls.ensure_enterprise(params)
        if not params.enterprise:
            return False
        scim_nodes = cls._scim_node_ids(params)
        if not scim_nodes:
            return False
        parents = cls._node_parents(params)
        return any(
            any(n in scim_nodes for n in cls._walk_ancestors(int(user['node_id']), parents))
            for user in params.enterprise.get('users') or []
            if user.get('node_id')
        )

    @classmethod
    def identity_change_error(cls, params: KeeperParams, identifier: str) -> Optional[str]:
        if not cls.is_scim_managed_identifier(params, identifier):
            return None
        if cls._is_all_pseudo_user(identifier):
            return (
                '@all includes one or more users managed by an existing SCIM provider. '
                'SailPoint may only change folder/record (and admin) entitlements; '
                'node/team/role identity changes are not allowed for those users.'
            )
        return (
            f'User {identifier} is managed by an existing SCIM provider. '
            'SailPoint may only change folder/record (and admin) entitlements; '
            'node/team/role identity changes are not allowed.'
        )
