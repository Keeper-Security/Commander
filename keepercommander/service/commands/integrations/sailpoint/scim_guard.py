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

from typing import Iterable, Optional, Set

from ..... import api
from .....params import KeeperParams


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
    def _node_ancestors(params: KeeperParams, node_id: int) -> Iterable[int]:
        by_id = {int(n['node_id']): n for n in params.enterprise.get('nodes') or []}
        current = node_id
        seen = set()
        while current and current not in seen:
            yield current
            seen.add(current)
            parent = by_id.get(current, {}).get('parent_id')
            if not parent or int(parent) == current:
                break
            current = int(parent)

    @classmethod
    def is_scim_managed_node(cls, params: KeeperParams, node_id: Optional[int]) -> bool:
        cls.ensure_enterprise(params)
        if not node_id or not params.enterprise:
            return False
        scim_nodes = cls._scim_node_ids(params)
        if not scim_nodes:
            return False
        return any(n in scim_nodes for n in cls._node_ancestors(params, int(node_id)))

    @classmethod
    def find_user(cls, params: KeeperParams, email: str):
        cls.ensure_enterprise(params)
        if not params.enterprise:
            return None
        target = email.strip().lower()
        for user in params.enterprise.get('users') or []:
            if (user.get('username') or '').lower() == target:
                return user
        return None

    @classmethod
    def is_scim_managed_user(cls, params: KeeperParams, email: str) -> bool:
        user = cls.find_user(params, email)
        if not user:
            return False
        return cls.is_scim_managed_node(params, user.get('node_id'))

    @classmethod
    def identity_change_error(cls, params: KeeperParams, email: str) -> Optional[str]:
        if cls.is_scim_managed_user(params, email):
            return (
                f'User {email} is managed by an existing SCIM provider. '
                'SailPoint may only change folder/record (and admin) entitlements; '
                'node/team/role identity changes are not allowed.'
            )
        return None
