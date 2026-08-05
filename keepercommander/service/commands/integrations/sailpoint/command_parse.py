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

"""Parse Service Mode command strings for SailPoint pending entitlement hooks."""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from typing import Any, List, Optional, Sequence, Tuple

_NSF_FOLDER = frozenset({'nsf-share-folder'})
_NSF_RECORD = frozenset({'nsf-share-record'})
_FOLDER_CMDS = frozenset({'share-folder', 'nsf-share-folder'})
_RECORD_CMDS = frozenset({'share-record', 'nsf-share-record'})
_EU_CMDS = frozenset({'enterprise-user', 'eu'})
_TRANSFER_CMDS = frozenset({'transfer-user', 'tu'})


@dataclass
class ParsedInvite:
    emails: List[str] = field(default_factory=list)
    node: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    teams: List[str] = field(default_factory=list)
    is_invite: bool = False


@dataclass
class ParsedShare:
    command: str
    emails: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    action: str = 'grant'
    can_edit: bool = False
    can_share: bool = False
    manage_records: Optional[str] = None
    manage_users: Optional[str] = None
    nsf_role: Optional[str] = None
    is_folder: bool = False
    is_record: bool = False
    is_nsf: bool = False

    @property
    def target(self) -> Optional[str]:
        return self.targets[-1] if self.targets else None

    @property
    def is_grant(self) -> bool:
        """Only grant (default) is deferred for Invited users; revoke/remove run natively."""
        return (self.action or 'grant').lower() == 'grant'


@dataclass
class ParsedIdentityMutation:
    """enterprise-user identity change (role/team/node) — used for SCIM coexistence."""

    emails: List[str] = field(default_factory=list)
    has_role_change: bool = False
    has_team_change: bool = False
    has_node_change: bool = False


@dataclass
class ParsedTransfer:
    """transfer-user offboard request (target comes from SailPoint config)."""

    emails: List[str] = field(default_factory=list)
    has_target_user: bool = False
    has_force: bool = False


class SailPointCommandParser:
    """Parse SailPoint Service Mode commands via Commander's argparse parsers."""

    @staticmethod
    def tokenize(command: str) -> List[str]:
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()

    @staticmethod
    def parse_known(parser, argv: Sequence[str]) -> Optional[Tuple[Any, List[str]]]:
        """Parse with a Commander parser; None when argparse rejects the argv."""
        from .....commands.base import ParseError

        try:
            ns, unknown = parser.parse_known_args(list(argv))
            return ns, list(unknown)
        except ParseError:
            return None

    @classmethod
    def parse_invite(cls, command: str) -> Optional[ParsedInvite]:
        tokens = cls.tokenize(command)
        if not tokens or tokens[0].lower() not in _EU_CMDS:
            return None

        from .....commands.enterprise import enterprise_user_parser

        parsed = cls.parse_known(enterprise_user_parser, tokens[1:])
        if not parsed:
            return None
        ns, _unknown = parsed
        if not (ns.invite or ns.add):
            return None
        emails = [e for e in (ns.email or []) if isinstance(e, str) and '@' in e]
        return ParsedInvite(
            emails=emails,
            node=ns.node,
            roles=list(ns.add_role or []),
            teams=list(ns.add_team or []),
            is_invite=True,
        )

    @classmethod
    def parse_identity_mutation(cls, command: str) -> Optional[ParsedIdentityMutation]:
        tokens = cls.tokenize(command)
        if not tokens or tokens[0].lower() not in _EU_CMDS:
            return None

        from .....commands.enterprise import enterprise_user_parser

        parsed = cls.parse_known(enterprise_user_parser, tokens[1:])
        if not parsed:
            return None
        ns, _unknown = parsed
        emails = [e for e in (ns.email or []) if isinstance(e, str) and '@' in e]
        has_role = bool(ns.add_role or ns.remove_role)
        has_team = bool(ns.add_team or ns.remove_team)
        has_node = bool(ns.node)
        if not (has_role or has_team or has_node) or not emails:
            return None
        return ParsedIdentityMutation(
            emails=emails,
            has_role_change=has_role,
            has_team_change=has_team,
            has_node_change=has_node,
        )

    @classmethod
    def parse_transfer(cls, command: str) -> Optional[ParsedTransfer]:
        tokens = cls.tokenize(command)
        if not tokens or tokens[0].lower() not in _TRANSFER_CMDS:
            return None

        from .....commands.transfer_account import transfer_user_parser

        parsed = cls.parse_known(transfer_user_parser, tokens[1:])
        if not parsed:
            return None
        ns, _unknown = parsed
        return ParsedTransfer(
            emails=[e for e in (ns.email or []) if isinstance(e, str) and '@' in e],
            has_target_user=bool(ns.target_user),
            has_force=bool(ns.force),
        )

    @classmethod
    def parse_share(cls, command: str) -> Optional[ParsedShare]:
        tokens = cls.tokenize(command)
        if not tokens:
            return None
        name = tokens[0].lower()
        if name not in _FOLDER_CMDS and name not in _RECORD_CMDS:
            return None

        parser = cls._share_parser(name)
        if parser is None:
            return None
        parsed = cls.parse_known(parser, tokens[1:])
        if not parsed:
            return None
        ns, _unknown = parsed

        is_folder = name in _FOLDER_CMDS
        is_record = name in _RECORD_CMDS
        is_nsf = name in _NSF_FOLDER or name in _NSF_RECORD

        if is_record:
            emails = list(getattr(ns, 'email', None) or [])
            record = getattr(ns, 'record', None)
            targets = [record] if record else []
        else:
            emails = list(getattr(ns, 'user', None) or [])
            folder = getattr(ns, 'folder', None) or []
            targets = list(folder) if isinstance(folder, list) else ([folder] if folder else [])

        if not emails or not targets:
            return None

        action = (getattr(ns, 'action', None) or 'grant').strip().lower() or 'grant'
        result = ParsedShare(
            command=name,
            emails=emails,
            targets=targets,
            action=action,
            is_folder=is_folder,
            is_record=is_record,
            is_nsf=is_nsf,
        )
        if is_nsf:
            result.nsf_role = getattr(ns, 'role', None)
        elif is_record:
            result.can_edit = bool(getattr(ns, 'can_edit', False))
            result.can_share = bool(getattr(ns, 'can_share', False))
        else:
            result.manage_records = getattr(ns, 'manage_records', None)
            result.manage_users = getattr(ns, 'manage_users', None)
        return result

    @staticmethod
    def _share_parser(name: str):
        if name == 'share-record':
            from .....commands.register import share_record_parser
            return share_record_parser
        if name == 'share-folder':
            from .....commands.register import share_folder_parser
            return share_folder_parser
        if name == 'nsf-share-record':
            from .....commands.nested_share_folder.parsers import nested_share_record_share_parser
            return nested_share_record_share_parser
        if name == 'nsf-share-folder':
            from .....commands.nested_share_folder.parsers import nested_share_folder_share_parser
            return nested_share_folder_share_parser
        return None
