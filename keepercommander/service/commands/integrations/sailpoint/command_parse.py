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
from typing import List, Optional, Tuple

_NSF_FOLDER = frozenset({'nsf-share-folder'})
_NSF_RECORD = frozenset({'nsf-share-record'})
_FOLDER_CMDS = frozenset({'share-folder', 'nsf-share-folder'})
_RECORD_CMDS = frozenset({'share-record', 'nsf-share-record'})
_EU_CMDS = frozenset({'enterprise-user', 'eu'})
_INVITE_FLAGS = frozenset({'--invite', '--add'})


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


class SailPointCommandParser:
    """Parse enterprise-user invite and share-* command strings."""

    @staticmethod
    def tokenize(command: str) -> List[str]:
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()

    @staticmethod
    def _matches_flag(token: str, *names: str) -> bool:
        """True for ``--flag``, ``-f``, or ``--flag=value`` forms."""
        for name in names:
            if token == name:
                return True
            if name.startswith('--') and token.startswith(f'{name}='):
                return True
        return False

    @staticmethod
    def _one_flag_value(token: str, tokens: List[str], index: int) -> Tuple[Optional[str], int]:
        """
        Match Commander argparse append flags (one value per flag):
          --add-role R1
          --add-role=R1
        """
        if '=' in token:
            return token.split('=', 1)[1], index + 1
        if index + 1 < len(tokens) and not tokens[index + 1].startswith('-'):
            return tokens[index + 1], index + 2
        return None, index + 1

    @staticmethod
    def _skip_unknown_flag(tokens: List[str], index: int) -> int:
        """Advance past an unrecognized flag and an optional value token."""
        token = tokens[index]
        if '=' in token:
            return index + 1
        if index + 1 < len(tokens) and not tokens[index + 1].startswith('-'):
            return index + 2
        return index + 1

    @classmethod
    def _append_flag_value(
        cls,
        token: str,
        tokens: List[str],
        index: int,
        dest: List[str],
    ) -> int:
        value, next_i = cls._one_flag_value(token, tokens, index)
        if value is not None:
            dest.append(value)
        return next_i

    @classmethod
    def parse_invite(cls, command: str) -> Optional[ParsedInvite]:
        tokens = cls.tokenize(command)
        if not tokens or tokens[0] not in _EU_CMDS:
            return None

        parsed = ParsedInvite()
        emails: List[str] = []
        i = 1
        while i < len(tokens):
            t = tokens[i]
            if t in _INVITE_FLAGS:
                parsed.is_invite = True
                i += 1
            elif cls._matches_flag(t, '--node', '-n'):
                value, i = cls._one_flag_value(t, tokens, i)
                if value is not None:
                    parsed.node = value
            elif cls._matches_flag(t, '--add-role'):
                i = cls._append_flag_value(t, tokens, i, parsed.roles)
            elif cls._matches_flag(t, '--add-team'):
                i = cls._append_flag_value(t, tokens, i, parsed.teams)
            elif t.startswith('-'):
                i = cls._skip_unknown_flag(tokens, i)
            else:
                if '@' in t:
                    emails.append(t)
                i += 1

        parsed.emails = emails
        return parsed if parsed.is_invite else None

    @classmethod
    def parse_identity_mutation(cls, command: str) -> Optional[ParsedIdentityMutation]:
        tokens = cls.tokenize(command)
        if not tokens or tokens[0] not in _EU_CMDS:
            return None

        emails: List[str] = []
        has_role = False
        has_team = False
        has_node = False
        i = 1
        while i < len(tokens):
            t = tokens[i]
            if cls._matches_flag(t, '--add-role', '--remove-role'):
                has_role = True
                _, i = cls._one_flag_value(t, tokens, i)
            elif cls._matches_flag(t, '--add-team', '--remove-team'):
                has_team = True
                _, i = cls._one_flag_value(t, tokens, i)
            elif cls._matches_flag(t, '--node', '-n'):
                has_node = True
                _, i = cls._one_flag_value(t, tokens, i)
            elif t.startswith('-'):
                i = cls._skip_unknown_flag(tokens, i)
            else:
                if '@' in t:
                    emails.append(t)
                i += 1

        if not (has_role or has_team or has_node) or not emails:
            return None
        return ParsedIdentityMutation(
            emails=emails,
            has_role_change=has_role,
            has_team_change=has_team,
            has_node_change=has_node,
        )

    @classmethod
    def parse_share(cls, command: str) -> Optional[ParsedShare]:
        tokens = cls.tokenize(command)
        if not tokens:
            return None
        name = tokens[0]
        if name not in _FOLDER_CMDS and name not in _RECORD_CMDS:
            return None

        parsed = ParsedShare(
            command=name,
            is_folder=name in _FOLDER_CMDS,
            is_record=name in _RECORD_CMDS,
            is_nsf=name in _NSF_FOLDER or name in _NSF_RECORD,
        )
        i = 1
        positional: List[str] = []
        while i < len(tokens):
            t = tokens[i]
            if cls._matches_flag(t, '-e', '--email'):
                value, i = cls._one_flag_value(t, tokens, i)
                if value:
                    parsed.emails.append(value)
            elif cls._matches_flag(t, '-a', '--action'):
                value, i = cls._one_flag_value(t, tokens, i)
                parsed.action = (value or 'grant').strip().lower() or 'grant'
            elif t in ('-w', '--write'):
                parsed.can_edit = True
                i += 1
            elif t in ('-s', '--share') and parsed.is_record:
                parsed.can_share = True
                i += 1
            elif cls._matches_flag(t, '-p', '--manage-records'):
                value, i = cls._one_flag_value(t, tokens, i)
                if value is not None:
                    parsed.manage_records = value
            elif cls._matches_flag(t, '-o', '--manage-users'):
                value, i = cls._one_flag_value(t, tokens, i)
                if value is not None:
                    parsed.manage_users = value
            elif cls._matches_flag(t, '-r', '--role') and parsed.is_nsf:
                value, i = cls._one_flag_value(t, tokens, i)
                if value is not None:
                    parsed.nsf_role = value
            elif t.startswith('-'):
                i = cls._skip_unknown_flag(tokens, i)
            else:
                positional.append(t)
                i += 1

        if parsed.is_record:
            if positional:
                parsed.targets = [positional[-1]]
        else:
            parsed.targets = list(positional)

        return parsed if parsed.emails and parsed.targets else None
