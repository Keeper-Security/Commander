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
from typing import List, Optional

_NSF_FOLDER = frozenset({'nsf-share-folder'})
_NSF_RECORD = frozenset({'nsf-share-record'})
_FOLDER_CMDS = frozenset({'share-folder', 'nsf-share-folder', 'sf'})
_RECORD_CMDS = frozenset({'share-record', 'nsf-share-record', 'sr'})
_IDENTITY_FLAGS = frozenset({
    '--add-role', '--remove-role', '--add-team', '--remove-team', '--node', '-n',
})


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


class SailPointCommandParser:
    """Parse enterprise-user invite and share-* command strings."""

    @staticmethod
    def _tokenize(command: str) -> List[str]:
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()

    @classmethod
    def parse_invite(cls, command: str) -> Optional[ParsedInvite]:
        tokens = cls._tokenize(command)
        if not tokens or tokens[0] not in ('enterprise-user', 'eu'):
            return None

        parsed = ParsedInvite()
        i = 1
        positional: List[str] = []
        while i < len(tokens):
            t = tokens[i]
            if t in ('--invite', '--add', '-invite'):
                parsed.is_invite = True
                i += 1
            elif t in ('--node', '-n') and i + 1 < len(tokens):
                parsed.node = tokens[i + 1]
                i += 2
            elif t == '--add-role' and i + 1 < len(tokens):
                parsed.roles.append(tokens[i + 1])
                i += 2
            elif t == '--add-team' and i + 1 < len(tokens):
                parsed.teams.append(tokens[i + 1])
                i += 2
            elif t.startswith('-'):
                if i + 1 < len(tokens) and not tokens[i + 1].startswith('-'):
                    i += 2
                else:
                    i += 1
            else:
                positional.append(t)
                i += 1

        parsed.emails = [e for e in positional if '@' in e]
        return parsed if parsed.is_invite else None

    @classmethod
    def parse_identity_mutation(cls, command: str) -> Optional[ParsedIdentityMutation]:
        tokens = cls._tokenize(command)
        if not tokens or tokens[0] not in ('enterprise-user', 'eu'):
            return None

        emails: List[str] = []
        mutating = False
        i = 1
        while i < len(tokens):
            t = tokens[i]
            if t in _IDENTITY_FLAGS:
                mutating = True
                if i + 1 < len(tokens) and not tokens[i + 1].startswith('-'):
                    i += 2
                else:
                    i += 1
            elif t.startswith('-'):
                if i + 1 < len(tokens) and not tokens[i + 1].startswith('-'):
                    i += 2
                else:
                    i += 1
            else:
                if '@' in t:
                    emails.append(t)
                i += 1

        if not mutating or not emails:
            return None
        return ParsedIdentityMutation(emails=emails)

    @classmethod
    def parse_share(cls, command: str) -> Optional[ParsedShare]:
        tokens = cls._tokenize(command)
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
            if t in ('-e', '--email') and i + 1 < len(tokens):
                parsed.emails.append(tokens[i + 1])
                i += 2
            elif t in ('-a', '--action') and i + 1 < len(tokens):
                parsed.action = tokens[i + 1].strip().lower() or 'grant'
                i += 2
            elif t in ('-w', '--write'):
                parsed.can_edit = True
                i += 1
            elif t in ('-s', '--share') and name in _RECORD_CMDS:
                parsed.can_share = True
                i += 1
            elif t in ('-p', '--manage-records') and i + 1 < len(tokens):
                parsed.manage_records = tokens[i + 1]
                i += 2
            elif t in ('-o', '--manage-users') and i + 1 < len(tokens):
                parsed.manage_users = tokens[i + 1]
                i += 2
            elif (
                t in ('-r', '--role')
                and name in (_NSF_FOLDER | _NSF_RECORD)
                and i + 1 < len(tokens)
            ):
                parsed.nsf_role = tokens[i + 1]
                i += 2
            elif t.startswith('-'):
                if i + 1 < len(tokens) and not tokens[i + 1].startswith('-'):
                    i += 2
                else:
                    i += 1
            else:
                positional.append(t)
                i += 1

        if name in _RECORD_CMDS:
            # Classic/NSF record share: single target (last positional).
            if positional:
                parsed.targets = [positional[-1]]
        else:
            parsed.targets = list(positional)

        return parsed if parsed.emails and parsed.targets else None
