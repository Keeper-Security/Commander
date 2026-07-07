#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import csv
import io
from typing import Dict, List, Optional

class UserTeamMatcher:
    """Matches CyberArk vault users and groups to Keeper users and teams.

    CyberArk users are matched by email (personalDetails.email).
    CyberArk groups are matched by name (groupName).
    Manual overrides via --user-map JSON file.
    Unmatched identities are collected for the ca_users_to_provision.csv report.
    """

    def __init__(self, keeper_users: List[dict] = None,
                 keeper_teams: List[dict] = None,
                 user_map_override: Optional[Dict[str, str]] = None):
        """Initialize matcher.

        Args:
            keeper_users: list of Keeper user dicts with 'username'/'email' keys
            keeper_teams: list of Keeper team dicts with 'name' key
            user_map_override: dict mapping CyberArk username → Keeper email
        """
        # Build lookup tables
        self._user_emails = set()  # lowercase Keeper user emails
        if keeper_users:
            for u in keeper_users:
                email = u.get('email', '') or u.get('username', '')
                if email:
                    self._user_emails.add(email.lower())

        self._team_names = set()  # lowercase Keeper team names
        if keeper_teams:
            for t in keeper_teams:
                name = t.get('name', '') or t.get('team_name', '')
                if name:
                    self._team_names.add(name.lower())

        self._overrides = {}
        if user_map_override:
            self._overrides = {
                str(k).lower(): str(v).lower()
                for k, v in user_map_override.items()
            }

        self.unmatched = []  # list of unmatched member dicts for CSV

    def match_user(self, cyberark_username: str,
                   cyberark_email: str = '',
                   cyberark_groups: str = '') -> Optional[str]:
        """Try to match a CyberArk user to a Keeper user.

        Returns the matched Keeper email or None if not found.
        """
        # Check manual override first
        override = self._overrides.get(cyberark_username.lower())
        if override and override in self._user_emails:
            return override

        # Match by email
        if cyberark_email and cyberark_email.lower() in self._user_emails:
            return cyberark_email.lower()

        # Match by username (might be an email)
        if '@' in cyberark_username and cyberark_username.lower() in self._user_emails:
            return cyberark_username.lower()

        # Not found
        self.unmatched.append({
            'cyberark_username': cyberark_username,
            'cyberark_email': cyberark_email,
            'cyberark_groups': cyberark_groups,
            'keeper_match_found': 'no',
            'keeper_email': '',
            'suggested_action': 'provision_user',
        })
        return None

    def match_team(self, cyberark_group_name: str) -> Optional[str]:
        """Try to match a CyberArk group to a Keeper team.

        Returns the matched Keeper team name or None if not found.
        """
        if cyberark_group_name.lower() in self._team_names:
            return cyberark_group_name
        # Not found
        self.unmatched.append({
            'cyberark_username': cyberark_group_name,
            'cyberark_email': '',
            'cyberark_groups': '(group)',
            'keeper_match_found': 'no',
            'keeper_email': '',
            'suggested_action': 'create_team',
        })
        return None

    def generate_csv(self) -> str:
        """Generate ca_users_to_provision.csv content from unmatched identities.

        Returns CSV as a string (no file I/O — caller writes to file/attachment).
        Uses csv.writer for proper quoting and escaping (prevents formula injection).
        """
        if not self.unmatched:
            return ''
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow(['cyberark_username', 'cyberark_email', 'cyberark_groups',
                         'keeper_match_found', 'keeper_email', 'suggested_action'])
        for row in self.unmatched:
            # Sanitize formula-triggering prefixes (=, +, -, @, \t, \r).
            # Strip leading whitespace first — spreadsheet apps often ignore
            # it when parsing formulas, so " =cmd()" would bypass a naive
            # first-char check.
            def _sanitize(val):
                s = str(val).lstrip()
                if s and s[0] in ('=', '+', '-', '@', '\t', '\r'):
                    s = "'" + s  # prefix with single quote to neutralize
                return s
            writer.writerow([
                _sanitize(row.get('cyberark_username', '')),
                _sanitize(row.get('cyberark_email', '')),
                _sanitize(row.get('cyberark_groups', '')),
                row.get('keeper_match_found', 'no'),
                row.get('keeper_email', ''),
                row.get('suggested_action', ''),
            ])
        return output.getvalue().strip()
