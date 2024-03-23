from enum import Enum
from typing import Dict, List

from keepercommander import api, utils
from keepercommander.proto import enterprise_pb2
from keepercommander.record import Record
from keepercommander.subfolder import find_folders, get_folder_path


def get_shared_records(params, record_uids, cache_only=False):
    def fetch_team_members(t_uids):
        members = {}
        if params.enterprise_ec_key:
            for team_uid in t_uids:
                team_users = members.get(team_uid, set())
                rq = enterprise_pb2.GetTeamMemberRequest()
                rq.teamUid = utils.base64_url_decode(team_uid)
                endpoint = 'vault/get_team_members'
                rs = api.communicate_rest(params, rq, endpoint, rs_type=enterprise_pb2.GetTeamMemberResponse)
                if rs.enterpriseUser:
                    team_users.update({x.email for x in rs.enterpriseUser})
                    members[team_uid] = team_users
        return members

    def get_cached_team_members(t_uids, uname_lookup):
        members = {}
        if not params.enterprise:
            return members

        team_users = params.enterprise.get('team_users') or []
        team_users = [tu for tu in team_users if tu.get('user_type') != 2 and tu.get('team_uid') in t_uids]

        for tu in team_users:
            user_id = tu.get('enterprise_user_id')
            username = uname_lookup.get(user_id)
            team_uid = tu.get('team_uid')
            t_members = members.get(team_uid, set())
            t_members.add(username)
            members[team_uid] = t_members

        return members

    def fetch_sf_admins():
        sf_uids = [uid for uid in params.shared_folder_cache]
        return {sf_uid: api.get_share_admins_for_shared_folder(params, sf_uid) for sf_uid in sf_uids}

    def get_restricted_role_members(uname_lookup):
        # Get team_uids and usernames (assigned directly and indirectly) in share-restricted roles
        members = set()
        if not params.enterprise:
            return members

        restrict_key = 'restrict_sharing_all'
        enf_key = 'enforcements'
        r_enforcements = params.enterprise.get('role_enforcements', [])
        no_share_roles = {re.get('role_id') for re in r_enforcements if re.get(enf_key).get(restrict_key) == 'true'}
        r_users = [u for u in params.enterprise.get('role_users', []) if u.get('role_id') in no_share_roles]
        r_teams = [t for t in params.enterprise.get('role_teams', []) if t.get('role_id') in no_share_roles]
        no_share_users = {uname_lookup.get(u.get('enterprise_user_id')) for u in r_users}
        no_share_teams = {t.get('team_uid') for t in r_teams}
        cached_team_members = get_cached_team_members(no_share_teams, uname_lookup)
        no_share_team_members = {t for team_uid in no_share_teams for t in cached_team_members.get(team_uid) or []}
        members = no_share_users.union(no_share_teams).union(no_share_team_members)
        return members

    api.get_record_shares(params, record_uids)
    sf_teams = [shared_folder.get('teams', []) for shared_folder in params.shared_folder_cache.values()]
    sf_share_admins = fetch_sf_admins() if not cache_only else {}
    team_uids = {t.get('team_uid') for teams in sf_teams for t in teams}
    enterprise_users = params.enterprise.get('users') if params.enterprise else []
    username_lookup = {u.get('enterprise_user_id'): u.get('username') for u in enterprise_users}
    restricted_role_members = get_restricted_role_members(username_lookup)
    team_members = get_cached_team_members(team_uids, username_lookup) if cache_only or params.enterprise \
        else fetch_team_members(team_uids)
    records = [api.get_record(params, uid) for uid in record_uids]  # type: List[Record or None]
    records = [r for r in records if r]
    shared_records = [SharedRecord(params, r, sf_share_admins, team_members, restricted_role_members) for r in records]
    return {shared_record.uid: shared_record for shared_record in shared_records}


class SharePermissions:
    SharePermissionsType = Enum('SharePermissionsType', ['USER', 'SF_USER', 'TEAM', 'TEAM_USER'])
    bits_text_lookup = {(1 << 0): 'Edit', (1 << 1): 'Share'}

    def __init__(self, sp_types=None):
        self.to_uid = ''
        self.to_name = ''
        self.can_edit = False
        self.can_share = False
        self.can_view = True
        self.expiration = 0
        self.folder_path = ''
        self.types = set()
        self.bits = 0
        self.is_admin = False
        self.team_members = dict()
        self.user_perms: Dict[str, SharePermissions] = {}
        self.team_perms: Dict[str, SharePermissions] = {}
        self.update_types(sp_types)

    def update_types(self, sp_types):
        if sp_types is not None:
            update_types_fn = self.types.update if isinstance(sp_types, set) else self.types.add
            update_types_fn(sp_types)

    def get_target(self, show_team_info):
        return self.get_team_view_name() if show_team_info else self.to_name

    def get_team_view_name(self):
        prefix_lookup = {
            SharePermissions.SharePermissionsType.TEAM: '(Team)',
            SharePermissions.SharePermissionsType.TEAM_USER: '(Team User)',
            SharePermissions.SharePermissionsType.USER: '',
            SharePermissions.SharePermissionsType.SF_USER: ''
        }
        prefix = ''.join(prefix_lookup.get(t) for t in self.types)
        return f'{prefix} {self.to_name}'.strip()

    @property
    def permissions_text(self):
        if not self.can_edit and not self.can_share:
            return 'Read Only' if self.can_view else 'Launch Only'
        else:
            privs = [self.can_share and 'Share', self.can_edit and 'Edit']
            return f'Can {" & ".join([p for p in privs if p])}'

    @staticmethod
    def load_permissions(perms, sp_type):
        sp = SharePermissions(sp_type)
        sp.to_uid = perms.get('uid') or perms.get('team_uid')
        sp.to_name = perms.get('username') or perms.get('name')
        sp.is_admin = perms.get('share_admin') or perms.get('is_admin')
        sp.can_edit = perms.get('editable') or perms.get('manage_records') or sp.is_admin
        sp.can_share = perms.get('shareable') or perms.get('manage_users') or sp.is_admin
        sp.can_view = perms.get('view', True)
        exp = perms.get('expiration')
        if isinstance(exp, int) and exp > 0:
            sp.expiration = exp
        return sp

    def apply_restrictions(self, *restrictions):
        for member in self.team_members.values():
            member.apply_restrictions(*restrictions)
        restrictions = ','.join(restrictions).lower()
        if 'edit' in restrictions:
            self.can_edit = False
        if 'share' in restrictions:
            self.can_share = False
        if 'view' in restrictions:
            self.can_view = False


class SharedRecord:
    """Defines a Keeper Shared Record (shared either via Direct-Share or as a child of a Shared-Folder node)"""

    def __init__(self, params, record, sf_sharing_admins, team_members, role_restricted_members):
        has_owner = record.record_uid in params.record_owner_cache
        user_owned = has_owner and params.record_owner_cache.get(record.record_uid).owner
        self.owner = params.user if user_owned else ''
        self.uid = record.record_uid
        self.name = record.title
        self.shared_folders = None
        self.sf_shares = {}
        self.permissions: Dict[str, SharePermissions] = {}
        self.team_permissions: Dict[str, SharePermissions] = {}
        self.user_permissions: Dict[str, SharePermissions] = {}
        self.revision = None
        self.params = params
        self.folder_uids = list(find_folders(params, record.record_uid))
        self.folder_paths = [get_folder_path(params, fuid) for fuid in self.folder_uids]
        self.team_members = team_members

        self.load(params, sf_sharing_admins, team_members, role_restricted_members)

    def get_ordered_permissions(self):
        ordered = list(self.permissions.values())
        for user_perms in self.user_permissions.values():
            if user_perms.to_uid:
                ordered.remove(user_perms)
                team_perms = self.team_permissions.get(user_perms.to_uid)
                ordered.insert(ordered.index(team_perms) + 1, user_perms)
        return ordered

    def merge_permissions(self, share_target, perms_to_merge, sp_type):
        new_perms = SharePermissions.load_permissions(perms_to_merge, sp_type)
        existing = self.permissions.get(share_target) or new_perms
        existing.to_uid = new_perms.to_uid or existing.to_uid
        existing.is_admin = existing.is_admin or new_perms.is_admin
        existing.can_share = existing.can_share or new_perms.can_share
        existing.can_edit = existing.can_edit or new_perms.can_edit
        existing.update_types(new_perms.types)
        if existing.expiration > 0:
            if new_perms.expiration > 0:
                if new_perms.expiration > existing.expiration:
                    existing.expiration = new_perms.expiration
            else:
                existing.expiration = 0

        self.permissions[share_target] = existing
        return existing

    def merge_user_permissions(self, email, user_perms, sp_type=None):
        new_perms = self.merge_permissions(email, user_perms, sp_type or SharePermissions.SharePermissionsType.USER)
        self.user_permissions[email] = new_perms
        return new_perms

    def merge_team_permissions(self, team_uid, team_perms):
        new_perms = self.merge_permissions(team_uid, team_perms, SharePermissions.SharePermissionsType.TEAM)
        self.team_permissions[team_uid] = new_perms
        return new_perms

    def load(self, params, sf_sharing_admins, team_members, role_restricted_members):
        def apply_team_restrictions(team_perms):
            if not params.enterprise:
                return team_perms

            restriction_permission_lookup = {
                'restrict_edit': 'manage_records',
                'restrict_sharing': 'manage_users',
                'restrict_view': 'view'
            }

            teams_cache = params.enterprise.get('teams', {})
            perms = team_perms.copy()
            team_info = next((t for t in teams_cache if t.get('team_uid') == perms.get('team_uid')))
            for restriction, permission in restriction_permission_lookup.items():
                if team_info.get(restriction):
                    perms[permission] = False
            return perms

        def apply_role_restrictions():
            for restricted_target in role_restricted_members:
                perms = self.permissions.get(restricted_target)
                perms and perms.apply_restrictions('share')

        def update_sf_shares(share_to, sf_uid):
            if sf_uid:
                sf_shares = self.sf_shares.get(sf_uid, set())
                sf_shares.add(share_to)
                self.sf_shares[sf_uid] = sf_shares

        def load_user_permissions(u_perms, sf_uid=None, sp_type=None):
            for up in u_perms:
                email = up.get('username')
                update_sf_shares(email, sf_uid)
                share_admins = sf_sharing_admins.get(sf_uid)
                is_admin = share_admins and email in share_admins
                if is_admin:
                    up['editable'] = True
                    up['shareable'] = True
                    up['share_admin'] = True
                self.merge_user_permissions(email, up, sp_type)

        def load_team_permissions(t_perms, sf_uid):
            for tp in t_perms:
                team_uid = tp.get('team_uid')
                team_name = tp.get('name')
                update_sf_shares(team_name, sf_uid)
                tp = apply_team_restrictions(tp)
                merged = self.merge_team_permissions(team_uid, tp)

                # load team-members' permissions
                t_users = team_members.get(team_uid, set())
                ups = [{**tp, 'username': t_username} for t_username in t_users]
                load_user_permissions(ups, sf_uid, SharePermissions.SharePermissionsType.TEAM_USER)
                merged.team_members.update({t_username: self.permissions.get(t_username) for t_username in t_users})

        rec_cached = params.record_cache.get(self.uid)
        shares = rec_cached.get('shares', dict())

        user_perms = list(shares.get('user_permissions', []))
        if len(user_perms) > 0:
            self.owner = next((up.get('username') for up in user_perms if up.get('owner')), '')
            load_user_permissions(user_perms)

        sf_perms = shares.get('shared_folder_permissions', [])
        SF_UID = 'shared_folder_uid'
        sf_cache = params.shared_folder_cache
        shared_folders = {sfp.get(SF_UID): sf_cache.get(sfp.get(SF_UID)) for sfp in sf_perms}
        shared_folders = {k: v for k, v in shared_folders.items() if v}

        sf_user_perms = {sf_uid: sf.get('users') for sf_uid, sf in shared_folders.items() if sf.get('users')}
        team_perms = {sf_uid: sf.get('teams') for sf_uid, sf in shared_folders.items() if sf.get('teams')}

        for sf_uid, sf_ups in sf_user_perms.items():
            share_type = SharePermissions.SharePermissionsType.SF_USER
            load_user_permissions(sf_ups, sf_uid, share_type)
        for sf_uid, teams in team_perms.items():
            load_team_permissions(teams, sf_uid)

        apply_role_restrictions()
