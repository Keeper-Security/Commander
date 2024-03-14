import logging
from typing import Iterable, Dict, Set, List, Optional

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from . import sox_types, sqlite_storage, storage_types
from .sox_types import RecordPermissions, SharedFolder
from .. import crypto, utils
from ..error import Error
from ..params import KeeperParams


class RebuildTask:
    def __init__(self, is_full_sync, load_compliance_data=False, load_aging_data=False):
        # type: (bool, bool, bool) -> None
        self.is_full_sync = is_full_sync                    # type: bool
        self.load_compliance_data = load_compliance_data    # type: bool
        self.records = set()                                # type: Set[str]
        self.load_aging_data = load_aging_data              # type: bool

    def update_records(self, record_ids):    # type: (Iterable[str]) -> None
        if self.is_full_sync:
            return
        self.records.update(record_ids)


def get_ec_private_key(params):  # type: (KeeperParams) -> EllipticCurvePrivateKey
    tree_key = params.enterprise['unencrypted_tree_key']
    ecc_key = utils.base64_url_decode(params.enterprise['keys']['ecc_encrypted_private_key'])
    ecc_key = crypto.decrypt_aes_v2(ecc_key, tree_key)
    return crypto.load_ec_private_key(ecc_key)


def clear_lookup(lookup, uids=None):  # type: (dict, Optional[Iterable]) -> None
    if uids:
        [lookup.pop(k) for k in uids]
    else:
        lookup.clear()


class SoxData:
    def __init__(self, params, storage, no_cache=False):
        # type: (KeeperParams, sqlite_storage.SqliteSoxStorage, Optional[bool]) -> None
        self.storage = storage                  # type: sqlite_storage.SqliteSoxStorage
        self._records = {}                      # type: Dict[str, sox_types.Record]
        self._users = {}                        # type: Dict[int, sox_types.EnterpriseUser]
        self._teams = {}                        # type: Dict[str, sox_types.Team]
        self._shared_folders = {}               # type: Dict[str, sox_types.SharedFolder]
        self.ec_private_key = get_ec_private_key(params)
        self.tree_key = params.enterprise.get('unencrypted_tree_key', b'')
        task = RebuildTask(True)
        self.rebuild_data(task, no_cache)

    def get_records(self, record_ids=None):
        return self._records if record_ids is None else {uid: self._records.get(uid) for uid in record_ids}

    def get_user(self, uid):    # type: (int) -> sox_types.EnterpriseUser
        return self._users.get(uid)

    def get_users(self, user_ids=None):
        return self._users if user_ids is None else {uid: self.get_user(uid) for uid in user_ids}

    def get_team(self, team_uid):
        return self._teams.get(team_uid)

    def get_teams(self, team_uids=None):
        return self._teams if team_uids is None else {uid: self.get_team(uid) for uid in team_uids}

    def get_user_records(self, user_uids=None):
        if user_uids:
            users = set()
            for uid in user_uids:
                user = self.get_user(uid)
                if user:
                    users.add(user)
        else:
            users = self._users.values()

        recs = set()
        for user in users:
            for r_uid in user.records:
                recs.add(sox_types.UserRecord(user.user_uid, self._records.get(r_uid)))
        return recs

    def get_shared_folders(self, sf_uids=None):
        return self._shared_folders if sf_uids is None else {uid: self._shared_folders.get(uid) for uid in sf_uids}

    def get_record_sfs(self, record_uid):
        get_ruids = lambda sf: [rp.record_uid for rp in sf.record_permissions]
        return [sf.folder_uid for sf in self._shared_folders.values() if record_uid in get_ruids(sf)]

    def get_record_owner(self, rec_uid):
        owner = None
        if rec_uid in self._records:
            for user in self._users.values():
                if rec_uid in user.records:
                    owner = user
                    break
        return owner

    def get_vault_records(self, user_ref):
        user_id = user_ref if isinstance(user_ref, int) or user_ref.isdigit() else next((k for k, v in self._users.items() if v.email == user_ref), 0)
        owned_sa_ruids = {ruid: rec for ruid, rec in self._records.items() if user_id in rec.user_permissions.keys()}

        # Get SF-shared records
        # Shared to team
        user_teams = {tuid for tuid, t in self._teams.items() if user_id in t.users}
        team_sf_uids = {sfuid for sfuid, sf in self._shared_folders.items() if sf.teams.intersection(user_teams)}
        # Shared to user
        user_sf_uids = {sfuid for sfuid, sf in self._shared_folders.items() if user_id in sf.users}
        sf_uids = team_sf_uids.union(user_sf_uids)
        user_sfs = [sf for uid, sf in self._shared_folders.items() if uid in sf_uids]
        user_sf_rec_uids = {rp.record_uid for sf in user_sfs for rp in sf.record_permissions}

        vault_record_uids = user_sf_rec_uids.union(owned_sa_ruids)
        return self.get_records(vault_record_uids)

    def clear_records(self, uids=None):
        clear_lookup(self._records, uids)

    def clear_users(self, uids=None):
        clear_lookup(self._users, uids)

    def clear_teams(self, uids=None):
        clear_lookup(self._teams, uids)

    def clear_shared_folders(self, uids=None):
        clear_lookup(self._shared_folders, uids)

    def clear_all(self):
        self.clear_records()
        self.clear_users()
        self.clear_teams()
        self.clear_shared_folders()

    @property
    def record_count(self):   # type: () -> int
        return len(self._records)

    def rebuild_data(self, changes, no_cache=False):   # type: (RebuildTask, Optional[bool]) -> None
        def decrypt(data):  # type: (bytes or str) -> str
            if isinstance(data, str):
                return data

            decrypted = ''
            try:
                decrypted_bytes = crypto.decrypt_aes_v1(data, self.tree_key) if data else b''
                decrypted = decrypted_bytes.decode()
            except Error as e:
                logging.info(f'Error decrypting data: type = {type(data)}, value = {data}, message = {e.message}')
            return decrypted

        def link_record_permissions(store, record_lookup):
            links = store.get_record_permissions().get_all_links()
            for link in links:
                record = record_lookup.get(link.record_uid)
                if record:
                    record.user_permissions.update({link.user_uid: link.permissions})
                else:
                    logging.info(f'record (uid = {link.record_uid}) not found')

            return record_lookup

        def load_records(store, changes):
            # type: (sqlite_storage.SqliteSoxStorage, RebuildTask) -> Dict[str, sox_types.Record]
            entities = []   # type: List[storage_types.StorageRecord]
            if changes.records:
                for uid in changes.records:
                    entity = store.records.get_entity(uid)
                    if entity:
                        entities.append(entity)
            else:
                entities.extend(store.records.get_all())

            record_lookup = {}
            for entity in entities:
                record = self._records.get(entity.record_uid) or sox_types.Record()
                record.update_properties(entity, self.ec_private_key)
                record_lookup[record.record_uid] = record

            record_lookup = link_record_aging(store, record_lookup)
            return link_record_permissions(store, record_lookup) if changes.load_compliance_data else record_lookup

        def link_record_aging(store, record_lookup):
            for aging in store.record_aging.get_all():
                record = record_lookup.get(aging.record_uid)
                if record:
                    record.created = aging.created
                    record.last_pw_change = aging.last_pw_change
                    record.last_modified = aging.last_modified
                    record.last_rotation = aging.last_rotation
            return record_lookup

        def link_user_records(store, user_lookup):
            links = store.get_user_record_links().get_all_links()
            for link in links:
                user = user_lookup.get(link.user_uid)
                rec = self._records.get(link.record_uid)
                if user:
                    user.trash_records.add(rec.record_uid) if rec.in_trash else user.active_records.add(rec.record_uid)
                    user.records.add(link.record_uid)
                else:
                    logging.info(f'user (uid = {link.user_uid} not found')
            return user_lookup

        def load_users(store):  # type: (sqlite_storage.SqliteSoxStorage) -> Dict[int, sox_types.EnterpriseUser]
            users = [sox_types.EnterpriseUser.load(eu, decrypt_fn=decrypt) for eu in store.users.get_all()]
            u_lookup = {user.user_uid: user for user in users}
            return link_user_records(store, u_lookup)

        def load_teams(store):
            teams = [sox_types.Team.load(entity) for entity in store.teams.get_all()]
            team_lookup = {team.team_uid: team for team in teams}
            return link_team_users(store, team_lookup)

        def link_team_users(store, team_lookup):
            links = store.get_team_user_links().get_all_links()
            for link in links:
                team = team_lookup.get(link.team_uid)
                team.users.append(link.user_uid)
            return team_lookup

        def load_shared_folders(store):
            sf_lookup = dict()  # type: Dict[str, SharedFolder]
            sf_lookup = link_sf_records(store, sf_lookup)
            sf_lookup = link_sf_users(store, sf_lookup)
            sf_lookup = link_sf_teams(store, sf_lookup)
            return sf_lookup

        def link_sf_records(store, folder_lookup):
            sf_record_links = store.get_sf_record_links().get_all_links()
            for link in sf_record_links:
                folder = folder_lookup[link.folder_uid] if link.folder_uid in folder_lookup \
                    else SharedFolder(link.folder_uid)
                folder.update_record_permissions(RecordPermissions(link.record_uid, link.permissions))
                folder_lookup[link.folder_uid] = folder

            return folder_lookup

        def link_sf_users(store, folder_lookup):
            sf_user_links = store.get_sf_user_links().get_all_links()
            for link in sf_user_links:
                folder = folder_lookup[link.folder_uid] if link.folder_uid in folder_lookup \
                    else SharedFolder(link.folder_uid)
                folder.users.add(link.user_uid)
                folder_lookup[link.folder_uid] = folder

            return folder_lookup

        def link_sf_teams(store, folder_lookup):
            sf_team_links = store.get_sf_team_links().get_all_links()
            for link in sf_team_links:
                folder = folder_lookup[link.folder_uid] if link.folder_uid in folder_lookup \
                    else SharedFolder(link.folder_uid)
                folder.teams.add(link.team_uid)
                folder_lookup[link.folder_uid] = folder

            return folder_lookup

        if changes.is_full_sync:
            self.clear_all()
        if changes.load_aging_data:
            self.clear_records(changes.records)
        if changes.load_compliance_data:
            self._teams.update(load_teams(self.storage))
            self._shared_folders.update(load_shared_folders(self.storage))
        self._records.update(load_records(self.storage, changes))
        if changes.is_full_sync or changes.load_compliance_data:
            self._users.update(load_users(self.storage))
        if no_cache:
            self.storage.delete_db()
