from typing import Iterable, Dict, Set, List
from . import sox_types

class RebuildTask:
    def __init__(self, is_full_sync):      # type: (bool) -> None
        self.is_full_sync = is_full_sync   # type: bool
        self.records = set()               # type: Set[str]

    def update_records(self, record_uids):    # type: (Iterable[str]) -> None
        if self.is_full_sync:
            return
        self.records.update(record_uids)


class SoxData:
    def __init__(self, ec_private_key, storage):    # type: (bytes, sox_storage.SqliteSoxStorage) -> None
        self.ec_private_key = ec_private_key    # type: bytes
        self.storage = storage                  # type: sox_storage.SqliteSoxStorage
        self._records = {}                      # type: Dict[str, sox_types.Record]
        self._users = {}                        # type: Dict[str, sox_types.EnterpriseUser]
        task = RebuildTask(True)
        self.rebuild_data(task)

    def get_records(self, record_uids=None):
        return self._records if record_uids is None else {uid: self._records.get(uid) for uid in record_uids}

    def get_user(self, uid): # type: (str) -> sox_types.EnterpriseUser
        return self._users.get(uid)

    def get_users(self, user_uids=None):
        return self._users if user_uids is None else {uid: self.get_user(uid) for uid in user_uids}

    def get_user_records(self, user_uids=None):
        users = self._users.values() if user_uids is None else {self.get_user(uid) for uid in user_uids}
        recs = set()
        for user in users:
            for r_uid in user.records:
                recs.add(sox_types.UserRecord(user.user_uid, self._records.get(r_uid)))
        return recs

    @property
    def record_count(self):   # type: () -> int
        return len(self._records)

    def rebuild_data(self, changes):   # type: (RebuildTask) -> None
        def load_records(store, records_uids=None):
            # type: (sqlite_storage.SqliteSoxStorage) -> Dict[str, sox_types.Record]
            if records_uids:
                recs = set()
                for ruid in records_uids:
                    recs.update({rec for rec in store.records.select_by_filter('record_uid', ruid)})
            else:
                recs = {rec for rec in store.records.get_all()}
            records = {sox_types.Record.load(rec, self.ec_private_key) for rec in recs}
            return {record.record_uid: record for record in records}

        def link_user_records(store, users):
            # type: (sqlite_storage.SqliteSoxStorage, Set[sox_types.EnterpriseUser]) -> None
            links = store.get_user_record_links().get_all_links()
            for link in links:
                for user in users:
                    if link.user_uid == user.user_uid:
                        user.records.append(link.record_uid)

        def load_users(store):  # type: (sqlite_storage.SqliteSoxStorage) -> Dict[str, sox_types.EnterpriseUser]
            users = {sox_types.EnterpriseUser.load(eu) for eu in store.users.get_all()}
            link_user_records(store, users)
            u_lookup = {user.user_uid: user for user in users}
            return u_lookup

        self._records.update(load_records(self.storage, changes.records))
        self._users.update(load_users(self.storage))
