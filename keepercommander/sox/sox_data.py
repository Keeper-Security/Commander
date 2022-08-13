from typing import Iterable, Dict, Set, List, Optional

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from . import sox_types, sqlite_storage


class RebuildTask:
    def __init__(self, is_full_sync):      # type: (bool) -> None
        self.is_full_sync = is_full_sync   # type: bool
        self.records = set()               # type: Set[str]

    def update_records(self, record_ids):    # type: (Iterable[str]) -> None
        if self.is_full_sync:
            return
        self.records.update(record_ids)


class SoxData:
    def __init__(self, ec_private_key, storage):
        # type: (EllipticCurvePrivateKey, sqlite_storage.SqliteSoxStorage) -> None
        self.ec_private_key = ec_private_key    # type: EllipticCurvePrivateKey
        self.storage = storage                  # type: sqlite_storage.SqliteSoxStorage
        self._records = {}                      # type: Dict[str, sox_types.Record]
        self._users = {}                        # type: Dict[int, sox_types.EnterpriseUser]
        task = RebuildTask(True)
        self.rebuild_data(task)

    def get_records(self, record_ids=None):
        return self._records if record_ids is None else {uid: self._records.get(uid) for uid in record_ids}

    def get_user(self, uid):    # type: (int) -> sox_types.EnterpriseUser
        return self._users.get(uid)

    def get_users(self, user_ids=None):
        return self._users if user_ids is None else {uid: self.get_user(uid) for uid in user_ids}

    def get_user_records(self, user_ids=None):  # type: (List[int]) -> List[sox_types.UserRecord]
        users = self._users.values() if user_ids is None else {self.get_user(uid) for uid in user_ids}
        user_records = []
        for user in users:
            for r_uid in user.records:
                user_records.append(sox_types.UserRecord(user.user_uid, self._records.get(r_uid)))
        return user_records

    @property
    def record_count(self):   # type: () -> int
        return len(self._records)

    def rebuild_data(self, changes):   # type: (RebuildTask) -> None
        def load_records(store, records_ids=None):
            # type: (sqlite_storage.SqliteSoxStorage, Optional[Iterable[str]]) -> Dict[str, sox_types.Record]
            record_entities = store.records.get_entities(records_ids) if records_ids else store.records.get_all()
            records = [sox_types.Record.load(entity, self.ec_private_key) for entity in record_entities]
            return {record.record_uid: record for record in records}

        def link_user_records(store, users):
            # type: (sqlite_storage.SqliteSoxStorage, Iterable[sox_types.EnterpriseUser]) -> None
            links = store.get_user_record_links().get_all_links()
            for link in links:
                for user in users:
                    if link.user_uid == user.user_uid:
                        user.records.append(link.record_uid)

        def load_users(store):  # type: (sqlite_storage.SqliteSoxStorage) -> Dict[int, sox_types.EnterpriseUser]
            users = [sox_types.EnterpriseUser.load(eu) for eu in store.users.get_all()]
            link_user_records(store, users)
            u_lookup = {user.user_uid: user for user in users}
            return u_lookup

        self._records.update(load_records(self.storage, changes.records))
        if changes.is_full_sync:
            self._users.update(load_users(self.storage))
