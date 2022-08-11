#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.coms
#
import datetime
import sqlite3
from typing import Callable

from ..storage import sqlite_dao, sqlite
from .storage_types import StorageRecord, StorageUser, StorageUserRecordLink


class Metadata:
    def __init__(self):
        self.last_updated = 0
        self.records_dated = 0
        self.last_pw_audit = 0


class SqliteSoxStorage:
    def __init__(self, get_connection, owner):
        self.get_connection = get_connection
        self.owner = owner

        metadata_schema = sqlite_dao.TableSchema.load_schema(Metadata, [], owner_column='account_uid')
        user_schema = sqlite_dao.TableSchema.load_schema(StorageUser, 'user_uid')
        record_schema = sqlite_dao.TableSchema.load_schema(StorageRecord, 'record_uid')
        user_record_schema = sqlite_dao.TableSchema.load_schema(StorageUserRecordLink, ['record_uid', 'user_uid'],
                                                                indexes={'UserUID': 'user_uid'})

        sqlite_dao.verify_database(self.get_connection(),
                                   (metadata_schema, user_schema, record_schema, user_record_schema))

        self._metadata = sqlite.SqliteRecordStorage(self.get_connection, metadata_schema, owner)
        self._users = sqlite.SqliteEntityStorage(self.get_connection, user_schema)
        self._records = sqlite.SqliteEntityStorage(self.get_connection, record_schema)
        self._user_record_links = sqlite.SqliteLinkStorage(self.get_connection, user_record_schema)

    def _get_history(self):
        return self._metadata.load() or Metadata()

    @property
    def last_updated(self):
        return self._get_history().last_updated

    def set_last_updated(self):
        history = self._get_history()
        history.last_updated = int(datetime.datetime.now().timestamp())
        self._metadata.store(history)

    @property
    def records_dated(self):
        return self._get_history().records_dated

    def set_records_dated(self):
        history = self._get_history()
        history.records_dated = int(datetime.datetime.now().timestamp())
        self._metadata.store(history)

    @property
    def last_pw_audit(self):
        return self._get_history().last_pw_audit

    def set_last_pw_audit(self):
        history = self._get_history()
        history.last_pw_audit = int(datetime.datetime.now().timestamp())
        self._metadata.store(history)

    def get_users(self):
        return self._users

    def get_records(self):
        return self._records

    def get_user_record_links(self):
        return self._user_record_links

    @property
    def records(self):    # type: () -> IEntityStorage[storage_types.StorageRecord]
        return self.get_records()

    @property
    def users(self):    # type: () -> IEntityStorage[storage_types.StorageUser]
        return self.get_users()

    def clear(self):
        self._records.delete_all()
        self._users.delete_all()
        self._user_record_links.delete_all()
        self._metadata.delete_all()

    def rebuild(self, users, records, links):
        self.clear()
        self._users.put_entities(users)
        self._records.put_entities(records)
        self._user_record_links.put_links(links)
        self.set_last_updated()