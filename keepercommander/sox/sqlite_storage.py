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
import logging
import os

from ..storage import sqlite_dao, sqlite
from .storage_types import StorageRecord, StorageUser, StorageUserRecordLink, StorageTeam, StorageRole, \
    StorageRecordPermissions, StorageTeamUserLink, StorageSharedFolderRecordLink, StorageSharedFolderUserLink, \
    StorageSharedFolderTeamLink, StorageRecordAging
from ..storage.types import IEntityStorage


class Metadata:
    def __init__(self):
        self.prelim_data_last_update = 0
        self.records_dated = 0
        self.last_pw_audit = 0
        self.compliance_data_last_update = 0
        self.shared_records_only = False


class SqliteSoxStorage:
    def __init__(self, get_connection, owner, database_name=''):
        self.get_connection = get_connection
        self.owner = owner
        self.database_name = database_name

        metadata_schema = sqlite_dao.TableSchema.load_schema(Metadata, [], owner_column='account_uid')
        user_schema = sqlite_dao.TableSchema.load_schema(StorageUser, 'user_uid')
        record_schema = sqlite_dao.TableSchema.load_schema(StorageRecord, 'record_uid')
        record_aging_schema = sqlite_dao.TableSchema.load_schema(StorageRecordAging, 'record_uid')
        user_record_schema = sqlite_dao.TableSchema.load_schema(StorageUserRecordLink, ['record_uid', 'user_uid'],
                                                                indexes={'UserUID': 'user_uid'})
        team_schema = sqlite_dao.TableSchema.load_schema(StorageTeam, 'team_uid')
        team_user_schema = sqlite_dao.TableSchema.load_schema(StorageTeamUserLink, ['team_uid', 'user_uid'],
                                                              indexes={'UserUID': 'user_uid'})
        role_schema = sqlite_dao.TableSchema.load_schema(StorageRole, 'role_id')
        record_permissions_schema = sqlite_dao.TableSchema.load_schema(StorageRecordPermissions,
                                                                       ['record_uid', 'user_uid'],
                                                                       indexes={'UserUID': 'user_uid'})
        shared_folder_record_schema = sqlite_dao.TableSchema.load_schema(StorageSharedFolderRecordLink,
                                                                         ['folder_uid', 'record_uid'],
                                                                         indexes={'RecordUID': 'record_uid'})
        shared_folder_user_schema = sqlite_dao.TableSchema.load_schema(StorageSharedFolderUserLink,
                                                                       ['folder_uid', 'user_uid'],
                                                                       indexes={'UserUID': 'user_uid'})
        shared_folder_team_schema = sqlite_dao.TableSchema.load_schema(StorageSharedFolderTeamLink,
                                                                       ['folder_uid', 'team_uid'],
                                                                       indexes={'TeamUID': 'team_uid'})
        sqlite_dao.verify_database(
            self.get_connection(),
            (metadata_schema, user_schema, record_schema, record_aging_schema, user_record_schema, team_schema,
             team_user_schema, role_schema, record_permissions_schema, shared_folder_record_schema,
             shared_folder_user_schema, shared_folder_team_schema)
        )

        self._metadata = sqlite.SqliteRecordStorage(self.get_connection, metadata_schema, owner)
        self._users = sqlite.SqliteEntityStorage(self.get_connection, user_schema)
        self._records = sqlite.SqliteEntityStorage(self.get_connection, record_schema)
        self._record_aging = sqlite.SqliteEntityStorage(self.get_connection, record_aging_schema)
        self._user_record_links = sqlite.SqliteLinkStorage(self.get_connection, user_record_schema)
        self._teams = sqlite.SqliteEntityStorage(self.get_connection, team_schema)
        self._team_user_links = sqlite.SqliteLinkStorage(self.get_connection, team_user_schema)
        self._roles = sqlite.SqliteEntityStorage(self.get_connection, role_schema)
        self._record_permissions = sqlite.SqliteLinkStorage(self.get_connection, record_permissions_schema)
        self._sf_record_links = sqlite.SqliteLinkStorage(self.get_connection, shared_folder_record_schema)
        self._sf_user_links = sqlite.SqliteLinkStorage(self.get_connection, shared_folder_user_schema)
        self._sf_team_links = sqlite.SqliteLinkStorage(self.get_connection, shared_folder_team_schema)

    def _get_history(self):
        return self._metadata.load() or Metadata()

    @property
    def last_prelim_data_update(self):
        return self._get_history().prelim_data_last_update

    def set_prelim_data_updated(self, ts=None):  # type: (int or None) -> None
        ts = int(datetime.datetime.now().timestamp()) if ts is None else ts
        history = self._get_history()
        history.prelim_data_last_update = ts
        self._metadata.store(history)

    def set_compliance_data_updated(self, ts=None):  # type: (int or None) -> None
        ts = int(datetime.datetime.now().timestamp()) if ts is None else ts
        history = self._get_history()
        history.compliance_data_last_update = ts
        self._metadata.store(history)

    @property
    def last_compliance_data_update(self):
        return self._get_history().compliance_data_last_update

    @property
    def records_dated(self):
        return self._get_history().records_dated

    def set_records_dated(self, ts=None):   # type: (int or None) -> None
        ts = int(datetime.datetime.now().timestamp()) if ts is None else ts
        history = self._get_history()
        history.records_dated = int(ts) if ts is not None else 0
        self._metadata.store(history)

    @property
    def last_pw_audit(self):
        return self._get_history().last_pw_audit

    def set_last_pw_audit(self, ts=None):    # type: (int or None) -> None
        ts = int(datetime.datetime.now().timestamp()) if ts is None else ts
        history = self._get_history()
        history.last_pw_audit = ts
        self._metadata.store(history)

    def get_users(self):
        return self._users

    def get_records(self):
        return self._records

    def get_record_aging(self):
        return self._record_aging

    def get_user_record_links(self):
        return self._user_record_links

    def get_teams(self):
        return self._teams

    def get_team_user_links(self):
        return self._team_user_links

    def get_record_permissions(self):
        return self._record_permissions

    def get_sf_record_links(self):
        return self._sf_record_links

    def get_sf_user_links(self):
        return self._sf_user_links

    def get_sf_team_links(self):
        return self._sf_team_links

    @property
    def records(self):  # type: () -> IEntityStorage
        return self.get_records()

    @property
    def record_aging(self):
        return self.get_record_aging()

    @property
    def users(self):  # type: () -> IEntityStorage
        return self.get_users()

    @property
    def teams(self):  # type: () -> IEntityStorage
        return self.get_teams()

    @property
    def shared_records_only(self):
        return self._get_history().shared_records_only

    def set_shared_records_only(self, value):   # type: (bool) -> None
        history = self._get_history()
        history.shared_records_only = value
        self._metadata.store(history)

    def clear_aging_data(self):
        self._record_aging.delete_all()
        self.set_records_dated(0)
        self.set_last_pw_audit(0)

    def clear_non_aging_data(self):
        self._records.delete_all()
        self._users.delete_all()
        self._user_record_links.delete_all()
        self._teams.delete_all()
        self._roles.delete_all()
        self._sf_team_links.delete_all()
        self._sf_user_links.delete_all()
        self._sf_record_links.delete_all()
        self._team_user_links.delete_all()
        self._record_permissions.delete_all()
        self.set_prelim_data_updated(0)
        self.set_compliance_data_updated(0)

    def rebuild_prelim_data(self, users, records, links):
        self.clear_non_aging_data()
        self._users.put_entities(users)
        self._records.put_entities(records)
        self._user_record_links.put_links(links)
        self.set_prelim_data_updated()

    def clear_all(self):
        self.clear_non_aging_data()
        self._record_aging.delete_all()
        self._metadata.delete_all()

    def delete_db(self):
        try:
            conn = self.get_connection()
            conn.close()
            os.remove(self.database_name)
        except Exception as e:
            logging.info(f'could not delete db from filesystem, name = {self.database_name}')
            logging.info(f'Exception e:\n{e}')
