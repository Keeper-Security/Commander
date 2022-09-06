#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import sqlite3
from typing import Callable, Union, Iterable, Tuple

from .types import IEntityStorage, ILinkStorage, IRecordStorage, IUidLink
from . import sqlite_dao


class SqliteEntityStorage(sqlite_dao.SqliteStorage, IEntityStorage):
    def __init__(self, get_connection, schema, owner=None):
        # type: (Callable[[], sqlite3.Connection], sqlite_dao.TableSchema, Union[str, int, None]) -> None

        super(SqliteEntityStorage, self).__init__(get_connection, schema, owner)
        if len(self.schema.primary_key) != 1:
            raise ValueError(f'SqliteEntityStorage: Primary key to have one column.')

    def get_entity(self, uid):
        results = list(self.select_by_filter(self.schema.primary_key, [uid]))
        return results[0] if results else None

    def get_entities(self, pk_values):
        for value in pk_values:
            yield self.get_entity(value)

    def get_all(self):
        for entity in self.select_all():
            yield entity

    def put_entities(self, entities):
        self.put(entities)

    def delete_uids(self, uids):
        self.delete_by_filter(self.schema.primary_key, uids, multiple_criteria=True)


class SqliteLinkStorage(sqlite_dao.SqliteStorage, ILinkStorage):
    def __init__(self, get_connection, schema, owner=None):
        # type: (Callable[[], sqlite3.Connection], sqlite_dao.TableSchema, Union[str, int, None]) -> None

        super(SqliteLinkStorage, self).__init__(get_connection, schema, owner)
        if len(self.schema.primary_key) != 2:
            raise ValueError('SqliteLinkStorage: Primary key to have two columns.')

        object_column = self.schema.primary_key[1]
        object_index_name = None
        if self.schema.indexes:
            for index_name, index_columns in self.schema.indexes.items():
                if index_columns[0].lower() == object_column.lower():
                    object_index_name = index_name
                    break
        if not object_index_name:
            raise ValueError(
                f'SqliteLinkStorage: Object UID column "{object_column}"is not indexed in table "{schema.table_name}".')

    def put_links(self, links):
        self.put(links)

    @staticmethod
    def expand_link_to_tuple(links):
        # type: (Iterable[Union[IUidLink, Tuple[str, str]]]) -> Iterable[Tuple[Union[str, int], Union[str, int]]]
        for link in links:
            if isinstance(link, IUidLink):
                yield link.subject_uid(), link.object_uid()
            elif isinstance(link, (list, tuple)) and len(link) == 2:
                yield link[0], link[1]
            else:
                raise ValueError('Unsupported link type')

    def delete_links(self, links):
        self.delete_by_filter(self.schema.primary_key, SqliteLinkStorage.expand_link_to_tuple(links),
                              multiple_criteria=True)

    def delete_links_for_subjects(self, subject_uids):
        self.delete_by_filter(self.schema.primary_key[0], subject_uids, multiple_criteria=True)

    def delete_links_for_objects(self, object_uids):
        self.delete_by_filter(self.schema.primary_key[1], object_uids, multiple_criteria=True)

    def get_links_for_subject(self, subject_uid):
        for link in self.select_by_filter(self.schema.primary_key[0], subject_uid):
            yield link

    def get_links_for_object(self, object_uid):
        for link in self.select_by_filter(self.schema.primary_key[1], object_uid):
            yield link

    def get_all_links(self):
        for link in self.select_all():
            yield link


class SqliteRecordStorage(sqlite_dao.SqliteStorage, IRecordStorage):
    def __init__(self, get_connection, schema, owner):
        # type: (Callable[[], sqlite3.Connection], sqlite_dao.TableSchema, Union[str, int]) -> None
        super(SqliteRecordStorage, self).__init__(get_connection, schema, owner)
        if not schema.owner_column:
            raise ValueError(f'SqliteRecordStorage: Schema \"{schema.table_name}\" should have an owner')
        if schema.primary_key:
            raise ValueError(f'SqliteRecordStorage: Schema \"{schema.table_name}\" should not have primary key')

    def load(self):
        return next(self.select_all(), None)

    def store(self, record):
        self.put([record])

    def delete(self):
        self.delete_all()
