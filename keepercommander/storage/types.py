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

import abc


class IUid(abc.ABC):
    @abc.abstractmethod
    def uid(self):
        pass


class IUidLink(abc.ABC):
    @abc.abstractmethod
    def subject_uid(self):
        pass

    @abc.abstractmethod
    def object_uid(self):
        pass


class UidLink(IUidLink):
    def __init__(self, subject_uid, object_uid):
        self._subject_uid = subject_uid
        self._object_uid = object_uid

    def subject_uid(self):
        return self._subject_uid

    def object_uid(self):
        return self._object_uid


class IRecordStorage(abc.ABC):
    @abc.abstractmethod
    def load(self):
        pass

    @abc.abstractmethod
    def store(self, record):
        pass

    @abc.abstractmethod
    def delete(self):
        pass


class IEntityStorage(abc.ABC):
    @abc.abstractmethod
    def get_entity(self, uid):
        pass

    @abc.abstractmethod
    def get_all(self):
        pass

    @abc.abstractmethod
    def put_entities(self, entities):
        pass

    @abc.abstractmethod
    def delete_uids(self, uids):
        pass


class ILinkStorage(abc.ABC):
    @abc.abstractmethod
    def put_links(self, links):
        pass

    @abc.abstractmethod
    def delete_links(self, links):
        pass

    @abc.abstractmethod
    def delete_links_for_subjects(self, subject_uids):
        pass

    @abc.abstractmethod
    def delete_links_for_objects(self, object_uids):
        pass

    @abc.abstractmethod
    def get_links_for_subject(self, subject_uid):
        pass

    @abc.abstractmethod
    def get_links_for_object(self, object_uid):
        pass

    @abc.abstractmethod
    def get_all_links(self):
        pass
