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
from typing import TypeVar, Generic, Iterable, Optional, Tuple, Union


K = TypeVar('K', int, str, bytes)

class IUid(Generic[K], abc.ABC):
    @abc.abstractmethod
    def uid(self) -> K:
        pass

KS = TypeVar('KS', int, str, bytes)
KO = TypeVar('KO', int, str, bytes)

class IUidLink(Generic[KS, KO], abc.ABC):
    @abc.abstractmethod
    def subject_uid(self) -> KS:
        pass

    @abc.abstractmethod
    def object_uid(self) -> KO:
        pass


class UidLink(IUidLink[str, str]):
    def __init__(self, subject_uid: str, object_uid: str):
        self._subject_uid = subject_uid
        self._object_uid = object_uid

    def subject_uid(self) -> str:
        return self._subject_uid

    def object_uid(self) -> str:
        return self._object_uid

T = TypeVar('T')

class IRecordStorage(Generic[T], abc.ABC):
    @abc.abstractmethod
    def load(self) -> None:
        pass

    @abc.abstractmethod
    def store(self, record: T):
        pass

    @abc.abstractmethod
    def delete(self) -> None:
        pass

class IEntityReader(Generic[T, K], abc.ABC):
    @abc.abstractmethod
    def get_all_entities(self) -> Iterable[T]:
        pass

    @abc.abstractmethod
    def get_entity(self, key: K) -> Optional[T]:
        pass

    def get_all(self) -> Iterable[T]:
        return self.get_all_entities()


class IEntityStorage(IEntityReader[T, K], abc.ABC):
    @abc.abstractmethod
    def put_entities(self, entities: Iterable[T]) -> None:
        pass

    @abc.abstractmethod
    def delete_uids(self, uids: Iterable[K]) -> None:
        pass

class ILinkReader(Generic[T, KS, KO], abc.ABC):
    @abc.abstractmethod
    def get_link(self, subject_id: KS, object_id: KO) -> Optional[T]:
        pass

    @abc.abstractmethod
    def get_links_for_subject(self, subject_id: KS) -> Iterable[T]:
        pass

    @abc.abstractmethod
    def get_links_for_object(self, object_id: KO) -> Iterable[T]:
        pass

    @abc.abstractmethod
    def get_all_links(self) -> Iterable[T]:
        pass

class ILinkStorage(ILinkReader[T, KS, KO], abc.ABC):
    @abc.abstractmethod
    def put_links(self, links: Iterable[T]) -> None:
        pass

    @abc.abstractmethod
    def delete_links(self, links: Iterable[Union[Tuple[KS, KO], IUidLink[KS, KO]]]) -> None:
        pass

    @abc.abstractmethod
    def delete_links_for_subjects(self, subject_uids: Iterable[KS]) -> None:
        pass

    @abc.abstractmethod
    def delete_links_for_objects(self, object_uids: Iterable[KO]) -> None:
        pass
