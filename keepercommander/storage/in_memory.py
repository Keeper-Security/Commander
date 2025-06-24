from typing import Dict, Any, Callable, Optional, Generic, Iterable
from .types import IEntityStorage, ILinkStorage, IRecordStorage, IUidLink, IUid, T, K, KS, KO


class InMemoryRecordStorage(Generic[T], IRecordStorage[T]):
    def __init__(self) -> None:
        self._record: Optional[T] = None
    def load(self) -> Optional[T]:
        return self._record

    def store(self, record: T):
        self._record = record

    def delete(self):
        self._record = None


GetUid = Callable[[Any], K]
class InMemoryEntityStorage(Generic[T, K], IEntityStorage[T, K]):
    def __init__(self, get_uid: Optional[GetUid]=None) -> None:
        self._items: Dict[K, T] = {}
        self.get_uid = get_uid

    def get_entity(self, uid):
        return self._items.get(uid)

    def get_all_entities(self):
        for item in self._items.values():
            yield item

    def put_entities(self, entities: Iterable[T]) -> None:
        for entity in entities:
            if isinstance(entity, IUid):
                uid = entity.uid()
            elif self.get_uid is not None:
                uid = self.get_uid(entity)
            else:
                raise ValueError(f'Cannot get UID for class {type(entity)}')

            if uid in self._items:
                if self._items[uid] is entity:
                    return
            self._items[uid] = entity

    def delete_uids(self, uids):
        for uid in uids:
            if uid in self._items:
                del self._items[uid]

    def clear(self):
        self._items.clear()


class InMemoryLinkStorage(Generic[T, KS, KO], ILinkStorage[T, KS, KO]):
    def __init__(self, get_subject: Optional[GetUid]=None, get_object: Optional[GetUid]=None) -> None:
        self.get_subject = get_subject
        self.get_object = get_object
        self._links: Dict[KS, Dict[KO, Any]] = {}

    def put_links(self, links):
        for link in links:
            if isinstance(link, IUidLink):
                subject_uid = link.subject_uid()
                object_uid = link.object_uid()
            elif self.get_subject and self.get_object:
                subject_uid = self.get_subject(link)
                object_uid = self.get_object(link)
            else:
                raise ValueError(f'Cannot get subject and object UIDs for class {type(link)}')

            if subject_uid not in self._links:
                self._links[subject_uid] = {}
            self._links[subject_uid][object_uid] = link

    def delete_links(self, links):
        for link in links:
            if isinstance(link, IUidLink):
                subject_uid = link.subject_uid()
                object_uid = link.object_uid()
            elif self.get_subject and self.get_object:
                subject_uid = self.get_subject(link)
                object_uid = self.get_object(link)
            elif isinstance(link, (list, tuple)) and len(link) == 2:
                subject_uid = link[0]
                object_uid = link[1]
            else:
                raise ValueError('Unsupported link type')
            if subject_uid in self._links:
                if object_uid in self._links[subject_uid]:
                    del self._links[subject_uid][object_uid]

    def delete_links_for_subjects(self, subject_uids):
        for subject_uid in subject_uids:
            if subject_uid in self._links:
                del self._links[subject_uid]

    def delete_links_for_objects(self, object_uids):
        for objects in self._links.values():
            for object_uid in object_uids:
                if object_uid in objects:
                    del objects[object_uid]

    def get_links_for_subject(self, subject_uid):
        if subject_uid in self._links:
            objects = self._links[subject_uid]
            yield from objects.values()

    def get_links_for_object(self, object_uid):
        for subj in self._links.values():
            if object_uid in subj:
                yield subj[object_uid]

    def get_all_links(self):
        for subj in self._links.values():
            yield from subj.values()

    def get_link(self, subject_uid, object_uid):
        if subject_uid in self._links:
            objects = self._links[subject_uid]
            if object_uid in objects:
                yield objects[object_uid]


    def clear(self):
        self._links.clear()
