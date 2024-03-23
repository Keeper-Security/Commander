#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import logging
from typing import Optional, Tuple, Dict, Iterable, List, Set, Union

from .params import KeeperParams


def get_folder_path(params, folder_uid, delimiter='/'):
    uid = folder_uid
    path = ''
    while uid in params.folder_cache:
        f = params.folder_cache[uid]
        name = f.name
        name = name.replace(delimiter, 2*delimiter)
        if len(path) > 0:
            path = name + delimiter + path
        else:
            path = name
        uid = f.parent_uid
    return path


def find_folders(params, record_uid):   # type: (KeeperParams, str) -> Iterable[str]
    for fuid in params.subfolder_record_cache:
        if record_uid in params.subfolder_record_cache[fuid]:
            if fuid:
                yield fuid


def find_all_folders(params, record_uid):   # type: (KeeperParams, str) -> Iterable[BaseFolderNode]
    for fuid in params.subfolder_record_cache:
        if record_uid in params.subfolder_record_cache[fuid]:
            if fuid:
                if fuid in params.folder_cache:
                    yield params.folder_cache[fuid]
            else:
                yield params.root_folder


def find_parent_top_folder(params, record_uid):

    """
    Find all top Shared Folders that will contain this record.
    Record can be in more than two folders by having a "link" which
    will present a record as a record with the same UID in more than
    one folder.
    """
    contained_folder_uids = []

    # Get all folders that might contain the given record
    for fuid in params.subfolder_record_cache:
        if fuid:    # record is in root folder
            if record_uid in params.subfolder_record_cache[fuid]:
                contained_folder_uids.append(fuid)

    shared_folders_containing_record = []

    # if records that belong to folder are found then go
    # through each one of them to get the share folder
    for cfuid in contained_folder_uids:
        if cfuid:
            folder = params.folder_cache[cfuid]

            # folder is already a shared folder
            if isinstance(folder, SharedFolderNode):
                shared_folders_containing_record.append(folder)
            # folder is a sub-folder, let's get its pared shared folder
            elif isinstance(folder, SharedFolderFolderNode):
                shared_folder_uid = folder.shared_folder_uid
                shared_folder = params.folder_cache[shared_folder_uid]
                shared_folders_containing_record.append(shared_folder)
            else:
                logging.debug("Folder UID={} is not a shared folder".format(cfuid))

    return shared_folders_containing_record


def contained_folders(params, folders, component):
    # type: (KeeperParams, List[Optional[BaseFolderNode]], str) -> List[Optional[BaseFolderNode]]
    """Return list of folders (empty if component not present) containing component within parent folder 'folder'"""
    get_folder_by_id = lambda uid: params.folder_cache.get(uid)
    get_folder_ids = lambda: params.folder_cache.keys()
    result = folders if component in ('.', '') \
        else [(get_folder_by_id(f.parent_uid) if f.parent_uid else params.root_folder) for f in folders] if component == '..' \
        else [get_folder_by_id(component)] if component in get_folder_ids() \
        else [get_folder_by_id(uid) for f in folders for uid in f.subfolders if get_folder_by_id(uid).name == component]
    return result


def lookup_path(params, folder, components):
    # type: (KeeperParams, BaseFolderNode, List[Optional[str]]) -> Tuple[int, List[Optional[BaseFolderNode]]]
    """
    Lookup path of components within the folder cache.

    Get all the folders starting from the left end of component, plus the index of the first component that isn't
    present in the folder cache.
    """
    remainder = 0
    folders = [folder]
    for index, component in enumerate(components):
        child_folders = contained_folders(params, folders, component)
        if not child_folders:
            break
        folders = child_folders
        remainder = index + 1
    return remainder, folders


def is_abs_path(path_string):
    """Return True iff path_string is an absolute path."""
    return path_string.startswith('/') and not path_string.startswith('//')


def path_split(params, folder, path_string):
    """Split a path into directories with two replaces and a split."""
    if is_abs_path(path_string):
        folder = params.root_folder
        path_string = path_string[1:]

    components = [s.replace('\0', '/') for s in path_string.replace('//', '\0').split('/')]
    return folder, components


def try_resolve_path(params, path, find_all_matches=False):
    # type: (KeeperParams, str, bool) -> Tuple[Union[List[BaseFolderNode], BaseFolderNode, None], Optional[str]]
    """
    Look up the final keepercommander.subfolder.UserFolderNode and name of the final component(s).
    Set find_all_matches = True to get a list of folders and component path

    If a record, the final component is the record.
    If existent folder(s), the final component is ''.
    If a non-existent folder, the final component is the folders, joined with /, that do not (yet) exist..
    """
    if type(path) is not str:
        path = ''

    folder = (
        params.folder_cache[params.current_folder]
        if params.current_folder in params.folder_cache
        else params.root_folder
    )

    folder, components = path_split(params, folder, path)

    remainder, folders = lookup_path(params, folder, components)

    tail = components[remainder:]

    path = '/'.join(component.replace('/', '//') for component in tail)

    # Return a 2-tuple of BaseFolderNode (or List[BaseFolderNode] if find_all_matches set to True), str
    # The first is the folder/s containing the second, or the folder of the last component if the second is ''.
    # The second is the final component of the path we're passed as an argument to this function. It could be a record, or
    # a not-yet-existent directory.
    return (folders, path) if find_all_matches \
        else (next(iter(folders)) if folders else None, path)


def get_folder_uids(params, name):  # type: (KeeperParams, str or None) -> Set[Optional[str]]
    uids = set()
    if name in params.folder_cache or name == '':
        uids.add(name)
    else:
        rs = try_resolve_path(params, name, find_all_matches=True)
        if rs is not None:
            folders, pattern = rs
            if len(pattern) == 0:
                uids.update([folder.uid or '' for folder in folders])
    return uids


def get_contained_folder_uids(params, name, children_only=True):
    def on_folder(f):
        f_uid = f.uid or ''
        parent_uid = f.parent_uid or ''
        if f_uid and f_uid not in root_folder_uids and (not children_only or parent_uid in root_folder_uids):
            folder_uids.add(f_uid)

    folder_uids = set()
    root_folder_uids = get_folder_uids(params, name)
    from keepercommander.commands.base import FolderMixin
    for uid in get_folder_uids(params, name):
        FolderMixin.traverse_folder_tree(params, uid, on_folder)

    return folder_uids


def get_contained_record_uids(params, name, children_only=True):
    # type: (KeeperParams, str, bool) -> Dict[str, Iterable[str]]
    from keepercommander.commands.base import FolderMixin
    recs_by_folder = dict()
    root_folder_uids = get_folder_uids(params, name)

    def add_child_recs(f_uid):
        child_recs = params.subfolder_record_cache.get(f_uid, set())
        recs_by_folder.update({f_uid: child_recs})

    def on_folder(f):  # type: (BaseFolderNode) -> None
        f_uid = f.uid or ''
        if not children_only or f_uid in root_folder_uids:
            add_child_recs(f_uid)

    for uid in root_folder_uids:
        FolderMixin.traverse_folder_tree(params, uid, on_folder)

    return recs_by_folder


class BaseFolderNode:
    RootFolderType = '/'
    UserFolderType = 'user_folder'
    SharedFolderType = 'shared_folder'
    SharedFolderFolderType = 'shared_folder_folder'

    """ Folder Common Fields"""
    def __init__(self, type):
        self.type = type
        self.uid = None
        self.parent_uid = None
        self.name = None
        self.color = None    # type: Optional[str]
        self.subfolders = []

    def get_folder_type(self):
        if self.type == BaseFolderNode.RootFolderType:
            return 'Root'
        elif self.type == BaseFolderNode.UserFolderType:
            return 'Personal Folder'
        elif self.type == BaseFolderNode.SharedFolderType:
            return 'Shared Folder'
        elif self.type == BaseFolderNode.SharedFolderFolderType:
            return 'Subfolder in Shared Folder'
        return ''

    def __repr__(self):
        return 'BaseFolderNode(type={}, uid={}, parent_uid={}, name={}, subfolders={})'.format(
            self.type,
            self.uid,
            self.parent_uid,
            self.name,
            self.subfolders,
        )

    def display(self):
        print('')
        print('{0:>20s}: {1:<20s}'.format('Folder UID', self.uid))
        print('{0:>20s}: {1:<20s}'.format('Folder Type', self.get_folder_type()))
        print('{0:>20s}: {1}'.format('Name', self.name))
        if self.parent_uid:
            print('{0:>20s}: {1:<20s}'.format('Parent Folder UID', self.parent_uid))
        if isinstance(self, SharedFolderFolderNode):
            print('{0:>20s}: {1:<20s}'.format('Shared Folder UID', self.shared_folder_uid))


class UserFolderNode(BaseFolderNode):
    def __init__(self):
        BaseFolderNode.__init__(self, BaseFolderNode.UserFolderType)


class SharedFolderFolderNode(BaseFolderNode):
    def __init__(self):
        BaseFolderNode.__init__(self, BaseFolderNode.SharedFolderFolderType)
        self.shared_folder_uid = None


class SharedFolderNode(BaseFolderNode):
    def __init__(self):
        BaseFolderNode.__init__(self, BaseFolderNode.SharedFolderType)

    @property
    def shared_folder_uid(self):
        return self.uid

    @shared_folder_uid.setter
    def shared_folder_uid(self, val):
        self.uid = val


class RootFolderNode(BaseFolderNode):
    def __init__(self):
        BaseFolderNode.__init__(self, BaseFolderNode.RootFolderType)
        self.name = 'My Vault'
