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


def find_folders(params, record_uid):
    for fuid in params.subfolder_record_cache:
        if record_uid in params.subfolder_record_cache[fuid]:
            if fuid:
                yield fuid


def contained_folder(params, folder, component):
    """Return the folder of component within parent folder 'folder' - or None if not present."""
    if component == '.':
        return folder
    if component == '..':
        if folder.parent_uid is None:
            return params.root_folder
        return params.folder_cache[folder.parent_uid]
    for subfolder_uid in folder.subfolders:
        subfolder = params.folder_cache[subfolder_uid]
        if subfolder.name == component:
            return subfolder
    return None


def lookup_path(params, folder, components):
    """
    Lookup a path of components within the folder cache.

    Get all the folders starting from the left end of component, plus the index of the first component that isn't present in the
    folder cache.
    """
    remainder = 0
    for index, component in enumerate(components):
        temp_folder = contained_folder(params, folder, component)
        if temp_folder is None:
            break
        folder = temp_folder
        remainder = index + 1
    return remainder, folder


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


def try_resolve_path(params, path):
    """
    Look up the final keepercommander.subfolder.UserFolderNode and name of the final component(s).

    If a record, the final component is the record.
    If an existent folder, the final component is ''.
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

    remainder, folder = lookup_path(params, folder, components)

    tail = components[remainder:]

    path = '/'.join(component.replace('/', '//') for component in tail)

    # Return a 2-tuple of keepercommander.subfolder.UserFolderNode, str
    # The first is the folder containing the second, or the folder of the last component if the second is ''.
    # The second is the final component of the path we're passed as an argument to this function. It could be a record, or
    # a not-yet-existent directory.
    return (folder, path)


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
        self.subfolders = []

    def get_folder_type(self):
        if self.type == BaseFolderNode.RootFolderType:
            return 'Root'
        elif self.type == BaseFolderNode.UserFolderType:
            return 'Regular Folder'
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

    def display(self, **kwargs):
        print('')
        print('{0:>20s}: {1:<20s}'.format('Folder UID', self.uid))
        print('{0:>20s}: {1:<20s}'.format('Folder Type', self.get_folder_type()))
        print('{0:>20s}: {1}'.format('Name', self.name))


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


class RootFolderNode(BaseFolderNode):
    def __init__(self):
        BaseFolderNode.__init__(self, BaseFolderNode.RootFolderType)
        self.name = 'My Vault'
