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


def handle_initial_slash(params, folder, components):
    """
    Deal with both initial / and initial //.

    Has a side-effect on components.
    Returns the current folder.
    """
    if components and components[0] == '':
        if components[1:] and components[1] == '':
            # This is an initial //, so treat it as a literal /
            if components[2:]:
                # We have an element to add the / to - add it
                components[2] = '/' + components[2]
                del components[:2]
            else:
                # We do not have an element to add the / to - create a single-element components list for it
                components[:] = ['/']
        else:
            # This is a single /, so treat it as an absolute path
            folder = params.root_folder
            del components[0]

    return folder


def handle_subsequent_slash_slash(components):
    """
    Deal with double-slashes other than one at the very beginning.

    Consider a//b/c, whch will be passed as ['a', '', '', 'b', 'c'].
    That should be ['a/b', 'c']

    This is mostly simple, but it's also O(c*n**2) because of the slicing.  But it's a small c and it's a small n.
    """
    parts = components[:]
    index = 0
    while index < len(parts):
        if (
            parts[index + 2:] and
            parts[index] != '' and
            parts[index + 1] == '' and
            parts[index + 2] != ''
        ):
            parts[index] = '{}/{}'.format(parts[index], parts[index + 2])
            del parts[index + 1:index + 3]
            index += 1
            continue
        if (
            parts[index + 2:] and
            parts[index] != '' and
            parts[index + 1] == '' and
            parts[index + 2] == ''
        ):
            parts[index] = '{}/'.format(parts[index])
            del parts[index + 1:index + 2]
            index += 1
            continue
        if parts[index] == '':
            del parts[index]
            continue
        index += 1

    return parts


def contained_folder(folder, component):
    """Return the folder of component within parent folder 'folder' - or None if not present."""
    for subfolder in folder.subfolders:
        if subfolder.name == component:
            return subfolder
    return None


def lookup_path(folder, components):
    """Get all the folders from the left end of component, and the index of the first that isn't present."""
    remainder = 0
    for index, component in enumerate(components):
        temp_folder = contained_folder(folder, component)
        if temp_folder is None:
            break
        folder = temp_folder
        remainder = index + 1
    return remainder, folder


def try_resolve_path(params, path):
    """
    Look up the final keepercommander.subfolder.UserFolderNode and name of the final component(s).

    If a record, the final component is the record.
    If an existent folder, the final component is ''.
    If a non-existent folder, the final component is the folders, joined with /, that do not (yet) exist..
    """
    # pudb.set_trace()

    if type(path) is not str:
        path = ''

    folder = (
        params.folder_cache[params.current_folder]
        if params.current_folder in params.folder_cache
        else params.root_folder
    )

    components = [part.strip() for part in path.split('/')]

    folder = handle_initial_slash(params, folder, components)

    components = handle_subsequent_slash_slash(components)

    remainder, folder = lookup_path(folder, components)

    path = '/'.join(components[remainder:])

    # Return a 2-tuple of keepercommander.subfolder.UserFolderNode, str
    # The first is the folder containing the second, or the folder of the last component if the second is ''.
    # The second is the final component of the path we're passed as an argument to this function. It could be a record, or
    # a not-yet-existent directory.
    return folder, path


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
