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


def try_resolve_path(params, path):
    """
    Look up the final keepercommander.subfolder.UserFolderNode and name of the final component(s).

    If a record, the final component is the record.
    If an existent folder, the final component is ''.
    If a non-existent folder, the final component is the folders, joined with /, that do not (yet) exist..
    """
    if type(path) is not str:
        path = ''

    folder = params.folder_cache[params.current_folder] if params.current_folder in params.folder_cache else params.root_folder
    if len(path) > 0:
        if path[0] == '/':
            # this is an absolute path; folder becomes the root
            folder = params.root_folder
            path = path[1:]

        # Divide a path into components on /'s
        start = 0
        while True:
            # Find the next /
            # FIXME: We're ignoring the fact that a path could start with // to be a literal /, like //abc giving /abc
            idx = path.find('/', start)
            path_component = ''
            if idx < 0:
                # There are no more slashes
                if len(path) > 0:
                    # We're at the final path component
                    path_component = path.strip()
            elif idx > 0 and path[idx - 1] == '\\':
                # The character before the / was a \ - treat it like a literal / and continue dividing.
                # This looks like we should be able to use abc\/def to get abc/def
                start = idx + 1
                continue
            else:
                # We have the next path component
                path_component = path[:idx].strip()

            if len(path_component) == 0:
                break

            # Look up the current component's uid
            folder_uid = ''
            if path_component == '.':
                # Get the current folder's uid
                folder_uid = folder.uid
            elif path_component == '..':
                # Get our parent folder's uid. This is a little weird, because / (a path) and a uid are two different things.
                # But see below.
                folder_uid = folder.parent_uid or '/'
            else:
                # Search this folder's subfolders for the uid of the current folder.  We ignore case, and we do
                # fancy stuff like treating German Eszett the same as "ss".  O(n).
                for uid in folder.subfolders:
                    sf = params.folder_cache[uid]
                    if sf.name.strip().casefold() == path_component.casefold():
                        folder_uid = uid
                        break
            if folder_uid:
                # Get the folder of this folder_uid. If the folder_uid is not in the params.folder_cache, then use the root
                # folder.  The folder.parent_uid or '/' above probably works because we treat it as a sentinel here.
                folder = params.folder_cache[folder_uid] if folder_uid in params.folder_cache else params.root_folder
            else:
                break
            if idx < 0:
                path = ''
                break

            # Advance to the next path component - still /-separated
            path = path[idx+1:]
            start = 0

    # Return a 2-tuple of keepercommander.subfolder.UserFolderNode, str
    # The first is the folder containing the second, or the folder of the last component if the second is ''.
    # The second is the final component of the path we're passed as an argument to this function.
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

