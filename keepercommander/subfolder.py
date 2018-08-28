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
    if type(path) is not str:
        path = ''

    folder = params.folder_cache[params.current_folder] if params.current_folder in params.folder_cache else params.root_folder
    if len(path) > 0:
        if path[0] == '/':
            folder = params.root_folder
            path = path[1:]

        start = 0
        while True:
            idx = path.find('/', start)
            path_component = ''
            if idx < 0:
                if len(path) > 0:
                    path_component = path.strip()
            elif idx > 0 and path[idx - 1] == '\\':
                start = idx + 1
                continue
            else:
                path_component = path[:idx].strip()

            if len(path_component) == 0:
                break

            folder_uid = ''
            if path_component == '.':
                folder_uid = folder.uid
            elif path_component == '..':
                folder_uid = folder.parent_uid or '/'
            else:
                for uid in folder.subfolders:
                    sf = params.folder_cache[uid]
                    if sf.name.strip() == path_component:
                        folder_uid = uid
            if folder_uid:
                folder = params.folder_cache[folder_uid] if folder_uid in params.folder_cache else params.root_folder
            else:
                break
            if idx < 0:
                path = ''
                break

            path = path[idx+1:]
            start = 0

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

