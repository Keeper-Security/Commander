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


def get_folder_path(params, folder_uid):
    uid = folder_uid
    path = ''
    while uid in params.folder_cache:
        f = params.folder_cache[uid]
        name = f.name
        if f.type == 'shared_folder':
            name = name + '$'
        path = name + '/' + path
        uid = f.parent_uid
    return '/' + path


def find_folders(params, record_uid):
    for fuid in params.subfolder_record_cache:
        if record_uid in params.subfolder_record_cache[fuid]:
            yield fuid


def try_resolve_path(params, path):
    if type(path) is str:
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
                    folder_uid = folder.parent_uid
                else:
                    for uid in folder.subfolders:
                        sf = params.folder_cache[uid]
                        if sf.name == path_component:
                            folder_uid = uid

                if len(folder_uid) == 0:
                    break

                folder = params.folder_cache[folder_uid]
                if idx < 0:
                    path = ''
                    break

                path = path[idx+1:]
                start = 0

        return folder, path

    return None


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

