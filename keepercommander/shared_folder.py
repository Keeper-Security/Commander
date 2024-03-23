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

import datetime

class SharedFolder:
    """Defines a Keeper Shared Folder"""

    def __init__(self,shared_folder_uid='',revision='',default_manage_records=False,
                 default_manage_users=False,default_can_edit=False,default_can_share=False,
                 name='',records=None,users=None,teams=None):
        self.shared_folder_uid = shared_folder_uid 
        self.revision = revision
        self.default_manage_records = default_manage_records 
        self.default_manage_users = default_manage_users 
        self.default_can_edit = default_can_edit 
        self.default_can_share = default_can_share 
        self.name = name 
        self.records = records or []
        self.users = users or []
        self.teams = teams or []
        self.share_admins = None

    def load(self, sf, revision=''):
        self.default_manage_records = sf['default_manage_records']
        self.default_manage_users = sf['default_manage_users']
        self.default_can_edit = sf['default_can_edit']
        self.default_can_share = sf['default_can_share']
        self.name = sf['name_unencrypted']

        if 'records' in sf:
            self.records = sf['records']
        else:
            self.records = []

        if 'users' in sf:
            self.users = sf['users']
        else:
            self.users = []

        if 'teams' in sf:
            self.teams = sf['teams']
        else:
            self.teams = []

        self.revision = revision

    def display(self):
        print('') 
        print('{0:>25s}: {1:<20s}'.format('Shared Folder UID', self.shared_folder_uid))
        print('{0:>25s}: {1}'.format('Name', self.name))
        print('{0:>25s}: {1}'.format('Default Manage Records', self.default_manage_records))
        print('{0:>25s}: {1}'.format('Default Manage Users', self.default_manage_users))
        print('{0:>25s}: {1}'.format('Default Can Edit', self.default_can_edit))
        print('{0:>25s}: {1}'.format('Default Can Share', self.default_can_share))

        if len(self.records) > 0:
            print('')
            print('{0:>25s}:'.format('Record Permissions'))
            for r in self.records:
                print('{0:>25s}: {1}'.format(r['record_uid'], SharedFolder.record_permission_to_string(r)))
                expiration = SharedFolder.expiration_to_string(r)
                if expiration:
                    print('{0:>25s}  {1}'.format('', expiration))

        if len(self.users) > 0:
            print('')
            print('{0:>25s}:'.format('User Permissions'))
            for u in self.users:
                print('{0:>25s}: {1}'.format(u['username'], SharedFolder.user_permission_to_string(u)))
                expiration = SharedFolder.expiration_to_string(u)
                if expiration:
                    print('{0:>25s}  {1}'.format('', expiration))

        if len(self.teams) > 0:
            print('')
            print('{0:>25s}:'.format('Team Permissions'))
            for t in self.teams:
                print('{0:>25s}: {1}'.format(t['name'], SharedFolder.user_permission_to_string(t)))
                expiration = SharedFolder.expiration_to_string(t)
                if expiration:
                    print('{0:>25s}  {1}'.format('', expiration))

        if self.share_admins:
            print('')
            print('{0:>25s}:'.format('Share Administrators'))
            for email in self.share_admins:
                print('{0:>25s}: {1}'.format(email, 'Can Manage Users & Records'))

        print('')

    @staticmethod
    def user_permission_to_string(permission):
        if isinstance(permission, dict):
            manage_users = permission.get('manage_users', False)
            manage_records = permission.get('manage_records', False)
            if manage_users and manage_records:
                return 'Can Manage Users & Records'
            if not manage_users and not manage_records:
                return 'No Folder Permissions'
            if manage_users:
                return 'Can Manage Users'
            return 'Can Manage Records'

    @staticmethod
    def record_permission_to_string(permission):
        if isinstance(permission, dict):
            can_edit = permission.get('can_edit', False)
            can_share = permission.get('can_share', False)
            if can_edit and can_share:
                return 'Can Edit & Share'
            if not can_edit and not can_share:
                return 'Read Only'
            if can_edit:
                return 'Can Edit'
            return 'Can Share'

    @staticmethod
    def expiration_to_string(permission):
        if isinstance(permission, dict):
            expires = permission.get('expiration')
            if isinstance(expires, (int, float)) and expires > 0:
                return 'Expires: ' + str(datetime.datetime.fromtimestamp(expires // 1000))

    def to_string(self):
        target = self.shared_folder_uid + str(self.users) + str(self.teams)
        return target

    def to_lowerstring(self):
        keywords = [self.shared_folder_uid, self.name]
        if self.users:
            for u in self.users:
                keywords.append(u['username'])
        if self.teams:
            for t in self.teams:
                keywords.append(t['name'])
                keywords.append(t['team_uid'])
        keywords = [x.lower() for x in keywords]
        return '\n'.join(keywords)
