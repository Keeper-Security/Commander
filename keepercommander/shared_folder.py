#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2017 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

class SharedFolder:
    """Defines a Keeper Shared Folder"""

    def __init__(self,shared_folder_uid='',revision='',manage_records=False,manage_users=True,name='',records=[],users=[]):
        self.shared_folder_uid = shared_folder_uid 
        self.revision = revision
        self.manage_records = manage_records 
        self.manage_users = manage_users 
        self.name = name 
        self.records = records 
        self.users = users 

    def load(self,sf,revision=''):
        self.manage_records = sf['manage_records']
        self.manage_users = sf['manage_users']
        self.name = sf['name']
        self.records = sf['records']
        self.users = sf['users']
        self.revision = revision

    def display(self):
        print('') 
        print('{0:>20s}: {1:<20s}'.format('Shared Folder UID',self.shared_folder_uid))
        print('{0:>20s}: {1}'.format('Revision',self.revision))
        print('{0:>20s}: {1}'.format('Name',self.name))
        print('{0:>20s}: {1}'.format('Manage Records',self.manage_records))
        print('{0:>20s}: {1}'.format('Manage Users',self.manage_users))
        print('')
        print('{0:>20s}:'.format('Record Permissions'))

        if len(self.records) > 0:
            for r in self.records:
                print('{0:>20s}: {1}: {2}, {3}: {4}'.format(r['record_uid'],'Can Edit',r['can_edit'],'Can Share',r['can_share']))

        print('')
        print('{0:>20s}:'.format('User Permissions'))

        if len(self.users) > 0:
            for u in self.users:
                print('{0:>20s}: {1}: {2}, {3}: {4}'.format(u['username'],'Can Manage Records',u['manage_records'],'Can Manage Users',u['manage_users']))

        print('')

    def to_string(self):
        target = self.shared_folder_uid + str(self.users)
        return target

    def to_lowerstring(self):
        return self.to_string().lower()

