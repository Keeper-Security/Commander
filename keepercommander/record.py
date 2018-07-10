#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#

from keepercommander.subfolder import get_folder_path, find_folders

class Record:
    """Defines a user-friendly Keeper Record for display purposes"""

    def __init__(self,record_uid='',folder='',title='',login='',password='',
                 login_url='',notes='',custom_fields=[],revision=''):
        self.record_uid = record_uid 
        self.folder = folder 
        self.title = title 
        self.login = login 
        self.password = password 
        self.login_url = login_url
        self.notes = notes 
        self.custom_fields = custom_fields
        self.attachments = None
        self.revision = revision 

    def load(self, data, **kwargs):

        def xstr(s):
            return str(s or '')

        if 'folder' in data:
            self.folder = xstr(data['folder'])
        if 'title' in data:
            self.title = xstr(data['title'])
        if 'secret1' in data:
            self.login = xstr(data['secret1'])
        if 'secret2' in data:
            self.password = xstr(data['secret2'])
        if 'notes' in data:
            self.notes = xstr(data['notes'])
        if 'link' in data:
            self.login_url = xstr(data['link'])
        if 'custom' in data:
            self.custom_fields = data['custom']
        if 'revision' in kwargs:
            self.revision = kwargs['revision']
        if 'extra' in kwargs:
            self.attachments = kwargs['extra'].get('files')

    def get(self,field):
        result = ''
        for c in self.custom_fields:
            if (c['name'] == field):
                result = c['value']
                break
        return result

    def set_field(self, name, value):
        found = False
        for field in self.custom_fields:
            if field['name'] == name:
                field['value'] = value
                found = True
                break
        if not found:
            self.custom_fields.append({'name': name, 'value': value})

    def display(self, **kwargs):
        print('') 
        print('{0:>20s}: {1:<20s}'.format('UID', self.record_uid))
        print('{0:>20s}: {1}'.format('Revision', self.revision))

        if 'params' in kwargs:
            params = kwargs['params']
            folders = [get_folder_path(params, x) for x in find_folders(params, self.record_uid)]
            for i in range(len(folders)):
                folder = folders[i]
                print('{0:>20s}: {1:<20s}'.format('Folder' if i == 0 else '', folders[i]))

        if self.title: print('{0:>20s}: {1:<20s}'.format('Title',self.title))
        if self.login: print('{0:>20s}: {1:<20s}'.format('Login',self.login))
        if self.password: print('{0:>20s}: {1:<20s}'.format('Password',self.password))
        if self.login_url: print('{0:>20s}: {1:<20s}'.format('URL',self.login_url))
        print('{0:>20s}: https://keepersecurity.com/vault#detail/{1}'.format('Link',self.record_uid))
        
        if len(self.custom_fields) > 0:
            for c in self.custom_fields:
                if not 'value' in c: c['value'] = ''
                if not 'name' in c: c['name'] = ''
                print('{0:>20s}: {1:<s}'.format(c['name'], c['value']))

        if self.notes:
            print('{0:>20s}: {1:<20s}'.format('Notes',self.notes))

        if self.attachments:
            for i in range(len(self.attachments)):
                atta = self.attachments[i]
                size = atta.get('size') or 0
                scale = 'b'
                if size > 0:
                    if size > 1000:
                        size = size / 1024
                        scale = 'Kb'
                    if size > 1000:
                        size = size / 1024
                        scale = 'Mb'
                    if size > 1000:
                        size = size / 1024
                        scale = 'Gb'
                sz = '{0:.2f}'.format(size).rstrip('0').rstrip('.')
                print('{0:>20s}: {1:<20s} {2:>6s}{3:<2s} {4:>6s}: {5}'.format('Attachments' if i == 0 else '', atta.get('name'), sz, scale, 'ID', atta.get('id')))
        print('')

    def to_string(self):
        target = self.record_uid + self.folder + self.title + \
                 self.login + self.password + self.notes + \
                 self.login_url + str(self.custom_fields)
        return target

    def to_lowerstring(self):
        return self.to_string().lower()

    def to_tab_delimited(self):

        def tabulate(*args):
            return '\t'.join(args)

        custom_fields = ''
        if self.custom_fields:
            for field in self.custom_fields:
                if ('name' in field) and ('value' in field):
                    custom_fields = '\t'.join([field['name'] + '\t' + \
                        field['value'] for field in self.custom_fields])

        return tabulate(self.folder, self.title, self.login, \
                        self.password, self.login_url, self.notes.replace('\n', '\\\\n'), \
                        custom_fields)

    def to_dictionary(self):
        return {
            'uid': self.record_uid,
            'folder': self.folder,
            'title': self.title,
            'login': self.login,
            'password': self.password,
            'login_url': self.login_url,
            'notes': self.notes,
            'custom_fields': self.custom_fields,
        }
