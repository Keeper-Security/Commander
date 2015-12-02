#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2015 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

class Record:
    """Defines a Keeper Record"""

    def __init__(self,record_uid='',folder='',title='',login='',password='',
                 link='',notes='',custom_fields=[],revision=''):
        self.record_uid = record_uid 
        self.folder = folder 
        self.title = title 
        self.login = login 
        self.password = password 
        self.link = link 
        self.notes = notes 
        self.custom_fields = custom_fields
        self.revision = revision 

    def load(self,data,revision=''):
        if 'folder' in data:
            self.folder = data['folder']
        if 'title' in data:
            self.title = data['title']
        if 'secret1' in data:
            self.login = data['secret1']
        if 'secret2' in data:
            self.password = data['secret2']
        if 'notes' in data:
            self.notes = data['notes']
        if 'link' in data:
            self.link = data['link']
        if 'custom' in data:
            self.custom_fields = data['custom']
        if revision:
            self.revision = revision

    def get(self,field):
        result = ''
        for c in self.custom_fields:
            if (c['name'] == field):
                result = c['value']
                break
        return result

    def display(self):
        print('') 
        print('{0:>20s}: {1:<20s}'.format('UID',self.record_uid))
        print('{0:>20s}: {1}'.format('Revision',self.revision))
        if self.folder: print('{0:>20s}: {1:<20s}'.format('Folder',self.folder))
        if self.title: print('{0:>20s}: {1:<20s}'.format('Title',self.title))
        if self.login: print('{0:>20s}: {1:<20s}'.format('Login',self.login))
        if self.password: print('{0:>20s}: {1:<20s}'.format('Password',self.password))
        if self.link: print('{0:>20s}: {1:<20s}'.format('URL',self.link))
        print('{0:>20s}: https://keepersecurity.com/vault#detail/{1}'.format('Link',self.record_uid))
        
        if len(self.custom_fields) > 0:
            for c in self.custom_fields:
                if not 'value' in c: c['value'] = ''
                if not 'name' in c: c['name'] = ''
                print('{0:>20s}: {1:<s}'.format(c['name'], c['value']))

        if self.notes:
            print('{0:>20s}: {1:<20s}'.format('Notes',self.notes))

        print('')

    def to_string(self):
        target = self.record_uid + self.folder + self.title + \
                 self.login + self.password + self.notes + \
                 self.link + str(self.custom_fields)
        return target

    def to_lowerstring(self):
        return self.to_string().lower()

    def to_tab_delimited(self):

        def tabulate(*args):
            return '\t'.join(args)

        custom_fields = '\t'.join([field['name'] + '\t' + field['value'] for field in self.custom_fields])
        return tabulate(self.folder, self.title, self.login, self.password, self.link, self.notes.replace('\n', '\\\\n'), custom_fields)