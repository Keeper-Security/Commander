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
                 link='',notes='',custom_fields=[]):
        self.record_uid = record_uid 
        self.folder = folder 
        self.title = title 
        self.login = login 
        self.password = password 
        self.link = link 
        self.notes = notes 
        self.custom_fields = custom_fields 

    def load(self,data):
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