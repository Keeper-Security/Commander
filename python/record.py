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

