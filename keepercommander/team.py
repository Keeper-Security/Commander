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

class Team:
    """Defines a Keeper Team """

    def __init__(self, team_uid='', restrict_edit=False, restrict_view=False, restrict_share=False, name=''):
        self.team_uid = team_uid 
        self.restrict_edit = restrict_edit 
        self.restrict_view = restrict_view
        self.restrict_share = restrict_share
        self.name = name

    def load(self,team):
        self.restrict_edit = team['restrict_edit'] or False
        self.restrict_view = team['restrict_view'] or False
        self.restrict_share = team['restrict_share'] or False
        self.name = team['name']

    def display(self):
        print('') 
        print('{0:>20s}: {1:<20s}'.format('Team UID',self.team_uid))
        print('{0:>20s}: {1}'.format('Name',self.name))
        print('{0:>20s}: {1}'.format('Restrict Edit',self.restrict_edit))
        print('{0:>20s}: {1}'.format('Restrict View',self.restrict_view))
        print('{0:>20s}: {1}'.format('Restrict Share',self.restrict_share))
        print('')

    def to_string(self):
        target = self.team_uid + str(self.restrict_edit) + str(self.restrict_view)
        return target

    def to_lowerstring(self):
        keywords = [self.team_uid, self.name]
        keywords = [x.lower() for x in keywords]
        return '\n'.join(keywords)

