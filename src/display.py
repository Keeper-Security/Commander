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

import sys
import json
import base64
from record import Record
from colorama import init
init()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def welcome():
    print('\n')
    print(bcolors.OKBLUE,' _  __  ' + bcolors.ENDC)
    print(bcolors.OKBLUE,'| |/ /___ ___ _ __  ___ _ _ ' + bcolors.ENDC)
    print(bcolors.OKBLUE,'| \' </ -_) -_) \'_ \\/ -_) \'_|' + bcolors.ENDC)
    print(bcolors.OKBLUE,'|_|\\_\\___\\___| .__/\\___|_|' + bcolors.ENDC)
    print(bcolors.OKBLUE,'             |_|            ' + bcolors.ENDC)
    print('')
    print(bcolors.FAIL,'password manager & digital vault' + bcolors.ENDC)
    print('')
    print('')

def formatted_records(records):
    """Display folders/titles/uids for the supplied records"""

    # Sort by folder+title
    records.sort(key=lambda x: (x.folder + x.title).lower(), reverse=False)

    if len(records) > 0:
        print('')
        print('   #  {0:<20s}   {1:<20s} {2:<20s}'.format(
            'Record UID', 'Folder', 'Title'))
        print('      {0:<20s}   {1:<20s} {2:<20s}'.format(
            '-----------', '------', '-----'))
    
        i = 1
        for r in records:
            print('{0:4d}. {1:<20s} {2:<20s} {3:}'.format(
               i, r.record_uid, r.folder[:20], r.title[:100]))
            i = i+1
    
        print('')

    # Under 5 recs, just display on the screen
    if len(records) < 5:
        for r in records:
            r.display()

def formatted_history(history):
    """ Show the history of commands"""

    if not history: return
    if len(history) == 0: return

    print('')
    print('Command history:')
    print('----------------')

    for h in history:
        print(h)

    print('')
