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
import re
from record import Record

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
    print(bcolors.OKBLUE,'| |/ /___ ___ _ __  ___ _ _ ®' + bcolors.ENDC)
    print(bcolors.OKBLUE,'| \' </ -_) -_) \'_ \\/ -_) \'_|' + bcolors.ENDC)
    print(bcolors.OKBLUE,'|_|\\_\\___\\___| .__/\\___|_|' + bcolors.ENDC)
    print(bcolors.OKBLUE,'             |_|            ' + bcolors.ENDC)
    print('')
    print(bcolors.FAIL,'password manager & digital vault' + bcolors.ENDC)
    print('')
    print('')

def formatted_record(params,record_uid):    

    record_uid = record_uid.strip()

    if not record_uid:
        print('No record UID provided')
        return

    if not params.record_cache:
        print('No record cache.  Sync down first.')
        return

    if not record_uid in params.record_cache:
        print('Record UID not found.')
        return

    cached_rec = params.record_cache[record_uid]

    if params.debug: print('Cached Rec: ' + str(cached_rec))
    data = json.loads(cached_rec['data'].decode('utf-8')) 

    rec = Record()
    rec.record_uid = record_uid 

    if 'folder' in data:
        rec.folder = data['folder']
    else: rec.folder = ''

    if 'title' in data:
        rec.title = data['title']
    else: rec.title = ''

    if 'secret1' in data:
        rec.login = data['secret1']
    else: rec.login = ''

    if 'secret2' in data:
        rec.password = data['secret2']
    else: rec.password = ''

    if 'notes' in data:
        rec.notes = data['notes']
    else: rec.notes = ''

    if 'link' in data:
        rec.link = data['link']
    else: rec.link = ''

    if 'custom' in data:
        rec.custom_fields = data['custom']
    else: rec.custom_fields = []

    rec.revision = cached_rec['revision']

    print('') 
    print('{0:>20s}: {1:<20s}'.format('UID',rec.record_uid))
    print('{0:>20s}: {1}'.format('Revision',rec.revision))
    if rec.folder: print('{0:>20s}: {1:<20s}'.format('Folder',rec.folder))
    if rec.title: print('{0:>20s}: {1:<20s}'.format('Title',rec.title))
    if rec.login: print('{0:>20s}: {1:<20s}'.format('Login',rec.login))
    if rec.password: print('{0:>20s}: {1:<20s}'.format('Password',rec.password))
    if rec.link: print('{0:>20s}: {1:<20s}'.format('URL',rec.link))
    
    if len(rec.custom_fields) > 0:
        for c in rec.custom_fields:
            print('{0:>20s}: {1:<s}'.format(c['name'], c['value']))

    if rec.notes:
        print('{0:>20s}: {1:<20s}'.format('Notes',rec.notes))

    print('') 

def formatted_search(params, searchstring):
    """Search and display folders/titles/uids"""

    if not params.record_cache:
        print('No record cache.  Sync down first.')
        return

    if searchstring != '': print('Searching for ' + searchstring)
    p = re.compile(searchstring.lower())

    rec = Record()
    all_recs = []

    for record_uid in params.record_cache:

        record = params.record_cache[record_uid]
        data = json.loads(record['data'].decode('utf-8'))

        rec = Record()
        rec.record_uid = record_uid

        if 'folder' in data:
            rec.folder = data['folder']
        else: rec.folder = ''
    
        if 'title' in data:
            rec.title = data['title']
        else: rec.title = ''
    
        if 'secret1' in data:
            rec.login = data['secret1']
        else: rec.login = ''
    
        if 'secret2' in data:
            rec.password = data['secret2']
        else: rec.password = ''
    
        if 'notes' in data:
            rec.notes = data['notes']
        else: rec.notes = ''
    
        if 'link' in data:
            rec.link = data['link']
        else: rec.link = ''
    
        if 'custom' in data:
            rec.custom_fields = data['custom']
        else: rec.custom_fields = []

        target = rec.record_uid + rec.folder + rec.title + \
                 rec.login + rec.password + rec.notes + \
                 rec.link + str(rec.custom_fields);
        target = target.lower()

        if p.search(target):
            all_recs.append(rec)

    # Sort by folder+title
    all_recs.sort(key=lambda x: (x.folder + x.title).lower(), reverse=False)

    if len(all_recs) > 0:
        print('')
        print('   #  {0:<20s}   {1:<20s} {2:<20s}'.format(
            'Record UID', 'Folder', 'Title'))
        print('      {0:<20s}   {1:<20s} {2:<20s}'.format(
            '-----------', '------', '-----'))
    
        i = 1
        for r in all_recs:
            print('{0:4d}. {1:<20s} {2:<20s} {3:}'.format(
               i, r.record_uid, r.folder[:20], r.title[:100]))
            i = i+1
    
        print('')

    # Under 5 recs, just display on the screen
    if len(all_recs) < 5:
        for r in all_recs:
            formatted_record(params, r.record_uid)


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
