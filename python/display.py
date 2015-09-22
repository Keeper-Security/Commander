import sys
import json
import base64
import re
from record import Record

def formatted_list(params):
    """Display list of folders/titles/uids"""

    if not params.record_cache:
        print('No records to display')
        return

    print('') 
    print('   #  {0:<20s}   {1:<20s} {2:<20s}'.format(
        'Record UID', 'Folder', 'Title'))
    print('      {0:<20s}   {1:<20s} {2:<20s}'.format(
        '-----------', '------', '-----'))

    rec = Record() 
    all_recs = []

    for record_uid in params.record_cache:

        record = params.record_cache[record_uid]
        data = json.loads(record['data'].decode('utf-8')) 

        rec = Record()
        rec.record_uid = record_uid 
        rec.folder = data['folder']
        rec.title = data['title']
        rec.login = data['secret2']
        rec.password = data['secret1']
        rec.notes = data['notes']
        rec.link = data['link']
        rec.custom_fields = data['custom']
        all_recs.append(rec)

    # Sort by folder+title
    all_recs.sort(key=lambda x: (x.folder + x.title).lower(), reverse=False)

    # display list
    i = 1
    for r in all_recs:
        print('{0:4d}. {1:<20s} {2:<20s} {3:}'.format(
           i, r.record_uid, r.folder[:20], r.title[:100]))
        i = i+1
        
    print('') 


def formatted_record(params,record_uid):    

    record_uid.strip()

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
    rec.folder = data['folder']
    rec.title = data['title']
    rec.login = data['secret2']
    rec.password = data['secret1']
    rec.notes = data['notes']
    rec.link = data['link']
    rec.custom_fields = data['custom']

    print('') 
    print('{0:>20s}: {1:<20s}'.format('UID',rec.record_uid))
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

    p = re.compile(searchstring)

    rec = Record()
    all_recs = []

    for record_uid in params.record_cache:

        record = params.record_cache[record_uid]
        data = json.loads(record['data'].decode('utf-8'))

        rec = Record()
        rec.record_uid = record_uid
        rec.folder = data['folder']
        rec.title = data['title']
        rec.login = data['secret2']
        rec.password = data['secret1']
        rec.notes = data['notes']
        rec.link = data['link']
        rec.custom_fields = data['custom']

        if p.match(rec.record_uid + rec.folder + rec.title + \
                   rec.login + rec.password + rec.notes + \
                   rec.link + str(rec.custom_fields) ):
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
