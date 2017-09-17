#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#
import json

from colorama import init
from tabulate import tabulate

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
    records.sort(key=lambda x: ((x.folder if x.folder else ' ') + x.title).lower(), reverse=False)

    if len(records) > 0:

        table = [[i + 1, r.record_uid, r.folder, r.title] for i, r in enumerate(records)]
        print(tabulate(table, headers=["#", 'Record UID', 'Folder', 'Title']))

        print('')

    # Under 5 recs, just display on the screen
    if len(records) < 5:
        for r in records:
            r.display()

def formatted_shared_folders(shared_folders):
    """Display folders/titles/uids for the supplied records"""

    # Sort by folder+title
    shared_folders.sort(key=lambda x: (x.name if x.name else ' ').lower(), reverse=False)

    if len(shared_folders) > 0:

        table = [[i + 1, sf.shared_folder_uid, sf.name] for i, sf in enumerate(shared_folders)]
        print(tabulate(table, headers=["#", 'Shared Folder UID', 'Name']))

        print('')

    # Under 5 recs, just display on the screen
    if len(shared_folders) < 5:
        for sf in shared_folders:
            sf.display()


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

def print_record(params, record_uid):
    """ Show record content """

    try:
        cached_rec = params.record_cache[record_uid]
    except KeyError as e:
        raise Exception('Record not found: ' + record_uid)
    data = json.loads(cached_rec['data'].decode('utf-8'))
    print(data)


