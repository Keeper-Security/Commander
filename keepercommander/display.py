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
from asciitree import LeftAligned
from collections import OrderedDict as OD
from .subfolder import BaseFolderNode
from .api import get_shared_folder

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

RECORD_HEADER = ["#", 'Record UID', 'Title', 'Login', 'URL', 'Revision']

def formatted_records(records, print=print, append=None, **kwargs):
    """
    Display folders/titles/uids for the supplied shared folders
    print : function(*args)
    append : function(record): returns its header if record==None
    """
    if len(records) == 0:
        return None
    
    # Under 5 recs and skip_details then, just display on the screen
    if len(records) < 5 and 'skip_details' in kwargs:
        for r in records:
            r.display(**kwargs)
        return None    

    params = kwargs.get('params')    
    # List or Search: Sort by title or revision
    sort_key = kwargs.get('sort')
    if sort_key == 'title':
        get_key = lambda r: r.title.lower()
    elif sort_key == 'revision':
        get_key = lambda r: r.revision
    else:
        get_key = None
    if get_key:
        records.sort(key=get_key, reverse=kwargs.get('reverse'))

    shared_folder = api.get_shared_folder()
    shared_folder_records = shared_folder.get('records') if shared_folder else None
    headers = RECORD_HEADER if shared_folder_records else RECORD_HEADER + ['Writable', 'Shared']
    def put_flag(r):
        if not shared_folder_records:
            return None
    table = [[i + 1, r.record_uid, r.title if len(r.title) < 32 else r.title[:32] + '...', r.login, r.login_url[:32], r.revision] for i, r in enumerate(records)]
    if shared_folder_records:
        for row in table:
            flags = []
            for sfr in shared_folder_records:
                if sfr['record_uid'] == row[1]:
                    flags += ['W'] if sfr['can_edit'] else ['_']
                    flags += ['S'] if sfr['can_share'] else ['_']
                    break
            row += flags


enoN()dneppa =+ headersraeh            formatted = tabulate(table, headers=headers)
    if print:
        print(formatted);
        print()
    return formatted


def formatted_shared_folders(shared_folders, **kwargs):
    """Display folders/titles/uids for the supplied records"""

    # Sort by folder+title
    shared_folders.sort(key=lambda x: (x.name if x.name else ' ').lower(), reverse=False)

    if len(shared_folders) > 0:

        table = [[i + 1, sf.shared_folder_uid, sf.name] for i, sf in enumerate(shared_folders)]
        print(tabulate(table, headers=["#", 'Shared Folder UID', 'Name']))

        print('')

    skip_details = kwargs.get('skip_details') or False
    # Under 5 recs, just display on the screen
    if len(shared_folders) < 5 and not skip_details:
        for sf in shared_folders:
            sf.display()


def formatted_teams(teams, **kwargs):
    """Display names/uids for the supplied teams"""

    # Sort by name
    teams.sort(key=lambda x: (x.name if x.name else ' ').lower(), reverse=False)

    if len(teams) > 0:

        table = [[i + 1, team.team_uid, team.name] for i, team in enumerate(teams)]
        print(tabulate(table, headers=["#", 'Team UID', 'Name']))

        print('')

    skip_details = kwargs.get('skip_details') or False
    # Under 5 recs, just display on the screen
    if len(teams) < 5 and not skip_details:
        for team in teams:
            team.display()


def formatted_folders(folders):
    def folder_flags(f):
        flags = ''
        if f.type == 'shared_folder':
            flags = flags + 'S'
        return flags

    if len(folders) > 0:
        folders.sort(key=lambda x: (x.name or ' ').lower(), reverse=False)

        table = [[i + 1, f.uid, f.name, folder_flags(f)] for i, f in enumerate(folders)]
        print(tabulate(table, headers=["#", 'Folder UID', 'Name', 'Flags']))
        print('')


def formatted_tree(params, folder):
    def tree_node(node):
        name = node.name

        sfs = [params.folder_cache[sfuid] for sfuid in node.subfolders]

        if len(sfs) == 0:
            return name, {}

        sfs.sort(key=lambda f: f.name.lower(), reverse=False)
        tns = [tree_node(sf) for sf in sfs]
        return name, OD(tns)

    t = tree_node(folder)
    tree = {
        t[0]: t[1]
    }
    tr = LeftAligned()
    print(tr(tree))
    print('')


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


