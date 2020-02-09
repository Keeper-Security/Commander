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
from pypager.source import GeneratorSource
from pypager.pager import Pager
from io import StringIO
import logging
from wsgiref.simple_server import make_server
from .subfolder import BaseFolderNode
from .error import NonSupportedType

init()

class TablePagerException(Exception):
    pass
class TableNotYetAssignedException(TablePagerException):
    pass

class TablePager(Pager):
    table = None
    headers = None
    
    def __init__(tbl, hdr):
        TablePager.table = tbl
        TablePager.headers = hdr
        super().__init__()
   
    @classmethod
    def get_uid(cls, uid: str) -> str or None:
        ''' Resolve uid by line number of previous list command
            Raise TablePagerException if not proper number
        '''
        if not cls.table:
            raise TableNotYetAssignedException("Record number specify needs to be after pager or web showed records.")
        import re
        mt = re.fullmatch(r"(\d{1,4})", uid)
        if mt:
            num = int(mt.group(0))
            if not 0 < num < 10000:
                raise TablePagerException(f"Specify number 1 or less than 10000.")
            lines = TablePager.table
            if num > len(lines):
                raise TablePagerException(f"Specify (0 < number <= ({len(lines)}).")
            return lines[num - 1][1]
        else:
            return None


pager = None

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

import locale

def formatted_records(records, print_func=print, appends=None, **kwargs):
    """
    Display folders/titles/uids for the supplied shared folders
    print : function(*args)
    appends : function(record): returns its header if record==None
    """
    if len(records) == 0:
        return None
    
    # Under 5 recs and skip_details then, just display on the screen
    if len(records) < 5 and not 'skip_details' in kwargs:
        for r in records:
            r.display(**kwargs)
        return None    

    # List or Search: Sort by title or revision
    reverse_sort = kwargs.get('reverse')
    sort_key = kwargs.get('sort')


    def xfrm(r, sort_key):
        try:
            key = getattr(r, sort_key)
            if isinstance(key, str):
                return locale.strxfrm(key)
            elif isinstance(key, (int, float)):
                return key
            else:
                raise NonSupportedType(f"key {sort_key} is not a supported sort key.")
        except AttributeError:
            raise
    

    sorted_records = sorted(records, key=lambda r: xfrm(r, sort_key), reverse=reverse_sort) if sort_key else None
    if sorted_records:
        records = sorted_records

    params = kwargs.get('params')    
    shared_folder = None
    if 'folder' in kwargs and params is not None:
        fuid = kwargs['folder']
        if fuid in params.folder_cache:
            folder = params.folder_cache[fuid]
            if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                if folder.type == BaseFolderNode.SharedFolderFolderType:
                    fuid = folder.shared_folder_uid
            else:
                fuid = None
            if fuid and fuid in params.shared_folder_cache:
                shared_folder = params.shared_folder_cache[fuid]
    shared_folder_records = shared_folder.get('records') if shared_folder else None
    headers = RECORD_HEADER if not shared_folder_records else RECORD_HEADER + ['Writable', 'Shared']
    if appends:
        headers += [f(None) for f in appends] # append field names
    table = [[i + 1, r.record_uid, r.title if len(r.title) < 32 else r.title[:32] + '...', r.login, r.login_url[:32], r.revision] for i, r in enumerate(records)]

    if shared_folder_records:
        from collections import deque
        for row in table:
            flags = collections.deque()
            for sfr in shared_folder_records:
                if sfr['record_uid'] == row[1]:
                    flags += 'W' if sfr['can_edit'] else '_'
                    flags += 'S' if sfr['can_share'] else '_'
                    break
            row += flags
    if appends:
        for row in table:
            xx = [f(row[1]) for f in appends]
            row += xx
    if kwargs.get('pager') or kwargs.get('webview'): # remove uid if pager option
        TablePager.table = oldtable = table
        table = [row[:1]+row[2:] for row in table]
        oldheaders = headers
        del headers[1]    
    formatted = tabulate(table, headers=headers)
    if kwargs.get('pager'):
        def generate_a_lot_of_content():
            yield [('', formatted)]
        global pager
        pager = TablePager(oldtable)
        pager.add_source(GeneratorSource(generate_a_lot_of_content()))
        pager.run()
    else:
        print_func(formatted)
    webview = kwargs.get('webview')
    if webview:
        try:
            port = int(webview)
            
            def helo(env, start_resp):
                start_resp("200 OK",
                    [("Content-type", 'text/html; charset=utf-8')])
                text = tabulate(oldtable, headers=oldheaders).encode('utf-8')
                head = b'<!DOCTYPE html> <html> <head> <meta charset="utf-8"/> </head>'
                body = b"<body> <pre> <code>"
                tail = b" </code> </pre> </body> </html>"
                return [head, body, text, tail]
            httpd = make_server('', port, helo)
            try:
                logging.info(f'A web view is opened at port {port}; Open browser with address "localhost:{port}" or cntrl-c to quit.')
                httpd.handle_request()
            except KeyboardInterrupt:
                logging.INFO('Quit http server with Keyboard Interrupt')
        except ValueError:
            logging.info('%s is not for port number' % webview)
        except OSError as e:
            logging.error("Making web server failed by " + e.strerror)
    return formatted


def formatted_shared_folders(shared_folders, print=print, appends=None, **kwargs):
    """Display folders/titles/uids for the supplied records as:
    headers=['#', 'Shared Folder UID', 'Name']
    Params must: len(shared_folders) > 0
    """
    # Sort by folder title
    shared_folders.sort(key=lambda x: (x.name if x.name else '').lower(), reverse=False)
    # In case items under 5 records and skip_datails option, just display on the screen
    if print:
        if len(shared_folders) < 5 and not 'skip_details' in kwargs:
            for sf in shared_folders:
                sf.display()
        else:
            table = [[i + 1, sf.shared_folder_uid, sf.name] for i, sf in enumerate(shared_folders)]
            print(tabulate(table, headers=["#", 'Shared Folder UID', 'Name']))
            print('')


def formatted_teams(teams, print=print, appends=None, **kwargs):
    """Display names/uids for the supplied teams as:
    headers=['#', 'Team UID', 'Name']
    """

    # Sort by name
    teams.sort(key=lambda x: (x.name if x.name else ' ').lower(), reverse=False)
    # Under 5 recs, just display on the screen
    if print:
        if len(teams) < 5 and not 'skip_details' in kwargs:
            for team in teams:
                team.display()
        else:
            table = [[i + 1, team.team_uid, team.name] for i, team in enumerate(teams)]
            print(tabulate(table, headers=['#', 'Team UID', 'Name']))
            print('')



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


