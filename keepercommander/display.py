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
import re
import shutil
from collections import OrderedDict as OD
from typing import Tuple, List, Union

from asciitree import LeftAligned
from colorama import init, Fore, Back, Style
from tabulate import tabulate

from keepercommander import __version__, api
from .record import Record
from .subfolder import BaseFolderNode, SharedFolderNode, get_contained_record_uids

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
    HIGHINTENSITYRED = '\033[1;91m'
    WHITE = '\033[0;37m'
    HIGHINTENSITYWHITE = '\033[97m'



def welcome():
    lines = []    # type: List[Union[str, Tuple[str, str]]]

    lines.append( r'         /#############/   /#\ ')
    lines.append( r'        /#############/   /###\      _    __  _______  _______  ______   _______  ______ (R)')
    lines.append( r'       /#############/   /#####\    | |  / / |  ____/ |  ____/ |  ___ \ |  ____/ |  ___ \ ')
    lines.append( r'      /######/           \######\   | | / /  | |____  | |____  | | __| || |____  | | __| | ')
    lines.append( r'     /######/             \######\  | |< <   |  ___/  |  ___/  | |/___/ |  ___/  | |/_  / ')
    lines.append( r'    /######/               \######\ | | \ \  | |_____ | |_____ | |      | |_____ | |  \ \ ')
    lines.append( r'    \######\               /######/ |_|  \_\ |_______||_______||_|      |_______||_|   \_\ ')
    lines.append((r'     \######\             /######/', r'     ____                                          _ '))
    lines.append((r'      \######\           /######/ ', r'   /  ___|___  _ __ ___  _ __ ___   __ _ _ __   __| | ___ _ __ '))
    lines.append((r'       \#############\   \#####/  ', r"  /  /   / _ \| '_ ` _ \| '_ ` _ \ / _` | '_ \ / _` |/ _ \ '__| "))
    lines.append((r'        \#############\   \###/   ', r'  \  \__| (_) | | | | | | | | | | | (_| | | | | (_| |  __/ | '))
    lines.append((r'         \#############\   \#/    ', r'   \_____\___/|_| |_| |_|_| |_| |_|\__,_|_| |_|\__,_|\___|_| '))
    lines.append('')

    try:
        width = shutil.get_terminal_size(fallback=(160, 50)).columns
    except:
        width = 160
    print(Style.RESET_ALL)
    print(Back.BLACK + Style.BRIGHT + '\n')
    for line in lines:
        if isinstance(line, str):
            if len(line) > width:
                line = line[:width]
            print('\033[2K' + Fore.LIGHTYELLOW_EX + line)
        elif isinstance(line, tuple):
            yellow_line = line[0] if len(line) > 0 else ''
            white_line = line[1] if len(line) > 1 else ''
            if len(yellow_line) > width:
                yellow_line = yellow_line[:width]
            if len(yellow_line) + len(white_line) > width:
                if len(yellow_line) < width:
                    white_line = white_line[:width - len(yellow_line)]
                else:
                    white_line = ''
            print('\033[2K' + Fore.LIGHTYELLOW_EX + yellow_line + Fore.LIGHTWHITE_EX + white_line)

    print('\033[2K' + Fore.LIGHTBLACK_EX + f'{("v" + __version__):>93}\n' + Style.RESET_ALL)


def formatted_records(records, **kwargs):
    """Display folders/titles/uids for the supplied shared folders"""
    params = None
    if 'params' in kwargs:
        params = kwargs['params']

    # Sort by title
    records.sort(key=lambda x: x.title.lower(), reverse=False)

    def abbreviate_text(text: str, chars_num: int):
        if 'verbose' in kwargs and kwargs['verbose']:
            return text
        else:
            return text if len(text) < chars_num else text[:chars_num] + '...'

    if len(records) > 0:
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

        table = [[i + 1, r.record_uid, abbreviate_text(r.record_type, 32), abbreviate_text(r.title, 32), r.login, abbreviate_text(r.login_url, 32)] for i, r in enumerate(records)]
        headers = ["#", 'Record UID', 'Type', 'Title', 'Login', 'URL']
        if shared_folder and 'records' in shared_folder:
            headers.append('Permissions')
            for row in table:
                permissions = ''
                for sfr in shared_folder['records']:
                    if sfr['record_uid'] == row[1]:
                        if sfr['can_edit']:
                            permissions = 'Can Edit'
                        if sfr['can_share']:
                            if permissions:
                                permissions += ' & Share'
                            else:
                                permissions = 'Can Share'
                        if not permissions:
                            permissions = 'Read Only'
                        break
                row.append(permissions)

        print(tabulate(table, headers=headers))


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


def formatted_tree(params, folder, verbose=False, show_records=False, shares=False, hide_shares_key=False, title=None):
    def print_share_permissions_key():
        perms_key = 'Share Permissions Key:\n' \
               '======================\n' \
               'RO = Read-Only\n' \
               'MU = Can Manage Users\n' \
               'MR = Can Manage Records\n' \
               'CE = Can Edit\n' \
               'CS = Can Share\n' \
               '======================\n'
        print(perms_key)

    def get_share_info(node):
        MU_KEY = 'manage_users'
        MR_KEY = 'manage_records'
        DMR_KEY = 'default_manage_records'
        DMU_KEY = 'default_manage_user'
        DCE_KEY = 'default_can_edit'
        DCS_KEY = 'default_can_share'
        perm_abbrev_lookup = {MU_KEY: 'MU', MR_KEY: 'MR', DMR_KEY: 'MU', DMU_KEY: 'MU', DCE_KEY: 'CE', DCS_KEY: 'CS'}

        def get_users_info(users):
            info = []
            for u in users:
                email = u.get('username')
                if email == params.user:
                    continue
                privs = [v for k, v in perm_abbrev_lookup.items() if u.get(k)] or ['RO']
                info.append(f'[{email}:{",".join(privs)}]')
            return 'users:' + ','.join(info) if info else ''

        def get_teams_info(teams):
            info = []
            for t in teams:
                name = t.get('name')
                privs = [v for k, v in perm_abbrev_lookup.items() if t.get(k)] or ['RO']
                info.append(f'[{name}:{",".join(privs)}]')
            return 'teams:' + ','.join(info) if info else ''

        result = ''
        if isinstance(node, SharedFolderNode):
            sf = params.shared_folder_cache.get(node.uid)
            teams_info = get_teams_info(sf.get('teams', []))
            users_info = get_users_info(sf.get('users', []))
            default_perms = [v for k, v in perm_abbrev_lookup.items() if sf.get(k)] or ['RO']
            default_perms = 'default:' + ','.join(default_perms)
            user_perms = [v for k, v in perm_abbrev_lookup.items() if sf.get(k)] or ['RO']
            user_perms = 'user:' + ','.join(user_perms)
            perms = [default_perms, user_perms, teams_info, users_info]
            perms = [p for p in perms if p]
            result = f' ({"; ".join(perms)})' if shares else ''

        return result

    def tree_node(node):
        node_uid = node.record_uid if isinstance(node, Record) else node.uid or ''
        node_name = node.title if isinstance(node, Record) else node.name
        node_name = f'{node_name} ({node_uid})'
        share_info = get_share_info(node) if isinstance(node, SharedFolderNode) and shares else ''
        node_name = f'{Style.DIM}{node_name} [Record]{Style.NORMAL}' if isinstance(node, Record) \
            else f'{node_name}{Style.BRIGHT} [SHARED]{Style.NORMAL}{share_info}' if isinstance(node, SharedFolderNode)\
            else node_name

        dir_nodes = [] if isinstance(node, Record) \
            else [params.folder_cache.get(fuid) for fuid in node.subfolders]
        rec_nodes = []
        if show_records and isinstance(node, BaseFolderNode):
            node_uid = '' if node.type == '/' else node.uid
            rec_uids = get_contained_record_uids(params, node_uid).get(node_uid)
            records = [api.get_record(params, rec_uid) for rec_uid in rec_uids]
            records = [r for r in records if isinstance(r, Record)]
            rec_nodes.extend(records)

        dir_nodes.sort(key=lambda f: f.name.lower(), reverse=False)
        rec_nodes.sort(key=lambda r: r.title.lower(), reverse=False)
        child_nodes = dir_nodes + rec_nodes

        tns = [tree_node(n) for n in child_nodes]
        return node_name, OD(tns)

    root, branches = tree_node(folder)
    tree = {root: branches}
    tr = LeftAligned()
    if shares and not hide_shares_key:
        print_share_permissions_key()
    if title:
        print(title)
    tree_txt = str(tr(tree))
    tree_txt = re.sub(r'\s+\(\)', '', tree_txt)
    if not verbose:
        lines = tree_txt.splitlines()
        for idx, line in enumerate(lines):
            line = re.sub(r'\s+\(.+?\)', '', line, count=1)
            lines[idx] = line
        tree_txt = '\n'.join(lines)
    print(tree_txt)
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
    data = json.loads(cached_rec['data_unencrypted'].decode('utf-8'))
    print(data)
