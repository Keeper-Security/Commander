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
import shutil

from collections import OrderedDict as OD
from typing import Tuple, List, Union

from asciitree import LeftAligned
from colorama import init, Fore, Back, Style
from tabulate import tabulate

from keepercommander import __version__
from .subfolder import BaseFolderNode, SharedFolderNode

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


def welcome():
    lines = []    # type: List[Union[str, Tuple[str, str]]]

    lines.append( r'           ___________    /#. ')
    lines.append( r'         /###########/   /###\ ')
    lines.append( r'        /###########/   /#####\      _    __  _______  _______  ______   _______  ______ (R)')
    lines.append( r'       /###########/    \######\    | |  / / |  ____/ |  ____/ |  ___ \ |  ____/ |  ___ \ ')
    lines.append( r'      /######/           \######\   | | / /  | |____  | |____  | | __| || |____  | | __| | ')
    lines.append( r'     /######/             \######\  | |< <   |  ___/  |  ___/  | |/___/ |  ___/  | |/_  / ')
    lines.append( r'    /######/               \######\ | | \ \  | |_____ | |_____ | |      | |_____ | |  \ \ ')
    lines.append( r'    \######\               /######/ |_|  \_\ |_______||_______||_|      |_______||_|   \_\ ')
    lines.append((r'     \######\             /######/', r'     ____                                          _ '))
    lines.append((r'      \######\           /######/ ', r'   /  ___|___  _ __ ___  _ __ ___   __ _ _ __   __| | ___ _ __ '))
    lines.append((r'       \#############\   \#####/  ', r"  /  /   / _ \| '_ ` _ \| '_ ` _ \ / _` | '_ \ / _` |/ _ \ '__| "))
    lines.append((r'        \#############\   \###/   ', r'  \  \__| (_) | | | | | | | | | | | (_| | | | | (_| |  __/ | '))
    lines.append((r'         \#############\   \#.    ', r'   \_____\___/|_| |_| |_|_| |_| |_|\__,_|_| |_|\__,_|\___|_| '))
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
            headers.append('Flags')
            for row in table:
                flag = ''
                for sfr in shared_folder['records']:
                    if sfr['record_uid'] == row[1]:
                        flag = flag + ('W' if sfr['can_edit'] else '_') + ' '
                        flag = flag + ('S' if sfr['can_share'] else '_')
                        break
                row.append(flag)

        print(tabulate(table, headers=headers))

        print('')

    skip_details = kwargs.get('skip_details') or False
    # Under 5 recs, just display on the screen
    if len(records) < 5 and not skip_details:
        for r in records:
            r.display(**kwargs)


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


def formatted_tree(params, folder, verbose=False):
    def tree_node(node):
        if verbose and node.uid:
            name = f'{node.name} ({node.uid})'
        else:
            name = node.name

        if isinstance(node, SharedFolderNode):
            name += ' ' + Style.BRIGHT + '[Shared]' + Style.NORMAL

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
    data = json.loads(cached_rec['data_unencrypted'].decode('utf-8'))
    print(data)


def format_msp_licenses(licenses):

    print('')
    print('MSP Plans and Licenses')
    print('-----------------------')

    if len(licenses) > 0:

        for i, lic in enumerate(licenses):

            if len(licenses) > 1:
                print('License # ', i+1)

            msp_license_pool = lic['msp_pool']

            table = [
                [
                    j + 1,
                    ml['product_id'],
                    ml['availableSeats'],
                    ml['seats'],
                    ml['stash'] if 'stash' in ml else ' -'   # sometimes stash won't be returned from the backend
                ] for j, ml in enumerate(msp_license_pool)]
            print(tabulate(table, headers=["#", 'Plan Id', 'Available Licenses', 'Total Licenses', 'Stash']))
            print('')


def format_managed_company(mcs):

    # Sort by title
    mcs.sort(key=lambda x: x['mc_enterprise_name'].lower(), reverse=False)

    if len(mcs) > 0:
        table = [[i + 1, mc['mc_enterprise_id'], mc['mc_enterprise_name'], mc['product_id'], mc['number_of_seats'], mc['number_of_users']] for i, mc in enumerate(mcs)]
        print(tabulate(table, headers=["#", 'ID', 'Name', 'Plan', 'Allocated', 'Active']))
        print('')


