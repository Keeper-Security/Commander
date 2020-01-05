#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2018 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import itertools
import shlex

from prompt_toolkit.completion import Completion, Completer

from .params import KeeperParams
from .commands.folder import mv_parser
from .commands.utils import ConnectCommand
from .commands import commands, enterprise_commands
from . import api


def no_parse_exception(m):
    pass


def no_exit():
    pass


record_parser = argparse.ArgumentParser()
record_parser.add_argument('-e', '--email', dest='email', action='append')
record_parser.add_argument('-a', '--action', dest='action', action='store')
record_parser.add_argument('--notes', dest='notes', action='store')
record_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
record_parser.error = no_parse_exception
record_parser.exit = no_exit

folder_parser = argparse.ArgumentParser()
folder_parser.add_argument('-e', '--email', dest='email', action='append')
folder_parser.add_argument('-a', '--action', dest='action', action='store')
folder_parser.add_argument('-r', '--record', dest='record', action='append')
folder_parser.add_argument('folder', nargs='?', type=str, action='store', help='record path or UID')
folder_parser.error = no_parse_exception
folder_parser.exit = no_exit


def try_resolve_path(params, path):
    if type(path) is str:
        folder = params.folder_cache[params.current_folder] if params.current_folder in params.folder_cache else params.root_folder
        if len(path) > 0:
            if path[0] == '/':
                folder = params.root_folder
                path = path[1:]

            start = 0
            while True:
                idx = path.find('/', start)
                path_component = ''
                if idx < 0:
                    if len(path) > 0:
                        path_component = path.strip()
                elif idx > 0 and path[idx - 1] == '\\':
                    start = idx + 1
                    continue
                else:
                    path_component = path[:idx].strip()

                if len(path_component) == 0:
                    break

                folder_uid = None
                if path_component == '.':
                    folder_uid = folder.uid
                elif path_component == '..':
                    folder_uid = folder.parent_uid or ''
                else:
                    for uid in folder.subfolders:
                        sf = params.folder_cache[uid]
                        if sf.name == path_component:
                            folder_uid = uid

                if folder_uid is None:
                    break

                if folder_uid == '':
                    folder = params.root_folder
                elif folder_uid in params.folder_cache:
                    folder = params.folder_cache[folder_uid]
                else:
                    break
                if idx < 0:
                    path = ''
                    break

                path = path[idx+1:]
                start = 0

        return folder, path

    return None


class CommandCompleter(Completer):
    def __init__(self, params, aliases):
        # type: (CommandCompleter, KeeperParams, dict) -> None
        Completer.__init__(self)
        self.params = params
        self.commands = commands
        self.aliases = aliases

    @staticmethod
    def fix_input(txt):
        is_escape = False
        is_quote = False
        is_double_quote = False
        for c in txt:
            if c == '\\':
                isEscape = not is_escape
            elif not is_escape:
                if c == '\'':
                    if is_double_quote:
                        return None
                    is_quote = not is_quote
                elif c == '"':
                    if is_quote:
                        return None
                    is_double_quote = not is_double_quote

        if is_quote:
            return txt + '\''

        if is_double_quote:
            return txt + '"'

        return txt

    def get_completions(self, document, complete_event):
        try:
            if document.is_cursor_at_the_end:
                pos = document.text.find(' ')
                if pos == -1:
                    cmds = [x for x in commands if x.startswith(document.text)]
                    if self.aliases:
                        al_cmds = [x[0] for x in self.aliases.items() if type(x[1]) == tuple and x[0].startswith(document.text)]
                        cmds.extend(al_cmds)
                    if self.params.enterprise:
                        e_cmds = [x for x in enterprise_commands if x.startswith(document.text)]
                        cmds.extend(e_cmds)
                    if len(cmds) > 0:
                        cmds.sort()
                        for c in cmds:
                            yield Completion(c, start_position=-len(document.text))
                elif pos > 0:
                    cmd = document.text[:pos]
                    if cmd in self.aliases:
                        ali = self.aliases[cmd]
                        if type(ali) == tuple:
                            cmd = ali[0]
                        else:
                            cmd = ali
                    raw_input = document.text[pos+1:].strip()
                    context = ''
                    extra = dict()
                    if cmd in {'download-attachment', 'upload-attachment', 'share-record', 'edit', 'append-notes',
                               'rm', 'clipboard-copy', 'find-password'}:
                        args = CommandCompleter.fix_input(raw_input)
                        if args is not None:
                            extra['escape_space'] = args == raw_input
                            opts, _ = record_parser.parse_known_args(shlex.split(args))
                            extra['prefix'] = opts.record or ''
                            context = 'path'
                    elif cmd in {'ls', 'share-folder', 'mkdir', 'tree', 'rmdir', 'cd', 'record-permission'}:
                        args = CommandCompleter.fix_input(raw_input)
                        if args is not None:
                            extra['escape_space'] = args == raw_input
                            opts, _ = folder_parser.parse_known_args(shlex.split(args))
                            extra['prefix'] = opts.folder or ''
                            context = 'folder'
                    elif cmd in {'mv', 'ln'}:
                        args = CommandCompleter.fix_input(raw_input)
                        if args is not None:
                            extra['escape_space'] = args == raw_input
                            opts, _ = mv_parser.parse_known_args(shlex.split(args))
                            if opts.dst is None:
                                word = document.get_word_under_cursor()
                                if len(word) == 0 and len(opts.src or '') > 0:
                                    extra['prefix'] = ''
                                    context = 'folder'
                                else:
                                    extra['prefix'] = opts.src or ''
                                    context = 'path'
                            else:
                                extra['prefix'] = opts.dst or ''
                                context = 'folder'
                    elif cmd == 'help':
                        args = CommandCompleter.fix_input(raw_input)
                        if args is not None:
                            extra['prefix'] = args
                            context = 'command'
                    elif cmd == 'connect':
                        args = CommandCompleter.fix_input(raw_input)
                        if args is not None:
                            extra['prefix'] = args
                            context = 'connect'

                    if context in {'folder', 'path'}:
                        rs = try_resolve_path(self.params, extra['prefix'])
                        if rs is not None:
                            folder, name = rs
                            is_path = False if name else True
                            for uid in folder.subfolders:
                                f = self.params.folder_cache[uid]
                                if f.name.startswith(name) and len(name) < len(f.name):
                                    n = f.name
                                    if is_path and not extra['prefix'].endswith('/'):
                                        n = '/' + n
                                    if extra.get('escape_space'):
                                        n = n.replace(' ', '\\ ')
                                    yield Completion(n, display=n + '/', start_position=-len(name))

                            if context == 'path':
                                name = name.lower()
                                folder_uid = folder.uid or ''
                                if folder_uid in self.params.subfolder_record_cache:
                                    for uid in self.params.subfolder_record_cache[folder_uid]:
                                        r = self.params.record_cache[uid]
                                        if 'display_name' not in r:
                                            rec = api.get_record(self.params, uid)
                                            r['display_name'] = rec.title or rec.record_uid
                                        n = r.get('display_name') or ''
                                        if len(n) > 0:
                                            if n.lower().startswith(name) and len(name) < len(n):
                                                if extra.get('escape_space'):
                                                    n = n.replace(' ', '\\ ')
                                                d = n
                                                if len(d) > 39:
                                                    d = d[:29] + '...' + d[-7:]
                                                yield Completion(n, display=d, start_position=-len(name))
                    elif context == 'command':
                        cmd = extra['prefix']
                        for c in itertools.chain(commands.keys(), enterprise_commands.keys()):
                            if c.startswith(cmd):
                                yield Completion(c, display=c, start_position=-len(cmd))
                    elif context == 'connect':
                        ConnectCommand.find_endpoints(self.params)
                        cmd = extra['prefix']
                        comp = cmd.casefold()
                        names = []
                        unique_names = set()
                        for x in ConnectCommand.Endpoints:
                            name = (x.name or '').casefold()
                            if name not in unique_names:
                                unique_names.add(name)
                                if name.startswith(comp):
                                    names.append(x.name)
                        for name in names:
                            yield Completion(name, display=name, start_position=-len(cmd))

        except Exception as e:
            pass

