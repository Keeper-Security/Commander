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
import shlex

from prompt_toolkit.completion import Completion, Completer
from .commands.folder import ls_parser, mv_parser
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

                folder_uid = ''
                if path_component == '.':
                    folder_uid = folder.uid
                elif path_component == '..':
                    folder_uid = folder.parent_uid
                else:
                    for uid in folder.subfolders:
                        sf = params.folder_cache[uid]
                        if sf.name == path_component:
                            folder_uid = uid

                if len(folder_uid) == 0:
                    break

                folder = params.folder_cache[folder_uid]
                if idx < 0:
                    path = ''
                    break

                path = path[idx+1:]
                start = 0

        return folder, path

    return None


class CommandCompleter(Completer):
    def __init__(self, params, commands):
        Completer.__init__(self)
        self.params = params
        self.commands = commands

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
                    cmds = [x for x in self.commands if x.startswith(document.text)]
                    if len(cmds) > 0:
                        cmds.sort()
                        for c in cmds:
                            yield Completion(c, start_position=-len(document.text))
                elif pos > 0:
                    cmd = document.text[:pos]
                    raw_input = document.text[pos+1:].strip()
                    context = ''
                    extra = dict()
                    if cmd == 'ls':
                        args = CommandCompleter.fix_input(raw_input)
                        if args is not None:
                            extra['escape_space'] = args == raw_input
                            opts, _ = ls_parser.parse_known_args(shlex.split(args))
                            extra['prefix'] = opts.pattern or ''
                            context = 'folder'
                    elif cmd in {'download-attachment', 'upload-attachment', 'share-record', 'append-notes', 'rm'} :
                        args = CommandCompleter.fix_input(raw_input)
                        if args is not None:
                            extra['escape_space'] = args == raw_input
                            opts, _ = record_parser.parse_known_args(shlex.split(args))
                            extra['prefix'] = opts.record or ''
                            context = 'path'
                    elif cmd in {'share-folder', 'mkdir', 'tree', 'rmdir', 'cd'}:
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

                    if context in {'folder', 'path'}:
                        rs = try_resolve_path(self.params, extra['prefix'])
                        if rs is not None:
                            folder, name = rs
                            for uid in folder.subfolders:
                                f = self.params.folder_cache[uid]
                                if f.name.startswith(name) and len(name) < len(f.name):
                                    n = f.name
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
        except Exception as e:
            pass

