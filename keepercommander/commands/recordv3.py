#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import os
import argparse
import re
import datetime
import json
from typing import Generator, List, Tuple
import requests
import base64
import tempfile
import logging
import threading
from Cryptodome.Cipher import AES
from pathlib import Path
from tabulate import tabulate

from ..team import Team
from .. import api, display, generator
from .. import record_pb2 as records, recordv3, loginv3, rest_api
from ..subfolder import BaseFolderNode, find_folders, try_resolve_path, get_folder_path
from .base import user_choice, suppress_exit, raise_parse_exception, dump_report_data, Command
from ..display import bcolors
from ..record import Record, get_totp_code
from ..params import KeeperParams, LAST_RECORD_UID
from ..error import CommandError
from .enterprise_pb2 import SharedRecordResponse
from . import record as recordv2
from .register import FileReportCommand


def register_commands(commands):
    commands['add'] = RecordAddCommand()
    commands['edit'] = RecordEditCommand()
    commands['rm'] = RecordRemoveCommand()
    commands['search'] = SearchCommand()
    commands['list'] = RecordListCommand()
    commands['list-sf'] = RecordListSfCommand()
    commands['list-team'] = RecordListTeamCommand()
    commands['get'] = RecordGetUidCommand()
    commands['append-notes'] = RecordAppendNotesCommand()
    commands['download-attachment'] = RecordDownloadAttachmentCommand()
    commands['upload-attachment'] = RecordUploadAttachmentCommand()
    commands['delete-attachment'] = RecordDeleteAttachmentCommand()
    commands['clipboard-copy'] = ClipboardCommand()
    commands['record-history'] = RecordHistoryCommand()
    commands['totp'] = TotpCommand()
    commands['shared-records-report'] = SharedRecordsReport()
    commands['record-type-info'] = RecordTypeInfo()
    commands['record-type'] = RecordRecordType()
    commands['file-report'] = RecordFileReportCommand()


def register_command_info(aliases, command_info):
    aliases['a'] = 'add'
    aliases['s'] = 'search'
    aliases['l'] = 'list'
    aliases['lsf'] = 'list-sf'
    aliases['lt'] = 'list-team'
    aliases['g'] = 'get'
    aliases['an'] = 'append-notes'
    aliases['da'] = 'download-attachment'
    aliases['ua'] = 'upload-attachment'
    aliases['cc'] = 'clipboard-copy'
    aliases['find-password'] = ('clipboard-copy', '--output=stdout')
    aliases['rh'] = 'record-history'
    aliases['rti'] = 'record-type-info'
    aliases['rt'] = 'record-type'

    for p in [add_parser, edit_parser, rm_parser, search_parser, list_parser, get_info_parser, append_parser,
                download_parser, upload_parser, delete_attachment_parser, clipboard_copy_parser, record_history_parser,
                totp_parser, shared_records_report_parser, record_type_info_parser, record_type_parser, file_report_parser]:
        command_info[p.prog] = p.description
    command_info['list-sf|lsf'] = 'Display all shared folders'
    command_info['list-team|lt'] = 'Display all teams'


add_parser = argparse.ArgumentParser(prog='add|a', description='Add a record')
add_parser.add_argument('--login', dest='login', action='store', help='login name')
command_group = add_parser.add_mutually_exclusive_group()
command_group.add_argument('--pass', dest='password', action='store', help='password')
command_group.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate a random password')
add_parser.add_argument('--url', dest='url', action='store', help='url')
add_parser.add_argument('--notes', dest='notes', action='store', help='notes')
add_parser.add_argument('--custom', dest='custom', action='store', help='add custom fields. JSON or name:value pairs separated by comma. CSV Example: --custom "name1: value1, name2: value2". JSON Example: --custom \'{"name1":"value1", "name2":"value: 2,3,4"}\'')
add_parser.add_argument('--folder', dest='folder', action='store', help='folder path or UID where record is to be created')
add_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt for omitted fields')
add_parser.add_argument('-t', '--title', dest='title', type=str, action='store', help='record title')
command_group = add_parser.add_mutually_exclusive_group()
command_group.add_argument('-v2', '--legacy', dest='legacy', action='store_true', help='add legacy record')
command_group.add_argument('-v3d', '--data', dest='data', action='store', help='load record type json data from string')
command_group.add_argument('-v3f', '--from-file', dest='data_file', action='store', help='load record type json data from file')
# command_group.add_argument('-o', '--option', dest='option', action='append', help='load record type data from string with dot notation')
add_parser.add_argument('option', nargs='*', type=str, action='store', help='load record type data from strings with dot notation')
add_parser.add_argument('-a', '--attach', dest='attach', action='append', help='file name to upload')
add_parser.error = raise_parse_exception
add_parser.exit = suppress_exit


edit_parser = argparse.ArgumentParser(prog='edit', description='Edit a record')
edit_parser.add_argument('--login', dest='login', action='store', help='login name')
command_group = edit_parser.add_mutually_exclusive_group()
command_group.add_argument('--pass', dest='password', action='store', help='password')
command_group.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate a random password')
edit_parser.add_argument('--url', dest='url', action='store', help='url')
edit_parser.add_argument('--notes', dest='notes', action='store', help='set or replace the notes. Use a plus sign (+) in front appends to existing notes')
edit_parser.add_argument('--custom', dest='custom', action='store', help='custom fields. JSON or name:value pairs separated by comma. CSV Example: --custom "name1: value1, name2: value2". JSON Example: --custom \'{"name1":"value1", "name2":"value: 2,3,4"}\'')
edit_parser.add_argument('-t', '--title', dest='title', type=str, action='store', help='record title')
command_group = edit_parser.add_mutually_exclusive_group()
# command_group.add_argument('-v2', '--legacy', dest='legacy', action='store_true', help='work with legacy records only')
command_group.add_argument('-v3d', '--data', dest='data', action='store', help='load record type json data from string')
command_group.add_argument('-v3f', '--from-file', dest='data_file', action='store', help='load record type json data from file')
# command_group.add_argument('-o', '--option', dest='option', action='append', help='load record type data from string with dot notation')
edit_parser.add_argument('option', nargs='*', type=str, action='store', help='load record type data from strings with dot notation')
edit_parser.add_argument('-r', '--record', dest='record', required=True, type=str, action='store', help='record path or UID')
command_group = edit_parser.add_mutually_exclusive_group()
command_group.add_argument('-c', '--convert', dest='convert', action='store_true', help='convert record v2 to v3 (type: General)')
edit_parser.error = raise_parse_exception
edit_parser.exit = suppress_exit


rm_parser = argparse.ArgumentParser(prog='rm', description='Remove a record')
rm_parser.add_argument('--purge', dest='purge', action='store_true', help='remove the record from all folders and purge it from the trash')
rm_parser.add_argument('-f', '--force', dest='force', action='store_true', help='do not prompt')
rm_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
rm_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
rm_parser.error = raise_parse_exception
rm_parser.exit = suppress_exit


search_parser = argparse.ArgumentParser(prog='search|s', description='Search the vault. Can use a regular expression')
search_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
search_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
#search_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
search_parser.error = raise_parse_exception
search_parser.exit = suppress_exit


list_parser = argparse.ArgumentParser(prog='list|l', description='List all records, ordered by title')
list_parser.add_argument('pattern', nargs='?', type=str, action='store', help='search pattern')
list_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='verbose output')
#list_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
list_parser.error = raise_parse_exception
list_parser.exit = suppress_exit


get_info_parser = argparse.ArgumentParser(prog='get|g', description='Get the details of a record/folder/team by UID')
get_info_parser.add_argument('--format', dest='format', action='store', choices=['detail', 'json', 'password'], default='detail', help='output format')
get_info_parser.add_argument('uid', type=str, action='store', help='UID')
get_info_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
get_info_parser.error = raise_parse_exception
get_info_parser.exit = suppress_exit


append_parser = argparse.ArgumentParser(prog='append-notes|an', description='Append notes to an existing record')
append_parser.add_argument('--notes', dest='notes', action='store', help='notes')
append_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
append_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
append_parser.error = raise_parse_exception
append_parser.exit = suppress_exit


download_parser = argparse.ArgumentParser(prog='download-attachment', description='Download record attachments')
#download_parser.add_argument('--files', dest='files', action='store', help='file names comma separated. All files if omitted')
download_parser.add_argument('record', action='store', help='record path or UID')
#download_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
download_parser.error = raise_parse_exception
download_parser.exit = suppress_exit


upload_parser = argparse.ArgumentParser(prog='upload-attachment', description='Upload record attachments')
upload_parser.add_argument('--file', dest='file', action='append', required=True, help='file name to upload')
upload_parser.add_argument('record', action='store', help='record path or UID')
#upload_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
upload_parser.error = raise_parse_exception
upload_parser.exit = suppress_exit


delete_attachment_parser = argparse.ArgumentParser(prog='delete-attachment', description='Delete an attachment from a record', usage="Example to remove two files for a record: delete-attachment {uid} --name secrets.txt --name photo.jpg")
delete_attachment_parser.add_argument('--name', dest='name', action='append', required=True, help='attachment file name or ID. Can be repeated.')
delete_attachment_parser.add_argument('record', action='store', help='record path or UID')
#delete_attachment_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
delete_attachment_parser.error = raise_parse_exception
delete_attachment_parser.exit = suppress_exit


clipboard_copy_parser = argparse.ArgumentParser(prog='find-password|clipboard-copy', description='Retrieve the password for a specific record')
clipboard_copy_parser.add_argument('--username', dest='username', action='store', help='match login name (optional)')
clipboard_copy_parser.add_argument('--output', dest='output', choices=['clipboard', 'stdout'], default='clipboard', action='store', help='password output destination')
clipboard_copy_parser.add_argument('-l', '--login', dest='login', action='store_true', help='output login name instead of password')
clipboard_copy_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
clipboard_copy_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
clipboard_copy_parser.error = raise_parse_exception
clipboard_copy_parser.exit = suppress_exit


record_history_parser = argparse.ArgumentParser(prog='record-history|rh', description='Show the history of a record modifications')
record_history_parser.add_argument('-a', '--action', dest='action', choices=['list', 'diff', 'show', 'restore'], action='store', help='filter by record history type. (default: \'list\')')
record_history_parser.add_argument('-r', '--revision', dest='revision', type=int, action='store', help='only show the details for a specific revision')
record_history_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
#record_history_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
record_history_parser.error = raise_parse_exception
record_history_parser.exit = suppress_exit


totp_parser = argparse.ArgumentParser(prog='totp', description='Display the Two Factor Code for a record')
totp_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')
totp_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
totp_parser.error = raise_parse_exception
totp_parser.exit = suppress_exit


shared_records_report_parser = argparse.ArgumentParser(prog='shared-records-report', description='Report shared records for a logged-in user')
shared_records_report_parser.add_argument('--format', dest='format', choices=['json', 'csv', 'table'], default='table', help='Data format output')
shared_records_report_parser.add_argument('name', type=str, nargs='?', help='file name')
#shared_records_report_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
shared_records_report_parser.error = raise_parse_exception
shared_records_report_parser.exit = suppress_exit


record_type_info_parser = argparse.ArgumentParser(prog='record-type-info|rti', description='Get record type info')
record_type_info_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display extended help on record types parameters')
record_type_info_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'], default='table', help='output format')
record_type_info_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')
command_group = record_type_info_parser.add_mutually_exclusive_group()
# command_group.add_argument('-d', '--description', dest='description', action='store_true', help='generate descriptive sample JSON')
command_group.add_argument('-e', '--example', dest='example', action='store_true', help='generate example JSON')
command_group = record_type_info_parser.add_mutually_exclusive_group()
# command_group.add_argument('-lc', '--category', dest='category', action='store', default=None, const = '*', nargs='?', help='list categories or record types in a category')
command_group.add_argument('-lr', '--list-record', dest='record_name', action='store', default=None, const = '*', nargs='?', help='list record type by name or use * to list all')
command_group.add_argument('-lf', '--list-field', type=str, dest='field_name', action='store', default=None, help='list field type by name or use * to list all')
record_type_info_parser.error = raise_parse_exception
record_type_info_parser.exit = suppress_exit


record_type_parser = argparse.ArgumentParser(prog='record-type|rt', description='Add, modify or delete record type definition')
record_type_parser.add_argument('record_type_id', default=None, nargs='?', type=int, action='store', help='record Type ID to update/delete')
record_type_parser.add_argument('--data', dest='data', action='store', help='record type definition in JSON format - use rti command to see existing definitions: ex. rti -lr login')
record_type_parser.add_argument('-a', '--action', dest='action', action='store', choices=['add', 'update', 'remove'], required=True, help='record type definition - add, update or remove')
# command_group = record_type_parser.add_mutually_exclusive_group()
# command_group.add_argument('-a', '--add-type', dest='add_type', action='store_true', help='add new custom record type')
# command_group.add_argument('-u', '--update-type', dest='update_type', action='store_true', help='update existing custom record type')
# command_group.add_argument('-r', '--remove-type', dest='remove_type', action='store_true', help='delete custom record type')
record_type_parser.error = raise_parse_exception
record_type_parser.exit = suppress_exit


file_report_parser = argparse.ArgumentParser(prog='file-report', description='List records with file attachments')
file_report_parser.add_argument('-d', '--try-download', dest='try_download', action='store_true',
                                help='Try downloading every attachment you have access to')
file_report_parser.add_argument('--legacy', dest='legacy', action='store_true', help='work with legacy records only')
file_report_parser.error = raise_parse_exception
file_report_parser.exit = suppress_exit


class RecordAddCommand(Command):
    def get_parser(self):
        return add_parser

    def execute(self, params, **kwargs):
        options = kwargs.get('option') or []
        options = [] if options == [None] else options
        has_v3_options = bool(kwargs.get('data') or kwargs.get('data_file') or options)
        has_v2_options = bool(kwargs.get('legacy') or kwargs.get('title') or kwargs.get('login') or kwargs.get('password') or kwargs.get('url') or kwargs.get('notes') or kwargs.get('custom'))
        if has_v2_options and has_v3_options:
            logging.error(bcolors.FAIL + 'Use either legacy arguments only (--title, --pass, --login --url, --notes, --custom) or record type options only (type=login title=MyRecord etc.) see. https://github.com/Keeper-Security/Commander/blob/master/record-types.md' + bcolors.ENDC)
            return

        # v2 record: when --legacy flag is set or a legacy option (--title, --login, --pass, --url, --notes, --custom)
        # v2 record: when no v3 option set - neither -v3d nor -v3f is set
        # v3 record: when no --legacy flag and no legacy options (--title, --login, --pass, --url, --notes, --custom)
        # NB! v3 record needs at least one of: -v3d or -v3f or -o to be set
        is_v2 = bool(kwargs.get('legacy'))
        # 2021-06-02 Legacy/v2 record is created only with -v2|--legacy option otherwise create v3 type=login from legacy options
        # is_v2 = is_v2 or bool(kwargs.get('title') or kwargs.get('login') or kwargs.get('password') or kwargs.get('url') or kwargs.get('notes') or kwargs.get('custom'))
        # is_v2 = is_v2 or not bool(kwargs.get('data') or kwargs.get('data_file') or kwargs.get('option'))
        v3_enabled = params.settings.get('record_types_enabled') if params.settings and isinstance(params.settings.get('record_types_enabled'), bool) else False
        # if is_v2 or (has_v2_options and not v3_enabled):
        if is_v2 or (not v3_enabled and not has_v3_options):
            recordv2.RecordAddCommand().execute(params, **kwargs)
            return

        if not v3_enabled:
            logging.error(bcolors.FAIL + 'Record Types are NOT enabled for this account. Please contact your enterprise administrator.' + bcolors.ENDC)
            return

        # positional aguments can't be in a mutually exclusive groups
        if has_v3_options and options and bool(kwargs.get('data') or kwargs.get('data_file')):
            logging.error(bcolors.FAIL + 'Positional arguments [option...]: not allowed with argument -v3d/--data or -v3f/--from-file' + bcolors.ENDC)
            return

        if has_v2_options:
            options.append('type=login')
            if kwargs.get('title'):
                options.append('title='+ str(kwargs.get('title')))
                kwargs['title'] = None
            if kwargs.get('notes'):
                options.append('notes='+ str(kwargs.get('notes')))
                kwargs['notes'] = None
            if kwargs.get('login'):
                options.append('f.login='+ str(kwargs.get('login')))
                kwargs['login'] = None
            if kwargs.get('password'):
                options.append('f.password='+ str(kwargs.get('password')))
                kwargs['password'] = None
            if kwargs.get('url'):
                options.append('f.url='+ str(kwargs.get('url')))
                kwargs['url'] = None
            if kwargs.get('custom'):
                kwargs['custom_list'] = recordv3.RecordV3.custom_options_to_list(kwargs.get('custom'))
                kwargs['custom'] = None
            kwargs['option'] = options

        rt_def = ''
        if options:
            # invalid options - no '=' or empty key or value
            inv = [x for x in options if len([s for s in (x or '').split('=', 1) if s.strip() != '']) != 2]
            if inv:
                logging.error(bcolors.FAIL + 'Invalid option(s): ' + str(inv) + bcolors.ENDC)
                logging.info('Record type options must be in the following format: key1=value1 key2=value2 ...')
                return

            # check for a single valid v3 record type
            types = [x for x in options if 'type' == (x or '').split('=', 1)[0].strip().lower()]
            uniq = list({x.split('=', 1)[1].strip() for x in types if x.__contains__('=')})
            if len(uniq) != 1: # RT either missing or specified more than once
                logging.error(bcolors.FAIL + 'Please specify a valid record type: ' + str(types) + bcolors.ENDC)
                return

            rt = types[0].split('=', 1)[1].strip()
            rt_def = RecordTypeInfo().resolve_record_type_by_name(params, rt)
            if not rt_def:
                logging.error(bcolors.FAIL + 'Record type definition not found for type: ' + rt +
                    ' - to get list of all available record types use: record-type-info -lr' + bcolors.ENDC)
                return

        data_json = str(kwargs['data']).strip() if 'data' in kwargs and kwargs['data'] else None
        data_file = str(kwargs['data_file']).strip() if 'data_file' in kwargs and kwargs['data_file'] else None
        data_opts = recordv3.RecordV3.convert_options_to_json(params, '', rt_def, kwargs) if rt_def else None
        if not (data_json or data_file or data_opts):
            logging.error(bcolors.FAIL + "Please provide valid record data as a JSON string, options or file name." + bcolors.ENDC)
            self.get_parser().print_help()
            return

        data = data_json
        if data_file and not data:
            if os.path.exists(data_file) and os.path.getsize(data_file) > 0 and os.path.getsize(data_file) <= 32_000:
                with open(data_file, 'r') as file:
                    data = file.read()
        if data_opts and not data:
            if data_opts.get('warnings'):
                logging.error(bcolors.WARNING + 'Options converted to a record type with warning(s): ' + str(data_opts.get('warnings')) + bcolors.ENDC)
            if data_opts.get('errors'):
                logging.error(bcolors.FAIL + 'Error(s) converting options to a record type: ' + str(data_opts.get('errors')) + bcolors.ENDC)
                return
            if not data_opts.get('errors'):
                rec = data_opts.get('record')
                data = json.dumps(rec) if rec else ''

        data = data.strip() if data else None
        if not data:
            logging.error(bcolors.FAIL + "Empty data. Unable to insert record." + bcolors.ENDC)
            return

        data_dict = json.loads(data)
        title = data_dict['title'] if 'title' in data_dict else None
        if not title:
            logging.error(bcolors.FAIL + 'Record title is required' + bcolors.ENDC)
            return

        folder = None
        folder_name = kwargs['folder'] if 'folder' in kwargs else None
        if folder_name:
            if folder_name in params.folder_cache:
                folder = params.folder_cache[folder_name]
            else:
                src = try_resolve_path(params, folder_name)
                if src is not None:
                    folder, name = src
                    if name:
                        raise CommandError('add', 'No such folder: {0}'.format(folder_name))
                else:
                    raise CommandError('add', 'No such folder: {0}'.format(folder_name))
        if not folder:
            folder = params.folder_cache[params.current_folder] if params.current_folder else params.root_folder

        if not kwargs.get('force'):
            folder_uid = folder.uid or ''
            if folder_uid in params.subfolder_record_cache:
                for uid in params.subfolder_record_cache[folder_uid]:
                    r = api.get_record(params, uid)
                    if r.title == title:
                        raise CommandError('add', 'Record with title "{0}" already exists. Use --force to create a new record with same title.'.format(title))

        # add any attachments
        files = []
        for name in kwargs.get('attach') or []:
            file_name = os.path.abspath(os.path.expanduser(name))
            if os.path.isfile(name):
                fname = Path(name).name
                fsize = Path(file_name).stat().st_size
                if (fsize > 100 * 2**20): # hard limit at 100MB for upload
                    raise CommandError('Attachment', '{0}: file size exceeds file plan limits.'.format(file_name))

                uid = api.generate_record_uid()
                rec_uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(uid)
                file = {
                    'full_path': file_name,
                    'file_name': fname,
                    'record_key': os.urandom(32),
                    'record_uid': rec_uid,
                    'size': fsize
                }
                file_data = {
                    'name': fname,
                    'size': fsize,
                    'title': fname,
                    'lastModified': api.current_milli_time(),
                    'type': 'application/octet-stream'
                }
                file['data_unencrypted'] = file_data
                rdata = json.dumps(file_data).encode('utf-8')
                rdata = api.encrypt_aes_plain(rdata, file['record_key'])
                file['data'] = rdata
                files.append(file)
            else:
                raise CommandError('Attachment', 'File "{0}" does not exists'.format(name))

        attachments = []
        record_links = { 'record_links' : [] }
        for file in files:
            def IV_LEN(): return 12
            def GCM_TAG_LEN(): return 16
            encrypted_file_size = IV_LEN() + file['size'] + GCM_TAG_LEN() # size of the encrypted file, not original file
            record_key = api.encrypt_aes_plain(file['record_key'], params.data_key)

            rf = records.File()
            rf.record_uid = file['record_uid']
            rf.record_key = record_key
            rf.data = file['data']
            rf.fileSize = encrypted_file_size

            rq = records.FilesAddRequest()
            rq.files.append(rf)
            rq.client_time = api.current_milli_time()
            rs = api.communicate_rest(params, rq, 'vault/files_add')
            files_add_rs = records.FilesAddResponse()
            files_add_rs.ParseFromString(rs)

            for f in files_add_rs.files:
                ruid = loginv3.CommonHelperMethods.bytes_to_url_safe_str(f.record_uid)
                status = records.FileAddResult.DESCRIPTOR.values_by_number[f.status].name
                success = (f.status == records.FileAddResult.DESCRIPTOR.values_by_name['FA_SUCCESS'].number)
                url = f.url
                parameters = f.parameters
                # tp = f.thumbnail_parameters
                # stats_code = f.success_status_code

                if not success:
                    logging.error(bcolors.FAIL + 'Error: upload failed with status - %s' + bcolors.ENDC, status)
                    continue

                BUFFER_SIZE = 10240
                with tempfile.TemporaryFile(mode='w+b') as dst:
                    with open(file['full_path'], mode='rb') as src:
                        iv = os.urandom(12)
                        dst.write(iv)
                        cipher = AES.new(key=file['record_key'], mode=AES.MODE_GCM, nonce=iv)
                        byte_data = src.read(BUFFER_SIZE)
                        while len(byte_data) != 0:
                            encrypted_data = cipher.encrypt(byte_data)
                            dst.write(encrypted_data)
                            byte_data = src.read(BUFFER_SIZE)

                        tag = cipher.digest()
                        dst.write(tag)
                        dst_size = src.tell()
                    dst.seek(0)

                    form_files = { 'file': (file['file_name'], dst, 'application/octet-stream') }
                    form_params = json.loads(parameters)
                    logging.info('Uploading %s ...', file['full_path'])
                    response = requests.post(url, data=form_params, files=form_files)
                    if 'success_action_status' in form_params and str(response.status_code) == form_params['success_action_status']:
                        attachments.append(file)
                        # params.queue_audit_event('file_attachment_uploaded', record_uid=record_uid, attachment_id=a['file_id'])
                        rl = {'record_uid': file['record_uid'], 'record_key': record_key}
                        record_links['record_links'].append(rl)

        new_attachments = [loginv3.CommonHelperMethods.bytes_to_url_safe_str(a['record_uid']) for a in attachments]
        fields = data_dict['fields'] if 'fields' in data_dict else []

        # find first fileRef or create new fileRef if missing
        file_ref = next((ft for ft in fields if ft['type'] == 'fileRef'), None)
        if file_ref:
            to_remove = []
            old_atachments = file_ref.get('value') or []
            if old_atachments:
                for atta in old_atachments:
                    if atta in params.record_cache:
                        uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(params.record_cache[atta]['record_uid']) if 'record_uid' in params.record_cache[atta] else b''
                        rku = params.record_cache[atta]['record_key_unencrypted'] if 'record_key_unencrypted' in params.record_cache[atta] else b''
                        key = api.encrypt_aes_plain(rku, params.data_key)
                        if uid and rku:
                            rl = {'record_uid': uid, 'record_key': key}
                            record_links['record_links'].append(rl)
                        else:
                            to_remove.append(atta)
                    else:
                        to_remove.append(atta)
                if to_remove:
                    logging.warning('Following file references were skipped - not in record cache: %s', to_remove)
                    old_atachments = [item for item in old_atachments if item not in to_remove]

            file_ref['value'] = [*old_atachments, *new_attachments]
        else:
            file_ref = {
                'type': 'fileRef',
                'value': new_attachments
            }
            fields.append(file_ref)
            if not 'fields' in data_dict: data_dict['fields'] = fields
        data = json.dumps(data_dict)

        # For compatibility w/ legacy: --password overides --generate AND --generate overrides dataJSON/option
        # dataJSON/option < kwargs: --generate < kwargs: --password
        password = kwargs.get('password')
        if not password and kwargs.get('generate'):
            password = generator.generate(16)
        if password:
            data = recordv3.RecordV3.update_password(password, data, recordv3.RecordV3.get_record_type_definition(params, data))

        record_key = os.urandom(32)
        record_uid = api.generate_record_uid()
        logging.debug('Generated Record UID: %s', record_uid)
        record = {
            'record_uid': record_uid,
            'record_key_unencrypted': record_key,
            'client_modified_time': api.current_milli_time(),
            'data_unencrypted': data
        }

        rq = {'command': 'record_add','record_uid': record_uid,'record_type': 'password','how_long_ago': 0 }
        if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            rq['folder_uid'] = folder.uid
            rq['folder_type'] = 'shared_folder' if folder.type == BaseFolderNode.SharedFolderType else 'shared_folder_folder'

            sh_uid = folder.uid if folder.type == BaseFolderNode.SharedFolderType else folder.shared_folder_uid
            sf = params.shared_folder_cache[sh_uid]
            rq['folder_key'] = api.encrypt_aes_plain(record_key, sf['shared_folder_key_unencrypted'])
            if 'key_type' not in sf:
                if 'teams' in sf:
                    for team in sf['teams']:
                        rq['team_uid'] = team['team_uid']
                        if team['manage_records']:
                            break
        else:
            rq['folder_type'] = 'user_folder'
            if folder.type != BaseFolderNode.RootFolderType:
                rq['folder_uid'] = folder.uid

        params.sync_data = True
        res = api.add_record_v3(params, record, **{'record_links': record_links, 'rq': rq})
        if res:
            params.environment_variables[LAST_RECORD_UID] = record_uid
            return record_uid


class RecordEditCommand(Command):
    def get_parser(self):
        return edit_parser

    def execute(self, params, **kwargs):
        name = kwargs['record'] if 'record' in kwargs else None
        if not name:
            self.get_parser().print_help()
            return

        record_uid = None
        if name in params.record_cache:
            record_uid = name
        else:
            rs = try_resolve_path(params, name)
            if rs is not None:
                folder, name = rs
                if folder is not None and name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.lower() == name.lower():
                                record_uid = uid
                                break

        if record_uid is None:
            raise CommandError('edit', 'Enter name or uid of existing record')

        rt_name = ''
        options = kwargs.get('option') or []
        options = [] if options == [None] else options
        rv = params.record_cache[record_uid].get('version') if params.record_cache and record_uid in params.record_cache else None
        if rv > 2:
            # convert any v2 options into corresponding v3 options for v3 type=login|general
            rt_data = params.record_cache[record_uid].get('data_unencrypted')
            rt_name = recordv3.RecordV3.get_record_type_name(rt_data)
            if rt_name in ("login", "general"):
                errors = self.convert_legacy_options(kwargs=kwargs)
                if errors:
                    logging.error(bcolors.FAIL + 'Conflict between record type and legacy options: ' + errors + bcolors.ENDC)
                    return
                options = kwargs.get('option') or options

        has_v3_options = bool(kwargs.get('data') or kwargs.get('data_file') or options)
        has_v2_options = bool(kwargs.get('legacy') or kwargs.get('title') or kwargs.get('login') or kwargs.get('password') or kwargs.get('url') or kwargs.get('notes') or kwargs.get('custom'))
        if has_v2_options and has_v3_options:
            logging.error(bcolors.FAIL + 'Use either legacy arguments only (--pass, --login --url, --notes, --custom) or record type options only (type=login title=MyRecord etc.) see. https://github.com/Keeper-Security/Commander/blob/master/record-types.md' + bcolors.ENDC)
            return

        # v2 record: when --legacy flag is set or a legacy option (--login, --pass, --url, --notes, --custom)
        # v2 record: when no v3 option set - neither -v3d nor -v3f is set
        # v3 record: when no --legacy flag and no legacy options (--title, --login, --pass, --url, --notes, --custom)
        # NB! v3 record needs at least one of: -v3d or -v3f or -o to be set
        is_v2 = bool(kwargs.get('legacy'))
        # 2021-06-02 Legacy/v2 record is created only with -v2|--legacy option otherwise create v3 type=login from legacy options
        # is_v2 = is_v2 or bool(kwargs.get('title') or kwargs.get('login') or kwargs.get('password') or kwargs.get('url') or kwargs.get('notes') or kwargs.get('custom'))
        # is_v2 = is_v2 or not bool(kwargs.get('data') or kwargs.get('data_file') or kwargs.get('option') or kwargs.get('generate'))
        # 2021-06-08 --legacy option is ignored - use record version and v3_enabled flag
        v3_enabled = params.settings.get('record_types_enabled') if params.settings and isinstance(params.settings.get('record_types_enabled'), bool) else False
        if is_v2:
            if rv and rv in (3, 4):
                if v3_enabled:
                    logging.error('Record %s is version 3 already. Please use version 3 editing options (--data, --from-file, option)', record_uid)
                else:
                    logging.error(bcolors.FAIL + 'Record Types are NOT enabled for this account. Please contact your enterprise administrator.' + bcolors.ENDC)
            else:
                recordv2.RecordEditCommand().execute(params, **kwargs)
            return

        #if has_v2_options and not has_v3_options and not v3_enabled:
        if has_v2_options:
            if rv in (3, 4):
                if v3_enabled:
                    logging.error('Record %s is version 3 already. Please use version 3 editing options (--data, --from-file, option)', record_uid)
                else:
                    logging.error(bcolors.FAIL + 'Record Types are NOT enabled for this account. Please contact your enterprise administrator.' + bcolors.ENDC)
            else:
                recordv2.RecordEditCommand().execute(params, **kwargs)
            return

        recordv3.RecordV3.validate_access(params, record_uid)
        convert = bool(kwargs.get('convert'))
        if convert:
            if recordv3.RecordV3.convert_to_record_type(record_uid, params=params):
                record = api.get_record(params, record_uid)
                params.sync_data = True
                api.update_record(params, record)
            else:
                logging.error('Conversion failed for record: %s', record_uid)
            return

        # positional aguments can't be in a mutually exclusive groups
        if has_v3_options and options and bool(kwargs.get('data') or kwargs.get('data_file')):
            logging.error(bcolors.FAIL + 'Positional arguments [option...]: not allowed with argument -v3d/--data or -v3f/--from-file' + bcolors.ENDC)
            return

        # Mixing v2 and v3 options not allowed for `edit` command
        # v2 to v3 conversion will fail if v3 record is NOT type=login
        # if has_v2_options:
        #     options.append('type=login')
        #     if kwargs.get('title'):
        #         options.append('title='+ str(kwargs.get('title')))
        #         kwargs['title'] = None
        #     if kwargs.get('notes'):
        #         options.append('notes='+ str(kwargs.get('notes')))
        #         kwargs['notes'] = None
        #     if kwargs.get('login'):
        #         options.append('f.login='+ str(kwargs.get('login')))
        #         kwargs['login'] = None
        #     if kwargs.get('password'):
        #         options.append('f.password='+ str(kwargs.get('password')))
        #         kwargs['password'] = None
        #     if kwargs.get('url'):
        #         options.append('f.url='+ str(kwargs.get('url')))
        #         kwargs['url'] = None
        #     if kwargs.get('custom'):
        #         kwargs['custom_list'] = recordv3.RecordV3.custom_options_to_list(kwargs.get('custom'))
        #         kwargs['custom'] = None
        #     kwargs['option'] = options

        record = api.get_record(params, record_uid)
        record_data = None
        if params and params.record_cache and record_uid in params.record_cache:
            if rv == 3:
                record_data = params.record_cache[record_uid]['data_unencrypted']
            else:
                raise CommandError('edit', 'Record UID "{0}" is not version 3. Use legacy options (--title --pass etc.)'.format(record_uid))
        record_data = record_data.decode('utf-8') if record_data and isinstance(record_data, bytes) else record_data
        record_data = record_data.strip() if record_data else ''
        rdata_dict = json.loads(record_data or '{}')

        rt_def = RecordTypeInfo().resolve_record_type_by_name(params, rt_name) or ''
        if options:
            # invalid options - no '=' NB! edit allows empty value(s) to be able to delete
            # inv = [x for x in options if len([s for s in (x or '').split('=', 1) if s.strip() != '']) != 2]
            inv = [x for x in options if not str(x).__contains__('=')]
            if inv:
                logging.error(bcolors.FAIL + 'Invalid option(s): ' + str(inv) + bcolors.ENDC)
                logging.info('Record type options must be in the following format: -o key1=value1 -o key2= ...')
                return

            # check for a single valid v3 record type
            types = [x for x in options if (x or '').split('=', 1)[0].strip().lower() == 'type']
            uniq = list({x.split('=', 1)[1].strip() for x in types if x.__contains__('=')})
            if uniq and len(uniq) == 1 and uniq[0] == '':
                logging.error(bcolors.FAIL + 'Cannot delete the type: "-o type=" is not a valid option.' + bcolors.ENDC)
                return
            if not uniq:
                rtype = rdata_dict.get('type')
                if rtype:
                    types.append('type=' + rtype)
                    uniq.append(rtype)
            if len(uniq) > 1: # RT specified more than once
                logging.error(bcolors.FAIL + 'Please specify a valid record type: ' + str(types) + bcolors.ENDC)
                return

            rt = types[0].split('=', 1)[1].strip()
            rt_def = RecordTypeInfo().resolve_record_type_by_name(params, rt)
            if not rt_def:
                logging.error(bcolors.FAIL + 'Record type definition not found for type: ' + rt +
                    ' - to get list of all available record types use: record-type-info -lr' + bcolors.ENDC)
                return

        data_json = str(kwargs['data']).strip() if 'data' in kwargs and kwargs['data'] else None
        data_file = str(kwargs['data_file']).strip() if 'data_file' in kwargs and kwargs['data_file'] else None
        data_opts = recordv3.RecordV3.convert_options_to_json(params, record_data, rt_def, kwargs) if rt_def else None
        if not (data_json or data_file or data_opts or kwargs.get('generate')):
            logging.error(bcolors.FAIL + "Please provide valid record data as a JSON string, options or file name." + bcolors.ENDC)
            self.get_parser().print_help()
            return

        data = data_json
        if data_file and not data:
            if os.path.exists(data_file) and os.path.getsize(data_file) > 0 and os.path.getsize(data_file) <= 32_000:
                with open(data_file, 'r') as file:
                    data = file.read()
        if data_opts and not data:
            if data_opts.get('warnings'):
                logging.error(bcolors.WARNING + 'Options converted to a record type with warning(s): ' + str(data_opts.get('warnings')) + bcolors.ENDC)
            if data_opts.get('errors'):
                logging.error(bcolors.FAIL + 'Error(s) converting options to a record type: ' + str(data_opts.get('errors')) + bcolors.ENDC)
                return
            if not data_opts.get('errors'):
                rec = data_opts.get('record')
                data = json.dumps(rec) if rec else ''
        if kwargs.get('generate') and not data:
            data = record_data

        data = data.strip() if data else None
        if not data:
            logging.error(bcolors.FAIL + "Empty data. Unable to update record." + bcolors.ENDC)
            return

        # For compatibility w/ legacy: --password overides --generate AND --generate overrides dataJSON/option
        # dataJSON/option < kwargs: --generate < kwargs: --password
        password = kwargs.get('password')
        if not password and kwargs.get('generate'):
            password = generator.generate(16)
        if password:
            record.password = password
            data = recordv3.RecordV3.update_password(password, data, recordv3.RecordV3.get_record_type_definition(params, data))

        data_dict = json.loads(data)
        changed = rdata_dict != data_dict
        # changed = json.dumps(rdata_dict, sort_keys=True) != json.dumps(data_dict, sort_keys=True)
        if changed:
            params.record_cache[record_uid]['data_unencrypted'] = json.dumps(data_dict)
            params.sync_data = True
            api.update_record_v3(params, record, **kwargs)

            newpass = recordv3.RecordV3.get_record_password(data) or ''
            oldpass = recordv3.RecordV3.get_record_password(record_data) or ''
            if newpass != oldpass:
                params.queue_audit_event('record_password_change', record_uid=record.record_uid)

    def convert_legacy_options(self, kwargs):
        options = kwargs.get('option') or []
        options = [] if options == [None] else options
        errors = ''
        lopt = [
            { 'option': '--title', 'dest': 'title', 'is_field': False },
            { 'option': '--notes', 'dest': 'notes', 'is_field': False },
            { 'option': '--login', 'dest': 'login', 'is_field': True },
            { 'option': '--pass', 'dest': 'password', 'is_field': True },
            { 'option': '--url', 'dest': 'url', 'is_field': True }
        ]

        for x in lopt:
            option = x.get('option')
            dest = x.get('dest')
            oval = kwargs.get(dest)
            if oval:
                pattern = '(f|fields)\\.{0}='.format(dest) if x.get('is_field') else '{}='.format(dest)
                dupes = [x for x in options if re.match(pattern, str(x), re.IGNORECASE)]
                if dupes:
                    errors += '\n  option {} conflicts with {}={}'.format(dupes[0], option, str(oval))
                else:
                    kvp = '{}{}={}'.format('f.' if x.get('is_field') else '', dest, str(oval))
                    options.append(kvp)
                    kwargs[dest] = None

        copt = kwargs.get('custom')
        if copt:
            clst = recordv3.RecordV3.custom_options_to_list(copt)

            # any custom.text field conflicts with any legacy --custom option text fields
            # ex. c.text.label=abc c.text=abc will overwrite first legacy --custom text field
            # err = [(x, 'c.text.label='+x.get('name')) for x in clst if any([y for y in options if y.startswith('c.text.label='+x.get('name'))])]
            ctxt = [y for y in options if re.search(r'(?:c|custom)\.text(?:=|\.label=)', y, re.IGNORECASE)]
            if ctxt:
                errors += 'Conflicting legacy/v2 and v3 options: --custom {} and {}'.format(copt, ctxt)

            kwargs['custom_list'] = clst
            kwargs['custom'] = None

        if not errors:
            kwargs['option'] = options

        return errors


class RecordAppendNotesCommand(Command):
    def get_parser(self):
        return append_parser

    def execute(self, params, **kwargs):
        notes = kwargs['notes'] if 'notes' in kwargs else None
        while not notes:
            notes = input("... Notes to append: ")

        edit_command = RecordEditCommand()
        kwargs['notes'] = '+' + notes
        edit_command.execute(params, **kwargs)


class RecordRemoveCommand(Command):
    def get_parser(self):
        return rm_parser

    def execute(self, params, **kwargs):
        is_v2 = bool(kwargs.get('legacy'))
        if is_v2:
            recordv2.RecordRemoveCommand().execute(params, **kwargs)
            return

        folder = None
        name = None
        record_path = kwargs['record'] if 'record' in kwargs else None
        if record_path:
            rs = try_resolve_path(params, record_path)
            if rs is not None:
                folder, name = rs

        if folder is None or name is None:
            logging.warning('Enter name of existing record')
            return

        record_uid = None
        if name in params.record_cache:
            record_uid = name
            folders = list(find_folders(params, record_uid))
            if len(folders) > 0:
                folder = params.folder_cache[folders[0]] if len(folders[0]) > 0 else params.root_folder
        else:
            folder_uid = folder.uid or ''
            if folder_uid in params.subfolder_record_cache:
                for uid in params.subfolder_record_cache[folder_uid]:
                    r = api.get_record(params, uid)
                    if r.title.lower() == name.lower():
                        record_uid = uid
                        break

        if record_uid is None:
            raise CommandError('rm', 'Enter name of existing record')

        rv = params.record_cache[record_uid].get('version') if params.record_cache and record_uid in params.record_cache else None
        if rv in (3, 4):
            recordv3.RecordV3.validate_access(params, record_uid)
        else:
            recordv2.RecordRemoveCommand().execute(params, **kwargs)
            return


        if kwargs.get('purge'):
            is_owner = False
            if record_uid in params.meta_data_cache:
                md = params.meta_data_cache[record_uid]
                is_owner = md.get('owner') or False
            if not is_owner:
                logging.warning('Record purge error: Not an owner')
                return

            rq = {
                'command': 'record_update',
                'pt': 'Commander',
                'device_id': 'Commander',
                'client_time': api.current_milli_time(),
                'delete_records': [record_uid]
            }
            if not kwargs.get('force'):
                answer = user_choice('Do you want to proceed with record purge?', 'yn', default='n')
                if answer.lower() != 'y':
                    return
            rs = api.communicate(params, rq)
            if 'delete_records' in rs:
                for status in rs['delete_records']:
                    if status['status'] != 'success':
                        logging.warning('Record purge error: %s', status.get('status'))
        else:
            del_obj = {
                'delete_resolution': 'unlink',
                'object_uid': record_uid,
                'object_type': 'record'
            }
            if folder.type in {BaseFolderNode.RootFolderType, BaseFolderNode.UserFolderType}:
                del_obj['from_type'] = 'user_folder'
                if folder.type == BaseFolderNode.UserFolderType:
                    del_obj['from_uid'] = folder.uid
            else:
                del_obj['from_type'] = 'shared_folder_folder'
                del_obj['from_uid'] = folder.uid

            rq = {
                'command': 'pre_delete',
                'objects': [del_obj]
            }

            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                pdr = rs['pre_delete_response']

                force = kwargs['force'] if 'force' in kwargs else None
                np = 'y'
                if not force:
                    summary = pdr['would_delete']['deletion_summary']
                    for x in summary:
                        print(x)
                    np = user_choice('Do you want to proceed with deletion?', 'yn', default='n')
                if np.lower() == 'y':
                    rq = {
                        'command': 'delete',
                        'pre_delete_token': pdr['pre_delete_token']
                    }
                    api.communicate(params, rq)
                    params.sync_data = True


class SearchCommand(Command):
    def get_parser(self):
        return search_parser

    def execute(self, params, **kwargs):
        recordv2.SearchCommand().execute(params, **kwargs)


class RecordListCommand(Command):
    def get_parser(self):
        return list_parser

    def execute(self, params, **kwargs):
        recordv2.RecordListCommand().execute(params, **kwargs)


class RecordListSfCommand(Command):
    def execute(self, params, **kwargs):
        recordv2.RecordListSfCommand().execute(params, **kwargs)


class RecordListTeamCommand(Command):
    def execute(self, params, **kwargs):
        recordv2.RecordListTeamCommand().execute(params, **kwargs)


class RecordDownloadAttachmentCommand(Command):
    def get_parser(self):
        return download_parser

    def execute(self, params, **kwargs):
        name = kwargs['record'] if 'record' in kwargs else None

        if not name:
            self.get_parser().print_help()
            return

        record_uid = None
        record_version = None
        if name in params.record_cache:
            record_uid = name
            record_version = params.record_cache[record_uid]['version'] if 'version' in params.record_cache[record_uid] else None
        else:
            rs = try_resolve_path(params, name)
            if rs is not None:
                folder, name = rs
                if folder is not None and name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.lower() == name.lower():
                                record_uid = uid
                                record_version = params.record_cache[record_uid]['version'] if 'version' in params.record_cache[record_uid] else None
                                break

        if not record_uid:
            logging.error('Record UID not found for record name "%s"', str(name))
            return
        if not record_version:
            logging.error('Record Version not found for record "%s"', str(name))
            return

        # is_v2 = bool(kwargs.get('legacy'))
        is_v2 = not record_version or record_version < 3
        if is_v2:
            recordv2.RecordDownloadAttachmentCommand().execute(params, **kwargs)
            return

        recordv3.RecordV3.validate_access(params, record_uid)
        if record_version != 3:
            logging.error('Record is not a record type (version 3) - UID: %s', str(record_uid))
            return

        if params.sync_data:
            api.sync_down(params)

        record_uids = []
        r = params.record_cache[record_uid]
        data = json.loads(r['data_unencrypted']) if 'data_unencrypted' in r else {}

        fields = data['fields'] if 'fields' in data else []
        for fr in (ft for ft in fields if ft['type'] == 'fileRef'):
            if fr and 'value' in fr:
                record_uids.extend(fr['value'])

        fields = data['custom'] if 'custom' in data else []
        for fr in (ft for ft in fields if ft['type'] == 'fileRef'):
            if fr and 'value' in fr:
                record_uids.extend(fr['value'])

        if not record_uids:
            raise CommandError('download-attachment', 'No attachments associated with the record')

        #api.resolve_record_access_path(params, record_uid, path=rq)
        record_uids = [loginv3.CommonHelperMethods.url_safe_str_to_bytes(i) if type(i) == str else i for i in record_uids]
        rq = records.FilesGetRequest()
        rq.record_uids.extend(record_uids)
        rq.for_thumbnails = False
        # rq.emergency_access_account_owner = ''
        rs = api.communicate_rest(params, rq, 'vault/files_download')
        files_get_rs = records.FilesGetResponse()
        files_get_rs.ParseFromString(rs)
        for f in files_get_rs.files:
            ruid = loginv3.CommonHelperMethods.bytes_to_url_safe_str(f.record_uid)
            status = records.FileGetResult.DESCRIPTOR.values_by_number[f.status].name
            success = (f.status == records.FileGetResult.DESCRIPTOR.values_by_name['FG_SUCCESS'].number)
            url = f.url
            stats_code = f.success_status_code

            if not success:
                #raise CommandError('download-attachment', 'FileRef "{0}": Failed to get file download data'.format(ruid))
                logging.info('download-attachment - FileRef "%s": Failed to get file download data', ruid)
                continue
            if not (url and url.strip()):
                #raise CommandError('download-attachment', 'FileRef "{0}": Failed to get file download URL'.format(ruid))
                logging.info('download-attachment - FileRef "%s": Failed to get file download URL', ruid)
                continue

            file_key = None
            file_name = None
            file_size = 0
            file_data = {}
            if ruid in params.record_cache:
                rdata = params.record_cache[ruid]['data'] if 'data' in params.record_cache[ruid] else ''
                rkey = params.record_cache[ruid]['record_key_unencrypted'] if 'record_key_unencrypted' in params.record_cache[ruid] else ''
                decoded_data = base64.urlsafe_b64decode(rdata + '==')
                data_unencrytped = api.decrypt_aes_plain(decoded_data, rkey)
                data_dict = json.loads(data_unencrytped)
                file_data = file_data | data_dict
                file_data['record_uid'] = ruid
                file_data['record_key'] = params.record_cache[ruid]['record_key_unencrypted']
                file_name = file_data.get('name') or file_data.get('title') # or file_data.get('record_uid')
                file_key = file_data.get('record_key')
                file_size = file_data.get('size') if file_data.get('size') else 0

            if not file_key:
                # raise CommandError('download-attachment', 'File "{0}": Failed to file encryption key'.format(file_name))
                logging.info('download-attachment - FileRef "%s": Failed to get file encryption key', ruid)
                continue

            BUFFER_SIZE = 10240
            rq_http = requests.get(url, stream=True)
            with open(file_name, 'wb') as f:
                logging.info('Downloading \'%s\'', os.path.abspath(f.name))
                iv = rq_http.raw.read(12)
                content_byte_count = 0
                tag = bytearray(b'')
                cipher = AES.new(file_key, AES.MODE_GCM, iv)
                data = rq_http.raw.read(BUFFER_SIZE)
                while len(data) != 0:
                    n = content_byte_count + len(data) - file_size
                    content_byte_count = (content_byte_count + len(data)) if n <= 0 else file_size
                    if n > 0:
                        tag.extend(data[-n:])
                        data = data[:-n]
                    decrypted_data = cipher.decrypt(data)
                    f.write(decrypted_data)
                    data = rq_http.raw.read(BUFFER_SIZE)
                dst_size = f.tell()
                assert (dst_size == file_size), "Files sizes don't match"
                cipher.verify(tag)


class RecordUploadAttachmentCommand(Command):
    def get_parser(self):
        return upload_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None

        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = None
        record_version = None
        if record_name in params.record_cache:
            record_uid = record_name
            record_version = params.record_cache[record_uid]['version'] if 'version' in params.record_cache[record_uid] else None
        else:
            rs = try_resolve_path(params, record_name)
            if rs is not None:
                folder, record_name = rs
                if folder is not None and record_name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.lower() == record_name.lower():
                                record_uid = uid
                                record_version = params.record_cache[record_uid]['version'] if 'version' in params.record_cache[record_uid] else None
                                break

        if not record_uid:
            logging.error('Record UID not found for record "%s"', str(record_name))
            return
        if not record_version:
            logging.error('Record Version not found for record "%s"', str(record_name))
            return

        # is_v2 = bool(kwargs.get('legacy'))
        is_v2 = not record_version or record_version < 3
        if is_v2:
            recordv2.RecordUploadAttachmentCommand().execute(params, **kwargs)
            return

        recordv3.RecordV3.validate_access(params, record_uid)
        if record_version != 3:
            logging.error('Record is not a record type (version 3) - UID: %s', str(record_uid))
            return

        if params.sync_data:
            api.sync_down(params)

        record_update = api.resolve_record_write_path(params, record_uid)
        if record_update is None:
            raise CommandError('upload-attachment', 'You do not have edit permissions on this record')

        files = []
        if 'file' in kwargs:
            for name in kwargs['file']:
                file_name = os.path.abspath(os.path.expanduser(name))
                if os.path.isfile(name):
                    fname = Path(name).name
                    fsize = Path(file_name).stat().st_size
                    # Hard limit at 100MB for upload
                    if (fsize > 100 * 2**20):
                        raise CommandError('upload-attachment', '{0}: file size exceeds file plan limits'.format(file_name))

                    uid = api.generate_record_uid()
                    rec_uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(uid)
                    file = {
                        'full_path': file_name,
                        'file_name': fname,
                        'record_key': os.urandom(32),
                        'record_uid': rec_uid,
                        'size': fsize
                    }
                    data = {
                        'name': fname,
                        'size': fsize,
                        'title': fname,  # should this also be the name?
                        'lastModified': api.current_milli_time(),
                        'type': 'application/octet-stream'
                    }
                    file['data_unencrypted'] = data
                    rdata = json.dumps(data).encode('utf-8')
                    rdata = api.encrypt_aes_plain(rdata, file['record_key'])
                    file['data'] = rdata
                    files.append(file)
                else:
                    raise CommandError('upload-attachment', 'File "{0}" does not exists'.format(name))
        if len(files) == 0:
            raise CommandError('upload-attachment', 'No files to upload')

        attachments = []
        record_links = { 'record_links_add' : [] }
        for file in files:
            def IV_LEN(): return 12
            def GCM_TAG_LEN(): return 16
            encrypted_file_size = IV_LEN() + file['size'] + GCM_TAG_LEN() # size of the encrypted file, not original file
            record_key = api.encrypt_aes_plain(file['record_key'], params.data_key)

            rf = records.File()
            rf.record_uid = file['record_uid']
            rf.record_key = record_key
            rf.data = file['data']
            rf.fileSize = encrypted_file_size

            rq = records.FilesAddRequest()
            rq.files.append(rf)
            rq.client_time = api.current_milli_time()
            rs = api.communicate_rest(params, rq, 'vault/files_add')
            files_add_rs = records.FilesAddResponse()
            files_add_rs.ParseFromString(rs)

            for f in files_add_rs.files:
                ruid = loginv3.CommonHelperMethods.bytes_to_url_safe_str(f.record_uid)
                status = records.FileAddResult.DESCRIPTOR.values_by_number[f.status].name
                success = (f.status == records.FileAddResult.DESCRIPTOR.values_by_name['FA_SUCCESS'].number)
                url = f.url
                parameters = f.parameters
                tp = f.thumbnail_parameters
                stats_code = f.success_status_code

                if not success:
                    logging.error(bcolors.FAIL + 'Error: upload failed with status - %s' + bcolors.ENDC, status)
                    continue

                BUFFER_SIZE = 10240
                with tempfile.TemporaryFile(mode='w+b') as dst:
                    with open(file['full_path'], mode='rb') as src:
                        iv = os.urandom(12)
                        dst.write(iv)
                        cipher = AES.new(key=file['record_key'], mode=AES.MODE_GCM, nonce=iv)
                        data = src.read(BUFFER_SIZE)
                        while len(data) != 0:
                            encrypted_data = cipher.encrypt(data)
                            dst.write(encrypted_data)
                            data = src.read(BUFFER_SIZE)

                        tag = cipher.digest()
                        dst.write(tag)
                        dst_size = src.tell()
                    dst.seek(0)

                    form_files = { 'file': (file['file_name'], dst, 'application/octet-stream') }
                    form_params = json.loads(parameters)
                    logging.info('Uploading %s ...', file['full_path'])
                    response = requests.post(url, data=form_params, files=form_files)
                    if 'success_action_status' in form_params and str(response.status_code) == form_params['success_action_status']:
                        attachments.append(file)
                        # params.queue_audit_event('file_attachment_uploaded', record_uid=record_uid, attachment_id=a['file_id'])
                        rl = {'record_uid': file['record_uid'], 'record_key': record_key}
                        record_links['record_links_add'].append(rl)

        new_attachments = [loginv3.CommonHelperMethods.bytes_to_url_safe_str(a['record_uid']) for a in attachments]
        if (new_attachments and record_uid in params.record_cache):
            changed = False
            record = params.record_cache[record_uid]
            data = json.loads(record['data_unencrypted']) if 'data_unencrypted' in record else {}
            fields = data['fields'] if 'fields' in data else []

            # find first fileRef or create new fileRef if missing
            file_ref = next((ft for ft in fields if ft['type'] == 'fileRef'), None)
            if file_ref:
                old_atachments = file_ref['value'] if 'value' in file_ref else []
                file_ref['value'] = [*old_atachments, *new_attachments]
            else:
                file_ref = {
                    'type': 'fileRef',
                    'value': new_attachments
                }
                fields.append(file_ref)
                if not 'fields' in data: data['fields'] = fields

            record_data = record['data_unencrypted'] if 'data_unencrypted' in record else ''
            record_data = record_data.decode('utf-8') if record_data and isinstance(record_data, bytes) else record_data
            new_data = json.dumps(data)
            if record_data and record_data != new_data:
                params.record_cache[record_uid]['data_unencrypted'] = new_data
                changed = True
            if changed:
                params.sync_data = True
                rec = api.get_record(params, record_uid)
                # api.resolve_record_access_path(params, record_uid, path=record_update)
                api.update_record_v3(params, rec, **{'record_links': record_links})


class RecordDeleteAttachmentCommand(Command):
    def get_parser(self):
        return delete_attachment_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None

        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = None
        record_version = None
        if record_name in params.record_cache:
            record_uid = record_name
            record_version = params.record_cache[record_uid]['version'] if 'version' in params.record_cache[record_uid] else None
        else:
            rs = try_resolve_path(params, record_name)
            if rs is not None:
                folder, record_name = rs
                if folder is not None and record_name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.lower() == record_name.lower():
                                record_uid = uid
                                record_version = params.record_cache[record_uid]['version'] if 'version' in params.record_cache[record_uid] else None
                                break

        if not record_uid:
            logging.error('Record UID not found for record "%s"', str(record_name))
            return
        if not record_version:
            logging.error('Record Version not found for record "%s"', str(record_name))
            return

        # is_v2 = bool(kwargs.get('legacy'))
        is_v2 = not record_version or record_version < 3
        if is_v2:
            recordv2.RecordDeleteAttachmentCommand().execute(params, **kwargs)
            return

        recordv3.RecordV3.validate_access(params, record_uid)
        if record_version != 3:
            logging.error('Record is not a record type (version 3) - UID: %s', str(record_uid))
            return

        record = api.get_record(params, record_uid)

        # using file names is too risky, duplicate names allowed - switched to fileRef UIDs only
        names = kwargs['name'] if 'name' in kwargs else None
        if names is None:
            raise CommandError('delete-attachment', 'No file reference UID specified')

        record_update = api.resolve_record_write_path(params, record_uid)
        if record_update is None:
            raise CommandError('delete-attachment', 'You do not have edit permissions on this record')

        rec = params.record_cache[record_uid]
        data = json.loads(rec['data_unencrypted']) if 'data_unencrypted' in rec else {}
        all_fields = data.get('fields') or []
        all_fields.extend(data.get('custom') or [])
        file_ids = [n.get('value') for n in all_fields if n.get('type') == 'fileRef' and n.get('value')]
        file_ids = sum(file_ids, [])

        names = set(names) # remove duplicates
        to_remove = set(file_ids) & names
        if names and len(names) > len(to_remove):
            logging.warning('Found only %s files to remove from %s selected.', len(to_remove), len(names))
            logging.warning('Warning! Record Type V3 requires file reference UID that belongs to the record UID.')
        if not to_remove:
            return

        record_links = { 'record_links_remove' : [{'record_uid': loginv3.CommonHelperMethods.url_safe_str_to_bytes(uid), 'record_key': None} for uid in to_remove] }
        for file_uid in to_remove:
            file_ref = [ft for ft in all_fields if ft.get('type') == 'fileRef' and file_uid in (ft.get('value') or [])]
            for fr in file_ref:
                values = fr.get('value') or []
                while file_uid in values: values.remove(file_uid)

            params.queue_audit_event('file_attachment_deleted', record_uid=record_uid, attachment_id=file_uid)

        rec['data_unencrypted'] = json.dumps(data)
        params.sync_data = True
        # api.resolve_record_access_path(params, record_uid, path=record_update)
        api.update_record_v3(params, record, **{'record_links': record_links})


class ClipboardCommand(Command):
    def get_parser(self):
        return clipboard_copy_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None

        if not record_name:
            self.get_parser().print_help()
            return

        user_pattern = None
        if kwargs['username']:
            user_pattern = re.compile(kwargs['username'], re.IGNORECASE)

        record_uid = None
        if record_name in params.record_cache:
            record_uid = record_name
        else:
            rs = try_resolve_path(params, record_name)
            if rs is not None:
                folder, record_name = rs
                if folder is not None and record_name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.lower() == record_name.lower():
                                if user_pattern:
                                    if not user_pattern.match(r.login):
                                        continue
                                record_uid = uid
                                break

        if record_uid is None:
            records = api.search_records(params, kwargs['record'])
            if user_pattern:
                records = [x for x in records if user_pattern.match(x.login)]
            if len(records) == 1:
                if kwargs['output'] == 'clipboard':
                    logging.info('Record Title: {0}'.format(records[0].title))
                record_uid = records[0].record_uid
            else:
                if len(records) == 0:
                    raise CommandError('clipboard-copy', 'Enter name or uid of existing record')
                else:
                    raise CommandError('clipboard-copy', 'More than one record are found for search criteria: {0}'.format(kwargs['record']))

        recordv3.RecordV3.validate_access(params, record_uid)
        rec = api.get_record(params, record_uid)
        txt = rec.login if kwargs.get('login') else rec.password
        if txt:
            if kwargs['output'] == 'clipboard':
                import pyperclip
                pyperclip.copy(txt)
                logging.info('Copied to clipboard')
            else:
                print(txt)
            if not kwargs.get('login'):
                params.queue_audit_event('copy_password', record_uid=record_uid)


class RecordHistoryCommand(Command):
    def get_parser(self):
        return record_history_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None
        if not record_name:
            self.get_parser().print_help()
            return

        record_uid = None
        if record_name in params.record_cache:
            record_uid = record_name
        else:
            rs = try_resolve_path(params, record_name)
            if rs is not None:
                folder, record_name = rs
                if folder is not None and record_name is not None:
                    folder_uid = folder.uid or ''
                    if folder_uid in params.subfolder_record_cache:
                        for uid in params.subfolder_record_cache[folder_uid]:
                            r = api.get_record(params, uid)
                            if r.title.lower() == record_name.lower():
                                record_uid = uid
                                break

        if record_uid is None:
            raise CommandError('history', 'Enter name or uid of existing record')

        current_rec = params.record_cache[record_uid]
        if record_uid in params.record_history:
            _,revision = params.record_history[record_uid]
            if revision < current_rec['revision']:
                del params.record_history[record_uid]
        if record_uid not in params.record_history:
            rq = {
                'command': 'get_record_history',
                'record_uid': record_uid,
                'client_time': api.current_milli_time
            }
            rs = api.communicate(params, rq)
            params.record_history[record_uid] = (rs['history'], current_rec['revision'])

        if record_uid in params.record_history:
            action = kwargs.get('action') or 'list'
            history,_ = params.record_history[record_uid]
            history.sort(key=lambda x: x['revision'])
            history.reverse()
            length = len(history)
            if length == 0:
                logging.info('Record does not have history of edit')
                return

            if 'revision' in kwargs and kwargs['revision'] is not None:
                revision = kwargs['revision']
                if revision < 1 or revision > length+1:
                    logging.error('Invalid revision {0}: valid revisions [1..{1}]'.format(revision, length + 1))
                    return
                if not kwargs.get('action'):
                    action = 'show'
            else:
                revision = 0

            if action == 'list':
                headers = ['Version', 'Modified By', 'Time Modified']
                rows = []
                for i, revision in enumerate(history):
                    if 'client_modified_time' in revision:
                        dt = datetime.datetime.fromtimestamp(revision['client_modified_time']/1000.0)
                        tm = dt.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        tm = ''
                    rows.append(['V.{}'.format(length-i), revision.get('user_name') or '', tm])
                print(tabulate(rows, headers=headers))
            elif action == 'show':
                if revision == 0:
                    revision = length + 1
                current_rec = params.record_cache[record_uid]
                key = current_rec['record_key_unencrypted']
                rev = history[length - revision]
                print('\n{0:>20s}: V.{1}'.format('Revision', revision))
                if (rev.get('version') in (1, 2)):
                    rec = RecordHistoryCommand.load_revision(params, key, rev)
                    rec.display()
                elif (rev.get('version') == 3):
                    recordv3.RecordV3.display(rev)
                else:
                    raise CommandError('history', 'Cannot restore this revision - unknown record version: {0}'.format(rev.get('version')))
            elif action == 'diff':
                if revision == 0:
                    revision = 1
                current_rec = params.record_cache[record_uid]
                key = current_rec['record_key_unencrypted']
                rev = history[0]
                record_next = RecordHistoryCommand.load_revision(params, key, rev)
                rows = []
                for current_revision in range(length, revision-1, -1):
                    current_rev = history[length - current_revision]
                    record_current = RecordHistoryCommand.load_revision(params, key, current_rev)
                    added = False
                    for d in RecordHistoryCommand.get_record_diffs(record_next, record_current):
                        rows.append(['V.{}'.format(current_revision+1) if not added else '', d[0], d[1], d[2]])
                        added = True
                    record_next = record_current
                record_current = Record()
                added = False
                for d in RecordHistoryCommand.get_record_diffs(record_next, record_current):
                    rows.append(['V.{}'.format(1) if not added else '', d[0], d[1], d[2]])
                    added = True
                headers = ('Version', 'Field', 'New Value', 'Old Value')
                print(tabulate(rows, headers=headers))
            elif action == 'restore':
                ro = api.resolve_record_write_path(params, record_uid)
                if not ro:
                    raise CommandError('history', 'You do not have permission to modify this record')
                if revision == 0:
                    raise CommandError('history', 'Invalid revision to restore: Revisions: 1-{0}'.format(length))

                rev = history[length - revision]
                current_rec = params.record_cache[record_uid] if record_uid in params.record_cache else {}
                if rev.get('version') in (1, 2) and current_rec.get('version') in (1, 2):
                    ro.update({
                        'version': rev['version'],
                        'client_modified_time': api.current_milli_time(),
                        'revision': current_rec['revision'],
                        'data': rev['data']
                    })
                    udata = current_rec.get('udata') or {}
                    extra = {}
                    if 'extra_unencrypted' in current_rec:
                        extra = json.loads(current_rec['extra_unencrypted'].decode('utf-8'))
                    if 'udata' in rev:
                        udata.update(rev['udata'])
                    udata['file_ids'] = []
                    if 'files' in extra:
                        del extra['files']

                    key = current_rec['record_key_unencrypted']
                    if 'extra' in rev:
                        decrypted_extra = api.decrypt_data(rev['extra'], key)
                        extra_object = json.loads(decrypted_extra.decode('utf-8'))
                        extra.update(extra_object)
                        if 'files' in extra:
                            for atta in extra_object['files']:
                                udata['file_ids'].append(atta['id'])
                                if 'thumbnails' in atta:
                                    for thumb in atta['thumbnails']:
                                        udata['file_ids'].append(thumb['id'])
                    ro['extra'] = api.encrypt_aes(json.dumps(extra).encode('utf-8'), key)
                    ro['udata'] = udata
                    rq = {
                        'command': 'record_update',
                        'update_records': [ro]
                    }
                    rs = api.communicate(params, rq)
                    if 'update_records' in rs:
                        params.sync_data = True
                        if rs['update_records']:
                            status = rs['update_records'][0]
                            if status['status'] == 'success':
                                logging.info('Revision V.{0} is restored'.format(revision))
                                params.queue_audit_event('revision_restored', record_uid=record_uid)
                            else:
                                raise CommandError('history', 'Failed to restore record revision: {0}'.format(status['status']))
                else:
                    raise CommandError('history', 'Cannot restore this revision')

    @staticmethod
    def load_revision(params, record_key, revision):
        # type: (KeeperParams, bytes, dict) -> Record
        data = json.loads(api.decrypt_data(revision['data'], record_key).decode('utf-8'))
        if 'extra' in revision:
            extra = json.loads(api.decrypt_data(revision['extra'], record_key).decode('utf-8'))
        else:
            extra = {}
        rec = Record(revision['record_uid'])
        rec.load(data, extra=extra)
        return rec

    @staticmethod
    def get_diff_index(value1, value2):
        length = min(len(value1), len(value2))
        for i in range(length):
            if value1[i] != value2[i]:
                return i
        return length

    TargetValueLength = 32
    @staticmethod
    def to_diff_str(value, index=0):
        if len(value) > RecordHistoryCommand.TargetValueLength:
            if index > 6:
                tail_len = len(value) - index
                if tail_len >= RecordHistoryCommand.TargetValueLength - 6:
                    value = '... ' + value[index-2:]
                else:
                    value = '... ' + value[-(RecordHistoryCommand.TargetValueLength - 6):]
            if len(value) > RecordHistoryCommand.TargetValueLength:
                value = value[:26] + ' ...'
        return value

    @staticmethod
    def compare_values(value1, value2):
        # type: (str, str) -> Tuple[str, str] or None
        if not value1 and not value2:
            return None
        if value1 and value2:
            if value1 == value2:
                return None
            idx = RecordHistoryCommand.get_diff_index(value1, value2)
            return RecordHistoryCommand.to_diff_str(value1, idx), RecordHistoryCommand.to_diff_str(value2, idx)
        else:
            return RecordHistoryCommand.to_diff_str(value1 or ''), RecordHistoryCommand.to_diff_str(value2 or '')

    @staticmethod
    def to_attachment_str(attachment):
        # type: (dict) -> str
        value = ''
        if attachment:
            value += attachment.get('title') or attachment.get('name') or attachment.get('id')
            size = attachment.get('size') or 0
            scale = 'b'
            if size > 0:
                if size > 2000:
                    size = size / 1024
                    scale = 'Kb'
                if size > 2000:
                    size = size / 1024
                    scale = 'Mb'
                if size > 2000:
                    size = size / 1024
                    scale = 'Gb'
                value += ': ' + '{0:.2f}'.format(size).rstrip('0').rstrip('.') + scale
        return value

    @staticmethod
    def get_record_diffs(record1, record2):
        # type: (Record, Record) -> Generator[str, str, str]
        d1 = record1.__dict__
        d2 = record2.__dict__
        for field in [('title', 'Title'), ('login', 'Login'), ('password', 'Password'), ('login_url', 'URL'), ('notes', 'Notes'), ('totp', 'Two Factor')]:
            v1 = d1.get(field[0]) or ''
            v2 = d2.get(field[0]) or ''
            cmp_result = RecordHistoryCommand.compare_values(v1, v2)
            if cmp_result:
                yield field[1], cmp_result[0], cmp_result[1]
        if record1.custom_fields or record2.custom_fields:
            all_keys = set()
            all_keys.update([x['name'] for x in record1.custom_fields if 'name' in x])
            all_keys.update([x['name'] for x in record2.custom_fields if 'name' in x])
            keys = [x for x in all_keys]
            keys.sort()
            for key in keys:
                v1 = record1.get(key) or ''
                v2 = record2.get(key) or ''
                cmp_result = RecordHistoryCommand.compare_values(v1, v2)
                if cmp_result:
                    yield key[:24], cmp_result[0], cmp_result[1]
        if record1.attachments or record2.attachments:
            att1 = {}
            att2 = {}
            if record1.attachments:
                for atta in record1.attachments:
                    if 'id' in atta:
                        att1[atta['id']] = atta
            if record2.attachments:
                for atta in record2.attachments:
                    if 'id' in atta:
                        att2[atta['id']] = atta
            s = set()
            s.update(att1.keys())
            s.symmetric_difference_update(att2.keys())
            if len(s) > 0:
                for id in s:
                    yield 'Attachment', RecordHistoryCommand.to_attachment_str(att1.get(id)), RecordHistoryCommand.to_attachment_str(att2.get(id))


class TotpEndpoint:
    def __init__(self, record_uid, record_title, paths):
        self.record_uid = record_uid
        self.record_title = record_title
        self.paths = paths


class TotpCommand(Command):
    LastRevision = 0 # int
    Endpoints = []   # type: List[TotpEndpoint]

    def get_parser(self):
        return totp_parser

    def execute(self, params, **kwargs):
        record_name = kwargs['record'] if 'record' in kwargs else None
        record_uid = None
        if record_name:
            if record_name in params.record_cache:
                record_uid = record_name
            else:
                rs = try_resolve_path(params, record_name)
                if rs is not None:
                    folder, record_name = rs
                    if folder is not None and record_name is not None:
                        folder_uid = folder.uid or ''
                        if folder_uid in params.subfolder_record_cache:
                            for uid in params.subfolder_record_cache[folder_uid]:
                                r = api.get_record(params, uid)
                                if r.title.lower() == record_name.lower():
                                    record_uid = uid
                                    break

            if record_uid is None:
                records = api.search_records(params, kwargs['record'])
                if len(records) == 1:
                    logging.info('Record Title: {0}'.format(records[0].title))
                    record_uid = records[0].record_uid
                else:
                    if len(records) == 0:
                        raise CommandError('totp', 'Enter name or uid of existing record')
                    else:
                        raise CommandError('totp', 'More than one record are found for search criteria: {0}'.format(kwargs['record']))

        is_v2 = bool(kwargs.get('legacy'))
        record = params.record_cache[record_uid] if record_uid in params.record_cache else {}
        version = record.get('version') or 0
        if is_v2 or version < 3:
            recordv2.TotpCommand().execute(params, **kwargs)
            return

        recordv3.RecordV3.validate_access(params, record_uid)
        if version != 3:
            raise CommandError('get', 'Record is not version 3 (record type)')

        if record_uid:
            rec = api.get_record(params, record_uid)

            data = record.get('data_unencrypted') or '{}'
            data = json.loads(data)
            fields = data['fields'] if 'fields' in data else []
            fields.extend(data['custom'] if 'custom' in data else [])
            totp = next((t.get('value') for t in fields if t['type'] == 'oneTimeCode'), None)
            rec.totp = totp[0] if totp else totp

            tmer = None     # type: threading.Timer or None
            done = False
            def print_code():
                global tmer
                if not done:
                    TotpCommand.display_code(rec.totp)
                    tmer = threading.Timer(1, print_code).start()
            try:
                print('Press <Enter> to exit\n')
                print_code()
                input()
            finally:
                done = True
                if tmer:
                    tmer.cancel()
        else:
            TotpCommand.find_endpoints(params)
            logging.info('')
            headers = ["#", 'Record UID', 'Record Title', 'Folder(s)']
            table = []
            for i in range(len(TotpCommand.Endpoints)):
                endpoint = TotpCommand.Endpoints[i]
                title = endpoint.record_title
                if len(title) > 23:
                    title = title[:20] + '...'
                folder = endpoint.paths[0] if len(endpoint.paths) > 0 else '/'
                table.append([i + 1, endpoint.record_uid, title, folder])
            table.sort(key=lambda x: x[2])
            print(tabulate(table, headers=headers))
            print('')

    LastDisplayedCode = ''

    @staticmethod
    def display_code(url):
        code, remains, total = get_totp_code(url)
        progress = ''.rjust(remains, '=')
        progress = progress.ljust(total, ' ')
        if os.isatty(0):
            print('\r', end='', flush=True)
            print('\t{0}\t\t[{1}]'.format(code, progress), end='', flush=True)
        else:
            if TotpCommand.LastDisplayedCode != code:
                print('\t{0}\t\tvalid for {1} seconds.'.format(code, remains))
                TotpCommand.LastDisplayedCode = code

    @staticmethod
    def find_endpoints(params):
        # type: (KeeperParams) -> None
        if TotpCommand.LastRevision < params.revision:
            TotpCommand.LastRevision = params.revision
            TotpCommand.Endpoints.clear()
            for record_uid in params.record_cache:
                record = api.get_record(params, record_uid)

                rec = params.record_cache[record_uid] if record_uid in params.record_cache else {}
                data = rec.get('data_unencrypted') or '{}'
                data = json.loads(data)
                fields = data['fields'] if 'fields' in data else []
                fields.extend(data['custom'] if 'custom' in data else [])
                totp = next((t.get('value') for t in fields if t['type'] == 'oneTimeCode'), None)
                record.totp = totp[0] if totp else totp

                if record.totp:
                    paths = []
                    for folder_uid in find_folders(params, record_uid):
                        path = '/' + get_folder_path(params, folder_uid, '/')
                        paths.append(path)
                    TotpCommand.Endpoints.append(TotpEndpoint(record_uid, record.title, paths))


class SharedRecordsReport(Command):
    def get_parser(self):
        return shared_records_report_parser

    def execute(self, params, **kwargs):
        recordv2.SharedRecordsReport().execute(params, **kwargs)


get_record_types_description = '''
Get Record Types Command Syntax Description:

Column Name       Description
  recordTypeId      Record Type Id
  content           Record type description in JSON format

--format:
            csv     CSV format
            json    JSON format
            table   Table format (default)

--example|-e:       Print example JSON for the field or record type

--list-record|-lr:  List specific record type - search by name or ID
--list-field|-lf:   List specific field type - search by name
'''


class RecordTypeInfo(Command):
    def get_parser(self):
        return record_type_info_parser

    def resolve_record_type(self, params, record_type_id):
        record_type_info = {}
        if params.record_type_cache and record_type_id in params.record_type_cache:
            record_type_info = { record_type_id: params.record_type_cache.get(record_type_id) }

        return record_type_info

    def resolve_record_type_by_name(self, params, record_type_name):
        record_type_info = None
        if record_type_name:
            if params.record_type_cache:
                for v in params.record_type_cache.values():
                    dict = json.loads(v)
                    # TODO: Is 'type' case sensitive
                    if dict and dict.get('$id').lower() == record_type_name.lower():
                        record_type_info = v
                        break

        return record_type_info

    def resolve_record_types(self, params, record_type_id):
        records = [] # (count, category, recordTypeId, content)
        if params.record_type_cache:
            if record_type_id and (type(record_type_id) == int or record_type_id.isdigit()):
                record_type_id = int(record_type_id)
                if record_type_id in params.record_type_cache:
                    content = params.record_type_cache.get(record_type_id)
                    dict = json.loads(content)
                    #content = json.dumps(dict, indent=2) # breaks csv, json
                    categories = dict['categories'] if 'categories' in dict else []
                    records.append((1, categories, record_type_id, content))
                else:
                    logging.warning(bcolors.WARNING + 'Record Type ID: ' + str(record_type_id) + ' not found!' + bcolors.ENDC)
            else:
                show_all = not record_type_id or record_type_id.isspace() or record_type_id == '*'
                for rtid in params.record_type_cache:
                    content = params.record_type_cache.get(rtid)
                    dict = json.loads(content)
                    #content = json.dumps(dict, indent=2) # breaks csv, json
                    categories = dict['categories'] if 'categories' in dict else []
                    name = dict['$id'] if '$id' in dict else None
                    if show_all: content = name
                    if show_all or (record_type_id and name and record_type_id == name):
                        records.append((1, categories, rtid, content))
                if not show_all and not records:
                    logging.warning(bcolors.WARNING + 'Record Type "' + str(record_type_id) + '" not found!' + bcolors.ENDC)

        return records

    def resolve_categories(self, params, category):
        categories = [] # count, category, recordTypeId, content
        should_resolve_all = not category or category.isspace() or category == '*'
        if params.record_type_cache:
            if should_resolve_all:
                cats = {}
                for rtid in params.record_type_cache:
                    json_content = params.record_type_cache.get(rtid)
                    content = json.loads(json_content)
                    cat_list = content['categories'] if 'categories' in content else [' ']
                    for category in cat_list:
                        cats[category] = cats[category] + 1 if category in cats else 1
                for cat_name, count in cats.items():
                    categories.append((count, cat_name, 0, None))
            else:
                for rtid in params.record_type_cache:
                    json_content = params.record_type_cache.get(rtid)
                    content = json.loads(json_content)
                    cat_list = content['categories'] if 'categories' in content else [' ']
                    if cat_list and category in cat_list:
                        categories.append((1, category, rtid, content))
                if not should_resolve_all and not categories:
                    logging.warning(bcolors.WARNING + 'Category "' + str(category) + '" not found!' + bcolors.ENDC)

        return categories

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(get_record_types_description)
            return

        format = kwargs.get('format') or 'table'
        # reload = kwargs.get('update') or False

        output = kwargs.get('output')
        sample = kwargs.get('description') # generate descriptive sample - incl. all possible enum values
        example = kwargs.get('example') # generate working example - JSON ready to copy/paste, includes single/valid enum value
        lcid = kwargs.get('category')
        lfid = kwargs.get('field_name')
        lrid = kwargs.get('record_name')

        has_categories_only = not lrid and (not lcid or lcid.isspace() or lcid == '*')
        has_record_type_names_only = not lcid and (not lrid or lrid.isspace() or lrid == '*')
        if (sample or example) and not((lfid and lfid != '*') or (lrid and lrid != '*')):
            logging.warning(bcolors.WARNING + 'Ignored options: --description/--example options require a single record/field type name, please use --example with -lr|lf NAME option' + bcolors.ENDC)

        if lfid:
            field_name = lfid
            list_all_field_types = not field_name or field_name.isspace() or field_name == '*'
            rows = []
            fields = ()
            column_names = ()
            if list_all_field_types:
                rows = recordv3.RecordV3.get_field_types()
                fields = ('id', 'type', 'lookup', 'multiple', 'description')
                column_names = ('Field Type ID', 'Type', 'Lookup', 'Multiple', 'Description')
            else:
                ft = recordv3.RecordV3.get_field_type(field_name)
                if not ft or not ft.get('id'):
                    logging.error(bcolors.FAIL + 'Error - Unknown field type: ' + field_name + bcolors.ENDC)
                    return

                val = ft.get('value')
                if val and format == 'json':
                    val = json.loads(val) if isinstance(val, str) and val.strip().startswith('{') else val

                if field_name and field_name != '*' and (sample or example):
                    # ignore --description/sample - it is shown in [Value Format] column for the field anyways
                    if sample:
                        print('{"type":"%s","value":[%s]}'%(field_name, json.dumps(val)))
                    elif example:
                        print('{"type":"%s","value":[%s]}'%(field_name, json.dumps(ft.get('sample'))))
                    return

                rows = [(ft['id'], ft['type'], ft['valueType'], val)]
                fields = ('id', 'type', 'valueType', 'value')
                column_names = ('Field Type ID', 'Type', 'Value Type', 'Value Format')

            field_descriptions = column_names if format == 'table' else fields

            table = [list(row) for row in rows]
            dump_report_data(table, field_descriptions, fmt=format, filename=output)
            return

        record_name = lrid
        if record_name and record_name != '*' and example:
            rtex = recordv3.RecordV3.get_record_type_example(params, record_name)
            print (rtex)
            return

        # row_data = []
        # if lcid is not None:
        #     row_data = self.resolve_categories(params, lcid)
        # elif lrid is not None:
        #     row_data = self.resolve_record_types(params, lrid)
        # else:
        #     count = len(params.record_type_cache)
        #     print('Cached ' + str(count) + ' record types.')
        #     return
        # 2021-06-07 if no record_name or field_name specified - list all record types
        has_categories_only = False
        row_data = self.resolve_record_types(params, lrid)

        rows = []
        for count, cat, rtid, content in row_data:
            record_type = {
                'numRecords': count,
                'category': cat,
                'recordTypeId': rtid,
                'content': content
            }
            rows.append(record_type)

        fields = ('numRecords', 'category') if has_categories_only else ('category', 'recordTypeId', 'content')
        field_descriptions = fields
        if format == 'table':
            field_descriptions = ('Record Types', 'Category') if has_categories_only else ('Category', 'Record Type ID', 'Content')
            if has_record_type_names_only:
                field_descriptions = ('Category', 'Record Type ID', 'Record Type Name')
            if not has_categories_only:
                for row in rows:
                    if 'content' in row and row['content']:
                        if isinstance(row['content'], str) and row['content'].strip().startswith('{'):
                            row['content'] = json.loads(row['content'])
                        row['content'] = json.dumps(row['content'], indent=2) if not isinstance(row['content'], str) else row['content']

        # recordTypeId must be first column
        if 'recordTypeId' in fields:
            i = fields.index('recordTypeId')
            fields = ('recordTypeId',) + (fields[:i] + fields[i+1:])
            field_descriptions = ('Record Type ID',) + (field_descriptions[:i] + field_descriptions[i+1:])
        # Hide categories from the ui for now
        if 'category' in fields:
            i = fields.index('category')
            fields = (fields[:i] + fields[i+1:])
            field_descriptions = (field_descriptions[:i] + field_descriptions[i+1:])
        if format != 'table':
            field_descriptions = fields

        table = []
        for raw in rows:
            row = []
            for f in fields:
                row.append(raw[f])
            table.append(row)
        dump_report_data(table, field_descriptions, fmt=format, filename=output)


record_type_description = '''
Record Type Command Syntax Description:

record-type-id:     Record type ID of the record to update/remove
                    Not required when adding new record type - new ID will be auto generated

--add-type | -a:    Add new custom record type definition
--update-type | -u: Update existing custom record type definition
--remove-type | -r: Remove custom record type definition

--data:             JSON string with record type definition
'''


class RecordRecordType(Command):
    def get_parser(self):
        return record_type_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(record_type_description)
            return

        # RecordTypeScope: RT_STANDARD, RT_USER, RT_ENTERPRISE
        # Only RT_ENTERPRISE scope is supported, RT_USER will be supported in the future.
        if not params.enterprise:
            logging.error('This command is restricted to Keeper Enterprise administrators.')
            return

        changed = False
        scope = records.RecordTypeScope.DESCRIPTOR.values_by_name['RT_ENTERPRISE'].number

        rtid = kwargs.get('record_type_id')
        data = kwargs.get('data')
        action = kwargs.get('action')

        if not action in ('add', 'update', 'remove'):
            logging.error('the following arguments are required: -a/--action (choose from "add", "update", "remove")')
            return

        if action == 'add':
            # add requires --data and no RTID
            if rtid:
                logging.error('Option --action=add cannot be used with positional argument: record_type_id')
                return
            if not data:
                logging.error('Cannot add record type without definition. Option --data is required for --action=add')
                return

            res = recordv3.RecordV3.is_valid_record_type_definition(data)
            if not res.get('is_valid'):
                logging.error('Error validating record type definition - ' + res.get('error'))
                return

            rq = records.RecordType()
            rq.content = data
            rq.scope = scope
            rs = api.communicate_rest(params, rq, 'vault/record_type_add')
            record_type_rs = records.RecordTypeModifyResponse()
            record_type_rs.ParseFromString(rs)
            changed = True
            print('Record type added - new record type ID: ' + str(record_type_rs.recordTypeId))

        elif action == 'remove':
            # remove requires RTID and no --data
            if not rtid:
                logging.error('To remove a record type - please provide the record type ID')
                return
            if data:
                logging.error('Option --data cannot be used with --action=add')
                return

            rq = records.RecordType()
            rq.recordTypeId = rtid
            rq.scope = scope
            rs = api.communicate_rest(params, rq, 'vault/record_type_delete')
            record_type_rs = records.RecordTypeModifyResponse()
            record_type_rs.ParseFromString(rs)
            changed = True
            print('Record type deleted - record type ID: ' + str(record_type_rs.recordTypeId))

        elif action == 'update':
            # update requires --data and RTID
            if not rtid or not data:
                logging.error("To update a record type - please provide both record type ID and new content in --data option")
                return

            res = recordv3.RecordV3.is_valid_record_type_definition(data)
            if not res.get('is_valid'):
                logging.error('Error validating record type definition - ' + res.get('error'))
                return

            # TODO: is it ok to change $id - ex. #41 from "$id": "rt1" to "rt2" == delete rt1 and insert rt2 at #41
            # is there a record type definition (change) history ~ like record history
            rq = records.RecordType()
            rq.recordTypeId = rtid
            rq.content = data
            rq.scope = scope
            rs = api.communicate_rest(params, rq, 'vault/record_type_update')
            record_type_rs = records.RecordTypeModifyResponse()
            record_type_rs.ParseFromString(rs)
            changed = True
            print('Record type updated - record type ID: ' + str(record_type_rs.recordTypeId))
        else:
            logging.error('Unknown argument "' + action + '" for -a/--action (choose from "add", "update", "remove")')

        if changed:
            params.sync_data = True


class RecordFileReportCommand(Command):
    def get_parser(self):
        return file_report_parser

    def execute(self, params, **kwargs):
        is_v2 = bool(kwargs.get('legacy'))
        if is_v2:
            FileReportCommand().execute(params, **kwargs)
            return

        v3_enabled = params.settings.get('record_types_enabled') if params.settings and isinstance(params.settings.get('record_types_enabled'), bool) else False
        if v3_enabled:
            print('Legacy records attachments:')

        FileReportCommand().execute(params, **kwargs)

        if not v3_enabled:
            return

        print('Record types attachments:')
        headers = ['#', 'Title', 'Record UID', 'File ID', 'Downloadable', 'File Size', 'File Name']
        table = []
        for record_uid in params.record_cache:
            r = api.get_record(params, record_uid)
            record_uids = []
            cached_rec = params.record_cache[record_uid] if params.record_cache and record_uid in params.record_cache else {}
            if (cached_rec and cached_rec.get('version') == 3):
                data = cached_rec.get('data_unencrypted') or '{}'
                data = json.loads(data)

                fields = data.get('fields') or []
                for fr in (ft for ft in fields if ft['type'] == 'fileRef'):
                    if fr and 'value' in fr:
                        fuid = fr.get('value')
                        if fuid:
                            record_uids.extend(fuid)

            if not record_uids:
                continue

            file_info = dict.fromkeys(record_uids, {})
            for fuid in file_info:
                file_rec = params.record_cache[fuid] if params.record_cache and fuid in params.record_cache else {}
                file_data = file_rec.get('data_unencrypted') or '{}'
                file_data = json.loads(file_data)
                file_info[fuid] = {
                    'size': recordv3.HumanBytes.format(file_data.get('size') or 0),
                    'name': file_data.get('name') or '',
                    'status': '-',
                    'url': ''
                }
            if kwargs.get('try_download'):
                # api.resolve_record_access_path(params, r.record_uid, path=rq)
                logging.info('Downloading attachments for record: %s', r.title)
                try:
                    ruids = [ruid for ruid in file_info]
                    ruids = [loginv3.CommonHelperMethods.url_safe_str_to_bytes(ruid) if type(ruid) == str else ruid for ruid in ruids]
                    rq = records.FilesGetRequest()
                    rq.record_uids.extend(ruids)
                    rq.for_thumbnails = False
                    rs = api.communicate_rest(params, rq, 'vault/files_download')
                    files_get_rs = records.FilesGetResponse()
                    files_get_rs.ParseFromString(rs)
                    for f in files_get_rs.files:
                        # success = (f.status == records.FileGetResult.DESCRIPTOR.values_by_name['FG_SUCCESS'].number)
                        ruid = loginv3.CommonHelperMethods.bytes_to_url_safe_str(f.record_uid)
                        if f.url and f.url.strip():
                            opt_rs = requests.get(f.url, headers={"Range": "bytes=0-1"})
                            file_info[ruid]['status'] = 'OK' if opt_rs.status_code in {200, 206} else str(opt_rs.status_code)
                except Exception as e:
                    logging.debug(e)

            for file_id in file_info:
                row = [len(table) + 1, r.title, r.record_uid, file_id, file_info[file_id]['status'], file_info[file_id]['size'], file_info[file_id]['name']]
                table.append(row)

        if not kwargs.get('try_download'):
            del headers[4] # remove downloadable status column
            for row in table:
                del row[4] 
        dump_report_data(table, headers)


class RecordGetUidCommand(Command):
    def get_parser(self):
        return get_info_parser

    def execute(self, params, **kwargs):
        uid = kwargs.get('uid')
        if not uid:
            raise CommandError('get', 'UID parameter is required')

        is_v2 = bool(kwargs.get('legacy'))
        version = params.record_cache[uid]['version'] if (uid in params.record_cache and 'version' in params.record_cache[uid]) else 0 or 0
        if is_v2 or version < 3:
            recordv2.RecordGetUidCommand().execute(params, **kwargs)
            return

        v3_enabled = params.settings.get('record_types_enabled') if params.settings and isinstance(params.settings.get('record_types_enabled'), bool) else False
        if version in (3, 4) and not v3_enabled:
            raise TypeError('Record ' + uid + ' not found. You don\'t have Record Types enabled.')

        if version != 3:
            raise CommandError('get', 'Record is not version 3 (record type)')

        fmt = kwargs.get('format') or 'detail'

        if api.is_shared_folder(params, uid):
            sf = api.get_shared_folder(params, uid)
            if fmt == 'json':
                sfo = {
                    "shared_folder_uid": sf.shared_folder_uid,
                    "name": sf.name,
                    "manage_users": sf.default_manage_users,
                    "manage_records": sf.default_manage_records,
                    "can_edit": sf.default_can_edit,
                    "can_share": sf.default_can_share
                }
                if sf.records:
                    sfo['records'] = [{
                        'record_uid': r['record_uid'],
                        'can_edit': r['can_edit'],
                        'can_share': r['can_share']
                    } for r in sf.records]
                if sf.users:
                    sfo['users'] = [{
                        'username': u['username'],
                        'manage_records': u['manage_records'],
                        'manage_users': u['manage_users']
                    } for u in sf.users]
                if sf.teams:
                    sfo['teams'] = [{
                        'name': t['name'],
                        'manage_records': t['manage_records'],
                        'manage_users': t['manage_users']
                    } for t in sf.teams]

                print(json.dumps(sfo, indent=2))
            else:
                sf.display()
            return

        if api.is_team(params, uid):
            team = api.get_team(params, uid)
            if fmt == 'json':
                to = {
                    'team_uid': team.team_uid,
                    'name': team.name,
                    'restrict_edit': team.restrict_edit,
                    'restrict_view': team.restrict_view,
                    'restrict_share': team.restrict_share
                }
                print(json.dumps(to, indent=2))
            else:
                team.display()
            return

        if uid in params.folder_cache:
            f = params.folder_cache[uid]
            if fmt == 'json':
                fo = {
                    'folder_uid': f.uid,
                    'type': f.type,
                    'name': f.name
                }
                print(json.dumps(fo, indent=2))
            else:
                f.display(params=params)
            return

        if uid in params.record_cache:
            api.get_record_shares(params, [uid])
            r = get_record(params, uid)
            if r:
                params.queue_audit_event('open_record', record_uid=uid)
                if fmt == 'json':
                    record_uid = r['record_uid'] if 'record_uid' in r else ''
                    data = r['data_unencrypted'] if 'data_unencrypted' in r else ''
                    data = data.decode('UTF-8') if isinstance(data, bytes) else str(data)
                    data = json.loads(data)
                    ro = {
                        'record_uid': record_uid,
                        'data': data
                    }
                    if record_uid in params.record_cache:
                        rec = params.record_cache[record_uid]
                        if 'shares' in rec:
                            if 'user_permissions' in rec['shares']:
                                permissions = rec['shares']['user_permissions']
                                ro['shared_with'] = [{
                                    'username': su['username'],
                                    'owner': su.get('owner') or False,
                                    'editable': su.get('editable') or False,
                                    'sharable': su.get('sharable') or False
                                } for su in permissions]

                    print(json.dumps(ro, indent=2))
                elif fmt == 'password':
                    password = str(recordv3.RecordV3.get_record_password(r.get('data_unencrypted')) or '')
                    if password and password.strip():
                        print(password)
                else:
                    recordv3.RecordV3.display(r, **{'params': params, 'format': fmt})
                return

        if params.available_team_cache is None:
            api.load_available_teams(params)

        if params.available_team_cache:
            for team in params.available_team_cache:
                if team.get('team_uid') == uid:
                    team_uid = team['team_uid']
                    team_name = team['team_name']
                    if fmt == 'json':
                        fo = {
                            'team_uid': team_uid,
                            'name': team_name
                        }
                        print(json.dumps(fo, indent=2))
                    else:
                        print('')
                        print('User {0} does not belong to team {1}'.format(params.user, team_name))
                        print('')
                        print('{0:>20s}: {1:<20s}'.format('Team UID', team_uid))
                        print('{0:>20s}: {1}'.format('Name', team_name))
                        print('')
                    return

        raise CommandError('get', 'Cannot find any object with UID: {0}'.format(uid))


def get_record(params, record_uid):
    """Return the referenced record cache"""
    record_uid = record_uid.strip()

    if not record_uid:
        logging.warning('No record UID provided')
        return

    if not params.record_cache:
        logging.warning('No record cache.  Sync down first.')
        return

    if not record_uid in params.record_cache:
        logging.warning('Record UID %s not found in cache.' % record_uid)
        return

    cached_rec = params.record_cache[record_uid]
    return cached_rec

