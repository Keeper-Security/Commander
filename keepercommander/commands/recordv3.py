#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import json
import logging
import os
import re
import tempfile
from pathlib import Path

import requests
from Cryptodome.Cipher import AES
from keepercommander.breachwatch import BreachWatch

from . import recordv2 as recordv2
from .base import suppress_exit, raise_parse_exception, dump_report_data, Command
from .. import api, crypto, generator
from .. import recordv3, loginv3
from ..display import bcolors
from ..error import CommandError
from ..params import LAST_RECORD_UID
from ..proto import record_pb2 as records
from ..subfolder import BaseFolderNode, try_resolve_path

DEFAULT_GENERATE_PASSWORD_LENGTH = 16


def register_commands(commands):
    commands['add'] = RecordAddCommand()
    commands['edit'] = RecordEditCommand()
    commands['record-type-info'] = RecordTypeInfo()
    commands['record-type'] = RecordRecordType()


def register_command_info(aliases, command_info):
    aliases['a'] = 'add'
    aliases['rti'] = 'record-type-info'
    aliases['rt'] = 'record-type'

    for p in [record_type_info_parser, record_type_parser]:
        command_info[p.prog] = p.description


add_parser = argparse.ArgumentParser(
    prog='add', description='****** DEPRECATED - Use record-add ******** - Add a record')
add_parser.add_argument('--login', dest='login', action='store', help='login name')
command_group = add_parser.add_mutually_exclusive_group()
command_group.add_argument('--pass', dest='password', action='store', help='password')
command_group.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate a random password')
command_group.add_argument(
    '-gr', '--generate-rules', dest='generate_rules', action='store',
    help='generate a random password with comma separated complexity integers (uppercase, lowercase, numbers, symbols)'
)
add_parser.add_argument(
    '-gl', '--generate-length', type=int, dest='generate_length', action='store',
    help='generate password with given length'
)
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


edit_parser = argparse.ArgumentParser(prog='edit', description='****** DEPRECATED - Use record-update - Edit a record')
edit_parser.add_argument('--login', dest='login', action='store', help='login name')
command_group = edit_parser.add_mutually_exclusive_group()
command_group.add_argument('--pass', dest='password', action='store', help='password')
command_group.add_argument('-g', '--generate', dest='generate', action='store_true', help='generate a random password')
command_group.add_argument(
    '-gr', '--generate-rules', dest='generate_rules', action='store',
    help='generate a random password with comma separated complexity integers (uppercase, lowercase, numbers, symbols)'
)
edit_parser.add_argument(
    '-gl', '--generate-length', type=int, dest='generate_length', action='store',
    help='generate password with given length'
)
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
edit_parser.error = raise_parse_exception
edit_parser.exit = suppress_exit


record_type_info_parser = argparse.ArgumentParser(prog='record-type-info', description='Get record type info')
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


record_type_parser = argparse.ArgumentParser(prog='record-type', description='Add, modify or delete record type definition')
record_type_parser.add_argument('record_type_id', default=None, nargs='?', type=int, action='store', help='record Type ID to update/delete')
record_type_parser.add_argument('--data', dest='data', action='store', help='record type definition in JSON format - use rti command to see existing definitions: ex. rti -lr login')
record_type_parser.add_argument('-a', '--action', dest='action', action='store', choices=['add', 'update', 'remove'], required=True, help='record type definition - add, update or remove')
# command_group = record_type_parser.add_mutually_exclusive_group()
# command_group.add_argument('-a', '--add-type', dest='add_type', action='store_true', help='add new custom record type')
# command_group.add_argument('-u', '--update-type', dest='update_type', action='store_true', help='update existing custom record type')
# command_group.add_argument('-r', '--remove-type', dest='remove_type', action='store_true', help='delete custom record type')
record_type_parser.error = raise_parse_exception
record_type_parser.exit = suppress_exit


def get_password_from_rules(generate_rules, generate_length):
    if generate_rules:
        kpg = generator.KeeperPasswordGenerator.create_from_rules(generate_rules, length=generate_length)
        if kpg is None:
            logging.warning('Using default password complexity rules')
            kpg = generator.KeeperPasswordGenerator(generate_length or DEFAULT_GENERATE_PASSWORD_LENGTH)
    else:
        kpg = generator.KeeperPasswordGenerator(generate_length or DEFAULT_GENERATE_PASSWORD_LENGTH)
    return kpg.generate()


class RecordAddCommand(Command, recordv2.RecordUtils):
    def get_parser(self):
        return add_parser

    def execute(self, params, **kwargs):
        options = kwargs.get('option') or []
        options = [] if options == [None] else options
        has_v3_options = bool(kwargs.get('data') or kwargs.get('data_file') or options)
        has_v2_options = bool(kwargs.get('legacy') or kwargs.get('title') or kwargs.get('login') or kwargs.get('password') or kwargs.get('url') or kwargs.get('notes') or kwargs.get('custom'))
        if has_v2_options and has_v3_options:
            logging.error(bcolors.FAIL + 'Use either legacy arguments only (--title, --pass, --login --url, --notes, --custom) or record type options only (type=login title=MyRecord etc.) see. https://github.com/Keeper-Security/Commander/blob/master/record_types.md' + bcolors.ENDC)
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
            return recordv2.RecordAddCommand().execute(params, **kwargs)

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
                clst = recordv3.RecordV3.custom_options_to_list(kwargs.get('custom'))
                for c in clst:
                    if 'value' in c:
                        c['value'] = self.custom_field_value(c['value'])
                kwargs['custom_list'] = clst
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
            rt_def = recordv3.RecordV3.resolve_record_type_by_name(params, rt)
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

        # Create parent record key which is needed by attachment
        record_key = os.urandom(32)
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
                rdata = crypto.encrypt_aes_v2(rdata, file['record_key'])
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
            attachment_record_key = crypto.encrypt_aes_v2(file['record_key'], params.data_key)
            record_link_key = crypto.encrypt_aes_v2(file['record_key'], record_key)

            rf = records.File()
            rf.record_uid = file['record_uid']
            rf.record_key = attachment_record_key
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
                        rl = {'record_uid': file['record_uid'], 'record_key': record_link_key}
                        record_links['record_links'].append(rl)

        new_attachments = [loginv3.CommonHelperMethods.bytes_to_url_safe_str(a['record_uid']) for a in attachments]
        fref_loc = recordv3.RecordV3.get_fileref_location(params, data_dict) or 'custom'
        fields = data_dict[fref_loc] if fref_loc in data_dict else []

        file_ref = {
            'type': 'fileRef',
            'value': new_attachments
        }
        fields.append(file_ref)

        if not fref_loc in data_dict:
            data_dict[fref_loc] = fields

        data = json.dumps(data_dict)

        # For compatibility w/ legacy: --password overides --generate AND --generate overrides dataJSON/option
        # dataJSON/option < kwargs: --generate < kwargs: --password
        password = kwargs.get('password')
        if not password and (kwargs.get('generate') or kwargs.get('generate_rules') or kwargs.get('generate_length')):
            password = get_password_from_rules(kwargs.get('generate_rules'), kwargs.get('generate_length'))
        if password:
            data = recordv3.RecordV3.update_password(password, data, recordv3.RecordV3.get_record_type_definition(params, data))

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
            rq['folder_key'] = crypto.encrypt_aes_v2(record_key, sf['shared_folder_key_unencrypted'])
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

        res = api.add_record_v3(params, record, **{'record_links': record_links, 'rq': rq})
        if res:
            params.environment_variables[LAST_RECORD_UID] = record_uid
            BreachWatch.scan_and_update_security_data(params, record_uid, params.breach_watch)
            params.sync_data = True

            return record_uid


class RecordEditCommand(Command, recordv2.RecordUtils):
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

        # if record is v2
        if rv <= 2:
            recordv2.RecordEditCommand().execute(params, **kwargs)
            return

        recordv3.RecordV3.validate_access(params, record_uid)

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

        rt_def = recordv3.RecordV3.resolve_record_type_by_name(params, rt_name) or ''
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
            if len(uniq) > 1:  # RT specified more than once
                logging.error(bcolors.FAIL + 'Please specify a valid record type: ' + str(types) + bcolors.ENDC)
                return

            rt = types[0].split('=', 1)[1].strip()
            rt_def = recordv3.RecordV3.resolve_record_type_by_name(params, rt)
            if not rt_def:
                logging.error(bcolors.FAIL + 'Record type definition not found for type: ' + rt +
                    ' - to get list of all available record types use: record-type-info -lr' + bcolors.ENDC)
                return

        data_json = str(kwargs['data']).strip() if 'data' in kwargs and kwargs['data'] else None
        data_file = str(kwargs['data_file']).strip() if 'data_file' in kwargs and kwargs['data_file'] else None
        data_opts = recordv3.RecordV3.convert_options_to_json(params, record_data, rt_def, kwargs) if rt_def else None
        generate = kwargs.get('generate') or kwargs.get('generate_rules') or kwargs.get('generate_length')
        if not (data_json or data_file or data_opts or generate):
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
        if generate and not data:
            data = record_data

        data = data.strip() if data else None
        if not data:
            logging.error(bcolors.FAIL + "Empty data. Unable to update record." + bcolors.ENDC)
            return

        # For compatibility w/ legacy: --password overides --generate AND --generate overrides dataJSON/option
        # dataJSON/option < kwargs: --generate < kwargs: --password
        password = kwargs.get('password')
        if not password and generate:
            password = get_password_from_rules(kwargs.get('generate_rules'), kwargs.get('generate_length'))
        if password:
            record.password = password
            data = recordv3.RecordV3.update_password(password, data, recordv3.RecordV3.get_record_type_definition(params, data))

        data_dict = json.loads(data)
        changed = rdata_dict != data_dict
        # changed = json.dumps(rdata_dict, sort_keys=True) != json.dumps(data_dict, sort_keys=True)
        if changed:
            params.record_cache[record_uid]['data_unencrypted'] = json.dumps(data_dict)
            result = api.update_record_v3(params, record, **kwargs)
            if 'return_result' in kwargs:
                kwargs['return_result']['update_record_v3'] = result

            BreachWatch.scan_and_update_security_data(params, record_uid, params.breach_watch)

            newpass = recordv3.RecordV3.get_record_password(data) or ''
            oldpass = recordv3.RecordV3.get_record_password(record_data) or ''
            if newpass != oldpass:
                params.queue_audit_event('record_password_change', record_uid=record.record_uid)
            params.sync_data = True

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
            for c in clst:
                if 'value' in c:
                    c['value'] = self.custom_field_value(c['value'])

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


def delete_orphaned_attachments(params):
    orphaned = {
        k: json.loads(v['data_unencrypted'])['title'] for k, v in params.record_cache.items() if v.get('version') == 4
    }
    for uid, rec in params.record_cache.items():
        if rec.get('version') == 3:
            data = json.loads(rec.get('data_unencrypted', '{}'))
            all_fields = data.get('fields') or []
            all_fields.extend(data.get('custom') or [])
            for fileref in (n.get('value') for n in all_fields if n.get('type') == 'fileRef' and n.get('value')):
                for fileref_id in fileref:
                    orphaned.pop(fileref_id, None)

    if len(orphaned) == 0:
        print('There are no orphaned file attachments in this account.')
    else:
        print('The following file attachments are not referenced by any records with a type in this account:')
        print('\n'.join(f'{v} ({k})' for k, v in orphaned.items()))
        msg = "\nIt's possible the files could be referenced elsewhere, are you sure you want to delete these files?"
        if input(f'{msg} (y/n) ').lower() == 'y':
            rq = {
                'command': 'record_update',
                'pt': 'Commander',
                'device_id': 'Commander',
                'client_time': api.current_milli_time(),
                'delete_records': list(orphaned.keys())
            }
            rs = api.communicate(params, rq)
            if 'delete_records' in rs:
                for status in rs['delete_records']:
                    if status['status'] != 'success':
                        logging.warning('Delete attachment error: %s', status.get('status'))

            api.sync_down(params)


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

    @staticmethod
    def resolve_record_type(params, record_type_id):
        record_type_info = {}
        if params.record_type_cache and record_type_id in params.record_type_cache:
            record_type_info = { record_type_id: params.record_type_cache.get(record_type_id) }

        return record_type_info

    @staticmethod
    def resolve_record_types(params, record_type_id):
        records = []  # (count, category, recordTypeId, content)
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

    @staticmethod
    def resolve_categories(params, category):
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
            return dump_report_data(table, field_descriptions, fmt=format, filename=output)

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
        row_data = RecordTypeInfo.resolve_record_types(params, lrid)

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
        return dump_report_data(table, field_descriptions, fmt=format, filename=output)


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
        scope = records.RT_ENTERPRISE

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
            print('Record type added - new record type ID: ' + str(record_type_rs.recordTypeId))
            api.sync_down(params, record_types=True)
            return

        if not rtid:
            logging.error(f'record type \'{action}\': please provide the record type ID')
            return

        num_rts_per_scope = 1000000
        enterprise_rt_id_min = num_rts_per_scope * records.RT_ENTERPRISE
        enterprise_rt_id_max = enterprise_rt_id_min + num_rts_per_scope
        is_enterprise_rt = enterprise_rt_id_min < rtid <= enterprise_rt_id_max
        real_type_id = rtid % num_rts_per_scope

        if not is_enterprise_rt:
            logging.error('Only custom record types can be modified or removed')
            return

        if action == 'remove':
            # remove requires no --data
            if data:
                logging.error('Option --data cannot be used with --action=remove')
                return

            rq = records.RecordType()
            rq.recordTypeId = real_type_id
            rq.scope = scope
            rs = api.communicate_rest(params, rq, 'vault/record_type_delete')
            record_type_rs = records.RecordTypeModifyResponse()
            record_type_rs.ParseFromString(rs)
            logging.info('Record type deleted - record type ID: %d', rtid)
            if rtid in params.record_type_cache:
                del params.record_type_cache[rtid]

        elif action == 'update':
            # update requires --data
            if not data:
                logging.error("To update a record type - please provide both record type ID and new content in --data option")
                return

            res = recordv3.RecordV3.is_valid_record_type_definition(data)
            if not res.get('is_valid'):
                logging.error('Error validating record type definition - ' + res.get('error'))
                return

            # TODO: is it ok to change $id - ex. #41 from "$id": "rt1" to "rt2" == delete rt1 and insert rt2 at #41
            # is there a record type definition (change) history ~ like record history
            rq = records.RecordType()
            rq.recordTypeId = real_type_id
            rq.content = data
            rq.scope = scope
            rs = api.communicate_rest(params, rq, 'vault/record_type_update')
            record_type_rs = records.RecordTypeModifyResponse()
            record_type_rs.ParseFromString(rs)
            logging.info('Record type updated - record type ID: %d', rtid)
            api.sync_down(params, record_types=True)
        else:
            logging.error('Unknown argument "' + action + '" for -a/--action (choose from "add", "update", "remove")')


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

