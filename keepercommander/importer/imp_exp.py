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
"""Import and export functionality."""

import abc
import base64
import bisect
import collections
import copy
import datetime
import hashlib
import itertools
import json
import logging
import os
import pathlib
import re
import sys
import math
import requests
import time
import tempfile

from typing import Iterator, List, Optional, Union, Dict, Tuple, Set, Iterable

from urllib.parse import urlparse, parse_qs

from .encryption_reader import EncryptionReader
from .importer import (importer_for_format, exporter_for_format, path_components, PathDelimiter, BaseExporter,
                       BaseImporter, Record as ImportRecord, RecordField as ImportRecordField, Folder as ImportFolder,
                       SharedFolder as ImportSharedFolder, Permission as ImportPermission, BytesAttachment,
                       Attachment as ImportAttachment, RecordSchemaField, File as ImportFile, Team as ImportTeam,
                       RecordReferences, FIELD_TYPE_ONE_TIME_CODE, TWO_FACTOR_CODE)
from .. import api, sync_down, utils, crypto, vault, vault_extensions, record_types, generator, attachment, record_management
from ..commands import base
from ..display import bcolors
from ..error import KeeperApiError, CommandError
from ..params import KeeperParams
from ..proto import record_pb2, folder_pb2
from ..recordv3 import RecordV3
from ..rest_api import CLIENT_VERSION  # pylint: disable=no-name-in-module
from ..subfolder import BaseFolderNode, SharedFolderFolderNode, find_folders, try_resolve_path
from ..constants import EMAIL_PATTERN

IV_LEN = 12
GCM_TAG_LEN = 16
RECORD_MAX_DATA_LEN = 2000000
RECORD_MAX_DATA_WARN = 'Skipping record "{}": Data size of {} exceeds limit of {}'
LARGE_FIELD_MSG = 'This field is stored as attachment "{}" to avoid 2Mb record limit'
FILE_ATTACHMENT_CHUNK = 100


STANDARD_RECORD_TYPES = {
    'login', 'bankAccount', 'address', 'bankCard', 'birthCertificate', 'contact', 'driverLicense', 'encryptedNotes', 'file',
    'healthInsurance', 'membership', 'passport', 'photo', 'serverCredentials', 'softwareLicense', 'ssnCard', 'general', 'sshKeys',
    'databaseCredentials', 'wifiCredentials'}


def get_record_data_json_bytes(data):
    """Get serialized and utf-8 encoded record data with padding"""
    data_str = json.dumps(data)
    padding = int(math.ceil(max(384, len(data_str)) / 16) * 16)
    if padding:
        data_str = data_str.ljust(padding)
    return data_str.encode('utf-8')


def get_import_folder(params, folder_uid, record_uid):
    """Get a folder name from a folder uid (?)."""
    folder = ImportFolder()

    uid = folder_uid
    is_path = True
    while uid in params.folder_cache:
        f = params.folder_cache[uid]

        if f.type == 'shared_folder':
            is_path = False
            if f.uid in params.shared_folder_cache:
                sf = params.shared_folder_cache[f.uid]
                if 'records' in sf:
                    for sfr in sf['records']:
                        if sfr['record_uid'] == record_uid:
                            folder.can_share = sfr['can_share']
                            folder.can_edit = sfr['can_edit']
                            break

        name = f.name.replace(PathDelimiter, 2*PathDelimiter)
        if is_path:
            if folder.path:
                folder.path = name + PathDelimiter + folder.path
            else:
                folder.path = name
        else:
            if folder.domain:
                folder.domain = name + PathDelimiter + folder.domain
            else:
                folder.domain = name

        uid = f.parent_uid
        if not uid:
            break

    return folder


def get_folder_path(params, folder_uid):
    """Get the path corresponding to a folder uid."""
    uid = folder_uid
    path = ''
    while uid in params.folder_cache:
        f = params.folder_cache[uid]
        name = f.name.replace(PathDelimiter, 2*PathDelimiter)
        if path:
            path = name + PathDelimiter + path
        else:
            path = name

        uid = f.parent_uid
        if not uid:
            break

    return path


def convert_keeper_record(record, has_attachments=False):
    # type: (dict, bool) -> Optional[ImportRecord]
    record_uid = record.get('record_uid')
    if not record_uid:
        logging.debug('Invalid Keeper record: no record uid')
        return

    version = record.get('version') or 2
    if not isinstance(version, int):
        try:
            version = int(version)
        except:
            logging.debug('Invalid Keeper record \"%s\" version: %s', record_uid, str(version))
            return
    if 'data_unencrypted' not in record:
        return

    data = json.loads(record['data_unencrypted'])
    rec = ImportRecord()
    rec.uid = record_uid
    rec.title = data.get('title') or ''
    rec.notes = data.get('notes') or ''
    rec.last_modified = record.get('client_modified_time') or 0
    if version == 2:
        rec.login = data.get('secret1') or ''
        rec.password = data.get('secret2') or ''
        rec.login_url = data.get('link')
        if 'custom' in data:
            for custom in data['custom'] or []:
                rf = ImportRecordField()
                rf.label = custom.get('name') or ''
                rf.value = custom.get('value') or ''
                rec.fields.append(rf)
        if 'extra_unencrypted' in record:
            try:
                extra = json.loads(record['extra_unencrypted'])
                if 'fields' in extra:
                    for field in extra['fields']:
                        if field['field_type'] == 'totp':
                            rf = ImportRecordField()
                            rf.type = FIELD_TYPE_ONE_TIME_CODE
                            rf.value = field['data']
                            rec.fields.append(rf)
            except:
                logging.debug('Error parsing extra for record \"%s\"', record_uid)

    elif version == 3 and 'type' in data:
        rec.type = data['type']
        schema_fields = []
        if 'fields' in data:
            for field in data['fields']:
                field_type = field.get('type') or ''
                if field_type:
                    schema_field = RecordSchemaField()
                    schema_field.ref = field_type
                    schema_field.label = field.get('label') or ''
                    schema_fields.append(schema_field)

        if rec.type not in STANDARD_RECORD_TYPES:
            rec.schema = schema_fields

        fields = data.get('fields') if 'fields' in data else []
        custom = data.get('custom') if 'custom' in data else []
        for field in itertools.chain(fields, custom):
            field_value = field.get('value') or ''
            if isinstance(field_value, list) and len(field_value) == 1:
                field_value = field_value[0]
            field_type = field.get('type') or ''

            if field_type == 'login' and not rec.login and isinstance(field_value, str):
                rec.login = field_value
            elif field_type == 'password' and not rec.password and isinstance(field_value, str):
                rec.password = field_value
            elif field_type == 'url' and not field.get('label') and not rec.login_url and isinstance(field_value, str):
                rec.login_url = field_value
            elif field_type.endswith('Ref'):
                ref_type = field_type[:-3]
                if ref_type == 'file':
                    continue
                uids = field_value if isinstance(field_value, list) else [str(field_value)]
                uids = [x for x in uids if x]
                if uids:
                    references = RecordReferences()
                    references.type = ref_type
                    references.uids = uids
                    if not rec.references:
                        rec.references = []
                    rec.references.append(references)
            else:
                rf = ImportRecordField()
                rf.type = field_type
                rf.label = field['label'] if 'label' in field else ''
                rf.value = field_value
                if not rf.value:
                    base_field = next((x for x in schema_fields if x.ref == rf.type and x.label == rf.label), None)
                    if base_field:
                        continue
                rec.fields.append(rf)
                if field_type == 'script' and has_attachments:
                    pass
    else:
        return

    return rec


def export(params, file_format, filename, **kwargs):
    # type: (KeeperParams, str, str, ...) -> None
    """Export data from Vault to a file in an assortment of formats."""
    sync_down.sync_down(params)

    exporter = exporter_for_format(file_format)()  # type: BaseExporter
    if 'max_size' in kwargs:
        exporter.max_size = int(kwargs['max_size'])

    save_in_vault = kwargs.get('save_in_vault') is True
    if save_in_vault and file_format != 'keepass':
        save_in_vault = False

    if not save_in_vault:
        if not filename and not exporter.supports_stdout():
            raise CommandError('export', 'File name parameter is required.')

    folder_filter = None      # type: Optional[Set[str]]
    record_filter = None      # type: Optional[Set[str]]
    folder_path = kwargs.get('folder')
    if folder_path:
        folder = None    # type: Optional[BaseFolderNode]
        rs = try_resolve_path(params, folder_path)
        if rs:
            f, rest = rs
            if not rest:
                folder = f
        if not folder:
            logging.warning('Folder \"%s\" not found', folder_path)
            return
        folder_filter = set()
        record_filter = set()

        def on_folder(base_folder):   # type: (BaseFolderNode) -> None
            folder_filter.add(base_folder.uid)
            if base_folder.uid in params.subfolder_record_cache:
                record_filter.update(params.subfolder_record_cache[base_folder.uid])
        base.FolderMixin.traverse_folder_tree(params, folder.uid, on_folder)

    to_export = []
    if exporter.has_shared_folders():
        shfolders = [api.get_shared_folder(params, sf_uid) for sf_uid in params.shared_folder_cache]
        shfolders.sort(key=lambda x: x.name.lower(), reverse=False)
        for f in shfolders:
            if folder_filter:
                if f.shared_folder_uid not in folder_filter:
                    continue

            fol = ImportSharedFolder()
            fol.uid = f.shared_folder_uid
            fol.path = get_folder_path(params, f.shared_folder_uid)
            fol.manage_users = f.default_manage_users
            fol.manage_records = f.default_manage_records
            fol.can_edit = f.default_can_edit
            fol.can_share = f.default_can_share
            fol.permissions = []
            if f.teams:
                for team in f.teams:
                    perm = ImportPermission()
                    perm.uid = team['team_uid']
                    perm.name = team['name']
                    perm.manage_users = team['manage_users']
                    perm.manage_records = team['manage_records']
                    fol.permissions.append(perm)
            if f.users:
                for user in f.users:
                    perm = ImportPermission()
                    perm.name = user['username']
                    perm.manage_users = user['manage_users']
                    perm.manage_records = user['manage_records']
                    fol.permissions.append(perm)

            to_export.append(fol)
    sf_count = len(to_export)

    force = kwargs.get('force', False)
    if not force and not exporter.supports_v3_record():
        answer = base.user_choice(f'Export to {file_format} format may not support all custom fields, data will be exported as best effort\n\n'
                                  'Do you want to continue?', 'yn', 'n')
        if answer.lower() != 'y':
            return

    # # assign export record id`
    # external_ids = {}
    # ext_id = 0
    # for record_uid in params.record_cache.keys():
    #     ext_id += 1
    #     external_ids[record_uid] = ext_id
    for record_uid in params.record_cache:
        if record_filter or folder_path:
            if record_uid not in record_filter:
                continue

        record = params.record_cache[record_uid]
        record_version = record.get('version') or 0
        if record_version == 2 or record_version == 3:
            try:
                rec = convert_keeper_record(record, exporter.has_attachments())
                if not rec:
                    continue
            except:
                logging.debug('Failed to export record \"%s\"', record_uid)
                continue
            if rec.title.lower() == 'exported vault':
                logging.info('Record \"%s\" is skipped from export', record_uid)
                continue

            if exporter.has_attachments():
                if record_version == 2 and 'extra_unencrypted' in record:
                    extra = json.loads(record['extra_unencrypted'])
                    if 'files' in extra:
                        rec.attachments = []
                        names = set()
                        for a in extra['files']:
                            orig_name = a.get('title') or a.get('name') or 'attachment'
                            name = orig_name
                            counter = 0
                            while name in names:
                                counter += 1
                                name = "{0}-{1}".format(orig_name, counter)
                            names.add(name)
                            atta = KeeperV2Attachment(params, rec.uid, a['id'])
                            atta.name = name
                            atta.size = a['size']
                            atta.key = utils.base64_url_decode(a['key'])
                            atta.mime = a.get('type') or ''
                            rec.attachments.append(atta)
                elif record_version == 3:
                    if 'data_unencrypted' in record:
                        data = json.loads(record['data_unencrypted'])
                        fields = itertools.chain(data.get('fields', []), data.get('custom', []))
                        attachment_fields = [x for x in fields if x.get('type', '') in ('fileRef', 'script')]
                        if isinstance(attachment_fields, list) and len(attachment_fields) > 0:
                            file_uids = set()
                            for attachment_field in attachment_fields:
                                field_type = attachment_field.get('type', '')
                                field_value = attachment_field.get('value')
                                if not isinstance(field_value, list):
                                    continue
                                if field_type == 'fileRef':
                                    file_uids.update(field_value)
                                elif field_type == 'script':
                                    if len(field_value) == 1:
                                        script = field_value[0]
                                        if isinstance(script, dict):
                                            if 'fileRef' in script:
                                                file_uids.add(script['fileRef'])
                            if len(file_uids) > 0:
                                rec.attachments = []
                                for file_uid in file_uids:
                                    if file_uid in params.record_cache:
                                        file = vault.KeeperRecord.load(params, file_uid)
                                        if isinstance(file, vault.FileRecord):
                                            atta = KeeperV3Attachment(params, file_uid)
                                            atta.key = file.record_key
                                            atta.name = file.name or file.title
                                            atta.size = file.size
                                            atta.mime = file.mime_type
                                            rec.attachments.append(atta)

            for folder_uid in find_folders(params, record_uid):
                if folder_filter:
                    if folder_uid not in folder_filter:
                        continue
                if folder_uid in params.folder_cache:
                    export_folder = get_import_folder(params, folder_uid, record_uid)
                    if rec.folders is None:
                        rec.folders = []
                    rec.folders.append(export_folder)

            to_export.append(rec)
        # elif record_version == 4:
        #     if 'data_unencrypted' in record:
        #         data = json.loads(record['data_unencrypted'])
        #         file = ImportFile()
        #         file.file_id = record['record_uid']
        #         file.name = data.get('name')
        #         file.title = data.get('title')
        #         file.size = data.get('size')
        #         file.mime = data.get('type')
        #         to_export.append(file)

    rec_count = len(to_export) - sf_count

    args = {}
    file_password = kwargs.get('file_password')
    if file_password:
        args['file_password'] = file_password
    zip_archive = kwargs.get('zip_archive') is True
    if zip_archive:
        args['zip_archive'] = zip_archive
    if save_in_vault:
        args['save_in_vault'] = True
        if 'file_password' not in args:
            args['file_password'] = generator.generate(20)
        if not filename:
            filename = tempfile.mktemp()
            p = pathlib.Path(filename)
            filename = str(p.with_suffix('.kdbx'))

    exporter.execute(filename, to_export, **args)
    if save_in_vault:
        logging.info('Storing Keepass export file to Keeper record')
        record = vault.KeeperRecord.create(params, 'encryptedNotes')  # type: Optional[vault.TypedRecord]
        record.title = 'Exported Vault'
        note = record.get_typed_field('note')
        if note is None:
            note = vault.TypedField.new_field('note', '')
            record.fields.append(note)
        note.value = 'Keepass Export'
        dt = record.get_typed_field('date')
        if dt is None:
            dt = vault.TypedField.new_field('date', 0)
            record.fields.append(dt)
        dt.value = int(datetime.datetime.now().timestamp()) * 1000
        pwd = vault.TypedField.new_field('password', args['file_password'], 'Keepass Password')
        record.fields.append(pwd)
        task = attachment.FileUploadTask(filename)
        task.name = 'keeper_vault.kdbx'
        task.title = 'keeper_vault.kdbx'
        attachment.upload_attachments(params, record, [task])
        record_management.add_record_to_folder(params, record)
        logging.info('Vault has been exported to record UID "%s"', record.record_uid)
        params.sync_data = True
        os.remove(filename)
    else:
        if filename and os.path.isfile(filename):
            logging.info('Vault has been exported to: %s', os.path.abspath(filename))

    params.queue_audit_event('exported_records', file_format=file_format)
    msg = f'{rec_count} records exported' if to_export \
        else 'Search results contain 0 records to be exported.\nDid you, perhaps, filter by (an) empty folder(s)?'
    logging.info(msg)


def import_teams(params, teams, full_sync=False):   # type: (KeeperParams, List[ImportTeam], bool) -> None
    if not params.enterprise:
        logging.warning('Only enterprise administrator can import teams.')
        return

    team_lookup = {}    # type: Dict[str, Union[str, List[str]]]
    if 'teams' in params.enterprise:
        for t in params.enterprise['teams']:
            team_uid = t.get('team_uid')
            team_name = t.get('name')
            if team_uid and team_name:
                team_name = team_name.lower()
                if team_name in team_lookup:
                    tn = team_lookup[team_name]
                    if not isinstance(tn, list):
                        tn = [tn]
                        team_lookup[team_name] = tn
                    tn.append(team_uid)
                else:
                    team_lookup[team_name] = team_uid

    user_lookup = {}    # type: Dict[str, int]
    if 'users' in params.enterprise:
        for u in params.enterprise['users']:
            if u['status'] == 'active' and u['lock'] == 0:
                user_lookup[u['username'].lower()] = u['enterprise_user_id']

    users_to_add = []       # type: List[Tuple[str, str]]
    users_to_remove = []    # type: List[Tuple[str, int]]
    for team in teams:
        team_uid = None
        if team.uid and isinstance(team.uid, str):
            for v in team_lookup.values():
                if isinstance(v, str):
                    if v == team.uid:
                        team_uid = team.uid
                        break
                elif isinstance(v, list):
                    if team.uid in v:
                        team_uid = team.uid
                        break

        if not team_uid:
            if isinstance(team.name, str):
                name = team.name.lower()
                if name in team_lookup:
                    v = team_lookup[name]
                    if isinstance(v, str):
                        team_uid = v
                    elif isinstance(v, list):
                        logging.warning('There are more than one teams with name \"%s\". Skipped from processing.', team.name)

        if team_uid and isinstance(team.members, list):
            current_members = set((x['enterprise_user_id'] for x in params.enterprise.get('team_users', []) if x['team_uid'] == team_uid))
            keep_members = set()
            for email in team.members:
                if isinstance(email, str):
                    email = email.lower()
                    if email in user_lookup:
                        user_id = user_lookup[email]
                        keep_members.add(user_id)
                        if user_id not in current_members:
                            users_to_add.append((email, team_uid))
            if full_sync and len(keep_members) > 0:
                users_to_remove.extend(((team_uid, x) for x in current_members.difference(keep_members)))

    rqs = []
    if len(users_to_add) > 0:
        emails = set((x[0] for x in users_to_add))
        api.load_user_public_keys(params, list(emails))
        team_uids = set((x[1] for x in users_to_add))
        api.load_team_keys(params, list(team_uids))

        for email, team_uid in users_to_add:
            if team_uid in params.key_cache and email in params.key_cache and email in user_lookup:
                team_key = params.key_cache[team_uid]
                user_public_keys = params.key_cache[email]
                if team_key.aes and user_public_keys.rsa:
                    try:
                        rsa_key = crypto.load_rsa_public_key(user_public_keys.rsa)
                        team_key = team_key.aes

                        rqs.append({
                            'command': 'team_enterprise_user_add',
                            'team_uid': team_uid,
                            'enterprise_user_id': user_lookup[email],
                            'user_type': 0,
                            'team_key': utils.base64_url_encode(crypto.encrypt_rsa(team_key, rsa_key))
                        })
                    except Exception as e:
                        logging.debug('Add user to team error: %s', str(e))

    if len(users_to_remove) > 0:
        rqs.extend(({
            'command': 'team_enterprise_user_remove',
            'team_uid': team_uid,
            'enterprise_user_id': user_id,
        } for team_uid, user_id in users_to_remove))
    if rqs:
        rs = api.execute_batch(params, rqs)
        api.query_enterprise(params)
        if rs:
            users_added = 0
            users_removed = 0
            error_count = 0
            for q, s in zip(rqs, rs):
                command = q.get('command') or ''
                if s.get('result') == 'success':
                    if command == 'team_enterprise_user_add':
                        users_added += 1
                    elif command == 'team_enterprise_user_remove':
                        users_removed += 1
                else:
                    error_count += 1
                    if error_count < 5:
                        team_uid = q.get('team_uid') or ''
                        logging.warning('%s: Team UID=%s failed: %s', command, team_uid, s.get('message'))
                    if error_count > 5:
                        logging.warning('%d errors more')

            if users_added > 0:
                logging.info("%d team membership(s) added", users_added)
            if users_removed > 0:
                logging.info("%d team membership(s) removed", users_removed)


def import_user_permissions(params,
                            shared_folders,
                            full_sync=False):  # type: (KeeperParams, List[ImportSharedFolder], bool) -> None
    if not shared_folders:
        return

    folders = [x for x in shared_folders if isinstance(x, ImportSharedFolder) and x.permissions]
    if not folders:
        return

    sync_down.sync_down(params)

    folder_lookup = {}
    if params.folder_cache:
        for f_uid in params.folder_cache:
            fol = params.folder_cache[f_uid]
            f_key = '{0}|{1}'.format((fol.name or '').casefold().strip(), fol.parent_uid or '')
            folder_lookup[f_key] = f_uid, fol.type

    for fol in folders:
        comps = list(path_components(fol.path))
        parent_uid = ''
        for i in range(len(comps)):
            is_last = False
            if i == len(comps) - 1:
                is_last = True
            comp = comps[i]
            if not comp:
                continue
            f_key = '{0}|{1}'.format(comp.casefold(), parent_uid)
            if f_key in folder_lookup:
                parent_uid, fol_type = folder_lookup[f_key]
                if is_last and fol_type == BaseFolderNode.SharedFolderType:
                    fol.uid = parent_uid
            else:
                break

    folders = [x for x in folders if x.uid in params.shared_folder_cache]
    if folders:
        permissions = prepare_folder_permission(params, folders, full_sync)
        if permissions:
            teams_added = 0
            users_added = 0
            teams_updated = 0
            users_updated = 0
            teams_removed = 0
            users_removed = 0
            while len(permissions) > 0:
                chunk = permissions[:999]
                permissions = permissions[999:]
                rqs = folder_pb2.SharedFolderUpdateV3RequestV2()
                for rq in chunk:
                    if isinstance(rq, folder_pb2.SharedFolderUpdateV3Request):
                        rqs.sharedFoldersUpdateV3.append(rq)
                try:
                    rss = api.communicate_rest(params, rqs, 'vault/shared_folder_update_v3', payload_version=1,
                                               rs_type=folder_pb2.SharedFolderUpdateV3ResponseV2)
                    for rs in rss.sharedFoldersUpdateV3Response:
                        if rs.status == 'success':
                            if len(rs.sharedFolderAddUserStatus) > 0:
                                users_added += len([x for x in rs.sharedFolderAddUserStatus if x.status == 'success'])
                            if len(rs.sharedFolderAddTeamStatus) > 0:
                                teams_added += len([x for x in rs.sharedFolderAddTeamStatus if x.status == 'success'])
                            if len(rs.sharedFolderUpdateUserStatus) > 0:
                                users_updated += len([x for x in rs.sharedFolderUpdateUserStatus if x.status == 'success'])
                            if len(rs.sharedFolderUpdateTeamStatus) > 0:
                                teams_updated += len([x for x in rs.sharedFolderUpdateTeamStatus if x.status == 'success'])
                            if len(rs.sharedFolderRemoveUserStatus) > 0:
                                users_removed += len([x for x in rs.sharedFolderRemoveUserStatus if x.status == 'success'])
                            if len(rs.sharedFolderRemoveTeamStatus) > 0:
                                teams_removed += len([x for x in rs.sharedFolderRemoveTeamStatus if x.status == 'success'])
                        else:
                            shared_folder_uid = utils.base64_url_encode(rs.sharedFolderUid)
                            logging.warning('Shared Folder "%s" update error: %s', shared_folder_uid, rs.status)
                except Exception as e:
                    logging.warning('Shared Folders update error: %s', e)
            sync_down.sync_down(params)

            if teams_added > 0:
                logging.info("%d team(s) added to shared folders", teams_added)
            if users_added > 0:
                logging.info("%d user(s) added to shared folders", users_added)
            if teams_updated > 0:
                logging.info("%d team(s) updated in shared folders", teams_updated)
            if users_updated > 0:
                logging.info("%d user(s) updated in shared folders", users_updated)
            if teams_removed > 0:
                logging.info("%d team(s) removed from shared folders", teams_removed)
            if users_removed > 0:
                logging.info("%d user(s) removed from shared folders", users_removed)


def _import(params, file_format, filename, **kwargs):
    """Import records from one of a variety of sources."""
    shared = kwargs.get('shared') or False
    import_users = kwargs.get('users_only') or False
    old_domain = kwargs.get('old_domain')
    new_domain = kwargs.get('new_domain')
    tmpdir = kwargs.get('tmpdir')
    record_type = kwargs.get('record_type')
    filter_folder = kwargs.get('filter_folder')
    dry_run = kwargs.get('dry_run') is True
    show_skipped = kwargs.get('show_skipped') is True

    import_into = kwargs.get('import_into') or ''
    if import_into:
        import_into = import_into.replace(PathDelimiter, 2*PathDelimiter)
    update_flag = kwargs.get('update_flag') or False

    importer = importer_for_format(file_format)()  # type: BaseImporter

    records_before = len(params.record_cache)

    folders = []        # type: List[ImportSharedFolder]
    records = []        # type: List[ImportRecord]
    files = []          # type: List[ImportFile]

    filter_folder_lower = filter_folder.lower() if isinstance(filter_folder, str) else ''

    for x in importer.execute(filename, params=params, users_only=import_users, filter_folder=filter_folder,
                              old_domain=old_domain, new_domain=new_domain, tmpdir=tmpdir, dry_run=dry_run):
        if isinstance(x, ImportRecord):
            if filter_folder and not importer.support_folder_filter():
                if not x.folders:
                    continue
                folder_match = None

                for f in x.folders:
                    if f.domain:
                        name = f.domain.lower()
                        if name == filter_folder_lower or name.startswith(f'{filter_folder_lower}\\'):
                            folder_match = f
                            break
                    elif f.path:
                        name = f.path.lower().lstrip('\\')
                        if name == filter_folder_lower or name.startswith(f'{filter_folder_lower}\\'):
                            folder_match = f
                            break
                if folder_match:
                    x.folders = [folder_match]
                else:
                    continue

            if shared or import_into:
                if not x.folders:
                    x.folders = [ImportFolder()]
                for f in x.folders:
                    if shared:
                        d_comps = list(path_components(f.domain)) if f.domain else []
                        p_comps = list(path_components(f.path)) if f.path else []
                        if len(d_comps) > 0:
                            f.domain = d_comps[0]
                            p_comps[0:0] = d_comps[1:]
                        elif len(p_comps) > 0:
                            f.domain = p_comps[0]
                            p_comps = p_comps[1:]
                        f.path = PathDelimiter.join([x.replace(PathDelimiter, 2*PathDelimiter) for x in p_comps])
                    if import_into:
                        if f.domain:
                            f.domain = PathDelimiter.join([import_into, f.domain])
                        elif f.path:
                            f.path = PathDelimiter.join([import_into, f.path])
                        else:
                            f.path = import_into

            if record_type and not x.type:
                x.type = record_type
            try:
                x.validate()
            except CommandError as ce:
                logging.info(ce.message)
            records.append(x)
        elif isinstance(x, ImportSharedFolder):
            if shared:
                continue
            if filter_folder and not importer.support_folder_filter():
                name = x.path.lower().lstrip('\\')
                if name != filter_folder_lower:
                    if not name.startswith(f'{filter_folder_lower}\\'):
                        continue
            x.validate()
            if import_into:
                if x.path:
                    x.path = PathDelimiter.join([import_into, x.path])

            folders.append(x)

    if import_users:
        import_user_permissions(params, folders)
        return

    sync_down.sync_down(params)

    manage_users = kwargs.get('manage_users') or False
    manage_records = kwargs.get('manage_records') or False
    can_edit = kwargs.get('can_edit') or False
    can_share = kwargs.get('can_share') or False

    if shared:
        sfol = set()
        for r in records:
            if r.folders:
                for f in r.folders:
                    if f.domain:
                        sfol.add(f.domain)
        for x in sfol:
            sf = ImportSharedFolder()
            sf.path = x
            sf.manage_users = manage_users
            sf.manage_records = manage_records
            sf.can_edit = can_edit
            sf.can_share = can_share
            folders.append(sf)

    # shared folder mapping
    sf_map = {}     # type: Dict[str, str]
    for shared_folder_uid in params.shared_folder_cache:
        folder = params.folder_cache.get(shared_folder_uid)
        if not folder:
            continue
        if folder.parent_uid:
            sf_path = get_folder_path(params, folder.parent_uid)
            sf_path.strip(PathDelimiter)
        else:
            sf_path = ''
        sf_name = folder.name.strip()
        if ' - ' in sf_name:
            sf_from_name = sf_name.replace(' - ', PathDelimiter)
            sf_to_name = folder.name
            if sf_path:
                sf_from_name = sf_path + PathDelimiter + sf_from_name
                sf_to_name = sf_path + PathDelimiter + sf_to_name
            sf_map[sf_from_name.lower()] = sf_to_name
    if len(sf_map) > 0:
        sf_keys = list(sf_map.keys())
        sf_keys.sort()
        for record in records:
            if isinstance(record.folders, list) and len(record.folders) > 0:
                for fol in record.folders:
                    path = fol.domain or ''
                    if fol.path:
                        if path:
                            path += PathDelimiter
                        path += fol.path
                    path_l = path.lower()
                    idx = bisect.bisect_right(sf_keys, path_l)
                    if 0 <= idx < len(sf_map) and path_l == sf_keys[idx]:
                        fol.domain = sf_map[path_l]
                        fol.path = ''
                    elif 0 < idx <= len(sf_map) and path_l.startswith(sf_keys[idx - 1]):
                        sf_name = sf_keys[idx - 1]
                        fol.domain = sf_map[sf_name]
                        fol.path = (path[len(sf_name):]).strip(PathDelimiter)

    folder_add = prepare_folder_add(params, folders, records, manage_users, manage_records, can_edit, can_share)
    if folder_add:
        if not dry_run:
            fol_rs, _ = execute_import_folder_record(params, folder_add, None)
            _ = fol_rs
            sync_down.sync_down(params)

    record_keys = {}
    audit_uids = []

    if records:  # create/update records
        records_v2_to_add = []      # type: List[folder_pb2.RecordRequest]
        records_v2_to_update = []   # type: List[dict]
        records_v3_to_add = []      # type: List[record_pb2.RecordAdd]
        records_v3_to_update = []   # type: List[record_pb2.RecordUpdate]
        import_uids = {}

        records_to_import, record_exists, external_lookup = prepare_record_add_or_update(update_flag, params, records)
        if show_skipped and record_exists:
            for existing_record in record_exists:
                folder_name = ''
                if existing_record.folders:
                    f = existing_record.folders[0]
                    if f.domain:
                        folder_name = f.domain + '\\'
                    if f.path:
                        folder_name += f.path

                if folder_name:
                    logging.info('Record "%s" appearing in Folder "%s" was skipped due to a duplicate record [%s] found.',
                                 existing_record.title, folder_name, existing_record.uid)
                else:
                    logging.info('Record "%s" was skipped due to a duplicate record [%s] found.',
                                 existing_record.title, existing_record.uid)
        reference_uids = set()

        table = []
        header = ['Folder', 'Title', 'Username', 'URL', 'Last Modified', 'Record UID']
        for import_record in records_to_import:
            existing_record = params.record_cache.get(import_record.uid)

            if dry_run:
                record_folder = ''
                if isinstance(import_record.folders, list) and len(import_record.folders) > 0:
                    f = import_record.folders[0]
                    record_folder = f.domain or ''
                    if f.path:
                        if record_folder:
                            record_folder += '\\'
                        record_folder += f.path
                modification_time = ''
                if isinstance(import_record.last_modified, int) and import_record.last_modified > 0:
                    ts = import_record.last_modified
                    if ts > 2000000000:
                        ts = int(ts / 1000)
                    if 1000000000 < ts < 2000000000:
                        dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
                        modification_time = dt.astimezone().strftime('%x %X')

                table.append([record_folder, import_record.title, import_record.login, import_record.login_url,
                              modification_time, existing_record.get('record_uid') if existing_record else ''])
                continue

            record_key = existing_record['record_key_unencrypted'] if existing_record else utils.generate_aes_key()
            record_keys[import_record.uid] = record_key
            reference_uids.clear()
            if import_record.references:
                for ref in import_record.references:
                    reference_uids.update([x for x in ref.uids if x in params.record_cache])
            if import_record.fields:
                for field in import_record.fields:
                    if field.type == 'script' and isinstance(field.value, dict):
                        if 'fileRef' in field.value:
                            reference_uids.add(field.value['fileRef'])

            if import_record.type and import_record.fields:
                for field in import_record.fields:
                    if field.type in RecordV3.field_values:
                        type_value = RecordV3.field_values[field.type].get('value')
                        if type_value is None:
                            continue
                        field_type = type(type_value)
                        if isinstance(field.value, list):
                            field.value = [x for x in field.value if isinstance(x, field_type)]
                        else:
                            if not isinstance(field.value, field_type):
                                field.value = copy.deepcopy(type_value)

            if existing_record:
                version = existing_record.get('version', 0)
                if version == 3:   # V3
                    orig_record = vault.KeeperRecord.load(params, existing_record)
                    if not isinstance(orig_record, vault.TypedRecord):
                        continue

                    if not import_record.type:
                        import_record.type = orig_record.record_type

                    v3_upd_rq = record_pb2.RecordUpdate()
                    v3_upd_rq.record_uid = utils.base64_url_decode(import_record.uid)
                    import_uids[import_record.uid] = {'ver': 'v3', 'op': 'update'}
                    v3_upd_rq.client_modified_time = utils.current_milli_time()
                    v3_upd_rq.revision = existing_record.get('revision') or 0
                    data = _construct_record_v3_data(import_record, orig_record)
                    v3_upd_rq.data = crypto.encrypt_aes_v2(api.get_record_data_json_bytes(data), record_key)
                    data_size = len(v3_upd_rq.data)
                    if data_size > RECORD_MAX_DATA_LEN:
                        logging.warning(RECORD_MAX_DATA_WARN.format(data['title'], data_size, RECORD_MAX_DATA_LEN))
                        continue

                    orig_refs = vault_extensions.extract_typed_record_refs(orig_record)
                    for uid in orig_refs.difference(reference_uids):
                        v3_upd_rq.record_links_remove.append(utils.base64_url_decode(uid))

                    for uid in reference_uids.difference(orig_refs):
                        link = record_pb2.RecordLink()
                        link.record_uid = utils.base64_url_decode(uid)
                        v3_upd_rq.record_links_add.append(link)

                    records_v3_to_update.append(v3_upd_rq)
                elif version == 2:
                    orig_extra = json.loads(existing_record['extra_unencrypted']) if 'extra_unencrypted' in existing_record else None

                    data, extra = _construct_record_v2(import_record, orig_extra)
                    encrypted_data = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), record_key)
                    v2_upd_rq = {
                        'record_uid': import_record.uid,
                        'data': utils.base64_url_encode(encrypted_data),
                        'version': 2,
                        'client_modified_time': api.current_milli_time(),
                        'revision': existing_record.get('revision') or 0,
                    }
                    import_uids[import_record.uid] = {'ver': 'v2', 'op': 'update'}
                    if extra:
                        encrypted_extra = crypto.encrypt_aes_v1(json.dumps(extra).encode('utf-8'), record_key)
                        v2_upd_rq['extra'] = utils.base64_url_encode(encrypted_extra)

                    records_v2_to_update.append(v2_upd_rq)
            else:
                # pick a folder to insert the record
                folder_type = BaseFolderNode.UserFolderType
                folder_uid = ''
                shared_folder_key = b''
                if import_record.folders:
                    folder_uid = import_record.folders[0].uid
                if folder_uid in params.folder_cache:
                    folder = params.folder_cache[folder_uid]    # type: Union[BaseFolderNode, SharedFolderFolderNode]
                    folder_type = folder.type
                    if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                        shared_folder_uid = folder.uid if folder.type == BaseFolderNode.SharedFolderType else folder.shared_folder_uid
                        shared_folder = params.shared_folder_cache[shared_folder_uid]
                        shared_folder_key = shared_folder.get('shared_folder_key_unencrypted')
                    else:
                        if folder.type == BaseFolderNode.RootFolderType:
                            folder_uid = ''

                if import_record.type:   # V3
                    v3_add_rq = record_pb2.RecordAdd()
                    v3_add_rq.record_uid = utils.base64_url_decode(import_record.uid)
                    import_uids[import_record.uid] = {'ver': 'v3', 'op': 'add'}
                    v3_add_rq.client_modified_time = utils.current_milli_time()
                    data = _construct_record_v3_data(import_record)
                    v3_add_rq.data = crypto.encrypt_aes_v2(api.get_record_data_json_bytes(data), record_key)
                    data_size = len(v3_add_rq.data)
                    if data_size > RECORD_MAX_DATA_LEN:
                        logging.warning(RECORD_MAX_DATA_WARN.format(data['title'], data_size, RECORD_MAX_DATA_LEN))
                        continue

                    v3_add_rq.record_key = crypto.encrypt_aes_v2(record_key, params.data_key)
                    v3_add_rq.folder_type = \
                        record_pb2.user_folder if folder_type == BaseFolderNode.UserFolderType else \
                        record_pb2.shared_folder if folder_type == BaseFolderNode.SharedFolderType else \
                        record_pb2.shared_folder_folder

                    if folder_uid:
                        v3_add_rq.folder_uid = utils.base64_url_decode(folder_uid)
                        if shared_folder_key:
                            v3_add_rq.folder_key = crypto.encrypt_aes_v2(record_key, shared_folder_key)
                    for uid in reference_uids:
                        link = record_pb2.RecordLink()
                        link.record_uid = utils.base64_url_decode(uid)
                        v3_add_rq.record_links.append(link)

                    if params.enterprise_ec_key:
                        audit_data = {
                            'title': import_record.title,
                            'record_type': import_record.type
                        }
                        if import_record.login_url:
                            audit_data['url'] = utils.url_strip(import_record.login_url)
                        v3_add_rq.audit.version = 0
                        v3_add_rq.audit.data = crypto.encrypt_ec(json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)

                    records_v3_to_add.append(v3_add_rq)
                else:
                    v2_add_rq = folder_pb2.RecordRequest()
                    v2_add_rq.recordUid = utils.base64_url_decode(import_record.uid)
                    import_uids[import_record.uid] = {'ver': 'v2', 'op': 'add'}
                    v2_add_rq.recordType = 0
                    v2_add_rq.howLongAgo = 0
                    data, extra = _construct_record_v2(import_record)
                    v2_add_rq.recordData = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), record_key)
                    if extra:
                        v2_add_rq.extra = crypto.encrypt_aes_v1(json.dumps(extra).encode('utf-8'), record_key)
                    v2_add_rq.encryptedRecordKey = crypto.encrypt_aes_v1(record_key, params.data_key)
                    v2_add_rq.folderType = \
                        folder_pb2.user_folder if folder_type == BaseFolderNode.UserFolderType else \
                        folder_pb2.shared_folder if folder_type == BaseFolderNode.SharedFolderType else \
                        folder_pb2.shared_folder_folder
                    if folder_uid:
                        v2_add_rq.folderUid = utils.base64_url_decode(folder_uid)
                        if shared_folder_key:
                            v2_add_rq.encryptedRecordFolderKey = crypto.encrypt_aes_v1(record_key, shared_folder_key)

                    records_v2_to_add.append(v2_add_rq)
                    if params.enterprise_ec_key:
                        audit_uids.append(import_record.uid)

        if dry_run:
            base.dump_report_data(table, header)
            return

        for v3_add_rq in records_v3_to_add:
            record_uid = utils.base64_url_encode(v3_add_rq.record_uid)
            record_key = record_keys.get(record_uid)
            for link in v3_add_rq.record_links:
                link_uid = link.record_uid
                link_key = record_keys.get(link_uid)
                if record_key and link_key:
                    link.record_key = crypto.encrypt_aes_v2(link_key, record_key)

        for v3_upd_rq in records_v3_to_update:
            record_uid = utils.base64_url_encode(v3_upd_rq.record_uid)
            record_key = record_keys.get(record_uid)
            for link in v3_upd_rq.record_links_add:
                link_uid = link.record_uid
                link_key = record_keys.get(link_uid)
                if record_key and link_key:
                    link.record_key = crypto.encrypt_aes_v2(link_key, record_key)

        if records_v2_to_add:
            _, rec_rs = execute_import_folder_record(params, None, records_v2_to_add)
        if records_v3_to_add:
            rec_rs = execute_records_add(params, records_v3_to_add)
        if records_v2_to_update:
            execute_update_v2_record(params, records_v2_to_update)
        if records_v3_to_update:
            rec_rs = execute_records_update(params, records_v3_to_update)

        sync_down.sync_down(params)

        # update audit data
        if audit_uids and params.enterprise_ec_key:
            audit_records = list(prepare_record_audit(params, audit_uids))
            while audit_records:
                try:
                    rq = record_pb2.AddAuditDataRequest()
                    rq.records.extend(audit_records[:999])
                    audit_records = audit_records[999:]
                    api.communicate_rest(params, rq, 'vault/record_add_audit_data')
                except Exception as e:
                    logging.debug('Update record audit error: %s', e)
            sync_down.sync_down(params)

        # ensure records are linked to folders
        record_links = prepare_record_link(params, records)
        if record_links:
            api.execute_batch(params, record_links)
            sync_down.sync_down(params)

        # adjust shared folder permissions
        shared_update = prepare_record_permission(params, records)
        if shared_update:
            api.execute_batch(params, shared_update)
            sync_down.sync_down(params)

        # upload attachments
        v2_atts = []
        v3_atts = []
        for r in records:
            if r.attachments:
                if r.uid in import_uids:
                    ver = import_uids[r.uid]['ver']
                    if ver == 'v3':
                        v3_atts.append(r)
                    else:
                        for a in r.attachments:
                            v2_atts.append((r.uid, a))
                elif r.uid in external_lookup:
                    existing_record = params.record_cache[external_lookup[r.uid]]
                    existing_data = json.loads(existing_record['data_unencrypted'])
                    filerefs = [f for f in existing_data.get('fields', []) if f['type'] == 'fileRef']
                    if len(filerefs) > 0:
                        existing_attachments = [
                            params.record_cache[u] for u in filerefs[0].get('value') or [] if u in params.record_cache
                        ]
                        attachment_data = [json.loads(a['data_unencrypted']) for a in existing_attachments]
                    else:
                        attachment_data = []

                    found_attachments = []
                    missing_attachments = []
                    for a in r.attachments:
                        data = [
                            d for d in attachment_data if d.get('title') == a.name and d.get('size') == a.size
                        ]
                        if len(data) > 0:
                            found_attachments.append(a)
                        else:
                            missing_attachments.append(a)

                    if found_attachments:
                        found = len(found_attachments)
                        total = len(r.attachments)
                        print(f'Found {found} of {total} attachments in record {r.title}.')
                        if missing_attachments:
                            for a in found_attachments:
                                r.attachments.remove(a)

                    if missing_attachments:
                        r.uid = external_lookup[r.uid]
                        if r.type:
                            v3_atts.append(r)

        if len(v2_atts) > 0:
            upload_attachment(params, v2_atts)
        if len(v3_atts) > 0:
            upload_v3_attachments(params, v3_atts)

    if hasattr(importer, 'cleanup') and callable(importer.cleanup):
        importer.cleanup()

    records_after = len(params.record_cache)
    if records_after > records_before:
        params.queue_audit_event('imported_records', file_format=file_format.upper())
        logging.info("%d records imported successfully", records_after - records_before)


def report_statuses(status_type, status_iter):
    """Report status codes from list of folder_pb2.*Response."""
    counter = collections.Counter(element.lower() for element in status_iter)
    for status, count in sorted(counter.items()):
        logging.info('%-15s %-15s %d', status_type, status, count)


def chunks(list_, n):
    """
    Yield successive n-sized chunks from list_.

    Based on https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
    """
    for offset in range(0, len(list_), n):
        yield list_[offset:offset + n]


def execute_update_v2_record(params, records_to_update):
    """Interact with the API to update preexisting records: we only change the password(s)."""
    for chunk in chunks(records_to_update, 100):
        request = {
            'command': 'record_update',
            'username': params.user,
            'session_token': params.session_token,
            'client_version': CLIENT_VERSION,
            'locale': api.LOCALE,
            'pt': 'Commander',
            'client_time': api.current_milli_time(),
            'update_records': chunk,
            'device_id': 'Commander',
        }
        result = api.communicate(params, request)
        if isinstance(result, dict):
            if 'result' in result:
                # Note that this may appear more than once for an import with many password updates
                report_statuses('update', (element['status'] for element in result['update_records']))
            else:
                logging.info('overall operation failed')


def execute_import_folder_record(params, folders, records):
    """Interact with the API to import folders and records."""
    rs_folder = []
    rs_record = []
    while folders or records:
        rq = folder_pb2.ImportFolderRecordRequest()
        cap = 999
        if folders:
            chunk = folders[:cap]
            folders = folders[cap:]
            cap = cap - len(folders)
            for e in chunk:
                rq.folderRequest.append(e)
        if records and cap > 0:
            chunk = records[:cap]
            records = records[cap:]
            for e in chunk:
                rq.recordRequest.append(e)

        import_rs = api.communicate_rest(params, rq, "folder/import_folders_and_records", rs_type=folder_pb2.ImportFolderRecordResponse)
        if len(import_rs.folderResponse) > 0:
            rs_folder.extend(import_rs.folderResponse)
        if len(import_rs.recordResponse) > 0:
            rs_record.extend(import_rs.recordResponse)
        if len(folders or []) > 0 or len(records or []) > 0:
            time.sleep(5)

    report_statuses('folder', (element.status for element in rs_folder))
    report_statuses('legacy record', (element.status for element in rs_record))

    return rs_folder, rs_record


def record_status_to_str(status):  # type: (record_pb2.RecordModifyStatus) -> str
    if status == record_pb2.RS_SUCCESS:
        return 'success'
    if status == record_pb2.RS_OUT_OF_SYNC:
        return 'out of sync'
    if status == record_pb2.RS_ACCESS_DENIED:
        return 'access denied'
    if status == record_pb2.RS_SHARE_DENIED:
        return 'share denied'
    if status == record_pb2.RS_RECORD_EXISTS:
        return 'record exists'
    if status == record_pb2.RS_OLD_RECORD_VERSION_TYPE:
        return 'old record version type'
    return str(status)


def execute_records_add(params, records):  # type: (KeeperParams, List[record_pb2.RecordAdd]) -> List[record_pb2.RecordModifyResult]
    rs_record = []
    while records:
        rq = record_pb2.RecordsAddRequest()
        rq.client_time = utils.current_milli_time()
        rq.records.extend(records[:999])
        records = records[999:]
        rs = api.communicate_rest(params, rq, 'vault/records_add', rs_type=record_pb2.RecordsModifyResponse)
        rs_record.extend(rs.records)

    report_statuses('record', (record_status_to_str(x.status) for x in rs_record))

    return rs_record


def execute_records_update(params, records):  # type: (KeeperParams, List[record_pb2.RecordUpdate]) -> List[record_pb2.RecordModifyResult]
    rs_record = []
    while records:
        rq = record_pb2.RecordsUpdateRequest()
        rq.client_time = utils.current_milli_time()
        rq.records.extend(records[:999])
        records = records[999:]
        rs = api.communicate_rest(params, rq, 'vault/records_update', rs_type=record_pb2.RecordsModifyResponse)
        rs_record.extend(rs.records)

    report_statuses('record', (record_status_to_str(x.status) for x in rs_record))

    return rs_record


def upload_v3_attachments(params, records_with_attachments):  # type: (KeeperParams, list) -> None
    """Interact with the API to upload v3 attachments"""
    print('Uploading v3 attachments:')

    while len(records_with_attachments) > 0:
        file_attachment_chunk = 0
        rq = record_pb2.FilesAddRequest()
        uid_to_attachment = {}
        for i, parent_record in enumerate(records_with_attachments):
            file_attachment_chunk += len(parent_record.attachments)
            if file_attachment_chunk > FILE_ATTACHMENT_CHUNK and i > 0:
                records_with_attachments = records_with_attachments[i:]
                break
            parent_uid = parent_record.uid
            existing_record = params.record_cache.get(parent_uid)
            for atta in parent_record.attachments:  # type: ImportAttachment
                if not existing_record:
                    parent_title = getattr(parent_record, 'title', '')
                    logging.warning(
                        f'Upload of {atta.name} failed: Parent record {parent_title} ({parent_uid}) is missing.'
                    )
                    continue

                atta.prepare()
                if isinstance(atta.size, int):
                    if atta.size == 0:
                        continue
                    if atta.size > 100 * 2 ** 20:  # hard limit at 100MB for upload
                        logging.warning(
                            f'Upload of {atta.name} failed: File size of {atta.size} exceeds the 100MB maximum.'
                        )
                        continue
                else:
                    continue

                file_data = {
                    'name': atta.name,
                    'size': atta.size,
                    'title': atta.name,
                    'lastModified': api.current_milli_time(),
                    'type': 'application/octet-stream'
                }
                rdata = json.dumps(file_data).encode('utf-8')

                file_key = utils.generate_aes_key()
                file_uid = utils.base64_url_decode(api.generate_record_uid())

                rf = record_pb2.File()
                rf.record_uid = file_uid
                rf.record_key = crypto.encrypt_aes_v2(file_key, params.data_key)
                rf.data = crypto.encrypt_aes_v2(rdata, file_key)
                rf.fileSize = IV_LEN + atta.size + GCM_TAG_LEN
                rq.files.append(rf)
                uid_to_attachment[file_uid] = (atta, parent_uid, file_key)

        else:  # for i, parent_record in enumerate(records_with_attachments)
            records_with_attachments = []

        if len(rq.files) == 0:
            return

        rq.client_time = api.current_milli_time()
        files_add_rs = api.communicate_rest(params, rq, 'vault/files_add', rs_type=record_pb2.FilesAddResponse)

        new_attachments_by_parent_uid = {}  # type: Dict[str, List[Tuple[ImportAttachment, bytes, bytes]]]
        for f in files_add_rs.files:
            atta, parent_uid, file_key = uid_to_attachment[f.record_uid]
            status = record_pb2.FileAddResult.DESCRIPTOR.values_by_number[f.status].name
            success = (f.status == record_pb2.FileAddResult.DESCRIPTOR.values_by_name['FA_SUCCESS'].number)

            if not success:
                logging.warning(f'{bcolors.FAIL}Upload of {atta.name} failed with status: {status}{bcolors.ENDC}')
                continue

            with atta.open() as src:
                with EncryptionReader.get_buffered_reader(src, file_key) as encrypted_src:
                    form_files = {'file': (atta.name, encrypted_src, 'application/octet-stream')}
                    form_params = json.loads(f.parameters)
                    print(f'{atta.name} ... ', file=sys.stderr, end='', flush=True)
                    response = requests.post(f.url, data=form_params, files=form_files)

            if str(response.status_code) == form_params.get('success_action_status'):
                print('Done')
                new_attachments = new_attachments_by_parent_uid.get(parent_uid)
                if new_attachments:
                    new_attachments.append((atta, f.record_uid, file_key))
                else:
                    new_attachments_by_parent_uid[parent_uid] = [(atta, f.record_uid, file_key)]
            else:
                print('Failed')

        rec_list = []
        record_links_add = {}
        external_file_uids = {}    # type: Dict[str, str]
        new_attachments_uids = []
        for parent_uid, attachments in new_attachments_by_parent_uid.items():
            external_file_uids.clear()
            new_attachments_uids.clear()
            for a in attachments:
                orig_file_uid = a[0].file_uid
                new_file_uid = utils.base64_url_encode(a[1])
                if orig_file_uid:
                    external_file_uids[orig_file_uid] = new_file_uid
                new_attachments_uids.append(new_file_uid)

            record_data = params.record_cache[parent_uid].get('data_unencrypted')
            if record_data:
                if isinstance(record_data, bytes):
                    record_data = record_data.decode('utf-8')
                data = json.loads(record_data.strip())
            else:
                data = {}
            if 'fields' not in data:
                data['fields'] = []

            # attachments for script fields
            all_fields = itertools.chain(data['fields'], data.get('custom', []))
            script_fields = [x for x in all_fields if x.get('type') == 'script']
            for sf in script_fields:
                field_value = sf.get('value')
                if not isinstance(field_value, list):
                    continue
                for script in field_value:
                    if not isinstance(script, dict):
                        continue
                    file_uid = script.get('fileRef')
                    if isinstance(file_uid, str) and  file_uid in external_file_uids:
                        new_uid = external_file_uids[file_uid]
                        script['fileRef'] = new_uid
                        new_attachments_uids.remove(new_uid)

            # find first fileRef or create new fileRef if missing
            file_ref = next((ft for ft in data['fields'] if ft['type'] == 'fileRef'), None)
            if file_ref:
                file_ref['value'] = file_ref.get('value', []) + new_attachments_uids
            else:
                data['fields'].append({'type': 'fileRef', 'value': new_attachments_uids})

            new_data = json.dumps(data)
            params.record_cache[parent_uid]['data_unencrypted'] = new_data
            rec = api.get_record(params, parent_uid)
            rec_list.append(rec)

            parent_key = params.record_cache[parent_uid]['record_key_unencrypted']
            record_links_add[parent_uid] = [
                {'record_uid': a[1], 'record_key': crypto.encrypt_aes_v2(a[2], parent_key)} for a in attachments
            ]

        api.update_records_v3(params, rec_list, record_links_by_uid={'record_links_add': record_links_add}, silent=True)
        params.sync_data = True


def upload_attachment(params, attachments):
    """
    Interact with the API to upload attachments.

    :param attachments:
    :type attachments: [(str, ImportAttachment)]
    """
    print('Uploading attachments:')
    while len(attachments) > 0:
        chunk = attachments[:90]
        attachments = attachments[90:]

        uploads = None

        file_no = 0
        file_size = 0
        for _, att in chunk:
            file_no += 1
            file_size += att.size or 0

        # TODO check storage subscription
        rq = {
            'command': 'request_upload',
            'file_count': file_no
        }
        try:
            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                uploads = rs['file_uploads']
        except Exception as e:
            logging.error(e)
            return

        uploaded = {}
        crypter = crypto.StreamCrypter()
        crypter.is_gcm = False
        for record_id, atta in chunk:
            if not uploads:
                break

            try:
                upload = uploads.pop()
                key = utils.generate_aes_key()
                crypter.key = key
                with atta.open() as plain, crypter.set_stream(plain, True) as encypted:
                    files = {
                        upload['file_parameter']: (atta.name, encypted, 'application/octet-stream')
                    }
                    print('{0} ... '.format(atta.name), file=sys.stderr, end='', flush=True)
                    response = requests.post(upload['url'], files=files, data=upload['parameters'])
                    if response.status_code == upload['success_status_code']:
                        if record_id not in uploaded:
                            uploaded[record_id] = []
                        uploaded[record_id].append({
                            'key': utils.base64_url_encode(key),
                            'name': atta.name,
                            'file_id': upload['file_id'],
                            'size': crypter.bytes_read
                        })
                        print('Done')
                    else:
                        print('Failed')

            except Exception as e:
                logging.warning(e)

        if len(uploaded) > 0:
            rq = {
                'command': 'record_update',
                'pt': 'Commander',
                'device_id': 'Commander',
                'client_time': api.current_milli_time(),
                'update_records': []
            }
            for record_id in uploaded:
                if record_id in params.record_cache:
                    rec = params.record_cache[record_id]
                    extra = json.loads(rec['extra_unencrypted'].decode('utf-8')) if 'extra' in rec else {}
                    files = extra.get('files')
                    if files is None:
                        files = []
                        extra['files'] = files
                    udata = rec['udata'] if 'udata' in rec else {}
                    file_ids = udata.get('file_ids')
                    if file_ids is None:
                        file_ids = []
                        udata['file_ids'] = file_ids
                    for atta in uploaded[record_id]:
                        file_ids.append(atta['file_id'])
                        files.append({
                            'id': atta['file_id'],
                            'name': atta['name'],
                            'size': atta['size'],
                            'key': atta['key']
                        })

                    ru = {
                        'record_uid': record_id,
                        'version': 2,
                        'client_modified_time': api.current_milli_time(),
                        'extra': utils.base64_url_encode(
                            crypto.encrypt_aes_v1(json.dumps(extra).encode('utf-8'), rec['record_key_unencrypted'])),
                        'udata': udata,
                        'revision': rec['revision']
                    }
                    api.resolve_record_access_path(params, record_id, path=ru)
                    rq['update_records'].append(ru)
            try:
                rs = api.communicate(params, rq)
                if rs['result'] == 'success':
                    sync_down.sync_down(params)
            except Exception as e:
                logging.debug(e)


def prepare_folder_add(params, folders, records, manage_users, manage_records, can_edit, can_share):
    """Find what folders to import (?)."""
    folder_hash = {}
    for f_uid in params.folder_cache:
        fol = params.folder_cache[f_uid]
        h = hashlib.md5()
        hs = '{0}|{1}'.format((fol.name or '').lower(), fol.parent_uid or '')
        h.update(hs.encode())
        shared_folder_key = None
        if fol.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
            sf_uid = fol.shared_folder_uid if fol.type == BaseFolderNode.SharedFolderFolderType else fol.uid
            if sf_uid in params.shared_folder_cache:
                shared_folder_key = params.shared_folder_cache[sf_uid]['shared_folder_key_unencrypted']
        folder_hash[h.hexdigest()] = f_uid, fol.type, shared_folder_key

    folder_add = []      # type: [folder_pb2.FolderRequest]
    if folders:
        for fol in folders:
            skip_folder = False
            parent_uid = ''
            comps = list(path_components(fol.path))
            for i in range(len(comps)):
                comp = comps[i]
                h = hashlib.md5()
                hs = '{0}|{1}'.format(comp.lower(), parent_uid)
                h.update(hs.encode())
                digest = h.hexdigest()

                is_last = False
                if i == len(comps) - 1:
                    is_last = True

                if digest not in folder_hash:
                    folder_uid = api.generate_record_uid()
                    folder_type = 'shared_folder' if is_last else 'user_folder'

                    fol_req = folder_pb2.FolderRequest()
                    fol_req.folderUid = base64.urlsafe_b64decode(folder_uid + '==')
                    fol_req.folderType = 2 if folder_type == 'shared_folder' else 1

                    if parent_uid:
                        fol_req.parentFolderUid = base64.urlsafe_b64decode(parent_uid + '==')

                    folder_key = utils.generate_aes_key()
                    fol_req.encryptedFolderKey = crypto.encrypt_aes_v1(folder_key, params.data_key)

                    data = {'name': comp}
                    fol_req.folderData = crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), folder_key)

                    if folder_type == 'shared_folder':
                        fol_req.sharedFolderFields.encryptedFolderName = \
                            crypto.encrypt_aes_v1(comp.encode('utf-8'), folder_key)
                        fol_req.sharedFolderFields.manageUsers = fol.manage_users or manage_users
                        fol_req.sharedFolderFields.manageRecords = fol.manage_records or manage_records
                        fol_req.sharedFolderFields.canEdit = fol.can_edit or can_edit
                        fol_req.sharedFolderFields.canShare = fol.can_share or can_share

                    folder_add.append(fol_req)
                    folder_hash[digest] = folder_uid, folder_type, folder_key if folder_type == 'shared_folder' else None
                else:
                    folder_uid, folder_type, folder_key = folder_hash[digest]
                    if is_last:
                        skip_folder = folder_type != 'shared_folder'
                    else:
                        skip_folder = folder_type != 'user_folder'

                parent_uid = folder_uid
                if skip_folder:
                    break

    if records:
        for rec in records:
            if rec.folders:
                for fol in rec.folders:
                    parent_uid = ''
                    parent_shared_folder_uid = None
                    parent_shared_folder_key = None
                    parent_type = ''
                    for is_domain in [True, False]:
                        path = fol.domain if is_domain else fol.path
                        if not path:
                            continue

                        comps = list(path_components(path))
                        for i in range(len(comps)):
                            comp = comps[i]
                            h = hashlib.md5()
                            hs = '{0}|{1}'.format(comp.lower(), parent_uid)
                            h.update(hs.encode())
                            digest = h.hexdigest()

                            if digest not in folder_hash:
                                is_shared = False
                                if i == len(comps) - 1:
                                    is_shared = is_domain

                                folder_uid = api.generate_record_uid()
                                if not parent_type or parent_type == 'user_folder':
                                    folder_type = 'shared_folder' if is_shared else 'user_folder'
                                else:
                                    folder_type = 'shared_folder_folder'

                                fol_req = folder_pb2.FolderRequest()
                                fol_req.folderUid = base64.urlsafe_b64decode(folder_uid + '==')
                                fol_req.folderType = 2 \
                                    if folder_type == 'shared_folder' \
                                    else 3 \
                                    if folder_type == 'shared_folder_folder' \
                                    else 1

                                if parent_uid:
                                    fol_req.parentFolderUid = base64.urlsafe_b64decode(parent_uid + '==')
                                    if folder_type == 'shared_folder_folder' and parent_uid == parent_shared_folder_uid:
                                        fol_req.parentFolderUid = b''

                                folder_key = os.urandom(32)
                                if folder_type == 'shared_folder_folder':
                                    fol_req.encryptedFolderKey = \
                                        crypto.encrypt_aes_v1(folder_key, parent_shared_folder_key or params.data_key)
                                else:
                                    fol_req.encryptedFolderKey = crypto.encrypt_aes_v1(folder_key, params.data_key)

                                data = json.dumps({'name': comp})
                                fol_req.folderData = crypto.encrypt_aes_v1(data.encode('utf-8'), folder_key)

                                if folder_type == 'shared_folder':
                                    fol_req.sharedFolderFields.encryptedFolderName = \
                                        crypto.encrypt_aes_v1(comp.encode('utf-8'), folder_key)

                                    parent_shared_folder_key = folder_key
                                    parent_shared_folder_uid = folder_uid

                                elif folder_type == 'shared_folder_folder':
                                    if parent_shared_folder_uid:
                                        fol_req.sharedFolderFolderFields.sharedFolderUid = \
                                            base64.urlsafe_b64decode(parent_shared_folder_uid + '==')

                                folder_add.append(fol_req)
                                folder_hash[digest] = folder_uid, folder_type, parent_shared_folder_key
                            else:
                                folder_uid, folder_type, parent_shared_folder_key = folder_hash[digest]

                            if folder_type == 'shared_folder':
                                parent_shared_folder_uid = folder_uid

                            parent_uid = folder_uid
                            parent_type = folder_type

                    fol.uid = parent_uid

    return folder_add


def prepare_record_audit(params, uids):
    # type: (KeeperParams, Iterable[str]) -> Iterator[record_pb2.RecordAddAuditData]
    if not params.enterprise_ec_key:
        return
    for uid in uids:
        if uid in params.record_cache:
            keeper_record = params.record_cache[uid]
            import_record = convert_keeper_record(keeper_record)
            if import_record and import_record.title:
                title = import_record.title
                if len(title) > 900:
                    title = title[:900]
                record_type = import_record.type
                audit_data = {
                    'title': title,
                    'record_type': import_record.type
                }
                if import_record.login_url:
                    audit_data['url'] = utils.url_strip(import_record.login_url)
                record_audit_rq = record_pb2.RecordAddAuditData()
                record_audit_rq.record_uid = utils.base64_url_decode(uid)
                record_audit_rq.revision = 0
                record_audit_rq.data = crypto.encrypt_ec(json.dumps(audit_data).encode('utf-8'), params.enterprise_ec_key)
                yield record_audit_rq


RECORD_FIELD_TYPES = {'login', 'password', 'url'}
IGNORABLE_FIELD_TYPES = {'text', 'fileRef', 'cardRef', 'oneTimeCode'}


def value_to_token(value): # type: (any) -> str
    if not value:
        return ''
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return ','.join((value_to_token(x) for x in value))
    if isinstance(value, dict):
        pairs = [x for x in value.items()]
        pairs.sort(key=lambda x: x[0])
        return ';'.join(f'{k}={value_to_token(v)}' for k, v in pairs)
    return str(value)


def tokenize_record_key(record):   # type: (ImportRecord) -> Iterator[str]
    """
    Turn a record-to-import into an iterable of str's for hashing.  This is really about import --update.

    Examine just the relevant parts of the record.
    """
    record_type = record.type or ""
    yield f'$type:{record_type}'
    yield f'$title:{record.title or ""}'
    yield f'$login:{record.login or ""}'
    yield f'$url:{record.login_url or ""}'

    if record_type in {'', 'login'}:
        return

    excluded = {x for x in RECORD_FIELD_TYPES}
    excluded.update(IGNORABLE_FIELD_TYPES)
    fields = {x.name_key(): x.value for x in record.fields if x.type and x.type not in excluded}
    if record.type == 'bankCard':
        if '$paymentcard' in fields:
            payment_card = fields.pop('$paymentcard')
        else:
            payment_card = {}
        yield '$paymentcard:' + value_to_token(payment_card.get('cardNumber'))
    elif record.type == 'bankAccount':
        yield value_to_token(fields.get('bankAccount'))
        yield value_to_token(fields.get('name'))
    elif record.type == 'address':
        yield value_to_token(fields.get('address'))
    else:
        fields = [x for x in record.fields if x.type not in excluded]
        fields.sort(key=ImportRecordField.name_key, reverse=False)
        for field in fields:
            hash_value = field.hash_key()
            if hash_value:
                yield hash_value


def tokenize_full_import_record(record):   # type: (ImportRecord) -> Iterator[str]
    """
    Turn a record-to-import into an iterable of str's for hashing.

    Examine the entire record.
    """
    yield f'$type:{record.type or ""}'
    yield f'$title:{record.title or ""}'
    yield f'$login:{record.login or ""}'
    yield f'$password:{record.password or ""}'
    yield f'$url:{record.login_url or ""}'
    yield f'$notes:{record.notes or ""}'

    fields = [x for x in record.fields]
    fields.sort(key=ImportRecordField.name_key, reverse=False)
    for field in fields:
        hash_key = field.hash_key()
        if hash_key:
            yield hash_key


def _construct_record_v2(rec_to_import, orig_extra=None):  # type: (ImportRecord, Optional[dict]) -> (dict, dict)
    totp = None
    custom_fields = []
    for field in rec_to_import.fields:
        value = ''
        if isinstance(field.value, str):
            value = field.value
        elif isinstance(field.value, list):
            if len(field.value) > 0:
                if field.value[0]:
                    value = str(field.value[0])
        elif field.value:
            value = str(field.value)

        if field.type == FIELD_TYPE_ONE_TIME_CODE:
            if value:
                totp = value
        elif field.label == TWO_FACTOR_CODE:
            if value:
                totp = value
        else:
            name = vault.sanitize_str_field_value(field.label or field.type)
            custom_fields.append({
                'type': 'text',
                'name': name,
                'value': value
            })

    data = {
        'title': vault.sanitize_str_field_value(rec_to_import.title),
        'secret1': vault.sanitize_str_field_value(rec_to_import.login),
        'secret2': vault.sanitize_str_field_value(rec_to_import.password),
        'link': vault.sanitize_str_field_value(rec_to_import.login_url),
        'notes': vault.sanitize_str_field_value(rec_to_import.notes),
        'custom': custom_fields
    }

    if totp and orig_extra:
        if 'fields' in orig_extra:
            orig_totp = next((x.get('data') for x in orig_extra['fields'] if x.get('field_type') == 'totp'), None)
            if orig_totp == totp:
                totp = None

    extra = None
    if isinstance(totp, str):
        extra = orig_extra or {}
        if 'fields' in extra:
            fields = extra['fields']
        else:
            fields = []
            extra['fields'] = fields
        fields.append({
            'id': utils.generate_uid(),
            'field_type': 'totp',
            'field_title': 'Two-Factor Code',
            'type': 0,
            'data': totp
        })

    return data, extra

def _verify_typed_field_value(expected_value, value):
    if isinstance(expected_value, str):
        if not isinstance(value, str):
            value = str(value)
    elif isinstance(expected_value, int):
        if not isinstance(value, int):
            try:
                value = int(value)
            except ValueError:
                value = 0
    elif isinstance(expected_value, bool):
        if isinstance(value, int):
            value = value != 0
        elif isinstance(value, str):
            value = value.lower() in ('t', 'true', 'ok', 'y', 'yes')
    elif isinstance(expected_value, dict):
        pass
    return value


def _create_field_v3(schema, value):  # type: (RecordSchemaField, any) -> dict
    if value:
        if not isinstance(value, list):
            value = [value]
    else:
        value = []
    value = [x for x in value if x is not None]

    field_type = schema.ref or 'text'
    if field_type in record_types.RecordFields:
        rf = record_types.RecordFields[field_type]
        if rf.type in record_types.FieldTypes:
            ft = record_types.FieldTypes[rf.type]
            value = [_verify_typed_field_value(ft.value, x) for x in value]

    field = {
        'type': field_type,
        'value': value
    }
    if schema.label:
        field['label'] = schema.label
    if schema.required is True:
        field['required'] = True
    return field


def _construct_record_v3_data(rec_to_import, orig_record=None, map_data_custom_to_rec_fields=None):
    # type: (ImportRecord, Optional[vault.TypedRecord], Optional[dict]) -> dict
    # verify typed fields values
    for field in rec_to_import.fields:
        if field.label == TWO_FACTOR_CODE:
            field.type = 'oneTimeCode'
            field.label = ''
        if field.type in ('otp', 'oneTimeCode'):
            if isinstance(field.value, str) and field.value:
                comps = urlparse(field.value)
                if comps.scheme == 'otpauth':
                    q = parse_qs(comps.query, keep_blank_values=True)
                    if 'secret' in q and len(q['secret']) > 0:
                        secret = next((x for x in q['secret'] if len(x) > 0), None)
                        if secret:
                            continue
                    field.value = None
    data = {}
    if isinstance(orig_record, vault.TypedRecord):
        data.update(vault_extensions.extract_typed_record_data(orig_record))
    data['title'] = vault.sanitize_str_field_value(rec_to_import.title)
    data['type'] = vault.sanitize_str_field_value(rec_to_import.type)
    data['notes'] = vault.sanitize_str_field_value(rec_to_import.notes)
    record_fields = [x for x in rec_to_import.fields]
    record_refs = [x for x in rec_to_import.references or []]
    data['fields'] = []
    for field in rec_to_import.schema or []:
        if field.ref == 'login' and rec_to_import.login:
            data['fields'].append(_create_field_v3(field, rec_to_import.login))
            rec_to_import.login = ''
        elif field.ref == 'password' and rec_to_import.password:
            data['fields'].append(_create_field_v3(field, rec_to_import.password))
            rec_to_import.password = ''
        elif field.ref == 'url' and rec_to_import.login_url:
            data['fields'].append(_create_field_v3(field, rec_to_import.login_url))
            rec_to_import.login_url = ''
        else:
            index = -1
            if field.ref.endswith('Ref'):
                for i, ref_value in enumerate(record_refs):
                    if ref_value.type == field.ref:
                        index = i
                        break
                ref_value = record_fields.pop(index) if index >= 0 else None
                data['fields'].append(_create_field_v3(field, ref_value.value if ref_value else []))
            else:
                for i, field_value in enumerate(record_fields):
                    if field_value.type == field.ref and (field_value.label or '') == (field.label or ''):
                        index = i
                        break
                field_value = record_fields.pop(index) if index >= 0 else None
                data['fields'].append(_create_field_v3(field, field_value.value if field_value else []))

    data['custom'] = []
    if rec_to_import.login:
        field = RecordSchemaField()
        field.ref = 'login'
        data['custom'].append(_create_field_v3(field, rec_to_import.login))
        rec_to_import.login = ''

    if rec_to_import.password:
        field = RecordSchemaField()
        field.ref = 'password'
        data['custom'].append(_create_field_v3(field, rec_to_import.password))
        rec_to_import.password = ''

    if rec_to_import.login_url:
        field = RecordSchemaField()
        field.ref = 'url'
        data['custom'].append(_create_field_v3(field, rec_to_import.login_url))
        rec_to_import.login_url = ''

    for i, field_value in enumerate(record_fields):
        field = RecordSchemaField()
        field.ref = field_value.type or 'text'
        if field_value.label:
            field.label = field_value.label
        data['custom'].append(_create_field_v3(field, field_value.value))
        if map_data_custom_to_rec_fields is not None:
            map_data_custom_to_rec_fields[len(data['custom']) - 1] = i

    for reference in record_refs:
        field = RecordSchemaField()
        field.ref = reference.type + 'Ref'
        field.label = reference.label
        data['custom'].append(_create_field_v3(field, reference.uids))

    return data


def build_record_hash(tokens):    # type: (Iterator[str]) -> str
    """Build a sha256 hash of record using tokenize_gen."""
    hasher = hashlib.sha256()
    for token in tokens:
        hasher.update(token.encode())
    return hasher.hexdigest()


def prepare_record_add_or_update(update_flag, params, records):
    # type: (bool, KeeperParams, Iterable[ImportRecord]) -> Tuple[List[ImportRecord], List[ImportRecord], dict]
    """
    Find what records to import or update.

    If update_flag is False:
        If a 100% match is found for a record, then just skip requesting anything; it doesn't need to be changed.
        Otherwise import the record, risking creating an almost-duplicate.
    If update_flag is True:
       if a unique field match (on title, login, and url) is found, then request a change in password only.
    """
    preexisting_entire_record_hash = {}
    preexisting_partial_record_hash = {}
    for record_uid in params.record_cache:
        import_record = convert_keeper_record(params.record_cache[record_uid])
        if import_record:
            record_hash = build_record_hash(tokenize_full_import_record(import_record))
            preexisting_entire_record_hash[record_hash] = record_uid
            if update_flag:
                record_hash = build_record_hash(tokenize_record_key(import_record))
                preexisting_partial_record_hash[record_hash] = record_uid
        else:
            pass

    record_to_import = []   # type: List[ImportRecord]
    record_exists = []   # type: List[ImportRecord]
    record_uid_to_update = set()
    external_lookup = {}

    for import_record in records:
        if import_record.type:
            if len(import_record.notes or '') > RECORD_MAX_DATA_LEN - 2 * (2 ** 10):
                if import_record.attachments is None:
                    import_record.attachments = []
                atta = BytesAttachment(f'{import_record.title}_notes_field.txt', import_record.notes.encode('utf-8'))
                import_record.attachments.append(atta)
                import_record.notes = LARGE_FIELD_MSG.format(atta.name)

            for f in import_record.fields:
                if not f.value:
                    continue
                if not f.type:
                    f.type = 'text'
                if isinstance(f.value, str):
                    if len(f.value) > RECORD_MAX_DATA_LEN - 2 * (2 ** 10):
                        if import_record.attachments is None:
                            import_record.attachments = []
                        atta = BytesAttachment(f'{import_record.title}_{f.type}_field.txt', f.value.encode('utf-8'))
                        import_record.attachments.append(atta)
                        f.value = LARGE_FIELD_MSG.format(atta.name)

        record_hash = build_record_hash(tokenize_full_import_record(import_record))
        if record_hash in preexisting_entire_record_hash:
            record_uid = preexisting_entire_record_hash[record_hash]
            if import_record.uid:
                external_lookup[import_record.uid] = record_uid
            import_record.uid = record_uid
            record_exists.append(import_record)
            continue

        if import_record.uid and import_record.uid in params.record_cache:
            record_uid_to_update.add(import_record.uid)
            record_to_import.append(import_record)
            continue
        elif update_flag:
            record_hash = build_record_hash(tokenize_record_key(import_record))
            if record_hash in preexisting_partial_record_hash:
                record_uid = preexisting_partial_record_hash[record_hash]
                if import_record.uid:
                    external_lookup[import_record.uid] = record_uid
                if record_uid not in record_uid_to_update:
                    record_uid_to_update.add(record_uid)
                    import_record.uid = record_uid
                    record_to_import.append(import_record)
                continue

        record_uid = utils.generate_uid()
        if import_record.uid:
            external_lookup[import_record.uid] = record_uid
        import_record.uid = record_uid
        record_to_import.append(import_record)

    record_types = {}
    if params.record_type_cache:
        for rts in params.record_type_cache.values():
            try:
                rto = json.loads(rts)
                if '$id' in rto:
                    record_types[rto['$id']] = rto
            except:
                pass

    for import_record in record_to_import:
        if not import_record.type:
            continue
        if import_record.schema:
            continue
        record_type = import_record.type
        if record_type in record_types:
            fields = record_types[record_type].get('fields') or []
            import_record.schema = []
            for field in fields:
                if '$ref' in field:
                    f = RecordSchemaField()
                    f.ref = field['$ref']
                    f.label = field.get('label') or ''
                    if 'required' in field:
                        if field['required']:
                            f.required = True
                    import_record.schema.append(f)

    # re-link references
    for import_record in record_to_import:
        if import_record.references:
            for ref in import_record.references:
                ref.uids = [external_lookup[x] for x in ref.uids if x in external_lookup]
        if import_record.fields:
            scripts = [x for x in import_record.fields if x.type == 'script']
            for script in scripts:
                if isinstance(script, dict):
                    if 'recordRef' in script:
                        script['recordRef'] = [external_lookup.get(x) or x for x in script['recordRef']]

    return record_to_import, record_exists, external_lookup


def prepare_record_link(params, records):
    """Prepare record links to folders."""
    record_folders = {}    # type: [str, [str]]
    record_links = []
    for rec in records:
        if rec.uid:
            if rec.uid in params.record_cache:
                if rec.uid in record_folders:
                    folder_ids = record_folders[rec.uid]
                else:
                    folder_ids = list(find_folders(params, rec.uid))
                    record_folders[rec.uid] = folder_ids
                record = params.record_cache[rec.uid]
                for fol in rec.folders or [None]:
                    folder_uid = fol.uid if fol else ''
                    if folder_uid and folder_uid not in params.folder_cache:
                        continue
                    if folder_uid in folder_ids:
                        continue
                    if len(folder_ids) > 0:
                        folder_ids.append(folder_uid)
                        src_folder = params.folder_cache[folder_ids[0]]
                        dst_folder = params.folder_cache[folder_uid] if folder_uid in params.folder_cache else params.root_folder
                        ft = dst_folder.type if dst_folder.type != BaseFolderNode.RootFolderType else BaseFolderNode.UserFolderType
                        req = {
                            'command': 'move',
                            'to_type': ft,
                            'link': True,
                            'move': [],
                            'transition_keys': []
                        }
                        if dst_folder.type != BaseFolderNode.RootFolderType:
                            req['to_uid'] = dst_folder.uid
                        ft = src_folder.type if src_folder.type != BaseFolderNode.RootFolderType else BaseFolderNode.UserFolderType
                        mo = {
                            'type': 'record',
                            'uid': rec.uid,
                            'from_type': ft,
                            'cascade': True
                        }
                        if src_folder.type != BaseFolderNode.RootFolderType:
                            mo['from_uid'] = src_folder.uid
                        req['move'].append(mo)

                        transition_key = None
                        record_key = record['record_key_unencrypted']
                        if src_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                            if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                                ssf_uid = src_folder.uid if src_folder.type == BaseFolderNode.SharedFolderType else \
                                    src_folder.shared_folder_uid
                                dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else \
                                    dst_folder.shared_folder_uid
                                if ssf_uid != dsf_uid:
                                    shf = params.shared_folder_cache[dsf_uid]
                                    transition_key = utils.base64_url_encode(
                                        crypto.encrypt_aes_v1(record_key, shf['shared_folder_key_unencrypted']))
                            else:
                                transition_key = utils.base64_url_encode(crypto.encrypt_aes_v1(record_key, params.data_key))
                        else:
                            if dst_folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                                dsf_uid = dst_folder.uid if dst_folder.type == BaseFolderNode.SharedFolderType else \
                                    dst_folder.shared_folder_uid
                                shf = params.shared_folder_cache[dsf_uid]
                                transition_key = utils.base64_url_encode(
                                    crypto.encrypt_aes_v1(record_key, shf['shared_folder_key_unencrypted']))
                        if transition_key is not None:
                            req['transition_keys'].append({
                                'uid': rec.uid,
                                'key': transition_key
                            })
                        record_links.append(req)
    return record_links


def prepare_folder_permission(params, folders, full_sync):
    # type: (KeeperParams, List[ImportSharedFolder], bool) -> list
    """Prepare a list of API interactions for changes to folder permissions."""
    shared_folder_lookup = {}
    api.load_available_teams(params)
    for shared_folder_uid in params.shared_folder_cache:
        path = get_folder_path(params, shared_folder_uid)
        if path:
            shared_folder_lookup[path.strip()] = shared_folder_uid

    email_pattern = re.compile(EMAIL_PATTERN)
    emails_to_add = set()
    teams_to_add = set()
    for fol in folders:
        shared_folder_uid = shared_folder_lookup.get(fol.path)
        if not shared_folder_uid:
            logging.debug('Cannot resolve shared folder UID by path: %s', fol.path)
            continue
        shared_folder = params.shared_folder_cache.get(shared_folder_uid)
        if not shared_folder:
            logging.debug('Cannot resolve shared folder by UID: %s', shared_folder_uid)
            continue
        shared_folder_key = shared_folder.get('shared_folder_key_unencrypted')
        if not shared_folder_key:
            logging.debug('Shared folder \"%s\" does not have a key', shared_folder_uid)
            continue

        logging.debug('Verify permissions for shared folder \"%s\"', fol.path)

        if fol.permissions:
            for perm in fol.permissions:
                if perm.uid:
                    if 'teams' in shared_folder:
                        found = next((True for x in shared_folder['teams'] if x['team_uid'] == perm.uid), False)
                        if found:
                            continue
                    teams_to_add.add(perm.uid)
                    if perm.name:
                        teams_to_add.add(perm.name)
                elif perm.name:
                    lower_name = perm.name.casefold()
                    match = email_pattern.match(perm.name)
                    if match:
                        if perm.name == params.user:
                            continue
                        if 'users' in shared_folder:
                            found = next((True for x in shared_folder['users'] if x['username'].lower() == lower_name), False)
                            if found:
                                continue
                        emails_to_add.add(perm.name.lower())
                    else:
                        if 'teams' in shared_folder:
                            found = next((True for x in shared_folder['teams'] if x['name'].lower() == lower_name), False)
                            if found:
                                continue
                        teams_to_add.add(perm.name)

    if len(emails_to_add) > 0:
        logging.debug('Loading public keys for %d user(s)', len(emails_to_add))
        api.load_user_public_keys(params, list(emails_to_add))

    if len(teams_to_add) > 0:
        logging.debug('Resolving team UIDs for %d team(s)', len(teams_to_add))
        team_uids = set()
        for t in teams_to_add:
            team_uid = next((
                x.get('team_uid') for x in (params.available_team_cache or []) if x.get('team_uid') == t or x.get('team_name').casefold() == t.casefold()
                ), None)
            if team_uid:
                team_uids.add(team_uid)
            else:
                logging.debug('\"%s\" cannot be resolved as team', t)
        if len(team_uids) > 0:
            logging.debug('Loading keys for %d team(s)', len(team_uids))
            api.load_team_keys(params, list(team_uids))

    folder_permissions = []
    for fol in folders:
        shared_folder_uid = shared_folder_lookup.get(fol.path)
        if not shared_folder_uid:
            continue
        shared_folder = params.shared_folder_cache.get(shared_folder_uid)
        if not shared_folder:
            continue
        shared_folder_key = shared_folder.get('shared_folder_key_unencrypted')
        if not shared_folder_key:
            continue

        existing_teams = set()
        if 'teams' in shared_folder:
            existing_teams.update((x['team_uid'] for x in shared_folder['teams']))
        existing_users = set()
        if 'users' in shared_folder:
            existing_users.update((x['username'] for x in shared_folder['users']))
            if params.user in existing_users:
                existing_users.remove(params.user)
        keep_teams = set()
        keep_users = set()

        if fol.permissions:
            add_users = []        # type: List[folder_pb2.SharedFolderUpdateUser]
            add_teams = []        # type: List[folder_pb2.SharedFolderUpdateTeam]
            update_users = []     # type: List[folder_pb2.SharedFolderUpdateUser]
            update_teams = []     # type: List[folder_pb2.SharedFolderUpdateTeam]
            remove_users = []     # type: List[str]
            remove_teams = []     # type: List[str]
            for perm in fol.permissions:
                team_uid = None
                username = None
                try:
                    if perm.uid and any(True for x in params.available_team_cache if x.get('team_uid') == perm.uid):
                        team_uid = perm.uid
                    elif perm.name:
                        name = perm.name.casefold()
                        team_uid = next((x.get('team_uid') for x in params.available_team_cache if x.get('team_name').casefold() == name), None)
                        if team_uid is None:
                            username = name

                    if team_uid:
                        folder_team = None
                        if 'teams' in shared_folder:
                            folder_team = next((x for x in shared_folder['teams'] if x['team_uid'] == team_uid), None)
                        if folder_team:
                            manage_users = folder_team.get('manage_users') or False
                            manage_records = folder_team.get('manage_records') or False
                            keep_teams.add(team_uid)
                            if manage_users != perm.manage_users or manage_records != perm.manage_records:
                                sft = folder_pb2.SharedFolderUpdateTeam()
                                sft.teamUid = utils.base64_url_decode(team_uid)
                                sft.manageUsers = perm.manage_users
                                sft.manageRecords = perm.manage_records
                                update_teams.append(sft)
                        else:
                            sft = folder_pb2.SharedFolderUpdateTeam()
                            sft.teamUid = utils.base64_url_decode(team_uid)
                            sft.manageUsers = perm.manage_users
                            sft.manageRecords = perm.manage_records
                            keep_teams.add(team_uid)
                            if team_uid in params.team_cache:
                                team = params.team_cache[team_uid]
                                if 'team_key_unencrypted' in team:
                                    team_key = team['team_key_unencrypted']
                                    sft.sharedFolderKey = crypto.encrypt_aes_v1(shared_folder_key, team_key)
                                else:
                                    continue
                            elif team_uid in params.key_cache:
                                team_keys = params.key_cache[team_uid]
                                if team_keys.aes:
                                    sft.sharedFolderKey = crypto.encrypt_aes_v1(shared_folder_key, team_keys.aes)
                                elif team_keys.rsa:
                                    rsa_key = crypto.load_rsa_public_key(team_keys.rsa)
                                    sft.sharedFolderKey = crypto.encrypt_rsa(shared_folder_key, rsa_key)
                                else:
                                    continue
                            add_teams.append(sft)
                        continue

                    if username:
                        folder_user = None
                        if 'users' in shared_folder:
                            folder_user = next(
                                (x for x in shared_folder['users'] if x['username'].lower() == username), None)
                        sfu = folder_pb2.SharedFolderUpdateUser()
                        sfu.username = username
                        sfu.manageUsers = folder_pb2.BOOLEAN_TRUE \
                            if perm.manage_users else folder_pb2.BOOLEAN_FALSE
                        sfu.manageRecords = folder_pb2.BOOLEAN_TRUE \
                            if perm.manage_records else folder_pb2.BOOLEAN_FALSE

                        if folder_user:
                            keep_users.add(username)
                            manage_users = folder_user.get('manage_users') or False
                            manage_records = folder_user.get('manage_records') or False
                            if manage_users != perm.manage_users or manage_records != perm.manage_records:
                                update_users.append(sfu)
                        else:
                            if username in params.key_cache:
                                public_keys = params.key_cache[username]
                                if public_keys.rsa:
                                    keep_users.add(username)

                                    rsa_key = crypto.load_rsa_public_key(public_keys.rsa)
                                    sfu.sharedFolderKey = crypto.encrypt_rsa(shared_folder_key, rsa_key)
                                    add_users.append(sfu)
                        continue
                except Exception as e:
                    logging.debug(e)

            update_defaults = False
            if full_sync:
                for prop in ('manage_users', 'manage_records', 'can_edit', 'can_share'):
                    if hasattr(fol, prop) and f'default_{prop}' in shared_folder:
                        b1 = getattr(fol, prop) is True
                        b2 = shared_folder.get(f'default_{prop}') is True
                        if b2 != b1:
                            update_defaults = True
                            break

                if len(keep_teams) > 0 or len(keep_users) > 0:
                    remove_users.extend(x for x in existing_users.difference(keep_users))
                    remove_teams.extend(x for x in existing_teams.difference(keep_teams))
            else:
                update_users.clear()
                update_teams.clear()

            request_v3 = folder_pb2.SharedFolderUpdateV3Request()
            request_v3.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            request_v3.forceUpdate = True

            # request_v3.fromTeamUid = ...
            if update_defaults:
                if isinstance(fol.manage_records, bool):
                    request_v3.defaultManageRecords = \
                        folder_pb2.BOOLEAN_TRUE if fol.manage_records else folder_pb2.BOOLEAN_FALSE
                if isinstance(fol.manage_users, bool):
                    request_v3.defaultManageUsers = \
                        folder_pb2.BOOLEAN_TRUE if fol.manage_users else folder_pb2.BOOLEAN_FALSE
                if isinstance(fol.can_edit, bool):
                    request_v3.defaultCanEdit = \
                        folder_pb2.BOOLEAN_TRUE if fol.can_edit else folder_pb2.BOOLEAN_FALSE
                if isinstance(fol.can_share, bool):
                    request_v3.defaultCanShare = \
                        folder_pb2.BOOLEAN_TRUE if fol.can_share else folder_pb2.BOOLEAN_FALSE

            if len(add_users) > 0:
                request_v3.sharedFolderAddUser.extend(add_users)
            if len(add_teams) > 0:
                request_v3.sharedFolderAddTeam.extend(add_teams)
            if len(update_users) > 0:
                request_v3.sharedFolderUpdateUser.extend(update_users)
            if len(update_teams) > 0:
                request_v3.sharedFolderUpdateTeam.extend(update_teams)
            if len(remove_users) > 0:
                request_v3.sharedFolderRemoveUser.extend(remove_users)
            if len(remove_teams) > 0:
                request_v3.sharedFolderRemoveTeam.extend((utils.base64_url_decode(x) for x in remove_teams))

            if (request_v3.sharedFolderAddUser or request_v3.sharedFolderAddTeam or
                    request_v3.sharedFolderUpdateUser or request_v3.sharedFolderUpdateTeam or
                    request_v3.sharedFolderRemoveUser or request_v3.sharedFolderRemoveTeam or update_defaults):
                folder_permissions.append(request_v3)

    return folder_permissions


def prepare_record_permission(params, records):
    """Prepare a list of API interactions for changes to record permissions."""
    shared_update = []
    for rec in records:
        if rec.folders and rec.uid:
            if rec.uid in params.record_cache:
                for fol in rec.folders:
                    if fol.can_edit is None and fol.can_share is None:
                        continue

                    if fol.uid and fol.uid in params.folder_cache:
                        folder = params.folder_cache[fol.uid]
                        if folder.type in {BaseFolderNode.SharedFolderType, BaseFolderNode.SharedFolderFolderType}:
                            sf_uid = \
                                folder.shared_folder_uid \
                                if folder.type == BaseFolderNode.SharedFolderFolderType \
                                else folder.uid
                            if sf_uid in params.shared_folder_cache:
                                sf = params.shared_folder_cache[sf_uid]
                                if 'records' in sf:
                                    for sfr in sf['records']:
                                        if sfr['record_uid'] == rec.uid:
                                            if sfr['can_share'] != fol.can_share or sfr['can_edit'] != fol.can_edit:
                                                req = {
                                                    'command': 'shared_folder_update',
                                                    'pt': 'Commander',
                                                    'operation': 'update',
                                                    'shared_folder_uid': sf_uid,
                                                    'force_update': True,
                                                    'update_records': [{
                                                        'record_uid': rec.uid,
                                                        'shared_folder_uid': sf_uid,
                                                        'can_edit': fol.can_edit or False,
                                                        'can_share': fol.can_share or False
                                                    }]
                                                }
                                                shared_update.append(req)
                                            break
    return shared_update


class KeeperBaseAttachment(ImportAttachment, crypto.StreamCrypter, abc.ABC):
    def __init__(self, params):
        super().__init__()
        self.params = params


class KeeperV2Attachment(KeeperBaseAttachment):
    def __init__(self, params, record_uid, file_id):
        super().__init__(params)
        self.file_id = file_id
        self.record_uid = record_uid
        self.is_gcm = False

    def open(self):
        rq = {
            'command': 'request_download',
            'file_ids': [self.file_id],
        }
        api.resolve_record_access_path(self.params, self.record_uid, path=rq)
        rs = api.communicate(self.params, rq)
        dl = rs['downloads'][0]
        rs_http = requests.get(dl['url'], proxies=self.params.rest_context.proxies, stream=True)
        return self.set_stream(rs_http.raw, for_encrypt=False)


class KeeperV3Attachment(KeeperBaseAttachment):
    def __init__(self, params, file_uid):
        super().__init__(params)
        self.file_uid = file_uid

    def open(self):
        rq = record_pb2.FilesGetRequest()
        rq.record_uids.append(utils.base64_url_decode(self.file_uid))
        rq.for_thumbnails = False
        rs = api.communicate_rest(self.params, rq, 'vault/files_download', rs_type=record_pb2.FilesGetResponse)
        file = rs.files[0]
        if file.status != record_pb2.FG_SUCCESS:
            raise KeeperApiError('access_denied', 'Attachment: access denied')
        self.is_gcm = file.fileKeyType == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM
        url = file.url
        rs_http = requests.get(url, proxies=self.params.rest_context.proxies, stream=True)
        if rs_http.status_code != file.success_status_code:
            raise KeeperApiError('file_not_found', 'Attachment: file not found')
        return self.set_stream(rs_http.raw, for_encrypt=False)
