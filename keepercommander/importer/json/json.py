#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import io
import json
import logging
import os.path
import pathlib
import sys
import zipfile

from typing import List, Optional, Any, Dict
from contextlib import contextmanager

from .. import imp_exp
from ..importer import (BaseFileImporter, BaseExporter, Record, RecordField, RecordSchemaField, RecordReferences,
                        Folder, SharedFolder, Permission, Team, Attachment,
                        BaseDownloadMembership, BaseDownloadRecordType, RecordType, RecordTypeField)
from ... import api, utils, record_types
from ...proto import enterprise_pb2


class KeeperJsonMixin:
    @staticmethod
    def json_to_record(j_record):   # type: (Dict[str, Any]) -> Optional[Record]
        record = Record()
        record.uid = j_record.get('uid')
        if '$type' in j_record:
            record.type = j_record['$type']
        record.title = j_record.get('title') or ''
        record.login = j_record.get('login') or ''
        record.password = j_record.get('password') or ''
        record.login_url = j_record.get('login_url') or ''
        record.notes = j_record.get('notes') or ''
        if 'last_modified' in j_record:
            lm = j_record['last_modified']
            if isinstance(lm, int):
                record.last_modified = lm
        custom_fields = j_record.get('custom_fields')
        if type(custom_fields) is dict:
            for name in custom_fields:
                value = custom_fields[name]
                if name[0] == '$':
                    pos = name.find(':')
                    if pos > 0:
                        field_type = name[1:pos].strip()
                        field_name = name[pos+1:].strip()
                    else:
                        field_type = name[1:].strip()
                        field_name = ''
                else:
                    field_type = ''
                    field_name = name
                if len(field_name) >= 2 and field_name[-2] == ':' and field_name[-1].isdigit():
                    field_name = field_name[:-2]

                is_multiple = False
                if field_type:
                    ft = record_types.RecordFields.get(field_type)
                    if ft:
                        is_multiple = ft.multiple != record_types.Multiple.Never

                if isinstance(value, list) and not is_multiple:
                    for v in value:
                        field = RecordField()
                        field.type = field_type
                        field.label = field_name
                        field.value = v
                        record.fields.append(field)
                else:
                    field = RecordField()
                    field.type = field_type
                    field.label = field_name
                    field.value = value
                    record.fields.append(field)
        if 'schema' in j_record:
            record.schema = []
            for s in j_record['schema']:
                pos = s.find(':')
                if pos > 0:
                    schema_ref = s[0:pos].strip()
                    schema_label = s[pos+1:].strip()
                else:
                    schema_ref = s
                    schema_label = ''
                if schema_ref[0] == '$':
                    schema_ref = schema_ref[1:]

                sf = RecordSchemaField()
                sf.ref = schema_ref
                sf.label = schema_label
                record.schema.append(sf)
        if 'references' in j_record:
            record.references = []
            for ref_name in j_record['references']:
                if not ref_name:
                    continue
                ref_value = j_record['references'][ref_name]
                if not ref_value:
                    continue
                if type(ref_value) != list:
                    ref_value = [ref_value]
                ref_type = ref_name
                ref_label = ''
                pos = ref_name.find(':')
                if pos > 0:
                    ref_type = ref_name[1:pos].strip()
                    ref_label = ref_name[pos+1].strip()
                if ref_type[0] == '$':
                    ref_type = ref_type[1:]
                rr = RecordReferences()
                rr.type = ref_type
                rr.label = ref_label
                rr.uids.extend(ref_value)
                record.references.append(rr)
        if 'folders' in j_record:
            record.folders = []
            for f in j_record['folders']:
                folder = Folder()
                folder.domain = f.get('shared_folder')
                folder.path = f.get('folder')
                folder.can_edit = f.get('can_edit')
                folder.can_share = f.get('can_share')
                record.folders.append(folder)
        return record


class ZipAttachment(Attachment):
    def __init__(self, zip_filename, file_uid):
        super().__init__()
        self.zip_filename = zip_filename
        self.file_uid = file_uid

    @contextmanager
    def open(self):
        with zipfile.ZipFile(self.zip_filename, mode='r') as zf:
            yield io.BytesIO(zf.read(f'files/{self.file_uid}'))

    def prepare(self):
        try:
            with zipfile.ZipFile(self.zip_filename, mode='r') as zf:
                try:
                    zi = zf.getinfo(f'files/{self.file_uid}')
                    self.size = zi.file_size
                except KeyError:
                    logging.debug('ZipAttachment: file \"%s\" not found', self.file_uid)
        except Exception as e:
            logging.debug('ZipAttachment: %s', e)
            self.size = 0


class KeeperJsonImporter(BaseFileImporter, KeeperJsonMixin):
    def do_import(self, filename, **kwargs):
        users_only = kwargs.get('users_only') or False
        if not os.path.isfile(filename):
            zip_name = pathlib.Path(filename).with_suffix('.zip').name
            if os.path.isfile(zip_name):
                if zipfile.is_zipfile(zip_name):
                    filename = zip_name
        file_path = pathlib.Path(filename)
        zip_archive = file_path.suffix == '.zip'
        if zip_archive:
            with zipfile.ZipFile(filename, 'r') as zf:
                export = json.loads(zf.read('export.json'))
        else:
            with open(filename, "r", encoding='utf-8') as jf:
                export = json.load(jf)

        records = None
        folders = None
        teams = None
        if type(export) == list:
            records = export

        elif type(export) == dict:
            records = export.get('records')
            folders = export.get('shared_folders')
            teams = export.get('teams') if users_only else None

        if folders:
            for shf in folders:
                fol = SharedFolder()
                fol.uid = shf.get('uid')
                fol.path = shf.get('path')
                fol.manage_records = shf.get('manage_records') or False
                fol.manage_users = shf.get('manage_users') or False
                fol.can_edit = shf.get('can_edit') or False
                fol.can_share = shf.get('can_share') or False
                if users_only and 'permissions' in shf:
                    fol.permissions = []
                    permissions = shf['permissions']
                    if not isinstance(permissions, list):
                        permissions = [permissions]
                    for perm in permissions:
                        if isinstance(perm, dict):
                            p = Permission()
                            p.uid = perm.get('uid')
                            p.name = perm.get('name')
                            if p.uid or p.name:
                                p.manage_records = perm.get('manage_records') or False
                                p.manage_users = perm.get('manage_users') or False
                                fol.permissions.append(p)

                yield fol

        if isinstance(teams, list):
            for t in teams:
                team = Team()
                team.name = t.get('name')
                if team.name:
                    team.uid = t.get('uid')
                    ms = t.get('members')
                    if isinstance(ms, list):
                        team.members = [x for x in ms if isinstance(x, str) and len(x) > 3]
                    yield team

        if not users_only and records:
            for r in records:
                record = KeeperJsonMixin.json_to_record(r)
                if zip_archive and 'attachments' in r:
                    attachments = r['attachments']
                    record.attachments = []
                    if isinstance(attachments, list):
                        for atta in attachments:
                            file_uid = atta.get('file_uid')
                            a = ZipAttachment(filename, file_uid)
                            a.name = atta.get('name') or file_uid
                            a.mime = atta.get('mime')
                            record.attachments.append(a)
                yield record

    def extension(self):
        return 'json'


class KeeperJsonExporter(BaseExporter):
    def do_export(self, filename, items, zip_archive=None, **kwargs):
        shared_folders = []     # type: List[SharedFolder]
        records = []            # type: List[Record]
        teams = []              # type: List[Team]

        if zip_archive is True and not filename:
            raise ValueError('Please provide zip archive file name')

        for item in items:
            if isinstance(item, Record):
                records.append(item)
            elif isinstance(item, SharedFolder):
                shared_folders.append(item)
            elif isinstance(item, Team):
                teams.append(item)

        ts = []
        for t in teams:
            team = {
                'name': t.name,
            }
            if t.uid:
                team['uid'] = t.uid
            if t.members:
                team['members'] = [x for x in t.members]
            ts.append(team)

        sfs = []
        for sf in shared_folders:
            sfo = {
                'path': sf.path,
            }
            if sf.uid:
                sfo['uid'] = sf.uid
            if sf.manage_users is not None:
                sfo['manage_users'] = sf.manage_users
            if sf.manage_records is not None:
                sfo['manage_records'] = sf.manage_records
            if sf.can_edit is not None:
                sfo['can_edit'] = sf.can_edit
            if sf.can_share is not None:
                sfo['can_share'] = sf.can_share

            if sf.permissions:
                sfo['permissions'] = []
                for perm in sf.permissions:
                    po = {
                        'name': perm.name,
                        'manage_users': perm.manage_users,
                        'manage_records': perm.manage_records
                    }
                    if perm.uid:
                        po['uid'] = perm.uid
                    sfo['permissions'].append(po)
            sfs.append(sfo)

        rs = []
        atta = {}
        for r in records:
            ro = {
                'title': r.title or ''
            }
            if r.uid:
                ro['uid'] = r.uid
            if r.login:
                ro['login'] = r.login
            if r.password:
                ro['password'] = r.password
            if r.login_url:
                ro['login_url'] = r.login_url
            if r.notes:
                ro['notes'] = r.notes
            if r.type:
                ro['$type'] = r.type
            if r.uid:
                ro['uid'] = r.uid
            if isinstance(r.last_modified, int) and r.last_modified > 0:
                ro['last_modified'] = int(r.last_modified / 1000)

            if r.fields:
                ro['custom_fields'] = {}
                for field in r.fields:
                    if not field.type and field.label and field.label.startswith('$'):
                        field.type = 'text'
                    if field.type and field.label:
                        name = f'${field.type}:{field.label}'
                    elif field.type:
                        name = f'${field.type}'
                    else:
                        name = field.label or '<No Name>'
                    value = field.value
                    if name in ro['custom_fields']:
                        orig_value = ro['custom_fields'][name]
                        if orig_value:
                            orig_value = orig_value if type(orig_value) is list else [orig_value]
                        else:
                            orig_value = []
                        if value:
                            orig_value.append(value)
                        value = orig_value
                    ro['custom_fields'][name] = value

            if r.schema:
                ro['schema'] = []
                for rsf in r.schema:
                    name = f'${rsf.ref}'
                    if rsf.label:
                        name += f':{rsf.label}'
                    ro['schema'].append(name)

            if r.references:
                ro['references'] = {}
                for ref in r.references:
                    ref_name = f'${ref.type}:{ref.label}' if ref.type and ref.label else f'${ref.type}' if ref.type else ref.label or ''
                    refs = ro['references'].get(ref_name)
                    if refs is None:
                        refs = []
                        ro['references'][ref_name] = refs
                    refs.extend(ref.uids)

            if r.folders:
                ro['folders'] = []
                for folder in r.folders:
                    if folder.domain or folder.path:
                        fo = {}
                        ro['folders'].append(fo)
                        if folder.domain:
                            fo['shared_folder'] = folder.domain
                        if folder.path:
                            fo['folder'] = folder.path
                        if folder.can_edit:
                            fo['can_edit'] = True
                        if folder.can_share:
                            fo['can_share'] = True

            if r.attachments and zip_archive:
                ro['attachments'] = []
                for at in r.attachments:
                    file_uid = at.file_uid or utils.generate_uid()
                    atta[file_uid] = at
                    a = {
                        'file_uid': file_uid,
                        'name': at.name
                    }
                    if at.mime:
                        a['mime'] = at.mime
                    ro['attachments'].append(a)

            rs.append(ro)

        jo = {}
        if ts:
            jo['teams'] = ts
        if sfs:
            jo['shared_folders'] = sfs
        if rs:
            jo['records'] = rs

        if zip_archive and filename:
            zip_name = pathlib.Path(filename).with_suffix('.zip').name
            with zipfile.ZipFile(zip_name, mode='w', compresslevel=zipfile.ZIP_DEFLATED) as zf:
                f = json.dumps(jo, indent=2, ensure_ascii=False)
                zf.writestr('export.json', f)
                total = len(atta)
                if total > 0:
                    logging.info('Downloading attachments...')
                    i = 1
                    for file_uid, at in atta.items():
                        logging.info(f'{i:>3} of {total:3} {at.name}')
                        i += 1
                        with at.open() as fs:
                            data = fs.read()
                            if data:
                                zf.writestr(f'files/{file_uid}', data)
        elif filename:
            with open(filename, mode="w", encoding='utf-8') as f:
                json.dump(jo, f, indent=2, ensure_ascii=False)
        else:
            json.dump(jo, sys.stdout, indent=2, ensure_ascii=False)
            print('')

    def has_shared_folders(self):
        return True

    def has_attachments(self):
        return True

    def extension(self):
        return 'json'

    def supports_stdout(self):
        return True

    def supports_v3_record(self):
        return True


class KeeperMembershipDownload(BaseDownloadMembership):
    def download_membership(self, params, **kwargs):
        teams = {}
        if params.shared_folder_cache:
            for shared_folder_uid in params.shared_folder_cache:
                shared_folder = api.get_shared_folder(params, shared_folder_uid)
                sf = SharedFolder()
                sf.uid = shared_folder.shared_folder_uid
                sf.path = imp_exp.get_folder_path(params, shared_folder.shared_folder_uid)
                sf.manage_users = shared_folder.default_manage_users
                sf.manage_records = shared_folder.default_manage_records
                sf.can_edit = shared_folder.default_can_edit
                sf.can_share = shared_folder.default_can_share
                sf.permissions = []
                if shared_folder.teams:
                    for team in shared_folder.teams:
                        perm = Permission()
                        perm.uid = team['team_uid']
                        perm.name = team['name']
                        perm.manage_users = team.get('manage_users', False)
                        perm.manage_records = team.get('manage_records', False)
                        teams[perm.uid] = perm.name
                        sf.permissions.append(perm)
                if shared_folder.users:
                    for user in shared_folder.users:
                        perm = Permission()
                        perm.name = user['username']
                        perm.manage_users = user.get('manage_users', False)
                        perm.manage_records = user.get('manage_records', False)
                        sf.permissions.append(perm)
                yield sf

        folders_only = kwargs.get('folders_only') is True
        if folders_only is True:
            return

        enterprise_teams = {}    # type: Dict[int, List[str]]
        if params.enterprise:
            users = {x['enterprise_user_id']: x['username'] for x in params.enterprise.get('users', [])
                     if x.get('status') == 'active'}
            if 'team_users' in params.enterprise:
                for tu in params.enterprise['team_users']:
                    team_uid = tu.get('team_uid')
                    user_id = tu.get('enterprise_user_id')
                    if team_uid and user_id:
                        if user_id in users:
                            if team_uid not in enterprise_teams:
                                enterprise_teams[team_uid] = []
                            enterprise_teams[team_uid].append(users[user_id])

        if teams and params.enterprise_ec_key:
            for team_uid in teams:
                t = Team()
                t.uid = team_uid
                t.name = teams[team_uid]
                if team_uid in enterprise_teams:
                    t.members = list(enterprise_teams[team_uid])
                else:
                    rq = enterprise_pb2.GetTeamMemberRequest()
                    rq.teamUid = utils.base64_url_decode(team_uid)
                    rs = api.communicate_rest(params, rq, 'vault/get_team_members', rs_type=enterprise_pb2.GetTeamMemberResponse)
                    t.members = [x.email for x in rs.enterpriseUser]
                yield t


class KeeperRecordTypeDownload(BaseDownloadRecordType):
    def download_record_type(self, params, **kwargs):
        if params.record_type_cache:
            for rt_id, rts in params.record_type_cache.items():
                if rt_id <= 1000:
                    continue
                try:
                    rto = json.loads(rts)
                    if '$id' in rto and 'fields' in rto:
                        rt = RecordType()
                        rt.name = rto['$id']
                        rt.description = rto.get('description') or ''
                        for field in rto['fields']:
                            rtf = RecordTypeField()
                            rtf.type = field['$ref']
                            if 'label' in field:
                                rtf.label = field['label']
                            if 'required' in field:
                                req = field['required']
                                if req:
                                    rtf.required = True
                            rt.fields.append(rtf)
                        yield rt
                except:
                    pass
