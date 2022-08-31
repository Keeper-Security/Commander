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

import json
import sys

from typing import List

from ..importer import BaseFileImporter, BaseExporter, Record, RecordField, RecordSchemaField, RecordReferences, Folder, SharedFolder, Permission
from ... import record_types


class KeeperJsonImporter(BaseFileImporter):
    def do_import(self, filename, **kwargs):
        users_only = kwargs.get('users_only') or False
        with open(filename, "r", encoding='utf-8') as json_file:
            j = json.load(json_file)
            records = None
            folders = None
            if type(j) == list:
                records = j
            elif type(j) == dict:
                records = j.get('records')
                folders = j.get('shared_folders')

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

            if not users_only and records:
                for r in records:
                    record = Record()
                    record.uid = r.get('uid')
                    if '$type' in r:
                        record.type = r['$type']
                    record.title = r.get('title')
                    record.login = r.get('login')
                    record.password = r.get('password')
                    record.login_url = r.get('login_url')
                    record.notes = r.get('notes')
                    custom_fields = r.get('custom_fields')
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

                            ft = record_types.RecordFields.get(field_type or 'text')
                            if ft:
                                is_multiple = ft.multiple != record_types.Multiple.Never
                            else:
                                is_multiple = False
                                if not field_name:
                                    field_name = name
                                    field_type = ''

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
                    if 'schema' in r:
                        record.schema = []
                        for s in r['schema']:
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
                    if 'references' in r:
                        record.references = []
                        for ref_name in r['references']:
                            if not ref_name:
                                continue
                            ref_value = r['references'][ref_name]
                            if not ref_value:
                                continue
                            if type(ref_value) != list:
                                ref_value = [ref_value]
                            ref_type = ref_name
                            ref_label = ''
                            pos = field_name.find(':')
                            if pos > 0:
                                ref_type = field_name[1:pos].strip()
                                ref_label = field_name[pos+1].strip()
                            if ref_type[0] == '$':
                                ref_type = ref_type[1:]
                            rr = RecordReferences()
                            rr.type = ref_type
                            rr.label = ref_label
                            rr.uids.extend(ref_value)
                            record.references.append(rr)
                    if 'folders' in r:
                        record.folders = []
                        for f in r['folders']:
                            folder = Folder()
                            folder.domain = f.get('shared_folder')
                            folder.path = f.get('folder')
                            folder.can_edit = f.get('can_edit')
                            folder.can_share = f.get('can_share')
                            record.folders.append(folder)

                    yield record

    def extension(self):
        return 'json'


class KeeperJsonExporter(BaseExporter):

    def do_export(self, filename, items, file_password=None):
        shared_folders = []     # type: List[SharedFolder]
        records = []            # type: List[Record]

        for item in items:
            if isinstance(item, SharedFolder):
                shared_folders.append(item)
            elif isinstance(item, Record):
                records.append(item)
        """
        external_uids = {}
        external_id = 1
        for record in records:
            if record.uid:
                external_uids[record.uid] = external_id
                external_id += 1
        for record in records:
            if record.uid:
                record.uid = external_uids.get(record.uid)
            if record.references:
                for ref in record.references:
                    ref.uids = [external_uids[x] for x in ref.uids if x in external_uids]
        """
        sfs = []
        for sf in shared_folders:
            sfo = {
                'uid': sf.uid,
                'path': sf.path,
            }
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
        for r in records:
            ro = {
                'uid': r.uid or '',
                'title': r.title or ''
            }
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
            rs.append(ro)

        jo = {'shared_folders': sfs, 'records': rs}
        if filename:
            with open(filename, mode="w", encoding='utf-8') as f:
                json.dump(jo, f, indent=2, ensure_ascii=False)
        else:
            json.dump(jo, sys.stdout, indent=2, ensure_ascii=False)
            print('')

    def has_shared_folders(self):
        return True

    def has_attachments(self):
        return False

    def extension(self):
        return 'json'

    def supports_stdout(self):
        return True

    def supports_v3_record(self):
        return True
