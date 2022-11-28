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
import base64
import collections
import datetime
import json
import logging
import os
from typing import List, Optional, Any, Dict, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .base import Command, RecordMixin
from .. import api, vault, record_types, generator, crypto, attachment, record_management, record_facades
from ..commands import recordv3
from ..error import CommandError
from ..importer.importer import BaseImporter
from ..params import KeeperParams, LAST_RECORD_UID
from ..subfolder import try_resolve_path

record_add_parser = argparse.ArgumentParser(prog='record-add', description='Add a record to folder')
record_add_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                               help='Display help on field parameters.')
record_add_parser.add_argument('-f', '--force', dest='force', action='store_true', help='ignore warnings')
record_add_parser.add_argument('-t', '--title', dest='title', action='store', help='record title')
record_add_parser.add_argument('-rt', '--record-type', dest='record_type', action='store', help='record type')
record_add_parser.add_argument('-n', '--notes', dest='notes', action='store', help='record notes')
record_add_parser.add_argument('--folder', dest='folder', action='store',
                               help='folder name or UID to store record')
record_add_parser.add_argument('fields', nargs='*', type=str,
                               help='load record type data from strings with dot notation')

record_update_parser = argparse.ArgumentParser(prog='record-update', description='Update a record')
record_update_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                                  help='Display help on field parameters.')
record_update_parser.add_argument('-f', '--force', dest='force', action='store_true', help='ignore warnings')
record_update_parser.add_argument('-t', '--title', dest='title', action='store', help='modify record title')
record_update_parser.add_argument('-rt', '--record-type', dest='record_type', action='store', help='record type')
record_update_parser.add_argument('-n', '--notes', dest='notes', action='store', help='append/modify record notes')
record_update_parser.add_argument('-r', '--record', dest='record', action='store',
                                  help='record path or UID')
record_update_parser.add_argument('fields', nargs='*', type=str,
                                  help='load record type data from strings with dot notation')

record_fields_description = '''
Commander supports two types of records:
1. Typed
2. Legacy

To create a Legacy record type pass "legacy" or "general" record type parameter 

The content of Typed record is defined by schema. The schema name is stored on record "type" field
To view all available record types:  "record-type-info" or "rti" 
To view fields for particular record type:  "record-type-info --list-record <record type>"  "rti -lt login"
To view field information type: "record-type-info --list-field <field type>"  "rti -lf host"

The Commander supports the following syntax for record fields:
[<FIELD_SET>][<FIELD_TYPE>][<FIELD_LABEL>]=[FIELD_VALUE]
Field components are separated with a dot (.)
1. FIELD_SET: Optional. 'f' or 'c'. Field section: field/f or custom/c
2. FIELD_TYPE: Mandatory for main fields optional for custom. if omitted 'text' field type is assumed
3. FIELD_LABEL: Optional. When adding multiple custom fields of the same type make sure the label is unique.
4. FIELD_VALUE: Optional. If is empty them field to be deleted. The field value content depends on field type.
Example:   "url.Web URL=https://google.com"

Field types are case sensitive
Field labels are case insensitive

Use full <FIELD_TYPE>.<FIELD_LABEL> syntax when field label collides with field type. 
Example:  "password"          "password" field with no label
          "text.password"     "text" field with "password" label
          "Password"          "text" field with "Password" label

Use full <FIELD_TYPE>.<FIELD_LABEL> syntax when field label contains a dot (.)
Example:   "google.com"       Incorrect field type google
           "text.google.com"  Field type "text" field label "google.com"
           
The Legacy records define the following field types.  
1. login
2. password
3. url
4. oneTimeCode

All records support:
3. Custom Fields: Any field that is not the pre-defined field is added to custom field section. 
   "url.Web URL=https://google.com"
4. File Attachments:   "file=@<FILE_NAME>"

Supported record type field values:
Field Type        Description            Value Type     Examples
===========       ==================     =========+     =====================================
file              File attachment                       @file.txt
date              Unix epoch time.       integer        1668639533 | 2022-11-16T10:58:53Z | 2022-11-16
host              host name / port       object         {"hostName": "", "port": ""} 
                                                        192.168.1.2:4321
address           Address                object         {"street1": "", "street2": "", "city": "", "state": "", 
                                                         "zip": "", "country": ""}
                                                        123 Main St, SmallTown, CA 12345, USA
phone             Phone                  object         {"region": "", "number": "", "ext": "", "type": ""}
                                                        Mobile: US (555)555-1234
name              Person name            object         {"first": "", "middle": "", "last": ""}
                                                        Doe, John Jr. | Jane Doe
securityQuestion  Security Q & A         array of       [{"question": "", "answer": ""}]
                                         objects        What city you were ...? city; What is the name of ...? name
paymentCard       Payment Card           object         {"cardNumber": "", "cardExpirationDate": "", "cardSecurityCode": ""}
                                                        4111111111111111 04/2026 123
bankAccount       Bank Account           object         {"accountType": "", "routingNumber": "", "accountNumber": ""}
                                                        Checking: 123456789 987654321
privateKey        Key Pair               object         {"publicKey": "", "privateKey": ""}
oneTimeCode       TOTP URL               string         otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP&issuer=Keeper
note              Masked multiline text  string         
multiline         Multiline text         string         
secret            Masked text            string         
login             Login                  string                                         
email             Email                  string         'name@company.com'                                
password          Password               string         
url               URL                    string         https://google.com/
text              Free form text         string         This field type generally has a label

$<ACTION>[:<PARAMS>, <PARAMS>]   executes an action that returns a field value   

Value                   Field type         Description                      Example
====================    ===============    ===================              ==============
$GEN                    password           Generates a random password      TBD
$GEN                    oneTimeCode        Generates TOTP URL               TBD
$GEN:[alg,][enc]}       privateKey         Generates a key pair and         $GEN:ec,enc
                                           optional passcode                alg: [rsa | ec | ed25519], enc 
$JSON:<JSON TEXT>       any object         Sets a field value as JSON       
                                           phone.Cell=$JSON:{"number": "(555) 555-1234", "type": "Mobile"} 
'''


ParsedFieldValue = collections.namedtuple('ParsedFieldValue', ['section', 'type', 'label', 'value'])


class RecordEditMixin:
    def __init__(self):
        self.warnings = []

    def on_warning(self, message):
        if message:
            self.warnings.append(message)

    def on_info(self, message):
        logging.info(message)

    @staticmethod
    def parse_field(field):   # type: (str) -> ParsedFieldValue
        if not isinstance(field, str):
            raise ValueError('Incorrect field value')

        name, sel, value = field.partition('=')
        if not sel:
            raise ValueError(f'Expected: <field>=<value>, got: {field}; Missing `=`')
        if not name:
            raise ValueError(f'Expected: <field>=<value>, got: {field}; Missing <field>')
        field_section = ''
        if name.startswith('f.') or name.startswith('c.'):
            field_section = name[0]
            name = name[2:]
        if not name:
            raise ValueError(f'Expected: <field>=<value>, got: {field}; Missing field type or label')

        field_type, sep, field_label = name.partition('.')
        if not sep:
            if field_type in ('file'):
                pass
            elif field_type not in record_types.RecordFields:
                field_label = field_type
                field_type = ''
        return ParsedFieldValue(field_section, field_type, field_label, value)

    def assign_legacy_fields(self, record, fields):
        # type: (vault.PasswordRecord, List[ParsedFieldValue]) -> None
        if not isinstance(record, vault.PasswordRecord):
            raise ValueError('Expected legacy record')
        if not isinstance(fields, list):
            raise ValueError('Fields parameter: expected array of strings')

        action_params = []
        for parsed_field in fields:
            if parsed_field.type == 'login':
                record.login = parsed_field.value
            elif parsed_field.type == 'password':
                if self.is_generate_value(parsed_field.value, action_params):
                    record.password = self.generate_password()
                else:
                    record.password = parsed_field.value
            elif parsed_field.type == 'url':
                record.link = parsed_field.value
            elif parsed_field.type == 'oneTimeCode':
                if self.is_generate_value(parsed_field.value, action_params):
                    record.totp = self.generate_totp_url()
                else:
                    record.totp = parsed_field.value
            else:
                field_type = parsed_field.type
                field_label = parsed_field.label
                if field_type and not field_label:
                    field_label = field_type
                index = next((i for i, x in enumerate(record.custom) if x.name.lower() == field_label.lower()), -1)
                if parsed_field.value:
                    if 0 <= index < len(record.custom):
                        record.custom[index].value = parsed_field.value
                    else:
                        record.custom.append(vault.CustomField.new_field(field_label, parsed_field.value))
                else:
                    if 0 <= index < len(record.custom):
                        record.custom.pop(index)

    def is_json_value(self, value, parameters):   # type: (str, List[Any]) -> Optional[bool]
        if value.startswith('$JSON'):
            value = value[5:]
            if value.startswith(':'):
                j_str = value[1:]
                if j_str and isinstance(parameters, list):
                    try:
                        parameters.append(json.loads(j_str))
                    except Exception as e:
                        self.on_warning(f'Invalid JSON value: {j_str}: {e}')
            return True

    @staticmethod
    def is_generate_value(value, parameters):    # type: (str, List[str]) -> Optional[bool]
        if value.startswith("$GEN"):
            value = value[4:]
            if value.startswith(':'):
                gen_parameters = value[1:]
                if gen_parameters and isinstance(parameters, list):
                    parameters.extend((x.strip() for x in gen_parameters.split(',')))
            return True

    @staticmethod
    def generate_key_pair(key_type, passphrase):  # type: (str, str) -> dict
        if key_type == 'ec':
            private_key, public_key = crypto.generate_ec_key()
        elif key_type == 'ed25519':
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
        else:
            private_key, public_key = crypto.generate_rsa_key()
        encryption = serialization.BestAvailableEncryption(passphrase.encode()) \
            if passphrase else serialization.NoEncryption()

        # noinspection PyTypeChecker
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption)
        # noinspection PyTypeChecker
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return {
            'privateKey': pem_private_key.decode(),
            'publicKey': pem_public_key.decode(),
        }

    @staticmethod
    def generate_password():
        return generator.generate(20)

    @staticmethod
    def generate_totp_url():
        secret = base64.b32encode(crypto.get_random_bytes(20)).decode()

        return f'otpauth://totp/Commander?secret={secret}&issuer=Keeper'

    def validate_json_value(self, field_type, field_value):        # type: (str, Any) -> Any
        record_field = record_types.RecordFields.get(field_type)
        if not record_field:
            self.on_warning(f'Incorrect record field type: \"{field_type}\"')
            return
        value_type = record_types.FieldTypes[record_field.name]
        if isinstance(value_type.value, dict):
            f_fields = set(value_type.value.keys())
            if isinstance(field_value, (list, dict)):
                if isinstance(field_value, list):
                    if record_field.multiple != record_types.Multiple.Always:
                        self.on_warning(f'Field \"{record_field.name}\" does not support multiple values')
                d_rs = []
                for dv in field_value if isinstance(field_value, list) else [field_value]:
                    if isinstance(dv, dict):
                        v_fields = set(dv.keys())
                        v_fields.difference_update(f_fields)
                        if len(v_fields) > 0:
                            self.on_warning(f'Field \"{record_field.name}\": '
                                            f'Properties \"{", ".join(v_fields)}\" are not supported.')
                        for key in f_fields:
                            if key not in dv:
                                dv[key] = ''
                        d_rs.append(dv)
                    else:
                        self.on_warning(f'Field \"{record_field.name}\": Incorrect value: \"{json.dumps(dv)}\"')
                        return
                if len(d_rs) > 1:
                    return d_rs
                elif len(d_rs) == 1:
                    return d_rs[0]
            else:
                self.on_warning(f'Field \"{record_field.name}\" ')
        elif isinstance(field_value, type(value_type.value)):
            return field_value
        else:
            self.on_warning(f'Field \"{record_field.name}\": Incorrect value: \"{field_value}\" ')

    @staticmethod
    def validate_notes(notes):    # type: (str) -> str
        if isinstance(notes, str):
            notes = notes.replace('\\n', '\n')
        return notes

    def assign_typed_fields(self, record, fields):
        # type: (vault.TypedRecord, List[ParsedFieldValue]) -> None
        if not isinstance(record, vault.TypedRecord):
            raise ValueError('Expected typed record')
        if not isinstance(fields, list):
            raise ValueError('Fields parameter: expected array of fields')

        parsed_fields = collections.deque(fields)
        while len(parsed_fields) > 0:
            parsed_field = parsed_fields.popleft()
            field_type = parsed_field.type or ''
            field_label = parsed_field.label or ''
            if field_type and field_type not in record_types.RecordFields:
                if not field_label:
                    field_label = field_type
                    field_type = 'text'
                else:
                    self.on_warning(f'Field type \"{field_type}\" is not supported. Field: {field_type}.{field_label}')
                    continue
            rf = record_types.RecordFields.get(field_type)
            ignore_label = rf.multiple == record_types.Multiple.Never if rf else False

            record_field = None    # type: Optional[vault.TypedField]
            is_field = False
            if parsed_field.section == 'f':   # ignore label
                fs = [x for x in record.fields if x.type == field_type and isinstance(x, vault.TypedField)]
                if len(fs) == 0:
                    self.on_warning(f'Field type \"{field_type}\" is not found for record type {record.record_type}')
                elif len(fs) == 1:
                    record_field = fs[0]
                else:
                    fs = [x for x in fs if (x.label or '').lower() == field_label.lower()]
                    if len(fs) == 0:
                        self.on_warning(
                            f'Field type \"{field_type}\" is not found for record type {record.record_type}')
                    else:
                        record_field = fs[0]
                is_field = True
            else:
                f_label = field_label.lower()
                record_field = next(
                    (x for x in record.fields
                     if (not parsed_field.type or x.type == parsed_field.type) and
                     (ignore_label or (x.label or '').lower() == f_label)), None)
                if record_field:
                    is_field = True
                else:
                    record_field = next(
                        (x for x in record.custom
                         if (not parsed_field.type or x.type == parsed_field.type) and
                         (ignore_label or (x.label or '').lower() == f_label)), None)
                    if record_field is None:
                        if not parsed_field.value:
                            continue
                        record_field = vault.TypedField.new_field(field_type or 'text', None, field_label)
                        record.custom.append(record_field)
            if not record_field:
                continue

            if parsed_field.value:
                value = None
                action_params = []
                if self.is_generate_value(parsed_field.value, action_params):
                    if record_field.type == 'password':
                        value = self.generate_password()
                    elif record_field.type == 'oneTimeCode':
                        value = self.generate_totp_url()
                    elif record_field.type == 'keyPair':
                        should_encrypt = 'enc' in action_params
                        passphrase = self.generate_password() if should_encrypt else None
                        key_type = next((x for x in action_params if x in ('rsa', 'ec', 'ed25519')), 'rsa')
                        value = self.generate_key_pair(key_type, passphrase)
                        if passphrase:
                            parsed_fields.append(ParsedFieldValue('', 'password', 'passphrase', passphrase))
                    else:
                        self.on_warning(f'Cannot generate a value for a \"{record_field.type}\" field.')
                elif self.is_json_value(parsed_field.value, action_params):
                    if len(action_params) > 0:
                        value = self.validate_json_value(record_field.type, action_params[0])
                else:
                    rf = record_types.RecordFields[record_field.type]
                    ft = record_types.FieldTypes.get(rf.type)
                    if isinstance(ft.value, str):
                        value = parsed_field.value
                        if ft.name == 'multiline':
                            value = self.validate_notes(value)
                    elif isinstance(ft.value, int):
                        if parsed_field.value.isdigit():
                            value = int(parsed_field.value)
                            if value < 1_000_000_000:
                                value *= 1000
                        else:
                            if len(parsed_field.value) <= 10:
                                dt = datetime.datetime.strptime(parsed_field.value, '%Y-%m-%d')
                            else:
                                dt = datetime.datetime.strptime(parsed_field.value, '%Y-%m-%dT%H:%M:%SZ')
                            value = int(dt.timestamp() * 1000)
                    elif isinstance(ft.value, bool):
                        lv = parsed_field.value.lower()
                        if lv in ('1', 'y', 'yes', 't', 'true'):
                            value = True
                        elif lv in ('0', 'n', 'no', 'f', 'false'):
                            value = False
                        else:
                            self.on_warning(f'Incorrect boolean value \"{parsed_field.value}\": [t]rue or [f]alse')
                    elif isinstance(ft.value, dict):
                        if ft.name == 'name':
                            value = BaseImporter.import_name_field(parsed_field.value)
                        elif ft.name == 'address':
                            value = BaseImporter.import_address_field(parsed_field.value)
                        elif ft.name == 'host':
                            value = BaseImporter.import_host_field(parsed_field.value)
                        elif ft.name == 'phone':
                            value = BaseImporter.import_phone_field(parsed_field.value)
                        elif ft.name == 'paymentCard':
                            value = BaseImporter.import_card_field(parsed_field.value)
                        elif ft.name == 'bankAccount':
                            value = BaseImporter.import_account_field(parsed_field.value)
                        elif ft.name == 'securityQuestion':
                            value = []
                            for qa in parsed_field.value.split(';'):
                                qa = qa.strip()
                                qav = BaseImporter.import_q_and_a_field(qa)
                                if qav:
                                    value.append(qav)
                        elif ft.name == 'privateKey':
                            value = BaseImporter.import_ssh_key_field(parsed_field.value)
                        else:
                            self.on_warning(f'Unsupported field type: {record_field.type}')
                if value:
                    if isinstance(value, list):
                        record_field.value.clear()
                        record_field.value.extend(value)
                    else:
                        if len(record_field.value) == 0:
                            record_field.value.append(value)
                        else:
                            record_field.value[0] = value
            else:
                if is_field:
                    record_field.value.clear()
                else:
                    index = next((i for i, x in enumerate(record.custom) if x is record_field), -1)
                    if 0 <= index < len(record.custom):
                        record.custom.pop(index)

    def upload_attachments(self, params, record, files, stop_on_error):
        # type: (KeeperParams, Union[vault.PasswordRecord, vault.TypedRecord], List[ParsedFieldValue], bool) -> None
        tasks = []
        for file_attachment in files:
            if file_attachment.value.startswith('@'):
                file_name = file_attachment.value[1:]
            else:
                file_name = file_attachment.value
            file_name = os.path.expanduser(file_name)
            if os.path.isfile(file_name):
                task = attachment.FileUploadTask(file_name)
                task.title = file_attachment.label
                tasks.append(task)
            else:
                self.on_warning(f'Upload attachment: file \"{file_name}\" not found')
                if stop_on_error:
                    return

        for task in tasks:
            try:
                self.on_info(f'Uploading {task.name} ...')
                attachment.upload_attachments(params, record, [task])
            except Exception as e:
                self.on_warning(str(e))
                if stop_on_error:
                    break

    def delete_attachments(self, params, record, file_names):
        # type: (KeeperParams, Union[vault.PasswordRecord, vault.TypedRecord], List[str]) -> None
        if isinstance(record, vault.PasswordRecord):
            for file_name in file_names:
                indexes = [i for i, x in enumerate(record.attachments or [])
                           if x.id == file_name or file_name.lower() in (x.name.lower(), x.title.lower())]
                if len(indexes) > 1:
                    self.on_warning(
                        f'There are multiple file attachments with name \"{file_name}\". Use attachment ID.')
                elif len(indexes) == 1:
                    record.attachments.pop(indexes[0])
        elif isinstance(record, vault.TypedRecord):
            facade = record_facades.FileRefRecordFacade()
            facade.record = record
            for file_name in file_names:
                index = next((i for i, x in enumerate(facade.file_ref) if x == file_name), -1)
                if index > 0:
                    facade.file_ref.pop(index)
                else:
                    file_uids = []
                    f_name = file_name.lower()
                    for file_uid in facade.file_ref:
                        if file_uid in params.record_cache:
                            file = vault.KeeperRecord.load(params, file_uid)
                            if isinstance(file, vault.FileRecord):
                                if f_name in (file.name.lower(), file.title.lower()):
                                    file_uids.append(file_uid)
                    if len(file_uids) > 1:
                        self.on_warning(
                            f'There are multiple file attachments with name \"{file_name}\". Use attachment ID.')
                    elif len(file_uids) == 1:
                        facade.file_ref.remove(file_uids[0])

    @staticmethod
    def resolve_folder(params, folder_name):    # type: (KeeperParams, str) -> Optional[str]
        if not folder_name:
            return params.current_folder

        if folder_name in params.folder_cache:
            return folder_name
        else:
            rs = try_resolve_path(params, folder_name)
            if rs is not None:
                folder, record_name = rs
                if folder and not record_name:
                    if folder.uid:
                        return folder.uid

    @staticmethod
    def get_record_type_fields(params, record_type):      # type: (KeeperParams, str) -> Optional[List[Dict]]
        rti = recordv3.RecordTypeInfo()
        js_rt = rti.execute(params, format='json', record_name=record_type)
        j_rt = json.loads(js_rt)
        if isinstance(j_rt, list):
            if len(j_rt) > 0:
                jrt_fields = j_rt[0].get('content')
                j_rt = json.loads(jrt_fields)
                if isinstance(j_rt, dict):
                    return j_rt.get('fields')


class RecordAddCommand(Command, RecordEditMixin):
    def __init__(self):
        super(RecordAddCommand, self).__init__()

    def get_parser(self):
        return record_add_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help') is True:
            print(record_fields_description)
            return

        folder_uid = self.resolve_folder(params, kwargs.get('folder'))

        self.warnings.clear()
        title = kwargs.get('title')
        if not title:
            raise CommandError('record-add', 'Title parameter is required.')
        record_type = kwargs.get('record_type')
        if not record_type:
            raise CommandError('record-add', 'Record type parameter is required.')

        fields = kwargs.get('fields', [])

        record_fields = []    # type: List[ParsedFieldValue]
        add_attachments = []  # type: List[ParsedFieldValue]
        rm_attachments = []   # type: List[ParsedFieldValue]
        for field in fields:
            parsed_field = RecordEditMixin.parse_field(field)
            if parsed_field.type == 'file':
                (add_attachments if parsed_field.value else rm_attachments).append(parsed_field)
            else:
                record_fields.append(parsed_field)

        if record_type in ('legacy', 'general'):
            record = vault.PasswordRecord()
            self.assign_legacy_fields(record, record_fields)
        else:
            rt_fields = self.get_record_type_fields(params, record_type)
            if not rt_fields:
                raise CommandError('record-add', f'Record type \"{record_type}\" cannot be found.')
            record = vault.TypedRecord()
            record.type_name = record_type
            for rf in rt_fields:
                ref = rf.get('$ref')
                if not ref:
                    continue
                label = rf.get('label', '')
                required = rf.get('required', False)
                field = vault.TypedField.new_field(ref, None, label)
                if required is True:
                    field.required = True
                record.fields.append(field)
            self.assign_typed_fields(record, record_fields)

        record.title = title
        record.notes = self.validate_notes(kwargs.get('notes') or '')

        ignore_warnings = kwargs.get('force') is True
        if len(self.warnings) > 0:
            for warning in self.warnings:
                logging.warning(warning)
            if not ignore_warnings:
                return
        self.warnings.clear()

        if len(add_attachments) > 0:
            self.upload_attachments(params, record, add_attachments, not ignore_warnings)
            if len(self.warnings) > 0:
                for warning in self.warnings:
                    logging.warning(warning)
                if not ignore_warnings:
                    return

        record_management.add_record_to_folder(params, record, folder_uid)

        params.environment_variables[LAST_RECORD_UID] = record.record_uid
        if params.breach_watch:
            api.sync_down(params)
            params.breach_watch.scan_and_store_record_status(params, record.record_uid)
        else:
            params.sync_data = True

        return record.record_uid


class RecordUpdateCommand(Command, RecordEditMixin, RecordMixin):
    def __init__(self):
        super(RecordUpdateCommand, self).__init__()
        self.warnings = []

    def get_parser(self):
        return record_update_parser

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help') is True:
            print(record_fields_description)
            return

        self.warnings.clear()
        record_name = kwargs.get('record')
        if not record_name:
            raise CommandError('record-update', 'Record parameter is required.')
        record = RecordMixin.resolve_single_record(params, record_name)
        if not record:
            raise CommandError('record-update', f'Record \"{record_name}\" not found.')
        if not isinstance(record, (vault.PasswordRecord, vault.TypedRecord)):
            raise CommandError('record-update', f'Record \"{record_name}\" can not be edited.')

        title = kwargs.get('title')
        if title:
            record.title = title
        notes = kwargs.get('notes')
        if isinstance(notes, str):
            notes = self.validate_notes(notes)
            append_notes = False
            if notes.startswith('+'):
                append_notes = True
                notes = notes[1:].strip()
            if append_notes:
                if record.notes:
                    record.notes += '\n'
                record.notes += notes
            else:
                record.notes = notes

        fields = kwargs.get('fields', [])

        record_fields = []    # type: List[ParsedFieldValue]
        add_attachments = []  # type: List[ParsedFieldValue]
        rm_attachments = []   # type: List[ParsedFieldValue]
        for field in fields:
            parsed_field = RecordEditMixin.parse_field(field)
            if parsed_field.type == 'file':
                (add_attachments if parsed_field.value else rm_attachments).append(parsed_field)
            else:
                record_fields.append(parsed_field)

        if isinstance(record, vault.PasswordRecord):
            self.assign_legacy_fields(record, record_fields)
        elif isinstance(record, vault.TypedRecord):
            record_type = kwargs.get('record_type')
            if record_type:
                rt_fields = self.get_record_type_fields(params, record_type)
                if not rt_fields:
                    raise CommandError('record-update', f'Record type \"{record_type}\" cannot be found.')
                self.adjust_typed_record_fields(record, rt_fields)
            self.assign_typed_fields(record, record_fields)
        else:
            raise CommandError('record-update', f'Record \"{record_name}\" can not be edited.')

        ignore_warnings = kwargs.get('force') is True
        if len(self.warnings) > 0:
            for warning in self.warnings:
                logging.warning(warning)
            if not ignore_warnings:
                return
        self.warnings.clear()

        if len(rm_attachments) > 0:
            names = [x.label for x in rm_attachments if x.label]
            self.delete_attachments(params, record, names)
            if len(self.warnings) > 0:
                for warning in self.warnings:
                    logging.warning(warning)
                if not ignore_warnings:
                    return
            self.warnings.clear()

        if len(add_attachments) > 0:
            self.upload_attachments(params, record, add_attachments, not ignore_warnings)
            if len(self.warnings) > 0:
                for warning in self.warnings:
                    logging.warning(warning)
                if not ignore_warnings:
                    return

        record_management.update_record(params, record)
        params.sync_data = True

    @staticmethod
    def adjust_typed_record_fields(record, typed_fields):    # type: (vault.TypedRecord, List[Dict]) -> Optional[bool]
        new_fields = []
        old_fields = list(record.fields)
        custom = list(record.custom)
        should_rebuild = False
        for typed_field in typed_fields:
            if not isinstance(typed_field, dict):
                return
            field_type = typed_field.get('$ref')
            if not field_type:
                return
            field_label = typed_field.get('label') or ''
            required = typed_field.get('required')
            rf = record_types.RecordFields.get(field_type)
            ignore_label = rf.multiple == record_types.Multiple.Never if rf else False

            field = next((x for x in old_fields if x.type == field_type and
                          (ignore_label or (x.label or '') == field_label)), None)
            if field:
                new_fields.append(field)
                old_fields.remove(field)
                if field.label != field_label:
                    field.label = field_label
                    should_rebuild = True
                continue

            field = next((x for x in custom if x.type == field_type and
                          (ignore_label or (x.label or '') == field_label)), None)
            if field:
                field.required = required
                new_fields.append(field)
                custom.remove(field)
                should_rebuild = True
                continue

            field = vault.TypedField.new_field(field_type, None, field_label)
            field.required = required
            new_fields.append(field)
            should_rebuild = True

        if len(old_fields) > 0:
            custom.extend(old_fields)
            should_rebuild = True

        if not should_rebuild:
            should_rebuild = any(x for x in custom if not x.value)

        if should_rebuild:
            record.fields.clear()
            record.fields.extend(new_fields)
            record.custom.clear()
            record.custom.extend((x for x in custom if x.value))

        return should_rebuild
