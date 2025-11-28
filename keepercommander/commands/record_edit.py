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
import itertools
import json
import logging
import os
from typing import List, Optional, Any, Dict, Union, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from urllib.parse import urlunparse

from .base import Command, RecordMixin, FolderMixin
from .helpers.timeout import parse_timeout
from .. import api, utils, vault, record_types, generator, crypto, attachment, record_facades, record_management
from ..breachwatch import BreachWatch
from ..commands import recordv3
from ..error import CommandError
from ..params import KeeperParams, LAST_RECORD_UID
from ..subfolder import try_resolve_path, find_folders, get_folder_path
from ..proto import APIRequest_pb2
from ..recordv3 import RecordV3


record_add_parser = argparse.ArgumentParser(prog='record-add', description='Add a record to folder.', allow_abbrev=False)
record_add_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true',
                               help='Display help on field parameters.')
record_add_parser.add_argument('-f', '--force', dest='force', action='store_true', help='ignore warnings')
record_add_parser.add_argument('-t', '--title', dest='title', action='store', help='record title')
record_add_parser.add_argument('-rt', '--record-type', dest='record_type', action='store', help='record type')
record_add_parser.add_argument('-n', '--notes', dest='notes', action='store', help='record notes')
record_add_parser.add_argument('--folder', dest='folder', action='store',
                               help='folder name or UID to store record')
record_add_parser.add_argument('--self-destruct', dest='self_destruct', action='store',
                               metavar='<NUMBER>[(m)inutes|(h)ours|(d)ays]',
                               help='Time period record share URL is valid. The record will be deleted in your vault in 5 minutes since open')
record_add_parser.add_argument('--pam-config', dest='pam_config', action='store',
                               help='PAM configuration UID or name to sync password to cloud provider (Azure AD, AWS IAM)')
record_add_parser.add_argument('--send-email', dest='send_email', action='store',
                               help='Email address to send onboarding email with share URL (requires --self-destruct)')
record_add_parser.add_argument('--email-config', dest='email_config', action='store',
                               help='Email configuration name to use for sending (required with --send-email)')
record_add_parser.add_argument('--email-message', dest='email_message', action='store',
                               help='Custom message to include in onboarding email')
record_add_parser.add_argument('fields', nargs='*', type=str,
                               help='load record type data from strings with dot notation')

record_update_parser = argparse.ArgumentParser(prog='record-update', description='Update a record.')
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


append_parser = argparse.ArgumentParser(prog='append-notes', description='Append notes to an existing record.')
append_parser.add_argument('--notes', dest='notes', action='store', help='notes')
append_parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')


delete_attachment_parser = argparse.ArgumentParser(
    prog='delete-attachment', description='Delete an attachment from a record.',
    usage="Example to remove two files for a record: delete-attachment {uid} --name secrets.txt --name photo.jpg")
delete_attachment_parser.add_argument('--name', dest='name', action='append', required=True, help='attachment file name or ID. Can be repeated.')
delete_attachment_parser.add_argument('record', action='store', help='record path or UID')


download_parser = argparse.ArgumentParser(prog='download-attachment', description='Download record attachments.')
download_parser.add_argument('-r', '--recursive', dest='recursive', action='store_true',
                             help='Download recursively through subfolders')
download_parser.add_argument('--out-dir', dest='out_dir', action='store', help='Local folder for downloaded files')
download_parser.add_argument('--preserve-dir', dest='preserve_dir', action='store_true',
                             help='Preserve vault folder structure')
download_parser.add_argument('--record-title', dest='record_title', action='store_true',
                             help='Add record title to attachment file.')
download_parser.add_argument('records', nargs='*', help='Record/Folder path or UID')


upload_parser = argparse.ArgumentParser(prog='upload-attachment', description='Upload record attachments.')
upload_parser.add_argument('--file', dest='file', action='append', required=True, help='file name to upload')
upload_parser.add_argument('record', action='store', help='record path or UID')


record_fields_description = '''
Commander supports two types of records:
1. Typed
2. Legacy (update only)

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

If field label contains equal sign '=' then double it.
If field value starts with equal sign then prepend a value with space
Example:
    text.aaa==bbb=" =ccc"     sets custom field with label "aaa=bbb" to "=ccc"

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
keyPair           Key Pair               object         {"publicKey": "", "privateKey": ""}

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
$GEN:[alg],[n]          password           Generates a random password      $GEN:dice,5
                                           Default algorith is rand         alg: [rand | dice | crypto]
                                           Optional: password length
$GEN                    oneTimeCode        Generates TOTP URL
$GEN:[alg,][enc]        keyPair            Generates a key pair and         $GEN:ec,enc
                                           optional passcode                alg: [rsa | ec | ed25519], enc
$JSON:<JSON TEXT>       any object         Sets a field value as JSON
                                           phone.Cell=$JSON:'{"number": "(555) 555-1234", "type": "Mobile"}'

PAM records require a PAM Configuration and additional commands for complete setup.
Example setup: A machine with user set up for rotation, connections, and tunneling:

mkdir gwapp -sf -a
secrets-manager app create gwapp1
secrets-manager share add --app=gwapp1 --secret=SHARED_FOLDER_UID --editable

pam gateway new --name=gateway1 --application=gwapp1 --config-init=b64 --return_value
pam config new --environment=local --title=config1 --gateway=gateway1 -sf=SHARED_FOLDER_UID \
    --connections=on --tunneling=on --rotation=on --remote-browser-isolation=on

record-add --folder=SHARED_FOLDER_UID --title=admin1 -rt=pamUser login=admin1 password="$GEN:rand,16"
record-add --folder=SHARED_FOLDER_UID --title=user1  -rt=pamUser login=user1  password="$GEN:rand,16"
record-add --folder=SHARED_FOLDER_UID --title=machine1 -rt=pamMachine \
  pamHostname="$JSON:{\"hostName\": \"127.0.0.1\", \"port\": \"22\"}"

pam tunnel edit PAM_MACHINE_UID --configuration=PAM_CONFIG_UID --enable-tunneling
pam connection edit PAM_MACHINE_UID --configuration=PAM_CONFIG_UID \
  --connections=on \
  --protocol=ssh \
  --admin-user=ADMIN_USER_UID

pam rotation edit --config=PAM_CONFIG_UID \
  --record=PAM_USER_UID \
  --resource=PAM_MACHINE_UID \
  --admin-user=ADMIN_USER_UID \
  --on-demand --enable --force
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
        while value.startswith('='):
            name1, sel, value1 = value[1:].partition('=')
            if sel:
                name += sel + name1
                value = value1
            else:
                break

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
        return ParsedFieldValue(field_section, field_type, field_label, value.strip())

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
                    record.password = self.generate_password(action_params)
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
    def generate_password(parameters=None):   # type: (Optional[Sequence[str]]) -> str
        if isinstance(parameters, (tuple, list, set)):
            algorithm = next((x for x in parameters if x in ('rand', 'dice', 'crypto')), 'rand')
            length = next((x for x in parameters if x.isnumeric()), None)
            if isinstance(length, str) and len(length) > 0:
                try:
                    length = int(length)
                except ValueError:
                    pass
        else:
            algorithm = 'rand'
            length = None

        if algorithm == 'crypto':
            gen = generator.CryptoPassphraseGenerator()
        elif algorithm == 'dice':
            if isinstance(length, int):
                if length < 1:
                    length = 1
                elif length > 40:
                    length = 40
            else:
                length = 5
            gen = generator.DicewarePasswordGenerator(length)
        else:
            if isinstance(length, int):
                if length < 4:
                    length = 4
                elif length > 200:
                    length = 200
            else:
                length = 20
            gen = generator.KeeperPasswordGenerator(length=length)
        return gen.generate()

    @staticmethod
    def generate_totp_url():
        secret = base64.b32encode(crypto.get_random_bytes(20)).decode()

        return f'otpauth://totp/Commander?secret={secret}&issuer=Keeper'

    def validate_json_value(self, field_type, field_value):        # type: (str, Any) -> Any
        record_field = record_types.RecordFields.get(field_type)
        if not record_field:
            return field_value
        value_type = record_types.FieldTypes[record_field.type]
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
            notes = notes.replace('\\\\n', '\x00')
            notes = notes.replace('\\n', '\n')
            notes = notes.replace('\x00', '\\n')
        return notes

    @staticmethod
    def adjust_typed_record_fields(record, typed_fields):    # type: (vault.TypedRecord, List[Dict]) -> Optional[bool]
        new_fields = []
        old_fields = [x for x in itertools.chain(record.fields, record.custom) if x.value]
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

            # exact match
            field = next((x for x in old_fields if x.type == field_type and
                          (ignore_label or (x.label or '') == field_label)), None)
            # match first not empty
            if not field:
                if field_label:
                    field = next((x for x in old_fields if x.type == field_type and not x.label and x.value), None)
                else:
                    field = next((x for x in old_fields if x.type == field_type and x.value), None)

            if field:
                old_fields.remove(field)
                new_fields.append(field)
                field.required = required
                if field.label != field_label:
                    field.label = field_label
                    should_rebuild = True
                continue

            default_value = None
            if field_type == 'appFiller' and 'appFillerData' in typed_field:
                default_value = typed_field['appFillerData']
            field = vault.TypedField.new_field(field_type, default_value, field_label)
            field.required = required
            new_fields.append(field)
            should_rebuild = True

        custom = []
        if len(old_fields) > 0:
            custom.extend(old_fields)
            should_rebuild = True

        if should_rebuild:
            record.fields.clear()
            record.fields.extend(new_fields)
            record.custom.clear()
            record.custom.extend((x for x in custom if x.value))

        return should_rebuild

    def assign_typed_fields(self, record, fields):
        # type: (vault.TypedRecord, List[ParsedFieldValue]) -> None
        if not isinstance(record, vault.TypedRecord):
            raise ValueError('Expected typed record')
        if not isinstance(fields, list):
            raise ValueError('Fields parameter: expected array of fields')

        parsed_fields = collections.deque(fields)
        while len(parsed_fields) > 0:
            parsed_field = parsed_fields.popleft()
            field_type = parsed_field.type or 'text'
            field_label = parsed_field.label or ''
            skip_validation = not parsed_field.value or parsed_field.value.startswith('$JSON')
            if field_type not in record_types.RecordFields:
                if not skip_validation:
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
                        value = self.generate_password(action_params)
                    elif record_field.type in ('oneTimeCode', 'otp'):
                        value = self.generate_totp_url()
                    elif record_field.type in ('keyPair', 'privateKey'):
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
                    elif isinstance(ft.value, bool):
                        lv = parsed_field.value.lower()
                        if lv in ('1', 'y', 'yes', 't', 'true'):
                            value = True
                        elif lv in ('0', 'n', 'no', 'f', 'false'):
                            value = False
                        else:
                            self.on_warning(f'Incorrect boolean value \"{parsed_field.value}\": [t]rue or [f]alse')
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
                    elif isinstance(ft.value, dict):
                        if ft.name == 'name':
                            value = vault.TypedField.import_name_field(parsed_field.value)
                        elif ft.name == 'address':
                            value = vault.TypedField.import_address_field(parsed_field.value)
                        elif ft.name == 'host':
                            value = vault.TypedField.import_host_field(parsed_field.value)
                        elif ft.name == 'phone':
                            value = vault.TypedField.import_phone_field(parsed_field.value)
                        elif ft.name == 'paymentCard':
                            value = vault.TypedField.import_card_field(parsed_field.value)
                        elif ft.name == 'bankAccount':
                            value = vault.TypedField.import_account_field(parsed_field.value)
                        elif ft.name == 'securityQuestion':
                            value = []
                            for qa in parsed_field.value.split(';'):
                                qa = qa.strip()
                                qav = vault.TypedField.import_q_and_a_field(qa)
                                if qav:
                                    value.append(qav)
                        elif ft.name == 'privateKey':
                            value = vault.TypedField.import_ssh_key_field(parsed_field.value)
                        elif ft.name == 'schedule':
                            value = vault.TypedField.import_schedule_field(parsed_field.value)
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
                            if isinstance(value, dict) and isinstance(record_field.value[0], dict):
                                record_field.value[0].update(value)
                                noneKeys = [k for k,v in record_field.value[0].items() if v is None]
                                for k in noneKeys:
                                    del record_field.value[0][k]
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

        # Validate email parameters
        send_email = kwargs.get('send_email')
        if send_email:
            if not kwargs.get('email_config'):
                raise CommandError('record-add', '--send-email requires --email-config to specify email configuration')

            # Validate email provider dependencies early (before creating record)
            try:
                from .email_commands import find_email_config_record, load_email_config_from_record
                from ..email_service import validate_email_provider_dependencies

                email_config_name = kwargs.get('email_config')
                config_uid = find_email_config_record(params, email_config_name)
                email_config_obj = load_email_config_from_record(params, config_uid)

                # Check if required dependencies are installed for this provider
                is_valid, error_message = validate_email_provider_dependencies(email_config_obj.provider)

                if not is_valid:
                    raise CommandError('record-add', f'\n{error_message}')

            except Exception as e:
                # Re-raise CommandError as-is, wrap other exceptions
                if isinstance(e, CommandError):
                    raise
                raise CommandError('record-add', f'Failed to validate email configuration: {e}')

        # Handle share link creation
        # If --send-email is used without --self-destruct, create a 24h time-based expiration (not self-destruct)
        expiration_period = None
        self_destruct = kwargs.get('self_destruct')
        is_self_destruct_link = False  # Track whether to enable self-destruct on first use

        if self_destruct:
            expiration_period = parse_timeout(self_destruct)
            if expiration_period.total_seconds() > 182 * 24 * 60 * 60:
                raise CommandError('', 'URL expiration period cannot be greater than 6 months.')
            is_self_destruct_link = True  # User explicitly requested self-destruct
        elif send_email:
            # Auto-create share link with 24-hour time-based expiration (without self-destruct)
            expiration_period = parse_timeout('24h')
            self_destruct = '24h'  # For email template text
            is_self_destruct_link = False  # Time-based only, can be used multiple times
            logging.info('--send-email used without --self-destruct, creating 24 hour time-based share link')

        folder_uid = FolderMixin.resolve_folder(params, kwargs.get('folder'))

        self.warnings.clear()
        title = kwargs.get('title')
        if not title:
            raise CommandError('record-add', 'Title parameter is required.')
        record_type = kwargs.get('record_type')   # type: Optional[str]
        if not record_type:
            raise CommandError('record-add', 'Record type parameter is required.')

        fields = kwargs.get('fields', [])
        # Filter out empty strings that might be introduced by copy-paste or line continuation issues
        fields = [field.strip() for field in fields if field.strip()]

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
            raise CommandError('record-add', 'Legacy record type is not supported anymore.')
            # record = vault.PasswordRecord()
            # self.assign_legacy_fields(record, record_fields)
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
                default_value = None
                if ref == 'appFiller':
                    if 'appFillerData' in rf:
                        default_value = rf['appFillerData']
                field = vault.TypedField.new_field(ref, default_value, label)
                if required is True:
                    field.required = True
                record.fields.append(field)
            self.assign_typed_fields(record, record_fields)

        record_uid = str(kwargs.get('record_uid', ''))
        if RecordV3.is_valid_ref_uid(record_uid):
            record.record_uid = record_uid
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
        params.sync_data = True
        params.environment_variables[LAST_RECORD_UID] = record.record_uid

        # PAM password sync (best-effort, Decision 4)
        pam_config_name = kwargs.get('pam_config')
        if pam_config_name:
            try:
                self._sync_password_to_pam(params, record, pam_config_name)
            except Exception as e:
                logging.warning(f'[PAM] Failed to sync password to cloud provider: {e}')
                # Best-effort: continue with record creation

        share_url = None
        if expiration_period is not None:
            record_uid = record.record_uid
            record_key = record.record_key
            client_key = utils.generate_aes_key()
            client_id = crypto.hmac_sha512(client_key, 'KEEPER_SECRETS_MANAGER_CLIENT_ID'.encode())
            rq = APIRequest_pb2.AddExternalShareRequest()
            rq.recordUid = utils.base64_url_decode(record_uid)
            rq.encryptedRecordKey = crypto.encrypt_aes_v2(record_key, client_key)
            rq.clientId = client_id
            rq.accessExpireOn = utils.current_milli_time() + int(expiration_period.total_seconds() * 1000)
            rq.isSelfDestruct = is_self_destruct_link
            api.communicate_rest(params, rq, 'vault/external_share_add', rs_type=APIRequest_pb2.Device)
            # Extract hostname from params.server in case it contains full URL with protocol
            from urllib.parse import urlparse
            parsed = urlparse(params.server)
            server_netloc = parsed.netloc if parsed.netloc else parsed.path  # parsed.path for plain hostname
            share_url = urlunparse(('https', server_netloc, '/vault/share', None, None, utils.base64_url_encode(client_key)))

        # Send onboarding email (best-effort, Decision 4)
        if send_email and share_url:
            try:
                self._send_onboarding_email(
                    params=params,
                    email_config_name=kwargs.get('email_config'),
                    to_address=send_email,
                    share_url=share_url,
                    record_title=record.title,
                    custom_message=kwargs.get('email_message', ''),
                    expiration=self_destruct
                )
            except Exception as e:
                logging.warning(f'[EMAIL] Failed to send onboarding email: {e}')
                # Best-effort: continue and return share URL

        if share_url:
            return share_url
        else:
            BreachWatch.scan_and_update_security_data(params, record.record_uid, params.breach_watch)
            return record.record_uid

    def _sync_password_to_pam(self, params: KeeperParams, record: vault.TypedRecord, pam_config_name: str):
        """
        Sync password to cloud provider using PAM configuration.

        Args:
            params: KeeperParams session
            record: TypedRecord containing credentials
            pam_config_name: PAM configuration UID or name

        Raises:
            CommandError: If PAM sync fails
        """
        logging.info(f'[PAM] Syncing password to cloud provider using config: {pam_config_name}')

        # Find PAM configuration record
        pam_config_uid = None
        if pam_config_name in params.record_cache:
            pam_config_uid = pam_config_name
        else:
            # Search by name
            for record_uid in params.record_cache:
                rec = vault.KeeperRecord.load(params, record_uid)
                if isinstance(rec, vault.TypedRecord) and rec.title == pam_config_name:
                    # Check if this is a PAM config (look for pamConfig record type)
                    if rec.record_type in ('pamAwsConfiguration', 'pamAzureConfiguration'):
                        pam_config_uid = record_uid
                        break

        if not pam_config_uid:
            raise CommandError('record-add', f'PAM configuration "{pam_config_name}" not found')

        # Extract username and password from record
        username = None
        password = None

        for field in record.fields:
            if field.type == 'login' and field.value:
                username = field.value[0] if isinstance(field.value, list) else field.value
            elif field.type == 'password' and field.value:
                password = field.value[0] if isinstance(field.value, list) else field.value

        if not username or not password:
            raise CommandError('record-add', 'Record must have login and password fields for PAM sync')

        # Load PAM configuration
        pam_record = vault.KeeperRecord.load(params, pam_config_uid)
        if not isinstance(pam_record, vault.TypedRecord):
            raise CommandError('record-add', f'PAM configuration record {pam_config_uid} is not a typed record')

        # Determine PAM plugin based on record type
        plugin_name = None
        if pam_record.record_type == 'pamAzureConfiguration':
            plugin_name = 'azureadpwd'
        elif pam_record.record_type == 'pamAwsConfiguration':
            plugin_name = 'awspswd'
        else:
            raise CommandError('record-add', f'Unsupported PAM configuration type: {pam_record.record_type}')

        # Invoke PAM plugin to set password
        try:
            logging.info(f'[PAM] Calling {plugin_name} plugin to set password for user: {username}')

            if plugin_name == 'azureadpwd':
                # Import Azure AD plugin
                from ...plugins.azureadpwd import azureadpwd

                # Call the rotate function with PAM config record
                success = azureadpwd.rotate(pam_record, password)

                if not success:
                    raise CommandError('record-add', 'Azure AD password rotation failed')

                logging.info(f'[PAM] Successfully synced password to Azure AD for user: {username}')

            elif plugin_name == 'awspswd':
                # Import AWS plugin and common rotator
                from ...plugins.awspswd import aws_passwd

                # Extract AWS credentials from PAM config
                aws_access_key = None
                aws_secret_key = None
                aws_profile = None
                aws_assume_role = None

                for field in pam_record.fields:
                    if field.type == 'login' and field.value:
                        aws_access_key = field.value[0] if isinstance(field.value, list) else field.value
                    elif field.type == 'password' and field.value:
                        aws_secret_key = field.value[0] if isinstance(field.value, list) else field.value

                # Check custom fields for profile and assume role
                for field in pam_record.custom:
                    if field.label == 'cmdr:aws_profile' and field.value:
                        aws_profile = field.value[0] if isinstance(field.value, list) else field.value
                    elif field.label == 'cmdr:aws_assume_role' and field.value:
                        aws_assume_role = field.value[0] if isinstance(field.value, list) else field.value

                # Create rotator instance
                rotator = aws_passwd.Rotator(
                    login=username,
                    password=password,
                    aws_profile=aws_profile,
                    aws_assume_role=aws_assume_role
                )

                # Set AWS credentials in environment or use profile
                if aws_access_key and aws_secret_key:
                    import os
                    original_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
                    original_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

                    try:
                        os.environ['AWS_ACCESS_KEY_ID'] = aws_access_key
                        os.environ['AWS_SECRET_ACCESS_KEY'] = aws_secret_key

                        # Rotate password
                        success = rotator.rotate(pam_record, password)
                    finally:
                        # Restore original environment
                        if original_access_key:
                            os.environ['AWS_ACCESS_KEY_ID'] = original_access_key
                        else:
                            os.environ.pop('AWS_ACCESS_KEY_ID', None)
                        if original_secret_key:
                            os.environ['AWS_SECRET_ACCESS_KEY'] = original_secret_key
                        else:
                            os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
                else:
                    # Use AWS profile
                    success = rotator.rotate(pam_record, password)

                if not success:
                    raise CommandError('record-add', 'AWS IAM password rotation failed')

                logging.info(f'[PAM] Successfully synced password to AWS IAM for user: {username}')

            else:
                raise CommandError('record-add', f'Unknown PAM plugin: {plugin_name}')

        except ImportError as e:
            raise CommandError('record-add', f'PAM plugin "{plugin_name}" dependencies not installed: {e}')
        except Exception as e:
            raise CommandError('record-add', f'PAM password sync failed: {e}')

    def _send_onboarding_email(
        self,
        params: KeeperParams,
        email_config_name: str,
        to_address: str,
        share_url: str,
        record_title: str,
        custom_message: str,
        expiration: str
    ):
        """
        Send onboarding email with one-time share URL.

        Args:
            params: KeeperParams session
            email_config_name: Email configuration name
            to_address: Recipient email address
            share_url: One-time share URL
            record_title: Title of the record
            custom_message: Custom message from administrator
            expiration: Expiration period string (e.g., "24h", "1d")

        Raises:
            CommandError: If email sending fails
        """
        logging.info(f'[EMAIL] Sending onboarding email to {to_address}')

        # Load email configuration
        from .email_commands import find_email_config_record, load_email_config_from_record
        from ..email_service import EmailSender, build_onboarding_email
        from .helpers.timeout import parse_timeout

        config_uid = find_email_config_record(params, email_config_name)
        if not config_uid:
            raise CommandError('record-add', f'Email configuration "{email_config_name}" not found')

        email_config = load_email_config_from_record(params, config_uid)

        # Build email - convert expiration to human-readable format
        expiration_text = '24 hours'  # default
        if expiration:
            try:
                expiration_period = parse_timeout(expiration)
                expire_seconds = int(expiration_period.total_seconds())

                # Convert to human-readable format
                if expire_seconds >= 86400:  # days
                    days = expire_seconds // 86400
                    expiration_text = f"{days} day{'s' if days > 1 else ''}"
                elif expire_seconds >= 3600:  # hours
                    hours = expire_seconds // 3600
                    expiration_text = f"{hours} hour{'s' if hours > 1 else ''}"
                else:  # minutes
                    minutes = expire_seconds // 60
                    expiration_text = f"{minutes} minute{'s' if minutes > 1 else ''}"
            except:
                expiration_text = expiration  # fallback to original if parsing fails

        html_body = build_onboarding_email(
            share_url=share_url,
            custom_message=custom_message or 'Your administrator has shared account credentials with you.',
            record_title=record_title,
            expiration=expiration_text
        )

        # Send email
        sender = EmailSender(email_config)
        subject = f'Keeper Security: Credentials for {record_title}'

        sender.send(
            to=to_address,
            subject=subject,
            body=html_body,
            html=True
        )

        # Persist OAuth tokens if they were refreshed
        if email_config.is_oauth_provider() and email_config._oauth_tokens_updated:
            from .email_commands import update_oauth_tokens_in_record
            logging.debug(f'[EMAIL] Persisting refreshed OAuth tokens for "{email_config_name}"')
            update_oauth_tokens_in_record(
                params,
                config_uid,
                email_config.oauth_access_token,
                email_config.oauth_refresh_token,
                email_config.oauth_token_expiry
            )

        logging.info(f'[EMAIL] Onboarding email sent successfully to {to_address}')


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
        
        from ..enforcement import MasterPasswordReentryEnforcer
        if not MasterPasswordReentryEnforcer.check_and_enforce(params, "record_level"):
            raise CommandError('record-update', 'Operation cancelled: Re-authentication failed')

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
        # Filter out empty strings that might be introduced by copy-paste or line continuation issues
        fields = [field.strip() for field in fields if field.strip()]

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
                record.type_name = record_type
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


class RecordAppendNotesCommand(Command):
    def get_parser(self):
        return append_parser

    def execute(self, params, **kwargs):
        notes = kwargs['notes'] if 'notes' in kwargs else None
        while not notes:
            notes = input("... Notes to append: ")

        edit_command = RecordUpdateCommand()
        kwargs['notes'] = '+' + notes
        edit_command.execute(params, **kwargs)


class RecordDeleteAttachmentCommand(Command):
    def get_parser(self):
        return delete_attachment_parser

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
            raise CommandError('delete-attachment', 'Enter name or uid of existing record')

        names = kwargs['name'] if 'name' in kwargs else None
        if names is None:
            raise CommandError('delete-attachment', 'No file names')

        record = vault.KeeperRecord.load(params, record_uid)
        if not record:
            logging.warning('Record UID \"%s\" not found.', record_uid)

        deleted_files = set()
        if isinstance(record, vault.PasswordRecord):
            if record.attachments:
                for name in names:
                    for atta in record.attachments:
                        if atta.id == name:
                            deleted_files.add(atta.id)
                        elif atta.title and atta.title.lower() == name.lower():
                            deleted_files.add(atta.id)
                        elif atta.name and atta.name.lower() == name.lower():
                            deleted_files.add(atta.id)
                if len(deleted_files) > 0:
                    record.attachments = [x for x in record.attachments if x.id not in deleted_files]
        elif isinstance(record, vault.TypedRecord):
            typed_field = record.get_typed_field('fileRef')
            if typed_field and isinstance(typed_field.value, list):
                for name in names:
                    for file_uid in typed_field.value:
                        if file_uid == name:
                            deleted_files.add(file_uid)
                        else:
                            file_record = vault.KeeperRecord.load(params, file_uid)
                            if isinstance(file_record, vault.FileRecord):
                                if file_record.title.lower() == name.lower():
                                    deleted_files.add(file_uid)
                                elif file_record.name.lower() == name.lower():
                                    deleted_files.add(file_uid)
                if len(deleted_files) > 0:
                    typed_field.value = [x for x in typed_field.value if x not in deleted_files]

        if len(deleted_files) == 0:
            logging.info('Attachment not found')
            return

        record_management.update_record(params, record)
        if params.enterprise_ec_key:
            for file_uid in deleted_files:
                params.queue_audit_event('file_attachment_deleted', record_uid=record_uid, attachment_id=file_uid)
        params.sync_data = True


class RecordDownloadAttachmentCommand(Command):
    def get_parser(self):
        return download_parser

    def execute(self, params, **kwargs):
        records = kwargs.get('records')
        if not records:
            self.get_parser().print_help()
            return

        record_uids = set()
        for record in records:
            folder = None
            if record in params.record_cache:
                record_uids.add(record)
            elif record in params.folder_cache:
                folder = params.folder_cache[record]
            else:
                rs = try_resolve_path(params, record)
                if rs is not None:
                    fol, name = rs
                    if fol is not None:
                        if name:
                            f_uid = fol.uid or ''
                            if f_uid in params.subfolder_record_cache:
                                for uid in params.subfolder_record_cache[f_uid]:
                                    r = vault.KeeperRecord.load(params, uid)
                                    if isinstance(r, (vault.PasswordRecord, vault.TypedRecord)):
                                        if r.title.lower() == name.lower():
                                            record_uids.add(r.record_uid)
                        else:
                            folder = fol
            if folder:
                folders = set()
                folder_uid = folder.uid or ''
                folders.add(folder_uid)
                if kwargs.get('recursive') is True:
                    FolderMixin.traverse_folder_tree(
                        params, folder_uid, lambda x: folders.add(x.uid))
                for uid in folders:
                    if uid in params.subfolder_record_cache:
                        for record_uid in params.subfolder_record_cache[uid]:
                            if record_uid in params.record_cache:
                                record_uids.add(record_uid)

        if len(record_uids) == 0:
            logging.error('Record(s) "%s" not found', ', '.join(records))
            return
        output_dir = kwargs.get('out_dir')
        if output_dir:
            output_dir = os.path.expanduser(output_dir)
        else:
            output_dir = os.getcwd()
        if not os.path.isdir(output_dir):
            os.makedirs(output_dir)

        preserve_dir = kwargs.get('preserve_dir') is True
        record_title = kwargs.get('record_title') is True
        for record_uid in record_uids:
            attachments = list(attachment.prepare_attachment_download(params, record_uid))
            if len(attachments) == 0:
                continue

            subfolder_path = ''
            if preserve_dir:
                folder_uid = next((x for x in find_folders(params, record_uid)), None)
                if folder_uid:
                    subfolder_path = get_folder_path(params, folder_uid, os.sep)
                    subfolder_path = ''.join(x for x in subfolder_path if x.isalnum() or x == os.sep)
                    subfolder_path = subfolder_path.replace(2*os.sep, os.sep)
            if subfolder_path:
                subfolder_path = os.path.join(output_dir, subfolder_path)
                if not os.path.isdir(subfolder_path):
                    os.makedirs(subfolder_path)
            else:
                subfolder_path = output_dir

            title = ''
            if record_title:
                record = vault.KeeperRecord.load(params, record_uid)
                title = record.title
                title = ''.join(x for x in title if x.isalnum() or x.isspace())

            for atta in attachments:
                file_name = atta.title
                if title:
                    file_name = f'{title}-{atta.title}'
                file_name = os.path.basename(file_name)
                name = os.path.join(subfolder_path, file_name)
                if os.path.isfile(name):
                    base_name, ext = os.path.splitext(file_name)
                    name = os.path.join(subfolder_path, f'{base_name}({record_uid}){ext}')
                if os.path.isfile(name):
                    base_name, ext = os.path.splitext(file_name)
                    name = os.path.join(subfolder_path, f'{base_name}({atta.file_id}){ext}')
                atta.download_to_file(params, name)


class RecordUploadAttachmentCommand(Command):
    def get_parser(self):
        return upload_parser

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

        if not record_uid:
            logging.error('Record UID not found for record "%s"', str(record_name))
            return

        upload_tasks = []
        files = kwargs.get('file')
        if isinstance(files, list):
            for name in files:
                file_name = os.path.abspath(os.path.expanduser(name))
                if os.path.isfile(file_name):
                    upload_tasks.append(attachment.FileUploadTask(file_name))
                else:
                    raise CommandError('upload-attachment', f'File "{name}" does not exists')

        if len(upload_tasks) == 0:
            raise CommandError('upload-attachment', 'No files to upload')

        record = vault.KeeperRecord.load(params, record_uid)
        if isinstance(record, (vault.PasswordRecord, vault.TypedRecord)):
            attachment.upload_attachments(params, record, upload_tasks)
            record_management.update_record(params, record)
            params.sync_data = True
