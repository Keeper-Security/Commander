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
import datetime
import getpass
import io
import logging
import os
import re
import uuid
import urllib.parse
from typing import Dict
from xml.sax.saxutils import escape

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
from pykeepass.attachment import Attachment as KeepassAttachment
from pykeepass.group import Group

from ..importer import path_components, PathDelimiter, BaseFileImporter, BaseExporter, \
    Record, Folder, SharedFolder, BytesAttachment, RecordField
from ... import utils
from ...display import bcolors
from ...utils import parse_totp_uri

_REFERENCE = r'\{REF:([TUPAN])@([IT]):([^\}]+)\}'


class XmlUtils(object):
    @staticmethod
    def escape_string(plain):   # type: (str) -> str
        if not plain:
            return ''
        output = escape(plain)
        return output.replace('\'', '&apos;').replace('\"', '&quot;')


class KeepassImporter(BaseFileImporter):

    @staticmethod
    def get_folder(group):  # type: (Group) -> str
        g = group
        path = ''
        comp = ''
        while isinstance(g, Group):
            if comp:
                if len(path) > 0:
                    path = PathDelimiter + path
                path = comp + path
                comp = None

            nm = g.name
            if nm:
                comp = nm.replace(PathDelimiter, PathDelimiter*2)
            g = g.group
        return path

    def do_import(self, filename, **kwargs):
        password = getpass.getpass(prompt='...' + 'Keepass Password'.rjust(20) + ': ', stream=None)
        print('Press Enter if your Keepass file is not protected with a key file')
        keyfile = input('...' + 'Path to Key file'.rjust(20) + ': ')
        if keyfile:
            keyfile = os.path.expanduser(keyfile)
        else:
            keyfile = None
        try:
            with PyKeePass(filename, password=password, keyfile=keyfile) as kdb:
                root = kdb.root_group
                if not root:
                    return
                groups = [root]  # type: list
                pos = 0
                while pos < len(groups):
                    g = groups[pos]
                    groups.extend(g.subgroups)
                    pos = pos + 1

                records = []
                for group in groups:
                    entries = group.entries
                    if len(entries) > 0:
                        folder = KeepassImporter.get_folder(group)
                        for entry in entries:
                            totp_secret = ''
                            totp_issuer = ''
                            totp_period = 0
                            totp_digits = 0
                            record = Record()
                            fol = Folder()
                            fol.path = folder
                            record.folders = [fol]
                            if entry.uuid:
                                record.uid = utils.base64_url_encode(entry.uuid.bytes)
                            if entry.title:
                                record.title = entry.title
                            if entry.username:
                                record.login = entry.username
                            if entry.password:
                                record.password = entry.password
                            if entry.url:
                                record.login_url = entry.url
                            if entry.notes:
                                record.notes = entry.notes
                            if entry.otp:
                                record.fields.append(RecordField('oneTimeCode', '', entry.otp))
                            if hasattr(entry, 'ctime'):
                                ctime = entry.ctime
                                if isinstance(ctime, datetime.datetime):
                                    record.last_modified = int(ctime.timestamp())
                            for key, value in entry.custom_properties.items():
                                if key == '$type':
                                    record.type = value
                                    continue
                                rest, sep, no = key.rpartition('#')
                                if sep:
                                    if no.isdigit():
                                        key = rest
                                if key.startswith('$'):
                                    ftype, sep, flabel = key.partition(':')
                                    field_type = ftype[1:]
                                    field_label = flabel
                                else:
                                    field_type = ''
                                    field_label = key
                                if field_label in ('TOTPSecret', 'TOTPPeriod', 'TOTPDigits', 'TOTPIssuer', 'ModifyTOTPSettings', 'ViewTOTPSettings'):
                                    # Ignore TOTP custom fields (set via previous Keeper -> KDBX export implementation)
                                    # if the entry's "otp" field contains the corresponding URI
                                    if entry.otp:
                                        continue
                                    if field_label == 'TOTPSecret':
                                        totp_secret = value
                                    elif field_label == 'TOTPIssuer':
                                        totp_issuer = value
                                    elif field_label == 'TOTPPeriod':
                                        try:
                                            totp_period = int(value)
                                        except:
                                            pass
                                    elif field_label == 'TOTPDigits':
                                        try:
                                            totp_digits = int(value)
                                        except:
                                            pass
                                else:
                                    field = RecordField()
                                    field.type = field_type
                                    field.label = field_label
                                    field.value = KeepassImporter.import_field(field_type, value)
                                    record.fields.append(field)
                            if totp_secret:
                                value = f'otpauth://totp/?secret={totp_secret}'
                                if totp_issuer:
                                    value += f'&issuer={urllib.parse.quote_plus(totp_issuer)}'
                                if totp_period > 0:
                                    value += f'&period={totp_period}'
                                if totp_digits > 0:
                                    value += f'&digits={totp_digits}'
                                field = RecordField()
                                field.type = 'oneTimeCode'
                                field.value = KeepassImporter.import_field(field_type, value)
                                record.fields.append(field)

                            if entry.attachments:
                                for a in entry.attachments:
                                    if isinstance(a, KeepassAttachment):
                                        if record.attachments is None:
                                            record.attachments = []
                                        atta = BytesAttachment(a.filename, a.binary)
                                        atta.file_uid = a.id
                                        record.attachments.append(atta)

                            records.append(record)
                id_map = None
                title_map = None
                ref_re = re.compile(_REFERENCE, re.IGNORECASE)

                def resolve_references(text):
                    nonlocal id_map
                    nonlocal title_map

                    if not text:
                        return text
                    matches = list(ref_re.finditer(text))
                    if not matches:
                        return text
                    values = []
                    for match in matches:
                        comps = match.groups()
                        val = match.group(0)
                        if len(comps) == 3:
                            rec = None
                            if comps[1].upper() == 'I':
                                if id_map is None:
                                    id_map = {}
                                    for r in records:
                                        if r.uid:
                                            id_map[r.uid] = r
                                uid = uuid.UUID(comps[2])
                                if uid:
                                    ref_id = utils.base64_url_encode(uid.bytes)
                                    rec = id_map.get(ref_id)
                            elif comps[1].upper() == 'T':
                                if title_map is None:
                                    title_map = {}
                                    for r in records:
                                        if r.title:
                                            title_map[r.title] = r
                                rec = title_map.get(comps[2])
                            if rec:
                                field_id = comps[0].upper()
                                if field_id == 'T':
                                    val = rec.title
                                elif field_id == 'U':
                                    val = rec.login
                                elif field_id == 'P':
                                    val = rec.password
                                elif field_id == 'A':
                                    val = rec.login_url
                                elif field_id == 'N':
                                    val = rec.notes
                        values.append(val or '')

                        idx = list(range(len(matches)))
                        idx.reverse()
                        for index in idx:
                            match = matches[index]
                            val = values[index] if index < len(values) else ''
                            text = text[:match.start()] + val + text[match.end():]
                        return text

                for record in records:
                    try:
                        record.login = resolve_references(record.login)
                        record.password = resolve_references(record.password)
                        record.login_url = resolve_references(record.login_url)
                        record.notes = resolve_references(record.notes)
                        for field in record.fields:
                            field.value = resolve_references(field.value)
                    except Exception as e:
                        logging.debug(e)
                    yield record
        except CredentialsError:
            logging.warning('Invalid Keepass credentials')

    def extension(self):
        return 'kdbx'


class KeepassExporter(BaseExporter, XmlUtils):
    @staticmethod
    def to_keepass_value(keeper_value):  # type: (any) -> str
        if not keeper_value:
            return ''
        if isinstance(keeper_value, list):
            return ','.join((KeepassExporter.to_keepass_value(x) for x in keeper_value))
        elif isinstance(keeper_value, dict):
            return ';\n'.join((f'{k}:{KeepassExporter.to_keepass_value(v)}' for k, v in keeper_value.items()))
        else:
            return str(keeper_value)

    def do_export(self, filename, records, file_password=None, **kwargs):
        master_password = file_password
        confirmed = True
        while not master_password or not confirmed:
            print('Choose password for your Keepass file')
            master_password = getpass.getpass(prompt='...' + 'Keepass Password'.rjust(20) + ': ', stream=None)
            print('\nRe-enter password for your Keepass file')
            confirmation = getpass.getpass(prompt='...' + 'Keepass Password'.rjust(20) + ': ', stream=None)
            confirmed = master_password == confirmation
            retry_msg = 'The passwords you entered do not match.\nPlease try again.\n'
            fail_msg = bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + retry_msg + bcolors.ENDC
            not confirmed and print(fail_msg)

        sfs = []  # type: list[SharedFolder]
        rs = []   # type: list[Record]
        for x in records:
            if isinstance(x, Record):
                rs.append(x)
            elif isinstance(x, SharedFolder):
                sfs.append(x)

        template_file = os.path.join(os.path.dirname(__file__), 'template.kdbx')

        with PyKeePass(template_file, password='111111') as kdb:
            kdb.password = master_password
            root = kdb.root_group

            for r in rs:
                try:
                    node = root
                    if r.folders:
                        fol = r.folders[0]
                        for is_shared in [True, False]:
                            path = fol.domain if is_shared else fol.path
                            if path:
                                comps = list(path_components(path))
                                for i in range(len(comps)):
                                    comp = comps[i]
                                    sub_node = next((x for x in node.subgroups if x.name == comp), None)
                                    if sub_node is None:
                                        sub_node = kdb.add_group(node, comp)
                                    node = sub_node
                    entry = None
                    entries = node.entries
                    for en in entries:
                        if en.title == r.title and en.username == r.login and en.password == r.password:
                            entry = en
                            break

                    if entry is None:
                        entry = kdb.add_entry(node, title=r.title or '', username=r.login or '',
                                              password=r.password or '', url=r.login_url or '',
                                              notes=r.notes or '')
                        if r.uid:
                            entry.UUID = uuid.UUID(bytes=utils.base64_url_decode(r.uid))
                    if r.type:
                        entry.set_custom_property('$type', r.type)
                    if r.fields:
                        custom_names = {}   # type: Dict[str, int]
                        for cf in r.fields:
                            if cf.type == 'oneTimeCode':
                                entry.otp = cf.value
                                # Set custom fields for Pleasant Password TOTP compatibility
                                totp_props = parse_totp_uri(cf.value)
                                for key in ['secret', 'period', 'issuer', 'digits']:
                                    val = totp_props.get(key)
                                    val and entry.set_custom_property(f'TOTP{key.capitalize()}', str(val))

                                continue
                            if cf.type and cf.label:
                                title = f'${cf.type}:{cf.label}'
                            elif cf.type:
                                title = f'${cf.type}'
                            else:
                                title = cf.label or ''
                            if title in custom_names:
                                no = custom_names[title]
                                no += 1
                                custom_names[title] = no
                                title = f'{title}#{no}'
                            else:
                                custom_names[title] = 1
                            entry.set_custom_property(title, self.to_keepass_value(BaseExporter.export_field(cf.type, cf.value)))

                    if r.attachments:
                        for atta in r.attachments:
                            if atta.size < self.max_size:
                                with atta.open() as ina, io.BytesIO() as outa:
                                    buffer = bytearray(10240)
                                    view = memoryview(buffer)
                                    while True:
                                        bytes_read = ina.readinto(view)
                                        if bytes_read == 0:
                                            break
                                        outa.write(view[0:bytes_read])
                                    del view
                                    del buffer
                                    outa.flush()
                                    binary = outa.getvalue()

                                if binary:
                                    binary_id = kdb.add_binary(binary, compressed=True, protected=False)
                                    entry.add_attachment(binary_id, atta.name)
                            else:
                                scale = ''
                                msize = self.max_size
                                if msize > 1024 ** 3:
                                    scale = 'G'
                                    msize //= 1024 ** 3
                                elif msize > 1024 ** 2:
                                    scale = 'M'
                                    msize //= 1024 ** 2
                                elif msize > 1024:
                                    scale = 'K'
                                    msize //= 1024
                                logging.warning(
                                    'File \'{0}\' was skipped because it exceeds the {1}{2} file size limit.'.format(atta.name, msize, scale))
                except Exception as e:
                    logging.debug(e)

            kdb.save(filename=filename)

    def has_shared_folders(self):
        return True

    def has_attachments(self):
        return True

    def extension(self):
        return 'kdbx'

    def supports_v3_record(self):
        return False
