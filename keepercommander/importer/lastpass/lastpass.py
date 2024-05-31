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
import calendar
import datetime
import getpass
import json
import logging
import tempfile
from glob import glob
from typing import Optional, List

from ...params import KeeperParams
from ..importer import (
    BaseImporter, Record, Folder, RecordField, RecordReferences, SharedFolder, Permission, BaseDownloadMembership,
    replace_email_domain, FIELD_TYPE_ONE_TIME_CODE)
from .account import Account
from .exceptions import LastPassUnknownError
from .vault import Vault, TMPDIR_PREFIX
from . import fetcher


class LastPassImporter(BaseImporter):
    def __init__(self):
        super(LastPassImporter, self).__init__()

        self.vault = None
        self.addresses = []  # type: List[LastPassAddress]
        self.months = {}
        _months = ['', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August',
                   'September', 'October', 'November', 'December']
        for i in range(len(_months)):
            if _months[i]:
                month = _months[i].casefold()
                if month not in self.months:
                    self.months[month] = i

        for i in range(len(calendar.month_name)):
            if calendar.month_name[i]:
                month = calendar.month_name[i].casefold()
                if month not in self.months:
                    self.months[month] = i

    def card_expiration(self, from_lastpass):  # type: (str) -> str
        if from_lastpass:
            comp = [x.strip().casefold() for x in from_lastpass.split(',')]
            if len(comp) == 2 and all(comp):
                try:
                    year = int(comp[1])
                    if year < 200:
                        year += 2000
                        comp[1] = str(year)
                except ValueError:
                    pass
                if comp[0] in self.months:
                    return f'{self.months[comp[0]]:0>2}/{comp[1]}'
        return from_lastpass

    def lastpass_date(self, from_lastpass):  # type: (str) -> int
        if from_lastpass:
            comp = [x.strip().casefold() for x in from_lastpass.split(',')]
            if len(comp) == 3 and all(comp):
                try:
                    month = self.months[comp[0]]
                    day = int(comp[1])
                    year = int(comp[2])
                    dt = datetime.date(year, month, day)
                    return int(datetime.datetime.fromordinal(dt.toordinal()).timestamp() * 1000)
                except:
                    pass
        return -1

    def find_address(self, address):  # type: (LastPassAddress) -> Optional[int]
        for i in range(len(self.addresses)):
            if self.addresses[i] == address:
                return i + 1

    def append_address(self, address):  # type: (LastPassAddress) -> Optional[int]
        if isinstance(address, LastPassAddress):
            self.addresses.append(address)
            return len(self.addresses)

    def parse_typed_notes(self, notes):    # type: (str) -> dict
        lines = notes.split('\n')
        fields = {}
        key = ''
        value = ''
        for line in lines:
            k, s, v = line.partition(':')
            if s == ':':
                if key:
                    if key == 'Notes':
                        value += line
                    elif key == 'Private Key':
                        if k == 'Public Key':
                            fields[key] = value
                            key = k
                            value = v
                        else:
                            value += '\n' + line
                    else:
                        fields[key] = value
                        key = k
                        value = v
                else:
                    key = k
                    value = v
            else:
                if key:
                    value += '\n' + line
        if key:
            fields[key] = value
        return fields

    def cleanup(self):
        """Cleanup should be performed when finished with encrypted attachment files"""
        # Don't remove custom specified tmpdir
        if self.vault and self.tmpdir is None:
            self.vault.cleanup()

        old_tmpdir = glob(f'{tempfile.gettempdir()}/{TMPDIR_PREFIX}*')
        if len(old_tmpdir) > 0:
            old_tmpdirs_str = '\n'.join(old_tmpdir)
            warn_msg = f'Previous temporary directories from interrupted imports detected:\n{old_tmpdirs_str}'
            logging.warning(warn_msg)

    def do_import(self, name, users_only=False, old_domain=None, new_domain=None, tmpdir=None, **kwargs):
        dry_run = kwargs.get('dry_run') or False
        request_settings = {}
        params = kwargs.get('params')
        if isinstance(params, KeeperParams):
            request_settings['proxies'] = params.rest_context.proxies
            request_settings['certificate_check'] = params.rest_context.certificate_check
        if 'filter_folder' in kwargs and kwargs['filter_folder']:
            request_settings['filter_folder'] = kwargs['filter_folder']

        self.tmpdir = tmpdir
        username = name
        password = getpass.getpass(prompt='...' + 'LastPass Password'.rjust(30) + ': ', stream=None)
        print('Press <Enter> if account is not protected with Multifactor Authentication')
        twofa_code = getpass.getpass(prompt='...' + 'Multifactor Password'.rjust(30) + ': ', stream=None)
        if not twofa_code:
            twofa_code = None

        try:
            vault = Vault.open_remote(username, password, multifactor_password=twofa_code, users_only=users_only,
                                      tmpdir=tmpdir, get_attachments=not dry_run, **request_settings)
        except LastPassUnknownError as lpe:
            message = str(lpe)
            if message.startswith('Try again OR look for an email'):
                message += 'If you do not receive an email, go to LastPass > Account Settings > Advanced Settings ' \
                           'and ensure that "Disable Email Verification" is unchecked.'
            logging.warning(message)
            return
        else:
            self.vault = vault
            if len(vault.errors) > 0:
                err_list = '\n'.join(vault.errors)
                logging.warning(f'The following errors occurred retrieving Lastpass shared folder members:\n{err_list}')

        for shared_folder in vault.shared_folders:
            if shared_folder.name:
                folder = SharedFolder()
                folder.path = shared_folder.name

                folder.permissions = []
                if shared_folder.members:
                    for member in shared_folder.members:
                        perm = Permission()
                        perm.name = replace_email_domain(member['username'], old_domain, new_domain)
                        perm.manage_records = member['readonly'] == '0'
                        perm.manage_users = member['can_administer'] == '1'
                        folder.permissions.append(perm)
                if shared_folder.teams:
                    for team in shared_folder.teams:
                        perm = Permission()
                        perm.name = team['name']
                        perm.manage_records = team['readonly'] == '0'
                        perm.manage_users = team['can_administer'] == '1'
                        folder.permissions.append(perm)

                yield folder

        missing_titles = 0
        for account in vault.accounts:  # type: Account
            record = Record()
            is_secure_note = False
            if account.url:
                record.login_url = account.url.decode('utf-8', 'ignore')
                if record.login_url == 'http://sn':
                    is_secure_note = True
                    record.login_url = None
                elif record.login_url == 'http://group':
                    continue

            record.type = 'login'
            if account.id:
                record.uid = account.id
            if account.name:
                record.title = account.name.decode('utf-8', 'ignore')
            else:
                missing_titles += 1
                record.title = f'Missing Title {missing_titles}'
                logging.warning(f'Missing title in record from LastPass. Assigning title "{record.title}"')
            if account.username:
                record.login = account.username.decode('utf-8', 'ignore')
            if account.password:
                record.password = account.password.decode('utf-8', 'ignore')
            if account.totp_url:
                record.fields.append(
                    RecordField(type=FIELD_TYPE_ONE_TIME_CODE, value=account.totp_url)
                )
            if isinstance(account.last_modified, int) and account.last_modified > 0:
                record.last_modified = account.last_modified
            if isinstance(account.custom_fields, list):
                for cf in account.custom_fields:
                    field_label = cf.name
                    if cf.type == 'password':
                        field_type = 'secret'
                    elif cf.type == 'email':
                        field_type = 'email'
                    elif cf.type == 'textarea':
                        field_type = 'multiline'
                    elif cf.type == 'tel':
                        field_type = 'phone'
                    else:
                        field_type = 'text'
                    cf = RecordField(type=field_type, label=field_label, value=cf.value)
                    record.fields.append(cf)
            if len(account.attachments) > 0:
                if record.attachments is None:
                    record.attachments = []
                record.attachments = account.attachments
            if account.notes:
                try:
                    notes = account.notes.decode('utf-8', 'ignore')
                except UnicodeDecodeError:
                    notes = ''
                if notes.startswith('NoteType:'):
                    typed_values = self.parse_typed_notes(notes)
                    if 'NoteType' in typed_values:
                        note_type = typed_values.pop('NoteType', '')
                        notes = typed_values.pop('Notes', '')
                        typed_values.pop('Language', None)

                        if note_type == 'Bank Account':
                            self.populate_bank_account(record, typed_values)
                        elif note_type == 'Credit Card':
                            self.populate_credit_card(record, typed_values)
                        elif note_type == 'Address':
                            address = LastPassAddress.from_lastpass(typed_values)
                            if address:
                                addr_ref = self.append_address(address)
                                if addr_ref:
                                    record.uid = addr_ref
                                self.populate_address_only(record, address)
                                self.populate_address(record, typed_values)
                        elif note_type == 'Driver\'s License':
                            address_record = self.populate_driver_license(record, typed_values)
                            if address_record is not None:
                                yield address_record
                        elif note_type == 'Passport':
                            self.populate_passport(record, typed_values)
                        elif note_type == 'Social Security':
                            self.populate_ssn_card(record, typed_values)
                        elif note_type == 'Health Insurance' or note_type == 'Insurance':
                            self.populate_health_insurance(record, typed_values)
                        elif note_type == 'Membership':
                            self.populate_membership(record, typed_values)
                        elif note_type == 'Database':
                            self.populate_database(record, typed_values)
                        elif note_type == 'Server':
                            self.populate_server(record, typed_values)
                        elif note_type == 'SSH Key':
                            self.populate_ssh_key(record, typed_values)
                        elif note_type == 'Software License':
                            self.populate_software_license(record, typed_values)

                    username = typed_values.pop('Username', '')
                    if username:
                        if record.login:
                            if record.login != username:
                                cf = RecordField(label='Username', value=username)
                                if record.type:
                                    cf.type = 'login'
                                record.fields.append(cf)
                        else:
                            record.login = username

                    password = typed_values.pop('Password', '')
                    if password:
                        if record.password:
                            if record.password != password:
                                cf = RecordField(label='Password', value=password)
                                if record.type:
                                    cf.type = 'password'
                                record.fields.append(cf)
                        else:
                            record.password = password

                    url = typed_values.pop('URL', '')
                    if url:
                        if record.login_url:
                            if record.login_url != url:
                                cf = RecordField(label='URL', value=url)
                                if record.type:
                                    cf.type = 'url'
                                record.fields.append(cf)
                        else:
                            record.login_url = url

                    for key in typed_values:
                        value = typed_values[key]
                        if value:
                            if record.type:
                                cf = RecordField(type='text', label=key, value=str(value))
                            else:
                                cf = RecordField(label=key, value=str(value))
                            record.fields.append(cf)
                else:
                    if is_secure_note and not record.login and not record.password:
                        record.type = 'encryptedNotes'
                        cf = RecordField(type='note', value=notes)
                        record.fields.append(cf)
                        notes = ''
                    else:
                        if record.login_url == 'http://':
                            record.login_url = ''

                record.notes = notes

            if account.group or account.shared_folder:
                fol = Folder()
                if account.shared_folder:
                    fol.domain = account.shared_folder.name
                if account.group:
                    fol.path = account.group
                    if isinstance(fol.path, bytes):
                        fol.path = fol.path.decode('utf-8', 'ignore')
                record.folders = [fol]

            yield record

    def populate_address(self, record, notes):  # type: (Record, dict) -> None
        person = LastPassPersonName()
        person.first = notes.pop('First Name', '')
        person.middle = notes.pop('Middle Name', '')
        person.last = notes.pop('Last Name', '')

        if person.first or person.last:
            pf = RecordField(type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)

        dt = self.lastpass_date(notes.pop('Birthday', None))
        if dt != -1:
            dtf = RecordField(type='birthDate', value=dt)
            record.fields.append(dtf)

        email = notes.pop('Email Address', None)
        if email:
            dtf = RecordField(type='email', value=email)
            record.fields.append(dtf)
        for phone_type in ['Phone', 'Evening Phone', 'Mobile Phone', 'Fax']:
            phone = notes.pop(phone_type, '')
            if phone:
                try:
                    phone_dict = json.loads(phone)
                    if isinstance(phone_dict, dict):
                        if 'num' in phone_dict:
                            phone_number = phone_dict['num']
                            phone_ext = phone_dict.get('ext') or ''
                            phone_country_code = phone_dict.get('cc3l') or ''
                            phf = RecordField(type='phone', label=phone_type)
                            phf.value = {
                              #  'region': phone_country_code,
                                'number': phone_number,
                                'ext': phone_ext,
                                'type': ('Mobile' if phone_type.startswith('Mobile') else
                                         'Home' if phone_type.startswith('Evening') else
                                         'Work')
                            }
                            record.fields.append(phf)
                except:
                    pass

    def populate_address_only(self, record, lastpass_address):  # type: (Record, LastPassAddress) -> None
        if lastpass_address:
            record.type = 'address'
            address = RecordField(type='address')
            address.value = {
                'street1': lastpass_address.street1 or '',
                'street2': lastpass_address.street2 or '',
                'city': lastpass_address.city or '',
                'state': lastpass_address.state or '',
                'zip': lastpass_address.zip or '',
                'country': lastpass_address.country or '',
            }
            record.fields.append(address)

    def populate_credit_card(self, record, notes):  # type: (Record, dict) -> None
        record.type = 'bankCard'
        card = RecordField(type='paymentCard')
        card.value = {
            'cardNumber': notes.pop('Number', ''),
            'cardExpirationDate': self.card_expiration(notes.pop('Expiration Date', '')),
            'cardSecurityCode': notes.pop('Security Code', '')
        }
        record.fields.append(card)
        card_holder = RecordField(type='text', label='cardholderName', value=notes.pop('Name on Card', ''))
        record.fields.append(card_holder)

        dt = self.lastpass_date(notes.pop('Start Date', None))
        if dt != -1:
            dtf = RecordField(type='date', label='Start Date', value=dt)
            record.fields.append(dtf)


    def populate_bank_account(self, record, notes):  # type: (Record, dict) -> None
        record.type = 'bankAccount'
        bank = RecordField(type='bankAccount')
        bank.value = {
            'accountType': notes.pop('Account Type', ''),
            'routingNumber': notes.pop('Routing Number', ''),
            'accountNumber': notes.pop('Account Number', ''),
        }
        record.fields.append(bank)

    def populate_passport(self, record, notes): # type: (Record, dict) -> None
        record.type = 'passport'
        number = RecordField(type='accountNumber', label='passportNumber', value=notes.pop('Number', None))
        record.fields.append(number)
        person = LastPassPersonName.from_lastpass(notes.pop('Name', None))
        if person:
            pf = RecordField(type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)
        dt = self.lastpass_date(notes.pop('Date of Birth', None))
        if dt != -1:
            dtf = RecordField(type='birthDate', value=dt)
            record.fields.append(dtf)
        dt = self.lastpass_date(notes.pop('Expiration Date', None))
        if dt != -1:
            dtf = RecordField(type='expirationDate', value=dt)
            record.fields.append(dtf)
        dt = self.lastpass_date(notes.pop('Issued Date', None))
        if dt != -1:
            dtf = RecordField(type='date', label='dateIssued', value=dt)
            record.fields.append(dtf)

    def populate_driver_license(self, record, notes):  # type: (Record, dict) -> Optional[Record]
        record.type = 'driverLicense'
        account_number = RecordField(type='accountNumber', label='dlNumber', value=notes.pop('Number', ''))
        record.fields.append(account_number)
        dt = self.lastpass_date(notes.pop('Expiration Date', None))
        if dt != -1:
            dtf = RecordField(type='expirationDate', value=dt)
            record.fields.append(dtf)
        dt = self.lastpass_date(notes.pop('Date of Birth', None))
        if dt != -1:
            dtf = RecordField(type='birthDate', value=dt)
            record.fields.append(dtf)
        person = LastPassPersonName.from_lastpass(notes.pop('Name', None))
        if person:
            pf = RecordField(type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)
        address = LastPassAddress.from_lastpass(notes)
        address_record = None
        if address:
            ref_no = self.find_address(address)
            if ref_no:
                if record.references is None:
                    record.references = []
                address_ref = next((x for x in record.references if x.type == 'address'), None)
                if address_ref is None:
                    address_ref = RecordReferences(type='address')
                    record.references.append(address_ref)
                address_ref.uids.append(ref_no)
        return address_record

    def populate_ssn_card(self, record, notes):  # type: (Record, dict) -> None
        record.type = 'ssnCard'
        number = RecordField(type='accountNumber', label='identityNumber', value=notes.pop('Number', None))
        record.fields.append(number)
        person = LastPassPersonName.from_lastpass(notes.pop('Name', None))
        if person:
            pf = RecordField(type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)

    def populate_health_insurance(self, record, notes):  # type: (Record, dict) -> None
        record.type = 'healthInsurance'
        number = RecordField(type='accountNumber', value=notes.pop('Policy Number', None))
        record.fields.append(number)
        dt = self.lastpass_date(notes.pop('Expiration', None))
        if dt != -1:
            dtf = RecordField(type='date', label='Expiration', value=dt)
            record.fields.append(dtf)

    def populate_membership(self, record, notes):  # type: (Record, dict) -> None
        record.type = 'membership'
        number = RecordField(type='accountNumber', value=notes.pop('Membership Number', None))
        record.fields.append(number)
        person = LastPassPersonName.from_lastpass(notes.pop('Member Name', None))
        if person:
            pf = RecordField(type='name')
            pf.value = {
                'first': person.first,
                'middle': person.middle,
                'last': person.last
            }
            record.fields.append(pf)
        dt = self.lastpass_date(notes.pop('Start Date', None))
        if dt != -1:
            dtf = RecordField(type='date', label='Start Date', value=dt)
            record.fields.append(dtf)
        dt = self.lastpass_date(notes.pop('Expiration Date', None))
        if dt != -1:
            dtf = RecordField(type='date', label='Expiration Date', value=dt)
            record.fields.append(dtf)

    def populate_database(self,  record, notes):  # type: (Record, dict) -> None
        record.type = 'databaseCredentials'
        db_type = RecordField(type='text', label='type', value=notes.pop('Type', None))
        record.fields.append(db_type)

        host = RecordField(type='host')
        host.value = {
            'hostName': notes.pop('Hostname', ''),
            'port': notes.pop('Port', ''),
        }
        record.fields.append(host)
        record.login_url = ''

    def populate_server(self, record, notes):  # type: (Record, dict) -> None
        record.type = 'serverCredentials'
        host = RecordField(type='host')
        host.value = {
            'hostName': notes.pop('Hostname', ''),
            'port': notes.pop('Port', ''),
        }
        record.fields.append(host)

    def populate_ssh_key(self, record, notes):  # type: (Record, dict) -> None
        record.type = 'sshKeys'
        passphrase = notes.pop('Passphrase', None)
        if passphrase:
            if record.password:
                if record.password != passphrase:
                    passphrase = RecordField(type='password', label='passphrase', value=passphrase)
                    record.fields.append(passphrase)
            else:
                record.password = passphrase
        host = RecordField(type='host')
        host.value = {
            'hostName': notes.pop('Hostname', ''),
            'port': notes.pop('Port', ''),
        }
        record.fields.append(host)
        private_key = notes.pop('Private Key', None)
        public_key = notes.pop('Public Key', None)
        if private_key or public_key:
            value = {
                'privateKey': private_key,
                'publicKey': public_key
            }
            pk = RecordField(type='keyPair', value=value)
            record.fields.append(pk)

        dt = self.lastpass_date(notes.pop('Date', None))
        if dt != -1:
            dtf = RecordField(type='date', value=dt)
            record.fields.append(dtf)

    def populate_software_license(self, record, notes):  # type: (Record, dict) -> None
        record.type = 'softwareLicense'
        number = RecordField(type='licenseNumber', value=notes.pop('License Key', None))
        record.fields.append(number)
        dt = self.lastpass_date(notes.pop('Purchase Date', None))
        if dt != -1:
            dtf = RecordField(type='date', label='dateActive', value=dt)
            record.fields.append(dtf)


class LastPassPersonName(object):
    def __init__(self):
        self.first = ''
        self.middle = ''
        self.last = ''

    @staticmethod
    def from_lastpass(name):  # type: (str) -> 'Optional[LastPassPersonName]'
        if not name:
            return None
        if not isinstance(name, str):
            return None
        person = LastPassPersonName()
        last, sep, other = name.partition(',')
        if sep == ',':
            person.last = last.strip()
            comps = [x for x in other.strip().split(' ') if x]
        else:
            comps = [x for x in name.split(' ') if x]
            person.last = comps.pop(-1)
        if len(comps) > 0:
            person.first = comps.pop(0)
        if len(comps) > 0:
            person.middle = ' '.join(comps)

        if not person.first and not person.last:
            return None

        return person


class LastPassAddress(object):
    def __init__(self):
        self.street1 = ''
        self.street2 = ''
        self.city = ''
        self.state = ''
        self.zip = ''
        self.country = ''

    @staticmethod
    def _compare_case_insensitive(s1, s2):  # type: (any, any) -> bool
        if isinstance(s1, str) and isinstance(s2, str):
            return s1.casefold() == s2.casefold()
        if s1 is None and s2 is None:
            return True
        return False

    def __eq__(self, other):
        if not isinstance(other, LastPassAddress):
            return False
        return (self._compare_case_insensitive(self.street1, other.street1) and
                self._compare_case_insensitive(self.street2, other.street2) and
                self._compare_case_insensitive(self.city, other.city) and
                self._compare_case_insensitive(self.state, other.state))

    @staticmethod
    def from_lastpass(notes):  # type: (dict) -> 'Optional[LastPassAddress]'
        if not isinstance(notes, dict):
            return None

        address = LastPassAddress()
        if 'Address 1' in notes:
            address.street1 = notes.pop('Address 1', '')
            address.street2 = notes.pop('Address 2', '')
            street3 = notes.pop('Address 3', '')
            if street3:
                address.street2 += f' {street3}'
                address.street2 = address.street2.strip()

        elif 'Address' in notes:
            s1, sep, s2 = notes.pop('Address', '').partition(',')
            address.street1 = s1.strip()
            if sep == ',':
                address.street2 = s2.strip()
        else:
            return None

        address.city = notes.pop('City / Town', '')
        address.state = notes.pop('State', '')
        address.zip = notes.pop('Zip / Postal Code', '')
        address.country = notes.pop('Country', '')

        return address


class LastpassMembershipDownload(BaseDownloadMembership):
    def download_membership(self, params, **kwargs):
        username = input('...' + 'LastPass Username'.rjust(30) + ': ')
        if not username:
            logging.warning('LastPass username is required')
            return
        password = getpass.getpass(prompt='...' + 'LastPass Password'.rjust(30) + ': ', stream=None)
        if not password:
            logging.warning('LastPass password is required')
            return

        print('Press <Enter> if account is not protected with Multifactor Authentication')
        twofa_code = getpass.getpass(prompt='...' + 'Multifactor Password'.rjust(30) + ': ', stream=None)
        if not twofa_code:
            twofa_code = None

        session = None
        request_settings = {
            'proxies': params.rest_context.proxies,
            'certificate_check': params.rest_context.certificate_check
        }
        try:
            session = fetcher.login(username, password, twofa_code, **request_settings)
            blob = fetcher.fetch(session, **request_settings)
            encryption_key = blob.encryption_key(username, password)
            vault = Vault(blob, encryption_key, session, shared_folder_details=False, get_attachments=False)

            lastpass_shared_folder = [x for x in vault.shared_folders]

            for lpsf in lastpass_shared_folder:
                logging.info('Loading shared folder membership for "%s"', lpsf.name)

                members, teams, error = fetcher.fetch_shared_folder_members(session, lpsf.id, **request_settings)
                sf = SharedFolder()
                sf.uid = lpsf.id
                sf.path = lpsf.name
                sf.permissions = []
                if members:
                    sf.permissions.extend((self._lastpass_permission(x) for x in members))
                if teams:
                    sf.permissions.extend((self._lastpass_permission(x, team=True) for x in teams))
                yield sf

        except Exception as e:
            logging.warning(e)
        finally:
            if session:
                fetcher.logout(session, **request_settings)

    @staticmethod
    def _lastpass_permission(lp_permission, team=False):  # type: (dict, Optional[bool]) -> Permission
        permission = Permission()
        if team:
            permission.name = lp_permission['name']
        else:
            permission.name = lp_permission['username']
        permission.manage_records = lp_permission['readonly'] == '0'
        permission.manage_users = lp_permission['can_administer'] == '1'
        return permission

