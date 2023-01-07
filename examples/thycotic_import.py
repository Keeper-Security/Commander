import xml.sax
import logging
from typing import Optional, Dict, Tuple
from keepercommander.importer.importer import Record, Folder, RecordField
from keepercommander.importer.json import Exporter
from keepercommander import record_types, vault


class ThycoticHandler(xml.sax.handler.ContentHandler):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.templates = {}
        self.secrets = []
        self.template = None   # type: Optional[dict]
        self.secret = None     # type: Optional[dict]

    def startElement(self, name, attrs):
        if len(self.stack) == 0 and name != 'ImportFile':
            raise Exception('Invalid Thycotic Secret Server XML Export File')

        if len(self.stack) == 2:
            if self.stack[1] == 'SecretTemplates':
                if name == 'secrettype':
                    if self.template is not None:
                        logging.info('Secret template has not been saved')
                    self.template = {
                        'name': '',
                        'fields': {},
                        'field': None,     # type: Optional[dict]
                    }
            elif self.stack[1] == 'Secrets':
                if name == 'Secret':
                    if self.secret is not None:
                        logging.info('Secret has not been saved')
                    self.secret = {
                        'name': '',
                        'template': '',
                        'folder': '',
                        'items': {},
                        'item': None,    # type: Optional[dict]
                    }
        elif len(self.stack) == 4:
            if name == 'field' and self.stack[1] == 'SecretTemplates' and self.stack[2] == 'secrettype' and self.stack[3] == 'fields':
                if self.template['field']:
                    logging.warning('Secret template: field has not been saved')
                self.template['field'] = {
                    'field_name': '',
                    'slug': '',
                }
            elif name == 'SecretItem' and self.stack[1] == 'Secrets' and self.stack[2] == 'Secret' and self.stack[3] == 'SecretItems':
                if self.secret['item']:
                    logging.warning('Secret: item has not been saved')
                self.secret['item'] = {
                    'field_name': '',
                    'slug': '',
                    'value': '',
                }

        self.stack.append(name)

    def endElement(self, name):
        e_name = self.stack.pop(-1)
        if e_name != name:
            logging.warning('Parse: unexpected closing element')
        if len(self.stack) == 2:
            if self.stack[1] == 'SecretTemplates':
                if name == 'secrettype':
                    if self.template is not None:
                        key = self.template.get('name')
                        if key:
                            self.templates[key] = self.template
                        self.template = None
                    else:
                        logging.info('endElement: Secret template has not been created')
            elif self.stack[1] == 'Secrets':
                if name == 'Secret':
                    if self.secret is not None:
                        self.secrets.append(self.secret)
                        self.secret = None
                    else:
                        logging.info('endElement: Secret has not been created')
        elif len(self.stack) == 4:
            if name == 'field' and self.stack[1] == 'SecretTemplates' and self.stack[2] == 'secrettype' and self.stack[3] == 'fields':
                if isinstance(self.template['field'], dict):
                    key = self.template['field'].get('fieldslugname') or self.template['field'].get('name')
                    if key:
                        self.template['fields'][key] = self.template['field']
                    self.template['field'] = None
                else:
                    logging.warning('Secret template: field has not been created')
            elif name == 'SecretItem' and self.stack[1] == 'Secrets' and self.stack[2] == 'Secret' and self.stack[3] == 'SecretItems':
                if isinstance(self.secret['item'], dict):
                    key = self.secret['item'].get('slug') or self.secret['item'].get('field_name')
                    value = self.secret['item'].get('value')
                    if key and value:
                        self.secret['items'][key] = self.secret['item']
                    self.secret['item'] = None
                else:
                    logging.warning('Secret: item has not been created')

    def characters(self, content):
        if len(self.stack) < 4:
            return
        if self.stack[1] == 'SecretTemplates' and self.stack[2] == 'secrettype':
            if self.template is not None:
                if len(self.stack) == 4 and self.stack[3] == 'name':
                    self.template['name'] = content
                if self.stack[3] == 'fields':
                    if isinstance(self.template['field'], dict):
                        if len(self.stack) == 6 and self.stack[4] == 'field':
                            if self.stack[5] == 'fieldslugname':
                                slug = self.template['field'].get('slug')
                                slug += content
                                self.template['field']['slug'] = slug
                            elif self.stack[5] == 'name':
                                field_name = self.template['field'].get('field_name')
                                field_name += content
                                self.template['field']['field_name'] = field_name
                            elif content == 'true':
                                if self.stack[5] in ('isurl', 'ispassword', 'isnotes', 'isfile'):
                                    self.template['field']['slug_type'] = self.stack[5]
            else:
                logging.info('characters: Secret template has not been created')

        elif self.stack[1] == 'Secrets' and self.stack[2] == 'Secret':
            if self.secret is not None:
                if len(self.stack) == 4:
                    if self.stack[3] == 'SecretName':
                        self.secret['name'] = content
                    elif self.stack[3] == 'SecretTemplateName':
                        self.secret['template'] = content
                    elif self.stack[3] == 'FolderPath':
                        content = content.strip('\\')
                        if content.startswith('Personal Folders\\'):
                            content = content.replace('Personal Folders\\', '')
                        self.secret['folder'] = content
                    elif self.stack[3] == 'TotpKey':
                        if content:
                            self.secret['items']['totp'] = {
                                'field_name': 'Totp Key',
                                'slug': 'totp',
                                'value': content,
                            }
                elif len(self.stack) == 6 and self.stack[3] == 'SecretItems' and self.stack[4] == 'SecretItem':
                    if isinstance(self.secret['item'], dict):
                        if self.stack[5] == 'FieldName':
                            field_name = self.secret['item'].get('field_name') or ''
                            field_name += field_name
                            self.secret['item']['field_name'] = content
                        elif self.stack[5] == 'Slug':
                            slug = self.secret['item'].get('slug') or ''
                            slug += content
                            self.secret['item']['slug'] = slug
                        elif self.stack[5] == 'Value':
                            value = self.secret['item'].get('value') or ''
                            value += content
                            self.secret['item']['value'] = value
                    else:
                        logging.info('characters: Secret item has not been created')
            else:
                logging.info('characters: Secret has not been created')


handler = ThycoticHandler()
xml.sax.parse('secrets-export.xml', handler)


def pop_field(items, name):     # type: (Dict[str, str], str) -> Tuple[str, Optional[Dict[str, str]]]
    item = items.pop(name, None)
    if isinstance(item, dict):
        value = item.get('value') or ''
        return str(value), item

    ln = name.replace('-', ' ').replace('   ', ' - ').lower()
    for key in list(items.keys()):
        lkey = key.lower()
        if lkey == ln:
            item = items.pop(lkey, None)
            if isinstance(item, dict):
                value = item.get('value') or ''
                return str(value), item
    return '', None


def pop_field_value(items, name):     # type: (Dict[str, str], str) -> str
    value, _ = pop_field(items, name)
    return value


def has_field(items, name):     # type: (Dict[str, str], str) -> bool
    if name in items:
        return True

    ln = name.replace('-', ' ').replace('   ', ' - ').lower()
    for key in list(items.keys()):
        lkey = key.lower()
        if lkey == ln:
            return True
    return False

records = []

for secret in handler.secrets:
    record = Record()
    record.title = secret.get('name', '')
    path = secret.get('folder', '')
    if path:
        record.folders = []
        record_folder = Folder()
        record_folder.path = path
        record.folders.append(record_folder)

    template_name = secret.get('template', '')
    items = secret['items']
    if template_name in ('Pin', 'Security Alarm Code'):
        record.type = 'encryptedNotes'
    elif template_name == 'Contact':
        record.type = 'address'
    elif template_name == 'Credit Card':
        record.type = 'bankCard'
    elif has_field(items, 'card-number'):
        record.type = 'bankCard'
    elif has_field(items, 'account-number') and has_field(items, 'routing-number'):
        record.type = 'bankAccount'
    elif has_field(items, 'ssn'):
        record.type = 'ssnCard'
    elif has_field(items, 'license-key'):
        record.type = 'softwareLicense'
    elif has_field(items, 'combination'):
        record.type = 'encryptedNotes'
    elif has_field(items, 'healthcare-provider-name'):
        record.type = 'healthInsurance'
    elif any(True for x in ('host', 'server', 'machine', 'ip-address---host-name') if x in items):
        if has_field(items, 'database'):
            record.type = 'databaseCredentials'
        else:
            record.type = 'serverCredentials'
    else:
        record.type = 'login'

    if record.type == 'bankAccount':
        bank_account = record_types.FieldTypes['bankAccount'].value.copy()
        bank_account['accountType'] = ''
        bank_account['accountNumber'] = pop_field_value(items, 'account-number')
        bank_account['routingNumber'] = pop_field_value(items, 'routing-number')
        record.fields.append(RecordField(type='bankAccount', label='', value=bank_account))

    if record.type == 'bankCard':
        bank_card = record_types.FieldTypes['paymentCard'].value.copy()
        bank_card['cardNumber'] = pop_field_value(items, 'card-number')
        _ = pop_field_value(items, 'card-type')
        exp = pop_field_value(items, 'expiration-date')
        if len(exp) >= 4:
            month, sep, year = exp.partition('/')
            if not sep:
                month = exp[:2]
                year = exp[2:]
            if len(month) == 2:
                pass
            elif len(month) == 1:
                month = '0' + month
            else:
                month = ''
            if len(year) == 4:
                pass
            elif len(year) == 2:
                year = '20' + year
            else:
                year = ''
            if month and year:
                bank_card['cardExpirationDate'] = f'{month}/{year}'
        record.fields.append(RecordField(type='paymentCard', label='', value=bank_card))
        name_on_card = pop_field_value(items, 'full-name')
        if name_on_card:
            record.fields.append(RecordField(type='text', label='cardholderName', value=name_on_card))

    for login_field in ('username', 'client-id'):
        if has_field(items, login_field):
            username, field = pop_field(items, login_field)
            if username:
                if record.login:
                    field_label = ''
                    if field:
                        field_label = field.get('field_name', '')
                    record.fields.append(RecordField(type='login', label=field_label, value=username))
                else:
                    record.login = username

    for password_field in ('password', 'client-secret'):
        if has_field(items, password_field):
            password, field = pop_field(items, password_field)
            if password:
                if record.password:
                    field_label = ''
                    if field:
                        field_label = field.get('field_name', '')
                    record.fields.append(RecordField(type='password', label=field_label, value=password))
                else:
                    record.password = password

    if has_field(items, 'address-1'):
        address = record_types.FieldTypes['address'].value.copy()
        address['street1'] = pop_field_value(items, 'address-1')
        address['street2'] = pop_field_value(items, 'address-2')
        addr = pop_field_value(items, 'address-3')
        if addr:
            city, sep, addr = addr.partition(',')
            address['city'] = city
            if sep:
                addr = addr.strip()
                state, sep, zip_code = addr.rpartition(',')
                if not sep:
                    state, sep, zip_code = addr.rpartition(' ')
                address['state'] = state
                address['zip'] = zip_code
        record.fields.append(RecordField(type='address', label='', value=address))

    if has_field(items, 'address1'):
        address = record_types.FieldTypes['address'].value.copy()    # type: dict
        address['street1'] = pop_field_value(items, 'address1')
        a2 = pop_field_value(items, 'address2')
        a3 = pop_field_value(items, 'address3')
        if a3:
            a2 += ' ' + a3
        a2 = a2.strip()
        address['street2'] = a2
        address['city'] = pop_field_value(items, 'city')
        address['state'] = pop_field_value(items, 'state')
        address['zip'] = pop_field_value(items, 'zip')
        address['country'] = pop_field_value(items, 'country')
        if any(True for x in address.values() if x):
            record.fields.append(RecordField(type='address', label='', value=address))

    if has_field(items, 'last-name'):
        name = record_types.FieldTypes['name'].value.copy()
        name['last'] = pop_field_value(items, 'last-name')
        name['first'] = pop_field_value(items, 'first-name')
        if any(True for x in name.values() if x):
            record.fields.append(RecordField(type='name', label='', value=name))

    for full_name_field in ('name'):
        if has_field(items, full_name_field):
            full_name = pop_field_value(items, full_name_field)
            if full_name:
                name = vault.TypedField.import_name_field(full_name)
                if name:
                    record.fields.append(RecordField(type='name', label='', value=name))

    for ssn in ('social-security-number', 'ssn'):
        number = pop_field_value(items, ssn)
        if number:
            record.fields.append(RecordField(type='accountNumber', label='identityNumber', value=number))

    if has_field(items, 'combination') and record.type == 'encryptedNotes':
        combination = pop_field_value(items, 'combination')
        if combination:
            record.fields.append(RecordField(type='note', label='', value=combination))

    for phone_slug in ('contact-number', 'work-phone', 'home-phone', 'mobile-phone', 'fax'):
        phone_number, field = pop_field(items, phone_slug)
        if phone_number:
            phone = vault.TypedField.import_phone_field(phone_number)
            if phone:
                field_label = ''
                if field:
                    field_label = field.get('field_name', '')

                if phone_slug.startswith('work'):
                    phone['type'] = 'Work'
                elif phone_slug.startswith('mobile'):
                    phone['type'] = 'Mobile'
                elif phone_slug.startswith('home'):
                    phone['type'] = 'Home'
                record.fields.append(RecordField(type='phone', label=field_label, value=phone))

    for url_slug in ('website', 'blog', 'resource', 'url', 'tenant'):
        url, field = pop_field(items, url_slug)
        if url:
            if record.login_url:
                field_label = ''
                if field:
                    field_label = field.get('field_name', '')
                record.fields.append(RecordField(type='url', label=field_label, value=url))
            else:
                record.login_url = url

    for host_slug in ('server', 'host', 'machine', 'ip-address---host-name'):
        host_address = pop_field_value(items, host_slug)
        port = pop_field_value(items, host_slug)
        if host_address:
            host = vault.TypedField.import_host_field(host_address)
            if port:
                host['port'] = port
            record.fields.append(RecordField(type='host', label='', value=host))

    for num_slug in ('policy-number', 'group-number'):
        if has_field(items, num_slug):
            number, field = pop_field(items, num_slug)
            if number:
                field_label = ''
                if field:
                    field_label = field.get('field_name', '')
                record.fields.append(RecordField(type='accountNumber', label=field_label, value=number))

    for email_slug in ('email'):
        if has_field(items, email_slug):
            email = pop_field_value(items, email_slug)
            if email:
                record.fields.append(RecordField(type='email', label='', value=email))

    if has_field(items, 'totp'):
        totp_code = pop_field_value(items, 'totp')
        if totp_code:
            field_value = f'otpauth://totp/?secret={totp_code}'
            record.fields.append(RecordField(type='oneTimeCode', label='', value=field_value))

    for slug in list(items.keys()):
        field_value, field = pop_field(items, slug)
        if not field_value:
            continue

        field_label = ''
        if field:
            field_label = field.get('field_name', '')
        slug_type = ''
        if template_name in handler.templates:
            template = handler.templates[template_name]
            slug_type = template['fields'].get(slug) or ''

        is_password = slug_type == 'ispassword'
        is_url = slug_type == 'isurl'
        is_note = slug_type == 'isnotes'

        if is_password and not record.password:
            record.password = field_value
            continue

        if is_url and not record.login_url:
            record.login_url = field_value
            continue

        if is_note and not record.notes:
            record.notes = field_value
            continue

        field_type = 'secret' if is_password else 'url' if is_url else 'note' if is_note else 'text'
        record.fields.append(RecordField(type=field_type, label=field_label, value=field_value))

    records.append(record)

exporter = Exporter()
exporter.execute('keeper-import.json', records)
logging.info('Exported %d records', len(records))
