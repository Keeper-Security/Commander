import xml.sax
import logging
from typing import Optional, Dict, List
from keepercommander.importer.importer import Record, Folder, RecordField, SharedFolder
from keepercommander.importer.json import Exporter
from keepercommander import record_types, vault


class ThycoticHandler(xml.sax.handler.ContentHandler):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.templates = {}
        self.secrets = []
        self.folders = []
        self.template = None   # type: Optional[dict]
        self.secret = None     # type: Optional[dict]
        self.folder = None     # type: Optional[dict]

    def startElement(self, name, attrs):
        if len(self.stack) == 0 and name != 'ImportFile':
            raise Exception('Invalid Thycotic Secret Server XML Export File')

        if len(self.stack) == 2:
            if self.stack[1] == 'SecretTemplates':
                if name == 'secrettype':
                    if self.template is not None:
                        logging.info('Secret template has not been saved')
                    self.template = {'name': '', 'fields': {}, 'field': None}

            elif self.stack[1] == 'Secrets':
                if name == 'Secret':
                    if self.secret is not None:
                        logging.info('Secret has not been saved')
                    self.secret = {'name': '', 'template': '', 'folder': '', 'totp_code': '', 'items': {}, 'item': None}

            elif self.stack[1] == 'Folders':
                if name == 'Folder':
                    if self.folder is not None:
                        logging.info('Folder has not been saved')
                    self.folder = {'name': '', 'path': '', 'permissions': [], 'permission': None, 'shared': False}

        elif len(self.stack) == 4:
            if name == 'field' and self.stack[1] == 'SecretTemplates' and self.stack[2] == 'secrettype' and self.stack[3] == 'fields':
                if self.template:
                    if self.template['field']:
                        logging.warning('Secret template: field has not been saved')
                    self.template['field'] = {'field_name': '', 'slug': '', 'slug_type': ''}
                else:
                    logging.warning('Secret template: field has not been created')

            elif name == 'SecretItem' and self.stack[1] == 'Secrets' and self.stack[2] == 'Secret' and self.stack[3] == 'SecretItems':
                if self.secret:
                    if self.secret['item']:
                        logging.warning('Secret: item has not been saved')
                    self.secret['item'] = {'field_name': '', 'slug': '', 'value': ''}
                else:
                    logging.warning('Secret: item has not been created')

            elif name == 'Permission' and self.stack[1] == 'Folders' and self.stack[2] == 'Folder' and self.stack[3] == 'Permissions':
                if self.folder:
                    if self.folder['permission']:
                        logging.warning('Folder: permission has not been saved')
                    self.folder['permission'] = {'group_name': '', 'user_name': '', 'secret_role': '', 'folder_role': ''}
                else:
                    logging.warning('Folder: permission has not been created')

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
            elif self.stack[1] == 'Folders':
                if name == 'Folder':
                    if self.folder is not None:
                        self.folders.append(self.folder)
                        self.folder = None
                    else:
                        logging.info('endElement: Folder has not been created')

        elif len(self.stack) == 4:
            if name == 'field' and self.stack[1] == 'SecretTemplates' and self.stack[2] == 'secrettype' and self.stack[3] == 'fields':
                if self.template and isinstance(self.template['field'], dict):
                    key = self.template['field'].get('slug') or self.template['field'].get('field_name')
                    if key:
                        self.template['fields'][key] = self.template['field']
                    self.template['field'] = None
                else:
                    logging.warning('Secret template: field has not been created')

            elif name == 'SecretItem' and self.stack[1] == 'Secrets' and self.stack[2] == 'Secret' and self.stack[3] == 'SecretItems':
                if self.secret and isinstance(self.secret['item'], dict):
                    key = self.secret['item'].get('slug') or self.secret['item'].get('field_name')
                    value = self.secret['item'].get('value')
                    if key and value:
                        self.secret['items'][key] = self.secret['item']
                    self.secret['item'] = None
                else:
                    logging.warning('Secret: item has not been created')

            elif name == 'Permission' and self.stack[1] == 'Folders' and self.stack[2] == 'Folder' and self.stack[3] == 'Permissions':
                if self.folder and isinstance(self.folder['permission'], dict):
                    self.folder['permissions'].append(self.folder['permission'])
                    self.folder['permission'] = None
                else:
                    logging.warning('Folder: permission has not been created')

    def characters(self, content):
        if len(self.stack) < 4:
            return
        if len(content) == 0:
            return

        if self.stack[1] == 'SecretTemplates' and self.stack[2] == 'secrettype':
            if self.template is not None:
                if len(self.stack) == 4 and self.stack[3] == 'name':
                    self.template['name'] += content
                elif self.stack[3] == 'fields':
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
                        self.secret['name'] += content
                    elif self.stack[3] == 'SecretTemplateName':
                        self.secret['template'] += content
                    elif self.stack[3] == 'FolderPath':
                        self.secret['folder'] += content
                    elif self.stack[3] == 'TotpKey':
                        self.secret['totp_code'] += content

                elif len(self.stack) == 6 and self.stack[3] == 'SecretItems' and self.stack[4] == 'SecretItem':
                    if isinstance(self.secret['item'], dict):
                        if self.stack[5] == 'FieldName':
                            field_name = self.secret['item'].get('field_name') or ''
                            field_name += content
                            self.secret['item']['field_name'] = field_name
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

        elif self.stack[1] == 'Folders' and self.stack[2] == 'Folder':
            if self.folder is not None:
                if len(self.stack) == 4:
                    if self.stack[3] == 'FolderName':
                        self.folder['name'] += content
                    elif self.stack[3] == 'FolderPath':
                        self.folder['path'] += content

                elif len(self.stack) == 6 and self.stack[3] == 'Permissions' and self.stack[4] == 'Permission':
                    if isinstance(self.folder['permission'], dict):
                        if self.stack[5] == 'GroupName':
                            group_name = self.folder['permission'].get('group_name') or ''
                            group_name += content
                            self.folder['permission']['group_name'] = group_name
                        if self.stack[5] == 'UserName':
                            user_name = self.folder['permission'].get('user_name') or ''
                            user_name += content
                            self.folder['permission']['user_name'] = user_name
                        elif self.stack[5] == 'SecretAccessRoleName':
                            secret_role = self.folder['permission'].get('secret_role') or ''
                            secret_role += content
                            self.folder['permission']['secret_role'] = secret_role
                        elif self.stack[5] == 'FolderAccessRoleName':
                            folder_role = self.folder['permission'].get('folder_role') or ''
                            folder_role += content
                            self.folder['permission']['folder_role'] = folder_role
                    else:
                        logging.info('characters: Folder permission has not been created')
            else:
                logging.info('characters: Folder has not been created')


handler = ThycoticHandler()
xml.sax.parse('secrets-export.xml', handler)


PERSONAL_FOLDER = '\\Personal Folders'


def trim_personal_folder(folder_path):    # type: (str) -> str
    if folder_path.startswith(PERSONAL_FOLDER):
        folder_path = folder_path[len(PERSONAL_FOLDER):]
    return folder_path.lstrip('\\')


for f in handler.folders:
    f['path'] = trim_personal_folder(f['path'])

for s in handler.secrets:
    s['folder'] = trim_personal_folder(s['folder'])

idx = next((i for i, x in enumerate(handler.folders) if not x['path']), -1)
if idx >= 0:
    handler.folders.pop(idx)

root_folders = {}
for f in handler.folders:
    if f['name'] == f['path']:
        root_folders[f['path']] = f
    permissions = f.get('permissions')
    if isinstance(permissions, list):
        if len(permissions) == 1 and permissions[0].get('folder_role', '') != 'Owner' and \
                permissions[0].get('secret_role', '') != 'Owner':
            f['shared'] = True

for f in handler.folders:
    if f['shared'] is True and f['name'] != f['path']:
        root, sep, rest = f['path'].partition('\\')
        if sep:
            if root in root_folders:
                root_folders[root]['shared'] = True


def pop_field(items, item_name):     # type: (Dict[str, str], str) -> Optional[Dict[str, str]]
    return items.pop(item_name, None)


def pop_field_value(items, item_name):     # type: (Dict[str, str], str) -> str
    item = pop_field(items, item_name)
    if item:
        return item.get('value')


shared_folders = []    # type: List[SharedFolder]
records = []           # type: List[Record]

for f in root_folders.values():
    sf = SharedFolder()
    sf.path = f['path']
    shared_folders.append(sf)

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
    elif 'card-number' in items:
        record.type = 'bankCard'
    elif 'account-number' in items and 'routing-number' in items:
        record.type = 'bankAccount'
    elif 'ssn' in items:
        record.type = 'ssnCard'
    elif 'license-key' in items:
        record.type = 'softwareLicense'
    elif 'combination' in items:
        record.type = 'encryptedNotes'
    elif 'healthcare-provider-name' in items:
        record.type = 'healthInsurance'
    elif any(True for x in ('host', 'server', 'machine', 'ip-address---host-name') if x in items):
        if 'database' in items:
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
        if exp and len(exp) >= 4:
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
        if login_field in items:
            field = pop_field(items, login_field)
            username = field.get('value') if field else ''
            if field and username:
                if record.login:
                    field_label = field.get('field_name', '')
                    record.fields.append(RecordField(type='login', label=field_label, value=username))
                else:
                    record.login = username

    for password_field in ('password', 'client-secret'):
        if password_field in items:
            field = pop_field(items, password_field)
            password = field.get('value') if field else ''
            if field and password:
                if record.password:
                    field_label = field.get('field_name', '')
                    record.fields.append(RecordField(type='secret', label=field_label, value=password))
                else:
                    record.password = password

    if 'address-1' in items:
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

    if 'address1' in items:
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

    if 'last-name' in items:
        name = record_types.FieldTypes['name'].value.copy()
        name['last'] = pop_field_value(items, 'last-name')
        name['first'] = pop_field_value(items, 'first-name')
        if any(True for x in name.values() if x):
            record.fields.append(RecordField(type='name', label='', value=name))

    for full_name_field in ('name'):
        if full_name_field in items:
            full_name = pop_field_value(items, full_name_field)
            if full_name:
                name = vault.TypedField.import_name_field(full_name)
                if name:
                    record.fields.append(RecordField(type='name', label='', value=name))

    for ssn in ('social-security-number', 'ssn'):
        number = pop_field_value(items, ssn)
        if number:
            record.fields.append(RecordField(type='accountNumber', label='identityNumber', value=number))

    if 'combination' in items and record.type == 'encryptedNotes':
        combination = pop_field_value(items, 'combination')
        if combination:
            record.fields.append(RecordField(type='note', label='', value=combination))

    for phone_slug in ('contact-number', 'work-phone', 'home-phone', 'mobile-phone', 'fax'):
        field = pop_field(items, phone_slug)
        phone_number = field.get('value') if field else ''
        if field and phone_number:
            phone = vault.TypedField.import_phone_field(phone_number)
            if phone:
                field_label = field.get('field_name', '')
                if phone_slug.startswith('work'):
                    phone['type'] = 'Work'
                elif phone_slug.startswith('mobile'):
                    phone['type'] = 'Mobile'
                elif phone_slug.startswith('home'):
                    phone['type'] = 'Home'
                record.fields.append(RecordField(type='phone', label=field_label, value=phone))

    for url_slug in ('website', 'url'):
        field = pop_field(items, url_slug)
        url = field.get('value') if field else ''
        if field and url:
            if record.login_url:
                field_label = field.get('field_name', '')
                record.fields.append(RecordField(type='url', label=field_label, value=url))
            else:
                record.login_url = url
    host_no = 0
    for host_slug in ('server', 'host', 'machine', 'ip-address---host-name'):
        field = pop_field(items, host_slug)
        host_address = field.get('value') if field else ''
        port = pop_field_value(items, host_slug)
        if host_address:
            host = vault.TypedField.import_host_field(host_address)
            if port:
                host['port'] = port
            host_no += 1
            if host_no == 1:
                record.fields.append(RecordField(type='host', label='', value=host))
            else:
                field_label = field.get('field_name', '')
                record.fields.append(RecordField(type='host', label=field_label, value=host))

    for num_slug in ('policy-number', 'group-number'):
        if num_slug in items:
            field = pop_field(items, num_slug)
            number = field.get('value') if field else ''
            if number:
                field_label = field.get('field_name', '')
                record.fields.append(RecordField(type='accountNumber', label=field_label, value=number))

    for email_slug in ('email'):
        if email_slug in items:
            field = pop_field(items, email_slug)
            email = field.get('value') if field else ''
            if field and email:
                field_label = field.get('field_name', '')
                record.fields.append(RecordField(type='email', label=field_label, value=email))

    totp_code = secret.get('totp_code')
    if totp_code:
        field_value = f'otpauth://totp/?secret={totp_code}'
        record.fields.append(RecordField(type='oneTimeCode', label='', value=field_value))

    for slug in list(items.keys()):
        field = pop_field(items, slug)
        if not field:
            continue
        field_value = field.get('value') if field else ''
        if not field_value:
            continue

        field_label = field.get('field_name', '')
        slug_type = ''
        if template_name in handler.templates:
            template = handler.templates[template_name]
            st = template['fields'].get(slug) or ''
            if isinstance(st, dict):
                slug_type = st.get('slug_type', '')

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
data = []
data.extend(shared_folders)
data.extend(records)
exporter.execute('keeper-import.json', data)
logging.info('Exported %d records', len(records))
