#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Contact: ops@keepersecurity.com
#

import abc
import collections.abc
import datetime
import json
import logging
from typing import Optional, List, Tuple, Iterable, Type, Union, Dict, Any

import itertools

from .params import KeeperParams
from . import record_types, constants


def sanitize_str_field_value(value):    # type: (Any) -> str
    if not isinstance(value, str):
        value = str(value) if value else ''
    return value


def sanitize_int_field_value(value, *, default=0):    # type: (Any, *Any, Optional[Any]) -> int
    if not isinstance(value, int):
        try:
            value = int(value)
        except:
            if default is not None:
                if not isinstance(default, int):
                    default = 0
            value = default
    return value


def sanitize_bool_field_value(value):    # type: (Any) -> bool
    if not isinstance(value, bool):
        if isinstance(value, int):
            value = value != 0
        else:
            value = False
    return value


class KeeperRecord(abc.ABC):
    def __init__(self):
        self.record_uid = ''
        self.title = ''
        self.client_time_modified = 0
        self.record_key = b''
        self.revision = 0
        self.shared = False

    @abc.abstractmethod
    def get_version(self):  # type: () -> int
        pass

    @property
    def version(self):
        return self.get_version()

    @abc.abstractmethod
    def get_record_type(self):  # type: () -> str
        pass

    @property
    def record_type(self):
        return self.get_record_type()

    @abc.abstractmethod
    def load_record_data(self, data, extra=None):   # type: (dict, Optional[dict]) -> None
        pass

    @staticmethod
    def create(params, record_type):  # type: (KeeperParams, str) -> Optional['KeeperRecord']
        if not record_type:
            record_type = 'login'
        if record_type in {'legacy', 'general'}:
            record = PasswordRecord()
        elif record_type == 'file':
            record = FileRecord()
        else:
            record = TypedRecord()
            meta_data = None
            if params.record_type_cache:
                for rts in params.record_type_cache.values():
                    try:
                        rto = json.loads(rts)
                        if '$id' in rto and rto['$id'].lower() == record_type.lower():
                            meta_data = rto
                            break
                    except:
                        pass
            if meta_data and 'fields' in meta_data:
                for field in meta_data['fields']:
                    typed_field = TypedField()
                    typed_field.type = field.get('$ref', 'text')
                    typed_field.label = field.get('label', None)
                    record.fields.append(typed_field)
        return record

    @staticmethod
    def load(params, rec):
        # type: (KeeperParams, Union[str, Dict[str, Any]]) -> Optional['KeeperRecord']
        if isinstance(rec, str):
            if rec not in params.record_cache:
                return
            record = params.record_cache[rec]
        elif isinstance(rec, dict):
            record = rec
        else:
            return

        if 'data_unencrypted' not in record:
            return
        version = record.get('version', 0)

        if version == 2:
            keeper_record = PasswordRecord()
        elif version == 3:
            keeper_record = TypedRecord(version=3)
        elif version == 4:
            keeper_record = FileRecord()
            keeper_record.storage_size = record.get('file_size')
        elif version == 5:
            keeper_record = ApplicationRecord()
        elif version == 6:
            keeper_record = TypedRecord(version=6)
        else:
            return
        keeper_record.record_uid = record['record_uid']
        keeper_record.revision = record.get('revision', 0)
        keeper_record.record_key = record['record_key_unencrypted']
        keeper_record.client_time_modified = record.get('client_modified_time', 0)
        keeper_record.shared = record.get('shared', False)

        try:
            data = json.loads(record['data_unencrypted'])
        except:
            logging.warning('Record \"%s\": Corrupted record data', keeper_record.record_uid)
            return

        extra_str = record['extra_unencrypted'] if 'extra_unencrypted' in record else None
        extra = None     # type: Optional[Dict]
        if extra_str:
            try:
                extra = json.loads(extra_str)
            except:
                logging.debug('Record \"%s\": Corrupted record extra', keeper_record.record_uid)

        keeper_record.load_record_data(data, extra)

        return keeper_record

    def enumerate_fields(self):    # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        yield '(title)', self.title

    @staticmethod
    def size_to_str(size):    # type: (Union[int, float]) -> str
        if isinstance(size, (int, float)):
            scale = 'Bytes'
            if size > 0:
                if size > 1000:
                    size = size / 1024
                    scale = 'Kb'
                if size > 1000:
                    size = size / 1024
                    scale = 'Mb'
                if size > 1000:
                    size = size / 1024
                    scale = 'Gb'
            return f'{size:.2f}'.rstrip('0').rstrip('.') + f' {scale}'
        elif isinstance(size, str):
            return size
        elif size:
            return str(size)
        else:
            return ''


class CustomField(object):
    def __init__(self, custom_field=None):  # type: (Optional[dict]) -> None
        if custom_field is None:
            custom_field = {}

        self.name = sanitize_str_field_value(custom_field.get('name')).strip()
        self.type = sanitize_str_field_value(custom_field.get('type')).strip().lower()
        self.value = sanitize_str_field_value(custom_field.get('value')).strip()

    @classmethod
    def new_field(cls, name, value):
        cf = CustomField()
        cf.type = 'text'
        cf.name = sanitize_str_field_value(name)
        cf.value = sanitize_str_field_value(value)
        return cf


class AttachmentFileThumb:
    def __init__(self, thumb_field=None):      # type: (Optional[dict]) -> None
        thumb_field = thumb_field or {}
        self.id = sanitize_str_field_value(thumb_field.get('id'))
        self.type = sanitize_str_field_value(thumb_field.get('type'))
        self.size = sanitize_int_field_value(thumb_field.get('size'))


class AttachmentFile(object):
    def __init__(self, file_field=None):  # type: (Optional[dict]) -> None
        file_field = file_field or {}
        self.id = sanitize_str_field_value(file_field.get('id'))
        self.key = sanitize_str_field_value(file_field.get('key'))
        self.name = sanitize_str_field_value(file_field.get('name'))
        self.title = sanitize_str_field_value(file_field.get('title'))
        self.mime_type = sanitize_str_field_value(file_field.get('type'))
        self.size = sanitize_int_field_value(file_field.get('size'))
        self.last_modified = sanitize_int_field_value(file_field.get('lastModified'), default=None)
        self.thumbnails = []         # type: List[AttachmentFileThumb]
        if file_field and 'thumbnails' in file_field:
            thumbs = file_field.get('thumbnails')
            if isinstance(thumbs, list):
                for thumb in thumbs:
                    self.thumbnails.append(AttachmentFileThumb(thumb))


class ExtraField(object):
    def __init__(self, extra_field=None):  # type: (Optional[dict]) -> None
        if extra_field is None:
            extra_field = {}
        self.id = sanitize_str_field_value(extra_field.get('id'))
        self.field_type = sanitize_str_field_value(extra_field.get('field_type'))
        self.field_title = sanitize_str_field_value(extra_field.get('field_title'))
        self.data = sanitize_str_field_value(extra_field.get('data'))


class PasswordRecord(KeeperRecord):
    def __init__(self):
        super(PasswordRecord, self).__init__()
        self.login = ''
        self.password = ''
        self.link = ''
        self.notes = ''
        self.custom = []         # type: List[CustomField]
        self.attachments = None  # type: Optional[List[AttachmentFile]]
        self.totp = ''

    def get_version(self):  # type: () -> int
        return 2

    def get_record_type(self):
        return ''

    def load_record_data(self, data, extra=None):
        self.title = sanitize_str_field_value(data.get('title')).strip()
        self.login = sanitize_str_field_value(data.get('secret1')).strip()
        self.password = sanitize_str_field_value(data.get('secret2'))
        self.link = sanitize_str_field_value(data.get('link'))
        self.notes = sanitize_str_field_value(data.get('notes'))
        custom = data.get('custom')
        if isinstance(custom, list):
            self.custom.extend((CustomField(x) for x in custom if isinstance(x, dict) and 'name' in x))
        if isinstance(extra, dict):
            if 'files' in extra:
                self.attachments = [AttachmentFile(x) for x in extra['files']]

            if 'fields' in extra and isinstance(extra['fields'], list):
                self.totp = next((x.get('data', '') for x in extra['fields'] if x.get('field_type') == 'totp'), '')

    def enumerate_fields(self):
        # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        for pair in super(PasswordRecord, self).enumerate_fields():
            yield pair
        yield '(login)', self.login
        yield '(password)', self.password
        yield '(url)', self.link
        yield '(notes)', self.notes
        if self.totp:
            yield '(oneTimeCode)', self.totp
        for cf in self.custom:
            yield cf.name, cf.value
        if self.attachments:
            for atta in self.attachments:
                yield atta.title or atta.name, f'File ID: {atta.id}; Size: {KeeperRecord.size_to_str(atta.size)}'

    def get_custom_value(self, name):   # type: (str) -> Optional[str]
        field = next((x for x in self.custom if x.name == name), None)
        if field:
            return field.value

    def set_custom_value(self, name, value):   # type: (str, Optional[str]) -> None
        field = next((x for x in self.custom if x.name == name), None)
        value = sanitize_str_field_value(value)
        if value:
            if field:
                field.value = value
            else:
                self.custom.append(CustomField.new_field(name, value))
        else:
            if field:
                self.custom.remove(field)


class TypedField(object):
    def __init__(self, typed_field=None):
        if typed_field is None:
            typed_field = {}
        self.type = sanitize_str_field_value(typed_field.get('type')).strip()
        self.label = sanitize_str_field_value(typed_field.get('label')).strip()
        value = typed_field.get('value')
        if not isinstance(value, list):
            if isinstance(value, (str, int, bool)):
                value = [value]
            elif isinstance(value, collections.abc.Iterable):
                value = [x for x in value]
            else:
                value = []
        self.value = value
        self.required = sanitize_bool_field_value(typed_field.get('required'))

    @classmethod
    def new_field(cls, field_type, field_value, field_label=None):
        # type: (str, Any, Optional[str]) -> 'TypedField'
        f_type = sanitize_str_field_value(field_type) or 'text'
        # TODO check field value
        if not isinstance(field_value, list):
            if field_value:
                field_value = [field_value]
            else:
                field_value = []
        tf = TypedField()
        tf.type = f_type
        tf.value = field_value
        tf.label = sanitize_str_field_value(field_label)
        return tf

    def get_default_value(self, value_type=None):  # type: (Optional[Type]) -> any
        value = None
        if isinstance(self.value, list):
            if len(self.value) > 0:
                value = self.value[0]
        else:
            value = self.value
        if isinstance(value_type, type):
            if not isinstance(value, value_type):
                return
        return value

    def get_field_name(self):
        return f'({self.type}).{self.label}' if self.type and self.label else \
               f'({self.type})' if self.type else \
               f'{self.label}'

    @staticmethod
    def export_host_field(value):    # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            host = value.get('hostName') or ''
            port = value.get('port') or ''
            if host or port:
                if port:
                    host += ':' + port
            return host

    @staticmethod
    def export_phone_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            phone = value.get('type') or ''
            if phone:
                phone += ':'
            region = value.get('region') or ''
            if region:
                if len(region) == 2 and region.isalpha():
                    pass
                elif region.isnumeric():
                    region = '+' + region
                else:
                    region = ''
                if region:
                    phone += '  ' + region
            number = (value.get('number') or '').replace(' ', '-')
            if number:
                phone += ' ' + number
            ext = (value.get('ext') or '').replace(' ', '-')
            if ext:
                phone += ' ' + ext
            return phone

    @staticmethod
    def export_name_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            first_name = value.get('first') or ''
            middle_name = value.get('middle') or ''
            name = value.get('last') or ''
            if first_name or middle_name or name:
                name = f'{name}, {first_name}'
                if middle_name:
                    name += ' ' + middle_name
            return name

    @staticmethod
    def export_address_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            address = value.get('street1', '').replace(',', '.')
            street2 = value.get('street2', '').replace(',', '.')
            if street2:
                address += ' ' + street2
            city = value.get('city', '').replace(',', '.')
            if city:
                address += ', ' + city
                state = value.get('state', '').replace(',', '.')
                zip_code = value.get('zip', '').replace(',', '.')
                if state or zip_code:
                    address += ', ' + state + ' ' + zip_code
                    country = value.get('country', '').replace(',', '.')
                    if country:
                        address += ', ' + country
            return address

    @staticmethod
    def export_q_and_a_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            q = value.get('question', '').replace('?', '')
            a = value.get('answer', '')
            return f'{q}? {a}'.strip()

    @staticmethod
    def export_card_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            comps = []
            number = value.get('cardNumber')
            if number:
                comps.append(number)
            expiration = value.get('cardExpirationDate')
            if expiration:
                comps.append(expiration)
            cvv = value.get('cardSecurityCode')
            if cvv:
                comps.append(cvv)
            if comps:
                return ' '.join(comps)

    @staticmethod
    def export_account_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            account_type = value.get('accountType', '').replace(' ', '')
            routing = value.get('routingNumber', '').replace(' ', '')
            account_number = value.get('accountNumber', '').replace(' ', '')
            if routing or account_number:
                comps = []
                if account_type:
                    comps.append(account_type)
                if routing:
                    comps.append(routing)
                if account_number:
                    comps.append(account_number)
                if comps:
                    return ' '.join(comps)

    @staticmethod
    def export_ssh_key_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            return value.get('privateKey', '')

    @staticmethod
    def export_schedule_field(value):   # type: (dict) -> Optional[str]
        if isinstance(value, dict):
            schedule_type = value.get('type')
            if schedule_type == 'RUN_ONCE':
                return ''

            if schedule_type == 'CRON':
                cron = value.get('cron')
                if isinstance(cron, str):
                    comps = [x for x in cron.split(' ') if x]
                    if len(comps) >= 6:
                        comps = comps[1:6]
                        return ' '.join(comps)
                return ''

            hour = '0'
            minute = '0'
            day = '*'
            month = '*'
            week_day = '*'
            utc_time = value.get('time')
            if not utc_time:
                utc_time = value.get('utcTime')
            if utc_time:
                comps = utc_time.split(':')
                if len(comps) >= 2:
                    if comps[0].isnumeric():
                        h = int(comps[0])
                        if 0 <= h <= 23:
                            hour = str(h)
                    if comps[1].isnumeric():
                        m = int(comps[1])
                        if 0 <= m <= 59:
                            minute = str(m)

            if schedule_type == 'DAILY':
                interval = value.get('intervalCount') or 0
                if interval > 1:
                    if interval > 28:
                        interval = 28
                    day = f'*/{interval}'
            elif schedule_type == 'WEEKLY':
                week_day = constants.get_cron_week_day(value.get('weekday')) or 1
            elif schedule_type == 'MONTHLY_BY_DAY':
                day = constants.get_cron_month_day(value.get('monthDay')) or 1
            elif schedule_type == 'MONTHLY_BY_WEEKDAY':
                wd = constants.get_cron_week_day(value.get('weekday')) or 1
                occ = constants.get_cron_occurrence(value.get('occurrence'))
                if occ == 'FIRST':
                    occ = 1
                elif occ == 'SECOND':
                    occ = 2
                elif occ == 'THIRD':
                    occ = 3
                elif occ == 'FOURTH':
                    occ = 4
                else:
                    occ = 1
                week_day = f'{wd}#{occ}'
            elif schedule_type == 'YEARLY':
                month = constants.get_cron_month(value.get('month')) or 1
                day = constants.get_cron_month_day(value.get('monthDay')) or 1
            else:
                return ''

            return f'{minute} {hour} {day} {month} {week_day}'

    @staticmethod
    def import_host_field(value):    # type: (str) -> Optional[dict]
        if isinstance(value, str):
            host, _, port = value.partition(':')
            return {
                'hostName': host.strip(),
                'port': port.strip()
            }

    @staticmethod
    def import_phone_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            region = ''
            number = ''
            ext = ''
            phone_type, _, rest = value.partition(':')
            if not rest:
                rest = phone_type
                phone_type = ''
            comps = rest.strip().split(' ')
            for comp in comps:
                comp = comp.strip()
                if comp.isalpha():
                    if len(comp) == 2:
                        if not region:
                            region = comp
                    elif not phone_type:
                        phone_type = comp
                elif len(comp) >= 6:
                    if not number:
                        number = comp
                elif not ext:
                    ext = comp
            result = {
                'type': '',
                'region': '',
                'number': number.strip(),
                'ext': ext.strip()
            }
            phone_type = phone_type.strip()
            region = region.strip()
            if phone_type:
                result['type'] = phone_type
            if region:
                result['region'] = region
            return result

    @staticmethod
    def import_name_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            first = ''
            middle = ''
            last = ''
            comma_pos = value.find(',')
            if comma_pos >= 0:
                last = value[:comma_pos]
                rest = value[comma_pos+1:]
            else:
                space_pos = value.rfind(' ')
                if space_pos >= 0:
                    last = value[space_pos+1:]
                    rest = value[:space_pos]
                else:
                    last = value
                    rest = ''
            rest = rest.strip()
            if rest:
                space_pos = rest.rfind(' ')
                if space_pos >= 0:
                    middle = rest[space_pos+1:]
                    first = rest[:space_pos]
                else:
                    middle = ''
                    first = rest

            return {
                'first': first.strip(),
                'middle': middle.strip(),
                'last': last.strip(),
            }

    @staticmethod
    def import_address_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            comps = value.split(',')
            street1 = comps[0].strip() if len(comps) > 0 else ''
            city = comps[1].strip() if len(comps) > 1 else ''
            state, _, zip_code = comps[2].strip().partition(' ') if len(comps) > 2 else ('', '', '')
            if state and not zip_code:
                if state.isnumeric():
                    zip_code = state
                    state = ''
            country = comps[3].strip() if len(comps) > 3 else ''

            return {
                'street1': street1,
                'street2': '',
                'city': city,
                'state': state,
                'zip': zip_code,
                'country': country
            }

    @staticmethod
    def import_q_and_a_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            q, sign, a = value.partition('?')
            return {
                'question': q.strip() + '?',
                'answer': a.strip(),
            }

    @staticmethod
    def import_card_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            comps = value.split(' ')
            number = ''
            expiration = ''
            cvv = ''
            for comp in comps:
                comp = comp.strip()
                if comp:
                    if len(comp) > 10:
                        number = comp
                    elif comp.find('/') >= 0:
                        expiration = comp
                    elif len(comp) <= 6:
                        cvv = comp
            if number or expiration or cvv:
                return {
                    'cardNumber': number,
                    'cardExpirationDate': expiration,
                    'cardSecurityCode':  cvv,
                }

    @staticmethod
    def import_account_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            account_type = ''
            routing = ''
            account_number = ''
            comps = value.split()
            for comp in comps:
                comp = comp.strip()
                if comp.isnumeric():
                    if not routing:
                        routing = comp
                    elif not account_number:
                        account_number = comp
                else:
                    if not account_type:
                        account_type = comp
            if routing or account_number:
                return {
                    'accountType': account_type,
                    'routingNumber': routing,
                    'accountNumber': account_number
                }

    @staticmethod
    def import_ssh_key_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str):
            return {
                'privateKey': value.replace('\\n', '\n'),
                'publicKey': ''
            }

    @staticmethod
    def import_schedule_field(value):   # type: (str) -> Optional[dict]
        if isinstance(value, str) and len(value) > 0:
            comps = value.split(' ')
            if len(comps) >= 3:
                schedule = None
                if len(comps) < 4:
                    comps.insert(0, '0')
                if len(comps) < 5:
                    comps.insert(0, '0')
                minute = int(comps[0]) if comps[0].isnumeric() else 0
                if minute < 0 or minute > 59:
                    minute = 0
                hour = 0
                if comps[1].isnumeric():
                    hour = int(comps[1])
                else:
                    hrs = comps[1].replace('-', ',').split(',')
                    if len(hrs) > 0 and hrs[0].isnumeric():
                        hour = int(hrs[0])
                if hour < 0 or hour > 23:
                    hour = 0
                time = f'{hour:02}:{minute:02}:00'
                intervalCount = 1

                if comps[3] in ('*', '?') and comps[4] in ('*', '?'):  # daily
                    if comps[2].isnumeric():
                        schedule = {
                            'type': 'MONTHLY_BY_DAY',
                            'monthDay': int(comps[2])
                        }
                    elif comps[2].startswith('*'):
                        schedule = {
                            'type': 'DAILY',
                        }
                        if comps[2].startswith('*/'):
                            intr = comps[2][2:]
                            if intr.isnumeric():
                                schedule['occurrences'] = int(intr)
                elif comps[4] not in ('*', '?'):  # day of week
                    if comps[4].isnumeric():
                        wd = int(comps[4])
                        if wd < 0 or wd > len(constants.week_days):
                            wd = 1
                        schedule = {
                            'type': 'WEEKLY',
                            'weekday': constants.week_days[wd]
                        }
                    elif comps[4].startswith('*/'):
                        schedule = {
                            'type': 'DAILY',
                        }
                        intr = comps[4][2:]
                        if intr.isnumeric():
                            schedule['occurrences'] = int(intr)
                    else:
                        wd_comps = comps[4].replace('%', '#').split('#')
                        if len(wd_comps) == 2 and wd_comps[0].isnumeric() and wd_comps[1].isnumeric():
                            wd = int(wd_comps[0])
                            if wd < 0 or wd > len(constants.week_days):
                                wd = 1
                            occ = int(wd_comps[1]) - 1
                            if occ < 0 or occ >= len(constants.occurrences):
                                occ = 0
                            occurrence = constants.occurrences[occ]
                            schedule = {
                                'type': 'MONTHLY_BY_WEEKDAY',
                                'weekday': constants.week_days[wd],
                                'occurrence': occurrence,
                            }
                elif comps[3].isnumeric():  # day of month
                    mm = int(comps[3])
                    if mm > 0:
                        mm -= 1
                        if mm >= len(constants.months):
                            mm = len(constants.months) - 1
                    else:
                        mm = 0

                    dd = 1
                    if comps[2].isnumeric():
                        dd = int(comps[2])

                    schedule = {
                        'type': 'YEARLY',
                        'month': constants.months[mm],
                        'monthDay': dd,
                    }
                else:
                    schedule = {
                        'type': 'RUN_ONCE',
                    }
                    time = '2000-01-01T00:00:00'

                schedule['tz'] = 'Etc/UTC'
                schedule['time'] = time
                schedule['intervalCount'] = intervalCount
                return schedule

    @staticmethod
    def get_exported_value(field_type, field_value):
        # type: (str, Any) -> Iterable[str]
        if not field_value:
            return

        if isinstance(field_value, str):
            yield field_value
            return

        rf = record_types.RecordFields.get(field_type)
        ft = record_types.FieldTypes.get(rf.type) if rf else None
        if isinstance(field_value, int):
            if ft and ft.name == 'date':
                if field_value != 0:
                    dt = datetime.datetime.fromtimestamp(int(field_value // 1000)).date()
                    yield str(dt)
            else:
                yield str(field_value)
        elif isinstance(field_value, list):
            for elem in field_value:
                for ev in TypedField.get_exported_value(field_type, elem):
                    yield ev
        elif isinstance(field_value, dict):
            if ft:
                if ft.name == 'host':
                    yield TypedField.export_host_field(field_value)
                elif ft.name == 'phone':
                    yield TypedField.export_phone_field(field_value)
                elif ft.name == 'name':
                    yield TypedField.export_name_field(field_value)
                elif ft.name == 'address':
                    yield TypedField.export_address_field(field_value)
                elif ft.name == 'securityQuestion':
                    yield TypedField.export_q_and_a_field(field_value)
                elif ft.name == 'paymentCard':
                    yield TypedField.export_card_field(field_value)
                elif ft.name == 'bankAccount':
                    yield TypedField.export_account_field(field_value)
                elif ft.name == 'privateKey':
                    yield TypedField.export_ssh_key_field(field_value)
                elif ft.name == 'schedule':
                    yield TypedField.export_schedule_field(field_value)

    def get_external_value(self):   # type: () -> Iterable[str]
        for value in self.get_exported_value(self.type, self.value):
            if value:
                yield value


class TypedRecord(KeeperRecord):
    def __init__(self, version=3):
        super(TypedRecord, self).__init__()
        self._version = version
        self.type_name = ''
        self.notes = ''
        self.fields = []         # type: List[TypedField]
        self.custom = []         # type: List[TypedField]
        self.linked_keys = None  # type: Optional[Dict[str, bytes]]

    def get_version(self):  # type: () -> int
        return self._version

    def get_record_type(self):
        return self.type_name

    def get_typed_field(self, field_type, label=None):    # type: (str, Optional[str]) -> Optional[TypedField]
        return next((x for x in itertools.chain(self.fields, self.custom)
                     if field_type == x.type and (not label or (x.label and label.casefold() == x.label.casefold()))),
                    None)

    def load_record_data(self, data, extra=None):
        self.type_name = sanitize_str_field_value(data.get('type')).strip()
        self.title = sanitize_str_field_value(data.get('title')).strip()
        self.notes = sanitize_str_field_value(data.get('notes'))
        self.fields.extend((TypedField(x) for x in data.get('fields', [])))
        self.custom.extend((TypedField(x) for x in data.get('custom', [])))

    def enumerate_fields(self):
        # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        for pair in super(TypedRecord, self).enumerate_fields():
            yield pair
        yield '(type)', self.record_type
        yield '(notes)', self.notes
        for field in itertools.chain(self.fields, self.custom):
            values = list(field.get_external_value())
            yield field.get_field_name(), '' if len(values) == 0 else values[0] if len(values) == 1 else values


class FileRecord(KeeperRecord):
    def __init__(self):
        super(FileRecord, self).__init__()
        self.name = ''
        self.size = None   # type: Optional[int]
        self.mime_type = ''
        self.last_modified = None   # type: Optional[int]
        self.storage_size = None   # type: Optional[int]

    def get_version(self):  # type: () -> int
        return 4

    def get_record_type(self):
        return 'file'

    def load_record_data(self, data, extra=None):
        self.title = sanitize_str_field_value(data.get('title')).strip()
        self.name = sanitize_str_field_value(data.get('name')).strip()
        self.size = sanitize_int_field_value(data.get('size'))
        self.mime_type = sanitize_str_field_value(data.get('type'))
        self.last_modified = sanitize_int_field_value(data.get('lastModified'), default=None)

    def enumerate_fields(self):  # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        for pair in super(FileRecord, self).enumerate_fields():
            yield pair
        yield '(type)', self.get_record_type()
        yield '(name)', self.name
        if self.mime_type:
            yield '(mime-type)', self.mime_type
        yield '(size)', KeeperRecord.size_to_str(self.size)


class ApplicationRecord(KeeperRecord):
    def __init__(self):
        super(ApplicationRecord, self).__init__()

    def get_version(self):
        return 5

    def get_record_type(self):
        return 'app'

    def load_record_data(self, data, extra=None):
        self.title = sanitize_str_field_value(data.get('title')).strip()

    def enumerate_fields(self):  # type: () -> Iterable[Tuple[str, Union[None, str, List[str]]]]
        for pair in super(ApplicationRecord, self).enumerate_fields():
            yield pair
        yield '(type)', self.get_record_type()
