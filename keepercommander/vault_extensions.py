#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Contact: ops@keepersecurity.com
#

import re
from typing import Optional, Union, List, Iterator

from . import utils, vault
from .params import KeeperParams


def find_records(params, search_str=None, record_type=None):
    # type: (KeeperParams, Optional[str], Optional[Union[str, List[str]]]) -> Iterator[vault.KeeperRecord]
    pattern = re.compile(search_str, re.IGNORECASE) if search_str else None

    type_filter = None
    if record_type:
        type_filter = set()
        if isinstance(record_type, list):
            type_filter.update(record_type)
        elif isinstance(record_type, str):
            type_filter.add(record_type)

    for record_uid in params.record_cache:
        record = vault.KeeperRecord.load(params, record_uid)
        if type_filter and record.record_type not in type_filter:
            continue
        if not pattern:
            yield record
        else:
            is_match = search_str == record.record_uid
            if not is_match and not type_filter:
                is_match = pattern.search(record.record_type)
            if not is_match:
                for _, value in record.enumerate_fields():
                    if is_match:
                        break
                    for token in vault.tokenize_typed_value(value):
                        if is_match:
                            break
                        is_match = pattern.search(token)
            if is_match:
                yield record


def get_record_description(record):   # type: (vault.KeeperRecord) -> Optional[str]
    if isinstance(record, vault.PasswordRecord):
        comps = [(record.login or '').strip(), (record.link or '').strip()]
        return ' @ '.join((x for x in comps if x))

    if isinstance(record, vault.TypedRecord):
        field = next((x for x in record.fields if x.type == 'login'), None)
        if field:
            comp = [(field.get_default_value() or '').strip()]
            field = next((x for x in record.fields if x.type == 'url'), None)
            address = ''
            if field:
                address = field.get_default_value()
            else:
                field = next((x for x in record.fields if x.type == 'host'), None)
                if field:
                    host = field.get_default_value()
                    if isinstance(host, dict):
                        address = host.get('hostName', '')
                        if address:
                            port = host.get('port')
                            if port:
                                address = f'{address}:{port}'
            comp.append((address or '').strip())
            return ' @ '.join((x for x in comp if x))

        field = next((x for x in record.fields if x.type == 'name'), None)
        if field:
            name = ''
            value = field.get_default_value()
            if isinstance(value, dict):
                comps = [value.get('first', ''), value.get('middle', ''), value.get('last', '')]
                name = ' '.join((x for x in comps if x))
            return name

        field = next((x for x in record.fields if x.type == 'address'), None)
        if field:
            address = ''
            value = field.get_default_value()
            if isinstance(value, dict):
                comp = [f'{value.get("street1", "")} {value.get("street2", "")}'.strip(),
                        value.get("city", ""),
                        f'{value.get("state", "")} {value.get("zip", "")}'.strip(),
                        value.get("country", "")]
                address = ', '.join((x for x in comp if x))
            return address

        field = next((x for x in record.fields if x.type == 'paymentCard'), None)
        if field:
            number = ''
            value = field.get_default_value()
            if isinstance(value, dict):
                number = value.get('cardNumber', '')
                if len(number) > 4:
                    number = 'x' + number[-4:]
            field = next((x for x in record.fields if x.type == 'text' and x.label == 'cardholderName'), None)
            if field:
                name = field.get_default_value()
                if name:
                    number = f'{number} / {name}'.strip()
            return number

        field = next((x for x in record.fields if x.type == 'keyPair'), None)
        if field:
            info = ''
            value = field.get_default_value()
            if isinstance(value, dict):
                info = '<Private Key>' if value.get('privateKey') else ''
                public = value.get('publicKey')
                if public:
                    info = info + ' / <Public Key>'
            return info

    if isinstance(record, vault.FileRecord):
        comp = [record.name, utils.size_to_str(record.size)]
        return ', '.join((x for x in comp if x))
