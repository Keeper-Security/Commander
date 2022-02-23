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
        if not record:
            continue
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
    comps = []

    if isinstance(record, vault.PasswordRecord):
        comps.extend((record.login or '', record.link or ''))
        return ' @ '.join((str(x) for x in comps if x))

    if isinstance(record, vault.TypedRecord):
        field = next((x for x in record.fields if x.type == 'login'), None)
        if field:
            comps.append(field.get_default_value() or '')
            field = next((x for x in record.fields if x.type == 'url'), None)
            if field:
                comps.append(field.get_default_value())
            else:
                field = next((x for x in record.fields if x.type == 'host'), None)
                if field:
                    host = field.get_default_value()
                    if isinstance(host, dict):
                        address = host.get('hostName')
                        if address:
                            port = host.get('port')
                            if port:
                                address = f'{address}:{port}'
                            comps.append(address)
            return ' @ '.join((str(x) for x in comps if x))

        field = next((x for x in record.fields if x.type == 'name'), None)
        if field:
            value = field.get_default_value()
            if isinstance(value, dict):
                comps.extend((value.get('first', ''), value.get('middle', ''), value.get('last', '')))
            return ' '.join((str(x) for x in comps if x))

        field = next((x for x in record.fields if x.type == 'address'), None)
        if field:
            value = field.get_default_value()
            if isinstance(value, dict):
                comps.extend((
                    f'{value.get("street1", "")} {value.get("street2", "")}'.strip(),
                    f'{value.get("city", "")}',
                    f'{value.get("state", "")} {value.get("zip", "")}'.strip(),
                    f'{value.get("country", "")}'))
            return ', '.join((str(x) for x in comps if x))

        field = next((x for x in record.fields if x.type == 'paymentCard'), None)
        if field:
            value = field.get_default_value()
            if isinstance(value, dict):
                number = value.get('cardNumber', '')
                if isinstance(number, str):
                    if len(number) > 4:
                        number = 'x' + number[-4:]
                        comps.append(number)

            field = next((x for x in record.fields if x.type == 'text' and x.label == 'cardholderName'), None)
            if field:
                name = field.get_default_value()
                if name and isinstance(name, str):
                    comps.append(name.upper())
            return ' / '.join((str(x) for x in comps if x))

        field = next((x for x in record.fields if x.type == 'keyPair'), None)
        if field:
            value = field.get_default_value()
            if isinstance(value, dict):
                if value.get('privateKey'):
                    comps.append('<Private Key>')
                if value.get('publicKey'):
                    comps.append('<Public Key>')
            return ' / '.join((str(x) for x in comps if x))

    if isinstance(record, vault.FileRecord):
        comps.extend((record.name, utils.size_to_str(record.size)))
        return ', '.join((str(x) for x in comps if x))
