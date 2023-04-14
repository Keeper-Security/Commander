#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
from typing import Iterable, Dict, List

from . import importer
from .. import vault, record_types
from ..commands.record_edit import RecordEditMixin
from ..params import KeeperParams


def import_to_typed_records(params, records):   # type: (KeeperParams, Iterable[importer.Record]) -> Iterable[vault.TypedRecord]
    record_type_fields = {}    # type: Dict[str, List]
    if params.record_type_cache:
        for rts in params.record_type_cache.values():
            try:
                rto = json.loads(rts)
                if '$id' in rto and 'fields' in rto:
                    record_type_fields[rto['$id'].lower()] = rto['fields']
            except:
                pass

    for record in records:
        if not isinstance(record, importer.Record):
            continue
        record_type = record.type or 'login'
        record_type_lower = record_type.lower()
        if record_type_lower not in record_type_fields:
            record_type_lower = 'login'

        typed_record = vault.TypedRecord()
        typed_record.title = record.title
        typed_record.notes = record.notes
        typed_record.type_name = record_type
        RecordEditMixin.adjust_typed_record_fields(typed_record, record_type_fields[record_type_lower])
        if record.login:
            field = typed_record.get_typed_field('login')
            if not field:
                field = vault.TypedField.new_field('login', '')
                typed_record.custom.append(field)
            field.value = [record.login]
        if record.password:
            field = typed_record.get_typed_field('password')
            if not field:
                field = vault.TypedField.new_field('password', '')
                typed_record.custom.append(field)
            field.value = [record.password]
        if record.login_url:
            field = typed_record.get_typed_field('url')
            if not field:
                field = vault.TypedField.new_field('url', '')
                typed_record.custom.append(field)
            field.value = [record.login_url]

        for f in record.fields:
            if f.type not in record_types.RecordFields:
                f.type = 'text'

            field = typed_record.get_typed_field(f.type, f.label)
            if not field:
                field = vault.TypedField.new_field(f.type, [], f.label)
                typed_record.custom.append(field)
            if isinstance(f.value, list):
                field.value.extend(f.value)
            elif f.value:
                field.value.append(f.value)

        yield typed_record
