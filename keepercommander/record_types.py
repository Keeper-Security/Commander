#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper SDK
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import collections
from typing import Dict

FieldType = collections.namedtuple('FieldType', ['name', 'value', 'description'])

FieldTypes = {x[0]: x for x in (
    FieldType('text', '', 'plain text'),
    FieldType('url', '', 'url string, can be clicked'),
    FieldType('multiline', '', 'multiline text'),
    FieldType('fileRef', '', 'reference to the file field on another record'),
    FieldType('email', '', 'valid email address plus tag'),
    FieldType('host', {'hostName': '', 'port': ''}, 'multiple fields to capture host information'),
    FieldType('phone', {'region': '', 'number': '', 'ext': '', 'type': ''}, 'numbers and symbols only plus tag'),
    FieldType('name', {'first': '', 'middle': '', 'last': ''}, 'multiple fields to capture name'),
    FieldType('address', {'street1': '', 'street2': '', 'city': '', 'state': '', 'zip': '', 'country': ''},
              'multiple fields to capture address'),
    FieldType('addressRef', '', 'reference to the address field on another record'),
    FieldType('cardRef', '', 'reference to the card record type'),
    FieldType('secret', '', 'the field value is masked'),
    FieldType('login', '', 'Login field, detected as the website login for browser extension or KFFA.'),
    FieldType('password', '', 'Field value is masked and allows for generation. Also complexity enforcements.'),
    FieldType('securityQuestion', {'question': '', 'answer': ''}, 'Security Question and Answer'),
    FieldType('otp', '', 'captures the seed, displays QR code'),
    FieldType('paymentCard', {'cardNumber': '', 'cardExpirationDate': '', 'cardSecurityCode': ''},
              'Field consisting of validated card number, expiration date and security code.'),
    FieldType('date', 0, 'calendar date with validation, stored as unix milliseconds'),
    FieldType('bankAccount', {'accountType': '', 'routingNumber': '', 'accountNumber': ''},
              'bank account information'),
    FieldType('privateKey', {'publicKey': '', 'privateKey': ''}, 'private and/or public keys in ASN.1 format')
)}   # type: Dict[str, FieldType]


class Multiple:
    Never = 0
    Optional = 1
    Always = 2


RecordField = collections.namedtuple('RecordField', ['name', 'type', 'multiple'])
RecordFields = {x[0]: x for x in (
    RecordField('login', 'login', Multiple.Never),
    RecordField('password', 'password', Multiple.Never),
    RecordField('company', 'text', Multiple.Never),
    RecordField('licenseNumber', 'multiline', Multiple.Never),
    RecordField('accountNumber', 'text', Multiple.Never),
    RecordField('bankAccount', 'bankAccount', Multiple.Never),
    RecordField('note', 'multiline', Multiple.Never),
    RecordField('oneTimeCode', 'otp', Multiple.Never),
    RecordField('keyPair', 'privateKey', Multiple.Never),
    RecordField('pinCode', 'secret', Multiple.Never),
    RecordField('expirationDate', 'date', Multiple.Never),
    RecordField('birthDate', 'date', Multiple.Never),
    RecordField('name', 'name', Multiple.Optional),
    RecordField('phone', 'phone', Multiple.Optional),
    RecordField('email', 'email', Multiple.Optional),
    RecordField('address', 'address', Multiple.Optional),
    RecordField('date', 'date', Multiple.Optional),
    RecordField('paymentCard', 'paymentCard', Multiple.Optional),
    RecordField('multiline', 'multiline', Multiple.Optional),
    RecordField('url', 'url', Multiple.Optional),
    RecordField('host', 'host', Multiple.Optional),
    RecordField('secret', 'secret', Multiple.Optional),
    RecordField('otp', 'otp', Multiple.Optional),
    RecordField('text', 'text', Multiple.Optional),
    RecordField('securityQuestion', 'securityQuestion', Multiple.Always),
    RecordField('addressRef', 'addressRef', Multiple.Optional),
    RecordField('cardRef', 'cardRef', Multiple.Optional),
    RecordField('fileRef', 'fileRef', Multiple.Always),
)}   # type: Dict[str, RecordField]
