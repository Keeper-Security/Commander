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

import copy
import datetime
import json
import logging
import re
from collections import Counter

from .display import bcolors
from .params import KeeperParams
from .record import get_totp_code
from .subfolder import get_folder_path, find_folders, BaseFolderNode


class RecordV3:
    """Defines a user-friendly Keeper Record v3 for display purposes"""

    def __init__(self, record_uid='', folder='', title='', type='', fields=None, custom_fields=None, notes='',
                 revision='', data=''):
        self.record_uid = record_uid
        self.folder = folder
        self.title = title
        self.type = type
        self.fields = custom_fields or []
        self.custom_fields = custom_fields or []
        self.notes = notes
        self.revision = revision
        self.data = data

    @staticmethod
    def is_valid_record_type(record_type_json: str, rt_definition_json: str) -> dict:
        # validate record type (a.k.a. record v3) data
        # https://github.com/Keeper-Security/record-templates/tree/master/standard_templates
        rt = {}
        try:
            rt = json.loads(record_type_json)
        except ValueError:
            return {'is_valid': False, 'error': 'Invalid record type JSON'}
        except Exception:
            return {'is_valid': False, 'error': 'Invalid record type'}

        res = RecordV3.is_valid_record_type_definition(rt_definition_json)
        if not res.get('is_valid'):
            return res
        rtd = json.loads(rt_definition_json)

        # Implicit fields - always present on any record, no need to be specified in the template: title, custom, notes
        rtd_type = rtd.get('$id') or ''
        rt_type = rt.get('type') or ''
        rt_title = rt.get('title') or ''
        rt_notes = rt.get('notes') or ''
        rt_fields = rt.get('fields') or []
        rt_custom = rt.get('custom') or []

        if not isinstance(rt_type, str):
            return {'is_valid': False, 'error': 'Record type "type" should be string: ' + str(rt_type)}
        if not isinstance(rt_title, str):
            return {'is_valid': False, 'error': 'Record type "title" should be string: ' + str(rt_title)}
        if not isinstance(rt_notes, str):
            return {'is_valid': False, 'error': 'Record type "notes" should be string: ' + str(rt_notes)}
        if not isinstance(rt_fields, list):
            return {'is_valid': False, 'error': 'Record type "fields" should be array: ' + str(rt_fields)}
        if not isinstance(rt_custom, list):
            return {'is_valid': False, 'error': 'Record type "custom" should be array: ' + str(rt_custom)}

        if not rt_type or not rt_type.strip():
            return {'is_valid': False, 'error': 'Missing record type type'}
        if rt_type.strip() != rtd_type.strip():
            return {'is_valid': False,
                    'error': 'Type mistmatch - RT "type" should match "$id" in RT definition: ' + rt_type + " != " + rtd_type}

        if not rt_title or not rt_title.strip():
            return {'is_valid': False, 'error': 'Missing record type title'}

        # Top level RT attributes - unknown attribute(s) generate error
        # All known attribute(s) from RT definition that don't belong to RT data also generate error
        tlod = [x for x in rtd]
        tlor = [x for x in rt]
        rtdef_only = ('$id', 'categories', 'description', 'label')  # these are in RT definitions only
        ilist = [x for x in tlor if x in rtdef_only]
        if ilist:
            return {'is_valid': False,
                    'error': 'Record has atributes that should be present in record type definitions only: ' + str(
                        ilist)}

        # ulist = [x for x in tlor if x not in ('type', 'title', 'notes', 'fields', 'custom')]
        ulist = [x for x in tlor if x not in tlod + [*RecordV3.record_fields.keys()]]
        if ulist:
            return {'is_valid': False, 'error': 'Unknown record type attribute(s): ' + str(ulist)}

        # Allow only valid/known field types - field types are case sensitive?
        badf = [x for x in rt_fields if not RecordV3.field_types.__contains__(x.get('type'))]
        if badf:
            return {'is_valid': False, 'error': 'Unknown field types in "fields": ' + str(badf)}
        badf = [x for x in rt_custom if not RecordV3.field_types.__contains__(x.get('type'))]
        if badf:
            return {'is_valid': False, 'error': 'Unknown field types in "custom": ' + str(badf)}

        # only one FT of type password allowed in record v3
        pwdf = [x for x in rt_fields if x.get('type') == 'password']
        pwdc = [x for x in rt_custom if x.get('type') == 'password']
        pwds = pwdf + pwdc
        if len(pwds) > 1:
            return {'is_valid': False, 'error': 'Error: Only one password allowed per record! ' + str(pwds)}
        elif len(pwds) == 1:
            rtdp = next((True for x in (rtd.get('fields') or []) if '$ref' in x and x.get('$ref') == 'password'), False)
            if rtdp:
                if pwdc: return {'is_valid': False,
                                 'error': 'Password must be in fields[] section as defined by record type! ' + str(
                                     pwds)}
            else:
                if pwdf: return {'is_valid': False,
                                 'error': 'Password must be in custom[] section - this record type does not allow password in fields[]! ' + str(
                                     pwds)}

        # All fields in fields[] must be in record type definition
        rtdf = [x.get('$ref') for x in (rtd.get('fields') or []) if '$ref' in x]
        badf = [x for x in rt_fields if x.get('type') not in rtdf]
        if badf:
            return {'is_valid': False,
                    'error': 'This record type doesn\'t allow these in fields[] (move to custom): ' + str(badf)}

        # fileRef use upload-attachment/delete-attachment commands
    # remove from validation to allow for cross referencing same fileRef from multiple records v3
        # refs = [x for x in rt_fields + rt_custom if x.get('type') == 'fileRef' and x.get('value')]
        # if refs:
        #   return { 'is_valid': False, 'error': 'File reference manipulations are disabled here. Use upload-attachment/delete-attachment commands instead. ' + str(refs) }

        # fields[] must contain all 'required' fields (and required value parts) - custom[] is not in RT definition
        reqd = [x.get('$ref') for x in (rtd.get('fields') or []) if '$ref' in x and 'required' in x]
        reqf = [x for x in rt_fields if x.get('type') in reqd]
        regf = [x for x in rt_fields if x.get('type') not in reqd] + rt_custom

        # all fields required by RT definition must be present
        miss = set(reqd) - set([x.get('type') for x in reqf])
        if miss:
            return {'is_valid': False, 'error': 'Missing required fields: ' + str(miss)}

        # validate field values
        fver = []
        for fld in reqf:
            err = RecordV3.is_valid_field_data(fld, True)
            fver.extend(err)
        if fver:
            return {'is_valid': False, 'error': 'Error(s) validating required fields: ' + str(fver)}

        for fld in regf:
            err = RecordV3.is_valid_field_data(fld, False)
            fver.extend(err)
        if fver:
            return {'is_valid': False, 'error': 'Error(s) validating fields: ' + str(fver)}

        return {'is_valid': True, 'error': ''}

    @staticmethod
    def is_valid_record_type_definition(record_type_definition_json: str) -> dict:
        # validate record type (a.k.a. record v3) definition
        # https://github.com/Keeper-Security/record-templates/tree/master/standard_templates

        rt = {}
        try:
            rt = json.loads(record_type_definition_json)
        except ValueError:
            return {'is_valid': False, 'error': 'Invalid record type JSON'}
        except Exception:
            return {'is_valid': False, 'error': 'Invalid record type definition'}

        rtid = rt.get('$id') or ''
        if not rtid or not rtid.strip():
            return {'is_valid': False, 'error': 'Missing record type name'}

        # Min RT definition: {"$id": "Name"} - allows only implicit (custom) fields
        # Max RT definition: {"$id": "Name", "categories": ["note"], "description": "Description", "fields":[]}
        # Implicit fields - always present on any record, no need to be specified in the template: title, custom, notes
        implicit_field_names = [x for x in RecordV3.record_implicit_fields]
        implicit_fields = [r for r in rt if r in implicit_field_names]
        if implicit_fields:
            return {'is_valid': False,
                    'error': 'Implicit fields not allowed in record type definition: ' + str(implicit_fields)}

        rt_attributes = ('$id', 'categories', 'description', 'fields')
        bada = [r for r in rt if r not in rt_attributes and r not in implicit_field_names]
        if bada:
            logging.debug(f'Unknown attributes in record type definition: {bada}')

        # Allow only valid/known field types - field types are case sensitive?
        flds = rt.get('fields') or []
        # Record type definitions without fields are OK? They still have title and custom[]
        # if not flds:
        #   return { 'is_valid': False, 'error': 'Missing fields list' }

        badf = [x for x in flds if not x.get('$ref')]
        if badf:
            return {'is_valid': False, 'error': 'Missing field type reference (ex. {"$ref": "login"}): ' + str(badf)}

        badf = [x for x in flds if not RecordV3.field_types.__contains__(x.get('$ref'))]
        if badf:
            return {'is_valid': False, 'error': 'Unknown field types: ' + str(badf)}

        known_ft_atributes = {'$ref', 'label', 'required', 'privacyScreen', 'enforceGeneration', 'complexity'}
        unknown_ft_atributes = [x for x in flds if not set(x.keys()).issubset(known_ft_atributes)]
        if unknown_ft_atributes:
            return {'is_valid': False, 'error': 'Unknown field atributes: ' + str(unknown_ft_atributes)}

        badf = [x for x in flds if not RecordV3.is_valid_field_type_ref(json.dumps(x))]
        if badf:
            return {'is_valid': False, 'error': 'Invalid field types: ' + str(badf)}

        return {'is_valid': True, 'error': ''}

    # Implicit fields - The following fields are always present on any record and do not need to be specified in the template:
    record_implicit_fields = {
        'title': '',  # string
        'custom': [],  # Array of Field Data objects
        'notes': ''  # string
    }

    record_fields = {
        'title': '',  # string - Record Title
        'type': '',  # string - Record Type (either one of the standard types or a custom type)
        'fields': [],  # Array of Field Data objects
        'custom': [],  # Array of Field Data objects
        'notes': ''  # string
    }

    # Fields are client-side defined. Fields are defined with a Field Type. All Field Types are fixed.
    # Meaning, although we may implement new field types, the client cannot arbitrarily add field types,
    # nor display/edit field types that are not pre programmed into the client.
    # Once the client is updated to understand the new field type, the data may then be displayed and edited.

    # TODO: translatable labels
    # NB! Allow only one login/password field per v3 record. Allow in custom[] only if RT definition doesn't have them
    # Standard RT definitions: always required - type, title
    record_types = {
        'login': {'label': 'Login'},
        # def.  {"$id":"login","categories":["login"],"description":"Login template","fields":[{"$ref":"login"},{"$ref":"password"},{"$ref":"url"},{"$ref":"securityQuestion"},{"$ref":"fileRef"},{"$ref":"oneTimeCode"}]}
        # ex.   {"title":"Title","type":"login","fields":[{"type":"login","value":[]},{"type":"password","value":[]},{"type":"url","value":[]},{"type":"securityQuestion","value":[]},{"type":"fileRef","value":[]},{"type":"oneTimeCode","value":[]}],"custom":[]}

        'bankAccount': {'label': 'Bank Account'},  # { "$ref": "bankAccount", "required": true }
        # def.  {"$id":"bankAccount","description":"Bank account template","fields":[{"$ref":"bankAccount","required":true},{"$ref":"name"},{"$ref":"login"},{"$ref":"password"},{"$ref":"url"},{"$ref":"cardRef"},{"$ref":"fileRef"},{"$ref":"oneTimeCode"}]}
        # ex.   {"title":"Title","type":"bankAccount","fields":[{"type":"bankAccount","value":[{"accountType":"","routingNumber":"","accountNumber":"1234","otherType":""}],"required":true},{"type":"name","value":[{"first":"John","last":"Doe"}]},{"type":"login","value":[]},{"type":"password","value":[]},{"type":"url","value":[]},{"type":"cardRef","value":[]},{"type":"fileRef","value":[]},{"type":"oneTimeCode","value":[]}],"custom":[]}

        'address': {'label': 'Address'},
        # def.  {"$id":"address","categories":["address"],"description":"Address template","fields":[{"$ref":"address"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"address","fields":[{"type":"address","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

        'bankCard': {'label': 'Payment Card'},
        # def.  {"$id":"bankCard","categories":["payment"],"description":"Bank card template","fields":[{"$ref":"paymentCard"},{"$ref":"text","label":"cardholderName"},{"$ref":"pinCode"},{"$ref":"addressRef"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"bankCard","fields":[{"type":"paymentCard","value":[]},{"type":"text","label":"Cardholder Name","value":[]},{"type":"pinCode","value":[]},{"type":"addressRef","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

        'birthCertificate': {'label': 'Birth Certificate'},
        # def.  {"$id":"birthCertificate","categories":["ids"],"description":"Birth certificate template","fields":[{"$ref":"name"},{"$ref":"birthDate"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"birthCertificate","fields":[{"type":"name","value":[]},{"type":"birthDate","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

        'contact': {'label': 'Contact'},  # { "$ref": "name", "required": true }
        # def.  {"$id":"contact","categories":["address"],"description":"Contact template","fields":[{"$ref":"name","required":true},{"$ref":"text","label":"company"},{"$ref":"email"},{"$ref":"phone"},{"$ref":"addressRef"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"contact","fields":[{"type":"name","value":[{"first":"John","last":"Doe"}],"required":true},{"type":"text","label":"Company","value":[]},{"type":"email","value":[]},{"type":"phone","value":[]},{"type":"addressRef","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

        'driverLicense': {'label': 'Driver\'s License'},
        # def.  {"$id":"driverLicense","categories":["ids"],"description":"Driver license template","fields":[{"$ref":"accountNumber","label":"dlNumber"},{"$ref":"name"},{"$ref":"birthDate"},{"$ref":"addressRef"},{"$ref":"expirationDate"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"driverLicense","fields":[{"type":"accountNumber","label":"Driver's License Number","value":[]},{"type":"name","value":[]},{"type":"birthDate","value":[]},{"type":"addressRef","value":[]},{"type":"expirationDate","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

        'encryptedNotes': {'label': 'Secure Note'},
        # def.  {"$id":"encryptedNotes","categories":["note"],"description":"Encrypted note template","fields":[{"$ref":"note"},{"$ref":"date"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"encryptedNotes","fields":[{"type":"note","value":[]},{"type":"date","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

        'file': {'label': 'File Attachment'},
        # def.  {"$id":"file","categories":["file"],"description":"File template","fields":[{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"file","fields":[{"type":"fileRef","value":[]}],"custom":[]}

        'healthInsurance': {'label': 'Health Insurance'},
        # def.  {"$id":"healthInsurance","categories":["ids"],"description":"Health insurance template","fields":[{"$ref":"accountNumber"},{"$ref":"name","label":"insuredsName"},{"$ref":"login"},{"$ref":"password"},{"$ref":"url"},{"$ref":"fileRef"},{"$ref":"securityQuestion"}]}
        # ex.   {"title":"Title","type":"healthInsurance","fields":[{"type":"accountNumber","value":[]},{"type":"name","label":"Insured's Name","value":[]},{"type":"login","value":[]},{"type":"password","value":[]},{"type":"url","value":[]},{"type":"fileRef","value":[]},{"type":"securityQuestion","value":[]}],"custom":[]}

        'membership': {'label': 'Membership'},
        # def.  {"$id":"membership","categories":["ids"],"description":"Membership template","fields":[{"$ref":"accountNumber"},{"$ref":"name"},{"$ref":"password"},{"$ref":"fileRef"},{"$ref":"securityQuestion"}]}
        # ex.   {"title":"Title","type":"membership","fields":[{"type":"accountNumber","value":[]},{"type":"name","value":[]},{"type":"password","value":[]},{"type":"fileRef","value":[]},{"type":"securityQuestion","value":[]}],"custom":[]}

        'passport': {'label': 'Passport'},
        # def.  {"$id":"passport","categories":["ids"],"description":"Passport template","fields":[{"$ref":"accountNumber","label":"passportNumber"},{"$ref":"name"},{"$ref":"birthDate"},{"$ref":"addressRef"},{"$ref":"expirationDate"},{"$ref":"date","label":"dateIssued"},{"$ref":"password"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"passport","fields":[{"type":"accountNumber","label":"Passport Number","value":[]},{"type":"name","value":[]},{"type":"birthDate","value":[]},{"type":"addressRef","value":[]},{"type":"expirationDate","value":[]},{"type":"date","label":"Date Issued","value":[]},{"type":"password","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

        'photo': {'label': 'Photo'},
        # def.  {"$id":"photo","categories":["file"],"description":"Photo template","fields":[{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"photo","fields":[{"type":"fileRef","value":[]}],"custom":[]}

        'serverCredentials': {'label': 'Server'},
        # def.  {"$id":"serverCredentials","categories":["login"],"description":"Server credentials template","fields":[{"$ref":"host"},{"$ref":"login"},{"$ref":"password"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"serverCredentials","fields":[{"type":"host","value":[]},{"type":"login","value":[]},{"type":"password","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

        'softwareLicense': {'label': 'Software License'},
        # def.  {"$id":"softwareLicense","categories":["note"],"description":"Software license template","fields":[{"$ref":"licenseNumber"},{"$ref":"expirationDate"},{"$ref":"date","label":"dateActive"},{"$ref":"fileRef"},{"$ref":"securityQuestion"}]}
        # ex.   {"title":"Title","type":"softwareLicense","fields":[{"type":"licenseNumber","value":[]},{"type":"expirationDate","value":[]},{"type":"date","label":"Date Active","value":[]},{"type":"fileRef","value":[]},{"type":"securityQuestion","value":[]}],"custom":[]}

        'ssnCard': {'label': 'Identity Card'},
        # def.  {"$id":"ssnCard","categories":["ids"],"description":"Identity card template","fields":[{"$ref":"accountNumber","label":"identityNumber"},{"$ref":"name"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"ssnCard","fields":[{"type":"accountNumber","label":"Identity Number","value":[]},{"type":"name","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

        'general': {'label': 'Legacy Record'},
        # def.  {"$id":"general","categories":["login"],"description":"Legacy template","fields":[{"$ref":"login"},{"$ref":"password"},{"$ref":"url"},{"$ref":"oneTimeCode"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"general","fields":[{"type":"login","value":[]},{"type":"password","value":[]},{"type":"url","value":[]},{"type":"oneTimeCode","value":[]},{"type":"fileRef","value":[]}],"custom":[],"notes":""}

        'sshKeys': {'label': 'SSH Key'},
        # def.  {"$id":"sshKeys","categories":["login"],"description":"SSH key template","fields":[{"$ref":"login"},{"$ref":"keyPair"},{"$ref":"text","label":"passphrase"},{"$ref":"host"},{"$ref":"fileRef"},{"$ref":"securityQuestion"}]}
        # ex.   {"title":"Title","type":"sshKeys","fields":[{"type":"login","value":[]},{"type":"keyPair","value":[]},{"type":"text","label":"Passphrase","value":[]},{"type":"host","value":[]},{"type":"fileRef","value":[]},{"type":"securityQuestion","value":[]}],"custom":[]}

        'databaseCredentials': {'label': 'Database'}
        # def.  {"$id":"databaseCredentials","categories":["login"],"description":"Database credentials template","fields":[{"$ref":"text","label":"type"},{"$ref":"host"},{"$ref":"login"},{"$ref":"password"},{"$ref":"fileRef"}]}
        # ex.   {"title":"Title","type":"databaseCredentials","fields":[{"type":"text","label":"Type","value":[]},{"type":"host","value":[]},{"type":"login","value":[]},{"type":"password","value":[]},{"type":"fileRef","value":[]}],"custom":[]}
    }

    # A field definition consists from:
    #   $id - ex. 'title', used to reference the field definitions and to translate the field labels
    #   type|$type - used to tell the UI how to render and edit the field
    #   lookup - optional flag: lookup values are shared based on the field reference.
    #     ex. all 'login' fields will share the same set of lookup values but will not see the lookup values from 'company' field
    #   multiple - optional flag: If specified, the UI should allow populating multiple instances of the field on the record
    #   label - optional modifier: If specified, the UI display the label instead of the translated value
    #   default - optional modifier: Defines the default value for the field
    #   readonly -  flag: restrict editable field to be readonly or relax readonly field to be editable
    #   required - optional flag: Can be used to make the field required
    #   hidden - optional flag. Can be used to hide a field from the base template

    # https://github.com/Keeper-Security/record-templates/blob/master/fields.json
    # NB! All field_types must have corresponding field_values
    field_types = {
        # 2021-05-06 FT 'text' added for compatibility with web vault
        'text': {
            '$id': 'text',
            'type': 'text'
        },
        # 2021-06-24 One RT added new FT 'secret' - type is yet unknown
        'secret': {
            '$id': 'secret',
            'type': 'text'
        },
        'title': {
            '$id': 'title',
            'type': 'text'
        },
        'login': {
            '$id': 'login',
            'type': 'login',
            'lookup': 'login'
        },
        'password': {
            '$id': 'password',
            'type': 'password'
        },
        'name': {
            '$id': 'name',
            'type': 'name',
            'lookup': 'name'
        },
        'company': {
            '$id': 'company',
            'type': 'text',
            'lookup': 'company'
        },
        'phone': {
            '$id': 'phone',
            'type': 'phone',
            'multiple': 'optional',
            'lookup': 'phone'
        },
        'email': {
            '$id': 'email',
            'type': 'email',
            'multiple': 'optional',
            'lookup': 'email'
        },
        'address': {
            '$id': 'address',
            'type': 'address',
            'label': 'Street Address'
        },
        'addressRef': {
            '$id': 'addressRef',
            'type': 'addressRef',
            'lookup': 'addressRef'
        },
        # 'cardNumber': {
        #   '$id': 'cardNumber',
        #   'type': 'cardNumber'  # undefined - probably replaced by paymentCard
        # },
        'date': {
            '$id': 'date',
            'type': 'date'
        },
        # 2021-06-18 One RT added new FT expirationDate probably just a date value
        'expirationDate': {
            '$id': 'expirationDate',
            'type': 'date'
        },
        'birthDate': {
            '$id': 'birthDate',
            'type': 'date'
        },
        'paymentCard': {
            '$id': 'paymentCard',
            'type': 'paymentCard'
        },
        'accountNumber': {
            '$id': 'accountNumber',
            'type': 'text',
            'lookup': 'accountNumber',
            'label': 'Account Number'
        },
        'groupNumber': {
            '$id': 'groupNumber',
            'type': 'text'
        },
        'bankAccount': {
            '$id': 'bankAccount',
            'type': 'bankAccount',
            'lookup': 'accountNumber'
        },
        'cardRef': {
            '$id': 'cardRef',
            'type': 'cardRef',
            'lookup': 'bankCard',
            'multiple': 'default'
        },
        'note': {
            '$id': 'note',
            'type': 'multiline'
        },
        'url': {
            '$id': 'url',
            'type': 'url',
            'multiple': 'optional'
        },
        # 2021-05-06 Unused photo, file - removed for compatibility with web vault
        # 'photo': {
        #   '$id': 'photo',
        #   'type': 'file'
        # },
        # 'file': {
        #   '$id': 'file',
        #   'type': 'file'
        # },
        'fileRef': {
            '$id': 'fileRef',
            'type': 'fileRef',
            'multiple': 'default'
        },
        'host': {
            '$id': 'host',
            'type': 'host',
            'lookup': 'host',
            'multiple': 'optional'
        },
        'securityQuestion': {
            '$id': 'securityQuestion',
            'type': 'securityQuestion',
            'multiple': 'default'
        },
        'pinCode': {
            '$id': 'pinCode',
            'type': 'secret'
        },
        'oneTimeCode': {
            '$id': 'oneTimeCode',
            'type': 'otp'
        },
        'keyPair': {
            '$id': 'keyPair',
            'type': 'privateKey'
        },
        'licenseNumber': {
            '$id': 'licenseNumber',
            'type': 'multiline'
        },
        'multiline': {
            '$id': 'multiline',
            'type': 'multiline'
        },
        # 'custom: {
        #   '$id': 'custom',
        #   'type': 'custom'
        # }
    }

    # https://github.com/Keeper-Security/record-templates/blob/master/field-types.json
    # Record labels override default field type labels
    field_values = {
        'text': {
            'type': 'text',
            'value_description': 'plain text',
            'value': ''  # string
        },
        'url': {
            'type': 'url',
            'value_description': 'url string, can be clicked',
            'value': ''  # string
        },
        'multiline': {
            'type': 'multiline',
            'value_description': 'multiline text',
            'value': ''  # string
        },
        # 2021-05-06 Unused file type - removed for compatibility with web vault
        # 'file': {
        #   'type': 'file',
        #   'value_description': 'large binary object, picture or other file',
        #   'value': '' # ???
        # },
        'fileRef': {
            'type': 'fileRef',
            'value_description': 'reference to the file field on another record',
            'value': ''  # string (record v4 UID)
        },
        'email': {
            'type': 'email',
            'value_description': 'valid email address plus tag',
            'value': ''  # string
        },
        'host': {
            'type': 'host',
            'value_description': 'multiple fields to capture host information',
            'value': {  # object
                'hostName': '',  # string
                'port': ''  # string
            }
        },
        'phone': {
            'type': 'phone',
            'value_description': 'numbers and symbols only plus tag',
            'value': {  # object
                'region': '',  # string
                'number': '',  # string
                'ext': '',  # string
                'type': ('', 'Mobile', 'Home', 'Work')
            }
        },
        'name': {
            'type': 'name',
            'value_description': 'multiple fields to capture name',
            'value': {  # object
                'first': '',  # string
                'middle': '',  # string
                'last': ''  # string
            },
            'required': ['first', 'last']
            # required parts of field value - enforced only when RT specify that field is required
            # 2021-04-01 use reference implementation (webVault - above) != from documentation (Record+Format+V3+draft - below)
            # 'value': {          # object
            #   'firstName': '',  # string
            #   'middleName': '', # string
            #   'lastName': ''    # string
            # },
            # 'required': ['firstName', 'lastName']
        },
        'address': {
            'type': 'address',
            'value_description': 'multiple fields to capture address',
            'value': {  # object
                'street1': '',  # string
                'street2': '',  # string
                'city': '',  # string
                'state': '',  # string
                'zip': '',  # string
                'country': ''  # string
            }
        },
        'addressRef': {
            'type': 'addressRef',
            'value_description': 'reference to the address field on another record',
            'value': ''  # string
        },
        'cardRef': {
            'type': 'cardRef',
            'value_description': 'reference to the bankCard field on another record',
            'value': ''  # string (record UID)
        },
        'secret': {
            'type': 'secret',
            'value_description': 'the field value is masked',
            'value': ''  # string
        },
        'login': {
            'type': 'login',
            'value_description': 'Login field, detected as the website login for browser extension or KFFA.',
            'value': ''  # string?
        },
        'password': {
            'type': 'password',
            'value_description': 'Field value is masked and allows for generation. Also complexity enforcements.',
            'value': ''  # string
        },
        'securityQuestion': {
            'type': 'securityQuestion',
            'value_description': 'Security Question and Answer',
            'value': {  # object
                'question': '',  # string
                'answer': ''  # string
            }
        },
        'otp': {
            'type': 'otp',
            'value_description': 'captures the seed, displays QR code',
            'value': ''  # string
        },
        'paymentCard': {
            'type': 'paymentCard',
            'value_description': 'Field consisting of validated card number, expiration date and security code.',
            'value': {  # object
                'cardNumber': '',  # string
                'cardExpirationDate': '',  # string
                'cardSecurityCode': ''  # string
            }
        },
        'date': {
            'type': 'date',
            'value_description': 'calendar date with validation, stored as unix milliseconds',
            'value': 0  # number (long)
        },
        'bankAccount': {
            'type': 'bankAccount',
            'value_description': 'bank account information',
            'value': {  # object
                'accountType': ('Checking', 'Savings', 'Other'),
                'otherType': '',  # string
                'routingNumber': '',  # string
                'accountNumber': ''  # string (required for RT bankAccount)
            },
            'required': ['accountNumber']
            # required parts of field value - enforced only when RT specify that field is required
        },
        'privateKey': {
            'type': 'privateKey',
            'value_description': 'private key in ASN.1 format',
            'value': {  # object
                'publicKey': '',  # string
                'privateKey': ''  # string
            }
        }
    }

    # field_values w/o field_type - probably migrated to different types
    # 'pinCode': '',       # string - currently v3.pinCode.type == secret /string/
    # 'keyPair': {         # object - currently v3.keyPair.type == privateKey /string (PEM encoded)/
    #     'publicKey': '', # string
    #     'privateKey': '' # string
    #   },
    # 'note': ''           # string - currently v3.note.type == multiline /string/

    @classmethod
    def is_valid_field(cls, field_json):
        ft_dict = {}
        if field_json:
            try:
                ft_dict = json.loads(field_json)
            except:
                ft_dict = {}

        ft = ft_dict.get('type')
        fv = ft_dict.get('value') or []
        valid_type = RecordV3.is_valid_field_type(ft)
        valid_value = RecordV3.is_valid_field_value(ft, fv)
        result = valid_type and valid_value
        return result

    @classmethod
    def is_valid_field_type(cls, field_type):
        result = True if field_type and cls.field_types.get(field_type) else False
        return result

    @classmethod
    def is_valid_field_value(cls, field_type, field_value):
        result = False
        if field_type and RecordV3.is_valid_field_type(field_type):
            # empty value is OK
            if field_value == []:
                result = True

            if not result and isinstance(field_value, list):
                fdef = cls.field_types.get(field_type) or {}
                ftyp = fdef.get('type')
                fvt = cls.field_values.get(ftyp)
                fval = fvt.get('value')
                results = True
                if ftyp in ('fileRef', 'cardRef', 'addressRef'):
                    for fv in field_value:
                        results = results and RecordV3.is_valid_ref_uid(fv)
                elif isinstance(fval, int):
                    for fv in field_value:
                        results = results and (isinstance(fv, int) or bool(re.match(r'^\s*[-+]?\s*\d+\s*$', str(fv))))
                elif isinstance(fval, str):
                    for fv in field_value:
                        results = results and isinstance(fv, str) and bool(fv)
                elif isinstance(fval, tuple):
                    for fv in field_value:
                        results = results and fval.__contains__(str(fv).strip())
                elif isinstance(fval, dict):
                    for fv in field_value:
                        results = results and isinstance(fv, dict)
                        if not results: break
                        for fvv in fv:
                            val1 = fval.get(fvv)
                            val2 = fv.get(fvv)
                            res = bool(val2)
                            if isinstance(val1, int):
                                res = res and (
                                            isinstance(val2, int) or bool(re.match(r'^\s*[-+]?\s*\d+\s*$', str(val2))))
                            elif isinstance(val1, str):
                                res = res and isinstance(val2, str) and bool(val2)
                            elif isinstance(val1, tuple):
                                res = res and val1.__contains__(str(val2).strip())
                            else:
                                res = False
                            results = results and res
                else:
                    results = False
                result = results

        return result

    @classmethod
    def is_valid_field_data(cls, field_data, required=False):
        errors = []

        # ex. {"type": "name", "value": [{"first": "", "middle": "", "last": ""}]}
        ft = field_data if isinstance(field_data, dict) else RecordV3.record_type_to_dict(field_data)
        ftype = ft.get('type')
        fvalue = ft.get('value') or []
        reqd = required or bool(ft.get('required')) or False
        if ftype and RecordV3.is_valid_field_type(ftype):
            # empty value is OK for non-required fields
            if not fvalue:
                if reqd:
                    errors.append('Field missing required value: ' + str(field_data))
                return errors

            if isinstance(fvalue, list):
                fdef = cls.field_types.get(ftype) or {}
                ftyp = fdef.get('type')
                fvt = cls.field_values.get(ftyp) or {}
                fval = fvt.get('value')
                freq = (fvt.get('required') or []) if reqd else []
                # warnings.append('Couldn\'t find required fields for field type: ' + str(ftyp))

                if ftyp in ('fileRef', 'cardRef', 'addressRef'):
                    for fv in fvalue:
                        # if reqd and not fv: errors.append('Missing required Ref UID: ' + fv)
                        if fv and not RecordV3.is_valid_ref_uid(fv):
                            errors.append('Invalid Ref UID: ' + fv)
                elif isinstance(fval, int):
                    for fv in fvalue:
                        # if reqd and not fv: errors.append('Missing required integer value: ' + fv)
                        if not ((isinstance(fv, int) or bool(re.match(r'^\s*[-+]?\s*\d+\s*$', str(fv))))):
                            errors.append('Invalid integer value: ' + fv)
                elif isinstance(fval, str):
                    for fv in fvalue:
                        # if reqd and not fv: errors.append('Missing required string value: ' + fv)
                        if not isinstance(fv, str):  # and bool(fv)
                            errors.append('Invalid string value: ' + fv)
                elif isinstance(fval, tuple):
                    for fv in fvalue:
                        # if reqd and not fv: errors.append('Missing required enum value: ' + fv)
                        if not fval.__contains__(str(fv).strip()):
                            errors.append('Invalid enum value: ' + fv)
                elif isinstance(fval, dict):
                    for fv in fvalue:
                        if not isinstance(fv, dict):
                            errors.append('Invalid object value: ' + fv)
                        if errors: break
                        for fvv in fv:
                            val1 = fval.get(fvv)
                            val2 = fv.get(fvv)
                            res = bool(val2)
                            if reqd and fvv in freq and not res:
                                errors.append('Missing required object field value: ' + fvv)
                            if not errors:
                                if isinstance(val1, int):
                                    if not (
                                    (isinstance(val2, int) or bool(re.match(r'^\s*[-+]?\s*\d+\s*$', str(val2))))):
                                        errors.append('Invalid integer object value: ' + fvv)
                                elif isinstance(val1, str):
                                    if not isinstance(val2, str):  # and bool(val2)
                                        errors.append('Invalid string object value: ' + fvv)
                                elif isinstance(val1, tuple):
                                    if not val1.__contains__(str(val2).strip()):
                                        errors.append('Invalid enum object value: ' + fvv)
                                else:
                                    errors.append('Invalid object value type: ' + fvv)
                else:
                    errors.append('Invalid value type: ' + fval)
            else:
                errors.append('Expected an array of field values: ' + str(ftype))
        else:
            errors.append('Field has unknown type: ' + str(ftype))

        return errors

    @classmethod
    def is_valid_field_type_ref(cls, field_type_json):
        # field ref inside record type definition - ex. {"$ref":"name", "required":true, "label":"placeName"}
        # 2021-04-26 currently the only used options in field ref are - $ref, label, required
        result = False
        if field_type_json:
            try:
                ft = json.loads(field_type_json)
            except:
                ft = {}
            ref = ft.get('$ref')
            result = RecordV3.is_valid_field_type(ref)

            known_keys = ('$ref', 'label', 'required', 'privacyscreen', 'enforcegeneration', 'complexity')
            unknown_keys = [x for x in ft if x.lower() not in known_keys]
            if unknown_keys:
                logging.warning('Unknown attributes in field reference: ' + str(unknown_keys))

        return result

    @classmethod
    def is_valid_field_type_data(cls, field_type_json):
        # field data inside record type - ex. {"type":"name","value":[{"first":"John","last":"Doe"}],"required":true, "label":"personName"}
        # 2021-04-26 currently the only used options in fields are - type, label, required, value[]
        result = False
        if field_type_json:
            try:
                ft = json.loads(field_type_json)
            except:
                ft = {}
            ref = ft.get('type')
            result = True if ref and cls.field_types.get(ref) else False

            known_keys = ('type', 'label', 'required')
            unknown_keys = [x for x in ft if x.lower() not in known_keys]
            if unknown_keys:
                logging.warning('Unknown attributes in field type data: ' + str(unknown_keys))
        return result

    @staticmethod
    def get_custom_list(custom_list):
        # parse a list of key-value pairs - accepted formats: json, csv, list
        custom = []
        error = ''
        if custom_list:
            if type(custom_list) == str:
                if custom_list[0] == '{' and custom_list[-1] == '}':
                    try:
                        custom_json = json.loads(custom_list)
                        for k, v in custom_json.items():
                            custom.append({
                                'name': k,
                                'value': str(v)
                            })
                    except ValueError as e:
                        error = 'Invalid custom fields JSON input for {0}, Error: {1}'.format(custom_list, e)
                else:
                    pairs = custom_list.split(',')
                    for pair in pairs:
                        idx = pair.find(':')
                        if idx > 0:
                            custom.append({
                                'name': pair[:idx].strip(),
                                'value': pair[idx + 1:].strip()
                            })
                        else:
                            error = 'Invalid custom fields input for {0}. Expected: "Key:Value". Got: "{1}"'.format(
                                custom_list, pair)
            elif type(custom_list) == list:
                for c in custom_list:
                    if type(c) == dict:
                        name = c.get('name')
                        value = c.get('value')
                        if name and value:
                            custom.append({'name': name, 'value': value})
        result = {'custom_list': custom, 'error': error}
        return result

    @staticmethod
    def get_record_password(rt_data):
        # Records v3 allow only one password to be stored either in fields[] or in custom[]
        rt = RecordV3.record_type_to_dict(rt_data)
        flds = (rt.get('fields') or []) + (rt.get('custom') or [])
        passwords = [x.get('value') or [] for x in flds if isinstance(x, dict) and x.get('type') == 'password']
        result = passwords[0][0] if passwords and passwords[0] else None
        return result

    @staticmethod
    def get_record_field_value(rt_data, field_name, printable=True):
        rt = RecordV3.record_type_to_dict(rt_data)
        flds = (rt.get('fields') or []) + (rt.get('custom') or [])
        values = [x.get('value') or [] for x in flds if isinstance(x, dict) and x.get('type') == field_name]
        result = values[0][0] if values and values[0] else ''
        if printable:
            result = str(result)
        return result

    @staticmethod
    def get_record_type_name(rt_data):
        result = None

        rt = rt_data if isinstance(rt_data, dict) else {}
        if rt_data and (isinstance(rt_data, str) or isinstance(rt_data, bytes)):
            try:
                rt = json.loads(rt_data or '{}')
            except:
                logging.error(bcolors.FAIL + 'Unable to parse record type JSON: ' + str(rt_data) + bcolors.ENDC)

        if rt and isinstance(rt, dict):
            rtt = rt.get('type')
            if rtt:
                result = rtt
            else:
                logging.error(bcolors.FAIL + 'Unable to find record type type - JSON: ' + str(rt_data) + bcolors.ENDC)

        return result

    @staticmethod
    def get_record_type_definition(params, rt_data):
        result = None

        rt_type = RecordV3.get_record_type_name(rt_data)
        if rt_type:
            rt_def = RecordV3.resolve_record_type_by_name(params, rt_type)
            if rt_def:
                result = rt_def
            else:
                logging.error(bcolors.FAIL + 'Record type definition not found for type: ' + str(rt_type) +
                              ' - to get list of all available record types use: record-type-info -lr' + bcolors.ENDC)

        return result

    @staticmethod
    def get_fileref_location(params, rt_data):
        # lookup for fileRef presence in following order:
        # 1) non-empty fileRef in fields[] 2) in custom 3) RT definition 4) if not found anywhere return 'custom'
        result = ''

        # first search for non-empty fileRef in record data
        rt = rt_data if isinstance(rt_data, dict) else RecordV3.record_type_to_dict(rt_data)
        flds = rt.get('fields') or []
        fref = [x.get('value') or [] for x in flds if isinstance(x, dict) and x.get('type') == 'fileRef']
        if fref:
          result = 'fields'
        else:
          flds = rt.get('custom') or []
          fref = [x.get('value') or [] for x in flds if isinstance(x, dict) and x.get('type') == 'fileRef']
          if fref:
            result = 'custom'

        # next lookup fileRef in RT definition if needed
        if not result:
          rt_def = RecordV3.get_record_type_definition(params, rt_data)
          rtdef = {}
          if rt_def:
            try: rtdef = json.loads(rt_def)
            except: logging.error(bcolors.FAIL + 'Unable to parse record type definition JSON: ' + str(rt_def) + bcolors.ENDC)
          if rtdef:
            has_fref = next((True for x in (rtdef.get('fields') or []) if '$ref' in x and x.get('$ref') == 'fileRef'), False)
            if has_fref:
              result = 'fields'

        # if not found anywhere - use custom
        if not result:
          result = 'custom'

        return result

    @staticmethod
    def get_record_type_title(rt_data):
        result = None

        rt = rt_data if isinstance(rt_data, dict) else {}
        if rt_data and (isinstance(rt_data, str) or isinstance(rt_data, bytes)):
            try:
                rt = json.loads(rt_data or '{}')
            except:
                logging.error(bcolors.FAIL + 'Unable to parse record type JSON: ' + str(rt_data) + bcolors.ENDC)

        if rt and isinstance(rt, dict):
            rtt = rt.get('title')
            if rtt:
                result = rtt
            else:
                logging.error(bcolors.FAIL + 'Unable to find record type title - JSON: ' + str(rt_data) + bcolors.ENDC)

        return result

    @staticmethod
    def resolve_record_type_by_name(params, record_type_name):
        record_type_info = None
        if record_type_name:
            if params.record_type_cache:
                for v in params.record_type_cache.values():
                    dict = json.loads(v)
                    # TODO: Is 'type' case sensitive
                    if dict and dict.get('$id').lower() == record_type_name.lower():
                        record_type_info = v
                        break

        return record_type_info

    @staticmethod
    def change_record_type(params, rt_data, new_rt_name):
        # Converts rt_data (dict or JSON) from one valid record type to another
        # by moving required fields between fields[] and custom[]

        result = {
            'errors': [],
            'warnings': [],
            'record': {}
        }

        r = rt_data if isinstance(rt_data, dict) else {}
        if isinstance(rt_data, str) or isinstance(rt_data, bytes):
            try:
                r = json.loads(rt_data)
            except:
                result['errors'].append('Unable to parse record type data JSON: ' + str(rt_data))

        newrtd = {}
        rt_def = RecordV3.resolve_record_type_by_name(params, new_rt_name)
        if rt_def:
            try:
                newrtd = json.loads(rt_def)
            except:
                result['errors'].append('Unable to parse record type definition JSON: ' + str(rt_def))
        else:
            result['errors'].append('Record type definition not found for type: ' + str(
                new_rt_name) + ' - to get list of all available record types use: record-type-info -lr')
        if result['errors']: return result

        rt = copy.deepcopy(r)
        newf = newrtd.get('fields') or []
        # newf = [x.get('$ref') for x in newf if isinstance(x, dict)]

        existing_fields = (rt.get('fields') or []) + (rt.get('custom') or [])
        new_fields = []
        for fld in newf:
            index = next((i for i, x in enumerate(existing_fields)
                          if fld.get('$ref', '') == x.get('type', '') and fld.get('label', '') == x.get('label', '')), -1)
            if index >= 0:
                new_fields.append(existing_fields.pop(index))
            else:
                f = {'type': fld['$ref'], 'value': []}
                if 'label' in fld:
                    f['label'] = fld['label']
                new_fields.append(f)
        new_custom = [x for x in existing_fields if isinstance(x.get('value'), list) and len(x.get('value')) > 0]

        rt['fields'] = new_fields
        rt['custom'] = new_custom
        rt['type'] = new_rt_name

        if not result['errors']:
            r = rt

        result['record'] = r
        return result

    @staticmethod
    def is_valid_ref_uid(uid: str) -> bool:
        # UID length is 22 and all characters are valid base64 urlsafe characters
        result = bool(re.search('^[A-Za-z0-9-_]{22}$', uid or ''))
        return result

    @staticmethod
    def add_field_label(rtdef, field_labels_to_add, fname):
        if fname not in field_labels_to_add:
            label_gen = (f.get('label') for f in rtdef.get('fields', []) if f.get('$ref') == fname)
            label = next(label_gen, None)
            if label is not None:
                field_labels_to_add[fname] = label

    @staticmethod
    def convert_options_to_json(params, rt_json, rt_def, kwargs):
        # Converts dot notation options string to JSON string representing a valid record type
        # NB! Currently duplicate field types cannot be added or edited using dot notation syntax
        # Use JSON representation for full add/edit capabilites

        result = {
            'errors': [],
            'warnings': [],
            'record': {}
        }

        is_edit = True if rt_json else False

        rt = {}
        if rt_json:
            try:
                rt = json.loads(rt_json or '{}')
            except:
                result['errors'].append('Unable to parse record type JSON: ' + str(rt_json))

        rtdef = {}
        if rt_def:
            try:
                rtdef = json.loads(rt_def)
            except:
                result['errors'].append('Unable to parse record type definition JSON: ' + str(rt_def))
        if result['errors']: return result

        options = kwargs.get('option') or []
        opts = [(x or '').split("=", 1) for x in options]
        if not options and not kwargs.get('custom_list'):
            return result

        # normalize prefixes: f. -> fields., c. -> custom.
        # so f.name.first is treated as duplicate of fields.name.first
        for x in opts:
            if x and x[0]:
                x[0] = re.sub(r'^\s*fields\.', 'fields.', x[0], 1, flags=re.IGNORECASE)
                x[0] = re.sub(r'^\s*custom\.', 'custom.', x[0], 1, flags=re.IGNORECASE)
                x[0] = re.sub(r'^\s*f\.', 'fields.', x[0], 1, flags=re.IGNORECASE)
                x[0] = re.sub(r'^\s*c\.', 'custom.', x[0], 1, flags=re.IGNORECASE)

        # check for duplicate keys or keys with more than one value
        dupes = [x for x in opts if x and len(x) != 2]  # keys with multiple values
        if dupes:
            result['errors'].append('Found keys with multiple values: ' + str(dupes))
        groups = {}  # duplicate key(s)
        for x, *values in opts: groups[x] = 1 + (groups.get(x) or 0)
        multi = [{x: groups[x]} for x in groups if groups[x] > 1]
        if multi:
            result['errors'].append('Found duplicate keys/values: ' + str(multi))
        if result['errors']: return result

        rt_type = next((x[1] for x in opts if x and len(x) == 2 and x[0].lower() == 'type'), None)
        if not rt_type and is_edit and isinstance(rt, dict): rt_type = rt.get('type')
        rt_title = next((x[1] for x in opts if x and len(x) == 2 and x[0].lower() == 'title'), None)
        rt_notes = next((x[1] for x in opts if x and len(x) == 2 and x[0].lower() == 'notes'), None)
        rt_fields = next((x[1] for x in opts if x and len(x) == 2 and x[0].lower() == 'fields'), None)
        rt_custom = next((x[1] for x in opts if x and len(x) == 2 and x[0].lower() == 'custom'), None)

        if not rt_type:
            result['errors'].append('Record types "type" is required')
        if rt_fields or rt_custom:
            result['errors'].append('Array types fields[] and custom[] cannot be assigned directly')
        if result['errors']: return result

        # Top level RT options - unknown attribute(s) generate error
        # All known attribute(s) /from RT definition/ generate а warning and are silently ignored
        tlo = [x for x in opts if x and not x[0].__contains__('.')]
        ignored = ('$id', 'categories', 'description', 'label')  # these are in RT definitions only
        ilist = [x for x in tlo if x and x[0] in ignored]
        if ilist:
            tlo = [x for x in tlo if x not in ilist]
            result['warnings'].append(
                'Removed record type attributes that should be present in record type definitions only: ' + str(ilist))

        ulist = [x for x in tlo if x and x[0].strip() not in ('type', 'title', 'notes')]
        if ulist:
            result['errors'].append('Unknown top level attributes: ' + str(ulist))

        # field type options - ex. -o field.name.first=Jane -o f.name.last=Doe
        flo = [x for x in opts if x and x[0].__contains__('.')]

        # All fields must be either in fields[] or custom[] arrays
        badg = [x for x in flo if x[0].split('.', 1)[0].strip().lower() not in ('fields', 'custom')]
        if badg:
            result['errors'].append('Unknown field group (not fields[] and not custom[]): ' + str(badg))

        # Allow only valid/known field types - field types are case sensitive?
        badf = [x for x in flo if not RecordV3.field_types.__contains__(x[0].split('.', 2)[1].strip())]
        if badf:
            result['errors'].append('Unknown field types: ' + str(badf))
        if result['errors']: return result

        # only one FT of type password allowed in record v3
        pwds = [x for x in flo if
                x and x[0].startswith(('fields.password', 'f.password', 'custom.password', 'c.password'))]
        if len(pwds) > 1:
            result['errors'].append('Error: Only one password allowed per record! ' + str(pwds))
        elif len(pwds) == 1:
            rtdp = next((True for x in (rtdef.get('fields') or []) if '$ref' in x and x.get('$ref') == 'password'),
                        False)
            pwdc = pwds[0][0] and pwds[0][0].lower().startswith('custom.')
            if rtdp:
                if pwdc: result['errors'].append(
                    'Password must be in fields[] section as defined by record type! ' + str(pwds))
            else:
                if not pwdc: result['errors'].append(
                    'Password must be in custom[] section - record type does not allow password in fields[]! ' + str(
                        pwds))
        if result['errors']: return result

        # All fields with prefix f./fields. must be in record type definition
        # Don't move f./fields. not in RT definition to custom[] - undefined order on duplicates, might break scripts
        rtdf = [x.get('$ref') for x in (rtdef.get('fields') or []) if '$ref' in x]
        flds = [x for x in flo if x and x[0].startswith(('fields.', 'f.'))]
        cust = [x for x in flo if x and x[0].startswith(('custom.', 'c.'))]
        badf = [x for x in flds if not x[0].split('.', 2)[1].strip() in rtdf]
        if badf:
            result['errors'].append(
                'This record type doesn\'t allow "fields." prefix for these (move to custom): ' + str(badf))
        # fileRef must use upload-attachment/delete-attachment commands instead
        refs = [x for x in flds + cust if x[0].split('.', 2)[1].strip().lower() == 'fileref']
        if refs:
            result['errors'].append(
                'File reference manipulations are disabled here. Use upload-attachment/delete-attachment commands instead. ' + str(
                    refs))
        if result['errors']: return result

        # edit command: JSON validation before update
        # add command: fields[] must contain all 'required' fields (and required value parts)
        if not is_edit:
            flon = [x[0] for x in flo if x and x[0]]
            reqd = [x.get('$ref') for x in (rtdef.get('fields') or []) if '$ref' in x and 'required' in x]
            for fld in reqd:
                ft = (RecordV3.field_types.get(fld) or {}).get('type')
                ftr = (RecordV3.field_values.get(ft) or {}).get('required') or []
                if ftr:
                    ftr = ['fields.' + fld + '.' + x for x in ftr]
                    ftrm = [x for x in ftr if x not in flon]
                    if ftrm:
                        result['errors'].append('Missing required fields: ' + str(
                            ftrm) + '   Use `rti -lf field_name --example` to generate valid field sample.')
                elif next((f for f in flon if f.split('.')[:2] == ['fields', fld]), None) is None:
                    result['warnings'].append('Couldn\'t find required fields for the field type: ' + str(ft))
        if result['errors']: return result

        # NB! cmdline labels override RT definition labels which override FT definition labels
        r = {}
        if is_edit and rt_type != rt.get('type'):
            res = RecordV3.change_record_type(params, rt_json, rt_type)
            if not res.get('errors'):
                r = res.get('record') or r
            if res.get('errors'): result['errors'].extend(res['errors'])
            if res.get('warnings'): result['warnings'].extend(res['warnings'])
        else:
            r = copy.deepcopy(rt)  # for edited or deleted items
            if not r: r = {'type': rt_type}  # add command
            if rt_title: r['title'] = rt_title
            if is_edit and rt_title == '': r['title'] = ''  # edit: delete title
            if rt_notes: r['notes'] = rt_notes
            if is_edit and rt_notes == '': r['notes'] = ''  # edit: delete notes
            if not 'fields' in r: r['fields'] = []
            if not 'custom' in r: r['custom'] = []
            unique_field_types = [k for k, v in Counter(rtdf).items() if v == 1]
            field_labels_to_add = {}
            for lst in [flds, cust]:
                for f in lst:
                    if f and len(f) == 2:
                        val = f[1]
                        path = f[0].split('.')
                        forc = path[0].strip() if path else ''  # fields or custom
                        fname = path[1].strip() if path and len(path) > 1 else ''  # field name
                        fvname = path[2].strip() if path and len(path) > 2 else ''  # field attribute (if any)
                        if fname:
                            if not forc in r: r[forc] = []  # create fields[] or custom[]
                            fv = next((x for x in r[forc] if isinstance(x, dict) and x.get('type') == fname), {})
                            if not fv:
                                fv = {'type': fname, 'value': []}
                                r[forc].append(fv)
                            if 'value' not in fv: fv['value'] = []
                            elif not isinstance(fv['value'], list): fv['value'] = []
                            if fvname:
                                # NB! required:true/false comes from RT definition and should not be re/set here
                                if fvname.lower() == 'required':
                                    result['warnings'].append(
                                        'Skipped "required" field attribute which comes from record type definition and should not be set here! ' + str(
                                            f))
                                    continue
                                # check if fvname is FT attribute vs FT value object parts - ex. c.name.label vs. c.name.first
                                if fvname.lower() == 'label':
                                    fv['label'] = val
                                elif is_edit and not val:  # delete
                                    if forc in r:
                                        v = next((x.get('value') or [] for x in r[forc] if
                                                  isinstance(x, dict) and x.get('type') == fname), [])
                                        # v = next((x for x in v if isinstance(x, dict) and fvname in x), {})
                                        v = next((x for x in v if isinstance(x, dict)), {})
                                        v.pop(fvname, None)
                                elif bool(val):  # upsert
                                    if forc == 'fields' and fname in unique_field_types:
                                        RecordV3.add_field_label(rtdef, field_labels_to_add, fname)
                                    # v = next((x for x in fv['value'] if isinstance(x, dict) and fvname in x), None)
                                    v = next((x for x in fv['value'] if isinstance(x, dict)), None)
                                    if v:
                                        v[fvname] = val
                                    else:
                                        fv['value'].append({fvname: val})
                                    ok = RecordV3.is_valid_field_value(fname, [{fvname: val}])
                                    if not ok: result['errors'].append(
                                        'Invalid field value: ' + str({fname: [{fvname: val}]}))
                                else:
                                    result['warnings'].append('Skipped empty field value: ' + str(f))
                            else:  # simple value str/int assign directly - ex. c.login=MyLogin
                                if bool(val):
                                    if forc == 'fields' and fname in unique_field_types:
                                        RecordV3.add_field_label(rtdef, field_labels_to_add, fname)
                                    del fv['value'][:]
                                    fv['value'].append(val)
                                elif 'value' in fv and isinstance(fv['value'], list):  # delete
                                    del fv['value'][:]
                    else:
                        result['errors'].append(
                            'Miltiple field values per single option aren\'t allowed. Use multiple options: -o f.name.first=A -o f.name.last=B ' + str(
                                f))
            if len(field_labels_to_add) > 0:
                for field_type, label in field_labels_to_add.items():
                    for rfield in r.get('fields', []):
                        if rfield['type'] in field_labels_to_add and 'label' not in rfield:
                            rfield['label'] = field_labels_to_add[rfield['type']]


        # add command could pass multiple custom options - ex. --custom='{"name1":"value1", "name2":"value: 2,3,4"}'
        # since dot format can't handle duplicate keys we pass these as kwargs['custom_list']
        custom_list = kwargs.get('custom_list') or []
        custom = [{
            'type': 'text',
            'label': x.get('name') or '',
            'value': [x.get('value')] if x.get('value') else []
        } for x in custom_list if x.get('name') or x.get('value')]
        if custom:
            r['custom'] = (r.get('custom') or [])
            if is_edit:
                # update value of existing custom field or insert new one
                for cr in custom:
                    cold = next((x for x in r['custom'] if
                                 x.get('type') == 'text' and x.get('label') == cr.get('label') and cr.get(
                                     'label') is not None), None)
                    if cold:
                        cold['value'] = cr.get('value')
                    else:
                        r['custom'].append(cr)
            else:
                r['custom'] = r['custom'] + custom

        if r and not result['errors']:
            if not r.get('custom'): r.pop('custom', None)
            if not r.get('fields'): r.pop('fields', None)
            rt = r

        if not result['errors']:
            result['record'] = rt

        return result

    @staticmethod
    def values_to_lowerstring(data_json):
        return RecordV3.values_to_string(data_json).lower()

    @staticmethod
    def values_to_string(data_json):
        result = ''

        rt = RecordV3.record_type_to_dict(data_json)
        result += rt.get('title') or ''
        result += rt.get('notes') or ''

        fields = rt.get('fields') or []
        custom = rt.get('custom') or []
        values = [x.get('value') for x in fields + custom if x.get('value')]
        values = [x if not isinstance(x[0], dict) else ';'.join(str(v) for v in x[0].values()) for x in values if
                  len(x) > 0]
        result += str(values)

        return result

    @staticmethod
    def record_type_to_dict(rt_json):
        rt = {}
        if rt_json:
            try:
                rt = json.loads(rt_json or '{}')
            except:
                rt = {}
                logging.error(bcolors.FAIL + 'Unable to parse record type JSON: ' + str(rt_json) + bcolors.ENDC)
        return rt

    @staticmethod
    def update_password(password, rt_json, rt_def):
        # Delete if pass is empty, Upsert if pass is present:
        # Check if there's password field in fields[], custom[] and replace first instance
        # If no password in RT but RT definition has a password field - add to fields[]
        # else add to custom[]
        result = rt_json

        rt = {}
        if rt_json:
            try:
                rt = json.loads(rt_json or '{}')
            except:
                logging.error(bcolors.FAIL + 'Unable to parse record type JSON: ' + str(rt_json) + bcolors.ENDC)

        rtdef = {}
        if rt_def:
            try:
                rtdef = json.loads(rt_def)
            except:
                logging.error(
                    bcolors.FAIL + 'Unable to parse record type definition JSON: ' + str(rt_def) + bcolors.ENDC)

        if not rt or not rtdef:
            logging.error(bcolors.FAIL + 'Failed to update password field!' + bcolors.ENDC)
            return result

        rtt = rt.get('type')
        rtdt = rtdef.get('$id')
        if not rtt or rtt != rtdt:
            logging.error(
                bcolors.FAIL + 'Record type missing or doesn\'t match definition! ' + str([rtt, rtdt]) + bcolors.ENDC)
            return result

        # Look for existing password in fields[] then custom[] and replace
        fields = rt.get('fields') or []
        custom = rt.get('custom') or []
        rtfp = [x for x in fields if 'type' in x and x.get('type') == 'password']
        rtcp = [x for x in custom if 'type' in x and x.get('type') == 'password']
        changed = False
        if rtfp:
            rtfp[0]['value'] = [password] if password else []
            changed = True
        elif rtcp:
            rtcp[0]['value'] = [password] if password else []
            changed = True
        elif password:
            # no existing password - add to fields[] (if RT definition allows) or to custom[]
            rtdp = next((True for x in (rtdef.get('fields') or []) if '$ref' in x and x.get('$ref') == 'password'),
                        False)
            if rtdp:
                if 'fields' not in rt:
                    rt['fields'] = []
                rt['fields'].append({'type': 'password', 'value': [password]})
            else:
                if 'custom' not in rt:
                    rt['custom'] = []
                rt['custom'].append({'type': 'password', 'value': [password]})
            changed = True

        if changed:
            result = json.dumps(rt)

        return result

    @staticmethod
    def get_field_types():
        ftypes = [{**RecordV3.field_types.get(fkey), **RecordV3.field_values.get(vkey)}
                  for fkey in RecordV3.field_types
                  for vkey in RecordV3.field_values
                  if (RecordV3.field_types.get(fkey) or {}).get('type') == vkey
                  ]
        rows = []  # (id, type, lookup, multiple, description)
        for ft in ftypes:
            field_id = ft.get('$id') or ''
            field_type = ft.get('type') or ''
            lookup = ft.get('lookup') or ''
            multiple = ft.get('multiple') or ''
            description = ft.get('value_description') or ''
            rows.append((field_id, field_type, lookup, multiple, description))
        return rows

    @staticmethod
    def get_field_type(id):
        STR_VALUE = 'text'
        ftypes = [{**RecordV3.field_types.get(fkey), **RecordV3.field_values.get(vkey)}
                  for fkey in RecordV3.field_types
                  for vkey in RecordV3.field_values
                  if (RecordV3.field_types.get(fkey) or {}).get('type') == vkey
                  ]
        ids = [ft for ft in ftypes if id and (id == ft.get('$id'))]
        result = ids[0] if ids else {}
        if result:
            val = result.get('value')
            vtype = ('integer' if isinstance(val, int)
                     else 'string' if isinstance(val, str)
            else 'enum' if isinstance(val, tuple)
            else 'object' if isinstance(val, dict)
            else 'unknown')
            obj = val if vtype != 'object' else {
                x: val[x] if not isinstance(val[x], tuple) else " | ".join(str(t) for t in val[x])
                for x in val
            }
            obj_sample = val if vtype != 'object' else {
                x: 0 if isinstance(val[x], int)
                else STR_VALUE if isinstance(val[x], str)
                else val[x][0] if isinstance(val[x], tuple)
                else val
                for x in val
            }
            value = (0 if vtype == 'integer'
                     else '' if vtype == 'string'
            else val[0] if vtype == 'enum'
            else obj if vtype == 'object'
            else '')
            sample = (0 if vtype == 'integer'
                      else STR_VALUE if vtype == 'string'
            else val[0] if vtype == 'enum'
            else obj_sample if vtype == 'object'
            else '')

            result = {
                'id': result.get('$id') or '',
                'type': result.get('type') or '',
                'valueType': vtype,
                'value': value,
                'sample': sample
            }
        return result

    @staticmethod
    def get_record_type_example(params, rt_name: str) -> str:
        STR_VALUE = 'text'

        result = ''
        rte = {}
        rt_def = RecordV3.resolve_record_type_by_name(params, rt_name)
        if rt_def:
            rtdd = RecordV3.record_type_to_dict(rt_def)
            rtdf = rtdd.get('fields') or []

            rte = {
                'type': rt_name,
                'title': STR_VALUE,
                'notes': STR_VALUE,
                'fields': [],
                'custom': []
            }

            rtdef = {}
            try:
                rtdef = json.loads(rt_def)
            except:
                logging.error(
                    bcolors.FAIL + 'Unable to parse record type definition JSON: ' + str(rt_def) + bcolors.ENDC)

            fields = rtdef.get('fields') or []
            fields = [x.get('$ref') for x in fields]
            for fname in fields:
                ft = RecordV3.get_field_type(fname)
                if not ft:
                    ft = {
                        'id': fname,
                        'type': 'text',
                        'valueType': 'string',
                        'value': '',
                        'sample': 'unknown type'
                    }

                val = {
                    'type': fname,
                    'value': []
                }

                if fname not in ('fileRef', 'addressRef', 'cardRef'):
                    # Fix for webVault - fails if phone's region is not valid country code
                    if fname == 'phone' and 'sample' in ft and 'region' in ft['sample']:
                        ft['sample']['region'] = 'US'

                    val['value'].append(ft.get('sample'))
                    required = next((x.get('required') for x in rtdf if x.get('$ref') == fname), None)
                    if required:
                        val['required'] = required
                    label = next((x.get('label') for x in rtdf if x.get('$ref') == fname), None)
                    if label:
                        val['label'] = label

                rte['fields'].append(val)
        else:
            logging.error(bcolors.FAIL + 'Unable to find record type definition for type: ' + str(rt_name) +
                          '   To show available record types definitions use `record-type-info --list-record *` command' + bcolors.ENDC)

        result = json.dumps(rte, indent=2) if rte else ''
        return result

    @staticmethod
    def display(r, **kwargs):
        record_uid = r['record_uid']
        print('')
        # print('{0:>20s}: https://keepersecurity.com/vault#detail/{1}'.format('Link', record_uid))
        print('{0:>20s}: {1:<20s}'.format('UID', record_uid))
        # if 'version' in r: print('{0:>20s}: {1:<20s}'.format('Version', str(r['version'])))
        params = None
        if 'params' in kwargs:
            params = kwargs['params']
            folders = [get_folder_path(params, x) for x in find_folders(params, record_uid)]
            for i in range(len(folders)):
                print('{0:>21s} {1:<20s}'.format('Folder:' if i == 0 else '', folders[i]))

        data = {}
        if 'data_unencrypted' in r:
            data = r['data_unencrypted'].decode() if isinstance(r['data_unencrypted'], bytes) else r['data_unencrypted']
            data = json.loads(data)
        fields = data.get('fields') or []
        custom = data.get('custom') or []

        record_type = data['type'] if 'type' in data else ''
        print('{0:>20s}: {1:<20s}'.format('Type', record_type))
        print('{0:>20s}: {1:<20s}'.format('Title', str(data['title']) if 'title' in data else ''))
        # NB! General notes here - fields[] might provide their own notes
        if 'notes' in data:
            notes = data['notes']
            if notes:
                lines = notes.split('\n')
                for i, line in enumerate(lines):
                    print('{0:>21s} {1}'.format('Notes:' if i == 0 else '', line.strip()))
        # fields[] * print Field# NN - atrib: value
        unmask = kwargs.get('unmask', False)
        for c in fields + custom:
            ftyp = c.get('type') or ''
            flab = c.get('label') or ''
            flds = c.get('value') or []
            fval = flds
            fkey = '{} ({})'.format(flab, ftyp)
            if ftyp in ['securityQuestion', 'paymentCard', 'host', 'keyPair', 'bankAccount', 'phone']:
                if not isinstance(flds, list):
                    flds = [flds]
                fval = []
                for x in flds:
                    if isinstance(x, dict):
                        if ftyp == 'securityQuestion':
                            q = x.get('question') or ''
                            if q and not q.endswith('?'):
                                q += '?'
                            a = x.get('answer', '') if unmask else '********'
                            fval.append(f'{q} {a}')
                        elif ftyp == 'paymentCard':
                            n = x.get('cardNumber') or ''
                            if n and not unmask:
                                n = '*' + n[-4:]
                            e = x.get('cardExpirationDate') or ''
                            c = (x.get('cardSecurityCode') or '') if unmask else '***'
                            fval.append(f'{n} exp:{e} cvv:{c}')
                        elif ftyp == 'keyPair':
                            public_key = x.get('publicKey')
                            if public_key:
                                fval.append(public_key)
                            private_key = x.get('privateKey')
                            if private_key:
                                fval.append(private_key if unmask else '********')
                        elif ftyp == 'host':
                            hostname = x.get('hostName') or ''
                            port = x.get('port') or ''
                            if port:
                                hostname += f':{port}'
                            if hostname:
                                fval.append(hostname)
                        elif ftyp == 'phone':
                            number = ''
                            phone_type = x.get('type') or ''
                            if phone_type:
                                number = f'{phone_type}: '
                            region = x.get('region') or ''
                            if region:
                                number += f'{region} '
                            number += x.get('number') or ''
                            ext = x.get('ext') or ''
                            if ext:
                                number += f' ({ext})'
                            fval.append(number)
                        elif ftyp == 'bankAccount':
                            account_type = x.get('accountType') or ''
                            routing_number = x.get('routingNumber') or ''
                            if routing_number and not unmask:
                                routing_number = '*' + routing_number[-3:]
                            account_number = x.get('accountNumber') or ''
                            if account_number and not unmask:
                                account_number = '*' + account_number[-3:]
                            number = f'{account_type}: ' if account_type else ''
                            if routing_number or account_number:
                                if routing_number and account_number:
                                    number += f'{routing_number} / {account_number}'
                                else:
                                    number = routing_number if routing_number else account_number
                            fval.append(number)

                for i, line in enumerate(fval):
                    print('{0:>20s}: {1:<s}'.format(fkey if i == 0 else '', line))
            else:
                if isinstance(flds, list) and len(flds) == 1:
                    if not flds[0]: continue
                    if isinstance(flds[0], dict):
                        fval = (' ' if ftyp.lower() == 'name' else ' | ').join((str(x) for x in flds[0].values()))
                    elif RecordV3.get_field_type(ftyp).get('type') == 'date' and bool(
                            re.match('^[+-]?[0-9]+$', str(flds[0]).strip())):
                        dt = datetime.datetime.fromtimestamp(int(flds[0] / 1000), tz=datetime.timezone.utc)
                        fval = str(dt.date())
                    elif record_type == 'ssnCard' and ftyp == 'accountNumber' and flab == 'identityNumber':
                        fval = flds[0] if unmask else '********'
                    else:
                        fval = flds[0]
                if fval:
                    if ftyp in ('fileRef', 'cardRef', 'addressRef'):
                        RecordV3.display_ref(ftyp, fval, **kwargs)
                    else:
                        is_masked = ftyp in ['password', 'pinCode', 'secret', 'note', 'oneTimeCode'] and not unmask
                        if is_masked:
                            print('{0:>20s}: {1:<s}'.format(fkey, '********'))
                        else:
                            if ftyp == 'multiline' and isinstance(fval, str):
                                lines = fval.split('\n')
                                lines = [x.strip() for x in lines if x]
                                for i, line in enumerate(lines):
                                    print('{0:>20s}: {1}'.format(fkey if i == 0 else '', line.strip()))
                            else:
                                print('{0:>20s}: {1:<s}'.format(fkey, str(fval)))

        totp = next((t.get('value') for t in fields if t.get('type', '') == 'oneTimeCode'), None)
        if totp:
            totp = totp[0] if isinstance(totp, list) else totp
        if totp:
            result = get_totp_code(totp)
            if result:
                code, remain, _ = result
                if code: print('{0:>20s}: {1:<20s} valid for {2} sec'.format('Two Factor Code', code, remain))

        if params is not None:
            if record_uid in params.record_cache:
                rec = params.record_cache[record_uid]
                if 'shares' in rec:
                    no = 0
                    if 'user_permissions' in rec['shares']:
                        perm = rec['shares']['user_permissions'].copy()
                        perm.sort(key=lambda r: (' 1' if r.get('owner') else ' 2' if r.get(
                            'editable') else ' 3' if r.get('sharable') else '') + r.get('username'))
                        for uo in perm:
                            flags = ''
                            if uo.get('owner'):
                                flags = 'Owner'
                            elif uo.get('awaiting_approval'):
                                flags = 'Awaiting Approval'
                            else:
                                if uo.get('editable'):
                                    flags = 'Edit'
                                if uo.get('sharable'):
                                    if flags:
                                        flags = flags + ', '
                                    flags = flags + 'Share'
                            if not flags:
                                flags = 'View'

                            print('{0:>21s} {1} ({2}) {3}'.format('Shared Users:' if no == 0 else '', uo['username'],
                                                                  flags,
                                                                  'self' if uo['username'] == params.user else ''))
                            no = no + 1
                    no = 0
                    if 'shared_folder_permissions' in rec['shares']:
                        for sfo in rec['shares']['shared_folder_permissions']:
                            flags = ''
                            if sfo.get('editable'):
                                flags = 'Edit'
                            if sfo.get('reshareable'):
                                if flags:
                                    flags = flags + ', '
                                flags = flags + 'Share'
                            if not flags:
                                flags = 'View'
                            sf_uid = sfo['shared_folder_uid']
                            for f_uid in find_folders(params, record_uid):
                                if f_uid in params.subfolder_cache:
                                    fol = params.folder_cache[f_uid]
                                    if fol.type in {BaseFolderNode.SharedFolderType,
                                                    BaseFolderNode.SharedFolderFolderType}:
                                        sfid = fol.uid if fol.type == BaseFolderNode.SharedFolderType else fol.shared_folder_uid
                                        if sf_uid == sfid:
                                            print('{0:>21s} {1:<20s}'.format('Shared Folders:' if no == 0 else '',
                                                                             fol.name))
                                            no = no + 1

        if kwargs.get('format') == 'detail':
            if 'shared' in r: print('{0:>20s}: {1:<20s}'.format('Shared', str(r['shared'])))
            if 'client_modified_time' in r:
                dt = datetime.datetime.fromtimestamp(r['client_modified_time'] / 1000.0)
                print('{0:>20s}: {1:<20s}'.format('Last Modified', dt.strftime('%Y-%m-%d %H:%M:%S')))
            if 'revision' in r: print('{0:>20s}: {1:<20s}'.format('Revision', str(r['revision'])))

        if params.breach_watch:
            bw_status = params.breach_watch.get_record_status(params, record_uid)
            if bw_status and 'status' in bw_status:
                status = bw_status['status']
                if status:
                    if status in {'WEAK', 'BREACHED'}:
                        status = 'High-Risk Password'
                    elif status == 'IGNORE':
                        status = 'Ignored'
                    print('{0:>20s}: {1:<20s}'.format('BreachWatch', status))

        print('')

    @staticmethod
    def display_ref(ftype, fvalue, **kwargs):
        # fileRef can hold multiple references - convert single value to list for compatibility
        fvalue = fvalue if isinstance(fvalue, list) else [fvalue]
        params = kwargs.get('params')
        unmask = kwargs.get('unmask', False)
        if ftype == 'fileRef':
            for fuid in fvalue:
                frec = params.record_cache.get(fuid) or {}
                fdat = frec.get('data_unencrypted') or '{}'
                fdic = RecordV3.record_type_to_dict(fdat)
                name = fdic.get('name') or ''
                size = fdic.get('size') or ''
                if isinstance(size, str) and size.isdigit():
                    size = int(size)
                size = HumanBytes.format(size or 0) if isinstance(size, int) else size
                print('{0:>20s}: {1:>22s}   {2:<12s}   {3:<s}'.format(str(ftype), str(fuid), str(size), str(name)))
        elif ftype == 'cardRef':
            for fuid in fvalue:
                frec = params.record_cache.get(fuid) or {}
                fdat = frec.get('data_unencrypted') or '{}'
                fdic = RecordV3.record_type_to_dict(fdat)
                title = RecordV3.get_record_type_title(fdat) or ''
                name = RecordV3.get_record_field_value(fdat, 'text', False) or ''
                card_line = 'Name: ' + name
                card = RecordV3.get_record_field_value(fdat, 'paymentCard', False)
                if isinstance(card, dict):
                    n = card.get('cardNumber') or ''
                    if n and not unmask:
                        n = '*' + n[-4:]
                    e = card.get('cardExpirationDate') or ''
                    c = (card.get('cardSecurityCode') or '') if unmask else '***'
                    card_line += f' | Card: {n} exp:{e} cvv:{c}'
                print('{0:>20s}: {1}'.format('card.' + str(title), card_line))
        elif ftype == 'addressRef':
            for fuid in fvalue:
                frec = params.record_cache.get(fuid) or {}
                fdat = frec.get('data_unencrypted') or '{}'
                fdic = RecordV3.record_type_to_dict(fdat)
                title = RecordV3.get_record_type_title(fdat) or ''
                addr = RecordV3.get_record_field_value(fdat, 'address', False) or '{}'
                addr = addr if isinstance(addr, dict) else RecordV3.record_type_to_dict(addr)
                addr_line = ' | '.join(str(x) for x in addr.values())
                print('{0:>20s}: {1:<s}'.format('address.' + str(title), str(addr_line)))
        else:
            logging.error(
                bcolors.FAIL + 'Unknown field reference type: ' + str(ftype) + ' for ' + str(fvalue) + bcolors.ENDC)

    @staticmethod
    def validate_access(params: KeeperParams, ruid: str):
        if ruid:
            v3_enabled = False
            if params and params.settings and isinstance(params.settings.get('record_types_enabled'), bool):
                v3_enabled = params.settings.get('record_types_enabled')
            if not v3_enabled:
                if params and params.record_cache and ruid in params.record_cache:
                    rv = params.record_cache[ruid].get('version') or None
                    if rv and rv in (3, 4):
                        raise TypeError('Record ' + ruid + ' not found. You don\'t have Record Types enabled.')

    @staticmethod
    def custom_options_to_list(options_list: str) -> list:
        custom = []
        if options_list:
            if type(options_list) == str:
                if options_list[0] == '{' and options_list[-1] == '}':
                    try:
                        custom_json = json.loads(options_list)
                        for k, v in custom_json.items():
                            custom.append({
                                'name': k,
                                'value': str(v)
                            })
                    except ValueError as e:
                        raise TypeError('Invalid custom fields JSON input: {0}'.format(e))
                else:
                    pairs = options_list.split(',')
                    for pair in pairs:
                        idx = pair.find(':')
                        if idx > 0:
                            custom.append({
                                'name': pair[:idx].strip(),
                                'value': pair[idx + 1:].strip()
                            })
                        else:
                            raise TypeError(
                                'Invalid custom fields input. Expected: "Key:Value". Got: "{0}"'.format(pair))

            elif type(options_list) == list:
                for c in options_list:
                    if type(c) == dict:
                        name = c.get('name')
                        value = c.get('value')
                        if name and value:
                            custom.append({
                                'name': name,
                                'value': value
                            })
        return custom


class HumanBytes:
    # Human-readable formatting of bytes, using binary (powers of 1024) or metric (powers of 1000) representation.
    METRIC_LABELS = ["bytes", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    BINARY_LABELS = ["bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"]
    PRECISION_OFFSETS = [0.5, 0.05, 0.005, 0.0005]
    PRECISION_FORMATS = ["{}{:.0f} {}", "{}{:.1f} {}", "{}{:.2f} {}", "{}{:.3f} {}"]

    @classmethod
    def format(cls, num, metric=False, precision=1) -> str:
        assert isinstance(precision, int) and precision >= 0 and precision <= 3, "precision must be an int (range 0-3)"
        unit_labels = cls.METRIC_LABELS if metric else cls.BINARY_LABELS
        last_label = unit_labels[-1]
        unit_step = 1000 if metric else 1024
        unit_step_thresh = unit_step - cls.PRECISION_OFFSETS[precision]

        is_negative = num < 0
        if is_negative:
            num = abs(num)
        if num < unit_step:  # return exact bytes when size is too small
            return cls.PRECISION_FORMATS[0].format('-' if is_negative else '', num, unit_labels[0])
        for unit in unit_labels:
            if num < unit_step_thresh:
                break
            if unit != last_label:
                num /= unit_step
        return cls.PRECISION_FORMATS[precision].format('-' if is_negative else '', num, unit)


def init_recordv3_commands(params):
    from .commands import commands, command_info, aliases
    v3_commands = {}

    def init_v3_commands():
        from .commands.recordv2 import RecordAddCommand, RecordEditCommand, add_parser, edit_parser
        global v3_commands
        if v3_commands:
            return
        v3_commands = {
            'record-type': {},
            'record-type-info': {},
            'add': {
                'substitute': {
                    'command': RecordAddCommand(),
                    'parser': add_parser,
                    'command_info': {add_parser.prog: add_parser.description},
                    'alias': {'a': 'add'}
                }
            },
            'edit': {
                'substitute': {
                    'command': RecordEditCommand(),
                    'parser': edit_parser,
                    'command_info': {edit_parser.prog: edit_parser.description},
                    'alias': {}
                }
            }
        }

    try:
        # parse v3 commands
        init_v3_commands()

        for cmd in v3_commands:
            if not v3_commands[cmd].get('command') and cmd in commands:
                prog = commands[cmd].get_parser().prog
                parts = prog.split('|')
                alias = parts[-1] if len(parts) == 2 else None
                v3_commands[cmd]['command'] = {cmd: commands[cmd]}
                if prog in command_info:
                    v3_commands[cmd]['command_info'] = {prog: command_info[prog]}
                if alias in aliases:
                    v3_commands[cmd]['alias'] = {alias: aliases[alias]}

        v3_enabled = params.settings.get('record_types_enabled') if params.settings and isinstance(
            params.settings.get('record_types_enabled'), bool) else False
        if v3_enabled:

            # add/replace v3 commands
            modified = []
            for cmd in v3_commands:
                cdic = v3_commands[cmd].get('command') or {}
                cname = next(iter(cdic), None)
                cmdc = commands.get(cmd) or 2
                cmdv = ((v3_commands.get(cmd) or {}).get('command') or {}).get(cmd) or 3
                if cname and (cname not in commands or cmdc != cmdv):
                    modified.append(cname)
                    commands[cname] = cdic[cname]
                    ciname = next(iter(v3_commands[cmd].get('command_info') or {}), None)
                    if ciname:
                        command_info[ciname] = v3_commands[cmd]['command_info'][ciname]
                    aname = next(iter(v3_commands[cmd].get('alias') or {}), None)
                    if aname:
                        aliases[aname] = v3_commands[cmd]['alias'][aname]

            # RT activation during live session - only a full sync will pull any pre-existing v3 records
            # full_sync = response_json.get('full_sync') or False
            # if modified and not full_sync:
            #     logging.warning(bcolors.WARNING + 'Record types - enabled. Please logout and login again if you have existing v3 records.' + bcolors.ENDC)
        else:
            # remove/replace v3 commands
            for cmd in v3_commands:
                cdic = v3_commands[cmd].get('command') or {}
                cname = next(iter(cdic), None)
                if cname and cname in commands:
                    subs = v3_commands[cmd].get('substitute')
                    subs = subs if isinstance(subs, dict) else {}
                    sub_class = subs.get('command')
                    if sub_class:
                        commands[cname] = sub_class
                    else:
                        commands.pop(cname)

                    ciname = next(iter(v3_commands[cmd].get('command_info') or {}), None)
                    sub_ciname = next(iter(subs.get('command_info') or {}), None)
                    if ciname:
                        if ciname == sub_ciname:
                            command_info[ciname] = subs['command_info'][sub_ciname]
                        else:
                            command_info.pop(ciname)
                            if sub_ciname and subs['command_info'][sub_ciname]:
                                command_info[sub_ciname] = subs['command_info'][sub_ciname]

                    aname = next(iter(v3_commands[cmd].get('alias') or {}), None)
                    sub_aname = next(iter(subs.get('alias') or {}), None)
                    if aname:
                        if aname == sub_aname:
                            aliases[aname] = subs['alias'][sub_aname]
                        else:
                            aliases.pop(aname)
                            if sub_aname and subs['alias'][sub_aname]:
                                aliases[aname] = subs['alias'][sub_aname]

    except Exception as e:
        logging.debug(e)
