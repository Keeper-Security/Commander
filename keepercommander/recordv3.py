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
import requests.exceptions
import urllib.parse

from requests.models import PreparedRequest

from keepercommander import api
from keepercommander.display import bcolors
from .subfolder import get_folder_path, find_folders, BaseFolderNode
from .record import get_totp_code


class RecordV3:
  """Defines a user-friendly Keeper Record v3 for display purposes"""

  def __init__(self, record_uid='', folder='', title = '', type = '', fields=None, custom_fields=None, notes = '', revision = '', data = ''):
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
      return { 'is_valid': False, 'error': 'Invalid record type JSON' }
    except Exception:
      return { 'is_valid': False, 'error': 'Invalid record type' }

    res = RecordV3.is_valid_record_type_definition(rt_definition_json)
    if not res.get('is_valid'):
      return res
    rtd = json.loads(rt_definition_json)

    # Implicit fields - always present on any record, no need to be specified in the template: title, custom, notes
    rt_type = rt.get('type') or ''
    if not rt_type or not rt_type.strip():
      return False, 'Missing record type type'
    rt_title = rt.get('title') or ''
    if not rt_title or not rt_title.strip():
      return False, 'Missing record type title'

    return { 'is_valid': True, 'error': '' }


  @staticmethod
  def is_valid_record_type_definition(record_type_definition_json: str) -> dict:
    # validate record type (a.k.a. record v3) definition
    # https://github.com/Keeper-Security/record-templates/tree/master/standard_templates

    rt = {}
    try:
      rt = json.loads(record_type_definition_json)
    except ValueError:
      return { 'is_valid': False, 'error': 'Invalid record type JSON' }
    except Exception:
      return { 'is_valid': False, 'error': 'Invalid record type definition' }

    rtid = rt.get('$id') or ''
    if not rtid or not rtid.strip():
      return { 'is_valid': False, 'error': 'Missing record type name' }

    # Min RT definition: {"$id": "Name"} - allows only implicit (custom) fields
    # Max RT definition: {"$id": "Name", "categories": ["note"], "description": "Description", "fields":[]}
    # Implicit fields - always present on any record, no need to be specified in the template: title, custom, notes
    implicit_field_names = [x for x in RecordV3.record_implicit_fields]
    implicit_fields = [r for r in rt if r in implicit_field_names]
    if implicit_fields:
      return { 'is_valid': False, 'error': 'Implicit fields not allowed in record type definition: ' + str(implicit_fields) }

    rt_attributes = ('$id', 'categories', 'description', 'fields')
    bada = [r for r in rt if r not in rt_attributes and r not in implicit_field_names]
    if bada:
      return { 'is_valid': False, 'error': 'Unknown attributes in record type definition: ' + str(bada) }

    # Allow only valid/known field types - field types are case sensitive?
    flds = rt.get('fields') or []
    # Record type definitions without fields are OK? They still have title and custom[]
    # if not flds:
    #   return { 'is_valid': False, 'error': 'Missing fields list' }

    badf = [x for x in flds if not x.get('$ref')]
    if badf:
      return { 'is_valid': False, 'error': 'Missing field type reference (ex. {"$ref": "login"}): ' + str(badf) }

    badf = [x for x in flds if not RecordV3.field_types.__contains__(x.get('$ref'))]
    if badf:
      return { 'is_valid': False, 'error': 'Unknown field types: ' + str(badf) }

    known_ft_atributes = {'$ref', 'label', 'required'}
    unknown_ft_atributes = [x for x in flds if not set(x.keys()).issubset(known_ft_atributes)]
    if unknown_ft_atributes:
      return { 'is_valid': False, 'error': 'Unknown field atributes: ' + str(unknown_ft_atributes) }

    badf = [x for x in flds if not RecordV3.is_valid_field_type_ref(json.dumps(x))]
    if badf:
      return { 'is_valid': False, 'error': 'Invalid field types: ' + str(badf) }

    return { 'is_valid': True, 'error': '' }


  # Implicit fields - The following fields are always present on any record and do not need to be specified in the template:
  record_implicit_fields = {
    'title': '',  # string
    'custom': [], # Array of Field Data objects
    'notes': ''   # string
  }

  record_fields = {
    'title': '',  # string - Record Title
    'type': '',   # string - Record Type (either one of the standard types or a custom type)
    'fields': [], # Array of Field Data objects
    'custom': [], # Array of Field Data objects
    'notes': ''   # string
  }

  # Fields are client-side defined. Fields are defined with a Field Type. All Field Types are fixed.  
  # Meaning, although we may implement new field types, the client cannot arbitrarily add field types,
  # nor display/edit field types that are not pre programmed into the client.  
  # Once the client is updated to understand the new field type, the data may then be displayed and edited. 

  # TODO: translatable labels
  # NB! Allow only one login/password field per v3 record. Allow in custom[] only if RT definition doesn't have them
  # Standard RT definitions: always required - type, title
  record_types = {
    'login': { 'label': 'Login' },
    # def.  {"$id":"login","categories":["login"],"description":"Login template","fields":[{"$ref":"login"},{"$ref":"password"},{"$ref":"url"},{"$ref":"securityQuestion"},{"$ref":"fileRef"},{"$ref":"oneTimeCode"}]}
    # ex.   {"title":"Title","type":"login","fields":[{"type":"login","value":[]},{"type":"password","value":[]},{"type":"url","value":[]},{"type":"securityQuestion","value":[]},{"type":"fileRef","value":[]},{"type":"oneTimeCode","value":[]}],"custom":[]}

    'bankAccount': { 'label': 'Bank Account' }, # { "$ref": "bankAccount", "required": true }
    # def.  {"$id":"bankAccount","description":"Bank account template","fields":[{"$ref":"bankAccount","required":true},{"$ref":"name"},{"$ref":"login"},{"$ref":"password"},{"$ref":"url"},{"$ref":"cardRef"},{"$ref":"fileRef"},{"$ref":"oneTimeCode"}]}
    # ex.   {"title":"Title","type":"bankAccount","fields":[{"type":"bankAccount","value":[{"accountType":"","routingNumber":"","accountNumber":"1234","otherType":""}],"required":true},{"type":"name","value":[{"first":"John","last":"Doe"}]},{"type":"login","value":[]},{"type":"password","value":[]},{"type":"url","value":[]},{"type":"cardRef","value":[]},{"type":"fileRef","value":[]},{"type":"oneTimeCode","value":[]}],"custom":[]}

    'address': { 'label': 'Address' },
    # def.  {"$id":"address","categories":["address"],"description":"Address template","fields":[{"$ref":"address"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"address","fields":[{"type":"address","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

    'bankCard': { 'label': 'Payment Card' },
    # def.  {"$id":"bankCard","categories":["payment"],"description":"Bank card template","fields":[{"$ref":"paymentCard"},{"$ref":"text","label":"cardholderName"},{"$ref":"pinCode"},{"$ref":"addressRef"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"bankCard","fields":[{"type":"paymentCard","value":[]},{"type":"text","label":"Cardholder Name","value":[]},{"type":"pinCode","value":[]},{"type":"addressRef","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

    'birthCertificate': { 'label': 'Birth Certificate' },
    # def.  {"$id":"birthCertificate","categories":["ids"],"description":"Birth certificate template","fields":[{"$ref":"name"},{"$ref":"birthDate"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"birthCertificate","fields":[{"type":"name","value":[]},{"type":"birthDate","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

    'contact': { 'label': 'Contact' }, # { "$ref": "name", "required": true }
    # def.  {"$id":"contact","categories":["address"],"description":"Contact template","fields":[{"$ref":"name","required":true},{"$ref":"text","label":"company"},{"$ref":"email"},{"$ref":"phone"},{"$ref":"addressRef"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"contact","fields":[{"type":"name","value":[{"first":"John","last":"Doe"}],"required":true},{"type":"text","label":"Company","value":[]},{"type":"email","value":[]},{"type":"phone","value":[]},{"type":"addressRef","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

    'driverLicense': { 'label': 'Driver\'s License' },
    # def.  {"$id":"driverLicense","categories":["ids"],"description":"Driver license template","fields":[{"$ref":"accountNumber","label":"dlNumber"},{"$ref":"name"},{"$ref":"birthDate"},{"$ref":"addressRef"},{"$ref":"expirationDate"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"driverLicense","fields":[{"type":"accountNumber","label":"Driver's License Number","value":[]},{"type":"name","value":[]},{"type":"birthDate","value":[]},{"type":"addressRef","value":[]},{"type":"expirationDate","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

    'encryptedNotes': { 'label': 'Secure Note' },
    # def.  {"$id":"encryptedNotes","categories":["note"],"description":"Encrypted note template","fields":[{"$ref":"note"},{"$ref":"date"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"encryptedNotes","fields":[{"type":"note","value":[]},{"type":"date","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

    'file': { 'label': 'File Attachment' },
    # def.  {"$id":"file","categories":["file"],"description":"File template","fields":[{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"file","fields":[{"type":"fileRef","value":[]}],"custom":[]}

    'healthInsurance': { 'label': 'Health Insurance' },
    # def.  {"$id":"healthInsurance","categories":["ids"],"description":"Health insurance template","fields":[{"$ref":"accountNumber"},{"$ref":"name","label":"insuredsName"},{"$ref":"login"},{"$ref":"password"},{"$ref":"url"},{"$ref":"fileRef"},{"$ref":"securityQuestion"}]}
    # ex.   {"title":"Title","type":"healthInsurance","fields":[{"type":"accountNumber","value":[]},{"type":"name","label":"Insured's Name","value":[]},{"type":"login","value":[]},{"type":"password","value":[]},{"type":"url","value":[]},{"type":"fileRef","value":[]},{"type":"securityQuestion","value":[]}],"custom":[]}

    'membership': { 'label': 'Membership' },
    # def.  {"$id":"membership","categories":["ids"],"description":"Membership template","fields":[{"$ref":"accountNumber"},{"$ref":"name"},{"$ref":"password"},{"$ref":"fileRef"},{"$ref":"securityQuestion"}]}
    # ex.   {"title":"Title","type":"membership","fields":[{"type":"accountNumber","value":[]},{"type":"name","value":[]},{"type":"password","value":[]},{"type":"fileRef","value":[]},{"type":"securityQuestion","value":[]}],"custom":[]}

    'passport': { 'label': 'Passport' },
    # def.  {"$id":"passport","categories":["ids"],"description":"Passport template","fields":[{"$ref":"accountNumber","label":"passportNumber"},{"$ref":"name"},{"$ref":"birthDate"},{"$ref":"addressRef"},{"$ref":"expirationDate"},{"$ref":"date","label":"dateIssued"},{"$ref":"password"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"passport","fields":[{"type":"accountNumber","label":"Passport Number","value":[]},{"type":"name","value":[]},{"type":"birthDate","value":[]},{"type":"addressRef","value":[]},{"type":"expirationDate","value":[]},{"type":"date","label":"Date Issued","value":[]},{"type":"password","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

    'photo': { 'label': 'Photo' },
    # def.  {"$id":"photo","categories":["file"],"description":"Photo template","fields":[{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"photo","fields":[{"type":"fileRef","value":[]}],"custom":[]}

    'serverCredentials': { 'label': 'Server' },
    # def.  {"$id":"serverCredentials","categories":["login"],"description":"Server credentials template","fields":[{"$ref":"host"},{"$ref":"login"},{"$ref":"password"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"serverCredentials","fields":[{"type":"host","value":[]},{"type":"login","value":[]},{"type":"password","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

    'softwareLicense': { 'label': 'Software License' },
    # def.  {"$id":"softwareLicense","categories":["note"],"description":"Software license template","fields":[{"$ref":"licenseNumber"},{"$ref":"expirationDate"},{"$ref":"date","label":"dateActive"},{"$ref":"fileRef"},{"$ref":"securityQuestion"}]}
    # ex.   {"title":"Title","type":"softwareLicense","fields":[{"type":"licenseNumber","value":[]},{"type":"expirationDate","value":[]},{"type":"date","label":"Date Active","value":[]},{"type":"fileRef","value":[]},{"type":"securityQuestion","value":[]}],"custom":[]}

    'ssnCard': { 'label': 'Identity Card' },
    # def.  {"$id":"ssnCard","categories":["ids"],"description":"Identity card template","fields":[{"$ref":"accountNumber","label":"identityNumber"},{"$ref":"name"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"ssnCard","fields":[{"type":"accountNumber","label":"Identity Number","value":[]},{"type":"name","value":[]},{"type":"fileRef","value":[]}],"custom":[]}

    'general': { 'label': 'Legacy Record' },
    # def.  {"$id":"general","categories":["login"],"description":"Legacy template","fields":[{"$ref":"login"},{"$ref":"password"},{"$ref":"url"},{"$ref":"oneTimeCode"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"general","fields":[{"type":"login","value":[]},{"type":"password","value":[]},{"type":"url","value":[]},{"type":"oneTimeCode","value":[]},{"type":"fileRef","value":[]}],"custom":[],"notes":""}

    'sshKeys': { 'label': 'SSH Key' },
    # def.  {"$id":"sshKeys","categories":["login"],"description":"SSH key template","fields":[{"$ref":"login"},{"$ref":"keyPair"},{"$ref":"text","label":"passphrase"},{"$ref":"host"},{"$ref":"fileRef"},{"$ref":"securityQuestion"}]}
    # ex.   {"title":"Title","type":"sshKeys","fields":[{"type":"login","value":[]},{"type":"keyPair","value":[]},{"type":"text","label":"Passphrase","value":[]},{"type":"host","value":[]},{"type":"fileRef","value":[]},{"type":"securityQuestion","value":[]}],"custom":[]}

    'databaseCredentials': { 'label': 'Database' }
    # def.  {"$id":"databaseCredentials","categories":["login"],"description":"Database credentials template","fields":[{"$ref":"text","label":"type"},{"$ref":"host"},{"$ref":"login"},{"$ref":"password"},{"$ref":"fileRef"}]}
    # ex.   {"title":"Title","type":"databaseCredentials","fields":[{"type":"text","label":"Type","value":[]},{"type":"host","value":[]},{"type":"login","value":[]},{"type":"password","value":[]},{"type":"fileRef","value":[]}],"custom":[]}
  }

  # A field definition consists from:
  #   $id - ex. 'title', used to reference the field definitions and to translate the field labels
  #   type|$type - used to tell the UI how to render and edit the field
  #   lookup - optional flag: lookup values are shared based on the field reference. 
  #     ex. all 'login' fields will share the same set of lookup values but will not see the lookup values from 'company' field
  #   multiple - optional flag: If specified, the UI should allow populating multiple instances of the filed on the record
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
    }
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
      'value': '' # string
    },
    'url': {
      'type': 'url',
      'value_description': 'url string, can be clicked',
      'value': '' # string
    },
    'multiline': {
      'type': 'multiline',
      'value_description': 'multiline text',
      'value': '' # string
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
      'value': '' # string (record v4 UID)
    },
    'email': {
      'type': 'email',
      'value_description': 'valid email address plus tag',
      'value': '' # string
    },
    'host': {
      'type': 'host',
      'value_description': 'multiple fields to capture host information',
      'value': {        # object
        'hostName': '', # string
        'port': ''      # string
      }
    },
    'phone': {
      'type': 'phone',
      'value_description': 'numbers and symbols only plus tag',
      'value': {      # object
        'region': '', # string
        'number': '', # string
        'ext': '',    # string
        'type': ('Mobile', 'Home', 'Work')
      }
    },
    'name': {
      'type': 'name',
      'value_description': 'multiple fields to capture name',
      'value': {          # object
        'first': '',  # string
        'middle': '', # string
        'last': ''    # string
      },
      'required': ['first', 'last'] # required parts of field value - enforced only when RT specify that field is required
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
      'value': {        # object
        'street1': '',  # string
        'street2': '',  # string
        'city': '',     # string
        'state': '',    # string
        'zip': '',      # string
        'country': ''   # string
      }
    },
    'addressRef': {
      'type': 'addressRef',
      'value_description': 'reference to the address field on another record',
      'value': '' # string
    },
    'cardRef': {
      'type': 'cardRef',
      'value_description': 'reference to the bankCard field on another record',
      'value': '' # string (record UID)
    },
    'secret': {
      'type': 'secret',
      'value_description': 'the field value is masked',
      'value': '' # string
    },
    'login': {
      'type': 'login',
      'value_description': 'Login field, detected as the website login for browser extension or KFFA.',
      'value': '' # string?
    },
    'password': {
      'type': 'password',
      'value_description': 'Field value is masked and allows for generation. Also complexity enforcements.',
      'value': '' # string
    },
    'securityQuestion': {
      'type': 'securityQuestion',
      'value_description': 'Security Question and Answer',
      'value': {        # object
        'question': '', # string
        'answer': ''    # string
      }
    },
    'otp': {
      'type': 'otp',
      'value_description': 'captures the seed, displays QR code',
      'value': '' # string
    },
    'paymentCard': {
      'type': 'paymentCard',
      'value_description': 'Field consisting of validated card number, expiration date and security code.',
      'value': {                    # object
          'cardNumber': '',         # string
          'cardExpirationDate': '', # string
          'cardSecurityCode': ''    # string
        }
    },
    'date': {
      'type': 'date',
      'value_description': 'calendar date with validation, stored as unix milliseconds',
      'value': 0 # number (long)
    },
    'bankAccount': {
      'type': 'bankAccount',
      'value_description': 'bank account information',
      'value': {              # object
        'accountType': ('Checking', 'Savings', 'Other'),
        'otherType': '',      # string
        'routingNumber': '',  # string
        'accountNumber': ''   # string (required for RT bankAccount)
      },
      'required': ['accountNumber'] # required parts of field value - enforced only when RT specify that field is required
    },
    'privateKey': {
      'type': 'privateKey',
      'value_description': 'private key in ASN.1 format',
      'value': '' # string (PEM encoded)
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
      try: ft_dict = json.loads(field_json)
      except: ft_dict = {}

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
            results = results and (isinstance(fv, int) or bool(re.match('^\s*[-+]?\s*\d+\s*$', str(fv))))
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
                res = res and (isinstance(val2, int) or bool(re.match('^\s*[-+]?\s*\d+\s*$', str(val2))))
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
  def is_valid_field_type_ref(cls, field_type_json):
    # field ref inside record type definition - ex. {"$ref":"name", "required":true, "label":"placeName"}
    # 2021-04-26 currently the only used options in field ref are - $ref, label, requried
    result = False
    if field_type_json:
      try: ft = json.loads(field_type_json)
      except: ft = {}
      ref = ft.get('$ref')
      result = RecordV3.is_valid_field_type(ref)

      known_keys = ('$ref', 'label', 'required')
      unknown_keys = [x for x in ft if x.lower() not in known_keys]
      if unknown_keys:
        logging.warning('Unknown attributes in field reference: ' + str(unknown_keys))

    return result


  @classmethod
  def is_valid_field_type_data(cls, field_type_json):
    # field data inside record type - ex. {"type":"name","value":[{"first":"John","last":"Doe"}],"required":true, "label":"personName"}
    # 2021-04-26 currently the only used options in fields are - type, label, requried, value[]
    result = False
    if field_type_json:
      try: ft = json.loads(field_type_json)
      except: ft = {}
      ref = ft.get('$ref')
      result = True if ref and cls.field_types.get(ref) else False

      known_keys = ('$ref', 'label', 'requried')
      unknown_keys = [x for x in ft if x.lower() not in known_keys]
      if unknown_keys:
        logging.warning('Unknown keys in field reference: ' + str(unknown_keys))
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
                    for k,v in custom_json.items():
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
                            'value': pair[idx+1:].strip()
                        })
                    else:
                        error = 'Invalid custom fields input for {0}. Expected: "Key:Value". Got: "{1}"'.format(custom_list, pair)
        elif type(custom_list) == list:
            for c in custom_list:
                if type(c) == dict:
                    name = c.get('name')
                    value = c.get('value')
                    if name and value:
                        custom.append({ 'name': name, 'value': value })
    result = { 'custom_list': custom, 'error': error }
    return result


  @staticmethod
  def change_record_type(params, rt_data, new_rt_name):
    from keepercommander.commands.recordv3 import RecordGetRecordTypes
    # Converts rt_data (dict or JSON) from one valid record type to another
    # by moving required fields between fields[] and custom[]

    result = {
      'errors': [],
      'warnings': [],
      'record': {}
    }

    r = rt_data if isinstance(rt_data, dict) else {}
    if isinstance(rt_data, str) or isinstance(rt_data, bytes):
      try: r = json.loads(rt_data)
      except: result['errors'].append('Unable to parse record type data JSON: ' + str(rt_data))

    newrtd = {}
    rt_def = RecordGetRecordTypes().resolve_record_type_by_name(params, new_rt_name)
    if rt_def:
      try: newrtd = json.loads(rt_def)
      except: result['errors'].append('Unable to parse record type definition JSON: ' + str(rt_def))
    else:
      result['errors'].append('Record type definition not found for type: ' + str(new_rt_name))
    if result['errors']: return result

    rt = copy.deepcopy(r)
    newf = newrtd.get('fields') or []
    newf = [x.get('$ref') for x in newf if isinstance(x, dict)]
    flds = rt.get('fields') or []
    cust = rt.get('custom') or []

    keep = [x for x in flds if isinstance(x, dict) and x.get('type') in newf]
    move = [x for x in flds if isinstance(x, dict) and x.get('type') not in newf]
    del flds[:]
    flds.extend(keep)
    cust.extend(move)

    cmove = [x for x in cust if isinstance(x, dict) and x.get('type') in newf]
    ckeep = [x for x in cust if isinstance(x, dict) and x.get('type') not in newf]
    cset = {x.get('type') for x in cmove if isinstance(x, dict) and x.get('type')}
    # move only first/one instance per field type
    cmoved = []
    for x in cmove:
      if x.get('type') in cset:
        cmoved.append(x)
        cset.remove(x.get('type'))
      else:
        ckeep.append(x)
    del cust[:]
    flds.extend(cmoved)
    cust.extend(ckeep)

    rt['fields'] = flds
    rt['custom'] = cust
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
      try: rt = json.loads(rt_json or '{}')
      except: result['errors'].append('Unable to parse record type JSON: ' + str(rt_json))

    rtdef = {}
    if rt_def:
      try: rtdef = json.loads(rt_def)
      except: result['errors'].append('Unable to parse record type definition JSON: ' + str(rt_def))
    if result['errors']: return result

    options = kwargs.get('option') or []
    opts = [(x or '').split("=", 1) for x in options]
    if not options:
      return result

    # normalize prefixes: f. -> fields., c. -> custom.
    # so f.name.first is treated as duplicate of fields.name.first
    for x in opts:
      if x and x[0]:
        x[0] = re.sub('^\s*fields\.', 'fields.', x[0], 1, flags=re.IGNORECASE)
        x[0] = re.sub('^\s*custom\.', 'custom.', x[0], 1, flags=re.IGNORECASE)
        x[0] = re.sub('^\s*f\.', 'fields.', x[0], 1, flags=re.IGNORECASE)
        x[0] = re.sub('^\s*c\.', 'custom.', x[0], 1, flags=re.IGNORECASE)

    # check for duplicate keys or keys with more than one value
    dupes = [x for x in opts if x and len(x) != 2] # keys with multiple values
    if dupes:
      result['errors'].append('Found keys with multiple values: ' + str(dupes))
    groups = {} # duplicate key(s)
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
      result['errors'].append('Record types "type" is requried')
    if rt_fields or rt_custom:
      result['errors'].append('Array types fields[] and custom[] cannot be assigned directly')
    if result['errors']: return result

    # Top level RT options - unknown attribute(s) generate error
    # All known attribute(s) /from RT definition/ generate а warning and are silently ignored
    tlo = [x for x in opts if x and not x[0].__contains__('.')]
    ignored = ('$id', 'categories', 'description', 'label') # these are in RT definitions only
    ilist = [x for x in tlo if x and x[0] in ignored]
    if ilist:
      tlo = [x for x in tlo if x not in ilist]
      result['warnings'].append('Removed record type attributes that should be present in record type definitions only: ' + str(ilist))

    ulist = [x for x in tlo if x and x[0].strip() not in ('type', 'title', 'notes')]
    if ulist:
      result['errors'].append('Unknown top level attributes: ' + str(ulist))

    # field type options - ex. -o field.name.first=Jane -o f.name.last=Doe
    flo = [x for x in opts if x and x[0].__contains__('.')]

    # All fields must be either in fields[] or custom[] arrays
    badg = [x for x in flo if x[0].split('.', 1)[0].strip().lower() not in ('fields', 'custom') ]
    if badg:
      result['errors'].append('Unknown field group (not fields[] and not custom[]): ' + str(badg))

    # Allow only valid/known field types - field types are case sensitive?
    badf = [x for x in flo if not RecordV3.field_types.__contains__(x[0].split('.', 2)[1].strip())]
    if badf:
      result['errors'].append('Unknown field types: ' + str(badf))
    if result['errors']: return result

    # only one FT of type password allowed in record v3
    pwds = [x for x in flo if x and x[0].startswith(('fields.password','f.password','custom.password','c.password'))]
    if len(pwds) > 1:
      result['errors'].append('Error: Only one password allowed per record! ' + str(pwds))
    elif len(pwds) == 1:
      rtdp = next((True for x in (rtdef.get('fields') or []) if '$ref' in x and x.get('$ref') == 'password'), False)
      pwdc = pwds[0][0] and pwds[0][0].lower().startswith('custom.')
      if rtdp:
        if pwdc: result['errors'].append('Password must be in fields[] section as defined by record type! ' + str(pwds))
      else:
        if not pwdc: result['errors'].append('Password must be in custom[] section - record type does not allow password in fields[]! ' + str(pwds))
    if result['errors']: return result

    # All fields with prefix f./fields. must be in record type definition
    # Don't move f./fileds. not in RT definition to custom[] - undefined order on duplicates, might break scripts
    rtdf = [x.get('$ref') for x in (rtdef.get('fields') or []) if '$ref' in x]
    flds = [x for x in flo if x and x[0].startswith(('fields.','f.'))]
    cust = [x for x in flo if x and x[0].startswith(('custom.','c.'))]
    badf = [x for x in flds if not x[0].split('.', 2)[1].strip() in rtdf]
    if badf:
      result['errors'].append('This record type doesn\'t allow "fields." prefix for these (move to custom): ' + str(badf))
    # fileRef must use upload-attachment/delete-attachment commands instead
    refs = [x for x in flds + cust if x[0].split('.', 2)[1].strip().lower() == 'fileref']
    if refs:
      result['errors'].append('File reference manipulations are disabled here. Use upload-attachment/delete-attachment commands instead.' + str(refs))
    if result['errors']: return result

    # edit command: JSON validation before update
    # add command: fields[] must contain all 'requried' fields (and requried value parts)
    if not is_edit:
      reqd = [x.get('$ref') for x in (rtdef.get('fields') or []) if '$ref' in x and 'required' in x]
      for fld in reqd:
        ft = (RecordV3.field_types.get(fld) or {}).get('type')
        ftr = (RecordV3.field_values.get(ft) or {}).get('required') or []
        if ftr:
          ftr = ['fields.' + fld + '.' + x for x in ftr]
          flon = [x[0] for x in flo if x and x[0]]
          ftrm = [x for x in ftr if x not in flon]
          if ftrm:
            result['errors'].append('Missing requried fields: ' + str(ftrm))
        else:
          result['warnings'].append('Couldn\'t find requried fields for filed type: ' + str(ft))
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
      r = copy.deepcopy(rt) # for edited or deleted items
      if not r: r = { 'type': rt_type } # add command
      if rt_title: r['title'] = rt_title
      if is_edit and rt_title == '': r['title'] = '' # edit: delete title
      if rt_notes: r['notes'] = rt_notes
      if is_edit and rt_notes == '': r['notes'] = '' # edit: delete notes
      if not 'fields' in r: r['fields'] = []
      if not 'custom' in r: r['custom'] = []
      for lst in [flds, cust]:
        for f in lst:
          if f and len(f) == 2:
            val = f[1]
            path = f[0].split('.')
            forc = path[0].strip() if path else '' # fields or custom
            fname = path[1].strip() if path and len(path) > 1 else ''  # field name
            fvname = path[2].strip() if path and len(path) > 2 else '' # field attribute (if any)
            if fname:
              if not forc in r: r[forc] = [] # create fields[] or custom[]
              fv = next((x for x in r[forc] if isinstance(x, dict) and x.get('type') == fname), {})
              if not fv:
                fv = { 'type': fname, 'value': [] }
                r[forc].append(fv)
              if not 'value' in fv: fv['value'] = []
              if fvname:
                # NB! required:true/false comes from RT definition and should not be re/set here
                if fvname.lower() == 'required':
                  result['warnings'].append('Skipped "required" field attribute which comes from record type definition and should not be set here! ' + str(f))
                  continue
                # check if fvname is FT attribute vs FT value object parts - ex. c.name.label vs. c.name.first
                if fvname.lower() == 'label':
                  fv['label'] = val
                elif is_edit and not val: # delete
                  if forc in r:
                    v = next((x.get('value') or [] for x in r[forc] if isinstance(x, dict) and x.get('type') == fname), [])
                    # v = next((x for x in v if isinstance(x, dict) and fvname in x), {})
                    v = next((x for x in v if isinstance(x, dict)), {})
                    v.pop(fvname, None)
                elif bool(val):  # upsert
                  # v = next((x for x in fv['value'] if isinstance(x, dict) and fvname in x), None)
                  v = next((x for x in fv['value'] if isinstance(x, dict)), None)
                  if v: v[fvname] = val
                  else: fv['value'].append({fvname: val})
                  ok = RecordV3.is_valid_field_value(fname, [{fvname: val}])
                  if not ok: result['errors'].append('Invalid field value: ' + str({fname: [{fvname: val}]}))
                else:
                  result['warnings'].append('Skipped empty field value: ' + str(f))
              else: # simple value str/int assign directly - ex. c.login=MyLogin
                if bool(val):
                  del fv['value'][:]
                  fv['value'].append(val)
                elif 'value' in fv and isinstance(fv['value'], list): # delete
                  del fv['value'][:]
          else:
            result['errors'].append('Miltiple field values per single option aren\'t allowed. Use multiple options: -o f.name.first=A -o f.name.last=B ' + str(f))

    if r and not result['errors']:
      if not r.get('custom'): r.pop('custom', None)
      if not r.get('fields'): r.pop('fields', None)
      rt = r

    if not result['errors']:
      result['record'] = rt

    return result

  @staticmethod
  def convert_to_record_type(record_uid, params):
    # Converts records v2 to v3
    result = False

    if not (record_uid and params and params.record_cache and record_uid in params.record_cache):
      logging.error(bcolors.FAIL + 'Record %s not found.' + bcolors.ENDC, record_uid)
      return result

    record = params.record_cache[record_uid]
    version = record.get('version') or 0
    if version != 2:
      logging.error(bcolors.FAIL + 'Record %s is not version 2.' + bcolors.ENDC, record_uid)
      return result

    udata = record.get('udata')
    data = record.get('data_unencrypted')
    extra = record.get('extra_unencrypted')
    # extra contains: files, fields, (favicon_url - deprecated, smartfill - deprecated)

    udata = udata if isinstance(udata, dict) else json.loads(udata or '{}')
    data = data if isinstance(data, dict) else json.loads(data or '{}')
    extra = extra if isinstance(extra, dict) else json.loads(extra or '{}')

    file_ids = udata.get('file_ids') or []
    files = extra.get('files') or []
    has_files = len(file_ids) > 0 or len(files) > 0
    if has_files:
      logging.error(bcolors.FAIL + 'Record %s has file atachments. Not convertible.' + bcolors.ENDC, record_uid)
      return result

    # check for other non-convertible data - ex. fields[] has "field_type" != "totp" if present
    fields = extra.get('fields') or []
    otps = [x for x in fields if 'totp' == (x.get('field_type') or '')]
    if bool(data.get('folder')) or len(fields) != len(otps):
      logging.error(bcolors.FAIL + 'Record %s has unknown extra fields.' + bcolors.ENDC, record_uid)
      return result

    otp = otps[0] if otps else {}
    totp = otp.get('data') or ''
    # label = otp.get('field_title') or ''

    title = data.get('title') or ''
    login = data.get('secret1') or ''
    password = data.get('secret2') or ''
    url = data.get('link') or ''

    notes = data.get('notes') or ''
    custom2 = data.get('custom') or []
    # custom.type	- Always "text" for legacy reasons.
    custom = [ {
      'type': 'text',
      'label': x.get('name') or '',
      'value': [x.get('value')] if x.get('value') else []
    } for x in custom2 if x.get('name') or x.get('value') ]

    # Add any remaining TOTP codes to custom[]
    if len(otps) > 1:
      otps.pop(0)
      otp2 = [ {
        'type': 'oneTimeCode',
        'value': [x.get('data')]
      } for x in otps if x.get('data') ]
      if otp2: custom.extend(otp2)

    rt = {
      'title': title,
      'type': 'general',
      'fields': [
        { 'type': 'login', 'value': [login] if login else []},
        { 'type': 'password', 'value': [password] if password else []},
        { 'type': 'url', 'value': [url] if url else []},
        { 'type': 'oneTimeCode', 'value': [totp] if totp else [] },
        { 'type': 'fileRef', 'value': []}
      ],
      'custom': custom,
      'notes': notes
    }

    record['version'] = 3
    record.pop('udata', None)
    record.pop('extra', None)
    record.pop('extra_unencrypted', None)
    record['data_unencrypted'] = json.dumps(rt)
    record['client_modified_time'] = api.current_milli_time()
    result = True
    return result


  @staticmethod
  def get_field_types():
    ftypes = [ { **RecordV3.field_types.get(fkey), **RecordV3.field_values.get(vkey) }
        for fkey in RecordV3.field_types
          for vkey in RecordV3.field_values
            if (RecordV3.field_types.get(fkey) or {}).get('type') == vkey
    ]
    rows = [] # (id, type, lookup, multiple, description)
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
    ftypes = [ { **RecordV3.field_types.get(fkey), **RecordV3.field_values.get(vkey) }
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
          else '_value' if isinstance(val[x], str)
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
        else '_value' if vtype == 'string'
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
  def display(r, **kwargs):
    ruid = r['record_uid']
    print('')
    # print('{0:>20s}: https://keepersecurity.com/vault#detail/{1}'.format('Link', ruid))
    print('{0:>20s}: {1:<20s}'.format('UID', ruid))
    if 'version' in r: print('{0:>20s}: {1:<20s}'.format('Version', str(r['version'])))
    params = None
    if 'params' in kwargs:
        params = kwargs['params']
        folders = [get_folder_path(params, x) for x in find_folders(params, ruid)]
        for i in range(len(folders)):
            print('{0:>21s} {1:<20s}'.format('Folder:' if i == 0 else '', folders[i]))

    if 'shared' in r: print('{0:>20s}: {1:<20s}'.format('Shared', str(r['shared'])))
    if 'client_modified_time' in r:
      dt = datetime.datetime.fromtimestamp(r['client_modified_time']/1000.0)
      print('{0:>20s}: {1:<20s}'.format('Last Modified', dt.strftime('%Y-%m-%d %H:%M:%S')))
    if 'revision' in r: print('{0:>20s}: {1:<20s}'.format('Revision', str(r['revision'])))

    data = {}
    if 'data_unencrypted' in r:
      data = r['data_unencrypted'].decode() if isinstance(r['data_unencrypted'], bytes) else r['data_unencrypted']
      data = json.loads(data)
    fields = data.get('fields') or []
    custom = data.get('custom') or []
    
    print('{0:>20s}: {1:<20s}'.format('Type', str(data['type']) if 'type' in data else ''))
    print('{0:>20s}: {1:<20s}'.format('Title', str(data['title']) if 'title' in data else ''))
    # NB! General notes here - fields[] might provide their own notes
    if 'notes' in data: print('{0:>20s}: {1:<20s}'.format('Notes', str(data['notes'])))
    # fields[] * print Field# NN - atrib: value

    for c in fields + custom:
      if not 'type' in c: c['type'] = ''
      if not 'value' in c: c['value'] = ''
      print('{0:>20s}: {1:<s}'.format(str(c['type']), str(c['value'])))

    # if self.notes:
    #     lines = self.notes.split('\n')
    #     for i in range(len(lines)):
    #         print('{0:>21s} {1}'.format('Notes:' if i == 0 else '', lines[i].strip()))

    # if self.attachments:
    #     for i in range(len(self.attachments)):
    #         atta = self.attachments[i]
    #         size = atta.get('size') or 0
    #         scale = 'b'
    #         if size > 0:
    #             if size > 1000:
    #                 size = size / 1024
    #                 scale = 'Kb'
    #             if size > 1000:
    #                 size = size / 1024
    #                 scale = 'Mb'
    #             if size > 1000:
    #                 size = size / 1024
    #                 scale = 'Gb'
    #         sz = '{0:.2f}'.format(size).rstrip('0').rstrip('.')
    #         print('{0:>21s} {1:<20s} {2:>6s}{3:<2s} {4:>6s}: {5}'.format('Attachments:' if i == 0 else '',
    #                                                                       atta.get('title') or atta.get('name'),
    #                                                                       sz, scale, 'ID',
    #                                                                       atta.get('id')))

    totp = next((t.get('value') for t in fields if t['type'] == 'oneTimeCode'), None)
    totp = totp[0] if totp else totp
    if totp:
      code, remain, _ = get_totp_code(totp)
      if code: print('{0:>20s}: {1:<20s} valid for {2} sec'.format('Two Factor Code', code, remain))

    # if params is not None:
    #     if self.record_uid in params.record_cache:
    #         rec = params.record_cache[self.record_uid]
    #         if 'shares' in rec:
    #             no = 0
    #             if 'user_permissions' in rec['shares']:
    #                 perm = rec['shares']['user_permissions'].copy()
    #                 perm.sort(key=lambda r: (' 1' if r.get('owner') else ' 2' if r.get(
    #                     'editable') else ' 3' if r.get('sharable') else '') + r.get('username'))
    #                 for uo in perm:
    #                     flags = ''
    #                     if uo.get('owner'):
    #                         flags = 'Owner'
    #                     elif uo.get('awaiting_approval'):
    #                         flags = 'Awaiting Approval'
    #                     else:
    #                         if uo.get('editable'):
    #                             flags = 'Edit'
    #                         if uo.get('sharable'):
    #                             if flags:
    #                                 flags = flags + ', '
    #                             flags = flags + 'Share'
    #                     if not flags:
    #                         flags = 'View'

    #                     print('{0:>21s} {1} ({2}) {3}'.format('Shared Users:' if no == 0 else '', uo['username'],
    #                                                           flags,
    #                                                           'self' if uo['username'] == params.user else ''))
    #                     no = no + 1
    #             no = 0
    #             if 'shared_folder_permissions' in rec['shares']:
    #                 for sfo in rec['shares']['shared_folder_permissions']:
    #                     flags = ''
    #                     if sfo.get('editable'):
    #                         flags = 'Edit'
    #                     if sfo.get('reshareable'):
    #                         if flags:
    #                             flags = flags + ', '
    #                         flags = flags + 'Share'
    #                     if not flags:
    #                         flags = 'View'
    #                     sf_uid = sfo['shared_folder_uid']
    #                     for f_uid in find_folders(params, self.record_uid):
    #                         if f_uid in params.subfolder_cache:
    #                             fol = params.folder_cache[f_uid]
    #                             if fol.type in {BaseFolderNode.SharedFolderType,
    #                                             BaseFolderNode.SharedFolderFolderType}:
    #                                 sfid = fol.uid if fol.type == BaseFolderNode.SharedFolderType else fol.shared_folder_uid
    #                                 if sf_uid == sfid:
    #                                     print('{0:>21s} {1:<20s}'.format('Shared Folders:' if no == 0 else '',
    #                                                                       fol.name))
    #                                     no = no + 1

    print('')

  @staticmethod
  def get_audit_url(url: str) -> str:
    # aduit URLs should be stripped of '<scheme>://' and '?<query>' components
    clean_url = ''
    if url:
        try:
            # validate URL
            purl = url
            try:
                PreparedRequest().prepare_url(purl, None)
            except requests.exceptions.MissingSchema:
                purl = 'http://' + url # NB! makes ~90% of random texts valid URLs
                PreparedRequest().prepare_url(purl, None)
            # valid URL - strip scheme and query only
            url_parts = urllib.parse.urlparse(purl)
            stripped = ('', *url_parts[1:4], '', url_parts[5])
            clean_url = urllib.parse.urlunparse(stripped).replace('//', '', 1)
        except:
            clean_url = ''
        if not clean_url:
            clean_url = url[0:80] if url else ''
    return clean_url


