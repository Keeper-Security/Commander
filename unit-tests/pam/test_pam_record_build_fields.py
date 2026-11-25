"""Batch record builder (`pam_record_build`) against the sequential import: field specs and dropped-field messages."""
import logging
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

from keepercommander.commands.pam_import.base import (
    PamMachineObject,
    PamRotationParams,
    PamUserObject,
)
from keepercommander.commands.pam_import.pam_record_build import build_record_add_kwargs, pam_object_to_typed_record

CFG = 'CCCCCCCCCCCCCCCCCCCCCA'
FOLDER = 'FFFFFFFFFFFFFFFFFFFFFA'


def machine(**over):
    data = {'type': 'pamMachine', 'title': 'M1', 'host': 'h.example', 'port': '22', 'operating_system': 'Linux'}
    data.update(over)
    return PamMachineObject.load(data, PamRotationParams(configUid=CFG, profiles={}))


class TestPamUserCustomFields(unittest.TestCase):
    def test_custom_fields_are_written_like_the_sequential_import(self):
        user = PamUserObject.load(
            {'type': 'pamUser', 'title': 'u1', 'login': 'u1', 'password': 'p',
             'custom': [{'type': 'text', 'label': 'Team', 'value': 'ops'},
                        {'type': 'text', 'label': 'a=b', 'value': '=x'}]},
            PamRotationParams(configUid=CFG, profiles={}))
        fields = build_record_add_kwargs(user, FOLDER)['fields']
        self.assertIn('c.text.Team=ops', fields)
        self.assertIn('c.text.a==b= =x', fields)

    def test_no_custom_list_adds_nothing(self):
        user = PamUserObject.load({'type': 'pamUser', 'title': 'u1', 'login': 'u1'},
                                  PamRotationParams(configUid=CFG, profiles={}))
        self.assertFalse([f for f in build_record_add_kwargs(user, FOLDER)['fields'] if f.startswith('c.')])


class TestDroppedFieldsAreLogged(unittest.TestCase):
    TEMPLATE = [{'$ref': 'pamHostname'}, {'$ref': 'trafficEncryptionSeed'}]      # no operatingSystem, no checkbox

    def build(self, obj):
        with patch('keepercommander.commands.pam_import.pam_record_build.RecordEditAddCommand.get_record_type_fields',
                   return_value=self.TEMPLATE), \
                patch('keepercommander.commands.pam_import.tunnel_setup.ensure_traffic_encryption_seed_on_typed_record'), \
                patch('keepercommander.commands.pam_import.tunnel_setup.merge_initial_pam_settings_on_record'):
            return pam_object_to_typed_record(MagicMock(), obj, FOLDER)

    def test_an_f_field_the_type_does_not_have_is_logged_with_the_record(self):
        with self.assertLogs(level=logging.WARNING) as logs:
            record = self.build(machine())
        text = '\n'.join(logs.output)
        self.assertIn('pamMachine "M1"', text)
        self.assertIn('Field type "text" is not found for record type pamMachine', text)
        self.assertFalse([f for f in record.fields if f.type == 'text'])

    def test_a_field_without_f_goes_to_a_custom_field_and_is_not_reported(self):
        with self.assertLogs(level=logging.WARNING) as logs:
            record = self.build(machine(ssl_verification=False))        # the log needs one record to fail: operatingSystem
        self.assertNotIn('checkbox', '\n'.join(logs.output))
        custom = [f for f in record.custom if f.type == 'checkbox']
        self.assertEqual([(f.label, f.value) for f in custom], [('sslVerification', [False])])

    def test_nothing_is_logged_when_every_field_fits(self):
        obj = machine(operating_system=None)
        obj.operatingSystem = None
        with self.assertNoLogs(level=logging.WARNING):
            self.build(obj)


def _t(*fields):
    return [dict(f) if isinstance(f, dict) else {'$ref': f} for f in fields]


# The server's record-type templates for the PAM types, as of database-updater DU-741 (the latest change of these types).
# NOTE: pamMachine has NO sslVerification (removed by DU-522) and pamCloudResource has NO oneTimeCode.
SEED = 'trafficEncryptionSeed'
SERVER_TEMPLATES = {
    'pamMachine': _t({'$ref': 'pamHostname', 'required': True}, 'pamSettings', SEED,
                     {'$ref': 'script', 'label': 'rotationScripts'}, *[
                         {'$ref': 'text', 'label': x} for x in
                         ('operatingSystem', 'instanceName', 'instanceId', 'providerGroup', 'providerRegion')],
                     'fileRef', 'oneTimeCode'),
    'pamDatabase': _t('pamHostname', {'$ref': 'checkbox', 'label': 'useSSL'}, 'pamSettings', SEED,
                      {'$ref': 'script', 'label': 'rotationScripts'}, {'$ref': 'text', 'label': 'databaseId'},
                      'databaseType', {'$ref': 'text', 'label': 'providerGroup'},
                      {'$ref': 'text', 'label': 'providerRegion'}, 'fileRef', 'oneTimeCode'),
    'pamDirectory': _t('pamHostname', {'$ref': 'checkbox', 'label': 'useSSL'}, 'pamSettings', SEED,
                       {'$ref': 'script', 'label': 'rotationScripts'}, {'$ref': 'text', 'label': 'domainName'},
                       {'$ref': 'multiline', 'label': 'alternativeIPs'}, {'$ref': 'text', 'label': 'directoryId'},
                       'directoryType', {'$ref': 'text', 'label': 'userMatch'},
                       {'$ref': 'text', 'label': 'providerGroup'}, {'$ref': 'text', 'label': 'providerRegion'},
                       'fileRef', 'oneTimeCode'),
    'pamUser': _t({'$ref': 'login', 'required': True}, 'password', {'$ref': 'script', 'label': 'rotationScripts'},
                  {'$ref': 'secret', 'label': 'privatePEMKey'}, {'$ref': 'secret', 'label': 'privateKeyPassphrase'},
                  {'$ref': 'secret', 'label': 'publicKey'}, {'$ref': 'text', 'label': 'distinguishedName'},
                  {'$ref': 'text', 'label': 'connectDatabase'}, {'$ref': 'checkbox', 'label': 'managed'},
                  'fileRef', 'oneTimeCode'),
    'pamRemoteBrowser': _t({'$ref': 'rbiUrl', 'required': True}, 'pamRemoteBrowserSettings', SEED, 'fileRef',
                           'oneTimeCode'),
    'pamCloudResource': _t({'$ref': 'rbiUrl', 'required': True},
                           {'$ref': 'accountNumber', 'label': 'pamCloudResourceAccountIdentifier'},
                           'pamRemoteBrowserSettings', SEED, 'fileRef'),
    'login': _t('login', 'password', 'url', 'fileRef', 'oneTimeCode'),
}


class TestEveryFieldFitsTheServerTemplate(unittest.TestCase):
    """With every key of an item filled in, the batch builder must not report a field the record type lacks."""

    ROT = PamRotationParams(configUid=CFG, profiles={})
    FULL = {
        'pamMachine': dict(host='h', port='22', ssl_verification=True, operating_system='Linux', instance_name='i',
                           instance_id='id', provider_group='g', provider_region='r', otp='otpauth://totp/x?secret=ABC'),
        'pamDatabase': dict(host='h', port='5432', use_ssl=True, database_id='d', database_type='postgresql',
                            provider_group='g', provider_region='r', otp='otpauth://totp/x?secret=ABC'),
        'pamDirectory': dict(host='h', port='389', use_ssl=True, domain_name='d.example', alternative_ips='1.1.1.1',
                             directory_id='x', directory_type='active_directory', user_match='ou',
                             provider_group='g', provider_region='r', otp='otpauth://totp/x?secret=ABC'),
        'pamUser': dict(login='u', password='p', private_pem_key='k', distinguished_name='cn=u', connect_database='db',
                        managed=True, otp='otpauth://totp/x?secret=ABC',
                        custom=[{'type': 'text', 'label': 'Team', 'value': 'ops'}]),
        'pamRemoteBrowser': dict(url='https://x.example', otp='otpauth://totp/x?secret=ABC'),
        'pamCloudResource': dict(url='https://acme.okta.com', account_identifier='0oa1', otp='otpauth://totp/x?secret=ABC'),
        'login': dict(login='u', password='p', url='https://x.example', otp='otpauth://totp/x?secret=ABC'),
    }

    def load(self, rtype):
        from keepercommander.commands.pam_import import base
        cls = {'pamMachine': base.PamMachineObject, 'pamDatabase': base.PamDatabaseObject,
               'pamDirectory': base.PamDirectoryObject, 'pamUser': base.PamUserObject,
               'pamRemoteBrowser': base.PamRemoteBrowserObject, 'pamCloudResource': base.PamCloudResourceObject,
               'login': base.LoginUserObject}[rtype]
        data = {'type': rtype, 'title': f'T-{rtype}', **self.FULL[rtype]}
        if rtype in ('pamRemoteBrowser', 'pamCloudResource', 'login'):
            return cls.load(data)
        return cls.load(data, self.ROT)

    def build(self, rtype, obj=None):
        obj = obj or self.load(rtype)
        with patch('keepercommander.commands.pam_import.pam_record_build.RecordEditAddCommand.get_record_type_fields',
                   return_value=SERVER_TEMPLATES[rtype]), \
                patch('keepercommander.commands.pam_import.tunnel_setup.ensure_traffic_encryption_seed_on_typed_record'), \
                patch('keepercommander.commands.pam_import.tunnel_setup.merge_initial_pam_settings_on_record'):
            return pam_object_to_typed_record(MagicMock(), obj, FOLDER)

    def test_no_type_reports_a_missing_field(self):
        for rtype in SERVER_TEMPLATES:
            with self.subTest(rtype):
                obj = self.load(rtype)                  # load-time warnings (empty users, ...) are not what is checked
                with self.assertNoLogs(level=logging.WARNING):
                    self.build(rtype, obj)

    def test_where_the_values_land(self):
        machine_record = self.build('pamMachine')
        self.assertEqual([(f.type, f.label, f.value) for f in machine_record.custom if f.type == 'checkbox'],
                         [('checkbox', 'sslVerification', [True])])              # no field in the type -> custom
        self.assertEqual(next(f.value for f in machine_record.fields if f.label == 'operatingSystem'), ['Linux'])
        cloud = self.build('pamCloudResource')
        self.assertEqual(cloud.custom, [])                                       # the otp is dropped at load, not kept as custom
        self.assertEqual(next(f.value for f in cloud.fields if f.type == 'accountNumber'), ['0oa1'])
        user = self.build('pamUser')
        self.assertEqual([(f.label, f.value) for f in user.custom], [('Team', ['ops'])])
        self.assertEqual(next(f.value for f in user.fields if f.label == 'privatePEMKey'), ['k'])


class TestFieldLabels(unittest.TestCase):
    """A template field without its own label gets none (``record-add --labels off``), like a record made in the Web Vault:
    with the type name as label the Web Vault shows the raw name ("fileRef" instead of "Attachments")."""

    def build(self, rtype='pamMachine'):
        helper = TestEveryFieldFitsTheServerTemplate()
        return helper.build(rtype, helper.load(rtype))

    def test_fields_without_a_template_label_have_no_label(self):
        record = self.build()
        labels = {f.type: f.label for f in record.fields}
        for field_type in ('fileRef', 'pamHostname', 'oneTimeCode', 'pamSettings', 'trafficEncryptionSeed'):
            self.assertEqual(labels[field_type], '', field_type)

    def test_the_template_labels_are_kept(self):
        record = self.build()
        labels = {f.label for f in record.fields}
        self.assertTrue({'operatingSystem', 'instanceName', 'rotationScripts'} <= labels)

    def test_both_import_paths_ask_for_labels_off(self):
        obj = TestEveryFieldFitsTheServerTemplate().load('pamMachine')
        self.assertEqual(build_record_add_kwargs(obj, FOLDER)['labels'], 'off')
        from keepercommander.commands.pam_import import base
        import inspect
        for cls in (base.PamUserObject, base.LoginUserObject, base.PamMachineObject, base.PamDatabaseObject,
                    base.PamDirectoryObject, base.PamRemoteBrowserObject):
            self.assertIn('"labels": "off"', inspect.getsource(cls.create_record), cls.__name__)


class TestCloudResourceOtp(unittest.TestCase):
    def test_otp_is_ignored_with_a_warning(self):
        from keepercommander.commands.pam_import.base import PamCloudResourceObject
        with self.assertLogs(level=logging.WARNING) as logs:
            obj = PamCloudResourceObject.load({'type': 'pamCloudResource', 'title': 'Okta', 'url': 'https://acme.okta.com',
                                               'otp': 'otpauth://totp/x?secret=ABC'})
        self.assertIsNone(obj.oneTimeCode)
        self.assertTrue(any('PAM Cloud "Okta": otp not used for pamCloudResource' in m for m in logs.output))
        self.assertFalse([f for f in build_record_add_kwargs(obj, FOLDER).get('fields', []) if 'oneTimeCode' in f])

    def test_a_remote_browser_keeps_its_otp(self):
        from keepercommander.commands.pam_import.base import PamRemoteBrowserObject
        obj = PamRemoteBrowserObject.load({'type': 'pamRemoteBrowser', 'title': 'x', 'url': 'https://x.example',
                                           'otp': 'otpauth://totp/x?secret=ABC'})
        self.assertIn('oneTimeCode=otpauth://totp/x?secret=ABC', build_record_add_kwargs(obj, FOLDER)['fields'])


if __name__ == '__main__':
    unittest.main()
