"""Crosswalk CSV round-trip, discovery and checks; NSF config lookup; unmapped rotation schedules."""

import os
import sys
import tempfile
import unittest
from unittest import mock

from keepercommander import vault
from keepercommander.commands.pam_import import delinea_access
from keepercommander.importer.thycotic.pam import (
    Crosswalk, CrosswalkRow, DelineaPamClient, FindingLog, RotationMapper, SecretPolicyResolver,
)

sys.path.insert(0, os.path.dirname(__file__))
from _delinea_fixtures import items, secret  # noqa: E402


class _Client:
    """Tenant with one SSH changer (id 9) used by template 6007, plus one changer nobody maps."""

    def __init__(self):
        self.secrets = {
            1: secret(1, 'ok', 6007, items=items(machine='h', username='u', password='p')),
            2: secret(2, 'bad', 6007, items=items(username='u', port='ssh')),
        }
        self.sample_calls = []

    def secret_templates(self):
        return [{'id': 6007, 'name': 'Unix Account (SSH)', 'secretCount': 2}]

    def secret_template(self, template_id):
        return {'id': template_id, 'name': 'Unix Account (SSH)', 'passwordTypeId': 9}

    def password_types(self):
        return {9: {'passwordTypeId': 9, 'name': 'Unix Account (SSH)'},
                12: {'passwordTypeId': 12, 'name': '=Custom Changer'}}

    def password_type(self, type_id):
        return {'name': self.password_types()[type_id]['name'], 'customPort': 2222 if type_id == 9 else 0}

    def secrets_for_template(self, template_id, limit):
        self.sample_calls.append((template_id, limit))
        return [{'id': sid, 'name': row['name']} for sid, row in self.secrets.items()][:limit]

    def secret(self, secret_id):
        return self.secrets.get(secret_id)


class TestCrosswalk(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, 'cw.csv')

    def write(self, text):
        with open(self.path, 'w', encoding='utf-8') as fh:
            fh.write(text)

    def test_discover_uses_custom_port_and_template_usage(self):
        rows = Crosswalk().discover(_Client())
        self.assertEqual([r.changer_name for r in rows], ['=Custom Changer', 'Unix Account (SSH)'])
        ssh = rows[1]
        self.assertEqual((ssh.templates, ssh.secret_count, ssh.mapping.port), (['Unix Account (SSH)'], 2, '2222'))
        self.assertIsNone(rows[0].mapping)

    def test_template_round_trip_escapes_formulas(self):
        rows = Crosswalk().discover(_Client())
        Crosswalk.write_template(rows, self.path)
        with open(self.path, encoding='utf-8') as fh:
            text = fh.read()
        self.assertIn("'=Custom Changer", text)
        loaded = Crosswalk.load(self.path)
        self.assertNotIn('=custom changer', loaded.mappings)          # unmapped row has no record_type
        self.assertEqual(loaded.resolve('Unix Account (SSH)').port, '2222')

        self.write("changer_name,record_type,protocol\n'=Custom Changer,login,\n")
        self.assertEqual(Crosswalk.load(self.path).resolve('=Custom Changer').record_type, 'login')

    def test_load_rejects_bad_files(self):
        self.write('changer_name,protocol\nX,ssh\n')
        with self.assertRaisesRegex(ValueError, 'record_type'):
            Crosswalk.load(self.path)
        self.write('changer_name,record_type\nX,pamMachin\n')
        with self.assertRaisesRegex(ValueError, 'line 2.*pamMachin'):
            Crosswalk.load(self.path)
        with self.assertRaises(OSError):
            Crosswalk.load(self.path + '.missing')

    def test_check_samples_secrets_and_reports_problems(self):
        client = _Client()
        crosswalk = Crosswalk()
        rows = crosswalk.discover(client)
        checks = crosswalk.check(client, rows, 5)
        self.assertEqual(client.sample_calls, [(6007, 5)])
        by_name = {c.secret_name: c for c in checks}
        self.assertTrue(by_name['ok'].ok)
        self.assertEqual(set(by_name['bad'].problems), {'no host', 'port is not numeric', 'no password'})
        self.assertEqual(crosswalk.check(client, rows, 0), [])
        self.assertEqual(crosswalk.check(client, [CrosswalkRow(1, 'unused')], 3), [])


class TestSecretsForTemplate(unittest.TestCase):
    def test_reads_one_page(self):
        auth = mock.Mock()
        auth.thycotic_entity.return_value = {'records': [{'id': 1}, 'junk', {'id': 2}, {'id': 3}]}
        client = DelineaPamClient(auth)
        self.assertEqual(client.secrets_for_template(6007, 2), [{'id': 1}, {'id': 2}])
        self.assertIn('filter.secretTemplateId=6007', auth.thycotic_entity.call_args[0][0])
        self.assertIn('take=2', auth.thycotic_entity.call_args[0][0])
        self.assertEqual(client.secrets_for_template(6007, 0), [])
        auth.thycotic_entity.return_value = None
        self.assertEqual(client.secrets_for_template(6007, 2), [])


class TestProjectConfigUids(unittest.TestCase):
    @staticmethod
    def typed(version, title):
        record = vault.TypedRecord(version=version)
        record.title = title
        return record

    def test_matches_title_and_suffix_on_pam_configurations_only(self):
        records = {
            'a': self.typed(6, 'Proj Configuration'),
            'b': self.typed(6, 'proj configuration #2'),
            'c': self.typed(6, 'Proj Configuration Old'),
            'd': self.typed(3, 'Proj Configuration'),
            'e': None,
            'f': mock.Mock(version=6, title='Proj Configuration'),  # not a TypedRecord
        }
        with mock.patch.object(delinea_access, 'iter_accessible_record_uids', return_value=iter(records)), \
                mock.patch.object(delinea_access, 'load_pam_record', side_effect=lambda _p, uid: records[uid]):
            self.assertEqual(delinea_access.project_config_uids(mock.Mock(), 'Proj'), {'a', 'b'})


class TestUnmappedSchedule(unittest.TestCase):
    def test_schedule_type_without_cron_is_a_finding(self):
        client = mock.Mock()
        client.secret_rpc.return_value = {'passwordTypeId': 9, 'passwordTypeName': 'Unix Account (SSH)',
                                          'autoChangeEnabled': True,
                                          'autoChangeSchedule': {'scheduleType': 'Hourly'}}
        client.secret_template.return_value = None
        client.password_type.return_value = None
        client.sites.return_value = {}
        findings = FindingLog()
        resolver = mock.Mock(spec=SecretPolicyResolver)
        resolver.policy_for.return_value = None
        policy = RotationMapper(client, resolver, Crosswalk(), findings).resolve(
            secret(4, 'acct', folderId=5), {'expirationDayInterval': 0})
        self.assertEqual(policy.schedule, {'type': 'on-demand'})
        self.assertEqual([f.category for f in findings], ['Rotation schedule'])


if __name__ == '__main__':
    unittest.main()
