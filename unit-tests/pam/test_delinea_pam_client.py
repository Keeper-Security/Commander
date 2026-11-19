"""DelineaPamClient: folder / secret loading, secret details, RPC schedule and admin credentials."""

import os
import sys
import unittest
from unittest import mock

from keepercommander.importer.thycotic.pam import DelineaPamClient
from keepercommander.importer.thycotic.pam.client import UNASSIGNED_POLICY_ID
from keepercommander.importer.thycotic.thycotic import ThycoticMixin

sys.path.insert(0, os.path.dirname(__file__))
from _delinea_fixtures import items, resources  # noqa: E402

FOLDERS = {
    1: {'id': 1, 'folderName': 'Personal Folders', 'folderPath': '\\Personal Folders'},
    5: {'id': 5, 'folderName': 'Servers', 'folderPath': '\\Servers'},
    3: {'id': 3, 'folderName': 'Databases', 'folderPath': ''},
}
ROTATING = {'id': 7, 'autoChangeEnabled': True}
RPC = '/v3/secrets/7/rpc-script-secrets'


class _Auth:
    """Fake ``ThycoticAuth``: entity payloads by path, lookup rows by folder id."""

    def __init__(self, entities=None, lookups=None):
        self.entities = entities or {}
        self.lookups = lookups or {}
        self.entity_calls = []

    def thycotic_entity(self, path):
        self.entity_calls.append(path)
        return self.entities.get(path)

    def thycotic_search(self, path):
        for folder_id, rows in self.lookups.items():
            if path.endswith(f'filter.folderId={folder_id}'):
                return rows
        return []


class _ClientCase(unittest.TestCase):
    def client(self, entities=None, lookups=None):
        self.auth = _Auth(entities, lookups)
        patcher = mock.patch.object(ThycoticMixin, '_load_folders',
                                    return_value={k: dict(v) for k, v in FOLDERS.items()})
        self.load_folders = patcher.start()
        self.addCleanup(patcher.stop)
        return DelineaPamClient(self.auth)


class TestValueHelpers(unittest.TestCase):
    def test_positive_secret_id(self):
        for value, expected in [(5, 5), ('7', 7), (' 12 ', 12), (0, None), (-1, None), ('-1', None),
                                ('', None), ('abc', None), (None, None), (True, None), (3.0, None), ([4], None)]:
            with self.subTest(value=value):
                self.assertEqual(DelineaPamClient._positive_secret_id(value), expected)

    def test_as_bool(self):
        for value, expected in [(True, True), (' TRUE ', True), ('false', False), ('yes', False),
                                (1, True), (0.0, False), (None, False), ([], False)]:
            with self.subTest(value=value):
                self.assertEqual(DelineaPamClient._as_bool(value), expected)

    def test_secret_name_key_precedence(self):
        for row, expected in [({'value': 'a', 'name': 'b'}, 'a'), ({'value': '', 'name': 'b'}, 'b'),
                              ({'secretName': 'c'}, 'c'), ({'value': 42}, '42'), ({}, '')]:
            with self.subTest(row=row):
                self.assertEqual(DelineaPamClient._secret_name(row), expected)

    def test_extract_secret_detail(self):
        raw = {'id': 9, 'name': 'raw', 'secretTemplateId': 6003, 'siteId': 2, 'autoChangeEnabled': 'True',
               'secretPolicyId': 14, 'items': items(username='u')}
        self.assertEqual(DelineaPamClient.extract_secret_detail(raw, 9, 'lookup name'), {
            'id': 9, 'name': 'lookup name', 'secretTemplateId': 6003, 'siteId': 2, 'autoChangeEnabled': True,
            'secretPolicyId': 14, 'items': items(username='u'), 'autoChangeSchedule': None,
            'privilegedAccountSecretId': None, 'administrativeCredentials': None,
        })

    def test_extract_secret_detail_defaults(self):
        detail = DelineaPamClient.extract_secret_detail({'secretPolicyId': None, 'items': 'x'}, 4)
        self.assertEqual((detail['id'], detail['name'], detail['items']), (4, '', []))
        self.assertFalse(detail['autoChangeEnabled'])
        self.assertEqual(detail['secretPolicyId'], UNASSIGNED_POLICY_ID)
        self.assertEqual(DelineaPamClient.extract_secret_detail({}, 4)['secretPolicyId'], UNASSIGNED_POLICY_ID)
        self.assertEqual(DelineaPamClient.extract_secret_detail({'secretPolicyId': 0}, 4)['secretPolicyId'], 0)
        self.assertEqual(DelineaPamClient.extract_secret_detail({'name': 'raw'}, 4)['name'], 'raw')


class TestFolders(_ClientCase):
    def test_folders_omit_personal_root_and_load_once(self):
        client = self.client()
        self.assertEqual(sorted(client.folders()), [3, 5])
        self.assertIn(1, client._folder_index())
        client.folder_secrets()
        self.load_folders.assert_called_once_with(self.auth)

    def test_load_failure_gives_empty_results(self):
        client = self.client()
        self.load_folders.return_value = None
        self.assertEqual(client.folders(), {})
        self.assertEqual(client.folder_secrets(), [])

    def test_secrets_lookup_dedupes_and_skips_bad_rows(self):
        client = self.client(lookups={5: [
            {'id': 1, 'value': 'a'}, {'id': 1, 'value': 'dup'}, {'value': 'no id'}, {'id': None},
            'not a dict', {'id': 2, 'name': 'b'},
        ]})
        self.assertEqual(client.secrets_lookup(5), [{'id': 1, 'name': 'a'}, {'id': 2, 'name': 'b'}])
        self.assertEqual(client.secret_ids([5, 5]), [1, 2, 1, 2])

    def test_folder_secrets_sorted_by_id(self):
        client = self.client(lookups={5: [{'id': 10, 'value': 's'}]})
        result = client.folder_secrets()
        self.assertEqual([f['id'] for f in result], [1, 3, 5])
        self.assertEqual(result[1], {'id': 3, 'folderName': 'Databases', 'folderPath': '', 'secrets': []})
        self.assertEqual(result[2]['secrets'], [{'id': 10, 'name': 's'}])


class TestSecretDetail(_ClientCase):
    def test_unreadable_secret_is_cached_as_none(self):
        for payload in (None, ['bad']):
            with self.subTest(payload=payload):
                client = self.client(entities={'/v1/secrets/7': payload})
                with self.assertLogs(level='WARNING'):
                    self.assertIsNone(client.secret_detail(7))
                self.assertIsNone(client.secret_detail(7))
                self.assertEqual(self.auth.entity_calls, ['/v1/secrets/7'])

    def test_rotation_off_skips_rpc(self):
        client = self.client(entities={'/v1/secrets/7': {'id': 7, 'autoChangeEnabled': False}})
        self.assertIsNone(client.secret_detail(7)['autoChangeSchedule'])
        self.assertEqual(self.auth.entity_calls, ['/v1/secrets/7'])

    def test_rotation_on_reads_schedule_and_admin_items(self):
        schedule = {'scheduleType': 'Daily'}
        client = self.client(entities={
            '/v1/secrets/7': ROTATING,
            RPC: {'autoChangeSchedule': schedule, 'privilegedAccountSecretId': '8'},
            '/v1/secrets/8': {'id': 8, 'items': items(username='admin')},
        })
        detail = client.secret_detail(7)
        self.assertEqual(detail['autoChangeSchedule'], schedule)
        self.assertEqual(detail['privilegedAccountSecretId'], 8)
        self.assertEqual(detail['administrativeCredentials'], items(username='admin'))

    def test_rpc_unreadable_leaves_defaults(self):
        client = self.client(entities={'/v1/secrets/7': ROTATING, RPC: 'not a dict'})
        with self.assertLogs(level='WARNING') as logs:
            detail = client.secret_detail(7)
        self.assertIn('RPC script secrets could not be read', logs.output[0])
        self.assertIsNone(detail['privilegedAccountSecretId'])

    def test_no_privileged_account_skips_admin_read(self):
        for privileged in (-1, 0, None, ''):
            with self.subTest(privileged=privileged):
                client = self.client(entities={'/v1/secrets/7': ROTATING,
                                               RPC: {'privilegedAccountSecretId': privileged}})
                detail = client.secret_detail(7)
                self.assertIsNone(detail['privilegedAccountSecretId'])
                self.assertIsNone(detail['administrativeCredentials'])
                self.assertEqual(self.auth.entity_calls, ['/v1/secrets/7', RPC])

    def test_admin_secret_unreadable_or_without_items(self):
        for admin, expected in ((None, None), ({'id': 8, 'items': None}, [])):
            with self.subTest(admin=admin):
                client = self.client(entities={'/v1/secrets/7': ROTATING, RPC: {'privilegedAccountSecretId': 8},
                                               '/v1/secrets/8': admin})
                detail = client.secret_detail(7)
                self.assertEqual(detail['privilegedAccountSecretId'], 8)
                self.assertEqual(detail['administrativeCredentials'], expected)

    def test_shared_admin_is_read_once(self):
        client = self.client(entities={
            '/v1/secrets/7': ROTATING, '/v1/secrets/9': {'id': 9, 'autoChangeEnabled': True},
            RPC: {'privilegedAccountSecretId': 8}, '/v3/secrets/9/rpc-script-secrets': {'privilegedAccountSecretId': 8},
            '/v1/secrets/8': {'id': 8, 'items': []},
        })
        client.secret_detail(7)
        client.secret_detail(9)
        self.assertEqual(self.auth.entity_calls.count('/v1/secrets/8'), 1)


class TestFolderSecretDetails(_ClientCase):
    def test_unreadable_secrets_are_dropped(self):
        client = self.client(entities={'/v1/secrets/10': {'id': 10}},
                             lookups={5: [{'id': 10, 'value': 'web'}, {'id': 11, 'value': 'gone'}]})
        with self.assertLogs(level='WARNING'):
            servers = next(f for f in client.folder_secret_details() if f['id'] == 5)
        self.assertEqual([(s['id'], s['name']) for s in servers['secrets']], [(10, 'web')])

    def test_secret_in_two_folders_is_fetched_once(self):
        client = self.client(entities={'/v1/secrets/10': {'id': 10}}, lookups={5: [{'id': 10}], 3: [{'id': 10}]})
        folders = client.folder_secret_details()
        self.assertEqual(self.auth.entity_calls.count('/v1/secrets/10'), 1)
        self.assertEqual(sum(len(f['secrets']) for f in folders), 2)

    def test_to_pam_import(self):
        client = self.client(entities={'/v1/secrets/10': {'id': 10, 'secretTemplateId': 6007,
                                                          'items': items(machine='web01')}},
                             lookups={5: [{'id': 10, 'value': 'web01 root'}]})
        document = client.to_pam_import('Proj')
        self.assertEqual(document['project'], 'Proj')
        self.assertEqual([r['title'] for r in resources(document)], ['web01'])


if __name__ == '__main__':
    unittest.main()
