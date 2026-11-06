"""build_pam_import: Secret Server secret details -> ``pam project import`` document."""

import os
import sys
import unittest

from keepercommander.importer.thycotic.pam import build_pam_import

sys.path.insert(0, os.path.dirname(__file__))
from _delinea_fixtures import build, by_title, connection, items, resources, secret, user_titles  # noqa: E402


def _one(*args, **kwargs):
    found = resources(build(secret(*args, **kwargs)))
    assert len(found) == 1, found
    return found[0]


class TestDocument(unittest.TestCase):
    def test_empty_input_and_default_project(self):
        for folders, project in ((None, None), ([], ''), ([{'folderName': 'E', 'secrets': []}], None),
                                 ([None], None), ([{'secrets': None}], None)):
            with self.subTest(folders=folders):
                document = build_pam_import(folders, project)
                self.assertEqual(document['project'], 'Delinea Migration')
                self.assertEqual(document['pam_data'], {'resources': [], 'users': []})
                self.assertEqual(document['safe_folders'], [])
                self.assertEqual(document['pam_configuration'], {
                    'environment': 'local', 'connections': 'on', 'rotation': 'on',
                    'graphical_session_recording': 'on'})

    def test_invalid_secrets_are_skipped(self):
        document = build_pam_import([{'folderName': 'F', 'secrets': [
            'bad', None, {'name': 'no id'}, {'id': None}, secret(1, 'ok', 6007, items=items(machine='h'))]}])
        self.assertEqual(len(resources(document)), 1)

    def test_secret_in_two_folders_is_imported_once_in_first(self):
        row = secret(1, 'root', 6007, items=items(machine='h'))
        document = build_pam_import([{'folderName': 'A', 'secrets': [row]}, {'folderName': 'B', 'secrets': [row]}])
        self.assertEqual([r['folder_path'] for r in resources(document)], ['A/A - Resources'])

    def test_resource_order_by_type_then_title(self):
        document = build(
            secret(1, 'db', items=items(server='zdb', port='5432')),
            secret(2, 'b', 6007, items=items(machine='b-host')),
            secret(3, 'ad', 6001, items=items(domain='corp.local')),
            secret(4, 'a', 6007, items=items(machine='a-host')),
        )
        self.assertEqual([(r['type'], r['title']) for r in resources(document)], [
            ('pamDirectory', 'corp.local'), ('pamMachine', 'a-host'), ('pamMachine', 'b-host'),
            ('pamDatabase', 'zdb')])


class TestMapping(unittest.TestCase):
    def test_unix_ssh(self):
        resource = _one(1, 'root', 6007, items=items(machine='web01', username='root', password='pw'))
        self.assertEqual((resource['type'], resource['host'], resource['port'], resource['operating_system']),
                         ('pamMachine', 'web01', '22', 'linux'))
        self.assertEqual((connection(resource)['protocol'], connection(resource)['port']), ('ssh', '22'))
        self.assertEqual(resource['pam_settings']['options']['tunneling'], 'off')
        user = resource['users'][0]
        self.assertEqual((user['type'], user['login'], user['password']), ('pamUser', 'root', 'pw'))
        self.assertEqual(connection(_one(1, 'r', 6007, items=items(machine='h', port='2222')))['port'], '2222')

    def test_windows_by_template_id(self):
        resource = _one(1, '108 - 6003 - Jane', 6003, items=items(machine='ws01', port='13389'))
        self.assertEqual((resource['operating_system'], resource['port']), ('Windows', '5986'))
        self.assertTrue(resource['ssl_verification'])
        self.assertEqual(connection(resource), {
            'protocol': 'rdp', 'port': '13389', 'security': 'any', 'ignore_server_cert': True,
            'launch_credentials': '108 - 6003 - Jane', 'administrative_credentials': '108 - 6003 - Jane'})
        self.assertEqual(resource['pam_settings']['options']['graphical_session_recording'], 'on')
        self.assertEqual(connection(_one(1, 'w', 6003, items=items(machine='ws01')))['port'], '3389')

    def test_active_directory(self):
        resource = _one(1, 'corp admin', 6001, items=items(domain='corp.local', username='jdoe'))
        self.assertEqual((resource['type'], resource['title'], resource['domain_name'], resource['directory_type']),
                         ('pamDirectory', 'corp.local', 'corp.local', 'active_directory'))
        self.assertEqual(resource['port'], '636')
        self.assertTrue(resource['use_ssl'])
        self.assertEqual((connection(resource)['protocol'], connection(resource)['port']), ('rdp', '3389'))
        self.assertEqual(resource['users'][0]['login'], 'jdoe@corp.local')
        self.assertFalse(_one(1, 'a', 6001, items=items(domain='corp.local', port='389'))['use_ssl'])

    def test_qualified_directory_login_is_kept(self):
        for login in ('jdoe@corp.local', 'CORP\\jdoe'):
            with self.subTest(login=login):
                user = _one(1, 'a', 6001, items=items(domain='corp.local', username=login))['users'][0]
                self.assertEqual(user['login'], login)

    def test_template_name_and_id_precedence(self):
        self.assertEqual(_one(1, 'x', secretTemplateName='MySQL Account', items=items(server='db'))['database_type'],
                         'mysql')
        self.assertEqual(_one(1, 'prod SQL Server Account', items=items(server='db'))['database_type'], 'mssql')
        self.assertEqual(_one(1, 'MySQL Account', 6007, items=items(machine='h'))['type'], 'pamMachine')

    def test_item_heuristics(self):
        cases = [
            (items(machine='h', private_key='PEM'), 'pamMachine', 'linux'),
            (items(server='db', port='1433'), 'pamDatabase', 'mssql'),
            (items(server='db', port='3306'), 'pamDatabase', 'mysql'),
            (items(server='db', port='5432'), 'pamDatabase', 'postgresql'),
            (items(server='db', port='1521'), 'pamDatabase', 'oracle'),
            (items(domain='corp.local'), 'pamDirectory', 'active_directory'),
            (items(machine='h', domain='corp'), 'pamMachine', 'Windows'),
            (items(machine='h', port='5985'), 'pamMachine', 'Windows'),
            (items(machine='WINDOWS-01'), 'pamMachine', 'Windows'),
            (items(**{'ip_address___host_name': '10.0.0.5'}), 'pamMachine', 'linux'),
        ]
        for values, record_type, subtype in cases:
            with self.subTest(items=values):
                resource = _one(1, 'acct', items=values)
                self.assertEqual(resource['type'], record_type)
                self.assertIn(subtype, (resource.get('operating_system'), resource.get('database_type'),
                                        resource.get('directory_type')))

    def test_types_without_connection_protocol(self):
        for resource in (_one(1, 'corp ldap', items=items(domain='dc=corp')),
                         _one(1, 'acct', items=items(server='db', port='1521'))):
            with self.subTest(resource=resource['title']):
                self.assertEqual(resource['pam_settings']['options']['connections'], 'off')
                self.assertNotIn('protocol', connection(resource))

    def test_login_and_unknown_secrets_are_not_imported(self):
        self.assertEqual(resources(build(
            secret(1, 'site', secretTemplateName='Web Password', items=items(username='u')),
            secret(2, 'note', items=items(notes='hi')))), [])

    def test_credentials(self):
        user = _one(1, 'k', items=items(machine='h', username='u', private_key='PEM'))['users'][0]
        self.assertEqual(user['private_pem_key'], 'PEM')
        self.assertNotIn('password', user)
        user = _one(1, 'k', 6007, items=items(machine='h', username='', password=''))['users'][0]
        self.assertEqual(user['login'], '')
        self.assertNotIn('password', user)


class TestRotation(unittest.TestCase):
    def test_rotation_settings(self):
        weekly = {'scheduleType': 'Weekly', 'monday': True, 'startingOn': '2024-01-01T03:15:00'}
        cases = [
            ({'autoChangeEnabled': False, 'autoChangeSchedule': weekly}, 'off', {'type': 'on-demand'}),
            ({'autoChangeEnabled': True, 'autoChangeSchedule': weekly}, 'on',
             {'type': 'cron', 'cron': '0 15 3 ? * MON'}),
            ({'autoChangeEnabled': True}, 'on', {'type': 'on-demand'}),
            ({'autoChangeEnabled': True, 'autoChangeSchedule': {'scheduleType': 'Weekly'}}, 'on',
             {'type': 'on-demand'}),
        ]
        for extra, enabled, schedule in cases:
            with self.subTest(extra=extra):
                resource = _one(1, 'root', 6007, items=items(machine='h'), **extra)
                self.assertEqual(resource['users'][0]['rotation_settings'],
                                 {'rotation': 'general', 'enabled': enabled, 'schedule': schedule})
                self.assertEqual(resource['pam_settings']['options']['rotation'], enabled)

    def test_unsupported_changer_has_no_rotation(self):
        resource = _one(1, 't', 6008, autoChangeEnabled=True, items=items(machine='tn'))
        self.assertEqual(resource['port'], '23')
        self.assertNotIn('rotation_settings', resource['users'][0])
        self.assertEqual(resource['pam_settings']['options']['rotation'], 'off')

    def test_resource_rotation_on_when_any_merged_user_rotates(self):
        resource = resources(build(secret(1, 'a', 6007, items=items(machine='h')),
                                   secret(2, 'b', 6007, autoChangeEnabled=True, items=items(machine='h'))))[0]
        self.assertEqual(resource['pam_settings']['options']['rotation'], 'on')


class TestMergeAndTitles(unittest.TestCase):
    def test_same_host_or_domain_merges_case_insensitively(self):
        for first, second in ((items(machine='web01'), items(machine='WEB01')),
                              (items(domain='corp.local'), items(domain='CORP.LOCAL'))):
            template = 6001 if first[0]['slug'] == 'domain' else 6007
            with self.subTest(first=first):
                found = resources(build(secret(1, 'a', template, items=first), secret(2, 'b', template, items=second)))
                self.assertEqual([user_titles(r) for r in found], [['a', 'b']])

    def test_different_port_or_type_stays_separate(self):
        self.assertEqual(len(resources(build(
            secret(1, 'a', 6007, items=items(machine='h')),
            secret(2, 'b', 6007, items=items(machine='h', port='2222')),
            secret(3, 'c', items=items(server='h', port='5432'))))), 3)

    def test_titles(self):
        document = build(secret(1, 'root', 6007, items=items(machine='h1')),
                         secret(2, 'ROOT', 6007, items=items(machine='h2')),
                         secret(3, 'h3', 6007, items=items(machine='h3')),
                         secret(4, '  ', 6007, items=items(machine='h4')))
        self.assertEqual([r['users'][0]['title'] for r in resources(document)], ['root', 'ROOT #2', 'h3 #3', 'Secret 4'])
        self.assertEqual(connection(by_title(document, 'h3'))['launch_credentials'], 'h3 #3')


class TestAdminCredentials(unittest.TestCase):
    def assertCredentials(self, resource, users, launch, admin):
        self.assertEqual(user_titles(resource), users)
        self.assertEqual((connection(resource)['launch_credentials'],
                          connection(resource)['administrative_credentials']), (launch, admin))

    def test_no_privileged_account_uses_first_user(self):
        resource = resources(build(secret(1, 'root', 6007, items=items(machine='h')),
                                   secret(2, 'svc', 6007, items=items(machine='h'))))[0]
        self.assertCredentials(resource, ['root', 'svc'], 'root', 'root')

    def test_unlisted_admin_is_added_as_second_user(self):
        for admin_items, title in ((items(machine='h', username='adm', password='ap'), 'adm'),
                                   (items(machine='h', password='ap'), 'Admin 20')):
            with self.subTest(title=title):
                resource = _one(1, 'root', 6007, privilegedAccountSecretId=20, items=items(machine='h'),
                                administrativeCredentials=admin_items)
                self.assertCredentials(resource, ['root', title], 'root', title)
                self.assertEqual(resource['users'][1]['password'], 'ap')

    def test_admin_on_another_resource_is_copied(self):
        document = build(secret(1, 'root', 6007, privilegedAccountSecretId=20, items=items(machine='h1')),
                         secret(20, 'adm', 6007, items=items(machine='h2')))
        h1, h2 = by_title(document, 'h1'), by_title(document, 'h2')
        self.assertCredentials(h1, ['root', 'adm'], 'root', 'adm')
        self.assertEqual(user_titles(h2), ['adm'])
        self.assertIsNot(h1['users'][1], h2['users'][0])

    def test_domain_admin_for_windows_machine(self):
        document = build(secret(1, 'local', 6003, privilegedAccountSecretId=20, items=items(machine='ws1'),
                                administrativeCredentials=items(domain='corp.local', username='domadm')))
        self.assertCredentials(by_title(document, 'ws1'), ['local', 'domadm'], 'local', 'domadm')
        self.assertIn('corp.local', [r['title'] for r in resources(document)])

    def test_admin_on_same_host_ends_up_right_after_login(self):
        admin = secret(20, 'adm', 6007, items=items(machine='h'))
        login = secret(1, 'root', 6007, privilegedAccountSecretId=20, items=items(machine='h'))
        other = secret(5, 'other', 6007, items=items(machine='h'))
        for order, users in (((admin, other, login), ['other', 'root', 'adm']),
                             ((login, admin), ['root', 'adm'])):
            with self.subTest(users=users):
                self.assertCredentials(resources(build(*order))[0], users, 'root', 'adm')

    def test_launch_is_the_user_that_has_a_privileged_account(self):
        resource = resources(build(
            secret(1, 'plain', 6007, items=items(machine='h')),
            secret(2, 'root', 6007, privilegedAccountSecretId=20, items=items(machine='h'),
                   administrativeCredentials=items(machine='h', username='adm'))))[0]
        self.assertCredentials(resource, ['plain', 'root', 'adm'], 'root', 'adm')

    def test_shared_admin_is_one_resource(self):
        admin_items = items(machine='h3', username='adm')
        document = build(
            secret(1, 'r1', 6007, privilegedAccountSecretId=20, items=items(machine='h1'),
                   administrativeCredentials=admin_items),
            secret(2, 'r2', 6007, privilegedAccountSecretId=20, items=items(machine='h2'),
                   administrativeCredentials=admin_items))
        for title in ('h1', 'h2'):
            self.assertEqual(connection(by_title(document, title))['administrative_credentials'], 'adm')
        self.assertEqual([r['title'] for r in resources(document)].count('h3'), 1)

    def test_missing_or_invalid_admin_falls_back_to_launch(self):
        cases = [(1, items(machine='h', username='adm'))]                          # self-privileged
        cases += [(20, admin) for admin in (None, [], 'bad')]                      # no admin items
        cases += [(pid, items(machine='h', username='adm')) for pid in (True, '20', 0, -1, 20.0)]
        for privileged, admin_items in cases:
            with self.subTest(privileged=privileged, admin_items=admin_items):
                resource = _one(1, 'root', 6007, privilegedAccountSecretId=privileged, items=items(machine='h'),
                                administrativeCredentials=admin_items)
                self.assertCredentials(resource, ['root'], 'root', 'root')

    @unittest.expectedFailure
    def test_admin_with_only_login_items_is_still_linked(self):
        # Admin items with no host / domain map to a "login" record and are dropped,
        # so administrative_credentials silently falls back to the launch user.
        resource = _one(1, 'root', 6007, privilegedAccountSecretId=20, items=items(machine='h'),
                        administrativeCredentials=items(username='adm', password='ap'))
        self.assertEqual(connection(resource)['administrative_credentials'], 'adm')


class TestSafeFolders(unittest.TestCase):
    def test_paths_and_entries(self):
        document = build_pam_import([
            {'folderName': 'Servers', 'secrets': [secret(1, 'a', 6007, items=items(machine='h1')),
                                                  secret(2, 'b', 6007, items=items(machine='h2'))]},
            {'folderName': 'AD', 'secrets': [secret(3, 'c', 6001, items=items(domain='corp'))]},
        ], 'P')
        machine = by_title(document, 'h1')
        self.assertEqual(machine['folder_path'], 'Servers/Servers - Resources')
        self.assertEqual(machine['users'][0]['folder_path'], 'Servers/Servers - Users')
        self.assertEqual([f['name'] for f in document['safe_folders']], ['Servers', 'AD'])
        self.assertEqual(document['safe_folders'][0], {
            'name': 'Servers', 'safe_name': 'Servers', 'manage_users': True, 'manage_records': True,
            'can_edit': True, 'can_share': True, 'permissions': []})

    def test_no_folder_name_uses_resource_title(self):
        resource = _one(1, 'a', 6007, items=items(machine='h1'))
        self.assertEqual(resources(build(secret(1, 'a', 6007, items=items(machine='h1')), folder=''))[0]
                         ['folder_path'], 'h1/h1 - Resources')
        self.assertEqual(resource['folder_path'], 'F/F - Resources')

    def test_merged_and_copied_users_follow_their_resource(self):
        document = build_pam_import([
            {'folderName': 'A', 'secrets': [secret(1, 'root', 6007, privilegedAccountSecretId=20,
                                                   items=items(machine='h1')),
                                            secret(2, 'svc', 6007, items=items(machine='h1'))]},
            {'folderName': 'B', 'secrets': [secret(20, 'adm', 6007, items=items(machine='h2')),
                                            secret(3, 'late', 6007, items=items(machine='h1'))]},
        ])
        h1 = by_title(document, 'h1')
        self.assertEqual(h1['folder_path'], 'A/A - Resources')
        self.assertEqual({u['folder_path'] for u in h1['users']}, {'A/A - Users'})
        self.assertEqual(by_title(document, 'h2')['users'][0]['folder_path'], 'B/B - Users')


if __name__ == '__main__':
    unittest.main()
