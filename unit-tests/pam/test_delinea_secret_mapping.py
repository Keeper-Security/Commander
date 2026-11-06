import unittest

from keepercommander.commands.pam_import.delinea_import import (
    DelineaImportOptions, DelineaImportOrchestrator,
)
from keepercommander.importer.thycotic.pam.launcher_mapper import LauncherMapper
from keepercommander.importer.thycotic.pam.models import FindingLog, PolicySource, PrincipalKind
from keepercommander.importer.thycotic.pam.permission_mapper import PermissionMapper, permission_boundaries
from keepercommander.importer.thycotic.pam.policy import SecretPolicyResolver
from keepercommander.importer.thycotic.pam.rotation_mapper import RotationMapper
from keepercommander.importer.thycotic.pam.secret_mapper import SecretMapper
from keepercommander.importer.thycotic.pam.crosswalk import Crosswalk


class FakeClient:
    def __init__(self):
        self.folders_data = {}
        self.folder_details = {}
        self.user_data = {}
        self.group_data = {}
        self.folder_rows = {}
        self.secret_rows = {}
        self.secrets = {}
        self.settings = {}
        self.rpc = {}
        self.templates = {}
        self.types = {}
        self.requirements = {}
        self.policies = {}
        self.site_data = {}
        self.ids_by_folder = {}

    def folders(self):
        return self.folders_data

    def folder(self, folder_id):
        return self.folder_details.get(folder_id)

    def users(self):
        return self.user_data

    def groups(self):
        return self.group_data

    def folder_permissions(self, folder_id):
        return list(self.folder_rows.get(folder_id, []))

    def secret_ids(self, folder_ids):
        ids = []
        for folder_id in folder_ids:
            ids.extend(self.ids_by_folder.get(folder_id, []))
        return ids

    def secret(self, secret_id):
        return self.secrets.get(secret_id)

    def secret_settings(self, secret_id):
        return self.settings.get(secret_id)

    def secret_rpc(self, secret_id):
        return self.rpc.get(secret_id)

    def secret_permissions(self, secret_id):
        return list(self.secret_rows.get(secret_id, []))

    def secret_policy(self, policy_id):
        return self.policies.get(policy_id)

    def secret_template(self, template_id):
        return self.templates.get(template_id)

    def password_type(self, type_id):
        return self.types.get(type_id)

    def password_requirement(self, requirement_id):
        return self.requirements.get(requirement_id)

    def sites(self):
        return self.site_data


def _unix_secret():
    return {
        'id': 100, 'name': 'prod-box', 'folderId': 11, 'secretTemplateId': 60,
        'siteId': 1, 'autoChangeEnabled': True, 'sessionRecordingEnabled': True,
        'items': [
            {'slug': 'machine', 'itemValue': 'box.example'},
            {'slug': 'username', 'itemValue': 'root'},
            {'slug': 'password', 'itemValue': 'secret'},
            {'slug': 'port', 'itemValue': '2222'},
        ],
    }


class DelineaSecretMappingTest(unittest.TestCase):
    def test_schedule_and_complexity(self):
        cron = RotationMapper.schedule_to_cron({
            'changeType': 'Days', 'days': 30, 'startingOn': '2020-01-01T02:15:00',
        })
        self.assertEqual(cron, '0 15 2 */30 * ?')
        weekly = RotationMapper.schedule_to_cron({
            'changeType': 'Weekly', 'monday': True, 'wednesday': True, 'startingOn': '2020-01-01T01:00:00',
        })
        self.assertEqual(weekly, '0 0 1 ? * MON,WED')
        monthly = RotationMapper.schedule_to_cron({
            'changeType': 'Monthly', 'monthScheduleType': 'Week', 'changeEveryMonths': 2,
            'weekNumber': 1, 'dayOfWeek': 'Monday',
        })
        self.assertEqual(monthly, '0 0 0 ? */2 MON#1')
        self.assertIsNone(RotationMapper.schedule_to_cron({'changeType': 'Custom'}))

        findings = FindingLog()
        complexity = RotationMapper.complexity_from_requirement({
            'minPasswordLength': 16,
            'passwordRequirementRules': [
                {'passwordRequirementType': 'MinimumOf', 'minCharactersRequired': 2,
                 'characterSet': {'name': 'Uppercase'}},
                {'passwordRequirementType': 'MinimumOf', 'minCharactersRequired': 1,
                 'characterSet': {'name': 'Emoji'}},
            ],
        }, findings)
        self.assertEqual(complexity.to_keeper(), '16,2,0,0,0')
        self.assertEqual(len(findings), 1)

    def test_inherited_policy_and_rotation(self):
        client = FakeClient()
        client.folder_details = {
            11: {'id': 11, 'inheritSecretPolicy': True, 'parentFolderId': 10},
            10: {'id': 10, 'inheritSecretPolicy': False, 'secretPolicyId': 7, 'parentFolderId': -1},
        }
        client.policies = {7: {
            'rpcItems': {'autoChangeOnExpiration': {'policyApplyType': 'Enforced', 'value': False}},
            'generalItems': {'siteId': {'policyApplyType': 'Default', 'value': 4}},
        }}
        client.templates = {60: {
            'id': 60, 'passwordTypeId': 3,
            'fields': [{'slug': 'password', 'passwordRequirementId': 9}],
        }}
        client.types = {3: {'passwordTypeId': 3, 'name': 'Unix Account (SSH)', 'customPort': 2200}}
        client.requirements = {'unused': None}
        client.requirements = {9: {'minPasswordLength': 12, 'passwordRequirementRules': []}}
        client.site_data = {4: {'siteId': 4, 'siteName': 'Lab'}}
        client.rpc = {100: {'passwordTypeName': 'Unix Account (SSH)', 'autoChangeEnabled': True}}

        resolver = SecretPolicyResolver(client)
        secret = _unix_secret()
        secret['enableInheritSecretPolicy'] = True
        secret['siteId'] = None
        policy = RotationMapper(client, resolver, Crosswalk(), FindingLog()).resolve(secret, {})
        self.assertIs(policy.source, PolicySource.POLICY_ENFORCED)
        self.assertEqual(policy.state.value, 'disabled')
        self.assertEqual(policy.changer_name, 'Unix Account (SSH)')
        self.assertEqual(policy.site_name, 'Lab')
        self.assertEqual(policy.complexity.length, 12)
        self.assertTrue(policy.inherited)

    def test_map_secret_uses_crosswalk_and_secret_port(self):
        client = FakeClient()
        client.secrets = {
            100: _unix_secret(),
            50: {'id': 50, 'name': 'break-glass', 'items': [
                {'slug': 'username', 'itemValue': 'admin'},
                {'slug': 'password', 'itemValue': 'admin-secret'},
            ]},
        }
        client.templates = {60: {'id': 60, 'passwordTypeId': 3}}
        client.types = {3: {'name': 'Unix Account (SSH)', 'customPort': 0}}
        client.rpc = {100: {
            'passwordTypeId': 3, 'passwordTypeName': 'Unix Account (SSH)',
            'autoChangeEnabled': True,
            'autoChangeSchedule': {'changeType': 'Days', 'days': 1, 'startingOn': '2020-01-01T00:00:00'},
            'privilegedAccountSecretId': 50,
        }}
        client.settings = {100: {'sshLauncherSettings': {'launcherType': 'ConnectAsSecret', 'secretId': 50}}}
        findings = FindingLog()
        resolver = SecretPolicyResolver(client)
        rotation = RotationMapper(client, resolver, Crosswalk(), findings)
        mapper = SecretMapper(client, resolver, Crosswalk(), rotation, LauncherMapper(findings), findings)
        mapped = mapper.map_secret(client.secrets[100], 'Linux')
        resource = mapped.resource
        self.assertEqual(resource['type'], 'pamMachine')
        self.assertEqual(resource['host'], 'box.example')
        self.assertEqual(resource['port'], '2222')
        self.assertEqual(resource['operating_system'], 'linux')
        self.assertEqual(resource['folder_path'], 'Linux/Linux - Resources')
        self.assertEqual(resource['pam_settings']['connection']['protocol'], 'ssh')
        self.assertEqual(resource['pam_settings']['connection']['port'], '2222')
        self.assertEqual(resource['pam_settings']['connection']['administrative_credentials'], 'break-glass')
        self.assertEqual(resource['pam_settings']['connection']['launch_credentials'], 'break-glass')
        user = resource['users'][0]
        self.assertEqual(user['login'], 'root')
        self.assertEqual(user['rotation_settings']['rotation'], 'general')
        self.assertEqual(user['rotation_settings']['schedule']['cron'], '0 0 0 */1 * ?')
        self.assertEqual(mapped.references, {50})
        reference = mapper.map_reference(client.secrets[50])
        self.assertEqual(reference['type'], 'pamUser')
        self.assertNotIn('folder_path', reference)

    def test_unmapped_changer_becomes_a_login(self):
        client = FakeClient()
        secret = {
            'id': 8, 'name': 'widget', 'secretTemplateId': 1,
            'items': [
                {'slug': 'username', 'itemValue': 'ada'},
                {'slug': 'password', 'itemValue': 'pw'},
            ],
        }
        client.templates = {1: {'passwordTypeId': 99}}
        client.types = {99: {'name': 'Lab Widget'}}
        client.rpc = {8: {'passwordTypeId': 99, 'passwordTypeName': 'Lab Widget'}}
        findings = FindingLog()
        resolver = SecretPolicyResolver(client)
        mapper = SecretMapper(
            client, resolver, Crosswalk(), RotationMapper(client, resolver, Crosswalk(), findings),
            LauncherMapper(findings), findings)
        mapped = mapper.map_secret(secret, 'Lab')
        self.assertIsNone(mapped.resource)
        self.assertEqual(mapped.login['type'], 'login')
        self.assertEqual(mapped.login['folder_path'], 'Lab/Lab - Users')
        self.assertEqual(mapped.rotation.state.value, 'unsupported')
        self.assertIn('Lab Widget', [item.item for item in findings])

    def test_permission_boundary_and_group_expansion(self):
        folders = {
            10: {'id': 10, 'folderName': 'Root', 'parentFolderId': -1, 'inheritPermissions': False},
            11: {'id': 11, 'folderName': 'Child', 'parentFolderId': 10, 'inheritPermissions': True},
            12: {'id': 12, 'folderName': 'Own', 'parentFolderId': 10, 'inheritPermissions': False},
        }
        self.assertEqual(permission_boundaries(folders), {10: 10, 11: 10, 12: 12})
        findings = FindingLog()
        mapper = PermissionMapper(
            {3: {'userName': 'ada', 'emailAddress': 'ada@example.com'},
             4: {'userName': 'bea', 'emailAddress': 'bea@example.com'}},
            {8: {'name': 'Ops', 'users': [3], 'groups': [9]},
             9: {'name': 'Ops-nested', 'users': [4], 'groups': []}},
            findings)
        grants = mapper.folder_grants([
            {'userId': 3, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'View'},
            {'userId': 3, 'folderAccessRoleName': 'Owner', 'secretAccessRoleName': 'Owner'},
        ])
        self.assertEqual(grants[0].role, 'full-manager')
        secret_grants = mapper.secret_grants([
            {'groupId': 8, 'secretAccessRoleName': 'Edit'},
        ])
        emails = sorted(grant.principal.email for grant in secret_grants)
        self.assertEqual(emails, ['ada@example.com', 'bea@example.com'])
        self.assertTrue(all(grant.principal.kind is PrincipalKind.USER for grant in secret_grants))
        self.assertTrue(PermissionMapper.is_override(
            {'inheritPermissions': True},
            [{'userId': 3, 'secretAccessRoleName': 'Edit'}],
            [{'userId': 3, 'secretAccessRoleName': 'View'}]))

    def test_orchestrator_maps_a_folder_through_the_crosswalk(self):
        client = FakeClient()
        client.folders_data = {
            10: {'id': 10, 'folderName': 'Linux', 'folderPath': '\\Linux',
                 'parentFolderId': -1, 'inheritPermissions': False},
        }
        client.ids_by_folder = {10: [100]}
        client.secrets = {100: _unix_secret()}
        client.secrets[100]['folderId'] = 10
        client.templates = {60: {'passwordTypeId': 3}}
        client.types = {3: {'name': 'Unix Account (SSH)'}}
        client.rpc = {100: {'passwordTypeId': 3, 'passwordTypeName': 'Unix Account (SSH)', 'autoChangeEnabled': True}}
        client.user_data = {3: {'userName': 'ada', 'emailAddress': 'ada@example.com'}}
        client.folder_rows = {10: [
            {'userId': 3, 'folderAccessRoleName': 'View', 'secretAccessRoleName': 'View'},
        ]}
        client.secret_rows = {100: [
            {'userId': 3, 'secretAccessRoleName': 'Owner'},
        ]}
        options = DelineaImportOptions(server='ss.example.com', folders=['Linux'], skip_permissions=False)
        params = type('Params', (), {'enterprise': {'users': [{'username': 'ada@example.com'}]},
                                     'available_team_cache': []})()
        mapped = DelineaImportOrchestrator(params, client, options).map(Crosswalk())
        self.assertEqual(len(mapped.resources), 1)
        self.assertEqual(mapped.resources[0]['pam_settings']['connection']['protocol'], 'ssh')
        self.assertEqual(mapped.resources[0]['port'], '2222')
        self.assertIn('Linux', mapped.folder_grants)
        self.assertEqual(mapped.folder_grants['Linux'][0].role, 'viewer')
        self.assertEqual(len(mapped.secret_grants), 1)
        self.assertEqual(mapped.secret_grants[0].grants[0].role, 'content-share-manager')


if __name__ == '__main__':
    unittest.main()
