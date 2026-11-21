import json
from types import SimpleNamespace
from unittest import TestCase, mock

from keepercommander import utils
from keepercommander.commands.discoveryrotation import PAMGatewayListCommand
from keepercommander.commands.email_commands import EmailConfigListCommand
from keepercommander.commands.enterprise import EnterpriseInfoCommand
from keepercommander.commands.ksm import KSMCommand
from keepercommander.commands.utils import WhoamiCommand
from keepercommander.params import KeeperParams, RecordOwner


class TestJsonOutputConsistency(TestCase):
    @mock.patch('keepercommander.commands.discoveryrotation.KSMCommand.get_ksm_app_display_info')
    @mock.patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    @mock.patch('keepercommander.commands.discoveryrotation.router_get_connected_gateways')
    def test_pam_gateway_list_json_includes_max_instances(
        self,
        mock_connected,
        mock_all_gateways,
        mock_app_info,
    ):
        gw1_uid = b'\x01' * 16
        gw2_uid = b'\x02' * 16
        app_uid = b'\x03' * 16

        c1 = SimpleNamespace(
            controllerUid=gw1_uid,
            controllerName='gw-single',
            applicationUid=app_uid,
            maxInstanceCount=3,
            deviceName='dev1',
            deviceToken='tok1',
            created=1700000000000,
            lastModified=1700000000000,
            nodeId=100,
        )
        c2 = SimpleNamespace(
            controllerUid=gw2_uid,
            controllerName='gw-pool',
            applicationUid=app_uid,
            maxInstanceCount=5,
            deviceName='dev2',
            deviceToken='tok2',
            created=1700000000000,
            lastModified=1700000000000,
            nodeId=100,
        )
        mock_all_gateways.return_value = [c1, c2]
        mock_connected.return_value = SimpleNamespace(
            controllers=[
                SimpleNamespace(controllerUid=gw1_uid, version='1.2.3;Linux', ipAddress='10.0.0.1', connectedOn=1700000000000),
                SimpleNamespace(controllerUid=gw2_uid, version='1.2.3;Linux', ipAddress='10.0.0.2', connectedOn=1700000000000),
                SimpleNamespace(controllerUid=gw2_uid, version='1.2.3;Linux', ipAddress='10.0.0.3', connectedOn=1700000000000),
            ]
        )
        mock_app_info.return_value = ('PAM App', True, 'PAM App')

        params = KeeperParams()
        out = PAMGatewayListCommand().execute(params, format='json')
        data = json.loads(out)
        by_name = {g['gateway_name']: g for g in data['gateways']}
        self.assertEqual(by_name['gw-single']['max_instances'], 3)
        self.assertEqual(by_name['gw-pool']['max_instances'], 5)
        self.assertEqual(len(by_name['gw-pool']['instances']), 2)

    def test_email_config_list_json_returns_string_when_empty_and_non_empty(self):
        params = KeeperParams()
        params.record_cache = {}
        params.record_owner_cache = {}
        params.meta_data_cache = {}

        empty_out = EmailConfigListCommand().execute(params, format='json')
        self.assertEqual(json.loads(empty_out), [])

        from keepercommander import vault

        rec = mock.MagicMock(spec=vault.TypedRecord)
        rec.record_uid = 'EMAIL_UID_1'
        rec.title = 'smtp-main'
        rec.record_type = 'login'

        params.record_cache = {'EMAIL_UID_1': {}}
        params.record_owner_cache = {'EMAIL_UID_1': RecordOwner(True, 'admin@acme.com')}

        with mock.patch('keepercommander.commands.email_commands.vault.KeeperRecord.load', return_value=rec), \
             mock.patch('keepercommander.commands.email_commands.vault_extensions.extract_typed_record_data', return_value={
                 'custom': [
                     {'type': 'text', 'label': '__email_config__', 'value': ['true']},
                     {'type': 'text', 'label': 'provider', 'value': ['smtp']},
                     {'type': 'text', 'label': 'from_address', 'value': ['noreply@acme.com']},
                 ]
             }):
            non_empty_out = EmailConfigListCommand().execute(params, format='json')
            parsed = json.loads(non_empty_out)
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0]['record_uid'], 'EMAIL_UID_1')
            self.assertEqual(parsed[0]['provider'], 'smtp')

    @mock.patch('keepercommander.commands.ksm.api.communicate_rest')
    def test_ksm_print_all_apps_records_json_empty_returns_list(self, mock_comm_rest):
        mock_comm_rest.return_value = SimpleNamespace(applicationSummary=[])
        params = KeeperParams()
        params.record_cache = {}
        out = KSMCommand.print_all_apps_records(params, format_type='json')
        self.assertEqual(json.loads(out), [])

    def test_ksm_license_helpers_tolerate_null_add_ons(self):
        params = KeeperParams()
        params.enterprise = {
            'licenses': [
                {'paid': True, 'next_billing_date': 1767225600000, 'add_ons': None}
            ]
        }
        lic = KSMCommand._ksm_pick_license(params)
        self.assertIsNotNone(lic)
        cycle = KSMCommand._ksm_billing_cycle(params, run_on_ms=1760000000000)
        self.assertIsNotNone(cycle)

    def test_whoami_json_tolerates_null_add_ons(self):
        params = KeeperParams()
        params.session_token = 'tok-123'
        params.user = 'admin@acme.com'
        params.server = 'https://keepersecurity.com/api/v2/'
        params.rest_context.server_base = 'https://keepersecurity.com/api/v2/'
        params.license = {
            'account_type': 2,
            'product_type_name': 'Enterprise',
            'expiration_date': '2027-01-01',
            'bytes_total': 1073741824,
            'bytes_used': 0,
            'storage_expiration_date': '2027-01-01',
        }
        params.settings = {}
        params.enforcements = {}
        params.enterprise = {
            'enterprise_name': 'Acme Corp',
            'nodes': [{'node_id': 100, 'data': {'displayname': 'Acme Corp'}}],
            'users': [{'enterprise_user_id': 1, 'username': 'admin@acme.com', 'node_id': 100, 'status': 'active', 'lock': 0}],
            'roles': [{'role_id': 10, 'data': {'displayname': 'Admin'}}],
            'role_users': [{'role_id': 10, 'enterprise_user_id': 1}],
            'managed_nodes': [{'role_id': 10, 'managed_node_id': 100, 'cascade_node_management': True}],
            'role_privileges': [],
            'licenses': [
                {
                    'product_type_id': 3,
                    'tier': 1,
                    'lic_status': 'business',
                    'name': 'Enterprise',
                    'paid': True,
                    'expiration': None,
                    'number_of_seats': 50,
                    'seats_allocated': 5,
                    'seats_pending': 0,
                    'add_ons': None,
                }
            ],
        }
        out = WhoamiCommand().execute(params, json_output=True, verbose=True)
        data = json.loads(out)
        self.assertEqual(data['user'], 'admin@acme.com')
        self.assertEqual(len(data['enterprise_licenses']), 1)
        self.assertNotIn('add_ons', data['enterprise_licenses'][0])

    def test_enterprise_info_roles_verbose_json_includes_enforcements(self):
        params = KeeperParams()
        params.user = 'admin@acme.com'
        params.enterprise = {
            'enterprise_name': 'Acme Corp',
            'user_managed_nodes': [100],
            'user_root_nodes': [100],
            'nodes': [{'node_id': 100, 'parent_id': 0, 'data': {'displayname': 'Acme Corp'}}],
            'users': [{'enterprise_user_id': 1, 'username': 'admin@acme.com', 'node_id': 100, 'status': 'active', 'lock': 0, 'tfa_enabled': True, 'transfer_acceptance_status': 0, 'data': {}}],
            'roles': [{'role_id': 10, 'node_id': 100, 'data': {'displayname': 'Admin'}, 'visible_below': True, 'new_user_inherit': False}],
            'role_users': [{'role_id': 10, 'enterprise_user_id': 1}],
            'managed_nodes': [{'role_id': 10, 'managed_node_id': 100, 'cascade_node_management': True}],
            'role_privileges': [],
            'role_enforcements': [
                {'role_id': 10, 'enforcements': {'master_password_minimum_length': 16}}
            ],
        }
        out = EnterpriseInfoCommand().execute(params, roles=True, verbose=True, format='json', quiet=True)
        rows = json.loads(out)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['role_id'], 10)
        self.assertEqual(rows[0]['enforcements'], {'master_password_minimum_length': 16})
