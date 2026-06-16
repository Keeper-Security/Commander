import json
import unittest
from datetime import datetime
from unittest.mock import patch, MagicMock

from keepercommander.error import CommandError
import keepercommander.vault as vault

def create_mock_params_and_record(record_type='pamUser'):
    mock_params = MagicMock()
    mock_params.rest_context.server_key_id = 8
    mock_params.session_token = 'base64_encoded_session_token'  # Mock a base64 encoded session token
    mock_params.record_cache = {'record_uid': MagicMock(record_type='pamUser')}
    mock_params.subfolder_record_cache = {'folder_uid': ['record_uid']}
    mock_params.folder_cache = {'folder_uid': MagicMock()}
    mock_params.record_rotation_cache = {
        'record_uid': {
            'pwd_complexity': 'eyJ0eXBlIjogInBhc3N3b3JkX2NvbXBsZXhpdHkiLCAidmFsdWUiOiAiY29tcGxleGl0eV92YWx1ZSJ9',
            'configuration_uid': 'config_uid',
            'schedule': '[]',
            'resourceUid': 'resource_uid',
            'revision': 1  # Ensure revision is set
        }
    }
    mock_params.rest_context.server_base = 'https://fake.keepersecurity.com'  # Mock URL as string

    mock_typed_record = MagicMock(spec=vault.TypedRecord)
    mock_typed_record.record_type = record_type
    mock_typed_record.record_uid = 'record_uid'
    mock_typed_record.title = 'Mock Title'  # Add the title attribute
    mock_typed_record.record_key = b'\x00' * 16  # Add the record_key attribute

    return mock_params, mock_typed_record


def create_mock_params():
    mock_params = MagicMock()
    mock_params.rest_context.server_key_id = 8
    mock_params.session_token = 'base64_encoded_session_token'
    mock_params.record_cache = {
        'record_uid': {
            'data_unencrypted': json.dumps({'title': 'Mock Title', 'type': 'pamMachine'})
        }
    }
    mock_params.subfolder_record_cache = {'folder_uid': ['record_uid']}
    mock_params.folder_cache = {'folder_uid': MagicMock()}
    mock_params.rest_context.server_base = 'https://fake.keepersecurity.com'

    return mock_params



import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from keepercommander import crypto, utils
from keepercommander.commands.discoveryrotation import (PAMCreateRecordRotationCommand, PAMListRecordRotationCommand,
                                                        PAMGatewayListCommand, PAMRouterGetRotationInfo)

class TestPAMCreateRecordRotationCommand(unittest.TestCase):

    def setUp(self):
        self.command = PAMCreateRecordRotationCommand()
        self.parser = self.command.get_parser()
        self.transmission_key = b'transmission_key'
        self.session_token = b'encrypted_session_token'
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

        # Serialize and deserialize the public key to ensure compatibility
        public_key_bytes = self.public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        loaded_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)

        self.encrypted_transmission_key = crypto.encrypt_ec(self.transmission_key, loaded_public_key)
        self.encrypted_session_token = crypto.encrypt_aes_v2(self.session_token, self.transmission_key)

    def test_parser(self):
        args = self.parser.parse_args(['--record', 'record_uid', '--force'])
        self.assertEqual(args.record_name, 'record_uid')
        self.assertTrue(args.force)

    @patch('keepercommander.vault.KeeperRecord.load')
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @patch('keepercommander.rest_api.SERVER_PUBLIC_KEYS', {8: ec.generate_private_key(ec.SECP256R1()).public_key()})
    def test_execute_with_folder(self, mock_TunnelDAG, mock_load):
        mock_params, mock_typed_record = create_mock_params_and_record()

        mock_load.return_value = mock_typed_record

        mock_dag_instance = mock_TunnelDAG.return_value
        mock_dag_instance.linking_dag.has_graph = True
        mock_dag_instance.check_if_resource_has_admin.return_value = True
        mock_dag_instance.get_all_owners.return_value = ['resource_uid']
        mock_dag_instance.resource_belongs_to_config.return_value = True
        mock_dag_instance.user_belongs_to_resource.return_value = True
        mock_dag_instance.record.record_uid = 'config_uid'  # Ensure it returns a string

        kwargs = {
            'folder_name': 'folder_uid',
            'force': True  # Add force to the kwargs
        }

        self.command.execute(mock_params, **kwargs)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_TunnelDAG.called)

    @patch('keepercommander.vault.KeeperRecord.load', return_value=None)
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @patch('keepercommander.rest_api.SERVER_PUBLIC_KEYS', {8: ec.generate_private_key(ec.SECP256R1()).public_key()})
    def test_execute_with_no_record(self, mock_TunnelDAG, mock_load):
        mock_params, _ = create_mock_params_and_record()
        mock_params.record_cache = {}

        kwargs = {
            'record_name': 'non_existent_record',
            'force': True  # Add force to the kwargs
        }

        with self.assertRaises(CommandError):
            self.command.execute(mock_params, **kwargs)

    @patch('keepercommander.vault.KeeperRecord.load', return_value=None)
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @patch('keepercommander.rest_api.SERVER_PUBLIC_KEYS', {8: ec.generate_private_key(ec.SECP256R1()).public_key()})
    def test_execute_with_invalid_password_complexity(self, mock_TunnelDAG, mock_load):
        mock_params, _ = create_mock_params_and_record()

        kwargs = {
            'record_name': 'record_uid',
            'pwd_complexity': 'invalid_complexity',
            'force': True  # Add force to the kwargs
        }

        with self.assertRaises(CommandError):
            self.command.execute(mock_params, **kwargs)

    @patch('keepercommander.vault.KeeperRecord.load')
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @patch('keepercommander.rest_api.SERVER_PUBLIC_KEYS', {8: ec.generate_private_key(ec.SECP256R1()).public_key()})
    def test_execute_with_valid_password_complexity(self, mock_TunnelDAG, mock_load):
        mock_params, mock_typed_record = create_mock_params_and_record()

        mock_load.return_value = mock_typed_record

        mock_dag_instance = mock_TunnelDAG.return_value
        mock_dag_instance.linking_dag.has_graph = True
        mock_dag_instance.check_if_resource_has_admin.return_value = True
        mock_dag_instance.get_all_owners.return_value = ['resource_uid']
        mock_dag_instance.resource_belongs_to_config.return_value = True
        mock_dag_instance.user_belongs_to_resource.return_value = True
        mock_dag_instance.record.record_uid = 'config_uid'  # Ensure it returns a string

        kwargs = {
            'record_name': 'record_uid',
            'pwd_complexity': '32,5,5,5,5',
            'force': True  # Add force to the kwargs
        }

        self.command.execute(mock_params, **kwargs)
        self.assertTrue(mock_load.called)
        self.assertEqual(mock_typed_record.record_key, b'\x00' * 16)

    @patch('keepercommander.vault.KeeperRecord.load')
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    @patch('keepercommander.rest_api.SERVER_PUBLIC_KEYS', {8: ec.generate_private_key(ec.SECP256R1()).public_key()})
    def test_execute_with_valid_record(self, mock_TunnelDAG, mock_load):
        mock_params, mock_typed_record = create_mock_params_and_record()

        mock_load.return_value = mock_typed_record

        mock_dag_instance = mock_TunnelDAG.return_value
        mock_dag_instance.linking_dag.has_graph = True
        mock_dag_instance.check_if_resource_has_admin.return_value = True
        mock_dag_instance.get_all_owners.return_value = ['resource_uid']
        mock_dag_instance.resource_belongs_to_config.return_value = True
        mock_dag_instance.user_belongs_to_resource.return_value = True
        mock_dag_instance.record.record_uid = 'config_uid'  # Ensure it returns a string

        kwargs = {
            'record_name': 'record_uid',
            'force': True  # Add force to the kwargs
        }

        self.command.execute(mock_params, **kwargs)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_TunnelDAG.called)
        self.assertEqual(mock_typed_record.record_key, b'\x00' * 16)


class TestPAMResourceRotateCommand(unittest.TestCase):

    def setUp(self):
        self.command = PAMCreateRecordRotationCommand()
        self.parser = self.command.get_parser()

    def test_parser(self):
        args = self.parser.parse_args(['--record', "abcdefg", '--enable'])
        self.assertEqual(args.record_name, 'abcdefg')
        self.assertTrue(args.enable)

    @patch('keepercommander.vault_extensions.find_records')
    @patch('keepercommander.vault.KeeperRecord.load')
    @patch('keepercommander.commands.discoveryrotation.get_keeper_tokens')
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    def test_execute_with_enable(self, mock_tunneldag, mock_get_keeper_tokens, mock_load, mock_find_records):
        mock_dag_instance = mock_tunneldag.return_value
        mock_dag_instance.linking_dag.has_graph = True
        mock_dag_instance.resource_belongs_to_config.return_value = True

        mock_get_keeper_tokens.return_value = (b'token', b'encrypted_key', b'transmission_key')

        mock_params, mock_typed_record = create_mock_params_and_record('pamMachine')
        mock_load.return_value = mock_typed_record

        mock_pam_config_record = MagicMock(spec=vault.TypedRecord)
        mock_pam_config_record.record_uid = 'config_uid'
        mock_pam_config_record.record_type = 'pamConfiguration'  # Use a valid PAM configuration record type
        mock_find_records.return_value = [mock_pam_config_record]

        kwargs = {
            'record_name': 'record_uid',
            'enable': True,
            'config_uid': 'config_uid'
        }

        self.command.execute(mock_params, **kwargs)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_tunneldag.called)
        self.assertTrue(mock_get_keeper_tokens.called)

    @patch('keepercommander.vault.KeeperRecord.load', return_value=None)
    def test_execute_with_invalid_uid(self, mock_load):
        mock_params, _ = create_mock_params_and_record('pamMachine')

        kwargs = {
            'record_name': 'invalid_uid',
            'enable': True
        }

        with self.assertRaises(CommandError):
            self.command.execute(mock_params, **kwargs)

    @patch('keepercommander.vault.KeeperRecord.load')
    def test_execute_with_invalid_record_type(self, mock_load):
        mock_params, mock_typed_record = create_mock_params_and_record(record_type='invalid_type')
        mock_load.return_value = mock_typed_record

        kwargs = {
            'record_name': 'record_uid',
            'enable': True
        }

        with self.assertRaises(CommandError):
            self.command.execute(mock_params, **kwargs)

    @patch('keepercommander.vault_extensions.find_records')
    @patch('keepercommander.vault.KeeperRecord.load')
    @patch('keepercommander.commands.discoveryrotation.get_keeper_tokens')
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    def test_execute_with_disable(self, mock_tunneldag, mock_get_keeper_tokens, mock_load, mock_find_records):
        mock_dag_instance = mock_tunneldag.return_value
        mock_dag_instance.linking_dag.has_graph = True
        mock_dag_instance.resource_belongs_to_config.return_value = True

        mock_get_keeper_tokens.return_value = (b'token', b'encrypted_key', b'transmission_key')

        mock_params, mock_typed_record = create_mock_params_and_record('pamMachine')
        mock_load.return_value = mock_typed_record

        mock_pam_config_record = MagicMock(spec=vault.TypedRecord)
        mock_pam_config_record.record_uid = 'config_uid'
        mock_pam_config_record.record_type = 'pamConfiguration'  # Use a valid PAM configuration record type
        mock_find_records.return_value = [mock_pam_config_record]

        kwargs = {
                'record_name': 'record_uid',
                'disable': True,
                'config_uid': 'config_uid'
            }

        self.command.execute(mock_params, **kwargs)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_tunneldag.called)
        self.assertTrue(mock_get_keeper_tokens.called)

    @patch('keepercommander.vault_extensions.find_records')
    @patch('keepercommander.vault.KeeperRecord.load')
    @patch('keepercommander.commands.discoveryrotation.get_keeper_tokens')
    @patch('keepercommander.commands.discoveryrotation.TunnelDAG')
    def test_execute_with_enable_and_admin(self, mock_tunneldag, mock_get_keeper_tokens, mock_load, mock_find_records):
        mock_dag_instance = mock_tunneldag.return_value
        mock_dag_instance.linking_dag.has_graph = True
        mock_dag_instance.resource_belongs_to_config.return_value = True

        mock_get_keeper_tokens.return_value = (b'token', b'encrypted_key', b'transmission_key')

        mock_params, mock_typed_record = create_mock_params_and_record('pamMachine')
        mock_load.return_value = mock_typed_record

        mock_pam_config_record = MagicMock(spec=vault.TypedRecord)
        mock_pam_config_record.record_uid = 'config_uid'
        mock_pam_config_record.record_type = 'pamConfiguration'  # Use a valid PAM configuration record type
        mock_find_records.return_value = [mock_pam_config_record]

        kwargs = {
            'record_name': 'record_uid',
            'enable': True,
            'config_uid': 'config_uid',
            'admin': 'admin_uid'
        }

        self.command.execute(mock_params, **kwargs)
        self.assertTrue(mock_load.called)
        self.assertTrue(mock_tunneldag.called)
        self.assertTrue(mock_get_keeper_tokens.called)
        mock_dag_instance.link_user_to_resource.assert_called_with('admin_uid', 'record_uid', is_admin=True)


class TestPAMListRecordRotationCommand(unittest.TestCase):

    def setUp(self):
        self.command = PAMListRecordRotationCommand()
        self.parser = self.command.get_parser()

    def test_parser(self):
        args = self.parser.parse_args(['--verbose'])
        self.assertTrue(args.is_verbose)

    @patch('keepercommander.commands.discoveryrotation.router_get_rotation_schedules')
    @patch('keepercommander.commands.discoveryrotation.router_get_connected_gateways')
    @patch('keepercommander.commands.discoveryrotation.pam_configurations_get_all')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    @patch('keepercommander.commands.discoveryrotation.pam_decrypt_configuration_data')
    @patch('keepercommander.commands.discoveryrotation.dump_report_data')
    def test_execute(self, mock_dump_report_data, mock_pam_decrypt_configuration_data, mock_get_all_gateways,
                     mock_pam_configurations_get_all, mock_router_get_connected_gateways, mock_router_get_rotation_schedules):
        mock_params = create_mock_params()

        # Mock the return values
        mock_router_get_rotation_schedules.return_value.schedules = [
            MagicMock(
                recordUid=utils.base64_url_decode('record_uid'),
                controllerUid=utils.base64_url_decode('controller_uid'),
                configurationUid=utils.base64_url_decode('config_uid'),
                noSchedule=False,
                scheduleData='RotateActionJob|daily.0.12.1'
            )
        ]

        mock_get_all_gateways.return_value = [
            MagicMock(controllerUid=utils.base64_url_decode('controller_uid'), controllerName='Controller Name')
        ]

        mock_router_get_connected_gateways.return_value.controllers = [
            MagicMock(controllerUid=utils.base64_url_decode('controller_uid'))
        ]

        mock_pam_configurations_get_all.return_value = [
            {'record_uid': 'config_uid', 'data_unencrypted': json.dumps({'title': 'Config Title', 'type': 'pamConfig'})}
        ]

        mock_pam_decrypt_configuration_data.return_value = {
            'title': 'Config Title',
            'type': 'pamConfig'
        }

        kwargs = {'is_verbose': True}
        self.command.execute(mock_params, **kwargs)

        self.assertTrue(mock_dump_report_data.called)
        self.assertTrue(mock_router_get_rotation_schedules.called)
        self.assertTrue(mock_get_all_gateways.called)
        self.assertTrue(mock_router_get_connected_gateways.called)
        self.assertTrue(mock_pam_configurations_get_all.called)

    @patch('keepercommander.commands.discoveryrotation.router_get_rotation_schedules')
    @patch('keepercommander.commands.discoveryrotation.router_get_connected_gateways')
    @patch('keepercommander.commands.discoveryrotation.pam_configurations_get_all')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    @patch('keepercommander.commands.discoveryrotation.pam_decrypt_configuration_data')
    @patch('keepercommander.commands.discoveryrotation.dump_report_data')
    def test_execute_with_no_schedules(self, mock_dump_report_data, mock_pam_decrypt_configuration_data, mock_get_all_gateways,
                                       mock_pam_configurations_get_all, mock_router_get_connected_gateways, mock_router_get_rotation_schedules):
        mock_params = create_mock_params()

        # Mock the return values
        mock_router_get_rotation_schedules.return_value.schedules = []

        mock_get_all_gateways.return_value = []

        mock_router_get_connected_gateways.return_value.controllers = []

        mock_pam_configurations_get_all.return_value = []

        mock_pam_decrypt_configuration_data.return_value = {}

        kwargs = {'is_verbose': True}
        self.command.execute(mock_params, **kwargs)

        self.assertTrue(mock_dump_report_data.called)
        self.assertTrue(mock_router_get_rotation_schedules.called)
        self.assertTrue(mock_get_all_gateways.called)
        self.assertTrue(mock_router_get_connected_gateways.called)
        self.assertTrue(mock_pam_configurations_get_all.called)


class TestPAMGatewayListCommand(unittest.TestCase):

    def setUp(self):
        self.command = PAMGatewayListCommand()
        self.parser = self.command.get_parser()

    def test_parser(self):
        args = self.parser.parse_args(['--verbose', '--force'])
        self.assertTrue(args.is_verbose)
        self.assertTrue(args.is_force)

    def test_parser_online(self):
        args = self.parser.parse_args(['--online'])
        self.assertTrue(args.online_only)

        args = self.parser.parse_args(['-o'])
        self.assertTrue(args.online_only)

    @patch('keepercommander.commands.discoveryrotation.router_get_connected_gateways')
    @patch('keepercommander.commands.discoveryrotation.router_helper.get_router_url')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_app_record')
    @patch('keepercommander.commands.discoveryrotation.dump_report_data')
    def test_execute(self, mock_dump_report_data, mock_get_app_record, mock_get_all_gateways,
                     mock_get_router_url, mock_router_get_connected_gateways):
        mock_params = create_mock_params()

        # Mock the return values
        mock_router_get_connected_gateways.return_value.controllers = [
            MagicMock(controllerUid=utils.base64_url_decode('controller_uid'))
        ]

        mock_get_all_gateways.return_value = [
            MagicMock(
                applicationUid=utils.base64_url_decode('app_uid'),
                controllerUid=utils.base64_url_decode('controller_uid'),
                controllerName='Controller Name',
                deviceName='Device Name',
                deviceToken='Device Token',
                created=int(datetime.now().timestamp() * 1000),
                lastModified=int(datetime.now().timestamp() * 1000),
                nodeId='Node ID'
            )
        ]

        mock_get_app_record.return_value = {
            'data_unencrypted': json.dumps({'title': 'App Title'})
        }

        kwargs = {'is_force': True, 'is_verbose': True}
        self.command.execute(mock_params, **kwargs)

        self.assertTrue(mock_dump_report_data.called)
        self.assertTrue(mock_router_get_connected_gateways.called)
        self.assertTrue(mock_get_all_gateways.called)
        self.assertTrue(mock_get_router_url.called)
        self.assertTrue(mock_get_app_record.called)

    @patch('keepercommander.commands.discoveryrotation.router_get_connected_gateways')
    @patch('keepercommander.commands.discoveryrotation.router_helper.get_router_url')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    @patch('keepercommander.commands.discoveryrotation.dump_report_data')
    def test_execute_router_down(self, mock_dump_report_data, mock_get_all_gateways,
                                 mock_get_router_url, mock_router_get_connected_gateways):
        mock_params = create_mock_params()

        # Simulate a connection error
        mock_router_get_connected_gateways.side_effect = requests.exceptions.ConnectionError

        mock_get_all_gateways.return_value = [
            MagicMock(
                applicationUid=utils.base64_url_decode('app_uid'),
                controllerUid=utils.base64_url_decode('controller_uid'),
                controllerName='Controller Name',
                deviceName='Device Name',
                deviceToken='Device Token',
                created=int(datetime.now().timestamp() * 1000),
                lastModified=int(datetime.now().timestamp() * 1000),
                nodeId='Node ID'
            )
        ]

        kwargs = {'is_force': True, 'is_verbose': True}
        self.command.execute(mock_params, **kwargs)

        self.assertTrue(mock_dump_report_data.called)
        self.assertTrue(mock_router_get_connected_gateways.called)
        self.assertTrue(mock_get_all_gateways.called)
        self.assertTrue(mock_get_router_url.called)

    @patch('keepercommander.commands.discoveryrotation.print')
    @patch('keepercommander.commands.discoveryrotation.router_get_connected_gateways')
    @patch('keepercommander.commands.discoveryrotation.router_helper.get_router_url')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    @patch('keepercommander.commands.discoveryrotation.KSMCommand.get_app_record')
    @patch('keepercommander.commands.discoveryrotation.dump_report_data')
    def test_execute_online_only(self, mock_dump_report_data, mock_get_app_record, mock_get_all_gateways,
                                 mock_get_router_url, mock_router_get_connected_gateways, mock_print):
        mock_params = create_mock_params()

        online_uid = utils.base64_url_decode('controller_uid')
        offline_uid = utils.base64_url_decode('offline_uid')

        mock_router_get_connected_gateways.return_value.controllers = [
            MagicMock(controllerUid=online_uid, version='1.0.0')
        ]

        mock_get_all_gateways.return_value = [
            MagicMock(
                applicationUid=utils.base64_url_decode('app_uid'),
                controllerUid=online_uid,
                controllerName='Online Gateway',
                deviceName='Device 1',
                deviceToken='Token 1',
                created=int(datetime.now().timestamp() * 1000),
                lastModified=int(datetime.now().timestamp() * 1000),
                nodeId='Node 1'
            ),
            MagicMock(
                applicationUid=utils.base64_url_decode('app_uid2'),
                controllerUid=offline_uid,
                controllerName='Offline Gateway',
                deviceName='Device 2',
                deviceToken='Token 2',
                created=int(datetime.now().timestamp() * 1000),
                lastModified=int(datetime.now().timestamp() * 1000),
                nodeId='Node 2'
            )
        ]

        mock_get_app_record.return_value = {
            'data_unencrypted': json.dumps({'title': 'App Title'})
        }

        kwargs = {'is_force': True, 'online_only': True}
        self.command.execute(mock_params, **kwargs)

        self.assertTrue(mock_dump_report_data.called)
        table = mock_dump_report_data.call_args[0][0]
        self.assertEqual(len(table), 1)
        self.assertIn('Online Gateway', table[0][1])

        totals_printed = any('Online: 1' in str(call.args[0]) for call in mock_print.call_args_list)
        self.assertTrue(totals_printed)

    @patch('keepercommander.commands.discoveryrotation.router_get_connected_gateways')
    @patch('keepercommander.commands.discoveryrotation.router_helper.get_router_url')
    @patch('keepercommander.commands.discoveryrotation.gateway_helper.get_all_gateways')
    def test_execute_no_gateways(self, mock_get_all_gateways,
                                 mock_get_router_url, mock_router_get_connected_gateways):
        mock_params = create_mock_params()

        mock_router_get_connected_gateways.return_value.controllers = []

        mock_get_all_gateways.return_value = []

        kwargs = {'is_force': True, 'is_verbose': True}
        self.command.execute(mock_params, **kwargs)

        self.assertTrue(mock_router_get_connected_gateways.called)
        self.assertTrue(mock_get_all_gateways.called)
        self.assertTrue(mock_get_router_url.called)

class TestPAMRouterGetRotationInfo(unittest.TestCase):

    def _make_rri(self, status_name='RRS_ONLINE'):
        """Build a minimal RouterRotationInfo mock."""
        from keepercommander.proto import router_pb2
        rri = MagicMock()
        rri.status = router_pb2.RouterRotationStatus.Value(status_name)
        rri.configurationUid = utils.base64_url_decode('config_uid_____')
        rri.nodeId = 42
        rri.controllerName = 'gw-test'
        rri.controllerUid = utils.base64_url_decode('gw_uid_________')
        rri.resourceUid = b''
        rri.pwdComplexity = ''
        rri.disabled = False
        rri.scriptName = ''
        return rri

    def _make_schedule(self, record_uid_bytes, no_schedule=False, schedule_data='daily.0.12.1'):
        s = MagicMock()
        s.recordUid = record_uid_bytes
        s.noSchedule = no_schedule
        s.scheduleData = schedule_data
        return s

    @patch('keepercommander.commands.discoveryrotation.router_get_rotation_schedules')
    @patch('keepercommander.commands.discoveryrotation.record_rotation_get')
    def test_json_online_status(self, mock_rrg, mock_schedules):
        """Online status + --format json returns valid JSON with expected keys."""
        from keeper_secrets_manager_core.utils import url_safe_str_to_bytes
        record_uid = 'test_record_uid_'
        record_uid_bytes = url_safe_str_to_bytes(record_uid)

        mock_rrg.return_value = self._make_rri('RRS_ONLINE')

        sched_mock = MagicMock()
        sched_mock.schedules = [self._make_schedule(record_uid_bytes, no_schedule=False,
                                                    schedule_data='daily.0.12.1')]
        mock_schedules.return_value = sched_mock

        mock_params = create_mock_params()
        mock_params.record_cache = {}

        cmd = PAMRouterGetRotationInfo()
        result = cmd.execute(mock_params, record_uid=record_uid, format='json')

        self.assertIsNotNone(result, "Expected JSON string, got None")
        data = json.loads(result)
        self.assertIn('status', data)
        self.assertTrue(data['ready_to_rotate'])
        self.assertIn('pam_config_uid', data)
        self.assertIn('gateway_name', data)
        self.assertEqual(data['gateway_name'], 'gw-test')
        self.assertIn('schedule_type', data)
        self.assertEqual(data['schedule_type'], 'scheduled')

    @patch('keepercommander.commands.discoveryrotation.router_get_rotation_schedules')
    @patch('keepercommander.commands.discoveryrotation.record_rotation_get')
    def test_json_non_online_status(self, mock_rrg, mock_schedules):
        """Non-online status + --format json returns minimal JSON with ready_to_rotate=false."""
        record_uid = 'test_record_uid_'

        mock_rrg.return_value = self._make_rri('RRS_NO_ROTATION')

        mock_params = create_mock_params()

        cmd = PAMRouterGetRotationInfo()
        result = cmd.execute(mock_params, record_uid=record_uid, format='json')

        self.assertIsNotNone(result, "Expected JSON string, got None")
        data = json.loads(result)
        self.assertIn('status', data)
        self.assertFalse(data['ready_to_rotate'])

    @patch('keepercommander.commands.discoveryrotation.router_get_rotation_schedules')
    @patch('keepercommander.commands.discoveryrotation.record_rotation_get')
    def test_table_mode_returns_none(self, mock_rrg, mock_schedules):
        """Table mode (default) prints to stdout and returns None."""
        from keeper_secrets_manager_core.utils import url_safe_str_to_bytes
        record_uid = 'test_record_uid_'
        record_uid_bytes = url_safe_str_to_bytes(record_uid)

        mock_rrg.return_value = self._make_rri('RRS_ONLINE')

        sched_mock = MagicMock()
        sched_mock.schedules = [self._make_schedule(record_uid_bytes)]
        mock_schedules.return_value = sched_mock

        mock_params = create_mock_params()
        mock_params.record_cache = {}

        cmd = PAMRouterGetRotationInfo()
        result = cmd.execute(mock_params, record_uid=record_uid, format='table')
        self.assertIsNone(result)

