import unittest
from unittest.mock import patch, MagicMock

import keepercommander.vault as vault
from keepercommander import utils
from keepercommander.commands.discoveryrotation import PAMGatewayActionRotateCommand

USER_UID = 'OYNvVgpPPJBrVfYOIRtdag'
ROTATION_CONFIG_UID = 'bU2LVM6LjX_hmCoSMDA7vg'
OTHER_CONFIG_UID = 'cU2LVM6LjX_hmCoSMDA7vc'
RESOURCE_UID = 'dU2LVM6LjX_hmCoSMDA7vx'
ROTATION_RESOURCE_UID = 'eU2LVM6LjX_hmCoSMDA7vQ'
GATEWAY_UID = 'gU2LVM6LjX_hmCoSMDA7vg'

MODULE = 'keepercommander.commands.discoveryrotation'


def make_rotation_info(configuration_uid, resource_uid=None):
    ri = MagicMock()
    ri.pwdComplexity = 'complexity'
    ri.configurationUid = utils.base64_url_decode(configuration_uid) if configuration_uid else b''
    ri.resourceUid = utils.base64_url_decode(resource_uid) if resource_uid else b''
    return ri


@patch(f'{MODULE}.print_router_response')
@patch(f'{MODULE}.router_send_action_to_gateway')
@patch(f'{MODULE}.router_get_connected_gateways')
@patch(f'{MODULE}.configuration_controller_get')
@patch(f'{MODULE}.PAMConfigurationListCommand._pam_config_allowed_settings_json', return_value={})
@patch(f'{MODULE}.TunnelDAG')
@patch(f'{MODULE}.get_config_uid')
@patch(f'{MODULE}.get_keeper_tokens', return_value=(b'token', b'tkey', b'key'))
@patch(f'{MODULE}.record_rotation_get')
@patch('keepercommander.vault.KeeperRecord.load')
class TestRecordRotateConfiguration(unittest.TestCase):

    def run_rotate(self, mock_load, mock_ri, mock_get_config_uid, mock_dag, mock_controller, mock_connected,
                   rotation_config_uid, graph_config_uid, rotation_resource_uid=None, graph_resource_uid=RESOURCE_UID):
        user = MagicMock(spec=vault.TypedRecord)
        user.record_uid = USER_UID
        user.record_key = b'\x00' * 32
        mock_load.return_value = user
        mock_ri.return_value = make_rotation_info(rotation_config_uid, rotation_resource_uid)
        mock_get_config_uid.return_value = graph_config_uid
        mock_dag.return_value.get_resource_uid.return_value = graph_resource_uid
        gateway = utils.base64_url_decode(GATEWAY_UID)
        mock_controller.return_value = MagicMock(controllerUid=gateway)
        mock_connected.return_value = MagicMock(controllers=[MagicMock(controllerUid=gateway)])

        params = MagicMock()
        cmd = PAMGatewayActionRotateCommand()
        cmd.self_destruct = None
        cmd.send_email = None
        cmd.record_rotate(params, USER_UID)

    def test_uses_rotation_settings_configuration_over_graph_lookup(self, mock_load, mock_ri, _tokens,
                                                                     mock_get_config_uid, mock_dag, _allowed, mock_controller,
                                                                     mock_connected, mock_send, _print):
        # The graph lookup would return another configuration the user is also linked to.
        self.run_rotate(mock_load, mock_ri, mock_get_config_uid, mock_dag, mock_controller, mock_connected,
                        ROTATION_CONFIG_UID, OTHER_CONFIG_UID)

        mock_get_config_uid.assert_not_called()
        args, kwargs = mock_dag.call_args
        self.assertEqual(args[3], ROTATION_CONFIG_UID)
        self.assertTrue(kwargs.get('is_config'))
        inputs = mock_send.call_args.kwargs['gateway_action'].inputs
        self.assertEqual(inputs.configurationUid, ROTATION_CONFIG_UID)
        self.assertEqual(inputs.resourceRef, RESOURCE_UID)

    def test_falls_back_to_graph_lookup_without_rotation_configuration(self, mock_load, mock_ri, _tokens,
                                                                       mock_get_config_uid, mock_dag, _allowed, mock_controller,
                                                                       mock_connected, mock_send, _print):
        self.run_rotate(mock_load, mock_ri, mock_get_config_uid, mock_dag, mock_controller, mock_connected,
                        None, OTHER_CONFIG_UID)

        mock_get_config_uid.assert_called_once()
        args, kwargs = mock_dag.call_args
        self.assertEqual(args[3], OTHER_CONFIG_UID)
        self.assertTrue(kwargs.get('is_config'))

    def test_falls_back_to_rotation_settings_resource_when_graph_has_none(self, mock_load, mock_ri, _tokens,
                                                                         mock_get_config_uid, mock_dag, _allowed,
                                                                         mock_controller, mock_connected, mock_send,
                                                                         _print):
        self.run_rotate(mock_load, mock_ri, mock_get_config_uid, mock_dag, mock_controller, mock_connected,
                        ROTATION_CONFIG_UID, None, rotation_resource_uid=ROTATION_RESOURCE_UID,
                        graph_resource_uid=None)

        inputs = mock_send.call_args.kwargs['gateway_action'].inputs
        self.assertEqual(inputs.configurationUid, ROTATION_CONFIG_UID)
        self.assertEqual(inputs.resourceRef, ROTATION_RESOURCE_UID)


if __name__ == '__main__':
    unittest.main()
