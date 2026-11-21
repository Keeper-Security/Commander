from unittest import TestCase, mock

from keepercommander.commands import msp
from keepercommander.commands.msp import MSPInfoCommand, SwitchToMcCommand, SwitchToMspCommand, get_mc_by_name_or_id
from keepercommander.error import CommandError
from keepercommander.params import KeeperParams


class TestMspSwitchToMcColdSession(TestCase):
    def setUp(self):
        msp.current_mc_id = None
        msp.msp_params = None
        msp.mc_params_dict.clear()

    def tearDown(self):
        msp.current_mc_id = None
        msp.msp_params = None
        msp.mc_params_dict.clear()

    @mock.patch('keepercommander.commands.msp.api.login_and_get_mc_params_login_v3')
    @mock.patch('keepercommander.commands.msp.api.query_enterprise')
    def test_switch_to_mc_auto_hydrates_enterprise_when_cold(self, mock_query_ent, mock_login_mc):
        params = KeeperParams()
        params.enterprise = None
        mc_params = KeeperParams()
        mc_params.enterprise = {'enterprise_name': 'Child MC'}

        def _hydrate(p, *args, **kwargs):
            p.enterprise = {
                'enterprise_name': 'MSP Root',
                'managed_companies': [
                    {'mc_enterprise_id': 323166, 'mc_enterprise_name': 'Child MC'}
                ],
            }

        mock_query_ent.side_effect = _hydrate
        mock_login_mc.return_value = mc_params

        returned = SwitchToMcCommand().execute(params, mc='323166')
        self.assertIs(returned, mc_params)
        self.assertEqual(msp.current_mc_id, 323166)
        self.assertIs(msp.msp_params, params)
        mock_query_ent.assert_called_once_with(params)
        mock_login_mc.assert_called_once_with(params, 323166)

        # Switch back to MSP resets current_mc_id
        SwitchToMspCommand().execute(params)
        self.assertIsNone(msp.current_mc_id)

    @mock.patch('keepercommander.commands.msp.api.query_enterprise')
    def test_switch_to_mc_raises_command_error_when_not_admin(self, _mock_query_ent):
        params = KeeperParams()
        params.enterprise = None
        with self.assertRaises(CommandError):
            SwitchToMcCommand().execute(params, mc='323166')

    @mock.patch('keepercommander.commands.msp.api.query_enterprise')
    def test_msp_info_auto_hydrates_when_cold(self, mock_query_ent):
        params = KeeperParams()
        params.enterprise = None

        def _hydrate(p, *args, **kwargs):
            p.enterprise = {'enterprise_name': 'MSP Root', 'managed_companies': []}

        mock_query_ent.side_effect = _hydrate
        MSPInfoCommand().execute(params)
        mock_query_ent.assert_called_once_with(params)

    def test_get_mc_by_name_or_id_accepts_int_and_empty_inputs(self):
        self.assertIsNone(get_mc_by_name_or_id(None, '323166'))
        self.assertIsNone(get_mc_by_name_or_id([], None))
        companies = [{'mc_enterprise_id': 323166, 'mc_enterprise_name': 'Acme Child'}]
        self.assertEqual(get_mc_by_name_or_id(companies, 323166), companies[0])
        self.assertEqual(get_mc_by_name_or_id(companies, 'acme child'), companies[0])
