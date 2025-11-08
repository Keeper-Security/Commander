import logging
import json
import io
from datetime import datetime, timedelta
from typing import Optional
from unittest import TestCase, mock

from data_enterprise import EnterpriseEnvironment, get_enterprise_data, enterprise_allocate_ids
from keepercommander import api, crypto, utils, vault
from keepercommander.params import KeeperParams, PublicKeys
from keepercommander.error import CommandError
from data_vault import VaultEnvironment, get_connected_params, get_synced_params
from keepercommander.commands import enterprise, risk_management
from keepercommander.proto import rmd_pb2


vault_env = VaultEnvironment()
ent_env = EnterpriseEnvironment()


class TestRiskManagement(TestCase):
    expected_commands = []


    @staticmethod
    def query_enterprise(params, force=False, tree_key=None):
        # type: (KeeperParams, Optional[bool], Optional[bytes]) -> None
        params.enterprise = get_enterprise_data(params)


    @staticmethod
    def communicate_rest_success(params, request, path, rs_type=None):
        """Mock successful REST API communication matching Commander terminal examples"""
        expected_path = TestRiskManagement.expected_commands.pop(0)

        if path == 'rmd/get_enterprise_stat_details' and expected_path == "RiskManagementEnterpriseStatDetailsCommand":
            # Mock list tokens response matching Commander terminal example
            rs = rmd_pb2.EnterpriseStatDetailsResponse()
            node = rmd_pb2.EnterpriseStatDetail()
            node.enterpriseUserId = ent_env.user1_id
            node.lastLoggedIn = 2
            node.hasRecords = False
            rs.enterpriseStatDetails.append(node)
            return rs
        elif path == 'rmd/get_enterprise_stat' and expected_path == "RiskManagementEnterpriseStatCommand":
            rs = rmd_pb2.EnterpriseStat()
            rs.usersLoggedRecent = 3
            rs.usersHasRecords = 5
            return rs
        elif path == 'rmd/get_security_benchmarks' and expected_path == "RiskManagementSecurityBenchmarksGetCommand":
            rs = rmd_pb2.GetSecurityBenchmarksResponse()
            node = rmd_pb2.EnterpriseSecurityBenchmark()
            node.securityBenchmark = rmd_pb2.SecurityBenchmark.SB_DEPLOY_ACROSS_ENTIRE_ORGANIZATION
            node.securityBenchmarkStatus = rmd_pb2.SecurityBenchmarkStatus.RESOLVED
            node.lastUpdated = 2
            node.autoResolve = True
            rs.enterpriseSecurityBenchmarks.append(node)
            return rs
#        elif path == 'rmd/get_security_alerts_summary' and expected_path == "get_security_alerts_summary":
#            rs = rmd_pb2.SecurityAlertsSummaryResponse()
#            return rs


    def setUp(self):
        TestRiskManagement.expected_commands.clear()
        query_enterprise_mock = mock.patch('keepercommander.api.query_enterprise').start()
        query_enterprise_mock.side_effect = TestRiskManagement.query_enterprise
        communicate_rest_mock = mock.patch('keepercommander.api.communicate_rest').start()
        communicate_rest_mock.side_effect = TestRiskManagement.communicate_rest_success


    def tearDown(self):
        mock.patch.stopall()


    def test_risk_management_enterprise_stat(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = risk_management.RiskManagementEnterpriseStatCommand()
        TestRiskManagement.expected_commands = ['RiskManagementEnterpriseStatCommand']
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.execute(params)
        self.assertEqual(len(TestRiskManagement.expected_commands), 0)

        output = captured_output.getvalue()
        self.assertIn('Logged in: 3', output)
        self.assertIn('Has records: 5', output)


    def test_risk_management_enterprise_stat_details(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = risk_management.RiskManagementEnterpriseStatDetailsCommand()
        TestRiskManagement.expected_commands = ['RiskManagementEnterpriseStatDetailsCommand']
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.execute(params)
        self.assertEqual(len(TestRiskManagement.expected_commands), 0)

        output = captured_output.getvalue()
        self.assertIn('unit.test@company.com', output)
        self.assertIn('1969-12-31 16:00:00', output)


    def test_risk_management_security_alerts_summary(self):
        return
        #TODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODO
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = risk_management.RiskManagementSecurityAlertsSummaryCommand()
        TestRiskManagement.expected_commands = ['RiskManagementSecurityAlertsSummaryCommand']
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.execute(params)
        self.assertEqual(len(TestRiskManagement.expected_commands), 0)

        output = captured_output.getvalue()
        self.assertIn('unit.test@company.com', output)
        self.assertIn('1969-12-31 16:00:00', output)


    def test_risk_management_security_alerts_detail(self):
        return
        #TODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODO
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = risk_management.RiskManagementSecurityAlertDetailCommand()
        TestRiskManagement.expected_commands = ['RiskManagementSecurityAlertDetailCommand']
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.execute(params)
        self.assertEqual(len(TestRiskManagement.expected_commands), 0)

        output = captured_output.getvalue()
        self.assertIn('unit.test@company.com', output)
        self.assertIn('1969-12-31 16:00:00', output)


    def test_risk_management_get_security_benchmarks(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = risk_management.RiskManagementSecurityBenchmarksGetCommand()
        TestRiskManagement.expected_commands = ['RiskManagementSecurityBenchmarksGetCommand']
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.execute(params)
        self.assertEqual(len(TestRiskManagement.expected_commands), 0)

        output = captured_output.getvalue()
        self.assertIn('SB_DEPLOY_ACROSS_ENTIRE_ORGANIZATION', output)
        self.assertIn('RESOLVED', output)
        self.assertIn('1969-12-31 16:00:00', output)


    def test_risk_management_set_security_benchmarks(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = risk_management.RiskManagementSecurityBenchmarksSetCommand()
        TestRiskManagement.expected_commands = ['RiskManagementSecurityBenchmarksSetCommand']
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.execute(params)
        self.assertEqual(len(TestRiskManagement.expected_commands), 0)

        output = captured_output.getvalue()
        self.assertIn('Done', output)
