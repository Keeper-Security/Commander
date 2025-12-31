import logging
import json
import io
from datetime import datetime, timedelta
from typing import Optional
from unittest import TestCase, mock
from unittest.mock import patch

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
    def audit_load_settings(params, reload=False):
        pass

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
        elif path == 'rmd/get_security_alerts_summary' and expected_path == "RiskManagementSecurityAlertsSummaryCommand":
            rs = rmd_pb2.SecurityAlertsSummaryResponse()
            node = rmd_pb2.SecurityAlertsSummary()
            node.auditEventTypeId = 123
            node.currentCount = 123123
            node.currentUserCount = 321321
            node.previousCount = 123456
            node.previousUserCount = 654321
            rs.securityAlertsSummary.append(node)
            return rs
        elif path == 'rmd/get_security_alerts_detail' and expected_path == "RiskManagementSecurityAlertDetailCommand":
            rs = rmd_pb2.SecurityAlertsDetailResponse()
            node = rmd_pb2.SecurityAlertsDetail()
            node.enterpriseUserId = ent_env.user1_id
            node.currentCount = 123123
            node.previousCount = 321321
            node.lastOccurrence = 2
            rs.securityAlertDetails.append(node)
            return rs


    def setUp(self):
        TestRiskManagement.expected_commands.clear()
        query_enterprise_mock = mock.patch('keepercommander.api.query_enterprise').start()
        query_enterprise_mock.side_effect = TestRiskManagement.query_enterprise
        communicate_rest_mock = mock.patch('keepercommander.api.communicate_rest').start()
        communicate_rest_mock.side_effect = TestRiskManagement.communicate_rest_success
        communicate_rest_mock = mock.patch('keepercommander.commands.audit_alerts.AuditSettingMixin.load_settings').start()
        communicate_rest_mock.side_effect = TestRiskManagement.audit_load_settings


    def tearDown(self):
        mock.patch.stopall()


    def test_risk_management_enterprise_stat_plain(self):
        self.risk_management_enterprise_stat("plain")

    def test_risk_management_enterprise_stat_json(self):
        self.risk_management_enterprise_stat("json")

    def risk_management_enterprise_stat(self, fmt):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = risk_management.RiskManagementEnterpriseStatCommand()
        TestRiskManagement.expected_commands = ['RiskManagementEnterpriseStatCommand']
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.execute(params, format=fmt)
        self.assertEqual(len(TestRiskManagement.expected_commands), 0)

        output = captured_output.getvalue()
        self.assertIn('3', output)
        self.assertIn('5', output)


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

    @patch("keepercommander.commands.audit_alerts.AuditSettingMixin.EVENT_TYPES", [(123, "account_recovery_decline")])
    def test_risk_management_security_alerts_summary(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = risk_management.RiskManagementSecurityAlertsSummaryCommand()
        TestRiskManagement.expected_commands = ['RiskManagementSecurityAlertsSummaryCommand']
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.execute(params)
        self.assertEqual(len(TestRiskManagement.expected_commands), 0)

        output = captured_output.getvalue()
        self.assertIn('account_recovery_decline', output)
        self.assertIn('123123', output)
        self.assertIn('321321', output)
        self.assertIn('123456', output)
        self.assertIn('654321', output)
        self.assertIn('Recovery Phrase Set Declined', output)


    @patch("keepercommander.commands.audit_alerts.AuditSettingMixin.EVENT_TYPES", [(123, "account_recovery_decline")])
    def test_risk_management_security_alerts_detail(self):
        params = get_connected_params()
        api.query_enterprise(params)

        cmd = risk_management.RiskManagementSecurityAlertDetailCommand()
        TestRiskManagement.expected_commands = ['RiskManagementSecurityAlertDetailCommand']
        captured_output = io.StringIO()
        with mock.patch('sys.stdout', captured_output):
            cmd.execute(params, aet="account_recovery_decline")
        self.assertEqual(len(TestRiskManagement.expected_commands), 0)

        output = captured_output.getvalue()
        self.assertIn('unit.test@company.com', output)
        self.assertIn('123123', output)
        self.assertIn('321321', output)


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
        self.assertIn('Deploy across your entire organization', output)


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
