import argparse
import datetime
import json

from . import base, enterprise_common, audit_alerts
from .. import api
from ..proto import rmd_pb2


class RiskManagementReportCommand(base.GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('user', RiskManagementUserReportCommand(), 'Show Risk Management User report', 'u')
        self.register_command('alert', RiskManagementAlertReportCommand(), 'Show Risk Management Alert report', 'a')
        self.register_command('enterprise-stat', RiskManagementEnterpriseStatCommand(), 'Show Risk Management recent login count', 'es')
        self.register_command('enterprise-stat-details', RiskManagementEnterpriseStatDetailsCommand(), 'Gets the recent login count (users who logged in the last 30 days) '
                              'and the number of users who have at least one record in their Vault', 'esd')
        self.register_command('security-alerts-summary', RiskManagementSecurityAlertsSummaryCommand(), 'Gets the summary of events that happened in the last 30 days with '
                              'a comparison to the previous 30 days.', 'sas')
        self.register_command('security-alerts-detail', RiskManagementSecurityAlertDetailCommand(), 'Gets the details of event that happened in the last 30 days with a '
                              'comparison to the previous 30 days. The response is paginated with a page size of 10000 users.', 'sad')
        self.register_command('security-benchmarks-get', RiskManagementSecurityBenchmarksGetCommand(), 'Get the list of security benchmark set for the calling enterprise.', 'sbg')
        self.register_command('security-benchmarks-set', RiskManagementSecurityBenchmarksGetCommand(), 'Set a list of security benchmark.  Corresponding audit events will be logged.', 'sbs')


rmd_user_parser = argparse.ArgumentParser(prog='risk-management user', description='Risk management user report', parents=[base.report_output_parser])

rmd_alert_parser = argparse.ArgumentParser(prog='risk-management alert', description='Risk management alert report', parents=[base.report_output_parser])

rmd_enterprise_stat_detail_parser = argparse.ArgumentParser(prog='risk-management enterprise-stat-details', description='Risk management enterprise stat details', parents=[base.report_output_parser])

rmd_security_alerts_summary_parser = argparse.ArgumentParser(prog='risk-management security-alerts-summary', description='Risk management security alerts summary', parents=[base.report_output_parser])

rmd_security_alerts_detail_parser = argparse.ArgumentParser(prog='risk-management security-alerts-detail', description='Risk management security alerts detail', parents=[base.report_output_parser])
rmd_security_alerts_detail_parser.add_argument(
    '--aetid', dest='aetid', type=int, action='store',
    help='show the details for audit event type ID.')

rmd_security_benchmarks_get_parser = argparse.ArgumentParser(prog='risk-management security-benchmarks-get', description='Risk management get security benchmarks', parents=[base.report_output_parser])

class RiskManagementUserReportCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_user_parser

    def execute(self, params, **kwargs):
        user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise.get('users', [])}
        rows = []
        header = ['username', 'last_logged_in', 'has_records']
        done = False
        last_updated = 0
        t_last_updated = 0
        t_last_id = 0
        while not done:
            rq = rmd_pb2.EnterpriseStatDetailsRequest()
            if last_updated > 0:
                rq.lastUpdated = last_updated
            if t_last_id > 0:
                rq.continuationToken.enterpriseUserId = t_last_id
            if t_last_updated > 0:
                rq.continuationToken.lastUpdated = t_last_updated

            rs = api.communicate_rest(params, rq, 'rmd/get_enterprise_stat_details', rs_type=rmd_pb2.EnterpriseStatDetailsResponse)
            done = rs.hasMore is False
            if not done:
                last_updated = rs.lastUpdated
                t_last_updated = rs.continuationToken.lastUpdated
                t_last_id = rs.continuationToken.enterpriseUserId
            for detail in rs.enterpriseStatDetails:
                enterprise_user_id = detail.enterpriseUserId
                username = user_lookup.get(enterprise_user_id) or str(enterprise_user_id)
                if detail.lastLoggedIn > 0:
                    last_logged_in = datetime.datetime.fromtimestamp(detail.lastLoggedIn // 1000)
                else:
                    last_logged_in = None

                rows.append([username, last_logged_in, detail.hasRecords])

        if kwargs.get('format') != 'json':
            header = [base.field_to_title(x) for x in header]

        return base.dump_report_data(rows, headers=header, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class RiskManagementAlertReportCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_alert_parser

    def execute(self, params, **kwargs):
        audit_alerts.AuditSettingMixin.load_settings(params, False)
        event_lookup = {x[0]: x[1] for x in audit_alerts.AuditSettingMixin.EVENT_TYPES}
        fmt = kwargs.get('format')
        if fmt == 'json':
            header = ['event', 'event_occurrences', 'last_events', 'unique_users', 'last_users']
        else:
            header = ['event', 'event_occurrences', 'last_events', 'unique_users', 'last_users', 'event_trend', 'user_trend']
        rows = []
        rs = api.communicate_rest(params, None, 'rmd/get_security_alerts_summary', rs_type=rmd_pb2.SecurityAlertsSummaryResponse)
        for sas in rs.securityAlertsSummary:
            event_id = sas.auditEventTypeId
            if event_id in event_lookup:
                event_id = event_lookup[event_id]
            event_count = sas.currentCount
            prev_event_count = sas.previousCount
            user_count = sas.currentUserCount
            prev_user_count = sas.previousUserCount

            if event_count != prev_event_count:
                if prev_event_count > 0 and event_count > 0:
                    rate = (event_count - prev_event_count) / prev_event_count
                    event_trend = '[   ↗ ]' if rate > 0 else '[ ↘   ]'
                elif prev_event_count > 0:
                    event_trend = '[    ↑]'
                else:
                    event_trend = '[↓    ]'
            else:
                event_trend = '[  -  ]'

            if user_count != prev_user_count:
                if prev_event_count > 0 and user_count > 0:
                    rate = (user_count - prev_user_count) / prev_user_count
                    user_trend = '[   ↗ ]' if rate > 0 else '[ ↘   ]'
                elif prev_event_count > 0:
                    user_trend = '[    ↑]'
                else:
                    user_trend = '[↓    ]'
            else:
                user_trend = '[  -  ]'

            if fmt == 'json':
                rows.append([event_id, event_count, prev_event_count, user_count, prev_user_count])
            else:
                rows.append([event_id, event_count, prev_event_count, user_count, prev_user_count, event_trend, user_trend])

        if kwargs.get('format') != 'json':
            header = [base.field_to_title(x) for x in header]

        return base.dump_report_data(rows, headers=header, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class RiskManagementEnterpriseStatCommand(enterprise_common.EnterpriseCommand):
    def execute(self, params, **kwargs):
        rs = api.communicate_rest(params, None, 'rmd/get_enterprise_stat', rs_type=rmd_pb2.EnterpriseStat)
        print('{0:>20s}:'.format('Users Enterprise Stat'))
        print('{0:>20s}: {1:<20d}'.format('Logged in', rs.usersLoggedRecent))
        print('{0:>20s}: {1:<20d}'.format('Has records', rs.usersHasRecords))


class RiskManagementEnterpriseStatDetailsCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_enterprise_stat_detail_parser

    def execute(self, params, **kwargs):
        request = rmd_pb2.EnterpriseStatDetailsRequest()
        done = False
        header = [
                'enterprise_user_id',
                'last_logged_in',
                'has_records',
                ]
        out_format = kwargs.get('format')
        if out_format != 'json':
            header = [base.field_to_title(x) for x in header]
        rows = []
        while not done:
            response = api.communicate_rest(params, request, 'rmd/get_enterprise_stat_details', rs_type=rmd_pb2.EnterpriseStatDetailsResponse)
            done = not response.hasMore
            request.continuationToken.lastUpdated = response.continuationToken.lastUpdated
            request.continuationToken.enterpriseUserId = response.continuationToken.enterpriseUserId
            for esd in response.enterpriseStatDetails:
                rows.append([esd.enterpriseUserId, esd.lastLoggedIn, esd.hasRecords])
        return base.dump_report_data(rows, headers=header, fmt=out_format, filename=kwargs.get('output'))


class RiskManagementSecurityAlertsSummaryCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_alerts_summary_parser

    def execute(self, params, **kwargs):
        header = [
                'audit_event_type_id',
                'current_count',
                'current_user_count',
                'previous_count',
                'previous_user_count',
                ]
        out_format = kwargs.get('format')
        if out_format != 'json':
            header = [base.field_to_title(x) for x in header]
        rows = []
        response = api.communicate_rest(params, None, 'rmd/get_security_alerts_summary', rs_type=rmd_pb2.SecurityAlertsSummaryResponse)
        for node in response.securityAlertsSummary:
            rows.append([
                node.auditEventTypeId,
                node.currentCount,
                node.currentUserCount,
                node.previousCount,
                node.previousUserCount,
                ])
        return base.dump_report_data(rows, headers=header, fmt=out_format, filename=kwargs.get('output'))


class RiskManagementSecurityAlertDetailCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_alerts_detail_parser

    def execute(self, params, **kwargs):
        request = rmd_pb2.SecurityAlertsDetailRequest()
        aetid = kwargs.get('aetid') or 0
        if aetid < 1:
            raise ValueError(f'Invalid aetid {aetid}: valid aetid > 0')
        request.auditEventTypeId = aetid
        done = False
        header = [
                'enterprise_user_id',
                'current_count',
                'previous_count',
                'last_occurrence',
                ]
        out_format = kwargs.get('format')
        if out_format != 'json':
            header = [base.field_to_title(x) for x in header]
        rows = []
        while not done:
            response = api.communicate_rest(params, request, 'rmd/get_security_alerts_detail', rs_type=rmd_pb2.SecurityAlertsDetailResponse)
            done = not response.hasMore
            request.continuationToken = response.continuationToken
            for node in response.securityAlertDetails:
                rows.append([
                    node.enterpriseUserId,
                    node.currentCount,
                    node.previousCount,
                    node.lastOccurrence,
                    ])
        return base.dump_report_data(rows, headers=header, fmt=out_format, filename=kwargs.get('output'))


class RiskManagementSecurityBenchmarksGetCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_benchmarks_get_parser

    def execute(self, params, **kwargs):
        header = [
                'security_benchmark',
                'status',
                ]
        out_format = kwargs.get('format')
        if out_format != 'json':
            header = [base.field_to_title(x) for x in header]
        rows = []
        response = api.communicate_rest(params, None, 'rmd/get_security_benchmarks', rs_type=rmd_pb2.GetSecurityBenchmarksResponse)
        for node in response.enterpriseSecurityBenchmarks:
            rows.append([
                rmd_pb2.SecurityBenchmark.Name(node.securityBenchmark),
                rmd_pb2.SecurityBenchmarkStatus.Name(node.securityBenchmarkStatus),
                ])
        return base.dump_report_data(rows, headers=header, fmt=out_format, filename=kwargs.get('output'))
