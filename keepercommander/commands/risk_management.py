import argparse
import datetime
import json

from . import base, enterprise_common, audit_alerts
from .. import api, constants
from ..proto import rmd_pb2


class RiskManagementReportCommand(base.GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('enterprise-stat', RiskManagementEnterpriseStatCommand(), 'Show Risk Management recent login count', 'es')
        self.register_command('enterprise-stat-details', RiskManagementEnterpriseStatDetailsCommand(), 'Gets the recent login count (users who logged in the last 30 days) '
                              'and the number of users who have at least one record in their Vault', 'esd')
        self.register_command('security-alerts-summary', RiskManagementSecurityAlertsSummaryCommand(), 'Gets the summary of events that happened in the last 30 days with '
                              'a comparison to the previous 30 days', 'sas')
        self.register_command('security-alerts-detail', RiskManagementSecurityAlertDetailCommand(), 'Gets the details of event that happened in the last 30 days with a '
                              'comparison to the previous 30 days', 'sad')
        self.register_command('security-benchmarks-get', RiskManagementSecurityBenchmarksGetCommand(), 'Get the list of security benchmark set for the calling enterprise', 'sbg')
        self.register_command('security-benchmarks-set', RiskManagementSecurityBenchmarksSetCommand(), 'Set a list of security benchmark. Corresponding audit events will be logged', 'sbs')
        #Backward compatibility
        self.register_command('user', RiskManagementEnterpriseStatDetailsCommand(), 'Show Risk Management User report (absolete)', 'u')
        self.register_command('alert', RiskManagementSecurityAlertsSummaryCommand(), 'Show Risk Management Alert report (absolete)', 'a')


rmd_enterprise_stat_parser = argparse.ArgumentParser(prog='risk-management enterprise-stat', description='Risk management enterprise stat', parents=[base.report_output_parser])

rmd_enterprise_stat_detail_parser = argparse.ArgumentParser(prog='risk-management enterprise-stat-details', description='Risk management enterprise stat details', parents=[base.report_output_parser])

rmd_security_alerts_summary_parser = argparse.ArgumentParser(prog='risk-management security-alerts-summary', description='Risk management security alerts summary', parents=[base.report_output_parser])

rmd_security_alerts_detail_parser = argparse.ArgumentParser(prog='risk-management security-alerts-detail', description='Risk management security alerts detail', parents=[base.report_output_parser])
rmd_security_alerts_detail_parser.add_argument('aet', nargs='?', type=str, action='store', help='show the details for audit event type.')

rmd_security_benchmarks_get_parser = argparse.ArgumentParser(prog='risk-management security-benchmarks-get', description='Risk management get security benchmarks', parents=[base.report_output_parser])
rmd_security_benchmarks_get_parser.add_argument('--description', dest='description', action='store_true', help='Add description.')

rmd_security_benchmarks_set_parser = argparse.ArgumentParser(prog='risk-management security-benchmarks-set', description='Risk management set security benchmarks', parents=[base.report_output_parser])
rmd_security_benchmarks_set_parser.add_argument('fields', nargs='*', type=str, action='store', help='fields to set for benchmark results.')

class RiskManagementEnterpriseStatDetailsCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_enterprise_stat_detail_parser

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


class RiskManagementSecurityAlertsSummaryCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_alerts_summary_parser

    def execute(self, params, **kwargs):
        audit_alerts.AuditSettingMixin.load_settings(params, False)
        event_lookup = {x[0]: x[1] for x in audit_alerts.AuditSettingMixin.EVENT_TYPES}
        fmt = kwargs.get('format')
        if fmt == 'json':
            header = ['event', 'event_occurrences', 'last_events', 'unique_users', 'last_users', 'event_title']
        else:
            header = ['event', 'event_occurrences', 'last_events', 'unique_users', 'last_users', 'event_title', 'event_trend', 'user_trend']
        rows = []
        rs = api.communicate_rest(params, None, 'rmd/get_security_alerts_summary', rs_type=rmd_pb2.SecurityAlertsSummaryResponse)
        for sas in rs.securityAlertsSummary:
            event_id = sas.auditEventTypeId
            if event_id in event_lookup:
                event_id = event_lookup[event_id]
            event_title = constants.AUDIT_EVENT_STATE_MAPPING.get(event_id, "")
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
                rows.append([event_id, event_count, prev_event_count, user_count, prev_user_count, event_title])
            else:
                rows.append([event_id, event_count, prev_event_count, user_count, prev_user_count, event_title, event_trend, user_trend])

        if kwargs.get('format') != 'json':
            header = [base.field_to_title(x) for x in header]

        return base.dump_report_data(rows, headers=header, fmt=kwargs.get('format'), filename=kwargs.get('output'))


class RiskManagementEnterpriseStatCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_enterprise_stat_parser

    def execute(self, params, **kwargs):
        rs = api.communicate_rest(params, None, 'rmd/get_enterprise_stat', rs_type=rmd_pb2.EnterpriseStat)
        fmt = kwargs.get('format')
        #filename=kwargs.get('output')
        if fmt == 'json':
            print(json.dumps({
                "users_logged_recent": rs.usersLoggedRecent,
                "users_has_records":  rs.usersHasRecords,
                }))
        else:
            print('{0:>20s}:'.format('Users Enterprise Stat'))
            print('{0:>20s}: {1:<20d}'.format('Logged in', rs.usersLoggedRecent))
            print('{0:>20s}: {1:<20d}'.format('Has records', rs.usersHasRecords))


class RiskManagementSecurityAlertDetailCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_alerts_detail_parser

    def execute(self, params, **kwargs):
        audit_alerts.AuditSettingMixin.load_settings(params, False)
        event_lookup = {x[1]: x[0] for x in audit_alerts.AuditSettingMixin.EVENT_TYPES}
        user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise.get('users', [])}
        request = rmd_pb2.SecurityAlertsDetailRequest()
        aet = kwargs.get('aet')
        aetid = event_lookup.get(aet, 0)
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
                enterprise_user_id = node.enterpriseUserId
                username = user_lookup.get(enterprise_user_id) or str(enterprise_user_id)
                last_occurrence = None
                if node.lastOccurrence and node.lastOccurrence > 0:
                    last_occurrence = datetime.datetime.fromtimestamp(node.lastOccurrence // 1000)
                rows.append([
                    username,
                    node.currentCount,
                    node.previousCount,
                    last_occurrence,
                    ])
        return base.dump_report_data(rows, headers=header, fmt=out_format, filename=kwargs.get('output'))


class RiskManagementSecurityBenchmarksGetCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_benchmarks_get_parser

    def execute(self, params, **kwargs):
        is_description = kwargs.get('description')
        header = [
                'id',
                'status',
                'last_updated',
                'auto_resolve',
                'title',
                ]
        if is_description:
            header.append("description")
        out_format = kwargs.get('format')
        if out_format != 'json':
            header = [base.field_to_title(x) for x in header]
        rows = []
        response = api.communicate_rest(params, None, 'rmd/get_security_benchmarks', rs_type=rmd_pb2.GetSecurityBenchmarksResponse)
        for node in response.enterpriseSecurityBenchmarks:
            last_updated = None
            if node.lastUpdated and node.lastUpdated > 0:
                last_updated = datetime.datetime.fromtimestamp(node.lastUpdated // 1000)
            name = rmd_pb2.SecurityBenchmark.Name(node.securityBenchmark)
            row = [
                name,
                rmd_pb2.SecurityBenchmarkStatus.Name(node.securityBenchmarkStatus),
                last_updated,
                node.autoResolve,
                constants.RMD_BENCHMARK_MAPPING.get(name, {}).get("title", ""),
                ]
            if is_description:
                row.append(constants.RMD_BENCHMARK_MAPPING.get(name, {}).get("description", ""))
            rows.append(row)
        return base.dump_report_data(rows, headers=header, fmt=out_format, filename=kwargs.get('output'))


class RiskManagementSecurityBenchmarksSetCommand(enterprise_common.EnterpriseCommand):
    def get_parser(self):
        return rmd_security_benchmarks_set_parser

    def execute(self, params, **kwargs):
        request = rmd_pb2.SetSecurityBenchmarksRequest()
        fields = kwargs.get('fields', [])
        for field in fields:
            k, v = field.strip().split(":")
            esb = rmd_pb2.EnterpriseSecurityBenchmark()
            esb.securityBenchmark = rmd_pb2.SecurityBenchmark.Value(k)
            esb.securityBenchmarkStatus = rmd_pb2.SecurityBenchmarkStatus.Value(v)
            request.enterpriseSecurityBenchmarks.append(esb)
        api.communicate_rest(params, request, 'rmd/set_security_benchmarks', rs_type=None)
        print("Done")
