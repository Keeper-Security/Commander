import argparse
import datetime

from . import base, enterprise_common, audit_alerts
from .. import api
from ..proto import rmd_pb2


class RiskManagementReportCommand(base.GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('user', RiskManagementUserReportCommand(), 'Show Risk Management User report', 'u')
        self.register_command('alert', RiskManagementAlertReportCommand(), 'Show Risk Management Alert report', 'a')


rmd_user_parser = argparse.ArgumentParser(prog='risk-management user', description='Risk management user report', parents=[base.report_output_parser])

rmd_alert_parser = argparse.ArgumentParser(prog='risk-management alert', description='Risk management alert report', parents=[base.report_output_parser])

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
