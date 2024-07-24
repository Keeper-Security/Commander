import argparse
import datetime

from . import base, enterprise_common
from ..proto import rmd_pb2
from .. import api


class RiskManagementReportCommand(base.GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('user', RiskManagementUserReportCommand(), 'Show Risk Management user report.', 'u')
        # self.register_command('alert', RiskManagementAlertReportCommand(), 'Show risk management alert report.', 'a')


rmd_user_parser = argparse.ArgumentParser(prog='risk-management user', description='Risk Management user report', parents=[base.report_output_parser])


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
