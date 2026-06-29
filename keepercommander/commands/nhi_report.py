#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import csv
import json
import logging
import os
import re
from typing import Optional, Set, Tuple, List, Dict

from .aram import AuditReportCommand
from .base import dump_report_data, raise_parse_exception, report_output_parser, suppress_exit, Command
from ..error import CommandError
from ..params import KeeperParams

PAM_USER_EVENT_TYPES = {
    'record_rotation_scheduled_ok',
    'record_rotation_on_demand_ok',
}

PAM_RESOURCE_EVENT_TYPES = {
    'pam_tunnel_started',
    'pam_kcm_connection_started',
    'pam_rbi_started',
    'pam_session_recording_started',
    'pam_session_rbi_recording_started',
}

PAM_GATEWAY_EVENT_TYPES = {
    'pam_gateway_online',
}

ALL_PAM_EVENT_TYPES = PAM_USER_EVENT_TYPES | PAM_RESOURCE_EVENT_TYPES | PAM_GATEWAY_EVENT_TYPES

_UID_RE = re.compile(r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{22}(?![A-Za-z0-9_-])')
_GATEWAY_ONLINE_UID_RE = re.compile(r'\(UID: ([^)]+)\)')

_CREATED_LABELS = {
    'today':         'Today',
    'yesterday':     'Yesterday',
    'last_7_days':   'Last 7 Days',
    'last_30_days':  'Last 30 Days',
    'month_to_date': 'Month to Date',
    'last_month':    'Last Month',
    'year_to_date':  'Year to Date',
    'last_year':     'Last Year',
}

NHI_SCOPE_NOTE = (
    'Note: This NHI report only includes active PAM record types '
    '(PAM Users and PAM Resources) and active Keeper Gateways. '
    'KSM Devices are not included in this calculation.'
)

nhi_report_parser = argparse.ArgumentParser(
    prog='nhi-report',
    description='Generate a Non-Human Identity (NHI) report listing PAM users, PAM resources, and gateways',
    parents=[report_output_parser],
)
nhi_report_parser.add_argument(
    '--created', dest='created', action='store', default='year_to_date',
    help='Date filter. Predefined: today, yesterday, last_7_days, last_30_days, month_to_date, '
         'last_month, year_to_date, last_year. Custom: "between YYYY-MM-DD and YYYY-MM-DD". '
         '(Default: year_to_date)',
)
nhi_report_parser.add_argument(
    '-v','--verbose', dest='verbose', action='store_true', default=False,
    help='Obtain a detailed list in the CLI. Defaults to a summary.',
)
nhi_report_parser.error = raise_parse_exception
nhi_report_parser.exit = suppress_exit


class NhiReportCommand(Command):
    def get_parser(self):
        return nhi_report_parser

    def execute(self, params: KeeperParams, **kwargs):
        created = kwargs.get('created') or 'year_to_date'
        verbose = kwargs.get('verbose')
        fmt = kwargs.get('format') or 'table'
        output = kwargs.get('output')

        logging.info('Fetching PAM NHI events (created=%s)...', created)
        pam_json = AuditReportCommand().execute(
            params,
            report_type='raw',
            created=created,
            limit=-1,
            format='json',
            event_type=list(ALL_PAM_EVENT_TYPES),
        )

        pam_events = json.loads(pam_json) if pam_json else []

        pam_users, pam_resources, gateways = self._collect_nhi_data(pam_events)

        logging.info(
            'NHI summary: %d PAM users, %d PAM resources, %d gateways',
            len(pam_users), len(pam_resources), len(gateways),
        )
        
        if fmt == 'json':
            return self._export_json(pam_users, pam_resources, gateways, output)
        elif fmt == 'csv':
            return self._export_csv(pam_users, pam_resources, gateways, output)
        elif verbose:
            return self._print_verbose(pam_users, pam_resources, gateways, created)
        else:
            self._print_summary(pam_users, pam_resources, gateways, created)

    @staticmethod
    def _collect_nhi_data(
        pam_events: list,
    ) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        pam_users = {}
        pam_resources = {}
        gateways = {}

        for event in pam_events:
            event_type = event.get('audit_event_type', '')
            event_data = {"recorded_event":event_type,"timestamp":event.get('created','')}
            message = event.get('message', '')
            if event_type in PAM_GATEWAY_EVENT_TYPES:
                m = _GATEWAY_ONLINE_UID_RE.search(message)
                if m:
                    gateways[m.group(1)] = {'uid':m.group(1), 'nhi_type':'gateway'} | event_data
            elif event_type in PAM_USER_EVENT_TYPES:
                uid = _extract_uid(message)
                if uid:
                    pam_users[uid] = {"uid":uid, 'nhi_type':'pam_user'} | event_data
            elif event_type in PAM_RESOURCE_EVENT_TYPES:
                uid = _extract_uid(message)
                if uid:
                    pam_resources[uid] = {"uid":uid, 'nhi_type':'pam_resource'} | event_data

        # Sort each list by first recorded event
        sorted_pam_users = sorted(list(pam_users.values()), key=lambda d: d["timestamp"])
        sorted_pam_resources = sorted(list(pam_resources.values()), key=lambda d: d["timestamp"])
        sorted_gateways = sorted(list(gateways.values()), key=lambda d: d["timestamp"])

        return sorted_pam_users, sorted_pam_resources, sorted_gateways

    @staticmethod
    def _export_json(
        pam_users: List[Dict],
        pam_resources: List[Dict],
        gateways: List[Dict],
        output: Optional[str],
    ):
        all_items = pam_users + pam_resources + gateways
        report = {
            'note': NHI_SCOPE_NOTE,
            'all': all_items,
            'pam_users': pam_users,
            'pam_resources': pam_resources,
            'gateways': gateways,
        }
        if output:
            _, ext = os.path.splitext(output)
            if not ext:
                output += '.json'
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            logging.info('Report path: %s', os.path.abspath(output))
        else:
            return json.dumps(report, indent=2)

    @staticmethod
    def _export_csv(
        pam_users: List[Dict],
        pam_resources: List[Dict],
        gateways: List[Dict],
        output: Optional[str],
    ):
        rows = (
            [[x['uid'], 'PAM User', x['recorded_event'], x['timestamp']] for x in pam_users] +
            [[x['uid'], 'PAM Resource', x['recorded_event'], x['timestamp']] for x in pam_resources] +
            [[x['uid'], 'Gateway', x['recorded_event'], x['timestamp']] for x in gateways]
        )

        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([NHI_SCOPE_NOTE])
        writer.writerow([])
        writer.writerow(['UID', 'NHI Type', 'Recorded Event', 'Timestamp'])
        writer.writerows(rows)
        writer.writerow([])
        writer.writerow(['Total', len(rows)])

        if output:
            _, ext = os.path.splitext(output)
            if not ext:
                output += '.csv'
            with open(output, 'w', newline='', encoding='utf-8') as f:
                f.write(buf.getvalue())
            logging.info('Report path: %s', os.path.abspath(output))
        else:
            return buf.getvalue()

    @staticmethod
    def _print_summary(
        pam_users: List[Dict],
        pam_resources: List[Dict],
        gateways: List[Dict],
        created: str,
    ):
        total = len(pam_users) + len(pam_resources) + len(gateways)
        rows = [
            ['PAM Users',     len(pam_users)],
            ['PAM Resources', len(pam_resources)],
            ['Gateways',      len(gateways)],
            ['Total',         total],
        ]
        date_label = _CREATED_LABELS.get(created, created)
        print(f'\n{NHI_SCOPE_NOTE}\n')
        dump_report_data(rows, ['nhi_type', 'count'], title=f'NHI Report Summary  |  Date Range: {date_label}', fmt='table')
        print('\nFor the full detailed list, export using:')
        print('  nhi-report --format=csv --output=nhi_report.csv')
        print('  nhi-report --format=json --output=nhi_report.json')

    @staticmethod
    def _print_verbose(
        pam_users: List[Dict],
        pam_resources: List[Dict],
        gateways: List[Dict],
        created: str,
    ):
        rows = [[x['uid'], 'PAM User', x['recorded_event'], x['timestamp']] for x in pam_users + pam_resources + gateways]
        
        date_label = _CREATED_LABELS.get(created, created)
        dump_report_data(rows, ['UID', 'NHI Type', 'Recorded Event', 'Event Timestamp'], title=f'NHI Report Summary  |  Date Range: {date_label}', fmt='table')
        

def _extract_uid(message: str) -> Optional[str]:
    """Return the first 22-char Keeper record UID found anywhere in the
    message, or None if no such token exists. Matches must be bounded
    by non-UID characters so substrings of longer tokens are skipped."""
    if not message:
        return None
    m = _UID_RE.search(message)
    return m.group(0) if m else None
