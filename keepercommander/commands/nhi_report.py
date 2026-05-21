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
from typing import Optional, Set, Tuple

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

KSM_DEVICE_EVENT_TYPES = {
    'app_client_access',
}

ALL_PAM_EVENT_TYPES = PAM_USER_EVENT_TYPES | PAM_RESOURCE_EVENT_TYPES | PAM_GATEWAY_EVENT_TYPES

_UID_RE = re.compile(r'[A-Za-z0-9_-]{22}$')
_GATEWAY_ONLINE_UID_RE = re.compile(r'\(UID: ([^)]+)\)')
_KSM_DEVICE_RE = re.compile(r'^KSM device (.+?) has accessed secrets')

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

nhi_report_parser = argparse.ArgumentParser(
    prog='nhi-report',
    description='Generate a Non-Human Identity (NHI) report listing PAM users, PAM resources, gateways, and KSM devices',
    parents=[report_output_parser],
)
nhi_report_parser.add_argument(
    '--created', dest='created', action='store', default='year_to_date',
    help='Date filter. Predefined: today, yesterday, last_7_days, last_30_days, month_to_date, '
         'last_month, year_to_date, last_year. Custom: "between YYYY-MM-DD and YYYY-MM-DD". '
         '(Default: year_to_date)',
)
nhi_report_parser.error = raise_parse_exception
nhi_report_parser.exit = suppress_exit


class NhiReportCommand(Command):
    def get_parser(self):
        return nhi_report_parser

    def execute(self, params: KeeperParams, **kwargs):
        created = kwargs.get('created') or 'year_to_date'
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

        logging.info('Fetching device NHI events (created=%s)...', created)
        device_json = AuditReportCommand().execute(
            params,
            report_type='raw',
            created=created,
            limit=-1,
            format='json',
            event_type=list(KSM_DEVICE_EVENT_TYPES),
        )

        pam_events = json.loads(pam_json) if pam_json else []
        device_events = json.loads(device_json) if device_json else []

        pam_users, pam_resources, gateways, ksm_devices = self._collect_nhi_data(pam_events, device_events)

        logging.info(
            'NHI summary: %d PAM users, %d PAM resources, %d gateways, %d KSM devices',
            len(pam_users), len(pam_resources), len(gateways), len(ksm_devices),
        )

        if fmt == 'json':
            return self._export_json(pam_users, pam_resources, gateways, ksm_devices, output)
        elif fmt == 'csv':
            return self._export_csv(pam_users, pam_resources, gateways, ksm_devices, output)
        else:
            self._print_summary(pam_users, pam_resources, gateways, ksm_devices, created)

    @staticmethod
    def _collect_nhi_data(
        pam_events: list,
        device_events: list,
    ) -> Tuple[Set[str], Set[str], Set[str], Set[str]]:
        pam_users: Set[str] = set()
        pam_resources: Set[str] = set()
        gateways: Set[str] = set()

        for event in pam_events:
            event_type = event.get('audit_event_type', '')
            message = event.get('message', '')
            if event_type in PAM_GATEWAY_EVENT_TYPES:
                m = _GATEWAY_ONLINE_UID_RE.search(message)
                if m:
                    gateways.add(m.group(1))
            elif event_type in PAM_USER_EVENT_TYPES:
                uid = _extract_uid(message)
                if uid:
                    pam_users.add(uid)
            elif event_type in PAM_RESOURCE_EVENT_TYPES:
                uid = _extract_uid(message)
                if uid:
                    pam_resources.add(uid)

        ksm_devices: Set[str] = set()

        for event in device_events:
            message = event.get('message', '')
            ksm_match = _KSM_DEVICE_RE.match(message)
            if ksm_match:
                ksm_devices.add(ksm_match.group(1))

        return pam_users, pam_resources, gateways, ksm_devices

    @staticmethod
    def _export_json(
        pam_users: Set[str],
        pam_resources: Set[str],
        gateways: Set[str],
        ksm_devices: Set[str],
        output: Optional[str],
    ):
        all_items = (
            [{'identifier': uid, 'type': 'PAM User'} for uid in sorted(pam_users)] +
            [{'identifier': uid, 'type': 'PAM Resource'} for uid in sorted(pam_resources)] +
            [{'identifier': name, 'type': 'Gateway'} for name in sorted(gateways)] +
            [{'identifier': name, 'type': 'KSM Device'} for name in sorted(ksm_devices)]
        )
        report = {
            'all': all_items,
            'pam_users': sorted(pam_users),
            'pam_resources': sorted(pam_resources),
            'gateways': sorted(gateways),
            'ksm_devices': sorted(ksm_devices),
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
        pam_users: Set[str],
        pam_resources: Set[str],
        gateways: Set[str],
        ksm_devices: Set[str],
        output: Optional[str],
    ):
        rows = (
            [[uid, 'PAM User'] for uid in sorted(pam_users)] +
            [[uid, 'PAM Resource'] for uid in sorted(pam_resources)] +
            [[name, 'Gateway'] for name in sorted(gateways)] +
            [[name, 'KSM Device'] for name in sorted(ksm_devices)]
        )

        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['identifier', 'type'])
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
        pam_users: Set[str],
        pam_resources: Set[str],
        gateways: Set[str],
        ksm_devices: Set[str],
        created: str,
    ):
        total = len(pam_users) + len(pam_resources) + len(gateways) + len(ksm_devices)
        rows = [
            ['PAM Users',     len(pam_users)],
            ['PAM Resources', len(pam_resources)],
            ['Gateways',      len(gateways)],
            ['KSM Devices',   len(ksm_devices)],
            ['Total',         total],
        ]
        date_label = _CREATED_LABELS.get(created, created)
        dump_report_data(rows, ['nhi_type', 'count'], title=f'NHI Report Summary  |  Date Range: {date_label}', fmt='table')
        print('\nFor the full detailed list, export using:')
        print('  nhi-report --format=csv --output=nhi_report.csv')
        print('  nhi-report --format=json --output=nhi_report.json')


def _extract_uid(message: str) -> Optional[str]:
    parts = message.split()
    if not parts:
        return None
    last = parts[-1]
    return last if _UID_RE.match(last) else None
