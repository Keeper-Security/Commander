#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import abc
import argparse
import base64
import copy
import datetime
import time
import json
import gzip
import logging
import platform
import re
from functools import partial

from typing import Optional, List, Union

import requests
import socket
import ssl
import hashlib
import hmac

from urllib.parse import urlparse

from .transfer_account import EnterpriseTransferUserCommand
from ..display import bcolors
from ..record import Record
from .recordv2 import RecordAddCommand
from .helpers import audit_report
from .enterprise_common import EnterpriseCommand
from .base import user_choice, suppress_exit, raise_parse_exception, dump_report_data, Command
from .. import api
from ..error import CommandError
from ..params import KeeperParams
from ..proto import enterprise_pb2
from .register import EMAIL_PATTERN
from ..sox import sox_data, get_prelim_data, is_compliance_reporting_enabled
from ..sox.sox_data import RebuildTask
from ..sox.storage_types import StorageRecordAging
from typing import Dict, Callable

audit_report_parser = argparse.ArgumentParser(prog='audit-report', description='Run an audit trail report.')
audit_report_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
audit_report_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'], default='table',
                                 help='output format.')
audit_report_parser.add_argument('--output', dest='output', action='store',
                                 help='output file name. (ignored for table format)')
audit_report_parser.add_argument('--report-type', dest='report_type', action='store', choices=['raw', 'dim', 'hour', 'day', 'week', 'month', 'span'],
                                 help='report type')
audit_report_parser.add_argument('--report-format', dest='report_format', action='store', choices=['message', 'fields'],
                                 help='output format (raw reports only)')
audit_report_parser.add_argument('--columns', dest='columns', action='append',
                                 help='Can be repeated. (ignored for raw reports)')
audit_report_parser.add_argument('--aggregate', dest='aggregate', action='append', choices=['occurrences', 'first_created', 'last_created'],
                                 help='aggregated value. Can be repeated. (ignored for raw reports)')
audit_report_parser.add_argument('--timezone', dest='timezone', action='store',
                                 help='return results for specific timezone')
audit_report_parser.add_argument('--limit', dest='limit', type=int, action='store',
                                 help='maximum number of returned rows (set to -1 to get all rows for raw report-type)')
audit_report_parser.add_argument('--order', dest='order', action='store', choices=['desc', 'asc'],
                                 help='sort order')
audit_report_parser.add_argument('--created', dest='created', action='store',
                                 help='Filter: Created date. Predefined filters: '
                                      'today, yesterday, last_7_days, last_30_days, month_to_date, last_month, '
                                      'year_to_date, last_year')
audit_report_parser.add_argument('--event-type', dest='event_type', action='store',
                                 help='Filter: Audit Event Type')
audit_report_parser.add_argument('--username', dest='username', action='store',
                                 help='Filter: Username of event originator')
audit_report_parser.add_argument('--to-username', dest='to_username', action='store',
                                 help='Filter: Username of event target')
audit_report_parser.add_argument('--geo-location', dest='geo_location', action='store',
                                 help='Filter: Geo location')
audit_report_parser.add_argument('--device-type', dest='device_type', action='store',
                                 help='Filter: Device type')
audit_report_parser.add_argument('--record-uid', dest='record_uid', action='store',
                                 help='Filter: Record UID')
audit_report_parser.add_argument('--shared-folder-uid', dest='shared_folder_uid', action='store',
                                 help='Filter: Shared Folder UID')
min_opt_help = 'limit report to event-specific and local data (skips retrieval of compliance data if not in cache)'
audit_report_parser.add_argument('--minimal', action='store_true', help=min_opt_help)
audit_report_parser.error = raise_parse_exception
audit_report_parser.exit = suppress_exit

audit_log_parser = argparse.ArgumentParser(prog='audit-log', description='Export the enterprise audit log.')
audit_log_parser.add_argument('--anonymize', dest='anonymize', action='store_true',
                              help='Anonymizes audit log by replacing email and user name with corresponding enterprise user id. '
                                   'If user was removed or if user\'s email was changed then the audit report will show that particular entry as deleted user.')
audit_log_parser.add_argument('--target', dest='target', action='store', required=True,
                              choices=['splunk', 'syslog', 'syslog-port', 'sumo', 'azure-la', 'json'],
                              help='export target')
audit_log_parser.add_argument('--record', dest='record', action='store',
                              help='keeper record name or UID')
audit_log_parser.error = raise_parse_exception
audit_log_parser.exit = suppress_exit


aging_report_parser = argparse.ArgumentParser(prog='aging-report', description='Run an aging report.')
aging_report_parser.add_argument('-r', '--rebuild', dest='rebuild', action='store_true',
                                 help='Rebuild record database')
aging_report_parser.add_argument('--no-cache', '-nc', action='store_true',
                                 help='remove any local non-memory storage of data upon command completion')
aging_report_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                                 default='table', help='output format.')
aging_report_parser.add_argument('--output', dest='output', action='store',
                                 help='output file name. (ignored for table format)')
aging_report_parser.add_argument('--period', dest='period', action='store',
                                 help='Period the password has not been modified')
aging_report_parser.add_argument('--username', dest='username', action='store',
                                 help='Report expired passwords for user')
aging_report_parser.error = raise_parse_exception
aging_report_parser.exit = suppress_exit

action_report_parser = argparse.ArgumentParser(prog='action-report', description='Run a user action report.')
action_report_parser.add_argument('--target', '-t', dest='target_user_status', action='store',
                                  choices=['no-logon', 'no-update', 'locked'], default='no-logon',
                                  help='user status to report on')
action_report_parser.add_argument('--days-since', '-d', dest='days_since', action='store', type=int,
                                  help='number of days since event of interest (e.g., login, record add/update, lock)')
action_report_parser.add_argument('--output', dest='output', action='store', help='path to resulting output file')
action_report_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                                  default='table', help='format of output')
action_report_parser.add_argument('--apply-action', '-a', dest='apply_action', action='store',
                                  choices=['lock', 'delete', 'transfer', 'none'], default='none',
                                  help='admin action to apply to each user in the report')
target_user_help = 'email to transfer users to when --apply-action=transfer is specified'
action_report_parser.add_argument('--target-user', action='store', help=target_user_help)
action_report_parser.add_argument('--dry-run', '-n', dest='dry_run', default=False, action='store_true',
                                  help='flag to enable dry-run mode')
force_action_help = 'skip confirmation prompt when applying irreversible admin actions (e.g., delete, transfer)'
action_report_parser.add_argument('--force', action='store_true', help=force_action_help)

syslog_templates = None  # type: Optional[List[str]]

API_EVENT_SUMMARY_ROW_LIMIT = 2000
API_EVENT_RAW_ROW_LIMIT = 1000


def load_syslog_templates(params):
    global syslog_templates
    if syslog_templates is None:
        syslog_templates = {}
        rq = {
            'command': 'get_audit_event_dimensions',
            'columns': ['audit_event_type']
        }
        rs = api.communicate(params, rq)
        for et in rs['dimensions']['audit_event_type']:
            name = et.get('name')
            syslog = et.get('syslog')
            if name and syslog:
                syslog_templates[name] = syslog


class AuditLogBaseExport(abc.ABC):
    def __init__(self):
        self.store_record = False
        self.should_cancel = False

    def chunk_size(self):
        return 1000

    @abc.abstractmethod
    def default_record_title(self):
        pass

    @abc.abstractmethod
    def get_properties(self, record, props):  # type: (Record, dict) -> None
        pass

    @abc.abstractmethod
    def convert_event(self, props, event):
        pass

    @abc.abstractmethod
    def export_events(self, props, events):  # type: (dict, list)  -> None
        pass

    @staticmethod
    def get_event_message(event):
        message = ''
        if event['audit_event_type'] in syslog_templates:
            info = syslog_templates[event['audit_event_type']]
            while True:
                pattern = re.search(r'\${(\w+)}', info)
                if pattern:
                    field = pattern[1]
                    val = event.get(field)
                    if val is None:
                        val = '<missing>'

                    sp = pattern.span()
                    info = info[:sp[0]] + str(val) + info[sp[1]:]
                else:
                    break
            message = info
        return message


class AuditLogSplunkExport(AuditLogBaseExport):
    def __init__(self):
        super(AuditLogSplunkExport, self).__init__()

    def default_record_title(self):
        return 'Audit Log: Splunk'

    def get_properties(self, record, props):
        try:
            logging.captureWarnings(True)
            url = record.login_url
            if not url:
                print('Enter HTTP Event Collector (HEC) endpoint in format [host:port].\nExample: splunk.company.com:8088')
                while not url:
                    address = input('...' + 'Splunk HEC endpoint: '.rjust(32))
                    if not address:
                        return
                    for test_url in ['https://{0}/services/collector'.format(address), 'http://{0}/services/collector'.format(address)]:
                        try:
                            print('Testing \'{0}\' ...'.format(test_url), end='', flush=True)
                            rs = requests.post(test_url, json='', verify=False)
                            if rs.status_code == 401:
                                js = rs.json()
                                if 'code' in js:
                                    if js['code'] == 2:
                                        url = test_url
                        except:
                            pass
                        if url:
                            print('Found.')
                            break
                        else:
                            print('Failed.')
                record.login_url = url
                self.store_record = True
            props['hec_url'] = url

            token = record.password
            if not token:
                while not token:
                    test_token = input('...' + 'Splunk Token: '.rjust(32))
                    if not test_token:
                        return
                    try:
                        auth={'Authorization': 'Splunk {0}'.format(test_token)}
                        rs = requests.post(url, json='', headers=auth, verify=False)
                        if rs.status_code == 400:
                            js = rs.json()
                            if 'code' in js:
                                if js['code'] == 6:
                                    token = test_token
                                elif js['code'] == 10:
                                    logging.error('HEC\'s Indexer Acknowledgement parameter is not supported yet')
                    except:
                        pass
                record.password = token
                self.store_record = True
            props['token'] = token
            props['host'] = platform.node()
        finally:
            logging.captureWarnings(False)

    def convert_event(self, props, event):
        evt = event.copy()
        evt.pop('id')
        created = evt.pop('created')
        js = {
            'time': created,
            'host': props['host'],
            'source': props['enterprise_name'],
            'sourcetype': '_json',
            'event': evt
        }
        return json.dumps(js)

    def export_events(self, props, events):
        auth = { 'Authorization': 'Splunk {0}'.format(props['token']) }
        try:
            logging.captureWarnings(True)
            rs = requests.post(props['hec_url'], data='\n'.join(events), headers=auth, verify=False)
        finally:
            logging.captureWarnings(False)

        if rs.status_code == 200:
            self.store_record = True
        else:
            self.should_cancel = True


class AuditLogSyslogBaseExport(AuditLogBaseExport, abc.ABC):
    def __init__(self):
        super(AuditLogSyslogBaseExport, self).__init__()

    def convert_event(self, props, event):
        pri = 13 * 8 + 6
        dt = datetime.datetime.fromtimestamp(event['created'], tz=datetime.timezone.utc)
        ip = "-"
        if 'ip_address' in event:
            ip = event['ip_address']

        message = '<{0}>1 {1} {2} {3} - {4}'.format(pri, dt.strftime('%Y-%m-%dT%H:%M:%SZ'), ip, 'Keeper', event['id'])

        evt = event.copy()
        evt.pop('id')
        evt.pop('created')
        if 'ip_address' in evt:
            evt.pop('ip_address')
        structured = 'Keeper@Commander'
        for key in evt:
            structured += ' {0}="{1}"'.format(key, evt[key])
        structured = '[' + structured + ']'
        return message + ' ' + structured + ' ' + AuditLogBaseExport.get_event_message(evt)


class AuditLogSyslogFileExport(AuditLogSyslogBaseExport):
    def __init__(self):
        super(AuditLogSyslogFileExport, self).__init__()

    def default_record_title(self):
        return 'Audit Log: Syslog'

    def get_properties(self, record, props):
        filename = record.login
        if not filename:
            print('Enter filename for syslog messages.')
            filename = input('...' + 'Syslog file name: '.rjust(32))
            if not filename:
                return
            if not filename.endswith('.gz'):
                gz = input('...' + 'Gzip messages? (y/N): '.rjust(32))
                if gz.lower() == 'y':
                    filename = filename + '.gz'
            record.login = filename
            self.store_record = True
        props['filename'] = record.login

    def export_events(self, props, events):
        is_gzipped = props['filename'].endswith('.gz')
        logf = gzip.GzipFile(filename=props['filename'], mode='ab') if is_gzipped else open(props['filename'], mode='ab')
        try:
            for line in events:
                logf.write(line.encode('utf-8'))
                logf.write(b'\n')
        finally:
            logf.flush()
            logf.close()


class AuditLogSyslogPortExport(AuditLogSyslogBaseExport):
    def __init__(self):
        super(AuditLogSyslogPortExport, self).__init__()

    def default_record_title(self):
        return 'Audit Log: Syslog Port'

    def get_properties(self, record, props):
        is_new_config = False

        host = None
        port = None
        is_ssl = False
        is_udp = False
        is_octet_counting = False
        url = record.login_url
        if url:
            p = urlparse(url)
            if p.scheme in ['syslog', 'syslogs', 'syslogu']:
                if p.scheme == 'syslogu':
                    is_udp = True
                else:
                    is_ssl = p.scheme == 'syslogs'
                host = p.hostname
                port = p.port

            val = record.get('is_octet_counting')
            if val:
                try:
                    oc = int(val)
                    is_octet_counting = oc > 0
                except:
                    pass

        if not host or not port:
            print('Enter Syslog connection parameters:')
            host_name = input('...' + 'Syslog host name: '.rjust(32))
            if not host_name:
                raise Exception('Syslog host name is empty')
            host = host_name

            conn_type = input('...' + 'Syslog port type [T]cp/[U]dp. Default TCP: '.rjust(32))
            is_udp = conn_type.lower() in ['u', 'udp']
            port_number = input('...' + 'Syslog port number: '.rjust(32))
            if not port_number:
                raise Exception('Syslog port is empty')
            if not port_number.isdigit():
                raise Exception('Syslog port is a numeric value')
            port = int(port_number)
            if not is_udp:
                has_ssl = input('...' + 'Syslog port requires SSL/TLS (y/N): '.rjust(32))
                is_ssl = has_ssl.lower() == 'y'

            is_new_config = True

        if is_new_config:
            print('Connecting to \'{0}:{1}\' ...'.format(host, port))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if not is_udp else socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                if is_ssl:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3)
                    s = context.wrap_socket(sock, server_hostname=host)
                else:
                    s = sock
                s.connect((host, port))
            record.login_url = 'syslog{0}://{1}:{2}'.format('u' if is_udp else 's' if is_ssl else '', host, port)
            record.set_field('is_octet_counting', '1' if is_octet_counting else '0')
            self.store_record = True

        props['is_udp'] = is_udp
        props['is_ssl'] = is_ssl
        props['host'] = host
        props['port'] = port
        props['is_octet_counting'] = is_octet_counting

    def export_events(self, props, events):
        try:
            is_udp = props['is_udp']
            is_octet_counting = props.get('is_octet_counting', False)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM if not is_udp else socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                hostname = props['host']
                if props['is_ssl']:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3)
                    s = context.wrap_socket(sock, server_hostname=hostname)
                else:
                    s = sock
                port = props['port']
                s.connect((hostname, port))
                for line in events:
                    syslog_event = f'{len(line)} {line}' if is_octet_counting else f'{line}\n'
                    s.send(syslog_event.encode('utf-8'))
        except Exception as e:
            logging.debug(e)
            self.should_cancel = True


class AuditLogSumologicExport(AuditLogBaseExport):
    def __init__(self):
        super(AuditLogSumologicExport, self).__init__()

    def default_record_title(self):
        return 'Audit Log: Sumologic'

    def get_properties(self, record, props):
        url = record.login_url
        if not url:
            print('Enter HTTP Logs Collector URL.')
            url = input('...' + 'HTTP Collector URL: '.rjust(32))
            if not url:
                raise Exception('HTTP Collector URL is required.')
            record.login_url = url
            self.store_record = True
        props['url'] = record.login_url

    def convert_event(self, props, event):
        evt = event.copy()
        evt.pop('id')
        dt = datetime.datetime.fromtimestamp(evt.pop('created'), tz=datetime.timezone.utc)
        evt['timestamp'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        evt['message'] = AuditLogBaseExport.get_event_message(evt)
        return json.dumps(evt, separators=(',', ':'))

    def export_events(self, props, events):
        str = '\n'.join(events)

        headers = {"Content-type": "application/text"}
        rs = requests.post(props['url'], data=str.encode('utf-8'), headers=headers)
        if rs.status_code == 200:
            self.store_record = True
        else:
            self.should_cancel = True

    def chunk_size(self):
        return 250


class AuditLogJsonExport(AuditLogBaseExport):
    def __init__(self):
        super(AuditLogJsonExport, self).__init__()

    def default_record_title(self):
        return 'Audit Log: JSON'

    def get_properties(self, record, props):
        filename = record.login
        if not filename:
            filename = input('JSON File name: ')
            if not filename:
                return
            record.login = filename
            self.store_record = True
        props['filename'] = record.login

        with open(filename, mode='w') as logf:
            json.dump([], logf)

    def convert_event(self, props, event):
        dt = datetime.datetime.fromtimestamp(event['created'], tz=datetime.timezone.utc)
        evt = event.copy()
        evt.pop('id')
        evt.pop('created')
        evt['timestamp'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        return evt

    def export_events(self, props, events):
        filename = props['filename']

        with open(filename, mode='r') as logf:
            try:
                data = json.load(logf)
                for record in events:
                    data.append(record)
            except ValueError:
                data = events

        with open(filename, mode='w') as logf:
            json.dump(data, logf)


class AuditLogAzureLogAnalyticsExport(AuditLogBaseExport):
    def __init__(self):
        super(AuditLogAzureLogAnalyticsExport, self).__init__()

    def default_record_title(self):
        return 'Audit Log: Azure Log Analytics'

    def get_properties(self, record, props):
        wsid = record.login
        if not wsid:
            print('Enter Azure Log Analytics workspace ID.')
            wsid = input('Workspace ID: ')
            if not wsid:
                raise Exception('Workspace ID is required.')
            record.login = wsid
            self.store_record = True
        props['wsid'] = record.login

        wskey = record.password
        if not wskey:
            print('Enter Azure Log Analytics primary or secondary key.')
            wskey = input('Key: ')
            if not wskey:
                raise Exception('Key is required.')
            record.password = wskey
            self.store_record = True
        props['wskey'] = record.password

    def convert_event(self, props, event):
        evt = event.copy()
        evt.pop('id')
        dt = datetime.datetime.fromtimestamp(evt.pop('created'), tz=datetime.timezone.utc)
        evt['timestamp'] = dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        return evt

    def export_events(self, props, events):
        url = "https://{0}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01".format(props['wsid'])
        data = json.dumps(events)
        dt = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        shared_key = self.build_shared_key(props['wsid'], props['wskey'], len(data), dt)
        headers = {
            "Authorization": "SharedKey {0}".format(shared_key),
            "Content-type": "application/json",
            "Log-Type": "Keeper",
            "x-ms-date": dt
        }
        rs = requests.post(url, data=data.encode('utf-8'), headers=headers)
        if rs.status_code == 200:
            self.store_record = True
        else:
            print(rs.content)
            self.should_cancel = True

    def chunk_size(self):
        return 250

    @staticmethod
    def build_shared_key(wsid, wskey, content_length, date_string):
        string_to_hash = 'POST\n'
        string_to_hash += '{0}\n'.format(str(content_length))
        string_to_hash += 'application/json\n'
        string_to_hash += 'x-ms-date:{0}\n'.format(date_string)
        string_to_hash += '/api/logs'

        bytes_to_hash = string_to_hash.encode('utf-8')
        decoded_key = base64.b64decode(wskey)
        encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode('utf-8')

        return "{0}:{1}".format(wsid, encoded_hash)


class AuditLogCommand(EnterpriseCommand):
    def get_parser(self):
        return audit_log_parser

    def resolve_uid(self, cache, username):
        uname = username or ''
        uid = cache.get(uname)
        if not uid:
            md5 = hashlib.md5(str(uname).encode('utf-8')).hexdigest()
            cache[uname] = 'DELETED-'+md5
            uid = cache.get(uname)
        return uid

    def execute(self, params, **kwargs):
        load_syslog_templates(params)

        target = kwargs.get('target')

        log_export = None        # type: Optional[AuditLogBaseExport]
        if target == 'splunk':
            log_export = AuditLogSplunkExport()
        elif target == 'syslog':
            log_export = AuditLogSyslogFileExport()
        elif target == 'syslog-port':
            log_export = AuditLogSyslogPortExport()
        elif target == 'sumo':
            log_export = AuditLogSumologicExport()
        elif target == 'json':
            log_export = AuditLogJsonExport()
        elif target == 'azure-la':
            log_export = AuditLogAzureLogAnalyticsExport()
        else:
            raise CommandError('audit-log', 'Audit log export: unsupported target')

        record = None
        record_name = kwargs.get('record') or log_export.default_record_title()
        for r_uid in params.record_cache:
            rec = api.get_record(params, r_uid)
            if record_name in [rec.record_uid, rec.title]:
                record = rec
        if record is None:
            answer = user_choice('Do you want to create a Keeper record to store audit log settings?', 'yn', 'n')
            if answer.lower() == 'y':
                record_title = input('Choose the title for audit log record [Default: {0}]: '.format(record_name)) or log_export.default_record_title()
                cmd = RecordAddCommand()
                record_uid = cmd.execute(params, **{
                    'title': record_title,
                    'force': True
                })
                if record_uid:
                    api.sync_down(params)
                    record = api.get_record(params, record_uid)
        if record is None:
            raise CommandError('audit-log', 'Record not found')

        props = {
            'enterprise_name': params.enterprise['enterprise_name']
        }
        log_export.store_record = False
        log_export.get_properties(record, props)
        if log_export.store_record:
            record_uid = record.record_uid
            api.update_record(params, record, silent=True)
            api.sync_down(params)
            record = api.get_record(params, record_uid)
            log_export.store_record = False

        # query data
        last_event_time = 0
        val = record.get('last_event_time')
        if val:
            try:
                last_event_time = int(val)
            except:
                pass

        events = []
        finished = False
        count = 0
        logged_ids = set()
        chunk_length = log_export.chunk_size()

        anonymize = bool(kwargs.get('anonymize'))
        ent_user_ids = {}
        if anonymize and params.enterprise and 'users' in params.enterprise:
            ent_user_ids = {x.get('username'): x.get('enterprise_user_id') for x in params.enterprise['users']}

        while not finished:
            finished = True
            rq = {
                'command': 'get_audit_event_reports',
                'report_type': 'raw',
                'scope': 'enterprise',
                'limit': 1000,
                'order': 'ascending'
            }

            if last_event_time > 0:
                rq['filter'] = {
                    'created': {'min': last_event_time}
                }

            rs = api.communicate(params, rq)
            if rs['result'] == 'success':
                finished = True
                if 'audit_event_overview_report_rows' in rs:
                    audit_events = rs['audit_event_overview_report_rows']
                    event_count = len(audit_events)
                    if event_count > 1:
                        # remove events from the tail for the last second
                        last_event_time = int(audit_events[-1]['created'])
                        while len(audit_events) > 0:
                            event = audit_events[-1]
                            if int(event['created']) < last_event_time:
                                break
                            audit_events = audit_events[:-1]

                        for event in audit_events:
                            event_id = event['id']
                            if event_id not in logged_ids:
                                logged_ids.add(event_id)
                                if anonymize:
                                    uname = event.get('email') or event.get('username') or ''
                                    ent_uid = self.resolve_uid(ent_user_ids, uname)
                                    event['username'] = ent_uid
                                    event['email'] = ent_uid
                                    to_uname = event.get('to_username') or ''
                                    if to_uname:
                                        event['to_username'] = self.resolve_uid(ent_user_ids, to_uname)
                                    from_uname = event.get('from_username') or ''
                                    if from_uname:
                                        event['from_username'] = self.resolve_uid(ent_user_ids, from_uname)
                                events.append(log_export.convert_event(props, event))

                        finished = len(events) == 0
                        if finished:
                            if event_count > 900:
                                finished = False
                                last_event_time += 1

            while len(events) > 0:
                to_store = events[:chunk_length]
                events = events[chunk_length:]
                log_export.export_events(props, to_store)
                if log_export.should_cancel:
                    finished = True
                    break
                count += len(to_store)
                print('+', end='', flush=True)

        if last_event_time > 0:
            logging.info('')
            logging.info('Exported %d audit event(s)', count)
            if count > 0:
                record.set_field('last_event_time', str(last_event_time))
                params.sync_data = True
                api.update_record(params, record, silent=True)


audit_report_description = '''
Audit Report Command Syntax Description:

Event properties
  id                    event ID
  created               event time
  username              user that created audit event
  to_username           user that is audit event target
  from_username         user that is audit event source
  ip_address            IP address
  audit_event_type      Audit event type
  keeper_version        Keeper application version
  channel               2FA channel
  status                Keeper API result_code
  record_uid            Record UID
  record_title          Record title
  record_url            Record URL
  shared_folder_uid     Shared Folder UID
  shared_folder_title   Shared Folder title
  node                  Node ID (enterprise events only)
  node_title            Node title (enterprise events only)
  team_uid              Team UID (enterprise events only)
  team_title            Team title (enterprise events only)
  role_id               Role ID (enterprise events only)
  role_title            Role title (enterprise events only)

--report-type:
            raw         Returns individual events. All event properties are returned.
                        Valid parameters: filters. Ignored parameters: columns, aggregates

  span hour day	        Aggregates audit event by created date. Span drops date aggregation
     week month         Valid parameters: filters, columns, aggregates

            dim         Returns event property description or distinct values.
                        Valid columns: 
                        audit_event_type, keeper_version, device_type, ip_address, geo_location, 
                        username
                        Ignored parameters: filters, aggregates

--columns:              Defines break down report properties.
                        can be any event property except: id, created

--aggregate:            Defines the aggregate value:
     occurrences        number of events. COUNT(*)
   first_created        starting date. MIN(created)
    last_created        ending date. MAX(created)

--limit:                Limits the number of returned records

--order:                "desc" or "asc"
                        raw report type: created
                        aggregate reports: first aggregate

Filters                 Supported: '=', '>', '<', '>=', '<=', 'IN(<>,<>,<>)'. Default '='
--created               Predefined ranges: today, yesterday, last_7_days, last_30_days, month_to_date, last_month, year_to_date, last_year
                        Range 'BETWEEN <> AND <>'
                        where value is UTC date or epoch time in seconds
--username              User email
--to-username           Target user email
--record-uid            Record UID
--shared-folder-uid     Shared Folder UID
--event-type            Audit Event Type.  Value is event type id or event type name
                        audit-report --report-type=dim --columns=audit_event_type
--geo-location          Geo location. 
                        Example: "El Dorado Hills, California, US", "CH", "Munich,Bayern,DE"
                        audit-report --report-type=dim --columns=geo_location
--device-type           Keeper device/application and optional version
                        Example: "Commander", "Web App, 16.3.4"    
                        audit-report --report-type=dim --columns=device_type                     
'''

in_pattern = re.compile(r"\s*in\s*\(\s*(.*)\s*\)", re.IGNORECASE)
between_pattern = re.compile(r"\s*between\s+(\S*)\s+and\s+(.*)", re.IGNORECASE)


class AuditReportCommand(Command):
    def __init__(self):
        self.sox_data = None    # type: Union[None, sox_data.SoxData]
        self.lookup = {}

    def get_value(self, params, field, event):
        if field == 'message':
            message = ''
            if event['audit_event_type'] in syslog_templates:
                info = syslog_templates[event['audit_event_type']]
                while True:
                    pattern = re.search(r'\${(\w+)}', info)
                    if pattern:
                        token = pattern[1]
                        val = self.get_value(params, token, event) if field != token else None
                        if val is None:
                            logging.error('Event value is missing: %s', pattern[1])
                            val = '<missing>'

                        sp = pattern.span()
                        info = info[:sp[0]] + str(val) + info[sp[1]:]
                    else:
                        break
                message = info
            return message

        elif field in event:
            return event.get(field)

        elif field in audit_report.fields_to_uid_name:
            return self.resolve_lookup(params, field, event)
        return ''

    def resolve_lookup(self, params, field, event):
        lookup_type = audit_report.LookupType.lookup_type_from_field_name(field)
        uid_value = event.get(lookup_type.uid)
        if uid_value:
            if uid_value in self.lookup:
                return self.lookup[uid_value][field]
            else:
                return getattr(self, lookup_type.method)(params, lookup_type, uid_value, field)
        else:
            return ''

    def resolve_record_lookup(self, params, lookup_type, record_uid, field):
        if record_uid not in self.lookup:
            self.lookup[record_uid] = lookup_type.init_fields('')
        if record_uid in params.record_cache:
            r = api.get_record(params, record_uid)
            if r:
                for fld, attr in lookup_type.field_attrs():
                    self.lookup[record_uid][fld] = getattr(r, attr, '')
        else:
            if self.sox_data:
                r = self.sox_data.get_records().get(record_uid)
                if r:
                    for fld, attr in lookup_type.field_attrs():
                        attr = re.sub(r'^login_', '', attr)
                        self.lookup[record_uid][fld] = r.data.get(attr, '')
        return self.lookup[record_uid][field]

    def resolve_shared_folder_lookup(self, params, lookup_type, shared_folder_uid, field):
        if shared_folder_uid not in self.lookup:
            self.lookup[shared_folder_uid] = lookup_type.init_fields('')
        if shared_folder_uid in params.shared_folder_cache:
            sf = api.get_shared_folder(params, shared_folder_uid)
            if sf:
                for fld, attr in lookup_type.field_attrs():
                    self.lookup[shared_folder_uid][fld] = getattr(sf, attr, '')
        return self.lookup[shared_folder_uid][field]

    def resolve_team_lookup(self, params, lookup_type, team_uid, field):
        if params.enterprise and 'teams' in params.enterprise:
            for team in params.enterprise['teams']:
                if 'team_uid' in team:
                    uid = team['team_uid']
                    if uid not in self.lookup:
                        self.lookup[uid] = lookup_type.init_fields('')
                        for fld, attr in lookup_type.field_attrs():
                            self.lookup[uid][fld] = team.get(attr, '')
        if team_uid not in self.lookup:
            self.lookup[team_uid] = lookup_type.init_fields('')
        return self.lookup[team_uid][field]

    def resolve_role_lookup(self, params, lookup_type, role_id, field):
        if params.enterprise and 'roles' in params.enterprise:
            for role in params.enterprise['roles']:
                if 'role_id' in role:
                    uid = str(role['role_id'])
                    if uid not in self.lookup:
                        self.lookup[uid] = lookup_type.init_fields('')
                        for fld, attr in lookup_type.field_attrs():
                            self.lookup[uid][fld] = role['data'].get(attr, '')
        if role_id not in self.lookup:
            self.lookup[role_id] = lookup_type.init_fields('')
        return self.lookup[role_id][field]

    def resolve_node_lookup(self, params, lookup_type, node_id, field):
        if params.enterprise and 'nodes' in params.enterprise:
            for node in params.enterprise['nodes']:
                if 'node_id' in node:
                    uid = str(node['node_id'])
                    if uid not in self.lookup:
                        self.lookup[uid] = lookup_type.init_fields('')
                        for fld, attr in lookup_type.field_attrs():
                            default_value = params.enterprise['enterprise_name'] if attr == 'displayname' else ''
                            self.lookup[uid][fld] = node['data'].get(attr, default_value)
        node_id = str(node_id)
        if node_id not in self.lookup:
            self.lookup[node_id] = lookup_type.init_fields('')
        return self.lookup[node_id][field]

    def get_parser(self):
        return audit_report_parser

    @staticmethod
    def convert_value(field, value, **kwargs):
        if not value:
            return ''

        if field == "created":
            if isinstance(value, str):
                return value
            if isinstance(value, (int, float)):
                dt = datetime.datetime.utcfromtimestamp(int(value)).replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
                rt = kwargs.get('report_type') or ''
                if rt in {'day', 'week'}:
                    dt = dt.date()
                elif rt == 'month':
                    dt = dt.strftime('%B, %Y')
                elif rt == 'hour':
                    dt = dt.strftime('%Y-%m-%d @%H:00')
                return dt
        elif field in {"first_created", "last_created"}:
            return datetime.datetime.utcfromtimestamp(int(value)).replace(tzinfo=datetime.timezone.utc).astimezone(tz=None)
        return value

    DimensionCache = {}
    CachedUsername = ''
    VirtualDimensions = {
        'geo_location': 'ip_address',
        'device_type': 'keeper_version',
    }

    @staticmethod
    def ensure_same_user(params):  # type: (KeeperParams) -> None
        if params.user != AuditReportCommand.CachedUsername:
            AuditReportCommand.DimensionCache.clear()
            AuditReportCommand.CachedUsername = params.user

    @staticmethod
    def load_audit_dimension(params, dimension):  # type: (KeeperParams, str) -> list[dict]
        AuditReportCommand.ensure_same_user(params)
        if dimension in AuditReportCommand.DimensionCache:
            return AuditReportCommand.DimensionCache[dimension]
        dimensions = None  # type: Optional[list]
        if dimension in AuditReportCommand.VirtualDimensions:
            keeper_dimension = AuditReportCommand.load_audit_dimension(
                params, AuditReportCommand.VirtualDimensions[dimension])
            if dimension == 'geo_location':
                geo_dim = {}
                for geo in keeper_dimension:
                    location = geo.get('geo_location')
                    ip = geo.get('ip_address')
                    if location and ip:
                        if location in geo_dim:
                            geo_dim[location]['ip_addresses'].append(ip)
                        else:
                            location_entry = copy.copy(geo)
                            del location_entry['ip_address']
                            location_entry['ip_addresses'] = [ip]
                            geo_dim[location] = location_entry
                dimensions = list(geo_dim.values())
                for geo in dimensions:
                    geo['ip_count'] = len(geo.get('ip_addresses', []))
                dimensions.sort(key=lambda x: f'{x.get("country_code", " ")}|{x.get("region", " ")}|{x.get("city", " ")}',
                                reverse=False)
            elif dimension == 'device_type':
                device_dim = {}
                for version in keeper_dimension:
                    type_id = version.get('type_id')
                    version_id = version.get('version_id')
                    if type_id and version_id:
                        if type_id in device_dim:
                            device_dim[type_id]['version_ids'].append(version_id)
                        else:
                            type_entry = copy.copy(version)
                            del type_entry['version_id']
                            type_entry['version_ids'] = [version_id]
                            device_dim[type_id] = type_entry
                dimensions = list(device_dim.values())
                dimensions.sort(key=lambda x: x.get('type_name', ' '), reverse=False)
        else:
            rq = {
                'command': 'get_audit_event_dimensions',
                'report_type': 'dim',
                'columns': [dimension],
                'limit': 2000,
                'scope': 'enterprise' if params.enterprise else 'user'
            }
            rs = api.communicate(params, rq)
            dimensions = rs['dimensions'][dimension]
            for row in dimensions:
                if dimension == 'ip_address':
                    city = row.get('city', '')
                    region = row.get('region', '')
                    country = row.get('country_code', '')
                    if city or region or country:
                        row['geo_location'] = ', '.join((city, region, country))
            if dimension == 'ip_address':
                dimensions.sort(key=lambda x: f'{x.get("country_code", " ")}|{x.get("region", " ")}|{x.get("city", " ")}',
                                reverse=False)
            elif dimension == 'keeper_version':
                dimensions.sort(key=lambda x: x.get('version_id', 0), reverse=False)

            elif dimension in {'username', 'to_username', 'from_username'}:
                pattern = re.compile(EMAIL_PATTERN, re.IGNORECASE)
                dimensions = [x for x in dimensions if pattern.match(x)]
                dimensions.sort()
        if dimensions:
            AuditReportCommand.DimensionCache[dimension] = dimensions
            return dimensions

    def execute(self, params, **kwargs):
        load_syslog_templates(params)

        if kwargs.get('syntax_help') or not kwargs['report_type']:
            logging.info(audit_report_description)
            if kwargs.get('syntax_help'):
                events = AuditReportCommand.load_audit_dimension(params, 'audit_event_type')
                event_types = [(et['id'], et['name']) for et in events]
                logging.info('The following are possible event type id and event type name values:')
                for event_id, event_name in event_types:
                    logging.info('{0:>10d}:  {1}'.format(event_id, event_name))
            return

        report_type = kwargs.get('report_type', 'raw')
        if report_type == 'dim':
            columns = kwargs['columns']
            if not isinstance(columns, list):
                raise CommandError('audit-report', "'columns' parameter is missing")
            for column in columns:
                dimension = AuditReportCommand.load_audit_dimension(params, column)
                if dimension:
                    table = []
                    if column == 'audit_event_type':
                        fields = ['id', 'name', 'category', 'syslog']
                    elif column == 'keeper_version':
                        fields = ['version_id', 'type_name', 'version', 'type_category']
                    elif column == 'ip_address':
                        fields = ['ip_address', 'city', 'region', 'country_code']
                    elif column == 'geo_location':
                        fields = ['geo_location', 'city', 'region', 'country_code', 'ip_count']
                    elif column == 'device_type':
                        fields = ['type_name', 'type_category']
                    else:
                        fields = [column]
                    for row in dimension:
                        if isinstance(row, dict):
                            table.append([row.get(x) for x in fields])
                        else:
                            table.append([row])
                    return dump_report_data(table, fields, fmt=kwargs.get('format'), filename=kwargs.get('output'))

            return

        rq = {
            'command': 'get_audit_event_reports',
            'report_type': report_type,
            'scope': 'enterprise' if params.enterprise else 'user'
        }
        if kwargs.get('timezone'):
            rq['timezone'] = kwargs['timezone']
        else:
            tt = time.tzname  # type: tuple
            if tt:
                if time.daylight < len(tt):
                    rq['timezone'] = tt[time.daylight]
                else:
                    rq['timezone'] = tt[0]
            else:
                now = time.time()
                utc_offset = datetime.datetime.fromtimestamp(now) - datetime.datetime.utcfromtimestamp(now)
                hours = (utc_offset.days * 24) + int(utc_offset.seconds / 60 / 60)
                rq['timezone'] = hours

        columns = []
        if report_type != 'raw' and kwargs.get('columns'):
            columns = kwargs['columns']
            rq_columns = columns.copy()
            for lookup_field, uid_name in audit_report.fields_to_uid_name.items():
                if lookup_field in rq_columns:
                    rq_columns.remove(lookup_field)
                    if uid_name not in rq_columns:
                        rq_columns.append(uid_name)
            rq['columns'] = list(set(rq_columns))

        aggregates = []
        if report_type != 'raw' and kwargs.get('aggregate'):
            if kwargs.get('aggregate'):
                aggregates = kwargs['aggregate']
                rq['aggregate'] = aggregates

        user_limit = kwargs.get('limit')
        rq_limit = 50 if user_limit is None else user_limit if user_limit > 0 else API_EVENT_RAW_ROW_LIMIT
        rq['limit'] = min(rq_limit, API_EVENT_RAW_ROW_LIMIT)

        if kwargs.get('order'):
            rq['order'] = 'ascending' if kwargs['order'] == 'asc' else 'descending'

        audit_filter = {}
        if 'created' in kwargs and kwargs['created']:
            if kwargs['created'] in ['today', 'yesterday', 'last_7_days', 'last_30_days', 'month_to_date', 'last_month', 'year_to_date', 'last_year']:
                audit_filter['created'] = kwargs['created']
            else:
                audit_filter['created'] = self.get_filter(kwargs['created'], AuditReportCommand.convert_date)
        if 'event_type' in kwargs and kwargs['event_type']:
            audit_filter['audit_event_type'] = self.get_filter(kwargs['event_type'], AuditReportCommand.convert_str_or_int)
        if 'username' in kwargs and kwargs['username']:
            audit_filter['username'] = self.get_filter(kwargs['username'], AuditReportCommand.convert_str)
        if 'to_username' in kwargs and kwargs['to_username']:
            audit_filter['to_username'] = self.get_filter(kwargs['to_username'], AuditReportCommand.convert_str)
        if 'record_uid' in kwargs and kwargs['record_uid']:
            audit_filter['record_uid'] = self.get_filter(kwargs['record_uid'], AuditReportCommand.convert_str)
        if 'shared_folder_uid' in kwargs and kwargs['shared_folder_uid']:
            audit_filter['shared_folder_uid'] = self.get_filter(kwargs['shared_folder_uid'], AuditReportCommand.convert_str)
        if 'geo_location' in kwargs and kwargs['geo_location']:
            ip_filter = set()
            geo_location_comps = kwargs['geo_location'].split(',')
            country = (geo_location_comps.pop() if geo_location_comps else '').strip().lower()
            if not country:
                raise CommandError('audit-report', "'geo_location' filter misses country")
            region = (geo_location_comps.pop() if geo_location_comps else '').strip().lower()
            city = (geo_location_comps.pop() if geo_location_comps else '').strip().lower()
            geo_dimension = AuditReportCommand.load_audit_dimension(params, 'geo_location')
            for geo in geo_dimension:
                if geo.get('country_code', '').lower() != country:
                    continue
                if region:
                    if geo.get('region', '').lower() != region:
                        continue
                if city:
                    if geo.get('city', '').lower() != city:
                        continue
                ip_filter.update(geo.get('ip_addresses'))
            if len(ip_filter) == 0:
                raise CommandError('audit-report', "'geo_location' filter: no events")
            audit_filter['ip_address'] = list(ip_filter)
        if 'device_type' in kwargs and kwargs['device_type']:
            version_filter = set()
            device_comps = kwargs['device_type'].split(',')
            device_type = (device_comps[0] if len(device_comps) > 0 else '').strip().lower()
            version = (device_comps[1] if len(device_comps) > 1 else '').strip().lower()
            if version and version.find('.') == -1:
                version += '.'
            if not device_type and not version:
                raise CommandError('audit-report', "'device_type' filter: empty")

            version_dimension = AuditReportCommand.load_audit_dimension(params, 'keeper_version')
            for ver in version_dimension:
                if device_type:
                    type_name = ver.get('type_name', '').lower()
                    type_category = ver.get('type_category', '').lower()
                    if not (device_type == type_name or device_type == type_category):
                        continue
                if version:
                    if not ver.get('version', '').startswith(version):
                        continue
                version_filter.add(ver.get('version_id'))
            if len(version_filter) == 0:
                raise CommandError('audit-report', "'device_type' filter: no events")
            audit_filter['keeper_version'] = list(version_filter)

        if audit_filter:
            rq['filter'] = audit_filter

        rs = api.communicate(params, rq)
        fields = []
        table = []

        details = kwargs.get('details') or False
        if report_type == 'raw':
            fields.extend(audit_report.RAW_FIELDS)
            misc_fields = list(audit_report.MISC_FIELDS) if kwargs.get('report_format') == 'fields' else ['message']
            incomplete = True
            while incomplete:
                events = rs.get('audit_event_overview_report_rows')
                for event in events:
                    if misc_fields:
                        lenf = len(fields)
                        for mf in misc_fields:
                            if mf == 'message':
                                fields.append(mf)
                            elif mf in event:
                                val = event.get(mf)
                                if val:
                                    fields.append(mf)
                                    if mf in audit_report.lookup_types:
                                        fields.extend(audit_report.lookup_types[mf].fields)
                        if len(fields) > lenf:
                            for f in fields[lenf:]:
                                if f not in audit_report.fields_to_uid_name:
                                    misc_fields.remove(f)

                    row = []
                    for field in fields:
                        value = self.get_value(params, field, event)
                        row.append(self.convert_value(field, value, details=details, params=params))
                    table.append(row)
                incomplete = len(events) >= API_EVENT_RAW_ROW_LIMIT
                if incomplete:
                    asc = rq.get('order') == 'ascending'
                    first_key, last_key = ('min', 'max') if asc else ('max', 'min')
                    rq_filter = rq.get('filter', {})
                    rq_period = rq_filter.get('created', {})
                    period = {first_key: int(events[-1]['created'])}
                    if not isinstance(rq_period, dict) or rq_period.get(last_key) is None:
                        last_rq = {**rq}
                        reverse = 'descending' if asc else 'ascending'
                        last_rq['order'] = reverse
                        last_rq['limit'] = 1
                        rs = api.communicate(params, last_rq)
                        last_row = rs.get('audit_event_overview_report_rows')[0]
                        period[last_key] = int(last_row['created'])
                    else:
                        period[last_key] = rq_period.get(last_key)
                    rq_filter['created'] = period
                    rq['filter'] = rq_filter
                    if user_limit and user_limit >= API_EVENT_RAW_ROW_LIMIT:
                        missing = user_limit - len(table)
                        if missing < API_EVENT_RAW_ROW_LIMIT:
                            if missing > 0:
                                rq['limit'] = missing
                            else:
                                break
                    rs = api.communicate(params, rq)
            return dump_report_data(table, fields, fmt=kwargs.get('format'), filename=kwargs.get('output'))
        else:
            if aggregates:
                fields.extend(aggregates)
            else:
                fields.append('occurrences')
            if report_type != 'span':
                fields.append('created')
            if columns:
                fields.extend(columns)
            if not self.sox_data and is_compliance_reporting_enabled(params):
                self.sox_data = get_prelim_data(params, 0, False, min_updated=0, cache_only=kwargs.get('minimal'))
            for event in rs['audit_event_overview_report_rows']:
                row = []
                for f in fields:
                    if f in event:
                        row.append(
                            self.convert_value(f, event[f], report_type=report_type, details=details, params=params)
                        )
                    elif f in audit_report.fields_to_uid_name:
                        row.append(self.resolve_lookup(params, f, event))
                    else:
                        row.append('')
                table.append(row)
            return dump_report_data(table, fields, fmt=kwargs.get('format'), filename=kwargs.get('output'))

    @staticmethod
    def convert_date(value):
        try:
            value = float(value)
        except:
            if len(value) <= 10:
                value = datetime.datetime.strptime(value, '%Y-%m-%d')
            else:
                value = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
            value = value.timestamp()
        return int(value)

    @staticmethod
    def convert_int(value):
        return int(value)

    @staticmethod
    def convert_str(value):
        return value

    @staticmethod
    def convert_str_or_int(value):
        if value.isdigit():
            return int(value)
        else:
            return value

    @staticmethod
    def get_filter(filter_value, convert):
        filter_value = filter_value.strip()
        bet = between_pattern.match(filter_value)
        if bet is not None:
            dt1, dt2, *_ = bet.groups()
            dt1 = convert(dt1)
            dt2 = convert(dt2)
            return {'min': dt1, 'max': dt2}

        inp = in_pattern.match(filter_value)
        if inp is not None:
            arr = []
            for v in inp.groups()[0].split(','):
                arr.append(convert(v.strip()))
            return arr

        for prefix in ['>=', '<=', '>', '<', '=']:
            if filter_value.startswith(prefix):
                value = convert(filter_value[len(prefix):].strip())
                if prefix == '>=':
                    return {'min': value}
                if prefix == '<=':
                    return {'max': value}
                if prefix == '>':
                    return {'min': value, 'exclude_min': True}
                if prefix == '<':
                    return {'max': value, 'exclude_max': True}
                return value

        return convert(filter_value)


class AgingReportCommand(Command):
    data_updated = False

    def get_parser(self):
        return aging_report_parser

    def execute(self, params, **kwargs):
        def get_floor(period):  # type: (str) -> Union[datetime.datetime, None]
            dt = datetime.datetime.now()
            if not period:
                logging.info('\n\nThe default password aging period is 3 months\n'
                             'To change this value pass --period=[PERIOD] parameter\n'
                             '[PERIOD] example: 10d for 10 days; 3m for 3 months; 1y for 1 year\n\n')
                period = '3m'
            co = period[-1]
            try:
                va = abs(int(period[:-1]))
            except:
                logging.warning(f'Invalid period: {period}')
                return None

            if co != 'd':
                if co == 'm':
                    va *= 30
                elif co == 'y':
                    va *= 365
                else:
                    logging.warning(f'Invalid period: {period}')
                    return None
            return dt - datetime.timedelta(days=va)

        enterprise_id = next(((x['node_id'] >> 32) for x in params.enterprise['nodes']), 0)
        dt = get_floor(kwargs.get('period'))
        if dt is None:
            return
        period_min_ts = int(dt.timestamp())

        from ..sox import get_prelim_data
        sd = get_prelim_data(params, enterprise_id, rebuild=kwargs.get('rebuild'), min_updated=period_min_ts)
        sd = self.update_aging_data(params, sd, period_start_ts=period_min_ts)

        def clean_up():
            if kwargs.get('no_cache') and sd:
                sd.storage.delete_db()

        users = {uid: user for uid, user in sd.get_users().items() if user.status == enterprise_pb2.OK}
        uid_lookup = {user.email: uid for uid, user in users.items()}
        username = kwargs.get('username')
        if username and username not in uid_lookup:
            logging.info(f'user {username} is not a valid enterprise user')
            clean_up()
            return
        else:
            user_uids = [uid_lookup.get(username)] if username is not None else None
        output_format = kwargs.get('format', 'table')
        date_ts = int(dt.timestamp())
        columns = ['owner', 'title', 'password_changed', 'shared', 'record_url'] if output_format == 'json' else \
            ['Owner', 'Record Title', 'Last Password Change', 'Shared', 'Record URL']
        table = []
        user_records = sd.get_user_records(user_uids)
        for ur in user_records:
            created_ts = ur.record.created
            change_ts = ur.record.last_pw_change
            created_after_date = created_ts and (created_ts >= date_ts)
            pw_changed_after_date = change_ts and (change_ts >= date_ts)
            if created_after_date or pw_changed_after_date:
                continue
            else:
                email = sd.get_user(ur.user_uid).email
                ts = change_ts or created_ts
                change_dt = datetime.datetime.fromtimestamp(ts) if ts else None
                record_url = f'https://{params.server}/value/#detail/{ur.record.record_uid}'
                row = [email, ur.record.data.get('title'), change_dt, ur.record.shared, record_url]
                table.append(row)
        clean_up()
        return dump_report_data(table, columns, fmt=output_format, filename=kwargs.get('output'))

    @staticmethod
    def get_database_path(params):
        pass

    def update_aging_data(self, params, sox, period_start_ts):
        # type: (KeeperParams, sox_data.SoxData, int) -> sox_data.SoxData
        def get_record_event_dates(params, record_uids, event_type, ts_floor):
            # type: (KeeperParams, List[Union[str, int]], str, int) -> Dict[str, int]
            rq = {
                'command':      'get_audit_event_reports',
                'scope':        'enterprise',
                'report_type':  'span',
                'event_type':   event_type,
                'columns':      ['record_uid'],
                'aggregate':    ['last_created'],
                'limit':        API_EVENT_SUMMARY_ROW_LIMIT
            }
            ts_lookup = dict()
            while record_uids:
                chunk = record_uids[:API_EVENT_SUMMARY_ROW_LIMIT]
                record_uids = record_uids[API_EVENT_SUMMARY_ROW_LIMIT:]
                rq_filter = {'record_uid': chunk, 'created': {'min': ts_floor}}
                rq['filter'] = rq_filter
                rs = api.communicate(params, rq)
                events = rs['audit_event_overview_report_rows']
                chunk_ts_lookup = {event['record_uid']: int(event['last_created']) for event in events}
                ts_lookup.update(chunk_ts_lookup)
            return ts_lookup

        def update_record_aging(params, sd, r_uids, event_type, set_ent_field_fn, on_updated, msg, ts_floor=0):
            # type: (KeeperParams, sox_data.SoxData, List[int], str, Callable, Callable, str, int) -> None
            logging.info(msg)
            ts_lookup = get_record_event_dates(params, r_uids, event_type, ts_floor)
            updated_entities = []
            for rec_uid in ts_lookup:
                entity = sd.storage.record_aging.get_entity(rec_uid) or StorageRecordAging(rec_uid)
                entity = set_ent_field_fn(entity, ts_lookup.get(rec_uid))
                updated_entities.append(entity)
            rebuild_task = RebuildTask(False)
            rebuild_task.update_records(ts_lookup.keys())
            sd.storage.record_aging.put_entities(updated_entities)
            sd.rebuild_data(rebuild_task)
            on_updated()

        def update_record_created_times(params, sd, ts_floor=0):   # type: (KeeperParams, sox_data.SoxData, int) -> None
            def update_ent(ent, val):   # type: (StorageRecordAging, int) -> StorageRecordAging
                ent.created = val
                return ent

            on_update_fn = sd.storage.set_records_dated
            r_uids = [uid for uid, record in sd.get_records().items() if not record.created]
            event_type = 'record_add'
            msg = 'Loading record creation time...'
            update_record_aging(params, sd, r_uids, event_type, update_ent, on_update_fn, msg, ts_floor)

        def update_pw_change_times(params, sd, ts_floor=0):
            def update_ent(ent, val):   # type: (StorageRecordAging, int) -> StorageRecordAging
                ent.last_pw_change = val
                return ent

            on_update_fn = sd.storage.set_last_pw_audit
            event_type = 'record_password_change'
            msg = 'Loading record password change information...'
            records = {id: rec for id, rec in sd.get_records().items() if rec.created and rec.last_pw_change < ts_floor}
            rec_uids = list(records.keys())
            created_timestamps = {record.created for record in records.values()}
            ts_floor = min(*created_timestamps, ts_floor) if created_timestamps else ts_floor
            update_record_aging(params, sd, rec_uids, event_type, update_ent, on_update_fn, msg, ts_floor)

        min_dt = datetime.datetime.now() - datetime.timedelta(days=365) * 5
        min_ts = int(min_dt.timestamp())
        if sox.storage.records_dated < period_start_ts:
            update_record_created_times(params, sox, min_ts)
        if sox.storage.last_pw_audit < period_start_ts:
            update_pw_change_times(params, sox, ts_floor=period_start_ts)
        return sox


class ActionReportCommand(EnterpriseCommand):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return action_report_parser

    def execute(self, params, **kwargs):
        def cmd_rq(cmd, **kwargs):
            rq = {
                'command': cmd,
                'scope': 'enterprise',
                **kwargs
            }
            return rq

        def report_rq(query_filter, cols=None):
            rq = {
                **cmd_rq('get_audit_event_reports'),
                'report_type': 'span',
                'columns': ['username'] if cols is None else cols,
                'filter': query_filter,
                'aggregate': ['last_created'],
                'limit': API_EVENT_SUMMARY_ROW_LIMIT,
            }
            return rq

        def get_excluded(candidates, query_filter, username_field='username'):
            excluded = []
            columns = [username_field]
            get_events = len(candidates) > len(excluded)
            while get_events:
                rq = report_rq(query_filter, columns)
                rs = api.communicate(params, rq)
                events = rs['audit_event_overview_report_rows']
                to_exclude = [event[username_field] for event in events]
                excluded = excluded + to_exclude
                get_events = len(events) >= API_EVENT_SUMMARY_ROW_LIMIT
                if get_events:
                    candidates = [user for user in candidates if user not in excluded]
                    end = int(events[-1]['last_created'])
                    query_filter['created']['max'] = end
                    query_filter[username_field] = candidates
            return excluded

        def get_no_action_users(candidates, days_since, event_types, name_key='username'):
            days_since = 30 if not isinstance(days_since, int) else days_since
            now_dt = datetime.datetime.now()
            min_dt = now_dt - datetime.timedelta(days=days_since)
            start = int(min_dt.timestamp())
            end = int(now_dt.timestamp())
            period = {'min': start, 'max': end}
            included = [candidate['username'] for candidate in candidates]
            query_filter = {
                'audit_event_type': ['login'] if event_types is None else event_types,
                'created': period
            }
            excluded = get_excluded(included, query_filter, name_key)
            return [user for user in candidates if user['username'] not in excluded]

        def get_action_results_text(cmd, cmd_status, server_msg, affected):
            return f'\tCOMMAND: {cmd}\n\tSTATUS: {cmd_status}\n\tSERVER MESSAGE: {server_msg}\n\tAFFECTED: {affected}'

        def batch_apply_cmd(users, api_cmd_rq=None, dryrun=False, userid_field='enterprise_user_id'):
            cmd_status = 'aborted' if api_cmd_rq else 'n/a'
            affected = 0
            server_msg = 'n/a'
            cmd = None if api_cmd_rq is None else api_cmd_rq.get('command')
            if api_cmd_rq is not None and len(users):
                cmd_rqs = [{**api_cmd_rq, userid_field: user[userid_field]} for user in users]
                rq = cmd_rq('execute', requests=cmd_rqs)
                if dryrun:
                    cmd_status = 'dry run'
                else:
                    rs = api.communicate(params, rq)
                    cmd_status = rs.get('result')
                    server_msg = rs.get('message')
                    affected = len(users)
                    if cmd_status == 'success':
                        results = rs.get('results')
                        fails = [result for result in results if result.get('result') != 'success']
                        if any(fails):
                            fail = fails[0]
                            cmd_status = 'incomplete'
                            affected = len(users) - len(fails)
                            server_msg = fail.get('message')

            return get_action_results_text(cmd, cmd_status, server_msg, affected)

        def transfer_accounts(from_users, to_user, dryrun=False):
            cmd = 'transfer_and_delete_user'
            cmd_status = 'aborted'
            affected = 0
            server_msg = 'n/a'
            if not to_user:
                return 'NONE (No transfer target specified)'

            if not from_users:
                return 'NONE (No accounts to transfer)'

            target = to_user.lower().strip()
            active_users = [u for u in params.enterprise.get('users') if u.get('status') == 'active']
            is_target_valid = target not in from_users and any([u for u in active_users if u.get('username') == target])
            if is_target_valid:
                if dryrun:
                    cmd_status = 'dry run'
                else:
                    pub_key = self.get_public_key(params, target)
                    if pub_key:
                        for email in [u.get('username') for u in from_users]:
                            result = EnterpriseTransferUserCommand.transfer_user_account(params, email, target, pub_key)
                            if result:
                                affected += 1

                        if affected > 0:
                            cmd_status = 'incomplete' if affected != len(from_users) else 'success'
                        else:
                            cmd_status = server_msg = 'fail'
                    else:
                        logging.warning(f'Failed to get user {target} public key')
            else:
                logging.warning(f'Invalid transfer target {target}')

            return get_action_results_text(cmd, cmd_status, server_msg, affected)

        def apply_admin_action(users, target_status='no-update', action='none', dryrun=False):
            default_allowed = {'none'}
            status_actions = {
                'no-logon':     {*default_allowed, 'lock'},
                'no-update':    {*default_allowed},
                'locked':       {*default_allowed, 'delete', 'transfer'}
            }

            invalid_action_msg = f'NONE (Action "{action}" not allowed on "{target_status}" users)'
            is_valid_action = action in status_actions[target_status]

            action_handlers = {
                'none': partial(batch_apply_cmd, users, None, dryrun),
                'lock': partial(batch_apply_cmd, users, cmd_rq('enterprise_user_lock', lock='locked'), dryrun),
                'delete': partial(batch_apply_cmd, users, cmd_rq('enterprise_user_delete'), dryrun),
                'transfer': partial(transfer_accounts, users, kwargs.get('target_user'), dryrun)
            }

            if action in ('delete', 'transfer') and not dryrun and not kwargs.get('force') and users:
                msg_action = 'deleting' if action == 'delete' else 'transferring'
                answer = user_choice(
                    bcolors.FAIL + bcolors.BOLD + '\nALERT!\n' + bcolors.ENDC +
                    'This action cannot be undone.\n\n' +
                    f'Do you want to proceed with {msg_action} {len(users)} account(s)?', 'yn', 'n')
                if answer.lower() != 'y':
                    return f'NONE (Cancelled by user)'

            return action_handlers.get(action)() if is_valid_action else invalid_action_msg

        candidates = params.enterprise['users']
        active = [user for user in candidates if user['status'] == 'active']
        locked = [user for user in active if user['lock']]
        target_status = kwargs['target_user_status']
        days = kwargs['days_since']
        if days is None:
            days = 90 if target_status == 'locked' else 30

        args_by_status = {
            'no-logon': [active, days, ['login']],
            'no-update': [active, days, ['record_add', 'record_update']],
            'locked': [locked, days, ['lock_user'], 'to_username']
        }
        args = args_by_status[target_status]
        target_users = get_no_action_users(*args)
        usernames = [user['username'] for user in target_users]

        admin_action = kwargs['apply_action']
        dry_run = kwargs['dry_run']
        action_msg = apply_admin_action(target_users, target_status, admin_action, dry_run)

        title = f'Admin Action Taken:\n{action_msg}\n'
        title += f'\n{len(usernames)} Users With "{target_status}" Status Older Than {days} Day(s): '
        filepath = kwargs.get('output')
        fmt = kwargs.get('format')
        formatted = [[name] for name in usernames]

        return dump_report_data(data=formatted, headers=['username'], title=title, fmt=fmt, filename=filepath)
