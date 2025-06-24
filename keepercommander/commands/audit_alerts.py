#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import copy
import datetime
import json
import logging
import os.path
import secrets
from typing import Optional, List, Tuple, Union

from . import aram
from .base import GroupCommand, report_output_parser, field_to_title, dump_report_data, raise_parse_exception, suppress_exit
from .enterprise_common import EnterpriseCommand
from .. import api, utils
from ..params import KeeperParams
from ..error import CommandError


PUT_ENTERPRISE_SETTING = 'put_enterprise_setting'
AUDIT_ALERT_CONTEXT = 'AuditAlertContext'

alert_list_parser = argparse.ArgumentParser(prog='audit-alert list', parents=[report_output_parser])
alert_list_parser.add_argument('--reload', dest='reload', action='store_true', help='reload alert information')

alert_target_parser = argparse.ArgumentParser(add_help=False)
alert_target_parser.add_argument('target', metavar='ALERT', help='Alert ID or Name.')
alert_view_parser = argparse.ArgumentParser(prog='audit-alert view')
alert_view_parser.add_argument('target', metavar='ALERT', nargs='?', help='Alert ID or Name')
alert_view_parser.add_argument('--all', dest='all', action='store_true', help='View all alerts')
alert_view_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json', 'pdf'],
                                  default='table', help='format of output')
alert_view_parser.add_argument('--output', dest='output', action='store',
                                  help='path to resulting output file (ignored for "table" format)')
alert_history_parser = argparse.ArgumentParser(
    prog='audit-alert history', parents=[report_output_parser, alert_target_parser])
alert_reset_counts_parser = argparse.ArgumentParser(prog='audit-alert reset-counts', parents=[alert_target_parser])
alert_delete_parser = argparse.ArgumentParser(prog='audit-alert remove')
alert_delete_parser.add_argument('target', metavar='ALERT', nargs='?', help='Alert ID or Name.')
alert_delete_parser.add_argument('--all', dest='delete_all', action='store_true', help='Delete all alerts')
alert_delete_parser.add_argument('--from', dest='from_id', metavar='ALERT ID', type=int,
                                help='Starting alert ID for range deletion')
alert_delete_parser.add_argument('--to', dest='to_id', metavar='ALERT ID', type=int,
                                help='Ending alert ID for range deletion')
alert_delete_parser.add_argument('--force', dest='force', action='store_true', 
                                help='Force deletion without confirmation prompt')

alert_recipient_edit_options = argparse.ArgumentParser(add_help=False)
alert_recipient_edit_options.add_argument(
    '--name', dest='name', metavar='NAME', action='store', help='recipient name')
alert_recipient_edit_options.add_argument(
    '--email', dest='email', metavar='EMAIL', action='store', help='email address')
alert_recipient_edit_options.add_argument(
    '--phone', dest='phone', metavar='PHONE', action='store', help='phone number. +1 (555) 555-1234')
alert_recipient_edit_options.add_argument(
    '--webhook', dest='webhook', metavar='URL', action='store',
    help='Webhook URL. See https://docs.keeper.io/enterprise-guide/webhooks')
alert_recipient_edit_options.add_argument(
    '--http-body', dest='http_body', metavar='HTTP_BODY', action='store',
    help='Webhook HTTP Body')
alert_recipient_edit_options.add_argument(
    '--cert-errors', dest='cert_errors', action='store', choices=['ignore', 'enforce'],
    help='Webhook SSL Certificate errors')
alert_recipient_edit_options.add_argument(
    '--generate-token', dest='generate_token', action='store_true', help='Generate new access token')


alert_recipient_parser = argparse.ArgumentParser(prog='audit-alert recipient', parents=[alert_target_parser])
subparsers = alert_recipient_parser.add_subparsers(title='recipient actions', dest='action')
alert_recipient_enable_parser = subparsers.add_parser('enable', help='enables recipient')
alert_recipient_enable_parser.add_argument(
    'recipient', metavar='RECIPIENT', help='Recipient ID or Name. Use "*" for "User who generated event"')
alert_recipient_enable_parser.error = raise_parse_exception
alert_recipient_enable_parser.exit = suppress_exit

alert_recipient_disable_parser = subparsers.add_parser('disable', help='disables recipient')
alert_recipient_disable_parser.add_argument(
    'recipient', metavar='RECIPIENT', help='Recipient ID or Name. Use "*" for "User who generated event"')
alert_recipient_disable_parser.error = raise_parse_exception
alert_recipient_disable_parser.exit = suppress_exit

alert_recipient_delete_parser = subparsers.add_parser('delete', help='deletes recipient')
alert_recipient_delete_parser.add_argument('recipient', metavar='RECIPIENT', help='Recipient ID or Name.')
alert_recipient_delete_parser.error = raise_parse_exception
alert_recipient_delete_parser.exit = suppress_exit

alert_recipient_add_parser = subparsers.add_parser('add', help='adds recipient', parents=[alert_recipient_edit_options])
alert_recipient_add_parser.error = raise_parse_exception
alert_recipient_add_parser.exit = suppress_exit

alert_recipient_edit_parser = subparsers.add_parser('edit', help='edit recipient', parents=[alert_recipient_edit_options])
alert_recipient_edit_parser.add_argument('recipient', metavar='RECIPIENT', help='Recipient ID or Name.')
alert_recipient_edit_parser.error = raise_parse_exception
alert_recipient_edit_parser.exit = suppress_exit


alert_edit_options = argparse.ArgumentParser(add_help=False)
alert_edit_options.add_argument('--name', action='store', metavar='NAME', help='Alert Name.')
alert_edit_options.add_argument(
    '--frequency', dest='frequency', action='store', metavar='FREQUENCY',
    help='Alert Frequency. "[N:]event|minute|hour|day"')
alert_edit_options.add_argument(
    '--audit-event', dest='audit_event', action='append', metavar='EVENT',
    help='Audit Event. Can be repeated.')
alert_edit_options.add_argument(
    '--user', dest='user', action='append', metavar='USER', help='Username. Can be repeated.')
alert_edit_options.add_argument(
    '--record-uid', dest='record_uid', action='append', metavar='RECORD_UID', help='Record UID. Can be repeated.')
alert_edit_options.add_argument(
    '--shared-folder-uid', dest='shared_folder_uid', action='append', metavar='SHARED_FOLDER_UID',
    help='Shared Folder UID. Can be repeated.')
alert_edit_options.add_argument(
    '--active', dest='active', action='store', metavar='ACTIVE', choices=['on', 'off'],
    help='Enable or disable alert')


alert_add_parser = argparse.ArgumentParser(prog='audit-alert add', parents=[alert_edit_options])
alert_edit_parser = argparse.ArgumentParser(prog='audit-alert edit', parents=[alert_target_parser, alert_edit_options])

alert_action_parser = argparse.ArgumentParser(prog='audit-alert action')
alert_action_parser.add_argument('target', metavar='ALERT', nargs='?', help='Alert ID or Name')
alert_action_parser.add_argument('--all', dest='apply_all', action='store_true', help='Apply action to all alerts')
alert_action_parser.error = raise_parse_exception
alert_action_parser.exit = suppress_exit


class AuditSettingMixin:
    LAST_USERNAME = ""
    LAST_ENTERPRISE_ID = 0
    SETTINGS = None   # type: Optional[dict]
    EVENT_TYPES = None  # type: Optional[List[Tuple[int, str]]]

    @staticmethod
    def load_settings(params, reload=False):  # type: (KeeperParams, Optional[bool]) -> Optional[dict]
        if params.enterprise is None:
            AuditSettingMixin.SETTINGS = None
            AuditSettingMixin.LAST_ENTERPRISE_ID = 0
            return
        if AuditSettingMixin.EVENT_TYPES is None:
            rq = {
                'command': 'get_audit_event_dimensions',
                'columns': ['audit_event_type']
            }
            rs = api.communicate(params, rq)
            AuditSettingMixin.EVENT_TYPES = []
            for et in rs['dimensions']['audit_event_type']:
                event_id = et.get('id')
                event_name = et.get('name')
                if event_name and isinstance(event_id, int):
                    AuditSettingMixin.EVENT_TYPES.append((event_id, event_name))

        enterprise_id = 0
        if isinstance(params.license, dict):
            enterprise_id = params.license.get('enterprise_id')

        if AuditSettingMixin.SETTINGS is None:
            reload = True
        elif AuditSettingMixin.LAST_USERNAME != params.user:
            reload = True
        elif enterprise_id == 0 or AuditSettingMixin.LAST_ENTERPRISE_ID != enterprise_id:
            reload = True

        if reload:
            rq = {
                'command': 'get_enterprise_setting',
                'include': ['AuditAlertContext', 'AuditAlertFilter', 'AuditReportFilter']
            }
            AuditSettingMixin.SETTINGS = api.communicate(params, rq)
            AuditSettingMixin.LAST_USERNAME = params.user
            AuditSettingMixin.LAST_ENTERPRISE_ID = enterprise_id
        return AuditSettingMixin.SETTINGS

    @staticmethod
    def invalidate_alerts():
        AuditSettingMixin.SETTINGS = None

    @staticmethod
    def frequency_to_text(freq):   # type: (dict) -> Optional[str]
        if not isinstance(freq, dict):
            return
        period = freq.get('period')
        count = freq.get('count')
        if period == 'event':
            if isinstance(count, int):
                return f'{count} of Occurrences Triggered'
            else:
                return 'Every Occurrence'
        elif period in ('day', 'hour', 'minutes') and isinstance(count, int):
            if period == 'minutes':
                period = 'minute'
            period = period.capitalize()
            return f'{count} {period}(s) from First Occurrence'
        else:
            return 'Not supported'

    @staticmethod
    def text_to_frequency(text):   # type: (str) -> dict
        if not isinstance(text, str):
            return {'period': 'event'}
        num, sep, occ = text.partition(':')
        if sep:
            if num:
                num = int(num)
            else:
                num = 0
            occ = occ.lower()
        else:
            num = 0
            occ = text.lower()
        if occ in ('event', 'e'):
            occ = 'event'
        elif occ in ('minute', 'minutes', 'm'):
            occ = 'minutes'
        elif occ in ('hour', 'h'):
            occ = 'hour'
        elif occ in ('day', 'd'):
            occ = 'day'
        else:
            raise Exception(f'Invalid alert frequency \"{occ}\". "event", "day", "hour", "minute"')
        if num <= 0:
            if occ == 'event':
                num = 0
            else:
                num = 1
        freq = {
            'period': occ
        }
        if num > 0:
            freq['count'] = num
        return freq

    @staticmethod
    def get_alert_context(alert_id):   # type: (int) -> Optional[dict]
        settings = AuditSettingMixin.SETTINGS
        if not settings:
            return
        alert_context = settings.get('AuditAlertContext')
        if not isinstance(alert_context, list):
            return

        return next((x for x in alert_context if x.get('id') == alert_id), None)

    @staticmethod
    def get_alert_configuration(params, alert_name):   # type: (KeeperParams, str) -> dict
        if not alert_name:
            raise Exception(f'Alert name cannot be empty')

        settings = AuditSettingMixin.load_settings(params)
        if not settings:
            raise Exception(f'Alert with name \"{alert_name}\" not found')
        alert_filter = settings.get('AuditAlertFilter')
        if not isinstance(alert_filter, list):
            raise Exception(f'Alert with name \"{alert_name}\" not found')

        a_number = int(alert_name) if alert_name.isnumeric() else 0
        if a_number > 0:
            for alert_filter in alert_filter:
                a_id = alert_filter.get('id')
                if isinstance(a_id, int):
                    if a_id == a_number:
                        return alert_filter

        alerts = []
        l_name = alert_name.casefold()
        for alert_filter in alert_filter:
            a_name = alert_filter.get('name') or ''
            if a_name.casefold() == l_name:
                alerts.append(alert_filter)

        if len(alerts) == 0:
            raise Exception(f'Alert with name \"{alert_name}\" not found')
        if len(alerts) > 1:
            raise Exception(f'There are {len(alerts)} alerts with name \"{alert_name})\". Use alert ID.')
        return alerts[0]

    @staticmethod
    def apply_alert_options(params, alert, **kwargs):     # type: (KeeperParams, dict, ...) ->  None
        alert_name = kwargs.get('name')
        if alert_name:
            alert['name'] = alert_name

        frequency = kwargs.get('frequency')
        if frequency:
            alert['frequency'] = AuditSettingMixin.text_to_frequency(frequency)

        alert_filter = alert.get('filter')
        if not isinstance(alert_filter, dict):
            alert['filter'] = {}

        events_option = kwargs.get('audit_event')
        if isinstance(events_option, list):
            event_ids = set()
            event_lookup = {n: i for i, n in AuditSettingMixin.EVENT_TYPES or []}
            for events in events_option:    # type: str
                for event_name in (x.strip().lower() for x in events.split(',')):
                    if event_name in event_lookup:
                        event_ids.add(event_lookup[event_name])
                    else:
                        raise CommandError('alert add', f'Event name \"{event_name}\" is invalid')
            if len(event_ids) > 0:
                event_list = list(event_ids)
                event_list.sort()
                alert_filter['events'] = event_list
            else:
                if 'events' in alert_filter:
                    del alert_filter['event']

        users_option = kwargs.get('user')
        if isinstance(users_option, list):
            user_ids = set()
            user_lookup = {x['username']: x for x in params.enterprise.get('users') or []}
            # TODO aliases
            for users in users_option:    # type: str
                for username in (x.strip().lower() for x in users.split(',')):
                    if username in user_lookup:
                        user_ids.add(user_lookup[username]['user_id'])
                    else:
                        raise CommandError('alert add', f'Username \"{username}\" is unknown')
            if len(user_ids) > 0:
                alert_filter['userIds'] = list(user_ids)
            else:
                if 'userIds' in alert_filter:
                    del alert_filter['userIds']

        record_uid_option = kwargs.get('record_uid')
        if isinstance(record_uid_option, list):
            record_uids = set()
            for r_uids in record_uid_option:    # type: str
                for record_uid in (x.strip() for x in r_uids.split(',')):
                    if not record_uid:
                        continue
                    if record_uid not in params.record_cache:
                        logging.info('Record UID \"%s\" cannot be verified as existing.', record_uid)
                    record_uids.add(record_uid)
            if len(record_uids) > 0:
                alert_filter['recordUids'] = [{'id': x, 'selected': True} for x in record_uids]
            else:
                if 'recordUids' in alert_filter:
                    del alert_filter['recordUids']

        shared_folder_uid_option = kwargs.get('shared_folder_uid')
        if isinstance(shared_folder_uid_option, list):
            shared_folder_uids = set()
            for sf_uids in shared_folder_uid_option:    # type: str
                for shared_folder_uid in (x.strip() for x in sf_uids.split(',')):
                    if not shared_folder_uid:
                        continue
                    if shared_folder_uid not in params.shared_folder_cache:
                        logging.info('Shared Folder UID \"%s\" cannot be verified as existing.', shared_folder_uid)
                    shared_folder_uids.add(shared_folder_uid)
            if len(shared_folder_uids) > 0:
                alert_filter['sharedFolderUids'] = [{'id': x, 'selected': True} for x in shared_folder_uids]
            else:
                if 'sharedFolderUids' in alert_filter:
                    del alert_filter['sharedFolderUids']


class AuditAlertList(EnterpriseCommand, AuditSettingMixin):
    def get_parser(self):
        return alert_list_parser

    def execute(self, params, **kwargs):
        alerts = self.load_settings(params, kwargs.get('reload') or False)
        if not isinstance(alerts, dict):
            logging.info('No alerts found')
            return
        alert_filter = alerts.get('AuditAlertFilter')
        if not isinstance(alert_filter, list):
            logging.info('No alerts found')
            return

        fmt = kwargs.get('format') or ''
        table = []
        headers = ['id', 'name', 'events', 'frequency', 'occurrences', 'alerts_sent', 'last_sent', 'active']
        if fmt != 'json':
            headers = [field_to_title(x) for x in headers]
        event_lookup = {i: n for i, n in self.EVENT_TYPES or []}
        for alert in alert_filter:
            alert_id = alert.get('id')
            ctx = AuditSettingMixin.get_alert_context(alert_id) or alert
            alert_name = alert.get('name')
            events = ''   # type: Union[str, List[str]]
            alert_filter = alert.get('filter')
            if isinstance(alert_filter, dict):
                es = list((event_lookup[x] for x in alert_filter.get('events') or [] if x in event_lookup))
                if len(es) == 1:
                    events = es[0]
                elif len(es) <= 5:
                    events = '\n'.join(es)
                elif len(es) > 5:
                    events = '\n'.join(es[:4]) + f'\n+{len(es) - 4} more'
            freq = self.frequency_to_text(alert.get('frequency'))
            occurrences = ctx.get('counter')
            alerts_sent = ctx.get('sentCounter')
            last_sent = ctx.get('lastSent')
            if last_sent:
                try:
                    last_sent = datetime.datetime.strptime(last_sent, '%Y-%m-%dT%H:%M:%S.%fZ')
                    last_sent = last_sent.replace(microsecond=0, tzinfo=datetime.timezone.utc).astimezone()
                except ValueError:
                    pass
            disabled = ctx.get('disabled') is True
            table.append([alert_id, alert_name, events, freq, occurrences, alerts_sent, last_sent, not disabled])
        return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'), sort_by=0)


class AuditAlertDelete(EnterpriseCommand, AuditSettingMixin):
    def get_parser(self):
        return alert_delete_parser

    def execute(self, params, **kwargs):
        target = kwargs.get('target')
        delete_all = kwargs.get('delete_all')
        from_id = kwargs.get('from_id')
        to_id = kwargs.get('to_id')
        
        # Load settings to get all alerts
        settings = self.load_settings(params)
        if not settings:
            logging.info('No alerts found')
            return
        alert_filter = settings.get('AuditAlertFilter')
        if not isinstance(alert_filter, list) or len(alert_filter) == 0:
            logging.info('No alerts found')
            return

        # Determine which deletion method to use and get alerts to delete
        if from_id is not None or to_id is not None:
            alerts_to_delete = self._delete_by_range(params, from_id, to_id, alert_filter)
        elif delete_all:
            alerts_to_delete = self._delete_all(params, alert_filter)
        elif target:
            alerts_to_delete = self._delete_single(params, target)
        else:
            raise CommandError('alert delete', 'Either target, --all, or --from/--to parameters are required.')

        # Confirm deletion unless --force is used
        force = kwargs.get('force', False)
        if not force and not self._confirm_deletion(alerts_to_delete):
            logging.info('Deletion cancelled by user.')
            return

        # Execute the deletion
        deleted_count = self._execute_deletion(params, alerts_to_delete)
        
        self.invalidate_alerts()
        
        if deleted_count > 0:
            # Show remaining alerts
            command = AuditAlertList()
            command.execute(params, reload=True)
        else:
            logging.warning('No alerts were deleted.')

    def _delete_by_range(self, params, from_id, to_id, alert_filter):
        """Handle range deletion with --from and --to parameters."""
        if from_id is None or to_id is None:
            raise CommandError('alert delete', 'Both --from and --to parameters are required for range deletion.')
        
        # Validation: both values should not be zero or negative
        if from_id <= 0 or to_id <= 0:
            raise CommandError('alert delete', 'Alert IDs must be positive integers. Please specify valid alert IDs.')
        
        # Validation: from value should be less than to value
        if from_id >= to_id:
            raise CommandError('alert delete', f'Invalid range: --from ({from_id}) must be less than --to ({to_id}).')
        
        # Find alerts in range
        alerts_to_delete = []
        for alert in alert_filter:
            alert_id = alert.get('id')
            if isinstance(alert_id, int) and from_id <= alert_id <= to_id:
                alerts_to_delete.append(alert)
        
        if not alerts_to_delete:
            raise CommandError('alert delete', f'No alerts found in range {from_id}-{to_id}')
        
        return alerts_to_delete

    def _delete_all(self, params, alert_filter):
        """Handle delete all with --all flag."""
        return alert_filter

    def _delete_single(self, params, target):
        """Handle single target deletion."""
        alert = AuditSettingMixin.get_alert_configuration(params, target)
        return [alert]

    def _confirm_deletion(self, alerts_to_delete):
        """Prompt user for confirmation before deleting alerts."""
        if not alerts_to_delete:
            return False
        
        print(f"\nThe following {len(alerts_to_delete)} alert(s) will be deleted:")
        print("-" * 60)
        for alert in alerts_to_delete:
            alert_id = alert.get('id', 'N/A')
            alert_name = alert.get('name', 'N/A')
            print(f"  ID: {alert_id} | Name: {alert_name}")
        print("-" * 60)
        
        try:
            response = input(f"Are you sure you want to delete {len(alerts_to_delete)} alert(s)? (y/n): ").strip().lower()
            return response in ('y', 'yes')
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled.")
            return False

    def _execute_deletion(self, params, alerts_to_delete):
        """Execute the actual deletion of alerts and return count of successfully deleted alerts."""
        deleted_count = 0
        for alert in alerts_to_delete:
            alert_id = alert.get('id')
            alert_name = alert.get('name', f'ID {alert_id}')
            try:
                rq = {
                    'command': 'delete_enterprise_setting',
                    'type': 'AuditAlertFilter',
                    'id': alert_id,
                }
                api.communicate(params, rq)
                deleted_count += 1
            except Exception as e:
                logging.error(f'Failed to delete alert: {alert_name} (ID: {alert_id}): {str(e)}')
        
        return deleted_count


class AuditAlertView(EnterpriseCommand, AuditSettingMixin):
    def get_parser(self):
        return alert_view_parser

    def execute(self, params, **kwargs):
        fmt = kwargs.get('format', '')
        view_all = kwargs.get('all') or not kwargs.get('target')
        
        if view_all:
            self._execute_view_all(params, kwargs, fmt)
        else:
            self._execute_view_single(params, kwargs, fmt)

    def _get_display_options(self, kwargs):
        """Determine what sections to show based on kwargs."""
        if kwargs.get('recipient_only'):
            return {'recipient': True, 'filter': False, 'stat': False}
        return {'recipient': True, 'filter': True, 'stat': True}

    def _get_headers(self, show_options, fmt):
        """Get appropriate headers based on display options."""
        if show_options['recipient'] and not show_options['filter'] and not show_options['stat']:
            headers = ['alert_id', 'alert_name', 'status', 'recipients']
        elif show_options['stat']:
            headers = ['alert_id', 'alert_name', 'status', 'frequency', 'occurrences', 
                      'sent_counter', 'last_sent', 'event_types', 'users', 'shared_folders', 
                      'records', 'recipients']
        else:
            headers = ['alert_id', 'alert_name', 'status', 'event_types', 'users', 
                      'shared_folders', 'records', 'recipients']
        
        return headers if fmt == 'json' else [field_to_title(x) for x in headers]

    def _format_datetime(self, date_str):
        """Format datetime string to local time."""
        if not date_str:
            return ''
        try:
            dt = datetime.datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
            dt = dt.replace(microsecond=0, tzinfo=datetime.timezone.utc).astimezone()
            return dt.isoformat()
        except ValueError:
            return ''

    def _get_event_names(self, event_ids):
        """Convert event IDs to names."""
        if not event_ids:
            return []
        event_lookup = {i: n for i, n in self.EVENT_TYPES or []}
        return [event_lookup[x] for x in event_ids if x in event_lookup]

    def _get_usernames(self, user_ids, params):
        """Convert user IDs to usernames."""
        if not user_ids:
            return []
        user_lookup = {x['user_id']: x['username'] for x in params.enterprise.get('users', [])}
        return [user_lookup[x] for x in user_ids if x in user_lookup]

    def _get_selected_ids(self, items):
        """Get IDs of selected items."""
        if not items:
            return []
        return [x['id'] for x in items if x.get('selected')]

    def _build_recipient_data(self, recipient):
        """Build recipient data dictionary."""
        data = {
            "Recipient ID": recipient.get('id', ''),
            "Name": recipient.get('name', ''),
            "Status": 'Disabled' if recipient.get('disabled') else 'Enabled'
        }
        
        if 'webhook' in recipient:
            wh = recipient['webhook']
            data["Webhook URL"] = wh.get('url', '')
            if wh.get('template'):
                data["HTTP Body"] = wh.get('template', '')
            if wh.get('token'):
                data["Webhook Token"] = wh.get('token', '')
            data["Certificate Errors"] = 'Ignore' if wh.get('allowUnverifiedCertificate') else 'Enforce'
        
        if recipient.get('email'):
            data["Email To"] = recipient.get('email')
        
        if recipient.get('phone'):
            phone_country = recipient.get('phoneCountry')
            phone_display = f"(+{phone_country}) {recipient.get('phone')}" if phone_country else recipient.get('phone')
            data["Text To"] = phone_display
        
        return data

    def _format_list_for_cell(self, items, fmt, max_lines=5):
        """Format a list of items for display in a table cell, with line limits for PDF."""
        if not items:
            return ''
        
        if fmt == 'pdf' and len(items) > max_lines:
            displayed_items = items[:max_lines]
            additional_count = len(items) - max_lines
            return '\n'.join(displayed_items) + f'\n+ {additional_count} more'
        
        return '\n'.join(items)

    def _format_recipients_for_cell(self, recipients_complete, fmt):
        """Format recipients data for display in a table cell, with limits for PDF."""
        recipients_json = json.dumps(recipients_complete, indent=2)
        
        if fmt == 'pdf':
            lines = recipients_json.split('\n')
            if len(lines) > 5:
                truncated_lines = lines[:5]
                additional_count = len(lines) - 5
                return '\n'.join(truncated_lines) + f'\n+ {additional_count} more lines'
        
        return recipients_json

    def _build_alert_row(self, alert, show_options, params, fmt=''):
        """Build a single alert row for the table."""
        alert_id = alert.get('id', '')
        ctx = AuditSettingMixin.get_alert_context(alert_id) or alert
        alert_filter_data = alert.get('filter', {})
        
        row = [
            alert_id,
            alert.get('name', ''),
            'Disabled' if ctx.get('disabled') else 'Enabled'
        ]
        
        if show_options['stat'] and not show_options.get('recipient_only'):
            row.extend([
                self.frequency_to_text(alert.get('frequency')) or '',
                ctx.get('counter', ''),
                ctx.get('sentCounter', ''),
                self._format_datetime(ctx.get('lastSent'))
            ])
        
        if not show_options.get('recipient_only'):
            events = self._get_event_names(alert_filter_data.get('events'))
            row.append(self._format_list_for_cell(events, fmt))
            
            users = self._get_usernames(alert_filter_data.get('userIds'), params)
            row.append(self._format_list_for_cell(users, fmt))
            
            folders = self._get_selected_ids(alert_filter_data.get('sharedFolderUids'))
            row.append(self._format_list_for_cell(folders, fmt))
            
            records = self._get_selected_ids(alert_filter_data.get('recordUids'))
            row.append(self._format_list_for_cell(records, fmt))
        
        recipients_data = [self._build_recipient_data(r) for r in alert.get('recipients', [])]
        recipients_complete = {
            "Send To Originator": alert.get('sendToOriginator', False),
            "Recipients": recipients_data
        }
        row.append(self._format_recipients_for_cell(recipients_complete, fmt))
        
        return row

    def _execute_view_all(self, params, kwargs, fmt):
        """Execute view all alerts functionality."""
        show_options = self._get_display_options(kwargs)
        
        alerts = self.load_settings(params, kwargs.get('reload', False))
        if not isinstance(alerts, dict):
            logging.info('No alerts found')
            return
        
        alert_filter = alerts.get('AuditAlertFilter')
        if not isinstance(alert_filter, list):
            logging.info('No alerts found')
            return
        
        headers = self._get_headers(show_options, fmt)
        table = [self._build_alert_row(alert, show_options, params, fmt) for alert in alert_filter]
        
        dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'), sort_by=None)

    def _add_filter_data_to_table(self, table, alert_filter, params):
        """Add filter data to table for single alert view."""
        table.extend([['', ''], ['Alert Filter:', '']])
        
        if 'events' in alert_filter:
            events = self._get_event_names(alert_filter.get('events'))
            table.append(['Event Types', events])
        
        if 'userIds' in alert_filter:
            users = self._get_usernames(alert_filter.get('userIds'), params)
            table.append(['User', users])
        
        if 'sharedFolderUids' in alert_filter:
            folders = self._get_selected_ids(alert_filter['sharedFolderUids'])
            table.append(['Shared Folder', folders])
        
        if 'recordUids' in alert_filter:
            records = self._get_selected_ids(alert_filter['recordUids'])
            table.append(['Record', records])

    def _add_recipient_data_to_table(self, table, alert):
        """Add recipient data to table for single alert view."""
        table.extend([['', ''], ['Recipients:', ''], 
                     ['Send To Originator (*)', alert.get('sendToOriginator', False)]])
        
        for recipient in alert.get('recipients', []):
            table.extend([
                ['', ''],
                ['Recipient ID', recipient.get('id')],
                ['Name', recipient.get('name')],
                ['Status', 'Disabled' if recipient.get('disabled') else 'Enabled']
            ])
            
            if 'webhook' in recipient:
                wh = recipient['webhook']
                table.append(['Webhook URL', wh.get('url')])
                if wh.get('template'):
                    table.append(['HTTP Body', wh.get('template')])
                table.append(['Webhook Token', wh.get('token')])
                table.append(['Certificate Errors', 'Ignore' if wh.get('allowUnverifiedCertificate') else 'Enforce'])
            
            if recipient.get('email'):
                table.append(['Email To', recipient.get('email')])
            
            if recipient.get('phone'):
                phone_country = recipient.get('phoneCountry')
                phone_display = (f'(+{phone_country}) {recipient.get("phone")}' 
                               if phone_country else recipient.get('phone'))
                table.append(['Text To', phone_display])

    def _execute_view_single(self, params, kwargs, fmt):
        """Execute view single alert functionality."""
        show_options = self._get_display_options(kwargs)
        target = kwargs.get('target')
        
        alert = AuditSettingMixin.get_alert_configuration(params, target)
        alert_id = alert.get('id')
        ctx = AuditSettingMixin.get_alert_context(alert_id) or alert
        
        header = ['name', 'value'] if fmt == 'json' else [field_to_title(x) for x in ['name', 'value']]
        
        table = [
            ['Alert ID', alert_id],
            ['Alert name', alert.get('name')],
            ['Status', 'Disabled' if ctx.get('disabled') else 'Enabled']
        ]
        
        if show_options['stat']:
            last_sent = ctx.get('lastSent')
            if last_sent:
                try:
                    last_sent = datetime.datetime.strptime(last_sent, '%Y-%m-%dT%H:%M:%S.%fZ')
                    last_sent = last_sent.replace(microsecond=0, tzinfo=datetime.timezone.utc).astimezone()
                except ValueError:
                    pass
            
            table.extend([
                ['Frequency', self.frequency_to_text(alert.get('frequency'))],
                ['Occurrences', ctx.get('counter')],
                ['Sent Counter', ctx.get('sentCounter')],
                ['Last Sent', last_sent.isoformat() if last_sent else '']
            ])
        
        if show_options['filter']:
            alert_filter = alert.get('filter', {})
            self._add_filter_data_to_table(table, alert_filter, params)
        
        if show_options['recipient']:
            self._add_recipient_data_to_table(table, alert)
        
        dump_report_data(table, header, no_header=True, right_align=(0,), 
                        fmt=fmt, filename=kwargs.get('output'), sort_by=None)

class AuditAlertHistory(EnterpriseCommand, AuditSettingMixin):
    def get_parser(self):
        return alert_history_parser

    def execute(self, params, **kwargs):
        alert = AuditSettingMixin.get_alert_configuration(params, kwargs.get('target'))
        command = aram.AuditReportCommand()
        json_str = command.execute(params, report_type='raw', report_format='fields',
                                   alert_uid=alert.get('alertUid'), event_type='audit_alert_sent',
                                   limit=100, order='desc', format='json')
        events = json.loads(json_str)
        fmt = kwargs.get('format') or ''
        headers = ['alert_sent_at', 'occurrences']
        if fmt != 'json':
            headers = [field_to_title(x) for x in headers]
        table = []
        for event in events:
            if 'recipient' in event:
                recipient = event.get('recipient')
                if recipient == 'throttled':
                    if len(table) > 0:
                        table[-1][1] += 1
                else:
                    table.append([event.get('created'), 1])
        return dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class AuditAlertResetCount(EnterpriseCommand, AuditSettingMixin):
    def get_parser(self):
        return alert_reset_counts_parser

    def execute(self, params, **kwargs):
        alert = AuditSettingMixin.get_alert_configuration(params, kwargs.get('target'))
        rq = {
            'command': 'put_enterprise_setting',
            'type': 'AuditAlertContext',
            'settings': {
                'id': alert.get('id'),
                'counter': 0,
                'sentCounter': 0,
                'lastReset': utils.current_milli_time()
            }
        }
        api.communicate(params, rq)
        AuditSettingMixin.invalidate_alerts()
        logging.info('Alert counts reset to zero')

class AuditAlertSent(EnterpriseCommand, AuditSettingMixin):    
    def __init__(self, action=None):
        super().__init__()
        self.action = action
    
    def get_parser(self):
        return alert_action_parser

    def execute(self, params, **kwargs):
        """Execute enable or disable action based on the command used"""
        apply_all = kwargs.get('apply_all', False)
        target = kwargs.get('target')
        action = self.action
        command_name = f'alert {action}'
        
        if apply_all and target:
            raise CommandError(command_name, 'Cannot specify both alert target and --all flag')
        elif apply_all:
            self._apply_to_all_alerts(params, action)
        elif not target:
            raise CommandError(command_name, 'Alert ID/Name is required unless using --all flag')
        else:
            self._apply_to_single_alert(params, target, action)
    
    def _apply_to_single_alert(self, params, target, action):
        alert = AuditSettingMixin.get_alert_configuration(params, target)
        disabled_value = action == 'disable'

        rq = {
            'command': PUT_ENTERPRISE_SETTING,
            'type': AUDIT_ALERT_CONTEXT,
            'settings': {
                'id': alert.get('id'),
                'disabled': disabled_value
            }
        }
        api.communicate(params, rq)
        AuditSettingMixin.invalidate_alerts()
        
        alert_name = alert.get('name') or f"Alert ID {alert.get('id')}"
        action_past = 'enabled' if action == 'enable' else 'disabled'
        logging.info(f'Alert "{alert_name}" has been {action_past}')
        command = AuditAlertView()
        command.execute(params, target=target)
    
    def _apply_to_all_alerts(self, params, action):
        alerts = self.load_settings(params)
        if not isinstance(alerts, dict):
            logging.info('No alerts found')
            return
        alert_filter = alerts.get('AuditAlertFilter')
        if not isinstance(alert_filter, list):
            logging.info('No alerts found')
            return
        
        disabled_value = action == 'disable'
        requests = []
        for alert in alert_filter:
            alert_id = alert.get('id')
            if alert_id:
                rq = {
                    'command': PUT_ENTERPRISE_SETTING,
                    'type': AUDIT_ALERT_CONTEXT,
                    'settings': {
                        'id': alert_id,
                        'disabled': disabled_value
                    }
                }
                requests.append(rq)
        
        if not requests:
            action_verb = 'enable' if action == 'enable' else 'disable'
            logging.info(f'No valid alerts found to {action_verb}')
            return
        
        api.execute_batch(params, requests)
        action_past = 'Enabled' if action == 'enable' else 'Disabled'
        logging.info(f'{action_past} {len(requests)} alert(s)')
  
        AuditSettingMixin.invalidate_alerts()
        command = AuditAlertList()
        command.execute(params)


class AuditAlertRecipients(EnterpriseCommand, AuditSettingMixin):
    def get_parser(self):
        return alert_recipient_parser

    def execute(self, params, **kwargs):
        alert = AuditSettingMixin.get_alert_configuration(params, kwargs.get('target'))
        alert = copy.deepcopy(alert)
        action = kwargs.get('action')
        skip_update = False
        if action in ('enable', 'disable'):
            name = kwargs.get('recipient')
            if name == '*':
                alert['sendToOriginator'] = action == 'enable'
            else:
                r = self.find_recipient(alert, name)
                r['disabled'] = action == 'disable'
        elif action == 'delete':
            r = self.find_recipient(alert, kwargs.get('recipient'))
            alert['recipients'].remove(r)
        elif action == 'edit':
            r = self.find_recipient(alert, kwargs.get('recipient'))
            self.apply_recipient(r, kwargs)
        elif action == 'add':
            if 'recipients' not in alert:
                alert['recipients'] = []
            ids = {x['id'] for x in alert['recipients'] if 'id' in x}
            r = {}
            for i in range(1000):
                if i+1 not in ids:
                    r['id'] = i + 1
                    break
            alert['recipients'].append(r)
            self.apply_recipient(r, kwargs)
        else:
            skip_update = True

        if not skip_update:
            rq = {
                'command': 'put_enterprise_setting',
                'type': 'AuditAlertFilter',
                'settings': alert,
            }
            api.communicate(params, rq)
            self.invalidate_alerts()
        command = AuditAlertView()
        command.execute(params, target=kwargs.get('target'), recipient_only=True)

    @staticmethod
    def apply_recipient(recipient, options):
        name = options.get('name')
        if name:
            recipient['name'] = name
        email = options.get('email')
        if email is not None:
            recipient['email'] = email
        phone = options.get('phone')
        if phone is not None:
            if phone:
                if phone.startswith('+'):
                    pc = ''
                    phone = phone[1:].strip()
                    while len(phone) > 0:
                        if phone[0:1].isnumeric():
                            pc += phone[0:1]
                            phone = phone[1:]
                        else:
                            break
                    phone_country = int(pc) if pc else 1
                    phone = phone.strip()
                else:
                    phone_country = 1
                recipient['phoneCountry'] = phone_country
                recipient['phone'] = phone
            else:
                recipient['phone'] = ''
                if 'phoneCountry' in recipient:
                    del recipient['phoneCountry']
        webhook = options.get('webhook')
        if webhook is not None:
            if webhook == '':
                if 'webhook' in recipient:
                    del recipient['webhook']
            else:
                if 'webhook' not in recipient:
                    recipient['webhook'] = {
                        'url': webhook,
                        'allowUnverifiedCertificate': False,
                        'token': utils.generate_uid()
                    }
                else:
                    recipient['webhook']['url'] = webhook
        http_body = options.get('http_body')
        if http_body is not None:
            if 'webhook' in recipient:
                webhook = recipient['webhook']
                if http_body:
                    if http_body[0] == '@':
                        file_name = http_body[1:]
                        file_name = os.path.expanduser(file_name)
                        if os.path.isfile(file_name):
                            with open(file_name, 'rt', encoding='utf-8') as tf:
                                webhook_body = tf.read()
                        else:
                            raise CommandError('', f'File \"{file_name}\" not found')
                        webhook['template'] = webhook_body
                    else:
                        webhook['template'] = http_body
                elif 'template' in webhook:
                    webhook['template'] = None

        cert_errors = options.get('cert_errors')
        if cert_errors is not None:
            if 'webhook' in recipient:
                recipient['webhook']['allowUnverifiedCertificate'] = cert_errors == 'ignore'
        if options.get('generate_token') is True:
            recipient['webhook']['token'] = utils.generate_uid()

    @staticmethod
    def find_recipient(alert, name):  # type: (dict, str) -> dict
        recs = []
        if isinstance(alert, dict):
            recipients = alert.get('recipients')
            if isinstance(recipients, list):
                r_id = int(name) if name.isnumeric() else -1
                if r_id > 0:
                    for r in recipients:
                        if r.get('id') == r_id:
                            return r
                l_name = name.lower()
                for r in recipients:
                    if (r.get('name') or '').lower() == l_name:
                        recs.append(r)
        if len(recs) == 0:
            raise Exception(f'Recipient \"{name}\" not found')
        if len(recs) > 1:
            raise Exception(f'There are {len(recs)} recipients with name \"{name}\". User recipient ID.')
        return recs[0]


class AuditAlertAdd(EnterpriseCommand, AuditSettingMixin):
    def get_parser(self):
        return alert_add_parser

    def execute(self, params, **kwargs):
        name = kwargs.get('name')
        if not name:
            raise CommandError('alert add', 'Alert name is required parameter')

        settings = self.load_settings(params)
        alert_filter = settings.get('AuditAlertFilter') or []

        exists = next((True for x in alert_filter if x['name'].lower() == name.lower()), False)
        if exists:
            raise CommandError('alert add', f'Alert name \"{name}\" is not unique')

        last_id = max((x['id'] for x in alert_filter), default=0)
        if not last_id:
            last_id = 0
        alert_id = last_id + 1

        alert = {
            'id': alert_id,
            'alertUid': secrets.randbelow(2**31),
            'name': name,
            'frequency': {
                'period': 'event'
            },
            'filter': {}
        }
        self.apply_alert_options(params, alert, **kwargs)

        rq = {
            'command': 'put_enterprise_setting',
            'type': 'AuditAlertFilter',
            'settings': alert,
        }
        api.communicate(params, rq)

        active = kwargs.get('active')
        if isinstance(active, str):
            if active == 'off':
                rq = {
                    'command': 'put_enterprise_setting',
                    'type': 'AuditAlertContext',
                    'settings': {
                        'id': alert_id,
                        'disabled': True
                    }
                }
                api.communicate(params, rq)

        self.invalidate_alerts()
        command = AuditAlertView()
        command.execute(params, target=str(alert_id))


class AuditAlertEdit(EnterpriseCommand, AuditSettingMixin):
    def get_parser(self):
        return alert_edit_parser

    def execute(self, params, **kwargs):
        alert = AuditSettingMixin.get_alert_configuration(params, kwargs.get('target'))
        self.apply_alert_options(params, alert, **kwargs)

        rq = {
            'command': 'put_enterprise_setting',
            'type': 'AuditAlertFilter',
            'settings': alert,
        }
        api.communicate(params, rq)

        active = kwargs.get('active')
        if isinstance(active, str):
            alert_id = alert.get('id')
            ctx = AuditSettingMixin.get_alert_context(alert_id) or {'id': alert_id}
            current_active = 'off' if ctx.get('disabled') is True else 'on'
            if active != current_active:
                rq = {
                    'command': 'put_enterprise_setting',
                    'type': 'AuditAlertContext',
                    'settings': {
                        'id': alert_id,
                        'disabled': active == 'off'
                    }
                }
                api.communicate(params, rq)

        self.invalidate_alerts()
        command = AuditAlertView()
        command.execute(params, target=kwargs.get('target'))


class AuditAlerts(GroupCommand):
    def __init__(self):
        super(AuditAlerts, self).__init__()
        self.register_command('list', AuditAlertList(), 'Display alert list', 'l')
        self.register_command('view', AuditAlertView(), 'View alert configuration', 'v')
        self.register_command('history', AuditAlertHistory(), 'View alert history', 'h')
        self.register_command('delete', AuditAlertDelete(), 'Delete audit alert(s) - single, range, or all', 'd')
        self.register_command('add', AuditAlertAdd(), 'Add audit alert', 'a')
        self.register_command('edit', AuditAlertEdit(), 'Edit audit alert', 'e')
        self.register_command('reset-counts', AuditAlertResetCount(), 'Reset alert counts')
        self.register_command('enable', AuditAlertSent('enable'), 'Enable audit alert')
        self.register_command('disable', AuditAlertSent('disable'), 'Disable audit alert')
        self.register_command('recipient', AuditAlertRecipients(), 'Modify alert recipients', 'r')
        self.default_verb = 'list'
