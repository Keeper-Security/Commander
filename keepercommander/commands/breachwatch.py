#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import base64
import getpass
import logging
from typing import Optional, Any, Dict

from .security_audit import SecurityAuditReportCommand
from .. import api, crypto, utils, vault, vault_extensions
from .base import GroupCommand, Command, dump_report_data
from ..breachwatch import BreachWatch
from ..params import KeeperParams
from ..error import CommandError
from ..proto import breachwatch_pb2, client_pb2


breachwatch_list_parser = argparse.ArgumentParser(prog='breachwatch-list')
breachwatch_list_parser.add_argument('--all', '-a', dest='all', action='store_true',
                                     help='Display all breached records (default is to show only first 30 records)')
breachwatch_list_parser.add_argument('--owned', '-o', dest='owned', action='store_true',
                                     help='Display only breached records owned by user (omits records shared to user)')
breachwatch_list_parser.add_argument('--numbered', '-n', action='store_true',
                                     help='Display records as a numbered list')
#breachwatch_list_parser.add_argument('--ignored', '-i', dest='ignored', action='store_true', help='Display ignored records')


breachwatch_password_parser = argparse.ArgumentParser(prog='breachwatch-password')
breachwatch_password_parser.add_argument('passwords', type=str, nargs='*', help='Password')

breachwatch_scan_parser = argparse.ArgumentParser(prog='breachwatch-scan')


breachwatch_ignore_parser = argparse.ArgumentParser(prog='breachwatch-ignore')
breachwatch_ignore_parser.add_argument('records', type=str, nargs='+', help='Record UID to ignore')

breachwatch_report_parser = argparse.ArgumentParser(prog='breachwatch-report')
breachwatch_report_parser.add_argument('--format', dest='format', action='store',
                                       choices=['table', 'csv', 'json'], default='table', help='output format.')
breachwatch_report_parser.add_argument('--output', dest='output', action='store',
                                       help='output file name. (ignored for table format)')


def register_commands(commands):
    commands['breachwatch'] = BreachWatchCommand()


def register_command_info(aliases, command_info):
    aliases['bw'] = 'breachwatch'
    command_info['breachwatch'] = 'BreachWatch.'


class BreachWatchCommand(GroupCommand):
    def __init__(self):
        super(BreachWatchCommand, self).__init__()
        self.register_command('list', BreachWatchListCommand(), 'Displays a list of breached passwords.')
        self.register_command('ignore', BreachWatchIgnoreCommand(), 'Ignores breached passwords.')
        self.register_command('password', BreachWatchPasswordCommand(),
                              'Check a password against our database of breached accounts.')
        self.register_command('scan', BreachWatchScanCommand(), 'Scan vault passwords.')
        report_desc = 'Run report on BreachWatch scan results across all vaults (must be an admin).'
        self.register_command('report', BreachWatchReportCommand(), report_desc)

        self.default_verb = 'list'

    def validate(self, params):  # type: (KeeperParams) -> None
        if not params.breach_watch:
            raise CommandError('breachwatch',
                               'BreachWatch is not active. Please visit the Web Vault at https://keepersecurity.com/vault')


class BreachWatchListCommand(Command):
    def get_parser(self):
        return breachwatch_list_parser

    def execute(self, params, **kwargs):   # type: (KeeperParams, ...) -> None
        table = []
        for record, _ in BreachWatch.get_records_by_status(params, ['WEAK', 'BREACHED'], kwargs.get('owned')):
            row = [record.record_uid, record.title, vault_extensions.get_record_description(record)]
            table.append(row)

        if table:
            table.sort(key=lambda x: x[1].casefold())
            total = len(table)
            if not kwargs.get('all', False) and total > 32:
                table = table[:30]
            columns = ['Record UID', 'Title', 'Login']
            dump_report_data(table, columns, title='Detected High-Risk Password(s)', row_number=kwargs.get('numbered'))
            if len(table) < total:
                logging.info('')
                logging.info('%d records skipped.', total - len(table))
        else:
            logging.info('No breached records detected')

        has_records_to_scan = any(params.breach_watch.get_records_to_scan(params))
        if has_records_to_scan:
            logging.info('Some passwords in your vault has not been scanned.\n'
                         'Use "breachwatch scan" command to scan your passwords against our database '
                         'of breached accounts on the Dark Web.')


class BreachWatchPasswordCommand(Command):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return breachwatch_password_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, **any) -> any
        passwords = kwargs.get('passwords')
        echo_password = True
        if not passwords:
            echo_password = False
            passwords = []
            try:
                password = getpass.getpass(prompt='Password to Check: ', stream=None)
                if not password:
                    return
                passwords.append(password)
            except KeyboardInterrupt:
                print('')

        euids = []
        for result in params.breach_watch.scan_passwords(params, passwords):
            if result[1].euid:
                euids.append(result[1].euid)
            pwd = result[0] if echo_password else "".rjust(len(result[0]), "*")
            print(f'{pwd:>16s}: {"WEAK" if result[1].breachDetected else "GOOD" }')
        if euids:
            params.breach_watch.delete_euids(params, euids)


class BreachWatchScanCommand(Command):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return breachwatch_scan_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, Any) -> Any
        records = [x[0] for x in params.breach_watch.get_records_to_scan(params)]
        record_passwords = dict()    # type: Dict[str, str]
        for record in records:
            if isinstance(record, vault.PasswordRecord):
                if record.password:
                    record_passwords[record.record_uid] = record.password
            elif isinstance(record, vault.TypedRecord):
                password_field = record.get_typed_field('password')
                if password_field:
                    password = password_field.get_default_value(str)
                    if password:
                        record_passwords[record.record_uid] = password

        if len(record_passwords):
            euid_to_delete = []
            bw_requests = []
            all_passwords = set(record_passwords.values())
            scans = {x[0]: x[1] for x in params.breach_watch.scan_passwords(params, all_passwords)}
            for record_uid, record_password in record_passwords.items():
                if params.breach_watch_records:
                    if record_uid in params.breach_watch_records:
                        bwr = params.breach_watch_records[record_uid]
                        if 'data_unencrypted' in bwr:
                            passwords = bwr['data_unencrypted'].get('passwords', [])
                            for password in passwords:
                                euid = password.get('euid')
                                if euid:
                                    euid_to_delete.append(base64.b64decode(euid))
                if record_password in scans:
                    bwrq = breachwatch_pb2.BreachWatchRecordRequest()
                    bwrq.recordUid = utils.base64_url_decode(record_uid)
                    bwrq.breachWatchInfoType = breachwatch_pb2.RECORD
                    bwrq.updateUserWhoScanned = True
                    hash_status = scans[record_password]
                    bw_password = client_pb2.BWPassword()
                    bw_password.value = record_password
                    bw_password.status = client_pb2.WEAK if hash_status.breachDetected else client_pb2.GOOD
                    bw_password.euid = hash_status.euid
                    bw_data = client_pb2.BreachWatchData()
                    bw_data.passwords.append(bw_password)
                    data = bw_data.SerializeToString()
                    try:
                        record_key = params.record_cache[record_uid]['record_key_unencrypted']
                        bwrq.encryptedData = crypto.encrypt_aes_v2(data, record_key)
                    except:
                        continue
                    bw_requests.append(bwrq)
            while bw_requests:
                chunk = bw_requests[0:999]
                bw_requests = bw_requests[999:]
                rq = breachwatch_pb2.BreachWatchUpdateRequest()
                rq.breachWatchRecordRequest.extend(chunk)
                api.communicate_rest(params, rq, 'breachwatch/update_record_data',
                                     rs_type=breachwatch_pb2.BreachWatchUpdateResponse)
                params.sync_data = True
            if euid_to_delete:
                params.breach_watch.delete_euids(params, euid_to_delete)
        if not kwargs.get('suppress_no_op') or record_passwords:
            logging.info(f'Scanned {len(record_passwords)} passwords.')
            if record_passwords:
                api.sync_down(params)


class BreachWatchIgnoreCommand(Command):
    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return breachwatch_ignore_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any
        if not params.record_cache:
            return
        if not params.breach_watch_records:
            return
        records = kwargs.get('records')
        if not records:
            return

        record_uids = set()
        for record_uid in records:
            if record_uid in record_uids:
                continue
            record_uids.add(record_uid)
            if record_uid not in params.record_cache:
                logging.warning(f'Record UID "{record_uid}" not found. Skipping.')
                continue
            if record_uid not in params.breach_watch_records:
                logging.warning(f'Record UID "{record_uid}": BreachWatch information not found')
                continue

        if len(record_uids) == 0:
            return

        bw_requests = []
        for record, password in params.breach_watch.get_records_by_status(params, ['WEAK', 'BREACHED']):
            if record.record_uid not in record_uids:
                continue
            record_uids.remove(record.record_uid)
            bwrq = breachwatch_pb2.BreachWatchRecordRequest()
            bwrq.recordUid = utils.base64_url_decode(record.record_uid)
            bwrq.breachWatchInfoType = breachwatch_pb2.RECORD
            bwrq.updateUserWhoScanned = False

            bw_password = client_pb2.BWPassword()
            bw_password.value = password.get('value')
            bw_password.resolved = utils.current_milli_time()
            bw_password.status = client_pb2.IGNORE
            euid = password.get('euid')
            if euid:
                bw_password.euid = base64.b64decode(euid)
            bw_data = client_pb2.BreachWatchData()
            bw_data.passwords.append(bw_password)
            data = bw_data.SerializeToString()
            try:
                record_key = params.record_cache[record.record_uid]['record_key_unencrypted']
                bwrq.encryptedData = crypto.encrypt_aes_v2(data, record_key)
            except:
                logging.warning(f'Record UID "{record.record_uid}" encryption error. Skipping.')
                continue
            bw_requests.append(bwrq)

        for record_uid in record_uids:
            logging.warning(f'Record UID "{record_uid}" cannot ignore. Skipping.')

        if bw_requests:
            params.sync_data = True
            if params.breach_watch.send_audit_events:
                params.queue_audit_event('bw_record_ignored')

            while bw_requests:
                chunk = bw_requests[0:999]
                bw_requests = bw_requests[999:]
                rq = breachwatch_pb2.BreachWatchUpdateRequest()
                rq.breachWatchRecordRequest.extend(chunk)
                rs = api.communicate_rest(params, rq, 'breachwatch/update_record_data',
                                          rs_type=breachwatch_pb2.BreachWatchUpdateResponse)
                for status in rs.breachWatchRecordStatus:
                    logging.info(f'{utils.base64_url_encode(status.recordUid)}: {status.status} {status.reason}')


class BreachWatchReportCommand(Command):
    def get_parser(self):
        return breachwatch_report_parser

    def execute(self, params, **kwargs):
        cmd = SecurityAuditReportCommand()
        return cmd.execute(params, **{'breachwatch':True, **kwargs})
