import argparse
import base64
import json
import logging
from json import JSONDecodeError
from typing import Dict, List, Optional, Any

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from keepercommander import api, crypto, utils
from keepercommander.breachwatch import BreachWatch
from keepercommander.commands.base import GroupCommand, raise_parse_exception, suppress_exit, field_to_title, \
    dump_report_data
from keepercommander.commands.enterprise_common import EnterpriseCommand
from keepercommander.params import KeeperParams
from keepercommander.proto import enterprise_pb2, APIRequest_pb2
from keepercommander.utils import confirm


def register_commands(commands):
    commands['security-audit'] = SecurityAuditCommand()


def register_command_info(aliases, command_info):
    aliases['sar'] = ('security-audit', 'report')
    aliases['security-audit-report'] = ('security-audit', 'report')
    aliases['sas'] = ('security-audit', 'sync')
    command_info['security-audit'] = 'Security Audit.'


report_parser = argparse.ArgumentParser(prog='security-audit-report', description='Run a security audit report.')
report_parser.add_argument('--syntax-help', dest='syntax_help', action='store_true', help='display help')
node_filter_help = 'name(s) or UID(s) of node(s) to filter results of the report by'
report_parser.add_argument('-n', '--node', action='append', help=node_filter_help)
report_parser.add_argument('-b', '--breachwatch', dest='breachwatch', action='store_true',
                           help='display BreachWatch report. Ignored if BreachWatch is not active.')
save_help = 'save updated security audit reports'
report_parser.add_argument('-s', '--save', action='store_true', help=save_help)
report_parser.add_argument('-su', '--show-updated', action='store_true', help='show updated data')
report_parser.add_argument('-st', '--score-type', action='store', choices=['strong_passwords', 'default'],
                           default='default', help='define how score is calculated')
report_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'], default='table',
                           help='output format.')
report_parser.add_argument('--output', dest='output', action='store',
                           help='output file name. (ignored for table format)')
attempt_fix_help = ('do a "hard" sync for vaults with invalid security-data. Associated security scores are reset and '
                    'will be inaccurate until affected vaults can re-calculate and update their security-data')
report_parser.add_argument('--attempt-fix', action='store_true', help=attempt_fix_help)
report_parser.add_argument('-f', '--force', action='store_true', help='skip confirmation prompts (non-interactive mode)')
report_parser.add_argument('--debug', action='store_true', help=argparse.SUPPRESS)
report_parser.error = raise_parse_exception
report_parser.exit = suppress_exit

sync_desc = 'Sync security audit data for enterprise vault(s).'
sync_parser = argparse.ArgumentParser(prog='security-audit-sync', description=sync_desc)
type_group = sync_parser.add_mutually_exclusive_group()
soft_sync_help = 'do "soft" sync of security data. Does not require corresponding vault login. This is the ' \
                 'default sync-type.'
medium_sync_help = 'do "medium" sync of security data. Can sync some data without the corresponding vault login.'
hard_sync_help = 'do "hard" sync of security data. No data synced until corresponding vault login occurs.'
type_group.add_argument('--soft', action='store_true', help=soft_sync_help)
type_group.add_argument('--medium', action='store_true', help=medium_sync_help)
type_group.add_argument('--hard', action='store_true', help=hard_sync_help)

sync_email_help = 'email of target vault\'s owner. Accepts multiple values. Supports the following pseudo-users: @all'
sync_parser.add_argument('email', type=str, nargs='+', help=sync_email_help)
sync_verbose_help = 'run and show the latest security-audit report immediately after sync'
sync_parser.add_argument('-v', '--verbose', action='store_true', help=sync_verbose_help)
sync_parser.add_argument('-f', '--force', action='store_true', help='do sync non-interactively')
sync_parser.add_argument('--format', dest='format', action='store', choices=['csv', 'json', 'table'], default='table',
                           help='output format. Valid only with --verbose.')
sync_parser.add_argument('--output', dest='output', action='store',
                           help='output file name. Ignore for table format, valid only with --verbose')

sync_parser.error = raise_parse_exception
sync_parser.exit = suppress_exit


class SecurityAuditCommand(GroupCommand):
    def __init__(self):
        super(SecurityAuditCommand, self).__init__()
        self.register_command('report', SecurityAuditReportCommand(), report_parser.description)
        self.register_command('sync', SecurityAuditSyncCommand(), sync_parser.description)
        self.default_verb = 'report'


security_audit_report_description = '''
Security Audit Report Command Syntax Description:

Column Name       Description
  username          user name
  email             e-mail address
  weak              number of records whose password strength is in the weak category
  fair              number of records whose password strength is in the fair category
  medium            number of records whose password strength is in the medium category
  strong            number of records whose password strength is in the strong category
  reused            number of reused passwords
  unique            number of unique passwords
  securityScore     security score
  twoFactorChannel  2FA - ON/OFF

--report-type:
            csv     CSV format
            json    JSON format
            table   Table format (default)
'''


class SecurityAuditReportCommand(EnterpriseCommand):
    SECURITY_SCORE_KEYS = (
        'weak_record_passwords',
        'fair_record_passwords',
        'medium_record_passwords',
        'strong_record_passwords',
        'total_record_passwords',
        'unique_record_passwords',
    )
    BREACHWATCH_SCORE_KEYS = (
        'passed_records',
        'at_risk_records',
        'ignored_records'
    )
    SCORE_DATA_KEYS = SECURITY_SCORE_KEYS + BREACHWATCH_SCORE_KEYS

    def __init__(self):
        super(SecurityAuditReportCommand, self).__init__()
        self.tree_key = None
        self.user_lookup = None
        self.enterprise_private_rsa_key = None
        self.debug_report_builder = None
        self.error_report_builder = None

    def get_error_report_builder(self):
        if not self.error_report_builder:
            self.error_report_builder = self.ErrorReportBuilder()
        return self.error_report_builder

    def clear_ancillary_report_data(self):
        self.error_report_builder = None
        self.debug_report_builder = None

    def get_enterprise_private_rsa_key(self, params, enterprise_priv_key):
        if not self.enterprise_private_rsa_key:
            tree_key = params.enterprise['unencrypted_tree_key']
            if not enterprise_priv_key:
                key = params.enterprise.get('keys', {}).get('rsa_encrypted_private_key', '')
                enterprise_priv_key = utils.base64_url_decode(key)
            key = crypto.decrypt_aes_v2(enterprise_priv_key, tree_key)
            key = crypto.load_rsa_private_key(key)
            self.enterprise_private_rsa_key = key
        return self.enterprise_private_rsa_key

    def get_parser(self):
        return report_parser

    def get_strong_by_total(self, total, strong):
        return 0 if (total == 0) else (strong / total)

    def resolve_user_info(self, params, enterprise_user_id):
        if self.user_lookup is None or params.enterprise.get('unencrypted_tree_key') != self.tree_key:
            self.tree_key = params.enterprise.get('unencrypted_tree_key')
            self.user_lookup = {}
            for user in params.enterprise.get('users'):
                if 'enterprise_user_id' in user and 'username' in user:
                    email = user['username']
                    username = user['data']['displayname'] if 'data' in user and 'displayname' in user['data'] \
                        else None
                    if (username is None or not username.strip()) and 'encrypted_data' in user and 'key_type' in user:
                        username = user['encrypted_data'] if user['key_type'] == 'no_key' else None
                    username = email if username is None or not username.strip() else username
                    node_id = user.get('node_id', 0)
                    self.user_lookup[user['enterprise_user_id']] = {
                        'username': username,
                        'email': email,
                        'node_id': node_id
                    }

        info = {
            'username': enterprise_user_id,
            'email': enterprise_user_id
        }

        if enterprise_user_id in self.user_lookup:
            info = self.user_lookup[enterprise_user_id]

        return info

    def get_security_score(self, total, strong, unique, twoFactorOn, masterPassword):
        strongByTotal = self.get_strong_by_total(total, strong)
        uniqueByTotal = 0 if (total == 0) else (unique / total)
        twoFactorOnVal = 1 if (twoFactorOn is True) else 0
        score = (strongByTotal + uniqueByTotal + masterPassword + twoFactorOnVal) / 4
        return score

    def flatten_report_data(self, data, num_reused_pws):
        sec_stats = data.get('securityAuditStats', {})
        bw_stats = data.get('bwStats', {})
        total = data.get('total_record_passwords') or sec_stats.get('total_record_passwords', 0)
        result = {k: data.get(k) or sec_stats.get(k) or bw_stats.get(k, 0) for k in self.SCORE_DATA_KEYS}
        result['unique_record_passwords'] = total - num_reused_pws
        # Fill in missing medium password count if report data is in old format
        if not sec_stats:
            weak = result.get('weak_record_passwords', 0)
            strong = result.get('strong_record_passwords', 0)
            result['medium_record_passwords'] = total - weak - strong
        return result

    def format_report_data(self, flattened_data):
        sec_stats = {k: flattened_data.get(k) for k in self.SECURITY_SCORE_KEYS}
        bw_stats = {k: flattened_data.get(k) for k in self.BREACHWATCH_SCORE_KEYS}
        return {'securityAuditStats': sec_stats, 'bwStats': bw_stats}

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(security_audit_report_description)
            return

        self.enterprise_private_rsa_key = None

        show_breachwatch = kwargs.get('breachwatch')
        if show_breachwatch:
            BreachWatch.validate_reporting('security-audit-report', params)

        def get_node_id(name_or_id):
            nodes = params.enterprise.get('nodes') or []
            matches = [n for n in nodes if name_or_id in (str(n.get('node_id')), n.get('data', {}).get('displayname'))]
            node = next(iter(matches)) if matches else {}
            return node.get('node_id')

        self.clear_ancillary_report_data()
        debug_mode = kwargs.get('debug')
        self.debug_report_builder = debug_mode and self.DebugReportBuilder()
        force = kwargs.get('force')
        attempt_fix = kwargs.get('attempt_fix')

        nodes = kwargs.get('node') or []
        node_ids = [get_node_id(n) for n in nodes]
        node_ids = [n for n in node_ids if n]
        score_type = kwargs.get('score_type', 'default')
        save_report = kwargs.get('save') or attempt_fix
        show_updated = save_report or kwargs.get('show_updated')
        updated_security_reports = []
        tree_key = (params.enterprise or {}).get('unencrypted_tree_key')
        from_page = 0
        complete = False
        rows = []
        while not complete:
            rq = APIRequest_pb2.SecurityReportRequest()
            rq.fromPage = from_page
            security_report_data_rs = api.communicate_rest(
                params, rq, 'enterprise/get_security_report_data', rs_type=APIRequest_pb2.SecurityReportResponse)
            to_page = security_report_data_rs.toPage
            complete = security_report_data_rs.complete
            from_page = to_page + 1
            try:
                rsa_key = self.get_enterprise_private_rsa_key(params, security_report_data_rs.enterprisePrivateKey)
            except:
                self.get_error_report_builder().set_current_email('Enterprise')
                self.get_error_report_builder().update_report_data('Invalid enterprise private key')
                continue

            for sr in security_report_data_rs.securityReport:
                user_info = self.resolve_user_info(params, sr.enterpriseUserId)
                node_id = user_info.get('node_id', 0)
                if node_ids and node_id not in node_ids:
                    continue
                user = user_info['username'] if 'username' in user_info else str(sr.enterpriseUserId)
                email = user_info['email'] if 'email' in user_info else str(sr.enterpriseUserId)
                node_path = self.get_node_path(params, node_id) if node_id > 0 else ''
                twofa_on = False if sr.twoFactor == 'two_factor_disabled' else True
                row = {
                    'name': user,
                    'email': email,
                    'sync_pending': None,
                    'node': node_path,
                    'total': 0,
                    'weak': 0,
                    'fair': 0,
                    'medium': 0,
                    'strong': 0,
                    'reused': sr.numberOfReusedPassword,
                    'unique': 0,
                    'passed': 0,
                    'at_risk': 0,
                    'ignored': 0,
                    'securityScore': 25,
                    'twoFactorChannel': 'Off' if sr.twoFactor == 'two_factor_disabled' else 'On'
                }
                master_pw_strength = 1

                self.get_error_report_builder().set_current_email(email)
                if sr.encryptedReportData:
                    try:
                        sri = crypto.decrypt_aes_v2(sr.encryptedReportData, tree_key)
                    except Exception as e:
                        msg = f'Decryption fail (old summary report). Reason: {e}'
                        logging.error(msg)
                        continue

                    try:
                        data = self.flatten_report_data(json.loads(sri), sr.numberOfReusedPassword)
                    except Exception as e:
                        logging.error(e)
                        continue
                else:
                    data = {dk: 0 for dk in self.SCORE_DATA_KEYS}

                if show_updated or debug_mode:
                    debug_mode and self.debug_report_builder.set_current_email(email)
                    data = self.get_updated_security_report_row(sr, rsa_key, data)

                # Skip summary-score calculation if errors encountered or debug/incremental-data-reporting is enabled
                if debug_mode or self.get_error_report_builder().has_errors_to_report() and not attempt_fix:
                    continue

                if save_report and not self.get_error_report_builder().has_errors_to_report():
                    updated_sr = APIRequest_pb2.SecurityReport()
                    updated_sr.revision = security_report_data_rs.asOfRevision
                    updated_sr.enterpriseUserId = sr.enterpriseUserId
                    report = json.dumps(self.format_report_data(data)).encode('utf-8')
                    updated_sr.encryptedReportData = crypto.encrypt_aes_v2(report, tree_key)
                    updated_security_reports.append(updated_sr)

                to_row_name = lambda name: name.split('_').pop(0) if name in self.SECURITY_SCORE_KEYS \
                    else '_'.join(name.split('_')[:-1])

                for k, v in data.items():
                    row[to_row_name(k)] = v

                strong = row.get('strong')
                total = row.get('total')
                unique = row.get('unique')
                if unique < 0 < total and attempt_fix:
                    self.get_error_report_builder().update_report_data('Missing security-data')
                    continue

                if total == 0 and row.get('reused') != 0:
                    row['sync_pending'] = True

                score = self.get_strong_by_total(total, strong) if score_type == 'strong_passwords' \
                    else self.get_security_score(total, strong, unique, twofa_on, master_pw_strength)

                # Match vault's score format (truncated, not rounded, to nearest whole %) if score_type specified
                score = int(100 * score) if score_type == 'strong_passwords' \
                    else int(100 * round(score, 2))
                row['securityScore'] = score

                rows.append(row)

        fmt = kwargs.get('format', 'table')
        out = kwargs.get('output')

        # Prioritize error-reports (created if any errors are encountered while parsing security score data) over others
        if self.get_error_report_builder().has_errors_to_report():
            error_report_builder = self.get_error_report_builder()
            fix_instructions = ('\nNote: To resolve the issues found above, re-run this command with the'
                                ' --attempt-fix switch, i.e., run\n\tsar --attempt-fix')
            result = error_report_builder.sync_problem_vaults(params, out, fmt=fmt, force=force) if attempt_fix \
                else error_report_builder.get_report(out, fmt)
            if not attempt_fix:
                if result is None:
                    logging.error(fix_instructions)
                else:
                    result += fix_instructions
            return result
        elif debug_mode:
            return self.debug_report_builder.get_report(out, fmt)

        if save_report:
            self.save_updated_security_reports(params, updated_security_reports)

        fields = ('email', 'name', 'sync_pending', 'at_risk', 'passed', 'ignored') if show_breachwatch else \
            ('email', 'name', 'sync_pending', 'weak', 'fair', 'medium', 'strong', 'reused', 'unique', 'securityScore',
             'twoFactorChannel', 'node')
        field_descriptions = fields

        if fmt == 'table':
            field_descriptions = (field_to_title(x) for x in fields)

        report_title = f'Security Audit Report{" (BreachWatch)" if show_breachwatch else ""}'
        table = []
        for raw in rows:
            row = []
            for f in fields:
                row.append(raw[f])
            table.append(row)
        return dump_report_data(table, field_descriptions, fmt=fmt, filename=out, title=report_title)

    def get_updated_security_report_row(self, sr, rsa_key, last_saved_data):
        # type: (APIRequest_pb2.SecurityReport, RSAPrivateKey, Dict[str, int]) -> Dict[str, int]
        def apply_incremental_data(old_report_data, incremental_dataset, key):
            # type: (Dict[str, int], List[APIRequest_pb2.SecurityReportIncrementalData], RSAPrivateKey) -> Dict[str, int]
            def decrypt_security_data(sec_data, k):  # type: (bytes, RSAPrivateKey) -> Dict[str, int] or None
                decrypted = None
                if sec_data:
                    try:
                        decrypted_bytes = crypto.decrypt_rsa(sec_data, k, apply_padding=True)
                    except Exception as e:
                        error = f'Decrypt fail (incremental data): {e}'
                        self.get_error_report_builder().update_report_data(error)
                        return

                    try:
                        decoded = decrypted_bytes.decode()
                    except UnicodeDecodeError:
                        error = f'Decode fail, incremental data (base 64):'
                        self.get_error_report_builder().update_report_data(error)
                        decoded_b64 = base64.b64encode(decrypted_bytes).decode('ascii')
                        self.get_error_report_builder().update_report_data(decoded_b64)
                        return
                    except Exception as e:
                        error = f'Decode fail: {e}'
                        self.get_error_report_builder().update_report_data(error)
                        return

                    try:
                        decrypted = json.loads(decoded)
                    except JSONDecodeError as jde:
                        error = f'Invalid JSON: {decoded}'
                        self.get_error_report_builder().update_report_data(error)
                    except Exception as e:
                        error = f'Load fail (incremental data). {e}'
                        self.get_error_report_builder().update_report_data(error)

                return decrypted

            def decrypt_incremental_data(inc_data):
                # type: (APIRequest_pb2.SecurityReportIncrementalData) -> Dict[str, Dict[str, int] or None]
                decrypted = {
                    'old': decrypt_security_data(inc_data.oldSecurityData, key),
                    'curr': decrypt_security_data(inc_data.currentSecurityData, key)
                }
                self.debug_report_builder and self.debug_report_builder.update_report_data(decrypted)
                return decrypted

            def decrypt_incremental_dataset(inc_dataset):
                # type: (List[APIRequest_pb2.SecurityReportIncrementalData]) -> List[Dict[str, Dict[str, int] or None]]
                return [decrypt_incremental_data(x) for x in inc_dataset]

            def get_security_score_deltas(rec_sec_data, delta):
                bw_result = rec_sec_data.get('bw_result')
                pw_strength = rec_sec_data.get('strength')
                sec_deltas = {k: 0 for k in self.SECURITY_SCORE_KEYS}
                bw_deltas = {k: 0 for k in self.BREACHWATCH_SCORE_KEYS}
                sec_key = 'strong_record_passwords' if utils.is_pw_strong(pw_strength) \
                    else 'fair_record_passwords' if utils.is_pw_fair(pw_strength) \
                    else 'weak_record_passwords' if utils.is_pw_weak(pw_strength) \
                    else 'medium_record_passwords'
                sec_deltas[sec_key] = delta
                sec_deltas['total_record_passwords'] = delta

                bw_key = 'at_risk_records' if utils.is_rec_at_risk(bw_result) \
                    else 'passed_records' if utils.passed_bw_check(bw_result) \
                    else 'ignored_records'
                bw_deltas[bw_key] = delta

                return {**sec_deltas, **bw_deltas}

            def apply_score_deltas(sec_data, deltas):
                new_scores = {k: v + sec_data.get(k, 0) for k, v in deltas.items()}
                sec_data = {**sec_data, **new_scores}
                return sec_data

            def update_scores(user_sec_data, inc_dataset):
                def update(u_sec_data, old_sec_d, diff):
                    if not old_sec_d:
                        return u_sec_data
                    deltas = get_security_score_deltas(old_sec_d, diff)
                    return apply_score_deltas(u_sec_data, deltas)

                for inc_data in inc_dataset:
                    if any(d for d in inc_data.values() if d is not None and d.get('strength') is None):
                        self.get_error_report_builder().update_report_data('Invalid data: "strength" is undefined')
                        break
                    existing_data_keys = [k for k, d in inc_data.items() if d]
                    for k in existing_data_keys:
                        user_sec_data = update(user_sec_data, inc_data.get(k), -1 if k == 'old' else 1)

                return user_sec_data

            report_data = {**old_report_data}
            if incremental_dataset:
                incremental_dataset = decrypt_incremental_dataset(incremental_dataset)
                # Skip score-aggregation if only incremental data are to be included in the report
                if not self.debug_report_builder:
                    report_data = update_scores(report_data, incremental_dataset)
            return report_data

        result = apply_incremental_data(last_saved_data, sr.securityReportIncrementalData, rsa_key)
        # Update unique password count
        total = result.get('total_record_passwords', 0)
        result['unique_record_passwords'] = total - sr.numberOfReusedPassword
        return result

    @staticmethod
    def save_updated_security_reports(params, reports):
        save_rq = APIRequest_pb2.SecurityReportSaveRequest()
        for r in reports:
            save_rq.securityReport.append(r)
        api.communicate_rest(params, save_rq, 'enterprise/save_summary_security_report')

    @staticmethod
    def get_title_for_field(field):  # type: (str) -> str
        if field == 'username':
            return 'User'
        elif field == 'email':
            return 'E-Mail'
        elif field == 'node_path':
            return 'Node'
        elif field == 'securityScore':
            return 'Security Score'
        elif field == 'twoFactorChannel':
            return '2FA'
        elif field == 'at_risk':
            return 'At Risk'

        return field.capitalize()

    class AncillaryReportBuilder:
        def __init__(self):
            self.report_data = dict()  # type: Dict[str, List[Any]]
            self.current_email = ''

        def set_current_email(self, value):
            self.current_email = value

        def update_report_data(self, data):
            current_email_data = self.report_data.get(self.current_email, [])
            self.report_data[self.current_email] = [*current_email_data, data]

        def get_report(self, out, fmt='table'):
            pass

    class ErrorReportBuilder(AncillaryReportBuilder):
        def has_errors_to_report(self):
            return bool(self.report_data.values())

        def get_report(self, out, fmt='table'):
            title = 'Security Audit Report - Problems Found\nSecurity data could not be parsed for the following vaults:'
            headers = ['vault_owner', 'error_message']
            if fmt == 'table':
                headers = [field_to_title(x) for x in headers]

            vault_errors_table = [[username, errors] for username, errors in self.report_data.items()]

            # Place errors not associated w/ a specific vault at the top
            vault_errors_table.sort(key=lambda error_row: error_row[0] != 'Enterprise')
            return dump_report_data(vault_errors_table, headers, fmt=fmt, filename=out, title=title)

        def sync_problem_vaults(self, params, out, fmt='table', force=False):
            owners = [x for x in self.report_data.keys() if '@' in x]
            confirm_txt = (f'{len(owners)} vault(s) with invalid security-data found.'
                           f'\nDo you wish to try to repair these data?')
            if force or confirm(confirm_txt):
                sync_command = SecurityAuditSyncCommand()
                cmd_kwargs = {
                    'email': owners,
                    'hard': True,
                    'force': True,
                    'verbose': True,
                    'output': out,
                    'format': fmt
                }
                return sync_command.execute(params, **cmd_kwargs)
            else:
                return self.get_report(out, fmt)

    class DebugReportBuilder(AncillaryReportBuilder):
        def get_report(self, out, fmt='table'):
            def tabulate_debug_data():
                table = []
                for email, inc_dataset in self.report_data.items():
                    if not inc_dataset:
                        continue
                    row = [email, [x.get('old') for x in inc_dataset], [x.get('curr') for x in inc_dataset]]
                    table.append(row)
                return table

            title = 'Security Audit Report: Debugging Info'
            headers = ['vault_owner', 'old_incremental_data', 'current_incremental_data']
            if fmt == 'table':
                headers = [field_to_title(x) for x in headers]
            debug_data = tabulate_debug_data()
            return dump_report_data(debug_data, headers, fmt=fmt, filename=out, title=title)


class SecurityAuditSyncCommand(EnterpriseCommand):
    def __init__(self):
        super(SecurityAuditSyncCommand, self).__init__()

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return sync_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, Any) -> Any
        type_lookup = {'soft': enterprise_pb2.RECALCULATE_SUMMARY_REPORT,
                       'medium': enterprise_pb2.FORCE_CLIENT_CHECK_FOR_MISSING_DATA,
                       'hard': enterprise_pb2.FORCE_CLIENT_RESEND_SECURITY_DATA}
        sync_type = next((st for st in type_lookup if kwargs.get(st)), 'soft')
        emails = kwargs.get('email')
        userid_lookup = {u.get('username'): u.get('enterprise_user_id') for u in params.enterprise.get('users', [])}
        sync_all = '@all' in emails
        userids = [userid_lookup.get(email) for email in emails if userid_lookup.get(email)]

        if not userids and not sync_all:
            logging.error('No vaults to sync. Aborting...')
            return

        def do_sync(target_ids, target_all=False):
            CHUNK_SIZE = 999
            while True:
                rq = enterprise_pb2.ClearSecurityDataRequest()  # type: enterprise_pb2.ClearSecurityDataRequest
                rq.type = type_lookup.get(sync_type, enterprise_pb2.RECALCULATE_SUMMARY_REPORT)
                rq.allUsers = target_all
                if not target_all:
                    chunk = [id for id in target_ids[:CHUNK_SIZE] if id]
                    target_ids = target_ids[CHUNK_SIZE:]
                    rq.enterpriseUserId.extend(chunk)

                api.communicate_rest(params, rq, 'enterprise/clear_security_data')
                if target_all or not target_ids:
                    break

        def confirm_sync():
            sync_targets = ['ALL USERS'] if sync_all else emails.copy()
            sync_targets = '\n'.join(sync_targets)
            prompt_title = f'\nYou are about to do a "{sync_type}" sync of security data for the following users: \n'
            confirm_txt = 'Do you wish to proceed?'
            if sync_type == 'hard':
                hard_sync_desc = f'NOTE: this action will likely result in temporarily-mismatching ' \
                                 f'scores for the vaults indicated above. \n' \
                                 f'Once a "hard" sync has been initiated, each affected vault owner MUST log in to ' \
                                 f'their account at least once in order to complete the process and re-align security' \
                                 f' scores.'
                confirm_txt = f'{hard_sync_desc}\n\n{confirm_txt}'
            prompt_txt = f'{prompt_title}{sync_targets}\n\n{confirm_txt}'
            if kwargs.get('force') or confirm(prompt_txt):
                do_sync(userids, sync_all)
                # Re-calculate and save new security scores
                if kwargs.get('verbose'):
                    sar_cmd = SecurityAuditReportCommand()
                    fmt = kwargs.get('format', 'table')
                    out = kwargs.get('output')
                    return sar_cmd.execute(params, save=True, format=fmt, output=out)
            else:
                logging.info(f'Security-data ({sync_type}) sync aborted')

        return confirm_sync()
