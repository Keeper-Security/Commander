import argparse
import json
import logging
from json import JSONDecodeError
from typing import Dict, List, Optional, Any

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from keepercommander import api, crypto, utils
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
    def __init__(self):
        super(SecurityAuditReportCommand, self).__init__()
        self.tree_key = None
        self.user_lookup = None
        self.enterprise_private_rsa_key = None
        self.score_data_keys = (
            'weak_record_passwords',
            'strong_record_passwords',
            'total_record_passwords',
            'passed_records',
            'at_risk_records',
            'ignored_records'
        )

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

    def execute(self, params, **kwargs):
        if kwargs.get('syntax_help'):
            logging.info(security_audit_report_description)
            return

        if kwargs.get('breachwatch') and not params.breach_watch:
            msg = ('Ignoring "--breachwatch" option because BreachWatch is not active. '
                   'Please visit the Web Vault at https://keepersecurity.com/vault')
            logging.warning(msg)

        def get_node_id(name_or_id):
            nodes = params.enterprise.get('nodes') or []
            matches = [n for n in nodes if name_or_id in (str(n.get('node_id')), n.get('data', {}).get('displayname'))]
            node = next(iter(matches)) if matches else {}
            return node.get('node_id')

        def report_errors():
            title = 'Security Audit Report - Problems Found\nSecurity data could not be parsed for the following vaults:'
            output_fmt = kwargs.get('format', 'table')
            headers = ['vault_owner', 'error_message']
            if output_fmt == 'table':
                headers = [field_to_title(x) for x in headers]
            vault_errors = []
            for username, errors in vault_errors_lookup.items():
                vault_errors.append([username, errors])

            # Place errors not associated w/ a specific vault at the top
            vault_errors.sort(key=lambda error_row: error_row[0] != 'Enterprise')
            return dump_report_data(vault_errors, headers, fmt=output_fmt, filename=kwargs.get('output'), title=title)

        vault_errors_lookup = dict()
        def update_vault_errors(username, error):
            errors = vault_errors_lookup.get(username) or []
            errors.append(error)
            vault_errors_lookup[username] = errors

        nodes = kwargs.get('node') or []
        node_ids = [get_node_id(n) for n in nodes]
        node_ids = [n for n in node_ids if n]
        score_type = kwargs.get('score_type', 'default')
        save_report = kwargs.get('save')
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
                update_vault_errors('Enterprise', 'Invalid enterprise private key')
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
                    'node': node_path,
                    'total': 0,
                    'weak': 0,
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

                if sr.encryptedReportData:
                    try:
                        sri = crypto.decrypt_aes_v2(sr.encryptedReportData, tree_key)
                        data = json.loads(sri)
                    except Exception as ex:
                        update_vault_errors(email, ex)
                        continue
                else:
                    data = {dk: 0 for dk in self.score_data_keys}

                if show_updated:
                    try:
                        data = self.get_updated_security_report_row(sr, rsa_key, data)
                    except Exception as e:
                        reason = f"Invalid JSON: {e.doc}" if isinstance(e, JSONDecodeError) else e
                        update_vault_errors(email, reason)
                        continue


                if save_report:
                    updated_sr = APIRequest_pb2.SecurityReport()
                    updated_sr.revision = security_report_data_rs.asOfRevision
                    updated_sr.enterpriseUserId = sr.enterpriseUserId
                    report = json.dumps(data).encode('utf-8')
                    updated_sr.encryptedReportData = crypto.encrypt_aes_v2(report, tree_key)
                    updated_security_reports.append(updated_sr)

                if 'weak_record_passwords' in data:
                    row['weak'] = data.get('weak_record_passwords') or 0
                if 'strong_record_passwords' in data:
                    row['strong'] = data.get('strong_record_passwords') or 0
                if 'total_record_passwords' in data:
                    row['total'] = data.get('total_record_passwords') or 0
                if 'passed_records' in data:
                    row['passed'] = data.get('passed_records') or 0
                if 'at_risk_records' in data:
                    row['at_risk'] = data.get('at_risk_records') or 0
                if 'ignored_records' in data:
                    row['ignored'] = data.get('ignored_records') or 0

                row['medium'] = row['total'] - row['weak'] - row['strong']
                row['unique'] = row['total'] - row['reused']

                strong = row.get('strong')
                total = row.get('total')
                unique = row.get('unique')
                score = self.get_strong_by_total(total, strong) if score_type == 'strong_passwords' \
                    else self.get_security_score(total, strong, unique, twofa_on, master_pw_strength)

                # Match vault's score format (truncated, not rounded, to nearest whole %) if score_type specified
                score = int(100 * score) if score_type == 'strong_passwords' \
                    else int(100 * round(score, 2))
                row['securityScore'] = score

                rows.append(row)

        if vault_errors_lookup.keys():
            return report_errors()

        if save_report:
            self.save_updated_security_reports(params, updated_security_reports)

        show_breachwatch = kwargs.get('breachwatch') and params.breach_watch
        fields = ('email', 'name', 'at_risk', 'passed', 'ignored') if show_breachwatch else \
            ('email', 'name', 'weak', 'medium', 'strong', 'reused', 'unique', 'securityScore', 'twoFactorChannel',
             'node')
        field_descriptions = fields

        fmt = kwargs.get('format', 'table')
        if fmt == 'table':
            field_descriptions = (field_to_title(x) for x in fields)

        report_title = f'Security Audit Report{" (BreachWatch)" if show_breachwatch else ""}'
        table = []
        for raw in rows:
            row = []
            for f in fields:
                row.append(raw[f])
            table.append(row)
        return dump_report_data(table, field_descriptions, fmt=fmt, filename=kwargs.get('output'), title=report_title)

    def get_updated_security_report_row(self, sr, rsa_key, last_saved_data):
        # type: (APIRequest_pb2.SecurityReport, RSAPrivateKey, Dict[str, int]) -> Dict[str, int]
        def apply_incremental_data(old_report_data, incremental_dataset, key):
            # type: (Dict[str, int], List[APIRequest_pb2.SecurityReportIncrementalData], RSAPrivateKey) -> Dict[str, int]

            def decrypt_security_data(sec_data, k):  # type: (bytes, RSAPrivateKey) -> Dict[str, int] or None
                decrypted = None
                if sec_data:
                    decrypted = crypto.decrypt_rsa(sec_data, k)
                    decrypted = json.loads(decrypted.decode())
                return decrypted

            def decrypt_incremental_data(inc_data):
                # type: (APIRequest_pb2.SecurityReportIncrementalData) -> Dict[str, Dict[str, int] or None]
                decrypted = {
                    'old': decrypt_security_data(inc_data.oldSecurityData, key),
                    'curr': decrypt_security_data(inc_data.currentSecurityData, key)
                }
                return decrypted

            def decrypt_incremental_dataset(inc_dataset):
                # type: (List[APIRequest_pb2.SecurityReportIncrementalData]) -> List[Dict[str, Dict[str, int] or None]]
                return [decrypt_incremental_data(x) for x in inc_dataset]

            def get_security_score_deltas(rec_sec_data, delta):
                bw_result = rec_sec_data.get('bw_result')
                pw_strength = rec_sec_data.get('strength')
                deltas = dict()
                deltas['at_risk_records'] = delta if utils.is_rec_at_risk(bw_result) else 0
                deltas['weak_record_passwords'] = delta if utils.is_pw_weak(pw_strength) else 0
                deltas['strong_record_passwords'] = delta if utils.is_pw_strong(pw_strength) else 0
                deltas['passed_records'] = delta if utils.passed_bw_check(bw_result) else 0
                deltas['ignored_records'] = delta if bw_result == 4 else 0
                deltas['total_record_passwords'] = delta
                return deltas

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
                    existing_data_keys = [k for k, d in inc_data.items() if d]
                    for k in existing_data_keys:
                        user_sec_data = update(user_sec_data, inc_data.get(k), -1 if k == 'old' else 1)

                return user_sec_data

            report_data = {**old_report_data}
            if incremental_dataset:
                incremental_dataset = decrypt_incremental_dataset(incremental_dataset)
                report_data = update_scores(report_data, incremental_dataset)
            return report_data

        result = apply_incremental_data(last_saved_data, sr.securityReportIncrementalData, rsa_key)
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
        uuid_lookup = {u.get('username'): u.get('enterprise_user_id') for u in params.enterprise.get('users', [])}
        rq = enterprise_pb2.ClearSecurityDataRequest()
        rq.type = type_lookup.get(sync_type, enterprise_pb2.RECALCULATE_SUMMARY_REPORT)
        sync_all = '@all' in emails
        if sync_all:
            rq.allUsers = True
        else:
            for e in emails:
                if e in uuid_lookup:
                    rq.enterpriseUserId.append(uuid_lookup.get(e))
                else:
                    logging.error(f'Skipping unrecognized email {e}')
            if len(rq.enterpriseUserId) == 0:
                logging.error('No vaults to sync. Aborting...')
                return

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
            if confirm(prompt_txt):
                api.communicate_rest(params, rq, 'enterprise/clear_security_data')
                # Re-calculate and save new security scores
                sar_cmd = SecurityAuditReportCommand()
                return sar_cmd.execute(params, save=True)
            else:
                logging.info(f'Security-data ({sync_type}) sync aborted')

        return confirm_sync()
