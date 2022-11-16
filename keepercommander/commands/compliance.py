import argparse
import datetime
import logging
import operator
from typing import Optional, Dict, Tuple, Union

from keepercommander.commands.base import GroupCommand, dump_report_data, field_to_title
from keepercommander.commands.enterprise_common import EnterpriseCommand
from keepercommander.sox.sox_types import RecordPermissions
from .. import sox, api
from ..error import CommunicationError
from ..params import KeeperParams

compliance_parser = argparse.ArgumentParser(add_help=False)
compliance_parser.add_argument('--rebuild', '-r', action='store_true', help='rebuild local data from source')
compliance_parser.add_argument('--no-cache', '-nc', action='store_true',
                               help='remove any local non-memory storage of data after report is generated')
compliance_parser.add_argument('--node', action='store', help='ID or name of node (defaults to root node)')
compliance_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                               default='table', help='format of output')
compliance_parser.add_argument('--output', dest='output', action='store',
                               help='path to resulting output file (ignored for "table" format)')

default_report_parser = argparse.ArgumentParser(prog='compliance-report', description='Run a SOX compliance report.',
                                                parents=[compliance_parser])
username_opt_help = 'user(s) whose records are to be included in report (set option once per user)'
default_report_parser.add_argument('--username', '-u', action='append', help=username_opt_help)
job_title_opt_help = 'job title(s) of users whose records are to be included in report (set option once per job title)'
default_report_parser.add_argument('--job-title', '-jt', action='append', help=job_title_opt_help)
team_opt_help = 'name or UID of team(s) whose members\' records are to be included in report (set once per team)'
default_report_parser.add_argument('--team', action='append', help=team_opt_help)
record_search_help = 'UID or title of record(s) to include in report (set once per record). To allow non-exact ' \
                     'matching on record titles, include "*" where appropriate (e.g., to include records with titles' \
                     ' ending in "Login", set option value to "*Login")'
default_report_parser.add_argument('--record', action='append', help=record_search_help)
default_report_parser.add_argument('--url', action='append',
                                   help='URL of record(s) to include in report (set once per URL)')
default_report_parser.add_argument('--shared', action='store_true',
                                   help='flag for excluding non-shared records from report')

team_report_desc = 'Run a report showing which shared folders enterprise teams have access to'
team_report_parser = argparse.ArgumentParser(prog='compliance-team-report', description=team_report_desc,
                                             parents=[compliance_parser])

access_report_desc = 'Run a report showing all records a user has accessed'
access_report_parser = argparse.ArgumentParser(prog='compliance-team-report', description=access_report_desc,
                                               parents=[compliance_parser])
access_report_parser.add_argument('user', metavar='USER', type=str, help='username or ID')


def register_commands(commands):
    commands['compliance'] = ComplianceCommand()


def register_command_info(aliases, command_info):
    aliases['cr'] = 'compliance'
    aliases['compliance-report'] = 'compliance'
    command_info['compliance'] = 'SOX Compliance Reporting'


class ComplianceCommand(GroupCommand):
    def __init__(self):
        super(ComplianceCommand, self).__init__()
        self.register_command('report', ComplianceReportCommand(), 'Run default SOX compliance report')
        self.register_command('team-report', ComplianceTeamReportCommand())
        self.register_command('record-access-report', ComplianceRecordAccessReportCommand())
        self.default_verb = 'report'

    def execute_args(self, params, args, **kwargs):  # type: (KeeperParams, str, dict) -> any
        if kwargs.get('command') in ('compliance-report', 'cr'):
            kwargs['command'] = 'compliance'
            args = ' '.join([self.default_verb, args])

        return super().execute_args(params, args, **kwargs)

    def validate(self, params):  # type: (KeeperParams) -> None
        sox.validate_data_access(params, cmd='compliance')


class BaseComplianceReportCommand(EnterpriseCommand):
    def __init__(self, report_headers, allow_no_opts=True, prelim_only=False):
        super(BaseComplianceReportCommand, self).__init__()
        self.report_headers = report_headers
        self.allow_no_opts = allow_no_opts
        self.prelim_only = prelim_only

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        pass

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        return []

    def show_help_text(self, local_data):
        pass

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any
        node_name_or_id = kwargs.get('node')
        node_name_or_id = int(node_name_or_id) if node_name_or_id and node_name_or_id.isdecimal() else node_name_or_id
        nodes = params.enterprise['nodes']
        root_node_id = nodes[0].get('node_id', 0)
        node_ids = (n.get('node_id') for n in nodes)
        node_id_lookup = {n.get('data').get('displayname'): n.get('node_id') for n in nodes}
        node_id = node_id_lookup.get(node_name_or_id) if node_name_or_id in node_id_lookup \
            else node_name_or_id if node_name_or_id in node_ids \
            else root_node_id
        enterprise_id = node_id >> 32
        max_data_age = datetime.timedelta(days=1)
        min_data_ts = (datetime.datetime.now() - max_data_age).timestamp()

        default_opts = {'command', 'action', 'format'}
        opts_set = [val for opt, val in kwargs.items() if val and opt not in default_opts]
        if not opts_set and not self.allow_no_opts:
            local_sox_data = sox.get_compliance_data(params, node_id, enterprise_id, False, min_updated=0)
            self.show_help_text(local_sox_data)
            return

        rebuild = kwargs.get('rebuild')
        no_cache = kwargs.get('no_cache')
        get_sox_data_fn = sox.get_prelim_data if self.prelim_only else sox.get_compliance_data
        fn_args = [params, enterprise_id] if self.prelim_only else [params, node_id, enterprise_id]
        fn_kwargs = {'rebuild': rebuild, 'min_updated': min_data_ts, 'no_cache': no_cache}
        sd = get_sox_data_fn(*fn_args, **fn_kwargs)
        report_fmt = kwargs.get('format', 'table')
        headers = self.report_headers if report_fmt == 'json' else [field_to_title(h) for h in self.report_headers]
        report_data = self.generate_report_data(params, kwargs, sd, report_fmt, node_id, root_node_id)
        return dump_report_data(report_data, headers, fmt=report_fmt, filename=kwargs.get('output'), column_width=32)


class ComplianceReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['record_uid', 'title', 'type', 'username', 'permissions', 'url']
        super(ComplianceReportCommand, self).__init__(headers, False)

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return default_report_parser

    def show_help_text(self, local_data):  # type: (sox.sox_data.SoxData) -> None
        last_update_ts = local_data.storage.last_compliance_data_update
        if not last_update_ts:
            logging.info("Cache last update: NONE -- to build the cache, call the following command:"
                         "\n\t'compliance-report --rebuild'")
        else:
            last_update = datetime.datetime.fromtimestamp(last_update_ts)
            num_users = len(local_data.get_users())
            num_shared = len([rec for rec in local_data.get_records().values() if rec.shared])
            msg = f'cache last update: {last_update} Total records: {local_data.record_count} ' \
                  f'Total Users: {num_users} Total shared records: {num_shared}'
            logging.info(msg)
        help_txt = "\nGet record and sharing information from all vaults in the enterprise\n" \
                   "Format:\ncompliance-report [-h] [--rebuild] [--no-cache] [--node NODE] [--username USERNAME] " \
                   "[--job-title JOB_TITLE] [--team TEAM] [--record RECORD] [--url DOMAIN] [--shared] " \
                   "[--format {table,csv,json}] [--output OUTPUT] " \
                   "\n\nExamples:" \
                   "\nSee all records for a user" \
                   "\n\t'compliance-report --username USERNAME'" \
                   "\nFind all records for a specific URL that have been shared" \
                   "\n\t'compliance-report --shared --url URL'" \
                   "\nExport report of all shared records in a node" \
                   "\n\t'compliance-report --shared --output compliance_share_report.csv --format csv " \
                   "--node NODE_NAME_OR_ID'" \
                   "\n\t* use 'enterprise-info --node' to see a list of available nodes" \
                   "\nCache controls" \
                   "\n\t'compliance-report --rebuild'  " \
                   "\tUpdate and rebuild the cache with new compliance information." \
                   "\n\t'compliance-report --no-cache'\tDelete the cache entirely.The cache will be rebuilt if " \
                   "compliance-report is run again."
        logging.info(help_txt)

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        def filter_owners(rec_owners):
            def filter_by_teams(users, teams):
                enterprise_teams = params.enterprise.get('teams', [])
                team_uids = {t.get('team_uid') for t in enterprise_teams}
                enterprise_team_users = params.enterprise.get('team_users', [])

                def get_team_users(team_ref):
                    team_ids = {team_ref} if team_ref in team_uids \
                        else {t.get('team_uid') for t in enterprise_teams if team_ref == t.get('name')}
                    return {u.get('enterprise_user_id') for u in enterprise_team_users if u.get('team_uid') in team_ids}

                team_users = set()
                for t_ref in teams:
                    team_users.update(get_team_users(t_ref))

                return [u for u in users if u.user_uid in team_users]

            usernames = kwargs.get('username')
            filtered = [o for o in rec_owners if o.email in usernames] if usernames else rec_owners
            job_titles = kwargs.get('job_title')
            filtered = [o for o in filtered if o.job_title in job_titles] if job_titles else filtered
            filtered = [o for o in filtered if o.node_id == node] if node != root_node else filtered
            team_refs = kwargs.get('team')
            filtered = filter_by_teams(filtered, team_refs) if team_refs else filtered
            return filtered

        def filter_records(records):
            shared_only = kwargs.get('shared')
            filtered = [r for r in records if not shared_only or r.shared]
            urls = kwargs.get('url')
            filtered = [r for r in filtered for url in urls if r.data.get('url') and url in r.data.get('url')] if urls \
                else filtered
            r_refs = kwargs.get('record')
            from fnmatch import fnmatch

            def title_match(title):
                return any([ref for ref in r_refs if fnmatch(title, ref)]) if title else False

            filtered = [r for r in filtered if r.record_uid in r_refs or title_match(r.data.get('title'))] if r_refs \
                else filtered
            return filtered

        owners = filter_owners(sox_data.get_users().values())
        shared_folders = sox_data.get_shared_folders()
        permissions_lookup = dict()  # type: Dict[Tuple[str, str], str]

        def update_permissions_lookup(perm_lookup, rec_uid, enterprise_user, perm_bits):
            lookup_key = rec_uid, enterprise_user.email
            p_bits = perm_lookup.get(lookup_key, perm_bits)
            perm_lookup.update({lookup_key: perm_bits | p_bits})

        for owner in owners:
            owner_records = filter_records(sox_data.get_records(owner.records).values())
            for record in owner_records:
                if not record:
                    continue
                r_uid = record.record_uid
                for user_uid, permission_bits in record.user_permissions.items():
                    user = sox_data.get_user(user_uid)
                    update_permissions_lookup(permissions_lookup, r_uid, user, permission_bits)
                for folder in shared_folders.values():
                    for rp in folder.record_permissions:
                        if rp.record_uid == r_uid:
                            for user in sox_data.get_users(folder.users).values():
                                update_permissions_lookup(permissions_lookup, r_uid, user, rp.permission_bits)
                            for team in sox_data.get_teams(folder.teams).values():
                                for team_user in sox_data.get_users(team.users).values():
                                    update_permissions_lookup(permissions_lookup, r_uid, team_user, rp.permission_bits)

        table = []
        for key, permission_bits in permissions_lookup.items():
            r_uid, email = key
            table.append({'record_uid': r_uid, 'email': email, 'permissions': permission_bits})

        def format_table(rows):
            rows.sort(key=operator.itemgetter('permissions'), reverse=True)
            rows.sort(key=lambda item: item.get('permissions') & 1, reverse=True)
            rows.sort(key=operator.itemgetter('record_uid'))
            last_rec_uid = ''
            formatted_rows = []
            record_lookup = sox_data.get_records()
            for row in rows:
                rec_uid = row.get('record_uid')
                rec = record_lookup.get(rec_uid)
                r_data = rec.data
                r_title = r_data.get('title', '')
                r_type = r_data.get('record_type', '')
                r_url = r_data.get('url', '')
                formatted_rec_uid = rec_uid if report_fmt != 'table' or last_rec_uid != rec_uid else ''
                u_email = row.get('email')
                permissions = RecordPermissions.to_permissions_str(row.get('permissions'))
                fmt_row = [formatted_rec_uid, r_title, r_type, u_email, permissions, r_url.rstrip('/')]
                formatted_rows.append(fmt_row)
                last_rec_uid = rec_uid
            return formatted_rows

        report_data = format_table(table)
        return report_data


class ComplianceTeamReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['team_name', 'shared_folder_name', 'shared_folder_uid', 'permissions']
        super(ComplianceTeamReportCommand, self).__init__(headers, True)

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return team_report_parser

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        def get_sf_name(uid):
            # TODO: get sf name via share admin data when implemented (for now, find in params.shared_folder_cache)
            sf = params.shared_folder_cache.get(uid, {})
            return sf.get('name_unencrypted', '')

        shared_folders = sox_data.get_shared_folders().items()
        team_lookup = sox_data.get_teams()
        report_data = []
        for sf_uid, folder in shared_folders:
            if not folder.record_permissions:
                continue
            for team_uid in folder.teams:
                team = team_lookup.get(team_uid)
                perms = next(iter(folder.record_permissions)).permissions
                report_data.append([team.team_name, get_sf_name(sf_uid), sf_uid, perms])

        return report_data


class ComplianceRecordAccessReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['record_uid',
                   'record_title',
                   'record_url',
                   'record_owner',
                   'ip_address',
                   'device',
                   'last_access']
        super(ComplianceRecordAccessReportCommand, self).__init__(headers, True, True)

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return access_report_parser

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        def get_accessed_records(user):
            columns = ['record_uid', 'ip_address', 'keeper_version']
            rq_filter = {'username': user, 'audit_event_type': 'open_record'}
            from keepercommander.commands.aram import API_EVENT_SUMMARY_ROW_LIMIT
            rq = {
                'command':      'get_audit_event_reports',
                'report_type':  'span',
                'scope':        'enterprise',
                'aggregate':    ['last_created'],
                'limit':        API_EVENT_SUMMARY_ROW_LIMIT,
                'filter':       rq_filter,
                'columns':      columns,
            }
            records_accessed = dict()   # type: Dict[str, Dict[str, Union[int, str]]]

            def update_records_accessed(events):
                for event in events:
                    r_uid = event.get('record_uid')
                    if r_uid not in records_accessed:
                        records_accessed.update({r_uid: event})

            def get_events(max_ts):
                rq_filter['created'] = {'max': max_ts}
                rs = api.communicate(params, rq)
                return rs.get('audit_event_overview_report_rows')

            max_ts = int(datetime.datetime.now().timestamp())
            while True:
                events = get_events(max_ts)
                update_records_accessed(events)
                if len(events) >= API_EVENT_SUMMARY_ROW_LIMIT:
                    earliest_event = events[-1]
                    max_ts = int(earliest_event.get('last_created'))
                else:
                    break
            return records_accessed

        def fill_table(access_events):
            table = []
            for rec in access_events.values():
                rec_uid = rec.get('record_uid')
                sox_rec = sox_data.get_records().get(rec_uid)
                rec_info = sox_rec.data if sox_rec else {}
                rec_owner = sox_data.get_record_owner(rec_uid)
                row = [
                    rec_uid,
                    rec_info.get('title'),
                    rec_info.get('url', '').rstrip('/'),
                    rec_owner and rec_owner.email,
                    rec.get('ip_address'),
                    rec.get('keeper_version'),
                    datetime.datetime.fromtimestamp(int(rec.get('last_created')))
                ]
                table.append(row)
            return table

        report_data = []
        user_lookup = {user.get('enterprise_user_id'): user.get('username') for user in params.enterprise.get('users')}
        username_or_id = kwargs.get('user')
        username = user_lookup.get(int(username_or_id)) if username_or_id.isdigit() else username_or_id

        try:
            accessed = get_accessed_records(username)
            report_data = fill_table(accessed)
        except CommunicationError as e:
            logging.warning(f'User {username_or_id} not found, error = "{e.message}"')

        return report_data

