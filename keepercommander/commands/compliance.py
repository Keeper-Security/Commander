import argparse
import datetime
import logging
import operator
from typing import Optional, Dict, Tuple, Union, List

from keepercommander.commands.base import GroupCommand, dump_report_data, field_to_title
from keepercommander.commands.enterprise_common import EnterpriseCommand
from keepercommander.sox.sox_types import RecordPermissions
from .. import sox, api
from ..error import Error
from ..params import KeeperParams
from ..sox import sox_types, get_node_id
from ..sox.sox_data import SoxData

compliance_parser = argparse.ArgumentParser(add_help=False)
rebuild_group = compliance_parser.add_mutually_exclusive_group()
rebuild_group.add_argument('--rebuild', '-r', action='store_true', help='rebuild local data from source')
nr_help = 'prevent remote data fetching if local cache present (invalid with --rebuild flag)'
rebuild_group.add_argument('--no-rebuild', '-nr', action='store_true', help=nr_help)
compliance_parser.add_argument('--no-cache', '-nc', action='store_true',
                               help='remove any local non-memory storage of data after report is generated')
compliance_parser.add_argument('--node', action='store', help='ID or name of node (defaults to root node)')
compliance_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                               default='table', help='format of output')
compliance_parser.add_argument('--output', dest='output', action='store',
                               help='path to resulting output file (ignored for "table" format)')

default_report_parser = argparse.ArgumentParser(prog='compliance report', description='Run a SOX compliance report.',
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
team_report_parser = argparse.ArgumentParser(prog='compliance team-report', description=team_report_desc,
                                             parents=[compliance_parser])
team_report_parser.add_argument('-tu', '--show-team-users', action='store_true', help='show all members of each team')

access_report_desc = 'Run a report showing all records a user has accessed'
access_report_parser = argparse.ArgumentParser(prog='compliance record-access-report', description=access_report_desc,
                                               parents=[compliance_parser])
access_report_parser.add_argument('user', metavar='USER', type=str, help='username or ID')

summary_report_desc = 'Run a summary SOX compliance report'
summary_report_parser = argparse.ArgumentParser(prog='compliance summary-report', description=summary_report_desc,
                                                parents=[compliance_parser])
sf_report_desc = 'Run an enterprise-wide shared-folder report'
sf_report_parser = argparse.ArgumentParser(prog='compliance shared-folder-report', description=sf_report_desc,
                                           parents=[compliance_parser])
sf_report_parser.add_argument('-tu', '--show-team-users', action='store_true', help='show all members of each team')


def register_commands(commands):
    commands['compliance'] = ComplianceCommand()


def register_command_info(aliases, command_info):
    aliases['cr'] = ('compliance', 'report')
    aliases['compliance-report'] = ('compliance', 'report')
    command_info['compliance'] = 'SOX Compliance Reporting'


def get_email(sdata, user_uid):    # type: (SoxData, int) -> str
    return sdata.get_users().get(user_uid).email


def get_team_usernames(sdata, team):  # type: (SoxData, sox_types.Team) -> List[str]
    return [get_email(sdata, userid) for userid in team.users]


class ComplianceCommand(GroupCommand):
    def __init__(self):
        super(ComplianceCommand, self).__init__()
        self.register_command('report', ComplianceReportCommand(), 'Run default SOX compliance report')
        self.register_command('team-report', ComplianceTeamReportCommand(), team_report_desc, 'tr')
        self.register_command('record-access-report', ComplianceRecordAccessReportCommand(), access_report_desc, 'rar')
        self.register_command('summary-report', ComplianceSummaryReportCommand(), summary_report_desc, 'stats')
        self.register_command('shared-folder-report', ComplianceSharedFolderReportCommand(), sf_report_desc, 'sfr')
        self.default_verb = 'report'

    def validate(self, params):  # type: (KeeperParams) -> None
        sox.validate_data_access(params, cmd='compliance')


class BaseComplianceReportCommand(EnterpriseCommand):
    def __init__(self, report_headers, allow_no_opts=True, prelim_only=False):
        super(BaseComplianceReportCommand, self).__init__()
        self.title = None
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
        node_id = get_node_id(params, node_name_or_id)
        enterprise_id = node_id >> 32
        nodes = params.enterprise['nodes']
        root_node_id = nodes[0].get('node_id', 0)
        max_data_age = datetime.timedelta(days=1)
        min_data_ts = 0 if kwargs.get('no_rebuild') else (datetime.datetime.now() - max_data_age).timestamp()

        default_opts = {'command', 'action', 'format'}
        opts_set = [val for opt, val in kwargs.items() if val and opt not in default_opts]
        if not opts_set and not self.allow_no_opts:
            local_sox_data = sox.get_compliance_data(params, node_id, enterprise_id, False, min_updated=0)
            self.show_help_text(local_sox_data)
            return

        rebuild = kwargs.get('rebuild')
        no_cache = kwargs.get('no_cache')
        shared_only = kwargs.get('shared')
        get_sox_data_fn = sox.get_prelim_data if self.prelim_only else sox.get_compliance_data
        fn_args = [params, enterprise_id] if self.prelim_only else [params, node_id, enterprise_id]
        fn_kwargs = {'rebuild': rebuild, 'min_updated': min_data_ts, 'no_cache': no_cache, 'shared_only': shared_only}
        sd = get_sox_data_fn(*fn_args, **fn_kwargs)
        report_fmt = kwargs.get('format', 'table')
        headers = self.report_headers if report_fmt == 'json' else [field_to_title(h) for h in self.report_headers]
        report_data = self.generate_report_data(params, kwargs, sd, report_fmt, node_id, root_node_id)
        report = dump_report_data(report_data, headers, title=self.title, fmt=report_fmt, filename=kwargs.get('output'),
                                  column_width=32)
        return report


class ComplianceReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['record_uid', 'title', 'type', 'username', 'permissions', 'url']
        super(ComplianceReportCommand, self).__init__(headers, allow_no_opts=False)

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
        headers = ['team_name', 'team_uid', 'shared_folder_name', 'shared_folder_uid', 'permissions', 'records']
        super(ComplianceTeamReportCommand, self).__init__(headers, allow_no_opts=True)

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return team_report_parser

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        def get_sf_name(uid):
            # TODO: get sf name via share admin data when implemented (for now, find in params.shared_folder_cache)
            sf = params.shared_folder_cache.get(uid, {})
            return sf.get('name_unencrypted', '')

        show_team_users = kwargs.get('show_team_users')
        shared_folders = sox_data.get_shared_folders().items()
        team_lookup = sox_data.get_teams()
        report_data = []
        for sf_uid, folder in shared_folders:
            num_recs = len(folder.record_permissions) if folder.record_permissions else 0
            for team_uid in folder.teams:
                team = team_lookup.get(team_uid)
                perms = [not team.restrict_share and 'Can Share', not team.restrict_edit and 'Can Edit']
                perms = [p for p in perms if p]
                perms = ', '.join(perms) if perms else 'Read Only'
                row = [team.team_name, team_uid, get_sf_name(sf_uid), sf_uid, perms, num_recs]
                if show_team_users:
                    row.append(get_team_usernames(sox_data, team))
                report_data.append(row)

        return report_data

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any
        kwargs['shared'] = True
        tu_header = 'team_users'
        show_team_users = kwargs.get('show_team_users')
        if show_team_users:
            if tu_header not in self.report_headers:
                self.report_headers.append(tu_header)
        else:
            if tu_header in self.report_headers:
                self.report_headers.remove(tu_header)
        return super().execute(params, **kwargs)


class ComplianceRecordAccessReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['record_uid',
                   'record_title',
                   'record_url',
                   'record_owner',
                   'ip_address',
                   'device',
                   'last_access']
        super(ComplianceRecordAccessReportCommand, self).__init__(headers, allow_no_opts=True, prelim_only=True)

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return access_report_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any
        kwargs['shared'] = True
        return super().execute(params, **kwargs)

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
        except Error as e:
            logging.warning(f'User {username_or_id} not found, error = "{e.message}"')

        return report_data


class ComplianceSummaryReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['email', 'records', 'active', 'deleted']
        super(ComplianceSummaryReportCommand, self).__init__(headers, allow_no_opts=True, prelim_only=False)

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return summary_report_parser

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        def get_row(u):
            num_deleted = len(u.trash_records)
            num_active = len(u.active_records)
            total = len(u.records)
            return u.email, total, num_active, num_deleted

        report_data = [get_row(u) for u in sox_data.get_users().values()]
        total_active = sum([num_active for _, _, num_active, _ in report_data])
        total_deleted = sum([num_deleted for _, _, _, num_deleted in report_data])
        total_all = sum([total for _, total, _, _ in report_data])
        report_data.append(('TOTAL', total_all, total_active, total_deleted))
        return report_data


class ComplianceSharedFolderReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['shared_folder_uid', 'team_uid', 'team_name', 'record_uid', 'email']
        super(ComplianceSharedFolderReportCommand, self).__init__(headers, allow_no_opts=True)

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return sf_report_parser

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        show_team_users = kwargs.get('show_team_users')
        team_users_title = '(TU) denotes a user whose membership in a team grants them access to the shared folder'
        self.title = team_users_title if show_team_users else None
        sfs = sox_data.get_shared_folders()
        teams = sox_data.get_teams()
        report_data = []
        for sfuid, sf in sfs.items():
            sf_team_uids = list(sf.teams)
            sf_team_names = [teams.get(t).team_name for t in sf.teams]
            records = [rp.record_uid for rp in sf.record_permissions]
            users = [get_email(sox_data, u) for u in sf.users]
            team_users = [tu for tuid in sf_team_uids for tu in get_team_usernames(sox_data, teams.get(tuid))] if show_team_users else []
            team_users = [f'(TU){email}' for email in team_users]
            row = [sfuid, sf_team_uids, sf_team_names, records, team_users + users]
            report_data.append(row)
        return report_data

