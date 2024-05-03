import argparse
import datetime
import json
import logging
import operator
from functools import partial
from typing import Optional, Dict, Tuple, List, Any, Iterable

from keepercommander.commands.base import GroupCommand, dump_report_data, field_to_title
from keepercommander.commands.enterprise_common import EnterpriseCommand
from keepercommander.sox.sox_types import RecordPermissions
from .. import sox, api
from ..error import CommandError
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

default_report_parser = argparse.ArgumentParser(prog='compliance report', description='Run a compliance report.',
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
                                   help='show shared records only')
deleted_status_group = default_report_parser.add_mutually_exclusive_group()
deleted_status_group.add_argument('--deleted-items', action='store_true',
                                  help='show deleted records only (not valid with --active-items flag)')
deleted_status_group.add_argument('--active-items', action='store_true',
                                  help='show active records only (not valid with --deleted-items flag)')

team_report_desc = 'Run a report showing which shared folders enterprise teams have access to'
team_report_parser = argparse.ArgumentParser(prog='compliance team-report', description=team_report_desc,
                                             parents=[compliance_parser])
team_report_parser.add_argument('-tu', '--show-team-users', action='store_true', help='show all members of each team')

access_report_desc = 'Run a report showing all records a user has accessed or can access'
access_report_parser = argparse.ArgumentParser(prog='compliance record-access-report', description=access_report_desc,
                                               parents=[compliance_parser])
user_arg_help = 'username(s) or ID(s). Set to "@all" to run report for all users'
access_report_parser.add_argument('user', nargs='+', metavar='USER', type=str, help=user_arg_help)
report_type_help = ('select type of record-access data to include in report (defaults to "history"). '
                    'Set to "history" to view past record-access activity, "vault" to view current vault contents')
ACCESS_REPORT_TYPES = ('history', 'vault')
access_report_parser.add_argument('--report-type', action='store', choices=ACCESS_REPORT_TYPES,
                                  default='history', help=report_type_help)
aging_help = 'include record-aging data (last modified, created, and last password rotation dates)'
access_report_parser.add_argument('--aging', action='store_true',  help=aging_help)

summary_report_desc = 'Run a summary compliance report'
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
    command_info['compliance'] = 'Compliance Reporting'


def get_email(sdata, user_uid):    # type: (SoxData, int) -> str
    return sdata.get_users().get(user_uid).email


def get_team_usernames(sdata, team):  # type: (SoxData, sox_types.Team) -> List[str]
    return [get_email(sdata, userid) for userid in team.users]


class ComplianceCommand(GroupCommand):
    def __init__(self):
        super(ComplianceCommand, self).__init__()
        self.register_command('report', ComplianceReportCommand(), 'Run default compliance report')
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
        self.group_by_column = None

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
        report_data = self.generate_report_data(params, kwargs, sd, report_fmt, node_id, root_node_id)
        headers = self.report_headers if report_fmt == 'json' else [field_to_title(h) for h in self.report_headers]
        report = dump_report_data(report_data, headers, title=self.title, fmt=report_fmt, filename=kwargs.get('output'),
                                  column_width=32, group_by=self.group_by_column)
        return report


class ComplianceReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['record_uid', 'title', 'type', 'username', 'permissions', 'url', 'in_trash']
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
            deleted_items = kwargs.get('deleted_items')
            active_items = kwargs.get('active_items')
            if active_items and deleted_items:
                error_msg = '--deleted-items and --active-items flags are mutually exclusive'
                raise CommandError(self.get_parser().prog, error_msg)
            filtered = [r for r in filtered if r.in_trash] if deleted_items \
                else [r for r in filtered if not r.in_trash] if active_items \
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
                fmt_row = [formatted_rec_uid, r_title, r_type, u_email, permissions, r_url.rstrip('/'), rec.in_trash]
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
        super(ComplianceRecordAccessReportCommand, self).__init__([], allow_no_opts=True, prelim_only=False)
        self.group_by_column = 0

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return access_report_parser

    def execute(self, params, **kwargs):  # type: (KeeperParams, any) -> any
        kwargs['shared'] = True
        return super().execute(params, **kwargs)

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        # type: (KeeperParams, Dict[str, Any], sox.sox_data.SoxData, str, int, int) -> List[List[str]]
        def get_records_accessed(email, records=None):
            records_accessed = dict()   # type: Dict[str, Dict[str, Any]]
            # Empty record filter list -> no records to search for
            if records is not None and not records:
                return records_accessed

            columns = ['record_uid', 'ip_address', 'keeper_version']
            rq_filter = {'username': email}
            if records is not None:
                rq_filter['record_uid'] = records

            rq = {
                'command':      'get_audit_event_reports',
                'report_type':  'span',
                'scope':        'enterprise',
                'aggregate':    ['last_created'],
                'limit':        API_EVENT_SUMMARY_ROW_LIMIT,
                'filter':       rq_filter,
                'columns':      columns,
            }

            def update_records_accessed(record_access_events):
                for event in record_access_events:
                    r_uid = event.get('record_uid')
                    records_accessed.setdefault(r_uid, event)

            def get_events(period_end, filter_recs):
                if period_end:
                    rq_filter['created'] = {'max': period_end}
                rq_filter['record_uid'] = filter_recs
                rs = api.communicate(params, rq)
                return rs.get('audit_event_overview_report_rows')

            done = records is not None and not records
            max_ts = 0
            missing_records = [] if not records else [*records]
            while not done:
                chunk = missing_records[:API_EVENT_SUMMARY_ROW_LIMIT]
                events = get_events(max_ts, chunk)
                update_records_accessed(events)
                missing_records = [r for r in records if r not in records_accessed] if records else []
                earliest_event = {} if not events else events[-1]
                max_ts = int(earliest_event.get('last_created', 0))
                done = not missing_records and records or len(events) < API_EVENT_SUMMARY_ROW_LIMIT

            return records_accessed

        def format_datetime(dt_str):
            if not dt_str:
                return None
            ts = datetime.datetime.fromisoformat(dt_str).timestamp()
            return datetime.datetime.fromtimestamp(int(ts))

        def from_ts(ts):
            return datetime.datetime.fromtimestamp(ts) if ts else None

        def compile_user_report(user, access_events):
            access_records = dict()
            user_access_data = {user: access_records}
            rec_uids = access_events.keys() if report_type == report_type_default \
                else {r for r in vault_records}

            for uid in rec_uids:
                access_event = access_events.get(uid, {})
                sox_rec = sox_data.get_records().get(uid)
                rec_info = sox_rec.data if sox_rec else {}
                rec_owner = sox_data.get_record_owner(uid)
                event_ts = access_event.get('last_created')
                access_record = {uid: {'record_title': rec_info.get('title'),
                                       'record_type':  rec_info.get('record_type'),
                                       'record_url': rec_info.get('url', '').rstrip('/'),
                                       'record_owner': rec_owner and rec_owner.email,
                                       'has_attachments': sox_rec.has_attachments if sox_rec else None,
                                       'in_trash': sox_rec.in_trash if sox_rec else None,
                                       'ip_address': access_event.get('ip_address'),
                                       'device': access_event.get('keeper_version'),
                                       'last_access': from_ts(int(event_ts)) if event_ts else None,
                                       'vault_owner': user}}
                access_records.update(access_record)
            return user_access_data

        def get_aging_data(rec_ids):
            if not rec_ids:
                return {}
            aging_data = {r: {'created': None, 'last_modified': None, 'last_rotation': None} for r in rec_ids}
            now = datetime.datetime.now()
            max_stored_age_dt = now - datetime.timedelta(days=1)
            max_stored_age_ts = int(max_stored_age_dt.timestamp())
            stored_entities = sox_data.storage.get_record_aging().get_all()
            stored_aging_data = {e.record_uid: {'created': from_ts(e.created), 'last_modified': from_ts(e.last_modified), 'last_rotation': from_ts(e.last_rotation)} for e in stored_entities}
            aging_data.update(stored_aging_data)

            from keepercommander.commands.aram import AuditReportCommand
            cmd = AuditReportCommand()

            def get_events(record_filter, type_filter, order='desc', aggregate='last_created'):
                events = []
                cmd_kwargs = {'report_type': 'span',
                              'columns': ['record_uid'],
                              'format': 'json',
                              'limit': API_EVENT_SUMMARY_ROW_LIMIT,
                              'order': order,
                              'aggregate': [aggregate]}
                if type_filter:
                    cmd_kwargs['event_type'] = type_filter
                while record_filter:
                    chunk = record_filter[:API_EVENT_SUMMARY_ROW_LIMIT]
                    record_filter = record_filter[API_EVENT_SUMMARY_ROW_LIMIT:]
                    cmd_kwargs['record_uid'] = chunk
                    event_data = cmd.execute(params, **cmd_kwargs)
                    event_data = json.loads(event_data)
                    events.extend(event_data)
                return events

            def get_known_aging_data(event_type):
                return {r: events.get(event_type) for r, events in stored_aging_data.items() if events.get(event_type) or 0 >= max_stored_age_ts}

            def get_created_dts():
                known_rec_created_lookup = get_known_aging_data('created')
                for rec_id, dt in known_rec_created_lookup.items():
                    aging_data[rec_id]['created'] = dt
                r_filter = [uid for uid in rec_ids if uid not in known_rec_created_lookup]
                event_data = get_events(r_filter, None, 'asc', 'first_created')
                record_created_lookup = {event.get('record_uid'): event.get('first_created') for event in event_data}
                for rec, created in record_created_lookup.items():
                    aging_data[rec]['created'] = format_datetime(created)

            def get_last_modified_dts():
                known_rec_last_modified_lookup = get_known_aging_data('last_modified')
                for rec_id, dt in known_rec_last_modified_lookup.items():
                    aging_data[rec_id]['last_modified'] = dt
                r_filter = [uid for uid in rec_ids if uid not in known_rec_last_modified_lookup]
                event_data = get_events(r_filter, ['record_update'])
                dt_lookup = {event.get('record_uid'): event.get('last_created') for event in event_data}
                for rec, dt in dt_lookup.items():
                    aging_data[rec]['last_modified'] = format_datetime(dt)
                for rec, events in aging_data.items():
                    events['last_modified'] = events.get('last_modified') or events.get('created')

            def get_last_rotation_dts():
                known_rec_last_rotation_lookup = get_known_aging_data('last_rotation')
                for rec_id, dt in known_rec_last_rotation_lookup.items():
                    aging_data[rec_id]['last_rotation'] = dt
                r_filter = [uid for uid in rec_ids if uid not in known_rec_last_rotation_lookup]
                event_data = get_events(r_filter, ['record_rotation_scheduled_ok', 'record_rotation_on_demand_ok'])
                dt_lookup = {event.get('record_uid'): event.get('last_created') for event in event_data}
                for rec, dt in dt_lookup.items():
                    aging_data[rec]['last_rotation'] = format_datetime(dt)

            get_created_dts()
            get_last_modified_dts()
            get_last_rotation_dts()
            save_aging_data(aging_data)
            return aging_data

        def save_aging_data(aging_data):
            existing_entities = sox_data.storage.get_record_aging()
            updated_entities = []
            for r, events in aging_data.items():
                entity = existing_entities.get_entity(r) or StorageRecordAging(r)
                created_dt = events.get('created')
                created_ts = int(created_dt.timestamp()) if created_dt else 0
                modified_dt = events.get('last_modified')
                modified_ts = int(modified_dt.timestamp()) if modified_dt else 0
                rotation_dt = events.get('last_rotation')
                rotation_ts = int(rotation_dt.timestamp()) if rotation_dt else 0

                entity.created = created_ts
                entity.last_modified = modified_ts
                entity.last_rotation = rotation_ts
                updated_entities.append(entity)
            sox_data.storage.record_aging.put_entities(updated_entities)

        def compile_report_data(rec_ids):
            aging_data = get_aging_data(rec_ids)
            for email, records in user_access_lookup.items():
                for uid, access_data in records.items():
                    row = [email, uid]
                    for i in range(len(row), len(self.report_headers)):
                        field = self.report_headers[i]
                        value = aging_data.get(uid, {}).get(field) if field in aging_columns \
                            else (access_data.get(field))
                        row.append(value)
                    report_data.append(row)

        from keepercommander.sox.storage_types import StorageRecordAging
        from keepercommander.commands.aram import API_EVENT_SUMMARY_ROW_LIMIT
        from keepercommander.commands.enterprise import EnterpriseInfoCommand

        report_data = []
        user_lookup = {user.get('enterprise_user_id'): user.get('username') for user in params.enterprise.get('users')}
        user_access_lookup = dict()
        aging = kwargs.get('aging')
        users = kwargs.get('user')
        managed_users = json.loads(EnterpriseInfoCommand().execute(params, users=True, quiet=True, format='json'))
        usernames = [user_lookup.get(user_id) for user_id in sox_data.get_users()] if '@all' in users \
            else [user_lookup.get(int(ref)) if ref.isdigit() else ref for ref in users]
        usernames = [u for u in usernames if u and u in [mu.get('email') for mu in managed_users]]

        report_type_default = self.get_parser().get_default('report_type')
        report_type = kwargs.get('report_type', report_type_default)
        if report_type not in ACCESS_REPORT_TYPES:
            error_msg = f'Unrecognized report-type: "{report_type}"\nValues allowed: {ACCESS_REPORT_TYPES}'
            raise CommandError(self.get_parser().prog, error_msg)

        default_columns = ['vault_owner', 'record_uid', 'record_title', 'record_type', 'record_url', 'has_attachments',
                           'in_trash', 'record_owner', 'ip_address', 'device', 'last_access']

        aging_columns = ['created', 'last_modified', 'last_rotation'] if aging else []
        self.report_headers = default_columns + aging_columns

        for name in usernames:
            vault_records = sox_data.get_vault_records(name)
            filter_by_recs = None if report_type == report_type_default else {r for r in vault_records}
            user_access_events = get_records_accessed(name, filter_by_recs)
            user_access_lookup.update(compile_user_report(name, user_access_events))

        record_ids = {r for recs in user_access_lookup.values() for r in recs} if aging else {}
        compile_report_data(record_ids)
        return report_data


class ComplianceSummaryReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['email', 'total_items', 'total_owned', 'active_owned', 'deleted_owned']
        super(ComplianceSummaryReportCommand, self).__init__(headers, allow_no_opts=True, prelim_only=False)

    def get_parser(self):  # type: () -> Optional[argparse.ArgumentParser]
        return summary_report_parser

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        # type: (KeeperParams, any, SoxData, str, int, int) -> List[Iterable[any]]
        def get_row(u):
            num_deleted = len(u.trash_records)
            num_active = len(u.active_records)
            num_owned = len(u.records)
            vault_recs = sox_data.get_vault_records(u.user_uid)
            num_total = len(vault_recs)
            email = managed_user_email_lookup.get(u.user_uid) or u.email
            return email, num_total, num_owned, num_active, num_deleted

        filter_by_node = node != root_node
        from keepercommander.commands.enterprise import EnterpriseInfoCommand
        cmd = EnterpriseInfoCommand()
        cmd_kwargs = {
            'users': True,
            'quiet': True,
            'format': 'json',
            'node': str(node) if filter_by_node else None
        }
        cmd_rs = partial(cmd.execute, params, **cmd_kwargs)()
        managed_users = json.loads(cmd_rs)
        managed_users = [mu for mu in managed_users if mu.get('status', '').lower() != 'invited']
        managed_user_email_lookup = {mu.get('user_id'): mu.get('email') for mu in managed_users}
        managed_user_ids = set(managed_user_email_lookup.keys())
        empty_vault_user_ids = {user_id for user_id in managed_user_ids if user_id not in sox_data.get_users()}
        empty_vault_users = [mu for mu in managed_users if mu.get('user_id') in empty_vault_user_ids]
        sox_users = sox_data.get_users().values()
        report_data = [get_row(u) for u in sox_users if not filter_by_node or u.user_uid in managed_user_ids]
        report_data.extend([(u.get('email'), 0, 0, 0, 0) for u in empty_vault_users])
        total_active = sum([num_active for _, _, _, num_active, _ in report_data])
        total_deleted = sum([num_deleted for _, _, _, _, num_deleted in report_data])
        total_owned = sum([owned for _, _, owned, _, _ in report_data])
        report_data.append(('TOTAL', None, total_owned, total_active, total_deleted))
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

