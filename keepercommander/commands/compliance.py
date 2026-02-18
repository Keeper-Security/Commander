import argparse
import datetime
import itertools
import json
import logging
import operator
from functools import partial
from typing import Optional, Dict, Tuple, List, Any, Iterable, Union

from .base import GroupCommand, dump_report_data, field_to_title, report_output_parser
from .enterprise_common import EnterpriseCommand
from ..sox.sox_types import RecordPermissions
from ..display import Spinner
from .helpers.reporting import filter_rows
from .. import sox, api
from ..error import CommandError
from ..params import KeeperParams
from ..sox import sox_types, get_node_id
from ..sox.sox_data import SoxData
from ..sox.storage_types import StorageRecordAging
from .aram import API_EVENT_SUMMARY_ROW_LIMIT

compliance_parser = argparse.ArgumentParser(add_help=False, parents=[report_output_parser])
rebuild_group = compliance_parser.add_mutually_exclusive_group()
rebuild_group.add_argument('--rebuild', '-r', action='store_true', help='rebuild local data from source')
nr_help = 'prevent remote data fetching if local cache present (invalid with --rebuild flag)'
rebuild_group.add_argument('--no-rebuild', '-nr', action='store_true', help=nr_help)
compliance_parser.add_argument('--no-cache', '-nc', action='store_true',
                               help='remove any local non-memory storage of data after report is generated')
compliance_parser.add_argument('--node', action='store', help='ID or name of node (defaults to root node)')
username_opt_help = 'user(s) whose records are to be included in report (set option once per user)'
compliance_parser.add_argument('--username', '-u', action='append', help=username_opt_help)
team_opt_help = 'name or UID of team(s) whose members\' records are to be included in report (set once per team)'
compliance_parser.add_argument('--team', action='append', help=team_opt_help)
compliance_parser.add_argument('--regex', action='store_true', help='Allow use of regular expressions in search criteria')
compliance_parser.add_argument('pattern', type=str, nargs='*', help='Search string / pattern to filter results by. Multiple values allowed.')

aging_help = 'include record-aging data (last modified, created, and last password rotation dates)'

default_report_parser = argparse.ArgumentParser(prog='compliance report', description='Run a compliance report.',
                                                parents=[compliance_parser])
job_title_opt_help = 'job title(s) of users whose records are to be included in report (set option once per job title)'
default_report_parser.add_argument('--job-title', '-jt', action='append', help=job_title_opt_help)
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
default_report_parser.add_argument('--aging', action='store_true', help=aging_help)

team_report_desc = 'Run a report showing which shared folders enterprise teams have access to'
team_report_parser = argparse.ArgumentParser(prog='compliance team-report', description=team_report_desc,
                                             parents=[compliance_parser])
team_report_parser.add_argument('-tu', '--show-team-users', action='store_true', help='show all members of each team')
team_report_parser.add_argument('--resolve-teams', action='store_true',
                                help='expand --team filter to also match shared folders where team members are individually present')

access_report_desc = 'Run a report showing all records a user has accessed or can access'
access_report_parser = argparse.ArgumentParser(prog='compliance record-access-report', description=access_report_desc,
                                               parents=[compliance_parser])
user_arg_help = 'username(s) or ID(s). Set once for each user to include. Set to "@all" to run report for all users'
access_report_parser.add_argument('--email', '-e', action='append', type=str, help=user_arg_help)
report_type_help = ('select type of record-access data to include in report (defaults to "history"). '
                    'Set to "history" to view past record-access activity, "vault" to view current vault contents')
ACCESS_REPORT_TYPES = ('history', 'vault')
access_report_parser.add_argument('--report-type', action='store', choices=ACCESS_REPORT_TYPES,
                                  default='history', help=report_type_help)
access_report_parser.add_argument('--aging', action='store_true', help=aging_help)

summary_report_desc = 'Run a summary compliance report'
summary_report_parser = argparse.ArgumentParser(prog='compliance summary-report', description=summary_report_desc,
                                                parents=[compliance_parser])
sf_report_desc = 'Run an enterprise-wide shared-folder report'
sf_report_parser = argparse.ArgumentParser(prog='compliance shared-folder-report', description=sf_report_desc,
                                           parents=[compliance_parser])
sf_report_parser.add_argument('-tu', '--show-team-users', action='store_true', help='show all members of each team')
sf_report_parser.add_argument('--resolve-teams', action='store_true',
                              help='expand --team filter to also match shared folders where team members are individually present')


def register_commands(commands):
    commands['compliance'] = ComplianceCommand()


def register_command_info(aliases, command_info):
    aliases['cr'] = ('compliance', 'report')
    aliases['compliance-report'] = ('compliance', 'report')
    command_info['compliance'] = 'Compliance Reporting for auditing'


def get_email(sdata, user_uid):    # type: (SoxData, int) -> str
    return sdata.get_users().get(user_uid).email


def get_team_usernames(sdata, team):  # type: (SoxData, sox_types.Team) -> List[str]
    return [get_email(sdata, userid) for userid in team.users]


def get_all_folder_user_uids(folder, team_lookup):
    """All user UIDs with access to a folder: direct members + team members."""
    all_uids = set(folder.users)
    for team_uid in folder.teams:
        team = team_lookup.get(team_uid)
        if team:
            all_uids.update(team.users)
    return all_uids


def _from_ts(ts):
    return datetime.datetime.fromtimestamp(ts) if ts else None


def get_aging_data(params, sox_data, rec_ids, use_spinner=True, stale_rec_ids=None):
    """Fetch/cache record-aging data for given record UIDs.

    stale_rec_ids: If provided, only fetch fresh data for these UIDs (per-user mode).
                   If None, standard 1-day TTL for all records.
    """
    if not rec_ids:
        return {}
    aging_data = {r: {'created': None, 'last_modified': None, 'last_rotation': None, 'last_pw_change': None}
                  for r in rec_ids if r}
    max_cache_age_ts = int((datetime.datetime.now() - datetime.timedelta(days=1)).timestamp())
    stored_aging_data = {}
    stored_entities = sox_data.storage.get_record_aging().get_all()
    stored_aging_data = {
        e.record_uid: {
            'created': _from_ts(e.created),
            'last_modified': _from_ts(e.last_modified),
            'last_rotation': _from_ts(e.last_rotation),
            'last_pw_change': _from_ts(e.last_pw_change),
            '_last_cached': e.last_cached or 0,
        }
        for e in stored_entities if e.record_uid
    }
    aging_data.update(stored_aging_data)

    types_by_aging_event = dict(
        created         = [],
        last_modified   = ['record_update'],
        last_rotation   = ['record_rotation_scheduled_ok', 'record_rotation_on_demand_ok'],
        last_pw_change  = ['record_password_change']
    )

    def get_known_aging_data(event_type):
        """Return cached records fetched within the 1-day TTL.

        Checks _last_cached timestamp (when we stored the data), not the event value itself.
        A record with last_pw_change=None but recent _last_cached means "checked, no event found"
        and should not be re-fetched until the cache expires.
        """
        return {r: events.get(event_type) for r, events in stored_aging_data.items()
                if events.get('_last_cached', 0) >= max_cache_age_ts}

    def get_request_params(record_aging_event):
        # type: (str) -> Tuple[List[str], Union[List[str], None], Optional[str], Optional[str]]
        known_events_map = get_known_aging_data(record_aging_event)
        if stale_rec_ids is not None:
            filter_recs = [uid for uid in rec_ids if uid in stale_rec_ids and uid not in known_events_map]
        else:
            filter_recs = [uid for uid in rec_ids if uid not in known_events_map]
        filter_types = types_by_aging_event.get(record_aging_event)
        order, aggregate = ('ascending', 'first_created') if record_aging_event == 'created' \
            else ('descending', 'last_created')
        return filter_recs, filter_types, order, aggregate

    def get_requests(filter_recs, filter_type, order='descending', aggregate='last_created'):
        columns = ['record_uid']
        requests = []
        while filter_recs:
            chunk = filter_recs[:API_EVENT_SUMMARY_ROW_LIMIT]
            filter_recs = filter_recs[API_EVENT_SUMMARY_ROW_LIMIT:]
            rq_filter = {'record_uid': chunk}
            if filter_type: rq_filter.update({'audit_event_type': filter_type})
            request = dict(
                command         = 'get_audit_event_reports',
                report_type     = 'span',
                scope           = 'enterprise',
                aggregate       = [aggregate],
                limit           = API_EVENT_SUMMARY_ROW_LIMIT,
                filter          = rq_filter,
                columns         = columns,
                order           = order
            )
            requests.append(request)
        return requests

    # Pre-compute request params once per stat (used for spinner check and fetch)
    aging_stats = ['created', 'last_modified', 'last_rotation', 'last_pw_change']
    params_by_stat = {stat: get_request_params(stat) for stat in aging_stats}

    # Build all requests across all stats for a single execute_batch call
    all_requests = []
    request_slices = {}  # stat -> (start_idx, count) into the combined response list
    for stat in aging_stats:
        stat_requests = get_requests(*params_by_stat[stat])
        request_slices[stat] = (len(all_requests), len(stat_requests))
        all_requests.extend(stat_requests)

    # Additional request: count event 80 occurrences per record to detect first-sets
    pw_filter_recs = params_by_stat['last_pw_change'][0]
    pw_count_requests = get_requests(pw_filter_recs, ['record_password_change'], aggregate='occurrences')
    request_slices['_pw_count'] = (len(all_requests), len(pw_count_requests))
    all_requests.extend(pw_count_requests)

    spinner = None
    try:
        if use_spinner and all_requests:
            spinner = Spinner('Loading record aging events...')
            spinner.start()
        if all_requests:
            responses = api.execute_batch(params, all_requests)
        else:
            responses = []
    finally:
        if spinner:
            spinner.stop()

    record_events_by_stat = {}
    for stat in aging_stats:
        start, count = request_slices[stat]
        stat_responses = responses[start:start + count]
        events = list(itertools.chain.from_iterable(
            rs.get('audit_event_overview_report_rows', []) for rs in stat_responses
        ))
        aggregate = 'first_created' if stat == 'created' else 'last_created'
        record_timestamps = {e.get('record_uid'): e.get(aggregate) for e in events if e.get('record_uid')}
        record_events_by_stat[stat] = {rec: _from_ts(ts) for rec, ts in record_timestamps.items()}

    # Parse event 80 occurrence counts
    pw_count_start, pw_count_n = request_slices['_pw_count']
    pw_count_responses = responses[pw_count_start:pw_count_start + pw_count_n]
    pw_count_events = list(itertools.chain.from_iterable(
        rs.get('audit_event_overview_report_rows', []) for rs in pw_count_responses
    ))
    pw_occurrences = {e.get('record_uid'): int(e.get('occurrences', 0))
                      for e in pw_count_events if e.get('record_uid')}

    fetched_rec_ids = set()
    for stat, record_event_dts in record_events_by_stat.items():
        for record, dt in record_event_dts.items():
            aging_data.get(record, {}).update({stat: dt})
            stat == 'created' and aging_data.get(record, {}).setdefault('last_modified', dt)
            fetched_rec_ids.add(record)

    # KC-1146: discard first-set false positives for record_password_change.
    # Event 80 is client-side and fires on initial password set (at creation or later edit),
    # not just on actual password rotation. If a record has only 1 occurrence of event 80,
    # it's a first-set — not a real password change.
    for record in pw_occurrences:
        if pw_occurrences[record] <= 1 and aging_data.get(record, {}).get('last_pw_change'):
            aging_data[record]['last_pw_change'] = None

    if fetched_rec_ids:
        save_aging_data(sox_data, aging_data, fetched_rec_ids)

    # Union last_pw_change (event 80) with last_rotation (events 250/252) for comprehensive signal.
    # These are disjoint event sets: event 80 = client-side manual changes,
    # events 250/252 = router-side PAM rotations. Both represent real password changes.
    for record, events in aging_data.items():
        pw_change_dt = events.get('last_pw_change')
        rotation_dt = events.get('last_rotation')
        if rotation_dt and (not pw_change_dt or rotation_dt > pw_change_dt):
            events['last_pw_change'] = rotation_dt

    return aging_data


def save_aging_data(sox_data, aging_data, dirty_rec_ids=None):
    """Persist aging data. If dirty_rec_ids given, only write those records."""
    existing_entities = sox_data.storage.get_record_aging()
    now_ts = int(datetime.datetime.now().timestamp())
    updated_entities = []
    records_to_save = dirty_rec_ids if dirty_rec_ids is not None else aging_data.keys()
    for r in records_to_save:
        if not r:
            continue
        events = aging_data.get(r)
        if not events:
            continue
        entity = existing_entities.get_entity(r) or StorageRecordAging(r)
        created_dt = events.get('created')
        entity.created = int(created_dt.timestamp()) if created_dt else 0
        pw_change_dt = events.get('last_pw_change')
        entity.last_pw_change = int(pw_change_dt.timestamp()) if pw_change_dt else 0
        modified_dt = events.get('last_modified')
        entity.last_modified = int(modified_dt.timestamp()) if modified_dt else 0
        rotation_dt = events.get('last_rotation')
        entity.last_rotation = int(rotation_dt.timestamp()) if rotation_dt else 0
        entity.last_cached = now_ts
        updated_entities.append(entity)
    sox_data.storage.record_aging.put_entities(updated_entities)


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

        # Pre-filter users for --username and --team to avoid fetching data for all enterprise users
        user_filter = None
        explicit_user_ids = set()
        usernames = kwargs.get('username')
        team_refs = kwargs.get('team')
        if usernames or team_refs:
            filtered_user_ids = set()
            enterprise_users = params.enterprise.get('users', [])
            if usernames:
                username_set = set(usernames)
                user_lookup = {eu.get('username'): eu.get('enterprise_user_id') for eu in enterprise_users}
                explicit_user_ids.update(uid for u, uid in user_lookup.items() if u in username_set)
                filtered_user_ids.update(explicit_user_ids)
            if team_refs:
                enterprise_teams = params.enterprise.get('teams', [])
                team_uids = {t.get('team_uid') for t in enterprise_teams}
                team_name_lookup = {t.get('name'): t.get('team_uid') for t in enterprise_teams}
                resolved_team_uids = set()
                for t_ref in team_refs:
                    if t_ref in team_uids:
                        resolved_team_uids.add(t_ref)
                    elif t_ref in team_name_lookup:
                        resolved_team_uids.add(team_name_lookup[t_ref])
                enterprise_team_users = params.enterprise.get('team_users', [])
                filtered_user_ids.update(tu.get('enterprise_user_id') for tu in enterprise_team_users
                                         if tu.get('team_uid') in resolved_team_uids)
            if not filtered_user_ids:
                logging.warning('No enterprise users matched the provided filters (usernames=%s, teams=%s).',
                                usernames, team_refs)
            user_filter = filtered_user_ids if filtered_user_ids else None
            kwargs['_team_filter'] = resolved_team_uids if team_refs else None
            if kwargs.get('resolve_teams') and team_refs:
                explicit_user_ids.update(filtered_user_ids)
            kwargs['_explicit_user_filter'] = explicit_user_ids if explicit_user_ids else None

        get_sox_data_fn = sox.get_prelim_data if self.prelim_only else sox.get_compliance_data
        fn_args = [params, enterprise_id] if self.prelim_only else [params, node_id, enterprise_id]
        fn_kwargs = {'rebuild': rebuild, 'min_updated': min_data_ts, 'no_cache': no_cache, 'shared_only': shared_only,
                     'user_filter': user_filter}
        sd = get_sox_data_fn(*fn_args, **fn_kwargs)
        kwargs['_user_filter'] = user_filter
        report_fmt = kwargs.get('format', 'table')
        report_data = self.generate_report_data(params, kwargs, sd, report_fmt, node_id, root_node_id)
        patterns = kwargs.get('pattern', [])
        if '@all' in patterns:
            patterns.remove('@all')
        if patterns:
            report_data = filter_rows(report_data, patterns, use_regex=kwargs.get('regex'))
        headers = self.report_headers if report_fmt == 'json' else [field_to_title(h) for h in self.report_headers]
        report = dump_report_data(report_data, headers, title=self.title, fmt=report_fmt, filename=kwargs.get('output'),
                                  column_width=32, group_by=self.group_by_column)
        if no_cache:
            sd.storage.delete_db()
        return report


class ComplianceReportCommand(BaseComplianceReportCommand):
    def __init__(self):
        headers = ['record_uid', 'title', 'type', 'username', 'permissions', 'url', 'in_trash', 'shared_folder_uid']
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
                   "[--job-title JOB_TITLE] [--team TEAM] [--record RECORD] [--url DOMAIN] [--shared] [--aging] " \
                   "[--format {table,csv,json,pdf}] [--output OUTPUT] " \
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
        # type: (KeeperParams, Dict[str, Any], SoxData, str, int, int) -> List[List[Union[str, Any]]]
        aging = kwargs.get('aging')
        aging_columns = ['created', 'last_pw_change', 'last_modified', 'last_rotation'] if aging else []
        self.report_headers = ['record_uid', 'title', 'type', 'username', 'permissions',
                               'url', 'in_trash', 'shared_folder_uid'] + aging_columns

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
            team_refs = kwargs.get('team')
            if usernames or team_refs:
                username_matched = {o for o in rec_owners if o.email in usernames} if usernames else set()
                team_matched = set(filter_by_teams(rec_owners, team_refs)) if team_refs else set()
                filtered = list(username_matched | team_matched)
            else:
                filtered = rec_owners
            job_titles = kwargs.get('job_title')
            filtered = [o for o in filtered if o.job_title in job_titles] if job_titles else filtered
            filtered = [o for o in filtered if o.node_id == node] if node != root_node else filtered
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
                rec_sfs = sox_data.get_record_sfs(rec_uid)
                formatted_rec_uid = rec_uid if report_fmt != 'table' or kwargs.get('pattern') or last_rec_uid != rec_uid else ''
                u_email = row.get('email')
                permissions = RecordPermissions.to_permissions_str(row.get('permissions'))
                fmt_row = [formatted_rec_uid, r_title, r_type, u_email, permissions, r_url.rstrip('/'), rec.in_trash, rec_sfs]
                formatted_rows.append(fmt_row)
                last_rec_uid = rec_uid
            return formatted_rows

        report_data = format_table(table)

        if aging:
            all_rec_uids = {key[0] for key in permissions_lookup.keys()}
            stale_rec_ids = None
            user_filter = kwargs.get('_user_filter')
            if user_filter is not None:
                min_aging_ts = int((datetime.datetime.now() - datetime.timedelta(days=1)).timestamp())
                stale_rec_ids = set()
                for uid in user_filter:
                    user_entity = sox_data.storage.get_users().get_entity(uid)
                    if not user_entity or (user_entity.last_aging_refreshed or 0) < min_aging_ts:
                        user = sox_data.get_user(uid)
                        if user:
                            stale_rec_ids.update(user.records & all_rec_uids)

            aging_data = get_aging_data(params, sox_data, all_rec_uids,
                                        use_spinner=not params.batch_mode,
                                        stale_rec_ids=stale_rec_ids)

            # Update last_aging_refreshed for stale users
            if user_filter is not None:
                now_ts = int(datetime.datetime.now().timestamp())
                updated_users = []
                for uid in user_filter:
                    user_entity = sox_data.storage.get_users().get_entity(uid)
                    if user_entity and (user_entity.last_aging_refreshed or 0) < min_aging_ts:
                        user_entity.last_aging_refreshed = now_ts
                        updated_users.append(user_entity)
                if updated_users:
                    sox_data.storage.get_users().put_entities(updated_users)

            # Append aging columns to each row
            record_lookup = sox_data.get_records()
            for fmt_row in report_data:
                rec_uid = fmt_row[0]
                # Handle collapsed UIDs in table format
                if not rec_uid and report_data:
                    idx = report_data.index(fmt_row)
                    for i in range(idx - 1, -1, -1):
                        if report_data[i][0]:
                            rec_uid = report_data[i][0]
                            break
                rec_aging = aging_data.get(rec_uid, {})
                fmt_row.extend([rec_aging.get('created'), rec_aging.get('last_pw_change'),
                                rec_aging.get('last_modified'), rec_aging.get('last_rotation')])

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
        explicit_user_filter = kwargs.get('_explicit_user_filter')
        team_filter = kwargs.get('_team_filter')
        shared_folders = sox_data.get_shared_folders().items()
        team_lookup = sox_data.get_teams()
        report_data = []
        for sf_uid, folder in shared_folders:
            if explicit_user_filter or team_filter:
                all_folder_uids = get_all_folder_user_uids(folder, team_lookup)
                matches_user = explicit_user_filter and all_folder_uids & explicit_user_filter
                matches_team = team_filter and folder.teams & team_filter
                if not matches_user and not matches_team:
                    continue
            num_recs = len(folder.record_permissions) if folder.record_permissions else 0
            for team_uid in folder.teams:
                if team_filter and team_uid not in team_filter and not matches_user:
                    continue
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
        emails = kwargs.get('email') or ['@all']
        if '@all' not in emails:
            enterprise_users = params.enterprise.get('users', [])
            id_to_email = {eu.get('enterprise_user_id'): eu.get('username') for eu in enterprise_users}
            resolved_emails = []
            for ref in emails:
                if ref.isdigit():
                    email = id_to_email.get(int(ref))
                    if email:
                        resolved_emails.append(email)
                else:
                    resolved_emails.append(ref)
            if resolved_emails:
                kwargs['username'] = resolved_emails
        return super().execute(params, **kwargs)

    def generate_report_data(self, params, kwargs, sox_data, report_fmt, node, root_node):
        # type: (KeeperParams, Dict[str, Any], sox.sox_data.SoxData, str, int, int) -> List[List[str]]
        use_spinner = not params.batch_mode

        def get_records_accessed_rq(email, filter_recs=None, created_max=None):
            # type: (str, Optional[List[str]], Optional[int]) -> Union[None, Dict[str, Any]]
            # Empty record filter list -> no records to search for
            if filter_recs is not None and not filter_recs:
                return None

            columns = ['record_uid', 'ip_address', 'keeper_version']
            rq_filter = {'username': email}
            if filter_recs is not None:
                rq_filter['record_uid'] = filter_recs
            if created_max:
                rq_filter['created'] = {'max': created_max}

            return dict(
                command         = 'get_audit_event_reports',
                report_type     = 'span',
                scope           = 'enterprise',
                aggregate       = ['last_created'],
                limit           = API_EVENT_SUMMARY_ROW_LIMIT,
                filter          = rq_filter,
                columns         = columns
            )

        # Extract data and meta-data from the server response, which determines the next request and/or its filter params
        # 2nd value of returned Tuple (filters for the next request) is None if there are no more events to fetch
        def process_access_events(events, filter_recs=None):
            records_accessed = dict()   # type: Dict[str, Dict[str, Any]]
            recs_set = set(filter_recs or [])

            for event in events:
                r_uid = event.get('record_uid')
                records_accessed.setdefault(r_uid, event)
                recs_set.discard(r_uid)

            queries_done = len(events) < API_EVENT_SUMMARY_ROW_LIMIT or not recs_set and filter_recs is not None
            filter_params = None
            if not queries_done:
                earliest_event = {} if not events else events[-1]
                filter_params = dict(
                    filter_recs =   list(recs_set) if filter_recs is not None else filter_recs,
                    created_max =   int(earliest_event.get('last_created', 0))
                )

            return records_accessed, filter_params

        def format_datetime(dt_str):
            if not dt_str:
                return None
            ts = datetime.datetime.fromisoformat(dt_str).timestamp()
            return datetime.datetime.fromtimestamp(int(ts))

        def compile_user_report(user, access_events):
            accessed_records = dict()
            rec_uids = access_events.keys() if report_type == report_type_default \
                else sox_data.get_vault_records(user).keys()

            for uid in rec_uids:
                access_event = access_events.get(uid, {})
                sox_rec = sox_data.get_records().get(uid)
                rec_info = sox_rec.data if sox_rec else {}
                rec_owner = sox_data.get_record_owner(uid)
                event_ts = access_event.get('last_created')
                accessed_record = {uid: {'record_title': rec_info.get('title'),
                                       'record_type':  rec_info.get('record_type'),
                                       'record_url': rec_info.get('url', '').rstrip('/'),
                                       'record_owner': rec_owner and rec_owner.email,
                                       'has_attachments': sox_rec.has_attachments if sox_rec else None,
                                       'in_trash': sox_rec.in_trash if sox_rec else None,
                                       'ip_address': access_event.get('ip_address'),
                                       'device': access_event.get('keeper_version'),
                                       'last_access': _from_ts(int(event_ts)) if event_ts else None,
                                       'vault_owner': user}}
                accessed_records.update(accessed_record)
            return accessed_records

        def compile_report_data(rec_ids):
            # Per-user aging cache invalidation when specific users selected
            stale_rec_ids = None
            is_filtered = '@all' not in (kwargs.get('email') or ['@all'])
            email_to_uid = {v: k for k, v in user_lookup.items()}
            user_filter_uids = {email_to_uid[e] for e in usernames if e in email_to_uid} if is_filtered else None
            min_aging_ts = int((datetime.datetime.now() - datetime.timedelta(days=1)).timestamp())
            if rec_ids and user_filter_uids is not None:
                stale_rec_ids = set()
                for uid in user_filter_uids:
                    user_entity = sox_data.storage.get_users().get_entity(uid)
                    if not user_entity or (user_entity.last_aging_refreshed or 0) < min_aging_ts:
                        user_email = user_lookup.get(uid)
                        user_recs = user_access_lookup.get(user_email, {})
                        stale_rec_ids.update(user_recs.keys() & rec_ids)

            aging_data = get_aging_data(params, sox_data, rec_ids,
                                        use_spinner=use_spinner,
                                        stale_rec_ids=stale_rec_ids)

            # Update last_aging_refreshed for stale users
            if user_filter_uids is not None:
                now_ts = int(datetime.datetime.now().timestamp())
                updated_users = []
                for uid in user_filter_uids:
                    user_entity = sox_data.storage.get_users().get_entity(uid)
                    if user_entity and (user_entity.last_aging_refreshed or 0) < min_aging_ts:
                        user_entity.last_aging_refreshed = now_ts
                        updated_users.append(user_entity)
                if updated_users:
                    sox_data.storage.get_users().put_entities(updated_users)

            for email, records in user_access_lookup.items():
                for uid, access_data in records.items():
                    row = [email, uid]
                    for i in range(len(row), len(self.report_headers)):
                        field = self.report_headers[i]
                        value = aging_data.get(uid, {}).get(field) if field in aging_columns \
                            else (access_data.get(field))
                        row.append(value)
                    report_data.append(row)

        def get_records_accessed(emails, limit_to_vault=False):
            # type: (List[str], Optional[bool]) -> Dict[str, Dict[str, List[str]]]
            get_rec_filter = lambda e: list(sox_data.get_vault_records(e).keys()) if limit_to_vault else None
            records_accessed_by_user = {e: dict() for e in emails}
            filters_by_user = {e: dict(filter_recs=get_rec_filter(e)) for e in emails}
            should_query = lambda rq_filter: rq_filter and (rq_filter.get('filter_recs') or not limit_to_vault)
            spinner = None
            total_users = len(emails)
            # Make requests in batches, walking backwards in time (w/ query filters) for all users in parallel (1 user per sub-request)
            try:
                while True:
                    users_to_query = [user for user, user_filter in filters_by_user.items() if should_query(user_filter)]
                    if not users_to_query:
                        break
                    if use_spinner and not spinner:
                        spinner = Spinner('Loading record access events...')
                        spinner.start()
                    if spinner:
                        spinner.message = f'Loading record access events - Users remaining: {len(users_to_query)}/{total_users}'
                    requests = [get_records_accessed_rq(email, **filters_by_user.get(email)) for email in users_to_query]
                    responses = api.execute_batch(params, requests)
                    responses_by_user = zip(users_to_query, responses)
                    for user, response in responses_by_user:
                        access_events = response.get('audit_event_overview_report_rows', [])
                        records_accessed = records_accessed_by_user.get(user, {})
                        records_accessed_new, filters = process_access_events(access_events, filter_recs=filters_by_user.get(user, {}).get('filter_recs'))
                        for rec_uid, event in records_accessed_new.items():
                            records_accessed.setdefault(rec_uid, event)
                        records_accessed_by_user.update({user: records_accessed})
                        filters_by_user.update({user: filters})
            finally:
                if spinner:
                    spinner.stop()
            return records_accessed_by_user

        from .enterprise import EnterpriseInfoCommand

        report_data = []
        user_lookup = {user.get('enterprise_user_id'): user.get('username') for user in params.enterprise.get('users')}
        user_access_lookup = dict()
        aging = kwargs.get('aging')
        users = kwargs.get('email') or ['@all']
        managed_users = json.loads( EnterpriseInfoCommand().execute(params, users=True, quiet=True, format='json'))
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

        aging_columns = ['created', 'last_pw_change', 'last_modified', 'last_rotation'] if aging else []
        self.report_headers = default_columns + aging_columns

        record_access_events = get_records_accessed(usernames, report_type != report_type_default)
        user_access_lookup = {user: compile_user_report(user, access_events) for user, access_events in record_access_events.items()}
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
        user_filter = kwargs.get('_user_filter')
        from .enterprise import EnterpriseInfoCommand
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
        if user_filter is not None:
            managed_user_ids &= user_filter
        empty_vault_user_ids = {user_id for user_id in managed_user_ids if user_id not in sox_data.get_users()}
        empty_vault_users = [mu for mu in managed_users if mu.get('user_id') in empty_vault_user_ids]
        sox_users = sox_data.get_users().values()
        report_data = [get_row(u) for u in sox_users if u.user_uid in managed_user_ids]
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
        explicit_user_filter = kwargs.get('_explicit_user_filter')
        team_filter = kwargs.get('_team_filter')
        sfs = sox_data.get_shared_folders()
        teams = sox_data.get_teams()
        report_data = []
        for sfuid, sf in sfs.items():
            if explicit_user_filter or team_filter:
                all_folder_uids = get_all_folder_user_uids(sf, teams)
                matches_user = explicit_user_filter and all_folder_uids & explicit_user_filter
                matches_team = team_filter and sf.teams & team_filter
                if not matches_user and not matches_team:
                    continue
            sf_team_uids = list(sf.teams)
            sf_team_names = [teams.get(t).team_name for t in sf_team_uids]
            records = [rp.record_uid for rp in sf.record_permissions]
            users = [get_email(sox_data, u) for u in sf.users]
            team_users = [tu for tuid in sf_team_uids for tu in get_team_usernames(sox_data, teams.get(tuid))] if show_team_users else []
            team_users = [f'(TU){email}' for email in team_users]
            row = [sfuid, sf_team_uids, sf_team_names, records, team_users + users]
            report_data.append(row)
        return report_data
