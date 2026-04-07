import datetime
import logging
import os
import sqlite3
import sys
from typing import Dict, Optional, Set, Tuple

import requests

from .. import api, crypto, utils
from ..display import Spinner

# Module-level connection cache to ensure single connection per database
_connection_cache = {}  # type: Dict[str, sqlite3.Connection]


def get_cached_connection(database_name):  # type: (str) -> sqlite3.Connection
    """Get or create a cached connection for the given database."""
    if database_name not in _connection_cache:
        _connection_cache[database_name] = sqlite3.connect(database_name)
    return _connection_cache[database_name]


def close_cached_connection(database_name):  # type: (str) -> None
    """Close and remove a cached connection."""
    if database_name in _connection_cache:
        try:
            _connection_cache[database_name].close()
        except Exception:
            pass
        del _connection_cache[database_name]
from ..commands.helpers.enterprise import user_has_privilege, is_addon_enabled
from ..error import CommandError, Error, KeeperApiError
from ..params import KeeperParams
from ..proto import enterprise_pb2
from . import sqlite_storage, sox_data
from .storage_types import StorageRecord, StorageUser, StorageUserRecordLink, StorageTeam, \
    StorageRecordPermissions, StorageTeamUserLink, StorageSharedFolderRecordLink, StorageSharedFolderUserLink, \
    StorageSharedFolderTeamLink

API_SOX_REQUEST_USER_LIMIT = 1000
API_SOX_MAX_USERS_PER_REQUEST = 5000  # Server limit: MAX_CHOSEN_ENTERPRISE_USERS
API_SOX_MAX_RECORDS_PER_REQUEST = 1000  # Server limit: MAX_REPORTED_RECORD_LIMIT


def validate_data_access(params, cmd=''):
    privilege = 'run_compliance_reports'
    addon = 'compliance_report'
    msg_no_priv = 'You do not have the required privilege to run a Compliance Report.'
    msg_no_addon = ('Compliance reports add-on is required to perform this action. '
                    'Please contact your administrator to enable this feature.')
    error_msg = msg_no_priv if not user_has_privilege(params, privilege) \
        else msg_no_addon if not is_addon_enabled(params, addon) \
        else None
    if error_msg:
        raise CommandError(cmd, error_msg)


def is_compliance_reporting_enabled(params):
    privilege = 'run_compliance_reports'
    addon = 'compliance_report'
    return user_has_privilege(params, privilege) and is_addon_enabled(params, addon)


def encrypt_data(params, data): # type: (KeeperParams, str) -> bytes
    data_bytes = utils.string_to_bytes(data) if data else b''
    encrypted = ''
    try:
        encrypted = crypto.encrypt_aes_v1(data_bytes, params.enterprise.get('unencrypted_tree_key'))
    except Error as e:
        logging.info(f'Error encrypting data, type = {type(data)}, value = {data}, message = {e.message}')
    return encrypted


def get_sox_database_name(params, enterprise_id):  # type: (KeeperParams, int) -> str
    path = os.path.dirname(os.path.abspath(params.config_filename or '1'))
    return os.path.join(path, f'sox_{enterprise_id}.db')


def get_prelim_data(params, enterprise_id=0, rebuild=False, min_updated=0, cache_only=False, no_cache=False, shared_only=False, user_filter=None):
    # type: (KeeperParams, int, bool, int, bool, bool, bool, Optional[Set[int]]) -> sox_data.SoxData
    def sync_down(name_by_id, store):  # type: (Dict[int, str], sqlite_storage.SqliteSoxStorage) ->  None
        spinner = None
        use_spinner = not params.batch_mode

        def start_spinner():
            nonlocal spinner
            if use_spinner and not spinner:
                spinner = Spinner('Loading record information...')
                spinner.start()

        def stop_spinner():
            if spinner:
                spinner.stop()

        def to_storage_types(user_data, username_lookup):
            def to_record_entity(record):
                record_uid_bytes = record.recordUid
                record_uid = utils.base64_url_encode(record_uid_bytes)
                entity = store.get_records().get_entity(record_uid) or StorageRecord()
                entity.record_uid_bytes = record_uid_bytes
                entity.record_uid = record_uid
                entity.encrypted_data = record.encryptedData
                entity.shared = record.shared
                return entity

            def to_user_entity(user, email_lookup):
                entity = store.get_users().get_entity(user.enterpriseUserId) or StorageUser()
                entity.status = user.status
                user_id = user.enterpriseUserId
                entity.user_uid = user_id
                email = email_lookup.get(user_id)
                entity.email = encrypt_data(params, email) if email else b''
                entity.last_refreshed = int(datetime.datetime.now().timestamp())
                return entity

            def to_user_record_link(uuid, ruid):
                link = StorageUserRecordLink()
                link.user_uid = uuid
                link.record_uid = ruid
                return link

            user_ent = to_user_entity(user_data, username_lookup)
            record_ents = [to_record_entity(x) for x in user_data.auditUserRecords if x.encryptedData]
            user_rec_links = {to_user_record_link(user_ent.user_uid, record_ent.record_uid) for record_ent in
                              record_ents}
            return user_ent, record_ents, user_rec_links

        def print_status(users_loaded, users_total, records_loaded, records_total,
                         chunk_size=None, batch_loaded=0, batch_total=0):
            if records_total > 0 and users_loaded < users_total and users_loaded > 0:
                estimated_total = int(records_total * users_total / users_loaded)
                records_str = f'{records_loaded}/~{estimated_total}'
            elif records_total > 0:
                records_str = f'{records_loaded}/{records_total}'
            else:
                records_str = str(records_loaded)
            message = (f'Loading record information - Users: {users_loaded}/{users_total}, '
                       f'Records: {records_str}')
            if batch_total > 0:
                message += f', Batch: {batch_loaded}/{batch_total}'
            if chunk_size is not None:
                message += f' (querying {chunk_size} user{"s" if chunk_size != 1 else ""})'
            if spinner:
                spinner.message = message
                return
            print('\r' + (100 * ' '), file=sys.stderr, end='', flush=True)
            print(f'\r{message}', file=sys.stderr, end='', flush=True)

        def sync_all():
            PRELIM_PAGE_LIMIT = 10000
            PROBE_TIMEOUT = (15, 30)
            start_spinner()
            user_ids = list(user_lookup.keys())
            users_total = len(user_ids)
            records_total = 0
            print_status(0, users_total, 0, records_total)
            users, records, links = [], [], []
            chunk_size = min(5, len(user_ids))
            avg_records_per_user = 0
            total_records_loaded = 0
            problem_ids = set()
            while user_ids:
                token = b''
                chunk = user_ids[:chunk_size]
                user_ids = user_ids[chunk_size:]
                rq = enterprise_pb2.PreliminaryComplianceDataRequest()
                rq.enterpriseUserIds.extend(chunk)
                rq.includeNonShared = not shared_only
                has_more = True
                current_batch_loaded = 0
                chunk_total = 0
                is_first_page = True
                seen_user_ids = []
                while has_more:
                    rq.continuationToken = token or rq.continuationToken
                    rq.includeTotalMatchingRecordsInFirstResponse = True
                    endpoint = 'enterprise/get_preliminary_compliance_data'
                    rs_type = enterprise_pb2.PreliminaryComplianceDataResponse
                    try:
                        call_timeout = PROBE_TIMEOUT if is_first_page and chunk_size > 1 else None
                        rs = api.communicate_rest(params, rq, endpoint, rs_type=rs_type, timeout=call_timeout)
                        is_first_page = False
                        has_more = rs.hasMore
                        if rs.totalMatchingRecords:
                            current_batch_loaded = 0
                            chunk_total = rs.totalMatchingRecords
                            records_total += chunk_total
                        token = rs.continuationToken
                        for user_data in rs.auditUserData:
                            t_user, t_recs, t_links = to_storage_types(user_data, name_by_id)
                            users += [t_user]
                            records += t_recs
                            current_batch_loaded += len(t_recs)
                            total_records_loaded += len(t_recs)
                            if t_user.user_uid not in seen_user_ids:
                                seen_user_ids.append(t_user.user_uid)
                            print_status(users_total - len(user_ids), users_total, total_records_loaded, records_total,
                                         len(chunk), current_batch_loaded, chunk_total)
                            links += t_links
                        if chunk_total > PRELIM_PAGE_LIMIT and len(chunk) > 1 and has_more:
                            avg_records_per_user = chunk_total / len(chunk)
                            chunk_size = max(1, int(PRELIM_PAGE_LIMIT / avg_records_per_user))
                            complete_ids = set(seen_user_ids[:-1]) if seen_user_ids else set()
                            requeue_ids = [uid for uid in chunk if uid not in complete_ids]
                            records_total -= (chunk_total - current_batch_loaded)
                            user_ids = [*requeue_ids, *user_ids]
                            break
                        if not has_more:
                            print_status(users_total - len(user_ids), users_total, total_records_loaded, records_total,
                                         len(chunk), current_batch_loaded, chunk_total)
                    except requests.exceptions.Timeout:
                        records_total -= chunk_total
                        complete_ids = set(seen_user_ids[:-1]) if seen_user_ids else set()
                        requeue_ids = [uid for uid in chunk if uid not in complete_ids]
                        if chunk_size > 1:
                            if avg_records_per_user > 0:
                                chunk_size = max(1, int(PRELIM_PAGE_LIMIT / avg_records_per_user))
                            else:
                                chunk_size = max(1, chunk_size // 2)
                        user_ids = [*requeue_ids, *user_ids]
                        break
                    except KeeperApiError as kae:
                        if kae.message.lower() == 'gateway_timeout':
                            records_total -= chunk_total
                            complete_ids = set(seen_user_ids[:-1]) if seen_user_ids else set()
                            requeue_ids = [uid for uid in chunk if uid not in complete_ids]
                            if len(requeue_ids) > 1 or chunk_size > 1:
                                if avg_records_per_user > 0:
                                    chunk_size = max(1, int(PRELIM_PAGE_LIMIT / avg_records_per_user))
                                else:
                                    chunk_size = max(1, chunk_size // 2)
                                user_ids = [*requeue_ids, *user_ids]
                            else:
                                problem_ids.update(requeue_ids)
                            break
                        else:
                            raise
                    except Exception as ex:
                        raise ex
                else:
                    if chunk_total > 0 and len(chunk) > 0:
                        avg_records_per_user = chunk_total / len(chunk)
                    if avg_records_per_user > 0:
                        chunk_size = max(1, min(int(PRELIM_PAGE_LIMIT / avg_records_per_user),
                                                API_SOX_REQUEST_USER_LIMIT))
                    elif chunk_size < API_SOX_REQUEST_USER_LIMIT:
                        chunk_size = min(chunk_size * 2, API_SOX_REQUEST_USER_LIMIT)
            if problem_ids:
                problem_emails = '\n'.join([name_by_id.get(id) for id in problem_ids])
                logging.error(f'Data could not be fetched for the following users: \n{problem_emails}')

            store.update_user_prelim_data(users, records, links, set(name_by_id.keys()))
            store.set_prelim_data_updated()
        success = False
        try:
            sync_all()
            success = True
        finally:
            stop_spinner()
        if spinner and success:
            print('Preliminary compliance data loaded.', flush=True)
        elif not spinner:
            print('', file=sys.stderr, flush=True)

    validate_data_access(params)
    enterprise_id = enterprise_id or next(((x['node_id'] >> 32) for x in params.enterprise['nodes']), 0)
    database_name = get_sox_database_name(params, enterprise_id)
    tree_key = params.enterprise['unencrypted_tree_key']
    ecc_key = utils.base64_url_decode(params.enterprise['keys']['ecc_encrypted_private_key'])
    ecc_key = crypto.decrypt_aes_v2(ecc_key, tree_key)
    key = crypto.load_ec_private_key(ecc_key)
    storage = sqlite_storage.SqliteSoxStorage(
        get_connection=lambda: get_cached_connection(database_name),
        owner=params.user,
        database_name=database_name,
        close_connection=lambda: close_cached_connection(database_name)
    )
    all_users = params.enterprise.get('users', [])
    candidate_lookup = {x['enterprise_user_id']: x['username'] for x in all_users
                        if user_filter is None or x['enterprise_user_id'] in user_filter}
    only_shared_cached = storage.shared_records_only
    if rebuild or (only_shared_cached and not shared_only):
        stale_ids = set(candidate_lookup.keys())
    else:
        stale_ids = set()
        for uid in candidate_lookup:
            user_entity = storage.get_users().get_entity(uid)
            if not user_entity or (user_entity.last_refreshed or 0) < min_updated:
                stale_ids.add(uid)
    if stale_ids and not cache_only:
        user_lookup = {uid: candidate_lookup[uid] for uid in stale_ids}
        sync_down(user_lookup, storage)
    storage.set_shared_records_only(shared_only)
    return sox_data.SoxData(params, storage=storage)


def get_compliance_data(params, node_id, enterprise_id=0, rebuild=False, min_updated=0, no_cache=False, shared_only=False, user_filter=None):
    # type: (KeeperParams, int, int, bool, int, bool, bool, Optional[Set[int]]) -> sox_data.SoxData
    def sync_down(sdata, node_uid, user_node_id_lookup):
        recs_processed = 0
        spinner = None
        use_spinner = not params.batch_mode

        def print_status(pct_done):
            message = f'Loading compliance data - {pct_done * 100:.2f}%'
            if spinner:
                spinner.message = message
                return
            print('\r' + (100 * ' '), file=sys.stderr, end='', flush=True)
            print(f'\r{message}', file=sys.stderr, end='', flush=True)

        def start_spinner():
            nonlocal spinner
            if use_spinner and not spinner:
                spinner = Spinner('Loading compliance data...')
                spinner.start()

        def stop_spinner():
            if spinner:
                spinner.stop()

        def run_sync_tasks():
            def do_tasks():
                start_spinner()
                print_status(0)
                users_uids = [int(uid) for uid in sdata.get_users()]
                storage_records = {e.record_uid: e for e in sdata.storage.records.get_all()}
                if rebuild:
                    stale_record_uids = set(storage_records.keys())
                else:
                    stale_record_uids = {
                        uid for uid, rec in storage_records.items()
                        if (rec.last_compliance_refreshed or 0) < min_updated
                    }
                if not stale_record_uids:
                    sdata.storage.set_compliance_data_updated()
                    return
                records_by_uid = {rec.record_uid: rec.record_uid_bytes for rec in storage_records.values()
                                  if rec.record_uid in stale_record_uids}
                max_records = API_SOX_MAX_RECORDS_PER_REQUEST
                max_users = API_SOX_MAX_USERS_PER_REQUEST
                if not users_uids:
                    return
                total_records = len(records_by_uid)
                user_chunks = [users_uids[x:x + max_users] for x in range(0, len(users_uids), max_users)]
                for user_chunk in user_chunks:
                    chunk_record_uids = set()
                    for uid in user_chunk:
                        user = sdata.get_user(uid)
                        if user:
                            chunk_record_uids.update(user.records & stale_record_uids)
                    chunk_records_raw = [records_by_uid[r] for r in chunk_record_uids if r in records_by_uid and records_by_uid[r]]
                    if not chunk_records_raw:
                        continue
                    chunk_user_uids = [uid for uid in user_chunk
                                       if any(r in stale_record_uids for r in (sdata.get_user(uid).records if sdata.get_user(uid) else set()))]
                    if not chunk_user_uids:
                        continue
                    ruid_chunks = [chunk_records_raw[x:x + max_records] for x in range(0, len(chunk_records_raw), max_records)]
                    for ruid_chunk in ruid_chunks:
                        try:
                            sync_chunk(ruid_chunk, chunk_user_uids)
                        except KeeperApiError as kae:
                            if kae.message.lower() == 'gateway_timeout':
                                logging.warning('Compliance sync chunk timed out (%d records, %d users), skipping.',
                                                len(ruid_chunk), len(chunk_user_uids))
                            else:
                                logging.error('Compliance sync chunk error: %s (%d records, %d users)',
                                              kae.message, len(ruid_chunk), len(chunk_user_uids))
                        except Exception as ex:
                            logging.error('Compliance sync chunk unexpected error: %s', ex)
                        if total_records > 0:
                            print_status(recs_processed / total_records)
                sdata.storage.set_compliance_data_updated()
                if not spinner:
                    print('', file=sys.stderr, flush=True)

            success = False
            try:
                do_tasks()
                success = True
            finally:
                stop_spinner()
            if spinner and success:
                print('Compliance data loaded.', flush=True)

        def sync_chunk(chunk, uuids):
            rs = fetch_response(raw_ruids=chunk, user_uids=uuids)
            save_response(rs)

        def fetch_response(raw_ruids, user_uids):
            if not user_uids or not raw_ruids:
                logging.debug('Skipping compliance report request: users=%d, records=%d', len(user_uids), len(raw_ruids))
                return enterprise_pb2.ComplianceReportResponse()
            rq = enterprise_pb2.ComplianceReportRequest()
            rq.saveReport = False
            rq.reportName = f'Compliance Report on {datetime.datetime.now()}'
            report_run = rq.complianceReportRun
            report_run.users.extend(user_uids)
            report_run.records.extend(raw_ruids)
            caf = report_run.reportCriteriaAndFilter
            caf.nodeId = node_uid
            caf.criteria.includeNonShared = not shared_only
            endpoint = 'enterprise/run_compliance_report'
            return api.communicate_rest(params, rq, endpoint, rs_type=enterprise_pb2.ComplianceReportResponse)

        anon_id = 0

        def save_response(rs):
            def hash_anon_ids(response):
                # create new user uid for each anonymous user (uid >> 32 == 0)
                anon_ids = dict()
                nonlocal anon_id
                for up in rs.userProfiles:
                    user_id = up.enterpriseUserId
                    if not user_id >> 32:
                        new_id = user_id + anon_id
                        anon_ids[user_id] = new_id
                        up.enterpriseUserId = new_id
                        anon_id = new_id
                for ur in rs.userRecords:
                    user_id = ur.enterpriseUserId
                    ur.enterpriseUserId = anon_ids.get(user_id, user_id)
                for folder in rs.sharedFolderUsers:
                    for idx, user_id in enumerate(folder.enterpriseUserIds):
                        folder.enterpriseUserIds[idx] = anon_ids.get(user_id, user_id)
                return response

            save_all_types(hash_anon_ids(rs))

        def save_all_types(rs):
            save_users(rs.userProfiles)
            save_records(rs.auditRecords)
            save_teams(rs.auditTeams)
            save_shared_folders_records(rs.sharedFolderRecords)
            save_shared_folder_users(rs.sharedFolderUsers)
            save_shared_folder_teams(rs.sharedFolderTeams)
            save_record_permissions(rs.sharedFolderRecords, rs.userRecords)
            save_team_users(rs.auditTeamUsers)

        def save_users(user_profiles):
            entities = []
            for up in user_profiles:
                entity = sdata.storage.users.get_entity(up.enterpriseUserId) or StorageUser()
                entity.user_uid = entity.user_uid or up.enterpriseUserId
                entity.email = entity.email or encrypt_data(params, up.email)
                entity.job_title = entity.job_title or encrypt_data(params, up.jobTitle)
                entity.full_name = entity.full_name or encrypt_data(params, up.fullName)
                user_node = user_node_id_lookup.get(up.enterpriseUserId)
                entity.node_id = user_node
                entities.append(entity)
            sdata.storage.users.put_entities(entities)

        def save_teams(audit_teams):
            entities = []
            for team in audit_teams:
                team_uid = utils.base64_url_encode(team.teamUid)
                entity = sdata.storage.teams.get_entity(team_uid) or StorageTeam()
                entity.team_uid = team_uid
                entity.team_name = team.teamName
                entity.restrict_edit = team.restrictEdit
                entity.restrict_share = team.restrictShare
                entities.append(entity)
            sdata.storage.teams.put_entities(entities)

        def save_team_users(audit_team_users):
            links = []
            for team in audit_team_users:
                team_uid = utils.base64_url_encode(team.teamUid)
                links.extend([StorageTeamUserLink(team_uid, user_uid) for user_uid in team.enterpriseUserIds])
            sdata.storage.get_team_user_links().put_links(links)

        def save_shared_folders_records(sf_records):
            links = []
            for folder in sf_records:
                folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
                for rp in folder.recordPermissions:
                    record_uid = utils.base64_url_encode(rp.recordUid)
                    link = StorageSharedFolderRecordLink(folder_uid, record_uid, rp.permissionBits)
                    links.append(link)
            sdata.storage.get_sf_record_links().put_links(links)

        def save_record_permissions(sf_records, user_records):
            def update_permissions_lookup(perm_lookup, record_uid, enterprise_user_id, perm_bits):
                lookup_key = record_uid, enterprise_user_id
                p_bits = perm_lookup.get(lookup_key, perm_bits)
                perm_lookup.update({lookup_key: perm_bits | p_bits})

            # Aggregate record-permissions for each user-record pair
            rec_perms_lookup = dict()   # type: Dict[Tuple[str, int], int]
            # Save share-admin permissions
            for folder in sf_records:
                rec_perms = folder.recordPermissions
                for sar in folder.shareAdminRecords:
                    rec_perm_idxs = sar.recordPermissionIndexes
                    sar_perms = [rp for idx, rp in enumerate(rec_perms) if idx in rec_perm_idxs]
                    rec_uids = [utils.base64_url_encode(rp.recordUid) for rp in sar_perms]
                    for ruid in rec_uids:
                        update_permissions_lookup(rec_perms_lookup, ruid, sar.enterpriseUserId, 16)

            for ur in user_records:
                for rp in ur.recordPermissions:
                    ruid = utils.base64_url_encode(rp.recordUid)
                    update_permissions_lookup(rec_perms_lookup, ruid, ur.enterpriseUserId, rp.permissionBits)

            links = []
            for k, v in rec_perms_lookup.items():
                rec_uid, user_id = k
                link = StorageRecordPermissions(rec_uid, user_id, v)
                links.append(link)
            sdata.storage.get_record_permissions().put_links(links)

        def save_shared_folder_users(sf_users):
            links = []
            for folder in sf_users:
                folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
                links.extend([StorageSharedFolderUserLink(folder_uid, uuid) for uuid in folder.enterpriseUserIds])
            sdata.storage.get_sf_user_links().put_links(links)

        def save_shared_folder_teams(sf_teams):
            links = []
            for folder in sf_teams:
                folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
                for tuid in folder.teamUids:
                    team_uid = utils.base64_url_encode(tuid)
                    links.append(StorageSharedFolderTeamLink(folder_uid, team_uid))
            sdata.storage.get_sf_team_links().put_links(links)

        def save_records(records):
            now_ts = int(datetime.datetime.now().timestamp())
            entities = []
            for record in records:
                nonlocal recs_processed
                recs_processed += 1
                print_status(recs_processed/len(sdata.get_records()))
                rec_uid = utils.base64_url_encode(record.recordUid)
                entity = sdata.storage.records.get_entity(rec_uid)
                if entity:
                    entity.in_trash = record.inTrash
                    entity.has_attachments = record.hasAttachments
                    entity.last_compliance_refreshed = now_ts
                    entities.append(entity)
            sdata.storage.records.put_entities(entities)

        run_sync_tasks()

    sd = get_prelim_data(params, enterprise_id, rebuild=rebuild, min_updated=min_updated, cache_only=not min_updated, shared_only=shared_only, user_filter=user_filter)
    enterprise_users = params.enterprise.get('users', [])
    all_user_node_ids = {e_user.get('enterprise_user_id'): e_user.get('node_id') for e_user in enterprise_users}
    if user_filter is not None:
        filtered_user_recs = set()
        for uid in user_filter:
            user = sd.get_user(uid)
            if user:
                filtered_user_recs.update(user.records)
        has_stale_records = rebuild or any(
            (rec.last_compliance_refreshed or 0) < min_updated
            for rec in sd.storage.records.get_all() if rec.record_uid in filtered_user_recs
        )
    else:
        has_stale_records = rebuild or any(
            (rec.last_compliance_refreshed or 0) < min_updated
            for rec in sd.storage.records.get_all()
        )
    if has_stale_records:
        sync_down(sd, node_id, user_node_id_lookup=all_user_node_ids)
        if user_filter is not None:
            now_ts = int(datetime.datetime.now().timestamp())
            updated_users = []
            for uid in user_filter:
                user_entity = sd.storage.get_users().get_entity(uid)
                if user_entity:
                    user_entity.last_compliance_refreshed = now_ts
                    updated_users.append(user_entity)
            if updated_users:
                sd.storage.get_users().put_entities(updated_users)
    rebuild_task = sox_data.RebuildTask(is_full_sync=False, load_compliance_data=True)
    sd.rebuild_data(rebuild_task)
    return sd


def get_node_id(params, name):
    name = int(name) if isinstance(name, str) and name.isdecimal() else name
    nodes = params.enterprise['nodes']
    root_node_id = nodes[0].get('node_id', 0)
    node_ids = (n.get('node_id') for n in nodes)
    node_id_lookup = {n.get('data').get('displayname'): n.get('node_id') for n in nodes}
    node_id = node_id_lookup.get(name) if name in node_id_lookup \
        else name if name in node_ids \
        else root_node_id
    return node_id
