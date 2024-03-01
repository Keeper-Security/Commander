import datetime
import logging
import os
import sqlite3
import sys
from typing import Dict, Tuple

from .. import api, crypto, utils
from ..error import CommandError, Error
from ..params import KeeperParams
from ..proto import enterprise_pb2
from . import sqlite_storage, sox_data
from .storage_types import StorageRecord, StorageUser, StorageUserRecordLink, StorageTeam, \
    StorageRecordPermissions, StorageTeamUserLink, StorageSharedFolderRecordLink, StorageSharedFolderUserLink, \
    StorageSharedFolderTeamLink

API_SOX_REQUEST_USER_LIMIT = 1000


def validate_data_access(params, cmd=''):
    if not is_compliance_reporting_enabled(params):
        msg = 'Compliance reports add-on required to perform this action. ' \
              'Please contact your administrator to enable this feature.'
        raise CommandError(cmd, msg)


def is_compliance_reporting_enabled(params):
    enterprise = params.enterprise
    if not enterprise:
        return False
    e_licenses = enterprise.get('licenses')
    if not isinstance(e_licenses, list):
        return False
    if len(e_licenses) == 0:
        return False
    if e_licenses[0].get('lic_status') == 'business_trial':
        return True
    addon = next((a for l in e_licenses for a in l.get('add_ons', [])
                  if a.get('name') == 'compliance_report' and (a.get('enabled') or a.get('included_in_product'))), None)
    if addon is None:
        return False

    if not params.msp_tree_key:
        role_privilege = 'run_compliance_reports'
        username = params.user
        users = enterprise.get('users')
        e_user_id = next(iter([u.get('enterprise_user_id') for u in users if u.get('username') == username]))
        role_users = enterprise.get('role_users')
        r_ids = [ru.get('role_id') for ru in role_users if ru.get('enterprise_user_id') == e_user_id]
        r_privileges = enterprise.get('role_privileges')
        p_key = 'privilege'
        return any([rp for rp in r_privileges if rp.get('role_id') in r_ids and rp.get(p_key) == role_privilege])
    else:
        return True


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


def get_prelim_data(params, enterprise_id=0, rebuild=False, min_updated=0, cache_only=False, no_cache=False, shared_only=False):
    # type: (KeeperParams, int, bool, int, bool, bool, bool) -> sox_data.SoxData
    def sync_down(name_by_id, store):  # type: (Dict[int, str], sqlite_storage.SqliteSoxStorage) ->  None
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

        def sync_all():
            print('Loading record information.', file=sys.stderr, end='', flush=True)
            user_ids = list(user_lookup.keys())
            users, records, links = [], [], []
            while user_ids:
                print('.', file=sys.stderr, end='', flush=True)
                token = b''
                chunk = user_ids[:API_SOX_REQUEST_USER_LIMIT]
                user_ids = user_ids[API_SOX_REQUEST_USER_LIMIT:]
                rq = enterprise_pb2.PreliminaryComplianceDataRequest()
                rq.enterpriseUserIds.extend(chunk)
                rq.includeNonShared = not shared_only
                has_more = True
                while has_more:
                    rq.continuationToken = token or rq.continuationToken
                    endpoint = 'enterprise/get_preliminary_compliance_data'
                    rs_type = enterprise_pb2.PreliminaryComplianceDataResponse
                    rs = api.communicate_rest(params, rq, endpoint, rs_type=rs_type)
                    print('.', file=sys.stderr, end='', flush=True)
                    has_more = rs.hasMore
                    token = rs.continuationToken
                    for user_data in rs.auditUserData:
                        t_user, t_recs, t_links = to_storage_types(user_data, name_by_id)
                        users += [t_user]
                        records += t_recs
                        links += t_links

            store.rebuild_prelim_data(users, records, links)

        sync_all()
        print('.', file=sys.stderr, flush=True)

    validate_data_access(params)
    enterprise_id = enterprise_id or next(((x['node_id'] >> 32) for x in params.enterprise['nodes']), 0)
    database_name = get_sox_database_name(params, enterprise_id)
    tree_key = params.enterprise['unencrypted_tree_key']
    ecc_key = utils.base64_url_decode(params.enterprise['keys']['ecc_encrypted_private_key'])
    ecc_key = crypto.decrypt_aes_v2(ecc_key, tree_key)
    key = crypto.load_ec_private_key(ecc_key)
    storage = sqlite_storage.SqliteSoxStorage(
        get_connection=lambda: sqlite3.connect(database_name), owner=params.user, database_name=database_name
    )
    last_updated = storage.last_prelim_data_update
    only_shared_cached = storage.shared_records_only
    refresh_data = rebuild or not last_updated or min_updated > last_updated or only_shared_cached and not shared_only
    if refresh_data and not cache_only:
        user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise.get('users', [])}
        storage.clear_non_aging_data()
        sync_down(user_lookup, storage)
        storage.set_shared_records_only(shared_only)
    return sox_data.SoxData(params, storage=storage, no_cache=no_cache)


def get_compliance_data(params, node_id, enterprise_id=0, rebuild=False, min_updated=0, no_cache=False, shared_only=False):
    def sync_down(sdata, node_uid, user_node_id_lookup):
        def run_sync_tasks():
            def do_tasks():
                print('Loading compliance data.', file=sys.stderr, end='', flush=True)
                users_uids = [int(uid) for uid in sdata.get_users()]
                record_uids_raw = [rec.record_uid_bytes for rec in sdata.get_records().values()]
                max_len = API_SOX_REQUEST_USER_LIMIT
                total_ruids = len(record_uids_raw)
                ruid_chunks = [record_uids_raw[x:x + max_len] for x in range(0, total_ruids, max_len)]
                for chunk in ruid_chunks:
                    sync_chunk(chunk, users_uids)
                sdata.storage.set_compliance_data_updated()
                print('', file=sys.stderr, flush=True)

            do_tasks()

        def sync_chunk(chunk, uuids):
            print('.', file=sys.stderr, end='', flush=True)
            rs = fetch_response(raw_ruids=chunk, user_uids=uuids)
            print('.', file=sys.stderr, end='', flush=True)
            save_response(rs)
            print(':', file=sys.stderr, end='', flush=True)

        def fetch_response(raw_ruids, user_uids):
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
            print('.', file=sys.stderr, end='', flush=True)

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
            entities = []
            for record in records:
                rec_uid = utils.base64_url_encode(record.recordUid)
                entity = sdata.storage.records.get_entity(rec_uid)
                if entity:
                    entity.in_trash = record.inTrash
                    entity.has_attachments = record.hasAttachments
                    entities.append(entity)
            sdata.storage.records.put_entities(entities)

        run_sync_tasks()

    sd = get_prelim_data(params, enterprise_id, rebuild=rebuild, min_updated=min_updated, cache_only=not min_updated, shared_only=shared_only)
    last_compliance_data_update = sd.storage.last_compliance_data_update
    refresh_data = rebuild or min_updated > last_compliance_data_update
    if refresh_data:
        enterprise_users = params.enterprise.get('users', [])
        user_node_ids = {e_user.get('enterprise_user_id'): e_user.get('node_id') for e_user in enterprise_users}
        sync_down(sd, node_id, user_node_id_lookup=user_node_ids)
    rebuild_task = sox_data.RebuildTask(is_full_sync=False, load_compliance_data=True)
    sd.rebuild_data(rebuild_task, no_cache=no_cache)
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
