import datetime
import os
import sqlite3
from typing import Dict

from .. import api, crypto, utils
from ..params import KeeperParams
from ..proto import enterprise_pb2
from . import sqlite_storage, sox_data
from .storage_types import StorageRecord, StorageUser, StorageUserRecordLink, StorageTeam, \
    StorageRecordPermissions, StorageTeamUserLink, StorageSharedFolderRecordLink, StorageSharedFolderUserLink, \
    StorageSharedFolderTeamLink

API_SOX_REQUEST_USER_LIMIT = 1000


def get_prelim_data(params, enterprise_id=0, rebuild=False, min_updated=0):
    # type: (KeeperParams, int, bool, int) -> sox_data.SoxData
    def sync_down(name_by_id, store):  # type: (Dict[int, str], sqlite_storage.SqliteSoxStorage) ->  None
        def to_storage_types(user_data, username_lookup):
            def to_record_entity(record):
                entity = StorageRecord()
                entity.record_uid = utils.base64_url_encode(record.recordUid)
                entity.encrypted_data = utils.base64_url_encode(record.encryptedData)
                entity.shared = record.shared
                return entity

            def to_user_entity(user, email_lookup):
                entity = StorageUser()
                entity.status = user.status
                entity.user_uid = user.enterpriseUserId
                entity.email = email_lookup.get(entity.user_uid)
                return entity

            def to_user_record_link(uuid, ruid):
                link = StorageUserRecordLink()
                link.user_uid = uuid
                link.record_uid = ruid
                return link

            user_ent = to_user_entity(user_data, username_lookup)
            record_ents = {to_record_entity(x) for x in user_data.auditUserRecords}
            user_rec_links = {to_user_record_link(user_ent.user_uid, record_ent.record_uid) for record_ent in
                              record_ents}
            return user_ent, record_ents, user_rec_links

        def fetch_entities():
            print('Loading record information.', end='', flush=True)
            record_entities = set()
            user_entities = set()
            user_record_links = set()
            user_ids = list(user_lookup.keys())
            while user_ids:
                print('.', end='', flush=True)
                token = b''
                chunk = user_ids[:API_SOX_REQUEST_USER_LIMIT]
                user_ids = user_ids[API_SOX_REQUEST_USER_LIMIT:]
                rq = enterprise_pb2.PreliminaryComplianceDataRequest()
                rq.enterpriseUserIds.extend(chunk)
                rq.includeNonShared = True
                has_more = True
                while has_more:
                    print('.', end='', flush=True)
                    if token:
                        rq.continuationToken = token
                    rs = api.communicate_rest(params, rq, 'enterprise/get_preliminary_compliance_data',
                                              rs_type=enterprise_pb2.PreliminaryComplianceDataResponse)
                    has_more = rs.hasMore
                    print('.', end='', flush=True) if has_more else print('.')
                    token = rs.continuationToken
                    for user_data in rs.auditUserData:
                        user, records, links = to_storage_types(user_data, name_by_id)
                        user_entities.add(user)
                        record_entities.update(records)
                        user_record_links.update(links)
            return user_entities, record_entities, user_record_links

        users, records, links = fetch_entities()
        store.rebuild_prelim_data(users, records, links)

    enterprise_id = enterprise_id or next(((x['node_id'] >> 32) for x in params.enterprise['nodes']), 0)
    path = os.path.dirname(os.path.abspath(params.config_filename or '1'))
    database_name = os.path.join(path, f'sox_{enterprise_id}.db')
    tree_key = params.enterprise['unencrypted_tree_key']
    ecc_key = utils.base64_url_decode(params.enterprise['keys']['ecc_encrypted_private_key'])
    ecc_key = crypto.decrypt_aes_v2(ecc_key, tree_key)
    key = crypto.load_ec_private_key(ecc_key)
    storage = sqlite_storage.SqliteSoxStorage(get_connection=lambda: sqlite3.connect(database_name), owner=params.user)
    user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise['users']}
    last_updated = storage.last_prelim_data_update
    rebuild_needed = rebuild or not last_updated or min_updated > last_updated
    if rebuild_needed:
        sync_down(user_lookup, storage)
    return sox_data.SoxData(ec_private_key=key, storage=storage)


def get_compliance_data(params, node_id, enterprise_id=0, rebuild=False, min_updated=0):
    def sync_down(sdata, node_uid, user_node_id_lookup):
        def sync_users(user_profiles):
            entities = []
            for up in user_profiles:
                entity = sd.storage.users.get_entity(up.enterpriseUserId) or StorageUser()
                entity.user_uid = entity.user_uid or up.enterpriseUserId
                entity.email = entity.email or up.email
                entity.job_title = entity.job_title or up.jobTitle
                entity.full_name = entity.full_name or up.fullName
                user_node = user_node_id_lookup.get(up.enterpriseUserId)
                entity.node_id = user_node
                entities.append(entity)
            sdata.storage.users.put_entities(entities)

        print('Loading compliance data.', end='', flush=True)
        users_uids = [int(uid) for uid in sd.get_users().keys()]
        record_uids = [utils.base64_url_decode(uid) for uid in sd.get_records().keys()]
        loaded_audit_records = []
        loaded_audit_teams = []
        loaded_audit_roles = []
        loaded_team_users = []
        loaded_sf_records = []
        loaded_sf_users = []
        loaded_sf_teams = []
        loaded_user_records = []
        anon_user_uid = 0

        while record_uids:
            print('.', end='', flush=True)
            chunk = record_uids[:API_SOX_REQUEST_USER_LIMIT]
            record_uids = record_uids[API_SOX_REQUEST_USER_LIMIT:]
            rq = enterprise_pb2.ComplianceReportRequest()
            rq.saveReport = False
            rq.reportName = f'Compliance Report on {datetime.datetime.now()}'
            report_run = rq.complianceReportRun
            report_run.users.extend(users_uids)
            report_run.records.extend(chunk)
            caf = report_run.reportCriteriaAndFilter
            caf.nodeId = node_uid
            rs = api.communicate_rest(params, rq, 'enterprise/run_compliance_report',
                                      rs_type=enterprise_pb2.ComplianceReportResponse)
            print('.', end='', flush=True) if record_uids else print('.')

            # create new user uid for each anonymous user (uid >> 32 == 0)
            anon_ids = dict()
            for up in rs.userProfiles:
                user_id = up.enterpriseUserId
                if not user_id >> 32:
                    new_id = user_id + anon_user_uid
                    anon_ids[user_id] = new_id
                    up.enterpriseUserId = new_id

            anon_user_uid = max(anon_ids.values()) if anon_ids else anon_user_uid

            for ur in rs.userRecords:
                user_id = ur.enterpriseUserId
                ur.enterpriseUserId = anon_ids.get(user_id, user_id)

            for folder in rs.sharedFolderUsers:
                for idx, user_id in enumerate(folder.enterpriseUserIds):
                    folder.enterpriseUserIds[idx] = anon_ids.get(user_id, user_id)

            loaded_user_records.extend(rs.userRecords)
            loaded_audit_records.extend(rs.auditRecords)
            loaded_audit_roles.extend(rs.auditRoles)
            loaded_audit_teams.extend(rs.auditTeams)
            sync_users(rs.userProfiles)
            loaded_team_users.extend(rs.auditTeamUsers)
            loaded_sf_users.extend(rs.sharedFolderUsers)
            loaded_sf_teams.extend(rs.sharedFolderTeams)
            loaded_sf_records.extend(rs.sharedFolderRecords)

        def sync_teams(audit_teams):
            entities = []
            for team in audit_teams:
                team_uid = utils.base64_url_encode(team.teamUid)
                entity = sd.storage.teams.get_entity(team_uid) or StorageTeam()
                entity.team_uid = team_uid
                entity.team_name = team.teamName
                entities.append(entity)
            sdata.storage.teams.put_entities(entities)

        def sync_team_users(audit_team_users):
            links = []
            for team in audit_team_users:
                team_uid = utils.base64_url_encode(team.teamUid)
                links.extend([StorageTeamUserLink(team_uid, user_uid) for user_uid in team.enterpriseUserIds])
            sdata.storage.get_team_user_links().put_links(links)

        def sync_shared_folders_records(sf_records):
            links = []
            for folder in sf_records:
                folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
                for rp in folder.recordPermissions:
                    record_uid = utils.base64_url_encode(rp.recordUid)
                    link = StorageSharedFolderRecordLink(folder_uid, record_uid, rp.permissionBits)
                    links.append(link)
            sdata.storage.get_sf_record_links().put_links(links)

        def sync_record_permissions(sf_records, user_records):
            def to_rec_perm_links(user_uid, record_permissions):
                rp_links = []
                for rp in record_permissions:
                    ruid = utils.base64_url_encode(rp.recordUid)
                    link = StorageRecordPermissions(ruid, user_uid, rp.permissionBits)
                    rp_links.append(link)
                return rp_links

            links = []
            for ur in user_records:
                links.extend(to_rec_perm_links(ur.enterpriseUserId, ur.recordPermissions))
            for folder in sf_records:
                rec_perms = folder.recordPermissions
                for sar in folder.shareAdminRecords:
                    user_uid = sar.enterpriseUserId
                    rec_perm_idxs = sar.recordPermissionIndexes
                    links.extend([to_rec_perm_links(user_uid, rec_perms[index]) for index in rec_perm_idxs])
            sdata.storage.get_record_permissions().put_links(links)

        def sync_shared_folder_users(sf_users):
            links = []
            for folder in sf_users:
                folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
                links.extend([StorageSharedFolderUserLink(folder_uid, uuid) for uuid in folder.enterpriseUserIds])
            sdata.storage.get_sf_user_links().put_links(links)

        def sync_shared_folder_teams(sf_teams):
            links = []
            for folder in sf_teams:
                folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
                for tuid in folder.teamUids:
                    team_uid = utils.base64_url_encode(tuid)
                    links.append(StorageSharedFolderTeamLink(folder_uid, team_uid))
            sdata.storage.get_sf_team_links().put_links(links)

        def sync_records(records):
            entities = []
            for record in records:
                rec_uid = utils.base64_url_encode(record.recordUid)
                entity = sdata.storage.records.get_entity(rec_uid)
                entity.in_trash = record.inTrash
                entity.has_attachments = record.hasAttachments
                entities.append(entity)
            sdata.storage.records.put_entities(entities)

        sync_records(loaded_audit_records)
        sync_teams(loaded_audit_teams)
        sync_team_users(loaded_team_users)
        sync_shared_folders_records(loaded_sf_records)
        sync_shared_folder_users(loaded_sf_users)
        sync_shared_folder_teams(loaded_sf_teams)
        sync_record_permissions(loaded_sf_records, loaded_user_records)
        sd.storage.set_compliance_data_updated()

    sd = get_prelim_data(params, enterprise_id, rebuild=rebuild, min_updated=min_updated)
    last_compliance_data_update = sd.storage.last_compliance_data_update
    refresh_data = rebuild or min_updated > last_compliance_data_update
    if refresh_data:
        enterprise_users = params.enterprise.get('users')
        user_node_ids = {e_user.get('enterprise_user_id'): e_user.get('node_id') for e_user in enterprise_users}
        sync_down(sd, node_id, user_node_id_lookup=user_node_ids)
    rebuild_task = sox_data.RebuildTask(is_full_sync=False, load_compliance_data=True)
    sd.rebuild_data(rebuild_task)
    return sd
