import asyncio
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


def get_prelim_data(params, enterprise_id=0, rebuild=False, min_updated=0, cache_only=False):
    # type: (KeeperParams, int, bool, int, bool) -> sox_data.SoxData
    def sync_down(name_by_id, store):  # type: (Dict[int, str], sqlite_storage.SqliteSoxStorage) ->  None
        def to_storage_types(user_data, username_lookup):
            def to_record_entity(record):
                entity = StorageRecord()
                entity.record_uid_bytes = record.recordUid
                entity.record_uid = utils.base64_url_encode(record.recordUid)
                entity.encrypted_data = record.encryptedData
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

        async def fetch_entities():
            print('Loading record information.', end='', flush=True)
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
                    rq.continuationToken = token or rq.continuationToken
                    rs = api.communicate_rest(params, rq, 'enterprise/get_preliminary_compliance_data',
                                              rs_type=enterprise_pb2.PreliminaryComplianceDataResponse)
                    has_more = rs.hasMore
                    token = rs.continuationToken
                    await asyncio.gather(*[save_data(*to_storage_types(ud, name_by_id)) for ud in rs.auditUserData])

        async def save_data(user, records, links):
            await store.async_put_prelim_data([user], records, links)
            print('.', end='', flush=True)

        store.clear_non_aging_data()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(fetch_entities())
        print('.')
        store.set_prelim_data_updated()

    enterprise_id = enterprise_id or next(((x['node_id'] >> 32) for x in params.enterprise['nodes']), 0)
    path = os.path.dirname(os.path.abspath(params.config_filename or '1'))
    database_name = os.path.join(path, f'sox_{enterprise_id}.db')
    tree_key = params.enterprise['unencrypted_tree_key']
    ecc_key = utils.base64_url_decode(params.enterprise['keys']['ecc_encrypted_private_key'])
    ecc_key = crypto.decrypt_aes_v2(ecc_key, tree_key)
    key = crypto.load_ec_private_key(ecc_key)
    storage = sqlite_storage.SqliteSoxStorage(
        get_connection=lambda: sqlite3.connect(database_name), owner=params.user, database_name=database_name
    )
    last_updated = storage.last_prelim_data_update
    refresh_data = rebuild or not last_updated or min_updated > last_updated
    if refresh_data and not cache_only:
        user_lookup = {x['enterprise_user_id']: x['username'] for x in params.enterprise['users']}
        sync_down(user_lookup, storage)
    return sox_data.SoxData(ec_private_key=key, storage=storage)


def get_compliance_data(params, node_id, enterprise_id=0, rebuild=False, min_updated=0, no_cache=False):
    def sync_down(sdata, node_uid, user_node_id_lookup):
        users_uids = [int(uid) for uid in sdata.get_users().keys()]
        record_uids_raw = [rec.record_uid_bytes for rec in sdata.get_records().values()]
        anon_id = 0

        def sync_all():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(start_sync())

        async def start_sync():
            limit = asyncio.Semaphore(10)
            max_len = API_SOX_REQUEST_USER_LIMIT
            total_ruids = len(record_uids_raw)
            ruid_chunks = [record_uids_raw[x:x + max_len] for x in range(0, total_ruids, max_len)]
            tasks = [sync_chunk(chunk, users_uids, limit) for chunk in ruid_chunks]
            await asyncio.gather(*tasks)

        async def sync_chunk(chunk, uuids, limit):
            async with limit:
                rs = await fetch_response(raw_ruids=chunk, user_uids=uuids, limit=limit)
                await save_response(rs)

        async def fetch_response(raw_ruids, user_uids, limit=10):
            rq = enterprise_pb2.ComplianceReportRequest()
            rq.saveReport = False
            rq.reportName = f'Compliance Report on {datetime.datetime.now()}'
            report_run = rq.complianceReportRun
            report_run.users.extend(user_uids)
            report_run.records.extend(raw_ruids)
            caf = report_run.reportCriteriaAndFilter
            caf.nodeId = node_uid
            print('.', end='', flush=True)
            endpoint = 'enterprise/run_compliance_report'
            return api.communicate_rest(params, rq, endpoint, rs_type=enterprise_pb2.ComplianceReportResponse)

        async def save_response(rs):
            def hash_anon_ids(response):
                # create new user uid for each anonymous user (uid >> 32 == 0)
                anon_ids = dict()
                nonlocal anon_id
                anon_id += API_SOX_REQUEST_USER_LIMIT
                for up in rs.userProfiles:
                    user_id = up.enterpriseUserId
                    if not user_id >> 32:
                        new_id = user_id + anon_id
                        anon_ids[user_id] = new_id
                        up.enterpriseUserId = new_id
                for ur in rs.userRecords:
                    user_id = ur.enterpriseUserId
                    ur.enterpriseUserId = anon_ids.get(user_id, user_id)
                for folder in rs.sharedFolderUsers:
                    for idx, user_id in enumerate(folder.enterpriseUserIds):
                        folder.enterpriseUserIds[idx] = anon_ids.get(user_id, user_id)
                return response

            rs = hash_anon_ids(rs)
            tasks = [
                sync_users(rs.userProfiles),
                sync_records(rs.auditRecords),
                sync_teams(rs.auditTeams),
                sync_shared_folders_records(rs.sharedFolderRecords),
                sync_shared_folder_users(rs.sharedFolderUsers),
                sync_shared_folder_teams(rs.sharedFolderTeams),
                sync_record_permissions(rs.sharedFolderRecords, rs.userRecords),
                sync_team_users(rs.auditTeamUsers)
            ]
            await asyncio.gather(*tasks)

        async def sync_users(user_profiles):
            entities = []
            for up in user_profiles:
                entity = sdata.storage.users.get_entity(up.enterpriseUserId) or StorageUser()
                entity.user_uid = entity.user_uid or up.enterpriseUserId
                entity.email = entity.email or up.email
                entity.job_title = entity.job_title or up.jobTitle
                entity.full_name = entity.full_name or up.fullName
                user_node = user_node_id_lookup.get(up.enterpriseUserId)
                entity.node_id = user_node
                entities.append(entity)
            await sdata.storage.users.async_put_entities(entities)
            print('.', end='', flush=True)

        async def sync_teams(audit_teams):
            entities = []
            for team in audit_teams:
                team_uid = utils.base64_url_encode(team.teamUid)
                entity = sdata.storage.teams.get_entity(team_uid) or StorageTeam()
                entity.team_uid = team_uid
                entity.team_name = team.teamName
                entities.append(entity)
            await sdata.storage.teams.async_put_entities(entities)
            print('.', end='', flush=True)

        async def sync_team_users(audit_team_users):
            links = []
            for team in audit_team_users:
                team_uid = utils.base64_url_encode(team.teamUid)
                links.extend([StorageTeamUserLink(team_uid, user_uid) for user_uid in team.enterpriseUserIds])
            await sdata.storage.get_team_user_links().async_put_links(links)
            print('.', end='', flush=True)

        async def sync_shared_folders_records(sf_records):
            links = []
            for folder in sf_records:
                folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
                for rp in folder.recordPermissions:
                    record_uid = utils.base64_url_encode(rp.recordUid)
                    link = StorageSharedFolderRecordLink(folder_uid, record_uid, rp.permissionBits)
                    links.append(link)
            await sdata.storage.get_sf_record_links().async_put_links(links)
            print('.', end='', flush=True)

        async def sync_record_permissions(sf_records, user_records):
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
            await sdata.storage.get_record_permissions().async_put_links(links)
            print('.', end='', flush=True)

        async def sync_shared_folder_users(sf_users):
            links = []
            for folder in sf_users:
                folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
                links.extend([StorageSharedFolderUserLink(folder_uid, uuid) for uuid in folder.enterpriseUserIds])
            await sdata.storage.get_sf_user_links().async_put_links(links)
            print('.', end='', flush=True)

        async def sync_shared_folder_teams(sf_teams):
            links = []
            for folder in sf_teams:
                folder_uid = utils.base64_url_encode(folder.sharedFolderUid)
                for tuid in folder.teamUids:
                    team_uid = utils.base64_url_encode(tuid)
                    links.append(StorageSharedFolderTeamLink(folder_uid, team_uid))
            await sdata.storage.get_sf_team_links().async_put_links(links)
            print('.', end='', flush=True)

        async def sync_records(records):
            entities = []
            for record in records:
                rec_uid = utils.base64_url_encode(record.recordUid)
                entity = sdata.storage.records.get_entity(rec_uid)
                entity.in_trash = record.inTrash
                entity.has_attachments = record.hasAttachments
                entities.append(entity)
            await sdata.storage.records.async_put_entities(entities)
            print('.', end='', flush=True)

        print('Loading compliance data.', end='', flush=True)
        sync_all()
        sdata.storage.set_compliance_data_updated()

    sd = get_prelim_data(params, enterprise_id, rebuild=rebuild, min_updated=min_updated, cache_only=not min_updated)
    last_compliance_data_update = sd.storage.last_compliance_data_update
    refresh_data = rebuild or min_updated > last_compliance_data_update
    if refresh_data:
        enterprise_users = params.enterprise.get('users')
        user_node_ids = {e_user.get('enterprise_user_id'): e_user.get('node_id') for e_user in enterprise_users}
        sync_down(sd, node_id, user_node_id_lookup=user_node_ids)
    rebuild_task = sox_data.RebuildTask(is_full_sync=False, load_compliance_data=True)
    sd.rebuild_data(rebuild_task, no_cache=no_cache)
    return sd
