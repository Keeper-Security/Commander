#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
import logging
from typing import Any, List, Dict, Optional

import google

from . import api, utils, crypto, convert_keys
from . import keeper_drive_sync
from .display import bcolors, Spinner
from .params import KeeperParams, RecordOwner
from .proto import SyncDown_pb2, record_pb2, client_pb2, breachwatch_pb2, folder_pb2
from .subfolder import RootFolderNode, UserFolderNode, SharedFolderNode, SharedFolderFolderNode, BaseFolderNode
from .vault import KeeperRecord


def sync_down(params, record_types=False):   # type: (KeeperParams, bool) -> None
    """Sync full or partial data down to the client"""

    params.sync_data = False
    token = params.sync_down_token

    # Use spinner animation for full sync (only in interactive mode, not batch/automation)
    spinner = None
    if not token and not params.batch_mode:
        spinner = Spinner('Syncing...')
        spinner.start()

    for record in params.record_cache.values():
        if 'shares' in record:
            del record['shares']

    def delete_record_key(rec_uid):
        if rec_uid in params.record_cache:
            record = params.record_cache[rec_uid]
            if 'record_key_unencrypted' in record:
                del record['record_key_unencrypted']
                if 'data_unencrypted' in record:
                    del record['data_unencrypted']
                if 'extra_unencrypted' in record:
                    del record['extra_unencrypted']

    def delete_shared_folder_key(sf_uid):
        if sf_uid in params.shared_folder_cache:
            shared_folder = params.shared_folder_cache[sf_uid]
            if 'shared_folder_key_unencrypted' in shared_folder:
                del shared_folder['shared_folder_key_unencrypted']
                if 'records' in shared_folder:
                    for sfr in shared_folder['records']:
                        record_uid = sfr['record_uid']
                        if record_uid not in params.meta_data_cache:
                            delete_record_key(record_uid)

    def delete_team_key(team_uid):
        if team_uid in params.team_cache:
            team = params.team_cache[team_uid]
            if 'team_key_unencrypted' in team:
                del team['team_key_unencrypted']
                if 'shared_folder_keys' in team:
                    for sfk in team['shared_folder_keys']:
                        delete_shared_folder_key(sfk['shared_folder_uid'])

    params.available_team_cache = None

    resp_bw_recs = []            # type: List[SyncDown_pb2.BreachWatchRecord]
    resp_sec_data_recs = []      # type: List[SyncDown_pb2.BreachWatchSecurityData]
    resp_sec_scores = []         # type: List[SyncDown_pb2.SecurityScoreData]
    record_rotation_items = []   # type: List[record_pb2.RecordRotation]
    kd_acc = keeper_drive_sync.create_accumulator()
    
    request = SyncDown_pb2.SyncDownRequest()
    revision = params.revision
    full_sync = False
    done = False
    while not done:
        if token:
            request.continuationToken = token
        response = api.communicate_rest(params, request, 'vault/sync_down', rs_type=SyncDown_pb2.SyncDownResponse)
        done = not response.hasMore
        token = response.continuationToken
        if response.cacheStatus == SyncDown_pb2.CLEAR:
            full_sync = True
            params.record_cache.clear()
            params.record_rotation_cache.clear()
            params.meta_data_cache.clear()
            params.shared_folder_cache.clear()
            params.team_cache.clear()
            params.available_team_cache = None
            params.subfolder_cache.clear()
            params.subfolder_record_cache.clear()
            params.record_history.clear()
            params.record_owner_cache.clear()
            params.breach_watch_security_data.clear()
            params.breach_watch_records.clear()
            params.security_score_data.clear()
            keeper_drive_sync.clear_caches(params)

        if len(response.removedRecords) > 0:
            logging.debug('Processing removed records')
            for record_uid_bytes in response.removedRecords:
                record_uid = utils.base64_url_encode(record_uid_bytes)
                # remove BW record data
                if record_uid in params.breach_watch_records:
                    del params.breach_watch_records[record_uid]
                # remove associated security data
                if record_uid in params.breach_watch_security_data:
                    del params.breach_watch_security_data[record_uid]
                # remove associated security score data
                params.security_score_data.pop(record_uid, None)
                # remove record metadata
                if record_uid in params.meta_data_cache:
                    del params.meta_data_cache[record_uid]
                # delete record key
                delete_record_key(record_uid)
                # remove record from user folders
                for folder_uid in params.subfolder_record_cache:
                    if record_uid in params.subfolder_record_cache[folder_uid]:
                        if folder_uid in params.subfolder_cache:
                            folder = params.subfolder_cache[folder_uid]
                            if folder.get('type') == 'user_folder':
                                params.subfolder_record_cache[folder_uid].remove(record_uid)
                        elif folder_uid == '':
                            params.subfolder_record_cache[folder_uid].remove(record_uid)

        if len(response.removedTeams) > 0:
            logging.debug('Processing removed teams')
            for team_uid_bytes in response.removedTeams:
                team_uid = utils.base64_url_encode(team_uid_bytes)
                delete_team_key(team_uid)
                # remove team from shared folder
                for shared_folder_uid in params.shared_folder_cache:
                    shared_folder = params.shared_folder_cache[shared_folder_uid]
                    if 'teams' in shared_folder:
                        shared_folder['teams'] = [x for x in shared_folder['teams'] if x['team_uid'] != team_uid]
                if team_uid in params.team_cache:
                    del params.team_cache[team_uid]

        if len(response.removedSharedFolders) > 0:
            logging.debug('Processing removed shared folders')
            for sf_uid_bytes in response.removedSharedFolders:
                sf_uid = utils.base64_url_encode(sf_uid_bytes)
                if sf_uid in params.shared_folder_cache:
                    delete_shared_folder_key(sf_uid)
                    shared_folder = params.shared_folder_cache[sf_uid]
                    if 'shared_folder_key' in shared_folder:
                        del shared_folder['shared_folder_key']
                    if 'key_type' in shared_folder:
                        del shared_folder['key_type']
                    if 'users' in shared_folder:
                        shared_folder['users'] = [x for x in shared_folder['users'] if x['username'] != params.user]
                    if 'records' in shared_folder:
                        for r in shared_folder['records']:
                            if 'record_uid' in r:
                                delete_record_key(r['record_uid'])

        if len(response.removedRecordLinks) > 0:
            logging.debug('Processing removed record links')
            for link in response.removedRecordLinks:
                record_uid = utils.base64_url_encode(link.childRecordUid)
                if record_uid in params.record_cache:
                    delete_record_key(record_uid)
                    parents = params.record_link_cache[record_uid]
                    parent_uid = utils.base64_url_encode(link.parentRecordUid)
                    if parent_uid in parents:
                        del parents[parent_uid]

        if len(response.removedUserFolders) > 0:
            for f_uid_bytes in response.removedUserFolders:
                f_uid = utils.base64_url_encode(f_uid_bytes)
                if f_uid in params.subfolder_cache:
                    del params.subfolder_cache[f_uid]
                if f_uid in params.subfolder_record_cache:
                    del params.subfolder_record_cache[f_uid]

        if len(response.removedSharedFolderFolders) > 0:
            for sffr in response.removedSharedFolderFolders:
                f_uid_bytes = sffr.folderUid or sffr.sharedFolderUid
                f_uid = utils.base64_url_encode(f_uid_bytes)
                if f_uid in params.subfolder_cache:
                    del params.subfolder_cache[f_uid]
                if f_uid in params.subfolder_record_cache:
                    del params.subfolder_record_cache[f_uid]

        if len(response.removedUserFolderSharedFolders) > 0:
            for ufsfr in response.removedUserFolderSharedFolders:
                f_uid = utils.base64_url_encode(ufsfr.sharedFolderUid)
                if f_uid in params.subfolder_cache:
                    del params.subfolder_cache[f_uid]
                if f_uid in params.subfolder_record_cache:
                    del params.subfolder_record_cache[f_uid]

        if len(response.removedUserFolderRecords) > 0:
            for ufrr in response.removedUserFolderRecords:
                f_uid = utils.base64_url_encode(ufrr.folderUid) if ufrr.folderUid else ''
                if f_uid in params.subfolder_record_cache:
                    rs = params.subfolder_record_cache[f_uid]
                    r_uid = utils.base64_url_encode(ufrr.recordUid)
                    if r_uid in rs:
                        rs.remove(r_uid)

        if len(response.removedSharedFolderFolderRecords) > 0:
            for sfrr in response.removedSharedFolderFolderRecords:
                f_uid = utils.base64_url_encode(sfrr.folderUid or sfrr.sharedFolderUid)
                if f_uid in params.subfolder_record_cache:
                    rs = params.subfolder_record_cache[f_uid]
                    r_uid = utils.base64_url_encode(sfrr.recordUid)
                    if r_uid in rs:
                        rs.remove(r_uid)

        if len(response.recordLinks) > 0:
            for rl in response.recordLinks:
                child_uid = utils.base64_url_encode(rl.childRecordUid)
                parents = params.record_link_cache.get(child_uid)
                if parents is None:
                    parents = {}
                    params.record_link_cache[child_uid] = parents
                parent_uid = utils.base64_url_encode(rl.parentRecordUid)
                parents[parent_uid] = {
                    'child_uid': child_uid,
                    'parent_uid': parent_uid,
                    'record_key': utils.base64_url_encode(rl.recordKey)
                }

        if len(response.recordMetaData) > 0:
            logging.debug('Processing record_meta_data')
            for rmd in response.recordMetaData:
                meta_data = {
                    'record_uid': utils.base64_url_encode(rmd.recordUid),
                    'owner': rmd.owner,
                    'can_edit': rmd.canEdit,
                    'can_share': rmd.canShare,
                    'record_key': utils.base64_url_encode(rmd.recordKey),
                    'record_key_type': rmd.recordKeyType,
                    'owner_account_uid': utils.base64_url_encode(rmd.ownerAccountUid or params.account_uid_bytes),
                }  # type: dict
                if rmd.expiration > 0:
                    meta_data['expiration'] = rmd.expiration
                record_uid = meta_data['record_uid']
                params.meta_data_cache[record_uid] = meta_data
                params.record_owner_cache[record_uid] = RecordOwner(meta_data['owner'], meta_data['owner_account_uid'])

        if len(response.records) > 0:
            logging.debug('Processing records')
            r = max((x.revision for x in response.records))
            if r > revision:
                revision = r

            def convert_record(r):
                o = {
                    'record_uid': utils.base64_url_encode(r.recordUid),
                    'revision': r.revision,
                    'version': r.version,
                    'shared': r.shared,
                    'client_modified_time': r.clientModifiedTime,
                    'data': utils.base64_url_encode(r.data),
                    'extra': utils.base64_url_encode(r.extra),
                    'file_size': r.fileSize,
                    'thumbnail_size': r.thumbnailSize,
                }
                if r.udata:
                    o['udata'] = json.loads(r.udata)
                return o

            for r in response.records:
                record = convert_record(r)
                params.record_cache[record['record_uid']] = record

        if len(response.nonSharedData) > 0:
            for nsd in response.nonSharedData:
                record_uid = utils.base64_url_encode(nsd.recordUid)
                params.non_shared_data_cache[record_uid] = {
                    'record_uid': record_uid,
                    'data': utils.base64_url_encode(nsd.data),
                }

        if len(response.teams) > 0:
            def assign_team(t, team):
                team['name'] = t.name
                team['team_key'] = utils.base64_url_encode(t.teamKey)
                team['team_key_type'] = t.teamKeyType
                team['restrict_edit'] = t.restrictEdit
                team['restrict_share'] = t.restrictShare
                team['restrict_view'] = t.restrictView
                if len(t.teamEccPrivateKey) > 0:
                    team['team_ec_private_key'] = utils.base64_url_encode(t.teamEccPrivateKey)
                if len(t.teamPrivateKey) > 0:
                    team['team_private_key'] = utils.base64_url_encode(t.teamPrivateKey)

            for t in response.teams:
                team_uid = utils.base64_url_encode(t.teamUid)
                team = params.team_cache.get(team_uid)
                if team is None:
                    team = {'team_uid': team_uid}
                    params.team_cache[team_uid] = team
                assign_team(t, team)

                if len(t.removedSharedFolders) > 0 and 'shared_folder_keys' in team:
                    sf_keys = team['shared_folder_keys']
                    if isinstance(sf_keys, list):
                        for rsf in t.removedSharedFolders:
                            sf_uid = utils.base64_url_encode(rsf)
                            delete_shared_folder_key(sf_uid)
                            pos = next((i for i, x in enumerate(sf_keys) if x['shared_folder_uid'] == sf_uid), -1)
                            if pos >= 0:
                                del sf_keys[pos]

                if len(t.sharedFolderKeys) > 0:
                    if 'shared_folder_keys' not in team:
                        team['shared_folder_keys'] = []
                    sf_keys = team['shared_folder_keys']  # type: List[Dict]
                    for sfk in t.sharedFolderKeys:
                        sf_uid = utils.base64_url_encode(sfk.sharedFolderUid)
                        sf_key = next((x for x in sf_keys if x['shared_folder_uid'] == sf_uid), None)
                        if sf_key is None:
                            sf_key = {
                                'shared_folder_uid': sf_uid
                            }
                            sf_keys.append(sf_key)
                        sf_key['shared_folder_key'] = utils.base64_url_encode(sfk.sharedFolderKey)
                        sf_key['key_type'] = sfk.keyType

        if len(response.sharedFolders) > 0:
            logging.debug('Processing shared_folders')
            r = max((x.revision for x in response.sharedFolders))
            if r > revision:
                revision = r

            def assign_shared_folder(sf, o):
                o['revision'] = sf.revision
                o['name'] = utils.base64_url_encode(sf.name)
                o['data'] = utils.base64_url_encode(sf.data)
                o['default_manage_records'] = sf.defaultManageRecords
                o['default_manage_users'] = sf.defaultManageUsers
                o['default_can_edit'] = sf.defaultCanEdit
                o['default_can_share'] = sf.defaultCanReshare
                o['owner_account_uid'] = utils.base64_url_encode(sf.ownerAccountUid or params.account_uid_bytes)

            for p_sf in response.sharedFolders:
                shared_folder_uid = utils.base64_url_encode(p_sf.sharedFolderUid)
                shared_folder = params.shared_folder_cache.get(shared_folder_uid)
                if shared_folder is None:
                    shared_folder = {
                        'shared_folder_uid': shared_folder_uid
                    }
                    params.shared_folder_cache[shared_folder_uid] = shared_folder
                else:
                    if p_sf.cacheStatus == SyncDown_pb2.CLEAR:
                        if 'users' in shared_folder:
                            del shared_folder['users']
                        if 'teams' in shared_folder:
                            del shared_folder['teams']
                        if 'records' in shared_folder:
                            del shared_folder['records']
                    if 'shared_folder_key_unencrypted' in shared_folder:
                        del shared_folder['shared_folder_key_unencrypted']
                    if 'data_unencrypted' in shared_folder:
                        del shared_folder['data_unencrypted']
                assign_shared_folder(p_sf, shared_folder)

                if p_sf.sharedFolderKey:
                    shared_folder['shared_folder_key'] = utils.base64_url_encode(p_sf.sharedFolderKey)
                    shared_folder['key_type'] = p_sf.keyType
                else:
                    if 'shared_folder_key' in shared_folder:
                        del shared_folder['shared_folder_key']
                    if 'key_type' in shared_folder:
                        del shared_folder['key_type']

        if len(response.sharedFolderUsers) > 0:
            for sfu in response.sharedFolderUsers:
                shared_folder_uid = utils.base64_url_encode(sfu.sharedFolderUid)
                account_uid = utils.base64_url_encode(sfu.accountUid) if sfu.accountUid else utils.base64_url_encode(params.account_uid_bytes)
                if shared_folder_uid in params.shared_folder_cache:
                    sf = params.shared_folder_cache[shared_folder_uid]
                    if 'users' not in sf:
                        sf['users'] = []
                    sf_user = next((x for x in sf['users'] if x['account_uid'] == account_uid), None)
                    if sf_user is None:
                        sf_user = {
                            'username': sfu.username,
                            'account_uid': account_uid
                        }
                        sf['users'].append(sf_user)
                    sf_user['manage_records'] = sfu.manageRecords
                    sf_user['manage_users'] = sfu.manageUsers
                    if sfu.expiration > 0:
                        sf_user['expiration'] = sfu.expiration

        if len(response.sharedFolderTeams) > 0:
            for sft in response.sharedFolderTeams:
                shared_folder_uid = utils.base64_url_encode(sft.sharedFolderUid)
                if shared_folder_uid in params.shared_folder_cache:
                    sf = params.shared_folder_cache[shared_folder_uid]
                    if 'teams' not in sf:
                        sf['teams'] = []
                    team_uid = utils.base64_url_encode(sft.teamUid)
                    sf_team = next((x for x in sf['teams'] if x['team_uid'] == team_uid), None)
                    if sf_team is None:
                        sf_team = {
                            'team_uid': team_uid
                        }
                        sf['teams'].append(sf_team)
                    sf_team['name'] = sft.name if hasattr(sft, 'name') else ''
                    sf_team['manage_records'] = sft.manageRecords
                    sf_team['manage_users'] = sft.manageUsers
                    if sft.expiration > 0:
                        sf_team['expiration'] = sft.expiration

        if len(response.sharedFolderRecords) > 0:
            def assign_shared_folder_record(sfr, sf_record):
                sf_record['record_key'] = utils.base64_url_encode(sfr.recordKey)
                sf_record['can_share'] = sfr.canShare
                sf_record['can_edit'] = sfr.canEdit
                sf_record['owner'] = sfr.owner
                sf_record['owner_account_uid'] = utils.base64_url_encode(sfr.ownerAccountUid or params.account_uid_bytes)
                if sfr.expiration > 0:
                    sf_record['expiration'] = sfr.expiration

            for sfr in response.sharedFolderRecords:
                shared_folder_uid = utils.base64_url_encode(sfr.sharedFolderUid)
                if shared_folder_uid in params.shared_folder_cache:
                    sf = params.shared_folder_cache[shared_folder_uid]
                    if 'records' not in sf:
                        sf['records'] = []
                    record_uid = utils.base64_url_encode(sfr.recordUid)
                    sf_record = next((x for x in sf['records'] if x['record_uid'] == record_uid), None)  # type: Dict
                    if sf_record is None:
                        sf_record = {
                            'record_uid': record_uid
                        }
                        sf['records'].append(sf_record)
                    assign_shared_folder_record(sfr, sf_record)
                    params.record_owner_cache[record_uid] = \
                        RecordOwner(sf_record['owner'], sf_record['owner_account_uid'])

        if len(response.removedSharedFolderRecords) > 0:
            for rsfr in response.removedSharedFolderRecords:
                shared_folder_uid = utils.base64_url_encode(rsfr.sharedFolderUid)
                record_uid = utils.base64_url_encode(rsfr.recordUid)
                delete_record_key(record_uid)
                if shared_folder_uid in params.shared_folder_cache:
                    sf = params.shared_folder_cache[shared_folder_uid]  # type: dict
                    if 'records' in sf:
                        pos = next((i for i, x in enumerate(sf['records']) if x['record_uid'] == record_uid), -1)
                        if pos >= 0:
                            del sf['records'][pos]

        if len(response.removedSharedFolderUsers) > 0:
            for rsfu in response.removedSharedFolderUsers:
                shared_folder_uid = utils.base64_url_encode(rsfu.sharedFolderUid)
                if shared_folder_uid in params.shared_folder_cache:
                    sf = params.shared_folder_cache[shared_folder_uid]
                    if 'users' in sf:
                        if len(rsfu.username) > 0:
                            pos = next((i for i, x in enumerate(sf['users']) if x['username'] == rsfu.username), -1)
                        else:
                            account_uid = utils.base64_url_encode(rsfu.accountUid)
                            pos = next((i for i, x in enumerate(sf['users']) if x['account_uid'] == account_uid), -1)
                        if pos >= 0:
                            del sf['users'][pos]

        if len(response.removedSharedFolderTeams) > 0:
            for rsft in response.removedSharedFolderTeams:
                shared_folder_uid = utils.base64_url_encode(rsft.sharedFolderUid)
                team_uid = utils.base64_url_encode(rsft.teamUid)
                if shared_folder_uid in params.shared_folder_cache:
                    sf = params.shared_folder_cache[shared_folder_uid]
                    if 'teams' in sf:
                        pos = next((i for i, x in enumerate(sf['teams']) if x['team_uid'] == team_uid), -1)
                        if pos >= 0:
                            del sf['teams'][pos]

        if len(response.userFolders) > 0:
            def convert_user_folder(uf):
                o = {
                    'folder_uid': utils.base64_url_encode(uf.folderUid),
                    'user_folder_key': utils.base64_url_encode(uf.userFolderKey),
                    'key_type': uf.keyType,
                    'revision': uf.revision,
                    'type': 'user_folder',
                    'data': utils.base64_url_encode(uf.data),
                }
                if uf.parentUid:
                    o['parent_uid'] = utils.base64_url_encode(uf.parentUid)
                return o

            for uf in response.userFolders:
                user_folder = convert_user_folder(uf)
                params.subfolder_cache[user_folder['folder_uid']] = user_folder

        if len(response.userFolderRecords) > 0:
            for ufr in response.userFolderRecords:
                fuid = utils.base64_url_encode(ufr.folderUid) if ufr.folderUid else ''
                if fuid not in params.subfolder_record_cache:
                    params.subfolder_record_cache[fuid] = set()
                record_uid = utils.base64_url_encode(ufr.recordUid)
                params.subfolder_record_cache[fuid].add(record_uid)

        if len(response.userFolderSharedFolders) > 0:
            def convert_user_folder_shared_folder(ufsf):
                o = {
                    'shared_folder_uid': utils.base64_url_encode(ufsf.sharedFolderUid),
                    'revision': ufsf.revision,
                    'type': 'shared_folder'
                }
                if ufsf.folderUid:
                    is_fake_uid = ufsf.folderUid.endswith(b'\0\0\0\0\0\0\0\0\0\0') or \
                                  ufsf.folderUid.startswith(b'\0\0\0\0\0\0\0\0\0\0')
                    if not is_fake_uid:
                        o['folder_uid'] = utils.base64_url_encode(ufsf.folderUid)
                return o

            for ufsf in response.userFolderSharedFolders:
                uf_sf = convert_user_folder_shared_folder(ufsf)
                sf_uid = uf_sf['shared_folder_uid']
                params.subfolder_cache[sf_uid] = uf_sf

        if len(response.sharedFolderFolders) > 0:
            for p_sff in response.sharedFolderFolders:
                sff = {
                    'shared_folder_uid': utils.base64_url_encode(p_sff.sharedFolderUid),
                    'folder_uid': utils.base64_url_encode(p_sff.folderUid),
                    'revision': p_sff.revision,
                    'shared_folder_folder_key': utils.base64_url_encode(p_sff.sharedFolderFolderKey),
                    'key_type': p_sff.keyType,
                    'type': 'shared_folder_folder',
                    'data': utils.base64_url_encode(p_sff.data),
                }
                if p_sff.parentUid:
                    sff['parent_uid'] = utils.base64_url_encode(p_sff.parentUid)
                params.subfolder_cache[sff['folder_uid']] = sff

        if len(response.sharedFolderFolderRecords) > 0:
            for sffr in response.sharedFolderFolderRecords:
                key = utils.base64_url_encode(sffr.folderUid or sffr.sharedFolderUid)
                if key not in params.subfolder_record_cache:
                    params.subfolder_record_cache[key] = set()
                record_uid = utils.base64_url_encode(sffr.recordUid)
                params.subfolder_record_cache[key].add(record_uid)

        if len(response.sharingChanges) > 0:
            for sharing_change in response.sharingChanges:
                record_uid = utils.base64_url_encode(sharing_change.recordUid)
                if record_uid in params.record_cache:
                    record = params.record_cache[record_uid]
                    record['shared'] = sharing_change.shared

        if len(response.shareInvitations) > 0:
            params.pending_share_requests.update((x.username for x in response.shareInvitations))

        if len(response.breachWatchRecords) > 0:
            resp_bw_recs.extend(response.breachWatchRecords)

        if len(response.breachWatchSecurityData) > 0:
            resp_sec_data_recs.extend(response.breachWatchSecurityData)

        if len(response.securityScoreData) > 0:
            resp_sec_scores.extend(response.securityScoreData)

        # Collect Keeper Drive atomic sync objects
        keeper_drive_sync.collect_from_response(
            kd_acc, response, resp_bw_recs, resp_sec_data_recs, resp_sec_scores, record_rotation_items
        )

        if len(response.removedUsers) > 0:
            for a_uid in response.removedUsers:
                account_uid = utils.base64_url_encode(a_uid)
                if account_uid in params.user_cache:
                    del params.user_cache[account_uid]

        if len(response.users) > 0:
            for user in response.users:
                account_uid = utils.base64_url_encode(user.accountUid)
                params.user_cache[account_uid] = user.username
        account_uid = utils.base64_url_encode(params.account_uid_bytes)
        if account_uid not in params.user_cache:
            params.user_cache[account_uid] = params.user

        if len(response.recordRotations) > 0:
            record_rotation_items.extend(response.recordRotations)

        params.sync_down_token = response.continuationToken

    params.revision = revision

    keeper_drive_sync.process(params, kd_acc)

    for sf in params.shared_folder_cache.values():
        owner = sf.get('owner_username')
        if not owner:
            account_uid = sf.get('owner_account_uid')
            if account_uid and account_uid in params.user_cache:
                sf['owner_username'] = params.user_cache[account_uid]

        if 'users' in sf:
            for u in sf['users']:
                username = u.get('username')
                if not username:
                    account_uid = u['account_uid']
                    if account_uid and account_uid in params.user_cache:
                        u['username'] = params.user_cache[account_uid]

        if 'records' in sf:
            for r in sf['records']:
                owner = r.get('owner_username')
                if not owner:
                    account_uid = r['owner_account_uid']
                    if account_uid and account_uid in params.user_cache:
                        r['owner_username'] = params.user_cache[account_uid]

    for md in params.meta_data_cache.values():
        owner = md.get('owner_username')
        if not owner:
            account_uid = md.get('owner_account_uid')
            if account_uid and account_uid in params.user_cache:
                md['owner_username'] = params.user_cache[account_uid]

    if params.breach_watch_records:
        for bwr in params.breach_watch_records.values():
            scanned_by = bwr.get('scanned_by')
            if not scanned_by:
                account_uid = bwr.get('scanned_by_account_uid')
                if account_uid and account_uid in params.user_cache:
                    bwr['scanned_by'] = params.user_cache[account_uid]

    to_delete = set()

    logging.debug('Decrypting meta data keys')
    for record_uid, meta_data in params.meta_data_cache.items():
        if 'record_key_unencrypted' in meta_data:
            continue
        record_key = None
        try:
            if 'record_key' not in meta_data:
                # old record that doesn't have a record key so make one
                logging.debug('...no record key.  creating...')
                # store as b64 encoded string
                # note: decode() converts bytestream (b'') to string
                # note2: remove == from the end
                record_key = utils.generate_aes_key()
                record_key_encrypted = crypto.encrypt_aes_v1(record_key, params.data_key)
                meta_data['record_key'] = utils.base64_url_encode(record_key_encrypted)
                meta_data['record_key_type'] = 1
                # temporary flag for decryption routine below
                meta_data['old_record_flag'] = True
                meta_data['is_converted_record_type'] = True
            else:
                record_key_encrypted = utils.base64_url_decode(meta_data['record_key'])
                key_type = meta_data['record_key_type']
                if key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                    record_key = crypto.decrypt_aes_v1(record_key_encrypted, params.data_key)
                elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                    record_key = crypto.decrypt_rsa(record_key_encrypted, params.rsa_key2)
                elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                    record_key = crypto.decrypt_aes_v2(record_key_encrypted, params.data_key)
                elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                    record_key = crypto.decrypt_ec(record_key_encrypted, params.ecc_key)
                else:
                    raise Exception('Unsupported key type')
        except Exception as e:
            logging.debug('Record %s meta data decryption error: %s', record_uid, e)

        if record_key and len(record_key) == 32:
            meta_data['record_key_unencrypted'] = record_key
        else:
            to_delete.add(record_uid)

    for record_uid in to_delete:
        del params.meta_data_cache[record_uid]
    to_delete.clear()

    logging.debug('Decrypting team keys')
    for team_uid, team in params.team_cache.items():
        if 'team_key_unencrypted' not in team:
            try:
                encrypted_team_key = utils.base64_url_decode(team['team_key'])
                key_type = team['team_key_type']
                if key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                    team_key = crypto.decrypt_aes_v1(encrypted_team_key, params.data_key)
                elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                    team_key = crypto.decrypt_rsa(encrypted_team_key, params.rsa_key2)
                elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                    team_key = crypto.decrypt_aes_v2(encrypted_team_key, params.data_key)
                elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                    team_key = crypto.decrypt_ec(encrypted_team_key, params.ecc_key)
                else:
                    raise Exception('Unsupported key type')
                team['team_key_unencrypted'] = team_key
                if 'team_private_key' in team:
                    encrypted_team_private_key = utils.base64_url_decode(team['team_private_key'])
                    team['team_private_key_unencrypted'] = crypto.decrypt_aes_v1(encrypted_team_private_key, team_key)
                if 'team_ec_private_key' in team:
                    encrypted_team_private_key = utils.base64_url_decode(team['team_ec_private_key'])
                    team['team_ec_private_key_unencrypted'] = crypto.decrypt_aes_v2(encrypted_team_private_key, team_key)
            except Exception as e:
                logging.info('Could not decrypt team %s key: %s', team_uid, e)
        if 'team_key_unencrypted' in team:
            team_key = team['team_key_unencrypted']
            team_uid = team['team_uid']
            if 'shared_folder_keys' in team:
                for sf_key in team['shared_folder_keys']:
                    shared_folder_uid = sf_key['shared_folder_uid']
                    if 'shared_folder_key_unencrypted' not in sf_key:
                        encrypted_sf_key = utils.base64_url_decode(sf_key['shared_folder_key'])
                        try:
                            key_type = sf_key['key_type']
                            decrypted_sf_key = None
                            if key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                                decrypted_sf_key = crypto.decrypt_aes_v1(encrypted_sf_key, team_key)
                            elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                                if 'team_private_key_unencrypted' in team:
                                    team_private_key = team['team_private_key_unencrypted']
                                    team_pk = crypto.load_rsa_private_key(team_private_key)
                                    decrypted_sf_key = crypto.decrypt_rsa(encrypted_sf_key, team_pk)
                            elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                                decrypted_sf_key = crypto.decrypt_aes_v2(encrypted_sf_key, team_key)
                            elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                                if 'team_ec_private_key_unencrypted' in team:
                                    team_private_key = team['team_ec_private_key_unencrypted']
                                    team_pk = crypto.load_ec_private_key(team_private_key)
                                    decrypted_sf_key = crypto.decrypt_ec(encrypted_sf_key, team_pk)
                            else:
                                raise Exception('Unsupported key type')
                            if decrypted_sf_key:
                                sf_key['shared_folder_key_unencrypted'] = decrypted_sf_key
                            else:
                                logging.debug('Cannot decrypt team\' shared folder key: team_uid=%s, shared_folder_uid=%s', team_uid, shared_folder_uid)
                        except Exception as e:
                            logging.debug('Decryption error: team_uid=%s, shared_folder_uid=%s: %s', team_uid, shared_folder_uid, e)
        else:
            to_delete.add(team_uid)

    for team_uid in to_delete:
        del params.team_cache[team_uid]
    to_delete.clear()

    logging.debug('Decrypting shared folder keys')
    for shared_folder_uid, shared_folder in params.shared_folder_cache.items():
        if 'shared_folder_key_unencrypted' not in shared_folder and 'shared_folder_key' in shared_folder:
            # shared folder key
            try:
                encrypted_sf_key = utils.base64_url_decode(shared_folder['shared_folder_key'])
                key_type = shared_folder['key_type']
                if key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                    sf_key = crypto.decrypt_aes_v1(encrypted_sf_key, params.data_key)
                elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                    sf_key = crypto.decrypt_rsa(encrypted_sf_key, params.rsa_key2)
                elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                    sf_key = crypto.decrypt_aes_v2(encrypted_sf_key, params.data_key)
                elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                    sf_key = crypto.decrypt_ec(encrypted_sf_key, params.ecc_key)
                else:
                    sf_key = crypto.decrypt_aes_v1(encrypted_sf_key, params.data_key)
                shared_folder['shared_folder_key_unencrypted'] = sf_key
            except Exception as e:
                logging.debug('Shared folder %s key decryption error: %s', shared_folder_uid, e)

        if 'shared_folder_key_unencrypted' not in shared_folder:
            # team's shared folder key
            for team_uid, team in params.team_cache.items():
                if 'shared_folder_keys' in team:
                    sf_key = next((x for x in team['shared_folder_keys'] if x['shared_folder_uid'] == shared_folder_uid), None)
                    if sf_key and 'shared_folder_key_unencrypted' in sf_key:
                        shared_folder['shared_folder_key_unencrypted'] = sf_key['shared_folder_key_unencrypted']

        if 'shared_folder_key_unencrypted' in shared_folder:
            sf_key = shared_folder['shared_folder_key_unencrypted']
            try:
                if 'name_unencrypted' not in shared_folder:
                    name = shared_folder.get('name')
                    if name:
                        shared_folder['name_unencrypted'] = \
                            crypto.decrypt_aes_v1(utils.base64_url_decode(name), sf_key).decode('utf-8')
                    else:
                        data = shared_folder.get('data')
                        if data:
                            shared_folder['data_unencrypted'] = \
                                crypto.decrypt_aes_v1(utils.base64_url_decode(data), sf_key)
                            data_json = json.loads(shared_folder['data_unencrypted'].decode('utf-8'))
                            shared_folder['name_unencrypted'] = data_json['name']
                if 'data' in shared_folder and 'data_unencrypted' not in shared_folder:
                    data = utils.base64_url_decode(shared_folder['data'])
                    shared_folder['data_unencrypted'] = crypto.decrypt_aes_v1(data, sf_key)

            except Exception as e:
                logging.debug('Shared folder %s name decryption error: %s', shared_folder_uid, e)
            if 'name_unencrypted' not in shared_folder:
                shared_folder['name_unencrypted'] = shared_folder_uid

            if 'records' in shared_folder:
                for sfr in shared_folder['records']:
                    if 'record_key_unencrypted' not in sfr:
                        try:
                            encrypted_key = utils.base64_url_decode(sfr['record_key'])
                            if len(encrypted_key) == 60:
                                decrypted_key = crypto.decrypt_aes_v2(encrypted_key, sf_key)
                            else:
                                decrypted_key = crypto.decrypt_aes_v1(encrypted_key, sf_key)
                            sfr['record_key_unencrypted'] = decrypted_key
                        except Exception as e:
                            logging.debug('Shared folder %s record key decryption error: %s', shared_folder_uid, e)
        else:
            to_delete.add(shared_folder_uid)

    for shared_folder_uid in to_delete:
        del params.shared_folder_cache[shared_folder_uid]
        if shared_folder_uid in params.subfolder_cache:
            del params.subfolder_cache[shared_folder_uid]
    to_delete.clear()

    logging.debug('Resolve record keys. Meta data')
    for record_uid, record in params.record_cache.items():
        if 'record_key_unencrypted' not in record:
            # meta data
            if record_uid in params.meta_data_cache:
                meta_data = params.meta_data_cache[record_uid]
                if 'record_key_unencrypted' in meta_data:
                    record['record_key_unencrypted'] = meta_data['record_key_unencrypted']
        if 'record_key_unencrypted' not in record:
            to_delete.add(record_uid)

    if len(to_delete) > 0:
        logging.debug('Resolve record keys. Shared folder')
        for shared_folder in params.shared_folder_cache.values():
            if 'records' in shared_folder:
                for record_key in shared_folder['records']:
                    record_uid = record_key['record_uid']
                    if record_uid in to_delete and 'record_key_unencrypted' in record_key:
                        record = params.record_cache[record_uid]
                        record['record_key_unencrypted'] = record_key['record_key_unencrypted']
                        to_delete.remove(record_uid)
            if len(to_delete) == 0:
                break

    if len(to_delete) > 0:
        logging.debug('Decrypt linked keys')
        for child_uid, parents in params.record_link_cache.items():
            if child_uid in to_delete:
                for parent_uid, link in parents.items():
                    if 'record_key_unencrypted' not in link and parent_uid in params.record_cache:
                        parent_record = params.record_cache[parent_uid]
                        if 'record_key_unencrypted' in parent_record:
                            try:
                                encrypted_record_key = utils.base64_url_decode(link['record_key'])
                                link['record_key_unencrypted'] = crypto.decrypt_aes_v2(
                                    encrypted_record_key, parent_record['record_key_unencrypted'])
                            except Exception as e:
                                logging.debug('Record link %s key decryption error: %s', child_uid, e)

                child_record = params.record_cache[child_uid]
                if 'record_key_unencrypted' not in child_record:
                    for parent_uid, link in parents.items():
                        if 'record_key_unencrypted' in link:
                            child_record['record_key_unencrypted'] = link['record_key_unencrypted']
                            to_delete.remove(child_uid)
                            break

    to_delete.clear()
    for record_uid, record in params.record_cache.items():
        if 'record_key_unencrypted' not in record:
            logging.debug('Record %s key could not be resolved', record_uid)
            to_delete.add(record_uid)

    for record_uid in to_delete:
        if record_uid in params.record_link_cache:
            del params.record_link_cache[record_uid]
        for parents in params.record_link_cache.values():
            if record_uid in parents:
                del parents[record_uid]
        del params.record_cache[record_uid]
    to_delete.clear()

    logging.debug('Decrypting records')
    for record_uid, record in params.record_cache.items():
        record_key = record['record_key_unencrypted']
        if 'data_unencrypted' not in record:
            try:
                if 'version' in record and record['version'] >= 3:
                    record['data_unencrypted'] = crypto.decrypt_aes_v2(utils.base64_url_decode(record['data']), record_key) if 'data' in record else b'{}'
                else:
                    record['data_unencrypted'] = crypto.decrypt_aes_v1(utils.base64_url_decode(record['data']), record_key) if 'data' in record else b'{}'
                    extra = record.get('extra')
                    if extra:
                        record['extra_unencrypted'] = crypto.decrypt_aes_v1(utils.base64_url_decode(extra), record_key)
                    else:
                        record['extra_unencrypted'] = b'{}'
            except Exception as e:
                logging.debug('Record %s data/extra decryption error: %s', record_uid, e)

    logging.debug('Decrypting non shared data')
    for record_uid, nsd in params.non_shared_data_cache.items():
        if 'data_unencrypted' not in nsd and record_uid in params.record_cache:
            record = params.record_cache[record_uid]
            data = nsd.get('data')
            if data:
                version = record.get('version') or 0
                try:
                    if version >= 3:
                        nsd['data_unencrypted'] = crypto.decrypt_aes_v2(utils.base64_url_decode(data), params.data_key)
                    else:
                        nsd['data_unencrypted'] = crypto.decrypt_aes_v1(utils.base64_url_decode(data), params.data_key)
                except:
                    try:
                        if version < 3:
                            nsd['data_unencrypted'] = crypto.decrypt_aes_v2(utils.base64_url_decode(data), params.data_key)
                        else:
                            nsd['data_unencrypted'] = crypto.decrypt_aes_v1(utils.base64_url_decode(data), params.data_key)
                    except Exception as e:
                        logging.debug('Non Shared Data %s data decryption error: %s', record_uid, e)

    logging.debug('Decrypting folders')
    for folder_uid, sf in params.subfolder_cache.items():
        folder_type = sf['type']
        if folder_type == 'user_folder':
            if 'folder_key_unencrypted' not in sf:
                try:
                    encrypted_key = utils.base64_url_decode(sf['user_folder_key'])
                    key_type = sf['key_type']
                    if key_type == record_pb2.ENCRYPTED_BY_DATA_KEY:
                        sf['folder_key_unencrypted'] = crypto.decrypt_aes_v1(encrypted_key, params.data_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY:
                        sf['folder_key_unencrypted'] = crypto.decrypt_rsa(encrypted_key, params.rsa_key2)
                    elif key_type == record_pb2.ENCRYPTED_BY_DATA_KEY_GCM:
                        sf['folder_key_unencrypted'] = crypto.decrypt_aes_v2(encrypted_key, params.data_key)
                    elif key_type == record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC:
                        sf['folder_key_unencrypted'] = crypto.decrypt_ec(encrypted_key, params.ecc_key)
                    else:
                        sf['folder_key_unencrypted'] = crypto.decrypt_aes_v1(encrypted_key, params.data_key)
                except Exception as e:
                    logging.debug('User folder data decryption error: %s', e)
        elif folder_type == 'shared_folder_folder':
            if 'folder_key_unencrypted' not in sf:
                try:
                    shared_folder_uid = sf['shared_folder_uid']
                    if shared_folder_uid in params.shared_folder_cache:
                        shared_folder = params.shared_folder_cache[shared_folder_uid]
                        encrypted_key = utils.base64_url_decode(sf['shared_folder_folder_key'])
                        sf['folder_key_unencrypted'] = crypto.decrypt_aes_v1(encrypted_key, shared_folder.get('shared_folder_key_unencrypted'))
                except Exception as e:
                    logging.debug('Shared folder folder %s data decryption error: %s', sf['folder_uid'], e)
        else:
            continue
        if 'folder_key_unencrypted' in sf:
            if 'data_unencrypted' not in sf:
                data_b64 = sf.get('data')
                if data_b64:
                    try:
                        data_encrypted = utils.base64_url_decode(data_b64)
                        sf['data_unencrypted'] = crypto.decrypt_aes_v1(data_encrypted, sf['folder_key_unencrypted'])
                    except Exception as e:
                        logging.debug('Error decrypting shared folder folder %s data: %s', sf['folder_uid'], e)

    prepare_folder_tree(params)

    # Populate/update cache record security data
    for sec_data in resp_sec_data_recs:
        record_uid = utils.base64_url_encode(sec_data.recordUid)
        params.breach_watch_security_data[record_uid] = {'revision': sec_data.revision}

    # Populate/update security score data
    for sec_score_rec in resp_sec_scores:
        record_uid = utils.base64_url_encode(sec_score_rec.recordUid or b'')
        record = KeeperRecord.load(params, record_uid)
        if not record:
            continue
        revision = sec_score_rec.revision
        data = sec_score_rec.data
        try:
            if data:
                data = crypto.decrypt_aes_v2(sec_score_rec.data, record.record_key).decode()
                data = json.loads(data)
            else:
                data = dict()
        except:
            data = dict()
        params.security_score_data.update({record_uid: dict(record_uid=record_uid, data=data, revision=revision)})

    # Populate/update cache BreachWatch records data
    for p_bwr in resp_bw_recs:
        record_uid = utils.base64_url_encode(p_bwr.recordUid)
        if not record_uid:
            continue
        record = params.record_cache.get(record_uid)
        if not record:
            continue
        if 'record_key_unencrypted' not in record:
            continue
        try:
            bwr = {
                'record_uid': utils.base64_url_encode(p_bwr.recordUid),
                'data': utils.base64_url_encode(p_bwr.data),
                'type': 'RECORD' if p_bwr.type == breachwatch_pb2.RECORD else 'ALTERNATE_PASSWORD',
                'revision': p_bwr.revision,
                'scanned_by_account_uid': utils.base64_url_encode(p_bwr.scannedByAccountUid or params.account_uid_bytes)
            }
            if len(p_bwr.data) > 0:
                data = crypto.decrypt_aes_v2(p_bwr.data, record['record_key_unencrypted'])
                data_obj = client_pb2.BreachWatchData()
                data_obj.ParseFromString(data)
                bwr['data_unencrypted'] = google.protobuf.json_format.MessageToDict(data_obj)
            params.breach_watch_records[record_uid] = bwr
        except Exception as e:
            logging.debug('Decrypt bw data: %s', e)

    if full_sync or record_types:
        # Record V3 types cache population
        record_types_rs = _sync_record_types(params)
        if len(record_types_rs.recordTypes) > 0:
            params.record_type_cache = {}
            for rt in record_types_rs.recordTypes:
                type_id = rt.recordTypeId
                type_id += rt.scope * 1000000
                params.record_type_cache[type_id] = rt.content

    # Stop spinner if running
    if spinner:
        spinner.stop()

    if full_sync:
        convert_keys.change_key_types(params)

        # Count breachwatch issues and store on params for summary display
        breachwatch_count = 0
        if params.breach_watch:
            for _ in params.breach_watch.get_records_by_status(params, ['WEAK', 'BREACHED']):
                breachwatch_count += 1
        params._sync_breachwatch_count = breachwatch_count

        # Count records and store on params for summary display
        record_count = 0
        valid_versions = {2, 3}
        for r in params.record_cache.values():
            if r.get('version', 0) in valid_versions:
                record_count += 1
        params._sync_record_count = record_count



def _process_keeper_drive_sync(params, folders, folder_keys, folder_accesses, revoked_folder_accesses,
                                records, record_data_list, record_keys, record_accesses, revoked_record_accesses,
                                folder_records, removed_folder_records, users):
    """Process Keeper Drive atomic sync objects and store in caches."""
    
    logging.debug(f"Processing Keeper Drive sync: {len(folders)} folders, {len(folder_records)} folder_records, {len(records)} records, {len(record_keys)} record_keys")
    
    # Store users in user_cache
    for user in users:
        account_uid = utils.base64_url_encode(user.accountUid)
        params.user_cache[account_uid] = user.username
    
    # Process folders
    for folder_data in folders:
        folder_uid = utils.base64_url_encode(folder_data.folderUid)
        folder_obj = {
            'folder_uid': folder_uid,
            'folder_type': folder_data.type if folder_data.type else 0,
            'parent_uid': utils.base64_url_encode(folder_data.parentUid) if folder_data.parentUid else None,
            'data': folder_data.data,
            'inherit_user_permissions': folder_data.inheritUserPermissions if folder_data.inheritUserPermissions else 0,
        }
        if folder_data.HasField('ownerInfo'):
            folder_obj['owner_account_uid'] = utils.base64_url_encode(folder_data.ownerInfo.accountUid)
            folder_obj['owner_username'] = folder_data.ownerInfo.username
        params.keeper_drive_folders[folder_uid] = folder_obj
    
    # Process folder keys (group by folder_uid)
    for fk in folder_keys:
        folder_uid = utils.base64_url_encode(fk.folderUid)
        if folder_uid not in params.keeper_drive_folder_keys:
            params.keeper_drive_folder_keys[folder_uid] = []
        fk_obj = {
            'folder_uid': folder_uid,
            'encrypted_key': fk.folderKey,
            'key_type': fk.encryptedBy,
        }
        params.keeper_drive_folder_keys[folder_uid].append(fk_obj)
    
    # Process folder accesses (group by folder_uid)
    for fa in folder_accesses:
        folder_uid = utils.base64_url_encode(fa.folderUid)
        if folder_uid not in params.keeper_drive_folder_accesses:
            params.keeper_drive_folder_accesses[folder_uid] = []
        fa_obj = {
            'folder_uid': folder_uid,
            'access_type_uid': utils.base64_url_encode(fa.accessTypeUid),
            'access_type': fa.accessType,
            'access_role_type': fa.accessRoleType if fa.accessRoleType else 0,
            'inherited': fa.inherited if fa.inherited else False,
            'hidden': fa.hidden if fa.hidden else False,
        }
        if fa.HasField('folderKey'):
            fa_obj['folder_key'] = {
                'encrypted_key': fa.folderKey.encryptedKey,
                'encrypted_key_type': fa.folderKey.encryptedKeyType,
            }
        if fa.HasField('permissions'):
            fa_obj['permissions'] = {
                'can_add_users': fa.permissions.canAddUsers if fa.permissions.canAddUsers else False,
                'can_remove_users': fa.permissions.canRemoveUsers if fa.permissions.canRemoveUsers else False,
                'can_add_records': fa.permissions.canAddRecords if fa.permissions.canAddRecords else False,
                'can_remove_records': fa.permissions.canRemoveRecords if fa.permissions.canRemoveRecords else False,
                'can_delete_records': fa.permissions.canDeleteRecords if fa.permissions.canDeleteRecords else False,
                'can_create_folders': fa.permissions.canCreateFolders if fa.permissions.canCreateFolders else False,
                'can_delete_folders': fa.permissions.canDeleteFolders if fa.permissions.canDeleteFolders else False,
                'can_change_user_permissions': fa.permissions.canChangeUserPermissions if fa.permissions.canChangeUserPermissions else False,
                'can_change_record_permissions': fa.permissions.canChangeRecordPermissions if fa.permissions.canChangeRecordPermissions else False,
                'can_change_folder_ownership': fa.permissions.canChangeFolderOwnership if fa.permissions.canChangeFolderOwnership else False,
                'can_change_record_ownership': fa.permissions.canChangeRecordOwnership if fa.permissions.canChangeRecordOwnership else False,
                'can_edit_records': fa.permissions.canEditRecords if fa.permissions.canEditRecords else False,
                'can_view_records': fa.permissions.canViewRecords if fa.permissions.canViewRecords else False,
                'can_reshare_records': fa.permissions.canReshareRecords if fa.permissions.canReshareRecords else False,
            }
        params.keeper_drive_folder_accesses[folder_uid].append(fa_obj)
    
    # Process revoked folder accesses
    for rfa in revoked_folder_accesses:
        folder_uid = utils.base64_url_encode(rfa.folderUid)
        actor_uid = utils.base64_url_encode(rfa.actorUid)
        if folder_uid in params.keeper_drive_folder_accesses:
            params.keeper_drive_folder_accesses[folder_uid] = [
                fa for fa in params.keeper_drive_folder_accesses[folder_uid]
                if fa['access_type_uid'] != actor_uid
            ]
    
    # Process records (DriveRecord metadata)
    for record in records:
        record_uid = utils.base64_url_encode(record.recordUid)
        record_obj = {
            'record_uid': record_uid,
            'revision': record.revision,
            'version': record.version,
            'shared': record.shared if record.shared else False,
            'client_modified_time': record.clientModifiedTime if record.clientModifiedTime else 0,
        }
        if record.fileSize:
            record_obj['file_size'] = record.fileSize
        if record.thumbnailSize:
            record_obj['thumbnail_size'] = record.thumbnailSize
        params.keeper_drive_records[record_uid] = record_obj
    
    # Process record data (encrypted content)
    for rd in record_data_list:
        record_uid = utils.base64_url_encode(rd.recordUid)
        rd_obj = {
            'record_uid': record_uid,
            'data': rd.data,
        }
        if rd.HasField('user'):
            rd_obj['user_account_uid'] = utils.base64_url_encode(rd.user.accountUid)
            rd_obj['user_username'] = rd.user.username
        params.keeper_drive_record_data[record_uid] = rd_obj
    
    # Process record keys (group by record_uid)
    for rk in record_keys:
        record_uid = utils.base64_url_encode(rk.record_uid)
        if record_uid not in params.keeper_drive_record_keys:
            params.keeper_drive_record_keys[record_uid] = []
        rk_obj = {
            'record_uid': record_uid,
            'user_uid': utils.base64_url_encode(rk.user_uid),
            'record_key': rk.record_key,
            'encrypted_key_type': rk.encrypted_key_type,
        }
        params.keeper_drive_record_keys[record_uid].append(rk_obj)
    
    # Process record accesses (group by record_uid)
    for ra in record_accesses:
        record_uid = utils.base64_url_encode(ra.recordUid)
        if record_uid not in params.keeper_drive_record_accesses:
            params.keeper_drive_record_accesses[record_uid] = []
        ra_obj = {
            'record_uid': record_uid,
            'access_uid': utils.base64_url_encode(ra.accessTypeUid),
            'access_type': ra.accessType,
            'access_role_type': ra.accessRoleType,  # Store the role type
            'owner': ra.owner if hasattr(ra, 'owner') else False,
            'inherited': ra.inherited if hasattr(ra, 'inherited') else False,
            'hidden': ra.hidden if hasattr(ra, 'hidden') else False,
            'denied_access': ra.deniedAccess if hasattr(ra, 'deniedAccess') else False,
            'can_edit': ra.can_edit if hasattr(ra, 'can_edit') and ra.can_edit else False,
            'can_view': ra.can_view if hasattr(ra, 'can_view') and ra.can_view else False,
            'can_share': ra.can_share if hasattr(ra, 'can_share') and ra.can_share else False,
            'can_delete': ra.can_delete if hasattr(ra, 'can_delete') and ra.can_delete else False,
            'can_request_access': ra.can_request_access if hasattr(ra, 'can_request_access') and ra.can_request_access else False,
            'can_approve_access': ra.can_approve_access if hasattr(ra, 'can_approve_access') and ra.can_approve_access else False,
        }
        params.keeper_drive_record_accesses[record_uid].append(ra_obj)
        logging.debug(f"Stored record access: record={record_uid}, role_type={ra.accessRoleType}, can_edit={ra_obj['can_edit']}, can_view={ra_obj['can_view']}, can_share={ra_obj['can_share']}, can_delete={ra_obj['can_delete']}")
    
    # Process revoked record accesses
    for rra in revoked_record_accesses:
        record_uid = utils.base64_url_encode(rra.recordUid)
        actor_uid = utils.base64_url_encode(rra.actorUid)
        if record_uid in params.keeper_drive_record_accesses:
            params.keeper_drive_record_accesses[record_uid] = [
                ra for ra in params.keeper_drive_record_accesses[record_uid]
                if ra['access_uid'] != actor_uid
            ]
    
    # Process folder records (associations)
    for fr in folder_records:
        folder_uid = utils.base64_url_encode(fr.folderUid)
        record_uid = utils.base64_url_encode(fr.recordMetadata.recordUid)
        if folder_uid not in params.keeper_drive_folder_records:
            params.keeper_drive_folder_records[folder_uid] = set()
        params.keeper_drive_folder_records[folder_uid].add(record_uid)
        
        # Store the record key from folder record (encrypted with folder key)
        # Check if encryptedRecordKey exists and is not empty
        has_key = hasattr(fr.recordMetadata, 'encryptedRecordKey') and fr.recordMetadata.encryptedRecordKey
        logging.debug(f"FolderRecord: record={record_uid}, folder={folder_uid}, has_encryptedRecordKey={has_key}, key_length={len(fr.recordMetadata.encryptedRecordKey) if has_key else 0}")
        
        if has_key:
            if record_uid not in params.keeper_drive_record_keys:
                params.keeper_drive_record_keys[record_uid] = []
            # This key is encrypted with the folder key
            rk_obj = {
                'record_uid': record_uid,
                'folder_uid': folder_uid,  # Mark that this is from a folder
                'record_key': fr.recordMetadata.encryptedRecordKey,
                'encrypted_key_type': fr.recordMetadata.encryptedRecordKeyType,
            }
            params.keeper_drive_record_keys[record_uid].append(rk_obj)
            logging.debug(f"Stored folder record key: record={record_uid}, folder={folder_uid}, type={fr.recordMetadata.encryptedRecordKeyType}")
        else:
            logging.debug(f"No encrypted record key in FolderRecord: record={record_uid}, folder={folder_uid}")
    
    # Process removed folder records
    for rfr in removed_folder_records:
        folder_uid = utils.base64_url_encode(rfr.folder_uid)
        record_uid = utils.base64_url_encode(rfr.record_uid)
        if folder_uid in params.keeper_drive_folder_records:
            params.keeper_drive_folder_records[folder_uid].discard(record_uid)
    
    # Decrypt folder and record keys
    _decrypt_keeper_drive_keys(params)
    
    # Reconstruct complete entities
    _reconstruct_keeper_drive_entities(params)


def _decrypt_keeper_drive_keys(params):
    """Decrypt Keeper Drive folder and record keys."""
    # Decrypt folder keys
    for folder_uid, folder_obj in params.keeper_drive_folders.items():
        if 'folder_key_unencrypted' in folder_obj:
            continue
        
        folder_key = None
        
        # Try to decrypt from folder keys (FolderKey messages)
        if folder_uid in params.keeper_drive_folder_keys:
            for fk in params.keeper_drive_folder_keys[folder_uid]:
                try:
                    if fk['key_type'] == folder_pb2.ENCRYPTED_BY_USER_KEY:
                        # Decrypt with user's data key using GCM
                        folder_key = crypto.decrypt_aes_v2(fk['encrypted_key'], params.data_key)
                        logging.debug(f"Folder {folder_uid}: decrypted with user data key (ENCRYPTED_BY_USER_KEY)")
                        break
                    elif fk['key_type'] == folder_pb2.ENCRYPTED_BY_PARENT_KEY:
                        # Get parent folder key
                        parent_uid = folder_obj.get('parent_uid')
                        if parent_uid and parent_uid in params.keeper_drive_folders:
                            parent_folder = params.keeper_drive_folders[parent_uid]
                            if 'folder_key_unencrypted' in parent_folder:
                                parent_key = parent_folder['folder_key_unencrypted']
                                folder_key = crypto.decrypt_aes_v2(fk['encrypted_key'], parent_key)
                                logging.debug(f"Folder {folder_uid}: decrypted with parent folder key (ENCRYPTED_BY_PARENT_KEY)")
                                break
                except Exception as e:
                    logging.debug(f"Failed to decrypt folder key for {folder_uid} from FolderKey: {e}")
        
        # Try to decrypt from folder access data (FolderAccessData.folderKey)
        if not folder_key and folder_uid in params.keeper_drive_folder_accesses:
            for fa in params.keeper_drive_folder_accesses[folder_uid]:
                if 'folder_key' not in fa:
                    continue
                
                try:
                    encrypted_key = fa['folder_key']['encrypted_key']
                    key_type = fa['folder_key']['encrypted_key_type']
                    
                    if key_type == folder_pb2.encrypted_by_data_key_gcm:
                        folder_key = crypto.decrypt_aes_v2(encrypted_key, params.data_key)
                        logging.debug(f"Folder {folder_uid}: decrypted with user data key (GCM) from FolderAccessData")
                        break
                    elif key_type == folder_pb2.encrypted_by_data_key:
                        folder_key = crypto.decrypt_aes_v1(encrypted_key, params.data_key)
                        logging.debug(f"Folder {folder_uid}: decrypted with user data key (CBC) from FolderAccessData")
                        break
                    elif key_type == folder_pb2.encrypted_by_public_key:
                        folder_key = crypto.decrypt_rsa(encrypted_key, params.rsa_key2)
                        logging.debug(f"Folder {folder_uid}: decrypted with RSA key from FolderAccessData")
                        break
                    elif key_type == folder_pb2.encrypted_by_public_key_ecc:
                        folder_key = crypto.decrypt_ec(encrypted_key, params.ecc_key)
                        logging.debug(f"Folder {folder_uid}: decrypted with ECC key from FolderAccessData")
                        break
                except Exception as e:
                    logging.debug(f"Failed to decrypt folder key for {folder_uid} from FolderAccessData: {e}")
        
        if folder_key:
            folder_obj['folder_key_unencrypted'] = folder_key
            
            # Decrypt folder data
            if 'data' in folder_obj and folder_obj['data']:
                try:
                    data_bytes = crypto.decrypt_aes_v2(folder_obj['data'], folder_key)
                    data_json = json.loads(data_bytes.decode('utf-8'))
                    folder_obj['name'] = data_json.get('name', 'Unnamed Folder')
                    if 'color' in data_json:
                        folder_obj['color'] = data_json['color']
                except Exception as e:
                    logging.debug(f"Failed to decrypt folder data for {folder_uid}: {e}")
    
    # Decrypt record keys
    for record_uid, record_keys_list in params.keeper_drive_record_keys.items():
        if record_uid in params.keeper_drive_records:
            record_obj = params.keeper_drive_records[record_uid]
            if 'record_key_unencrypted' in record_obj:
                continue
            
            logging.debug(f"Attempting to decrypt key for record {record_uid}, have {len(record_keys_list)} key(s)")
            record_key = None
            for rk in record_keys_list:
                try:
                    # Check if this key is from a folder record (encrypted with folder key)
                    if 'folder_uid' in rk:
                        folder_uid = rk['folder_uid']
                        logging.debug(f"Record {record_uid}: trying folder key from folder {folder_uid}, type={rk['encrypted_key_type']}")
                        if folder_uid in params.keeper_drive_folders:
                            folder_obj = params.keeper_drive_folders[folder_uid]
                            if 'folder_key_unencrypted' in folder_obj:
                                folder_key = folder_obj['folder_key_unencrypted']
                                # Decrypt record key with folder key
                                if rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key_gcm:
                                    record_key = crypto.decrypt_aes_v2(rk['record_key'], folder_key)
                                    logging.debug(f"Record {record_uid}: decrypted with AES-GCM using folder key")
                                elif rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key:
                                    record_key = crypto.decrypt_aes_v1(rk['record_key'], folder_key)
                                    logging.debug(f"Record {record_uid}: decrypted with AES-CBC using folder key")
                                else:
                                    # Try both v1 and v2 decryption
                                    try:
                                        record_key = crypto.decrypt_aes_v2(rk['record_key'], folder_key)
                                        logging.debug(f"Record {record_uid}: decrypted with AES-GCM (fallback)")
                                    except:
                                        record_key = crypto.decrypt_aes_v1(rk['record_key'], folder_key)
                                        logging.debug(f"Record {record_uid}: decrypted with AES-CBC (fallback)")
                                if record_key:
                                    break
                            else:
                                logging.debug(f"Record {record_uid}: folder {folder_uid} has no decrypted key")
                        else:
                            logging.debug(f"Record {record_uid}: folder {folder_uid} not found in keeper_drive_folders")
                    else:
                        # This is a direct record key (encrypted with user/public key)
                        logging.debug(f"Record {record_uid}: trying direct key, type={rk['encrypted_key_type']}")
                        if rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key_gcm:
                            # Decrypt with user's data key using GCM (v2)
                            record_key = crypto.decrypt_aes_v2(rk['record_key'], params.data_key)
                            logging.debug(f"Record {record_uid}: decrypted with user data key (GCM)")
                            break
                        elif rk['encrypted_key_type'] == folder_pb2.encrypted_by_data_key:
                            # Decrypt with user's data key using CBC (v1)
                            record_key = crypto.decrypt_aes_v1(rk['record_key'], params.data_key)
                            logging.debug(f"Record {record_uid}: decrypted with user data key (CBC)")
                            break
                        elif rk['encrypted_key_type'] == folder_pb2.encrypted_by_public_key:
                            # Decrypt with RSA private key
                            if params.rsa_key2:
                                record_key = crypto.decrypt_rsa(rk['record_key'], params.rsa_key2)
                                logging.debug(f"Record {record_uid}: decrypted with RSA")
                                break
                        elif rk['encrypted_key_type'] == folder_pb2.encrypted_by_public_key_ecc:
                            # Decrypt with ECC private key
                            if params.ecc_key:
                                record_key = crypto.decrypt_ec(rk['record_key'], params.ecc_key)
                                logging.debug(f"Record {record_uid}: decrypted with ECC")
                                break
                        elif rk['encrypted_key_type'] == folder_pb2.no_key or rk['encrypted_key_type'] == 0:
                            # Type is 0 or missing - try decrypting with user's data key (most common)
                            # First try GCM (v2), then CBC (v1) as fallback
                            logging.debug(f"Record {record_uid}: type is 0/no_key, trying data key decryption")
                            try:
                                record_key = crypto.decrypt_aes_v2(rk['record_key'], params.data_key)
                                logging.debug(f"Record {record_uid}: decrypted with user data key (GCM, type=0)")
                                break
                            except:
                                try:
                                    record_key = crypto.decrypt_aes_v1(rk['record_key'], params.data_key)
                                    logging.debug(f"Record {record_uid}: decrypted with user data key (CBC, type=0)")
                                    break
                                except:
                                    logging.debug(f"Record {record_uid}: failed to decrypt with data key (type=0)")
                except Exception as e:
                    logging.debug(f"Failed to decrypt record key for {record_uid}: {e}")
            
            if record_key:
                record_obj['record_key_unencrypted'] = record_key
                logging.debug(f"Record {record_uid}: stored unencrypted key")
                
                # Decrypt record data if available
                if record_uid in params.keeper_drive_record_data:
                    rd_obj = params.keeper_drive_record_data[record_uid]
                    if 'data' in rd_obj and rd_obj['data']:
                        try:
                            # Try AES-GCM (v2) first, then fall back to AES-CBC (v1)
                            try:
                                data_bytes = crypto.decrypt_aes_v2(rd_obj['data'], record_key)
                            except:
                                data_bytes = crypto.decrypt_aes_v1(rd_obj['data'], record_key)
                            
                            data_json = json.loads(data_bytes.decode('utf-8'))
                            rd_obj['data_json'] = data_json
                            logging.debug(f"Record {record_uid}: decrypted and parsed data, title={data_json.get('title', 'N/A')}")
                        except Exception as e:
                            logging.warning(f"Failed to decrypt record data for {record_uid}: {e}")
                    else:
                        logging.debug(f"Record {record_uid}: no data field to decrypt")
                else:
                    logging.debug(f"Record {record_uid}: not in keeper_drive_record_data")


def _reconstruct_keeper_drive_entities(params):
    """Reconstruct complete Keeper Drive entities from atomic objects."""
    # Integrate folders into subfolder_cache
    for folder_uid, folder_obj in params.keeper_drive_folders.items():
        if 'folder_key_unencrypted' not in folder_obj:
            continue
        
        # Create user_folder entry compatible with existing subfolder_cache
        user_folder = {
            'folder_uid': folder_uid,
            'type': 'user_folder',
            'name': folder_obj.get('name', 'Unnamed Folder'),
            'folder_key_unencrypted': folder_obj['folder_key_unencrypted'],
        }
        
        if 'parent_uid' in folder_obj and folder_obj['parent_uid']:
            user_folder['parent_uid'] = folder_obj['parent_uid']
        
        if 'color' in folder_obj:
            user_folder['color'] = folder_obj['color']
        
        params.subfolder_cache[folder_uid] = user_folder
    
    # Integrate folder-record associations
    for folder_uid, record_uids in params.keeper_drive_folder_records.items():
        if folder_uid not in params.subfolder_record_cache:
            params.subfolder_record_cache[folder_uid] = set()
        for record_uid in record_uids:
            params.subfolder_record_cache[folder_uid].add(record_uid)
    
    # Integrate records into record_cache
    for record_uid, record_obj in params.keeper_drive_records.items():
        if 'record_key_unencrypted' not in record_obj:
            continue
        
        # Check if record data is available
        if record_uid not in params.keeper_drive_record_data:
            continue
        
        rd_obj = params.keeper_drive_record_data[record_uid]
        if 'data_json' not in rd_obj:
            continue
        
        # Create record entry compatible with existing record_cache
        record_entry = {
            'record_uid': record_uid,
            'revision': record_obj.get('revision', 0),
            'version': record_obj.get('version', 0),
            'shared': record_obj.get('shared', False),
            'record_key_unencrypted': record_obj['record_key_unencrypted'],
            'data_unencrypted': json.dumps(rd_obj['data_json']).encode('utf-8'),
        }
        
        params.record_cache[record_uid] = record_entry
        
        # Add to meta_data_cache
        if record_uid not in params.meta_data_cache:
            meta_data = {
                'record_uid': record_uid,
                'record_key_unencrypted': record_obj['record_key_unencrypted'],
                'can_share': True,
                'can_edit': True,
            }
            if 'user_account_uid' in rd_obj:
                meta_data['owner_account_uid'] = rd_obj['user_account_uid']
                if rd_obj['user_account_uid'] in params.user_cache:
                    meta_data['owner_username'] = params.user_cache[rd_obj['user_account_uid']]
            params.meta_data_cache[record_uid] = meta_data
        
        # Add to record_owner_cache
        if record_uid not in params.record_owner_cache:
            if 'user_account_uid' in rd_obj:
                # Determine if the current user is the owner
                is_owner = (rd_obj['user_account_uid'] == utils.base64_url_encode(params.account_uid_bytes))
                # RecordOwner is a NamedTuple with (owner: bool, account_uid: str)
                params.record_owner_cache[record_uid] = RecordOwner(
                    is_owner,
                    rd_obj['user_account_uid']
                )
    
    logging.info(f"Reconstructed {len(params.keeper_drive_folders)} Keeper Drive folder(s) and {len(params.keeper_drive_records)} record(s)")


def _sync_record_types(params):  # type: (KeeperParams) -> Any
    rq = record_pb2.RecordTypesRequest()
    rq.standard = True
    rq.user = True
    rq.enterprise = True
    rq.pam = True
    return api.communicate_rest(params, rq, 'vault/get_record_types', rs_type=record_pb2.RecordTypesResponse)


def merge_lists_on_value(list1, list2, field_name):
    d = {x[field_name]: x for x in list1}
    d.update({x[field_name]: x for x in list2})
    return [x for x in d.values()]


def prepare_folder_tree(params):    # type: (KeeperParams) -> None
    params.folder_cache = {}
    params.root_folder = RootFolderNode()

    for sf in params.subfolder_cache.values():
        data_unencrypted = sf.get('data_unencrypted')    # type: Optional[bytes]
        folder_uid = None
        if sf['type'] == 'user_folder':
            folder_uid = sf['folder_uid']
            uf = UserFolderNode()
            uf.uid = folder_uid
            uf.parent_uid = sf.get('parent_uid')
            params.folder_cache[uf.uid] = uf

        elif sf['type'] == 'shared_folder_folder':
            folder_uid = sf['folder_uid']
            sff = SharedFolderFolderNode()
            sff.uid = folder_uid
            sff.shared_folder_uid = sf['shared_folder_uid']
            sff.parent_uid = sf.get('parent_uid') or sff.shared_folder_uid
            params.folder_cache[sff.uid] = sff

        elif sf['type'] == 'shared_folder':
            folder_uid = sf['shared_folder_uid']
            shf = SharedFolderNode()
            shf.uid = folder_uid
            shf.parent_uid = sf.get('folder_uid')
            folder = params.shared_folder_cache.get(shf.uid)
            if folder is not None:
                data_unencrypted = folder.get('data_unencrypted')
                shf.name = folder['name_unencrypted']
            params.folder_cache[shf.uid] = shf

        if data_unencrypted and folder_uid:
            try:
                f = params.folder_cache.get(folder_uid)    # type: Optional[BaseFolderNode]
                data = json.loads(data_unencrypted.decode())
                f.name = data.get('name') or f.name or f.uid
                f.color = data.get('color')
            except Exception as e:
                logging.debug('Error decrypting user folder name. Folder UID: %s. Error: %s', sf.uid, e)

    for f in params.folder_cache.values():
        parent_folder = params.folder_cache.get(f.parent_uid) if f.parent_uid else params.root_folder
        if parent_folder:
            parent_folder.subfolders.append(f.uid)
