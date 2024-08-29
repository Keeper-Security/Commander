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

from . import api, utils, crypto
from .display import bcolors
from .params import KeeperParams, RecordOwner
from .proto import SyncDown_pb2, record_pb2, client_pb2, breachwatch_pb2
from .proto.SyncDown_pb2 import BreachWatchRecord, BreachWatchSecurityData
from .subfolder import RootFolderNode, UserFolderNode, SharedFolderNode, SharedFolderFolderNode, BaseFolderNode


def sync_down(params, record_types=False):   # type: (KeeperParams, bool) -> None
    """Sync full or partial data down to the client"""

    params.sync_data = False
    token = params.sync_down_token
    if not token:
        logging.info('Syncing...')

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

    resp_bw_recs = []       # type: List[BreachWatchRecord]
    resp_sec_data_recs = []     # type: List[BreachWatchSecurityData]
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
                team['team_private_key'] = utils.base64_url_encode(t.teamPrivateKey)
                team['restrict_edit'] = t.restrictEdit
                team['restrict_share'] = t.restrictShare
                team['restrict_view'] = t.restrictView

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
            for rr in response.recordRotations:
                record_uid = utils.base64_url_encode(rr.recordUid)
                rr_obj = {
                    'record_uid': record_uid,
                    'revision': rr.revision,
                    'configuration_uid': utils.base64_url_encode(rr.configurationUid),
                    'schedule': rr.schedule,
                    'pwd_complexity': utils.base64_url_encode(rr.pwdComplexity),
                    'disabled': rr.disabled,
                    'resource_uid': utils.base64_url_encode(rr.resourceUid),
                    'last_rotation': rr.lastRotation,
                    'last_rotation_status': rr.lastRotationStatus,
                }
                params.record_rotation_cache[record_uid] = rr_obj

        params.sync_down_token = response.continuationToken

    params.revision = revision

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
                if key_type == 1:                        # AES256CBC
                    record_key = crypto.decrypt_aes_v1(record_key_encrypted, params.data_key)
                elif meta_data['record_key_type'] == 2:  # RSA
                    record_key = crypto.decrypt_rsa(record_key_encrypted, params.rsa_key2)
                elif key_type == 3:                      # AES256GCM
                    record_key = crypto.decrypt_aes_v2(record_key_encrypted, params.data_key)
                elif meta_data['record_key_type'] == 4:  # EC
                    record_key = crypto.decrypt_ec(record_key_encrypted, params.ecc_key)
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
                if key_type == 2:
                    team_key = crypto.decrypt_rsa(encrypted_team_key, params.rsa_key2)
                else:
                    team_key = crypto.decrypt_aes_v1(encrypted_team_key, params.data_key)
                team['team_key_unencrypted'] = team_key
                encrypted_team_private_key = utils.base64_url_decode(team['team_private_key'])
                team['team_private_key_unencrypted'] = \
                    crypto.decrypt_aes_v1(encrypted_team_private_key, team_key)
            except Exception as e:
                logging.warning('Could not decrypt team %s key: %s', team_uid, e)
        if 'team_key_unencrypted' in team:
            if 'shared_folder_keys' in team:
                for sf_key in team['shared_folder_keys']:
                    if 'shared_folder_key_unencrypted' not in sf_key:
                        encrypted_sf_key = utils.base64_url_decode(sf_key['shared_folder_key'])
                        try:
                            if sf_key['key_type'] == 2:
                                team_private_key = team['team_private_key_unencrypted']
                                team_pk = crypto.load_rsa_private_key(team_private_key)
                                decrypted_sf_key = crypto.decrypt_rsa(encrypted_sf_key, team_pk)
                            else:
                                decrypted_sf_key = crypto.decrypt_aes_v1(encrypted_sf_key, team['team_key_unencrypted'])
                            sf_key['shared_folder_key_unencrypted'] = decrypted_sf_key
                        except Exception as e:
                            logging.debug('Decryption error: %s', e)
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
                if key_type == 2:
                    sf_key = crypto.decrypt_rsa(encrypted_sf_key, params.rsa_key2)
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
                    if sf['key_type'] == 2:
                        sf['folder_key_unencrypted'] = crypto.decrypt_rsa(encrypted_key, params.rsa_key2)
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
                        sf['folder_key_unencrypted'] = crypto.decrypt_aes_v1(encrypted_key, shared_folder['shared_folder_key_unencrypted'])
                except Exception as e:
                    logging.debug('Shared folder folder %s data decryption error: %s', sf['folder_uid'], e)
        else:
            continue
        if 'folder_key_unencrypted' in sf:
            if 'data_unencrypted' not in sf:
                try:
                    data_encrypted = utils.base64_url_decode(sf['data'])
                    sf['data_unencrypted'] = crypto.decrypt_aes_v1(data_encrypted, sf['folder_key_unencrypted'])
                except Exception as e:
                    logging.debug('Error decrypting shared folder folder %s data: %s', sf['folder_uid'], e)

    prepare_folder_tree(params)

    # Populate/update cache record security data
    for sec_data in resp_sec_data_recs:
        record_uid = utils.base64_url_encode(sec_data.recordUid)
        params.breach_watch_security_data[record_uid] = {'revision': sec_data.revision}

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

    if full_sync:
        if params.breach_watch:
            weak_count = 0
            for _ in params.breach_watch.get_records_by_status(params, ['WEAK', 'BREACHED']):
                weak_count += 1
            if weak_count > 0:
                logging.info(bcolors.WARNING +
                             f'The number of records that are affected by breaches or contain high-risk passwords: {weak_count}' +
                             '\nUse \"breachwatch list\" command to get more details' +
                             bcolors.ENDC)

        record_count = 0
        valid_versions = {2, 3}
        for r in params.record_cache.values():
            if r.get('version', 0) in valid_versions:
                record_count += 1
        if record_count:
            logging.info('Decrypted [%d] record(s)', record_count)


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
