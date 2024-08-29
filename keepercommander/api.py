#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import base64
import collections
import itertools
import json
import logging
import math
import os
import re
import time
from datetime import datetime
from typing import Optional, Tuple, Iterable, List, Dict, Any

import google
from Cryptodome.PublicKey import RSA

from . import constants, rest_api, loginv3, utils, crypto, vault
from .display import bcolors
from .enterprise import query_enterprise as qe
from .error import KeeperApiError
from .params import KeeperParams, PublicKeys, LAST_RECORD_UID
from .proto import APIRequest_pb2, record_pb2, enterprise_pb2
from .record import Record
from .recordv3 import RecordV3
from .shared_folder import SharedFolder
from .subfolder import BaseFolderNode
from .sync_down import sync_down
from .team import Team
from .ttk import TTK

current_milli_time = lambda: int(round(time.time() * 1000))


# PKCS7 padding helpers
BS = 16
pad_binary = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
unpad_binary = lambda s: s[0:-s[-1]]
unpad_char = lambda s: s[0:-ord(s[-1])]

decode_uid_to_str = lambda uid: base64.urlsafe_b64encode(uid).decode().rstrip('=')

LOCALE = 'en_US'


def run_command(params, request):
    # type: (KeeperParams, dict) -> dict
    if 'client_version' not in request:
        request['client_version'] = rest_api.CLIENT_VERSION

    return rest_api.v2_execute(params.rest_context, request)


def login(params, new_login=False, login_ui=None):
    # type: (KeeperParams, bool, Optional[Any]) -> None

    logging.info('Logging in to Keeper Commander')
    flow = loginv3.LoginV3Flow(login_ui)
    try:
        flow.login(params, new_login=new_login)
    except loginv3.InvalidDeviceToken:
        logging.warning('Registering new device')
        flow.login(params, new_device=True)


def accept_account_transfer_consent(params):
    share_account_by = params.get_share_account_timestamp()
    print(constants.ACCOUNT_TRANSFER_MSG.format(share_account_by.strftime('%a, %b %d %Y')))

    expired = datetime.today() > share_account_by
    input_options = 'Accept/L(ogout)' if expired else 'Accept/L(ater)'
    answer = input('Do you accept Account Transfer policy? {}: '.format(input_options))
    answer = answer.lower()
    if answer.lower() == 'accept':
        for role in params.settings['share_account_to']:
            encoded_public = utils.base64_url_decode(role['public_key'])
            public_key = crypto.load_rsa_public_key(encoded_public)
            transfer_key = crypto.encrypt_rsa(params.data_key, public_key)
            request = {
                'command': 'share_account',
                'to_role_id': role['role_id'],
                'transfer_key': utils.base64_url_encode(transfer_key)
            }
            communicate(params, request)
        return True
    else:
        return False


def get_record_data_json_bytes(data):    # type: (dict) -> bytes
    """Get serialized and utf-8 encoded record data with padding"""
    data_str = json.dumps(data)
    padding = int(math.ceil(max(384, len(data_str)) / 16) * 16)
    if padding:
        data_str = data_str.ljust(padding)
    return data_str.encode('utf-8')


def pad_aes_gcm(json):
    # AES-GCM encryption leaks length of plaintext, so we pad the object prior to encryption.
    result = json
    json_bytes = json.encode('UTF-8') if isinstance(json, str) else json
    if isinstance(json_bytes, bytes):
        bytes_len = len(json_bytes)
        padded_len = max(384, bytes_len)
        # padded_len = math.ceil(padded_len / 16) * 16
        if padded_len % 16: padded_len = padded_len + 16 - (padded_len % 16)

        if padded_len != bytes_len:
            pad_len = abs(padded_len - bytes_len)
            pad = ' ' * pad_len # fill with spaces (byte value 0x20)
            result = result + pad if isinstance(result, str) else b''.join([result, pad.encode('UTF-8')])

    return result


def decrypt_rsa_key(encrypted_private_key, data_key):
    """ Decrypt the RSA private key
    PKCS1 formatted private key, which is described by the ASN.1 type:
    RSAPrivateKey ::= SEQUENCE {
          version           Version,
          modulus           INTEGER,  -- n
          publicExponent    INTEGER,  -- e
          privateExponent   INTEGER,  -- d
          prime1            INTEGER,  -- p
          prime2            INTEGER,  -- q
          exponent1         INTEGER,  -- d mod (p-1)
          exponent2         INTEGER,  -- d mod (q-1)
          coefficient       INTEGER,  -- (inverse of q) mod p
          otherPrimeInfos   OtherPrimeInfos OPTIONAL
    }
    """
    decoded_data = utils.base64_url_decode(encrypted_private_key)
    return RSA.importKey(crypto.decrypt_aes_v1(decoded_data, data_key))


def get_record(params, record_uid):
    """Return the referenced record cache"""
    record_uid = record_uid.strip()

    if not record_uid:
        logging.warning('No record UID provided')
        return

    if not params.record_cache:
        logging.warning('No record cache.  Sync down first.')
        return

    if record_uid not in params.record_cache:
        logging.warning('Record UID %s not found in cache.' % record_uid)
        return

    cached_rec = params.record_cache[record_uid]
    version = cached_rec.get('version', 2)

    try:
        rec = Record(record_uid)
        data = json.loads(cached_rec['data_unencrypted'])
        extra = json.loads(cached_rec['extra_unencrypted']) if 'extra_unencrypted' in cached_rec else None
        rec.load(data, version=version, revision=cached_rec['revision'], extra=extra)
        if not resolve_record_view_path(params, record_uid):
            rec.mask_password()
        return rec
    except:
        logging.error('**** Error decrypting record %s', record_uid)


def is_shared_folder(params,shared_folder_uid):
    shared_folder_uid = shared_folder_uid.strip()

    if not shared_folder_uid:
        return False

    if not params.shared_folder_cache:
        return False

    if shared_folder_uid not in params.shared_folder_cache:
        return False

    return True


def is_team(params,team_uid):
    team_uid = team_uid.strip()

    if not team_uid:
        return False

    if not params.team_cache:
        return False

    if team_uid not in params.team_cache:
        return False

    return True


def get_share_admins_for_shared_folder(params, shared_folder_uid):
    # type: (KeeperParams, str) -> Optional[List[str]]
    if params.enterprise_ec_key:
        if shared_folder_uid in params.shared_folder_cache:
            if 'share_admins' in params.shared_folder_cache[shared_folder_uid]:
                return params.shared_folder_cache[shared_folder_uid]['share_admins']

        try:
            rq = enterprise_pb2.GetSharingAdminsRequest()
            rq.sharedFolderUid = utils.base64_url_decode(shared_folder_uid)
            rs = communicate_rest(params, rq, 'enterprise/get_sharing_admins',
                                  rs_type=enterprise_pb2.GetSharingAdminsResponse)
            admins = [x.email for x in rs.userProfileExts if x.isShareAdminForSharedFolderOwner]
        except Exception as e:
            logging.debug(e)
            return
        if shared_folder_uid in params.shared_folder_cache:
            params.shared_folder_cache[shared_folder_uid]['share_admins'] = admins

        return admins


def get_share_admins_for_record(params, record_uid):    # type: (KeeperParams, str) -> Optional[List[str]]
    if params.enterprise_ec_key:
        if record_uid in params.record_cache:
            if 'share_admins' in params.record_cache[record_uid]:
                return params.record_cache[record_uid]['share_admins']

        try:
            rq = enterprise_pb2.GetSharingAdminsRequest()
            rq.recordUid = utils.base64_url_decode(record_uid)
            rs = communicate_rest(params, rq, 'enterprise/get_sharing_admins',
                                  rs_type=enterprise_pb2.GetSharingAdminsResponse)
            admins = [x.email for x in rs.userProfileExts if x.isShareAdminForRequestedObject]
        except Exception as e:
            logging.debug(e)
            return
        if record_uid in params.record_cache:
            params.record_cache[record_uid]['share_admins'] = admins

        return admins


def get_shared_folder(params, shared_folder_uid):   # type: (KeeperParams, str) -> Optional[SharedFolder]
    """Return the referenced shared folder"""
    shared_folder_uid = shared_folder_uid.strip()

    if not shared_folder_uid:
        logging.warning('No shared folder UID provided')
        return None

    if not params.shared_folder_cache:
        logging.warning('No shared folder cache.  Sync down first.')
        return None

    if shared_folder_uid not in params.shared_folder_cache:
        logging.warning('Shared folder UID not found.')
        return None

    cached_sf = params.shared_folder_cache[shared_folder_uid]

    sf = SharedFolder(shared_folder_uid)
    sf.load(cached_sf, cached_sf['revision'])
    return sf


def load_user_public_keys(params, emails, send_invites=False):  # type: (KeeperParams, List[str], bool) -> Optional[List[str]]
    s = set((x.casefold() for x in emails))
    s.difference_update(params.key_cache.keys())
    if not s:
        return

    emails_to_load = list(s)
    rq = APIRequest_pb2.GetPublicKeysRequest()
    rq.usernames.extend(emails_to_load)
    need_share_accept = []
    rs = communicate_rest(params, rq, 'vault/get_public_keys', rs_type=APIRequest_pb2.GetPublicKeysResponse)
    for pk in rs.keyResponses:
        email = pk.username
        if pk.errorCode in ['', 'success']:
            rsa = pk.publicKey
            ec = pk.publicEccKey
            params.key_cache[email] = PublicKeys(rsa=rsa, ec=ec)
        elif pk.errorCode == 'no_active_share_exist':
            need_share_accept.append(pk.username)
    if len(need_share_accept) > 0 and send_invites:
        for email in need_share_accept:
            rq = APIRequest_pb2.SendShareInviteRequest()
            rq.email = email
            try:
                communicate_rest(params, rq, 'vault/send_share_invite')
            except Exception as e:
                logging.debug('Share invite failed: %s', e)
        return need_share_accept


def load_team_keys(params, team_uids):          # type: (KeeperParams, List[str]) -> None
    s = set(team_uids)
    s.difference_update(params.key_cache.keys())
    if not s:
        return

    if params.enterprise:
        logging.debug('Resolve team keys shared with enterprise')
        tree_key = params.enterprise['unencrypted_tree_key']
        for t in params.enterprise.get('teams', []):
            team_uid = t.get('team_uid')
            if team_uid in s:
                try:
                    encrypted_team_key = t.get('encrypted_team_key')
                    if encrypted_team_key:
                        team_key = crypto.decrypt_aes_v2(utils.base64_url_decode(encrypted_team_key), tree_key)
                        params.key_cache[team_uid] = PublicKeys(aes=team_key)
                        s.remove(team_uid)
                except Exception as e:
                    logging.debug('Team UID \"%s\": Decrypt key error: %s', team_uid, str(e))

    if not s:
        return

    logging.debug('Loading %d team keys', len(s))
    uids_to_load = list(s)

    while len(uids_to_load) > 0:
        uids = uids_to_load[:90]
        uids_to_load = uids_to_load[90:]
        rq = {
            'command': 'team_get_keys',
            'teams': uids
        }
        rs = communicate(params, rq)
        if 'keys' in rs:
            for tk in rs['keys']:
                if 'key' in tk:
                    team_uid = tk['team_uid']
                    try:
                        aes = b''
                        rsa = b''
                        encrypted_key = utils.base64_url_decode(tk['key'])
                        if tk['type'] == 1:
                            aes = crypto.decrypt_aes_v1(encrypted_key, params.data_key)
                        elif tk['type'] == 2:
                            aes = crypto.decrypt_rsa(tk['key'], params.rsa_key2)
                        elif tk['type'] == 3:
                            rsa = encrypted_key
                        params.key_cache[team_uid] = PublicKeys(rsa=rsa, aes=aes)
                    except Exception as e:
                        logging.debug(e)


def load_available_teams(params):
    if params.available_team_cache is not None:
        return

    rq = {
        'command': 'get_available_teams'
    }
    try:
        rs = communicate(params, rq)
        params.available_team_cache = rs.get('teams')
    except Exception as e:
        logging.debug(e)


def get_team(params,team_uid):
    """Return the referenced team """
    team_uid = team_uid.strip()

    if not team_uid:
        logging.warning('No team UID provided')
        return

    if not params.team_cache:
        logging.warning('No team cache.  Sync down first.')
        return

    if team_uid not in params.team_cache:
        logging.warning('Team UID not found.')
        return

    cached_team = params.team_cache[team_uid]
    team = Team(team_uid)
    team.load(cached_team)

    return team


def search_records(params, searchstring):
    """Search for string in record contents 
       and return array of Record objects """

    p = re.compile(searchstring.lower())
    search_results = []

    for record_uid in params.record_cache:
        rec = get_record(params, record_uid)
        if not rec:
            continue
        cached_rec = params.record_cache[record_uid] or {}

        if cached_rec.get('version') == 3:
            data = cached_rec.get('data_unencrypted')
            rec.record_type = RecordV3.get_record_type_name(data)
            target = RecordV3.values_to_lowerstring(data)
        else:
            target = rec.to_lowerstring()

        if p.search(target):
            search_results.append(rec)
            
    return search_results


def search_shared_folders(params, searchstring):
    """Search shared folders """

    p = re.compile(searchstring.lower())

    search_results = [] 

    for shared_folder_uid in params.shared_folder_cache:

        logging.debug('Getting Shared Folder UID: %s', shared_folder_uid)
        sf = get_shared_folder(params, shared_folder_uid)
        target = sf.to_lowerstring()

        if p.search(target):
            logging.debug('Search success')
            search_results.append(sf)
     
    return search_results


def search_teams(params, searchstring):
    """Search teams """

    p = re.compile(searchstring.lower())

    search_results = [] 

    for team_uid in params.team_cache:
        team = get_team(params, team_uid)

        target = team.to_lowerstring()

        if p.search(target):
            logging.debug('Search success')
            search_results.append(team)
     
    return search_results


def prepare_record(params, record):
    """ Prepares the Record() object to be sent to the Keeper Cloud API
        by serializing and encrypting it in the proper JSON format used for
        transmission.  If the record has no UID, one is generated and the
        encrypted record key is sent to the server.  If this record was
        converted from RSA to AES we send the new record key. If the record
        is in a shared folder, must send shared folder UID for edit permission.
    """

    record_object = {
        'version': 2,
        'client_modified_time': current_milli_time()
    }

    if not record.record_uid:
        logging.debug('Generated Record UID: %s', record.record_uid)
        record.record_uid = generate_record_uid()

    record_object['record_uid'] = record.record_uid

    data = {}
    extra = {}
    udata = {}
    unencrypted_key = None
    if record.record_uid in params.record_cache:
        path = resolve_record_write_path(params, record.record_uid)
        if path:
            record_object.update(path)
        else:
            logging.error('You do not have edit permissions on this record')
            return None

        rec = params.record_cache[record.record_uid]

        data.update(json.loads(rec['data_unencrypted'].decode('utf-8')))
        if data.get('secret2') != record.password:
            params.queue_audit_event('record_password_change', record_uid=record.record_uid)

        if 'extra' in rec:
            extra.update(json.loads(rec['extra_unencrypted'].decode('utf-8')))
        if 'udata' in rec:
            udata.update(rec['udata'])
        unencrypted_key = rec['record_key_unencrypted']
        record_object['revision'] = rec['revision']
        if record.record_uid in params.meta_data_cache and params.meta_data_cache[record.record_uid].get('is_converted_record_type'):
            logging.debug('Converted record sends record key')
            record_object['record_key'] = \
                utils.base64_url_encode(crypto.encrypt_aes_v1(unencrypted_key, params.data_key))
    else:
        logging.debug('Generated record key')
        unencrypted_key = os.urandom(32)
        record_object['record_key'] = utils.base64_url_encode(crypto.encrypt_aes_v1(unencrypted_key, params.data_key))
        record_object['revision'] = 0

    data['title'] = record.title
    data['folder'] = record.folder
    data['secret1'] = record.login
    data['secret2'] = record.password
    data['link'] = record.login_url
    data['notes'] = record.notes
    data['custom'] = record.custom_fields
    Record.validate_record_data(data, extra, udata)

    record_object['data'] = \
        utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(data).encode('utf-8'), unencrypted_key))
    record_object['extra'] = \
        utils.base64_url_encode(crypto.encrypt_aes_v1(json.dumps(extra).encode('utf-8'), unencrypted_key))
    record_object['udata'] = udata

    try:
        if params.license and 'account_type' in params.license:
            if record.password and params.license['account_type'] == 2:
                for record_uid in params.record_cache:
                    if record_uid != record.record_uid:
                        rec = get_record(params, record_uid)
                        if rec.password == record.password:
                            params.queue_audit_event('reused_password', record_uid=record.record_uid)
                            break
    except:
        pass

    return record_object


def prepare_record_v3(params, record):   # type: (KeeperParams, Record) -> Optional[Tuple[dict, Optional[bytes]]]
    """ Prepares the Record() object to be sent to the Keeper Cloud API
        by serializing and encrypting it in the proper JSON format used for
        transmission.  If the record has no UID, one is generated and the
        encrypted record key is sent to the server.  If the record is in a
        shared folder, must send shared folder UID for edit permission.
    """
    if not record.record_uid:
        logging.debug('Generated Record UID: %s', record.record_uid)
        record.record_uid = generate_record_uid()

    record_object = {
        'record_uid': record.record_uid,
        'client_modified_time': current_milli_time()
    }

    audit_data = None
    data = ''
    if record.record_uid in params.record_cache:
        path = resolve_record_write_path(params, record.record_uid)
        if path:
            record_object.update(path)
        else:
            share_admins = get_share_admins_for_record(params, record.record_uid)
            if not share_admins or params.user not in share_admins:
                logging.error('You do not have edit permissions on this record')
                return None
            record_object['record_uid'] = record.record_uid

        rec = params.record_cache[record.record_uid]

        data = rec['data_unencrypted'].decode('utf-8') if isinstance(rec['data_unencrypted'], bytes) else rec['data_unencrypted']
        try:
            if params.enterprise_ec_key:
                d = json.loads(data)
                rt_name = d.get('type') or ''
                fields = itertools.chain(d.get('fields') or [], (d.get('custom') or []))
                url_field = next((u.get('value') for u in fields if u.get('type') == 'url' and u.get('value')), None)
                url = ''
                if url_field and isinstance(url_field, list):
                    url = utils.url_strip(url_field[0])

                adata = {
                    'title': d.get('title', ''),
                    'record_type': rt_name,
                }
                if url:
                    adata['url'] = url  # url will only be supplied if there is one on the record
                audit_data = crypto.encrypt_ec(json.dumps(adata).encode('utf-8'), params.enterprise_ec_key)

        except Exception as e:
            logging.error(bcolors.FAIL + 'Invalid record type! Error: ' + str(e) + bcolors.ENDC)
            return None

        data = pad_aes_gcm(data)

        unencrypted_key = rec['record_key_unencrypted']
        record_object['revision'] = rec['revision']
    else:
        logging.debug('Generated record key')
        unencrypted_key = utils.generate_aes_key()
        key = crypto.decrypt_aes_v2(unencrypted_key, params.data_key)
        key = base64.urlsafe_b64encode(key)
        record_object['record_key'] = key
        record_object['revision'] = 0

    rdata = crypto.encrypt_aes_v2(bytes(data, 'utf-8'), unencrypted_key)
    record_object['data'] = base64.urlsafe_b64encode(rdata).decode('utf-8')

    try:
        if params.license and 'account_type' in params.license:
            if record.password and params.license['account_type'] == 2:
                for record_uid in params.record_cache:
                    if record_uid != record.record_uid:
                        rec = get_record(params, record_uid)
                        if rec.password == record.password:
                            params.queue_audit_event('reused_password', record_uid=record.record_uid)
                            break
    except:
        pass

    return record_object, audit_data


def communicate_rest(params, request, endpoint, *, rs_type=None, payload_version=None):
    api_request_payload = APIRequest_pb2.ApiRequestPayload()
    if params.session_token:
        api_request_payload.encryptedSessionToken = utils.base64_url_decode(params.session_token)
    if request:
        if logging.getLogger().level <= logging.DEBUG:
            js = google.protobuf.json_format.MessageToJson(request)
            logging.debug('>>> [RQ] %s: %s', endpoint, js)
        api_request_payload.payload = request.SerializeToString()
    if isinstance(payload_version, int):
        api_request_payload.apiVersion = payload_version

    rs = rest_api.execute_rest(params.rest_context, endpoint, api_request_payload)
    if isinstance(rs, bytes):
        TTK.update_time_of_last_activity()
        if rs_type:
            proto_rs = rs_type()
            proto_rs.ParseFromString(rs)
            if logging.getLogger().level <= logging.DEBUG:
                js = google.protobuf.json_format.MessageToJson(proto_rs)
                logging.debug('>>> [RS] %s: %s', endpoint, js)
            return proto_rs
        else:
            return rs
    elif isinstance(rs, dict):
        kae = KeeperApiError(rs['error'], rs['message'])
        if kae.result_code == 'session_token_expired':
            params.session_token = None
        raise kae
    raise KeeperApiError('Error', endpoint)


def communicate(params, request):
    # type: (KeeperParams, dict) -> dict

    request['client_time'] = current_milli_time()
    request['locale'] = LOCALE
    request['device_id'] = 'Commander'
    request['session_token'] = params.session_token
    request['username'] = params.user.lower()
    try:
        response_json = run_command(params, request)
        if response_json['result'] != 'success':
            raise KeeperApiError(response_json['result_code'], response_json['message'])
        TTK.update_time_of_last_activity()
        return response_json
    except KeeperApiError as kae:
        if kae.result_code == 'session_token_expired':
            params.session_token = None
        raise kae


def execute_batch(params, requests):
    # type: (KeeperParams, [dict]) -> [dict]
    responses = []
    if not requests:
        return responses

    throttle_delay = 10
    chunk_size = 999
    queue = requests.copy()
    delay_next_batch = False

    while len(queue) > 0:
        chunk = queue[:chunk_size]
        queue = queue[chunk_size:]

        rq = {
            'command': 'execute',
            'requests': chunk
        }
        try:
            if delay_next_batch:
                time.sleep(throttle_delay)
            rs = communicate(params, rq)
            if 'results' in rs:
                results = rs['results']  # type: list
                if len(results) > 0:
                    error_rs = results[-1]
                    throttled = error_rs.get('result') != 'success' and error_rs.get('result_code') == 'throttled'
                    if throttled:
                        delay_next_batch = True
                        results.pop()
                responses.extend(results)

                if len(results) < len(chunk):
                    queue = chunk[len(results):] + queue
        except Exception as e:
            logging.error(e)

    return responses


def update_record(params, record, **kwargs):
    """ Push a record update to the cloud. 
        Takes a Record() object, converts to record JSON
        and pushes to the Keeper cloud API
    """

    if (record and record.record_uid in params.record_cache
            and 'version' in params.record_cache[record.record_uid]
            and params.record_cache[record.record_uid]['version'] == 3):
        return update_record_v3(params, record, **kwargs)

    record_rq = prepare_record(params, record)
    if record_rq is None:
        return

    request = {
        'command': 'record_update',
        'update_records': [record_rq]
    }
    response_json = communicate(params, request)

    new_revision = 0
    if 'update_records' in response_json:
        for info in response_json['update_records']:
            if info['record_uid'] == record.record_uid:
                if info['status'] == 'success':
                    new_revision = response_json['revision']

    if new_revision == 0:
        logging.error('Error: Revision not updated')
        return False

    if new_revision == record_rq['revision']:
        logging.error('Error: Revision did not change')
        return False

    if not kwargs.get('silent'):
        logging.info('Update record successful for record_uid=%s, revision=%d, new_revision=%s',
                     record_rq['record_uid'], record_rq['revision'], new_revision)

    record_rq['revision'] = new_revision

    # sync down the data which updates the caches
    sync_down(params)
    add_record_audit_data(params, [record.record_uid])
    return True


def get_pb2_record_update(params, rec, **kwargs):
    # type: (KeeperParams, Record, ...) -> Optional[dict]
    """Get an instance Protobuf RecordUpdate from an instance of Record (rec)

    Return a dictionary of necessary record items including the Protobuf RecordUpdate instance
    """
    rec_data = prepare_record_v3(params, rec)
    if rec_data is None:
        return
    record_rq, audit = rec_data

    links_by_uid = kwargs.get('record_links_by_uid')
    if links_by_uid:
        links_add_by_uid = links_by_uid.get('record_links_add') or {}
        links_add = links_add_by_uid.get(rec.record_uid) or []
        links_del_by_uid = links_by_uid.get('record_links_remove') or {}
        links_remove = links_del_by_uid.get(rec.record_uid) or []
    else:
        links = kwargs.get('record_links') or {}
        links_add = links.get('record_links_add') or []
        links_remove = links.get('record_links_remove') or []

    record_links_add = []
    for link in links_add:
        rl = record_pb2.RecordLink()
        rl.record_uid = link.get('record_uid')
        rl.record_key = link.get('record_key')
        if rl.record_uid and rl.record_key:
            record_links_add.append(rl)

    record_links_remove = [x['record_uid'] or b'' for x in links_remove]

    ru = record_pb2.RecordUpdate()
    uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(record_rq['record_uid'])
    data = loginv3.CommonHelperMethods.url_safe_str_to_bytes(record_rq['data'])
    ru.record_uid = uid
    ru.client_modified_time = record_rq['client_modified_time']
    ru.revision = record_rq['revision']
    ru.data = data
    #ru.non_shared_data = b''
    if record_links_add:
        ru.record_links_add.extend(record_links_add)
    if record_links_remove:
        ru.record_links_remove.extend(record_links_remove)
    if audit:
        ru.audit.data = audit

    record_rq['pb2_record_update'] = ru
    return record_rq


def get_record_v3_response(params, rq, endpoint, record_rq_by_uid, silent=True):
    # type: (KeeperParams, Any, str, dict[dict], bool) -> Optional[bool]
    rs = communicate_rest(params, rq, endpoint)
    records_modify_rs = record_pb2.RecordsModifyResponse()
    records_modify_rs.ParseFromString(rs)

    for r in records_modify_rs.records:
        ruid = loginv3.CommonHelperMethods.bytes_to_url_safe_str(r.record_uid)
        record_rq = record_rq_by_uid[ruid]
        success = (r.status == record_pb2.RecordModifyResult.DESCRIPTOR.values_by_name['RS_SUCCESS'].number)
        status = record_pb2.RecordModifyResult.DESCRIPTOR.values_by_number[r.status].name

        if not success:
            logging.error(bcolors.FAIL + 'Error: Record update failed with status - %s' + bcolors.ENDC, status)
            return False

        new_revision = 0
        if success:
            new_revision = records_modify_rs.revision

        if new_revision == 0:
            logging.error('Error: Revision not updated')
            return False

        if new_revision == record_rq['revision']:
            logging.error('Error: Revision did not change')
            return False

        if not silent:
            logging.info(
                'Update record successful for record_uid=%s, revision=%d, new_revision=%s',
                ruid, record_rq['revision'], new_revision
            )

        record_rq['revision'] = new_revision

    params.sync_data = True
    return True


def update_record_v3(params, rec, **kwargs):   # type: (KeeperParams, Record, ...) -> Optional[bool]
    """ Push a record update to the cloud.
        Takes a Record() object, converts to record JSON
        and pushes to the Keeper cloud API
    """
    record_rq = get_pb2_record_update(params, rec, **kwargs)
    if not record_rq:
        return
    ru = record_rq['pb2_record_update']
    rq = record_pb2.RecordsUpdateRequest()
    rq.records.append(ru)
    record_rq_by_uid = {rec.record_uid: record_rq}
    return get_record_v3_response(params, rq, 'vault/records_update', record_rq_by_uid, silent=kwargs.get('silent'))


def update_records_v3(params, rec_list, **kwargs):   # type: (KeeperParams, List[Record], ...) -> Optional[bool]
    """ Push a record update to the cloud.
        Takes a Record() object, converts to record JSON
        and pushes to the Keeper cloud API
    """
    rq = record_pb2.RecordsUpdateRequest()
    record_rq_by_uid = {}
    for rec in rec_list:
        record_rq = get_pb2_record_update(params, rec, **kwargs)
        if record_rq:
            record_rq_by_uid[rec.record_uid] = record_rq
            rq.records.append(record_rq['pb2_record_update'])

    return get_record_v3_response(params, rq, 'vault/records_update', record_rq_by_uid)


def add_record(params, record,  **kwargs):   # type: (KeeperParams, Record, any) -> bool

    new_record = prepare_record(params, record)
    request = {
        'command': 'record_add',
        'record_uid': new_record['record_uid'],
        'record_type': 'password',
        'record_key': new_record['record_key'],
        'folder_type': 'user_folder',
        'how_long_ago': 0,
        'data': new_record['data'],
        'extra': new_record['extra'],
    }

    communicate(params, request)

    if not kwargs.get('silent'):
        logging.info('New record successful. record_uid=%s', new_record['record_uid'])

    # update record UID
    record.record_uid = new_record['record_uid']

    # sync down the data which updates the caches
    sync_down(params)
    params.environment_variables[LAST_RECORD_UID] = record.record_uid
    return True


def add_record_audit_data(params, record_uids):   # type: (KeeperParams, Iterable[str]) -> None
    if not params.enterprise_ec_key:
        return

    uids = set((x for x in record_uids if x in params.record_cache))
    audit_data = []   # type: List[record_pb2.RecordAddAuditData]
    for record_uid in uids:
        record = get_record(params, record_uid)
        if record:
            if record.title:
                title = record.title
                if len(title) > 900:
                    title = title[:900]
                audit = record_pb2.RecordAddAuditData()
                audit.record_uid = utils.base64_url_decode(record_uid)
                audit.revision = record.revision
                data = {
                    'title': title,
                    'record_type': record.record_type,
                }
                if record.login_url:
                    data['url'] = utils.url_strip(record.login_url)
                audit.data = crypto.encrypt_ec(json.dumps(data).encode('utf-8'), params.enterprise_ec_key)
                audit_data.append(audit)

    if audit_data:
        rq = record_pb2.AddAuditDataRequest()
        rq.records.extend(audit_data)
        try:
            communicate_rest(params, rq, 'vault/record_add_audit_data')
        except Exception as e:
            logging.info('Failed to store audit data: %s', str(e))


def add_record_v3(params, record, **kwargs):   # type: (KeeperParams, dict, ...) -> Optional[bool]
    """ Push a record update to the cloud.
        Takes a Record() object, converts to record JSON
        and pushes to the Keeper cloud API
    """

    record_rq = record
    if record_rq is None:
        return

    record_links = []
    links = kwargs.get('record_links') or {}
    links = links.get('record_links') or []

    for link in links:
        rl = record_pb2.RecordLink()
        rl.record_uid = link.get('record_uid')
        rl.record_key = link.get('record_key')
        if rl.record_uid and rl.record_key:
            record_links.append(rl)

    uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(record_rq['record_uid'])

    unencrypted_key = record_rq['record_key_unencrypted']
    key = crypto.encrypt_aes_v2(unencrypted_key, params.data_key)
    #key = base64.urlsafe_b64encode(key)

    data = record_rq['data_unencrypted'].decode('utf-8') if isinstance(record_rq['data_unencrypted'], bytes) else record_rq['data_unencrypted']
    try:
        d = json.loads(data)
        rt_name = d.get('type') or ''
        rt_def = RecordV3.resolve_record_type_by_name(params, rt_name)
        res = RecordV3.is_valid_record_type(data, rt_def)
        if not res.get('is_valid'):
            logging.info(res.get('error'))
    except Exception as e:
        logging.error(bcolors.FAIL + 'Invalid record type! Error: ' + str(e) + bcolors.ENDC)
        return None

    # Audit - if the title or url has changed and the user is an enterprise user
    audit = None
    if params.enterprise_ec_key:
        fields = itertools.chain(d.get('fields') or [], (d.get('custom') or []))
        url_field = next((u.get('value') for u in fields if u.get('type') == 'url' and u.get('value')), None)
        url = ''
        if url_field and isinstance(url_field, list):
            if len(url_field) > 0:
                url = utils.url_strip(str(url_field[0]))

        adata = {
            'title': d.get('title', ''),
            'record_type': rt_name,
        }
        if url: adata['url'] = url  # url will only be supplied if there is one on the record
        audit = record_pb2.RecordAudit()
        audit.version = 0
        audit.data = crypto.encrypt_ec(json.dumps(adata).encode('utf-8'), params.enterprise_ec_key)

    data = pad_aes_gcm(data)

    rdata = bytes(data, 'utf-8')
    rdata = crypto.encrypt_aes_v2(rdata, unencrypted_key)

    rq = kwargs.get('rq') or {}
    folder_type = rq.get('folder_type')
    folder_uid = rq.get('folder_uid')
    folder_key = rq.get('folder_key')
    if folder_type:
        folder_type_enum = {
            BaseFolderNode.RootFolderType: record_pb2.RecordFolderType.DESCRIPTOR.values_by_name['user_folder'].number,
            BaseFolderNode.UserFolderType: record_pb2.RecordFolderType.DESCRIPTOR.values_by_name['user_folder'].number,
            BaseFolderNode.SharedFolderType: record_pb2.RecordFolderType.DESCRIPTOR.values_by_name['shared_folder'].number,
            BaseFolderNode.SharedFolderFolderType: record_pb2.RecordFolderType.DESCRIPTOR.values_by_name['shared_folder_folder'].number
        }
        folder_type = folder_type_enum.get(folder_type)

    ra = record_pb2.RecordAdd()
    ra.record_uid = uid
    ra.record_key = key
    ra.client_modified_time = record_rq['client_modified_time']
    ra.data = rdata
    #ra.non_shared_data = b''
    if folder_uid and isinstance(folder_type, int):
        ra.folder_type = folder_type
        ra.folder_uid = loginv3.CommonHelperMethods.url_safe_str_to_bytes(folder_uid)
        if folder_key:
            ra.folder_key = folder_key
    if record_links:
        ra.record_links.extend(record_links)
    if audit:
        #ra.audit = audit # Assignment not allowed to field "audit" in protocol message object.
        ra.audit.version = audit.version
        ra.audit.data = audit.data

    rq = record_pb2.RecordsAddRequest()
    rq.records.append(ra)
    #NB! 'error code (Invalid data) has occurred.' won't return proper status - throws CommunicationError
    rs = communicate_rest(params, rq, 'vault/records_add')
    records_modify_rs = record_pb2.RecordsModifyResponse()
    records_modify_rs.ParseFromString(rs)

    for r in records_modify_rs.records:
        ruid = loginv3.CommonHelperMethods.bytes_to_url_safe_str(r.record_uid)
        success = (r.status == record_pb2.RecordModifyResult.DESCRIPTOR.values_by_name['RS_SUCCESS'].number)
        status = record_pb2.RecordModifyResult.DESCRIPTOR.values_by_number[r.status].name

        if not success:
            logging.error(bcolors.FAIL + 'Error: Record add failed with status - %s' + bcolors.ENDC, status)
            return False

        new_revision = 0
        if success and ruid == record['record_uid']:
            new_revision = records_modify_rs.revision

        if new_revision == 0:
            logging.error('Error: Revision not updated')
            return False

        if not kwargs.get('silent'):
            logging.debug('Add record successful for record_uid=%s, revision=%d', record_rq['record_uid'], new_revision)

        record_rq['revision'] = new_revision

    return True


def delete_record(params, record_uid):
    """ Delete a record """  
    request = {
        'command': 'record_update',
        'delete_records': [record_uid]
    }
    _ = communicate(params, request)
    logging.info('Record deleted with success')
    sync_down(params)
    return True


def generate_record_uid():
    """ Generate url safe base 64 16 byte uid """
    return base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip('=')


def generate_aes_key():
    return os.urandom(32)


def resolve_record_permission_path(params, record_uid, permission):
    # type: (KeeperParams, str, str) -> Optional[Dict]

    for ap in enumerate_record_access_paths(params, record_uid):
        if ap.get(permission):
            path = {
                'record_uid': record_uid
            }
            if 'shared_folder_uid' in ap:
                path['shared_folder_uid'] = ap['shared_folder_uid']
            if 'team_uid' in ap:
                path['team_uid'] = ap['team_uid']
            return path

    return None


def resolve_record_write_path(params, record_uid):
    # type: (KeeperParams, str) -> dict or None
    return resolve_record_permission_path(params, record_uid, 'can_edit')


def resolve_record_share_path(params, record_uid):
    # type: (KeeperParams, str) -> dict or None
    return resolve_record_permission_path(params, record_uid, 'can_share')


def resolve_record_view_path(params, record_uid):
    # type: (KeeperParams, str) -> dict or None
    return resolve_record_permission_path(params, record_uid, 'can_view')


def resolve_record_access_path(params, record_uid, path=None):
    # type: (KeeperParams, str, dict or None) -> dict
    best_path = None

    for ap in enumerate_record_access_paths(params, record_uid):
        use_this_path = False
        if not best_path:
            use_this_path = True
        else:
            if not best_path.get('can_edit') and ap.get('can_edit'):
                use_this_path = True
            elif not best_path.get('can_share') and ap.get('can_share'):
                use_this_path = True
            elif not best_path.get('can_view') and ap.get('can_view'):
                use_this_path = True

        if use_this_path:
            best_path = ap
            if best_path.get('can_edit') and best_path.get('can_share') and best_path.get('can_view'):
                break

    if path is None:
        path = {
            'record_uid': record_uid
        }

    if best_path:
        if 'shared_folder_uid' in best_path:
            path['shared_folder_uid'] = best_path['shared_folder_uid']
        if 'team_uid' in best_path:
            path['team_uid'] = best_path['team_uid']

    return path


def enumerate_record_access_paths(params, record_uid):
    # type: (KeeperParams, str) -> collections.Iterable[dict]

    if record_uid in params.meta_data_cache:
        rmd = params.meta_data_cache[record_uid]
        yield {
            'record_uid': record_uid,
            'can_edit': rmd.get('can_edit') or False,
            'can_share': rmd.get('can_share') or False,
            'can_view': True
        }

    for sf_uid in params.shared_folder_cache:
        sf = params.shared_folder_cache[sf_uid]
        if 'records' in sf:
            sfrs = [x for x in sf['records'] if x['record_uid'] == record_uid]
            if len(sfrs) > 0:
                sfr = sfrs[0]
                is_owner = sfr.get('owner') is True
                if is_owner:
                    can_edit = True
                    can_share = True
                else:
                    can_edit = sfr['can_edit']
                    can_share = sfr['can_share']
                if 'key_type' in sf:
                    yield {
                        'record_uid': record_uid,
                        'shared_folder_uid': sf_uid,
                        'can_edit': can_edit,
                        'can_share': can_share,
                        'can_view': True
                    }
                else:
                    if 'teams' in sf:
                        for sf_team in sf['teams']:
                            team_uid = sf_team['team_uid']
                            if team_uid in params.team_cache:
                                team = params.team_cache[team_uid]
                                yield {
                                    'record_uid': record_uid,
                                    'shared_folder_uid': sf_uid,
                                    'team_uid': team_uid,
                                    'can_edit': can_edit and not team['restrict_edit'],
                                    'can_share': can_share and not team['restrict_share'],
                                    'can_view': not team['restrict_view']
                                }


def get_record_shares(params, record_uids, is_share_admin=False):
    # type: (KeeperParams, Iterable[str], bool) -> List[dict]
    def need_share_info(uid):
        if uid in params.record_cache:
            r = params.record_cache[uid]
            return 'shares' not in r
        return is_share_admin

    result = []
    unique = set(record_uids)
    uids = [x for x in unique if need_share_info(x)]
    try:
        while len(uids) > 0:
            chunk = uids[:999]
            uids = uids[999:]
            rq = record_pb2.GetRecordDataWithAccessInfoRequest()
            rq.clientTime = utils.current_milli_time()
            rq.recordUid.extend([utils.base64_url_decode(x) for x in chunk])
            rq.recordDetailsInclude = record_pb2.SHARE_ONLY
            rs = communicate_rest(params, rq, 'vault/get_records_details',
                                  rs_type=record_pb2.GetRecordDataWithAccessInfoResponse)
            for info in rs.recordDataWithAccessInfo:
                record_uid = utils.base64_url_encode(info.recordUid)
                rec = params.record_cache[record_uid] if record_uid in params.record_cache else {'record_uid': record_uid}  # type: dict
                if 'shares' not in rec:
                    rec['shares'] = {}
                rec['shares']['user_permissions'] = []
                rec['shares']['shared_folder_permissions'] = []
                for up in info.userPermission:
                    oup = {
                        'username': up.username,
                        'owner': up.owner,
                        'share_admin': up.shareAdmin,
                        'shareable': up.sharable,
                        'editable': up.editable,
                    }
                    if up.awaitingApproval:
                        oup['awaiting_approval'] = up.awaitingApproval
                    if up.expiration > 0:
                        oup['expiration'] = up.expiration
                    rec['shares']['user_permissions'].append(oup)
                for sp in info.sharedFolderPermission:
                    osp = {
                        'shared_folder_uid': utils.base64_url_encode(sp.sharedFolderUid),
                        'reshareable': sp.resharable,
                        'editable': sp.editable,
                        'revision': sp.revision,
                    }
                    if sp.expiration > 0:
                        osp['expiration'] = sp.expiration
                    rec['shares']['shared_folder_permissions'].append(osp)

                if record_uid not in params.record_cache:
                    result.append(rec)
    except Exception as e:
        logging.error(e)

    if len(result) > 0:
        return result


def query_enterprise(params, force=False, tree_key=None):
    try:
        if force is True and params.enterprise:
            params.enterprise = None
        qe(params, tree_key=tree_key)
    except Exception as e:
        share_account_by = params.get_share_account_timestamp()
        share_account_expired = share_account_by and datetime.today() > share_account_by
        # An exception is expected here if an Account Transfer is expired
        if share_account_expired:
            params.enterprise = None
        else:
            logging.warning(e, exc_info=True)


def login_and_get_mc_params_login_v3(params: KeeperParams, mc_id):

    resp = loginv3.LoginV3API.loginToMc(params.rest_context, params.session_token, mc_id)

    mc_params = KeeperParams(server=params.server)

    mc_params.config = params.config
    mc_params.debug = params.debug
    mc_params.auth_verifier = params.auth_verifier
    mc_params.salt = params.salt
    mc_params.iterations = params.iterations
    mc_params.user = params.user
    mc_params.account_uid_bytes = params.account_uid_bytes
    mc_params.password = params.password
    mc_params.enterprise_id = mc_id
    mc_params.session_token = params.session_token
    mc_params.data_key = params.data_key
    mc_params.rsa_key = params.rsa_key
    mc_params.rsa_key2 = params.rsa_key2
    mc_params.ecc_key = params.ecc_key

    mc_params.session_token = loginv3.CommonHelperMethods.bytes_to_url_safe_str(resp.encryptedSessionToken)
    mc_params.msp_tree_key = params.enterprise['unencrypted_tree_key']
    tree_key = crypto.decrypt_aes_v2(utils.base64_url_decode(resp.encryptedTreeKey), mc_params.msp_tree_key)

    sync_down(mc_params)
    query_enterprise(mc_params, True, tree_key=tree_key)

    return mc_params


def login_and_get_mc_params(params, mc_id):
    mc_params = KeeperParams(server=params.server)
    mc_params.config = params.config
    mc_params.auth_verifier = params.auth_verifier
    mc_params.salt = params.salt
    mc_params.iterations = params.iterations
    mc_params.user = params.user
    mc_params.password = params.password
    mc_params.account_uid_bytes = params.account_uid_bytes
    mc_params.enterprise_id = mc_id
    mc_params.msp_tree_key = params.enterprise['unencrypted_tree_key']
    mc_params.session_token = None

    login(mc_params)
    query_enterprise(mc_params)

    return mc_params


def get_correct_salt(salts):
    if len(salts) > 1:
        salt = next((s for s in salts if s.name.lower() == 'alternate'), salts[0])
    else:
        salt = salts[0]
    return salt


def send_keepalive(params):
    """Send a keepalive to the server, using protobufs."""
    communicate_rest(params, None, 'keep_alive')


def load_records_in_shared_folder(params, shared_folder_uid, record_uids=None):
    # type: (KeeperParams, str, Optional[Iterable[str]]) -> None

    if shared_folder_uid not in params.shared_folder_cache:
        raise Exception(f'Shared folder \"{shared_folder_uid}\" is not loaded.')
    shared_folder = params.shared_folder_cache[shared_folder_uid]
    shared_folder_key = shared_folder['shared_folder_key_unencrypted']
    record_keys = {}    # type: Dict[str, bytes]
    for rk in shared_folder.get('records', []):
        record_uid = rk.get('record_uid')
        try:
            key = utils.base64_url_decode(rk['record_key'])
            if len(key) == 60:
                record_key = crypto.decrypt_aes_v2(key, shared_folder_key)
            else:
                record_key = crypto.decrypt_aes_v1(key, shared_folder_key)
            record_keys[record_uid] = record_key
        except Exception as e:
            logging.debug('Cannot decrypt record \"%s\" key: %s', record_uid, e)

    if record_uids:
        record_set = set(record_uids)
        record_set.intersection_update(record_keys.keys())
    else:
        record_set = set(record_keys.keys())
    record_set.difference_update(params.record_cache.keys())

    while len(record_set) > 0:
        rq = record_pb2.GetRecordDataWithAccessInfoRequest()
        rq.clientTime = utils.current_milli_time()
        rq.recordDetailsInclude = record_pb2.DATA_PLUS_SHARE
        for uid in record_set:
            try:
                rq.recordUid.append(utils.base64_url_decode(uid))
            except Exception as e:
                logging.debug('Incorrect record UID \"%s\": %s', uid, e)
        record_set.clear()

        rs = communicate_rest(params, rq, 'vault/get_records_details', rs_type=record_pb2.GetRecordDataWithAccessInfoResponse)
        for record_info in rs.recordDataWithAccessInfo:
            record_uid = utils.base64_url_encode(record_info.recordUid)
            record_data = record_info.recordData
            try:
                if record_data.ownerRecordUid and record_data.encryptedLinkedRecordKey:
                    owner_id = utils.base64_url_encode(record_data.ownerRecordUid)
                    if owner_id in record_keys:
                        record_keys[record_uid] = crypto.decrypt_aes_v2(record_data.encryptedLinkedRecordKey, record_keys[owner_id])

                if record_uid not in record_keys:
                    continue

                record_key = record_keys[record_uid]
                version = record_data.version
                record = {
                    'record_uid': record_uid,
                    'revision': record_data.revision,
                    'version': version,
                    'shared': record_data.shared,
                    'data': record_data.encryptedRecordData,
                    'record_key_unencrypted': record_keys[record_uid],
                    'client_modified_time': record_data.clientModifiedTime,
                }
                data_decoded = utils.base64_url_decode(record_data.encryptedRecordData)
                if version <= 2:
                    record['data_unencrypted'] = crypto.decrypt_aes_v1(data_decoded, record_key)
                else:
                    record['data_unencrypted'] = crypto.decrypt_aes_v2(data_decoded, record_key)

                if record_data.encryptedExtraData and version <= 2:
                    record['extra'] = record_data.encryptedExtraData
                    extra_decoded = utils.base64_url_decode(record_data.encryptedExtraData)
                    record['extra_unencrypted'] = crypto.decrypt_aes_v1(extra_decoded, record_key)
                    record_data['udata'] = {
                        'file_id': []
                    }
                if version == 3:
                    v3_record = vault.KeeperRecord.load(params, record)
                    if isinstance(v3_record, vault.TypedRecord):
                        for ref in itertools.chain(v3_record.fields, v3_record.custom):
                            if ref.type.endswith('Ref') and isinstance(ref.value, list):
                                record_set.update(ref.value)
                elif version == 4:
                    if record_data.fileSize > 0:
                        record['file_size'] = record_data.fileSize
                    if record_data.thumbnailSize > 0:
                        record['thumbnail_size'] = record_data.thumbnailSize
                if record_data.ownerRecordUid and record_data.encryptedLinkedRecordKey:
                    record['owner_uid'] = utils.base64_url_encode(record_data.ownerRecordUid)
                    record['link_key'] = utils.base64_url_encode(record_data.encryptedLinkedRecordKey)

                record['shares'] = {
                    'user_permissions': [{
                        'username': up.username,
                        'owner': up.owner,
                        'share_admin': up.shareAdmin,
                        'shareable': up.sharable,
                        'editable': up.editable,
                        'awaiting_approval': up.awaitingApproval,
                        'expiration': up.expiration,
                    } for up in record_info.userPermission],
                    'shared_folder_permissions': [{
                        'shared_folder_uid': utils.base64_url_encode(sp.sharedFolderUid),
                        'reshareable': sp.resharable,
                        'editable': sp.editable,
                        'revision': sp.revision,
                        'expiration': sp.expiration,
                    } for sp in record_info.sharedFolderPermission],
                }

                params.record_cache[record_uid] = record
            except Exception as e:
                logging.debug('Error decrypting record \"%s\": %s', record_uid, e)
        record_set.difference_update(params.record_cache.keys())
