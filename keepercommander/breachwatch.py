#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import base64
import logging
from urllib.parse import urlparse, urlunparse
from typing import Iterator, Tuple, Optional, List, Callable, Union

from .constants import KEEPER_PUBLIC_HOSTS
from . import api, crypto, utils, rest_api
from .proto import breachwatch_pb2 as breachwatch_proto, client_pb2 as client_proto
from .proto import APIRequest_pb2 as api_request_proto
from .error import KeeperApiError
from .record import Record
from .params import KeeperParams


class BreachWatch(object):
    def __init__(self):
        self.rest_api = None
        self.domain_token = None
        self.email_token = None
        self.password_token = None
        self.send_audit_events = False

    def scan_password(self, params, password, euid=None):
        # type: (KeeperParams, str, Optional[bytes]) -> Optional[breachwatch_proto.HashStatus]

        bw_hash = utils.breach_watch_hash(password)
        if not euid:
            score = utils.password_score(password)
            if score < 40:
                result = breachwatch_proto.HashStatus()
                result.hash1 = bw_hash
                result.breachDetected = True
                return result

        self._ensure_init(params)
        check = breachwatch_proto.HashCheck()
        check.hash1 = bw_hash
        if euid:
            check.euid = euid
        rq = breachwatch_proto.BreachWatchStatusRequest()
        rq.hashCheck.append(check)
        rs = self._execute_status(rq)
        return rs.hashStatus[0]

    def scan_passwords(self, params, passwords):  # type: (any, Iterator[str]) -> Iterator[Tuple[str, any]]
        results = {}
        hashes = {}
        if passwords:
            for password in passwords:
                score = utils.password_score(password)
                bw_hash = utils.breach_watch_hash(password)
                if score >= 40:
                    hashes[bw_hash] = password
                else:
                    status = breachwatch_proto.HashStatus()
                    status.hash1 = bw_hash
                    status.breachDetected = True
                    results[password] = status
        if len(hashes) > 0:
            rq = breachwatch_proto.BreachWatchStatusRequest()
            for hash in hashes:
                check = breachwatch_proto.HashCheck()
                check.hash1 = hash
                rq.hashCheck.append(check)
            self._ensure_init(params)
            rs = self._execute_status(rq)
            for status in rs.hashStatus:
                results[hashes[status.hash1]] = status

        for password in results:
            yield password, results[password]

    def scan_and_store_record_status(self, params, record_uid):  # type: (KeeperParams, str) -> None
        record = api.get_record(params, record_uid)
        if not record:
            return

        bw_record = params.breach_watch_records.get(record_uid) if params.breach_watch_records else None
        if record.password:
            euid = None
            if bw_record:
                data_obj = bw_record.get('data_unencrypted')
                if data_obj and 'passwords' in data_obj:
                    password = next((x for x in data_obj['passwords'] if x.get('value', '') == record.password), None)
                    if password:
                        return
                    euid = next((base64.b64decode(x['euid']) for x in data_obj['passwords'] if 'euid' in x), None)

            hash_status = self.scan_password(params, record.password, euid)
            if hash_status.breachDetected:
                logging.info('High-Risk password detected')
                if self.send_audit_events:
                    params.queue_audit_event('bw_record_high_risk')

            bwrq = breachwatch_proto.BreachWatchRecordRequest()
            bwrq.recordUid = utils.base64_url_decode(record_uid)
            bwrq.breachWatchInfoType = breachwatch_proto.RECORD
            bwrq.updateUserWhoScanned = True
            bw_password = client_proto.BWPassword()
            bw_password.value = record.password
            bw_password.status = client_proto.WEAK if hash_status.breachDetected else client_proto.GOOD
            bw_password.euid = hash_status.euid
            bw_data = client_proto.BreachWatchData()
            bw_data.passwords.append(bw_password)
            data = bw_data.SerializeToString()
            try:
                record_key = params.record_cache[record_uid]['record_key_unencrypted']
                bwrq.encryptedData = crypto.encrypt_aes_v2(data, record_key)
                rq = breachwatch_proto.BreachWatchUpdateRequest()
                rq.breachWatchRecordRequest.append(bwrq)
                rs = api.communicate_rest(params, rq, 'breachwatch/update_record_data',
                                          rs_type=breachwatch_proto.BreachWatchUpdateResponse)
                status = rs.breachWatchRecordStatus[0]
                if status.reason:
                    raise Exception(status.reason)
            except Exception as e:
                logging.warning('BreachWatch: %s', str(e))

    def delete_euids(self, params, euids):
        self._ensure_init(params)
        while euids:
            chunk = euids[:999]
            euids = euids[999:]
            rq = breachwatch_proto.BreachWatchStatusRequest()
            rq.removedEuid.extend(chunk)
            self._execute_status(rq)

    def _execute_status(self, rq):
        rq.anonymizedToken = self.password_token
        api_request_payload = api_request_proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()
        rs = rest_api.execute_rest(self.rest_api, 'breachwatch/status', api_request_payload)
        if isinstance(rs, bytes):
            bw_rs = breachwatch_proto.BreachWatchStatusResponse()
            bw_rs.ParseFromString(rs)
            return bw_rs
        elif isinstance(rs, dict):
            raise KeeperApiError(rs['error'], rs['message'])
        raise KeeperApiError('Error', 'breachwatch/status')

    def _ensure_init(self, params):
        if self.rest_api:
            if not self.password_token:
                raise KeeperApiError('not_initialized', 'BreachWatch init error.')
            return

        url_comp = urlparse(params.rest_context.server_base)
        us_server = KEEPER_PUBLIC_HOSTS['US']
        if not url_comp.netloc.endswith(us_server):
            for region in KEEPER_PUBLIC_HOSTS.values():
                if url_comp.netloc.endswith(region):
                    url_comp = url_comp._replace(netloc=url_comp.netloc[0: -len(region)] + us_server)
                    break
        bw_endpoint = rest_api.RestApiContext(server=urlunparse(url_comp), locale=params.rest_context.locale)
        bw_endpoint.server_key_id = params.rest_context.server_key_id
        self.rest_api = bw_endpoint

        rs = api.communicate_rest(params, None, 'breachwatch/initialize',
                                  rs_type=breachwatch_proto.BreachWatchTokenResponse)
        if rs.clientEncrypted:
            enc_token = rs.breachWatchToken
            breach_watch_token = crypto.decrypt_aes_v2(enc_token, params.data_key)
        else:
            breach_watch_token = rs.breachWatchToken
            enc_token = crypto.encrypt_aes_v2(breach_watch_token, params.data_key)
            rq = breachwatch_proto.BreachWatchTokenRequest()
            rq.breachWatchToken = enc_token
            api.communicate_rest(params, rq, 'breachwatch/save_token')

        rq = breachwatch_proto.BreachWatchTokenRequest()
        rq.breachWatchToken = breach_watch_token
        rs = api.communicate_rest(params, rq, 'breachwatch/anonymize_token',
                                  rs_type=breachwatch_proto.AnonymizedTokenResponse)
        self.domain_token = rs.domainToken
        self.email_token = rs.emailToken
        self.password_token = rs.passwordToken

        if params.enforcements:
            pass

    @staticmethod
    def get_record_status(params, record_uid):  # type: (KeeperParams, str) -> Optional[dict]
        if not params.breach_watch_records:
            return
        bw_record = params.breach_watch_records.get(record_uid)
        if bw_record:
            data_obj = bw_record['data_unencrypted']
            if data_obj and 'passwords' in data_obj:
                record = api.get_record(params, record_uid)
                return next((x for x in data_obj['passwords'] if x.get('value', '') == record.password), None)

    @staticmethod
    def get_records(params, callback, owned=False):
        # type: (KeeperParams, Callable[[Record, Optional[dict]], bool], bool) -> Iterator[Tuple[Record, Optional[dict]]]
        if not params.record_cache:
            return
        for record_uid in params.record_cache:
            record = api.get_record(params, record_uid)
            if not record:
                continue
            if not record.password:
                continue
            if owned:
                if record_uid not in params.meta_data_cache:
                    continue
                meta_data = params.meta_data_cache[record_uid]
                if not meta_data.get('owner'):
                    continue
            password_dict = None
            if params.breach_watch_records:
                bwr = params.breach_watch_records.get(record_uid)
                data_obj = bwr['data_unencrypted'] if bwr else None
                if data_obj and 'passwords' in data_obj:
                    password_dict = next((x for x in data_obj['passwords'] if x.get('value', '') == record.password), None)
            if callback(record, password_dict):
                yield record, password_dict

    @staticmethod
    def get_records_to_scan(params):  # type: (KeeperParams) -> Iterator[Record]
        yield from BreachWatch.get_records(params, lambda r, b: b is None, owned=True)

    @staticmethod
    def check_status(bwr, statuses):
        if isinstance(bwr, dict) and isinstance(statuses, set):
            return bwr.get('status', '').casefold() in statuses
        return False

    @staticmethod
    def get_records_by_status(params, status, owned=False):
        # type: (KeeperParams, Optional[str, List[str]], bool) -> Iterator[Record]
        statuses = set()
        if status:
            if isinstance(status, list):
                statuses.update((x.casefold() for x in status if isinstance(x, str)))
            elif isinstance(status, str):
                statuses.add(status.casefold())
        else:
            statuses.update((x.casefold() for x in client_proto.BWStatus.keys()))

        yield from params.breach_watch.get_records(params, lambda r, b: BreachWatch.check_status(b, statuses), owned)
