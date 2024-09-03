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
import json
import logging
from urllib.parse import urlparse, urlunparse
from typing import Iterator, Tuple, Optional, List, Callable, Dict, Iterable, Union

from .commands.helpers.enterprise import user_has_privilege, is_addon_enabled
from .constants import KEEPER_PUBLIC_HOSTS
from . import api, crypto, utils, rest_api, vault
from .proto import breachwatch_pb2, client_pb2, APIRequest_pb2
from .error import KeeperApiError, CommandError
from .params import KeeperParams
from .vault import KeeperRecord


class BreachWatch(object):
    def __init__(self):
        self.rest_api = None
        self.domain_token = None
        self.email_token = None
        self.password_token = None
        self.send_audit_events = False

    @staticmethod
    def extract_password(record):     # type: (vault.KeeperRecord) -> Optional[str]
        if isinstance(record, vault.PasswordRecord):
            return record.password
        if isinstance(record, vault.TypedRecord):
            password_field = record.get_typed_field('password')
            if password_field:
                return password_field.get_default_value(str)

    @staticmethod
    def extract_url(record):     # type: (vault.KeeperRecord) -> Optional[str]
        if isinstance(record, vault.PasswordRecord):
            return record.link
        if isinstance(record, vault.TypedRecord):
            url_field = record.get_typed_field('url')
            if url_field:
                return url_field.get_default_value(str)

    def scan_password(self, params, password, euid=None):
        # type: (KeeperParams, str, Optional[bytes]) -> Optional[breachwatch_pb2.HashStatus]

        bw_hash = utils.breach_watch_hash(password)
        if not euid:
            score = utils.password_score(password)
            if score < 40:
                result = breachwatch_pb2.HashStatus()
                result.hash1 = bw_hash
                result.breachDetected = True
                return result

        self._ensure_init(params)
        check = breachwatch_pb2.HashCheck()
        check.hash1 = bw_hash
        if euid:
            check.euid = euid
        rq = breachwatch_pb2.BreachWatchStatusRequest()
        rq.hashCheck.append(check)
        rs = self._execute_status(rq)
        return rs.hashStatus[0]

    def scan_passwords(self, params, passwords):
        # type: (KeeperParams, Iterator[str]) -> Iterator[Tuple[str, breachwatch_pb2.HashStatus]]
        results = {}      # type: Dict[str, breachwatch_pb2.HashStatus]
        bw_hashes = {}    # type: Dict[bytes, str]
        for password in passwords:
            if isinstance(password, str) and len(password) > 0:
                score = utils.password_score(password)
                bw_hash = utils.breach_watch_hash(password)
                if score >= 40:
                    bw_hashes[bw_hash] = password
                else:
                    status = breachwatch_pb2.HashStatus()
                    status.hash1 = bw_hash
                    status.breachDetected = True
                    results[password] = status
        if len(bw_hashes) > 0:
            logging.info('Breachwatch: %d passwords to scan', len(bw_hashes))
            hashes = []     # type: List[breachwatch_pb2.HashCheck]
            for bw_hash in bw_hashes:
                check = breachwatch_pb2.HashCheck()
                check.hash1 = bw_hash
                hashes.append(check)
            self._ensure_init(params)

            while len(hashes) > 0:
                chunk = hashes[:500]
                hashes = hashes[500:]

                rq = breachwatch_pb2.BreachWatchStatusRequest()
                rq.hashCheck.extend(chunk)

                rs = self._execute_status(rq)
                for status in rs.hashStatus:
                    password = bw_hashes.get(status.hash1)
                    if isinstance(password, str) and len(password) > 0:
                        results[password] = status

        for password in results:
            yield password, results[password]

    def scan_and_store_record_status(self, params, record, force_update=False):
        # type: (KeeperParams, KeeperRecord, Optional[bool]) -> None
        def get_euid():
            result = None
            if bw_record:
                bw_pw_objs = bw_record.get('data_unencrypted', {}).get('passwords', [])
                euids = [x.get('euid') for x in bw_pw_objs if x.get('euid')]
                if euids:
                    result = base64.b64decode(next(iter(euids)))
            return result

        def get_last_pw():
            result = ''
            if bw_record:
                bw_pw_objs = bw_record.get('data_unencrypted', {}).get('passwords', [])
                passwords = [x.get('value') for x in bw_pw_objs if x.get('value')]
                if passwords:
                    result = next(iter(passwords))
            return result

        def update_bw_data():
            result = None
            bwrq = breachwatch_pb2.BreachWatchRecordRequest()
            bwrq.recordUid = utils.base64_url_decode(record_uid)
            bwrq.breachWatchInfoType = breachwatch_pb2.RECORD
            bwrq.updateUserWhoScanned = True
            bw_data = client_pb2.BreachWatchData()

            if record_password:
                hash_status = self.scan_password(params, record_password, get_euid())

                if hash_status.breachDetected:
                    logging.info('High-Risk password detected')
                    if self.send_audit_events:
                        params.queue_audit_event('bw_record_high_risk')
                bw_password = client_pb2.BWPassword()
                bw_password.value = record_password
                bw_password.status = client_pb2.WEAK if hash_status.breachDetected else client_pb2.GOOD
                bw_password.euid = hash_status.euid
                bw_data.passwords.append(bw_password)
                result = bw_password.status
            try:
                data = bw_data.SerializeToString()
                record_key = params.record_cache[record_uid]['record_key_unencrypted']
                bwrq.encryptedData = crypto.encrypt_aes_v2(data, record_key)
                rq = breachwatch_pb2.BreachWatchUpdateRequest()
                rq.breachWatchRecordRequest.append(bwrq)
                rs = api.communicate_rest(params, rq, 'breachwatch/update_record_data',
                                          rs_type=breachwatch_pb2.BreachWatchUpdateResponse)
                status = rs.breachWatchRecordStatus[0]
                if status.reason:
                    raise Exception(status.reason)
            except Exception as e:
                logging.warning('BreachWatch: %s', str(e))
            return result

        def skip_update():
            if record_password == get_last_pw():
                return True
            return False

        record_uid = record.record_uid
        bw_record = params.breach_watch_records.get(record_uid) if params.breach_watch_records else None

        record_password = BreachWatch.extract_password(record) or ''
        if skip_update():
            return None

        bw_res = update_bw_data()
        if not record_password:
            euid = get_euid()
            if euid:
                params.breach_watch.delete_euids(params, [euid])
        api.sync_down(params)
        return bw_res

    @staticmethod
    def update_security_data(params, record, bw_result=None, force_update=False):
        # type: (KeeperParams, KeeperRecord, Optional[int], Optional[bool]) -> None
        def calculate_security_data():  # type: () -> APIRequest_pb2.SecurityData
            def prepare_security_data():
                strength = utils.password_score(record_pw)
                result = {'strength': strength}
                if bw_result is not None:
                    result['bw_result'] = bw_result
                elif bw_enabled:
                    logging.error(f'No BreachWatch status for record {record.record_uid}')

                url = BreachWatch.extract_url(record)
                parse_results = urlparse(url)
                domain = parse_results.hostname or parse_results.path
                if domain:
                    # truncate domain string if needed to avoid reaching RSA encryption data size limitation
                    result['domain'] = domain[:200]
                return result

            sec_data = APIRequest_pb2.SecurityData()
            sec_data.uid = utils.base64_url_decode(record.record_uid)
            if record_pw:
                rec_sd = prepare_security_data()
                sec_data.data = crypto.encrypt_rsa(json.dumps(rec_sd).encode('utf-8'), params.enterprise_rsa_key)

            return sec_data

        def skip_update():
            # Allow for enterprise users only
            if not params.enterprise_ec_key:
                return True

            if force_update:
                return False

            security_data = params.breach_watch_security_data.get(record_uid, {}) if params.breach_watch_security_data \
                else {}
            bw_data = params.breach_watch_records.get(record_uid, {}) if params.breach_watch_records \
                else {}

            # Ignore records with no password and no security data
            if not record_pw and not security_data:
                return True

            # Check if security data is already up-to-date
            sd_revision = security_data.get('revision', 0)
            return (sd_revision >= bw_data.get('revision', 0)) if bw_enabled else (sd_revision >= record.revision)

        if not record:
            return

        record_uid = record.record_uid
        record_pw = BreachWatch.extract_password(record)
        bw_enabled = bool(params.breach_watch)
        if skip_update():
            return

        update_rq = APIRequest_pb2.SecurityDataRequest()
        rec_sec_data = calculate_security_data()
        update_rq.recordSecurityData.append(rec_sec_data)
        api.communicate_rest(params, update_rq, 'enterprise/update_security_data')

    @staticmethod
    def save_reused_pw_count(params):
        def get_reused_pw_count(recs):   # type: (Iterable[vault.KeeperRecord]) -> int
            pw_counts = {}
            for rec in recs:
                pw = BreachWatch.extract_password(rec)
                if pw:
                    pw_count = pw_counts.get(pw, 0)
                    pw_counts[pw] = pw_count + 1

            dupe_pw_counts = {k: v for k, v in pw_counts.items() if v > 1}
            return sum([count for count in dupe_pw_counts.values()])

        if params.enterprise_ec_key:
            api.sync_down(params)
            owned = [uid for uid, own in params.record_owner_cache.items()
                              if own.owner is True and uid in params.record_cache]
            owned_recs = [x for x in (vault.KeeperRecord.load(params, ruid) for ruid in owned)
                          if x and x.version in (2, 3)]
            total_reused = get_reused_pw_count(owned_recs)
            save_rq = APIRequest_pb2.ReusedPasswordsRequest()
            save_rq.count = total_reused
            api.communicate_rest(params, save_rq, 'enterprise/set_reused_passwords')

    def delete_euids(self, params, euids):
        self._ensure_init(params)
        while euids:
            chunk = euids[:999]
            euids = euids[999:]
            rq = breachwatch_pb2.BreachWatchStatusRequest()
            rq.removedEuid.extend(chunk)
            self._execute_status(rq)

    def _execute_status(self, rq):
        rq.anonymizedToken = self.password_token
        api_request_payload = APIRequest_pb2.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()
        rs = rest_api.execute_rest(self.rest_api, 'breachwatch/status', api_request_payload)
        if isinstance(rs, bytes):
            bw_rs = breachwatch_pb2.BreachWatchStatusResponse()
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
                                  rs_type=breachwatch_pb2.BreachWatchTokenResponse)
        if rs.clientEncrypted:
            enc_token = rs.breachWatchToken
            breach_watch_token = crypto.decrypt_aes_v2(enc_token, params.data_key)
        else:
            breach_watch_token = rs.breachWatchToken
            enc_token = crypto.encrypt_aes_v2(breach_watch_token, params.data_key)
            rq = breachwatch_pb2.BreachWatchTokenRequest()
            rq.breachWatchToken = enc_token
            api.communicate_rest(params, rq, 'breachwatch/save_token')

        rq = breachwatch_pb2.BreachWatchTokenRequest()
        rq.breachWatchToken = breach_watch_token
        rs = api.communicate_rest(params, rq, 'breachwatch/anonymize_token',
                                  rs_type=breachwatch_pb2.AnonymizedTokenResponse)
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
            data_obj = bw_record.get('data_unencrypted')
            if data_obj and 'passwords' in data_obj:
                record = vault.KeeperRecord.load(params, record_uid)
                if record:
                    record_password = BreachWatch.extract_password(record)
                    if record_password:
                        return next((x for x in data_obj['passwords'] if x.get('value', '') == record_password), None)

    @staticmethod
    def get_records(params,            # type: KeeperParams
                    callback,          # type: Callable[[vault.KeeperRecord, Optional[dict]], bool]
                    owned=False        # type: bool
                    ):                 # type: (...) -> Iterator[Tuple[vault.KeeperRecord, Optional[dict]]]
        if not params.record_cache:
            return

        for record_uid in params.record_cache:
            record = vault.KeeperRecord.load(params, record_uid)
            if not record:
                continue
            if owned:
                if record_uid not in params.record_owner_cache:
                    continue
                if not params.record_owner_cache[record_uid].owner is True:
                    continue

            password = BreachWatch.extract_password(record)
            if not password:
                continue

            if isinstance(password, str) and password:
                password_dict = None
                if params.breach_watch_records:
                    bwr = params.breach_watch_records.get(record_uid)
                    data_obj = bwr.get('data_unencrypted') if bwr else None
                    if data_obj and 'passwords' in data_obj:
                        password_dict = next((x for x in data_obj['passwords'] if x.get('value', '') == password), None)
                if callback(record, password_dict):
                    yield record, password_dict

    @staticmethod
    def get_records_to_scan(params):  # type: (KeeperParams) -> Iterator[Tuple[vault.KeeperRecord, Optional[dict]]]
        yield from BreachWatch.get_records(params, lambda r, b: b is None, owned=True)

    @staticmethod
    def check_status(bwr, statuses):
        if isinstance(bwr, dict) and isinstance(statuses, set):
            return bwr.get('status', '').casefold() in statuses
        return False

    @staticmethod
    def get_records_by_status(params, status, owned=False):
        # type: (KeeperParams, Optional[str, List[str]], bool) -> Iterator[Tuple[vault.KeeperRecord, Optional[dict]]]
        statuses = set()
        if status:
            if isinstance(status, list):
                statuses.update((x.casefold() for x in status if isinstance(x, str)))
            elif isinstance(status, str):
                statuses.add(status.casefold())
        else:
            statuses.update((x.casefold() for x in client_pb2.BWStatus.keys()))

        yield from params.breach_watch.get_records(params, lambda r, b: BreachWatch.check_status(b, statuses), owned)


    @staticmethod
    def scan_and_update_security_data(params, record_uid, bw_obj=None, force_update=False, set_reused_pws=True):
        # type: (KeeperParams, Union[str, List[str]], Optional[BreachWatch], Optional[bool], Optional[bool]) -> None
        api.sync_down(params)
        record = vault.KeeperRecord.load(params, record_uid)
        if not record:
            return
        if not isinstance(record, (vault.PasswordRecord, vault.TypedRecord)):
            return

        bw_res = bw_obj.scan_and_store_record_status(params, record, force_update) if bw_obj else None
        BreachWatch.update_security_data(params, record, force_update=force_update, bw_result=bw_res)
        if set_reused_pws:
            BreachWatch.save_reused_pw_count(params)
        api.sync_down(params)

    @staticmethod
    def validate_reporting(cmd, params):
        msg_no_priv = 'You do not have the required privilege to run a BreachWatch report'
        msg_no_addon = ('BreachWatch is not enabled for this enterprise. '
                        'Please visit https://www.keepersecurity.com/breachwatch.html for more information.')

        privilege = 'run_reports'
        addon = 'enterprise_breach_watch'
        error_msg = msg_no_priv if not user_has_privilege(params, privilege) \
            else msg_no_addon if not is_addon_enabled(params, addon) \
            else None
        if error_msg:
            raise CommandError(cmd, error_msg)
