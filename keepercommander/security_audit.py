import json
import logging
import urllib
from typing import Union, List, Dict
from urllib import parse

from . import utils, crypto
from .error import KeeperApiError
from .params import KeeperParams
from .proto import APIRequest_pb2, client_pb2, enterprise_pb2, record_pb2
from .utils import is_pw_strong
from .vault import KeeperRecord, TypedRecord, PasswordRecord

def has_passkey(record):   # type: (KeeperRecord) -> bool
    if not isinstance(record, TypedRecord) or not record.get_typed_field('passkey'):
        return False
    return bool(record.get_typed_field('passkey').value)

def _get_pass(record):  # type: (KeeperRecord) -> Union[str, None]
    from .breachwatch import BreachWatch
    return BreachWatch.extract_password(record) or None

def get_security_score(record): # type: (KeeperRecord) -> Union[int, None]
    password = _get_pass(record)
    return utils.password_score(password) or has_passkey(record) and 100 or 0

def encrypt_security_data(params, data):
    try:
        if params.forbid_rsa and not params.enterprise_ec_key:
            raise Exception('Enterprise ECC public key is not available')

        if not params.forbid_rsa and not params.enterprise_rsa_key:
            raise Exception('Enterprise RSA public key is not available')

        data = json.dumps(data).encode('utf8')
        pubkey = params.enterprise_ec_key if params.forbid_rsa else params.enterprise_rsa_key
        encrypt_fn = crypto.encrypt_ec if params.forbid_rsa else crypto.encrypt_rsa
        data = encrypt_fn(data, pubkey)
    except Exception as e:
        logging.error(f'Error: {e}')
        data = b''
    return data

def prep_security_data(params, record):
    get_bw_obj = lambda rec: next(
        iter(params.breach_watch_records.get(rec, {}).get('data_unencrypted', {}).get('passwords', [])),
        {}) if params.breach_watch else None

    from .breachwatch import BreachWatch
    score = get_security_score(record)
    # Send empty object to remove old security data (when password and/or passkey are removed)
    sec_data = b''
    if score:
        sec_data = {'strength': score}
        password = _get_pass(record)
        login_url = BreachWatch.extract_url(record)
        parse_results = urllib.parse.urlparse(login_url)
        domain = parse_results.hostname or parse_results.path
        pw_obj = get_bw_obj(record.record_uid)
        if pw_obj is not None and password:
            status = pw_obj.get('status')
            sec_data['bw_result'] = client_pb2.BWStatus.Value(status) if status \
                else client_pb2.BWStatus.GOOD if is_pw_strong(score) \
                else client_pb2.BWStatus.WEAK
        if domain:
            # truncate domain string if needed to avoid reaching RSA encryption data size limitation
            sec_data['domain'] = domain[:200]
        sec_data = encrypt_security_data(params, sec_data)
    return sec_data

def prep_security_data_update(params, record): # type: (KeeperParams, KeeperRecord) -> APIRequest_pb2.SecurityData
    sd = APIRequest_pb2.SecurityData()
    sd.uid = utils.base64_url_decode(record.record_uid)
    data = prep_security_data(params, record)
    if data:
        sd.data = data
    return sd

def prep_score_data(record):
    empty_score_data = crypto.encrypt_aes_v2(json.dumps(dict()).encode('utf8'), record.record_key)
    score = get_security_score(record)
    if not score:
        return empty_score_data

    try:
        password = _get_pass(record)
        pad_length = max(25 - len(password), 0) if password else 0
        pad = ''.join([' ' for _ in range(pad_length)])
        score_data = dict(version=1, password=password, score=score, padding=pad)
        data = json.dumps(score_data).encode('utf-8')
        sec_score_data = crypto.encrypt_aes_v2(data, record.record_key)
    except Exception as ex:
        logging.error(f'Could not calculate security score data for record, {record and record.title}\nReason: {ex}')
        sec_score_data = empty_score_data
    return sec_score_data

def prep_score_data_update(params, record):    # type: (KeeperParams, KeeperRecord) -> APIRequest_pb2.SecurityScoreData
    ssd = APIRequest_pb2.SecurityScoreData()
    revision = params.security_score_data.get(record.record_uid, {}).get('revision')
    ssd.uid = utils.base64_url_decode(record.record_uid)
    ssd.data = prep_score_data(record)
    if revision:
        ssd.revision = revision
    return ssd

def needs_security_audit(params, record):  # type: (KeeperParams, KeeperRecord) -> bool
    if not params.enterprise_ec_key or not record:
        return False

    saved_score_data = params.security_score_data.get(record.record_uid, {})
    saved_sec_data = params.breach_watch_security_data.get(record.record_uid, {})
    score_data =  saved_score_data.get('data', {})
    current_password = _get_pass(record)
    if current_password != score_data.get('password') or None:
        return True

    scores = dict(new=get_security_score(record), old=score_data.get('score', 0))
    score_changed_on_passkey = any(x >= 100 for x in scores.values()) and any(x < 100 for x in scores.values())
    creds_removed = bool(scores.get('old') and not scores.get('new'))
    needs_alignment = bool(scores.get('new')) and saved_sec_data.get('revision', 0) < saved_score_data.get('revision', 0)
    return score_changed_on_passkey or creds_removed or needs_alignment

def update_security_audit_data(params, records):   # type: (KeeperParams, List[KeeperRecord]) -> int
    if not params.enterprise_ec_key:
        return 0

    from . import api
    update_limit = 1000
    total_updates = len(records)
    failed_updates = []
    while records:
        chunk = records[:update_limit]
        records = records[update_limit:]
        rq = APIRequest_pb2.SecurityDataRequest()
        rq.encryptionType = enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY_ECC if params.forbid_rsa else enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY
        try:
            rq.recordSecurityData.extend(prep_security_data_update(params, rec) for rec in chunk)
            rq.recordSecurityScoreData.extend(prep_score_data_update(params, rec) for rec in chunk)
            rs = api.communicate_rest(params, rq, 'enterprise/update_security_data')
        except KeeperApiError as kae:
            logging.error(f'Problem updating security data, reason: {kae}')
            failed_updates.extend(chunk)

    if failed_updates:
        logging.error(f'Could not update security data for {len(failed_updates)} records')

    return total_updates - len(failed_updates)

def attach_security_data(params, record, rq_param):
    # type: (KeeperParams, Union[str, Dict[str, any], KeeperRecord], Union[record_pb2.RecordUpdate, record_pb2.RecordAdd]) -> Union[record_pb2.RecordUpdate, record_pb2.RecordAdd]
    if params.forbid_rsa:   # Skip attaching security data if encrypting w/ EC key (use update_security_data instead)
        return rq_param

    try:
        if not isinstance(record, TypedRecord):
            record = KeeperRecord.load(params, record)
        if needs_security_audit(params, record):
            for param, prep_fn in [(rq_param.securityData, prep_security_data), (rq_param.securityScoreData, prep_score_data)]:
                data = prep_fn(params, record)
                if data:
                    param.data = data
    except Exception as ex:
        logging.error(f'Could not update record security-audit data. Reason: {ex}')

    return rq_param
