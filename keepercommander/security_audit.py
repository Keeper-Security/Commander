import json
import logging
import urllib
from typing import Union, List, Dict, Optional
from urllib import parse

from . import utils, crypto
from .params import KeeperParams
from .proto import APIRequest_pb2, client_pb2, record_pb2
from .utils import is_pw_strong
from .vault import KeeperRecord, TypedRecord

def has_passkey(record):   # type: (KeeperRecord) -> bool
    if not isinstance(record, TypedRecord) or not record.get_typed_field('passkey'):
        return False
    return bool(record.get_typed_field('passkey').value)

def _get_pass(record):  # type: (KeeperRecord) -> Union[str, None]
    from .breachwatch import BreachWatch
    return BreachWatch.extract_password(record) or None

def get_security_score(record): # type: (KeeperRecord) -> Union[int, None]
    password = _get_pass(record)
    return None if not password \
        else utils.password_score(password) or has_passkey(record) and 100 or 0

def encrypt_security_data(params, data):
    if params.forbid_rsa and not params.enterprise_ec_key:
        raise Exception('Enterprise ECC public key is not available')

    if not params.forbid_rsa and not params.enterprise_rsa_key:
        raise Exception('Enterprise RSA public key is not available')

    data = json.dumps(data).encode('utf8')
    pubkey = params.enterprise_ec_key if params.forbid_rsa else params.enterprise_rsa_key
    encrypt_fn = crypto.encrypt_ec if params.forbid_rsa else crypto.encrypt_rsa
    return encrypt_fn(data, pubkey)

def prep_security_data(params, record):
    get_bw_obj = lambda rec: next(
        iter(params.breach_watch_records.get(rec, {}).get('data_unencrypted', {}).get('passwords', [])),
        {}) if params.breach_watch else None

    from .breachwatch import BreachWatch
    score = get_security_score(record)
    # Send empty object to remove old security data (when password and/or passkey are removed)
    sec_data = b''
    if score is not None:
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
            sec_data.update(dict(domain=domain))
            data_size = len(json.dumps(sec_data).encode('utf8'))
            max_size = 244
            diff = max_size - data_size
            # truncate domain string if needed to avoid reaching RSA encryption data size limitation
            if diff < 0:
                new_length = len(domain) + diff
                sec_data.update(dict(domain=domain[:new_length]))
        sec_data = encrypt_security_data(params, sec_data)
    return sec_data

def prep_security_data_update(params, record): # type: (KeeperParams, KeeperRecord) -> Optional[APIRequest_pb2.SecurityData]
    sd = APIRequest_pb2.SecurityData()
    try:
        sd.uid = utils.base64_url_decode(record.record_uid)
        data = prep_security_data(params, record)
    except:
        logging.error('Could not update security data for record')
        return
    if data:
        sd.data = data
    return sd

def prep_score_data(record):
    empty_score_data = crypto.encrypt_aes_v2(json.dumps(dict()).encode('utf8'), record.record_key)
    score = get_security_score(record)
    if score is None:
        return empty_score_data

    try:
        password = _get_pass(record)
        pad_length = max(25 - len(password), 0) if password else 0
        pad = ''.join([' ' for _ in range(pad_length)])
        score_data = dict(version=1, password=password, score=score, padding=pad)
        data = json.dumps(score_data).encode('utf-8')
        sec_score_data = crypto.encrypt_aes_v2(data, record.record_key)
    except:
        logging.error(f'Could not calculate security score data for record')
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

    scores = dict(new=get_security_score(record) or 0, old=score_data.get('score', 0))
    score_changed_on_passkey = any(x >= 100 for x in scores.values()) and any(x < 100 for x in scores.values())
    creds_removed = bool(scores.get('old') and not scores.get('new'))
    needs_alignment = bool(scores.get('new')) and not saved_sec_data
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
        rq.encryptionType = get_security_data_key_type(params)
        try:
            sec_data_objs = (prep_security_data_update(params, rec) for rec in chunk)
            score_data_objs = (prep_score_data_update(params, rec) for rec in chunk)
            rq.recordSecurityData.extend(sd for sd in sec_data_objs if sd)
            rq.recordSecurityScoreData.extend(sd for sd in score_data_objs if sd)
            rs = api.communicate_rest(params, rq, 'enterprise/update_security_data')
        except:
            failed_updates.extend(chunk)

    if failed_updates:
        logging.error(f'Could not update security data for {len(failed_updates)} records')

    return total_updates - len(failed_updates)

def attach_security_data(params, record, rq_param):
    # type: (KeeperParams, Union[str, Dict[str, any], KeeperRecord], Union[record_pb2.RecordUpdate, record_pb2.RecordAdd]) -> Union[record_pb2.RecordUpdate, record_pb2.RecordAdd]
    try:
        if not isinstance(record, TypedRecord):
            if isinstance(record, dict):
                record['version'] = record.get('version', 3)
            record = KeeperRecord.load(params, record)
        if needs_security_audit(params, record):
            rq_param.securityData.data = prep_security_data(params, record)
            rq_param.securityScoreData.data = prep_score_data(record)
    except:
        pass
    return rq_param

def get_security_data_key_type(params):
    return record_pb2.ENCRYPTED_BY_PUBLIC_KEY_ECC if params.forbid_rsa \
        else record_pb2.ENCRYPTED_BY_PUBLIC_KEY
