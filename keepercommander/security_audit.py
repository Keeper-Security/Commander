import json
import logging
import urllib
from typing import Union, List
from urllib import parse

from keepercommander import utils, crypto, api
from keepercommander.error import KeeperApiError
from keepercommander.params import KeeperParams
from keepercommander.proto import APIRequest_pb2, client_pb2, enterprise_pb2
from keepercommander.vault import KeeperRecord

def _get_pass(record):  # type: (KeeperRecord) -> Union[str, None]
    from keepercommander.breachwatch import BreachWatch
    return BreachWatch.extract_password(record) or None

def prep_security_data_update(params, record): # type: (KeeperParams, KeeperRecord) -> APIRequest_pb2.SecurityData
    sd = APIRequest_pb2.SecurityData()
    sd.uid = utils.base64_url_decode(record.record_uid)
    get_bw_obj = lambda rec: next(
        iter(params.breach_watch_records.get(rec, {}).get('data_unencrypted', {}).get('passwords', [])),
        {}) if params.breach_watch else None

    from keepercommander.breachwatch import BreachWatch
    password = _get_pass(record)
    # Send empty security data for this record if password was removed -- this removes the old security data
    sd_data = None
    if password:
        strength = utils.password_score(password)
        sd_data = {'strength': strength}
        login_url = BreachWatch.extract_url(record)
        parse_results = urllib.parse.urlparse(login_url)
        domain = parse_results.hostname or parse_results.path
        pw_obj = get_bw_obj(record.record_uid)
        if isinstance(pw_obj, dict):
            status = pw_obj.get('status')
            sd_data['bw_result'] = client_pb2.BWStatus.Value(status) if status \
                else client_pb2.BWStatus.GOOD if bool(pw_obj.get('euid')) \
                else client_pb2.BWStatus.WEAK
        if domain:
            # truncate domain string if needed to avoid reaching RSA encryption data size limitation
            sd_data['domain'] = domain[:200]
    if sd_data:
        try:
            if params.forbid_rsa:
                if params.enterprise_ec_key:
                    sd.data = crypto.encrypt_ec(json.dumps(sd_data).encode('utf-8'), params.enterprise_ec_key)
                else:
                    raise Exception('Enterprise ECC public key is not available')
            else:
                if params.enterprise_rsa_key:
                    sd.data = crypto.encrypt_rsa(json.dumps(sd_data).encode('utf-8'), params.enterprise_rsa_key)
                else:
                    raise Exception('Enterprise RSA public key is not available')
        except Exception as e:
            logging.error(f'Error: {e}')
            logging.error(f'Enterprise RSA key length = {params.enterprise_rsa_key.key_size}')
            return
    return sd

def prep_score_data_update(params, record):    # type: (KeeperParams, KeeperRecord) -> APIRequest_pb2.SecurityScoreData
    ssd = APIRequest_pb2.SecurityScoreData()
    ssd.uid = utils.base64_url_decode(record.record_uid)
    get_revision = lambda uid: params.security_score_data.get(uid, {}).get('revision', 0)
    ssd.revision = get_revision(record.record_uid)
    password = _get_pass(record)
    if password:
        score = utils.password_score(password)
        pad_length = max(25 - len(password), 0)
        pad = ''.join([' ' for _ in range(pad_length)])
        score_data = dict(version=1, password=password, score=score, padding=pad)
        data = json.dumps(score_data).encode('utf-8')
        ssd.data = crypto.encrypt_aes_v2(data, record.record_key)
    return ssd

def needs_security_audit(params, record):  # type: (KeeperParams, KeeperRecord) -> bool
    if not params.enterprise_ec_key or not record:
        return False

    score_data =  params.security_score_data.get(record.record_uid, {}).get('data', {})
    security_data = params.breach_watch_security_data.get(record.record_uid)
    password = _get_pass(record)
    return score_data.get('password', None) != password or not security_data and bool(password)

def update_security_audit_data(params, records):   # type: (KeeperParams, List[KeeperRecord]) -> None
    if not params.enterprise_ec_key:
        return

    update_limit = 1000
    while records:
        chunk = records[:update_limit]
        rq = APIRequest_pb2.SecurityDataRequest()
        rq.encryptionType = enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY_ECC if params.forbid_rsa else enterprise_pb2.KT_ENCRYPTED_BY_PUBLIC_KEY
        rq.recordSecurityData.extend(prep_security_data_update(params, rec) for rec in chunk)
        rq.recordSecurityScoreData.extend(prep_score_data_update(params, rec) for rec in chunk)
        try:
            api.communicate_rest(params, rq, 'enterprise/update_security_data')
        except KeeperApiError:
            pass
        finally:
            records = records[update_limit:]
