#!/usr/bin/env python3

"""Code/Data shared between recordv3.py and record.py."""

import hashlib
import hmac
import json
import logging
import urllib.parse

from .. import api
from .. import crypto
from .. import utils
from ..display import bcolors
from ..proto import breachwatch_pb2  # has BreachWatchUpdateResponse but not BreachWatchData
from ..proto import client_pb2  # has BreachWatchData but not BreachWatchUpdateResponse


def display_totp_details(otp_url):
    """Display Time-based One Time Password details."""
    query_fields = extract_query_fields(otp_url)
    display_totp_query_fields(query_fields)


def extract_otp_url(data, is_v2):
    """Get the otpauth url from our decoded json as a string."""
    assert isinstance(data, dict)
    fields = data['fields']
    assert isinstance(fields, list)
    if is_v2:
        assert len(fields) == 1
        return fields[0]['data']
    # For v3 records
    for subdict in fields:
        if subdict['type'] == 'oneTimeCode':
            value = subdict['value']
            assert isinstance(value, list)
            assert len(value) == 1
            return value[0]
    raise AssertionError('No otpauth URL found')


def extract_query_fields(otp_url):
    """Get the query fields from an otpauth query string as a dict."""
    parsed_url = urllib.parse.urlparse(otp_url)
    query_string = parsed_url.query
    parsed_query = urllib.parse.parse_qs(query_string)
    return parsed_query


def display_totp_query_fields(query_fields):
    """Display the details of totp data."""
    for key in ('secret', 'issuer', 'period'):
        if key in query_fields:
            assert len(query_fields[key]) == 1
            print('{}: {}'.format(key, query_fields[key][0]))
        else:
            print('{} not found'.format(key))


def are_all_good_passwords(params, password_list, *, with_count=False, with_color=False, from_command_line=False):
    """Return True iff all passwords in password_list have no breach detected by BreachWatch."""
    if not params.license.get('breach_watch_enabled'):
        return True

    if with_color:
        start_warning_color = bcolors.WARNING
        end_color = bcolors.ENDC
    else:
        start_warning_color = ''
        end_color = ''

    result = send_recv_breach_watch_status(params, password_list)
    bad_password_count = 0
    for bws_rs in result.hashStatus:
        if bws_rs.breachDetected:
            if with_count:
                # Increment the counter and continue checking.
                bad_password_count += 1
            else:
                # Return False for the first bad password detected.
                return False

    if bad_password_count > 0:
        logging.info(
            start_warning_color +
            'Detected {} breached passwords out of {}.'.format(bad_password_count, len(password_list)) +
            ('  Please go to https://keepersecurity.com/vault/# to correct the problem' if not from_command_line else '') +
            end_color
        )
        return False
    else:
        len_password_list = len(password_list)
        if len_password_list == 1:
            logging.info('Good: One password not-breached')
        else:
            logging.info('Good: All %s passwords not-breached', len_password_list)
    return True


def send_recv_breach_watch_status(params, password_list):
    """Send a BreachWatchStatusRequest and receive+return a BreachWatchStatusResponse.  Also maintain the hash1_to_euid dict."""
    assert isinstance(password_list, list)
    for password in password_list:
        assert isinstance(password, str)
    anon_token = params.anon_token
    breach_watch_status_request = calc_breach_watch_status_request(params, anon_token, password_list)
    breach_watch_status_response = api.communicate_rest_not_authed(
        params=params,
        request=breach_watch_status_request,
        endpoint='breachwatch/status',
        rs_type=breachwatch_pb2.BreachWatchStatusResponse,
    )
    if not hasattr(params, 'hash1_to_euid'):
        params.hash1_to_euid = {}
    for hs in breach_watch_status_response.hashStatus:
        params.hash1_to_euid[hs.hash1] = hs.euid
    return breach_watch_status_response


def calc_breach_watch_status_request(params, anon_token, password_list):
    """Derive a BreachWatchStatusRequest protobuf for the benefit of BreachWatch.  Also stash password_to_hash1 dict in params."""
    breach_watch_status_request = breachwatch_pb2.BreachWatchStatusRequest()
    breach_watch_status_request.anonymizedToken = anon_token
    hashes = [calc_hash_check(pw) for pw in password_list]
    breach_watch_status_request.hashCheck.extend(hashes)
    just_hashes = [one_hash.hash1 for one_hash in hashes]
    assert len(password_list) == len(just_hashes)
    if not hasattr(params, 'password_to_hash1'):
        params.password_to_hash1 = {}
    dict_to_update_with = dict(zip(password_list, just_hashes))
    params.password_to_hash1.update(dict_to_update_with)
    # We intentionally ignore breach_watch_status_request.removedEuid
    return breach_watch_status_request


def calc_hash_check(password):
    """Derive a HashCheck protobuf for the benefit of BreachWatch."""
    hash_check = breachwatch_pb2.HashCheck()
    hash_check.hash1 = calc_hash1(password)
    return hash_check


def calc_hash1(password):
    """Derive a hash1 from password for the benefit of BreachWatch."""
    bits = utils.base64_url_decode('phl9kdMA_gkJkSfeOYWpX-FOyvfh-APhdSFecIDMyfI')
    pw_bytes = ('password:' + password).encode('utf-8')
    hmac_hash1 = hmac.new(bits, msg=pw_bytes, digestmod=hashlib.sha512)
    hash1_bytes = hmac_hash1.digest()
    return hash1_bytes


def extract_password_from_dict(json_dict):
    """Pull a password from the record add/edit API dict."""
    fields = json_dict.get('fields')
    if not fields:
        raise AssertionError('No fields key in json_dict')
    for subdict in fields:
        if subdict['type'] == 'password':
            assert len(subdict['value']) == 1
            return subdict['value'][0]
    raise AssertionError('no password in json_str')


def extract_password_from_json_str(json_str):
    """Pull a password from a record add/edit API json str."""
    json_dict = json.loads(json_str)
    return extract_password_from_dict(json_dict)


def extract_passwords_from_params(params):
    """Extract passwords from params."""
    # xxx, yyy, zzz are the passwords
    # {'04dFmnmRhKTPqsR5ibppxQ': {'passwords': [{'euid': 'UQUt/h8HJveqC0r/lhyCCHATPEZjypQvTikIqgdvUVJmJZmjVqQt6AhW6Qo=',
    #                                            'value': 'xxx'}]},
    #  '4P_oDuk1Il5nf9dw450gdw': {'passwords': [{'status': 'WEAK',
    #                                            'value': 'yyy'}]},
    #  '5apyRNoVOvdFM-adSvWiFA': {'passwords': [{'euid': 'DELbKtiK4LrAndI1+ISGcPTeYipVWShvLAAZGbgKJSpQBotfhayyIrnbkN0=',
    #                                            'value': 'zzz'}]},
    result = []
    for subdict in params.breach_watch_records.values():
        assert 'passwords' in subdict
        passwords_list = subdict['passwords']
        assert len(passwords_list) == 1
        password_dict = passwords_list[0]
        result.append(password_dict['value'])
    return result


class BreachWatchRecord:
    """Hold breachwatch-related record data.  We're just a container."""

    # namedtuples are cool, but last I heard pylint didn't like them much.

    def __init__(self, uid, password, euid, key):
        """Initialize."""
        assert uid is not None
        assert password is not None
        self.uid = uid
        self.password = password
        self.euid = euid
        self.key = key

    def __str__(self):
        """Return a str/repr of this object."""
        return f'BreachWatchRecord(uid={self.uid}, password={self.password}, euid={self.euid}, key={self.key})'

    __repr__ = __str__


def lookup_euid_from_password(params, password):
    """Return the euid corresponding to this password, if any."""
    if not hasattr(params, 'password_to_hash1'):
        return None
    hash1 = params.password_to_hash1[password]
    if not hasattr(params, 'hash1_to_euid'):
        return None
    euid = params.hash1_to_euid[hash1]
    return euid


def extract_bwr_from_jsonish_record_dict_v3(params, rec_dict):
    """Get a BreachWatchRecord class from the jsonish rec_dict."""
    fields = rec_dict.get('fields')
    assert fields is not None
    # fields:
    # [{'type': 'login', 'value': ['foo']},
    #  {'type': 'password', 'value': ['princess17dafads']},
    #  {'type': 'fileRef', 'value': []}]
    password = None
    record_uid = None
    euid = None
    for subdict in fields:
        if subdict.get('type') == 'password':
            value = subdict.get('value')
            assert len(value) == 1
            password = value[0]
            euid = lookup_euid_from_password(params, password)
        if subdict.get('type') == 'record_uid':
            value = subdict.get('value')
            assert len(value) == 1
            record_uid = value[0]
    bwr = BreachWatchRecord(
        uid=record_uid,
        euid=euid,
        password=password,
        key=params.record_cache[record_uid]['record_key_unencrypted'],
    )
    return bwr


def upload_breachwatch_records_v3(params, jsonish_record_list):
    """Upload records to breachwatch."""
    rec_list = []
    for rec_dict in jsonish_record_list:
        bwr = extract_bwr_from_jsonish_record_dict_v3(params, rec_dict)
        rec_list.append(bwr)
    send_recv_breach_watch_update_record_data(params, rec_list)


def extract_bwr_from_jsonish_record_dict_v2(params, rec_dict, record_uid, record_key):
    """Get our a BreachWatchRecord class from the jsonish rec_dict."""
    password = rec_dict['secret2']
    euid = lookup_euid_from_password(params, password)
    bwr = BreachWatchRecord(uid=record_uid, euid=euid, password=password, key=record_key)
    return bwr


def upload_breachwatch_record_v2_ji(params, jsonish_record_dict, record_uid, record_key):
    """Upload records to breachwatch."""
    # In this one, we cannot rely on the record cache because the record does not yet exist.
    bwr = extract_bwr_from_jsonish_record_dict_v2(params, jsonish_record_dict, record_uid, record_key)
    rec_list = [bwr]
    send_recv_breach_watch_update_record_data(params, rec_list)


def upload_breachwatch_record_v2_rec(params, record, record_uid):
    """Upload records to breachwatch."""
    # In this one, we can rely on the record cache because the record preexists.
    euid = lookup_euid_from_password(params, record.password)
    rec_from_cache = params.record_cache[record_uid]
    key = rec_from_cache['record_key_unencrypted']
    bwr = BreachWatchRecord(record_uid, record.password, euid, key)
    rec_list = [bwr]
    send_recv_breach_watch_update_record_data(params, rec_list)


def send_recv_breach_watch_update_record_data(params, record_list):
    """
    Upload breachwatch data for records in record_list.

    IOW, send a BreachWatchStatusRequest and receive a BreachWatchStatusResponse.
    """
    # A little type enforcement.
    assert isinstance(record_list, list)
    for record in record_list:
        assert isinstance(record, BreachWatchRecord)

    # Send the request
    breach_watch_update_request = calc_breach_watch_update_request(params, record_list)
    rs = api.communicate_rest(
        params,
        breach_watch_update_request,
        'breachwatch/update_record_data',
        rs_type=breachwatch_pb2.BreachWatchUpdateResponse,
    )

    # Check the response
    bad_count = 0
    if hasattr(rs, 'breachWatchRecordStatus'):
        for elem in rs.breachWatchRecordStatus:
            if hasattr(elem, 'status'):
                if elem.status != 'success':
                    bad_count += 1
                    if hasattr(elem, 'reason'):
                        logging.warning(elem.reason)
            else:
                logging.warning('elem has no status field')
    else:
        logging.warning('rs has no breachWatchRecordStatus field')

    if len(rs.breachWatchRecordStatus) - bad_count > 0:
        # At least one record was successfully uploaded, so stash the good ones in params As Though They Had Been Downloaded.
        sideload_breachwatch_data(params, rs.breachWatchRecordStatus, record_list)

    if bad_count:
        logging.warning('Attempted {} record updates; {} failed'.format(len(record_list), bad_count))


def sideload_breachwatch_data(params, breach_watch_record_status_list, record_list):
    """
    Stash a copy of the data we just uploaded in params.

    We do this because frequently the implict sync_down after this function completes, occurs too soon after the server
    receives our breachwatch data, so the new records aren't downloaded yet.  Without this stashing, it seems like the
    upload (and subequent download) didn't work.  With this stashing, things look good to the user.
    """
    record_dict = {rec.uid: rec for rec in record_list}

    for one_bwrs in breach_watch_record_status_list:
        if one_bwrs.status == 'success':
            # Sideload this one, because it was successfully uploaded.
            uid = utils.base64_url_encode(one_bwrs.recordUid)
            breach_watch_record = record_dict[uid]
            if breach_watch_record.euid:
                # ...but only if this record has an euid defined.  We do not (yet?) add "WEAK" data.
                params_content = construct_bwr_dict_value(breach_watch_record)
                params.breach_watch_records[breach_watch_record.uid] = params_content


def construct_bwr_dict_value(breach_watch_record):
    """Construct the jsonish data that belongs in params.bwr_dict."""
    # {'passwords': [{'euid': 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', 'value': 'yyyyyyyyyyyyyyyyyyyy'}]}}
    subdict_ = {'euid': breach_watch_record.euid, 'value': breach_watch_record.password}
    list_ = [subdict_]
    result_dict = {'passwords': list_}
    assert len(result_dict['passwords']) == 1
    assert len(result_dict['passwords'][0]) == 2
    return result_dict


def calc_breach_watch_update_request(params, record_list):
    """
    Derive a BreachWatchUpdateRequest protobuf for the benefit of BreachWatch.

    2 fields
    """
    breach_watch_update_request = breachwatch_pb2.BreachWatchUpdateRequest()
    breach_watch_record_request_list = list(gen_breach_watch_record_request(params, record_list=record_list))
    breach_watch_update_request.breachWatchRecordRequest.extend(breach_watch_record_request_list)
    # We intentionally ignore this field.
    # breach_watch_update_request.encryptedData = calc_breach_watch_data(record_list).SerializeToString()
    return breach_watch_update_request


def gen_breach_watch_record_request(params, record_list):
    """
    Derive a BreachWatchRecordRequest from passwords for the benefit of BreachWatch.

    This also has emails and domains attributes, but we don't need those yet.
    4 fields
    """
    for record in record_list:
        breach_watch_record_request = breachwatch_pb2.BreachWatchRecordRequest()
        bits = utils.base64_url_decode(record.uid)
        breach_watch_record_request.recordUid = bits
        breach_watch_data = calc_breach_watch_data([record])
        breach_watch_data_bytes = breach_watch_data.SerializeToString()
        encrypted_data_bytes = crypto.encrypt_aes_v2(breach_watch_data_bytes, record.key)
        breach_watch_record_request.encryptedData = encrypted_data_bytes
        breach_watch_record_request.breachWatchInfoType = breachwatch_pb2.BreachWatchInfoType.RECORD
        # We're intentionally skipping updateUserWhoScanned
        # breach_watch_record_request.updateUserWhoScanned =
        yield breach_watch_record_request


def calc_breach_watch_data(record_list):
    """
    Derive a BreachWatchData for the benefit of BreachWatch.

    3 fields, but we only care about 1 so far: the passwords.
    """
    # I see this as a small problem - we have to use a mix of breachwatch_pb2 and client_pb2
    breach_watch_data = client_pb2.BreachWatchData()
    breach_watch_data.passwords.extend(gen_bw_password(record_list))
    return breach_watch_data


def gen_bw_password(record_list):
    """
    Derive a BWPassword for the benefit of BreachWatch.

    4 fields.
    """
    # A little type enforcement.
    assert isinstance(record_list, list)
    for record in record_list:
        assert isinstance(record, BreachWatchRecord)

    for record in record_list:
        bw_password = client_pb2.BWPassword()
        bw_password.value = record.password
        # This isn't (yet?) resolved.
        # bw_password.resolved =
        # We assume always-good for now.
        bw_password.status = client_pb2.BWStatus.GOOD
        if record.euid:
            # If breached this is empty, else this is the value returned by keeperapp after submission.
            bw_password.euid = record.euid
        yield bw_password
