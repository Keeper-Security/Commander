#!/usr/bin/env python3

"""Code/Data shared between recordv3.py and record.py."""

import base64
import hashlib
import hmac
import json
import logging
import urllib.parse

from ..proto import breachwatch_pb2  # has BreachWatchUpdateResponse but not BreachWatchData
from ..proto import client_pb2  # has BreachWatchData but not BreachWatchUpdateResponse
from .. import api


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


def are_all_good_passwords(params, password_list, *, with_count=False):
    """Return True iff all passwords in password_list have no breach detected by BreachWatch."""
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
        print('Detected {} breached passwords.  Please go to https://keepersecurity.com/vault/# to correct the problem'.format(
            bad_password_count,
        ))
        return False
    return True


def send_recv_breach_watch_status(params, password_list):
    """Send a BreachWatchStatusRequest and receive+return a BreachWatchStatusResponse."""
    assert isinstance(password_list, list)
    for password in password_list:
        assert isinstance(password, str)
    anon_token = params.anon_token
    breach_watch_status_request = calc_breach_watch_status_request(anon_token, password_list)
    breach_watch_status_response = api.communicate_rest_not_authed(
        params=params,
        request=breach_watch_status_request,
        endpoint='breachwatch/status',
        rs_type=breachwatch_pb2.BreachWatchStatusResponse,
    )
    return breach_watch_status_response


def calc_breach_watch_status_request(anon_token, password_list):
    """Derive a BreachWatchStatusRequest protobuf for the benefit of BeachWatch."""
    breach_watch_status_request = breachwatch_pb2.BreachWatchStatusRequest()
    breach_watch_status_request.anonymizedToken = anon_token
    hashes = [calc_hash_check(pw) for pw in password_list]
    breach_watch_status_request.hashCheck.extend(hashes)
    # FIXME: what should breach_watch_status_request.removedEuid be, if anything?  Its name suggests possibly a boolean, but it's
    # really a repeated bytes.
    return breach_watch_status_request


def calc_hash_check(password):
    """Derive a HashCheck protobuf for the benefit of BreachWatch."""
    hash_check = breachwatch_pb2.HashCheck()
    hash_check.hash1 = calc_hash1(password)
    return hash_check


def calc_hash1(password):
    """Derive a hash1 from password for the benefit of BreachWatch."""
    bits = base64.urlsafe_b64decode('phl9kdMA_gkJkSfeOYWpX-FOyvfh-APhdSFecIDMyfI' + '==')
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
        # FIXME: Should we assert this or not?
        # assert euid is not None
        self.uid = uid
        self.password = password
        self.euid = euid
        self.key = key

    def __str__(self):
        """Return a str/repr of this object."""
        return f'BreachWatchRecord(uid={self.uid}, password={self.password}, euid={self.euid}, key={self.key}'

    __repr__ = __str__


def extract_bwr_from_jsonish_record_dict(params, rec_dict):
    """Get our a BreachWatchRecord class from the jsonish rec_dict."""
    fields = rec_dict.get('fields')
    assert fields is not None
    # fields:
    # [{'type': 'login', 'value': ['foo']},
    #  {'type': 'password', 'value': ['princess17dafads']},
    #  {'type': 'fileRef', 'value': []}]
    password = None
    record_uid = None
    # FIXME: Note that we do not currently make an effort to extract the euid.  Where should it come from, if at all?
    euid = None
    for subdict in fields:
        if subdict.get('type') == 'password':
            value = subdict.get('value')
            assert len(value) == 1
            password = value[0]
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


def upload_records(params, jsonish_record_list):
    """Upload records to breachwatch."""
    rec_list = []
    for rec_dict in jsonish_record_list:
        bwr = extract_bwr_from_jsonish_record_dict(params, rec_dict)
        rec_list.append(bwr)
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
    if rs.status != 'success':
        logging.warning('Attempted {} record updates; one or more failed'.format(len(record_list)))
    return


def calc_breach_watch_update_request(params, record_list):
    """
    Derive a BreachWatchUpdateRequest protobuf for the benefit of BreachWatch.

    2 fields
    """
    breach_watch_update_request = breachwatch_pb2.BreachWatchUpdateRequest()
    breach_watch_record_request_list = list(gen_breach_watch_record_request(params, record_list=record_list))
    breach_watch_update_request.breachWatchRecordRequest.extend(breach_watch_record_request_list)
    breach_watch_update_request.encryptedData = calc_breach_watch_data(record_list).SerializeToString()
    return breach_watch_update_request


def gen_breach_watch_record_request(params, record_list):
    """
    Derive a BreachWatchRecordRequest from passwords for the benefit of BreachWatch.

    This also has emails and domains attributes, but we don't need those yet.
    4 fields
    """
    for record in record_list:
        breach_watch_record_request = breachwatch_pb2.BreachWatchRecordRequest()
        bits = base64.urlsafe_b64decode(record.uid + '==')
        breach_watch_record_request.recordUid = bits
        # This is a BreachWatchRecordData message encrypted with the record key
        # We're guessing that means BreachWatchData, really, since BreachWatchRecordData doesn't appear to exist.
        breach_watch_data = calc_breach_watch_data([record])
        breach_watch_data_bytes = breach_watch_data.SerializeToString()
        encrypted_data = api.encrypt_aes(breach_watch_data_bytes, record.key)
        encrypted_data_bytes = encrypted_data.encode('utf-8')
        breach_watch_record_request.encryptedData = encrypted_data_bytes
        breach_watch_record_request.breachWatchInfoType = breachwatch_pb2.BreachWatchInfoType.RECORD
        # FIXME: We're skipping this field, because I don't know what it's for yet, or even if it's important.
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
            # FIXME: Is it appropriate to skip this?
            bw_password.euid = record.euid
        yield bw_password
