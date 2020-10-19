#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2019 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import requests
import base64
import os
import json
import hashlib
import hmac
import logging

from .params import RestApiContext
from .error import KeeperApiError, CommunicationError
from . import APIRequest_pb2 as proto

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_v1_5


LEGACY_CLIENT_VERSION = 'c14.0.0'
CLIENT_VERSION = 'c15.0.0'


SERVER_PUBLIC_KEYS = {
    1: RSA.importKey(base64.urlsafe_b64decode(
        'MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfH' +
        'OOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInn' +
        'j4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb' +
        '_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-V' +
        'xIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB' +
        '6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB')),

    2: RSA.importKey(base64.urlsafe_b64decode(
        'MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQq' +
        'YHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmY' +
        'KP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvd' +
        'WUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUsl' +
        'BnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpN' +
        'ArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB')),

    3: RSA.importKey(base64.urlsafe_b64decode(
        'MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoI' +
        'hubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUi' +
        'rgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYS' +
        'HzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_N' +
        'Xn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wE' +
        'AgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB')),

    4: RSA.importKey(base64.urlsafe_b64decode(
        'MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eR' +
        'FKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4H' +
        'CYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX' +
        '-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJ' +
        'KMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5' +
        'osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB')),

    5: RSA.importKey(base64.urlsafe_b64decode(
        'MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51Hv' +
        'sILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmH' +
        'FSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_' +
        'uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVV' +
        'hBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nO' +
        'WdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB')),

    6: RSA.importKey(base64.urlsafe_b64decode(
        'MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqL' +
        'AvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9v' +
        'w8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl' +
        '_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-' +
        'ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ' +
        '17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB')),
}


def encrypt_rsa(data, rsa_key):
    # type: (bytes, RSA.RsaKey) -> bytes
    cipher = PKCS1_v1_5.new(rsa_key)
    return cipher.encrypt(data)


def encrypt_aes(data, key):
    # type: (bytes, bytes) -> bytes
    iv = os.urandom(12)
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=iv)
    enc_data, tag = cipher.encrypt_and_digest(data)
    return iv + enc_data + tag


def decrypt_aes(data, key):
    # type: (bytes, bytes) -> bytes
    cipher = AES.new(key=key, mode=AES.MODE_GCM, nonce=data[:12])
    return cipher.decrypt_and_verify(data[12:-16], data[-16:])


def derive_key_v2(domain, password, salt, iterations):
    # type: (str, str, bytes, int) -> bytes
    derived_key = hashlib.pbkdf2_hmac('sha512', (domain+password).encode('utf-8'), salt, iterations, 64)
    return hmac.new(derived_key, domain.encode('utf-8'), digestmod=hashlib.sha256).digest()


def execute_rest(context, endpoint, payload):    # type: (RestApiContext, str, proto.ApiRequestPayload) -> any
    if not context.transmission_key:
        context.transmission_key = os.urandom(32)

    if not context.server_key_id:
        context.server_key_id = 1

    run_request = True
    while run_request:
        run_request = False

        api_request = proto.ApiRequest()
        api_request.encryptedTransmissionKey = encrypt_rsa(context.transmission_key, SERVER_PUBLIC_KEYS[context.server_key_id])
        api_request.publicKeyId = context.server_key_id
        api_request.locale = context.locale or 'en_US'

        api_request.encryptedPayload = encrypt_aes(payload.SerializeToString(), context.transmission_key)

        request_data = api_request.SerializeToString()
        url = context.server_base + endpoint

        logging.debug('>>> Request URL: [%s]', url)
        rs = requests.post(url, data=request_data, headers={'Content-Type': 'application/octet-stream'})
        logging.debug('<<< Response Code: [%d]', rs.status_code)
        logging.debug('<<< Response Headers: [%s]', str(rs.headers))

        content_type = rs.headers.get('Content-Type') or ''
        if rs.status_code == 200:
            if content_type == 'application/json':
                return rs.json()        # type: dict

            rs_body = rs.content
            if rs_body:
                rs_body = decrypt_aes(rs.content, context.transmission_key)
            return rs_body
        elif rs.status_code >= 400:
            if content_type == 'application/json':
                failure = rs.json()
                if rs.status_code == 401:
                    if failure.get('error') == 'key':
                        server_key_id = failure['key_id']
                        if server_key_id != context.server_key_id:
                            context.server_key_id = server_key_id
                            run_request = True
                            continue
                return failure
            else:
                logging.debug('<<< HTTP Status: [%s]  Reason: [%s]', rs.status_code, rs.reason)
                if logging.getLogger().level <= logging.DEBUG:
                    if rs.text:
                        logging.debug('<<< Response Content: [%s]', str(rs.text))
                raise CommunicationError('Code {0}: {1}'.format(rs.status_code, rs.reason))


def get_device_token(context):
    # type: (RestApiContext) -> str

    if not context.device_id:
        rq = proto.DeviceRequest()
        rq.clientVersion = CLIENT_VERSION
        rq.deviceName = ''

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()
        rs = execute_rest(context, 'authentication/get_device_token', api_request_payload)
        if type(rs) is bytes:
            device_rs = proto.DeviceResponse()
            device_rs.ParseFromString(rs)
            if proto.DeviceStatus.Name(device_rs.status) == 'DEVICE_OK':
                context.device_id = device_rs.encryptedDeviceToken
        elif type(rs) is dict:
            raise KeeperApiError(rs['error'], rs['message'])

    return context.device_id


def pre_login(context, username, two_factor_token=None):
    # type: (RestApiContext, str, bytes or None) -> proto.PreLoginResponse

    attempt = 0
    while attempt < 3:
        attempt += 1
        rq = proto.PreLoginRequest()
        rq.authRequest.clientVersion = CLIENT_VERSION
        rq.authRequest.username = username.lower()
        rq.authRequest.encryptedDeviceToken = get_device_token(context)
        rq.loginType = proto.LoginType.Value('NORMAL')
        if two_factor_token:
            rq.twoFactorToken = two_factor_token

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()
        rs = execute_rest(context, 'authentication/pre_login', api_request_payload)
        if type(rs) == bytes:
            pre_login_rs = proto.PreLoginResponse()
            pre_login_rs.ParseFromString(rs)
            return pre_login_rs

        elif type(rs) is dict:
            if 'error' in rs and 'message' in rs:
                if rs['error'] == 'region_redirect':
                    context.device_id = None
                    context.server_base = 'https://{0}/'.format(rs['region_host'])
                    logging.warning('Switching to region: %s', rs['region_host'])
                    continue
                if rs['error'] == 'bad_request':
                    logging.warning('Pre-Auth error: %s', rs.get('additional_info'))
                    context.device_id = None
                    continue

                raise KeeperApiError(rs['error'], rs['message'])
    raise CommunicationError('Cannot get user information')


def get_new_user_params(context, username):
    # type: (RestApiContext, str) -> proto.NewUserMinimumParams
    rq = proto.AuthRequest()
    rq.clientVersion = CLIENT_VERSION
    rq.username = username.lower()
    rq.encryptedDeviceToken = get_device_token(context)

    api_request_payload = proto.ApiRequestPayload()
    api_request_payload.payload = rq.SerializeToString()
    rs = execute_rest(context, 'authentication/get_new_user_params', api_request_payload)
    if type(rs) is bytes:
        pre_login_rs = proto.NewUserMinimumParams()
        pre_login_rs.ParseFromString(rs)
        return pre_login_rs

    if type(rs) is dict:
        raise KeeperApiError(rs['error'], rs['message'])


def v2_execute(context, rq):
    # type: (RestApiContext, dict) -> dict

    api_request_payload = proto.ApiRequestPayload()
    api_request_payload.payload = json.dumps(rq).encode('utf-8')
    rs_data = execute_rest(context, 'vault/execute_v2_command', api_request_payload)
    if rs_data:
        if type(rs_data) is bytes:
            rs = json.loads(rs_data.decode('utf-8'))
            logger = logging.getLogger()
            if logger.level <= logging.DEBUG:
                logger.debug('>>> Request JSON: [%s]', json.dumps(rq, sort_keys=True, indent=4))
                logger.debug('<<< Response JSON: [%s]', json.dumps(rs, sort_keys=True, indent=4))
            return rs

        if type(rs_data) is dict:
            raise KeeperApiError(rs_data['error'], rs_data['message'])

