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

import requests
import os
import json
import logging
import ssl
import time

from typing import Union, Dict

from .params import RestApiContext
from .error import KeeperApiError, CommunicationError
from .proto import APIRequest_pb2 as proto
from . import crypto, utils
from cryptography.hazmat.primitives.asymmetric import rsa, ec

from . import __version__


# CLIENT_VERSION = 'c' + __version__
CLIENT_VERSION = 'c16.8.0'

SERVER_PUBLIC_KEYS = {
    1: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA9Z_CZzxiNUz8-npqI4V10-zW3AL7-M4UQDdd_17759Xzm0MOEfH' +
        'OOsOgZxxNK1DEsbyCTCE05fd3Hz1mn1uGjXvm5HnN2mL_3TOVxyLU6VwH9EDInn' +
        'j4DNMFifs69il3KlviT3llRgPCcjF4xrF8d4SR0_N3eqS1f9CBJPNEKEH-am5Xb' +
        '_FqAlOUoXkILF0UYxA_jNLoWBSq-1W58e4xDI0p0GuP0lN8f97HBtfB7ijbtF-V' +
        'xIXtxRy-4jA49zK-CQrGmWqIm5DzZcBvUtVGZ3UXd6LeMXMJOifvuCneGC2T2uB' +
        '6G2g5yD54-onmKIETyNX0LtpR1MsZmKLgru5ugwIDAQAB')),

    2: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAkOpym7xC3sSysw5DAidLoVF7JUgnvXejbieDWmEiD-DQOKxzfQq' +
        'YHoFfeeix__bx3wMW3I8cAc8zwZ1JO8hyB2ON732JE2Zp301GAUMnAK_rBhQWmY' +
        'KP_-uXSKeTJPiuaW9PVG0oRJ4MEdS-t1vIA4eDPhI1EexHaY3P2wHKoV8twcGvd' +
        'WUZB5gxEpMbx5CuvEXptnXEJlxKou3TZu9uwJIo0pgqVLUgRpW1RSRipgutpUsl' +
        'BnQ72Bdbsry0KKVTlcPsudAnnWUtsMJNgmyQbESPm-aVv-GzdVUFvWKpKkAxDpN' +
        'ArPMf0xt8VL2frw2LDe5_n9IMFogUiSYt156_mQIDAQAB')),

    3: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAyvxCWbLvtMRmq57oFg3mY4DWfkb1dir7b29E8UcwcKDcCsGTqoI' +
        'hubU2pO46TVUXmFgC4E-Zlxt-9F-YA-MY7i_5GrDvySwAy4nbDhRL6Z0kz-rqUi' +
        'rgm9WWsP9v-X_BwzARqq83HNBuzAjf3UHgYDsKmCCarVAzRplZdT3Q5rnNiYPYS' +
        'HzwfUhKEAyXk71UdtleD-bsMAmwnuYHLhDHiT279An_Ta93c9MTqa_Tq2Eirl_N' +
        'Xn1RdtbNohmMXldAH-C8uIh3Sz8erS4hZFSdUG1WlDsKpyRouNPQ3diorbO88wE' +
        'AgpHjXkOLj63d1fYJBFG0yfu73U80aEZehQkSawIDAQAB')),

    4: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA0TVoXLpgluaqw3P011zFPSIzWhUMBqXT-Ocjy8NKjJbdrbs53eR' +
        'FKk1waeB3hNn5JEKNVSNbUIe-MjacB9P34iCfKtdnrdDB8JXx0nIbIPzLtcJC4H' +
        'CYASpjX_TVXrU9BgeCE3NUtnIxjHDy8PCbJyAS_Pv299Q_wpLWnkkjq70ZJ2_fX' +
        '-ObbQaZHwsWKbRZ_5sD6rLfxNACTGI_jo9-vVug6AdNq96J7nUdYV1cG-INQwJJ' +
        'KMcAbKQcLrml8CMPc2mmf0KQ5MbS_KSbLXHUF-81AsZVHfQRSuigOStQKxgSGL5' +
        'osY4NrEcODbEXtkuDrKNMsZYhijKiUHBj9vvgKwIDAQAB')),

    5: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEAueOWC26w-HlOLW7s88WeWkXpjxK4mkjqngIzwbjnsU9145R51Hv' +
        'sILvjXJNdAuueVDHj3OOtQjfUM6eMMLr-3kaPv68y4FNusvB49uKc5ETI0HtHmH' +
        'FSn9qAZvC7dQHSpYqC2TeCus-xKeUciQ5AmSfwpNtwzM6Oh2TO45zAqSA-QBSk_' +
        'uv9TJu0e1W1AlNmizQtHX6je-mvqZCVHkzGFSQWQ8DBL9dHjviI2mmWfL_egAVV' +
        'hBgTFXRHg5OmJbbPoHj217Yh-kHYA8IWEAHylboH6CVBdrNL4Na0fracQVTm-nO' +
        'WdM95dKk3fH-KJYk_SmwB47ndWACLLi5epLl9vwIDAQAB')),

    6: crypto.load_rsa_public_key(utils.base64_url_decode(
        'MIIBCgKCAQEA2PJRM7-4R97rHwY_zCkFA8B3llawb6gF7oAZCpxprl6KB5z2cqL' +
        'AvUfEOBtnr7RIturX04p3ThnwaFnAR7ADVZWBGOYuAyaLzGHDI5mvs8D-NewG9v' +
        'w8qRkTT7Mb8fuOHC6-_lTp9AF2OA2H4QYiT1vt43KbuD0Y2CCVrOTKzDMXG8msl' +
        '_JvAKt4axY9RGUtBbv0NmpkBCjLZri5AaTMgjLdu8XBXCqoLx7qZL-Bwiv4njw-' +
        'ZAI4jIszJTdGzMtoQ0zL7LBj_TDUBI4Qhf2bZTZlUSL3xeDWOKmd8Frksw3oKyJ' +
        '17oCQK-EGau6EaJRGyasBXl8uOEWmYYgqOWirNwIDAQAB')),

    7: crypto.load_ec_public_key(utils.base64_url_decode(
        'BK9w6TZFxE6nFNbMfIpULCup2a8xc6w2tUTABjxny7yFmxW0dAEojwC6j6zb5nTlmb1dAx8nwo3qF7RPYGmloRM')),

    8: crypto.load_ec_public_key(utils.base64_url_decode(
        'BKnhy0obglZJK-igwthNLdknoSXRrGB-mvFRzyb_L-DKKefWjYdFD2888qN1ROczz4n3keYSfKz9Koj90Z6w_tQ')),

    9: crypto.load_ec_public_key(utils.base64_url_decode(
        'BAsPQdCpLIGXdWNLdAwx-3J5lNqUtKbaOMV56hUj8VzxE2USLHuHHuKDeno0ymJt-acxWV1xPlBfNUShhRTR77g')),

    10: crypto.load_ec_public_key(utils.base64_url_decode(
        'BNYIh_Sv03nRZUUJveE8d2mxKLIDXv654UbshaItHrCJhd6cT7pdZ_XwbdyxAOCWMkBb9AZ4t1XRCsM8-wkEBRg')),

    11: crypto.load_ec_public_key(utils.base64_url_decode(
        'BA6uNfeYSvqagwu4TOY6wFK4JyU5C200vJna0lH4PJ-SzGVXej8l9dElyQ58_ljfPs5Rq6zVVXpdDe8A7Y3WRhk')),

    12: crypto.load_ec_public_key(utils.base64_url_decode(
        'BMjTIlXfohI8TDymsHxo0DqYysCy7yZGJ80WhgOBR4QUd6LBDA6-_318a-jCGW96zxXKMm8clDTKpE8w75KG-FY')),

    13: crypto.load_ec_public_key(utils.base64_url_decode(
        'BJBDU1P1H21IwIdT2brKkPqbQR0Zl0TIHf7Bz_OO9jaNgIwydMkxt4GpBmkYoprZ_DHUGOrno2faB7pmTR7HhuI')),

    14: crypto.load_ec_public_key(utils.base64_url_decode(
        'BJFF8j-dH7pDEw_U347w2CBM6xYM8Dk5fPPAktjib-opOqzvvbsER-WDHM4ONCSBf9O_obAHzCyygxmtpktDuiE')),

    15: crypto.load_ec_public_key(utils.base64_url_decode(
        'BDKyWBvLbyZ-jMueORl3JwJnnEpCiZdN7yUvT0vOyjwpPBCDf6zfL4RWzvSkhAAFnwOni_1tQSl8dfXHbXqXsQ8')),

    16: crypto.load_ec_public_key(utils.base64_url_decode(
        'BDXyZZnrl0tc2jdC5I61JjwkjK2kr7uet9tZjt8StTiJTAQQmnVOYBgbtP08PWDbecxnHghx3kJ8QXq1XE68y8c')),

    17: crypto.load_ec_public_key(utils.base64_url_decode(
        'BFX68cb97m9_sweGdOVavFM3j5ot6gveg6xT4BtGahfGhKib-zdZyO9pwvv1cBda9ahkSzo1BQ4NVXp9qRyqVGU')),
}   # type: Dict[int, Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]]


def encrypt_aes(data, key):
    return crypto.encrypt_aes_v2(data, key)


def decrypt_aes(data, key):
    return crypto.decrypt_aes_v2(data, key)


def execute_rest(context, endpoint, payload):
    # type: (RestApiContext, str, proto.ApiRequestPayload) -> Union[bytes, dict]
    if not context.transmission_key:
        context.transmission_key = os.urandom(32)

    if not context.server_key_id:
        context.server_key_id = 1

    run_request = True
    while run_request:
        run_request = False

        api_request = proto.ApiRequest()
        server_public_key = SERVER_PUBLIC_KEYS[context.server_key_id]
        if isinstance(server_public_key, rsa.RSAPublicKey):
            api_request.encryptedTransmissionKey = crypto.encrypt_rsa(context.transmission_key, server_public_key)
        elif isinstance(server_public_key, ec.EllipticCurvePublicKey):
            api_request.encryptedTransmissionKey = crypto.encrypt_ec(context.transmission_key, server_public_key)
        else:
            raise ValueError('Invalid server public key')
        api_request.publicKeyId = context.server_key_id
        api_request.locale = context.locale or 'en_US'

        api_request.encryptedPayload = encrypt_aes(payload.SerializeToString(), context.transmission_key)

        request_data = api_request.SerializeToString()
        if endpoint.startswith('https://'):
            url = endpoint
        else:
            url = context.server_base + endpoint

        try:
            rs = requests.post(url, data=request_data, headers={'Content-Type': 'application/octet-stream'},
                               proxies=context.proxies, verify=context.certificate_check)
        except requests.exceptions.SSLError as e:
            doc_url = 'https://docs.keeper.io/secrets-manager/commander-cli/using-commander/troubleshooting-commander-cli#ssl-certificate-errors'
            if len(e.args) > 0:
                inner_e = e.args[0]
                if hasattr(inner_e, 'reason'):
                    reason = getattr(inner_e, 'reason')
                    if isinstance(reason, Exception) and hasattr(reason, 'args'):
                        args = getattr(reason, 'args')
                        if isinstance(args, tuple) and len(args) > 0:
                            inner_e = args[0]
                            if isinstance(inner_e, ssl.SSLCertVerificationError):
                                raise CommunicationError(f'Certificate validation error. More info:\n{doc_url}')
            raise e

        content_type = rs.headers.get('Content-Type') or ''
        if rs.status_code == 200:
            if content_type == 'application/json':
                return rs.json()

            rs_body = rs.content
            if rs_body:
                rs_body = decrypt_aes(rs.content, context.transmission_key)
            return rs_body
        elif rs.status_code >= 400:
            if content_type == 'application/json':
                failure = rs.json()
                logging.debug('<<< Response Error: [%s]', failure)
                if rs.status_code == 401:
                    if failure.get('error') == 'key':
                        server_key_id = failure['key_id']
                        if server_key_id != context.server_key_id:
                            context.server_key_id = server_key_id
                            run_request = True
                            continue
                elif rs.status_code == 403:
                    if failure.get('error') == 'throttled' and not context.fail_on_throttle:
                        logging.info('Throttled. sleeping for 10 seconds')
                        time.sleep(10)
                        run_request = True
                        continue
                return failure
            else:
                if logging.getLogger().level <= logging.DEBUG:
                    if rs.text:
                        logging.debug('<<< Response Content: [%s]', rs.text)
                    else:
                        logging.debug('<<< HTTP Status: [%s]  Reason: [%s]', rs.status_code, rs.reason)
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
