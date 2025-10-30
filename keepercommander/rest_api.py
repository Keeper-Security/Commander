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
import sys

from typing import Union, Dict, Optional

from .params import RestApiContext
from .error import KeeperApiError, Error
from .proto import APIRequest_pb2 as proto
from . import crypto, utils
from cryptography.hazmat.primitives.asymmetric import rsa, ec

CLIENT_VERSION = 'c17.2.0'

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
    
    100: utils.base64_url_decode('ptAEoVGStDoCA3eimGdCoYMkqBQ_HjNttdG2nQgcm6Q28ZgdG7So9umXNqAS0FkUQMGyeoLMnJgJPDBGg5Q2LswhEcA2UWR9uTFfsqSohUYBN1hSxKeSvowlIUa4rQMAG-a7BOZB7AA9JSFcMeoxMglMGZGuRpZtHAWZNCK0repSq1u2rOZapUgGPkSARejDfTBQiwOUv4lyD3O2jSdPzNOlz6GsdKcwGSGdDpgGtWQ9tulbsmcHJRZxY6xiusMEmpkIsySoT_ME3eBPzgxUCyqEYXycKBBviFKE-tUiOlBCEXOkemQYL2xbb0wta1lSYBO6LHE-CmIgtXU63GwjL1OaXAzFSZWglNZjBrsXObQCN1R_8eigCQCqnig0GhG5FDxN0TRyMqskOGY3MAm1dOJQ96RIWzl8KUYaa9MZLNlzqkSKjYZ0lWplLORblKkMQXGmHASWwbmZ3JY2LLVxhQZ8gSCE3miWDNgM6YNi4BED5ucLD7FzdAg3KeM5QyK41CC5wmU-Rck0LAkt3wNPD8p1GhgSS9Njk8E_Z5uk4gyhgiWMcgMJgEMnSKyh5SGqhAuDfSDIdusPGrKMFJJtaUtllcpmPAYHBLqILbljsxqwR1IB1-oqpUlmt7rA0lYO2iNXyLEZpZJhdEho-SQ62FlfiJmAEnewBNqKSXNjawUdFEjN0dFDdLAbBelIHwiKz7A1E6y-kBnHVmqxizk-gwG5UzaGU5VFktRKgJVU5irHtNUA3RVvubqgNkK4FWOzq_kOMXxyAHvMrpGhZtcjxOoZPQZZiwQI79d4qIGPaXm42rFE6RKAIdWvZzptIzMqNucQ8Xgf_fiiLzxCxOGyfQbIqMmOUeSCOfeD8XybCCRR1QLEzfbNR2t-_wgwX1xAIoW1cHI_sQcJb3prH1MUKoygXVpGTDYndjJj1VMhuLw0LDoOrRedT5dBfyhJNFINRWmDRHYDqrnGTsIkIsQBo2emcBYD5GJ1c3hF6lwpKeYi8aOUVpYXq4quHlyHmcKMW7IGpkMEuPZtLEQoBsJfb2wVHvCtmXZUKGO1KZc7VZhpJEOixSkBNZqqkBG1c0dfrpBV8caPFBwyPPUIwFkIifq9E8mPiRqb-AsA7hq8oQR3IMeVD0FEoAyMrMKj6uK68kp0i0WVLtqooSJ6olSLZQq0fzekjUhQIIzIcOh0wfSSzrtORSW_i5lHL6t3IkGJyKKSrgItk0gCJ7aS02woQBAbhLVCTjF7ccwaUehRaGeKSIUJWsy3x3N1zZOjPLtnRwNF39jKThV3IFO2e_gvi-YCLRsRvQAt94ok4XIZcZZg6HE93LKhNGoimkgUlvsYppF06Ey_qbW0bAu34cStM-wzROKReEqOlmaDmIl0j1p0DoutrySZY5MaX4ZOIzcS-xwakSoEOdQu_4g2W8KAcjtG37O3y4mz_6q9YrCQOKt0yfFXjkSvP0yPHymX1jxOp3iNHHM3oyygGLZqviSVwyTJPwBSiWErgCSEMpatXQdeupHPU9dXObkJEvN17oqmPk5iLeu8orx8Xv9GEjIvTvD0Trcy5saV2lCDkia48BM'),
    # 101: None,  # QA ML-KEM key
    # 102: None,  # Staging ML-KEM key
    # 103: None,  # Prod ML-KEM key
}   # type: Dict[int, Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey, Dict[str, Union[ec.EllipticCurvePublicKey, bytes]]]]


def encrypt_with_keeper_key(context, data: bytes) -> bytes:
    key_id = context.server_key_id
    if 1 <= key_id <= 6:
        return crypto.encrypt_rsa(data, SERVER_PUBLIC_KEYS[key_id])
    elif 7 <= key_id <= 17:
        return crypto.encrypt_ec(data, SERVER_PUBLIC_KEYS[key_id])
    else:
        raise KeeperApiError('invalid_key_id', f'Key ID \"{key_id}\" is not valid.')


def execute_rest(context, endpoint, payload):
    # type: (RestApiContext, str, proto.ApiRequestPayload) -> Optional[Union[bytes, dict]]
    if not context.transmission_key:
        context.transmission_key = os.urandom(32)

    if not context.server_key_id:
        context.server_key_id = 7

    run_request = True
    while run_request:
        run_request = False

        api_request = proto.ApiRequest()
        qrc_success = False
        
        # Try QRC encryption if qrc_key_id is available
        if context.qrc_key_id and context.qrc_key_id >= 100:
            qrc_mlkem_key = SERVER_PUBLIC_KEYS.get(context.qrc_key_id)
            if qrc_mlkem_key and isinstance(qrc_mlkem_key, bytes):
                try:
                    logging.debug(f"Using QRC hybrid encryption (ML-KEM key ID: {context.qrc_key_id}, EC key ID: {context.server_key_id})")

                    if not hasattr(context, 'client_ec_private_key') or not context.client_ec_private_key:
                        context.client_ec_private_key = crypto.generate_ec_key()[0]
                    
                    from .qrc.qrc_crypto import encrypt_qrc
                    ec_public_key = SERVER_PUBLIC_KEYS[context.server_key_id]
                    qrc_message = encrypt_qrc(context.transmission_key, context.client_ec_private_key, ec_public_key, qrc_mlkem_key)

                    api_request.qrcMessageKey.clientEcPublicKey = qrc_message['client_ec_public_key']
                    api_request.qrcMessageKey.mlKemEncapsulatedKey = qrc_message['ml_kem_encapsulated_key']
                    api_request.qrcMessageKey.data = qrc_message['data']
                    api_request.qrcMessageKey.msgVersion = qrc_message['msg_version']
                    api_request.qrcMessageKey.ecKeyId = context.server_key_id
                    
                    qrc_success = True
                except Exception as e:
                    logging.warning(f"QRC encryption failed ({e}), falling back to EC encryption")
        
        # Fallback to EC encryption if QRC not available or failed
        if not qrc_success:
            server_public_key = SERVER_PUBLIC_KEYS[context.server_key_id]
            if isinstance(server_public_key, rsa.RSAPublicKey):
                api_request.encryptedTransmissionKey = crypto.encrypt_rsa(context.transmission_key, server_public_key)
            elif isinstance(server_public_key, ec.EllipticCurvePublicKey):
                api_request.encryptedTransmissionKey = crypto.encrypt_ec(context.transmission_key, server_public_key)
            else:
                raise ValueError('Invalid server public key')
        
        api_request.publicKeyId = context.qrc_key_id if qrc_success else context.server_key_id
        api_request.locale = context.locale or 'en_US'

        api_request.encryptedPayload = crypto.encrypt_aes_v2(payload.SerializeToString(), context.transmission_key)

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
                                raise Error(f'Certificate validation error. More info:\n{doc_url}')
            raise e

        content_type = rs.headers.get('Content-Type') or ''
        if rs.status_code == 200:
            if content_type == 'application/json':
                return rs.json()

            rs_body = rs.content
            if rs_body:
                rs_body = crypto.decrypt_aes_v2(rs.content, context.transmission_key)
            return rs_body
        elif rs.status_code >= 400:
            if content_type.startswith('application/json'):
                failure = rs.json()
                logging.debug('<<< Response Error: [%s]', failure)
                if rs.status_code == 401:
                    if failure.get('error') == 'key':
                        server_key_id = failure['key_id']
                        if 'qrc_ec_key_id' in failure:
                            qrc_ec_key_id = failure['qrc_ec_key_id']
                            logging.debug(f"QRC key mismatch: ML-KEM key {server_key_id}, EC key {qrc_ec_key_id}")
                            if server_key_id != context.server_key_id:
                                context.server_key_id = server_key_id
                                run_request = True
                                continue
                        else:
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
                elif rs.status_code == 400:
                    if context.server_key_id >= 100:
                        logging.warning(f"QRC request failed with 400 error, falling back to EC encryption: {failure.get('message', 'Unknown error')}")
                        context.server_key_id = 7
                        run_request = True
                        continue
                return failure
            else:
                if logging.getLogger().level <= logging.DEBUG:
                    if rs.text:
                        logging.debug('<<< Response Content: [%s]', rs.text)
                    else:
                        logging.debug('<<< HTTP Status: [%s]  Reason: [%s]', rs.status_code, rs.reason)
                raise KeeperApiError(rs.status_code, rs.reason)


def v2_execute(context, rq):
    # type: (RestApiContext, dict) -> Optional[dict]

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
