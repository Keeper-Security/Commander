import base64
import getpass
import io
import json
import logging
import os
from typing import Optional

import pyperclip
import re
import webbrowser

from Cryptodome.Math.Numbers import Integer
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.asn1 import DerSequence
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from google.protobuf.json_format import MessageToJson
from sys import platform as _platform
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

from . import api, rest_api, utils, crypto
from .breachwatch import BreachWatch
from .display import bcolors
from .error import KeeperApiError
from .humps import decamelize
from .params import KeeperParams
from .proto import APIRequest_pb2 as proto, AccountSummary_pb2 as proto_as
from .proto import breachwatch_pb2 as breachwatch_proto
from .proto import ssocloud_pb2 as ssocloud
from .proto.enterprise_pb2 import LoginToMcRequest, LoginToMcResponse

install_fido_package_warning = 'You can use Security Key with Commander:\n' + \
                               'Install fido2 package ' + bcolors.OKGREEN + \
                               '\'pip install fido2\'\n' + bcolors.ENDC

permissions_error_msg = "Grant Commander SDK permissions to access Keeper by navigating to Admin Console -> Admin -> " \
                        "Roles -> [Select User's Role] -> Enforcement Policies -> Platform Restrictions -> Click on " \
                        "'Enable' check box next to Commander SDK.\nAlso note that if user has more than two roles " \
                        "assigned then the most restrictive policy from all the roles will be applied."


class LoginV3Flow:
    warned_on_fido_package = False

    @staticmethod
    def login(params, new_device=False, new_login=False):   # type: (KeeperParams, bool, bool) -> None

        logging.debug("Login v3 Start as '%s'", params.user)

        CommonHelperMethods.startup_check(params)

        encryptedDeviceToken = LoginV3API.get_device_id(params, new_device)

        clone_code_bytes = CommonHelperMethods.config_file_get_property_as_bytes(params, 'clone_code')
        config_user = params.config.get('user')    # type: str
        if params.user and config_user:
            if params.user.lower() != config_user.lower():
                clone_code_bytes = None
        if new_login:
            clone_code_bytes = None

        params.sso_login_info = None
        login_type = 'NORMAL'
        if params.config and params.config.get('sso_master_password'):
            login_type = 'ALTERNATE'

        resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken, cloneCode=clone_code_bytes, loginType=login_type)

        is_alternate_login = False

        while True:

            is_cloud = resp.loginState == proto.REQUIRES_DEVICE_ENCRYPTED_DATA_KEY

            if resp.loginState == proto.DEVICE_APPROVAL_REQUIRED:  # client goes to “standard device approval”.
                print("\nDevice Approval Required")

                verDevResp = LoginV3Flow.verifyDevice(
                    params,
                    encryptedDeviceToken,
                    resp.encryptedLoginToken
                )

                if verDevResp:
                    resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken)

                    if resp.loginState != proto.DEVICE_APPROVAL_REQUIRED:
                        print(bcolors.OKGREEN + "\nDevice was approved" + bcolors.ENDC + "\n")

                    else:
                        print(bcolors.BOLD + "\nWaiting for device approval." + bcolors.ENDC)
                        print("Check email, SMS message or push notification on the approved device.\n")

            elif resp.loginState == proto.REQUIRES_2FA:

                encryptedLoginToken = LoginV3Flow.handleTwoFactor(params, resp.encryptedLoginToken, resp)

                if encryptedLoginToken:
                    # Successfully completed 2FA. Re-login

                    login_type = 'ALTERNATE' if is_alternate_login else 'NORMAL'

                    resp = LoginV3API.resume_login(params, encryptedLoginToken, encryptedDeviceToken, loginType=login_type)

            elif resp.loginState == proto.REQUIRES_USERNAME:

                if not params.user:
                    params.user = getpass.getpass(prompt='User(Email): ', stream=None)

                    while not params.user:
                        params.user = getpass.getpass(prompt='User(Email): ', stream=None)

                encryptedLoginToken = resp.encryptedLoginToken
                if encryptedLoginToken:
                    # Successfully completed 2FA. Re-login
                    resp = LoginV3API.resume_login(params, encryptedLoginToken, encryptedDeviceToken, clone_code_bytes)

                # raise Exception('Username is required.')

            elif resp.loginState == proto.REDIRECT_ONSITE_SSO  or resp.loginState == proto.REDIRECT_CLOUD_SSO:
                encryptedLoginToken = LoginV3Flow.handleSsoRedirect(params, resp.loginState == proto.REDIRECT_CLOUD_SSO, resp.url, resp.encryptedLoginToken)
                if encryptedLoginToken:
                    resp = LoginV3API.resume_login(params, encryptedLoginToken, encryptedDeviceToken, loginMethod='AFTER_SSO')
                else:
                    logging.info(bcolors.BOLD + bcolors.OKGREEN + "\nAttempting to authenticate with a master password." + bcolors.ENDC + bcolors.ENDC)
                    logging.info(bcolors.OKBLUE + "(Note: SSO users can create a Master Password in Web Vault > Settings)\n" + bcolors.ENDC)
                    is_alternate_login = True
                    resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken, loginType='ALTERNATE')

            elif resp.loginState == proto.REQUIRES_DEVICE_ENCRYPTED_DATA_KEY:
                encryptedLoginToken = resp.encryptedLoginToken
                LoginV3Flow.handleSsoRequestDataKey(params, resp.encryptedLoginToken, encryptedDeviceToken)
                resp = LoginV3API.resume_login(params, encryptedLoginToken, encryptedDeviceToken)

            elif resp.loginState == proto.REQUIRES_ACCOUNT_CREATION:
                # if isSSOAccount:
                #     return createNewSso
                raise Exception('This account need to be created.' % rest_api.CLIENT_VERSION)

            elif resp.loginState == proto.REGION_REDIRECT:
                params.server = resp.stateSpecificValue
                logging.info('Redirecting to region: %s', params.server)
                LoginV3API.register_device_in_region(params, encryptedDeviceToken)
                resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken)

            elif resp.loginState == proto.REQUIRES_AUTH_HASH:

                salt = api.get_correct_salt(resp.salt)

                salt_bytes = salt.salt
                salt_iterations = salt.iterations

                while True:
                    if not params.password and params.sso_login_info:
                        if 'sso_password' in params.sso_login_info and params.sso_login_info['sso_password']:
                            params.password = params.sso_login_info['sso_password'].pop()

                    CommonHelperMethods.fill_password_with_prompt_if_missing(params)
                    if not params.password:
                        return

                    params.salt = salt_bytes
                    params.iterations = salt_iterations
                    params.auth_verifier = LoginV3API.auth_verifier_loginv3(params)

                    try:
                        resp = LoginV3API.validateAuthHashMessage(params, resp.encryptedLoginToken)
                        break
                    except KeeperApiError as kae:
                        if kae.result_code == 'auth_failed':
                            params.password = None
                            if not params.sso_login_info:
                                logging.info(kae)
                        else:
                            raise kae

                if LoginV3Flow.post_login_processing(params, resp):
                    return
                else:
                    # Not successfully authenticated, so restart login process
                    clone_code_bytes = CommonHelperMethods.config_file_get_property_as_bytes(params, 'clone_code')
                    resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken, cloneCode=clone_code_bytes)

            elif resp.loginState == proto.DEVICE_ACCOUNT_LOCKED:
                params.clear_session()
                raise Exception('\n*** Device for this account is locked ***\n')
            elif resp.loginState == proto.DEVICE_LOCKED:
                params.clear_session()
                raise Exception('\n*** This device is locked ***\n')
            elif resp.loginState == proto.ACCOUNT_LOCKED:
                raise Exception('\n*** User account `' + params.user + '` is LOCKED ***\n')
            elif resp.loginState == proto.LICENSE_EXPIRED:
                raise Exception('\n*** Your Keeper license has expired ***\n')
            elif resp.loginState == proto.UPGRADE:
                raise Exception('Application or device is out of date and requires an update.')
            elif resp.loginState == proto.LOGGED_IN:
                LoginV3Flow.post_login_processing(params, resp)
                return
            else:
                raise Exception("UNKNOWN LOGIN STATE [%s]" % resp.loginState)

    @staticmethod
    def post_login_processing(params: KeeperParams, resp: proto.LoginResponse):
        """Processing after login

        Returns True if authentication is successful and False otherwise.
        """
        params.user = resp.primaryUsername
        params.account_uid_bytes = resp.accountUid
        session_token = CommonHelperMethods.bytes_to_url_safe_str(resp.encryptedSessionToken)
        params.session_token = session_token

        login_type_message = LoginV3Flow.get_data_key(params, resp)
        params.password = None
        params.clone_code = resp.cloneCode
        CommonHelperMethods.persist_state_data(params)

        LoginV3Flow.populateAccountSummary(params)

        if resp.sessionTokenType != proto.NO_RESTRICTION:
            # This is not a happy-path login.  Let the user know what's wrong.
            if resp.sessionTokenType in (proto.PURCHASE, proto.RESTRICT):
                params.session_token = None
                msg = (
                    'Your Keeper account has expired. Please open the Keeper app to renew or visit the Web '
                    'Vault at https://keepersecurity.com/vault'
                )
                raise Exception(msg)
            elif resp.sessionTokenType == proto.ACCOUNT_RECOVERY:
                if LoginV3Flow.change_master_password(params):
                    return False
                else:
                    params.clear_session()
                    raise Exception('Change password failed')
            elif resp.sessionTokenType == proto.SHARE_ACCOUNT:
                logging.info('Account transfer required')
                accepted = api.accept_account_transfer_consent(params)
                if accepted:
                    return False
                else:
                    params.clear_session()
                    raise Exception('Account transfer logout')
            else:
                raise Exception('Please log into the web Vault to update your account settings.')

        if params.license and 'account_type' in params.license:
            if params.license['account_type'] == 2:
                try:
                    rs = api.communicate_rest(params, None, 'enterprise/get_enterprise_public_key', rs_type=breachwatch_proto.EnterprisePublicKeyResponse)
                    if rs.enterpriseECCPublicKey:
                        params.enterprise_ec_key = crypto.load_ec_public_key(rs.enterpriseECCPublicKey)
                except Exception as e:
                    logging.debug('Get enterprise public key: %s', e)

        if params.license and params.license.get('breach_watch_enabled', False) and not params.license.get('breach_watch_feature_disable', False):
            params.breach_watch = BreachWatch()
            if params.enforcements and 'booleans' in params.enforcements:
                bw_audit = next((x.get('value') for x in params.enforcements['booleans'] if x.get('key') == 'send_breach_watch_events'), None)
                if bw_audit:
                    params.breach_watch.send_audit_events = True

        logging.info(bcolors.OKGREEN + "Successfully authenticated with " + login_type_message + "" + bcolors.ENDC)
        return True

    @staticmethod
    def get_data_key(params: KeeperParams, resp: proto.LoginResponse):
        """Get decrypted data key and store in params.data_key

        Returns login_type_message which is one of ("Persistent Login", "Password", "Master Password").
        """
        if resp.encryptedDataKeyType == proto.BY_DEVICE_PUBLIC_KEY:
            decrypted_data_key = CommonHelperMethods.decrypt_ec(params, resp.encryptedDataKey)
            if params.sso_login_info:
                login_type_message = bcolors.UNDERLINE + "SSO Login"
            else:
                login_type_message = bcolors.UNDERLINE + "Persistent Login"

        elif resp.encryptedDataKeyType == proto.BY_PASSWORD:
            decrypted_data_key = api.decrypt_encryption_params(
                CommonHelperMethods.bytes_to_url_safe_str(resp.encryptedDataKey),
                params.password)
            login_type_message = bcolors.UNDERLINE + "Password"

        elif resp.encryptedDataKeyType == proto.BY_ALTERNATE:
            decrypted_data_key = api.decrypt_data_key(params, resp.encryptedDataKey)
            login_type_message = bcolors.UNDERLINE + "Master Password"

        elif resp.encryptedDataKeyType == proto.NO_KEY \
                or resp.encryptedDataKeyType == proto.BY_BIO:
            raise Exception("Data Key type %s decryption not implemented" % resp.encryptedDataKeyType)
        else:
            raise Exception("Data Key type %s decryption not implemented" % resp.encryptedDataKeyType)

        params.data_key = decrypted_data_key
        return login_type_message

    @staticmethod
    def change_master_password(params: KeeperParams):
        """Change the master password when expired

        Return True if the master password is successfully changed and False otherwise.
        """
        try:
            print('Your Master Password has expired, you are required to change it before you can login.')
            print('')
            while True:
                print('Please choose a new Master Password.')
                password = getpass.getpass(prompt='... {0:>24}: '.format('Master Password'),
                                           stream=None).strip()
                if not password:
                    raise KeyboardInterrupt()
                password2 = getpass.getpass(prompt='... {0:>24}: '.format('Re-Enter Password'),
                                            stream=None).strip()

                if password == password2:
                    failed_rules = []
                    for rule in params.settings['rules']:
                        pattern = re.compile(rule['pattern'])
                        if not re.match(pattern, password):
                            failed_rules.append(rule['description'])
                    if len(failed_rules) == 0:
                        LoginV3API.change_master_password(params, password)
                        logging.info('Password changed')
                        params.password = password
                        return True
                    else:
                        for description in failed_rules:
                            logging.warning(description)
                else:
                    logging.warning('Passwords do not match.')
        except KeyboardInterrupt:
            logging.info('Canceled')
        return False

    @staticmethod
    def populateAccountSummary(params: KeeperParams):

        acct_summary = LoginV3API.accountSummary(params)

        if acct_summary.clientKey:
            try:
                params.client_key = crypto.decrypt_aes_v1(acct_summary.clientKey, params.data_key)
            except Exception as e:
                logging.debug('Decrypt client key error: %s', e)

        # Loading summary as dictionary for backwards compatibility
        acct_summary_json = MessageToJson(acct_summary, preserving_proto_field_name=False)
        acct_summary_dict = json.loads(acct_summary_json)
        acct_summary_dict_snake_case = decamelize(acct_summary_dict)

        if 'keys_info' in acct_summary_dict_snake_case:
            keys = acct_summary_dict_snake_case['keys_info']

            # if 'encrypted_data_key' in keys:
            #     encrypted_data_key = base64.urlsafe_b64decode(keys['encrypted_data_key'])
            #     key = rest_api.derive_key_v2('data_key', params.password, params.salt, params.iterations)
            #     params.data_key = rest_api.decrypt_aes(encrypted_data_key, key)
            # elif 'encryption_params' in keys:
            #     params.data_key = api.decrypt_encryption_params(keys['encryption_params'], params.password)

            params.rsa_key = api.decrypt_rsa_key(keys['encrypted_private_key'], params.data_key)
            if 'encrypted_ecc_private_key' in keys:
                encrypted_ecc_key = utils.base64_url_decode(keys['encrypted_ecc_private_key'])
                decrypted_ecc_key = crypto.decrypt_aes_v2(encrypted_ecc_key, params.data_key)
                params.ecc_key = crypto.load_ec_private_key(decrypted_ecc_key)

        if not params.session_token:
            if 'session_token' in acct_summary_dict_snake_case:
                params.session_token = acct_summary_dict_snake_case['session_token']

        # enforcements
        if 'enforcements' in acct_summary_dict_snake_case:
            params.enforcements = acct_summary_dict_snake_case['enforcements']
            if params.enforcements:
                if 'logout_timer_desktop' in params.enforcements:
                    logout_timer = params.enforcements['logout_timer_desktop']
                    if logout_timer > 0:
                        if params.logout_timer == 0 or logout_timer < params.logout_timer:
                            params.logout_timer = logout_timer

        # settings
        params.settings = acct_summary_dict_snake_case['settings']

        # keys
        # if acct_summary.clientKey:
        #     clientKey = acct_summary.clientKey

        # if acct_summary.keysInfo:
        #     if acct_summary.keysInfo.encryptedPrivateKey:
        #         print("ddd")

        # license
        params.license = acct_summary_dict_snake_case['license']

        if acct_summary_dict_snake_case.get('is_enterprise_admin'):
            api.query_enterprise(params)

        params.sync_data = True
        params.prepare_commands = True

        server = urlparse(params.rest_context.server_base).hostname
        store_config = not params.config or \
                       params.config.get('user') != params.user or \
                       params.config.get('server') not in [server, params.rest_context.server_base] or \
                       (params.config.get('proxy') or '') != (params.proxy or '')

        if store_config:
            params.config['user'] = params.user
            if params.config.get('server') not in [server, params.rest_context.server_base]:
                params.config['server'] = server
            if params.proxy:
                params.config['proxy'] = params.proxy
            else:
                if 'proxy' in params.config:
                    del params.config['proxy']

            if params.config_filename:
                try:
                    with open(params.config_filename, 'w') as f:
                        json.dump(params.config, f, ensure_ascii=False, indent=2)
                        logging.info('Updated %s', params.config_filename)
                except Exception as e:
                    logging.debug('Unable to update %s. %s', params.config_filename, e)

    @staticmethod
    def verifyDevice(params: KeeperParams, encryptedDeviceToken: bytes, encryptedLoginToken: bytes):

        print("Approve by selecting a method below:")

        print("\t\"" + bcolors.OKGREEN + "email_send" + bcolors.ENDC + "\" to send email")
        print("\t\"" + bcolors.OKGREEN + "email_code=<code>" + bcolors.ENDC + "\" to validate verification code sent via email")
        print("\t\"" + bcolors.OKGREEN + "keeper_push" + bcolors.ENDC + "\" to send Keeper Push notification")
        print("\t\"" + bcolors.OKGREEN + "2fa_send" + bcolors.ENDC + "\" to send 2FA code")
        print("\t\"" + bcolors.OKGREEN + "2fa_code=<code>" + bcolors.ENDC + "\" to validate a code provided by 2FA application")
        print("\t\"" + bcolors.OKGREEN + "<Enter>" + bcolors.ENDC + "\" to resume")

        selection = input('Type your selection or <Enter> to resume: ')

        if selection == "email_send" or selection == "es":

            rs = LoginV3API.requestDeviceVerificationMessage(params, encryptedDeviceToken, 'email')

            if type(rs) == bytes:
                print(bcolors.WARNING + "\nAn email with instructions has been sent to " + params.user + bcolors.WARNING + '\nPress <Enter> when approved.')
            else:
                raise KeeperApiError(rs['error'], rs['message'])

        elif selection.startswith("email_code="):
            code = selection.replace("email_code=", "")

            rs = LoginV3API.validateDeviceVerificationCodeMessage(
                params,
                code
            )

            if type(rs) == bytes:

                print("Successfully verified email code.")
                return True
            else:
                print()
                print(bcolors.WARNING + rs['message'] + bcolors.ENDC)

        elif selection == "2fa_send" or selection == "2fs":
            rs = LoginV3API.twoFactorSend2FAPushMessage(
                params,
                encryptedLoginToken)
            if type(rs) == bytes:
                print(bcolors.WARNING + "\n2FA code was sent." + bcolors.ENDC)
            else:
                raise KeeperApiError(rs['error'], rs['message'])

        elif selection.startswith("2fa_code="):
            code = selection.replace("2fa_code=", "")

            rs = LoginV3API.twoFactorValidateMessage(params, encryptedLoginToken, code, proto.TWO_FA_EXP_IMMEDIATELY)

            if type(rs) == bytes:
                logging.info("Successfully verified 2FA code.")
                return True
            else:
                raise KeeperApiError(rs['error'], rs['message'])

        elif selection == "keeper_push" or selection == "kp":

            rs = LoginV3API.twoFactorSend2FAPushMessage(
                params,
                encryptedLoginToken,
                pushType=proto.TWO_FA_PUSH_KEEPER)

            if type(rs) == bytes:
                logging.info('Successfully made a push notification to the approved device.\nPress <Enter> when approved.')
            else:
                raise KeeperApiError(rs['error'], rs['message'])

        elif selection == "":
            return True

    @staticmethod
    def handleSsoRequestDataKey(params, login_token, device_token):  # type: (KeeperParams, bytes) -> None
        print('Approve this device by selecting a method below:')
        print('  1. Keeper Push. Send a push notification to your device.')
        print('  2. Admin Approval. Request your admin to approve this device.')
        print('')
        print('  r. Resume SSO login after device is approved.')
        print('  q. Quit SSO login attempt and return to Commander prompt.')

        while True:
            answer = input('Selection: ')
            if answer == 'q':
                raise KeyboardInterrupt()
            if answer == 'r':
                return
            try:
                if answer == '1':
                    rq = proto.TwoFactorSendPushRequest()
                    rq.pushType = proto.TWO_FA_PUSH_KEEPER
                    rq.encryptedLoginToken = login_token

                    api.communicate_rest(params, rq, "authentication/2fa_send_push")
                elif answer == '2':
                    rq = proto.DeviceVerificationRequest()
                    rq.username = params.user
                    rq.clientVersion = rest_api.CLIENT_VERSION
                    rq.encryptedDeviceToken = device_token

                    rs = api.communicate_rest(params, rq, "authentication/request_device_admin_approval", rs_type=proto.DeviceVerificationResponse)
                    if rs.deviceStatus == proto.DEVICE_OK:
                        return
                elif answer:
                    logging.info(f'Action \"{answer}\" is not supported.')
            except Exception as e:
                logging.warning(f'Device approval request failed: {e}')

    @staticmethod
    def handleSsoRedirect(params, is_cloud, sso_url, login_token):  # type: (KeeperParams, bool, str, bytes) -> bytes
        sp_url_builder = urlparse(sso_url)
        sp_url_query = parse_qsl(sp_url_builder.query, keep_blank_values=True)
        if is_cloud:
            sso_rq = ssocloud.SsoCloudRequest()
            sso_rq.clientVersion = rest_api.CLIENT_VERSION
            sso_rq.dest = 'commander'
            sso_rq.username = params.user.lower()
            sso_rq.forceLogin = False
            sso_rq.detached = True

            transmission_key = utils.generate_aes_key()
            rq_payload = proto.ApiRequestPayload()
            rq_payload.apiVersion = 3
            rq_payload.payload = sso_rq.SerializeToString()
            api_rq = proto.ApiRequest()
            api_rq.locale = params.rest_context.locale or 'en_US'

            server_public_key = rest_api.SERVER_PUBLIC_KEYS[params.rest_context.server_key_id]
            if isinstance(server_public_key, rsa.RSAPublicKey):
                api_rq.encryptedTransmissionKey = crypto.encrypt_rsa(transmission_key, server_public_key)
            elif isinstance(server_public_key, ec.EllipticCurvePublicKey):
                api_rq.encryptedTransmissionKey = crypto.encrypt_ec(transmission_key, server_public_key)
            else:
                raise ValueError('Invalid server public key')
            api_rq.publicKeyId = params.rest_context.server_key_id
            api_rq.encryptedPayload = crypto.encrypt_aes_v2(rq_payload.SerializeToString(), transmission_key)

            sp_url_query.append(('payload', utils.base64_url_encode(api_rq.SerializeToString())))
        else:
            rsa_private, rsa_public = crypto.generate_rsa_key()
            rsa_public_bytes = crypto.unload_rsa_public_key(rsa_public)
            sp_url_query.append(('key', utils.base64_url_encode(rsa_public_bytes)))
            sp_url_query.append(('dest', 'commander'))
            sp_url_query.append(('embedded', ''))

        try:
            wb = webbrowser.get()
        except:
            wb = None
        sp_url_builder = sp_url_builder._replace(query=urlencode(sp_url_query, doseq=True))
        sp_url = urlunparse(sp_url_builder)
        print(f'\nSSO Login URL:\n{sp_url}')
        print('Navigate to SSO Login URL with your browser and complete login.')
        print('Copy a returned SSO Token into clipboard.')
        print('Paste that token into Commander')
        print('NOTE: To copy SSO Token please click "Copy login token" button on "SSO Connect" page.')
        print('')
        print('  a. SSO User with a Master Password')
        print('  c. Copy SSO Login URL to clipboard')
        if wb:
            print('  o. Navigate to SSO Login URL with the default web browser')
        print('  p. Paste SSO Token from clipboard')
        print('  q. Quit SSO login attempt and return to Commander prompt')

        while True:
            token = input('Selection: ')
            if token == 'q':
                raise KeyboardInterrupt()
            if token == 'a':
                return None
            if token == 'c':
                token = None
                try:
                    pyperclip.copy(sp_url)
                    print('SSO Login URL is copied to clipboard.')
                except:
                    print('Failed to copy SSO Login URL to clipboard.')
            elif token == 'o':
                token = None
                if wb:
                    try:
                        wb.open_new_tab(sp_url)
                    except:
                        print('Failed to open web browser.')
            elif token == 'p':
                try:
                    token = pyperclip.paste()
                except:
                    token = ''
                    logging.info('Failed to paste from clipboard')
            if token:
                try:
                    if is_cloud:
                        rs_bytes = crypto.decrypt_aes_v2(utils.base64_url_decode(token), transmission_key)
                        sso_rs = ssocloud.SsoCloudResponse()
                        sso_rs.ParseFromString(rs_bytes)
                        params.user = sso_rs.email
                        params.sso_login_info = {
                            'is_cloud': is_cloud,
                            'sso_provider': sso_rs.providerName,
                            'idp_session_id': sso_rs.idpSessionId,
                            'sso_url': sso_url,
                        }
                        return sso_rs.encryptedLoginToken
                    else:
                        sso_dict = json.loads(token)
                        if 'email' in sso_dict:
                            params.user = sso_dict['email']

                        params.sso_login_info = {
                            'is_cloud': is_cloud,
                            'sso_provider': sso_dict.get('provider_name') or '',
                            'idp_session_id': sso_dict.get('session_id') or '',
                            'sso_url': sso_url,
                            'sso_password': []
                        }
                        if 'password' in sso_dict:
                            pswd = utils.base64_url_decode(sso_dict['password'])
                            pswd = crypto.decrypt_rsa(pswd, rsa_private)
                            params.sso_login_info['sso_password'].append(pswd.decode('utf-8'))
                        if 'new_password' in sso_dict:
                            pswd = utils.base64_url_decode(sso_dict['new_password'])
                            pswd = crypto.decrypt_rsa(pswd, rsa_private)
                            params.sso_login_info['sso_password'].append(pswd.decode('utf-8'))

                        if sso_dict.get('login_token'):
                            return utils.base64_url_decode(sso_dict.get('login_token'))
                        else:
                            return login_token
                except Exception as e:
                    logging.warning(f'SSO Login error: {e}')

    @staticmethod
    def two_factor_channel_to_desc(channel):
        if channel == proto.TWO_FA_CODE_TOTP:
            return 'TOTP (Google and Microsoft Authenticator)'
        if channel == proto.TWO_FA_CT_SMS:
            return 'Send SMS Code'
        if channel == proto.TWO_FA_CODE_DUO:
            return 'DUO'
        if channel == proto.TWO_FA_CODE_RSA:
            return 'RSA SecurID'
        if channel == proto.TWO_FA_CT_U2F:
            return 'U2F (FIDO Security Key)'
        if channel == proto.TWO_FA_CT_WEBAUTHN:
            return 'WebAuthN (FIDO2 Security Key)'
        if channel == proto.TWO_FA_CODE_DNA:
            return 'Keeper DNA (Watch)'

    @staticmethod
    def handleTwoFactor(params: KeeperParams, encryptedLoginToken, login_resp):
        print("This account requires 2FA Authentication")

        supported_channels = {proto.TWO_FA_CODE_TOTP, proto.TWO_FA_CT_SMS, proto.TWO_FA_CODE_DUO, proto.TWO_FA_CODE_RSA,
                              proto.TWO_FA_CT_U2F, proto.TWO_FA_CT_WEBAUTHN, proto.TWO_FA_CODE_DNA}
        channels = [x for x in login_resp.channels if x.channelType in supported_channels]

        if LoginV3Flow.warned_on_fido_package:
            channels = [x for x in channels if x.channelType not in {proto.TWO_FA_CT_U2F, proto.TWO_FA_CT_WEBAUTHN}]

        for i in range(len(channels)):
            channel = channels[i]
            print(f"{i+1:>3}. {LoginV3Flow.two_factor_channel_to_desc(channel.channelType)} {channel.channelName} {channel.phoneNumber}")

        print(f"  q. Quit login attempt and return to Commander prompt")
        try:
            selection = input('Selection: ')
            if selection == 'q':
                raise KeyboardInterrupt()
            assert selection.isnumeric()
            idx = 1 if not selection else int(selection)
            assert 1 <= idx <= len(channels)
            channel = channels[idx-1]
            logging.debug(f"Selected {idx}. {LoginV3Flow.two_factor_channel_to_desc(channel.channelType)}")
        except AssertionError:
            print("Invalid entry, additional factors of authentication shown may be configured if not currently enabled.")
            return
        except EOFError:
            exit(1)

        mfa_prompt = False

        if channel.channelType == proto.TWO_FA_CODE_NONE:
            pass

        elif channel.channelType == proto.TWO_FA_CT_SMS:
            rs = LoginV3API.twoFactorSend2FAPushMessage(
                params,
                encryptedLoginToken,
                pushType=proto.TWO_FA_PUSH_SMS,
                channel_uid=channel.channel_uid,
                expireIn=proto.TWO_FA_EXP_IMMEDIATELY
            )

            if type(rs) == bytes:
                logging.info(bcolors.OKGREEN + "\nSuccessfully sent SMS.\n" + bcolors.ENDC)
                mfa_prompt = True
            else:
                logging.error("Was unable to send SMS.")
                raise KeeperApiError(rs['error'], rs['message'])

        elif channel.channelType in {proto.TWO_FA_CT_U2F, proto.TWO_FA_CT_WEBAUTHN}:
            try:
                from .yubikey import yubikey_authenticate
                challenge = json.loads(channel.challenge)
                response = yubikey_authenticate(challenge)

                if response:
                    if channel.channelType == proto.TWO_FA_CT_U2F:
                        signature = response
                        key_value_type = proto.TWO_FA_RESP_U2F
                    else:
                        signature = {
                            "id": utils.base64_url_encode(response['credentialId']),
                            "rawId": utils.base64_url_encode(response['credentialId']),
                            "response": {
                                "authenticatorData": utils.base64_url_encode(response['authenticatorData']),
                                "clientDataJSON": response['clientData'].b64,
                                "signature": utils.base64_url_encode(response['signature']),
                            },
                            "type": "public-key",
                            "clientExtensionResults": response['extensionResults'] or {}
                        }
                        key_value_type = proto.TWO_FA_RESP_WEBAUTHN

                    rs = LoginV3API.twoFactorValidateMessage(params, encryptedLoginToken, json.dumps(signature),
                                                             proto.TWO_FA_EXP_IMMEDIATELY, key_value_type,
                                                             channel_uid=channel.channel_uid)

                    if type(rs) == bytes:

                        print(bcolors.OKGREEN + "Verified 2FA Code." + bcolors.ENDC)

                        two_fa_validation_rs = proto.TwoFactorValidateResponse()
                        two_fa_validation_rs.ParseFromString(rs)

                        return two_fa_validation_rs.encryptedLoginToken
                    else:
                        print(bcolors.FAIL + "Unable to verify code generated by security key" + bcolors.ENDC)

            except ImportError as e:

                logging.warning(e)
                if not LoginV3Flow.warned_on_fido_package:
                    logging.warning(install_fido_package_warning)
                    LoginV3Flow.warned_on_fido_package = True
            except Exception as e:
                logging.error(e)

        elif channel.channelType in {proto.TWO_FA_CT_TOTP, proto.TWO_FA_CT_DUO, proto.TWO_FA_CT_RSA, proto.TWO_FA_CT_DNA}:
            mfa_prompt = True
        else:
            raise NotImplementedError("Unhandled channel type %s" % channel.channelType)

        if mfa_prompt:
            config_expiration = params.config.get('mfa_duration') or 'login'
            mfa_expiration = \
                proto.TWO_FA_EXP_IMMEDIATELY if config_expiration == 'login' else \
                    proto.TWO_FA_EXP_NEVER if config_expiration == 'forever' else \
                        proto.TWO_FA_EXP_30_DAYS

            otp_code = ''
            show_duration = True
            mfa_pattern = re.compile(r'2fa_duration\s*=\s*(.+)', re.IGNORECASE)
            while not otp_code:
                if show_duration:
                    show_duration = False
                    prompt_exp = '\n2FA Code Duration: {0}.\nTo change duration: 2fa_duration=login|30_days|forever' \
                        .format('Require Every Login' if mfa_expiration == proto.TWO_FA_EXP_IMMEDIATELY else
                                'Save on this Device Forever' if mfa_expiration == proto.TWO_FA_EXP_NEVER else
                                'Ask Every 30 days')
                    print(prompt_exp)

                try:
                    answer = input('\nEnter 2FA Code or Duration: ')
                except KeyboardInterrupt:
                    return

                m_duration = re.match(mfa_pattern, answer)
                if m_duration:
                    answer = m_duration.group(1).strip().lower()
                    if answer not in ['login', '30_days', 'forever']:
                        print('Invalid 2FA Duration: {0}'.format(answer))
                        answer = ''

                if answer == 'login':
                    show_duration = True
                    mfa_expiration = proto.TWO_FA_EXP_IMMEDIATELY
                elif answer == '30_days':
                    show_duration = True
                    mfa_expiration = proto.TWO_FA_EXP_30_DAYS
                elif answer == 'forever':
                    show_duration = True
                    mfa_expiration = proto.TWO_FA_EXP_NEVER
                else:
                    otp_code = answer

            rs = LoginV3API.twoFactorValidateMessage(
                params,
                encryptedLoginToken,
                otp_code,
                mfa_expiration,
                channel_uid=channel.channel_uid
            )

            if type(rs) == bytes:

                logging.info(bcolors.OKGREEN + "Successfully verified 2FA Code." + bcolors.ENDC)

                two_fa_validation_rs = proto.TwoFactorValidateResponse()
                two_fa_validation_rs.ParseFromString(rs)

                return two_fa_validation_rs.encryptedLoginToken
            else:
                warning_msg = bcolors.WARNING + "Unable to verify 2FA code '" + otp_code + "'. Regenerate the code and try again." + bcolors.ENDC
                logging.warning(warning_msg)


class LoginV3API:

    @staticmethod
    def rest_request(params: KeeperParams, api_endpoint: str, rq):
        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        rs = rest_api.execute_rest(params.rest_context, api_endpoint, api_request_payload)

        return rs

    @staticmethod
    def get_device_id(params, new_device=False):   # type: (KeeperParams, bool) -> bytes
        if new_device:
            logging.info('Resetting device token')
            params.device_token = None
            if 'device_token' in params.config:
                del params.config['device_token']
            if params.device_private_key:
                params.device_private_key = None
            if 'private_key' in params.config:
                del params.config['private_key']

        encrypted_device_token_str = None

        if params.device_token:
            encrypted_device_token_str = params.device_token
        elif 'device_token' in params.config:
            if params.config['device_token']:
                encrypted_device_token_str = params.config['device_token']

        if encrypted_device_token_str is None:

            public_key = CommonHelperMethods.public_key_ecc(params)

            rq = proto.DeviceRegistrationRequest()

            rq.clientVersion = rest_api.CLIENT_VERSION
            rq.deviceName = CommonHelperMethods.get_device_name()
            rq.devicePublicKey = public_key

            api_request_payload = proto.ApiRequestPayload()
            api_request_payload.payload = rq.SerializeToString()

            rs = rest_api.execute_rest(params.rest_context, 'authentication/register_device', api_request_payload)

            if type(rs) == bytes:
                register_device_rs = proto.Device()
                register_device_rs.ParseFromString(rs)

                # A globally unique device id for each device encrypted by the device token key
                encrypted_device_token_bytes = register_device_rs.encryptedDeviceToken
            else:
                raise KeeperApiError(rs['error'], rs['message'])

            # Get or save key from file
            encrypted_device_token_str = CommonHelperMethods.bytes_to_url_safe_str(encrypted_device_token_bytes)

            CommonHelperMethods.config_file_set_property(params, "device_token", encrypted_device_token_str)

        try:
            encrypted_device_token_bytes = utils.base64_url_decode(encrypted_device_token_str)
        except:
            raise InvalidDeviceToken()
        return encrypted_device_token_bytes

    @staticmethod
    def requestDeviceVerificationMessage(params: KeeperParams,
                                         encrypted_device_token: bytes,
                                         verification_channel: str,
                                         message_session_uid: bytes = None):
        rq = proto.DeviceVerificationRequest()

        rq.username = params.user.lower()
        rq.encryptedDeviceToken = encrypted_device_token
        rq.verificationChannel = verification_channel
        rq.clientVersion = rest_api.CLIENT_VERSION
        rq.messageSessionUid = CommonHelperMethods.url_safe_str_to_bytes(message_session_uid or "")

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        return rest_api.execute_rest(params.rest_context, 'authentication/request_device_verification', api_request_payload)

    @staticmethod
    def validateDeviceVerificationCodeMessage(params: KeeperParams, verificationCode: str, message_session_uid=None):

        rq = proto.ValidateDeviceVerificationCodeRequest()

        rq.username = params.user.lower()
        rq.clientVersion = rest_api.CLIENT_VERSION
        # rq.encryptedDeviceToken = encrypted_device_token
        rq.verificationCode = verificationCode
        rq.messageSessionUid = CommonHelperMethods.url_safe_str_to_bytes(message_session_uid or "")

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        return rest_api.execute_rest(params.rest_context, 'authentication/validate_device_verification_code', api_request_payload)

    @staticmethod
    def resume_login(params: KeeperParams, encryptedLoginToken, encryptedDeviceToken, cloneCode = None, loginType = 'NORMAL', loginMethod='EXISTING_ACCOUNT'):
        rq = proto.StartLoginRequest()
        rq.clientVersion = rest_api.CLIENT_VERSION
        rq.encryptedLoginToken = encryptedLoginToken
        rq.encryptedDeviceToken = encryptedDeviceToken
        rq.username = params.user.lower()
        rq.loginType = proto.LoginType.Value(loginType)
        if cloneCode:
            rq.loginMethod = proto.LoginMethod.Value(loginMethod)
            rq.cloneCode = cloneCode

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        rs = rest_api.execute_rest(params.rest_context, 'authentication/start_login', api_request_payload)

        if type(rs) == bytes:
            login_resp = proto.LoginResponse()
            login_resp.ParseFromString(rs)
            return login_resp

        elif type(rs) is dict:
            if 'error' in rs and 'message' in rs:
                if rs['error'] == 'region_redirect':
                    params.server = rs['region_host']
                    logging.info('Redirecting to region: %s', params.server)
                    LoginV3API.register_device_in_region(params, encryptedDeviceToken)
                    return LoginV3API.startLoginMessage(params, encryptedDeviceToken, loginType=loginType)

                if rs['error'] == 'bad_request':
                    # logging.warning('Pre-Auth error: %s', rs.get('additional_info'))
                    params.device_id = None
                    # continue
                if rs['error'] == 'restricted_client_type':
                    msg = "%s.\n\n%s" % (rs['message'], permissions_error_msg)
                    raise KeeperApiError(rs['error'], msg)
                else:
                    raise KeeperApiError(rs['error'], rs['message'])

    @staticmethod
    def startLoginMessage(params, encryptedDeviceToken, cloneCode = None, loginType = 'NORMAL'):
        # type: (KeeperParams, bytes, Optional[bytes], str) -> proto.LoginResponse
        rq = proto.StartLoginRequest()
        rq.clientVersion = rest_api.CLIENT_VERSION
        rq.username = params.user.lower()
        rq.encryptedDeviceToken = encryptedDeviceToken
        rq.loginType = proto.LoginType.Value(loginType)
        rq.loginMethod = proto.LoginMethod.Value('EXISTING_ACCOUNT')

        if cloneCode:
            rq.cloneCode = cloneCode
            rq.username = ''

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        rs = rest_api.execute_rest(params.rest_context, 'authentication/start_login', api_request_payload)

        if type(rs) == bytes:
            login_resp = proto.LoginResponse()
            login_resp.ParseFromString(rs)

            if not hasattr(login_resp, 'loginState'):
                raise Exception('API did not return login state')

            return login_resp

        elif type(rs) is dict:
            if 'error' in rs and 'message' in rs:
                if rs['error'] == 'region_redirect':
                    params.server = rs['region_host']
                    logging.info('Redirecting to region: %s', params.server)
                    LoginV3API.register_device_in_region(params, encryptedDeviceToken)
                    return LoginV3API.startLoginMessage(params, encryptedDeviceToken, loginType=loginType)

                if rs['error'] == 'device_not_registered':
                    if rs['additional_info'] == 'invalid device token, not registered in this region':
                        LoginV3API.register_device_in_region(params, encryptedDeviceToken)
                        return LoginV3API.startLoginMessage(params, encryptedDeviceToken, loginType=loginType)
                    else:
                        raise InvalidDeviceToken()

                if rs['error'] == 'bad_request':
                    # logging.warning('Pre-Auth error: %s', rs.get('additional_info'))
                    params.device_id = None
                    # continue

                err_msg = rs['message']
                if rs['error'] == 'device_not_registered':
                    err_msg += "\nRegister this user in the current region or change server region"

                add_info = rs.get('additional_info')
                if add_info:
                    err_msg += "\n" + rs['additional_info']

                raise KeeperApiError(rs['error'], err_msg)

    @staticmethod
    def auth_verifier_loginv3(params: KeeperParams):
        derived_key = api.derive_key(params.password, params.salt, params.iterations)
        derived_key = api.hashlib.sha256(derived_key).digest()
        return derived_key

    @staticmethod
    def validateAuthHashMessage(params: KeeperParams, encrypted_login_token_bytes):

        rq = proto.ValidateAuthHashRequest()
        rq.passwordMethod = proto.PasswordMethod.Value("ENTERED")

        rq.authResponse = params.auth_verifier
        rq.encryptedLoginToken = encrypted_login_token_bytes

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        rs = rest_api.execute_rest(params.rest_context, 'authentication/validate_auth_hash', api_request_payload)

        if type(rs) == bytes:
            login_resp = proto.LoginResponse()
            login_resp.ParseFromString(rs)
            return login_resp
        else:
            error_code = rs['error']
            raise KeeperApiError(error_code, 'Invalid email or password combination, please re-enter.' if error_code == 'auth_failed' else rs['message'] )

    @staticmethod
    def twoFactorValidateMessage(params, encryptedLoginToken, otp_code, tfa_expire_in,
                                 twoFactorValueType=None, channel_uid=None):

        rq = proto.TwoFactorValidateRequest()
        rq.encryptedLoginToken = encryptedLoginToken
        rq.value = otp_code

        if twoFactorValueType:
            rq.valueType = twoFactorValueType
        if channel_uid:
            rq.channel_uid = channel_uid

        rq.expireIn = tfa_expire_in

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        rs = rest_api.execute_rest(params.rest_context, 'authentication/2fa_validate', api_request_payload)

        return rs

    @staticmethod
    def twoFactorSend2FAPushMessage(params: KeeperParams,
                                    encryptedLoginToken: bytes,
                                    pushType=None,
                                    channel_uid=None,
                                    expireIn=None):

        rq = proto.TwoFactorSendPushRequest()

        rq.encryptedLoginToken = encryptedLoginToken
        if channel_uid:
            rq.channel_uid = channel_uid

        if expireIn:
            rq.expireIn = expireIn

        if pushType:
            rq.pushType = pushType

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        return rest_api.execute_rest(params.rest_context, 'authentication/2fa_send_push', api_request_payload)

    @staticmethod
    def rename_device(params: KeeperParams, new_name):

        rq = proto.DeviceUpdateRequest()
        rq.clientVersion = rest_api.CLIENT_VERSION
        # rq.deviceStatus = proto.DEVICE_OK
        rq.deviceName = new_name
        rq.encryptedDeviceToken = LoginV3API.get_device_id(params)

        api.communicate_rest(params, rq, 'authentication/update_device')

    @staticmethod
    def change_master_password(params: KeeperParams, password):
        auth_salt = os.urandom(16)
        data_salt = os.urandom(16)
        rq = {
            'command': 'change_master_password',
            'auth_verifier': api.create_auth_verifier(password, auth_salt, params.iterations),
            'encryption_params': api.create_encryption_params(password, data_salt, params.iterations, params.data_key)
        }
        rs = api.communicate(params, rq)
        params.password = password
        params.salt = auth_salt

    @staticmethod
    def register_encrypted_data_key_for_device(params: KeeperParams):
        rq = proto.RegisterDeviceDataKeyRequest()

        rq.encryptedDeviceToken = LoginV3API.get_device_id(params)
        rq.encryptedDeviceDataKey = CommonHelperMethods.get_encrypted_device_data_key(params)

        try:
            api.communicate_rest(params, rq, 'authentication/register_encrypted_data_key_for_device')
        except KeeperApiError as e:
            if e.result_code == 'device_data_key_exists':
                return False
            raise e

        return True

    @staticmethod
    def register_device_in_region(params, encrypted_device_token):  # type: (KeeperParams, bytes) -> None
        rq = proto.RegisterDeviceInRegionRequest()
        rq.encryptedDeviceToken = encrypted_device_token
        rq.clientVersion = rest_api.CLIENT_VERSION
        rq.deviceName = CommonHelperMethods.get_device_name()
        rq.devicePublicKey = CommonHelperMethods.public_key_ecc(params)

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()
        rs = rest_api.execute_rest(params.rest_context, 'authentication/register_device_in_region', api_request_payload)
        if isinstance(rs, dict):
            raise InvalidDeviceToken()

    @staticmethod
    def set_user_setting(params: KeeperParams, name: str, value: str):

        # Available setting names:
        #   - logout_timer
        #   - persistent_login
        #   - ip_disable_auto_approve

        rq = proto.UserSettingRequest()
        rq.setting = name
        rq.value = value

        try:
            rs = api.communicate_rest(params, rq, 'setting/set_user_setting')
        except Exception as e:
            raise e

        return True

    @staticmethod
    def accountSummary(params: KeeperParams):
        rq = proto_as.AccountSummaryRequest()
        rq.summaryVersion = 1
        return api.communicate_rest(params, rq, 'login/account_summary', rs_type=proto_as.AccountSummaryElements)

    @staticmethod
    def loginToMc(rest_context, session_token, mc_id):

        endpoint = 'authentication/login_to_mc'

        rq = LoginToMcRequest()
        rq.mcEnterpriseId = mc_id

        api_request_payload = proto.ApiRequestPayload()
        # api_request_payload.payload = rq.SerializeToString()

        api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(session_token + '==')
        api_request_payload.payload = rq.SerializeToString()

        try:
            rs = rest_api.execute_rest(rest_context, endpoint, api_request_payload)
        except Exception as e:
            raise KeeperApiError('Rest API', str(e))

        if type(rs) == bytes:

            login_to_mc_rs = LoginToMcResponse()
            login_to_mc_rs.ParseFromString(rs)

            return login_to_mc_rs
        elif type(rs) == dict:
            raise KeeperApiError(rs['error'], rs['message'])
        raise KeeperApiError('Error', endpoint)

    @staticmethod
    def create_user(params, new_username, user_password, verification_code):
        # type: (KeeperParams, str, str, Optional[str]) -> None
        endpoint = 'authentication/request_create_user'
        data_key = utils.generate_aes_key()
        auth_verifier = utils.create_auth_verifier(user_password, crypto.get_random_bytes(16), 100000)
        encryption_params = utils.create_encryption_params(user_password, crypto.get_random_bytes(16), 100000, data_key)

        rsa_pri, rsa_pub = crypto.generate_rsa_key()
        rsa_private = crypto.unload_rsa_private_key(rsa_pri)
        rsa_private = crypto.encrypt_aes_v1(rsa_private, data_key)
        rsa_public = crypto.unload_rsa_public_key(rsa_pub)

        ec_pri, ec_pub = crypto.generate_ec_key()
        ec_private = crypto.unload_ec_private_key(ec_pri)
        ec_private = crypto.encrypt_aes_v2(ec_private, data_key)
        ec_public = crypto.unload_ec_public_key(ec_pub)

        create_user_rq = proto.CreateUserRequest()
        create_user_rq.clientVersion = rest_api.CLIENT_VERSION
        create_user_rq.username = new_username
        create_user_rq.authVerifier = auth_verifier
        create_user_rq.encryptionParams = encryption_params
        create_user_rq.rsaPublicKey = rsa_public
        create_user_rq.rsaEncryptedPrivateKey = rsa_private
        create_user_rq.eccPublicKey = ec_public
        create_user_rq.eccEncryptedPrivateKey = ec_private
        create_user_rq.encryptedClientKey = crypto.encrypt_aes_v1(utils.generate_aes_key(), data_key)
        create_user_rq.encryptedDeviceToken = LoginV3API.get_device_id(params)

        device_private_key = CommonHelperMethods.get_private_key_ecc(params)
        create_user_rq.encryptedDeviceDataKey = crypto.encrypt_ec(data_key, device_private_key.public_key())

        if verification_code:
            create_user_rq.verificationCode = verification_code

        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = create_user_rq.SerializeToString()
        rs = rest_api.execute_rest(params.rest_context, endpoint, api_request_payload)
        if isinstance(rs, dict):
            raise KeeperApiError(rs['error'], rs['message'])


class CommonHelperMethods:

    @staticmethod
    def bytes_to_int(b):
        return int.from_bytes(b, byteorder='big')

    @staticmethod
    def url_safe_str_to_bytes(s):
        b = base64.urlsafe_b64decode(s + '==')
        return b

    @staticmethod
    def url_safe_str_to_int(s):
        b = CommonHelperMethods.url_safe_str_to_bytes(s)
        return CommonHelperMethods.bytes_to_int(b)

    @staticmethod
    def bytes_to_url_safe_str(b):
        return base64.urlsafe_b64encode(b).decode().rstrip('=')

    @staticmethod
    def get_os():
        if _platform.lower().startswith("linux"):
            return "linux"
        elif _platform.lower().startswith("darwin"):
            return "macOS"
        # elif _platform.lower().startswith("win32"):
        #     return "win32"
        # elif _platform.lower().startswith("win64"):
        #     return "win64"
        else:
            return _platform

    @staticmethod
    def public_key_ecc(params: KeeperParams):
        private_key = CommonHelperMethods.get_private_key_ecc(params)
        pub_key = private_key.public_key()
        pub_key_bytes = pub_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return pub_key_bytes

    @staticmethod
    def generate_ecc_keys():

        encryption_key_bytes = CommonHelperMethods.generate_encryption_key_bytes()
        private_key_str = CommonHelperMethods.bytes_to_url_safe_str(encryption_key_bytes)
        encryption_key_int = CommonHelperMethods.url_safe_str_to_int(private_key_str)
        private_key = ec.derive_private_key(encryption_key_int, ec.SECP256R1(), default_backend())

        return private_key

    @staticmethod
    def generate_new_ecc_key():
        curve = ec.SECP256R1()
        ephemeral_key = ec.generate_private_key(curve, default_backend())
        return ephemeral_key

    @staticmethod
    def decrypt_ec(params: KeeperParams, encrypted_data_bag: bytes):
        curve = ec.SECP256R1()

        ecc_private_key = CommonHelperMethods.get_private_key_ecc(params)

        server_public_key = encrypted_data_bag[:65]
        encrypted_data = encrypted_data_bag[65:]

        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, server_public_key)
        shared_key = ecc_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(shared_key)
        enc_key = digest.finalize()
        decrypted_data = rest_api.decrypt_aes(encrypted_data, enc_key)
        return decrypted_data

    @staticmethod
    def startup_check(params: KeeperParams):
        if not params.config_filename:
            return



        if os.path.isfile(params.config_filename) and os.access(params.config_filename, os.R_OK):
            # checks if file exists
            logging.debug("Configuration file '" + params.config_filename + "' exists and is readable")
        else:
            logging.debug("Either config file is missing or is not readable, creating file...")
            with io.open(os.path.join(params.config_filename), 'w') as config_file:
                json.dump({}, config_file, sort_keys=False, indent=4)
                config_file.close()

    @staticmethod
    def get_private_key_ecc(params: KeeperParams):

        if params.device_private_key:
            private_key_str = params.device_private_key
        elif 'private_key' not in params.config:
            encryption_key_bytes = CommonHelperMethods.generate_encryption_key_bytes()
            private_key_str = CommonHelperMethods.bytes_to_url_safe_str(encryption_key_bytes)

            params.config['private_key'] = private_key_str

            CommonHelperMethods.config_file_set_property(params, 'private_key', private_key_str)

        else:
            private_key_str = params.config['private_key']

        encryption_key_int = CommonHelperMethods.url_safe_str_to_int(private_key_str)

        private_key = ec.derive_private_key(encryption_key_int, ec.SECP256R1(), default_backend())

        return private_key

    @staticmethod
    def config_file_get_property_as_str(params: KeeperParams, key):

        if params.config_filename and os.path.exists(params.config_filename):
            try:
                try:
                    with open(params.config_filename) as config_file:
                        config_data = json.load(config_file)

                        if key in config_data:
                            return config_data[key]

                        else:
                            return None

                except Exception as e:
                    logging.error('Unable to parse JSON configuration file "%s"', params.config_filename)
                    answer = input('Do you want to delete it (y/N): ')
                    if answer in ['y', 'Y']:
                        os.remove(params.config_filename)
                    else:
                        raise e
            except IOError as ioe:
                logging.warning('Error: Unable to open config file %s: %s', params.config_filename, ioe)

    @staticmethod
    def config_file_get_property_as_bytes(params: KeeperParams, key):
        val_str = CommonHelperMethods.config_file_get_property_as_str(params, key)
        if val_str:
            val_bytes = CommonHelperMethods.url_safe_str_to_bytes(val_str)
            return val_bytes
        else:
            return None

    @staticmethod
    def config_file_set_property(params: KeeperParams, key: str, val: str):

        if not params.config_filename:
            return

        with open(params.config_filename, 'r') as json_file:
            config_data = json.load(json_file)
            json_file.close()
        config_data[key] = val

        with open(params.config_filename, 'w') as json_file:
            json.dump(config_data, json_file, sort_keys=False, indent=4)
            json_file.close()

        params.config[key] = val

        logging.debug("set property: " + key + ":"+val + ".\t Conf. file: " + params.config_filename)

    @staticmethod
    def get_encrypted_device_data_key(params: KeeperParams):
        try:
            device_public_key = CommonHelperMethods.get_private_key_ecc(params).public_key()
            ephemeral_key2 = CommonHelperMethods.generate_new_ecc_key()
            shared_key = ephemeral_key2.exchange(ec.ECDH(), device_public_key)
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_key)
            enc_key = digest.finalize()
            encrypted_data_key = rest_api.encrypt_aes(params.data_key, enc_key)
            eph_public_key = ephemeral_key2.public_key().public_bytes(serialization.Encoding.X962,
                                                                      serialization.PublicFormat.UncompressedPoint)

            return eph_public_key + encrypted_data_key

        except Exception as e:
            logging.warning(e)
            return

    @staticmethod
    def persist_state_data(params: KeeperParams):

        clone_code_str = CommonHelperMethods.bytes_to_url_safe_str(params.clone_code)
        CommonHelperMethods.config_file_set_property(params, "clone_code", clone_code_str)

    @staticmethod
    def generate_random_bytes(length):
        return os.urandom(length)

    @staticmethod
    def generate_encryption_key_bytes():
        return CommonHelperMethods.generate_random_bytes(32)

    @staticmethod
    def get_device_name():
        return "Commander CLI on %s" % CommonHelperMethods.get_os()

    @staticmethod
    def check_int(s):
        # check if string is an integer
        num_str = str(s)

        if num_str[0] in ('-', '+'):
            return num_str[1:].isdigit()
        return num_str.isdigit()

    @staticmethod
    def generate_rsa_key_pair():

        rsa_key = RSA.generate(2048)

        private_key = DerSequence([0,
                                   rsa_key.n,
                                   rsa_key.e,
                                   rsa_key.d,
                                   rsa_key.p,
                                   rsa_key.q,
                                   rsa_key.d % (rsa_key.p - 1),
                                   rsa_key.d % (rsa_key.q - 1),
                                   Integer(rsa_key.q).inverse(rsa_key.p)
                                   ]).encode()
        pub_key = rsa_key.publickey()
        public_key = DerSequence([pub_key.n,
                                  pub_key.e
                                  ]).encode()

        return private_key, public_key

    @staticmethod
    def fill_password_with_prompt_if_missing(params: KeeperParams):
        while not params.user:
            params.user = getpass.getpass(prompt='User(Email): ', stream=None)

        if not params.password:
            logging.info('\nEnter password for {0}'.format(params.user))
            try:
                params.password = getpass.getpass(prompt='Password: ', stream=None)
            except KeyboardInterrupt:
                print('')
            except EOFError:
                return 0


class InvalidDeviceToken(Exception):
    pass
