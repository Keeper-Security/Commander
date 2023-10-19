import base64
import bisect
import getpass
import json
import logging
import os
import re
import webbrowser
from sys import platform as _platform
from typing import Optional, List
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

import pyperclip
from prompt_toolkit.shortcuts import prompt
from prompt_toolkit.lexers.base import Lexer
from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.validation import Validator, ValidationError
from prompt_toolkit.filters import completion_is_selected
from prompt_toolkit.enums import EditingMode
from prompt_toolkit.shortcuts import CompleteStyle
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from google.protobuf.json_format import MessageToJson

from . import api, rest_api, utils, crypto, constants, generator
from .breachwatch import BreachWatch
from .config_storage import loader
from .display import bcolors
from .error import KeeperApiError
from .humps import decamelize
from .params import KeeperParams
from .proto import APIRequest_pb2 as proto, AccountSummary_pb2 as proto_as
from .proto import breachwatch_pb2 as breachwatch_proto
from .proto import ssocloud_pb2 as ssocloud
from .proto.enterprise_pb2 import LoginToMcRequest, LoginToMcResponse, DomainPasswordRulesRequest

permissions_error_msg = "Grant Commander SDK permissions to access Keeper by navigating to Admin Console -> Admin -> " \
                        "Roles -> [Select User's Role] -> Enforcement Policies -> Platform Restrictions -> Click on " \
                        "'Enable' check box next to Commander SDK.\nAlso note that if user has more than two roles " \
                        "assigned then the most restrictive policy from all the roles will be applied."


class LoginV3Flow:
    @staticmethod
    def login(params, new_device=False, new_login=False):   # type: (KeeperParams, bool, bool) -> None

        logging.debug("Login v3 Start as '%s'", params.user)

        encryptedDeviceToken = LoginV3API.get_device_id(params, new_device)

        if new_login:
            clone_code_bytes = None
        else:
            clone_code_bytes = utils.base64_url_decode(params.clone_code) if params.clone_code else None

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
                if len(resp.salt) > 0:
                    salt = api.get_correct_salt(resp.salt)

                    salt_bytes = salt.salt
                    salt_iterations = salt.iterations
                    is_entered = False

                    while True:
                        if not params.password and params.sso_login_info:
                            if 'sso_password' in params.sso_login_info and params.sso_login_info['sso_password']:
                                params.password = params.sso_login_info['sso_password'].pop()

                        try:
                            is_entered = CommonHelperMethods.fill_password_with_prompt_if_missing(params, is_entered)
                        except NeedAccountRecovery:
                            LoginV3API.handle_account_recovery(params, resp.encryptedLoginToken)
                            return

                        if not params.password:
                            return

                        params.salt = salt_bytes
                        params.iterations = salt_iterations
                        params.auth_verifier = crypto.derive_keyhash_v1(params.password, salt_bytes, salt_iterations)

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
                else:
                    LoginV3API.handle_account_recovery(params, resp.encryptedLoginToken)
                    return

                if LoginV3Flow.post_login_processing(params, resp):
                    return
                else:
                    # Not successfully authenticated, so restart login process
                    clone_code_bytes = utils.base64_url_decode(params.clone_code) if params.clone_code else None
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
        params.clone_code = utils.base64_url_encode(resp.cloneCode)
        loader.store_config_properties(params)

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
                print('Your Master Password has expired, you are required to change it before you can login.\n')
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
                    if rs.enterprisePublicKey:
                        params.enterprise_rsa_key = crypto.load_rsa_public_key(rs.enterprisePublicKey)
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
            private_key = crypto.load_ec_private_key(utils.base64_url_decode(params.device_private_key))
            decrypted_data_key = crypto.decrypt_ec(resp.encryptedDataKey, private_key)
            if params.sso_login_info:
                login_type_message = bcolors.UNDERLINE + "SSO Login"
            else:
                login_type_message = bcolors.UNDERLINE + "Persistent Login"

        elif resp.encryptedDataKeyType == proto.BY_PASSWORD:
            decrypted_data_key = \
                utils.decrypt_encryption_params(resp.encryptedDataKey, params.password)
            login_type_message = bcolors.UNDERLINE + "Password"

        elif resp.encryptedDataKeyType == proto.BY_ALTERNATE:
            decryption_key = crypto.derive_keyhash_v2('data_key', params.password, params.salt, params.iterations)
            decrypted_data_key = crypto.decrypt_aes_v2(resp.encryptedDataKey, decryption_key)
            login_type_message = bcolors.UNDERLINE + "Master Password"

        elif resp.encryptedDataKeyType == proto.NO_KEY \
                or resp.encryptedDataKeyType == proto.BY_BIO:
            raise Exception("Data Key type %s decryption not implemented" % resp.encryptedDataKeyType)
        else:
            raise Exception("Data Key type %s decryption not implemented" % resp.encryptedDataKeyType)

        params.data_key = decrypted_data_key
        return login_type_message

    @staticmethod
    def get_default_password_rules(params):  # type: (KeeperParams) -> (List[proto.PasswordRules], int)
        rq = DomainPasswordRulesRequest()
        rq.username = params.user
        rs = api.communicate_rest(params, rq, 'authentication/get_domain_password_rules',
                                  rs_type=proto.NewUserMinimumParams)
        rules = []
        for regexp, description in zip(rs.passwordMatchRegex, rs.passwordMatchDescription):
            rule = proto.PasswordRules()
            rule.match = True
            rule.pattern = regexp
            rule.description = description
            rules.append(rule)

        return rules, rs.minimumIterations

    @staticmethod
    def change_master_password(params, password_rules=None, min_iterations=None):
        # type: (KeeperParams, Optional[List[proto.PasswordRules]], Optional[int]) -> bool
        """Change the master password when expired

        Return True if the master password is successfully changed and False otherwise.
        """
        if password_rules is None:
            password_rules, min_iterations = LoginV3Flow.get_default_password_rules(params)

        try:
            while True:
                print('Please choose a new Master Password.')
                password = getpass.getpass(prompt='... {0:>24}: '.format('Master Password'), stream=None).strip()
                if not password:
                    raise KeyboardInterrupt()
                password2 = getpass.getpass(prompt='... {0:>24}: '.format('Re-Enter Password'), stream=None).strip()

                if password == password2:
                    failed_rules = []
                    for rule in password_rules:
                        pattern = re.compile(rule.pattern)
                        if not re.match(pattern, password):
                            failed_rules.append(rule.description)
                    if len(failed_rules) == 0:
                        LoginV3API.change_master_password(params, password, min_iterations)
                        logging.info('Password changed')
                        params.password = password
                        return True
                    else:
                        for description in failed_rules:
                            logging.warning(f'\t{description}')
                else:
                    logging.warning('Passwords do not match.')
        except KeyboardInterrupt:
            logging.info('Canceled')
        params.session_token = None
        params.data_key = None
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
            if 'encrypted_private_key' in keys:
                params.rsa_key = api.decrypt_rsa_key(keys['encrypted_private_key'], params.data_key)
                encrypted_private_key = utils.base64_url_decode(keys['encrypted_private_key'])
                decrypted_private_key = crypto.decrypt_aes_v1(encrypted_private_key, params.data_key)
                params.rsa_key2 = crypto.load_rsa_private_key(decrypted_private_key)
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
    def handleSsoRequestDataKey(params, login_token, device_token):  # type: (KeeperParams, bytes, bytes) -> None
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
    def handleSsoRedirect(params, is_cloud, sso_url, login_token):
        # type: (KeeperParams, bool, str, bytes) -> Optional[bytes]
        sp_url_builder = urlparse(sso_url)
        sp_url_query = parse_qsl(sp_url_builder.query, keep_blank_values=True)
        if is_cloud:
            sso_rq = ssocloud.SsoCloudRequest()
            sso_rq.messageSessionUid = crypto.get_random_bytes(16)
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
            else:
                if len(token) < 10:
                    print(f'Unsupported menu option: {token}')
                    token = None
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
        if channel == proto.TWO_FA_CT_TOTP:
            return 'TOTP (Google and Microsoft Authenticator)'
        if channel == proto.TWO_FA_CT_SMS:
            return 'Send SMS Code'
        if channel == proto.TWO_FA_CT_DUO:
            return 'DUO'
        if channel == proto.TWO_FA_CT_RSA:
            return 'RSA SecurID'
        if channel == proto.TWO_FA_CT_U2F:
            return 'U2F (FIDO Security Key)'
        if channel == proto.TWO_FA_CT_WEBAUTHN:
            return 'WebAuthN (FIDO2 Security Key)'
        if channel == proto.TWO_FA_CT_DNA:
            return 'Keeper DNA (Watch)'
        if channel == proto.TWO_FA_CT_BACKUP:
            return 'Backup Codes'

    @staticmethod
    def handleTwoFactor(params: KeeperParams, encryptedLoginToken, login_resp):
        print("This account requires 2FA Authentication")

        supported_channels = {proto.TWO_FA_CODE_TOTP, proto.TWO_FA_CT_SMS, proto.TWO_FA_CT_DUO, proto.TWO_FA_CT_RSA,
                              proto.TWO_FA_CT_U2F, proto.TWO_FA_CT_WEBAUTHN, proto.TWO_FA_CT_DNA,
                              proto.TWO_FA_CT_BACKUP}
        channels = [x for x in login_resp.channels if x.channelType in supported_channels]

        if len(channels) == 0:
            backup_code_channel = proto.TwoFactorChannelInfo()
            backup_code_channel.channelType = proto.TWO_FA_CT_BACKUP
            channels.append(backup_code_channel)

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
                from .yubikey.yubikey import yubikey_authenticate
                challenge = json.loads(channel.challenge)
                response = yubikey_authenticate(challenge)

                if response:
                    if channel.channelType == proto.TWO_FA_CT_U2F:
                        signature = response
                        key_value_type = proto.TWO_FA_RESP_U2F
                    else:
                        credential_id = response.credential_id
                        signature = {
                            "id": utils.base64_url_encode(credential_id),
                            "rawId": utils.base64_url_encode(credential_id),
                            "response": {
                                "authenticatorData": utils.base64_url_encode(response.authenticator_data),
                                "clientDataJSON": response.client_data.b64,
                                "signature": utils.base64_url_encode(response.signature),
                            },
                            "type": "public-key",
                            "clientExtensionResults": response.extension_results or {}
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
                from .yubikey import display_fido2_warning
                display_fido2_warning()
                logging.warning(e)
            except Exception as e:
                logging.error(e)

        elif channel.channelType in {proto.TWO_FA_CT_TOTP, proto.TWO_FA_CT_DUO, proto.TWO_FA_CT_RSA,
                                     proto.TWO_FA_CT_DNA, proto.TWO_FA_CT_BACKUP}:
            mfa_prompt = True
        else:
            raise NotImplementedError(f"Unhandled channel type {channel.channelType}")

        if mfa_prompt:
            config_expiration = params.config.get('mfa_duration') or 'login'
            mfa_expiration = \
                proto.TWO_FA_EXP_IMMEDIATELY if config_expiration == 'login' else \
                    proto.TWO_FA_EXP_NEVER if config_expiration == 'forever' else \
                        proto.TWO_FA_EXP_12_HOURS if config_expiration == '12_hours' else \
                            proto.TWO_FA_EXP_24_HOURS if config_expiration == '24_hours' else \
                                proto.TWO_FA_EXP_30_DAYS

            if mfa_expiration > channel.maxExpiration:
                mfa_expiration = channel.maxExpiration

            allowed_expirations = ['login']     # type: List[str]
            if channel.maxExpiration >= proto.TWO_FA_EXP_12_HOURS:
                allowed_expirations.append('12_hours')
            if channel.maxExpiration >= proto.TWO_FA_EXP_24_HOURS:
                allowed_expirations.append('24_hours')
            if channel.maxExpiration >= proto.TWO_FA_EXP_30_DAYS:
                allowed_expirations.append('30_days')
            if channel.maxExpiration >= proto.TWO_FA_EXP_NEVER:
                allowed_expirations.append('forever')

            otp_code = ''
            show_duration = True
            mfa_pattern = re.compile(r'2fa_duration\s*=\s*(.+)', re.IGNORECASE)
            while not otp_code:
                if show_duration:
                    show_duration = False
                    prompt_exp = '\n2FA Code Duration: {0}.\nTo change duration: 2fa_duration={1}'.format(
                        'Require Every Login' if mfa_expiration == proto.TWO_FA_EXP_IMMEDIATELY else
                        'Save on this Device Forever' if mfa_expiration == proto.TWO_FA_EXP_NEVER else
                        'Ask Every 12 hours' if mfa_expiration == proto.TWO_FA_EXP_12_HOURS else
                        'Ask Every 24 hours' if mfa_expiration == proto.TWO_FA_EXP_24_HOURS else
                        'Ask Every 30 days',
                        "|".join(allowed_expirations))
                    print(prompt_exp)

                try:
                    answer = input('\nEnter 2FA Code or Duration: ')
                except KeyboardInterrupt:
                    return

                m_duration = re.match(mfa_pattern, answer)
                if m_duration:
                    answer = m_duration.group(1).strip().lower()
                    if answer not in allowed_expirations:
                        print(f'Invalid 2FA Duration: {answer}')
                        answer = ''

                if answer == 'login':
                    show_duration = True
                    mfa_expiration = proto.TWO_FA_EXP_IMMEDIATELY
                elif answer == '12_hours':
                    show_duration = True
                    mfa_expiration = proto.TWO_FA_EXP_12_HOURS
                elif answer == '24_hours':
                    show_duration = True
                    mfa_expiration = proto.TWO_FA_EXP_24_HOURS
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

        if not params.device_token:
            private, public = crypto.generate_ec_key()

            rq = proto.DeviceRegistrationRequest()
            rq.clientVersion = rest_api.CLIENT_VERSION
            rq.deviceName = CommonHelperMethods.get_device_name()
            rq.devicePublicKey = crypto.unload_ec_public_key(public)

            api_request_payload = proto.ApiRequestPayload()
            api_request_payload.payload = rq.SerializeToString()

            rs = rest_api.execute_rest(params.rest_context, 'authentication/register_device', api_request_payload)

            if type(rs) == bytes:
                register_device_rs = proto.Device()
                register_device_rs.ParseFromString(rs)

                # A globally unique device id for each device encrypted by the device token key
                params.device_token = utils.base64_url_encode(register_device_rs.encryptedDeviceToken)
                params.device_private_key = utils.base64_url_encode(crypto.unload_ec_private_key(private))
                loader.store_config_properties(params)
            else:
                raise KeeperApiError(rs['error'], rs['message'])

        return utils.base64_url_decode(params.device_token)

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

                err_msg = rs['message']
                if rs['error'] == 'device_not_registered':
                    err_msg += "\nRegister this user in the current region or change server region"

                add_info = rs.get('additional_info')
                if add_info:
                    err_msg += "\n" + rs['additional_info']

                raise KeeperApiError(rs['error'], err_msg)

    @staticmethod
    def handle_account_recovery(params, encrypted_login_token_bytes):
        logging.info('')
        logging.info('Password Recovery')
        rq = proto.MasterPasswordRecoveryVerificationRequest()
        rq.encryptedLoginToken = encrypted_login_token_bytes
        try:
            api.communicate_rest(params, rq, 'authentication/master_password_recovery_verification_v2')
        except KeeperApiError as kae:
            if kae.result_code != 'bad_request' and not kae.message.startswith('Email has been sent.'):
                raise kae

        logging.info('Please check your email and enter the verification code below:')
        verification_code = input('Verification Code: ')
        if not verification_code:
            return

        rq = proto.GetSecurityQuestionV3Request()
        rq.encryptedLoginToken = encrypted_login_token_bytes
        rq.verificationCode = verification_code
        rs = api.communicate_rest(params, rq, 'authentication/account_recovery_verify_code',
                                  rs_type=proto.AccountRecoveryVerifyCodeResponse)

        backup_type = rs.backupKeyType

        if backup_type == proto.BKT_SEC_ANSWER:
            print(f'Security Question: {rs.securityQuestion}')
            answer = getpass.getpass(prompt='Answer: ', stream=None)
            if not answer:
                return
            recovery_phrase = answer.lower()
            auth_hash = crypto.derive_keyhash_v1(recovery_phrase, rs.salt, rs.iterations)
        elif backup_type == proto.BKT_PASSPHRASE_HASH:
            p = PassphrasePrompt()
            print('Please enter your Recovery Phrase ')
            if os.isatty(0):
                phrase = prompt('Recovery Phrase: ', lexer=p, completer=p, key_bindings=p.kb, validator=p,
                                validate_while_typing=False, editing_mode=EditingMode.VI, wrap_lines=True,
                                complete_style=CompleteStyle.MULTI_COLUMN, complete_while_typing=True,
                                bottom_toolbar=p.get_word_count_text)
            else:
                phrase = input('Recovery Phrase: ')
            if not phrase:
                return
            words = [x.strip() for x in phrase.lower().split(' ') if x]
            if len(words) != 24:
                raise Exception('Recovery phrase should contain 24 words')
            recovery_phrase = ' '.join(words)
            auth_hash = crypto.generate_hkdf_key('recovery_auth_token', recovery_phrase)
        else:
            logging.info('Unsupported account recovery type')
            return

        rq = proto.GetDataKeyBackupV3Request()
        rq.encryptedLoginToken = encrypted_login_token_bytes
        rq.verificationCode = verification_code
        rq.securityAnswerHash = auth_hash
        rs = api.communicate_rest(params, rq, 'authentication/get_data_key_backup_v3', rs_type=proto.GetDataKeyBackupV3Response)
        if backup_type == proto.BKT_SEC_ANSWER:
            params.data_key = utils.decrypt_encryption_params(rs.dataKeyBackup, recovery_phrase)
        else:
            encryption_key = crypto.generate_hkdf_key('recovery_key_aes_gcm_256', recovery_phrase)
            params.data_key = crypto.decrypt_aes_v2(rs.dataKeyBackup, encryption_key)
        params.session_token = utils.base64_url_encode(rs.encryptedSessionToken)

        success = LoginV3Flow.change_master_password(params, list(rs.passwordRules), rs.minimumPbkdf2Iterations)
        if success:
            LoginV3Flow.login(params)

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
    def change_master_password(params, password, iterations=0):  # type: (KeeperParams, str, int) -> None
        iterations = max(iterations, params.iterations, constants.PBKDF2_ITERATIONS)
        auth_salt = os.urandom(16)
        auth_verifier = utils.create_auth_verifier(password, auth_salt, iterations)
        data_salt = os.urandom(16)
        encryption_params = utils.create_encryption_params(password, data_salt, iterations, params.data_key)
        rq = {
            'command': 'change_master_password',
            'auth_verifier': utils.base64_url_encode(auth_verifier),
            'encryption_params': utils.base64_url_encode(encryption_params),
        }
        api.communicate(params, rq)
        params.password = password
        params.salt = auth_salt
        params.iterations = iterations

    @staticmethod
    def register_encrypted_data_key_for_device(params: KeeperParams):
        device_key = crypto.load_ec_private_key(utils.base64_url_decode(params.device_private_key))
        rq = proto.RegisterDeviceDataKeyRequest()
        rq.encryptedDeviceToken = utils.base64_url_decode(params.device_token)
        rq.encryptedDeviceDataKey = crypto.encrypt_ec(params.data_key, device_key.public_key())
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
        device_key = crypto.load_ec_private_key(utils.base64_url_decode(params.device_private_key))
        rq.devicePublicKey = crypto.unload_ec_public_key(device_key.public_key())
        api_request_payload = proto.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()
        rs = rest_api.execute_rest(params.rest_context, 'authentication/register_device_in_region', api_request_payload)
        if isinstance(rs, dict):
            # KA has a bug where it returns 'exists' for non-existing device token
            # if 'error' in rs and rs['error'] == 'exists':
            #     return
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
    def fill_password_with_prompt_if_missing(params: KeeperParams, ask_for_recovery=False) -> bool:
        while not params.user:
            params.user = getpass.getpass(prompt='User(Email): ', stream=None)

        if not params.password:
            logging.info('')
            if ask_for_recovery:
                logging.info('Forgot password? Type "recover"<Enter>')
            logging.info('Enter password for {0}'.format(params.user))
            try:
                password = getpass.getpass(prompt='Password: ', stream=None)
                if password == 'recover':
                    raise NeedAccountRecovery()
                params.password = password
                return True
            except KeyboardInterrupt:
                print('')
            except EOFError:
                print('')
        return False


class PassphrasePrompt(AutoSuggest, Completer, Lexer, Validator):
    def __init__(self):
        gen = generator.CryptoPassphraseGenerator()
        self.words = list(gen.get_vocabulary())
        self.words.sort()
        self.word_count = 0
        self.kb = KeyBindings()
        decorator = self.kb.add('enter', filter=completion_is_selected)
        decorator(PassphrasePrompt.hide_completion_on_enter)

    @staticmethod
    def hide_completion_on_enter(event):
        event.current_buffer.complete_state = None
        b = event.app.current_buffer
        b.complete_state = None

    def get_word_count_text(self):
        left = 24 - self.word_count
        if left > 0:
            return FormattedText([('', f'{left} left')])
        elif left == 0:
            return FormattedText([('ansigreen', 'OK')])
        else:
            return FormattedText([('ansired', 'Extra')])

    def get_word_index(self, word):   # type: (str) -> int
        idx = bisect.bisect_left(self.words, word)
        if 0 <= idx < len(self.words) and self.words[idx] == word:
            return idx
        return -1

    def lex_document(self, document):
        lines = document.lines

        def highlight(lineno):
            line = lines[lineno]
            tokens = []
            pos = 0
            word_count = 0
            while pos < len(line):
                if line[pos].isspace():
                    tokens.append(('', line[pos]))
                    pos += 1
                else:
                    pos_space = line.find(' ', pos)
                    if pos_space < 0:
                        rest = line[pos:]
                        if rest:
                            word_count += 1
                        tokens.append(('', rest))
                        break
                    else:
                        word = line[pos:pos_space]
                        idx = self.get_word_index(word)
                        is_valid = 0 <= idx < len(self.words)
                        tokens.append(('ansigreen' if is_valid else 'ansired bold', word))
                        word_count += 1
                    pos = pos_space
            self.word_count = word_count
            return tokens
        return highlight

    def get_suggestion(self, buffer, document):
        if not document.is_cursor_at_the_end:
            return
        text = document.text
        if not text:
            return
        if text[-1].isspace():
            return
        idx = text.rfind(' ')
        if idx == -1:
            word = text
        else:
            word = text[idx+1:]
        if len(word) <= 2:
            return
        idx = bisect.bisect_left(self.words, word)
        if idx < len(self.words):
            if self.words[idx].startswith(word):
                if idx < len(self.words) - 1:
                    if self.words[idx+1].startswith(word):
                        return
                return Suggestion(self.words[idx][len(word):] + ' ')

    def get_completions(self, document, complete_event):
        if not document.is_cursor_at_the_end:
            return

        text = document.text
        if not text:
            return
        if text[-1].isspace():
            return
        idx = text.rfind(' ')
        if idx == -1:
            word = text
        else:
            word = text[idx+1:]
        if len(word) < 2:
            return

        idx = bisect.bisect_left(self.words, word)
        while idx < len(self.words) and self.words[idx].startswith(word):
            yield Completion(self.words[idx], display=self.words[idx] + ' ', start_position=-len(word))
            idx += 1

    def validate(self, document):
        if self.word_count != 24:
            error = f'Expected 24 passphrase words. Got {self.word_count}. Press Ctrl-C to cancel current input.'
            raise ValidationError(cursor_position=document.cursor_position, message=error)


class NeedAccountRecovery(Exception):
    pass


class InvalidDeviceToken(Exception):
    pass
