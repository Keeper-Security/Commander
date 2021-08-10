import base64
import getpass
import io
import json
import logging
import os
import re
import sys
from urllib.parse import urlparse, urlunparse
from collections import OrderedDict
from email.utils import parseaddr
from sys import platform as _platform

import requests
from Cryptodome.Math.Numbers import Integer
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.asn1 import DerSequence
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.protobuf.json_format import MessageToDict, MessageToJson

from .commands import enterprise as enterprise_command
from .plugins import humps as humps

from . import api, __version__, cli
from . import rest_api, APIRequest_pb2 as proto, AccountSummary_pb2 as proto_as
from .display import bcolors
from .error import KeeperApiError, CommandError
from .params import KeeperParams

warned_on_fido_package = False

permissions_error_msg = "Grant Commander SDK permissions to access Keeper by navigating to Admin Console -> Admin -> " \
                        "Roles -> [Select User's Role] -> Enforcement Policies -> Platform Restrictions -> Click on " \
                        "'Enable' check box next to Commander SDK.\nAlso note that if user has more than two roles " \
                        "assigned then the most restrictive policy from all the roles will be applied."


class LoginV3Flow:

    @staticmethod
    def login(params: KeeperParams):

        logging.debug("Login v3 Start as '%s'" % params.user)

        CommonHelperMethods.startup_check(params)

        encryptedDeviceToken = LoginV3API.get_device_id(params)

        clone_code_bytes = CommonHelperMethods.config_file_get_property_as_bytes(params, 'clone_code')

        resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken, cloneCode=clone_code_bytes)

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

                cli.prompt_for_username_if_needed(params)
                encryptedLoginToken = resp.encryptedLoginToken
                if encryptedLoginToken:
                    # Successfully completed 2FA. Re-login
                    resp = LoginV3API.resume_login(params, encryptedLoginToken, encryptedDeviceToken, clone_code_bytes)

                # raise Exception('Username is required.')

            elif resp.loginState == proto.REDIRECT_ONSITE_SSO \
                    or resp.loginState == proto.REDIRECT_CLOUD_SSO:
                logging.info(bcolors.BOLD + bcolors.OKGREEN + "\nSSO login not supported, will attempt to authenticate with your master password." + bcolors.ENDC + bcolors.ENDC)
                logging.info(bcolors.OKBLUE + "(Note: If you have not set a master password, set one in your Vault via Settings -> Master Password)\n" + bcolors.ENDC)

                is_alternate_login = True

                resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken, loginType='ALTERNATE')

            elif resp.loginState == proto.REQUIRES_DEVICE_ENCRYPTED_DATA_KEY:
                # TODO: Restart login
                raise Exception('Device encrypted data key is not supported by Commander %s at this time.' % rest_api.CLIENT_VERSION)

            elif resp.loginState == proto.REQUIRES_ACCOUNT_CREATION:
                # if isSSOAccount:
                #     return createNewSso
                raise Exception('This account need to be created.' % rest_api.CLIENT_VERSION)

            elif resp.loginState == proto.REGION_REDIRECT:
                p = urlparse(params.server)
                new_server = urlunparse((p.scheme, resp.stateSpecificValue, '', None, None, None))

                warn_msg = \
                    "\n'%s' has indicated that this account was originally created in a different region." \
                    "\nPlease update config to use server: %s"\
                    "\nYou may also need to register this device in the other region, unsetting the the device_token and clone_code will do this automatically upon login."\
                    % (p.netloc.upper(), new_server)

                logging.warning(warn_msg)

                raise Exception("Changes to configuration are required.")

                # TODO: change configuration structure so that device_token is paired with server, so that a given device_token is more certain to work for a given server, and will not be forced to be unset to "find out"
                # params.rest_context.server_base = new_server
                # params.server = params.rest_context.server_base
                #
                # LoginV3API.register_device_in_region(params)
                #
                # resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken)



            elif resp.loginState == proto.REQUIRES_AUTH_HASH:

                CommonHelperMethods.fill_password_with_prompt_if_missing(params)

                salt = api.get_correct_salt(resp.salt)

                salt_bytes = salt.salt
                salt_iterations = salt.iterations

                params.salt = salt_bytes
                params.iterations = salt_iterations
                params.auth_verifier = LoginV3API.auth_verifier_loginv3(params)

                resp = LoginV3API.validateAuthHashMessage(params, resp.encryptedLoginToken)
                # login_state = proto.LoginState.Name(resp.loginState)

                params.user = resp.primaryUsername
                params.account_uid_bytes = resp.accountUid
                params.session_token_bytes = resp.encryptedSessionToken
                params.session_token_restriction = resp.sessionTokenType  # getSessionTokenScope(login_resp.sessionTokenType)
                params.clone_code = resp.cloneCode
                # params.device_token_bytes = encryptedDeviceToken
                # auth_context.message_session_uid = login_resp.messageSessionUid

                if not params.device_private_key:
                    params.device_private_key = CommonHelperMethods.get_private_key_ecc(params)

                if resp.encryptedDataKeyType == proto.EncryptedDataKeyType.Value("BY_DEVICE_PUBLIC_KEY"):
                    params.data_key = resp.encryptedDataKey
                    # raise Exception("Encrypted device public key is not supported by Commander")

                elif resp.encryptedDataKeyType == proto.EncryptedDataKeyType.Value("BY_PASSWORD"):
                    params.data_key = api.decrypt_encryption_params(
                        CommonHelperMethods.bytes_to_url_safe_str(resp.encryptedDataKey),
                        params.password)

                elif resp.encryptedDataKeyType == proto.EncryptedDataKeyType.Value("BY_ALTERNATE"):
                    params.data_key = api.decrypt_data_key(params, resp.encryptedDataKey)
                    # raise Exception("Alternate data key encryption is not supported by Commander")
                elif resp.encryptedDataKeyType == proto.EncryptedDataKeyType.Value("BY_BIO"):
                    raise Exception("Biometrics encryption is not supported by Commander")
                elif resp.encryptedDataKeyType == proto.EncryptedDataKeyType.Value("NO_KEY"):
                    raise Exception("No key encryption is not supported by Commander")
                else:
                    raise Exception("Unhandled encryption data key ''" % resp.encryptedDataKeyType)

                CommonHelperMethods.persist_state_data(params)

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

                session_token = CommonHelperMethods.bytes_to_url_safe_str(resp.encryptedSessionToken)
                params.session_token = session_token

                if resp.encryptedDataKeyType == proto.BY_DEVICE_PUBLIC_KEY:
                    decrypted_data_key = CommonHelperMethods.decrypt_ec(params, resp.encryptedDataKey)
                    params.data_key = decrypted_data_key
                    login_type_message = bcolors.UNDERLINE + "Persistent Login"

                elif resp.encryptedDataKeyType == proto.BY_PASSWORD:

                    params.data_key = api.decrypt_encryption_params(
                        CommonHelperMethods.bytes_to_url_safe_str(resp.encryptedDataKey),
                        params.password)

                    login_type_message = bcolors.UNDERLINE + "Password"

                elif resp.encryptedDataKeyType == proto.BY_ALTERNATE:
                    params.data_key = api.decrypt_data_key(params, resp.encryptedDataKey)

                    login_type_message = bcolors.UNDERLINE + "Alternate Master Password"

                elif resp.encryptedDataKeyType == proto.NO_KEY \
                        or resp.encryptedDataKeyType == proto.BY_BIO:
                    raise Exception("Data Key type %s decryption not implemented" % resp.encryptedDataKeyType)

                params.clone_code = resp.cloneCode
                CommonHelperMethods.persist_state_data(params)

                LoginV3Flow.populateAccountSummary(params)

                logging.info(bcolors.OKGREEN + "Successfully authenticated with Login V3 (" + login_type_message + ")" + bcolors.ENDC)

                return
            else:
                raise Exception("UNKNOWN LOGIN STATE [%s]" % resp.loginState)

    @staticmethod
    def populateAccountSummary(params: KeeperParams):

        acct_summary = LoginV3API.accountSummary(params)

        # Loading summary as dictionary for backwards compatibility
        acct_summary_json = MessageToJson(acct_summary, preserving_proto_field_name=False)
        acct_summary_dict = json.loads(acct_summary_json)
        acct_summary_dict_snake_case = humps.humps.decamelize(acct_summary_dict)

        if 'keys_info' in acct_summary_dict_snake_case:
            keys = acct_summary_dict_snake_case['keys_info']

            # if 'encrypted_data_key' in keys:
            #     encrypted_data_key = base64.urlsafe_b64decode(keys['encrypted_data_key'])
            #     key = rest_api.derive_key_v2('data_key', params.password, params.salt, params.iterations)
            #     params.data_key = rest_api.decrypt_aes(encrypted_data_key, key)
            # elif 'encryption_params' in keys:
            #     params.data_key = api.decrypt_encryption_params(keys['encryption_params'], params.password)

            params.rsa_key = api.decrypt_rsa_key(keys['encrypted_private_key'], params.data_key)

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

        if 'is_enterprise_admin' in acct_summary_dict_snake_case \
                and acct_summary_dict_snake_case['is_enterprise_admin']:
            api.query_enterprise(params)
            api.query_msp(params)

        params.sync_data = True
        params.prepare_commands = True

        store_config = not params.config or params.config.get('user') != params.user

        if store_config:
            params.config['user'] = params.user

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
                proto.TWO_FA_PUSH_KEEPER)

            if type(rs) == bytes:
                logging.info('Successfully made a push notification to the approved device.\nPress <Enter> when approved.')
            else:
                raise KeeperApiError(rs['error'], rs['message'])

        elif selection == "":
            return True

    @staticmethod
    def handleTwoFactor(params: KeeperParams, encryptedLoginToken, login_resp):

        global u2f_response
        global warned_on_fido_package

        print("This account requires 2FA Authentication")
        login_resp_dict = MessageToDict(login_resp, preserving_proto_field_name=True)

        channel_types = OrderedDict([
            ('TWO_FA_CT_U2F', 'U2F (FIDO Security Key)'),
            ('TWO_FA_CT_SMS', 'Send SMS Code'),
            ('TWO_FA_CT_TOTP', 'TOTP (Google Authenticator)'),
            ('TWO_FA_CT_DUO', 'DUO'),
            # ('TWO_FA_CODE_RSA', 'RSA Authenticator'),
        ])

        try:
            assert 'channels' in login_resp_dict
        except AssertionError:
            raise Exception("No channels provided by API")
        else:

            available_channels = dict([(channel['channelType'], channel) for channel in login_resp_dict['channels']])

            for n, (channel_type, channel_desc) in enumerate(channel_types.items()):
                if channel_type in available_channels:
                    print(f"{n+1:>3}. {channel_desc} {bcolors.OKGREEN}[ ENABLED ]{bcolors.ENDC}")
                else:
                    print(f"     {channel_desc}")

            try:
                selection: str = input('Selection: ')
                idx = 1 if not selection else int(selection)
                assert 1 <= idx <= len(channel_types)
                channel_type = list(channel_types.keys())[idx - 1]
                channel = available_channels.get(channel_type)
                logging.debug(f"Selected {idx}. {channel_type}")
                assert channel is not None
            except AssertionError:
                print("Invalid entry, additional factors of authentication shown may be configured if not currently enabled.")
                return
            except (KeyboardInterrupt, EOFError):
                exit(1)

        mfa_prompt = False

        if channel_type == 'TWO_FA_CODE_NONE':
            pass

        elif channel_type == "TWO_FA_CT_SMS":
            rs = LoginV3API.twoFactorSend2FAPushMessage(
                params,
                encryptedLoginToken,
                proto.TWO_FA_PUSH_NONE,
                expireIn=proto.TWO_FA_EXP_IMMEDIATELY
            )

            if type(rs) == bytes:
                logging.info(bcolors.OKGREEN + "\nSuccessfully sent SMS.\n" + bcolors.ENDC)
                mfa_prompt = True
            else:
                logging.error("Was unable to send SMS.")
                raise KeeperApiError(rs['error'], rs['message'])

        elif channel_type == 'TWO_FA_CODE_RSA':
            logging.debug("DO RSA")
            raise NotImplementedError("RSA Authentication not yet available in Commander.")

        elif channel_type == "TWO_FA_CT_U2F":
            try:
                from .yubikey import u2f_authenticate
                challenge = json.loads(channel['challenge'])
                u2f_request = challenge['authenticateRequests']
                u2f_response = u2f_authenticate(u2f_request)

                if u2f_response:
                    signature = json.dumps(u2f_response)

                    rs = LoginV3API.twoFactorValidateMessage(params, encryptedLoginToken, signature, proto.TWO_FA_EXP_IMMEDIATELY, proto.TWO_FA_RESP_U2F)

                    if type(rs) == bytes:

                        print(bcolors.OKGREEN + "Verified 2FA Code." + bcolors.ENDC)

                        two_fa_validation_rs = proto.TwoFactorValidateResponse()
                        two_fa_validation_rs.ParseFromString(rs)

                        return two_fa_validation_rs.encryptedLoginToken
                    else:
                        print(bcolors.FAIL + "Unable to verify code generated by security key" + bcolors.ENDC)

            except ImportError as e:
                logging.error(e)
                if not warned_on_fido_package:
                    logging.warning(api.install_fido_package_warning)
                    warned_on_fido_package = True
            except Exception as e:
                logging.error(e)

        # elif channel_type == 'TWO_FA_RESP_WEBAUTHN':
        # elif channel_type == 'TWO_FA_CT_KEEPER':
        # elif channel_type == 'TWO_FA_CODE_TOTP':
        # elif channel_type == 'TWO_FA_CODE_DUO':
        # elif channel_type == 'TWO_FA_CODE_DNA':
        # elif channel_type == 'EMAIL_CODE':
        elif channel_type in ['TWO_FA_CT_TOTP', 'TWO_FA_CT_DUO']:
            mfa_prompt = True
        else:
            raise NotImplementedError("Unhandled channel type %s" % channel_type)

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
                mfa_expiration
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
    def get_device_id(params: KeeperParams):

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

        encrypted_device_token_bytes = CommonHelperMethods.url_safe_str_to_bytes(encrypted_device_token_str)

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
    def resume_login(params: KeeperParams, encryptedLoginToken, encryptedDeviceToken, cloneCode = None, loginType = 'NORMAL'):
        rq = proto.StartLoginRequest()
        rq.clientVersion = rest_api.CLIENT_VERSION
        rq.encryptedLoginToken = encryptedLoginToken
        rq.encryptedDeviceToken = encryptedDeviceToken
        rq.username = params.user.lower()
        rq.loginType = proto.LoginType.Value(loginType)
        if cloneCode:
            rq.loginMethod = proto.LoginMethod.Value('EXISTING_ACCOUNT')
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
                    params.device_id = None
                    params.server_base = 'https://{0}/'.format(rs['region_host'])
                    # logging.warning('Switching to region: %s', rs['region_host'])
                    # continue
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
    def startLoginMessage(params: KeeperParams, encryptedDeviceToken, cloneCode = None, loginType: str = 'NORMAL'):

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
                    params.device_id = None
                    params.server_base = 'https://{0}/'.format(rs['region_host'])
                    # logging.warning('Switching to region: %s', rs['region_host'])
                    # continue
                if rs['error'] == 'bad_request':
                    # logging.warning('Pre-Auth error: %s', rs.get('additional_info'))
                    params.device_id = None
                    # continue

                if 'additional_info' in rs:
                    err_msg = "\n" + rs['additional_info']

                    if rs['error'] == 'device_not_registered':
                        err_msg += "\nRegister this user in the current region or change server region"

                    raise KeeperApiError(rs['error'], err_msg)
                else:
                    raise KeeperApiError(rs['error'], rs['message'])

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
            raise KeeperApiError(rs['error'], "Account validation error.\n" + rs['message'])

    @staticmethod
    def twoFactorValidateMessage(params: KeeperParams, encryptedLoginToken: bytes, otp_code: str, tfa_expire_in, twoFactorValueType=None):

        rq = proto.TwoFactorValidateRequest()
        rq.encryptedLoginToken = encryptedLoginToken
        rq.value = otp_code

        if twoFactorValueType:
            rq.valueType = twoFactorValueType

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
        # rq.channel_uid = channel_uid

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
    def register_encrypted_data_key_for_device(params: KeeperParams):
        rq = proto.RegisterDeviceDataKeyRequest()

        rq.encryptedDeviceToken = LoginV3API.get_device_id(params)
        rq.encryptedDeviceDataKey = CommonHelperMethods.get_encrypted_device_data_key(params)

        try:
            rs = api.communicate_rest(params, rq, 'authentication/register_encrypted_data_key_for_device')
        except Exception as e:
            if e.result_code == 'device_data_key_exists':
                return False
            raise e

        return True

    @staticmethod
    def register_device_in_region(params: KeeperParams):
        rq = proto.RegisterDeviceInRegionRequest()
        rq.encryptedDeviceToken = CommonHelperMethods.url_safe_str_to_bytes(params.device_token)
        rq.clientVersion = rest_api.CLIENT_VERSION
        rq.deviceName = CommonHelperMethods.get_device_name()
        rq.devicePublicKey = CommonHelperMethods.public_key_ecc(params)

        # TODO: refactor into util for handling Standard Rest Authentication Errors
        # try:
        rs = api.communicate_rest(params, rq, 'authentication/register_device_in_region')
        # except Exception as e:
        #     # device_disabled - this device has been disabled for all users / all commands
        #     # user_device_disabled - this user has disabled access from this device
        #     # redirect - depending on the command, if the user is a pending enterprise user, or and existing user and they are in a different region, they will be redirected to the proper keeperapp server to submit the request
        #     # client_version - Invalid client version
        #     logging.error(f"Unable to register device in {params.region}: {e}")
        #     return False
        # else:
        #     return True

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

        rs = api.communicate_rest(params, rq, 'login/account_summary')

        acct_summary_rs = proto_as.AccountSummaryElements()
        acct_summary_rs.ParseFromString(rs)

        return acct_summary_rs

    @staticmethod
    def loginToMc(rest_context, session_token, mc_id):

        endpoint = 'authentication/login_to_mc'

        rq = proto.LoginToMcRequest()
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

            login_to_mc_rs = proto.LoginToMcResponse()
            login_to_mc_rs.ParseFromString(rs)

            return login_to_mc_rs
        elif type(rs) == dict:
            raise KeeperApiError(rs['error'], rs['message'])
        raise KeeperApiError('Error', endpoint)

    @staticmethod
    def create_user(params: KeeperParams, new_username: str):

        endpoint = 'authentication/request_create_user'

        auth_verifier = api.create_auth_verifier(params.password, params.salt, params.iterations)
        encryption_params = api.create_encryption_params(params.password, params.salt, params.iterations, params.data_key)
        encrypted_device_token_str = params.config['device_token']

        rsa_public_key_bytes, rsa_private_key = CommonHelperMethods.generate_rsa_key_pair()

        rsa_encrypted_private_key = api.encrypt_aes(rsa_private_key, params.data_key)

        # Generating private and public keys
        ephemeral_key = CommonHelperMethods.generate_new_ecc_key()
        private_value: int = ephemeral_key.private_numbers().private_value

        ecc_private_key_bytes = int.to_bytes(private_value, length=32, byteorder='big', signed=False)
        ecc_private_key_encrypted_bytes = rest_api.encrypt_aes(ecc_private_key_bytes, params.data_key)
        ecc_public_key_bytes = ephemeral_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

        encrypted_client_key = api.encrypt_aes(os.urandom(32), params.data_key)

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
        except Exception as e:
            logging.warning(e)
            return

        create_user_rq = proto.CreateUserRequest()
        create_user_rq.username = new_username
        create_user_rq.authVerifier = CommonHelperMethods.url_safe_str_to_bytes(auth_verifier)
        create_user_rq.encryptionParams = CommonHelperMethods.url_safe_str_to_bytes(encryption_params)
        create_user_rq.rsaPublicKey = rsa_public_key_bytes
        create_user_rq.rsaEncryptedPrivateKey = CommonHelperMethods.url_safe_str_to_bytes(rsa_encrypted_private_key)
        create_user_rq.eccPublicKey = ecc_public_key_bytes                                                              # 65 bytes, on curve
        create_user_rq.eccEncryptedPrivateKey = ecc_private_key_encrypted_bytes                                         # 60 bytes
        create_user_rq.encryptedDeviceToken = CommonHelperMethods.url_safe_str_to_bytes(encrypted_device_token_str)     # 65 bytes
        create_user_rq.encryptedClientKey = CommonHelperMethods.url_safe_str_to_bytes(encrypted_client_key)             # 64 bytes
        create_user_rq.clientVersion = rest_api.CLIENT_VERSION
        create_user_rq.encryptedDeviceDataKey = eph_public_key + encrypted_data_key

        try:
            api_request_payload = proto.ApiRequestPayload()
            api_request_payload.payload = create_user_rq.SerializeToString()

            rs = rest_api.execute_rest(params.rest_context, endpoint, api_request_payload)
        except Exception as e:
            raise KeeperApiError('Rest API', str(e))

        if type(rs) == bytes:
            return True
        elif type(rs) == dict:
            raise KeeperApiError(rs['error'], rs['message'])
        raise KeeperApiError('Error', endpoint)

    @staticmethod
    def register_for_login_v3(params, kwargs):
        email = kwargs['email'] if 'email' in kwargs else None

        if email:
            _, email = parseaddr(email)
        if not email:
            raise CommandError('register', 'A valid email address is expected.')

        node = kwargs.get('node')

        displayname = kwargs.get('name')

        if not displayname:
            raise CommandError('register', '\'name\' parameter is required for enterprise users')

        # Provision user to the logged-in admin's enterprise
        provisioned = LoginV3API().provision_user_in_enterprise(params, email, node, displayname)

        if provisioned:
            logging.info("User '%s' create and added to the enterprise" % email)

            # Refresh (sync-down) enterprise data only
            api.query_enterprise(params)

        # Create user (will send email to the user)
        # loginv3.LoginV3API().create_user(params, email)

    @staticmethod
    def provision_user_in_enterprise(params: KeeperParams,
                                     email,
                                     node,
                                     displayname):

        if params.enterprise:
            node_id = None
            if node:
                for enode in params.enterprise['nodes']:
                    if node in {str(enode['node_id']), enode['data'].get('displayname')}:
                        node_id = enode['node_id']
                        break
                    elif not enode.get('parent_id') and node == params.enterprise['enterprise_name']:
                        node_id = enode['node_id']
                        break
            if node_id is None:
                for enode in params.enterprise['nodes']:
                    if not enode.get('parent_id'):
                        node_id = enode['node_id']
                        break
            data = {'displayname': displayname}

            rq = {
                'command': 'enterprise_user_add',
                'enterprise_user_id': enterprise_command.EnterpriseCommand.get_enterprise_id(params),
                'enterprise_user_username': email,
                'encrypted_data': api.encrypt_aes(json.dumps(data).encode('utf-8'),
                                                  params.enterprise['unencrypted_tree_key']),
                'node_id': node_id,
                'suppress_email_invite': False
            }

            try:
                rs = api.communicate(params, rq)

                return True
            except Exception as e:
                logging.warning(e.message)
                return False

        return False


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

        if os.path.exists(params.config_filename):
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
            logging.info('Enter password for {0}'.format(params.user))
            try:
                params.password = getpass.getpass(prompt='Password: ', stream=None)
            except KeyboardInterrupt:
                print('')
            except EOFError:
                return 0
