import base64
import bisect
import getpass
import json
import logging
import os
import re
from collections import namedtuple
from sys import platform as _platform
from typing import Optional, List, Any
from urllib.parse import urlparse, urlencode, urlunparse, parse_qsl

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from google.protobuf.json_format import MessageToJson
from prompt_toolkit.auto_suggest import AutoSuggest, Suggestion
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.enums import EditingMode
from prompt_toolkit.filters import completion_is_selected
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.lexers.base import Lexer
from prompt_toolkit.shortcuts import CompleteStyle
from prompt_toolkit.shortcuts import prompt
from prompt_toolkit.validation import Validator, ValidationError

from . import api, rest_api, utils, crypto, constants, generator
from .auth import login_steps, console_ui
from .breachwatch import BreachWatch
from .config_storage import loader
from .display import bcolors
from .error import KeeperApiError
from .humps import decamelize
from .params import KeeperParams
from .proto import APIRequest_pb2, AccountSummary_pb2, breachwatch_pb2, ssocloud_pb2, enterprise_pb2

permissions_error_msg = "Grant Commander SDK permissions to access Keeper by navigating to Admin Console -> Admin -> " \
                        "Roles -> [Select User's Role] -> Enforcement Policies -> Platform Restrictions -> Click on " \
                        "'Enable' check box next to Commander SDK.\nAlso note that if user has more than two roles " \
                        "assigned then the most restrictive policy from all the roles will be applied."


class LoginV3Flow:
    def __init__(self, login_ui=None):   # type: (login_steps.LoginUi) -> None
        self.login_ui = login_ui or console_ui.ConsoleLoginUi()    # type: login_steps.LoginUi

    def login(self, params, new_device=False, new_login=False):   # type: (KeeperParams, bool, bool) -> None

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
            is_cloud = resp.loginState == APIRequest_pb2.REQUIRES_DEVICE_ENCRYPTED_DATA_KEY

            if resp.loginState == APIRequest_pb2.DEVICE_APPROVAL_REQUIRED:  # client goes to “standard device approval”.
                should_cancel = False
                should_resume = False

                class DeviceApproval(login_steps.LoginStepDeviceApproval):
                    @property
                    def username(self):
                        return params.user

                    def cancel(self):
                        nonlocal should_cancel
                        should_cancel = True

                    def send_push(self, channel):
                        nonlocal should_resume
                        should_resume = LoginV3Flow.verifyDevice(
                            params, encryptedDeviceToken, resp.encryptedLoginToken, approval_action='push', approval_channel=channel)

                    def send_code(self, channel, code):
                        nonlocal should_resume
                        should_resume = LoginV3Flow.verifyDevice(
                            params, encryptedDeviceToken, resp.encryptedLoginToken, approval_action='code', approval_channel=channel, approval_code=code)

                    def resume(self):
                        nonlocal should_resume
                        should_resume = True

                self.login_ui.on_device_approval(DeviceApproval())
                if should_cancel:
                    break
                if should_resume:
                    resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken)

            elif resp.loginState == APIRequest_pb2.REQUIRES_2FA:
                supported_channels = {APIRequest_pb2.TWO_FA_CODE_TOTP, APIRequest_pb2.TWO_FA_CT_SMS,
                                      APIRequest_pb2.TWO_FA_CT_DUO, APIRequest_pb2.TWO_FA_CT_RSA,
                                      APIRequest_pb2.TWO_FA_CT_U2F, APIRequest_pb2.TWO_FA_CT_WEBAUTHN,
                                      APIRequest_pb2.TWO_FA_CT_DNA, APIRequest_pb2.TWO_FA_CT_BACKUP}
                channels = [_tfa_channel_info_keeper_to_sdk(x) for x in resp.channels if x.channelType in supported_channels]
                channels = [x for x in channels if x.channel_type != login_steps.TwoFactorChannel.Other]
                if len(channels) == 0:
                    backup_code_channel = APIRequest_pb2.TwoFactorChannelInfo()
                    backup_code_channel.channelType = APIRequest_pb2.TWO_FA_CT_BACKUP
                    channels.append(backup_code_channel)

                encrypted_login_token = None   # type: Optional[bytes]
                should_cancel = False

                class TwoFactorApproval(login_steps.LoginStepTwoFactor):
                    def get_channels(self):
                        return channels

                    def get_channel_push_actions(self, channel_uid):
                        pass

                    def send_push(self, channel_uid, action):
                        LoginV3API.twoFactorSend2FAPushMessage(
                            params, encryptedLoginToken, pushType=tfa_action_sdk_to_keeper(action),
                            channel_uid=channel_uid, expireIn=APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY)

                    def send_code(self, channel_uid: bytes, code: str) -> None:
                        nonlocal encrypted_login_token
                        channel = next((x for x in channels if x.channel_uid == channel_uid), None)
                        if channel:
                            encrypted_login_token = LoginV3API.twoFactorValidateMessage(
                                params, resp.encryptedLoginToken, code, tfa_expire_in=_duration_sdk_to_keeper(self.duration),
                                channel_uid=channel_uid, twoFactorValueType=_channel_keeper_value(channel.channel_type))

                    def resume(self) -> None:
                        nonlocal encrypted_login_token
                        encrypted_login_token = resp.encryptedLoginToken

                    def cancel(self):
                        nonlocal should_cancel
                        should_cancel = True

                self.login_ui.on_two_factor(TwoFactorApproval())
                if should_cancel:
                    break

                if encrypted_login_token:
                    # Successfully completed 2FA. Re-login
                    login_type = 'ALTERNATE' if is_alternate_login else 'NORMAL'
                    resp = LoginV3API.resume_login(params, encrypted_login_token, encryptedDeviceToken, loginType=login_type)

            elif resp.loginState == APIRequest_pb2.REQUIRES_USERNAME:
                if not params.user:
                    raise Exception('Username is required.')
                resp = LoginV3API.resume_login(params, resp.encryptedLoginToken, encryptedDeviceToken, clone_code_bytes)

            elif resp.loginState == APIRequest_pb2.REDIRECT_ONSITE_SSO or resp.loginState == APIRequest_pb2.REDIRECT_CLOUD_SSO:
                encryptedLoginToken = self.handleSsoRedirect(params, resp.loginState == APIRequest_pb2.REDIRECT_CLOUD_SSO, resp.url, resp.encryptedLoginToken)
                if encryptedLoginToken:
                    resp = LoginV3API.resume_login(params, encryptedLoginToken, encryptedDeviceToken, loginMethod='AFTER_SSO')
                else:
                    logging.info(bcolors.BOLD + bcolors.OKGREEN + "\nAttempting to authenticate with a master password." + bcolors.ENDC + bcolors.ENDC)
                    logging.info(bcolors.OKBLUE + "(Note: SSO users can create a Master Password in Web Vault > Settings)\n" + bcolors.ENDC)
                    is_alternate_login = True
                    resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken, loginType='ALTERNATE')

            elif resp.loginState == APIRequest_pb2.REQUIRES_DEVICE_ENCRYPTED_DATA_KEY:
                encryptedLoginToken = resp.encryptedLoginToken
                should_resume = self.handleSsoRequestDataKey(params, resp.encryptedLoginToken, encryptedDeviceToken)
                if should_resume:
                    resp = LoginV3API.resume_login(params, encryptedLoginToken, encryptedDeviceToken)

            elif resp.loginState == APIRequest_pb2.REQUIRES_ACCOUNT_CREATION:
                raise Exception('This account needs to be created.' % rest_api.CLIENT_VERSION)

            elif resp.loginState == APIRequest_pb2.REGION_REDIRECT:
                params.server = resp.stateSpecificValue
                logging.info('Redirecting to region: %s', params.server)
                LoginV3API.register_device_in_region(params, encryptedDeviceToken)
                resp = LoginV3API.startLoginMessage(params, encryptedDeviceToken)

            elif resp.loginState == APIRequest_pb2.REQUIRES_AUTH_HASH:
                if len(resp.salt) == 0:
                    self.handle_account_recovery(params, resp.encryptedLoginToken)
                    return

                salt = api.get_correct_salt(resp.salt)
                salt_bytes = salt.salt
                salt_iterations = salt.iterations
                need_account_recovery = False
                verify_password_response = None
                should_cancel = False

                class PasswordStep(login_steps.LoginStepPassword):
                    @property
                    def username(self):
                        return params.user

                    def forgot_password(self):
                        nonlocal need_account_recovery
                        need_account_recovery = True

                    def verify_password(self, password):
                        nonlocal verify_password_response
                        params.auth_verifier = crypto.derive_keyhash_v1(password, salt_bytes, salt_iterations)
                        verify_password_response = LoginV3API.validateAuthHashMessage(params, resp.encryptedLoginToken)
                        if verify_password_response:
                            params.password = password

                    def verify_biometric_key(self, biometric_key):
                        pass

                    def cancel(self):
                        nonlocal should_cancel
                        should_cancel = True

                step = PasswordStep()
                while True:
                    if not params.password and params.sso_login_info:
                        if 'sso_password' in params.sso_login_info and params.sso_login_info['sso_password']:
                            params.password = params.sso_login_info['sso_password'].pop()

                    if params.password:
                        try:
                            step.verify_password(params.password)
                        except:
                            params.password = None
                    else:
                        self.login_ui.on_password(step)
                        if should_cancel:
                            return
                        elif need_account_recovery:
                            self.handle_account_recovery(params, resp.encryptedLoginToken)
                            return

                    if verify_password_response:
                        break

                if verify_password_response:
                    params.salt = salt_bytes
                    params.iterations = salt_iterations
                    resp = verify_password_response

            elif resp.loginState == APIRequest_pb2.DEVICE_ACCOUNT_LOCKED:
                params.clear_session()
                raise Exception('\n*** Device for this account is locked ***\n')
            elif resp.loginState == APIRequest_pb2.DEVICE_LOCKED:
                params.clear_session()
                raise Exception('\n*** This device is locked ***\n')
            elif resp.loginState == APIRequest_pb2.ACCOUNT_LOCKED:
                raise Exception('\n*** User account `' + params.user + '` is LOCKED ***\n')
            elif resp.loginState == APIRequest_pb2.LICENSE_EXPIRED:
                raise Exception('\n*** Your Keeper license has expired ***\n')
            elif resp.loginState == APIRequest_pb2.UPGRADE:
                raise Exception('Application or device is out of date and requires an update.')
            elif resp.loginState == APIRequest_pb2.LOGGED_IN:
                LoginV3Flow.post_login_processing(params, resp)
                return
            else:
                raise Exception("UNKNOWN LOGIN STATE [%s]" % resp.loginState)

    @staticmethod
    def post_login_processing(params: KeeperParams, resp: APIRequest_pb2.LoginResponse):
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

        if resp.sessionTokenType != APIRequest_pb2.NO_RESTRICTION:
            # This is not a happy-path login.  Let the user know what's wrong.
            if resp.sessionTokenType in (APIRequest_pb2.PURCHASE, APIRequest_pb2.RESTRICT):
                params.session_token = None
                msg = (
                    'Your Keeper account has expired. Please open the Keeper app to renew or visit the Web '
                    'Vault at https://keepersecurity.com/vault'
                )
                raise Exception(msg)
            elif resp.sessionTokenType == APIRequest_pb2.ACCOUNT_RECOVERY:
                print('Your Master Password has expired, you are required to change it before you can login.\n')
                if LoginV3Flow.change_master_password(params):
                    return False
                else:
                    params.clear_session()
                    raise Exception('Change password failed')
            elif resp.sessionTokenType == APIRequest_pb2.SHARE_ACCOUNT:
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
                    rs = api.communicate_rest(params, None, 'enterprise/get_enterprise_public_key',
                                              rs_type=breachwatch_pb2.EnterprisePublicKeyResponse)
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
    def get_data_key(params: KeeperParams, resp: APIRequest_pb2.LoginResponse):
        """Get decrypted data key and store in params.data_key

        Returns login_type_message which is one of ("Persistent Login", "Password", "Master Password").
        """
        if resp.encryptedDataKeyType == APIRequest_pb2.BY_DEVICE_PUBLIC_KEY:
            private_key = crypto.load_ec_private_key(utils.base64_url_decode(params.device_private_key))
            decrypted_data_key = crypto.decrypt_ec(resp.encryptedDataKey, private_key)
            if params.sso_login_info:
                login_type_message = bcolors.UNDERLINE + "SSO Login"
            else:
                login_type_message = bcolors.UNDERLINE + "Persistent Login"

        elif resp.encryptedDataKeyType == APIRequest_pb2.BY_PASSWORD:
            decrypted_data_key = \
                utils.decrypt_encryption_params(resp.encryptedDataKey, params.password)
            login_type_message = bcolors.UNDERLINE + "Password"

        elif resp.encryptedDataKeyType == APIRequest_pb2.BY_ALTERNATE:
            decryption_key = crypto.derive_keyhash_v2('data_key', params.password, params.salt, params.iterations)
            decrypted_data_key = crypto.decrypt_aes_v2(resp.encryptedDataKey, decryption_key)
            login_type_message = bcolors.UNDERLINE + "Master Password"

        elif resp.encryptedDataKeyType == APIRequest_pb2.NO_KEY \
                or resp.encryptedDataKeyType == APIRequest_pb2.BY_BIO:
            raise Exception("Data Key type %s decryption not implemented" % resp.encryptedDataKeyType)
        else:
            raise Exception("Data Key type %s decryption not implemented" % resp.encryptedDataKeyType)

        params.data_key = decrypted_data_key
        return login_type_message

    @staticmethod
    def get_default_password_rules(params):  # type: (KeeperParams) -> (List[APIRequest_pb2.PasswordRules], int)
        rq = enterprise_pb2.DomainPasswordRulesRequest()
        rq.username = params.user
        rs = api.communicate_rest(params, rq, 'authentication/get_domain_password_rules',
                                  rs_type=APIRequest_pb2.NewUserMinimumParams)
        rules = []
        for regexp, description in zip(rs.passwordMatchRegex, rs.passwordMatchDescription):
            rule = APIRequest_pb2.PasswordRules()
            rule.match = True
            rule.pattern = regexp
            rule.description = description
            rules.append(rule)

        return rules, rs.minimumIterations

    @staticmethod
    def change_master_password(params, password_rules=None, min_iterations=None):
        # type: (KeeperParams, Optional[List[APIRequest_pb2.PasswordRules]], Optional[int]) -> bool
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

        params.is_enterprise_admin = acct_summary_dict_snake_case.get('is_enterprise_admin') is True

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
        params.sync_data = True
        params.prepare_commands = True

    @staticmethod
    def verifyDevice(params,                 # type: KeeperParams
                     encryptedDeviceToken,   # type: bytes
                     encryptedLoginToken,    # type: bytes
                     *,
                     approval_action,        # type: str
                     approval_channel,       # login_steps.DeviceApprovalChannel
                     approval_code=None      # Optional[str]
                     ):  # type: (...) -> bool
        if approval_action == 'push':
            if approval_channel == login_steps.DeviceApprovalChannel.Email:
                LoginV3API.requestDeviceVerificationMessage(params, encryptedDeviceToken, 'email')
            elif approval_channel == login_steps.DeviceApprovalChannel.KeeperPush:
                LoginV3API.twoFactorSend2FAPushMessage(params, encryptedLoginToken, pushType=APIRequest_pb2.TWO_FA_PUSH_KEEPER)
            elif approval_channel == login_steps.DeviceApprovalChannel.TwoFactor:
                LoginV3API.twoFactorSend2FAPushMessage(params, encryptedLoginToken)
            return False

        if approval_action == 'code':
            if approval_channel == login_steps.DeviceApprovalChannel.Email:
                LoginV3API.validateDeviceVerificationCodeMessage(params, approval_code)
            elif approval_channel == login_steps.DeviceApprovalChannel.TwoFactor:
                LoginV3API.twoFactorValidateMessage(params, encryptedLoginToken, approval_code)
            return True

        return False

    def handleSsoRequestDataKey(self, params, login_token, device_token):  # type: (KeeperParams, bytes, bytes) -> bool
        should_cancel = False
        should_resume = False

        class SsoDataKeyStep(login_steps.LoginStepSsoDataKey):
            def request_data_key(self, channel):
                nonlocal should_resume
                if channel == login_steps.DataKeyShareChannel.KeeperPush:
                    rq = APIRequest_pb2.TwoFactorSendPushRequest()
                    rq.pushType = APIRequest_pb2.TWO_FA_PUSH_KEEPER
                    rq.encryptedLoginToken = login_token
                    api.communicate_rest(params, rq, "authentication/2fa_send_push")
                elif channel == login_steps.DataKeyShareChannel.AdminApproval:
                    rq = APIRequest_pb2.DeviceVerificationRequest()
                    rq.username = params.user
                    rq.clientVersion = rest_api.CLIENT_VERSION
                    rq.encryptedDeviceToken = device_token

                    rs = api.communicate_rest(params, rq, "authentication/request_device_admin_approval",
                                              rs_type=APIRequest_pb2.DeviceVerificationResponse)
                    if rs.deviceStatus == APIRequest_pb2.DEVICE_OK:
                        should_resume = True

            def resume(self):
                nonlocal should_resume
                should_resume = True

            def cancel(self):
                nonlocal should_cancel
                should_cancel = True

        self.login_ui.on_sso_data_key(SsoDataKeyStep())
        if should_cancel:
            raise KeyboardInterrupt()
        return should_resume

    def handleSsoRedirect(self, params, is_cloud, sso_url, login_token):    # type: (KeeperParams, bool, str, bytes) -> Optional[bytes]
        sp_url_builder = urlparse(sso_url)
        sp_url_query = parse_qsl(sp_url_builder.query, keep_blank_values=True)
        transmission_key = None     # type: Optional[bytes]
        rsa_private = None
        if is_cloud:
            sso_rq = ssocloud_pb2.SsoCloudRequest()
            sso_rq.messageSessionUid = crypto.get_random_bytes(16)
            sso_rq.clientVersion = rest_api.CLIENT_VERSION
            sso_rq.dest = 'commander'
            sso_rq.username = params.user.lower()
            sso_rq.forceLogin = False
            sso_rq.detached = True

            transmission_key = utils.generate_aes_key()
            rq_payload = APIRequest_pb2.ApiRequestPayload()
            rq_payload.apiVersion = 3
            rq_payload.payload = sso_rq.SerializeToString()
            api_rq = APIRequest_pb2.ApiRequest()
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

        sp_url_builder = sp_url_builder._replace(query=urlencode(sp_url_query, doseq=True))
        sp_url = urlunparse(sp_url_builder)

        should_cancel = False
        use_master_password = False
        sso_token = None    # type: Optional[str]

        class SsoRedirectStep(login_steps.LoginStepSsoToken):
            def set_sso_token(self, token):
                nonlocal sso_token
                sso_token = token

            def login_with_password(self):
                nonlocal use_master_password
                use_master_password = True

            @property
            def is_cloud_sso(self):
                return is_cloud

            @property
            def is_provider_login(self):
                return False

            @property
            def login_name(self):
                return params.user

            @property
            def sso_login_url(self):
                return sp_url

            def cancel(self):
                nonlocal should_cancel
                should_cancel = True

        self.login_ui.on_sso_redirect(SsoRedirectStep())
        if use_master_password:
            return None
        if should_cancel:
            raise KeyboardInterrupt()
        if sso_token:
            if is_cloud:
                rs_bytes = crypto.decrypt_aes_v2(utils.base64_url_decode(sso_token), transmission_key)
                sso_rs = ssocloud_pb2.SsoCloudResponse()
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
                sso_dict = json.loads(sso_token)
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
        raise KeyboardInterrupt()

    def handle_account_recovery(self, params, encrypted_login_token_bytes):
        logging.info('')
        logging.info('Password Recovery')
        rq = APIRequest_pb2.MasterPasswordRecoveryVerificationRequest()
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

        rq = APIRequest_pb2.GetSecurityQuestionV3Request()
        rq.encryptedLoginToken = encrypted_login_token_bytes
        rq.verificationCode = verification_code
        rs = api.communicate_rest(params, rq, 'authentication/account_recovery_verify_code',
                                  rs_type=APIRequest_pb2.AccountRecoveryVerifyCodeResponse)

        backup_type = rs.backupKeyType

        if backup_type == APIRequest_pb2.BKT_SEC_ANSWER:
            print(f'Security Question: {rs.securityQuestion}')
            answer = getpass.getpass(prompt='Answer: ', stream=None)
            if not answer:
                return
            recovery_phrase = answer.lower()
            auth_hash = crypto.derive_keyhash_v1(recovery_phrase, rs.salt, rs.iterations)
        elif backup_type == APIRequest_pb2.BKT_PASSPHRASE_HASH:
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

        rq = APIRequest_pb2.GetDataKeyBackupV3Request()
        rq.encryptedLoginToken = encrypted_login_token_bytes
        rq.verificationCode = verification_code
        rq.securityAnswerHash = auth_hash
        rs = api.communicate_rest(params, rq, 'authentication/get_data_key_backup_v3',
                                  rs_type=APIRequest_pb2.GetDataKeyBackupV3Response)
        if backup_type == APIRequest_pb2.BKT_SEC_ANSWER:
            params.data_key = utils.decrypt_encryption_params(rs.dataKeyBackup, recovery_phrase)
        else:
            encryption_key = crypto.generate_hkdf_key('recovery_key_aes_gcm_256', recovery_phrase)
            params.data_key = crypto.decrypt_aes_v2(rs.dataKeyBackup, encryption_key)
        params.session_token = utils.base64_url_encode(rs.encryptedSessionToken)

        success = LoginV3Flow.change_master_password(params, list(rs.passwordRules), rs.minimumPbkdf2Iterations)
        if success:
            self.login(params)


class LoginV3API:
    @staticmethod
    def rest_request(params: KeeperParams, api_endpoint: str, rq):
        api_request_payload = APIRequest_pb2.ApiRequestPayload()
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

            rq = APIRequest_pb2.DeviceRegistrationRequest()
            rq.clientVersion = rest_api.CLIENT_VERSION
            rq.deviceName = CommonHelperMethods.get_device_name()
            rq.devicePublicKey = crypto.unload_ec_public_key(public)

            api_request_payload = APIRequest_pb2.ApiRequestPayload()
            api_request_payload.payload = rq.SerializeToString()

            rs = rest_api.execute_rest(params.rest_context, 'authentication/register_device', api_request_payload)

            if type(rs) == bytes:
                register_device_rs = APIRequest_pb2.Device()
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
        rq = APIRequest_pb2.DeviceVerificationRequest()

        rq.username = params.user.lower()
        rq.encryptedDeviceToken = encrypted_device_token
        rq.verificationChannel = verification_channel
        rq.clientVersion = rest_api.CLIENT_VERSION
        if message_session_uid:
            rq.messageSessionUid = utils.base64_url_encode(message_session_uid)

        api.communicate_rest(params, rq, 'authentication/request_device_verification',
                             rs_type=APIRequest_pb2.DeviceVerificationResponse)

    @staticmethod
    def validateDeviceVerificationCodeMessage(params: KeeperParams, verificationCode: str):
        rq = APIRequest_pb2.ValidateDeviceVerificationCodeRequest()
        rq.username = params.user.lower()
        rq.clientVersion = rest_api.CLIENT_VERSION
        # rq.encryptedDeviceToken = encrypted_device_token
        rq.verificationCode = verificationCode

        api_request_payload = APIRequest_pb2.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        api.communicate_rest(params, rq, 'authentication/validate_device_verification_code')

    @staticmethod
    def resume_login(params: KeeperParams, encryptedLoginToken, encryptedDeviceToken, cloneCode = None, loginType = 'NORMAL', loginMethod='EXISTING_ACCOUNT'):
        rq = APIRequest_pb2.StartLoginRequest()
        rq.clientVersion = rest_api.CLIENT_VERSION
        rq.encryptedLoginToken = encryptedLoginToken
        rq.encryptedDeviceToken = encryptedDeviceToken
        rq.username = params.user.lower()
        rq.loginType = APIRequest_pb2.LoginType.Value(loginType)
        if cloneCode:
            rq.loginMethod = APIRequest_pb2.LoginMethod.Value(loginMethod)
            rq.cloneCode = cloneCode

        api_request_payload = APIRequest_pb2.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        rs = rest_api.execute_rest(params.rest_context, 'authentication/start_login', api_request_payload)

        if type(rs) == bytes:
            login_resp = APIRequest_pb2.LoginResponse()
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
        # type: (KeeperParams, bytes, Optional[bytes], str) -> APIRequest_pb2.LoginResponse
        rq = APIRequest_pb2.StartLoginRequest()
        rq.clientVersion = rest_api.CLIENT_VERSION
        rq.username = params.user.lower()
        rq.encryptedDeviceToken = encryptedDeviceToken
        rq.loginType = APIRequest_pb2.LoginType.Value(loginType)
        rq.loginMethod = APIRequest_pb2.LoginMethod.Value('EXISTING_ACCOUNT')

        if cloneCode:
            rq.cloneCode = cloneCode
            rq.username = ''

        api_request_payload = APIRequest_pb2.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        rs = rest_api.execute_rest(params.rest_context, 'authentication/start_login', api_request_payload)

        if type(rs) == bytes:
            login_resp = APIRequest_pb2.LoginResponse()
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
    def validateAuthHashMessage(params: KeeperParams, encrypted_login_token_bytes):

        rq = APIRequest_pb2.ValidateAuthHashRequest()
        rq.passwordMethod = APIRequest_pb2.PasswordMethod.Value("ENTERED")

        rq.authResponse = params.auth_verifier
        rq.encryptedLoginToken = encrypted_login_token_bytes

        api_request_payload = APIRequest_pb2.ApiRequestPayload()
        api_request_payload.payload = rq.SerializeToString()

        rs = rest_api.execute_rest(params.rest_context, 'authentication/validate_auth_hash', api_request_payload)

        if type(rs) == bytes:
            login_resp = APIRequest_pb2.LoginResponse()
            login_resp.ParseFromString(rs)
            return login_resp
        else:
            error_code = rs['error']
            raise KeeperApiError(error_code, 'Invalid email or password combination, please re-enter.' if error_code == 'auth_failed' else rs['message'] )

    @staticmethod
    def twoFactorValidateMessage(params,                   # type: KeeperParams
                                 encryptedLoginToken,      # type: bytes
                                 otp_code,                 # type: str
                                 *,
                                 tfa_expire_in=None,       # type: Any
                                 twoFactorValueType=None,  # type: Any
                                 channel_uid=None          # type: Any
                                 ):                        # type: (...) -> Optional[bytes]

        rq = APIRequest_pb2.TwoFactorValidateRequest()
        rq.encryptedLoginToken = encryptedLoginToken
        rq.value = otp_code
        if twoFactorValueType:
            rq.valueType = twoFactorValueType
        if channel_uid:
            rq.channel_uid = channel_uid
        rq.expireIn = tfa_expire_in

        rs = api.communicate_rest(params, rq, 'authentication/2fa_validate',
                                  rs_type=APIRequest_pb2.TwoFactorValidateResponse)
        if rs:
            return rs.encryptedLoginToken

    @staticmethod
    def twoFactorSend2FAPushMessage(params: KeeperParams,
                                    encryptedLoginToken: bytes,
                                    *,
                                    pushType=None,
                                    channel_uid=None,
                                    expireIn=None):

        rq = APIRequest_pb2.TwoFactorSendPushRequest()
        rq.encryptedLoginToken = encryptedLoginToken
        if channel_uid:
            rq.channel_uid = channel_uid
        if expireIn:
            rq.expireIn = expireIn
        if pushType:
            rq.pushType = pushType

        api.communicate_rest(params, rq, 'authentication/2fa_send_push')

    @staticmethod
    def rename_device(params: KeeperParams, new_name):

        rq = APIRequest_pb2.DeviceUpdateRequest()
        rq.clientVersion = rest_api.CLIENT_VERSION
        # rq.deviceStatus = APIRequest_pb2.DEVICE_OK
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
        rq = APIRequest_pb2.RegisterDeviceDataKeyRequest()
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
        rq = APIRequest_pb2.RegisterDeviceInRegionRequest()
        rq.encryptedDeviceToken = encrypted_device_token
        rq.clientVersion = rest_api.CLIENT_VERSION
        rq.deviceName = CommonHelperMethods.get_device_name()
        device_key = crypto.load_ec_private_key(utils.base64_url_decode(params.device_private_key))
        rq.devicePublicKey = crypto.unload_ec_public_key(device_key.public_key())
        api_request_payload = APIRequest_pb2.ApiRequestPayload()
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

        rq = APIRequest_pb2.UserSettingRequest()
        rq.setting = name
        rq.value = value

        try:
            rs = api.communicate_rest(params, rq, 'setting/set_user_setting')
        except Exception as e:
            raise e

        return True

    @staticmethod
    def accountSummary(params: KeeperParams):
        rq = AccountSummary_pb2.AccountSummaryRequest()
        rq.summaryVersion = 1
        return api.communicate_rest(params, rq, 'login/account_summary', rs_type=AccountSummary_pb2.AccountSummaryElements)

    @staticmethod
    def loginToMc(rest_context, session_token, mc_id):

        endpoint = 'authentication/login_to_mc'

        rq = enterprise_pb2.LoginToMcRequest()
        rq.mcEnterpriseId = mc_id

        api_request_payload = APIRequest_pb2.ApiRequestPayload()
        # api_request_payload.payload = rq.SerializeToString()

        api_request_payload.encryptedSessionToken = base64.urlsafe_b64decode(session_token + '==')
        api_request_payload.payload = rq.SerializeToString()

        try:
            rs = rest_api.execute_rest(rest_context, endpoint, api_request_payload)
        except Exception as e:
            raise KeeperApiError('Rest API', str(e))

        if type(rs) == bytes:

            login_to_mc_rs = enterprise_pb2.LoginToMcResponse()
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


class InvalidDeviceToken(Exception):
    pass


TwoFactorChannelMapping = namedtuple('TwoFactorChannelMapping', ['sdk', 'proto', 'value'])
TwoFactorChannels: List[TwoFactorChannelMapping] = [
    TwoFactorChannelMapping(sdk=login_steps.TwoFactorChannel.Authenticator, proto=APIRequest_pb2.TWO_FA_CT_TOTP,
                            value=APIRequest_pb2.TWO_FA_CODE_TOTP),
    TwoFactorChannelMapping(sdk=login_steps.TwoFactorChannel.TextMessage, proto=APIRequest_pb2.TWO_FA_CT_SMS,
                            value=APIRequest_pb2.TWO_FA_CODE_SMS),
    TwoFactorChannelMapping(sdk=login_steps.TwoFactorChannel.DuoSecurity, proto=APIRequest_pb2.TWO_FA_CT_DUO,
                            value=APIRequest_pb2.TWO_FA_CODE_DUO),
    TwoFactorChannelMapping(sdk=login_steps.TwoFactorChannel.RSASecurID, proto=APIRequest_pb2.TWO_FA_CT_RSA,
                            value=APIRequest_pb2.TWO_FA_CODE_RSA),
    TwoFactorChannelMapping(sdk=login_steps.TwoFactorChannel.SecurityKey, proto=APIRequest_pb2.TWO_FA_CT_WEBAUTHN,
                            value=APIRequest_pb2.TWO_FA_RESP_WEBAUTHN),
    TwoFactorChannelMapping(sdk=login_steps.TwoFactorChannel.KeeperDNA, proto=APIRequest_pb2.TWO_FA_CT_DNA,
                            value=APIRequest_pb2.TWO_FA_CODE_DNA),
    TwoFactorChannelMapping(sdk=login_steps.TwoFactorChannel.Backup, proto=APIRequest_pb2.TWO_FA_CT_BACKUP,
                            value=APIRequest_pb2.TWO_FA_CODE_NONE),
]


def _channel_keeper_to_sdk(channel_proto):  # type: (APIRequest_pb2.TwoFactorChannelType) -> login_steps.TwoFactorChannel
    return next((x.sdk for x in TwoFactorChannels if x.proto == channel_proto), login_steps.TwoFactorChannel.Other)


def _channel_keeper_value(channel_sdk):  # type: (login_steps.TwoFactorChannel) -> APIRequest_pb2.TwoFactorValueType
    return next((x.value for x in TwoFactorChannels if x.sdk == channel_sdk), APIRequest_pb2.TWO_FA_CODE_NONE)


DurationMapping = namedtuple('DurationMapping', ['sdk', 'proto'])
Durations: List[DurationMapping] = [
    DurationMapping(sdk=login_steps.TwoFactorDuration.EveryLogin, proto=APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY),
    DurationMapping(sdk=login_steps.TwoFactorDuration.EveryLogin, proto=APIRequest_pb2.TWO_FA_EXP_5_MINUTES),
    DurationMapping(sdk=login_steps.TwoFactorDuration.Every12Hours, proto=APIRequest_pb2.TWO_FA_EXP_12_HOURS),
    DurationMapping(sdk=login_steps.TwoFactorDuration.Every24Hours, proto=APIRequest_pb2.TWO_FA_EXP_24_HOURS),
    DurationMapping(sdk=login_steps.TwoFactorDuration.EveryDay, proto=APIRequest_pb2.TWO_FA_EXP_24_HOURS),
    DurationMapping(sdk=login_steps.TwoFactorDuration.Every30Days, proto=APIRequest_pb2.TWO_FA_EXP_30_DAYS),
    DurationMapping(sdk=login_steps.TwoFactorDuration.Forever, proto=APIRequest_pb2.TWO_FA_EXP_NEVER),
]


def _duration_keeper_to_sdk(duration):    # type: (APIRequest_pb2.TwoFactorExpiration) -> login_steps.TwoFactorDuration
    return next((x.sdk for x in Durations if x.proto == duration), login_steps.TwoFactorDuration.EveryLogin)


def _duration_sdk_to_keeper(duration):   # type: (login_steps.TwoFactorDuration) -> APIRequest_pb2.TwoFactorExpiration
    return next((x.proto for x in Durations if x.sdk == duration), APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY)


def _tfa_channel_info_keeper_to_sdk(channel_info):   # type: (APIRequest_pb2.TwoFactorChannelInfo) -> login_steps.TwoFactorChannelInfo
    info = login_steps.TwoFactorChannelInfo()
    info.channel_type = _channel_keeper_to_sdk(channel_info.channelType)
    info.channel_uid = channel_info.channel_uid
    info.channel_name = channel_info.channelName
    info.phone = channel_info.phoneNumber
    info.max_expiration = _duration_keeper_to_sdk(channel_info.maxExpiration)
    info.challenge = channel_info.challenge
    return info


TwoFactorPushMapping = namedtuple('TwoFactorPushMapping', ['sdk', 'proto'])
TwoFactorPushes: List[TwoFactorPushMapping] = [
    TwoFactorPushMapping(sdk=login_steps.TwoFactorPushAction.DuoPush, proto=APIRequest_pb2.TWO_FA_PUSH_DUO_PUSH),
    TwoFactorPushMapping(sdk=login_steps.TwoFactorPushAction.DuoTextMessage, proto=APIRequest_pb2.TWO_FA_PUSH_DUO_TEXT),
    TwoFactorPushMapping(sdk=login_steps.TwoFactorPushAction.DuoVoiceCall, proto=APIRequest_pb2.TWO_FA_PUSH_DUO_CALL),
    TwoFactorPushMapping(sdk=login_steps.TwoFactorPushAction.TextMessage, proto=APIRequest_pb2.TWO_FA_PUSH_SMS),
    TwoFactorPushMapping(sdk=login_steps.TwoFactorPushAction.KeeperDna, proto=APIRequest_pb2.TWO_FA_PUSH_KEEPER),
]


def tfa_action_sdk_to_keeper(action: login_steps.TwoFactorPushAction) -> APIRequest_pb2.TwoFactorPushType:
    return next((x.proto for x in TwoFactorPushes if x.sdk == action), APIRequest_pb2.TWO_FA_PUSH_NONE)
