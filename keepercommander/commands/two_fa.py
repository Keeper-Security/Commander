#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import datetime
import json
import logging

from .base import GroupCommand, Command, report_output_parser, dump_report_data, field_to_title, user_choice
from .. import api, utils
from ..error import CommandError, KeeperApiError
from ..proto import APIRequest_pb2


class TwoFaCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('list', TfaListCommand(), 'Displays a list of 2FA methods')
        self.register_command('add', TfaAddCommand(), 'Add 2FA method')
        self.register_command('delete', TfaDeleteCommand(), 'Delete 2FA method')
        self.default_verb = 'list'

    @staticmethod
    def two_factor_channel_to_desc(channel):
        if channel == APIRequest_pb2.TWO_FA_CT_TOTP:
            return 'TOTP'
        if channel == APIRequest_pb2.TWO_FA_CT_SMS:
            return 'SMS'
        if channel == APIRequest_pb2.TWO_FA_CT_DUO:
            return 'DUO'
        if channel == APIRequest_pb2.TWO_FA_CT_RSA:
            return 'RSA SecurID'
        if channel == APIRequest_pb2.TWO_FA_CT_U2F:
            return 'U2F'
        if channel == APIRequest_pb2.TWO_FA_CT_WEBAUTHN:
            return 'Security Key'
        if channel == APIRequest_pb2.TWO_FA_CT_DNA:
            return 'Keeper DNA (Watch)'
        if channel == APIRequest_pb2.TWO_FA_CT_BACKUP:
            return 'Backup Codes'


class TfaListCommand(Command):
    parser = argparse.ArgumentParser(prog='2fa list', parents=[report_output_parser])

    def get_parser(self):
        return TfaListCommand.parser

    def execute(self, params, **kwargs):
        rs = api.communicate_rest(params, None, 'authentication/2fa_list', rs_type=APIRequest_pb2.TwoFactorListResponse)
        expire_at = ''
        if rs.expireOn > 0:
            if rs.expireOn > 3_000_000_000_000:
                expire_at = 'Never'
            else:
                dt = datetime.datetime.fromtimestamp(rs.expireOn // 1000)
                expire_at = dt.isoformat()

        if expire_at is not None:
            logging.info('2FA authentication expires: %s\n', expire_at)
        table = []
        for channel in rs.channels:
            created_on = datetime.datetime.fromtimestamp(channel.createdOn // 1000)
            row = [TwoFaCommand.two_factor_channel_to_desc(channel.channelType),
                   utils.base64_url_encode(channel.channel_uid), channel.channelName, created_on, channel.phoneNumber]
            table.append(row)

        fmt = kwargs.get('format')
        header = ['method', 'channel_uid', 'name', 'created', 'phone_number']
        if fmt != 'json':
            header = [field_to_title(x) for x in header]

        return dump_report_data(table, header, fmt=fmt, filename=kwargs.get('output'), row_number=True)


class TfaAddCommand(Command):
    parser = argparse.ArgumentParser(prog='2fa add', description='Add 2FA method')
    parser.add_argument('--method', '-m', dest='method', action='store', required=True,
                        choices=['totp', 'key', 'sms', 'duo', 'backup'], help='2FA auth method')
    parser.add_argument('--name', dest='name', action='store', help='2FA auth name')
    parser.add_argument('--key-pin', dest='key_pin', action='store_true', help='force using Security Key PIN')

    def get_parser(self):
        return TfaAddCommand.parser

    def execute(self, params, **kwargs):
        all_tfa_restrictions = {'require_security_key_pin', 'restrict_two_factor_channel_text',
                                'restrict_two_factor_channel_google', 'restrict_two_factor_channel_duo',
                                'restrict_two_factor_channel_security_key', 'restrict_two_factor_channel_rsa',
                                'restrict_two_factor_channel_dna'}
        tfa_restrictions = set()
        if params.enforcements and 'booleans' in params.enforcements:
            for x in params.enforcements['booleans']:
                key = (x.get('key') or '').lower()
                if key in all_tfa_restrictions:
                    tfa_restrictions.add(key)

        method = kwargs.get('method')
        rq = APIRequest_pb2.TwoFactorAddRequest()
        rq.channel_uid = utils.base64_url_decode(utils.generate_uid())
        rq.channelName = kwargs.get('name') or ''

        if method == 'totp':
            if 'restrict_two_factor_channel_google' in tfa_restrictions:
                raise CommandError('', 'Authenticator App (TOTP) 2FA method is disabled by the Administrator')
            rq.channelType = APIRequest_pb2.TWO_FA_CT_TOTP
        elif method == 'sms':
            if 'restrict_two_factor_channel_text' in tfa_restrictions:
                raise CommandError('', 'Text Message (SMS) 2FA method is disabled by the Administrator')
            rq.channelType = APIRequest_pb2.TWO_FA_CT_SMS
        elif method == 'key':
            if 'restrict_two_factor_channel_security_key' in tfa_restrictions:
                raise CommandError('', 'Security Key 2FA method is disabled by the Administrator')
            rq.channelType = APIRequest_pb2.TWO_FA_CT_WEBAUTHN
        elif method == 'duo':
            rq.channelType = APIRequest_pb2.TWO_FA_CT_DUO
        elif method == 'backup':
            rq.channelType = APIRequest_pb2.TWO_FA_CT_BACKUP
        else:
            raise CommandError('2fa add', f'2FA method "{method}" is not supported')

        # Input
        if rq.channelType == APIRequest_pb2.TWO_FA_CT_SMS:
            try:
                phone_number = input('\nEnter your phone number for text messages: ')
                if not phone_number:
                    return
                rq.phoneNumber = phone_number
            except KeyboardInterrupt:
                return

        elif rq.channelType == APIRequest_pb2.TWO_FA_CT_DUO:
            duo_rs = api.communicate_rest(params, None, 'authentication/2fa_duo_status',
                                          rs_type=APIRequest_pb2.TwoFactorDuoStatus)
            if duo_rs.enroll_url:
                logging.warning(duo_rs.message)
                logging.warning("Enroll URL")
                print(duo_rs.enroll_url)
                return
            capabilities = [x for x in duo_rs.capabilities if x in ('mobile_otp', 'sms', 'voice')]
            print(f'Device Phone Number: {duo_rs.phoneNumber}')
            if len(capabilities) == 0:
                return
            print('We\'ll send you a text message or call with a passcode to your device:')
            for no in range(len(capabilities)):
                c = capabilities[no]
                if c == 'sms':
                    c = 'Send a Text Message'
                elif c == 'voice':
                    c = 'Make a Voice Call'
                if c == 'mobile_otp':
                    c = 'OTP Code on Mobile'
                print(f'  {no+1}. {c}')
            print(f'  q. Cancel')
            while True:
                answer = input('Selection: ')
                if answer in ('q', 'Q'):
                    return
                if answer:
                    if answer.isnumeric():
                        code = int(answer)
                        if 0 < code < len(capabilities):
                            c = capabilities[code - 1]
                            rq.duoPushType = \
                                APIRequest_pb2.TWO_FA_PUSH_DUO_TEXT if c == 'sms' else \
                                APIRequest_pb2.TWO_FA_PUSH_DUO_CALL if c == 'voice' else \
                                APIRequest_pb2.TWO_FA_PUSH_NONE
                            break
                    logging.info(f'Action \"{answer}\" is not supported.')

        rs = api.communicate_rest(params, rq, 'authentication/2fa_add', rs_type=APIRequest_pb2.TwoFactorAddResponse)

        if rq.channelType == APIRequest_pb2.TWO_FA_CT_BACKUP:
            codes = list(rs.backupKeys)
            table = []
            for no in range(0, len(codes), 2):
                table.append(codes[no: no+2])
            dump_report_data(table, ('', ''), title='Backup Codes', no_header=True)
            return

        if rq.channelType == APIRequest_pb2.TWO_FA_CT_WEBAUTHN:
            try:
                from ..yubikey.yubikey import yubikey_register
                request = json.loads(rs.challenge)
                force_pin = kwargs.get('key_pin') is True
                response = yubikey_register(request, force_pin)
                credential_id = response.attestation_object.auth_data.credential_data.credential_id
                attestation = {
                    'id': utils.base64_url_encode(credential_id),
                    'rawId': utils.base64_url_encode(credential_id),
                    'response': {
                        'attestationObject': utils.base64_url_encode(response.attestation_object),
                        'clientDataJSON': response.client_data.b64
                    },
                    'type': 'public-key',
                    # 'transports': ['usb'],
                    'clientExtensionResults': response.extension_results or {}
                }
                rq_yubikey = APIRequest_pb2.TwoFactorValidateRequest()
                rq_yubikey.valueType = APIRequest_pb2.TWO_FA_RESP_WEBAUTHN
                rq_yubikey.value = json.dumps(attestation)
                rq_yubikey.channel_uid = rq.channel_uid
                rq_yubikey.expireIn = APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY
                api.communicate_rest(params, rq_yubikey, 'authentication/2fa_add_validate')
            except ImportError as e:
                from ..yubikey import display_fido2_warning
                logging.warning(e)
                display_fido2_warning()
            except Exception as e:
                logging.warning(e)
            return

        if rq.channelType == APIRequest_pb2.TWO_FA_CT_TOTP:
            url = f'otpauth://totp/Keeper:{params.user}?secret={rs.challenge}'
            print(f'TOTP URL:\n{url}')
            try:
                import pyqrcode
                url = pyqrcode.create(url)
                print(url.terminal('black', 'white'))
            except ModuleNotFoundError:
                print('QR Code library is not installed.\npip install pyqrcode')

        rq_validate = APIRequest_pb2.TwoFactorValidateRequest()
        if rq.channelType == APIRequest_pb2.TWO_FA_CT_TOTP:
            rq_validate.valueType = APIRequest_pb2.TWO_FA_CODE_TOTP
        elif rq.channelType == APIRequest_pb2.TWO_FA_CT_SMS:
            rq_validate.valueType = APIRequest_pb2.TWO_FA_CODE_SMS
        elif rq.channelType == APIRequest_pb2.TWO_FA_CT_WEBAUTHN:
            rq_validate.valueType = APIRequest_pb2.TWO_FA_RESP_WEBAUTHN
        elif rq.channelType == APIRequest_pb2.TWO_FA_CT_DUO:
            rq_validate.valueType = APIRequest_pb2.TWO_FA_CODE_DUO

        rq_validate.expireIn = APIRequest_pb2.TWO_FA_EXP_IMMEDIATELY
        rq_validate.channel_uid = rq.channel_uid
        while True:
            try:
                answer = input('Verification Code: ')
                if answer:
                    rq_validate.value = answer
                    try:
                        api.communicate_rest(params, rq_validate, 'authentication/2fa_add_validate')
                        print("\033[2J")
                        logging.info('2FA method is added')
                        return
                    except KeeperApiError as kae:
                        logging.warning('Invalid 2FA code: (%s): %s ', kae.result_code, kae.message)
            except KeyboardInterrupt:
                return


class TfaDeleteCommand(Command):
    parser = argparse.ArgumentParser(prog='2fa delete', description='Delete 2FA method')
    parser.add_argument('--force', dest='force', action='store_true', help='do not prompt for confirmation')
    parser.add_argument('name', help='2FA method UID or name')

    def get_parser(self):
        return TfaDeleteCommand.parser

    def execute(self, params, **kwargs):
        name = kwargs.get('name')
        if not name:
            raise CommandError('2fa delete', '"name" argument is required')
        rs = api.communicate_rest(params, None, 'authentication/2fa_list', rs_type=APIRequest_pb2.TwoFactorListResponse)
        channel = next((x for x in rs.channels if utils.base64_url_encode(x.channel_uid) == name), None)
        if not channel:
            l_name = name.casefold()
            for x in rs.channels:
                if l_name == x.channelName.casefold():
                    channel = x
                    break
        if not channel:
            raise CommandError('2fa delete', f'2FA channel "{name}" not found')

        if not kwargs.get('force') is True:
            channel_name = channel.channelName
            if not channel_name:
                channel_name = utils.base64_url_encode(channel.channel_uid)
            answer = user_choice(f'Do you want to delete 2FA channel "{channel_name}"?', 'yn', 'n')
            if answer not in ('y', 'Y'):
                return
        rq = APIRequest_pb2.TwoFactorDeleteRequest()
        rq.channel_uid = channel.channel_uid
        api.communicate_rest(params, rq, 'authentication/2fa_delete')
        logging.info('2FA channel is deleted')
