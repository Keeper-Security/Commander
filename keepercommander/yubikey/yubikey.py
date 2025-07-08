#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2021 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import getpass
import logging
import os
import threading
from typing import Optional

from fido2.client import ClientError, DefaultClientDataCollector, UserInteraction, WebAuthnClient

from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice
from fido2.webauthn import (PublicKeyCredentialRequestOptions, AuthenticationResponse,
                            PublicKeyCredentialCreationOptions, RegistrationResponse,
                            UserVerificationRequirement)
from fido2.ctap2.pin import ClientPin, Ctap2
from prompt_toolkit import PromptSession

from .. import utils

def verify_rp_id_none(rp_id, origin):
    return True


prompt_session = None    # type: Optional[PromptSession]
if os.isatty(0) and os.isatty(1):
    prompt_session = PromptSession(multiline=False, complete_while_typing=False)


class CliInteraction(UserInteraction):
    def prompt_up(self):
        print("\nTouch the flashing Security key to authenticate or "
              "press Ctrl-C to resume with the primary two factor authentication...\n")

    def request_pin(self, permissions, rd_id):
        global prompt_session
        prompt = "Enter Security Key PIN: "
        if prompt_session:
            return prompt_session.prompt(prompt, is_password=True)
        else:
            return getpass.getpass(prompt)

    def request_uv(self, permissions, rd_id):
        print("User Verification required.")
        return True


def yubikey_register(request, force_pin=False):    # type: (dict, bool) -> Optional[RegistrationResponse]
    rq = request.copy()
    user_id = rq['user']['id']
    if isinstance(user_id, str):
        rq['user']['id'] = utils.base64_url_decode(user_id)
    challenge = rq['challenge']
    if isinstance(challenge, str):
        rq['challenge'] = utils.base64_url_decode(challenge)

    if force_pin:
        uv = rq['authenticatorSelection']['userVerification']
        if uv != UserVerificationRequirement.REQUIRED:
            rq['authenticatorSelection']['userVerification'] = UserVerificationRequirement.REQUIRED

    options = PublicKeyCredentialCreationOptions.from_dict(rq)   # type: PublicKeyCredentialCreationOptions
    origin = options.extensions.get('appidExclude') or options.rp.id

    client = None   # type: Optional[WebAuthnClient]
    data_collector = DefaultClientDataCollector(origin, verify=verify_rp_id_none)
    if os.name == 'nt':
        from fido2.client.windows import WindowsClient
        client = WindowsClient(client_data_collector=data_collector)
    else:
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            logging.warning("No Security Key detected")
            return

        from fido2.client import Fido2Client
        fido_client = Fido2Client(dev, client_data_collector=data_collector, user_interaction=CliInteraction())
        uv_configured = any(fido_client.info.options.get(k) for k in ("uv", "clientPin", "bioEnroll"))
        uv = options.authenticator_selection.user_verification
        if uv == UserVerificationRequirement.REQUIRED:
            if not uv_configured:
                print('\nSecret Key PIN is required')
                answer = input('Do you want to setup PIN code for your Secret Key? (y/n): ')
                if answer not in ('y', 'Y'):
                    return
                prompt1 = '       PIN Code: '
                prompt2 = ' PIN Code Again: '
                if prompt_session:
                    pin1 = prompt_session.prompt(prompt1, is_password=True)
                else:
                    pin1 = getpass.getpass(prompt1)
                if not pin1:
                    raise Exception('PIN is required')
                if prompt_session:
                    pin2 = prompt_session.prompt(prompt2, is_password=True)
                else:
                    pin2 = getpass.getpass(prompt2)
                if not pin2:
                    raise Exception('PIN is required')
                if pin1 != pin2:
                    raise Exception('PINs do not match')
                client_pin = ClientPin(Ctap2(dev))
                client_pin.set_pin(pin1)
        elif uv == UserVerificationRequirement.PREFERRED:
            if not uv_configured:
                rq['authenticatorSelection']['userVerification'] = UserVerificationRequirement.DISCOURAGED
                options = PublicKeyCredentialCreationOptions.from_dict(rq)
        client = fido_client

    evt = threading.Event()
    try:
        return client.make_credential(options, event=evt)
    except ClientError as err:
        if isinstance(err.cause, CtapError):
            if err.cause.code == CtapError.ERR.PIN_INVALID:
                raise Exception('PIN is invalid')
            elif err.cause.code == CtapError.ERR.PIN_AUTH_BLOCKED:
                raise Exception('PIN is blocked')
        elif isinstance(err.cause, str):
            if err.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED:
                raise Exception('Security key user verification (PIN or Biometric) is not configured')
        raise err
    except Exception as e:
        raise e
    finally:
        evt.set()


def yubikey_authenticate(request):  # type: (dict) -> Optional[AuthenticationResponse]
    if 'publicKeyCredentialRequestOptions' not in request:
        return

    options = request['publicKeyCredentialRequestOptions'].copy()
    origin = ''
    if 'extensions' in options:
        extensions = options['extensions']
        origin = extensions.get('appid') or ''
        if 'largeBlob' not in options['extensions']:
            options['extensions']['largeBlob'] = {'read': None}

    credentials = options.get('allowCredentials') or []
    for c in credentials:
        if isinstance(c.get('id'), str):
            c['id'] = utils.base64_url_decode(c['id'])

    challenge = options['challenge']
    if isinstance(challenge, str):
        options['challenge'] = utils.base64_url_decode(challenge)

    client = None   # type: Optional[WebAuthnClient]
    data_collector = DefaultClientDataCollector(origin, verify=verify_rp_id_none)
    if os.name == 'nt':
        from fido2.client.windows import WindowsClient
        client = WindowsClient(client_data_collector=data_collector)
    else:
        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            logging.warning("No Security Key detected")
            return

        from fido2.client import Fido2Client
        fido_client = Fido2Client(dev, client_data_collector=data_collector, user_interaction=CliInteraction())

        uv_configured = any(fido_client.info.options.get(k) for k in ("uv", "clientPin", "bioEnroll"))
        if not uv_configured:
            uv = options['userVerification']
            if uv == UserVerificationRequirement.PREFERRED:
                options['userVerification'] = UserVerificationRequirement.DISCOURAGED
        client = fido_client

    if client is None:
        return

    evt = threading.Event()
    try:
        try:
            rq_options = PublicKeyCredentialRequestOptions.from_dict(options)  # type: PublicKeyCredentialRequestOptions
            rs = client.get_assertion(rq_options, event=evt)
            return rs.get_response(0)
        except ClientError as err:
            if isinstance(err.cause, CtapError):
                if err.cause.code == CtapError.ERR.NO_CREDENTIALS:
                    print('\n\nKeeper Security stopped supporting U2F security keys starting February 2022.\n'
                          'If you registered your security key prior to this date please re-register it within the Web Vault.\n'
                          'For information on using security keys with Keeper see the documentation: \n'
                          'https://docs.keeper.io/enterprise-guide/two-factor-authentication#security-keys-fido-webauthn\n'
                          'Commander will use the fallback security key authentication method.\n\n'
                          'To use your Yubikey with Commander, please touch the flashing Security key one more time.\n')
                    options['rpId'] = origin
                    rq_options = PublicKeyCredentialRequestOptions.from_dict(options)
                    rs = client.get_assertion(rq_options, event=evt)
                    return rs.get_response(0)
                elif err.cause.code == CtapError.ERR.PIN_INVALID:
                    raise Exception('PIN is invalid')
                elif err.cause.code == CtapError.ERR.PIN_AUTH_BLOCKED:
                    raise Exception('PIN is blocked')
            elif isinstance(err.cause, str):
                if err.code == ClientError.ERR.CONFIGURATION_UNSUPPORTED:
                    raise Exception('Security key user verification (PIN or Biometric) is not configured')
            raise err

    except KeyboardInterrupt:
        return
    except Exception as e:
        raise e
    finally:
        evt.set()
