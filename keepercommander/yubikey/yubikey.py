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

import logging
import os
import threading
import time
from typing import Optional, Callable, Union

from fido2.client import Fido2Client, WindowsClient, ClientError
from fido2.ctap import CtapError
from fido2.hid import CtapHidDevice
from fido2.webauthn import PublicKeyCredentialRequestOptions, AuthenticatorAssertionResponse
from prompt_toolkit import PromptSession

from .. import utils


def verify_rp_id_none(rp_id, origin):
    return True


def yubikey_authenticate(request):  # type: (dict) -> Optional[dict]
    auth_func = None    # type: Optional[Callable[[], Union[AuthenticatorAssertionResponse, dict, None]]]
    evt = threading.Event()
    response = None  # type: Optional[str]

    if 'publicKeyCredentialRequestOptions' in request:  # WebAuthN
        origin = ''
        options = request['publicKeyCredentialRequestOptions']
        if 'extensions' in options:
            extensions = options['extensions']
            origin = extensions.get('appid') or ''

        credentials = options.get('allowCredentials') or []
        for c in credentials:
            if isinstance(c.get('id'), str):
                c['id'] = utils.base64_url_decode(c['id'])

        rq_options = PublicKeyCredentialRequestOptions(utils.base64_url_decode(options['challenge']),
                                                       rp_id=options['rpId'], user_verification='discouraged',
                                                       allow_credentials=credentials)

        if WindowsClient.is_available():
            client = WindowsClient(origin, verify=verify_rp_id_none)
        else:
            dev = next(CtapHidDevice.list_devices(), None)
            if not dev:
                logging.warning("No Security Key detected")
                return
            client = Fido2Client(dev, origin, verify=verify_rp_id_none)

        def auth_func():
            nonlocal response
            nonlocal rq_options
            attempt = 0
            while attempt < 2:
                attempt += 1
                try:
                    rs = client.get_assertion(rq_options, event=evt)
                    response = rs.get_response(0)
                    break
                except ClientError as err:
                    if isinstance(err.cause, CtapError) and attempt == 1:
                        if err.cause.code == CtapError.ERR.NO_CREDENTIALS:
                            print('\n\nKeeper Security stopped supporting U2F security keys starting February 2022.\n'
                                  'If you registered your security key prior to this date please re-register it within the Web Vault.\n'
                                  'For information on using security keys with Keeper see the documentation: \n'
                                  'https://docs.keeper.io/enterprise-guide/two-factor-authentication#security-keys-fido-webauthn\n'
                                  'Commander will use the fallback security key authentication method.\n\n'
                                  'To use your Yubikey with Commander, please touch the flashing Security key one more time.\n')
                            rq_options = PublicKeyCredentialRequestOptions(
                                utils.base64_url_decode(options['challenge']), rp_id=origin, user_verification='discouraged',
                                allow_credentials=credentials)
                            continue
                    raise err
    else:
        logging.warning('Invalid Security Key request')
        return

    prompt_session = None

    def func():
        nonlocal prompt_session
        nonlocal evt
        try:
            time.sleep(0.1)
            auth_func()
        except:
            pass
        if prompt_session:
            evt = None
            prompt_session.app.exit()
        elif evt:
            print('\npress Enter to resume...')

    th = threading.Thread(target=func)
    th.start()
    try:
        prompt = 'Touch the flashing Security key to authenticate or press Enter to resume with the primary two factor authentication...'
        if os.isatty(0) and os.isatty(1):
            prompt_session = PromptSession(multiline=False, complete_while_typing=False)
            prompt_session.prompt(prompt)
            prompt_session = None
        else:
            input(prompt)
    except KeyboardInterrupt:
        prompt_session = None
    if evt:
        evt.set()
        evt = None
    th.join()

    return response
