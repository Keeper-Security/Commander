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

from fido2.client import U2fClient, Fido2Client, WindowsClient
from fido2.hid import CtapHidDevice
from fido2.webauthn import PublicKeyCredentialRequestOptions, AuthenticatorAssertionResponse
from prompt_toolkit import PromptSession

from .. import utils


def yubikey_authenticate(request):  # type: (dict) -> Optional[dict]
    auth_func = None    # type: Optional[Callable[[], Union[AuthenticatorAssertionResponse, dict, None]]]
    evt = threading.Event()
    response = None  # type: Optional[str]

    if 'authenticateRequests' in request:    # U2F

        options = request['authenticateRequests']
        origin = options[0].get('appId') or ''
        challenge = options[0]['challenge']
        keys = [{
            'version': x.get('version') or '',
            'keyHandle': x['keyHandle']
        } for x in options if 'keyHandle' in x]

        dev = next(CtapHidDevice.list_devices(), None)
        if not dev:
            logging.warning("No Security Key detected")
            return
        client = U2fClient(dev, origin)

        def auth_func():
            nonlocal response
            response = client.sign(origin, challenge, keys, event=evt)

    elif 'publicKeyCredentialRequestOptions' in request:  # WebAuthN
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
            client = WindowsClient(origin)
        else:
            dev = next(CtapHidDevice.list_devices(), None)
            if not dev:
                logging.warning("No Security Key detected")
                return
            client = Fido2Client(dev, origin)

        def auth_func():
            nonlocal response
            rs = client.get_assertion(rq_options, event=evt)
            response = rs.get_response(0)
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
