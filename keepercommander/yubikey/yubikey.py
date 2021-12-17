#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Copyright 2019 Keeper Security Inc.
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


"""
u2f_response = None
should_cancel_u2f = False

if os.name == 'nt':
    import msvcrt
    win_cancel_getch = False

def get_input_interrupted(prompt):
    # TODO: refactor to use interruptable prompt from prompt_toolkit in api.py:193 (login: process 2fa error codes).
    #  This method to be removed.
    if os.name == 'nt':
        global win_cancel_getch

        print(prompt)
        win_cancel_getch = False
        result = b''
        while not win_cancel_getch:
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch in [b'\r', b'\n']:
                    break
                result += ch
            else:
                time.sleep(0.1)
        if win_cancel_getch:
            raise KeyboardInterrupt()
        return result.decode()
    else:
        return getpass.getpass(prompt=prompt)


def u2f_authenticate(authenticateRequests):
    # type: ([dict]) -> dict or None

    global should_cancel_u2f
    global u2f_response

    if not authenticateRequests:
        return None

    devices = list(CtapHidDevice.list_devices())
    if not devices:
        logging.warning("No U2F Devices detected")
        return None

    to_auth = []
    for i in range(len(devices)):
        u2f_client = CTAP1(devices[i])
        u2f_version = u2f_client.get_version()
        for request in authenticateRequests:
            try:
                version = request['version']
                if version == u2f_version:
                    app_id = request['appId']
                    challenge = request['challenge']
                    key_handle = base64.urlsafe_b64decode(request['keyHandle'] + '==')
                    app_id_hash = sha256(app_id.encode('ascii')).digest()
                    cl_data = {
                        'typ': U2F_TYPE.SIGN,
                        'challenge': challenge,
                        'origin': app_id
                    }
                    client_data = json.dumps(cl_data)
                    try:
                        client_param = sha256(client_data.encode('utf8')).digest()
                        u2f_client.authenticate(client_param, app_id_hash, key_handle, check_only=True)
                    except ApduError as e:
                        if e.code == APDU.USE_NOT_SATISFIED:
                            to_auth.append((u2f_client, client_data, app_id_hash, key_handle))
            except:
                pass

    if to_auth:
        u2f_thread = threading.Thread(target=thread_function, args=((to_auth,)))
        u2f_thread.start()
        try:
            get_input_interrupted(bcolors.WARNING + '\nTouch the flashing U2F device to authenticate or press Enter to resume with the primary two factor authentication...\n' + bcolors.ENDC)
            should_cancel_u2f = True
            u2f_thread.join()
        except KeyboardInterrupt:
            pass
    return u2f_response


def thread_function(auth_requests):
    # type: ([(CTAP1, str, bytes, bytes)]) -> None
    global should_cancel_u2f
    global u2f_response

    should_cancel_u2f = False
    u2f_response = None

    while len(auth_requests) > 0 and not u2f_response and not should_cancel_u2f:
        for i in range(len(auth_requests)):
            try:
                u2f_client, client_data, app_id_hash, key_handle = auth_requests[i]
                client_param = sha256(client_data.encode('utf8')).digest()
                signature = u2f_client.authenticate(client_param, app_id_hash, key_handle, check_only=False)
                u2f_response = {
                    'clientData': base64.urlsafe_b64encode(client_data.encode('utf8')).decode().rstrip('='),
                    'signatureData': signature.b64,
                    'keyHandle': base64.urlsafe_b64encode(key_handle).decode().rstrip('=')
                }
                continue
            except ApduError as e:
                if e.code == APDU.USE_NOT_SATISFIED:
                    continue
            except:
                pass
            auth_requests[i] = None
        auth_requests = [x for x in auth_requests if x]
        if len(auth_requests) == 0:
            continue
        time.sleep(0.25)

    if u2f_response:
        logging.info('OK')
    if os.name == 'nt':
        global win_cancel_getch
        win_cancel_getch = True
    else:
        os.kill(os.getpid(), signal.SIGINT)
"""
