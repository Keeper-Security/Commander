# coding: utf-8
import hashlib
import json
import logging
import requests
from base64 import b64decode
from binascii import hexlify
from xml.etree import ElementTree as etree
from . import blob
from .version import __version__
from .exceptions import (
    NetworkError,
    InvalidResponseError,
    UnknownResponseSchemaError,
    LastPassUnknownUsernameError,
    LastPassInvalidPasswordError,
    LastPassIncorrectGoogleAuthenticatorCodeError,
    LastPassIncorrectYubikeyPasswordError,
    LastPassUnknownError
)
from .session import Session


http = requests
headers = {'user-agent': 'lastpass-python/{}'.format(__version__)}
https_host = 'https://lastpass.com'
query_string = 'mobile=1&requestsrc=cli&hasplugin=3.0.23'


def login(username, password, multifactor_password=None, client_id=None, **kwargs):
    key_iteration_count = request_iteration_count(username, **kwargs)
    return request_login(username, password, key_iteration_count, multifactor_password, client_id, **kwargs)


def logout(session, web_client=http, **kwargs):
    # type: (Session, requests, ...) -> None
    response = web_client.get('https://lastpass.com/logout.php?mobile=1', cookies={'PHPSESSID': session.id},
                              proxies=kwargs.get('proxies'), verify=kwargs.get('certificate_check'))

    if response.status_code != requests.codes.ok:
        raise NetworkError()


def fetch(session, web_client=http, **kwargs):
    url = f'{https_host}/getaccts.php?{query_string}'
    response = web_client.get(url, cookies={'PHPSESSID': session.id},
                              proxies=kwargs.get('proxies'), verify=kwargs.get('certificate_check'))

    if response.status_code != requests.codes.ok:
        try:
            message = response.text
            raise NetworkError(f'{response.reason}: {message}')
        except:
            raise NetworkError(response.reason)

    return blob.Blob(response.content, session.key_iteration_count)


def stream_attachment(session, attach_info, web_client=http, **kwargs):
    url = f'{https_host}/getattach.php'
    data = {'getattach': attach_info.storagekey}
    shared_folder = attach_info.parent.shared_folder
    if shared_folder:
        data['sharedfolderid'] = shared_folder.id
    response = web_client.post(url, data=data, cookies={'PHPSESSID': session.id}, stream=True,
                               proxies=kwargs.get('proxies'), verify=kwargs.get('certificate_check'))

    if response.status_code != requests.codes.ok:
        shared_folder_msg = '' if shared_folder is None else f' in shared folder {shared_folder.name}'
        record_name = attach_info.parent.name.decode('utf-8')
        logging.warning(
            f'''Attachment {attach_info.name} in record {record_name}{shared_folder_msg} failed to download:
            HTTP {response.status_code}, {response.reason}'''
        )
        return None

    return response


def fetch_shared_folder_members(session, shareid, web_client=http, **kwargs):
    url = f'{https_host}/getSharedFolderMembers.php?{query_string}&shareid={shareid}'
    response = web_client.get(url, cookies={'PHPSESSID': session.id},
                              proxies=kwargs.get('proxies'), verify=kwargs.get('certificate_check'))

    if response.status_code != requests.codes.ok:
        error = f'HTTP {response.status_code}, {response.reason}'
        return [], [], error

    response_dict = json.loads(response.content.decode('utf-8'))
    if 'users' in response_dict:
        shared_folder_members = response_dict['users']
        error = None
    elif 'error' in response_dict:
        shared_folder_members = []
        error = response_dict['error']
        if error == 'not_allowed':
            error += ' (Lastpass folder admin access required to access folder members)'
    else:
        shared_folder_members = []
        error = 'Unknown response from Lastpass'
    return shared_folder_members, response_dict.get('groups', []), error


def request_iteration_count(username, web_client=http, **kwargs):
    response = web_client.get('https://lastpass.com/iterations.php', params={'email': username}, headers=headers,
                              proxies=kwargs.get('proxies'), verify=kwargs.get('certificate_check'))
    if response.status_code != requests.codes.ok:
        raise NetworkError()

    try:
        count = int(response.content)
    except:
        count = 100100
        logging.debug('Assume default iterations')

    if count > 0:
        return count
    raise InvalidResponseError('Key iteration count is not positive')


def request_login(username, password, key_iteration_count, multifactor_password=None, client_id=None,
                  web_client=http, **kwargs):
    body = {
        'method': 'mobile',
        'web': 1,
        'xml': 1,
        'username': username,
        'hash': make_hash(username, password, key_iteration_count),
        'iterations': key_iteration_count,
    }

    if multifactor_password:
        body['otp'] = multifactor_password

    if client_id:
        body['imei'] = client_id

    response = web_client.post('https://lastpass.com/login.php', data=body, headers=headers,
                               proxies=kwargs.get('proxies'), verify=kwargs.get('certificate_check'))

    if response.status_code != requests.codes.ok:
        raise NetworkError()

    try:
        parsed_response = etree.fromstring(response.content)
    except etree.ParseError:
        parsed_response = None

    if parsed_response is None:
        raise InvalidResponseError()

    if parsed_response.tag == 'response':
        error = parsed_response.find('error')
        if isinstance(error.attrib, dict) and 'iterations' in error.attrib:
            iterations = error.attrib['iterations']
            try:
                key_iteration_count = int(iterations)
                body['iterations'] = key_iteration_count
                body['hash'] = make_hash(username, password, key_iteration_count),

                response = web_client.post(
                    'https://lastpass.com/login.php', data=body, headers=headers)
                parsed_response = etree.fromstring(response.content)
                if parsed_response is None:
                    raise InvalidResponseError()
            except ValueError:
                pass

    session = create_session(parsed_response, key_iteration_count)
    if not session:
        raise login_error(parsed_response)
    return session


def create_session(parsed_response, key_iteration_count):
    if parsed_response.tag == 'ok':
        session_id = parsed_response.attrib.get('sessionid')
        if isinstance(session_id, str):
            return Session(session_id, key_iteration_count)


def login_error(parsed_response):
    error = None if parsed_response.tag != 'response' else parsed_response.find('error')
    if error is None or len(error.attrib) == 0:
        raise UnknownResponseSchemaError()

    exceptions = {
        "unknownemail": LastPassUnknownUsernameError,
        "unknownpassword": LastPassInvalidPasswordError,
        "googleauthrequired": LastPassIncorrectGoogleAuthenticatorCodeError,
        "googleauthfailed": LastPassIncorrectGoogleAuthenticatorCodeError,
        "yubikeyrestricted": LastPassIncorrectYubikeyPasswordError,
    }

    cause = error.attrib.get('cause')
    message = error.attrib.get('message')

    if cause:
        return exceptions.get(cause, LastPassUnknownError)(message or cause)
    return InvalidResponseError(message)


def decode_blob(blob):
    return b64decode(blob)


def make_key(username, password, key_iteration_count):
    # type: (str, str, int) -> bytes
    if key_iteration_count == 1:
        return hashlib.sha256(username.encode('utf-8') + password.encode('utf-8')).digest()
    else:
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), username.encode('utf-8'), key_iteration_count, 32)


def make_hash(username, password, key_iteration_count):
    # type: (str, str, int) -> bytes
    if key_iteration_count == 1:
        return bytearray(hashlib.sha256(hexlify(make_key(username, password, 1)) + password.encode('utf-8')).hexdigest(), 'ascii')
    else:
        return hexlify(hashlib.pbkdf2_hmac(
            'sha256',
            make_key(username, password, key_iteration_count),
            password.encode('utf-8'),
            1,
            32
        ))
