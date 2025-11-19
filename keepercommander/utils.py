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

import base64
import json
import logging
import math
import os
import platform
import re
import stat
import subprocess
import time
from typing import Dict, Union
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path
import sys

from . import crypto
from .constants import EMAIL_PATTERN


VALID_URL_SCHEME_CHARS = '+-.:'

def get_logger():
    return logging.getLogger('keeper')

def get_default_path(override_path=None):
    """
    Get the default path for Commander's data directory.
    
    Precedence order (highest to lowest):
    1. override_path parameter (e.g., from CLI --data-dir) - auto-appends .keeper if needed
    2. KEEPER_DATA_HOME environment variable - auto-appends .keeper if needed
    3. XDG_DATA_HOME/.keeper (XDG Base Directory Specification)
    4. HOME/.keeper (legacy default)
    
    Args:
        override_path (str, optional): Override path, typically from CLI argument
        
    Returns:
        Path: The path to use for Commander's data directory
    """
    import os
    
    def ensure_keeper_suffix(path_str):
        """Helper to ensure path ends with .keeper suffix"""
        expanded_path = Path(os.path.expanduser(path_str))
        if expanded_path.name == '.keeper':
            return expanded_path
        else:
            return expanded_path.joinpath('.keeper')
    
    if override_path:
        default_path = ensure_keeper_suffix(override_path)
    else:
        keeper_data_home = os.getenv('KEEPER_DATA_HOME')
        if keeper_data_home:
            default_path = ensure_keeper_suffix(keeper_data_home)
        else:
            xdg_data_home = os.getenv('XDG_DATA_HOME')
            if xdg_data_home:
                default_path = Path(xdg_data_home).joinpath('.keeper')
            else:
                default_path = Path.home().joinpath('.keeper')
    
    default_path.mkdir(parents=True, exist_ok=True)
    return default_path


def generate_uid():             # type: () -> str
    b = crypto.get_random_bytes(16)
    if (b[0] & 0xf8) == 0xf8:
        b = bytes([b[0] & 0x7f]) + b[1:]
    return base64_url_encode(b)


def generate_aes_key():         # type: () -> bytes
    return crypto.get_random_bytes(32)


def set_file_permissions(file_path):     # type: (str) -> None
    """
    Set secure file permissions (600) for configuration files containing sensitive data.
    This ensures only the owner can read and write the file.
    """
    file_path = os.path.abspath(file_path)
    
    try:
        if os.path.islink(file_path):
            logging.warning(f'Skipping permission setting on symbolic link: {file_path}')
            return
        
        if platform.system() != 'Windows':
            file_stat = os.stat(file_path)
            if file_stat.st_uid != os.getuid():
                logging.warning(f'Skipping permission setting on file not owned by current user: {file_path}')
                return
            
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
            logging.debug(f'Set secure permissions (600) for file: {file_path}')
        else:
            username = os.getlogin()
            subprocess.run(["icacls", file_path, "/inheritance:r"], check=True, capture_output=True)
            subprocess.run(["icacls", file_path, "/remove", "NT AUTHORITY\\SYSTEM", "BUILTIN\\Administrators"], check=False, capture_output=True)
            subprocess.run(["icacls", file_path, "/grant", f"{username}:RW"], check=True, capture_output=True)
            logging.debug(f'Set secure permissions (owner RW only) for Windows file: {file_path}')
    except Exception:
        logging.warning(f'Failed to set file permissions for {file_path}')


def ensure_config_permissions(file_path):     # type: (str) -> None
    """
    Check and fix file permissions for existing configuration files.
    If the file has overly permissive permissions, log a warning and fix them.
    """
    file_path = os.path.abspath(file_path)
    
    if not os.path.exists(file_path):
        return
    
    try:
        if os.path.islink(file_path):
            logging.warning(f'Skipping permission check on symbolic link: {file_path}')
            return
        
        if platform.system() != 'Windows':
            file_stat = os.stat(file_path)
            if file_stat.st_uid != os.getuid():
                logging.warning(f'Skipping permission check on file not owned by current user: {file_path} (owner: {file_stat.st_uid}, current: {os.getuid()})')
                return
            
            current_permissions = file_stat.st_mode & 0o777
            if current_permissions != 0o600:
                logging.warning(f'Configuration file {file_path} has insecure permissions '
                              f'{oct(current_permissions)}. Setting to secure permissions (600).')
                set_file_permissions(file_path)
        else:
            logging.debug(f'Checking Windows file permissions for: {file_path}')
            set_file_permissions(file_path)
            
    except OSError:
        logging.warning(f'Failed to check file permissions for {file_path}')


def current_milli_time():       # type: () -> int
    return int(round(time.time() * 1000))


def base64_url_decode(s):       # type: (str) -> bytes
    return base64.urlsafe_b64decode(s + '==')


def base64_url_encode(b):       # type: (bytes) -> str
    bs = base64.urlsafe_b64encode(b)
    return bs.rstrip(b'=').decode('ascii')


def string_to_bytes(string):
    return string.encode('utf-8')


def json_to_base64(json_str):
    json_bytes = string_to_bytes(json_str)
    json_b64 = base64.b64encode(json_bytes).decode()
    return json_b64


def decrypt_encryption_params(encryption_params, password):     # type: (bytes, str) -> bytes

    if len(encryption_params) != 100:
        raise Exception('Invalid encryption params: bad params length')

    _ = int.from_bytes(encryption_params[0:1], byteorder='big', signed=False)
    iterations = int.from_bytes(encryption_params[1:4], byteorder='big', signed=False)
    salt = encryption_params[4:20]
    encrypted_data_key = encryption_params[20:]

    key = crypto.derive_key_v1(password, salt, iterations)
    decrypted_data_key = crypto.decrypt_aes_v1(encrypted_data_key, key, use_padding=False)

    # validate the key is formatted correctly
    if len(decrypted_data_key) != 64:
        raise Exception('Invalid data key length')

    if decrypted_data_key[:32] != decrypted_data_key[32:]:
        raise Exception('Invalid data key: failed mirror verification')

    return decrypted_data_key[:32]


def create_encryption_params(password, salt, iterations, data_key):  # type: (str, bytes, int, bytes) -> bytes

    key = crypto.derive_key_v1(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    enc_iv = crypto.get_random_bytes(16)
    enc_data_key = crypto.encrypt_aes_v1(data_key * 2, key, iv=enc_iv, use_padding=False)
    return b'\x01' + enc_iter + salt + enc_data_key


def create_auth_verifier(password, salt, iterations):   # type: (str, bytes, int) -> bytes

    derived_key = crypto.derive_key_v1(password, salt, iterations)
    enc_iter = int.to_bytes(iterations, length=3, byteorder='big', signed=False)
    return b'\x01' + enc_iter + salt + derived_key


def is_url(test_str):   # type: (str) -> bool
    if not isinstance(test_str, str):
        return False
    url_parts = test_str.split('://')
    url_scheme = url_parts[0]
    valid_scheme = all(c.isalnum or c in VALID_URL_SCHEME_CHARS for c in url_scheme)
    if len(test_str.split()) == 1 and len(url_parts) > 1 and valid_scheme:
        return True
    else:
        return False


email_pattern = re.compile(EMAIL_PATTERN)


def is_email(test_str):
    return email_pattern.match(test_str) is not None


def is_json(txt):
    try:
        json.loads(txt)
    except ValueError as e:
        return False
    return True

def url_strip(url):   # type: (str) -> str
    if not url:
        return ''
    try:
        result = urlparse(url)
        return result.netloc + result.path
    except Exception:
        return ''


_breach_watch_key = base64_url_decode('phl9kdMA_gkJkSfeOYWpX-FOyvfh-APhdSFecIDMyfI')


def breach_watch_hash(password):  # type: (str) -> bytes
    return crypto.hmac_sha512(_breach_watch_key, f'password:{password}'.encode('utf-8'))


def chunk_text(text, func):  # type (str, Callable[[str], bool]) -> Iterable[str]
    acc = ''
    for x in text:
        if func(x):
            acc += x
        else:
            if acc:
                yield acc
                acc = ''
    if acc:
        yield acc


def offset_char(text, func):  # type (str, Callable[[str, str], int]) -> Iterable[int]
    if not text:
        return
    prev = text[0]
    for ch in text[1:]:
        yield func(prev, ch)
        prev = ch


def password_score(password):  # type: (str) -> int
    score = 0
    if not password:
        return score
    if not isinstance(password, str):
        return score

    total = len(password)
    uppers = 0
    lowers = 0
    digits = 0
    symbols = 0
    for x in password:
        if x.isupper():
            uppers += 1
        elif x.islower():
            lowers += 1
        elif x.isdecimal():
            digits += 1
        else:
            symbols += 1

    ds = digits + symbols
    if not password[0].isalpha():
        ds -= 1
    if not password[-1].isalpha():
        ds -= 1
    if ds < 0:
        ds = 0

    score += total * 4
    if uppers > 0:
        score += (total-uppers) * 2
    if lowers > 0:
        score += (total-lowers) * 2
    if digits > 0:
        score += digits * 4
    score += symbols * 6
    score += ds * 2

    variance = 0
    if uppers > 0:
        variance += 1
    if lowers > 0:
        variance += 1
    if digits > 0:
        variance += 1
    if symbols > 0:
        variance += 1
    if total >= 8 and variance >= 3:
        score += (variance + 1) * 2

    if digits + symbols == 0:
        score -= total

    if uppers + lowers + symbols == 0:
        score -= total

    rep_inc = 0
    pwd_len = len(password)
    rep_count = 0
    for i in range(pwd_len):
        char_exists = False
        for j in range(pwd_len):
            if i != j and password[i] == password[j]:
                char_exists = True
                rep_inc += pwd_len / abs(i - j)
        if char_exists:
            rep_count += 1
            unq_count = pwd_len - rep_count
            rep_inc = math.ceil(rep_inc if unq_count == 0 else rep_inc / unq_count)

    if rep_count > 0:
        score -= rep_inc

    count = 0
    for consec in [str.isupper, str.islower, str.isdecimal]:
        for chunk in chunk_text(password, consec):
            length = len(chunk)
            if length >= 2:
                count += length - 1
    if count > 0:
        score -= 2 * count

    count = 0
    for cnt, seq in [(26, str.isalpha), (10, str.isdecimal)]:
        cnt = 0
        for chunk in chunk_text(password.lower(), seq):
            if len(chunk) >= 3:
                offsets = [x if x >= 0 else x + cnt for x in offset_char(chunk, lambda x, y: ord(x) - ord(y))]
                op = offsets[0]
                for oc in offsets[1:]:
                    if oc == op:
                        if op != 0:
                            count += 1
                    else:
                        op = oc

    symbols = {x[1]: x[0] for x in enumerate('!@#$%^&*()_+[]\\{}|;\':\",./<>?')}
    cnt = 0
    for chunk in chunk_text(password, symbols.__contains__):
        if len(chunk) >= 3:
            offsets = [x if x >= 0 else x + cnt for x in offset_char(chunk, lambda x, y: symbols[x] - symbols[y])]
            op = offsets[0]
            for oc in offsets[1:]:
                if oc == op:
                    if op != 0:
                        count += 1
                else:
                    op = oc

    if count > 0:
        score -= 3 * count

    return score if 0 <= score <= 100 else 0 if score < 0 else 100


def is_pw_weak(pw_score):           # type: (int) -> bool
    return pw_score < 40


def is_pw_fair(pw_score):           # type: (int) -> bool
    return 40 <= pw_score < 60


def is_pw_strong(pw_score):         # type: (int) -> bool
    return pw_score >= 80


def is_rec_at_risk(bw_result):      # type (int) -> bool
    return bw_result in (2, 3)


def passed_bw_check(bw_result):     # type (int) -> bool
    return bw_result in (0, 1)


def confirm(msg):
    """Simple confirmation through user input

    msg(str): Message expecting a yes or no answer
    Returns True if answer is "yes" and False otherwise.
    """
    question = f'{msg} (y/n) '
    answer = ''
    while answer not in ('y', 'n'):
        answer = input(question).lower()
    return answer == 'y'


def size_to_str(size):  # type: (int) -> str
    if not isinstance(size, int):
        return ''
    if size < 2000:
        return f'{size} b'
    size = size / 1024
    if size < 1000:
        return f'{size:.2f} Kb'
    size = size / 1024
    if size < 1000:
        return f'{size:.2f} Mb'
    size = size / 1024
    return f'{size:,.2f} Gb'

def parse_totp_uri(uri):    # type: (str) -> Dict[str, Union[str, int, None]]
    def parse_int(val):
        return val and int(val)

    def decode_uri_component(component):  # type: (str) -> str
        return unquote(component or '').strip()

    result = dict()

    if not uri:
        return result

    parsed = urlparse(uri)
    if parsed.scheme == 'otpauth':
        label = re.sub(r'^/+', '', parsed.path or '')
        parts = re.split(r':|%3A', label)
        parts = [part for part in parts if part]
        account_name = len(parts) and parts.pop()
        issuer = len(parts) and parts.pop()

        parsed = parse_qs(parsed.query)

        issuers = parsed.get('issuer')
        secrets = parsed.get('secret')
        algorithms = parsed.get('algorithm')
        digits_vals = parsed.get('digits')
        periods = parsed.get('period')
        result = {
            'issuer': decode_uri_component(issuers and next(iter(issuers)) or issuer),
            'account': decode_uri_component(account_name),
            'secret': secrets and next(iter(secrets)),
            'algorithm': algorithms and next(iter(algorithms)) or 'SHA1',
            'digits': parse_int(digits_vals and next(iter(digits_vals))) or 6,
            'period': parse_int(periods and next(iter(periods))) or 30
        }

    return result

def value_to_boolean(value):
    """
    Replacement for distutils.util.strtobool
    """
    value = str(value)
    if value.lower() in ['true', 'yes', 'on', '1']:
        return True
    elif value.lower() in ['false', 'no', 'off', '0']:
        return False
    else:
        return None

def get_ssl_cert_file():
    """Get SSL certificate file path, preferring system CA store for corporate environments like Zscaler"""
    import ssl
    import platform
    import certifi
    import os
    
    # Allow user to override via environment variable
    user_cert_file = os.getenv('KEEPER_SSL_CERT_FILE')
    if user_cert_file:
        if user_cert_file.lower() == 'system':
            pass  # Continue with system detection below
        elif user_cert_file.lower() == 'certifi':
            return certifi.where()
        elif user_cert_file.lower() == 'none' or user_cert_file.lower() == 'false':
            return False  # Disable SSL verification
        elif os.path.exists(user_cert_file):
            return user_cert_file
        else:
            # Don't use logging here as it can interfere with main logging config
            print(f"Warning: SSL cert file specified in KEEPER_SSL_CERT_FILE not found: {user_cert_file}", file=sys.stderr)
    
    # Try to use system CA store first for corporate environments
    try:
        # On macOS, try Homebrew certificates first (better for corporate environments like Zscaler)
        if platform.system() == 'Darwin':
            system_ca_paths = [
                '/opt/homebrew/etc/ca-certificates/cert.pem',  # Homebrew CA bundle (best for Zscaler)
                '/usr/local/etc/ssl/cert.pem',  # Homebrew SSL (older location)
                '/etc/ssl/cert.pem',  # macOS system CA bundle
            ]
            for ca_path in system_ca_paths:
                if os.path.exists(ca_path):
                    return ca_path
        
        # On Linux/Unix systems
        elif platform.system() == 'Linux':
            system_ca_paths = [
                '/etc/ssl/certs/ca-certificates.crt',  # Debian/Ubuntu
                '/etc/pki/tls/certs/ca-bundle.crt',    # RHEL/CentOS
                '/etc/ssl/ca-bundle.pem',              # OpenSUSE
                '/etc/ssl/cert.pem',                   # Generic
            ]
            for ca_path in system_ca_paths:
                if os.path.exists(ca_path):
                    return ca_path
        
        # Try to get default SSL context locations
        try:
            default_locations = ssl.get_default_verify_paths()
            if default_locations.cafile and os.path.exists(default_locations.cafile):
                return default_locations.cafile
            if default_locations.capath and os.path.exists(default_locations.capath):
                return default_locations.capath
        except:
            pass
            
    except Exception:
        pass
    
    # Fall back to certifi if system CA not available
    return certifi.where()


def ssl_aware_request(method, url, **kwargs):
    """Make an SSL-aware HTTP request using system CA certificates when available"""
    import requests
    
    # Only set verify if not already specified
    if 'verify' not in kwargs:
        cert_file = get_ssl_cert_file()
        if cert_file is False:
            kwargs['verify'] = False
        elif cert_file:
            kwargs['verify'] = cert_file
        # If cert_file is None, let requests use its default
    
    return requests.request(method, url, **kwargs)


def ssl_aware_get(url, **kwargs):
    """SSL-aware GET request using system CA certificates when available"""
    return ssl_aware_request('GET', url, **kwargs)

def is_windows_11():
    if sys.platform != "win32":
        return False
    version = sys.getwindowsversion()
    return version.major >= 10 and version.build >= 22000