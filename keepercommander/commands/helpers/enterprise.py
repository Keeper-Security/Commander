import logging
import re
from ... import utils, crypto
from ...params import KeeperParams


MAX_ENTERPRISE_NAME_LENGTH = 255
_NAME_PREVIEW_LENGTH = 40

# Backend length-violation responses look like: ``max=185, length=255, value=<bad>``
_BACKEND_LENGTH_ERROR_RE = re.compile(
    r'max\s*=\s*(\d+)\s*,\s*length\s*=\s*(\d+)(?:\s*,\s*value\s*=.*)?',
    re.IGNORECASE | re.DOTALL,
)


def is_valid_name_length(name, field_label, command_label):
    """Return True if name fits within the enterprise name length limit; otherwise warn and return False."""
    if name is None:
        return True
    name = str(name)
    if len(name) <= MAX_ENTERPRISE_NAME_LENGTH:
        return True
    preview = name[:_NAME_PREVIEW_LENGTH]
    if len(name) > _NAME_PREVIEW_LENGTH:
        preview += '...'
    logging.warning(
        '%s: %s \'%s\' is %d characters long. Maximum allowed is %d. Skipping.',
        command_label, field_label, preview, len(name), MAX_ENTERPRISE_NAME_LENGTH,
    )
    return False


def simplify_backend_message(message):
    """Rewrite the backend's ``max=N, length=N, value=...`` length error into a friendlier sentence."""
    if not message or not isinstance(message, str):
        return message
    match = _BACKEND_LENGTH_ERROR_RE.search(message)
    if not match:
        return message
    actual_len = int(match.group(2))
    max_len = int(match.group(1))
    return 'value is {0} characters but the maximum allowed is {1}'.format(actual_len, max_len)


def simplify_batch_responses(responses):
    """Rewrite known noisy server validation messages in place on each response dict."""
    if not responses:
        return
    for rs in responses:
        if isinstance(rs, dict) and rs.get('message'):
            rs['message'] = simplify_backend_message(rs['message'])


def is_addon_enabled(params, addon_name):    # type: (KeeperParams, Dict[str, ]) -> Boolean
    def is_enabled(addon):
        return addon.get('enabled') or addon.get('included_in_product')

    enterprise = params.enterprise or {}
    licenses = enterprise.get('licenses')
    if not isinstance(licenses, list):
        return False
    if next(iter(licenses), {}).get('lic_status') == 'business_trial':
        return True
    addons = [a for l in licenses for a in l.get('add_ons', []) if a.get('name') == addon_name]
    return any(a for a in addons if is_enabled(a))


def user_has_privilege(params, privilege):  # type: (KeeperParams, str) -> bool
    # Running as MSP admin, user has all available privileges in this context
    if params.msp_tree_key:
        return True

    enterprise = params.enterprise

    # Not an admin account (user has no admin privileges)
    if not enterprise:
        return False

    # Check role-derived privileges
    username = params.user
    users = enterprise.get('users')
    e_user_id = next(iter([u.get('enterprise_user_id') for u in users if u.get('username') == username]))
    role_users = enterprise.get('role_users')
    r_ids = [ru.get('role_id') for ru in role_users if ru.get('enterprise_user_id') == e_user_id]
    r_privileges = enterprise.get('role_privileges')
    p_key = 'privilege'
    return any(rp for rp in r_privileges if rp.get('role_id') in r_ids and rp.get(p_key) == privilege)

def get_enterprise_key(params, is_rsa=False):
    keys = params.enterprise.get('keys', {})
    try:
        pk_data = utils.base64_url_decode(keys.get(f'{is_rsa and "rsa" or "ecc"}_encrypted_private_key'))
        pk_data = crypto.decrypt_aes_v2(pk_data, params.enterprise['unencrypted_tree_key'])
        return is_rsa and crypto.load_rsa_private_key(pk_data) or crypto.load_ec_private_key(pk_data)
    except Exception as e:
        logging.debug(e)

def try_enterprise_decrypt(params, data):
    dec_params = [
        [crypto.decrypt_ec, get_enterprise_key(params, is_rsa=False)],
        [crypto.decrypt_rsa, get_enterprise_key(params, is_rsa=True)]
    ]
    while dec_params:
        decrypt_fn, pk = dec_params.pop()
        try:
            decrypted = decrypt_fn(data, pk)
            return decrypted
        except:
            continue
