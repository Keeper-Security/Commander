import logging
from ... import utils, crypto
from ...params import KeeperParams


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
