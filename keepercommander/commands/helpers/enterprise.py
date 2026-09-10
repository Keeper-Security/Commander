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


KSM_CASCADE_REQUIRED = 'KSM_CASCADE_REQUIRED'
# Server commands that remove a user's team-based access and can therefore lock or delete the user's
# Keeper Secrets Manager devices.
KSM_CASCADE_COMMANDS = {'team_delete', 'team_enterprise_user_remove', 'team_enterprise_user_update'}


def _is_ksm_cascade_refusal(rq, rs):
    return (isinstance(rs, dict) and rq.get('command') in KSM_CASCADE_COMMANDS
            and rs.get('result') != 'success' and rs.get('result_code') == 'access_denied'
            and rs.get('additional_info') == KSM_CASCADE_REQUIRED)


def execute_batch_confirming_ksm_cascade(params, request_batch, force=False):
    """Run an enterprise batch; confirm and retry requests the server refuses with KSM_CASCADE_REQUIRED.

    Removing a user from a team, deleting a team, or hiding shared folders from a team member can lock
    (or, if the user loses their last route to the application, delete) the user's Secrets Manager
    devices. The server refuses such a request unless `force_remove_share` is set. With `force` the
    flag is sent up front. Otherwise the user is asked once, and only the refused requests are retried
    with the flag. If the user declines, the refused responses get a message explaining how to confirm.
    """
    from ... import api
    from ..base import user_choice

    if force:
        for rq in request_batch:
            if rq.get('command') in KSM_CASCADE_COMMANDS:
                rq['force_remove_share'] = True

    rss = api.execute_batch(params, request_batch)
    if not rss:
        return rss

    refused = [i for i, (rq, rs) in enumerate(zip(request_batch, rss)) if _is_ksm_cascade_refusal(rq, rs)]
    if not refused:
        return rss

    prompt = (
        f'{len(refused)} change(s) remove access that Keeper Secrets Manager devices depend on. '
        'Affected devices will be locked (they can be unlocked later), or deleted if the user loses their '
        'last route to the application (this cannot be undone).\nProceed?')
    if user_choice(prompt, 'yn', 'n').lower() in ('y', 'yes'):
        for i in refused:
            request_batch[i]['force_remove_share'] = True
        retried = api.execute_batch(params, [request_batch[i] for i in refused])
        for i, rs in zip(refused, retried or []):
            rss[i] = rs
    else:
        for i in refused:
            rss[i]['message'] = ('Not done: it would lock or delete Keeper Secrets Manager devices. '
                                 'Re-run with --force-remove-share to confirm.')
    return rss


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
    username = (params.user or '').casefold()
    users = enterprise.get('users') or []
    e_user_id = next(
        (u.get('enterprise_user_id') for u in users
         if (u.get('username') or '').casefold() == username),
        None
    )
    if e_user_id is None:
        return False

    role_users = enterprise.get('role_users') or []
    r_ids = {
        ru.get('role_id') for ru in role_users
        if ru.get('enterprise_user_id') == e_user_id
    }
    if not r_ids:
        return False

    r_privileges = enterprise.get('role_privileges') or []
    return any(
        rp.get('role_id') in r_ids and rp.get('privilege') == privilege
        for rp in r_privileges
    )

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
