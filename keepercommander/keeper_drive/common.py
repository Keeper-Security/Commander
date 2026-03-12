"""
KeeperDrive — shared utilities used across all API modules.

DRY: centralises every repeated lookup pattern so no other module
in this package ever needs to inline key/user/response logic.
"""

import logging
from typing import Optional, Dict, Any, Tuple

from .. import utils, crypto, api
from ..proto import folder_pb2, record_sharing_pb2
from ..error import KeeperApiError

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Key lookup helpers  (previously copy-pasted 9+ / 3+ times)
# ═══════════════════════════════════════════════════════════════════════════

def get_folder_key(params, folder_uid: str, raise_on_missing: bool = True) -> Optional[bytes]:
    """Retrieve the unencrypted folder key from keeper_drive_folders or subfolder_cache."""
    for cache in (getattr(params, 'keeper_drive_folders', {}),
                  getattr(params, 'subfolder_cache', {})):
        obj = cache.get(folder_uid)
        if obj and 'folder_key_unencrypted' in obj:
            return obj['folder_key_unencrypted']
    if raise_on_missing:
        raise ValueError(
            f"Folder key not found for folder {folder_uid}. "
            f"Try running 'sync-down' first.")
    return None


def get_record_key(params, record_uid: str, raise_on_missing: bool = True) -> Optional[bytes]:
    """Retrieve the unencrypted record key from keeper_drive_records or record_cache."""
    for cache in (getattr(params, 'keeper_drive_records', {}),
                  getattr(params, 'record_cache', {})):
        obj = cache.get(record_uid)
        if obj and 'record_key_unencrypted' in obj:
            return obj['record_key_unencrypted']
    if raise_on_missing:
        raise ValueError(
            f"Record key not found for record {record_uid}. "
            f"Record may not exist or is not accessible.")
    return None


def get_record_from_cache(params, record_uid: str) -> Optional[dict]:
    """Get a record dict from keeper_drive_records or record_cache."""
    for attr in ('keeper_drive_records', 'record_cache'):
        cache = getattr(params, attr, {})
        if record_uid in cache:
            return cache[record_uid]
    return None


def get_record_key_type(params, record_uid: str) -> Optional[int]:
    """Return the record key type if available (legacy AES-CBC vs AES-GCM)."""
    meta = getattr(params, 'meta_data_cache', {}).get(record_uid)
    if meta and 'record_key_type' in meta:
        return meta['record_key_type']
    return None


def encrypt_record_key_for_folder(
    record_key: bytes,
    encryption_key: bytes,
    record_key_type: Optional[int]
) -> Tuple[bytes, int]:
    """Encrypt record_key with encryption_key; returns (ciphertext, key_type)."""
    if record_key_type == folder_pb2.encrypted_by_data_key:
        return crypto.encrypt_aes_v1(record_key, encryption_key), folder_pb2.encrypted_by_data_key
    if record_key_type == folder_pb2.encrypted_by_data_key_gcm:
        return crypto.encrypt_aes_v2(record_key, encryption_key), folder_pb2.encrypted_by_data_key_gcm
    return crypto.encrypt_aes_v2(record_key, encryption_key), folder_pb2.encrypted_by_data_key_gcm


# ═══════════════════════════════════════════════════════════════════════════
# Asymmetric encryption helper  (previously inlined 5+ times)
# ═══════════════════════════════════════════════════════════════════════════

def encrypt_for_recipient(plaintext_key: bytes, public_key, use_ecc: bool) -> bytes:
    """Encrypt *plaintext_key* with the recipient's public key."""
    if use_ecc:
        return crypto.encrypt_ec(plaintext_key, public_key)
    return crypto.encrypt_rsa(plaintext_key, public_key)


# ═══════════════════════════════════════════════════════════════════════════
# User resolution  (previously copy-pasted 4+ times)
# ═══════════════════════════════════════════════════════════════════════════

def resolve_user_uid_bytes(params, user_identifier: str) -> Optional[bytes]:
    """Resolve an email or base64-url UID to raw UID bytes.

    Lookup order: user_cache → enterprise users → base64 decode.
    Returns None when the identifier cannot be resolved.
    """
    is_email = '@' in user_identifier

    if is_email:
        lower = user_identifier.lower()
        if hasattr(params, 'user_cache'):
            for uid_str, username in params.user_cache.items():
                if username.lower() == lower:
                    return utils.base64_url_decode(uid_str)
        if hasattr(params, 'enterprise') and params.enterprise:
            for user in params.enterprise.get('users', []):
                if user.get('username', '').lower() == lower:
                    if user.get('user_account_uid'):
                        return utils.base64_url_decode(user['user_account_uid'])
                    break
        return None

    try:
        return utils.base64_url_decode(user_identifier)
    except Exception:
        return None


def resolve_uid_email(params, user_identifier: str) -> Tuple[Optional[bytes], str]:
    """Resolve user identifier and return (uid_bytes, email_str).

    If *user_identifier* is a UID, tries to find its email.
    """
    uid_bytes = resolve_user_uid_bytes(params, user_identifier)
    is_email = '@' in user_identifier

    if is_email:
        return uid_bytes, user_identifier

    email = user_identifier
    if uid_bytes and hasattr(params, 'user_cache'):
        for uid_str, username in params.user_cache.items():
            if utils.base64_url_decode(uid_str) == uid_bytes:
                email = username
                break
    return uid_bytes, email


# ═══════════════════════════════════════════════════════════════════════════
# Public key resolution  (the 175-line function, kept as single source)
# ═══════════════════════════════════════════════════════════════════════════

def get_user_public_key(params, recipient_email, require_uid=True):
    """Get user's public key from cache / enterprise / API.

    Returns: (public_key_object, use_ecc, user_uid_bytes, needs_invite)
    """
    from ..proto import APIRequest_pb2
    from ..proto.record_pb2 import GetShareObjectsRequest, GetShareObjectsResponse
    from ..params import PublicKeys

    recipient_public_key = None
    use_ecc = False
    needs_invite = False
    recipient_uid_bytes = None

    def _load_pk(rsa_bytes, ec_bytes):
        nonlocal use_ecc
        if rsa_bytes:
            use_ecc = False
            return crypto.load_rsa_public_key(rsa_bytes)
        if ec_bytes:
            use_ecc = True
            return crypto.load_ec_public_key(ec_bytes)
        return None

    cache_key = recipient_email.lower()
    cached = params.key_cache.get(recipient_email) or params.key_cache.get(cache_key)
    if cached:
        recipient_public_key = _load_pk(cached.rsa, cached.ec)

    if not recipient_public_key and hasattr(params, 'enterprise') and params.enterprise:
        for user in params.enterprise.get('users', []):
            if user.get('username', '').lower() == recipient_email.lower():
                rsa_b = utils.base64_url_decode(user['public_key']) if user.get('public_key') else None
                ec_b = utils.base64_url_decode(user['public_key_ecc']) if user.get('public_key_ecc') else None
                recipient_public_key = _load_pk(rsa_b, ec_b)
                break

    if not recipient_public_key:
        recipient_public_key, use_ecc, recipient_uid_bytes, needs_invite = \
            _fetch_public_key_from_api(params, recipient_email, _load_pk,
                                       APIRequest_pb2, GetShareObjectsRequest,
                                       GetShareObjectsResponse, PublicKeys)

    if not recipient_uid_bytes:
        recipient_uid_bytes = resolve_user_uid_bytes(params, recipient_email)

    if not recipient_uid_bytes and require_uid:
        try:
            rq = GetShareObjectsRequest()
            rs = api.communicate_rest(params, rq, 'vault/get_share_objects',
                                      rs_type=GetShareObjectsResponse)
            if not hasattr(params, 'user_cache'):
                params.user_cache = {}
            for ul in (rs.shareRelationships, rs.shareFamilyUsers,
                       rs.shareEnterpriseUsers, rs.shareMCEnterpriseUsers):
                for su in ul:
                    if su.userAccountUid and su.username:
                        su_uid_b64 = utils.base64_url_encode(su.userAccountUid)
                        params.user_cache[su_uid_b64] = su.username
                        if su.username.lower() == recipient_email.lower():
                            recipient_uid_bytes = (su.userAccountUid if isinstance(su.userAccountUid, bytes)
                                                   else utils.base64_url_decode(su.userAccountUid))
        except Exception:
            pass

    return recipient_public_key, use_ecc, recipient_uid_bytes, needs_invite


def _fetch_public_key_from_api(params, recipient_email, _load_pk,
                                APIRequest_pb2, GetShareObjectsRequest,
                                GetShareObjectsResponse, PublicKeys):
    """Internal helper for the get_public_keys + share-objects fallback chain."""
    recipient_public_key = None
    use_ecc = False
    recipient_uid_bytes = None
    needs_invite = False

    try:
        lookup_email = recipient_email.lower()
        rq = APIRequest_pb2.GetPublicKeysRequest()
        rq.usernames.append(lookup_email)
        rs = api.communicate_rest(params, rq, 'vault/get_public_keys',
                                  rs_type=APIRequest_pb2.GetPublicKeysResponse)
        for pk in rs.keyResponses:
            if pk.username.lower() == recipient_email.lower():
                if pk.errorCode in ('', 'success'):
                    recipient_public_key = _load_pk(pk.publicKey or None, pk.publicEccKey or None)
                    if recipient_public_key:
                        params.key_cache[recipient_email] = PublicKeys(
                            aes=None, rsa=pk.publicKey or None, ec=pk.publicEccKey or None)
                elif pk.errorCode == 'no_active_share_exist':
                    recipient_public_key, use_ecc, recipient_uid_bytes, needs_invite = \
                        _retry_with_canonical_email(
                            params, recipient_email, _load_pk,
                            APIRequest_pb2, GetShareObjectsRequest,
                            GetShareObjectsResponse, PublicKeys)
                break
    except Exception:
        pass

    return recipient_public_key, use_ecc, recipient_uid_bytes, needs_invite


def _retry_with_canonical_email(params, recipient_email, _load_pk,
                                 APIRequest_pb2, GetShareObjectsRequest,
                                 GetShareObjectsResponse, PublicKeys):
    """Retry get_public_keys with the server-stored canonical email."""
    recipient_public_key = None
    use_ecc = False
    recipient_uid_bytes = None
    needs_invite = False

    try:
        rq2 = GetShareObjectsRequest()
        rs2 = api.communicate_rest(params, rq2, 'vault/get_share_objects',
                                   rs_type=GetShareObjectsResponse)
        canonical_email = None
        for ul in (rs2.shareRelationships, rs2.shareFamilyUsers,
                   rs2.shareEnterpriseUsers, rs2.shareMCEnterpriseUsers):
            for su in ul:
                if su.username.lower() == recipient_email.lower():
                    canonical_email = su.username
                    if su.userAccountUid:
                        uid = su.userAccountUid
                        recipient_uid_bytes = uid if isinstance(uid, bytes) else utils.base64_url_decode(uid)
                    break
            if canonical_email:
                break

        if canonical_email and canonical_email != recipient_email.lower():
            rq3 = APIRequest_pb2.GetPublicKeysRequest()
            rq3.usernames.append(canonical_email)
            rs3 = api.communicate_rest(params, rq3, 'vault/get_public_keys',
                                       rs_type=APIRequest_pb2.GetPublicKeysResponse)
            for pk3 in rs3.keyResponses:
                if pk3.username.lower() == recipient_email.lower():
                    if pk3.errorCode in ('', 'success'):
                        recipient_public_key = _load_pk(pk3.publicKey or None, pk3.publicEccKey or None)
                        if recipient_public_key:
                            params.key_cache[recipient_email] = PublicKeys(
                                aes=None, rsa=pk3.publicKey or None, ec=pk3.publicEccKey or None)
                    else:
                        needs_invite = True
                    break
        else:
            needs_invite = True
    except Exception:
        needs_invite = True

    return recipient_public_key, use_ecc, recipient_uid_bytes, needs_invite


# ═══════════════════════════════════════════════════════════════════════════
# Share invite helper  (previously duplicated in share + update_share)
# ═══════════════════════════════════════════════════════════════════════════

def handle_share_invite(params, recipient_email, needs_invite):
    """Send a share invite if *needs_invite* is True; raise ValueError."""
    if not needs_invite:
        return
    try:
        from ..proto import APIRequest_pb2
        rq = APIRequest_pb2.SendShareInviteRequest()
        rq.email = recipient_email
        api.communicate_rest(params, rq, 'vault/send_share_invite')
        raise ValueError(
            f"Share invitation has been sent to '{recipient_email}'. "
            f"Please repeat this command once the invitation is accepted.")
    except ValueError:
        raise
    except Exception:
        raise ValueError(
            f"No sharing relationship with '{recipient_email}'. "
            f"Please invite them to share first, then repeat this command.")


# ═══════════════════════════════════════════════════════════════════════════
# Folder access response parsing  (previously duplicated 3 times)
# ═══════════════════════════════════════════════════════════════════════════

def parse_folder_access_result(response, folder_uid, user_uid, default_message):
    """Parse a FolderAccessResponse into a standard result dict."""
    if response.folderAccessResults:
        result = response.folderAccessResults[0]
        status_value = result.status
        is_failure = (status_value != 0) or (result.message and len(result.message) > 0)
        status_name = (folder_pb2.FolderModifyStatus.Name(status_value)
                       if status_value != 0 else 'SUCCESS')
        return {
            'folder_uid': folder_uid,
            'user_uid': user_uid,
            'status': 'ERROR' if is_failure and status_value == 0 else status_name,
            'message': result.message if result.message else default_message,
            'success': not is_failure,
        }
    return {
        'folder_uid': folder_uid,
        'user_uid': user_uid,
        'status': 'SUCCESS',
        'message': default_message,
        'success': True,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Sharing status parsing  (used by record sharing functions)
# ═══════════════════════════════════════════════════════════════════════════

def parse_sharing_status(status) -> Dict[str, Any]:
    """Parse a RecordSharing.Status protobuf into a result dict."""
    try:
        status_name = record_sharing_pb2.SharingStatus.Name(status.status)
    except Exception:
        status_name = str(status.status)

    is_success = status.status == record_sharing_pb2.SUCCESS
    is_pending = status.status == record_sharing_pb2.PENDING_ACCEPT

    return {
        'record_uid': utils.base64_url_encode(status.recordUid),
        'recipient_uid': utils.base64_url_encode(status.recipientUid),
        'status': status_name,
        'message': status.message,
        'success': is_success or is_pending,
        'pending': is_pending,
    }


# ═══════════════════════════════════════════════════════════════════════════
# User public-key loading for folder access  (used by grant/batch)
# ═══════════════════════════════════════════════════════════════════════════

def load_user_public_key(params, user_email):
    """Load a user's public key from key_cache or the server.

    Returns (public_key_object, use_ecc) or raises ValueError.
    """
    user_keys = params.key_cache.get(user_email)
    if not user_keys:
        api.load_user_public_keys(params, [user_email])
        user_keys = params.key_cache.get(user_email)
    if not user_keys:
        raise ValueError(f"Public key not found for user {user_email}")

    if user_keys.rsa:
        return crypto.load_rsa_public_key(user_keys.rsa), False
    if user_keys.ec:
        return crypto.load_ec_public_key(user_keys.ec), True
    raise ValueError(f"No valid public key (RSA or ECC) found for user {user_email}")
