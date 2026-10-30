from ... import api, crypto, utils


class MissingTeamEncryptionKey(ValueError):
    """The enterprise tree key or data key needed to create a team is missing."""


def generate_team_add_key_fields(team_key, allow_rsa=True):
    # type: (bytes, bool) -> dict
    """Generate the EC (and, when allowed, RSA) key fields for a team_add request.

    The EC private key is encrypted with AES-v2 and the RSA private key with AES-v1,
    both under ``team_key``. Every value is base64url-encoded. Returned names match
    the request fields: ``ecc_private_key``, ``ecc_public_key``, and when RSA is
    allowed ``private_key`` and ``public_key``.
    """
    ec_private_key, ec_public_key = crypto.generate_ec_key()
    fields = {
        'ecc_private_key': utils.base64_url_encode(
            crypto.encrypt_aes_v2(crypto.unload_ec_private_key(ec_private_key), team_key)),
        'ecc_public_key': utils.base64_url_encode(crypto.unload_ec_public_key(ec_public_key)),
    }
    if allow_rsa:
        rsa_private_key, rsa_public_key = crypto.generate_rsa_key()
        fields['private_key'] = utils.base64_url_encode(
            crypto.encrypt_aes_v1(crypto.unload_rsa_private_key(rsa_private_key), team_key))
        fields['public_key'] = utils.base64_url_encode(crypto.unload_rsa_public_key(rsa_public_key))
    return fields


def build_team_add_request(params, team_name, node_id,
                           restrict_edit=False, restrict_share=False, restrict_view=False,
                           manage_only=True, team_uid=None, team_key=None):
    # type: (object, str, int, bool, bool, bool, bool, str, bytes) -> tuple
    """Build a team_add request and return ``(request, team_key)``.

    ``team_uid`` and the team AES key are generated when the caller does not
    supply them. The team key is encrypted with the data key (AES-v1) and the
    enterprise tree key (AES-v2). RSA key fields are omitted when
    ``params.forbid_rsa`` is set. Raises MissingTeamEncryptionKey when the tree
    key or data key is missing. The returned team key is the raw AES key, for
    callers that still need it to add members.
    """
    tree_key = (getattr(params, 'enterprise', None) or {}).get('unencrypted_tree_key')
    data_key = getattr(params, 'data_key', None)
    if not tree_key or not data_key:
        raise MissingTeamEncryptionKey('Enterprise tree key or data key is not available')

    if team_uid is None:
        team_uid = api.generate_record_uid()
    if team_key is None:
        team_key = api.generate_aes_key()

    request = {
        'command': 'team_add',
        'team_uid': team_uid,
        'team_name': team_name,
        'restrict_edit': restrict_edit,
        'restrict_share': restrict_share,
        'restrict_view': restrict_view,
        'node_id': node_id,
        'team_key': utils.base64_url_encode(crypto.encrypt_aes_v1(team_key, data_key)),
        'encrypted_team_key': utils.base64_url_encode(crypto.encrypt_aes_v2(team_key, tree_key)),
        'manage_only': manage_only,
    }
    request.update(generate_team_add_key_fields(
        team_key, allow_rsa=not getattr(params, 'forbid_rsa', False)))
    return request, team_key