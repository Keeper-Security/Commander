"""
Tests for ``get_config_uid_from_local_vault`` and the ``get_config_uid`` flow
that now tries the local scan first.

The local scan resolves resource_uid -> config_uid by enumerating PAM
Configuration vault records (record_version=6) and finding the one whose
`pamResources.resourceRef` list contains the resource_uid. This is Web Vault
parity — zero network, no gateway required. The legacy `get_dag_leafs` path
remains as a fallback for cold-vault scenarios.
"""
import importlib
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

# Pre-warm the circular-import chain.
importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')

from keepercommander.commands.tunnel.port_forward import tunnel_helpers  # noqa: E402
from keepercommander import vault  # noqa: E402


RESOURCE_UID = 'RESOURCE_UID_1111111111'
OTHER_RESOURCE_UID = 'RESOURCE_UID_2222222222'
CONFIG_UID = 'CONFIG_UID_AAAAAAAAAAAAA'
OTHER_CONFIG_UID = 'CONFIG_UID_BBBBBBBBBBBBB'


# --------------------------------------------------------------------------- #
# Fixtures                                                                     #
# --------------------------------------------------------------------------- #


def _make_config_record(record_uid, resource_refs):
    """
    Build a stand-in for a PAM Configuration TypedRecord whose `pamResources`
    typed field carries the given resourceRef list.
    """
    rec = MagicMock(spec=vault.TypedRecord)
    rec.record_uid = record_uid
    rec.record_type = 'pamNetworkConfiguration'

    field = MagicMock()
    field.get_default_value.return_value = {
        'controllerUid': 'GATEWAY_UID',
        'folderUid': '',
        'resourceRef': list(resource_refs),
    }
    rec.get_typed_field.return_value = field
    return rec


# --------------------------------------------------------------------------- #
# get_config_uid_from_local_vault — happy paths                                #
# --------------------------------------------------------------------------- #


def test_local_vault_finds_config_for_resource():
    """Returns config_uid when a local PAM config's resourceRef contains the resource_uid."""
    records = [
        _make_config_record(OTHER_CONFIG_UID, resource_refs=[OTHER_RESOURCE_UID]),
        _make_config_record(CONFIG_UID, resource_refs=[RESOURCE_UID, 'unrelated_uid']),
    ]
    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter(records)):
        result = tunnel_helpers.get_config_uid_from_local_vault(params, RESOURCE_UID)
    assert result == CONFIG_UID


def test_local_vault_returns_first_match():
    """If multiple configs (shouldn't happen in practice) list the resource, returns first encountered."""
    records = [
        _make_config_record(CONFIG_UID, resource_refs=[RESOURCE_UID]),
        _make_config_record(OTHER_CONFIG_UID, resource_refs=[RESOURCE_UID]),
    ]
    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter(records)):
        result = tunnel_helpers.get_config_uid_from_local_vault(params, RESOURCE_UID)
    assert result == CONFIG_UID


# --------------------------------------------------------------------------- #
# get_config_uid_from_local_vault — no-match / edge cases                      #
# --------------------------------------------------------------------------- #


def test_local_vault_returns_none_when_no_config_owns_resource():
    """No config has the resource in its resourceRef -> None (caller falls back to get_dag_leafs)."""
    records = [
        _make_config_record(OTHER_CONFIG_UID, resource_refs=[OTHER_RESOURCE_UID]),
    ]
    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter(records)):
        result = tunnel_helpers.get_config_uid_from_local_vault(params, RESOURCE_UID)
    assert result is None


def test_local_vault_returns_none_when_empty_vault():
    records = []
    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter(records)):
        result = tunnel_helpers.get_config_uid_from_local_vault(params, RESOURCE_UID)
    assert result is None


def test_local_vault_returns_none_for_blank_record_uid():
    """Defensive: empty/None resource_uid short-circuits without iterating the vault."""
    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records') as mock_find:
        assert tunnel_helpers.get_config_uid_from_local_vault(params, None) is None
        assert tunnel_helpers.get_config_uid_from_local_vault(params, '') is None
        mock_find.assert_not_called()


def test_local_vault_skips_records_without_pam_resources_field():
    """Records missing the pamResources field are skipped, not fatal."""
    bad_rec = MagicMock(spec=vault.TypedRecord)
    bad_rec.record_uid = 'BAD_REC'
    bad_rec.get_typed_field.return_value = None  # field missing

    good_rec = _make_config_record(CONFIG_UID, resource_refs=[RESOURCE_UID])

    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter([bad_rec, good_rec])):
        result = tunnel_helpers.get_config_uid_from_local_vault(params, RESOURCE_UID)
    assert result == CONFIG_UID


def test_local_vault_skips_non_typed_records():
    """find_records may return non-TypedRecord items (e.g. PasswordRecord); skip them."""
    non_typed = MagicMock(spec=[])  # no TypedRecord interface
    good_rec = _make_config_record(CONFIG_UID, resource_refs=[RESOURCE_UID])

    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter([non_typed, good_rec])):
        result = tunnel_helpers.get_config_uid_from_local_vault(params, RESOURCE_UID)
    assert result == CONFIG_UID


# --------------------------------------------------------------------------- #
# get_config_uid — wires local scan in front of get_dag_leafs                  #
# --------------------------------------------------------------------------- #


def test_get_config_uid_uses_local_match_and_skips_get_dag_leafs():
    """When local scan finds a config, get_dag_leafs is never called."""
    records = [_make_config_record(CONFIG_UID, resource_refs=[RESOURCE_UID])]
    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter(records)), \
         patch.object(tunnel_helpers, 'get_dag_leafs') as mock_dl:
        result = tunnel_helpers.get_config_uid(params, b'tok', b'tk', RESOURCE_UID)
    assert result == CONFIG_UID
    mock_dl.assert_not_called()


def test_get_config_uid_uses_pam_link_before_get_dag_leafs():
    """No local match -> precise PAM_LINK resolution wins and legacy get_dag_leafs is skipped.

    Regression guard for the "Found multiple vertex that use the path" bug: the
    legacy graphId=0 get_dag_leafs can return a stale/duplicate config when a
    resource still has link edges under more than one PAM config. Resolving the
    owner precisely via the per-graph PAM_LINK get_leafs avoids loading that
    ambiguous graph, so it must run before the legacy path.
    """
    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter([])), \
         patch.object(tunnel_helpers, 'get_config_uid_via_pam_link', return_value=CONFIG_UID) as mock_link, \
         patch.object(tunnel_helpers, 'get_dag_leafs') as mock_dl:
        result = tunnel_helpers.get_config_uid(params, b'tok', b'tk', RESOURCE_UID)
    assert result == CONFIG_UID
    mock_link.assert_called_once()
    mock_dl.assert_not_called()


def test_get_config_uid_falls_back_to_get_dag_leafs_when_no_local_match():
    """No local match and no PAM_LINK owner -> legacy get_dag_leafs path; its result flows through."""
    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter([])), \
         patch.object(tunnel_helpers, 'get_config_uid_via_pam_link', return_value=''), \
         patch.object(tunnel_helpers, 'get_dag_leafs',
                      return_value=[{'type': 'rec', 'value': CONFIG_UID, 'name': None}]) as mock_dl:
        result = tunnel_helpers.get_config_uid(params, b'tok', b'tk', RESOURCE_UID)
    assert result == CONFIG_UID
    mock_dl.assert_called_once()


def test_get_config_uid_returns_none_when_neither_path_resolves():
    """No local match, no PAM_LINK owner, and get_dag_leafs returns None -> None propagates."""
    params = MagicMock()
    with patch('keepercommander.vault_extensions.find_records', return_value=iter([])), \
         patch.object(tunnel_helpers, 'get_config_uid_via_pam_link', return_value=''), \
         patch.object(tunnel_helpers, 'get_dag_leafs', return_value=None):
        result = tunnel_helpers.get_config_uid(params, b'tok', b'tk', RESOURCE_UID)
    assert result is None
