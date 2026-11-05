from unittest.mock import patch

import pytest

pytest.importorskip('fido2')  # fido2 is only installed on Python >= 3.10

from keepercommander.biometric.client import BiometricClient
from keepercommander.biometric.commands.list import BiometricListCommand
from keepercommander.biometric.utils.aaguid import get_provider_name_from_aaguid
from keepercommander.params import KeeperParams
from keepercommander.proto import APIRequest_pb2


@pytest.mark.parametrize('aaguid', [
    'fcc0118f-cd45-435b-8da1-9782b2da0715',
    'c1f9a0bc-1dd2-404a-b27f-8e29047a43fd',
    'FCC0118F-CD45-435B-8DA1-9782B2DA0715',
    'fcc0118fcd45435b8da19782b2da0715',
    '  FCC0118FCD45435B8DA19782B2DA0715  ',
])
def test_yubikey_fips_name_matches_web_vault(aaguid):
    assert get_provider_name_from_aaguid(aaguid) == 'YubiKey 5 FIPS Series with NFC'


@pytest.mark.parametrize('aaguid, name', [
    ('08987058-cadc-4b81-b6e1-30de50dcbe96', 'Windows Hello'),
    ('fbfc3007-154e-4ecc-8c0b-6e020557d7bd', 'Apple Passwords'),
    ('dd4ec289-e01d-41c9-bb89-70fa845d4bf2', 'iCloud Keychain (Managed)'),
    ('42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3', 'Google Titan Security Key v2'),
    ('2cd2f727-f6ca-44da-8f48-5c2e5da000a2', 'Nitrokey 3 AM'),
    ('0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6', 'Keeper'),
])
def test_platform_and_hardware_names_from_combined_registry(aaguid, name):
    assert get_provider_name_from_aaguid(aaguid) == name


@pytest.mark.parametrize('aaguid', [
    None, '', '   ', 'unknown',
    '00000000-0000-0000-0000-000000000000',
    '11111111-1111-1111-1111-111111111111',
])
def test_unknown_authenticator_matches_web_vault_fallback(aaguid):
    assert get_provider_name_from_aaguid(aaguid) == 'Unknown Authenticator'


@pytest.mark.parametrize('friendly_name', ['', 'My security key'])
def test_list_resolves_api_aaguid_not_friendly_name(friendly_name, capsys):
    response = APIRequest_pb2.PasskeyListResponse(passkeyInfo=[
        APIRequest_pb2.PasskeyInfo(
            userId=123, credentialId=b'credential', friendlyName=friendly_name,
            AAGUID='fcc0118f-cd45-435b-8da1-9782b2da0715',
            createdAtMillis=0, lastUsedMillis=0,
        ),
    ])
    client = object.__new__(BiometricClient)
    with patch('keepercommander.biometric.client.api.communicate_rest', return_value=response):
        credentials = client.get_available_credentials(KeeperParams())
    assert credentials[0]['aaguid'] == response.passkeyInfo[0].AAGUID
    assert credentials[0]['name'] == friendly_name

    command = object.__new__(BiometricListCommand)
    command._display_credentials(credentials)
    output = capsys.readouterr().out
    assert 'Name: YubiKey 5 FIPS Series with NFC\n' in output
    assert 'None' not in output
    if friendly_name:
        assert 'Friendly Name: My security key\n' in output
    else:
        assert 'Friendly Name:' not in output


def test_list_missing_aaguid_never_prints_none(capsys):
    command = object.__new__(BiometricListCommand)
    command._display_credentials([{'name': 'My key', 'created': 0, 'last_used': 0}])
    output = capsys.readouterr().out
    assert 'Name: Unknown Authenticator\n' in output
    assert 'Friendly Name: My key\n' in output
    assert 'None' not in output
