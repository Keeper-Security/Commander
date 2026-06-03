"""
Layer-B `configure_resource` tests (plan §13.3 / task #23).

Verifies the `router_configure_resource` wrapper in `pam/router_helper.py`:
- Targets `/api/user/configure_resource`.
- Sends a `PAMResourceConfig` protobuf body, encrypted with the transmission key.
- Round-trips through `_post_request_to_router` (which is the shared protobuf
  transport layer for all Layer-B endpoints).

For each `PAMResourceConfig` field that the krouter handler at UserRest.kt:375-581
processes, one happy-path test confirms Commander builds the right proto.

For each permission-denial code that the handler can return (RRC_NOT_ALLOWED,
RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED for connections / rotation /
connections_and_rotation enforcement checks), one test confirms the
`RouterResponseError` raised by `_post_request_to_router` exposes the right
`response_code_name` so callers can decide on fallback.
"""
import importlib
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))

# Pre-warm the import chain through pam_import.keeper_ai_settings to avoid the
# pre-existing circular import in commands.record/ksm.utils when router_helper
# is the first thing to drag in commands.utils. See test_dag_layer_b_migration.py
# for a test file that triggers the chain naturally; this one needs the explicit
# warm-up because it imports router_helper directly.
importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')  # side-effect: pre-warm

from keepercommander.commands.pam._layer_b import RouterResponseError  # noqa: E402
from keepercommander.proto import pam_pb2, router_pb2  # noqa: E402


# Mock seam: the requests.request inside _post_request_to_router.
REQUESTS_TARGET = 'keepercommander.commands.pam.router_helper.requests.request'

RESOURCE_UID = b'\xAA' * 16
NETWORK_UID = b'\xBB' * 16
ADMIN_UID = b'\xCC' * 16
DOMAIN_UID = b'\xDD' * 16


def _mock_params():
    p = MagicMock()
    p.config = {'server': 'krouter.test'}
    p.session_token = 'BBBBBBBB'  # base64 of 6 bytes; sufficient for url_safe_base64_decode
    p.rest_context.server_key_id = 7
    os.environ['KROUTER_URL'] = 'https://krouter.test'
    os.environ['VERIFY_SSL'] = 'false'
    return p


def _ok_router_response():
    """Build a successful RouterResponse wire payload."""
    rs = router_pb2.RouterResponse()
    rs.responseCode = router_pb2.RRC_OK
    rsp = MagicMock()
    rsp.status_code = 200
    rsp.headers = {}
    rsp.content = rs.SerializeToString()
    rsp.raise_for_status.return_value = None
    return rsp


def _error_router_response(code_name: str, error_message: str = 'denied'):
    """Build a RouterResponse with a non-OK responseCode wire payload."""
    rs = router_pb2.RouterResponse()
    rs.responseCode = router_pb2.RouterResponseCode.Value(code_name)
    rs.errorMessage = error_message
    rsp = MagicMock()
    rsp.status_code = 200  # HTTP 200; the error lives inside the protobuf body
    rsp.headers = {}
    rsp.content = rs.SerializeToString()
    rsp.raise_for_status.return_value = None
    return rsp


def _capture_call(mock_req):
    """Return the (url, body_bytes) that requests.request was last called with."""
    kwargs = mock_req.call_args.kwargs
    return kwargs.get('url') or mock_req.call_args.args[1], kwargs.get('data')


# --------------------------------------------------------------------------- #
# Happy path: URL + body shape                                                 #
# --------------------------------------------------------------------------- #


def test_configure_resource_hits_correct_url():
    """POSTs to /api/user/configure_resource."""
    from keepercommander.commands.pam.router_helper import router_configure_resource
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID, networkUid=NETWORK_UID)
    with patch(REQUESTS_TARGET, return_value=_ok_router_response()) as mock_req:
        router_configure_resource(_mock_params(), rq)
    url, _ = _capture_call(mock_req)
    assert url.endswith('/api/user/configure_resource')


def test_configure_resource_sends_protobuf_body():
    """Body is the encrypted PAMResourceConfig protobuf, not JSON."""
    from keepercommander.commands.pam.router_helper import router_configure_resource
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID, networkUid=NETWORK_UID, adminUid=ADMIN_UID)
    with patch(REQUESTS_TARGET, return_value=_ok_router_response()) as mock_req:
        router_configure_resource(_mock_params(), rq)
    _, body = _capture_call(mock_req)
    assert isinstance(body, (bytes, bytearray)), f'body must be bytes, got {type(body)}'
    # Body is encrypted; check that it's NOT a JSON-encoded payload (sanity).
    assert not body.startswith(b'{'), 'body should be encrypted protobuf, not JSON'


# --------------------------------------------------------------------------- #
# Per-field proto-shape tests — exercises every PAMResourceConfig field the    #
# krouter handler reads. Catches accidental field-name typos or proto schema   #
# drift.                                                                       #
# --------------------------------------------------------------------------- #


def test_configure_resource_proto_recordUid_only():
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID)
    assert rq.recordUid == RESOURCE_UID
    assert rq.networkUid == b''
    assert rq.adminUid == b''


def test_configure_resource_proto_full_credential_link():
    """A typical 'configure resource with admin credential' shape."""
    rq = pam_pb2.PAMResourceConfig(
        recordUid=RESOURCE_UID,
        networkUid=NETWORK_UID,
        adminUid=ADMIN_UID,
    )
    assert rq.recordUid == RESOURCE_UID
    assert rq.networkUid == NETWORK_UID
    assert rq.adminUid == ADMIN_UID


def test_configure_resource_proto_connect_users_uid_list():
    rq = pam_pb2.PAMResourceConfig(
        recordUid=RESOURCE_UID,
        connectUsers=pam_pb2.UidList(uids=[b'\xEE' * 16, b'\xFF' * 16]),
    )
    assert list(rq.connectUsers.uids) == [b'\xEE' * 16, b'\xFF' * 16]


def test_configure_resource_proto_domainUid():
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID, domainUid=DOMAIN_UID)
    assert rq.domainUid == DOMAIN_UID


def test_configure_resource_proto_meta_bytes():
    meta_json = b'{"allowedSettings":{"connections":true}}'
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID, meta=meta_json)
    assert rq.meta == meta_json


def test_configure_resource_proto_jit_settings():
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID, jitSettings=b'JIT_BYTES')
    assert rq.jitSettings == b'JIT_BYTES'


def test_configure_resource_proto_keeper_ai_settings():
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID, keeperAiSettings=b'AI_BYTES')
    assert rq.keeperAiSettings == b'AI_BYTES'


def test_configure_resource_proto_all_fields_together():
    """All-fields construction — useful as a smoke for proto schema completeness."""
    rq = pam_pb2.PAMResourceConfig(
        recordUid=RESOURCE_UID,
        networkUid=NETWORK_UID,
        adminUid=ADMIN_UID,
        meta=b'{"allowedSettings":{}}',
        connectionSettings=b'CONN',
        connectUsers=pam_pb2.UidList(uids=[b'\x11' * 16]),
        domainUid=DOMAIN_UID,
        jitSettings=b'JIT',
        keeperAiSettings=b'AI',
    )
    # All fields round-trip through serialization (catches missing field-number gaps).
    parsed = pam_pb2.PAMResourceConfig()
    parsed.ParseFromString(rq.SerializeToString())
    assert parsed.recordUid == RESOURCE_UID
    assert parsed.networkUid == NETWORK_UID
    assert parsed.adminUid == ADMIN_UID
    assert parsed.meta == b'{"allowedSettings":{}}'
    assert parsed.connectionSettings == b'CONN'
    assert list(parsed.connectUsers.uids) == [b'\x11' * 16]
    assert parsed.domainUid == DOMAIN_UID
    assert parsed.jitSettings == b'JIT'
    assert parsed.keeperAiSettings == b'AI'


# --------------------------------------------------------------------------- #
# Permission denial paths — each enforcement check at UserRest.kt:540-571      #
# surfaces a specific RouterResponseCode; verify Commander parses it into the  #
# right `response_code_name` so the fallback logic can branch correctly.       #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('code_name', [
    'RRC_NOT_ALLOWED',                          # validatePamAccess failure (linking unauthorized record)
    'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED',  # connections / rotation / both enforcement disabled
])
def test_configure_resource_raises_router_response_error_on_permission_denied(code_name):
    """Verify Commander parses the responseCode and surfaces it via RouterResponseError."""
    from keepercommander.commands.pam.router_helper import router_configure_resource
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID, networkUid=NETWORK_UID, adminUid=ADMIN_UID)
    with patch(REQUESTS_TARGET, return_value=_error_router_response(code_name, 'denied')):
        with pytest.raises(RouterResponseError) as exc_info:
            router_configure_resource(_mock_params(), rq)
    assert exc_info.value.response_code_name == code_name
    assert 'denied' in str(exc_info.value)


@pytest.mark.parametrize('code_name', ['RRC_GENERAL_ERROR', 'RRC_BAD_REQUEST', 'RRC_TIMEOUT'])
def test_configure_resource_raises_router_response_error_on_non_permission_codes(code_name):
    """Non-permission errors also surface as RouterResponseError; callers don't fall back on these."""
    from keepercommander.commands.pam.router_helper import router_configure_resource
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID)
    with patch(REQUESTS_TARGET, return_value=_error_router_response(code_name, 'something broke')):
        with pytest.raises(RouterResponseError) as exc_info:
            router_configure_resource(_mock_params(), rq)
    assert exc_info.value.response_code_name == code_name


# --------------------------------------------------------------------------- #
# Transport-level error surfacing (4xx/5xx HTTP errors)                        #
# --------------------------------------------------------------------------- #


def test_configure_resource_raises_keeper_api_error_on_http_4xx():
    """An HTTP 4xx from krouter surfaces as KeeperApiError (not RouterResponseError)."""
    from keepercommander.error import KeeperApiError
    from keepercommander.commands.pam.router_helper import router_configure_resource
    rq = pam_pb2.PAMResourceConfig(recordUid=RESOURCE_UID)
    rsp = MagicMock()
    rsp.status_code = 401
    rsp.text = 'unauthorized'
    rsp.headers = {}
    with patch(REQUESTS_TARGET, return_value=rsp):
        with pytest.raises(KeeperApiError) as exc_info:
            router_configure_resource(_mock_params(), rq)
    assert exc_info.value.result_code == 401
