"""
Layer-B `set_record_rotation` tests (plan §13.4 / task #24).

Covers the `router_set_record_rotation_information` wrapper in
`pam/router_helper.py`, which POSTs `Router.RouterRecordRotationRequest` to
krouter's `/api/user/set_record_rotation` endpoint (UserRest.kt:652-693).

Krouter-side validation (mirrored in tests below):
- Schedule frequency < 1h -> RRC_GENERAL_ERROR with cron-interval message.
- KA backend failure -> error propagates.
- Scheduler `setup_rotation` HTTP non-OK -> RRC_BAD_REQUEST / RRC_GENERAL_ERROR.
- IAM noop variant + happy path.
"""
import importlib
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))

# Pre-warm the import chain (see test_dag_layer_b_configure_resource.py for context).
importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')  # side-effect: pre-warm

from keepercommander.commands.pam._layer_b import RouterResponseError  # noqa: E402
from keepercommander.proto import router_pb2  # noqa: E402


REQUESTS_TARGET = 'keepercommander.commands.pam.router_helper.requests.request'

RECORD_UID = b'\xAA' * 16
CONFIG_UID = b'\xBB' * 16
RESOURCE_UID = b'\xCC' * 16


def _mock_params():
    p = MagicMock()
    p.config = {'server': 'krouter.test'}
    p.session_token = 'BBBBBBBB'
    p.rest_context.server_key_id = 7
    os.environ['KROUTER_URL'] = 'https://krouter.test'
    os.environ['VERIFY_SSL'] = 'false'
    return p


def _ok_router_response():
    rs = router_pb2.RouterResponse()
    rs.responseCode = router_pb2.RRC_OK
    rsp = MagicMock()
    rsp.status_code = 200
    rsp.headers = {}
    rsp.content = rs.SerializeToString()
    rsp.raise_for_status.return_value = None
    return rsp


def _error_router_response(code_name: str, error_message: str = ''):
    rs = router_pb2.RouterResponse()
    rs.responseCode = router_pb2.RouterResponseCode.Value(code_name)
    rs.errorMessage = error_message
    rsp = MagicMock()
    rsp.status_code = 200
    rsp.headers = {}
    rsp.content = rs.SerializeToString()
    rsp.raise_for_status.return_value = None
    return rsp


# --------------------------------------------------------------------------- #
# URL + body                                                                   #
# --------------------------------------------------------------------------- #


def test_set_record_rotation_hits_correct_url():
    from keepercommander.commands.pam.router_helper import router_set_record_rotation_information
    rq = router_pb2.RouterRecordRotationRequest(recordUid=RECORD_UID, configurationUid=CONFIG_UID)
    with patch(REQUESTS_TARGET, return_value=_ok_router_response()) as mock_req:
        router_set_record_rotation_information(_mock_params(), rq)
    url = mock_req.call_args.kwargs.get('url') or mock_req.call_args.args[1]
    assert url.endswith('/api/user/set_record_rotation')


def test_set_record_rotation_sends_protobuf_body():
    from keepercommander.commands.pam.router_helper import router_set_record_rotation_information
    from keepercommander import crypto, utils
    rq = router_pb2.RouterRecordRotationRequest(
        recordUid=RECORD_UID,
        configurationUid=CONFIG_UID,
        resourceUid=RESOURCE_UID,
        schedule='0 0 * * *',
    )
    transmission_key = utils.generate_aes_key()
    with patch(REQUESTS_TARGET, return_value=_ok_router_response()) as mock_req:
        router_set_record_rotation_information(_mock_params(), rq, transmission_key=transmission_key)
    body = mock_req.call_args.kwargs.get('data')
    assert isinstance(body, (bytes, bytearray))
    # Body is the AES-GCM-encrypted protobuf — not the plaintext proto, and not
    # JSON. Decrypt with the known transmission key and confirm it round-trips.
    # (A first-byte heuristic like `not body.startswith(b'{')` is flaky: ~1/256
    # of ciphertexts legitimately start with 0x7b.)
    assert body != rq.SerializeToString()
    decrypted = crypto.decrypt_aes_v2(body, transmission_key)
    parsed = router_pb2.RouterRecordRotationRequest()
    parsed.ParseFromString(decrypted)
    assert parsed.recordUid == RECORD_UID
    assert parsed.configurationUid == CONFIG_UID
    assert parsed.resourceUid == RESOURCE_UID
    assert parsed.schedule == '0 0 * * *'


# --------------------------------------------------------------------------- #
# Proto shape — every field krouter consumes                                   #
# --------------------------------------------------------------------------- #


def test_rotation_proto_minimal():
    rq = router_pb2.RouterRecordRotationRequest(recordUid=RECORD_UID)
    assert rq.recordUid == RECORD_UID
    assert rq.schedule == ''
    assert rq.disabled is False
    assert rq.noop is False


def test_rotation_proto_full_shape_roundtrips():
    rq = router_pb2.RouterRecordRotationRequest(
        recordUid=RECORD_UID,
        revision=42,
        configurationUid=CONFIG_UID,
        resourceUid=RESOURCE_UID,
        schedule='0 2 * * *',  # daily 2am
        enterpriseUserId=12345,
        pwdComplexity=b'\x14\x04\x04\x04\x04',  # length=20, caps=4, digits=4, lower=4, special=4
        disabled=False,
        noop=False,
        saasConfiguration=b'',
    )
    parsed = router_pb2.RouterRecordRotationRequest()
    parsed.ParseFromString(rq.SerializeToString())
    assert parsed.recordUid == RECORD_UID
    assert parsed.revision == 42
    assert parsed.configurationUid == CONFIG_UID
    assert parsed.resourceUid == RESOURCE_UID
    assert parsed.schedule == '0 2 * * *'
    assert parsed.enterpriseUserId == 12345
    assert parsed.pwdComplexity == b'\x14\x04\x04\x04\x04'
    assert parsed.disabled is False
    assert parsed.noop is False


def test_rotation_proto_iam_noop_variant():
    """IAM users: resourceUid empty, noop=False (links to config directly)."""
    rq = router_pb2.RouterRecordRotationRequest(
        recordUid=RECORD_UID,
        configurationUid=CONFIG_UID,
        resourceUid=b'',
        noop=False,
    )
    assert rq.resourceUid == b''
    assert rq.noop is False


def test_rotation_proto_disabled_with_empty_schedule():
    """Clear-schedule case: disabled=True, schedule='[]' (or empty) — krouter clears scheduler."""
    rq = router_pb2.RouterRecordRotationRequest(
        recordUid=RECORD_UID,
        configurationUid=CONFIG_UID,
        disabled=True,
        schedule='',
    )
    assert rq.disabled is True
    assert rq.schedule == ''


# --------------------------------------------------------------------------- #
# Error surfacing                                                              #
# --------------------------------------------------------------------------- #


def test_subhour_schedule_surfaces_general_error():
    """Krouter rejects schedule with frequency < 1h as RRC_GENERAL_ERROR (UserRest.kt:654-658)."""
    from keepercommander.commands.pam.router_helper import router_set_record_rotation_information
    rq = router_pb2.RouterRecordRotationRequest(recordUid=RECORD_UID, schedule='*/5 * * * *')
    with patch(REQUESTS_TARGET, return_value=_error_router_response(
            'RRC_GENERAL_ERROR', 'Cron setup error: interval set to less than one hour')):
        with pytest.raises(RouterResponseError) as exc_info:
            router_set_record_rotation_information(_mock_params(), rq)
    assert exc_info.value.response_code_name == 'RRC_GENERAL_ERROR'
    assert 'less than one hour' in str(exc_info.value)


def test_ka_backend_failure_propagates():
    """KA (KeeperApp) backend rejection during set_record_rotation propagates."""
    from keepercommander.commands.pam.router_helper import router_set_record_rotation_information
    rq = router_pb2.RouterRecordRotationRequest(recordUid=RECORD_UID)
    with patch(REQUESTS_TARGET, return_value=_error_router_response(
            'RRC_GENERAL_ERROR', 'KA returned error')):
        with pytest.raises(RouterResponseError) as exc_info:
            router_set_record_rotation_information(_mock_params(), rq)
    assert exc_info.value.response_code_name == 'RRC_GENERAL_ERROR'


def test_scheduler_bad_request_surfaces_as_rrc_bad_request():
    """Scheduler `setup_rotation` returning 400 -> RRC_BAD_REQUEST per UserRest.kt:682-684."""
    from keepercommander.commands.pam.router_helper import router_set_record_rotation_information
    rq = router_pb2.RouterRecordRotationRequest(recordUid=RECORD_UID, schedule='0 2 * * *')
    with patch(REQUESTS_TARGET, return_value=_error_router_response(
            'RRC_BAD_REQUEST', 'scheduler rejected')):
        with pytest.raises(RouterResponseError) as exc_info:
            router_set_record_rotation_information(_mock_params(), rq)
    assert exc_info.value.response_code_name == 'RRC_BAD_REQUEST'


# --------------------------------------------------------------------------- #
# Happy path                                                                   #
# --------------------------------------------------------------------------- #


def test_happy_path_returns_without_error():
    from keepercommander.commands.pam.router_helper import router_set_record_rotation_information
    rq = router_pb2.RouterRecordRotationRequest(
        recordUid=RECORD_UID,
        configurationUid=CONFIG_UID,
        resourceUid=RESOURCE_UID,
        schedule='0 2 * * *',  # daily 2am — well over 1h frequency
        revision=1,
    )
    with patch(REQUESTS_TARGET, return_value=_ok_router_response()):
        # Should not raise
        router_set_record_rotation_information(_mock_params(), rq)
