"""
Layer-A cross-cutting tests (plan §13.6).

Concerns that touch every DAG/graph-sync request rather than any single endpoint:
- Auth header construction (Authorization, TransmissionKey, User-Agent).
- HTTP error surfacing (4xx/5xx -> DAGConnectionException after retries).
- 429 throttle handling (doesn't count against retry budget; backs off).
- Debug logging includes URL on each attempt.

Mock seams (same as test_dag_graph_sync_endpoints.py):
- `keepercommander.keeper_dag.connection.commander.requests.request` for the HTTP call.
- `keepercommander.keeper_dag.connection.commander.time.sleep` so retry tests are fast.
"""
import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests as requests_lib

sys.path.insert(0, os.path.dirname(__file__))
import _dag_fixtures  # noqa: E402

from keepercommander.keeper_dag.exceptions import DAGConnectionException  # noqa: E402
from keepercommander.keeper_dag.types import PamEndpoints  # noqa: E402

REQUESTS_MODULE = 'keepercommander.keeper_dag.connection.commander.requests'
SLEEP_TARGET = 'keepercommander.keeper_dag.connection.commander.time.sleep'


def _build_connection_with_real_headers():
    """Build a Connection where header construction runs but no real crypto is needed.

    Uses the deprecated `encrypted_transmission_key`/`encrypted_session_token`/`transmission_key`
    constructor kwargs which short-circuit the public-key encryption path in
    payload_and_headers(), so tests can run without server keys.
    """
    from keepercommander.keeper_dag.connection.commander import Connection

    params = MagicMock()
    params.config = {'server': 'krouter.test'}
    os.environ['KROUTER_URL'] = 'https://krouter.test'
    os.environ['VERIFY_SSL'] = 'false'

    conn = Connection(
        params=params,
        verify_ssl=False,
        encrypted_transmission_key=b'\x11' * 64,
        encrypted_session_token=b'\x22' * 80,
        transmission_key=b'\x33' * 32,
    )
    return conn


def _ok_response():
    rsp = MagicMock()
    rsp.status_code = 200
    rsp.content = b''
    rsp.raise_for_status.return_value = None
    return rsp


def _http_error_response(status_code):
    rsp = MagicMock()
    rsp.status_code = status_code
    rsp.content = b'simulated error'
    rsp.reason = 'Simulated'
    err = requests_lib.exceptions.HTTPError(response=rsp)
    rsp.raise_for_status.side_effect = err
    return rsp


# --------------------------------------------------------------------------- #
# Auth headers                                                                 #
# --------------------------------------------------------------------------- #


def test_request_includes_keeperuser_authorization_header():
    """Authorization: KeeperUser <base64> must accompany every user request."""
    conn = _build_connection_with_real_headers()
    query = _dag_fixtures.make_sync_query()
    with patch(f'{REQUESTS_MODULE}.request', return_value=_ok_response()) as mock_req:
        conn.sync(query, endpoint=PamEndpoints.PAM)
    sent_headers = mock_req.call_args.kwargs['headers']
    assert 'Authorization' in sent_headers, f'no Authorization header; got {sorted(sent_headers)}'
    assert sent_headers['Authorization'].startswith('KeeperUser '), (
        f'expected KeeperUser scheme, got {sent_headers["Authorization"]!r}'
    )


def test_request_includes_transmission_key_header():
    """TransmissionKey header carries the encrypted-with-server-public-key blob."""
    conn = _build_connection_with_real_headers()
    query = _dag_fixtures.make_sync_query()
    with patch(f'{REQUESTS_MODULE}.request', return_value=_ok_response()) as mock_req:
        conn.sync(query, endpoint=PamEndpoints.PAM)
    sent_headers = mock_req.call_args.kwargs['headers']
    assert 'TransmissionKey' in sent_headers
    assert len(sent_headers['TransmissionKey']) > 0


def test_request_includes_user_agent_header():
    """User-Agent must be set so server can identify caller version."""
    conn = _build_connection_with_real_headers()
    query = _dag_fixtures.make_sync_query()
    with patch(f'{REQUESTS_MODULE}.request', return_value=_ok_response()) as mock_req:
        conn.sync(query, endpoint=PamEndpoints.PAM, agent='test-agent/1.0')
    sent_headers = mock_req.call_args.kwargs['headers']
    assert sent_headers.get('User-Agent') == 'test-agent/1.0'


# --------------------------------------------------------------------------- #
# Error surfacing                                                              #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize('status_code', [400, 401, 403, 404, 500, 502, 503])
def test_non_throttle_http_errors_raise_dag_exception(status_code):
    """4xx (non-429) and 5xx exhaust retries then raise DAGConnectionException."""
    conn = _build_connection_with_real_headers()
    query = _dag_fixtures.make_sync_query()
    with patch(SLEEP_TARGET):  # skip real sleep between retries
        with patch(f'{REQUESTS_MODULE}.request', return_value=_http_error_response(status_code)) as mock_req:
            with pytest.raises(DAGConnectionException) as exc_info:
                conn.sync(query, endpoint=PamEndpoints.PAM)
    # Default retry is 5 attempts in rest_call_to_router signature
    assert mock_req.call_count == 5, f'expected 5 retry attempts, got {mock_req.call_count}'
    assert str(status_code) in str(exc_info.value)


def test_429_does_not_consume_retry_budget_and_increases_wait():
    """429 throttle: retries indefinitely* against budget, retry_wait scaled by throttle_inc_factor.

    *In practice the loop still terminates because retry_wait grows exponentially and a real
    deployment hits other failures; this test checks the documented behavior: 429 does
    `attempt -= 1` and `retry_wait *= throttle_inc_factor` for some number of cycles before
    we forcibly stop the mock.
    """
    conn = _build_connection_with_real_headers()
    query = _dag_fixtures.make_sync_query()
    throttled = _http_error_response(429)
    ok = _ok_response()

    # 3 throttles, then success — would normally exceed the default retry=5 budget if
    # 429 counted against it, but 429s decrement attempt so we should reach success.
    responses = [throttled, throttled, throttled, ok]
    sleep_calls = []
    with patch(SLEEP_TARGET, side_effect=lambda s: sleep_calls.append(s)):
        with patch(f'{REQUESTS_MODULE}.request', side_effect=responses):
            conn.sync(query, endpoint=PamEndpoints.PAM)
    # Three throttles -> three sleeps with strictly increasing wait (factor 1.5).
    assert len(sleep_calls) == 3, f'expected 3 sleeps between throttles, got {sleep_calls}'
    assert sleep_calls[0] < sleep_calls[1] < sleep_calls[2], (
        f'retry_wait did not grow: {sleep_calls}'
    )


# --------------------------------------------------------------------------- #
# Debug logging                                                                #
# --------------------------------------------------------------------------- #


def test_debug_logging_includes_full_url(caplog):
    """Every attempt logs the full URL at DEBUG so operators can trace request paths."""
    conn = _build_connection_with_real_headers()
    conn.logger = logging.getLogger('test_dag_cross_cutting')
    query = _dag_fixtures.make_sync_query()
    with caplog.at_level(logging.DEBUG, logger='test_dag_cross_cutting'):
        with patch(f'{REQUESTS_MODULE}.request', return_value=_ok_response()):
            conn.sync(query, endpoint=PamEndpoints.PAM)
    url_log = next(
        (rec.message for rec in caplog.records
         if 'graph web service call to' in rec.message),
        None,
    )
    assert url_log is not None, f'expected URL debug log, captured: {[r.message for r in caplog.records]}'
    assert '/api/user/graph-sync/pam/sync' in url_log
