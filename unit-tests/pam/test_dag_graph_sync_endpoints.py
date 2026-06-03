"""
Layer-A graph-sync endpoint tests (plan §13.2).

Covers the URL routing migration from the legacy `/api/user/<verb>` endpoint to
the per-graph `/api/user/graph-sync/<graph>/<verb>` routes that landed in krouter's
DAGRest.kt. Five graphs (pam, discovery_rules, discovery_jobs, infrastructure,
service_links) crossed with four verbs (add_data, sync, multi_sync, get_leafs)
= 20 routes; backward-compat and device-side variants verified separately.

Mock seam: `keepercommander.keeper_dag.connection.commander.requests.request` for
end-to-end URL assertions, and direct `ConnectionBase._endpoint(...)` calls for
the URL-builder unit tests.
"""
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Make _dag_fixtures importable when pytest discovers the test from the repo root.
sys.path.insert(0, os.path.dirname(__file__))
import _dag_fixtures  # noqa: E402

from keepercommander.keeper_dag.connection import ConnectionBase  # noqa: E402
from keepercommander.keeper_dag.types import (  # noqa: E402
    ENDPOINT_TO_GRAPH_ID_MAP,
    GRAPH_ID_TO_ENDPOINT,
    PamEndpoints,
    PamGraphId,
)

REQUESTS_MODULE = 'keepercommander.keeper_dag.connection.commander.requests'


# --------------------------------------------------------------------------- #
# URL builder tests — the direct verification that PamEndpoints values map to  #
# the right URL path segment.                                                  #
# --------------------------------------------------------------------------- #


def _make_user_conn() -> ConnectionBase:
    return ConnectionBase(is_device=False, logger=MagicMock())


def _make_device_conn() -> ConnectionBase:
    return ConnectionBase(is_device=True, logger=MagicMock())


@pytest.mark.parametrize('endpoint_enum, graph_token', _dag_fixtures.ALL_GRAPHS)
@pytest.mark.parametrize('verb', _dag_fixtures.ALL_VERBS)
def test_user_endpoint_routes_per_graph(endpoint_enum, graph_token, verb):
    """20 cases: every (graph, verb) hits /api/user/graph-sync/<graph>/<verb>."""
    conn = _make_user_conn()
    url = conn._endpoint(action='/' + verb, endpoint=endpoint_enum)
    assert url == f'/api/user/graph-sync/{graph_token}/{verb}', (
        f'PamEndpoints.{endpoint_enum.name} + {verb} -> {url!r}'
    )


@pytest.mark.parametrize('endpoint_enum, graph_token', _dag_fixtures.ALL_GRAPHS)
@pytest.mark.parametrize('verb', _dag_fixtures.ALL_VERBS)
def test_device_endpoint_routes_per_graph(endpoint_enum, graph_token, verb):
    """20 cases (Gateway perspective): /api/device/graph-sync/<graph>/<verb>."""
    conn = _make_device_conn()
    url = conn._endpoint(action='/' + verb, endpoint=endpoint_enum)
    assert url == f'/api/device/graph-sync/{graph_token}/{verb}'


@pytest.mark.parametrize('verb', _dag_fixtures.ALL_VERBS)
def test_legacy_user_path_when_no_endpoint(verb):
    """Backward compat: no endpoint -> /api/user/<verb> (legacy generic route)."""
    conn = _make_user_conn()
    url = conn._endpoint(action='/' + verb, endpoint=None)
    assert url == f'/api/user/{verb}'


@pytest.mark.parametrize('verb', _dag_fixtures.ALL_VERBS)
def test_legacy_device_path_when_no_endpoint(verb):
    """Backward compat (Gateway): /api/device/<verb> when endpoint=None."""
    conn = _make_device_conn()
    url = conn._endpoint(action='/' + verb, endpoint=None)
    assert url == f'/api/device/{verb}'


def test_endpoint_accepts_raw_string_form():
    """_endpoint() must tolerate the raw string form (not just the enum)."""
    conn = _make_user_conn()
    url = conn._endpoint(action='/sync', endpoint=PamEndpoints.PAM.value)
    assert url == '/api/user/graph-sync/pam/sync'


def test_endpoint_normalizes_slashes():
    """_endpoint() should produce a single-slash URL regardless of input slash count."""
    conn = _make_user_conn()
    url = conn._endpoint(action='sync', endpoint='/graph-sync/pam/')
    assert url == '/api/user/graph-sync/pam/sync'


# --------------------------------------------------------------------------- #
# Inverse-map symmetry: GRAPH_ID_TO_ENDPOINT and ENDPOINT_TO_GRAPH_ID_MAP must  #
# round-trip cleanly. Catches a future drift between the two maps.             #
# --------------------------------------------------------------------------- #


def test_graph_id_endpoint_maps_are_inverses():
    """Every graph_id maps back to its PamEndpoints value and vice versa."""
    for endpoint_str, graph_id in ENDPOINT_TO_GRAPH_ID_MAP.items():
        assert GRAPH_ID_TO_ENDPOINT[graph_id].value == endpoint_str
    for graph_id, endpoint_enum in GRAPH_ID_TO_ENDPOINT.items():
        assert ENDPOINT_TO_GRAPH_ID_MAP[endpoint_enum.value] == graph_id


def test_all_pam_graph_ids_are_routable():
    """Every PamGraphId value must have a GRAPH_ID_TO_ENDPOINT entry."""
    for graph in PamGraphId:
        assert graph.value in GRAPH_ID_TO_ENDPOINT, (
            f'PamGraphId.{graph.name} has no endpoint mapping'
        )


def test_all_pam_endpoints_are_routable():
    """Every PamEndpoints value must have an ENDPOINT_TO_GRAPH_ID_MAP entry."""
    for endpoint in PamEndpoints:
        assert endpoint.value in ENDPOINT_TO_GRAPH_ID_MAP


# --------------------------------------------------------------------------- #
# End-to-end smoke: through the Commander Connection class, verify that the    #
# URL actually sent to `requests.request` matches the expected pattern.        #
# Uses a fully stubbed Connection to skip crypto setup.                        #
# --------------------------------------------------------------------------- #


def _build_stubbed_commander_connection():
    """Build a Commander Connection with crypto bypassed for end-to-end URL assertions."""
    from keepercommander.keeper_dag.connection.commander import Connection

    params = MagicMock()
    params.config = {'server': 'krouter.test'}

    # Bypass dag_server_url's hostname derivation; force a deterministic host.
    os.environ['KROUTER_URL'] = 'https://krouter.test'
    os.environ['VERIFY_SSL'] = 'false'

    conn = Connection(params=params, verify_ssl=False)

    # Skip the encryption pipeline — payload_and_headers normally encrypts the
    # protobuf body with the transmission key. Tests only need to verify the URL,
    # so return the raw serialized proto and a minimal header dict.
    def _stub_payload_and_headers(payload):
        body = payload.SerializeToString() if hasattr(payload, 'SerializeToString') else payload
        return body, {'Content-Type': 'application/octet-stream'}

    conn.payload_and_headers = _stub_payload_and_headers
    conn.transmission_key = b'\x00' * 32
    return conn


def _ok_response():
    rsp = MagicMock()
    rsp.status_code = 200
    rsp.content = b''
    rsp.raise_for_status.return_value = None
    return rsp


@pytest.mark.parametrize('endpoint_enum, graph_token', _dag_fixtures.ALL_GRAPHS)
def test_sync_end_to_end_url(endpoint_enum, graph_token):
    """sync() with endpoint=PamEndpoints.X hits /api/user/graph-sync/<graph>/sync."""
    conn = _build_stubbed_commander_connection()
    query = _dag_fixtures.make_sync_query()
    with patch(f'{REQUESTS_MODULE}.request', return_value=_ok_response()) as mock_req:
        conn.sync(query, endpoint=endpoint_enum)
    sent_url = mock_req.call_args.kwargs['url']
    assert sent_url == f'https://krouter.test/api/user/graph-sync/{graph_token}/sync'


@pytest.mark.parametrize('endpoint_enum, graph_token', _dag_fixtures.ALL_GRAPHS)
def test_add_data_end_to_end_url(endpoint_enum, graph_token):
    """add_data() with endpoint=PamEndpoints.X hits .../add_data."""
    conn = _build_stubbed_commander_connection()
    req = _dag_fixtures.make_add_data_request()
    with patch(f'{REQUESTS_MODULE}.request', return_value=_ok_response()) as mock_req:
        conn.add_data(req, endpoint=endpoint_enum)
    sent_url = mock_req.call_args.kwargs['url']
    assert sent_url == f'https://krouter.test/api/user/graph-sync/{graph_token}/add_data'


def test_end_to_end_sends_protobuf_bytes_not_json():
    """Wire-format gate: the body sent is the protobuf serialization, not JSON."""
    conn = _build_stubbed_commander_connection()
    query = _dag_fixtures.make_sync_query(stream_id=b'A' * 16, sync_point=42)
    with patch(f'{REQUESTS_MODULE}.request', return_value=_ok_response()) as mock_req:
        conn.sync(query, endpoint=PamEndpoints.PAM)
    sent_body = mock_req.call_args.kwargs['data']
    # Body should be raw bytes (protobuf), not a JSON-encoded string.
    assert isinstance(sent_body, (bytes, bytearray))
    # Round-trip parse to confirm it's a valid GraphSyncQuery proto with the right fields.
    from keepercommander.keeper_dag.proto import GraphSync_pb2 as gs_pb2
    parsed = gs_pb2.GraphSyncQuery()
    parsed.ParseFromString(bytes(sent_body))
    assert parsed.streamId == b'A' * 16
    assert parsed.syncPoint == 42
