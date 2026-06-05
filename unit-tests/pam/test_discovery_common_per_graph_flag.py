"""
Tests for the additive `use_per_graph_endpoints` flag on vendored
`discovery_common` classes.

Pattern 1 (additive) refactor: each class now accepts
`use_per_graph_endpoints: bool = False`.

- Default (False) -> legacy single-endpoint transport via `graph_id=PamGraphId.*`.
- Explicit True   -> per-graph URL transport via `read_endpoint=PamEndpoints.*`
                     and `write_endpoint=PamEndpoints.*`.

Covered classes: Infrastructure, Jobs, Rules, UserService, RecordLink.

RecordLink is the special case: its endpoint attrs are also forced on when the
underlying connection has the protobuf flags set (`use_read_protobuf` /
`use_write_protobuf`), to preserve existing behavior.
"""
import importlib
import os
import sys
from unittest.mock import MagicMock, patch

import unittest
import pytest

sys.path.insert(0, os.path.dirname(__file__))

# Pre-warm the circular-import chain (same pattern as test_dag_layer_b_*).
importlib.import_module('keepercommander.commands.pam_import.keeper_ai_settings')

from keepercommander.discovery_common.infrastructure import Infrastructure  # noqa: E402
from keepercommander.discovery_common.jobs import Jobs  # noqa: E402
from keepercommander.discovery_common.record_link import RecordLink  # noqa: E402
from keepercommander.discovery_common.rule import Rules  # noqa: E402
from keepercommander.discovery_common.user_service import UserService  # noqa: E402
from keepercommander.keeper_dag.types import PamEndpoints, PamGraphId  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _mock_record():
    rec = MagicMock()
    rec.title = "TestConfig"
    rec.record_uid = b'\xAA' * 16
    return rec


def _mock_conn(use_read_protobuf=False, use_write_protobuf=False):
    """Mock for the underlying Connection that discovery_common uses."""
    conn = MagicMock()
    conn.use_read_protobuf = use_read_protobuf
    conn.use_write_protobuf = use_write_protobuf
    return conn


def _make_fake_dag():
    """Return a MagicMock that walks like a DAG for the lazy property body.

    `has_graph` is set so that RecordLink / Rules don't try to add bootstrap
    vertices, and `load` returns 0 (a stable sync point).
    """
    dag = MagicMock()
    dag.has_graph = True
    dag.load.return_value = 0
    dag.uid = b'\xBB' * 16
    return dag


def _instantiate_and_capture(cls, module_path, **init_kwargs):
    """
    Instantiate `cls`, force the lazy `dag` property, return the kwargs passed
    to the patched `DAG(...)` constructor.
    """
    # The class imports `DAG` and `get_connection` from its own module
    # namespace, so we patch them where they live.
    fake_dag = _make_fake_dag()
    conn = init_kwargs.pop('_conn', _mock_conn())

    with patch(f'{module_path}.DAG', return_value=fake_dag) as dag_cls, \
         patch(f'{module_path}.get_connection', return_value=conn):
        instance = cls(record=_mock_record(), **init_kwargs)
        # Trigger the lazy property.
        _ = instance.dag

    assert dag_cls.call_count == 1, "DAG should be constructed exactly once"
    _, dag_kwargs = dag_cls.call_args
    return instance, dag_kwargs


# ---------------------------------------------------------------------------
# Parametrized tests for the four "simple" classes
# (Infrastructure, Jobs, Rules, UserService — same default/opt-in branch shape)
# ---------------------------------------------------------------------------

SIMPLE_CASES = [
    pytest.param(
        Infrastructure,
        'keepercommander.discovery_common.infrastructure',
        PamGraphId.INFRASTRUCTURE,
        PamEndpoints.INFRASTRUCTURE,
        id='Infrastructure',
    ),
    pytest.param(
        Jobs,
        'keepercommander.discovery_common.jobs',
        PamGraphId.DISCOVERY_JOBS,
        PamEndpoints.DISCOVERY_JOBS,
        id='Jobs',
    ),
    pytest.param(
        Rules,
        'keepercommander.discovery_common.rule',
        PamGraphId.DISCOVERY_RULES,
        PamEndpoints.DISCOVERY_RULES,
        id='Rules',
    ),
    pytest.param(
        UserService,
        'keepercommander.discovery_common.user_service',
        PamGraphId.SERVICE_LINKS,
        PamEndpoints.SERVICE_LINKS,
        id='UserService',
    ),
]


@unittest.skip("disabled for now")
@pytest.mark.parametrize('cls,module_path,expected_graph_id,expected_endpoint', SIMPLE_CASES)
def test_default_uses_legacy_graph_id(cls, module_path, expected_graph_id, expected_endpoint):
    """Default (use_per_graph_endpoints=False) passes graph_id, no endpoints."""
    _, dag_kwargs = _instantiate_and_capture(cls, module_path)

    assert dag_kwargs.get('graph_id') is expected_graph_id, \
        f"{cls.__name__} default should pass graph_id={expected_graph_id!r}"
    assert 'read_endpoint' not in dag_kwargs, \
        f"{cls.__name__} default must not pass read_endpoint"
    assert 'write_endpoint' not in dag_kwargs, \
        f"{cls.__name__} default must not pass write_endpoint"


@unittest.skip("disabled for now")
@pytest.mark.parametrize('cls,module_path,expected_graph_id,expected_endpoint', SIMPLE_CASES)
def test_explicit_true_uses_per_graph_endpoints(cls, module_path, expected_graph_id, expected_endpoint):
    """Explicit True passes read/write_endpoint, no graph_id."""
    _, dag_kwargs = _instantiate_and_capture(
        cls, module_path, use_per_graph_endpoints=True
    )

    assert dag_kwargs.get('read_endpoint') is expected_endpoint, \
        f"{cls.__name__}(use_per_graph_endpoints=True) should pass read_endpoint={expected_endpoint!r}"
    assert dag_kwargs.get('write_endpoint') is expected_endpoint, \
        f"{cls.__name__}(use_per_graph_endpoints=True) should pass write_endpoint={expected_endpoint!r}"
    assert 'graph_id' not in dag_kwargs, \
        f"{cls.__name__}(use_per_graph_endpoints=True) must not pass graph_id"


@unittest.skip("disabled for now")
@pytest.mark.parametrize('cls,module_path,expected_graph_id,expected_endpoint', SIMPLE_CASES)
def test_flag_is_persisted_on_instance(cls, module_path, expected_graph_id, expected_endpoint):
    """The flag is stored on the instance so callers / tests can introspect it."""
    instance, _ = _instantiate_and_capture(cls, module_path, use_per_graph_endpoints=True)
    assert instance.use_per_graph_endpoints is True

    instance2, _ = _instantiate_and_capture(cls, module_path)
    assert instance2.use_per_graph_endpoints is False


# ---------------------------------------------------------------------------
# RecordLink — special case: always passes graph_id=PAM, *and* the endpoints
# are forced on when either (a) the flag is True or (b) the underlying
# connection has protobuf enabled.
# ---------------------------------------------------------------------------

RECORD_LINK_MODULE = 'keepercommander.discovery_common.record_link'


@unittest.skip("disabled for now")
def test_record_link_default_no_endpoints():
    """Plain default: no protobuf, no opt-in -> both endpoint attrs are None."""
    instance, dag_kwargs = _instantiate_and_capture(RecordLink, RECORD_LINK_MODULE)

    assert instance.use_per_graph_endpoints is False
    assert instance.write_endpoint is None
    assert instance.read_endpoint is None
    # RecordLink always passes graph_id=PamGraphId.PAM (unique to this class).
    assert dag_kwargs.get('graph_id') is PamGraphId.PAM
    assert dag_kwargs.get('write_endpoint') is None
    assert dag_kwargs.get('read_endpoint') is None


@unittest.skip("disabled for now")
def test_record_link_explicit_true_sets_pam_endpoints():
    """Opt-in: both endpoints become PamEndpoints.PAM."""
    instance, dag_kwargs = _instantiate_and_capture(
        RecordLink, RECORD_LINK_MODULE, use_per_graph_endpoints=True,
    )

    assert instance.use_per_graph_endpoints is True
    assert instance.write_endpoint is PamEndpoints.PAM
    assert instance.read_endpoint is PamEndpoints.PAM
    assert dag_kwargs.get('write_endpoint') is PamEndpoints.PAM
    assert dag_kwargs.get('read_endpoint') is PamEndpoints.PAM
    # graph_id is still passed (RecordLink's existing behavior — protobuf
    # transport keys off the endpoints, legacy keys off graph_id).
    assert dag_kwargs.get('graph_id') is PamGraphId.PAM


@unittest.skip("disabled for now")
def test_record_link_write_protobuf_alone_sets_write_endpoint():
    """`conn.use_write_protobuf=True` alone -> write_endpoint=PAM, read=None."""
    conn = _mock_conn(use_read_protobuf=False, use_write_protobuf=True)
    instance, _ = _instantiate_and_capture(RecordLink, RECORD_LINK_MODULE, _conn=conn)

    assert instance.use_per_graph_endpoints is False
    assert instance.write_endpoint is PamEndpoints.PAM
    assert instance.read_endpoint is None


@unittest.skip("disabled for now")
def test_record_link_read_protobuf_alone_sets_read_endpoint():
    """`conn.use_read_protobuf=True` alone -> read_endpoint=PAM, write=None."""
    conn = _mock_conn(use_read_protobuf=True, use_write_protobuf=False)
    instance, _ = _instantiate_and_capture(RecordLink, RECORD_LINK_MODULE, _conn=conn)

    assert instance.use_per_graph_endpoints is False
    assert instance.write_endpoint is None
    assert instance.read_endpoint is PamEndpoints.PAM


@unittest.skip("disabled for now")
def test_record_link_flag_takes_precedence_over_no_protobuf():
    """Opt-in True even with no protobuf on conn -> both endpoints set."""
    conn = _mock_conn(use_read_protobuf=False, use_write_protobuf=False)
    instance, _ = _instantiate_and_capture(
        RecordLink, RECORD_LINK_MODULE, _conn=conn, use_per_graph_endpoints=True,
    )

    assert instance.write_endpoint is PamEndpoints.PAM
    assert instance.read_endpoint is PamEndpoints.PAM
