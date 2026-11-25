#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""DAG.save(): a failed add_data batch must be sent again by the next save().

Before the fix save() cleared ``edge.modified`` while it built the payload, so after a failed batch
nothing was left dirty and the failed batch (and all later ones) were lost.
"""

import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from keepercommander.commands.pam_import.batch_pipeline import (
    PAM_DAG_SAVE_BATCH_COUNT_MIN, _is_graph_add_data_server_error, flush_deferred_graph,
)
from keepercommander.keeper_dag.exceptions import DAGConnectionException
from keepercommander.keeper_dag import DAG, EdgeType
from keepercommander.keeper_dag.connection import ConnectionBase
from keepercommander.keeper_dag.types import PamEndpoints, RefType


class FakeConnection(ConnectionBase):
    """Records the size of every add_data call; calls listed in ``fail_on`` raise."""

    def __init__(self):
        super().__init__(is_device=False, use_read_protobuf=True, use_write_protobuf=True)
        self.calls = []        # sizes of the batches that were ACCEPTED
        self.attempts = 0
        self.fail_on = set()   # attempt numbers (0 based) that fail

    def add_data(self, payload, graph_id=None, endpoint=None, agent=None):
        attempt = self.attempts
        self.attempts += 1
        if attempt in self.fail_on:
            raise RuntimeError('add_data 500')
        self.calls.append(len(payload.data))


def _dag(edges, batch_count):
    conn = FakeConnection()
    dag = DAG(conn=conn, key_bytes=os.urandom(32), name='t', write_endpoint=PamEndpoints.PAM,
              read_endpoint=PamEndpoints.PAM, save_batch_count=batch_count)
    root = dag.get_vertex(dag.uid) or dag.add_vertex(name='root', uid=dag.uid, vertex_type=RefType.PAM_NETWORK)
    for i in range(edges):
        dag.add_vertex(name=f'v{i}', vertex_type=RefType.PAM_MACHINE).belongs_to(root, edge_type=EdgeType.LINK)
    return dag, conn


def _dirty(dag):
    return sum(1 for v in dag.all_vertices for e in v.edges if e.modified)


def test_successful_save_clears_every_edge_and_a_second_save_sends_nothing():
    dag, conn = _dag(edges=7, batch_count=3)
    dag.save()
    assert conn.calls == [3, 3, 1]
    assert _dirty(dag) == 0
    dag.save()
    assert conn.calls == [3, 3, 1]


def test_failed_batch_and_the_batches_after_it_stay_dirty_and_are_sent_by_the_next_save():
    dag, conn = _dag(edges=7, batch_count=3)
    conn.fail_on = {1}                      # 2nd batch fails

    try:
        dag.save()
        raise AssertionError('save() should have raised')
    except RuntimeError:
        pass

    assert conn.calls == [3]                # only the first batch was accepted
    assert _dirty(dag) == 4                 # the failed batch (3) + the batch after it (1)

    dag.save()
    assert conn.calls == [3, 3, 1]          # the 4 unsent edges, in order; the 3 sent ones are NOT sent again
    assert _dirty(dag) == 0


def test_without_batching_a_failure_keeps_everything_dirty():
    dag, conn = _dag(edges=5, batch_count=0)
    conn.fail_on = {0}
    try:
        dag.save()
    except RuntimeError:
        pass
    assert conn.calls == [] and _dirty(dag) == 5
    dag.save()
    assert conn.calls == [5] and _dirty(dag) == 0


def test_flush_retries_with_a_smaller_batch_and_sends_every_edge_exactly_once():
    dag, conn = _dag(edges=100, batch_count=40)
    conn.fail_on = {1}                      # first save: batch 0 (40) ok, batch 1 fails
    tdag = SimpleNamespace(linking_dag=dag)

    flush_deferred_graph(tdag, MagicMock(), label='test flush')

    assert conn.calls[0] == 40
    assert dag.save_batch_count == 20       # halved once (40 -> 20), floor is PAM_DAG_SAVE_BATCH_COUNT_MIN
    assert dag.save_batch_count >= PAM_DAG_SAVE_BATCH_COUNT_MIN
    assert conn.calls[1:] == [20, 20, 20]   # the 60 edges not accepted yet
    assert sum(conn.calls) == 100           # nothing lost, nothing sent twice
    assert _dirty(dag) == 0


_URL = "https://connect.keepersecurity.com/api/user/graph-sync/pam/add_data"


@pytest.mark.parametrize("message", [
    f"Call to graph web service {_URL}, after 5 attempts, failed!: 500, Internal Server Error",
    f"Call to graph web service {_URL}, after 5 attempts, failed!: 502, Bad Gateway",
    f"Call to graph web service {_URL}, after 5 attempts, failed!: 503, Service Unavailable",
    f"Call to graph web service {_URL}, after 5 attempts, failed!: 504, Gateway Time-out",
    f"Call to graph web service {_URL}, after 5 attempts, failed!: HTTPSConnectionPool(host='x', port=443): "
    "Read timed out. (read timeout=30)",
    f"Call to graph web service {_URL}, after 5 attempts, failed!: ('Connection aborted.', "
    "RemoteDisconnected('Remote end closed connection without response'))",
    f"Call to graph web service {_URL}, after 5 attempts, failed!: ConnectionResetError(10054)",
])
def test_server_side_and_timeout_failures_are_retried_with_a_smaller_batch(message):
    assert _is_graph_add_data_server_error(DAGConnectionException(message))


@pytest.mark.parametrize("message", [
    f"Call to graph web service {_URL}, after 5 attempts, failed!: 400, Bad Request",
    f"Call to graph web service {_URL}, after 5 attempts, failed!: 403, Forbidden",
    f"Call to graph web service {_URL}, after 5 attempts, failed!: 401, Unauthorized",
])
def test_client_errors_are_not_retried(message):
    assert not _is_graph_add_data_server_error(DAGConnectionException(message))


def test_other_exceptions_count_only_when_they_name_add_data():
    assert _is_graph_add_data_server_error(RuntimeError("add_data 500"))
    assert _is_graph_add_data_server_error(RuntimeError("add_data timed out"))
    assert not _is_graph_add_data_server_error(RuntimeError("something else 500"))
    assert not _is_graph_add_data_server_error(ValueError("add_data bad value"))


def test_flush_retries_with_a_smaller_batch_after_a_timeout(caplog):
    dag, conn = _dag(edges=100, batch_count=40)
    real_add_data = conn.add_data
    state = {"calls": 0}

    def timing_out_add_data(payload, *args, **kwargs):
        state["calls"] += 1
        if state["calls"] == 2:
            raise DAGConnectionException(
                f"Call to graph web service {_URL}, after 5 attempts, failed!: Read timed out. (read timeout=30)")
        real_add_data(payload, *args, **kwargs)

    conn.add_data = timing_out_add_data

    with caplog.at_level("WARNING"):
        flush_deferred_graph(SimpleNamespace(linking_dag=dag), MagicMock(), label="timeout flush")

    assert dag.save_batch_count == 20
    assert sum(conn.calls) == 100
    assert _dirty(dag) == 0
    # the log names the elapsed time and the cause
    assert any("add_data failed after" in r.message and "Read timed out" in r.message for r in caplog.records)
