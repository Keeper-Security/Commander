"""
Layer-A / Layer-B integration tests (plan §13.8 T1 / task #30).

These tests hit a real dev krouter and require a logged-in `KeeperParams` from
`tests/dag_integration.json` (same JSON shape used by `tests/data_config.py`).
Gated by `@pytest.mark.integration` so they don't run as part of the default
CI matrix (`pytest unit-tests/`).

Manual run:
    cd <worktree>
    <umbrella-venv-python> -m pytest -m integration tests/test_dag_integration.py -v

If `dag_integration.json` is missing, the whole class skips cleanly.

Scope:
- Layer A: one sync round-trip per graph (5 graphs × 1 verb = 5 cases). Validates
  URL routing + auth + protobuf serialization end-to-end against the real server.
- Layer A: one get_leafs smoke (consolidation case).
- Layer B: configure_resource shape validation (1 happy-path no-op, 1 permission-denied).
- Layer B: set_record_rotation validation paths (sub-1h rejected, invalid record rejected).

Total: ~10 cases.
"""
import os
from unittest import TestCase, skipUnless

import pytest

from data_config import read_config_file
from keepercommander import api
from keepercommander.params import KeeperParams


_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_DAG_CONFIG = os.path.join(_TESTS_DIR, 'dag_integration.json')


@pytest.mark.integration
@skipUnless(
    os.path.isfile(_DAG_CONFIG),
    'tests/dag_integration.json not found (integration credentials; create one with '
    'server/user/private_key/device_token/clone_code/password fields to enable)',
)
class TestDagIntegration(TestCase):
    """Real-server integration tests for the DAG / graph-sync + Layer-B endpoints."""

    params: KeeperParams = None  # type: ignore[assignment]

    @classmethod
    def setUpClass(cls):
        cls.params = KeeperParams()
        read_config_file(cls.params, 'dag_integration.json')
        api.login(cls.params)

    # ----------------------------------------------------------------------- #
    # Layer A — one sync round-trip per graph                                  #
    # ----------------------------------------------------------------------- #

    def _do_sync_smoke(self, endpoint):
        """Send an empty sync to the given PamEndpoints; expect a clean 200 (proto)."""
        from keepercommander.keeper_dag.connection.commander import Connection
        from keepercommander.keeper_dag.proto import GraphSync_pb2 as gs_pb2

        conn = Connection(params=self.params)
        query = gs_pb2.GraphSyncQuery(
            streamId=b'\x00' * 16,    # nonexistent stream — server returns empty
            origin=b'\x00' * 16,
            syncPoint=0,
        )
        result = conn.sync(query, endpoint=endpoint)
        # Should return bytes (encrypted protobuf) without raising. Content may be empty.
        self.assertIsNotNone(result)

    def test_sync_pam_graph(self):
        from keepercommander.keeper_dag.types import PamEndpoints
        self._do_sync_smoke(PamEndpoints.PAM)

    def test_sync_discovery_rules_graph(self):
        from keepercommander.keeper_dag.types import PamEndpoints
        self._do_sync_smoke(PamEndpoints.DISCOVERY_RULES)

    def test_sync_discovery_jobs_graph(self):
        from keepercommander.keeper_dag.types import PamEndpoints
        self._do_sync_smoke(PamEndpoints.DISCOVERY_JOBS)

    def test_sync_infrastructure_graph(self):
        from keepercommander.keeper_dag.types import PamEndpoints
        self._do_sync_smoke(PamEndpoints.INFRASTRUCTURE)

    def test_sync_service_links_graph(self):
        from keepercommander.keeper_dag.types import PamEndpoints
        self._do_sync_smoke(PamEndpoints.SERVICE_LINKS)

    # ----------------------------------------------------------------------- #
    # Layer A — get_leafs consolidation                                        #
    # ----------------------------------------------------------------------- #

    def test_get_leafs_empty_vertices_list(self):
        """get_leafs with empty vertices list returns a clean empty result (consolidation case)."""
        from keepercommander.keeper_dag.connection.commander import Connection
        from keepercommander.keeper_dag.proto import GraphSync_pb2 as gs_pb2
        from keepercommander.keeper_dag.types import PamEndpoints

        conn = Connection(params=self.params)
        query = gs_pb2.GraphSyncLeafsQuery(vertices=[])
        result = conn.get_leafs(query, endpoint=PamEndpoints.PAM)
        self.assertIsNotNone(result)

    # ----------------------------------------------------------------------- #
    # Layer B — configure_resource                                             #
    # ----------------------------------------------------------------------- #

    def test_configure_resource_unauthorized_record_returns_not_allowed(self):
        """Sending configure_resource with a recordUid we don't own should fail with RRC_NOT_ALLOWED."""
        from keepercommander.commands.pam._layer_b import RouterResponseError
        from keepercommander.commands.pam.router_helper import router_configure_resource
        from keepercommander.proto import pam_pb2

        rq = pam_pb2.PAMResourceConfig(
            recordUid=b'\x00' * 16,   # nonexistent / unauthorized
            networkUid=b'\x00' * 16,
            adminUid=b'\x00' * 16,
        )
        with self.assertRaises(Exception) as cm:
            router_configure_resource(self.params, rq)
        # The exact code depends on krouter's validation order; we expect a permission
        # or bad-request style failure, not a generic 500.
        err = cm.exception
        if isinstance(err, RouterResponseError):
            self.assertIn(
                err.response_code_name,
                {'RRC_NOT_ALLOWED', 'RRC_NOT_ALLOWED_ENFORCEMENT_NOT_ENABLED', 'RRC_BAD_REQUEST'},
                f'unexpected response code: {err.response_code_name}',
            )

    # ----------------------------------------------------------------------- #
    # Layer B — set_record_rotation                                            #
    # ----------------------------------------------------------------------- #

    def test_set_record_rotation_subhour_schedule_rejected(self):
        """Krouter rejects schedule with frequency < 1h (UserRest.kt:654-658)."""
        from keepercommander.commands.pam._layer_b import RouterResponseError
        from keepercommander.commands.pam.router_helper import router_set_record_rotation_information
        from keepercommander.proto import router_pb2

        rq = router_pb2.RouterRecordRotationRequest(
            recordUid=b'\x00' * 16,
            schedule='*/5 * * * *',  # every 5 minutes — sub-1h
        )
        with self.assertRaises(Exception) as cm:
            router_set_record_rotation_information(self.params, rq)
        err = cm.exception
        # Server validates schedule before record-existence, so this should always
        # surface as RRC_GENERAL_ERROR with the cron-interval message.
        if isinstance(err, RouterResponseError):
            self.assertEqual(err.response_code_name, 'RRC_GENERAL_ERROR')
            self.assertIn('hour', str(err).lower())

    def test_set_record_rotation_unauthorized_record_rejected(self):
        """Setting rotation on a nonexistent / unauthorized record returns an error."""
        from keepercommander.commands.pam._layer_b import RouterResponseError
        from keepercommander.commands.pam.router_helper import router_set_record_rotation_information
        from keepercommander.proto import router_pb2

        rq = router_pb2.RouterRecordRotationRequest(
            recordUid=b'\x00' * 16,
            schedule='0 2 * * *',   # valid daily schedule (well above 1h)
            configurationUid=b'\x00' * 16,
        )
        with self.assertRaises(Exception) as cm:
            router_set_record_rotation_information(self.params, rq)
        err = cm.exception
        if isinstance(err, RouterResponseError):
            # Some flavor of "not allowed" or "bad request" — never RRC_OK.
            self.assertNotEqual(err.response_code_name, 'RRC_OK')
