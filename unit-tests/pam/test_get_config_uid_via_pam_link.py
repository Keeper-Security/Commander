"""
Unit tests for tunnel_helpers.get_config_uid_via_pam_link — the KRouter
graph-sync/pam/get_leafs fallback used by `pam connection edit` when the
legacy get_leafs lookup misses. Mirrors the web vault's
`getMultiLeafsPamLinkDag` call (see vault/js/lib/api/pam/api-dag-pam-link.ts).
"""

import unittest
from unittest import mock

skip_tests = False
skip_reason = ""
try:
    from keepercommander.commands.tunnel.port_forward.tunnel_helpers import get_config_uid_via_pam_link
    from keepercommander.keeper_dag.proto import GraphSync_pb2 as gs_pb2
    from keepercommander import utils
except ImportError as e:
    skip_tests = True
    skip_reason = f"Cannot import tunnel_helpers/GraphSync_pb2: {e}"


@unittest.skipIf(skip_tests, skip_reason)
class TestGetConfigUidViaPamLink(unittest.TestCase):
    def setUp(self):
        self.params = mock.MagicMock()
        self.record_uid = 'AAAAAAAAAAAAAAAAAAAAAA'  # roundtrip-safe base64url for 16 bytes
        self.config_uid = 'AQEBAQEBAQEBAQEBAQEBAQ'  # roundtrip-safe base64url for 16 bytes

    @mock.patch('keepercommander.commands.pam.router_helper._post_request_to_router')
    def test_returns_config_uid_on_single_ref(self, mock_post):
        cfg_bytes = utils.base64_url_decode(self.config_uid)
        mock_post.return_value = gs_pb2.GraphSyncRefsResult(
            refs=[gs_pb2.GraphSyncRef(type=gs_pb2.RFT_PAM_NETWORK, value=cfg_bytes, name='')]
        )
        result = get_config_uid_via_pam_link(self.params, self.record_uid)
        self.assertEqual(result, self.config_uid)
        # Verify endpoint + query shape
        args, kwargs = mock_post.call_args
        self.assertEqual(args[1], 'graph-sync/pam/get_leafs')
        rq = kwargs.get('rq_proto') or args[2]
        self.assertEqual(len(rq.vertices), 1)
        self.assertEqual(rq.vertices[0], utils.base64_url_decode(self.record_uid))

    @mock.patch('keepercommander.commands.pam.router_helper._post_request_to_router')
    def test_returns_empty_string_when_no_refs(self, mock_post):
        mock_post.return_value = gs_pb2.GraphSyncRefsResult(refs=[])
        self.assertEqual(get_config_uid_via_pam_link(self.params, self.record_uid), '')

    @mock.patch('keepercommander.commands.pam.router_helper._post_request_to_router')
    def test_returns_empty_string_when_response_is_none(self, mock_post):
        mock_post.return_value = None
        self.assertEqual(get_config_uid_via_pam_link(self.params, self.record_uid), '')

    @mock.patch('keepercommander.commands.pam.router_helper._post_request_to_router')
    def test_skips_refs_with_empty_value(self, mock_post):
        cfg_bytes = utils.base64_url_decode(self.config_uid)
        mock_post.return_value = gs_pb2.GraphSyncRefsResult(refs=[
            gs_pb2.GraphSyncRef(type=gs_pb2.RFT_PAM_NETWORK, value=b'', name=''),
            gs_pb2.GraphSyncRef(type=gs_pb2.RFT_PAM_NETWORK, value=cfg_bytes, name=''),
        ])
        self.assertEqual(get_config_uid_via_pam_link(self.params, self.record_uid), self.config_uid)

    @mock.patch('keepercommander.commands.pam.router_helper._post_request_to_router')
    def test_swallows_exceptions_and_returns_empty(self, mock_post):
        mock_post.side_effect = RuntimeError('krouter unreachable')
        self.assertEqual(get_config_uid_via_pam_link(self.params, self.record_uid), '')


if __name__ == '__main__':
    unittest.main()
