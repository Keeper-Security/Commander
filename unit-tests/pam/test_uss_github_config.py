"""
Unit tests for the Universal Secrets Sync (USS) GitHub configuration fields on
`pam universal-sync-config add / edit / list`.

Covers the nested `GitHubConfig` shape documented in krouter's
`docs/User API/ConfigureUniversalSync.md`: GitHub's scope/owner/organizationVisibility/repos
live under a single `github` message field on `PAMUniversalSyncConfig`, not as flat fields.
"""
import json
import unittest
from unittest import mock

from keepercommander import crypto, utils, vault
from keepercommander.commands.universalsecretsync import (
    PAMUniversalSyncConfigAddCommand,
    PAMUniversalSyncConfigEditCommand,
    PAMUniversalSyncConfigListCommand,
)
from keepercommander.proto import pam_pb2

NETWORK_UID = 'AAAAAAAAAAAAAAAAAAAAAA'  # roundtrip-safe base64url, 22 chars
RECORD_KEY = bytes(range(16))
FAKE_TOKENS = (b'enc-session-token', b'enc-transmission-key', b'transmission-key')


def _make_network_record(record_type='pamGitHubConfiguration'):
    network = vault.TypedRecord()
    network.record_uid = NETWORK_UID
    network.record_key = RECORD_KEY
    network.title = 'GitHub Network'
    network.type_name = record_type
    return network


class FakeEdge:
    def __init__(self, path, head_uid, content=None):
        self.path = path
        self.head_uid = head_uid
        self._content = content

    @property
    def content_as_dict(self):
        return self._content


class FakeVertex:
    def __init__(self, uid, edges=None, child_vertices=None):
        self.uid = uid
        self.edges = edges or []
        self._child_vertices = child_vertices or []

    def has_vertices(self, *_args, **_kwargs):
        return self._child_vertices


def _patch_dag(existing_config=None):
    """Build mock DAG/Connection classes matching the lazy `from ..keeper_dag import DAG`
    imports inside universalsecretsync.py. Returns (dag_class, connection_class, root)."""
    root = FakeVertex(uid=NETWORK_UID)
    if existing_config is not None:
        root.edges = [FakeEdge('universal_sync', head_uid=NETWORK_UID, content=existing_config)]

    dag_instance = mock.MagicMock()
    dag_instance.get_root = root
    dag_instance.load.return_value = None

    dag_class = mock.MagicMock(return_value=dag_instance)
    connection_class = mock.MagicMock()
    return dag_class, connection_class, root


class TestPAMUniversalSyncConfigAddCommand(unittest.TestCase):
    def setUp(self):
        self.params = mock.MagicMock()
        self.network = _make_network_record()
        mock.patch('keepercommander.commands.universalsecretsync.get_keeper_tokens',
                   return_value=FAKE_TOKENS).start()
        mock.patch('keepercommander.vault.KeeperRecord.load', return_value=self.network).start()
        self.mock_router = mock.patch(
            'keepercommander.commands.universalsecretsync.router_helper.router_configure_universal_sync').start()
        self.addCleanup(mock.patch.stopall)

    def _execute(self, **kwargs):
        kwargs.setdefault('network', NETWORK_UID)
        kwargs.setdefault('enabled', 'true')
        kwargs.setdefault('dry_run', 'false')
        PAMUniversalSyncConfigAddCommand().execute(self.params, **kwargs)
        self.assertEqual(self.mock_router.call_count, 1)
        return self.mock_router.call_args[0][1]

    def test_writes_github_config_under_nested_field(self):
        rq = self._execute(scope='organization', owner='my-org', org_visibility='selected',
                           repo=['repo-a', 'repo-b'])

        self.assertTrue(rq.HasField('github'))
        self.assertEqual(rq.github.scope, pam_pb2.ORGANIZATION)
        self.assertEqual(rq.github.organizationVisibility, pam_pb2.SELECTED)
        self.assertEqual(crypto.decrypt_aes_v2(rq.github.owner, RECORD_KEY), b'my-org')

        self.assertEqual(len(rq.github.repos), 2)
        decrypted_repos = [crypto.decrypt_aes_v2(r.name, RECORD_KEY).decode('utf-8') for r in rq.github.repos]
        self.assertEqual(decrypted_repos, ['repo-a', 'repo-b'])

    def test_repository_scope_maps_correctly(self):
        rq = self._execute(scope='repository', owner='my-user')
        self.assertEqual(rq.github.scope, pam_pb2.REPOSITORY)

    def test_no_github_flags_leaves_github_field_unset(self):
        rq = self._execute()
        self.assertFalse(rq.HasField('github'))

    def test_flat_fields_no_longer_exist_on_the_message(self):
        rq = pam_pb2.PAMUniversalSyncConfig()
        for flat_field in ('scope', 'owner', 'organizationVisibility', 'repos'):
            with self.assertRaises(AttributeError):
                getattr(rq, flat_field)


class TestPAMUniversalSyncConfigEditCommand(unittest.TestCase):
    def setUp(self):
        self.params = mock.MagicMock()
        self.network = _make_network_record()
        mock.patch('keepercommander.commands.universalsecretsync.get_keeper_tokens',
                   return_value=FAKE_TOKENS).start()
        mock.patch('keepercommander.vault.KeeperRecord.load', return_value=self.network).start()
        self.mock_router = mock.patch(
            'keepercommander.commands.universalsecretsync.router_helper.router_configure_universal_sync').start()
        self.addCleanup(mock.patch.stopall)

    @staticmethod
    def _existing_github_config(repo_names, scope=pam_pb2.REPOSITORY, org_visibility=pam_pb2.PRIVATE,
                                owner='existing-owner'):
        encrypted_owner = crypto.encrypt_aes_v2(owner.encode('utf-8'), RECORD_KEY)
        repos_b64 = [utils.base64_url_encode(crypto.encrypt_aes_v2(name.encode('utf-8'), RECORD_KEY))
                    for name in repo_names]
        return {
            'scope': scope,
            'owner': utils.base64_url_encode(encrypted_owner),
            'organizationVisibility': org_visibility,
            'repos': repos_b64,
        }

    def _execute_with_dag(self, existing_config, **kwargs):
        dag_class, connection_class, _root = _patch_dag(existing_config)
        kwargs.setdefault('network', NETWORK_UID)
        with mock.patch('keepercommander.keeper_dag.DAG', dag_class), \
             mock.patch('keepercommander.keeper_dag.connection.commander.Connection', connection_class):
            PAMUniversalSyncConfigEditCommand().execute(self.params, **kwargs)
        # Guard against the broad try/except in the command silently swallowing a bad mock wire-up.
        self.assertEqual(dag_class.call_count, 1)
        self.assertEqual(self.mock_router.call_count, 1)
        return self.mock_router.call_args[0][1]

    def test_preserves_existing_github_config_when_not_overridden(self):
        existing = {'github': self._existing_github_config(['repo-1', 'repo-2'])}
        rq = self._execute_with_dag(existing)

        self.assertTrue(rq.HasField('github'))
        self.assertEqual(rq.github.scope, pam_pb2.REPOSITORY)
        self.assertEqual(rq.github.organizationVisibility, pam_pb2.PRIVATE)
        self.assertEqual(crypto.decrypt_aes_v2(rq.github.owner, RECORD_KEY), b'existing-owner')
        decrypted = [crypto.decrypt_aes_v2(r.name, RECORD_KEY).decode('utf-8') for r in rq.github.repos]
        self.assertEqual(decrypted, ['repo-1', 'repo-2'])

    def test_overrides_take_precedence_over_existing(self):
        existing = {'github': self._existing_github_config(['old-repo'])}
        rq = self._execute_with_dag(existing, scope='organization', owner='new-owner',
                                    org_visibility='all', repo=['new-repo'])

        self.assertEqual(rq.github.scope, pam_pb2.ORGANIZATION)
        self.assertEqual(rq.github.organizationVisibility, pam_pb2.ALL)
        self.assertEqual(crypto.decrypt_aes_v2(rq.github.owner, RECORD_KEY), b'new-owner')
        decrypted = [crypto.decrypt_aes_v2(r.name, RECORD_KEY).decode('utf-8') for r in rq.github.repos]
        self.assertEqual(decrypted, ['new-repo'])

    def test_partial_override_preserves_the_rest(self):
        # Only --owner is overridden; scope/org-visibility/repos should carry forward.
        existing = {'github': self._existing_github_config(['repo-1'], scope=pam_pb2.ORGANIZATION,
                                                            org_visibility=pam_pb2.SELECTED)}
        rq = self._execute_with_dag(existing, owner='new-owner')

        self.assertEqual(crypto.decrypt_aes_v2(rq.github.owner, RECORD_KEY), b'new-owner')
        self.assertEqual(rq.github.scope, pam_pb2.ORGANIZATION)
        self.assertEqual(rq.github.organizationVisibility, pam_pb2.SELECTED)
        decrypted = [crypto.decrypt_aes_v2(r.name, RECORD_KEY).decode('utf-8') for r in rq.github.repos]
        self.assertEqual(decrypted, ['repo-1'])

    def test_no_existing_and_no_override_leaves_github_unset(self):
        rq = self._execute_with_dag(None)
        self.assertFalse(rq.HasField('github'))


class TestPAMUniversalSyncConfigListDetails(unittest.TestCase):
    def setUp(self):
        self.params = mock.MagicMock()
        self.params.folder_cache = {}
        self.params.subfolder_cache = {}
        self.network = _make_network_record()
        mock.patch('keepercommander.vault.KeeperRecord.load', return_value=self.network).start()
        self.addCleanup(mock.patch.stopall)

    def _print_details(self, existing_config, format_type='json'):
        dag_class, connection_class, _root = _patch_dag(existing_config)
        with mock.patch('keepercommander.keeper_dag.DAG', dag_class), \
             mock.patch('keepercommander.keeper_dag.connection.commander.Connection', connection_class):
            return PAMUniversalSyncConfigListCommand.print_uss_configuration_details(
                self.params, NETWORK_UID, format_type=format_type)

    def test_json_details_reads_nested_github_fields(self):
        encrypted_owner = crypto.encrypt_aes_v2(b'my-org', RECORD_KEY)
        encrypted_repo = crypto.encrypt_aes_v2(b'my-repo', RECORD_KEY)
        existing_config = {
            'enabled': True,
            'github': {
                'scope': pam_pb2.ORGANIZATION,
                'owner': utils.base64_url_encode(encrypted_owner),
                'organizationVisibility': pam_pb2.ALL,
                'repos': [utils.base64_url_encode(encrypted_repo)],
            },
        }

        result = json.loads(self._print_details(existing_config))

        self.assertEqual(result['scope'], 'ORGANIZATION')
        self.assertEqual(result['organization_visibility'], 'ALL')
        self.assertEqual(result['owner'], 'my-org')
        self.assertEqual(result['repos'], ['my-repo'])

    def test_json_details_without_github_config(self):
        result = json.loads(self._print_details({'enabled': True}))

        self.assertEqual(result['scope'], 'N/A')
        self.assertEqual(result['organization_visibility'], 'N/A')
        self.assertEqual(result['owner'], 'N/A')
        self.assertEqual(result['repos'], [])


if __name__ == '__main__':
    unittest.main()
