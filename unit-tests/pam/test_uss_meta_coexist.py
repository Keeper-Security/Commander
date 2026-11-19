"""Regression: PAM config ``meta`` and ``universal_sync`` DATA edges share the root vertex of
graph 0 and must not evict each other (USS readers use history_level=1)."""
import os
import unittest
from unittest import mock

from keepercommander.keeper_dag import DAG


def _dag(path_aware):
    conn = mock.MagicMock(use_read_protobuf=False, use_write_protobuf=False)
    return DAG(conn=conn, key_bytes=os.urandom(32), graph_id=0, history_level=1, path_aware=path_aware)


class TestMetaAndUssCoexist(unittest.TestCase):

    def _paths(self, dag):
        return sorted(e.path for e in dag.get_root.edges)

    def test_meta_after_uss_keeps_both(self):
        dag = _dag(True)
        root = dag.get_root
        root.add_data(content={'enabled': True}, path='universal_sync', needs_encryption=False)
        root.add_data(content={'allowedSettings': {}}, path='meta', needs_encryption=False)
        self.assertEqual(self._paths(dag), ['meta', 'universal_sync'])

    def test_uss_after_meta_keeps_both(self):
        dag = _dag(True)
        root = dag.get_root
        root.add_data(content={'allowedSettings': {}}, path='meta', needs_encryption=False)
        root.add_data(content={'enabled': True}, path='universal_sync', needs_encryption=False)
        self.assertEqual(self._paths(dag), ['meta', 'universal_sync'])


if __name__ == '__main__':
    unittest.main()
