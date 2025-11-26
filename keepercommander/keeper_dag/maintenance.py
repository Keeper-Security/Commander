from __future__ import annotations
from .dag import DAG
from .edge import EdgeType
from .exceptions import DAGVertexException, DAGDataException
from .crypto import decrypt_aes, str_to_bytes


class Maintenance:

    def __init__(self, dag: DAG, sync_point: int = 0, decrypt=False):
        self.dag = dag
        self.sync_point = sync_point
        self.decrypt = decrypt
        self._loaded = False
        self._load_sync_point = None

    def debug(self, msg: str, level: int = 0):
        return self.dag.debug(msg, level)

    @property
    def logger(self):
        return self.dag.logger

    def _get_keychain(self, v):
        self.debug(f"getting keychain for vertex {v.uid}, {v.name}, {v.vertex_type}", level=1)

        keychain = []

        found_key_edge = False
        for e in v.edges:
            if e.edge_type == EdgeType.KEY:
                head = self.dag.get_vertex(e.head_uid)
                keychain += self._get_keychain(head)

                # Each vertex has a "keychain".
                # However, this will be one key in an array.
                try:
                    content = decrypt_aes(e.content, keychain[-1]["key"])
                    keychain += [
                        {
                            "uid": v.uid,
                            "name": v.name,
                            "type": v.vertex_type,
                            "key": content,
                            "corrupt": False
                        }
                    ]
                    found_key_edge = True
                    break
                except Exception as err:
                    self.logger.error(f"could not decrypt key for {v.uid}, {keychain[-1]['key']}: {err}", level=1)
                    keychain += [
                        {
                            "uid": v.uid,
                            "name": v.name,
                            "type": v.vertex_type,
                            "corrupt": True
                        }
                    ]
                    return keychain

        if found_key_edge:
            return keychain
        else:
            return [
                {
                    "uid": self.dag.uid,
                    "key": self.dag.key,
                    "name": self.dag.name,
                    "type": self.dag.vertex_type,
                    "corrupt": False
                }
            ]

    def load(self, sync_point: int = 0):
        if self._loaded is False or sync_point != self._load_sync_point:
            self.logger.info(f"reloading the graph with decrypt {self.decrypt} and sync point {self.sync_point}")
            # Disable the automatic decrypt of the KEY and DATA edges.
            self.dag.decrypt = self.decrypt
            self.dag.load(sync_point=self.sync_point)
            self._loaded = True
            self._load_sync_point = sync_point

    def reload(self):
        self._loaded = False
        self.load()

    def get_keychain(self, uid: str, sync_point: int = 0):
        """

        :param uid: Either the UID, or name of the vertex.
        :param sync_point: A starting sync point for loading the graph.
        :return:
        """

        # Disable the automatic decrypt of the KEY and DATA edges.
        self.dag.decrypt = False
        self.load(sync_point=sync_point)

        vertex = self.dag.get_vertex(uid)
        if vertex is None:
            raise DAGVertexException(f"Vertex {uid} does not exists.", uid=uid)

        key_chain = self._get_keychain(vertex)

        return key_chain

    def get_data(self, uid: str, key: bytes, sync_point: int = 0):

        self.dag.decrypt = False
        self.load(sync_point=sync_point)

        vertex = self.dag.get_vertex(uid)
        if vertex is None:
            raise DAGVertexException(f"Vertex {uid} does not exists.", uid=uid)

        content = vertex.content
        if content is None:
            raise DAGVertexException(f"Vertex {uid} does not have a DATA edge.", uid=uid)

        try:
            return decrypt_aes(content, key)
        except (Exception,):
            raise DAGDataException(f"Vertex {uid} DATA edge can not be decrypted.")

    def delete_data(self):
        pass
