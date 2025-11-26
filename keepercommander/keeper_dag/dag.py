from __future__ import annotations
import logging
import os
from .vertex import DAGVertex
from .types import DAGData, EdgeType, RefType, Ref, ENDPOINT_TO_GRAPH_ID_MAP
from .crypto import encrypt_aes, decrypt_aes, generate_uid_str, str_to_bytes, urlsafe_str_to_bytes, generate_uid_bytes
from .exceptions import (DAGConfirmException, DAGPathException, DAGVertexAlreadyExistsException, DAGKeyException,
                         DAGVertexException, DAGCorruptException, DAGDataException)
from .utils import value_to_boolean
from .struct.protobuf import DataStruct as ProtobufDataStruct
from .struct.default import DataStruct as DefaultDataStruct
from .__version__ import __version__
from enum import Enum
import json
import importlib
import traceback
import sys
from typing import Optional, Union, List, Any, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .connection import ConnectionBase
    Content = Union[str, bytes, dict]
    QueryValue = Union[list, dict, str, float, int, bool]
    Logger = Union[logging.RootLogger, logging.Logger]


class DAG:

    # Debug level. Increase to get finer debug messages.
    DEBUG_LEVEL = 0

    UID_KEY_BYTES_SIZE = 16
    UID_KEY_STR_SIZE = 22

    # For the dot output, enum to text.
    EDGE_LABEL = {
        EdgeType.DATA: "DATA",
        EdgeType.KEY: "KEY",
        EdgeType.LINK: "LINK",
        EdgeType.ACL: "ACL",
        EdgeType.DELETION: "DELETION",
    }

    def __init__(self,
                 conn: ConnectionBase,
                 record: Optional[object] = None,
                 key_bytes: Optional[bytes] = None,
                 name: Optional[str] = None,
                 read_endpoint: Optional[Union[str, Enum]] = None,
                 write_endpoint: Optional[Union[str, Enum]] = None,
                 graph_id: Optional[Union[int, Enum]] = None,
                 auto_save: bool = False,
                 history_level: int = 0,
                 logger: Optional[Any] = None,
                 debug_level: int = 0,
                 is_dev: bool = False,
                 vertex_type: RefType = RefType.PAM_NETWORK,
                 decrypt: bool = True,
                 fail_on_corrupt: bool = True,
                 data_requires_encryption: bool = False,
                 log_prefix: str = "GraphSync",
                 save_batch_count: Optional[int] = None,
                 agent: Optional[str] = None,
                 dedup_edges: bool = False):

        """
        Create a GraphSync instance.

        :param conn: Connection instance
        :param record: If set, the key bytes will use the key bytes in the record. Overrides key_bytes.
        :param key_bytes:  If set, these key bytes will be used.
        :param name: Optional name for the graph.
        :param read_endpoint: Endpoint for reading from graph. Use this over `graph_id`. (i.e. graph-sync/pam )
        :param write_endpoint: Endpoint for writing to graph. Use this over `graph_id`. (i.e. graph-sync/pam )
        :param graph_id: Graph ID sets which graph to load for the graph. `endpoint` replaces this, but code is
                         backwards compatiable.
        :param auto_save: Automatically save when modifications are performed. Default is False.
        :param history_level: How much edge history to keep in memory. Default is 0, no history.
        :param logger: Python logger instance to use for logging.
        :param debug_level: Debug level; the higher the number will result in more debug information.
        :param is_dev: Is the code running in a development environment?
        :param vertex_type: The default vertex/ref type for the root vertex, if auto creating.
        :param decrypt: Decrypt the graph; Default is TRUE
        :param fail_on_corrupt: If unable to decrypt encrypted data, fail out.
        :param data_requires_encryption: Data edges are already encrypted. Default is False.
        :param log_prefix: Text prepended to the log messages. Handy if dealing with multiple graphs.
        :param save_batch_count: The number of edges to save at one time.
        :param agent: User Agent to send with web service requests.
        :param dedup_edges: Remove modified edges if the same edge added before save.
        :return: Instance of GraphSync
        """

        if logger is None:
            logger = logging.getLogger()
        self.logger = logger
        if debug_level is None:
            debug_level = int(os.environ.get("GS_DEBUG_LEVEL", os.environ.get("DAG_DEBUG_LEVEL", 0)))

        # Prevent duplicate edges to be added.
        # The goal is to prevent unneeded edges.
        # If warning is turned on, log dup and stacktrace.
        self.dedup_edge = value_to_boolean(os.environ.get("GS_DEDUP_EDGES", dedup_edges))
        self.dedup_edge_warning = value_to_boolean(os.environ.get("GS_DEDUP_EDGES_WARN", False))

        if self.dedup_edge and auto_save:
            raise Exception("Cannot run dedup_edge and auto_save at the same time. The dedup_edge feature only works "
                            "in bulk saves.")

        self.debug_level = debug_level
        self.log_prefix = log_prefix

        if save_batch_count is None or save_batch_count <= 0:
            save_batch_count = 0
        self.save_batch_count = save_batch_count

        self.vertex_type = vertex_type

        self.data_requires_encryption = data_requires_encryption
        self.decrypt = decrypt
        self.fail_on_corrupt = fail_on_corrupt

        gs_is_dev = os.environ.get("GS_IS_DEV", os.environ.get("DAG_IS_DEV"))
        if gs_is_dev is not None:
            is_dev = value_to_boolean(gs_is_dev)
        self.is_dev = is_dev

        # If the record is passed in, use the UID and key bytes from the record.
        self.uid = None
        if record is not None:
            self.uid = conn.get_record_uid(record)
            key_bytes = conn.get_key_bytes(record)

        self.key = key_bytes

        if key_bytes is None:
            raise ValueError("Either the record or the key_bytes needs to be passed.")

        # If the UID is blank, use the key bytes to generate a UID
        if self.uid is None:
            self.uid = generate_uid_str(key_bytes[:16])

        if graph_id is None and (read_endpoint is None or write_endpoint is None):
            raise ValueError("Either graph_id or read/write endpoints needs to be set.")

        # graph_id and endpoint determine how/where the graph is stored on the GraphSync service.
        if graph_id is not None:
            if isinstance(read_endpoint, Enum):
                graph_id = ENDPOINT_TO_GRAPH_ID_MAP.get(read_endpoint.value)
        self.graph_id = graph_id

        if read_endpoint is not None:
            if isinstance(read_endpoint, Enum):
                read_endpoint = read_endpoint.value
        if write_endpoint is not None:
            if isinstance(write_endpoint, Enum):
                write_endpoint = write_endpoint.value

        self.read_endpoint = read_endpoint
        self.write_endpoint = write_endpoint

        if name is None:
            name = f"{self.log_prefix} ROOT"
        self.name = name

        # The order of the vertices is important.
        # The order creates the history.
        # The web service will order edge by their edge_id
        # Store in and array.
        # The lookup table to make UID to DAGVertex easier.
        # The integer is the index into the array.
        self._vertices = []  # type: List[DAGVertex]
        self._uid_lookup = {}  # type: dict[str, int]

        # This is like the batch
        self.origin_ref_value = generate_uid_bytes(16)
        self.origin_uid = generate_uid_str(uid_bytes=self.origin_ref_value)

        # If True, any addition or changes will automatically be saved.
        self.auto_save = auto_save

        # To auto save, both allow_auto_save and auto_save needs to be True.
        # If the graph has not been saved before and the root vertex has not been connected,
        #   we want to disable auto save.
        self._allow_auto_save = False

        # For big changes, we need a confirmation to save.
        self.need_save_confirm = False

        # The last sync point after save.
        self.last_sync_point = 0

        # Amount of history to keep.
        # The default is 0, which will keep all history.
        # Setting to 1 will only keep the latest edges.
        # Settings to 2 will keep the latest and prior edges.
        # And so on.
        self.history_level = history_level

        # If data was corrupt in the graph, the vertex UID will appear in this list.
        self.corrupt_uids = []

        self.conn = conn

        self.read_struct_obj: Union[ProtobufDataStruct, DefaultDataStruct] = ProtobufDataStruct() \
            if conn.use_read_protobuf else DefaultDataStruct()
        self.write_struct_obj: Union[ProtobufDataStruct, DefaultDataStruct] = ProtobufDataStruct() \
            if conn.use_write_protobuf else DefaultDataStruct()

        self.agent = f"keeper-dag/{__version__}"
        if agent is not None:
            self.agent += "; " + agent

        self.debug(f"save batch count is set to {self.save_batch_count}")
        if self.is_dev is True:
            self.debug("GraphSync is running in a development environment, vertex names will be included.")
        self.debug(f"edge de-dup is {self.dedup_edge}", level=1)
        self.debug(f"edge de-dup debug warning {self.dedup_edge_warning}", level=1)
        self.debug(f"{self.log_prefix} key {self.key}", level=1)
        self.debug(f"{self.log_prefix} UID {self.uid}", level=1)
        self.debug(f"{self.log_prefix} UID HEX {urlsafe_str_to_bytes(self.uid).hex()}", level=1)

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        """
        Explicitly clean up the DAG and break circular references.

        This method allows users to manually trigger cleanup before the object
        goes out of scope. This is useful in scenarios where you want to ensure
        immediate memory release, such as:
        - High-frequency DAG creation/destruction
        - Long-running processes
        - Memory-constrained environments

        After calling this method, the DAG object should not be used.

        Example:
            dag = DAG(conn=conn, key_bytes=key)
            # ... use the dag ...
            dag.cleanup()  # Explicitly clean up
            del dag
        """

        try:
            # Safely get the root vertex without creating a new one
            if hasattr(self, '_vertices') and hasattr(self, 'uid') and hasattr(self, '_uid_lookup'):
                if len(self._vertices) > 0 and self.uid in self._uid_lookup:
                    idx = self._uid_lookup[self.uid]
                    if idx < len(self._vertices):
                        root = self._vertices[idx]
                        if hasattr(root, 'clean_edges'):
                            root.clean_edges()
        except (Exception,):
            pass
        finally:
            # Always attempt to clear these collections, even if clean_edges() fails
            try:
                if hasattr(self, '_vertices'):
                    self._vertices.clear()
                if hasattr(self, '_uid_lookup'):
                    self._uid_lookup.clear()
                if hasattr(self, 'corrupt_uids'):
                    self.corrupt_uids.clear()
            except (Exception,):
                pass

        # Clear all collections to break circular references
        self.read_struct_obj = None
        del self.read_struct_obj
        self.write_struct_obj = None
        del self.write_struct_obj
        self.conn = None
        del self.conn

    def debug(self, msg: str, level: int = 0):
        """
        Debug with granularity level.

        If the debug level is greater or equal to the level on the message, the message will be displayed.

        :param msg: Text debug message
        :param level: Debug level of message
        :return:
        """

        if self.debug_level >= level:

            msg = f"{self.log_prefix}: {msg}"

            if self.logger is not None:
                self.logger.debug(msg)
            else:
                logging.debug(msg)

    def debug_stacktrace(self):
        exc = sys.exc_info()[0]
        # the last one would be full_stack()
        stack = traceback.extract_stack()[:-1]
        if exc is not None:
            del stack[-1]
        trc = 'Traceback (most recent call last):\n'
        msg = trc + ''.join(traceback.format_list(stack))
        if exc is not None:
            msg += '  ' + traceback.format_exc().lstrip(trc)
        self.debug(msg)

    def __str__(self):
        ret = f"GraphSync {self.uid}\n"
        ret += f"  python instance id: {id(self)}\n"
        ret += f"  name: {self.name}\n"
        ret += f"  key: {self.key}\n"
        ret += f"  vertices:\n"
        for v in self.all_vertices:
            ret += f"    * {v.uid}, Keys: {v.keychain}, Active: {v.active}\n"
            for e in v.edges:
                if e.edge_type == EdgeType.DATA:
                    ret += f"      + has a DATA edge"
                    if e.content is not None:
                        ret += ", has content"
                else:
                    ret += f"      + belongs to {e.head_uid}, {DAG.EDGE_LABEL.get(e.edge_type)}, {e.content}"
                ret += "\n"

        return ret

    @property
    def is_corrupt(self):
        return len(self.corrupt_uids) > 0

    @property
    def allow_auto_save(self) -> bool:
        """
        Return the flag indicating if auto save is allowed.
        :return:
        """

        return self._allow_auto_save

    @allow_auto_save.setter
    def allow_auto_save(self, value: bool):
        """
        Set the ability to auto save.
        :param value: True enables, False disables.
        :return:
        """

        if value:
            self.debug("ability to auto save has been ENABLED", level=2)
        else:
            self.debug("ability to auto save has been DISABLED", level=2)

        self._allow_auto_save = value

    @property
    def origin_ref(self) -> Ref:

        """
        Return an instance of the origin reference for adding data
        :return:
        """

        return Ref(
            type=RefType.DEVICE,
            value=self.origin_uid,
            name=self.name if self.is_dev is True else None
        )

    @property
    def has_graph(self) -> bool:
        """
        Do we have any graph items?

        :return: True if there are vertices. False if no vertices.
        """

        return len(self._vertices) > 0

    @property
    def vertices(self) -> List[DAGVertex]:
        """
        Get all active vertices

        :return: List of DAGVertex instance
        """

        return [
            vertex
            for vertex in self._vertices
            if vertex.active is True
        ]

    @property
    def all_vertices(self) -> List[DAGVertex]:
        """
        Get all vertices
        :return: List of DAGVertex instance
        """

        return self._vertices

    def get_vertex(self, key) -> Optional[DAGVertex]:

        """
        Get a single vertex.

        The key can be either a UID, path or name.

        The UID is most reliable since there can only be one per graph.

        The path is second reliable if it is set by the user.
        It will find an edge with the path, the vertex that is the edge's tail is returned.
        There is no unique constraint for the path.
        You can have duplicates.

        The name is third, and not reliable.
        The name only exists when the graph is created.
        If loaded, the name will be None.

        :param key: A UID, path item, or name of a vertex.
        :return: DAGVertex instance, if it exists.
        """

        if key is None:
            return None

        # Is the key a UID? If so, return the vertex from the lookup.
        if key in self._uid_lookup:
            index = self._uid_lookup[key]
            return self._vertices[index]

        # Is the key a path?
        # We also want to include any deleted edges.
        vertices = self.get_vertices_by_path_value(key, inc_deleted=True)
        if len(vertices) > 0:
            if len(vertices) > 1:
                raise DAGPathException("Cannot get vertex using the path. Found multiple vertex that use the path.")
            return vertices[0]

        # Is the key a name? This is a last resort.
        for vertex in vertices:
            if vertex.name == key:
                return vertex

        return None

    @property
    def get_root(self) -> Optional[DAGVertex]:
        """
        Get the root vertex

        If the root vertex does not exist, it will create the vertex with a ref type of PAM_NETWORK.

        :return:
        """
        root = self.get_vertex(self.uid)
        if root is None:
            root = self.add_vertex(uid=self.uid, name=self.name, vertex_type=self.vertex_type)
        return root

    def vertex_exists(self, key: str) -> bool:
        """
        Check if a vertex identified by the key exists.
        :param key: UID, path, or name
        :return:
        """

        return self.get_vertex(key) is not None

    def get_vertices_by_path_value(self, path: str, inc_deleted: bool = False) -> List[DAGVertex]:
        """
        Find all vertices that have an edge that match the path
        :param path: A string path value. This is a path to walk, just the value.
        :param inc_deleted: Include deleted edges.
        :return: List of DAGVertex
        """
        results = []
        if inc_deleted:
            vertices = self.all_vertices
        else:
            vertices = self.vertices

        for vertex in vertices:
            for edge in vertex.edges:
                if edge.path == path:
                    results.append(vertex)
        return results

    def _sync(self, sync_point: int = 0) -> Tuple[List[DAGData], int]:

        # The web service will send 500 items, if there is more the 'has_more' flag is set to True.
        has_more = True

        # Make the web service call to set all the data
        all_data = []
        while has_more:
            # Load a page worth of items

            sync_query = self.read_struct_obj.sync_query(stream_id=self.uid,
                                                         sync_point=sync_point,
                                                         graph_id=self.graph_id)

            results = self.read_struct_obj.get_sync_result(
                self.conn.sync(
                    sync_query=sync_query,
                    graph_id=self.graph_id,
                    endpoint=self.read_endpoint,
                    agent=self.agent
                ))

            if results.syncPoint == 0:
                return all_data, 0

            all_data += results.data

            # The server will tell us if there is more data to get.
            has_more = results.hasMore

            # The sync_point will indicate where we need to start the sync from. Think syncPoint > value
            sync_point = results.syncPoint

        return all_data, sync_point

    def _load(self, sync_point: int = 0):

        """
        Load the DAG

        This will clear the existing graph.
        It will make web services calls to get the fresh graph, which will return a list of edges.
        With the list of edges, it will create vertices and connect them with the edges.
        The content of the edges will remain encrypted. The 'encrypted' flag is set to True.
        We need the entire graph structure before decrypting.

        We don't have to worry about keys at this point. We are just trying to get structure
        and content in the right place. Nothing is decrypted here.

        :param sync_point: Where to load
        """

        # Clear the existing vertices.
        self._vertices = []  # type: List[DAGVertex]
        self._uid_lookup = {}  # type: dict[str, int]

        self.debug("# SYNC THE GRAPH ##################################################################", level=1)

        # Make the web service call to set all the data
        all_data, sync_point = self._sync(sync_point=sync_point)

        self.debug("  PROCESS the non-DATA edges", level=2)

        # Process the non-DATA edges
        for data in all_data:

            # Skip all the DATA edge
            edge_type = EdgeType.find_enum(data.type)
            if edge_type == EdgeType.DATA:
                continue

            # The ref the tail. It connects to stored in the vertex.
            tail_uid = data.ref.value

            # The parentRef is the head. It's the arrowhead on the edge. For DATA edges, it will be None.
            head_uid = None
            if data.parentRef is not None:
                head_uid = data.parentRef.value

            self.debug(f"  * edge {edge_type}, tail {tail_uid} to head {head_uid}", level=3)

            # We want to store this edge in the Vertex with the same value/UID as the ref.
            if not self.vertex_exists(tail_uid):
                self.debug(f"    * tail vertex {tail_uid} does not exists. create.", level=3)
                self.add_vertex(
                    uid=tail_uid,
                    name=data.ref.name,

                    # This will be 0/GENERAL right now. We do the lookup just in case things will change in the
                    # future.
                    vertex_type=RefType.find_enum(data.ref.type)
                )

            # Get the tail vertex.
            tail = self.get_vertex(tail_uid)

            # This most likely is a DELETION edge of a DATA edge.
            # Set the head to be the same as the tail.
            if head_uid is None:
                head_uid = tail_uid

            # If the head vertex doesn't exist, we need to create.
            if not self.vertex_exists(head_uid):
                self.debug(f"    * head vertex {head_uid} does not exists. create.", level=3)
                self.add_vertex(
                    uid=head_uid,
                    name=data.parentRef.name,
                    vertex_type=RefType.GENERAL
                )
            # Get the head vertex, which will exist now.
            head = self.get_vertex(head_uid)
            self.debug(f"    * tail {tail_uid} belongs to {head_uid}, "
                       f"edge type {edge_type}", level=3)

            if edge_type == EdgeType.DELETION:
                tail.disconnect_from(head)
            else:
                content = data.content
                if content is not None:
                    if data.content_is_base64:
                        content = str_to_bytes(content)

                # Connect this vertex to the head vertex. It belongs to that head vertex.
                tail.belongs_to(
                    vertex=head,
                    edge_type=edge_type,
                    content=content,
                    # ACL and LINK edges are not encrypted.
                    is_encrypted=False,
                    path=data.path,
                    modified=False,
                    from_load=True
                )

        self.debug("", level=2)
        self.debug("  PROCESS the DATA edges", level=2)

        # Process the DATA edges
        # We don't have to worry about vertex creation since they will all exist.
        for data in all_data:

            # Only process the data edges.
            edge_type = EdgeType.find_enum(data.type)
            if edge_type != EdgeType.DATA:
                continue

            # Get the tail vertex.
            tail_uid = data.ref.value
            # We want to store this edge in the Vertex with the same value/UID as the ref.
            if not self.vertex_exists(tail_uid):
                self.debug(f"    * tail vertex {tail_uid} does not exists. create.", level=3)
                self.add_vertex(
                    uid=tail_uid,
                    name=data.ref.name,

                    # This will be 0/GENERAL right now. We do the lookup just in case things will change in the
                    # future.
                    vertex_type=RefType.find_enum(data.ref.type)
                )
            tail = self.get_vertex(tail_uid)

            content = data.content
            if content is not None:
                if data.content_is_base64:
                    content = str_to_bytes(content)

            self.debug(f"  * DATA edge belongs to {tail.uid}", level=3)
            tail.add_data(
                content=content,
                # Assume DATA is encrypted; it might not be but, we will handle that later.
                is_encrypted=True,
                path=data.path,
                modified=False,
                from_load=True,
            )

        self.debug("", level=1)

        return sync_point

    def _mark_deletion(self):

        """
        Mark vertices as deleted.

        Check each vertex to see if there is any non-DELETION edge connecting to another vertex.
        If there are no edges, then the vertex is flagged at deleted.

        This is done to prevent the edges from being connected to a deleted vertex.
        Also, to display deleted vertex in the DOT graph.
        :return:
        """

        self.debug("  CHECK dag vertices to see if they are active", level=1)
        for vertex in self.all_vertices:

            self.debug(f"check vertex {vertex.uid}", level=3)
            found_edge_to_another_vertex = False
            for edge in vertex.edges:
                # Skip the DELETION and DATA edges.
                if edge.edge_type == EdgeType.DELETION or edge.edge_type == EdgeType.DATA:
                    continue

                # Check if this edge has a matching DELETION edge.
                # If it does not, this vertex cannot be deleted.
                if not edge.is_deleted:
                    found_edge_to_another_vertex = True
                    break

            # If the vertex belongs to no vertex, and it not the root, then flag it for deletion.
            if found_edge_to_another_vertex is False and vertex.uid != self.uid:
                self.debug(f"  * vertex is deleted", level=3)
                vertex.active = False

        self.debug("", level=1)

    def _decrypt_keychain(self):

        """
        Decrypt KEY/ACL edges

        Part one is to decrypt the KEY and ACL edges.
        To decrypt the edge, we need to walk up the edges until we can no longer.
        If we get the point where we can't walk up any farther, we need to use the record key bytes.
        While walking up, if we get to a keychain that has been decrypted, we return that keychain.
        As we walk back, we can decrypt any keychain that is still encrypted.
        The decrypt keychain is set in the vertex.
        """

        self.debug("  DECRYPT the dag KEY edges", level=1)

        def _get_keychain(v):
            self.debug(f"  * looking at {v.uid}", level=3)

            # If the vertex has a decrypted key, then return it.
            if v.has_decrypted_keys is True:
                self.debug("  found a decrypted keychain on vertex", level=3)
                return v.keychain

            # Else we need KEY/ACL edge and get the key from the vertex that this vertex belongs to
            found_key_edge = False
            for e in v.edges:
                if e.edge_type == EdgeType.KEY:

                    self.debug(f"    has edge that is a key, check head vertex {e.head_uid}", level=3)
                    head = self.get_vertex(e.head_uid)
                    keychain = _get_keychain(head)

                    # No need to check if keychain exists.
                    # At default, it should contain the record bytes if no KEY/ACL edges existed for a vertex.

                    self.debug(f"  * decrypt {v.uid} with keys {keychain}", level=3)
                    was_able_to_decrypt = False

                    # Try the keys in the keychain. One should be able to decrypt the content.
                    for key in keychain:
                        try:
                            # The edge will contain a single key.
                            # Adding a key to
                            self.debug(f"    decrypt with key {key}", level=3)
                            content = decrypt_aes(e.content, key)
                            self.debug(f"    content {content}", level=3)
                            v.add_to_keychain(content)
                            self.debug(f"  * vertex {v.uid} keychain is {v.keychain}", level=3)
                            was_able_to_decrypt = True
                            found_key_edge = True
                            break
                        except (Exception,):
                            self.debug(f"      !! this is not the key", level=3)

                    if not was_able_to_decrypt:

                        # Flag that the edge is corrupt, flag that the vertex keychain is corrupt,
                        #   and store vertex UID/tail UID.
                        # If we fail on corrupt keys, then raise exceptions.
                        e.corrupt = True
                        v.corrupt = True
                        self.corrupt_uids.append(v.uid)
                        if self.fail_on_corrupt:
                            raise DAGKeyException(f"Could not decrypt vertex {v.uid} keychain for edge path {e.path}")
                        return []

            if found_key_edge:
                return v.keychain
            else:
                self.debug("  * using record bytes", level=3)
                return [self.key]

        for vertex in self.all_vertices:
            if not vertex.has_key:
                continue
            self.debug(f"vertex {vertex.uid}, {vertex.has_key}, {vertex.has_decrypted_keys}", level=3)
            vertex.keychain = _get_keychain(vertex)
            self.debug(f"  setting keychain to {vertex.keychain}", level=3)

        self.debug("", level=1)

    def _decrypt_data(self):

        """
        Decrypt DATA edges

        At this point, all the vertex should have an encrypted key.
        This key is used to decrypt the DATA edge's content.
        Walk each vertex and decrypt the DATA edge if there is a DATA edge.
        """

        self.debug("  DECRYPT the dag data", level=1)
        for vertex in self.all_vertices:
            if not vertex.has_data:
                continue
            self.debug(f"vertex {vertex.uid}, {vertex.keychain}", level=3)

            for edge in vertex.edges:
                if edge.edge_type != EdgeType.DATA:
                    continue

                # If the vertex/KEY edge that tail is this vertex is corrupt, we cannot decrypt data.
                if vertex.corrupt:
                    self.debug(f"the key for the DATA edge is corrupt for vertex {vertex.uid}; "
                               "cannot decrypt data.", level=3)
                    continue

                if not edge.is_encrypted:
                    raise ValueError("The content has already been decrypted.")

                content = edge.content

                self.debug(f"  * enc safe content {content}", level=3)
                self.debug(f"  * enc {content}, enc key {vertex.keychain}", level=3)
                able_to_decrypt = False

                keychain = vertex.keychain

                # Try the keys in the keychain. One should be able to decrypt the content.
                for key in keychain:
                    try:
                        edge.content = decrypt_aes(content, key)
                        able_to_decrypt = True
                        self.debug(f"  * content {edge.content}", level=3)
                        break
                    except (Exception,):
                        self.debug(f"      !! this is not the key", level=3)

                if not able_to_decrypt:

                    # If the DATA edge requires encryption, throw error if we cannot decrypt.
                    if self.data_requires_encryption:
                        self.corrupt_uids.append(vertex.uid)
                        raise DAGDataException(f"The data edge {vertex.uid} could not be decrypted.")

                    edge.content = content
                    edge.needs_encryption = False
                    self.debug(f"  * edge is not encrypted or key is incorrect.")

                # Change the flag indicating that the content is in decrypted state.
                edge.is_encrypted = False

        self.debug("", level=1)

    def _flag_as_not_modified(self):

        """
        Flag all edges a not modified.

        :return:
        """

        for vertex in self.all_vertices:
            for edge in vertex.edges:
                edge.modified = False

    def load(self, sync_point: int = 0) -> int:

        """
        Load data from the graph.

        The first step is to recreate the structure of the graph.
        The second step is mark vertex as deleted.
        The third step is to decrypt the KEY/ACL/DATA edges.
        Forth is to flag all edges as not modified.

        :return: The sync point of the graph stream
        """

        # During the load, turn off auto save
        self.allow_auto_save = False

        self.debug("== LOAD DAG ========================================================================", level=2)
        sync_point = self._load(sync_point)
        self.debug(f"sync point is {sync_point}")
        self._mark_deletion()
        if self.decrypt:
            self._decrypt_keychain()
            self._decrypt_data()
        else:
            self.logger.info("the DAG has not been decrypted, the decrypt flag was get to False")
        self._flag_as_not_modified()
        self.debug("====================================================================================", level=2)

        # We have loaded the graph, enable the ability to use auto save.
        self.allow_auto_save = True

        self.last_sync_point = sync_point

        return sync_point

    def _make_delta_graph(self, duplicate_data: bool = True):

        self.debug("DELTA GRAPH", level=3)
        modified_vertices = []
        for vertex in self.all_vertices:
            found_modification = False
            for edge in vertex.edges:
                if edge.skip_on_save:
                    continue
                if edge.modified:
                    found_modification = True
                    break
            if found_modification:
                modified_vertices.append(vertex)
        if len(modified_vertices) == 0:
            self.debug("nothing has been modified")
            return

        self.debug(f"has {len(modified_vertices)} vertices", level=3)

        def _flag(v: DAGVertex):

            self.debug(f"check vertex {v.uid}", level=3)
            if v.uid == self.uid:
                self.debug(f"  FOUND ROOT", level=3)
                return True

            # Check if we have any of these edges in this order.
            found_path = False
            for edge_type in [EdgeType.KEY, EdgeType.ACL, EdgeType.LINK]:
                seen = {}
                for e in v.edges:
                    self.debug(f"  checking {e.edge_type}, {v.uid} to {e.head_uid}", level=3)
                    is_deletion = None
                    if e.edge_type == edge_type:
                        self.debug(f"    found {edge_type}", level=3)
                        next_vertex = self.get_vertex(e.head_uid)

                        if is_deletion is None:

                            # If the most recent edge a DELETION edge?
                            version, highest_edge = v.get_highest_edge_version(next_vertex.uid)
                            is_deletion = highest_edge.edge_type == EdgeType.DELETION
                            if is_deletion:
                                self.debug(f"    highest deletion edge. will not mark any edges as modified",
                                           level=3)

                        found_path = _flag(next_vertex)
                        if found_path is True and seen.get(e.head_uid) is None:
                            self.debug(f"  setting {v.uid}, {edge_type} active", level=3)
                            if not is_deletion:
                                e.modified = True
                                seen[e.head_uid] = True
                    else:
                        self.debug(f"    edge is not {edge_type}", level=3)

                if found_path is True:
                    break

            # If we found a path, we may need to duplicate the DATA edge.
            if found_path is True and duplicate_data is True:
                for e in v.edges:
                    if e.edge_type == EdgeType.DATA:
                        e.modified = True
                        break

            return found_path

        self.logger.debug("BEGIN delta graph edge detection")
        for modified_vertex in modified_vertices:
            _flag(modified_vertex)
        self.logger.debug("END delta graph edge detection")

    def save(self, confirm: bool = False, delta_graph: bool = False):

        """
        Save the graph

        We will not save if using the default graph.

        The save process will only save edges that have been flagged as modified, or are newly added.
        The process will get the edges from all vertices.
        The UID of the vertex is the tail UID of the edge.
        For DATA edges, the key (first key in the keychain) will be used for encryption.

        If the web service takes too long or hangs, the batch_count can be used to reduce the amount the web service
          needs to handle per request. If set to None or non-postivie value, it will not send in batches.

        :param confirm: Confirm save.
                        Only need this when deleting all vertices.
        :param delta_graph: Make a standalone graph from the modifications.
                            Use sync points to load this graph.

        :return:
        """

        self.debug("== SAVE GRAPH ========================================================================", level=2)

        if self.is_corrupt:
            self.logger.error(f"the graph is corrupt, there are problem UIDs: {','.join(self.corrupt_uids)}")
            raise DAGCorruptException(f"Cannot save. Graph steam uid {self.uid}, "
                                      f"graph {self.write_endpoint}:{self.graph_id} "
                                      f"has corrupt vertices: {','.join(self.corrupt_uids)}")

        root_vertex = self.get_vertex(self.uid)
        if root_vertex is None:
            raise DAGVertexException("Cannot save. Could not find the root vertex.")

        if root_vertex.vertex_type != RefType.PAM_NETWORK and root_vertex.vertex_type != RefType.PAM_USER:
            raise DAGVertexException("Cannot save. Root vertex type needs to be PAM_NETWORK or PAM_USER.")

        # Do we need to the 'confirm' parameter set to True?
        # This is needed if the entire graph is being deleted.
        if self.need_save_confirm is True and confirm is False:
            raise DAGConfirmException("Cannot save. Confirmation is required.")
        self.need_save_confirm = False

        if delta_graph:
            self._make_delta_graph()

        data_list = []

        def _add_data(vertex):
            self.debug(f"processing vertex {vertex.uid}, key {vertex.key}, type {vertex.vertex_type}", level=3)
            # The vertex UID and edge tail UID
            uid = vertex.uid
            for edge in vertex.edges:

                if edge.skip_on_save:
                    continue

                self.debug(f"  * edge {edge.edge_type.value}, head {edge.head_uid}, tail {vertex.uid}", level=3)

                # If this edge is not modified, don't add to the data list to save.
                if not edge.modified:
                    self.debug(f"    not modified, not saving.", level=3)
                    continue

                content = edge.content

                # If we are decrypting the edge data, then we want to encrypt it when we save.
                # Else, save the content as it is.
                if self.decrypt:
                    if edge.edge_type == EdgeType.DATA:
                        self.debug(f"    edge is data, encrypt data: {edge.needs_encryption}", level=3)
                        if isinstance(content, dict):
                            content = json.dumps(content).encode()
                        if isinstance(content, str):
                            content = content.encode()

                        # If individual edges require encryption or all DATA edge require encryption, then encrypt
                        if edge.needs_encryption is True or self.data_requires_encryption is True:
                            self.debug(f"    content {edge.content}, enc key {vertex.key}", level=3)
                            content = encrypt_aes(content, vertex.key)
                            self.debug(f"    enc content {content}", level=3)

                        self.debug(f"    enc safe content {content}", level=3)
                    elif edge.edge_type == EdgeType.KEY:
                        self.debug(f"    edge is key or acl, encrypt key", level=3)
                        head_vertex = self.get_vertex(edge.head_uid)
                        key = head_vertex.key
                        if key is None:
                            self.debug(f"     the edges head vertex {edge.head_uid} did not have a key. "
                                       "using root dag key.", level=3)
                            key = self.key
                        self.debug(f"    key {vertex.key}, enc key {key}", level=3)
                        content = encrypt_aes(vertex.key, key)
                    elif edge.edge_type == EdgeType.ACL:
                        content = edge.content
                    else:
                        self.debug(f"    edge is {edge.edge_type}", level=3)

                parent_vertex = self.get_vertex(edge.head_uid)

                if content is not None and len(content) > 65_535:
                    self.debug(f"    !! vertex {vertex.uid} data edge is {len(content)}, over 64K.")
                    raise DAGDataException(f"vertex {vertex.uid} DATA edge is {len(content)} bytes. "
                                           "This is too large for the MySQL BLOB (64K).")

                dag_data = self.write_struct_obj.data(
                    data_type=edge.edge_type,
                    content=content,
                    tail_uid=uid,
                    tail_ref_type=vertex.vertex_type,
                    tail_name=vertex.name if self.is_dev is True else None,
                    head_uid=edge.head_uid,
                    head_ref_type=parent_vertex.vertex_type,
                    head_name=parent_vertex.name if self.is_dev is True else None,
                    path=edge.path)

                data_list.append(dag_data)

                # Flag that this edge is no longer modified.
                edge.modified = False

        # Add the root vertex first
        _add_data(self.get_root)

        # Add the rest.
        # Only add is the skip_save is False.
        for v in self.all_vertices:
            if v.skip_save is False:
                if v.uid != self.uid:
                    _add_data(v)

        # Save the keys before the data.
        # This is done to make sure the web service can figure out the stream id.
        # By saving the keys before data, the structure of the graph is formed.
        if len(data_list) > 0:

            if self.debug_level >= 4:

                self.debug("EDGE LIST")
                self.debug("##############################################")
                for data in data_list:
                    self.debug(f"{data.ref.value} -> {data.parentRef.value} ({data.type})")
                self.debug("##############################################")

            self.debug(f"total list has {len(data_list)} items", level=0)
            self.debug(f"batch {self.save_batch_count} edges", level=0)

            batch_num = 0
            while len(data_list) > 0:

                # If using batch add, then take the first batch_count items.
                # Remove them from the data list
                if self.save_batch_count > 0:
                    batch_list = data_list[:self.save_batch_count]
                    data_list = data_list[self.save_batch_count:]

                # Else take everything and clear the data list (else infinite loop)
                else:
                    batch_list = data_list
                    data_list = []

                # Little sanity check
                if len(batch_list) == 0:
                    break

                self.debug(f"adding {len(batch_list)} edges, batch {batch_num}", level=0)

                payload = self.write_struct_obj.payload(
                    origin_ref=self.write_struct_obj.origin_ref(
                        origin_ref_value=self.origin_ref_value,
                        name=self.name if self.is_dev is True else None
                    ),
                    data_list=batch_list,
                    graph_id=self.graph_id
                )

                try:
                    self.conn.add_data(payload,
                                       graph_id=self.graph_id,
                                       endpoint=self.write_endpoint,
                                       agent=self.agent)
                except Exception as err:
                    self.logger.error(f"could not add data to graph for batch {batch_num}: {err}")
                    raise err

                batch_num += 1

                # It's a POST that returns no data
        else:
            self.debug("data list was empty, not saving.", level=2)

        self.debug("====================================================================================", level=2)

    def do_auto_save(self):
        # If allow_auto_save is False, we will not allow auto saving.
        # On newly created graph, this will happen if the root vertex has not been connected.
        # The root vertex/disconnect edge head is needed to get a proper stream ID.
        if not self.allow_auto_save:
            self.debug("cannot auto_save, allow_auto_save is False.", level=3)
            return
        if self.auto_save:
            self.debug("... dag auto saving", level=1)
            self.save()

    def add_vertex(self, name: Optional[str] = None, uid: Optional[str] = None,  keychain: Optional[List[bytes]] = None,
                   vertex_type: RefType = RefType.GENERAL) -> DAGVertex:

        """
        Add a vertex to the graph.

        :param name: Name for the vertex.
        :param uid: String unique identifier.
                    It's a 16bit hex value that is base64 encoded.
        :param keychain: List if key bytes to use for encryption/description. This is set by the load/save method.
        :param vertex_type: A RefType enumeration type. If blank, it will default to GENERAL.
        :return:
        """

        if name is None:
            name = uid

        vertex = DAGVertex(
            name=name,
            dag=self,
            uid=uid,
            keychain=keychain,
            vertex_type=vertex_type
        )
        if self.vertex_exists(vertex.uid):
            raise DAGVertexAlreadyExistsException(f"Vertex {vertex.uid} already exists.")

        # Set the UID to array index lookup.
        # This is where the vertex will be in the vertices list.
        # Then append the vertex to the vertices list.
        self._uid_lookup[vertex.uid] = len(self._vertices)
        self._vertices.append(vertex)

        return vertex

    @property
    def is_modified(self) -> bool:
        for vertex in self.all_vertices:
            for edge in vertex.edges:
                if edge.modified is True:
                    return True
        return False

    @property
    def modified_edges(self):
        edges = []
        for vertex in self.all_vertices:
            for edge in vertex.edges:
                if edge.modified is True:
                    edges.append(edge)
        return edges

    def delete(self):
        """
        Delete the entire graph.

        This will delete all the vertex, which will delete all the edges.
        This will not automatically save.
        The save method will need to be called.
        The save will require the 'confirm' parameter to be set to True.
        :return:
        """
        for vertex in self.vertices:
            vertex.delete()
        self.need_save_confirm = True

    def _search(self, content: Any, value: QueryValue, ignore_case: bool = False):

        if isinstance(value, dict):
            # If the object is not a dictionary, then it's not match
            if not isinstance(content, dict):
                return False
            for next_key, next_value in value.items():
                if next_key not in content:
                    return False
                if not self._search(content=content[next_key],
                                    value=next_value,
                                    ignore_case=ignore_case):
                    return False
            return True
        elif isinstance(value, list):
            # If the object is not a dictionary, then it's not match
            for next_value in value:
                if self._search(content=content,
                                value=next_value,
                                ignore_case=ignore_case):
                    return True
            return False
        else:
            content = str(content)
            value = str(value)
            if ignore_case:
                content = content.lower()
                value = value.lower()

            return value in content

    def search_content(self, query, ignore_case: bool = False):
        results = []
        for vertex in self.vertices:
            if vertex.has_data is False or vertex.active is False:
                continue
            content = vertex.content
            if isinstance(query, bytes):
                if query == content:
                    results.append(vertex)
            elif isinstance(query, str):
                try:
                    content = content.decode()
                    if query in content:
                        results.append(vertex)
                    continue

                except (Exception,):
                    pass
            elif isinstance(query, dict):
                try:
                    content = content.decode()
                    content = json.loads(content)
                    search_result = self._search(content, value=query, ignore_case=ignore_case)
                    if search_result:
                        results.append(vertex)
                except (Exception,):
                    pass
            else:
                raise ValueError("Query is not an accepted type.")
        return results

    def walk_down_path(self, path: Union[str, List[str]]) -> Optional[DAGVertex]:

        """
        Walk the vertices using the path and return the vertex starting at root vertex.

        :param path: An array of path string, or string where the path is joined with a "/" (i.e., think URL)
        :return: DAGVertex is the path completes, None is failure.
        """

        self.debug("walking path starting at the root vertex", level=2)
        vertex = self.get_vertex(self.uid)
        return vertex.walk_down_path(path)

    def edge_count(self, only_active: bool = True, only_modified: bool = False) -> int:
        """
        Return number of edges in graph.

        Edges that have neen flags as dups will not be inclued.

        :param only_active: Default True. If True, only edges that are active (not DELETION) are counted.
        :param only_modified: Default False. If Trtue, only edges that are new or have been modified are counted.
        :return:
        """

        count = 0
        for v in self.all_vertices:
            for e in v.edges:
                if e.skip_on_save:
                    continue
                if (only_active and not e.active) or (only_modified and not e.modified):
                    continue
                count += 1

        return count

    def to_dot(self, graph_format: str = "svg", show_hex_uid: bool = False,
               show_version: bool = True, show_only_active: bool = False):

        """
        Generate a graphviz Gigraph in DOT format that is marked up.

        :param graph_format:
        :param show_hex_uid:
        :param show_version:
        :param show_only_active:
        :return:
        """

        try:
            mod = importlib.import_module("graphviz")
        except ImportError:
            raise Exception("Cannot to_dot(), graphviz module is not installed.")

        dot = getattr(mod, "Digraph")(comment=f"GraphSync for {self.name}", format=graph_format)
        dot.attr(rankdir='BT')

        for v in self._vertices:
            if show_only_active is True and v.active is False:
                continue
            if not v.corrupt:
                fillcolor = "white"
                if not v.active:
                    fillcolor = "grey"
                label = f"uid={v.uid}"
                if v.name is not None and v.name != v.uid:
                    label += f"\\nname={v.name}"
                if show_hex_uid:
                    label += f"\\nhex={urlsafe_str_to_bytes(v.uid).hex()}"
            else:
                fillcolor = "red"
                label = f"{v.uid} (CORRUPT)"

            dot.node(v.uid, label, fillcolor=fillcolor, style="filled")
            for edge in v.edges:
                if edge.skip_on_save:
                    continue

                if not edge.corrupt:
                    color = "grey"
                    style = "solid"

                    # To reduce the number of edges, only show the active edges
                    if edge.active:
                        color = "black"
                        style = "bold"
                    elif show_only_active:
                        continue

                    # If the vertex is not active, gray out the DATA edge
                    if not edge.active:
                        color = "grey"

                    if edge.edge_type == EdgeType.DELETION:
                        style = "dotted"

                    label = DAG.EDGE_LABEL.get(edge.edge_type)
                    if label is None:
                        label = "UNK"
                    if edge.path is not None and edge.path != "":
                        label += f"\\npath={edge.path}"
                    if show_version:
                        label += f"\\ne{edge.version}"
                    # tail, head (arrow side), label
                else:
                    color = "red"
                    style = "solid"
                    label = f"{DAG.EDGE_LABEL.get(edge.edge_type)} (CORRUPT)"

                dot.edge(v.uid, edge.head_uid, label, style=style, fontcolor=color, color=color)

        return dot

    def to_dot_raw(self, graph_format: str = "svg", sync_point: int = 0, rank_dir="BT"):

        """
        Generate a graphviz Gigraph in DOT format that is not (heavily) marked up.

        :param graph_format:
        :param sync_point:
        :param rank_dir:
        :return:
        """

        try:
            mod = importlib.import_module("graphviz")
        except ImportError:
            raise Exception("Cannot to_dot(), graphviz module is not installed.")

        dot = getattr(mod, "Digraph")(comment=f"GraphSync for {self.name}", format=graph_format)
        dot.attr(rankdir=rank_dir)

        all_data, sync_point = self._sync(sync_point=sync_point)

        for edge in all_data:
            edge_type = edge.type
            tail_uid = edge.ref.value
            dot.node(tail_uid, tail_uid)
            if edge.parentRef is not None:
                head_uid = edge.parentRef.value
                dot.edge(tail_uid, head_uid, edge_type)
            else:
                dot.edge(tail_uid, tail_uid, edge_type)
        return dot
