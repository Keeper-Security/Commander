from __future__ import annotations
from .edge import DAGEdge
from .types import EdgeType, RefType
from .crypto import generate_random_bytes, generate_uid_str, urlsafe_str_to_bytes
from .exceptions import DAGDeletionException, DAGIllegalEdgeException, DAGVertexException, DAGKeyException
from typing import Optional, Union, List, Any, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .dag import DAG
    Content = Union[str, bytes, dict]
    QueryValue = Union[list, dict, str, float, int, bool]
    import pydantic
    from pydantic import BaseModel


class DAGVertex:

    def __init__(self, dag: DAG, uid: Optional[str] = None, name: Optional[str] = None,
                 keychain: Optional[bytes] = None, vertex_type: RefType = RefType.GENERAL):

        self.dag = dag

        # If the UID is not set, generate a UID.
        if uid is None:
            uid = generate_uid_str()
        # Else verify that the UID is valid. The UID should be a 16-byte value that is web-safe base64 serialized.
        else:
            if len(uid) != 22:
                raise ValueError(f"The uid {uid} is not a 22 characters in length.")
            try:
                b = urlsafe_str_to_bytes(uid)
                if len(b) != 16:
                    raise ValueError("not 16 bytes")
            except Exception:
                raise ValueError("The uid does not appear to be web-safe base64 string contains a 16 bytes value.")

        # If the UID is the root UID, make sure the vertex type is not general.
        # The root vertex needs to be either PAM_NETWORK or PAM_USER, if not set to PAM_NETWORK.
        if uid == self.dag.uid and (vertex_type != RefType.PAM_NETWORK and vertex_type != RefType.PAM_USER):
            vertex_type = RefType.PAM_NETWORK
        self.vertex_type = vertex_type

        # If the name is not defined, use the UID. Name is not persistent in the DAG.
        # If you load the DAG, the web service will not return the name.
        if name is None:
            name = uid

        self._uid = uid
        self._name = name

        # The keychain is a list of keys that can be used.
        # The keychain may contain multiple keys, when loading the default graph (graph_id)
        # For normal editing, the keychain will contain only one key.
        self._keychain = []
        if keychain is not None:
            if not isinstance(keychain, list):
                keychain = [keychain]
            self._keychain += keychain

        # Is the keychain corrupt?
        self.corrupt = False

        # These are edges to which vertex own this vertex. This vertex belongs to. So this would
        self.edges: list[Optional[DAGEdge]] = []
        self.has_uid = []

        # Flag indicating that this vertex is active.
        # This means this vertex has an active edge connected to another vertex.
        self.active = True

        # By default, we will save this vertex; not skip_save.
        # If in the process building the graph, it is decided that a vertex should not be saved; this can be set to
        #  prevent the vertex from being saved.
        self._skip_save = False

    def __str__(self):
        ret = f"Vertex {self.uid}\n"
        ret += f"  python instance id: {id(self)}\n"
        ret += f"  name: {self.name}\n"
        ret += f"  keychain: {self.keychain}\n"
        ret += f"  active: {self.active}\n"
        ret += f"  edges:\n"
        for edge in self.edges:
            ret += f"    * type {self.dag.__class__.EDGE_LABEL.get(edge.edge_type)}"
            ret += f", connect to {edge.head_uid}"
            ret += f", path {edge.path}, "
            ret += f", active: {edge.active}"
            ret += f", modified: {edge.modified}"
            ret += f", content: {'yes' if edge.content is not None else 'no'}"
            ret += f", content type: {type(edge.content)}"
            ret += "\n"
        return ret

    def __repr__(self):
        return f"<DAGVertex {self.uid}>"

    def debug(self, msg: str, level: int = 0):
        self.dag.debug(msg, level=level)

    @property
    def name(self) -> str:
        """
        Get the name for vertex

        If the name is not defined, the UID will be returned.
        The name is not persistent.
        If loading a DAG, the name will not be set.

        :return:
        """
        if self._name is not None:
            return self._name
        return self._uid

    @property
    def key(self) -> Optional[Union[str, bytes]]:
        """
        Get a single key from the keychain.

        :return:
        """

        keychain = self.keychain
        if len(keychain) > 0:
            return self.keychain[0]

        return None

    @property
    def skip_save(self):
        return self._skip_save

    @skip_save.setter
    def skip_save(self, value):
        self._skip_save = value

        for vertex in self.has_vertices():
            vertex._skip_save = value

    def add_to_keychain(self, key: Union[str, bytes]):
        """
        Add a key to the keychain

        :param key: A decrypted key bytes or encrypted key str
        :return:
        """
        if key not in self._keychain:
            self._keychain.append(key)

    @property
    def keychain(self) -> Optional[List[Union[str, bytes]]]:
        """
        Get the keychain for the vertex.

        The key is stored on the edges, however, the key belongs to the vertex.
        KEY and ACL edges from this vertex will have the same encrypted key.
        It is simpler to store the key on the DAGVertex instance.

        The keychain in an array of keys.
        When using graph_id = 0, different graphs that have the same UID will
        have different keys.
        When decrypting DATA edges, each key in the keychain will be tried.

        If the keychain has not been set, check if any edges exist that require a key.
        If there are, then generate a random key.
        The load process will populate the key.
        If the vertex does not have a key in the keychain, it is because this is a newly
        added vertex.

        If there are no edges that require a key, then return None.
        """

        # If the vertex is root, then the keychain will be the key bytes.
        if self.dag.get_root == self:
            self._keychain = [self.dag.key]

        # If the keychain is empty, generate a key for a specific edge type.
        elif len(self._keychain) == 0:
            for e in self.edges:
                if e.edge_type in [EdgeType.KEY, EdgeType.DATA]:
                    self._keychain.append(generate_random_bytes(self.dag.__class__.UID_KEY_BYTES_SIZE))
                    break

        return self._keychain

    @keychain.setter
    def keychain(self, value: List[Union[str, bytes]]):
        """
        Set the key in the vertex.

        The save method will use this key for any KEY/ACL edges.
        A key of str type means it is encrypted.
        """
        self._keychain = value

    @property
    def has_decrypted_keys(self) -> Optional[bool]:
        """
        Does the vertex have a decrypted keys?

        If the vertex contains a KEY, ACL or DATA edge and if the key is bytes, then the key is decrypted.
        If it is a str type, then it is encrypted.
        """
        if len(self._keychain) > 0:
            for e in self.edges:
                if e.edge_type in [EdgeType.KEY, EdgeType.DATA]:
                    all_decrypted = True
                    for key in self._keychain:
                        if not isinstance(key, bytes):
                            all_decrypted = False
                            break
                    return all_decrypted
        return None

    @property
    def uid(self):
        """
        Get the vertex UID.

        Once set, don't allow it to be changed.
        """
        return self._uid

    def get_edge(self, vertex: DAGVertex, edge_type: EdgeType) -> DAGEdge:
        high_edge = None
        high_version = -1
        for edge in self.edges:
            # Get all the edge point at the same vertex.
            # Don't include DATA edges.
            if edge.head_uid == vertex.uid and edge.edge_type == edge_type:
                if edge.version > high_version:
                    high_version = edge.version
                    high_edge = edge
        return high_edge

    def get_highest_edge_version(self, head_uid: str) -> Tuple[int, Optional[DAGEdge]]:
        """
        Find the highest DAGEdge version of all edge types.

        :param head_uid:
        :return:
        """

        high_edge = None
        high_version = -1
        for edge in self.edges:
            # Get all the edge point at the same vertex.
            # Don't include DATA edges.
            if edge.head_uid == head_uid:
                if edge.version > high_version:
                    high_edge = edge
                    high_version = edge.version
        return high_version, high_edge

    def edge_count(self, vertex: DAGVertex, edge_type: EdgeType) -> int:
        """
        Get the number of edges between two vertices.

        :param vertex:
        :param edge_type:
        :return:
        """
        count = 0
        for edge in self.edges:
            if edge.head_uid == vertex.uid and edge.edge_type == edge_type:
                count += 1
        return count

    def edge_by_type(self, vertex: DAGVertex, edge_type: EdgeType) -> List[DAGEdge]:
        edge_list = []
        for edge in self.edges:
            if edge.edge_type == edge_type and edge.head_uid == vertex.uid:
                edge_list.append(edge)
        return edge_list

    @property
    def has_data(self) -> bool:

        """
        Does this vertex contain a DATA edge?

        :return: True if vertex has a DATA edge.
        """

        for item in self.edges:
            if item.edge_type == EdgeType.DATA:
                return True
        return False

    def get_data(self, index: Optional[int] = None) -> Optional[DAGEdge]:
        """
        Get data edge

        If the index is None or 0, the latest data edge will be returned.
        A positive and negative, non-zero, index will return the same data.
        It will be the absolute value of the index from the latest data.
        This means the 1 or -1 will return the prior data.

        If there is no data, None is returned.

        :param index:
        :return:
        """

        data_list = self.edge_by_type(self, EdgeType.DATA)
        data_count = len(data_list)
        if data_count == 0:
            return None

        # If the index is None, get the latest.
        if index is None or index == 0:
            index = -1
        # Since -1 is the current, switch index to a negative number and subtract one more.
        # For example, 1 means prior, -1 would be the latest, so we need to subtract one to get -2.
        elif index > 0:
            index *= -1
            index -= 1
        # If already a negative index, just subtract one.
        else:
            index -= 1

        try:
            data = data_list[index]
        except IndexError:
            raise ValueError(f"The index is not valid. Currently there are {data_count} data edges")

        return data

    def add_data(self,
                 content: Any,
                 is_encrypted: bool = False,
                 is_serialized: bool = False,
                 path: Optional[str] = None,
                 modified: bool = True,
                 from_load: bool = False,
                 needs_encryption: bool = True):

        """
        Add a DATA edge to the vertex.

        :param content: The content to store in the DATA edge.
        :param is_encrypted: Is the content encrypted?
        :param is_serialized: Is the content base64 serialized?
        :param path: Simple string tag to identify the edge.
        :param modified: Does this modify the content?
                         By default, adding a DATA edge will flag that the edge has been modified.
                         If loading, modified will be set to False.
        :param from_load: This call is being performed the load() method.
                          Do not validate adding data.
        :param needs_encryption: Default is True.
                                 Does the content need to be encrypted?
        """

        self.debug(f"connect {self.uid} to DATA edge", level=1)

        # Are we trying to add DATA to a deleted vertex?

        if not self.active:
            # If deleted, there will not be a KEY to decrypt the data.
            # Throw an exception if not from the loading method.
            if not from_load:
                raise DAGDeletionException("This vertex is not active. Cannot add DATA edge.")
            # If from loading, do not add and do not throw an exception.
            return

        # Make sure the vertex belongs before auto saving. If it does not belong, it's just an orphan right now.
        # This only is checked if using this module is used to create the graph.
        if self.belongs_to_a_vertex is False and from_load is False:
            raise DAGVertexException(f"Before adding data, connect this vertex {self.uid} to another vertex.")

        # Make sure that we have a KEY.
        # Allow a DATA edge to be connected to the root vertex, which will not have a KEY edge.
        # Or if we are loading, allow out of sync edges.

        if needs_encryption:
            found_key_edge = self.dag.get_root == self or from_load is True
            if found_key_edge is False:
                for edge in self.edges:
                    if edge.edge_type == EdgeType.KEY:
                        found_key_edge = True
            if found_key_edge is False:
                raise DAGKeyException(f"Cannot add DATA edge without a KEY edge for vertex {self.uid}.")

        # Get the prior data, set the version and inactive the prior data.
        version = 0
        prior_data = self.get_data()
        if prior_data is not None:
            version = prior_data.version + 1
            prior_data.active = False

            # Check if DATA has already been created/modified per this session.
            # If it has, the prior will be overwritten, no sense on saving this edge.
            # If warning is enabled, print a debug message and the stacktrace to we what added the DATA.
            if self.dag.dedup_edge and prior_data.modified:
                prior_data.skip_on_save = True
                if self.dag.dedup_edge_warning:
                    self.dag.debug("DATA edge added multiple times for session. stacktrace on what did it follows ...")
                    self.dag.debug_stacktrace()

        # The tail UID is the UID of the vertex. Since data loops back to the vertex, the head UID is the same.
        self.edges.append(
            DAGEdge(
                vertex=self,
                edge_type=EdgeType.DATA,
                head_uid=self.uid,
                version=version,
                content=content,
                path=path,
                modified=modified,
                is_serialized=is_serialized,
                is_encrypted=is_encrypted,
                needs_encryption=needs_encryption
            )
        )

        # If using a history level, we want to remove edges if we exceed the history level.
        # The history level is per edge type.
        # It's FIFO, so we will remove the first edge type if we exceed the history level.
        if self.dag.history_level > 0:
            data_count = self.data_count()
            while data_count > self.dag.history_level:
                for index in range(0, len(self.edges) - 1):
                    if self.edges[index].edge_type == EdgeType.DATA:
                        del self.edges[index]
                        data_count -= 1
                        break

        self.dag.do_auto_save()

    def data_count(self):
        return self.edge_count(self, EdgeType.DATA)

    def data_delete(self):

        # Get the DATA edge.
        # It will be a reference to itself.
        data_edge = self.get_edge(self, EdgeType.DATA)
        if data_edge is None:
            self.debug("cannot delete the data, no data edge exists.")

        data_edge.active = False

        self.belongs_to(
            vertex=self,
            edge_type=EdgeType.DELETION
        )
        self.debug(f"deleted data edge for {self.uid}")

    @property
    def latest_data_version(self):
        version = -1
        for edge in self.edges:
            if edge.edge_type == EdgeType.DATA and edge.version > version:
                version = edge.version
        return version

    @property
    def content(self) -> Optional[Union[str, bytes]]:
        """
        Get the content of the active DATA edge.

        If the content is a str, then the content is encrypted.
        """
        data_edge = self.get_data()
        if data_edge is None:
            return None
        return data_edge.content

    @property
    def content_as_dict(self) -> Optional[dict]:
        """
        Get the content from the active DATA edge as a dictionary.
        :return: Content as a dictionary.
        """
        data_edge = self.get_data()
        if data_edge is None:
            return None
        return data_edge.content_as_dict

    @property
    def content_as_str(self) -> Optional[str]:
        """
        Get the content from the active DATA edge as a str.
        :return: Content as a str.
        """

        data_edge = self.get_data()
        if data_edge is None:
            return None
        return data_edge.content_as_str

    def content_as_object(self,
                          meta_class: pydantic._internal._model_construction.ModelMetaclass) -> Optional[BaseModel]:
        """
        Get the content as a pydantic based object.

        :param meta_class: The class to return
        :return:
        """
        data_edge = self.get_data()
        if data_edge is None:
            return None

        return data_edge.content_as_object(meta_class)

    @property
    def has_key(self) -> bool:

        """
        Does this vertex contain any KEY or ACL edges?

        :return: True if vertex has a KEY or ACL edge.
        """

        for item in self.edges:
            if item.edge_type == EdgeType.KEY:
                return True
        return False

    def belongs_to(self,
                   vertex: DAGVertex,
                   edge_type: EdgeType,
                   content: Optional[Any] = None,
                   is_encrypted: bool = False,
                   path: Optional[str] = None,
                   modified: bool = True,
                   from_load: bool = False):

        """
        Connect a vertex to another vertex (as the owner).

        This will create an edge between this vertex and the passed in vertex.
        The passed in vertex will own this vertex.

        If the edge_type is a KEY or ACL, data will be treated as a key. If a DATA edge already exists, the
        edge_type will be changed to a KEY, if not a KEY or ACL edge_type.

        :param vertex: The vertex has this vertex.
        :param edge_type: The edge type that connects the two vertices.
        :param content: Data to store as the edges content.
        :param is_encrypted: Is the content encrypted?
        :param path: Text tag for the edge.
        :param modified: Does adding this edge modify the stored DAG?
        :param from_load: Is being connected from load() method?
        :return:
        """

        self.debug(f"connect {self.uid} to {vertex.uid} with edge type {edge_type.value}", level=1)

        if vertex is None:
            raise ValueError("Vertex is blank.")
        if self.uid == self.dag.uid and not (edge_type == EdgeType.DATA or edge_type == EdgeType.DELETION):
            if not from_load:
                raise DAGIllegalEdgeException(f"Cannot create edge to self for edge type {edge_type}.")
            self.dag.debug(f"vertex {self.uid} , the root vertex, "
                           f"attempted to create '{edge_type.value}' edge to self, skipping.")
            return

        # Cannot make an edge to the same vertex, unless the edge type is a DELETION.
        # Normally an edge to self is a DATA type, use add_data for that.
        # A DELETION edge to self is allowed.
        # Just means the DATA edge is being deleted.
        if self.uid == vertex.uid and not (edge_type == EdgeType.DATA or edge_type == EdgeType.DELETION):
            if not from_load:
                raise DAGIllegalEdgeException(f"Cannot create edge to self for edge type {edge_type}.")
            self.dag.debug(f"vertex {self.uid} attempted to make '{edge_type.value}' to self, skipping.")
            return

        # Figure out what version of the edge we are.

        version, version_edge = self.get_highest_edge_version(head_uid=vertex.uid)

        # If the new edge is not DELETION
        if edge_type != EdgeType.DELETION:

            # Find the current active edge for this edge type to make it inactive.
            current_edge_by_type = self.get_edge(vertex, edge_type)
            if current_edge_by_type is not None:
                current_edge_by_type.active = False

                # Check if edge has already been created/modified per this session.
                # If it has, the prior will be overwritten, no sense on saving this edge.
                # If warning is enabled, print a debug message and the stacktrace to we what added the DATA.
                if self.dag.dedup_edge and current_edge_by_type.modified:
                    current_edge_by_type.skip_on_save = True
                    if self.dag.dedup_edge_warning:
                        self.dag.debug(f"{edge_type.value.upper()} edge added multiple times for session. "
                                       "stacktrace on what did it follows ...")
                        self.dag.debug_stacktrace()

            # If we are adding a non-DELETION edge, it will inactivate the DELETION edge.
            highest_deletion_edge = self.get_edge(vertex, EdgeType.DELETION)
            if highest_deletion_edge is not None:
                highest_deletion_edge.active = False

        # For this purpose, only DATA edge are allow to set the is_encrypted flag.
        if edge_type != EdgeType.DATA:
            is_encrypted = False

        # Should we activate the vertex again?
        if not self.active:

            # If the vertex is already inactive, and we are trying to delete, return.
            if edge_type == EdgeType.DELETION:
                return

            if self.dag.dedup_edge and version_edge.modified:
                version_edge.skip_on_save = True
                if self.dag.dedup_edge_warning:
                    self.dag.debug("edge was deleted in session, will not save DELETION edge")
                    self.dag.debug_stacktrace()
            else:
                self.dag.debug(f"vertex {self.uid} was inactive; reactivating vertex.")
            self.active = True

        # Create and append a new DAGEdge instance.
        # Disable the auto saving after the content is changed since the edge has not been appended yet.
        # Once the edge is created, disable blocking auto save for content changes.
        edge = DAGEdge(
            vertex=self,
            edge_type=edge_type,
            head_uid=vertex.uid,
            version=version + 1,
            block_content_auto_save=True,
            content=content,
            is_encrypted=is_encrypted,
            path=path,
            modified=modified
        )
        edge.block_content_auto_save = False

        self.edges.append(edge)
        if self.uid not in vertex.has_uid:
            vertex.has_uid.append(self.uid)

        self.dag.do_auto_save()

    def belongs_to_root(self,
                        edge_type: EdgeType,
                        path: Optional[str] = None):

        """
        Connect the vertex to the root vertex.

        :param edge_type: The type of edge to use for the connection.
        :param path: Short tag for this edge.
        :return:
        """

        self.debug(f"connect {self.uid} to root", level=1)

        if self.uid == self.dag.uid:
            raise DAGIllegalEdgeException("Cannot create edge to self.")

        if not self.active:
            raise DAGDeletionException("This vertex is not active. Cannot connect to root.")

        # We are adding the root, we can enable auto save now.
        # We can get the correct stream id with an edge to the root vertex.
        self.belongs_to(self.dag.get_root, edge_type=edge_type, path=path)

        self.dag.allow_auto_save = True
        self.dag.do_auto_save()

    def has_vertices(self, edge_type: Optional[EdgeType] = None, allow_inactive: bool = False,
                     allow_self_ref: bool = False) -> List[DAGVertex]:

        """
        Get a list of vertices that belong to this vertex.
        :return: List of DAGVertex
        """

        vertices = []
        for uid in self.has_uid:

            # This will remove DATA and DATA that have changed to DELETION edges.
            # Prevent looping.
            if uid == self.uid and allow_self_ref is False:
                continue

            vertex = self.dag.get_vertex(uid)
            if edge_type is not None:
                edge = vertex.get_edge(self, edge_type=edge_type)
                if edge is not None:
                    vertices.append(vertex)

            # If no edge type was specified, do not return DATA and DELETION.
            # Also do not include vertices that are inactive by default.
            elif edge_type != EdgeType.DATA and edge_type != EdgeType.DELETION:
                if vertex.active is True or allow_inactive is True:
                    vertices.append(vertex)

        return vertices

    def has(self, vertex: DAGVertex, edge_type: Optional[EdgeType] = None) -> bool:

        """
        Does this vertex have the passed in vertex?

        :return: True if request vertex belongs to this vertex.
                 False if it does not.
        """

        vertices = self.has_vertices(edge_type=edge_type)
        return vertex in vertices

    def belongs_to_vertices(self) -> List[DAGVertex]:
        """
        Get a list of vertices that this vertex belongs to
        :return:
        """

        vertices = []
        for edge in self.edges:
            # If the edge is not a DATA or DELETION type, and the edge is the highest version/active
            if edge.edge_type != EdgeType.DATA and edge.edge_type != EdgeType.DELETION and edge.active is True:

                # The head will point at the remote vertex.
                # If it is active, and not already in the list, add it to the list of vertices this vertex belongs to.
                vertex = self.dag.get_vertex(edge.head_uid)
                if vertex.active is True and vertex not in vertices:
                    vertices.append(vertex)
        return vertices

    @property
    def belongs_to_a_vertex(self) -> bool:
        """
        Does this vertex belong to another vertex?
        :return:
        """

        # If this is the root vertex, return True.
        # Where this is being called should handle operations involving the root vertex.
        if self.dag.get_root == self:
            return True

        return len(self.belongs_to_vertices()) > 0

    def disconnect_from(self, vertex: DAGVertex, path: Optional[str] = None):

        """
        Disconnect this vertex from another vertex.

        This will add a DELETION edge between two vertices.
        If the vertex no longer belongs to another vertex, the vertex will be deleted.

        :param vertex: The vertex this vertex belongs to
        :param path: an Optional path for the DELETION edge.
        :return:
        """

        if vertex is None:
            raise ValueError("Vertex is blank.")

        # Flag all the edges as inactive.
        for edge in self.edges:
            if edge.head_uid == vertex.uid and edge.edge_type:
                edge.active = False

        # Add the DELETION edge
        self.belongs_to(
            vertex=vertex,
            edge_type=EdgeType.DELETION,
            path=path
        )

        # If all the KEY edges are inactive now, the DATA edge needs to be made inactive.
        # There is no longer a KEY edge to decrypt the DATA.
        has_active_key_edge = False
        for edge in self.edges:
            if edge.edge_type == EdgeType.KEY and edge.active is True:
                has_active_key_edge = True
                break
        if not has_active_key_edge:
            for edge in self.edges:
                if edge.edge_type == EdgeType.DATA:
                    edge.active = False

        if not self.belongs_to_a_vertex:
            self.debug(f"vertex {self.uid} is now not active", level=1)
            self.active = False

    def delete(self, ignore_vertex: Optional[DAGVertex] = None):

        """
        Delete a vertex

        Deleting a vertex will inactivate the vertex.
        It will also inactivate any vertices, and their edges, that belong to the vertex.
        It will not inactivate a vertex that belongs to multiple vertices.
        :return:
        """

        def _delete(vertex, prior_vertex):

            # Do not delete the root vertex
            if vertex.uid == self.dag.uid:
                self.debug(f"  * vertex is root, cannot delete root", level=2)
                return

            self.debug(f"> checking vertex {vertex.uid}")

            # Should we ignore a vertex?
            # If deleting an edge, we want to ignore the vertex that owns the edge.
            # This prevents circular calls.
            if ignore_vertex is not None and vertex.uid == ignore_vertex.uid:
                return

            # Get a list of vertices that belong to this vertex (v)
            has_v = vertex.has_vertices()

            if len(has_v) > 0:
                self.debug(f"  * vertex has {len(has_v)} vertices that belong to it.", level=2)
                for v in has_v:
                    self.debug(f"    checking {v.uid}")
                    _delete(v, vertex)
            else:
                self.debug(f"  * vertex {vertex.uid} has NO vertices.", level=2)

            for e in list(vertex.edges):
                if e.edge_type != EdgeType.DATA and (prior_vertex is None or e.head_uid == prior_vertex.uid):
                    e.delete()
            if vertex.belongs_to_a_vertex is False:
                self.debug(f"  * inactive vertex {vertex.uid}")
                vertex.active = False

        self.debug(f"DELETING vertex {self.uid}", level=3)

        # Perform the DELETION edges save in one batch.
        # Get the current allowed auto save state, and disable auto save.
        current_allow_auto_save = self.dag.allow_auto_save
        self.dag.allow_auto_save = False

        _delete(self, None)

        # Restore the allow auto save and trigger auto save()
        self.dag.allow_auto_save = current_allow_auto_save
        self.dag.do_auto_save()

    def walk_down_path(self, path: Union[str, List[str]]) -> Optional[DAGVertex]:

        """
        Walk the vertices using the path and return the vertex starting at this vertex.

        :param path: An array of path string, or string where the path is joined with a "/" (i.e., think URL)
        :return: DAGVertex is the path completes, None is failure.
        """

        self.debug(f"walking path in vertex {self.uid}", level=2)

        # If the path is str, break it into an array. Get rid of leading /
        if isinstance(path, str):
            self.debug("path is str, break into array", level=2)
            if path.startswith("/"):
                path = path[1:]
            path = path.split("/")

        # Unshift the path

        current_path = path[0]
        path = path[1:]
        self.debug(f"current path: {current_path}", level=2)
        self.debug(f"path left: {path}", level=2)

        # Check the DATA edges.
        # If a DATA edge has the current path, return this vertex.
        for edge in self.edges:
            if edge.edge_type != EdgeType.DATA:
                continue
            if edge.path == current_path:
                return self

        # Check the vertices that belong to this vertex for edges going to this vertex and the path matches.
        for vertex in self.has_vertices():
            self.debug(f"vertex {self.uid} has {vertex.uid}", level=2)
            for edge in vertex.edges:
                # If the edge matches the current path, the head of the edge is this vertex, a route exists.
                if edge.path == current_path and edge.head_uid == self.uid:
                    # If there is no path left, this is our vertex
                    if len(path) == 0:
                        return vertex
                    # If there is still more path, call vertex to walk more of the path.
                    else:
                        return vertex.walk_down_path(path)
        return None

    def get_paths(self) -> List[str]:
        """
        Get paths from this vertex to vertex owned by this vertex.
        :return: List of string paths
        """

        paths = []
        for vertex in self.has_vertices():
            for edge in vertex.edges:
                if edge.path is None or edge.path == "":
                    continue
                paths.append(edge.path)

        return paths

    def clean_edges(self):
        """
        Recursively clean edges and break circular references.

        This method clears all edge lists and reference tracking to help
        Python's garbage collector clean up circular references between
        DAG, DAGVertex, and DAGEdge objects.
        """
        # Recursively clean child vertices first
        for vertex in self.has_vertices():
            vertex.clean_edges()

        # Clear all reference lists
        self.edges.clear()
        self.has_uid.clear()
