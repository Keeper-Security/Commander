from __future__ import annotations
import logging
from .types import EdgeType
from .exceptions import DAGContentException
import json
from typing import Optional, Union, Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .vertex import DAGVertex
    Content = Union[str, bytes, dict]
    QueryValue = Union[list, dict, str, float, int, bool]
    import pydantic
    from pydantic import BaseModel


class DAGEdge:
    def __init__(self, vertex: DAGVertex, edge_type: EdgeType, head_uid: str, version: int = 0,
                 content: Optional[Any] = None, path: Optional[str] = None,
                 modified: bool = True, block_content_auto_save: bool = False, from_load: bool = False,
                 needs_encryption: bool = False):
        """
        Create an instance of DAGEdge.

        A primary key of the edge the vertex UID, the head UID, and edge_type.

        :param vertex: The DAGVertex instance that owns these edges.
        :param edge_type: The enumeration EdgeType. Indicate the type of the edge.
        :param head_uid: The vertex uid that has this edge's vertex. The vertex uid that the edge arrow points at.
        :param version: Version of this edge.
        :param content: The content of this edge.
        :param path: Short tag about this edge. Do
        :param modified:
        :param block_content_auto_save:
        :param from_load: Is this being called from the load() method?
        :param needs_encryption: Flag to indicate if the content needs to be encrypted.
        :return: An instance of DAGEdge
        """

        # This is the vertex that owns this edge.
        self.vertex = vertex
        self.edge_type = edge_type
        self.head_uid = head_uid

        # Flag to indicate if the edge has been modified. Used to determine if the edge should be part of saved data.
        # Set this before setting the content, else setting the content will cause an auto save.
        self._modified = None
        self.modified = modified

        # Block auto save in the content setter.
        # When creating an edge, don't save until the edge is added to the edge list.
        self.block_content_auto_save = block_content_auto_save

        # Does this edge's content need encryption?
        self.needs_encryption = needs_encryption

        # If the content is being populated from a the load() method, and the edge type is a KEY or DATA, then the
        # content will be encrypted (str).
        # We want to keep a str, unless KEYs are decrypted.

        # If the edge data need encryption, is _content, currently encrypted.
        self.encrypted = from_load is True and edge_type in [EdgeType.KEY, EdgeType.DATA]

        # If the content could not be decrypted, set
        self.corrupt = False

        self._content = None  # type: Optional[Any]
        self.content = content
        self.path = path

        self.version = version

        # If a higher version edge exists, this will be False.
        # If True, this is the highest edge.
        self.active = True

    def __str__(self) -> str:
        return f"<Edge type {self.vertex.dag.__class__.EDGE_LABEL.get(self.edge_type)}, head {self.head_uid}, "\
               f"tail {self.vertex.uid}, path {self.path}, version {self.version}>"

    def debug(self, msg, level=0):
        self.vertex.dag.debug(msg, level=level)

    @property
    def modified(self):
        return self._modified

    @modified.setter
    def modified(self, value):
        if value is True:
            self.debug(f"vertex {self.vertex.uid}, type {self.vertex.dag.__class__.EDGE_LABEL.get(self.edge_type)}, "
                       f"head {self.head_uid} has been modified", level=5)
        else:
            self.debug(f"vertex {self.vertex.uid}, type {self.vertex.dag.__class__.EDGE_LABEL.get(self.edge_type)}, "
                       f"head {self.head_uid} had modified RESET", level=5)
        self._modified = value

    @property
    def content(self) -> Optional[Union[str, bytes]]:
        """
        Get the content of the edge.

        If the content is a str, then the content is encrypted.
        """
        return self._content

    @property
    def content_as_dict(self) -> Optional[dict]:
        """
        Get the content from the DATA edge as a dictionary.
        :return: Content as a dictionary.
        """
        content = self._content
        if content is not None:
            try:
                content = json.loads(content)
            except Exception as err:
                raise DAGContentException(f"Cannot decode JSON. Is the content a dictionary? : {err}")
        return content

    @property
    def content_as_str(self) -> Optional[str]:
        """
        Get the content from the DATA edge as string
        :return:
        """
        content = self._content
        try:
            content = content.decode()
        except Exception as err:
            pass
        return content

    def content_as_object(self, meta_class: pydantic._internal._model_construction.ModelMetaclass) -> (
            Optional)[BaseModel]:
        """
        Get the content as a pydantic based object.

        :param meta_class: The class to return
        :return:
        """
        content = self.content_as_str
        if content is not None:
            content = meta_class.model_validate_json(self.content_as_str)
        return content

    @content.setter
    def content(self, value: Any):

        """
        Set the content in the edge.

        The content should be stored as bytes.
        If the encrypted flag is set, the content will be stored as is.
        Content that is a str type is encrypted data (A Base64, AES encrypted bytes, str)
        """

        self.debug(f"vertex {self.vertex.uid}, type {self.vertex.dag.__class__.EDGE_LABEL.get(self.edge_type)}, "
                   f"head {self.head_uid} setting content", level=2)

        # If the data is encrypted, set it.
        # Don't try to make it bytes.
        # Also don't set the modified flag to True.
        if self.encrypted is True:
            self.debug("  content is encrypted.", level=3)
            self._content = value
            return

        if self._content is not None:
            raise DAGContentException("Cannot update existing content. Use add_data() to change the content.")

        if isinstance(value, dict) is True:
            value = json.dumps(value)

        # Is this a Pydantic based class?
        if hasattr(value, "model_dump_json") is True:
            value = value.model_dump_json()

        if isinstance(value, str) is True:
            value = value.encode()

        self._content = value

    def delete(self):
        """
        Delete the edge.

        Deleting an edge does not remove the existing edge.
        It will create another edge with the same tail and head, but will be type DELETION.
        """

        # If already inactive, return
        if self.active is False:
            return

        version, _ = self.vertex.get_highest_edge_version(head_uid=self.head_uid)

        # Flag all other edges as inactive.
        for edge in self.vertex.edges:
            edge.active = False

        self.vertex.edges.append(
            DAGEdge(
                vertex=self.vertex,
                edge_type=EdgeType.DELETION,
                head_uid=self.head_uid,
                version=version + 1
            )
        )

        # Perform the DELETION edges save in one batch.
        # Get the current allowed auto save state, and disable auto save.
        current_allow_auto_save = self.vertex.dag.allow_auto_save
        self.vertex.dag.allow_auto_save = False

        if self.vertex.belongs_to_a_vertex is False:
            self.vertex.delete(ignore_vertex=self.vertex)

        self.vertex.dag.allow_auto_save = current_allow_auto_save
        self.vertex.dag.do_auto_save()

    @property
    def is_deleted(self) -> bool:
        """
        Does this edge have a DELETION edge that has the same head?

        This should be used to check in a non-DELETION edge type has a matching DELETION edge.
        :return:
        """

        # We shouldn't be checking the DELETION edge if it deleted.
        # Throw some info message to make sure the coder knows their code might be something foolish.
        if self.edge_type == EdgeType.DELETION:
            logging.info(f"The edge is_deleted() just check if the DELETION edge is DELETION "
                         f"for vertex {self.vertex.uid}, head UID {self.head_uid}. Returned True, but code should "
                         "not be checking this edge.")
            return True

        # Check the other edges for this vertex for an active DELETION-edge type.
        for edge in self.vertex.edges:
            if edge.edge_type == EdgeType.DELETION and edge.head_uid == self.head_uid and edge.active is True:
                return True

        return False
