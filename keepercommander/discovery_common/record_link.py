from __future__ import annotations
import logging
from .utils import get_connection, make_agent
from .types import UserAcl, DiscoveryObject
from ..keeper_dag import DAG, EdgeType
from ..keeper_dag.types import PamGraphId, PamEndpoints
import importlib
from typing import Any, Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ..keeper_dag.vertex import DAGVertex


class RecordLink:

    def __init__(self,
                 record: Any,
                 logger: Optional[Any] = None,
                 debug_level: int = 0,
                 fail_on_corrupt: bool = True,
                 log_prefix: str = "GS Record Linking",
                 save_batch_count: int = 200,
                 agent: Optional[str] = None,
                 use_read_protobuf: bool = False,
                 use_write_protobuf: bool = True,
                 **kwargs):

        self.conn = get_connection(logger=logger,
                                   use_read_protobuf=use_read_protobuf,
                                   use_write_protobuf=use_write_protobuf,
                                   **kwargs)

        # This will either be a KSM Record, or Commander KeeperRecord
        self.record = record
        self._dag = None
        if logger is None:
            logger = logging.getLogger()
        self.logger = logger
        self.log_prefix = log_prefix
        self.debug_level = debug_level
        self.save_batch_count = save_batch_count

        # Based on the connection type, use_write_protobuf might be set to False is True was passed.
        # Use self.conn.use_write_protobuf; don't use passed in use_write_protobuf.
        # If using protobuf to write, then use the endpoint.
        self.write_endpoint = None
        if self.conn.use_write_protobuf:
            self.write_endpoint = PamEndpoints.PAM

        self.read_endpoint = None
        if self.conn.use_read_protobuf:
            self.read_endpoint = PamEndpoints.PAM

        self.agent = make_agent("record_linking")
        if agent is not None:
            self.agent += "; " + agent

        # Technically, since there is no encryption in this graph, there should be no corruption.
        # Allow it to be set regardlessly.
        self.fail_on_corrupt = fail_on_corrupt

    @property
    def dag(self) -> DAG:
        if self._dag is None:

            # Make sure this auto save is False.
            # Since we don't have transactions, we want to save the record link if everything worked.
            self._dag = DAG(conn=self.conn,
                            record=self.record,
                            write_endpoint=self.write_endpoint,
                            read_endpoint=self.read_endpoint,
                            graph_id=PamGraphId.PAM,
                            auto_save=False,
                            logger=self.logger,
                            debug_level=self.debug_level,
                            name="Record Linking",
                            fail_on_corrupt=self.fail_on_corrupt,
                            log_prefix=self.log_prefix,
                            save_batch_count=self.save_batch_count,
                            agent=self.agent)
            sync_point = self._dag.load(sync_point=0)
            self.logger.debug(f"the record linking sync point is {sync_point or 0}")
            if not self.dag.has_graph:
                self.dag.add_vertex(name=self.record.title, uid=self._dag.uid)

        return self._dag

    def close(self):
        """
        Clean up resources held by this RecordLink instance.
        Releases the DAG instance and connection to prevent memory leaks.
        """
        if self._dag is not None:
            self._dag = None
        self.conn = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensures cleanup."""
        self.close()
        return False

    def __del__(self):
        self.close()

    @property
    def has_graph(self) -> bool:
        return self.dag.has_graph

    def reload(self):
        self._dag.load(sync_point=0)

    def get_record_link(self, uid: str) -> DAGVertex:
        return self.dag.get_vertex(uid)

    def get_parent_uid(self, uid: str) -> Optional[str]:
        """
        Get the vertex that the UID belongs to.

        This method will check the vertex ACL to see which edge has a True value for belongs_to.
        If it is found, the record UID that the head points at will be returned.
        If not found, None is returned.
        """

        vertex = self.dag.get_vertex(uid)
        if vertex is not None:
            for edge in vertex.edges:
                if edge.edge_type == EdgeType.ACL:
                    content = edge.content_as_object(UserAcl)
                    if content.belongs_to is True:
                        return edge.head_uid
        return None

    @staticmethod
    def get_record_uid(discovery_vertex: DAGVertex, validate_record_type: Optional[str] = None) -> str:
        """
        Get the record UID from the vertex

        """
        data = discovery_vertex.get_data()
        if data is None:
            raise Exception(f"The discovery vertex {discovery_vertex.uid} does not have a DATA edge. "
                            "Cannot get record UID.")
        content = DiscoveryObject.get_discovery_object(discovery_vertex)

        if validate_record_type is not None:
            if validate_record_type != content.record_type:
                raise Exception(f"The vertex is not record type {validate_record_type}")

        if content.record_uid is not None:
            return content.record_uid
        raise Exception(f"The discovery vertex {discovery_vertex.uid} data does not have a populated record UID.")

    def add_configuration(self, discovery_vertex: DAGVertex):
        """
        Add the configuration vertex to the DAG root.

        The configuration record UID will be the same as root UID.

        """

        record_uid = self.get_record_uid(discovery_vertex)
        record_vertex = self.dag.get_vertex(record_uid)
        if record_vertex is None:
            record_vertex = self.dag.add_vertex(uid=record_uid, name=discovery_vertex.name)
        if not self.dag.get_root.has(record_vertex):
            record_vertex.belongs_to_root(EdgeType.LINK)

    def discovery_belongs_to(self, discovery_vertex: DAGVertex, discovery_parent_vertex: DAGVertex,
                             acl: Optional[UserAcl] = None):

        """
        Link vault record using the vertices from discovery.

        If a link already exists, no additional link will be created.
        """

        try:
            record_uid = self.get_record_uid(discovery_vertex)
        except Exception as err:
            self.logger.warning(f"The discovery vertex is missing a record uid, cannot connect record: {err}")
            return

        # If the parent_vertex is the root, then don't get the record UID from the data.
        # The root vertex will have no data, and the record UID is the same as the vertex UID.
        if discovery_parent_vertex.uid == self.dag.uid:
            parent_record_uid = discovery_parent_vertex.uid
        else:
            try:
                parent_record_uid = self.get_record_uid(discovery_parent_vertex)
            except Exception as err:
                self.logger.warning("The discovery parent vertex is missing a record uid, cannot connect record: "
                                    f"{err}")
                return

        self.belongs_to(
            record_uid=record_uid,
            parent_record_uid=parent_record_uid,
            acl=acl,
            record_name=discovery_vertex.name,
            parent_record_name=discovery_parent_vertex.name
        )

    def belongs_to(self, record_uid: str, parent_record_uid: str, acl: Optional[UserAcl] = None,
                   record_name: Optional[str] = None, parent_record_name: Optional[str] = None):

        """
        Link vault records using record UIDs.

        If a link already exists, no additional link will be created.
        """

        # Get the record's vertices.
        # If a vertex does not exist, then add the vertex using the record UID
        record_vertex = self.dag.get_vertex(record_uid)
        if record_vertex is None:
            self.logger.debug(f"adding record linking vertex for record UID {record_uid} ({record_name})")
            record_vertex = self.dag.add_vertex(uid=record_uid, name=record_name)

        parent_record_vertex = self.dag.get_vertex(parent_record_uid)
        if parent_record_vertex is None:
            self.logger.debug(f"adding record linking vertex for parent record UID {parent_record_uid}")
            parent_record_vertex = self.dag.add_vertex(uid=parent_record_uid, name=parent_record_name)

        self.logger.debug(f"record UID {record_vertex.uid} belongs to {parent_record_vertex.uid} "
                          f"({parent_record_name})")

        # By default, the LINK edge will link records.
        # If ACL information was passed in, use the ACL edge.
        edge_type = EdgeType.LINK
        if acl is not None:
            edge_type = EdgeType.ACL

        # Get the current edge if it exists.
        # We need to create it if it does not exist and only add it if the ACL changed.
        existing_edge = record_vertex.get_edge(parent_record_vertex, edge_type=edge_type)
        add_edge = True
        if existing_edge is not None and existing_edge.active is True:
            if edge_type == EdgeType.ACL:
                content = existing_edge.content_as_object(UserAcl)  # type: UserAcl
                if content.model_dump_json() == acl.model_dump_json():
                    add_edge = False
            else:
                add_edge = False

        if add_edge:
            self.logger.debug(f"  added {edge_type} edge")
            record_vertex.belongs_to(parent_record_vertex, edge_type=edge_type, content=acl)

    def get_acl(self, record_uid: str, parent_record_uid: str, record_name: Optional[str] = None,
                parent_record_name: Optional[str] = None) -> Optional[UserAcl]:

        # Get the record's vertices.
        # If a vertex does not exist, then add the vertex using the record UID
        record_vertex = self.dag.get_vertex(record_uid)
        if record_vertex is None:
            self.logger.debug(f"adding record linking vertex for record UID {record_uid} ({record_name})")
            record_vertex = self.dag.add_vertex(uid=record_uid, name=record_name)

        parent_record_vertex = self.dag.get_vertex(parent_record_uid)
        if parent_record_vertex is None:
            self.logger.debug(f"adding record linking vertex for parent record UID {parent_record_uid}")
            parent_record_vertex = self.dag.add_vertex(uid=parent_record_uid, name=parent_record_name)

        acl_edge = record_vertex.get_edge(parent_record_vertex, edge_type=EdgeType.ACL)
        if acl_edge is None:
            return None

        return acl_edge.content_as_object(UserAcl)

    def acl_has_belong_to_vertex(self, discovery_vertex: DAGVertex) -> Optional[DAGVertex]:
        """
        Get the resource vertex for this user vertex that handles rotation, using the user's infrastructure vertex.
        """

        record_uid = self.get_record_uid(discovery_vertex, "pamUser")
        if record_uid is None:
            return None

        return self.acl_has_belong_to_record_uid(record_uid)

    def acl_has_belong_to_record_uid(self, record_uid: str) -> Optional[DAGVertex]:

        """
        Get the resource vertex for this user vertex that handles rotation. using the user's record UID.
        """

        record_vertex = self.dag.get_vertex(record_uid)
        if record_vertex is None:
            return None
        for edge in record_vertex.edges:
            if edge.edge_type != EdgeType.ACL:
                continue
            content = edge.content_as_object(UserAcl)
            if content.belongs_to is True:
                return self.dag.get_vertex(edge.head_uid)
        return None

    def get_parent_record_uid(self, record_uid: str) -> Optional[str]:
        """
        Get the parent record uid.

        Check the ACL edges for the one where belongs_to is True
        If there is a LINK edge that leads to the parent.
        """

        record_vertex = self.dag.get_vertex(record_uid)
        if record_vertex is None:
            return None
        for edge in record_vertex.edges:
            if edge.edge_type == EdgeType.ACL:
                content = edge.content_as_object(UserAcl)  # type: UserAcl
                if content.belongs_to:
                    return edge.head_uid
            elif edge.edge_type == EdgeType.LINK:
                return edge.head_uid
        return None

    def get_child_record_uids(self, record_uid: str) -> List[str]:
        """
        Get a list of child record for this parent.

        The list contains any parent that this record uid has a LINK or ACL edge to.
        """

        record_vertex = self.dag.get_vertex(record_uid)
        if record_vertex is None:
            self.logger.debug(f"could not get the parent record for {record_uid}")
            return []

        record_uids = []
        self.logger.debug(f"has {record_vertex.has_vertices()}")
        for child_vertex in record_vertex.has_vertices(EdgeType.ACL):
            record_uids.append(child_vertex.uid)
        for child_vertex in record_vertex.has_vertices(EdgeType.LINK):
            record_uids.append(child_vertex.uid)

        return record_uids

    def get_parent_record_uids(self, record_uid: str) -> List[str]:
        """
        Get a list of parent record this child record belongs to.

        The list contains any parent that this record uid has a LINK or ACL edge to.
        """

        record_vertex = self.dag.get_vertex(record_uid)
        if record_vertex is None:
            self.logger.debug(f"could not get the child record for {record_uid}")
            return []

        record_uids = []
        for vertex in record_vertex.belongs_to_vertices():
            edge = vertex.get_edge(record_vertex, EdgeType.ACL)
            if edge is None:
                edge = vertex.get_edge(record_vertex, EdgeType.LINK)
            if edge is not None:
                record_uids.append(record_vertex.uid)
        return record_uids

    def get_admin_record_uid(self, record_uid: str) -> Optional[str]:
        """
        Get the record that admins this resource record.

        """

        record_vertex = self.dag.get_vertex(record_uid)
        if record_vertex is not None:
            for vertex in record_vertex.has_vertices():
                for edge in vertex.edges:
                    if edge.head_uid != record_vertex.uid:
                        continue
                    if edge.edge_type == EdgeType.ACL:
                        content = edge.content_as_object(UserAcl)  # type: UserAcl
                        if content.is_admin is True:
                            return vertex.uid
        return None

    def discovery_disconnect_from(self, discovery_vertex: DAGVertex, discovery_parent_vertex: DAGVertex):
        record_uid = self.get_record_uid(discovery_vertex)
        parent_record_uid = self.get_record_uid(discovery_parent_vertex)
        self.disconnect_from(record_uid=record_uid, parent_record_uid=parent_record_uid)

    def disconnect_from(self, record_uid: str, parent_record_uid: str):
        record_vertex = self.dag.get_vertex(record_uid)
        parent_record_vertex = self.dag.get_vertex(parent_record_uid)

        # Check if we got vertex for the record UIDs.
        # Log info if we didn't.
        # Since we are disconnecting, we are not going to treat this as a fatal error.
        if record_vertex is None:
            self.logger.info(f"for record linking, could not find the vertex for record UID {record_uid}."
                             f"  cannot disconnect from parent vertex for record UID {parent_record_uid}")
            return
        if parent_record_vertex is None:
            self.logger.info(f"for record linking, could not find the parent vertex for record UID {parent_record_uid}."
                             f"  cannot disconnect the child vertex for record UID {record_uid}")
            return

        parent_record_vertex.disconnect_from(record_vertex)

    @staticmethod
    def delete(vertex: DAGVertex):
        if vertex is not None:
            vertex.delete()

    def save(self):
        if self.dag.has_graph is True:
            self.logger.debug("saving the record linking.")
            self.dag.save(delta_graph=False)
        else:
            self.logger.debug("the record linking graph does not contain any data, was not saved.")

    def to_dot(self, graph_format: str = "svg", show_version: bool = True, show_only_active_vertices: bool = True,
               show_only_active_edges: bool = True, graph_type: str = "dot"):

        try:
            mod = importlib.import_module("graphviz")
        except ImportError:
            raise Exception("Cannot to_dot(), graphviz module is not installed.")

        dot = getattr(mod, "Digraph")(comment=f"DAG for Record Linking", format=graph_format)

        if graph_type == "dot":
            dot.attr(rankdir='RL')
        elif graph_type == "twopi":
            dot.attr(layout="twopi")
            dot.attr(ranksep="10")
            dot.attr(ratio="auto")
        else:
            dot.attr(layout=graph_type)

        self.logger.debug(f"have {len(self.dag.all_vertices)} vertices")
        for v in self.dag.all_vertices:
            if show_only_active_vertices is True and v.active is False:
                continue

            tooltip = ""

            for edge in v.edges:

                color = "grey"
                style = "solid"

                # To reduce the number of edges, only show the active edges
                if edge.active is True:
                    color = "black"
                    style = "bold"
                elif show_only_active_edges is True:
                    continue

                # If the vertex is not active, gray out the DATA edge
                if edge.edge_type == EdgeType.DATA and v.active is False:
                    color = "grey"

                if edge.edge_type == EdgeType.DELETION:
                    style = "dotted"

                edge_tip = ""
                if edge.edge_type == EdgeType.ACL and v.active is True:
                    content = edge.content_as_dict
                    if content.get("is_admin") is True:
                        color = "red"
                    if content.get("belongs_to") is True:
                        if color == "red":
                            color = "purple"
                        else:
                            color = "blue"

                    tooltip += f"TO {edge.head_uid}\\n"
                    for k, val in content.items():
                        tooltip += f" * {k}={val}\\n"
                    tooltip += f"--------------------\\n\\n"

                label = DAG.EDGE_LABEL.get(edge.edge_type)
                if label is None:
                    label = "UNK"
                if edge.path is not None and edge.path != "":
                    label += f"\\npath={edge.path}"
                if show_version is True:
                    label += f"\\nv={edge.version}"

                # tail, head (arrow side), label, ...
                dot.edge(v.uid, edge.head_uid, label, style=style, fontcolor=color, color=color, tooltip=edge_tip)

            shape = "ellipse"
            fillcolor = "white"
            color = "black"
            if v.active is False:
                fillcolor = "grey"

            label = f"uid={v.uid}"
            dot.node(v.uid, label, color=color, fillcolor=fillcolor, style="filled", shape=shape, tooltip=tooltip)

        return dot
