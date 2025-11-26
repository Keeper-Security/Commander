from __future__ import annotations
import logging
from .utils import get_connection, make_agent
from ..keeper_dag import DAG, EdgeType
from ..keeper_dag.exceptions import DAGVertexException
from ..keeper_dag.crypto import urlsafe_str_to_bytes
from ..keeper_dag.types import PamGraphId, PamEndpoints
import os
import importlib
import time
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..keeper_dag.vertex import DAGVertex


class Infrastructure:

    """
    Create a graph of the infrastructure.

    The first run will create a full graph since the vertices do not exist.
    Further discovery run will only show vertices that ...
    * do not have vaults records.
    * the data has changed.
    * the ACL has changed.

    """

    KEY_PATH = "infrastructure"
    DELTA_PATH = "delta"
    ADMIN_PATH = "ADMINS"
    USER_PATH = "USERS"

    def __init__(self, record: Any, logger: Optional[Any] = None, history_level: int = 0,
                 debug_level: int = 0, fail_on_corrupt: bool = True, log_prefix: str = "GS Infrastructure",
                 save_batch_count: int = 200, agent: Optional[str] = None,
                 **kwargs):

        # This will either be a KSM Record, or Commander KeeperRecord
        self.record = record
        self._dag = None
        if logger is None:
            logger = logging.getLogger()
        self.logger = logger
        self.log_prefix = log_prefix
        self.history_level = history_level
        self.debug_level = debug_level
        self.fail_on_corrupt = fail_on_corrupt
        self.save_batch_count = save_batch_count

        self.auto_save = False
        self.delta_graph = True
        self.last_sync_point = -1

        self.agent = make_agent("infra")
        if agent is not None:
            self.agent += "; " + agent

        self.conn = get_connection(logger=logger, **kwargs)

    @property
    def dag(self) -> DAG:
        if self._dag is None:

            self.logger.debug(f"loading the dag graph {PamGraphId.INFRASTRUCTURE.value}")
            self.logger.debug(f"setting graph save batch count to {self.save_batch_count}")

            self._dag = DAG(conn=self.conn,
                            record=self.record,
                            # endpoint=PamEndpoints.INFRASTRUCTURE,
                            graph_id=PamGraphId.INFRASTRUCTURE,
                            auto_save=self.auto_save,
                            logger=self.logger,
                            history_level=self.history_level,
                            debug_level=self.debug_level,
                            name="Discovery Infrastructure",
                            fail_on_corrupt=self.fail_on_corrupt,
                            log_prefix=self.log_prefix,
                            save_batch_count=self.save_batch_count,
                            agent=self.agent)
            # Do not load the DAG here.
            # We don't know if we are using a sync point yet.

        return self._dag

    @property
    def has_discovery_data(self) -> bool:
        # Does the graph array have any vertices?
        if not self.dag.has_graph:
            return False

        # If we at least have the root, does is have the configuration?
        if not self.get_root.has_vertices():
            return False

        return True

    @property
    def get_root(self) -> DAGVertex:
        return self.dag.get_root

    @property
    def get_configuration(self) -> DAGVertex:
        try:
            configuration = self.get_root.has_vertices()[0]
        except (Exception,):
            raise DAGVertexException("Could not find the configuration vertex for the infrastructure graph.")
        return configuration

    @property
    def sync_point(self):
        return self._dag.load(sync_point=0)

    def load(self, sync_point: int = 0):
        ts = time.time()
        res = self.dag.load(sync_point=sync_point) or 0
        self.logger.debug(f"infrastructure took {time.time()-ts} secs to load")
        return res

    def close(self):
        """
        Clean up resources held by this Infrastructure instance.
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

    def save(self, delta_graph: Optional[bool] = None):
        if delta_graph is None:
            delta_graph = self.delta_graph

        self.logger.debug(f"current sync point {self.last_sync_point}")
        if delta_graph:
            self.logger.debug("saving delta graph of the infrastructure")
        ts = time.time()
        self._dag.save(delta_graph=delta_graph)
        self.logger.debug(f"infrastructure took {time.time()-ts} secs to save")

    def to_dot(self, graph_format: str = "svg", show_hex_uid: bool = False,
               show_version: bool = True, show_only_active_vertices: bool = False,
               show_only_active_edges: bool = False, sync_point: int = None, graph_type: str = "dot"):

        try:
            mod = importlib.import_module("graphviz")
        except ImportError:
            raise Exception("Cannot to_dot(), graphviz module is not installed.")

        dot = getattr(mod, "Digraph")(comment=f"DAG for Discovery", format=graph_format)

        if sync_point is None:
            sync_point = self.last_sync_point

        self.logger.debug(f"generating infrastructure dot starting at sync point {sync_point}")

        self.dag.load(sync_point=sync_point)

        count = 0
        if len(self.dag.get_root.has_vertices()) > 0:
            config_vertex = self.dag.get_root.has_vertices()[0]
            count = len(config_vertex.has_vertices())

        if graph_type == "dot":
            dot.attr(rankdir='RL')
            rank_sep = 10
            if count > 10:
                rank_sep += int(count * 0.10)
            dot.attr(ranksep=str(rank_sep))
        elif graph_type == "twopi":
            rank_sep = 20
            if count > 20:
                rank_sep += int(count * 0.10)

            dot.attr(layout="twopi")
            dot.attr(ranksep=str(rank_sep))
            dot.attr(ratio="auto")
        else:
            dot.attr(layout=graph_type)
            dot.attr(ranksep=10)

        for v in self.dag.all_vertices:
            if show_only_active_vertices is True and v.active is False:
                continue

            shape = "ellipse"
            fillcolor = "white"
            color = "black"

            if not v.corrupt:

                if not v.active:
                    fillcolor = "grey"

                record_type = None
                record_uid = None
                name = v.name
                source = None
                try:
                    data = v.content_as_dict
                    record_type = data.get("record_type")
                    record_uid = data.get("record_uid")
                    name = data.get("name")
                    item = data.get("item")
                    if item is not None:
                        if item.get("managed", False) is True:
                            shape = "box"
                        source = item.get("source")
                    if record_uid is not None:
                        fillcolor = "#AFFFAF"
                    if data.get("ignore_object", False):
                        fillcolor = "#DFDFFF"
                except (Exception,):
                    pass

                label = f"uid={v.uid}"
                if record_type is not None:
                    label += f"\\nrt={record_type}"
                if name is not None and name != v.uid:
                    name = name.replace("\\", "\\\\")
                    label += f"\\nname={name}"
                if source is not None:
                    label += f"\\nsource={source}"
                if record_uid is not None:
                    label += f"\\nruid={record_uid}"
                if show_hex_uid:
                    label += f"\\nhex={urlsafe_str_to_bytes(v.uid).hex()}"
                if v.uid == self.dag.get_root.uid:
                    fillcolor = "gold"
                    label += f"\\nsp={sync_point}"

                tooltip = f"ACTIVE={v.active}\\n\\n"
                try:
                    content = v.content_as_dict
                    for k, val in content.items():
                        if k == "item":
                            continue
                        if isinstance(val, str):
                            val = val.replace("\\", "\\\\")
                        tooltip += f"{k}={val}\\n"

                    item = content.get("item")
                    if item is not None:
                        tooltip += f"------------------\\n"
                        for k, val in item.items():
                            if isinstance(val, str):
                                val = val.replace("\\", "\\\\")
                            tooltip += f"{k}={val}\\n"
                except Exception as err:
                    tooltip += str(err)
            else:
                fillcolor = "red"
                label = f"{v.uid} (CORRUPT)"
                tooltip = "CORRUPT"

            dot.node(v.uid, label, color=color, fillcolor=fillcolor, style="filled", shape=shape, tooltip=tooltip)

            head_uids = []
            for edge in v.edges:

                # Don't show edges that reference self, DATA and data that has been DELETION
                if edge.head_uid == v.uid:
                    continue

                if edge.head_uid not in head_uids:
                    head_uids.append(edge.head_uid)

            def _render_edge(e):

                edge_color = "grey"
                style = "solid"

                if e.corrupt is False:

                    # To reduce the number of edges, only show the active edges
                    if e.active is True:
                        edge_color = "black"
                        style = "bold"
                    elif show_only_active_edges:
                        return

                    # If the vertex is not active, gray out the DATA edge
                    if e.edge_type == EdgeType.DATA and v.active is False:
                        edge_color = "grey"

                    if e.edge_type == EdgeType.DELETION:
                        style = "dotted"

                    edge_tip = ""
                    if e.edge_type == EdgeType.ACL and v.active is True:
                        edge_content = e.content_as_dict
                        for key, value in content.items():
                            edge_tip += f"{key}={value}\\n"
                        if edge_content.get("is_admin") is True:
                            edge_color = "red"

                    edge_label = DAG.EDGE_LABEL.get(e.edge_type)
                    if edge_label is None:
                        edge_label = "UNK"
                    if e.path is not None and e.path != "":
                        edge_label += f"\\npath={e.path}"
                    if show_version:
                        edge_label += f"\\nv={e.version}"
                else:
                    edge_label = f"{e.edge_type.value} (CORRUPT)"
                    edge_color = "red"
                    edge_tip = "CORRUPT"

                # tail, head (arrow side), label, ...
                dot.edge(v.uid, e.head_uid, edge_label, style=style, fontcolor=edge_color, color=edge_color,
                         tooltip=edge_tip)

            for head_uid in head_uids:
                version, edge = v.get_highest_edge_version(head_uid)
                _render_edge(edge)

            data_edge = v.get_data()
            if data_edge is not None:
                _render_edge(data_edge)

        return dot

    def render(self, name: str, **kwargs):

        output_name = os.environ.get("GRAPH_DIR", os.environ.get("HOME", os.environ.get("PROFILENAME", ".")))
        output_name = os.path.join(output_name, name)
        dot = self.to_dot(**kwargs)
        dot.render(output_name)
