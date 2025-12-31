from __future__ import annotations
from .utils import get_connection, make_agent
from .types import JobContent, JobItem, Settings, DiscoveryDelta
from ..keeper_dag import DAG, EdgeType
from ..keeper_dag.types import PamGraphId, PamEndpoints
import logging
import os
import base64
import importlib
from time import time
import copy
from typing import Any, Optional, List, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from ..keeper_dag.vertex import DAGVertex


class Jobs:

    KEY_PATH = "jobs"

    # Break up the serialized delta.
    # This is so it fits in data edge with is limit to a MySQL BLOB, 65k
    # The content will be encrypted and base64, so this delta size needs to take that in account.
    DELTA_SIZE = 48_000

    # Only keep history for the last 30 runs.
    HISTORY_LIMIT = 30

    # Limit stacktrace characters
    STACKTRACE_LIMIT = 20_000

    # Limit the length of the error message in JobContent
    ERROR_LIMIT = 10_000
    SUMMARY_ERROR_LIMIT = 40

    def __init__(self, record: Any, logger: Optional[Any] = None, debug_level: int = 0, fail_on_corrupt: bool = True,
                 log_prefix: str = "GS Jobs", save_batch_count: int = 200, agent: Optional[str] = None,
                 **kwargs):

        self.conn = get_connection(logger=logger, **kwargs)

        # This will either be a KSM Record, or Commander KeeperRecord
        self.record = record
        self._dag = None
        if logger is None:
            logger = logging.getLogger()
        logger.propagate = False
        self.logger = logger
        self.log_prefix = log_prefix
        self.debug_level = debug_level
        self.fail_on_corrupt = fail_on_corrupt
        self.save_batch_count = save_batch_count

        self.agent = make_agent("jobs")
        if agent is not None:
            self.agent += "; " + agent

    @property
    def dag(self) -> DAG:
        if self._dag is None:

            self._dag = DAG(conn=self.conn,
                            record=self.record,
                            # endpoint=PamEndpoints.DISCOVERY_JOBS,
                            graph_id=PamGraphId.DISCOVERY_JOBS,
                            auto_save=False,
                            logger=self.logger,
                            debug_level=self.debug_level,
                            name="Discovery Jobs",
                            fail_on_corrupt=self.fail_on_corrupt,
                            log_prefix=self.log_prefix,
                            save_batch_count=self.save_batch_count,
                            agent=self.agent)

            ts = time()
            self._dag.load()
            self.logger.debug(f"jobs took {time() - ts} secs to load")

            # Has the status been initialized?
            if not self._dag.has_graph:
                self._dag.allow_auto_save = False
                status = self._dag.add_vertex()
                status.belongs_to_root(
                    EdgeType.KEY,
                    path=Jobs.KEY_PATH)
                status.add_data(
                    content=JobContent(
                        active_job_id=None,
                        job_history=[]
                    ),
                )
                self._dag.save()
        return self._dag

    def close(self):
        """
        Clean up resources held by this Jobs instance.
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
    def data_path(self):
        return f"/{Jobs.KEY_PATH}"

    def get_jobs(self):

        self.logger.debug("loading discovery jobs from DAG")

        vertex = self.dag.walk_down_path(self.data_path)
        current_dict = vertex.content_as_dict

        if current_dict is None:
            self.logger.debug("  there is no job content, creating empty job content")
            vertex.add_data(
                content=JobContent(
                    active_job_id=None,
                    job_history=[]
                ),
            )
            current_dict = vertex.content_as_dict

        # For job_history, settings will be blank/defaults.
        # This make sure setting is set to blank, if it was None.
        for job in current_dict.get("job_history", []):
            job["settings"] = {}

        return JobContent.model_validate(current_dict)

    def _chunk_delta_data(self, job_vertex: DAGVertex, delta: DiscoveryDelta):

        # From the job vertex we want to create vertices to hold the delta information.
        # Break them up based on the DELTA_SIZE.
        # Each DATA edge will contain part of the content.
        # Each delta vertex has a path so we know the order on how to re-assemble them.
        delta_content = delta.model_dump_json()
        self.logger.debug(f"job delta content is {len(delta_content)} bytes, chunk size is {Jobs.DELTA_SIZE} bytes")

        existing_delta_vertices = job_vertex.has_vertices()
        if len(existing_delta_vertices) > 0:
            self.logger.debug(f"job delta exists, remove old delta")
            for delta_vertex in existing_delta_vertices:
                delta_vertex.delete()

        chunk_num = 0
        while delta_content != "":
            path = str(chunk_num)

            chunk = delta_content[:Jobs.DELTA_SIZE]
            delta_content = delta_content[Jobs.DELTA_SIZE:]

            new_vertex = job_vertex.dag.add_vertex()
            new_vertex.belongs_to(job_vertex, edge_type=EdgeType.KEY, path=path)
            new_vertex.add_data(chunk)

            self.logger.debug(f" * vertex {new_vertex.uid}, chunk {chunk_num}, {len(chunk)} bytes")

            chunk_num += 1

    def set_jobs(self, jobs: JobContent):

        self.logger.debug("saving discovery jobs to DAG")

        # Get the main vertex.
        jobs_vertex = self.dag.walk_down_path(self.data_path)

        clean_jobs = []
        for job in jobs.job_history:

            # Does the job vertex exist?
            # If not created it.
            job_vertex = jobs_vertex.walk_down_path(job.job_id)
            if job_vertex is None:
                self.logger.debug(f"  create a job vertex for {job.job_id}")
                job_vertex = jobs_vertex.dag.add_vertex()
                job_vertex.belongs_to(jobs_vertex, edge_type=EdgeType.KEY, path=job.job_id)
            else:
                self.logger.debug(f"  job vertex for {job.job_id} exists")

            # If the job has delta data, chunk save it and remove it from the JobItem.
            # If is not store in the history anymore.
            if job.delta is not None:
                self.logger.debug("  included discovery delta")
                self._chunk_delta_data(job_vertex, job.delta)
                job.delta = None
            else:
                self.logger.debug("  did not include discovery delta")

            # In-case the stacktrace is too large, take only a limit about of characters from the end.
            if job.stacktrace is not None:
                self.logger.debug(f"stacktrace is {len(job.stacktrace)} characters")
                if len(job.stacktrace) > Jobs.STACKTRACE_LIMIT:
                    self.logger.debug(f"  stacktrace too long; truncate to {Jobs.STACKTRACE_LIMIT} characters")
                    start = len(job.stacktrace) - Jobs.STACKTRACE_LIMIT
                    job.stacktrace = job.stacktrace[start:]

            # Reduce the error message, if set, and remove stacktrace.
            if job.error is not None:
                self.logger.debug(f"error is {len(job.error)} characters")
                if len(job.error) > Jobs.ERROR_LIMIT:
                    self.logger.debug(f"  error too long; truncate to {Jobs.ERROR_LIMIT} characters")
                    job.error = job.error[:Jobs.ERROR_LIMIT] + "..."

            # Store the full JobItem (minus delta) on the job vertex.
            job_vertex.add_data(
                content=job
            )

            # Reduce the error message, if set, and remove stacktrace.
            if job.error is not None and len(job.error) > Jobs.SUMMARY_ERROR_LIMIT:
                job.error = job.error[:Jobs.SUMMARY_ERROR_LIMIT] + "..."
            job.stacktrace = None
            job.settings = Settings()

            clean_jobs.append(job)

        # Store the JobContent, with reduced JobItems, on the main vertex.
        # This still has the actives and list of job history.
        jobs.job_history = clean_jobs
        jobs_vertex.add_data(
            content=jobs
        )

        ts = time()
        self.dag.save()
        self.logger.debug(f"jobs took {time()-ts} secs to save")

        self.logger.debug("  finished saving")

    def _remove_old_history(self, job_history: List[JobItem], limit: int) -> List[JobItem]:

        self.logger.debug("clean up job history and migrate discovery delta")

        # The oldest will be first (lower start_ts, older the job)
        job_history = sorted(job_history, key=lambda j: j.start_ts)

        # Limit the number of job history to the last few jobs.
        while (len(list(job_history))) > limit:
            job = job_history[0]
            self.logger.debug(f"remove job {job.job_id} item")
            job_history = job_history[1:]
            job_vertex = self.dag.walk_down_path(f"{self.data_path}/{job.job_id}")
            if job_vertex is not None:
                self.logger.debug(f"remove job {job.job_id} vertex")
                job_vertex.delete()

        self.logger.debug(f"found {len(job_history)} items in job history")

        return job_history

    def start(self, settings: Optional[Settings] = None, resource_uid: Optional[str] = None,
              conversation_id: Optional[str] = None) -> str:

        """
        Start a discovery job.
        """

        self.logger.debug("starting a discovery job")

        if settings is None:
            settings = Settings()
        else:
            # We want to remove the user_map, because it may contain a lot of data; It might break the graph.
            # Make a copy of settings, remove the user map, and save this version of settings.
            settings = copy.deepcopy(settings)
            settings.user_map = None

        jobs = self.get_jobs()

        # The -1 is for the new job we are going to add. When done we are done starting the job have the limit.
        job_history = self._remove_old_history(jobs.job_history, limit=Jobs.HISTORY_LIMIT - 1)

        new_job = JobItem(
            job_id="JOB" + base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip('='),
            start_ts=int(time()),
            settings=settings,
            resource_uid=resource_uid,
            conversation_id=conversation_id,

            # Create a blank discovery delta.
            # Commander has a bug where it needs at least one.
            # It will be overwritten when the job is finished.
            delta=DiscoveryDelta()
        )
        jobs.active_job_id = new_job.job_id
        job_history.append(new_job)
        jobs.job_history = job_history

        self.set_jobs(jobs)

        return new_job.job_id

    def get_job_content(self) -> JobContent:
        jobs = self.dag.walk_down_path(path=self.data_path)
        return jobs.content_as_object(JobContent)

    def get_job(self, job_id) -> Optional[JobItem]:
        jobs = self.get_jobs()
        for job in jobs.job_history:
            if job.job_id == job_id:

                job_vertex = self.dag.walk_down_path(path=f"{self.data_path}/{job.job_id}")
                if job_vertex is not None:

                    # Get the job item from the job vertex DATA edge.
                    # Replace the one from the job history if we have it.
                    try:
                        job = job_vertex.content_as_object(JobItem)
                    except Exception as err:
                        self.logger.debug(f"could not find job item on job vertex, use job histry entry: {err}")

                    # If the job delta is None, check to see if it chunked as vertices.
                    delta_lookup = {}
                    vertices = job_vertex.has_vertices()
                    self.logger.debug(f"found {len(vertices)} delta vertices")
                    for vertex in vertices:
                        edge = vertex.get_edge(job_vertex, edge_type=EdgeType.KEY)
                        delta_lookup[int(edge.path)] = vertex

                    json_value = ""
                    # Sort numerically increasing and then append their content.
                    # This will re-assemble the JSON
                    for key in sorted(delta_lookup):
                        json_value += delta_lookup[key].content_as_str
                    if json_value != "":
                        self.logger.debug(f"delta content length is {len(json_value)}")
                        job.delta = DiscoveryDelta.model_validate_json(json_value)
                else:
                    self.logger.debug("could not find job vertex")

                # If settings was not set, then set it the default.
                if job.settings is None:
                    job.settings = Settings()

                return job
        return None

    def error(self, job_id: str, error: Optional[str], stacktrace: Optional[str] = None):

        self.logger.debug("flag discovery job as error")

        jobs = self.get_jobs()
        for job in jobs.job_history:
            if job.job_id == job_id:
                logging.debug("found job to add error message")
                job.end_ts = int(time())
                job.success = False
                job.error = error
                job.stacktrace = stacktrace

        self.set_jobs(jobs)

    def finish(self, job_id: str, sync_point: int, delta: DiscoveryDelta):

        self.logger.debug("finish discovery job")

        jobs = self.get_jobs()
        for job in jobs.job_history:
            if job.job_id == job_id:
                self.logger.debug("found job to finish")
                job.sync_point = sync_point
                job.end_ts = int(time())
                job.success = True
                job.delta = delta

        self.set_jobs(jobs)

    def cancel(self, job_id):

        self.logger.debug("cancel discovery job")

        jobs = self.get_jobs()
        for job in jobs.job_history:
            if job.job_id == job_id:
                self.logger.debug("found job to cancel")
                if job.end_ts is None:
                    job.end_ts = int(time())
        jobs.active_job_id = None
        self.set_jobs(jobs)

    @property
    def history(self) -> List[JobItem]:
        jobs = self.get_jobs()
        return jobs.job_history

    @property
    def job_id_list(self) -> List[str]:
        return [j.job_id for j in self.history]

    @property
    def current_job(self) -> Optional[JobItem]:
        """
        Get the current job

        The current job is the oldest unprocessed job
        """
        jobs = self.get_jobs()
        if jobs.active_job_id is None:
            return None
        return self.get_job(jobs.active_job_id)

    def __str__(self):
        def _h(i: JobItem):
            return f"Job ID: {i.job_id}, {i.success}, {i.sync_point} "

        ret = "HISTORY\n"
        for item in self.history:
            ret += _h(item)
        return ret

    def to_dot(self, graph_format: str = "svg", show_version: bool = True, show_only_active_vertices: bool = True,
               show_only_active_edges: bool = True, graph_type: str = "dot"):

        try:
            mod = importlib.import_module("graphviz")
        except ImportError:
            raise Exception("Cannot to_dot(), graphviz module is not installed.")

        dot = getattr(mod, "Digraph")(comment=f"DAG for Jobs", format=graph_format)

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

            fillcolor = "white"
            tooltip = ""

            for edge in v.edges:

                color = "grey"
                style = "solid"

                # To reduce the number of edges, only show the active edges
                if edge.active:
                    color = "black"
                    style = "bold"
                elif show_only_active_edges:
                    continue

                # If the vertex is not active, gray out the DATA edge
                if edge.edge_type == EdgeType.DATA:
                    if not v.active:
                        color = "grey"
                    elif v.has_data:

                        try:
                            data = v.content_as_object(JobContent)  # type: JobContent
                            if data.active_job_id is not None:
                                tooltip = f"Current Job Id: {data.active_job_id}\n"\
                                          f"History: \n"
                                for item in data.job_history:
                                    tooltip += f" * {item.job_id}, {item.sync_point}, {item.start_ts_str}, "\
                                               f"{item.delta}, {item.error}\n"
                                fillcolor = "#FFFF00"
                            else:
                                fillcolor = "#CFCFFF"
                        except (Exception,):
                            try:
                                data = v.content_as_object(JobItem)  # type: JobItem
                                if data.job_id is not None:
                                    tooltip = f"Job Id: {data.job_id}\n" \
                                              f"Resource ID: {data.resource_uid}\n" \
                                              f"Start Ts: {data.start_ts}\n" \
                                              f"End Ts: {data.end_ts}\n" \
                                              f"Converstion ID: {data.conversation_id}\n" \
                                              f"Error: {data.error}\n" \
                                              f"Stack Trace: {data.stacktrace}\n" \
                                              f"Sync Point: {data.sync_point}\n"
                                    fillcolor = "#FFFFF0"
                                else:
                                    fillcolor = "#CFCFFF"
                            except (Exception,):
                                fillcolor = "#CFCFFF"

                if edge.edge_type == EdgeType.DELETION:
                    style = "dotted"

                label = DAG.EDGE_LABEL.get(edge.edge_type)
                if label is None:
                    label = "UNK"
                if edge.path is not None and edge.path != "":
                    label += f"\\npath={edge.path}"
                if show_version:
                    label += f"\\nv={edge.version}"

                # tail, head (arrow side), label, ...
                dot.edge(v.uid, edge.head_uid, label, style=style, fontcolor=color, color=color)

            shape = "ellipse"

            color = "black"
            if not v.active:
                fillcolor = "grey"

            label = f"uid={v.uid}"
            dot.node(v.uid, label, color=color, fillcolor=fillcolor, style="filled", shape=shape, tooltip=tooltip)

        return dot
