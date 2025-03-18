from __future__ import annotations
from .constants import DIS_JOBS_GRAPH_ID
from .utils import get_connection
from .types import JobContent, JobItem, Settings, DiscoveryDelta
from keepercommander.keeper_dag import DAG, EdgeType
import logging
import os
import base64
from time import time
from typing import Any, Optional, List


class Jobs:

    KEY_PATH = "jobs"

    # Break up the serialized delta.
    # This is so it fits in data edge with is limit to a MySQL BLOB, 65k
    # The content will be encrypted and base64, so this delta size needs to take that in account.
    DELTA_SIZE = 48_000

    def __init__(self, record: Any, logger: Optional[Any] = None, debug_level: int = 0, fail_on_corrupt: bool = True,
                 log_prefix: str = "GS Jobs", save_batch_count: int = 200, **kwargs):

        self.conn = get_connection(**kwargs)

        # This will either be a KSM Record, or Commander KeeperRecord
        self.record = record
        self._dag = None
        if logger is None:
            logger = logging.getLogger()
        self.logger = logger
        self.log_prefix = log_prefix
        self.debug_level = debug_level
        self.fail_on_corrupt = fail_on_corrupt
        self.save_batch_count = save_batch_count

    @property
    def dag(self) -> DAG:
        if self._dag is None:

            self._dag = DAG(conn=self.conn, record=self.record, graph_id=DIS_JOBS_GRAPH_ID, auto_save=False,
                            logger=self.logger, debug_level=self.debug_level, name="Discovery Jobs",
                            fail_on_corrupt=self.fail_on_corrupt, log_prefix=self.log_prefix,
                            save_batch_count=self.save_batch_count)
            self._dag.load()

            # Has the status been initialized?
            if self._dag.has_graph is False:
                self._dag.allow_auto_save = False
                status = self._dag.add_vertex()
                status.belongs_to_root(
                    EdgeType.KEY,
                    path=Jobs.KEY_PATH)
                status.add_data(
                    content=JobContent(
                        active_job_id=None,
                        history=[]
                    ),
                )
                self._dag.allow_auto_save = True
                self._dag.save()
        return self._dag

    @property
    def data_path(self):
        return f"/{Jobs.KEY_PATH}"

    def get_jobs(self):

        self.logger.debug("loading discovery jobs from DAG")

        vertex = self.dag.walk_down_path(self.data_path)
        current_json = vertex.content_as_str
        if current_json is None:
            vertex.add_data(
                content=JobContent(
                    active_job_id=None,
                    history=[]
                ),
            )
            current_json = vertex.content_as_str

        return JobContent.model_validate_json(current_json)

    def set_jobs(self, jobs: JobContent, job_id: Optional[str] = None, delta: Optional[DiscoveryDelta] = None):

        self.logger.debug("saving discovery jobs to DAG")

        jobs_vertex = self.dag.walk_down_path(self.data_path)
        jobs_vertex.add_data(
            content=jobs
        )

        if job_id is not None and delta is not None:

            # Pretty sure we will not find the job vertex.
            # When we don't create a new vertex and give it a path of the job id.
            job_vertex = jobs_vertex.walk_down_path(job_id)
            if job_vertex is None:
                job_vertex = jobs_vertex.dag.add_vertex()
                job_vertex.belongs_to(jobs_vertex, edge_type=EdgeType.KEY, path=job_id)

            # If, for some reason, we find an existing job vertex; remove all the child vertices.
            else:
                for vertex in job_vertex.has_vertices():
                    vertex.delete()

            # From the job vertex we want to create vertices to hold the delta information.
            # Break them up based on the DELTA_SIZE.
            # Each DATA edge will contain part of the content.
            # Each delta vertex has a path so we know the order on how to re-assemble them.
            delta_content = delta.model_dump_json()
            chunk_num = 0
            while delta_content != "":
                path = str(chunk_num)

                chunk = delta_content[:Jobs.DELTA_SIZE]
                delta_content = delta_content[Jobs.DELTA_SIZE:]

                new_vertex = job_vertex.dag.add_vertex()
                new_vertex.belongs_to(job_vertex, edge_type=EdgeType.KEY, path=path)
                new_vertex.add_data(chunk)

                chunk_num += 1

        self.dag.save()

    def start(self, settings: Optional[Settings] = None, resource_uid: Optional[str] = None,
              conversation_id: Optional[str] = None) -> str:

        self.logger.debug("starting a discovery job")

        if settings is None:
            settings = Settings()

        jobs = self.get_jobs()

        new_job = JobItem(
            job_id="JOB" + base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip('='),
            start_ts=int(time()),
            settings=settings,
            resource_uid=resource_uid,
            conversation_id=conversation_id
        )
        jobs.active_job_id = new_job.job_id
        jobs.job_history.append(new_job)

        self.set_jobs(jobs)

        return new_job.job_id

    def get_job(self, job_id) -> Optional[JobItem]:
        jobs = self.get_jobs()
        for job in jobs.job_history:
            if job.job_id == job_id:

                # If the job delta is None, check to see if it chunked as vertices.
                if job.delta is None:
                    self.logger.debug(f"loading delta content from job vertex for job id {job.job_id}")
                    delta_vertex = self.dag.walk_down_path(path=f"/jobs/{job.job_id}")
                    if delta_vertex is not None:
                        delta_lookup = {}
                        vertices = delta_vertex.has_vertices()
                        self.logger.debug(f"found {len(vertices)} delta vertices")
                        for vertex in vertices:
                            edge = vertex.get_edge(delta_vertex, edge_type=EdgeType.KEY)
                            delta_lookup[int(edge.path)] = vertex

                        json_value = ""
                        # Sort numerically increasing and then append their content.
                        # This will re-assemble the JSON
                        for key in sorted(delta_lookup):
                            json_value += delta_lookup[key].content_as_str
                        job.delta = DiscoveryDelta.model_validate_json(json_value)
                    else:
                        self.logger.debug("could not find job vertex")
                else:
                    self.logger.debug("delta content was part of the JobItem")

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

        self.set_jobs(jobs,
                      job_id=job_id,
                      delta=delta)

    def cancel(self, job_id):

        self.logger.debug("cancel discovery job")

        jobs = self.get_jobs()
        for job in jobs.job_history:
            if job.job_id == job_id:
                self.logger.debug("found job to cancel")
                job.end_ts = int(time())
                job.success = None
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
