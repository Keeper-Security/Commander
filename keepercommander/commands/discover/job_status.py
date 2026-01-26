from __future__ import annotations
import argparse
import logging
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ..pam.router_helper import router_get_connected_gateways
from ... import vault_extensions
from ...display import bcolors
from ...discovery_common.jobs import Jobs
from ...discovery_common.infrastructure import Infrastructure
from ...discovery_common.constants import DIS_INFRA_GRAPH_ID
from ...discovery_common.types import DiscoveryDelta, DiscoveryObject
from ...keeper_dag.dag import DAG
from typing import Optional, Dict, List, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...discovery_common.jobs import JobItem


def _h(text):
    return f"{bcolors.HEADER}{text}{bcolors.ENDC}"


def _f(text):
    return f"{bcolors.FAIL}{text}{bcolors.ENDC}"


def _g(text):
    return f"{bcolors.OKGREEN}{text}{bcolors.ENDC}"


def _b(text):
    return f"{bcolors.OKBLUE}{text}{bcolors.ENDC}"


class PAMGatewayActionDiscoverJobStatusCommand(PAMGatewayActionDiscoverCommandBase):
    """
    Get the status of discovery jobs.

    If no parameters are given, it will check all gateways for discovery job status.

    """

    parser = argparse.ArgumentParser(prog='pam action discover status')
    parser.add_argument('--gateway', '-g', required=False, dest='gateway', action='store',
                        help='Show only discovery jobs from a specific gateway.')
    parser.add_argument('--job-id', '-j', required=False, dest='job_id', action='store',
                        help='Detailed information for a specific discovery job.')
    parser.add_argument('--history', required=False, dest='show_history', action='store_true',
                        help='Show history')
    parser.add_argument('--configuration-uid', '-c', required=False, dest='configuration_uid',
                        action='store', help='PAM configuration UID is using --history')

    def get_parser(self):
        return PAMGatewayActionDiscoverJobStatusCommand.parser

    @staticmethod
    def print_job_table(jobs: List[Dict],
                        max_gateway_name: int,
                        show_history: bool = False):

        """
        Print jobs in a table.

        This method takes a list of dictionary item which contains the cooked job information.

        """

        print("")
        print(f"{bcolors.HEADER}{'Job ID'.ljust(14, ' ')} "
              f"{'Gateway Name'.ljust(max_gateway_name, ' ')} "
              f"{'Gateway UID'.ljust(22, ' ')} "
              f"{'Configuration UID'.ljust(22, ' ')} "
              f"{'Status'.ljust(12, ' ')} "
              f"{'Resource UID'.ljust(22, ' ')} "
              f"{'Started'.ljust(19, ' ')} "
              f"{'Completed'.ljust(19, ' ')} "
              f"{'Duration'.ljust(19, ' ')} "
              f"{bcolors.ENDC}")

        print(f"{''.ljust(14, '=')} "
              f"{''.ljust(max_gateway_name, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(12, '=')} "
              f"{''.ljust(22, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(19, '=')} "
              f"{''.ljust(19, '=')}")

        completed_jobs = []
        running_jobs = []
        failed_jobs = []

        for job in jobs:
            color = ""
            job_id = job['job_id']
            if job['status'] == "COMPLETE":
                color = bcolors.OKGREEN
                completed_jobs.append(job_id)
            elif job['status'] == "RUNNING":
                color = bcolors.OKBLUE
                running_jobs.append(job_id)
            elif job['status'] == "FAILED":
                failed_jobs.append(job_id)
                color = bcolors.FAIL
            print(f"{color}{job_id} "
                  f"{job['gateway'].ljust(max_gateway_name, ' ')} "
                  f"{job['gateway_uid']} "
                  f"{job['configuration_uid']} "
                  f"{job['status'].ljust(12, ' ')} "
                  f"{(job.get('resource_uid') or 'NA').ljust(22, ' ')} "
                  f"{(job.get('start_ts_str') or 'NA').ljust(19, ' ')} "
                  f"{(job.get('end_ts_str') or 'NA').ljust(19, ' ')} "
                  f"{(job.get('duration') or 'NA').ljust(19, ' ')} "
                  f"{bcolors.ENDC}")

        if len(completed_jobs) > 0 and show_history is False:
            print("")
            if len(completed_jobs) == 1:
                print(f"There is one {_g('COMPLETED')} job. To process, use the following command.")
            else:
                print(f"There are {len(completed_jobs)} {_g('COMPLETED')} jobs. "
                      "To process, use one of the the following commands.")
            for job_id in completed_jobs:
                print(_g(f"  pam action discover process -j {job_id}"))

        if len(running_jobs) > 0 and show_history is False:
            print("")
            if len(running_jobs) == 1:
                print(f"There is one {_b('RUNNING')} job. "
                      "If there is a problem, use the following command to cancel/remove the job.")
            else:
                print(f"There are {len(running_jobs)} {_b('RUNNING')} jobs. "
                      "If there is a problem, use one of the following commands to cancel/remove the job.")
            for job_id in running_jobs:
                print(_b(f"  pam action discover remove -j {job_id}"))

        if len(failed_jobs) > 0 and show_history is False:
            print("")
            if len(failed_jobs) == 1:
                print(f"There is one {_f('FAILED')} job. "
                      "If there is a problem, use the following command to get more information.")
            else:
                print(f"There are {len(failed_jobs)} {_f('FAILED')} jobs. "
                      "If there is a problem, use one of the following commands to get more information.")
            for job_id in failed_jobs:
                print(_f(f"  pam action discover status -j {job_id}"))
            print("")
            if len(failed_jobs) == 1:
                print(f"To remove the job, use the following command.")
            else:
                print(f"To remove the {_f('FAILED')} job, use one of the following commands.")
            for job_id in failed_jobs:
                print(_f(f"  pam action discover remove -j {job_id}"))

        print("")

    @staticmethod
    def print_job_detail(params: KeeperParams,
                         all_gateways: List,
                         job_id: str):

        def _find_job(configuration_record) -> Optional[Dict]:
            jobs_obj = Jobs(record=configuration_record, params=params)
            job_item = jobs_obj.get_job(job_id)
            if job_item is not None:
                return {
                    "jobs": jobs_obj,
                }
            return None

        gateway_context, payload = GatewayContext.find_gateway(params=params,
                                                               find_func=_find_job,
                                                               gateways=all_gateways)

        if gateway_context is not None:
            jobs = payload["jobs"]
            job = jobs.get_job(job_id)  # type: JobItem
            infra = Infrastructure(record=gateway_context.configuration, params=params)

            color = bcolors.OKBLUE
            status = "RUNNING"
            if job.end_ts is not None and not job.error:
                if job.success is None:
                    color = bcolors.WHITE
                    status = "CANCELLED"
                else:
                    color = bcolors.OKGREEN
                    status = "COMPLETE"
            elif job.error:
                color = bcolors.FAIL
                status = "FAILED"

            color_status = f"{color}{status}{bcolors.ENDC}"

            print("")
            print(f"{_h('Job ID')}: {job.job_id}")
            print(f"{_h('Sync Point')}: {job.sync_point}")
            print(f"{_h('Gateway Name')}: {gateway_context.gateway_name}")
            print(f"{_h('Gateway UID')}: {gateway_context.gateway_uid}")
            print(f"{_h('Configuration UID')}: {gateway_context.configuration_uid}")
            print(f"{_h('Status')}: {color_status}")
            print(f"{_h('Resource UID')}: {job.resource_uid or 'NA'}")
            print(f"{_h('Started')}: {job.start_ts_str}")
            print(f"{_h('Completed')}: {job.end_ts_str}")
            print(f"{_h('Duration')}: {job.duration_sec_str}")

            # If it failed, show the error and stacktrace.
            if status == "FAILED":
                print("")
                print(f"{_h('Gateway Error')}:")
                print(f"{color}{job.error}{bcolors.ENDC}")
                print("")
                print(f"{_h('Gateway Stacktrace')}:")
                print(f"{color}{job.stacktrace}{bcolors.ENDC}")
            # If it finished, show information about what was discovered.
            elif job.end_ts is not None:

                try:
                    infra.load(sync_point=0)
                    print("")
                    delta_json = job.delta
                    if delta_json is not None:
                        delta = DiscoveryDelta.model_validate(delta_json)
                        print(f"{_h('Added')} - {len(delta.added)} count")
                        for item in delta.added:
                            vertex = infra.dag.get_vertex(item.uid)
                            if vertex is None or vertex.active is False or vertex.has_data is False:
                                logging.debug("added: vertex is none, inactive or has no data")
                                continue
                            discovery_object = DiscoveryObject.get_discovery_object(vertex)
                            print(f"  * {discovery_object.description}")

                        print("")
                        print(f"{_h('Changed')} - {len(delta.changed)} count")
                        for item in delta.changed:
                            vertex = infra.dag.get_vertex(item.uid)
                            if vertex is None or vertex.active is False or vertex.has_data is False:
                                logging.debug("changed: vertex is none, inactive or has no data")
                                continue
                            discovery_object = DiscoveryObject.get_discovery_object(vertex)
                            print(f"  * {discovery_object.description}")
                            if item.changes is None:
                                print(f"    no changed, may be a object not added in prior discoveries.")
                            else:
                                for key, value in item.changes.items():
                                    print(f"    - {key} = {value}")

                        print("")
                        print(f"{_h('Deleted')} - {len(delta.deleted)} count")
                        for item in delta.deleted:
                            print(f"  * discovery vertex {item.uid}")
                    else:
                        print(f"{_f('There are no available delta changes for this job.')}")

                except Exception as err:
                    print(f"{_f('Could not load delta from infrastructure: ' + str(err))}")
                    print("Fall back to raw graph.")
                    print("")
                    dag = DAG(conn=infra.conn, record=infra.record, graph_id=DIS_INFRA_GRAPH_ID)
                    print(dag.to_dot_raw(sync_point=job.sync_point, rank_dir="RL"))

        else:
            print(f"{bcolors.FAIL}Could not find the gateway with job {job_id}.")

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        # If this is set, only show status for this gateway and history for this gateway.
        gateway_filter = kwargs.get("gateway")

        # If this is set, only show detailed information about this job.
        job_id = kwargs.get("job_id")

        # Show the history for the gateway.
        # gateway_filter needs to be set for
        show_history = kwargs.get("show_history")

        # Get all the gateways here so we don't have to keep calling this method.
        # It gets passed into find_gateway, and find_gateway will pass it around.
        all_gateways = GatewayContext.all_gateways(params)

        # If we are showing all gateways, disable show history.
        # History is shown for a specific gateway.
        if gateway_filter is None:
            show_history = False

        # This is used to format the table. Start with a length of 12 characters for the gateway.
        max_gateway_name = 12

        # If we have a job id, only display information about the one job
        if job_id:
            self.print_job_detail(params=params,
                                  all_gateways=all_gateways,
                                  job_id=job_id)

        # Else show jobs in a table
        else:

            # Based on parameters set by user, select specific jobs to be displayed.
            selected_jobs = []  # type: List[Dict]

            # For each configuration/ gateway, we are going to get all jobs.
            # We are going to query the gateway for any updated status.

            configuration_records = GatewayContext.get_configuration_records(params=params)
            for configuration_record in configuration_records:

                gateway_context = GatewayContext.from_configuration_uid(
                    params=params,
                    configuration_uid=configuration_record.record_uid,
                    gateways=all_gateways)

                if gateway_context is None:
                    continue

                # If we are using a gateway filter, and this gateway is not the one, then go onto the next conf/gateway.
                if gateway_filter is not None and gateway_context.is_gateway(gateway_filter) is False:
                    continue

                # If the gateway name is longer that the prior, set the max length to this gateway's name.
                if len(gateway_context.gateway_name) > max_gateway_name:
                    max_gateway_name = len(gateway_context.gateway_name)

                jobs = Jobs(record=configuration_record, params=params)
                if show_history is True:
                    job_list = reversed(jobs.history)
                else:
                    job_list = []
                    if jobs.current_job is not None:
                        job_list = [jobs.current_job]

                for job_item in job_list:
                    job = job_item.model_dump()
                    job["status"] = "RUNNING"
                    if job_item.start_ts is not None:
                        job["start_ts_str"] = job_item.start_ts_str
                    if job_item.end_ts is not None:
                        job["end_ts_str"] = job_item.end_ts_str
                        job["status"] = "COMPLETE"

                    job["duration"] = job_item.duration_sec_str

                    job["gateway"] = gateway_context.gateway_name
                    job["gateway_uid"] = gateway_context.gateway_uid
                    job["configuration_uid"] = gateway_context.configuration_uid

                    # This is needs for details
                    job["gateway_context"] = gateway_context
                    job["job_item"] = job_item

                    if job_item.success is None and job_item.end_ts:
                        job["status"] = "CANCELLED"
                    elif job_item.success is False:
                        job["status"] = "FAILED"

                    selected_jobs.append(job)

            if len(selected_jobs) == 0:
                print(f"{bcolors.FAIL}There are no discovery jobs. Use 'pam action discover start' to start a "
                      f"discovery job.{bcolors.ENDC}")
                return

            self.print_job_table(jobs=selected_jobs,
                                 max_gateway_name=max_gateway_name,
                                 show_history=show_history)
