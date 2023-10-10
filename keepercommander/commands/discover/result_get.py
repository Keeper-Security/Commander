from __future__ import annotations
import argparse
import json
import importlib
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ... import vault_extensions
from ...display import bcolors
from ..pam.router_helper import router_get_connected_gateways
from discovery_common.jobs import Jobs
from discovery_common.infrastructure import Infrastructure
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from discovery_common.jobs import JobItem


class PAMGatewayActionDiscoverResultGetCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='dr-discover-command-process')
    parser.add_argument('--job-id', '-j', required=True, dest='job_id', action='store',
                        help='Discovery job id.')
    parser.add_argument('--file', required=True, dest='filename', action='store',
                        help='Save results to file.')

    def get_parser(self):
        return PAMGatewayActionDiscoverResultGetCommand.parser

    def execute(self, params, **kwargs):

        job_id = kwargs.get("job_id")

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))
        for configuration_record in configuration_records:

            gateway_context = GatewayContext.from_configuration_uid(params, configuration_record.record_uid)
            if gateway_context is None:
                continue

            jobs = Jobs(record=configuration_record, params=params)
            job_item = jobs.get_job(job_id)  # type: JobItem
            if job_item is None:
                continue

            if job_item.end_ts is None:
                print(f'{bcolors.FAIL}Discovery job is currently running. Cannot get results.{bcolors.ENDC}')
                return
            if job_item.success is False:
                print(f'{bcolors.FAIL}Discovery job failed. Cannot get results.{bcolors.ENDC}')
                return

            # TODO - Make a way to serialize the discovery into a form
            infra = Infrastructure(record=configuration_record, params=params)

            return

        print(f'{bcolors.FAIL}Discovery job not found. Cannot get results.{bcolors.ENDC}')
