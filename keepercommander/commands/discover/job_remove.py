from __future__ import annotations
import argparse
import logging
from . import PAMGatewayActionDiscoverCommandBase, GatewayContext
from ..pam.pam_dto import GatewayActionDiscoverJobRemoveInputs, GatewayActionDiscoverJobRemove, GatewayAction
from ..pam.router_helper import router_send_action_to_gateway, router_get_connected_gateways
from ... import vault_extensions
from ...display import bcolors
from ...discovery_common.jobs import Jobs
from ...proto import pam_pb2


class PAMGatewayActionDiscoverJobRemoveCommand(PAMGatewayActionDiscoverCommandBase):
    parser = argparse.ArgumentParser(prog='pam-action-discover-remove')
    parser.add_argument('--job-id', '-j', required=True, dest='job_id', action='store',
                        help='Discovery job id.')

    def get_parser(self):
        return PAMGatewayActionDiscoverJobRemoveCommand.parser

    def execute(self, params, **kwargs):

        if not hasattr(params, 'pam_controllers'):
            router_get_connected_gateways(params)

        job_id = kwargs.get("job_id")

        # Get all the PAM configuration records
        configuration_records = list(vault_extensions.find_records(params, "pam.*Configuration"))
        all_gateways = GatewayContext.all_gateways(params)

        for configuration_record in configuration_records:

            gateway_context = GatewayContext.from_configuration_uid(params=params,
                                                                    configuration_uid=configuration_record.record_uid,
                                                                    gateways=all_gateways)
            if gateway_context is None:
                continue

            jobs = Jobs(record=configuration_record, params=params)
            job_item = jobs.get_job(job_id)
            if job_item is not None:

                try:
                    # First, cancel the running discovery job if it is running.
                    logging.debug("cancel job on the gateway, if running")
                    action_inputs = GatewayActionDiscoverJobRemoveInputs(
                        configuration_uid=gateway_context.configuration_uid,
                        job_id=job_id
                    )

                    conversation_id = GatewayAction.generate_conversation_id()
                    router_response = router_send_action_to_gateway(
                        params=params,
                        gateway_action=GatewayActionDiscoverJobRemove(
                            inputs=action_inputs,
                            conversation_id=conversation_id),
                        message_type=pam_pb2.CMT_DISCOVERY,
                        is_streaming=False,
                        destination_gateway_uid_str=gateway_context.gateway_uid
                    )

                    data = self.get_response_data(router_response)
                    if data is None:
                        raise Exception("The router returned a failure.")
                    elif data.get("success") is False:
                        error = data.get("error")
                        raise Exception(f"Discovery job was not removed: {error}")
                except Exception as err:
                    logging.debug(f"gateway return error removing discovery job: {err}")

                jobs.cancel(job_id)

                print(f"{bcolors.OKGREEN}Discovery job has been removed or cancelled.{bcolors.ENDC}")
                return

        print(f'{bcolors.FAIL}Discovery job not found. Cannot get remove the job.{bcolors.ENDC}')
        return
