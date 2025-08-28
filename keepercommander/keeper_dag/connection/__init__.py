from __future__ import annotations
import logging
from ..__version__ import __version__
from ..exceptions import DAGException, DAGConnectionException
from ..crypto import generate_random_bytes
from ..types import SyncData, SyncQuery, DataPayload
from ..utils import value_to_boolean
import csv
import os
import json
import base64
import time
import sys
from enum import Enum
from typing import Optional, Union, TYPE_CHECKING
if TYPE_CHECKING:  # pragma: no cover
    Logger = Union[logging.RootLogger, logging.Logger]


class ConnectionBase:

    ADD_DATA = "/add_data"
    SYNC = "/sync"

    def __init__(self,
                 is_device: bool,
                 logger: Optional[Logger] = None,
                 log_transactions: Optional[bool] = None,
                 log_transactions_dir: Optional[str] = None):

        # device is a gateway device if is_device is False then we use user authentication flow
        self.is_device = is_device

        if logger is None:
            logger = logging.getLogger()
        self.logger = logger

        # Debug tool; log transaction to the file
        if log_transactions is not None:
            self.log_transactions = value_to_boolean(log_transactions)
        else:
            self.log_transactions: bool = value_to_boolean(os.environ.get("GS_LOG_TRANS", False))

        self.log_transactions_dir = os.environ.get("GS_LOG_TRANS_DIR", log_transactions_dir)
        if self.log_transactions_dir is None:
            self.log_transactions_dir = "."

        if self.log_transactions is True:
            self.logger.info("keeper-dag transaction logging is ENABLED; "
                             f"write directory at {self.log_transactions_dir}")

    def log_transaction_path(self, file: str):
        return os.path.join(self.log_transactions_dir, f"graph_{file}.csv")

    @staticmethod
    def get_record_uid(record: object) -> str:
        pass

    @staticmethod
    def get_key_bytes(record: object) -> bytes:
        pass

    def rest_call_to_router(self, http_method, endpoint, agent, payload_json=None) -> str:
        return ""

    def _endpoint(self, action: str, endpoint: Optional[str] = None) -> str:

        """
        Build the endpoint on the remote site.

        This method will attempt to fix slashes.

        :param action:
        :param endpoint:
        :return:
        """

        # Make sure endpoint is /path/to/endpoint; starting / and no ending /
        if endpoint is not None and endpoint != "":
            if isinstance(endpoint, Enum):
                endpoint = endpoint.value

            while endpoint.startswith("/"):
                endpoint = endpoint[1:]
            while endpoint.endswith("/"):
                endpoint = endpoint[:-1]
            endpoint = "/" + endpoint
        else:
            endpoint = ""

        while action.startswith("/"):
            action = action[1:]
        while action.endswith("/"):
            action = action[:-1]
        action = "/" + action

        base = "/api/device"
        if not self.is_device:
            base = "/api/user"

        return base + endpoint + action

    def write_transaction_log(self,
                              agent: str,
                              endpoint: str,
                              graph_id: Optional[int] = None,
                              payload_json: Optional[str] = None,
                              error: Optional[str] = None):
        # If log transaction is True, we want to append to the log file.

        if self.log_transactions is True:

            file_name = graph_id
            if file_name is None:
                file_name = endpoint.replace("/", "_")

            with open(self.log_transaction_path(str(file_name)), mode='a', newline='') as file:
                self.logger.debug("write add_data to transaction log")
                writer = csv.writer(file)
                writer.writerow([
                    time.time(),
                    sys.argv[0],
                    endpoint,
                    agent,
                    payload_json,
                    error
                ])
                file.close()

    def add_data(self, payload: Union[DataPayload, str], endpoint: Optional[str] = None, agent: Optional[str] = None):

        # if payload is DataPayload
        payload_data = None
        if isinstance(payload, DataPayload):
            payload_data = payload.model_dump_json()
        elif isinstance(payload, str):

            # make sure it is a valid json and raise and exception if not. make an exception for the case of a string
            # that is a valid json
            if not payload.startswith('{') and not payload.endswith('}'):
                raise DAGException(f'Invalid payload: {payload}.')

            payload_data = payload
            try:
                payload = DataPayload.model_validate_json(payload)
            except Exception as err:
                raise DAGException(f"JSON DataPayload cannot be deserialized: {err}.")

        if payload_data is None:
            raise DAGException(f'JSON  DataPayload is blank.')

        if agent is None:
            f"keeper-dag/{__version__}"

        endpoint = self._endpoint(ConnectionBase.ADD_DATA, endpoint)
        self.logger.debug(f"endpoint {endpoint}")

        try:
            self.rest_call_to_router(http_method="POST",
                                     endpoint=endpoint,
                                     payload_json=payload_data,
                                     agent=agent)
            self.write_transaction_log(
                graph_id=payload.graphId,
                payload_json=payload_data,
                agent=agent,
                endpoint=endpoint,
                error=None
            )
        except DAGConnectionException as err:
            self.write_transaction_log(
                graph_id=payload.graphId,
                payload_json=payload_data,
                agent=agent,
                endpoint=endpoint,
                error=str(err)
            )
            raise err
        except Exception as err:
            self.write_transaction_log(
                graph_id=payload.graphId,
                payload_json=payload_data,
                agent=agent,
                endpoint=endpoint,
                error=str(err)
            )
            raise DAGException(f"Could not create a new DAG structure: {err}")

    def sync(self, stream_id: str, agent: Optional[str] = None, sync_point: Optional[int] = 0,
             endpoint: Optional[str] = None, graph_id: Optional[int] = None) -> SyncData:

        if agent is None:
            f"keeper-dag/{__version__}"

        endpoint = self._endpoint(ConnectionBase.SYNC, endpoint)
        self.logger.debug(f"endpoint {endpoint}")

        sync_query = SyncQuery(
            streamId=stream_id,
            deviceId=base64.urlsafe_b64encode(generate_random_bytes(16)).decode(),
            syncPoint=sync_point,
            graphId=graph_id
        )
        sync_query_json_str = sync_query.model_dump_json()

        try:
            data_resp = self.rest_call_to_router(http_method="POST",
                                                 endpoint=endpoint,
                                                 agent=agent,
                                                 payload_json=sync_query_json_str)
            sync_data_resp = SyncData.model_validate_json(data_resp)

            self.write_transaction_log(
                graph_id=graph_id,
                payload_json=json.dumps({
                    "payload": sync_query_json_str,
                    "sync_point": sync_data_resp.syncPoint,
                    "rows": len(sync_data_resp.data)
                }),
                agent=agent,
                endpoint=endpoint,
                error=None
            )

            return sync_data_resp
        except DAGConnectionException as err:

            self.write_transaction_log(
                graph_id=graph_id,
                payload_json=json.dumps({
                    "payload": sync_query_json_str,
                    "sync_point": None,
                    "rows": 0
                }),
                agent=agent,
                endpoint=endpoint,
                error=str(err)
            )
            raise err
        except Exception as err:
            self.write_transaction_log(
                graph_id=graph_id,
                payload_json=json.dumps({
                    "payload": sync_query_json_str,
                    "sync_point": None,
                    "rows": 0
                }),
                agent=agent,
                endpoint=endpoint,
                error=str(err)
            )
            raise DAGException(f"Could not load the DAG structure: {err}")

    def debug_dump(self) -> str:
        return "Connection does not allow debug dump."
