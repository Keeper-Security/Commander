from __future__ import annotations
import logging
from ..__version__ import __version__
from ..exceptions import DAGException, DAGConnectionException
from ..crypto import generate_random_bytes
from ..types import SyncData, SyncQuery, DataPayload
import json
import base64
from typing import Optional, Union, TYPE_CHECKING
if TYPE_CHECKING:  # pragma: no cover
    Logger = Union[logging.RootLogger, logging.Logger]


class ConnectionBase:

    def __init__(self, is_device: bool, logger: Optional[Logger] = None):
        # device is a gateway device if is_device is False then we use user authentication flow
        self.is_device = is_device

        if logger is None:
            logger = logging.getLogger()
        self.logger = logger

    @staticmethod
    def get_record_uid(record: object) -> str:
        pass

    @staticmethod
    def get_key_bytes(record: object) -> bytes:
        pass

    def rest_call_to_router(self, http_method, endpoint, agent, payload_json=None) -> str:
        return ""

    def _endpoint(self, action: str) -> str:
        if action.startswith("/") is False:
            action = "/" + action

        base = "/api/device"
        if not self.is_device:
            base = "/api/user"
        return base + action

    def add_data(self, payload: Union[DataPayload, str], agent: Optional[str] = None):

        # if payload is DataPayload
        if isinstance(payload, DataPayload):
            payload_data = payload.model_dump_json()
        elif isinstance(payload, str):
            payload_data = payload

            # make sure it is a valid json and raise and exception if not. make an exception for the case of a string
            # that is a valid json
            if not payload_data.startswith('{') and not payload_data.endswith('}'):
                raise DAGException(f'Invalid payload: {payload_data}')

            # double check if it is a valid json inside the string
            json.loads(payload_data)
        else:
            raise DAGException(f'Unsupported payload type: {type(payload)}')

        if agent is None:
            f"keeper-dag/{__version__}"

        try:
            self.rest_call_to_router(http_method="POST",
                                     endpoint=self._endpoint("/add_data"),
                                     payload_json=payload_data,
                                     agent=agent)
        except DAGConnectionException as err:
            raise err
        except Exception as err:
            raise DAGException(f"Could not create a new DAG structure: {err}")

    def sync(self, stream_id: str, agent: Optional[str] = None, sync_point: Optional[int] = 0,
             graph_id: Optional[int] = 0) -> SyncData:

        if agent is None:
            f"keeper-dag/{__version__}"

        try:
            sync_query = SyncQuery(
                streamId=stream_id,
                deviceId=base64.urlsafe_b64encode(generate_random_bytes(16)).decode(),
                syncPoint=sync_point,
                graphId=graph_id
            )
            sync_query_json_str = sync_query.model_dump_json()

            data_resp = self.rest_call_to_router(http_method="POST",
                                                 endpoint=self._endpoint("/sync"),
                                                 agent=agent,
                                                 payload_json=sync_query_json_str)
            sync_data_resp = SyncData.model_validate_json(data_resp)

            return sync_data_resp
        except DAGConnectionException as err:
            raise err
        except Exception as err:
            raise DAGException(f"Could not load the DAG structure: {err}")

    def debug_dump(self) -> str:
        return "Connection does not allow debug dump."
