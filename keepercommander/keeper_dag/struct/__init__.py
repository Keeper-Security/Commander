from __future__ import annotations
import logging
from ..types import SyncQuery, Ref, RefType, DAGData, DataPayload, EdgeType
from ..proto import GraphSync_pb2 as gs_pb2
from pydantic import BaseModel
from typing import Optional, Union, List, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    Logger = Union[logging.RootLogger, logging.Logger]


class SyncResult(BaseModel):
    sync_point: int = 0
    data: List[DAGData] = []
    has_more: bool = False


class DataStructBase:

    def __init__(self,
                 logger: Optional[Logger] = None):

        if logger is None:
            logger = logging.getLogger()
        self.logger = logger

    def sync_query(self,
                   stream_id: str,
                   sync_point: int = 0,
                   graph_id: Optional[int] = None) -> Union[SyncQuery, gs_pb2.GraphSyncQuery]:
        pass

    @staticmethod
    def origin_ref(origin_uid: str,
                   name: str) -> Union[Ref, gs_pb2.GraphSyncRef]:
        pass

    def data(self,
             data_type: EdgeType,
             tail_uid: str,
             content: Optional[bytes] = None,
             head_uid: Optional[str] = None,
             tail_name: Optional[str] = None,
             head_name: Optional[str] = None,
             tail_ref_type: Optional[RefType] = None,
             head_ref_type: Optional[RefType] = None,
             path: Optional[str] = None) -> Union[DAGData,gs_pb2.GraphSyncData]:

        pass

    @staticmethod
    def payload(origin_ref: Union[Ref, gs_pb2.GraphSyncRef],
                data_list: List[Union[DAGData, gs_pb2.GraphSyncData]],
                graph_id: Optional[int] = None) -> Union[DataPayload, gs_pb2.GraphSyncAddDataRequest]:

        pass
