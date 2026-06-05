from __future__ import annotations
from . import DataStructBase
from ..types import SyncQuery, Ref, RefType, DAGData, DataPayload, EdgeType, SyncData
from ..crypto import generate_random_bytes, generate_uid_str, bytes_to_str
import base64
from typing import Optional, List


class DataStruct(DataStructBase):

    def sync_query(self,
                   stream_id: str,
                   sync_point: int = 0,
                   graph_id: Optional[int] = None) -> SyncQuery:

        return SyncQuery(
            streamId=stream_id,
            deviceId=base64.urlsafe_b64encode(generate_random_bytes(16)).decode(),
            syncPoint=sync_point,
            graphId=graph_id
        )

    @staticmethod
    def get_sync_result(results: bytes) -> SyncData:
        res = SyncData.model_validate_json(results)
        return res

    @staticmethod
    def origin_ref(origin_ref_value: bytes,
                   name: str) -> Ref:

        return Ref(
            type=RefType.DEVICE,
            value=generate_uid_str(uid_bytes=origin_ref_value),
            name=name
        )

    def data(self,
             data_type: EdgeType,
             tail_uid: str,
             content: Optional[bytes] = None,
             head_uid: Optional[str] = None,
             tail_name: Optional[str] = None,
             head_name: Optional[str] = None,
             tail_ref_type: Optional[RefType] = None,
             head_ref_type: Optional[RefType] = None,
             path: Optional[str] = None) -> DAGData:

        if content is not None:
            content = bytes_to_str(content)

        return DAGData(
            type=data_type,
            content=content,
            # tail point at this vertex, so it uses this vertex's uid.
            ref=Ref(
                type=tail_ref_type,
                value=tail_uid,
                name=tail_name
            ),
            # Head, the arrowhead, points at the vertex this vertex belongs to, the parent.
            # Apparently, for DATA edges, the parentRef is allowed to be None.
            # Doesn't hurt to send it.
            parentRef=Ref(
                type=head_ref_type,
                value=head_uid,
                name=head_name
            ),
            path=path
        )

    @staticmethod
    def payload(origin_ref: Ref,
                data_list: List[DAGData],
                graph_id: Optional[int] = None) -> DataPayload:

        return DataPayload(
            origin=origin_ref,
            dataList=data_list,
            graphId=graph_id
        )
