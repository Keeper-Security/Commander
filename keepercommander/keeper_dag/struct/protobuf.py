from __future__ import annotations
from . import DataStructBase
from ..proto import GraphSync_pb2 as gs_pb2
from ..types import RefType, EdgeType, Ref, SyncData, SyncDataItem
from ..crypto import generate_random_bytes, urlsafe_str_to_bytes, bytes_to_urlsafe_str
from typing import Optional, List


class DataStruct(DataStructBase):

    # https://github.com/Keeper-Security/keeperapp-protobuf/blob/master/GraphSync.proto

    REF_TO_PB_MAP = {
        RefType.GENERAL: gs_pb2.RefType.RFT_GENERAL,
        RefType.USER: gs_pb2.RefType.RFT_USER,
        RefType.DEVICE: gs_pb2.RefType.RFT_DEVICE,
        RefType.REC: gs_pb2.RefType.RFT_REC,
        RefType.FOLDER: gs_pb2.RefType.RFT_FOLDER,
        RefType.TEAM: gs_pb2.RefType.RFT_TEAM,
        RefType.ENTERPRISE: gs_pb2.RefType.RFT_ENTERPRISE,
        RefType.PAM_DIRECTORY: gs_pb2.RefType.RFT_PAM_DIRECTORY,
        RefType.PAM_MACHINE: gs_pb2.RefType.RFT_PAM_MACHINE,
        RefType.PAM_DATABASE: gs_pb2.RefType.RFT_PAM_DATABASE,
        RefType.PAM_USER: gs_pb2.RefType.RFT_PAM_USER,
        RefType.PAM_NETWORK: gs_pb2.RefType.RFT_PAM_NETWORK,
        RefType.PAM_BROWSER: gs_pb2.RefType.RFT_PAM_BROWSER,
        RefType.CONNECTION: gs_pb2.RefType.RFT_CONNECTION,
        RefType.WORKFLOW: gs_pb2.RefType.RFT_WORKFLOW,
        RefType.NOTIFICATION: gs_pb2.RefType.RFT_NOTIFICATION,
        RefType.USER_INFO: gs_pb2.RefType.RFT_USER_INFO,
        RefType.TEAM_INFO: gs_pb2.RefType.RFT_TEAM_INFO,
        RefType.ROLE: gs_pb2.RefType.RFT_ROLE
    }

    DATA_TO_PB_MAP = {
        EdgeType.DATA: gs_pb2.GraphSyncDataType.GSE_DATA,
        EdgeType.KEY: gs_pb2.GraphSyncDataType.GSE_KEY,
        EdgeType.LINK: gs_pb2.GraphSyncDataType.GSE_LINK,
        EdgeType.ACL: gs_pb2.GraphSyncDataType.GSE_ACL,
        EdgeType.DELETION: gs_pb2.GraphSyncDataType.GSE_DELETION
    }

    PB_TO_REF_MAP = {v: k for k, v in REF_TO_PB_MAP.items()}
    PB_TO_DATA_MAP = {v: k for k, v in DATA_TO_PB_MAP.items()}

    def sync_query(self,
                   stream_id: str,
                   sync_point: int = 0,
                   graph_id: Optional[int] = None) -> gs_pb2.GraphSyncQuery:

        return gs_pb2.GraphSyncQuery(
            streamId=urlsafe_str_to_bytes(stream_id),
            origin=generate_random_bytes(16),
            syncPoint=sync_point,

            # Use the default from KRouter; currently 500
            maxCount=0
        )

    @staticmethod
    def _sync_data_from_result(message: gs_pb2.GraphSyncResult) -> SyncData:
        """Convert a single GraphSyncResult protobuf into a SyncData pydantic
        model. Extracted so both single-`sync` and multi_sync code paths share
        identical per-result decoding.
        """
        data_list: List[SyncDataItem] = []
        for item in message.data:
            data_list.append(
                SyncDataItem(
                    type=DataStruct.PB_TO_DATA_MAP.get(item.data.type),
                    content=item.data.content,
                    content_is_base64=False,
                    ref=Ref(
                        type=DataStruct.PB_TO_REF_MAP.get(item.data.ref.type),
                        value=bytes_to_urlsafe_str(item.data.ref.value),
                    ),
                    parentRef=Ref(
                        type=DataStruct.PB_TO_REF_MAP.get(item.data.parentRef.type),
                        value=bytes_to_urlsafe_str(item.data.parentRef.value)
                    ),
                    path=item.data.path
                )
            )

        return SyncData(
            syncPoint=message.syncPoint,
            data=data_list,
            hasMore=message.hasMore,
            streamId=bytes(message.streamId) if message.streamId else None,
        )

    @staticmethod
    def get_sync_result(results: bytes) -> SyncData:

        try:
            message = gs_pb2.GraphSyncResult()
            message.ParseFromString(results)
        except Exception as err:
            raise Exception(f"Could not parse the GraphSyncResult message: {err}")

        return DataStruct._sync_data_from_result(message)

    @staticmethod
    def origin_ref(origin_ref_value: bytes,
                   name: str) -> gs_pb2.GraphSyncRef:

        return gs_pb2.GraphSyncRef(
            type=gs_pb2.RefType.RFT_DEVICE,
            value=origin_ref_value,
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
             path: Optional[str] = None) -> gs_pb2.GraphSyncData:

        if isinstance(tail_uid, str):
            tail_uid = urlsafe_str_to_bytes(tail_uid)
        if head_uid is not None and isinstance(head_uid, str):
            head_uid = urlsafe_str_to_bytes(head_uid)

        return gs_pb2.GraphSyncData(
            type=DataStruct.DATA_TO_PB_MAP.get(data_type),
            content=content,
            # tail point at this vertex, so it uses this vertex's uid.
            ref=gs_pb2.GraphSyncRef(
                type=DataStruct.REF_TO_PB_MAP.get(tail_ref_type),
                value=tail_uid,
                name=tail_name
            ),
            # Head, the arrowhead, points at the vertex this vertex belongs to, the parent.
            # Apparently, for DATA edges, the parentRef is allowed to be None.
            # Doesn't hurt to send it.
            parentRef=gs_pb2.GraphSyncRef(
                type=DataStruct.REF_TO_PB_MAP.get(head_ref_type),
                value=head_uid,
                name=head_name
            ),
            path=path
        )

    @staticmethod
    def payload(origin_ref: gs_pb2.GraphSyncRef,
                data_list: List[gs_pb2.GraphSyncData],
                graph_id: Optional[int] = None) -> gs_pb2.GraphSyncAddDataRequest:

        return gs_pb2.GraphSyncAddDataRequest(
            origin=origin_ref,
            data=data_list)

    # --- Per-graph multi-stream read transport ---------------------------

    def leafs_query(self, vertices: List[str]) -> gs_pb2.GraphSyncLeafsQuery:
        return gs_pb2.GraphSyncLeafsQuery(
            vertices=[urlsafe_str_to_bytes(v) for v in vertices]
        )

    @staticmethod
    def get_leafs_result(results: bytes) -> List[Ref]:
        msg = gs_pb2.GraphSyncRefsResult()
        try:
            msg.ParseFromString(results)
        except Exception as err:
            raise Exception(f"Could not parse the GraphSyncRefsResult message: {err}")
        return [
            Ref(
                type=DataStruct.PB_TO_REF_MAP.get(r.type),
                value=bytes_to_urlsafe_str(r.value),
                name=r.name or None,
            )
            for r in msg.refs
        ]

    def multi_sync_query(self,
                         stream_ids: List[bytes],
                         origin: bytes,
                         sync_point: int = 0) -> gs_pb2.GraphSyncMultiQuery:
        return gs_pb2.GraphSyncMultiQuery(queries=[
            gs_pb2.GraphSyncQuery(
                streamId=sid,
                origin=origin,
                syncPoint=sync_point,
                maxCount=0,    # let krouter default (currently 500)
            )
            for sid in stream_ids
        ])

    @staticmethod
    def get_multi_sync_result(results: bytes) -> List[SyncData]:
        msg = gs_pb2.GraphSyncMultiResult()
        try:
            msg.ParseFromString(results)
        except Exception as err:
            raise Exception(f"Could not parse the GraphSyncMultiResult message: {err}")
        return [DataStruct._sync_data_from_result(r) for r in msg.results]
