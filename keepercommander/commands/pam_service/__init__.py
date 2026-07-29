from __future__ import annotations
from ...discovery_common.types import NormalizedRecord, RecordField
from ...utils import value_to_boolean
from ... import vault
import os
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...vault import TypedRecord
    from ...keeper_dag.connection import ConnectionBase


def get_connection(params: KeeperParams) -> ConnectionBase:
    if value_to_boolean(os.environ.get("USE_LOCAL_DAG", False)) is False:
        from ...keeper_dag.connection.commander import Connection as CommanderConnection
        return CommanderConnection(params=params)
    else:
        from ...keeper_dag.connection.local import Connection as LocalConnection
        return LocalConnection()


def record_lookup(record_uid: str,
                  context: Any | None = None,
                  **kwargs) -> NormalizedRecord | None:

    """
    Get the record from the Vault, normalize it, and return it.

    Since common code is using this method we want to flatten/abstract the KeeperRecord/TypedRecord.
    """

    params = context.get("params")
    record = vault.TypedRecord.load(params, record_uid)  # type: TypedRecord | None
    if record is None:
        return None

    normalized_record = NormalizedRecord(
        record_uid=record.record_uid,
        record_type=record.record_type,
        record_key_bytes=record.record_key,
        title=record.title,
    )
    for field in record.fields:
        normalized_record.fields.append(
            RecordField(
                type=field.type,
                label=field.label,
                value=field.value,
            )
        )
    if record.custom is not None:
        for field in record.custom:
            normalized_record.fields.append(
                RecordField(
                    type=field.type,
                    label=field.label,
                    value=field.value,
                )
            )
    return normalized_record