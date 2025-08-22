from __future__ import annotations
from ...utils import value_to_boolean
import os
from typing import  TYPE_CHECKING

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...keeper_dag.connection import ConnectionBase


def get_connection(params: KeeperParams) -> ConnectionBase:
    if value_to_boolean(os.environ.get("USE_LOCAL_DAG", False)) is False:
        from ...keeper_dag.connection.commander import Connection as CommanderConnection
        return CommanderConnection(params=params)
    else:
        from ...keeper_dag.connection.local import Connection as LocalConnection
        return LocalConnection()