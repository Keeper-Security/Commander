from __future__ import annotations
from ...utils import value_to_boolean
import os
from typing import TYPE_CHECKING

from ..pam_import.record_loader import load_pam_record  # noqa: F401  — re-export for pam_debug modules
from ...error import CommandError

if TYPE_CHECKING:
    from ...params import KeeperParams
    from ...keeper_dag.connection import ConnectionBase


def get_connection(params: KeeperParams) -> ConnectionBase:
    use_local_dag = value_to_boolean(os.environ.get("USE_LOCAL_DAG", False))
    if use_local_dag and getattr(params, 'service_mode', False):
        raise CommandError(
            'pam action debug dump',
            'The local DAG engine is not available through Service Mode.',
        )
    if use_local_dag is False:
        from ...keeper_dag.connection.commander import Connection as CommanderConnection
        # New per-graph endpoints (`/api/user/graph-sync/<graph>/<verb>`) are
        # protobuf-only — JSON reads on those routes return empty. Match the
        # default in `discovery_common.utils.get_connection`.
        return CommanderConnection(params=params,
                                   use_read_protobuf=True,
                                   use_write_protobuf=True)
    else:
        from ...keeper_dag.connection.local import Connection as LocalConnection
        return LocalConnection()
