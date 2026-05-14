#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
"""PAM extended: discovery rule commands.

Discovery rules live in the PAM DAG under PamGraphId.DISCOVERY_RULES.
Commander reads/writes them via the ``PAMModifyRequest`` + ``PAMDataOperation``
mechanism (ADD / UPDATE / DELETE on PAMElementData).

Commands:
  pam extended rule list   [--config-uid <uid>]
  pam extended rule add    <name> --type <machine|user|db> --cidr <cidr> --config-uid <uid>
  pam extended rule delete <name_or_uid> --config-uid <uid>
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from typing import TYPE_CHECKING

from ..base import ArgparseCommand
from ...error import CommandError
from ... import utils

if TYPE_CHECKING:
    from ...params import KeeperParams

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_dag_rules(params: "KeeperParams", config_uid: str) -> list[dict]:
    """Return discovery rules from the PAM DAG for a configuration."""
    try:
        from ...keeper_dag.types import PamGraphId
        from ...keeper_dag.vertex import DAGVertex
    except ImportError:
        return []

    config_uid_bytes = utils.base64_url_decode(config_uid)
    dag = getattr(params, "pam_dag", None)
    if dag is None:
        return []

    config_vertex = dag.get_vertex(config_uid_bytes)
    if config_vertex is None:
        return []

    rules_vertex = config_vertex.get_child(PamGraphId.DISCOVERY_RULES)
    if rules_vertex is None:
        return []

    rows = []
    for child in rules_vertex.children:
        data = child.data
        if isinstance(data, (bytes, bytearray)):
            try:
                data = json.loads(data)
            except Exception:
                data = {}
        rows.append({"uid": child.uid.hex() if isinstance(child.uid, bytes) else child.uid,
                     **data})
    return rows


def _modify_dag_rule(params: "KeeperParams", config_uid: str,
                     operation: str, rule_data: dict,
                     element_uid: bytes | None = None) -> None:
    """Apply an ADD / UPDATE / DELETE operation on a discovery rule DAG element."""
    from ...proto import pam_pb2
    from ...api import communicate_rest

    op_map = {"ADD": pam_pb2.PAMOperationType.ADD,
               "UPDATE": pam_pb2.PAMOperationType.UPDATE,
               "DELETE": pam_pb2.PAMOperationType.DELETE}
    if operation not in op_map:
        raise CommandError(f"Unknown operation: {operation}")

    config_uid_bytes = utils.base64_url_decode(config_uid)
    element_uid_bytes = element_uid or os.urandom(16)

    data_op = pam_pb2.PAMDataOperation()
    data_op.operationType = op_map[operation]

    element = pam_pb2.PAMElementData()
    element.elementUid = element_uid_bytes
    element.parentUid = config_uid_bytes
    element.data = json.dumps(rule_data).encode()
    data_op.element.CopyFrom(element)

    rq = pam_pb2.PAMModifyRequest()
    rq.operations.append(data_op)
    communicate_rest(params, rq, "pam/modify", rs_type=pam_pb2.PAMModifyResult)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

class PamExtendedRuleListCommand(ArgparseCommand):
    """``pam extended rule list``."""

    def __init__(self) -> None:
        parser = argparse.ArgumentParser(prog="list", description="List PAM discovery rules")
        parser.add_argument("--config-uid", dest="config_uid", required=True)
        parser.add_argument("--format", dest="fmt", choices=["table", "json"], default="table")
        super().__init__(parser)

    def execute(self, params: "KeeperParams", **kwargs) -> None:
        rows = _get_dag_rules(params, kwargs["config_uid"])
        if kwargs.get("fmt") == "json":
            print(json.dumps(rows, indent=2))
        else:
            if not rows:
                print("No discovery rules found.")
                return
            for r in rows:
                print(f"  {r.get('uid', '?')}  name={r.get('name', '?')}  "
                      f"type={r.get('target_type', '?')}  cidr={r.get('target_cidr', '?')}")


class PamExtendedRuleAddCommand(ArgparseCommand):
    """``pam extended rule add``."""

    def __init__(self) -> None:
        parser = argparse.ArgumentParser(prog="add", description="Add a PAM discovery rule")
        parser.add_argument("name", help="Rule name")
        parser.add_argument(
            "--type", dest="target_type",
            choices=["machine", "user", "database"], default="machine",
        )
        parser.add_argument("--cidr", dest="target_cidr", required=True, help="Target CIDR range")
        parser.add_argument(
            "--protocol", dest="protocol",
            choices=["ssh", "rdp", "database"], default="ssh",
        )
        parser.add_argument("--config-uid", dest="config_uid", required=True)
        parser.add_argument(
            "--credential-uid", dest="credential_uid", default=None,
            help="Credential record UID",
        )
        super().__init__(parser)

    def execute(self, params: "KeeperParams", **kwargs) -> None:
        rule_data = {
            "name": kwargs["name"],
            "target_type": kwargs.get("target_type", "machine"),
            "target_cidr": kwargs["target_cidr"],
            "protocol": kwargs.get("protocol", "ssh"),
        }
        if kwargs.get("credential_uid"):
            rule_data["credential_uid_ref"] = kwargs["credential_uid"]

        _modify_dag_rule(params, kwargs["config_uid"], "ADD", rule_data)
        print(f"Discovery rule '{kwargs['name']}' added to config {kwargs['config_uid']}")


class PamExtendedRuleDeleteCommand(ArgparseCommand):
    """``pam extended rule delete``."""

    def __init__(self) -> None:
        parser = argparse.ArgumentParser(prog="delete", description="Delete a PAM discovery rule")
        parser.add_argument("uid", help="Rule element UID (hex)")
        parser.add_argument("--config-uid", dest="config_uid", required=True)
        super().__init__(parser)

    def execute(self, params: "KeeperParams", **kwargs) -> None:
        element_uid = bytes.fromhex(kwargs["uid"])
        _modify_dag_rule(
            params, kwargs["config_uid"], "DELETE", {},
            element_uid=element_uid,
        )
        print(f"Discovery rule {kwargs['uid']} deleted from config {kwargs['config_uid']}")
