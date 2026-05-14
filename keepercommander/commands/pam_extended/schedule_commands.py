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
"""PAM extended: named rotation schedule commands.

Schedules are stored as JSON inside ``PAMRotationSchedule.scheduleData``.
Commander sets them via the ``set_pam_rotation_schedule`` REST endpoint.

Commands:
  pam extended schedule list   [--config-uid <uid>]
  pam extended schedule set    <uid_ref> --cron <expr> [--config-uid <uid>]
  pam extended schedule delete <uid_ref> [--config-uid <uid>]
"""
from __future__ import annotations

import argparse
import json
import logging
from typing import TYPE_CHECKING

from ..base import ArgparseCommand
from ...error import CommandError

if TYPE_CHECKING:
    from ...params import KeeperParams

logger = logging.getLogger(__name__)


def _set_schedule(params: "KeeperParams", record_uid: str,
                  config_uid: str, cron_expr: str, notify_emails: list[str] | None = None) -> None:
    """Write a named rotation schedule via the PAM rotation REST endpoint."""
    from ...proto import pam_pb2
    from ...api import communicate_rest

    rq = pam_pb2.PAMRotationSchedule()
    rq.recordUid = bytes.fromhex(record_uid) if len(record_uid) == 32 else record_uid.encode()
    if config_uid:
        rq.configurationUid = (
            bytes.fromhex(config_uid) if len(config_uid) == 32 else config_uid.encode()
        )
    schedule_data: dict = {"type": "cron", "cron": cron_expr}
    if notify_emails:
        schedule_data["notifyEmails"] = notify_emails
    rq.scheduleData = json.dumps(schedule_data)
    communicate_rest(params, rq, "pam/set_pam_rotation_schedule")


def _delete_schedule(params: "KeeperParams", record_uid: str) -> None:
    """Remove a rotation schedule (set noSchedule=True)."""
    from ...proto import pam_pb2
    from ...api import communicate_rest

    rq = pam_pb2.PAMRotationSchedule()
    rq.recordUid = bytes.fromhex(record_uid) if len(record_uid) == 32 else record_uid.encode()
    rq.noSchedule = True
    communicate_rest(params, rq, "pam/set_pam_rotation_schedule")


def _list_schedules(params: "KeeperParams", config_uid: str | None = None) -> list[dict]:
    """Return rotation schedules visible to the authenticated user."""
    from ...proto import pam_pb2
    from ...api import communicate_rest

    rq = pam_pb2.PAMGenericUidsRequest() if config_uid else pam_pb2.PAMGenericUidRequest.__new__(
        pam_pb2.PAMGenericUidRequest
    )
    rs = communicate_rest(
        params, rq,
        "pam/get_rotation_schedules",
        rs_type=pam_pb2.PAMRotationSchedulesResponse,
    )
    rows = []
    for s in rs.schedules:
        entry: dict = {
            "record_uid": s.recordUid.hex() if isinstance(s.recordUid, bytes) else s.recordUid,
            "no_schedule": s.noSchedule,
        }
        if s.scheduleData:
            try:
                entry["schedule"] = json.loads(s.scheduleData)
            except Exception:
                entry["schedule_raw"] = s.scheduleData
        rows.append(entry)
    return rows


class PamExtendedScheduleListCommand(ArgparseCommand):
    """``pam extended schedule list`` — list rotation schedules."""

    def __init__(self) -> None:
        parser = argparse.ArgumentParser(
            prog="list", description="List PAM rotation schedules"
        )
        parser.add_argument(
            "--config-uid", dest="config_uid", default=None,
            help="Filter by PAM configuration UID",
        )
        parser.add_argument(
            "--format", dest="fmt", choices=["table", "json"], default="table",
        )
        super().__init__(parser)

    def execute(self, params: "KeeperParams", **kwargs) -> None:
        rows = _list_schedules(params, config_uid=kwargs.get("config_uid"))
        if kwargs.get("fmt") == "json":
            print(json.dumps(rows, indent=2))
        else:
            if not rows:
                print("No rotation schedules found.")
                return
            for r in rows:
                sched = r.get("schedule", {})
                cron = sched.get("cron", "(none)")
                print(f"  {r['record_uid']}  cron={cron}")


class PamExtendedScheduleSetCommand(ArgparseCommand):
    """``pam extended schedule set`` — create or update a named rotation schedule."""

    def __init__(self) -> None:
        parser = argparse.ArgumentParser(
            prog="set", description="Create or update a PAM rotation schedule"
        )
        parser.add_argument("uid_ref", help="PAM record UID")
        parser.add_argument("--cron", dest="cron", required=True, help="Cron expression (5-field)")
        parser.add_argument(
            "--config-uid", dest="config_uid", default=None,
            help="PAM configuration UID (optional)",
        )
        parser.add_argument(
            "--notify", dest="notify", action="append", default=None,
            metavar="EMAIL", help="Email(s) to notify on schedule fire",
        )
        super().__init__(parser)

    def execute(self, params: "KeeperParams", **kwargs) -> None:
        uid_ref: str = kwargs["uid_ref"]
        cron: str = kwargs["cron"]
        config_uid: str | None = kwargs.get("config_uid")
        notify: list[str] | None = kwargs.get("notify")

        _set_schedule(params, uid_ref, config_uid or "", cron, notify_emails=notify)
        logger.info("Rotation schedule set: uid=%s cron=%s", uid_ref, cron)
        print(f"Rotation schedule set for {uid_ref} (cron: {cron})")


class PamExtendedScheduleDeleteCommand(ArgparseCommand):
    """``pam extended schedule delete`` — remove a rotation schedule."""

    def __init__(self) -> None:
        parser = argparse.ArgumentParser(
            prog="delete", description="Remove a PAM rotation schedule"
        )
        parser.add_argument("uid_ref", help="PAM record UID")
        super().__init__(parser)

    def execute(self, params: "KeeperParams", **kwargs) -> None:
        uid_ref: str = kwargs["uid_ref"]
        _delete_schedule(params, uid_ref)
        logger.info("Rotation schedule deleted: uid=%s", uid_ref)
        print(f"Rotation schedule removed for {uid_ref}")
