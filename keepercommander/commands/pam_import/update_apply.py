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

"""Writes the changes of an ``UpdatePlan`` - the GRAPH side (order of work, step 5).

ROUTER ONLY (owner decision 2026-11-16): every graph write goes through krouter (`configure_resource`, the
workflow API). The legacy direct DAG writes (and the ``KEEPER_DAG_LB_FALLBACK`` fallbacks) are not used: they may be
switched off at any time. So nothing here can reset a `meta` key to its default (the router deep-merges `meta` and
never removes a key); the planner reports those as warnings instead of changes.

One ``configure_resource`` request per resource carries everything that is graph data of that resource:
``meta`` (merged by the router; sent whenever the request has jit or AI settings, because the router only loads the
resource's edges for a request that carries meta/jit/connection), ``jitSettings`` and ``keeperAiSettings`` (whole
blobs, encrypted with the record key, built from the stored blob plus the changed keys), the launch credential list
and the admin (``connectUsers`` is the COMPLETE list of launch credentials and ``adminUid`` only takes effect
together with it, so both are always sent together), and ``updateServices``. One request is atomic on the server.
The workflow is a separate router API. APPLY errors are collected per resource and the run goes on (plan: error
policy); ``update`` is run again to finish.

NOT here yet: record fields (waits for the re-send test, order of work 3a) and the rotation of users.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .import_items import KIND_RESOURCE
from .update_diff import KIND_GRAPH, KIND_RECORD, OP_ADD, OP_CHANGE
from .update_plan import ItemResult, UpdatePlan
from ...keeper_dag.crypto import encrypt_aes
from ...proto import pam_pb2
from ...utils import base64_url_decode

NOT_APPLIED_ROTATION = 'rotation changes are not applied yet'
NOT_APPLIED_RECORD = 'record field changes are not applied yet'


@dataclass
class ApplyReport:
    applied: List[str] = field(default_factory=list)       # "<title>: <what>"
    errors: List[str] = field(default_factory=list)        # APPLY errors: the run went on
    not_applied: List[str] = field(default_factory=list)   # changes the writer cannot make yet

    @property
    def ok(self) -> bool:
        return not self.errors and not self.not_applied


def _comparator(change) -> str:
    return change.target.comparator if change.target is not None else ''


def meta_payload(result: ItemResult) -> Tuple[Optional[Dict[str, Any]], Optional[bool]]:
    """(meta, update_services) from the ``meta`` changes of a resource.

    ``meta`` always carries ``version`` (a versionless payload after a v1 write is rejected: "Decreasing the version
    of a resource is not allowed") and ``allowedSettings`` (the router requires the object; ``{}`` changes nothing
    because the router merges). ``no_update_services`` is sent as the request field ``updateServices``."""
    meta: Dict[str, Any] = {'version': 1, 'allowedSettings': {}}
    update_services: Optional[bool] = None
    touched = False
    for change in result.changes:
        if change.kind != KIND_GRAPH or _comparator(change) != 'meta' or change.op not in (OP_ADD, OP_CHANGE):
            continue
        key = change.path.split('.', 1)[1]
        if key == 'no_update_services':
            update_services = not bool(change.new)
            continue
        node = meta
        parts = key.split('.')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = change.new
        touched = True
    return (meta if touched else None), update_services


def credential_args(result: ItemResult) -> Tuple[Optional[List[str]], Optional[str]]:
    """(launch uid list, admin uid) for a changed admin and / or launch credential, else (None, None).

    ``connectUsers`` replaces the launch credentials of the resource: a changed launch credential is the new list,
    and when only the admin changes the CURRENT holders are sent back so nobody loses the flag."""
    admin: Optional[str] = None
    launch: Optional[str] = None
    for change in result.changes:
        if change.kind != KIND_GRAPH or change.op not in (OP_ADD, OP_CHANGE):
            continue
        if _comparator(change) == 'admin_credential':
            admin = change.new
        elif _comparator(change) == 'launch_credential':
            launch = change.new
    if admin is None and launch is None:
        return None, None
    users = [launch] if launch else list(result.acl_holders.get('launch') or [])
    return users, admin


def _encrypt(blob: Dict[str, Any], record_key: bytes) -> bytes:
    return encrypt_aes(json.dumps(blob).encode(), record_key)


def build_resource_request(params, config_uid: str, result: ItemResult) -> Optional[pam_pb2.PAMResourceConfig]:
    """The ``configure_resource`` request for the graph changes of one resource, or None when there are none."""
    meta, update_services = meta_payload(result)
    users, admin = credential_args(result)
    if meta is None and update_services is None and users is None \
            and result.new_jit_blob is None and result.new_ai_blob is None:
        return None
    rq = pam_pb2.PAMResourceConfig(recordUid=base64_url_decode(result.uid), networkUid=base64_url_decode(config_uid))
    needs_key = result.new_jit_blob is not None or result.new_ai_blob is not None
    if needs_key:
        record_key = ((params.record_cache or {}).get(result.uid) or {}).get('record_key_unencrypted')
        if not record_key:
            raise ValueError(f'the record key of {result.uid} is not available')
        if result.new_jit_blob is not None:
            rq.jitSettings = _encrypt(result.new_jit_blob, record_key)
        if result.new_ai_blob is not None:
            rq.keeperAiSettings = _encrypt(result.new_ai_blob, record_key)
        if meta is None:
            meta = {'version': 1, 'allowedSettings': {}}
    if meta is not None:
        rq.meta = json.dumps(meta).encode()
    if update_services is not None:
        rq.updateServices = update_services
    if users is not None:
        rq.connectUsers.CopyFrom(pam_pb2.UidList(uids=[base64_url_decode(u) for u in users]))
        if admin is not None:
            rq.adminUid = base64_url_decode(admin)
    return rq


def _default_send(params) -> Callable[[pam_pb2.PAMResourceConfig], Any]:
    from ..pam.router_helper import router_configure_resource

    def send(rq):
        return router_configure_resource(params, rq)
    return send


def _default_workflow(params) -> Callable[..., Any]:
    from .workflow_apply import apply_workflow

    def apply(uid, title, opts):
        return apply_workflow(params, uid, title, opts)
    return apply


def _short(err: Exception) -> str:
    return str(err).strip().splitlines()[0][:300] if str(err).strip() else err.__class__.__name__


def apply_graph(params, plan: UpdatePlan, config_uid: str, *, send: Optional[Callable] = None,
                workflow: Optional[Callable] = None) -> ApplyReport:
    """Write the graph changes of every resource of *plan*; collect errors and go on.

    *send* and *workflow* are the router calls (replaceable in tests)."""
    send = send or _default_send(params)
    workflow = workflow or _default_workflow(params)
    report = ApplyReport()
    for result in plan.results:
        if not result.changes:
            continue
        label = result.title or result.uid
        graph_changes = [c for c in result.changes if c.kind == KIND_GRAPH]
        if result.item.kind != KIND_RESOURCE:
            if any(_comparator(c) == 'rotation' for c in graph_changes):
                report.not_applied.append(f'{label}: {NOT_APPLIED_ROTATION}')
        else:
            try:
                rq = build_resource_request(params, config_uid, result)
            except ValueError as err:
                report.errors.append(f'{label}: {_short(err)}')
                rq = None
            if rq is not None:
                try:
                    send(rq)
                    report.applied.append(f'{label}: graph settings')
                except Exception as err:   # pylint: disable=broad-except
                    logging.debug('configure_resource failed for %s: %s', result.uid, err, exc_info=True)
                    report.errors.append(f'{label}: graph settings were not written: {_short(err)}')
            if result.workflow_options is not None and any(_comparator(c) == 'workflow' for c in graph_changes):
                try:
                    workflow(result.uid, result.title, result.workflow_options)
                    report.applied.append(f'{label}: workflow')
                except Exception as err:   # pylint: disable=broad-except
                    logging.debug('workflow failed for %s: %s', result.uid, err, exc_info=True)
                    report.errors.append(f'{label}: the workflow was not written: {_short(err)}')
        if any(c.kind == KIND_RECORD for c in result.changes):
            report.not_applied.append(f'{label}: {NOT_APPLIED_RECORD}')
    return report
