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

"""Writes the ROTATION changes of an existing user of an ``UpdatePlan`` (order of work step 5, rotation side).

One ``set_record_rotation`` request (the router API ``pam rotation edit`` uses) per user whose rotation differs. The
request is built from the rotation the vault has now (``params.record_rotation_cache``): every property that did not
change is sent back as it is stored (the schedule as the stored TEXT, never re-serialised; the encrypted complexity
blob), and only ``enabled`` (``disabled``), ``schedule`` and ``pwdComplexity`` take the JSON value. Nothing of the
service accounts is sent (absent = no change); the rotation type, configuration and resource stay as they are.

Written here: the rotation of a ``general`` user (the credential belongs to a machine). NOT written yet, and reported
as such: a user that has NO rotation in the vault yet (it needs the admin and the resource, like the import), and the
``iam_user`` / ``scripts_only`` / ``saas`` profiles (the rotation cache does not say whether a rotation is a NOOP, and
a wrong guess would change the profile; use ``pam rotation edit``).

``pam rotation edit`` also sets the "rotation allowed" flag of the machine when a user is enabled or disabled, through
a direct graph write. update does not: that flag is ``pam_settings.options.rotation`` of the machine and is written
with the machine's graph settings.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from . import update_compare as uc
from .update_apply import ApplyReport
from .update_diff import KIND_GRAPH, OP_ADD, Change
from .update_plan import ItemResult, UpdatePlan
from ... import crypto, utils
from ...proto import router_pb2

NOT_APPLIED_ADD = ('a rotation the user does not have yet is not written yet '
                   '(use `pam project extend` or `pam rotation edit`)')
NOT_APPLIED_PROFILE = 'the {profile} rotation profile is not written yet (use `pam rotation edit`)'


def rotation_changes(result: ItemResult) -> List[Change]:
    return [c for c in result.changes
            if c.kind == KIND_GRAPH and c.target is not None and c.target.comparator == 'rotation']


def schedule_json(rotation) -> Optional[str]:
    """The ``schedule`` text of the request for the JSON's schedule: '' = on-demand, else the one-item CRON list."""
    schedule = getattr(rotation, 'schedule', None)
    if schedule is None or not schedule.type:
        return None
    if schedule.type == 'on-demand':
        return ''
    if not schedule.cron:
        return None
    tz = (schedule.tz or '').strip()
    return json.dumps([{'type': 'CRON', 'cron': schedule.cron, 'tz': 'Etc/UTC' if uc._tz(tz) == 'UTC' else tz}])


def complexity_rules(text: str, stored: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The complexity dict for "32,5,5,5,5": the five numbers replace the stored ones, the stored ``specialChars`` stay."""
    from ..discoveryrotation import PAM_DEFAULT_SPECIAL_CHAR       # lazy: circular import at module level
    nums = uc._complexity_wanted(text)
    if nums is None:
        raise ValueError(f'unreadable password complexity "{text}"')
    rules = dict(stored) if isinstance(stored, dict) else {}
    rules.update(zip(('length', 'caps', 'lowercase', 'digits', 'special'), nums))
    rules.setdefault('specialChars', PAM_DEFAULT_SPECIAL_CHAR)
    return rules


def _decode(value: Any) -> bytes:
    return utils.base64_url_decode(value) if value else b''


def build_request(result: ItemResult, entry: Dict[str, Any], record_key: Optional[bytes]
                  ) -> router_pb2.RouterRecordRotationRequest:
    """The ``set_record_rotation`` request: the stored rotation *entry* with the changed properties replaced."""
    rq = router_pb2.RouterRecordRotationRequest()
    rq.revision = entry.get('revision') or 0
    rq.recordUid = _decode(result.uid)
    rq.configurationUid = _decode(entry.get('configuration_uid'))
    rq.resourceUid = _decode(entry.get('resource_uid'))
    rq.noop = False
    rq.schedule = entry.get('schedule') or ''
    rq.pwdComplexity = _decode(entry.get('pwd_complexity'))
    rq.disabled = bool(entry.get('disabled'))
    rotation = result.item.obj.rotation_settings
    for change in rotation_changes(result):
        if change.path == 'rotation.enabled':
            rq.disabled = change.new == 'off'
        elif change.path == 'rotation.schedule':
            text = schedule_json(rotation)
            if text is None:
                raise ValueError('the schedule of the JSON cannot be written')
            rq.schedule = text
        elif change.path == 'rotation.password_complexity':
            if not record_key:
                raise ValueError('the record key is not available')
            stored = None
            if rq.pwdComplexity:
                try:
                    stored = json.loads(crypto.decrypt_aes_v2(bytes(rq.pwdComplexity), record_key).decode())
                except Exception:       # pylint: disable=broad-except
                    stored = None
            from ..pam.router_helper import encrypt_pwd_complexity
            rq.pwdComplexity = encrypt_pwd_complexity(complexity_rules(str(change.new), stored), record_key)
    return rq


def _default_send(params) -> Callable[[router_pb2.RouterRecordRotationRequest], Any]:
    from ..pam.router_helper import router_set_record_rotation_information
    from ..tunnel.port_forward.tunnel_helpers import get_keeper_tokens

    def send(rq):
        session_token, encrypted_key, transmission_key = get_keeper_tokens(params)
        return router_set_record_rotation_information(params, rq, transmission_key, encrypted_key, session_token)
    return send


def _default_record_key(params) -> Callable[[str], Optional[bytes]]:
    def record_key(uid):
        key = (params.record_cache.get(uid) or {}).get('record_key_unencrypted')
        if key:
            return key
        from ...nested_share_folder.common import get_record_key
        return get_record_key(params, uid, raise_on_missing=False)
    return record_key


def _short(err: Exception) -> str:
    return str(err).strip().splitlines()[0][:300] if str(err).strip() else err.__class__.__name__


def apply_rotations(params, plan: UpdatePlan, *, send: Optional[Callable] = None,
                    record_key: Optional[Callable[[str], Optional[bytes]]] = None) -> ApplyReport:
    """Write the rotation changes of the existing users of *plan*; collect errors and go on."""
    report = ApplyReport()
    send_request = send
    for result in plan.results:
        changes = rotation_changes(result)
        if not changes:
            continue
        label = result.title or result.uid
        rotation = getattr(result.item.obj, 'rotation_settings', None)
        profile = str(getattr(rotation, 'rotation', '') or '').lower()
        if any(c.op == OP_ADD and c.path == 'rotation' for c in changes):
            report.not_applied.append(f'{label}: {NOT_APPLIED_ADD}')
            continue
        entry = (params.record_rotation_cache or {}).get(result.uid)
        if profile != 'general':
            report.not_applied.append(f'{label}: ' + NOT_APPLIED_PROFILE.format(profile=profile or 'unknown'))
            continue
        if not entry:
            report.errors.append(f'{label}: rotation was not written: the rotation is not in the vault cache; '
                                 'run update again')
            continue
        if not entry.get('resource_uid') or entry.get('resource_uid') == entry.get('configuration_uid'):
            report.not_applied.append(f'{label}: the vault rotation is not a general one (no machine); '
                                      + NOT_APPLIED_PROFILE.format(profile='iam_user / scripts_only / saas'))
            continue
        try:
            key = (record_key or _default_record_key(params))(result.uid)
            rq = build_request(result, entry, key)
            send_request = send_request or _default_send(params)
            send_request(rq)
            report.applied.append(f'{label}: rotation ({len(changes)})')
        except Exception as err:        # pylint: disable=broad-except
            logging.debug('set_record_rotation failed for %s: %s', result.uid, err, exc_info=True)
            report.errors.append(f'{label}: rotation was not written: {_short(err)}')
    if report.applied:
        params.sync_data = True
    return report
