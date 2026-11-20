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
as such: the ``iam_user`` / ``scripts_only`` / ``saas`` profiles (the rotation cache does not say whether a rotation is
a NOOP, and a wrong guess would change the profile; use ``pam rotation edit``).

``pam rotation edit`` also sets the "rotation allowed" flag of the machine when a user is enabled or disabled, through
a direct graph write. update does not for a user that has a rotation: that flag is ``pam_settings.options.rotation``
of the machine and is written with the machine's graph settings.

A user that has NO rotation yet (an ADD of the whole rotation) is written the way the import writes it: through the
``pam rotation edit`` command (``batch_step2._apply_rotation`` arguments), because the user -> machine link
(``belongs_to``) cannot be written through ``configure_resource``. It needs the machine and an administrative
credential on the machine (already in the vault, or set by the graph settings of the same run); without them the
rotation is reported as NOT WRITTEN YET. Like the import, the command sets the machine's "rotation allowed" flag from
``enabled`` of that user. The admin is passed to the command, which uses it only when
the machine has none.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from . import update_compare as uc
from .update_apply import ApplyReport, credential_args
from .update_diff import KIND_GRAPH, OP_ADD, Change
from .update_plan import ItemResult, RotationAdd, UpdatePlan
from ... import crypto, utils
from ...proto import router_pb2

NOT_APPLIED_NO_MACHINE = ('a rotation the user does not have yet is not written yet: the machine of the user '
                          'is not known (use `pam rotation edit`)')
NOT_APPLIED_NO_ADMIN = ('a rotation the user does not have yet is not written yet: the machine has no '
                        'administrative credential (set administrative_credentials in the JSON of the machine, '
                        'or use `pam rotation edit`)')
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


def machine_admin(plan: UpdatePlan, add: RotationAdd) -> str:
    """The admin the machine has after the graph writes of this run: the one the plan sets, else the one it has now."""
    for result in plan.results:
        if result.uid == add.machine_uid:
            _, admin = credential_args(result)
            if admin:
                return admin
    return add.admin_uid


def add_arguments(result: ItemResult, add: RotationAdd, admin: str, config_uid: str) -> Dict[str, Any]:
    """The ``pam rotation edit`` arguments of the import's ``_apply_rotation`` for the user of *result*."""
    from .batch_step2 import _rotation_common_args       # pylint: disable=import-outside-toplevel,protected-access
    args: Dict[str, Any] = {'force': True, 'config': config_uid, 'record_name': result.uid, 'admin': admin,
                            'resource': add.machine_uid}
    args.update(_rotation_common_args(result.item.obj))
    return args


def _default_add(params) -> Callable[[Dict[str, Any], str], Any]:
    from ..discoveryrotation import PAMCreateRecordRotationCommand      # lazy: circular import at module level
    from .rotation_throttle import RotationThrottle
    from .throttle_retry import call_with_throttle_retry, rest_fail_on_throttle
    command = PAMCreateRecordRotationCommand()
    throttle = RotationThrottle()

    def add(args, label):
        throttle.before_call()
        return call_with_throttle_retry(lambda: command.execute(params, silent=True, **args), max_retries=5,
                                        label=f'rotation {label}', fail_on_throttle=rest_fail_on_throttle(params))
    return add


def apply_rotations(params, plan: UpdatePlan, *, send: Optional[Callable] = None,
                    record_key: Optional[Callable[[str], Optional[bytes]]] = None,
                    add: Optional[Callable[[Dict[str, Any], str], Any]] = None) -> ApplyReport:
    """Write the rotation changes of the users of *plan*; collect errors and go on.

    *send* (``set_record_rotation``, a user that has a rotation) and *add* (``pam rotation edit``, a user that has
    none) are the calls to the server (replaceable in tests)."""
    report = ApplyReport()
    send_request = send
    add_rotation = add
    for result in plan.results:
        changes = rotation_changes(result)
        if not changes:
            continue
        label = result.title or result.uid
        rotation = getattr(result.item.obj, 'rotation_settings', None)
        profile = str(getattr(rotation, 'rotation', '') or '').lower()
        added = next((c for c in changes if c.op == OP_ADD and c.path == 'rotation'), None)
        if added is not None:
            if profile != 'general':
                report.not_applied.append(f'{label}: ' + NOT_APPLIED_PROFILE.format(profile=profile or 'unknown'))
                continue
            info = added.data if isinstance(added.data, RotationAdd) else RotationAdd('')
            if not info.machine_uid:
                report.not_applied.append(f'{label}: {NOT_APPLIED_NO_MACHINE}')
                continue
            admin = machine_admin(plan, info)
            if not admin:
                report.not_applied.append(f'{label}: {NOT_APPLIED_NO_ADMIN}')
                continue
            try:
                add_rotation = add_rotation or _default_add(params)
                add_rotation(add_arguments(result, info, admin, plan.config_uid), label)
                report.applied.append(f'{label}: rotation (added)')
            except Exception as err:        # pylint: disable=broad-except
                logging.debug('rotation add failed for %s: %s', result.uid, err, exc_info=True)
                report.errors.append(f'{label}: rotation was not written: {_short(err)}')
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
