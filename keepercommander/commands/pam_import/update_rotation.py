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

Written here: the rotation of a ``general`` user (the credential belongs to a machine), and of an ``iam_user`` /
``scripts_only`` / ``saas`` user. The rotation cache has no NOOP flag, so the profile of the vault rotation is read
from the user -> configuration ACL edge of the PAM graph (``update_compare.vault_rotation_profile``); a change is
written only when it is the JSON's profile, and then the request keeps it: an IAM rotation is sent with an empty
resource, a ``scripts_only`` one with ``noop`` and an empty resource (the way ``pam rotation edit --schedule-only``
keeps them), a ``saas`` one the same plus ``saasConfiguration`` = the SaaS record the vault rotation has now (the
``saas_record_uid_list`` of the same edge; the SaaS record itself is never changed here). A JSON profile that is not
the vault's is a plan warning and nothing is written; so is a rotation that has a SaaS record besides its IAM / machine
profile (the Web Vault's unsupported "IAM User + SaaS Account" / "General + SaaS Account", which it refuses to save
too). A ``saas`` rotation that does not name exactly one SaaS record is reported as NOT written yet, and that is by
design (see ``NOT_APPLIED_SAAS_RECORD``). If the PAM graph could not be read the profile is unknown and nothing is
written (``NOT_APPLIED_GRAPH``).

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

A top-level ``iam_user`` / ``scripts_only`` / ``saas`` user without a rotation is added the same way, with the
arguments of the import (``--rotation-profile``; ``saas`` also the SaaS configuration record). No machine or admin is
involved. A nested user of these profiles is NOT WRITTEN YET (the import skips it too).
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
NOT_APPLIED_GRAPH = ('the {profile} rotation is not written: the profile of the vault rotation could not be read from '
                     'the PAM graph, and a request built without it could change the profile (use `pam rotation edit`)')
# A nested iam_user / scripts_only / saas user is refused for the reasons the import gives (batch_step2): an IAM user
# hangs directly off the PAM configuration and has no machine, scripts_only never runs a machine's scripts, and the
# Gateway looks for the SaaS list on the machine ancestor when there is one.
NOT_APPLIED_NESTED = ('a rotation the user does not have yet is not written yet: a {profile} user must be a top-level '
                      'user, like in the import - move the user from the machine\'s "users" to the top-level '
                      '"pam_data.users" of the JSON, or use `pam rotation edit`')
# EXACTLY ONE SaaS record is by design, not a gap. Every supported writer has one: the router field
# RouterRecordRotationRequest.saasConfiguration is a single `bytes`; the Web Vault builds it from one saasConfigUid
# (vault/js/lib/record-rotation.ts), its profile editor has a single SaaS Configuration dropdown
# (PasswordRotationSettings.tsx) and it reads only saas_record_uid_list[0] (lib/pam/dag-pam-link.ts). A list of another
# length cannot be sent back faithfully (a request names one record), so it is reported and never rewritten. Zero cannot
# happen: a NOOP rotation without a SaaS record is classified scripts_only (update_compare.vault_rotation_profile).
NOT_APPLIED_SAAS_RECORD = ('the saas rotation profile is not written yet: the vault rotation names {count} SaaS '
                           'configuration records, not one (use `pam rotation edit`)')
CHANGE_PROFILES = ('iam_user', 'scripts_only', 'saas')   # profiles whose CHANGES are written (the vault profile is confirmed)
ADD_PROFILES = ('iam_user', 'scripts_only', 'saas')  # profiles that are added through the import's arguments


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
    rotation = result.item.obj.rotation_settings
    profile = str(getattr(rotation, 'rotation', '') or '').lower()
    if profile in CHANGE_PROFILES:      # no machine: an IAM rotation keeps its profile with an empty resource, NOOP with noop
        rq.resourceUid = b''
        rq.noop = profile != 'iam_user'
        if profile == 'saas':           # the router keeps the SaaS record only if the request names it again
            if len(result.vault_saas_uids) != 1:
                raise ValueError(NOT_APPLIED_SAAS_RECORD.format(count=len(result.vault_saas_uids)))
            rq.saasConfiguration = _decode(result.vault_saas_uids[0])
    rq.schedule = entry.get('schedule') or ''
    rq.pwdComplexity = _decode(entry.get('pwd_complexity'))
    rq.disabled = bool(entry.get('disabled'))
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


def profile_add_arguments(params, result: ItemResult, profile: str, config_uid: str) -> Dict[str, Any]:
    """The ``pam rotation edit`` arguments the import uses for a top-level ``iam_user`` / ``scripts_only`` / ``saas``
    user (``run_step2_global_profile_rotations`` / ``run_step2_global_saas``)."""
    from .batch_step2 import _rotation_common_args, resolve_saas_config_uid   # pylint: disable=import-outside-toplevel,protected-access
    obj = result.item.obj
    args: Dict[str, Any] = {'force': True, 'config': config_uid, 'record_name': result.uid, 'rotation_profile': profile}
    if profile == 'saas':
        saas_uid = resolve_saas_config_uid(params, getattr(obj.rotation_settings, 'saas_config', ''), [])
        if not saas_uid:
            raise ValueError('the saas_config of the JSON is not a single SaaS configuration record in the vault')
        args.update({'saas_config_uid': saas_uid, 'saas_in_request': True})
    args.update(_rotation_common_args(obj))
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
            info = added.data if isinstance(added.data, RotationAdd) else RotationAdd('')
            if profile in ADD_PROFILES:
                if not info.global_user:
                    report.not_applied.append(f'{label}: ' + NOT_APPLIED_NESTED.format(profile=profile))
                    continue
            elif profile != 'general':
                report.not_applied.append(f'{label}: ' + NOT_APPLIED_PROFILE.format(profile=profile or 'unknown'))
                continue
            elif not info.machine_uid:
                report.not_applied.append(f'{label}: {NOT_APPLIED_NO_MACHINE}')
                continue
            admin = machine_admin(plan, info) if profile == 'general' else ''
            if profile == 'general' and not admin:
                report.not_applied.append(f'{label}: {NOT_APPLIED_NO_ADMIN}')
                continue
            try:
                add_rotation = add_rotation or _default_add(params)
                args = (add_arguments(result, info, admin, plan.config_uid) if profile == 'general'
                        else profile_add_arguments(params, result, profile, plan.config_uid))
                add_rotation(args, label)
                report.applied.append(f'{label}: rotation (added)')
            except Exception as err:        # pylint: disable=broad-except
                logging.debug('rotation add failed for %s: %s', result.uid, err, exc_info=True)
                report.errors.append(f'{label}: rotation was not written: {_short(err)}')
            continue
        entry = (params.record_rotation_cache or {}).get(result.uid)
        if profile != 'general' and not (profile in CHANGE_PROFILES and result.vault_rotation_profile == profile):
            # The cache has no NOOP flag and a rebuilt request could change the profile, so the graph must confirm it.
            # The plan reports a profile that differs (a warning, no change), so what reaches this point is a profile
            # without a writer, or a graph that could not be read (profile None).
            if profile in CHANGE_PROFILES and result.vault_rotation_profile is None:
                report.not_applied.append(f'{label}: ' + NOT_APPLIED_GRAPH.format(profile=profile))
            else:
                report.not_applied.append(f'{label}: ' + NOT_APPLIED_PROFILE.format(profile=profile or 'unknown'))
            continue
        if profile == 'saas' and len(result.vault_saas_uids) != 1:
            report.not_applied.append(f'{label}: ' + NOT_APPLIED_SAAS_RECORD.format(count=len(result.vault_saas_uids)))
            continue
        if not entry:
            report.errors.append(f'{label}: rotation was not written: the rotation is not in the vault cache; '
                                 'run update again')
            continue
        if profile == 'general' and (not entry.get('resource_uid')
                                     or entry.get('resource_uid') == entry.get('configuration_uid')):
            report.not_applied.append(f'{label}: the vault rotation is not a general one (no machine); '
                                      'update does not change the rotation type (use `pam rotation edit`)')
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
