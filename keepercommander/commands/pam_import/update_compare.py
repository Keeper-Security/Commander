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

"""The comparators of `pam project update` for the settings that are not plain dicts:

* KeeperAI settings (``ai_settings`` edge)       - ``plan_ai``
* rotation settings of a pamUser                 - ``diff_rotation``
* workflow of a resource (router API)            - ``diff_workflow``
* credential references (admin / launch / ...)   - ``diff_credential_refs``

Like ``update_diff`` these are pure functions on plain data (designs and owner decisions: plan, section "Comparator
designs for KeeperAI, rotation and workflow", 2026-11-16). Each one compares a NORMALISED projection of the two
sides, so a re-run after a successful apply gives no change, and only looks at what the JSON wrote. Each returns
``(changes, warnings)``. Removals that belong to the deferred graph-side rule of ``overwrite`` are produced only
with ``graph_overwrite=True``.
"""

from __future__ import annotations

import copy
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .base import DagAiSettingsObject, PamRotationSettingsObject, PamWorkflowOptions
from .update_diff import (
    KIND_GRAPH, KIND_RECORD, MODE_OVERWRITE, OP_ADD, OP_CHANGE, OP_REMOVE, Change, is_blank, same,
)
from . import update_schema as us

RISK_LEVELS = ('critical', 'high', 'medium', 'low')


def _graph(op: str, path: str, old: Any = None, new: Any = None, note: str = '', comparator: str = '') -> Change:
    return Change(KIND_GRAPH, op, path, old, new, note=note,
                  target=us.Target(us.KIND_GRAPH, comparator=comparator or path.split('.')[0], key=path))


def _escalation_text(value: Tuple[bool, int]) -> str:
    """``(escalation on/off, after ms)`` of a workflow approver as the report shows it."""
    escalation, after_ms = value
    if not escalation:
        return 'no escalation'
    seconds = int(after_ms or 0) // 1000
    for unit, size in (('d', 86400), ('h', 3600), ('m', 60)):
        if seconds >= size and seconds % size == 0:
            return f'escalates after {seconds // size}{unit}'
    return f'escalates after {seconds}s' if seconds else 'escalates at once'


# --------------------------------------------------------------------------------------------------------------
# KeeperAI settings
# --------------------------------------------------------------------------------------------------------------

def ai_projection(blob: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """{level: {'terminate': bool | None, 'allow': [tags], 'deny': [tags]}} of a stored `ai_settings` blob.

    The audit log of every tag and the blob version are deliberately not part of it.
    """
    out: Dict[str, Dict[str, Any]] = {}
    levels = (blob or {}).get('riskLevels') if isinstance(blob, dict) else None
    for level, data in (levels or {}).items():
        if not isinstance(data, dict):
            continue
        tags = data.get('tags') if isinstance(data.get('tags'), dict) else {}
        out[level] = {
            'terminate': data.get('aiSessionTerminate'),
            'allow': [e.get('tag') for e in tags.get('allow') or [] if isinstance(e, dict) and e.get('tag')],
            'deny': [e.get('tag') for e in tags.get('deny') or [] if isinstance(e, dict) and e.get('tag')],
        }
    return out


def _tag_entry(tag: str, action: str, user_id: str, now_ms: int) -> Dict[str, Any]:
    return {'tag': tag, 'auditLog': [{'date': now_ms, 'userId': user_id, 'action': action}]}


def plan_ai(raw_ai: Any, current_blob: Optional[Dict[str, Any]], *, mode: str = 'merge',
            graph_overwrite: bool = False, user_id: str = '', now_ms: Optional[int] = None
            ) -> Tuple[Optional[Dict[str, Any]], List[Change], List[str]]:
    """Compare the JSON ``ai_settings`` with the stored blob. Returns (new blob, changes, warnings).

    The new blob is built FROM the stored one: tags that stay keep their entry and audit log, a new tag gets a
    fresh audit entry, a tag the JSON puts in the other list is moved (JSON wins, also in merge), and the stored
    ``version`` is kept. ``new blob`` is None when nothing changes. Tags the JSON does not list are removed only in
    overwrite with ``graph_overwrite``. Only the levels / lists the JSON wrote are looked at.
    """
    changes: List[Change] = []
    warnings: List[str] = []
    if not isinstance(raw_ai, dict):
        return None, changes, warnings
    loaded = DagAiSettingsObject.load(raw_ai)
    if loaded is None:
        return None, changes, ['ai_settings has no usable risk level (ignored)']
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    blob = copy.deepcopy(current_blob) if isinstance(current_blob, dict) else {}
    levels = blob.setdefault('riskLevels', {})
    blob.setdefault('version', loaded.version)
    remove_extra = mode == MODE_OVERWRITE and graph_overwrite

    raw_levels = raw_ai.get('risk_levels') or {}
    for level in RISK_LEVELS:
        wanted = loaded.risk_levels.get(level)
        if wanted is None:
            continue
        raw_level = raw_levels.get(level) or {}
        activities = raw_level.get('activities') if isinstance(raw_level.get('activities'), dict) else {}
        cur = levels.setdefault(level, {})
        tags = cur.setdefault('tags', {})
        lists = {'allow': tags.setdefault('allow', []), 'deny': tags.setdefault('deny', [])}
        base = f'ai_settings.riskLevels.{level}'

        if 'ai_session_terminate' in raw_level and wanted['ai_session_terminate'] is not None:
            old = cur.get('aiSessionTerminate')
            new = wanted['ai_session_terminate']
            if old is None:
                changes.append(_graph(OP_ADD, f'{base}.aiSessionTerminate', None, new, comparator='ai_settings'))
                cur['aiSessionTerminate'] = new
            elif old != new:
                changes.append(_graph(OP_CHANGE, f'{base}.aiSessionTerminate', old, new, comparator='ai_settings'))
                cur['aiSessionTerminate'] = new

        wanted_lists = {'allow': wanted['allow'], 'deny': wanted['deny']}
        both = set(wanted_lists['allow']) & set(wanted_lists['deny'])
        for tag in sorted(both):
            warnings.append(f'ai_settings {level}: tag "{tag}" is listed in both allow and deny (skipped)')
        for name, other, action in (('allow', 'deny', 'added_to_allow'), ('deny', 'allow', 'added_to_deny')):
            if name not in activities:
                continue
            have = {e.get('tag') for e in lists[name] if isinstance(e, dict)}
            in_other = {e.get('tag') for e in lists[other] if isinstance(e, dict)}
            for tag in wanted_lists[name]:
                if tag in both or tag in have:
                    continue
                if tag in in_other:
                    lists[other][:] = [e for e in lists[other] if e.get('tag') != tag]
                    changes.append(_graph(OP_CHANGE, f'{base}.{name}', f'{tag} (in {other})', f'{tag} (in {name})',
                                          note='moved', comparator='ai_settings'))
                else:
                    changes.append(_graph(OP_ADD, f'{base}.{name}', None, tag, comparator='ai_settings'))
                lists[name].append(_tag_entry(tag, action, user_id, now_ms))
            if remove_extra:
                keep = set(wanted_lists[name]) | set(wanted_lists[other])
                for entry in list(lists[name]):
                    if entry.get('tag') not in keep:
                        lists[name].remove(entry)
                        changes.append(_graph(OP_REMOVE, f'{base}.{name}', entry.get('tag'), None,
                                              comparator='ai_settings'))
    return (blob if changes else None), changes, warnings


# --------------------------------------------------------------------------------------------------------------
# rotation
# --------------------------------------------------------------------------------------------------------------

_UTC = {'', 'utc', 'etc/utc'}
_DAY3 = {'MONDAY': 'MON', 'TUESDAY': 'TUE', 'WEDNESDAY': 'WED', 'THURSDAY': 'THU', 'FRIDAY': 'FRI',
         'SATURDAY': 'SAT', 'SUNDAY': 'SUN'}


def _tz(value: Any) -> str:
    text = str(value or '').strip()
    return 'UTC' if text.lower() in _UTC else text


def _clock(value: Any) -> Optional[Tuple[int, int, int]]:
    parts = str(value or '').strip().split(':')
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return None
    if len(nums) not in (2, 3):
        return None
    return nums[0], nums[1], nums[2] if len(nums) == 3 else 0


def canonical_cron(cron: str) -> str:
    """6-field cron with the day-of-month / day-of-week `?` read as `*`, whitespace collapsed."""
    parts = str(cron or '').split()
    if len(parts) == 6:
        parts[3] = '*' if parts[3] == '?' else parts[3]
        parts[5] = '*' if parts[5] == '?' else parts[5]
    return ' '.join(parts)


def canonical_schedule(schedule: Any) -> Tuple[str, ...]:
    """('none',) for on-demand, ('cron', cron, tz) when the schedule has an exact cron form, ('other', text) else.

    Understands a stored list as the server keeps it: ``CRON``, and the simple ``DAILY`` / ``WEEKLY`` /
    ``MONTHLY_BY_DAY`` the Web Vault writes (interval 1, no end date, no occurrence limit).
    """
    if schedule in (None, '', []):
        return ('none',)
    if not isinstance(schedule, list) or len(schedule) != 1 or not isinstance(schedule[0], dict):
        return ('other', 'several or unreadable schedules')
    item = schedule[0]
    kind = str(item.get('type') or '').upper()
    tz = _tz(item.get('tz'))
    if kind == 'CRON':
        if item.get('endDate') or item.get('occurrences'):
            return ('other', 'CRON with an end date or occurrence limit')
        return ('cron', canonical_cron(item.get('cron')), tz)
    simple = (item.get('intervalCount') in (None, 1) and not item.get('endDate') and not item.get('occurrences'))
    clock = _clock(item.get('time') or item.get('utcTime'))
    if kind in ('DAILY', 'WEEKLY', 'MONTHLY_BY_DAY') and simple and clock:
        hour, minute, second = clock
        if kind == 'DAILY':
            return ('cron', f'{second} {minute} {hour} * * *', tz)
        if kind == 'WEEKLY' and str(item.get('weekday') or '').upper() in _DAY3:
            return ('cron', f'{second} {minute} {hour} * * {_DAY3[str(item["weekday"]).upper()]}', tz)
        if kind == 'MONTHLY_BY_DAY' and str(item.get('monthDay') or '').isdigit():
            return ('cron', f'{second} {minute} {hour} {int(item["monthDay"])} * *', tz)
    return ('other', f'{kind or "unknown"} schedule')


def schedule_text(canon: Tuple[str, ...]) -> str:
    if canon[0] == 'none':
        return 'on-demand'
    if canon[0] == 'cron':
        return f'cron "{canon[1]}" ({canon[2]})'
    return f'Web Vault schedule: {canon[1]}'


def _complexity_tuple(stored: Any) -> Optional[Tuple[int, int, int, int, int]]:
    if not isinstance(stored, dict):
        return None
    try:
        return (int(stored.get('length', 0)), int(stored.get('caps', 0)), int(stored.get('lowercase', 0)),
                int(stored.get('digits', 0)), int(stored.get('special', 0)))
    except (TypeError, ValueError):
        return None


def _complexity_wanted(text: str) -> Optional[Tuple[int, ...]]:
    try:
        nums = tuple(int(x) for x in str(text).split(','))
    except ValueError:
        return None
    return nums if len(nums) == 5 else None


def vault_rotation_profile(acl_edges: Iterable[Any], user_uid: str, config_uid: str, machine_uid: str = '') -> str:
    """The profile of a rotation, from the ACL edges of the PAM graph (the rotation cache has no NOOP flag):

    * ``user -> PAM configuration``: ``iam_user`` (``is_iam_user``), ``saas`` (NOOP + a SaaS record list),
      ``scripts_only`` (NOOP);
    * ``iam_saas``: ``is_iam_user`` AND a SaaS record list on that edge, and ``general_saas``: a SaaS record list on the
      ``user -> machine`` edge. These are the "IAM User + SaaS Account" / "General + SaaS Account" states the Web Vault
      calls UNSUPPORTED (``UnsupportedRotationProfile`` in ``vault/js/lib/types/record-rotation.ts``; it refuses to save
      them, ``PasswordRotationSettings.tsx``: "Please select a supported rotation profile"). They are never rewritten
      here: a request without ``saasConfiguration`` could drop the SaaS record;
    * '' = the edges say nothing (a ``general`` rotation, or no rotation)."""
    acl_edges = list(acl_edges)             # read twice below
    for edge in acl_edges:
        if (_edge_attr(edge, 'tail') != user_uid or _edge_attr(edge, 'head') != config_uid
                or str(_edge_attr(edge, 'edge_type') or 'acl') != 'acl'):
            continue
        contents = _edge_attr(edge, 'contents') or {}
        settings = contents.get('rotation_settings') or {}
        if contents.get('is_iam_user'):
            return 'iam_saas' if settings.get('saas_record_uid_list') else 'iam_user'
        if settings.get('noop'):
            return 'saas' if settings.get('saas_record_uid_list') else 'scripts_only'
    if machine_uid:
        for edge in acl_edges:
            if (_edge_attr(edge, 'tail') == user_uid and _edge_attr(edge, 'head') == machine_uid
                    and str(_edge_attr(edge, 'edge_type') or 'acl') == 'acl'
                    and ((_edge_attr(edge, 'contents') or {}).get('rotation_settings') or {}).get('saas_record_uid_list')):
                return 'general_saas'
    return ''


def vault_saas_uids(acl_edges: Iterable[Any], user_uid: str, config_uid: str) -> List[str]:
    """The SaaS configuration record(s) of a ``saas`` rotation: ``rotation_settings.saas_record_uid_list`` of the same
    ``user -> PAM configuration`` ACL edge (the router stores the ``saasConfiguration`` of the request there).

    A rotation has exactly ONE SaaS record in every supported client, so the writer refuses a list of any other length
    (see ``update_rotation``): the Web Vault sends one ``saasConfiguration`` from one ``saasConfigUid``
    (``vault/js/lib/record-rotation.ts``), its profile editor has a single SaaS Configuration dropdown
    (``PasswordRotationSettings.tsx``), and it reads only ``saas_record_uid_list[0]`` (``lib/pam/dag-pam-link.ts``)."""
    for edge in acl_edges:
        if (_edge_attr(edge, 'tail') != user_uid or _edge_attr(edge, 'head') != config_uid
                or str(_edge_attr(edge, 'edge_type') or 'acl') != 'acl'):
            continue
        settings = (_edge_attr(edge, 'contents') or {}).get('rotation_settings') or {}
        if settings.get('noop') and settings.get('saas_record_uid_list'):
            return [str(uid) for uid in settings['saas_record_uid_list']]
    return []


def diff_rotation(rotation: PamRotationSettingsObject, explicit: Iterable[str], current: Optional[Dict[str, Any]], *,
                  expected_resource_uid: str = '', expected_config_uid: str = '', title: str = '',
                  vault_profile: Optional[str] = None, json_saas_uid: str = '',
                  vault_saas: Optional[List[str]] = None) -> Tuple[List[Change], List[str]]:
    """Rotation of one pamUser. *explicit* = the keys written under ``rotation_settings``; *current* is
    ``record_state.rotation_info`` (None = the user has no rotation).

    The rotation TYPE (who owns the credential: ``general`` -> the machine, the others -> the configuration) and the
    configuration are identity: a mismatch is a warning and the user's rotation is left as it is. *vault_profile* is
    ``vault_rotation_profile`` (None = not known): when known, a non-general JSON profile must be the vault's.
    *json_saas_uid* / *vault_saas*: the SaaS record the JSON names (resolved) and the one(s) the vault rotation uses.
    Which SaaS record a rotation uses is identity too: update never moves it, so a different one is a warning.
    """
    explicit = set(explicit)
    who = f'"{title}": ' if title else ''
    if current is None:
        summary = {'rotation': rotation.rotation, 'enabled': rotation.enabled or 'default',
                   'schedule': rotation.schedule.type if rotation.schedule and rotation.schedule.type else '',
                   'password_complexity': rotation.password_complexity}
        return [_graph(OP_ADD, 'rotation', None, {k: v for k, v in summary.items() if v}, comparator='rotation')], []

    # A general rotation belongs to its machine. The other profiles have no machine: the vault stores an EMPTY resource
    # for a NOOP (scripts_only) rotation (seen on QA 2026-11-19) and the configuration for an IAM one, so both mean "no
    # machine"; only a machine UID there is a real mismatch.
    mismatch = []
    stored_resource = current.get('resource_uid') or ''
    if rotation.rotation == 'general':
        if expected_resource_uid and stored_resource != expected_resource_uid:
            mismatch.append('owner (resource)')
    elif stored_resource not in ('', expected_config_uid):
        mismatch.append('owner (resource)')
    if expected_config_uid and current.get('configuration_uid') != expected_config_uid:
        mismatch.append('configuration')
    if vault_profile is not None and (
            (rotation.rotation != 'general' and vault_profile != rotation.rotation)
            or (rotation.rotation == 'general' and vault_profile in ('iam_saas', 'general_saas'))):
        # a general JSON is checked only against the SaaS combinations (any other profile is caught by the owner check)
        mismatch.append(f'type (the vault has "{vault_profile or "general"}")')
    if (rotation.rotation == 'saas' and vault_profile == 'saas' and json_saas_uid and vault_saas
            and json_saas_uid not in vault_saas):
        mismatch.append(f'SaaS configuration (the vault rotation uses "{", ".join(vault_saas)}", the JSON names '
                        f'"{json_saas_uid}")')
    if mismatch:
        return [], [f'{who}rotation {" and ".join(mismatch)} differs from the JSON (type "{rotation.rotation}"); '
                    'update does not move a rotation - left as it is (use `pam rotation edit`)']

    changes: List[Change] = []
    if 'enabled' in explicit and rotation.enabled in ('on', 'off'):
        now_enabled = not current.get('disabled')
        wants = rotation.enabled == 'on'
        if now_enabled != wants:
            changes.append(_graph(OP_CHANGE, 'rotation.enabled', 'on' if now_enabled else 'off', rotation.enabled,
                                  comparator='rotation'))
    if 'schedule' in explicit and rotation.schedule and rotation.schedule.type:
        if rotation.schedule.type == 'on-demand':
            wanted: Tuple[str, ...] = ('none',)
        elif rotation.schedule.cron:
            wanted = ('cron', canonical_cron(rotation.schedule.cron), _tz(rotation.schedule.tz))
        else:
            wanted = ()
        have = canonical_schedule(current.get('schedule'))
        if wanted and wanted != have:
            changes.append(_graph(OP_CHANGE if have != ('none',) or wanted == ('none',) else OP_ADD, 'rotation.schedule',
                                  schedule_text(have), schedule_text(wanted), comparator='rotation'))
    if 'password_complexity' in explicit and rotation.password_complexity:
        wanted_c = _complexity_wanted(rotation.password_complexity)
        have_c = _complexity_tuple(current.get('pwd_complexity'))
        if wanted_c is not None and wanted_c != have_c:
            fmt = (lambda t: ','.join(str(n) for n in t) if t else '')
            changes.append(_graph(OP_CHANGE if have_c else OP_ADD, 'rotation.password_complexity', fmt(have_c),
                                  fmt(wanted_c), comparator='rotation'))
    return changes, []


# --------------------------------------------------------------------------------------------------------------
# workflow
# --------------------------------------------------------------------------------------------------------------

_WF_DAYS = {'mon': 'MONDAY', 'tue': 'TUESDAY', 'wed': 'WEDNESDAY', 'thu': 'THURSDAY', 'fri': 'FRIDAY',
            'sat': 'SATURDAY', 'sun': 'SUNDAY'}
_WF_FLAGS = (('approvals_needed', 'approvalsNeeded', 0), ('checkout_needed', 'checkoutNeeded', False),
             ('start_access_on_approval', 'startAccessOnApproval', False), ('require_reason', 'requireReason', False),
             ('require_ticket', 'requireTicket', False), ('require_mfa', 'requireMFA', False))


def _hhmm(text: str) -> int:
    hours, _, minutes = str(text).strip().partition(':')
    return int(hours) * 100 + int(minutes or 0)


def _team_key(value: Any) -> str:
    """Team UIDs come as standard base64 from the protobuf JSON and as url-safe base64 from the import."""
    return str(value or '').replace('+', '-').replace('/', '_').rstrip('=')


def workflow_projection(config: Optional[Dict[str, Any]], user_email_of=None) -> Dict[str, Any]:
    """Canonical form of a stored workflow (``read_workflow_config`` dict)."""
    params = (config or {}).get('parameters') or {}
    allowed = params.get('allowedTimes') or {}
    approvers: Dict[str, Tuple[bool, int]] = {}
    for item in (config or {}).get('approvers') or []:
        if item.get('user'):
            key = f'user:{str(item["user"]).strip().lower()}'
        elif item.get('teamUid'):
            key = f'team:{_team_key(item["teamUid"])}'
        elif item.get('userId') is not None and user_email_of:
            key = f'user:{str(user_email_of(item["userId"]) or item["userId"]).strip().lower()}'
        else:
            key = f'userId:{item.get("userId")}'
        approvers[key] = (bool(item.get('escalation')), int(item.get('escalationAfterMs') or 0))
    return {
        'flags': {raw: params.get(stored, default) for raw, stored, default in _WF_FLAGS},
        'access_duration_ms': int(params.get('accessLength') or 0),
        'allowed_days': sorted(allowed.get('allowedDays') or []),
        'time_ranges': sorted((int(r.get('startTime') or 0), int(r.get('endTime') or 0))
                              for r in allowed.get('timeRanges') or []),
        'timezone': allowed.get('timeZone') or '',
        'approvers': approvers,
    }


def diff_workflow(opts: Optional[PamWorkflowOptions], raw_workflow: Any, current: Optional[Dict[str, Any]], *,
                  mode: str = 'merge', graph_overwrite: bool = False, user_email_of=None, title: str = ''
                  ) -> Tuple[List[Change], List[str]]:
    """Workflow of one resource. *opts* is the parsed JSON section (None for a trivial one), *current* the router's
    config as a dict (None = no workflow). Only the keys written in the JSON are compared."""
    who = f'"{title}": ' if title else ''
    if not isinstance(raw_workflow, dict):
        return [], []
    if opts is None:
        return [], [f'{who}the workflow section is trivial (nothing to set); it is ignored, a workflow is never removed by it']
    if current is None:
        return [_graph(OP_ADD, 'workflow', None, 'new workflow', comparator='workflow')], []

    have = workflow_projection(current, user_email_of)
    changes: List[Change] = []
    warnings: List[str] = []
    for raw_key, _stored, _default in _WF_FLAGS:
        if raw_key not in raw_workflow:
            continue
        wanted = getattr(opts, raw_key)
        if have['flags'][raw_key] != wanted:
            changes.append(_graph(OP_CHANGE, f'workflow.{raw_key}', have['flags'][raw_key], wanted, comparator='workflow'))
    if 'access_duration' in raw_workflow and have['access_duration_ms'] != opts.access_duration_ms:
        changes.append(_graph(OP_CHANGE, 'workflow.access_duration', have['access_duration_ms'], opts.access_duration_ms,
                              comparator='workflow'))
    times = raw_workflow.get('allowed_times') if isinstance(raw_workflow.get('allowed_times'), dict) else {}
    if 'allowed_days' in times:
        wanted_days = sorted(_WF_DAYS[d] for d in opts.allowed_days if d in _WF_DAYS)
        if wanted_days != have['allowed_days']:
            changes.append(_graph(OP_CHANGE, 'workflow.allowed_days', have['allowed_days'], wanted_days, comparator='workflow'))
    if 'time_ranges' in times:
        wanted_ranges = sorted((_hhmm(r['start']), _hhmm(r['end'])) for r in opts.time_ranges)
        if wanted_ranges != have['time_ranges']:
            changes.append(_graph(OP_CHANGE, 'workflow.time_ranges', have['time_ranges'], wanted_ranges, comparator='workflow'))
    if 'timezone' in times and opts.timezone != have['timezone']:
        changes.append(_graph(OP_CHANGE, 'workflow.timezone', have['timezone'], opts.timezone, comparator='workflow'))
    if 'approvers' in raw_workflow:
        wanted_keys: Dict[str, Tuple[bool, int]] = {}
        for a in opts.approvers:
            key = f'user:{a["email"].strip().lower()}' if a['principal_type'] == 'user' else f'team:{_team_key(a["team_uid_b64"])}'
            wanted_keys[key] = (bool(a['escalation']), int(a['escalation_after_ms'] or 0))
        for key, value in wanted_keys.items():
            if key not in have['approvers']:
                changes.append(_graph(OP_ADD, 'workflow.approvers', None, key, comparator='workflow'))
            elif have['approvers'][key] != value:
                changes.append(_graph(OP_CHANGE, f'workflow.approvers.{key}', _escalation_text(have['approvers'][key]),
                                      _escalation_text(value), comparator='workflow'))
        extra = sorted(key for key in have['approvers'] if key not in wanted_keys)
        if mode == MODE_OVERWRITE and graph_overwrite:
            for key in extra:
                changes.append(_graph(OP_REMOVE, 'workflow.approvers', key, None, comparator='workflow'))
        elif extra:
            # report only: an approver added elsewhere (e.g. in the Web Vault) is kept, never removed by update
            warnings.append(f'{who}the vault workflow has approver(s) the JSON does not list: {", ".join(extra)} '
                            '(kept; update does not remove approvers - remove them in the Web Vault)')
    return changes, warnings


_DAY_TOKEN = {v: k for k, v in _WF_DAYS.items()}


def _hhmm_text(value: int) -> str:
    return f'{int(value) // 100:02d}:{int(value) % 100:02d}'


def workflow_options_from_config(config: Dict[str, Any], user_email_of=None) -> PamWorkflowOptions:
    """The stored workflow as the options object the apply step sends (every field filled from the config).

    Raises ValueError for an approver that has only a user id and cannot be resolved to an email: such an approver
    could not be written back, and the apply step would delete it."""
    params = (config or {}).get('parameters') or {}
    allowed = params.get('allowedTimes') or {}
    opts = PamWorkflowOptions()
    opts.approvals_needed = int(params.get('approvalsNeeded') or 0)
    opts.checkout_needed = bool(params.get('checkoutNeeded'))
    opts.start_access_on_approval = bool(params.get('startAccessOnApproval'))
    opts.require_reason = bool(params.get('requireReason'))
    opts.require_ticket = bool(params.get('requireTicket'))
    opts.require_mfa = bool(params.get('requireMFA'))
    opts.access_duration_ms = int(params.get('accessLength') or opts.access_duration_ms)
    opts.allowed_days = [_DAY_TOKEN[d] for d in allowed.get('allowedDays') or [] if d in _DAY_TOKEN]
    opts.time_ranges = [{'start': _hhmm_text(r.get('startTime') or 0), 'end': _hhmm_text(r.get('endTime') or 0)}
                        for r in allowed.get('timeRanges') or []]
    opts.timezone = allowed.get('timeZone') or ''
    for item in (config or {}).get('approvers') or []:
        escalation = {'escalation': bool(item.get('escalation')),
                      'escalation_after_ms': int(item.get('escalationAfterMs') or 0)}
        if item.get('user'):
            opts.approvers.append({'principal_type': 'user', 'email': str(item['user']), 'team_uid_b64': None,
                                   **escalation})
        elif item.get('teamUid'):
            opts.approvers.append({'principal_type': 'team', 'email': None,
                                   'team_uid_b64': _team_key(item['teamUid']), **escalation})
        elif item.get('userId') is not None and user_email_of and user_email_of(item['userId']):
            opts.approvers.append({'principal_type': 'user', 'email': str(user_email_of(item['userId'])),
                                   'team_uid_b64': None, **escalation})
        else:
            raise ValueError(f'an approver with the user id {item.get("userId")} cannot be resolved to an email')
    return opts


def merged_workflow_options(opts: PamWorkflowOptions, raw_workflow: Dict[str, Any], current: Optional[Dict[str, Any]], *,
                            mode: str = 'merge', graph_overwrite: bool = False, user_email_of=None) -> PamWorkflowOptions:
    """The options to send: ``apply_workflow`` replaces ALL parameters, so for an existing workflow start from the
    stored one and overlay only the keys the JSON wrote. Approvers: the union (JSON wins on escalation); exactly the
    JSON's in overwrite with ``graph_overwrite``. A new workflow is the JSON's options as they are."""
    if current is None:
        return opts
    merged = workflow_options_from_config(current, user_email_of)
    for raw_key, _stored, _default in _WF_FLAGS:
        if raw_key in raw_workflow:
            setattr(merged, raw_key, getattr(opts, raw_key))
    if 'access_duration' in raw_workflow:
        merged.access_duration_ms = opts.access_duration_ms
    times = raw_workflow.get('allowed_times') if isinstance(raw_workflow.get('allowed_times'), dict) else {}
    if 'allowed_days' in times:
        merged.allowed_days = list(opts.allowed_days)
    if 'time_ranges' in times:
        merged.time_ranges = list(opts.time_ranges)
    if 'timezone' in times:
        merged.timezone = opts.timezone
    if 'approvers' in raw_workflow:
        def key(a):
            return f'user:{a["email"].strip().lower()}' if a['principal_type'] == 'user' else f'team:{_team_key(a["team_uid_b64"])}'
        if mode == MODE_OVERWRITE and graph_overwrite:
            merged.approvers = list(opts.approvers)
        else:
            by_key = {key(a): a for a in merged.approvers}
            for a in opts.approvers:
                by_key[key(a)] = a
            merged.approvers = list(by_key.values())
    return merged


# --------------------------------------------------------------------------------------------------------------
# credential references
# --------------------------------------------------------------------------------------------------------------

def _edge_attr(edge: Any, name: str) -> Any:
    return edge.get(name) if isinstance(edge, dict) else getattr(edge, name, None)


def acl_holders(edges: Iterable[Any], resource_uid: str) -> Dict[str, List[str]]:
    """{'admin': [user uids], 'launch': [user uids]} from the ACL edges that point at *resource_uid*."""
    holders: Dict[str, List[str]] = {'admin': [], 'launch': []}
    for edge in edges:
        if _edge_attr(edge, 'head') != resource_uid or str(_edge_attr(edge, 'edge_type') or 'acl') != 'acl':
            continue
        contents = _edge_attr(edge, 'contents') or {}
        if contents.get('is_admin'):
            holders['admin'].append(_edge_attr(edge, 'tail'))
        if contents.get('is_launch_credential'):
            holders['launch'].append(_edge_attr(edge, 'tail'))
    return holders


def diff_credential_refs(resolved: Dict[str, Optional[str]], explicit: Iterable[str], current_conn: Optional[Dict[str, Any]],
                         acl_edges: Iterable[Any], resource_uid: str, *, title: str = ''
                         ) -> Tuple[List[Change], List[str]]:
    """References to other records written in ``pam_settings.connection``.

    *resolved* maps the comparator names (``admin_credential``, ``launch_credential``, ``http_credentials``,
    ``sftp_resource``, ``sftp_user``) to the UID the matcher found for the title / login in the JSON (None = could
    not be resolved). *explicit* names the ones the JSON wrote. Admin and launch credential are single slots: a
    different one REPLACES the old (the router moves the flag), also in merge. Both live only on the ACL edge
    (``is_admin`` / ``is_launch_credential``): the import does NOT write ``connection.userRecords`` (checked in a dump
    of a PROD import, 2026-11-18), so the record is not compared for them.
    """
    explicit = set(explicit)
    who = f'"{title}": ' if title else ''
    changes: List[Change] = []
    warnings: List[str] = []
    conn = current_conn if isinstance(current_conn, dict) else {}
    holders = acl_holders(acl_edges, resource_uid)

    def record_change(name: str, path: str, old: Any, new: Any) -> None:
        target = us.Target(us.KIND_RECORD, field='pamSettings', sub=path, scope=us.SCOPE_ANY)
        op = OP_ADD if is_blank(old) else OP_CHANGE
        changes.append(Change(KIND_RECORD, op, f'pamSettings.{path}', old, new, target=target))

    for name in ('admin_credential', 'launch_credential', 'http_credentials', 'sftp_resource', 'sftp_user'):
        if name not in explicit:
            continue
        uid = resolved.get(name)
        if not uid:
            warnings.append(f'{who}{name.replace("_", " ")} could not be resolved to a record (skipped)')
            continue
        if name == 'admin_credential':
            have = holders['admin']
            if uid not in have or len(have) > 1:
                old = have[0] if have else None
                changes.append(_graph(OP_CHANGE if old else OP_ADD, 'acl.is_admin', old, uid, comparator='admin_credential'))
                if old and old != uid:
                    warnings.append(f'{who}the administrative credential changes from {old} to {uid}')
        elif name == 'launch_credential':
            have = holders['launch']
            if uid not in have or len(have) > 1:
                old = have[0] if have else None
                changes.append(_graph(OP_CHANGE if old else OP_ADD, 'acl.is_launch_credential', old, uid,
                                      comparator='launch_credential'))
                if old and old != uid:
                    warnings.append(f'{who}the launch credential changes from {old} to {uid}')
        elif name == 'http_credentials':
            old = conn.get('httpCredentialsUid')
            old = old[0] if isinstance(old, list) and old else old
            if not same(old, uid):
                record_change(name, 'connection.httpCredentialsUid', old, uid)
        else:
            key = 'sftpResourceUid' if name == 'sftp_resource' else 'sftpUserUid'
            old = (conn.get('sftp') or {}).get(key) if isinstance(conn.get('sftp'), dict) else None
            if not same(old, uid):
                record_change(name, f'connection.sftp.{key}', old, uid)
    return changes, warnings
