#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

import datetime
from collections import Counter
from typing import Dict, List, Optional, Tuple

from ...cyberark.pam.master_policy_mapper import MasterPolicyMapper
from .client import DelineaPamClient
from .crosswalk import Crosswalk
from .models import ChangerMapping, FindingLog, PasswordComplexity, RotationPolicy, RotationState
from .policy import SecretPolicyResolver


class RotationMapper:
    """Resolves a secret's effective RPC policy and converts it to Keeper ``rotation_settings``."""

    def __init__(self, client: DelineaPamClient, resolver: SecretPolicyResolver, crosswalk: Crosswalk,
                 findings: FindingLog):
        self.client = client
        self.resolver = resolver
        self.crosswalk = crosswalk
        self.findings = findings

    def resolve(self, secret: dict, settings: Optional[dict]) -> RotationPolicy:
        """Effective RPC policy of *secret* (*settings* is ``client.secret_settings``).

        Each value goes through ``SecretPolicyResolver.effective`` against the
        policy's ``rpcItems``:
          * changer       ``secret_rpc.passwordTypeId`` / ``passwordTypeName``, else the
                          template's ``passwordTypeId``
          * auto change   ``secret_rpc.autoChangeEnabled`` (fallback ``secret.autoChangeEnabled``)
                          vs ``rpcItems.autoChangeOnExpiration``
          * schedule      ``secret_rpc.autoChangeSchedule`` vs ``rpcItems.autoChangeSchedule``
                          via ``schedule_to_cron``; else ``settings.expirationDayInterval`` via
                          ``MasterPolicyMapper.days_to_cron``; else on-demand
          * complexity    template password field ``passwordRequirementId`` via
                          ``complexity_from_requirement``
          * site          ``secret.siteId`` vs ``generalItems.siteId``, named from ``client.sites()``
          * admin secret  ``secret_rpc.privilegedAccountSecretId`` vs ``rpcItems.privilegedSecretId``

        State: UNSUPPORTED when the changer is unmapped or its mapping has no
        ``rotation``; otherwise ENABLED / DISABLED from auto change. ``source``
        is the source of the auto-change value. ``secret_rpc`` returning ``None``
        (pre-11.7 servers) is not an error.
        """
        raise NotImplementedError

    @staticmethod
    def to_rotation_settings(policy: RotationPolicy, mapping: Optional[ChangerMapping]) -> Optional[dict]:
        """``pamUser.rotation_settings`` for the import JSON, or ``None`` when UNSUPPORTED."""
        if policy.state is RotationState.UNSUPPORTED or not mapping or not mapping.rotation:
            return None
        enabled = policy.state is RotationState.ENABLED
        settings = {
            'rotation': mapping.rotation,
            'enabled': 'on' if enabled else 'off',
            'schedule': policy.schedule if enabled else {'type': 'on-demand'},
        }
        if policy.complexity:
            settings['password_complexity'] = policy.complexity.to_keeper()
        return settings

    @staticmethod
    def schedule_to_cron(schedule: Optional[dict]) -> Optional[str]:
        """Quartz cron (six fields, as ``MasterPolicyMapper.days_to_cron``) for an AutoChangeScheduleModel.

        ``startingOn`` supplies minute / hour. Secret Server sends ``scheduleType``
        (``Daily`` / ``Weekly`` / ``Monthly``); older payloads use ``changeType``.
          * Days     every ``days`` days: ``0 M H */days * ?`` (``days`` 1 = daily)
          * Weekly   weekday booleans: ``0 M H ? * MON,WED``
          * Monthly  ``monthScheduleType`` day-of-month: ``0 M H D */changeEveryMonths ?``;
                     nth weekday: ``0 M H ? */changeEveryMonths DOW#N``
        Returns ``None`` for unknown types so the caller can record a Finding.

        Times are converted to UTC. When that moves the run to another day, the
        weekday or day of month moves with it (day 0 becomes ``L``, day 32 becomes
        1). For nth-weekday schedules only the weekday moves, so a run near a
        month boundary can land on the neighbouring week's occurrence.
        """
        if not isinstance(schedule, dict):
            return None
        minute, hour, shift = RotationMapper._clock(schedule.get('startingOn'))
        change = str(schedule.get('scheduleType') or schedule.get('changeType') or '').strip().casefold()
        if change in ('days', 'daily'):
            days = RotationMapper._positive_int(schedule.get('days'), 1)
            if not days:
                return None
            dom = '*' if days == 1 else f'*/{days}'
            return f'0 {minute} {hour} {dom} * ?'
        if change == 'weekly':
            weekdays = RotationMapper._weekdays(schedule)
            if not weekdays:
                return None
            weekdays = RotationMapper._sorted_days(RotationMapper._shift_dow(day, shift) for day in weekdays)
            return f'0 {minute} {hour} ? * {",".join(weekdays)}'
        if change == 'monthly':
            return RotationMapper._monthly_cron(schedule, minute, hour, shift)
        return None

    @staticmethod
    def _clock(starting_on) -> Tuple[int, int, int]:
        """UTC (minute, hour, day shift) for *starting_on*; shift is -1, 0 or +1."""
        if not starting_on:
            return 0, 0, 0
        text = str(starting_on).strip()
        if text.endswith(('Z', 'z')):
            text = text[:-1] + '+00:00'
        try:
            parsed = datetime.datetime.fromisoformat(text)
        except ValueError:
            return 0, 0, 0
        # The cron feeds Keeper's utcTime. Naive timestamps are taken as UTC.
        if parsed.tzinfo is None:
            return parsed.minute, parsed.hour, 0
        utc = parsed.astimezone(datetime.timezone.utc)
        shift = (utc.date() - parsed.date()).days
        return utc.minute, utc.hour, shift

    _QUARTZ_DAYS = ('SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT')

    @staticmethod
    def _shift_dow(day: str, shift: int) -> str:
        days = RotationMapper._QUARTZ_DAYS
        return days[(days.index(day) + shift) % 7]

    @staticmethod
    def _sorted_days(days) -> List[str]:
        return sorted(set(days), key=RotationMapper._QUARTZ_DAYS.index)

    @staticmethod
    def _positive_int(value, default: int) -> Optional[int]:
        if value in (None, ''):
            return default
        try:
            number = int(value)
        except (TypeError, ValueError):
            return None
        return number if number > 0 else None

    @staticmethod
    def _weekdays(schedule: dict) -> List[str]:
        names = ('sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday')
        quartz = ('SUN', 'MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT')
        selected = []
        listed = schedule.get('weeklyDays') or schedule.get('daysOfWeek') or []
        listed_names = {str(day).strip().casefold()[:3] for day in listed} if isinstance(listed, list) else set()
        for name, short in zip(names, quartz):
            if RotationMapper._flag(schedule, name) or name[:3] in listed_names or short.casefold() in listed_names:
                selected.append(short)
        return selected

    @staticmethod
    def _flag(schedule: dict, name: str) -> bool:
        for key, value in schedule.items():
            if str(key).casefold() != name:
                continue
            if isinstance(value, str):
                return value.strip().casefold() == 'true'
            return bool(value)
        return False

    @staticmethod
    def _monthly_cron(schedule: dict, minute: int, hour: int, shift: int = 0) -> Optional[str]:
        months = RotationMapper._positive_int(schedule.get('changeEveryMonths'), 1)
        if not months:
            return None
        month_field = '*' if months == 1 else f'*/{months}'
        kind = str(schedule.get('monthScheduleType') or 'day').strip().casefold().replace('_', '').replace('-', '')
        if kind in ('day', 'dayofmonth'):
            day = RotationMapper._positive_int(
                schedule.get('changeEveryMonthsDayNumber', schedule.get('dayOfMonth', schedule.get('day'))),
                1,
            )
            if not day or day > 31:
                return None
            day += shift
            dom = 'L' if day < 1 else str(1 if day > 31 else day)
            return f'0 {minute} {hour} {dom} {month_field} ?'
        if kind in ('weekday', 'nthweekday', 'week', 'weekofmonth'):
            dow = RotationMapper._dow(
                schedule.get('changeEveryMonthsInstanceTarget')
                or schedule.get('weekDay') or schedule.get('dayOfWeek')
            )
            nth = RotationMapper._week_number(
                schedule.get('changeEveryMonthsInstance')
                or schedule.get('weekNumber') or schedule.get('weekOfMonth')
            )
            if not dow or not nth:
                return None
            dow = RotationMapper._shift_dow(dow, shift)
            occurrence = f'{dow}L' if nth == 'L' else f'{dow}#{nth}'
            return f'0 {minute} {hour} ? {month_field} {occurrence}'
        return None

    @staticmethod
    def _dow(value) -> Optional[str]:
        text = str(value or '').strip().casefold()
        names = {
            'sun': 'SUN', 'sunday': 'SUN', 'mon': 'MON', 'monday': 'MON',
            'tue': 'TUE', 'tuesday': 'TUE', 'wed': 'WED', 'wednesday': 'WED',
            'thu': 'THU', 'thursday': 'THU', 'fri': 'FRI', 'friday': 'FRI',
            'sat': 'SAT', 'saturday': 'SAT',
        }
        return names.get(text)

    @staticmethod
    def _week_number(value) -> Optional[str]:
        text = str(value or '').strip().casefold()
        names = {'first': '1', 'second': '2', 'third': '3', 'fourth': '4', 'last': 'L',
                 '1': '1', '2': '2', '3': '3', '4': '4', 'l': 'L'}
        return names.get(text)

    @staticmethod
    def complexity_from_requirement(requirement: Optional[dict]) -> Optional[PasswordComplexity]:
        """Password requirement to complexity.

        ``minPasswordLength`` is the length; each ``passwordRequirementRules[]``
        with ``passwordRequirementType == 'MinimumOf'`` adds
        ``minCharactersRequired`` to upper / lower / digits / symbols according
        to ``characterSet.name``. Unknown character sets yield a Finding.
        """
        raise NotImplementedError

    @staticmethod
    def days_to_cron(days: int) -> Optional[str]:
        return MasterPolicyMapper.days_to_cron(days)

    @staticmethod
    def summary(policies: List[RotationPolicy]) -> Dict[str, int]:
        """Counts for the report: enabled, disabled, unsupported, and inherited."""
        counts = Counter(p.state.value for p in policies)
        counts['inherited'] = sum(1 for p in policies if p.inherited)
        return dict(counts)