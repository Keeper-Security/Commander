#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ...cyberark.pam.master_policy_mapper import MasterPolicyMapper
from .client import DelineaPamClient
from .crosswalk import Crosswalk
from .models import ChangerMapping, FindingLog, PasswordComplexity, RotationPolicy, RotationState, _positive
from .policy import SecretPolicyResolver

_WEEKDAYS: Tuple[Tuple[str, str], ...] = (
    ('sunday', 'SUN'), ('monday', 'MON'), ('tuesday', 'TUE'), ('wednesday', 'WED'),
    ('thursday', 'THU'), ('friday', 'FRI'), ('saturday', 'SAT'),
)
_WEEKDAY_QUARTZ = {quartz: quartz for _, quartz in _WEEKDAYS}
_WEEKDAY_QUARTZ.update({name: quartz for name, quartz in _WEEKDAYS})
_WEEKDAY_BY_INDEX = {index: quartz for index, (_, quartz) in enumerate(_WEEKDAYS)}

_CHARACTER_SETS = (
    ('upper', 'upper'),
    ('lower', 'lower'),
    ('digit', 'digits'),
    ('numeric', 'digits'),
    ('number', 'digits'),
    ('symbol', 'symbols'),
    ('special', 'symbols'),
)


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
        secret_id = _int_id(secret.get('id')) or 0
        policy = self.resolver.policy_for(secret)
        rpc = self._rpc(secret_id)
        changer_id, changer_name = self._changer(secret, rpc)
        rpc_items = (policy or {}).get('rpcItems') or {}

        auto_raw = rpc.get('autoChangeEnabled')
        if auto_raw is None:
            auto_raw = secret.get('autoChangeEnabled')
        auto_value, auto_source = SecretPolicyResolver.effective(
            auto_raw, rpc_items.get('autoChangeOnExpiration'))
        mapping = self.crosswalk.resolve(changer_name, self._password_type(changer_id))
        if mapping is None or not mapping.rotation:
            state = RotationState.UNSUPPORTED
        elif auto_value:
            state = RotationState.ENABLED
        else:
            state = RotationState.DISABLED

        schedule_value, _source = SecretPolicyResolver.effective(
            rpc.get('autoChangeSchedule'), rpc_items.get('autoChangeSchedule'))
        schedule = {'type': 'on-demand'}
        cron = self.schedule_to_cron(schedule_value if isinstance(schedule_value, dict) else None)
        if isinstance(schedule_value, dict) and schedule_value.get('changeType') and not cron:
            self.findings.add(
                'Rotation schedule', changer_name or str(secret_id),
                'Schedule type has no Keeper equivalent; using the expiration interval or on-demand')
        if not cron and isinstance(settings, dict):
            cron = self.days_to_cron(settings.get('expirationDayInterval'))
        if cron:
            schedule = {'type': 'cron', 'cron': cron}

        site_value, _source = SecretPolicyResolver.effective(
            secret.get('siteId'), ((policy or {}).get('generalItems') or {}).get('siteId'))
        site_id = site_value if isinstance(site_value, int) and site_value > 0 else None
        try:
            sites = self.client.sites() or {}
        except Exception:
            sites = {}
        site = sites.get(site_id) if site_id else None
        site_name = ''
        if isinstance(site, dict):
            site_name = str(site.get('siteName') or site.get('name') or '')

        admin_raw, _source = SecretPolicyResolver.effective(
            _positive(rpc.get('privilegedAccountSecretId')),
            rpc_items.get('privilegedSecretId'))
        admin_secret_id = _positive(admin_raw)

        return RotationPolicy(
            secret_id=secret_id,
            state=state,
            source=auto_source,
            changer_id=changer_id,
            changer_name=changer_name,
            schedule=schedule,
            complexity=self._complexity(secret, changer_name),
            site_id=site_id,
            site_name=site_name,
            admin_secret_id=admin_secret_id,
        )

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

        ``startingOn`` supplies minute / hour. Cases by ``changeType``:
          * Days     every ``days`` days: ``0 M H */days * ?`` (``days`` 1 = daily)
          * Weekly   weekday booleans: ``0 M H ? * MON,WED``
          * Monthly  ``monthScheduleType`` day-of-month: ``0 M H D */changeEveryMonths ?``;
                     nth weekday: ``0 M H ? */changeEveryMonths DOW#N``
        Returns ``None`` for unknown types so the caller can record a Finding.
        """
        if not isinstance(schedule, dict):
            return None
        change_type = str(schedule.get('changeType') or '').strip().casefold()
        minute, hour = _clock(schedule)
        if change_type == 'days':
            days = _int_id(schedule.get('days'))
            if not days or days <= 0:
                return None
            return f'0 {minute} {hour} */{days} * ?'
        if change_type == 'weekly':
            days = _selected_weekdays(schedule)
            if not days:
                return None
            return f'0 {minute} {hour} ? * {",".join(days)}'
        if change_type == 'monthly':
            months = _int_id(schedule.get('changeEveryMonths') or schedule.get('months')) or 1
            if months <= 0:
                return None
            month_field = f'*/{months}'
            kind = str(schedule.get('monthScheduleType') or schedule.get('monthlyScheduleType') or '').casefold()
            weekday = _quartz_weekday(schedule.get('dayOfWeek') or schedule.get('weekday'))
            week_number = _int_id(schedule.get('weekNumber') or schedule.get('weekOrder') or schedule.get('monthlyWeek'))
            if 'week' in kind and weekday and week_number and week_number > 0:
                return f'0 {minute} {hour} ? {month_field} {weekday}#{week_number}'
            day = _int_id(schedule.get('dayOfMonth') or schedule.get('day') or schedule.get('date'))
            if day and day > 0:
                return f'0 {minute} {hour} {day} {month_field} ?'
        return None

    @staticmethod
    def complexity_from_requirement(requirement: Optional[dict],
                                    findings: Optional[FindingLog] = None) -> Optional[PasswordComplexity]:
        """Password requirement to complexity.

        ``minPasswordLength`` is the length; each ``passwordRequirementRules[]``
        with ``passwordRequirementType == 'MinimumOf'`` adds
        ``minCharactersRequired`` to upper / lower / digits / symbols according
        to ``characterSet.name``. Unknown character sets yield a Finding.
        """
        if not isinstance(requirement, dict):
            return None
        length = _int_id(requirement.get('minPasswordLength'))
        if not length or length <= 0:
            return None
        counts = {'upper': 0, 'lower': 0, 'digits': 0, 'symbols': 0}
        rules = requirement.get('passwordRequirementRules')
        if not isinstance(rules, list):
            rules = requirement.get('rules') if isinstance(requirement.get('rules'), list) else []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if str(rule.get('passwordRequirementType') or '').casefold() != 'minimumof':
                continue
            amount = _int_id(rule.get('minCharactersRequired')) or 0
            if amount <= 0:
                continue
            bucket = _character_bucket(rule.get('characterSet'))
            if bucket is None:
                label = _character_label(rule.get('characterSet')) or 'unknown'
                if findings is not None:
                    findings.add('Password complexity', label,
                                 'Character set has no Keeper equivalent and was ignored')
                continue
            counts[bucket] += amount
        return PasswordComplexity(length=length, **counts)

    def _rpc(self, secret_id: int) -> dict:
        if secret_id <= 0:
            return {}
        try:
            rpc = self.client.secret_rpc(secret_id)
        except Exception:
            return {}
        return rpc if isinstance(rpc, dict) else {}

    def _changer(self, secret: dict, rpc: dict) -> Tuple[Optional[int], str]:
        changer_id = _positive(rpc.get('passwordTypeId'))
        changer_name = str(rpc.get('passwordTypeName') or '').strip()
        if changer_id is None:
            template_id = secret.get('secretTemplateId')
            template = None
            if isinstance(template_id, int):
                try:
                    template = self.client.secret_template(template_id)
                except Exception:
                    template = None
            if isinstance(template, dict):
                changer_id = _positive(template.get('passwordTypeId'))
                if not changer_name:
                    changer_name = str(template.get('passwordTypeName') or '').strip()
        detail = self._password_type(changer_id)
        if isinstance(detail, dict) and not changer_name:
            changer_name = str(detail.get('name') or detail.get('passwordTypeName') or '').strip()
        return changer_id, changer_name

    def _password_type(self, changer_id: Optional[int]) -> Optional[dict]:
        if not changer_id:
            return None
        try:
            detail = self.client.password_type(changer_id)
        except Exception:
            return None
        return detail if isinstance(detail, dict) else None

    def _complexity(self, secret: dict, changer_name: str) -> Optional[PasswordComplexity]:
        template_id = secret.get('secretTemplateId')
        template = None
        if isinstance(template_id, int):
            try:
                template = self.client.secret_template(template_id)
            except Exception:
                template = None
        requirement_id = _requirement_id(template)
        if not requirement_id:
            return None
        try:
            requirement = self.client.password_requirement(requirement_id)
        except Exception as exc:
            self.findings.add('Password complexity', changer_name or str(requirement_id),
                              f'Password requirement could not be read: {exc}')
            return None
        return self.complexity_from_requirement(requirement, self.findings)

    @staticmethod
    def days_to_cron(days: int) -> Optional[str]:
        return MasterPolicyMapper.days_to_cron(days)

    @staticmethod
    def summary(policies: List[RotationPolicy]) -> Dict[str, int]:
        """Counts for the report: enabled, disabled, unsupported, and inherited."""
        counts = Counter(p.state.value for p in policies)
        counts['inherited'] = sum(1 for p in policies if p.inherited)
        return dict(counts)


def _int_id(value) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip('-').isdigit():
        return int(value.strip())
    return None




def _clock(schedule: dict) -> Tuple[int, int]:
    raw = schedule.get('startingOn') or schedule.get('startTime') or ''
    if isinstance(raw, str) and 'T' in raw:
        text = raw.replace('Z', '+00:00')
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            parsed = None
        if parsed is not None:
            return parsed.minute, parsed.hour
    return 0, 0


def _selected_weekdays(schedule: dict) -> List[str]:
    sources = [schedule]
    for key in ('weekly', 'weeklySchedule'):
        nested = schedule.get(key)
        if isinstance(nested, dict):
            sources.append(nested)
    selected: List[str] = []
    for source in sources:
        for name, quartz in _WEEKDAYS:
            if source.get(name) is True and quartz not in selected:
                selected.append(quartz)
    return selected


def _quartz_weekday(value) -> Optional[str]:
    if isinstance(value, str):
        return _WEEKDAY_QUARTZ.get(value.strip().casefold())
    index = _int_id(value)
    if index is None:
        return None
    if index in _WEEKDAY_BY_INDEX:
        return _WEEKDAY_BY_INDEX[index]
    if 1 <= index <= 7:
        return _WEEKDAY_BY_INDEX[index - 1]
    return None


def _character_label(character_set) -> str:
    if isinstance(character_set, dict):
        return str(character_set.get('name') or character_set.get('characterSetName') or '')
    if isinstance(character_set, str):
        return character_set
    return ''


def _character_bucket(character_set) -> Optional[str]:
    label = _character_label(character_set).casefold()
    if not label:
        return None
    for needle, bucket in _CHARACTER_SETS:
        if needle in label:
            return bucket
    return None


def _requirement_id(template: Optional[dict]) -> Optional[int]:
    if not isinstance(template, dict):
        return None
    fields = template.get('fields')
    if not isinstance(fields, list):
        fields = template.get('items') if isinstance(template.get('items'), list) else []
    for field in fields:
        if not isinstance(field, dict):
            continue
        slug = str(field.get('slug') or '').casefold()
        if slug != 'password' and not field.get('isPassword'):
            continue
        requirement_id = _positive(field.get('passwordRequirementId'))
        if requirement_id:
            return requirement_id
    return None
