#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from collections import Counter
from typing import Dict, List, Optional

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

        ``startingOn`` supplies minute / hour. Cases by ``changeType``:
          * Days     every ``days`` days: ``0 M H */days * ?`` (``days`` 1 = daily)
          * Weekly   weekday booleans: ``0 M H ? * MON,WED``
          * Monthly  ``monthScheduleType`` day-of-month: ``0 M H D */changeEveryMonths ?``;
                     nth weekday: ``0 M H ? */changeEveryMonths DOW#N``
        Returns ``None`` for unknown types so the caller can record a Finding.
        """
        raise NotImplementedError

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
