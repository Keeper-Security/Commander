#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from typing import Any, Optional, Tuple

from .models import ChangerMapping, FindingLog, PolicySource, _positive
from .policy import SecretPolicyResolver


class LauncherMapper:
    """Maps Delinea launcher and session settings onto ``pam_settings``."""

    def __init__(self, findings: FindingLog):
        self.findings = findings

    def pam_settings(self, secret: dict, settings: Optional[dict], policy: Optional[dict],
                     mapping: ChangerMapping, rotation_enabled: bool,
                     launch_title: str, admin_title: str) -> Optional[dict]:
        """``pam_settings`` for a resource; ``None`` for ``login`` and other non-PAM types."""
        if mapping.record_type not in ('pamMachine', 'pamDatabase', 'pamDirectory'):
            return None
        recording = self.session_recording(secret, policy)
        options = {
            'rotation': 'on' if rotation_enabled else 'off',
            'connections': 'on' if mapping.protocol else 'off',
            'tunneling': 'off',
            'graphical_session_recording': 'on' if recording else 'off',
            'text_session_recording': 'on' if recording and mapping.protocol != 'rdp' else 'off',
        }
        result: dict = {'options': options}
        if mapping.protocol:
            connection = {
                'protocol': mapping.protocol,
                'port': mapping.port,
                'launch_credentials': launch_title,
                'administrative_credentials': admin_title,
            }
            if mapping.protocol == 'rdp':
                connection.update(self.rdp_options(settings, policy))
            result['connection'] = connection
        return result

    def connect_as_secret_id(self, secret: dict, settings: Optional[dict], policy: Optional[dict]) -> Optional[int]:
        """Secret the launcher connects as (becomes ``launch_credentials``), or ``None``.

        ``settings.sshLauncherSettings`` with ``launcherType == 'ConnectAsSecret'``
        gives ``secretId``; otherwise ``secret.launcherConnectAsSecretId``;
        ``securityItems.runLauncherUsingSSHKeySecretId`` applies via ``effective``.
        """
        secret = secret or {}
        settings = settings or {}
        ssh = settings.get('sshLauncherSettings') if isinstance(settings.get('sshLauncherSettings'), dict) else {}
        chosen = None
        if str(ssh.get('launcherType') or '') == 'ConnectAsSecret':
            chosen = _positive(ssh.get('secretId'))
        if chosen is None:
            chosen = _positive(secret.get('launcherConnectAsSecretId'))
        value, _source = LauncherMapper.effective(
            chosen, policy, 'securityItems', 'runLauncherUsingSSHKeySecretId')
        return _positive(value)

    def session_recording(self, secret: dict, policy: Optional[dict]) -> bool:
        """``secret.sessionRecordingEnabled`` vs ``securityItems.isSessionRecordingEnabled``.

        An effective ``securityItems.enableSshCommandRestrictions`` has no Keeper
        equivalent and is recorded as a Finding.
        """
        secret = secret or {}
        enabled, _source = LauncherMapper.effective(
            secret.get('sessionRecordingEnabled'), policy, 'securityItems', 'isSessionRecordingEnabled')
        restricted, _source = LauncherMapper.effective(
            secret.get('enableSshCommandRestrictions'), policy,
            'securityItems', 'enableSshCommandRestrictions')
        if restricted:
            self.findings.add(
                'Session recording', 'SSH command restrictions',
                'Delinea SSH command restrictions have no Keeper equivalent')
        return bool(enabled)

    def rdp_options(self, settings: Optional[dict], policy: Optional[dict]) -> dict:
        """RDP connection keys from ``settings.rdpLauncherSettings`` vs ``launcherItems.launcherSettings``.

        ``allowClipboard`` false sets ``disable_copy`` and ``disable_paste``.
        ``allowDrives`` / ``allowPrinters`` / ``allowSmartCards`` true have no
        Keeper equivalent and are recorded as Findings.
        """
        settings_value = (settings or {}).get('rdpLauncherSettings') if isinstance(settings, dict) else None
        value, _source = LauncherMapper.effective(
            settings_value, policy, 'launcherItems', 'launcherSettings')
        if not isinstance(value, dict):
            return {}
        result = {}
        if value.get('allowClipboard') is False:
            result['disable_copy'] = True
            result['disable_paste'] = True
        unsupported = (
            ('allowDrives', 'drive redirection'),
            ('allowPrinters', 'printer redirection'),
            ('allowSmartCards', 'smart card redirection'),
        )
        for key, label in unsupported:
            if value.get(key) is True:
                self.findings.add('RDP launcher', label, 'No Keeper equivalent')
        return result

    @staticmethod
    def effective(secret_value: Any, policy: Optional[dict], group: str, item: str) -> Tuple[Any, PolicySource]:
        """``SecretPolicyResolver.effective`` for ``policy[group][item]``."""
        policy_item = ((policy or {}).get(group) or {}).get(item)
        return SecretPolicyResolver.effective(secret_value, policy_item)