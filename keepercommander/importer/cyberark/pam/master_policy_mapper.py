#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import logging
from typing import Any, Dict, List, Optional, Tuple

class MasterPolicyMapper:
    """Maps CyberArk Master Policy rules to Keeper PAM Configuration settings.

    Handles BOTH supported CyberArk Master Policy response shapes:

    1. Self-Hosted PVWA / Privilege Cloud canonical endpoint
       ``GET /PasswordVault/API/Policies/1`` returns a flat dict::

           {
             "PasswordChangeDays":         {"Value": 90},
             "PasswordVerificationDays":   {"Value": 7},
             "TransparentConnection":      {"Value": true},
             "RecordActivity":             {"Value": true},
             "RequireMonitoringAndIsolation": {"Value": true},
             "EnforceOneTimePassword":     {"Value": false},
             "EnforceExclusiveAccess":     {"Value": false},
             "DualControl":                {"Value": false},
             ...
           }

    2. Privilege Cloud (newer) endpoint
       ``GET /PasswordVault/API/Policy/MasterPolicy`` returns::

           {"Policy": {"Rules": [
              {"RuleName": "RecordAndSaveSessionActivity", "Active": true},
              {"RuleName": "AllowEPVTransparentConnections", "Active": true},
              {"RuleName": "SafeAuditRetention", "Value": 365},
              ...
           ]}}

    The mapper normalizes both formats into a single rule lookup before
    deciding which Keeper PAM Configuration knobs to flip.
    """

    DEFAULTS = {
        "connections": "on",
        "rotation": "on",
        "tunneling": "on",
        "graphical_session_recording": "off",
        "text_session_recording": "off",
        # Keeper-specific features that have no CyberArk Master Policy
        # equivalent — default off so a CyberArk migration doesn't silently
        # enable RBI or AI threat detection on customers who didn't opt in.
        # PamConfigEnvironment defaults RBI to "on", so we set explicitly.
        "remote_browser_isolation": "off",
        "ai_threat_detection": "off",
        "ai_terminate_session_on_detection": "off",
        # Rotation cadence imported from CyberArk's "Require password change
        # every X days" rule. ``default_rotation_schedule`` is the same shape
        # the import JSON expects — see PamConfigEnvironment.load() and
        # build_import_json() below. ``password_change_days`` is kept
        # alongside as informational metadata for the import report.
        "default_rotation_schedule": {"type": "on-demand"},
        "password_change_days": 0,
    }

    # CyberArk → Keeper rule-name aliases. Each Keeper-side concept can come
    # from any of the three API formats described in the class docstring; we
    # accept every documented spelling (PascalCase from the legacy PVWA
    # endpoints AND camelCase from the new ISPSS ``/api/platforms/master-
    # rotation-policy/`` endpoint) and use whichever one the server returns.
    _RECORDING_RULES = ("RecordActivity", "recordActivity",
                        "RecordAndSaveSessionActivity", "recordAndSaveSessionActivity")
    _CONNECTION_RULES = ("TransparentConnection", "transparentConnection",
                         "AllowEPVTransparentConnections", "allowEPVTransparentConnections")
    _MONITORING_RULES = ("RequireMonitoringAndIsolation", "requireMonitoringAndIsolation",
                         "RequirePrivilegedSessionMonitoringAndIsolation",
                         "requirePrivilegedSessionMonitoringAndIsolation")
    _DUAL_CONTROL_RULES = ("DualControl", "dualControl",
                           "RequireDualControlPasswordAccessApproval",
                           "requireDualControlPasswordAccessApproval")
    _EXCLUSIVE_RULES = ("EnforceExclusiveAccess", "enforceExclusiveAccess",
                        "EnforceCheckinCheckoutExclusiveAccess",
                        "enforceCheckinCheckoutExclusiveAccess")
    _ONE_TIME_RULES = ("EnforceOneTimePassword", "enforceOneTimePassword",
                       "EnforceOnetimePasswordAccess", "enforceOnetimePasswordAccess")
    _AUDIT_RETENTION_RULES = ("RetentionPeriod", "retentionPeriod",
                              "SafeAuditRetention", "safeAuditRetention")
    # Rotation cadence: PascalCase (PVWA self-hosted), camelCase (ISPSS
    # /Policies/1), platform-style (Get-Platforms credentialsManagement),
    # and the *new* short names used by the Privilege Cloud
    # ``/api/platforms/master-rotation-policy/`` endpoint
    # (``changeInterval`` / ``verifyInterval`` — confirmed live response,
    # this is what the Metron tenant returned).
    _CHANGE_DAYS_RULES = ("PasswordChangeDays", "passwordChangeDays",
                          "requirePasswordChangeEveryXDays",
                          "RequirePasswordChangeEveryXDays",
                          "changeInterval", "ChangeInterval")
    _VERIFY_DAYS_RULES = ("PasswordVerificationDays", "passwordVerificationDays",
                          "requirePasswordVerificationEveryXDays",
                          "RequirePasswordVerificationEveryXDays",
                          "verifyInterval", "VerifyInterval")

    @staticmethod
    def normalize(policy_data: dict) -> Dict[str, Any]:
        """Flatten any of the three Master Policy response shapes.

        - **Self-Hosted ``/Policies/1``** → ``{"DualControl": {"Value": true}}``
          becomes ``{"DualControl": True}``.
        - **Privilege Cloud ``/Policy/MasterPolicy``** →
          ``{"Policy": {"Rules": [{"RuleName": "X", "Active": true,
          "Value": 7}]}}`` becomes ``{"X": True}`` for boolean rules, or
          ``{"X": 7}`` when only ``Value`` is present (SafeAuditRetention).
        - **ISPSS ``/api/platforms/master-rotation-policy/``** → flat
          camelCase JSON. Booleans/ints are kept as-is. If the server wraps
          related settings in groups (e.g. ``{"credentialsManagement": {
          "requirePasswordChangeEveryXDays": 90, ... }}`` — the same shape
          ``Get-Platforms`` uses), nested dicts are flattened one level down
          so the same rule lookup works for every endpoint.
        """
        rules: Dict[str, Any] = {}

        # ── Format B: Privilege Cloud "Rules" array ──────────────
        policy_obj = policy_data.get("Policy", None)
        if isinstance(policy_obj, dict):
            for rule in (policy_obj.get("Rules") or []):
                if not isinstance(rule, dict):
                    continue
                name = rule.get("RuleName", "")
                if not name:
                    continue
                if "Active" in rule:
                    rules[name] = bool(rule.get("Active"))
                elif "Value" in rule:
                    rules[name] = rule.get("Value")

        # ── Formats A & C: flat dicts (Self-Hosted wrapped, ISPSS bare) ──
        # We iterate the top-level dict (skipping the "Policy" key we
        # already consumed) so a server returning more than one shape still
        # parses. ISPSS responses occasionally nest related rules inside a
        # group object — we flatten nested dicts one level so the lookup
        # tables in map_policy() find them under their leaf name.
        for name, val in policy_data.items():
            if name == "Policy":
                continue
            if isinstance(val, dict):
                if "Value" in val and len(val) == 1:
                    rules[name] = val["Value"]
                    continue
                # Nested ISPSS group (e.g. credentialsManagement,
                # sessionManagement, privilegedAccessWorkflows). Also
                # surface the parent key so callers can introspect groups
                # if needed, but rules lookup uses leaf names.
                for subname, subval in val.items():
                    if isinstance(subval, dict) and "Value" in subval:
                        rules.setdefault(subname, subval["Value"])
                    elif isinstance(subval, (bool, int, float, str)):
                        rules.setdefault(subname, subval)
                continue
            if isinstance(val, (bool, int, float, str)):
                rules.setdefault(name, val)
        return rules

    @staticmethod
    def first_rule(rules: Dict[str, Any], names: Tuple[str, ...]) -> Tuple[bool, Any]:
        """Return ``(found, value)`` for the first alias present in ``rules``."""
        for n in names:
            if n in rules:
                return True, rules[n]
        return False, None

    @staticmethod
    def days_to_cron(days: int) -> Optional[str]:
        """Convert CyberArk PasswordChangeDays → Quartz 6-field CRON string.

        Keeper's rotation engine validates expressions with
        ``validate_cron_expression(..., for_rotation=True)`` which requires
        SIX fields (``sec min hour dom month dow``) and a ``?`` placeholder
        in either day-of-month or day-of-week. CyberArk only tells us the
        cadence (e.g. "every 90 days") — not the specific time/day — so we
        bucket the cadence into the closest "round" Quartz schedule that
        Keeper accepts. The chosen anchor (midnight on the 1st) matches
        CyberArk's own default rotation behavior of running CPM jobs after
        midnight on the next eligible day.

        Returns ``None`` when ``days <= 0`` so callers fall back to the
        on-demand default.
        """
        try:
            d = int(days)
        except (TypeError, ValueError):
            return None
        if d <= 0:
            return None
        # Each branch produces a 6-field Quartz expression (sec min hour dom
        # month dow) with ``?`` in either dom or dow as Keeper's
        # validate_cron_expression(for_rotation=True) requires. Only the
        # ``*/N`` step form is accepted by the validator regex, so we avoid
        # ``X/N``-style anchors.
        if d == 1:
            return "0 0 0 * * ?"
        if d <= 6:
            # Every N days at midnight (step on day-of-month)
            return f"0 0 0 */{d} * ?"
        if d <= 13:
            # Weekly — Sunday (Quartz dow 1 = Sunday)
            return "0 0 0 ? * 1"
        if d <= 27:
            # Bi-weekly — the 1st and 15th of each month at midnight
            return "0 0 0 1,15 * ?"
        if d <= 59:
            # Monthly — first day of every month
            return "0 0 0 1 * ?"
        if d <= 89:
            # Bi-monthly — first day of every other month
            return "0 0 0 1 */2 ?"
        if d <= 179:
            # Quarterly — covers CyberArk's 90-day default
            return "0 0 0 1 */3 ?"
        if d <= 364:
            # Semi-annual
            return "0 0 0 1 */6 ?"
        # Annual or longer — Jan 1 at midnight
        return "0 0 0 1 1 ?"

    @staticmethod
    def map_policy(policy_data: Optional[dict]) -> Tuple[dict, List[dict]]:
        """Map Master Policy to PAM config settings.

        Returns ``(pam_config_updates, unmapped_items)``.
        """
        if not policy_data or not isinstance(policy_data, dict):
            return dict(MasterPolicyMapper.DEFAULTS), []

        # Backward compat: tests pass {"Policy": <invalid>}; treat anything
        # that isn't a dict as a missing policy section but still try the
        # flat top-level format above it.
        policy_section = policy_data.get("Policy", None)
        if "Policy" in policy_data and not isinstance(policy_section, dict):
            # Caller explicitly sent a malformed Policy block — keep the
            # historical behavior of returning the bare defaults so existing
            # crash-case tests stay green.
            return dict(MasterPolicyMapper.DEFAULTS), []

        rules = MasterPolicyMapper.normalize(policy_data)
        config = dict(MasterPolicyMapper.DEFAULTS)
        unmapped: List[dict] = []

        # ── Session recording (Active → on) ─────────────────────
        found, val = MasterPolicyMapper.first_rule(rules, MasterPolicyMapper._RECORDING_RULES)
        if found:
            on = bool(val)
            config["graphical_session_recording"] = "on" if on else "off"
            config["text_session_recording"] = "on" if on else "off"

        # ── Transparent connections ─────────────────────────────
        found, val = MasterPolicyMapper.first_rule(rules, MasterPolicyMapper._CONNECTION_RULES)
        if found:
            config["connections"] = "on" if bool(val) else "off"

        # ── PSM monitoring (no direct Keeper toggle) ────────────
        # If CyberArk requires monitoring + isolation we leave Keeper's
        # connections=on but flag the granular PSM behavior as unmapped so
        # the admin reviews it after migration.
        found, val = MasterPolicyMapper.first_rule(rules, MasterPolicyMapper._MONITORING_RULES)
        if found and bool(val):
            config["connections"] = "on"
            unmapped.append({
                "category": "Master Policy",
                "item": "Privileged session monitoring & isolation = Active",
                "action": "Enable session recording + connection auditing on the "
                          "Keeper PAM Configuration; PSM-style isolation is "
                          "delivered by the Keeper Gateway and Connection records.",
            })

        # ── Rotation cadence (Require password change every X days) ──
        # This is the part of the Master Rotation Policy described at
        # docs.cyberark.com/.../privcloud_get_masterpolicy.htm. The cadence
        # is exposed under different field names depending on the API:
        #   - PVWA self-hosted /Policies/1 → ``PasswordChangeDays``
        #   - ISPSS /api/platforms/master-rotation-policy/ →
        #     ``passwordChangeDays`` / ``requirePasswordChangeEveryXDays``
        # We translate the integer into Keeper's ``default_rotation_schedule``
        # so newly-imported PAM users inherit the same rotation frequency.
        found, raw_days = MasterPolicyMapper.first_rule(
            rules, MasterPolicyMapper._CHANGE_DAYS_RULES)
        if found:
            try:
                days = int(raw_days or 0)
            except (TypeError, ValueError):
                days = 0
            config["password_change_days"] = days
            cron = MasterPolicyMapper.days_to_cron(days)
            if cron:
                config["default_rotation_schedule"] = {"type": "CRON", "cron": cron}
            elif days == 0:
                # 0 in CyberArk = "do not auto-change"; leave default on-demand
                # but warn the admin so they don't think rotation is enforced.
                unmapped.append({
                    "category": "Master Policy",
                    "item": "Password change interval = 0 (auto-change disabled)",
                    "action": "Auto-rotation was disabled in CyberArk. Imported "
                              "records default to on-demand rotation in Keeper — "
                              "enable a CRON schedule per record/PAM Config when "
                              "ready to rotate.",
                })

        # ── Verification cadence (no direct Keeper equivalent) ──
        found, raw_vdays = MasterPolicyMapper.first_rule(
            rules, MasterPolicyMapper._VERIFY_DAYS_RULES)
        if found:
            try:
                vdays = int(raw_vdays or 0)
            except (TypeError, ValueError):
                vdays = 0
            if vdays > 0:
                unmapped.append({
                    "category": "Master Policy",
                    "item": f"Password verification interval = {vdays} days",
                    "action": "Keeper does not run separate password-verification "
                              "jobs; rotation itself validates credentials. Set a "
                              "tighter rotation schedule if periodic verification "
                              "is required.",
                })

        # ── Audit retention (RetentionPeriod or SafeAuditRetention) ──
        found, val = MasterPolicyMapper.first_rule(rules, MasterPolicyMapper._AUDIT_RETENTION_RULES)
        if found and val not in (None, 0, False):
            unmapped.append({
                "category": "Master Policy",
                "item": f"Audit retention = {val} days",
                "action": "Configure audit retention at the vault level in the "
                          "Keeper Admin Console (Reporting & Alerts).",
            })

        # ── Other policies with no Keeper equivalent ────────────
        unmapped_aliases = (
            (MasterPolicyMapper._DUAL_CONTROL_RULES, "Dual control approval",
             "Use ticketing integration (ServiceNow/Jira) for approval workflows"),
            (MasterPolicyMapper._EXCLUSIVE_RULES, "Exclusive checkout",
             "Use time-limited record sharing in KeeperPAM"),
            (MasterPolicyMapper._ONE_TIME_RULES, "One-time password access",
             "Enable post-use rotation in KeeperPAM rotation settings"),
            (("MultiLevelApproval", "multiLevelApproval"), "Multi-level approval",
             "Configure approval chains via Keeper SSO/Compliance Reporting"),
            (("OnlyManagersApproval", "onlyManagersApproval"), "Manager-only approval",
             "Enforce manager approval through Keeper team membership policies"),
            (("RequireReason", "requireReason"), "Require reason on access",
             "Reason-on-access is per-record in Keeper; enable on shared folders "
             "as needed"),
            (("AllowFreeText", "allowFreeText"), "Allow free-text reason",
             "Keeper accepts free-text reasons by default for audit comments"),
            (("AllowViewPassword", "allowViewPassword"), "Allow view password",
             "Password visibility is governed by Keeper sharing/role policies"),
        )
        for aliases, label, action in unmapped_aliases:
            found, val = MasterPolicyMapper.first_rule(rules, aliases)
            if found and bool(val):
                unmapped.append({
                    "category": "Master Policy",
                    "item": f"{label} = Active",
                    "action": action,
                })

        # Confirmers count — only meaningful when > 0
        confirmers_raw = rules.get("ConfirmersNumber") or rules.get("confirmersNumber")
        if confirmers_raw:
            try:
                n = int(confirmers_raw)
            except (TypeError, ValueError):
                n = 0
            if n > 0:
                unmapped.append({
                    "category": "Master Policy",
                    "item": f"ConfirmersNumber = {n}",
                    "action": "Configure approval workflow with the matching "
                              "number of approvers in Keeper Admin Console.",
                })

        return config, unmapped
