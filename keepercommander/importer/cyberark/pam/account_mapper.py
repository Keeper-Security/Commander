#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import copy
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from .client import CyberArkPVWAClient
from .constants import DEFAULT_PLATFORM_MAP, FALLBACK_PLATFORM_MAP
from .master_policy_mapper import MasterPolicyMapper
from .platform_mapping import (
    _CATEGORY_PREFIX_RE,
    _SYSTEM_TYPE_MAP,
    _extract_port,
    _guess_platform_mapping,
    _port_from_platform_details,
    _split_host_port,
)
from .policy_rules import (
    PLATFORM_DUAL_CONTROL_KEYS,
    PLATFORM_EXCLUSIVE_KEYS,
    PLATFORM_MONITOR_KEYS,
    PLATFORM_ONETIME_KEYS,
    PLATFORM_RECORD_KEYS,
    flatten_asmx_grid,
    truthy,
)


class AccountMapper:
    """Maps CyberArk accounts to KeeperPAM record dicts matching pam project import JSON schema."""

    def __init__(self, platform_map_override: Optional[dict] = None,
                 platforms: Optional[List[dict]] = None,
                 client: Optional['CyberArkPVWAClient'] = None,
                 default_rotation_schedule: Optional[dict] = None):
        self.platform_map = copy.deepcopy(DEFAULT_PLATFORM_MAP)
        if platform_map_override:
            self.platform_map.update(platform_map_override)
        self.unmapped_platforms = {}  # platformId → count
        # Schedule applied to each imported user's rotation_settings so the
        # CyberArk Master Policy "Require password change every X days" rule
        # is honored at the per-record level (the project-level
        # default_rotation_schedule alone does not affect already-imported
        # users — Keeper PAM rotation reads the per-record schedule first).
        self._default_rotation_schedule: dict = {"type": "on-demand"}
        if isinstance(default_rotation_schedule, dict) and default_rotation_schedule:
            self._default_rotation_schedule = default_rotation_schedule
        # PlatformID → {"base_id": ..., "system_type": ...} from PVWA /Platforms
        self._platform_index: Dict[str, dict] = {}
        if platforms:
            for p in platforms:
                if not isinstance(p, dict):
                    continue
                pid = str(p.get("PlatformID") or p.get("PlatformId") or "").strip()
                if not pid:
                    continue
                self._platform_index[pid] = {
                    "base_id": str(p.get("PlatformBaseID") or p.get("PlatformBaseId") or "").strip(),
                    "system_type": str(p.get("SystemType") or "").strip(),
                    "platform_name": str(p.get("PlatformName") or "").strip(),
                }
        # Used (optionally) to fetch per-platform Details for port discovery.
        self._client = client
        self._details_cache: Dict[str, Optional[dict]] = {}
        # Cache of per-platform rotation policies translated to Keeper
        # ``schedule`` dicts. Maps platformId → resolved schedule (or
        # ``None`` once we've decided the platform inherits the master
        # policy default). One CyberArk API call per unique platformId.
        self._platform_schedule_cache: Dict[str, Optional[dict]] = {}
        # Diagnostic counter — how many accounts received a platform-level
        # schedule vs. inherited the master default. Surfaced in the
        # cyberark_import.py orchestrator output so operators can verify
        # the override was applied.
        self.platform_schedule_overrides: Dict[str, int] = {}
        # Per-platform session-recording overrides. Maps platformId →
        # ("on"|"off"|None) for graphical session recording. ``None``
        # means we couldn't determine the policy — caller falls back to
        # whatever the master policy / Keeper default dictates. Only one
        # API call per unique platformId thanks to caching.
        self._platform_session_cache: Dict[str, Optional[Tuple[str, str]]] = {}
        self.platform_recording_overrides: Dict[str, int] = {}
        # Per-platform privileged-access workflow overrides (dual control,
        # exclusive checkout, one-time password). These have no direct
        # Keeper PAM toggle, so they roll up into the unmapped-items list
        # exposed via ``platform_workflow_unmapped`` for the report.
        self._platform_workflows_cache: Dict[str, Optional[dict]] = {}
        self.platform_workflow_unmapped: List[dict] = []
        self._platform_workflows_seen: set = set()
        # Per-platform operational metadata extracted from the rotation
        # policy: rotationNoticePeriod, headstartInterval, maxRetries,
        # minDelayBetweenRetries, etc. Cached and applied as custom fields
        # on every Keeper PAM resource record from the same platform so
        # the source-system context is preserved post-migration.
        self._platform_metadata_cache: Dict[str, List[dict]] = {}
        # Per-platform CyberArk passwordGenRules → Keeper
        # ``rotation_settings.password_complexity`` translation cache.
        # Populated lazily on first hit of each platformId.
        self._platform_complexity_cache: Dict[str, Optional[str]] = {}
        self.platform_complexity_overrides: Dict[str, int] = {}

    # CyberArk per-platform rotation-policy field aliases. The endpoint at
    # /api/platforms/{platformId}/rotation-policy/ documents settings under
    # different names depending on the tenant version; we accept every
    # reasonable spelling and treat the first match as authoritative.
    _PLATFORM_ROTATE_DAYS_KEYS = (
        "rotateEveryXDays", "rotationDays", "passwordChangeDays",
        "PasswordChangeDays", "requirePasswordChangeEveryXDays",
        "RequirePasswordChangeEveryXDays",
    )
    _PLATFORM_ROTATE_AUTO_KEYS = (
        "rotateAutomatically", "performPeriodicChange",
        "PerformPeriodicChange", "rotatePasswordsAutomatically",
    )

    @staticmethod
    def _flatten_rotation_policy(data: dict) -> Dict[str, Any]:
        """Flatten the platform rotation-policy payload to a single dict.

        CyberArk has been observed to return the policy in two shapes:

          - flat: ``{"rotateEveryXDays": 30, "rotateAutomatically": true}``
          - grouped: ``{"credentialsManagement": {"rotateEveryXDays": 30,
            ...}, "rotationPolicy": {...}}``

        The grouped shape mirrors ``Get-Platforms``. We look one level deep
        so leaf settings end up in a single key/value table the resolver
        below can search with the ``_PLATFORM_*_KEYS`` aliases.
        """
        flat: Dict[str, Any] = {}
        if not isinstance(data, dict):
            return flat
        for k, v in data.items():
            if isinstance(v, dict):
                # CyberArk Self-Hosted /Policies/N format keeps {"Value": x}
                if "Value" in v and len(v) == 1:
                    flat.setdefault(k, v["Value"])
                    continue
                for subk, subv in v.items():
                    if isinstance(subv, dict) and "Value" in subv:
                        flat.setdefault(subk, subv["Value"])
                    elif isinstance(subv, (bool, int, float, str)):
                        flat.setdefault(subk, subv)
            elif isinstance(v, (bool, int, float, str)):
                flat.setdefault(k, v)
        return flat

    def _resolve_platform_schedule(self, platform_id: str) -> Optional[dict]:
        """Return Keeper ``schedule`` dict for ``platform_id`` (cached).

        Calls ``/api/platforms/{platformId}/rotation-policy/`` once per
        platform and translates the response into a Quartz CRON via
        ``MasterPolicyMapper.days_to_cron``. Returns ``None`` when the
        platform has no custom policy — callers fall back to the master
        policy default schedule.

        Honors CyberArk's three-state cascade:

          1. **Per-platform with override** — when the response carries a
             ``change`` group with ``overridesMasterPolicy=true``, we use
             ``change.interval`` and ``change.allowedPeriodic`` directly.
          2. **Per-platform without override** — ``overridesMasterPolicy``
             is explicitly false (the common Metron case where every
             platform inherits master) → return ``None`` so the caller
             falls back to the master policy default.
          3. **Legacy flat shapes** — older PVWA Self-Hosted responses
             that flatten the rotation interval at top level
             (``rotateEveryXDays`` / ``passwordChangeDays``) are still
             supported via the alias tables.

        ``allowedPeriodic=False`` (or its aliases) forces the schedule to
        ``on-demand`` regardless of the day count, because the platform
        explicitly opts out of periodic rotation.
        """
        if not platform_id or not self._client:
            return None
        if platform_id in self._platform_schedule_cache:
            return self._platform_schedule_cache[platform_id]

        raw = self._client.fetch_platform_rotation_policy(platform_id)
        if not raw:
            self._platform_schedule_cache[platform_id] = None
            return None

        # ── New ISPSS shape ────────────────────────────────────
        change = raw.get("change") if isinstance(raw.get("change"), dict) else None
        if change is not None:
            overrides = change.get("overridesMasterPolicy")
            if overrides is False:
                # Platform explicitly inherits master policy — let the
                # master rotation cadence drive the user's schedule.
                logging.debug(
                    "Platform '%s' rotation policy: overridesMasterPolicy=false "
                    "(inheriting master policy)", platform_id,
                )
                self._platform_schedule_cache[platform_id] = None
                return None

            try:
                days = int(change.get("interval") or 0)
            except (TypeError, ValueError):
                days = 0
            allowed_periodic = change.get("allowedPeriodic")
            if allowed_periodic is False:
                schedule: Optional[dict] = {"type": "on-demand"}
            else:
                cron = MasterPolicyMapper.days_to_cron(days)
                schedule = {"type": "CRON", "cron": cron} if cron else None

            self._platform_schedule_cache[platform_id] = schedule
            if schedule:
                logging.debug(
                    "Platform '%s' rotation policy override: every %d day(s) -> %s",
                    platform_id, days, schedule,
                )
            return schedule

        # ── Legacy flat shapes (PVWA Self-Hosted, Get-Platforms) ───
        flat = self._flatten_rotation_policy(raw)
        days = 0
        for key in self._PLATFORM_ROTATE_DAYS_KEYS:
            if key in flat:
                try:
                    days = int(flat[key] or 0)
                except (TypeError, ValueError):
                    days = 0
                break

        auto_rotate: Optional[bool] = None
        for key in self._PLATFORM_ROTATE_AUTO_KEYS:
            if key in flat:
                auto_rotate = bool(flat[key])
                break

        if auto_rotate is False:
            schedule = {"type": "on-demand"}
        else:
            cron = MasterPolicyMapper.days_to_cron(days)
            schedule = {"type": "CRON", "cron": cron} if cron else None

        self._platform_schedule_cache[platform_id] = schedule
        if schedule:
            logging.debug(
                "Platform '%s' rotation policy: every %d day(s) -> %s",
                platform_id, days, schedule,
            )
        return schedule

    def _resolve_platform_password_complexity(self, platform_id: str) -> Optional[str]:
        """Translate ``passwordGenRules`` into Keeper's password_complexity.

        CyberArk's ``/api/platforms/{id}/secrets-policy/`` endpoint exposes
        password generation under a ``passwordGenRules`` block, e.g.::

            {
              "passwordGenRules": {
                "passwordLen": 12, "minUppercase": 2, "minLowercase": 2,
                "minDigit": 1,    "minSpecial": 1
              },
              ...
            }

        Keeper PAM's ``rotation_settings.password_complexity`` accepts a
        comma-separated string ``"length,upper,lower,digits,symbols"``
        (matching the format generated by the legacy import path). We
        cache the result per-platform so subsequent accounts under the
        same platform reuse it without another API call.

        Returns ``None`` when:
          - ``passwordGenRules`` is absent / not a dict, or
          - ``passwordLen`` is missing / non-positive (Keeper requires a
            length to honor the complexity string).
        """
        if not platform_id or not self._client:
            return None
        if platform_id in self._platform_complexity_cache:
            return self._platform_complexity_cache[platform_id]

        raw = self._client.fetch_platform_secrets_policy(platform_id)
        if not isinstance(raw, dict):
            self._platform_complexity_cache[platform_id] = None
            return None

        rules = raw.get("passwordGenRules")
        if not isinstance(rules, dict):
            self._platform_complexity_cache[platform_id] = None
            return None

        try:
            length = int(rules.get("passwordLen") or 0)
            upper = int(rules.get("minUppercase") or 0)
            lower = int(rules.get("minLowercase") or 0)
            digits = int(rules.get("minDigit") or 0)
            symbols = int(rules.get("minSpecial") or 0)
        except (TypeError, ValueError):
            self._platform_complexity_cache[platform_id] = None
            return None

        if length <= 0:
            self._platform_complexity_cache[platform_id] = None
            return None

        complexity = f"{length},{upper},{lower},{digits},{symbols}"
        self._platform_complexity_cache[platform_id] = complexity
        logging.debug("Platform '%s' password complexity: %s", platform_id, complexity)
        return complexity

    def _resolve_platform_metadata(self, platform_id: str) -> List[dict]:
        """Return CyberArk operational metadata as Keeper custom fields.

        Translates fields like ``rotationNoticePeriod``,
        ``headstartInterval``, ``maxRetries`` from the
        ``/api/platforms/{id}/rotation-policy/`` and
        ``/api/platforms/{id}/workflows-policy/`` responses into the
        ``custom = [{type, label, value}, ...]`` list shape that Keeper
        PAM resource records support. Returns ``[]`` when the platform
        has no usable metadata. Each entry is ready to ``extend()`` onto
        ``resource["custom"]`` in ``map_account``.

        Cached per platformId so we only compute the field list once.
        """
        if not platform_id or not self._client:
            return []
        if platform_id in self._platform_metadata_cache:
            return self._platform_metadata_cache[platform_id]

        out: List[dict] = []
        rotation_raw = self._client.fetch_platform_rotation_policy(platform_id)
        if isinstance(rotation_raw, dict):
            change = rotation_raw.get("change") if isinstance(rotation_raw.get("change"), dict) else {}
            verify = rotation_raw.get("verify") if isinstance(rotation_raw.get("verify"), dict) else {}

            def _add(label: str, val):
                if val in (None, "", [], {}):
                    return
                out.append({
                    "type": "text", "label": label, "value": [str(val)],
                })

            # Rotation cadence operational settings — preserved on the
            # Keeper record so a user can reproduce them in CyberArk.
            _add("CyberArk Rotation Interval (days)", change.get("interval"))
            if change.get("allowedPeriodic") is not None:
                _add("CyberArk Rotation Allowed Periodic",
                     "Yes" if change.get("allowedPeriodic") else "No")
            _add("CyberArk Rotation Headstart (days)", change.get("headstartInterval"))
            _add("CyberArk Rotation Notice Period (min)",
                 rotation_raw.get("rotationNoticePeriod"))
            if rotation_raw.get("enableRotationNoticePeriod") is not None:
                _add("CyberArk Rotation Notice Enabled",
                     "Yes" if rotation_raw.get("enableRotationNoticePeriod") else "No")
            _add("CyberArk Rotation Max Retries", rotation_raw.get("maxRetries"))
            _add("CyberArk Rotation Retry Delay (min)",
                 rotation_raw.get("minDelayBetweenRetries"))
            _add("CyberArk Verify Interval (days)", verify.get("interval"))
            if verify.get("allowedPeriodic") is not None:
                _add("CyberArk Verify Allowed Periodic",
                     "Yes" if verify.get("allowedPeriodic") else "No")
            if rotation_raw.get("timezone"):
                _add("CyberArk Rotation Timezone", rotation_raw.get("timezone"))
            if rotation_raw.get("origin"):
                _add("CyberArk Platform Origin", rotation_raw.get("origin"))

        # Workflows policy carries minimum-validity-period style settings.
        wf_raw = self._client.fetch_platform_workflows_policy(platform_id)
        if isinstance(wf_raw, dict):
            if "minValidityPeriod" in wf_raw and wf_raw.get("minValidityPeriod") not in (None, ""):
                out.append({
                    "type": "text",
                    "label": "CyberArk Min Validity Period (min)",
                    "value": [str(wf_raw.get("minValidityPeriod"))],
                })
            if wf_raw.get("unlockIfFail") is not None:
                out.append({
                    "type": "text",
                    "label": "CyberArk Unlock If Fail",
                    "value": ["Yes" if wf_raw.get("unlockIfFail") else "No"],
                })

        self._platform_metadata_cache[platform_id] = out
        if out:
            logging.debug("Platform '%s' metadata captured: %d custom field(s)",
                          platform_id, len(out))
        return out

    def _resolve_platform_session_recording(
            self, platform_id: str) -> Optional[Tuple[str, str]]:
        """Return ``("on"|"off", "on"|"off")`` for (graphical, text) recording.

        Probes the per-platform endpoints in order (secrets-policy →
        platform details → legacy .asmx). When the platform exposes a
        ``recordAndSaveSessionActivity`` rule we honor it; that single
        boolean drives both Keeper recording flags because CyberArk does
        not split graphical vs. text. Returns ``None`` when no endpoint
        answered with usable data — the resource then inherits whatever
        the master policy / Keeper default decides.
        """
        if not platform_id or not self._client:
            return None
        if platform_id in self._platform_session_cache:
            return self._platform_session_cache[platform_id]

        # Session-recording flags can live in any of three CyberArk
        # surfaces depending on tenant type — none of them is a single
        # source of truth, so we query and merge:
        #
        #   1. ``/PasswordVault/API/Platforms/{id}`` — Get-Platform-Details.
        #      On older PVWA Self-Hosted this carries the
        #      ``sessionManagement.recordAndSaveSessionActivity`` boolean.
        #      On Privilege Cloud / ISPSS this DOES NOT include the
        #      session-recording flag (only the PSMServer reference and
        #      connection components), but we still pull
        #      ``PSMServerId``/``PSMServerName`` from here as a fallback
        #      indicator (PSM-attached platforms record by default).
        #   2. ``/PasswordVault/services/PoliciesMgt.asmx/
        #      GetPolicyRulesSessionMonitoring`` — the PVWA admin-UI grid
        #      service. On Privilege Cloud this is the *canonical* place
        #      where ``RecordSession`` / ``MonitorSession`` rules are
        #      surfaced (the user explicitly pointed us here).
        #   3. PSMServer presence — heuristic fallback when neither (1)
        #      nor (2) has the explicit flag: a platform that has a PSM
        #      ConnectionComponent (``PSM-RDP``, ``PSM-SSH``, ...)
        #      records sessions by default in CyberArk.
        if platform_id not in self._details_cache:
            self._details_cache[platform_id] = self._client.fetch_platform_details(platform_id)
        details = self._details_cache.get(platform_id)
        asmx = None
        if hasattr(self._client, 'fetch_platform_session_monitoring'):
            asmx = self._client.fetch_platform_session_monitoring(platform_id)

        if not details and not asmx:
            self._platform_session_cache[platform_id] = None
            return None

        # ── Build a flat ``rules`` dict from every envelope we got ────
        rules: Dict[str, Any] = {}
        for raw in (details, asmx):
            if not isinstance(raw, dict) or not raw:
                continue
            rules.update(MasterPolicyMapper.normalize(raw))
            rules.update(flatten_asmx_grid(raw))

            # Walk every known PVWA / Privilege Cloud envelope shape and
            # all of its nested groups (sessionManagement,
            # credentialsManagement, privilegedAccessWorkflows, ...).
            envelopes: List[dict] = []
            for key in ("Platforms", "Platform", "Details"):
                val = raw.get(key)
                if isinstance(val, list) and val and isinstance(val[0], dict):
                    envelopes.append(val[0])
                elif isinstance(val, dict):
                    envelopes.append(val)
            envelopes.append(raw)  # top-level fallback

            for envelope in envelopes:
                if not isinstance(envelope, dict):
                    continue
                for grp in envelope.values():
                    if isinstance(grp, dict):
                        for k, v in grp.items():
                            if isinstance(v, (bool, int, float, str)):
                                rules.setdefault(k, v)
                        # Two-level walk for connection components and
                        # other deeply nested PVWA groups (e.g.
                        # ``Properties.Required[]``).
                        for nested in grp.values():
                            if isinstance(nested, dict):
                                for k, v in nested.items():
                                    if isinstance(v, (bool, int, float, str)):
                                        rules.setdefault(k, v)

        record_val: Optional[bool] = None
        # 1) Explicit RecordSession / RecordAndSaveSessionActivity.
        for k in PLATFORM_RECORD_KEYS:
            if k in rules:
                record_val = truthy(rules[k])
                break
        # 2) PSM monitoring + isolation implies recording.
        if record_val is None:
            for k in PLATFORM_MONITOR_KEYS:
                if k in rules and truthy(rules[k]):
                    record_val = True
                    break
        # 3) Heuristic: PSMServer reference present → PSM is engaged
        #    and CyberArk records by default. Used only when neither
        #    (1) nor (2) provided an answer.
        if record_val is None:
            for k in ("PSMServerId", "PSMServerID", "psmServerId",
                      "PSMServerName", "psmServerName"):
                v = rules.get(k)
                if isinstance(v, str) and v.strip():
                    logging.debug(
                        "Platform '%s' has PSMServer=%s — assuming "
                        "session recording is on (PSM default)",
                        platform_id, v,
                    )
                    record_val = True
                    break

        if record_val is None:
            self._platform_session_cache[platform_id] = None
            return None

        flag = "on" if record_val else "off"
        result = (flag, flag)
        self._platform_session_cache[platform_id] = result
        logging.debug(
            "Platform '%s' session recording: graphical=%s text=%s",
            platform_id, flag, flag,
        )
        return result

    def _resolve_platform_workflows(self, platform_id: str) -> Optional[dict]:
        """Return the platform's privileged-access workflows policy.

        Caches the response per-platform and emits one unmapped-item entry
        for each *active* workflow rule (dual control, exclusive checkout,
        one-time password access) the *first* time we see it on a given
        platform. The accumulated list is exposed via
        ``self.platform_workflow_unmapped`` for the import report.
        """
        if not platform_id or not self._client:
            return None
        if platform_id in self._platform_workflows_cache:
            return self._platform_workflows_cache[platform_id]

        # ISPSS workflows-policy endpoint (when present) carries
        # minValidityPeriod / unlockIfFail style settings, but the actual
        # dual-control / exclusive-checkout / one-time-password rules live
        # in the platform's ``privilegedAccessWorkflows`` group on the
        # generic ``/PasswordVault/API/Platforms/{id}`` endpoint. We query
        # both and merge so we don't miss either source.
        rules: Dict[str, Any] = {}
        wf_raw = self._client.fetch_platform_workflows_policy(platform_id)
        if isinstance(wf_raw, dict) and wf_raw:
            rules.update(MasterPolicyMapper.normalize(wf_raw))

        # Reuse the shared details_cache populated by port discovery /
        # session-recording resolver so we issue at most one Platforms/{id}
        # call per platform across the whole import.
        if platform_id not in self._details_cache:
            self._details_cache[platform_id] = self._client.fetch_platform_details(platform_id)
        details_raw = self._details_cache.get(platform_id)
        if isinstance(details_raw, dict) and details_raw:
            for envelope_key in ("Platforms", "Platform", "Details"):
                env = details_raw.get(envelope_key)
                if isinstance(env, list) and env and isinstance(env[0], dict):
                    env = env[0]
                if isinstance(env, dict):
                    for grp in env.values():
                        if isinstance(grp, dict):
                            for k, v in grp.items():
                                if isinstance(v, (bool, int, float, str)):
                                    rules.setdefault(k, v)
            for grp in details_raw.values():
                if isinstance(grp, dict):
                    for k, v in grp.items():
                        if isinstance(v, (bool, int, float, str)):
                            rules.setdefault(k, v)

        if not rules:
            self._platform_workflows_cache[platform_id] = None
            return None

        # Translate first time we see each platform; later accounts on the
        # same platform reuse the cache without re-emitting unmapped items.
        if platform_id not in self._platform_workflows_seen:
            self._platform_workflows_seen.add(platform_id)
            for keys, label, action in (
                (PLATFORM_DUAL_CONTROL_KEYS,
                 "Dual control approval",
                 "Use ticketing integration (ServiceNow/Jira) or Keeper "
                 "Compliance approval workflows"),
                (PLATFORM_EXCLUSIVE_KEYS,
                 "Exclusive checkout",
                 "Use time-limited record sharing in KeeperPAM"),
                (PLATFORM_ONETIME_KEYS,
                 "One-time password access",
                 "Enable post-use rotation in KeeperPAM rotation settings"),
            ):
                for k in keys:
                    if k in rules and truthy(rules[k]):
                        self.platform_workflow_unmapped.append({
                            "category": "Platform workflow",
                            "item": f"{label} (platform: {platform_id})",
                            "action": action,
                        })
                        break

        self._platform_workflows_cache[platform_id] = rules
        return rules

    def _resolve_from_platform_metadata(self, platform_id: str) -> Optional[dict]:
        """Map a custom platformId via PVWA's PlatformBaseID / SystemType.

        Order:
          1. PlatformBaseID matches a built-in (e.g. WinDomain) — use that mapping.
          2. SystemType matches our SYSTEM_TYPE_MAP (e.g. Windows → RDP).
          3. None — caller falls through to keyword guessing.
        """
        meta = self._platform_index.get(platform_id)
        if not meta:
            return None
        base = meta.get("base_id")
        if base and base in DEFAULT_PLATFORM_MAP:
            return dict(DEFAULT_PLATFORM_MAP[base])
        system_type = (meta.get("system_type") or "").lower()
        if system_type:
            for key, mapping in _SYSTEM_TYPE_MAP.items():
                if key in system_type:
                    return dict(mapping)
        return None

    @staticmethod
    def _infer_operating_system(platform_id: str,
                                protocol: Optional[str]) -> Optional[str]:
        """Derive the ``operating_system`` field for a pamMachine record.

        CyberArk's PVWA does not expose a clean OS attribute on accounts —
        the closest signal is ``platformId``. We use a keyword scan on the
        platform name ("Win"/"Windows" → windows, "Unix"/"Linux"/"AIX"/
        "Solaris" → linux) and fall back to the protocol mapping (rdp ⇒
        windows, ssh ⇒ linux) so custom platforms like
        ``METRON-WindowsDomainAccount`` still resolve correctly. Returns
        ``None`` for ambiguous platforms (network gear, generic database
        platforms) — the caller leaves the field unset rather than guessing.
        """
        pid = (platform_id or "").lower()
        if pid:
            if "win" in pid:
                return "windows"
            if any(tok in pid for tok in ("unix", "linux", "aix", "solaris",
                                          "ubuntu", "redhat", "rhel",
                                          "centos", "debian", "macos")):
                return "linux"
        proto = (protocol or "").lower()
        if proto == "rdp":
            return "windows"
        if proto == "ssh":
            # Network appliances also use SSH; only commit when the platform
            # is unrecognized but clearly a host (not a database platform).
            if pid and any(tok in pid for tok in ("network", "cisco",
                                                  "juniper", "paloalto",
                                                  "f5", "checkpoint",
                                                  "fortinet", "arista")):
                return None
            return "linux" if pid else None
        return None

    def _enrich_port_from_details(self, platform_id: str, mapping: dict) -> dict:
        """Overlay the platform's own default Port (from /Platforms/{id}) onto
        a mapping dict, when available. Cached to avoid re-fetching."""
        if not platform_id or not self._client:
            return mapping
        if platform_id not in self._details_cache:
            self._details_cache[platform_id] = self._client.fetch_platform_details(platform_id)
        details = self._details_cache.get(platform_id)
        if details:
            port = _port_from_platform_details(details)
            if port:
                mapping = dict(mapping)
                mapping["port"] = port
        return mapping

    def map_account(self, account: dict, password: Optional[str] = None,
                    safe_name: str = "") -> Optional[dict]:
        """Convert a CyberArk account dict → pam_data record dict.

        Returns None if the platformId is completely unknown and has no default.
        """
        platform_id = account.get("platformId", "")
        mapping = self.platform_map.get(platform_id) if platform_id else None
        mapping_source = "platform-map" if mapping else None

        if mapping is None:
            # Resolution order for unknown / customer-renamed platforms:
            #   1. PVWA platform metadata — PlatformBaseID → DEFAULT_PLATFORM_MAP,
            #      or SystemType → _SYSTEM_TYPE_MAP. Authoritative.
            #   2. Substring keyword match on platformId / name.
            #   3. pamMachine/SSH fallback.
            label = platform_id if platform_id else "(empty)"
            self.unmapped_platforms[label] = self.unmapped_platforms.get(label, 0) + 1

            via_pvwa = self._resolve_from_platform_metadata(platform_id) if platform_id else None
            if via_pvwa:
                mapping = via_pvwa
                mapping_source = "pvwa-platform"
                logging.warning(
                    "Unknown platformId '%s' for account '%s' — resolved via PVWA "
                    "platform metadata to %s/%s (port %s). Add it to --platform-map "
                    "to lock in.",
                    platform_id, account.get("name", ""),
                    mapping.get("record_type"), mapping.get("protocol") or "n/a",
                    mapping.get("port") or "n/a",
                )
            else:
                guessed = _guess_platform_mapping(platform_id, account.get("name", ""))
                if guessed:
                    mapping = guessed
                    mapping_source = "keyword-guess"
                    if platform_id:
                        logging.warning(
                            "Unknown platformId '%s' for account '%s' — pattern-matched "
                            "to %s/%s (port %s). Add it to --platform-map to lock in.",
                            platform_id, account.get("name", ""),
                            mapping.get("record_type"), mapping.get("protocol") or "n/a",
                            mapping.get("port") or "n/a",
                        )
                    else:
                        logging.debug(
                            "Empty platformId for account '%s' — pattern-matched to %s/%s.",
                            account.get("name", ""),
                            mapping.get("record_type"), mapping.get("protocol") or "n/a",
                        )
                else:
                    mapping = dict(FALLBACK_PLATFORM_MAP)
                    mapping_source = "fallback-ssh"
                    if platform_id:
                        logging.warning(
                            "Unknown platformId '%s' for account '%s' — defaulting to "
                            "pamMachine/SSH. Use --platform-map to override.",
                            platform_id, account.get("name", ""))
                    else:
                        logging.debug("Empty platformId for account '%s' — defaulting to pamMachine/SSH.",
                                      account.get("name", ""))

            # When the mapping came from a fallback path we trust PVWA's
            # per-platform Details endpoint over our static defaults for the
            # port. Cheap with caching — one call per unique custom platform.
            if mapping_source in ("pvwa-platform", "keyword-guess", "fallback-ssh"):
                mapping = self._enrich_port_from_details(platform_id, mapping)

        record_type = mapping.get("record_type", "pamMachine")
        props = account.get("platformAccountProperties", {}) or {}

        # Extract fields
        address = account.get("address", "")
        user_name = account.get("userName", "")
        # CyberArk occasionally stores "host:port" in `address`. Split so the
        # host field stays clean; _extract_port() picks up the embedded port if
        # platformAccountProperties has no explicit one.
        address_host, _addr_port = _split_host_port(address)
        if _addr_port:
            address = address_host

        # Build title: strip CyberArk category and platform prefixes; when the
        # resulting name is still long (e.g. the CPM policy name is embedded
        # rather than the platformId), fall back to {address}-{userName}.
        raw_name = account.get("name", "")
        stripped = _CATEGORY_PREFIX_RE.sub("", raw_name)
        if platform_id:
            stripped = re.sub(rf"^.*{re.escape(platform_id)}[\-_ ]", "", stripped)
        if len(stripped) > 40 and address and user_name:
            title = f"{address}-{user_name}"
        else:
            title = stripped
        logon_domain = props.get("LogonDomain", "")
        login = f"{logon_domain}\\{user_name}" if logon_domain and user_name else user_name
        url = props.get("URL", "")
        item_name = props.get("ItemName", "")
        port, port_source = _extract_port(
            props, account.get("address", ""), mapping.get("port", "") or "",
        )
        logging.debug(
            "CyberArk account '%s' (platformId=%s) port=%s (source=%s)",
            account.get("name", "?"), platform_id or "?", port or "(empty)", port_source,
        )

        if record_type == "login":
            # BusinessWebsite → login record (not pamMachine)
            record = {
                "type": "login",
                "title": item_name or title,
                "login": login,
                "password": password or "",
            }
            if url:
                record["url"] = url
            return record

        if record_type in ("pamMachine", "pamDatabase"):
            secret_type_check = account.get("secretType", "password").lower()
            # No target host and no SSH key material → route to login. A
            # pamMachine without a host can never be reached by the gateway,
            # so the credential is more useful as a standalone login record.
            # SSH keys keep pamMachine semantics even without an address so
            # the private_pem_key field is preserved.
            if not address and secret_type_check != "key":
                note = (f"CyberArk platform: {platform_id}\n"
                        "No address — imported as login (not pamMachine)"
                        if platform_id else
                        "CyberArk account had no address — imported as login")
                return {
                    "type": "login",
                    "title": title or raw_name,
                    "login": login,
                    "password": password or "",
                    "notes": note,
                }
            # Build pamUser nested inside the resource
            user_record = {
                "type": "pamUser",
                "title": f"{login}@{title}" if login else f"user@{title}",
                "login": login,
                "password": password or "",
            }
            # SSH key detection: check platform name OR secretType field from API
            # (ark-sdk-python uses secretType: "key" for any platform with SSH keys)
            platform_id = account.get("platformId", "")
            secret_type = account.get("secretType", "password").lower()
            is_ssh_key = (platform_id in ("UnixSSHKey", "UnixSSHKeys")
                          or secret_type == "key")
            if is_ssh_key and password:
                # CyberArk exports SSH keys with \r\r\n line endings (a PVWA
                # artifact); normalize to \n so OpenSSH libraries accept the PEM.
                user_record["private_pem_key"] = password.replace("\r\r\n", "\n")
                user_record["password"] = ""
            # Map Database property for database platforms (MSSql, MySQL, Oracle, PostgreSQL)
            database_name = props.get("Database", "")
            if database_name and record_type == "pamDatabase":
                user_record["connect_database"] = database_name
            # Map DistinguishedName for Active Directory accounts
            dn = props.get("DistinguishedName", "") or props.get("distinguishedName", "")
            if dn:
                user_record["distinguished_name"] = dn
            # Rotation settings — derive from CyberArk secretManagement state
            secret_mgmt = account.get("secretManagement", {})
            cpm_enabled = secret_mgmt.get("automaticManagementEnabled", True)
            if mapping.get("rotation"):
                # Resolve the per-user schedule with this priority:
                #   1. Platform-level rotation-policy (CyberArk:
                #      /api/platforms/{platformId}/rotation-policy/) —
                #      overrides the master policy for accounts on that
                #      platform.
                #   2. Master Policy default
                #      (passwordChangeDays / PasswordChangeDays).
                #   3. on-demand fallback when neither is present.
                #
                # If CyberArk has CPM auto-management disabled on the
                # account itself we always fall back to on-demand so we
                # don't schedule rotations against credentials the admin
                # explicitly opted out of.
                platform_id_for_sched = account.get("platformId", "")
                if cpm_enabled:
                    platform_sched = self._resolve_platform_schedule(
                        platform_id_for_sched)
                    if platform_sched:
                        schedule = copy.deepcopy(platform_sched)
                        self.platform_schedule_overrides[platform_id_for_sched] = (
                            self.platform_schedule_overrides.get(
                                platform_id_for_sched, 0) + 1
                        )
                    else:
                        schedule = copy.deepcopy(self._default_rotation_schedule)
                else:
                    schedule = {"type": "on-demand"}
                user_record["rotation_settings"] = {
                    "rotation": mapping["rotation"],
                    "enabled": "on" if cpm_enabled else "off",
                    "schedule": schedule,
                }
                # Pull CyberArk's per-platform passwordGenRules into the
                # Keeper rotation settings so a rotated password meets the
                # same complexity requirements the source system enforced.
                complexity = self._resolve_platform_password_complexity(
                    platform_id_for_sched)
                if complexity:
                    user_record["rotation_settings"]["password_complexity"] = complexity
                    self.platform_complexity_overrides[platform_id_for_sched] = (
                        self.platform_complexity_overrides.get(
                            platform_id_for_sched, 0) + 1
                    )
                reason = secret_mgmt.get("manualManagementReason", "")
                if not cpm_enabled:
                    existing = user_record.get("notes", "")
                    line = f"CyberArk CPM disabled: {reason}"
                    user_record["notes"] = f"{existing}\n{line}".strip()
                cpm_status = secret_mgmt.get("status", "")
                if cpm_status and cpm_status.lower() == "failure":
                    existing = user_record.get("notes", "")
                    line = f"CyberArk CPM status: FAILURE ({reason})"
                    user_record["notes"] = f"{existing}\n{line}".strip()
            if password:
                user_record["managed"] = True

            resource_title = title or address or raw_name
            resource = {
                "type": record_type,
                "title": resource_title,
                "host": address,
                "port": str(port) if port else "",
                "users": [user_record],
            }
            # Map LogonDomain → domain_name on resource (Windows AD domain)
            if logon_domain and record_type == "pamMachine":
                resource["domain_name"] = logon_domain
            # Derive operating_system on pamMachine so downstream consumers
            # (notably ``pam action service add``, which only mounts on Windows
            # hosts) can dispatch on it. Inferred from platformId keywords,
            # fallback to protocol (rdp ⇒ windows, ssh ⇒ linux).
            if record_type == "pamMachine":
                inferred_os = self._infer_operating_system(
                    platform_id, mapping.get("protocol"),
                )
                if inferred_os:
                    resource["operating_system"] = inferred_os
            # Tag pamDatabase resources with database_type so Keeper renders
            # the correct DB icon/template. Mapping carries it from the
            # platform tables in constants.py / platform_mapping.py. Skipped
            # for non-DB record types and when the mapping has no entry.
            if record_type == "pamDatabase":
                db_type = mapping.get("database_type") or ""
                if db_type:
                    resource["database_type"] = db_type
            if mapping.get("protocol"):
                # Resolve per-platform overrides for session recording and
                # workflows. Both are looked up once per unique platformId
                # thanks to the caches on AccountMapper.
                platform_id_for_settings = account.get("platformId", "")
                recording = self._resolve_platform_session_recording(
                    platform_id_for_settings)
                # Trigger workflows resolution (records unmapped items in
                # self.platform_workflow_unmapped — return value not used
                # here because Keeper has no per-resource workflow toggles).
                self._resolve_platform_workflows(platform_id_for_settings)

                graphical_recording = "off"
                if recording:
                    graphical_recording = recording[0]
                    self.platform_recording_overrides[platform_id_for_settings] = (
                        self.platform_recording_overrides.get(
                            platform_id_for_settings, 0) + 1
                    )
                resource["pam_settings"] = {
                    "options": {
                        "rotation": "on" if cpm_enabled else "off",
                        "connections": "on",
                        "tunneling": "off",
                        "graphical_session_recording": graphical_recording,
                    },
                    "connection": {
                        "protocol": mapping["protocol"],
                        "port": str(port) if port else "",
                        "launch_credentials": user_record["title"],
                        # Default to self-rotation: the nested user IS the admin
                        # when CyberArk does not provide a separate reconcile /
                        # enable linked account. resolve_linked_accounts() will
                        # overwrite this when a real admin credential is found.
                        # Without it, PAMCreateRecordRotationCommand aborts with
                        # "PAM Resource ... does not have admin credentials".
                        "administrative_credentials": user_record["title"],
                    }
                }

            # Preserve CyberArk operational metadata (rotationNoticePeriod,
            # headstartInterval, maxRetries, ...) on the resource record so
            # admins can reproduce the source-system policy in Keeper. Each
            # call is cached per-platform; later accounts on the same
            # platform get the same custom-field list copied in.
            metadata_fields = self._resolve_platform_metadata(
                account.get("platformId", ""))
            if metadata_fields:
                resource.setdefault("custom", []).extend(
                    copy.deepcopy(metadata_fields))
            return resource

        logging.warning('Unsupported record_type "%s" for platform "%s" — account skipped',
                        record_type, account.get("platformId", "Unknown"))
        return None

    def is_incomplete(self, account: dict) -> Tuple[bool, str]:
        """Check if a CyberArk account is missing required fields for PAM import."""
        reasons = []
        if not account.get("address"):
            reasons.append("missing address/host")
        if not account.get("userName"):
            reasons.append("missing userName")
        if reasons:
            return True, "; ".join(reasons)
        return False, ""

