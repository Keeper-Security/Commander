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

import datetime
import getpass
import logging
from typing import NamedTuple, Optional

from ..pam.router_helper import _post_request_to_router
from ...display import bcolors
from ...params import KeeperParams
from ...proto import workflow_pb2, router_pb2
from ... import vault, utils

from .helpers import (
    ProtobufRefBuilder,
    WorkflowFormatter,
    is_workflow_exempt,
    prompt_for_reason_ticket,
    sanitize_router_error,
    start_workflow_for_record,
    submit_access_request,
)

try:
    from zoneinfo import ZoneInfo  # Python 3.9+
except ImportError:
    ZoneInfo = None

_TRANSPORT_ERROR = object()


class WorkflowGate(NamedTuple):
    """Result of the pre-launch workflow gate, consumed by pam launch / pam tunnel."""
    allowed: bool
    two_factor_value: Optional[str] = None
    flow_uid: Optional[bytes] = None
    expires_on_ms: int = 0
    started_by_launch: bool = False


class WorkflowAccessValidator:

    _DEFAULT_RESULT = {
        'allowed': True, 'require_mfa': False, 'flow_uid': None, 'expires_on_ms': 0,
        'block_reason': None, 'pending_conditions': (),
    }
    _BLOCKED_RESULT = {
        'allowed': False, 'require_mfa': False, 'flow_uid': None, 'expires_on_ms': 0,
        'block_reason': None, 'pending_conditions': (),
    }

    def __init__(self, params: KeeperParams, record_uid: str):
        self.params = params
        self.record_uid = record_uid
        self.record_uid_bytes = utils.base64_url_decode(record_uid)

        record = vault.KeeperRecord.load(params, record_uid)
        self.record_name = record.title if record else record_uid

    def validate(self, silent_actionable: bool = False) -> dict:
        if is_workflow_exempt(self.params, self.record_uid):
            return dict(self._DEFAULT_RESULT)

        config = self._read_workflow_config()
        if config is _TRANSPORT_ERROR:
            self._print_transport_error('read workflow configuration')
            return self._blocked('transport_error')
        if config is None:
            return dict(self._DEFAULT_RESULT)

        mfa_required = bool(config.parameters and config.parameters.requireMFA)

        if not self._check_allowed_times(config):
            return self._blocked('outside_time_window')

        no_approvals = config.parameters and config.parameters.approvalsNeeded == 0
        workflow = self._find_active_workflow()
        if workflow is _TRANSPORT_ERROR:
            self._print_transport_error('verify workflow access state')
            return self._blocked('transport_error')
        if workflow is None and no_approvals:
            workflow = self._get_workflow_state_by_record()
            if workflow is _TRANSPORT_ERROR:
                self._print_transport_error('verify workflow state')
                return self._blocked('transport_error')
        if workflow is None:
            if no_approvals:
                self._print_needs_start()
                return self._blocked('needs_start')
            self._print_no_workflow()
            return self._blocked('no_workflow')

        return self._evaluate_stage(workflow, mfa_required, silent_actionable)

    def _blocked(self, reason: str, **extra) -> dict:
        result = dict(self._BLOCKED_RESULT)
        result['block_reason'] = reason
        result.update(extra)
        return result

    def _read_workflow_config(self):
        ref = ProtobufRefBuilder.record_ref(self.record_uid_bytes, self.record_name)
        try:
            return _post_request_to_router(
                self.params, 'read_workflow_config',
                rq_proto=ref, rs_type=workflow_pb2.WorkflowConfig,
            )
        except Exception as e:
            logging.debug('Failed to read workflow config for %s: %s', self.record_uid, e)
            return _TRANSPORT_ERROR

    def _find_active_workflow(self):
        try:
            user_state = _post_request_to_router(
                self.params, 'get_user_access_state',
                rs_type=workflow_pb2.UserAccessState,
            )
        except Exception as e:
            logging.debug('Failed to get user access state: %s', e)
            return _TRANSPORT_ERROR

        if user_state and user_state.workflows:
            for wf in user_state.workflows:
                if wf.resource and wf.resource.value == self.record_uid_bytes:
                    return wf
        return None

    def _check_allowed_times(self, config) -> bool:
        if not config.parameters or not config.parameters.HasField('allowedTimes'):
            return True

        at = config.parameters.allowedTimes
        if not at.timeRanges and not at.allowedDays:
            return True

        tz = None
        if at.timeZone and ZoneInfo is not None:
            try:
                tz = ZoneInfo(at.timeZone)
            except Exception:
                logging.debug("Unknown timezone '%s'; falling back to local time", at.timeZone)

        now = datetime.datetime.now(tz) if tz else datetime.datetime.now().astimezone()

        # protobuf DayOfWeek: MONDAY=1..SUNDAY=7. Python weekday(): MONDAY=0..SUNDAY=6.
        if at.allowedDays:
            current_day = now.weekday() + 1
            if current_day not in at.allowedDays:
                self._print_outside_time_window(at, now)
                return False

        if at.timeRanges:
            current_minutes = now.hour * 60 + now.minute
            in_range = False
            for r in at.timeRanges:
                if r.startTime <= r.endTime:
                    if r.startTime <= current_minutes <= r.endTime:
                        in_range = True
                        break
                else:
                    # range crosses midnight (e.g. 22:00-06:00)
                    if current_minutes >= r.startTime or current_minutes <= r.endTime:
                        in_range = True
                        break
            if not in_range:
                self._print_outside_time_window(at, now)
                return False

        return True

    def _print_outside_time_window(self, at, now):
        formatted = WorkflowFormatter.format_temporal_filter(at) or {}
        print(f"\n{bcolors.WARNING}Workflow access is outside the allowed time window.{bcolors.ENDC}")
        tz_label = at.timeZone or 'local'
        print(f"Current time ({tz_label}): {now.strftime('%a %H:%M')}")
        if formatted.get('allowed_days'):
            print(f"Allowed days: {', '.join(formatted['allowed_days'])}")
        if formatted.get('time_ranges'):
            print(f"Allowed times: {', '.join(formatted['time_ranges'])}")
        if formatted.get('timezone'):
            print(f"Timezone: {formatted['timezone']}")
        print()

    def _evaluate_stage(self, workflow, mfa_required: bool,
                        silent_actionable: bool = False) -> dict:
        if not workflow.status:
            self._print_no_workflow()
            return self._blocked('no_status')

        stage = workflow.status.stage

        if stage == workflow_pb2.WS_STARTED:
            return {
                'allowed': True,
                'require_mfa': mfa_required,
                'flow_uid': bytes(workflow.flowUid) if workflow.flowUid else None,
                'expires_on_ms': int(workflow.status.expiresOn) if workflow.status.expiresOn else 0,
                'block_reason': None,
                'pending_conditions': (),
            }

        if stage == workflow_pb2.WS_READY_TO_START:
            if not silent_actionable:
                self._print_ready_to_start()
            return self._blocked(
                'ready_to_start',
                flow_uid=bytes(workflow.flowUid) if workflow.flowUid else None,
            )

        if stage == workflow_pb2.WS_WAITING:
            conditions = tuple(workflow.status.conditions) if workflow.status.conditions else ()
            cond_str = WorkflowFormatter.format_conditions(conditions) if conditions else 'approval'
            print(f"\n{bcolors.WARNING}Workflow access is pending: waiting for {cond_str}.{bcolors.ENDC}")
            if workflow.status.checkedOutBy:
                print(f"Record is currently checked out by: {workflow.status.checkedOutBy}")
            print("Your request is being processed. Please wait for approval.\n")
            return self._blocked(
                'waiting',
                flow_uid=bytes(workflow.flowUid) if workflow.flowUid else None,
                pending_conditions=conditions,
            )

        if stage == workflow_pb2.WS_NEEDS_ACTION:
            conditions = tuple(workflow.status.conditions) if workflow.status.conditions else ()
            if not silent_actionable:
                self._print_needs_action(conditions, workflow.flowUid)
            return self._blocked(
                'needs_action',
                flow_uid=bytes(workflow.flowUid) if workflow.flowUid else None,
                pending_conditions=conditions,
            )

        self._print_no_workflow()
        return self._blocked('no_workflow')

    def _print_ready_to_start(self):
        print(f"\n{bcolors.WARNING}Workflow access approved but not yet checked out.{bcolors.ENDC}")
        print(f"Run: {bcolors.OKBLUE}pam workflow start {self.record_uid}{bcolors.ENDC} to check out the record.\n")

    def _print_needs_action(self, conditions, flow_uid_bytes):
        print(f"\n{bcolors.WARNING}Workflow requires additional action before access is granted.{bcolors.ENDC}")
        if conditions:
            has_reason = workflow_pb2.AC_REASON in conditions
            has_ticket = workflow_pb2.AC_TICKET in conditions
            has_approval = workflow_pb2.AC_APPROVAL in conditions
            if has_reason or has_ticket:
                opts = []
                if has_reason:
                    opts.append('--reason "<reason>"')
                if has_ticket:
                    opts.append('--ticket "<ticket>"')
                print(f"Run: {bcolors.OKBLUE}pam workflow request {self.record_uid} "
                      f"{' '.join(opts)}{bcolors.ENDC}")
            elif has_approval:
                print(f"Run: {bcolors.OKBLUE}pam workflow request {self.record_uid}{bcolors.ENDC} "
                      f"to request approval.")
            else:
                cond_str = WorkflowFormatter.format_conditions(conditions)
                print(f"Pending conditions: {cond_str}")
        elif flow_uid_bytes:
            flow_uid_str = utils.base64_url_encode(flow_uid_bytes)
            print(f"Run: {bcolors.OKBLUE}pam workflow state --flow-uid {flow_uid_str}{bcolors.ENDC} "
                  f"to see details.")
        print()

    def _get_workflow_state_by_record(self):
        try:
            state_query = workflow_pb2.WorkflowState()
            state_query.resource.CopyFrom(
                ProtobufRefBuilder.record_ref(self.record_uid_bytes, self.record_name)
            )
            return _post_request_to_router(
                self.params, 'get_workflow_state',
                rq_proto=state_query, rs_type=workflow_pb2.WorkflowState,
            )
        except Exception as e:
            logging.debug('Failed to get workflow state for %s: %s', self.record_uid, e)
            return _TRANSPORT_ERROR

    def _print_transport_error(self, action: str):
        print(f"\n{bcolors.FAIL}Unable to {action} — the server may be unavailable.{bcolors.ENDC}")
        print("Access is blocked until workflow status can be verified. Please try again later.\n")

    def _print_no_workflow(self):
        print(f"\n{bcolors.WARNING}This record is protected by a workflow.{bcolors.ENDC}")
        print("You must request access before connecting.")
        print(f"Run: {bcolors.OKBLUE}pam workflow request {self.record_uid}{bcolors.ENDC} to request access.\n")

    def _print_needs_start(self):
        print(f"\n{bcolors.WARNING}This record is protected by a workflow.{bcolors.ENDC}")
        print("No approvals required, but the record must be checked out first.")
        print(f"Run: {bcolors.OKBLUE}pam workflow start {self.record_uid}{bcolors.ENDC} to check out the record.\n")


class WorkflowMfaPrompt:

    def __init__(self, params: KeeperParams):
        self.params = params

    def prompt(self):
        from ...proto import APIRequest_pb2
        from ... import api

        tfa_list = self._fetch_2fa_list(self.params, api, APIRequest_pb2)
        if tfa_list is None:
            try:
                code = getpass.getpass('2FA required. Enter TOTP code: ').strip()
                return code if code else None
            except (KeyboardInterrupt, EOFError):
                return None

        supported_types = {
            APIRequest_pb2.TWO_FA_CT_TOTP: 'TOTP (Authenticator App)',
            APIRequest_pb2.TWO_FA_CT_SMS: 'SMS Text Message',
            APIRequest_pb2.TWO_FA_CT_DUO: 'DUO Security',
            APIRequest_pb2.TWO_FA_CT_WEBAUTHN: 'Security Key',
            APIRequest_pb2.TWO_FA_CT_DNA: 'Keeper DNA (Watch)',
        }

        channels = [ch for ch in tfa_list.channels if ch.channelType in supported_types]

        if not channels:
            print(f"{bcolors.FAIL}No supported 2FA methods found. Supported: TOTP, SMS, DUO, Security Key.{bcolors.ENDC}")
            return None

        selected = self._select_channel(channels, supported_types)
        if selected is None:
            return None

        return self._dispatch(selected.channelType, APIRequest_pb2)

    @staticmethod
    def _fetch_2fa_list(params, api, APIRequest_pb2):
        try:
            tfa_list = api.communicate_rest(
                params, None, 'authentication/2fa_list',
                rs_type=APIRequest_pb2.TwoFactorListResponse,
            )
        except Exception:
            return None

        if not tfa_list.channels:
            print(f"\n{bcolors.FAIL}This workflow requires 2FA verification{bcolors.ENDC}")
            print(
                "Your account does not have any 2FA methods configured. "
                f"For available methods, run: {bcolors.OKBLUE}2fa add -h{bcolors.ENDC}"
            )
            return None

        return tfa_list

    @staticmethod
    def _select_channel(channels, supported_types):
        if len(channels) == 1:
            return channels[0]

        print(f"\n{bcolors.OKBLUE}2FA required. Select authentication method:{bcolors.ENDC}")
        for idx, ch in enumerate(channels, 1):
            name = supported_types.get(ch.channelType, 'Unknown')
            extra = f' ({ch.channelName})' if ch.channelName else ''
            print(f"  {idx}. {name}{extra}")
        print("  q. Cancel")

        try:
            answer = input('Selection: ').strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if answer.lower() == 'q':
            return None
        try:
            idx = int(answer) - 1
            if 0 <= idx < len(channels):
                return channels[idx]
        except ValueError:
            pass

        print(f"{bcolors.FAIL}Invalid selection.{bcolors.ENDC}")
        return None

    def _dispatch(self, channel_type, APIRequest_pb2):
        if channel_type == APIRequest_pb2.TWO_FA_CT_TOTP:
            try:
                code = getpass.getpass('Enter TOTP code: ').strip()
                return code if code else None
            except (KeyboardInterrupt, EOFError):
                return None

        push_config = {
            APIRequest_pb2.TWO_FA_CT_SMS: (
                APIRequest_pb2.TWO_FA_PUSH_SMS,
                'SMS sent.', 'SMS',
            ),
            APIRequest_pb2.TWO_FA_CT_DUO: (
                APIRequest_pb2.TWO_FA_PUSH_DUO_PUSH,
                'DUO push sent. Respond on your device, then enter the code.', 'DUO',
            ),
            APIRequest_pb2.TWO_FA_CT_DNA: (
                APIRequest_pb2.TWO_FA_PUSH_DNA,
                'Keeper DNA push sent. Approve on your watch, then enter the code.', 'DNA',
            ),
        }

        if channel_type in push_config:
            push_type, sent_msg, label = push_config[channel_type]
            return self._send_push_and_prompt(push_type, sent_msg, label)

        if channel_type == APIRequest_pb2.TWO_FA_CT_WEBAUTHN:
            return self._handle_webauthn()

        return None

    def _send_push_and_prompt(self, push_type, sent_message, prompt_label):
        try:
            push_rq = router_pb2.Router2FASendPushRequest()
            push_rq.pushType = push_type
            _post_request_to_router(self.params, '2fa_send_push', rq_proto=push_rq)
            print(f"{bcolors.OKGREEN}{sent_message}{bcolors.ENDC}")
        except Exception:
            print(f"{bcolors.FAIL}Failed to send {prompt_label} push. Please try again.{bcolors.ENDC}")
            return None

        try:
            code = getpass.getpass(f'Enter {prompt_label} code: ').strip()
            return code if code else None
        except (KeyboardInterrupt, EOFError):
            return None

    def _handle_webauthn(self):
        import json as _json

        try:
            challenge_rq = router_pb2.Router2FAGetWebAuthnChallengeRequest()
            challenge_rs = _post_request_to_router(
                self.params, '2fa_get_webauthn_challenge', rq_proto=challenge_rq,
                rs_type=router_pb2.Router2FAGetWebAuthnChallengeResponse,
            )
            if not challenge_rs or not challenge_rs.challenge:
                print(f"{bcolors.FAIL}Failed to get WebAuthn challenge from server.{bcolors.ENDC}")
                return None

            challenge = _json.loads(challenge_rs.challenge)

            from ...yubikey.yubikey import yubikey_authenticate
            response = yubikey_authenticate(challenge)

            if response:
                signature = {
                    "id": response.id,
                    "rawId": utils.base64_url_encode(response.raw_id),
                    "response": {
                        "authenticatorData": utils.base64_url_encode(response.response.authenticator_data),
                        "clientDataJSON": response.response.client_data.b64,
                        "signature": utils.base64_url_encode(response.response.signature),
                    },
                    "type": "public-key",
                    "clientExtensionResults": (
                        dict(response.client_extension_results)
                        if response.client_extension_results else {}
                    ),
                }
                return _json.dumps(signature)

            print(f"{bcolors.FAIL}Security key authentication failed or was cancelled.{bcolors.ENDC}")
            return None

        except ImportError:
            from ...yubikey import display_fido2_warning
            display_fido2_warning()
            return None
        except Exception:
            print(f"{bcolors.FAIL}Security key authentication failed. Please try again.{bcolors.ENDC}")
            return None


def check_workflow_access(params: KeeperParams, record_uid: str) -> dict:
    return WorkflowAccessValidator(params, record_uid).validate()


def check_workflow_for_launch(
    params: KeeperParams,
    record_uid: str,
    *,
    reason: Optional[str] = None,
    ticket: Optional[str] = None,
    auto_checkout: bool = False,
) -> WorkflowGate:
    """Pre-launch workflow gate: validate access, optionally submit a missing
    reason/ticket request and check out the record inline, prompt for MFA if
    required, and return the active flow's UID and lease expiry (millis since
    epoch) so callers can auto check-in and force-disconnect on lease expiry.

    When the workflow is in WS_NEEDS_ACTION with AC_REASON / AC_TICKET pending,
    the supplied reason/ticket flags are used directly; otherwise the user is
    prompted via prompt_toolkit. After submission the workflow is re-validated
    once so the resulting state (waiting / ready_to_start / started) is shown.

    When the workflow is in WS_READY_TO_START, the user is prompted to check
    out (or auto_checkout=True confirms automatically). On success the gate
    re-validates and reports started_by_launch=True so the caller can release
    the lease in its cleanup path.
    """
    validator = WorkflowAccessValidator(params, record_uid)
    started_by_launch = False
    handled_needs_action = False
    handled_ready_to_start = False

    # Up to 3 transitions: needs_action -> ready_to_start -> started.
    for _attempt in range(3):
        result = validator.validate(silent_actionable=True)
        if result.get('allowed', True):
            break
        block_reason = result.get('block_reason')

        if block_reason == 'needs_action' and not handled_needs_action:
            handled_needs_action = True
            conditions = result.get('pending_conditions') or ()
            needs_reason = workflow_pb2.AC_REASON in conditions
            needs_ticket = workflow_pb2.AC_TICKET in conditions
            needs_approval_only = (
                workflow_pb2.AC_APPROVAL in conditions
                and not needs_reason and not needs_ticket
            )

            final_reason = reason
            final_ticket = ticket

            if needs_reason or needs_ticket:
                prompt_reason = needs_reason and not final_reason
                prompt_ticket = needs_ticket and not final_ticket
                if prompt_reason or prompt_ticket:
                    p_reason, p_ticket = prompt_for_reason_ticket(prompt_reason, prompt_ticket)
                    if prompt_reason:
                        if p_reason is None:
                            validator._print_needs_action(conditions, result.get('flow_uid'))
                            return WorkflowGate(allowed=False)
                        final_reason = p_reason
                    if prompt_ticket:
                        if p_ticket is None:
                            validator._print_needs_action(conditions, result.get('flow_uid'))
                            return WorkflowGate(allowed=False)
                        final_ticket = p_ticket

            if not (needs_reason or needs_ticket or needs_approval_only):
                validator._print_needs_action(conditions, result.get('flow_uid'))
                return WorkflowGate(allowed=False)

            try:
                submit_access_request(
                    params, record_uid,
                    reason=final_reason or '',
                    ticket=final_ticket or '',
                )
                print(f"\n{bcolors.OKGREEN}Access request submitted.{bcolors.ENDC}\n")
            except Exception as e:
                logging.error("Failed to submit access request: %s", sanitize_router_error(e))
                return WorkflowGate(allowed=False)
            continue

        if block_reason == 'ready_to_start' and not handled_ready_to_start:
            handled_ready_to_start = True
            confirmed = auto_checkout
            if not confirmed:
                try:
                    answer = input(
                        f"\n{bcolors.OKBLUE}Workflow approved. Check out '{record_uid}' now? [Y/n]: {bcolors.ENDC}"
                    ).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    answer = 'n'
                confirmed = answer in ('', 'y', 'yes')
            if not confirmed:
                validator._print_ready_to_start()
                return WorkflowGate(allowed=False)
            try:
                start_workflow_for_record(params, record_uid)
                print(f"{bcolors.OKGREEN}Checked out.{bcolors.ENDC}\n")
                started_by_launch = True
            except Exception as e:
                logging.error("Failed to check out: %s", sanitize_router_error(e))
                return WorkflowGate(allowed=False)
            continue

        # Block reason we don't auto-handle (waiting, no_workflow, transport_error,
        # outside_time_window, no_status, needs_start) — those validator paths
        # already printed their own message in non-silent branches; for the
        # actionable ones suppressed by silent_actionable, fall back to the
        # explicit print so the user always sees something.
        if block_reason == 'needs_action':
            validator._print_needs_action(
                result.get('pending_conditions') or (),
                result.get('flow_uid'),
            )
        elif block_reason == 'ready_to_start':
            validator._print_ready_to_start()
        return WorkflowGate(allowed=False)

    if not result.get('allowed', True):
        return WorkflowGate(allowed=False)

    flow_uid = result.get('flow_uid')
    expires_on_ms = int(result.get('expires_on_ms') or 0)

    two_factor_value = None
    if result.get('require_mfa', False):
        two_factor_value = WorkflowMfaPrompt(params).prompt()
        if not two_factor_value:
            return WorkflowGate(allowed=False)

    return WorkflowGate(
        allowed=True,
        two_factor_value=two_factor_value,
        flow_uid=flow_uid,
        expires_on_ms=expires_on_ms,
        started_by_launch=started_by_launch,
    )


def check_workflow_and_prompt_2fa(params: KeeperParams, record_uid: str):
    """Backward-compatible wrapper around check_workflow_for_launch.
    Prefer check_workflow_for_launch in new code — it carries flow_uid and
    expires_on_ms needed for auto check-in and lease-expiry teardown."""
    gate = check_workflow_for_launch(params, record_uid)
    return (gate.allowed, gate.two_factor_value)
