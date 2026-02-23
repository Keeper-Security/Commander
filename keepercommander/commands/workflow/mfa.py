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

from ..pam.router_helper import _post_request_to_router
from ...display import bcolors
from ...params import KeeperParams
from ...proto import workflow_pb2
from ... import vault, utils

from .helpers import ProtobufRefBuilder, WorkflowFormatter


class WorkflowAccessValidator:

    _DEFAULT_RESULT = {'allowed': True, 'require_mfa': False}

    def __init__(self, params: KeeperParams, record_uid: str):
        self.params = params
        self.record_uid = record_uid
        self.record_uid_bytes = utils.base64_url_decode(record_uid)

        record = vault.KeeperRecord.load(params, record_uid)
        self.record_name = record.title if record else record_uid

    def validate(self) -> dict:
        config = self._read_workflow_config()
        if config is None:
            return dict(self._DEFAULT_RESULT)

        mfa_required = bool(config.parameters and config.parameters.requireMFA)

        workflow = self._find_active_workflow()
        if workflow is None:
            self._print_no_workflow()
            return {'allowed': False, 'require_mfa': False}

        return self._evaluate_stage(workflow, mfa_required)

    def _read_workflow_config(self):
        ref = ProtobufRefBuilder.record_ref(self.record_uid_bytes, self.record_name)
        try:
            return _post_request_to_router(
                self.params, 'read_workflow_config',
                rq_proto=ref, rs_type=workflow_pb2.WorkflowConfig,
            )
        except Exception:
            return None

    def _find_active_workflow(self):
        try:
            user_state = _post_request_to_router(
                self.params, 'get_user_access_state',
                rs_type=workflow_pb2.UserAccessState,
            )
        except Exception:
            return None

        if user_state and user_state.workflows:
            for wf in user_state.workflows:
                if wf.resource and wf.resource.value == self.record_uid_bytes:
                    return wf
        return None

    def _evaluate_stage(self, workflow, mfa_required: bool) -> dict:
        if not workflow.status:
            self._print_no_workflow()
            return {'allowed': False, 'require_mfa': False}

        stage = workflow.status.stage

        if stage == workflow_pb2.WS_STARTED:
            return {'allowed': True, 'require_mfa': mfa_required}

        if stage == workflow_pb2.WS_READY_TO_START:
            print(f"\n{bcolors.WARNING}Workflow access approved but not yet checked out.{bcolors.ENDC}")
            print(f"Run: {bcolors.OKBLUE}pam workflow start {self.record_uid}{bcolors.ENDC} to check out the record.\n")
            return {'allowed': False, 'require_mfa': False}

        if stage == workflow_pb2.WS_WAITING:
            conditions = workflow.status.conditions
            cond_str = WorkflowFormatter.format_conditions(conditions) if conditions else 'approval'
            print(f"\n{bcolors.WARNING}Workflow access is pending: waiting for {cond_str}.{bcolors.ENDC}")
            print("Your request is being processed. Please wait for approval.\n")
            return {'allowed': False, 'require_mfa': False}

        if stage == workflow_pb2.WS_NEEDS_ACTION:
            flow_uid_str = utils.base64_url_encode(workflow.flowUid)
            print(f"\n{bcolors.WARNING}Workflow requires additional action before access is granted.{bcolors.ENDC}")
            print(f"Run: {bcolors.OKBLUE}pam workflow state --flow-uid {flow_uid_str}{bcolors.ENDC} to see details.\n")
            return {'allowed': False, 'require_mfa': False}

        self._print_no_workflow()
        return {'allowed': False, 'require_mfa': False}

    def _print_no_workflow(self):
        print(f"\n{bcolors.WARNING}This record is protected by a workflow.{bcolors.ENDC}")
        print("You must request access before connecting.")
        print(f"Run: {bcolors.OKBLUE}pam workflow request {self.record_uid}{bcolors.ENDC} to request access.\n")


class WorkflowMfaPrompt:

    def __init__(self, params: KeeperParams):
        self.params = params

    def prompt(self):
        import getpass
        from ...proto import APIRequest_pb2
        from ... import api

        tfa_list = self._fetch_2fa_list(self.params, api, APIRequest_pb2, getpass)
        if tfa_list is None:
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
    def _fetch_2fa_list(params, api, APIRequest_pb2, getpass):
        try:
            tfa_list = api.communicate_rest(
                params, None, 'authentication/2fa_list',
                rs_type=APIRequest_pb2.TwoFactorListResponse,
            )
        except Exception:
            try:
                code = getpass.getpass('2FA required. Enter TOTP code: ').strip()
                return code if code else None
            except (KeyboardInterrupt, EOFError):
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
        import getpass

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
        import getpass
        from ...proto import router_pb2

        try:
            push_rq = router_pb2.Router2FASendPushRequest()
            push_rq.pushType = push_type
            _post_request_to_router(self.params, '2fa_send_push', rq_proto=push_rq)
            print(f"{bcolors.OKGREEN}{sent_message}{bcolors.ENDC}")
        except Exception as e:
            print(f"{bcolors.FAIL}Failed to send {prompt_label} push: {e}{bcolors.ENDC}")
            return None

        try:
            code = getpass.getpass(f'Enter {prompt_label} code: ').strip()
            return code if code else None
        except (KeyboardInterrupt, EOFError):
            return None

    def _handle_webauthn(self):
        import json as _json
        from ...proto import router_pb2

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
        except Exception as e:
            print(f"{bcolors.FAIL}Security key error: {e}{bcolors.ENDC}")
            return None


def check_workflow_access(params: KeeperParams, record_uid: str) -> dict:
    return WorkflowAccessValidator(params, record_uid).validate()


def check_workflow_and_prompt_2fa(params: KeeperParams, record_uid: str):
    result = check_workflow_access(params, record_uid)
    if not result.get('allowed', True):
        return (False, None)
    if result.get('require_mfa', False):
        value = WorkflowMfaPrompt(params).prompt()
        if not value:
            return (False, None)
        return (True, value)
    return (True, None)
