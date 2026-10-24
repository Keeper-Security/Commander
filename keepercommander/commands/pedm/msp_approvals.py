"""MSP-wide EPM approval navigation with client-side MC key derivation."""

import argparse
import datetime
import json
import logging
import re
from typing import Any, Dict, List, Tuple

from ... import api, crypto, utils
from ...error import CommandError
from ...params import KeeperParams
from ...proto import pedm_pb2, enterprise_pb2
from .. import base
from ..enterprise_common import EnterpriseCommand
from ..helpers import report_utils
from ...pedm import admin_plugin, pedm_shared


def decrypt_approval(approval: pedm_pb2.ApprovalNode, agent_key: bytes) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    account_info = json.loads(crypto.decrypt_aes_v2(approval.accountInfo, agent_key)) if approval.accountInfo else {}
    application_info = json.loads(crypto.decrypt_aes_v2(approval.applicationInfo, agent_key)) if approval.applicationInfo else {}
    justification = crypto.decrypt_aes_v2(approval.justification, agent_key).decode('utf-8') if approval.justification else ''
    return account_info, application_info, justification


class MspApprovalsCommand(base.GroupCommandNew):
    def __init__(self):
        super().__init__('List and act on EPM approvals across managed companies')
        self.register_command_new(MspApprovalsListCommand(), 'list', 'l')
        self.register_command_new(MspApprovalActionCommand(), 'action', 'a')
        self.default_verb = 'list'

    def execute_args(self, params, args, **kwargs):
        # Preserve the original `epm msp-approvals --enterprise ID` invocation.
        if args and args.lstrip().startswith('-') and not args.lstrip().startswith(('-h', '--help')):
            args = 'list ' + args
        return super().execute_args(params, args, **kwargs)


class MspApprovalsListCommand(base.ArgparseCommand):
    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='msp-approvals', description='List pending EPM approvals across managed companies',
            parents=[base.report_output_parser])
        parser.add_argument('--enterprise', type=int, action='append', metavar='ID',
                            help='Managed company enterprise ID (repeat to select multiple; default: all accessible)')
        parser.add_argument('--page-size', type=int, default=200, metavar='N',
                            help='Approvals per API request (1-200; default: 200)')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        if not EnterpriseCommand.is_msp(context):
            raise CommandError('msp-approvals', 'An MSP account is required')

        enterprise_ids = kwargs.get('enterprise') or []
        if any(enterprise_id <= 0 for enterprise_id in enterprise_ids) or len(enterprise_ids) > 1000:
            raise CommandError('msp-approvals', 'Specify at most 1000 positive enterprise IDs')
        page_size = kwargs.get('page_size', 200)
        if page_size is None or not 1 <= page_size <= 200:
            raise CommandError('msp-approvals', 'Page size must be between 1 and 200')

        mc_request = enterprise_pb2.GetMCsInfoRequest(mcEnterpriseId=enterprise_ids, includePrivateKeys=True)
        mc_response = api.communicate_rest(
            context, mc_request, 'enterprise/get_mcs_info', rs_type=enterprise_pb2.GetMCsInfoResponse)
        if mc_response is None:
            raise CommandError('msp-approvals', 'KeeperApp did not return managed company key information')
        plugin = admin_plugin.get_pedm_plugin(context, skip_sync=True)
        try:
            eligible_ids = plugin.load_mc_agent_keys(mc_response.mcInfo)
        except Exception as e:
            raise CommandError('msp-approvals', 'Unable to derive managed company approval keys') from e
        if enterprise_ids:
            eligible_ids = eligible_ids.intersection(enterprise_ids)

        company_names = {
            mc['mc_enterprise_id']: mc.get('mc_enterprise_name')
            for mc in (context.enterprise or {}).get('managed_companies', [])
            if 'mc_enterprise_id' in mc
        }
        headers = ['enterprise', 'approval_uid', 'approval_type', 'status', 'agent_uid',
                   'account_info', 'application_info', 'justification', 'expire_in', 'created']
        fmt = kwargs.get('format')
        table: List[List[Any]] = []
        if not eligible_ids:
            logging.warning('No managed companies with usable EC approval keys were found')
            if fmt != 'json':
                headers = [report_utils.field_to_title(header) for header in headers]
            return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))
        if len(eligible_ids) > 1000:
            raise CommandError('msp-approvals', 'Too many managed companies with approval keys; select a subset')

        # An empty enterprise list means "all accessible" to the router, so do not request
        # a token until we have a nonempty, decryptable subset.
        token_request = pedm_pb2.GetApprovalNavigationTokenRequest(enterprise_id=sorted(eligible_ids))
        token_response = api.execute_router(
            context, 'pedm/get_approval_navigation_token', token_request,
            rs_type=pedm_pb2.GetApprovalNavigationTokenResponse)
        if not token_response or not token_response.navigation_token:
            raise CommandError('msp-approvals', 'Router did not return an approval navigation token')
        token = token_response.navigation_token
        seen_tokens = set()
        while True:
            if token in seen_tokens:
                raise CommandError('msp-approvals', 'Router returned a repeated navigation token')
            seen_tokens.add(token)
            request = pedm_pb2.ApprovalNavigationRequest(
                navigation_token=token, direction=pedm_pb2.NAVIGATION_DIRECTION_BACKWARD,
                limit=page_size)
            response = api.execute_router(
                context, 'pedm/navigate_approvals', request,
                rs_type=pedm_pb2.ApprovalNavigationResponse)
            if response is None:
                raise CommandError('msp-approvals', 'Router did not return an approval page')

            for envelope in response.approvals:
                status = 'Escalated' if envelope.is_escalated else 'Pending'
                approval = envelope.approval
                enterprise_id = envelope.enterprise_id
                company_name = company_names.get(enterprise_id)
                enterprise = f'{company_name} ({enterprise_id})' if company_name else str(enterprise_id)
                created = datetime.datetime.fromtimestamp(approval.created / 1000)
                agent_key = plugin.get_mc_agent_key(enterprise_id)
                if agent_key is None:
                    raise CommandError('msp-approvals', f'Missing approval key for managed company {enterprise_id}')
                try:
                    account_info, application_info, justification = decrypt_approval(approval, agent_key)
                except Exception as e:
                    raise CommandError(
                        'msp-approvals', f'Unable to decrypt approval in managed company {enterprise_id}') from e
                if fmt != 'json':
                    account_info = [f'{k}={v}'[:30] for k, v in account_info.items()]
                    application_info = [f'{k}={v}'[:30] for k, v in application_info.items()]
                    try:
                        parsed = json.loads(justification)
                        if isinstance(parsed, dict):
                            justification = parsed.get('text', justification)
                    except (json.JSONDecodeError, ValueError):
                        pass
                table.append([
                    enterprise, utils.base64_url_encode(approval.approvalUid),
                    pedm_shared.approval_type_to_name(approval.approvalType), status,
                    utils.base64_url_encode(approval.agentUid),
                    account_info, application_info, justification,
                    approval.expireIn, created,
                ])

            if not response.has_more:
                break
            if not response.next_navigation_token:
                raise CommandError('msp-approvals', 'Router did not return a continuation token')
            token = response.next_navigation_token

        if fmt != 'json':
            headers = [report_utils.field_to_title(header) for header in headers]
        return report_utils.dump_report_data(table, headers, fmt=fmt, filename=kwargs.get('output'))


class MspApprovalActionCommand(base.ArgparseCommand):
    """Send enterprise-qualified approval actions to the MSP router endpoint."""

    def __init__(self):
        parser = argparse.ArgumentParser(
            prog='action', description='Approve, deny, or remove managed-company EPM requests',
            parents=[base.report_output_parser])
        for action in ('approve', 'deny', 'remove'):
            parser.add_argument(f'--{action}', action='append', metavar='ENTERPRISE_ID:APPROVAL_UID',
                                help=f'Managed company enterprise ID and approval UID to {action} (repeatable)')
        super().__init__(parser)

    def execute(self, context: KeeperParams, **kwargs) -> Any:
        if not EnterpriseCommand.is_msp(context):
            raise CommandError('msp-approvals', 'An MSP account is required')

        request = pedm_pb2.MspApprovalActionRequest()
        actions = {}
        for action in ('approve', 'deny', 'remove'):
            for value in kwargs.get(action) or []:
                match = re.fullmatch(r'([1-9][0-9]{0,9}):([A-Za-z0-9_-]{22})', value)
                if not match or int(match[1]) > 2**31 - 1:
                    raise CommandError('msp-approvals', f'Invalid approval reference: {value}')
                enterprise_id = int(match[1])
                uid = utils.base64_url_decode(match[2])
                if len(uid) != 16 or utils.base64_url_encode(uid) != match[2]:
                    raise CommandError('msp-approvals', f'Invalid approval UID: {match[2]}')
                key = (enterprise_id, uid)
                if key in actions:
                    raise CommandError('msp-approvals', f'Duplicate approval reference: {value}')
                actions[key] = action
                getattr(request, action).add(enterprise_id=enterprise_id, approval_uid=uid)
        if not actions or len(actions) > 1000:
            raise CommandError('msp-approvals', 'Specify between 1 and 1000 approval actions')

        response = api.execute_router(context, 'pedm/msp_approval_action', request,
                                      rs_type=pedm_pb2.PedmStatusResponse)
        if response is None:
            raise CommandError('msp-approvals', 'Router did not return approval action statuses')

        rows = []
        seen = set()
        for action, statuses in (('approve', response.addStatus),
                                 ('deny', response.updateStatus),
                                 ('remove', response.removeStatus)):
            for status in statuses:
                if len(status.key) != 2 or len(status.key[0]) != 16 or len(status.key[1]) != 4:
                    raise CommandError('msp-approvals', 'Router returned an invalid approval action status')
                enterprise_id = int.from_bytes(status.key[1], 'big')
                key = (enterprise_id, status.key[0])
                if actions.get(key) != action or key in seen:
                    raise CommandError('msp-approvals', 'Router returned an unexpected approval action status')
                seen.add(key)
                rows.append([enterprise_id, utils.base64_url_encode(status.key[0]),
                             action, status.success, status.message])
        if seen != actions.keys():
            raise CommandError('msp-approvals', 'Router did not return all approval action statuses')
        headers = ['enterprise', 'approval_uid', 'action', 'success', 'message']
        fmt = kwargs.get('format')
        if fmt != 'json':
            headers = [report_utils.field_to_title(header) for header in headers]
        return report_utils.dump_report_data(rows, headers, fmt=fmt, filename=kwargs.get('output'))
