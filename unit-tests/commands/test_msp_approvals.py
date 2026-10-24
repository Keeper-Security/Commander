from types import SimpleNamespace
from unittest.mock import patch
import json
import logging

import pytest

from keepercommander.commands.pedm.msp_approvals import (
    MspApprovalsCommand, MspApprovalsListCommand, MspApprovalActionCommand,
)
from keepercommander.commands import base
from keepercommander.error import CommandError
from keepercommander.proto import pedm_pb2
from keepercommander.proto import enterprise_pb2
from keepercommander import crypto, utils
from keepercommander.pedm.admin_plugin import PedmPlugin


def msp_context():
    return SimpleNamespace(enterprise={
        'licenses': [{'lic_status': 'msp_active'}],
        'managed_companies': [{'mc_enterprise_id': 42, 'mc_enterprise_name': 'Example MC'}],
    })


def test_registered_under_epm_only():
    enterprise_commands, msp_commands = {}, {}
    aliases, command_info = {}, {}
    base.register_enterprise_commands(enterprise_commands, aliases, command_info)
    base.register_msp_commands(msp_commands, aliases, command_info)
    assert isinstance(enterprise_commands['epm'].subcommands['msp-approvals'], MspApprovalsCommand)
    assert isinstance(enterprise_commands['epm'].subcommands['msp-approvals'].subcommands['list'], MspApprovalsListCommand)
    assert isinstance(enterprise_commands['epm'].subcommands['msp-approvals'].subcommands['action'], MspApprovalActionCommand)
    assert 'msp-approvals' not in msp_commands


def test_repeatable_enterprise_and_backward_pagination():
    command = MspApprovalsListCommand()
    args = command.get_parser().parse_args(['--enterprise', '42', '--enterprise', '43', '--page-size', '1'])
    assert args.enterprise == [42, 43]

    key = b'k' * 32
    approval = pedm_pb2.ApprovalNode(
        approvalUid=b'a' * 16, agentUid=b'b' * 16, approvalType=1, created=1000,
        accountInfo=crypto.encrypt_aes_v2(json.dumps({'user': 'alice'}).encode(), key),
        applicationInfo=crypto.encrypt_aes_v2(json.dumps({'app': 'Terminal'}).encode(), key),
        justification=crypto.encrypt_aes_v2(b'{"text":"Business need"}', key))
    responses = [
        pedm_pb2.GetApprovalNavigationTokenResponse(navigation_token=b'first'),
        pedm_pb2.ApprovalNavigationResponse(
            approvals=[pedm_pb2.ApprovalEnvelope(enterprise_id=42, approval=approval)],
            next_navigation_token=b'second', has_more=True),
        pedm_pb2.ApprovalNavigationResponse(
            approvals=[pedm_pb2.ApprovalEnvelope(enterprise_id=43, is_escalated=True, approval=approval)]),
    ]
    calls = []

    def router(_context, endpoint, request, *, rs_type):
        calls.append((endpoint, request))
        return responses.pop(0)

    plugin = SimpleNamespace(load_mc_agent_keys=lambda infos: {42, 43}, get_mc_agent_key=lambda enterprise_id: key)
    with patch('keepercommander.commands.pedm.msp_approvals.api.execute_router', side_effect=router), \
            patch('keepercommander.commands.pedm.msp_approvals.api.communicate_rest',
                  return_value=enterprise_pb2.GetMCsInfoResponse()), \
            patch('keepercommander.commands.pedm.msp_approvals.admin_plugin.get_pedm_plugin', return_value=plugin), \
            patch('keepercommander.commands.pedm.msp_approvals.report_utils.dump_report_data',
                  side_effect=lambda rows, headers, **kwargs: (rows, headers)):
        rows, headers = command.execute(msp_context(), enterprise=args.enterprise, page_size=args.page_size)

    assert calls[0][0] == 'pedm/get_approval_navigation_token'
    assert list(calls[0][1].enterprise_id) == [42, 43]
    assert [call[0] for call in calls[1:]] == ['pedm/navigate_approvals'] * 2
    assert all(call[1].direction == pedm_pb2.NAVIGATION_DIRECTION_BACKWARD for call in calls[1:])
    assert [call[1].navigation_token for call in calls[1:]] == [b'first', b'second']
    assert len(rows) == 2
    assert rows[0][0] == 'Example MC (42)'
    assert rows[1][0] == '43'
    assert [row[3] for row in rows] == ['Pending', 'Escalated']
    assert rows[0][5] == ['user=alice']
    assert rows[0][6] == ['app=Terminal']
    assert rows[0][7] == 'Business need'
    assert headers[0] == 'Enterprise'


def test_requires_msp_before_router_call():
    with patch('keepercommander.commands.pedm.msp_approvals.api.execute_router') as router:
        with pytest.raises(CommandError, match='MSP account'):
            MspApprovalsListCommand().execute(SimpleNamespace(enterprise={'licenses': []}))
        router.assert_not_called()


def test_rejects_repeated_continuation_token():
    responses = [
        pedm_pb2.GetApprovalNavigationTokenResponse(navigation_token=b'first'),
        pedm_pb2.ApprovalNavigationResponse(next_navigation_token=b'first', has_more=True),
    ]
    plugin = SimpleNamespace(load_mc_agent_keys=lambda infos: {42}, get_mc_agent_key=lambda enterprise_id: b'k' * 32)
    with patch('keepercommander.commands.pedm.msp_approvals.api.execute_router', side_effect=responses), \
            patch('keepercommander.commands.pedm.msp_approvals.api.communicate_rest',
                  return_value=enterprise_pb2.GetMCsInfoResponse()), \
            patch('keepercommander.commands.pedm.msp_approvals.admin_plugin.get_pedm_plugin', return_value=plugin):
        with pytest.raises(CommandError, match='repeated navigation token'):
            MspApprovalsListCommand().execute(msp_context())


def test_mc_hash_keys_use_msp_tree_key_and_mc_private_ec_key():
    msp_tree_key = b'm' * 32
    mc_tree_key = bytes(range(32))
    ec_private_key = b'p' * 32
    plugin = PedmPlugin.__new__(PedmPlugin)
    plugin.params = SimpleNamespace(enterprise={
        'unencrypted_tree_key': msp_tree_key,
        'managed_companies': [{
            'mc_enterprise_id': 42,
            'tree_key': utils.base64_url_encode(crypto.encrypt_aes_v2(mc_tree_key, msp_tree_key)),
        }],
    })
    plugin._mc_agent_keys = {}
    plugin.logger = logging.getLogger('test.msp_approvals')
    encrypted_private_key = crypto.encrypt_aes_v2(ec_private_key, mc_tree_key)
    mc_info = enterprise_pb2.MCInfo(enterpriseId=42, eccEncryptedPrivateKey=encrypted_private_key)
    with patch('keepercommander.pedm.admin_plugin.crypto.derive_key_v1', return_value=b'h' * 32) as derive:
        plugin.load_mc_agent_keys([mc_info])
    expected_salt = bytes(a ^ b for a, b in zip(mc_tree_key[:16], mc_tree_key[16:]))
    derive.assert_called_once_with(utils.base64_url_encode(ec_private_key), expected_salt, 1_000_000)
    assert plugin.get_mc_agent_key(42) == b'h' * 32
    assert plugin.get_mc_agent_key(43) is None


def test_mc_hash_keys_support_ecc_wrapped_tree_key():
    msp_tree_key = b'm' * 32
    mc_tree_key = b't' * 32
    ec_private_key = b'p' * 32
    msp_private_key, msp_public_key = crypto.generate_ec_key()
    plugin = PedmPlugin.__new__(PedmPlugin)
    plugin.params = SimpleNamespace(enterprise={
        'unencrypted_tree_key': msp_tree_key,
        'keys': {'ecc_encrypted_private_key': utils.base64_url_encode(
            crypto.encrypt_aes_v2(crypto.unload_ec_private_key(msp_private_key), msp_tree_key))},
        'managed_companies': [{
            'mc_enterprise_id': 42, 'tree_key_type_id': 4,
            'tree_key': utils.base64_url_encode(crypto.encrypt_ec(mc_tree_key, msp_public_key)),
        }],
    })
    plugin._mc_agent_keys = {}
    plugin.logger = logging.getLogger('test.msp_approvals')
    mc_info = enterprise_pb2.MCInfo(
        enterpriseId=42, eccEncryptedPrivateKey=crypto.encrypt_aes_v2(ec_private_key, mc_tree_key))
    with patch('keepercommander.pedm.admin_plugin.crypto.derive_key_v1', return_value=b'h' * 32) as derive:
        plugin.load_mc_agent_keys([mc_info])
    expected_salt = bytes(a ^ b for a, b in zip(mc_tree_key[:16], mc_tree_key[16:]))
    derive.assert_called_once_with(utils.base64_url_encode(ec_private_key), expected_salt, 1_000_000)
    assert plugin.get_mc_agent_key(42) == b'h' * 32


def test_mc_hash_keys_skip_missing_and_invalid_keys_without_losing_usable_mcs():
    msp_tree_key = b'm' * 32
    mc_tree_key = b't' * 32
    plugin = PedmPlugin.__new__(PedmPlugin)
    plugin.params = SimpleNamespace(enterprise={
        'unencrypted_tree_key': msp_tree_key,
        'managed_companies': [
            {'mc_enterprise_id': 42},
            {'mc_enterprise_id': 43, 'tree_key': utils.base64_url_encode(crypto.encrypt_aes_v2(mc_tree_key, msp_tree_key))},
            {'mc_enterprise_id': 44, 'tree_key': utils.base64_url_encode(crypto.encrypt_aes_v2(mc_tree_key, msp_tree_key))},
        ],
    })
    plugin.logger = logging.getLogger('test.msp_approvals')
    plugin._mc_agent_keys = {42: b'old'}
    infos = [
        enterprise_pb2.MCInfo(enterpriseId=42),
        enterprise_pb2.MCInfo(enterpriseId=43, eccEncryptedPrivateKey=b'invalid'),
        enterprise_pb2.MCInfo(enterpriseId=44, eccEncryptedPrivateKey=crypto.encrypt_aes_v2(b'p' * 32, mc_tree_key)),
    ]
    with patch('keepercommander.pedm.admin_plugin.crypto.derive_key_v1', return_value=b'h' * 32):
        assert plugin.load_mc_agent_keys(infos) == {44}
    assert plugin.get_mc_agent_key(42) is None
    assert plugin.get_mc_agent_key(43) is None
    assert plugin.get_mc_agent_key(44) == b'h' * 32
    assert plugin.load_mc_agent_keys([]) == set()
    assert plugin.get_mc_agent_key(42) is None
    assert plugin.get_mc_agent_key(44) is None


def test_router_only_receives_mcs_with_usable_private_ec_keys():
    plugin = SimpleNamespace(load_mc_agent_keys=lambda infos: {43}, get_mc_agent_key=lambda enterprise_id: b'k' * 32)
    with patch('keepercommander.commands.pedm.msp_approvals.api.communicate_rest',
               return_value=enterprise_pb2.GetMCsInfoResponse()) as mc_api, \
            patch('keepercommander.commands.pedm.msp_approvals.admin_plugin.get_pedm_plugin', return_value=plugin), \
            patch('keepercommander.commands.pedm.msp_approvals.api.execute_router',
                  side_effect=[pedm_pb2.GetApprovalNavigationTokenResponse(navigation_token=b'token'),
                               pedm_pb2.ApprovalNavigationResponse()]) as router, \
            patch('keepercommander.commands.pedm.msp_approvals.report_utils.dump_report_data',
                  side_effect=lambda rows, headers, **kwargs: (rows, headers)):
        MspApprovalsListCommand().execute(msp_context(), enterprise=[42, 43])
    assert list(mc_api.call_args.args[1].mcEnterpriseId) == [42, 43]
    assert list(router.call_args_list[0].args[2].enterprise_id) == [43]


def test_no_usable_mc_keys_does_not_request_all_enterprises_from_router():
    plugin = SimpleNamespace(load_mc_agent_keys=lambda infos: set())
    with patch('keepercommander.commands.pedm.msp_approvals.api.communicate_rest',
               return_value=enterprise_pb2.GetMCsInfoResponse()), \
            patch('keepercommander.commands.pedm.msp_approvals.admin_plugin.get_pedm_plugin', return_value=plugin), \
            patch('keepercommander.commands.pedm.msp_approvals.api.execute_router') as router, \
            patch('keepercommander.commands.pedm.msp_approvals.report_utils.dump_report_data',
                  side_effect=lambda rows, headers, **kwargs: (rows, headers)):
        rows, headers = MspApprovalsListCommand().execute(msp_context())
    assert rows == []
    assert headers[0] == 'Enterprise'
    router.assert_not_called()


def test_msp_approval_action_sends_qualified_references_and_reports_statuses():
    uid1, uid2, uid3 = (bytes([n]) * 16 for n in (1, 2, 3))
    refs = [f'{enterprise_id}:{utils.base64_url_encode(uid)}'
            for enterprise_id, uid in ((42, uid1), (43, uid2), (42, uid3))]
    command = MspApprovalActionCommand()
    args = command.get_parser().parse_args([
        '--approve', refs[0], '--deny', refs[1], '--remove', refs[2]])
    response = pedm_pb2.PedmStatusResponse(
        addStatus=[pedm_pb2.PedmStatus(key=[uid1, (42).to_bytes(4, 'big')], success=True)],
        updateStatus=[pedm_pb2.PedmStatus(key=[uid2, (43).to_bytes(4, 'big')], success=False,
                                            message='Not pending')],
        removeStatus=[pedm_pb2.PedmStatus(key=[uid3, (42).to_bytes(4, 'big')], success=True)])
    with patch('keepercommander.commands.pedm.msp_approvals.api.execute_router',
               return_value=response) as router, \
            patch('keepercommander.commands.pedm.msp_approvals.report_utils.dump_report_data',
                  side_effect=lambda rows, headers, **kwargs: (rows, headers)):
        rows, headers = command.execute(msp_context(), **vars(args))
    request = router.call_args.args[2]
    assert router.call_args.args[1] == 'pedm/msp_approval_action'
    assert (request.approve[0].enterprise_id, request.approve[0].approval_uid) == (42, uid1)
    assert (request.deny[0].enterprise_id, request.deny[0].approval_uid) == (43, uid2)
    assert (request.remove[0].enterprise_id, request.remove[0].approval_uid) == (42, uid3)
    assert rows == [[42, utils.base64_url_encode(uid1), 'approve', True, ''],
                    [43, utils.base64_url_encode(uid2), 'deny', False, 'Not pending'],
                    [42, utils.base64_url_encode(uid3), 'remove', True, '']]
    assert headers == ['Enterprise', 'Approval UID', 'Action', 'Success', 'Message']


@pytest.mark.parametrize('values', [
    {},
    {'approve': ['42:invalid']},
    {'approve': ['0:' + utils.base64_url_encode(b'a' * 16)]},
    {'approve': ['2147483648:' + utils.base64_url_encode(b'a' * 16)]},
    {'approve': ['42:' + utils.base64_url_encode(b'a' * 16)],
     'deny': ['42:' + utils.base64_url_encode(b'a' * 16)]},
])
def test_msp_approval_action_rejects_invalid_or_duplicate_references(values):
    with patch('keepercommander.commands.pedm.msp_approvals.api.execute_router') as router:
        with pytest.raises(CommandError):
            MspApprovalActionCommand().execute(msp_context(), **values)
        router.assert_not_called()


def test_msp_approval_action_requires_msp():
    with patch('keepercommander.commands.pedm.msp_approvals.api.execute_router') as router:
        with pytest.raises(CommandError, match='MSP account'):
            MspApprovalActionCommand().execute(SimpleNamespace(enterprise={'licenses': []}),
                                               approve=['42:' + utils.base64_url_encode(b'a' * 16)])
        router.assert_not_called()


def test_msp_approvals_group_keeps_direct_list_options():
    context = SimpleNamespace(session_token='token', environment_variables={})
    with patch.object(MspApprovalsListCommand, 'execute', return_value='listed') as execute:
        assert MspApprovalsCommand().execute_args(context, '--enterprise 42', command='epm') == 'listed'
    assert execute.call_args.kwargs['enterprise'] == [42]
