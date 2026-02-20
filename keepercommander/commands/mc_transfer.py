import argparse
import enum
import logging
from typing import Optional, Tuple, List, Set, Any

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from . import base, enterprise_common
from .helpers import report_utils
from .. import api, error, crypto, utils
from ..proto import MCTransfer_pb2, breachwatch_pb2


def register_commands(commands):
    commands['mc-transfer'] = McTransferCommand()

class McTransferCommand(base.GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('join-msp', McTransferJoinMspCommand())
        self.register_command('leave-msp', McTransferLeaveMspCommand())
        self.register_command('accept-mc', McTransferAcceptMcCommand())
        self.register_command('cancel', McTransferCancelCommand())
        self.register_command('status', McTransferStatusCommand())
        self.register_command('perform', McTransferPerformCommand())

mc_transfer_target_parser = argparse.ArgumentParser(add_help=False)
mc_transfer_target_parser.add_argument('--target-name', dest='target_name', help='Target enterprise name')
mc_transfer_target_parser.add_argument('--target-email', dest='target_email', help='Target administrator email')

mc_transfer_join_msp_parser = argparse.ArgumentParser(
    prog='mc-transfer join-msp', description='Initializes Regular/MC/MSP transfer to MSP', parents=[mc_transfer_target_parser])

mc_transfer_leave_msp_parser = argparse.ArgumentParser(
    prog='mc-transfer leave-msp', description='Initializes MC leaving MSP', parents=[mc_transfer_target_parser])

mc_transfer_accept_mc_parser = argparse.ArgumentParser(
    prog='mc-transfer accept-mc', description='MSP accepts Regular/MC/MSP transfer', parents=[mc_transfer_target_parser])

mc_transfer_status_parser = argparse.ArgumentParser(
    prog='mc-transfer status', description='Checks MC transfer status', parents=[mc_transfer_target_parser])

mc_transfer_cancel_parser = argparse.ArgumentParser(
    prog='mc-transfer cancel', description='Cancels MC transfer', parents=[mc_transfer_target_parser])

mc_transfer_perform_parser = argparse.ArgumentParser(
    prog='mc-transfer perform', description='Completes MC transfer', parents=[mc_transfer_target_parser])


class EnterpriseType(enum.Enum):
    Unknown = 0,
    Trial = 1,
    Regular = 2,
    MSP = 3,
    MC = 4,
    Distributor = 5


class McTransferMixin:
    @staticmethod
    def transfer_status_to_text(status: MCTransfer_pb2.MCTransferStatus) -> str:
        if status == MCTransfer_pb2.MCTransferStatus.STATUS_INVALID:
            return 'Invalid'
        if status == MCTransfer_pb2.MCTransferStatus.STATUS_REQUESTED:
            return 'Requested'
        if status == MCTransfer_pb2.MCTransferStatus.STATUS_ACCEPTED:
            return 'Accepted'
        if status == MCTransfer_pb2.MCTransferStatus.STATUS_PENDING_APPROVAL:
            return 'Pending'
        if status == MCTransfer_pb2.MCTransferStatus.STATUS_DENIED:
            return 'Denied'
        if status == MCTransfer_pb2.MCTransferStatus.STATUS_APPROVED:
            return 'Approved'
        return 'Unsupported'

    @staticmethod
    def get_transfer_parameters(command_name: str, **kwargs) -> Tuple[str, str]:
        enterprise_name = kwargs.get('target_name')
        if not enterprise_name:
            raise error.CommandError(command_name, 'Target enterprise name cannot be empty')

        enterprise_email = kwargs.get('target_email')
        if not enterprise_email:
            raise error.CommandError(command_name, 'Target enterprise admin email cannot be empty')
        return enterprise_name, enterprise_email

    @staticmethod
    def get_enterprise_license(params) -> EnterpriseType:
        licenses = params.enterprise.get('licenses', [])
        if isinstance(licenses, list) and licenses:
            lic = licenses[0]
            if isinstance(lic, dict):
                product_type_id = lic.get('product_type_id', 0)
                if product_type_id in (3, 5):
                    return EnterpriseType.Regular
                elif product_type_id in (9, 10):
                    distributor = lic.get('distributor', False)
                    return EnterpriseType.Distributor if distributor else EnterpriseType.MSP
                elif product_type_id in (11, 12):
                    return EnterpriseType.MSP
                elif product_type_id == 8:
                    return EnterpriseType.MC
                if product_type_id in (5, 10, 12):
                    return EnterpriseType.Trial
        return EnterpriseType.Unknown

    @staticmethod
    def selected_managed_companies(params) -> Set[int]:
        CHECKBOX_EMPTY = "[ ]"
        CHECKBOX_X = "[x]"

        managed_companies = params.enterprise.get('managed_companies')
        selected_mc: Set[int] = set()
        if isinstance(managed_companies, list) and managed_companies:
            headers = ['', 'MC ID', 'MC Name', 'Seats']
            mcs: List[List[Any]] = []
            for mc in managed_companies:
                seats = mc.get('number_of_seats')
                if seats > 2000000:
                    seats = '*'
                mcs.append([mc.get('mc_enterprise_id'), mc.get('mc_enterprise_name'), seats])
            mcs.sort(key=lambda x: x[0])
            while True:
                table = []
                for mc in mcs:
                    selected = mc[0] in selected_mc
                    row = [CHECKBOX_X if selected else CHECKBOX_EMPTY]
                    row.extend(mc)
                    table.append(row)
                base.dump_report_data(table, headers)
                answer = input('Select managed companies to transfer ([a]ll, [n]one, [d]one or list of MC IDs): ')
                answer = answer.lower()
                if answer in ['a', 'all']:
                    selected_mc.clear()
                    selected_mc.update([x[0] for x in mcs])
                elif answer in ['n', 'none']:
                    selected_mc.clear()
                elif answer in ['d', 'done']:
                    break
                else:
                    answer = answer.replace(',', ' ')
                    mc_ids = answer.split()
                    for mc_id in mc_ids:
                        try:
                            id_mc = int(mc_id)
                            mc = next((x for x in mcs if x[0] == id_mc), None)
                            if mc:
                                selected_mc.add(id_mc)
                            else:
                                logging.info(f'"{mc_id}" is not a valid Managed Company ID')
                        except:
                            logging.info(f'"{mc_id}" is not a valid Managed Company ID')
            if len(selected_mc) == len(managed_companies):
                answer = base.user_choice('Do you want to transfer MSP company as well?', 'yn', 'n')
                if answer.lower() == 'y':
                    selected_mc.add(params.enterprise_id)

        return selected_mc

class McTransferJoinMspCommand(enterprise_common.EnterpriseCommand, McTransferMixin):
    def get_parser(self):
        return mc_transfer_join_msp_parser

    def execute(self, params, **kwargs):
        enterprise_name, enterprise_email = self.get_transfer_parameters('mc-transfer join-msp', **kwargs)
        enterprise_type = self.get_enterprise_license(params)
        if enterprise_type not in (EnterpriseType.Regular, EnterpriseType.MSP, EnterpriseType.MC, EnterpriseType.Distributor):
            raise error.CommandError('mc-transfer join-msp', 'Command is available to Regular, MSP, and MC enterprises')

        rq = MCTransfer_pb2.MCTransferRequest()
        rq.enterpriseName = enterprise_name
        rq.enterpriseAdminEmail = enterprise_email
        if enterprise_type == EnterpriseType.MSP:
            selected_mcs = self.selected_managed_companies(params)
            if len(selected_mcs) > 0:
                for mc_id in selected_mcs:
                    mct = MCTransfer_pb2.MCTransferTreeKey()
                    mct.enterpriseId = mc_id
                    rq.mcTransferTreeKeys.append(mct)
            else:
                raise error.CommandError('mc-transfer join-msp', 'No Managed Companies to transfer selected')

        try:
            api.communicate_rest(params, rq, 'enterprise/mc_transfer_join_msp')
        except error.KeeperApiError as kae:
            raise error.CommandError('mc-transfer join-msp', kae.message)


class McTransferStatusCommand(enterprise_common.EnterpriseCommand, McTransferMixin):
    def get_parser(self):
        return mc_transfer_status_parser

    def execute(self, params, **kwargs):
        enterprise_name = kwargs.get('target_name')
        enterprise_email = kwargs.get('target_email')

        enterprise_type = self.get_enterprise_license(params)
        if enterprise_type not in (EnterpriseType.Regular, EnterpriseType.MSP, EnterpriseType.MC, EnterpriseType.Distributor):
            raise error.CommandError('mc-transfer status', 'Command is available to Regular, MSP, and MC enterprises')

        rq = MCTransfer_pb2.MCTransferRequest()
        if enterprise_name:
            rq.enterpriseName = enterprise_name
        if enterprise_email:
            rq.enterpriseAdminEmail = enterprise_email
        transfer: Optional[MCTransfer_pb2.MCTransferState]
        transfer = api.communicate_rest(params, rq, 'enterprise/mc_transfer_status', rs_type=MCTransfer_pb2.MCTransferState)
        if transfer:
            headers = ['from_enterprise_name', 'from_admin_email', 'target_enterprise_name', 'target_admin_email', 'status', 'comments']
            status_text = self.transfer_status_to_text(transfer.transferStatus)
            row: List[Any] = [transfer.movingEnterpriseName, transfer.movingEnterpriseAdminEmail, transfer.receivingEnterpriseName,
                   transfer.receivingEnterpriseAdminEmail, status_text, transfer.comments]
            if transfer.mcTransferEnterprises:
                headers.append('managed_companies')
                row.append([f'{x.enterpriseId:-8} : {x.enterpriseName}' for x in transfer.mcTransferEnterprises])

            headers = [report_utils.field_to_title(x) for x in headers]
            table = [[x[0], x[1]] for x in zip(headers, row)]
            headers = [report_utils.field_to_title(x) for x in ['property', 'value']]
            return base.dump_report_data(table, headers)
        else:
            raise error.CommandError('mc-transfer status', 'MC Transfer status is empty')


class McTransferCancelCommand(enterprise_common.EnterpriseCommand, McTransferMixin):
    def get_parser(self):
        return mc_transfer_cancel_parser

    def execute(self, params, **kwargs):
        enterprise_name, enterprise_email = self.get_transfer_parameters('mc-transfer cancel', **kwargs)
        enterprise_type = self.get_enterprise_license(params)
        if enterprise_type not in (EnterpriseType.MSP, EnterpriseType.MC, EnterpriseType.Distributor):
            raise error.CommandError('mc-transfer cancel', 'Command is available to MSP and MC enterprises')

        rq = MCTransfer_pb2.MCTransferRequest()
        rq.enterpriseName = enterprise_name
        rq.enterpriseAdminEmail = enterprise_email
        try:
            api.communicate_rest(params, rq, 'enterprise/mc_transfer_cancel')
        except error.KeeperApiError as kae:
            raise error.CommandError('mc-transfer cancel', kae.message)


class McTransferLeaveMspCommand(enterprise_common.EnterpriseCommand, McTransferMixin):
    def get_parser(self):
        return mc_transfer_leave_msp_parser

    def execute(self, params, **kwargs):
        enterprise_type = self.get_enterprise_license(params)
        if enterprise_type != EnterpriseType.MC:
            raise error.CommandError('mc-transfer leave-msp', 'Command is available to Managed Companies (MC)')
        try:
            api.communicate_rest(params, None, 'enterprise/mc_transfer_leave_msp')
        except error.KeeperApiError as kae:
            raise error.CommandError('mc-transfer leave-msp', kae.message)


class McTransferAcceptMcCommand(enterprise_common.EnterpriseCommand, McTransferMixin):
    def get_parser(self):
        return mc_transfer_accept_mc_parser

    def execute(self, params, **kwargs):
        enterprise_name, enterprise_email = self.get_transfer_parameters('mc-transfer accept-mc', **kwargs)
        enterprise_type = self.get_enterprise_license(params)
        if enterprise_type not in (EnterpriseType.MSP, EnterpriseType.Distributor):
            raise error.CommandError('mc-transfer accept-mc', 'Command is available to MSP')

        try:
            rq = MCTransfer_pb2.MCTransferRequest()
            rq.enterpriseName = enterprise_name
            rq.enterpriseAdminEmail = enterprise_email
            api.communicate_rest(params, rq, 'enterprise/mc_transfer_accept_mc')
        except error.KeeperApiError as kae:
            raise error.CommandError('mc-transfer accept-mc', kae.message)


class McTransferPerformCommand(enterprise_common.EnterpriseCommand, McTransferMixin):
    def get_parser(self):
        return mc_transfer_perform_parser

    def execute(self, params, **kwargs):
        enterprise_name, enterprise_email = self.get_transfer_parameters('mc-transfer perform', **kwargs)
        enterprise_type = self.get_enterprise_license(params)
        if enterprise_type not in (EnterpriseType.MSP, EnterpriseType.MC, EnterpriseType.Regular):
            raise error.CommandError('mc-transfer perform', 'Command is available to Regular, MSP, and MC enterprises')

        rq = MCTransfer_pb2.MCTransferRequest()
        rq.enterpriseName = enterprise_name
        rq.enterpriseAdminEmail = enterprise_email
        transfer: Optional[MCTransfer_pb2.MCTransferState]
        transfer = api.communicate_rest(params, rq, 'enterprise/mc_transfer_status', rs_type=MCTransfer_pb2.MCTransferState)
        if transfer.transferStatus != MCTransfer_pb2.MCTransferStatus.STATUS_APPROVED:
            raise error.CommandError('mc-transfer perform', 'The transfer has not been approved')


        rq = MCTransfer_pb2.MCTransferRequest()
        rq.enterpriseName = enterprise_name
        rq.enterpriseAdminEmail = enterprise_email

        if transfer.receivingEnterpriseName:
            public_key_rs: Optional[breachwatch_pb2.EnterprisePublicKeyResponse]
            public_key_rs = api.communicate_rest(params, rq, 'enterprise/mc_transfer_get_public_key', rs_type=breachwatch_pb2.EnterprisePublicKeyResponse)
            if not public_key_rs:
                raise error.CommandError('mc-transfer perform', 'Failed to get transfer key')

            rsa_key: Optional[RSAPublicKey] = None
            ec_key: Optional[EllipticCurvePublicKey] = None
            if len(public_key_rs.enterprisePublicKey) > 0:
                rsa_key = crypto.load_rsa_public_key(public_key_rs.enterprisePublicKey)
            elif len(public_key_rs.enterpriseECCPublicKey):
                ec_key = crypto.load_ec_public_key(public_key_rs.enterpriseECCPublicKey)
            else:
                raise error.CommandError('mc-transfer perform', 'Failed to get transfer key')

            enterprise_tree_key = params.enterprise['unencrypted_tree_key']
            transfer_self = False
            if len(transfer.mcTransferEnterprises) > 0:
                managed_companies = params.enterprise.get('managed_companies')
                has_failed_mc = False
                for mct in transfer.mcTransferEnterprises:
                    id_mc = mct.enterpriseId
                    if id_mc == params.enterprise_id:
                        transfer_self = True
                    else:
                        mc = next((x for x in managed_companies if x.get('mc_enterprise_id') == id_mc), None)
                        if mc:
                            encrypted_tree_key = utils.base64_url_decode(mc['tree_key'])
                            if enterprise_tree_key:
                                try:
                                    tree_key = crypto.decrypt_aes_v2(encrypted_tree_key, enterprise_tree_key)
                                    if ec_key:
                                        encrypted_tree_key = crypto.encrypt_ec(tree_key, ec_key)
                                    else:
                                        encrypted_tree_key = crypto.encrypt_rsa(tree_key, rsa_key)
                                    key = MCTransfer_pb2.MCTransferTreeKey()
                                    key.enterpriseId = id_mc
                                    key.treeKey = encrypted_tree_key
                                    rq.mcTransferTreeKeys.append(key)
                                except:
                                    logging.info(f'"{id_mc}" cannot decrypt encryption key')
                                    has_failed_mc = True
                if has_failed_mc:
                    transfer_self = False
            elif transfer.movingEnterpriseId == params.enterprise_id:
                transfer_self = True

            if transfer_self:
                try:
                    if ec_key:
                        encrypted_tree_key = crypto.encrypt_ec(enterprise_tree_key, ec_key)
                    else:
                        encrypted_tree_key = crypto.encrypt_rsa(enterprise_tree_key, rsa_key)
                    key = MCTransfer_pb2.MCTransferTreeKey()
                    key.enterpriseId = params.enterprise_id
                    key.treeKey = encrypted_tree_key
                    rq.mcTransferTreeKeys.append(key)
                except:
                    logging.warning(f'Failed to encrypt enterprise key: ID: {transfer.movingEnterpriseId}, Name: {transfer.movingEnterpriseName}')
            if len(rq.mcTransferTreeKeys) == 0:
                raise error.CommandError('mc-transfer perform', 'No enterprise to transfer')
        try:
            api.communicate_rest(params, rq, 'enterprise/mc_transfer_perform')
        except error.KeeperApiError as kae:
            raise error.CommandError('mc-transfer perform', kae.message)
