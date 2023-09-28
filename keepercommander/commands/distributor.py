#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import json
import fnmatch
import logging
import re
from typing import Optional, Set

from .base import GroupCommand, dump_report_data
from .enterprise import EnterpriseCommand
from .. import api, constants
from ..error import CommandError
from ..params import KeeperParams
from ..proto import enterprise_pb2

distributor_info_parser = argparse.ArgumentParser(prog='distributor info')
distributor_info_parser.add_argument('--reload', dest='reload', action='store_true', help='reload distributors')
distributor_info_parser.add_argument('--mc-details', dest='mc_details', action='store_true', help='Display MC details')
distributor_info_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Display verbose information')
distributor_info_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                                     default='table', help='output format.')
distributor_info_parser.add_argument('--output', dest='output', action='store',
                                     help='output file name. (ignored for table format)')

distributor_msp_info_parser = argparse.ArgumentParser(prog='distributor msp-info')
distributor_msp_info_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Display verbose information')
distributor_msp_info_parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                                         default='table', help='output format.')
distributor_msp_info_parser.add_argument('--output', dest='output', action='store',
                                         help='output file name. (ignored for table format)')
distributor_msp_info_parser.add_argument('msp', action='store', metavar='MSP_NAME',
                                         help='Managed Company Provider identifier (name or ID).')


distributor_license_parser = argparse.ArgumentParser(prog='distributor license')
distributor_license_parser.add_argument('--add-product', dest='add_product', action='append',
                                        choices=[x[1] for x in constants.MSP_PLANS],
                                        help='Allows MSP to use product. Can be repeated')
distributor_license_parser.add_argument('--remove-product', dest='remove_product', action='append',
                                        choices=[x[1] for x in constants.MSP_PLANS],
                                        help='Disables MSP to use product. Can be repeated')
distributor_license_parser.add_argument('--add-addon', dest='add_addon', action='append',
                                        choices=[x[0] for x in constants.MSP_ADDONS],
                                        help='Allows MSP to use add-on. Can be repeated')
distributor_license_parser.add_argument('--remove-addon', dest='remove_addon', action='append',
                                        choices=[x[0] for x in constants.MSP_ADDONS],
                                        help='Disables MSP to use add-on. Can be repeated')
distributor_license_parser.add_argument('--max-file-plan', dest='max_file_plan', action='store',
                                        choices=[x[2] for x in constants.MSP_FILE_PLANS],
                                        help='Maximum available file plan.')
distributor_license_parser.add_argument('--allocate-unlimited', dest='allocate_unlimited', action='store', choices=['on', 'off'],
                                        help='Allow MSPs to allocate unlimited licenses.')
distributor_license_parser.add_argument('msp', action='store', metavar='MSP_NAME', nargs='*',
                                        help='Managed Company Provider (name, ID, or name pattern).')


class DistributorCommand(GroupCommand):
    def __init__(self):
        super(DistributorCommand, self).__init__()
        self.register_command('info', DistributorInfoCommand(), description='Lists information about MSPs', alias='i')
        self.register_command('license', DistributorLicenseCommand(), alias='l',
                              description='Lists or changes available products/addons/file plans for named MSP (name or ID)')
        self.register_command('msp-info', DistributorMspInfoCommand(), alias='mi',
                              description='Lists MSP info for named MSP (name or ID)')

        self.default_verb = 'info'


class DistributorMixin:
    @staticmethod
    def convert_add_ons(add_on):  # type: (enterprise_pb2.LicenseAddOn) -> dict
        return {
            'name': add_on.name,
            'enabled': add_on.enabled,
            'is_trial': add_on.isTrial,
            'expiration': add_on.expiration,
            'created': add_on.created,
            'seats': add_on.seats,
            'activation_time': add_on.activationTime,
            'included_in_product': add_on.includedInProduct,
            'api_call_count': add_on.apiCallCount
        }

    @staticmethod
    def get_distributor_list(params, reload=False):
        # type: (KeeperParams, Optional[bool]) -> Optional[list]
        if not params.enterprise:
            return

        if reload is True:
            if 'distributors' in params.enterprise:
                del params.enterprise['distributors']
        if 'distributors' not in params.enterprise:
            rs = api.communicate_rest(params, None, 'distributor/get_distributor_info',
                                      rs_type=enterprise_pb2.GetDistributorInfoResponse)
            msps = []
            for d in rs.distributors:
                distributor_name = d.name
                for p_msp in d.mspInfos:
                    msp = {
                        'distributor_name': distributor_name,
                        'enterprise_id': p_msp.enterpriseId,
                        'enterprise_name': p_msp.enterpriseName,
                        'allocated_licenses': p_msp.allocatedLicenses,
                        'allowed_mc_products': list(p_msp.allowedMcProducts),
                        'allowed_add_ons': list(p_msp.allowedAddOns),
                        'max_file_plan_type': p_msp.maxFilePlanType,
                        'managed_companies': [],
                        'allow_unlimited_licenses': p_msp.allowUnlimitedLicenses,
                        'add_ons': [DistributorMixin.convert_add_ons(x) for x in p_msp.addOns]
                    }
                    for p_mc in p_msp.managedCompanies:
                        mc = {
                            'mc_enterprise_id': p_mc.mcEnterpriseId,
                            'mc_enterprise_name': p_mc.mcEnterpriseName,
                            'msp_node_id': p_mc.mspNodeId,
                            'number_of_seats': p_mc.numberOfSeats,
                            'number_of_users': p_mc.numberOfUsers,
                            'product_id': p_mc.productId,
                            'is_expired': p_mc.isExpired,
                            'file_plan_type': p_mc.filePlanType,
                            'add_ons': [DistributorMixin.convert_add_ons(x) for x in p_mc.addOns]
                        }
                        msp['managed_companies'].append(mc)
                    msps.append(msp)
            params.enterprise['distributors'] = msps

        return params.enterprise.get('distributors')

    @staticmethod
    def get_msp(params, msp_name, reload=False):    # type: (KeeperParams, str, bool) -> Optional[dict]
        msps = DistributorMixin.get_distributor_list(params, reload)
        msp_name_l = msp_name.lower() if isinstance(msp_name, str) else str(msp_name)
        return next((x for x in msps if str(x['enterprise_id']) == msp_name_l or x['enterprise_name'].lower() == msp_name_l), None)


class DistributorInfoCommand(EnterpriseCommand, DistributorMixin):
    def get_parser(self):
        return distributor_info_parser

    def execute(self, params, **kwargs):
        msps = DistributorMixin.get_distributor_list(params, kwargs.get('reload'))
        if not isinstance(msps, list):
            raise CommandError('', 'This command is only available for Distributors.')

        show_mc_details = kwargs.get('mc_details') is True
        output_format = kwargs.get('format', 'table')
        verbose = kwargs.get('verbose') is True
        if output_format == 'json':
            return json.dumps(msps, indent=4)
        else:
            right_align = (2, 4, 5) if show_mc_details else (2, 3, 4)
            header = ['ID', 'MSP Name', '# MC\'s']
            if show_mc_details:
                header.extend(('MC Name', 'Plan', 'Storage', 'Total Licenses'))
            else:
                header.extend(('Unlimited allowed', 'Allowed Addons'))
            header.extend(['Licenses used', 'KSM', 'KCM', 'Addons'])
            addon_lookup = {x[0]: x[3] for x in constants.MSP_ADDONS}

            table = []
            for msp in msps:
                msp_name = msp.get('enterprise_name')
                if len(msp_name) > 40 and not verbose:
                    msp_name = msp_name[:37] + '...'
                row = [msp.get('enterprise_id'), msp_name, len(msp.get('managed_companies', []))]
                if show_mc_details:
                    row.extend((None, None, None, None))
                else:
                    unlimited_allowed = msp.get('allow_unlimited_licenses')
                    row.extend(('Allowed' if unlimited_allowed else 'Not Allowed',
                                [addon_lookup.get(x.lower(), x) for x in msp.get('allowed_add_ons', [])]))
                add_ons = msp.get('add_ons', [])
                kcm = next((x for x in add_ons if x and x['name'].lower() == 'connection_manager'), None)
                kcm_text = 'enabled' if kcm else 'disabled'
                if kcm:
                    seats = kcm.get("seats")
                    if isinstance(seats, int) and seats > 0:
                        kcm_text = f'{seats} seats'

                ksm = next((x for x in add_ons if x and x['name'].lower() == 'secrets_manager'), None)
                ksm_text = 'enabled' if ksm else 'disabled'
                if ksm:
                    apis = ksm.get("api_call_count")
                    if isinstance(apis, int) and apis > 0:
                        ksm_text = f'{apis} Calls/Month'

                add_ons = [x['name'] for x in add_ons
                           if x['name'].lower() not in {'connection_manager', 'secrets_manager'} and
                           not x['included_in_product']]

                row.extend((msp.get('allocated_licenses'),
                            ksm_text, kcm_text,
                            [addon_lookup.get(x.lower(), x) for x in add_ons]))
                table.append(row)

                if show_mc_details:
                    product_lookup = {x[1]: x[2] for x in constants.MSP_PLANS}
                    file_plan_lookup = {x[1]: x[2] for x in constants.MSP_FILE_PLANS}
                    for mc in msp.get('managed_companies', []):
                        mc_name = mc.get('mc_enterprise_name')
                        product = mc.get('product_id')
                        product = product_lookup.get(product, product)
                        file_plan = mc.get('file_plan_type')
                        file_plan = file_plan_lookup.get(file_plan, file_plan)
                        is_expired = mc.get('is_expired', False)
                        if len(mc_name) > 40 and not verbose:
                            mc_name = mc_name[:37] + '...'
                        total_licences = mc.get('number_of_seats')
                        if total_licences > 2000000000:
                            total_licences = 'Unlimited'
                        used = '-' if is_expired else mc.get('number_of_users')

                        add_ons = list(mc.get('add_ons'))
                        kcm = next((x for x in add_ons if x and x['name'].lower() == 'connection_manager'), None)
                        kcm_text = 'enabled' if kcm else 'disabled'
                        if kcm:
                            seats = kcm.get("seats")
                            if isinstance(seats, int) and seats > 0:
                                kcm_text = f'{seats} seats'
                        ksm = next((x for x in add_ons if x and x['name'].lower() == 'secrets_manager'), None)
                        ksm_text = 'enabled' if ksm else 'disabled'
                        if ksm:
                            apis = ksm.get("api_call_count")
                            if isinstance(apis, int) and apis > 0:
                                ksm_text = f'{apis} Calls/Month'
                        add_ons = [x['name'] for x in add_ons
                                   if x['name'].lower() not in {'connection_manager', 'secrets_manager'} and
                                   not x['included_in_product']]

                        row = [mc.get('mc_enterprise_id'), msp_name, None,
                               mc_name, product, file_plan, total_licences,
                               used, ksm_text, kcm_text,
                               [addon_lookup.get(x.lower(), x) for x in add_ons]]
                        table.append(row)

            return dump_report_data(table, header, fmt=output_format, filename=kwargs.get('output'), row_number=True,
                                    right_align=right_align)


class DistributorMspInfoCommand(EnterpriseCommand, DistributorMixin):
    def get_parser(self):
        return distributor_msp_info_parser

    def execute(self, params, **kwargs):
        msp_name = kwargs.get('msp')
        if not msp_name:
            raise CommandError('', '"msp" parameter is required.')
        msp = DistributorMixin.get_msp(params, msp_name)
        if not msp:
            raise CommandError('', f'MSP \"{msp_name}\" not found.')

        product_lookup = {x[1]: x[2] for x in constants.MSP_PLANS}
        file_plan_lookup = {x[1]: x[2] for x in constants.MSP_FILE_PLANS}
        addon_lookup = {x[0]: x[3] for x in constants.MSP_ADDONS}
        output_format = kwargs.get('format', 'table')
        verbose = kwargs.get('verbose') is True
        if output_format == 'json':
            return json.dumps(msp, indent=4)
        else:
            header = ['ID', 'MC Name', 'Node ID', 'Plan', 'Storage', 'Addons', 'Allocated', 'Active']
            table = []
            for mc in msp.get('managed_companies', []):
                mc_name = mc.get('mc_enterprise_name')
                if len(mc_name) > 40 and not verbose:
                    mc_name = mc_name[:37] + '...'
                msp_node_id = mc.get('msp_node_id')
                allowed = mc.get('number_of_seats')
                is_expired = mc.get('is_expired', False)
                if allowed > 2000000000:
                    allowed = 'Unlimited'
                used = '-' if is_expired else mc.get('number_of_users')
                add_ons = list(mc.get('add_ons'))
                if verbose:
                    ao = []
                    for x in add_ons:
                        addon_name = addon_lookup.get(x['name'], x['name'])
                        seats = x.get('seats', 0)
                        if seats > 0:
                            addon_name += f' ({seats})'
                        ao.append(addon_name)
                    ao.sort()
                    addons = '\n'.join(ao)
                else:
                    addons = len(add_ons)
                product = mc.get('product_id')
                product = product_lookup.get(product, product)
                file_plan = mc.get('file_plan_type')
                file_plan = file_plan_lookup.get(file_plan, file_plan)
                row = [mc.get('mc_enterprise_id'), mc_name, msp_node_id, product, file_plan, addons, allowed, used]

                table.append(row)

            right_align = (6, 7) if verbose else (5, 6, 7)
            return dump_report_data(table, header, fmt=output_format, filename=kwargs.get('output'), row_number=True, right_align=right_align)


class DistributorLicenseCommand(EnterpriseCommand, DistributorMixin):
    def get_parser(self):
        return distributor_license_parser

    def execute(self, params, **kwargs):
        msp_dict = {x['enterprise_id']: x for x in  DistributorMixin.get_distributor_list(params, False)}
        msps = set()  # type: Set[int]

        msp_names = kwargs.get('msp')
        if msp_names:
            if isinstance(msp_names, (str, int)):
                msp_names = [msp_names]

            for msp_name in msp_names:
                if isinstance(msp_name, int) or isinstance(msp_name, str) and msp_name.isnumeric():
                    try:
                        msp_id = int(msp_name)
                        if msp_id in msp_dict:
                            msps.add(msp_id)
                    except:
                        pass
                if isinstance(msp_name, str):
                    pattern = fnmatch.translate(msp_name)
                    for msp_id, msp in msp_dict.items():
                        if re.match(pattern, msp['enterprise_name'], re.IGNORECASE):
                            msps.add(msp_id)
        else:
            edit_opts = {'add_product', 'remove_product', 'add_addon', 'remove_addon', 'max_file_plan', 'allocate_unlimited'}
            if edit_opts.intersection((key for key, value in kwargs.items() if value)):
                logging.warning('Changes to MSP configuration will be ignored.\nPass MSP ID, name, or name search pattern.')

        if len(msps) > 0:
            for msp_id in msps:
                msp = msp_dict[msp_id]

                has_updates = False
                products = set((x.lower() for x in msp['allowed_mc_products']))
                add_products = kwargs.get('add_product')
                if isinstance(add_products, str):
                    add_products = [add_products]
                remove_products = kwargs.get('remove_product')
                if isinstance(remove_products, str):
                    remove_products = [remove_products]

                if add_products or remove_products:
                    has_updates = True
                    all_products = {x[1].lower() for x in constants.MSP_PLANS}
                    if isinstance(add_products, (list, tuple)):
                        for product in add_products:
                            product = product.lower()
                            if product not in all_products:
                                raise CommandError('', f'Unknown Product: {product}')
                            products.add(product)

                    if isinstance(remove_products, (list, tuple)):
                        for product in remove_products:
                            product = product.lower()
                            if product not in all_products:
                                raise CommandError('', f'Unknown Product: {product}')
                            if product in products:
                                products.remove(product)

                addons = set((x.lower() for x in msp['allowed_add_ons']))
                add_addons = kwargs.get('add_addon')
                if isinstance(add_addons, str):
                    add_addons = [add_addons]
                remove_addons = kwargs.get('remove_addon')
                if isinstance(remove_addons, str):
                    remove_addons = [remove_addons]

                if add_addons or remove_addons:
                    has_updates = True
                    all_addons = {x[0].lower() for x in constants.MSP_ADDONS}
                    if isinstance(add_addons, (list, tuple)):
                        for addon in add_addons:
                            if addon.lower() not in all_addons:
                                raise CommandError('', f'Unknown Add On: {addon}')
                            addons.add(addon.lower())

                    if isinstance(remove_addons, (list, tuple)):
                        for addon in remove_addons:
                            addon = addon.lower()
                            if addon not in all_addons:
                                raise CommandError('', f'Unknown product: {addon}')
                            if addon in addons:
                                addons.remove(addon)

                max_file_plan = msp['max_file_plan_type']
                file_plan = kwargs.get('max_file_plan')
                if file_plan and isinstance(file_plan, str):
                    has_updates = True
                    all_plans = {x[2].lower(): x[1] for x in constants.MSP_FILE_PLANS}
                    l_file_plan = file_plan.lower()
                    if l_file_plan not in all_plans:
                        raise CommandError('', f'Unknown File Plan: {file_plan}')
                    max_file_plan = all_plans[l_file_plan]

                allow_unlimited = msp['allow_unlimited_licenses']  # type: bool
                allocate_unlimited = kwargs.get('allocate_unlimited')
                if allocate_unlimited:
                    if allocate_unlimited == 'on':
                        allow_unlimited = True
                    else:
                        allow_unlimited = False
                    if msp.get('allow_unlimited_licenses') != allow_unlimited:
                        has_updates = True

                if has_updates:
                    if len(msps) > 1:
                        logging.info('Updating %s', msp['enterprise_name'])
                    rq = enterprise_pb2.UpdateMSPPermitsRequest()
                    rq.mspEnterpriseId = msp['enterprise_id']
                    rq.allowUnlimitedLicenses = allow_unlimited
                    all_products = {x[1].lower(): x[1] for x in constants.MSP_PLANS}
                    rq.allowedMcProducts.extend(all_products.get(x, x) for x in products)
                    all_addons = {x[0].lower(): x[0] for x in constants.MSP_ADDONS}
                    rq.allowedAddOns.extend(all_addons.get(x, x) for x in addons)
                    rq.maxFilePlanType = max_file_plan

                    api.communicate_rest(params, rq, 'distributor/update_msp_permits')
            msp_dict = {x['enterprise_id']: x for x in  DistributorMixin.get_distributor_list(params, True)}
        else:
            if msp_names:
                logging.warning('MSP \"%s\" not found.', ', '.join(msp_names))

        # display
        table = []
        header = ['MSP ID', 'MSP Name', 'Unlimited Allowed', 'Allowed Products', 'Allowed Addons', 'Max File Plan']
        for msp_id, msp in msp_dict.items():
            if len(msps) > 0 and msp_id not in msps:
                continue

            row = [msp['enterprise_id'], msp['enterprise_name'], msp['allow_unlimited_licenses']]
            products = msp['allowed_mc_products']
            if products and isinstance(products, list):
                all_products = {x[1].lower(): x[2] for x in constants.MSP_PLANS}
                products = [x + f' ({all_products.get(x.lower(), "")})' for x in products]
            else:
                products = None
            row.append(products)

            addons = msp['allowed_add_ons']
            if addons and isinstance(addons, list):
                all_addons = {x[0].lower(): x[3] for x in constants.MSP_ADDONS}
                addons = [x.lower() + f' ({all_addons.get(x.lower(), "")})' for x in addons]
            else:
                addons = None
            row.append(addons)

            max_file_plan = msp['max_file_plan_type']
            all_file_plans = {x[1].lower(): x[2] for x in constants.MSP_FILE_PLANS}
            row.append(all_file_plans.get(max_file_plan.lower(), max_file_plan))
            table.append(row)
        dump_report_data(table, headers=header, right_align=(0,))
