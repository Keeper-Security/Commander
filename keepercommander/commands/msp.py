#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import calendar
import datetime
import json
import logging
import os
from typing import Set, Dict, List, Iterable, Any, Tuple, Union
from urllib.parse import urlparse, urlunparse

from .base import dump_report_data, user_choice, field_to_title
from .enterprise import EnterpriseCommand
from .. import api, crypto, utils, loginv3, error, constants
from ..params import KeeperParams
from ..display import bcolors
from ..error import CommandError
from ..proto import enterprise_pb2, BI_pb2


def register_commands(commands):
    commands['msp-down'] = GetMSPDataCommand()
    commands['msp-info'] = MSPInfoCommand()
    commands['msp-add'] = MSPAddCommand()
    commands['msp-remove'] = MSPRemoveCommand()
    commands['msp-update'] = MSPUpdateCommand()
    commands['msp-legacy-report'] = MSPLegacyReportCommand()
    commands['msp-billing-report'] = MSPBillingReportCommand()
    commands['msp-convert-node'] = MSPConvertNodeCommand()
    commands['msp-copy-role'] = MSPCopyRoleCommand()


def register_command_info(aliases, command_info):
    aliases['md'] = 'msp-down'
    aliases['mi'] = 'msp-info'
    aliases['ma'] = 'msp-add'
    aliases['mrm'] = 'msp-remove'
    aliases['mu'] = 'msp-update'
    aliases['mlr'] = 'msp-legacy-report'
    aliases['mbr'] = 'msp-billing-report'

    for p in [msp_data_parser, msp_info_parser, msp_add_parser, msp_remove_parser, msp_update_parser,
              msp_copy_role_parser, msp_legacy_report_parser, msp_billing_report_parser]:
        command_info[p.prog] = p.description


msp_data_parser = argparse.ArgumentParser(prog='msp-down|md', usage='msp-down',
                                          description='Download current MSP data from the Keeper Cloud.')

msp_info_parser = argparse.ArgumentParser(prog='msp-info|mi', usage='msp-info',
                                          description='Displays MSP details, such as managed companies and pricing.')
msp_info_parser.add_argument('-p', '--pricing', dest='pricing', action='store_true', help='Display pricing information')
msp_info_parser.add_argument('-r', '--restriction', dest='restriction', action='store_true', help='Display MSP restriction information')
msp_info_parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Print details')
# msp_info_parser.add_argument('-u', '--users', dest='users', action='store_true', help='print user list')

msp_update_parser = argparse.ArgumentParser(prog='msp-update', usage='msp-update',
                                            description='Modify Managed Company license.')
msp_update_parser.add_argument('-p', '--plan', dest='plan', action='store',
                               choices=['business', 'businessPlus', 'enterprise', 'enterprisePlus'],
                               help=f'License plan: {", ".join((x[1] for x in constants.MSP_PLANS))}')
msp_update_parser.add_argument('-s', '--seats', dest='seats', action='store', type=int,
                               help='Maximum licences allowed. -1: unlimited')
msp_update_parser.add_argument('-f', '--file-plan', dest='file_plan', action='store',
                               help=f'File storage plan: {", ".join((x[2].lower() for x in constants.MSP_FILE_PLANS))}')
msp_update_parser.add_argument('-aa', '--add-addon', dest='add_addon', action='append', metavar='ADDON[:SEATS]',
                               help=f'Add add-ons: {", ".join(((x[0]+(":N" if x[2] else "")) for x in constants.MSP_ADDONS))}')
msp_update_parser.add_argument('-ra', '--remove-addon', dest='remove_addon', action='append', metavar='ADDON',
                               help=f'Add add-ons: {", ".join((x[0] for x in constants.MSP_ADDONS))}')
msp_update_parser.add_argument('mc', action='store',
                               help='Managed Company identifier (name or id). Ex. 3862 OR "Keeper Security, Inc."')

ranges = ['today', 'yesterday', 'last_7_days', 'last_30_days', 'month_to_date', 'last_month', 'year_to_date', 'last_year']
msp_legacy_report_parser = argparse.ArgumentParser(prog='msp-legacy-report',
                                                   description='Generate MSP Legacy Report.')
msp_legacy_report_parser.add_argument('--format', dest='format', choices=['table', 'csv', 'json'], default='table',
                                      help='Format of the report output')
msp_legacy_report_parser.add_argument('--output', dest='output', action='store',
                                      help='Output file name. (ignored for table format)')
group = msp_legacy_report_parser.add_argument_group('Pre-defined date ranges')
group.add_argument('--range', dest='range', choices=ranges, default='last_30_days',
                   help="Pre-defined data ranges to run the report.")
group = msp_legacy_report_parser.add_argument_group('Custom date ranges')
group.add_argument('--from', dest='from_date',
                   help='Run report from this date. Value in ISO 8601 format (YYYY-mm-dd) or Unix timestamp format. '
                        'Only applicable to the `audit` report AND when there is no `range` specified. '
                        'Example: `2020-08-18` or `1596265200`')
group.add_argument('--to', dest='to_date',
                   help='Run report until this date. Value in ISO 8601 format (YYYY-mm-dd) '
                        'or Unix timestamp format. Only applicable to the `audit` report AND '
                        'when there is no `range` specified.'
                        'Example: `2020-08-18` or `1596265200`')

msp_billing_report_parser = argparse.ArgumentParser(prog='msp-billing-report',
                                                    description='Generate MSP Billing Reports.')
msp_billing_report_parser.add_argument('--format', dest='format', choices=['table', 'csv', 'json'], default='table',
                                       help='Format of the report output')
msp_billing_report_parser.add_argument('--output', dest='output', action='store',
                                       help='Output file name. (ignored for table format)')
msp_billing_report_parser.add_argument('--month', dest='month', action='store', metavar='YYYY-MM', help='Month for billing report: 2022-02')
msp_billing_report_parser.add_argument('-d', '--show-date', dest='show_date', action='store_true', help='Breakdown report by date')
msp_billing_report_parser.add_argument('-c', '--show-company', dest='show_company', action='store_true', help='Breakdown report by managed company')


msp_add_parser = argparse.ArgumentParser(prog='msp-add', description='Add Managed Company.')
msp_add_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
msp_add_parser.add_argument('-s', '--seats', dest='seats', action='store', type=int,
                            help='Maximum licences allowed. -1: unlimited')
msp_add_parser.add_argument('-p', '--plan', dest='plan', action='store', required=True,
                            choices=['business', 'businessPlus', 'enterprise', 'enterprisePlus'],
                            help=f'License plan: {", ".join((x[1] for x in constants.MSP_PLANS))}')
msp_add_parser.add_argument('-f', '--file-plan', dest='file_plan', action='store',
                            help=f'File storage plan: {", ".join((x[2].lower() for x in constants.MSP_FILE_PLANS))}')
msp_add_parser.add_argument('-a', '--addon', dest='addon', action='append', metavar='ADDON[:SEATS]',
                            help=f'Add-ons: {", ".join((x[0]+(":N" if x[2] else "") for x in constants.MSP_ADDONS))}')
msp_add_parser.add_argument('name', action='store', help='Managed Company name')

msp_remove_parser = argparse.ArgumentParser(prog='msp-remove', description='Remove Managed Company.')
msp_remove_parser.add_argument('-f', '--force', dest='force', action='store_true',
                               help='do not prompt for confirmation')
msp_remove_parser.add_argument('mc', action='store',
                               help='Managed Company identifier (name or id). Ex. 3862 OR "Keeper Security, Inc."')

msp_convert_node_parser = argparse.ArgumentParser(prog='msp-convert-node', description='Converts MSP node into Managed Company.')
msp_convert_node_parser.add_argument('-s', '--seats', dest='seats', action='store', type=int,
                                     help='Number of seats')
msp_convert_node_parser.add_argument('-p', '--plan', dest='plan', action='store',
                                     choices=['business', 'businessPlus', 'enterprise', 'enterprisePlus'],
                                     help='License Plan')
msp_convert_node_parser.add_argument('node', action='store', help='node name or node ID')

msp_copy_role_parser = argparse.ArgumentParser(
    prog='msp-copy-role', description='Copy role with enforcements to Managed Companies.')
msp_copy_role_parser.add_argument('-r', '--role', dest='role', action='append',
                                  help='Role Name or ID. Can be repeated.')
msp_copy_role_parser.add_argument(
    'mc', action='store', nargs='+', help='Managed Company identifier (name or id)."')


def bi_url(params, endpoint):
    p = urlparse(params.rest_context.server_base)
    return urlunparse((p.scheme, p.netloc, '/bi_api/v2/enterprise_console/' + endpoint, None, None, None))


class GetMSPDataCommand(EnterpriseCommand):

    def get_parser(self):
        return msp_data_parser

    def execute(self, params, **kwargs):
        api.query_enterprise(params)


class MSPMixin:
    @staticmethod
    def price_text_short(price_info):
        price = ''
        if isinstance(price_info, dict):
            if 'amount' in price_info:
                currency = price_info.get('currency')
                if currency:
                    if currency == 'USD':
                        currency = '$'
                    elif currency == 'EUR':
                        currency = '\u20AC'
                    elif currency == 'GBP':
                        currency = '\u00a3'
                    elif currency == 'JPY':
                        currency = '\u00a5'
                    price += currency

                price += str(price_info['amount'])
        return price

    @staticmethod
    def price_text(price_info):
        price = MSPMixin.price_text_short(price_info)
        if price and isinstance(price_info, dict):
            unit = price_info.get('unit')
            if unit:
                if unit == 'USER_MONTH':
                    unit = 'user/month'
                elif unit == 'MONTH':
                    unit = 'month'
                elif unit == 'USER_CONSUMED_MONTH':
                    unit = '50k API calls/month'
                price += '/' + unit
        return price

    @staticmethod
    def get_msp_addons(params):   # type: (Any) -> Dict[int, str]
        if 'msp_addons' not in params.enterprise:
            url = bi_url(params, 'mapping/addons')
            rq = BI_pb2.MappingAddonsRequest()
            rs = api.communicate_rest(params, rq, url, rs_type=BI_pb2.MappingAddonsResponse)
            addon_map = {x.id: x.name for x in rs.addons}
            params.enterprise['msp_addons'] = addon_map
        return params.enterprise['msp_addons']

    @staticmethod
    def get_msp_pricing(params):
        if 'msp_pricing' not in params.enterprise:
            plan_map = {x[0]: x[1] for x in constants.MSP_PLANS}
            file_map = {x[0]: x[1] for x in constants.MSP_FILE_PLANS}
            addon_map = MSPMixin.get_msp_addons(params)

            pricing = {}
            params.enterprise['msp_pricing'] = pricing

            url = bi_url(params, 'subscription/mc_pricing')
            rq = BI_pb2.SubscriptionMcPricingRequest()
            rs = api.communicate_rest(params, rq, url, rs_type=BI_pb2.SubscriptionMcPricingResponse)

            units = BI_pb2.Cost.AmountPer.keys()
            currencies = BI_pb2.Currency.keys()
            pricing['mc_base_plans'] = {}
            for p in rs.basePlans:
                if p.id in plan_map:
                    pricing['mc_base_plans'][plan_map[p.id]] = {
                        'amount': p.cost.amount,
                        'unit': units[p.cost.amountPer],
                        'currency': currencies[p.cost.currency]
                    }
            pricing['mc_addons'] = {}
            for p in rs.addons:
                if p.id in addon_map:
                    pricing['mc_addons'][addon_map[p.id]] = {
                        'amount': p.cost.amount,
                        'unit': units[p.cost.amountPer],
                        'currency': currencies[p.cost.currency]
                    }
            pricing['mc_file_plans'] = {}
            for p in rs.filePlans:
                if p.id in file_map:
                    pricing['mc_file_plans'][file_map[p.id]] = {
                        'amount': p.cost.amount,
                        'unit': units[p.cost.amountPer],
                        'currency': currencies[p.cost.currency]
                    }

        return params.enterprise['msp_pricing']


class MSPInfoCommand(EnterpriseCommand, MSPMixin):
    def get_parser(self):
        return msp_info_parser

    def execute(self, params, **kwargs):
        if kwargs.get('restriction'):
            permits = next((x['msp_permits'] for x in params.enterprise.get('licenses', []) if 'msp_permits' in x), None)
            if permits:
                all_products = {x[1].lower(): x[2] for x in constants.MSP_PLANS}
                all_addons = {x[0].lower(): x[3] for x in constants.MSP_ADDONS}
                all_file_plans = {x[1].lower(): x[2] for x in constants.MSP_FILE_PLANS}
                max_file_plan = permits['max_file_plan_type']
                table = [
                    ['Allow Unlimited Licenses', permits['allow_unlimited_licenses']],
                    ['Allowed Products', [x + f' ({all_products.get(x.lower(), "")})' for x in permits['allowed_mc_products']]],
                    ['Allowed Add-Ons', [x + f' ({all_addons.get(x.lower(), "")})' for x in permits['allowed_add_ons']]],
                    ['Max File Storage plan', all_file_plans.get(max_file_plan.lower(), max_file_plan)]
                ]
                dump_report_data(table, ['Permit Name', 'Value'])
            else:
                logging.info('MSP has no restrictions')
            return

        if kwargs.get('pricing'):
            pricing = MSPMixin.get_msp_pricing(params)

            header = ['Name', 'Code', 'Price']
            table = []
            if 'mc_base_plans' in pricing:
                plans = pricing['mc_base_plans']
                for plan in constants.MSP_PLANS:
                    code = plan[1]
                    if code in plans:
                        info = plans[code]
                        row = [plan[2], code, MSPMixin.price_text(info)]
                        table.append(row)
            if 'mc_addons' in pricing:
                table.append([])
                table.append(['Addons'])
                addons = pricing['mc_addons']
                for addon in constants.MSP_ADDONS:
                    code = addon[0]
                    if code in addons:
                        info = addons[code]
                        row = [addon[1], code, MSPMixin.price_text(info)]
                        table.append(row)

            if 'mc_file_plans' in pricing:
                table.append([])
                table.append(['File Plans'])
                plans = pricing['mc_file_plans']
                for addon in constants.MSP_FILE_PLANS:
                    plan = addon[1]
                    if plan in plans:
                        info = plans[plan]
                        row = [addon[2], plan, MSPMixin.price_text(info)]
                        table.append(row)

            dump_report_data(table, header)
            return

        if 'managed_companies' in params.enterprise:
            sort_dict = {x[0]: i for i, x in enumerate(constants.MSP_ADDONS)}
            verbose = kwargs.get('verbose')
            header = ['ID', 'Name', 'Node', 'Plan', 'Storage', 'Addons', 'Allocated', 'Active']
            table = []
            plan_map = {x[1]: x[2] for x in constants.MSP_PLANS}
            file_plan_map = {x[1]: x[2] for x in constants.MSP_FILE_PLANS}
            for mc in params.enterprise['managed_companies']:
                node_id = mc['msp_node_id']
                if verbose:
                    node_path = str(node_id)
                else:
                    node_path = self.get_node_path(params, node_id, True)
                file_plan = mc['file_plan_type']
                file_plan = file_plan_map.get(file_plan, file_plan)
                addons = [x['name'] for x in mc.get('add_ons', [])]
                addons.sort(key=lambda x: sort_dict.get(x, -1))
                if not verbose:
                    addons = len(addons)
                plan = mc['product_id']
                if not verbose:
                    plan = plan_map.get(plan, plan)
                seats = mc['number_of_seats']
                if seats > 2000000:
                    seats = None
                table.append([mc['mc_enterprise_id'], mc['mc_enterprise_name'], node_path,
                              plan, file_plan, addons, seats, mc['number_of_users']])
            table.sort(key=lambda x: x[1].lower())
            dump_report_data(table, header, row_number=True)
        else:
            logging.info("No Managed Companies")


class MSPUpdateCommand(EnterpriseCommand):
    def get_parser(self):
        return msp_update_parser

    def execute(self, params, **kwargs):
        managed_companies = params.enterprise['managed_companies']
        mc_input = kwargs.get('mc')
        current_mc = get_mc_by_name_or_id(managed_companies, mc_input)
        if not current_mc:
            raise error.CommandError('msp-remove', f'Managed Company \"{mc_input}\" not found')

        rq = {
            'command': 'enterprise_update_by_msp',
            'enterprise_id': current_mc['mc_enterprise_id'],
            'enterprise_name': current_mc['mc_enterprise_name'],
            'product_id': current_mc['product_id'],
            'seats': current_mc['number_of_seats'],
        }

        permits = next((x['msp_permits'] for x in params.enterprise.get('licenses', []) if 'msp_permits' in x), None)

        plan_name = kwargs.get('plan')
        if plan_name:
            plan_name = plan_name.lower()
            product_plan = next((x for x in constants.MSP_PLANS if x[1].lower() == plan_name), None)
            if not product_plan:
                logging.warning('Managed Company plan \"%s\" is not found', plan_name)
                return
            if permits:
                has_plan = any((True for x in permits['allowed_mc_products'] if x.lower() == plan_name))
                if not has_plan:
                    logging.warning('Managed Company plan \"%s\" is not allowed', plan_name)
                    return
            rq['product_id'] = product_plan[1]

        seats = kwargs.get('seats')
        if isinstance(seats, int):
            if seats < 0 and permits:
                if permits['allow_unlimited_licenses'] is False:
                    logging.warning('Managed Company unlimited licences are not allowed')
                    return
            rq['seats'] = seats if seats >= 0 else 2147483647

        plan_name = kwargs.get('file_plan')
        if plan_name:
            plan_name = plan_name.lower()
            file_plan = next((x for x in constants.MSP_FILE_PLANS if plan_name in (y.lower() for y in x if isinstance(y, str))), None)
            if not file_plan:
                logging.warning('File plan \"%s\" is not found', plan_name)
                return
            if permits:
                allowed_file_plan_name = permits['max_file_plan_type'].lower()
                if allowed_file_plan_name:
                    allowed_plan = next((x for x in constants.MSP_FILE_PLANS if allowed_file_plan_name == x[1].lower()), None)
                    if allowed_plan and allowed_plan[0] < file_plan[0]:
                        logging.warning('Managed Company file storage \"%s\" is not allowed', file_plan[2])
                        return
            product_id = rq['product_id'].lower()
            product_plan = next((x for x in constants.MSP_PLANS if product_id == x[1].lower()), None)
            if product_plan and product_plan[3] < file_plan[0]:
                rq['file_plan_type'] = file_plan[1]

        addons = {}
        for ao in current_mc.get('add_ons', []):
            if not ao['enabled']:
                continue
            if ao.get('included_in_product') is True:
                continue
            addon_name = ao['name']
            keep_addon = {
                'add_on': addon_name
            }
            seats = ao.get('seats')
            if seats > 0:
                keep_addon['seats'] = seats
            addons[addon_name] = keep_addon

        for action in ('add_addon', 'remove_addon'):
            action_addons = kwargs.get(action)
            if isinstance(action_addons, list):
                for aon in action_addons:
                    addon_name, sep, seats = aon.partition(':')
                    addon_name = addon_name.lower()
                    addon = next((x for x in constants.MSP_ADDONS if addon_name == x[0]), None)
                    if addon is None:
                        logging.warning('Addon \"%s\" is not found', addon_name)
                        return
                    addon_seats = 0
                    if sep == ':' and addon[2] and action == 'add_addon':
                        try:
                            addon_seats = int(seats)
                        except:
                            logging.warning('Addon \"%s\". Number of seats \"%s\" is not integer', addon_name, seats)
                            return
                    if action == 'add_addon':
                        if permits:
                            if addon_name not in (x.lower() for x in permits['allowed_add_ons']):
                                logging.warning('Managed Company add-on \"%s\" is not allowed', addon_name)
                                return
                        add_addon = {
                            'add_on': addon_name
                        }
                        if addon_seats > 0:
                            add_addon['seats'] = seats
                        addons[addon_name] = add_addon
                    else:
                        if addon_name in addons:
                            del addons[addon_name]
        rq['add_ons'] = list(addons.values())
        rs = api.communicate(params, rq)
        if rs['result'] == 'success':
            mc_from_rs = find(lambda mc: mc['mc_enterprise_id'] == rs["enterprise_id"], managed_companies)
            print("Successfully updated '%s' id=%d" % (mc_from_rs['mc_enterprise_name'], mc_from_rs['mc_enterprise_id']))
            api.query_enterprise(params)


class DailySnapshot(object):
    def __init__(self, mc_id, date_no):
        self.mc_enterprise_id = mc_id
        self.date_no = date_no

    def __eq__(self, other):
        if isinstance(other, DailySnapshot):
            return self.mc_enterprise_id == other.mc_enterprise_id and self.date_no == other.date_no
        return False

    def __str__(self):
        return f'MC ID: {self.mc_enterprise_id}; Date: {self.date_no}'

    def __hash__(self):
        b = (self.mc_enterprise_id << 32) + self.date_no
        return b.__hash__()

    @staticmethod
    def merge_units(unit_iter):    # type: (Iterable[Dict[int, Union[int, Tuple[int, int]]]]) -> Dict[int, Tuple[int, int]]
        ret = {}   # type: Dict[int, Tuple[int, int]]
        for units in unit_iter:
            if not isinstance(units, dict):
                continue
            for unit in units:
                if not isinstance(unit, int):
                    continue
                count = units[unit]
                if not isinstance(count, (int, tuple)):
                    continue
                if isinstance(count, int):
                    qty = count
                    days = 1
                else:
                    qty = count[0]
                    days = count[1]
                if unit in ret:
                    q1, d1 = ret[unit]
                    ret[unit] = (q1 + qty, d1 + days)
                else:
                    ret[unit] = (qty, days)
        return ret


class MSPBillingReportCommand(EnterpriseCommand):
    LAST_USER = ''
    SNAPSHOT_CACHE = {}  # type: Dict[str, Dict[DailySnapshot, Dict[int, int]]]
    COMPANY_CACHE = {}

    def get_parser(self):
        return msp_billing_report_parser

    @staticmethod
    def is_plan_id(msp_id):   # type: (int) -> bool
        return 0 < msp_id < 100

    @staticmethod
    def is_storage_plan_id(msp_id):   # type: (int) -> bool
        return 100 < msp_id < 10000

    @staticmethod
    def is_addon_id(msp_id):   # type: (int) -> bool
        return 10000 < msp_id

    @staticmethod
    def get_count_id(msp_id):
        if 0 < msp_id < 100:
            return msp_id
        if 100 < msp_id < 10000:
            return msp_id // 100
        if msp_id > 10000:
            return msp_id // 10000
        return 0

    @staticmethod
    def get_daily_snapshots(params, year, month):
        if MSPBillingReportCommand.LAST_USER:
            if MSPBillingReportCommand.LAST_USER != params.user:
                MSPBillingReportCommand.SNAPSHOT_CACHE.clear()
                MSPBillingReportCommand.COMPANY_CACHE.clear()
        MSPBillingReportCommand.LAST_USER = params.user

        key = f'{year}-{month}'
        if key not in MSPBillingReportCommand.SNAPSHOT_CACHE:
            rq = BI_pb2.ReportingDailySnapshotRequest()
            rq.year = year
            rq.month = month
            url = bi_url(params, 'reporting/daily_snapshot')
            rs = api.communicate_rest(params, rq, url, rs_type=BI_pb2.ReportingDailySnapshotResponse)
            for company in rs.mcEnterprises:
                MSPBillingReportCommand.COMPANY_CACHE[company.id] = company.name

            snapshot = {}
            for record in rs.records:
                units = {}
                if record.maxLicenseCount > 0:
                    if record.maxBasePlanId > 0:
                        units[record.maxBasePlanId] = record.maxLicenseCount
                    if record.maxFilePlanTypeId > 0:
                        units[record.maxFilePlanTypeId * 100] = record.maxLicenseCount
                    for addon in record.addons:
                        if addon.maxAddonId > 0:
                            units[addon.maxAddonId * 10000] = addon.units
                mc_id = record.mcEnterpriseId
                ds = datetime.datetime.utcfromtimestamp(record.date // 1000)
                dt = ds.date()
                daily = DailySnapshot(mc_id, dt.toordinal())
                snapshot[daily] = units
            MSPBillingReportCommand.SNAPSHOT_CACHE[key] = snapshot
        return MSPBillingReportCommand.SNAPSHOT_CACHE[key]

    def execute(self, params, **kwargs):
        month_str = kwargs.get('month')
        if not month_str:
            dt = datetime.datetime.now()
            month = dt.month
            year = dt.year
            month -= 1
            if month < 1:
                month += 12
                year -= 1
        else:
            year_part, sep, month_part = month_str.partition('-')
            try:
                year = int(year_part)
                month = int(month_part)
            except:
                logging.warning('Given month \"%s\" is not valid. YYYY-MM', month_str)
                return
        daily_counts = MSPBillingReportCommand.get_daily_snapshots(params, year, month)
        title = f'Consumption Billing Statement: {calendar.month_name[month]} {year}'
        headers = []
        table = []

        show_date = kwargs.get('show_date', False)
        show_company = kwargs.get('show_company', False)
        merged_counts = {}  # type: Dict[DailySnapshot, Dict[int, Tuple[int, int]]]
        for dc in daily_counts:
            d = DailySnapshot(dc.mc_enterprise_id if show_company else 0, dc.date_no if show_date else 0)
            merged_counts[d] = DailySnapshot.merge_units((merged_counts.get(d), daily_counts[dc]))

        if show_date:
            headers.append('date')
        if show_company:
            headers.extend(('company', 'company_id'))
        headers.extend(('product', 'licenses', 'rate'))
        if not show_date:
            headers.append('avg_per_day')
        plan_lookup = {x[0]: x for x in constants.MSP_PLANS}
        storage_lookup = {x[0]: x for x in constants.MSP_FILE_PLANS}
        addon_lookup = {}
        addons = {x[0]: x for x in constants.MSP_ADDONS}
        for a_id, a_name in MSPMixin.get_msp_addons(params).items():
            if a_name in addons:
                addon_lookup[a_id] = addons[a_name]
        pricing = MSPMixin.get_msp_pricing(params)
        for point in merged_counts:
            day_str = str(datetime.date.fromordinal(point.date_no)) if show_date else ''
            company = MSPBillingReportCommand.COMPANY_CACHE.get(point.mc_enterprise_id, '') if show_company else ''
            counts = merged_counts[point]
            products = list(counts.keys())
            products.sort()
            for product in products:
                row = []
                if show_date:
                    row.append(day_str)
                if show_company:
                    row.extend((company, point.mc_enterprise_id))
                count_id = MSPBillingReportCommand.get_count_id(product)
                count, days = counts[product]

                product_name = ''
                rate_text = ''
                if MSPBillingReportCommand.is_plan_id(product):
                    plan = plan_lookup.get(count_id)
                    product_name = plan[2] if plan else str(count_id)
                    if 'mc_base_plans' in pricing:
                        if plan[1] in pricing['mc_base_plans']:
                            rate = pricing['mc_base_plans'][plan[1]]
                            rate_text = MSPMixin.price_text_short(rate)
                elif MSPBillingReportCommand.is_storage_plan_id(product):
                    plan = storage_lookup.get(count_id)
                    product_name = plan[2] if plan else str(count_id)
                    if 'mc_file_plans' in pricing:
                        if plan[1] in pricing['mc_file_plans']:
                            rate = pricing['mc_file_plans'][plan[1]]
                            rate_text = MSPMixin.price_text_short(rate)
                elif MSPBillingReportCommand.is_addon_id(product):
                    addon = storage_lookup.get(count_id)
                    product_name = addon[1] if addon else str(count_id)
                    if 'mc_addons' in pricing:
                        if addon[0] in pricing['mc_addons']:
                            rate = pricing['mc_addons'][addon[0]]
                            rate_text = MSPMixin.price_text_short(rate)
                else:
                    product_name = str(product)

                row.extend((product_name, count, rate_text))
                if not show_date:
                    row.append(count // days)

                table.append(row)

        output_format = kwargs.get('format')
        if output_format == 'table':
            headers = [field_to_title(x) for x in headers]
        return dump_report_data(table, headers, fmt=output_format, filename=kwargs.get('output'), title=title)


class MSPLegacyReportCommand(EnterpriseCommand):
    def get_parser(self):
        return msp_legacy_report_parser

    def execute(self, params, **kwargs):
        from_date_str = kwargs.get('from_date')
        to_date_str = kwargs.get('to_date')
        if not from_date_str or not to_date_str:
            # will use data range to query
            rng = kwargs.get('range')
            from_date, to_date = date_range_str_to_dates(rng)
        else:
            # will use start and end data
            if loginv3.CommonHelperMethods.check_int(from_date_str):
                from_date = datetime.datetime.fromtimestamp(int(from_date_str))
            else:
                from_date = datetime.datetime.strptime(from_date_str + " 00:00:00", "%Y-%m-%d %H:%M:%S")

            if loginv3.CommonHelperMethods.check_int(to_date_str):
                to_date = datetime.datetime.fromtimestamp(int(to_date_str))
            else:
                to_date = datetime.datetime.strptime(to_date_str + " 11:59:59", "%Y-%m-%d %H:%M:%S")

        from_date_timestamp = int(from_date.timestamp() * 1000)
        to_date_timestamp = int(to_date.timestamp() * 1000)

        rq = {
            'command': 'get_mc_license_adjustment_log',
            'from': from_date_timestamp,
            'to': to_date_timestamp
        }

        rs = api.communicate(params, rq)

        title = None
        headers = []
        table = []
        for log in rs['log']:
            table.append([log['id'], log['date'], log['enterprise_id'], log['enterprise_name'], log['status'],
                          log['new_number_of_seats'], log['new_product_type'], log['note'], log['price']])

        headers.extend(('id', 'time', 'company_id', 'company_name', 'status', 'number_of_allocations', 'plan', 'transaction_notes', 'price_estimate'))

        output_format = kwargs.get('format')
        if output_format == 'table':
            headers = [field_to_title(x) for x in headers]
        return dump_report_data(table, headers, fmt=output_format, filename=kwargs.get('output'), title=title)


class MSPAddCommand(EnterpriseCommand):
    def get_parser(self):
        return msp_add_parser

    def execute(self, params, **kwargs):
        node_id = None
        node_name = kwargs.get('node')
        if node_name:
            nodes = list(self.resolve_nodes(params, node_name))
            if len(nodes) == 0:
                logging.warning('Node \"%s\" is not found', node_name)
                return
            if len(nodes) > 1:
                logging.warning('More than one nodes \"%s\" are found', node_name)
                return
            node_id = nodes[0]['node_id']
        if node_id is None:
            root_nodes = list(self.get_user_root_nodes(params))
            if len(root_nodes) == 0:
                raise CommandError('msp-create', 'No root nodes were detected. Specify --node parameter')
            node_id = root_nodes[0]

        permits = next((x['msp_permits'] for x in params.enterprise.get('licenses', []) if 'msp_permits' in x), None)

        plan_name = kwargs.get('plan')
        if not plan_name and permits:
            allowed_products = permits['allowed_mc_products']
            if allowed_products:
                plan_name = allowed_products[0]
        if not plan_name:
            plan_name = constants.MSP_PLANS[0][1]
        if permits:
            has_plan = any((True for x in permits['allowed_mc_products'] if x.lower() == plan_name.lower()))
            if not has_plan:
                logging.warning('Managed Company plan \"%s\" is not allowed', plan_name)
                return

        plan_name = plan_name.lower()
        product_plan = next((x for x in constants.MSP_PLANS if x[1].lower() == plan_name), None)
        if not product_plan:
            logging.warning('Managed Company plan \"%s\" is not found', plan_name)
            return

        seats = kwargs.get('seats')
        if isinstance(seats, int) and seats < 0:
            if permits:
                if permits['allow_unlimited_licenses'] is False:
                    logging.warning('Managed Company unlimited licences are not allowed')
                    return
            seats = 2147483647

        name = kwargs['name']
        tree_key = utils.generate_aes_key()
        rq = {
            'command': 'enterprise_registration_by_msp',
            'node_id': node_id,
            'product_id': product_plan[1],
            'seats': seats if isinstance(seats, int) else 0,
            'enterprise_name': name,
            'encrypted_tree_key': utils.base64_url_encode(
                crypto.encrypt_aes_v2(tree_key, params.enterprise['unencrypted_tree_key'])),
            'role_data': utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps({'displayname': 'Keeper Administrator'}).encode(), tree_key)),
            'root_node': utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps({'displayname': 'root'}).encode(), tree_key))
        }

        plan_name = kwargs.get('file_plan')
        if plan_name:
            plan_name = plan_name.lower()
            file_plan = next((x for x in constants.MSP_FILE_PLANS if plan_name in (y.lower() for y in x if isinstance(y, str))), None)
            if not file_plan:
                logging.warning('File plan \"%s\" is not found', plan_name)
                return
            if product_plan[3] < file_plan[0]:
                rq['file_plan_type'] = file_plan[1]
            if permits:
                allowed_file_plan_name = permits['max_file_plan_type'].lower()
                if allowed_file_plan_name:
                    allowed_plan = next((x for x in constants.MSP_FILE_PLANS if allowed_file_plan_name == x[1].lower()), None)
                    if allowed_plan and allowed_plan[0] < file_plan[0]:
                        logging.warning('Managed Company file storage \"%s\" is not allowed', file_plan[2])
                        return

        addons = kwargs.get('addon')
        if isinstance(addons, list):
            rq['add_ons'] = []
            for v in addons:
                addon_name, sep, seats = v.partition(':')
                addon_name = addon_name.lower()
                addon = next((x for x in constants.MSP_ADDONS if x[0] == addon_name), None)
                if addon is None:
                    logging.warning('Addon \"%s\" is not found', addon_name)
                    return
                if permits:
                    if addon_name not in (x.lower() for x in permits['allowed_add_ons']):
                        logging.warning('Managed Company add-on \"%s\" is not allowed', addon_name)
                        return
                addon_seats = 0
                if sep == ':' and addon[2]:
                    try:
                        addon_seats = int(seats)
                    except:
                        logging.warning('Addon \"%s\". Number of seats \"%s\" is not integer', addon_name, seats)
                        return
                rqa = {
                    'add_on': addon[0]
                }
                if addon_seats > 0:
                    rqa['seats'] = addon_seats
                rq['add_ons'].append(rqa)

        company_id = -1
        rs = api.communicate(params, rq)
        if rs:
            company_id = rs.get('enterprise_id', -1)
            params.environment_variables['last_mc_id'] = str(company_id)
            logging.info('Managed company \"%s\" added. ID=%d', name, company_id)
        api.query_enterprise(params)
        return company_id


class MSPRemoveCommand(EnterpriseCommand):
    def get_parser(self):
        return msp_remove_parser

    def execute(self, params, **kwargs):
        mc_input = kwargs.get('mc', '')
        if not mc_input:
            raise error.CommandError('msp-remove', 'Managed Company name or id is required')
        managed_companies = params.enterprise.get('managed_companies', [])
        current_mc = get_mc_by_name_or_id(managed_companies, mc_input)
        if not current_mc:
            raise error.CommandError('msp-remove', f'Managed Company \"{mc_input}\" not found')
        if kwargs.get('force') is True:
            answer = 'y'
        else:
            answer = user_choice(bcolors.FAIL + bcolors.BOLD + 'ALERT!\n' + bcolors.ENDC + 'Remove Managed Company.\n\n' +
                                 'Removing will expire the licences for the managed company and your admin access for the account.\n' +
                                 f'Managed Company Name: \"{current_mc["mc_enterprise_name"]}\", Licences: {current_mc["number_of_seats"]}\n\n' +
                                 'I want to remove these licences managed vault folder and my access to the admin console from my MSP account.', 'yn', 'n')
        if answer.lower() == 'y':
            rq = {
                'command': 'enterprise_remove_by_msp',
                'enterprise_id': current_mc['mc_enterprise_id']
            }
            rs = api.communicate(params, rq)
            if rs:
                logging.info('Managed company \"%s\" removed. ID=%d', current_mc['mc_enterprise_name'], current_mc['mc_enterprise_id'])
            api.query_enterprise(params)


def get_mc_by_name_or_id(msc, name_or_id):
    if loginv3.CommonHelperMethods.check_int(name_or_id):
        # get by id
        found_mc = find(lambda mc: mc['mc_enterprise_id'] == int(name_or_id), msc)
    else:
        # get by company name (all lower case)
        found_mc = find(lambda mc: mc['mc_enterprise_name'].lower() == name_or_id.lower(), msc)

    return found_mc


def find(f, seq):
    """Return first item in sequence where f(item) == True."""
    for item in seq:
        if f(item):
            return item


def report_generation_message(filename, filetype):
    if filename:
        _, ext = os.path.splitext(filename)
        if not ext:
            filename += '.'+filetype

    return filename


def date_range_str_to_dates(range_str):

    if range_str not in ranges:
        raise CommandError('', "Given range %s is not supported. Supported ranges: %s" % (range_str, ranges))

    current_time = datetime.datetime.now()

    today_start_dt = current_time.replace(hour=0, minute=0, second=0)
    today_end_dt = current_time.replace(hour=11, minute=59, second=59)

    start_date = None
    end_date = None

    def last_day_of_month(dt):
        year = dt.strftime("%Y")                       # get the year
        month = str(int(dt.strftime("%m")) % 12 + 1)   # get month, watch rollover

        ldom = calendar.monthrange(int(year), int(month))[1]  # get num of days in this month

        last_date_of_month = dt.replace(hour=11, minute=59, second=59, day=ldom)

        return last_date_of_month

    if range_str == 'today':
        start_date = today_start_dt
        end_date = today_end_dt

    elif range_str == 'yesterday':
        start_date = today_start_dt - datetime.timedelta(1)
        end_date = today_end_dt - datetime.timedelta(1)

    elif range_str == 'last_7_days':
        start_date = today_start_dt - datetime.timedelta(7)
        end_date = today_end_dt

    elif range_str == 'last_30_days':
        start_date = today_start_dt - datetime.timedelta(30)
        end_date = today_end_dt

    elif range_str == 'month_to_date':
        start_date = today_start_dt.replace(hour=0, minute=0, second=0, day=1)
        end_date = today_end_dt

    elif range_str == 'last_month':
        last_month_num = current_time.month - 1 if current_time.month > 1 else 12
        last_month_dt = current_time.replace(month=last_month_num)

        start_date = current_time.replace(month=last_month_num, day=1, hour=0, minute=0, second=0)
        end_date = last_day_of_month(last_month_dt)

    elif range_str == 'year_to_date':
        start_date = today_start_dt.replace(day=1, month=1, hour=0, minute=0, second=0)
        end_date = today_end_dt

    elif range_str == 'last_year':
        start_date = today_start_dt.replace(year=(today_start_dt.year - 1), day=1,  month=1,  hour=0,  minute=0,  second=0)
        end_date = today_start_dt.replace(year=(today_start_dt.year - 1), day=31, month=12, hour=11, minute=59, second=59)

    return start_date, end_date


class MSPConvertNodeCommand(EnterpriseCommand):
    def get_parser(self):
        return msp_convert_node_parser

    def execute(self, params, **kwargs):
        msp_node_id = None
        node_name = kwargs.get('node')
        if node_name:
            nodes = list(self.resolve_nodes(params, node_name))
            if len(nodes) == 0:
                logging.warning('Node \"%s\" is not found', node_name)
                return
            if len(nodes) > 1:
                logging.warning('More than one nodes \"%s\" are found', node_name)
                return
            msp_node_id = nodes[0]['node_id']
        if msp_node_id is None:
            raise CommandError('msp-convert-node', 'node parameter is required')
        root_nodes = list(self.get_user_root_nodes(params))
        if msp_node_id in root_nodes:
            raise CommandError('msp-convert-node', 'root node cannot be converted')

        node_lookup = {x['node_id']: x for x in params.enterprise.get('nodes', [])}
        role_lookup = {x['role_id']: x for x in params.enterprise.get('roles', [])}
        team_lookup = {x['team_uid']: x for x in params.enterprise.get('teams', [])}
        user_lookup = {x['enterprise_user_id']: x for x in params.enterprise.get('users', [])}

        node_tree = {}    # type: Dict[int, Set[int]]
        for node in node_lookup.values():
            node_id = node['node_id']
            parent_id = node.get('parent_id')
            if isinstance(parent_id, int) and isinstance(node_id, int):
                if parent_id not in node_tree:
                    node_tree[parent_id] = set()
                node_tree[parent_id].add(node_id)
        all_subnodes = [msp_node_id]   # type: List[int]
        pos = 0
        while pos < len(all_subnodes):
            node_id = all_subnodes[pos]
            pos += 1
            if node_id in node_tree:
                all_subnodes.extend(node_tree[node_id])
        nodes_to_move = set(all_subnodes)
        roles_to_move = {x['role_id'] for x in role_lookup.values() if x['node_id'] in nodes_to_move}
        teams_to_move = {x['team_uid'] for x in team_lookup.values() if x['node_id'] in nodes_to_move}
        users_to_move = {x['enterprise_user_id'] for x in user_lookup.values() if x['node_id'] in nodes_to_move}

        errors = []
        for bridge in params.enterprise.get('bridges', []):
            node_id = bridge.get('node_id', 0)
            if node_id in nodes_to_move:
                errors.append(f'Remove bridge provisioning before conversion from node {self.get_node_path(params, node_id)}')
        for scim in params.enterprise.get('scims', []):
            node_id = scim.get('node_id', 0)
            if node_id in nodes_to_move:
                errors.append(f'Remove SCIM provisioning before conversion from node {self.get_node_path(params, node_id)}')
        for sso in params.enterprise.get('sso_services', []):
            node_id = sso.get('node_id', 0)
            if node_id in nodes_to_move:
                errors.append(f'Remove SSO provisioning before conversion from node {self.get_node_path(params, node_id)}')
        for email in params.enterprise.get('email_provision', []):
            node_id = email.get('node_id', 0)
            if node_id in nodes_to_move:
                errors.append(f'Remove email provisioning before conversion from node {self.get_node_path(params, node_id)}')
        for mc in params.enterprise.get('managed_companies', []):
            node_id = mc.get('node_id', 0)
            if node_id in nodes_to_move:
                errors.append(f'Remove managed company before conversion from node {self.get_node_path(params, node_id)}')
        for qt in params.enterprise.get('queued_teams', []):
            node_id = qt['node_id']
            if node_id in nodes_to_move:
                errors.append(f'Remove queued team {qt["name"]} before conversion from node {self.get_node_path(params, node_id)}')

        for user in (y for x, y in user_lookup.items() if x in users_to_move):
            if user['status'] == 'invited':
                errors.append(f'Pending user {user["username"]} must be removed')

        for ru in params.enterprise.get('role_users', []):
            user_id = ru['enterprise_user_id']
            role_id = ru['role_id']
            move_user = user_id in users_to_move
            move_role = role_id in roles_to_move
            if move_role != move_user:
                user = user_lookup.get(user_id)
                username = (user.get('username') if user else '') or str(user_id)
                role = role_lookup.get(role_id)
                rolename = (role['data'].get('displayname') if role else '') or str(role_id)
                errors.append(f'Conflicting role membership: User: {username}, Role: {rolename}')

        for rt in params.enterprise.get('role_teams', []):
            team_uid = rt['team_uid']
            role_id = rt['role_id']
            move_team = team_uid in teams_to_move
            move_role = role_id in roles_to_move
            if move_role != move_team:
                team = team_lookup.get(team_uid)
                teamname = team.get('name', team_uid)
                role = role_lookup.get(role_id)
                rolename = (role['data'].get('displayname') if role else '') or str(role_id)
                errors.append(f'Conflicting role membership: Team: {teamname}, Role: {rolename}')

        for tu in params.enterprise.get('team_users', []):
            user_id = tu['enterprise_user_id']
            team_uid = tu['team_uid']
            move_user = user_id in users_to_move
            move_team = team_uid in teams_to_move
            if move_team != move_user:
                user = user_lookup.get(user_id)
                username = (user['username'] if user else '') or str(user_id)
                team = team_lookup.get(team_uid)
                teamname = (team['name'] if team else '') or team_uid
                errors.append(f'Conflicting team membership: User: {username}, Team: {teamname}')

        for mn in params.enterprise.get('managed_nodes', []):
            role_id = mn['role_id']
            node_id = mn['managed_node_id']
            move_role = role_id in roles_to_move
            move_node = node_id in nodes_to_move
            if move_role != move_node:
                role = role_lookup.get(role_id)
                rolename = (role['data'].get('displayname') if role else '') or str(role_id)
                nodename = self.get_node_path(params, node_id)
                errors.append(f'Conflicting admin role management: Node: {nodename}, Role: {rolename}')

        if len(errors) > 0:
            print('\n'.join(errors))
            return

        seats = kwargs.get('seats') or 0
        if seats < len(users_to_move):
            seats = len(users_to_move)
        if seats == 0:
            seats = 1
        plan = kwargs.get('plan') or 'business'

        msp_node = node_lookup[msp_node_id]
        msp_node_name = msp_node['data'].get('displayname')
        mc = None
        if msp_node_name:
            mc = next(
                (x for x in params.enterprise.get('managed_companies', []) if x['mc_enterprise_name'] == msp_node_name),
                None)
        tree_key = params.enterprise['unencrypted_tree_key']
        if mc:
            mc_id = mc['mc_enterprise_id']
            encrypted_tree_key = mc.get('tree_key')
            if not encrypted_tree_key:
                login_rq = enterprise_pb2.LoginToMcRequest()
                login_rq.mcEnterpriseId = mc_id
                login_rq.messageSessionUid = utils.base64_url_decode(params.session_token)
                login_rs = api.communicate_rest(
                    params, login_rq, 'authentication/login_to_mc', rs_type=enterprise_pb2.LoginToMcResponse)
                encrypted_tree_key = login_rs.encryptedTreeKey
            mc_tree_key = crypto.decrypt_aes_v2(utils.base64_url_decode(encrypted_tree_key), tree_key)
        else:
            mc_tree_key = utils.generate_aes_key()
            rq = {
                'command': 'enterprise_registration_by_msp',
                'node_id': root_nodes[0],
                'seats': seats,
                'product_id': plan,
                'enterprise_name': msp_node_name,
                'encrypted_tree_key': utils.base64_url_encode(
                    crypto.encrypt_aes_v2(mc_tree_key, tree_key)),
                'role_data': utils.base64_url_encode(
                    crypto.encrypt_aes_v1(json.dumps({'displayname': 'Keeper Administrator'}).encode(), mc_tree_key)),
                'root_node': utils.base64_url_encode(
                    crypto.encrypt_aes_v1(json.dumps({'displayname': 'root'}).encode(), mc_tree_key))
            }
            rs = api.communicate(params, rq)
            mc_id = rs['enterprise_id']

        mc_rq = enterprise_pb2.NodeToManagedCompanyRequest()
        mc_rq.companyId = mc_id
        for node_id in all_subnodes:
            node = node_lookup[node_id]
            red = enterprise_pb2.ReEncryptedData()
            red.id = node_id
            data = json.dumps(node['data']).encode()
            red.data = utils.base64_url_encode(crypto.encrypt_aes_v1(data, mc_tree_key))
            mc_rq.nodes.append(red)

        for role_id in roles_to_move:
            role = role_lookup[role_id]
            red = enterprise_pb2.ReEncryptedData()
            red.id = role_id
            data = json.dumps(role['data']).encode()
            red.data = utils.base64_url_encode(crypto.encrypt_aes_v1(data, mc_tree_key))
            mc_rq.roles.append(red)

        for user_id in users_to_move:
            user = user_lookup[user_id]
            red = enterprise_pb2.ReEncryptedData()
            red.id = user_id
            if user.get('key_type') == 'no_key':
                displayname = user['data'].get('displayname', '?')
                red.data = displayname
            else:
                data = json.dumps(user['data']).encode()
                red.data = utils.base64_url_encode(crypto.encrypt_aes_v1(data, mc_tree_key))
            mc_rq.users.append(red)

        for mn in params.enterprise.get('managed_nodes', []):
            role_id = mn['role_id']
            if role_id in roles_to_move:
                role_key2 = next((x for x in params.enterprise.get('role_keys2', [])), None)
                if role_key2:
                    role_key = utils.base64_url_decode(role_key2['role_key'])
                    role_key = crypto.decrypt_aes_v2(role_key, tree_key)
                    rerk = enterprise_pb2.ReEncryptedRoleKey()
                    rerk.role_id = role_id
                    rerk.encryptedRoleKey = crypto.encrypt_aes_v2(role_key, mc_tree_key)
                    mc_rq.roleKeys.append(rerk)

        for team_uid, team in team_lookup.items():
            if team_uid in teams_to_move:
                etkr = enterprise_pb2.EncryptedTeamKeyRequest()
                etkr.teamUid = utils.base64_url_decode(team_uid)
                encrypted_team_key = team.get('encrypted_team_key')
                if encrypted_team_key:
                    team_key = utils.base64_url_decode(encrypted_team_key)
                    team_key = crypto.decrypt_aes_v2(team_key, tree_key)
                    etkr.encryptedTeamKey = crypto.encrypt_aes_v2(team_key, mc_tree_key)
                else:
                    etkr.force = True
                mc_rq.teamKeys.append(etkr)

        api.communicate_rest(params, mc_rq, 'enterprise/node_to_managed_company')
        logging.info(f'Node \"{msp_node_name}\" was converted to Managed Company')
        api.query_enterprise(params)


class MSPCopyRoleCommand(EnterpriseCommand):
    def get_parser(self):
        return msp_copy_role_parser

    def execute(self, params, **kwargs):
        src_roles = {}
        roles = kwargs.get('role')
        if not roles:
            raise error.CommandError('msp-copy-role', f'Source role parameter is required')

        if not isinstance(roles, list):
            roles = [roles]

        for role_name in roles:
            if not isinstance(role_name, str):
                role_name = str(role_name)
            matched_roles = list(MSPCopyRoleCommand.find_roles(params, role_name))
            if len(matched_roles) == 1:
                role = matched_roles[0]
                src_roles[role['role_id']] = role
            elif len(matched_roles) > 1:
                raise Exception(f'There are more than one roles with name \"{role_name}\". Use Role ID')
            else:
                raise Exception(f'Role \"{role_name}\" not found')

        managed_companies = params.enterprise.get('managed_companies', [])
        mcs = {}
        for mc_name in kwargs.get('mc') or []:
            mc = get_mc_by_name_or_id(managed_companies, mc_name)
            if not mc:
                raise error.CommandError('msp-copy-role', f'Managed Company \"{mc_name}\" not found')
            mcs[mc['mc_enterprise_id']] = mc

        for mc in mcs.values():
            mc_id = mc['mc_enterprise_id']
            mc_params = api.login_and_get_mc_params_login_v3(params, mc_id)
            node_id = next((x['node_id'] for x in mc_params.enterprise.get('nodes', []) if not x.get('parent_id')), None)
            mc_rqs = []
            for role in src_roles.values():
                src_role_id = role['role_id']
                role_name = role['data'].get('displayname') or ''
                if not role_name:
                    continue
                dst_roles = list(MSPCopyRoleCommand.find_roles(mc_params, role_name))
                if len(dst_roles) > 1:
                    logging.warning('MC # %d: There are more than one roles with name \"%s\". Skipping', mc_id, role_name)
                    continue

                if len(dst_roles) == 1:
                    dst_role_id = dst_roles[0]['role_id']
                else:
                    dst_role_id = self.get_enterprise_id(mc_params)
                    dt = { "displayname": role_name }
                    mc_rqs.append({
                        "command": 'role_add',
                        "role_id": dst_role_id,
                        "node_id": node_id,
                        "encrypted_data": api.encrypt_aes(json.dumps(dt).encode('utf-8'), mc_params.enterprise['unencrypted_tree_key']),
                        "visible_below": role.get('visible_below', True),
                        "new_user_inherit": role.get('new_user_inherit',  False)
                    })
                enf = next((x['enforcements'] for x in params.enterprise.get('role_enforcements') or [] if x.get('role_id') == src_role_id), None)
                src_enforcements = enf.copy() if isinstance(enf, dict) else {}
                enf = next((x['enforcements'] for x in mc_params.enterprise.get('role_enforcements') or [] if x.get('role_id') == dst_role_id), None)
                dst_enforcements = enf.copy() if isinstance(enf, dict) else {}
                for enforcement in src_enforcements:
                    src_value = src_enforcements[enforcement]
                    if enforcement in dst_enforcements:
                        command = 'role_enforcement_update'
                        dst_value = dst_enforcements[enforcement]
                        if src_value != dst_value:
                            command = 'role_enforcement_update'
                        dst_enforcements.pop(enforcement)
                    else:
                        command = 'role_enforcement_add'
                    if command:
                        rq = {
                            'command': command,
                            'role_id': dst_role_id,
                            'enforcement': enforcement,
                        }
                        try:
                            value = MSPCopyRoleCommand.get_enforcement_value(enforcement, src_value)
                            if value is not None:
                                if not isinstance(value, bool):
                                    rq['value'] = value
                                mc_rqs.append(rq)
                        except Exception as e:
                            logging.warning('Role %s: Enforcement %s: %s', role_name, enforcement, e)
                for enforcement in dst_enforcements:
                    rq = {
                        'command': 'role_enforcement_remove',
                        'role_id': dst_role_id,
                        'enforcement': enforcement,
                    }
                    mc_rqs.append(rq)
            if mc_rqs:
                api.execute_batch(mc_params, mc_rqs)
            logging.info('MC %s: Roles are in sync', mc_id)

    @staticmethod
    def get_enforcement_value(name, value):    # type: (str, str) -> Any
        name = name.lower()
        if name in constants.ENFORCEMENTS:
            enforcement_type = constants.ENFORCEMENTS[name]
            if enforcement_type == 'long':
                try:
                    return int(value)
                except Exception as e:
                    raise Exception(f'Enforcement {name}: invalid integer value: {value}')
            if enforcement_type == 'boolean':
                return value == 'true'
            if enforcement_type == 'account_share':  # not supported
                return
            if enforcement_type in ('record_types', 'json', 'jsonarray'):
                return json.loads(value)

            return value  # 'ip_whitelist', 'string', 'two_factor_duration', 'ternary_*'

    @staticmethod
    def find_roles(params, name):   # type: (KeeperParams, str) -> Iterable[Dict]
        if isinstance(params.enterprise, dict):
            if name.isdigit():
                role_id = int(name)
                for role in params.enterprise.get('roles') or []:
                    if role_id == role.get('role_id'):
                        yield role
                        return

            for role in params.enterprise.get('roles') or []:
                role_name = role['data'].get('displayname') or ''
                if role_name.casefold() == name.casefold():
                    yield role
