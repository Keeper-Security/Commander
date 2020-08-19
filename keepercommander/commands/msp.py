#_  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2020 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
import argparse
import os
import string
from datetime import datetime

from .base import suppress_exit, raise_parse_exception, dump_report_data, Command
from .enterprise import EnterpriseCommand
from .. import api
from ..display import format_managed_company, format_msp_licenses
from ..error import CommandError


def register_commands(commands):
    commands['msp-down'] = GetMSPDataCommand()
    commands['msp-info'] = MSPInfoCommand()
    commands['msp-license'] = MSPLicenseCommand()
    commands['msp-license-report'] = MSPLicensesReportCommand()


def register_command_info(aliases, command_info):
    aliases['md'] = 'msp-down'
    aliases['mi'] = 'msp-info'
    aliases['ml'] = 'msp-license'
    aliases['mlr'] = 'msp-license-report'

    for p in [msp_data_parser, msp_info_parser, msp_license_parser, msp_license_report_parser]:
        command_info[p.prog] = p.description


msp_data_parser = argparse.ArgumentParser(prog='msp-down|md',
                                          description='Refresh MSP data from the server',
                                          usage='msp-down')
msp_data_parser.error = raise_parse_exception
msp_data_parser.exit = suppress_exit

msp_info_parser = argparse.ArgumentParser(prog='msp-info|mi',
                                          description='Display MSP details, such as licenses and managed companies',
                                          usage='msp-info')
# msp_info_parser.add_argument('-n', '--nodes', dest='nodes', action='store_true', help='print node tree')
# msp_info_parser.add_argument('-u', '--users', dest='users', action='store_true', help='print user list')
msp_info_parser.error = raise_parse_exception
msp_info_parser.exit = suppress_exit

msp_license_parser = argparse.ArgumentParser(prog='msp-license', description='MSP License Management', usage='msp-license --add --seats=4')
msp_license_parser.add_argument('-a', '--action', dest='action', action='store', choices=['list', 'add', 'revoke', 'usage'], help='Action to perform on the licenses')
msp_license_parser.add_argument('--mc_id', dest='mc_id', action='store', help='Numerical ID of the Managed Company. Ex. 3862')
# msp_license_parser.add_argument('--product_id', dest='product_id', action='store', choices=['business', 'businessPlus', 'enterprise', 'enterprisePlus'], help='Plan Id.')
msp_license_parser.add_argument('-s', '--seats', dest='seats', action='store', type=int, help='Seats to add or revoke.')
msp_license_parser.error = raise_parse_exception
msp_license_parser.exit = suppress_exit

msp_license_report_parser = argparse.ArgumentParser(prog='msp-license-report', description='MSP License Reports')
msp_license_report_parser.add_argument('--type', dest='report_type', choices=['allocation', 'audit'], help='Type of the report', default='allocation')
msp_license_report_parser.add_argument('--format', dest='report_format', choices=['table', 'csv', 'json'], help='Format of the report output', default='table')
msp_license_report_parser.add_argument('--from', dest='from_date', help='Run report from this date. Example: 08/16/2020')
msp_license_report_parser.add_argument('--to', dest='to_date', help='Run report until this date. Example: 08/18/2020')
msp_license_report_parser.add_argument('--output', dest='output', action='store', help='output file name. (ignored for table format)')
msp_license_report_parser.error = raise_parse_exception
msp_license_report_parser.exit = suppress_exit


class GetMSPDataCommand(Command):

    def get_parser(self):
        return msp_data_parser

    def execute(self, params, **kwargs):
        print("In GetMSPDataCommand()", kwargs)
        api.query_msp(params)


class MSPInfoCommand(Command):
    def get_parser(self):
        return msp_info_parser

    def execute(self, params, **kwargs):

        # MSP license pool
        licenses = params.enterprise['licenses']
        if licenses:
            format_msp_licenses(licenses)

        mcs = params.enterprise['managed_companies']

        if mcs:
            format_managed_company(mcs)


class MSPLicenseCommand(EnterpriseCommand):

    def get_parser(self):
        return msp_license_parser

    def execute(self, params, **kwargs):

        # product_id = kwargs['product_id']
        action = kwargs['action']

        enterprise = params.enterprise

        if action == 'usage':
            licenses = enterprise['licenses']
            if licenses:
                format_msp_licenses(licenses)
            return

        elif action is 'add' or 'revoke':
            seats = kwargs['seats']

            mc_id = int(kwargs['mc_id']) if kwargs['mc_id'] else -1

            msp_license_pool = enterprise['licenses'][0]['msp_pool']
            managed_companies = enterprise['managed_companies']

            current_mc = find(lambda mc: mc['mc_enterprise_id'] == mc_id, managed_companies)
            current_product_id = current_mc['product_id']
            seats_to_set = 0

            license_from_pool = find(lambda lic: lic['product_id'] == current_product_id, msp_license_pool)

            if action == 'add':
                if license_from_pool['availableSeats'] < seats:
                    error_message = "Cannot add more than allowed seats. Currently available seats " + str(license_from_pool['availableSeats']) + " trying to add " + str(seats)
                    raise CommandError('msp-license', error_message)
                else:
                    seats_to_set = current_mc['number_of_seats'] + seats
            elif action == 'revoke':
                seats_to_set = current_mc['number_of_seats'] - seats

                if seats_to_set < 0:
                    seats_to_set = 0

            rq = {
                'command': 'enterprise_update_by_msp',
                'enterprise_id': mc_id,                     # --mc_id=3862
                'enterprise_name': current_mc['mc_enterprise_name'],
                'product_id': current_mc['product_id'],
                'seats': seats_to_set
            }

            rs = api.communicate(params, rq)

            if rs['result'] == 'success':
                mc_from_rs = find(lambda mc: mc['mc_enterprise_id'] == rs["enterprise_id"], managed_companies)
                print("Successfully updated '%s' id=%d" % (mc_from_rs['mc_enterprise_name'], mc_from_rs['mc_enterprise_id']))
                api.query_msp(params)


class MSPLicensesReportCommand(EnterpriseCommand):
    def get_parser(self):
        return msp_license_report_parser

    def execute(self, params, **kwargs):

        report_output_file = kwargs['output']
        report_type = kwargs['report_type']
        report_format = kwargs['report_format']
        from_date_str = kwargs['from_date']
        to_date_str = kwargs['to_date']

        to_append = False

        rows = []

        if report_type == 'allocation':
            licenses = params.enterprise['licenses']

            headers = ['plan_id', 'available_licenses', 'total_licenses', 'stash']

            if len(licenses) > 0:
                for i, lic in enumerate(licenses):
                    rows = [[ml['product_id'], ml['availableSeats'], ml['seats'], ml['stash']] for j, ml in enumerate(lic['msp_pool'])]
        else:
            if not from_date_str and not to_date_str:
                raise CommandError('msp-license-report', "to and from are required to run the report.")

            from_date = datetime.strptime(from_date_str + " 00:00:00", "%m/%d/%Y %H:%M:%S")
            from_date_timestamp = int(from_date.timestamp() * 1000)

            to_date = datetime.strptime(to_date_str + " 11:59:59", "%m/%d/%Y %H:%M:%S")
            to_date_timestamp = int(to_date.timestamp() * 1000)

            rq = {
                'command': 'get_mc_license_adjustment_log',
                'from': from_date_timestamp,
                'to': to_date_timestamp
            }

            rs = api.communicate(params, rq)

            headers = ['id', 'time', 'company_id', 'company_name', 'status', 'number_of_allocations', 'plan',
                       'transaction_notes', 'price_estimate']

            for log in rs['log']:
                rows.append([log['id'],
                             log['date'],
                             log['enterprise_id'],
                             log['enterprise_name'],
                             log['status'],
                             log['new_number_of_seats'],
                             log['new_product_type'],
                             log['note'],
                             log['price']])

        # if kwargs.get('format') != 'json':
        #     headers = [string.capwords(x.replace('_', ' ')) for x in headers]

        dump_report_data(rows, headers, fmt=report_format, filename=report_output_file, append=to_append)

        if report_format != 'table':
            print("Successfully saved report to", report_generation_message(report_output_file, report_format))
            print()


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
