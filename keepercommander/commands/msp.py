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
import json
import logging
import os
import string
from datetime import datetime, timedelta
from typing import Set, Dict, List

from .base import suppress_exit, raise_parse_exception, dump_report_data, user_choice
from .enterprise import EnterpriseCommand
from ..proto import enterprise_pb2
from .. import api, crypto, utils, loginv3, error
from ..display import format_managed_company, format_msp_licenses, bcolors
from ..error import CommandError


def register_commands(commands):
    commands['msp-down'] = GetMSPDataCommand()
    commands['msp-info'] = MSPInfoCommand()
    commands['msp-add'] = MSPAddCommand()
    commands['msp-remove'] = MSPRemoveCommand()
    commands['msp-license'] = MSPLicenseCommand()
    commands['msp-license-report'] = MSPLicensesReportCommand()
    commands['msp-convert-node'] = MSPConvertNodeCommand()


def register_command_info(aliases, command_info):
    aliases['md'] = 'msp-down'
    aliases['mi'] = 'msp-info'
    aliases['ma'] = 'msp-add'
    aliases['mrm'] = 'msp-remove'
    aliases['ml'] = 'msp-license'
    aliases['mlr'] = 'msp-license-report'

    for p in [msp_data_parser, msp_info_parser, msp_add_parser, msp_remove_parser, msp_license_parser, msp_license_report_parser]:
        command_info[p.prog] = p.description


msp_data_parser = argparse.ArgumentParser(prog='msp-down|md',
                                          description='Download current MSP data from the Keeper Cloud.',
                                          usage='msp-down')
msp_data_parser.error = raise_parse_exception
msp_data_parser.exit = suppress_exit

msp_info_parser = argparse.ArgumentParser(prog='msp-info|mi',
                                          description='Displays MSP details, such as licenses and managed companies.',
                                          usage='msp-info')
# msp_info_parser.add_argument('-n', '--nodes', dest='nodes', action='store_true', help='print node tree')
# msp_info_parser.add_argument('-u', '--users', dest='users', action='store_true', help='print user list')
msp_info_parser.error = raise_parse_exception
msp_info_parser.exit = suppress_exit

msp_license_parser = argparse.ArgumentParser(prog='msp-license', description='View and Manage MSP licenses.', usage='msp-license --add --seats=4')
msp_license_parser.add_argument('-a', '--action', dest='action', action='store', choices=['add', 'reduce', 'usage'], help='Action to perform on the licenses', default='usage')
msp_license_parser.add_argument('--mc', dest='mc', action='store', help='Managed Company identifier (name or id). Ex. 3862 OR "Keeper Security, Inc."')
# msp_license_parser.add_argument('--product_id', dest='product_id', action='store', choices=['business', 'businessPlus', 'enterprise', 'enterprisePlus'], help='Plan Id.')
msp_license_parser.add_argument('-s', '--seats', dest='seats', action='store', type=int, help='Number of seats to add or reduce.')
msp_license_parser.error = raise_parse_exception
msp_license_parser.exit = suppress_exit

ranges = ['today', 'yesterday', 'last_7_days', 'last_30_days', 'month_to_date', 'last_month', 'year_to_date', 'last_year']

msp_license_report_parser = argparse.ArgumentParser(prog='msp-license-report',
                                                    description='Generate MSP License Reports.')
msp_license_report_parser.add_argument('--type',
                                       dest='report_type',
                                       choices=['allocation', 'audit'],
                                       help='Type of the report',
                                       default='allocation')
msp_license_report_parser.add_argument('--format', dest='report_format', choices=['table', 'csv', 'json'],
                                       help='Format of the report output', default='table')
msp_license_report_parser.add_argument('--range', dest='range', choices=ranges, default='last_30_days',
                                       help="Pre-defined data ranges to run the report.")
msp_license_report_parser.add_argument('--from', dest='from_date',
                                       help='Run report from this date. Value in ISO 8601 format (YYYY-mm-dd) or Unix timestamp format. Only applicable to the `audit` report AND when there is no `range` specified. Example: `2020-08-18` or `1596265200`Example: 2020-08-18 or 1596265200')
msp_license_report_parser.add_argument('--to', dest='to_date',
                                       help='Run report until this date. Value in ISO 8601 format (YYYY-mm-dd) or Unix timestamp format. Only applicable to the `audit` report AND when there is no `range` specified. Example: `2020-08-18` or `1596265200`Example: 2020-08-18 or 1596265200')
msp_license_report_parser.add_argument('--output', dest='output', action='store', help='Output file name. (ignored for table format)')
msp_license_report_parser.error = raise_parse_exception
msp_license_report_parser.exit = suppress_exit

msp_add_parser = argparse.ArgumentParser(prog='msp-add', description='Add Managed Company.')
msp_add_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
msp_add_parser.add_argument('-s', '--seats', dest='seats', action='store', required=True, type=int,
                            help='Number of seats')
msp_add_parser.add_argument('-p', '--plan', dest='plan', action='store', required=True,
                            choices=['business', 'businessPlus', 'enterprise', 'enterprisePlus'],
                            help='License Plan')
msp_add_parser.add_argument('name', action='store', help='Managed Company name')

msp_remove_parser = argparse.ArgumentParser(prog='msp-remove', description='Remove Managed Company.')
msp_remove_parser.add_argument('mc', action='store', help='Managed Company identifier (name or id). Ex. 3862 OR "Keeper Security, Inc."')

msp_convert_node_parser = argparse.ArgumentParser(prog='msp-convert-node', description='Converts MSP node into Managed Company.')
msp_convert_node_parser.add_argument('-s', '--seats', dest='seats', action='store', type=int,
                                     help='Number of seats')
msp_convert_node_parser.add_argument('-p', '--plan', dest='plan', action='store',
                                     choices=['business', 'businessPlus', 'enterprise', 'enterprisePlus'],
                                     help='License Plan')
msp_convert_node_parser.add_argument('node', action='store', help='node name or node ID')


class GetMSPDataCommand(EnterpriseCommand):

    def get_parser(self):
        return msp_data_parser

    def execute(self, params, **kwargs):
        api.query_enterprise(params)


class MSPInfoCommand(EnterpriseCommand):
    def get_parser(self):
        return msp_info_parser

    def execute(self, params, **kwargs):

        # MSP license pool
        licenses = params.enterprise['licenses']
        if licenses:
            format_msp_licenses(licenses)

        mcs = None

        if 'managed_companies' in params.enterprise:
            mcs = params.enterprise['managed_companies']

        if mcs:
            format_managed_company(mcs)
        else:
            print("No Managed Companies\n")


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

        elif action == 'add' or action == 'reduce':
            seats = kwargs['seats']

            mc_input = kwargs['mc'] if kwargs['mc'] else -1

            msp_license_pool = enterprise['licenses'][0]['msp_pool']
            managed_companies = enterprise['managed_companies']

            current_mc = get_mc_by_name_or_id(managed_companies, mc_input)

            if current_mc is None:
                raise CommandError('msp-license', 'No managed company found for given company id or name')

            current_product_id = current_mc['product_id']
            seats_to_set = 0

            license_from_pool = find(lambda lic: lic['product_id'] == current_product_id, msp_license_pool)

            if action == 'add':
                if license_from_pool['availableSeats'] < seats:
                    error_message = "Cannot add more than allowed seats. Currently available seats " + str(license_from_pool['availableSeats']) + " trying to add " + str(seats)
                    raise CommandError('msp-license', error_message)
                else:
                    seats_to_set = current_mc['number_of_seats'] + seats
            elif action == 'reduce':
                seats_to_set = current_mc['number_of_seats'] - seats

                if seats_to_set < 0:
                    seats_to_set = 0

            rq = {
                'command': 'enterprise_update_by_msp',
                'enterprise_id': current_mc['mc_enterprise_id'],
                'enterprise_name': current_mc['mc_enterprise_name'],
                'product_id': current_mc['product_id'],
                'seats': seats_to_set
            }

            rs = api.communicate(params, rq)

            if rs['result'] == 'success':
                mc_from_rs = find(lambda mc: mc['mc_enterprise_id'] == rs["enterprise_id"], managed_companies)
                print("Successfully updated '%s' id=%d" % (mc_from_rs['mc_enterprise_name'], mc_from_rs['mc_enterprise_id']))
                api.query_enterprise(params)


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
                    rows = [
                        [
                            ml.get('product_id') or '-',
                            ml.get('availableSeats') or '-',
                            ml.get('seats') or '-',
                            ml.get('stash') or '-'
                        ] for j, ml in enumerate(lic.get('msp_pool'))]
        else:

            if not from_date_str or not to_date_str:
                # will use data range to query

                rng = kwargs['range']
                from_date1, end_date1 = date_range_str_to_dates(rng)

                from_date = from_date1
                to_date = end_date1
            else:
                # will use start and end data
                if loginv3.CommonHelperMethods.check_int(from_date_str):
                    from_date = datetime.fromtimestamp(int(from_date_str))
                else:
                    from_date = datetime.strptime(from_date_str + " 00:00:00", "%Y-%m-%d %H:%M:%S")

                if loginv3.CommonHelperMethods.check_int(to_date_str):
                    to_date = datetime.fromtimestamp(int(to_date_str))
                else:
                    to_date = datetime.strptime(to_date_str + " 11:59:59", "%Y-%m-%d %H:%M:%S")

            from_date_timestamp = int(from_date.timestamp() * 1000)
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

        if kwargs.get('format') != 'json':
            headers = [string.capwords(x.replace('_', ' ')) for x in headers]

        output = dump_report_data(rows, headers, fmt=report_format, filename=report_output_file, append=to_append)

        if report_format != 'table' and not output:
            print("Successfully saved report to", report_generation_message(report_output_file, report_format))
            print()

        return output


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
        name = kwargs['name']
        tree_key = utils.generate_aes_key()
        rq = {
            'command': 'enterprise_registration_by_msp',
            'node_id': node_id,
            'seats': kwargs['seats'],
            'product_id': kwargs['plan'],
            'enterprise_name': name,
            'encrypted_tree_key': utils.base64_url_encode(
                crypto.encrypt_aes_v2(tree_key, params.enterprise['unencrypted_tree_key'])),
            'role_data': utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps({'displayname': 'Keeper Administrator'}).encode(), tree_key)),
            'root_node': utils.base64_url_encode(
                crypto.encrypt_aes_v1(json.dumps({'displayname': 'root'}).encode(), tree_key))
        }
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

    found_mc = None
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

    current_time = datetime.now()

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
        start_date = today_start_dt - timedelta(1)
        end_date = today_end_dt - timedelta(1)

    elif range_str == 'last_7_days':
        start_date = today_start_dt - timedelta(7)
        end_date = today_end_dt

    elif range_str == 'last_30_days':
        start_date = today_start_dt - timedelta(30)
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

        msp_license_pool = params.enterprise['licenses'][0]['msp_pool']
        seats = kwargs.get('seats') or 0
        if seats < len(users_to_move):
            seats = len(users_to_move)
        if seats == 0:
            seats = 1
        plan = kwargs.get('plan')
        if plan:
            pool = next((x for x in msp_license_pool if x['product_id'] == plan), None)
            if pool:
                if pool['availableSeats'] < seats:
                    errors.append(f'Not enough seats ({seats}) in the selected plan {plan}')
            else:
                errors.append(f'Invalid plan {plan}')

        else:
            plan = next((x['product_id'] for x in msp_license_pool if x['availableSeats'] >= seats), None)
            if not plan:
                errors.append(f'There is no plan with {seats} available seats')

        if len(errors) > 0:
            print('\n'.join(errors))
            return

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
        logging.info(f'Node \"{msp_node_name}\" was converted to Managed Company' )
        api.query_enterprise(params)
