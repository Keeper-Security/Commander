#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2021 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example code to create a Team and add users to the team
#
# This example also pulls configuration from config.json 
# or writes the config file if it does not exist.
#
# Usage:
#    python3 create_mc.py

import getpass
import os

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands import msp

my_params = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))
while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

api.login(my_params)
if not my_params.session_token:
    exit(1)

api.query_enterprise(my_params)

# create MC
# msp_add_parser.add_argument('--node', dest='node', action='store', help='node name or node ID')
# msp_add_parser.add_argument('-s', '--seats', dest='seats', action='store', type=int,
#                             help='Maximum licences allowed. -1: unlimited')
# msp_add_parser.add_argument('-p', '--plan', dest='plan', action='store', required=True,
#                             choices=['business', 'businessPlus', 'enterprise', 'enterprisePlus'])
# msp_add_parser.add_argument('-f', '--file-plan', dest='file_plan', action='store',
#                             choices=['100gb', '1tb', '10tb'])
# msp_add_parser.add_argument('-a', '--addon', dest='addon', action='append', metavar='ADDON[:SEATS]',
#                             help=f'Add-ons: enterprise_breach_watch, compliance_report, enterprise_audit_and_reporting,
#                             msp_service_and_support, secrets_manager, connection_manager:N, chat
# msp_add_parser.add_argument('name', action='store', help='Managed Company name')

mc_add_command = msp.MSPAddCommand()
node = None              # optional. node ID or Name. parameter name is the same as "dest"
seats = -1               # optional
plan = 'businessPlus'    # required
file_plan = None         # optional.  '100gb' or '1tb' or '10tb'
addon = ['compliance_report']  # optional. should be an array of addons
# Add-ons: enterprise_breach_watch, compliance_report, enterprise_audit_and_reporting, msp_service_and_support, secrets_manager, connection_manager:N, chat
name = 'New MC'          # required

# create businessPlus MC with unlimited seats,  compliance_report addon
# MC ID is returned
mc_id = mc_add_command.execute(my_params, plan=plan, name=name, addon=addon)

# update MC
# msp_update_parser.add_argument('-p', '--plan', dest='plan', action='store',
#                                choices=['business', 'businessPlus', 'enterprise', 'enterprisePlus'])
# msp_update_parser.add_argument('-s', '--seats', dest='seats', action='store', type=int,
#                                help='Maximum licences allowed. -1: unlimited')
# msp_update_parser.add_argument('-f', '--file-plan', dest='file_plan', action='store',
#                                choices=['100gb', '1tb', '10tb'])
#
# Add-ons: enterprise_breach_watch, compliance_report, enterprise_audit_and_reporting, msp_service_and_support, secrets_manager, connection_manager:N, chat
#
# msp_update_parser.add_argument('-aa', '--add-addon', dest='add_addon', action='append', metavar='ADDON[:SEATS]'')
# msp_update_parser.add_argument('-ra', '--remove-addon', dest='remove_addon', action='append', metavar='ADDON')
# msp_update_parser.add_argument('mc', action='store',
#                                help='Managed Company identifier (name or id). Ex. 3862 OR "Keeper Security, Inc."')

mc_update_command = msp.MSPUpdateCommand()
seats = 4
add_addon = ['secrets_manager']
remove_addon = ['compliance_report']
mc_update_command.execute(my_params, mc=mc_id, seats=seats, add_addon=add_addon, remove_addon=remove_addon)


# remove MC
mc_remove_command = msp.MSPRemoveCommand()
mc_remove_command.execute(my_params, mc=mc_id, force=True)

api.query_enterprise(my_params)