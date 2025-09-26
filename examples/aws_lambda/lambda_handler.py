#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com

import os

# Without mounted volumes, Lambda can only write to /tmp. 
# The following environment variables are needed to make sure the Python import cache 
# is written to /tmp and not the user folder.
os.environ['HOME'] = '/tmp'
os.environ['TMPDIR'] = '/tmp'
os.environ['TEMP'] = '/tmp'

from keepercommander import api
from keepercommander.__main__ import get_params_from_config

# By default, Keeper Commander will attempt to create a .keeper directory 
# in the user folder to store the JSON configuration.
# In this case we will create a .keeper directory in /tmp 
# to store the JSON configuration (using get_params_from_config()).
keeper_tmp = '/tmp/.keeper'
os.makedirs(keeper_tmp, exist_ok=True)

# ------------------------------------------------------
# Keeper initialization function
# ------------------------------------------------------
def get_params():
    # Change the default JSON configuration location to /tmp
    params = get_params_from_config(keeper_tmp + '/config.json') 

    # Set username and password for Keeper Commander login
    #params.config = {'sso_master_password': True} # Force Master-Password login for SSO users
    #params.server = os.environ.get('KEEPER_SERVER') # https://keepersecurity.com
    params.user = os.environ.get('KEEPER_USER')
    params.password = os.environ.get('KEEPER_PASSWORD')
    

    return params

# ------------------------------------------------------
# Keeper JSON report function
# ------------------------------------------------------
def get_keeper_report(params, kwargs):
    from keepercommander.commands.aram import AuditReportCommand
    from json import loads
    
    report_class = AuditReportCommand()
    report = report_class.execute(params, **kwargs)
    return loads(report)
    
# ------------------------------------------------------
# Keeper CLI function
# ------------------------------------------------------
def run_keeper_cli(params, command):
    from keepercommander import cli
    
    cli.do_command(params, command)
    # No return statement as this function runs the CLI command 
    # without returning anything in Python
    
# ------------------------------------------------------
# Lambda handler
# ------------------------------------------------------
def lambda_handler(event, context):
    # Initialize Keeper Commander params
    params = get_params()

    # Keeper login and sync
    api.login(params)
    api.sync_down(params)
    # Enterprise sync (for enterprise commands)
    api.query_enterprise(params)

    run_keeper_cli(
        params, 
        'device-approve -a'
    )
    
    run_keeper_cli(
        params, 
        'action-report --target locked --apply-action delete --dry-run'
    )

    return get_keeper_report(
        params,
        {
            'report_type':'raw', 
            'format':'json',
            'limit':100,
            'event_type':['login']
        }
    )
