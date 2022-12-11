#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example script to run a BreachWatch status report, parse the results,
# and send users an email reminder to address their found issues.
#
# Note: SMTP credentials must be supplied via a vault record
# in order to send the email. 
# 
# This example also pulls configuration
# from config.json or writes the config file if it does not exist.
#
# Usage:
#    python send_breachwatch_reminder.py

import base64
import getpass
import json
import os
import ssl

from smtplib import SMTP

from keepercommander import api, vault_extensions, vault
from keepercommander.commands.enterprise import SecurityAuditReportCommand
from keepercommander.params import KeeperParams


email_message = '''
From: {0}
Subject: Keeper BreachWatch Alert

BreachWatch detected records at risk in your vault.
Please login to Keeper and review the records marked "At Risk".
'''

def read_config_file(params):
    params.config_filename = os.path.join(os.path.dirname(__file__), 'config.json')
    if os.path.isfile(params.config_filename):
        with open(params.config_filename, 'r') as f:
            params.config = json.load(f)
            if 'user' in params.config:
                params.user = params.config['user']

            if 'password' in params.config:
                params.password = params.config['password']

            if 'mfa_token' in params.config:
                params.mfa_token = params.config['mfa_token']

            if 'server' in params.config:
                params.server = params.config['server']

            if 'device_id' in params.config:
                device_id = base64.urlsafe_b64decode(params.config['device_id'] + '==')
                params.rest_context.device_id = device_id


my_params = KeeperParams()
read_config_file(my_params)

while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

while not my_params.password:
    my_params.password = getpass.getpass(prompt='Master Password: ', stream=None)

report_command = SecurityAuditReportCommand()
report_json = report_command.execute(my_params, breachwatch=True, format='json')
report = json.loads(report_json)
emails = [x['email'] for x in report if x.get('at_risk') > 5]
if emails:
    api.sync_down(my_params)
    smtp_record = next(vault_extensions.find_records(my_params, search_str='smtp', record_type='serverCredentials'), None)
    if isinstance(smtp_record, vault.TypedRecord):
        smtp_host = None
        smtp_port = 0
        username = None
        password = None
        field = smtp_record.get_typed_field('host')
        if field:
            host_value = field.get_default_value()
            if isinstance(host_value, dict):
                smtp_host = host_value.get('hostName')
                port = host_value.get('port')
                if port:
                    try:
                        smtp_port = int(port)
                    except ValueError:
                        pass
        if smtp_host:
            field = smtp_record.get_typed_field('login')
            if field:
                username = field.get_default_value()
            field = smtp_record.get_typed_field('password')
            if field:
                password = field.get_default_value()

        if smtp_host:
            with SMTP(host=smtp_host, port=smtp_port) as connection:
                if username:
                    connection.starttls(context=ssl.create_default_context())
                    connection.login(user=username, password=password)
                connection.sendmail(my_params.user, emails, email_message.format(my_params.user))
