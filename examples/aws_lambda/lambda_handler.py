#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#
#
# Sample AWS Lambda handler script
# In this example, we generate a report that combines the outputs
# of the `security-audit-report` and `user-report` commands,
# and then send those results to a specified email address ("KEEPER_SENDTO")


import json
import os
import datetime
from typing import Optional

from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import boto3

from keepercommander import api
from keepercommander.commands.enterprise import UserReportCommand
from keepercommander.commands.security_audit import SecurityAuditReportCommand
from keepercommander.params import KeeperParams


# This Lambda's entry point
def lambda_handler(event, context):
    params = get_params()
    api.login(params)
    api.query_enterprise(params, True)

    # Log Commander-related issues (e.g., incorrect credentials)
    # using AWS's built-in logging module and abort
    if not params.session_token:
        print('Not connected')
        return 'Error: See Lambda log for details'
    if not params.enterprise:
        print('Not enterprise administrator')
        return 'Error: See Lambda log for details'

    # Generate and send report
    report = create_user_report(params)
    response = email_result(report)
    return response


# Create report (format: JSON) combining data from 2 existing Commander reports
def create_user_report(params):  # type: (KeeperParams) -> Optional[str]
    user_report_cmd = UserReportCommand()
    user_report_data = user_report_cmd.execute(params, format='json')
    data = json.loads(user_report_data)
    users = {x['email']: x for x in data}
    security_audit_report = SecurityAuditReportCommand()
    security_audit_report_data = security_audit_report.execute(params, format='json')
    if security_audit_report_data:
        data = json.loads(security_audit_report_data)
        for x in data:
            if 'email' in x:
                email = x['email']
                if email in users:
                    user = users[email]
                    for key in x:
                        if key not in user:
                            if key not in ('node_path', 'username'):
                                user[key] = x[key]
                else:
                    users[email] = x

    return json.dumps(list(users.values()), indent=2)


# Email report data (as JSON attachment) to recipient specified in this Lambda
# function's environment variables
def email_result(report):
    sender = os.environ.get('KEEPER_SENDER')
    sendto = os.environ.get('KEEPER_SENDTO')
    region = 'us-east-1'
    ses_client = boto3.client('ses', region_name=region)

    message = MIMEMultipart('mixed')
    message['Subject'] = 'Keeper Commander User Security Report With  CSV (attached)'
    message['To'] = sendto
    message['From'] = sender
    now = datetime.datetime.now()

    body = MIMEText(f'User Report Output created and sent at {now}', 'plain')
    message.attach(body)

    attachment = MIMEApplication(report)
    attachment.add_header(
        'Content-Disposition',
        'attachment',
        filename='user-report.json'
    )
    message.attach(attachment)

    response = ses_client.send_raw_email(
        Source=message['From'],
        Destinations=[sendto],
        RawMessage={'Data': message.as_string()}
    )

    return response


# Get required Commander parameters from Lambda's environment variables (in "Configuration")
def get_params():
    user = os.environ.get('KEEPER_USER')
    pw = os.environ.get('KEEPER_PASSWORD')
    server = os.environ.get('KEEPER_SERVER')
    private_key = os.environ.get('KEEPER_PRIVATE_KEY')
    token = os.environ.get('KEEPER_DEVICE_TOKEN')
    my_params = KeeperParams()

    # Force password-login (needed for SSO + Master Password accounts)
    my_params.config = {'sso_master_password': True}

    my_params.user = user
    my_params.password = pw
    my_params.server = server
    my_params.device_private_key = private_key
    my_params.device_token = token
    return my_params

