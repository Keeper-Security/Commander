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
#
import json
import os
from typing import Optional

from keepercommander import api
from keepercommander.commands.enterprise import UserReportCommand
from keepercommander.commands.security_audit import SecurityAuditReportCommand
from keepercommander.params import KeeperParams


def create_user_report(params):  # type: (KeeperParams) -> Optional[str]
    user_report = UserReportCommand()
    user_report_data = user_report.execute(params, format='json')
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


def lambda_handler(event, context):
    params = get_params()
    api.login(params)
    if not params.session_token:
        return {
            'statusCode': 401,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'Not Connected',
        }

    if not params.enterprise:
        return {
            'statusCode': 401,
            'headers': {'Content-Type': 'text/plain'},
            'body': 'Not enterprise administrator',
        }
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': create_user_report(params),
    }


# Get required Commander parameters from environment variables
def get_params():
    user = os.environ.get('KEEPER_USER')
    pw = os.environ.get('KEEPER_PASSWORD')
    server = os.environ.get('KEEPER_SERVER')
    private_key = os.environ.get('KEEPER_PRIVATE_KEY')
    token = os.environ.get('KEEPER_DEV_TOKEN')
    my_params = KeeperParams()
    my_params.user = user
    my_params.password = pw
    my_params.server = server
    my_params.device_private_key = private_key
    my_params.device_token = token
    return my_params


if __name__ == '__main__':
    from keepercommander.__main__ import get_params_from_config
    my_params = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))

    if my_params.user:
        print(f'User(Email): {my_params.user}')
    else:
        while not my_params.user:
            my_params.user = input('User(Email): ')

    api.login(my_params)
    if not my_params.session_token:
        exit(1)

    print(create_user_report(my_params))
