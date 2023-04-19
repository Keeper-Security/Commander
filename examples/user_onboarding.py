#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2023 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#
# Example code to onboard a user
# 1. Approve teams for a new user
# 2. Check for "enterprise_push.json" file
#
# Usage:
#    python3 user_onboarding.py

import getpass
import os
import time

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands.enterprise import TeamApproveCommand
from keepercommander.params import KeeperParams
from keepercommander.commands.enterprise_push import EnterprisePushCommand


def approve_teams(params):
    command = TeamApproveCommand()
    command.execute(params, team=True, user=True)


def push_records_to_user(params, enterprise_user_id):    # type: (KeeperParams, int) -> None
    email = next((x['username'] for x in params.enterprise['users']
                  if x['enterprise_user_id'] == enterprise_user_id), None)
    if email:
        command = EnterprisePushCommand()
        command.execute(params, user=email, file='enterprise_push.json')


my_params = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))
while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

api.login(my_params)
if not my_params.session_token:
    exit(1)

if not my_params.enterprise:
    print('Not an enterprise administrator')
    exit(1)

active_users = {x['username'] for x in my_params.enterprise['users'] if x['status'] == 'active' and x.get('lock') == 0}
new_users = {}

# detect new users by checking queued users
if 'teams' in my_params.enterprise:
    teams = {x['team_uid'] for x in my_params.enterprise['teams']}
    if 'queued_team_users' in my_params.enterprise:
        for qu in my_params.enterprise['queued_team_users']:
            if qu['team_uid'] in teams:
                new_users.update((x for x in qu['users'] if x in active_users))


while True:
    if len(new_users) > 0:
        print(f'Provisioning: {(",".join(new_users))}')
        approve_teams(my_params)
        if os.path.isfile('enterprise_push.json'):
            for user in new_users:
                try:
                    push_records_to_user(my_params, user)
                except Exception as e:
                    print(f'Cannot push records to user {user}: {e}')
        new_users.clear()

    time.sleep(5 * 60)

    api.query_enterprise(my_params)
    au = {x['username'] for x in my_params.enterprise['users'] if x['status'] == 'active' and x.get('lock') == 0}
    new_users.update(au.difference(active_users))
    if len(new_users) > 0:
        active_users.update(new_users)
