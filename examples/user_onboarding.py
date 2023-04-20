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

import argparse
import getpass
import logging
import os
import sys
import time
from typing import Set

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands.enterprise import TeamApproveCommand
from keepercommander.params import KeeperParams
from keepercommander.commands.enterprise_push import EnterprisePushCommand


parser = argparse.ArgumentParser(description='Onboard users')
parser.add_argument('--debug', action='store_true', help='Enables debug logging')
opts, flags = parser.parse_known_args(sys.argv[1:])
logging.basicConfig(level=logging.DEBUG if opts.debug is True else logging.INFO, format='%(message)s')


if os.path.isfile('enterprise_push.json'):
    logging.debug('Enterprise push file detected.')


def approve_teams(params):
    command = TeamApproveCommand()
    command.execute(params, team=True, user=True)


def push_records_to_user(params, enterprise_user_id):    # type: (KeeperParams, int) -> None
    username = next((x['username'] for x in params.enterprise['users'] if x['enterprise_user_id'] == enterprise_user_id), None)
    if username:
        command = EnterprisePushCommand()
        command.execute(params, user=[username], file='enterprise_push.json')
    else:
        logging.debug(f'Cannot resolve username for {enterprise_user_id}')


my_params = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))
while not my_params.user:
    my_params.user = getpass.getpass(prompt='User(Email): ', stream=None)

api.login(my_params)
if not my_params.session_token:
    exit(1)

if not my_params.enterprise:
    print('Not an enterprise administrator')
    exit(1)

active_users = {x['enterprise_user_id'] for x in my_params.enterprise['users']
                if x['status'] == 'active' and x.get('lock') == 0}    # type: Set[int]
new_users = set()    # type: Set[int]

# detect new users by checking queued users
if 'teams' in my_params.enterprise:
    teams = {x['team_uid'] for x in my_params.enterprise['teams']}
    if 'queued_team_users' in my_params.enterprise:
        for qu in my_params.enterprise['queued_team_users']:
            if qu['team_uid'] in teams:
                new_users.update((x for x in qu['users'] if x in active_users))


while True:
    if len(new_users) > 0:
        print(f'Provisioning {len(new_users)} users')
        approve_teams(my_params)
        if os.path.isfile('enterprise_push.json'):
            for user_id in new_users:
                try:
                    push_records_to_user(my_params, user_id)
                except Exception as e:
                    print(f'Cannot push records to user ID {user_id}: {e}')
        new_users.clear()

    logging.debug('Sleeping for 5 minutes.')
    time.sleep(5 * 60)

    api.query_enterprise(my_params)
    au = {x['enterprise_user_id'] for x in my_params.enterprise['users']
          if x['status'] == 'active' and x.get('lock') == 0}
    new_users.update(au.difference(active_users))
    active_users = au
