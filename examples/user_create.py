#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Usage:
#    python3 user_create.py

import argparse
import getpass
import logging
import os
import sys
import re
from typing import Optional

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands.enterprise import EnterpriseUserCommand
from keepercommander.commands.enterprise_push import EnterprisePushCommand
from keepercommander.commands.enterprise_create_user import CreateEnterpriseUserCommand
from keepercommander import vault, vault_extensions, record_management

parser = argparse.ArgumentParser(description='Onboard users')
parser.add_argument('--debug', action='store_true', help='Enables debug logging')
parser.add_argument('--email', help='User to create')
opts, flags = parser.parse_known_args(sys.argv[1:])
logging.basicConfig(level=logging.DEBUG if opts.debug is True else logging.INFO, format='%(message)s', filename="keeper_log.txt", filemode='w')

NODE_NAME = '<NODE NAME HERE>'

authKeeper = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))

while not authKeeper.user:
    authKeeper.user = getpass.getpass(prompt='User(Email): ', stream=None)

def create_or_invite_user(params, email):
    try:
        create_command = CreateEnterpriseUserCommand()
        create_command.execute(params, email=email, node=NODE_NAME)
    except Exception as e:
        logging.warning(e)

    user = next((x for x in authKeeper.enterprise['users'] if x['username'] == email), None)
    if user is None:
        try:
            user_command = EnterpriseUserCommand()
            user_command.execute(params, invite=True, node=NODE_NAME, email=[email])
        except Exception as e:
            logging.warning(e)

def push_records_to_user(params, email):
    script_dir = os.path.dirname(__file__)
    script_name = os.path.join(script_dir, 'enterprise_push.json')
    if os.path.isfile(script_name):
        command = EnterprisePushCommand()
        command.execute(params, user=[email], file=script_name)
    else:
        logging.info('Push script file "%s" is not found (USE-103)', script_name)


if not opts.email:
    logging.info('Username parameter is required.')
    exit(1)

api.login(authKeeper)

if not authKeeper.session_token:
    logging.info('Could not connect to Keeper Commander (USE-103)')
    exit(1)

api.query_enterprise(authKeeper)
if not authKeeper.enterprise:
    logging.info('Not an enterprise administrator (USE-104)')
    exit(1)

username = opts.email.lower()

user = next((x for x in authKeeper.enterprise['users'] if x['username'] == username), None)
if user is None:   # user does not exist
    if re.search(r'[\w.]+@[\w.]+', username):
        create_or_invite_user(authKeeper, username)
    else:
        logging.info('Not a valid email address (USE-102)')
        exit(1)

user = next((x for x in authKeeper.enterprise['users'] if x['username'] == username), None)
if user is None:
    logging.info(f'User {username} was not created/invited')
    exit(1)

status = user.get('status')
if status != 'active':
    logging.info(f'User {username} is invited')
    exit(1)

api.sync_down(params=authKeeper)
record = next(vault_extensions.find_records(authKeeper, 'Created users'), None)   # type: Optional[vault.TypedRecord]
if record is None:
    record = vault.KeeperRecord.create(authKeeper, 'encryptedNotes')
    record.title = 'Created users'
    record_management.add_record_to_folder(authKeeper, record)
    api.sync_down(params=authKeeper)
    record = next(vault_extensions.find_records(authKeeper, 'Created users'), None)

if record is not None:
    field = next((x for x in record.custom if x.type == 'checkbox' and x.label == username), None)
    if field is None:
        push_records_to_user(authKeeper, username)
        field = vault.TypedField.new_field('checkbox', True, username)
        record.custom.append(field)
        record_management.update_record(authKeeper, record)
