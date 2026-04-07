#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Description: 
#
#   This script demonstrates how to script the onboarding user accounts in an enterprise
#   and pushing records to the user's vault. 
#
#   - If the email domain has been reserved, the account is created instantly 
#     and the records are pushed.
#
#   - If the email domain is not reserved (e.g. gmail.com), the user will receive
#   an invite to create their vault. Upon next execution 
#
# Usage:
#    - Example: Invite a specific user:
#    python3 user_create.py <email>
#
#    - Example: Check the status of users and push records:
#    python3 user_create.py
#

import argparse
import getpass
import logging
import os
import re
import sys
from typing import Optional

from keepercommander import api
from keepercommander import vault, vault_extensions, record_management
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands.enterprise import EnterpriseUserCommand
from keepercommander.commands.enterprise_create_user import CreateEnterpriseUserCommand
from keepercommander.commands.enterprise_push import EnterprisePushCommand

parser = argparse.ArgumentParser(description='Onboard users')
parser.add_argument('--debug', action='store_true', help='Enables debug logging')
parser.add_argument('email', nargs='?', help='User to create')
opts, flags = parser.parse_known_args(sys.argv[1:])
logging.basicConfig(level=logging.DEBUG if opts.debug is True else logging.WARNING, format='%(message)s')

# Enter the name of the node where you are onboarding the users
NODE_NAME = '<NODE NAME HERE>'

authKeeper = get_params_from_config(os.path.join(os.path.dirname(__file__), 'config.json'))

# Prompt for login unless the config exists
while not authKeeper.user:
    authKeeper.user = getpass.getpass(prompt='User(Email): ', stream=None)

def create_or_invite_user(params, email):
    try:
        # Attempt to create the account without an invitation
        create_command = CreateEnterpriseUserCommand()
        create_command.execute(params, email=email, node=NODE_NAME)
        # Get the latest enterprise data
        api.query_enterprise(authKeeper)
    except Exception as e:
        logging.warning(e)

    user = next((x for x in authKeeper.enterprise['users'] if x['username'] == email), None)
    if user is None:
        try:
            # User must be invited normally
            user_command = EnterpriseUserCommand()
            user_command.execute(params, invite=True, node=NODE_NAME, email=[email])
            api.query_enterprise(authKeeper)
        except Exception as e:
            logging.warning(e)

def push_records_to_user(params, email):
    script_dir = os.path.dirname(__file__)
    script_name = os.path.join(script_dir, 'enterprise_push.json')
    if os.path.isfile(script_name):
        command = EnterprisePushCommand()
        command.execute(params, user=[email], file=script_name)
    else:
        logging.error('Unable to locate JSON push file "%s"', script_name)

api.login(authKeeper)

if not authKeeper.session_token:
    logging.error('Unable to login to Keeper')
    exit(1)

api.query_enterprise(authKeeper)
if not authKeeper.enterprise:
    logging.error('Unable to retrieve enterprise data - not an enterprise administrator')
    exit(1)

username = opts.email
if username:
    username = opts.email.lower()

    # See if the user exists in the enterprise
    user = next((x for x in authKeeper.enterprise['users'] if x['username'] == username), None)
    if user is None:   # user does not exist
        if re.search(r'[\w.]+@[\w.]+', username):
            create_or_invite_user(authKeeper, username)
        else:
            logging.warning('Not a valid email address: %s', username)
            exit(1)

        # Check to see if we succeeded in creating or inviting the user
        user = next((x for x in authKeeper.enterprise['users'] if x['username'] == username), None)
        if user is None:
            logging.error(f'User {username} was not created/invited')
            exit(1)

# Search for a record in the vault with the name "Created users"
# and use this record for storing the status of invited users
api.sync_down(params=authKeeper)
record = next(vault_extensions.find_records(authKeeper, 'Created users'), None)   # type: Optional[vault.TypedRecord]
if record is None:
    # record not found, so create it
    record = vault.KeeperRecord.create(authKeeper, 'encryptedNotes')
    record.title = 'Created users'
    record_management.add_record_to_folder(authKeeper, record)
    api.sync_down(params=authKeeper)
    record = next(vault_extensions.find_records(authKeeper, 'Created users'), None)
    if record is None:
        logging.error(f'Record "Created users" cannot be created')
        exit(1)
    else:
        logging.warning(f'Record "Created users" created')

pushed_to = []
should_update_record = False
try:
    if username:
        field = next((x for x in record.custom if x.type == 'text' and x.label == username), None)
        if field is None:
            field = vault.TypedField.new_field('text', ['push'], username)
            record.custom.append(field)
            should_update_record = True

    for status_field in record.custom:
        if status_field.type != 'text':
            continue
        email = status_field.label
        if not email:
            continue
        status_value = status_field.get_default_value(str)
        if not status_value:
            continue
        if status_value.casefold() != 'push':
            continue

        # find user
        user = next((x for x in authKeeper.enterprise['users'] if x['username'] == email), None)
        if user is None:
            continue
        # Check the status of the user (it can be active or invited)
        status = user.get('status')
        if status != 'active':
            continue
        lock = user.get('lock')
        if isinstance(lock, int) and lock != 0:
            logging.warning('User "%s" is locked. Skipping.', email)
            continue

        logging.warning('Pushing records to user "%s"', email)
        try:
            push_records_to_user(authKeeper, email)
            status_field.value = ['done']
            should_update_record = True
            pushed_to.append(email)
        except Exception as e:
            logging.warning('Error pushing records to %s: %s', email, e)
finally:
    if should_update_record:
        if len(pushed_to) > 0:
            logging.warning('Pushed records to:')
            for email in pushed_to:
                no = 1
                logging.warning(f'{no:>4}. {email}')
                no += 1
        record_management.update_record(authKeeper, record)
