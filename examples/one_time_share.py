import argparse
import logging
import sys

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands import register

parser = argparse.ArgumentParser(description='Create one time share URL')
parser.add_argument('--name', dest='share_name', action='store', help='one-time share URL name')
parser.add_argument('-e', '--expire', dest='expire', action='store', metavar='<NUMBER>[(m)inutes|(h)ours|(d)ays]',
                                          help='Time period record share URL is valid.')
parser.add_argument('record', nargs='?', type=str, action='store', help='record path or UID')

opts, flags = parser.parse_known_args(sys.argv[1:])

# Load Keeper configuration file
my_params = get_params_from_config('')

# Login to Keeper
api.login(my_params)
if not my_params.session_token:
    exit(1)

# Load vault
api.sync_down(my_params)

# Create one time share command
cmd = register.OneTimeShareCreateCommand()
url = cmd.execute(my_params, record=opts.record, share_name=opts.share_name, expire=opts.expire)
print(url)
