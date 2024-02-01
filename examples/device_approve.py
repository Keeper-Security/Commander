import argparse
import logging
import sys

from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.commands import enterprise

parser = argparse.ArgumentParser(description='Approves pending SSO devices')
parser.add_argument('--debug', action='store_true', help='Enables debug logging')
parser.add_argument('--reload', '-r', dest='reload', action='store_true', help='reload list of pending approval requests')
parser.add_argument('--approve', '-a', dest='approve', action='store_true', help='approve user devices')
parser.add_argument('--deny', '-d', dest='deny', action='store_true', help='deny user devices')
parser.add_argument('--format', dest='format', action='store', choices=['table', 'csv', 'json'],
                                   default='table', help='Output format. Applicable to list of devices in the queue.')
parser.add_argument('--output', dest='output', action='store',
                                   help='Output file name (ignored for table format)')
parser.add_argument('device', type=str, nargs='?', action="append", help='User email or device ID')
opts, flags = parser.parse_known_args(sys.argv[1:])

logging.basicConfig(level=logging.DEBUG if opts.debug is True else logging.WARNING, format='%(message)s')

my_params = get_params_from_config('')

api.login(my_params)
if not my_params.session_token:
    exit(1)

api.query_enterprise(my_params)

if logging.getLogger().getEffectiveLevel() == logging.WARNING:
    logging.getLogger().setLevel(logging.INFO)

cmd = enterprise.DeviceApproveCommand()
kwargs = {
    'reload': opts.reload,
    'approve': opts.approve,
    'deny': opts.deny,
    'format': opts.format,
    'output': opts.output,
    'device': opts.device
}
response = cmd.execute(my_params, **kwargs)
print(response)
