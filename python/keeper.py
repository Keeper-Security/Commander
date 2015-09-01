# Keeper Commander for Python

import argparse
import json
# from pprint import pprint

version = '0.1'

CONFIG_FILENAME = 'config.json'
email = ''
password = ''
mfa = ''
command = ''
debug = True
gui = False

try:
    with open(CONFIG_FILENAME) as config_file:

        print('Loading config from ' + CONFIG_FILENAME)
        config = json.load(config_file)

        if 'email' in config:
            email = config['email']

        if 'command' in config:
            command = config['command']

        if 'password' in config:
            password = config['password']

        if 'mfa' in config:
            mfa = config['mfa']

        if 'gui' in config:
            gui = config['gui']

        if 'debug' in config:
            debug = config['debug']

except IOError:

    parser = argparse.ArgumentParser(
        description='Keeper Commander version ' + version)
    parser.add_argument("email", help="Email address of the Keeper profile")
    parser.add_argument("command", help="Command to run")
    parser.add_argument("--debug", help="Turn on debug mode",
                        action="store_true")
    parser.add_argument("--gui", help="GUI mode",
                        action="store_true")
    args = parser.parse_args()
    email = args.email
    password = args.password
    command = args.command
    mfa = args.mfa
    debug = args.debug
    gui = args.gui

if debug:
    print ("Debug turned on")

if gui:
    print ("GUI mode turned on")

if email:
    print ('Email: ' + email)

if command:
    print ('Command: ' + command)

if password:
    print ('Password: *******')






