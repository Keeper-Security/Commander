#!/usr/bin/env python3

# Dumps HashiCorp Vault secrets to a Keeper JSON file ready for import.

# Requirements:
# pip install hvac

# Reads env vars:
#  VAULT_ADDR  which points to desired Hashicorp Vault instance, default http://localhost:8200
#  VAULT_TOKEN vault access token, no default - if empty get token from already-authenticated session
#  VAULT_MOUNT_PATH  to specify storage engine mount point, default /secret/
#  VAULT_ROOT_PREFIX to specify path to dump for partial backups, default '/'

# To use custom encoding set:
#  PYTHONIOENCODING=utf-8

# Example usage
# set PYTHONIOENCODING=utf-8
# set VAULT_ADDR=http://127.0.0.1:8200
# set VAULT_MOUNT_PATH=/secret
# set VAULT_ROOT_PREFIX=/dev/
# vault_dump_hvac.py > export.json

import copy
import datetime
import getpass
import json
import os
import subprocess
import sys

import hvac

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def print_header():
    user = getpass.getuser()
    date = "{} UTC".format(datetime.datetime.utcnow())
    vault_address = os.environ.get('VAULT_ADDR', 'http://localhost:8200')
    vault_token = os.environ.get('VAULT_TOKEN','')
    vault_mount_path = os.environ.get('VAULT_MOUNT_PATH','/secret/')
    vault_root_prefix = os.environ.get('VAULT_ROOT_PREFIX','/')

    eprint ('# vault_dump_hvac.py')
    eprint ("# dump made by {}".format(user))
    eprint ("# backup date: {}".format(date))
    eprint ("# VAULT_ADDR env variable: {}".format(vault_address))
    eprint ("# VAULT_TOKEN env variable: {}".format('*' * len(vault_token)))
    eprint ("# VAULT_MOUNT_PATH env variable: {}".format(vault_mount_path))
    eprint ("# VAULT_ROOT_PREFIX env variable: {}".format(vault_root_prefix))
    eprint ('# STDIN encoding: {}'.format(sys.stdin.encoding))
    eprint ('# STDOUT encoding: {}'.format(sys.stdout.encoding))
    eprint ('#')
    eprint ('# WARNING: not guaranteed to be consistent!')
    eprint ()

# looks at an argument for a value and adds it to the export dict
def recurse_for_values(path_prefix, candidate_key, data_dict):
    # NB! if latest version is deleted - record is considered deleted by vault
    # although prev version(s) may still exist but not restored
    if 'keys' in candidate_key:
        candidate_values = candidate_key['keys']
    else:
        candidate_values = candidate_key['data']['keys']

    for candidate_value in candidate_values:
        next_index = path_prefix + candidate_value
        if candidate_value.endswith('/'):
            next_value = client.secrets.kv.v2.list_secrets(path=next_index)
            recurse_for_values(next_index, next_value, data_dict)
        else:
            deletion_time = ''
            final_data = {}

            try:
                final_data = client.secrets.kv.v2.read_secret(next_index) or {}
            except hvac.exceptions.InvalidPath as e:
                if e.args and isinstance(e.args, tuple) and len(e.args) > 0:
                    dict = json.loads(e.args[0])
                    deletion_time = dict.get('data', {}).get('metadata', {}).get('deletion_time', '')

            if 'data' in final_data:
                dirs = [s for s in next_index.split('/') if s != '']
                rec = copy.deepcopy(record_dict_template)
                rec['uid'] = len(data_dict['records']) + 1
                rec['title'] = dirs[-1]
                folder = '\\'.join(dirs[:-1])
                rec['folders'].append({'folder': folder})

                final_dict = final_data['data']
                final_data = final_dict.get('data') or {}
                # sorted_final_keys = sorted(final_data.keys())
                for final_key in final_data.keys():
                    field_key = field_key_template.format(final_key)
                    final_value = final_data[final_key]
                    field_value = final_value if isinstance(final_value, str) else json.dumps(final_value)
                    rec['custom_fields'][field_key] = field_value

                data_dict['records'].append(rec)
            elif 'rules' in final_data:
                rules = "\necho -ne {} | vault policy write {} -".format(repr(final_data['rules']), candidate_value)
                eprint("\n*** WARNING: skipped rules: " + rules)
            elif deletion_time:
                eprint("\n*** WARNING: index {} deleted {}".format(repr(next_index), repr(deletion_time)))
            else:
                eprint("\n*** WARNING: no data for {}".format(repr(next_index)))

env_vars = os.environ.copy()
hvac_token = os.environ.get('VAULT_TOKEN', '')
if not hvac_token:
    # Get token from already-authenticated session - needs vault binary in $PATH.
    eprint("\n*** WARNING: VAULT_TOKEN not present or empty")
    eprint("\n*** WARNING: Trying to get token from already-authenticated session - needs vault binary in $PATH.")
    hvac_token = subprocess.check_output("vault read -field id auth/token/lookup-self", shell=True, env=env_vars)

hvac_url = os.environ.get('VAULT_ADDR', 'http://localhost:8200')
client = hvac.Client(url=hvac_url, token=hvac_token)

if os.environ.get('VAULT_SKIP_VERIFY'):
    import requests
    rs = requests.Session()
    client.session = rs
    rs.verify = False
    import warnings
    warnings.filterwarnings("ignore")
assert client.is_authenticated()

vault_mount_path = os.environ.get('VAULT_MOUNT_PATH','/secret/').strip()
vault_root_prefix = os.environ.get('VAULT_ROOT_PREFIX','/').strip()
if not vault_root_prefix.startswith('/'):
        vault_root_prefix = '/' + vault_root_prefix
if not vault_root_prefix.endswith('/'):
    vault_root_prefix += '/'

field_key_template = "$text:{}:1"
record_dict_template = {
    "uid": None,
    "title": "",
    "$type": "login",
    "custom_fields": {
        # "$text:KEY1:1": "VALUE1",
        # "$text:KEY2:1": "VALUE2"
    },
    "folders": [
        # {"folder": "A\\B\\C\\D"}
    ]
}

print_header()

# must have right to list keys for VAULT_ROOT_PREFIX, otherwise get error with trace.
# NB! path must exist, ex. if vault is empty - error: InvalidPath
top_level_keys = client.secrets.kv.v2.list_secrets(mount_point=vault_mount_path, path=vault_root_prefix)
export_dict = {'records': []}
recurse_for_values(vault_root_prefix, top_level_keys, export_dict)

print(json.dumps(export_dict, indent=2))
print()
