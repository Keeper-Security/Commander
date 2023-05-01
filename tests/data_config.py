import os
import json

from keepercommander.params import KeeperParams


def read_config_file(params, file_name='config.json'):       # type: (KeeperParams, str) -> None
    params.config_filename = os.path.join(os.path.dirname(__file__), file_name)
    with open(params.config_filename, 'r') as f:
        params.config = json.load(f)
        params.server = params.config['server']
        params.user = params.config['user']
        params.device_private_key = params.config['private_key']
        params.device_token = params.config['device_token']
        params.clone_code = params.config['clone_code']
        params.password = params.config.get('password', None)

