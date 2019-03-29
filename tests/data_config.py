import os
import json
import base64

from keepercommander.params import KeeperParams

def read_config_file(params):
    # type: (KeeperParams) -> None
    params.config_filename = os.path.join(os.path.dirname(__file__), 'config.json')
    with open(params.config_filename, 'r') as f:
        params.config = json.load(f)
        params.server = params.config['server']
        params.user = params.config['user']
        params.password = params.config['password']
        device_id = base64.urlsafe_b64decode(params.config['device_id'] + '==')
        params.rest_context.device_id = device_id

