#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import json
import os
import sys
from flask import Flask, jsonify, request
from html import escape
from keepercommander import api
from keepercommander.__main__ import get_params_from_config
from keepercommander.service.app import create_app
from keepercommander.service.config.service_config import ServiceConfig
from keepercommander.service.core.process_info import ProcessInfo
from keepercommander.service.decorators.unified import unified_api_decorator
from keepercommander.service.util.command_util import CommandExecutor

flask_app = create_app()


if __name__ == '__main__':
    service_config = ServiceConfig()
    config_data = service_config.load_config()
    
    if not (port := config_data.get("port")):
        print("Error: Service configuration is incomplete. Please configure the service port in service_config")
    flask_app.run(port=port, host="0.0.0.0")
