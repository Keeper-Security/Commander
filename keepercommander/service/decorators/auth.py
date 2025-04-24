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

from functools import wraps
from flask import request
from datetime import datetime
from ..util.str_util import split_to_list
from ..util.config_reader import ConfigReader
from ..decorators.logging import debug_decorator, logger

def auth_check(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get('api-key')
        if not api_key:
            return {
                'status': 'fail',
                'message': 'Please provide a valid api key.'
            }, 401

        stored_key = ConfigReader.read_config('api-key', api_key)
        if not stored_key or api_key.strip() != stored_key.strip():
            return {
                'status': 'fail',
                'message': 'Please provide a valid api key.'
            }, 401

        expiration_timestamp = ConfigReader.read_config('expiration_timestamp', api_key)
        if not expiration_timestamp:
            return {
                'status': 'fail',
                'message': 'Invalid or expired API key.'
            }, 401
        
        if datetime.now() > datetime.fromisoformat(expiration_timestamp):
            return {
                'status': 'fail',
                'message': 'API key has expired.'
            }, 401

        kwargs['api-key'] = True
        return fn(*args, **kwargs)
    return wrapper

@debug_decorator
def policy_check(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get('api-key')
        policy = ConfigReader.read_config('command_list', api_key)
        command_content = request.json.get("command")
        if len(command_content) > 4096:
            return {
                'status': 'fail',
                'message': 'Command length exceeded'
            }, 400
        command = command_content.split(" ")
        if not policy or not policy.strip():
            return {
                'status': 'fail',
                'message': 'Not permitted to perform this function'
            }, 403
        allowed_commands = split_to_list(policy, ',')

        logger.debug(f"Allowed Commands : {allowed_commands}")
        logger.debug(f"Command : {command[0]}")

        if not any(command[0] == cmd.strip() for cmd in allowed_commands):
            return {
                'status': 'fail',
                'message': 'Not permitted to perform this function'
            }, 403
            
        return fn(*args, **kwargs)
    return wrapper