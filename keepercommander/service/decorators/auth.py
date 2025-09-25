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
from ...service.util.verified_command import Verifycommand

def auth_check(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get('api-key')
        if not api_key:
            return {
                'status': 'error',
                'error': 'Please provide a valid api key'
            }, 401

        stored_key = ConfigReader.read_config('api-key', api_key)
        if not stored_key or api_key.strip() != stored_key.strip():
            return {
                'status': 'error',
                'error': 'Please provide a valid api key'
            }, 401

        expiration_timestamp = ConfigReader.read_config('expiration_timestamp', api_key)
        if not expiration_timestamp:
            return {
                'status': 'error',
                'error': 'Invalid or expired API key'
            }, 401
        
        if datetime.now() > datetime.fromisoformat(expiration_timestamp):
            return {
                'status': 'error',
                'error': 'API key has expired'
            }, 401

        kwargs['api-key'] = True
        return fn(*args, **kwargs)
    return wrapper

@debug_decorator
def policy_check(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        # Skip policy check for GET requests entirely
        if request.method == 'GET':
            return fn(*args, **kwargs)

        request_data = request.get_json(silent=True)
        if not request_data:
            return fn(*args, **kwargs)
            
        api_key = request.headers.get('api-key')
        policy = ConfigReader.read_config('command_list', api_key)
        command_content = request_data.get("command")
        
        if command_content is None:
            return {
                'status': 'error',
                'error': 'Missing required field "command"'
            }, 400
            
        if not isinstance(command_content, str):
            return {
                'status': 'error',
                'error': 'Command must be a string'
            }, 400
            
        if len(command_content) > 4096:
            return {
                'status': 'error',
                'error': 'Command length exceeded'
            }, 400
        command = command_content.split(" ")
        if not policy or not policy.strip():
            return {
                'status': 'error',
                'error': 'Not permitted to perform this function'
            }, 403
        allowed_commands = split_to_list(policy, ',')

        logger.debug(f"Allowed Commands : {allowed_commands}")
        logger.debug(f"Command : {command[0]}")

        if not any(command[0] == cmd.strip() for cmd in allowed_commands):
            return {
                'status': 'error',
                'error': 'Not permitted to perform this function'
            }, 403
        
        # Validate append-notes command
        append_error = Verifycommand.validate_append_command(command)
        if append_error:
            logger.debug(f"Command validation failed: {command[0]} - {append_error}")
            return {
                'status': 'error',
                'error': append_error
            }, 400
        
        # Validate mkdir command
        mkdir_error = Verifycommand.validate_mkdir_command(command)
        if mkdir_error:
            logger.debug(f"Command validation failed: {command[0]} - {mkdir_error}")
            return {
                'status': 'error',
                'error': mkdir_error
            }, 400
        
        # Validate transform-folder command
        transform_folder_error = Verifycommand.validate_transform_folder_command(command)
        if transform_folder_error:
            logger.debug(f"Command validation failed: {command[0]} - {transform_folder_error}")
            return {
                'status': 'error',
                'error': transform_folder_error
            }, 400
            
        return fn(*args, **kwargs)
    return wrapper