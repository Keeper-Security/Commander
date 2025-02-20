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

class CommandExecutionError(Exception):
    """Raised when command execution fails"""
    pass

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

class ConfigError(Exception):
    pass