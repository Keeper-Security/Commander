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

from typing import Callable
from functools import wraps
from .logging import debug_decorator, catch_all
from .api_logging import api_log_handler
from .security import security_check
from .auth import auth_check, policy_check

def unified_api_decorator() -> Callable:
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        @api_log_handler
        @security_check
        @auth_check
        @policy_check
        @catch_all
        @debug_decorator
        def wrapped_function(*args, **kwargs):
            return f(*args, **kwargs)
        return wrapped_function
    return decorator