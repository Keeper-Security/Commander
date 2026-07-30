#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""SailPoint Service Mode integration package."""

from .command_policy import SailPointCommandPolicy
from .constants import DOCKER_RECORD_ENV, PARAMS_ATTR, SAILPOINT_ALLOWED_COMMANDS, SAILPOINT_RECORD_ENV


def __getattr__(name):
    if name == 'SailPointService':
        from .service import SailPointService
        return SailPointService
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')


__all__ = [
    'DOCKER_RECORD_ENV',
    'SAILPOINT_RECORD_ENV',
    'PARAMS_ATTR',
    'SAILPOINT_ALLOWED_COMMANDS',
    'SailPointCommandPolicy',
    'SailPointService',
]
