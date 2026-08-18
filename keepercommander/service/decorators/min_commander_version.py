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

"""Enforce Min-Commander-Version header against the running Commander."""

import os
from functools import wraps
from typing import Optional, Tuple

from flask import request
from packaging.version import InvalidVersion, Version

from ... import __version__ as commander_version
from .logging import logger

# Hyphenated only: Werkzeug/WSGI silently drops headers that contain underscores.
MIN_COMMANDER_VERSION_HEADER = 'Min-Commander-Version'
# Set on terraform-app-setup compose; not a secret — instance identity only.
TERRAFORM_DOCKER_ENV = 'KEEPER_TERRAFORM'


def _parse_version(version_str: str) -> Optional[Version]:
    if not version_str or len(version_str) > 64:
        return None
    try:
        return Version(version_str.lstrip('vV'))
    except InvalidVersion:
        return None


_RUNNING_VERSION_RAW = str(commander_version).strip()
_RUNNING_VERSION = _parse_version(_RUNNING_VERSION_RAW)


def _is_terraform_docker() -> bool:
    """True when this process was started from terraform-app-setup compose."""
    return bool((os.environ.get(TERRAFORM_DOCKER_ENV) or '').strip())


def _read_min_commander_version_header() -> Optional[str]:
    if not _is_terraform_docker():
        return None
    value = request.headers.get(MIN_COMMANDER_VERSION_HEADER)
    if value is None:
        return None
    value = value.strip()
    return value or None


def check_min_commander_version() -> Optional[Tuple[dict, int]]:
    """
    On Terraform Docker only: if Min-Commander-Version is present, require
    running Commander >= that version.

    Non-Terraform service mode: no-op even if the header is sent.
    Missing header: no-op.
    Invalid header: 400.
    Too old: 426 with upgrade guidance.
    """
    required_raw = _read_min_commander_version_header()
    if required_raw is None:
        return None

    required = _parse_version(required_raw)
    if required is None:
        return {
            'status': 'error',
            'error': (
                f'Invalid {MIN_COMMANDER_VERSION_HEADER} header. '
                'Expected a dotted version such as 18.1.0.'
            ),
        }, 400

    if _RUNNING_VERSION is None:
        logger.error('Unable to parse running Commander version')
        return {
            'status': 'error',
            'error': 'Unable to determine running Commander version.',
        }, 500

    if _RUNNING_VERSION >= required:
        return None

    message = (
        f'Commander version {_RUNNING_VERSION_RAW} is below the required minimum {required_raw}. '
        f'Please update Keeper Commander to >= {required_raw} and retry.'
    )
    logger.info(message)
    return {'status': 'error', 'error': message}, 426


def min_commander_version_check(fn):
    """Run after auth: enforce Min-Commander-Version on Terraform Docker only."""

    @wraps(fn)
    def wrapper(*args, **kwargs):
        version_error = check_min_commander_version()
        if version_error:
            return version_error
        return fn(*args, **kwargs)

    return wrapper
