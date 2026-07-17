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

"""Service-mode mapping for local rate limits and upstream Keeper/edge throttling."""

from typing import Any, Optional, Tuple, Union

from ...error import KeeperApiError

RESULT_THROTTLED = 'throttled'
RESULT_RATE_LIMITED = 'rate_limited'
RESULT_EDGE_429 = '429'

_THROTTLE_TEXT_MARKERS = ('throttled', 'too many requests')


def is_throttle_text(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in _THROTTLE_TEXT_MARKERS)


def is_throttle_error(exc_or_text: Union[BaseException, str]) -> bool:
    if isinstance(exc_or_text, KeeperApiError):
        code = exc_or_text.result_code
        if code == RESULT_THROTTLED or code == 429 or str(code) == RESULT_EDGE_429:
            return True
        return is_throttle_text(exc_or_text.message or str(exc_or_text))
    return is_throttle_text(str(exc_or_text or ''))


def normalize_throttle_result_code(result_code: Any = None) -> str:
    if result_code in (None, ''):
        return RESULT_THROTTLED
    if result_code == 429 or str(result_code) == RESULT_EDGE_429:
        return RESULT_EDGE_429
    return str(result_code)


def clean_throttle_message(message: Optional[str]) -> str:
    """Prefer Keeper's API message; drop duplicated client retry log noise."""
    if not message:
        return 'Request throttled'

    text = message.replace('\\n', '\n')
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        lowered = line.lower()
        # Skip Commander client retry warnings captured from logging
        if 'retrying in' in lowered or ('throttled (' in lowered and 'attempt' in lowered):
            continue
        if 'too many requests' in lowered:
            return 'Too Many Requests'
        if 'throttled' in lowered or 'due to repeated attempts' in lowered:
            if lowered.startswith('throttled:'):
                return line.split(':', 1)[1].strip() or line
            return line

    if 'retrying in' in text.lower():
        return 'Request throttled by Keeper API'

    first_line = text.strip().splitlines()[0]
    return first_line[:500]


def throttle_error_response(
        message: Optional[str] = None,
        result_code: Any = RESULT_THROTTLED,
) -> Tuple[dict, int]:
    return {
        'status': 'error',
        'error': clean_throttle_message(message),
        'result_code': normalize_throttle_result_code(result_code),
    }, 429


def rate_limited_response(detail: Optional[str] = None) -> Tuple[dict, int]:
    error = 'Service rate limit exceeded'
    if detail:
        error = f'{error}: {detail}'
    return {
        'status': 'error',
        'error': error,
        'result_code': RESULT_RATE_LIMITED,
    }, 429
