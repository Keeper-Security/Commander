import logging
from datetime import timedelta
from re import findall

from ...constants import (
    TIMEOUT_DEFAULT, TIMEOUT_MIN, TIMEOUT_DEFAULT_UNIT, TIMEOUT_ALLOWED_UNITS
)


def parse_timeout(timeout_input):
    """Parse timeout input to return instance of timedelta

    timeout_input(str): String to parse for one or more integer values followed by time unit names. The allowed time
        units are found in the list constants.TIMEOUT_ALLOWED_UNITS. Any substring from the beginning of the allowed
        unit may be provided. If no time unit names are included, then the default time unit from
        constants.TIMEOUT_DEFAULT_UNIT is used. An error is raised if a unit name in timeout_input is unrecognized.
    Returns instance of timedelta from the unit values and names.
    """
    if timeout_input.strip().isnumeric():
        tdelta_kwargs = {TIMEOUT_DEFAULT_UNIT: int(timeout_input)}
    else:
        all_units = TIMEOUT_ALLOWED_UNITS
        tdelta_kwargs = {}
        for v, input_unit in findall(r'(\d+)\s*([a-zA-Z]+)\s*', timeout_input):
            key_match = [t for t in all_units if t.startswith(input_unit)]
            if len(key_match) == 0:
                raise ValueError(
                    f'{input_unit} is not allowed as a unit for the timeout value. '
                    f'Valid units for the timeout value are {TIMEOUT_ALLOWED_UNITS}.'
                )
            tdelta_kwargs[key_match[0]] = int(v)
    return timedelta(**tdelta_kwargs)


def format_timeout(timeout_delta):
    """Format timeout as instance of timedelta for output to console

    timeout_delta(timedelta): Timeout setting as instance of timedelta.
    Returns string with value and names of time units separated by commas. If all unit values are zero,
        then the string '0' is returned.
    """
    if timeout_delta == timedelta(0):
        return '0'
    else:
        time_units = {'days': timeout_delta.days}
        hours_minutes = str(timeout_delta).split(', ')[-1]
        time_units['hours'], time_units['minutes'], _ = hours_minutes.split(':')
        for k, v in time_units.items():
            time_units[k] = int(v)
        nonzero_units = [f'{v} {k[:-1] if v == 1 else k}' for k, v in time_units.items() if v != 0]
        return ', '.join(nonzero_units)


def enforce_timeout_range(timeout_delta):
    """Enforce the range of allowed timeout values based on constants TIMEOUT_MIN
    Warnings are raised if the timeout is outside of the range.

    timeout_delta(timedelta): Timeout setting as instance of timedelta.
    """
    if timeout_delta < TIMEOUT_MIN:
        logging.warning(
            f'The minimum device timeout value is {format_timeout(TIMEOUT_MIN)}. '
            'The device timeout has been set to the default Keeper timeout value.'
        )
        return TIMEOUT_DEFAULT
    else:
        return timeout_delta


def get_timeout_setting_from_delta(timeout_delta):
    """Get timeout setting in minutes to be used in an API call to the Keeper backend

    timeout_delta(timedelta): Timeout setting as instance of timedelta.
    Returns string representation of the integer value of timeout minutes.
    """
    timeout_seconds = int(timeout_delta.total_seconds() // 60)
    return str(timeout_seconds)


def get_delta_from_timeout_setting(timeout_setting):
    """Get the timeout as an instance of timedelta from the setting returned from the API call

    timeout_setting(str): Timeout setting as a string representation of the integer value of timeout milliseconds.
    Returns timedelta instance.
    """
    return timedelta(milliseconds=int(timeout_setting))
