from datetime import timedelta
from re import findall

from keepercommander.constants import TIMEOUT_DEFAULT_UNIT, TIMEOUT_ALLOWED_UNITS


def parse_timeout(timeout_input):
    if timeout_input.strip().isnumeric():
        tdelta_kwargs = {TIMEOUT_DEFAULT_UNIT: int(timeout_input)}
    else:
        all_units = TIMEOUT_ALLOWED_UNITS
        tdelta_kwargs = {}
        for v, input_unit in findall(r'(\d+)\s*([a-zA-Z]+)\s*', timeout_input):
            key_match = [t for t in all_units if t.startswith(input_unit)]
            if len(key_match) == 0:
                raise ValueError(f'{input_unit} is not allowed as a unit for the timeout value.')
            tdelta_kwargs[key_match[0]] = int(v)
    return timedelta(**tdelta_kwargs)


def format_timeout(timeout_delta):
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


def get_timeout_setting_from_delta(timeout_delta):
    timeout_seconds = int(timeout_delta.total_seconds() // 60)
    return str(timeout_seconds)
