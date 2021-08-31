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
    tdelta_str = str(timeout_delta)
    day_delimiter = ' days, '
    tunit = {}
    if day_delimiter in tdelta_str:
        tunit['days'], hours_minutes = tdelta_str.split(' days, ')
    else:
        tunit['days'] = 0
        hours_minutes = tdelta_str
    tunit['hours'], tunit['minutes'], _ = hours_minutes.split(':')
    for k, v in tunit.items():
        tunit[k] = int(v)
    nonzero_tunits = [f'{v} {k[:-1] if v == 1 else k}' for k, v in tunit.items() if v != 0]
    if len(nonzero_tunits) == 0:
        return '0'
    else:
        return ', '.join(nonzero_tunits)
