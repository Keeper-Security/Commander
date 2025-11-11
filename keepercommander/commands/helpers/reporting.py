import re

""" Filter rows by pattern(s). All non-primitive data type values contained are assumed to be of type List """
def filter_rows(rows, patterns, use_regex=False):
    if not patterns:
        return rows

    is_a = lambda o, t: isinstance(o, t)
    to_string = lambda el: el if is_a(el, str) else is_a(el, list) and ' '.join([to_string(c) for c in el]) or str(el) or ''
    if use_regex:
        pattern = re.compile('|'.join(patterns))
        is_match = lambda row: bool(pattern.search(row))
    else:
        is_match = lambda row: any(p for p in patterns if p.casefold() in row.casefold())
    return list(
        filter(
            lambda row: is_match(to_string(row)),
            rows
        )
    )
