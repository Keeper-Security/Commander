import re

""" Filter rows by pattern(s). All non-primitive data type values contained are assumed to be of type List """
def filter_rows(rows, patterns, use_regex=False):
    if not patterns:
        return rows

    pattern = re.compile('|'.join(patterns))
    is_a = lambda o, t: isinstance(o, t)
    to_string = lambda el: el if is_a(el, str) else is_a(el, list) and ''.join([to_string(c) for c in el]) or str(el) or ''
    match_regex = lambda r: bool(pattern.search(r))

    def match_simple(r):
        r = r.casefold()
        for p in patterns:
            if p.casefold() in r:
                return True
        return False

    is_match = lambda r: use_regex and match_regex(r) or match_simple(r)

    return list(
        filter(
            lambda r: is_match(to_string(r)),
            rows
        )
    )
