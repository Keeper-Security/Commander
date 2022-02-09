#!/usr/bin/env python3

"""Code/Data shared between recordv3.py and recordv2.py."""

import urllib.parse


def display_totp_details(otp_url):
    """Display Time-based One Time Password details."""
    query_fields = extract_query_fields(otp_url)
    display_totp_query_fields(query_fields)


def extract_otp_url(data, is_v2):
    """Get the otpauth url from our decoded json as a string."""
    assert isinstance(data, dict)
    fields = data['fields']
    assert isinstance(fields, list)
    if is_v2:
        assert len(fields) == 1
        return fields[0]['data']
    # For v3 records
    for subdict in fields:
        if subdict['type'] == 'oneTimeCode':
            value = subdict['value']
            assert isinstance(value, list)
            assert len(value) == 1
            return value[0]
    raise AssertionError('No otpauth URL found')


def extract_query_fields(otp_url):
    """Get the query fields from an otpauth query string as a dict."""
    parsed_url = urllib.parse.urlparse(otp_url)
    query_string = parsed_url.query
    parsed_query = urllib.parse.parse_qs(query_string)
    return parsed_query


def display_totp_query_fields(query_fields):
    """Display the details of totp data."""
    for key in ('secret', 'issuer', 'period'):
        if key in query_fields:
            assert len(query_fields[key]) == 1
            print('{}: {}'.format(key, query_fields[key][0]))
        else:
            print('{} not found'.format(key))
