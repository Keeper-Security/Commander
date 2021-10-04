#!/usr/bin/env python3

"""Tests for keeper interactive shell autocompletion."""

import pytest

# This crufty import makes keepercommander.autocomplete import successfully.
import keepercommander.cli

import keepercommander.autocomplete as autocomplete

# And this silences the IDE/Editor warning from importing something we don't intend to use.
_ = keepercommander.cli


def check_roundtrip_w_in_double_quotes(string):
    """Test string for escape -> unescape, both with double quotes."""
    escaped = autocomplete.escape_string(True, string)
    unescaped = autocomplete.unescape_string(True, escaped)
    assert string == unescaped


def check_roundtrip_wo_in_double_quotes(string):
    """Test string for escape -> unescape, both without double quotes."""
    escaped = autocomplete.escape_string(False, string)
    unescaped = autocomplete.unescape_string(False, escaped)
    assert string == unescaped


strings_to_test = (
    '\\"k',
    'a//',
    'c ',
    'c\\ ',
    r"e\'f",
    r'g\"',
    'i\\',
    'k\\"',
    r'r\s',
    r'"\"k',
    '"a//',
    '"c ',
    '"c\\ ',
    '"e\'f',
    r'"g\"',
    r'"i\\',
    r'"k\"',
    r'"r\\',
    r"'",
    r"''",
    r"'a'",
)


@pytest.mark.parametrize('string_to_test', strings_to_test)
def test_w_double_quotes(string_to_test):
    r"""Test if a string round trips with in_double_quotes."""
    check_roundtrip_w_in_double_quotes(string_to_test)


@pytest.mark.parametrize('string_to_test', strings_to_test)
def test_wo_double_quotes(string_to_test):
    r"""Test if a string round trips without in_double_quotes."""
    check_roundtrip_wo_in_double_quotes(string_to_test)
