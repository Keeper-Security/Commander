#!/usr/bin/env python3

"""Tests for keeper interactive shell autocompletion."""

from unittest import TestCase

# This crufty import makes autocomplete import successfully.
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


class TestAutocompleteQuotingWithInDoubleQuotes(TestCase):
    """Tests for keeper interactive shell autocompletion - quoting."""

    def test_backslash_quote_k(self):
        r"""Test if '\"k' works with in_double_quotes."""
        check_roundtrip_w_in_double_quotes('\\"k')

    def test_a_slash_slash(self):
        """Test if 'a//' works."""
        check_roundtrip_w_in_double_quotes('a//')

    def test_c_space(self):
        r"""Test if 'c\ ' works."""
        check_roundtrip_w_in_double_quotes('c\\ ')

    def test_e_blackslash_apostrophe(self):
        r"""Test if 'e\'f' works."""
        check_roundtrip_w_in_double_quotes(r"e\'f")

    def test_g_backslash_backslash_double_quote(self):
        r"""Test if 'g\"' works."""
        check_roundtrip_w_in_double_quotes(r'g\"')

    def test_i_backslash(self):
        r"""Test if 'i\' works."""
        check_roundtrip_w_in_double_quotes('i\\')

    def test_k_backslash_double_quote(self):
        r"""Test if 'k\"' works."""
        check_roundtrip_w_in_double_quotes('k\\"')

    def test_r_backslash_s(self):
        r"""Test if 'r\s' works."""
        check_roundtrip_w_in_double_quotes(r'r\s')

    def test_double_quote_backslash_k(self):
        r"""Test if '"\"k' works."""
        check_roundtrip_w_in_double_quotes(r'"\"k')

    def test_double_quote_a_slash_slash(self):
        """Test if '"a//' works."""
        check_roundtrip_w_in_double_quotes('"a//')

    def test_double_quote_c_space(self):
        """Test if '"c ' works."""
        check_roundtrip_w_in_double_quotes('"c ')

    def test_double_quote_e_apostrophe(self):
        """Test if '"e'f' works."""
        check_roundtrip_w_in_double_quotes('"e\'f')

    def test_double_quote_g_backslash_double_quote(self):
        r"""Test if '"g\"' works."""
        check_roundtrip_w_in_double_quotes(r'"g\"')

    def test_double_quote_i_backslash_backslash(self):
        r"""Test if '"i\\' works."""
        check_roundtrip_w_in_double_quotes(r'"i\\')

    def test_double_quote_k_backslash_double_quote(self):
        r"""Test if '"k\"' works."""
        check_roundtrip_w_in_double_quotes(r'"k\"')

    def test_double_quote_r_backslash(self):
        r"""Test if '"r\\' works."""
        check_roundtrip_w_in_double_quotes(r'"r\\')

    def test_apostrophe(self):
        r"""Test if "'" works."""
        check_roundtrip_w_in_double_quotes(r"'")

    def test_apostrophe_apostrophe(self):
        r"""Test if "''" works."""
        check_roundtrip_w_in_double_quotes(r"''")

    def test_apostrophe_a_apostrophe(self):
        r"""Test if "'a'" works."""
        check_roundtrip_w_in_double_quotes(r"'a'")


class TestAutocompleteQuotingWithoutInDoubleQuotes(TestCase):
    """Tests for keeper interactive shell autocompletion - quoting."""

    def test_backslash_quote_k(self):
        r"""Test if '\"k' works with in_double_quotes."""
        check_roundtrip_wo_in_double_quotes('\\"k')

    def test_a_slash_slash(self):
        """Test if 'a//' works."""
        check_roundtrip_wo_in_double_quotes('a//')

    def test_c_space(self):
        r"""Test if 'c\ ' works."""
        check_roundtrip_wo_in_double_quotes('c\\ ')

    def test_e_blackslash_apostrophe(self):
        r"""Test if 'e\'f' works."""
        check_roundtrip_wo_in_double_quotes(r"e\'f")

    def test_g_backslash_backslash_double_quote(self):
        r"""Test if 'g\"' works."""
        check_roundtrip_wo_in_double_quotes(r'g\"')

    def test_i_backslash(self):
        r"""Test if 'i\' works."""
        check_roundtrip_wo_in_double_quotes('i\\')

    def test_k_backslash_double_quote(self):
        r"""Test if 'k\"' works."""
        check_roundtrip_wo_in_double_quotes('k\\"')

    def test_r_backslash_s(self):
        r"""Test if 'r\s' works."""
        check_roundtrip_wo_in_double_quotes(r'r\s')

    def test_double_quote_backslash_k(self):
        r"""Test if '"\"k' works."""
        check_roundtrip_wo_in_double_quotes(r'"\"k')

    def test_double_quote_a_slash_slash(self):
        """Test if '"a//' works."""
        check_roundtrip_wo_in_double_quotes('"a//')

    def test_double_quote_c_space(self):
        """Test if '"c ' works."""
        check_roundtrip_wo_in_double_quotes('"c ')

    def test_double_quote_e_apostrophe(self):
        """Test if '"e'f' works."""
        check_roundtrip_wo_in_double_quotes('"e\'f')

    def test_double_quote_g_backslash_double_quote(self):
        r"""Test if '"g\"' works."""
        check_roundtrip_wo_in_double_quotes(r'"g\"')

    def test_double_quote_i_backslash_backslash(self):
        r"""Test if '"i\\' works."""
        check_roundtrip_wo_in_double_quotes(r'"i\\')

    def test_double_quote_k_backslash_double_quote(self):
        r"""Test if '"k\"' works."""
        check_roundtrip_wo_in_double_quotes(r'"k\"')

    def test_double_quote_r_backslash(self):
        r"""Test if '"r\\' works."""
        check_roundtrip_wo_in_double_quotes(r'"r\\')

    def test_apostrophe(self):
        r"""Test if "\"'" works."""
        check_roundtrip_wo_in_double_quotes(r"\"'")

    def test_apostrophe_apostrophe(self):
        r"""Test if "\"''" works."""
        check_roundtrip_wo_in_double_quotes(r"\"''")

    def test_apostrophe_a_apostrophe(self):
        r"""Test if "\"'a'" works."""
        check_roundtrip_wo_in_double_quotes(r"\"'a'")


if __name__ == '__main__':
    instance = TestAutocompleteQuotingWithInDoubleQuotes()
    if hasattr(instance, 'setUp'):
        instance.setUp()
    instance.test_backslash_quote_k()
    if hasattr(instance, 'tearDown'):
        instance.tearDown()
