from datetime import timedelta
from unittest import TestCase

import pytest

from keepercommander.commands.helpers.timeout import (
    enforce_timeout_range, format_timeout, get_delta_from_timeout_setting, get_timeout_setting_from_delta, parse_timeout
)
from keepercommander.constants import TIMEOUT_DEFAULT


@pytest.mark.parametrize(
    'time_input,expected',
    [
        ('3', timedelta(minutes=3)),
        ('1d2h3mi', timedelta(days=1, hours=2, minutes=3)),
        ('4 minutes 5 hours 6 days', timedelta(days=6, hours=5, minutes=4))
    ]
)
def test_parse_timeout(time_input, expected):
    assert parse_timeout(time_input) == expected


@pytest.mark.parametrize(
    'timeout_delta,expected',
    [
        (timedelta(), '0'),
        (timedelta(minutes=3), '3 minutes'),
        (timedelta(days=1, hours=2, minutes=3), '1 day, 2 hours, 3 minutes'),
        (timedelta(days=6, hours=5, minutes=4), '6 days, 5 hours, 4 minutes')
    ]
)
def test_format_timeout(timeout_delta, expected):
    assert format_timeout(timeout_delta) == expected


class TestParseTimeout(TestCase):
    def test_parse_timeout_invalid(self):
        time_input = '3 invalidunits'
        with self.assertRaises(ValueError):
            parse_timeout(time_input)


class TestEnforceTimeoutRange(TestCase):
    def test_less_than_min(self):
        timeout_delta = timedelta(0)
        expect_delta = TIMEOUT_DEFAULT
        new_timeout_delta = enforce_timeout_range(timeout_delta)
        self.assertEqual(expect_delta, new_timeout_delta)


class TestTimeoutSetting(TestCase):
    def test_get_timeout_setting_from_delta(self):
        timeout_delta = timedelta(minutes=20000)
        expect_setting = '20000'

        self.assertEqual(expect_setting, get_timeout_setting_from_delta(timeout_delta))

    def test_get_delta_from_timeout_setting(self):
        # 10000 (minutes) * 60000 (milliseconds per minute)
        timeout_setting = '600000000'
        expect_delta = timedelta(minutes=10000)

        self.assertEqual(expect_delta, get_delta_from_timeout_setting(timeout_setting))
