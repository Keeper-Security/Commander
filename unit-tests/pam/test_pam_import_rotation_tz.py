"""rotation_settings.schedule.tz of an import / extend user is applied (it used to be parsed and dropped)."""
import json
import logging
from types import SimpleNamespace

from keepercommander.commands.discoveryrotation import parse_schedule_data
from keepercommander.commands.pam_import import batch_step2
from keepercommander.commands.pam_import.base import PamRotationSettingsObject

CRON6 = '0 30 18 * * ?'     # a rotation schedule needs all 6 fields (seconds first)


def _user(schedule):
    settings = PamRotationSettingsObject.load({'rotation': 'general', 'enabled': 'on', 'schedule': schedule})
    return SimpleNamespace(rotation_settings=settings)


def test_a_cron_without_tz_keeps_the_old_utc_path():
    args = batch_step2._rotation_common_args(_user({'type': 'cron', 'cron': CRON6}))
    assert args['schedule_cron_data'] == [CRON6]
    assert 'schedule_json_data' not in args


def test_utc_spellings_use_the_old_path_too():
    for tz in ('UTC', 'utc', 'Etc/UTC'):
        args = batch_step2._rotation_common_args(_user({'type': 'cron', 'cron': CRON6, 'tz': tz}))
        assert args['schedule_cron_data'] == [CRON6] and 'schedule_json_data' not in args


def test_another_time_zone_is_sent_with_the_schedule():
    args = batch_step2._rotation_common_args(_user({'type': 'cron', 'cron': CRON6, 'tz': 'America/Chicago'}))
    assert 'schedule_cron_data' not in args
    assert [json.loads(x) for x in args['schedule_json_data']] == [
        {'type': 'CRON', 'cron': CRON6, 'tz': 'America/Chicago'}]
    # and the rotation command turns it into the stored schedule unchanged
    assert parse_schedule_data(args) == [{'type': 'CRON', 'cron': CRON6, 'tz': 'America/Chicago'}]


def test_an_invalid_cron_with_a_time_zone_is_dropped_like_on_the_utc_path(caplog):
    with caplog.at_level(logging.ERROR):
        args = batch_step2._rotation_common_args(_user({'type': 'cron', 'cron': '30 18 * * *', 'tz': 'Europe/Berlin'}))
    assert 'schedule_json_data' not in args and 'schedule_cron_data' not in args
    assert 'Invalid CRON' in caplog.text


def test_on_demand_and_the_other_options_are_unchanged():
    settings = PamRotationSettingsObject.load({'rotation': 'general', 'enabled': 'off', 'password_complexity': '32,5,5,5,5',
                                               'schedule': {'type': 'on-demand', 'tz': 'America/Chicago'}})
    args = batch_step2._rotation_common_args(SimpleNamespace(rotation_settings=settings))
    assert args == {'disable': True, 'on_demand': True, 'pwd_complexity': '32,5,5,5,5'}
