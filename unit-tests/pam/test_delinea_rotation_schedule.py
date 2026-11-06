"""Delinea rotation schedules: Secret Server AutoChangeSchedule -> Quartz cron -> Keeper schedule JSON."""

import unittest

from keepercommander.commands.pam_import.base import quartz_cron_to_keeper_schedule
from keepercommander.importer.thycotic.pam.rotation_mapper import RotationMapper


def _schedule(schedule_type, time, interval=1, **extra):
    return {'type': schedule_type, 'utcTime': time, 'intervalCount': interval, 'tz': 'Etc/UTC', **extra}


class TestQuartzCronToKeeperSchedule(unittest.TestCase):
    def test_mapped_shapes(self):
        cases = [
            ('0 30 2 * * ?', _schedule('DAILY', '02:30')),
            ('0 30 2 * * *', _schedule('DAILY', '02:30')),
            ('0 5 14 */3 * ?', _schedule('DAILY', '14:05', 3)),
            ('0 0 9 ? * MON', _schedule('WEEKLY', '09:00', weekday='MONDAY')),
            ('0 0 9 * * SAT', _schedule('WEEKLY', '09:00', weekday='SATURDAY')),
            ('0 45 23 15 * ?', _schedule('MONTHLY_BY_DAY', '23:45', monthDay=15)),
            ('0 0 0 31 */6 ?', _schedule('MONTHLY_BY_DAY', '00:00', 6, monthDay=31)),
            ('  0  30   2 * * ?  ', _schedule('DAILY', '02:30')),
        ]
        for cron, expected in cases:
            with self.subTest(cron=cron):
                self.assertEqual(quartz_cron_to_keeper_schedule(cron), expected)

    def test_every_weekday_name(self):
        for dow, name in (('SUN', 'SUNDAY'), ('MON', 'MONDAY'), ('TUE', 'TUESDAY'), ('WED', 'WEDNESDAY'),
                          ('THU', 'THURSDAY'), ('FRI', 'FRIDAY'), ('SAT', 'SATURDAY')):
            with self.subTest(dow=dow):
                self.assertEqual(quartz_cron_to_keeper_schedule(f'0 0 9 ? * {dow}')['weekday'], name)

    def test_unmapped_shapes_fall_back_to_raw_cron(self):
        for cron in (
            None, 12345, '', '0 0 * * *', '0 0 0 * * ? 2025',       # not six fields
            '0 */5 * * * ?', '0 0 */2 * * ?', '0 0,30 2 * * ?',     # non-numeric clock
            '0 0 1 */0 * ?', '0 0 1 */x * ?',                       # bad day step
            '0 0 9 ? * MON,WED', '0 0 9 ? * mon',                   # several / lowercase weekdays
            '0 0 9 ? * MON#2', '0 0 9 ? */2 FRIL',                  # nth / last weekday
            '0 0 0 0 * ?', '0 0 0 32 * ?', '0 0 0 1 */0 ?',         # bad month day / step
            '0 0 0 1 3 ?', '0 0 0 * 3 ?',                           # fixed month
        ):
            with self.subTest(cron=cron):
                self.assertIsNone(quartz_cron_to_keeper_schedule(cron))

    def test_every_single_day_rotation_mapper_cron_maps(self):
        for schedule in (
            {'scheduleType': 'Daily', 'startingOn': '2024-01-01T02:30:00'},
            {'scheduleType': 'Days', 'days': 4},
            {'scheduleType': 'Weekly', 'friday': True},
            {'scheduleType': 'Monthly', 'changeEveryMonthsDayNumber': 10, 'changeEveryMonths': 2},
        ):
            with self.subTest(schedule=schedule):
                self.assertIsNotNone(quartz_cron_to_keeper_schedule(RotationMapper.schedule_to_cron(schedule)))

    def test_out_of_range_clock_is_rejected(self):
        self.assertIsNone(quartz_cron_to_keeper_schedule('0 0 24 * * ?'))
        self.assertIsNone(quartz_cron_to_keeper_schedule('0 60 2 * * ?'))
        self.assertIsNone(quartz_cron_to_keeper_schedule('0 0 25 * * ?'))
        self.assertIsNone(quartz_cron_to_keeper_schedule('0 99 2 * * ?'))


class TestScheduleToCron(unittest.TestCase):
    def assertCron(self, cases):
        for schedule, expected in cases:
            with self.subTest(schedule=schedule):
                self.assertEqual(RotationMapper.schedule_to_cron(schedule), expected)

    def test_invalid_input(self):
        self.assertCron([(value, None) for value in (None, [], 'Daily', 7, {}, {'scheduleType': 'Hourly'})])

    def test_days(self):
        self.assertCron([
            ({'scheduleType': 'Daily'}, '0 0 0 * * ?'),
            ({'scheduleType': '  DAILY '}, '0 0 0 * * ?'),
            ({'changeType': 'Days', 'days': 2}, '0 0 0 */2 * ?'),
            ({'scheduleType': 'Days', 'days': '7'}, '0 0 0 */7 * ?'),
            ({'scheduleType': 'Days', 'days': ''}, '0 0 0 * * ?'),
            ({'scheduleType': 'Days', 'days': 0}, None),
            ({'scheduleType': 'Days', 'days': -3}, None),
            ({'scheduleType': 'Days', 'days': 'abc'}, None),
        ])

    def test_schedule_type_wins_over_change_type(self):
        self.assertCron([({'scheduleType': 'Weekly', 'changeType': 'Days', 'monday': True}, '0 0 0 ? * MON')])

    def test_starting_on(self):
        self.assertCron([
            ({'scheduleType': 'Daily', 'startingOn': '2024-05-01T13:07:00'}, '0 7 13 * * ?'),
            ({'scheduleType': 'Daily', 'startingOn': '2024-05-01T13:07:00Z'}, '0 7 13 * * ?'),
            ({'scheduleType': 'Daily', 'startingOn': 'tomorrow'}, '0 0 0 * * ?'),
        ])

    def test_starting_on_offset_is_converted_to_utc(self):
        # The result feeds Keeper's utcTime. 02:30-05:00 is 07:30 UTC.
        self.assertCron([
            ({'scheduleType': 'Daily', 'startingOn': '2024-01-01T02:30:00-05:00'}, '0 30 7 * * ?'),
            ({'scheduleType': 'Daily', 'startingOn': '2024-01-01T23:15:00+05:30'}, '0 45 17 * * ?'),
        ])

    def test_utc_day_shift_moves_weekday_and_day_of_month(self):
        late = '2024-01-01T23:00:00-05:00'   # 04:00 UTC next day
        early = '2024-01-01T01:00:00+05:00'  # 20:00 UTC previous day
        monthly = {'scheduleType': 'Monthly', 'monthScheduleType': 'Week_Day'}
        self.assertCron([
            ({'scheduleType': 'Daily', 'startingOn': late}, '0 0 4 * * ?'),
            ({'scheduleType': 'Weekly', 'monday': True, 'saturday': True, 'startingOn': late}, '0 0 4 ? * SUN,TUE'),
            ({'scheduleType': 'Weekly', 'sunday': True, 'startingOn': early}, '0 0 20 ? * SAT'),
            ({'scheduleType': 'Monthly', 'day': 15, 'startingOn': late}, '0 0 4 16 * ?'),
            ({'scheduleType': 'Monthly', 'day': 31, 'startingOn': late}, '0 0 4 1 * ?'),
            ({'scheduleType': 'Monthly', 'day': 1, 'startingOn': early}, '0 0 20 L * ?'),
            ({**monthly, 'weekNumber': 'second', 'weekDay': 'tue', 'startingOn': late}, '0 0 4 ? * WED#2'),
            ({**monthly, 'weekNumber': 'first', 'weekDay': 'sun', 'startingOn': early}, '0 0 20 ? * SAT#1'),
        ])

    def test_weekly(self):
        self.assertCron([
            ({'scheduleType': 'Weekly', 'saturday': True, 'monday': True, 'sunday': True}, '0 0 0 ? * SUN,MON,SAT'),
            ({'scheduleType': 'Weekly', 'Tuesday': 'True', 'Wednesday': 'false', 'THURSDAY': 1}, '0 0 0 ? * TUE,THU'),
            ({'scheduleType': 'Weekly', 'weeklyDays': ['Friday', 'mon']}, '0 0 0 ? * MON,FRI'),
            ({'scheduleType': 'Weekly', 'daysOfWeek': ['WED']}, '0 0 0 ? * WED'),
            ({'scheduleType': 'Weekly', 'weeklyDays': 'Monday'}, None),
            ({'scheduleType': 'Weekly', 'monday': False}, None),
        ])

    def test_monthly_day_of_month(self):
        self.assertCron([
            ({'scheduleType': 'Monthly'}, '0 0 0 1 * ?'),
            ({'scheduleType': 'Monthly', 'monthScheduleType': 'DayOfMonth', 'changeEveryMonthsDayNumber': 15,
              'changeEveryMonths': 3, 'startingOn': '2024-01-01T04:00:00'}, '0 0 4 15 */3 ?'),
            ({'scheduleType': 'Monthly', 'dayOfMonth': 20}, '0 0 0 20 * ?'),
            ({'scheduleType': 'Monthly', 'day': 5}, '0 0 0 5 * ?'),
            ({'scheduleType': 'Monthly', 'changeEveryMonthsDayNumber': 0}, None),
            ({'scheduleType': 'Monthly', 'changeEveryMonthsDayNumber': 32}, None),
            ({'scheduleType': 'Monthly', 'changeEveryMonths': 0}, None),
            ({'scheduleType': 'Monthly', 'monthScheduleType': 'Quarterly'}, None),
        ])

    def test_monthly_nth_weekday(self):
        monthly = {'scheduleType': 'Monthly', 'monthScheduleType': 'Week_Day'}
        self.assertCron([
            ({**monthly, 'changeEveryMonthsInstance': 'Second', 'changeEveryMonthsInstanceTarget': 'Tuesday'},
             '0 0 0 ? * TUE#2'),
            ({**monthly, 'changeEveryMonths': 2, 'weekNumber': 'last', 'weekDay': 'fri'}, '0 0 0 ? */2 FRIL'),
            ({**monthly, 'monthScheduleType': 'WeekOfMonth', 'weekOfMonth': 4, 'dayOfWeek': 'SUN'},
             '0 0 0 ? * SUN#4'),
            ({**monthly, 'weekNumber': 'first'}, None),
            ({**monthly, 'weekDay': 'mon'}, None),
            ({**monthly, 'weekNumber': 'fifth', 'weekDay': 'mon'}, None),
            ({**monthly, 'weekNumber': 'first', 'weekDay': 'funday'}, None),
        ])


if __name__ == '__main__':
    unittest.main()
