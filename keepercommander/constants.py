from datetime import timedelta


# Set to default value by using timedelta of 0
TIMEOUT_DEFAULT = timedelta(0)
TIMEOUT_MIN = timedelta(minutes=1)
TIMEOUT_MAX = timedelta(days=30)
TIMEOUT_DEFAULT_UNIT = 'minutes'
TIMEOUT_ALLOWED_UNITS = ('days', 'hours', 'minutes')
