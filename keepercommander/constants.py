from datetime import timedelta


TIMEOUT_DEFAULT = timedelta()  # Default is timedelta of zero
TIMEOUT_MIN = timedelta(minutes=1)
TIMEOUT_MAX = timedelta(days=30)
TIMEOUT_DEFAULT_UNIT = 'minutes'
TIMEOUT_ALLOWED_UNITS = ('days', 'hours', 'minutes')
