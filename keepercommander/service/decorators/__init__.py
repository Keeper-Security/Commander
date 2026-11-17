#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""Service decorator exports.

Keep these imports lazy so importing a leaf module such as
``service.decorators.logging`` does not eagerly import security middleware and
its configuration validator dependencies.
"""

from importlib import import_module

__all__ = [
    'auth_check',
    'policy_check',
    'security_check',
    'debug_decorator',
    'limiter'
]

_EXPORTS = {
    'auth_check': ('.auth', 'auth_check'),
    'policy_check': ('.auth', 'policy_check'),
    'security_check': ('.security', 'security_check'),
    'limiter': ('.security', 'limiter'),
    'debug_decorator': ('.logging', 'debug_decorator'),
}


def __getattr__(name):
    try:
        module_name, attribute_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc

    module = import_module(module_name, __name__)
    value = getattr(module, attribute_name)
    globals()[name] = value
    return value
