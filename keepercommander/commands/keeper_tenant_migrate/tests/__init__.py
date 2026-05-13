"""Plugin test package init.

Disables the adaptive throttle by default for unit tests so calls
through `commander_clients._call` don't spend real seconds in the
default 2s base-delay sleep. Tests that specifically exercise throttle
behavior enable/configure it themselves (see test_throttle.py).
"""

from keepercommander.commands.keeper_tenant_migrate.throttle import AdaptiveThrottle

AdaptiveThrottle.configure_defaults(enabled=False)
