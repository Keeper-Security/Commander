"""CI smoke layer — kwarg-strict, end-to-end-per-subcommand suite.

The smoke layer runs alongside the unit suite on every PR. Where unit
tests use permissive fakes that accept any kwargs, the smoke stub
asserts kwargs against the EXACT argparse `dest` names of the
installed `keepercommander` release. A typo or drift in
`commander_clients.py` that the unit suite tolerates shows up here as
a hard failure — the same way the live SDK would behave on a real
tenant.

Run:
    python3 -m unittest discover keepercommander.commands.keeper_tenant_migrate.smoke

Phase-D context: see migration_scripts/ci/REHEARSAL_GUIDE.md
'CI smoke layer (Phase D)'.
"""

from keepercommander.commands.keeper_tenant_migrate.throttle import AdaptiveThrottle

# Disable the adaptive throttle in smoke runs — we don't want the
# 2s-per-call default delay polluting the < 60s CI budget. Live
# rehearsals (comprehensive_rehearsal.py) keep throttling on.
AdaptiveThrottle.configure_defaults(enabled=False)
