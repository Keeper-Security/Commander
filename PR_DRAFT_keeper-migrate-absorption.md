# Draft PR: Add `keeper migrate <verb>` commands

## Summary

Adds 8 tenant-migration commands to Commander via a new `keepercommander/commands/migrate.py`
module. Delegates to the DSK shim library for the actual migration logic. Optional
install via `pip install keepercommander[migrate]`.

The top-level `migrate` command is categorized under "Import and Exporting Data"
because the surface is closest to Commander import/export migration workflows and
does not require a new help category for this draft.

## Verbs added

- `keeper migrate adopt <run_dir>` - Adopt a keeperCMD run-dir into a DSK manifest
- `keeper migrate plan <target_state>` - Build a migration plan
- `keeper migrate apply <manifest>` - Apply a migration manifest or prebuilt plan
- `keeper migrate diff <manifest>` - Diff a manifest against live state
- `keeper migrate audit-explain <audit_log>` - Explain a migration audit log
- `keeper migrate drift-watch <manifest> [manifest ...]` - Watch for drift
- `keeper migrate rehearse-report <run_dir>` - Rehearsal report
- `keeper migrate bundle <manifest>` - Bundle compliance evidence

## Files added (3)

- `keepercommander/commands/migrate.py` - 389 LoC
- `unit-tests/test_command_migrate.py` - 206 LoC
- `PR_DRAFT_keeper-migrate-absorption.md` - 64 LoC (PR notes for Bob/joao review)

## Files modified (3)

- `keepercommander/commands/base.py` - +4 LoC (registration hook)
- `keepercommander/command_categories.py` - one-line category entry
- `setup.cfg` - +4 net LoC (`extras_require[migrate]`)

## Test results

- `python3 -m pytest unit-tests/test_command_migrate.py -v` - 12 passed
- `python3 -m pytest unit-tests/ -q` - 813 passed, 32 skipped, 2 warnings, 72 subtests passed
- `python3 -c "from keepercommander.commands import migrate; print(migrate.MigrateGroupCommand())"` - passed

## Install smoke

- `python3 -m pip install -e '.[migrate]'` - failed only because `keeper-tenant-migrate>=1.7.5,<2` has no matching published distribution

## Dependencies

- `declarative-sdk-for-k>=2.21,<3` (DSK library, optional via `[migrate]` extra)
- `keeper-tenant-migrate>=1.7.5,<2` (joao's plugin, optional via `[migrate]` extra)

## Known caveats

- `keeper-tenant-migrate` not yet on PyPI; install path needs joao's publication
- Verb names use kebab-case (`audit-explain`, `drift-watch`) per Commander convention
- Parser shapes mirror `dsk.shim` at `dsk@3999428`; `diff` currently accepts one manifest path and `bundle` accepts a compliance bundle manifest
- DSK shim deprecated aliases (`import_from_keepercmd`, `audit`) still work but emit `DeprecationWarning`; not exposed via Commander surface
- `migrate` is a normal `GroupCommand`, visible pre-enterprise-login. Per joao pending decision (see agent-collab inbox), may need re-gating to `enterprise_commands`.

## Open questions for Keeper engineering

1. PR target: `release` or `master`?
2. Should `migrate` be enterprise-gated?
3. Acceptable upper bound `<3` on DSK dep?
4. Acceptable to add `keeper-tenant-migrate` as optional dep when not yet on PyPI?
