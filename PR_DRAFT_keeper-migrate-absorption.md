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

- `python3 -m pytest unit-tests/test_command_migrate.py -v` - 17 passed
- `python3 -m pytest unit-tests/ -q` - 813 passed, 32 skipped, 2 warnings, 72 subtests passed
- `python3 -c "from keepercommander.commands import migrate; print(migrate.MigrateGroupCommand())"` - passed

## Dependencies

- `declarative-sdk-for-k>=2.21,<3` (DSK library, optional via `[migrate]` extra)
- `keeper-tenant-migrate>=1.7.5,<2` (joao's plugin, optional via `[migrate]` extra)

### Note on `keeper-tenant-migrate` dependency

The `[migrate]` extras_require pulls both `declarative-sdk-for-k>=2.21,<3`
and `keeper-tenant-migrate>=1.7.5,<2`. The Commander `migrate.py` wrapper
itself ONLY imports `dsk.shim`; it does NOT directly import
`keeper_tenant_migrate`. The `keeper-tenant-migrate` dep is here because
`dsk.shim.adopt` transitively requires it for parsing keeperCMD run-dirs.

This means:
- A user running `pip install keepercommander[migrate]` gets DSK and
  keeper-tenant-migrate installed
- The Commander `migrate.py` source has no `import keeper_tenant_migrate`
- Future verbs that wrap `keeper_tenant_migrate.declare.*` directly would add
  the import then; not Phase 1

### Dependencies status

- `declarative-sdk-for-k>=2.21,<3` - published to PyPI as
  `declarative-sdk-for-k` (PEP 503 hyphenated form; Python import remains
  `import dsk`). Version 2.21.0 current as of 2026-05-10.
- `keeper-tenant-migrate>=1.7.5,<2` - release prep landed in
  `keeperCMD@ed68cf7` (CHANGELOG, pyproject, PUBLISHING.md); operator runs
  `twine upload` next. Will resolve from PyPI within hours of this PR opening.

## Changes

| Change | Date | Files |
|---|---|---|
| Apply Bob's Lurey-style review (L1 + L6 + L3 + L5) | 2026-05-10 | keepercommander/commands/migrate.py + unit-tests/test_command_migrate.py |

## Known caveats

- Verb names use kebab-case (`audit-explain`, `drift-watch`) per Commander convention
- Parser shapes mirror `dsk.shim` at `dsk@3999428`; `diff` currently accepts one manifest path and `bundle` accepts a compliance bundle manifest
- DSK shim deprecated aliases (`import_from_keepercmd`, `audit`) still work but emit `DeprecationWarning`; not exposed via Commander surface
- `migrate` is a normal `GroupCommand`, visible pre-enterprise-login. Per joao pending decision (see agent-collab inbox), may need re-gating to `enterprise_commands`.

## Open questions for Keeper engineering

1. PR target: `release` or `master`?
2. Should `migrate` be enterprise-gated?
3. Acceptable upper bound `<3` on DSK dep?
4. **Should `keeper migrate <verb>` use the user's active Commander session,
   OR always require `--commander-config <path>`?**

   Phase 1 choice: always require `--commander-config`. DSK manages its own
   Commander auth (per `dsk shim --commander-config <path>` pattern); the
   Commander wrapper does not pass `params` (`KeeperParams`) into the verb
   handlers. This means the operator must point at their config file
   explicitly, not rely on `keeper login` having created an active session.

   Trade-off: simpler Phase 1 implementation, BUT operator surface is
   inconsistent with other Commander commands that auto-use the active
   session.

   Recommended Phase 3 follow-up: design a Commander session-handoff API so
   DSK can accept the active session instead of requiring `--commander-config`.
   Out of scope for this PR.
