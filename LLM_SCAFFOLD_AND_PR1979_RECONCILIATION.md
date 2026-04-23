# LLM Scaffold + Design Reconciliation (PR #1979 Context)

## Purpose

Create a shared alignment artifact for humans and agents that:

1. Provides a complete repository folder/subfolder scaffold.
2. Captures how to navigate the codebase safely and quickly.
3. Reconciles the linked design requirements from PR #1979 against current `master`.
4. Identifies what appears dropped/not merged and what to implement next.

Primary linked context:  
`https://github.com/Keeper-Security/Commander/pull/1979#issuecomment-4297610355`

---

## Inputs Used (Repository + Documentation)

### Repository evidence
- PR #1979 metadata/body/comments via `gh pr view --json ...`
- Current `master` code in:
  - `keepercommander/commands/pam_launch/launch.py`
  - `keepercommander/commands/pam_launch/terminal_connection.py`
- Unit test discovery in `unit-tests/pam`
- Full directory walk from current checkout

### Keeper documentation evidence
- `https://docs.keeper.io/en/keeperpam/secrets-manager/developer-sdk-library/java-sdk/linked-credentials-on-pam-records`
  - Confirms `jit_settings` as an expected link/settings path in Keeper PAM tooling.

---

## Step-by-step method used

1. Resolved the linked comment and then fetched full PR #1979 JSON to extract actual requirements (the specific comment only pings reviewers; requirements are in PR body).
2. Queried current code for JIT launch markers (`--jit`, `jitSettings`, `jitElevation`, `credentialType='ephemeral'`, and TODO markers).
3. Read launch and terminal connection modules end-to-end to verify behavior (not only symbol existence).
4. Generated complete directory scaffold from filesystem walk (excluding `.git` internals/caches).
5. Cross-checked Keeper docs for `jit_settings` terminology and schema-path intent.
6. Produced requirement-by-requirement reconciliation with evidence and concrete remediation sequence.

---

## Repository profile (current checkout)

- Total directories (excluding `.git` and common caches): **105**
- Total files: **633**
- Dominant language: **Python** (`.py`: 539 files)
- Primary app package: **`keepercommander/`** (513 files)
- Test roots: **`tests/`** and **`unit-tests/`**

Top-level file counts:
- `keepercommander`: 513
- `unit-tests`: 37
- `examples`: 33
- repo root: 25
- `tests`: 14

---

## Complete folder + subfolder scaffold

```text
.
├── .github
│   └── workflows
├── dotnet-keeper-sdk
├── examples
│   ├── aws_lambda
│   └── pam-kcm-import
├── images
├── keepercommander
│   ├── auth
│   ├── biometric
│   │   ├── commands
│   │   ├── platforms
│   │   │   └── macos
│   │   └── utils
│   ├── commands
│   │   ├── discover
│   │   ├── domain_management
│   │   ├── helpers
│   │   ├── pam
│   │   ├── pam_cloud
│   │   ├── pam_debug
│   │   ├── pam_import
│   │   ├── pam_launch
│   │   │   ├── guac_cli
│   │   │   └── guacamole
│   │   ├── pam_saas
│   │   ├── pam_service
│   │   ├── pedm
│   │   ├── supershell
│   │   │   ├── data
│   │   │   ├── handlers
│   │   │   ├── renderers
│   │   │   ├── screens
│   │   │   ├── state
│   │   │   ├── themes
│   │   │   └── widgets
│   │   └── tunnel
│   │       └── port_forward
│   ├── config_storage
│   │   ├── aws-kms
│   │   └── aws-sm
│   ├── discovery_common
│   ├── humps
│   ├── importer
│   │   ├── 1password
│   │   ├── bitwarden
│   │   ├── csv
│   │   ├── cyberark
│   │   ├── cyberark_portal
│   │   ├── dashlane
│   │   ├── json
│   │   ├── keepass
│   │   ├── lastpass
│   │   ├── manageengine
│   │   ├── myki
│   │   ├── nordpass
│   │   ├── proton
│   │   └── thycotic
│   ├── keeper_dag
│   │   ├── connection
│   │   ├── proto
│   │   └── struct
│   ├── pedm
│   ├── plugins
│   │   ├── adpasswd
│   │   ├── awskey
│   │   ├── awspswd
│   │   ├── azureadpwd
│   │   ├── mssql
│   │   ├── mysql
│   │   ├── oracle
│   │   ├── postgresql
│   │   ├── pspasswd
│   │   ├── ssh
│   │   ├── sshkey
│   │   ├── unixpasswd
│   │   └── windows
│   ├── proto
│   ├── qrc
│   ├── resources
│   │   └── email_templates
│   ├── rsync
│   │   └── sftp
│   ├── scim
│   ├── service
│   │   ├── api
│   │   ├── commands
│   │   │   └── integrations
│   │   ├── config
│   │   ├── core
│   │   ├── decorators
│   │   ├── docker
│   │   └── util
│   ├── sox
│   ├── storage
│   └── yubikey
├── sample_data
├── tests
│   └── compliance
└── unit-tests
    ├── commands
    │   └── helpers
    ├── pam
    └── service
```

---

## Agent navigation notes (high signal paths)

- PAM launch entrypoint:  
  `keepercommander/commands/pam_launch/launch.py`
- Terminal tunnel + gateway payload construction:  
  `keepercommander/commands/pam_launch/terminal_connection.py`
- PAM import/edit (contains existing JIT-settings data handling on import side):  
  `keepercommander/commands/pam_import/`
- PAM-related unit tests:  
  `unit-tests/pam/`
- CLI/parsing and command routing patterns:  
  `keepercommander/commands/`

Safe change strategy for agents:
1. Update launch argument parser + validations in `launch.py`.
2. Thread state into `launch_terminal_connection(...)/create_connection_context(...)`.
3. Extend gateway `inputs` payload assembly in `terminal_connection.py`.
4. Add unit tests under `unit-tests/pam/`.
5. Document command behavior near `pam_launch` docs/README.

---

## Design requirements extracted from PR #1979

From PR #1979 summary/body, expected behavior is:

1. Add optional `-j/--jit` for `pam launch`.
2. Read `pamSettings.options.jit_settings` from `pamMachine`.
3. Support three modes:
   - ephemeral account (`create_ephemeral: true`)
   - privilege elevation (`elevate: true`)
   - both combined
4. Precedence: `allowSupplyHost > JIT > allowSupplyUser > linked`.
5. `-j` mutually exclusive with `-cr`, `-H`, `-hr`.
6. `ephemeral_account_type=='domain'` requires `pam_directory_uid_ref`.
7. Gateway inputs contract:
   - ephemeral/both => `credentialType='ephemeral'` + `jitSettings`
   - elevation => linked credential + `jitElevation`
   - both => include both payloads
8. Guacd username/password should be empty in ephemeral mode.
9. Remove the existing JIT TODO marker.
10. Add README + dedicated unit tests for JIT launch.

---

## Reconciliation against current `master` (what appears dropped / not merged)

| Requirement | Status on current `master` | Evidence |
|---|---|---|
| `-j/--jit` CLI flag exists | **Missing** | `launch.py` parser block (lines ~265-286) has no `--jit` argument. |
| JIT TODO removed | **Not removed** | `launch.py` lines ~507-511 still contain `# TODO: Add JIT ...`. |
| Read `pamSettings.options.jit_settings` in launch path | **Missing** | No JIT extraction helpers in `launch.py`; no `jit_settings` handling in `pam_launch` path. |
| Three JIT modes derived | **Missing** | No `_derive_jit_mode` / equivalent logic found in `pam_launch` module. |
| Precedence `allowSupplyHost > JIT > allowSupplyUser > linked` | **Partial / JIT absent** | Existing code handles allowSupplyHost/user precedence among current options but has no JIT branch to apply this full ordering. |
| `-j` mutually exclusive with `-cr/-H/-hr` | **Missing** | No `jit` option or conflict checks exist in `launch.py` argument/validation flow. |
| Domain ephemeral requires `pam_directory_uid_ref` | **Missing** | No domain-specific JIT validation in launch flow. |
| Gateway `credentialType='ephemeral'` path | **Missing** | In `terminal_connection.py` lines ~1656-1704, inputs only branch to `linked`/`userSupplied` (or none). |
| Emit `jitSettings` / `jitElevation` payloads | **Missing** | No assignment of `inputs['jitSettings']` or `inputs['jitElevation']` in offer inputs assembly. |
| Empty guacd creds in ephemeral mode | **Missing** | `_build_guacamole_connection_settings()` populates username/password from linked/pamMachine paths; no ephemeral override branch. |
| New `pam_launch/README.md` for JIT | **Missing** | File not present at `keepercommander/commands/pam_launch/README.md`. |
| JIT unit test file | **Missing** | `unit-tests/pam/test_pam_launch_jit.py` does not exist; no JIT tests found under `unit-tests/pam/`. |

Additional note:
- `terminal_connection.py` docstring mentions `'ephemeral'` as a conceptual credential type in function comments, but runtime branching does not implement it. This is a **documentation/code mismatch**, not functional support.

---

## Reconciliation conclusion

The linked PR #1979 design appears **not merged into current `master`** (or was dropped/reverted later).  
Current codebase retains pre-JIT launch behavior with an explicit TODO marker and no transport payload support for `jitSettings`/`jitElevation`.

---

## Suggested implementation sequence (for follow-on agents)

1. **Launch parser + validation (`launch.py`)**
   - Add `--jit/-j`.
   - Implement explicit conflict matrix with `-cr/-H/-hr`.
   - Add JIT extraction and mode derivation helpers.
   - Enforce domain/pam_directory requirement.
   - Integrate precedence ordering with existing allowSupply logic.

2. **Context threading (`terminal_connection.py`)**
   - Include `jit_enabled`, `jit_mode`, raw/normalized JIT payloads in extracted settings/context.

3. **Gateway payload contract**
   - Extend `inputs` builder to set:
     - `credentialType='ephemeral'` when required.
     - `jitSettings` and/or `jitElevation` with schema-aligned keys.

4. **Guacd credential behavior**
   - For ephemeral mode, ensure username/password are empty before connect path.

5. **Tests + docs**
   - Add `unit-tests/pam/test_pam_launch_jit.py` with mode/precedence/payload coverage.
   - Add `keepercommander/commands/pam_launch/README.md` documenting flag, precedence, payloads, and compatibility.

---

## Hand-off notes for humans/reviewers

- This document is an alignment artifact only; no runtime behavior changes were introduced.
- If desired, next step can be a dedicated implementation PR that ports PR #1979 behavior onto current `master` with updated tests and docs.

