I’ll review the branch from the changed code and the smoke-test doc, then map findings back to the review axes and commits. I’m starting with the branch diff and the three primary Python files so the report is grounded in actual behavior.
`rg` is not installed in this workspace, so I’m falling back to standard shell search. One referenced file path does not exist at the exact location given, so I’m locating the actual registry module before assessing the lease logic.
The branch has deleted `keepercommander/commands/tunnel_registry.py`; the current lease expiry/dedup implementation appears embedded in `tunnel_and_connections.py`. I’m expanding the review to the workflow helper modules because the validator, transport fallback, approval polling, and command validation live there rather than in the launch terminal module.
The validator’s transport-error branch does allow launch/tunnel when workflow API reads fail. I’m checking whether that is constrained elsewhere by server-side checks, config gates, or action enforcement, and whether command paths can distinguish intentional denials from unavailable workflow endpoints.
I’ve found one concrete regression in the workflow read display path: create/update encode time as HHMM, but the table formatter still decodes with `/60`, so table output lies for values with minutes. I’m now mapping the smoke document against the actual commit list to separate code issues from coverage gaps.
**Scope Notes**

[OK] I reviewed the changed Python paths plus workflow helper modules where the actual gate logic lives; `keepercommander/commands/tunnel_registry.py` is deleted on this branch, with lease timer logic now in `tunnel_and_connections.py`.
Recommendation: Update the review/smoke references to the current file layout.

[LOW] The branch is 24 commits above `f4c35150`, while the smoke doc says “all 11 commits” and uses stale commit hashes.
Recommendation: Refresh the smoke doc commit map before treating it as merge evidence.

**Security Review**

[HIGH] Workflow transport fallback is too broad: `WorkflowAccessValidator.validate()` allows access on any exception from `read_workflow_config`, `get_user_access_state`, or `get_workflow_state` after a config may exist ([mfa.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/workflow/mfa.py:89)).
Recommendation: Fail open only for explicit “endpoint unsupported/not deployed” capability errors; fail closed for authz, 5xx, timeout, malformed response, and any state-read failure after a workflow config is known.

[HIGH] Strict-deny enforcement is not actually strict when `params.enforcements["booleans"]` is empty; launch/tunnel and rotation return allow for an empty list ([helpers.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/workflow/helpers.py:124), [discoveryrotation.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/discoveryrotation.py:3045)).
Recommendation: Treat an enterprise enforcement context with an empty/missing specific key as deny; reserve allow only for truly non-enterprise/no-enforcement context.

[HIGH] Debug logging can leak secrets: `guacd_params` includes username/password/private key/passphrase and is copied into `offer_data`, then logged wholesale; TURN password and callback token are also logged ([terminal_connection.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/pam_launch/terminal_connection.py:1123), [terminal_connection.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/pam_launch/terminal_connection.py:1348), [terminal_connection.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/pam_launch/terminal_connection.py:1742)).
Recommendation: Redact secret-bearing keys before logging, or log only structural fields and lengths.

[OK] The workflow exemption enforces the intended AND condition: it first requires `allow_configure_workflow_settings`, then requires owner/edit access from owner/meta/shared-folder caches ([helpers.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/workflow/helpers.py:49)).
Recommendation: Add a regression test for edit-only, enforcement-only, and both-together cases.

[OK] Approval-to-checkout race handling is mostly delegated to `start_workflow`; client code does not assume approval is sufficient and catches checkout failure ([mfa.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/workflow/mfa.py:724)).
Recommendation: Preserve the ready flow UID across checkout so auto check-in still works if the post-checkout revalidation has a transient failure.

[OK] Rotation now mirrors the launch/tunnel two-gate pattern for enforcement and PAM config, and intentionally does not workflow-gate rotation ([discoveryrotation.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/discoveryrotation.py:3288)).
Recommendation: Fix the empty-booleans strict-deny issue there too.

**Code Quality Review**

[MEDIUM] `pam workflow update` boolean parsers silently turn any non-`true` value into `False`, so typos like `--require-mfa maybe` disable MFA ([config_commands.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/workflow/config_commands.py:371)).
Recommendation: Use a strict boolean parser accepting only `true/false` with a `CommandError` for invalid values.

[MEDIUM] HHMM encoding is only partly fixed: create/update and JSON formatting use HHMM, but table read output still decodes with `divmod(..., 60)` ([config_commands.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/workflow/config_commands.py:330)).
Recommendation: Change table formatting to `divmod(..., 100)` and add tests for `09:30-17:45`.

[MEDIUM] There is no backward-compat handling for workflow configs previously written as minutes-since-midnight; the new validator compares as HHMM ([mfa.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/workflow/mfa.py:206)).
Recommendation: Detect impossible HHMM values and document/migrate old branch-created configs where feasible.

[LOW] `--wait-timeout` accepts zero/negative values; the poller then waits at least 8 seconds while printing the invalid timeout ([mfa.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/workflow/mfa.py:556)).
Recommendation: Validate `--wait-timeout > 0` in both launch and tunnel command paths.

[LOW] `_print_transport_error()` and the `transport_error` comment path are now unreachable after fail-open transport handling ([mfa.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/workflow/mfa.py:345)).
Recommendation: Remove dead code or reinstate explicit fail-closed transport states.

[LOW] Tunnel lease timer dedup is per-record and cancels prior timers, so it avoids duplicate timer accumulation; stopped tunnels can still leave one timer alive until lease expiry ([tunnel_and_connections.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/tunnel_and_connections.py:775)).
Recommendation: Keep the dedup, but consider canceling or marking timers when workflows are manually ended to avoid stale notices.

**Usability / Ergonomics**

[MEDIUM] `pam tunnel start --auto-checkout` help says the lease is released when the tunnel ends, but the implementation intentionally does not release tunnel-owned workflow leases ([tunnel_and_connections.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/tunnel_and_connections.py:529)).
Recommendation: Fix the help text to say the lease remains until expiry or `pam workflow end`.

[MEDIUM] Auto check-in failure after `pam launch` is debug-only, leaving users unaware that a launch-owned lease stayed checked out ([launch.py](/Users/martin/Downloads/Cursor%20tests/Commander/keepercommander/commands/pam_launch/launch.py:1859)).
Recommendation: Emit a warning with `pam workflow end <record-or-flow>` guidance when auto check-in fails.

[LOW] Inline prompts are usable interactively, but CI safety depends on callers remembering `--reason`, `--ticket`, and `--auto-checkout`; there is no strict non-interactive mode.
Recommendation: Add `--non-interactive` or fail fast when required workflow inputs are missing and stdin is not a TTY.

[OK] Create/delete pre-check messages are actionable when the read succeeds.
Recommendation: For delete, distinguish “no config” from “could not verify config” instead of treating read failure as nothing to delete.

**Test Coverage Review**

[HIGH] The smoke doc has no transport-error fallback test and does not verify that transport failures cannot bypass intentional denies.
Recommendation: Add router/API fault tests for unsupported endpoint vs timeout/5xx/access-denied, including an approved-denied workflow state.

[MEDIUM] Auto check-in failure is not tested; section 8 covers success and preserving manual checkout only.
Recommendation: Mock `end_workflow` failure after launch exit and assert user-visible warning plus lease remains.

[OK] `--wait` timeout is documented as a manual variation at smoke lines 550-552.
Recommendation: Add invalid timeout coverage for `0` and negative values.

[MEDIUM] No explicit smoke coverage for: `8f4aaa37`, `828a2257`, `790eef62`, `c0a7638e`, `43c2d83b`, `3711e014`, `7a18ac69`, `f8d51dba`, and the unrelated `79a709a5` / `a19d6e88`.
Recommendation: Add focused sections or remove “covers all commits” language.

[MEDIUM] Partial-only coverage for `3d238705` and `e3b17dc2`: the doc exercises time ranges and lease expiry, but not HHMM read/table compatibility or duplicate timer suppression.
Recommendation: Add exact expected read output and repeat-start-before-expiry checks.

**Overall**

Quality score: 3/5.

Top 3 action items before merge:
1. Replace broad workflow transport fail-open with explicit unsupported-endpoint compatibility handling.
2. Fix strict-deny enforcement for empty enterprise boolean lists across launch/tunnel/rotation.
3. Redact debug logs that currently include credentials, private keys, TURN passwords, and callback tokens.

<!-- REVIEW DONE -->
