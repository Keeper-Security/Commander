# Scenario template

Copy to `<NN>-<slug>.md` (next free number). All fields are required; brevity is fine.

---

## Attack

One sentence describing the attack in plain language. What does the attacker do, and what do they want?

## Pre-condition

What does the attacker need access to, before this scenario applies? (Shell access, repo write access, network position, etc.)

## Defense

How is this attack prevented or detected? Cite the specific code path, validator, sidecar, interlock, or audit-trail that catches it.

## Pinning test

`path/to/test_file.py::TestClass::test_method` — the test that asserts the defense fires when the attack is attempted. If no such test exists yet, write `none — TODO`.

## Status

One of: 🔵 seeded · 🟡 needs test · 🟢 pinned · 🛑 superseded · with optional one-line context.

## Affected phase / opportunity

Which phase of [`declare-overlay-execution-plan.md`](https://github.com/msawczynk/agent-collab/blob/main/shared/context/declare-overlay-execution-plan.md) or which opportunity in [`../../../DSK_INTEGRATION_ANALYSIS.md`](../../../DSK_INTEGRATION_ANALYSIS.md) does this attack target?

## Owner

Bob (keeperCMD) / Midas (DSK) / Both — who owns the defense + pinning test for this scenario?
