# Red-team corpus — `keeper-tenant-migrate` adversarial scenarios

**Status:** seed v1.0 — 2026-05-08.
**Owner:** joao (cmd-side). Cross-product scenarios (Tier 3) describe
attack vectors at the cmd→DSK consumer boundary but are owned cmd-side
because the migration tool's output is what attackers would target.

This directory is the **adversarial test corpus** for the
`keeper-tenant-migrate` tool. Each scenario enumerates a known attack
vector that the threat model must close, and either points at an
existing pinning test or specifies a new test that needs writing.

---

## Why a shared corpus

Cross-product integrations have boundary attacks that neither product would catch on its own:

- **keeperCMD writes** `manifest.csv` / `inventory.json` / `records-export/` — DSK consumes them. An attacker between the two has a clean injection surface.
- **DSK adopts** records via ownership marker writes — keeperCMD doesn't see those. An attacker forging the marker pre-adoption pollutes DSK's ownership graph.
- **Both products** subprocess to Commander. Commander's own failure classes (LIVE_BUGS catalog) are shared blast radius.

Each side has its own attack model. The integration adds new ones. This corpus tracks all of them in one place so both bots can reason about coverage.

---

## Tiers

The corpus is organised in three tiers by attack scope:

| Tier | Scope | Status |
|---|---|---|
| **Tier 1** — cmd-internal | Attack surface: cmd subcommands consumed by an operator on one machine. Already covered by `tests/test_adversarial.py` (8 categories, 18 tests). | ✅ existing — pointer-only here |
| **Tier 2** — DSK-internal | Attack surface: DSK subcommands consumed by an operator on one machine. Lives in DSK's own test suite (`msawczynk/dsk`). | 🟡 indexed by reference; DSK-side owners maintain |
| **Tier 3** — cross-product boundary | Attack surface: the integration line — `manifest.csv` between `keeper-migrate` finishing and any downstream consumer starting, ownership-marker forgery on the target tenant, concurrent read/write of the run-dir. | 🔵 seeded with the 5 scenarios below |

---

## Tier 1 — keeperCMD-internal (existing)

Already covered by [`../test_adversarial.py`](../test_adversarial.py) — 8 categories, 18 tests, all green:

| Cat | Class | Attack vector |
|---|---|---|
| 1 | `SafeguardBypassTests` | `prefix=''` wipe attempt, empty-roster commit, missing `--expected-tenant-name` |
| 2 | `SideloadingTests` | malformed/malicious inventory, manifest, checkpoint files |
| 3 | `SilentFailureTests` | Commander no-op masquerading as success, error-swallowing in cleanup paths |
| 4 | `ManifestDaisyChainTests` | `records-manifest` output weaponised as `records-shares` input |
| 5 | `DecommissionPlanAuditTests` | hand-crafted decommission plan claiming false progress |
| 6 | `AuditTamperingTests` | edited `audit.log` survives `audit-verify` (must fail) |
| 7 | `SourceReadOnlyHarnessRailTests` | source-config rail bypass attempts |
| 8 | `MCContextLateralMovementTests` | `--mc` route confusion, MC-as-MSP write-path |

When a new keeperCMD-internal attack vector surfaces, add it to `test_adversarial.py` (existing convention) and append a row here.

---

## Tier 2 — DSK-internal (indexed by reference)

Lives in DSK's own test suite (`msawczynk/dsk`). cmd-side this section
is informational only — DSK's own adversarial coverage is the
authoritative source for Tier 2 scenarios.

---

## Tier 3 — cross-product boundary (seed scenarios — expand here)

Each scenario below has its own file under [`scenarios/`](scenarios/) with a fixed shape: **Attack / Pre-condition / Defense / Pinning test / Status**. New scenarios get `<NN>-<slug>.md` filenames so the directory listing self-orders.

| ID | Scenario | Phase impact | Status |
|---|---|---|---|
| [`01-overlay-role-rename-privilege-escalation.md`](scenarios/01-overlay-role-rename-privilege-escalation.md) | Malicious `edits.yaml` renames a role to escalate access on the target tenant | Phase 1 (declare wedge) | 🔵 seeded — pinning test exists in spike branch |
| [`02-manifest-csv-tamper-between-keepercmd-and-dsk.md`](scenarios/02-manifest-csv-tamper-between-keepercmd-and-dsk.md) | Attacker modifies `manifest.csv` between `keeper-migrate` finishing and any downstream consumer starting (UID swap) | Records pipeline boundary | 🟡 needs consumer-side test |
| [`03-ownership-marker-forgery.md`](scenarios/03-ownership-marker-forgery.md) | Attacker writes an ownership-marker field to a target-tenant record before a downstream consumer adopts it (poisons the adoption graph) | Post-migration adoption boundary | 🟡 needs consumer-side test |
| [`04-concurrent-overlay-runs.md`](scenarios/04-concurrent-overlay-runs.md) | Two `declare overlay` invocations run concurrently against the same base inventory; attacker triggers race | Declare overlay | 🟡 needs file-lock test |
| [`05-shell-access-between-plan-and-apply.md`](scenarios/05-shell-access-between-plan-and-apply.md) | Attacker has temporary shell access on the operator host between `plan` and `apply` — can they tamper with `inventory.json` undetected? | Declare overlay | 🔵 seeded — SHA-256 sidecar invariant covers it |

---

## Contribution protocol

When a new attack vector worth pinning surfaces:

1. **Pick a tier**: which scope does it fall under? (1 cmd-internal /
   2 DSK-internal / 3 cross-product boundary)
2. **Tier 1** — add the test in `tests/test_adversarial.py`; append a
   row to the Tier 1 table above.
3. **Tier 3** — write a new scenario file `scenarios/<NN>-<slug>.md`
   following the template ([`scenarios/00-template.md`](scenarios/00-template.md)).
   Add a row to the Tier 3 table above.
4. **Don't delete scenarios**: if a defense is later removed (we
   decided the scenario is implausible / superseded), mark
   `status: superseded` in the file rather than deleting — the
   historical signal is the value.

Scenarios are append-only on intent.

---

## Status meanings

- 🔵 **seeded** — scenario described, pinning test either exists or is unnecessary (defense is structural)
- 🟡 **needs test** — scenario described, no pinning test yet; needs one of us to write it
- 🟢 **pinned** — scenario described and pinning test exists, both linked
- 🛑 **superseded** — scenario no longer applies (with a one-line why)

---

## See also

- [`../test_adversarial.py`](../test_adversarial.py) — Tier 1
  source-of-truth (18 tests across 8 categories)
- [`../../DSK_INTEGRATION_ANALYSIS.md`](../../DSK_INTEGRATION_ANALYSIS.md)
  — cross-product context with `msawczynk/dsk`
