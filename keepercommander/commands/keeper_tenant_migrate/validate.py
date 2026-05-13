"""9-phase field-level validator (framework + initial checks).

Port target: `test_full_spectrum.sh` (1125 lines, 9 phases). The full
per-field comparison is too large for a single PR; this module establishes
the phase/check framework plus the structural phases (1-3: pre-flight,
nodes, teams). Phases 4-9 (roles, shared folders, records, record types,
enforcement details, per-user TOTP/custom-field checks) layer in later.

Architecture:
  - Each phase is a generator of `Check` objects yielded against a
    `ValidationContext` (inventory + target state + phase-scoped data).
  - Run produces a list[Check] with PASS/FAIL/SKIP/WARN statuses matching
    the bash script's categorization.
"""

from enum import Enum

from .helpers.node_paths import leaf_of
from .structure import LOCKOUT_RISK_ENFORCEMENTS


# Bug 81 — roles that target tenants on MSP edition auto-provision
# with managed_node bindings even when source had none. When source
# count < target count and the role is in this allowlist, the
# managed_nodes diff downgrades from FAIL to WARN with a specific
# tenant-edition explanation. Names are MSP-edition Commander built-ins
# observed in rehearsal-16 (Keeperdemo MSP target).
MSP_AUTO_PROVISIONED_ROLES = frozenset({
    'MSP Subscription Manager',
    'MSP Admin',
    'MSP Manager',
})


class Severity(Enum):
    PASS = 'PASS'
    FAIL = 'FAIL'
    SKIP = 'SKIP'
    WARN = 'WARN'


class Check:
    __slots__ = ('phase', 'severity', 'message', 'detail')

    def __init__(self, phase, severity, message, detail=''):
        self.phase = phase
        self.severity = severity
        self.message = message
        self.detail = detail

    def as_row(self):
        return [self.phase, self.severity.value, self.message, self.detail]

    def __repr__(self):
        sev = getattr(self.severity, 'value', self.severity)
        tail = f' — {self.detail}' if self.detail else ''
        return f'Check({sev} [{self.phase}] {self.message}{tail})'


class ValidationContext:
    """Carries the frozen source inventory + live target state between phases.

    target_state layout mirrors reconcile.py:
        {'nodes': [...], 'teams': [...], 'roles': [...], 'users': [...],
         'shared_folders': [...], 'record_types': [...] (optional)}

    `params` is the live Commander session (optional). Phases that don't
    need it (nodes/teams/roles/SFs/records) ignore it. Phase 8
    (vault_health) uses it to probe target state beyond the frozen snapshot.
    """

    def __init__(self, inventory, target_state, target_label='', params=None,
                 rename_map=None, structure_skipped_enforcements=None,
                 structure_skipped_privileges=None,
                 structure_skipped_privileges_set=None,
                 users_stage_status='unknown'):
        self.inventory = inventory
        self.target_state = target_state
        self.target_label = target_label
        self.params = params
        # Bug 61 — {(original_name, source_node): renamed} for roles,
        # teams, and (Bug 73) nodes; passed in by VerifyCommand from
        # the structure stage's persisted rename_map.json. Empty dict
        # when no disambiguation happened (or pre-v1.6 inventory). For
        # nodes, `source_node` is the source PARENT node name (the
        # field that disambiguates duplicate leaves).
        self.rename_map = rename_map or {'roles': {}, 'teams': {}, 'nodes': {}}
        # v1.7 / T2.2 — {(role_name, enforcement_key): reason} from
        # structure_results.csv classify-skip rows. Lets verify
        # distinguish "structure intentionally SKIPped this" from
        # "structure had no opinion (target lost it some other way)"
        # for lockout-risk and other auto-skipped enforcements. Empty
        # dict when no structure_results.csv was found alongside the
        # inventory or when running over pre-v1.7 artifacts.
        self.structure_skipped_enforcements = (
            structure_skipped_enforcements or {})
        # Bug 79 — {role_name: skipped_count} from structure_results.csv
        # role_priv add-privilege SKIPPED rows. Used by phase_roles
        # count-aggregator to subtract structure-time-skipped privileges
        # (target-edition-unsupported, e.g. `privilege_access` on a
        # non-MSP target) before comparing privileges count parity.
        self.structure_skipped_privileges = (
            structure_skipped_privileges or {})
        # Bug 78 derivative — {(role_name, priv_lower): True} from the
        # same SKIPPED rows, but per-(role, priv) instead of per-role
        # count. `_compare_role_privileges` consults this to downgrade
        # MISSING-on-target FAILs to SKIP for target-edition-unsupported
        # privileges. Without this, the role-level count check passes
        # (Bug 79) but the per-priv check still fires N FAILs.
        self.structure_skipped_privileges_set = (
            structure_skipped_privileges_set or set())
        # 2026-05-06 — auto-migrate's `users` stage is INTENTIONALLY
        # SKIP by default (sends real invitation emails — high blast
        # radius). When operators run auto-migrate without a
        # subsequent `tenant-migrate users --roster <csv>` step,
        # source users legitimately don't exist on target yet — that's
        # a pre-invite state, NOT a migration FAIL. phase_users uses
        # this hint to downgrade NOT-FOUND-on-target to SKIP with
        # operator-facing guidance ("run `tenant-migrate users
        # --roster <path>` to invite"). 'unknown' preserves pre-v1.7
        # FAIL behavior when verify is run without an audit.log to
        # reference.
        self.users_stage_status = users_stage_status

    def target_name_for(self, kind, source_name, source_node):
        # Bug 61 — resolve the disambiguated target name for a source
        # role/team. Falls back to source_name when no rename was
        # recorded — the common case for unique names.
        m = (self.rename_map or {}).get(kind, {}) or {}
        return m.get((source_name, source_node), source_name)

    def source_entities(self, kind):
        return self.inventory.get('entities', {}).get(kind, [])

    def target_entities(self, kind):
        return self.target_state.get(kind, [])


def load_structure_skipped_enforcements(path):
    """Read `structure_results.csv` and extract per-(role, key)
    classify-skip rows.

    Pre-v1.7 structure runs aggregate enforcement skips into a single
    `enforcements,All roles,set,SUCCESS,...,N skipped` summary row;
    v1.7+ adds per-key SKIP rows under `category=enforcement`,
    `action=classify-skip`. This loader returns those as
    `{(role_name, enforcement_key): reason}`. Pre-v1.7 artifacts
    yield an empty dict — verify falls back to the generic SKIP
    message in that case.
    """
    import csv
    import os
    out = {}
    if not path or not os.path.isfile(path):
        return out
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if (row.get('category') == 'enforcement'
                    and row.get('action') == 'classify-skip'
                    and row.get('status') == 'SKIPPED'):
                # `name` shape: '<role_name>.<enforcement_key>'.
                # rsplit instead of partition because role names CAN
                # contain dots (customer-defined names like
                # `Region.US`) — the key is the right-side anchor and
                # uses a known limited vocabulary, so split-from-right
                # is correct.
                row_name = row.get('name', '')
                if '.' not in row_name:
                    continue
                role_name, key = row_name.rsplit('.', 1)
                out[(role_name, key)] = row.get('notes', '')
    return out


def load_structure_skipped_privileges(path):
    """Read `structure_results.csv` and count `role_priv` SKIPPED
    rows per role.

    Bug 79 — the role-level privileges count check uses raw
    `len(privileges)` which trips when structure correctly SKIPs
    target-edition-unsupported privileges (`_classify_error`'s
    `'invalid privilege'` marker, e.g. `privilege_access` on a
    non-MSP target). Returns `{role_name: skipped_count}` so the
    count compare can subtract before checking parity.

    Row shape captured by `step_managed_nodes`:
        category=role_priv, name='<role_name>: <priv> on <node>',
        action=add-privilege, status=SKIPPED
    """
    counts, _ = _parse_structure_skipped_privileges(path)
    return counts


def load_structure_skipped_privileges_set(path):
    """Bug 78 derivative — return per-(role, priv) skip set so the
    managed-node-level privilege comparison in `_compare_role_privileges`
    can downgrade target-edition-unsupported privileges from FAIL to
    SKIP. Without this, a role with 'privilege_access' or
    'manage_billing' (MSP-only privileges) FAILs verify against a
    non-MSP target even though structure correctly SKIPped them at
    write time. Companion to `load_structure_skipped_privileges`
    which returns a count for the role-level count check.

    Returns `{(role_name, privilege_lower): True}` — privilege names
    are lowercased to match `_compare_role_privileges` which
    normalizes both sides to lowercase before comparing.
    """
    _, skip_set = _parse_structure_skipped_privileges(path)
    return skip_set


def _load_manifest_uid_map(manifest_path):
    """Bug 86 — load source_uid → target_uid pairs from
    `manifest.csv` (records-import writes one row per imported
    record). Returns `{source_uid: target_uid}`; empty when the
    file is absent (older runs / hand-staged target_state).
    """
    import csv
    import os
    out = {}
    if not manifest_path or not os.path.isfile(manifest_path):
        return out
    try:
        with open(manifest_path) as f:
            reader = csv.DictReader(f)
            for row in reader:
                src = (row.get('source_uid') or '').strip()
                tgt = (row.get('target_uid') or '').strip()
                if src and tgt:
                    out[src] = tgt
    except OSError:
        return {}
    return out


def detect_users_stage_status(audit_log_path):
    """Inspect the run's `audit.log` to determine whether the `users`
    stage was actually run.

    Returns one of:
      - 'ran'      — at least one entry in audit.log carries
                     `"subcommand": "users"` (operator ran
                     `tenant-migrate users --roster ...`).
      - 'skipped'  — audit.log exists, contains other subcommands
                     (e.g. structure / verify / records-*), but no
                     `users` entry. Auto-migrate's default-SKIP
                     never recorded one. Verify should treat
                     source-user-not-on-target as a pre-invite
                     state, not a migration failure.
      - 'unknown'  — audit.log is missing or unreadable. Verify
                     keeps the pre-existing FAIL semantic.

    The line format is one JSON object per line — easy to grep
    without full parsing for the common case.
    """
    import os
    if not audit_log_path or not os.path.isfile(audit_log_path):
        return 'unknown'
    saw_users = False
    saw_other = False
    try:
        with open(audit_log_path) as f:
            for line in f:
                if '"subcommand": "users"' in line:
                    saw_users = True
                elif '"subcommand":' in line:
                    saw_other = True
    except OSError:
        return 'unknown'
    if saw_users:
        return 'ran'
    if saw_other:
        return 'skipped'
    return 'unknown'


def _parse_structure_skipped_privileges(path):
    """Single-pass parse of structure_results.csv `role_priv SKIPPED`
    rows. Returns (counts_by_role, set_of_(role, priv_lower))."""
    import csv
    import os
    counts = {}
    skip_set = set()
    if not path or not os.path.isfile(path):
        return counts, skip_set
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if (row.get('category') == 'role_priv'
                    and row.get('action') == 'add-privilege'
                    and row.get('status') == 'SKIPPED'):
                # name: '<role_name>: <privilege> on <node>'
                # Role name may contain ': ' if operator-defined
                # (`Access Level: Read-Only`), but the right-most
                # ': ' before ' on ' is the priv anchor. Split on
                # the LAST ': ' that precedes ' on '.
                row_name = row.get('name', '')
                if ': ' not in row_name or ' on ' not in row_name:
                    continue
                # Find the ': ' immediately before ' on '.
                on_idx = row_name.rfind(' on ')
                if on_idx < 0:
                    continue
                head = row_name[:on_idx]
                colon_idx = head.rfind(': ')
                if colon_idx < 0:
                    continue
                role_name = head[:colon_idx]
                priv = head[colon_idx + 2:].strip().lower()
                counts[role_name] = counts.get(role_name, 0) + 1
                if priv:
                    skip_set.add((role_name, priv))
    return counts, skip_set


# ─── Phase 1: pre-flight — counts match ──────────────────────────────────────


def phase_pre_flight(ctx):
    """Verify source and target are both populated with expected top-level counts."""
    if not ctx.inventory:
        yield Check('pre_flight', Severity.FAIL, 'Inventory missing', '')
        return
    if not ctx.target_state:
        yield Check('pre_flight', Severity.FAIL, 'Target state missing', '')
        return
    yield Check('pre_flight', Severity.PASS,
                'Inventory + target state loaded',
                f"source_user={ctx.inventory.get('source_user', '')}")


# ─── Phase 2: nodes — name present, isolated flag propagated ─────────────────


def phase_nodes(ctx):
    source = ctx.source_entities('nodes')
    target_entries = ctx.target_entities('nodes')

    if not source:
        yield Check('nodes', Severity.SKIP, 'No source nodes in inventory')
        return

    # Bug 16 follow-up: parent-path topology check.
    # Source root → target root remap is computed once. Children whose
    # parent equals the scope node should land under that scope node on
    # target (preserved by structure.py's topological_node_order). Any
    # other parent should match by leaf name.
    source_root = (ctx.inventory.get('source_root') or '').strip()
    scope_node = (ctx.inventory.get('scope_node') or '').strip()
    # Best-effort target-root resolution. Old captures don't carry
    # `enterprise_name`; we fall back to the parent of the first
    # rootless target node.
    target_root = (ctx.target_state.get('enterprise_name') or '').strip()
    if not target_root:
        for tn in target_entries:
            if not (tn.get('parent') or '').strip():
                target_root = tn.get('name', '').strip()
                break

    def expected_target_parent(src_parent):
        """Apply the same remap StructureRestore uses so verify's
        comparison is in target-namespace terms."""
        sp = (src_parent or '').strip()
        if sp == source_root:
            return target_root
        # Scope-node case is preserved (Bug 16 fix in topological_node_order)
        # so the leaf name matches — no remap needed.
        return sp

    # Bug 73 — composite (name, parent) index disambiguates duplicate
    # leaf names (Finance under Subsidiary A vs Subsidiary B). The
    # prior name-only dict collapsed siblings so phase_nodes treated 6
    # source rows as 1 target row and never reported the missing
    # duplicates. Legacy captures without the parent field fall back
    # to the name-only index.
    target_by_pair = {}
    target_by_name = {}
    for t in target_entries:
        nm = t.get('name', '')
        if 'parent' in t:
            par = (t.get('parent') or '').strip()
            target_by_pair[(nm, par)] = t
        target_by_name.setdefault(nm, t)

    for node in source:
        name = node.get('name', '')
        if not name:
            continue
        src_parent = (node.get('parent') or '').strip()
        # Bug 75 — the source enterprise root ("My company" on EU demo;
        # whatever `source_root` carries) is NOT migrated by design.
        # Target keeps its own root (e.g. Keeperdemo); the source root
        # has no target counterpart. Skip the row with an explicit SKIP
        # so the audit trail records the intentional non-migration
        # instead of the FAIL phase_nodes used to emit ("Node missing
        # on target: My company") on every rehearsal.
        if (source_root and name == source_root and
                src_parent in ('', source_root)):
            yield Check('nodes', Severity.SKIP,
                        f'Source root {name!r} not migrated by design '
                        f'(target keeps its own root)')
            continue
        expected = expected_target_parent(src_parent)
        # Bug 73 — for duplicate-name source nodes, the structure stage
        # renamed all-but-the-first to `<name> (<parent leaf>)` so the
        # CLI's tenant-wide name dedup doesn't drop them. Translate
        # the source name through rename_map (keyed by source parent)
        # before the target lookup. Identity passthrough for unique
        # names. The composite (name, parent) key still disambiguates
        # legacy captures or `--preserve-duplicate-node-names` runs.
        target_name = ctx.target_name_for(
            'nodes', name, leaf_of(src_parent) if src_parent else '')
        t = target_by_pair.get((target_name, expected))
        if t is None:
            t = target_by_name.get(target_name)
        if not t:
            display = name if target_name == name else f'{name}→{target_name}'
            label = (f'{display} (parent={src_parent!r})'
                     if src_parent else display)
            yield Check('nodes', Severity.FAIL,
                        f'Node missing on target: {label}')
            continue
        # Isolated-flag parity
        src_iso = bool(node.get('isolated', False))
        tgt_iso = bool(t.get('isolated', False))
        if src_iso != tgt_iso:
            yield Check('nodes', Severity.FAIL,
                        f'Node {target_name} isolated flag mismatch: source={src_iso} target={tgt_iso}')
            continue
        # Parent-path check. Skip silently when the target capture
        # predates the parent field (older artifacts) or scope/source
        # root resolution failed — old verify behavior preserved.
        if 'parent' in t and source_root:
            tgt_parent = (t.get('parent') or '').strip()
            if expected and tgt_parent and expected != tgt_parent:
                yield Check('nodes', Severity.FAIL,
                            f'Node {target_name} parent mismatch: '
                            f'source parent={src_parent!r} → expected '
                            f'target parent={expected!r}, actual={tgt_parent!r}',
                            'topology divergence — likely scope-node remap bug')
                continue
        detail = f'isolated={src_iso}'
        if target_name != name:
            detail = f'renamed→{target_name!r}; {detail}'
        yield Check('nodes', Severity.PASS, f'Node {name}', detail)


# ─── Phase 3: teams — name, node, restrictions ───────────────────────────────


def phase_teams(ctx):
    source = ctx.source_entities('teams')
    target_entries = ctx.target_entities('teams')
    target_by_name = {t.get('name', ''): t for t in target_entries}
    # Bug 65 — also index by stripped name so whitespace-padded source
    # names match teams created by the whitespace-stripping structure
    # path (Bug 55).
    target_by_stripped = {(t.get('name', '') or '').strip(): t
                          for t in target_entries
                          if t.get('name', '')}

    if not source:
        yield Check('teams', Severity.SKIP, 'No source teams in inventory')
        return

    for team in source:
        name = team.get('name', '')
        if not name:
            continue
        # Bug 61 — resolve through rename_map: source teams whose names
        # collide across nodes get a node-suffix appended on target.
        target_name = ctx.target_name_for('teams', name, team.get('node', ''))
        t = target_by_name.get(target_name) or target_by_stripped.get(target_name.strip())
        if not t:
            yield Check('teams', Severity.FAIL, f'Team missing on target: {name}')
            continue
        src_restricts = (team.get('restricts', '') or '').upper().strip()
        tgt_restricts = (t.get('restricts', '') or '').upper().strip()
        if src_restricts != tgt_restricts:
            yield Check('teams', Severity.FAIL,
                        f'Team {name} restricts mismatch: source="{src_restricts}" target="{tgt_restricts}"')
        else:
            yield Check('teams', Severity.PASS, f'Team {name}',
                        f'restricts="{src_restricts}"')

        # Team-level count parity. role_count drift is FAIL (would mean
        # structure-restore dropped an assignment). user_count drift is
        # WARN — pending invitations move it.
        src_users = team.get('user_count', 0) or 0
        tgt_users = t.get('user_count', 0) or 0
        if src_users != tgt_users:
            yield Check('teams', Severity.WARN,
                        f'Team {name} user_count src={src_users} '
                        f'target={tgt_users} (invite acceptance lag)')
        src_roles = team.get('role_count', 0) or 0
        tgt_roles = t.get('role_count', 0) or 0
        if src_roles != tgt_roles:
            yield Check('teams', Severity.FAIL,
                        f'Team {name} role_count src={src_roles} '
                        f'target={tgt_roles}')

        # Bug 44 — node placement check. Cross-tenant root remap is
        # legit (`My company\X` → `Keeperdemo\X`), so we compare leaf
        # names only. WARN on mismatch — FAIL would over-flag every
        # cross-tenant migration that involves a node-name change.
        src_node = (team.get('node') or '').strip()
        tgt_node = (t.get('node') or '').strip()
        if src_node and tgt_node:
            src_leaf = src_node.rsplit('\\', 1)[-1]
            tgt_leaf = tgt_node.rsplit('\\', 1)[-1]
            if src_leaf != tgt_leaf:
                yield Check('teams', Severity.WARN,
                            f'Team {name} node leaf src={src_leaf!r} '
                            f'target={tgt_leaf!r}')
            else:
                yield Check('teams', Severity.PASS,
                            f'Team {name} node leaf={src_leaf}')


# ─── Phase 4: roles — managed nodes, privileges, enforcements, teams ─────────


def _normalize_bool(v):
    if isinstance(v, bool):
        return 'true' if v else 'false'
    return str(v)


# Standard Keeper record types — UIDs stable across tenants per Bug 60.
# Used by Bug 77 verify-side normalization for `restrict_record_types`
# when source carries name-strings and target was captured as the JSON
# `{"std":[...],"ent":[...]}` payload.
_STD_RECORD_TYPE_ID_TO_NAME = {
    1: 'address', 2: 'bankAccount', 3: 'bankCard', 4: 'birthCertificate',
    5: 'contact', 6: 'databaseCredentials', 7: 'driverLicense',
    8: 'encryptedNotes', 9: 'file', 10: 'general', 11: 'healthInsurance',
    12: 'login', 13: 'membership', 14: 'passport', 15: 'photo',
    16: 'serverCredentials', 17: 'softwareLicense', 18: 'sshKeys',
    19: 'ssnCard', 96: 'wifiCredentials',
}


def _restrict_record_types_to_name_set(value, ent_id_to_name=None):
    """Normalize a `restrict_record_types` value (any captured shape) to a
    name-set so source and target can be set-compared.

    Source side after Bug 60 emits a portable comma-separated name string.
    Target side captures the value verbatim from `params.enterprise.roles`
    as `'{"std":[..],"ent":[..]}'` (JSON) or as the same comma-name
    string when read through a CLI path. Both shapes flatten here.

    `ent_id_to_name` (optional): target's record_types snapshot keyed by
    ID. Custom enterprise types resolve through it; unresolved IDs are
    surfaced as `<ent:NNN>` markers so the diff is explicit rather than
    silently dropped. Returns None when value is unrecognized — caller
    falls back to raw string compare.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if s.startswith('{'):
        import json as _json
        try:
            payload = _json.loads(s)
        except (TypeError, ValueError):
            return None
        if not isinstance(payload, dict):
            return None
        names = set()
        for sid in payload.get('std', []) or []:
            names.add(_STD_RECORD_TYPE_ID_TO_NAME.get(sid, f'<std:{sid}>'))
        for eid in payload.get('ent', []) or []:
            if ent_id_to_name and eid in ent_id_to_name:
                names.add(ent_id_to_name[eid])
            else:
                names.add(f'<ent:{eid}>')
        return names
    return {tok.strip() for tok in s.split(',') if tok.strip()}


def _names_of(items):
    out = set()
    for t in items or []:
        if isinstance(t, dict):
            out.add(t.get('name', t.get('team_name', '')))
        elif t:
            out.add(str(t))
    return {n for n in out if n}


def _compare_role_privileges(phase, name, src_mn, tgt_mn, skip_privs=None):
    """`skip_privs` is the set of priv names (lowercased) that
    structure SKIPped at write time (target-edition-unsupported).
    Source-side privs that landed in this set get SKIP, not FAIL.
    Companion to Bug 79 count adjust — without per-priv awareness the
    aggregate count passes but each individual missing priv still
    FAILs the role."""
    skip_privs = skip_privs or set()
    src_privs = set(src_mn.get('privileges', []) or [])
    tgt_privs = set(tgt_mn.get('privileges', []) or [])
    for p in sorted(src_privs):
        if p in tgt_privs:
            yield Check(phase, Severity.PASS, f'{name}: privilege {p}')
        elif (p or '').lower() in skip_privs:
            yield Check(phase, Severity.SKIP,
                        f'{name}: privilege {p} not applied on target '
                        f'(structure SKIP recorded: target edition does '
                        f'not support this privilege)')
        else:
            yield Check(phase, Severity.FAIL, f'{name}: privilege {p} MISSING on target')
    for p in sorted(tgt_privs - src_privs):
        yield Check(phase, Severity.WARN, f'{name}: privilege {p} EXTRA on target')
    if src_mn.get('cascade', False) != tgt_mn.get('cascade', False):
        yield Check(phase, Severity.FAIL,
                    f'{name}: cascade mismatch src={src_mn.get("cascade", False)} '
                    f'target={tgt_mn.get("cascade", False)}')


def _diagnose_password_complexity_diff(sv, tv):
    """Bug 78 — when `generated_password_complexity` source/target
    values differ, classify the diff so verify can emit a specific
    Bug-78 message instead of the generic `expected/actual` text.

    Returns a tuple `(category, summary)`:
      - ('multi_domain_truncation', '<n_src> rules → <n_tgt> rules')
        when source has more rules than target (the canonical Bug 78
        write-side symptom — Commander only ingests the first list
        element).
      - ('length_mutation', 'rule[0] length: <src> → <tgt>') when
        source and target have the same rule count but the first
        rule's `length` value differs (the secondary Bug 78 symptom
        — Commander applies a default length when the inbound payload
        partially parses).
      - ('value_diff', '<short>') for any other value difference —
        falls back to a normalized inline summary so verify still
        emits a useful message.
      - (None, None) when either side isn't parseable as JSON.
    """
    if not isinstance(sv, str) or not isinstance(tv, str):
        return None, None
    import json as _json
    try:
        s = _json.loads(sv)
        t = _json.loads(tv)
    except (TypeError, ValueError):
        return None, None
    if not isinstance(s, list) or not isinstance(t, list):
        return None, None
    if len(s) > len(t):
        return ('multi_domain_truncation',
                f'source has {len(s)} complexity rule(s); '
                f'target has {len(t)} (truncation — only the first '
                f'rule landed)')
    if len(s) == len(t) and s and t:
        s0_len = (s[0] or {}).get('length')
        t0_len = (t[0] or {}).get('length')
        if s0_len is not None and t0_len is not None and s0_len != t0_len:
            return ('length_mutation',
                    f'rule[0] length src={s0_len} target={t0_len}')
    return ('value_diff',
            f'src list[{len(s)}] != target list[{len(t)}]')


def _compare_role_enforcements(phase, name, src_enfs, tgt_enfs,
                               ent_id_to_name=None,
                               structure_skipped_enforcements=None):
    for key in sorted(src_enfs or {}):
        raw_sv = src_enfs[key]
        sv = _normalize_bool(raw_sv)
        tv = tgt_enfs.get(key)
        if tv is None:
            # Bug 76.1 — `false` on a BOOLEAN enforcement is canonically
            # absent on target: enforcement_direct._build_request maps
            # False → role_enforcement_remove, which is a no-op against a
            # role that didn't carry the key. Source `false` matched by
            # absent target is the correct round-trip.
            if raw_sv is False or sv == 'false':
                yield Check(phase, Severity.PASS,
                            f'{name}: enforcement {key}=false (canonical absent on target)')
                continue
            # Bug 84 (v1.7.2) — empty-string source value is also
            # canonical-absent: `--enforcement KEY:` (empty) is
            # interpreted by Commander as "remove the enforcement"
            # (a no-op against an absent target key). Common for
            # JSON-typed enforcements like `generated_password_complexity`
            # / `master_password_reentry` / `two_factor_by_ip` when
            # source had the key emit-but-empty (operator created the
            # role but never configured the rule). Source empty value
            # matched by absent target is the correct round-trip.
            if raw_sv == '' or (isinstance(raw_sv, str) and not raw_sv.strip()):
                yield Check(phase, Severity.PASS,
                            f'{name}: enforcement {key} '
                            f'(empty source value; canonical absent '
                            f'on target)')
                continue
            # Bug 76.2 / v1.7 — every key in `LOCKOUT_RISK_ENFORCEMENTS`
            # legitimately ends up absent on target via multiple
            # structure-time SKIP paths:
            #  - `require_account_share`: Bug 47 self-reference, Bug 64
            #    missing TRANSFER_ACCOUNT, Bug 51 cross-tenant rejection,
            #    or unresolved role_id.
            #  - All four (incl. `restrict_ip_addresses`,
            #    `master_password_reentry`, `two_factor_by_ip`): v1.7
            #    structure-side default-skip on builtin-admin roles.
            # Verify reports SKIP with operator-handoff guidance instead
            # of FAIL so a clean rehearsal isn't muddied by intentional
            # structure-time skips. The 2026-04-26 `jlima+demo2` lockout
            # incident is the worked example for why this enforcement
            # class warrants conservative cross-tenant handling.
            if key in LOCKOUT_RISK_ENFORCEMENTS:
                # v1.7 / T2.2 — consult structure-time audit for the
                # specific reason if present. A matching `(role, key)`
                # row says "structure intentionally SKIPped this" and
                # the verify message can quote the exact reason. No
                # match means the absence wasn't recorded by structure
                # — could be a write-path regression or a pre-v1.7
                # artifact dir without per-key SKIP rows. In either
                # case, still SKIP (lockout-risk safety stays the
                # same), but tag the message so the operator knows.
                skip_map = structure_skipped_enforcements or {}
                exact = skip_map.get((name, key))
                if exact:
                    detail = f'structure SKIP recorded: {exact}'
                else:
                    detail = ('no structure-stage SKIP recorded — '
                              'check structure_results.csv or pre-v1.7 '
                              'artifact dir')
                yield Check(phase, Severity.SKIP,
                            f'{name}: enforcement {key} not applied on target '
                            f'(lockout-risk; {detail}; apply manually '
                            f'post-migration after auditing target-tenant '
                            f'compatibility)')
                continue
            yield Check(phase, Severity.FAIL,
                        f'{name}: enforcement {key} MISSING on target (expected={sv})')
            continue
        tv_s = _normalize_bool(tv)
        # Bug 77 — `restrict_record_types` captures in different shapes
        # across tenants (source: portable name-string post-Bug-60;
        # target: `{"std":[..],"ent":[..]}` JSON). Both shapes flatten
        # to a name-set; compare those rather than raw strings.
        if key == 'restrict_record_types':
            s_set = _restrict_record_types_to_name_set(sv)
            t_set = _restrict_record_types_to_name_set(tv_s, ent_id_to_name)
            if s_set is not None and t_set is not None:
                if s_set == t_set:
                    yield Check(phase, Severity.PASS,
                                f'{name}: enforcement {key} types={len(s_set)} match')
                    continue
                missing = sorted(s_set - t_set)
                extra = sorted(t_set - s_set)
                detail_bits = []
                if missing:
                    detail_bits.append(f'missing={missing}')
                if extra:
                    detail_bits.append(f'extra={extra}')
                yield Check(phase, Severity.FAIL,
                            f'{name}: enforcement {key} type-set diff '
                            f'({"; ".join(detail_bits)})')
                continue
        if key == 'require_account_share' and sv != tv_s:
            # role_id values differ across tenants by design — resolved by
            # structure-restore to point at the same role NAME on target.
            yield Check(phase, Severity.PASS,
                        f'{name}: enforcement {key} role IDs differ cross-tenant '
                        f'(expected if structure-restore succeeded)')
        elif sv == tv_s:
            yield Check(phase, Severity.PASS, f'{name}: enforcement {key}={sv}')
        elif key == 'generated_password_complexity':
            # Bug 78 — multi-domain truncation. Diagnose specifically
            # so the operator gets actionable guidance instead of a
            # raw value diff. The write-path fix (split into N CLI
            # calls or upstream Commander patch) is staged as v1.7.x
            # — for now, verify surfaces the symptom unambiguously.
            category, summary = _diagnose_password_complexity_diff(sv, tv_s)
            if category == 'multi_domain_truncation':
                yield Check(phase, Severity.FAIL,
                            f'{name}: enforcement {key} multi-domain '
                            f'truncation (Bug 78) — {summary}; remaining '
                            f'rules must be applied manually post-'
                            f'migration via Keeper Admin Console')
            elif category == 'length_mutation':
                yield Check(phase, Severity.FAIL,
                            f'{name}: enforcement {key} length-mutation '
                            f'(Bug 78) — {summary}; review and re-apply '
                            f'manually if intended')
            elif category == 'value_diff':
                yield Check(phase, Severity.FAIL,
                            f'{name}: enforcement {key} value diff '
                            f'({summary})')
            else:
                # Both sides non-parseable — fall back to generic.
                yield Check(phase, Severity.FAIL,
                            f'{name}: enforcement {key} expected={sv} actual={tv_s}')
        else:
            yield Check(phase, Severity.FAIL,
                        f'{name}: enforcement {key} expected={sv} actual={tv_s}')
    extras = sorted(set(tgt_enfs or {}).difference(src_enfs or {}))
    for key in extras:
        yield Check(phase, Severity.WARN, f'{name}: enforcement {key} EXTRA on target')


def phase_roles(ctx):
    """Compare roles field-by-field. Matches Phase 4 of test_full_spectrum.sh."""
    source = ctx.source_entities('roles')
    target_by_name = {r.get('name', ''): r for r in ctx.target_entities('roles')}
    if not source:
        yield Check('roles', Severity.SKIP, 'No source roles in inventory')
        return

    # Bug 77 — build target's enterprise-record-type id→name map once so
    # `restrict_record_types` comparison can resolve `ent` IDs back to
    # names. Standard types use the stable-UID table; custom enterprise
    # types only resolve when target_state captured the record_types
    # snapshot (capture-target-state v1.6.0+).
    ent_id_to_name = {}
    for rt in ctx.target_state.get('record_types', []) or []:
        if isinstance(rt, dict):
            rid = rt.get('id') or rt.get('record_type_id')
            content = rt.get('content') or {}
            rname = (content.get('$id') if isinstance(content, dict) else None) \
                    or rt.get('name')
            if rid is not None and rname:
                ent_id_to_name[rid] = rname

    for role in source:
        name = role.get('name', '')
        if not name:
            continue
        # Bug 61 — resolve through rename_map: source roles whose names
        # collide across nodes get a node-suffix appended on target.
        target_name = ctx.target_name_for('roles', name, role.get('node', ''))
        t = target_by_name.get(target_name)
        if not t:
            yield Check('roles', Severity.FAIL, f'Role {name}: NOT FOUND on target')
            continue
        yield Check('roles', Severity.PASS, f'Role {name}: exists on target')

        src_mn = role.get('managed_nodes', []) or []
        tgt_mn = t.get('managed_nodes', []) or []
        bare_for_msp = name.replace(' (Migrated)', '')
        if len(src_mn) != len(tgt_mn):
            # Bug 81 — MSP-edition target tenants auto-bind managed_nodes
            # to specific roles (e.g. `MSP Subscription Manager` gets
            # bound to MSP root automatically by Commander). Source
            # has no equivalent. Verify can't predict tenant-edition
            # auto-bindings — downgrade to WARN with explanation.
            if (bare_for_msp in MSP_AUTO_PROVISIONED_ROLES
                    and len(tgt_mn) > len(src_mn)):
                yield Check('roles', Severity.WARN,
                            f'{name}: managed_nodes count '
                            f'expected={len(src_mn)} actual={len(tgt_mn)} '
                            f'(MSP-edition auto-provisioned binding; '
                            f'tenant-shape difference)')
            else:
                yield Check('roles', Severity.FAIL,
                            f'{name}: managed_nodes count expected={len(src_mn)} actual={len(tgt_mn)}')
        else:
            yield Check('roles', Severity.PASS,
                        f'{name}: managed_nodes count={len(src_mn)}')

        # Bug 78 derivative — per-(role, priv) skip set keyed by
        # target-side role name (structure_results.csv rows are
        # written under the post-rename name); fall back to source
        # name for the common no-rename case.
        priv_skip_set = ctx.structure_skipped_privileges_set or set()
        role_skipped_privs = {priv for (rn, priv) in priv_skip_set
                              if rn in (target_name, name)}
        for i, smn in enumerate(src_mn):
            tmn = tgt_mn[i] if i < len(tgt_mn) else {}
            yield from _compare_role_privileges('roles', name, smn, tmn,
                                                 skip_privs=role_skipped_privs)

        yield from _compare_role_enforcements('roles', name,
                                              role.get('enforcements', {}) or {},
                                              t.get('enforcements', {}) or {},
                                              structure_skipped_enforcements=(
                                                  ctx.structure_skipped_enforcements),
                                              ent_id_to_name=ent_id_to_name)

        if bool(role.get('default_role', False)) != bool(t.get('default_role', False)):
            yield Check('roles', Severity.FAIL,
                        f'{name}: default_role src={role.get("default_role", False)} '
                        f'target={t.get("default_role", False)}')
        else:
            yield Check('roles', Severity.PASS,
                        f'{name}: default_role={role.get("default_role", False)}')

        src_team_names = _names_of(role.get('teams', []))
        tgt_team_names = _names_of(t.get('teams', []))
        for team in sorted(src_team_names):
            if team in tgt_team_names:
                yield Check('roles', Severity.PASS, f'{name}: team {team} assigned')
            else:
                yield Check('roles', Severity.FAIL,
                            f'{name}: team {team} MISSING on target')

        # Role-level count parity — same consistency guarantee as per-record.
        # managed_nodes/privileges/enforcements/team count is a FAIL when
        # they diverge; user-count is a WARN since invitation state moves.
        def _role_counts(r):
            mn = r.get('managed_nodes', []) or []
            return {
                'managed_nodes': len(mn),
                'privileges': sum(len(m.get('privileges', []) or []) for m in mn),
                'enforcements': len(r.get('enforcements', {}) or {}),
                'teams': len(r.get('teams', []) or []),
                'users': len(r.get('users', []) or []),
            }
        src_counts = _role_counts(role)
        tgt_counts = _role_counts(t)

        # Bug 79 — subtract structure-time SKIPs + canonical-absent
        # values from src counts before comparing. Two sources of
        # legitimate target-side reduction:
        #  (a) structure_results.csv `enforcement classify-skip` rows
        #      (Bug 47 self-ref / Bug 64 missing TRANSFER_ACCOUNT /
        #      Bug 51 cross-tenant rejection / v1.7 lockout-risk
        #      default-skip on builtin-admin) — adjust regardless of
        #      what's on target, since structure refused to write.
        #  (b) Bug 76.1 canonical-absent — `false` boolean enforcements
        #      legitimately absent on target (enforcement_direct maps
        #      False→role_enforcement_remove, no-op against absent key)
        #      — only adjust when target actually lacks the key. If
        #      target has it (e.g. test mirror, manual config),
        #      counts match without adjustment.
        # Same pattern for privileges via
        # `structure_skipped_privileges` (target-edition-unsupported).
        src_enfs_dict = role.get('enforcements', {}) or {}
        tgt_enfs_dict = t.get('enforcements', {}) or {}
        skip_map = ctx.structure_skipped_enforcements or {}
        priv_skipped_map = ctx.structure_skipped_privileges or {}
        # Bug 78 — structure_results.csv rows are emitted under the
        # TARGET role name (post-rename, e.g. 'Keeper Administrator
        # (Migrated)'). Verify iterates source roles, so query the skip
        # maps by `target_name` first, with `name` as fallback for the
        # common case where source and target names match.
        enf_skipped = sum(1 for k in src_enfs_dict
                          if (target_name, k) in skip_map
                          or (name, k) in skip_map)
        # Bug 76.1 + Bug 84 — canonical-absent: `false` boolean and
        # empty-string source values are no-ops at write time and
        # legitimately absent on target.
        enf_canonical_absent = sum(
            1 for k, v in src_enfs_dict.items()
            if (v is False or _normalize_bool(v) == 'false'
                or v == ''
                or (isinstance(v, str) and not v.strip()))
            and k not in tgt_enfs_dict)
        priv_skipped = (priv_skipped_map.get(target_name)
                        or priv_skipped_map.get(name, 0))
        adjustments = {
            'enforcements': enf_skipped + enf_canonical_absent,
            'privileges': priv_skipped,
            'managed_nodes': 0,
            'teams': 0,
        }
        # `managed_nodes` count is already checked above (line ~630)
        # with the Bug-81 MSP-edition carve-out; iterate the other
        # categories here to avoid emitting duplicate count checks.
        for key in ('privileges', 'enforcements', 'teams'):
            adj = adjustments.get(key, 0)
            effective_src = src_counts[key] - adj
            if effective_src != tgt_counts[key]:
                detail = (f' (adjusted: -{adj} structure-time SKIP/'
                          f'canonical-absent)' if adj else '')
                # Bug 81 — same MSP-edition allowlist applies to
                # privileges (auto-bound roles get auto-privileges).
                bare = name.replace(' (Migrated)', '')
                if (key == 'privileges'
                        and bare in MSP_AUTO_PROVISIONED_ROLES
                        and tgt_counts[key] > effective_src):
                    yield Check('roles', Severity.WARN,
                                f'{name}: {key} count src={src_counts[key]} '
                                f'target={tgt_counts[key]} (MSP-edition '
                                f'auto-provisioned binding; tenant-shape '
                                f'difference, not migration drift)')
                    continue
                yield Check('roles', Severity.FAIL,
                            f'{name}: {key} count src={src_counts[key]} '
                            f'target={tgt_counts[key]}{detail}')
        if src_counts['users'] != tgt_counts['users']:
            yield Check('roles', Severity.WARN,
                        f'{name}: users count src={src_counts["users"]} '
                        f'target={tgt_counts["users"]} (invite acceptance lag expected)')

        # Bug 44 — node placement + visible_below. Same WARN-on-leaf-
        # mismatch policy as phase_teams (cross-tenant root remap is
        # legitimate). visible_below is a hard FAIL — flipping it
        # silently breaks scope-down enforcement on target.
        src_node = (role.get('node') or '').strip()
        tgt_node = (t.get('node') or '').strip()
        if src_node and tgt_node:
            src_leaf = src_node.rsplit('\\', 1)[-1]
            tgt_leaf = tgt_node.rsplit('\\', 1)[-1]
            if src_leaf != tgt_leaf:
                yield Check('roles', Severity.WARN,
                            f'{name}: node leaf src={src_leaf!r} '
                            f'target={tgt_leaf!r}')
            else:
                yield Check('roles', Severity.PASS,
                            f'{name}: node leaf={src_leaf}')

        if 'visible_below' in role and 'visible_below' in t:
            src_vb = bool(role.get('visible_below', False))
            tgt_vb = bool(t.get('visible_below', False))
            if src_vb != tgt_vb:
                yield Check('roles', Severity.FAIL,
                            f'{name}: visible_below src={src_vb} '
                            f'target={tgt_vb}')
            else:
                yield Check('roles', Severity.PASS,
                            f'{name}: visible_below={src_vb}')


# ─── Phase 5: shared folders — existence + default permission flags ─────────


_SF_USER_PERM_FLAGS = ('manage_users', 'manage_records', 'can_edit', 'can_share')
_SF_TEAM_PERM_FLAGS = ('manage_users', 'manage_records')


def _index_sf_users(users):
    """Build {username_lower: perm_dict} for a shared-folder's user list."""
    out = {}
    for u in users or []:
        if isinstance(u, dict):
            key = (u.get('username') or u.get('email') or '').strip().lower()
            if key:
                out[key] = u
    return out


def _index_sf_teams(teams):
    out = {}
    for t in teams or []:
        if isinstance(t, dict):
            key = (t.get('name') or t.get('team_name') or '').strip()
            if key:
                out[key] = t
    return out


def phase_shared_folders(ctx):
    source = ctx.source_entities('shared_folders')
    # Bug 65 — index target SFs by both verbatim name AND stripped
    # name. Source captures often carry trailing whitespace that the
    # structure stage strips at create time (Bug 55). Pre-fix verify
    # was looking up the un-stripped source name in target's stripped-
    # name dict → false NOT FOUND on every whitespace-padded SF.
    target_entries = ctx.target_entities('shared_folders')
    target_by_name = {s.get('name', ''): s for s in target_entries}
    target_by_stripped = {(s.get('name', '') or '').strip(): s
                          for s in target_entries
                          if s.get('name', '')}
    if not source:
        yield Check('shared_folders', Severity.SKIP, 'No source shared folders')
        return

    for sf in source:
        name = sf.get('name', '')
        if not name:
            continue
        t = target_by_name.get(name) or target_by_stripped.get(name.strip())
        if not t:
            yield Check('shared_folders', Severity.FAIL,
                        f'SF {name}: NOT FOUND on target')
            continue
        yield Check('shared_folders', Severity.PASS, f'SF {name}: exists')
        for flag in ('default_manage_users', 'default_manage_records',
                     'default_can_edit', 'default_can_share'):
            sv = sf.get(flag)
            tv = t.get(flag)
            if sv is None and tv is None:
                continue
            if bool(sv) != bool(tv):
                yield Check('shared_folders', Severity.WARN,
                            f'SF {name}: {flag} src={sv} target={tv}')

        # Per-user permission diff
        src_users = _index_sf_users(sf.get('users'))
        tgt_users = _index_sf_users(t.get('users'))
        for user_email, sperm in sorted(src_users.items()):
            tperm = tgt_users.get(user_email)
            if not tperm:
                yield Check('shared_folders', Severity.WARN,
                            f'SF {name}: user {user_email} MISSING on target')
                continue
            for flag in _SF_USER_PERM_FLAGS:
                sv = bool(sperm.get(flag, False))
                tv = bool(tperm.get(flag, False))
                if sv != tv:
                    yield Check('shared_folders', Severity.WARN,
                                f'SF {name}: {user_email} {flag} '
                                f'src={sv} target={tv}')
        extra = sorted(set(tgt_users) - set(src_users))
        for user_email in extra:
            yield Check('shared_folders', Severity.WARN,
                        f'SF {name}: user {user_email} EXTRA on target')

        # Per-team permission diff
        src_teams = _index_sf_teams(sf.get('teams'))
        tgt_teams = _index_sf_teams(t.get('teams'))
        for team_name, sperm in sorted(src_teams.items()):
            tperm = tgt_teams.get(team_name)
            if not tperm:
                yield Check('shared_folders', Severity.WARN,
                            f'SF {name}: team {team_name} MISSING on target')
                continue
            for flag in _SF_TEAM_PERM_FLAGS:
                sv = bool(sperm.get(flag, False))
                tv = bool(tperm.get(flag, False))
                if sv != tv:
                    yield Check('shared_folders', Severity.WARN,
                                f'SF {name}: team {team_name} {flag} '
                                f'src={sv} target={tv}')


# ─── Phase 6: records — existence by title + attachment/share counts ────────


_FIELD_LEVEL_KEYS = ('login', 'password', 'login_url', 'notes', 'totp_secret')


def _compare_field(title, key, src_val, tgt_val):
    if (src_val or '') == (tgt_val or ''):
        return Check('records', Severity.PASS, f'"{title}": {key} matches')
    return Check('records', Severity.FAIL,
                 f'"{title}": {key} mismatch (source != target)')


def _compare_custom_fields(title, src_cf, tgt_cf):
    src_cf = src_cf or {}
    tgt_cf = tgt_cf or {}
    for label in sorted(src_cf):
        sv = src_cf[label]
        tv = tgt_cf.get(label)
        if tv is None:
            yield Check('records', Severity.FAIL,
                        f'"{title}": custom field "{label}" MISSING on target')
        elif sv == tv:
            yield Check('records', Severity.PASS,
                        f'"{title}": custom field "{label}" matches')
        else:
            yield Check('records', Severity.FAIL,
                        f'"{title}": custom field "{label}" mismatch')
    for label in sorted(set(tgt_cf).difference(src_cf)):
        yield Check('records', Severity.WARN,
                    f'"{title}": custom field "{label}" EXTRA on target')


def phase_records(ctx):
    source = ctx.source_entities('records')
    target = ctx.target_entities('records')
    if not source:
        yield Check('records', Severity.SKIP, 'No source records')
        return
    # Bug 86 (v1.7.4) — pair source records to target through
    # `manifest.csv`'s source_uid → target_uid map. Title-based
    # pairing alone misaligns when source has duplicate titles
    # (e.g. two `Debug-Test` records, one `pamMachine` + one
    # `login`); pre-fix verify reported false-positive type
    # divergence as "Bug 34 (pre-v1.3.3 convert)" when in reality
    # the migration was correct but verify paired source[0]
    # against the wrong target. Manifest is the authoritative
    # source-of-truth: records-import wrote it as it created each
    # target record, so source_uid → target_uid is exact.
    manifest_path = (ctx.target_state or {}).get('_manifest_path', '')
    src_uid_to_tgt_uid = _load_manifest_uid_map(manifest_path)
    target_by_uid = {r.get('record_uid', ''): r for r in target
                     if r.get('record_uid')}
    target_by_title = {r.get('title', ''): r for r in target}
    for rec in source:
        title = rec.get('title', '')
        if not title:
            continue
        # Pair via manifest first, fall back to title for older
        # runs (pre-Bug-86 verify) and for source records absent
        # from the manifest (e.g. records-import dropped them —
        # which is itself a real failure to surface).
        src_uid = rec.get('uid') or ''
        tgt_uid = src_uid_to_tgt_uid.get(src_uid)
        t = (target_by_uid.get(tgt_uid) if tgt_uid else None) or \
            target_by_title.get(title)
        if not t:
            yield Check('records', Severity.FAIL, f'Record "{title}" NOT FOUND on target')
            continue
        yield Check('records', Severity.PASS, f'Record "{title}" exists on target')

        # Bug 41 — type-fidelity check. Pre-Bug-34, every non-login
        # record landed on target as `login` because convert emitted
        # `type` instead of `$type`. Bug 86 — manifest-aware pairing
        # makes the type comparison meaningful: false-positive type
        # divergence used to fire when verify mis-paired duplicate-
        # title source records to the wrong target.
        src_type = rec.get('type')
        tgt_type = t.get('type')
        if src_type and tgt_type and src_type != tgt_type:
            # Only attribute to Bug 34 when target is `login` (the
            # symptom of the convert bug — every non-login record
            # collapsed to `login` because `$type` was missing).
            if tgt_type == 'login':
                detail = (' (Bug 34 — pre-v1.3.3 convert emitted '
                          '`type` not `$type`)')
            else:
                detail = ''
            yield Check('records', Severity.FAIL,
                        f'"{title}": type src={src_type!r} '
                        f'target={tgt_type!r}{detail}')
        elif src_type and tgt_type:
            yield Check('records', Severity.PASS,
                        f'"{title}": type={src_type}')

        # Count-parity checks (consistency guarantee):
        #   FAIL on field-count mismatch — that's lost data.
        #   WARN on attachment/share drift — may legitimately differ
        #     across tenants (e.g., size-quota rejection).
        for key, severity in (
            ('standard_field_count', Severity.FAIL),
            ('custom_field_count',   Severity.FAIL),
            ('total_field_count',    Severity.FAIL),
        ):
            s = rec.get(key)
            tgt = t.get(key)
            # Skip when either side omits the count (older inventory format).
            if s is None or tgt is None:
                continue
            if s != tgt:
                yield Check('records', severity,
                            f'"{title}": {key} src={s} target={tgt}')
            else:
                yield Check('records', Severity.PASS,
                            f'"{title}": {key}={s}')
        sac = rec.get('attachment_count', 0)
        tac = t.get('attachment_count', 0)
        if sac != tac:
            yield Check('records', Severity.WARN,
                        f'"{title}": attachment_count src={sac} target={tac}')
        sds = len(rec.get('direct_shares', []) or [])
        tds = len(t.get('direct_shares', []) or [])
        if sds != tds:
            yield Check('records', Severity.WARN,
                        f'"{title}": direct_shares count src={sds} target={tds}')
        if rec.get('has_totp') != t.get('has_totp'):
            yield Check('records', Severity.WARN,
                        f'"{title}": has_totp src={rec.get("has_totp")} '
                        f'target={t.get("has_totp")}')

        # Field-level comparison when both sides captured full data (--include-fields).
        if any(k in rec for k in _FIELD_LEVEL_KEYS) and any(k in t for k in _FIELD_LEVEL_KEYS):
            for key in _FIELD_LEVEL_KEYS:
                yield _compare_field(title, key, rec.get(key), t.get(key))
            yield from _compare_custom_fields(title,
                                               rec.get('custom_fields'),
                                               t.get('custom_fields'))


# ─── Phase 7: record types — custom type names carry across ─────────────────


def phase_record_types(ctx):
    src_types = {rt.get('content', {}).get('$id', rt.get('name', ''))
                 for rt in ctx.inventory.get('record_types', []) or []
                 if isinstance(rt, dict)}
    tgt_types = {rt.get('content', {}).get('$id', rt.get('name', ''))
                 for rt in ctx.target_state.get('record_types', []) or []
                 if isinstance(rt, dict)}
    if not src_types:
        yield Check('record_types', Severity.SKIP, 'No source record types captured')
        return
    for rt in sorted(src_types):
        if rt in tgt_types:
            yield Check('record_types', Severity.PASS, f'Record type {rt}: present on target')
        else:
            yield Check('record_types', Severity.FAIL, f'Record type {rt}: MISSING on target')


# ─── Phase 7b: per-user verification ────────────────────────────────────────


_USER_PENDING_STATUSES = {'invited', 'pending', 'transfer_pending'}


def _user_email(u):
    return (u.get('email') or u.get('username') or '').strip().lower()


def phase_users(ctx):
    """Compare users between source inventory and target enterprise state.

    Bug 42 — pre-fix verify had no per-user phase, so user-migration drift
    (missing emails, unattached team/role memberships, HSF settings that
    didn't apply) went unchecked on every migration. The mid-migration
    invitation lifecycle means we can't FAIL on every status mismatch —
    `invited` and `pending` are expected mid-flight; FAIL is reserved for
    "source user is missing entirely on target".

    Severity policy:
      - FAIL: source user not found on target (any matching alias counts).
      - WARN: target has the user but status is invited/pending (mid-flight).
      - WARN: extra users on target (may be pre-existing tenant residents).
      - WARN: node mismatch (cross-tenant remap can produce legit divergence).
      - PASS: team/role membership match (set comparison).
    """
    source = ctx.source_entities('users')
    if not source:
        yield Check('users', Severity.SKIP, 'No source users in inventory')
        return

    target = ctx.target_entities('users') or []
    target_by_email = {_user_email(u): u for u in target if _user_email(u)}
    matched_target_emails = set()

    for u in source:
        email = _user_email(u)
        if not email:
            continue
        # Aliases let us follow a rename across tenants. Source projection
        # carries `aliases` (list); target projection currently doesn't, so
        # this is forward-compatible only.
        candidates = [email] + [a.lower() for a in (u.get('aliases') or []) if a]
        t = None
        for cand in candidates:
            if cand in target_by_email:
                t = target_by_email[cand]
                matched_target_emails.add(cand)
                break

        if t is None:
            # 2026-05-06 — auto-migrate's users stage is default-SKIP
            # (sends real invitations). When the operator hasn't yet
            # run `tenant-migrate users --roster <csv>`, source users
            # legitimately don't exist on target. Emit SKIP with
            # operator-facing guidance instead of a misleading FAIL.
            if ctx.users_stage_status == 'skipped':
                yield Check('users', Severity.SKIP,
                            f'User {email}: not yet invited to target '
                            f'(auto-migrate users stage is default-SKIP; '
                            f'run `tenant-migrate users --roster <csv>` '
                            f'to invite)')
            else:
                yield Check('users', Severity.FAIL,
                            f'User {email}: NOT FOUND on target')
            continue

        # Status: invited/pending is expected mid-migration, WARN not FAIL.
        t_status = (t.get('status') or '').strip().lower()
        if t_status in _USER_PENDING_STATUSES:
            yield Check('users', Severity.WARN,
                        f'{email}: target status={t_status or "unknown"} (acceptance pending)')
        else:
            yield Check('users', Severity.PASS,
                        f'{email}: status={t_status or "active"}')

        # Node placement — cross-tenant remap can produce legit different
        # paths (My company\X -> Keeperdemo\X). WARN on mismatch.
        src_node = (u.get('node') or '').strip()
        tgt_node = (t.get('node') or '').strip()
        if src_node and tgt_node:
            # Compare leaf-name only; tolerates root-name remap.
            src_leaf = src_node.rsplit('\\', 1)[-1]
            tgt_leaf = tgt_node.rsplit('\\', 1)[-1]
            if src_leaf != tgt_leaf:
                yield Check('users', Severity.WARN,
                            f'{email}: node leaf src={src_leaf!r} target={tgt_leaf!r}')
            else:
                yield Check('users', Severity.PASS, f'{email}: node leaf={src_leaf}')

        # Team membership — set comparison.
        src_teams = set(u.get('teams') or [])
        tgt_teams = set(t.get('teams') or [])
        for missing in sorted(src_teams - tgt_teams):
            yield Check('users', Severity.FAIL,
                        f'{email}: team {missing} MISSING on target')
        if src_teams and src_teams.issubset(tgt_teams):
            yield Check('users', Severity.PASS,
                        f'{email}: teams={sorted(src_teams)}')

        # Role membership — set comparison.
        src_roles = set(u.get('roles') or [])
        tgt_roles = set(t.get('roles') or [])
        for missing in sorted(src_roles - tgt_roles):
            yield Check('users', Severity.FAIL,
                        f'{email}: role {missing} MISSING on target')
        if src_roles and src_roles.issubset(tgt_roles):
            yield Check('users', Severity.PASS,
                        f'{email}: roles={sorted(src_roles)}')

    # Extra users on target — WARN. Common when target tenant pre-existed
    # with its own admin or when re-running into a non-empty tenant.
    extras = sorted(e for e in target_by_email if e not in matched_target_emails)
    for e in extras:
        yield Check('users', Severity.WARN, f'EXTRA on target: {e}')


# ─── Phase 8: target vault health ────────────────────────────────────────────


def phase_vault_health(ctx):
    """Report ownerless records, duplicates, and shared-folder integrity on target.

    Runs Commander's diagnostic commands (find-ownerless, find-duplicate --full,
    verify-shared-folders --dry-run) with stdout captured and emits WARN checks
    for anything non-zero. Requires a live `params` object in the context;
    without one, this phase SKIPs cleanly (offline verify stays functional).
    """
    params = getattr(ctx, 'params', None)
    if params is None:
        yield Check('vault_health', Severity.SKIP,
                    'No live params — offline verify')
        return

    # 1. Ownerless records
    try:
        import contextlib
        import io
        from keepercommander.commands.register import FindOwnerlessCommand
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            FindOwnerlessCommand().execute(params, format='json')
        out = buf.getvalue().strip() or '[]'
        import json as _json
        try:
            data = _json.loads(out)
            count = len(data) if isinstance(data, list) else 0
        except _json.JSONDecodeError:
            count = 0
        if count == 0:
            yield Check('vault_health', Severity.PASS, 'No ownerless records')
        else:
            yield Check('vault_health', Severity.WARN,
                        f'{count} ownerless record(s) — run find-ownerless --claim')
    except Exception as e:                             # noqa: BLE001
        yield Check('vault_health', Severity.SKIP,
                    f'find-ownerless unavailable: {type(e).__name__}')

    # 2. Duplicates
    try:
        from keepercommander.commands.register import FindDuplicateCommand
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            FindDuplicateCommand().execute(params, full=True)
        out = buf.getvalue()
        dup_count = out.lower().count('duplicate')
        if dup_count == 0:
            yield Check('vault_health', Severity.PASS, 'No duplicate records')
        else:
            yield Check('vault_health', Severity.WARN,
                        f'{dup_count} potential duplicate(s) — run find-duplicate --full --dry-run')
    except Exception as e:                             # noqa: BLE001
        yield Check('vault_health', Severity.SKIP,
                    f'find-duplicate unavailable: {type(e).__name__}')

    # 3. Shared folder integrity
    try:
        from keepercommander.commands.verify_records import (
            VerifySharedFoldersCommand,
        )
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            VerifySharedFoldersCommand().execute(params, dry_run=True)
        out = buf.getvalue().lower()
        issues = sum(out.count(marker) for marker in ('issue', 'error', 'fix'))
        if issues == 0:
            yield Check('vault_health', Severity.PASS,
                        'Shared folder integrity OK')
        else:
            yield Check('vault_health', Severity.WARN,
                        f'Shared folder integrity: {issues} potential issue(s)')
    except Exception as e:                             # noqa: BLE001
        yield Check('vault_health', Severity.SKIP,
                    f'verify-shared-folders unavailable: {type(e).__name__}')


# ─── Phase 9: entity-count comparison (aggregate) ───────────────────────────


def phase_entity_counts(ctx):
    """Compare high-level counts against the frozen inventory."""
    expected = ctx.inventory.get('counts', {}) or {}
    observed = {
        'nodes': len(ctx.target_entities('nodes')),
        'teams': len(ctx.target_entities('teams')),
        'roles': len(ctx.target_entities('roles')),
        'shared_folders': len(ctx.target_entities('shared_folders')),
        # Bug 42 — entity_counts now also covers users so a silently-dropped
        # invite (or an extra resident on target) shows up at the aggregate
        # level even if the per-user phase SKIPped on a stub inventory.
        'users': len(ctx.target_entities('users')),
    }
    for k, obs in observed.items():
        exp = expected.get(k)
        if exp is None:
            yield Check('counts', Severity.SKIP, f'{k}: no expected count')
            continue
        if obs == exp:
            yield Check('counts', Severity.PASS, f'{k}: {obs}/{exp}')
        elif obs > exp:
            yield Check('counts', Severity.WARN,
                        f'{k}: target has MORE ({obs} > {exp} source)')
        else:
            # Bug 82 derivative — users count drift is expected when
            # the operator hasn't yet run `tenant-migrate users
            # --roster <csv>`. Match phase_users severity calibration:
            # SKIP with operator-facing guidance instead of FAIL when
            # we can detect the auto-migrate users-stage-default-SKIP
            # state.
            if k == 'users' and ctx.users_stage_status == 'skipped':
                yield Check('counts', Severity.SKIP,
                            f'{k}: target has FEWER ({obs} < {exp} '
                            f'source) — users stage default-SKIP; run '
                            f'`tenant-migrate users --roster <csv>` '
                            f'to invite')
            else:
                yield Check('counts', Severity.FAIL,
                            f'{k}: target has FEWER ({obs} < {exp} source)')


def phase_skip_audit(ctx):
    # Bug 63 — surface skip_audit.csv unknowns as FAIL (likely new
    # plugin bugs), bug-pending as WARN (will resolve next rehearsal),
    # source-quality as WARN (operator must fix source), and the
    # rest as PASS (categorized + actionable). When skip_audit.csv
    # isn't present (older runs / hand-staged), SKIP the phase.
    skip_audit_path = (ctx.target_state.get('_skip_audit_path')
                       if ctx.target_state else '')
    if not skip_audit_path:
        # Try the conventional location: alongside structure_results.csv
        # which sits next to inventory + target_state.
        for sibling in (ctx.target_state or {}).get('_run_dir_hint', []):
            candidate = f'{sibling}/skip_audit.csv'
            import os as _os
            if _os.path.isfile(candidate):
                skip_audit_path = candidate
                break
    if not skip_audit_path:
        yield Check('skip_audit', Severity.SKIP,
                    'No skip_audit.csv in run-dir — older artifacts or '
                    'structure stage was not run via auto-migrate')
        return
    from .skip_audit import audit_structure_results, summarize_audit
    rows = audit_structure_results(skip_audit_path)
    counts = summarize_audit(rows)
    if counts.get('unknown', 0) > 0:
        yield Check('skip_audit', Severity.FAIL,
                    f'{counts["unknown"]} UNKNOWN SKIP(s) in '
                    f'{skip_audit_path} — likely a new plugin bug; '
                    'investigate before next rehearsal')
    if counts.get('bug-pending', 0) > 0:
        yield Check('skip_audit', Severity.WARN,
                    f'{counts["bug-pending"]} bug-pending SKIP(s) — '
                    'will resolve on next rehearsal after v1.6 fixes')
    if counts.get('source-quality', 0) > 0:
        yield Check('skip_audit', Severity.WARN,
                    f'{counts["source-quality"]} source-quality SKIP(s) — '
                    'operator must fix source data before re-export')
    if counts.get('target-capability', 0) > 0:
        yield Check('skip_audit', Severity.PASS,
                    f'{counts["target-capability"]} target-capability '
                    'SKIP(s) — target plan does not enable these features '
                    '(genuine gap, not a bug)')
    if counts.get('cascade', 0) > 0:
        yield Check('skip_audit', Severity.PASS,
                    f'{counts["cascade"]} cascade SKIP(s) — dependents '
                    'of upstream SKIPs (resolve when parents resolve)')
    if counts.get('by-design', 0) > 0:
        yield Check('skip_audit', Severity.PASS,
                    f'{counts["by-design"]} by-design SKIP(s) — '
                    'expected SKIPs (self-ref, intentional users SKIP)')
    if counts.get('total_skipped', 0) == 0:
        yield Check('skip_audit', Severity.PASS,
                    'Zero SKIPs in structure stage — clean migration')


# Registry of phases the validator will run.
PHASES = [
    phase_pre_flight,
    phase_nodes,
    phase_teams,
    phase_roles,
    phase_shared_folders,
    phase_records,
    phase_record_types,
    phase_users,
    phase_vault_health,
    phase_entity_counts,
    phase_skip_audit,
]


class Validator:
    def __init__(self, ctx):
        self.ctx = ctx

    def run(self):
        checks = []
        for phase in PHASES:
            for c in phase(self.ctx):
                checks.append(c)
        return checks


def summarize(checks):
    counts = {s.value: 0 for s in Severity}
    for c in checks:
        counts[c.severity.value] += 1
    return counts
