"""Enumerate the human actions customers must take around a migration.

Source-of-truth for this list is the bash pipeline + everything we learned
from the migration_scripts/ runbook. Every item here is a thing the tool
CANNOT do automatically — somebody (the admin, the source user, or a
specific target user) has to perform it outside this plugin.

Used by `tenant-migrate dry-run` (and `plan --manual`) to surface:
  - Prerequisite user actions (share MIGRATION-* folder with admin,
    accept REQUIRE_ACCOUNT_SHARE, etc.)
  - Mid-flight actions (accept target-tenant invite so direct shares
    resolve, email-domain mismatch remaps)
  - Post-migration actions (verify data visibility, clean up personal
    Keeper accounts if Category B)

Each action has:
  - `actor`     — 'source_user' / 'target_user' / 'admin'
  - `phase`     — 'prerequisite' / 'during_users' / 'during_shares' /
                  'post_migration'
  - `email`     — optional, who specifically
  - `note`      — plain-English instruction
  - `blocks`    — subcommand(s) that silently skip or fail without this
"""


SOURCE_USER = 'source_user'
TARGET_USER = 'target_user'
ADMIN = 'admin'

PREREQUISITE = 'prerequisite'
DURING_USERS = 'during_users'
DURING_SHARES = 'during_shares'
DURING_OWNERSHIP = 'during_ownership'
POST_MIGRATION = 'post_migration'


def _action(actor, phase, note, *, email='', blocks=()):
    return {
        'actor': actor, 'phase': phase, 'email': email,
        'note': note, 'blocks': list(blocks),
    }


def _direct_share_grantees(records):
    """Return {grantee_email: [record_title, ...]} for every non-owner share."""
    out = {}
    for rec in records or []:
        for share in rec.get('direct_shares') or []:
            email = (share.get('username') or '').strip().lower()
            if not email:
                continue
            out.setdefault(email, []).append(rec.get('title', '<untitled>'))
    return out


def _sf_members(shared_folders):
    """Return {member_email: [sf_name, ...]} across all source shared folders."""
    out = {}
    for sf in shared_folders or []:
        for u in sf.get('users') or []:
            email = (u.get('username') or u.get('email') or '').strip().lower()
            if email:
                out.setdefault(email, []).append(sf.get('name', ''))
    return out


def enumerate_actions(inventory, target_state=None, transition_plan=None):
    """Build the full list of manual actions for this migration.

    inventory       : frozen source inventory dict (from `plan` or
                      `assemble-inventory`)
    target_state    : optional target-state projection (from
                      `capture-target-state`) — lets us flag users who
                      are already present vs missing
    transition_plan : optional list from `transition-check` — narrows
                      per-user actions by category (A/D/E/UNKNOWN/B/C)
    """
    actions = []

    src_users = inventory.get('entities', {}).get('users', []) or []
    src_records = inventory.get('entities', {}).get('records', []) or []
    src_sfs = inventory.get('entities', {}).get('shared_folders', []) or []

    target_users_set = set()
    if target_state:
        for u in target_state.get('users') or []:
            e = (u.get('email') or '').strip().lower()
            if e:
                target_users_set.add(e)

    transition_by_email = {}
    for row in transition_plan or []:
        e = (row.get('source_email') or '').strip().lower()
        if e:
            transition_by_email[e] = (row.get('category') or '').strip().upper()

    # ─── Prerequisite: each source user must share MIGRATION-* with admin
    #     (Path A) OR accept REQUIRE_ACCOUNT_SHARE enforcement (Path B) ──
    for user in src_users:
        email = (user.get('email') or '').strip().lower()
        if not email:
            continue
        actions.append(_action(
            SOURCE_USER, PREREQUISITE,
            ('Create a `MIGRATION-<YourName>` shared folder and move your '
             'records into it; share it with the admin at owner-level '
             '(Path A). OR accept the REQUIRE_ACCOUNT_SHARE enforcement '
             'on next login so admin can transfer your full vault (Path B).'),
            email=email, blocks=['take-ownership', 'transfer-user'],
        ))

    # ─── During users phase: target users must accept invitation emails ──
    for user in src_users:
        email = (user.get('email') or '').strip().lower()
        if not email:
            continue
        category = transition_by_email.get(email, '')
        if category == 'D':
            continue   # already in target — no user action needed
        if category == 'UNKNOWN':
            actions.append(_action(
                ADMIN, DURING_USERS,
                'User is Locked/Disabled on target — unlock manually before '
                'the users phase runs.',
                email=email, blocks=['users', 'run'],
            ))
            continue
        if category in ('B', 'CONFLICT_B'):
            actions.append(_action(
                SOURCE_USER, DURING_USERS,
                'Personal-Keeper conflict — either delete the personal '
                'account or accept the transfer-account prompt before the '
                'users phase is rerun.',
                email=email, blocks=['users'],
            ))
            continue
        if category in ('C', 'CONFLICT_C'):
            actions.append(_action(
                ADMIN, DURING_USERS,
                'Cross-enterprise conflict — coordinate with Keeper Support '
                'to release the email before the users phase is rerun.',
                email=email, blocks=['users'],
            ))
            continue
        # Category A/E/empty — user needs to accept the invite
        actions.append(_action(
            TARGET_USER, DURING_USERS,
            ('After the users phase runs, you will receive an invitation '
             'email on the target tenant. Accept it within the consent '
             'window to activate your account.'),
            email=email, blocks=['records-shares'],
        ))

    # ─── During shares phase: direct-share grantees must exist on target ──
    grantees = _direct_share_grantees(src_records)
    for email, titles in sorted(grantees.items()):
        if email in target_users_set:
            continue
        actions.append(_action(
            TARGET_USER, DURING_SHARES,
            (f'{len(titles)} record(s) direct-shared with this email on '
             'source — target account must exist + have accepted the '
             'invitation BEFORE records-shares runs, or the grants '
             'silently skip.'),
            email=email, blocks=['records-shares'],
        ))

    # ─── During structure phase: SF member emails must match on target ──
    sf_members = _sf_members(src_sfs)
    for email, sfs in sorted(sf_members.items()):
        if email in target_users_set:
            continue
        actions.append(_action(
            TARGET_USER, DURING_OWNERSHIP,
            (f'Member of {len(sfs)} source shared folder(s) — apply-membership '
             'on target tenant will skip this email unless it matches a '
             'target-side user. Pre-invite required, or use '
             '`download-membership --old-domain X --new-domain Y` to remap.'),
            email=email, blocks=['structure', 'run'],
        ))

    # ─── Post-migration: user verifies, admin decommissions ──
    for user in src_users:
        email = (user.get('email') or '').strip().lower()
        if not email:
            continue
        actions.append(_action(
            TARGET_USER, POST_MIGRATION,
            ('Log in to the target tenant. Verify that your records, shared '
             'folders, and attachments are all visible. Report any missing '
             'data to admin BEFORE the decommission step.'),
            email=email,
        ))
    actions.append(_action(
        ADMIN, POST_MIGRATION,
        ('After user sign-off, run `tenant-migrate point-of-no-return` '
         'followed by `tenant-migrate decommission` on the source session. '
         'Source users will be locked + deleted — irreversible.'),
    ))

    # ─── PAM: rotation + gateway configs don't survive the migration ────
    from .pam_detection import summarize_pam_impact
    pam = summarize_pam_impact(inventory)
    if pam['total_flagged']:
        type_brief = ', '.join(f'{k}={v}' for k, v in sorted(pam['by_type'].items()))
        actions.append(_action(
            ADMIN, POST_MIGRATION,
            (f'{pam["total_flagged"]} PAM record(s) detected ({type_brief}). '
             'Rotation schedules, gateway registrations, and agent tokens do '
             'NOT transfer across tenants. On the target: re-register '
             'gateways, re-issue agent tokens, and re-enable rotation per '
             'record after manual review.'),
            blocks=[],
        ))

    # ─── SSO / SCIM: IdP side must be repointed at the new tenant ────────
    sso_config = inventory.get('sso_config') or {}
    providers = sso_config.get('providers') or []
    sso_user_count = sso_config.get('user_count_sso', 0) or 0
    sso_users = [u for u in src_users if u.get('is_sso')]
    if providers or sso_users:
        for prov in providers:
            bits = []
            if prov.get('name'):
                bits.append(f"name={prov['name']!r}")
            if prov.get('entity_id'):
                bits.append(f"entity_id={prov['entity_id']}")
            if prov.get('sp_url'):
                bits.append(f"source ACS={prov['sp_url']}")
            if prov.get('scim_url'):
                bits.append(f"source SCIM={prov['scim_url']}")
            actions.append(_action(
                ADMIN, PREREQUISITE,
                ('SSO/SCIM provider on source will NOT automatically '
                 'follow to target. On the IdP (Azure AD / Okta / etc.) '
                 'update the SAML app to point at the NEW tenant\'s ACS URL '
                 'and rotate the SCIM bearer token for the new tenant before '
                 'the users phase runs, otherwise SSO-provisioned users '
                 'cannot authenticate. '
                 f"Provider details: {', '.join(bits) or '(unnamed)'}"),
                blocks=['users', 'run'],
            ))
        if sso_users:
            actions.append(_action(
                ADMIN, PREREQUISITE,
                (f'{len(sso_users)} source user(s) are SSO-provisioned '
                 '(not manually invited). Instead of running `users` for them, '
                 're-provision via the IdP\'s SCIM connector against the new '
                 'tenant. Use `--sso-policy skip` on the users subcommand to '
                 'prevent accidental invite attempts.'),
                blocks=['users'],
            ))

    # SCIM endpoints: each configured SCIM connector is tied to ONE
    # tenant's node tree. The admin must generate a fresh SCIM bearer
    # token on the target and reconfigure each upstream IdP.
    scim_configs = sso_config.get('scims') or []
    for scim in scim_configs:
        actions.append(_action(
            ADMIN, PREREQUISITE,
            (f'SCIM connector (status={scim.get("status", "?")}, '
             f'last_synced={scim.get("last_synced")}) is tenant-scoped and '
             'does NOT follow the migration. On target: Admin Console → '
             'SCIM → Add Connector at the same node, generate a new '
             'bearer token, paste that token into the IdP. Old tenant\'s '
             'SCIM connector should be disabled AFTER users are '
             'reprovisioned to avoid churn.'),
            blocks=['users'],
        ))

    # Bridges (on-prem AD/LDAP): appliance config is tenant-specific.
    bridge_configs = sso_config.get('bridges') or []
    for br in bridge_configs:
        actions.append(_action(
            ADMIN, POST_MIGRATION,
            (f'Keeper Bridge appliance (status={br.get("status", "?")}, '
             f'wan={br.get("wan_ip_enforcement", "?")}) — appliance '
             'registration is per-tenant. Register a new bridge in the '
             'target tenant and reconfigure the appliance (config file + '
             'enterprise code) to point there. Old bridge should be '
             'retired after users are re-provisioned.'),
        ))

    return actions


def render_actions_markdown(actions):
    """Group by phase → actor, emit a Markdown checklist."""
    if not actions:
        return '# Customer manual actions\n\nNone — all automated.\n'

    phase_order = [PREREQUISITE, DURING_OWNERSHIP, DURING_USERS,
                   DURING_SHARES, POST_MIGRATION]
    phase_titles = {
        PREREQUISITE: 'Before migration starts (prerequisite)',
        DURING_OWNERSHIP: 'During ownership transfer / structure phase',
        DURING_USERS: 'During users phase',
        DURING_SHARES: 'Before records-shares runs',
        POST_MIGRATION: 'After migration completes',
    }

    by_phase = {p: [] for p in phase_order}
    for a in actions:
        by_phase.setdefault(a['phase'], []).append(a)

    lines = ['# Customer manual actions', '']
    total = len(actions)
    lines.append(f'**Total items**: {total}')
    lines.append('')

    for phase in phase_order:
        rows = by_phase.get(phase) or []
        if not rows:
            continue
        lines.append(f'## {phase_titles[phase]} ({len(rows)})')
        lines.append('')
        # Further group by actor for readability
        by_actor = {}
        for r in rows:
            by_actor.setdefault(r['actor'], []).append(r)
        for actor, entries in sorted(by_actor.items()):
            lines.append(f'### {actor} ({len(entries)})')
            lines.append('')
            for r in entries[:200]:
                who = f' — `{r["email"]}`' if r['email'] else ''
                blocks = (f'  (blocks: {", ".join(r["blocks"])})'
                          if r['blocks'] else '')
                lines.append(f'- [ ]{who} {r["note"]}{blocks}')
            if len(entries) > 200:
                lines.append(f'- …and {len(entries) - 200} more')
            lines.append('')
    return '\n'.join(lines) + '\n'
