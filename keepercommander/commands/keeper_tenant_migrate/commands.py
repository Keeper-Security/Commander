"""Commander plugin entry point for `tenant-migrate ...`.

Each subcommand operates on the CURRENT Commander session's `params` — the
user authenticates to the right tenant (source or target) before invoking.
Cross-tenant subcommands (plan/records/run) that need simultaneous access
to both tenants remain staged until the SDK gains a dual-session API; their
decomposed counterparts (assemble-inventory, convert, transition-check) are
fully functional today.

Subcommand implementation status:
   WORKING (operate on current session or offline files):
     - convert            (offline — v3→v2 record format)
     - assemble-inventory (offline — staged CSV/JSON → inventory JSON)
     - transition-check   (offline — inventory + target CSV → A/D/E/UNKNOWN plan)
     - structure          (current session = target)
     - users              (current session = target)
     - verify             (offline — inventory + target state JSON)
     - reconcile          (offline — inventory + target state JSON)

   DEFERRED (need cross-tenant auth — see README/PYTHON_PORT_PLAN.md):
     - plan               (needs source session + target for pre-invite lookup)
     - records            (needs source + target simultaneously)
     - run                (orchestrates plan + records)
"""

import argparse
import json
import logging
import os

from keepercommander.commands.base import Command, GroupCommand

from .declare.commands import DeclareGroupCommand


# ───── Parsers ────────────────────────────────────────────────────────────────

plan_parser = argparse.ArgumentParser(
    prog='tenant-migrate-plan',
    description='Capture source inventory from the current (source) session. '
                'For the transition-plan phase, run `transition-check` with '
                'a target CSV once you switch to the target session.',
)
plan_parser.add_argument('--output', required=True,
                         help='Inventory JSON path (sha256 sidecar auto-written).')
plan_parser.add_argument('--node', default='', dest='scope_node',
                         help='Scope to a named node subtree (recursive).')
plan_parser.add_argument('--prefix', default='',
                         help='Entity-name prefix filter (e.g. MIGTEST-).')
plan_parser.add_argument('--target-user', default='',
                         help='Target tenant admin identity (label only).')
plan_parser.add_argument('--target-root', default='',
                         help='Target root node name (label only).')
plan_parser.add_argument('--include-fields', action='store_true',
                         help='Capture full record field data (login/password/'
                              'url/notes/custom) for field-level verify. '
                              'Default off — keeps passwords out of inventory.')
plan_parser.add_argument('--skip-hsf-scrape', action='store_true',
                         help='Skip per-team scrape for hide_shared_folders '
                              '(user_type==2). Faster for large tenants; hsf '
                              'info won\'t reach the users subcommand.')

users_parser = argparse.ArgumentParser(
    prog='tenant-migrate-users',
    description='Invite users on the current (target) tenant per a frozen inventory.',
)
users_parser.add_argument('--inventory', required=True,
                          help='Source inventory JSON from `assemble-inventory`.')
users_parser.add_argument('--roster', required=True,
                          help='Roster CSV with `email,full_name` columns.')
users_parser.add_argument('--transition-plan',
                          help='Transition plan CSV from `transition-check` (optional).')
users_parser.add_argument('--source-root', default='My company',
                          help='Source root node name (for node path remapping).')
users_parser.add_argument('--target-root', default='',
                          help='Target root node name (auto-detected if empty).')
users_parser.add_argument('--default-node', default='',
                          help='Fallback node when a user has no node in inventory.')
users_parser.add_argument('--dry-run', action='store_true',
                          help='Log every invite + placement + classify '
                               'against current target state.')
users_parser.add_argument('--dry-run-report', default='',
                          help='Markdown path for the dry-run plan report.')
users_parser.add_argument('--mc',
                          help='Target a specific Managed Company before invoking.')
users_parser.add_argument('--old-domain', default='',
                          help='When source/target email domains differ, '
                               'remap roster emails from this domain.')
users_parser.add_argument('--new-domain', default='',
                          help='Remap roster emails TO this domain '
                               '(paired with --old-domain).')
users_parser.add_argument('--delay', type=float, default=0.0,
                          help='Seconds between invite calls (rate-limit knob).')
users_parser.add_argument('--batch-size', type=int, default=0,
                          help='Extra pause every N users to let '
                               'Commander sync-down catch up.')
users_parser.add_argument('--sso-policy', default='warn',
                          choices=('allow', 'warn', 'skip'),
                          help='SSO-provisioned users: allow (treat as normal), '
                               'warn (log + proceed, default), skip (mark BLOCKED '
                               '— re-provision via IdP SCIM instead).')
users_parser.add_argument('--run-dir', default='',
                          help='Directory for checkpoint state. '
                               'Defaults to the roster\'s directory.')
users_parser.add_argument('--resume', action='store_true',
                          help='Resume from checkpoint after partial run. '
                               'Roster must match (same email list).')
users_parser.add_argument('--force-restart', action='store_true',
                          help='Wipe any existing checkpoint and start fresh.')

structure_parser = argparse.ArgumentParser(
    prog='tenant-migrate-structure',
    description='Restore nodes/teams/roles/enforcements/SF membership on '
                'the current (target) tenant from a staged plan directory '
                'OR a consolidated inventory JSON.',
)
struct_input_group = structure_parser.add_mutually_exclusive_group(required=True)
struct_input_group.add_argument('--plan', help='Plan directory with nodes.json, teams.json, '
                                'roles.json, roles_complete.json, '
                                'shared_folder_membership.json, record_types.json.')
struct_input_group.add_argument('--inventory',
                                help='Inventory JSON from `plan` / `assemble-inventory`.')
structure_parser.add_argument('--source-root', default='My company',
                                help='Source root node name (for node path remapping).')
structure_parser.add_argument('--target-root', default='',
                              help='Target root node name (auto-detected if empty).')
structure_parser.add_argument('--scope-node', default='',
                              help='Scope the subtree root when the plan is subtree-scoped.')
structure_parser.add_argument('--steps', default='0-12',
                              help='Step range, e.g. "0-3" or "4-6". Default: 0-12.')
structure_parser.add_argument('--dry-run', action='store_true',
                              help='Log every write + classify as CREATE/SKIP/'
                                   'CONFLICT/DELETE vs current target state.')
structure_parser.add_argument('--dry-run-report', default='',
                              help='Markdown path for the dry-run plan report '
                                   '(only used with --dry-run).')
structure_parser.add_argument('--mc',
                              help='Target a specific Managed Company under the '
                                   'current MSP session before running.')
structure_parser.add_argument('--nested-sf-plan', dest='nested_sf_plan',
                              default='',
                              help='Optional path to a `nested-sf-plan` JSON. '
                                   'When present, shared_folder_folder entries '
                                   'classified `promote-to-shared_folder` are '
                                   'created as top-level shared_folders on '
                                   'target with a qualified name '
                                   '(`Parent - Child`) instead of subfolders.')
structure_parser.add_argument('--resume', action='store_true',
                              help='Resume after a mid-stage crash. Each '
                                   'step queries target state and pre-filters '
                                   'source rows to the delta — entities '
                                   'already created on target get logged as '
                                   'SKIPPED (already present); entities that '
                                   'were missing get logged as SUCCESS '
                                   '(created — was missing on resume); '
                                   'partial enforcements get reconciled. '
                                   'Default off — operators see no behavior '
                                   'change without the flag. Idempotent: '
                                   'running twice in a row makes the second '
                                   'run a no-op.')
structure_parser.add_argument('--preserve-duplicate-node-names',
                              dest='preserve_duplicate_node_names',
                              action='store_true',
                              help='Skip the rename-with-suffix '
                                   'disambiguation that the structure '
                                   'stage applies to duplicate-leaf-name '
                                   'source nodes (e.g. multiple Finance '
                                   'nodes under different Subsidiary '
                                   'parents). Default off — duplicates '
                                   'land as `Finance (Subsidiary B)` etc., '
                                   'mirroring the team/role rename pattern. '
                                   'When on, the SDK boundary calls '
                                   '`node_add` directly with the original '
                                   'name; only safe when the server is '
                                   'verified to accept duplicate '
                                   'displaynames under distinct parents '
                                   '(rehearsal-15+ live-test required '
                                   'before defaulting on).')
structure_parser.add_argument('--apply-admin-lockout-risk-enforcements',
                              dest='apply_admin_lockout_risk_enforcements',
                              action='store_true',
                              help='Apply lockout-risk enforcements '
                                   '(`require_account_share`, '
                                   '`restrict_ip_addresses`, '
                                   '`master_password_reentry`, '
                                   '`two_factor_by_ip`) on roles in '
                                   "Keeper's BUILTIN_ROLE_NAMES set "
                                   '(Administrator / Keeper '
                                   'Administrator / Admin / Enterprise '
                                   'Admin / Executive). Default off — '
                                   'these enforcements are SKIP'
                                   'ped on builtin-admin roles to '
                                   'prevent admin lockout from '
                                   'cross-tenant value drift '
                                   '(2026-04-26 `jlima+demo2` incident). '
                                   'Opt in only after auditing each '
                                   'value for target-tenant '
                                   'compatibility — these enforcements '
                                   'can lock the operator out of the '
                                   'target tenant before they have a '
                                   'chance to fix the value.')
structure_parser.add_argument('--overrides', dest='overrides', default='',
                              help='Path to a hand-edited overrides.yaml '
                                   '(see .context/overrides-schema.md). When '
                                   'present, the operator-supplied nested-SF '
                                   'plan is loaded, the overrides are '
                                   'validated against it, and a NEW plan is '
                                   'produced with the user\'s choices applied. '
                                   'The original plan file is never mutated. '
                                   'Every applied override is signed into the '
                                   'audit chain with before/after values + '
                                   'the user\'s note. Validation errors abort '
                                   'before any structure step runs.')
structure_parser.add_argument('--accept-risk', dest='accept_risk',
                              action='store_true',
                              help='Acknowledge that the overrides file '
                                   'sets `tier:` to a non-default value. '
                                   'NOTE: tier overrides are advisory + '
                                   'audit-only in this release — the '
                                   'audit log records before/after, but '
                                   'the actual throttle is still driven '
                                   'by --delay / --batch-size on the CLI. '
                                   'Tier under-sizing is the #1 cause of '
                                   'mid-migration throttle failures, so '
                                   'we still gate the override note behind '
                                   'an explicit opt-in.')

records_umbrella_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records',
    description='Umbrella for the records pipeline. Detects whether this '
                'shell is source (runs export + convert) or target (runs '
                'manifest + import + attachments + shares) and chains '
                'the appropriate stages under a shared run-dir.',
)
records_umbrella_parser.add_argument('--run-dir', required=True,
                                      help='Shared run directory.')
records_umbrella_parser.add_argument(
    '--stages', default='',
    help='Comma-separated stages to run '
          '(export,convert,manifest,import,attachments,shares). '
          'Default: auto-derived from session role.')
records_umbrella_parser.add_argument('--dry-run', action='store_true',
                                      help='Pass --dry-run to every stage.')
records_umbrella_parser.add_argument('--staging-dir', default='',
                                      help='Attachment staging dir '
                                           '(default: <run-dir>/attachments).')
records_umbrella_parser.add_argument('--record-type', default='',
                                      help='Optional --record-type for import.')

records_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records',
    description='[DEFERRED] End-to-end records migration. Use '
                'records-export → convert → records-import → records-shares.',
)
records_parser.add_argument('--plan', help='Plan directory.')

records_export_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-export',
    description='Export records from the current (source) session as v3 JSON, '
                'suitable for `convert` + `records-import`.',
)
records_export_parser.add_argument('--output-dir', required=True,
                                    help='Directory to write one JSON per record.')
records_export_parser.add_argument('--prefix', default='',
                                    help='Only export records whose title starts with this prefix.')
records_export_parser.add_argument('--folder-uid', action='append', default=[],
                                    dest='folder_uids',
                                    help='Scope to records under a folder UID (repeatable). '
                                         'Walks the subfolder tree recursively. Combines '
                                         'with --prefix (AND semantics).')

records_import_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-import',
    description='Import an import-ready JSON bundle into the current (target) '
                'session via Commander\'s native import flow.',
)
records_import_parser.add_argument('--input', required=True,
                                    help='Output of `convert` (single JSON) or a run-batch file.')
records_import_parser.add_argument('--dry-run', action='store_true',
                                    help='Preview without committing.')
records_import_parser.add_argument('--record-type', default='',
                                    help='Force a single record type (when not using --split-by-type).')
records_import_parser.add_argument('--permissions', default='',
                                    help='Default SF permissions for records that reference '
                                         'shared folders. Letters: U=manage users, R=manage '
                                         'records, E=can edit, S=can share, A=all, N=none. '
                                         "Default: 'N' (batch-safe — no interactive prompt).")
# Bug 68 (v1.6.2) — chunked import with inter-chunk delay so a large
# bundle on a heavily-throttled tenant (MSP target) doesn't stall on
# Commander's monolithic batched import. Mirrors pam-import's natural
# pacing where every mutation is followed by sync_down. Default 0
# preserves pre-fix behavior (single monolithic import).
records_import_parser.add_argument('--chunk-size', type=int, default=0,
                                    help='Split the bundle into chunks of N records and import '
                                         'each chunk separately. Adds inter-chunk pause to give '
                                         'the target tenant\'s rate limiter time to recover. 0 '
                                         '(default) = single monolithic import (legacy).')
records_import_parser.add_argument('--chunk-delay', type=float, default=2.0,
                                    help='Seconds to sleep between chunks when --chunk-size > 0. '
                                         'Default 2.0s.')

records_attachments_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-attachments',
    description='Migrate attachments between source and target records. '
                'Must run from a session that can see both — typically a '
                'target session where the source records have been added '
                'to an accessible shared folder.',
)
records_attachments_parser.add_argument('--manifest', required=True,
                                         help='CSV with source_uid,target_uid columns.')
records_attachments_parser.add_argument('--staging-dir', required=True,
                                         help='Directory for intermediate downloaded files.')
records_attachments_parser.add_argument('--dry-run', action='store_true',
                                         help='Count attachments per manifest row '
                                              'without downloading or uploading.')
records_attachments_parser.add_argument('--dry-run-report', default='',
                                         help='Markdown path for the dry-run plan.')
records_attachments_parser.add_argument('--delay', type=float, default=0.0,
                                         help='Seconds between upload calls.')
records_attachments_parser.add_argument('--batch-size', type=int, default=0,
                                         help='Extra pause every N attachments.')

records_attachments_download_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-attachments-download',
    description='Phase 1 of two-phase attachments: downloads every '
                'attachment for each source_uid into <staging-dir>/'
                '<source_uid>/. Writes staging.json so the target-side '
                'upload can run later without needing source session.',
)
records_attachments_download_parser.add_argument(
    '--source-uids', required=True,
    help='CSV with a source_uid column OR a plain text file with one '
         'UID per line.')
records_attachments_download_parser.add_argument(
    '--staging-dir', required=True,
    help='Directory to receive downloaded files + staging.json index.')
records_attachments_download_parser.add_argument(
    '--delay', type=float, default=0.0,
    help='Seconds between downloads.')
records_attachments_download_parser.add_argument(
    '--batch-size', type=int, default=0,
    help='Extra pause every N records.')

records_attachments_upload_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-attachments-upload',
    description='Phase 2: reads files pre-downloaded by records-'
                'attachments-download + a source_uid→target_uid manifest, '
                'uploads to the target session. Source session NOT needed.',
)
records_attachments_upload_parser.add_argument(
    '--manifest', required=True,
    help='CSV with source_uid,target_uid columns.')
records_attachments_upload_parser.add_argument(
    '--staging-dir', required=True,
    help='Same directory used by records-attachments-download.')
records_attachments_upload_parser.add_argument(
    '--delay', type=float, default=0.0,
    help='Seconds between uploads.')
records_attachments_upload_parser.add_argument(
    '--batch-size', type=int, default=0,
    help='Extra pause every N records.')
records_attachments_upload_parser.add_argument(
    '--run-dir', default='',
    help='Directory for checkpoint state. '
         'Defaults to the staging-dir.')
records_attachments_upload_parser.add_argument(
    '--resume', action='store_true',
    help='Resume from checkpoint after partial run.')
records_attachments_upload_parser.add_argument(
    '--force-restart', action='store_true',
    help='Wipe any existing checkpoint and start fresh.')

records_shares_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-shares',
    description='Replay user_permissions[] from source records onto target. '
                'Same session constraints as records-attachments.',
)
records_shares_parser.add_argument('--manifest', required=True,
                                    help='CSV with source_uid,target_uid columns.')
records_shares_parser.add_argument('--skip-missing-users', action='store_true',
                                    help='Skip users not found on target (default: fail).')
records_shares_parser.add_argument('--dry-run', action='store_true',
                                    help='List every share-record that would run.')
records_shares_parser.add_argument('--dry-run-report', default='',
                                    help='Markdown path for the dry-run plan.')
records_shares_parser.add_argument('--old-domain', default='',
                                    help='Remap share target emails from this domain.')
records_shares_parser.add_argument('--new-domain', default='',
                                    help='Remap share target emails TO this domain.')
records_shares_parser.add_argument('--delay', type=float, default=0.0,
                                    help='Seconds between share-record calls.')
records_shares_parser.add_argument('--batch-size', type=int, default=0,
                                    help='Extra pause every N records processed.')
records_shares_parser.add_argument('--run-dir', default='',
                                    help='Directory for checkpoint state. '
                                         'Defaults to the manifest\'s directory.')
records_shares_parser.add_argument('--resume', action='store_true',
                                    help='Resume from an existing checkpoint — '
                                         'skips to the pair after the last '
                                         'successful one. Input manifest must '
                                         'match (same SHA-256).')
records_shares_parser.add_argument('--force-restart', action='store_true',
                                    help='Wipe any existing checkpoint and '
                                         'start fresh. Use when the manifest '
                                         'has legitimately changed.')

records_shares_extract_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-shares-extract',
    description='Phase 1 of cross-tenant direct-share migration. '
                'Source-side dump: read user_permissions[] from each '
                'source record (Bug 19 lazy-fetch), apply email remap, '
                'write a JSON manifest the target-side `records-shares-'
                'apply` consumes. No target session needed.',
)
records_shares_extract_parser.add_argument(
    '--manifest', required=True,
    help='CSV with source_uid,target_uid columns (from records-manifest).',
)
records_shares_extract_parser.add_argument(
    '--output', required=True,
    help='Path for the extract JSON. 0600.',
)
records_shares_extract_parser.add_argument(
    '--old-domain', default='',
    help='Remap share target emails from this domain.',
)
records_shares_extract_parser.add_argument(
    '--new-domain', default='',
    help='Remap share target emails TO this domain.',
)

records_shares_apply_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-shares-apply',
    description='Phase 2 of cross-tenant direct-share migration. '
                'Target-side: read the JSON written by `records-shares-'
                'extract` and grant each share via share-record on the '
                'target session.',
)
records_shares_apply_parser.add_argument(
    '--input', required=True,
    help='Path to the extract JSON written by records-shares-extract.',
)
records_shares_apply_parser.add_argument(
    '--skip-missing-users', action='store_true',
    help='Skip users not found on target (default: fail).',
)
records_shares_apply_parser.add_argument(
    '--delay', type=float, default=0.0,
    help='Seconds between share-record calls.',
)
records_shares_apply_parser.add_argument(
    '--batch-size', type=int, default=0,
    help='Extra pause every N entries processed.',
)
records_shares_apply_parser.add_argument(
    '--run-dir', default='',
    help='Directory for checkpoint state. Defaults to the input\'s '
         'directory.',
)
records_shares_apply_parser.add_argument(
    '--resume', action='store_true',
    help='Resume from an existing checkpoint — skips to the entry after '
         'the last successful one.',
)
records_shares_apply_parser.add_argument(
    '--force-restart', action='store_true',
    help='Wipe any existing checkpoint and start fresh.',
)

records_manifest_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-manifest',
    description='Build a source_uid,target_uid manifest by matching record '
                'titles across a source export directory and the current '
                '(target) session.',
)
records_manifest_parser.add_argument('--source-dir', required=True,
                                      help='Directory from `records-export`.')
records_manifest_parser.add_argument('--output', required=True,
                                      help='Manifest CSV path.')
records_manifest_parser.add_argument('--allow-ambiguous', action='store_true',
                                      help='Positionally pair duplicate-title '
                                           'records (default: flag as ambiguous).')

records_references_rewrite_parser = argparse.ArgumentParser(
    prog='tenant-migrate-records-references-rewrite',
    description='Bug 33 — remap source-record UIDs embedded in target '
                'record field values (httpCredentialsUid, recordRef, '
                'pamUserUid, pamConfigurationUid, targetRecord, '
                'controllerUid, resourceRef) to their target equivalents '
                'using the records manifest. Idempotent.',
)
records_references_rewrite_parser.add_argument(
    '--manifest', required=True,
    help='Records manifest CSV (source_uid,target_uid,title).')
records_references_rewrite_parser.add_argument(
    '--run-dir', help='Run directory; audit events are appended to '
                       '<run-dir>/audit.log when present.')
records_references_rewrite_parser.add_argument(
    '--dry-run', action='store_true',
    help='Inspect only — list records that would be rewritten, do not '
          'persist changes.')

convert_parser = argparse.ArgumentParser(
    prog='tenant-migrate-convert',
    description='Convert exported v3 records to Commander import v2 format.')
convert_parser.add_argument('--input-dir', '--input', dest='input_dir',
                              required=True,
                              help='Directory of per-record v3 JSON files (as produced by `records-export`). `--input` is accepted as an alias.')
convert_parser.add_argument('--output', required=True, help='Output import-ready JSON file.')
convert_parser.add_argument('--compliance-csv', help='Compliance SF report CSV for folder assignments.')
convert_parser.add_argument('--sf-json', help='Shared-folders JSON for SF name resolution.')
convert_parser.add_argument('--include-sf', action='store_true', help='Emit shared_folders section.')
convert_parser.add_argument('--split-by-type', action='store_true',
                            help='Emit one file per record type + a run-batch script.')

transition_parser = argparse.ArgumentParser(
    prog='tenant-migrate-transition-check',
    description='Classify source users (A/D/E/UNKNOWN) against target tenant state.')
transition_group = transition_parser.add_mutually_exclusive_group(required=True)
transition_group.add_argument('--inventory', help='Source inventory JSON.')
transition_group.add_argument('--roster', help='Roster CSV with an `email` column.')
transition_parser.add_argument('--target-users-csv', required=True,
                               help='Target-tenant enterprise-info --users --format csv output.')
transition_parser.add_argument('--target-label', default='',
                                help='Human-readable label for the target tenant (stamped into the Markdown report header).')
transition_parser.add_argument('--csv-output', required=True, help='Plan CSV path.')
transition_parser.add_argument('--md-output', required=True, help='Markdown summary path.')

assemble_parser = argparse.ArgumentParser(
    prog='tenant-migrate-assemble-inventory',
    description='Assemble an inventory JSON from staged CSV/JSON (00d-style tmp dir).')
assemble_parser.add_argument('--input-dir', required=True,
                             help='Staging dir with nodes.csv/teams.csv/users.csv/roles/records/shared_folders.json.')
assemble_parser.add_argument('--output', required=True,
                             help='Output inventory JSON path (sha256 sidecar auto-written).')
assemble_parser.add_argument('--prefix', default='',
                              help='Entity-name prefix filter (e.g. MIGTEST-).')
assemble_parser.add_argument('--scope-node', default='',
                              help='Scope to a named node subtree.')
assemble_parser.add_argument('--source-user', default='',
                              help='Source tenant admin identity (stamped into inventory metadata).')
assemble_parser.add_argument('--source-server', default='',
                              help='Source tenant server hostname (for data-center stamp).')
assemble_parser.add_argument('--source-root', default='',
                              help='Source root node name (for node path remapping).')
assemble_parser.add_argument('--target-user', default='',
                              help='Target tenant admin identity (label only — for transition-plan headers).')
assemble_parser.add_argument('--target-root', default='',
                              help='Target root node name (label only — for transition-plan headers).')

verify_parser = argparse.ArgumentParser(
    prog='tenant-migrate-verify',
    description='Field-level verification against a frozen inventory.')
verify_parser.add_argument('--inventory', required=True, help='Inventory JSON.')
verify_parser.add_argument('--target-state', required=True,
                           help='Target-state JSON (same layout as inventory.entities).')
verify_parser.add_argument('--output', help='Optional CSV path for check results.')

reconcile_parser = argparse.ArgumentParser(
    prog='tenant-migrate-reconcile',
    description='Source/Target/Delta Markdown report.')
reconcile_parser.add_argument('--inventory', required=True, help='Inventory JSON.')
reconcile_parser.add_argument('--target-state', required=True,
                              help='Target-state JSON (same layout as inventory.entities).')
reconcile_parser.add_argument('--output', required=True, help='Markdown report path.')

capture_parser = argparse.ArgumentParser(
    prog='tenant-migrate-capture-target-state',
    description='Dump the current session\'s enterprise data to JSON for use with '
                '`verify` and `reconcile`.',
)
capture_parser.add_argument('--output', required=True,
                            help='Target-state JSON path.')
capture_parser.add_argument('--include-fields', action='store_true',
                            help='Also capture full record field data (for '
                                 'field-level verify). Off by default.')
capture_parser.add_argument('--prefix', default='',
                            help='Restrict records to those matching this title prefix.')
capture_parser.add_argument('--mc',
                            help='Capture from a specific Managed Company under '
                                 'the current MSP session (read-only MC scope).')

audit_verify_parser = argparse.ArgumentParser(
    prog='tenant-migrate-audit-verify',
    description='Verify integrity of a migration artifact directory: '
                'checks SHA256SUMS.txt against each file + validates the '
                'prev-hash chain of audit.log if present.',
)
audit_verify_parser.add_argument('--directory', required=True,
                                  help='Directory previously emitted by '
                                       '`records-export` or `take-ownership`.')
audit_verify_parser.add_argument('--audit-log',
                                  help='Optional explicit audit.log path '
                                       '(defaults to <directory>/audit.log).')

audit_lockout_risk_parser = argparse.ArgumentParser(
    prog='tenant-migrate-audit-lockout-risk',
    description='Read-only audit of lockout-risk enforcements '
                "(`require_account_share`, `restrict_ip_addresses`, "
                "`master_password_reentry`, `two_factor_by_ip`) on the "
                "target tenant's BUILTIN_ROLE_NAMES roles. Run pre-"
                'migration to baseline target, post-migration to verify '
                'no lockout vector landed unexpectedly. Optionally cross-'
                'compares against a source inventory to flag drift.',
)
audit_lockout_risk_parser.add_argument(
    '--source-inventory', dest='source_inventory', default='',
    help='Optional path to source inventory.json. When supplied, the '
         'audit cross-compares each target builtin-admin role against '
         'the source baseline and flags drift.')
audit_lockout_risk_parser.add_argument(
    '--output', default='',
    help='Optional path to write the report (markdown). Default: stdout.')
audit_lockout_risk_parser.add_argument(
    '--mc', default='',
    help='MC scope when target is an MSP managed company.')

undo_parser = argparse.ArgumentParser(
    prog='tenant-migrate-undo',
    description='Rollback migration steps using the tamper-evident audit '
                'log as source of truth. Chain verify first; dry-run by '
                'default; --execute required to mutate.',
)
undo_parser.add_argument('--audit-log', required=True,
                          help='Path to the audit.log to rewind.')
undo_parser.add_argument('--up-to',
                          help='Stop at the event with this signature '
                               '(that event stays done). Omit → full rollback.')
undo_parser.add_argument('--execute', action='store_true',
                          help='Actually perform the inverse ops. Without '
                               'this flag we only print the plan.')
undo_parser.add_argument('--hard', action='store_true',
                          help='For `users` rollback: delete the invited '
                               'users instead of just locking them.')
undo_parser.add_argument('--yes', '-y', action='store_true',
                          help='Bypass interactive confirmation.')
undo_parser.add_argument('--mc', default='',
                          help='MSP-only: scope the rollback to a specific '
                               'Managed Company. Mirrors --mc on cleanup/'
                               'structure/users/auto-migrate; lets undo '
                               'reverse events that were originally scoped '
                               'to an MC.')

audit_export_parser = argparse.ArgumentParser(
    prog='tenant-migrate-audit-export',
    description='Export the tamper-evident audit.log to a SIEM-ingestible '
                'format (json-lines / syslog / cef). Read-only; never '
                'mutates the source chain.',
)
audit_export_parser.add_argument('--audit-log', required=True,
                                  help='Path to audit.log from a run-dir.')
audit_export_parser.add_argument('--output', required=True,
                                  help='Output file (one line per event, chmod 0600).')
audit_export_parser.add_argument('--format', default='json-lines',
                                  choices=('json-lines', 'syslog', 'cef'),
                                  help='Destination format.')
audit_export_parser.add_argument('--hostname', default='',
                                  help='Override hostname in syslog output '
                                       '(default: socket.gethostname()).')

manual_actions_parser = argparse.ArgumentParser(
    prog='tenant-migrate-manual-actions',
    description='Emit a Markdown checklist of human actions the migration '
                'cannot automate (users sharing folders, accepting invites, '
                'admin unlocking blocked users, post-migration verification).',
)
manual_actions_parser.add_argument('--inventory', required=True,
                                    help='Source inventory JSON.')
manual_actions_parser.add_argument('--target-state',
                                    help='Optional target-state JSON — lets us '
                                         'skip "user must accept invite" for '
                                         'users already on target.')
manual_actions_parser.add_argument('--transition-plan',
                                    help='Optional plan CSV from transition-check '
                                         '— narrows per-user actions by category.')
manual_actions_parser.add_argument('--output', required=True,
                                    help='Markdown output path.')

session_parser = argparse.ArgumentParser(
    prog='tenant-migrate-session',
    description='Show who this shell is logged in as + which region/'
                'tenant/role. Read-only — no writes anywhere.',
)

auto_migrate_parser = argparse.ArgumentParser(
    prog='tenant-migrate-auto-migrate',
    description='Single-command end-to-end migration. The current session '
                '(from --config) is the source; the target is authenticated '
                'in-process via --target-user (interactive) or --target-config '
                '(pre-authenticated). Runs plan → estimate → structure → '
                'records pipeline → sf-reconcile → verify → reconcile. '
                'Defaults to --dry-run; pass --live to execute.',
)
# Target auth (exactly one of --target-user or --target-config).
auto_migrate_parser.add_argument('--target-user',
                                  help='Target tenant admin email. Prompts for '
                                       'master password via getpass at runtime.')
auto_migrate_parser.add_argument('--target-server', default='',
                                  help='Target data center region '
                                       '(US, EU, AU, CA, JP, GOV, …). '
                                       'Only used with --target-user.')
auto_migrate_parser.add_argument('--target-config', default='',
                                  help='Path to a pre-authenticated target '
                                       'config.json. Alternative to '
                                       '--target-user for CI / scripted use.')
auto_migrate_parser.add_argument('--target-vault-record', default='',
                                  help='Bootstrap target auth from a LOGIN '
                                       'record in the source vault. Record '
                                       'must have login + password fields; '
                                       'server is derived from the URL. '
                                       'Source session must be authenticated.')

# Scope.
auto_migrate_parser.add_argument('--scope-node', default='',
                                  help='Source subtree to migrate.')
auto_migrate_parser.add_argument('--prefix', default='',
                                  help='Entity/record name-prefix filter.')
auto_migrate_parser.add_argument('--target-root', default='',
                                  help='Where to land the scope subtree on '
                                       'target (auto-detects if empty).')
auto_migrate_parser.add_argument('--mc', default='',
                                  help='Target MC under the target MSP.')
auto_migrate_parser.add_argument('--source-folder-uid', action='append',
                                  default=[], dest='source_folder_uids',
                                  help='Scope export to specific source folder '
                                       'UIDs (repeatable, walks subfolders).')

# Pipeline control.
auto_migrate_parser.add_argument('--run-dir', required=True,
                                  help='Shared artifact directory — all '
                                       'stages read/write here. Created if '
                                       'missing.')
auto_migrate_parser.add_argument('--dry-run', action='store_true',
                                  default=True,
                                  help='Default ON. Destructive target stages '
                                       'skip execution. Pass --live to commit.')
auto_migrate_parser.add_argument('--live', action='store_true',
                                  help='Opt in to actually write on target. '
                                       'Overrides --dry-run.')
auto_migrate_parser.add_argument('--only-stages', default='',
                                  help='Comma-separated whitelist of stages. '
                                       'Overrides canonical order.')
auto_migrate_parser.add_argument('--skip-stages', default='',
                                  help='Comma-separated stages to skip.')
auto_migrate_parser.add_argument('--resume', action='store_true',
                                  help='Resume from checkpoint (loop stages).')
auto_migrate_parser.add_argument('--force-restart', action='store_true',
                                  help='Wipe any checkpoint and start fresh.')

# Safety.
auto_migrate_parser.add_argument('--yes', '-y', action='store_true',
                                  help='Bypass pre-run confirm banner.')
auto_migrate_parser.add_argument('--expected-source-tenant', default='',
                                  help='Abort if source tenant name mismatches.')
auto_migrate_parser.add_argument('--expected-target-tenant', default='',
                                  help='Abort if target tenant name mismatches.')

# Behavior.
auto_migrate_parser.add_argument('--old-domain', default='',
                                  help='Remap email domain (source → target).')
auto_migrate_parser.add_argument('--new-domain', default='',
                                  help='Paired with --old-domain.')
auto_migrate_parser.add_argument('--include-fields', action='store_true',
                                  help='Include plaintext fields in inventory '
                                       '(0600). Default off.')
auto_migrate_parser.add_argument('--sso-policy', default='warn',
                                  choices=('allow', 'warn', 'skip'),
                                  help='SSO user handling on the users stage.')
auto_migrate_parser.add_argument('--allow-ambiguous', action='store_true',
                                  help='records-manifest: positional-pair '
                                       'duplicate-title records instead of '
                                       'dropping them. Use only when source '
                                       'and target order is known to align '
                                       '(e.g. fresh target imported in-order '
                                       'from source). Default off.')
auto_migrate_parser.add_argument('--delay', type=float, default=0.0,
                                  help='Unified per-call delay. Stage '
                                       'defaults apply when 0 (structure 3s, '
                                       'records 1s, attachments 0.5s, shares '
                                       '3s). Per-stage overrides below win.')
auto_migrate_parser.add_argument('--delay-structure', type=float, default=0.0,
                                  help='Override per-call delay for the '
                                       'structure stage only. Default 3s.')
auto_migrate_parser.add_argument('--delay-records', type=float, default=0.0,
                                  help='Override per-call delay for records '
                                       '(import/manifest). Default 1s.')
auto_migrate_parser.add_argument('--delay-attachments', type=float, default=0.0,
                                  help='Override per-call delay for '
                                       'attachment download/upload. Default 0.5s.')
auto_migrate_parser.add_argument('--delay-shares', type=float, default=0.0,
                                  help='Override per-call delay for '
                                       'records-shares + sf-reconcile. '
                                       'Default 3s.')
auto_migrate_parser.add_argument('--import-chunk-size', type=int, default=0,
                                  help='Bug 68 — split records-import bundle '
                                       'into N-record chunks with inter-chunk '
                                       'pause. Mirrors pam-import\'s natural '
                                       'pacing (sync_down between mutations) '
                                       'so heavily-throttled tenants get rate-'
                                       'limit recovery time between batches. '
                                       '0 (default) = legacy single-pass '
                                       'monolithic import. Recommended 100 '
                                       'for MSP/EU targets.')
auto_migrate_parser.add_argument('--import-chunk-delay', type=float, default=2.0,
                                  help='Seconds to sleep between chunks when '
                                       '--import-chunk-size > 0. Default 2.0s.')
auto_migrate_parser.add_argument('--jitter', type=float, default=0.5,
                                  help='Random 0..jitter seconds added to '
                                       'each inter-call sleep to desync from '
                                       "Commander's 30s throttle-retry wave. "
                                       '0 disables.')
auto_migrate_parser.add_argument('--reserve-quota-every', type=int, default=0,
                                  help='Every N API calls, sleep extra so the '
                                       'admin browser can reclaim rate-limit '
                                       'quota. 20 is a good starting value; '
                                       '0 disables.')
auto_migrate_parser.add_argument('--reserve-quota-seconds', type=float,
                                  default=2.0,
                                  help='Pause length at each reserve-quota '
                                       'checkpoint. Default 2s.')
auto_migrate_parser.add_argument('--adaptive-throttle', dest='adaptive_throttle',
                                  action='store_true', default=True,
                                  help='Enable global adaptive throttle — '
                                       "grows inter-call delay on observed "
                                       'Commander throttle events, decays '
                                       'after clean runs. Default on.')
auto_migrate_parser.add_argument('--no-adaptive-throttle',
                                  dest='adaptive_throttle',
                                  action='store_false',
                                  help='Disable adaptive throttle. Per-stage '
                                       '--delay-* flags still apply.')
auto_migrate_parser.add_argument('--adaptive-base-delay', type=float,
                                  default=2.0,
                                  help='Adaptive throttle starting delay in '
                                       'seconds. Default 2.0s.')
auto_migrate_parser.add_argument('--adaptive-max-delay', type=float,
                                  default=30.0,
                                  help='Adaptive throttle ceiling. Default '
                                       '30s (matches Commander rest_api '
                                       'internal backoff floor).')
auto_migrate_parser.add_argument('--adaptive-success-reset', type=int,
                                  default=20,
                                  help='Clean calls before adaptive delay '
                                       'decays one step. Default 20.')
auto_migrate_parser.add_argument('--calls-per-minute', type=float, default=0.0,
                                  help='Cap sustained API rate at N calls/min '
                                       '(e.g. 30 for large tenants, 60 for '
                                       'medium). Overrides --adaptive-base-delay '
                                       'with 60/N minus observed latency. '
                                       'Also feeds the estimator so the banner '
                                       'shows a realistic ETA. EU enterprise '
                                       'tenants throttle around 90–100/min on '
                                       'writes; pick 30–60 for safety margin. '
                                       '0 = use --adaptive-base-delay directly.')
auto_migrate_parser.add_argument('--burst-capacity', type=int, default=3,
                                  help='Token-bucket capacity — caps how many '
                                       'back-to-back API calls fire before the '
                                       'bucket gates the next one. Roles have '
                                       'many options (enforcements, managed '
                                       'nodes, privileges) that burst from the '
                                       'plugin loop; capacity=3 matches '
                                       "Commander's observed burst budget.")
auto_migrate_parser.add_argument('--cluster-window', type=float, default=120.0,
                                  help='Seconds within which two throttle '
                                       'hits are considered clustered; '
                                       'triggers exponential delay growth '
                                       '(doubles current) instead of linear '
                                       "(+step). Default 120s (Commander's "
                                       'own 60s backoff spaces hits apart; '
                                       'smaller windows rarely fire).')
auto_migrate_parser.add_argument('--decay-cooldown', type=float, default=60.0,
                                  help='Minimum seconds since last throttle '
                                       'before any decay fires. Prevents '
                                       'oscillation where decay-then-rethrottle '
                                       'forms a steady cycle. Default 60s.')
auto_migrate_parser.add_argument('--bucket-decay-every-n-windows', type=int,
                                  default=3,
                                  help='Bucket refill decays only every Nth '
                                       'success_reset window — keeps burst '
                                       'cap conservative while delay relaxes. '
                                       'Default 3.')
auto_migrate_parser.add_argument('--batch-size', type=int, default=0,
                                  help='Checkpoint pause every N ops.')
auto_migrate_parser.add_argument('--debug', action='store_true',
                                  help='Bug 71 — verbose mode. Sets root '
                                       'logger to DEBUG, surfaces per-item '
                                       'progress (chunk N/M, enforcement '
                                       'N/M, attachment N/M, reference-rewrite '
                                       'per-record), and emits a final '
                                       'categorized summary of every SKIP / '
                                       'WARN / FAIL with operator-facing '
                                       'reasons. Default off (WARNING level).')

sf_reconcile_parser = argparse.ArgumentParser(
    prog='tenant-migrate-shared-folders-reconcile',
    description='Apply SF memberships that were deferred during structure '
                'because their users were still pending_invite. Idempotent, '
                'cron-able — run daily post-migration until the still-pending '
                'list empties. Add-only by default; pass --prune to also '
                'remove target memberships not listed in the source inventory.',
)
sf_reconcile_parser.add_argument('--inventory', required=True,
                                  help='Source inventory JSON from `plan`.')
sf_reconcile_parser.add_argument('--report', default='',
                                  help='Markdown path for the run report. '
                                       'Default: reconcile.md beside inventory.')
sf_reconcile_parser.add_argument('--dry-run', action='store_true',
                                  help='Emit plan only, apply nothing.')
sf_reconcile_parser.add_argument('--old-domain', default='',
                                  help='Remap expected member emails from this '
                                       'domain before comparing to target.')
sf_reconcile_parser.add_argument('--new-domain', default='',
                                  help='Remap expected member emails to this '
                                       'domain (paired with --old-domain).')
sf_reconcile_parser.add_argument('--delay', type=float, default=0.0,
                                  help='Seconds between share-folder calls.')
sf_reconcile_parser.add_argument('--batch-size', type=int, default=0,
                                  help='Extra pause every N grants processed.')
sf_reconcile_parser.add_argument('--run-dir', default='',
                                  help='Directory for checkpoint state. '
                                       'Defaults to the inventory\'s directory.')
sf_reconcile_parser.add_argument('--resume', action='store_true',
                                  help='Resume from checkpoint after a prior '
                                       'partial run. Input plan must match.')
sf_reconcile_parser.add_argument('--force-restart', action='store_true',
                                  help='Wipe any existing checkpoint and '
                                       'start fresh.')
sf_reconcile_parser.add_argument('--prune', action='store_true',
                                  help='DESTRUCTIVE: also remove target '
                                       'memberships that are NOT in the '
                                       'source inventory. Off by default '
                                       '(reconcile is add-only by spec). '
                                       'Pair with --dry-run first to preview '
                                       'what would be pruned.')

estimate_parser = argparse.ArgumentParser(
    prog='tenant-migrate-estimate',
    description='Pre-flight tenant size + API call budget + runtime '
                'estimate from a `plan`-produced inventory. Read-only.',
)
estimate_parser.add_argument('--inventory', required=True,
                             help='Inventory JSON from `plan` '
                                  '(or `assemble-inventory`).')
estimate_parser.add_argument('--output', default='',
                             help='Markdown report path. Default: '
                                  'estimate.md beside inventory.')
estimate_parser.add_argument('--output-json', default='',
                             help='Machine-readable JSON path. Default: '
                                  'estimate.json beside inventory.')
estimate_parser.add_argument('--tier-driver', default='auto',
                             choices=('auto', 'users', 'records'),
                             help='Which entity count drives the throttle '
                                  'tier. auto = max(users, records).')
estimate_parser.add_argument('--calls-per-minute', type=float, default=0.0,
                             help='Override tier-derived delay with a '
                                  'specific rate cap. 30 cpm = safe for '
                                  'EU large tenants, 60 for medium. 0 = '
                                  'use tier default.')

nested_sf_plan_parser = argparse.ArgumentParser(
    prog='tenant-migrate-nested-sf-plan',
    description='Classify shared_folder_folder subfolders against the '
                '5-option migration matrix (preserve-subfolder, promote-'
                'to-sibling, promote-to-true-nested, flatten-with-prefix, '
                'hybrid-per-folder). Emits a JSON plan that '
                '`structure --nested-sf-plan` consumes per-row. Read-only.',
)
nested_sf_plan_parser.add_argument('--inventory', required=True,
                                    help='Inventory JSON from `plan` / '
                                         '`assemble-inventory`.')
nested_sf_plan_parser.add_argument('--output', required=True,
                                    help='Path to write the nested-SF '
                                         'plan JSON (chmod 0600).')
nested_sf_plan_parser.add_argument(
    '--default-action',
    choices=['preserve-subfolder', 'promote-to-sibling',
             'promote-to-true-nested', 'flatten-with-prefix'],
    default='promote-to-sibling',
    help='Default action for subfolders that diverge from parent. '
         "Default: 'promote-to-sibling' (matches v1.3.0 behaviour). "
         "Use 'flatten-with-prefix' for legacy targets that don't "
         "support shared_folder_folder; 'promote-to-true-nested' is a "
         'placeholder until Commander ships nested-SF support.')
nested_sf_plan_parser.add_argument(
    '--per-folder-rules', default='',
    help='Path to JSON file mapping subfolder UID → action override. '
         'Override wins over --default-action. Use to mix strategies '
         'across a tenant (hybrid-per-folder mode).')
nested_sf_plan_parser.add_argument(
    '--default-conflict-resolution',
    choices=['error', 'suffix', 'merge'], default='error',
    help='Per-row policy for name collisions on target. Default: '
         "'error' (operator must edit plan to resolve).")

plan_report_parser = argparse.ArgumentParser(
    prog='tenant-migrate-plan-report',
    description='Render a customer-friendly markdown report combining '
                '`plan` + `nested-sf-plan` + `estimate` outputs. Surfaces '
                'only the decisions that need operator review; buckets '
                'safe-default rows. Read-only — no live tenant access.',
)
plan_report_parser.add_argument('--inventory', default='',
                                 help='Inventory JSON from `plan`.')
plan_report_parser.add_argument('--nested-sf-plan', dest='nested_sf_plan',
                                 default='',
                                 help='Plan JSON from `nested-sf-plan`.')
plan_report_parser.add_argument('--estimate', default='',
                                 help='Estimate JSON from `estimate`.')
plan_report_parser.add_argument('--output', required=True,
                                 help='Markdown report path. A companion '
                                      '`<output>.json` (machine-readable '
                                      'mirror, used by overrides.yaml '
                                      'validation) is written next to it.')

wizard_parser = argparse.ArgumentParser(
    prog='tenant-migrate-wizard',
    description='Menu-driven migration wizard. Reads / creates '
                '<run-dir>/migration.yaml, detects whether this shell is '
                'the source or target tenant, and proposes the next step. '
                'Each shell must already be logged in via `keeper login`.',
)
wizard_parser.add_argument('--run-dir', required=True,
                            help='Shared run directory — both source and '
                                 'target shells point at the same path.')
wizard_parser.add_argument('--no-auto-adjust', dest='no_auto_adjust',
                            action='store_true',
                            help='Disable automated email-domain remap, '
                                 'rate-limit scaling, and SSO policy '
                                 'inference. Each step uses its own '
                                 'per-call kwargs only.')

selftest_parser = argparse.ArgumentParser(
    prog='tenant-migrate-self-test',
    description='Read-only check that every SDK integration works against the '
                'current session. Run this against a sandbox before any '
                'destructive operation.',
)

preflight_parser = argparse.ArgumentParser(
    prog='tenant-migrate-pre-flight',
    description='Pre-migration environment checks (roster sanity, Commander '
                'version, auth, disk, output-dir writability).',
)
preflight_parser.add_argument('--roster', required=True,
                               help='Roster CSV path to validate.')
preflight_parser.add_argument('--output-dir', default='./migration_logs',
                               help='Directory used for migration artifacts '
                                    '(checked for writability + disk space).')
preflight_parser.add_argument('--csv-output',
                               help='Optional CSV path for the full check list.')

take_ownership_parser = argparse.ArgumentParser(
    prog='tenant-migrate-take-ownership',
    description='Path-A ownership transfer: move MIGRATION-* folders from '
                'source users to the admin (current session), with per-user '
                'JSON backup written first. Processes rows where status=READY '
                'in the verification report CSV.',
)
take_ownership_parser.add_argument('--verification-report', required=True,
                                    help='CSV with email, full_name, expected_folder, '
                                         'record_count, status columns.')
take_ownership_parser.add_argument('--backup-dir', required=True,
                                    help='Directory for per-user JSON backups (chmod 0600).')
take_ownership_parser.add_argument('--report-output', required=True,
                                    help='CSV path for the ownership-transfer report.')
take_ownership_parser.add_argument('--admin-email',
                                    help='Admin email receiving ownership. '
                                         'Defaults to the current session user.')
take_ownership_parser.add_argument('--delay', type=float, default=0.5,
                                    help='Seconds between each row (throttle-friendly).')
take_ownership_parser.add_argument('--dry-run', action='store_true',
                                    help='List every backup + ownership transfer '
                                         'that would run, without writing anything.')
take_ownership_parser.add_argument('--dry-run-report', default='',
                                    help='Markdown path for the dry-run plan '
                                         '(only used with --dry-run).')
take_ownership_parser.add_argument('--yes', '-y', action='store_true',
                                    help='Bypass interactive confirmation.')
take_ownership_parser.add_argument('--expected-tenant-name', default='',
                                    help='Abort if session tenant name differs. '
                                         'REQUIRED unless --skip-tenant-check is '
                                         'passed.')
take_ownership_parser.add_argument('--skip-tenant-check', action='store_true',
                                    help='Explicitly bypass the mandatory tenant '
                                         'assertion. Only safe when the caller '
                                         'has pre-validated the session by other '
                                         'means (e.g. auto-migrate SessionPair).')
take_ownership_parser.add_argument('--old-domain', default='',
                                    help='Remap admin email from this domain '
                                         '(for cross-domain ownership transfers).')
take_ownership_parser.add_argument('--new-domain', default='',
                                    help='Remap admin email TO this domain.')
take_ownership_parser.add_argument('--batch-size', type=int, default=0,
                                    help='Extra pause every N transfers.')
take_ownership_parser.add_argument('--run-dir', default='',
                                    help='Shared run-dir — resolves '
                                         'migration.yaml for source-mode check.')
take_ownership_parser.add_argument('--confirm-source-destructive',
                                    action='store_true',
                                    help='REQUIRED when the current session '
                                         'matches the run-spec source tenant. '
                                         'Layered with source_mode:destructive '
                                         'and --expected-tenant-name.')
take_ownership_parser.add_argument('--resume', action='store_true',
                                    help='Resume from checkpoint after partial '
                                         'run. Verification report must match.')
take_ownership_parser.add_argument('--force-restart', action='store_true',
                                    help='Wipe any existing checkpoint and '
                                         'start fresh.')

restore_ownership_parser = argparse.ArgumentParser(
    prog='tenant-migrate-take-ownership-restore',
    description='Undo: grant MIGRATION-* folder ownership back to the '
                'original users using the CSV report from `take-ownership`. '
                'Optionally verifies the backup dir\'s integrity first.',
)
restore_ownership_parser.add_argument('--report', required=True,
                                       help='Ownership report CSV from take-ownership.')
restore_ownership_parser.add_argument('--verify-backup-dir',
                                       help='Backup dir — verify SHA256SUMS + '
                                            'audit.log chain before restoring.')
restore_ownership_parser.add_argument('--dry-run', action='store_true',
                                       help='List rows that would be restored.')

transfer_user_parser = argparse.ArgumentParser(
    prog='tenant-migrate-transfer-user',
    description='Path-B: transfer entire user vaults into the admin account '
                '(current session). Auto-locks each source user per Commander '
                '`transfer-user` behavior. For users who accepted the '
                'REQUIRE_ACCOUNT_SHARE enforcement.',
)
transfer_user_parser.add_argument('--readiness-report', required=True,
                                   help='CSV from `00c_check_transfer_readiness.sh` '
                                        'with a `migration_path` column.')
transfer_user_parser.add_argument('--report-output', required=True,
                                   help='CSV path for the transfer report.')
transfer_user_parser.add_argument('--admin-email',
                                   help='Admin account receiving vaults. '
                                        'Defaults to the current session user.')
transfer_user_parser.add_argument('--delay', type=float, default=2.0,
                                   help='Seconds after each transfer before sync-down '
                                        '(lets the target vault converge).')
transfer_user_parser.add_argument('--dry-run', action='store_true',
                                   help='List every transfer-user call that would run.')
transfer_user_parser.add_argument('--dry-run-report', default='',
                                   help='Markdown path for the dry-run plan.')
transfer_user_parser.add_argument('--yes', '-y', action='store_true',
                                   help='Bypass interactive confirmation.')
transfer_user_parser.add_argument('--expected-tenant-name', default='',
                                   help='Abort if session tenant name differs. '
                                        'REQUIRED unless --skip-tenant-check is '
                                        'passed.')
transfer_user_parser.add_argument('--skip-tenant-check', action='store_true',
                                   help='Explicitly bypass the mandatory tenant '
                                        'assertion. Only safe when the caller '
                                        'has pre-validated the session by other '
                                        'means (e.g. auto-migrate SessionPair).')
transfer_user_parser.add_argument('--batch-cap', type=int, default=50,
                                   help='Refuse to transfer more than this '
                                        'many users without --override-batch-cap.')
transfer_user_parser.add_argument('--override-batch-cap', action='store_true',
                                   help='Explicit opt-in to exceed --batch-cap.')
transfer_user_parser.add_argument('--run-dir', default='',
                                   help='Shared run-dir — resolves '
                                        'migration.yaml for source-mode check.')
transfer_user_parser.add_argument('--confirm-source-destructive',
                                   action='store_true',
                                   help='REQUIRED when the current session '
                                        'matches the run-spec source tenant. '
                                        'Layered with source_mode:destructive '
                                        'and --expected-tenant-name.')
transfer_user_parser.add_argument('--resume', action='store_true',
                                   help='Resume from checkpoint after partial '
                                        'run. Readiness report must match.')
transfer_user_parser.add_argument('--force-restart', action='store_true',
                                   help='Wipe any existing checkpoint and '
                                        'start fresh.')

cleanup_parser = argparse.ArgumentParser(
    prog='tenant-migrate-cleanup',
    description='Delete teams/roles/nodes on the current session whose names '
                'start with a given prefix (e.g. MIGTEST-). Safely-ordered: '
                'teams → roles → nodes (deepest first).',
)
cleanup_parser.add_argument('--prefix', required=True,
                             help='Name prefix to match (required, non-empty).')
cleanup_parser.add_argument('--confirm', action='store_true',
                             help='Required — without this the subcommand exits '
                                  'without touching anything. Safety rail.')
cleanup_parser.add_argument('--dry-run', action='store_true',
                             help='List every entity that would be deleted '
                                  'without touching the tenant.')
cleanup_parser.add_argument('--dry-run-report', default='',
                             help='Markdown path for the dry-run plan.')
cleanup_parser.add_argument('--yes', '-y', action='store_true',
                             help='Bypass interactive confirmation (for CI). '
                                  'Alias for --confirm.')
cleanup_parser.add_argument('--expected-tenant-name', default='',
                             help='Abort if the current session tenant name '
                                  'does not match this string. REQUIRED unless '
                                  '--skip-tenant-check is passed (mandatory '
                                  'since the 2026-04-20 polluted-config '
                                  'red-team incident).')
cleanup_parser.add_argument('--skip-tenant-check', action='store_true',
                             help='Explicitly bypass the mandatory tenant '
                                  'assertion. Only safe when the caller has '
                                  'pre-validated the session by other means '
                                  '(e.g. auto-migrate SessionPair).')
cleanup_parser.add_argument('--batch-cap', type=int, default=50,
                             help='Refuse to delete more than this many '
                                  'entities without --override-batch-cap.')
cleanup_parser.add_argument('--override-batch-cap', action='store_true',
                             help='Explicit opt-in to delete more than '
                                  '--batch-cap entities.')
cleanup_parser.add_argument('--run-dir', default='',
                             help='Shared run directory — used to resolve '
                                  'migration.yaml for source-mode checking.')
cleanup_parser.add_argument('--confirm-source-destructive', action='store_true',
                             help='REQUIRED when the current session matches '
                                  'the run-spec source tenant. Layered with '
                                  'source_mode: destructive in migration.yaml '
                                  'and --expected-tenant-name. See '
                                  'SECURITY_MODEL.md.')
cleanup_parser.add_argument('--mc',
                             help='Scope cleanup at a specific Managed Company '
                                  'under the current MSP session. Uses the same '
                                  'switch-to-mc context-manager as structure/users.')
cleanup_parser.add_argument('--include-records', action='store_true',
                             help='Also delete records whose title starts with '
                                  '--prefix. Opt-in because cleanup was '
                                  'originally scoped to enterprise structure '
                                  '(nodes/teams/roles) only. Needed for '
                                  'reproducible rehearsals that re-import the '
                                  'same records — otherwise duplicates '
                                  'accumulate.')

gate_parser = argparse.ArgumentParser(
    prog='tenant-migrate-point-of-no-return',
    description='Authorize destructive next steps by writing a signed '
                'checkpoint. Refuses if checks.csv has any FAIL entries.',
)
gate_parser.add_argument('--checks', required=True,
                         help='Validator checks.csv output path.')
gate_parser.add_argument('--reconciliation',
                         help='Optional reconcile Markdown report.')
gate_parser.add_argument('--checkpoint', required=True,
                         help='Checkpoint JSON output path.')
gate_parser.add_argument('--confirm', required=True,
                         help='Must be exactly "YES".')

decom_parser = argparse.ArgumentParser(
    prog='tenant-migrate-decommission',
    description='Lock + delete source-tenant users. Refuses to run without a '
                'valid non-expired checkpoint from point-of-no-return.',
)
decom_parser.add_argument('--roster', required=True,
                          help='Roster CSV with an `email` column.')
decom_parser.add_argument('--checkpoint', default='',
                          help='Checkpoint JSON from point-of-no-return. '
                               'Required for the automated execution path; '
                               'ignored for --plan-only and '
                               '--confirm-manual-completion.')
decom_parser.add_argument('--report-output', default='',
                          help='CSV path for the decommission report. '
                               'Required for the automated execution path.')
decom_parser.add_argument('--plan-only', action='store_true',
                          help='RECOMMENDED: emit a Markdown plan with the '
                               'exact `keeper enterprise-user --lock/--delete` '
                               'commands, do not execute. User deletion is '
                               'irreversible — run the plan manually.')
decom_parser.add_argument('--plan-output', default='',
                          help='Markdown path for --plan-only output. '
                               'Default: decommission.plan.md beside roster.')
decom_parser.add_argument('--confirm-manual-completion', action='store_true',
                          help='Append a "manually deleted by operator" '
                               'event to the audit log. Use after running '
                               'the --plan-only commands by hand.')
decom_parser.add_argument('--audit-log', default='',
                          help='Audit log path for --confirm-manual-completion '
                               '(default: $RUN/audit.log).')
decom_parser.add_argument('--operator', default='',
                          help='Operator name/email for --confirm-manual-completion '
                               'audit metadata.')
decom_parser.add_argument('--delay', type=float, default=0.5,
                          help='Seconds between users.')
decom_parser.add_argument('--max-age-hours', type=int, default=72,
                          help='Reject checkpoints older than this many hours '
                               '(default 72, matches bash reference).')
decom_parser.add_argument('--dry-run', action='store_true',
                          help='List every lock+delete that would run without '
                               'touching the source tenant.')
decom_parser.add_argument('--dry-run-report', default='',
                          help='Markdown path for the dry-run plan.')
decom_parser.add_argument('--expected-tenant-name', default='',
                          help='Abort if session tenant name differs. REQUIRED '
                               'unless --skip-tenant-check is passed.')
decom_parser.add_argument('--skip-tenant-check', action='store_true',
                          help='Explicitly bypass the mandatory tenant '
                               'assertion. Only safe when the caller has '
                               'pre-validated the session by other means '
                               '(e.g. auto-migrate SessionPair).')
decom_parser.add_argument('--run-dir', default='',
                          help='Shared run-dir — resolves migration.yaml '
                               'for source-mode check.')
decom_parser.add_argument('--confirm-source-destructive',
                          action='store_true',
                          help='REQUIRED when the current session matches '
                               'the run-spec source tenant. Layered with '
                               'source_mode:destructive + --expected-tenant-name.')

run_parser = argparse.ArgumentParser(
    prog='tenant-migrate-run',
    description='Target-side orchestrator: structure → users → '
                'capture-target-state → verify → reconcile in one shot. '
                'Uses a checkpoint file for --resume.',
)
run_parser.add_argument('--inventory', required=True,
                        help='Source inventory JSON from `plan` or `assemble-inventory`.')
run_parser.add_argument('--roster',
                        help='Roster CSV for the users stage. Omit to skip users.')
run_parser.add_argument('--transition-plan',
                        help='Transition plan CSV from `transition-check` (optional).')
run_parser.add_argument('--output-dir', required=True,
                        help='Directory for intermediate artifacts + final report.')
run_parser.add_argument('--source-root', default='My company',
                         help='Source root node name (for node path remapping).')
run_parser.add_argument('--target-root', default='',
                         help='Target root node name (auto-detected if empty).')
run_parser.add_argument('--scope-node', default='',
                         help='Scope the subtree root when the plan is subtree-scoped.')
run_parser.add_argument('--default-node', default='',
                         help='Fallback node when a user has no node in inventory.')
run_parser.add_argument('--resume', action='store_true',
                        help='Pick up from the last completed stage.')
run_parser.add_argument('--start-stage',
                        choices=['structure', 'users', 'verify', 'reconcile'],
                        help='Start at this stage instead of the default (structure). '
                             'Note: capture_state runs automatically before verify '
                             'and reconcile — it is not a user-selectable stage.')
run_parser.add_argument('--end-stage',
                        choices=['structure', 'users', 'verify', 'reconcile'],
                        help='Stop after this stage.')
run_parser.add_argument('--mc',
                        help='MSP admins: scope the whole run to a specific '
                             'Managed Company (name or id). Invokes '
                             '`switch-to-mc MC` before any stage.')


# ───── Command classes ────────────────────────────────────────────────────────


class _DeferredCommand(Command):
    """Stub for subcommands that require cross-tenant auth."""

    subcommand_name = 'subcommand'
    pointer = ''  # human hint at what works today

    def __init__(self, parser):
        super().__init__()
        self._parser = parser

    def get_parser(self):
        return self._parser

    def execute(self, params, **kwargs):
        logging.warning('tenant-migrate %s: deferred (cross-tenant auth required).',
                        self.subcommand_name)
        if self.pointer:
            logging.warning('Use %s today.', self.pointer)


class PlanCommand(Command):
    def get_parser(self):
        return plan_parser

    def execute(self, params, **kwargs):
        from .commander_clients import sync_down
        from .live_inventory import build_inventory_from_params, write_inventory

        sync_down(params)
        inventory = build_inventory_from_params(
            params,
            scope_node=kwargs.get('scope_node', ''),
            prefix=kwargs.get('prefix', ''),
            target_user=kwargs.get('target_user', ''),
            target_root=kwargs.get('target_root', ''),
            include_fields=kwargs.get('include_fields', False),
            scrape_hsf=not kwargs.get('skip_hsf_scrape', False),
        )
        checksum = write_inventory(inventory, kwargs['output'])
        logging.info('Plan captured: %s | sha256=%s', inventory['counts'], checksum)
        logging.info('Next: switch to target session and run `tenant-migrate '
                     'transition-check --inventory %s --target-users-csv TARGET_USERS.csv ...`',
                     kwargs['output'])
        return inventory


class RecordsCommand(_DeferredCommand):
    subcommand_name = 'records'
    pointer = '`convert` for v3→v2 format conversion'

    def __init__(self):
        super().__init__(records_parser)


class RecordsUmbrellaCommand(Command):
    """Chain the records stages that apply to the current shell.

    Source role runs: records-export → convert
    Target role runs: records-manifest → records-import → records-attachments → records-shares

    The split is role-driven because Commander can't hold two sessions at
    once — the source shell does the read side, the target shell does
    the write side. Both share a run-dir so the artifacts flow between
    them (export dir + import bundle + manifest + audit.log).
    """

    STAGE_ORDER = ('export', 'convert', 'manifest', 'import',
                    'attachments', 'shares')
    SOURCE_STAGES = ('export', 'convert')
    TARGET_STAGES = ('manifest', 'import', 'attachments', 'shares')

    def get_parser(self):
        return records_umbrella_parser

    def execute(self, params, **kwargs):
        from .session import detect_session_role
        from .wizard import load_migration_yaml

        run_dir = kwargs['run_dir']
        spec = load_migration_yaml(run_dir)
        role = detect_session_role(params, spec)

        # Parse the requested stages (or pick per role).
        requested = [s.strip() for s in (kwargs.get('stages') or '').split(',')
                      if s.strip()]
        if requested:
            stages = [s for s in self.STAGE_ORDER if s in requested]
            for s in requested:
                if s not in self.STAGE_ORDER:
                    logging.error('unknown stage: %s', s)
                    return {'error': f'unknown stage: {s}'}
        elif role == 'source':
            stages = list(self.SOURCE_STAGES)
        elif role == 'target':
            stages = list(self.TARGET_STAGES)
        else:
            logging.error(
                'records umbrella: session role is %s — cannot auto-select '
                'stages. Pass --stages or set up migration.yaml first.', role)
            return {'error': f'role={role}', 'stages': []}

        dry = bool(kwargs.get('dry_run'))
        staging_dir = kwargs.get('staging_dir') or os.path.join(
            run_dir, 'attachments')
        export_dir = os.path.join(run_dir, 'records_export')
        import_bundle = os.path.join(run_dir, 'records_import.json')
        manifest_csv = os.path.join(run_dir, 'manifest.csv')
        audit_log = os.path.join(run_dir, 'audit.log')

        logging.info('records umbrella: role=%s stages=%s', role,
                     ','.join(stages))
        outcomes = {}

        for stage in stages:
            logging.info('── records stage: %s ──', stage)
            try:
                if stage == 'export':
                    outcomes[stage] = RecordsExportCommand().execute(
                        params, output_dir=export_dir,
                        include_fields=False, audit_log=audit_log)
                elif stage == 'convert':
                    # Convert is offline and takes the export dir directly.
                    outcomes[stage] = ConvertCommand().execute(
                        params, input_dir=export_dir,
                        output=import_bundle)
                elif stage == 'manifest':
                    outcomes[stage] = RecordsManifestCommand().execute(
                        params, source_dir=export_dir,
                        output=manifest_csv, allow_ambiguous=False)
                elif stage == 'import':
                    import_kwargs = {'input': import_bundle,
                                      'audit_log': audit_log}
                    if dry:
                        import_kwargs['dry_run'] = True
                    if kwargs.get('record_type'):
                        import_kwargs['record_type'] = kwargs['record_type']
                    outcomes[stage] = RecordsImportCommand().execute(
                        params, **import_kwargs)
                elif stage == 'attachments':
                    outcomes[stage] = RecordsAttachmentsCommand().execute(
                        params, manifest=manifest_csv,
                        staging_dir=staging_dir, audit_log=audit_log,
                        dry_run=dry)
                elif stage == 'shares':
                    outcomes[stage] = RecordsSharesCommand().execute(
                        params, manifest=manifest_csv,
                        skip_missing_users=False, audit_log=audit_log,
                        dry_run=dry)
            except Exception as e:                     # noqa: BLE001
                # One stage failing shouldn't take down the rest in dry-run,
                # but in a real run the downstream stages depend on the
                # prior stage's output — abort so the admin can fix the
                # cause rather than chain errors.
                logging.error('records stage %r failed: %s', stage, e,
                               exc_info=True)
                outcomes[stage] = {'error': str(e)}
                if not dry:
                    break

        return {'role': role, 'stages': stages, 'outcomes': outcomes}


class RunCommand(Command):
    """Target-side orchestrator using orchestrator.py stage framework.

    Source-side `plan` runs in a SEPARATE session (Commander can't be
    logged into two tenants at once). This command chains the target-side
    work: structure → users → capture_state → verify → reconcile.
    """

    def get_parser(self):
        return run_parser

    def execute(self, params, **kwargs):
        from .mc_context import MCContext
        with MCContext(params, kwargs.get('mc', '')) as ctx:
            # Use ctx.params — it's the MC-scoped session when --mc was
            # passed, or the original params otherwise. Passing the raw
            # `params` here would silently operate against the MSP
            # instead of the MC (this was a real bug pre-v1.3.1).
            return self._run(ctx.params, kwargs)

    def _run(self, params, kwargs):
        from .orchestrator import (Checkpoint, Orchestrator,
                                    OrchestratorContext, STAGE_ORDER)

        output_dir = kwargs['output_dir']
        os.makedirs(output_dir, exist_ok=True)

        ctx = OrchestratorContext(
            inventory_path=kwargs['inventory'],
            roster_path=kwargs.get('roster'),
            transition_plan_path=kwargs.get('transition_plan'),
            source_root=kwargs.get('source_root') or 'My company',
            target_root=kwargs.get('target_root') or _detect_target_root(params) or 'Root',
            scope_node=kwargs.get('scope_node', ''),
            default_node=kwargs.get('default_node', ''),
            output_dir=output_dir,
        )

        stages = self._build_stages(params, ctx)

        checkpoint = os.path.join(output_dir, '.run_state')
        orch = Orchestrator(stages, checkpoint)
        orch.run(
            ctx,
            start_stage=kwargs.get('start_stage'),
            end_stage=kwargs.get('end_stage'),
            resume=kwargs.get('resume', False),
        )

        path = orch.save_state(ctx, output_dir)
        logging.info('Run complete. Results: %s', path)
        return {'stage_results': ctx.stage_results, 'results_json': path}

    def _build_stages(self, params, ctx):
        """Return a stages dict keyed by the target-side stage names that map
        to each subcommand's execute().

        The orchestrator framework expects STAGE_ORDER names (plan/users/...).
        We reuse only a subset matching target-side work.
        """
        # Allow: users / structure / verify / reconcile from STAGE_ORDER.
        # Add a 'capture_state' step before verify/reconcile so the target
        # state JSON is fresh.
        stages = {}

        def stage_structure(_ctx):
            cmd = StructureCommand()
            cmd.execute(
                params,
                inventory=_ctx.get('inventory_path'),
                plan=None,
                source_root=_ctx.get('source_root'),
                target_root=_ctx.get('target_root'),
                scope_node=_ctx.get('scope_node'),
                steps='0-12',
            )
            return 'PASSED'

        def stage_users(_ctx):
            if not _ctx.get('roster_path'):
                return 'SKIPPED'
            cmd = UsersCommand()
            cmd.execute(
                params,
                inventory=_ctx.get('inventory_path'),
                roster=_ctx.get('roster_path'),
                transition_plan=_ctx.get('transition_plan_path'),
                source_root=_ctx.get('source_root'),
                target_root=_ctx.get('target_root'),
                default_node=_ctx.get('default_node'),
            )
            return 'PASSED'

        def stage_records(_ctx):
            """Chain records-import → records-attachments → records-shares
            in one orchestrator stage. Any single sub-stage failing aborts
            the chain — downstream stages depend on the prior output."""
            run_dir = _ctx.get('output_dir')
            import_bundle = os.path.join(run_dir, 'records_import.json')
            manifest_csv = os.path.join(run_dir, 'manifest.csv')
            staging_dir = os.path.join(run_dir, 'attachments')
            audit_log = os.path.join(run_dir, 'audit.log')
            ran = False
            if os.path.exists(import_bundle):
                RecordsImportCommand().execute(
                    params, input=import_bundle, audit_log=audit_log)
                ran = True
            if os.path.exists(manifest_csv):
                RecordsAttachmentsCommand().execute(
                    params, manifest=manifest_csv,
                    staging_dir=staging_dir, audit_log=audit_log,
                    dry_run=False)
                RecordsSharesCommand().execute(
                    params, manifest=manifest_csv,
                    skip_missing_users=False, audit_log=audit_log,
                    dry_run=False)
                ran = True
            return 'PASSED' if ran else 'SKIPPED'

        def stage_capture_state(_ctx):
            state_path = os.path.join(_ctx.get('output_dir'), 'target_state.json')
            cmd = CaptureTargetStateCommand()
            cmd.execute(params, output=state_path,
                        include_fields=False, prefix='')
            _ctx.set('target_state_path', state_path)
            return 'PASSED'

        def stage_verify(_ctx):
            state_path = _ctx.get('target_state_path')
            if not state_path:
                return 'SKIPPED'
            cmd = VerifyCommand()
            cmd.execute(params,
                        inventory=_ctx.get('inventory_path'),
                        target_state=state_path,
                        output=os.path.join(_ctx.get('output_dir'), 'checks.csv'))
            return 'PASSED'

        def stage_reconcile(_ctx):
            state_path = _ctx.get('target_state_path')
            if not state_path:
                return 'SKIPPED'
            cmd = ReconcileCommand()
            cmd.execute(params,
                        inventory=_ctx.get('inventory_path'),
                        target_state=state_path,
                        output=os.path.join(_ctx.get('output_dir'), 'reconciliation.md'))
            return 'PASSED'

        # Map to STAGE_ORDER names where they match; use custom names otherwise.
        # 'plan' is source-only (not wired). 'gate' unused. 'records' deferred.
        stages['structure'] = stage_structure
        stages['users'] = stage_users
        stages['records'] = stage_records
        stages['verify'] = stage_verify
        stages['reconcile'] = stage_reconcile
        # capture_state isn't in STAGE_ORDER; chain it via the orchestrator
        # by extending the stages dict. Note: orchestrator looks up by name
        # in STAGE_ORDER, so capture_state piggy-backs via the verify stage
        # running capture first if needed. Simpler: call capture from
        # stage_verify/reconcile so we get a fresh snapshot each time.
        def _wrap_capture_then(fn):
            def wrapped(_ctx):
                stage_capture_state(_ctx)
                return fn(_ctx)
            return wrapped

        stages['verify'] = _wrap_capture_then(stage_verify)
        stages['reconcile'] = _wrap_capture_then(stage_reconcile)
        return stages


class TransitionCheckCommand(Command):
    def get_parser(self):
        return transition_parser

    def execute(self, params, **kwargs):
        from .transition import UserTransitionChecker
        if kwargs.get('inventory'):
            checker = UserTransitionChecker.from_inventory(
                kwargs['inventory'], kwargs['target_users_csv'],
                target_label=kwargs.get('target_label', ''))
        else:
            checker = UserTransitionChecker.from_roster(
                kwargs['roster'], kwargs['target_users_csv'],
                target_label=kwargs.get('target_label', ''))
        return checker.run(kwargs['csv_output'], kwargs['md_output'])


class AssembleInventoryCommand(Command):
    def get_parser(self):
        return assemble_parser

    def execute(self, params, **kwargs):
        from .inventory import InventoryAssembler
        asm = InventoryAssembler(
            tmp_dir=kwargs['input_dir'],
            prefix=kwargs.get('prefix', ''),
            scope_node=kwargs.get('scope_node', ''),
            source_user=kwargs.get('source_user', ''),
            source_server=kwargs.get('source_server', ''),
            source_root=kwargs.get('source_root', ''),
            target_user=kwargs.get('target_user', ''),
            target_root=kwargs.get('target_root', ''),
        )
        inventory, checksum = asm.write(kwargs['output'])
        logging.info('Counts: %s | SHA-256: %s', inventory['counts'], checksum)
        return inventory


class ConvertCommand(Command):
    def get_parser(self):
        return convert_parser

    def execute(self, params, **kwargs):
        from .converter import RecordConverter
        converter = RecordConverter(
            include_sf=kwargs.get('include_sf', False),
            split_by_type=kwargs.get('split_by_type', False),
        )
        return converter.run(
            input_dir=kwargs['input_dir'],
            output_path=kwargs['output'],
            compliance_csv=kwargs.get('compliance_csv'),
            sf_json=kwargs.get('sf_json'),
        )


def _load_run_spec_if_any(run_dir):
    """Load migration.yaml from run_dir. Empty dict when not present.

    IMPORTANT: we ONLY swallow FileNotFoundError. A corrupt migration.yaml
    is NOT the same as "no spec" — silently treating it as empty would
    evaporate Layer 4 of the source-mode interlock (spec.source.
    enterprise_name can't cross-check what the operator typed). Raise
    so the caller sees the parse error instead of running with no
    safeguards.
    """
    if not run_dir:
        return {}
    from .wizard import load_migration_yaml
    try:
        return load_migration_yaml(run_dir) or {}
    except FileNotFoundError:
        return {}
    # Anything else — JSONDecodeError, YAMLError, UnicodeDecodeError,
    # PermissionError — must propagate so the operator fixes the spec.


def _enforce_source_mode_from_kwargs(params, kwargs, subcommand):
    """Wrapper around safeguards.enforce_source_mode that plumbs
    kwargs → safeguard arguments consistently across subcommands."""
    from .safeguards import enforce_source_mode
    run_spec = _load_run_spec_if_any(kwargs.get('run_dir', ''))
    enforce_source_mode(
        params, run_spec,
        confirm_flag=bool(kwargs.get('confirm_source_destructive')),
        expected_tenant_name=kwargs.get('expected_tenant_name', ''),
        subcommand=subcommand,
    )


def _detect_target_root(params):
    """Return the target-tenant top-level node name ('' on any failure)."""
    ent = getattr(params, 'enterprise', None) or {}
    for n in ent.get('nodes', []) or []:
        if not n.get('parent_id'):
            return n.get('data', {}).get('displayname', '') or ent.get('enterprise_name', '')
    return ''


# ── Destructive-command marker + registry ──────────────────────────
#
# The 4 source-destructive subcommands (cleanup, decommission,
# take-ownership, transfer-user) must always apply the source-mode
# interlock before any write. Before v1.4.1 this relied on each
# Command remembering to call `_enforce_source_mode_from_kwargs`
# inside its execute(). A future destructive Command that forgot
# would silently bypass the guard.
#
# DestructiveCommand makes the guard structural:
#   1. Every destructive Command inherits from it.
#   2. The subclass MUST set `SUBCOMMAND = '<name>'` as a class attr.
#   3. __init_subclass__ enforces (2) at import time — forgetting
#      SUBCOMMAND raises DestructiveCommandMisconfigured.
#   4. The class is auto-registered in DESTRUCTIVE_COMMANDS so the
#      test suite can verify every destructive-by-call-graph Command
#      is in fact a DestructiveCommand.
#
# Subclasses implement `_run(params, **kwargs)`. The base class's
# execute() handles MCContext wrap + source-mode enforcement + dispatch.

DESTRUCTIVE_COMMANDS: list = []


class DestructiveCommand(Command):
    """Base class for subcommands that write destructive changes.

    Subclasses override `_run(params, **kwargs)` and set
    `SUBCOMMAND = '<cli-name>'` as a class attr. `execute()` is
    implemented here — it enforces the source-mode interlock BEFORE
    any subclass code runs. Impossible to forget because the check
    is in the inherited execute().

    Subclasses that need MC-context wrapping (--mc flag) do it inside
    their own _run(); we don't bake MCContext in here because only
    `cleanup` uses it among the destructive commands.
    """

    SUBCOMMAND: str = ''   # MUST be set by subclasses

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # Each direct subclass must declare its subcommand name.
        if not getattr(cls, 'SUBCOMMAND', ''):
            from .safeguards import DestructiveCommandMisconfigured
            raise DestructiveCommandMisconfigured(
                f'{cls.__name__}: DestructiveCommand subclass must set '
                f'`SUBCOMMAND = "<name>"` (e.g. "cleanup").'
            )
        DESTRUCTIVE_COMMANDS.append(cls)

    def execute(self, params, **kwargs):
        # Source-mode interlock runs FIRST, before any subclass logic.
        # Dry-run bypasses the guard — dry-runs are always safe.
        if not bool(kwargs.get('dry_run')):
            from .safeguards import SafeguardBlocked
            try:
                _enforce_source_mode_from_kwargs(
                    params, kwargs, subcommand=self.SUBCOMMAND)
            except SafeguardBlocked as e:
                # Return the standard blocked-dict shape (preserves
                # compat with callers that inspect the result rather
                # than catching the exception — notably run_migration
                # orchestrator and anyone scripting subcommand use).
                logging.error('SAFEGUARD: %s', e)
                return {'blocked': True, 'reason': str(e)}
        return self._run(params, **kwargs)

    def _run(self, params, **kwargs):
        raise NotImplementedError(
            f'{self.__class__.__name__} must implement _run()')


class StructureCommand(Command):
    def get_parser(self):
        return structure_parser

    def _parse_step_range(self, spec):
        """'0-12' → (0, 12); '4-6' → (4, 6). Raises ValueError on malformed input.

        Critical: silently falling back to full range 0-12 would execute every
        destructive step when a user typo'd `--steps 0_5` instead of `0-5`.
        """
        try:
            lo_str, hi_str = spec.split('-', 1)
            lo = int(lo_str)
            hi = int(hi_str)
        except (ValueError, AttributeError) as e:
            raise ValueError(
                f'invalid --steps {spec!r}; expected N-M (e.g. 0-12 or 4-6)'
            ) from e
        if lo < 0 or hi > 12 or lo > hi:
            raise ValueError(
                f'--steps out of range: {lo}-{hi} (must be within 0-12 and lo<=hi)'
            )
        return lo, hi

    def _load_plan_json(self, plan_dir, filename):
        path = os.path.join(plan_dir, filename)
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return json.load(f)

    def _load_from_inventory(self, inventory_path):
        with open(inventory_path) as f:
            inv = json.load(f)
        entities = inv.get('entities', {}) or {}
        # Bug 23 — derive a `shared_folder_membership.json` from the
        # inventory's SF entries so step_sf_membership has something
        # to apply. Pre-fix, --inventory mode silently skipped SF
        # membership migration entirely (only --plan mode triggered
        # it). The derived file lives next to the inventory and uses
        # the same filename Commander's `apply-membership` defaults
        # to, so re-runs see the same input.
        sfs = entities.get('shared_folders', []) or []
        membership_path = ''
        if sfs:
            membership_path = self._write_derived_membership(
                inventory_path, sfs)
        # Bug 40 — write a `record_types.json` next to the inventory
        # when the inventory carries record_types. Pre-fix this set
        # `record_types_path=''` and step_record_types short-circuited;
        # custom enterprise types never landed on target. Inventory
        # builders pre-Bug-40 don't populate `entities.record_types`,
        # in which case we keep the legacy empty-path behaviour.
        record_types = entities.get('record_types', []) or []
        record_types_path = ''
        if record_types:
            record_types_path = self._write_derived_record_types(
                inventory_path, record_types)
        return {
            'nodes': entities.get('nodes', []) or [],
            'teams': entities.get('teams', []) or [],
            'roles_complete': entities.get('roles', []) or [],
            'users': entities.get('users', []) or [],
            'vault_folders': entities.get('vault_folders', []) or [],
            'record_types_path': record_types_path,
            'membership_path': membership_path,
            'membership_flat': '',
            'user_memberships_available': True,  # inventory carries teams/roles lists
        }

    def _write_derived_record_types(self, inventory_path, record_types):
        """Bug 40 — materialize inventory's `entities.record_types` into the
        `{"record_types":[...]}` shape Commander's LoadRecordTypeCommand
        consumes, next to the inventory file. Re-runs reuse the same path.
        """
        path = os.path.join(os.path.dirname(inventory_path) or '.',
                            'record_types.json')
        with open(path, 'w') as f:
            json.dump({'record_types': record_types}, f, indent=2)
        return path

    def _write_derived_membership(self, inventory_path, sfs):
        """Convert inventory's `entities.shared_folders` list into the
        shape Commander's `apply-membership` consumes (KeeperJsonImporter
        with users_only=True). Writes to
        `<inv_dir>/shared_folder_membership.json` and returns that path.

        Output format (mirrors `download-membership`):
          {
            "shared_folders": [
              {"uid": ..., "path": ...,
               "manage_users": ..., "manage_records": ...,
               "can_edit": ..., "can_share": ...,
               "permissions": [
                 {"name": email_or_team_name,
                  "manage_users": ..., "manage_records": ...},
                 ...]
              },
              ...]
          }
        """
        out_sfs = []
        for sf in sfs:
            perms = []
            for u in sf.get('users') or []:
                name = (u.get('username') or u.get('name') or '').strip()
                if not name:
                    continue
                perms.append({
                    'name': name,
                    'manage_users': bool(u.get('manage_users', False)),
                    'manage_records': bool(u.get('manage_records', False)),
                })
            for t in sf.get('teams') or []:
                name = (t.get('name') or t.get('team_name') or '').strip()
                if not name:
                    continue
                perms.append({
                    'name': name,
                    'manage_users': bool(t.get('manage_users', False)),
                    'manage_records': bool(t.get('manage_records', False)),
                })
            out_sfs.append({
                'uid': sf.get('uid', ''),
                'path': sf.get('name', ''),
                'manage_users': bool(sf.get('default_manage_users', False)),
                'manage_records': bool(sf.get('default_manage_records', False)),
                'can_edit': bool(sf.get('default_can_edit', False)),
                'can_share': bool(sf.get('default_can_share', False)),
                'permissions': perms,
            })
        out = {'shared_folders': out_sfs}
        path = os.path.join(
            os.path.dirname(os.path.abspath(inventory_path)),
            'shared_folder_membership.json')
        with open(path, 'w') as f:
            json.dump(out, f, indent=2)
        os.chmod(path, 0o600)
        return path

    def _load_from_plan_dir(self, plan_dir):
        nodes = self._load_plan_json(plan_dir, 'nodes.json') or []
        if isinstance(nodes, dict):
            nodes = list(nodes.values())
        teams = self._load_plan_json(plan_dir, 'teams.json') or []
        if isinstance(teams, dict):
            teams = list(teams.values())
        users = self._load_plan_json(plan_dir, 'users.json') or []
        if isinstance(users, dict):
            users = list(users.values())
        return {
            'nodes': nodes,
            'teams': teams,
            'roles_complete': self._load_plan_json(plan_dir, 'roles_complete.json') or [],
            'users': users,
            # plan-dir path doesn't stage vault_folders — the CSV/JSON
            # layout predates the PR-A capture. Use --inventory for full
            # vault-folder restore.
            'vault_folders': [],
            'record_types_path': os.path.join(plan_dir, 'record_types.json'),
            'membership_path': os.path.join(plan_dir, 'shared_folder_membership.json'),
            'membership_flat': os.path.join(plan_dir, 'shared_folder_membership_flat.json'),
            'user_memberships_available': False,  # plan-dir users.json lacks teams/roles lists
        }

    def _users_have_memberships(self, users):
        """True if at least one user carries a `teams` or `roles` list."""
        for u in users or []:
            if u.get('teams') or u.get('roles'):
                return True
        return False

    def execute(self, params, **kwargs):
        from .structure import StructureRestore
        from .commander_clients import CommanderStructureClient, sync_down
        from .dry_run import DryRun, classify_plan, render_report, summarize
        from .mc_context import MCContext

        with MCContext(params, kwargs.get('mc', '')) as ctx:
            return self._run(ctx.params, kwargs)

    def _run(self, params, kwargs):
        from .structure import StructureRestore
        from .commander_clients import CommanderStructureClient, sync_down
        from .dry_run import DryRun, classify_plan, render_report, summarize
        from .safeguards import banner_for

        banner_for('structure', dry_run=bool(kwargs.get('dry_run')),
                   details=[f'scope: {kwargs.get("scope_node", "") or "(full tenant)"}',
                            f'steps: {kwargs.get("steps", "0-12")}'])

        if kwargs.get('plan'):
            if not os.path.isdir(kwargs['plan']):
                logging.error('Plan dir not found: %s', kwargs['plan'])
                return
            data = self._load_from_plan_dir(kwargs['plan'])
        else:
            if not os.path.isfile(kwargs['inventory']):
                logging.error('Inventory file not found: %s', kwargs['inventory'])
                return
            data = self._load_from_inventory(kwargs['inventory'])

        target_root = kwargs.get('target_root') or _detect_target_root(params) or 'Root'
        source_root = kwargs.get('source_root') or 'My company'
        scope_node = kwargs.get('scope_node', '')

        sync_down(params)
        real_client = CommanderStructureClient(params)
        dry = bool(kwargs.get('dry_run'))
        client = DryRun(real_client) if dry else real_client
        restore = StructureRestore(
            client, source_root=source_root, target_root=target_root,
            scope_node=scope_node,
            # Throttle management: structure's enforcement loop on a
            # full-tenant restore hammers the API with ~50 roles × ~40
            # enforcements each, which without pacing burns hours in
            # Commander's hardcoded 30/60/120s backoff ladder. These
            # four knobs plumb per-call pacing through every step loop.
            delay=float(kwargs.get('delay', 0.0) or 0.0),
            jitter=float(kwargs.get('jitter', 0.0) or 0.0),
            reserve_quota_every=int(kwargs.get('reserve_quota_every', 0) or 0),
            reserve_quota_seconds=float(
                kwargs.get('reserve_quota_seconds', 2.0) or 2.0),
            # G7 — opt-in resume. Off by default; when on, every step
            # pre-filters its source input by querying current target
            # state and skipping rows already created on target.
            resume=bool(kwargs.get('resume', False)),
            # Bug 73 — opt-in: skip the rename-with-suffix
            # disambiguation for duplicate node names. Off by default
            # (target gets unique names like 'Finance (Subsidiary B)');
            # when on, falls through to the SDK boundary's direct
            # `node_add` bypass which sends duplicate displaynames to
            # the server. Only safe when the server is verified to
            # accept duplicate displaynames under distinct parents
            # (rehearsal-15+ live-test pending).
            preserve_duplicate_node_names=bool(
                kwargs.get('preserve_duplicate_node_names', False)),
            # v1.7 — opt-in: apply lockout-risk enforcements on
            # builtin-admin roles. Default off keeps the operator safe
            # from cross-tenant drift causing target-tenant lockout
            # (2026-04-26 incident). When on, restores pre-v1.7
            # behavior.
            apply_admin_lockout_risk_enforcements=bool(
                kwargs.get('apply_admin_lockout_risk_enforcements', False)),
        )

        lo, hi = self._parse_step_range(kwargs.get('steps') or '0-12')
        nodes = data['nodes']
        teams = data['teams']
        roles_complete = data['roles_complete']
        users = data['users']

        record_types_path = data['record_types_path']
        membership_path = data['membership_path']
        membership_flat = data['membership_flat']

        user_mem_ok = data.get('user_memberships_available') or self._users_have_memberships(users)

        # Step dispatch
        if lo <= 0 <= hi and record_types_path and os.path.exists(record_types_path):
            restore.step_record_types(record_types_path)
        if lo <= 1 <= hi:
            restore.step_nodes(nodes)
        if lo <= 2 <= hi:
            restore.step_isolated_flags(nodes)
        if lo <= 3 <= hi:
            restore.step_teams(teams)
        if lo <= 4 <= hi:
            restore.step_roles(roles_complete or [])
        if lo <= 5 <= hi and roles_complete:
            restore.step_managed_nodes(roles_complete)
        if lo <= 6 <= hi and roles_complete:
            from .enforcement_direct import (
                record_types_value_to_names, set_role_enforcements_direct,
            )

            def _direct(role_name, direct_enfs):
                return set_role_enforcements_direct(params, role_name, direct_enfs)

            def _record_types(value):
                return record_types_value_to_names(value, params=params)

            restore.step_enforcements(roles_complete,
                                       direct_api_fn=_direct,
                                       record_types_translator=_record_types)
        if lo <= 7 <= hi:
            restore.step_user_nodes(users)
        if lo <= 8 <= hi:
            if user_mem_ok:
                restore.step_user_teams(users)
            else:
                logging.warning('Step 8 (user→team): plan-dir users.json lacks '
                                'team memberships — use --inventory for this step.')
        if lo <= 9 <= hi and roles_complete:
            restore.step_role_users(roles_complete)
        if lo <= 10 <= hi and roles_complete:
            restore.step_role_teams(roles_complete)
        # Step 11 (PR-B) — personal-vault folder hierarchy. Runs
        # BEFORE step 12 (sf_membership) so any SFs in the vault-
        # folder list exist on target before apply-membership tries
        # to attach permissions. The uid_map returned here is the
        # bridge records-import / records-shares will consume to
        # place imported records in the right target folders.
        # (Bug 27 fix — pre-fix, step ordering had sf_membership at
        # 11 and vault_folders at 12; apply-membership silent-skipped
        # for personal-vault SFs that hadn't been created yet.)
        vault_folders = data.get('vault_folders') or []
        action_plan = {}
        nested_plan_path = kwargs.get('nested_sf_plan') or ''
        overrides_path = kwargs.get('overrides') or ''
        accept_risk = bool(kwargs.get('accept_risk'))
        applied_overrides_audit: list = []
        if nested_plan_path:
            if not os.path.isfile(nested_plan_path):
                logging.warning('nested-sf-plan path not found: %s — '
                                'continuing without nested-SF actions',
                                nested_plan_path)
            else:
                from .nested_sf_plan import action_lookup, load_plan
                try:
                    loaded_plan = load_plan(nested_plan_path)
                except (OSError, json.JSONDecodeError) as e:
                    logging.warning('failed to load nested-sf-plan %s: %s',
                                    nested_plan_path, e)
                    loaded_plan = None
                if loaded_plan is not None:
                    if overrides_path:
                        from .overrides import (OverridesValidationError,
                                                  format_validation_errors,
                                                  load_validate_apply)
                        try:
                            loaded_plan, applied_overrides_audit = (
                                load_validate_apply(
                                    overrides_path, loaded_plan,
                                    accept_risk=accept_risk))
                            logging.info(
                                'overrides: %d delta(s) applied from %s',
                                len(applied_overrides_audit),
                                overrides_path)
                        except OverridesValidationError as e:
                            logging.error(
                                format_validation_errors(
                                    e.errors, path=overrides_path))
                            return None
                    action_plan = action_lookup(loaded_plan)
                    logging.info('nested-sf-plan: %d subfolder(s) with '
                                 'per-row actions', len(action_plan))
        elif overrides_path:
            logging.error(
                '--overrides %s passed but --nested-sf-plan not '
                'set; overrides apply to the nested-SF plan only. '
                'Re-run with both flags or drop --overrides.',
                overrides_path)
            return None
        if lo <= 11 <= hi and vault_folders:
            uid_map = restore.step_vault_folders(
                vault_folders, action_plan=action_plan)
            # Persist uid_map alongside the run so downstream stages can
            # translate source-UIDs to target-UIDs without having to
            # re-walk the folder cache.
            run_dir = kwargs.get('run_dir') or ''
            if run_dir and os.path.isdir(run_dir):
                try:
                    uid_map_path = os.path.join(run_dir,
                                                 'vault_folder_uid_map.json')
                    with open(uid_map_path, 'w') as f:
                        json.dump(uid_map, f, indent=2)
                    os.chmod(uid_map_path, 0o600)
                except OSError as e:
                    logging.warning('could not persist vault_folder_uid_map: %r',
                                    e)
        # Step 12 (Bug 27 reorder) — sf_membership now runs AFTER
        # vault_folders so personal-vault SFs created in step 11 are
        # already on target when apply-membership tries to attach
        # permissions to them.
        if lo <= 12 <= hi and membership_path and os.path.exists(membership_path):
            restore.step_sf_membership(
                membership_path,
                membership_flat if (membership_flat and os.path.exists(membership_flat)) else None,
            )

        if dry:
            target_state = _params_enterprise_to_target_state(params)
            classified = classify_plan(client, target_state)
            counts = summarize(classified)
            logging.info('[dry-run] plan: %s', counts)
            report_path = kwargs.get('dry_run_report') or None
            if report_path:
                with open(report_path, 'w') as f:
                    f.write(render_report(classified, counts))
                # Report lists entity names + scoped tenant — 0600 so
                # it's consistent with take-ownership / transfer-user /
                # decommission reports.
                os.chmod(report_path, 0o600)
                logging.info('[dry-run] report: %s', report_path)
            return {'dry_run': True, 'counts': counts, 'classified': classified}

        logging.info('Structure restore summary: %s', restore.counters)

        # Audit event — feeds `tenant-migrate undo` which deletes the
        # created entities in reverse dependency order.
        try:
            from .audit import append_audit_event
            created = {'nodes': [], 'teams': [], 'roles': [], 'shared_folders': []}
            for r in restore.results:
                if r.action != 'create' or r.status != 'SUCCESS':
                    continue
                key = {'node': 'nodes', 'team': 'teams', 'role': 'roles'}.get(r.category)
                if key:
                    created[key].append(r.name)
            input_path = kwargs.get('inventory') or kwargs.get('plan') or ''
            # Phase 8 unified fallback: prefer explicit run_dir over
            # dirname(input). Top-level run_dir is the canonical home
            # of the audit chain (dsk_hooks.py:20 contract).
            audit_log = kwargs.get('audit_log') or os.path.join(
                kwargs.get('run_dir') or os.path.dirname(input_path)
                or '.', 'audit.log')
            audit_summary = {'created_entities': created,
                             'counters': dict(restore.counters)}
            if restore.resume:
                # Resume telemetry — surfaces the `--resume` outcome
                # to the audit log so an operator can confirm a re-run
                # was a clean no-op (resume_skipped == total ops, 0
                # SUCCESS) vs a real recovery (some SUCCESS lines
                # noted as 'created — was missing on resume').
                audit_summary['resume'] = {
                    'enabled': True,
                    'skipped_already_present': restore.resume_skipped,
                    'reconciled': restore.resume_reconciled,
                }
            if applied_overrides_audit:
                # T2.5 — every applied user override lands in the
                # audit chain so support can later answer "what did
                # the customer change from operator's defaults?".
                audit_summary['overrides'] = {
                    'source': os.path.abspath(overrides_path)
                              if overrides_path else '',
                    'count': len(applied_overrides_audit),
                    'entries': applied_overrides_audit,
                }
            # Rename logs from step_teams / step_roles.
            # `dedupe_team_names` / `dedupe_role_names` rename
            # duplicate-name teams/roles to `<name> [<leaf>]` to
            # disambiguate. Previously the rename information was
            # produced but dropped on the floor — neither the audit
            # nor downstream subcommands (users.py) had visibility.
            # Now it lands in the audit event for operator inspection.
            # (Full rename-aware routing in users.py needs per-user-
            # node disambiguation logic and is tracked separately.)
            if (restore.team_rename_log or restore.role_rename_log
                    or restore.node_rename_log):
                audit_summary['renames'] = {
                    'teams': [
                        {'original': orig, 'source_node': node,
                         'renamed': renamed}
                        for orig, node, renamed in restore.team_rename_log
                    ],
                    'roles': [
                        {'original': orig, 'source_node': node,
                         'renamed': renamed}
                        for orig, node, renamed in restore.role_rename_log
                    ],
                    'nodes': [
                        {'original': orig, 'source_node': parent,
                         'renamed': renamed}
                        for orig, parent, renamed in restore.node_rename_log
                    ],
                }
            append_audit_event(audit_log, {
                'subcommand': 'structure',
                'inputs': {'source': os.path.abspath(input_path)} if input_path else {},
                'summary': audit_summary,
            })
        except OSError as _e:
            logging.warning('structure audit emit skipped (I/O error): %s', _e)

        # Bug 51 / v1.5.5 — emit per-step results CSV alongside the
        # audit event so operators can enumerate FAILED/SKIPPED items
        # without grep-archaeology on stdout. The audit summary's
        # `counters` dict tells you "FAILED=18" but not which 18; this
        # CSV closes that gap. Best-effort — failure to write is
        # logged at WARNING and doesn't break the migration.
        try:
            import csv as _csv
            results_dir = (os.path.dirname(audit_log)
                           if audit_log else
                           (os.path.dirname(input_path) or '.'))
            results_csv = os.path.join(results_dir, 'structure_results.csv')
            with open(results_csv, 'w', newline='') as _f:
                _w = _csv.writer(_f)
                _w.writerow(['category', 'name', 'action',
                             'status', 'notes'])
                for r in restore.results:
                    _w.writerow([r.category, r.name, r.action,
                                 r.status, r.notes])
            os.chmod(results_csv, 0o600)
            logging.info('per-step results: %s', results_csv)
        except OSError as _e:
            logging.warning('structure_results.csv emit skipped (I/O '
                            'error): %s', _e)

        # Bug 63 (v1.6) — emit categorized SKIP audit alongside
        # structure_results.csv. Operator-facing answer to "what was
        # skipped and why": classifies each SKIPPED row into
        # by-design / bug-pending / source-quality / target-capability /
        # cascade / unknown, and emits actionable guidance per category.
        # Surfaces unknowns prominently — they're the most likely
        # signal of a new plugin bug.
        try:
            from .skip_audit import audit_structure_results, write_audit_csv
            audit_dir = (os.path.dirname(audit_log)
                         if audit_log else
                         (os.path.dirname(input_path) or '.'))
            audit_csv_in = os.path.join(audit_dir, 'structure_results.csv')
            audit_csv_out = os.path.join(audit_dir, 'skip_audit.csv')
            audit_rows = audit_structure_results(audit_csv_in)
            if audit_rows:
                counts = write_audit_csv(audit_rows, audit_csv_out)
                logging.info('skip audit: %s', counts)
                if counts.get('unknown', 0) > 0:
                    logging.warning(
                        'skip audit: %d UNKNOWN SKIP(s) — likely a '
                        'new plugin bug; investigate before next '
                        'rehearsal. See %s',
                        counts['unknown'], audit_csv_out)
        except (OSError, ImportError) as _e:
            logging.warning('skip_audit.csv emit skipped: %s', _e)

        # Bug 61 (v1.6) — persist rename map so verify can correctly
        # match source roles/teams against their renamed counterparts on
        # target. Without this, source-role lookup-by-name in
        # validate.phase_roles fails for every disambiguated duplicate
        # (e.g. 'Departaments - Finance Interns' on two source nodes
        # both got node-suffix renames; verify reported 7+ NOT FOUND in
        # rehearsal-10 even though all roles were created successfully).
        # Keyed by (original_name, source_node) → renamed target name.
        try:
            rename_dir = (os.path.dirname(audit_log)
                          if audit_log else
                          (os.path.dirname(input_path) or '.'))
            rename_path = os.path.join(rename_dir, 'rename_map.json')
            with open(rename_path, 'w') as _f:
                json.dump({
                    'roles': [
                        {'original': orig, 'source_node': node,
                         'renamed': renamed}
                        for orig, node, renamed in restore.role_rename_log
                    ],
                    'teams': [
                        {'original': orig, 'source_node': node,
                         'renamed': renamed}
                        for orig, node, renamed in restore.team_rename_log
                    ],
                    # Bug 73 — node disambiguation parallels teams/roles.
                    # `source_node` here is the source PARENT (the field
                    # that disambiguates duplicate leaf names).
                    'nodes': [
                        {'original': orig, 'source_node': parent,
                         'renamed': renamed}
                        for orig, parent, renamed in restore.node_rename_log
                    ],
                }, _f, indent=2)
            os.chmod(rename_path, 0o600)
            logging.info('rename map: %s', rename_path)
        except OSError as _e:
            logging.warning('rename_map.json emit skipped (I/O '
                            'error): %s', _e)
        return restore.counters


class UsersCommand(Command):
    def get_parser(self):
        return users_parser

    def execute(self, params, **kwargs):
        from .mc_context import MCContext
        with MCContext(params, kwargs.get('mc', '')) as ctx:
            return self._run(ctx.params, kwargs)

    def _run(self, params, kwargs):
        from .users import UserRunner
        from .commander_clients import CommanderUserClient, sync_down
        from .dry_run import DryRun, classify_plan, render_report, summarize
        from .safeguards import banner_for

        banner_for('users', dry_run=bool(kwargs.get('dry_run')))

        with open(kwargs['inventory']) as f:
            inventory = json.load(f)

        roster = []
        with open(kwargs['roster'], newline='') as f:
            import csv
            reader = csv.DictReader(f)
            for row in reader:
                email = (row.get('email') or row.get('Email') or '').strip()
                if email:
                    roster.append({
                        'email': email,
                        'full_name': (row.get('full_name') or row.get('name') or '').strip(),
                    })

        transition_plan = None
        if kwargs.get('transition_plan'):
            transition_plan = []
            with open(kwargs['transition_plan'], newline='') as f:
                import csv
                for row in csv.DictReader(f):
                    transition_plan.append(row)

        target_root = kwargs.get('target_root') or _detect_target_root(params) or 'Root'
        sync_down(params)
        real_client = CommanderUserClient(params)
        dry = bool(kwargs.get('dry_run'))
        client = DryRun(real_client) if dry else real_client
        from .email_remap import log_remap_banner
        log_remap_banner(kwargs.get('old_domain', ''),
                          kwargs.get('new_domain', ''))
        # Checkpoint wiring — invite itself isn't idempotent (each call
        # sends an email), so --resume is extra-important: you don't want
        # to re-invite users you already invited in the prior run.
        from .checkpoint import Checkpoint, CheckpointMismatchError
        ckpt = None
        if not dry:
            run_dir = kwargs.get('run_dir') or (
                os.path.dirname(kwargs['roster']) or '.')
            ckpt = Checkpoint('users', run_dir)

        runner = UserRunner(
            client,
            source_root=kwargs.get('source_root') or 'My company',
            target_root=target_root,
            default_node=kwargs.get('default_node') or target_root,
            old_domain=kwargs.get('old_domain', ''),
            new_domain=kwargs.get('new_domain', ''),
            delay=kwargs.get('delay', 0.0),
            batch_size=kwargs.get('batch_size', 0),
            sso_policy=kwargs.get('sso_policy', 'warn'),
            checkpoint=ckpt,
            resume=bool(kwargs.get('resume')),
            force_restart=bool(kwargs.get('force_restart')),
        )
        try:
            results = runner.run(roster, inventory=inventory,
                                  transition_plan=transition_plan)
        except CheckpointMismatchError as e:
            logging.error('%s', e)
            return {'blocked': True, 'reason': 'checkpoint mismatch'}
        for r in results:
            logging.info('  %s → %s (category=%s)', r.email, r.status, r.category)

        if not dry:
            # Audit event feeds `tenant-migrate undo` — without the
            # invited_emails list the undo planner has nothing to lock.
            try:
                from .audit import append_audit_event
                invited = [r.email for r in results
                           if r.status in ('YES', 'EXTENDED')]
                # Phase 8 unified fallback: prefer explicit run_dir.
                audit_log = kwargs.get('audit_log') or os.path.join(
                    kwargs.get('run_dir') or os.path.dirname(
                        kwargs['inventory']) or '.', 'audit.log')
                append_audit_event(audit_log, {
                    'subcommand': 'users',
                    'inputs': {'inventory': os.path.abspath(kwargs['inventory']),
                                'roster': os.path.abspath(kwargs['roster'])},
                    'summary': {
                        'invited_emails': invited,
                        'counts': {
                            'total': len(results),
                            'invited': sum(1 for r in results if r.status == 'YES'),
                            'extended': sum(1 for r in results if r.status == 'EXTENDED'),
                            'existing': sum(1 for r in results if r.status == 'EXISTS'),
                            'blocked': sum(1 for r in results if r.status == 'BLOCKED'),
                            'failed': sum(1 for r in results if r.status == 'FAILED'),
                        },
                    },
                })
            except OSError as _e:
                logging.warning('users audit emit skipped (I/O error): %s', _e)

        if dry:
            target_state = _params_enterprise_to_target_state(params)
            classified = classify_plan(client, target_state)
            counts = summarize(classified)
            logging.info('[dry-run] plan: %s', counts)
            if kwargs.get('dry_run_report'):
                with open(kwargs['dry_run_report'], 'w') as f:
                    f.write(render_report(classified, counts))
                os.chmod(kwargs['dry_run_report'], 0o600)
                logging.info('[dry-run] report: %s', kwargs['dry_run_report'])
            return {'dry_run': True, 'counts': counts, 'classified': classified}
        return results


class VerifyCommand(Command):
    def get_parser(self):
        return verify_parser

    def execute(self, params, **kwargs):
        from .audit import append_audit_event, hash_verify_receipt
        from .validate import (Validator, ValidationContext, summarize,
                                load_structure_skipped_enforcements,
                                load_structure_skipped_privileges,
                                load_structure_skipped_privileges_set,
                                detect_users_stage_status)
        with open(kwargs['inventory']) as f:
            inventory = json.load(f)
        with open(kwargs['target_state']) as f:
            target_state = json.load(f)
        # Cross-region advisory: source + target on different data centers
        # is a compliance-sensitive scenario — log a prominent notice.
        src_dc = _keeper_dc_for_server(inventory.get('source_server', ''))
        tgt_dc = (target_state.get('data_center') or
                  _keeper_dc_for_server(target_state.get('server', '')))
        if src_dc and tgt_dc and src_dc != tgt_dc:
            logging.warning(
                '⚠ CROSS-REGION migration: source=%s target=%s — verify '
                'legal/compliance requirements for data residency before '
                'proceeding to any destructive stage.', src_dc, tgt_dc,
            )
        # Bug 61 (v1.6) — load rename_map persisted by the structure
        # stage so verify can match source roles/teams against their
        # node-suffix-renamed counterparts on target.
        rename_map = _load_rename_map(kwargs.get('inventory'),
                                      kwargs.get('target_state'))
        # Bug 63 — locate skip_audit.csv next to inventory/target_state
        # so phase_skip_audit can surface unknown SKIPs as FAIL.
        # Bug 86 — locate manifest.csv too so phase_records can pair
        # source records to target via the source_uid → target_uid map
        # records-import wrote.
        for p in (kwargs.get('inventory'), kwargs.get('target_state')):
            if not p:
                continue
            sa = os.path.join(os.path.dirname(p), 'skip_audit.csv')
            if os.path.isfile(sa):
                target_state['_skip_audit_path'] = sa
            mf = os.path.join(os.path.dirname(p), 'manifest.csv')
            if os.path.isfile(mf):
                target_state['_manifest_path'] = mf
            if target_state.get('_skip_audit_path') or \
                    target_state.get('_manifest_path'):
                break
        # v1.7 / T2.2 — locate structure_results.csv next to
        # inventory/target_state and harvest per-(role, key) enforcement
        # SKIP reasons so phase_roles can sharpen its lockout-risk
        # SKIP message. Pre-v1.7 runs without per-key audit rows yield
        # an empty map; verify falls back to the generic message.
        # Bug 79 — same file feeds the role_priv SKIP-count loader so
        # the count-aggregator can subtract structure-time-skipped
        # privileges (target-edition-unsupported) before comparing.
        structure_skipped = {}
        priv_skipped = {}
        priv_skipped_set = set()
        users_stage_status = 'unknown'
        for p in (kwargs.get('inventory'), kwargs.get('target_state')):
            if not p:
                continue
            sr = os.path.join(os.path.dirname(p), 'structure_results.csv')
            if os.path.isfile(sr):
                structure_skipped = load_structure_skipped_enforcements(sr)
                priv_skipped = load_structure_skipped_privileges(sr)
                priv_skipped_set = load_structure_skipped_privileges_set(sr)
            # 2026-05-06 — read audit.log to detect whether the
            # users stage was run; phase_users uses this to downgrade
            # source-user-not-on-target NOT FOUND from FAIL to SKIP
            # when the operator hasn't yet invited users.
            # Phase 8 unified fallback: prefer explicit run_dir for
            # the read path to match the write path's resolution.
            audit_path = os.path.join(
                kwargs.get('run_dir') or os.path.dirname(p),
                'audit.log')
            if os.path.isfile(audit_path):
                users_stage_status = detect_users_stage_status(audit_path)
            if structure_skipped or priv_skipped or users_stage_status != 'unknown':
                break
        # Pass params so phase_vault_health can probe target state live.
        ctx = ValidationContext(inventory, target_state, params=params,
                                rename_map=rename_map,
                                structure_skipped_enforcements=structure_skipped,
                                structure_skipped_privileges=priv_skipped,
                                structure_skipped_privileges_set=priv_skipped_set,
                                users_stage_status=users_stage_status)
        checks = Validator(ctx).run()
        counts = summarize(checks)
        logging.info('Verify: %s', counts)
        if kwargs.get('output'):
            import csv
            with open(kwargs['output'], 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['phase', 'severity', 'message', 'detail'])
                for c in checks:
                    writer.writerow(c.as_row())
            os.chmod(kwargs['output'], 0o600)
        # Signed audit receipt — tampering with checks.csv or the Markdown
        # reconcile report after the fact no longer matches the on-chain
        # hash. audit-verify surfaces the discrepancy.
        source_counts = (inventory.get('counts') or {})
        target_counts_projected = {
            'nodes': len(target_state.get('nodes', [])),
            'teams': len(target_state.get('teams', [])),
            'roles': len(target_state.get('roles', [])),
            'users': len(target_state.get('users', [])),
            'shared_folders': len(target_state.get('shared_folders', [])),
            'records': len(target_state.get('records', [])),
        }
        receipt_hash = hash_verify_receipt(
            checks, counts=counts,
            source_counts=source_counts,
            target_counts=target_counts_projected,
        )
        # Phase 8 unified fallback: prefer explicit run_dir.
        audit_log = kwargs.get('audit_log') or (
            os.path.join(
                kwargs.get('run_dir') or os.path.dirname(kwargs['output'])
                or '.', 'audit.log')
            if kwargs.get('output') or kwargs.get('run_dir') else ''
        )
        manifest_path = ''
        if audit_log:
            # Emit a run-dir-wide SHA256SUMS manifest. Verify is the
            # natural closing step — this gives audit-verify a single
            # integrity document covering every artifact the run left
            # on disk. Harmless to re-run: it overwrites deterministically.
            from .audit import write_sha256sums
            run_dir = os.path.dirname(os.path.abspath(audit_log))
            if os.path.isdir(run_dir):
                try:
                    # Exclude audit.log from the manifest — verify APPENDS
                    # its own event to audit.log AFTER this call, which
                    # would mismatch any self-referential hash we wrote.
                    # The audit chain itself is verified separately via
                    # verify_audit_log() which walks the hash chain.
                    manifest_path = write_sha256sums(
                        run_dir, exclude=('audit.log',))
                except OSError as _e:
                    logging.warning('verify manifest emit skipped (I/O): %s', _e)

            append_audit_event(audit_log, {
                'subcommand': 'verify',
                'inputs': {'inventory': os.path.abspath(kwargs['inventory']),
                           'target_state': os.path.abspath(kwargs['target_state'])},
                'outputs': {'checks_csv': os.path.abspath(kwargs['output'])
                                          if kwargs.get('output') else '',
                            'receipt_hash': receipt_hash,
                            'manifest': manifest_path},
                'summary': {'counts': counts,
                            'source_counts': source_counts,
                            'target_counts': target_counts_projected},
                # Region stamps so compliance can prove data-flow direction.
                'regions': {'source_dc': src_dc,
                            'source_server': inventory.get('source_server', ''),
                            'target_dc': tgt_dc,
                            'target_server': target_state.get('server', ''),
                            'cross_region': bool(src_dc and tgt_dc and
                                                  src_dc != tgt_dc)},
            })
        # Fail-loud on FAIL rows. Prior behaviour: verify silently
        # exited 0 with FAIL rows in checks.csv — CI / batch callers
        # trusting the exit code missed the failure. Now: artifacts
        # already written above (checks.csv, audit receipt, run-dir
        # manifest); raise CommandError if any FAIL rows so the
        # process exits nonzero. Empty checks → warn + exit 0.
        # WARN / SKIP rows do NOT count as hard failures.
        from .validate import Severity
        if not checks:
            logging.warning('verify: no checks ran')
        else:
            fail_count = sum(1 for c in checks if c.severity is Severity.FAIL)
            if fail_count:
                from keepercommander.commands.base import CommandError
                logging.error(
                    'verify failed: %d FAIL row(s) in checks.csv', fail_count)
                raise CommandError(
                    f'verify failed: {fail_count} FAIL row(s) in checks.csv',
                )
        return {'counts': counts, 'checks': checks,
                'receipt_hash': receipt_hash,
                'manifest': manifest_path,
                'source_counts': source_counts,
                'target_counts': target_counts_projected}


class ReconcileCommand(Command):
    def get_parser(self):
        return reconcile_parser

    def execute(self, params, **kwargs):
        from .reconcile import Reconciler
        with open(kwargs['target_state']) as f:
            target_state = json.load(f)
        reconciler = Reconciler(
            kwargs['inventory'],
            target_state_provider=lambda: target_state,
        )
        result = reconciler.run(kwargs['output'])
        summary = result['summary']
        logging.info('Reconcile: %d found, %d missing (%.1f%%)',
                     summary['total_found'], summary['total_missing'],
                     summary['success_pct'])
        return result


def _params_enterprise_to_target_state(params):
    """Project Commander's `params.enterprise` dict into the target_state shape
    that verify/reconcile consume.

    Source/target schema alignment:
      - nodes:  {name, isolated, parent}
      - teams:  {name, restricts, node}
      - roles:  {name, default_role, enforcements, managed_nodes, teams,
                 users, node, visible_below}
      - users:  {email, status, node, teams, roles}
      - shared_folders: {name, default_can_edit, default_can_share,
                         default_manage_users, default_manage_records}
    """
    ent = getattr(params, 'enterprise', None) or {}

    nodes = []
    node_by_id = {}
    node_parent_ids = []  # parallel to `nodes`; one entry per source node
    for n in ent.get('nodes', []) or []:
        data = n.get('data', {}) or {}
        name = data.get('displayname') or ''
        if not name and not n.get('parent_id'):
            name = ent.get('enterprise_name', '')
        node = {'name': name, 'isolated': bool(data.get('restrict_visibility', False))}
        nodes.append(node)
        node_by_id[n.get('node_id')] = node
        node_parent_ids.append(n.get('parent_id'))
    # Bug 73 — resolve parent per-source-node, not per-name. Multiple
    # nodes can share a leaf name (e.g. Finance under Subsidiary A vs
    # Subsidiary B); the prior name-keyed map collapsed them so all
    # duplicates inherited the last-seen parent, making target_state
    # claim siblings under one parent and phase_nodes miss real
    # divergence (and treat 6 source rows as 1 target row).
    for node, pid in zip(nodes, node_parent_ids):
        parent = node_by_id.get(pid)
        node['parent'] = parent['name'] if parent else ''

    # Team/role construction routes through live_inventory so the capture
    # side shares the exact same key-mapping fixes as the source side
    # (restrict_sharing on teams, role_privileges pivot, new_user_inherit
    # on roles). Previously this had a duplicate — buggy — copy that
    # silently lost S-restrict on teams and all managed_node privileges
    # on roles.
    from .live_inventory import (
        restricts_code, build_role_pivots,
    )

    # Bug 42 + Bug 44 — node path resolver shared by user/team/role
    # projections. Pre-fix users carried a raw node_id, teams + roles
    # had no node attribute at all. Build a node_id -> backslash path
    # map matching the source-side convention so verify can compare
    # apples-to-apples. Cached across all callers in this projection.
    _node_path_by_id = {}
    _node_by_id = {n.get('node_id'): n for n in ent.get('nodes', []) or []}

    def _node_path(nid):
        cached = _node_path_by_id.get(nid)
        if cached is not None:
            return cached
        chain = []
        cur = _node_by_id.get(nid)
        seen = set()
        while cur and cur.get('node_id') not in seen:
            seen.add(cur.get('node_id'))
            data = cur.get('data', {}) or {}
            name = data.get('displayname') or ''
            if not name and not cur.get('parent_id'):
                name = ent.get('enterprise_name', '')
            if name:
                chain.append(name)
            cur = _node_by_id.get(cur.get('parent_id'))
        path = '\\'.join(reversed(chain))
        _node_path_by_id[nid] = path
        return path

    teams = []
    for t in ent.get('teams', []) or []:
        teams.append({
            'name': t.get('name', ''),
            'restricts': restricts_code(t).strip(),
            # Bug 44 — node placement so phase_teams can verify the
            # team landed on the right enterprise subtree.
            'node': _node_path(t.get('node_id')),
        })

    managed_by_role, enf_by_role, users_by_role, teams_by_role = build_role_pivots(ent)
    roles = []
    for r in ent.get('roles', []) or []:
        data = r.get('data', {}) or {}
        rid = r.get('role_id')
        new_user_flag = bool(r.get('new_user_inherit', False))
        roles.append({
            'name': data.get('displayname') or r.get('name', ''),
            'new_user': new_user_flag,
            'default_role': new_user_flag,
            'enforcements': enf_by_role.get(rid, {}) or (r.get('enforcements') or {}),
            'managed_nodes': managed_by_role.get(rid, []) or (r.get('managed_nodes') or []),
            'teams': teams_by_role.get(rid, []) or (r.get('teams') or []),
            'users': users_by_role.get(rid, []) or (r.get('users') or []),
            # Bug 44 — node + visible_below. Source-side projection emits
            # both; target was dropping them so phase_roles couldn't catch
            # a role landing in the wrong subtree (or losing scope-down
            # visibility).
            'node': _node_path(r.get('node_id')),
            'visible_below': bool(r.get('visible_below', False)),
        })

    users = []
    for u in ent.get('users', []) or []:
        u_teams = [t.get('team_name', t.get('name', ''))
                   for t in (u.get('teams') or []) if isinstance(t, dict)]
        u_roles = [r.get('role_name', r.get('name', ''))
                   for r in (u.get('roles') or []) if isinstance(r, dict)]
        users.append({
            'email': u.get('username', ''),
            'status': u.get('status', ''),
            'node': _node_path(u.get('node_id')),
            'teams': [t for t in u_teams if t],
            'roles': [r for r in u_roles if r],
        })

    # Bug 21 — capture both enterprise SFs AND personal-vault SFs.
    # `ent['shared_folders']` only carries enterprise-level SFs; personal
    # ones live in `params.shared_folder_cache`. Source-side
    # `live_inventory.build_shared_folder_entities` reads both; target
    # capture must too or `verify` would FAIL for every personally-owned
    # SF migrated by structure restore.
    # Bug 28 — extract users + teams from each SF so verify can
    # compare membership. Pre-fix the projection emitted defaults
    # only and verify reported every SF user/team as MISSING even
    # when the membership was correctly applied on target.
    def _sf_users(sf_dict):
        return [
            {
                'username': u.get('username', ''),
                'manage_users': bool(u.get('manage_users', False)),
                'manage_records': bool(u.get('manage_records', False)),
                'can_edit': bool(u.get('can_edit', False)),
                'can_share': bool(u.get('can_share', False)),
            }
            for u in (sf_dict.get('users') or [])
            if u.get('username')
        ]

    def _sf_teams(sf_dict):
        return [
            {
                'name': t.get('name', '') or t.get('team_name', ''),
                'manage_users': bool(t.get('manage_users', False)),
                'manage_records': bool(t.get('manage_records', False)),
            }
            for t in (sf_dict.get('teams') or [])
            if (t.get('name') or t.get('team_name'))
        ]

    sfs = []
    seen_uids = set()
    for sf in ent.get('shared_folders', []) or []:
        sfs.append({
            'name': sf.get('name', ''),
            'default_can_edit': bool(sf.get('default_can_edit', False)),
            'default_can_share': bool(sf.get('default_can_share', False)),
            'default_manage_users': bool(sf.get('default_manage_users', False)),
            'default_manage_records': bool(sf.get('default_manage_records', False)),
            'users': _sf_users(sf),
            'teams': _sf_teams(sf),
        })
        uid = sf.get('shared_folder_uid') or sf.get('uid')
        if uid:
            seen_uids.add(uid)
    sf_cache = getattr(params, 'shared_folder_cache', None) or {}
    folder_cache = getattr(params, 'folder_cache', None) or {}
    # folder_cache has decrypted names; shared_folder_cache holds raw
    # (still-encrypted) names until first vault access. Prefer folder_cache.
    name_by_uid = {}
    for fuid, fc in folder_cache.items():
        if isinstance(fc, dict) and fc.get('type') == 'shared_folder':
            n = fc.get('name', '')
            if n:
                name_by_uid[fuid] = n
        elif hasattr(fc, 'name') and getattr(fc, 'type', '') == 'shared_folder':
            name_by_uid[fuid] = fc.name
    for uid, raw in sf_cache.items():
        if uid in seen_uids:
            continue
        name = name_by_uid.get(uid) or raw.get('name', '') or ''
        sfs.append({
            'name': name,
            'default_can_edit': bool(raw.get('default_can_edit', False)),
            'default_can_share': bool(raw.get('default_can_share', False)),
            'default_manage_users': bool(raw.get('default_manage_users', False)),
            'default_manage_records': bool(raw.get('default_manage_records', False)),
            'users': _sf_users(raw),
            'teams': _sf_teams(raw),
        })

    # Bug 85 — capture-target-state must query record_types via the
    # vault/get_record_types API like the source-side does, because
    # Commander does NOT populate `params.enterprise['record_types']`
    # (the dict-based path always yields empty). Without this, target
    # role.restrict_record_types values like `{"ent":[22246,...]}` can't
    # be resolved to type names by phase_roles, and the verify report
    # surfaces `<ent:22246>` placeholders that look like Bug 77
    # carryovers. Re-uses the source-side helper to keep behavior
    # consistent across capture-source and capture-target.
    record_types = []
    for rt in ent.get('record_types', []) or []:
        if isinstance(rt, dict):
            record_types.append(rt)
    if not record_types:
        try:
            from keepercommander import api
            from keepercommander.proto import record_pb2
            rq = record_pb2.RecordTypesRequest()
            rq.standard = True
            rq.user = True
            rq.enterprise = True
            rs = api.communicate_rest(
                params, rq, 'vault/get_record_types',
                rs_type=record_pb2.RecordTypesResponse)
            import json as _json_rt
            for rti in rs.recordTypes or []:
                try:
                    rto = _json_rt.loads(rti.content)
                except (TypeError, ValueError):
                    continue
                # Match the source-side projection shape so
                # `_restrict_record_types_to_name_set` can build its
                # ent_id_to_name lookup uniformly. record_type_id +
                # content's `$id` are the verify-side anchors.
                record_types.append({
                    'record_type_id': rti.recordTypeId,
                    'name': rto.get('$id') or '',
                    'content': rto,
                })
        except Exception as e:                                 # noqa: BLE001
            logging.warning(
                'capture-target-state: get_record_types unavailable, '
                'restrict_record_types verify-side resolution may show '
                '<ent:NNN> placeholders: %r', e)

    return {
        'server': getattr(params, 'server', '') or ent.get('server', ''),
        'data_center': _keeper_dc_for_server(getattr(params, 'server', '')),
        'captured_user': getattr(params, 'user', '') or ent.get('user', ''),
        'nodes': nodes,
        'teams': teams,
        'roles': roles,
        'users': users,
        'shared_folders': sfs,
        'record_types': record_types,
        # Records populated separately when --include-fields is set (expensive).
        'records': [],
    }


def _load_rename_map(inventory_path, target_state_path):
    # Bug 61 — locate rename_map.json next to either the inventory or
    # the target_state JSON (auto-migrate writes both into the same
    # run-dir). Returns {'roles': {(orig, src_node): renamed},
    # 'teams': {(orig, src_node): renamed}}; empty dict when the file
    # is absent (older runs / hand-staged inventories).
    candidates = []
    for p in (inventory_path, target_state_path):
        if not p:
            continue
        candidates.append(os.path.join(os.path.dirname(p), 'rename_map.json'))
    out = {'roles': {}, 'teams': {}, 'nodes': {}}
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path) as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as _e:
            logging.warning('rename_map.json load failed (%s): %s', path, _e)
            return {'roles': {}, 'teams': {}, 'nodes': {}}
        for kind in ('roles', 'teams', 'nodes'):
            for entry in data.get(kind, []) or []:
                key = (entry.get('original', ''), entry.get('source_node', ''))
                renamed = entry.get('renamed', '')
                if key[0] and renamed:
                    out[kind][key] = renamed
        return out
    return out


def _keeper_dc_for_server(server):
    """Map Commander server hostname → Keeper data-center code.

    Helps compliance readers tell at a glance "this target-state was
    captured from the EU DC" without having to memorize hostnames.
    """
    if not server:
        return ''
    s = server.lower()
    if 'keeperjapan' in s or '.jp' in s:
        return 'JP'
    if '.eu' in s:
        return 'EU'
    if '.com.au' in s:
        return 'AU'
    if 'govcloud' in s:
        return 'GOV'
    if '.ca' in s:
        return 'CA'
    if 'keepersecurity' in s:
        return 'US'
    return ''


def _collect_records_under_folders(params, folder_uids):
    """Return a set of record UIDs reachable under the given folder UIDs.

    Walks the subfolder tree recursively — records in any descendant
    folder are included. Missing folder UIDs are logged and skipped.
    Used by `records-export --folder-uid` to scope the export to a
    specific subtree without touching anything outside it.

    This is deliberately READ-ONLY against the source session. It
    reads params.folder_cache + params.subfolder_record_cache, both
    populated by sync_down. Never mutates either.
    """
    folder_cache = getattr(params, 'folder_cache', None) or {}
    subfolder_record_cache = getattr(params, 'subfolder_record_cache', None) or {}

    # Walk descendants using each node's .subfolders list.
    visited_folders: set = set()
    queue = list(folder_uids)
    while queue:
        fuid = queue.pop(0)
        if not fuid or fuid in visited_folders:
            continue
        if fuid not in folder_cache:
            logging.warning('records-export: folder UID %r not found in '
                            'folder_cache — skipping', fuid)
            continue
        visited_folders.add(fuid)
        subs = getattr(folder_cache[fuid], 'subfolders', None) or []
        queue.extend(subs)

    record_uids: set = set()
    for fuid in visited_folders:
        record_uids.update(subfolder_record_cache.get(fuid) or set())
    return record_uids


def _build_folder_path_index(params):
    """Return {record_uid: ['FolderA/Sub1', 'SharedFolderB']}.

    Walks params.folder_cache to resolve each folder's full path
    (backslash-style Commander convention) and params.subfolder_record_cache
    to find which folder(s) each record lives in. Records can appear in
    multiple folders — Keeper supports that — so the value is a list.

    Excludes the root folder (records at the user-vault root). Includes
    both user folders ('Personal/Work') and shared folders ('Team SF/
    Credentials') — the importer distinguishes via the shared_folder_uid
    on each folder.
    """
    folder_cache = getattr(params, 'folder_cache', None) or {}
    subfolder_record_cache = getattr(params, 'subfolder_record_cache', None) or {}
    # uid → name (no path), uid → parent_uid
    name_by_uid = {}
    parent_by_uid = {}
    sf_uid_by_uid = {}   # for shared-folder-folder / shared-folder roots
    for fuid, f in folder_cache.items():
        name_by_uid[fuid] = getattr(f, 'name', '') or ''
        parent_by_uid[fuid] = getattr(f, 'parent_uid', None)
        sf_uid_by_uid[fuid] = getattr(f, 'shared_folder_uid', None)

    def resolve_path(fuid):
        parts = []
        cur = fuid
        guard = 0
        while cur and guard < 32:
            n = name_by_uid.get(cur)
            if not n:
                break
            parts.append(n)
            cur = parent_by_uid.get(cur)
            guard += 1
        return '\\'.join(reversed(parts))

    record_to_folders = {}
    for fuid, record_uids in subfolder_record_cache.items():
        path = resolve_path(fuid)
        if not path:
            continue
        for ruid in (record_uids or []):
            record_to_folders.setdefault(ruid, []).append({
                'path': path,
                'shared_folder_uid': sf_uid_by_uid.get(fuid),
            })
    return record_to_folders


class RecordsExportCommand(Command):
    def get_parser(self):
        return records_export_parser

    def execute(self, params, **kwargs):
        """Write one JSON file per record in the current session's vault.

        Uses params.record_cache + api.get_record to render each record to
        disk in the v3 shape `convert` consumes. Filter by title prefix.
        """
        import json as _json
        from .commander_clients import sync_down
        from keepercommander import api

        sync_down(params)
        output_dir = kwargs['output_dir']
        prefix = kwargs.get('prefix', '') or ''
        folder_uids = kwargs.get('folder_uids') or []
        os.makedirs(output_dir, exist_ok=True)

        # Resolve folder paths for every record BEFORE the loop. Records
        # that live in user folders (personal hierarchy) were previously
        # exported with no folder info — import would drop them at the
        # target vault root, losing the hierarchy.
        folder_index = _build_folder_path_index(params)

        # --folder-uid scoping: walk the subfolder tree rooted at each
        # provided folder UID, gather every record UID reachable. Set
        # to None when --folder-uid wasn't passed (no folder filter).
        allowed_record_uids = None
        if folder_uids:
            allowed_record_uids = _collect_records_under_folders(
                params, folder_uids,
            )
            logging.info(
                'records-export: --folder-uid scope matched %d record(s) '
                'under %d folder root(s)',
                len(allowed_record_uids), len(folder_uids),
            )

        cache = getattr(params, 'record_cache', {}) or {}
        written = 0
        for uid, cached in cache.items():
            rec = api.get_record(params, uid)
            if rec is None or not rec.title:
                continue
            if prefix and not rec.title.startswith(prefix):
                continue
            if allowed_record_uids is not None and uid not in allowed_record_uids:
                continue
            # Build a record-get-style dict (Record.to_dictionary misses shares
            # + v3 custom fields; hydrate from the data_unencrypted blob).
            data_raw = cached.get('data_unencrypted', b'{}')
            if isinstance(data_raw, bytes):
                data_raw = data_raw.decode('utf-8', errors='replace')
            try:
                data = _json.loads(data_raw)
            except _json.JSONDecodeError as e:
                # A corrupt cache row would silently emit a body-less record
                # file with only {uid, title} — user thinks export succeeded,
                # sha256 looks healthy. Skip + surface instead.
                logging.error('records-export: cache corrupt for %s: %s', uid, e)
                continue
            out = dict(data)
            out['record_uid'] = uid
            out['title'] = rec.title
            out['type'] = data.get('type') or 'login'
            shares = cached.get('shares') or {}
            out['user_permissions'] = shares.get('user_permissions', [])[:]
            out['shared_folder_permissions'] = shares.get('shared_folder_permissions', [])[:]
            # Folder placement — captures both user-folder hierarchy
            # (personal vault subfolders) AND shared-folder placement.
            # Without this, import drops every record at the vault root.
            out['folders'] = folder_index.get(uid, [])
            # Plaintext record data (passwords, TOTP seeds, notes) — 0600.
            rec_path = os.path.join(output_dir, f'{uid}.json')
            with open(rec_path, 'w') as f:
                _json.dump(out, f, indent=2)
            os.chmod(rec_path, 0o600)
            written += 1
        # Audit sidecar: standard sha256sum manifest next to the
        # exported record JSONs (integrity check for the bundle).
        from .audit import append_audit_event, hash_directory_tree, write_sha256sums
        manifest_path = write_sha256sums(output_dir)
        tree_hash = hash_directory_tree(output_dir)
        # Audit-chain event lands at the TOP-LEVEL <run_dir>/audit.log
        # per cmd's published contract (dsk_hooks.py:20 +
        # OUTPUT_CONTRACT.md:35). Pre-fix this landed at
        # <output_dir>/audit.log which fragmented the chain — audit-
        # verify walking the top-level log couldn't see records-export
        # events. Fall back to output_dir only when run_dir cannot be
        # resolved (standalone invocation outside a run-dir).
        audit_log = kwargs.get('audit_log') or os.path.join(
            kwargs.get('run_dir') or os.path.dirname(
                os.path.abspath(output_dir)) or output_dir,
            'audit.log',
        )
        append_audit_event(audit_log, {
            'subcommand': 'records-export',
            'outputs': {'output_dir': output_dir, 'files': written,
                        'tree_hash': tree_hash,
                        'manifest': os.path.basename(manifest_path)},
            'summary': {'written': written},
        })
        logging.info('Exported %d record(s) to %s  (sha256 tree=%s)',
                     written, output_dir, tree_hash[:12])
        return {'written': written, 'output_dir': output_dir,
                'tree_hash': tree_hash, 'manifest': manifest_path}


def _run_chunked_import(cmd, params, base_kwargs, bundle, chunk_size,
                        chunk_delay):
    """Backwards-compat shim kept for any in-tree caller still using the
    private name. Delegates to `bulk_records.run_chunked_import`. The
    canonical entry point is the public function in `bulk_records`."""
    from .bulk_records import run_chunked_import
    return run_chunked_import(cmd=cmd, params=params,
                              base_kwargs=base_kwargs, bundle=bundle,
                              chunk_size=chunk_size,
                              chunk_delay=chunk_delay)


class RecordsImportCommand(Command):
    def get_parser(self):
        return records_import_parser

    def execute(self, params, **kwargs):
        """Run Commander's native `import` on a prepared JSON bundle.

        Any exception mid-import may have already landed a PARTIAL batch
        on target — don't report it as "nothing happened". We surface
        the partial-import risk in the return dict so the orchestrator
        and reconcile can flag it.
        """
        from keepercommander.commands.base import CommandError
        from keepercommander.importer.commands import RecordImportCommand
        from .safeguards import banner_for

        banner_for('records-import', dry_run=bool(kwargs.get('dry_run')),
                   details=[f'input: {kwargs.get("input", "?")}'])
        cmd = RecordImportCommand()
        import_kwargs = {
            'format': 'json',
            'name': kwargs['input'],
            'shared': True,
            # Default SF permissions. Without this kwarg Commander's
            # import prompts interactively ("manage (U)sers, manage
            # (R)ecords, can (E)dit, can (S)hare, or (A)ll, (N)one").
            # In batch mode the prompt hits EOF and aborts mid-import.
            # 'N' = None (create SFs without auto-granting access);
            # callers can override via --permissions if they need wider
            # defaults. Keep this explicit even when the bundle has no
            # shared folders — the code-path reads `permissions` before
            # deciding whether to prompt.
            'permissions': kwargs.get('permissions') or 'N',
        }
        if kwargs.get('record_type'):
            import_kwargs['record_type'] = kwargs['record_type']
        if kwargs.get('dry_run'):
            import_kwargs['dry_run'] = True

        # Read the input bundle to learn the titles we expect to land
        # on target. Post-import cache-diff can false-positive when a
        # concurrent sync-down pulls unrelated UIDs between before/after;
        # filtering diff additions by "title is in the bundle" catches
        # that. Keep the raw diff too — if title match yields far fewer
        # UIDs than the raw diff we warn (cache got polluted).
        expected_titles = set()
        try:
            with open(kwargs['input']) as f:
                bundle = json.load(f)
            for r in bundle.get('records') or []:
                if isinstance(r, dict):
                    t = (r.get('title') or '').strip()
                    if t:
                        expected_titles.add(t)
        except (OSError, json.JSONDecodeError) as _e:
            logging.warning('records-import: could not read bundle for '
                             'expected-title set: %s', _e)

        # Snapshot target UIDs so we can diff post-import and stamp the
        # `imported_uids` list into the audit event. Commander's native
        # RecordImportCommand doesn't return UIDs — the diff is the only
        # reliable signal.
        before_uids = set((getattr(params, 'record_cache', None) or {}).keys())
        partial = False
        reason = ''

        # Bug 68 (v1.6.2) — chunked import. When --chunk-size > 0 split
        # the bundle into N-record chunks, write each to a temp file,
        # import sequentially, sleep --chunk-delay between. This
        # mirrors pam-import's natural inter-call pacing (every
        # mutation followed by sync_down) and gives heavily-throttled
        # tenants (MSP target observed in rehearsal-11) time to recover
        # rate-limit budget between chunks. Single monolithic import
        # (chunk_size=0) keeps the legacy fast path for tenants
        # without throttle pressure.
        chunk_size = int(kwargs.get('chunk_size') or 0)
        chunk_delay = float(kwargs.get('chunk_delay') or 2.0)
        try:
            if chunk_size > 0 and bundle.get('records'):
                from .bulk_records import run_chunked_import
                run_chunked_import(cmd=cmd, params=params,
                                   base_kwargs=import_kwargs,
                                   bundle=bundle,
                                   chunk_size=chunk_size,
                                   chunk_delay=chunk_delay)
            else:
                cmd.execute(params, **import_kwargs)
        except CommandError as e:
            # User-visible import error (parser rejection, etc.) —
            # Commander raises BEFORE any write, so target is clean.
            logging.error('records-import rejected by Commander: %s', e)
            return {'ok': False, 'partial': False, 'reason': str(e)}
        except Exception as e:                         # noqa: BLE001
            # Anything else (network drop, auth expiry, KeyboardInterrupt
            # adjacent) may have left partial records on target. Escalate
            # — and still emit the audit event for whatever did land.
            logging.error(
                'records-import raised %s mid-run — TARGET MAY HAVE PARTIAL '
                'IMPORT. Run `tenant-migrate reconcile` before retrying.',
                type(e).__name__, exc_info=True,
            )
            partial = True
            reason = f'{type(e).__name__}: {e}'

        # Diff after execute() — sync_down() happens inside RecordImportCommand
        # so record_cache reflects the newly imported UIDs.
        after_uids = set((getattr(params, 'record_cache', None) or {}).keys())
        raw_diff = sorted(after_uids - before_uids)

        # Narrow the raw diff to UIDs whose title is in the bundle. When
        # expected_titles is empty we couldn't parse the bundle, so fall
        # back to the raw diff (still useful). When expected_titles is
        # non-empty but raw_diff is much larger, warn — concurrent
        # sync-down pulled unrelated UIDs that shouldn't be attributed
        # to this import in the audit log.
        if expected_titles:
            from keepercommander import api
            imported_uids = []
            for uid in raw_diff:
                try:
                    rec = api.get_record(params, uid)
                except Exception:                       # noqa: BLE001
                    continue
                if rec is None:
                    continue
                if (rec.title or '').strip() in expected_titles:
                    imported_uids.append(uid)
            if len(raw_diff) > len(imported_uids) * 2 and raw_diff:
                # Raw diff was at least 2x the matched subset — cache
                # likely picked up unrelated UIDs. Audit the full raw
                # diff too so the operator can investigate.
                logging.warning(
                    'records-import: raw cache diff=%d but only %d '
                    'matched a bundle title — concurrent sync-down may '
                    'have added unrelated UIDs; recording both sets '
                    'in the audit event.',
                    len(raw_diff), len(imported_uids),
                )
        else:
            imported_uids = raw_diff
        if not kwargs.get('dry_run'):
            try:
                from .audit import append_audit_event
                # Phase 8 unified fallback: prefer explicit run_dir.
                audit_log = kwargs.get('audit_log') or os.path.join(
                    kwargs.get('run_dir') or os.path.dirname(
                        kwargs['input']) or '.', 'audit.log')
                append_audit_event(audit_log, {
                    'subcommand': 'records-import',
                    'inputs': {'input': os.path.abspath(kwargs['input'])},
                    'summary': {
                        'imported_uids': imported_uids,
                        'counts': {'imported': len(imported_uids)},
                        'partial': partial,
                    },
                })
            except OSError as _e:
                logging.warning('records-import audit emit skipped (I/O error): %s', _e)

        if partial:
            return {'ok': False, 'partial': True,
                    'reason': reason,
                    'imported_uids': imported_uids,
                    'action': 'reconcile target before retry'}
        logging.info('records-import: %s (%d newly imported UID(s))',
                     kwargs['input'], len(imported_uids))
        return {'ok': True, 'partial': False, 'imported_uids': imported_uids}


def _read_source_uid_list(path):
    """Read source_uids from CSV-with-source_uid-column OR plain-text
    (one UID per line). Returns a deduplicated list in file order."""
    uids = []
    seen = set()
    with open(path) as f:
        first = f.readline()
        # Detect CSV with source_uid column vs plain text
        if 'source_uid' in first.lower():
            f.seek(0)
            import csv as _csv
            reader = _csv.DictReader(f)
            for row in reader:
                uid = (row.get('source_uid') or '').strip()
                if uid and uid not in seen:
                    seen.add(uid)
                    uids.append(uid)
        else:
            f.seek(0)
            for line in f:
                uid = line.strip()
                if uid and not uid.startswith('#') and uid not in seen:
                    seen.add(uid)
                    uids.append(uid)
    return uids


class RecordsAttachmentsDownloadCommand(Command):
    """Phase 1 of two-phase attachments flow — runs on source shell.

    Pulls every attachment for each source_uid into <staging-dir>/<uid>/
    and writes staging.json so the target-side upload can run later
    without needing simultaneous source session access. This is what
    makes cross-tenant attachments migrations possible when Commander
    can't hold two sessions at once.
    """

    def get_parser(self):
        return records_attachments_download_parser

    def execute(self, params, **kwargs):
        from .attachments import AttachmentDownloader
        from .commander_clients import CommanderAttachmentClient, sync_down
        from .safeguards import banner_for

        banner_for('records-attachments-download', dry_run=False,
                   details=['reads source records — non-destructive'])
        sync_down(params)
        uids = _read_source_uid_list(kwargs['source_uids'])
        if not uids:
            logging.error('no source_uids read from %s',
                           kwargs['source_uids'])
            return {'error': 'no source_uids'}
        real_client = CommanderAttachmentClient(params)
        downloader = AttachmentDownloader(
            real_client, kwargs['staging_dir'],
            delay=kwargs.get('delay', 0.0),
            batch_size=kwargs.get('batch_size', 0),
        )
        summary = downloader.run(uids)
        logging.info('Attachments downloaded: %d record(s), %d file(s) → %s',
                     summary['total'], summary['total_files'],
                     kwargs['staging_dir'])
        return summary


class RecordsAttachmentsUploadCommand(Command):
    """Phase 2 — runs on the target shell. Reads pre-downloaded files
    from <staging-dir>/ (populated by records-attachments-download)
    and uploads each to its paired target record per the manifest."""

    def get_parser(self):
        return records_attachments_upload_parser

    def execute(self, params, **kwargs):
        from .attachments import AttachmentUploader, load_manifest
        from .checkpoint import Checkpoint, CheckpointMismatchError
        from .commander_clients import CommanderAttachmentClient, sync_down
        from .safeguards import banner_for

        banner_for('records-attachments-upload', dry_run=False)
        sync_down(params)
        pairs = load_manifest(kwargs['manifest'])
        real_client = CommanderAttachmentClient(params)

        run_dir = kwargs.get('run_dir') or kwargs.get('staging_dir') or '.'
        ckpt = Checkpoint('records-attachments-upload', run_dir)

        uploader = AttachmentUploader(
            real_client, kwargs['staging_dir'],
            delay=kwargs.get('delay', 0.0),
            batch_size=kwargs.get('batch_size', 0),
            checkpoint=ckpt,
            resume=bool(kwargs.get('resume')),
            force_restart=bool(kwargs.get('force_restart')),
        )
        try:
            summary = uploader.run(pairs)
        except CheckpointMismatchError as e:
            logging.error('%s', e)
            return {'blocked': True, 'reason': 'checkpoint mismatch'}
        logging.info('Attachments uploaded: pass=%d fail=%d skip=%d (of %d)',
                     summary['pass'], summary['fail'],
                     summary['skip'], summary['total'])

        # Audit event — same shape as records-attachments for undo
        # compatibility.
        try:
            from .audit import append_audit_event
            uploaded = []
            for r in summary.get('per_record') or []:
                uploaded.extend(r.get('uploaded_files') or [])
            # Phase 8 unified fallback: prefer explicit run_dir.
            audit_log = kwargs.get('audit_log') or os.path.join(
                kwargs.get('run_dir') or os.path.dirname(
                    kwargs['manifest']) or '.', 'audit.log')
            append_audit_event(audit_log, {
                'subcommand': 'records-attachments-upload',
                'inputs': {'manifest': os.path.abspath(kwargs['manifest']),
                            'staging_dir': os.path.abspath(kwargs['staging_dir'])},
                'summary': {
                    'uploaded': uploaded,
                    'counts': {'total': summary['total'],
                                'pass': summary['pass'],
                                'fail': summary['fail'],
                                'skip': summary['skip']},
                },
            })
        except OSError as _e:
            logging.warning('records-attachments-upload audit emit '
                             'skipped (I/O error): %s', _e)

        # Bug 56 / v1.6 — persist file_uid_map.json so the
        # records-references-rewrite stage can remap fileRef values.
        # Empty when no source-side file UIDs were captured (older
        # staging dir / source client without list_record_file_uids).
        try:
            file_uid_map = summary.get('file_uid_map') or {}
            if file_uid_map:
                run_dir = kwargs.get('run_dir') or os.path.dirname(
                    kwargs['manifest']) or '.'
                map_path = os.path.join(run_dir, 'file_uid_map.json')
                with open(map_path, 'w') as _f:
                    json.dump(file_uid_map, _f, indent=2, sort_keys=True)
                os.chmod(map_path, 0o600)
                logging.info('file_uid_map: %d pair(s) → %s',
                             len(file_uid_map), map_path)
        except OSError as _e:
            logging.warning('file_uid_map.json emit skipped: %s', _e)

        return summary


class RecordsAttachmentsCommand(Command):
    def get_parser(self):
        return records_attachments_parser

    def execute(self, params, **kwargs):
        from .attachments import AttachmentMigrator, load_manifest
        from .commander_clients import CommanderAttachmentClient, sync_down
        from .dry_run import DryRun, classify_plan, render_report, summarize
        from .safeguards import banner_for

        banner_for('records-attachments', dry_run=bool(kwargs.get('dry_run')))
        sync_down(params)
        real_client = CommanderAttachmentClient(params)
        dry = bool(kwargs.get('dry_run'))
        client = DryRun(real_client) if dry else real_client
        migrator = AttachmentMigrator(
            client, kwargs['staging_dir'],
            delay=kwargs.get('delay', 0.0),
            batch_size=kwargs.get('batch_size', 0),
        )
        summary = migrator.run(load_manifest(kwargs['manifest']))
        if dry:
            classified = classify_plan(client, target_state={})
            counts = summarize(classified)
            if kwargs.get('dry_run_report'):
                with open(kwargs['dry_run_report'], 'w') as f:
                    f.write(render_report(classified, counts))
                os.chmod(kwargs['dry_run_report'], 0o600)
            logging.info('[dry-run] %s', counts)
            return {'dry_run': True, 'counts': counts,
                    'classified': classified, 'summary': summary}
        logging.info('Attachments: pass=%d fail=%d skip=%d (of %d)',
                     summary['pass'], summary['fail'],
                     summary['skip'], summary['total'])

        # Audit event — feeds `tenant-migrate undo` which deletes each
        # uploaded attachment from its target record.
        try:
            from .audit import append_audit_event
            uploaded = []
            for r in summary.get('per_record') or []:
                uploaded.extend(r.get('uploaded_files') or [])
            # Phase 8 unified fallback: prefer explicit run_dir.
            audit_log = kwargs.get('audit_log') or os.path.join(
                kwargs.get('run_dir') or os.path.dirname(
                    kwargs['manifest']) or '.', 'audit.log')
            append_audit_event(audit_log, {
                'subcommand': 'records-attachments',
                'inputs': {'manifest': os.path.abspath(kwargs['manifest'])},
                'summary': {
                    'uploaded': uploaded,
                    'counts': {'total': summary['total'],
                                'pass': summary['pass'],
                                'fail': summary['fail'],
                                'skip': summary['skip']},
                },
            })
        except OSError as _e:
            logging.warning('records-attachments audit emit skipped (I/O error): %s', _e)
        return summary


class RecordsManifestCommand(Command):
    def get_parser(self):
        return records_manifest_parser

    def execute(self, params, **kwargs):
        from .commander_clients import sync_down
        from .manifest import build_from_session

        sync_down(params)
        result = build_from_session(
            kwargs['source_dir'], params, kwargs['output'],
            allow_ambiguous=kwargs.get('allow_ambiguous', False),
        )
        counts = result['counts']
        logging.info('Manifest: paired=%d ambiguous=%d source_only=%d target_only=%d',
                     counts['pairs'], counts['ambiguous'],
                     counts['source_only'], counts['target_only'])
        if counts['ambiguous']:
            logging.warning('%d title(s) have multiple source/target matches. '
                            'Use --allow-ambiguous or resolve manually.',
                            counts['ambiguous'])
        return result


class RecordsReferencesRewriteCommand(Command):
    """Bug 33 (v1.5.1) — runs the references rewrite over a records
    manifest. Idempotent: re-runs only persist records whose embedded
    UIDs still resolve to a different target value, so a partial run
    can be safely resumed by re-invoking the command.
    """

    def get_parser(self):
        return records_references_rewrite_parser

    def execute(self, params, **kwargs):
        from .commander_clients import (
            CommanderRecordReferenceClient, sync_down,
        )
        from .references_rewrite import (
            ReferencesRewriter, load_manifest_pairs,
        )

        sync_down(params)
        pairs = load_manifest_pairs(kwargs['manifest'])
        if not pairs:
            logging.info('records-references-rewrite: empty manifest, nothing to do')
            return _empty_rewrite_result()

        if kwargs.get('dry_run'):
            client = _DryRunReferenceClient(
                CommanderRecordReferenceClient(params))
        else:
            client = CommanderRecordReferenceClient(params)

        # Bug 56 / v1.6 — load file_uid_map.json (emitted by the
        # attachments-upload stage) so the rewriter remaps fileRef
        # values alongside record UIDs. Empty when no file UIDs were
        # captured (older runs / staging without UID metadata).
        file_uid_map = {}
        run_dir = kwargs.get('run_dir')
        if run_dir:
            file_map_path = os.path.join(run_dir, 'file_uid_map.json')
            if os.path.isfile(file_map_path):
                try:
                    with open(file_map_path) as _f:
                        file_uid_map = json.load(_f) or {}
                except (OSError, json.JSONDecodeError) as _e:
                    logging.warning(
                        'file_uid_map.json load failed (%s): %s',
                        file_map_path, _e)
                    file_uid_map = {}
                else:
                    logging.info('file_uid_map: %d pair(s) loaded',
                                 len(file_uid_map))

        rewriter = ReferencesRewriter(client, file_uid_map=file_uid_map)
        result = rewriter.run(pairs)
        logging.info(
            'references-rewrite: inspected=%d with_refs=%d rewritten=%d '
            'remapped=%d unknown=%d empty=%d load_fail=%d persist_fail=%d',
            result['records_inspected'], result['records_with_refs'],
            result['records_rewritten'], result['refs_remapped'],
            result['refs_unknown'], result['refs_empty'],
            result['load_failures'], result['persist_failures'])

        # Audit event — undo treats this subcommand as MANUAL because
        # reverting a structured-field substitution requires the
        # before-image, which we don't store. The event still records
        # which target UIDs were touched so the operator has a clear
        # rollback target if they need to re-import from the source
        # bundle.
        if not kwargs.get('dry_run') and kwargs.get('run_dir'):
            try:
                from .audit import append_audit_event
                # Bug 50 — `append_audit_event` opens the path with
                # `open(path, 'a')`; a directory raises
                # IsADirectoryError. Construct the audit-log file
                # path explicitly (matches every other audit-emitting
                # subcommand: see commands.py:1346, 1502, etc.).
                audit_log = os.path.join(kwargs['run_dir'], 'audit.log')
                append_audit_event(audit_log, {
                    'subcommand': 'records-references-rewrite',
                    'summary': {
                        'rewritten_uids': result['rewritten_uids'],
                        'records_rewritten': result['records_rewritten'],
                        'refs_remapped': result['refs_remapped'],
                    },
                })
            except Exception as e:                          # noqa: BLE001
                logging.warning('audit append failed: %r', e)
        return result


def _empty_rewrite_result():
    return {
        'records_inspected': 0,
        'records_with_refs': 0,
        'records_rewritten': 0,
        'refs_remapped': 0,
        'refs_unknown': 0,
        'refs_empty': 0,
        'persist_failures': 0,
        'load_failures': 0,
        'rewritten_uids': [],
        'failed_uids': [],
    }


class _DryRunReferenceClient:
    """Wraps a real reference client; load delegates, persist is a
    no-op. The rewriter still runs the walk + remap so the operator
    sees the would-be effect, but no Commander API call mutates target."""

    def __init__(self, inner):
        self._inner = inner

    def load_field_values(self, record_uid):
        return self._inner.load_field_values(record_uid)

    def persist(self, record_uid, loaded):
        logging.info('[dry-run] would persist references rewrite on %s',
                      record_uid)
        return True


class RecordsSharesCommand(Command):
    def get_parser(self):
        return records_shares_parser

    def execute(self, params, **kwargs):
        from .attachments import load_manifest
        from .commander_clients import CommanderShareClient, sync_down
        from .dry_run import DryRun, classify_plan, render_report, summarize
        from .safeguards import banner_for
        from .shares import ShareRestorer

        banner_for('records-shares', dry_run=bool(kwargs.get('dry_run')))
        sync_down(params)
        real_client = CommanderShareClient(params, params)
        dry = bool(kwargs.get('dry_run'))
        client = DryRun(real_client) if dry else real_client
        from .email_remap import log_remap_banner
        log_remap_banner(kwargs.get('old_domain', ''),
                          kwargs.get('new_domain', ''))

        # Checkpoint: opt-in via --resume / --force-restart, state lives in
        # <run-dir>/checkpoints/records-shares.json. Suppressed on dry-run
        # so a planning pass never clobbers a mid-flight real run.
        from .checkpoint import Checkpoint, CheckpointMismatchError
        ckpt = None
        if not dry:
            run_dir = kwargs.get('run_dir') or (
                os.path.dirname(kwargs['manifest']) or '.')
            ckpt = Checkpoint('records-shares', run_dir)

        restorer = ShareRestorer(
            client,
            skip_missing_users=kwargs.get('skip_missing_users', False),
            old_domain=kwargs.get('old_domain', ''),
            new_domain=kwargs.get('new_domain', ''),
            delay=kwargs.get('delay', 0.0),
            batch_size=kwargs.get('batch_size', 0),
            checkpoint=ckpt,
            resume=bool(kwargs.get('resume')),
            force_restart=bool(kwargs.get('force_restart')),
        )
        try:
            summary = restorer.run(load_manifest(kwargs['manifest']))
        except CheckpointMismatchError as e:
            logging.error('%s', e)
            return {'blocked': True, 'reason': 'checkpoint mismatch'}
        if dry:
            classified = classify_plan(client, target_state={})
            counts = summarize(classified)
            if kwargs.get('dry_run_report'):
                with open(kwargs['dry_run_report'], 'w') as f:
                    f.write(render_report(classified, counts))
                os.chmod(kwargs['dry_run_report'], 0o600)
            logging.info('[dry-run] %s', counts)
            return {'dry_run': True, 'counts': counts,
                    'classified': classified, 'summary': summary}
        logging.info('Shares: pass=%d fail=%d skip=%d (of %d)',
                     summary['pass'], summary['fail'],
                     summary['skip'], summary['total'])

        # Audit event — feeds `tenant-migrate undo` which revokes each
        # (target_uid, email) grant.
        try:
            from .audit import append_audit_event
            share_grants = []
            for r in summary.get('per_record') or []:
                share_grants.extend(r.get('grants') or [])
            # Phase 8 unified fallback: prefer explicit run_dir.
            audit_log = kwargs.get('audit_log') or os.path.join(
                kwargs.get('run_dir') or os.path.dirname(
                    kwargs['manifest']) or '.', 'audit.log')
            append_audit_event(audit_log, {
                'subcommand': 'records-shares',
                'inputs': {'manifest': os.path.abspath(kwargs['manifest'])},
                'summary': {
                    'share_grants': share_grants,
                    'counts': {'total': summary['total'],
                                'pass': summary['pass'],
                                'fail': summary['fail'],
                                'skip': summary['skip']},
                },
            })
        except OSError as _e:
            logging.warning('records-shares audit emit skipped (I/O error): %s', _e)
        return summary


class RecordsSharesExtractCommand(Command):
    """Bug 20 — phase 1 of cross-tenant share migration.

    Source-side: read user_permissions[] from each pair's source record
    (Bug 19 lazy-fetches when record_cache.shares is empty), apply
    email remap, write JSON manifest.
    """

    def get_parser(self):
        return records_shares_extract_parser

    def execute(self, params, **kwargs):
        from .attachments import load_manifest
        from .commander_clients import CommanderShareClient, sync_down
        from .email_remap import log_remap_banner
        from .safeguards import banner_for
        from .shares import extract_shares, write_extract_manifest

        banner_for('records-shares-extract', dry_run=False)
        sync_down(params)
        client = CommanderShareClient(params, params)
        log_remap_banner(kwargs.get('old_domain', ''),
                         kwargs.get('new_domain', ''))

        pairs = load_manifest(kwargs['manifest'])
        entries = extract_shares(
            client, pairs,
            old_domain=kwargs.get('old_domain', ''),
            new_domain=kwargs.get('new_domain', ''),
        )
        out_path = write_extract_manifest(kwargs['output'], entries)
        with_shares = sum(1 for e in entries if e.get('shares'))
        total_grants = sum(len(e.get('shares') or []) for e in entries)
        logging.info(
            'records-shares-extract: %d pair(s) processed, %d with '
            'shares, %d total grants → %s',
            len(entries), with_shares, total_grants, out_path,
        )
        return {
            'output': out_path,
            'pairs_total': len(entries),
            'pairs_with_shares': with_shares,
            'total_grants': total_grants,
        }


class RecordsSharesApplyCommand(Command):
    """Bug 20 — phase 2 of cross-tenant share migration.

    Target-side: read the JSON written by `records-shares-extract`,
    grant each share via target session's share-record. No source
    session needed. Same checkpoint / resume semantics as
    `records-shares`.
    """

    def get_parser(self):
        return records_shares_apply_parser

    def execute(self, params, **kwargs):
        from .commander_clients import CommanderShareClient, sync_down
        from .checkpoint import Checkpoint, CheckpointMismatchError
        from .safeguards import banner_for
        from .shares import ShareApplier, read_extract_manifest

        banner_for('records-shares-apply', dry_run=False)
        sync_down(params)
        # CommanderShareClient takes (source_params, target_params).
        # In apply phase the "source" never gets used — we only call
        # share_record, not get_record_json. Pass params as both for
        # symmetry with the single-session path.
        client = CommanderShareClient(params, params)

        run_dir = kwargs.get('run_dir') or (
            os.path.dirname(kwargs['input']) or '.')
        ckpt = Checkpoint('records-shares-apply', run_dir)

        applier = ShareApplier(
            client,
            skip_missing_users=bool(kwargs.get('skip_missing_users')),
            delay=kwargs.get('delay', 0.0),
            batch_size=kwargs.get('batch_size', 0),
            checkpoint=ckpt,
            resume=bool(kwargs.get('resume')),
            force_restart=bool(kwargs.get('force_restart')),
        )

        try:
            entries = read_extract_manifest(kwargs['input'])
        except (OSError, ValueError) as e:
            logging.error('records-shares-apply: %s', e)
            return {'blocked': True, 'reason': str(e)}

        try:
            summary = applier.run(entries)
        except CheckpointMismatchError as e:
            logging.error('%s', e)
            return {'blocked': True, 'reason': 'checkpoint mismatch'}

        logging.info('Shares-apply: pass=%d fail=%d skip=%d (of %d)',
                     summary['pass'], summary['fail'],
                     summary['skip'], summary['total'])

        # Audit event for undo. Same shape as records-shares.
        try:
            from .audit import append_audit_event
            share_grants = []
            for r in summary.get('per_record') or []:
                share_grants.extend(r.get('grants') or [])
            # Phase 8 unified fallback: prefer explicit run_dir.
            audit_log = kwargs.get('audit_log') or os.path.join(
                kwargs.get('run_dir') or os.path.dirname(
                    kwargs['input']) or '.', 'audit.log')
            append_audit_event(audit_log, {
                'subcommand': 'records-shares-apply',
                'inputs': {'input': os.path.abspath(kwargs['input'])},
                'summary': {
                    'share_grants': share_grants,
                    'counts': {'total': summary['total'],
                                'pass': summary['pass'],
                                'fail': summary['fail'],
                                'skip': summary['skip']},
                },
            })
        except OSError as _e:
            logging.warning('records-shares-apply audit emit skipped '
                            '(I/O error): %s', _e)
        return summary


class TakeOwnershipCommand(DestructiveCommand):
    SUBCOMMAND = 'take-ownership'

    def get_parser(self):
        return take_ownership_parser

    def _run(self, params, **kwargs):
        import datetime
        from .commander_clients import CommanderOwnershipClient, sync_down
        from .dry_run import DryRun, classify_plan, render_report, summarize
        from .safeguards import (
            SafeguardBlocked, banner_for, confirm_interactive,
            require_tenant_assertion, production_tenant_warning,
        )
        from .take_ownership import load_ready_users, process_users

        sync_down(params)
        admin_email = kwargs.get('admin_email') or getattr(params, 'user', '')
        if not admin_email:
            logging.error('No admin-email specified and params.user is empty.')
            return
        ts = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        users = list(load_ready_users(kwargs['verification_report']))
        dry = bool(kwargs.get('dry_run'))

        # Source-mode interlock already enforced by DestructiveCommand
        # base class. Remaining live-only safeguards below.
        if not dry:
            try:
                require_tenant_assertion(
                    params, kwargs.get('expected_tenant_name', ''),
                    skip_check=bool(kwargs.get('skip_tenant_check')),
                    subcommand='take-ownership',
                )
            except SafeguardBlocked as e:
                logging.error('SAFEGUARD: %s', e)
                return {'blocked': True, 'reason': str(e)}
            production_tenant_warning(params)
            banner_for('take-ownership', dry_run=False, details=[
                f'{len(users)} user folder(s) will transfer to {admin_email}',
                'JSON backups written first; transfer skipped if backup fails',
            ])
            if not kwargs.get('yes'):
                ok = confirm_interactive(
                    'CONFIRM take-ownership',
                    f'Back up + transfer ownership of {len(users)} MIGRATION-* '
                    f'folder(s) to {admin_email}?',
                )
                if not ok:
                    logging.info('take-ownership rejected by user.')
                    return {'aborted': True}

        real_client = CommanderOwnershipClient(params)
        client = DryRun(real_client) if dry else real_client
        from .email_remap import log_remap_banner
        log_remap_banner(kwargs.get('old_domain', ''),
                          kwargs.get('new_domain', ''))

        from .checkpoint import Checkpoint, CheckpointMismatchError
        ckpt = None
        if not dry:
            run_dir = kwargs.get('run_dir') or (
                os.path.dirname(kwargs['verification_report']) or '.')
            ckpt = Checkpoint('take-ownership', run_dir)

        try:
            summary = process_users(
                users, client, admin_email,
                backup_dir=kwargs['backup_dir'],
                report_path=kwargs['report_output'],
                sleep_seconds=kwargs.get('delay', 0.5),
                timestamp=ts, dry_run=dry,
                old_domain=kwargs.get('old_domain', ''),
                new_domain=kwargs.get('new_domain', ''),
                batch_size=kwargs.get('batch_size', 0),
                checkpoint=ckpt,
                resume=bool(kwargs.get('resume')),
                force_restart=bool(kwargs.get('force_restart')),
            )
        except CheckpointMismatchError as e:
            logging.error('%s', e)
            return {'blocked': True, 'reason': 'checkpoint mismatch'}
        # Backup files contain plaintext record data → 0600.
        if os.path.isdir(kwargs['backup_dir']):
            for fn in os.listdir(kwargs['backup_dir']):
                path = os.path.join(kwargs['backup_dir'], fn)
                if os.path.isfile(path):
                    os.chmod(path, 0o600)
            # Audit manifest for the backup dir. Narrow exception: OSError
            # covers actual I/O failure (disk full, permission denied) and
            # is legitimately recoverable — log + skip. Anything else is
            # a packaging/logic bug and SHOULD propagate; take-ownership
            # backups without an audit manifest defeat their own purpose.
            try:
                from .audit import append_audit_event, hash_directory_tree, write_sha256sums
                manifest_path = write_sha256sums(kwargs['backup_dir'])
                tree_hash = hash_directory_tree(kwargs['backup_dir'])
                # Audit-chain event lands at top-level <run_dir>/audit.log
                # per cmd's published contract (dsk_hooks.py:20 +
                # OUTPUT_CONTRACT.md:35). Pre-fix this landed at
                # <backup_dir>/audit.log which fragmented the chain.
                # Fall back to parent-of-backup-dir when run_dir is not
                # explicit (auto_migrate / wizard set backup_dir as a
                # subdir of run_dir; the parent IS run_dir).
                audit_log = kwargs.get('audit_log') or os.path.join(
                    kwargs.get('run_dir') or os.path.dirname(
                        os.path.abspath(kwargs['backup_dir'])) or
                    kwargs['backup_dir'],
                    'audit.log',
                )
                append_audit_event(
                    audit_log,
                    {'subcommand': 'take-ownership',
                     'outputs': {'backup_dir': kwargs['backup_dir'],
                                 'tree_hash': tree_hash,
                                 'manifest': os.path.basename(manifest_path)},
                     'summary': summary},
                )
            except OSError as _e:
                logging.warning('audit manifest skipped (I/O error): %s', _e)
        # Report has no secrets but keep consistent permissions.
        if os.path.exists(kwargs['report_output']):
            os.chmod(kwargs['report_output'], 0o600)

        if dry:
            classified = classify_plan(client, target_state={})
            counts = summarize(classified)
            md_path = kwargs.get('dry_run_report') or ''
            if md_path:
                with open(md_path, 'w') as f:
                    f.write(render_report(classified, counts))
                os.chmod(md_path, 0o600)
                logging.info('[dry-run] report: %s', md_path)
            logging.info('[dry-run] %s', counts)
            return {'dry_run': True, 'counts': counts, 'classified': classified,
                    'summary': summary}

        logging.info('Ownership transfer: %d total, %d backups, %d transfers, %d errors',
                     summary['total'], summary['backups'],
                     summary['ownerships'], summary['errors'])
        return summary


class CleanupCommand(DestructiveCommand):
    SUBCOMMAND = 'cleanup'

    def get_parser(self):
        return cleanup_parser

    def _run(self, params, **kwargs):
        # Source-mode interlock already enforced by DestructiveCommand.
        # MCContext wrap stays here because only cleanup supports --mc
        # among the destructive commands.
        from .mc_context import MCContext
        with MCContext(params, kwargs.get('mc', '')) as ctx:
            return self._run_cleanup(ctx.params, **kwargs)

    def _run_cleanup(self, params, **kwargs):
        from .cleanup import cleanup, matching_entities
        from .commander_clients import CommanderCleanupClient, sync_down
        from .dry_run import DryRun, classify_plan, render_report, summarize
        from .safeguards import (
            SafeguardBlocked, banner_for, confirm_interactive,
            enforce_batch_cap, require_tenant_assertion,
            production_tenant_warning,
        )

        prefix = kwargs['prefix']
        sync_down(params)
        real_client = CommanderCleanupClient(params)
        dry = bool(kwargs.get('dry_run'))
        auto_yes = bool(kwargs.get('yes') or kwargs.get('confirm'))

        if not dry:
            # Source-mode interlock was already applied by the
            # DestructiveCommand base class. Remaining safeguards
            # (tenant-name, batch-cap) are live-only.
            try:
                require_tenant_assertion(
                    params, kwargs.get('expected_tenant_name', ''),
                    skip_check=bool(kwargs.get('skip_tenant_check')),
                    subcommand='cleanup',
                )
                matches = matching_entities(real_client.list_entities(), prefix)
                total_matches = sum(len(v) for v in matches.values())
                enforce_batch_cap(
                    total_matches, kwargs.get('batch_cap', 50),
                    override=kwargs.get('override_batch_cap', False),
                    entity_label=f'entities matching {prefix!r}',
                )
            except SafeguardBlocked as e:
                logging.error('SAFEGUARD: %s', e)
                return {'blocked': True, 'reason': str(e)}
            production_tenant_warning(params)
            banner_for('cleanup', dry_run=False, details=[
                f'prefix: {prefix!r}',
                f'entities matched: {total_matches}',
                f'tenant: {(getattr(params, "enterprise", None) or {}).get("enterprise_name", "?")}',
            ])
            # Interactive prompt unless explicitly pre-confirmed.
            if not auto_yes:
                ok = confirm_interactive(
                    'CONFIRM cleanup',
                    f'Delete {total_matches} entities whose names start with '
                    f'{prefix!r}? This is IRREVERSIBLE — re-create via '
                    '`structure` if needed.',
                )
                if not ok:
                    logging.info('cleanup rejected by user.')
                    return {'deleted': 0, 'aborted': True}

        client = DryRun(real_client) if dry else real_client
        summary = cleanup(client, prefix,
                           include_records=bool(kwargs.get('include_records')),
                           dry_run=dry)
        if dry:
            classified = classify_plan(client, target_state={})
            counts = summarize(classified)
            if kwargs.get('dry_run_report'):
                with open(kwargs['dry_run_report'], 'w') as f:
                    f.write(render_report(classified, counts))
                os.chmod(kwargs['dry_run_report'], 0o600)
            logging.info('[dry-run] would delete: %s', counts)
            return {'dry_run': True, 'counts': counts,
                    'classified': classified, 'summary': summary}
        logging.info('Cleanup: deleted teams=%d roles=%d nodes=%d errors=%d',
                     summary['teams'], summary['roles'],
                     summary['nodes'], summary['errors'])
        # Phase 2 audit-emission gap fix: cleanup is destructive; the
        # tamper-evident audit chain MUST record what was deleted, on
        # which tenant, by what filter. audit-verify walks audit.log
        # to prove what happened end-to-end.
        audit_log = kwargs.get('audit_log') or os.path.join(
            kwargs.get('run_dir') or '.', 'audit.log',
        )
        if audit_log:
            from .audit import append_audit_event
            append_audit_event(audit_log, {
                'subcommand': 'cleanup',
                'tenant': (getattr(params, 'enterprise', None) or {}).get(
                    'enterprise_name', ''),
                'inputs': {'prefix': prefix,
                           'include_records': bool(kwargs.get('include_records')),
                           'expected_tenant_name': kwargs.get('expected_tenant_name', ''),
                           'mc': kwargs.get('mc', '')},
                'summary': {
                    'teams_deleted': summary.get('teams', 0),
                    'roles_deleted': summary.get('roles', 0),
                    'nodes_deleted': summary.get('nodes', 0),
                    'records_deleted': summary.get('records', 0),
                    'errors': summary.get('errors', 0),
                },
            })
        return summary


class PointOfNoReturnCommand(Command):
    def get_parser(self):
        return gate_parser

    def execute(self, params, **kwargs):
        from .gate import evaluate, write_checkpoint, GateError
        try:
            checkpoint = evaluate(
                kwargs['checks'],
                reconcile_md=kwargs.get('reconciliation'),
                confirm_token=kwargs.get('confirm', ''),
            )
        except GateError as e:
            logging.error('gate FAILED: %s', e)
            return {'passed': False, 'reason': str(e)}
        signed = write_checkpoint(checkpoint, kwargs['checkpoint'])
        logging.info('gate PASSED — checkpoint written: %s', kwargs['checkpoint'])
        # Phase 2 audit-emission gap fix: the point-of-no-return gate
        # is the explicit authorization to begin destructive ops. The
        # signed checkpoint is the artifact; the chain entry binds it
        # to a timestamped event in the audit log so downstream
        # destructive verbs can be traced back to who authorized them.
        audit_log = kwargs.get('audit_log') or os.path.join(
            kwargs.get('run_dir') or
            (os.path.dirname(kwargs.get('checkpoint', '')) or '.'),
            'audit.log',
        )
        if audit_log:
            from .audit import append_audit_event
            append_audit_event(audit_log, {
                'subcommand': 'point-of-no-return',
                'tenant': (getattr(params, 'enterprise', None) or {}).get(
                    'enterprise_name', ''),
                'inputs': {'checks': kwargs.get('checks', ''),
                           'reconciliation': kwargs.get('reconciliation', ''),
                           'checkpoint_path': kwargs.get('checkpoint', ''),
                           'confirm_token_present': bool(kwargs.get('confirm'))},
                'summary': {
                    'passed': True,
                    'checkpoint_timestamp': checkpoint.get('timestamp', ''),
                },
            })
        return {'passed': True, 'checkpoint': signed}


class DecommissionCommand(DestructiveCommand):
    SUBCOMMAND = 'decommission'

    def get_parser(self):
        return decom_parser

    def _run(self, params, **kwargs):
        from .commander_clients import CommanderDecommissionClient, sync_down
        from .decommission import (
            append_manual_completion_audit, generate_plan_markdown,
            load_user_emails, process_users,
        )
        from .dry_run import DryRun, classify_plan, render_report, summarize
        from .gate import GateError, read_checkpoint
        from .safeguards import (
            SafeguardBlocked, banner_for, require_tenant_assertion,
            enforce_batch_cap, production_tenant_warning,
        )

        dry = bool(kwargs.get('dry_run'))
        plan_only = bool(kwargs.get('plan_only'))
        manual_confirm = bool(kwargs.get('confirm_manual_completion'))

        # Plan-only: emit the manual-run script, don't touch the tenant.
        # No checkpoint needed — there's nothing to authorize automating.
        if plan_only:
            emails = list(load_user_emails(kwargs['roster']))
            cfg = getattr(params, 'config_filename', '') or ''
            plan_md = generate_plan_markdown(
                emails, source_config_path=cfg,
            )
            out = kwargs.get('plan_output') or os.path.join(
                os.path.dirname(kwargs['roster']) or '.',
                'decommission.plan.md',
            )
            with open(out, 'w') as f:
                f.write(plan_md)
            os.chmod(out, 0o600)
            logging.info('Plan-only: %d user(s), wrote %s', len(emails), out)
            logging.info('  Run those commands manually, then '
                         'rerun with --confirm-manual-completion.')
            return {'plan_only': True, 'users': len(emails),
                    'plan_path': out}

        # Manual-completion: append the audit event and stop. The
        # deletions were performed by hand.
        if manual_confirm:
            emails = list(load_user_emails(kwargs['roster']))
            audit_log = kwargs.get('audit_log') or os.path.join(
                kwargs.get('run_dir') or '.', 'audit.log',
            )
            event = append_manual_completion_audit(
                emails, audit_log_path=audit_log,
                operator=kwargs.get('operator', ''),
            )
            logging.info('Manual-completion audit: %d user(s) recorded as '
                         'deleted by %s → %s',
                         event['summary']['count'],
                         event['summary']['operator'], audit_log)
            return {'confirm_manual_completion': True,
                    'users': event['summary']['count'],
                    'audit_log': audit_log}

        # Automated execution path — preserved for scripted users, but
        # no longer the recommended flow. Surface that up-front.
        if not kwargs.get('checkpoint'):
            logging.error(
                'BLOCKED: --checkpoint is required for the automated path. '
                'Use --plan-only for the recommended manual flow.'
            )
            return {'blocked': True, 'reason': 'no checkpoint'}
        if not kwargs.get('report_output'):
            logging.error(
                'BLOCKED: --report-output is required for the automated path.'
            )
            return {'blocked': True, 'reason': 'no report-output'}

        logging.warning(
            'Running the AUTOMATED decommission path. User deletion is '
            'irreversible — consider --plan-only instead.'
        )

        try:
            checkpoint = read_checkpoint(
                kwargs['checkpoint'],
                max_age_hours=kwargs.get('max_age_hours', 72),
            )
        except GateError as e:
            logging.error('BLOCKED: %s', e)
            return {'blocked': True, 'reason': str(e)}

        logging.info('Checkpoint valid (age ok, signature ok): %s',
                     checkpoint.get('timestamp'))
        sync_down(params)

        emails = list(load_user_emails(kwargs['roster']))

        # Source-mode interlock enforced by DestructiveCommand base.
        # Remaining live-only safeguards below.
        if not dry:
            try:
                require_tenant_assertion(
                    params,
                    (kwargs.get('expected_tenant_name', '')
                     or kwargs.get('expected_tenant', '')),
                    skip_check=bool(kwargs.get('skip_tenant_check')),
                    subcommand='decommission',
                )
                enforce_batch_cap(
                    len(emails), kwargs.get('batch_cap', 50),
                    override=kwargs.get('override_batch_cap', False),
                    entity_label='source users',
                )
            except SafeguardBlocked as e:
                logging.error('SAFEGUARD: %s', e)
                return {'blocked': True, 'reason': str(e)}
            production_tenant_warning(params)
            banner_for('decommission', dry_run=False, details=[
                f'{len(emails)} source user(s) will be locked + deleted',
                f'tenant: {(getattr(params, "enterprise", None) or {}).get("enterprise_name", "?")}',
            ])

        real_client = CommanderDecommissionClient(params)
        client = DryRun(real_client) if dry else real_client
        summary = process_users(
            emails, client, kwargs['report_output'],
            sleep_seconds=kwargs.get('delay', 0.5),
            dry_run=dry,
        )
        if os.path.exists(kwargs['report_output']):
            os.chmod(kwargs['report_output'], 0o600)
        if dry:
            classified = classify_plan(client, target_state={})
            counts = summarize(classified)
            if kwargs.get('dry_run_report'):
                with open(kwargs['dry_run_report'], 'w') as f:
                    f.write(render_report(classified, counts))
                os.chmod(kwargs['dry_run_report'], 0o600)
            logging.info('[dry-run] would lock+delete: %s', counts)
            return {'dry_run': True, 'counts': counts,
                    'classified': classified, 'summary': summary}
        logging.info('Decommission: %d total, %d deleted, %d errors',
                     summary['total'], summary['deleted'], summary['errors'])
        return summary


class TakeOwnershipRestoreCommand(Command):
    def get_parser(self):
        return restore_ownership_parser

    def execute(self, params, **kwargs):
        from .commander_clients import CommanderRestoreClient, sync_down
        from .take_ownership_restore import restore

        sync_down(params)
        client = CommanderRestoreClient(params)
        result = restore(
            client, kwargs['report'],
            verify_backup_dir=kwargs.get('verify_backup_dir', ''),
            dry_run=bool(kwargs.get('dry_run')),
        )
        logging.info('Restore: %s', result)
        # Phase 2 audit-emission gap fix: ownership restoration is a
        # destructive reversal (moves vaults BACK from admin to users).
        # Must be in the tamper-evident chain alongside the original
        # take-ownership event so audit-verify can pair them.
        if not bool(kwargs.get('dry_run')):
            audit_log = kwargs.get('audit_log') or os.path.join(
                kwargs.get('run_dir') or
                (os.path.dirname(kwargs.get('report', '')) or '.'),
                'audit.log',
            )
            if audit_log:
                from .audit import append_audit_event
                append_audit_event(audit_log, {
                    'subcommand': 'take-ownership-restore',
                    'tenant': (getattr(params, 'enterprise', None) or {}).get(
                        'enterprise_name', ''),
                    'inputs': {'report': kwargs.get('report', ''),
                               'verify_backup_dir': kwargs.get(
                                   'verify_backup_dir', '')},
                    'summary': result if isinstance(result, dict) else {
                        'result': str(result)},
                })
        return result


class TransferUserCommand(DestructiveCommand):
    SUBCOMMAND = 'transfer-user'

    def get_parser(self):
        return transfer_user_parser

    def _run(self, params, **kwargs):
        from .commander_clients import CommanderTransferUserClient, sync_down
        from .dry_run import DryRun, classify_plan, render_report, summarize
        from .safeguards import (
            SafeguardBlocked, banner_for, confirm_interactive,
            enforce_batch_cap, require_tenant_assertion,
            production_tenant_warning,
        )
        from .transfer_user import load_ready_transfer_users, process_users

        sync_down(params)
        admin_email = kwargs.get('admin_email') or getattr(params, 'user', '')
        if not admin_email:
            logging.error('No admin-email specified and params.user is empty.')
            return
        users = list(load_ready_transfer_users(kwargs['readiness_report']))
        real_client = CommanderTransferUserClient(params)
        dry = bool(kwargs.get('dry_run'))

        # Source-mode interlock enforced by DestructiveCommand base.
        if not dry:
            try:
                require_tenant_assertion(
                    params, kwargs.get('expected_tenant_name', ''),
                    skip_check=bool(kwargs.get('skip_tenant_check')),
                    subcommand='transfer-user',
                )
                enforce_batch_cap(
                    len(users), kwargs.get('batch_cap', 50),
                    override=kwargs.get('override_batch_cap', False),
                    entity_label='READY_TRANSFER users',
                )
            except SafeguardBlocked as e:
                logging.error('SAFEGUARD: %s', e)
                return {'blocked': True, 'reason': str(e)}
            production_tenant_warning(params)
            banner_for('transfer-user', dry_run=False, details=[
                f'{len(users)} source vault(s) will be transferred + locked',
                f'into admin={admin_email}',
                f'tenant: {(getattr(params, "enterprise", None) or {}).get("enterprise_name", "?")}',
            ])
            if not kwargs.get('yes'):
                ok = confirm_interactive(
                    'CONFIRM transfer-user',
                    f'Transfer {len(users)} user vault(s) into {admin_email} '
                    'and auto-lock each source user? Source users cannot log '
                    'in again until unlocked manually.',
                )
                if not ok:
                    logging.info('transfer-user rejected by user.')
                    return {'aborted': True}

        client = DryRun(real_client) if dry else real_client

        from .checkpoint import Checkpoint, CheckpointMismatchError
        ckpt = None
        if not dry:
            run_dir = kwargs.get('run_dir') or (
                os.path.dirname(kwargs['readiness_report']) or '.')
            ckpt = Checkpoint('transfer-user', run_dir)

        try:
            summary = process_users(
                users, client, admin_email,
                report_path=kwargs['report_output'],
                sleep_seconds=kwargs.get('delay', 2.0),
                dry_run=dry,
                checkpoint=ckpt,
                resume=bool(kwargs.get('resume')),
                force_restart=bool(kwargs.get('force_restart')),
            )
        except CheckpointMismatchError as e:
            logging.error('%s', e)
            return {'blocked': True, 'reason': 'checkpoint mismatch'}

        if os.path.exists(kwargs['report_output']):
            os.chmod(kwargs['report_output'], 0o600)
        if dry:
            classified = classify_plan(client, target_state={})
            counts = summarize(classified)
            if kwargs.get('dry_run_report'):
                with open(kwargs['dry_run_report'], 'w') as f:
                    f.write(render_report(classified, counts))
                os.chmod(kwargs['dry_run_report'], 0o600)
            logging.info('[dry-run] %s', counts)
            return {'dry_run': True, 'counts': counts,
                    'classified': classified, 'summary': summary}
        logging.info('Transfer-user: %d total, %d transferred, %d skipped, %d errors',
                     summary['total'], summary['transferred'],
                     summary['skipped'], summary['errors'])
        # Phase 2 audit-emission gap fix: transfer-user is destructive
        # (locks source users, transfers their vaults). Mutation MUST
        # be in the tamper-evident chain.
        audit_log = kwargs.get('audit_log') or os.path.join(
            kwargs.get('run_dir') or
            (os.path.dirname(kwargs.get('readiness_report', '')) or '.'),
            'audit.log',
        )
        if audit_log:
            from .audit import append_audit_event
            append_audit_event(audit_log, {
                'subcommand': 'transfer-user',
                'tenant': (getattr(params, 'enterprise', None) or {}).get(
                    'enterprise_name', ''),
                'inputs': {'admin_email': admin_email,
                           'user_count_input': len(users),
                           'expected_tenant_name': kwargs.get('expected_tenant_name', '')},
                'summary': {
                    'total': summary.get('total', 0),
                    'transferred': summary.get('transferred', 0),
                    'skipped': summary.get('skipped', 0),
                    'errors': summary.get('errors', 0),
                },
            })
        return summary


class SessionCommand(Command):
    def get_parser(self):
        return session_parser

    def execute(self, params, **kwargs):
        from .session import detect_session, format_session_banner
        ctx = detect_session(params)
        for line in format_session_banner(ctx).splitlines():
            logging.info(line)
        return ctx


class AutoMigrateCommand(Command):
    """Unified end-to-end migration. See auto_migrate.py for the
    stage catalog + safety model."""

    def get_parser(self):
        return auto_migrate_parser

    def execute(self, params, **kwargs):
        from . import auto_migrate

        # --live wins over the default-on --dry-run.
        dry_run = not bool(kwargs.get('live')) and bool(kwargs.get('dry_run', True))

        # Bug 71 / Bug 72 (v1.6.6) — --debug bumps the keeperCMD
        # plugin's logger to INFO (not ROOT to DEBUG, which leaked
        # Commander's raw RSA/ECC key material into log files via
        # internal DEBUG dumps). Per-stage progress is now wired
        # via INFO-level lines in our own code; --debug just
        # enables visibility on those without touching upstream
        # Commander's verbosity.
        if kwargs.get('debug'):
            import logging as _logging
            # Bug 71 → Bug 72 (v1.6.6): bump ROOT to INFO (not DEBUG).
            # DEBUG-level Commander internals dump enterprise data
            # blobs including encrypted RSA/ECC private keys + tree
            # key. INFO-level Commander output is operationally
            # safe (status banners, throttle events). Operators
            # wanting raw protocol-level debug can pass --keeper-
            # debug separately (Commander's own flag).
            _logging.getLogger().setLevel(_logging.INFO)
            _logging.warning('--debug enabled: INFO-level progress for our '
                             'plugin + INFO-level Commander internals. For '
                             'protocol-level Commander debug (CAUTION: '
                             'leaks key material to log file), pass '
                             '--keeper-debug separately.')

        only = [s.strip() for s in (kwargs.get('only_stages') or '').split(',')
                if s.strip()]
        skip = [s.strip() for s in (kwargs.get('skip_stages') or '').split(',')
                if s.strip()]

        cfg = auto_migrate.RunConfig(
            run_dir=kwargs['run_dir'],
            scope_node=kwargs.get('scope_node', ''),
            prefix=kwargs.get('prefix', ''),
            target_root=kwargs.get('target_root', ''),
            mc=kwargs.get('mc', ''),
            target_user=kwargs.get('target_user', '') or '',
            target_server=kwargs.get('target_server', '') or '',
            target_config=kwargs.get('target_config', '') or '',
            target_vault_record=kwargs.get('target_vault_record', '') or '',
            dry_run=dry_run,
            yes=bool(kwargs.get('yes')),
            expected_source_tenant=kwargs.get('expected_source_tenant', ''),
            expected_target_tenant=kwargs.get('expected_target_tenant', ''),
            only_stages=only,
            skip_stages=skip,
            resume=bool(kwargs.get('resume')),
            force_restart=bool(kwargs.get('force_restart')),
            old_domain=kwargs.get('old_domain', '') or '',
            new_domain=kwargs.get('new_domain', '') or '',
            include_fields=bool(kwargs.get('include_fields')),
            sso_policy=kwargs.get('sso_policy', 'warn'),
            # Bug 49 — propagate to RecordsManifestCommand via
            # _s_records_manifest. Default-False preserves prior strict
            # behavior; --allow-ambiguous opts in to positional pairing.
            allow_ambiguous=bool(kwargs.get('allow_ambiguous')),
            import_chunk_size=int(kwargs.get('import_chunk_size', 0) or 0),
            import_chunk_delay=float(
                kwargs.get('import_chunk_delay', 2.0) or 2.0),
            delay=float(kwargs.get('delay', 0.0) or 0.0),
            delay_structure=float(kwargs.get('delay_structure', 0.0) or 0.0),
            delay_records=float(kwargs.get('delay_records', 0.0) or 0.0),
            delay_attachments=float(
                kwargs.get('delay_attachments', 0.0) or 0.0),
            delay_shares=float(kwargs.get('delay_shares', 0.0) or 0.0),
            jitter=float(kwargs.get('jitter', 0.5) or 0.0),
            reserve_quota_every=int(kwargs.get('reserve_quota_every', 0) or 0),
            reserve_quota_seconds=float(
                kwargs.get('reserve_quota_seconds', 2.0) or 2.0),
            adaptive_throttle=bool(
                kwargs.get('adaptive_throttle', True)
                if kwargs.get('adaptive_throttle') is not None else True),
            adaptive_base_delay=float(
                kwargs.get('adaptive_base_delay', 2.0) or 2.0),
            adaptive_max_delay=float(
                kwargs.get('adaptive_max_delay', 30.0) or 30.0),
            adaptive_success_reset=int(
                kwargs.get('adaptive_success_reset', 20) or 20),
            calls_per_minute=float(
                kwargs.get('calls_per_minute', 0.0) or 0.0),
            burst_capacity=int(
                kwargs.get('burst_capacity', 3) or 3),
            cluster_window=float(
                kwargs.get('cluster_window', 120.0) or 120.0),
            decay_cooldown=float(
                kwargs.get('decay_cooldown', 60.0) or 60.0),
            bucket_decay_every_n_windows=int(
                kwargs.get('bucket_decay_every_n_windows', 3) or 3),
            batch_size=int(kwargs.get('batch_size', 0) or 0),
            source_folder_uids=list(kwargs.get('source_folder_uids') or []),
        )

        try:
            auto_migrate.validate_config(cfg)
        except ValueError as e:
            logging.error('auto-migrate config invalid: %s', e)
            return {'ok': False, 'reason': str(e)}

        # Build the session pair. Source is already authenticated
        # via the outer --config flag; target is obtained now.
        sessions = auto_migrate.SessionPair(source_params=params)

        if cfg.target_config:
            auto_migrate.attach_config_target(
                sessions, config_path=cfg.target_config,
            )
        elif cfg.target_vault_record:
            auto_migrate.attach_vault_record_target(
                sessions, record_uid=cfg.target_vault_record,
                server_override=cfg.target_server,
            )
        else:
            auto_migrate.attach_interactive_target(
                sessions, user=cfg.target_user,
                server=cfg.target_server,
            )

        # Post-login safety — expected_* assertions.
        if (cfg.expected_source_tenant
                and sessions.source_tenant_name
                and cfg.expected_source_tenant != sessions.source_tenant_name):
            logging.error(
                'auto-migrate: source tenant %r ≠ expected %r',
                sessions.source_tenant_name, cfg.expected_source_tenant,
            )
            return {'ok': False, 'reason': 'expected_source_tenant'}
        if (cfg.expected_target_tenant
                and sessions.target_tenant_name
                and cfg.expected_target_tenant != sessions.target_tenant_name):
            logging.error(
                'auto-migrate: target tenant %r ≠ expected %r',
                sessions.target_tenant_name, cfg.expected_target_tenant,
            )
            return {'ok': False, 'reason': 'expected_target_tenant'}

        # Pre-run banner.
        from .safeguards import banner_for, confirm_interactive
        banner_for('auto-migrate', dry_run=cfg.dry_run, details=[
            f'source: {sessions.source_tenant_name or "?"}',
            f'target: {sessions.target_tenant_name or "?"}',
            f'scope:  {cfg.scope_node or "(full tenant)"}',
            f'prefix: {cfg.prefix or "(none)"}',
            f'run-dir: {cfg.run_dir}',
            f'stages: {len(auto_migrate.effective_stages(cfg))}',
        ])
        if not cfg.dry_run and not cfg.yes:
            ok = confirm_interactive(
                'CONFIRM auto-migrate',
                f'Commit writes to target tenant '
                f'{sessions.target_tenant_name!r}? This will create '
                f'structure + import records.',
            )
            if not ok:
                logging.info('auto-migrate rejected by user.')
                return {'aborted': True}

        summary = auto_migrate.run(sessions, cfg)
        counts = summary['counts']
        logging.info('auto-migrate: %d PASS / %d FAIL / %d SKIP',
                     counts['PASS'], counts['FAIL'], counts['SKIP'])
        return summary


class SharedFoldersReconcileCommand(Command):
    def get_parser(self):
        return sf_reconcile_parser

    def execute(self, params, **kwargs):
        from .checkpoint import Checkpoint, CheckpointMismatchError
        from .commander_clients import CommanderSFReconcileClient, sync_down
        from .sf_reconcile import (
            SFReconciler, load_inventory, plan_reconciliation, render_report,
        )

        sync_down(params)
        inv_path = kwargs['inventory']
        inventory = load_inventory(inv_path)
        client = CommanderSFReconcileClient(params)
        prune = bool(kwargs.get('prune'))
        plan = plan_reconciliation(
            inventory, client,
            old_domain=kwargs.get('old_domain', ''),
            new_domain=kwargs.get('new_domain', ''),
            prune=prune,
        )

        report_path = kwargs.get('report') or os.path.join(
            os.path.dirname(inv_path) or '.', 'reconcile.md')

        if kwargs.get('dry_run'):
            with open(report_path, 'w') as f:
                f.write(render_report(plan))
            logging.info(
                'Dry-run: would apply=%d, pending=%d, errors=%d, '
                'to_prune=%d',
                len(plan.to_apply), len(plan.pending), len(plan.errors),
                len(plan.to_prune),
            )
            logging.info('  report: %s', report_path)
            return {
                'dry_run': True,
                'to_apply': len(plan.to_apply),
                'pending': len(plan.pending),
                'errors': len(plan.errors),
                'to_prune': len(plan.to_prune),
            }

        run_dir = kwargs.get('run_dir') or (
            os.path.dirname(inv_path) or '.')
        ckpt = Checkpoint('shared-folders-reconcile', run_dir)
        reconciler = SFReconciler(
            client,
            delay=kwargs.get('delay', 0.0),
            batch_size=kwargs.get('batch_size', 0),
            checkpoint=ckpt,
            resume=bool(kwargs.get('resume')),
            force_restart=bool(kwargs.get('force_restart')),
            prune=prune,
        )
        try:
            result = reconciler.run(plan)
        except CheckpointMismatchError as e:
            logging.error('%s', e)
            return {'blocked': True, 'reason': 'checkpoint mismatch'}

        with open(report_path, 'w') as f:
            f.write(render_report(plan, run=result))

        logging.info(
            'Reconcile: applied=%d pending=%d errors=%d (resumed=%d)',
            len(result['applied']), len(result['pending']),
            len(result['errors']), result['resumed'],
        )
        logging.info('  report: %s', report_path)

        # Audit — each grant is a first-class event.
        try:
            from .audit import append_audit_event
            audit_log = os.path.join(run_dir, 'audit.log')
            append_audit_event(audit_log, {
                'subcommand': 'shared-folders-reconcile',
                'inputs': {'inventory': os.path.abspath(inv_path)},
                'summary': {
                    'applied': [{'sf': it.sf_name, 'email': it.email}
                                for it in result['applied']],
                    'counts': {
                        'applied': len(result['applied']),
                        'pending': len(result['pending']),
                        'errors': len(result['errors']),
                    },
                },
            })
        except OSError as _e:
            logging.warning('reconcile audit emit skipped (I/O error): %s', _e)

        return {
            'applied': len(result['applied']),
            'pending': len(result['pending']),
            'errors': len(result['errors']),
            'resumed': result['resumed'],
            'report': report_path,
        }


class EstimateCommand(Command):
    def get_parser(self):
        return estimate_parser

    def execute(self, params, **kwargs):
        import json
        from .estimate import (
            estimate_from_counts, load_inventory_counts, render_markdown,
        )

        inv_path = kwargs['inventory']
        counts = load_inventory_counts(inv_path)

        out_arg = kwargs.get('output') or ''
        out_json_arg = kwargs.get('output_json') or ''
        # Route based on extension so `--output X.json` writes JSON not markdown.
        if out_arg.endswith('.json') and not out_json_arg:
            out_json_arg, out_arg = out_arg, ''
        out_md = out_arg or os.path.join(
            os.path.dirname(inv_path) or '.', 'estimate.md')
        out_json = out_json_arg or os.path.join(
            os.path.dirname(inv_path) or '.', 'estimate.json')

        est = estimate_from_counts(
            counts, tier_driver=kwargs.get('tier_driver') or 'auto',
            calls_per_minute=float(kwargs.get('calls_per_minute', 0.0) or 0.0),
        )

        enterprise = ''
        try:
            with open(inv_path) as f:
                enterprise = (json.load(f).get('enterprise') or {}).get('name', '')
        except (OSError, json.JSONDecodeError):
            pass

        with open(out_md, 'w') as f:
            f.write(render_markdown(est, enterprise_name=enterprise))
        with open(out_json, 'w') as f:
            json.dump(est.as_json(), f, indent=2)

        logging.info('Estimate: %s calls, ~%s at %s',
                     f'{est.total_calls:,}',
                     est.as_json()['totals']['duration_human'],
                     est.tier_label)
        logging.info('  report: %s', out_md)
        logging.info('  json:   %s', out_json)
        return est.as_json()


class PlanReportCommand(Command):
    def get_parser(self):
        return plan_report_parser

    def execute(self, params, **kwargs):
        from .plan_report import write_report

        inv = kwargs.get('inventory') or ''
        nsf = kwargs.get('nested_sf_plan') or ''
        est = kwargs.get('estimate') or ''
        if not (inv or nsf or est):
            logging.error('plan-report: at least one of --inventory, '
                          '--nested-sf-plan, or --estimate is required.')
            return {'error': 'no_inputs'}

        out_md = kwargs['output']
        md_path, json_path = write_report(
            out_md,
            inventory_path=inv,
            nested_sf_plan_path=nsf,
            estimate_path=est,
        )
        logging.info('Plan report: %s', md_path)
        logging.info('  mirror:   %s', json_path)
        return {'report_path': md_path, 'mirror_path': json_path}


class NestedSfPlanCommand(Command):
    def get_parser(self):
        return nested_sf_plan_parser

    def execute(self, params, **kwargs):
        from .nested_sf_plan import (
            classify_inventory, load_inventory, write_plan,
        )

        inv_path = kwargs['inventory']
        if not os.path.isfile(inv_path):
            logging.error('Inventory file not found: %s', inv_path)
            return {'error': 'inventory_missing', 'path': inv_path}

        inventory = load_inventory(inv_path)
        default_action = (kwargs.get('default_action')
                          or 'promote-to-sibling')
        per_folder_rules = kwargs.get('per_folder_rules') or None
        default_conflict = (kwargs.get('default_conflict_resolution')
                            or 'error')
        plan = classify_inventory(
            inventory,
            default_action=default_action,
            per_folder_rules=per_folder_rules,
            default_conflict_resolution=default_conflict,
        )
        out_path = kwargs['output']
        checksum = write_plan(plan, out_path)
        logging.info('nested-sf-plan: %d decisions (inherit=%d, '
                     'promotion-candidate=%d, cannot-classify=%d)',
                     len(plan['decisions']),
                     plan['summary'].get('inherit', 0),
                     plan['summary'].get('promotion-candidate', 0),
                     plan['summary'].get('cannot-classify', 0))
        plan['_checksum'] = checksum
        plan['_output_path'] = out_path
        return plan


class WizardCommand(Command):
    def get_parser(self):
        return wizard_parser

    def execute(self, params, **kwargs):
        from .wizard import Wizard
        wiz = Wizard(params, kwargs['run_dir'],
                      auto_adjust=not kwargs.get('no_auto_adjust'))
        return wiz.run()


class SelfTestCommand(Command):
    def get_parser(self):
        return selftest_parser

    def execute(self, params, **kwargs):
        from .selftest import run
        from .commander_clients import sync_down
        sync_down(params)
        results, fails = run(params)
        status = 'PASS' if fails == 0 else f'{fails} FAIL'
        logging.info('Self-test: %d check(s), %s', len(results), status)
        return {'results': results, 'fails': fails}


class PreFlightCommand(Command):
    def get_parser(self):
        return preflight_parser

    def execute(self, params, **kwargs):
        from .preflight import run
        results, fails, warns = run(
            params, kwargs['roster'], kwargs.get('output_dir', '.'),
        )
        logging.info('Pre-flight: %d total, %d fails, %d warns',
                     len(results), fails, warns)
        if kwargs.get('csv_output'):
            import csv as _csv
            with open(kwargs['csv_output'], 'w', newline='') as f:
                w = _csv.writer(f)
                w.writerow(['name', 'status', 'message'])
                for r in results:
                    w.writerow(r.as_row())
        return {'results': results, 'fails': fails, 'warns': warns}


class AuditVerifyCommand(Command):
    def get_parser(self):
        return audit_verify_parser

    def execute(self, params, **kwargs):
        from .audit import verify_audit_log, verify_sha256sums
        directory = kwargs['directory']
        if not os.path.isdir(directory):
            logging.error('not a directory: %s', directory)
            return {'ok': False, 'reason': 'directory_missing'}
        try:
            sums = verify_sha256sums(directory)
        except FileNotFoundError as e:
            sums = None
            logging.warning('%s', e)
        audit_log = kwargs.get('audit_log') or os.path.join(directory, 'audit.log')
        chain_ok, broken_line = True, None
        if os.path.exists(audit_log):
            chain_ok, broken_line = verify_audit_log(audit_log)
        else:
            logging.info('no audit.log found — skipping chain verify')

        files_ok = sums is not None and len(sums.get('mismatch', [])) == 0 \
            and len(sums.get('missing', [])) == 0
        logging.info('File hashes: ok=%d missing=%d mismatch=%d  |  '
                     'chain=%s (broken@%s)',
                     len(sums.get('ok', [])) if sums else 0,
                     len(sums.get('missing', [])) if sums else 0,
                     len(sums.get('mismatch', [])) if sums else 0,
                     'PASS' if chain_ok else 'FAIL', broken_line)
        return {'ok': bool(sums) and files_ok and chain_ok,
                'files': sums, 'chain_ok': chain_ok,
                'broken_line': broken_line}


class AuditLockoutRiskCommand(Command):
    """v1.7 — read-only audit of lockout-risk enforcements on target's
    builtin-admin roles. Sister to the structure-side default-skip
    (`--apply-admin-lockout-risk-enforcements`) and the verify-side
    SKIP coverage. Runs pre- or post-migration; never writes."""

    def get_parser(self):
        return audit_lockout_risk_parser

    def execute(self, params, **kwargs):
        from .mc_context import MCContext
        with MCContext(params, kwargs.get('mc', '')) as ctx:
            return self._run(ctx.params, **kwargs)

    def _run(self, params, **kwargs):
        from .commander_clients import sync_down
        from .structure import (BUILTIN_ROLE_NAMES, BUILTIN_ROLE_SUFFIX,
                                LOCKOUT_RISK_ENFORCEMENTS)
        sync_down(params)
        target_state = _params_enterprise_to_target_state(params)

        target_findings = self._scan_roles(
            target_state.get('roles', []) or [],
            BUILTIN_ROLE_NAMES, BUILTIN_ROLE_SUFFIX,
            LOCKOUT_RISK_ENFORCEMENTS)

        source_findings = None
        source_path = kwargs.get('source_inventory') or ''
        if source_path:
            if not os.path.isfile(source_path):
                logging.error('source inventory not found: %s', source_path)
                return {'ok': False, 'reason': 'source_inventory_missing'}
            with open(source_path) as f:
                inv = json.load(f)
            source_findings = self._scan_roles(
                (inv.get('entities') or {}).get('roles') or [],
                BUILTIN_ROLE_NAMES, BUILTIN_ROLE_SUFFIX,
                LOCKOUT_RISK_ENFORCEMENTS)

        report = self._render_markdown(target_findings, source_findings,
                                       LOCKOUT_RISK_ENFORCEMENTS)
        out_path = kwargs.get('output') or ''
        if out_path:
            with open(out_path, 'w') as f:
                f.write(report)
            logging.info('audit-lockout-risk report → %s', out_path)
        else:
            print(report)
        return {'ok': True, 'target': target_findings,
                'source': source_findings}

    @staticmethod
    def _scan_roles(roles, builtin_names, builtin_suffix, lockout_keys):
        """For each builtin-admin role in `roles`, return a dict
        mapping bare-role-name → set of present lockout-risk keys."""
        out = {}
        for r in roles:
            name = r.get('name', '') or ''
            bare = name.replace(builtin_suffix, '')
            if bare not in builtin_names:
                continue
            enfs = r.get('enforcements', {}) or {}
            present = sorted(k for k in enfs if k in lockout_keys)
            out[bare] = present
        return out

    @staticmethod
    def _render_markdown(target_findings, source_findings, lockout_keys):
        lines = []
        lines.append('# Lockout-Risk Enforcement Audit')
        lines.append('')
        lines.append('Tracked enforcements (any of these can lock the '
                     'target tenant administrator out):')
        lines.append('')
        for k in sorted(lockout_keys):
            lines.append(f'- `{k}`')
        lines.append('')
        lines.append('## Target tenant — builtin-admin roles')
        lines.append('')
        if not target_findings:
            lines.append('_no builtin-admin roles found on target_')
        else:
            lines.append('| Role | Lockout-risk enforcements present |')
            lines.append('|---|---|')
            for role in sorted(target_findings):
                keys = target_findings[role]
                cell = ', '.join(f'`{k}`' for k in keys) if keys \
                    else '_(none)_'
                lines.append(f'| `{role}` | {cell} |')
        lines.append('')
        if source_findings is not None:
            lines.append('## Source-vs-target drift')
            lines.append('')
            all_roles = sorted(set(source_findings) | set(target_findings))
            drift_rows = []
            for role in all_roles:
                src_keys = set(source_findings.get(role, []))
                tgt_keys = set(target_findings.get(role, []))
                only_source = sorted(src_keys - tgt_keys)
                only_target = sorted(tgt_keys - src_keys)
                if only_source or only_target:
                    drift_rows.append((role, only_source, only_target))
            if not drift_rows:
                lines.append('_no drift — source and target agree on all '
                             'builtin-admin lockout-risk enforcements_')
            else:
                lines.append('| Role | Only on source | Only on target |')
                lines.append('|---|---|---|')
                for role, only_s, only_t in drift_rows:
                    s = ', '.join(f'`{k}`' for k in only_s) or '—'
                    t = ', '.join(f'`{k}`' for k in only_t) or '—'
                    lines.append(f'| `{role}` | {s} | {t} |')
        lines.append('')
        lines.append('## Operator guidance')
        lines.append('')
        lines.append('- **Pre-migration**: target should ideally have '
                     'NONE of these enforcements set on builtin-admin '
                     'roles before migration so the operator has '
                     'unrestricted access to fix any drift the '
                     'migration produces.')
        lines.append('- **Post-migration**: any value here that doesn\'t '
                     'match an audited source value warrants a manual '
                     'check before the operator hands the tenant off '
                     'to the customer.')
        lines.append('- **Default v1.7 structure-side behavior**: '
                     'these enforcements are SKIPPED on builtin-admin '
                     'roles unless `--apply-admin-lockout-risk-'
                     'enforcements` is passed. See '
                     '`.context/v1.7-lockout-risk-enforcements-plan.md`.')
        return '\n'.join(lines) + '\n'


class AuditExportCommand(Command):
    def get_parser(self):
        return audit_export_parser

    def execute(self, params, **kwargs):
        from .audit_export import export
        result = export(
            kwargs['audit_log'], kwargs['output'],
            kwargs['format'], hostname=kwargs.get('hostname', ''),
        )
        logging.info('audit-export: %d event(s) → %s (%s)',
                     result['written'], result['output_path'],
                     result['format'])
        return result


class UndoCommand(Command):
    def get_parser(self):
        return undo_parser

    def execute(self, params, **kwargs):
        from .commander_clients import CommanderUndoClient
        from .mc_context import MCContext
        from .safeguards import (
            SafeguardBlocked, banner_for, confirm_interactive,
        )
        from .undo import run as undo_run

        execute = bool(kwargs.get('execute'))
        hard = bool(kwargs.get('hard'))

        if execute:
            banner_for('undo', dry_run=False, details=[
                f'audit-log: {kwargs["audit_log"]}',
                f'mode: {"HARD (delete users)" if hard else "soft (lock users)"}',
            ])
            if not kwargs.get('yes'):
                ok = confirm_interactive(
                    'CONFIRM undo',
                    'Rewind migration per audit.log? This mutates the target.',
                )
                if not ok:
                    logging.info('undo aborted by user.')
                    return {'aborted': True}

        # Phase 2 Audit 3 #5 fix: prior events may have been scoped to
        # a Managed Company via --mc; rewinding must target the same
        # MC scope or the inverse ops land on the MSP root by default.
        # MCContext is a context manager — the with block must wrap
        # the mutation so the MC scope stays applied during undo_run.
        with MCContext(params, kwargs.get('mc', '')) as ctx:
            client = CommanderUndoClient(ctx.params) if execute else None
            result = undo_run(
                kwargs['audit_log'], client,
                up_to_signature=kwargs.get('up_to'),
                hard=hard, execute=execute,
            )
        # Phase 2 audit-emission gap fix: undo IS the destructive
        # reversal — by definition it must self-record so a second
        # undo, a verify, or a post-mortem can see what was rewound,
        # in what mode, by whom. Use a SEPARATE post-event log to
        # avoid corrupting the audit chain that undo is reading.
        if execute:
            audit_log_in = kwargs['audit_log']
            undo_audit_log = kwargs.get('undo_audit_log') or (
                os.path.join(os.path.dirname(audit_log_in) or '.',
                             'audit.undo.log'))
            from .audit import append_audit_event
            append_audit_event(undo_audit_log, {
                'subcommand': 'undo',
                'tenant': (getattr(params, 'enterprise', None) or {}).get(
                    'enterprise_name', ''),
                'inputs': {'source_audit_log': audit_log_in,
                           'up_to_signature': kwargs.get('up_to', ''),
                           'hard': hard,
                           'execute': True,
                           'mc': kwargs.get('mc', '')},
                'summary': result if isinstance(result, dict) else {
                    'result': str(result)},
            })
        return result


class ManualActionsCommand(Command):
    def get_parser(self):
        return manual_actions_parser

    def execute(self, params, **kwargs):
        from .manual_actions import enumerate_actions, render_actions_markdown

        with open(kwargs['inventory']) as f:
            inventory = json.load(f)
        target_state = None
        if kwargs.get('target_state'):
            with open(kwargs['target_state']) as f:
                target_state = json.load(f)
        transition_plan = None
        if kwargs.get('transition_plan'):
            import csv as _csv
            with open(kwargs['transition_plan'], newline='') as f:
                transition_plan = list(_csv.DictReader(f))

        actions = enumerate_actions(inventory, target_state=target_state,
                                     transition_plan=transition_plan)
        with open(kwargs['output'], 'w') as f:
            f.write(render_actions_markdown(actions))
        logging.info('Manual actions: %d item(s) → %s',
                     len(actions), kwargs['output'])
        return {'actions': actions, 'output': kwargs['output']}


class CaptureTargetStateCommand(Command):
    def get_parser(self):
        return capture_parser

    def execute(self, params, **kwargs):
        from .mc_context import MCContext
        with MCContext(params, kwargs.get('mc', '')) as ctx:
            return self._capture(ctx.params, **kwargs)

    def _capture(self, params, **kwargs):
        from .commander_clients import sync_down
        sync_down(params)
        state = _params_enterprise_to_target_state(params)
        # Always emit record title+uid from the cache so phase_records
        # can do presence checks without `--include-fields` (which would
        # leak plaintext to disk). `include_fields` upgrades this list
        # to the full field-level summary.
        prefix = kwargs.get('prefix', '')
        if kwargs.get('include_fields'):
            from .live_inventory import build_record_entities
            state['records'] = build_record_entities(
                params, prefix, include_fields=True,
            )
        else:
            # Lightweight list — title + uid + count flags. A single
            # decryption or cache-miss on one UID must NOT abort the
            # whole capture; log+skip per-uid keeps target_state.json
            # writeable even when the admin has stale shares.
            # Bug 24 — extract attachment_count and has_totp from the
            # decrypted record data so phase_records can compare these
            # without --include-fields. Source-side build_record_entities
            # already emits them; target was missing them, causing
            # spurious "attachment_count src=1 target=0" WARNs after
            # successful attachment migration.
            cache = getattr(params, 'record_cache', None) or {}
            from keepercommander import api
            import json as _json
            lightweight = []
            skipped = 0
            for uid in cache.keys():
                try:
                    rec = api.get_record(params, uid)
                except Exception as e:                   # noqa: BLE001
                    # Narrow exception would be preferable but Commander's
                    # get_record can raise anything from api.CryptoError to
                    # KeyError to RuntimeError across SDK versions.
                    logging.debug('capture: skipping %s: %r', uid, e)
                    skipped += 1
                    continue
                if rec is None or not rec.title:
                    continue
                if prefix and not rec.title.startswith(prefix):
                    continue
                # Extract attachment_count + has_totp + record type
                # from the decoded record data. Best-effort: a parse
                # failure leaves the defaults (0 / False / 'login')
                # rather than crashing the capture.
                # Bug 24 added attachment_count + has_totp.
                # Bug 43 adds `type` so phase_records' Bug 41 type
                # check can fire — without it the lightweight target
                # projection had no type and the check skipped silently.
                attach_count = 0
                has_totp = False
                rec_type = 'login'
                try:
                    data_raw = cache.get(uid, {}).get('data_unencrypted', b'{}')
                    if isinstance(data_raw, bytes):
                        data_raw = data_raw.decode('utf-8', errors='replace')
                    data = _json.loads(data_raw)
                    rec_type = data.get('type') or 'login'
                    fields = data.get('fields') or []
                    for f in fields:
                        if not isinstance(f, dict):
                            continue
                        ftype = f.get('type', '')
                        if ftype == 'fileRef':
                            attach_count += len(f.get('value') or [])
                        elif ftype == 'oneTimeCode' and f.get('value'):
                            has_totp = True
                except (_json.JSONDecodeError, AttributeError, TypeError):
                    pass
                lightweight.append({
                    'record_uid': uid, 'title': rec.title,
                    'type': rec_type,
                    'attachment_count': attach_count,
                    'has_totp': has_totp,
                })
            state['records'] = lightweight
            if skipped:
                logging.warning('capture: skipped %d record(s) that '
                                 'failed to decrypt or load', skipped)
        with open(kwargs['output'], 'w') as f:
            json.dump(state, f, indent=2)
        # May contain plaintext record fields when --include-fields is set.
        if kwargs.get('include_fields'):
            os.chmod(kwargs['output'], 0o600)
        logging.info('Captured target state: nodes=%d teams=%d roles=%d users=%d '
                     'sfs=%d records=%d → %s',
                     len(state['nodes']), len(state['teams']),
                     len(state['roles']), len(state['users']),
                     len(state['shared_folders']),
                     len(state.get('records', [])), kwargs['output'])
        return state


class TenantMigrateCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command('plan', PlanCommand(),
                              'Capture source inventory from current session.')
        self.register_command('users', UsersCommand(),
                              'Invite/place users on current (target) tenant per inventory.')
        self.register_command('structure', StructureCommand(),
                              'Restore nodes, teams, roles, enforcements, SFs.')
        self.register_command('records', RecordsUmbrellaCommand(),
                              'Umbrella: export+convert (source) or '
                              'manifest+import+attachments+shares (target), '
                              'driven by --run-dir.')
        self.register_command('verify', VerifyCommand(),
                              'Field-level verification against frozen inventory.')
        self.register_command('reconcile', ReconcileCommand(),
                              'Source/Target/Delta Markdown reconciliation report.')
        self.register_command('run', RunCommand(),
                              'Target-side orchestrator: structure → users → '
                              'records → verify → reconcile (records = '
                              'import+attachments+shares when bundle present).')
        self.register_command('convert', ConvertCommand(),
                              'Convert exported v3 records to Commander import v2 format.')
        self.register_command('assemble-inventory', AssembleInventoryCommand(),
                              'Assemble inventory JSON from staged CSV/JSON.')
        self.register_command('transition-check', TransitionCheckCommand(),
                              'Classify source users (A/D/E/UNKNOWN) against target state.')
        self.register_command('capture-target-state', CaptureTargetStateCommand(),
                              'Dump the current session\'s enterprise data to JSON.')
        self.register_command('manual-actions', ManualActionsCommand(),
                              'Emit Markdown checklist of human actions the '
                              'migration cannot automate (user folder sharing, '
                              'invite acceptance, admin unlocking, etc.).')
        self.register_command('audit-verify', AuditVerifyCommand(),
                              'Check SHA256SUMS.txt + chained audit.log integrity '
                              'in a records-export / take-ownership output dir.')
        self.register_command('audit-export', AuditExportCommand(),
                              'Export audit.log to SIEM-ingestible format '
                              '(json-lines / syslog / cef). Read-only.')
        self.register_command('audit-lockout-risk',
                              AuditLockoutRiskCommand(),
                              'Read-only audit of lockout-risk '
                              'enforcements (require_account_share, '
                              'restrict_ip_addresses, '
                              'master_password_reentry, '
                              'two_factor_by_ip) on target builtin-'
                              'admin roles. Optionally cross-compare '
                              'with source inventory.')
        self.register_command('undo', UndoCommand(),
                              'Rollback migration steps using audit.log as '
                              'source of truth. Dry-run by default; --execute '
                              'required to mutate.')
        self.register_command('self-test', SelfTestCommand(),
                              'Read-only SDK-integration check against current session.')
        self.register_command('session', SessionCommand(),
                              'Show current session context (user / region / '
                              'tenant / MSP status).')
        self.register_command('estimate', EstimateCommand(),
                              'Pre-flight tenant size + API call budget + '
                              'runtime estimate from a plan inventory.')
        self.register_command('shared-folders-reconcile',
                              SharedFoldersReconcileCommand(),
                              'Apply deferred SF memberships as target users '
                              'activate. Idempotent, cron-able; add-only.')
        self.register_command('auto-migrate', AutoMigrateCommand(),
                              'Single-command end-to-end migration. '
                              'Authenticates target in-process; chains every '
                              'stage. Defaults to dry-run (pass --live).')
        self.register_command('declare', DeclareGroupCommand(),
                              'Declarative overlay over captured inventory — see `declare overlay` / `declare validate`.')
        self.register_command('wizard', WizardCommand(),
                              'Menu-driven migration wizard — detects source/'
                              'target role, coordinates via shared run-dir, '
                              'and invokes the right next step.')
        self.register_command('pre-flight', PreFlightCommand(),
                              'Roster / Commander version / disk / auth checks before a run.')
        self.register_command('take-ownership', TakeOwnershipCommand(),
                              'Path-A: transfer MIGRATION-* folder ownership to admin '
                              '(with per-user JSON backup).')
        self.register_command('take-ownership-restore', TakeOwnershipRestoreCommand(),
                              'Undo take-ownership: return MIGRATION-* folders to '
                              'original users using the report CSV (with optional '
                              'SHA256SUMS + audit-chain verification).')
        self.register_command('transfer-user', TransferUserCommand(),
                              'Path-B: pull entire user vaults into admin account '
                              '(auto-locks source users).')
        self.register_command('cleanup', CleanupCommand(),
                              'Delete entities matching a prefix (e.g. MIGTEST-). '
                              'Requires --confirm.')
        self.register_command('point-of-no-return', PointOfNoReturnCommand(),
                              'Authorize destructive next steps via signed checkpoint.')
        self.register_command('decommission', DecommissionCommand(),
                              'Lock + delete source users — checkpoint-gated.')
        self.register_command('records-export', RecordsExportCommand(),
                              'Export records from current (source) session as v3 JSON.')
        self.register_command('records-import', RecordsImportCommand(),
                              'Import a convert-ready JSON bundle on current (target) session.')
        self.register_command('records-attachments', RecordsAttachmentsCommand(),
                              'Migrate attachments using a source_uid,target_uid manifest '
                              '(single-session — see records-attachments-download / '
                              '-upload for cross-tenant).')
        self.register_command('records-attachments-download',
                              RecordsAttachmentsDownloadCommand(),
                              'Phase 1 of cross-tenant attachments: source-side '
                              'download into staging-dir.')
        self.register_command('records-attachments-upload',
                              RecordsAttachmentsUploadCommand(),
                              'Phase 2 of cross-tenant attachments: target-side '
                              'upload from staging-dir.')
        self.register_command('records-shares', RecordsSharesCommand(),
                              'Replay direct record shares using the same '
                              'manifest (single-session — see '
                              'records-shares-extract / -apply for '
                              'cross-tenant).')
        self.register_command('records-shares-extract',
                              RecordsSharesExtractCommand(),
                              'Phase 1 of cross-tenant direct shares: '
                              'source-side dump to JSON manifest.')
        self.register_command('records-shares-apply',
                              RecordsSharesApplyCommand(),
                              'Phase 2 of cross-tenant direct shares: '
                              'target-side replay from JSON manifest.')
        self.register_command('records-manifest', RecordsManifestCommand(),
                              'Match source export titles to target UIDs into a manifest CSV.')
        self.register_command('records-references-rewrite',
                              RecordsReferencesRewriteCommand(),
                              'Bug 33 — remap source-record UIDs embedded '
                              'in target record field values (PAM record '
                              'types: httpCredentialsUid, recordRef, '
                              'pamUserUid, pamConfigurationUid, …). '
                              'Idempotent. Run after records-import + '
                              'records-attachments-upload.')
        self.register_command('nested-sf-plan', NestedSfPlanCommand(),
                              'Classify shared_folder_folder subfolders '
                              '(inherit / promotion-candidate / '
                              'cannot-classify) for nested-SF target '
                              'placement. Read-only.')
        self.register_command('plan-report', PlanReportCommand(),
                              'Render customer-friendly markdown report '
                              'combining plan + nested-sf-plan + estimate '
                              'outputs. Read-only. Surfaces only the '
                              'decisions that need operator review.')
        self.default_verb = ''


def register_commands(commands):
    commands['tenant-migrate'] = TenantMigrateCommand()


def register_command_info(aliases, command_info):
    command_info['tenant-migrate'] = 'Migrate tenant structure + users + records between Keeper tenants.'
