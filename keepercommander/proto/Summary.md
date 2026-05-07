Summary
The Commander codebase (CLI, not the Web Vault — same backend, different client) already has substantial KeeperDrive scaffolding. A full kd-* command surface is wired up via keepercommander/commands/keeper_drive/ and an API service layer in keepercommander/keeper_drive/, plus sync-down handling and the KEEPER_DRIVE feature flag.

But several MRD requirements are unimplemented or only partially covered. Here is the requirement-by-requirement audit, then the concrete to-do list.

What's already in place
MRD ID	Requirement	Where it lives	Status
KD1, KD2
Create root / nested folders (canAdd)
kd-mkdir → keeper_drive.create_folder_v3
Implemented
KD3, KD4
Independent sharing & override of inherited permissions (canUpdateAccess)
kd-rndir --no-inherit / --inherit, _build_update_data sets inheritUserPermissions
Implemented
KD5
Update folder metadata title/color (canUpdateSetting)
kd-rndir → update_folder_v3
Implemented
KD6, KD7
Remove / permanently delete folder
kd-rmdir -o folder-trash / delete-permanent → remove_folder_v3
Implemented
KD8, KD9
View folder structure / record titles
kd-list, sync caches keeper_drive_folders/records
Implemented
KD10
View folder accessors (canListAccess)
get_folder_access_v3 (vault/folders/v3/access), kd-get -v
Implemented
KD11
Update folder access
kd-share-folder → grant/update/revoke_folder_access_v3
Implemented (users only — see gaps)
KD13, KD14, KD20–22
View / edit record content
kd-get, kd-record-update, kd-record-add
Implemented
KD15, KD16
Create record at root / inside folder
kd-record-add --folder → create_record_v3
Implemented
KD17, KD18, KD19
Remove record (folder / unlink / permanent)
kd-rm -o owner-trash / folder-trash / unlink → remove_record_v3
Implemented
KD23
View record accessors
get_record_accesses_v3 exposed via kd-get
Implemented
KD24
Update record access
kd-share-record grant/revoke → share_record_v3
Implemented (users only)
KD25
Change record ownership
kd-share-record -a owner and kd-transfer-record → transfer_record_ownership_v3
Implemented
KD32
FeatureFlag.KEEPER_DRIVE gating
params.is_feature_disallowed('keeper_drive') used in cli.py, sync_down.py, autocomplete.py
Implemented
KD33
KeeperDrive ↔ Legacy isolation in mv
commands/folder.py lines 859–911
Partial (only mv)
KD34
Inheritance vs independent sharing
Same as KD3/KD4
Implemented
KD35
Explicit deny overrides
Marked N/A for MVP
N/A
What's missing or incomplete
1. KSM application support (KD29, KD30, KD31) — fully missing
There are zero KeeperDrive↔KSM hooks anywhere under keepercommander/keeper_drive/ or commands/keeper_drive/. A grep for ksm/secrets_manager in those directories returns nothing.

You need:

A kd-ksm-app-add (KD29 / KD31) that creates a KSM Application either at the vault root or inside a KeeperDrive folder context (canAdd).
A kd-ksm-app-share (KD30) that wires a KSM application share into a KeeperDrive folder.
Probably a service-layer module keepercommander/keeper_drive/ksm_api.py plus exposure through the package __init__.py _SUBMODULE_MAP.
The existing legacy commands/ksm.py is the natural source to refactor against — it already speaks the KSM endpoints; you just need the v3 wiring + folder-context parameter.

2. Team sharing (KD11, KD24) — only user-as-actor is supported
The MRD wording for both folder and record sharing is "users or teams", and the proto already has AT_TEAM. But the only place AT_TEAM is referenced in keeper_drive/ is removal_api.py (and only to count affected_teams_count).

In folder_api.py the entire share path hard-codes accessType = folder_pb2.AT_USER (lines 327, 385, 412, 441, 461, 478) and kd-share-folder/kd-share-record parsers accept only --email. There's no --team/--team-uid switch and no team-key-encryption path.

Add:

--team / -T to kd-share-folder and kd-share-record parsers.
A resolve_team_uid_bytes helper paralleling resolve_user_uid_bytes in common.py.
A team branch in grant_folder_access_v3 / manage_folder_access_batch_v3 / record-share that sets accessType = AT_TEAM and encrypts the folder/record key with the team key.
3. Maximum nesting depth = 5 (KD2) — not enforced
Nothing in kd-mkdir, create_folder_v3, _prepare_folder_for_creation, or helpers.py checks the depth of the parent chain. A grep for MAX_DEPTH / depth returns no matches.

Add a check in KeeperDriveMkdirCommand.execute (or in create_folder_v3) that walks parent_uid → parent_uid through params.keeper_drive_folders and refuses with a friendly error when depth >= 5.

4. Cross-model nesting prevention (KD28) — only mv is guarded
commands/folder.py FolderMoveCommand blocks moves between SharedFolder and KeeperDrive. But FolderMakeCommand (legacy mkdir) at line 482+ never inspects whether base_folder is a KeeperDriveFolderType. So mkdir -sf "X" while cd'd into a KD folder would try to create a Legacy SharedFolder inside KeeperDrive (server may reject, but client should fail fast).

Add the symmetric guard to FolderMakeCommand.execute:

if base_folder.type == BaseFolderNode.KeeperDriveFolderType:
    raise CommandError('mkdir',
        'Legacy folders cannot be created inside a KeeperDrive folder. '
        'Use kd-mkdir instead.')
The same guard belongs in legacy RecordAddCommand (legacy add/record-add) so that when the current folder is KD, the user is told to use kd-record-add (KD27 contextual create rule).

5. kd-mkdir cannot target a parent (KD2 ergonomics)
KeeperDriveMkdirCommand discovers the parent only via params.current_folder. There is no --folder / --parent argument the way kd-record-add has --folder, so building hierarchies non-interactively requires cd between every call.

Add --folder/--parent FOLDER to keeper_drive_mkdir_parser and pass it through create_folder_v3(parent_uid=…).

6. Folder-permission–driven record actions (KD13, KD14) — client checks only the record-level grant
helpers._check_record_permission looks up keeper_drive_record_accesses only. The MRD says folder-level canViewRecords / canEditRecords should also authorize record reads/edits inside that folder.

kd-record-update and kd-get therefore reject users who hold the right via the parent folder rather than the record itself. The server is probably permissive, but pre-flight checks are wrong.

Update _check_record_permission to also walk find_kd_folders_for_record(params, record_uid) and accept when any containing folder grants can_view_records / can_edit_records.

7. Permission matrix vs MRD scope
keeper_drive/permissions.py includes NAVIGATOR=0 and REQUESTOR=1, and ROLE_NAME_MAP exposes 'contributor' / 'requestor' (both → 1). The MRD explicitly limits Phase 1 roles to VIEWER (2), SHARED_MANAGER (3), CONTENT_MANAGER (4), CONTENT_SHARE_MANAGER (5), MANAGER (6).

This is fine if backend will silently accept those, but kd-share-folder/kd-share-record parsers do already restrict --role choices to MRD-allowed names, so the extras are dead options reachable only programmatically. Decide whether to:

Drop NAVIGATOR/REQUESTOR/contributor mapping for V1 to avoid drift, or
Keep them but document them as internal.
Also: the helpers.role_label and infer_role functions still return 'contributor'/'requestor'/'navigator' on display — they will leak into kd-list -p and kd-get -v. Trim them for V1 to match the MRD's display surface.

8. KD12 — Change folder ownership
MRD marks this as N/A for MVP, and there is no kd-chown-folder in the codebase. Confirmed correct — leave a stub TODO if desired.

9. Out-of-scope features that are actually present
The MRD explicitly puts these out of scope but the code partially supports them:

Out-of-scope feature	Where it leaks in	Recommendation
TLA (time-limited access)
--expire-at / --expire-in on kd-share-folder and kd-share-record; tlaProperties.expiration set in grant_folder_access_v3
Either keep (server will reject if disabled) or hide the switches behind a feature flag check.
TrashCan / restore
Staged trashcan_sync_pb2 files appear in the original git status snapshot but are untracked-uncommitted; keeper_drive_trashed_folders cache is referenced in sync.py clear_caches
Don't ship the proto pieces in this PR; remove the cache code or feature-flag it.
Move To / Drag-and-Drop
kd-ln and kd-shortcut are link operations, fine. But mv partially still talks about "Drive folders" — that path is correctly raising CommandError, leave as is.
10. current_folder for KD context (KD27 contextual create)
commands/folder.py FolderCdCommand.execute (line 363) already accepts a KD folder UID as current_folder. Good. But kd-record-add only consumes --folder and ignores params.current_folder. To match the MRD wording ("If a KeeperDrive folder is selected and Add/Create is clicked, the dialog shall create a record … within that KeeperDrive folder context"), have KeeperDriveAddRecordCommand.execute default folder_uid to params.current_folder when it is a KD folder UID.

11. KEEPER_DRIVE flag handling on every kd-* command (KD32)
The flag is checked in command-listing/help (cli.py line 387) and in sync ingestion (sync_down.py line 79), but the individual kd-* execute() methods don't re-check the flag. So a user with the flag disallowed who somehow types kd-mkdir directly will hit it. Recommend adding a guard in a base helper used by every kd-* command (e.g., in helpers.command_error_handler or a separate require_keeper_drive(params, cmd_name) decorator).

12. Minor
keeper_drive_share_folder_parser has no --team (see #2) and no JSON output mode, while every other kd-* listing/inspection has --format json. Add for parity if needed.
_check_folder_permission (in helpers.py) silently returns on the first matching username; if no matching access entry is found, it never raises — letting actions pass when they shouldn't. Add a final raise CommandError(cmd_name, error_message) after the loop.
kd-share-record parser sets --email required=True even for folder-bulk mode (-R). Reconsider.
Concrete to-do list, priority-ordered
Add KSM commands & service module (KD29/30/31). New work, needed for MRD section 8.
Add team-as-actor support to kd-share-folder / kd-share-record and the underlying *_v3 calls (KD11/KD24).
Enforce max depth 5 in kd-mkdir (KD2).
Block legacy mkdir/add inside KD folders to satisfy KD28; mirror the mv guard in FolderMakeCommand and the legacy add command.
Add --folder/--parent to kd-mkdir and have kd-record-add honor params.current_folder (KD27 ergonomics).
Fix folder-derived record permission checks in _check_record_permission (KD13/14).
Add a global feature-flag guard at the top of every kd-* execute() (KD32).
Tighten _check_folder_permission so a missing access record raises instead of falling through.
Trim NAVIGATOR/REQUESTOR/contributor surface from display helpers and the role map (MRD V1 role list).
Either ship or revert the staged trashcan_sync_pb2* files — they're listed in the git snapshot but absent on disk; trash sync is out of scope per MRD.
Want me to start with any of these (KSM commands and team support are the two largest gaps)?