# Thycotic NSF ACL — Quick Start Guide

**For new team members:** Start here → then read the full [README.md](./README.md)

---

## 30-Second Overview

This module imports **Delinea Secret Server** into Keeper's Nested Share Folders with **automatic ACL mapping**.

- 🎯 Delinea folder ACL → NSF folder permissions
- 📋 Secret-level ACL → NSF record shares (when different)
- 👥 Delinea groups → Keeper team grants
- 🔄 Email domain rewriting (optional)

---

## One-Command Import

```bash
import --format=thycotic --nsf user@https://delinea.company.com/ --add-users --add-teams
```

That's it. You get:
- ✅ NSF folder structure
- ✅ All records in folders
- ✅ Folder-level permissions (NSF roles)
- ✅ Secret-level overrides (as direct record shares)
- ✅ Teams expanded to member permissions

---

## Key Files

| File | Purpose | Link |
|------|---------|------|
| `README.md` | **Complete guide** (READ THIS FIRST) | [Full docs](./README.md) |
| `thycotic.py` | Main importer (800+ lines) | [Code](./thycotic.py#L247) |
| `nsf_acl.py` | Role mapping (NEW) | [4 functions](./nsf_acl.py#L14) |
| `test_thycotic_nsf_acl.py` | 34 unit tests (NEW) | [Tests](../../unit-tests/test_thycotic_nsf_acl.py) |

---

## Role Mapping at a Glance

What Delinea folder + secret ACL becomes in NSF:

```
Owner + Owner          → full-manager     (full control)
Owner + Edit           → full-manager     (full control)
Edit + Owner           → content-manager  (manage content)
Owner + View           → viewer           (⚠️ lossy — log warning)
View + Edit            → content-manager  (secret wins)
View + View            → viewer           (read-only)
Any + List             → requestor        (workflow/request)
(Group)                → (per-member)     (expanded to users)
```

---

## Step-by-Step Example

### Step 1: Authenticate to Keeper

```bash
login
```

### Step 2: Import with Full ACL

```bash
import --format=thycotic --nsf jane@https://delinea.company.com/ --add-users --add-teams
# Enter Delinea password when prompted
```

### Step 3: Check Logs

```
✓ Loading X Records ...
✓ Granted N Nested Share Folder permission(s)
✓ Granted M NSF record permission(s)
```

### Step 4: Verify in Keeper

- Open Nested Share Folders
- Check folder structure matches Delinea
- Check permissions (Manage → Members)

---

## Advanced Usage

### Dry Run (Preview First)

```bash
import --format=thycotic --nsf jane@https://host/ --add-users --add-teams --dry-run
# See what would happen without writing to Keeper
```

### Email Domain Rewrite

```bash
import --format=thycotic --nsf jane@https://host/ --add-users --add-teams \
  --old-domain=delinea.com --new-domain=keeper.com
# jane.doe@delinea.com → jane.doe@keeper.com
```

### Update Permissions Only

```bash
import --format=thycotic --nsf jane@https://host/ --add-users --add-teams --users
# Re-sync permissions without re-importing records
```

### Specific Secrets

```bash
import --format=thycotic --nsf jane@https://host/ --add-users --add-teams \
  --secret-ids 123,456,789
# Import only these secret IDs
```

---

## Troubleshooting Checklist

| Issue | Check | Fix |
|-------|-------|-----|
| No permissions granted | Logs say "0 permissions" | Run `--dry-run` to see mapping |
| "Group not found" | Groups referenced but not in Keeper | Run `team-add <group-name>` first |
| "Lossy mapping" warning | Expected (lossy mappings logged) | Secret role takes precedence — check record |
| Import hangs | Large number of secrets/permissions | Run with smaller batch (--secret-ids) |
| Email wrong domain | Domain didn't rewrite | Confirm `--old-domain` matches actual |

---

## Architecture in 90 Seconds

```
1. CONNECT to Delinea
   ↓
2. FETCH folders with permissions
   ↓
3. MAP Delinea roles → NSF roles
   ↓
4. YIELD NSF SharedFolder objects
   ↓
5. CREATE NSF folders + set break_inheritance
   ↓
6. GRANT folder permissions (nsf roles)
   ↓
7. FETCH secrets + FETCH secret ACL
   ↓
8. COMPUTE secret ACL deltas vs folder role
   ↓
9. ATTACH NsfRecordShare overrides to records
   ↓
10. GRANT record shares (deltas only)
   ↓
✓ Done
```

---

## Code Locations

### Where role mapping happens

**File:** `nsf_acl.py` (NEW)

```python
# Main function
def thycotic_roles_to_nsf_role(folder_role, secret_role):
    # Returns 'viewer', 'content-manager', 'full-manager', 'requestor', or None
```

### Where folders are yielded

**File:** `thycotic.py` line 785

```python
def _yield_nsf_shared_folders(self, auth, folders, users_by_id, groups_by_id, **kwargs):
    # Builds NSF SharedFolder objects with Permission objects
    # Each permission has: name (email), uid (team ID), role (NSF role)
```

### Where secret ACL is computed

**File:** `thycotic.py` line 827

```python
def _attach_secret_nsf_permissions(self, record, secret_id, folder_nsf_role_by_email, ...):
    # Fetches secret permissions
    # Computes delta vs folder role
    # Attaches NsfRecordShare overrides
```

### Where permissions are granted

**File:** `nsf_import.py` line 483 (updated)

```python
def apply_nsf_folder_permissions(params, folders, ...):
    # Grants NSF folder permissions
    # Calls update_folder_v3(..., inherit_permissions=False)
    # Calls grant_folder_access_v3(..., role=...)

def apply_nsf_record_permissions(params, records, ...):
    # Grants NSF record permissions (NEW)
    # Calls batch_create_record_shares_v3(...)
```

---

## Test Everything Works

```bash
cd /path/to/Commander

# Run NSF ACL tests (34 tests)
python3 -m pytest unit-tests/test_thycotic_nsf_acl.py -v

# Run NSF import tests (28 tests, regression)
python3 -m pytest unit-tests/test_nsf_import.py -v

# Run both
python3 -m pytest unit-tests/test_thycotic_nsf_acl.py unit-tests/test_nsf_import.py -q
# Expected: 62 passed ✅
```

---

## Next Steps

1. ✅ **Read this** (QUICK_START.md) — 5 min
2. 📖 **Read README.md** — 20 min
3. 🔬 **Review nsf_acl.py** — 10 min (4 functions, well-commented)
4. 🧪 **Run tests** — verify everything works
5. 🚀 **Try a dry run** — `import ... --dry-run`
6. 📝 **Check logs** — see actual behavior

---

## Key Contacts

- **Role mapping logic:** See `nsf_acl.py` + tests
- **Delinea API details:** `thycotic.py` (ThycoticAuth, thycotic_search)
- **NSF permission apply:** `nsf_import.py` (apply_nsf_folder_permissions, apply_nsf_record_permissions)
- **Tests:** `unit-tests/test_thycotic_nsf_acl.py` (34 examples)

---

## Important Links

- 📖 **Full README:** [keepercommander/importer/thycotic/README.md](./README.md)
- 📊 **Design doc:** [THYCOTIC_NSF_ACL_AGENT_HANDOFF.md](../../images/THYCOTIC_NSF_ACL_AGENT_HANDOFF.md)
- ✅ **Implementation summary:** [THYCOTIC_NSF_ACL_IMPLEMENTATION.md](../../THYCOTIC_NSF_ACL_IMPLEMENTATION.md)
- 🧪 **All tests:** [unit-tests/test_thycotic_nsf_acl.py](../../unit-tests/test_thycotic_nsf_acl.py) (34 tests)
- 📚 **Related APIs:** [nsf_import.py](../nsf_import.py) | [nested_share_folder/](../../nested_share_folder/)

---

## Command Reference

```bash
# Full ACL import
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams

# With domain rewrite
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams \
  --old-domain=FROM --new-domain=TO

# Permissions only
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams --users

# Dry run
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams --dry-run

# Specific secrets
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams --secret-ids ID1,ID2

# Combine options
import --format=thycotic --nsf USER@https://HOST/ --add-users --add-teams \
  --old-domain=delinea.com --new-domain=keeper.com --dry-run
```

---

**Version:** 1.0  
**Status:** Production Ready ✅  
**Last Updated:** November 4, 2026

👉 **Ready to dive deeper?** Go to [README.md](./README.md)
