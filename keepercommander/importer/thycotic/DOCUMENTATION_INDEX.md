# Thycotic NSF ACL — Documentation Index

**Complete guide to understanding the Thycotic/Delinea NSF ACL implementation**

## 📚 Start Here

### For New Team Members

1. **[QUICK_START.md](./QUICK_START.md)** ← **START HERE** (5 min read)
   - 30-second overview
   - One-command import
   - Key files location
   - Troubleshooting checklist
   - Test commands

2. **[README.md](./README.md)** (20 min read)
   - Complete implementation guide
   - Architecture diagram
   - File structure
   - Usage examples (basic + advanced)
   - Role mapping reference table
   - Prerequisites & setup
   - Code deep dive
   - Testing guide
   - Troubleshooting solutions
   - Performance notes

### For Implementers

3. **[Implementation Summary](../../THYCOTIC_NSF_ACL_IMPLEMENTATION.md)** (10 min read)
   - What was built
   - All P0 + P1 gaps addressed
   - Files changed
   - Test results (62 passing)
   - Sign-off checklist

4. **[Design Handoff](../../images/THYCOTIC_NSF_ACL_AGENT_HANDOFF.md)** (Reference)
   - Original gap analysis
   - Architecture diagrams
   - Implementation checklist
   - Out of scope items

---

## 🎯 Quick Navigation

### By Role

| Role | Start With | Then Read |
|------|-----------|-----------|
| **New Developer** | QUICK_START.md | README.md → Code |
| **Code Reviewer** | IMPLEMENTATION.md | README.md (deep dive section) |
| **QA / Tester** | QUICK_START.md (tests) | README.md (testing) |
| **Operations** | QUICK_START.md (commands) | README.md (usage examples) |
| **Architect** | IMPLEMENTATION.md | Design Handoff |

### By Topic

| Topic | Document | Section |
|-------|----------|---------|
| **Role Mapping** | README.md | "Role Mapping Reference" |
| **Architecture** | README.md | "How to Use" (diagram) |
| **Testing** | README.md | "Testing" |
| **Troubleshooting** | README.md | "Troubleshooting" |
| **Code Structure** | README.md | "File Structure" + "Code Deep Dive" |
| **Prerequisites** | README.md | "Prerequisites & Setup" |
| **Command Examples** | QUICK_START.md | "Command Reference" |
| **Implementation Status** | IMPLEMENTATION.md | "Implemented Features" |

---

## 📖 Documentation Map

### User-Facing Documentation

```
QUICK_START.md
    ├── One-command import
    ├── Key files
    ├── Role mapping table
    ├── Step-by-step example
    ├── Advanced usage
    └── Troubleshooting checklist

README.md
    ├── Overview
    ├── Architecture diagram
    ├── File structure
    ├── How to use (basic + advanced)
    ├── Role mapping reference
    ├── Prerequisites
    ├── Code deep dive
    ├── Model types
    ├── Testing
    ├── Logging & monitoring
    ├── Troubleshooting (solutions)
    ├── Performance notes
    ├── Related docs (external links)
    └── Contributing
```

### Developer Documentation

```
IMPLEMENTATION.md
    ├── What was built (all gaps)
    ├── Files changed
    ├── Key behaviors
    ├── Test coverage
    ├── Not implemented (out of scope)
    ├── Known limitations
    ├── Sign-off checklist
    └── Next steps

Design Handoff (AGENT_HANDOFF.md)
    ├── Gap analysis (P0, P1, P2)
    ├── Baseline code
    ├── Architecture diagrams
    ├── Acceptance criteria
    └── Implementation order
```

---

## 🔗 Cross-References

### Role Mapping Logic

- **Quick:** QUICK_START.md → "Role Mapping at a Glance"
- **Complete:** README.md → "Role Mapping Reference"
- **Code:** nsf_acl.py → functions + unit tests
- **Tests:** unit-tests/test_thycotic_nsf_acl.py

### Folder ACL

- **How it works:** README.md → "Architecture"
- **Code:** thycotic.py → `_yield_nsf_shared_folders()` (line 785)
- **Apply:** nsf_import.py → `apply_nsf_folder_permissions()` (line 483)
- **Tests:** test_nsf_import.py → folder-related tests

### Secret ACL Overrides

- **Concept:** README.md → "How to Use" section
- **Code:** thycotic.py → `_attach_secret_nsf_permissions()` (line 827)
- **Apply:** nsf_import.py → `apply_nsf_record_permissions()` (line 580)
- **Tests:** test_thycotic_nsf_acl.py → TestSecretAclOverrides

### Team/Group Support

- **Overview:** README.md → "Architecture"
- **Implementation:** thycotic.py → `_yield_nsf_shared_folders()` with `groups_by_id`
- **API:** ThycoticMixin.get_group_lookup() (line 77)
- **Tests:** test_nsf_import.py → group-related tests

### Domain Rewriting

- **Usage:** QUICK_START.md → "Email Domain Rewrite"
- **Code:** thycotic.py → passes `--old-domain`/`--new-domain` kwargs
- **Function:** importer.py → `replace_email_domain()`
- **Applied to:** folder permissions + record shares

---

## 🧪 Testing Guide

### Run Tests

```bash
# All NSF ACL tests
python3 -m pytest unit-tests/test_thycotic_nsf_acl.py -v

# All NSF import tests (regression)
python3 -m pytest unit-tests/test_nsf_import.py -v

# Both
python3 -m pytest unit-tests/test_thycotic_nsf_acl.py unit-tests/test_nsf_import.py -q
# Expected: 62 passed ✅
```

### Test References

| Test Suite | Count | Location | Covers |
|-----------|-------|----------|--------|
| test_thycotic_nsf_acl.py | 34 | unit-tests/ | Role mapping, deltas, overrides |
| test_nsf_import.py | 28 | unit-tests/ | NSF import (regression, no breaks) |

---

## 🛠️ Implementation Files

### Core Implementation

| File | Lines | Purpose |
|------|-------|---------|
| `thycotic.py` | 900+ | Main importer + NSF methods |
| `nsf_acl.py` | 120 | Role mapping functions (NEW) |
| `nsf_import.py` | 650+ | Permission applying (updated) |
| `importer.py` | - | Model types (updated) |
| `imp_exp.py` | - | Pipeline wiring (updated) |
| `commands.py` | - | CLI help (updated) |

### Tests

| File | Tests | Purpose |
|------|-------|---------|
| test_thycotic_nsf_acl.py | 34 | NSF ACL logic |
| test_nsf_import.py | 28 | NSF import (no regression) |

### Documentation

| File | Type | Audience |
|------|------|----------|
| QUICK_START.md | Guide | New developers |
| README.md | Complete | All developers |
| IMPLEMENTATION.md | Summary | Reviewers, QA |
| AGENT_HANDOFF.md | Design | Architects |
| DOCUMENTATION_INDEX.md | Index | Finding info (this file) |

---

## 💡 How to Use This Index

### "I want to understand how role mapping works"

1. Read: QUICK_START.md → "Role Mapping at a Glance"
2. Check: README.md → "Role Mapping Reference" (table)
3. Study: nsf_acl.py (4 small functions)
4. Run tests: `pytest unit-tests/test_thycotic_nsf_acl.py -v`

### "I need to fix a bug in folder permissions"

1. Check: README.md → "Troubleshooting" → "Folder permissions not granted"
2. Trace: thycotic.py → `_yield_nsf_shared_folders()` → nsf_import.py → `apply_nsf_folder_permissions()`
3. Test: `pytest unit-tests/test_nsf_import.py::TestNsfImport::test_apply_permissions_classic_and_role -v`

### "I need to debug secret ACL overrides"

1. Read: README.md → "How to Use" section
2. Find: thycotic.py → `_attach_secret_nsf_permissions()`
3. Trace: nsf_import.py → `apply_nsf_record_permissions()`
4. Test: `pytest unit-tests/test_thycotic_nsf_acl.py::TestSecretAclOverrides -v`

### "I'm reviewing the implementation"

1. Start: IMPLEMENTATION.md → "Implemented Features"
2. Check: IMPLEMENTATION.md → "Sign-off Checklist"
3. Verify: Run all tests (62 should pass)
4. Review: Code in thycotic.py, nsf_acl.py, nsf_import.py

### "I'm onboarding a new team member"

1. Send: This index
2. Point to: QUICK_START.md
3. Then: README.md (deep dive)
4. Hands-on: `import --format=thycotic --nsf ... --dry-run`

---

## 🔑 Key Concepts (One-Liners)

| Concept | Explanation | Where |
|---------|-------------|-------|
| **NSF Role** | viewer, content-manager, full-manager, requestor | nsf_acl.py |
| **Folder ACL** | Delinea folder permissions → NSF folder grants | thycotic.py line 785 |
| **Secret ACL** | Delinea secret permissions → NSF record shares (deltas only) | thycotic.py line 827 |
| **Role Mapping** | Delinea roles (Owner, Edit, View, List) → NSF roles | nsf_acl.py |
| **Delta** | Where secret role ≠ folder role → direct record share | diff_secret_acl() |
| **Lossy** | Mapping that loses info (e.g., Owner folder + View secret → viewer) | is_lossy_folder_secret_pair() |
| **break_inheritance** | NSF folder flag to break inherited permissions | SharedFolder.break_inheritance |
| **Domain Rewrite** | --old-domain/--new-domain → user email translation | replace_email_domain() |

---

## ❓ FAQ (with links)

**Q: How do I import with full ACL?**  
A: See QUICK_START.md → "One-Command Import" or README.md → "How to Use"

**Q: What role does my user get?**  
A: Check README.md → "Role Mapping Reference" table

**Q: Why no permissions granted?**  
A: See README.md → "Troubleshooting" → "Folder permissions not granted"

**Q: How do I test changes?**  
A: See README.md → "Testing"

**Q: What files were changed?**  
A: See IMPLEMENTATION.md → "Files Changed"

**Q: Is domain rewriting supported?**  
A: Yes! See QUICK_START.md → "Email Domain Rewrite"

**Q: Can I import specific secrets?**  
A: Yes! See QUICK_START.md → "Specific Secrets"

**Q: How does secret ACL work?**  
A: See README.md → "How to Use" (architecture diagram)

---

## 📊 Documentation Stats

| Metric | Value |
|--------|-------|
| Total documents | 5 |
| Total lines (docs) | ~1500 |
| Code files changed | 6 |
| New code files | 1 (nsf_acl.py) |
| Tests written | 34 |
| All tests passing | 62 ✅ |
| Role mapping functions | 4 |
| Examples provided | 15+ |
| Troubleshooting topics | 10+ |

---

## 🚀 Next Steps

### For Developers

1. ✅ Read QUICK_START.md (5 min)
2. ✅ Read README.md (20 min)
3. ✅ Review nsf_acl.py (10 min)
4. ✅ Run tests (2 min)
5. ✅ Try `import ... --dry-run` (5 min)

### For Reviewers

1. ✅ Read IMPLEMENTATION.md (10 min)
2. ✅ Check sign-off checklist
3. ✅ Run tests (2 min)
4. ✅ Review code changes (30 min)

### For Operations

1. ✅ Read QUICK_START.md (5 min)
2. ✅ Read commands section of README.md (10 min)
3. ✅ Prepare Keeper teams if using `--add-teams`
4. ✅ Try dry run first

---

## 📞 Support

- **Code questions:** Check README.md "Code Deep Dive" section
- **Role mapping questions:** See "Role Mapping Reference" table
- **Test failures:** Run specific test suite, check README.md troubleshooting
- **General questions:** Check this index or relevant doc

---

## 📅 Version History

| Version | Date | Status | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-11-04 | 🟢 Production Ready | Initial release, all P0+P1 implemented |

---

## 📋 Checklist for Deployment

Before deploying to production:

- [ ] Read all documentation (QUICK_START + README + IMPLEMENTATION)
- [ ] Run all tests: `pytest ... -q` → 62 passed
- [ ] Test with `--dry-run` on test Delinea tenant
- [ ] Verify NSF folder creation
- [ ] Verify folder permissions granted
- [ ] Verify secret ACL deltas applied
- [ ] Test `--old-domain`/`--new-domain` rewriting
- [ ] Test `--add-teams` with existing Keeper teams
- [ ] Check logs for warnings (especially lossy mappings)
- [ ] Confirm no regression in classic Thycotic import

---

**Last Updated:** November 4, 2026  
**Status:** Production Ready ✅  

👉 **Start here:** [QUICK_START.md](./QUICK_START.md)
