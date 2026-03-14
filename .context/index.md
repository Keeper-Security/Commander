# Commander (Keeper Commander) - Master Index
**Version**: latest | **Updated**: 2026-02-07 | **Role**: Authoritative guide

---
## Rules
1. This file is the single source of truth
2. Before writing new docs, check this index first
3. No duplicate content across files
4. Topic files are append-only
5. Plans 100% done get deleted
6. New plans must register here
7. New ideas go to .context/ideas/
8. Always check for duplication first
9. When task completed: document, mark done, update CHANGELOG

## A. Source Code
- `keeper.py` - Main entry point
- `keepercommander/` - Core package
  - `cli.py` - CLI interface
  - `api.py` - API module
  - `crypto.py` - Cryptography module
  - `params.py` - Parameters and configuration
  - `loginv3.py` - Login v3 implementation
  - `enterprise.py` - Enterprise management
  - `generator.py` - Password generator
  - `display.py` - Display/output formatting
  - `breachwatch.py` - Breach monitoring
  - `record_facades.py` - Record abstraction layer
  - `attachment.py` - Attachment handling
  - `auth/` - Authentication module
  - `commands/` - CLI commands (including PAM, PAM import, license consumption)
  - `plugins/` - Rotation plugins
  - `importer/` - Import modules (KeePass, LastPass)
  - `discovery_common/` - Discovery common utilities
  - `keeper_dag/` - DAG module
  - `proto/` - Protobuf definitions
  - `service/` - Service module
  - `yubikey/` - YubiKey integration
  - `config_storage/` - Configuration storage
  - `humps/` - Case conversion utilities
- `dotnet-keeper-sdk/` - .NET SDK variant
- `examples/` - Usage examples
- `tests/` - Test suite
- `unit-tests/` - Unit test suite
- `sample_data/` - Sample data for testing
- `keeper_api_reverse_engineer.py` - API reverse engineering tool
- `keeper_commander_security_scanner.py` - Security scanner

## B. Topic References
(none yet - create topic files as needed)

## C. Core Documentation
- `README.md` - Keeper Commander overview: CLI and SDK for Keeper Password Manager, links to docs.keeper.io
- `CLAUDE.md` - Automation system config (Python type, port 5001)
- `AUTOMATION_README.md` - Universal automation system documentation
- `record_types.md` - Record V3 format: types, fields, categories, CLI add/edit/download commands, dot notation, JSON format

### Module-Level Documentation
- `dotnet-keeper-sdk/README.md` - .NET SDK documentation
- `keepercommander/commands/LICENSE_CONSUMPTION_REPORT.md` - License consumption reporting for enterprise admins
- `keepercommander/commands/pam/README.md` - PAM commands documentation
- `keepercommander/commands/pam_import/README.md` - PAM import commands
- `keepercommander/discovery_common/README.md` - Discovery common module docs
- `keepercommander/importer/keepass/README.md` - KeePass importer documentation
- `keepercommander/importer/lastpass/README.md` - LastPass importer documentation
- `keepercommander/keeper_dag/README.md` - DAG module documentation
- `keepercommander/plugins/password_rules.md` - Password rules for rotation plugins
- `keepercommander/proto/README.md` - Protobuf definitions documentation
- `keepercommander/service/README.md` - Service module documentation
- `keepercommander/yubikey/README.md` - YubiKey integration documentation

## D. Analysis Reports
- `api_analysis.json` - API analysis results (735K)
- `basic_scan.json` - Basic scan results (701K)
- `report.txt` - Security/analysis report (153K)
- `keeper_scan_results.json` - Scan results
- `security_research.log` - Security research log

## E. Active Plans
(none)

## F. File Registry
| File | Section |
|------|---------|
| `README.md` | C - Core Documentation |
| `CLAUDE.md` | C - Core Documentation |
| `AUTOMATION_README.md` | C - Core Documentation |
| `record_types.md` | C - Core Documentation |
| `dotnet-keeper-sdk/README.md` | C - Module Documentation |
| `keepercommander/commands/LICENSE_CONSUMPTION_REPORT.md` | C - Module Documentation |
| `keepercommander/commands/pam/README.md` | C - Module Documentation |
| `keepercommander/commands/pam_import/README.md` | C - Module Documentation |
| `keepercommander/discovery_common/README.md` | C - Module Documentation |
| `keepercommander/importer/keepass/README.md` | C - Module Documentation |
| `keepercommander/importer/lastpass/README.md` | C - Module Documentation |
| `keepercommander/keeper_dag/README.md` | C - Module Documentation |
| `keepercommander/plugins/password_rules.md` | C - Module Documentation |
| `keepercommander/proto/README.md` | C - Module Documentation |
| `keepercommander/service/README.md` | C - Module Documentation |
| `keepercommander/yubikey/README.md` | C - Module Documentation |

## G. Quick Reference
```bash
# Quick start
./quick-start.sh

# Automated start
./start-automated.sh

# Run keeper
python keeper.py

# Run tests
python -m pytest tests/ -v
python -m pytest unit-tests/ -v

# Automation status
python3 .automation/auto_track_daemon.py status

# Install dependencies
pip install -r requirements.txt

# Install dev dependencies
pip install -r requirements-dev.txt

# Documentation
# https://docs.keeper.io/secrets-manager/commander-cli/overview
```

## H. Architecture Quick Facts
- **Purpose**: CLI and SDK for Keeper Password Manager
- **Language**: Python (with .NET SDK variant in `dotnet-keeper-sdk/`)
- **Key Capabilities**: Vault access, admin functions, remote sessions, password rotation, import/export, breach monitoring
- **Modules**: Core CLI, plugins (rotation), importers (KeePass/LastPass), PAM commands, discovery, protobuf, service mode, YubiKey
- **Auth**: Login v3, YubiKey support
- **Records**: V3 format with types, fields, categories
- **Enterprise**: License consumption reporting, role management
- **Automation**: Universal automation system v2.1.0 on port 5001

## I. Open Priorities
(none documented locally - upstream Keeper Security project)
