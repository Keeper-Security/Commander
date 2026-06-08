# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## ⚠️ Do not edit vendored directories

**Never edit files under `keepercommander/discovery_common/` or `keepercommander/keeper_dag/`.** These are copied in from external "golden" repositories (`keeper-dag`, and the shared Gateway/KDNRM `discovery-common` code). Any edits made here will be **overwritten** the next time the directories are synced from upstream. If a change is needed in this code, make it in the upstream repo — not here. The same applies to generated protobuf files in `keepercommander/proto/` (`*_pb2.py` / `*.pyi`): regenerate from the `.proto` source, never hand-edit.

## What this is

Keeper Commander is a command-line and terminal-UI client for Keeper Password Manager and KeeperPAM. It is a Python package (`keepercommander`) that ships as the `keeper` console script. Beyond vault access it does enterprise administration, PAM (privileged access: rotation, tunnels, discovery), data import/export from other password managers, and can run as a REST service.

## Setup & running

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
pip install -e '.[email]'   # optional email-sending extras
```

Run the CLI:
- `keeper help` — list all commands
- `keeper shell` — interactive command shell
- `keeper supershell` — full terminal vault UI (Textual)
- `keeper <command> [args]` — run a single command and exit
- `python keeper.py ...` — equivalent entry point (calls `keepercommander.__main__:main`)

Config defaults to `config.json` (cwd or platform data dir); override with `KEEPER_CONFIG_FILE`. Set `KEEPER_COMMANDER_DEBUG` for debug logging.

## Testing

CI runs only `unit-tests/` on Python 3.8 and 3.14 (`.github/workflows/test-with-pytest.yml`). Supported range is 3.8–3.14.

```bash
pip install '.[test]'
pytest unit-tests/                       # what CI runs
pytest unit-tests/test_sync_down.py      # single file
pytest unit-tests/test_sync_down.py::TestClass::test_name   # single test
pytest -m keeper_imports                 # smoke test: every module imports cleanly
```

Test marker semantics (see `pytest.ini`):
- `unit` — mocked, no live server (credential-provision)
- `e2e` — end-to-end, run manually (`pytest -m e2e`)
- `integration` — hits internal `dev.keepersecurity.com` accounts via a `config.json` (`tests/data_config.py`); not for general use
- `cross_enterprise` — excluded by default in `addopts`

Note: `pytest.ini` excludes `venv/`, ignores `unit-tests/test_command_utils.py` (circular import) and `unit-tests/test_login.py` (connection errors), and disables warnings. The `tests/` directory holds heavier integration/e2e suites that are *not* run by CI.

Lint config is `pylintrc`; `desired-pylint-warnings` documents which warning categories the team cares about.

## Architecture

**Entry & dispatch.** `__main__.py` loads config into a `KeeperParams`, then `cli.py` drives the REPL/one-shot execution. `cli.do_command()` is the central dispatcher: it parses a command line, resolves aliases, picks the right registry (`commands`, `enterprise_commands`, or `msp_commands`), and calls the command. Control characters in command input are rejected at this boundary.

**Commands.** Every command subclasses `Command` (or `ArgparseCommand`) in `keepercommander/commands/base.py`. The contract:
- `get_parser()` returns an `argparse.ArgumentParser`; `execute_args()` parses the raw string and dispatches to `execute(params, **kwargs)`.
- `is_authorised()` gates whether login is required.
- `GroupCommand` / `GroupCommandNew` compose sub-verbs (e.g. `pam <verb>`); they own their own sub-registries and aliases.
- Mixins `RecordMixin` / `FolderMixin` provide shared record/folder resolution helpers.

Commands are registered through `register_commands(commands, aliases, command_info)` in `commands/base.py`, which imports each command module and calls its `register_commands` / `register_command_info`. To add a command, create the module, implement the `Command`, and wire it into the appropriate `register_commands` function. The `commands/` subdirectories group large feature areas (`pam`, `pam_cloud`, `pam_import`, `discover`, `enterprise*`, `domain_management`, `remote_management`, `keeper_drive`, `pedm`, `scim`).

**Session & state.** `KeeperParams` (`params.py`) is the single mutable object threaded through everything: session tokens, the in-memory vault cache (records, folders, shared folders, teams), enterprise data, and `RestApiContext` (server, transmission/encryption keys, QRC/EC key negotiation). Commands read and mutate this object rather than passing data around.

**Network & data sync.** `api.py` is the transport layer: `login()`, `communicate()` / `communicate_rest()` (protobuf request/response with throttle retry), and `query_enterprise()`. `rest_api.py` / `loginv3.py` handle the low-level REST and login-v3 flows; `auth/` holds login-step and console-UI logic. `sync_down.py` pulls and decrypts the vault into `params`, then `prepare_folder_tree()` builds the folder hierarchy. Wire formats live in `proto/` (generated `*_pb2.py` — do not hand-edit). Crypto primitives are in `crypto.py`.

**Vault data model.** `vault.py` defines the record types: `KeeperRecord` (abstract) with `PasswordRecord` (v2), `TypedRecord` (v3, field-based with `TypedField`), `FileRecord`, `ApplicationRecord`. `record_facades.py` / `vault_extensions.py` provide typed views; `subfolder.py` models the folder tree.

**Local storage.** `storage/` (SQLite + in-memory DAOs) and `config_storage/` persist cache and config; secure config storage can be encrypted (`loader.SecureStorageException` path in `__main__.py`).

**PAM / discovery / graph.** `keeper_dag/` and `discovery_common/` implement the directed-acyclic graph (DAG) backing PAM discovery, record-linking, and rotation. `commands/pam/`, `commands/pam_cloud/`, and `commands/discover/` build on top of them. These two directories are **vendored copies** of external golden repos — see the warning at the top of this file before touching them.

**Importers.** `importer/` has per-product subpackages (1password, bitwarden, lastpass, keepass, dashlane, proton, thycotic, cyberark, etc.) plus generic csv/json. `imp_exp.py` orchestrates import/export.

**Service mode.** `service/` is a Flask-based REST API server exposing Commander commands over HTTP with API-key auth, rate limiting, and optional response encryption. See `keepercommander/service/README.md`. Managed via `service-create` / `service-start` / etc. commands.

**Plugins.** `plugins/` are rotation plugins loaded dynamically and registered like other commands.

## Style

Follow [PEP 8](https://peps.python.org/pep-0008/), with the project-specific settings enforced by `pylintrc`:
- **Line length: 100** (not PEP 8's default 79).
- `snake_case` for functions, methods, arguments, variables, and attributes.
- `PascalCase` for classes.
- `UPPER_CASE` for module-level and class constants.
- 4-space indentation, no tabs.

Run `pylint keepercommander/<module>.py` to check; `desired-pylint-warnings` documents which warning categories the team treats as meaningful.

## Conventions

- Match the surrounding file's style; most modules carry the Keeper ASCII-art header.
- Never edit `keeper_dag/`, `discovery_common/`, or generated `proto/` files (see the warning at the top of this file).
- Version lives in `keepercommander/__init__.py` (`__version__`); `setup.cfg` reads it via `attr:`.