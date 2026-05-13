"""Commander plugin verbs for `tenant-migrate declare ...`.

Two leaf verbs in Phase 1.4:
  declare overlay   — apply YAML edits over a captured inventory.json
  declare validate  — schema-check a manifest YAML, return exit-code only
"""
import argparse
import json
import logging
import os

import yaml
from keepercommander.commands.base import Command, GroupCommand
from pydantic import ValidationError

from .overlay import apply_overlay
from .ref_graph import find_dangling_refs
from .schema.overlay_v1 import OverlayManifest
from .secret_guard import find_secret_fields


# ─── Parsers ─────────────────────────────────────────────────────────────────

declare_overlay_parser = argparse.ArgumentParser(
    prog="tenant-migrate-declare-overlay",
    description="Apply a YAML overlay edits manifest to a captured "
                "inventory.json and write the resulting inventory.",
)
declare_overlay_parser.add_argument(
    "--base", required=True,
    help="Captured inventory.json (the output of `tenant-migrate plan`).",
)
declare_overlay_parser.add_argument(
    "--edits", required=True,
    help="Overlay manifest YAML.",
)
declare_overlay_parser.add_argument(
    "--output", required=True,
    help="Output inventory.json path. Written 0o600.",
)
declare_overlay_parser.add_argument(
    "--dry-run", action="store_true",
    help="Validate manifest + apply overlay in memory without writing --output.",
)


declare_validate_parser = argparse.ArgumentParser(
    prog="tenant-migrate-declare-validate",
    description="Schema-check a YAML overlay manifest. Exit 0 on PASS, "
                "2 on schema/validation error.",
)
declare_validate_parser.add_argument(
    "manifest", help="Overlay manifest YAML.",
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _load_manifest(yaml_path):
    """Load YAML, run secret_guard, then validate against OverlayManifest."""
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(
            "manifest must be a YAML mapping, got {}".format(type(data).__name__)
        )
    leaks = find_secret_fields(data)
    if leaks:
        raise ValueError(
            "manifest carries forbidden secret-flavoured field name(s): "
            + ", ".join(leaks)
        )
    return OverlayManifest.model_validate(data)


def _log_validation_errors(prefix, ve):
    for err in ve.errors():
        loc = ".".join(str(x) for x in err["loc"])
        logging.error("%s  %s: %s", prefix, loc, err["msg"])


# ─── Leaf commands ───────────────────────────────────────────────────────────


class DeclareOverlayCommand(Command):
    def get_parser(self):
        return declare_overlay_parser

    def execute(self, params, **kwargs):
        edits_path = kwargs["edits"]
        base_path = kwargs["base"]
        output_path = kwargs["output"]
        dry_run = kwargs.get("dry_run", False)

        try:
            manifest = _load_manifest(edits_path)
        except ValidationError as ve:
            logging.error("declare-overlay: schema error in %s", edits_path)
            _log_validation_errors("declare-overlay:", ve)
            return {"ok": False, "exit": 2, "reason": "schema"}
        except (yaml.YAMLError, ValueError) as e:
            logging.error("declare-overlay: parse error in %s: %s", edits_path, e)
            return {"ok": False, "exit": 2, "reason": "parse"}

        with open(base_path, "r") as f:
            base = json.load(f)

        ref_errors = find_dangling_refs(manifest, base)
        if ref_errors:
            for err in ref_errors:
                logging.error("declare-overlay: dangling ref — %s", err)
            return {"ok": False, "exit": 3, "reason": "dangling_ref"}

        out = apply_overlay(base, manifest)

        if dry_run:
            logging.info(
                "declare-overlay: dry-run OK, would write %s "
                "(roles=%d sfs=%d records=%d)",
                output_path,
                len((out.get("entities") or {}).get("roles") or []),
                len((out.get("entities") or {}).get("shared_folders") or []),
                len((out.get("entities") or {}).get("records") or []),
            )
            return {"ok": True, "exit": 0, "dry_run": True}

        # 0o600 — overlay output may carry plaintext via include-fields
        # semantics, matching the existing records-export default mode.
        # O_NOFOLLOW — refuse to follow a symlink at the output path,
        # closing the symlink-overwrite vector. ELOOP / EEXIST surface
        # as OSError; treat as a safeguard block (exit 5).
        try:
            fd = os.open(
                output_path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
        except OSError as exc:
            logging.error(
                "declare-overlay: cannot open %s safely: %s "
                "(refusing to follow symlinks at output path)",
                output_path, exc,
            )
            return {"ok": False, "exit": 5, "reason": "output_unsafe"}
        with os.fdopen(fd, "w") as f:
            json.dump(out, f, indent=2)
        logging.info("declare-overlay: wrote %s (mode 0600)", output_path)
        return {"ok": True, "exit": 0, "output": output_path}


class DeclareValidateCommand(Command):
    def get_parser(self):
        return declare_validate_parser

    def execute(self, params, **kwargs):
        path = kwargs["manifest"]
        try:
            manifest = _load_manifest(path)
        except ValidationError as ve:
            logging.error("declare-validate: FAIL %s", path)
            _log_validation_errors("declare-validate:", ve)
            return {"ok": False, "exit": 2, "reason": "schema"}
        except (yaml.YAMLError, ValueError) as e:
            logging.error("declare-validate: FAIL parse %s: %s", path, e)
            return {"ok": False, "exit": 2, "reason": "parse"}

        logging.info(
            "declare-validate: PASS %s (schema=%s, name=%s)",
            path, manifest.schema_, manifest.name,
        )
        return {
            "ok": True, "exit": 0,
            "schema": manifest.schema_, "name": manifest.name,
        }


# ─── Group ───────────────────────────────────────────────────────────────────


class DeclareGroupCommand(GroupCommand):
    def __init__(self):
        super().__init__()
        self.register_command(
            "overlay", DeclareOverlayCommand(),
            "Apply YAML overlay edits to a captured inventory.",
        )
        self.register_command(
            "validate", DeclareValidateCommand(),
            "Schema-check a YAML overlay manifest.",
        )
        self.default_verb = ""
