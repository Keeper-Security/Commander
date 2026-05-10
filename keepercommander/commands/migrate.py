"""Keeper Tenant Migration commands (`migrate <verb>`).

Wraps the DSK shim and keeper_tenant_migrate plugin into a Commander command
surface. Requires `pip install keepercommander[migrate]` for the optional deps.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from keepercommander.commands.base import Command, GroupCommand
from keepercommander.error import CommandError
from keepercommander.params import KeeperParams

logger = logging.getLogger(__name__)


_MIGRATE_EXTRAS_HELP = (
    "The `migrate` commands require the optional dependencies. "
    "Install them with: pip install keepercommander[migrate]"
)
_COMMANDER_SENSITIVE_ARG_NAMES = (
    "--github-token",
    "--slack-webhook",
    "--servicenow-api-key",
    "--password",
    "--passphrase",
    "--api-key",
    "--secret",
    "--token",
)
_COMMANDER_SENSITIVE_ARG_SUFFIXES = (
    "-token",
    "-secret",
    "-webhook",
    "-api-key",
    "-key",
    "-password",
)
_COMMANDER_REDACTION = "***REDACTED***"


def _is_sensitive_arg_name(arg: str) -> bool:
    return arg in _COMMANDER_SENSITIVE_ARG_NAMES or any(
        arg.endswith(suffix) for suffix in _COMMANDER_SENSITIVE_ARG_SUFFIXES
    )


def _redact_args_for_safety(args: list[str]) -> list[str]:
    """Mirror DSK shim arg redaction before Commander emits JSON."""
    redacted: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        if "=" in arg and arg.startswith("--"):
            opt_name = arg.split("=", 1)[0]
            if _is_sensitive_arg_name(opt_name):
                redacted.append(f"{opt_name}={_COMMANDER_REDACTION}")
                i += 1
                continue
        elif _is_sensitive_arg_name(arg):
            redacted.append(arg)
            if i + 1 < len(args):
                redacted.append(_COMMANDER_REDACTION)
                i += 2
                continue
        redacted.append(arg)
        i += 1
    return redacted


def _require_dsk_shim():
    """Import dsk.shim lazily; raise a helpful error if extras not installed."""
    try:
        from dsk import shim as dsk_shim
    except ImportError as exc:
        raise RuntimeError(_MIGRATE_EXTRAS_HELP) from exc
    return dsk_shim


def _require_keeper_tenant_migrate():
    try:
        import keeper_tenant_migrate
    except ImportError as exc:
        raise RuntimeError(_MIGRATE_EXTRAS_HELP) from exc
    return keeper_tenant_migrate


def _add_format_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        dest="format",
        choices=("text", "json"),
        default=None,
        help="Output format. Defaults to json when stdout is piped.",
    )


def _add_dry_run_pair(parser: argparse.ArgumentParser, default: bool) -> None:
    dry_run = parser.add_mutually_exclusive_group()
    dry_run.add_argument("--dry-run", dest="dry_run", action="store_true", help="Preview changes")
    dry_run.add_argument("--no-dry-run", dest="dry_run", action="store_false", help="Write changes")
    parser.set_defaults(dry_run=default)


def _json_output(kwargs: Mapping[str, Any]) -> bool:
    output_format = kwargs.get("format")
    if output_format:
        return output_format == "json"
    return not sys.stdout.isatty()


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _to_jsonable(asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        jsonable = {}
        for k, v in value.items():
            key = str(k)
            if key == "args" and isinstance(v, Sequence) and not isinstance(
                v, (str, bytes, bytearray)
            ):
                jsonable[key] = _redact_args_for_safety([str(arg) for arg in v])
            else:
                jsonable[key] = _to_jsonable(v)
        return jsonable
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_to_jsonable(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _emit_result(result: Any, kwargs: Mapping[str, Any]) -> str:
    if _json_output(kwargs):
        return json.dumps(_to_jsonable(result), indent=2, sort_keys=True)

    stderr = getattr(result, "stderr", "")
    if stderr:
        logger.warning(stderr.rstrip())

    stdout = getattr(result, "stdout", "")
    if stdout:
        return stdout.rstrip()

    return json.dumps(_to_jsonable(result), indent=2, sort_keys=True)


def _shim_or_command_error(command: str):
    try:
        return _require_dsk_shim()
    except RuntimeError as exc:
        raise CommandError(command, str(exc)) from exc


class MigrateAdoptCommand(Command):
    """Adopt a keeperCMD run-dir into a DSK manifest."""

    parser = argparse.ArgumentParser(
        prog="migrate adopt",
        description="Adopt a keeperCMD run-dir into a DSK manifest or ownership markers.",
    )
    parser.add_argument("run_dir", help="Path to the keeperCMD run directory")
    parser.add_argument("--output", "-o", help="Output manifest path")
    _add_dry_run_pair(parser, default=True)
    parser.add_argument("--auto-approve", action="store_true", help="Approve marker writes without prompting")
    parser.add_argument("--skip-audit-verify", action="store_true", help="Skip audit-chain verification")
    parser.add_argument("--skip-sha256", action="store_true", help="Skip SHA256SUMS verification")
    parser.add_argument("--suspect-threshold", type=int, default=0, help="Suspect marker threshold")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--require-output-signature", action="store_true", help="Require signed keeperCMD output")
    parser.add_argument("--signature-pubkey", help="Path to signature public key")
    parser.add_argument("--signature-pubkey-keeper-record", help="Keeper record containing signature public key")
    parser.add_argument("--commander-config", help="Commander config path")
    _add_format_argument(parser)

    def get_parser(self):
        return self.parser

    def execute(self, params: KeeperParams, **kwargs: Any) -> str:
        dsk_shim = _shim_or_command_error("migrate adopt")
        result = dsk_shim.adopt(
            run_dir=kwargs["run_dir"],
            output=kwargs.get("output"),
            dry_run=kwargs.get("dry_run", True),
            auto_approve=kwargs.get("auto_approve", False),
            skip_audit_verify=kwargs.get("skip_audit_verify", False),
            skip_sha256=kwargs.get("skip_sha256", False),
            suspect_threshold=kwargs.get("suspect_threshold", 0),
            verbose=kwargs.get("verbose", False),
            require_output_signature=kwargs.get("require_output_signature", False),
            signature_pubkey=kwargs.get("signature_pubkey"),
            signature_pubkey_keeper_record=kwargs.get("signature_pubkey_keeper_record"),
            commander_config=kwargs.get("commander_config"),
        )
        return _emit_result(result, kwargs)


class MigratePlanCommand(Command):
    """Build a migration plan from a manifest."""

    parser = argparse.ArgumentParser(
        prog="migrate plan",
        description="Build a DSK migration plan from a target-state manifest.",
    )
    parser.add_argument("target_state", help="Path to the target-state manifest")
    parser.add_argument("--allow-delete", action="store_true", help="Include managed deletes in the plan")
    parser.add_argument("--provider", default="mock", help="DSK provider backend")
    parser.add_argument("--folder-uid", help="Keeper shared-folder scope")
    _add_format_argument(parser)

    def get_parser(self):
        return self.parser

    def execute(self, params: KeeperParams, **kwargs: Any) -> str:
        dsk_shim = _shim_or_command_error("migrate plan")
        result = dsk_shim.plan(
            target_state=kwargs["target_state"],
            allow_delete=kwargs.get("allow_delete", False),
            provider=kwargs.get("provider", "mock"),
            folder_uid=kwargs.get("folder_uid"),
        )
        return _emit_result(result, kwargs)


class MigrateApplyCommand(Command):
    """Apply a migration plan."""

    parser = argparse.ArgumentParser(
        prog="migrate apply",
        description="Apply a DSK migration manifest or prebuilt plan.",
    )
    parser.add_argument("plan", help="Manifest path, or a DSK Plan object when called as a library")
    parser.add_argument("--manifest-path", help="Manifest path for a prebuilt DSK Plan")
    _add_dry_run_pair(parser, default=True)
    parser.add_argument("--allow-delete", action="store_true", help="Allow managed deletes")
    parser.add_argument("--auto-approve", action="store_true", help="Apply without prompting")
    parser.add_argument("--provider", default="mock", help="DSK provider backend")
    parser.add_argument("--folder-uid", help="Keeper shared-folder scope")
    _add_format_argument(parser)

    def get_parser(self):
        return self.parser

    def execute(self, params: KeeperParams, **kwargs: Any) -> str:
        dsk_shim = _shim_or_command_error("migrate apply")
        result = dsk_shim.apply(
            plan=kwargs["plan"],
            manifest_path=kwargs.get("manifest_path"),
            dry_run=kwargs.get("dry_run", True),
            allow_delete=kwargs.get("allow_delete", False),
            auto_approve=kwargs.get("auto_approve", False),
            provider=kwargs.get("provider", "mock"),
            folder_uid=kwargs.get("folder_uid"),
        )
        return _emit_result(result, kwargs)


class MigrateDiffCommand(Command):
    """Diff a manifest against live state."""

    parser = argparse.ArgumentParser(
        prog="migrate diff",
        description="Render a field-level DSK diff for a target-state manifest.",
    )
    parser.add_argument("manifest_path", help="Path to the target-state manifest")
    parser.add_argument("--allow-delete", action="store_true", help="Include managed deletes")
    parser.add_argument("--provider", default="mock", help="DSK provider backend")
    parser.add_argument("--folder-uid", help="Keeper shared-folder scope")
    _add_format_argument(parser)

    def get_parser(self):
        return self.parser

    def execute(self, params: KeeperParams, **kwargs: Any) -> str:
        dsk_shim = _shim_or_command_error("migrate diff")
        result = dsk_shim.diff(
            manifest_path=kwargs["manifest_path"],
            allow_delete=kwargs.get("allow_delete", False),
            provider=kwargs.get("provider", "mock"),
            folder_uid=kwargs.get("folder_uid"),
        )
        return _emit_result(result, kwargs)


class MigrateAuditExplainCommand(Command):
    """Explain a migration audit log."""

    parser = argparse.ArgumentParser(
        prog="migrate audit-explain",
        description="Explain a keeperCMD audit-chain log.",
    )
    parser.add_argument("audit_log", help="Path to the keeperCMD audit log")
    summary = parser.add_mutually_exclusive_group()
    summary.add_argument("--summary", dest="summary", action="store_true", help="Include time-span summary")
    summary.add_argument("--no-summary", dest="summary", action="store_false", help="Suppress time-span summary")
    parser.set_defaults(summary=True)
    _add_format_argument(parser)

    def get_parser(self):
        return self.parser

    def execute(self, params: KeeperParams, **kwargs: Any) -> str:
        dsk_shim = _shim_or_command_error("migrate audit-explain")
        result = dsk_shim.audit_explain(
            audit_log=kwargs["audit_log"],
            summary=kwargs.get("summary", True),
        )
        return _emit_result(result, kwargs)


class MigrateDriftWatchCommand(Command):
    """Watch for drift between manifests and live state."""

    parser = argparse.ArgumentParser(
        prog="migrate drift-watch",
        description="Run the preview-gated DSK drift watcher.",
    )
    parser.add_argument("manifest_paths", nargs="+", help="Target-state manifest paths")
    parser.add_argument("--interval", type=int, default=300, help="Poll interval in seconds")
    parser.add_argument("--github-repo", help="GitHub owner/repo for drift PRs")
    parser.add_argument("--github-token", help="GitHub token")
    parser.add_argument("--pr-base", default="main", help="Base branch for drift PRs")
    _add_dry_run_pair(parser, default=True)
    parser.add_argument("--slack-webhook", help="Slack incoming webhook URL")
    parser.add_argument("--slack-channel", help="Slack channel override")
    parser.add_argument("--servicenow-instance", help="ServiceNow instance")
    parser.add_argument("--servicenow-api-key", help="ServiceNow API key")
    parser.add_argument("--verbose", action="store_true")
    _add_format_argument(parser)

    def get_parser(self):
        return self.parser

    def execute(self, params: KeeperParams, **kwargs: Any) -> str:
        dsk_shim = _shim_or_command_error("migrate drift-watch")
        result = dsk_shim.drift_watch(
            manifest_paths=kwargs["manifest_paths"],
            interval=kwargs.get("interval", 300),
            github_repo=kwargs.get("github_repo"),
            github_token=kwargs.get("github_token"),
            pr_base=kwargs.get("pr_base", "main"),
            dry_run=kwargs.get("dry_run", True),
            slack_webhook=kwargs.get("slack_webhook"),
            slack_channel=kwargs.get("slack_channel"),
            servicenow_instance=kwargs.get("servicenow_instance"),
            servicenow_api_key=kwargs.get("servicenow_api_key"),
            verbose=kwargs.get("verbose", False),
        )
        return _emit_result(result, kwargs)


class MigrateRehearseReportCommand(Command):
    """Generate rehearsal report from a dry-run."""

    parser = argparse.ArgumentParser(
        prog="migrate rehearse-report",
        description="Emit the keeperCMD rehearsal drift report.",
    )
    parser.add_argument("run_dir", help="Path to the keeperCMD rehearsal run directory")
    parser.add_argument("--output", "-o", help="Write report to path")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Do not write ownership markers")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument(
        "--format",
        dest="output_format",
        choices=("text", "junit"),
        default="text",
        help="DSK report format",
    )

    def get_parser(self):
        return self.parser

    def execute(self, params: KeeperParams, **kwargs: Any) -> str:
        dsk_shim = _shim_or_command_error("migrate rehearse-report")
        result = dsk_shim.rehearse_report(
            run_dir=kwargs["run_dir"],
            output=kwargs.get("output"),
            dry_run=kwargs.get("dry_run", False),
            verbose=kwargs.get("verbose", False),
            output_format=kwargs.get("output_format", "text"),
        )
        return _emit_result(result, kwargs)


class MigrateBundleCommand(Command):
    """Bundle a run-dir for sharing/audit."""

    parser = argparse.ArgumentParser(
        prog="migrate bundle",
        description="Generate or preview a compliance evidence bundle.",
    )
    parser.add_argument("manifest_path", help="Path to the compliance bundle manifest")
    parser.add_argument("--output-dir", help="Output directory")
    parser.add_argument("--dry-run", action="store_true", default=False, help="Preview bundle contents")
    _add_format_argument(parser)

    def get_parser(self):
        return self.parser

    def execute(self, params: KeeperParams, **kwargs: Any) -> str:
        dsk_shim = _shim_or_command_error("migrate bundle")
        result = dsk_shim.bundle(
            manifest_path=kwargs["manifest_path"],
            output_dir=kwargs.get("output_dir"),
            dry_run=kwargs.get("dry_run", False),
        )
        return _emit_result(result, kwargs)


class MigrateGroupCommand(GroupCommand):
    """`keeper migrate <verb>` router."""

    def __init__(self):
        super().__init__()
        self.register_command("adopt", MigrateAdoptCommand(), "Adopt a keeperCMD run-dir")
        self.register_command("plan", MigratePlanCommand(), "Build a migration plan")
        self.register_command("apply", MigrateApplyCommand(), "Apply a migration plan")
        self.register_command("diff", MigrateDiffCommand(), "Diff a manifest against live state")
        self.register_command("audit-explain", MigrateAuditExplainCommand(), "Explain audit log")
        self.register_command("drift-watch", MigrateDriftWatchCommand(), "Watch for drift")
        self.register_command("rehearse-report", MigrateRehearseReportCommand(), "Rehearsal report")
        self.register_command("bundle", MigrateBundleCommand(), "Bundle run-dir")
        self.default_verb = "help"


def register_commands(commands: dict) -> None:
    """Register the `migrate` group command into Commander's command registry."""
    commands["migrate"] = MigrateGroupCommand()


def register_command_info(aliases: dict, command_info: dict) -> None:
    """Register migrate help info and any aliases."""
    command_info["migrate"] = "Tenant migration commands (requires [migrate] extras)"
