"""Tests for keepercommander.commands.keeper_tenant_migrate.integrations.dsk_hooks.

Builds a minimal but realistic run-dir per OUTPUT_CONTRACT.md v1.0 in
tmpdir, runs each hook against it, and pins the public-API shape DSK
relies on.
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from keepercommander.commands.keeper_tenant_migrate.audit import (
    append_audit_event,
    write_sha256sums,
)
from keepercommander.commands.keeper_tenant_migrate.integrations.dsk_hooks import (
    EnterpriseState,
    HealthCheck,
    IntegrityReport,
    MspState,
    ProductDependencyMap,
    RunDirArtifacts,
    UnsafeArtifactError,
    VaultSharingState,
    discover_run_dir,
    get_audit_chain_tail,
    get_compliance_evidence,
    get_enterprise_state,
    get_msp_context_state,
    get_transition_baseline,
    get_users_transition_table,
    get_vault_sharing_state,
    list_keeper_product_dependencies,
    run_static_health_checks,
    stream_compliance_evidence_for_siem,
    validate_run_dir_for_adopt,
    verify_run_dir_integrity,
)
from keepercommander.commands.keeper_tenant_migrate.integrations import dsk_hooks as _hooks


def _build_minimal_run_dir(root: Path) -> Path:
    """Materialize the minimum cmd run-dir DSK adopt expects."""
    rd = root / "rd"
    rd.mkdir()
    (rd / "records_export").mkdir()
    inv = {
        "schema_version": "1.0",
        "_contract_version": "1.0",
        "captured_at": "2026-05-10T20:00:00Z",
        "tenant_uid": "src-tenant-1",
        "counts": {"users": 1, "roles": 0, "teams": 0,
                   "shared_folders": 0, "records": 0, "nodes": 0},
        "entities": {
            "users": [{"email": "alice@src.example", "node": "Acme",
                       "teams": [], "roles": [], "status": "Active",
                       "transfer_status": "", "aliases": [], "alias": "alice@src.example",
                       "2fa_enabled": False, "job_title": "",
                       "hide_shared_folders_teams": []}],
            "roles": [], "teams": [], "shared_folders": [], "records": [], "nodes": [],
        },
    }
    (rd / "inventory.json").write_text(json.dumps(inv), encoding="utf-8")
    (rd / "manifest.csv").write_text(
        "source_uid,target_uid,title\n", encoding="utf-8"
    )
    (rd / "records_import.json").write_text(
        json.dumps({"records": []}), encoding="utf-8"
    )
    # Append one audit event so the chain is non-empty.
    append_audit_event(str(rd / "audit.log"),
                       {"event": "test_init", "tenant_uid": "src-tenant-1"})
    write_sha256sums(str(rd))
    return rd


class DiscoveryTests(unittest.TestCase):

    def test_discover_returns_paths_for_required_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            artifacts = discover_run_dir(rd)
            self.assertIsInstance(artifacts, RunDirArtifacts)
            self.assertTrue(artifacts.inventory_json.is_file())
            self.assertTrue(artifacts.manifest_csv.is_file())
            self.assertTrue(artifacts.records_import_json.is_file())
            self.assertTrue(artifacts.records_export_dir.is_dir())
            self.assertTrue(artifacts.audit_log.is_file())
            self.assertTrue(artifacts.sha256sums_txt.is_file())

    def test_discover_raises_on_missing_run_dir(self):
        with self.assertRaises(FileNotFoundError):
            discover_run_dir("/no/such/dir")

    def test_discover_lists_every_missing_required_file(self):
        with tempfile.TemporaryDirectory() as td:
            rd = Path(td) / "incomplete"
            rd.mkdir()
            (rd / "records_export").mkdir()
            with self.assertRaises(FileNotFoundError) as cm:
                discover_run_dir(rd)
            msg = str(cm.exception)
            for name in ("inventory.json", "manifest.csv",
                         "records_import.json", "audit.log", "SHA256SUMS.txt"):
                self.assertIn(name, msg)


class IntegrityTests(unittest.TestCase):

    def test_clean_run_dir_passes(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            report = verify_run_dir_integrity(rd)
        self.assertIsInstance(report, IntegrityReport)
        self.assertTrue(report.sha256sums_ok)
        self.assertTrue(report.audit_chain_ok)
        self.assertTrue(report.ok)
        self.assertEqual(report.errors, ())

    def test_tampered_inventory_fails_sha256(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            (rd / "inventory.json").write_text("{}", encoding="utf-8")
            report = verify_run_dir_integrity(rd)
        self.assertFalse(report.sha256sums_ok)
        self.assertFalse(report.ok)
        self.assertTrue(any("SHA256" in e for e in report.errors))

    def test_minisig_required_but_absent_fails(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            report = verify_run_dir_integrity(rd, require_minisig=True)
        self.assertFalse(report.ok)
        self.assertTrue(any("minisig" in e.lower() for e in report.errors))


class AuditChainTests(unittest.TestCase):

    def test_tail_returns_last_event(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            append_audit_event(str(rd / "audit.log"),
                               {"event": "second", "x": 1})
            tail = get_audit_chain_tail(rd)
        self.assertEqual(tail.get("event"), "second")
        self.assertIn("prev_hash", tail)
        self.assertIn("signature", tail)


class TransitionTableTests(unittest.TestCase):

    def test_users_transition_table_has_email(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            users = get_users_transition_table(rd)
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].get("email"), "alice@src.example")

    def test_baseline_keyed_by_lowercase_email(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            baseline = get_transition_baseline(rd)
        self.assertIn("alice@src.example", baseline)
        self.assertEqual(baseline["alice@src.example"]["email"], "alice@src.example")


class EnterpriseStateTests(unittest.TestCase):

    def test_extracts_nodes_teams_roles_and_memberships(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            # Augment with nodes/teams/roles + memberships for this test.
            with open(rd / "inventory.json", encoding="utf-8") as f:
                inv = json.load(f)
            inv["entities"]["nodes"] = [{"name": "Eng"}, {"name": "Ops"}]
            inv["entities"]["teams"] = [{"name": "Alpha"}, {"name": "Beta"}]
            inv["entities"]["roles"] = [
                {"name": "Admin", "node": "Eng",
                 "teams": ["Alpha", {"team_name": "Beta"}],
                 "users": [{"email": "a@x"}, "b@x"]},
            ]
            (rd / "inventory.json").write_text(json.dumps(inv), encoding="utf-8")
            state = get_enterprise_state(rd)
        self.assertIsInstance(state, EnterpriseState)
        self.assertEqual([n["name"] for n in state.nodes], ["Eng", "Ops"])
        self.assertEqual([t["name"] for t in state.teams], ["Alpha", "Beta"])
        self.assertEqual([r["name"] for r in state.roles], ["Admin"])
        self.assertEqual(
            sorted((m["role"], m["team"]) for m in state.role_team_memberships),
            [("Admin", "Alpha"), ("Admin", "Beta")],
        )
        self.assertEqual(
            sorted((m["role"], m["user_email"])
                   for m in state.role_user_memberships),
            [("Admin", "a@x"), ("Admin", "b@x")],
        )


class VaultSharingStateTests(unittest.TestCase):

    def test_extracts_sf_users_teams_record_shares(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            with open(rd / "inventory.json", encoding="utf-8") as f:
                inv = json.load(f)
            inv["entities"]["shared_folders"] = [
                {"uid": "SF1", "name": "Shared",
                 "users": [{"username": "alice@x"}, "string-skipped"],
                 "teams": [{"team_name": "Alpha"}, "Beta"]},
            ]
            inv["entities"]["records"] = [
                {"uid": "R1", "title": "secret",
                 "direct_shares": [{"username": "carol@x", "editable": True}]},
            ]
            (rd / "inventory.json").write_text(json.dumps(inv), encoding="utf-8")
            state = get_vault_sharing_state(rd)
        self.assertIsInstance(state, VaultSharingState)
        self.assertEqual(len(state.shared_folders), 1)
        # SF.users: only the dict entry (string entries are skipped)
        self.assertEqual([u["user_email"] if "user_email" in u else u["username"]
                          for u in state.sf_user_memberships], ["alice@x"])
        # SF.teams: dict {team_name} + plain string both captured
        team_names = sorted(m["team_name"] for m in state.sf_team_memberships)
        self.assertEqual(team_names, ["Alpha", "Beta"])
        self.assertEqual(state.record_direct_shares,
                         [{"record_uid": "R1", "username": "carol@x", "editable": True}])


class ComplianceEvidenceTests(unittest.TestCase):

    def test_export_cef_writes_to_default_path(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            out = get_compliance_evidence(rd, fmt="cef")
            self.assertTrue(out.is_file())
            self.assertEqual(out.name, "compliance-evidence.cef")
            self.assertGreater(out.stat().st_size, 0)

    def test_export_jsonlines_to_custom_path(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            target = Path(td) / "evidence.ndjson"
            out = get_compliance_evidence(rd, fmt="json-lines",
                                          output_path=target)
            self.assertEqual(out, target)
            self.assertTrue(out.is_file())


class StaticHealthCheckTests(unittest.TestCase):

    def test_runs_at_least_one_check(self):
        results = run_static_health_checks()
        self.assertGreaterEqual(len(results), 1)
        for r in results:
            self.assertIsInstance(r, HealthCheck)
            self.assertIn(r.status, ("PASS", "SKIP", "FAIL"))


class SafeReadTrustBoundaryTests(unittest.TestCase):
    """Mirror of DSK's _safe_open trust-boundary discipline (audit DA #1
    surfaced this gap in dsk_hooks's first pass)."""

    def test_safe_open_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            real = Path(td) / "real.json"
            real.write_text("{}", encoding="utf-8")
            link = Path(td) / "linked.json"
            link.symlink_to(real)
            with self.assertRaises(UnsafeArtifactError) as cm:
                with _hooks._safe_open(link):
                    pass
            self.assertIn("symlink", str(cm.exception).lower())

    def test_safe_open_refuses_directory(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "dir"
            d.mkdir()
            with self.assertRaises(UnsafeArtifactError):
                with _hooks._safe_open(d):
                    pass

    def test_safe_open_refuses_oversized(self):
        with tempfile.TemporaryDirectory() as td:
            big = Path(td) / "big.json"
            big.write_bytes(b"x" * 1024)
            old = os.environ.get("KCM_HOOK_MAX_ARTIFACT_BYTES")
            os.environ["KCM_HOOK_MAX_ARTIFACT_BYTES"] = "10"
            try:
                with self.assertRaises(UnsafeArtifactError) as cm:
                    with _hooks._safe_open(big):
                        pass
                self.assertIn("exceeding", str(cm.exception))
            finally:
                if old is None:
                    del os.environ["KCM_HOOK_MAX_ARTIFACT_BYTES"]
                else:
                    os.environ["KCM_HOOK_MAX_ARTIFACT_BYTES"] = old

    def test_get_enterprise_state_refuses_symlinked_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            real = rd / "inventory.json"
            real_content = real.read_text(encoding="utf-8")
            real.unlink()
            elsewhere = Path(td) / "elsewhere.json"
            elsewhere.write_text(real_content, encoding="utf-8")
            real.symlink_to(elsewhere)
            with self.assertRaises(UnsafeArtifactError):
                get_enterprise_state(rd)


class ValidateAdoptTimeInventoryOnlyTests(unittest.TestCase):
    """validate_run_dir_for_adopt(target_state=None) returns inventory-
    only checks; doesn't FAIL on empty target."""

    def test_default_target_state_none_runs_inventory_only_checks(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            checks = validate_run_dir_for_adopt(rd)  # target_state=None
        phases = [c.phase for c in checks]
        # Inventory-only mode emits entities_present:* + ref_graph
        # checks; does NOT include verify-time pre_flight (which would
        # FAIL on empty target).
        self.assertTrue(any(p.startswith("entities_present:") for p in phases))
        self.assertTrue(any(p.startswith("ref_graph:") for p in phases))
        self.assertNotIn("pre_flight",
                         [c.phase for c in checks if c.severity.value == "FAIL"])

    def test_explicit_target_state_runs_full_validator(self):
        # Passing an empty dict explicitly opts into verify-mode (and
        # gets pre_flight FAIL because target really is empty).
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            checks = validate_run_dir_for_adopt(rd, target_state={})
        # Verify-mode includes phase_pre_flight which FAILs on empty target.
        self.assertTrue(any(c.phase == "pre_flight"
                            and c.severity.value == "FAIL"
                            for c in checks))

    def test_inventory_only_passes_on_clean_minimal_run_dir(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            checks = validate_run_dir_for_adopt(rd)
        # No FAILs in inventory-only mode for the minimal valid fixture.
        fails = [c for c in checks if c.severity.value == "FAIL"]
        self.assertEqual(fails, [], f"unexpected FAIL rows: {fails}")


class MspContextStateTests(unittest.TestCase):

    def test_non_msp_run_returns_clean_state(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            state = get_msp_context_state(rd)
        self.assertIsInstance(state, MspState)
        self.assertFalse(state.is_msp_run)
        self.assertEqual(state.source_msp_name, "")
        self.assertEqual(state.target_mc_uid, "")
        self.assertEqual(state.managed_companies, [])

    def test_msp_signal_in_inventory_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            with open(rd / "inventory.json", encoding="utf-8") as f:
                inv = json.load(f)
            inv["is_msp"] = True
            inv["msp_name"] = "AcmeMSP"
            inv["entities"]["managed_companies"] = [
                {"uid": "MC1", "name": "Acme-Subsidiary-A",
                 "node_count": 3, "user_count": 12},
            ]
            (rd / "inventory.json").write_text(json.dumps(inv), encoding="utf-8")
            state = get_msp_context_state(rd)
        self.assertTrue(state.is_msp_run)
        self.assertEqual(state.source_msp_name, "AcmeMSP")
        self.assertEqual(len(state.managed_companies), 1)
        self.assertEqual(state.managed_companies[0]["name"], "Acme-Subsidiary-A")


class SiemStreamingTests(unittest.TestCase):

    def test_cef_stream_yields_one_per_event(self):
        from keepercommander.commands.keeper_tenant_migrate.audit import append_audit_event
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            append_audit_event(str(rd / "audit.log"),
                               {"event": "second", "x": 1})
            from keepercommander.commands.keeper_tenant_migrate.audit import write_sha256sums
            write_sha256sums(str(rd))
            events = list(stream_compliance_evidence_for_siem(rd, fmt="cef"))
        self.assertEqual(len(events), 2)
        for ev in events:
            self.assertTrue(ev.startswith("CEF:"))

    def test_jsonlines_stream_returns_strings(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            events = list(stream_compliance_evidence_for_siem(rd, fmt="json-lines"))
        self.assertGreaterEqual(len(events), 1)
        for line in events:
            self.assertIsInstance(line, str)
            json.loads(line)  # parses cleanly

    def test_invalid_format_raises(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            with self.assertRaises(ValueError):
                list(stream_compliance_evidence_for_siem(rd, fmt="bogus"))


class ProductDependencyMapTests(unittest.TestCase):

    def test_minimal_run_dir_has_no_pam_no_msp(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            deps = list_keeper_product_dependencies(rd)
        self.assertIsInstance(deps, ProductDependencyMap)
        self.assertFalse(deps.requires_pam)
        self.assertFalse(deps.requires_msp)
        # minimal fixture has 1 user but no nodes/teams/roles/SFs/records
        self.assertFalse(deps.requires_enterprise)
        self.assertFalse(deps.requires_shared_folders)
        self.assertFalse(deps.requires_records)

    def test_pam_record_types_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            with open(rd / "inventory.json", encoding="utf-8") as f:
                inv = json.load(f)
            inv["entities"]["records"] = [
                {"uid": "R1", "title": "DB Prod", "record_type": "pamDatabase"},
                {"uid": "R2", "title": "App Cfg", "record_type": "pamConfig"},
                {"uid": "R3", "title": "Plain login", "record_type": "login"},
            ]
            (rd / "inventory.json").write_text(json.dumps(inv), encoding="utf-8")
            deps = list_keeper_product_dependencies(rd)
        self.assertTrue(deps.requires_pam)
        self.assertTrue(deps.requires_records)
        self.assertTrue(any("PAM record" in n for n in deps.notes))

    def test_msp_signal_flagged_in_dependencies(self):
        with tempfile.TemporaryDirectory() as td:
            rd = _build_minimal_run_dir(Path(td))
            with open(rd / "inventory.json", encoding="utf-8") as f:
                inv = json.load(f)
            inv["is_msp"] = True
            inv["msp_name"] = "DepMSP"
            (rd / "inventory.json").write_text(json.dumps(inv), encoding="utf-8")
            deps = list_keeper_product_dependencies(rd)
        self.assertTrue(deps.requires_msp)
        self.assertTrue(any("MSP" in n for n in deps.notes))


if __name__ == "__main__":
    unittest.main()
