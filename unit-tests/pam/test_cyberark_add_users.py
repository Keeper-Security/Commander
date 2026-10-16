import unittest
from types import SimpleNamespace
from unittest import mock

from keepercommander.commands.pam_import.cyberark_import import (
    CyberArkImportOrchestrator,
    CyberArkPAMImportCommand,
)
from keepercommander.importer.cyberark.pam.client import CyberArkPVWAClient
from keepercommander.importer.cyberark.pam.import_builder import (
    _format_enterprise_users,
    build_report,
)

_MODULE = "keepercommander.commands.pam_import.cyberark_import"


class _QuietTestCase(unittest.TestCase):
    """Silences console output, sleeps and logging for every test."""

    def setUp(self):
        for target in ("time.sleep", "print_formatted_text", "logging"):
            self._patch(f"{_MODULE}.{target}")
        self._patch(f"{_MODULE}.HTML", side_effect=lambda text: text)
        self._patch("builtins.print")
        self.log = self._mocks["logging"]
        self.sleep = self._mocks["time.sleep"]

    def _patch(self, target, **kwargs):
        patcher = mock.patch(target, **kwargs)
        self.__dict__.setdefault("_mocks", {})[target.rsplit(f"{_MODULE}.", 1)[-1]] = patcher.start()
        self.addCleanup(patcher.stop)


def _orchestrator(client=None, **options):
    orch = CyberArkImportOrchestrator.__new__(CyberArkImportOrchestrator)
    orch.client = client or mock.MagicMock()
    orch.params = object()
    orch._cmd = mock.MagicMock()
    orch.options = SimpleNamespace(**{
        "add_cyberark_users": False, "list_safes": False, "estimate_only": False,
        "output_file": "", "dry_run": False, "project_name": "p", "config_uid": "", **options,
    })
    return orch


def _command():
    return CyberArkPAMImportCommand.__new__(CyberArkPAMImportCommand)


class TestExtractUserEmail(_QuietTestCase):
    def test_source_priority_and_edge_cases(self):
        full = {
            "internet": {"businessEmail": "biz@x.com", "homeEmail": "home@x.com", "otherEmail": "other@x.com"},
            "email": "top@x.com",
            "personalDetails": {"email": "personal@x.com"},
        }
        cases = [
            ("business wins over everything", full, "biz@x.com"),
            ("home when no business", {"internet": {"homeEmail": "home@x.com"}, "email": "top@x.com"}, "home@x.com"),
            ("top-level before personal", {"email": "top@x.com", "personalDetails": {"email": "p@x.com"}}, "top@x.com"),
            ("personal as last resort", {"personalDetails": {"email": "p@x.com"}}, "p@x.com"),
            ("keys are case-insensitive", {"Internet": {"BUSINESSEMAIL": "biz@x.com"}}, "biz@x.com"),
            ("value is trimmed", {"email": "  top@x.com \n"}, "top@x.com"),
            ("blank / non-string falls through", {"internet": {"businessEmail": "   ", "homeEmail": 42},
                                                 "email": "top@x.com"}, "top@x.com"),
            ("internet not a dict is ignored", {"internet": "biz@x.com", "email": "top@x.com"}, "top@x.com"),
            ("no address anywhere", {"username": "bob", "internet": {}}, None),
            ("None input", None, None),
            ("list input", ["a@x.com"], None),
        ]
        orch = _orchestrator()
        for name, user, expected in cases:
            with self.subTest(name):
                self.assertEqual(orch._extract_user_email(user), expected)


class TestPrepareUsers(_QuietTestCase):
    def _prepare(self, users, details=None):
        client = mock.MagicMock()
        client.fetch_users.return_value = users
        client.fetch_user_details.side_effect = details or (lambda user_id: None)
        return _orchestrator(client)._prepare_users(), client

    def test_list_email_skips_detail_fetch(self):
        found, client = self._prepare([{"id": "1", "username": "a", "email": "a@x.com"}])
        self.assertEqual(found, [{"id": "1", "username": "a", "email": "a@x.com"}])
        client.fetch_user_details.assert_not_called()
        self.sleep.assert_not_called()

    def test_missing_email_is_fetched_from_details_with_throttle(self):
        found, client = self._prepare(
            [{"id": "7", "username": "b"}],
            details=lambda user_id: {"internet": {"businessEmail": "b@x.com"}},
        )
        self.assertEqual(found, [{"id": "7", "username": "b", "email": "b@x.com"}])
        client.fetch_user_details.assert_called_once_with("7")
        self.sleep.assert_called_once_with(CyberArkImportOrchestrator.DELAY)

    def test_detail_fetch_failure_omits_only_that_user(self):
        def details(user_id):
            raise RuntimeError("403 Forbidden")
        found, _ = self._prepare(
            [{"id": "1", "username": "bad"}, {"id": "2", "username": "ok", "email": "ok@x.com"}],
            details=details,
        )
        self.assertEqual([u["username"] for u in found], ["ok"])
        self.log.warning.assert_called_once()

    def test_rows_without_usable_email_or_id(self):
        found, client = self._prepare([
            {"username": "no-email-no-id"},
            {"id": "", "username": "blank-id"},
            {"username": "email-no-id", "email": "e@x.com"},
            {"id": "3", "username": "details-empty"},
            "not-a-dict",
            None,
        ])
        self.assertEqual(found, [{"id": None, "username": "email-no-id", "email": "e@x.com"}])
        client.fetch_user_details.assert_called_once_with("3")

    def test_missing_username_becomes_empty_string(self):
        found, _ = self._prepare([{"id": "1", "email": "a@x.com", "username": None}])
        self.assertEqual(found[0]["username"], "")


class TestLoadExistingKeeperUsers(_QuietTestCase):
    def setUp(self):
        super().setUp()
        self._patch(f"{_MODULE}.api.query_enterprise")
        self.query = self._mocks["api.query_enterprise"]

    def test_cached_enterprise_with_real_keeper_shape(self):
        # Keeper enterprise rows carry the address in "username", not "email".
        params = SimpleNamespace(enterprise={"users": [
            {"username": " Alice@X.com ", "status": "invited"},
            {"username": "bob@x.com"},
            "junk",
        ]})
        users, error = _command()._load_existing_keeper_users(params)
        self.assertEqual(error, "")
        self.assertEqual(users, [
            {"email": "Alice@X.com", "status": "invited"},
            {"email": "bob@x.com", "status": "active"},
        ])
        self.query.assert_not_called()

    def test_enterprise_is_queried_when_not_loaded(self):
        params = SimpleNamespace(enterprise=None)
        self.query.side_effect = lambda p: setattr(p, "enterprise", {"users": [{"email": "a@x.com"}]})
        users, error = _command()._load_existing_keeper_users(params)
        self.assertEqual((users, error), ([{"email": "a@x.com", "status": "active"}], ""))

    def test_query_failure_returns_error(self):
        self.query.side_effect = RuntimeError("not an admin")
        users, error = _command()._load_existing_keeper_users(SimpleNamespace(enterprise=None))
        self.assertEqual(users, [])
        self.assertTrue(error)


class TestCreateEnterpriseUsers(_QuietTestCase):
    def _run(self, users, existing=(), error="", create_result="uid"):
        cmd = _command()
        cmd._load_existing_keeper_users = mock.MagicMock(return_value=(list(existing), error))
        cmd._create_keeper_user = mock.MagicMock(return_value=create_result)
        report = cmd._create_enterprise_users(object(), users)
        return report["users"], cmd._create_keeper_user

    def test_every_outcome_in_input_order(self):
        rows, create = self._run(
            [
                {"username": "new", "email": "new@x.com"},
                {"username": "old", "email": "old@x.com"},
                {"username": "bad", "email": "not-an-email"},
                {"username": "blank", "email": ""},
                {},
                "",
                None
            ],
            existing=[{"email": "old@x.com", "status": "locked"}],
        )
        self.assertEqual([(r["email"], r["flag"]) for r in rows], [
            ("new@x.com", "created"), ("old@x.com", "existing"),
            ("not-an-email", "skipped"), ("", "skipped"), ("", "skipped"),
        ])
        self.assertEqual(rows[1]["status"], "locked")
        create.assert_called_once_with(mock.ANY, "new@x.com", "new")

    def test_existing_match_ignores_case(self):
        rows, create = self._run(
            [{"username": "john", "email": "John.Doe@Corp.com"}, {}, None, ""],
            existing=[{"email": "john.doe@corp.com", "status": "active"}],
        )
        self.assertEqual(rows[0]["flag"], "existing")
        create.assert_not_called()

    def test_case_variant_duplicates_are_created_once(self):
        rows, create = self._run([
            {"username": "a1", "email": "A@corp.com"},
            {"username": "a2", "email": "a@corp.com"},
            {}, # it will skip this
            {}, # it will skip this
            None,
            "",
            "  ",
            "!",
            12.3
        ])
        self.assertEqual(len(rows), 3)
        create.assert_called_once()

    def test_email_is_trimmed_and_username_falls_back_to_email(self):
        rows, create = self._run([{"username": None, "email": "  c@x.com  "}])
        create.assert_called_once_with(mock.ANY, "c@x.com", "c@x.com")
        self.assertEqual(rows[0]["email"], "c@x.com")

    def test_failed_create_is_reported_and_not_retried(self):
        rows, create = self._run(
            [{"username": "f", "email": "f@x.com"}, {"username": "f", "email": "f@x.com"}],
            create_result=None,
        )
        self.assertEqual([r["flag"] for r in rows], ["failed"])
        create.assert_called_once()

    def test_loader_error_still_creates_users(self):
        rows, _ = self._run([{"username": "n", "email": "n@x.com"}], error="Failed to Load Existing User")
        self.assertEqual(rows[0]["flag"], "created")


class TestCreateKeeperUser(_QuietTestCase):
    def setUp(self):
        super().setUp()
        patcher = mock.patch("keepercommander.commands.enterprise_create_user.CreateEnterpriseUserCommand")
        self.command_cls = patcher.start()
        self.addCleanup(patcher.stop)

    def test_forwards_email_and_name(self):
        self.command_cls.return_value.execute.return_value = "record-uid"
        params = object()
        self.assertEqual(_command()._create_keeper_user(params, "a@x.com", "Alice"), "record-uid")
        self.command_cls.return_value.execute.assert_called_once_with(params, email="a@x.com", name="Alice")

    def test_error_returns_none_and_warns(self):
        self.command_cls.return_value.execute.side_effect = RuntimeError("reserved domain required")
        self.assertIsNone(_command()._create_keeper_user(object(), "a@x.com", "Alice"))
        self.log.warning.assert_called_once()


class TestFetchUserDetails(unittest.TestCase):
    def _client(self, response):
        client = CyberArkPVWAClient.__new__(CyberArkPVWAClient)
        client.pvwa_host = "pvwa.example.com"
        client._get = mock.MagicMock(return_value=response)
        return client

    def test_requests_user_endpoint_and_returns_json(self):
        response = mock.MagicMock()
        response.json.return_value = {"id": 5}
        client = self._client(response)
        self.assertEqual(client.fetch_user_details("5"), {"id": 5})
        client._get.assert_called_once_with("https://pvwa.example.com/PasswordVault/API/Users/5")

    def test_http_error_propagates(self):
        response = mock.MagicMock()
        response.raise_for_status.side_effect = RuntimeError("404")
        with self.assertRaises(RuntimeError):
            self._client(response).fetch_user_details("5")


class TestEnterpriseUsersReport(unittest.TestCase):
    def test_section_counts_and_rows(self):
        lines = _format_enterprise_users({"users": [
            {"email": "a@x.com", "flag": "created"},
            {"email": "b@x.com", "flag": "existing", "status": "invited"},
            {"email": "bad", "flag": "skipped", "reason": "invalid email"},
            {"username": "c", "flag": "failed", "reason": "user was not created"},
        ], "error": "Failed to Load Existing User"})
        text = "\n".join(lines)
        self.assertIn("created    1   existing    1   skipped    1   failed    1", text)
        self.assertIn("Failed to Load Existing User", text)
        self.assertIn("[existing] b@x.com  invited", text)
        self.assertIn("[skipped] bad  invalid email", text)
        self.assertIn("[failed] c  user was not created", text)

    def test_build_report_includes_section_only_when_provided(self):
        args = dict(project_name="p", safes_processed=0, total_accounts=0, resource_counts={},
                    platform_counts={}, skipped=[], incomplete_count=0, duration=0.0)
        self.assertNotIn("ENTERPRISE USERS", build_report(**args))
        report = build_report(**args, enterprise_users={"users": [{"email": "a@x.com", "flag": "created"}]})
        self.assertIn("ENTERPRISE USERS", report)


class TestRunFlow(_QuietTestCase):
    def _run(self, **options):
        self._patch(f"{_MODULE}.validate_import_data", return_value=[])
        orch = _orchestrator(**options)
        mapped = mock.MagicMock()
        mapped.mapper.platform_workflow_unmapped = []
        stubs = {
            "_prepare_safes": ([{"safeName": "s"}], 0), "_maybe_interactive_safe_pick": [{"safeName": "s"}],
            "_fetch_safe_members": ({}, []), "_fetch_accounts": {"s": [{"id": "acc"}]},
            "_map_accounts": mapped, "_prepare_idempotency": None, "_build_import_payload": {},
            "_confirm_import": True, "_execute_vault_import": {"project_name": "p"},
            "_prepare_users": [{"id": "1", "username": "a", "email": "a@x.com"}],
        }
        for name in ("_load_master_policy", "_build_user_team_matcher", "_maybe_auto_extend",
                     "_print_mapping_summary", "_print_dry_run", "_print_estimate",
                     "_write_output_file", "_finalize_report"):
            setattr(orch, name, mock.MagicMock())
        for name, value in stubs.items():
            setattr(orch, name, mock.MagicMock(return_value=value))
        orch._cmd._create_enterprise_users.return_value = {"users": ["report"]}
        return orch

    def test_flag_off_does_not_touch_users(self):
        orch = self._run()
        orch.run()
        orch._prepare_users.assert_not_called()
        orch._cmd._create_enterprise_users.assert_not_called()
        self.assertIsNone(orch._finalize_report.call_args.kwargs["enterprise_users"])

    def test_flag_on_creates_users_and_reports_them(self):
        orch = self._run(add_cyberark_users=True)
        orch.run()
        orch._cmd._create_enterprise_users.assert_called_once_with(
            orch.params, [{"id": "1", "username": "a", "email": "a@x.com"}])
        self.assertEqual(orch._finalize_report.call_args.kwargs["enterprise_users"], {"users": ["report"]})

    def test_user_fetch_failure_does_not_abort_import(self):
        orch = self._run(add_cyberark_users=True)
        orch._prepare_users.side_effect = RuntimeError("403 Forbidden")
        orch.run()
        orch._execute_vault_import.assert_called_once()
        orch._cmd._create_enterprise_users.assert_not_called()
        self.assertTrue(orch._finalize_report.call_args.kwargs["enterprise_users"]["error"])

    def test_non_writing_modes_never_fetch_or_create_users(self):
        for mode in ({"dry_run": True}, {"output_file": "out.json"}, {"estimate_only": True}, {"list_safes": True}):
            with self.subTest(mode):
                orch = self._run(add_cyberark_users=True, **mode)
                orch.run()
                orch._prepare_users.assert_not_called()
                orch._cmd._create_enterprise_users.assert_not_called()

    def test_parser_flag(self):
        parser = CyberArkPAMImportCommand.parser
        self.assertTrue(parser.parse_args(["pvwa.example.com", "--add-cyberark-users"]).add_cyberark_users)
        self.assertFalse(parser.parse_args(["pvwa.example.com"]).add_cyberark_users)


if __name__ == "__main__":
    unittest.main()
