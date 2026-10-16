import copy
import unittest
from collections import UserDict
from types import SimpleNamespace
from unittest import mock
from keepercommander.commands.pam_import.cyberark_import import (
    CyberArkImportOrchestrator,
    CyberArkPAMImportCommand,
)
from keepercommander.error import CommandError

def _orchestrator(client=None):
    orch = CyberArkImportOrchestrator.__new__(CyberArkImportOrchestrator)
    orch.client = client if client is not None else mock.MagicMock()
    return orch

class _BadKey:
    def __str__(self):
        raise RuntimeError("key stringification failed")

class TestGetCaseInsensitive(unittest.TestCase):
    def test_exact_key(self):
        found = CyberArkImportOrchestrator._get_case_insensitive(
            {"email": "a@b.com"}, "email",
        )
        self.assertEqual(found, "a@b.com")

    def test_match_is_case_insensitive(self):
        data = {"BusinessEmail": "a@b.com"}
        lower = CyberArkImportOrchestrator._get_case_insensitive(data, "businessemail")
        upper = CyberArkImportOrchestrator._get_case_insensitive(data, "BUSINESSEMAIL")
        self.assertEqual(lower, "a@b.com")
        self.assertEqual(upper, "a@b.com")

    def test_missing_key_returns_none(self):
        found = CyberArkImportOrchestrator._get_case_insensitive(
            {"username": "bob"}, "email",
        )
        self.assertIsNone(found)

    def test_empty_dict_returns_none(self):
        found = CyberArkImportOrchestrator._get_case_insensitive({}, "email")
        self.assertIsNone(found)

    def test_non_dict_returns_none(self):
        samples = [None, [], (), "email", 0, 1.5, b"email", True]
        for data in samples:
            with self.subTest(data=data):
                found = CyberArkImportOrchestrator._get_case_insensitive(data, "email")
                self.assertIsNone(found)

    def test_mapping_that_is_not_a_dict_returns_none(self):
        found = CyberArkImportOrchestrator._get_case_insensitive(
            UserDict({"email": "a@b.com"}), "email",
        )
        self.assertIsNone(found)

    def test_falsy_values_are_returned_unchanged(self):
        samples = ["", 0, False, None, [], {}]
        for stored in samples:
            with self.subTest(stored=stored):
                found = CyberArkImportOrchestrator._get_case_insensitive(
                    {"email": stored}, "Email",
                )
                self.assertEqual(found, stored)

    def test_returned_container_is_the_same_object(self):
        nested = {"businessEmail": "a@b.com"}
        found = CyberArkImportOrchestrator._get_case_insensitive(
            {"Internet": nested}, "internet",
        )
        self.assertEqual(found, nested)
        self.assertIs(found, nested)

    def test_first_case_variant_wins(self):
        data = {"Email": "first@b.com", "email": "second@b.com"}
        found = CyberArkImportOrchestrator._get_case_insensitive(data, "EMAIL")
        self.assertEqual(found, "first@b.com")

    def test_does_not_match_substring_or_padded_key(self):
        data = {"email": "exact@b.com", "email ": "pad@b.com", "e-mail": "dash@b.com"}
        exact = CyberArkImportOrchestrator._get_case_insensitive(data, "email")
        padded = CyberArkImportOrchestrator._get_case_insensitive(data, " email")
        self.assertEqual(exact, "exact@b.com")
        self.assertIsNone(padded)

    def test_empty_target_matches_only_empty_key(self):
        blank = CyberArkImportOrchestrator._get_case_insensitive({"": "blank"}, "")
        missing = CyberArkImportOrchestrator._get_case_insensitive({"email": "a@b.com"}, "")
        self.assertEqual(blank, "blank")
        self.assertIsNone(missing)

    def test_non_string_key_matches_via_str(self):
        one = CyberArkImportOrchestrator._get_case_insensitive({1: "one"}, "1")
        nada = CyberArkImportOrchestrator._get_case_insensitive({None: "nada"}, "none")
        yes = CyberArkImportOrchestrator._get_case_insensitive({True: "yes"}, "true")
        self.assertEqual(one, "one")
        self.assertEqual(nada, "nada")
        self.assertEqual(yes, "yes")

    def test_bytes_key_does_not_match_its_text(self):
        found = CyberArkImportOrchestrator._get_case_insensitive(
            {b"email": "a@b.com"}, "email",
        )
        self.assertIsNone(found)

    def test_lower_is_not_casefold(self):
        sharp = CyberArkImportOrchestrator._get_case_insensitive({"ß": 1}, "ß")
        folded = CyberArkImportOrchestrator._get_case_insensitive({"ß": 1}, "ss")
        turkish = CyberArkImportOrchestrator._get_case_insensitive({"İ": 1}, "i")
        self.assertEqual(sharp, 1)
        self.assertIsNone(folded)
        self.assertIsNone(turkish)

    def test_non_string_target_raises(self):
        with self.assertRaises(AttributeError):
            CyberArkImportOrchestrator._get_case_insensitive({"email": "a@b.com"}, None)

    def test_key_whose_string_conversion_raises_propagates(self):
        with self.assertRaisesRegex(RuntimeError, "key stringification failed"):
            CyberArkImportOrchestrator._get_case_insensitive({_BadKey(): 1}, "email")

    def test_dict_subclass_is_accepted(self):
        class Payload(dict):
            pass
        found = CyberArkImportOrchestrator._get_case_insensitive(
            Payload({"Email": "a@b.com"}), "email",
        )
        self.assertEqual(found, "a@b.com")

class TestExtractUserEmail(unittest.TestCase):
    def setUp(self):
        self.orch = _orchestrator()
    def test_extract_user_email(self):
        cases = [
            (
                {
                    "internet": {
                        "businessEmail": "biz@e.com",
                        "homeEmail": "home@e.com",
                        "otherEmail": "other@e.com",
                    },
                    "email": "flat@e.com",
                    "personalDetails": {"email": "personal@e.com"},
                },
                "biz@e.com",
                "Priority: internet.businessEmail over rest",
            ),
            (
                {
                    "internet": {
                        "homeEmail": "home@e.com",
                        "otherEmail": "other@e.com",
                    },
                    "email": "flat@e.com",
                },
                "home@e.com",
                "Priority: internet.homeEmail over flat email",
            ),
            (
                {
                    "internet": {"otherEmail": "other@e.com"},
                    "email": "flat@e.com",
                },
                "other@e.com",
                "Priority: internet.otherEmail over flat email",
            ),
            (
                {
                    "email": "flat@e.com",
                    "personalDetails": {"email": "personal@e.com"},
                },
                "flat@e.com",
                "Priority: flat email over personalDetails.email",
            ),
            (
                {"personalDetails": {"email": "personal@e.com"}},
                "personal@e.com",
                "Fallback: personalDetails.email",
            ),
            (
                {"INTERNET": {"BUSINESSEMAIL": "Alice@Example.COM"}},
                "Alice@Example.COM",
                "Case-insensitive keys, preserves value case",
            ),
            (
                {
                    "internet": {"businessEmail": "   ", "homeEmail": 0},
                    "email": False,
                    "personalDetails": {"email": "valid@e.com"},
                },
                "valid@e.com",
                "Falsy/blank values fall through to next priority",
            ),
            (
                {"email": "  a@b.com \n"},
                "a@b.com",
                "Trimming surrounding whitespace",
            ),
            (
                {"email": "a @b.com"},
                "a @b.com",
                "Preserving internal whitespace",
            ),
            (
                {"email": "not-an-email"},
                "not-an-email",
                "Does not require '@' symbol",
            ),
            (
                {
                    "internet": "not-a-dict",
                    "personalDetails": None,
                    "email": 12345,
                },
                None,
                "Non-dict nested objects and non-string values return None",
            ),
        ]
        for user, expected, msg in cases:
            with self.subTest(msg=msg):
                found = self.orch._extract_user_email(user)
                self.assertEqual(found, expected)

    def test_invalid_input_types_return_none(self):
        for sample in [{}, None, [], "not-a-user", 5]:
            with self.subTest(sample=type(sample).__name__):
                self.assertIsNone(self.orch._extract_user_email(sample))

    def test_does_not_mutate_input_user(self):
        user = {
            "internet": {"businessEmail": "  biz@e.com  "},
            "email": "flat@e.com",
        }
        snapshot = {
            "internet": {"businessEmail": "  biz@e.com  "},
            "email": "flat@e.com",
        }
        self.orch._extract_user_email(user)
        self.assertEqual(user, snapshot)

class TestPrepareUsers(unittest.TestCase):
    def setUp(self):
        self.sleep_mock = self._start_patch(mock.patch(
            "keepercommander.commands.pam_import.cyberark_import.time.sleep",
        ))
        self.printed = self._start_patch(mock.patch(
            "keepercommander.commands.pam_import.cyberark_import.print_formatted_text",
        ))
        self._start_patch(mock.patch(
            "keepercommander.commands.pam_import.cyberark_import.HTML",
            side_effect=lambda text: text,
        ))
        self._start_patch(mock.patch("builtins.print"))
        self.log_warning = self._start_patch(mock.patch(
            "keepercommander.commands.pam_import.cyberark_import.logging.warning",
        ))
        self.client = mock.MagicMock()
        self.client.fetch_users.return_value = []
        self.orch = _orchestrator(self.client)

    def _start_patch(self, patcher):
        started = patcher.start()
        self.addCleanup(patcher.stop)
        return started

    def test_empty_list(self):
        found = self.orch._prepare_users()
        self.assertEqual(found, [])
        self.client.fetch_users.assert_called_once_with()
        self.client.fetch_user_details.assert_not_called()
        self.sleep_mock.assert_not_called()
        self.assertEqual(self.printed.call_args.args[0], "Found <b>0</b> CyberArk users ")

    def test_list_address_skips_detail_fetch(self):
        self.client.fetch_users.return_value = [{
            "id": 7,
            "username": "alice",
            "internet": {"businessEmail": "  alice@e.com  "},
        }]
        found = self.orch._prepare_users()
        self.assertEqual(found, [{
            "id": 7,
            "username": "alice",
            "email": "alice@e.com",
        }])
        self.client.fetch_user_details.assert_not_called()
        self.sleep_mock.assert_not_called()
        self.assertEqual(self.printed.call_args.args[0], "Found <b>1</b> CyberArk users ")

    def test_detail_fetch_when_list_payload_has_no_address(self):
        self.client.fetch_users.return_value = [{"id": "12", "username": "bob", "email": ""}]
        self.client.fetch_user_details.return_value = {
            "personalDetails": {"email": "bob@e.com"},
        }
        found = self.orch._prepare_users()
        self.assertEqual(found, [{
            "id": "12",
            "username": "bob",
            "email": "bob@e.com",
        }])
        self.client.fetch_user_details.assert_called_once_with("12")
        self.sleep_mock.assert_called_once_with(CyberArkImportOrchestrator.DELAY)

    def test_detail_fetch_is_ordered_before_the_request(self):
        order = []
        self.sleep_mock.side_effect = lambda delay: order.append(("sleep", delay))
        self.client.fetch_users.return_value = [{"id": 1, "username": "bob"}]
        def _details(user_id):
            order.append(("details", user_id))
            return {"email": "bob@e.com"}
        self.client.fetch_user_details.side_effect = _details
        self.orch._prepare_users()
        self.assertEqual(
            order, [("sleep", CyberArkImportOrchestrator.DELAY), ("details", 1)],
        )

    def test_user_without_any_address_is_omitted(self):
        self.client.fetch_users.return_value = [{"id": 3, "username": "cara"}]
        self.client.fetch_user_details.return_value = {"username": "cara"}
        found = self.orch._prepare_users()
        self.assertEqual(found, [])
        self.client.fetch_user_details.assert_called_once_with(3)
        self.sleep_mock.assert_called_once_with(0.5)
        self.assertEqual(self.printed.call_args.args[0], "Found <b>0</b> CyberArk users ")

    def test_unusable_detail_payload_omits_the_user(self):
        samples = [None, [], "user", 0, {"email": "   "}]
        for details in samples:
            with self.subTest(details=details):
                self.client.fetch_users.return_value = [
                    {"id": 3, "username": "cara", "email": None},
                ]
                self.client.fetch_user_details.return_value = details
                found = self.orch._prepare_users()
                self.assertEqual(found, [])

    def test_non_dict_rows_are_skipped(self):
        self.client.fetch_users.return_value = [
            None,
            "alice",
            ["id", 1],
            5,
            {"id": 1, "username": "alice", "email": "alice@e.com"},
        ]
        found = self.orch._prepare_users()
        self.assertEqual(found, [{
            "id": 1, "username": "alice", "email": "alice@e.com",
        }])
        self.client.fetch_user_details.assert_not_called()
        self.sleep_mock.assert_not_called()
        self.assertEqual(self.printed.call_args.args[0], "Found <b>1</b> CyberArk users ")

    def test_mixed_users_keep_input_order(self):
        self.client.fetch_users.return_value = [
            {"id": 1, "username": "has-mail", "email": "a@e.com"},
            "skip-me",
            {"id": 2, "username": "needs-details"},
            {"id": 3, "username": "no-mail"},
            {"id": 4, "username": "also-has-mail", "Internet": {"HomeEmail": "d@e.com"}},
        ]
        self.client.fetch_user_details.side_effect = [
            {"email": "b@e.com"},
            {},
        ]
        found = self.orch._prepare_users()
        self.assertEqual(found, [
            {"id": 1, "username": "has-mail", "email": "a@e.com"},
            {"id": 2, "username": "needs-details", "email": "b@e.com"},
            {"id": 4, "username": "also-has-mail", "email": "d@e.com"},
        ])
        self.assertEqual(self.client.fetch_user_details.call_args_list[0].args, (2,))
        self.assertEqual(self.client.fetch_user_details.call_args_list[1].args, (3,))
        self.assertEqual(self.sleep_mock.call_count, 2)

    def test_duplicate_rows_are_not_collapsed(self):
        row = {"id": 1, "username": "alice", "email": "a@e.com"}
        self.client.fetch_users.return_value = [row, dict(row)]
        found = self.orch._prepare_users()
        self.assertEqual(found, [row, row])

    def test_id_zero_is_a_real_id(self):
        self.client.fetch_users.return_value = [{"id": 0, "username": "root"}]
        self.client.fetch_user_details.return_value = {"email": "root@e.com"}
        found = self.orch._prepare_users()
        self.assertEqual(found, [{
            "id": 0, "username": "root", "email": "root@e.com",
        }])
        self.client.fetch_user_details.assert_called_once_with(0)

    def test_missing_username_becomes_empty_string(self):
        self.client.fetch_users.return_value = [{"id": 8, "email": "a@e.com"}]
        found = self.orch._prepare_users()
        self.assertEqual(found, [{"id": 8, "username": "", "email": "a@e.com"}])

    def test_result_rows_have_only_id_username_email(self):
        self.client.fetch_users.return_value = [{
            "id": 1,
            "username": "alice",
            "email": "a@e.com",
            "userType": "EPVUser",
            "componentUser": True,
            "groupsMembership": [{"groupName": "Admins"}],
        }]
        found = self.orch._prepare_users()
        self.assertEqual(list(found[0]), ["id", "username", "email"])

    def test_component_users_are_not_filtered_here(self):
        self.client.fetch_users.return_value = [{
            "id": 9, "username": "CPM", "componentUser": True, "email": "cpm@e.com",
        }]
        found = self.orch._prepare_users()
        self.assertEqual(found, [{
            "id": 9, "username": "CPM", "email": "cpm@e.com",
        }])

    def test_list_payload_address_wins_over_details(self):
        self.client.fetch_users.return_value = [{
            "id": 1, "username": "alice", "email": "list@e.com",
        }]
        self.client.fetch_user_details.return_value = {"email": "detail@e.com"}
        found = self.orch._prepare_users()
        self.assertEqual(found, [{
            "id": 1, "username": "alice", "email": "list@e.com",
        }])
        self.client.fetch_user_details.assert_not_called()

    def test_whitespace_only_list_address_still_uses_a_later_source(self):
        self.client.fetch_users.return_value = [{
            "id": 1,
            "username": "alice",
            "internet": {"businessEmail": "   ", "homeEmail": "home@e.com"},
        }]
        found = self.orch._prepare_users()
        self.assertEqual(found, [{
            "id": 1, "username": "alice", "email": "home@e.com",
        }])
        self.client.fetch_user_details.assert_not_called()
        self.sleep_mock.assert_not_called()

    def test_address_without_id_is_kept(self):
        self.client.fetch_users.return_value = [{"username": "bob", "email": "bob@e.com"}]
        found = self.orch._prepare_users()
        self.assertEqual(found, [{
            "id": None, "username": "bob", "email": "bob@e.com",
        }])
        self.client.fetch_user_details.assert_not_called()
        self.sleep_mock.assert_not_called()

    def test_no_address_and_no_id_is_skipped_without_detail_fetch(self):
        for user_id in (None, ""):
            with self.subTest(user_id=user_id):
                self.client.fetch_users.return_value = [{"id": user_id, "username": "bob"}]
                found = self.orch._prepare_users()
                self.assertEqual(found, [])
        self.client.fetch_users.return_value = [{"username": "bob"}]
        self.assertEqual(self.orch._prepare_users(), [])
        self.client.fetch_user_details.assert_not_called()
        self.sleep_mock.assert_not_called()

    def test_tuple_of_users_is_accepted(self):
        self.client.fetch_users.return_value = (
            {"id": 1, "username": "a", "email": "a@e.com"},
        )
        found = self.orch._prepare_users()
        self.assertEqual(found, [{"id": 1, "username": "a", "email": "a@e.com"}])

    def test_dict_payload_is_not_a_user_list(self):
        self.client.fetch_users.return_value = {"id": 1, "username": "a", "email": "a@e.com"}
        found = self.orch._prepare_users()
        self.assertEqual(found, [])
        self.client.fetch_user_details.assert_not_called()
        self.sleep_mock.assert_not_called()
        self.assertEqual(self.printed.call_args.args[0], "Found <b>0</b> CyberArk users ")

    def test_none_user_list_raises(self):
        self.client.fetch_users.return_value = None
        with self.assertRaises(TypeError):
            self.orch._prepare_users()

    def test_fetch_users_error_propagates(self):
        self.client.fetch_users.side_effect = RuntimeError("pvwa down")
        with self.assertRaisesRegex(RuntimeError, "pvwa down"):
            self.orch._prepare_users()

    def test_detail_fetch_error_is_logged_and_user_omitted(self):
        error = RuntimeError("detail failed")
        self.client.fetch_users.return_value = [
            {"id": 1, "username": "ok", "email": "ok@e.com"},
            {"id": 2, "username": "bad"},
        ]
        self.client.fetch_user_details.side_effect = error
        found = self.orch._prepare_users()
        self.assertEqual(found, [{"id": 1, "username": "ok", "email": "ok@e.com"}])
        self.log_warning.assert_called_once_with(
            'Failed to fetch user with id "%s": %s', 2, error,
        )

    def test_does_not_mutate_source_rows(self):
        row = {"id": 1, "username": "alice", "email": "  a@e.com  ", "source": "CyberArk"}
        self.client.fetch_users.return_value = [row]
        self.orch._prepare_users()
        self.assertEqual(row, {
            "id": 1, "username": "alice", "email": "  a@e.com  ", "source": "CyberArk",
        })

_MODULE = "keepercommander.commands.pam_import.cyberark_import"
_CREATE_USER_COMMAND = (
    "keepercommander.commands.enterprise_create_user.CreateEnterpriseUserCommand"
)

def _enterprise_params(users):
    return SimpleNamespace(enterprise={"users": users})

class _OfflineCommandTestCase(unittest.TestCase):
    def setUp(self):
        self.command = CyberArkPAMImportCommand.__new__(CyberArkPAMImportCommand)
        patchers = {
            "query_enterprise": mock.patch(f"{_MODULE}.api.query_enterprise"),
            "create_command": mock.patch(_CREATE_USER_COMMAND),
            "log_error": mock.patch(f"{_MODULE}.logging.error"),
            "log_warning": mock.patch(f"{_MODULE}.logging.warning"),
            "printed": mock.patch("builtins.print"),
        }
        for name, patcher in patchers.items():
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

class TestLoadExistingKeeperUsers(_OfflineCommandTestCase):
    def _populate_on_query(self, users):
        def populate(params):
            params.enterprise = {"users": users}
        self.query_enterprise.side_effect = populate

    def _load(self, params):
        users, error = self.command._load_existing_keeper_users(params)
        self.assertEqual(error, "")
        return users

    def test_cached_enterprise_is_used_without_query(self):
        params = _enterprise_params([
            {"email": "alice@example.com", "status": "active"},
        ])
        found = self._load(params)
        self.assertEqual(found, [{"email": "alice@example.com", "status": "active"}])
        self.query_enterprise.assert_not_called()

    def test_missing_or_falsy_enterprise_triggers_query(self):
        samples = {
            "attribute missing": SimpleNamespace,
            "None": lambda: SimpleNamespace(enterprise=None),
            "empty dict": lambda: SimpleNamespace(enterprise={}),
            "empty list": lambda: SimpleNamespace(enterprise=[]),
            "empty string": lambda: SimpleNamespace(enterprise=""),
            "zero": lambda: SimpleNamespace(enterprise=0),
        }
        self._populate_on_query([{"email": "loaded@example.com"}])
        for label, make_params in samples.items():
            with self.subTest(enterprise=label):
                self.query_enterprise.reset_mock()
                params = make_params()
                found = self._load(params)
                self.assertEqual(found, [{"email": "loaded@example.com", "status": "active"}])
                self.query_enterprise.assert_called_once_with(params)

    def test_query_failure_returns_empty_list_and_error(self):
        for enterprise in (None, {}):
            with self.subTest(enterprise=enterprise):
                self.query_enterprise.side_effect = RuntimeError("network down")
                found = self.command._load_existing_keeper_users(
                    SimpleNamespace(enterprise=enterprise),
                )
                self.assertEqual(found, ([], "Failed to Load Existing User"))

    def test_query_that_does_not_populate_enterprise_raises(self):
        with self.assertRaises(AttributeError):
            self._load(SimpleNamespace(enterprise=None))
        self.log_error.assert_not_called()

    def test_base_exceptions_from_query_are_not_swallowed(self):
        for error in (KeyboardInterrupt, SystemExit):
            with self.subTest(error=error.__name__):
                self.query_enterprise.side_effect = error
                with self.assertRaises(error):
                    self._load(SimpleNamespace(enterprise=None))

    def test_missing_users_key_returns_empty_list(self):
        params = SimpleNamespace(enterprise={"nodes": [{"node_id": 1}]})
        self.assertEqual(self._load(params), [])
        self.query_enterprise.assert_not_called()

    def test_users_none_raises(self):
        with self.assertRaises(TypeError):
            self._load(_enterprise_params(None))

    def test_non_iterable_users_raises(self):
        for users in (5, 1.5, True):
            with self.subTest(users=users):
                with self.assertRaises(TypeError):
                    self._load(_enterprise_params(users))

    def test_non_dict_enterprise_raises(self):
        for enterprise in (["users"], "users", 1):
            with self.subTest(enterprise=enterprise):
                with self.assertRaises(AttributeError):
                    self._load(
                        SimpleNamespace(enterprise=enterprise),
                    )
        self.query_enterprise.assert_not_called()

    def test_string_or_dict_users_container_yields_no_rows(self):
        samples = ["alice@example.com", {"alice": {"email": "alice@example.com"}}]
        for users in samples:
            with self.subTest(users=type(users).__name__):
                found = self._load(_enterprise_params(users))
                self.assertEqual(found, [])

    def test_tuple_and_generator_users_are_accepted(self):
        row = {"email": "a@example.com", "status": "active"}
        for users in ((row,), (r for r in [row])):
            with self.subTest(users=type(users).__name__):
                found = self._load(_enterprise_params(users))
                self.assertEqual(found, [row])

    def test_non_dict_rows_are_skipped(self):
        class Row(dict):
            pass
        users = [
            None, "a@example.com", 1, ["a@example.com"], ("email", "a@example.com"),
            UserDict({"email": "userdict@example.com"}),
            Row(email="subclass@example.com"),
        ]
        found = self._load(_enterprise_params(users))
        self.assertEqual(found, [{"email": "subclass@example.com", "status": "active"}])

    def test_email_normalization_and_username_fallback(self):
        cases = [
            ({"email": "  A@Example.com\n"}, "A@Example.com", "trimmed, case kept"),
            ({"email": "a@example.com", "username": "other"}, "a@example.com", "email wins"),
            ({"email": None, "username": "u@example.com"}, "u@example.com", "None email"),
            ({"email": "", "username": "u"}, "u", "empty email"),
            ({"email": "   ", "username": " u "}, "u", "blank email"),
            ({"email": 0, "username": "u"}, "u", "zero email"),
            ({"email": False, "username": "u"}, "u", "False email"),
            ({"username": "u"}, "u", "missing email key"),
            ({"email": 123}, "123", "non-string email"),
            ({"email": None, "username": None}, "", "both None"),
            ({"email": "  ", "username": "  "}, "", "both blank"),
            ({}, "", "empty row"),
        ]
        for user, expected, msg in cases:
            with self.subTest(msg=msg):
                found = self._load(_enterprise_params([user]))
                self.assertEqual(found, [{"email": expected, "status": "active"}])

    def test_status_defaults_to_active_for_falsy_values(self):
        for status in (None, "", 0, False):
            with self.subTest(status=status):
                found = self._load(
                    _enterprise_params([{"email": "a@example.com", "status": status}]),
                )
                self.assertEqual(found[0]["status"], "active")
        found = self._load(
            _enterprise_params([{"email": "a@example.com"}]),
        )
        self.assertEqual(found[0]["status"], "active")

    def test_status_values_are_kept_as_is(self):
        for status in ("invited", "locked", "inactive", "ACTIVE", 1):
            with self.subTest(status=status):
                found = self._load(
                    _enterprise_params([{"email": "a@example.com", "status": status}]),
                )
                self.assertEqual(found[0]["status"], status)

    def test_rows_keep_order_duplicates_and_only_two_keys(self):
        users = [
            {"email": "b@example.com", "status": "invited", "node_id": 7, "lock": 1},
            {"email": "a@example.com"},
            {"email": "b@example.com", "status": "active"},
            {"email": "", "username": ""},
            {"username": ""},
            {"email": "   ", "username": "   "},
        ]
        found = self._load(_enterprise_params(users))
        self.assertEqual(found, [
            {"email": "b@example.com", "status": "invited"},
            {"email": "a@example.com", "status": "active"},
            {"email": "b@example.com", "status": "active"},
            {"email": "", "status": "active"},
            {"email": "", "status": "active"},
            {"email": "", "status": "active"},
        ])
        for row in found:
            self.assertEqual(list(row), ["email", "status"])

    def test_does_not_mutate_enterprise_data(self):
        users = [{"email": "  a@example.com ", "status": None, "extra": [1]}, None]
        params = _enterprise_params(users)
        snapshot = copy.deepcopy(params.enterprise)
        self._load(params)
        self.assertEqual(params.enterprise, snapshot)

    def test_value_whose_string_conversion_raises_propagates(self):
        with self.assertRaisesRegex(RuntimeError, "key stringification failed"):
            self._load(
                _enterprise_params([{"email": _BadKey()}]),
            )

class TestCreateKeeperUser(_OfflineCommandTestCase):
    EMAIL = "alice@example.com"
    def setUp(self):
        super().setUp()
        self.execute = self.create_command.return_value.execute
        self.params = object()

    def test_forwards_arguments_and_returns_result(self):
        created = {"email": self.EMAIL}
        self.execute.return_value = created
        found = self.command._create_keeper_user(self.params, self.EMAIL, "Alice")
        self.assertIs(found, created)
        self.create_command.assert_called_once_with()
        self.execute.assert_called_once_with(self.params, email=self.EMAIL, name="Alice")
        self.log_warning.assert_not_called()

    def test_new_command_instance_per_call(self):
        self.command._create_keeper_user(self.params, self.EMAIL, "Alice")
        self.command._create_keeper_user(self.params, "bob@example.com", "Bob")
        self.assertEqual(self.create_command.call_count, 2)
        self.assertEqual(self.execute.call_args_list, [
            mock.call(self.params, email=self.EMAIL, name="Alice"),
            mock.call(self.params, email="bob@example.com", name="Bob"),
        ])

    def test_falsy_results_are_returned_unchanged(self):
        for result in (None, "", {}, [], False, 0):
            with self.subTest(result=result):
                self.execute.return_value = result
                found = self.command._create_keeper_user(self.params, self.EMAIL, "Alice")
                self.assertIs(found, result)
        self.log_warning.assert_not_called()

    def test_null_and_odd_arguments_are_forwarded_unchanged(self):
        cases = [(None, None, None), ("", "", ""), (self.EMAIL, 42, None)]
        for params, email, name in cases:
            with self.subTest(email=email, name=name):
                self.execute.reset_mock()
                self.command._create_keeper_user(params, email, name)
                self.execute.assert_called_once_with(params, email=email, name=name)

    def test_execute_errors_return_none_and_log_warning(self):
        errors = [
            RuntimeError("denied"),
            CommandError("enterprise-user", "user already invited"),
            ValueError("bad email"),
            KeyError("enterprise"),
            AttributeError("no enterprise loaded"),
        ]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                self.log_warning.reset_mock()
                self.execute.side_effect = error
                found = self.command._create_keeper_user(self.params, self.EMAIL, "Alice")
                self.assertIsNone(found)
                self.log_warning.assert_called_once_with(
                    'Could not create enterprise user "%s": %s', self.EMAIL, error,
                )

    def test_constructor_error_returns_none_and_logs_warning(self):
        error = RuntimeError("cannot build command")
        self.create_command.side_effect = error
        found = self.command._create_keeper_user(self.params, self.EMAIL, "Alice")
        self.assertIsNone(found)
        self.log_warning.assert_called_once_with(
            'Could not create enterprise user "%s": %s', self.EMAIL, error,
        )

    def test_base_exceptions_propagate(self):
        for error in (KeyboardInterrupt, SystemExit):
            with self.subTest(error=error.__name__):
                self.execute.side_effect = error
                with self.assertRaises(error):
                    self.command._create_keeper_user(self.params, self.EMAIL, "Alice")

class TestCreateEnterpriseUsers(_OfflineCommandTestCase):
    def setUp(self):
        super().setUp()
        self.load_existing = mock.MagicMock(return_value=([], ""))
        self.create = mock.MagicMock(return_value={"created": True})
        self.command._load_existing_keeper_users = self.load_existing
        self.command._create_keeper_user = self.create
        self.params = object()

    def _run(self, users):
        return self.command._create_enterprise_users(self.params, users)

    def test_reports_each_flag_in_input_order(self):
        users = [
            {"username": "existing", "email": "existing@example.com"},
            {"username": "new", "email": "new@example.com"},
            {"username": "failed", "email": "failed@example.com"},
            {"username": "invalid", "email": "bad name@example.com"},
            {"email": "   "},
            {"username": "", "email": ""},
            {}
        ]
        self.load_existing.return_value = ([
            {"email": "existing@example.com", "status": "invited"},
        ], "")
        self.create.side_effect = [{"created": True}, None]
        found = self._run(users)
        self.assertEqual(found, {"users": [
            {"username": "existing", "email": "existing@example.com",
             "flag": "existing", "status": "invited"},
            {"username": "new", "email": "new@example.com", "flag": "created"},
            {"username": "failed", "email": "failed@example.com",
             "flag": "failed", "reason": "user was not created"},
            {"username": "invalid", "email": "bad name@example.com",
             "flag": "skipped", "reason": "invalid email"},
            {"username": "", "email": "", "flag": "skipped", "reason": "invalid email"},
            {"username": "", "email": "", "flag": "skipped", "reason": "invalid email"},
            {"username": "", "email": "", "flag": "skipped", "reason": "invalid email"},
        ]})
        self.load_existing.assert_called_once_with(self.params)
        self.assertEqual(self.create.call_args_list, [
            mock.call(self.params, "new@example.com", "new"),
            mock.call(self.params, "failed@example.com", "failed"),
        ])

    def test_existing_status_defaults_to_active(self):
        for existing in ({"email": "a@example.com"},
                         {"email": "a@example.com", "status": None},
                         {"email": "a@example.com", "status": ""},
                         {"email": "a@example.com", "status": 0},
                         {"email": "a@example.com", "status": False}):
            with self.subTest(existing=existing):
                self.load_existing.return_value = ([existing], "")
                found = self._run([{"username": "a", "email": "a@example.com"}])
                self.assertEqual(found["users"][0]["status"], "active")
        self.create.assert_not_called()

    def test_loader_row_without_matching_email_is_not_existing(self):
        for loaded in ([{}], [{"email": ""}], [{"email": None}], [{}, {"email": ""}]):
            with self.subTest(loaded=loaded):
                self.create.reset_mock()
                self.load_existing.return_value = (loaded, "")
                found = self._run([{"username": "a", "email": "a@example.com"}])
                self.assertEqual(found["users"][0]["flag"], "created")
                self.create.assert_called_once()

    def test_falsy_create_result_is_reported_failed(self):
        for result in (None, "", {}, [], False, 0):
            with self.subTest(result=result):
                self.create.return_value = result
                found = self._run([{"username": "a", "email": "a@example.com"}])
                self.assertEqual(found["users"], [{
                    "username": "a", "email": "a@example.com",
                    "flag": "failed", "reason": "user was not created",
                }])

    def test_invalid_addresses_are_skipped_and_valid_addresses_are_created(self):
        emails = [
            None, "", "   ", 0, False, 123, [], {},
            "example.com",
            "a@example.com",
            "a@example.COM",
            "a@sub.example.com",
            "a@example.com.evil",
            "a@notexample.com",
        ]
        users = [{"username": "u", "email": e} for e in emails] + [{"username": "no-email-key"}]
        found = self._run(users)
        self.assertEqual(
            [row["flag"] for row in found["users"]],
            ["skipped"] * 9 + ["created"] * 5 + ["skipped"],
        )
        self.load_existing.assert_called_once_with(self.params)
        self.assertEqual(self.create.call_count, 5)

    def test_invalid_address_already_in_keeper_is_reported_existing(self):
        self.load_existing.return_value = ([
            {"email": "bad name@example.com", "status": "active"},
        ], "")
        found = self._run([
            {"username": "u", "email": "bad name@example.com"},
            {"email": "bad name@example.com"},
        ])
        self.assertEqual([row["flag"] for row in found["users"]], ["existing"])
        self.create.assert_not_called()

    def test_email_is_trimmed_everywhere(self):
        for raw_email in ("  a@example.com\n", "\t a@example.com \r\n", "a@example.com "):
            with self.subTest(raw_email=repr(raw_email)):
                self.load_existing.reset_mock()
                self.create.reset_mock()
                found = self._run([{"username": "a", "email": raw_email}])
                self.load_existing.assert_called_once_with(self.params)
                self.create.assert_called_once_with(self.params, "a@example.com", "a")
                self.assertEqual(found["users"][0]["email"], "a@example.com")

    def test_missing_or_falsy_username_falls_back_to_email(self):
        email = "a@example.com"
        for user in ({"email": email}, {"email": email, "username": None},
                     {"email": email, "username": ""}, {"email": email, "username": 0},
                     {"email": email, "username": False}):
            with self.subTest(user=user):
                self.create.reset_mock()
                found = self._run([user])
                self.assertEqual(found["users"][0]["username"], "")
                self.create.assert_called_once_with(self.params, email, email)

    def test_non_string_username_is_stringified_in_report_only(self):
        for username in (42, 3.14, True, ["a"]):
            with self.subTest(username=username):
                self.create.reset_mock()
                found = self._run([{"username": username, "email": "a@example.com"}])
                self.assertEqual(found["users"][0]["username"], str(username))
                self.create.assert_called_once_with(self.params, "a@example.com", username)

    def test_empty_inputs_return_empty_report(self):
        for users in ([], (), {}, iter([]), set(), frozenset()):
            with self.subTest(users=type(users).__name__):
                self.assertEqual(self._run(users), {"users": []})
        self.assertEqual(self.load_existing.call_count, 6)

    def test_tuple_and_generator_inputs_are_accepted(self):
        row = {"username": "a", "email": "a@example.com"}
        for users in ((row,), (r for r in [row]), [row]):
            with self.subTest(users=type(users).__name__):
                self.assertEqual(self._run(users)["users"][0]["flag"], "created")

    def test_null_or_non_iterable_input_raises(self):
        for users in (None, 5, 1.5, True, False):
            with self.subTest(users=users):
                with self.assertRaises(TypeError):
                    self._run(users)

    def test_non_dict_rows_raise(self):
        for bad in (None, "a@example.com", 5, ["a@example.com"], ("email", "a@example.com"), 1.5):
            with self.subTest(row=bad):
                with self.assertRaises(AttributeError):
                    self._run([bad])

    def test_dict_payload_iterates_keys_and_raises(self):
        for payload in ({"email": "a@example.com"}, {"a": 1, "b": 2}, {"": 1}):
            with self.subTest(payload=payload):
                with self.assertRaises(AttributeError):
                    self._run(payload)

    def test_bad_row_after_good_row_aborts_without_partial_report(self):
        with self.assertRaises(AttributeError):
            self._run([{"username": "a", "email": "a@example.com"}, None])
        self.create.assert_called_once()
        self.create.reset_mock()
        with self.assertRaises(AttributeError):
            self._run([None, {"username": "a", "email": "a@example.com"}])
        self.create.assert_not_called()

    def test_duplicate_new_emails_are_created_once(self):
        row = {"username": "a", "email": "a@example.com"}
        other_username = {"username": "b", "email": " a@example.com "}
        found = self._run([row, dict(row), other_username])
        self.assertEqual([u["flag"] for u in found["users"]], ["created"])
        self.create.assert_called_once_with(self.params, "a@example.com", "a")

    def test_duplicate_failed_emails_are_attempted_once(self):
        self.create.return_value = None
        row = {"username": "a", "email": "a@example.com"}
        found = self._run([row, dict(row)])
        self.assertEqual([u["flag"] for u in found["users"]], ["failed"])
        self.create.assert_called_once()

    def test_duplicate_invalid_emails_are_each_reported(self):
        found = self._run([{"email": "bad"}, {"email": "bad"}])
        self.assertEqual([u["flag"] for u in found["users"]], ["skipped", "skipped"])

    def test_duplicate_existing_emails_are_reported_once(self):
        self.load_existing.return_value = ([{"email": "a@example.com", "status": "active"}], "")
        found = self._run([
            {"username": "a", "email": "a@example.com"},
            {"username": "b", "email": " a@example.com "},
        ])
        self.assertEqual(found["users"], [{
            "username": "a", "email": "a@example.com", "flag": "existing", "status": "active",
        }])
        self.create.assert_not_called()

    def test_loader_error_message_is_printed_and_processing_continues(self):
        self.load_existing.return_value = ([], "Failed to Load Existing User")
        found = self._run([{"username": "a", "email": "a@example.com"}])
        self.printed.assert_called_once_with("Failed to Load Existing User")
        self.assertEqual(found["users"][0]["flag"], "created")

    def test_loader_error_propagates_before_processing(self):
        for error in (RuntimeError("load failed"), ValueError("bad data"), KeyError("x")):
            with self.subTest(error=type(error).__name__):
                self.create.reset_mock()
                self.load_existing.side_effect = error
                with self.assertRaises(type(error)):
                    self._run([{"username": "a", "email": "a@example.com"}])
                self.create.assert_not_called()
        self.load_existing.side_effect = None

    def test_create_error_propagates(self):
        for error in (RuntimeError("create failed"), ValueError("bad email"), KeyError("x")):
            with self.subTest(error=type(error).__name__):
                self.create.side_effect = error
                with self.assertRaises(type(error)):
                    self._run([{"username": "a", "email": "a@example.com"}])
        self.create.side_effect = None

    def test_report_rows_have_fixed_keys(self):
        self.load_existing.return_value = ([{"email": "e@example.com", "status": "active"}], "")
        self.create.side_effect = [{"ok": 1}, None, {"created": True}]
        users = [
            {"username": "e", "email": "e@example.com", "id": 1, "source": "x"},
            {"username": "c", "email": "c@example.com", "id": 2},
            {"username": "f", "email": "f@example.com", "id": 3},
            {},
            {"email": "g@example.com", "id": 4},
        ]
        found = self._run(users)
        self.assertEqual(list(found), ["users"])
        self.assertEqual([list(r) for r in found["users"]], [
            ["username", "email", "flag", "status"],
            ["username", "email", "flag"],
            ["username", "email", "flag", "reason"],
            ["username", "email", "flag", "reason"],
            ["username", "email", "flag"],
        ])
        self.assertEqual(found["users"][3], {
            "username": "", "email": "", "flag": "skipped", "reason": "invalid email",
        })
        self.assertEqual(found["users"][4], {
            "username": "", "email": "g@example.com", "flag": "created",
        })
        self.assertEqual(self.create.call_count, 3)

    def test_does_not_mutate_input(self):
        users = [
            {"username": None, "email": "  a@example.com ", "id": 1},
            {"email": "", "extra": [1, 2]},
            {"username": "", "email": "   "},
            {},
        ]
        snapshot = copy.deepcopy(users)
        self._run(users)
        self.assertEqual(users, snapshot)

if __name__ == "__main__":
    unittest.main()