"""Strict tests for CyberArk user preparation helpers.


Value checks use ``assertEqual`` (``==``). ``assertIs`` is used only when the
test is specifically about object identity.
"""
import unittest
from collections import UserDict
from types import SimpleNamespace
from unittest import mock


from keepercommander.commands.pam_import.cyberark_import import (
    CyberArkImportOrchestrator,
    CyberArkPAMImportCommand,
)




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
        # UserDict is a Mapping, not a dict. The helper does not walk it.
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
        # str(b"email") is "b'email'", not "email".
        found = CyberArkImportOrchestrator._get_case_insensitive(
            {b"email": "a@b.com"}, "email",
        )
        self.assertIsNone(found)


    def test_lower_is_not_casefold(self):
        # "ß".lower() stays "ß"; casefold() would be "ss".
        sharp = CyberArkImportOrchestrator._get_case_insensitive({"ß": 1}, "ß")
        folded = CyberArkImportOrchestrator._get_case_insensitive({"ß": 1}, "ss")
        # Turkish capital I lowercases to "i" + combining dot, not "i".
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
            # 1. Source priority hierarchy (internet -> email -> personalDetails)
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
            # 2. Case-insensitive key lookup & value casing preservation
            (
                {"INTERNET": {"BUSINESSEMAIL": "Alice@Example.COM"}},
                "Alice@Example.COM",
                "Case-insensitive keys, preserves value case",
            ),
            # 3. Blank values fall through to next valid source
            (
                {
                    "internet": {"businessEmail": "   ", "homeEmail": 0},
                    "email": False,
                    "personalDetails": {"email": "valid@e.com"},
                },
                "valid@e.com",
                "Falsy/blank values fall through to next priority",
            ),
            # 4. Whitespace trimming behavior
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
            # 5. Non-email text formats are accepted
            (
                {"email": "not-an-email"},
                "not-an-email",
                "Does not require '@' symbol",
            ),
            # 6. Invalid structure handling & non-dict skipping
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
        self.sleep_patcher = mock.patch(
            "keepercommander.commands.pam_import.cyberark_import.sleep",
        )
        self.print_patcher = mock.patch(
            "keepercommander.commands.pam_import.cyberark_import.print_formatted_text",
        )
        self.html_patcher = mock.patch(
            "keepercommander.commands.pam_import.cyberark_import.HTML",
            side_effect=lambda text: text,
        )
        self.builtin_print_patcher = mock.patch("builtins.print")
        self.sleep_mock = self.sleep_patcher.start()
        self.printed = self.print_patcher.start()
        self.html_patcher.start()
        self.builtin_print_patcher.start()
        self.client = mock.MagicMock()
        self.client.fetch_users.return_value = []
        self.orch = _orchestrator(self.client)


    def tearDown(self):
        self.builtin_print_patcher.stop()
        self.html_patcher.stop()
        self.print_patcher.stop()
        self.sleep_patcher.stop()


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


    def test_missing_username_is_preserved_as_none(self):
        self.client.fetch_users.return_value = [{"id": 8, "email": "a@e.com"}]
        found = self.orch._prepare_users()
        self.assertEqual(found, [{"id": 8, "username": None, "email": "a@e.com"}])


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


    def test_tuple_of_users_is_accepted(self):
        self.client.fetch_users.return_value = (
            {"id": 1, "username": "a", "email": "a@e.com"},
        )
        found = self.orch._prepare_users()
        self.assertEqual(found, [{"id": 1, "username": "a", "email": "a@e.com"}])


    def test_dict_payload_is_not_a_user_list(self):
        # Iterating a dict yields keys. Those strings are not user records.
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


    def test_detail_fetch_error_propagates(self):
        self.client.fetch_users.return_value = [
            {"id": 1, "username": "ok", "email": "ok@e.com"},
            {"id": 2, "username": "bad"},
        ]
        self.client.fetch_user_details.side_effect = RuntimeError("detail failed")
        with self.assertRaisesRegex(RuntimeError, "detail failed"):
            self.orch._prepare_users()


    def test_does_not_mutate_source_rows(self):
        row = {"id": 1, "username": "alice", "email": "  a@e.com  ", "source": "CyberArk"}
        self.client.fetch_users.return_value = [row]
        self.orch._prepare_users()
        self.assertEqual(row, {
            "id": 1, "username": "alice", "email": "  a@e.com  ", "source": "CyberArk",
        })




class TestLoadExistingKeeperUsers(unittest.TestCase):
    def setUp(self):
        self.command = CyberArkPAMImportCommand.__new__(CyberArkPAMImportCommand)


    @mock.patch(
        "keepercommander.commands.pam_import.cyberark_import.api.query_enterprise",
    )
    def test_uses_preloaded_enterprise_and_normalizes_rows(self, query_enterprise):
        params = SimpleNamespace(enterprise={"users": [
            {"email": "  alice@example.com  ", "status": "invited"},
            {"email": "", "username": "  bob@example.com  ", "status": ""},
            {"username": "cara@example.com"},
            "not-a-user",
            None,
        ]})


        found = self.command._load_existing_keeper_users(params)


        self.assertEqual(found, [
            {"email": "alice@example.com", "status": "invited"},
            {"email": "bob@example.com", "status": "active"},
            {"email": "cara@example.com", "status": "active"},
        ])
        query_enterprise.assert_not_called()


    @mock.patch(
        "keepercommander.commands.pam_import.cyberark_import.api.query_enterprise",
    )
    def test_queries_enterprise_when_cache_is_missing(self, query_enterprise):
        params = SimpleNamespace(enterprise=None)


        def populate_enterprise(arg):
            self.assertIs(arg, params)
            arg.enterprise = {
                "users": [{"email": "loaded@example.com", "status": "active"}],
            }


        query_enterprise.side_effect = populate_enterprise


        found = self.command._load_existing_keeper_users(params)


        self.assertEqual(found, [
            {"email": "loaded@example.com", "status": "active"},
        ])
        query_enterprise.assert_called_once_with(params)


    @mock.patch(
        "keepercommander.commands.pam_import.cyberark_import.api.query_enterprise",
    )
    def test_empty_preloaded_enterprise_is_refreshed(self, query_enterprise):
        params = SimpleNamespace(enterprise={})
        query_enterprise.side_effect = lambda arg: setattr(
            arg, "enterprise", {"users": []},
        )


        self.assertEqual(self.command._load_existing_keeper_users(params), [])
        query_enterprise.assert_called_once_with(params)




class TestCheckExistingKeeperUser(unittest.TestCase):
    def setUp(self):
        self.command = CyberArkPAMImportCommand.__new__(CyberArkPAMImportCommand)
        self.command._load_existing_keeper_users = mock.MagicMock(return_value=[
            {"email": "alice@example.com", "status": "active"},
            {"email": "Bob@example.com", "status": "invited"},
        ])


    @mock.patch("builtins.print")
    def test_returns_exact_email_match(self, printed):
        params = object()


        found = self.command.check_exisitng_user(params, "Bob@example.com")


        self.assertEqual(found, {
            "email": "Bob@example.com", "status": "invited",
        })
        self.command._load_existing_keeper_users.assert_called_once_with(params)
        self.assertEqual(printed.call_count, 2)


    @mock.patch("builtins.print")
    def test_returns_none_when_email_is_absent_or_case_differs(self, printed):
        self.assertIsNone(
            self.command.check_exisitng_user(object(), "bob@example.com"),
        )
        self.assertEqual(printed.call_count, 2)




class TestCreateKeeperUser(unittest.TestCase):
    def setUp(self):
        self.command = CyberArkPAMImportCommand.__new__(CyberArkPAMImportCommand)


    @mock.patch(
        "keepercommander.commands.enterprise_create_user.CreateEnterpriseUserCommand",
    )
    def test_executes_create_command_and_returns_result(self, create_command):
        params = object()
        created_user = {"email": "alice@norvaledynamics.com"}
        create_command.return_value.execute.return_value = created_user


        found = self.command._create_keeper_user(
            params, "alice@norvaledynamics.com", "Alice",
        )


        self.assertIs(found, created_user)
        create_command.assert_called_once_with()
        create_command.return_value.execute.assert_called_once_with(
            params, email="alice@norvaledynamics.com", name="Alice",
        )


    @mock.patch(
        "keepercommander.commands.pam_import.cyberark_import.logging.warning",
    )
    @mock.patch(
        "keepercommander.commands.enterprise_create_user.CreateEnterpriseUserCommand",
    )
    def test_returns_none_and_logs_when_creation_fails(
        self, create_command, warning,
    ):
        create_command.return_value.execute.side_effect = RuntimeError("denied")


        found = self.command._create_keeper_user(
            object(), "alice@norvaledynamics.com", "Alice",
        )


        self.assertIsNone(found)
        warning.assert_called_once_with(
            'Could not create enterprise user "%s": %s',
            "alice@norvaledynamics.com",
            create_command.return_value.execute.side_effect,
        )




class TestCreateEnterpriseUsers(unittest.TestCase):
    def setUp(self):
        self.command = CyberArkPAMImportCommand.__new__(CyberArkPAMImportCommand)
        self.command.check_exisitng_user = mock.MagicMock()
        self.command._create_keeper_user = mock.MagicMock()
        self.params = object()


    def test_reports_existing_created_failed_and_invalid_users(self):
        users = [
            {"username": "existing", "email": "existing@norvaledynamics.com"},
            {"username": "new", "email": "new@norvaledynamics.com"},
            {"username": "failed", "email": "failed@norvaledynamics.com"},
            {"username": "invalid", "email": "bad name@norvaledynamics.com"},
        ]
        self.command.check_exisitng_user.side_effect = [
            {"email": users[0]["email"], "status": "invited"},
            None,
            None,
            None,
        ]
        self.command._create_keeper_user.side_effect = [
            {"email": users[1]["email"]},
            None,
        ]


        found = self.command._create_enterprise_users(self.params, users)


        self.assertEqual(found, {"users": [
            {
                "username": "existing",
                "email": "existing@norvaledynamics.com",
                "flag": "existing",
                "status": "invited",
            },
            {
                "username": "new",
                "email": "new@norvaledynamics.com",
                "flag": "created",
            },
            {
                "username": "failed",
                "email": "failed@norvaledynamics.com",
                "flag": "failed",
                "reason": "user was not created",
            },
            {
                "username": "invalid",
                "email": "bad name@norvaledynamics.com",
                "flag": "skipped",
                "reason": "invalid email",
            },
        ]})
        self.assertEqual(self.command.check_exisitng_user.call_count, 4)
        self.assertEqual(self.command._create_keeper_user.call_args_list, [
            mock.call(self.params, "new@norvaledynamics.com", "new"),
            mock.call(self.params, "failed@norvaledynamics.com", "failed"),
        ])


    def test_ignores_blank_foreign_and_case_mismatched_domains(self):
        users = [
            {"username": "blank", "email": ""},
            {"username": "foreign", "email": "user@example.com"},
            {"username": "upper", "email": "user@NORVALEDYNAMICS.COM"},
            {"username": "missing"},
        ]


        found = self.command._create_enterprise_users(self.params, users)


        self.assertEqual(found, {"users": []})
        self.command.check_exisitng_user.assert_not_called()
        self.command._create_keeper_user.assert_not_called()


    def test_trims_email_and_uses_it_when_username_is_missing(self):
        self.command.check_exisitng_user.return_value = None
        self.command._create_keeper_user.return_value = {"created": True}


        found = self.command._create_enterprise_users(self.params, [{
            "email": "  alice@norvaledynamics.com  ",
        }])


        self.assertEqual(found, {"users": [{
            "username": "",
            "email": "alice@norvaledynamics.com",
            "flag": "created",
        }]})
        self.command._create_keeper_user.assert_called_once_with(
            self.params,
            "alice@norvaledynamics.com",
            "alice@norvaledynamics.com",
        )


    def test_existing_user_without_status_defaults_to_active(self):
        self.command.check_exisitng_user.return_value = {
            "email": "alice@norvaledynamics.com",
        }


        found = self.command._create_enterprise_users(self.params, [{
            "username": "alice",
            "email": "alice@norvaledynamics.com",
        }])


        self.assertEqual(found["users"][0]["status"], "active")
        self.command._create_keeper_user.assert_not_called()


    def test_empty_input_returns_empty_report(self):
        self.assertEqual(
            self.command._create_enterprise_users(self.params, []),
            {"users": []},
        )
        self.command.check_exisitng_user.assert_not_called()
        self.command._create_keeper_user.assert_not_called()




if __name__ == "__main__":
    unittest.main()
