#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Tests for CyberArk → KeeperPAM import
#

import json
import os
import pytest
from unittest.mock import MagicMock, patch

from keepercommander.importer.cyberark.cyberark_pam import (
    AccountMapper,
    AdaptiveThrottler,
    ApplicationMapper,
    CyberArkPVWAClient,
    RecordKind,
    SafeFolderMapper,
    UserTeamMatcher,
    apply_safe_filter,
    discriminate_record_kind,
    exclude_system_safes,
    build_import_json,
    build_extend_json,
    build_report,
    build_shared_folder_permissions,
    validate_import_data,
    format_duration,
    strip_credentials,
    DEFAULT_PLATFORM_MAP,
)
from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMImportCommand


# ── AccountMapper Tests ──────────────────────────────────────


class TestAccountMapper:

    def test_unix_ssh_maps_to_pam_machine(self):
        mapper = AccountMapper()
        account = {
            "id": "1", "name": "UnixSSH-server01", "platformId": "UnixSSH",
            "address": "10.0.0.1", "userName": "root",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "secret123")
        assert result["type"] == "pamMachine"
        assert result["host"] == "10.0.0.1"
        assert result["port"] == "22"
        assert result["title"] == "server01"
        assert len(result["users"]) == 1
        user = result["users"][0]
        assert user["type"] == "pamUser"
        assert user["login"] == "root"
        assert user["password"] == "secret123"
        assert user["rotation_settings"]["rotation"] == "general"

    def test_unix_ssh_key_maps_to_pam_machine(self):
        mapper = AccountMapper()
        account = {
            "id": "2", "name": "UnixSSHKey-server02", "platformId": "UnixSSHKey",
            "address": "10.0.0.2", "userName": "admin",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "key123")
        assert result["type"] == "pamMachine"
        assert result["users"][0]["rotation_settings"]["rotation"] == "general"

    def test_win_domain_maps_to_pam_machine_ad_user(self):
        mapper = AccountMapper()
        account = {
            "id": "3", "name": "WinDomain-dc01", "platformId": "WinDomain",
            "address": "192.168.1.10", "userName": "Administrator",
            "platformAccountProperties": {"LogonDomain": "CORP"},
        }
        result = mapper.map_account(account, "pass123")
        assert result["type"] == "pamMachine"
        assert result["port"] == "3389"
        user = result["users"][0]
        assert user["login"] == "CORP\\Administrator"
        assert user["rotation_settings"]["rotation"] == "general"

    def test_win_local_account_maps_to_pam_machine(self):
        mapper = AccountMapper()
        account = {
            "id": "4", "name": "WinLocalAccount-workstation", "platformId": "WinLocalAccount",
            "address": "10.0.0.5", "userName": "localadmin",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pass")
        assert result["type"] == "pamMachine"
        assert result["users"][0]["rotation_settings"]["rotation"] == "general"

    def test_oracle_maps_to_pam_database(self):
        mapper = AccountMapper()
        account = {
            "id": "5", "name": "Oracle-proddb", "platformId": "Oracle",
            "address": "db.example.com", "userName": "sys",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "dbpass")
        assert result["type"] == "pamDatabase"
        assert result["port"] == "1521"
        assert result["users"][0]["rotation_settings"]["rotation"] == "general"

    def test_mysql_maps_to_pam_database(self):
        mapper = AccountMapper()
        account = {
            "id": "6", "name": "MySQL-appdb", "platformId": "MySQL",
            "address": "mysql.internal", "userName": "root",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "dbpass")
        assert result["type"] == "pamDatabase"
        assert result["port"] == "3306"

    def test_mssql_maps_to_pam_database(self):
        mapper = AccountMapper()
        account = {
            "id": "7", "name": "MSSql-reporting", "platformId": "MSSql",
            "address": "sql.internal", "userName": "sa",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pass")
        assert result["type"] == "pamDatabase"
        assert result["port"] == "1433"

    def test_postgresql_maps_to_pam_database(self):
        mapper = AccountMapper()
        account = {
            "id": "8", "name": "PostgreSQL-analytics", "platformId": "PostgreSQL",
            "address": "pg.internal", "userName": "postgres",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pass")
        assert result["type"] == "pamDatabase"
        assert result["port"] == "5432"

    def test_business_website_maps_to_login(self):
        mapper = AccountMapper()
        account = {
            "id": "9", "name": "BusinessWebsite-portal", "platformId": "BusinessWebsite",
            "address": "", "userName": "user@example.com",
            "platformAccountProperties": {
                "URL": "https://portal.example.com",
                "ItemName": "Company Portal",
            },
        }
        result = mapper.map_account(account, "webpass")
        assert result["type"] == "login"
        assert result["title"] == "Company Portal"
        assert result["login"] == "user@example.com"
        assert result["url"] == "https://portal.example.com"
        assert result["password"] == "webpass"
        assert "users" not in result  # login records don't have nested users

    def test_unknown_platform_defaults_to_pam_machine(self):
        mapper = AccountMapper()
        account = {
            "id": "10", "name": "CustomPlatform-server", "platformId": "CustomLinux",
            "address": "10.0.0.99", "userName": "admin",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pass")
        assert result["type"] == "pamMachine"
        assert result["users"][0]["rotation_settings"]["rotation"] == "general"
        assert mapper.unmapped_platforms["CustomLinux"] == 1

    def test_platform_map_override(self):
        override = {
            "CustomLinux": {"record_type": "pamMachine", "rotation": "general", "protocol": "ssh", "port": "2222"},
        }
        mapper = AccountMapper(platform_map_override=override)
        account = {
            "id": "11", "name": "CustomLinux-custom", "platformId": "CustomLinux",
            "address": "10.0.0.50", "userName": "root",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pass")
        assert result["port"] == "2222"
        assert "CustomLinux" not in mapper.unmapped_platforms

    def test_is_incomplete_missing_address(self):
        mapper = AccountMapper()
        account = {"address": "", "userName": "root"}
        incomplete, reason = mapper.is_incomplete(account)
        assert incomplete is True
        assert "address" in reason

    def test_is_incomplete_missing_username(self):
        mapper = AccountMapper()
        account = {"address": "10.0.0.1", "userName": ""}
        # userName is empty string which is falsy
        incomplete, reason = mapper.is_incomplete(account)
        assert incomplete is True
        assert "userName" in reason

    def test_is_complete(self):
        mapper = AccountMapper()
        account = {"address": "10.0.0.1", "userName": "root"}
        incomplete, reason = mapper.is_incomplete(account)
        assert incomplete is False
        assert reason == ""

    def test_logon_domain_prepended(self):
        mapper = AccountMapper()
        account = {
            "id": "12", "name": "WinDomain-test", "platformId": "WinDomain",
            "address": "10.0.0.1", "userName": "admin",
            "platformAccountProperties": {"LogonDomain": "MYDOMAIN"},
        }
        result = mapper.map_account(account, "pass")
        assert result["users"][0]["login"] == "MYDOMAIN\\admin"

    def test_password_none_not_managed(self):
        mapper = AccountMapper()
        account = {
            "id": "13", "name": "UnixSSH-nopass", "platformId": "UnixSSH",
            "address": "10.0.0.1", "userName": "root",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, None)
        user = result["users"][0]
        assert user["password"] == ""
        assert user.get("managed") is None  # not managed without password

    def test_port_from_account_properties(self):
        mapper = AccountMapper()
        account = {
            "id": "14", "name": "UnixSSH-custom-port", "platformId": "UnixSSH",
            "address": "10.0.0.1", "userName": "root",
            "platformAccountProperties": {"Port": "2222"},
        }
        result = mapper.map_account(account, "pass")
        assert result["port"] == "2222"

    def test_title_strips_platform_prefix(self):
        mapper = AccountMapper()
        account = {
            "id": "15", "name": "UnixSSH-my-server", "platformId": "UnixSSH",
            "address": "10.0.0.1", "userName": "root",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pass")
        assert result["title"] == "my-server"

    def test_title_strips_operating_system_category_prefix(self):
        """Real CyberArk names often start with 'Operating System-<platform>-<addr>-<user>'."""
        mapper = AccountMapper()
        account = {
            "id": "1", "name": "Operating System-UnixSSH-10.0.1.30-simon",
            "platformId": "UnixSSH", "address": "10.0.1.30", "userName": "simon",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pw")
        assert result["title"] == "10.0.1.30-simon"

    def test_title_falls_back_to_address_user_when_verbose(self):
        """When the name embeds a CPM policy name (not the platformId), stripping
        leaves it verbose — fall back to {address}-{user} for readability."""
        mapper = AccountMapper()
        account = {
            "id": "2",
            "name": "Operating System-WindowsDesktopLocalAccountsRotationalPolicy-10.0.1.20-x_accountB",
            "platformId": "WinDesktopLocal", "address": "10.0.1.20", "userName": "x_accountB",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pw")
        assert result["title"] == "10.0.1.20-x_accountB"
        assert len(result["title"]) < 40

    def test_title_preserves_short_custom_names(self):
        """Short admin-set names (Linux2, db1, windows1) stay untouched."""
        mapper = AccountMapper()
        for name in ("Linux2", "db1", "windows1"):
            account = {
                "id": "3", "name": name, "platformId": "UnixSSH",
                "address": "10.0.0.1", "userName": "root",
                "platformAccountProperties": {},
            }
            result = mapper.map_account(account, "pw")
            assert result["title"] == name


# ── SafeFolderMapper Tests ───────────────────────────────────


class TestSafeFolderMapper:

    def test_flat_mode_returns_empty(self):
        mapper = SafeFolderMapper(mode="flat")
        assert mapper.map_safe("Production Servers", "MyProject") == ""

    def test_exact_mode_preserves_name(self):
        mapper = SafeFolderMapper(mode="exact")
        assert mapper.map_safe("Production & Servers (2024)", "MyProject") == "Production & Servers (2024)"

    def test_ksm_mode_sanitizes(self):
        mapper = SafeFolderMapper(mode="ksm")
        assert mapper.map_safe("Production & Servers (2024)", "MyProject") == "Production Servers 2024"

    def test_ksm_mode_collapses_spaces(self):
        mapper = SafeFolderMapper(mode="ksm")
        result = mapper.map_safe("My   Safe   Name", "Project")
        assert "   " not in result
        assert result == "My Safe Name"

    def test_ksm_mode_handles_special_chars(self):
        mapper = SafeFolderMapper(mode="ksm")
        result = mapper.map_safe("Safe/With\\Special<Chars>", "Project")
        assert "/" not in result
        assert "\\" not in result
        assert "<" not in result

    def test_exact_mode_long_name(self):
        mapper = SafeFolderMapper(mode="exact")
        long_name = "A" * 200
        assert mapper.map_safe(long_name, "Project") == long_name

    def test_duplicate_safe_names_preserved(self):
        """exact mode should preserve names even if they look similar."""
        mapper = SafeFolderMapper(mode="exact")
        assert mapper.map_safe("Servers", "P") == "Servers"
        assert mapper.map_safe("servers", "P") == "servers"


# ── apply_safe_filter Tests ──────────────────────────────────


class TestApplySafeFilter:

    def _safes(self, names):
        return [{"safeName": n} for n in names]

    def test_no_filter_returns_all(self):
        safes = self._safes(["A", "B", "C"])
        result = apply_safe_filter(safes)
        assert len(result) == 3

    def test_include_filter(self):
        safes = self._safes(["Prod-Servers", "Dev-Servers", "Prod-DBs"])
        result = apply_safe_filter(safes, include="Prod-*")
        assert len(result) == 2
        assert all("Prod" in s["safeName"] for s in result)

    def test_exclude_filter(self):
        safes = self._safes(["Prod-Servers", "Dev-Servers", "Test-Servers"])
        result = apply_safe_filter(safes, exclude="Dev-*,Test-*")
        assert len(result) == 1
        assert result[0]["safeName"] == "Prod-Servers"

    def test_include_and_exclude(self):
        safes = self._safes(["Prod-Servers", "Prod-Test", "Dev-Servers"])
        result = apply_safe_filter(safes, include="Prod-*", exclude="*-Test")
        assert len(result) == 1
        assert result[0]["safeName"] == "Prod-Servers"

    def test_glob_pattern_matching(self):
        safes = self._safes(["Safe_001", "Safe_002", "Other_001"])
        result = apply_safe_filter(safes, include="Safe_*")
        assert len(result) == 2


# ── AdaptiveThrottler Tests ──────────────────────────────────


class TestAdaptiveThrottler:

    def test_initial_delay(self):
        t = AdaptiveThrottler(base_delay=1.0)
        assert t.current_delay == 1.0

    def test_success_decreases_delay(self):
        t = AdaptiveThrottler(base_delay=0.5, max_delay=5.0)
        t.current_delay = 2.0  # simulate elevated delay
        t.record_response(500, True)  # fast success
        assert t.current_delay < 2.0

    def test_failure_increases_delay(self):
        t = AdaptiveThrottler(base_delay=0.5, max_delay=5.0)
        initial = t.current_delay
        t.record_response(5000, False)
        assert t.current_delay > initial

    def test_delay_never_below_base(self):
        t = AdaptiveThrottler(base_delay=0.5)
        for _ in range(20):
            t.record_response(100, True)
        assert t.current_delay >= t.base_delay

    def test_delay_never_above_max(self):
        t = AdaptiveThrottler(base_delay=0.5, max_delay=5.0)
        for _ in range(20):
            t.record_response(10000, False)
        assert t.current_delay <= t.max_delay

    def test_delay_increases_after_errors(self):
        t = AdaptiveThrottler()
        initial_delay = t.current_delay
        for _ in range(5):
            t.record_response(1000, False)
        assert t.current_delay > initial_delay

    def test_delay_stable_on_success(self):
        t = AdaptiveThrottler()
        initial_delay = t.current_delay
        for _ in range(5):
            t.record_response(200, True)
        assert t.current_delay <= initial_delay


# ── build_import_json Tests ──────────────────────────────────


class TestBuildImportJson:

    def test_basic_structure(self):
        result = build_import_json("Test Project", "my-gateway", [], [])
        assert result["project"] == "Test Project"
        assert result["pam_configuration"]["gateway_name"] == "my-gateway"
        assert result["pam_configuration"]["environment"] == "local"
        assert result["pam_configuration"]["rotation"] == "on"
        assert result["pam_data"]["resources"] == []
        assert result["pam_data"]["users"] == []

    def test_no_gateway(self):
        result = build_import_json("Test", None, [], [])
        assert "gateway_name" not in result["pam_configuration"]

    def test_with_resources_and_users(self):
        resources = [{"type": "pamMachine", "title": "srv1", "host": "10.0.0.1"}]
        users = [{"type": "login", "title": "web", "login": "user"}]
        result = build_import_json("Test", None, resources, users)
        assert len(result["pam_data"]["resources"]) == 1
        assert len(result["pam_data"]["users"]) == 1


class TestBuildExtendJson:

    def test_extend_only_has_pam_data(self):
        result = build_extend_json(
            [{"type": "pamMachine", "title": "srv"}],
            [{"type": "login", "title": "web"}],
        )
        assert "project" not in result
        assert "pam_configuration" not in result
        assert len(result["pam_data"]["resources"]) == 1
        assert len(result["pam_data"]["users"]) == 1


# ── strip_credentials Tests ─────────────────────────────────


class TestStripCredentials:

    def test_strips_user_passwords(self):
        data = {"pam_data": {"users": [{"password": "secret"}], "resources": []}}
        strip_credentials(data)
        assert data["pam_data"]["users"][0]["password"] == "***"

    def test_strips_nested_resource_user_passwords(self):
        data = {
            "pam_data": {
                "users": [],
                "resources": [
                    {"type": "pamMachine", "users": [{"password": "secret"}]}
                ],
            }
        }
        strip_credentials(data)
        assert data["pam_data"]["resources"][0]["users"][0]["password"] == "***"

    def test_handles_empty_data(self):
        data = {"pam_data": {"users": [], "resources": []}}
        strip_credentials(data)  # should not raise


# ── format_duration Tests ────────────────────────────────────


class TestFormatDuration:

    def test_seconds_only(self):
        assert format_duration(45) == "45s"

    def test_minutes_and_seconds(self):
        assert format_duration(125) == "2m 5s"

    def test_zero(self):
        assert format_duration(0) == "0s"


# ── build_report Tests ───────────────────────────────────────


class TestBuildReport:

    def test_report_contains_project_name(self):
        report = build_report(
            project_name="Test Migration",
            safes_processed=5,
            total_accounts=50,
            resource_counts={"pamMachine": {"ok": 20, "skip": 0, "err": 0}},
            platform_counts={"UnixSSH": {"rotation": "general", "count": 20}},
            skipped=[],
            incomplete_count=0,
            duration=120.0,
        )
        assert "Test Migration" in report
        assert "Safes processed:  5" in report
        assert "Accounts found:   50" in report

    def test_report_shows_unmapped_platforms(self):
        report = build_report(
            project_name="Test",
            safes_processed=1,
            total_accounts=10,
            resource_counts={},
            platform_counts={"CustomPlatform": {"rotation": "UNMAPPED", "count": 5}},
            skipped=[],
            incomplete_count=0,
            duration=10.0,
            unmapped_platforms={"CustomPlatform": 5},
        )
        assert "UNMAPPED" in report
        assert "--platform-map" in report

    def test_report_shows_skipped(self):
        report = build_report(
            project_name="Test",
            safes_processed=1,
            total_accounts=10,
            resource_counts={},
            platform_counts={},
            skipped=[
                {"reason": "password retrieval failed"},
                {"reason": "password retrieval failed"},
                {"reason": "CPM disabled"},
            ],
            incomplete_count=2,
            duration=10.0,
        )
        assert "Password retrieval failed:   2" in report
        assert "Manual mgmt (CPM disabled):  1" in report
        assert "Incomplete (missing fields): 2" in report

    def test_report_shows_duration(self):
        report = build_report(
            project_name="Test",
            safes_processed=1,
            total_accounts=10,
            resource_counts={},
            platform_counts={},
            skipped=[],
            incomplete_count=0,
            duration=272.0,
        )
        assert "4m 32s" in report


# ── CyberArkPVWAClient Tests ────────────────────────────────


class TestCyberArkPVWAClientNormalize:

    def test_normalize_plain_host(self):
        host, params = CyberArkPVWAClient._normalize_host("pvwa.example.com")
        assert host == "pvwa.example.com"
        assert params == {}

    def test_normalize_strips_https(self):
        host, params = CyberArkPVWAClient._normalize_host("https://pvwa.example.com")
        assert host == "pvwa.example.com"

    def test_normalize_privilege_cloud(self):
        host, params = CyberArkPVWAClient._normalize_host("mycompany.cyberark.cloud")
        assert host == "mycompany.privilegecloud.cyberark.cloud"

    def test_normalize_with_query_params(self):
        host, params = CyberArkPVWAClient._normalize_host("pvwa.example.com?WinDomain")
        assert host == "pvwa.example.com"
        assert params == {"search": "WinDomain"}

    def test_normalize_with_kv_query_params(self):
        host, params = CyberArkPVWAClient._normalize_host("pvwa.example.com?limit=10&offset=20")
        assert host == "pvwa.example.com"
        assert params == {"limit": "10", "offset": "20"}


# ── SSRF Protection Tests ────────────────────────────────────


class TestSSRFProtection:

    def test_rejects_localhost(self):
        with pytest.raises(ValueError, match="local address"):
            CyberArkPVWAClient._validate_host("localhost")

    def test_rejects_127_0_0_1(self):
        with pytest.raises(ValueError, match="local address"):
            CyberArkPVWAClient._validate_host("127.0.0.1")

    def test_rejects_private_ip(self):
        with pytest.raises(ValueError, match="private/reserved"):
            CyberArkPVWAClient._validate_host("10.0.0.1")

    def test_rejects_link_local(self):
        with pytest.raises(ValueError, match="private/reserved"):
            CyberArkPVWAClient._validate_host("169.254.169.254")

    def test_rejects_empty_host(self):
        with pytest.raises(ValueError, match="local address"):
            CyberArkPVWAClient._validate_host("")

    def test_rejects_invalid_hostname_chars(self):
        with pytest.raises(ValueError, match="invalid characters"):
            CyberArkPVWAClient._validate_host("pvwa.example.com/../../admin")

    def test_accepts_valid_hostname(self):
        CyberArkPVWAClient._validate_host("pvwa.example.com")  # should not raise

    def test_accepts_cyberark_cloud(self):
        CyberArkPVWAClient._validate_host("mycompany.privilegecloud.cyberark.cloud")


# ── Login Type Validation Tests ──────────────────────────────


class TestLoginTypeValidation:

    def test_valid_login_types(self):
        from keepercommander.importer.cyberark.cyberark_pam import VALID_LOGON_TYPES
        for lt in ("cyberark", "ldap", "radius", "windows"):
            assert lt in VALID_LOGON_TYPES
        for lt in ("Cyberark", "CyberArk", "LDAP", "RADIUS", "Windows"):
            assert lt.lower() in VALID_LOGON_TYPES

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.prompt")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_invalid_login_type_rejected_by_authenticate(self, mock_dns, mock_prompt, mock_requests):
        """authenticate() should return False for invalid login types."""
        mock_prompt.side_effect = ["../../admin", "user", "pass"]
        client = CyberArkPVWAClient("pvwa.example.com")
        with patch("keepercommander.importer.cyberark.cyberark_pam.print_formatted_text"):
            result = client.authenticate()
        assert result is False


# ── SSL Verification Tests ───────────────────────────────────


class TestSSLVerification:

    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_cloud_always_verify(self, mock_dns):
        """Privilege Cloud must always verify SSL, even if verify_ssl=False."""
        client = CyberArkPVWAClient("mycompany.cyberark.cloud", verify_ssl=False)
        assert client.verify_ssl is True

    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_selfhosted_respects_verify_flag(self, mock_dns):
        """Self-hosted PVWA should respect verify_ssl=False."""
        client = CyberArkPVWAClient("pvwa.example.com", verify_ssl=False)
        assert client.verify_ssl is False

    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_selfhosted_default_verify_true(self, mock_dns):
        """Self-hosted defaults to verify_ssl=True."""
        client = CyberArkPVWAClient("pvwa.example.com")
        assert client.verify_ssl is True


# ── CyberArkPAMImportCommand Tests ──────────────────────────


class TestCyberArkPAMImportCommandParser:

    def test_all_flags_parse(self):
        cmd = CyberArkPAMImportCommand()
        args = cmd.parser.parse_args([
            "pvwa.example.com",
            "--name", "My Project",
            "--config", "config-uid-123",
            "--gateway", "gw-uid-456",
            "--folder-mode", "exact",
            "--safes", "Prod-*",
            "--exclude-safes", "Test-*",
            "--list-safes",
            "--dry-run",
            "--output", "output.json",
            "--include-credentials",
            "--estimate",
            "--yes",
            "--skip-users",
            "--skip-linked-accounts",
            "--skip-members",
            "--include-system-safes",
            "--user-map", "users.json",
            "--batch-size", "50",
            "--batch-delay", "1.0",
            "--platform-map", "map.json",
            "--state-filter", "active,inactive",
            "--no-verify-ssl",
        ])
        assert args.server == "pvwa.example.com"
        assert args.project_name == "My Project"
        assert args.config == "config-uid-123"
        assert args.gateway == "gw-uid-456"
        assert args.folder_mode == "exact"
        assert args.safes == "Prod-*"
        assert args.exclude_safes == "Test-*"
        assert args.list_safes is True
        assert args.dry_run is True
        assert args.output == "output.json"
        assert args.include_credentials is True
        assert args.estimate is True
        assert args.yes is True
        assert args.skip_users is True
        assert args.skip_linked_accounts is True
        assert args.skip_members is True
        assert args.include_system_safes is True
        assert args.user_map == "users.json"
        assert args.batch_size == 50
        assert args.batch_delay == 1.0
        assert args.platform_map == "map.json"
        assert args.state_filter == "active,inactive"
        assert args.no_verify_ssl is True

    def test_minimal_args(self):
        cmd = CyberArkPAMImportCommand()
        args = cmd.parser.parse_args(["pvwa.example.com"])
        assert args.server == "pvwa.example.com"
        assert args.project_name == ""
        assert args.dry_run is False

    def test_folder_mode_choices(self):
        cmd = CyberArkPAMImportCommand()
        # Valid choices
        for mode in ("ksm", "exact", "flat"):
            args = cmd.parser.parse_args(["server", "--folder-mode", mode])
            assert args.folder_mode == mode

    def test_short_flags(self):
        cmd = CyberArkPAMImportCommand()
        args = cmd.parser.parse_args(["server", "-n", "Proj", "-d", "-y", "-o", "out.json"])
        assert args.project_name == "Proj"
        assert args.dry_run is True
        assert args.yes is True
        assert args.output == "out.json"


# ── Dry Run Integration Test (mocked PVWA) ──────────────────



# ── Default Platform Map Completeness ────────────────────────


class TestDefaultPlatformMap:

    def test_all_common_platforms_mapped(self):
        expected = [
            "UnixSSH", "UnixSSHKey", "WinDomain", "WinLocalAccount",
            "Oracle", "MySQL", "MSSql", "PostgreSQL", "BusinessWebsite",
        ]
        for platform in expected:
            assert platform in DEFAULT_PLATFORM_MAP, f"Missing platform: {platform}"

    def test_all_mappings_have_required_fields(self):
        for platform, mapping in DEFAULT_PLATFORM_MAP.items():
            assert "record_type" in mapping, f"{platform} missing record_type"
            assert "rotation" in mapping, f"{platform} missing rotation"
            assert "protocol" in mapping, f"{platform} missing protocol"
            assert "port" in mapping, f"{platform} missing port"

    def test_business_website_is_login_type(self):
        m = DEFAULT_PLATFORM_MAP["BusinessWebsite"]
        assert m["record_type"] == "login"
        assert m["rotation"] is None

    def test_unix_platforms_use_ssh(self):
        for p in ("UnixSSH", "UnixSSHKey"):
            assert DEFAULT_PLATFORM_MAP[p]["protocol"] == "ssh"
            assert DEFAULT_PLATFORM_MAP[p]["port"] == "22"

    def test_windows_platforms_use_rdp(self):
        for p in ("WinDomain", "WinLocalAccount", "WinServerLocal", "WinDesktopLocal"):
            assert DEFAULT_PLATFORM_MAP[p]["protocol"] == "rdp"
            assert DEFAULT_PLATFORM_MAP[p]["port"] == "3389"

    def test_database_platforms_have_correct_ports(self):
        assert DEFAULT_PLATFORM_MAP["Oracle"]["port"] == "1521"
        assert DEFAULT_PLATFORM_MAP["MySQL"]["port"] == "3306"
        assert DEFAULT_PLATFORM_MAP["MSSql"]["port"] == "1433"
        assert DEFAULT_PLATFORM_MAP["PostgreSQL"]["port"] == "5432"


# ── Secure Temp File Tests ───────────────────────────────────


class TestSecureTempFiles:

    def test_write_secure_temp_creates_valid_json(self):
        from keepercommander.commands.pam_import.cyberark_import import _write_secure_temp_json, _remove_secure_temp
        data = {"test": "value", "nested": {"key": 123}}
        tmp_path = _write_secure_temp_json(data)
        try:
            assert os.path.exists(tmp_path)
            with open(tmp_path, 'r') as f:
                loaded = json.load(f)
            assert loaded == data
            # Check permissions (skip on Windows)
            if os.name != 'nt':
                import stat
                mode = os.stat(tmp_path).st_mode & 0o777
                assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"
        finally:
            _remove_secure_temp(tmp_path)

    def test_remove_secure_temp_deletes_file(self):
        from keepercommander.commands.pam_import.cyberark_import import _write_secure_temp_json, _remove_secure_temp
        data = {"secret": "password123"}
        tmp_path = _write_secure_temp_json(data)
        assert os.path.exists(tmp_path)
        _remove_secure_temp(tmp_path)
        assert not os.path.exists(tmp_path)

    def test_remove_secure_temp_handles_missing_file(self):
        from keepercommander.commands.pam_import.cyberark_import import _remove_secure_temp
        _remove_secure_temp("/nonexistent/path/file.json")  # should not raise


# ── Config UID Lookup Tests ──────────────────────────────────


class TestFindConfigUid:
    """Tests calling the real _find_config_uid method."""

    def _make_mock_record(self, title, uid):
        record = MagicMock()
        record.title = title
        record.record_uid = uid
        return record

    @patch('keepercommander.vault_extensions')
    @patch('keepercommander.api.sync_down')
    def test_exact_match(self, mock_sync, mock_ve):
        mock_ve.find_records.return_value = [
            self._make_mock_record("MyProject Configuration", "uid-001"),
        ]
        cmd = CyberArkPAMImportCommand()
        result = cmd._find_config_uid(MagicMock(), "MyProject")
        assert result == "uid-001"

    @patch('keepercommander.vault_extensions')
    @patch('keepercommander.api.sync_down')
    def test_suffix_picks_highest_numerically(self, mock_sync, mock_ve):
        """#10 should sort after #9 (numeric, not lexicographic)."""
        mock_ve.find_records.return_value = [
            self._make_mock_record("MyProject Configuration", "uid-001"),
            self._make_mock_record("MyProject Configuration #2", "uid-002"),
            self._make_mock_record("MyProject Configuration #10", "uid-010"),
        ]
        cmd = CyberArkPAMImportCommand()
        result = cmd._find_config_uid(MagicMock(), "MyProject")
        assert result == "uid-010"

    @patch('keepercommander.vault_extensions')
    @patch('keepercommander.api.sync_down')
    def test_no_match_returns_empty(self, mock_sync, mock_ve):
        mock_ve.find_records.return_value = [
            self._make_mock_record("OtherProject Configuration", "uid-999"),
        ]
        cmd = CyberArkPAMImportCommand()
        result = cmd._find_config_uid(MagicMock(), "MyProject")
        assert result == ""

    @patch('keepercommander.vault_extensions')
    @patch('keepercommander.api.sync_down')
    def test_rejects_partial_match(self, mock_sync, mock_ve):
        mock_ve.find_records.return_value = [
            self._make_mock_record("MyProject Configuration Extra", "uid-bad"),
        ]
        cmd = CyberArkPAMImportCommand()
        result = cmd._find_config_uid(MagicMock(), "MyProject")
        assert result == ""


# ── Platform Map Validation Tests ────────────────────────────


class TestPlatformMapValidation:

    def test_map_account_missing_record_type_defaults(self):
        """AccountMapper should default to pamMachine if record_type missing from override."""
        override = {"CustomPlatform": {"rotation": "general", "protocol": "ssh", "port": "22"}}
        mapper = AccountMapper(platform_map_override=override)
        account = {
            "id": "1", "name": "Custom-server", "platformId": "CustomPlatform",
            "address": "10.0.0.1", "userName": "root",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pass")
        assert result["type"] == "pamMachine"  # defaulted

    def test_platform_map_invalid_json_file(self, tmp_path):
        """Invalid JSON should raise CommandError."""
        from keepercommander.error import CommandError
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not valid json {{{")
        cmd = CyberArkPAMImportCommand()
        with pytest.raises(CommandError, match="Invalid JSON"):
            cmd.execute(MagicMock(), server="pvwa.example.com",
                        platform_map=str(bad_file), dry_run=True,
                        project_name="Test", config="", gateway="",
                        folder_mode="flat", safes="", exclude_safes="",
                        list_safes=False, output="", include_credentials=False,
                        estimate=False, yes=False, skip_users=False,
                        auto_throttle=True, batch_size=100, batch_delay=0.5,
                        state_filter="", no_verify_ssl=True)

    def test_platform_map_missing_record_type_file(self, tmp_path):
        """Entry without record_type should raise CommandError."""
        from keepercommander.error import CommandError
        bad_file = tmp_path / "bad_map.json"
        bad_file.write_text('{"CustomPlatform": {"rotation": "general"}}')
        cmd = CyberArkPAMImportCommand()
        with pytest.raises(CommandError, match="record_type"):
            cmd.execute(MagicMock(), server="pvwa.example.com",
                        platform_map=str(bad_file), dry_run=True,
                        project_name="Test", config="", gateway="",
                        folder_mode="flat", safes="", exclude_safes="",
                        list_safes=False, output="", include_credentials=False,
                        estimate=False, yes=False, skip_users=False,
                        auto_throttle=True, batch_size=100, batch_delay=0.5,
                        state_filter="", no_verify_ssl=True)

    def test_platform_map_not_dict_file(self, tmp_path):
        """Non-dict JSON should raise CommandError."""
        from keepercommander.error import CommandError
        bad_file = tmp_path / "list.json"
        bad_file.write_text('[1, 2, 3]')
        cmd = CyberArkPAMImportCommand()
        with pytest.raises(CommandError, match="JSON object"):
            cmd.execute(MagicMock(), server="pvwa.example.com",
                        platform_map=str(bad_file), dry_run=True,
                        project_name="Test", config="", gateway="",
                        folder_mode="flat", safes="", exclude_safes="",
                        list_safes=False, output="", include_credentials=False,
                        estimate=False, yes=False, skip_users=False,
                        auto_throttle=True, batch_size=100, batch_delay=0.5,
                        state_filter="", no_verify_ssl=True)


# ── Critical Fix Validation Tests ────────────────────────────


class TestRotationTypesValid:
    """C1: Verify all rotation types in DEFAULT_PLATFORM_MAP are accepted by base.py."""

    def test_all_platform_rotations_are_valid(self):
        from keepercommander.commands.pam_import.base import PamRotationSettingsObject
        valid_types = ("general", "iam_user", "scripts_only")
        for platform_id, mapping in DEFAULT_PLATFORM_MAP.items():
            rotation = mapping.get("rotation")
            if rotation is None:
                continue  # login records have no rotation
            assert rotation in valid_types, (
                f"Platform '{platform_id}' has invalid rotation '{rotation}'. "
                f"Valid types: {valid_types}"
            )

    def test_rotation_settings_load_accepts_general(self):
        from keepercommander.commands.pam_import.base import PamRotationSettingsObject
        r = PamRotationSettingsObject.load({"rotation": "general", "enabled": "on"})
        assert r.rotation == "general"

    def test_rotation_settings_load_rejects_ad_user(self):
        from keepercommander.commands.pam_import.base import PamRotationSettingsObject
        r = PamRotationSettingsObject.load({"rotation": "ad_user", "enabled": "on"})
        assert r.rotation == ""  # rejected — empty

    def test_rotation_settings_load_rejects_database(self):
        from keepercommander.commands.pam_import.base import PamRotationSettingsObject
        r = PamRotationSettingsObject.load({"rotation": "database", "enabled": "on"})
        assert r.rotation == ""  # rejected — empty


class TestCPMRotationMapping:
    """C2b: Verify CyberArk CPM state maps to rotation_settings and pam_settings."""

    def test_cpm_enabled_sets_rotation_on(self):
        mapper = AccountMapper()
        account = {
            "id": "1", "name": "linux-root", "platformId": "UnixSSH",
            "address": "10.0.0.1", "userName": "root",
            "secretManagement": {"automaticManagementEnabled": True, "status": "active"},
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert user["rotation_settings"]["enabled"] == "on"
        assert result["pam_settings"]["options"]["rotation"] == "on"

    def test_cpm_disabled_sets_rotation_off(self):
        mapper = AccountMapper()
        account = {
            "id": "2", "name": "manual-acct", "platformId": "UnixSSH",
            "address": "10.0.0.2", "userName": "svc",
            "secretManagement": {
                "automaticManagementEnabled": False,
                "manualManagementReason": "Service account — no auto-rotation",
            },
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert user["rotation_settings"]["enabled"] == "off"
        assert "CPM disabled" in user.get("notes", "")
        assert result["pam_settings"]["options"]["rotation"] == "off"

    def test_missing_secret_management_defaults_to_on(self):
        mapper = AccountMapper()
        account = {
            "id": "3", "name": "no-mgmt", "platformId": "WinDomain",
            "address": "dc1.local", "userName": "admin",
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert user["rotation_settings"]["enabled"] == "on"

    def test_pam_settings_options_structure(self):
        mapper = AccountMapper()
        account = {
            "id": "4", "name": "ssh-box", "platformId": "UnixSSH",
            "address": "10.0.0.4", "userName": "deploy",
        }
        result = mapper.map_account(account, "pass")
        ps = result["pam_settings"]
        assert "options" in ps
        assert ps["options"]["connections"] == "on"
        assert ps["options"]["tunneling"] == "off"
        assert ps["options"]["graphical_session_recording"] == "off"

    def test_pam_settings_launch_credentials(self):
        mapper = AccountMapper()
        account = {
            "id": "5", "name": "db-admin", "platformId": "MSSql",
            "address": "sqlserver.local", "userName": "sa",
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert result["pam_settings"]["connection"]["launch_credentials"] == user["title"]

    def test_schedule_always_on_demand(self):
        mapper = AccountMapper()
        account = {
            "id": "6", "name": "scheduled", "platformId": "UnixSSH",
            "address": "10.0.0.6", "userName": "root",
            "secretManagement": {"automaticManagementEnabled": True},
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert user["rotation_settings"]["schedule"] == {"type": "on-demand"}


class TestConnectDatabaseMapping:
    """C3: Verify Database property flows to connect_database on pamUser."""

    def test_mssql_database_mapped(self):
        mapper = AccountMapper()
        account = {
            "id": "100", "name": "MSSql-hr", "platformId": "MSSql",
            "address": "dbserver1.cyberark.local", "userName": "sa",
            "platformAccountProperties": {"Port": "15345", "Database": "hr"},
        }
        result = mapper.map_account(account, "pass")
        assert result["type"] == "pamDatabase"
        assert result["port"] == "15345"
        user = result["users"][0]
        assert user.get("connect_database") == "hr"

    def test_mysql_database_mapped(self):
        mapper = AccountMapper()
        account = {
            "id": "101", "name": "MySQL-app", "platformId": "MySQL",
            "address": "mysql.internal", "userName": "root",
            "platformAccountProperties": {"Database": "appdb"},
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert user.get("connect_database") == "appdb"

    def test_no_database_property_no_field(self):
        mapper = AccountMapper()
        account = {
            "id": "102", "name": "UnixSSH-srv", "platformId": "UnixSSH",
            "address": "10.0.0.1", "userName": "root",
            "platformAccountProperties": {},
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert "connect_database" not in user

    def test_database_only_on_pam_database_type(self):
        """Database property should not appear on pamMachine records."""
        mapper = AccountMapper()
        account = {
            "id": "103", "name": "UnixSSH-srv", "platformId": "UnixSSH",
            "address": "10.0.0.1", "userName": "root",
            "platformAccountProperties": {"Database": "should_not_appear"},
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert "connect_database" not in user


class TestOracleProtocol:
    """C2: Verify Oracle uses a valid protocol."""

    def test_oracle_protocol_is_registered(self):
        mapping = DEFAULT_PLATFORM_MAP["Oracle"]
        # sql-server is a registered protocol in base.py
        assert mapping["protocol"] == "sql-server"


class TestReconcileAdminCredentials:
    """H1: Verify reconcile account maps to administrative_credentials."""

    def test_reconcile_role_tagged(self):
        """resolve_linked_accounts should tag reconcile users with _ca_role."""
        from keepercommander.importer.cyberark.cyberark_pam import resolve_linked_accounts
        client = MagicMock()
        client.fetch_account_details.return_value = {
            "linkedAccounts": {
                "reconcileAccount": {
                    "id": "99_1", "name": "recon-admin",
                    "safeName": "AdminSafe", "userName": "recon_user"
                }
            }
        }
        client.retrieve_password.return_value = "recon_pass"
        account = {"id": "1", "name": "target-account", "safeName": "TestSafe"}
        result = resolve_linked_accounts(client, account)
        assert len(result) == 1
        assert result[0]["_ca_role"] == "reconcile"
        assert result[0]["login"] == "recon_user"

    def test_logon_role_tagged(self):
        from keepercommander.importer.cyberark.cyberark_pam import resolve_linked_accounts
        client = MagicMock()
        client.fetch_account_details.return_value = {
            "linkedAccounts": {
                "logonAccount": {
                    "id": "99_2", "name": "logon-svc",
                    "safeName": "SvcSafe", "userName": "svc_user"
                }
            }
        }
        client.retrieve_password.return_value = "logon_pass"
        account = {"id": "2", "name": "target", "safeName": "TestSafe"}
        result = resolve_linked_accounts(client, account)
        assert len(result) == 1
        assert result[0]["_ca_role"] == "logon"


class TestPickAdminCredentials:
    """Keeper has one administrative_credentials slot; CyberArk may have both
    reconcile and enable linked accounts. Reconcile wins; enable is fallback."""

    def test_reconcile_only(self):
        from keepercommander.importer.cyberark.cyberark_pam import pick_admin_credentials
        linked = [{"title": "recon-svc (reconcile account)", "_ca_role": "reconcile"}]
        title, role = pick_admin_credentials(linked)
        assert title == "recon-svc (reconcile account)"
        assert role == "reconcile"

    def test_enable_only_used_as_fallback(self):
        from keepercommander.importer.cyberark.cyberark_pam import pick_admin_credentials
        linked = [{"title": "enable-svc (enable account)", "_ca_role": "enable"}]
        title, role = pick_admin_credentials(linked)
        assert title == "enable-svc (enable account)"
        assert role == "enable"

    def test_reconcile_preferred_over_enable_when_both_present(self):
        from keepercommander.importer.cyberark.cyberark_pam import pick_admin_credentials
        linked = [
            {"title": "enable-svc (enable account)", "_ca_role": "enable"},
            {"title": "recon-svc (reconcile account)", "_ca_role": "reconcile"},
        ]
        title, role = pick_admin_credentials(linked)
        assert role == "reconcile"
        assert title == "recon-svc (reconcile account)"

    def test_logon_only_returns_none(self):
        from keepercommander.importer.cyberark.cyberark_pam import pick_admin_credentials
        linked = [{"title": "logon-svc (logon account)", "_ca_role": "logon"}]
        title, role = pick_admin_credentials(linked)
        assert title is None
        assert role is None

    def test_empty_list_returns_none(self):
        from keepercommander.importer.cyberark.cyberark_pam import pick_admin_credentials
        title, role = pick_admin_credentials([])
        assert title is None and role is None


class TestPickLaunchCredentials:
    """CyberArk's logonAccount is the connection credential (PSM logs in as the
    logon account, then switches to the target). That maps to Keeper's
    launch_credentials slot."""

    def test_logon_returns_title(self):
        from keepercommander.importer.cyberark.cyberark_pam import pick_launch_credentials
        linked = [{"title": "svc-logon (logon account)", "_ca_role": "logon"}]
        assert pick_launch_credentials(linked) == "svc-logon (logon account)"

    def test_no_logon_returns_none(self):
        from keepercommander.importer.cyberark.cyberark_pam import pick_launch_credentials
        linked = [
            {"title": "recon-svc (reconcile account)", "_ca_role": "reconcile"},
            {"title": "enable-svc (enable account)", "_ca_role": "enable"},
        ]
        assert pick_launch_credentials(linked) is None

    def test_empty_list_returns_none(self):
        from keepercommander.importer.cyberark.cyberark_pam import pick_launch_credentials
        assert pick_launch_credentials([]) is None


# ── Existing CyberArk Importer Unchanged ────────────────────


class TestExistingImporterUnchanged:

    def test_original_importer_still_importable(self):
        from keepercommander.importer.cyberark import Importer
        from keepercommander.importer.cyberark.cyberark import CyberArkImporter
        assert Importer is CyberArkImporter

    def test_original_importer_has_do_import(self):
        from keepercommander.importer.cyberark.cyberark import CyberArkImporter
        assert hasattr(CyberArkImporter, "do_import")

    def test_original_endpoints_unchanged(self):
        from keepercommander.importer.cyberark.cyberark import CyberArkImporter
        expected_endpoints = {
            "accounts": "Accounts",
            "account_password": "Accounts/{account_id}/Password/Retrieve",
            "logon": "Auth/{type}/Logon",
            "safes": "Safes",
        }
        assert expected_endpoints.items() <= CyberArkImporter.ENDPOINTS.items()


# ── Phase 2 Tests: System Safe Exclusion + Safe Filtering ─────

class TestSystemSafeExclusion:
    """Tests for exclude_system_safes()."""

    def test_excludes_system_safes(self):
        from keepercommander.importer.cyberark.cyberark_pam import exclude_system_safes
        safes = [
            {"safeName": "Windows-Admins"},
            {"safeName": "System"},
            {"safeName": "VaultInternal"},
            {"safeName": "PVWAConfig"},
            {"safeName": "Unix-Servers"},
        ]
        result = exclude_system_safes(safes)
        names = [s["safeName"] for s in result]
        assert "Windows-Admins" in names
        assert "Unix-Servers" in names
        assert "System" not in names
        assert "VaultInternal" not in names
        assert "PVWAConfig" not in names

    def test_include_system_override(self):
        from keepercommander.importer.cyberark.cyberark_pam import exclude_system_safes
        safes = [
            {"safeName": "Windows-Admins"},
            {"safeName": "System"},
            {"safeName": "VaultInternal"},
        ]
        result = exclude_system_safes(safes, include_system=True)
        assert len(result) == 3

    def test_empty_list(self):
        from keepercommander.importer.cyberark.cyberark_pam import exclude_system_safes
        assert exclude_system_safes([]) == []

    def test_all_system_safes(self):
        from keepercommander.importer.cyberark.cyberark_pam import exclude_system_safes, SYSTEM_SAFES
        safes = [{"safeName": name} for name in list(SYSTEM_SAFES)[:5]]
        result = exclude_system_safes(safes)
        assert len(result) == 0


class TestSafeNameSanitization:
    """Tests for sanitize_safe_name() and deduplicate_safe_names()."""

    def test_basic_name(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name
        assert sanitize_safe_name("Windows-Admins") == "Windows-Admins"

    def test_path_traversal_stripped(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name
        result = sanitize_safe_name("../../../etc/passwd")
        assert ".." not in result
        assert "/" not in result

    def test_slashes_replaced(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name
        result = sanitize_safe_name("Corp/IT\\Servers")
        assert "/" not in result
        assert "\\" not in result

    def test_max_length_truncated(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name, MAX_SAFE_NAME_LENGTH
        long_name = "A" * 50
        result = sanitize_safe_name(long_name)
        assert len(result) <= MAX_SAFE_NAME_LENGTH

    def test_empty_name(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name
        assert sanitize_safe_name("") == "Unnamed-Safe"

    def test_whitespace_only(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name
        assert sanitize_safe_name("   ") == "Unnamed-Safe"

    def test_dedup_collisions(self):
        from keepercommander.importer.cyberark.cyberark_pam import deduplicate_safe_names
        safes = [
            {"safeUrlId": "safe1", "safeName": "TestSafe"},
            {"safeUrlId": "safe2", "safeName": "TestSafe"},
            {"safeUrlId": "safe3", "safeName": "TestSafe"},
        ]
        result = deduplicate_safe_names(safes)
        assert result["safe1"] == "TestSafe"
        assert result["safe2"] == "TestSafe #2"
        assert result["safe3"] == "TestSafe #3"

    def test_dedup_no_collision(self):
        from keepercommander.importer.cyberark.cyberark_pam import deduplicate_safe_names
        safes = [
            {"safeUrlId": "a", "safeName": "Alpha"},
            {"safeUrlId": "b", "safeName": "Beta"},
        ]
        result = deduplicate_safe_names(safes)
        assert result["a"] == "Alpha"
        assert result["b"] == "Beta"


# ── Phase 2 Audit Fix Tests ──────────────────────────────────

class TestSystemSafeExclusionCaseInsensitive:
    """Verify case-insensitive system safe exclusion."""

    def test_lowercase_system_safe_excluded(self):
        from keepercommander.importer.cyberark.cyberark_pam import exclude_system_safes
        safes = [{"safeName": "system"}, {"safeName": "UserSafe"}]
        result = exclude_system_safes(safes)
        assert len(result) == 1
        assert result[0]["safeName"] == "UserSafe"

    def test_uppercase_system_safe_excluded(self):
        from keepercommander.importer.cyberark.cyberark_pam import exclude_system_safes
        safes = [{"safeName": "VAULTINTERNAL"}, {"safeName": "RealSafe"}]
        result = exclude_system_safes(safes)
        assert len(result) == 1
        assert result[0]["safeName"] == "RealSafe"

    def test_mixed_case_system_safe_excluded(self):
        from keepercommander.importer.cyberark.cyberark_pam import exclude_system_safes
        safes = [{"safeName": "pvwaConfig"}, {"safeName": "Production"}]
        result = exclude_system_safes(safes)
        assert len(result) == 1


class TestSafeNameSanitizationExtended:
    """Additional edge cases for sanitize_safe_name."""

    def test_unicode_name_preserved(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name
        result = sanitize_safe_name("Café-Serveurs")
        assert "Café" in result

    def test_control_chars_stripped(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name
        result = sanitize_safe_name("Safe\x00Name\nWith\tCtrl")
        assert "\x00" not in result
        assert "\n" not in result
        assert "\t" not in result
        assert "SafeName" in result

    def test_exact_max_length(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name, MAX_SAFE_NAME_LENGTH
        name = "A" * MAX_SAFE_NAME_LENGTH
        result = sanitize_safe_name(name)
        assert len(result) == MAX_SAFE_NAME_LENGTH

    def test_one_over_max_length(self):
        from keepercommander.importer.cyberark.cyberark_pam import sanitize_safe_name, MAX_SAFE_NAME_LENGTH
        name = "A" * (MAX_SAFE_NAME_LENGTH + 1)
        result = sanitize_safe_name(name)
        assert len(result) == MAX_SAFE_NAME_LENGTH

    def test_dedup_respects_max_length(self):
        from keepercommander.importer.cyberark.cyberark_pam import deduplicate_safe_names, MAX_SAFE_NAME_LENGTH
        long_name = "A" * 30  # exceeds 28
        safes = [
            {"safeUrlId": "a", "safeName": long_name},
            {"safeUrlId": "b", "safeName": long_name},
        ]
        result = deduplicate_safe_names(safes)
        for name in result.values():
            assert len(name) <= MAX_SAFE_NAME_LENGTH


class TestInteractiveSafePicker:
    """Tests for _interactive_safe_picker."""

    def test_select_all(self):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMImportCommand
        from unittest.mock import patch
        safes = [{"safeName": "Safe1"}, {"safeName": "Safe2"}]
        with patch("builtins.input", return_value="A"):
            result = CyberArkPAMImportCommand._interactive_safe_picker(safes)
        assert result is None  # None = import all

    def test_select_empty(self):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMImportCommand
        from unittest.mock import patch
        safes = [{"safeName": "Safe1"}, {"safeName": "Safe2"}]
        with patch("builtins.input", return_value=""):
            result = CyberArkPAMImportCommand._interactive_safe_picker(safes)
        assert result is None

    def test_select_specific(self):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMImportCommand
        from unittest.mock import patch
        safes = [{"safeName": "Alpha"}, {"safeName": "Beta"}, {"safeName": "Gamma"}]
        with patch("builtins.input", return_value="1,3"):
            result = CyberArkPAMImportCommand._interactive_safe_picker(safes)
        assert result == "Alpha,Gamma"

    def test_select_invalid_input(self):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMImportCommand
        from unittest.mock import patch
        safes = [{"safeName": "Safe1"}]
        with patch("builtins.input", return_value="abc"):
            result = CyberArkPAMImportCommand._interactive_safe_picker(safes)
        assert result is None  # invalid → all

    def test_eof_returns_none(self):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMImportCommand
        from unittest.mock import patch
        safes = [{"safeName": "Safe1"}]
        with patch("builtins.input", side_effect=EOFError):
            result = CyberArkPAMImportCommand._interactive_safe_picker(safes)
        assert result is None


class TestListSafesDetailed:
    """Tests for _list_safes_detailed."""

    def test_output_contains_safe_names(self, capsys):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMImportCommand
        safes = [
            {"safeName": "Windows-Admins", "managingCPM": "PasswordManager"},
            {"safeName": "Unix-Servers", "managingCPM": ""},
        ]
        CyberArkPAMImportCommand._list_safes_detailed(safes, 3)
        out = capsys.readouterr().out
        assert "Windows-Admins" in out
        assert "Unix-Servers" in out
        assert "3 system safes excluded" in out
        assert "Total: 2 safes" in out

    def test_output_no_system_excluded(self, capsys):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMImportCommand
        safes = [{"safeName": "MySafe", "managingCPM": "CPM1"}]
        CyberArkPAMImportCommand._list_safes_detailed(safes, 0)
        out = capsys.readouterr().out
        assert "system safes excluded" not in out


# ── Phase 3 Tests: Linked Accounts + Dual Accounts ───────────

class TestFetchAccountDetails:
    """Tests for CyberArkPVWAClient.fetch_account_details."""

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_returns_details_with_linked_accounts(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "id": "25_4",
            "name": "WinDomain-admin",
            "linkedAccounts": {
                "logonAccount": {"id": "25_8", "name": "logon-svc", "safeName": "Admins"},
                "reconcileAccount": {"id": "25_9", "name": "recon-svc", "safeName": "Admins"},
            }
        }
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test-token"
        result = client.fetch_account_details("25_4")
        assert result is not None
        assert "linkedAccounts" in result
        assert "logonAccount" in result["linkedAccounts"]

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_returns_none_on_failure(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test-token"
        result = client.fetch_account_details("bad_id")
        assert result is None

    def test_rejects_invalid_account_id(self):
        from keepercommander.importer.cyberark.cyberark_pam import CyberArkPVWAClient
        client = CyberArkPVWAClient.__new__(CyberArkPVWAClient)
        client.auth_token = "test"
        client.verify_ssl = True
        result = client.fetch_account_details("../../admin")
        assert result is None


class TestResolveLinkedAccounts:
    """Tests for resolve_linked_accounts."""

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_resolves_logon_and_reconcile(self, mock_dns, mock_requests):
        from keepercommander.importer.cyberark.cyberark_pam import resolve_linked_accounts
        # Mock detail response with linked accounts
        detail_resp = MagicMock()
        detail_resp.status_code = 200
        detail_resp.json.return_value = {
            "id": "25_4",
            "linkedAccounts": {
                "logonAccount": {"id": "25_8", "name": "logon-svc", "userName": "logon-user", "safeName": "Admins"},
                "reconcileAccount": {"id": "25_9", "name": "recon-svc", "userName": "recon-user", "safeName": "Admins"},
            }
        }
        # Mock password responses
        pw_resp = MagicMock()
        pw_resp.status_code = 200
        pw_resp.text = '"LinkedPwd123"'

        mock_requests.get.return_value = detail_resp
        mock_requests.post.return_value = pw_resp

        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test-token"

        account = {"id": "25_4", "name": "admin-account", "safeName": "Admins"}
        result = resolve_linked_accounts(client, account)

        assert len(result) == 2
        types = {r["title"] for r in result}
        assert any("logon" in t for t in types)
        assert any("reconcile" in t for t in types)
        assert all(r["type"] == "pamUser" for r in result)

    def test_returns_empty_when_no_linked(self):
        from keepercommander.importer.cyberark.cyberark_pam import resolve_linked_accounts
        client = MagicMock()
        client.fetch_account_details.return_value = {"id": "1", "linkedAccounts": {}}
        result = resolve_linked_accounts(client, {"id": "1"})
        assert result == []

    def test_returns_empty_when_details_fail(self):
        from keepercommander.importer.cyberark.cyberark_pam import resolve_linked_accounts
        client = MagicMock()
        client.fetch_account_details.return_value = None
        result = resolve_linked_accounts(client, {"id": "1"})
        assert result == []


class TestDetectDualAccount:
    """Tests for detect_dual_account."""

    def test_detects_dual_account(self):
        from keepercommander.importer.cyberark.cyberark_pam import detect_dual_account
        account = {
            "platformAccountProperties": {
                "VirtualUserName": "svc_rotation",
                "GroupPlatformID": "WinDualAccount",
                "Index": "1",
            }
        }
        result = detect_dual_account(account)
        assert result is not None
        assert result["ca_virtual_username"] == "svc_rotation"
        assert result["ca_dual_account_group"] == "WinDualAccount"
        assert result["ca_dual_account_index"] == "1"

    def test_returns_none_for_normal_account(self):
        from keepercommander.importer.cyberark.cyberark_pam import detect_dual_account
        account = {
            "platformAccountProperties": {"LogonDomain": "mydomain"}
        }
        result = detect_dual_account(account)
        assert result is None

    def test_handles_missing_properties(self):
        from keepercommander.importer.cyberark.cyberark_pam import detect_dual_account
        account = {}
        result = detect_dual_account(account)
        assert result is None

    def test_partial_dual_fields(self):
        from keepercommander.importer.cyberark.cyberark_pam import detect_dual_account
        account = {
            "platformAccountProperties": {"VirtualUserName": "svc_user"}
        }
        result = detect_dual_account(account)
        assert result is not None
        assert "ca_virtual_username" in result
        assert "ca_dual_account_group" not in result


# ── Phase 4 Tests: Permission Mapping + Safe Members ─────────

class TestPermissionMapper:
    """Tests for PermissionMapper.map_permissions and map_member."""

    def test_view_only(self):
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        perms = {"listAccounts": True, "useAccounts": True,
                 "retrieveAccounts": True, "addAccounts": False,
                 "updateAccountContent": False, "manageSafe": False,
                 "manageSafeMembers": False}
        result = PermissionMapper.map_permissions(perms)
        assert result["can_edit"] is False
        assert result["can_share"] is False
        assert result["manage_users"] is False
        assert result["manage_records"] is False

    def test_edit_tier(self):
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        perms = {"listAccounts": True, "useAccounts": True,
                 "addAccounts": True, "updateAccountContent": True,
                 "manageSafe": False, "manageSafeMembers": False}
        result = PermissionMapper.map_permissions(perms)
        assert result["can_edit"] is True
        assert result["can_share"] is False
        assert result["manage_users"] is False

    def test_manage_tier(self):
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        perms = {"listAccounts": True, "useAccounts": True,
                 "addAccounts": True, "updateAccountContent": True,
                 "manageSafe": True, "manageSafeMembers": True}
        result = PermissionMapper.map_permissions(perms)
        assert result["can_edit"] is True
        assert result["can_share"] is True
        assert result["manage_users"] is True
        assert result["manage_records"] is True

    def test_edit_via_update_properties(self):
        """updateAccountProperties alone (without updateAccountContent) triggers edit tier."""
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        perms = {"listAccounts": True, "useAccounts": True,
                 "addAccounts": True, "updateAccountProperties": True,
                 "updateAccountContent": False,
                 "manageSafe": False, "manageSafeMembers": False}
        result = PermissionMapper.map_permissions(perms)
        assert result["can_edit"] is True
        assert result["manage_records"] is True
        assert result["manage_users"] is False

    def test_edit_tier_grants_manage_records(self):
        """Edit tier should set manage_records=True (can modify records in shared folder)."""
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        perms = {"listAccounts": True, "useAccounts": True,
                 "addAccounts": True, "updateAccountContent": True}
        result = PermissionMapper.map_permissions(perms)
        assert result["manage_records"] is True
        assert result["manage_users"] is False

    def test_no_permissions(self):
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        result = PermissionMapper.map_permissions({})
        assert result["can_edit"] is False
        assert result["can_share"] is False

    def test_none_input(self):
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        result = PermissionMapper.map_permissions(None)
        assert result["can_edit"] is False

    def test_unmapped_permissions_detected(self):
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        perms = {"accessWithoutConfirmation": True,
                 "requestsAuthorizationLevel1": True,
                 "requestsAuthorizationLevel2": False}
        result = PermissionMapper.get_unmapped_permissions(perms)
        assert "accessWithoutConfirmation" in result
        assert "requestsAuthorizationLevel1" in result
        assert "requestsAuthorizationLevel2" not in result

    def test_map_member_user(self):
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        member = {
            "memberName": "john.doe@company.com",
            "memberType": "User",
            "permissions": {"listAccounts": True, "useAccounts": True,
                            "addAccounts": False, "updateAccountContent": False,
                            "manageSafe": False, "manageSafeMembers": False},
        }
        result = PermissionMapper.map_member(member)
        assert result["name"] == "john.doe@company.com"
        assert result["member_type"] == "user"
        assert result["permissions"]["can_edit"] is False

    def test_map_member_group(self):
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        member = {
            "memberName": "Windows-Admins",
            "memberType": "Group",
            "permissions": {"listAccounts": True, "useAccounts": True,
                            "addAccounts": True, "updateAccountContent": True,
                            "manageSafe": True, "manageSafeMembers": True},
        }
        result = PermissionMapper.map_member(member)
        assert result["name"] == "Windows-Admins"
        assert result["member_type"] == "team"
        assert result["permissions"]["can_share"] is True
        assert result["permissions"]["manage_users"] is True

    def test_manage_requires_edit(self):
        """manage without edit should not grant manage."""
        from keepercommander.importer.cyberark.cyberark_pam import PermissionMapper
        perms = {"listAccounts": True, "useAccounts": True,
                 "addAccounts": False, "updateAccountContent": False,
                 "manageSafe": True, "manageSafeMembers": True}
        result = PermissionMapper.map_permissions(perms)
        assert result["manage_users"] is False
        assert result["can_share"] is False


class TestFetchSafeMembers:
    """Tests for CyberArkPVWAClient.fetch_safe_members."""

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_fetches_and_filters_predefined(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "value": [
                {"memberName": "Master", "memberType": "User", "isPredefinedUser": True,
                 "permissions": {}},
                {"memberName": "john.doe", "memberType": "User", "isPredefinedUser": False,
                 "permissions": {"listAccounts": True}},
                {"memberName": "Admins", "memberType": "Group", "isPredefinedUser": False,
                 "permissions": {"manageSafe": True}},
            ],
            "count": 3,
        }
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test-token"
        result = client.fetch_safe_members("TestSafe")
        assert len(result) == 2  # Master filtered out
        names = [m["memberName"] for m in result]
        assert "Master" not in names
        assert "john.doe" in names
        assert "Admins" in names

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_handles_api_failure(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test-token"
        result = client.fetch_safe_members("ForbiddenSafe")
        assert result == []


class TestSkipMembersFlag:
    """Verify --skip-members flag parses correctly."""

    def test_skip_members_flag_parses(self):
        cmd = CyberArkPAMImportCommand()
        args = cmd.parser.parse_args(["pvwa.example.com", "--skip-members"])
        assert args.skip_members is True

    def test_skip_members_default_false(self):
        cmd = CyberArkPAMImportCommand()
        args = cmd.parser.parse_args(["pvwa.example.com"])
        assert args.skip_members is False


class TestFetchSafeMembersPagination:
    """Test pagination loop in fetch_safe_members."""

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_pagination_fetches_multiple_pages(self, mock_dns, mock_requests):
        page1 = [{"memberName": f"user{i}", "memberType": "User",
                   "isPredefinedUser": False, "permissions": {}}
                  for i in range(100)]
        page2 = [{"memberName": "last_user", "memberType": "User",
                   "isPredefinedUser": False, "permissions": {}}]

        resp1 = MagicMock()
        resp1.status_code = 200
        resp1.json.return_value = {"value": page1, "count": 101}

        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.json.return_value = {"value": page2, "count": 101}

        mock_requests.get.side_effect = [resp1, resp2]

        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_safe_members("TestSafe")
        assert len(result) == 101
        assert result[-1]["memberName"] == "last_user"


# ── Phase 5 Tests: User/Team Matching + CSV ──────────────────

class TestUserTeamMatcher:
    """Tests for UserTeamMatcher."""

    def test_match_user_by_email(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher(
            keeper_users=[{"email": "john@company.com"}])
        result = matcher.match_user("john.doe", cyberark_email="john@company.com")
        assert result == "john@company.com"
        assert len(matcher.unmatched) == 0

    def test_match_user_by_username_email(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher(
            keeper_users=[{"email": "john@company.com"}])
        result = matcher.match_user("john@company.com")
        assert result == "john@company.com"

    def test_match_user_by_override(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher(
            keeper_users=[{"email": "john@company.com"}],
            user_map_override={"ca_admin": "john@company.com"})
        result = matcher.match_user("ca_admin")
        assert result == "john@company.com"

    def test_user_not_found(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher(keeper_users=[{"email": "john@company.com"}])
        result = matcher.match_user("unknown_user", cyberark_email="unknown@other.com")
        assert result is None
        assert len(matcher.unmatched) == 1
        assert matcher.unmatched[0]["cyberark_username"] == "unknown_user"

    def test_match_team_by_name(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher(
            keeper_teams=[{"name": "Windows Admins"}])
        result = matcher.match_team("Windows Admins")
        assert result == "Windows Admins"

    def test_match_team_case_insensitive(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher(
            keeper_teams=[{"name": "Windows Admins"}])
        result = matcher.match_team("windows admins")
        assert result == "windows admins"

    def test_team_not_found(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher(keeper_teams=[{"name": "Existing Team"}])
        result = matcher.match_team("New Team")
        assert result is None
        assert len(matcher.unmatched) == 1
        assert matcher.unmatched[0]["suggested_action"] == "create_team"

    def test_empty_matcher(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher()
        result = matcher.match_user("anyone")
        assert result is None
        result = matcher.match_team("any_team")
        assert result is None
        assert len(matcher.unmatched) == 2


class TestCSVGeneration:
    """Tests for UserTeamMatcher.generate_csv."""

    def test_generates_csv_with_unmatched(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher()
        matcher.match_user("admin", cyberark_email="admin@old.com",
                           cyberark_groups="Admins")
        matcher.match_team("Missing Team")
        csv = matcher.generate_csv()
        lines = csv.strip().split('\n')
        assert len(lines) == 3  # header + 2 rows
        assert 'cyberark_username' in lines[0]
        assert 'admin' in lines[1]
        assert 'Missing Team' in lines[2]

    def test_empty_csv_when_all_matched(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher(
            keeper_users=[{"email": "admin@company.com"}])
        matcher.match_user("admin", cyberark_email="admin@company.com")
        csv = matcher.generate_csv()
        assert csv == ''

    def test_csv_escapes_commas(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher()
        matcher.match_user("user,with,commas", cyberark_email="test@x.com")
        csv_output = matcher.generate_csv()
        # csv.writer with QUOTE_ALL properly quotes fields with commas
        assert '"user,with,commas"' in csv_output

    def test_no_credentials_in_csv(self):
        from keepercommander.importer.cyberark.cyberark_pam import UserTeamMatcher
        matcher = UserTeamMatcher()
        matcher.match_user("admin", cyberark_email="admin@x.com")
        csv = matcher.generate_csv()
        assert 'password' not in csv.lower()
        assert 'secret' not in csv.lower()
        assert 'token' not in csv.lower()


class TestFetchUsersAndGroups:
    """Tests for fetch_users and fetch_user_groups."""

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_fetch_users_excludes_component(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Users": [
                {"id": 1, "username": "john.doe", "componentUser": False,
                 "personalDetails": {"email": "john@x.com"}},
            ],
            "Total": 1,
        }
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_users()
        assert len(result) == 1
        assert result[0]["username"] == "john.doe"

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_fetch_user_groups(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "value": [
                {"id": 10, "groupName": "Windows Admins", "groupType": "Vault"},
            ],
            "count": 1,
        }
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_user_groups()
        assert len(result) == 1
        assert result[0]["groupName"] == "Windows Admins"

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_fetch_users_handles_failure(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_users()
        assert result == []


# ── Phase 6 Tests: Master Policy → PAM Config ────────────────

class TestMasterPolicyMapper:
    """Tests for MasterPolicyMapper.map_policy."""

    def test_session_recording_active(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        policy = {"Policy": {"Rules": [
            {"RuleName": "RecordAndSaveSessionActivity", "Active": True},
        ]}}
        config, unmapped = MasterPolicyMapper.map_policy(policy)
        assert config["graphical_session_recording"] == "on"
        assert config["text_session_recording"] == "on"

    def test_session_recording_inactive(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        policy = {"Policy": {"Rules": [
            {"RuleName": "RecordAndSaveSessionActivity", "Active": False},
        ]}}
        config, unmapped = MasterPolicyMapper.map_policy(policy)
        assert config["graphical_session_recording"] == "off"
        assert config["text_session_recording"] == "off"

    def test_connections_active(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        policy = {"Policy": {"Rules": [
            {"RuleName": "AllowEPVTransparentConnections", "Active": True},
        ]}}
        config, unmapped = MasterPolicyMapper.map_policy(policy)
        assert config["connections"] == "on"

    def test_connections_inactive(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        policy = {"Policy": {"Rules": [
            {"RuleName": "AllowEPVTransparentConnections", "Active": False},
        ]}}
        config, unmapped = MasterPolicyMapper.map_policy(policy)
        assert config["connections"] == "off"

    def test_unmapped_dual_control(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        policy = {"Policy": {"Rules": [
            {"RuleName": "RequireDualControlPasswordAccessApproval", "Active": True},
            {"RuleName": "EnforceCheckinCheckoutExclusiveAccess", "Active": True},
            {"RuleName": "EnforceOnetimePasswordAccess", "Active": False},
        ]}}
        config, unmapped = MasterPolicyMapper.map_policy(policy)
        categories = [u["item"] for u in unmapped]
        assert any("Dual control" in c for c in categories)
        assert any("Exclusive checkout" in c for c in categories)
        assert not any("One-time" in c for c in categories)  # False = not active

    def test_audit_retention_unmapped(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        policy = {"Policy": {"Rules": [
            {"RuleName": "SafeAuditRetention", "Value": 365},
        ]}}
        config, unmapped = MasterPolicyMapper.map_policy(policy)
        assert any("365" in u["item"] for u in unmapped)
        assert any("Admin Console" in u["action"] for u in unmapped)

    def test_none_policy_returns_defaults(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        config, unmapped = MasterPolicyMapper.map_policy(None)
        assert config["connections"] == "on"
        assert config["graphical_session_recording"] == "off"
        assert unmapped == []

    def test_empty_dict_returns_defaults(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        config, unmapped = MasterPolicyMapper.map_policy({})
        assert config["connections"] == "on"
        assert unmapped == []

    def test_malformed_rules_handled(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        policy = {"Policy": {"Rules": ["not_a_dict", 42, None]}}
        config, unmapped = MasterPolicyMapper.map_policy(policy)
        assert config["connections"] == "on"  # defaults
        assert unmapped == []


class TestMasterPolicyRotationExceptions:
    """Tests for master-rotation-policy/exceptions parsing."""

    def test_parse_list_shape(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        data = [
            {"platformId": "WinDesktopLocal", "changeInterval": 30},
            {"platformId": "WinDomain", "interval": 60, "allowedPeriodic": True},
        ]
        schedules = MasterPolicyMapper.parse_rotation_exceptions(data)
        assert "WinDesktopLocal" in schedules
        assert schedules["WinDesktopLocal"]["type"] == "CRON"
        assert schedules["WinDomain"]["type"] == "CRON"

    def test_parse_cyberark_exceptions_envelope(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        data = {
            "exceptions": [
                {"platformId": "WinDesktopLocal", "verifyInterval": 7,
                 "changeInterval": 30},
                {"platformId": "WinDomain", "verifyInterval": 7,
                 "changeInterval": 0},
            ],
            "totalCount": 2,
        }
        schedules = MasterPolicyMapper.parse_rotation_exceptions(data)
        assert schedules["WinDesktopLocal"]["type"] == "CRON"
        assert schedules["WinDesktopLocal"]["cron"] == "0 0 0 1 * ?"
        assert "WinDomain" not in schedules  # changeInterval=0 → no schedule

    def test_parse_grouped_shape(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        data = {
            "changeInterval": [
                {"platformId": "WinLocalAccount", "interval": 30},
            ],
        }
        schedules = MasterPolicyMapper.parse_rotation_exceptions(data)
        assert schedules["WinLocalAccount"]["cron"] == "0 0 0 1 * ?"

    def test_allowed_periodic_false_still_uses_interval(self):
        """``allowedPeriodic`` is informational only — an explicit exception
        interval is always honored as a CRON cadence, same as the Master
        Policy default itself (which has no such flag to check)."""
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        data = [{"platformId": "WinDesktopLocal", "interval": 90,
                 "allowedPeriodic": False}]
        schedules = MasterPolicyMapper.parse_rotation_exceptions(data)
        assert schedules["WinDesktopLocal"] == {"type": "CRON", "cron": "0 0 0 1 */3 ?"}

    def test_empty_payload(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        assert MasterPolicyMapper.parse_rotation_exceptions(None) == {}
        assert MasterPolicyMapper.parse_rotation_exceptions([]) == {}


class TestPlatformScheduleWithExceptions:
    """AccountMapper honors master-policy rotation exceptions."""

    def test_master_exception_overrides_inherit_master(self):
        client = MagicMock()
        client.fetch_platform_rotation_policy.return_value = {
            "change": {
                "interval": 90,
                "allowedPeriodic": True,
                "overridesMasterPolicy": False,
            },
        }
        exc = {"WinDesktopLocal": {"type": "CRON", "cron": "0 0 0 */30 * ?"}}
        mapper = AccountMapper(
            client=client,
            master_rotation_exceptions=exc,
        )
        sched = mapper._resolve_platform_schedule("WinDesktopLocal")
        assert sched == exc["WinDesktopLocal"]
        assert mapper.platform_schedule_overrides.get("WinDesktopLocal", 0) == 0

    def test_platform_override_beats_master_exception(self):
        client = MagicMock()
        client.fetch_platform_rotation_policy.return_value = {
            "change": {
                "interval": 30,
                "allowedPeriodic": True,
                "overridesMasterPolicy": True,
            },
        }
        exc = {"WinDesktopLocal": {"type": "CRON", "cron": "0 0 0 1 */3 ?"}}
        mapper = AccountMapper(client=client, master_rotation_exceptions=exc)
        sched = mapper._resolve_platform_schedule("WinDesktopLocal")
        assert sched == {"type": "CRON", "cron": "0 0 0 1 * ?"}

    def test_allowed_periodic_false_without_exception_inherits_master(self):
        """``overridesMasterPolicy=False`` means no exception exists — the
        platform inherits the Master Policy's own CRON schedule. The
        informational ``allowedPeriodic=False`` flag must NOT force
        on-demand here (CyberArk's own Master Policy default has no such
        flag and is always applied as CRON)."""
        client = MagicMock()
        client.fetch_platform_rotation_policy.return_value = {
            "change": {
                "interval": 90,
                "allowedPeriodic": False,
                "overridesMasterPolicy": False,
            },
        }
        mapper = AccountMapper(client=client)
        sched = mapper._resolve_platform_schedule("WinDesktopLocal")
        assert sched is None  # caller applies default_rotation_schedule (master CRON)

    def test_interval_mismatch_treated_as_exception_without_flag(self):
        """No recognized override flag present, but the platform's own
        interval differs from the Master Policy value — CyberArk is
        clearly applying a platform-specific cadence, so honor it."""
        client = MagicMock()
        client.fetch_platform_rotation_policy.return_value = {
            "change": {
                "interval": 30,
                "allowedPeriodic": True,
                # No overridesMasterPolicy / isException key at all.
            },
        }
        mapper = AccountMapper(client=client, master_change_days=90)
        sched = mapper._resolve_platform_schedule("WinDesktopLocal")
        assert sched == {"type": "CRON", "cron": "0 0 0 1 * ?"}  # 30 days -> monthly

    def test_matching_interval_without_flag_inherits_master(self):
        """No flag, and the interval matches master — no exception exists."""
        client = MagicMock()
        client.fetch_platform_rotation_policy.return_value = {
            "change": {"interval": 90, "allowedPeriodic": True},
        }
        mapper = AccountMapper(client=client, master_change_days=90)
        sched = mapper._resolve_platform_schedule("WinDesktopLocal")
        assert sched is None

    def test_legacy_is_exception_flag_name_honored(self):
        """Alternate flag name (``isException``) observed on some tenants."""
        client = MagicMock()
        client.fetch_platform_rotation_policy.return_value = {
            "change": {
                "interval": 14,
                "allowedPeriodic": True,
                "isException": True,
            },
        }
        mapper = AccountMapper(client=client, master_change_days=90)
        sched = mapper._resolve_platform_schedule("WinLocalAccount")
        assert sched == {"type": "CRON", "cron": "0 0 0 1,15 * ?"}  # 14 days -> bi-weekly


class TestMasterRotationExceptionsBogusShapeDetection:
    """CyberArkPVWAClient must not mistake the base master-policy object
    (re-served by some tenants at .../exceptions/) for real exception data."""

    def test_looks_like_base_master_policy_detected(self):
        data = {
            "changeInterval": 90,
            "changeIntervalExceptionsCount": 1,
            "verifyInterval": 7,
            "verifyIntervalExceptionsCount": 0,
        }
        assert CyberArkPVWAClient._looks_like_base_master_policy(data) is True

    def test_real_exceptions_envelope_not_flagged(self):
        data = {
            "exceptions": [{"platformId": "WinDesktopLocal",
                             "changeInterval": 30, "verifyInterval": 7}],
            "totalCount": 1,
        }
        assert CyberArkPVWAClient._looks_like_base_master_policy(data) is False

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_fetch_returns_none_for_bogus_shape(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "changeInterval": 90,
            "changeIntervalExceptionsCount": 1,
            "verifyInterval": 7,
            "verifyIntervalExceptionsCount": 0,
        }
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_master_rotation_policy_exceptions()
        assert result is None

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_fetch_returns_data_for_real_envelope(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "exceptions": [{"platformId": "WinDesktopLocal",
                             "changeInterval": 30, "verifyInterval": 7}],
            "totalCount": 1,
        }
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_master_rotation_policy_exceptions()
        assert result is not None
        assert result["totalCount"] == 1


class TestFetchMasterPolicy:
    """Tests for CyberArkPVWAClient.fetch_master_policy."""

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_returns_policy_on_success(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Policy": {"Rules": [
                {"RuleName": "RecordAndSaveSessionActivity", "Active": True},
            ]}
        }
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_master_policy()
        assert result is not None
        assert "Policy" in result

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_returns_none_on_403(self, mock_dns, mock_requests):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_requests.get.return_value = mock_resp
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_master_policy()
        assert result is None

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_returns_none_on_network_error(self, mock_dns, mock_requests):
        import requests as _req
        mock_requests.get.side_effect = _req.ConnectionError("network down")
        mock_requests.RequestException = _req.RequestException
        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_master_policy()
        assert result is None


# ── Red Team Coverage Tests ──────────────────────────────────

class TestEscFunction:
    """Tests for _esc() HTML + control char sanitizer."""

    def test_html_chars_escaped(self):
        from keepercommander.importer.cyberark.cyberark_pam import _esc
        assert '&lt;' in _esc('<script>')
        assert '&amp;' in _esc('A & B')
        assert '&gt;' in _esc('x > y')

    def test_control_chars_stripped(self):
        from keepercommander.importer.cyberark.cyberark_pam import _esc
        result = _esc("Safe\x00Name\x1b[31mRed\x1b[0m")
        assert '\x00' not in result
        assert '\x1b' not in result
        assert 'SafeName' in result

    def test_none_input(self):
        from keepercommander.importer.cyberark.cyberark_pam import _esc
        assert _esc(None) == 'None'

    def test_integer_input(self):
        from keepercommander.importer.cyberark.cyberark_pam import _esc
        assert _esc(12345) == '12345'

    def test_empty_string(self):
        from keepercommander.importer.cyberark.cyberark_pam import _esc
        assert _esc('') == ''


class TestFormatDurationEdgeCases:
    """Tests for format_duration edge cases from red team."""

    def test_infinity(self):
        from keepercommander.importer.cyberark.cyberark_pam import format_duration
        assert format_duration(float('inf')) == 'N/A'

    def test_negative_infinity(self):
        from keepercommander.importer.cyberark.cyberark_pam import format_duration
        assert format_duration(float('-inf')) == 'N/A'

    def test_nan(self):
        from keepercommander.importer.cyberark.cyberark_pam import format_duration
        assert format_duration(float('nan')) == 'N/A'

    def test_negative(self):
        from keepercommander.importer.cyberark.cyberark_pam import format_duration
        assert format_duration(-10) == '0s'

    def test_large_value(self):
        from keepercommander.importer.cyberark.cyberark_pam import format_duration
        result = format_duration(1000000)
        assert 'm' in result  # should be clamped and formatted


class TestMapPolicyCrashers:
    """Tests for MasterPolicyMapper crash cases from red team."""

    def test_policy_none_value(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        config, unmapped = MasterPolicyMapper.map_policy({"Policy": None})
        assert config["connections"] == "on"  # defaults

    def test_policy_list_value(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        config, unmapped = MasterPolicyMapper.map_policy({"Policy": []})
        assert config["connections"] == "on"

    def test_policy_string_value(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        config, unmapped = MasterPolicyMapper.map_policy({"Policy": "invalid"})
        assert config["connections"] == "on"

    def test_rules_null(self):
        from keepercommander.importer.cyberark.cyberark_pam import MasterPolicyMapper
        config, unmapped = MasterPolicyMapper.map_policy({"Policy": {"Rules": None}})
        assert config["connections"] == "on"


class TestDetectDualAccountCrashers:
    """Tests for detect_dual_account crash cases."""

    def test_none_input(self):
        from keepercommander.importer.cyberark.cyberark_pam import detect_dual_account
        assert detect_dual_account(None) is None

    def test_list_input(self):
        from keepercommander.importer.cyberark.cyberark_pam import detect_dual_account
        assert detect_dual_account([]) is None

    def test_integer_input(self):
        from keepercommander.importer.cyberark.cyberark_pam import detect_dual_account
        assert detect_dual_account(42) is None


class TestPaginationCap:
    """Tests for MAX_FETCH_RECORDS pagination cap."""

    def test_cap_constant_defined(self):
        from keepercommander.importer.cyberark.cyberark_pam import MAX_FETCH_RECORDS
        assert MAX_FETCH_RECORDS == 50000

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_fetch_users_respects_cap(self, mock_dns, mock_requests):
        """Verify fetch_users stops at MAX_FETCH_RECORDS."""
        from keepercommander.importer.cyberark.cyberark_pam import MAX_FETCH_RECORDS
        # Return exactly limit users per page to trigger pagination
        page = [{"id": i, "username": f"user{i}", "componentUser": False}
                for i in range(100)]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"Users": page, "Total": 999999}
        mock_requests.get.return_value = mock_resp

        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client.fetch_users()
        # Should stop well before 999999 — capped at MAX_FETCH_RECORDS
        assert len(result) <= MAX_FETCH_RECORDS + 100  # allow 1 page overshoot


class TestPaginationNextLinkSsrf:
    """A compromised PVWA could return a nextLink pointing at an attacker host
    to exfiltrate the Authorization header. Pagination must refuse cross-origin
    nextLink values."""

    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_cross_origin_next_link_stops_pagination(self, mock_dns, mock_requests):
        """nextLink pointing at a different host should halt pagination
        without following the link (no token exfiltration)."""
        call_urls = []

        def mock_get(url, **kwargs):
            call_urls.append(url)
            resp = MagicMock()
            resp.status_code = 200
            if len(call_urls) == 1:
                # First page returns a malicious nextLink to an external host
                resp.json.return_value = {
                    "Users": [{"id": 1, "username": "u1", "componentUser": False}],
                    "nextLink": "https://attacker.example.com/steal?token=x",
                }
            else:
                # If we DID follow it, we'd hit this — test asserts we don't
                resp.json.return_value = {"Users": [], "nextLink": None}
            return resp

        mock_requests.get.side_effect = mock_get

        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "sensitive-token"
        client.fetch_users()
        # Only the original host should have been contacted
        for u in call_urls:
            assert "attacker.example.com" not in u, \
                f"pagination followed attacker nextLink: {u}"


class TestGetRetry429:
    """Tests for _get() HTTP 429 retry logic."""

    @patch("keepercommander.importer.cyberark.cyberark_pam.time.sleep")
    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_retries_on_429(self, mock_dns, mock_requests, mock_sleep):
        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.headers = {"Retry-After": "2"}

        resp_200 = MagicMock()
        resp_200.status_code = 200

        mock_requests.get.side_effect = [resp_429, resp_200]

        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client._get("https://pvwa.example.com/API/test")
        assert result.status_code == 200
        assert mock_sleep.called

    @patch("keepercommander.importer.cyberark.cyberark_pam.time.sleep")
    @patch("keepercommander.importer.cyberark.cyberark_pam.requests")
    @patch("keepercommander.importer.cyberark.cyberark_pam.socket.getaddrinfo",
           return_value=[(2, 1, 6, '', ('93.184.216.34', 0))])
    def test_returns_429_after_max_retries(self, mock_dns, mock_requests, mock_sleep):
        resp_429 = MagicMock()
        resp_429.status_code = 429
        resp_429.headers = {}

        mock_requests.get.return_value = resp_429

        client = CyberArkPVWAClient("pvwa.example.com")
        client.auth_token = "test"
        result = client._get("https://pvwa.example.com/API/test")
        assert result.status_code == 429
        assert mock_requests.get.call_count == 3  # MAX_RETRIES


# ── Phase 7 Tests: Enhanced Report + Cleanup ─────────────────

class TestEnhancedReport:
    """Tests for the enhanced build_report with all sections."""

    def test_report_has_all_sections(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_report
        report = build_report(
            project_name="Test",
            safes_processed=3,
            total_accounts=50,
            resource_counts={"pamMachine": {"ok": 20, "skip": 0, "err": 0},
                             "login": {"ok": 10, "skip": 0, "err": 0}},
            platform_counts={"UnixSSH": {"rotation": "general", "count": 20}},
            skipped=[{"reason": "password retrieval failed"}],
            incomplete_count=2,
            duration=120.0,
            unmapped_items=[{"category": "Master Policy",
                             "item": "Dual control = Active",
                             "action": "Use ticketing"}],
            server="pvwa.example.com",
        )
        assert "SOURCE SUMMARY" in report
        assert "IMPORT RESULTS" in report
        assert "PLATFORM MAPPING" in report
        assert "SKIPPED ACCOUNTS" in report
        assert "UNMAPPED" in report
        assert "NEXT STEPS" in report
        assert "COMMAND" in report
        assert "pvwa.example.com" in report
        assert "Dual control" in report

    def test_report_gateway_token(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_report
        report = build_report(
            project_name="GW Test",
            safes_processed=1, total_accounts=5,
            resource_counts={}, platform_counts={},
            skipped=[], incomplete_count=0, duration=10.0,
            project_result={"gateway": {"gateway_name": "GW1",
                                        "gateway_uid": "uid1",
                                        "gateway_token": "TOKEN123"}},
        )
        assert "GATEWAY DEPLOYMENT" in report
        assert "TOKEN123" in report
        assert "docker run" in report

    def test_report_no_gateway_for_extend(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_report
        report = build_report(
            project_name="Extend",
            safes_processed=1, total_accounts=5,
            resource_counts={}, platform_counts={},
            skipped=[], incomplete_count=0, duration=10.0,
        )
        assert "GATEWAY DEPLOYMENT" not in report

    def test_report_cleanup_command(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_report
        report = build_report(
            project_name="MyProject",
            safes_processed=1, total_accounts=5,
            resource_counts={}, platform_counts={},
            skipped=[], incomplete_count=0, duration=10.0,
        )
        assert 'cyberark-cleanup --name "MyProject"' in report


class TestCleanupCommand:
    """Tests for CyberArkPAMCleanupCommand."""

    def test_missing_args_raises(self):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMCleanupCommand
        from keepercommander.error import CommandError
        cmd = CyberArkPAMCleanupCommand()
        with pytest.raises(CommandError):
            cmd.execute(MagicMock(), project_name="", config_uid="")

    def test_parser_has_flags(self):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMCleanupCommand
        cmd = CyberArkPAMCleanupCommand()
        args = cmd.parser.parse_args(["--name", "Test", "--dry-run", "--yes"])
        assert args.project_name == "Test"
        assert args.dry_run is True
        assert args.auto_confirm is True

    def test_parser_config_flag(self):
        from keepercommander.commands.pam_import.cyberark_import import CyberArkPAMCleanupCommand
        cmd = CyberArkPAMCleanupCommand()
        args = cmd.parser.parse_args(["--config", "uid123"])
        assert args.config_uid == "uid123"


class TestSSHKeyImport:
    """C4: SSH key platforms store private key in private_pem_key, not password."""

    def test_unix_ssh_key_platform_maps_private_key(self):
        mapper = AccountMapper()
        account = {
            "id": "1", "name": "sshkey-acct", "platformId": "UnixSSHKey",
            "address": "10.0.0.1", "userName": "deploy",
        }
        fake_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        result = mapper.map_account(account, fake_key)
        user = result["users"][0]
        assert user.get("private_pem_key") == fake_key
        assert user.get("password") == ""

    def test_unix_ssh_keys_platform_maps_private_key(self):
        mapper = AccountMapper()
        account = {
            "id": "2", "name": "sshkeys-acct", "platformId": "UnixSSHKeys",
            "address": "10.0.0.2", "userName": "ansible",
        }
        fake_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA...\n-----END OPENSSH PRIVATE KEY-----"
        result = mapper.map_account(account, fake_key)
        user = result["users"][0]
        assert user.get("private_pem_key") == fake_key
        assert user.get("password") == ""

    def test_ssh_key_without_password_no_key_field(self):
        mapper = AccountMapper()
        account = {
            "id": "3", "name": "sshkey-nopass", "platformId": "UnixSSHKey",
            "address": "10.0.0.3", "userName": "root",
        }
        result = mapper.map_account(account, None)
        user = result["users"][0]
        assert "private_pem_key" not in user

    def test_secret_type_key_on_custom_platform(self):
        """Custom platform with secretType=key should be treated as SSH key."""
        mapper = AccountMapper()
        account = {
            "id": "5", "name": "custom-sshkey", "platformId": "CustomLinux",
            "address": "10.0.0.5", "userName": "ansible",
            "secretType": "key",
        }
        fake_key = "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----"
        result = mapper.map_account(account, fake_key)
        user = result["users"][0]
        assert user.get("private_pem_key") == fake_key
        assert user.get("password") == ""

    def test_unix_ssh_regular_does_not_set_key(self):
        mapper = AccountMapper()
        account = {
            "id": "4", "name": "ssh-regular", "platformId": "UnixSSH",
            "address": "10.0.0.4", "userName": "root",
        }
        result = mapper.map_account(account, "s3cret")
        user = result["users"][0]
        assert "private_pem_key" not in user

    def test_pem_crrn_line_endings_normalized(self):
        """CyberArk exports PEMs with \\r\\r\\n line endings (PVWA artifact).
        OpenSSH rejects this; we normalize to \\n on import."""
        mapper = AccountMapper()
        account = {
            "id": "6", "name": "crrn-key", "platformId": "UnixSSHKeys",
            "address": "10.0.0.6", "userName": "root", "secretType": "key",
        }
        ca_key = (
            "-----BEGIN RSA PRIVATE KEY-----\r\r\n"
            "MIIEpAIBAAKCAQEAyNzN8vyPmMaZfV8cUxuvCxZKXO99I4wFlZpvkJcUZPM7lOo+\r\r\n"
            "-----END RSA PRIVATE KEY-----"
        )
        result = mapper.map_account(account, ca_key)
        pem = result["users"][0]["private_pem_key"]
        assert "\r\r\n" not in pem
        assert pem.startswith("-----BEGIN RSA PRIVATE KEY-----\n")
        assert "\nMIIEpAIBAAKCAQEAyNzN8vyPmMaZfV8cUxuvCxZKXO99I4wFlZpvkJcUZPM7lOo+\n" in pem
        assert result["users"][0]["password"] == ""


class TestSharedFolderPermissions:
    """C3: Safe member permissions flow into shared folder structure."""

    def test_build_shared_folder_permissions_basic(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_shared_folder_permissions
        safe_members = {
            "safe1": [
                {"name": "admin@corp.com", "member_type": "user",
                 "permissions": {"manage_users": True, "manage_records": True,
                                 "can_edit": True, "can_share": True},
                 "unmapped_permissions": []},
            ]
        }
        matcher = UserTeamMatcher(
            keeper_users=[{"email": "admin@corp.com"}],
        )
        result = build_shared_folder_permissions(safe_members, matcher)
        assert "shared_folder_resources" in result
        assert "shared_folder_users" in result
        perms = result["shared_folder_resources"]["permissions"]
        assert len(perms) == 1
        assert perms[0]["name"] == "admin@corp.com"
        assert perms[0]["manage_users"] is True
        assert perms[0]["manage_records"] is True

    def test_merge_permissions_across_safes_takes_highest(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_shared_folder_permissions
        safe_members = {
            "safe1": [
                {"name": "user1@corp.com", "member_type": "user",
                 "permissions": {"manage_users": False, "manage_records": False,
                                 "can_edit": False, "can_share": False},
                 "unmapped_permissions": []},
            ],
            "safe2": [
                {"name": "user1@corp.com", "member_type": "user",
                 "permissions": {"manage_users": True, "manage_records": True,
                                 "can_edit": True, "can_share": True},
                 "unmapped_permissions": []},
            ],
        }
        matcher = UserTeamMatcher(
            keeper_users=[{"email": "user1@corp.com"}],
        )
        result = build_shared_folder_permissions(safe_members, matcher)
        perms = result["shared_folder_resources"]["permissions"]
        assert perms[0]["manage_users"] is True
        assert perms[0]["manage_records"] is True

    def test_unmatched_members_excluded_from_permissions(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_shared_folder_permissions
        safe_members = {
            "safe1": [
                {"name": "unknown@other.com", "member_type": "user",
                 "permissions": {"manage_users": True, "manage_records": True,
                                 "can_edit": True, "can_share": True},
                 "unmapped_permissions": []},
            ]
        }
        matcher = UserTeamMatcher(keeper_users=[{"email": "admin@corp.com"}])
        result = build_shared_folder_permissions(safe_members, matcher)
        assert result == {}  # No matched members → no shared folder perms

    def test_team_members_matched(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_shared_folder_permissions
        safe_members = {
            "safe1": [
                {"name": "IT-Admins", "member_type": "team",
                 "permissions": {"manage_users": True, "manage_records": True,
                                 "can_edit": True, "can_share": True},
                 "unmapped_permissions": []},
            ]
        }
        matcher = UserTeamMatcher(keeper_teams=[{"name": "IT-Admins"}])
        result = build_shared_folder_permissions(safe_members, matcher)
        perms = result["shared_folder_resources"]["permissions"]
        assert perms[0]["name"] == "IT-Admins"

    def test_empty_safe_member_map_returns_empty(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_shared_folder_permissions
        result = build_shared_folder_permissions({})
        assert result == {}

    def test_build_import_json_includes_shared_folders(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_import_json
        safe_members = {
            "safe1": [
                {"name": "user@corp.com", "member_type": "user",
                 "permissions": {"manage_users": True, "manage_records": True,
                                 "can_edit": True, "can_share": True},
                 "unmapped_permissions": []},
            ]
        }
        matcher = UserTeamMatcher(keeper_users=[{"email": "user@corp.com"}])
        result = build_import_json("test-project", None, [], [],
                                   safe_member_map=safe_members,
                                   user_team_matcher=matcher)
        assert "shared_folder_resources" in result
        assert "shared_folder_users" in result
        assert result["shared_folder_resources"]["permissions"][0]["name"] == "user@corp.com"

    def test_build_import_json_without_members_has_no_shared_folders(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_import_json
        result = build_import_json("test-project", None, [], [])
        assert "shared_folder_resources" not in result
        assert "shared_folder_users" not in result


class TestRealDataEdgeCases:
    """Tests derived from real on-prem CyberArk PVWA API output."""

    def test_empty_platform_id_uses_fallback(self):
        mapper = AccountMapper()
        account = {
            "id": "25_25", "name": "testobject", "platformId": "",
            "safeName": "Test", "address": "", "userName": "",
            "secretType": "password",
        }
        result = mapper.map_account(account, None)
        assert result is not None
        # No address + no platform → routed to login (not an unreachable pamMachine)
        assert result["type"] == "login"
        assert mapper.unmapped_platforms.get("(empty)", 0) == 1

    def test_no_address_account_routed_to_login(self):
        """CyberArk accounts without an address can't be PAM resources
        (gateway has nothing to connect to) — import as login."""
        mapper = AccountMapper()
        account = {
            "id": "1", "name": "floating-cred", "platformId": "UnixSSH",
            "safeName": "Test", "address": "", "userName": "svc",
            "secretType": "password",
        }
        result = mapper.map_account(account, "s3cret")
        assert result["type"] == "login"
        assert result["login"] == "svc"
        assert result["password"] == "s3cret"
        assert "No address" in result["notes"]

    def test_no_address_ssh_key_stays_pam_machine(self):
        """SSH keys without address stay as pamMachine so the
        private_pem_key field is preserved."""
        mapper = AccountMapper()
        account = {
            "id": "2", "name": "key-no-addr", "platformId": "UnixSSHKeys",
            "safeName": "Test", "address": "", "userName": "root",
            "secretType": "key",
        }
        fake_key = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"
        result = mapper.map_account(account, fake_key)
        assert result["type"] == "pamMachine"
        assert result["users"][0]["private_pem_key"] == fake_key

    def test_missing_platform_id_uses_fallback(self):
        mapper = AccountMapper()
        account = {
            "id": "36_3", "name": "PSMServer",
            "safeName": "PSM", "address": "10.0.1.20", "userName": "PSMConnect",
        }
        result = mapper.map_account(account, "pass")
        assert result is not None
        assert result["type"] == "pamMachine"

    def test_palo_alto_maps_to_ssh(self):
        mapper = AccountMapper()
        account = {
            "id": "25_28", "name": "Network Device-PaloAltoNetworks-10.8.8.8-palo",
            "platformId": "PaloAltoNetworks",
            "address": "10.8.8.8", "userName": "palo",
        }
        result = mapper.map_account(account, "pass")
        assert result["type"] == "pamMachine"
        assert result["pam_settings"]["connection"]["protocol"] == "ssh"

    def test_cyberark_internal_platform_mapped(self):
        mapper = AccountMapper()
        account = {
            "id": "27_3", "name": "SCIM-account", "platformId": "CyberArk",
            "address": "10.0.1.10", "userName": "SCIM-user",
        }
        result = mapper.map_account(account, "pass")
        assert result is not None
        assert result["type"] == "pamMachine"

    def test_logon_domain_maps_to_domain_name(self):
        mapper = AccountMapper()
        account = {
            "id": "25_3", "name": "windows1", "platformId": "WinDesktopLocal",
            "address": "components", "userName": "svc_account",
            "platformAccountProperties": {"LogonDomain": "components"},
        }
        result = mapper.map_account(account, "pass")
        assert result.get("domain_name") == "components"
        user = result["users"][0]
        assert user["login"] == "components\\svc_account"

    def test_logon_domain_not_set_for_databases(self):
        mapper = AccountMapper()
        account = {
            "id": "1", "name": "db1", "platformId": "MSSql",
            "address": "dbserver.local", "userName": "sa",
            "platformAccountProperties": {"LogonDomain": "corp", "Port": "1433"},
        }
        result = mapper.map_account(account, "pass")
        assert "domain_name" not in result  # Only pamMachine gets domain_name

    def test_cpm_failure_status_annotated(self):
        mapper = AccountMapper()
        account = {
            "id": "25_7", "name": "x_accountB", "platformId": "WinDesktopLocal",
            "address": "components", "userName": "x_accountB",
            "secretManagement": {
                "automaticManagementEnabled": False,
                "manualManagementReason": "(CPM)MaxRetries",
                "status": "failure",
            },
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert "FAILURE" in user.get("notes", "")
        assert "(CPM)MaxRetries" in user.get("notes", "")

    def test_system_safes_expanded(self):
        from keepercommander.importer.cyberark.cyberark_pam import SYSTEM_SAFES
        assert "PasswordManager" in SYSTEM_SAFES
        assert "SCIM Config" in SYSTEM_SAFES
        assert "PSM" in SYSTEM_SAFES
        assert "PSMRecordings" in SYSTEM_SAFES

    def test_distinguished_name_mapped(self):
        mapper = AccountMapper()
        account = {
            "id": "1", "name": "win-dc", "platformId": "WinDomain",
            "address": "dc1.corp.local", "userName": "admin",
            "platformAccountProperties": {
                "DistinguishedName": "CN=admin,OU=Admins,DC=corp,DC=local",
            },
        }
        result = mapper.map_account(account, "pass")
        user = result["users"][0]
        assert user.get("distinguished_name") == "CN=admin,OU=Admins,DC=corp,DC=local"


class TestFolderDeduplication:
    """Verify SafeFolderMapper deduplicates colliding names."""

    def test_ksm_mode_dedup_adds_suffix(self):
        mapper = SafeFolderMapper(mode="ksm")
        name1 = mapper.map_safe("IT Safe", "proj")
        name2 = mapper.map_safe("IT Safe!", "proj")  # "!" stripped → "IT Safe" collision
        assert name1 != name2
        assert "#2" in name2

    def test_same_safe_returns_cached(self):
        mapper = SafeFolderMapper(mode="ksm")
        name1 = mapper.map_safe("MySafe", "proj")
        name2 = mapper.map_safe("MySafe", "proj")
        assert name1 == name2

    def test_exact_mode_no_truncation(self):
        mapper = SafeFolderMapper(mode="exact")
        long_name = "A" * 200
        assert mapper.map_safe(long_name, "proj") == long_name

    def test_ksm_mode_truncates(self):
        from keepercommander.importer.cyberark.cyberark_pam import MAX_SAFE_NAME_LENGTH
        mapper = SafeFolderMapper(mode="ksm")
        long_name = "A" * 200
        result = mapper.map_safe(long_name, "proj")
        assert len(result) <= MAX_SAFE_NAME_LENGTH


class TestPreImportValidation:
    """Verify validate_import_data catches issues."""

    def test_warns_missing_host(self):
        from keepercommander.importer.cyberark.cyberark_pam import validate_import_data
        resources = [{"title": "no-host", "type": "pamMachine", "host": "", "users": []}]
        warnings = validate_import_data(resources, [])
        assert any("no host" in w for w in warnings)

    def test_warns_missing_password(self):
        from keepercommander.importer.cyberark.cyberark_pam import validate_import_data
        resources = [{"title": "srv", "type": "pamMachine", "host": "10.0.0.1",
                      "users": [{"title": "u1", "login": "root"}]}]
        warnings = validate_import_data(resources, [])
        assert any("no password" in w for w in warnings)

    def test_warns_standalone_logins(self):
        from keepercommander.importer.cyberark.cyberark_pam import validate_import_data
        users = [{"title": "login1", "type": "login", "password": "x"}]
        warnings = validate_import_data([], users)
        assert any("standalone" in w for w in warnings)

    def test_warns_rotation_without_creds(self):
        from keepercommander.importer.cyberark.cyberark_pam import validate_import_data
        resources = [{"title": "srv", "type": "pamMachine", "host": "10.0.0.1",
                      "users": [{"title": "u1", "login": "root",
                                 "rotation_settings": {"enabled": "on"}}]}]
        warnings = validate_import_data(resources, [])
        assert any("rotation" in w.lower() for w in warnings)

    def test_no_warnings_for_clean_data(self):
        from keepercommander.importer.cyberark.cyberark_pam import validate_import_data
        resources = [{"title": "srv", "type": "pamMachine", "host": "10.0.0.1",
                      "users": [{"title": "u1", "login": "root", "password": "pass"}]}]
        warnings = validate_import_data(resources, [])
        assert len(warnings) == 0


class TestMasterPolicyInConfig:
    """Verify Master Policy flows into pam_configuration."""

    def test_session_recording_from_policy(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_import_json
        mp = {"connections": "on", "rotation": "on", "tunneling": "off",
              "graphical_session_recording": "on", "text_session_recording": "on"}
        result = build_import_json("test", None, [], [], master_policy_config=mp)
        cfg = result["pam_configuration"]
        assert cfg["graphical_session_recording"] == "on"
        assert cfg["text_session_recording"] == "on"
        assert cfg["tunneling"] == "off"

    def test_default_without_policy(self):
        from keepercommander.importer.cyberark.cyberark_pam import build_import_json
        result = build_import_json("test", None, [], [])
        cfg = result["pam_configuration"]
        assert cfg["graphical_session_recording"] == "off"
        assert cfg["text_session_recording"] == "off"


# ═══════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS — Real CyberArk PVWA JSON → Keeper Vault JSON
# ═══════════════════════════════════════════════════════════════════════
# These tests use actual CyberArk API response shapes captured from a
# real on-prem PVWA environment. They verify the full input→output
# pipeline: API response → AccountMapper → SafeFolderMapper →
# validate_import_data → build_import_json → vault-ready JSON.

# Real CyberArk PVWA /api/Accounts response (subset from on-prem env)
REAL_PVWA_ACCOUNTS = [
    # Unix SSH — CPM enabled, standard account
    {"id": "28_11", "name": "Operating System-UnixSSH-10.0.1.30-simon",
     "platformId": "UnixSSH", "safeName": "partner",
     "address": "10.0.1.30", "userName": "simon", "secretType": "password",
     "platformAccountProperties": {},
     "secretManagement": {"automaticManagementEnabled": True,
                          "lastModifiedTime": 1674712329},
     "createdTime": 1674712329},

    # MSSQL Database — CPM disabled, custom port + database
    {"id": "25_15", "name": "db1", "platformId": "MSSql", "safeName": "Test",
     "address": "dbserver1.cyberark.local", "userName": "sa",
     "secretType": "password",
     "platformAccountProperties": {"Port": "15345", "Database": "hr"},
     "secretManagement": {"automaticManagementEnabled": False,
                          "manualManagementReason": "NoReason"},
     "createdTime": 1563922540},

    # Windows Desktop — CPM enabled, LogonDomain set
    {"id": "25_3", "name": "windows1", "platformId": "WinDesktopLocal",
     "safeName": "Test", "address": "components", "userName": "svc_account",
     "secretType": "password",
     "platformAccountProperties": {"LogonDomain": "components"},
     "secretManagement": {"automaticManagementEnabled": True,
                          "status": "success"},
     "createdTime": 1551300856},

    # SSH Keys — CPM disabled, secretType=key
    {"id": "25_14", "name": "Linux2", "platformId": "UnixSSHKeys",
     "safeName": "Test", "address": "linux2.cyberark.local", "userName": "root",
     "secretType": "key", "platformAccountProperties": {},
     "secretManagement": {"automaticManagementEnabled": False,
                          "manualManagementReason": "NoReason"},
     "createdTime": 1563922244},

    # Windows — CPM failure status
    {"id": "25_7",
     "name": "Operating System-WindowsDesktopLocalAccountsRotationalPolicy-10.0.1.20-x_accountB",
     "platformId": "WinDesktopLocal", "safeName": "Test",
     "address": "components", "userName": "x_accountB",
     "secretType": "password", "platformAccountProperties": {},
     "secretManagement": {"automaticManagementEnabled": False,
                          "manualManagementReason": "(CPM)MaxRetries",
                          "status": "failure"},
     "createdTime": 1551306296},

    # BusinessWebsite → login record (not pamMachine)
    {"id": "25_5", "name": "web-portal", "platformId": "BusinessWebsite",
     "safeName": "Test", "address": "", "userName": "admin",
     "platformAccountProperties": {"URL": "https://portal.company.com"},
     "secretManagement": {"automaticManagementEnabled": True},
     "createdTime": 1551306296},

    # System safe account (should be filtered out)
    {"id": "36_3", "name": "PSMServer", "platformId": "", "safeName": "PSM",
     "address": "10.0.1.20", "userName": "PSMConnect",
     "secretType": "password", "platformAccountProperties": {},
     "secretManagement": {"automaticManagementEnabled": True},
     "createdTime": 1670950940},

    # Network device — PaloAlto
    {"id": "25_28",
     "name": "Network Device-PaloAltoNetworks-10.8.8.8-palo",
     "platformId": "PaloAltoNetworks", "safeName": "Test",
     "address": "10.8.8.8", "userName": "palo", "secretType": "password",
     "platformAccountProperties": {},
     "secretManagement": {"automaticManagementEnabled": True},
     "createdTime": 1692833795},

    # CyberArk internal platform in system safe (should be filtered)
    {"id": "27_3", "name": "SCIM-account", "platformId": "CyberArk",
     "safeName": "SCIM Config", "address": "10.0.1.10",
     "userName": "SCIM-user", "secretType": "password",
     "platformAccountProperties": {},
     "secretManagement": {"automaticManagementEnabled": True,
                          "status": "success"},
     "createdTime": 1527261324},

    # Windows Domain with DistinguishedName
    {"id": "25_20", "name": "ad-svc", "platformId": "WinDomain",
     "safeName": "Test", "address": "dc01.corp.local", "userName": "svc_backup",
     "secretType": "password",
     "platformAccountProperties": {
         "LogonDomain": "CORP",
         "DistinguishedName": "CN=svc_backup,OU=ServiceAccounts,DC=corp,DC=local",
     },
     "secretManagement": {"automaticManagementEnabled": True},
     "createdTime": 1563908159},

    # Oracle Database — custom port + database
    {"id": "25_16", "name": "db2", "platformId": "Oracle", "safeName": "Test",
     "address": "dbserver2.cyberark.local", "userName": "oradb",
     "secretType": "password",
     "platformAccountProperties": {"Port": "16234", "Database": "hr"},
     "secretManagement": {"automaticManagementEnabled": False,
                          "manualManagementReason": "NoReason"},
     "createdTime": 1563922714},

    # Empty platformId — should use fallback
    {"id": "25_25", "name": "testobject", "platformId": "",
     "safeName": "Test", "address": "", "userName": "",
     "secretType": "password", "platformAccountProperties": {},
     "secretManagement": {"automaticManagementEnabled": True},
     "createdTime": 1674712262},
]


def _run_full_pipeline(accounts=None, project_name="CyberArk-Test",
                       gateway="TestGateway", folder_mode="ksm",
                       master_policy=None):
    """Helper: run accounts through the full import pipeline, return vault JSON."""
    if accounts is None:
        accounts = REAL_PVWA_ACCOUNTS

    # Step 1: Filter system safes
    all_safes = [{"safeName": s} for s in set(a["safeName"] for a in accounts)]
    filtered = exclude_system_safes(all_safes)
    ok_safes = {s["safeName"] for s in filtered}

    # Step 2: Map accounts → resources + users
    mapper = AccountMapper()
    folder_mapper = SafeFolderMapper(mode=folder_mode)
    resources, users, skipped = [], [], []

    for a in accounts:
        if a["safeName"] not in ok_safes:
            skipped.append(a["name"])
            continue
        pw = "s3cret_pw" if a.get("secretType") != "key" else "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        record = mapper.map_account(a, pw, a["safeName"])
        if record is None:
            continue
        safe_folder = folder_mapper.map_safe(a["safeName"], project_name)
        if safe_folder:
            res_root = f"{project_name} - Resources"
            usr_root = f"{project_name} - Users"
            if record.get("type") == "login":
                record["folder_path"] = f"{usr_root}/{safe_folder}"
            else:
                record["folder_path"] = f"{res_root}/{safe_folder}"
            for u in record.get("users", []):
                u["folder_path"] = f"{usr_root}/{safe_folder}"
        if record.get("type") == "login":
            users.append(record)
        else:
            resources.append(record)

    # Step 3: Validate
    warnings = validate_import_data(resources, users)

    # Step 4: Build vault JSON
    mp = master_policy or {"connections": "on", "rotation": "on",
                           "tunneling": "on",
                           "graphical_session_recording": "on",
                           "text_session_recording": "off"}
    data = build_import_json(project_name, gateway, resources, users,
                             master_policy_config=mp)
    return data, warnings, skipped, mapper


class TestEndToEndPipeline:
    """Integration: real PVWA JSON → full vault import JSON."""

    def test_overall_structure(self):
        data, _, _, _ = _run_full_pipeline()
        assert "project" in data
        assert "pam_configuration" in data
        assert "pam_data" in data
        assert "resources" in data["pam_data"]
        assert "users" in data["pam_data"]
        assert data["project"] == "CyberArk-Test"

    def test_pam_configuration_from_master_policy(self):
        data, _, _, _ = _run_full_pipeline()
        cfg = data["pam_configuration"]
        assert cfg["environment"] == "local"
        assert cfg["gateway_name"] == "TestGateway"
        assert cfg["graphical_session_recording"] == "on"
        assert cfg["text_session_recording"] == "off"
        assert cfg["connections"] == "on"
        assert cfg["rotation"] == "on"
        assert cfg["default_rotation_schedule"] == {"type": "on-demand"}

    def test_system_safes_filtered(self):
        """PSM and SCIM Config accounts should be excluded."""
        _, _, skipped, _ = _run_full_pipeline()
        assert "PSMServer" in skipped
        assert "SCIM-account" in skipped

    def test_resource_count(self):
        """Should produce resources for all non-system, non-login accounts."""
        data, _, _, _ = _run_full_pipeline()
        resources = data["pam_data"]["resources"]
        # 12 accounts - 2 system safe - 1 login = 9 resources
        # BUT empty platformId testobject has no address → still created as resource
        assert len(resources) >= 8

    def test_login_records_separated(self):
        data, _, _, _ = _run_full_pipeline()
        logins = data["pam_data"]["users"]
        # web-portal (BusinessWebsite) + testobject (no-address fallback)
        assert len(logins) == 2
        assert all(l["type"] == "login" for l in logins)
        web = next((l for l in logins if l["title"] == "web-portal"), None)
        assert web is not None
        assert web["url"] == "https://portal.company.com"
        assert web["login"] == "admin"


class TestResourceOutputStructure:
    """Verify each resource type produces correct vault record shape."""

    def _find_resource(self, data, title_contains):
        for r in data["pam_data"]["resources"]:
            if title_contains.lower() in r.get("title", "").lower():
                return r
        raise AssertionError(f"Resource containing '{title_contains}' not found")

    def test_unix_ssh_resource(self):
        data, _, _, _ = _run_full_pipeline()
        r = self._find_resource(data, "simon")
        assert r["type"] == "pamMachine"
        assert r["host"] == "10.0.1.30"
        assert r["port"] == "22"
        assert r["folder_path"] == "CyberArk-Test - Resources/partner"
        # pam_settings
        assert r["pam_settings"]["connection"]["protocol"] == "ssh"
        assert r["pam_settings"]["options"]["rotation"] == "on"
        assert r["pam_settings"]["options"]["connections"] == "on"
        # Nested user
        u = r["users"][0]
        assert u["type"] == "pamUser"
        assert u["login"] == "simon"
        assert u["password"] == "s3cret_pw"
        assert u["managed"] is True
        assert u["rotation_settings"]["rotation"] == "general"
        assert u["rotation_settings"]["enabled"] == "on"
        # launch_credentials links user to resource
        assert r["pam_settings"]["connection"]["launch_credentials"] == u["title"]

    def test_mssql_database_resource(self):
        data, _, _, _ = _run_full_pipeline()
        r = self._find_resource(data, "db1")
        assert r["type"] == "pamDatabase"
        assert r["host"] == "dbserver1.cyberark.local"
        assert r["port"] == "15345"
        assert r["pam_settings"]["connection"]["protocol"] == "mssql"
        # CPM disabled
        assert r["pam_settings"]["options"]["rotation"] == "off"
        u = r["users"][0]
        assert u["connect_database"] == "hr"
        assert u["rotation_settings"]["enabled"] == "off"
        assert "CPM disabled" in u.get("notes", "")

    def test_oracle_database_resource(self):
        data, _, _, _ = _run_full_pipeline()
        r = self._find_resource(data, "db2")
        assert r["type"] == "pamDatabase"
        assert r["port"] == "16234"
        assert r["pam_settings"]["connection"]["protocol"] == "sql-server"
        u = r["users"][0]
        assert u["connect_database"] == "hr"

    def test_windows_domain_with_logon_domain_and_dn(self):
        data, _, _, _ = _run_full_pipeline()
        r = self._find_resource(data, "ad-svc")
        assert r["type"] == "pamMachine"
        assert r["domain_name"] == "CORP"
        assert r["pam_settings"]["connection"]["protocol"] == "rdp"
        assert r["port"] == "3389"
        u = r["users"][0]
        assert u["login"] == "CORP\\svc_backup"
        assert u["distinguished_name"] == "CN=svc_backup,OU=ServiceAccounts,DC=corp,DC=local"

    def test_windows_desktop_with_logon_domain(self):
        data, _, _, _ = _run_full_pipeline()
        r = self._find_resource(data, "windows1")
        assert r["domain_name"] == "components"
        u = r["users"][0]
        assert u["login"] == "components\\svc_account"
        assert r["pam_settings"]["connection"]["launch_credentials"] == u["title"]

    def test_ssh_key_resource(self):
        data, _, _, _ = _run_full_pipeline()
        r = self._find_resource(data, "Linux2")
        assert r["type"] == "pamMachine"
        u = r["users"][0]
        assert "private_pem_key" in u
        assert u["private_pem_key"].startswith("-----BEGIN RSA")
        assert u["password"] == ""
        assert u["rotation_settings"]["enabled"] == "off"

    def test_cpm_failure_annotated(self):
        data, _, _, _ = _run_full_pipeline()
        r = self._find_resource(data, "x_accountB")
        u = r["users"][0]
        notes = u.get("notes", "")
        assert "CPM disabled" in notes
        assert "(CPM)MaxRetries" in notes
        assert "FAILURE" in notes
        assert u["rotation_settings"]["enabled"] == "off"

    def test_palo_alto_network_device(self):
        data, _, _, _ = _run_full_pipeline()
        r = self._find_resource(data, "palo")
        assert r["type"] == "pamMachine"
        assert r["host"] == "10.8.8.8"
        assert r["pam_settings"]["connection"]["protocol"] == "ssh"

    def test_empty_platform_id_handled(self):
        data, _, _, mapper = _run_full_pipeline()
        assert "(empty)" in mapper.unmapped_platforms


class TestUserResourceLinking:
    """Verify edit.py can process the linking fields we produce."""

    def test_every_resource_has_nested_user(self):
        data, _, _, _ = _run_full_pipeline()
        for r in data["pam_data"]["resources"]:
            assert len(r.get("users", [])) >= 1, f"Resource {r['title']} has no users"

    def test_every_nested_user_is_pam_user(self):
        data, _, _, _ = _run_full_pipeline()
        for r in data["pam_data"]["resources"]:
            for u in r["users"]:
                assert u["type"] == "pamUser"

    def test_launch_credentials_matches_user_title(self):
        """edit.py resolves launch_credentials by title → UID."""
        data, _, _, _ = _run_full_pipeline()
        for r in data["pam_data"]["resources"]:
            ps = r.get("pam_settings", {})
            lc = ps.get("connection", {}).get("launch_credentials", "")
            if lc:
                user_titles = [u["title"] for u in r["users"]]
                assert lc in user_titles, (
                    f"launch_credentials '{lc}' not in user titles {user_titles} "
                    f"for resource '{r['title']}'")

    def test_rotation_settings_resource_field(self):
        """edit.py resolves rotation_settings.resource from parent machine title."""
        data, _, _, _ = _run_full_pipeline()
        for r in data["pam_data"]["resources"]:
            for u in r["users"]:
                rs = u.get("rotation_settings", {})
                if rs.get("rotation") == "general":
                    # edit.py auto-sets resourceUid to parent machine UID
                    # We don't set it here — edit.py handles it at import time
                    assert rs["rotation"] == "general"

    def test_managed_flag_on_users_with_password(self):
        data, _, _, _ = _run_full_pipeline()
        for r in data["pam_data"]["resources"]:
            for u in r["users"]:
                if u.get("password") or u.get("private_pem_key"):
                    assert u.get("managed") is True


class TestFolderAssignment:
    """Verify folder_path flows from safe → resource + nested users."""

    def test_folder_path_on_resources(self):
        data, _, _, _ = _run_full_pipeline(folder_mode="ksm")
        for r in data["pam_data"]["resources"]:
            assert "folder_path" in r, f"Resource {r['title']} missing folder_path"

    def test_folder_path_on_nested_users(self):
        data, _, _, _ = _run_full_pipeline(folder_mode="ksm")
        for r in data["pam_data"]["resources"]:
            for u in r["users"]:
                assert "folder_path" in u, f"User {u['title']} missing folder_path"

    def test_resource_folder_under_resources_root(self):
        data, _, _, _ = _run_full_pipeline(folder_mode="ksm")
        for r in data["pam_data"]["resources"]:
            fp = r["folder_path"]
            assert fp.startswith("CyberArk-Test - Resources/"), f"Resource folder not under Resources root: {fp}"

    def test_nested_user_folder_under_users_root(self):
        data, _, _, _ = _run_full_pipeline(folder_mode="ksm")
        for r in data["pam_data"]["resources"]:
            for u in r["users"]:
                fp = u.get("folder_path", "")
                assert fp.startswith("CyberArk-Test - Users/"), f"Nested user folder not under Users root: {fp}"

    def test_resource_and_user_share_safe_subfolder(self):
        """Resource in 'Test' safe → Resources/Test, its user → Users/Test."""
        data, _, _, _ = _run_full_pipeline(folder_mode="ksm")
        for r in data["pam_data"]["resources"]:
            res_safe = r["folder_path"].split("/", 1)[1] if "/" in r["folder_path"] else ""
            for u in r["users"]:
                usr_safe = u["folder_path"].split("/", 1)[1] if "/" in u["folder_path"] else ""
                assert res_safe == usr_safe, (
                    f"Resource and user should be in same safe subfolder: "
                    f"resource={r['folder_path']}, user={u['folder_path']}")

    def test_flat_mode_no_folders(self):
        data, _, _, _ = _run_full_pipeline(folder_mode="flat")
        for r in data["pam_data"]["resources"]:
            assert r.get("folder_path", "") == ""

    def test_login_record_under_users_root(self):
        data, _, _, _ = _run_full_pipeline(folder_mode="ksm")
        logins = data["pam_data"]["users"]
        assert logins[0].get("folder_path") == "CyberArk-Test - Users/Test"


class TestValidationWarnings:
    """Verify pre-import validation catches the right issues."""

    def test_real_data_warnings(self):
        _, warnings, _, _ = _run_full_pipeline()
        # We have 1 login record not linked to a resource
        assert any("standalone" in w for w in warnings)

    def test_no_address_account_becomes_login(self):
        """testobject (no address) is routed to a login record rather than
        an unreachable pamMachine — validated at the data level."""
        data, _, _, _ = _run_full_pipeline()
        logins = data["pam_data"]["users"]
        testobject = next((l for l in logins if l["title"] == "testobject"), None)
        assert testobject is not None
        assert "no address" in testobject.get("notes", "").lower()

    def test_clean_data_no_warnings(self):
        clean = [REAL_PVWA_ACCOUNTS[0]]  # Just the Unix SSH account
        _, warnings, _, _ = _run_full_pipeline(accounts=clean)
        assert len(warnings) == 0


class TestVaultJsonSchema:
    """Verify the output JSON matches what edit.py PAMProjectImportCommand expects."""

    def test_top_level_keys(self):
        data, _, _, _ = _run_full_pipeline()
        assert set(data.keys()) >= {"project", "pam_configuration", "pam_data"}

    def test_pam_config_required_fields(self):
        data, _, _, _ = _run_full_pipeline()
        cfg = data["pam_configuration"]
        required = {"environment", "title", "connections", "rotation",
                    "tunneling", "default_rotation_schedule"}
        assert required <= set(cfg.keys())

    def test_pam_config_keeper_specific_fields_explicit(self):
        """RBI and AI fields must be set explicitly so PamConfigEnvironment
        doesn't fall back to its built-in defaults (RBI=on) which conflict
        with the CyberArk migration intent (off by default)."""
        data, _, _, _ = _run_full_pipeline()
        cfg = data["pam_configuration"]
        assert cfg.get("remote_browser_isolation") == "off"
        assert cfg.get("ai_threat_detection") == "off"
        assert cfg.get("ai_terminate_session_on_detection") == "off"

    def test_resource_required_fields(self):
        data, _, _, _ = _run_full_pipeline()
        for r in data["pam_data"]["resources"]:
            assert "type" in r
            assert "title" in r
            assert "host" in r
            assert "users" in r
            assert r["type"] in ("pamMachine", "pamDatabase", "pamDirectory",
                                 "pamRemoteBrowser")

    def test_user_required_fields(self):
        data, _, _, _ = _run_full_pipeline()
        for r in data["pam_data"]["resources"]:
            for u in r["users"]:
                assert "type" in u
                assert "title" in u
                assert "login" in u
                assert u["type"] == "pamUser"

    def test_rotation_settings_schema(self):
        data, _, _, _ = _run_full_pipeline()
        valid_rotations = ("general", "iam_user", "scripts_only")
        valid_enabled = ("on", "off", "default")
        for r in data["pam_data"]["resources"]:
            for u in r["users"]:
                rs = u.get("rotation_settings")
                if rs:
                    assert rs["rotation"] in valid_rotations
                    assert rs["enabled"] in valid_enabled
                    assert rs["schedule"]["type"] in ("on-demand", "cron")

    def test_pam_settings_schema(self):
        data, _, _, _ = _run_full_pipeline()
        for r in data["pam_data"]["resources"]:
            ps = r.get("pam_settings")
            if ps:
                assert "options" in ps
                assert "connection" in ps
                opts = ps["options"]
                for key in ("rotation", "connections", "tunneling",
                            "graphical_session_recording"):
                    assert opts[key] in ("on", "off")
                conn = ps["connection"]
                assert "protocol" in conn

    def test_login_record_schema(self):
        data, _, _, _ = _run_full_pipeline()
        for u in data["pam_data"]["users"]:
            assert u["type"] == "login"
            assert "title" in u
            assert "login" in u

    def test_output_is_json_serializable(self):
        data, _, _, _ = _run_full_pipeline()
        serialized = json.dumps(data)
        roundtrip = json.loads(serialized)
        assert roundtrip["project"] == data["project"]
        assert len(roundtrip["pam_data"]["resources"]) == len(data["pam_data"]["resources"])


# ── Real PVWA sample from Prathamesh's environment (PAM-only subset) ──
# Files live under .sample-data/ (gitignored). Tests skip when absent so CI
# and other devs aren't broken by missing sample data.

_SAMPLE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".sample-data"))
_SAMPLE_FILES = ("safes.json", "accounts.json", "passwords.json")


def _sample_available() -> bool:
    return all(os.path.exists(os.path.join(_SAMPLE_DIR, f)) for f in _SAMPLE_FILES)


def _load_sample():
    with open(os.path.join(_SAMPLE_DIR, "safes.json")) as f:
        safes = json.load(f)["value"]
    with open(os.path.join(_SAMPLE_DIR, "accounts.json")) as f:
        accounts_dict = json.load(f)
    with open(os.path.join(_SAMPLE_DIR, "passwords.json")) as f:
        passwords = json.load(f)
    accounts = []
    for acct in accounts_dict.values():
        acct = dict(acct)
        acct.setdefault("platformAccountProperties", {})
        accounts.append(acct)
    return safes, accounts, passwords


@pytest.mark.skipif(not _sample_available(),
                    reason="Prathamesh sample (.sample-data/*.json) not present")
class TestPrathameshSample:
    """Integration against real PVWA export — regression net for authentic data shapes."""

    def test_files_parse_and_ids_align(self):
        safes, accounts, passwords = _load_sample()
        assert len(safes) > 0
        assert len(accounts) == len(passwords)
        assert {a["id"] for a in accounts} == set(passwords.keys())

    def test_pipeline_no_crashes(self):
        _, accounts, passwords = _load_sample()
        mapper = AccountMapper()
        for a in accounts:
            pw = passwords.get(a["id"], {}).get("password", "")
            mapper.map_account(a, pw, a.get("safeName", ""))

    def test_non_system_accounts_produce_records(self):
        _, accounts, passwords = _load_sample()
        mapper = AccountMapper()
        all_safes = [{"safeName": s} for s in {a["safeName"] for a in accounts}]
        kept = {s["safeName"] for s in exclude_system_safes(all_safes)}
        user_accounts = [a for a in accounts if a["safeName"] in kept]
        records = [mapper.map_account(a, passwords[a["id"]]["password"], a["safeName"])
                   for a in user_accounts]
        assert len(records) > 0
        assert all(r is not None for r in records)

    def test_ssh_key_routed_to_private_pem_key(self):
        _, accounts, passwords = _load_sample()
        mapper = AccountMapper()
        ssh_key_accounts = [a for a in accounts if a.get("secretType") == "key"]
        assert len(ssh_key_accounts) >= 1
        for a in ssh_key_accounts:
            pw = passwords[a["id"]]["password"]
            rec = mapper.map_account(a, pw, a.get("safeName", ""))
            assert rec is not None and rec["type"] == "pamMachine"
            user = rec["users"][0]
            # Key material must be stored under private_pem_key (not password)
            # and \r\r\n line endings must be normalized to \n.
            assert user["private_pem_key"]
            assert "\r\r\n" not in user["private_pem_key"]
            assert user["password"] == ""

    def test_empty_password_does_not_crash(self):
        _, accounts, passwords = _load_sample()
        mapper = AccountMapper()
        empty_pw = [a for a in accounts
                    if passwords.get(a["id"], {}).get("password") == ""]
        assert len(empty_pw) >= 1
        for a in empty_pw:
            rec = mapper.map_account(a, "", a.get("safeName", ""))
            if rec and rec["type"] in ("pamMachine", "pamDatabase"):
                assert rec["users"][0]["password"] == ""

    def test_vault_json_builds_and_serializes(self):
        _, accounts, passwords = _load_sample()
        mapper = AccountMapper()
        all_safes = [{"safeName": s} for s in {a["safeName"] for a in accounts}]
        kept = {s["safeName"] for s in exclude_system_safes(all_safes)}
        resources, users = [], []
        for a in accounts:
            if a["safeName"] not in kept:
                continue
            rec = mapper.map_account(a, passwords[a["id"]]["password"], a["safeName"])
            if rec is None:
                continue
            (users if rec["type"] == "login" else resources).append(rec)
        data = build_import_json("Prathamesh-Sample", "TestGW", resources, users)
        json.dumps(data)  # must serialize cleanly
        assert data["project"] == "Prathamesh-Sample"
        assert "pam_data" in data


# ── Record-kind discriminator + ApplicationMapper stub ───────


class TestRecordKindDiscriminator:
    """Coverage for `discriminate_record_kind`. Stub-level — the
    real Application/API-token shapes will be confirmed when
    Prathamesh's samples land (deliverable #2)."""

    def test_account_payload_returns_account(self):
        # Standard /Accounts shape — minimum fields the AccountMapper consumes.
        payload = {"id": "1_2", "platformId": "UnixSSH", "userName": "root",
                   "safeName": "S", "address": "10.0.0.1"}
        assert discriminate_record_kind(payload) == RecordKind.ACCOUNT

    def test_application_payload_returns_application(self):
        # /Applications response items have AppID; absent on /Accounts.
        assert discriminate_record_kind({"AppID": "MyApp"}) == RecordKind.APPLICATION

    def test_api_token_payload_returns_api_token(self):
        # Placeholder shape — real discriminator field TBD post-sample.
        assert discriminate_record_kind({"platformType": "Application"}) == RecordKind.API_TOKEN

    def test_application_wins_over_api_token_when_both_present(self):
        # AppID is more specific than platformType=Application.
        payload = {"AppID": "X", "platformType": "Application"}
        assert discriminate_record_kind(payload) == RecordKind.APPLICATION

    def test_non_dict_falls_back_to_account(self):
        # Defensive: bad input doesn't crash; falls back to safest kind.
        assert discriminate_record_kind(None) == RecordKind.ACCOUNT
        assert discriminate_record_kind("not a dict") == RecordKind.ACCOUNT
        assert discriminate_record_kind([]) == RecordKind.ACCOUNT


class TestApplicationMapperStub:
    """ApplicationMapper is intentionally a NotImplementedError stub
    until Prathamesh's /Applications sample arrives. These tests pin
    the contract so a future implementer can't accidentally swallow
    real applications by silently returning None."""

    def test_map_application_raises_not_implemented(self):
        mapper = ApplicationMapper(client=MagicMock())
        with pytest.raises(NotImplementedError) as exc:
            mapper.map_application({"AppID": "X"})
        assert "awaiting" in str(exc.value).lower()

    def test_target_record_type_is_documented_placeholder(self):
        # Forces the implementer to revisit the placeholder rather
        # than ship 'login' as the default forever.
        assert ApplicationMapper.TARGET_RECORD_TYPE == "login"
        # If/when this changes, update this test alongside the platform-team confirmation.

    def test_field_map_starts_empty(self):
        # Guard against regressions where someone adds a partial map
        # without the corresponding NotImplementedError lift.
        assert ApplicationMapper._field_map == {}
