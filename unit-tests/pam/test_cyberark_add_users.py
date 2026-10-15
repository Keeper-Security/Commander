from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from keepercommander.commands.pam_import.cyberark_import import (
    CyberArkImportOrchestrator,
    CyberArkPAMImportCommand,
    ImportRunOptions,
)
from keepercommander.importer.cyberark.pam.import_builder import build_report
import pytest

@pytest.fixture(autouse=True)
def _silence_console():
    with patch[MagicMock | AsyncMock]("keepercommander.commands.pam_import.cyberark_import.print_formatted_text") as mock:
        yield

def _options(**overrides):
    values = dict(
        server="pvwa.example.com",
        project_name="CyberArk Migration",
        config_uid="",
        gateway_name="",
        folder_mode="safe",
        dry_run=False,
        output_file="",
        include_creds=False,
        estimate_only=False,
        skip_confirm=True,
        skip_users=False,
        skip_linked=False,
        skip_members=False,
        skip_dependents=False,
        safe_include="",
        safe_exclude="",
        list_safes=False,
        batch_size=100,
        batch_delay=0.5,
        platform_map_override=None,
        state_filter=None,
        include_system_safes=False,
        user_map_file="",
        add_cyberark_users=False,
    )
    values.update(overrides)
    return ImportRunOptions(**values)

def _orchestrator(client=None, **option_overrides):
    return CyberArkImportOrchestrator(
        CyberArkPAMImportCommand(),
        MagicMock(),
        client or MagicMock(),
        _options(**option_overrides),
    )

def test_add_cyberark_users_flag_defaults_off():
    args = CyberArkPAMImportCommand().parser.parse_args(["pvwa.example.com"])
    assert args.add_cyberark_users is False

def test_add_cyberark_users_flag_parses():
    args = CyberArkPAMImportCommand().parser.parse_args(
        ["pvwa.example.com", "--add-cyberark-users"],
    )
    assert args.add_cyberark_users is True

def test_run_does_not_fetch_users_when_flag_off():
    orchestrator = _orchestrator(add_cyberark_users=False)
    orchestrator._load_master_policy = MagicMock(return_value={})
    orchestrator._prepare_users = MagicMock()
    orchestrator._prepare_safes = MagicMock(return_value=([], 0))
    orchestrator.run()
    orchestrator._prepare_users.assert_not_called()

def test_run_fetches_users_when_flag_on():
    orchestrator = _orchestrator(add_cyberark_users=True)
    orchestrator._load_master_policy = MagicMock(return_value={})
    orchestrator._prepare_users = MagicMock(return_value=[])
    orchestrator._prepare_safes = MagicMock(return_value=([], 0))
    orchestrator.run()
    orchestrator._prepare_users.assert_called_once()

def test_extract_user_email_prefers_business_email():
    email = CyberArkImportOrchestrator._extract_user_email({
        "Internet": {
            "businessEmail": "  ada@example.com  ",
            "homeEmail": "home@example.com",
        },
    })
    assert email == "ada@example.com"

def test_extract_user_email_falls_back_to_flat_then_personal():
    assert CyberArkImportOrchestrator._extract_user_email(
        {"Email": "flat@example.com"},
    ) == "flat@example.com"
    assert CyberArkImportOrchestrator._extract_user_email(
        {"personalDetails": {"email": "personal@example.com"}},
    ) == "personal@example.com"
    assert CyberArkImportOrchestrator._extract_user_email({}) == ""

def test_prepare_users_uses_list_payload_and_fetches_missing_detail():
    client = MagicMock()
    client.fetch_users.return_value = [
        {
            "ID": 1,
            "UserName": "alice",
            "UserType": "EPVUser",
            "Source": "CyberArk",
            "internet": {"businessEmail": "alice@example.com"},
            "groupsMembership": [{"groupName": "Admins"}],
        },
        {"id": 2, "username": "bob"},
        "not-a-dict",
    ]
    client.fetch_user_details.return_value = {
        "internet": {"homeEmail": "bob@example.org"},
        "groupsMembership": [{"groupName": "Ops"}],
    }
    orchestrator = _orchestrator(client)
    orchestrator.DELAY = 0
    users = orchestrator._prepare_users()
    assert users == [
        {
            "id": 1,
            "username": "alice",
            "email": "alice@example.com",
            "type": "EPVUser",
            "source": "CyberArk",
            "groups_membership": [{"groupName": "Admins"}],
        },
        {
            "id": 2,
            "username": "bob",
            "email": "bob@example.org",
            "type": "",
            "source": "",
            "groups_membership": [{"groupName": "Ops"}],
        },
    ]
    client.fetch_user_details.assert_called_once_with(2)

def test_prepare_users_keeps_row_when_detail_fetch_fails():
    client = MagicMock()
    client.fetch_users.return_value = [{"id": 2, "username": "bob"}]
    client.fetch_user_details.side_effect = RuntimeError("down")
    orchestrator = _orchestrator(client)
    orchestrator.DELAY = 0


    users = orchestrator._prepare_users()
    assert users == [{
        "id": 2,
        "username": "bob",
        "email": "",
        "type": "",
        "source": "",
        "groups_membership": [],
    }]

def test_enterprise_data_loaded():
    cmd = CyberArkPAMImportCommand()
    assert cmd._enterprise_data_loaded(None) is False
    assert cmd._enterprise_data_loaded({}) is False
    assert cmd._enterprise_data_loaded({"users": []}) is True
    assert cmd._enterprise_data_loaded({"enterprise_name": "Example"}) is True

def test_load_existing_keeper_users_indexes_username():
    cmd = CyberArkPAMImportCommand()
    params = SimpleNamespace(enterprise={
        "users": [
            {"username": "Alice@Example.com", "email": "ignored@example.com", "status": "active"},
            {"email": "bob@example.org"},
            "not-a-dict",
        ],
    })
    with patch("keepercommander.commands.pam_import.cyberark_import.api.query_enterprise"):
        existing, error = cmd._load_existing_keeper_users(params)
    assert error == ""
    assert set(existing) == {"alice@example.com", "bob@example.org"}
    assert existing["alice@example.com"]["status"] == "active"

def test_load_existing_keeper_users_uses_cache_when_refresh_fails():
    cmd = CyberArkPAMImportCommand()
    params = SimpleNamespace(enterprise={
        "users": [{"username": "alice@example.com", "status": "invited"}],
    })
    def refresh(params):
        params.enterprise = {}
        raise RuntimeError("nope")
    with patch(
        "keepercommander.commands.pam_import.cyberark_import.api.query_enterprise",
        side_effect=refresh,
    ):
        existing, error = cmd._load_existing_keeper_users(params)
    assert error == ""
    assert existing["alice@example.com"]["status"] == "invited"

def test_load_existing_keeper_users_errors_when_nothing_is_loaded():
    cmd = CyberArkPAMImportCommand()
    params = SimpleNamespace(enterprise=None)
    with patch("keepercommander.commands.pam_import.cyberark_import.api.query_enterprise"):
        existing, error = cmd._load_existing_keeper_users(params)
    assert existing == {}
    assert "enterprise admin" in error

def test_create_enterprise_users_creates_any_domain_and_matches_existing():
    cmd = CyberArkPAMImportCommand()
    params = SimpleNamespace(enterprise={
        "enterprise_name": "Example",
        "users": [
            {"username": "alice@example.com", "status": "active"},
            {"username": "bob@example.com", "status": "invited"},
        ],
    })
    with patch(
        "keepercommander.commands.pam_import.cyberark_import.api.query_enterprise",
    ), patch(
        "keepercommander.commands.enterprise_create_user.CreateEnterpriseUserCommand.execute",
        return_value="record-uid",
    ) as create:
        result = cmd._create_enterprise_users(params, [
            {"username": "alice", "email": "alice@example.com"},
            {"username": "bob", "email": "Bob@Example.com"},
            {"username": "carol", "email": "carol@example.com"},
            {"username": "dave", "email": "dave@example.org"},
            {"username": "carol-dup", "email": "carol@example.com"},
            {"username": "svc", "email": ""},
            "not-a-dict",
        ])
    flags = [(row["username"], row["flag"]) for row in result["users"]]
    assert flags == [
        ("alice", "existing"),
        ("bob", "existing"),
        ("carol", "created"),
        ("dave", "created"),
        ("carol-dup", "existing"),
        ("svc", "created"),
    ]
    assert result["users"][0]["status"] == "active"
    assert result["users"][1]["status"] == "invited"
    assert [call.kwargs["email"] for call in create.call_args_list] == [
        "carol@example.com",
        "dave@example.org",
        "",
    ]
    assert create.call_args_list[0].kwargs["name"] == "carol"

def test_create_enterprise_users_flags_create_errors():
    cmd = CyberArkPAMImportCommand()
    params = SimpleNamespace(enterprise={"users": [], "enterprise_name": "Example"})
    with patch(
        "keepercommander.commands.pam_import.cyberark_import.api.query_enterprise",
    ), patch(
        "keepercommander.commands.enterprise_create_user.CreateEnterpriseUserCommand.execute",
        side_effect=[RuntimeError("domain not reserved"), None],
    ):
        result = cmd._create_enterprise_users(params, [
            {"username": "a", "email": "a@example.com"},
            {"username": "b", "email": "b@example.org"},
        ])
    assert result["users"][0]["flag"] == "failed"
    assert result["users"][0]["reason"] == "domain not reserved"
    assert result["users"][1]["flag"] == "failed"
    assert result["users"][1]["reason"] == "user was not created"

def test_create_enterprise_users_fails_every_row_when_enterprise_cannot_load():
    cmd = CyberArkPAMImportCommand()
    params = SimpleNamespace(enterprise=None)
    with patch(
        "keepercommander.commands.pam_import.cyberark_import.api.query_enterprise",
    ), patch(
        "keepercommander.commands.enterprise_create_user.CreateEnterpriseUserCommand.execute",
    ) as create:
        result = cmd._create_enterprise_users(params, [
            {"username": "carol", "email": "carol@example.com"},
            {"username": "dave", "email": "dave@example.org"},
        ])
    assert "enterprise admin" in result["error"]
    assert [row["flag"] for row in result["users"]] == ["failed", "failed"]
    create.assert_not_called()

def test_report_renders_enterprise_user_flags():
    report = build_report(
        project_name="Test",
        safes_processed=1,
        total_accounts=1,
        resource_counts={},
        platform_counts={},
        skipped=[],
        incomplete_count=0,
        duration=1.0,
        enterprise_users={
            "error": "Enterprise users could not be loaded.",
            "users": [
                {"email": "new@example.com", "flag": "created"},
                {"email": "old@example.com", "flag": "existing", "status": "active"},
                {"username": "svc", "email": "", "flag": "skipped", "reason": "no email"},
                {"email": "bad@example.org", "flag": "failed", "reason": "domain not reserved"},
            ],
        },
    )
    assert "ENTERPRISE USERS" in report
    assert "created    1   existing    1   skipped    1   failed    1" in report
    assert "Enterprise users could not be loaded." in report
    assert "[created] new@example.com" in report
    assert "[existing] old@example.com  active" in report
    assert "[skipped] svc  no email" in report
    assert "[failed] bad@example.org  domain not reserved" in report

