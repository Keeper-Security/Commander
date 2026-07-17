#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)


class RecordKind:
    """PVWA record entity kinds — each maps to a different Keeper mapper."""

    ACCOUNT = "account"
    APPLICATION = "application"
    API_TOKEN = "api_token"


def discriminate_record_kind(payload: dict) -> str:
    """Return the RecordKind for a PVWA payload."""
    if not isinstance(payload, dict):
        return RecordKind.ACCOUNT
    if "AppID" in payload:
        return RecordKind.APPLICATION
    if payload.get("platformType") == "Application":
        return RecordKind.API_TOKEN
    return RecordKind.ACCOUNT
