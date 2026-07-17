#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

from .client import CyberArkPVWAClient


class ApplicationMapper:
    """Placeholder for PVWA Application Identity Manager mapping (not yet implemented)."""

    TARGET_RECORD_TYPE = "login"

    _field_map = {}

    def __init__(self, client: CyberArkPVWAClient):
        self._client = client

    def map_application(self, payload: dict) -> dict:
        raise NotImplementedError(
            "ApplicationMapper is not implemented; applications are skipped during import."
        )
