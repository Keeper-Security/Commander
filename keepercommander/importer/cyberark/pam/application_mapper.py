#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

from .client import CyberArkPVWAClient


class ApplicationMapper:
    """Maps PVWA Applications (Application Identity Manager) to Keeper records.

    STUB — awaiting real /Applications PVWA samples. Until implemented the
    import driver skips applications with a warning.
    """

    TARGET_RECORD_TYPE = "login"

    _field_map = {}

    def __init__(self, client: CyberArkPVWAClient):
        self._client = client

    def map_application(self, payload: dict) -> dict:
        raise NotImplementedError(
            "ApplicationMapper.map_application awaiting PVWA "
            "/Applications sample. Until then, applications are skipped "
            "with a warning."
        )
