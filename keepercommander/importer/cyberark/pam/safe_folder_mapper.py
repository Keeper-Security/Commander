#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import re

from .constants import MAX_SAFE_NAME_LENGTH

class SafeFolderMapper:
    """Maps CyberArk Safe names to Keeper folder paths with deduplication.

    Modes:
      - ``flat``  : returns ``""`` — all records land in the project's
        Resources/Users folders with no per-safe separation.
      - ``ksm``   : sanitized safe name, max ``MAX_SAFE_NAME_LENGTH`` chars,
        nested under the project Resources/Users folders.
      - ``exact`` : raw safe name, nested under the project Resources/Users
        folders.
      - ``safe``  : sanitized safe name, used as the *root* shared folder name
        under the project wrapper (no Resources/Users prefix). Each safe gets
        its own shared folder with its own CyberArk-derived permission set.
    """

    def __init__(self, mode: str = "flat"):
        self.mode = mode
        self._seen = {}  # sanitized name → count (for dedup)
        self._cache = {}  # raw safe name → resolved folder path

    def map_safe(self, safe_name: str, project_name: str) -> str:
        """Returns folder_path for use in pam_data extend JSON.

        Deduplicates colliding names with #N suffix (e.g. 'Safe #2').
        """
        if self.mode == "flat":
            return ""
        # Return cached result if already mapped (same safe = same folder)
        if safe_name in self._cache:
            return self._cache[safe_name]

        if self.mode == "exact":
            sanitized = safe_name
        elif self.mode in ("ksm", "safe"):
            # ``safe`` reuses the same sanitization rules as ``ksm`` so the
            # resulting shared-folder name is well-formed for the Keeper
            # vault (no URL-escapes, single internal whitespace).
            sanitized = re.sub(r"[^\w\s\-]", "", safe_name)
            sanitized = re.sub(r"\s+", " ", sanitized).strip()
        else:
            sanitized = safe_name

        # Deduplicate: if two safes sanitize to the same name, add #N suffix
        if sanitized in self._seen:
            self._seen[sanitized] += 1
            suffix = f" #{self._seen[sanitized]}"
            if self.mode in ("ksm", "safe"):
                max_base = MAX_SAFE_NAME_LENGTH - len(suffix)
                result = f"{sanitized[:max_base]}{suffix}"
            else:
                result = f"{sanitized}{suffix}"
        else:
            self._seen[sanitized] = 1
            if self.mode in ("ksm", "safe"):
                result = sanitized[:MAX_SAFE_NAME_LENGTH]
            else:
                result = sanitized

        self._cache[safe_name] = result
        return result

    def iter_mapped(self):
        """Yields ``(raw_safe_name, resolved_folder_name)`` pairs for every
        safe that has been mapped so far. Useful for emitting the
        ``safe_folders`` block of the import JSON without round-tripping
        through the records list (which would miss safes whose accounts
        were all skipped).
        """
        for raw, resolved in self._cache.items():
            yield raw, resolved

