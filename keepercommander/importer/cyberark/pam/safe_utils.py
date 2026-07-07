#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — CyberArk PAM import (split module)

import fnmatch
import logging
import re
from typing import Dict, List, Optional

from .constants import MAX_SAFE_NAME_LENGTH, SYSTEM_SAFES

def exclude_system_safes(safes: List[dict], include_system: bool = False) -> List[dict]:
    """Remove CyberArk system/internal safes from the list.

    System safes (VaultInternal, PVWAConfig, etc.) don't contain
    user-managed accounts and should be excluded from migration.
    Override with include_system=True (--include-system-safes flag).
    """
    if include_system:
        return safes
    before = len(safes)
    system_lower = {s.lower() for s in SYSTEM_SAFES}
    filtered = [s for s in safes if s.get("safeName", "").lower() not in system_lower]
    excluded = before - len(filtered)
    if excluded > 0:
        logging.info('Excluded %d system safe(s) from migration', excluded)
    return filtered


def apply_safe_filter(safes: List[dict], include: Optional[str] = None,
                      exclude: Optional[str] = None) -> List[dict]:
    """Filter safes by --safes (include) and --exclude-safes patterns.

    Patterns are comma-separated and support glob matching.
    """
    if include:
        patterns = [p.strip() for p in include.split(",") if p.strip()]
        safes = [s for s in safes if any(fnmatch.fnmatch(s["safeName"], p) for p in patterns)]
    if exclude:
        patterns = [p.strip() for p in exclude.split(",") if p.strip()]
        safes = [s for s in safes if not any(fnmatch.fnmatch(s["safeName"], p) for p in patterns)]
    return safes


def sanitize_safe_name(name: str) -> str:
    """Sanitize a CyberArk safe name for use as a Keeper folder name.

    - Strip/replace characters not allowed in folder names
    - Truncate to MAX_SAFE_NAME_LENGTH
    - Handle dedup by appending suffix if needed
    """
    # Strip control characters (null bytes, newlines, etc.)
    safe = re.sub(r'[\x00-\x1f\x7f]', '', name)
    # Strip path separators
    safe = safe.replace('/', '_').replace('\\', '_').replace('..', '_')
    # Remove leading/trailing whitespace
    safe = safe.strip()
    # Truncate to max length
    if len(safe) > MAX_SAFE_NAME_LENGTH:
        safe = safe[:MAX_SAFE_NAME_LENGTH].rstrip()
    return safe or 'Unnamed-Safe'


def deduplicate_safe_names(safes: List[dict]) -> Dict[str, str]:
    """Build a mapping of safeUrlId → sanitized folder name, deduplicating collisions.

    Returns dict: { safeUrlId: "FolderName" }
    """
    name_map = {}  # safeUrlId → sanitized name
    seen = {}      # sanitized name → count

    for safe in safes:
        url_id = safe.get("safeUrlId", safe.get("safeName", ""))
        raw_name = safe.get("safeName", url_id)
        sanitized = sanitize_safe_name(raw_name)

        if sanitized in seen:
            seen[sanitized] += 1
            suffix = f" #{seen[sanitized]}"
            # Trim base name to fit suffix within MAX_SAFE_NAME_LENGTH
            max_base = MAX_SAFE_NAME_LENGTH - len(suffix)
            sanitized = f"{sanitized[:max_base]}{suffix}"
        else:
            seen[sanitized] = 1

        name_map[url_id] = sanitized

    return name_map
