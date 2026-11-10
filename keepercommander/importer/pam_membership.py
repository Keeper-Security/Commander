#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import copy
import fnmatch

from .importer import PathDelimiter, path_components
from .cyberark.pam.safe_utils import sanitize_safe_name

PAM_ROOT_FOLDER_NAME = "PAM Environments"


def membership_safe_name(folder_path):
    """Return the leaf folder/safe name from a membership path."""
    leaf = (folder_path or "").strip().strip("/\\").replace("/", PathDelimiter)
    if not leaf:
        return ""
    comps = list(path_components(leaf))
    return comps[-1] if comps else leaf


def apply_pam_project_prefix(folder_path, project):
    """Map a bare membership path onto PAM Environments/{project}/{safe}.

    Paths already under that project prefix are left unchanged (separators
    normalized to PathDelimiter). CyberArk-style leaf names are sanitized the
    same way PAM import names shared folders.
    """
    project = (project or "").strip().strip("/\\")
    if not project:
        return folder_path

    raw_leaf = (folder_path or "").strip().strip("/\\")
    leaf = raw_leaf.replace("/", PathDelimiter)
    prefix = PathDelimiter.join([PAM_ROOT_FOLDER_NAME, project])
    leaf_cf = leaf.casefold()
    prefix_cf = prefix.casefold()
    if leaf_cf == prefix_cf or leaf_cf.startswith(prefix_cf + PathDelimiter):
        return leaf

    safe_leaf = sanitize_safe_name(raw_leaf)
    return PathDelimiter.join([PAM_ROOT_FOLDER_NAME, project, safe_leaf])


def filter_shared_folders_by_safes(shared_folders, safes_pattern):
    """Keep membership folders whose leaf name matches comma-separated globs."""
    if not safes_pattern or not shared_folders:
        return shared_folders
    patterns = [p.strip() for p in str(safes_pattern).split(",") if p.strip()]
    if not patterns:
        return shared_folders
    matched = []
    for folder in shared_folders:
        name = membership_safe_name(folder.path)
        if any(fnmatch.fnmatch(name, pattern) for pattern in patterns):
            matched.append(folder)
    return matched


def apply_pam_project_to_folders(shared_folders, pam_project):
    """Apply PAM project prefix to shared folder paths without mutating original objects."""
    if not pam_project:
        return shared_folders

    processed_folders = []
    for folder in shared_folders:
        new_folder = copy.copy(folder)
        new_folder.path = apply_pam_project_prefix(folder.path, pam_project)
        new_folder.uid = None
        processed_folders.append(new_folder)

    return processed_folders
