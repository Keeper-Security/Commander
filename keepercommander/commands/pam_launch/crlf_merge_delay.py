#  _  __
# | |/ /___ ___ _ __  ___ _ _ (R)
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""CRLF partner merge window for ``pam launch`` stdin pipe and key-event Enter paths."""

from __future__ import annotations

import os

# Public: documented in ``pam launch --help``.
PAM_LAUNCH_CRLF_MERGE_DELAY_MS_ENV = "PAM_LAUNCH_CRLF_MERGE_DELAY_MS"
DEFAULT_CRLF_MERGE_DELAY_MS = 50
MIN_CRLF_MERGE_DELAY_MS = 50
MAX_CRLF_MERGE_DELAY_MS = 500


def pam_launch_crlf_merge_delay_ms() -> int:
    """
    Whole milliseconds after a lone ``\\r`` before a partner ``\\n`` may be dropped
    (split CRLF across reads).

    Parsed from :data:`PAM_LAUNCH_CRLF_MERGE_DELAY_MS_ENV` (integer). Values below
    :data:`MIN_CRLF_MERGE_DELAY_MS` or above :data:`MAX_CRLF_MERGE_DELAY_MS` are clamped.
    Invalid or missing values use :data:`DEFAULT_CRLF_MERGE_DELAY_MS`.
    """
    raw = os.environ.get(PAM_LAUNCH_CRLF_MERGE_DELAY_MS_ENV)
    if raw is None or not str(raw).strip():
        return DEFAULT_CRLF_MERGE_DELAY_MS
    s = str(raw).strip()
    try:
        v = int(s, 10)
    except ValueError:
        return DEFAULT_CRLF_MERGE_DELAY_MS
    if v < 0:
        return DEFAULT_CRLF_MERGE_DELAY_MS
    if v < MIN_CRLF_MERGE_DELAY_MS:
        return MIN_CRLF_MERGE_DELAY_MS
    if v > MAX_CRLF_MERGE_DELAY_MS:
        return MAX_CRLF_MERGE_DELAY_MS
    return v


def pam_launch_crlf_merge_delay_sec() -> float:
    """Seconds for ``time.monotonic()`` deadlines (internal use)."""
    return pam_launch_crlf_merge_delay_ms() / 1000.0
