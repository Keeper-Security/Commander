"""Shared fixtures for PAM import tests."""
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def mock_stdin_tty():
    """Ensure sys.stdin.isatty() returns True in test environment."""
    with patch('keepercommander.commands.pam_import.kcm_import.sys.stdin') as mock_stdin:
        mock_stdin.isatty.return_value = True
        yield mock_stdin
