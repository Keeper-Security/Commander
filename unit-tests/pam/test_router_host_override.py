"""
One Router host override (KROUTER_URL), read the same way by every caller.

Either shape of the value (bare host with optional port, or full URL) must give the
same host from `get_router_host` and the same base URL from `get_router_url`, the DAG
connections and the KSM connection.
"""
from unittest.mock import MagicMock

import pytest

from keepercommander.constants import get_router_host
from keepercommander.commands.pam.router_helper import get_router_url
from keepercommander.keeper_dag.connection.ksm import Connection as KsmConnection

BARE = 'router.example:8443'
URL = 'https://router.example:8443'


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ('KROUTER_URL', 'ROUTER_HOST', 'ROUTER_URL', 'USE_SSL'):
        monkeypatch.delenv(name, raising=False)


def _params():
    params = MagicMock()
    params.rest_context.server_base = 'https://keepersecurity.com/api/rest/'
    return params


def _ksm_connection():
    return KsmConnection(config={'hostname': 'keepersecurity.com'})


def test_get_router_host_from_url_override(monkeypatch):
    monkeypatch.setenv('KROUTER_URL', URL)
    assert get_router_host('keepersecurity.com') == BARE


def test_get_router_host_from_bare_override(monkeypatch):
    monkeypatch.setenv('KROUTER_URL', BARE)
    assert get_router_host('keepersecurity.com') == BARE


def test_get_router_url_from_bare_override(monkeypatch):
    monkeypatch.setenv('KROUTER_URL', BARE)
    assert get_router_url(_params()) == URL


def test_get_router_url_from_url_override(monkeypatch):
    monkeypatch.setenv('KROUTER_URL', URL)
    assert get_router_url(_params()) == URL


def test_ksm_http_router_url_from_bare_override(monkeypatch):
    monkeypatch.setenv('KROUTER_URL', BARE)
    assert _ksm_connection().http_router_url_from_ksm_config_or_env() == URL


def test_ksm_http_router_url_from_url_override(monkeypatch):
    monkeypatch.setenv('KROUTER_URL', URL)
    assert _ksm_connection().http_router_url_from_ksm_config_or_env() == URL
