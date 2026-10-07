"""syslog export must emit a valid RFC 5424 HOSTNAME."""
import pytest

import keepercommander.commands.aram as aram


@pytest.fixture(autouse=True)
def seed_templates(monkeypatch):
    # convert_event() reads the module-level template cache, normally loaded from the server.
    monkeypatch.setattr(aram, 'syslog_templates',
                        {'device_approved': 'Device ${device_name} is approved for user ${username}'})


BASE_EVENT = {
    'id': 24983911115,
    'created': 1788369452,  # 2026-09-02T17:17:32Z
    'audit_event_type': 'device_approved',
    'device_name': 'Browser Extension',
    'username': 'test@example.com',
}


def header_hostname(line):
    # HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME ...
    parts = line.split(' ')
    return parts[2], parts[3]


@pytest.mark.parametrize('exporter_cls', [aram.AuditLogSyslogFileExport, aram.AuditLogSyslogPortExport])
@pytest.mark.parametrize('ip_value, expected', [
    (None, '-'),          # key present with null
    ('', '-'),            # empty string — backend may return "" instead of omitting the key
    (' ', '-'),
    ('\t', '-'),
    ('10.0.0.1​', '-'),  # non-printable / non-ASCII
    ('10.0.0.1\x00', '-'),
    ('10.0.12.64', '10.0.12.64'),
    (' 10.0.12.64 ', '10.0.12.64'),
    ('2001:db8::1', '2001:db8::1'),
])
def test_hostname_is_rfc5424_valid(exporter_cls, ip_value, expected):
    event = {**BASE_EVENT, 'ip_address': ip_value}
    line = exporter_cls().convert_event({}, event)
    hostname, app_name = header_hostname(line)
    assert hostname == expected
    assert app_name == 'Keeper'
    assert '  ' not in line.split(' [', 1)[0]


def test_missing_key_still_uses_nilvalue():
    line = aram.AuditLogSyslogFileExport().convert_event({}, dict(BASE_EVENT))
    assert line.startswith('<110>1 2026-09-02T17:17:32Z - Keeper - 24983911115 ')


def test_hostname_truncated_to_255():
    event = {**BASE_EVENT, 'ip_address': 'a' * 300}
    hostname, _ = header_hostname(aram.AuditLogSyslogFileExport().convert_event({}, event))
    assert len(hostname) == 255


def test_ip_address_not_duplicated_in_structured_data():
    event = {**BASE_EVENT, 'ip_address': ''}
    line = aram.AuditLogSyslogFileExport().convert_event({}, event)
    assert 'ip_address=' not in line
