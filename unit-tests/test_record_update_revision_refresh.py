"""Regression tests: update_record must leave params.record_cache at the revision
the server just returned.

update_record puts the revision from the cache (not from the record object) on the
wire, so a second update of the same record inside one command used to resend the
pre-update revision and fail with RS_OUT_OF_SYNC ("This object no longer exists").
"""
import json
from types import SimpleNamespace
from unittest.mock import patch

from keepercommander import crypto, record_management, utils, vault
from keepercommander.proto import record_pb2

RECORD_UID = 'wKpRON0rxJfq6qefq43y7g'
RECORD_KEY = b'k' * 32


def _params():
    data = {'type': 'pamMachine', 'title': 'Machine', 'fields': [], 'custom': []}
    plain = json.dumps(data).encode()
    return SimpleNamespace(
        record_cache={
            RECORD_UID: {
                'record_uid': RECORD_UID,
                'version': 3,
                'revision': 5380934,
                'client_modified_time': 1787187441498,
                'shared': True,
                'data': utils.base64_url_encode(crypto.encrypt_aes_v2(plain, RECORD_KEY)),
                'data_unencrypted': plain,
                'record_key_unencrypted': RECORD_KEY,
            }
        },
        enterprise_ec_key=None,
        enterprise_rsa_key=None,
        breach_watch=None,
        sync_data=False,
        forbid_rsa=False,
    )


def _record(params, title='Machine'):
    record = vault.KeeperRecord.load(params, RECORD_UID)
    record.title = title
    return record


def _run_update(params, record, new_revision):
    """Drive update_record with a stubbed transport; return the revision sent."""
    sent = {}

    def fake_communicate_rest(_params, rq, endpoint, rs_type=None):
        assert endpoint == 'vault/records_update'
        sent['revision'] = rq.records[0].revision
        sent['data'] = rq.records[0].data
        rs = record_pb2.RecordsModifyResponse()
        rs.revision = new_revision
        status = rs.records.add()
        status.record_uid = utils.base64_url_decode(RECORD_UID)
        status.status = record_pb2.RS_SUCCESS
        return rs

    with patch('keepercommander.record_management.api.communicate_rest',
               side_effect=fake_communicate_rest), \
            patch('keepercommander.record_management.attach_security_data',
                  side_effect=lambda _p, _r, ru: ru), \
            patch('keepercommander.record_management.add_record_audit_data'), \
            patch('keepercommander.record_management.BreachWatch.scan_and_update_security_data'):
        record_management.update_record(params, record)
    return sent


def test_update_record_refreshes_cached_revision():
    params = _params()
    sent = _run_update(params, _record(params), 5380938)

    assert sent['revision'] == 5380934, 'first update sends the cached revision'
    assert params.record_cache[RECORD_UID]['revision'] == 5380938


def test_second_update_in_same_run_sends_fresh_revision():
    # The failure mode from the log: two writes on one record with no sync between.
    params = _params()
    first = _run_update(params, _record(params, 'First'), 5380938)
    second = _run_update(params, _record(params, 'Second'), 5380942)

    assert first['revision'] == 5380934
    assert second['revision'] == 5380938, 'stale revision would be rejected as RS_OUT_OF_SYNC'
    assert params.record_cache[RECORD_UID]['revision'] == 5380942


def test_update_record_keeps_cached_payload_consistent_with_revision():
    # A bumped revision paired with stale data would make the next load return
    # pre-update fields; the cache must carry what was actually persisted.
    params = _params()
    record = _record(params, 'Renamed')
    sent = _run_update(params, record, 5380938)

    cached = params.record_cache[RECORD_UID]
    assert cached['data'] == utils.base64_url_encode(sent['data'])
    assert json.loads(cached['data_unencrypted'])['title'] == 'Renamed'
    assert vault.KeeperRecord.load(params, RECORD_UID).title == 'Renamed'
    assert crypto.decrypt_aes_v2(utils.base64_url_decode(cached['data']), RECORD_KEY) \
        == cached['data_unencrypted']


def test_update_record_leaves_cache_untouched_when_revision_missing():
    params = _params()
    before = dict(params.record_cache[RECORD_UID])
    _run_update(params, _record(params), 0)

    assert params.record_cache[RECORD_UID]['revision'] == before['revision']
    assert params.record_cache[RECORD_UID]['data'] == before['data']
