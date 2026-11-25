"""``nsf_helpers.fetch_file_record_infos``: file records of an NSF record are fetched by uid (QA 2026-11-19)."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from keepercommander import crypto, utils
from keepercommander.commands.pam_import import nsf_helpers as nh
from keepercommander.proto import record_details_pb2, record_pb2


def make_response(data_key, files):
    rs = record_details_pb2.RecordDataResponse()
    for uid, payload in files.items():
        rd = rs.data.add()
        rd.recordUid = utils.base64_url_decode(uid)
        rd.version = 4
        record_key = utils.generate_aes_key()
        rd.recordKeyType = record_pb2.ENCRYPTED_BY_DATA_KEY_GCM
        rd.recordKey = crypto.encrypt_aes_v2(record_key, data_key)
        rd.encryptedRecordData = utils.base64_url_encode(crypto.encrypt_aes_v2(json.dumps(payload).encode(), record_key))
    return rs


class TestFetchFileRecordInfos(unittest.TestCase):
    def setUp(self):
        self.key = utils.generate_aes_key()
        self.params = SimpleNamespace(data_key=self.key)
        self.u1, self.u2 = utils.generate_uid(), utils.generate_uid()

    def test_name_and_size_come_from_the_decrypted_data(self):
        rs = make_response(self.key, {self.u1: {'name': 'run.sh', 'size': 19, 'title': 'run.sh',
                                                  'type': 'application/octet-stream', 'lastModified': 5}})
        with patch.object(nh.api, 'communicate_rest', return_value=rs) as call:
            out = nh.fetch_file_record_infos(self.params, [self.u1, self.u2, self.u1])
        self.assertEqual(call.call_args[0][2], 'vault/records/v3/details/data')
        self.assertEqual(len(call.call_args[0][1].recordUids), 2)             # de-duplicated, one request
        self.assertEqual(out, {self.u1: {'record_uid': self.u1, 'name': 'run.sh', 'size': 19,
                                         'mime_type': 'application/octet-stream', 'last_modified': 5}})

    def test_a_failing_request_or_a_wrong_key_gives_nothing_not_an_exception(self):
        with patch.object(nh.api, 'communicate_rest', side_effect=RuntimeError('down')):
            self.assertEqual(nh.fetch_file_record_infos(self.params, [self.u1]), {})
        rs = make_response(utils.generate_aes_key(), {self.u1: {'name': 'x', 'size': 1}})    # encrypted with ANOTHER data key
        with patch.object(nh.api, 'communicate_rest', return_value=rs):
            self.assertEqual(nh.fetch_file_record_infos(self.params, [self.u1]), {})

    def test_no_uids_no_request(self):
        with patch.object(nh.api, 'communicate_rest') as call:
            self.assertEqual(nh.fetch_file_record_infos(self.params, []), {})
        call.assert_not_called()


if __name__ == '__main__':
    unittest.main()
