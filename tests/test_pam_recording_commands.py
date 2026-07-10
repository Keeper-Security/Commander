"""Tests for PAM recording commands (PR-212 / get_recordings_for_users)."""

import json
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch, call

from keepercommander.commands.pam.recording_commands import (
    PAMGetRecordingsForUsersCommand,
    PAMDownloadRecordingsCommand,
    RECORDING_TYPE_NAMES,
    RISK_LEVEL_NAMES,
    _parse_dt,
    _fmt_ts,
    _get_record_key,
    _download_one,
    _DOWNLOAD_WORKERS,
)
from keepercommander.proto import pam_pb2


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_recording(**kwargs):
    """Build a PAMRecording proto with sensible defaults."""
    rec = pam_pb2.PAMRecording()
    rec.connectionUid = bytes.fromhex(kwargs.get('connectionUid', 'deadbeef' * 4))
    rec.recordUid = bytes.fromhex(kwargs.get('recordUid', 'cafebabe' * 4))
    rec.userName = kwargs.get('userName', 'alice@example.com')
    rec.recordingType = kwargs.get('recordingType', pam_pb2.PRT_SESSION)
    rec.protocol = kwargs.get('protocol', 'SSH')
    rec.startedOn = kwargs.get('startedOn', int(time.time()) * 1000)
    rec.length = kwargs.get('length', 120)
    rec.fileSize = kwargs.get('fileSize', 4096)
    rec.createdOn = kwargs.get('createdOn', int(time.time()) * 1000)
    rec.aiOverallRiskLevel = kwargs.get('aiOverallRiskLevel', pam_pb2.PRR_UNSPECIFIED)
    return rec


def _make_response(recordings, has_more=False):
    rs = pam_pb2.PAMRecordingsResponse()
    rs.recordings.extend(recordings)
    rs.hasMore = has_more
    return rs


def _make_params(record_key=None, record_uid_hex='cafebabe' * 4):
    """Return a mock params object with a record_cache entry."""
    params = MagicMock()
    import base64
    uid_bytes = bytes.fromhex(record_uid_hex)
    uid_str = base64.urlsafe_b64encode(uid_bytes).rstrip(b'=').decode()
    if record_key is not None:
        params.record_cache = {uid_str: {'record_key_unencrypted': record_key}}
    else:
        params.record_cache = {}
    return params


FAKE_KEY = b'\x00' * 32
FAKE_PLAINTEXT = b'decrypted session data'

def _make_fake_recording_bytes(record_key=FAKE_KEY):
    """Build a minimal valid recording wire format so _decrypt_recording_file succeeds."""
    import base64, json, struct
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    import os

    conv_uid_b64 = base64.b64encode(b'\xde\xad\xbe\xef' * 4).decode()  # standard b64 (with +/=)
    nonce = os.urandom(12)
    salt = os.urandom(12)
    salt_b64 = base64.b64encode(salt).decode()

    # derive resource key
    info = f"{conv_uid_b64}_RECORDING-SESSION_AES-GCM-256".encode()
    resource_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(record_key)

    # recording secret
    recording_secret = os.urandom(32)
    private_meta = json.dumps({'recordingSecret': base64.b64encode(recording_secret).decode(),
                               'resourceIp': '127.0.0.1', 'resourcePort': '22',
                               'startTime': 0, 'userName': 'test'}).encode()
    resource_data_nonce = os.urandom(12)
    resource_data_enc = resource_data_nonce + AESGCM(resource_key).encrypt(resource_data_nonce, private_meta, None)
    resource_data_b64 = base64.b64encode(resource_data_enc).decode()

    ad = {'conversationUid': conv_uid_b64, 'recordingType': 'ses',
          'resourceKeysSalt': salt_b64, 'resourceUid': 'AAAA',
          'resourceData': resource_data_b64, 'userData': ''}
    ad_bytes = json.dumps(ad).encode()
    ad_len_bytes = struct.pack('>I', len(ad_bytes))

    # encrypt recording data
    recording_ct = AESGCM(recording_secret).encrypt(nonce, FAKE_PLAINTEXT, ad_bytes)

    return ad_len_bytes + ad_bytes + b';' + nonce + recording_ct


# ---------------------------------------------------------------------------
# _parse_dt
# ---------------------------------------------------------------------------

class TestParseDt(unittest.TestCase):
    def test_date_only(self):
        dt = _parse_dt('2025-03-15')
        self.assertEqual((dt.year, dt.month, dt.day), (2025, 3, 15))

    def test_datetime_T(self):
        dt = _parse_dt('2025-03-15T08:30:00')
        self.assertEqual(dt.hour, 8)

    def test_datetime_space(self):
        dt = _parse_dt('2025-03-15 08:30:00')
        self.assertEqual(dt.hour, 8)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            _parse_dt('not-a-date')


# ---------------------------------------------------------------------------
# _fmt_ts
# ---------------------------------------------------------------------------

class TestFmtTs(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(_fmt_ts(0), '')

    def test_none(self):
        self.assertEqual(_fmt_ts(None), '')

    def test_known_epoch(self):
        # 1000 ms = 1 second past epoch → still 1970
        self.assertIn('1970', _fmt_ts(1000))


# ---------------------------------------------------------------------------
# _get_record_key
# ---------------------------------------------------------------------------

class TestGetRecordKey(unittest.TestCase):
    def test_found(self):
        params = _make_params(record_key=FAKE_KEY)
        key = _get_record_key(params, bytes.fromhex('cafebabe' * 4))
        self.assertEqual(key, FAKE_KEY)

    def test_not_found(self):
        params = _make_params(record_key=None)
        key = _get_record_key(params, bytes.fromhex('cafebabe' * 4))
        self.assertIsNone(key)


# ---------------------------------------------------------------------------
# _download_one
# ---------------------------------------------------------------------------

class TestDownloadOne(unittest.TestCase):
    def test_success(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                       return_value=_make_fake_recording_bytes(FAKE_KEY)):
                filename, nbytes, err = _download_one(
                    MagicMock(), bytes.fromhex('deadbeef' * 4), 'ses', tmpdir, FAKE_KEY)
        self.assertIsNone(err)
        self.assertEqual(nbytes, len(FAKE_PLAINTEXT))
        self.assertTrue(filename.endswith('.ses'))

    def test_router_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                       side_effect=Exception('404')):
                filename, nbytes, err = _download_one(
                    MagicMock(), bytes.fromhex('deadbeef' * 4), 'ses', tmpdir, FAKE_KEY)
        self.assertIsNotNone(err)
        self.assertEqual(nbytes, 0)

    def test_decrypt_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                       return_value=b'invalid-garbage-bytes'):
                _, nbytes, err = _download_one(
                    MagicMock(), bytes.fromhex('deadbeef' * 4), 'ses', tmpdir, FAKE_KEY)
        self.assertIsNotNone(err)


# ---------------------------------------------------------------------------
# PAMGetRecordingsForUsersCommand (list-by-user)
# ---------------------------------------------------------------------------

class TestPAMGetRecordingsForUsersCommand(unittest.TestCase):

    def _run(self, router_return, **kwargs):
        cmd = PAMGetRecordingsForUsersCommand()
        params = _make_params(record_key=FAKE_KEY)
        with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                   return_value=router_return) as mock_router:
            cmd.execute(params, **kwargs)
        return mock_router

    def test_basic_request_shape(self):
        rs = _make_response([_make_recording()])
        mock = self._run(rs, usernames=['alice@example.com'], output_format='json')
        rq = mock.call_args[0][1]
        self.assertIsInstance(rq, pam_pb2.PAMRecordingsForUsersRequest)
        self.assertIn('alice@example.com', rq.usernames)
        self.assertEqual(rq.maxCount, 0)

    def test_multiple_usernames(self):
        rs = _make_response([])
        mock = self._run(rs, usernames=['alice@example.com', 'bob@example.com'])
        rq = mock.call_args[0][1]
        self.assertIn('alice@example.com', rq.usernames)
        self.assertIn('bob@example.com', rq.usernames)

    def test_max_count(self):
        rs = _make_response([])
        mock = self._run(rs, usernames=['u@x.com'], max_count=50)
        self.assertEqual(mock.call_args[0][1].maxCount, 50)

    def test_range_filters(self):
        rs = _make_response([])
        mock = self._run(rs, usernames=['u@x.com'],
                         range_start='2025-01-01', range_end='2025-12-31')
        rq = mock.call_args[0][1]
        self.assertTrue(rq.HasField('rangeStart'))
        self.assertTrue(rq.HasField('rangeEnd'))
        self.assertGreater(rq.rangeEnd, rq.rangeStart)

    def test_type_filter(self):
        rs = _make_response([])
        mock = self._run(rs, usernames=['u@x.com'], types=['session', 'typescript'])
        rq = mock.call_args[0][1]
        self.assertIn(pam_pb2.PRT_SESSION, rq.types)
        self.assertIn(pam_pb2.PRT_TYPESCRIPT, rq.types)

    def test_risk_filter(self):
        rs = _make_response([])
        mock = self._run(rs, usernames=['u@x.com'], risks=['high', 'critical'])
        rq = mock.call_args[0][1]
        self.assertIn(pam_pb2.PRR_HIGH, rq.risks)
        self.assertIn(pam_pb2.PRR_CRITICAL, rq.risks)

    def test_protocol_filter(self):
        rs = _make_response([])
        mock = self._run(rs, usernames=['u@x.com'], protocols=['SSH', 'RDP'])
        rq = mock.call_args[0][1]
        self.assertIn('SSH', rq.protocols)
        self.assertIn('RDP', rq.protocols)

    def test_empty_usernames_aborts(self):
        cmd = PAMGetRecordingsForUsersCommand()
        with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users') as mock:
            cmd.execute(MagicMock(), usernames=[])
            mock.assert_not_called()

    def test_none_response(self):
        printed = []
        cmd = PAMGetRecordingsForUsersCommand()
        with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                   return_value=None), \
             patch('builtins.print', side_effect=printed.append):
            cmd.execute(MagicMock(), usernames=['u@x.com'])
        self.assertTrue(any('No response' in str(p) for p in printed))

    def test_router_error(self):
        cmd = PAMGetRecordingsForUsersCommand()
        with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                   side_effect=Exception('network error')):
            cmd.execute(MagicMock(), usernames=['u@x.com'])  # must not raise

    def test_json_output_shape(self):
        rec = _make_recording(userName='alice@example.com', protocol='SSH',
                               aiOverallRiskLevel=pam_pb2.PRR_HIGH)
        rs = _make_response([rec], has_more=True)
        lines = []
        cmd = PAMGetRecordingsForUsersCommand()
        with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                   return_value=rs), \
             patch('builtins.print', side_effect=lambda x: lines.append(x)):
            cmd.execute(MagicMock(), usernames=['alice@example.com'], output_format='json')
        data = json.loads('\n'.join(lines))
        self.assertIn('recordings', data)
        self.assertTrue(data['hasMore'])
        row = data['recordings'][0]
        self.assertEqual(row['userName'], 'alice@example.com')
        self.assertEqual(row['aiOverallRiskLevel'], 'high')

    def test_json_output_to_file(self):
        rec = _make_recording()
        rs = _make_response([rec])
        cmd = PAMGetRecordingsForUsersCommand()
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            outpath = f.name
        try:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs):
                cmd.execute(MagicMock(), usernames=['u@x.com'], output=outpath)
            with open(outpath) as f:
                data = json.load(f)
            self.assertIn('recordings', data)
        finally:
            os.unlink(outpath)

    def test_output_format_inferred_from_csv_extension(self):
        rs = _make_response([_make_recording()])
        cmd = PAMGetRecordingsForUsersCommand()
        with tempfile.NamedTemporaryFile(suffix='.csv', delete=False) as f:
            outpath = f.name
        try:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs), \
                 patch('keepercommander.commands.pam.recording_commands.dump_report_data') as mock_dump:
                cmd.execute(MagicMock(), usernames=['u@x.com'], output=outpath)
            fmt_used = mock_dump.call_args[1].get('fmt') or mock_dump.call_args[0][2]
            self.assertEqual(fmt_used, 'csv')
        finally:
            os.unlink(outpath)

    def test_download_dir_triggers_download(self):
        rec = _make_recording()
        rs = _make_response([rec])
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs), \
                 patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                       return_value=_make_fake_recording_bytes(FAKE_KEY)) as mock_dl:
                params = _make_params(record_key=FAKE_KEY, record_uid_hex='cafebabe' * 4)
                cmd = PAMGetRecordingsForUsersCommand()
                cmd.execute(params, usernames=['u@x.com'], download_dir=tmpdir)
            mock_dl.assert_called()

    def test_download_dir_skips_missing_record_key(self):
        rec = _make_recording()
        rs = _make_response([rec])
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs), \
                 patch('keepercommander.commands.pam.recording_commands.router_download_recording') as mock_dl:
                params = _make_params(record_key=None)  # no key in cache
                cmd = PAMGetRecordingsForUsersCommand()
                cmd.execute(params, usernames=['u@x.com'], download_dir=tmpdir)
            mock_dl.assert_not_called()


# ---------------------------------------------------------------------------
# PAMDownloadRecordingsCommand
# ---------------------------------------------------------------------------

class TestPAMDownloadRecordingsCommand(unittest.TestCase):

    def test_connection_uid_requires_record_uid(self):
        cmd = PAMDownloadRecordingsCommand()
        with patch('keepercommander.commands.pam.recording_commands.router_download_recording') as mock_dl:
            cmd.execute(MagicMock(), connection_uid=['deadbeef' * 4])
            mock_dl.assert_not_called()

    def test_invalid_connection_uid_hex(self):
        cmd = PAMDownloadRecordingsCommand()
        params = _make_params(record_key=FAKE_KEY)
        with patch('keepercommander.commands.pam.recording_commands.router_download_recording') as mock_dl:
            cmd.execute(params,
                        connection_uid=['not-hex'],
                        record_uid='cafebabe' * 4,
                        output_dir='/tmp')
            mock_dl.assert_not_called()

    def test_invalid_record_uid_hex(self):
        cmd = PAMDownloadRecordingsCommand()
        with patch('keepercommander.commands.pam.recording_commands.router_download_recording') as mock_dl:
            cmd.execute(MagicMock(),
                        connection_uid=['deadbeef' * 4],
                        record_uid='not-hex',
                        output_dir='/tmp')
            mock_dl.assert_not_called()

    def test_record_key_not_in_cache(self):
        cmd = PAMDownloadRecordingsCommand()
        params = _make_params(record_key=None)  # empty cache
        with patch('keepercommander.commands.pam.recording_commands.router_download_recording') as mock_dl:
            cmd.execute(params,
                        connection_uid=['deadbeef' * 4],
                        record_uid='cafebabe' * 4,
                        output_dir='/tmp')
            mock_dl.assert_not_called()

    def test_single_connection_uid_downloads_and_decrypts(self):
        cmd = PAMDownloadRecordingsCommand()
        params = _make_params(record_key=FAKE_KEY, record_uid_hex='cafebabe' * 4)
        fake_wire = _make_fake_recording_bytes(FAKE_KEY)
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                       return_value=fake_wire):
                cmd.execute(params,
                            connection_uid=['deadbeef' * 4],
                            record_uid='cafebabe' * 4,
                            output_dir=tmpdir,
                            types=['session'])
            saved = [f for f in os.listdir(tmpdir) if f.endswith('.ses')]
            self.assertEqual(len(saved), 1)
            with open(os.path.join(tmpdir, saved[0]), 'rb') as f:
                self.assertEqual(f.read(), FAKE_PLAINTEXT)

    def test_multiple_connection_uids(self):
        cmd = PAMDownloadRecordingsCommand()
        params = _make_params(record_key=FAKE_KEY, record_uid_hex='cafebabe' * 4)
        uid1 = 'deadbeef' * 4
        uid2 = 'beefdead' * 4
        fake_wire = _make_fake_recording_bytes(FAKE_KEY)
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                       return_value=fake_wire):
                cmd.execute(params,
                            connection_uid=[uid1, uid2],
                            record_uid='cafebabe' * 4,
                            output_dir=tmpdir,
                            types=['session'])
            saved = [f for f in os.listdir(tmpdir) if f.endswith('.ses')]
            self.assertEqual(len(saved), 2)

    def test_username_mode_no_results(self):
        cmd = PAMDownloadRecordingsCommand()
        rs = _make_response([])
        printed = []
        with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                   return_value=rs), \
             patch('builtins.print', side_effect=printed.append):
            cmd.execute(MagicMock(), usernames=['u@x.com'])
        self.assertTrue(any('No recordings' in str(p) for p in printed))

    def test_username_mode_downloads_with_decryption(self):
        rec = _make_recording()
        rs = _make_response([rec])
        params = _make_params(record_key=FAKE_KEY, record_uid_hex='cafebabe' * 4)
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs), \
                 patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                       return_value=_make_fake_recording_bytes(FAKE_KEY)):
                cmd = PAMDownloadRecordingsCommand()
                cmd.execute(params, usernames=['alice@example.com'], output_dir=tmpdir)
            saved = os.listdir(tmpdir)
            self.assertTrue(len(saved) > 0)
            with open(os.path.join(tmpdir, saved[0]), 'rb') as f:
                self.assertEqual(f.read(), FAKE_PLAINTEXT)

    def test_username_mode_skips_missing_key(self):
        rec = _make_recording()
        rs = _make_response([rec])
        params = _make_params(record_key=None)  # no key
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs), \
                 patch('keepercommander.commands.pam.recording_commands.router_download_recording') as mock_dl:
                cmd = PAMDownloadRecordingsCommand()
                cmd.execute(params, usernames=['alice@example.com'], output_dir=tmpdir)
            mock_dl.assert_not_called()

    def test_username_mode_type_filter(self):
        rec = _make_recording(recordingType=pam_pb2.PRT_SESSION)
        rs = _make_response([rec])
        params = _make_params(record_key=FAKE_KEY, record_uid_hex='cafebabe' * 4)
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs), \
                 patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                       return_value=_make_fake_recording_bytes(FAKE_KEY)) as mock_dl:
                cmd = PAMDownloadRecordingsCommand()
                cmd.execute(params, usernames=['u@x.com'],
                            types=['session'], output_dir=tmpdir)
            # should only request .ses, not all 4 types
            calls = mock_dl.call_args_list
            exts = [c[0][2] for c in calls]
            self.assertEqual(exts, ['ses'])

    def test_router_error_in_username_mode(self):
        cmd = PAMDownloadRecordingsCommand()
        with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                   side_effect=Exception('network error')):
            cmd.execute(MagicMock(), usernames=['u@x.com'])  # must not raise

    def test_none_response_in_username_mode(self):
        printed = []
        cmd = PAMDownloadRecordingsCommand()
        with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                   return_value=None), \
             patch('builtins.print', side_effect=printed.append):
            cmd.execute(MagicMock(), usernames=['u@x.com'])
        self.assertTrue(any('No response' in str(p) for p in printed))

    def test_has_more_warning_printed(self):
        rec = _make_recording()
        rs = _make_response([rec], has_more=True)
        params = _make_params(record_key=FAKE_KEY, record_uid_hex='cafebabe' * 4)
        printed = []
        with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                   return_value=rs), \
             patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                   return_value=_make_fake_recording_bytes(FAKE_KEY)), \
             patch('builtins.print', side_effect=printed.append):
            cmd = PAMDownloadRecordingsCommand()
            with tempfile.TemporaryDirectory() as tmpdir:
                cmd.execute(params, usernames=['u@x.com'], output_dir=tmpdir)
        self.assertTrue(any('more' in str(p).lower() for p in printed))


# ---------------------------------------------------------------------------
# get_parser (covers argparse setup lines)
# ---------------------------------------------------------------------------

class TestGetParser(unittest.TestCase):
    def test_lbu_parser_returns_parser(self):
        parser = PAMGetRecordingsForUsersCommand().get_parser()
        self.assertIsNotNone(parser)

    def test_dl_parser_returns_parser(self):
        parser = PAMDownloadRecordingsCommand().get_parser()
        self.assertIsNotNone(parser)

    def test_lbu_parser_has_download_dir(self):
        parser = PAMGetRecordingsForUsersCommand().get_parser()
        args = parser.parse_args(['user@example.com', '--download-dir', '/tmp/recs'])
        self.assertEqual(args.download_dir, '/tmp/recs')

    def test_dl_parser_has_output_dir(self):
        parser = PAMDownloadRecordingsCommand().get_parser()
        args = parser.parse_args(['--usernames', 'user@example.com', '--output-dir', '/tmp/recs'])
        self.assertEqual(args.output_dir, '/tmp/recs')

    def test_lbu_parser_filter_args(self):
        parser = PAMGetRecordingsForUsersCommand().get_parser()
        args = parser.parse_args(['u@x.com', '--types', 'session', '--risks', 'high',
                                   '--protocols', 'SSH', '--max-count', '10'])
        self.assertEqual(args.types, ['session'])
        self.assertEqual(args.risks, ['high'])
        self.assertEqual(args.max_count, 10)


# ---------------------------------------------------------------------------
# Legacy salt path (line 85)
# ---------------------------------------------------------------------------

class TestDecryptLegacySalt(unittest.TestCase):
    def test_no_resource_keys_salt_uses_nonce(self):
        """When resourceKeysSalt is absent, the nonce is used as the salt."""
        import base64 as b64, struct
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from keepercommander.commands.pam.recording_commands import _decrypt_recording_file
        import os

        record_key = FAKE_KEY
        conv_uid_b64 = b64.b64encode(b'\xaa\xbb\xcc\xdd' * 4).decode()
        nonce = os.urandom(12)

        # Use nonce as salt (legacy path — no resourceKeysSalt key in AD)
        info = f"{conv_uid_b64}_RECORDING-SESSION_AES-GCM-256".encode()
        resource_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=nonce, info=info).derive(record_key)

        recording_secret = os.urandom(32)
        private_meta = json.dumps({'recordingSecret': b64.b64encode(recording_secret).decode()}).encode()
        rd_nonce = os.urandom(12)
        resource_data_enc = rd_nonce + AESGCM(resource_key).encrypt(rd_nonce, private_meta, None)

        # No 'resourceKeysSalt' key
        ad = {'conversationUid': conv_uid_b64, 'resourceData': b64.b64encode(resource_data_enc).decode()}
        ad_bytes = json.dumps(ad).encode()
        ad_len_bytes = struct.pack('>I', len(ad_bytes))
        plaintext_msg = b'legacy plaintext'
        ct = AESGCM(recording_secret).encrypt(nonce, plaintext_msg, ad_bytes)

        wire = ad_len_bytes + ad_bytes + b';' + nonce + ct
        result = _decrypt_recording_file(wire, record_key)
        self.assertEqual(result, plaintext_msg)


# ---------------------------------------------------------------------------
# _download_recording_files error path (line 184)
# ---------------------------------------------------------------------------

class TestDownloadRecordingFilesError(unittest.TestCase):
    def test_error_logged_when_download_fails(self):
        from keepercommander.commands.pam.recording_commands import _download_recording_files
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                       side_effect=Exception('server error')), \
                 patch('keepercommander.commands.pam.recording_commands.logging') as mock_log:
                _download_recording_files(MagicMock(), bytes(16), ['ses'], tmpdir, FAKE_KEY)
                mock_log.warning.assert_called()


# ---------------------------------------------------------------------------
# _download_recordings edge cases (lines 198, 212-213, 224)
# ---------------------------------------------------------------------------

class TestDownloadRecordingsEdgeCases(unittest.TestCase):
    def test_skips_recording_with_no_connection_uid(self):
        from keepercommander.commands.pam.recording_commands import _download_recordings
        rec = _make_recording()
        rec.ClearField('connectionUid')  # empty bytes
        printed = []
        with patch('keepercommander.commands.pam.recording_commands.router_download_recording') as mock_dl, \
             patch('builtins.print', side_effect=printed.append):
            _download_recordings(_make_params(FAKE_KEY), [rec], [], '/tmp/noop_dir')
        mock_dl.assert_not_called()
        self.assertTrue(any('Nothing' in str(p) for p in printed))

    def test_nothing_to_download_when_all_keys_missing(self):
        from keepercommander.commands.pam.recording_commands import _download_recordings
        rec = _make_recording()
        params = _make_params(record_key=None)  # no keys
        printed = []
        with patch('builtins.print', side_effect=printed.append):
            with tempfile.TemporaryDirectory() as tmpdir:
                _download_recordings(params, [rec], [], tmpdir)
        self.assertTrue(any('Nothing' in str(p) for p in printed))

    def test_error_in_parallel_loop_logged(self):
        from keepercommander.commands.pam.recording_commands import _download_recordings
        rec = _make_recording()
        params = _make_params(record_key=FAKE_KEY, record_uid_hex='cafebabe' * 4)
        with patch('keepercommander.commands.pam.recording_commands.router_download_recording',
                   side_effect=Exception('download failed')), \
             patch('keepercommander.commands.pam.recording_commands.logging') as mock_log:
            with tempfile.TemporaryDirectory() as tmpdir:
                _download_recordings(params, [rec], [], tmpdir)
            mock_log.warning.assert_called()


# ---------------------------------------------------------------------------
# Grid output format (.md / .txt extension → line 281)
# ---------------------------------------------------------------------------

class TestGridOutputFormat(unittest.TestCase):
    def test_md_extension_uses_grid_format(self):
        rec = _make_recording()
        rs = _make_response([rec])
        cmd = PAMGetRecordingsForUsersCommand()
        with tempfile.NamedTemporaryFile(suffix='.md', delete=False) as f:
            outpath = f.name
        try:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs), \
                 patch('keepercommander.commands.pam.recording_commands.dump_report_data') as mock_dump:
                cmd.execute(MagicMock(), usernames=['u@x.com'], output=outpath)
            fmt_used = mock_dump.call_args[1].get('fmt') or mock_dump.call_args[0][2]
            self.assertEqual(fmt_used, 'grid')
        finally:
            os.unlink(outpath)

    def test_txt_extension_uses_grid_format(self):
        rec = _make_recording()
        rs = _make_response([rec])
        cmd = PAMGetRecordingsForUsersCommand()
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            outpath = f.name
        try:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs), \
                 patch('keepercommander.commands.pam.recording_commands.dump_report_data') as mock_dump:
                cmd.execute(MagicMock(), usernames=['u@x.com'], output=outpath)
            fmt_used = mock_dump.call_args[1].get('fmt') or mock_dump.call_args[0][2]
            self.assertEqual(fmt_used, 'grid')
        finally:
            os.unlink(outpath)


# ---------------------------------------------------------------------------
# _print_table with output_file (lines 406-407)
# ---------------------------------------------------------------------------

class TestPrintTableOutputFile(unittest.TestCase):
    def test_table_written_to_txt_file(self):
        rec = _make_recording()
        rs = _make_response([rec])
        cmd = PAMGetRecordingsForUsersCommand()
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            outpath = f.name
        try:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs), \
                 patch('keepercommander.commands.pam.recording_commands.dump_report_data'):
                cmd.execute(MagicMock(), usernames=['u@x.com'], output=outpath)
        finally:
            os.unlink(outpath)


# ---------------------------------------------------------------------------
# _print_json to file (lines 435-438)
# ---------------------------------------------------------------------------

class TestPrintJsonToFile(unittest.TestCase):
    def test_json_written_to_file(self):
        rec = _make_recording()
        rs = _make_response([rec])
        cmd = PAMGetRecordingsForUsersCommand()
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            outpath = f.name
        try:
            with patch('keepercommander.commands.pam.recording_commands.router_get_recordings_for_users',
                       return_value=rs):
                cmd.execute(MagicMock(), usernames=['u@x.com'], output=outpath)
            with open(outpath) as f:
                data = json.load(f)
            self.assertIn('recordings', data)
        finally:
            os.unlink(outpath)


if __name__ == '__main__':
    unittest.main()
