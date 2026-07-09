import argparse
import base64
import datetime
import json
import logging
import os
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ... import crypto, utils
from ...proto import pam_pb2
from .router_helper import router_get_recordings_for_users, router_download_recording
from ..base import Command, dump_report_data

RISK_LEVEL_NAMES = {
    pam_pb2.PRR_UNSPECIFIED: 'unspecified',
    pam_pb2.PRR_LOW: 'low',
    pam_pb2.PRR_MEDIUM: 'medium',
    pam_pb2.PRR_HIGH: 'high',
    pam_pb2.PRR_CRITICAL: 'critical',
}

RECORDING_TYPE_NAMES = {
    pam_pb2.PRT_SESSION: 'session',
    pam_pb2.PRT_TYPESCRIPT: 'typescript',
    pam_pb2.PRT_TIME: 'time',
    pam_pb2.PRT_SUMMARY: 'summary',
}

RECORDING_TYPE_VALUES = {v: k for k, v in RECORDING_TYPE_NAMES.items()}
RISK_LEVEL_VALUES = {v: k for k, v in RISK_LEVEL_NAMES.items() if v != 'unspecified'}

# PAMRecordingType → file extension used in the download URL
_TYPE_EXT = {
    pam_pb2.PRT_SESSION: 'ses',
    pam_pb2.PRT_TYPESCRIPT: 'tys',
    pam_pb2.PRT_TIME: 'tim',
    pam_pb2.PRT_SUMMARY: 'sum',
}


def _get_record_key(params, record_uid_bytes):
    """Return the plaintext AES record key for a record UID, or None if not cached."""
    uid_str = utils.base64_url_encode(record_uid_bytes)
    rec = params.record_cache.get(uid_str)
    if rec is None:
        return None
    return rec.get('record_key_unencrypted')


def _decrypt_recording_file(raw_bytes, record_key):
    """Decrypt a PAM recording file.

    Wire format (from vault session-recordings-util.ts):
      [4 bytes big-endian: AD length][AD JSON bytes][0x3B ';'][12-byte nonce][AES-GCM ciphertext]

    Key derivation:
      salt        = AD.resourceKeysSalt (base64) if present, else nonce (legacy)
      info        = b"{AD.conversationUid}_RECORDING-SESSION_AES-GCM-256"
      resourceKey = HKDF-SHA256(ikm=record_key, salt=salt, info=info, length=32)

    Then:
      privateMeta = AES-GCM-decrypt(AD.resourceData_base64, resourceKey)  → JSON
      plaintext   = AES-GCM-decrypt(ciphertext, privateMeta.recordingSecret, nonce=nonce, aad=AD_bytes)
    """
    # --- parse wire format ---
    ad_len = struct.unpack('>I', raw_bytes[:4])[0]
    ad_bytes = raw_bytes[4:4 + ad_len]
    term_pos = 4 + ad_len
    if raw_bytes[term_pos:term_pos + 1] != b';':
        raise ValueError('Recording format error: expected ";" terminator after Associated Data')
    nonce = raw_bytes[term_pos + 1:term_pos + 13]        # 12 bytes
    ciphertext = raw_bytes[term_pos + 13:]

    ad = json.loads(ad_bytes.decode('utf-8'))

    # --- derive resource key ---
    if ad.get('resourceKeysSalt'):
        salt = base64.b64decode(ad['resourceKeysSalt'])
    else:
        salt = nonce  # legacy recordings: nonce was used as salt

    info = f"{ad['conversationUid']}_RECORDING-SESSION_AES-GCM-256".encode('utf-8')
    resource_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(record_key)

    # --- decrypt AD.resourceData → PrivateMeta JSON (contains recordingSecret) ---
    resource_data_enc = base64.b64decode(ad['resourceData'])
    # stored as nonce(12) + ciphertext — same layout as crypto.decrypt_aes_v2
    private_meta_bytes = AESGCM(resource_key).decrypt(
        resource_data_enc[:12], resource_data_enc[12:], None)
    private_meta = json.loads(private_meta_bytes.decode('utf-8'))

    # --- decrypt recording data using recordingSecret ---
    recording_secret = base64.b64decode(private_meta['recordingSecret'])
    plaintext = AESGCM(recording_secret).decrypt(nonce, ciphertext, ad_bytes)
    return plaintext


def _parse_dt(s):
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.datetime.strptime(s, fmt)
        except ValueError:
            pass
    raise ValueError(f'Cannot parse datetime: {s!r}  (use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)')


def _fmt_ts(epoch_ms):
    if not epoch_ms:
        return ''
    return datetime.datetime.utcfromtimestamp(epoch_ms / 1000).strftime('%Y-%m-%d %H:%M:%S UTC')


def _build_user_request(kwargs):
    """Build a PAMRecordingsForUsersRequest from command kwargs."""
    rq = pam_pb2.PAMRecordingsForUsersRequest()
    rq.usernames.extend(kwargs.get('usernames') or [])
    rq.maxCount = kwargs.get('max_count') or 0

    if kwargs.get('range_start'):
        rq.rangeStart = int(_parse_dt(kwargs['range_start']).timestamp() * 1000)
    if kwargs.get('range_end'):
        rq.rangeEnd = int(_parse_dt(kwargs['range_end']).timestamp() * 1000)

    for t in (kwargs.get('types') or []):
        rq.types.append(RECORDING_TYPE_VALUES[t])
    for r in (kwargs.get('risks') or []):
        rq.risks.append(RISK_LEVEL_VALUES[r])
    rq.protocols.extend(kwargs.get('protocols') or [])
    return rq


def _add_filter_args(parser):
    """Add the shared filter arguments to a parser."""
    parser.add_argument('--types', nargs='+', metavar='TYPE',
                        choices=list(RECORDING_TYPE_VALUES.keys()),
                        help='filter by type: session typescript time summary')
    parser.add_argument('--risks', nargs='+', metavar='RISK',
                        choices=list(RISK_LEVEL_VALUES.keys()),
                        help='filter by AI risk: low medium high critical')
    parser.add_argument('--protocols', nargs='+', metavar='PROTOCOL',
                        help='filter by protocol, e.g. SSH RDP')
    parser.add_argument('--range-start', metavar='DATE',
                        help='recordings on or after this date (YYYY-MM-DD)')
    parser.add_argument('--range-end', metavar='DATE',
                        help='recordings on or before this date (YYYY-MM-DD)')
    parser.add_argument('--max-count', type=int, default=0, metavar='N',
                        help='max results to fetch (default: server max of 1000)')


# KRouter rate limit: 50 requests / 5 seconds per user (HTTP.kt).
# We keep workers at 4 so a burst of 4 files lands well inside that budget,
# leaving headroom for any other concurrent API calls in the same session.
_DOWNLOAD_WORKERS = 4


def _download_one(params, conn_uid_bytes, ext, output_dir, record_key):
    """Download, decrypt, and save a single recording file. Returns (filename, bytes_written, error)."""
    uid_b64 = base64.urlsafe_b64encode(conn_uid_bytes).rstrip(b'=').decode()
    filename = f'{uid_b64}.{ext}'
    dest = os.path.join(output_dir, filename)
    try:
        raw = router_download_recording(params, conn_uid_bytes, ext)
        plaintext = _decrypt_recording_file(raw, record_key)
        with open(dest, 'wb') as f:
            f.write(plaintext)
        return filename, len(plaintext), None
    except Exception as e:
        return filename, 0, e


def _download_recording_files(params, conn_uid_bytes, exts, output_dir, record_key):
    """Download and decrypt one session's recording files (parallel across types)."""
    tasks = [(conn_uid_bytes, ext, output_dir, record_key) for ext in exts]
    with ThreadPoolExecutor(max_workers=min(len(tasks), _DOWNLOAD_WORKERS)) as ex:
        futures = {ex.submit(_download_one, params, *t): t[1] for t in tasks}
        for fut in as_completed(futures):
            filename, nbytes, err = fut.result()
            if err:
                logging.warning('  ✗ %s  — %s', filename, err)
            else:
                print(f'  ✓ {filename}  ({nbytes:,} bytes)')


def _download_recordings(params, recordings, type_filter, output_dir):
    """Download and decrypt all recordings in parallel, fetching keys from vault cache."""
    os.makedirs(output_dir, exist_ok=True)
    print(f'Downloading to {os.path.abspath(output_dir)} ...')

    # Build the full flat task list: (conn_uid_bytes, ext, record_key)
    tasks = []
    for rec in recordings:
        if not rec.connectionUid:
            continue
        record_key = _get_record_key(params, rec.recordUid) if rec.recordUid else None
        if record_key is None:
            logging.warning('  skipping %s — record key not in vault cache (run sync-down first)',
                            rec.connectionUid.hex()[:12])
            continue
        if type_filter:
            exts = [_TYPE_EXT[t] for t in type_filter]
        else:
            ext = _TYPE_EXT.get(rec.recordingType)
            exts = [ext] if ext else []
        for ext in exts:
            tasks.append((rec.connectionUid, ext, record_key))

    if not tasks:
        print('Nothing to download.')
        return

    with ThreadPoolExecutor(max_workers=_DOWNLOAD_WORKERS) as ex:
        futures = {
            ex.submit(_download_one, params, conn_uid, ext, output_dir, key): (conn_uid, ext)
            for conn_uid, ext, key in tasks
        }
        for fut in as_completed(futures):
            filename, nbytes, err = fut.result()
            if err:
                logging.warning('  ✗ %s  — %s', filename, err)
            else:
                print(f'  ✓ {filename}  ({nbytes:,} bytes)')


class PAMGetRecordingsForUsersCommand(Command):
    """List PAM session recordings for one or more users, with optional download."""

    def get_parser(self):
        parser = argparse.ArgumentParser(
            prog='pam recording list-by-user',
            description='List PAM session recordings for one or more users.')
        parser.add_argument('usernames', nargs='+', metavar='USERNAME',
                            help='one or more Keeper email addresses')
        _add_filter_args(parser)
        parser.add_argument('--format', dest='output_format',
                            choices=['table', 'json', 'csv'], default='table',
                            help='display format (default: table)')
        parser.add_argument('--output', metavar='FILE',
                            help='save listing to a file; format inferred from extension '
                                 '(.json, .csv, .md/.txt = markdown table)')
        parser.add_argument('--download-dir', metavar='DIR',
                            help='download and decrypt recording files into this directory '
                                 '(implies download; created if it does not exist)')
        return parser

    def execute(self, params, **kwargs):
        usernames = kwargs.get('usernames') or []
        if not usernames:
            logging.error('At least one username is required.')
            return

        rq = _build_user_request(kwargs)

        try:
            rs = router_get_recordings_for_users(params, rq)
        except Exception as e:
            logging.error('get_recordings_for_users failed: %s', e)
            return

        if rs is None:
            print('No response from router.')
            return

        recordings = list(rs.recordings)
        has_more = rs.hasMore

        # --- listing output ---
        output_file = kwargs.get('output')
        output_format = kwargs.get('output_format', 'table')
        if output_file:
            file_ext = output_file.rsplit('.', 1)[-1].lower() if '.' in output_file else ''
            if file_ext == 'json':
                output_format = 'json'
            elif file_ext == 'csv':
                output_format = 'csv'
            else:
                output_format = 'grid'  # markdown table for .md / .txt

        if output_format == 'json':
            _print_json(recordings, has_more, output_file)
        else:
            _print_table(recordings, has_more, output_format, output_file)

        # --- optional download ---
        dl_dir = kwargs.get('download_dir')
        if dl_dir and recordings:
            type_filter = [RECORDING_TYPE_VALUES[t] for t in (kwargs.get('types') or [])]
            _download_recordings(params, recordings, type_filter, dl_dir)


class PAMDownloadRecordingsCommand(Command):
    """Download and decrypt PAM session recording files.

    Two modes:
      --usernames   List recordings for those users then download all of them.
      --connection-uid  Download specific session(s) by connection UID
                        (requires --record-uid so the file can be decrypted).
    """

    def get_parser(self):
        parser = argparse.ArgumentParser(
            prog='pam recording download',
            description='Download and decrypt PAM recording files to a local directory.')
        src = parser.add_mutually_exclusive_group(required=True)
        src.add_argument('--usernames', nargs='+', metavar='USERNAME',
                         help='download all recordings for these users')
        src.add_argument('--connection-uid', nargs='+', metavar='HEX',
                         help='one or more connection UIDs (hex) to download directly')
        parser.add_argument('--record-uid', metavar='HEX',
                            help='record UID (hex) — required with --connection-uid for decryption')
        parser.add_argument('--output-dir', metavar='DIR', default='recordings',
                            help='directory to save files into (default: ./recordings)')
        _add_filter_args(parser)
        return parser

    def execute(self, params, **kwargs):
        output_dir = kwargs.get('output_dir') or 'recordings'
        type_filter = [RECORDING_TYPE_VALUES[t] for t in (kwargs.get('types') or [])]

        conn_uid_hexes = kwargs.get('connection_uid') or []
        if conn_uid_hexes:
            record_uid_hex = kwargs.get('record_uid')
            if not record_uid_hex:
                logging.error(
                    '--record-uid <HEX> is required with --connection-uid so the file can be decrypted.\n'
                    '  Find the record UID with:  pam rec lbu <username> --format json')
                return
            try:
                record_uid_bytes = bytes.fromhex(record_uid_hex)
            except ValueError:
                logging.error('Invalid --record-uid (expected hex): %s', record_uid_hex)
                return

            record_key = _get_record_key(params, record_uid_bytes)
            if record_key is None:
                logging.error('Record %s not found in vault cache — run sync-down first.', record_uid_hex)
                return

            os.makedirs(output_dir, exist_ok=True)
            print(f'Downloading to {os.path.abspath(output_dir)} ...')
            exts = [_TYPE_EXT[t] for t in (type_filter or list(_TYPE_EXT.keys()))]
            for conn_uid_hex in conn_uid_hexes:
                try:
                    conn_uid_bytes = bytes.fromhex(conn_uid_hex)
                except ValueError:
                    logging.error('Invalid --connection-uid (expected hex): %s', conn_uid_hex)
                    continue
                _download_recording_files(params, conn_uid_bytes, exts, output_dir, record_key)
            return

        # --- username mode ---
        usernames = kwargs.get('usernames') or []
        rq = _build_user_request(kwargs)

        try:
            rs = router_get_recordings_for_users(params, rq)
        except Exception as e:
            logging.error('Failed to list recordings: %s', e)
            return

        if rs is None:
            print('No response from router.')
            return

        recordings = list(rs.recordings)
        if not recordings:
            print('No recordings found.')
            return

        if rs.hasMore:
            print(f'Found {len(recordings)} recording(s) (server has more — narrow filters or increase --max-count).')
        else:
            print(f'Found {len(recordings)} recording(s).')

        _download_recordings(params, recordings, type_filter, output_dir)


def _print_table(recordings, has_more, fmt='table', output_file=None):
    if not recordings:
        print('No recordings found.')
        return

    rows = []
    for rec in recordings:
        conn_uid = rec.connectionUid.hex() if rec.connectionUid else ''
        record_uid = rec.recordUid.hex() if rec.recordUid else ''
        rec_type = RECORDING_TYPE_NAMES.get(rec.recordingType, str(rec.recordingType))
        risk = RISK_LEVEL_NAMES.get(rec.aiOverallRiskLevel, '')
        rows.append([
            conn_uid[:16] + '…' if len(conn_uid) > 16 else conn_uid,
            record_uid[:16] + '…' if len(record_uid) > 16 else record_uid,
            rec.userName,
            rec_type,
            rec.protocol or '',
            _fmt_ts(rec.startedOn) if rec.startedOn else '',
            str(rec.length) + 's' if rec.length else '',
            risk,
        ])

    headers = ['ConnUID', 'RecordUID', 'User', 'Type', 'Protocol', 'Started', 'Duration', 'Risk']
    dump_report_data(rows, headers, fmt=fmt, filename=output_file or '', row_number=False)
    if output_file:
        print(f'Wrote {len(recordings)} recording(s) to {output_file}')
    else:
        suffix = '  (more available — narrow filters or increase --max-count)' if has_more else ''
        print(f'\nTotal: {len(recordings)}{suffix}')


def _print_json(recordings, has_more, output_file=None):
    import json
    from base64 import b64encode

    out = []
    for rec in recordings:
        out.append({
            'connectionUid': rec.connectionUid.hex() if rec.connectionUid else None,
            'recordUid': rec.recordUid.hex() if rec.recordUid else None,
            'userName': rec.userName,
            'recordingType': RECORDING_TYPE_NAMES.get(rec.recordingType, rec.recordingType),
            'protocol': rec.protocol or None,
            'startedOn': rec.startedOn,
            'createdOn': rec.createdOn,
            'length': rec.length,
            'fileSize': rec.fileSize,
            'closeReason': rec.closeReason or None,
            'recordingDuration': rec.recordingDuration or None,
            'aiOverallRiskLevel': RISK_LEVEL_NAMES.get(rec.aiOverallRiskLevel, None),
            'aiOverallSummary': b64encode(rec.aiOverallSummary).decode() if rec.aiOverallSummary else None,
        })
    payload = json.dumps({'recordings': out, 'hasMore': has_more}, indent=2)
    if output_file:
        with open(output_file, 'w') as f:
            f.write(payload)
        print(f'Wrote {len(recordings)} recording(s) to {output_file}')
    else:
        print(payload)
