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

from __future__ import annotations

import argparse
import copy
import datetime
import getpass
import ipaddress
import json
import logging
import os
import subprocess
import tempfile
import time

from typing import Dict, List, Tuple

from ..base import Command
from ...error import CommandError
from ... import vault, utils


TOTP_ACCOUNT = 'kcm-totp%40keepersecurity.com'

SQL_GROUPS = """
SELECT
    cg.connection_group_id,
    parent_id,
    connection_group_name,
    cga.attribute_value AS ksm_config
FROM
    guacamole_connection_group cg
LEFT JOIN
    guacamole_connection_group_attribute cga
ON
    cg.connection_group_id = cga.connection_group_id
    AND cga.attribute_name = 'ksm-config'
"""

SQL_CONNECTIONS = """
SELECT
    c.connection_id,
    c.connection_name AS name,
    c.protocol,
    c.max_connections,
    cp.parameter_name,
    cp.parameter_value,
    g.connection_group_id,
    g.parent_id,
    g.connection_group_name AS group_name,
    ca.attribute_name,
    ca.attribute_value
FROM
    guacamole_connection c
LEFT JOIN
    guacamole_connection_parameter cp ON c.connection_id = cp.connection_id
LEFT JOIN
    guacamole_connection_attribute ca ON c.connection_id = ca.connection_id
LEFT JOIN
    guacamole_connection_group g ON c.parent_id = g.connection_group_id
"""

PROTOCOL_TYPE_MAP = {
    'http': 'pamRemoteBrowser',
    'mysql': 'pamDatabase',
    'postgres': 'pamDatabase',
    'sql-server': 'pamDatabase',
}


class KCMDatabaseConnector:
    """Connects to a KCM/Guacamole database and extracts connection data."""

    def __init__(self, db_type, host, port, user, password, database, ssl=False):
        self.db_type = db_type
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.ssl = ssl
        self.conn = None
        self.cursor = None

    def connect(self):
        if self.db_type == 'mysql':
            self._connect_mysql()
        else:
            self._connect_postgresql()

    def _connect_mysql(self):
        kwargs = dict(
            host=self.host, port=self.port, user=self.user,
            password=self.password, database=self.database
        )
        if self.ssl:
            kwargs['ssl'] = {'ssl': True}
        try:
            import pymysql
            self.conn = pymysql.connect(**kwargs)
            self.cursor = self.conn.cursor(pymysql.cursors.DictCursor)
        except ImportError:
            try:
                from mysql.connector import connect
                if self.ssl:
                    kwargs.pop('ssl', None)
                    kwargs['ssl_disabled'] = False
                self.conn = connect(**kwargs)
                self.cursor = self.conn.cursor(dictionary=True)
            except ImportError:
                raise CommandError('kcm-import',
                    'MySQL driver not found. Install pymysql: pip3 install pymysql')

    def _connect_postgresql(self):
        try:
            import psycopg2
            import psycopg2.extras
            kwargs = dict(
                host=self.host, port=self.port, user=self.user,
                password=self.password, database=self.database
            )
            if self.ssl:
                kwargs['sslmode'] = 'require'
            self.conn = psycopg2.connect(**kwargs)
            self.cursor = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        except ImportError:
            raise CommandError('kcm-import',
                'PostgreSQL driver not found. Install psycopg2: pip3 install psycopg2-binary')

    def validate_schema(self):
        required_tables = [
            'guacamole_connection',
            'guacamole_connection_parameter',
            'guacamole_connection_group',
        ]
        try:
            placeholders = ','.join(f"'{t}'" for t in required_tables)
            self.cursor.execute(
                "SELECT table_name FROM information_schema.tables "
                f"WHERE table_name IN ({placeholders})"
            )
            found = {row['table_name'] if isinstance(row, dict)
                     else row[0] for row in self.cursor.fetchall()}
            missing = [t for t in required_tables if t not in found]
            if missing:
                raise CommandError('kcm-import',
                    f'KCM schema not found: missing table(s) '
                    f'{", ".join(missing)}')
        except CommandError:
            raise
        except Exception as e:
            logging.debug('Schema validation error: %s', e)
            raise CommandError('kcm-import',
                               f'Schema validation failed: {type(e).__name__}')

    def extract_groups(self):
        self.cursor.execute(SQL_GROUPS)
        rows = self.cursor.fetchall()
        return [dict(r) for r in rows]

    def extract_connections(self):
        self.cursor.execute(SQL_CONNECTIONS)
        rows = self.cursor.fetchall()
        return [dict(r) for r in rows]

    def close(self):
        try:
            if self.cursor:
                self.cursor.close()
        except Exception:
            pass
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass


def _set_nested(d, dotted_path, value):
    """Set a value in a nested dict using a dotted key path."""
    keys = dotted_path.split('.')
    for key in keys[:-1]:
        child = d.get(key)
        if not isinstance(child, dict):
            child = {}
            d[key] = child
        d = child
    d[keys[-1]] = value


class KCMParameterMapper:
    """Applies kcm_mappings.json transformations to raw KCM connection data."""

    def __init__(self):
        mappings_path = os.path.join(os.path.dirname(__file__), 'kcm_mappings.json')
        with open(mappings_path, 'r') as f:
            self.mappings = json.load(f)

    def transform(self, connection_rows, include_disabled=False):
        # type: (List[Dict], bool) -> Tuple[List[Dict], List[Dict]]
        """Group rows by connection_id, apply mappings, return (resources, users)."""
        connections = {}  # type: Dict[int, Dict]
        users = {}  # type: Dict[int, Dict]
        disabled_ids = set()  # type: set

        # Pre-scan for disabled connections (max_connections == 0)
        if not include_disabled:
            for row in connection_rows:
                if row.get('max_connections') == 0:
                    disabled_ids.add(row['connection_id'])

        for row in connection_rows:
            cid = row['connection_id']
            if cid in disabled_ids:
                continue
            name = row['name']
            protocol = row['protocol']

            if cid not in connections:
                record_type = PROTOCOL_TYPE_MAP.get(protocol, 'pamMachine')
                conn_protocol = 'postgresql' if protocol == 'postgres' else protocol
                connections[cid] = {
                    'title': f'KCM Resource - {name}',
                    'type': record_type,
                    'host': '',
                    'pam_settings': {
                        'options': {
                            'rotation': 'off',
                            'connections': 'on',
                            'tunneling': 'off',
                            'graphical_session_recording': 'off'
                        },
                        'connection': {
                            'protocol': conn_protocol,
                            'launch_credentials': f'KCM User - {name}'
                        }
                    },
                    '_group_id': row.get('connection_group_id'),
                }

            if cid not in users:
                users[cid] = {
                    'title': f'KCM User - {name}',
                    'type': 'pamUser',
                    'password': '',
                    '_group_id': row.get('connection_group_id'),
                }

            param_name = row.get('parameter_name')
            param_value = row.get('parameter_value') or ''
            attr_name = row.get('attribute_name')
            attr_value = row.get('attribute_value') or ''

            if param_name:
                self._apply_mapping(cid, param_name, param_value,
                                    connections, users)
            if attr_name:
                self._apply_mapping(cid, attr_name, attr_value,
                                    connections, users)

        return list(connections.values()), list(users.values())

    def _apply_mapping(self, cid, arg, value, connections, users):
        resource = connections[cid]
        user = users[cid]

        # Special cases first
        if arg == 'hostname':
            resource['host'] = value
            return
        if arg == 'port':
            try:
                resource['pam_settings']['connection']['port'] = str(int(value))
            except (ValueError, TypeError):
                resource['pam_settings']['connection']['port'] = value
            return
        if arg.startswith('totp-') and value:
            self._handle_totp(user, arg, value)
            return
        # Legacy Guacamole autofill selectors → autofill_targets
        if arg in ('username-field', 'password-field') and value:
            self._append_legacy_autofill(resource, arg, value)
            return
        # KCM autofill-configuration is a JSON/YAML array of page
        # objects — convert to Keeper's newline key=value format
        if arg == 'autofill-configuration' and value:
            self._convert_kcm_autofill(resource, value)
            return
        # Params with no RBI equivalent — append to notes
        if arg == 'profile-storage-directory' and value:
            existing = resource.get('notes', '') or ''
            resource['notes'] = (
                f'{existing}\nKCM profile-storage-directory: {value}'.strip())
            return

        # User mappings
        if value and arg in self.mappings['users']:
            mapping = self.mappings['users'][arg]
            self._apply_single_mapping(mapping, value, user)
            return

        # Resource mappings
        if arg in self.mappings['resources']:
            mapping = self.mappings['resources'][arg]
            self._apply_single_mapping(mapping, value, resource)

    def _apply_single_mapping(self, mapping, value, target):
        if mapping == 'ignore':
            return
        if mapping == 'log':
            logging.debug('KCM parameter not mapped (action=log)')
            return
        if mapping is None:
            return
        if '=' in mapping:
            mapping, value = mapping.split('=', 1)
        _set_nested(target, mapping, value)

    def _handle_totp(self, user, arg, value):
        if '_totp_parts' not in user:
            user['_totp_parts'] = {}
        user['_totp_parts'][arg] = value

    @staticmethod
    def finalize_totp(users):
        """Convert collected TOTP parts into otpauth:// URLs."""
        for user in users:
            parts = user.pop('_totp_parts', None)
            if not parts:
                continue
            alg = parts.get('totp-algorithm', '')
            digits = parts.get('totp-digits', '')
            period = parts.get('totp-period', '')
            secret = parts.get('totp-secret', '')
            stripped_secret = ''.join(c for c in secret if c.isalnum())
            if not stripped_secret:
                continue
            user['otp'] = (
                f'otpauth://totp/{TOTP_ACCOUNT}'
                f'?secret={stripped_secret}&issuer=&algorithm={alg}'
                f'&digits={digits}&period={period}'
            )

    @staticmethod
    def _convert_kcm_autofill(resource, raw_value):
        """Clean KCM autofill-configuration JSON for Keeper RBI.

        Keeper RBI uses the same JSON array format as KCM/Guacamole:
          [{"page": "*.example.com", "username-field": "#user",
            "password-field": "#pass", "submit": "button"}]

        The KCM database often stores this with excessive whitespace
        and literal \\n characters from PostgreSQL extraction.
        Parse and re-serialize as compact JSON.
        """
        conn = resource.get('pam_settings', {}).get('connection', {})

        # The KCM/PostgreSQL extraction chain may double-escape the JSON:
        #   real newlines → literal \n,  \" → \\"
        # Un-escape one level before parsing.
        cleaned = (raw_value
                   .replace('\\\\"', '\\"')   # \\" → \"  (double-escaped quotes)
                   .replace('\\n', '\n')      # \n → real newline
                   .replace('\\t', '\t'))     # \t → real tab

        # Try parsing as JSON to validate and compact it
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, list):
                conn['autofill_targets'] = json.dumps(parsed)
                return
        except (json.JSONDecodeError, TypeError):
            pass

        # Fallback: try the raw value as-is (real newlines already)
        try:
            parsed = json.loads(raw_value)
            if isinstance(parsed, list):
                conn['autofill_targets'] = json.dumps(parsed)
                return
        except (json.JSONDecodeError, TypeError):
            pass

        # Not valid JSON — store cleaned/stripped version
        conn['autofill_targets'] = cleaned.strip()

    @staticmethod
    def _append_legacy_autofill(resource, arg, value):
        """Convert legacy username-field/password-field to autofill JSON.

        Old Guacamole used simple CSS selectors (e.g. 'u', 'passwd') as
        username-field/password-field params. Convert these to the JSON
        array format used by both KCM and Keeper RBI.
        """
        conn = resource.get('pam_settings', {}).get('connection', {})
        existing = conn.get('autofill_targets', '')

        # Parse existing JSON array or start fresh
        try:
            steps = json.loads(existing) if existing else []
            if not isinstance(steps, list):
                steps = []
        except (json.JSONDecodeError, TypeError):
            steps = []

        # Merge into existing step or create new one
        if steps:
            # Add to the last step (same page)
            steps[-1][arg] = value
        else:
            steps.append({arg: value})

        conn['autofill_targets'] = json.dumps(steps)

    @staticmethod
    def map_protocol_to_type(protocol):
        return PROTOCOL_TYPE_MAP.get(protocol, 'pamMachine')


class KCMGroupResolver:
    """Builds folder hierarchy from KCM connection groups."""

    def __init__(self, groups, mode='ksm'):
        self.groups = {g['connection_group_id']: g for g in groups}
        self.mode = mode
        self.paths = {}  # type: Dict[int, str]
        self._resolve_all()

    def _resolve_all(self):
        for gid in self.groups:
            if self.mode == 'flat':
                raw = self.groups[gid]['connection_group_name']
                self.paths[gid] = raw.replace('/', '_').replace('\\', '_').replace('..', '_')
            else:
                self._resolve_path(gid)

    def _resolve_path(self, group_id, _seen=None):
        if group_id is None:
            return 'ROOT'
        if group_id in self.paths:
            return self.paths[group_id]
        if _seen is None:
            _seen = set()
        if group_id in _seen:
            return 'ROOT'
        _seen.add(group_id)
        group = self.groups.get(group_id)
        if not group:
            return 'ROOT'
        # Sanitize group name: strip path separators to prevent traversal
        raw_name = group.get('connection_group_name') or f'group_{group_id}'
        safe_name = raw_name.replace('/', '_').replace('\\', '_').replace('..', '_')
        if self.mode == 'ksm' and group.get('ksm_config'):
            self.paths[group_id] = safe_name
            return safe_name
        parent_path = self._resolve_path(group.get('parent_id'), _seen)
        full_path = f"{parent_path}/{safe_name}"
        self.paths[group_id] = full_path
        return full_path

    def resolve_path(self, group_id):
        if group_id is None:
            return 'ROOT'
        return self.paths.get(group_id, 'ROOT')

    def get_shared_folders(self):
        folders = set()
        for path in self.paths.values():
            root = path.split('/')[0]
            folders.add(root)
        return sorted(folders)


class AdaptiveThrottler:
    """Probe-based adaptive batch throttler for Keeper API imports.

    Sends small probe batches before the real import to measure server
    response times, then computes optimal batch parameters. During import,
    continuously monitors batch timing and adjusts if throttles are detected
    or headroom is available.

    The API rate limit is global per device token (~50 calls before HTTP 403).
    Each record type has a known API call cost:
      - Resource + nested user: ~20 calls (measured avg 19.2)
      - External user (login): ~8 calls (measured avg 8.0)

    Batch sizes are bounded by: budget / calls_per_record.
    Delays are per-type: proportional to calls_per_batch so the rate window
    can absorb each batch before the next one starts.

    Adaptation is type-specific:
      On throttle: only the offending type's batch_size halved, delay doubled
      On recovery:  3 clean batches → type's batch_size += 1, delay *= 0.85
    """

    # API call costs per record type (measured via instrumentation)
    CALLS_PER_RESOURCE = 20   # PAM resource + nested user (measured avg 19.2)
    CALLS_PER_USER = 8        # External login record (measured avg 8.0)
    SECS_PER_CALL = 0.3       # Empirical: ~100-120 calls/min rate limit

    # Adaptation parameters
    CLEAN_BATCHES_TO_RECOVER = 3   # consecutive clean batches before speeding up
    MIN_DELAY = 3.0                # never go below 3s delay
    MAX_DELAY = 60.0               # never exceed 60s delay
    MIN_BATCH_SIZE = 1
    MAX_BATCH_SIZE = 10

    # Throttle detection: if batch takes longer than
    # base_rtt * batch_size * THROTTLE_RATIO, consider it throttled.
    # Ratio > 3x the expected time means the server injected backoff.
    THROTTLE_RATIO = 3.0
    # Minimum absolute headroom (seconds) to avoid false positives on
    # small batches where even a short network hiccup looks like 3x.
    THROTTLE_HEADROOM_SECS = 30.0

    def __init__(self, enabled=True):
        self.enabled = enabled
        self.probe_rtts = []        # round-trip times from probe batches
        self.base_rtt = None        # median probe RTT

        # Active batch parameters (set after probe or from defaults)
        self.res_batch_size = 2
        self.usr_batch_size = 8
        self.res_delay = 15.0
        self.usr_delay = 15.0

        # Runtime state
        self.throttle_count = 0
        self.consecutive_clean = 0
        self.total_batches = 0

        # Optimal values (computed from probe, used as floor for recovery)
        self._optimal_res_batch = 2
        self._optimal_usr_batch = 8
        self._optimal_res_delay = 15.0
        self._optimal_usr_delay = 15.0

    def run_probe(self, params, config_uid, pam_json, extend_cmd_factory):
        """Run probe batches to measure server response characteristics.

        Sends 3 single-record probe batches with decreasing delays (10s, 5s, 2s)
        to determine the server's baseline RTT and throttle sensitivity.

        Args:
            params: Keeper session params
            config_uid: PAM config UID for extend calls
            pam_json: Full PAM JSON (used as template for probe batches)
            extend_cmd_factory: Callable returning a PAMProjectExtendCommand instance

        Returns:
            dict with probe results: base_rtt, probed_window, recommended params
        """
        if not self.enabled:
            return {'skipped': True, 'reason': 'auto-throttle disabled'}

        all_resources = pam_json['pam_data'].get('resources', [])
        all_users = pam_json['pam_data'].get('users', [])

        # Pick a small probe record (prefer users — cheaper at ~8 API calls)
        probe_items = all_users[:1] if all_users else all_resources[:1]
        if not probe_items:
            return {'skipped': True, 'reason': 'no records to probe with'}
        is_user_probe = bool(all_users)

        probe_delays = [8.0, 4.0, 1.0]  # decreasing delays between probes
        probe_was_throttled = False

        logging.warning('[Probe] Measuring server response (3 probe batches)...')

        for i, probe_delay in enumerate(probe_delays):
            # Build minimal batch JSON
            batch_json = copy.deepcopy(pam_json)
            if is_user_probe:
                batch_json['pam_data']['resources'] = []
                batch_json['pam_data']['users'] = probe_items
            else:
                batch_json['pam_data']['resources'] = probe_items
                batch_json['pam_data']['users'] = []

            tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
            try:
                with os.fdopen(tmp_fd, 'w') as tmp:
                    json.dump(batch_json, tmp, indent=2)

                batch_start = time.time()
                cmd = extend_cmd_factory()
                cmd.execute(params, config=config_uid,
                            file_name=tmp_path, dry_run=False)
                rtt = time.time() - batch_start
                self.probe_rtts.append(rtt)

                logging.warning('[Probe %d/3] RTT=%.1fs (delay before next: %.0fs)',
                                i + 1, rtt, probe_delay if i < 2 else 0)

                # Check for throttle signature: RTT > 30s suggests server
                # injected a backoff (rest_api.py sleeps 30-120s on 403)
                if rtt > 30.0:
                    probe_was_throttled = True
                    logging.warning('[Probe] Throttle detected at probe %d '
                                    '(RTT=%.1fs > 30s threshold)', i + 1, rtt)
                    break  # Don't stress the server further

            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

            if i < len(probe_delays) - 1:
                time.sleep(probe_delay)

        if not self.probe_rtts:
            return {'skipped': True, 'reason': 'all probes failed'}

        # Compute baseline RTT (median, excluding throttled values)
        clean_rtts = [r for r in self.probe_rtts if r < 30.0]
        if clean_rtts:
            sorted_rtts = sorted(clean_rtts)
            mid = len(sorted_rtts) // 2
            self.base_rtt = sorted_rtts[mid]
        else:
            # All probes were slow — server is heavily throttled
            self.base_rtt = min(self.probe_rtts)

        # Compute optimal parameters from probe data
        self._compute_optimal_params(probe_was_throttled)

        result = {
            'base_rtt': self.base_rtt,
            'probe_rtts': self.probe_rtts,
            'throttle_detected': probe_was_throttled,
            'optimal_res_batch': self._optimal_res_batch,
            'optimal_usr_batch': self._optimal_usr_batch,
            'optimal_res_delay': self._optimal_res_delay,
            'optimal_usr_delay': self._optimal_usr_delay,
        }

        logging.warning(
            '[Probe] Results: base_rtt=%.1fs, throttle=%s → '
            'res: batch=%d delay=%.0fs, usr: batch=%d delay=%.0fs',
            self.base_rtt, probe_was_throttled,
            self._optimal_res_batch, self._optimal_res_delay,
            self._optimal_usr_batch, self._optimal_usr_delay)

        # Apply optimal params
        self.res_batch_size = self._optimal_res_batch
        self.usr_batch_size = self._optimal_usr_batch
        self.res_delay = self._optimal_res_delay
        self.usr_delay = self._optimal_usr_delay

        # Let the rate window clear after probe before real import starts.
        # The probe's API calls are still in the server's sliding window.
        cooldown = max(10, int(self.base_rtt * 5)) if not probe_was_throttled else 30
        logging.warning('[Probe] Cooldown %ds (clearing rate window)...', cooldown)
        time.sleep(cooldown)

        return result

    def _compute_optimal_params(self, probe_throttled):
        """Compute optimal batch parameters from probe results.

        The API rate limit is global (~50 calls before HTTP 403 on EU).
        Batch sizes are bounded by: budget / calls_per_record.
        Delays are per-type: calls_per_batch * SECS_PER_CALL, so each
        batch's API calls can be absorbed by the server's rate window
        before the next batch starts.
        """
        # API call budget: stay under 70% of throttle window per batch
        budget = 50 * 0.7  # ~35 calls safe per batch

        if probe_throttled:
            # Server is already rate-limiting — very conservative
            self._optimal_res_batch = 1
            self._optimal_usr_batch = 2
            self._optimal_res_delay = max(15.0, self.base_rtt * 3)
            self._optimal_usr_delay = max(15.0, self.base_rtt * 3)
        else:
            # Batch size = budget / calls_per_record, capped at MAX_BATCH
            self._optimal_res_batch = max(
                self.MIN_BATCH_SIZE,
                min(self.MAX_BATCH_SIZE,
                    int(budget / self.CALLS_PER_RESOURCE)))
            self._optimal_usr_batch = max(
                self.MIN_BATCH_SIZE,
                min(self.MAX_BATCH_SIZE,
                    int(budget / self.CALLS_PER_USER)))
            # Delay per type: proportional to API calls in the batch.
            # This gives heavier batches more time for the rate window
            # to absorb and prevents oscillating throttle/recovery.
            res_calls = self._optimal_res_batch * self.CALLS_PER_RESOURCE
            usr_calls = self._optimal_usr_batch * self.CALLS_PER_USER
            self._optimal_res_delay = max(
                self.MIN_DELAY, res_calls * self.SECS_PER_CALL)
            self._optimal_usr_delay = max(
                self.MIN_DELAY, usr_calls * self.SECS_PER_CALL)

    def record_batch(self, batch_elapsed, num_records, is_resource=True):
        """Record a completed batch and adapt parameters if needed.

        Throttle detection is purely timing-based: if the batch took more
        than THROTTLE_RATIO × the expected time (based on probe RTT),
        the server likely injected a backoff.

        Args:
            batch_elapsed: Wall-clock time for the batch (seconds)
            num_records: Number of records in the batch
            is_resource: True for resource batches, False for user batches

        Returns:
            dict with adaptation info (for logging)
        """
        self.total_batches += 1
        if not self.enabled:
            return {'adapted': False}

        # Expected time scales linearly with records. Use base_rtt as
        # per-record baseline. Resources are ~5x heavier than users.
        if self.base_rtt and self.base_rtt > 0:
            weight = 5.0 if is_resource else 1.0
            expected = num_records * self.base_rtt * weight + 5.0
        else:
            expected = num_records * (15.0 if is_resource else 3.0) + 10.0

        # Throttle = batch took much longer than expected
        threshold = max(expected * self.THROTTLE_RATIO,
                        expected + self.THROTTLE_HEADROOM_SECS)
        throttled = batch_elapsed > threshold

        if throttled:
            return self._adapt_down(batch_elapsed, expected, is_resource)
        else:
            return self._adapt_up(is_resource)

    def _adapt_down(self, batch_elapsed, expected_time, is_resource):
        """Throttle detected — reduce the offending type's batch size and
        increase its delay.  The other type is left untouched."""
        self.throttle_count += 1
        self.consecutive_clean = 0

        if is_resource:
            old_batch = self.res_batch_size
            old_delay = self.res_delay
            self.res_batch_size = max(self.MIN_BATCH_SIZE,
                                      self.res_batch_size // 2)
            self.res_delay = min(self.MAX_DELAY, self.res_delay * 2)
            logging.warning(
                '  [Throttle #%d] Resource batch took %.0fs (expected ~%.0fs). '
                'Adjusting: res_batch %d→%d, res_delay %.0fs→%.0fs',
                self.throttle_count, batch_elapsed, expected_time,
                old_batch, self.res_batch_size,
                old_delay, self.res_delay)
        else:
            old_batch = self.usr_batch_size
            old_delay = self.usr_delay
            self.usr_batch_size = max(self.MIN_BATCH_SIZE,
                                      self.usr_batch_size // 2)
            self.usr_delay = min(self.MAX_DELAY, self.usr_delay * 2)
            logging.warning(
                '  [Throttle #%d] User batch took %.0fs (expected ~%.0fs). '
                'Adjusting: usr_batch %d→%d, usr_delay %.0fs→%.0fs',
                self.throttle_count, batch_elapsed, expected_time,
                old_batch, self.usr_batch_size,
                old_delay, self.usr_delay)

        return {
            'adapted': True, 'direction': 'down',
            'res_batch': self.res_batch_size,
            'usr_batch': self.usr_batch_size,
            'res_delay': self.res_delay,
            'usr_delay': self.usr_delay,
        }

    def _adapt_up(self, is_resource):
        """Clean batch — potentially increase the current type's throughput."""
        self.consecutive_clean += 1

        if self.consecutive_clean < self.CLEAN_BATCHES_TO_RECOVER:
            return {'adapted': False}

        changed = False

        if is_resource:
            old_batch = self.res_batch_size
            old_delay = self.res_delay
            if self.res_batch_size < self._optimal_res_batch:
                self.res_batch_size = min(self._optimal_res_batch,
                                          self.res_batch_size + 1)
                changed = True
            if self.res_delay > self._optimal_res_delay:
                self.res_delay = max(self._optimal_res_delay,
                                     self.res_delay * 0.85)
                changed = True
            if changed:
                self.consecutive_clean = 0
                logging.warning(
                    '  [Recovery] %d clean batches → res_batch %d→%d, '
                    'res_delay %.0fs→%.0fs',
                    self.CLEAN_BATCHES_TO_RECOVER,
                    old_batch, self.res_batch_size,
                    old_delay, self.res_delay)
        else:
            old_batch = self.usr_batch_size
            old_delay = self.usr_delay
            if self.usr_batch_size < self._optimal_usr_batch:
                self.usr_batch_size = min(self._optimal_usr_batch,
                                          self.usr_batch_size + 1)
                changed = True
            if self.usr_delay > self._optimal_usr_delay:
                self.usr_delay = max(self._optimal_usr_delay,
                                     self.usr_delay * 0.85)
                changed = True
            if changed:
                self.consecutive_clean = 0
                logging.warning(
                    '  [Recovery] %d clean batches → usr_batch %d→%d, '
                    'usr_delay %.0fs→%.0fs',
                    self.CLEAN_BATCHES_TO_RECOVER,
                    old_batch, self.usr_batch_size,
                    old_delay, self.usr_delay)

        return {'adapted': changed, 'direction': 'up' if changed else 'none'}

    def get_summary(self):
        """Return summary dict for post-import stats."""
        return {
            'probe_rtts': self.probe_rtts,
            'base_rtt': self.base_rtt,
            'throttle_count': self.throttle_count,
            'total_batches': self.total_batches,
            'final_res_batch': self.res_batch_size,
            'final_usr_batch': self.usr_batch_size,
            'final_res_delay': self.res_delay,
            'final_usr_delay': self.usr_delay,
        }


class PAMProjectKCMImportCommand(Command):
    _PRIVATE_NETS = (
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
    )

    parser = argparse.ArgumentParser(prog='pam project kcm-import')

    # Database options
    parser.add_argument('--db-host', dest='db_host', action='store',
                        help='KCM database hostname')
    parser.add_argument('--docker-detect', dest='docker_detect', action='store_true',
                        default=False,
                        help='Auto-detect credentials from Docker container')
    parser.add_argument('--docker-container', dest='docker_container',
                        action='store', default='guacamole',
                        help='Docker container name for --docker-detect (default: guacamole)')
    parser.add_argument('--db-port', dest='db_port', type=int, action='store',
                        help='Database port (default: 3306 mysql, 5432 postgresql)')
    parser.add_argument('--db-name', dest='db_name', action='store',
                        default=None, help='Database name (default: guacamole_db)')
    parser.add_argument('--db-type', dest='db_type', action='store',
                        choices=['mysql', 'postgresql'], default='mysql',
                        help='Database type')
    parser.add_argument('--db-user', dest='db_user', action='store',
                        default=None, help='Database username (default: guacamole_user)')
    parser.add_argument('--db-password-record', dest='db_password_record',
                        action='store',
                        help='Keeper record UID containing DB password')
    parser.add_argument('--db-ssl', dest='db_ssl', action='store_true',
                        default=False,
                        help='Require SSL/TLS for database connection')
    parser.add_argument('--allow-cleartext', dest='allow_cleartext',
                        action='store_true', default=False,
                        help='Allow unencrypted connection to remote database (not recommended)')

    # Import options
    parser.add_argument('--name', '-n', dest='project_name', action='store',
                        help='Project name')
    parser.add_argument('--config', '-c', dest='config', action='store',
                        help='Existing PAM config UID or title (extend mode)')
    parser.add_argument('--folder-mode', dest='folder_mode', action='store',
                        choices=['ksm', 'exact', 'flat'], default='ksm',
                        help='Connection group mapping mode')
    parser.add_argument('--output', '-o', dest='output', action='store',
                        help='Save JSON to file instead of importing')
    parser.add_argument('--include-credentials', dest='include_credentials',
                        action='store_true', default=False,
                        help='Include real passwords in --output file (default: redacted)')

    # Gateway options
    parser.add_argument('--gateway', '-g', dest='gateway', action='store',
                        help='Existing gateway UID or name (skips gateway creation)')
    parser.add_argument('--max-instances', dest='max_instances', type=int,
                        default=0,
                        help='Set gateway pool size (0 = skip, requires new gateway)')

    # Flags
    parser.add_argument('--dry-run', '-d', dest='dry_run', action='store_true',
                        default=False, help='Preview without vault changes')
    parser.add_argument('--skip-users', dest='skip_users', action='store_true',
                        default=False, help='Import connections only, skip users')
    parser.add_argument('--include-disabled', dest='include_disabled',
                        action='store_true', default=False,
                        help='Include disabled KCM connections')
    parser.add_argument('--estimate', dest='estimate', action='store_true',
                        default=False,
                        help='Scan database and show migration estimate without importing')
    parser.add_argument('--yes', '-y', dest='auto_confirm', action='store_true',
                        default=False,
                        help='Skip interactive confirmation prompt')
    parser.add_argument('--batch-size', dest='batch_size', type=int,
                        default=None,
                        help='Resources per batch (auto-scaled if not set)')
    parser.add_argument('--batch-delay', dest='batch_delay', type=float,
                        default=None,
                        help='Seconds to wait between batches (default: 10)')
    parser.add_argument('--auto-throttle', dest='auto_throttle',
                        action='store_true', default=True,
                        help='Enable adaptive throttling with probe (default: on)')
    parser.add_argument('--no-auto-throttle', dest='auto_throttle',
                        action='store_false',
                        help='Disable adaptive throttling, use fixed batch params')

    def get_parser(self):
        return PAMProjectKCMImportCommand.parser

    def execute(self, params, **kwargs):
        db_host = kwargs.get('db_host') or ''
        docker_detect = kwargs.get('docker_detect', False)

        if not db_host and not docker_detect:
            raise CommandError('kcm-import',
                'Either --db-host or --docker-detect is required')

        db_type = kwargs.get('db_type', 'mysql')
        folder_mode = kwargs.get('folder_mode', 'ksm')
        output_file = kwargs.get('output') or ''
        dry_run = kwargs.get('dry_run', False)
        skip_users = kwargs.get('skip_users', False)
        config_uid = kwargs.get('config') or ''
        project_name = kwargs.get('project_name') or ''
        include_disabled = kwargs.get('include_disabled', False)

        # Read CLI values (None when not explicitly provided)
        db_port = kwargs.get('db_port')
        db_name = kwargs.get('db_name')
        db_user = kwargs.get('db_user')

        # Resolve DB credentials — CLI flags override docker-detected values
        if docker_detect:
            container_name = kwargs.get('docker_container', 'guacamole')
            conn_info, db_password = \
                self._detect_docker_credentials(db_type, container_name)
            det_host, det_port, det_name, det_user = conn_info
            db_host = db_host or det_host
            db_port = db_port or det_port
            db_name = db_name or det_name
            db_user = db_user or det_user
        else:
            db_password = self._resolve_db_password(params, kwargs)

        # Apply defaults for anything not set by CLI or docker-detect
        db_port = db_port or (3306 if db_type == 'mysql' else 5432)
        db_name = db_name or 'guacamole_db'
        db_user = db_user or 'guacamole_user'

        # Connection target for log messages (not a credential)
        log_target = '{}:{}'.format(db_host, db_port)

        # Connect and extract
        db_ssl = kwargs.get('db_ssl', False)
        allow_cleartext = kwargs.get('allow_cleartext', False)
        if not db_ssl and not self._is_local_host(db_host):
            if not allow_cleartext:
                raise CommandError('kcm-import',
                    f'Refusing to connect to remote host {db_host} without SSL/TLS. '
                    f'Credentials and data would transit in cleartext. '
                    f'Use --db-ssl to encrypt, or --allow-cleartext to override.')
            logging.warning(
                'WARNING: Connecting to remote database %s without SSL/TLS. '
                'Credentials and extracted data will transit in cleartext.', log_target)
        connector = KCMDatabaseConnector(
            db_type, db_host, db_port, db_user, db_password, db_name, ssl=db_ssl
        )
        try:
            logging.info('Connecting to KCM database at %s...', log_target)
            connector.connect()
            connector.validate_schema()

            logging.info('Extracting connection groups...')
            groups = connector.extract_groups()

            logging.info('Extracting connections and parameters...')
            connection_rows = connector.extract_connections()
        except CommandError:
            raise
        except Exception as e:
            logging.debug('Database error: %s: %s', type(e).__name__, e)
            raise CommandError('kcm-import',
                               f'Database connection failed: {type(e).__name__}. '
                               f'Use --debug for details.')
        finally:
            connector.close()
            # Clear credentials from memory (best effort — Python strings are immutable)
            connector.password = None
            db_password = None  # noqa: F841

        logging.info('Extracted %d group(s), %d connection row(s)',
                     len(groups), len(connection_rows))

        # Build group hierarchy
        resolver = KCMGroupResolver(groups, mode=folder_mode)

        # Transform parameters
        mapper = KCMParameterMapper()
        resources, users = mapper.transform(connection_rows,
                                            include_disabled=include_disabled)

        # Estimation mode: scan and report without importing
        if kwargs.get('estimate'):
            total_connections = len({r['connection_id'] for r in connection_rows})
            self._print_estimate(groups, resources, users, skip_users,
                                 include_disabled, total_connections)
            return

        # Ensure project_name is set before folder_path assignment
        if not project_name:
            ts = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            project_name = f'KCM-Import-{ts}'

        # Assign folder paths under project-named shared folders
        res_root = f'{project_name} - Resources'
        usr_root = f'{project_name} - Users'
        for item in resources:
            group_id = item.pop('_group_id', None)
            kcm_path = resolver.resolve_path(group_id)
            if kcm_path == 'ROOT':
                item['folder_path'] = res_root
            elif kcm_path.startswith('ROOT/'):
                item['folder_path'] = f'{res_root}/{kcm_path[5:]}'
            else:
                item['folder_path'] = f'{res_root}/{kcm_path}'

        for item in users:
            group_id = item.pop('_group_id', None)
            kcm_path = resolver.resolve_path(group_id)
            if kcm_path == 'ROOT':
                item['folder_path'] = usr_root
            elif kcm_path.startswith('ROOT/'):
                item['folder_path'] = f'{usr_root}/{kcm_path[5:]}'
            else:
                item['folder_path'] = f'{usr_root}/{kcm_path}'

        # Finalize TOTP
        KCMParameterMapper.finalize_totp(users)

        # Clean SFTP settings — SFTP is a connection setting on the record,
        # NOT a separate resource. Strip fields that don't belong per protocol.
        for resource in resources:
            conn = resource.get('pam_settings', {}).get('connection', {})
            sftp = conn.get('sftp')
            if not sftp:
                continue
            protocol = conn.get('protocol', '')

            if protocol in ('ssh', 'telnet'):
                # SSH/Telnet: only enable_sftp + sftp_root_directory
                cleaned = {}
                if sftp.get('enable_sftp'):
                    cleaned['enable_sftp'] = sftp['enable_sftp']
                if sftp.get('sftp_root_directory'):
                    cleaned['sftp_root_directory'] = sftp['sftp_root_directory']
                if cleaned:
                    conn['sftp'] = cleaned
                else:
                    conn.pop('sftp', None)

            elif protocol in ('rdp', 'vnc'):
                # RDP/VNC: keep SFTPConnectionSettings fields as-is
                # (enable_sftp, sftp_root_directory, sftp_upload_directory,
                #  host, port, login, password, private_key, etc.)
                # These are connection settings, not separate records.
                pass

        # Flag records with incomplete data from KCM source.
        # Move them to a special subfolder with notes explaining the issues.
        self._flag_incomplete_records(resources, users, res_root, usr_root)

        # Nest users inside their parent resources for proper extend.py linking.
        # extend.py expects users in resource['users'] to create DAG links.
        # Exception: pamRemoteBrowser (RBI) — PamRemoteBrowserObject has no
        # 'users' attribute; RBI users must stay top-level and are linked via
        # autofill_credentials in rbi_settings, not launch_credentials.
        if not skip_users:
            user_index = {}
            for user in users:
                title = user.get('title', '')
                if title:
                    user_index.setdefault(title, []).append(user)

            nested_ids = set()  # track id() of nested user dicts
            for resource in resources:
                launch_cred = (resource.get('pam_settings', {})
                               .get('connection', {})
                               .get('launch_credentials', ''))
                if not launch_cred or launch_cred not in user_index:
                    continue

                # RBI: keep users top-level, set autofill_credentials
                if resource.get('type') == 'pamRemoteBrowser':
                    rbi_conn = (resource.get('pam_settings', {})
                                .get('connection', {}))
                    rbi_conn['autofill_credentials'] = launch_cred
                    # RBI users are Login records, not pamUser
                    for u in user_index.get(launch_cred, []):
                        u['type'] = 'login'
                    continue
                candidates = [u for u in user_index[launch_cred]
                              if id(u) not in nested_ids]
                if len(candidates) == 1:
                    resource['users'] = [candidates[0]]
                    nested_ids.add(id(candidates[0]))
                elif len(candidates) > 1:
                    # Duplicate titles across groups — match by folder path
                    res_fp = resource.get('folder_path', '')
                    res_suffix = (res_fp.split(' - Resources', 1)[-1]
                                  if ' - Resources' in res_fp else res_fp)
                    for u in candidates:
                        u_fp = u.get('folder_path', '')
                        u_suffix = (u_fp.split(' - Users', 1)[-1]
                                    if ' - Users' in u_fp else u_fp)
                        if res_suffix == u_suffix:
                            resource['users'] = [u]
                            nested_ids.add(id(u))
                            break

            # Top-level users: only those not nested into a resource
            users = [u for u in users if id(u) not in nested_ids]

        # Build shared folder list
        sf_list = [res_root, usr_root]

        # Build PAM JSON
        pam_json = {
            'pam_data': {
                'shared_folders': sf_list,
                'resources': resources,
                'users': users if not skip_users else [],
            }
        }

        if not config_uid:
            pam_json['project'] = project_name

        num_resources = len(resources)
        nested_user_count = sum(len(r.get('users', [])) for r in resources)
        num_users = (nested_user_count + len(users)) if not skip_users else 0

        # Output or import
        if output_file:
            include_creds = kwargs.get('include_credentials', False)
            out_data = pam_json if include_creds else self._redact_for_display(pam_json)
            fd = os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                json.dump(out_data, f, indent=2)
            redact_note = '' if include_creds else ' (credentials redacted)'
            logging.warning('JSON written to %s (%d resources, %d users)%s',
                            output_file, num_resources, num_users, redact_note)
            if not include_creds:
                logging.info('Use --include-credentials to include passwords in output')
            return

        if dry_run:
            redacted = self._redact_for_display(pam_json)
            print(json.dumps(redacted, indent=2))
            self._print_import_summary(
                project_name, config_uid, num_resources, num_users,
                resources, users, skip_users)
            logging.warning('Dry run: %d resources, %d users (no vault changes)',
                            num_resources, num_users)
            return

        # Validate data before import
        warnings = self._validate_import_data(resources, users, skip_users)
        for w in warnings:
            logging.warning('Validation: %s', w)

        # Pre-import summary + confirmation
        auto_confirm = kwargs.get('auto_confirm', False)
        if not auto_confirm:
            self._print_import_summary(
                project_name, config_uid, num_resources, num_users,
                resources, users, skip_users)
            answer = input('\n  Proceed with import? [y/N]: ').strip().lower()
            if answer not in ('y', 'yes'):
                raise CommandError('kcm-import', 'Import cancelled by user.')

        # Gateway selection (only for new project imports, not extend mode)
        is_new_project = not config_uid
        gateway_arg = kwargs.get('gateway') or ''
        if gateway_arg and not config_uid:
            resolved_config = self._resolve_gateway(params, gateway_arg)
            if resolved_config:
                # Gateway is already bound to an existing project
                actual_res, actual_usr = self._discover_shared_folder_names(
                    params, resolved_config)
                existing_project = actual_res.rsplit(' - Resources', 1)[0] if actual_res else '(unknown)'
                print(f'\nGateway "{gateway_arg}" belongs to project "{existing_project}".')
                print(f'  [1] Create a NEW project with its own folders and gateway (recommended)')
                print(f'  [2] Add records into "{existing_project}" existing folders')
                print(f'  [3] Cancel import')
                choice = input('\n  Select [1]: ').strip()
                if choice == '2':
                    config_uid = resolved_config
                    is_new_project = False
                elif choice == '3':
                    raise CommandError('kcm-import', 'Import cancelled by user.')
                # Default (1 or empty): create new project

        # Phase 1: Create project skeleton if no existing config
        if not config_uid:
            config_uid = self._create_project_skeleton(
                params, project_name, pam_json)
            is_new_project = True

        # Discover actual shared folder names and rewrite paths if needed
        actual_res, actual_usr = self._discover_shared_folder_names(
            params, config_uid)
        if actual_res and actual_usr:
            self._rewrite_folder_paths(
                pam_json, actual_res, actual_usr, project_name)
            pam_json['pam_data']['shared_folders'] = [actual_res, actual_usr]

        # Phase 2: Populate records via batched extend calls.
        # Phase 2a: External users (login records) in small batches
        # Phase 2b: Resources (with nested users) — users=[] since external
        #           users already exist and are found by title match.

        from .extend import PAMProjectExtendCommand
        from ... import api

        all_resources = pam_json['pam_data']['resources']
        all_users = pam_json['pam_data']['users']

        # Set up adaptive throttler
        auto_throttle = kwargs.get('auto_throttle', True)
        override_size = kwargs.get('batch_size')
        override_delay = kwargs.get('batch_delay')
        # Disable adaptive throttle if user set manual batch params
        if override_size is not None or override_delay is not None:
            auto_throttle = False

        throttler = AdaptiveThrottler(enabled=auto_throttle)

        if auto_throttle:
            # Probe phase: measure server response before importing
            probe_result = throttler.run_probe(
                params, config_uid, pam_json,
                extend_cmd_factory=PAMProjectExtendCommand)
            if probe_result.get('skipped'):
                logging.info('[Probe] Skipped: %s — using static params',
                             probe_result.get('reason', 'unknown'))
                # Fall back to static params
                res_batch, usr_batch, delay = self._compute_batch_params(
                    len(all_resources), len(all_users), None, None)
                throttler.res_batch_size = res_batch
                throttler.usr_batch_size = usr_batch
                throttler.res_delay = delay
                throttler.usr_delay = delay
        else:
            # Static batch params (manual overrides or auto-throttle off)
            res_batch, usr_batch, delay = self._compute_batch_params(
                len(all_resources), len(all_users),
                override_size, override_delay)
            throttler.res_batch_size = res_batch
            throttler.usr_batch_size = usr_batch
            throttler.res_delay = delay
            throttler.usr_delay = delay

        pre_count = len(params.record_cache)
        tmp_path = None
        import_start = time.time()

        # Log import plan (batch counts use current throttler params)
        res_batch = throttler.res_batch_size
        usr_batch = throttler.usr_batch_size
        res_batches_n = ((len(all_resources) + res_batch - 1) // res_batch
                         if all_resources else 0)
        usr_batches_n = ((len(all_users) + usr_batch - 1) // usr_batch
                         if all_users else 0)
        total_phases = usr_batches_n + res_batches_n
        throttle_mode = 'adaptive' if auto_throttle else 'fixed'
        logging.warning(
            '[Phase 2] Import plan (%s): %d users in %d batches '
            '(size %d, %.0fs delay) + %d resources in %d batches '
            '(size %d, %.0fs delay)',
            throttle_mode,
            len(all_users), usr_batches_n, usr_batch, throttler.usr_delay,
            len(all_resources), res_batches_n, res_batch, throttler.res_delay)

        try:
            # Phase 2a: External users (RBI login records)
            if all_users:
                logging.warning('[Phase 2a] Importing %d external users...',
                                len(all_users))
                ui = 0  # user index pointer
                ub = 0  # batch counter
                while ui < len(all_users):
                    batch_size = throttler.usr_batch_size
                    batch_users = all_users[ui:ui + batch_size]

                    batch_json = copy.deepcopy(pam_json)
                    batch_json['pam_data']['resources'] = []
                    batch_json['pam_data']['users'] = batch_users

                    if tmp_path and os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                    tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
                    with os.fdopen(tmp_fd, 'w') as tmp:
                        json.dump(batch_json, tmp, indent=2)

                    elapsed = time.time() - import_start
                    logging.warning(
                        '[Phase 2a] Users batch %d: users %d-%d of %d '
                        '[%.0fs elapsed, batch_size=%d, delay=%.0fs]',
                        ub + 1, ui + 1,
                        min(ui + batch_size, len(all_users)),
                        len(all_users), elapsed,
                        batch_size, throttler.usr_delay)

                    batch_start = time.time()
                    cmd = PAMProjectExtendCommand()
                    cmd.execute(params,
                                config=config_uid,
                                file_name=tmp_path,
                                dry_run=False)
                    batch_elapsed = time.time() - batch_start

                    # Record batch timing for adaptive adjustment
                    throttler.record_batch(batch_elapsed, len(batch_users),
                                           is_resource=False)

                    ui += len(batch_users)
                    ub += 1
                    if ui < len(all_users):
                        time.sleep(throttler.usr_delay)

                logging.warning(
                    '[Phase 2a] Complete: %d users imported in %d batches '
                    '[%.0fs]',
                    len(all_users), ub, time.time() - import_start)

            # Phase 2b: Resources (nested users travel with parent resource)
            if all_resources:
                logging.warning(
                    '[Phase 2b] Importing %d resources...',
                    len(all_resources))
                phase2b_start = time.time()
                ri = 0  # resource index pointer
                rb = 0  # batch counter
                while ri < len(all_resources):
                    batch_size = throttler.res_batch_size
                    batch_resources = all_resources[ri:ri + batch_size]

                    batch_json = copy.deepcopy(pam_json)
                    batch_json['pam_data']['resources'] = batch_resources
                    batch_json['pam_data']['users'] = []

                    if tmp_path and os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                    tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
                    with os.fdopen(tmp_fd, 'w') as tmp:
                        json.dump(batch_json, tmp, indent=2)

                    elapsed = time.time() - import_start
                    # Estimate remaining time based on average batch time
                    if rb > 0:
                        avg_batch = (time.time() - phase2b_start) / rb
                        remaining_items = len(all_resources) - ri
                        remaining_batches = (remaining_items + batch_size - 1) // batch_size
                        remaining = avg_batch * remaining_batches
                        eta_str = f', ~{remaining:.0f}s remaining'
                    else:
                        eta_str = ''

                    logging.warning(
                        '[Phase 2b] Resources batch %d: resources %d-%d '
                        'of %d [%.0fs elapsed%s, batch_size=%d, delay=%.0fs]',
                        rb + 1, ri + 1,
                        min(ri + batch_size, len(all_resources)),
                        len(all_resources), elapsed, eta_str,
                        batch_size, throttler.res_delay)

                    batch_start = time.time()
                    cmd = PAMProjectExtendCommand()
                    cmd.execute(params,
                                config=config_uid,
                                file_name=tmp_path,
                                dry_run=False)
                    batch_elapsed = time.time() - batch_start

                    # Record batch timing for adaptive adjustment
                    throttler.record_batch(batch_elapsed, len(batch_resources),
                                           is_resource=True)

                    ri += len(batch_resources)
                    rb += 1
                    if ri < len(all_resources):
                        time.sleep(throttler.res_delay)

                logging.warning(
                    '[Phase 2b] Complete: %d resources imported in %d batches '
                    '[%.0fs]',
                    len(all_resources), rb, time.time() - import_start)

            api.sync_down(params)
            post_count = len(params.record_cache)
            created = post_count - pre_count

            if created == 0:
                raise CommandError('kcm-import',
                    'Extend phase created 0 records. '
                    'Check errors above (duplicate titles, bad paths, etc.)')

            # Post-import summary
            total_time = time.time() - import_start
            expected = num_resources + num_users
            if created < expected:
                logging.warning(
                    'WARNING: Created %d records but expected %d '
                    '(%d resources + %d users). Some records may have '
                    'failed — check warnings above.',
                    created, expected, num_resources, num_users)
            else:
                logging.warning('KCM import complete: %d records created '
                                '(%d resources, %d users)',
                                created, num_resources, num_users)

            # Import statistics with throttler summary
            summary = throttler.get_summary()
            logging.warning(
                'Import stats: %.0fs total, %d throttle events, '
                '%d batches, final params: res=%d@%.0fs usr=%d@%.0fs%s',
                total_time, summary['throttle_count'],
                summary['total_batches'],
                summary['final_res_batch'], summary['final_res_delay'],
                summary['final_usr_batch'], summary['final_usr_delay'],
                f' (probe RTT: {summary["base_rtt"]:.1f}s)'
                if summary.get('base_rtt') else '')

            # Set max instances for gateway pooling (new gateways only)
            max_instances = kwargs.get('max_instances', 0)
            if max_instances > 0 and is_new_project:
                self._set_gateway_pool_size(params, project_name, max_instances)

            # Print deployment instructions for new gateways
            if is_new_project:
                self._print_deploy_instructions(project_name)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    @staticmethod
    def _compute_batch_params(num_resources, num_users,
                              override_size=None, override_delay=None):
        """Compute batch sizes and delay to avoid API throttling.

        API call costs per record (measured via instrumentation):
          External user:   ~8 calls   →  batch of 8  = ~64 calls
          Resource+user:  ~20 calls   →  batch of 2  = ~40 calls (safe)

        Keeper EU throttle window: ~50 requests triggers HTTP 403 + 60s
        backoff. Conservative batching with 15s delays avoids throttles.

        Returns (resource_batch_size, user_batch_size, delay_seconds).
        """
        total = num_resources + num_users
        if total <= 50:
            res_batch, usr_batch, delay = 2, 8, 12.0
        elif total <= 500:
            res_batch, usr_batch, delay = 2, 8, 15.0
        elif total <= 5000:
            res_batch, usr_batch, delay = 1, 6, 15.0
        else:
            res_batch, usr_batch, delay = 1, 5, 15.0

        # Allow CLI overrides
        if override_size and override_size > 0:
            res_batch = override_size
        if override_delay is not None and override_delay >= 0:
            delay = float(override_delay)

        return res_batch, usr_batch, delay

    @staticmethod
    def _set_gateway_pool_size(params, project_name, max_instances):
        """Set max instances for the newly created gateway."""
        from ..pam import gateway_helper
        gateways = gateway_helper.get_all_gateways(params)
        gw_name = f'{project_name} Gateway'
        match = next((g for g in gateways if g.controllerName == gw_name), None)
        if match:
            try:
                from ...proto import pam_pb2
                from ... import api
                rq = pam_pb2.PAMSetMaxInstanceCountRequest()
                rq.controllerUid = match.controllerUid
                rq.maxInstanceCount = max_instances
                api.communicate_rest(params, rq, 'pam/set_controller_max_instance_count')
                logging.warning('Gateway pool size set to %d instances.', max_instances)
            except Exception as e:
                logging.warning('Could not set pool size: %s', type(e).__name__)
        else:
            logging.warning('Could not find gateway "%s" to set pool size.', gw_name)

    @staticmethod
    def _print_estimate(groups, resources, users, skip_users,
                        include_disabled, total_connections):
        """Print a pre-import migration estimate."""
        # Count resource types
        type_counts = {}  # type: Dict[str, int]
        for r in resources:
            rtype = r.get('type', 'pamMachine')
            type_counts[rtype] = type_counts.get(rtype, 0) + 1
        num_users = len(users) if not skip_users else 0
        num_resources = len(resources)

        # Estimate API calls per record type (measured via instrumentation):
        #   resource + nested user: ~20 calls (avg 19.2, range 16-25)
        #   external user (login): ~8 calls (avg 8.0, range 6-10)
        #   project setup: ~20 calls (folders, KSM app, gateway, config)
        api_per_resource = 20
        api_per_user = 8
        api_setup = 20
        est_api_calls = (api_setup
                         + num_resources * api_per_resource
                         + num_users * api_per_user)

        # Time estimates at different throughput rates (requests per second)
        rates = [
            ('Conservative  (5 req/s)', 5),
            ('Standard     (15 req/s)', 15),
            ('Enterprise   (50 req/s)', 50),
        ]

        def _fmt_duration(seconds):
            if seconds < 60:
                return f'{seconds:.0f}s'
            m, s = divmod(int(seconds), 60)
            if m < 60:
                return f'{m}m {s:02d}s'
            h, m = divmod(m, 60)
            return f'{h}h {m:02d}m {s:02d}s'

        print()
        print('=' * 60)
        print('KCM Migration Estimate')
        print('=' * 60)
        print()
        print(f'  Connection groups:   {len(groups):>6d}')
        print(f'  Total connections:   {total_connections:>6d}')
        if not include_disabled:
            disabled = total_connections - num_resources
            if disabled > 0:
                print(f'  Disabled (excluded): {disabled:>6d}')
        print()
        print('  Resources:')
        for rtype, count in sorted(type_counts.items()):
            label = rtype.replace('pam', '').replace('Machine', 'SSH/RDP/VNC')
            print(f'    {label:<22s} {count:>5d}')
        print(f'    {"Total":<22s} {num_resources:>5d}')
        print()
        if skip_users:
            print('  Users:                 (skipped)')
        else:
            print(f'  Users:               {num_users:>6d}')
        print()
        print(f'  Estimated API calls: ~{est_api_calls:>5d}')
        print()
        print('  Estimated import time:')
        for label, rps in rates:
            seconds = est_api_calls / rps
            print(f'    {label}  {_fmt_duration(seconds):>10s}')
        print()
        print('=' * 60)
        print()
        logging.info('Estimate complete. Run without --estimate to import.')

    @staticmethod
    def _validate_import_data(resources, users, skip_users):
        """Pre-import validation. Returns list of warning strings."""
        warnings = []

        # Check for resources with rotation_settings (should never exist from KCM)
        for r in resources:
            if r.get('rotation_settings'):
                warnings.append(
                    f'Resource "{r.get("title")}" has rotation_settings '
                    f'(unexpected for KCM imports)')
        if not skip_users:
            for u in users:
                if u.get('rotation_settings'):
                    warnings.append(
                        f'User "{u.get("title")}" has rotation_settings '
                        f'(will cause errors without admin credentials)')
            for r in resources:
                for nu in r.get('users', []):
                    if nu.get('rotation_settings'):
                        warnings.append(
                            f'Nested user "{nu.get("title")}" has rotation_settings')

        # Check for unnested users (will become external users without resource linkage)
        if not skip_users and users:
            warnings.append(
                f'{len(users)} user(s) not linked to any resource '
                f'(will be created as external users)')

        # Check for resources missing host
        for r in resources:
            if not r.get('host'):
                warnings.append(
                    f'Resource "{r.get("title")}" has no host/IP address')

        return warnings

    @staticmethod
    def _flag_incomplete_records(resources, users, res_root, usr_root):
        """Flag records with incomplete KCM source data.

        Moves incomplete resources/users to an 'Incomplete (KCM Source)'
        subfolder and adds a 'notes' field describing the issues.
        """
        incomplete_res_folder = f'{res_root}/Incomplete (KCM Source)'
        incomplete_usr_folder = f'{usr_root}/Incomplete (KCM Source)'

        # Protocols that require a host field (pamRemoteBrowser uses url)
        host_required = {'ssh', 'rdp', 'vnc', 'telnet',
                         'mysql', 'postgresql', 'sql-server'}
        # Protocols that require a login on the user record
        login_required = {'ssh', 'rdp', 'telnet',
                          'mysql', 'postgresql', 'sql-server'}

        # Build a lookup from resource title to user for cross-referencing
        user_by_title = {}
        for u in users:
            t = u.get('title', '')
            if t:
                user_by_title.setdefault(t, []).append(u)

        for resource in resources:
            conn = resource.get('pam_settings', {}).get('connection', {})
            protocol = conn.get('protocol', '')
            issues = []

            # Check host for protocols that need it
            if protocol in host_required and not resource.get('host'):
                issues.append(f'Missing host/IP address (required for {protocol})')

            # Check url for http/pamRemoteBrowser
            if protocol == 'http' and not resource.get('host') and not resource.get('url'):
                issues.append('Missing URL (required for Remote Browser connections)')

            # Check SFTP completeness for RDP/VNC
            sftp = conn.get('sftp', {})
            if protocol in ('rdp', 'vnc') and sftp.get('enable_sftp'):
                missing_sftp = []
                if not sftp.get('host'):
                    missing_sftp.append('host')
                if not sftp.get('port'):
                    missing_sftp.append('port')
                if not sftp.get('login'):
                    missing_sftp.append('login')
                if not sftp.get('password') and not sftp.get('private_key'):
                    missing_sftp.append('password or private_key')
                if missing_sftp:
                    issues.append(
                        f'SFTP enabled but missing: {", ".join(missing_sftp)}')

            # Check user login and passphrase for protocols that require it
            launch_cred = conn.get('launch_credentials', '')
            if protocol in login_required and launch_cred:
                matched_users = user_by_title.get(launch_cred, [])
                for u in matched_users:
                    if not u.get('login'):
                        issues.append(
                            f'User "{launch_cred}" has no login '
                            f'(required for {protocol})')
                        break
                # Warn if private key exists but passphrase was dropped
                for u in matched_users:
                    if u.get('private_pem_key') and not u.get('passphrase'):
                        issues.append(
                            f'User "{launch_cred}" has a private key but '
                            f'its passphrase was not imported (if the key '
                            f'is encrypted, authentication will fail)')
                        break

            if not issues:
                continue

            # Build note text
            note_lines = [
                'INCOMPLETE DATA AT KCM SOURCE',
                '=' * 35,
                f'Protocol: {protocol}',
                f'Original folder: {resource.get("folder_path", "unknown")}',
                '',
                'Issues found:',
            ]
            for i, issue in enumerate(issues, 1):
                note_lines.append(f'  {i}. {issue}')
            note_lines.extend([
                '',
                'This record was imported from KCM (Guacamole) with incomplete',
                'configuration. It was moved to the "Incomplete (KCM Source)"',
                'folder for review. Fix the missing fields above, then move',
                'the record to the appropriate folder.',
            ])
            resource['notes'] = '\n'.join(note_lines)

            # Move resource to incomplete folder
            resource['folder_path'] = incomplete_res_folder

            # Move matching user(s) too
            if launch_cred:
                for u in user_by_title.get(launch_cred, []):
                    u['folder_path'] = incomplete_usr_folder

    @staticmethod
    def _print_import_summary(project_name, config_uid, num_resources,
                              num_users, resources, users, skip_users):
        """Print pre-import summary with folder hierarchy for user review."""
        mode = 'Extend existing project' if config_uid else 'New project'

        print()
        print('=' * 60)
        print('KCM Import Summary')
        print('=' * 60)
        print()
        print(f'  Project:    {project_name}')
        print(f'  Mode:       {mode}')
        print(f'  Resources:  {num_resources}')
        print(f'  Users:      {num_users}')
        print()

        # Collect and display folder hierarchy
        folders = set()
        for r in resources:
            fp = r.get('folder_path', '')
            if fp:
                folders.add(fp)
            for nu in r.get('users', []):
                nfp = nu.get('folder_path', '')
                if nfp:
                    folders.add(nfp)
        if not skip_users:
            for u in users:
                fp = u.get('folder_path', '')
                if fp:
                    folders.add(fp)

        if folders:
            print('  Folders to create:')
            for f in sorted(folders):
                # Count records in this folder
                count = sum(1 for r in resources if r.get('folder_path') == f)
                if not skip_users:
                    count += sum(1 for u in users if u.get('folder_path') == f)
                    for r in resources:
                        count += sum(1 for nu in r.get('users', [])
                                     if nu.get('folder_path') == f)
                print(f'    {f}  ({count} records)')
            print()

        print('  This will create vault records that cannot be easily undone.')
        print('  Use --dry-run to preview the full JSON first.')

    @staticmethod
    def _print_deploy_instructions(project_name):
        """Print Docker deployment one-liner after gateway creation."""
        print('\n' + '─' * 60)
        print('Gateway Deployment')
        print('─' * 60)
        print()
        print('Copy the access_token from above and deploy:')
        print()
        print('  # Docker (single instance)')
        print('  docker run -d --name keeper-gateway \\')
        print('    -e GATEWAY_CONFIG="<access_token>" \\')
        print('    -e ACCEPT_EULA=Y \\')
        print('    --shm-size=2g \\')
        print('    --restart unless-stopped \\')
        print('    keeper/gateway:latest')
        print()
        print('  # Docker Compose (HA pool)')
        print('  # Set GATEWAY_CONFIG in .env, then:')
        print('  # docker compose up -d')
        print()
        print('  # Kubernetes')
        print('  # Use the base64 config as a Secret:')
        print('  # kubectl create secret generic gateway-config \\')
        print('  #   --from-literal=GATEWAY_CONFIG="<access_token>"')
        print()
        print(f'  # Verify (after deployment):')
        print(f'  pam gateway list  # should show "{project_name} Gateway" as ONLINE')
        print('─' * 60)

    @staticmethod
    def _resolve_gateway(params, gateway_arg):
        """Interactive gateway selection. Returns PAM config UID or None.

        Flow:
          --gateway <uid/name>  → find matching gateway, find its config, use extend mode
          (no flag, interactive) → list gateways, let user choose or create new
          'new' choice          → return None (import engine creates new gateway)
        """
        from ..pam import gateway_helper
        from ..pam.router_helper import router_get_connected_gateways

        gateways = gateway_helper.get_all_gateways(params)

        # Determine online status by cross-referencing with router
        online_uids = set()
        try:
            connected = router_get_connected_gateways(params)
            if connected and connected.controllers:
                online_uids = {c.controllerUid for c in connected.controllers}
        except Exception:
            logging.debug('Could not reach router to check online gateways')

        online = [g for g in gateways if g.controllerUid in online_uids]

        # If --gateway flag provided, find it directly
        if gateway_arg:
            match = None
            for g in gateways:
                uid_str = utils.base64_url_encode(g.controllerUid)
                if uid_str == gateway_arg or g.controllerName == gateway_arg:
                    match = g
                    break
            if not match:
                raise CommandError('kcm-import',
                    f'Gateway "{gateway_arg}" not found. Use --dry-run to preview without a gateway.')
            if match.controllerUid not in online_uids:
                logging.warning('Gateway "%s" is OFFLINE — connections will not work until it is started.',
                                match.controllerName)
            return PAMProjectKCMImportCommand._find_config_for_gateway(params, match)

        # Interactive: show options
        print('\nGateway Selection')
        print('─' * 50)
        if online:
            print(f'  Found {len(online)} online gateway(s):\n')
            for i, g in enumerate(online, 1):
                uid_str = utils.base64_url_encode(g.controllerUid)
                print(f'  [{i}] {g.controllerName}  ({uid_str})')
            print(f'\n  [N] Create a new gateway')
            print()
            choice = input('  Select gateway [N]: ').strip()
            if choice and choice.upper() != 'N':
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(online):
                        selected = online[idx]
                        logging.info('Using existing gateway: %s', selected.controllerName)
                        return PAMProjectKCMImportCommand._find_config_for_gateway(params, selected)
                except (ValueError, IndexError):
                    pass
                logging.warning('Invalid selection — creating new gateway.')
        else:
            print('  No online gateways found.')
            print('  A new gateway will be created. Deploy it with the token shown after import.\n')

        # Return None = import engine creates new gateway
        return None

    @staticmethod
    def _find_config_for_gateway(params, gateway):
        """Find the PAM config UID associated with a gateway."""
        from ..pam.config_helper import configuration_controller_get

        gateway_uid_bytes = gateway.controllerUid

        # Search all PAM configs to find one linked to this gateway
        all_records = params.record_cache.values()
        for rec in all_records:
            if rec.get('version') != 6:
                continue
            try:
                rec_uid = rec.get('record_uid', '')
                if not rec_uid:
                    continue
                controller = configuration_controller_get(
                    params, utils.base64_url_decode(rec_uid))
                if controller and controller.controllerUid == gateway_uid_bytes:
                    logging.info('Found PAM config "%s" for gateway "%s"',
                                 rec_uid, gateway.controllerName)
                    return rec_uid
            except Exception as e:
                logging.debug('Skipping record %s: %s', rec_uid, e)
                continue

        raise CommandError('kcm-import',
            f'No PAM configuration found for gateway "{gateway.controllerName}". '
            f'Create one first with: pam config create')

    @staticmethod
    def _create_project_skeleton(params, project_name, pam_json):
        """Phase 1: Create PAM project skeleton (folders, KSM app, gateway,
        PAM config) without records.  Returns the PAM config UID."""
        from .edit import PAMProjectImportCommand
        from ... import api as keeper_api

        skeleton_json = copy.deepcopy(pam_json)
        skeleton_json['pam_data']['resources'] = []
        skeleton_json['pam_data']['users'] = []
        skeleton_json['project'] = project_name

        tmp_fd, tmp_path = tempfile.mkstemp(suffix='.json')
        try:
            with os.fdopen(tmp_fd, 'w') as tmp:
                json.dump(skeleton_json, tmp, indent=2)

            cmd = PAMProjectImportCommand()
            cmd.execute(params,
                        project_name=project_name,
                        file_name=tmp_path,
                        dry_run=False)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

        # Find the PAM config just created
        keeper_api.sync_down(params)
        config_name = f'{project_name} Configuration'
        from ... import vault_extensions
        for cfg in vault_extensions.find_records(params, record_version=6):
            if cfg.title == config_name:
                return cfg.record_uid

        raise CommandError('kcm-import',
            f'Failed to find PAM config "{config_name}" after skeleton creation')

    @staticmethod
    def _rewrite_folder_paths(pam_json, actual_res_name, actual_usr_name, project_name):
        """Rewrite folder_path roots to match actual shared folder names.

        Needed when edit.py adds a #N dedup suffix to the project folder,
        making the actual shared folder names differ from the computed ones.
        """
        old_res = f'{project_name} - Resources'
        old_usr = f'{project_name} - Users'
        if old_res == actual_res_name and old_usr == actual_usr_name:
            return

        pam_data = pam_json.get('pam_data', {})
        for item in pam_data.get('resources', []):
            fp = item.get('folder_path', '')
            if fp == old_res or fp.startswith(old_res + '/'):
                item['folder_path'] = actual_res_name + fp[len(old_res):]
            # Also rewrite nested users inside this resource
            for nested in item.get('users', []):
                nfp = nested.get('folder_path', '')
                if nfp == old_usr or nfp.startswith(old_usr + '/'):
                    nested['folder_path'] = actual_usr_name + nfp[len(old_usr):]
        for item in pam_data.get('users', []):
            fp = item.get('folder_path', '')
            if fp == old_usr or fp.startswith(old_usr + '/'):
                item['folder_path'] = actual_usr_name + fp[len(old_usr):]

    @staticmethod
    def _discover_shared_folder_names(params, config_uid):
        """Discover shared folder names from an existing PAM config's KSM app.

        Returns (resources_folder_name, users_folder_name) or (None, None).
        """
        from ..pam.config_helper import configuration_controller_get
        from ..pam import gateway_helper
        from ...loginv3 import CommonHelperMethods
        from ... import api as keeper_api

        keeper_api.sync_down(params)
        configuration = vault.KeeperRecord.load(params, config_uid)
        if not configuration:
            return None, None

        try:
            controller = configuration_controller_get(
                params, CommonHelperMethods.url_safe_str_to_bytes(
                    configuration.record_uid))
        except Exception as e:
            logging.debug('Could not resolve controller for config %s: %s',
                          config_uid, e)
            return None, None
        if not controller or not controller.controllerUid:
            return None, None

        all_gateways = gateway_helper.get_all_gateways(params)
        found = [g for g in all_gateways
                 if g.controllerUid == controller.controllerUid]
        if not found:
            return None, None

        # Import extend only when needed — it pulls in pydantic which may
        # not be available in all CI environments.
        from .extend import PAMProjectExtendCommand
        ksmapp_uid = utils.base64_url_encode(found[0].applicationUid)
        cmd = PAMProjectExtendCommand()
        ksm_shared_folders = cmd.get_app_shared_folders(params, ksmapp_uid)

        res_name = usr_name = None
        for shf in ksm_shared_folders:
            name = shf.get('name', '')
            if name.endswith('- Resources'):
                res_name = name
            elif name.endswith('- Users'):
                usr_name = name
        return res_name, usr_name

    def _resolve_db_password(self, params, kwargs):
        record_uid = kwargs.get('db_password_record') or ''
        if record_uid:
            record = vault.KeeperRecord.load(params, record_uid)
            if not record:
                raise CommandError('kcm-import',
                    f'Record {record_uid} not found in vault')
            # PasswordRecord (v2) has .password directly
            if hasattr(record, 'password') and record.password:
                return record.password
            # TypedRecord (v3) stores password in typed fields
            if hasattr(record, 'get_typed_field'):
                field = record.get_typed_field('password')
                if field and field.value:
                    val = field.value
                    if isinstance(val, list) and val:
                        return str(val[0])
                    if isinstance(val, str) and val:
                        return val
            raise CommandError('kcm-import',
                f'Record {record_uid} has no password field')
        return getpass.getpass('KCM Database Password: ')

    @staticmethod
    def _is_local_host(host):
        """Check if host is a local/private address (no SSL warning needed).

        Only trusts literal IP addresses and 'localhost'. Does NOT resolve
        hostnames via DNS to prevent TOCTOU / SSRF bypass of SSL enforcement.
        """
        if not host:
            return False
        if host in ('localhost', '127.0.0.1', '::1'):
            return True
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            # Hostname, not a literal IP — treat as remote (require SSL)
            return False
        if addr.is_loopback:
            return True
        return any(addr in net for net in PAMProjectKCMImportCommand._PRIVATE_NETS)

    @staticmethod
    def _detect_docker_credentials(db_type, container='guacamole'):
        # Env var prefixes vary across deployments:
        #   KCM docker-compose: GUACAMOLE_*
        #   Vanilla Guacamole:  MYSQL_* / POSTGRESQL_*
        #   Some images:        POSTGRES_* (short form)
        if db_type == 'mysql':
            db_prefixes = ['MYSQL']
        else:
            db_prefixes = ['POSTGRESQL', 'POSTGRES']
        default_port = 3306 if db_type == 'mysql' else 5432

        # Single docker inspect call, parse all env vars at once
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format',
                 '{{range .Config.Env}}{{println .}}{{end}}', '--', container],
                capture_output=True, text=True, timeout=10
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            raise CommandError('kcm-import',
                f'Docker inspect failed: {type(e).__name__}')

        if result.returncode != 0:
            logging.debug('Docker stderr: %s', result.stderr.strip())
            raise CommandError('kcm-import',
                f'Docker inspect failed for container "{container}" (exit code {result.returncode})')

        env_vars = {}
        for line in result.stdout.strip().splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                env_vars[k] = v
        # Clear raw docker output — contains all container env vars including secrets
        result = None

        def _env(field, default=''):
            val = env_vars.get(f'GUACAMOLE_{field}')
            if not val:
                for prefix in db_prefixes:
                    val = env_vars.get(f'{prefix}_{field}')
                    if val:
                        break
            return val or default

        try:
            password = _env('PASSWORD')
            if not password:
                prefix_list = ' or '.join(
                    f'{p}_PASSWORD' for p in ['GUACAMOLE'] + db_prefixes)
                raise CommandError('kcm-import',
                    f'Could not detect database password from Docker container "{container}". '
                    f'Expected {prefix_list} in container env.')

            host = _env('HOSTNAME', '127.0.0.1')
            user = _env('USER') or _env('USERNAME', 'guacamole_user')
            database = _env('DATABASE', 'guacamole_db')
            port_str = _env('PORT')
            try:
                port = int(port_str) if port_str else default_port
            except ValueError:
                raise CommandError('kcm-import',
                    f'Invalid port value from Docker: {port_str}')

            # Resolve Docker service hostnames (e.g. "db") to container IPs
            host = PAMProjectKCMImportCommand._resolve_docker_host(host, container)

            logging.info('Docker auto-detected: host=%s, port=%d, db=%s',
                         host, port, database)
            # Return connection info separate from password so static analysis
            # can distinguish sensitive from non-sensitive values
            return (host, port, database, user), password
        finally:
            env_vars.clear()

    @staticmethod
    def _resolve_docker_host(host, source_container):
        """Resolve a Docker service hostname to a reachable container IP.

        When the detected hostname is a Docker service name (e.g. 'db'),
        it is only resolvable inside the Docker network. This method
        finds the actual container IP by inspecting containers on the
        same Docker network(s) as the source container.
        """
        # If already an IP address or localhost, return as-is
        if host in ('localhost', '127.0.0.1', '::1'):
            return host
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass

        # hostname is a service name — resolve via Docker inspect
        try:
            # Get networks the source container is on
            result = subprocess.run(
                ['docker', 'inspect', '--format',
                 '{{range $net, $conf := .NetworkSettings.Networks}}'
                 '{{$net}} {{end}}', '--', source_container],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                logging.debug('Could not inspect networks for %s', source_container)
                return host
            networks = result.stdout.strip().split()

            # Search for a container whose name/alias matches the hostname
            for network in networks:
                result = subprocess.run(
                    ['docker', 'network', 'inspect', '--format',
                     '{{range .Containers}}{{.Name}}|{{.IPv4Address}}\n{{end}}',
                     network],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode != 0:
                    continue
                for line in result.stdout.strip().splitlines():
                    if '|' not in line:
                        continue
                    name, ip_cidr = line.split('|', 1)
                    # Match: exact name, or host appears as a segment
                    # (e.g., "postgres" matches "project-postgres-1")
                    name_lower = name.lower()
                    host_lower = host.lower()
                    segments = name_lower.replace('_', '-').split('-')
                    if (host_lower == name_lower or host_lower in segments) \
                            and '/' in ip_cidr:
                        resolved_ip = ip_cidr.split('/')[0]
                        logging.info('Resolved Docker hostname "%s" to %s '
                                     '(container: %s)', host, resolved_ip, name)
                        return resolved_ip

            logging.warning('Could not resolve Docker hostname "%s" — '
                            'using as-is. If connection fails, use --db-host '
                            'with the container IP.', host)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logging.debug('Docker command failed during hostname resolution')
        return host

    @staticmethod
    def _redact_for_display(pam_json):
        """Deep-copy JSON and replace password values with [REDACTED]."""
        redacted = copy.deepcopy(pam_json)
        sensitive_keys = {'password', 'private_pem_key', 'private_key', 'otp',
                          '_totp_parts'}
        def _walk(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in sensitive_keys and v:
                        obj[k] = '[REDACTED]'
                    else:
                        _walk(v)
            elif isinstance(obj, list):
                for item in obj:
                    _walk(item)
        _walk(redacted)
        return redacted


class PAMProjectKCMCleanupCommand(Command):
    """Remove a KCM-imported project: shared folders, records, gateway, KSM app.

    Usage:
        pam project kcm-cleanup --name "KCM-Import-20260404-203552"
        pam project kcm-cleanup --config <PAM_CONFIG_UID>
    """

    parser = argparse.ArgumentParser(prog='pam project kcm-cleanup')
    parser.add_argument('--name', '-n', dest='project_name', action='store',
                        help='Project name (matches PAM config title prefix)')
    parser.add_argument('--config', '-c', dest='config_uid', action='store',
                        help='PAM config record UID')
    parser.add_argument('--dry-run', '-d', dest='dry_run', action='store_true',
                        default=False, help='Show what would be deleted')
    parser.add_argument('--yes', '-y', dest='auto_confirm', action='store_true',
                        default=False, help='Skip confirmation prompt')

    def get_parser(self):
        return PAMProjectKCMCleanupCommand.parser

    def execute(self, params, **kwargs):
        project_name = kwargs.get('project_name') or ''
        config_uid = kwargs.get('config_uid') or ''
        dry_run = kwargs.get('dry_run', False)
        auto_confirm = kwargs.get('auto_confirm', False)

        if not project_name and not config_uid:
            raise CommandError('kcm-cleanup',
                'Either --name or --config is required')

        from ... import api as keeper_api
        from ..pam import gateway_helper
        from ..pam.config_helper import configuration_controller_get
        from ...loginv3 import CommonHelperMethods

        keeper_api.sync_down(params)

        # Step 1: Find the PAM config record
        config_record = None
        if config_uid:
            config_record = vault.KeeperRecord.load(params, config_uid)
            if not config_record:
                raise CommandError('kcm-cleanup',
                    f'PAM config record "{config_uid}" not found')
            project_name = config_record.title.replace(' Configuration', '')
        else:
            # Search by project name
            config_name = f'{project_name} Configuration'
            from ... import vault_extensions
            for cfg in vault_extensions.find_records(params, record_version=6):
                if cfg.title == config_name:
                    config_record = cfg
                    config_uid = cfg.record_uid
                    break
            if not config_record:
                raise CommandError('kcm-cleanup',
                    f'PAM config "{config_name}" not found. '
                    f'Use --config with the exact UID.')

        # Step 2: Find the gateway
        gateway_uid = None
        gateway_name = None
        gw_match = None
        try:
            controller = configuration_controller_get(
                params, CommonHelperMethods.url_safe_str_to_bytes(
                    config_record.record_uid))
            if controller and controller.controllerUid:
                gateway_uid = controller.controllerUid
                all_gw = gateway_helper.get_all_gateways(params)
                gw_match = next((g for g in all_gw
                                 if g.controllerUid == gateway_uid), None)
                if gw_match:
                    gateway_name = gw_match.controllerName
        except Exception as e:
            logging.debug('Could not resolve gateway: %s', e)

        # Step 3: Find the KSM app
        ksm_app_uid = None
        ksm_app_name = None
        if gw_match and gw_match.applicationUid:
                ksm_app_uid = utils.base64_url_encode(gw_match.applicationUid)
                # Find app name from shared_folder_cache or record_cache
                app_rec = vault.KeeperRecord.load(params, ksm_app_uid)
                if app_rec:
                    ksm_app_name = getattr(app_rec, 'title', ksm_app_uid)

        # Step 4: Find shared folders
        sf_names = []
        sf_uids = []
        res_name = f'{project_name} - Resources'
        usr_name = f'{project_name} - Users'
        for sf_uid, sf in params.shared_folder_cache.items():
            name = sf.get('name_unencrypted', '')
            if name in (res_name, usr_name) or name.startswith(f'{project_name} '):
                sf_names.append(name)
                sf_uids.append(sf_uid)

        # Step 5: Count records in shared folders
        record_uids = set()
        for sf_uid in sf_uids:
            sf = params.shared_folder_cache.get(sf_uid, {})
            for rec in sf.get('records', []):
                rec_uid = rec.get('record_uid', '')
                if rec_uid:
                    record_uids.add(rec_uid)

        # Also count records in subfolders
        for folder_uid, folder in params.folder_cache.items():
            if hasattr(folder, 'shared_folder_uid') and folder.shared_folder_uid in sf_uids:
                for rec_uid in params.subfolder_record_cache.get(folder_uid, []):
                    record_uids.add(rec_uid)

        # Display what will be deleted
        print()
        print('=' * 60)
        print('KCM Project Cleanup')
        print('=' * 60)
        print()
        print(f'  Project:          {project_name}')
        print(f'  PAM Config:       {config_uid}')
        print(f'  Gateway:          {gateway_name or "(not found)"}')
        print(f'  KSM App:          {ksm_app_name or "(not found)"}')
        print(f'  Shared Folders:   {len(sf_names)}')
        for name in sorted(sf_names):
            print(f'    - {name}')
        print(f'  Records:          {len(record_uids)}')
        print()

        if dry_run:
            print('  (dry run — no changes made)')
            print('=' * 60)
            return

        if not auto_confirm:
            answer = input('  Delete all of the above? [y/N]: ').strip().lower()
            if answer not in ('y', 'yes'):
                raise CommandError('kcm-cleanup', 'Cleanup cancelled.')

        # Step 6: Delete records (same API as api.delete_record but batched
        # to avoid N individual sync_down calls)
        deleted_count = 0
        if record_uids:
            logging.warning('Deleting %d records...', len(record_uids))
            uid_list = list(record_uids)
            batch_size = 50
            for i in range(0, len(uid_list), batch_size):
                batch = uid_list[i:i + batch_size]
                try:
                    rq = {'command': 'record_update', 'delete_records': batch}
                    keeper_api.communicate(params, rq)
                    deleted_count += len(batch)
                except Exception as e:
                    logging.warning('Failed to delete batch: %s', e)

        # Step 7: Delete shared folders
        if sf_uids:
            logging.warning('Removing %d shared folder(s)...', len(sf_uids))
            for sf_uid in sf_uids:
                try:
                    # Build folder delete request
                    folder = params.folder_cache.get(sf_uid)
                    if folder:
                        del_obj = {
                            'delete_resolution': 'unlink',
                            'object_uid': folder.uid,
                            'object_type': folder.type,
                        }
                        parent = params.folder_cache.get(folder.parent_uid)
                        if parent:
                            del_obj['from_uid'] = parent.uid
                            del_obj['from_type'] = parent.type
                        else:
                            del_obj['from_type'] = 'user_folder'
                        rq = {
                            'command': 'pre_delete',
                            'objects': [del_obj]
                        }
                        rs = keeper_api.communicate(params, rq)
                        if rs.get('result') == 'success':
                            pdr = rs.get('pre_delete_response', {})
                            del_rq = {
                                'command': 'delete',
                                'pre_delete_token': pdr.get('pre_delete_token', '')
                            }
                            keeper_api.communicate(params, del_rq)
                except Exception as e:
                    logging.warning('Failed to remove shared folder %s: %s',
                                    sf_uid, e)

        # Step 8: Remove gateway
        if gateway_uid:
            logging.warning('Removing gateway "%s"...', gateway_name or gateway_uid)
            try:
                gateway_helper.remove_gateway(params, gateway_uid)
            except Exception as e:
                logging.warning('Failed to remove gateway: %s', e)

        # Step 9: Remove KSM app
        if ksm_app_uid:
            logging.warning('Removing KSM app "%s"...', ksm_app_name or ksm_app_uid)
            try:
                from ..ksm import KSMCommand
                KSMCommand.remove_v5_app(params, ksm_app_uid,
                                         purge=True, force=True)
            except Exception as e:
                logging.warning('Failed to remove KSM app: %s', e)

        # Step 10: Delete PAM config record
        if config_uid:
            logging.warning('Deleting PAM config record...')
            try:
                keeper_api.delete_record(params, config_uid)
            except Exception as e:
                logging.warning('Failed to delete config record: %s', e)

        keeper_api.sync_down(params)

        print()
        print('=' * 60)
        print(f'Cleanup complete: {deleted_count} records deleted')
        print('=' * 60)
