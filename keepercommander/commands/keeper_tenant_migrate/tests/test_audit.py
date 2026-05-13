import hashlib
import json
import os
import stat
import tempfile
import unittest

from keepercommander.commands.keeper_tenant_migrate.audit import (
    append_audit_event,
    hash_directory_tree,
    hash_verify_receipt,
    sha256_of_bytes,
    sha256_of_file,
    verify_audit_log,
    verify_sha256sums,
    write_sha256sums,
)


class HashHelperTests(unittest.TestCase):
    def test_sha256_of_bytes_matches_hashlib(self):
        self.assertEqual(sha256_of_bytes(b'hi'),
                         hashlib.sha256(b'hi').hexdigest())

    def test_sha256_of_file_reads_in_chunks(self):
        with tempfile.NamedTemporaryFile('wb', delete=False) as t:
            payload = b'abc' * 1000
            t.write(payload)
            path = t.name
        try:
            self.assertEqual(sha256_of_file(path),
                             hashlib.sha256(payload).hexdigest())
        finally:
            os.unlink(path)


class Sha256SumsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_roundtrip_write_then_verify(self):
        for name, body in [('a.txt', b'aaa'), ('b.txt', b'bbb')]:
            with open(os.path.join(self.tmp, name), 'wb') as f:
                f.write(body)
        manifest = write_sha256sums(self.tmp)
        self.assertEqual(os.path.basename(manifest), 'SHA256SUMS.txt')
        # 0600 on the manifest
        mode = stat.S_IMODE(os.stat(manifest).st_mode)
        self.assertEqual(mode, 0o600)

        result = verify_sha256sums(self.tmp)
        self.assertEqual(sorted(result['ok']), ['a.txt', 'b.txt'])
        self.assertEqual(result['missing'], [])
        self.assertEqual(result['mismatch'], [])

    def test_detects_missing_file(self):
        with open(os.path.join(self.tmp, 'a.txt'), 'wb') as f:
            f.write(b'x')
        write_sha256sums(self.tmp)
        os.unlink(os.path.join(self.tmp, 'a.txt'))
        result = verify_sha256sums(self.tmp)
        self.assertIn('a.txt', result['missing'])

    def test_detects_tampered_content(self):
        with open(os.path.join(self.tmp, 'a.txt'), 'wb') as f:
            f.write(b'original')
        write_sha256sums(self.tmp)
        with open(os.path.join(self.tmp, 'a.txt'), 'wb') as f:
            f.write(b'tampered')
        result = verify_sha256sums(self.tmp)
        self.assertIn('a.txt', result['mismatch'])

    def test_missing_manifest_raises(self):
        with self.assertRaises(FileNotFoundError):
            verify_sha256sums(self.tmp)

    def test_manifest_excludes_itself(self):
        with open(os.path.join(self.tmp, 'a.txt'), 'wb') as f:
            f.write(b'x')
        write_sha256sums(self.tmp)
        # The manifest file shouldn't appear as a managed row
        with open(os.path.join(self.tmp, 'SHA256SUMS.txt')) as f:
            body = f.read()
        self.assertNotIn('SHA256SUMS.txt', body)

    def test_nested_files_are_hashed_by_default(self):
        # Ensure walk recurses — a nested file lands in the manifest
        # with its relative path.
        os.makedirs(os.path.join(self.tmp, 'sub'))
        with open(os.path.join(self.tmp, 'a.txt'), 'wb') as f:
            f.write(b'top')
        with open(os.path.join(self.tmp, 'sub', 'b.txt'), 'wb') as f:
            f.write(b'nested')
        write_sha256sums(self.tmp)
        result = verify_sha256sums(self.tmp)
        # sub/b.txt uses a path separator — normalize across OSes
        self.assertIn('a.txt', result['ok'])
        self.assertTrue(any('b.txt' in p for p in result['ok']))

    def test_basename_exclude_skips_nested_file_but_logs(self):
        # Legacy: exclude=('audit.log',) skips BOTH top-level and
        # nested — we log a DEBUG line for the nested case.
        os.makedirs(os.path.join(self.tmp, 'sub'))
        with open(os.path.join(self.tmp, 'audit.log'), 'wb') as f:
            f.write(b'top')
        with open(os.path.join(self.tmp, 'sub', 'audit.log'), 'wb') as f:
            f.write(b'nested')
        with open(os.path.join(self.tmp, 'data.txt'), 'wb') as f:
            f.write(b'd')
        write_sha256sums(self.tmp, exclude=('audit.log',))
        with open(os.path.join(self.tmp, 'SHA256SUMS.txt')) as f:
            body = f.read()
        # Both audit.log files excluded; data.txt present
        self.assertNotIn('audit.log', body)
        self.assertIn('data.txt', body)

    def test_strict_path_exclude_only_skips_top_level(self):
        # New: exclude=('audit.log', 'sub/audit.log') would be needed
        # to skip BOTH. Strict top-level-only: 'audit.log' with an
        # explicit path separator in the pattern matches only that path.
        os.makedirs(os.path.join(self.tmp, 'sub'))
        with open(os.path.join(self.tmp, 'audit.log'), 'wb') as f:
            f.write(b'top')
        with open(os.path.join(self.tmp, 'sub', 'audit.log'), 'wb') as f:
            f.write(b'nested')
        # Strict mode — match literal relative path.
        write_sha256sums(self.tmp, exclude=('./audit.log', 'audit.log'))
        result = verify_sha256sums(self.tmp)
        # Top-level audit.log excluded; nested one is ALSO excluded
        # (basename legacy). To get nested-only hashing, strict-only:
        os.unlink(os.path.join(self.tmp, 'SHA256SUMS.txt'))
        write_sha256sums(self.tmp, exclude=('audit.log',))   # legacy
        result = verify_sha256sums(self.tmp)
        # Legacy: both skipped.
        joined = ' '.join(result['ok'])
        self.assertNotIn('audit.log', joined)

    def test_symlinks_skipped_and_logged(self):
        with open(os.path.join(self.tmp, 'real.txt'), 'wb') as f:
            f.write(b'body')
        link_path = os.path.join(self.tmp, 'link.txt')
        os.symlink('real.txt', link_path)
        with self.assertLogs(level='WARNING') as logs:
            write_sha256sums(self.tmp)
        self.assertTrue(any('symlink skipped' in m for m in logs.output))
        # Manifest does NOT include the symlink
        with open(os.path.join(self.tmp, 'SHA256SUMS.txt')) as f:
            body = f.read()
        self.assertIn('real.txt', body)
        self.assertNotIn('link.txt', body)


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.log = os.path.join(self.tmp, 'audit.log')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_chain_valid_across_multiple_events(self):
        append_audit_event(self.log, {'subcommand': 'a'})
        append_audit_event(self.log, {'subcommand': 'b'})
        append_audit_event(self.log, {'subcommand': 'c'})
        ok, broken = verify_audit_log(self.log)
        self.assertTrue(ok)
        self.assertIsNone(broken)

    def test_first_line_prev_hash_is_genesis(self):
        append_audit_event(self.log, {'subcommand': 'a'})
        with open(self.log) as f:
            first = json.loads(f.readline())
        self.assertEqual(first['prev_hash'], '0' * 64)

    def test_tampering_any_earlier_line_breaks_chain(self):
        append_audit_event(self.log, {'subcommand': 'a'})
        append_audit_event(self.log, {'subcommand': 'b'})
        # Flip a character in line 1 — chain should break at line 1 or 2
        with open(self.log) as f:
            lines = f.readlines()
        tampered = json.loads(lines[0])
        tampered['subcommand'] = 'X'
        lines[0] = json.dumps(tampered, sort_keys=True) + '\n'
        with open(self.log, 'w') as f:
            f.writelines(lines)
        ok, broken = verify_audit_log(self.log)
        self.assertFalse(ok)
        self.assertEqual(broken, 1)

    def test_missing_file_returns_false(self):
        ok, broken = verify_audit_log(self.log)
        self.assertFalse(ok)

    def test_invalid_json_line_flagged(self):
        with open(self.log, 'w') as f:
            f.write('not-json\n')
        ok, broken = verify_audit_log(self.log)
        self.assertFalse(ok)
        self.assertEqual(broken, 1)

    # ── 2026-05-10 fail-open property fix ──
    # Pre-fix verify_audit_log returned (True, None) when the file
    # existed but contained zero verifiable events. Consumer asking
    # "chain valid?" got True when there was nothing to validate.
    # Same class as a property-based-test finding from a sister project on b'\x1c' input.

    def test_fail_open_empty_file_now_fails_closed(self):
        # File exists but is 0 bytes — pre-fix (True, None); post-fix False.
        with open(self.log, 'w'):
            pass
        ok, broken = verify_audit_log(self.log)
        self.assertFalse(ok)
        self.assertEqual(broken, 0)

    def test_fail_open_blank_lines_only_now_fails_closed(self):
        with open(self.log, 'w') as f:
            f.write('\n\n\n   \n\t\n')
        ok, broken = verify_audit_log(self.log)
        self.assertFalse(ok)
        self.assertEqual(broken, 0)

    def test_fail_open_whitespace_only_now_fails_closed(self):
        with open(self.log, 'w') as f:
            f.write('   \t  \n   \n')
        ok, broken = verify_audit_log(self.log)
        self.assertFalse(ok)
        self.assertEqual(broken, 0)

    def test_fail_open_ascii_separator_only_now_fails_closed(self):
        # b'\x1c' (ASCII File Separator) — Python's str.strip() removes
        # it because isspace() treats it as whitespace. Pre-fix this was
        # the property-based-test counterexample found on a sister project's audit
        # verify; same property bug existed here.
        with open(self.log, 'wb') as f:
            f.write(b'\x1c\n\x1d\n\x1e\n\x1f\n')
        ok, broken = verify_audit_log(self.log)
        self.assertFalse(ok)
        self.assertEqual(broken, 0)

    def test_one_real_event_after_blank_lines_still_passes(self):
        # Sanity check the fix doesn't break the legitimate case where
        # there's one or more real event but blank lines inbetween.
        append_audit_event(self.log, {'subcommand': 'a'})
        with open(self.log, 'a') as f:
            f.write('\n\n')
        append_audit_event(self.log, {'subcommand': 'b'})
        ok, broken = verify_audit_log(self.log)
        self.assertTrue(ok)
        self.assertIsNone(broken)

    def test_0600_on_log(self):
        append_audit_event(self.log, {'subcommand': 'x'})
        mode = stat.S_IMODE(os.stat(self.log).st_mode)
        self.assertEqual(mode, 0o600)

    # ── SEC-3 regression suite — chain integrity + atomicity + lock ──

    def test_sec3_malformed_last_line_raises_chain_corrupt(self):
        """SEC-3 — pre-fix _last_signature silently returned GENESIS on
        a malformed last line, which let a crash mid-write (or an
        attacker appending garbage) silently reset the chain on the
        next append. Post-fix the next append refuses with
        AuditChainCorrupt and forces the operator to inspect the file.
        """
        from keepercommander.commands.keeper_tenant_migrate.audit import AuditChainCorrupt
        # First event lands cleanly so the chain has a valid baseline.
        append_audit_event(self.log, {'subcommand': 'first'})
        # Now simulate a crash mid-write: append a partial JSON line.
        with open(self.log, 'a') as f:
            f.write('{"subcommand": "partial-cras')  # no closing brace, no newline
        with self.assertRaises(AuditChainCorrupt) as cm:
            append_audit_event(self.log, {'subcommand': 'next'})
        msg = str(cm.exception).lower()
        self.assertIn('malformed', msg)
        self.assertIn('chain', msg)

    def test_sec3_missing_signature_field_raises_chain_corrupt(self):
        """SEC-3 — last line is JSON but missing the `signature` key
        (e.g. someone hand-edited the file). Pre-fix the .get() with
        default GENESIS_HASH silently reset; post-fix we raise.
        """
        from keepercommander.commands.keeper_tenant_migrate.audit import AuditChainCorrupt
        append_audit_event(self.log, {'subcommand': 'first'})
        # Append a syntactically valid but signature-less JSON line.
        with open(self.log, 'a') as f:
            f.write('{"subcommand": "missing-sig"}\n')
        with self.assertRaises(AuditChainCorrupt) as cm:
            append_audit_event(self.log, {'subcommand': 'next'})
        self.assertIn('signature', str(cm.exception).lower())

    def test_sec3_concurrent_appends_form_chain_not_branch(self):
        """SEC-3 — pre-fix two concurrent appends computed the same
        prev_hash from the same tail line, then both wrote events
        claiming the same predecessor → verify_audit_log rejected.
        Post-fix the flock around _last_signature + atomic-replace
        serialises the writers, so concurrent appends form a valid
        linear chain.
        """
        import threading
        events = []
        errors = []
        barrier = threading.Barrier(8)

        def worker(i):
            try:
                barrier.wait()
                ev = append_audit_event(self.log, {'subcommand': f'op-{i}'})
                events.append(ev)
            except Exception as e:           # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [],
                         f'concurrent appends raised: {errors}')
        self.assertEqual(len(events), 8)

        ok, broken_line = verify_audit_log(self.log)
        self.assertTrue(ok, f'chain broken at line {broken_line} after '
                            f'8 concurrent appends — flock did not '
                            f'serialise correctly')

    def test_sec3_atomic_write_no_partial_lines_visible(self):
        """SEC-3 — every line in the log is either fully present or
        fully absent. Read the log mid-write should never see a
        truncated tail line. We approximate this by writing many
        events and asserting every line is parseable JSON.
        """
        for i in range(50):
            append_audit_event(self.log, {'subcommand': f'op-{i}'})
        with open(self.log) as f:
            lines = [ln for ln in f.read().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 50)
        for n, ln in enumerate(lines, 1):
            try:
                json.loads(ln)
            except json.JSONDecodeError:
                self.fail(f'line {n} is malformed: {ln!r}')


class HashDirectoryTreeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_stable_across_runs(self):
        with open(os.path.join(self.tmp, 'a.txt'), 'wb') as f:
            f.write(b'x')
        h1 = hash_directory_tree(self.tmp)
        h2 = hash_directory_tree(self.tmp)
        self.assertEqual(h1, h2)

    def test_changes_when_content_changes(self):
        path = os.path.join(self.tmp, 'a.txt')
        with open(path, 'wb') as f:
            f.write(b'x')
        h1 = hash_directory_tree(self.tmp)
        with open(path, 'wb') as f:
            f.write(b'y')
        h2 = hash_directory_tree(self.tmp)
        self.assertNotEqual(h1, h2)

    def test_ignores_sha256sums_file(self):
        with open(os.path.join(self.tmp, 'a.txt'), 'wb') as f:
            f.write(b'x')
        h_before = hash_directory_tree(self.tmp)
        write_sha256sums(self.tmp)
        h_after = hash_directory_tree(self.tmp)
        self.assertEqual(h_before, h_after)


class HashVerifyReceiptTests(unittest.TestCase):
    """Tampering with a checks CSV after verify must not match the on-chain
    receipt. Any change to severities, counts, or source/target numbers
    produces a different hash."""

    def _sample(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import Check, Severity
        return {
            'checks': [
                Check('nodes', Severity.PASS, 'Node A', ''),
                Check('teams', Severity.FAIL, 'Team B missing', ''),
            ],
            'counts': {'PASS': 1, 'FAIL': 1, 'SKIP': 0, 'WARN': 0},
            'source_counts': {'nodes': 2, 'teams': 2},
            'target_counts': {'nodes': 2, 'teams': 1},
        }

    def test_stable_across_runs(self):
        sample = self._sample()
        h1 = hash_verify_receipt(**sample)
        h2 = hash_verify_receipt(**sample)
        self.assertEqual(h1, h2)

    def test_different_when_severity_changed(self):
        from keepercommander.commands.keeper_tenant_migrate.validate import Check, Severity
        sample = self._sample()
        h1 = hash_verify_receipt(**sample)
        # Flip FAIL → PASS — exactly the kind of after-the-fact tamper
        # we want to detect.
        tampered = dict(sample)
        tampered['checks'] = [
            Check('nodes', Severity.PASS, 'Node A', ''),
            Check('teams', Severity.PASS, 'Team B missing', ''),
        ]
        self.assertNotEqual(h1, hash_verify_receipt(**tampered))

    def test_different_when_target_count_changed(self):
        sample = self._sample()
        h1 = hash_verify_receipt(**sample)
        bad = dict(sample)
        bad['target_counts'] = {'nodes': 99, 'teams': 99}
        self.assertNotEqual(h1, hash_verify_receipt(**bad))

    def test_accepts_plain_dict_checks(self):
        """Validator-independent: raw dicts also hash consistently."""
        dict_form = {
            'counts': {'PASS': 1, 'FAIL': 0, 'SKIP': 0, 'WARN': 0},
            'source_counts': {}, 'target_counts': {},
            'checks': [{'phase': 'nodes', 'severity': 'PASS',
                        'message': 'ok', 'detail': ''}],
        }
        self.assertIsInstance(hash_verify_receipt(**dict_form), str)
        self.assertEqual(len(hash_verify_receipt(**dict_form)), 64)


if __name__ == '__main__':
    unittest.main()
