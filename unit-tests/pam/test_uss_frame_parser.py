"""Unit tests for make_uss_frame_parser and the USS dry-run result printer."""
import io
import json
import unittest
from contextlib import redirect_stdout

from keepercommander.commands.pam.router_helper import make_uss_frame_parser
from keepercommander.commands.universalsecretsync import PAMUniversalSyncRunCommand

CONV = 'abcdefghijklmnopqrstuv'


def frame(data, conv=CONV, **payload_extra):
    payload = {'is_ok': True, 'data': json.dumps(data), **payload_extra}
    return json.dumps({'type': 'gw_response', 'conversationId': conv, 'payload': json.dumps(payload)})


class TestUssFrameParser(unittest.TestCase):
    def setUp(self):
        self.parse = make_uss_frame_parser(CONV)

    def test_terminal_frame(self):
        data = {'new_secrets': [{'secret_name': 'a'}]}
        self.assertEqual(self.parse(frame(data)), data)

    def test_ack_ignored(self):
        self.assertIsNone(self.parse(frame({'Response': 'Queued', 'jobId': CONV})))

    def test_other_conversation_ignored(self):
        self.assertIsNone(self.parse(frame({'new_secrets': []}, conv='zzzzzzzzzzzzzzzzzzzzzz')))

    def test_progress_frame_ignored(self):
        self.assertIsNone(self.parse(frame({'new_secrets': []}, progressFlag=2)))

    def test_complete_and_fail_flags_accepted(self):
        for flag in (0, 1):
            self.assertEqual(self.parse(frame({'new_secrets': []}, progressFlag=flag)), {'new_secrets': []})

    def test_top_level_progress_flag(self):
        raw = json.loads(frame({'new_secrets': []}))
        raw['progressFlag'] = 2
        self.assertIsNone(self.parse(json.dumps(raw)))
        raw['progressFlag'] = 0
        self.assertEqual(self.parse(json.dumps(raw)), {'new_secrets': []})

    def test_progress_then_complete_in_array(self):
        frames = [json.loads(frame({'new_secrets': ['p']}, progressFlag=2)),
                  json.loads(frame({'new_secrets': ['done']}, progressFlag=0))]
        self.assertEqual(self.parse(json.dumps(frames)), {'new_secrets': ['done']})

    def test_error_payload(self):
        raw = json.dumps({'conversationId': CONV, 'payload': json.dumps({'is_ok': False, 'errors': ['boom']})})
        self.assertIn('boom', self.parse(raw)['error'])

    def test_garbage(self):
        self.assertIsNone(self.parse('not json'))


class TestDryRunPrinter(unittest.TestCase):
    @staticmethod
    def render(data):
        buf = io.StringIO()
        with redirect_stdout(buf):
            PAMUniversalSyncRunCommand._print_dry_run_results(data)
        return buf.getvalue()

    def test_unchanged_present(self):
        out = self.render({'new_secrets': [], 'unchanged_secrets': [{'secret_name': 'x'}]})
        self.assertIn('UNCHANGED: x', out)

    def test_unchanged_missing_mentions_version(self):
        self.assertIn('KDNRM 1.4.42', self.render({'new_secrets': []}))


if __name__ == '__main__':
    unittest.main()
