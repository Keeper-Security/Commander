"""Tests for ``download-membership`` --timeout / --api-page-size-limit (MM-11)."""


from contextlib import contextmanager
from unittest import TestCase, mock

from keepercommander.commands.base import ParseError
from keepercommander.importer import commands
from keepercommander.importer.cyberark.cyberark import CyberArkMembershipDownload

def _page(values, count):
    response = mock.MagicMock()
    response.status_code = 200
    response.json.return_value = {'value': values, 'count': count}
    return response




@contextmanager
def _api_safes_source():
    """Force ``fetch_all_safes`` onto the PVWA request path."""
    with mock.patch('keepercommander.importer.cyberark.cyberark.path.isfile', return_value=False), \
            mock.patch.dict('keepercommander.importer.cyberark.cyberark.environ', {}, clear=True):
        yield

class TestMembershipDownloadParser(TestCase):
    parser = commands.download_membership_parser

    def test_defaults(self):
        opts = self.parser.parse_args(['--source', 'cyberark'])
        self.assertEqual(opts.timeout, 10)
        self.assertEqual(opts.api_page_size_limit, 200)


    def test_custom_values(self):
        opts = self.parser.parse_args(['--source', 'cyberark', '--timeout', '60', '--api-page-size-limit', '50'])
        self.assertEqual(opts.timeout, 60)
        self.assertEqual(opts.api_page_size_limit, 50)


    def test_non_integer_timeout_rejected(self):
        with self.assertRaises(ParseError):
            self.parser.parse_args(['--source', 'cyberark', '--timeout', 'abc'])


    def test_non_integer_page_size_rejected(self):
        with self.assertRaises(ParseError):
            self.parser.parse_args(['--source', 'cyberark', '--api-page-size-limit', '1.5'])


    def test_negative_timeout_accepted_by_parser(self):
        opts = self.parser.parse_args(['--source', 'cyberark', '--timeout', '-5'])
        self.assertEqual(opts.timeout, -5)


    def test_negative_page_size_accepted_by_parser(self):
        opts = self.parser.parse_args(['--source', 'cyberark', '--api-page-size-limit', '-10'])
        self.assertEqual(opts.api_page_size_limit, -10)


class TestCyberArkMembershipDownload(TestCase):
    HOST = 'pvwa.example.com'

    def setUp(self):
        mock.patch('keepercommander.importer.cyberark.cyberark.print_formatted_text').start()
        mock.patch('keepercommander.importer.cyberark.cyberark.sleep').start()
        self.plugin = CyberArkMembershipDownload()

    def tearDown(self):
        mock.patch.stopall()


    def test_ispositive_int(self):
        f = CyberArkMembershipDownload._ispositive_int
        self.assertEqual(f(5), 5)
        self.assertEqual(f('42'), 42)
        for value in (0, -1, '0', 'abc', None, '', '1.5'):
            with self.subTest(value=value):
                self.assertIsNone(f(value))


    def test_set_timeout_none_keeps_current(self):
        self.plugin.timeout = 33
        self.assertTrue(self.plugin.set_timeout(None))
        self.assertEqual(self.plugin.timeout, 33)


    def test_set_timeout_invalid(self):
        for value in (9, 1, 0, -5, 'abc'):
            with self.subTest(value=value):
                self.plugin.timeout = 10
                self.assertFalse(self.plugin.set_timeout(value))
                self.assertEqual(self.plugin.timeout, 10)


    def test_negative_timeout_rejected(self):
        self.assertFalse(self.plugin.set_timeout(-5))
        self.assertEqual(self.plugin.timeout, 10)


    def test_set_page_size_none_keeps_current(self):
        self.assertTrue(self.plugin.set_api_page_size_limit(None))
        self.assertEqual(self.plugin.api_page_size_limit, 200)


    def test_set_page_size_invalid(self):
        for value in (9, 0, -1, 'abc'):
            with self.subTest(value=value):
                self.plugin.api_page_size_limit = 200
                self.assertFalse(self.plugin.set_api_page_size_limit(value))
                self.assertEqual(self.plugin.api_page_size_limit, 200)


    def test_negative_page_size_rejected(self):
        self.assertFalse(self.plugin.set_api_page_size_limit(-10))
        self.assertEqual(self.plugin.api_page_size_limit, 200)


    def _fetch_safes(self, pages, page_size):
        self.plugin.api_page_size_limit = page_size
        with _api_safes_source(), mock.patch.object(self.plugin, 'get_response', side_effect=pages) as get_response:
            safes = self.plugin.fetch_all_safes(self.HOST, 'token')
        return safes, get_response


    def test_fetch_all_safes_uses_page_size(self):
        pages = [_page([{'safeName': 'a'}, {'safeName': 'b'}], 3), _page([{'safeName': 'c'}], 3)]
        safes, get_response = self._fetch_safes(pages, page_size=2)
        self.assertEqual([s['safeName'] for s in safes], ['a', 'b', 'c'])
        queries = [c.args[2] for c in get_response.call_args_list]
        self.assertEqual(queries, [{'offset': 0, 'limit': 2}, {'offset': 2, 'limit': 2}])


    def test_fetch_all_safes_empty_response(self):
        cases = (
            ('count zero', [], 0),
            ('empty value list', [], 5),
        )
        for name, values, count in cases:
            with self.subTest(case=name):
                safes, get_response = self._fetch_safes([_page(values, count)], page_size=2)
                self.assertEqual(safes, [])
                self.assertEqual(get_response.call_count, 1)
                self.assertEqual(get_response.call_args.args[2], {'offset': 0, 'limit': 2})


    def test_fetch_all_safes_exact_page_multiple(self):
        pages = [
            _page([{'safeName': 'a'}, {'safeName': 'b'}], 4),
            _page([{'safeName': 'c'}, {'safeName': 'd'}], 4),
        ]
        safes, get_response = self._fetch_safes(pages, page_size=2)
        self.assertEqual([s['safeName'] for s in safes], ['a', 'b', 'c', 'd'])
        self.assertEqual(get_response.call_count, 2)
        queries = [c.args[2] for c in get_response.call_args_list]
        self.assertEqual(queries, [{'offset': 0, 'limit': 2}, {'offset': 2, 'limit': 2}])


    def test_fetch_all_safes_single_page(self):
        for count in (1, 2):
            with self.subTest(count=count):
                values = [{'safeName': f's{i}'} for i in range(count)]
                safes, get_response = self._fetch_safes([_page(values, count)], page_size=2)
                self.assertEqual([s['safeName'] for s in safes], [f's{i}' for i in range(count)])
                self.assertEqual(get_response.call_count, 1)
                self.assertEqual(get_response.call_args.args[2], {'offset': 0, 'limit': 2})


    def test_fetch_safe_members_uses_page_size(self):
        self.plugin.api_page_size_limit = 15
        page = _page([{'memberName': 'alice'}, {'memberName': 'Master', 'isPredefinedUser': True}], 2)
        with mock.patch.object(self.plugin, 'get_response', return_value=page) as get_response:
            members = self.plugin.fetch_safe_members(self.HOST, 'token', 'Safe1')
        self.assertEqual(members, [{'memberName': 'alice'}])
        self.assertEqual(get_response.call_args.args[2], {'offset': 0, 'limit': 15})


    def _assert_request_timeout(self, fetch):
        """Fail when ``get_response`` sends ``TIMEOUT`` instead of ``timeout``."""
        self.plugin.TIMEOUT = 10
        self.plugin.timeout = 45
        page = _page([{'safeName': 'a', 'memberName': 'alice'}], 1)
        with _api_safes_source(), mock.patch.object(self.plugin, '_request', return_value=page) as request:
            fetch()
        self.assertGreaterEqual(request.call_count, 1)
        for call in request.call_args_list:
            self.assertEqual(call.kwargs['timeout'], 45)


    def test_fetch_all_safes_forwards_timeout(self):
        self.plugin.api_page_size_limit = 2
        self._assert_request_timeout(lambda: self.plugin.fetch_all_safes(self.HOST, 'token'))


    def test_fetch_safe_members_forwards_timeout(self):
        self.plugin.api_page_size_limit = 15
        self._assert_request_timeout(
            lambda: self.plugin.fetch_safe_members(self.HOST, 'token', 'Safe1')
        )



