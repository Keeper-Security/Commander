"""Tests for ``download-membership`` --timeout / --api-page-size-limit (MM-11)."""

import os
import tempfile
from types import SimpleNamespace
from unittest import TestCase, mock

from keepercommander.commands.base import ParseError
from keepercommander.importer import commands
from keepercommander.importer.cyberark.cyberark import CyberArkImporter, CyberArkMembershipDownload


def _page(values, count):
    response = mock.MagicMock()
    response.status_code = 200
    response.json.return_value = {'value': values, 'count': count}
    return response


class TestDownloadMembershipParser(TestCase):
    HOST = 'pvwa.example.com'

    parser = commands.download_membership_parser

    def setUp(self):
        mock.patch('keepercommander.importer.cyberark.cyberark.print_formatted_text').start()
        self.plugin = CyberArkMembershipDownload()

    def tearDown(self):
        mock.patch.stopall()

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

    def test_negative_timeout_rejected(self):
        opts = self.parser.parse_args(['--source', 'cyberark', '--timeout', '-5'])
        self.assertEqual(opts.timeout, -5)  # parser accepts it; plugin rejects it
        with mock.patch('keepercommander.importer.cyberark.cyberark.print_formatted_text'):
            plugin = CyberArkMembershipDownload()
            self.assertFalse(plugin.set_timeout(opts.timeout))
        self.assertEqual(plugin.timeout, 10)
    
    def test_negative_page_size_rejected(self):
        opts = self.parser.parse_args(['--source', 'cyberark', '--api-page-size-limit', '-10'])
        self.assertEqual(opts.api_page_size_limit, -10)
        with mock.patch('keepercommander.importer.cyberark.cyberark.print_formatted_text'):
            plugin = CyberArkMembershipDownload()
            self.assertFalse(plugin.set_api_page_size_limit(opts.api_page_size_limit))
        self.assertEqual(plugin.api_page_size_limit, 200)

    def test_ispositive_int(self):
        f = CyberArkMembershipDownload._ispositive_int
        self.assertEqual(f(5), 5)
        self.assertEqual(f('42'), 42)
        for value in (0, -1, '0', 'abc', None, '', '1.5'):
            self.assertIsNone(f(value), value)

    def test_set_timeout_none_keeps_current(self):
        self.plugin.timeout = 33
        self.assertTrue(self.plugin.set_timeout(None))
        self.assertEqual(self.plugin.timeout, 33)

    def test_set_timeout_invalid(self):
        for value in (9, 1, 0, -5, 'abc'):
            self.plugin.timeout = 10
            self.assertFalse(self.plugin.set_timeout(value), value)
            self.assertEqual(self.plugin.timeout, 10)

    def test_set_page_size_none_keeps_current(self):
        self.assertTrue(self.plugin.set_api_page_size_limit(None))
        self.assertEqual(self.plugin.api_page_size_limit, 200)

    def test_set_page_size_invalid(self):
        for value in (9, 0, -1, 'abc'):
            self.plugin.api_page_size_limit = 200
            self.assertFalse(self.plugin.set_api_page_size_limit(value), value)
            self.assertEqual(self.plugin.api_page_size_limit, 200)

    def test_fetch_all_safes_uses_page_size(self):
        self.plugin.api_page_size_limit = 2
        pages = [_page([{'safeName': 'a'}, {'safeName': 'b'}], 3), _page([{'safeName': 'c'}], 3)]
        with mock.patch.object(self.plugin, 'get_response', side_effect=pages) as get_response:
            safes = self.plugin.fetch_all_safes(self.HOST, 'token')
        self.assertEqual([s['safeName'] for s in safes], ['a', 'b', 'c'])
        queries = [c.args[2] for c in get_response.call_args_list]
        self.assertEqual(queries, [{'offset': 0, 'limit': 2}, {'offset': 2, 'limit': 2}])

    def test_fetch_safe_members_uses_page_size(self):
        self.plugin.api_page_size_limit = 15
        page = _page([{'memberName': 'alice'}, {'memberName': 'Master', 'isPredefinedUser': True}], 2)
        with mock.patch.object(self.plugin, 'get_response', return_value=page) as get_response:
            members = self.plugin.fetch_safe_members(self.HOST, 'token', 'Safe1')
        self.assertEqual(members, [{'memberName': 'alice'}])
        self.assertEqual(get_response.call_args.args[2], {'offset': 0, 'limit': 15})


    