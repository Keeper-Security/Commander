import contextlib
import io
import unittest
from unittest import mock

import requests

from keepercommander.importer import commands
from keepercommander.importer.thycotic.thycotic import (
    ThycoticAttachment,
    ThycoticAuth,
    ThycoticImporter,
    build_secrets_lookup_query,
    lookup_secret_ids,
    with_secret_access_params,
)

VISIBLE_ID = 7
RESTRICTED_ID = 4242
SHARED_ID = 99
CHECKOUT_QUERY = 'autoCheckout=true&autoCheckIn=true&autoComment=Checking%20out'
REQUESTS_GET = 'keepercommander.importer.thycotic.thycotic.requests.get'
SLEEP = 'keepercommander.importer.thycotic.thycotic.time.sleep'


def _search(query):
    rows = [{'id': VISIBLE_ID, 'name': 'visible'}]
    if 'filter.includeRestricted=true' in query:
        rows.append({'id': RESTRICTED_ID, 'name': 'restricted'})
    return rows


def _response(status_code, text='', json_value=None, reason=''):
    rs = mock.Mock(spec=requests.Response)
    rs.status_code = status_code
    rs.text = text
    rs.reason = reason
    if json_value is None:
        rs.json.side_effect = ValueError('Expecting value')
    else:
        rs.json.return_value = json_value
    return rs


def _auth():
    auth = ThycoticAuth('https://ss.example.com/SecretServer')
    auth.access_token = 'token'
    auth.expires_in = 3600
    auth.last_login = 2 ** 40
    return auth


class TestRestrictedLookup(unittest.TestCase):
    def test_parameter_is_on_every_lookup(self):
        tenant = build_secrets_lookup_query()
        folder = build_secrets_lookup_query(15)
        self.assertEqual(tenant, '/v1/secrets/lookup?filter.includeRestricted=true')
        self.assertEqual(
            folder,
            '/v1/secrets/lookup?filter.folderId=15&filter.includeSubFolders=true&filter.includeRestricted=true',
        )

    def test_restricted_ids_appear_only_when_enabled(self):
        self.assertEqual(lookup_secret_ids(_search), [VISIBLE_ID, RESTRICTED_ID])
        self.assertEqual(lookup_secret_ids(_search, include_restricted=False), [VISIBLE_ID])
        self.assertIn(RESTRICTED_ID, lookup_secret_ids(_search, folder_ids=[15]))
        self.assertNotIn(RESTRICTED_ID, lookup_secret_ids(_search, folder_ids=[15], include_restricted=False))

    def test_include_restricted_flag_is_not_on_the_command(self):
        flags = [
            option
            for action in commands.import_parser._actions
            for option in action.option_strings
        ]
        self.assertNotIn('--include-restricted', flags)
        self.assertNotIn('--report', flags)


class TestLookupDeduplication(unittest.TestCase):
    def test_secret_in_overlapping_folders_is_returned_once(self):
        # Folder 20 is a subfolder of 10; both match the folder filter, and
        # includeSubFolders=true makes folder 10 return folder 20's secrets too.
        by_folder = {
            '10': [{'id': VISIBLE_ID}, {'id': SHARED_ID}],
            '20': [{'id': SHARED_ID}, {'id': RESTRICTED_ID}],
        }

        def search(query):
            folder_id = query.split('filter.folderId=')[1].split('&')[0]
            return by_folder[folder_id]

        ids = lookup_secret_ids(search, folder_ids=[10, 20])
        self.assertEqual(ids, [VISIBLE_ID, SHARED_ID, RESTRICTED_ID])

    def test_same_folder_listed_twice_is_returned_once(self):
        ids = lookup_secret_ids(_search, folder_ids=[15, 15])
        self.assertEqual(ids, [VISIBLE_ID, RESTRICTED_ID])


class TestSecretAccessParams(unittest.TestCase):
    def test_secret_read_sends_checkout_params(self):
        self.assertEqual(with_secret_access_params('/v1/secrets/42'), f'/v1/secrets/42?{CHECKOUT_QUERY}')
        self.assertEqual(
            with_secret_access_params('/v1/secrets/42/fields/private-key'),
            f'/v1/secrets/42/fields/private-key?{CHECKOUT_QUERY}',
        )

    def test_space_is_percent_encoded(self):
        endpoint = with_secret_access_params('/v1/secrets/42')
        self.assertIn('autoComment=Checking%20out', endpoint)
        self.assertNotIn('+', endpoint)

    def test_existing_query_params_are_kept(self):
        endpoint = with_secret_access_params('/v1/secrets/42?includeInactive=true')
        self.assertEqual(endpoint, f'/v1/secrets/42?includeInactive=true&{CHECKOUT_QUERY}')

    def test_existing_checkout_params_are_replaced_not_duplicated(self):
        endpoint = with_secret_access_params('/v1/secrets/42?autoCheckout=false&autoComment=old')
        self.assertEqual(endpoint.count('autoCheckout='), 1)
        self.assertEqual(endpoint.count('autoComment='), 1)
        self.assertIn('autoCheckout=true', endpoint)
        self.assertNotIn('autoComment=old', endpoint)

    def test_round_trip_is_stable(self):
        once = with_secret_access_params('/v1/secrets/42')
        self.assertEqual(with_secret_access_params(once), once)


class TestThycoticSecret(unittest.TestCase):
    def setUp(self):
        sleep = mock.patch(SLEEP)
        sleep.start()
        self.addCleanup(sleep.stop)

    def test_plain_read_succeeds_without_checkout(self):
        with mock.patch(REQUESTS_GET, return_value=_response(200, '{"id": 42}', {'id': 42})) as get:
            secret, error = _auth().thycotic_secret('/v1/secrets/42')
        self.assertEqual(secret, {'id': 42})
        self.assertIsNone(error)
        self.assertEqual(get.call_count, 1)
        self.assertTrue(get.call_args[0][0].endswith('/api/v1/secrets/42'))
        self.assertNotIn('autoCheckout', get.call_args[0][0])

    def test_checkout_params_added_only_after_plain_read_fails(self):
        denied = _response(400, '{"message": "Checkout required"}', {'message': 'Checkout required'})
        ok = _response(200, '{"id": 42}', {'id': 42})
        with mock.patch(REQUESTS_GET, side_effect=[denied, ok]) as get:
            secret, error = _auth().thycotic_secret('/v1/secrets/42')
        self.assertEqual(secret, {'id': 42})
        self.assertIsNone(error)
        first_url = get.call_args_list[0][0][0]
        retry_url = get.call_args_list[1][0][0]
        self.assertNotIn('autoCheckout', first_url)
        self.assertTrue(retry_url.endswith(f'/api/v1/secrets/42?{CHECKOUT_QUERY}'))

    def test_checkout_retry_keeps_existing_query_params(self):
        denied = _response(400, '{"message": "Comment required"}', {'message': 'Comment required'})
        ok = _response(200, '{"id": 42}', {'id': 42})
        with mock.patch(REQUESTS_GET, side_effect=[denied, ok]) as get:
            _auth().thycotic_secret('/v1/secrets/42?includeInactive=true')
        retry_url = get.call_args_list[1][0][0]
        self.assertTrue(retry_url.endswith(f'/api/v1/secrets/42?includeInactive=true&{CHECKOUT_QUERY}'))

    def test_returns_error_when_both_reads_fail(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        with mock.patch(REQUESTS_GET, return_value=denied) as get:
            secret, error = _auth().thycotic_secret('/v1/secrets/42')
        self.assertIsNone(secret)
        self.assertEqual(error, (403, 'Access denied'))
        self.assertEqual(get.call_count, 2)

    def test_error_uses_body_when_response_is_not_json(self):
        html = _response(502, '<html>Bad Gateway</html>', reason='Bad Gateway')
        with mock.patch(REQUESTS_GET, return_value=html):
            secret, error = _auth().thycotic_secret('/v1/secrets/42')
        self.assertIsNone(secret)
        self.assertEqual(error, (502, '<html>Bad Gateway</html>'))

    def test_error_reports_network_failure(self):
        with mock.patch(REQUESTS_GET, side_effect=requests.exceptions.ConnectionError('refused')):
            secret, error = _auth().thycotic_secret('/v1/secrets/42')
        self.assertIsNone(secret)
        self.assertEqual(error, ('N/A', 'refused'))

    def test_error_reports_exception_on_checkout_read(self):
        auth = _auth()
        with mock.patch.object(auth, 'ensure_auth_token', side_effect=Exception('refresh failed')):
            secret, error = auth.thycotic_secret('/v1/secrets/42')
        self.assertIsNone(secret)
        self.assertEqual(error, ('N/A', 'refresh failed'))

    def test_checkout_retry_runs_when_plain_read_raises(self):
        auth = _auth()
        ok = _response(200, '{"id": 42}', {'id': 42})
        with mock.patch.object(auth, 'ensure_auth_token', side_effect=[Exception('refresh failed'), None]), \
                mock.patch(REQUESTS_GET, return_value=ok) as get:
            secret, _ = auth.thycotic_secret('/v1/secrets/42')
        self.assertEqual(secret, {'id': 42})
        self.assertEqual(get.call_count, 1)
        self.assertIn('autoCheckout=true', get.call_args[0][0])


class TestThycoticSecretGet(unittest.TestCase):
    def test_plain_field_read_succeeds_without_checkout(self):
        ok = _response(200, 'key')
        with mock.patch(REQUESTS_GET, return_value=ok) as get:
            rs = _auth().thycotic_secret_get('/v1/secrets/42/fields/private-key')
        self.assertIs(rs, ok)
        self.assertEqual(get.call_count, 1)
        self.assertNotIn('autoCheckout', get.call_args[0][0])

    def test_field_read_retries_with_checkout_and_closes_failed_response(self):
        denied = _response(400, '{"message": "Checkout required"}', {'message': 'Checkout required'})
        ok = _response(200, 'key')
        with mock.patch(REQUESTS_GET, side_effect=[denied, ok]) as get:
            rs = _auth().thycotic_secret_get('/v1/secrets/42/fields/private-key')
        self.assertIs(rs, ok)
        denied.close.assert_called_once()
        retry_url = get.call_args_list[1][0][0]
        self.assertTrue(retry_url.endswith(f'/api/v1/secrets/42/fields/private-key?{CHECKOUT_QUERY}'))

    def test_field_read_retries_with_checkout_after_exception(self):
        ok = _response(200, 'key')
        with mock.patch(SLEEP), mock.patch(REQUESTS_GET, side_effect=[
                requests.exceptions.ConnectionError('reset'), requests.exceptions.ConnectionError('reset'), ok]) as get:
            rs = _auth().thycotic_secret_get('/v1/secrets/42/fields/private-key')
        self.assertIs(rs, ok)
        self.assertIn('autoCheckout=true', get.call_args_list[2][0][0])


class TestThycoticEntity(unittest.TestCase):
    def setUp(self):
        sleep = mock.patch(SLEEP)
        sleep.start()
        self.addCleanup(sleep.stop)

    def test_entity_never_adds_checkout_params(self):
        denied = _response(400, '{"message": "Bad request"}', {'message': 'Bad request'})
        with mock.patch(REQUESTS_GET, return_value=denied) as get:
            self.assertIsNone(_auth().thycotic_entity('/v1/secret-templates/5/export'))
        self.assertEqual(get.call_count, 1)

    def test_network_error_returns_none(self):
        error = requests.exceptions.ConnectionError('connection refused')
        with mock.patch(REQUESTS_GET, side_effect=error) as get:
            secret = _auth().thycotic_entity('/v1/secrets/42')
        self.assertIsNone(secret)
        self.assertEqual(get.call_count, 2)

    def test_network_error_recovers_on_retry(self):
        error = requests.exceptions.ConnectionError('connection reset')
        ok = _response(200, '{"id": 42}', {'id': 42})
        with mock.patch(REQUESTS_GET, side_effect=[error, ok]):
            secret = _auth().thycotic_entity('/v1/secrets/42')
        self.assertEqual(secret, {'id': 42})

    def test_non_json_error_response_does_not_crash(self):
        html = _response(502, '<html>Bad Gateway</html>', reason='Bad Gateway')
        with mock.patch(REQUESTS_GET, return_value=html):
            self.assertIsNone(_auth().thycotic_entity('/v1/secrets/42'))

    def test_non_json_success_response_does_not_crash(self):
        with mock.patch(REQUESTS_GET, return_value=_response(200, '<html>login</html>')):
            self.assertIsNone(_auth().thycotic_entity('/v1/secrets/42'))

    def test_json_error_that_is_not_an_object_does_not_crash(self):
        with mock.patch(REQUESTS_GET, return_value=_response(500, '["boom"]', ['boom'])):
            self.assertIsNone(_auth().thycotic_entity('/v1/secrets/42'))


class TestThycoticAttachment(unittest.TestCase):
    def test_successful_download_sets_content(self):
        ok = _response(200, 'data')
        ok.headers = {'Content-Length': '4'}
        ok.content = b'data'
        ok.__enter__ = mock.Mock(return_value=ok)
        ok.__exit__ = mock.Mock(return_value=False)
        auth = _auth()
        with mock.patch.object(auth, 'thycotic_secret_get', return_value=ok):
            attachment = ThycoticAttachment(auth, '/v1/secrets/42/fields/cert', 'cert.pem')
            attachment.prepare()
        self.assertEqual(attachment.size, 4)

    def test_failed_download_warns_and_leaves_size_unset(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        denied.__enter__ = mock.Mock(return_value=denied)
        denied.__exit__ = mock.Mock(return_value=False)
        auth = _auth()
        with mock.patch.object(auth, 'thycotic_secret_get', return_value=denied), \
                self.assertLogs(level='WARNING') as logs:
            attachment = ThycoticAttachment(auth, '/v1/secrets/42/fields/cert', 'cert.pem')
            attachment.prepare()
        self.assertIsNone(attachment.size)
        self.assertIn('cert.pem', logs.output[0])
        self.assertIn('403', logs.output[0])
        self.assertIn('Access denied', logs.output[0])

    def test_network_error_warns_instead_of_raising(self):
        auth = _auth()
        with mock.patch.object(auth, 'thycotic_secret_get',
                               side_effect=requests.exceptions.ConnectionError('reset')), \
                self.assertLogs(level='WARNING') as logs:
            ThycoticAttachment(auth, '/v1/secrets/42/fields/cert', 'cert.pem').prepare()
        self.assertIn('reset', logs.output[0])


class TestPrintSkipped(unittest.TestCase):
    def _output(self, secrets, fields):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ThycoticImporter.print_skipped(secrets, fields)
        return out.getvalue()

    def test_nothing_printed_when_nothing_skipped(self):
        self.assertEqual(self._output([], []), '')

    def test_skipped_secrets_table(self):
        output = self._output([
            {'ID': 42, 'Status': 403, 'Message': 'Access denied'},
            {'ID': 108, 'Status': 'N/A', 'Message': 'Read timed out'},
        ], [])
        self.assertIn('Skipped 2 Secrets:', output)
        for text in ('ID', 'Status', 'Message', '42', '403', 'Access denied', '108', 'Read timed out'):
            self.assertIn(text, output)
        self.assertNotIn('Fields', output)

    def test_skipped_fields_table(self):
        output = self._output([], [
            {'ID': 77, 'Secret': 'DB Server', 'Field': 'private-key', 'Status': 400, 'Message': 'Checkout required'},
        ])
        self.assertIn('Skipped 1 Fields:', output)
        for text in ('Secret', 'Field', 'DB Server', 'private-key', 'Checkout required'):
            self.assertIn(text, output)
        self.assertNotIn('Secrets:', output)


class TestErrorResponses(unittest.TestCase):
    def test_log_response_handles_none(self):
        with self.assertLogs(level='INFO') as logs:
            _auth()._log_thycotic_response('/v1/secrets/42', None, 'boom')
        self.assertIn('no response', logs.output[0])

    def test_search_non_json_error_raises_readable_message(self):
        html = _response(503, '<html>Service Unavailable</html>', reason='Service Unavailable')
        with mock.patch(REQUESTS_GET, return_value=html):
            with self.assertRaises(Exception) as ctx:
                _auth().thycotic_search('/v1/secrets/lookup')
        self.assertIn('HTTP 503', str(ctx.exception))
        self.assertNotIsInstance(ctx.exception, ValueError)

    def test_search_json_error_uses_message(self):
        denied = _response(403, '{"message": "Access denied"}', {'message': 'Access denied'})
        with mock.patch(REQUESTS_GET, return_value=denied):
            with self.assertRaises(Exception) as ctx:
                _auth().thycotic_search('/v1/secrets/lookup')
        self.assertEqual(str(ctx.exception), 'Access denied')

    def test_refresh_non_json_error_raises_readable_message(self):
        auth = _auth()
        auth.refresh_token = 'refresh'
        html = _response(500, '<html>Server Error</html>', reason='Internal Server Error')
        with mock.patch('keepercommander.importer.thycotic.thycotic.requests.post', return_value=html):
            with self.assertRaises(Exception) as ctx:
                auth.refresh_auth_token()
        self.assertIn('HTTP 500', str(ctx.exception))


class TestThycoticTerminalSummary(unittest.TestCase):
    def test_uses_cyberark_finish_summary(self):
        self.assertTrue(ThycoticImporter.verbose_import_summary)


if __name__ == '__main__':
    unittest.main()
