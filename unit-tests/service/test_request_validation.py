import json
import unittest

from flask import Flask

from keepercommander.service.util.request_validation import RequestValidator

app = Flask(__name__)


class TestValidateRequestJson(unittest.TestCase):
    def test_valid_json_passes(self):
        with app.test_request_context('/', method='POST',
                                       data=json.dumps({"command": "ls"}),
                                       content_type='application/json'):
            self.assertIsNone(RequestValidator.validate_request_json())

    def test_wrong_content_type_rejected(self):
        with app.test_request_context('/', method='POST',
                                       data='{"command": "ls"}',
                                       content_type='text/plain'):
            response, status = RequestValidator.validate_request_json()
            self.assertEqual(status, 400)
            self.assertIn('Content-Type', response.get_json()['error'])

    def test_empty_json_object_rejected(self):
        """{} is falsy in Python, and was rejected by the old `if not request.json`
        check - the get_json()-based rewrite must preserve that, not just check for None."""
        with app.test_request_context('/', method='POST',
                                       data='{}',
                                       content_type='application/json'):
            response, status = RequestValidator.validate_request_json()
            self.assertEqual(status, 400)
            self.assertEqual(response.get_json()['error'], 'Invalid or empty JSON')

    def test_malformed_json_does_not_leak_parser_detail(self):
        with app.test_request_context('/', method='POST',
                                       data='{not valid json',
                                       content_type='application/json'):
            response, status = RequestValidator.validate_request_json()
            self.assertEqual(status, 400)
            error_message = response.get_json()['error']
            self.assertEqual(error_message, 'Invalid JSON format')
            self.assertNotIn('not valid json', error_message)
            self.assertNotIn('line', error_message)
            self.assertNotIn('column', error_message)


if __name__ == '__main__':
    unittest.main()
