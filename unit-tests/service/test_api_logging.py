import sys
if sys.version_info >= (3, 8):
    import pytest
    from unittest import TestCase, mock
    from flask import Flask, request
    from keepercommander.service.decorators.api_logging import api_log_handler


    class TestApiLogging(TestCase):
        def setUp(self):
            self.app = Flask(__name__)
            self.client = self.app.test_client()

            @self.app.route('/test', methods=['POST'])
            @api_log_handler
            def test_endpoint():
                if not request.is_json:
                    return {'error': 'Content-Type must be application/json'}, 415
                return {'status': 'success'}, 200

            @self.app.route('/error', methods=['POST'])
            @api_log_handler
            def error_endpoint():
                if not request.is_json:
                    return {'error': 'Content-Type must be application/json'}, 415
                raise Exception("Test error")

        def test_api_log_success_request(self):
            """Test logging of successful API request"""
            with mock.patch('keepercommander.service.decorators.api_logging.logger.info') as mock_log:
                test_data = {"test": "data"}
                response = self.client.post('/test',
                                        json=test_data,
                                        headers={
                                            'X-Forwarded-For': '127.0.0.1',
                                            'Content-Type': 'application/json'
                                        })

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json, {'status': 'success'})

                mock_log.assert_called_once()
                log_message = mock_log.call_args[0][0]
                self.assertIn('POST', log_message)
                self.assertIn('/test', log_message)
                self.assertIn('127.0.0.1', log_message)
                self.assertIn('200', log_message)
                self.assertIn(f"data={str(test_data)}", log_message)

        def test_api_log_error_request(self):
            """Test logging of failed API request"""
            with mock.patch('keepercommander.service.decorators.api_logging.logger.error') as mock_log:
                response = self.client.post('/error', json={}, 
                                        headers={'X-Forwarded-For': '127.0.0.1', 
                                                'Content-Type': 'application/json'})

                self.assertEqual(response.status_code, 500)
                mock_log.assert_called_once()
                log_message = mock_log.call_args[0][0]
                self.assertIn('POST', log_message)
                self.assertIn('/error', log_message)
                self.assertIn('127.0.0.1', log_message)
                self.assertIn("error='Test error'", log_message)

        def test_api_log_remote_addr_fallback(self):
            """Test logging falls back to remote_addr when X-Forwarded-For is missing"""
            with mock.patch('keepercommander.service.decorators.api_logging.logger.info') as mock_log:
                response = self.client.post('/test', json={}, 
                                        headers={'Content-Type': 'application/json'}, 
                                        environ_base={'REMOTE_ADDR': '192.168.1.1'})

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json, {'status': 'success'})

                mock_log.assert_called_once()
                log_message = mock_log.call_args[0][0]
                self.assertIn('192.168.1.1', log_message)

        def test_api_log_timing(self):
            """Test request timing is logged"""
            with mock.patch('keepercommander.service.decorators.api_logging.logger.info') as mock_log:
                response = self.client.post('/test', json={}, 
                                        headers={'Content-Type': 'application/json'})

                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.json, {'status': 'success'})

                mock_log.assert_called_once()
                log_message = mock_log.call_args[0][0]
                self.assertRegex(log_message, r'\d+\.\d+s')
