import sys

if sys.version_info >= (3, 8):
    import unittest
    from unittest import mock
    from flask import Blueprint, Flask

    from keepercommander.service.api.command import create_command_blueprint, create_legacy_command_blueprint
    from keepercommander.service.api.routes import init_routes


    def passthrough_decorator():
        def decorator(fn):
            return fn
        return decorator


    class TestServiceApiRoutes(unittest.TestCase):
        def test_queue_mode_registers_v1_and_v2_routes(self):
            app = Flask(__name__)
            onboarding_bp = Blueprint("test_onboarding", __name__)

            with mock.patch('keepercommander.service.api.command.unified_api_decorator', passthrough_decorator), \
                 mock.patch('keepercommander.service.api.routes.create_onboarding_blueprint', return_value=onboarding_bp), \
                 mock.patch('keepercommander.service.core.request_queue.queue_manager.start') as mock_start, \
                 mock.patch('keepercommander.service.config.service_config.ServiceConfig.load_config', return_value={"queue_enabled": "y"}):
                init_routes(app)

            routes = {rule.rule for rule in app.url_map.iter_rules()}
            self.assertIn('/api/v1/executecommand', routes)
            self.assertIn('/api/v2/executecommand-async', routes)
            self.assertIn('/api/v2/status/<request_id>', routes)
            self.assertIn('/api/v2/result/<request_id>', routes)
            self.assertIn('/api/v2/queue/status', routes)
            self.assertIn('/health', routes)
            mock_start.assert_called_once()

        def test_legacy_mode_registers_only_v1_route(self):
            app = Flask(__name__)

            with mock.patch('keepercommander.service.api.command.unified_api_decorator', passthrough_decorator), \
                 mock.patch('keepercommander.service.config.service_config.ServiceConfig.load_config', return_value={"queue_enabled": "n"}):
                init_routes(app)

            routes = {rule.rule for rule in app.url_map.iter_rules()}
            self.assertIn('/api/v1/executecommand', routes)
            self.assertNotIn('/api/v2/executecommand-async', routes)

        def test_v1_compatibility_route_waits_for_queue_result(self):
            app = Flask(__name__)

            with mock.patch('keepercommander.service.api.command.unified_api_decorator', passthrough_decorator), \
                 mock.patch('keepercommander.service.api.command.queue_manager.submit_request', return_value='req-1') as mock_submit, \
                 mock.patch('keepercommander.service.api.command.queue_manager.wait_for_result', return_value=({"status": "success", "data": {"command": "ls"}}, 200)) as mock_wait:
                app.register_blueprint(create_legacy_command_blueprint(use_queue=True), url_prefix='/api/v1')
                response = app.test_client().post('/api/v1/executecommand', json={"command": "ls"})

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get('X-API-Legacy'), 'true')
            self.assertEqual(response.get_json(), {"status": "success", "data": {"command": "ls"}})
            mock_submit.assert_called_once_with('ls', [])
            mock_wait.assert_called_once_with('req-1')

        def test_v1_direct_route_keeps_legacy_execution_path(self):
            app = Flask(__name__)

            with mock.patch('keepercommander.service.api.command.unified_api_decorator', passthrough_decorator), \
                 mock.patch('keepercommander.service.api.command.CommandExecutor.execute', return_value=({"status": "success", "data": {"command": "ls"}}, 200)) as mock_execute, \
                 mock.patch('keepercommander.service.api.command.queue_manager.submit_request') as mock_submit:
                app.register_blueprint(create_legacy_command_blueprint(use_queue=False), url_prefix='/api/v1')
                response = app.test_client().post('/api/v1/executecommand', json={"command": "ls"})

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers.get('X-API-Legacy'), 'true')
            self.assertEqual(response.get_json(), {"status": "success", "data": {"command": "ls"}})
            mock_execute.assert_called_once_with('ls')
            mock_submit.assert_not_called()
