import sys

if sys.version_info >= (3, 8):
    import queue
    import threading
    import time
    import unittest
    from unittest import mock
    from flask import Flask

    from keepercommander.service.api.command import create_command_blueprint, create_legacy_command_blueprint
    from keepercommander.service.core.request_queue import (
        DEFAULT_QUEUE_MAX_SIZE,
        DEFAULT_REQUEST_TIMEOUT,
        DEFAULT_RESULT_RETENTION,
        RequestQueueManager,
    )


    def passthrough_decorator():
        def decorator(fn):
            return fn
        return decorator


    class TestQueueConcurrency(unittest.TestCase):
        def setUp(self):
            self.manager = RequestQueueManager()
            self._reset_manager()

        def tearDown(self):
            self._reset_manager()

        def _reset_manager(self):
            self.manager.stop()
            self.manager.request_queue = queue.Queue(maxsize=DEFAULT_QUEUE_MAX_SIZE)
            self.manager.active_requests = {}
            self.manager.completed_requests = {}
            self.manager.worker_thread = None
            self.manager.is_running = False
            self.manager.current_request_id = None
            self.manager.request_timeout = DEFAULT_REQUEST_TIMEOUT
            self.manager.result_retention = DEFAULT_RESULT_RETENTION

        def _create_app(self, include_v2=False):
            app = Flask(__name__)
            with mock.patch('keepercommander.service.api.command.unified_api_decorator', passthrough_decorator):
                app.register_blueprint(create_legacy_command_blueprint(use_queue=True), url_prefix='/api/v1')
                if include_v2:
                    app.register_blueprint(create_command_blueprint(), url_prefix='/api/v2')
            return app

        def test_queue_manager_serializes_concurrent_submissions(self):
            state_lock = threading.Lock()
            inflight = {"count": 0, "max": 0}
            results = {}

            def fake_execute(command):
                with state_lock:
                    inflight["count"] += 1
                    inflight["max"] = max(inflight["max"], inflight["count"])

                time.sleep(0.05)

                with state_lock:
                    inflight["count"] -= 1

                return {"status": "success", "data": {"command": command}}, 200

            with mock.patch('keepercommander.service.core.request_queue.CommandExecutor.execute', side_effect=fake_execute):
                self.manager.start()

                def submit_and_wait(index):
                    request_id = self.manager.submit_request(f"cmd-{index}")
                    results[index] = self.manager.wait_for_result(request_id, timeout=2)

                threads = [threading.Thread(target=submit_and_wait, args=(i,)) for i in range(5)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()

            self.assertEqual(inflight["max"], 1)
            self.assertEqual(len(results), 5)
            for index in range(5):
                payload, status_code = results[index]
                self.assertEqual(status_code, 200)
                self.assertEqual(payload["data"]["command"], f"cmd-{index}")

        def test_v1_and_v2_share_single_queue_worker(self):
            app = self._create_app(include_v2=True)
            state_lock = threading.Lock()
            inflight = {"count": 0, "max": 0}
            outputs = {}
            start_barrier = threading.Barrier(3)

            def fake_execute(command):
                with state_lock:
                    inflight["count"] += 1
                    inflight["max"] = max(inflight["max"], inflight["count"])

                time.sleep(0.05)

                with state_lock:
                    inflight["count"] -= 1

                return {"status": "success", "data": {"command": command}}, 200

            with mock.patch('keepercommander.service.api.command.queue_manager', self.manager), \
                 mock.patch('keepercommander.service.core.request_queue.CommandExecutor.execute', side_effect=fake_execute):
                self.manager.start()

                def call_v1():
                    with app.test_client() as client:
                        start_barrier.wait()
                        response = client.post('/api/v1/executecommand', json={"command": "legacy-cmd"})
                        outputs["v1"] = (response.status_code, response.get_json(), response.headers.get('X-API-Legacy'))

                def call_v2():
                    with app.test_client() as client:
                        start_barrier.wait()
                        response = client.post('/api/v2/executecommand-async', json={"command": "async-cmd"})
                        response_data = response.get_json()
                        outputs["v2_submit"] = (response.status_code, response_data)
                        outputs["v2_result"] = self.manager.wait_for_result(response_data["request_id"], timeout=2)

                v1_thread = threading.Thread(target=call_v1)
                v2_thread = threading.Thread(target=call_v2)
                v1_thread.start()
                v2_thread.start()
                start_barrier.wait()
                v1_thread.join()
                v2_thread.join()

            self.assertEqual(inflight["max"], 1)
            self.assertEqual(outputs["v1"][0], 200)
            self.assertEqual(outputs["v1"][1]["data"]["command"], "legacy-cmd")
            self.assertEqual(outputs["v1"][2], "true")
            self.assertEqual(outputs["v2_submit"][0], 202)
            self.assertEqual(outputs["v2_submit"][1]["status"], "queued")
            self.assertEqual(outputs["v2_result"][1], 200)
            self.assertEqual(outputs["v2_result"][0]["data"]["command"], "async-cmd")

        def test_timed_out_v1_request_does_not_execute_after_expiration(self):
            app = self._create_app(include_v2=False)
            request_timeout = 0.1
            self.manager.request_timeout = request_timeout

            first_started = threading.Event()
            release_first = threading.Event()
            executed_commands = []
            executed_lock = threading.Lock()

            def fake_execute(command):
                with executed_lock:
                    executed_commands.append(command)

                if command == "first":
                    first_started.set()
                    release_first.wait(timeout=2)

                return {"status": "success", "data": {"command": command}}, 200

            with mock.patch('keepercommander.service.api.command.queue_manager', self.manager), \
                 mock.patch('keepercommander.service.core.request_queue.CommandExecutor.execute', side_effect=fake_execute):
                self.manager.start()

                def call_first():
                    with app.test_client() as client:
                        return client.post('/api/v1/executecommand', json={"command": "first"})

                first_thread = threading.Thread(target=call_first)
                first_thread.start()
                self.assertTrue(first_started.wait(timeout=1))

                with app.test_client() as client:
                    second_response = client.post('/api/v1/executecommand', json={"command": "second"})

                self.assertEqual(second_response.status_code, 504)

                release_first.set()
                first_thread.join()
                time.sleep(request_timeout + 0.1)

            self.assertIn("first", executed_commands)
            self.assertNotIn("second", executed_commands)

        def test_processing_v1_request_waits_past_queue_timeout(self):
            app = self._create_app(include_v2=False)
            request_timeout = 0.1
            self.manager.request_timeout = request_timeout

            started_processing = threading.Event()

            def fake_execute(command):
                started_processing.set()
                time.sleep(request_timeout + 0.15)
                return {"status": "success", "data": {"command": command}}, 200

            with mock.patch('keepercommander.service.api.command.queue_manager', self.manager), \
                 mock.patch('keepercommander.service.core.request_queue.CommandExecutor.execute', side_effect=fake_execute):
                self.manager.start()

                with app.test_client() as client:
                    response = client.post('/api/v1/executecommand', json={"command": "slow-command"})

            self.assertTrue(started_processing.is_set())
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["data"]["command"], "slow-command")
