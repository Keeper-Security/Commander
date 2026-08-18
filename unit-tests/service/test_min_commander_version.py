#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

import os
from unittest import TestCase, mock

from flask import Flask
from packaging.version import Version

from keepercommander.service.decorators.min_commander_version import (
    MIN_COMMANDER_VERSION_HEADER,
    TERRAFORM_DOCKER_ENV,
    check_min_commander_version,
    min_commander_version_check,
    _parse_version,
)

_TERRAFORM_DOCKER_ENV = {TERRAFORM_DOCKER_ENV: '1'}


class TestParseVersion(TestCase):
    def test_parses_simple_semver(self):
        self.assertEqual(_parse_version('18.1.0'), Version('18.1.0'))

    def test_strips_v_prefix(self):
        self.assertEqual(_parse_version('v18.2.1'), Version('18.2.1'))

    def test_normalizes_partial_versions(self):
        self.assertEqual(_parse_version('18.1'), Version('18.1.0'))

    def test_rejects_invalid(self):
        self.assertIsNone(_parse_version(''))
        self.assertIsNone(_parse_version('abc'))
        self.assertIsNone(_parse_version('1.2.x'))
        self.assertIsNone(_parse_version('x' * 65))


class TestMinCommanderVersionCheck(TestCase):
    def setUp(self):
        self.app = Flask(__name__)

    @mock.patch.dict(os.environ, _TERRAFORM_DOCKER_ENV, clear=False)
    def test_missing_header_is_noop(self):
        with self.app.test_request_context('/api/v2/executecommand-async', method='POST'):
            self.assertIsNone(check_min_commander_version())

    @mock.patch.dict(os.environ, _TERRAFORM_DOCKER_ENV, clear=False)
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION',
        Version('18.1.0'),
    )
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION_RAW',
        '18.1.0',
    )
    def test_accepts_when_current_meets_minimum(self):
        with self.app.test_request_context(
            '/api/v2/executecommand-async',
            method='POST',
            headers={MIN_COMMANDER_VERSION_HEADER: '18.0.0'},
        ):
            self.assertIsNone(check_min_commander_version())

    @mock.patch.dict(os.environ, _TERRAFORM_DOCKER_ENV, clear=False)
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION',
        Version('18.1.0'),
    )
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION_RAW',
        '18.1.0',
    )
    def test_accepts_case_insensitive_header(self):
        with self.app.test_request_context(
            '/api/v2/executecommand-async',
            method='POST',
            headers={'min-commander-version': '18.1.0'},
        ):
            self.assertIsNone(check_min_commander_version())

    @mock.patch.dict(os.environ, _TERRAFORM_DOCKER_ENV, clear=False)
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION',
        Version('18.1.0'),
    )
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION_RAW',
        '18.1.0',
    )
    def test_accepts_partial_required_version(self):
        with self.app.test_request_context(
            '/api/v2/executecommand-async',
            method='POST',
            headers={MIN_COMMANDER_VERSION_HEADER: '18.1'},
        ):
            self.assertIsNone(check_min_commander_version())

    @mock.patch.dict(os.environ, _TERRAFORM_DOCKER_ENV, clear=False)
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION',
        Version('17.0.0'),
    )
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION_RAW',
        '17.0.0',
    )
    def test_rejects_when_current_too_old(self):
        with self.app.test_request_context(
            '/api/v2/executecommand-async',
            method='POST',
            headers={MIN_COMMANDER_VERSION_HEADER: '18.1.0'},
        ):
            body, status = check_min_commander_version()
            self.assertEqual(status, 426)
            self.assertEqual(body['status'], 'error')
            self.assertIn('17.0.0', body['error'])
            self.assertIn('18.1.0', body['error'])
            self.assertIn('Please update Keeper Commander to >= 18.1.0 and retry.', body['error'])

    @mock.patch.dict(os.environ, _TERRAFORM_DOCKER_ENV, clear=False)
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION',
        Version('18.1.0'),
    )
    def test_rejects_invalid_header(self):
        with self.app.test_request_context(
            '/api/v2/executecommand-async',
            method='POST',
            headers={MIN_COMMANDER_VERSION_HEADER: 'not-a-version'},
        ):
            body, status = check_min_commander_version()
            self.assertEqual(status, 400)
            self.assertEqual(body['status'], 'error')
            self.assertIn('Invalid', body['error'])

    @mock.patch.dict(os.environ, _TERRAFORM_DOCKER_ENV, clear=False)
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION',
        None,
    )
    def test_rejects_when_running_version_unparseable(self):
        with self.app.test_request_context(
            '/api/v2/executecommand-async',
            method='POST',
            headers={MIN_COMMANDER_VERSION_HEADER: '18.1.0'},
        ):
            body, status = check_min_commander_version()
            self.assertEqual(status, 500)
            self.assertEqual(body['status'], 'error')
            self.assertIn('Unable to determine running Commander version', body['error'])

    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION',
        Version('17.0.0'),
    )
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION_RAW',
        '17.0.0',
    )
    def test_non_terraform_docker_ignores_min_version_header(self):
        env = {k: v for k, v in os.environ.items() if k != TERRAFORM_DOCKER_ENV}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.app.test_request_context(
                '/api/v2/executecommand-async',
                method='POST',
                headers={MIN_COMMANDER_VERSION_HEADER: '99.0.0'},
            ):
                self.assertIsNone(check_min_commander_version())

    @mock.patch.dict(os.environ, _TERRAFORM_DOCKER_ENV, clear=False)
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION',
        Version('17.0.0'),
    )
    @mock.patch(
        'keepercommander.service.decorators.min_commander_version._RUNNING_VERSION_RAW',
        '17.0.0',
    )
    def test_decorator_blocks_handler(self):
        called = {'value': False}

        @min_commander_version_check
        def handler():
            called['value'] = True
            return {'status': 'success'}, 200

        with self.app.test_request_context(
            '/test',
            method='POST',
            headers={MIN_COMMANDER_VERSION_HEADER: '99.0.0'},
        ):
            body, status = handler()
            self.assertEqual(status, 426)
            self.assertFalse(called['value'])
            self.assertEqual(body['status'], 'error')
