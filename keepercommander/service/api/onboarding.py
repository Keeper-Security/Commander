#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2024 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Onboarding API endpoints for Keeper Commander Service.

Provides REST API for email configuration management and automated employee onboarding.
"""

from flask import Blueprint, request, jsonify, Response
from typing import Tuple, Union
import logging

from ... import api
from ..decorators.unified import unified_api_decorator
from ..decorators.logging import logger
from ...commands.email_commands import (
    find_email_config_record,
    load_email_config_from_record,
    create_email_config_record
)
from ...commands.record import RecordRemoveCommand
from ...commands.record_edit import RecordAddCommand
from ...email_service import EmailConfig, EmailSender
from ...error import CommandError
from ... import vault, vault_extensions


def create_onboarding_blueprint():
    """Create blueprint for onboarding API endpoints."""
    bp = Blueprint("onboarding_bp", __name__)

    # =============================================================================
    # Email Configuration Endpoints
    # =============================================================================

    @bp.route("/email-config", methods=["GET"])
    @unified_api_decorator()
    def list_email_configs(**kwargs) -> Tuple[Response, int]:
        """
        List all email configurations.

        GET /api/v2/email-config

        Returns:
            200: List of email configurations
            500: Server error
        """
        try:
            params = kwargs.get('params')
            if not params:
                return jsonify({"status": "error", "error": "Not authenticated"}), 401

            configs = []

            # Find all email config records
            for record_uid in params.record_cache:
                try:
                    record = vault.KeeperRecord.load(params, record_uid)
                    if not isinstance(record, vault.TypedRecord):
                        continue
                    if record.record_type != 'login':
                        continue

                    # Check if this is an email config
                    record_dict = vault_extensions.extract_typed_record_data(record)
                    custom_fields = record_dict.get('custom', [])

                    is_email_config = False
                    provider = None
                    from_address = None

                    for field in custom_fields:
                        if field.get('label') == '__email_config__':
                            is_email_config = True
                        elif field.get('label') == 'provider':
                            values = field.get('value', [])
                            if values:
                                provider = values[0]
                        elif field.get('label') == 'from_address':
                            values = field.get('value', [])
                            if values:
                                from_address = values[0]

                    if is_email_config:
                        configs.append({
                            'name': record.title,
                            'record_uid': record_uid,
                            'provider': provider or 'unknown',
                            'from_address': from_address or ''
                        })
                except Exception as e:
                    logging.debug(f'Error loading record {record_uid}: {e}')
                    continue

            return jsonify({
                "success": True,
                "configs": configs
            }), 200

        except Exception as e:
            logger.error(f"Error listing email configs: {e}", exc_info=True)
            return jsonify({"status": "error", "error": "An internal error occurred while listing email configurations"}), 500

    @bp.route("/email-config", methods=["POST"])
    @unified_api_decorator()
    def create_email_config(**kwargs) -> Tuple[Response, int]:
        """
        Create a new email configuration.

        POST /api/v2/email-config
        Content-Type: application/json

        Body (SMTP):
        {
            "name": "Gmail",
            "provider": "smtp",
            "from_address": "admin@company.com",
            "from_name": "IT Department",
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "smtp_username": "admin@company.com",
            "smtp_password": "app-password",
            "smtp_use_tls": true,
            "folder": "optional-folder-uid"
        }

        Body (AWS SES):
        {
            "name": "AWS-SES",
            "provider": "ses",
            "from_address": "noreply@company.com",
            "aws_region": "us-east-1",
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_key": "secret-key"
        }

        Body (SendGrid):
        {
            "name": "SendGrid",
            "provider": "sendgrid",
            "from_address": "noreply@company.com",
            "sendgrid_api_key": "SG.xxxx"
        }

        Returns:
            201: Email configuration created
            400: Invalid request
            409: Configuration already exists
            500: Server error
        """
        try:
            params = kwargs.get('params')
            if not params:
                return jsonify({"status": "error", "error": "Not authenticated"}), 401

            data = request.json
            if not data:
                return jsonify({"status": "error", "error": "Request body required"}), 400

            # Validate required fields
            name = data.get('name')
            provider = data.get('provider')
            from_address = data.get('from_address')

            if not name or not provider or not from_address:
                return jsonify({
                    "status": "error",
                    "error": "Required fields: name, provider, from_address"
                }), 400

            # Check if config already exists
            existing_uid = find_email_config_record(params, name)
            if existing_uid:
                return jsonify({
                    "status": "error",
                    "error": f"Email configuration '{name}' already exists"
                }), 409

            # Build EmailConfig
            config = EmailConfig(
                record_uid='',  # Will be generated
                name=name,
                provider=provider,
                from_address=from_address,
                from_name=data.get('from_name', 'Keeper Commander')
            )

            # Provider-specific fields
            if provider == 'smtp':
                config.smtp_host = data.get('smtp_host')
                config.smtp_port = data.get('smtp_port', 587)
                config.smtp_username = data.get('smtp_username')
                config.smtp_password = data.get('smtp_password')
                config.smtp_use_tls = data.get('smtp_use_tls', True)
                config.smtp_use_ssl = data.get('smtp_use_ssl', False)

            elif provider == 'ses':
                config.aws_region = data.get('aws_region')
                config.aws_access_key = data.get('aws_access_key')
                config.aws_secret_key = data.get('aws_secret_key')

            elif provider == 'sendgrid':
                config.sendgrid_api_key = data.get('sendgrid_api_key')

            else:
                return jsonify({
                    "status": "error",
                    "error": f"Unknown provider: {provider}. Supported: smtp, ses, sendgrid"
                }), 400

            # Validate configuration
            errors = config.validate()
            if errors:
                return jsonify({
                    "status": "error",
                    "error": "Invalid configuration",
                    "validation_errors": errors
                }), 400

            # Create record
            folder_uid = data.get('folder')
            record_uid = create_email_config_record(params, config, folder_uid)

            # Sync with server
            api.sync_down(params)

            return jsonify({
                "success": True,
                "record_uid": record_uid,
                "message": f"Email configuration '{name}' created successfully"
            }), 201

        except Exception as e:
            logger.error(f"Error creating email config: {e}", exc_info=True)
            return jsonify({"status": "error", "error": "An internal error occurred while creating email configuration"}), 500

    @bp.route("/email-config/<config_name>/test", methods=["POST"])
    @unified_api_decorator()
    def test_email_config(config_name: str, **kwargs) -> Tuple[Response, int]:
        """
        Test email configuration connection.

        POST /api/v2/email-config/<config_name>/test
        Content-Type: application/json

        Body (optional):
        {
            "to": "test@example.com"  # If provided, sends test email
        }

        Returns:
            200: Connection test successful
            404: Configuration not found
            500: Connection test failed
        """
        try:
            params = kwargs.get('params')
            if not params:
                return jsonify({"status": "error", "error": "Not authenticated"}), 401

            # Find config
            record_uid = find_email_config_record(params, config_name)
            if not record_uid:
                return jsonify({
                    "status": "error",
                    "error": f"Email configuration '{config_name}' not found"
                }), 404

            # Load config
            config = load_email_config_from_record(params, record_uid)

            # Create sender
            sender = EmailSender(config)

            # Test connection
            success = sender.test_connection()
            if not success:
                return jsonify({
                    "status": "error",
                    "error": f"Connection test failed for '{config_name}'"
                }), 500

            # Send test email if address provided
            data = request.json or {}
            to_address = data.get('to')

            if to_address:
                subject = 'Keeper Commander Email Test'
                body = f'This is a test email from Keeper Commander.\n\nEmail Configuration: {config_name}\nProvider: {config.provider}'

                sender.send(to_address, subject, body, html=False)

                return jsonify({
                    "success": True,
                    "message": f"Connection test passed. Test email sent to {to_address}"
                }), 200

            return jsonify({
                "success": True,
                "message": f"Connection test passed for '{config_name}'"
            }), 200

        except Exception as e:
            logger.error(f"Error testing email config: {e}", exc_info=True)
            return jsonify({"status": "error", "error": "An internal error occurred while testing email configuration"}), 500

    @bp.route("/email-config/<config_name>", methods=["DELETE"])
    @unified_api_decorator()
    def delete_email_config(config_name: str, **kwargs) -> Tuple[Response, int]:
        """
        Delete an email configuration.

        DELETE /api/v2/email-config/<config_name>

        Returns:
            200: Configuration deleted
            404: Configuration not found
            500: Server error
        """
        try:
            params = kwargs.get('params')
            if not params:
                return jsonify({"status": "error", "error": "Not authenticated"}), 401

            # Find config
            record_uid = find_email_config_record(params, config_name)
            if not record_uid:
                return jsonify({
                    "status": "error",
                    "error": f"Email configuration '{config_name}' not found"
                }), 404

            # Delete record
            remove_cmd = RecordRemoveCommand()
            remove_cmd.execute(params, record=[record_uid], force=True)

            return jsonify({
                "success": True,
                "message": f"Email configuration '{config_name}' deleted"
            }), 200

        except Exception as e:
            logger.error(f"Error deleting email config: {e}", exc_info=True)
            return jsonify({"status": "error", "error": "An internal error occurred while deleting email configuration"}), 500

    # =============================================================================
    # Onboarding Endpoint
    # =============================================================================

    @bp.route("/onboard", methods=["POST"])
    @unified_api_decorator()
    def onboard_employee(**kwargs) -> Tuple[Response, int]:
        """
        Automated employee onboarding with optional PAM sync and email delivery.

        POST /api/v2/onboard
        Content-Type: application/json

        Body:
        {
            "title": "John Doe - AWS Console",
            "record_type": "login",
            "fields": {
                "login": "john.doe@company.com",
                "password": "GeneratedPass123!"
            },
            "self_destruct": "24h",
            "pam_config": "AWS-IAM-Config",  // optional
            "send_email": "john.doe@company.com",  // optional
            "email_config": "Gmail",  // required if send_email is set
            "email_message": "Welcome to the team!",  // optional
            "folder": "optional-folder-uid"  // optional
        }

        Returns:
            201: Employee onboarded, returns share URL
            400: Invalid request
            404: Email/PAM config not found
            500: Server error
        """
        try:
            params = kwargs.get('params')
            if not params:
                return jsonify({"status": "error", "error": "Not authenticated"}), 401

            data = request.json
            if not data:
                return jsonify({"status": "error", "error": "Request body required"}), 400

            # Validate required fields
            title = data.get('title')
            record_type = data.get('record_type', 'login')
            fields = data.get('fields', {})
            self_destruct = data.get('self_destruct')
            send_email = data.get('send_email')
            email_config = data.get('email_config')

            if not title:
                return jsonify({"status": "error", "error": "Field 'title' is required"}), 400

            if not self_destruct:
                return jsonify({"status": "error", "error": "Field 'self_destruct' is required"}), 400

            # Validate email parameters
            if send_email and not email_config:
                return jsonify({
                    "status": "error",
                    "error": "Field 'email_config' is required when 'send_email' is set"
                }), 400

            # Build field parameters for record-add
            field_params = []
            for field_type, value in fields.items():
                field_params.append(f"{field_type}={value}")

            # Build kwargs for RecordAddCommand
            cmd_kwargs = {
                'title': title,
                'record_type': record_type,
                'fields': field_params,
                'self_destruct': self_destruct,
                'folder': data.get('folder'),
                'pam_config': data.get('pam_config'),
                'send_email': send_email,
                'email_config': email_config,
                'email_message': data.get('email_message'),
                'force': True
            }

            # Execute record-add command
            cmd = RecordAddCommand()
            share_url = cmd.execute(params, **cmd_kwargs)

            return jsonify({
                "success": True,
                "share_url": share_url,
                "message": f"Employee onboarded successfully"
            }), 201

        except CommandError as e:
            # CommandError exceptions are user-facing validation errors, safe to expose
            logger.warning(f"Command error in onboarding: {e}")
            return jsonify({"status": "error", "error": "Invalid request parameters"}), 400

        except Exception as e:
            # Generic exceptions may contain sensitive internal details, use generic message
            logger.error(f"Error in onboarding: {e}", exc_info=True)
            return jsonify({"status": "error", "error": "An internal error occurred during employee onboarding"}), 500

    return bp
