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

from flask import Flask, jsonify
from typing import Optional
from .command import create_command_blueprint, create_legacy_command_blueprint
from .onboarding import create_onboarding_blueprint
from ..decorators.logging import logger, debug_decorator

def _setup_queue_mode(app: Flask) -> None:
    """Setup queue mode with v2 API endpoints."""
    from ..core.request_queue import queue_manager
    queue_manager.start()

    command_bp = create_command_blueprint()
    app.register_blueprint(command_bp, url_prefix='/api/v2')

    # Register onboarding endpoints
    onboarding_bp = create_onboarding_blueprint()
    app.register_blueprint(onboarding_bp, url_prefix='/api/v2')

    logger.debug("Started queue manager and registered command blueprint with URL prefix '/api/v2'")

def _setup_legacy_mode(app: Flask) -> None:
    """Setup legacy mode with v1 API endpoints."""
    legacy_bp = create_legacy_command_blueprint()
    app.register_blueprint(legacy_bp, url_prefix='/api/v1')
    logger.info("Using /api/v1 - Enable queue mode (-q y) for /api/v2")

@debug_decorator
def init_routes(app: Optional[Flask] = None) -> None:
    """Initialize routes and queue manager for the Keeper Commander Service."""
    if app is None:
        raise ValueError("App instance is required")

    # Add health check endpoint (no authentication required for Docker/orchestrators)
    @app.route("/health", methods=["GET"])
    def health_check():
        """Health check endpoint for Docker and orchestrators."""
        return jsonify({"status": "ok"}), 200

    logger.debug("Starting route initialization")
    
    try:
        from ..config.service_config import ServiceConfig
        service_config = ServiceConfig()
        config_data = service_config.load_config()
        queue_enabled = config_data.get("queue_enabled", "y")  # Default to enabled
        
        if queue_enabled == "y":
            logger.debug("Queue enabled - setting up v2 API with request queue")
            _setup_queue_mode(app)
        else:
            logger.debug("Queue disabled - setting up v1 API with direct execution")
            _setup_legacy_mode(app)
            
    except Exception as e:
        logger.warning(f"Could not load service config, defaulting to queue mode: {e}")
        _setup_queue_mode(app)
    
    logger.debug("Route initialization completed successfully")
