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

from flask import Flask
from typing import Optional
from .command import create_command_blueprint
from ..decorators.logging import logger, debug_decorator

@debug_decorator
def init_routes(app: Optional[Flask] = None) -> None:
    """Initialize routes for the Keeper Commander Service."""
    if app is None:
        raise ValueError("App instance is required")
    
    logger.debug("Starting route initialization")
    command_bp = create_command_blueprint()

    logger.debug("Registering command blueprint with URL prefix '/api/v1'")
    app.register_blueprint(command_bp, url_prefix='/api/v1')
    
    logger.info("Route initialization completed successfully")