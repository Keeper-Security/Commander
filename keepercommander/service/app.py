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
from werkzeug.middleware.proxy_fix import ProxyFix
from .decorators.security import limiter
from .api.routes import init_routes
from .decorators.logging import logger

def create_app():
    """Create and configure the Keeper Commander Service."""
    logger.debug("Initializing Keeper Commander Service")
    
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1, x_prefix=1)
    
    try:
        logger.debug("Configuring rate limiter")
        limiter.init_app(app)
        
        logger.debug("Initializing API routes")
        init_routes(app)
        
        print("Keeper Commander Service initialization complete")
        return app
        
    except Exception as e:
        logger.error(f"Failed to initialize Keeper Commander Service: {str(e)}")
        raise