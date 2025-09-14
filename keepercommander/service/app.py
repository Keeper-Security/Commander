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
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
from .decorators.security import limiter
from .api.routes import init_routes
from .decorators.logging import logger

    
def create_app():
    """Create and configure the Keeper Commander Service."""
    logger.debug("Initializing Keeper Commander Service")

    # Custom logging filter to replace SSL handshake errors with user-friendly message
    class SSLHandshakeFilter(logging.Filter):
        def filter(self, record):
            # Replace "Bad request version" errors with a clearer message
            if hasattr(record, 'getMessage'):
                message = record.getMessage()
                if "Bad request version" in message and any(ord(c) > 127 for c in message):
                    # Replace the ugly SSL handshake error with a user-friendly message
                    record.msg = "HTTPS request received but HTTPS protocol is not enabled on this service"
                    record.args = ()
            return True
    
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    log.addFilter(SSLHandshakeFilter())
    
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