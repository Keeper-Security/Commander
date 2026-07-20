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
import logging
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter.errors import RateLimitExceeded
from .decorators.security import limiter, is_behind_proxy
from .decorators.api_logging import SSLHandshakeFilter
from .api.routes import init_routes
from .decorators.logging import logger
from .util.throttle import rate_limited_response

    
def create_app():
    """Create and configure the Keeper Commander Service."""
    logger.debug("Initializing Keeper Commander Service")

    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    log.addFilter(SSLHandshakeFilter())
    
    app = Flask(__name__)

    if is_behind_proxy():
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    try:
        logger.debug("Configuring rate limiter")
        limiter.init_app(app)

        @app.errorhandler(RateLimitExceeded)
        def handle_rate_limit_exceeded(e):
            detail = getattr(e, 'description', None) or str(e)
            body, status = rate_limited_response(detail)
            return jsonify(body), status

        logger.debug("Initializing API routes")
        init_routes(app)

        print("Keeper Commander Service initialization complete")
        return app

    except Exception as e:
        logger.error(f"Failed to initialize Keeper Commander Service: {str(e)}")
        raise