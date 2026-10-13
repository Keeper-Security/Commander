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

import ipaddress
import os
from functools import wraps
from flask import request, jsonify
from ..util.config_reader import ConfigReader
from ..config.config_validation import ConfigValidator, ValidationError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from ..decorators.logging import logger

DEFAULT_RATE_LIMIT = "60/minute"

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[DEFAULT_RATE_LIMIT, "600 per hour", "6000/day"],
    storage_uri="memory://"
)

_cached_rate_limit = None
    
def is_allowed_ip(ip_addr, allowed_ips_str, denied_ips_str):
    """Check if the given IP address is allowed based on allow/deny lists.

    Rules:
    - No lists configured → allow all
    - Deny list only → allow unless explicitly denied
    - Allow list (with or without deny list) → must be in allow list AND not in deny list
    """
    logger.debug(f"allowed_ips_str: {allowed_ips_str}")
    logger.debug(f"denied_ips_str: {denied_ips_str}")
    logger.debug(f"requested ip_addr: {ip_addr}")

    allow_list = [ip.strip() for ip in allowed_ips_str.split(',') if ip.strip()] if allowed_ips_str else []
    deny_list = [ip.strip() for ip in denied_ips_str.split(',') if ip.strip()] if denied_ips_str else []

    if not allow_list and not deny_list:
        return True

    try:
        parsed_ip = ipaddress.ip_address(ip_addr)
    except ValueError:
        logger.warning(f"Failed to parse IP address: {ip_addr}")
        return False

    if any(_ip_matches(parsed_ip, entry) for entry in deny_list):
        return False

    if allow_list:
        return any(_ip_matches(parsed_ip, entry) for entry in allow_list)

    return True


def _ip_matches(parsed_ip, pattern):
    """Check if a parsed IP matches a pattern (single IP, CIDR network, or dash-range)."""
    try:
        if '-' in pattern:
            start_str, end_str = pattern.split('-', 1)
            return ipaddress.ip_address(start_str.strip()) <= parsed_ip <= ipaddress.ip_address(end_str.strip())
        if '/' in pattern:
            return parsed_ip in ipaddress.ip_network(pattern, strict=False)
        return parsed_ip == ipaddress.ip_address(pattern)
    except ValueError:
        return False


def _validated_rate_limit(value, source):
    """Validate and return rate limit, or None if invalid."""
    if not value:
        return None
    try:
        return ConfigValidator.validate_rate_limit(value.strip())
    except ValidationError as e:
        logger.warning(f"Invalid rate limit from {source} ({value!r}): {e}")
        return None


def _resolve_rate_limit():
    """Resolve and validate rate limit once at startup/first call, caching the result.

    Priority order:
    1. KEEPER_RATE_LIMIT environment variable (for streamlined mode deployments)
    2. rate_limiting from config file
    3. Default: 60/minute

    Warns at most once per process if invalid values are detected.
    """
    global _cached_rate_limit
    if _cached_rate_limit is not None:
        return _cached_rate_limit

    # Check environment variable first (highest priority for streamlined mode)
    env_limit = os.environ.get('KEEPER_RATE_LIMIT')
    if env_limit:
        validated = _validated_rate_limit(env_limit, "KEEPER_RATE_LIMIT env var")
        if validated:
            logger.debug(f"Using rate limit from KEEPER_RATE_LIMIT env var: {validated}")
            _cached_rate_limit = validated
            return validated
        # Fall through to config if env var is invalid (don't use hardcoded default)

    # Try reading from config file
    config_limit = ConfigReader.read_config("rate_limiting")
    if config_limit:
        validated = _validated_rate_limit(config_limit, "config file")
        if validated:
            logger.debug(f"Using rate limit from config: {validated}")
            _cached_rate_limit = validated
            return validated

    # Empty config is normal default; log at DEBUG, not WARNING
    logger.debug(f"Rate limit not configured. Using default {DEFAULT_RATE_LIMIT}.")
    _cached_rate_limit = DEFAULT_RATE_LIMIT
    return DEFAULT_RATE_LIMIT


def get_rate_limit():
    """Get cached rate limit for Flask-Limiter decorator.

    Called on every request, but uses cached value from _resolve_rate_limit()
    to avoid re-validating and re-logging on every call.
    """
    return _resolve_rate_limit()

def get_rate_limit_key():
    """Generate rate limit key per IP + endpoint for separate limits per endpoint"""
    return f"{get_remote_address()}:{request.endpoint}"

def is_behind_proxy():
    """Check if the service is configured behind a reverse proxy (ngrok/cloudflare)."""
    try:
        return bool(
            ConfigReader.read_config('ngrok_public_url')
            or ConfigReader.read_config('cloudflare_public_url')
        )
    except Exception:
        return False


def security_check(fn):
    @wraps(fn)
    @limiter.limit(get_rate_limit, key_func=get_rate_limit_key)
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr
        try:
            allowed_ips_str = ConfigReader.read_config('ip_allowed_list')
            denied_ips_str = ConfigReader.read_config('ip_denied_list')
            if is_allowed_ip(client_ip, allowed_ips_str, denied_ips_str):
                return fn(*args, **kwargs)
                
            return jsonify({"status": "error", "error": "IP is not allowed to call API service"}), 403
        except Exception as e:
            logger.error(f"Security check error: {e}")
            return jsonify({"status": "error", "error": "Access denied"}), 403
    return wrapper