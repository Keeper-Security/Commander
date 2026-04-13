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
from functools import wraps
from flask import request, jsonify
from ..util.config_reader import ConfigReader
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from ..decorators.logging import logger

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["60/minute", "600 per hour", "6000/day"],
    storage_uri="memory://"
)
    
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
    
def get_rate_limit():
    """Get configured rate limit"""
    return ConfigReader.read_config("rate_limiting") or "60/minute"

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