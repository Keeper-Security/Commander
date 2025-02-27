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

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10/minute", "100 per hour", "1000/day"],
    storage_uri="memory://"
)

def is_blocked_ip(ip_addr, blocked_ips_str):
    """Check if the given IP address is blocked."""
    try:
        ip_addr = ipaddress.ip_address(ip_addr)
    except ValueError:
        return True

    for blocked in blocked_ips_str.split(','):
        blocked = blocked.strip()
        try:
            if ipaddress.ip_address(blocked) == ip_addr:
                return True
        except ValueError:
            try:
                network = ipaddress.ip_network(blocked, strict=False)
                if ip_addr in network:
                    return True
            except ValueError:
                continue
    return False

def security_check(fn):
    @wraps(fn)
    @limiter.limit(lambda: ConfigReader.read_config("rate_limiting")) 
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr
        try:
            blocked_ips_str = ConfigReader.read_config('ip_denied_list')
            if is_blocked_ip(client_ip, blocked_ips_str):
                return jsonify({"error": "IP is blocked"}), 403
            return fn(*args, **kwargs)
        except Exception as e:
            return jsonify({"error": "Access denied"}), 403
    return wrapper