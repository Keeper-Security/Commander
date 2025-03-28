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
    default_limits=["10/minute", "100 per hour", "1000/day"],
    storage_uri="memory://"
)
    
def is_allowed_ip(ip_addr, allowed_ips_str, denied_ips_str):
    """Check if the given IP address is blocked."""
    logger.debug(f"allowed_ips_str :{allowed_ips_str}")
    logger.debug(f"denied_ips_str : {denied_ips_str}")
    logger.debug(f"requested ip_addr : {ip_addr}")
    
    ip_allow_list = allowed_ips_str.split(',') if allowed_ips_str else []
    ip_deny_list = denied_ips_str.split(',') if denied_ips_str else []
    try:
        # Check if the IP is in the allow list first
        if ip_allow_list:
            for allow_ip in ip_allow_list:
                if is_ip_in_range(ip_addr, allow_ip.strip()):
                    return True  # IP allowed
        # If ip_allow is empty, skip this check
        elif not ip_allow_list:
         # If ip_allow is empty, deny if IP is in deny list
            for deny_ip in ip_deny_list:
                if is_ip_in_range(ip_addr, deny_ip.strip()):
                    return False  # IP denied
        # If ip_allow is empty and ip_deny is not empty, check if IP is in deny list
        if ip_deny_list:
            for deny_ip in ip_deny_list:
                if is_ip_in_range(ip_addr, deny_ip.strip()):
                    return False  # IP denied
                
        ip_addr = ipaddress.ip_address(ip_addr)
    except ValueError:
        return True

    for allowed in allowed_ips_str.split(','):
        allowed = allowed.strip()
        try:
            if ipaddress.ip_address(allowed) == ip_addr:
                return True
        except ValueError:
            try:
                network = ipaddress.ip_network(allowed, strict=False)
                if ip_addr in network:
                    return True
            except ValueError:
                continue
    return False

def is_ip_in_range(ip, ip_range):
    try:
        # For IP range like 10.10.1.1-10.10.1.255
        if '-' in ip_range:
            start_ip, end_ip = ip_range.split('-')
            return ipaddress.IPv4Address(start_ip) <= ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(end_ip)
        else:
            # For single IP address
            return ip == ip_range
    except ValueError:
        return False
    
def security_check(fn):
    @wraps(fn)
    @limiter.limit(lambda: ConfigReader.read_config("rate_limiting")) 
    def wrapper(*args, **kwargs):
        client_ip = request.remote_addr
        try:
            allowed_ips_str = ConfigReader.read_config('ip_allowed_list')
            denied_ips_str = ConfigReader.read_config('ip_denied_list')
            if is_allowed_ip(client_ip, allowed_ips_str, denied_ips_str):
                return fn(*args, **kwargs)
                
            return jsonify({"error": "IP is not allowed to call API service"}), 403
        except Exception as e:
            return jsonify({"error": "Access denied"}), 403
    return wrapper