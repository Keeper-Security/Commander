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

from dataclasses import dataclass
from typing import Dict, Any, Optional, List

@dataclass
class ServiceConfigData:
    """Data structure for service configuration."""
    title: str
    port: Optional[int]
    ngrok: str
    ngrok_auth_token: str
    ngrok_custom_domain: str
    ngrok_public_url: str
    tls_certificate: str
    certfile: str
    certpassword: str
    is_advanced_security_enabled: str
    rate_limiting: str
    ip_allowed_list: str
    ip_denied_list: str
    encryption: str
    encryption_private_key: str
    fileformat: str
    run_mode: str
    queue_enabled: str
    records: List[Dict[str, Any]]
    cloudflare: str = "n"
    cloudflare_tunnel_token: str = ""
    cloudflare_custom_domain: str = ""
    cloudflare_public_url: str = ""