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

# Default queue configuration constants
DEFAULT_QUEUE_MAX_SIZE = 100
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes in seconds
DEFAULT_RESULT_RETENTION = 3600  # 1 hour in seconds

@dataclass
class ServiceConfigData:
    """Data structure for service configuration."""
    title: str
    port: Optional[int]
    ngrok: str
    ngrok_auth_token: str
    ngrok_custom_domain: str
    tls_certificate: str
    certfile: str
    certpassword: str
    ngrok_public_url: str
    is_advanced_security_enabled: str
    rate_limiting: str
    ip_allowed_list: str
    ip_denied_list: str
    encryption: str
    encryption_private_key: str
    fileformat: str
    run_mode: str
    records: List[Dict[str, Any]]
    # Queue system configuration
    queue_max_size: int = DEFAULT_QUEUE_MAX_SIZE
    request_timeout: int = DEFAULT_REQUEST_TIMEOUT
    result_retention: int = DEFAULT_RESULT_RETENTION