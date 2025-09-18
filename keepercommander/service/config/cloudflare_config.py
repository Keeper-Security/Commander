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

from typing import Dict, Any, Optional
import time
import os
import psutil
    
from ..decorators.logging import logger, debug_decorator
from .service_config import ServiceConfig
from ..util.tunneling import generate_cloudflare_url

class CloudflareConfigurator:
    # Constants
    _DEFAULT_HEALTH_CHECK_TIMEOUT = 10
    _HEALTH_CHECK_RETRY_INTERVAL = 1
    
    # Tunnel status patterns
    _SUCCESS_PATTERNS = [
        "tunnel started",
        "Connection established", 
        "Tunnel connection established",
        "trycloudflare.com",
        "cfargotunnel.com"
    ]
    
    _FAILURE_PATTERNS = [
        "failed to dial to edge with quic: timeout",
        "timeout: no recent network activity",
        "failed to dial a quic connection", 
        "connection timeout",
        "network unreachable"
    ]
    
    @staticmethod
    def _check_cloudflare_tunnel_health(max_wait_seconds=None):
        """
        Check if cloudflare tunnel started successfully by examining the log file.
        Returns (success: bool, error_message: str)
        """
        if max_wait_seconds is None:
            max_wait_seconds = CloudflareConfigurator._DEFAULT_HEALTH_CHECK_TIMEOUT
            
        service_core_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
        log_file = os.path.join(service_core_dir, "logs", "cloudflare_tunnel_subprocess.log")
        
        # Wait for log file to be created and populated
        for _ in range(max_wait_seconds):
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    # Check for connection success indicators
                    if any(pattern in content for pattern in CloudflareConfigurator._SUCCESS_PATTERNS):
                        return True, ""
                        
                    # Check for firewall/network blocking patterns
                    if any(pattern in content for pattern in CloudflareConfigurator._FAILURE_PATTERNS):
                        return False, "Cloudflare tunnel failed to connect. This is likely due to firewall/proxy blocking the connection."
                        
                    # Check for other errors
                    if "ERR" in content and "Failed" in content:
                        return False, "Cloudflare tunnel encountered errors during startup."
                        
                except (IOError, OSError, UnicodeDecodeError) as e:
                    logger.debug(f"Error reading cloudflare log file: {type(e).__name__}")
                except Exception as e:
                    logger.warning(f"Unexpected error reading cloudflare log: {type(e).__name__}")
                    
            time.sleep(CloudflareConfigurator._HEALTH_CHECK_RETRY_INTERVAL)
            
        # If we can't determine success after waiting, assume failure
        return False, "Cloudflare tunnel status could not be determined within timeout period."

    @staticmethod
    @debug_decorator  
    def configure_cloudflare(config_data: Dict[str, Any], service_config: ServiceConfig) -> Optional[int]:
        """Configure Cloudflare tunnel if enabled. Returns tunnel PID if started in background mode, None otherwise."""
        if config_data.get("cloudflare") == 'y':
            logger.debug("Configuring Cloudflare tunnel")
            result = generate_cloudflare_url(
                config_data["port"], 
                config_data["cloudflare_tunnel_token"],
                config_data["cloudflare_custom_domain"],
                config_data["run_mode"],
            )
            if isinstance(result, tuple):
                config_data["cloudflare_public_url"], cloudflare_pid = result
                
                # Check if tunnel started successfully
                logger.debug("Checking Cloudflare tunnel health...")
                tunnel_success, error_message = CloudflareConfigurator._check_cloudflare_tunnel_health()
                
                if not tunnel_success:
                    if cloudflare_pid and psutil:
                        try:
                            process = psutil.Process(cloudflare_pid)
                            process.terminate()
                            logger.debug(f"Terminated failed cloudflare process {cloudflare_pid}")
                        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as e:
                            logger.debug(f"Error terminating cloudflare process: {type(e).__name__}")
                    elif cloudflare_pid:
                        logger.warning("Cannot terminate cloudflare process: psutil not available")
                    
                    raise Exception(f"Commander Service failed to start: {error_message}")
                
                if config_data["cloudflare_public_url"]:
                    print(f'Generated Cloudflare tunnel URL: {config_data["cloudflare_public_url"]}')
                else:
                    print('Cloudflare tunnel started, URL will be available in logs')
                return cloudflare_pid
            else:
                config_data["cloudflare_public_url"] = result
                print(f'Generated Cloudflare tunnel URL: {result}')
                return None
            # service_config.save_config(config_data)
        return None

