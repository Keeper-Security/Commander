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
from ..util.exceptions import ValidationError

class CloudflareConfigurator:
    # Constants
    _DEFAULT_HEALTH_CHECK_TIMEOUT = 10
    _HEALTH_CHECK_RETRY_INTERVAL = 1
    
    # Tunnel status patterns
    _SUCCESS_PATTERNS = [
        "tunnel started",
        "Connection established", 
        "Tunnel connection established",
        "Registered tunnel connection",
        "Updated to new configuration",
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
    
    _SUCCESS_TIMEOUT_MESSAGE = "Cloudflare tunnel status could not be determined within timeout period."
    _NETWORK_FAILURE_MESSAGE = "Cloudflare tunnel failed to connect. This is likely due to firewall/proxy blocking the connection."
    _STARTUP_ERROR_MESSAGE = "Cloudflare tunnel encountered errors during startup."

    @staticmethod
    def _validate_cloudflare_config(config_data: Dict[str, Any], service_config: ServiceConfig) -> None:
        """Validate Cloudflare configuration parameters."""
        required_keys = ["port", "cloudflare_tunnel_token", "cloudflare_custom_domain", "run_mode"]
        
        for key in required_keys:
            if key not in config_data:
                raise ValidationError(f"Missing required configuration key: {key}")
        
        service_config.validator.validate_port(config_data["port"])
        service_config.validator.validate_cloudflare_token(config_data["cloudflare_tunnel_token"])
        service_config.validator.validate_domain(config_data["cloudflare_custom_domain"])
        
        if config_data["run_mode"] not in ["foreground", "background"]:
            raise ValidationError(f"Invalid run_mode: {config_data['run_mode']}")
        
        logger.debug("Cloudflare configuration validation successful")
    
    @staticmethod
    def _check_cloudflare_tunnel_health(max_wait_seconds=None):
        """
        Check if cloudflare tunnel started successfully by examining the log file.
        Returns (success: bool, error_message: str)
        """
        max_wait_seconds = max_wait_seconds or CloudflareConfigurator._DEFAULT_HEALTH_CHECK_TIMEOUT
        log_file = CloudflareConfigurator._get_cloudflare_log_path()
        
        for _ in range(max_wait_seconds):
            if os.path.exists(log_file):
                success, error = CloudflareConfigurator._analyze_tunnel_log(log_file)
                if success is not None:  # Definitive result
                    return success, error
            time.sleep(CloudflareConfigurator._HEALTH_CHECK_RETRY_INTERVAL)
        
        return False, CloudflareConfigurator._SUCCESS_TIMEOUT_MESSAGE

    @staticmethod
    def _get_cloudflare_log_path() -> str:
        """Get the path to the Cloudflare tunnel log file."""
        service_core_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "core")
        return os.path.join(service_core_dir, "logs", "cloudflare_tunnel_subprocess.log")

    @staticmethod
    def _analyze_tunnel_log(log_file: str) -> tuple[Optional[bool], str]:
        """
        Analyze tunnel log content for success/failure indicators.
        Returns (success: Optional[bool], error_message: str)
        - True: Success detected
        - False: Failure detected  
        - None: No definitive result yet
        """
        try:
            content = CloudflareConfigurator._read_log_file(log_file)
            return CloudflareConfigurator._check_tunnel_patterns(content)
        except (IOError, OSError, UnicodeDecodeError) as e:
            logger.debug(f"Error reading cloudflare log file: {type(e).__name__}")
            return None, ""
        except Exception as e:
            logger.error(f"Unexpected error reading cloudflare log: {type(e).__name__}")
            raise

    @staticmethod
    def _read_log_file(log_file: str) -> str:
        """Read and return the content of the log file."""
        with open(log_file, 'r', encoding='utf-8') as f:
            return f.read()

    @staticmethod
    def _check_tunnel_patterns(content: str) -> tuple[Optional[bool], str]:
        """Check log content for success/failure patterns."""
        if any(pattern in content for pattern in CloudflareConfigurator._SUCCESS_PATTERNS):
            return True, ""
            
        if any(pattern in content for pattern in CloudflareConfigurator._FAILURE_PATTERNS):
            return False, CloudflareConfigurator._NETWORK_FAILURE_MESSAGE
            
        if "ERR" in content and "Failed" in content:
            return False, CloudflareConfigurator._STARTUP_ERROR_MESSAGE
            
        return None, ""

    @staticmethod
    @debug_decorator  
    def configure_cloudflare(config_data: Dict[str, Any], service_config: ServiceConfig) -> Optional[int]:
        """Configure Cloudflare tunnel if enabled. Returns tunnel PID if started in background mode, None otherwise."""
        if config_data.get("cloudflare") != 'y':
            return None
        
        logger.debug("Configuring Cloudflare tunnel")
        
        try:
            CloudflareConfigurator._validate_cloudflare_config(config_data, service_config)
            
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
                    CloudflareConfigurator._cleanup_failed_process(cloudflare_pid)
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
                
        except ValidationError as e:
            logger.error(f"Invalid Cloudflare configuration: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to configure Cloudflare tunnel: {e}")
            raise

    @staticmethod
    def _cleanup_failed_process(cloudflare_pid: Optional[int]) -> None:
        """Clean up failed Cloudflare process."""
        if not cloudflare_pid:
            return
            
        logger.debug(f"Cleaning up failed Cloudflare process {cloudflare_pid}")
        
        try:
            if psutil:
                try:
                    process = psutil.Process(cloudflare_pid)
                    process.terminate()
                    logger.debug(f"Terminated failed cloudflare process {cloudflare_pid}")
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    logger.debug(f"Process cleanup - process not found or access denied: {type(e).__name__}")
                except psutil.ZombieProcess:
                    logger.debug(f"Process {cloudflare_pid} is already a zombie process")
                except (OSError, IOError) as e:
                    logger.warning(f"OS error during process cleanup: {type(e).__name__}")
            else:
                logger.warning("Cannot terminate cloudflare process: psutil not available")
        except (KeyboardInterrupt, SystemExit):
            logger.info("Process cleanup interrupted by user or system")
            raise  
        except Exception as e:
            logger.error(f"Unexpected error during process cleanup: {type(e).__name__}")

