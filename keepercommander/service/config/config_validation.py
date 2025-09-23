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

import os
import re
import socket
import ipaddress
from typing import Any
from datetime import timedelta
from ..decorators.logging import logger, debug_decorator
from ..util.exceptions import ValidationError

class ConfigValidator:
    """Validator class for service configuration"""
    MIN_PORT = 0
    MAX_PORT = 65535

    @staticmethod
    def validate_port(port: Any) -> int:
        """Validate port number"""
        try:
            port_num = int(port)
            logger.debug(f"Validating port number: {port_num}")
            
            if not ConfigValidator.MIN_PORT <= port_num <= ConfigValidator.MAX_PORT:
                msg = f"Port must be between {ConfigValidator.MIN_PORT} and {ConfigValidator.MAX_PORT}"
                raise ValidationError(msg)
                
            if ConfigValidator._is_port_in_use(port_num):
                msg = f"Port {port_num} is already in use"
                raise ValidationError(msg)
                
            logger.debug(f"Port {port_num} validation successful")
            return port_num
            
        except ValueError:
            msg = "Port must be a valid integer"
            raise ValidationError(msg)

    @staticmethod
    def validate_cert_file(certfile: Any) -> str:
        """Validate certificate file format based on its extension"""
        if not isinstance(certfile, str):
            raise ValidationError("Certificate file path must be a string")

        valid_extensions = {".pem", ".crt", ".cer", ".key"}
        file_ext = os.path.splitext(certfile)[1].lower()

        if file_ext not in valid_extensions:
            raise ValidationError(f"Invalid certificate format. Allowed formats: {', '.join(valid_extensions)}")

        return certfile
    
    @staticmethod
    def validate_certpassword(certpassword: Any) -> str:
        """Validate certificate password"""
        if not isinstance(certpassword, str):
            raise ValidationError("Certificate password must be a string")

        if not certpassword:
            raise ValidationError("Certificate password cannot be empty")

        if len(certpassword) < 8:
            raise ValidationError("Certificate password must be at least 8 characters long")

        return certpassword

    @staticmethod
    @debug_decorator
    def _is_port_in_use(port: int) -> bool:
        """Check if port is already in use"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                s.close()
                logger.debug(f"Port {port} is available")
                return False
        except socket.error:
            logger.debug(f"Port {port} is in use")
            return True

    @staticmethod
    def validate_ngrok_token(token: str) -> str:
        """Validate Ngrok authentication token"""
        logger.debug("Validating Ngrok auth token")
        
        if not token:
            msg = "Ngrok auth token cannot be empty"
            raise ValidationError(msg)
            
        if not re.match(r'^[0-9a-zA-Z_-]{8,}$', token):
            msg = "Invalid Ngrok auth token format"
            raise ValidationError(msg)
            
        logger.debug("Ngrok token validation successful")
        return token

    @staticmethod
    def validate_cloudflare_token(token: str) -> str:
        """Validate Cloudflare tunnel token"""
        logger.debug("Validating Cloudflare tunnel token")
        
        # Allow empty token for temporary tunnels
        if not token or not token.strip():
            logger.debug("Empty Cloudflare token - will use temporary tunnel")
            return ""
            
        # Cloudflare tunnel tokens are typically long base64-encoded strings
        # They usually start with "ey" (base64 for '{"') or are alphanumeric with dashes/underscores
        if not re.match(r'^[0-9a-zA-Z_\-=+/]{32,}$', token):
            msg = "Invalid Cloudflare tunnel token format. Must be a valid tunnel token from Cloudflare dashboard."
            raise ValidationError(msg)
            
        logger.debug("Cloudflare token validation successful")
        return token

    @staticmethod
    def validate_domain(domain: str) -> str:
        """Validate domain name format"""
        logger.debug(f"Validating domain: {domain}")
        
        if not domain or not domain.strip():
            raise ValidationError("Domain cannot be empty")
        
        domain = domain.strip().lower()
        
        if len(domain) > 253:
            raise ValidationError("Domain name too long (max 253 characters)")
        
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(domain_pattern, domain):
            raise ValidationError("Invalid domain format. Domain must contain only letters, numbers, hyphens, and dots.")
        
        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                raise ValidationError(f"Domain label '{label}' too long (max 63 characters)")
            if label.startswith('-') or label.endswith('-'):
                raise ValidationError(f"Domain label '{label}' cannot start or end with hyphen")
        
        if '.' not in domain:
            raise ValidationError("Please provide a valid domain name")
            
        logger.debug("Domain validation successful")
        return domain

    @staticmethod
    def validate_rate_limit(rate_limit: str) -> str:
        """Validate rate limiting format"""
        if not rate_limit:
            logger.debug("Empty rate limit provided, skipping validation")
            return rate_limit

        logger.debug(f"Validating rate limit: {rate_limit}")
        pattern = r'^\d+/(?:minute|hour|day)$|^\d+\s+per\s+(?:minute|hour|day)$'
        
        if not re.match(pattern, rate_limit, re.IGNORECASE):
            msg = ("Invalid rate limit format. Use formats like 'X/minute', 'X/hour', 'X/day', "
                  "'X per minute', 'X per hour', or 'X per day'.")
            raise ValidationError(msg)
            
        logger.debug("Rate limit validation successful")
        return rate_limit

    @staticmethod
    def validate_ip_list(ip_list: str) -> str:
        """Validate IP address list"""
        if not ip_list:
            logger.debug("Empty IP list provided, skipping validation")
            return ip_list

        logger.debug(f"Validating IP list: {ip_list}")
        ips = [ip.strip() for ip in ip_list.split(',')]
        for ip in ips:
            try:
                if '-' in ip:
                    start_ip, end_ip = ip.split('-')
                    ipaddress.ip_network(start_ip)
                    ipaddress.ip_network(end_ip)
                else:
                   ipaddress.ip_network(ip)     
            except ValueError:
                try:
                    ipaddress.ip_network(ip, strict=False)
                except ValueError:
                    msg = f"Invalid IP address or CIDR block: {ip}"
                    raise ValidationError(msg)
                
        logger.debug("IP list validation successful")
        return ip_list

    @staticmethod
    def validate_encryption_key(key: str) -> str:
        """Validate encryption private key"""
        logger.debug("Validating encryption key")
        
        if not key:
            msg = "Encryption key cannot be empty"
            raise ValidationError(msg)
            
        if len(key) != 32:
            msg = "Encryption key must be 32 characters long"
            raise ValidationError(msg)
            
        if not re.match(r'^[A-Za-z0-9@#$%^&+=]{32,}$', key):
            msg = "Encryption key must contain only alphanumeric and special characters (@#$%^&+=)"
            raise ValidationError(msg)
            
        logger.debug("Encryption key validation successful")
        return key

    @staticmethod
    def parse_expiration_time(expiration_str: str) -> timedelta:
        """Parse expiration time string into timedelta"""
        logger.debug(f"Parsing expiration time: {expiration_str}")
        
        if not re.match(r'^\d+[mhd]$', expiration_str.lower()):
            msg = "Invalid expiration format. Use Xm, Xh, or Xd (e.g., 30m, 24h, 7d)"
            raise ValidationError(msg)

        time_unit = expiration_str[-1].lower()
        try:
            value = int(expiration_str[:-1])
            if value <= 0:
                msg = "Duration must be a positive number"
                raise ValidationError(msg)
                
        except ValueError:
            msg = "Invalid duration value. Please enter a valid number"
            raise ValidationError(msg)

        result = None
        if time_unit == 'm':
            result = timedelta(minutes=value)
        elif time_unit == 'h':
            result = timedelta(hours=value)
        elif time_unit == 'd':
            result = timedelta(days=value)
        else:
            msg = "Invalid time unit. Use m for minutes, h for hours, or d for days"
            raise ValidationError(msg)
            
        logger.debug(f"Successfully parsed expiration time to {result}")
        return result