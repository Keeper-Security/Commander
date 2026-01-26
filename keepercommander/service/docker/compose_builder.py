#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2026 Keeper Security Inc.
# Contact: commander@keepersecurity.com
#

"""
Builder class for generating docker-compose.yml configuration
"""
import os
from typing import Dict, Any, List


class DockerComposeBuilder:
    """Builder for docker-compose.yml content with support for Commander and Slack App services"""
    
    def __init__(self, setup_result, config: Dict[str, Any]):
        """
        Initialize the builder
        
        Args:
            setup_result: Results from Docker setup containing UIDs and KSM config (SetupResult object)
            config: Service configuration dictionary
        """
        self.setup_result = setup_result
        self.config = config
        self._service_cmd_parts: List[str] = []
        self._volumes: List[str] = []
        self._services: Dict[str, Dict[str, Any]] = {}
    
    def build(self) -> str:
        """
        Build the complete docker-compose.yml content
        
        Returns:
            YAML content as a string
        """
        if 'commander' not in self._services:
            self._services['commander'] = self._build_commander_service()
        return self.to_yaml()
    
    def build_dict(self) -> Dict[str, Any]:
        """
        Build the docker-compose structure as a dictionary
        
        Returns:
            Dictionary structure ready for YAML serialization
        """
        if 'commander' not in self._services:
            self._services['commander'] = self._build_commander_service()
        return {'services': self._services}
    
    def add_slack_service(self, slack_record_uid: str) -> 'DockerComposeBuilder':
        """
        Add Slack App service to the compose configuration
        
        Args:
            slack_record_uid: UID of the Slack config record
            
        Returns:
            Self for method chaining
        """
        # Ensure commander service exists first
        if 'commander' not in self._services:
            self._services['commander'] = self._build_commander_service()
        # Add slack service
        self._services['slack-app'] = self._build_slack_service(slack_record_uid)
        return self
    
    def _build_commander_service(self) -> Dict[str, Any]:
        """Build the Commander service configuration"""
        self._build_service_command()
        
        service = {
            'container_name': 'keeper-service',
            'ports': [f"127.0.0.1:{self.config['port']}:{self.config['port']}"],
            'image': 'keeper/commander:latest',
            'command': ' '.join(self._service_cmd_parts),
            'healthcheck': self._build_healthcheck(),
            'restart': 'unless-stopped'
        }
        
        if self._volumes:
            service['volumes'] = self._volumes
        
        return service
    
    def _build_slack_service(self, slack_record_uid: str) -> Dict[str, Any]:
        """Build the Slack App service configuration"""
        return {
            'container_name': 'keeper-slack-app',
            'image': 'keeper/slack-app:latest',
            'environment': {
                'KSM_CONFIG': self.setup_result.b64_config,
                'COMMANDER_RECORD': self.setup_result.record_uid,
                'SLACK_RECORD': slack_record_uid
            },
            'depends_on': {
                'commander': {
                    'condition': 'service_healthy'
                }
            },
            'restart': 'unless-stopped'
        }
    
    def _build_service_command(self) -> None:
        """Build the service-create command parts"""
        port = self.config['port']
        commands = self.config['commands']
        queue_enabled = self.config.get('queue_enabled', True)
        
        self._service_cmd_parts = [
            f"service-create -p {port}",
            f"-c '{commands}'",
            "-f json",
            f"-q {'y' if queue_enabled else 'n'}"
        ]
        
        self._add_security_options()
        self._add_tunneling_options()
        self._add_docker_options()
    
    def _add_security_options(self) -> None:
        """Add advanced security options (IP filtering, rate limiting, encryption)"""
        # IP allowed list (only add if not default)
        allowed_ip = self.config.get('allowed_ip', '0.0.0.0/0,::/0')
        if allowed_ip and allowed_ip != '0.0.0.0/0,::/0':
            self._service_cmd_parts.append(f"-aip '{allowed_ip}'")
        
        # IP denied list
        denied_ip = self.config.get('denied_ip', '')
        if denied_ip:
            self._service_cmd_parts.append(f"-dip '{denied_ip}'")
        
        # Rate limiting
        rate_limit = self.config.get('rate_limit', '')
        if rate_limit:
            self._service_cmd_parts.append(f"-rl '{rate_limit}'")
        
        # Encryption (automatically enabled if encryption_key is provided)
        encryption_key = self.config.get('encryption_key', '')
        if encryption_key:
            self._service_cmd_parts.append(f"-ek '{encryption_key}'")
        
        # Token expiration
        token_expiration = self.config.get('token_expiration', '')
        if token_expiration:
            self._service_cmd_parts.append(f"-te '{token_expiration}'")
    
    def _add_tunneling_options(self) -> None:
        """Add ngrok and Cloudflare tunneling options"""
        # Ngrok configuration
        if self.config.get('ngrok_enabled') and self.config.get('ngrok_auth_token'):
            self._service_cmd_parts.append(f"-ng {self.config['ngrok_auth_token']}")
            if self.config.get('ngrok_custom_domain'):
                self._service_cmd_parts.append(f"-cd {self.config['ngrok_custom_domain']}")
        
        # Cloudflare configuration
        if self.config.get('cloudflare_enabled') and self.config.get('cloudflare_tunnel_token'):
            self._service_cmd_parts.append(f"-cf {self.config['cloudflare_tunnel_token']}")
            if self.config.get('cloudflare_custom_domain'):
                self._service_cmd_parts.append(f"-cfd {self.config['cloudflare_custom_domain']}")
    
    def _add_docker_options(self) -> None:
        """Add Docker-specific parameters (KSM config, record UIDs)"""
        self._service_cmd_parts.extend([
            f"-ur {self.setup_result.record_uid}",
            f"--ksm-config {self.setup_result.b64_config}",
            f"--record {self.setup_result.record_uid}"
        ])
    
    def _build_healthcheck(self) -> Dict[str, Any]:
        """Build the healthcheck configuration"""
        port = self.config['port']
        
        # Build the Python script as a single-line command
        health_script = (
            f"python -c \"import sys, urllib.request; "
            f"sys.exit(0 if urllib.request.urlopen('http://localhost:{port}/health', timeout=2).status == 200 else 1)\""
        )
        
        return {
            'test': ['CMD-SHELL', health_script],
            'interval': '60s',
            'timeout': '3s',
            'start_period': '10s',
            'retries': 30
        }
    
    def to_yaml(self) -> str:
        """
        Convert the docker-compose structure to YAML string
        
        Returns:
            YAML formatted string
        """
        try:
            import yaml
        except ImportError:
            # Fallback if PyYAML is not installed
            raise ImportError("PyYAML is required for YAML generation. Install it with: pip install PyYAML")
        
        compose_dict = self.build_dict()
        
        # Use yaml.dump with proper settings
        return yaml.dump(
            compose_dict,
            default_flow_style=False,
            sort_keys=False,
            indent=2,
            width=float("inf")  # Prevent line wrapping
        )

