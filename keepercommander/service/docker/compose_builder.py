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

"""docker-compose.yml generation."""
import os
from typing import Dict, Any, List, Optional, Union


class DockerComposeBuilder:
    """Builds docker-compose.yml for Commander + integration services."""

    # The source is explicitly collected during interactive setup and must be
    # accessible on the machine where Docker Compose will run.
    _CA_BUNDLE_CONTAINER_PATH = '/certs/keeper-ca-bundle.pem'
    
    def __init__(self, setup_result, config: Dict[str, Any], commander_service_name: str = 'commander',
                 commander_container_name: str = 'keeper-service',
                 commander_environment: Dict[str, str] = None,
                 ca_bundle_path: Optional[str] = None):
        self.setup_result = setup_result
        self.config = config
        self.commander_service_name = commander_service_name
        self.commander_container_name = commander_container_name
        self.commander_environment = commander_environment or {}
        self._service_cmd_parts: List[str] = []
        self._volumes: List[Union[str, Dict[str, Any]]] = []
        self._services: Dict[str, Dict[str, Any]] = {}
        self._ca_bundle_source = self._validate_ca_bundle_path(ca_bundle_path)

    @classmethod
    def _validate_ca_bundle_path(cls, configured_path: Optional[str]) -> Optional[str]:
        """Normalize a Docker-host CA path, if supplied.

        Do not stat the path here: Compose may be generated on macOS and run
        later against a Docker host on EC2, where the source path only exists.
        """
        if not configured_path or not configured_path.strip():
            return None

        return os.path.normpath(configured_path.strip())

    @staticmethod
    def _get_ca_bundle_volume(source: str) -> Dict[str, Any]:
        return {
            'type': 'bind',
            'source': source,
            'target': DockerComposeBuilder._CA_BUNDLE_CONTAINER_PATH,
            'read_only': True,
        }

    def _add_ca_bundle_to_service(self, service: Dict[str, Any]) -> None:
        if not self._ca_bundle_source:
            return

        environment = service.setdefault('environment', {})
        environment['KEEPER_SSL_CERT_FILE'] = self._CA_BUNDLE_CONTAINER_PATH
        # The KSM SDK uses Requests independently of Commander's REST client.
        environment['REQUESTS_CA_BUNDLE'] = self._CA_BUNDLE_CONTAINER_PATH

        volumes = list(service.get('volumes', []))
        ca_volume = self._get_ca_bundle_volume(self._ca_bundle_source)
        if ca_volume not in volumes:
            volumes.append(ca_volume)

        service['volumes'] = volumes

    def build(self) -> str:
        if self.commander_service_name not in self._services:
            self._services[self.commander_service_name] = self._build_commander_service()
        return self.to_yaml()

    def build_dict(self) -> Dict[str, Any]:
        if self.commander_service_name not in self._services:
            self._services[self.commander_service_name] = self._build_commander_service()
        return {'services': self._services}
    
    def add_integration_service(self, service_name: str, container_name: str,
                                image: str, record_uid: str,
                                record_env_key: str,
                                ports: List[str] = None) -> 'DockerComposeBuilder':
        """Add an integration service to the compose file. Returns self."""
        if self.commander_service_name not in self._services:
            self._services[self.commander_service_name] = self._build_commander_service()
        self._services[service_name] = self._build_integration_service(
            container_name, image, record_uid, record_env_key, ports or []
        )
        return self

    
    def _build_commander_service(self) -> Dict[str, Any]:
        self._build_service_command()
        
        service = {
            'container_name': self.commander_container_name,
            'ports': [f"127.0.0.1:{self.config['port']}:{self.config['port']}"],
            'image': 'keeper/commander:latest',
            'command': ' '.join(self._service_cmd_parts),
            'healthcheck': self._build_healthcheck(),
            'restart': 'unless-stopped'
        }

        if self.commander_environment:
            service['environment'] = dict(self.commander_environment)
        
        if self._volumes:
            service['volumes'] = self._volumes

        self._add_ca_bundle_to_service(service)
        
        return service
    
    def _build_integration_service(self, container_name: str, image: str,
                                    record_uid: str, record_env_key: str,
                                    ports: List[str] = None) -> Dict[str, Any]:
        service: Dict[str, Any] = {
            'container_name': container_name,
            'image': image,
        }
        if ports:
            service['ports'] = ports
        service['environment'] = {
            'KSM_CONFIG': self.setup_result.b64_config,
            'COMMANDER_RECORD': self.setup_result.record_uid,
            record_env_key: record_uid
        }
        service['depends_on'] = {
            self.commander_service_name: {
                'condition': 'service_healthy'
            }
        }
        service['restart'] = 'unless-stopped'
        self._add_ca_bundle_to_service(service)
        return service
    
    def _build_service_command(self) -> None:
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
        self._service_cmd_parts.extend([
            f"-ur {self.setup_result.record_uid}",
            f"--ksm-config {self.setup_result.b64_config}",
            f"--record {self.setup_result.record_uid}"
        ])
    
    def _build_healthcheck(self) -> Dict[str, Any]:
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

