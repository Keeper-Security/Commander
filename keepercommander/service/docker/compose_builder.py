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

    # Mounted path used inside both the Commander and integration containers.
    # The source path is supplied by the SMK installation on the Docker host.
    _KEEPER_CA_CONTAINER_PATH = '/certs/keeper-ca-bundle.pem'
    _REQUESTS_CA_CONTAINER_PATH = '/certs/requests-ca-bundle.pem'
    _CA_DISABLED_VALUES = {'none', 'false', 'system', 'certifi'}
    
    def __init__(self, setup_result, config: Dict[str, Any], commander_service_name: str = 'commander',
                 commander_container_name: str = 'keeper-service',
                 commander_environment: Dict[str, str] = None):
        self.setup_result = setup_result
        self.config = config
        self.commander_service_name = commander_service_name
        self.commander_container_name = commander_container_name
        self.commander_environment = commander_environment or {}
        self._service_cmd_parts: List[str] = []
        self._volumes: List[Union[str, Dict[str, Any]]] = []
        self._services: Dict[str, Dict[str, Any]] = {}
        self._keeper_ca_source = self._get_ca_bundle_source('KEEPER_SSL_CERT_FILE')
        self._requests_ca_source = self._get_ca_bundle_source('REQUESTS_CA_BUNDLE')

    @classmethod
    def _get_ca_bundle_source(cls, env_name: str) -> Optional[str]:
        """Return an explicitly configured, readable host CA bundle path.

        An SMK private CA must be available inside each container that makes
        HTTPS requests. Keep the setting optional so normal Keeper Cloud
        deployments continue to use the image's standard trust store. The
        Commander REST client and Requests-based KSM SDK can use separate
        bundles, so preserve each setting independently.
        """
        configured_path = os.environ.get(env_name, '').strip()
        if not configured_path or configured_path.lower() in cls._CA_DISABLED_VALUES:
            return None

        path = os.path.abspath(os.path.expanduser(configured_path))
        if not os.path.isfile(path):
            raise ValueError(
                f'{env_name} is set to "{configured_path}", but that CA bundle '
                'is not a file readable by Docker Compose.'
            )
        if not os.access(path, os.R_OK):
            raise ValueError(
                f'{env_name} is set to "{configured_path}", but the CA bundle '
                'is not readable.'
            )
        return path

    @staticmethod
    def _get_ca_bundle_volume(source: str, target: str) -> Dict[str, Any]:
        return {
            'type': 'bind',
            'source': source,
            'target': target,
            'read_only': True,
        }

    def _add_ca_bundle_to_service(self, service: Dict[str, Any]) -> None:
        if not self._keeper_ca_source and not self._requests_ca_source:
            return

        environment = service.setdefault('environment', {})
        volumes = list(service.get('volumes', []))

        if self._keeper_ca_source:
            environment['KEEPER_SSL_CERT_FILE'] = self._KEEPER_CA_CONTAINER_PATH
            keeper_volume = self._get_ca_bundle_volume(
                self._keeper_ca_source, self._KEEPER_CA_CONTAINER_PATH
            )
            if keeper_volume not in volumes:
                volumes.append(keeper_volume)

        # The KSM SDK makes HTTPS requests through Requests, which does not use
        # Commander's KEEPER_SSL_CERT_FILE setting. Honor an explicit Requests
        # bundle when supplied; otherwise use the Commander bundle as a
        # convenient fallback for SMK installations that provide one bundle.
        requests_ca_source = self._requests_ca_source or self._keeper_ca_source
        if requests_ca_source:
            requests_ca_target = (
                self._KEEPER_CA_CONTAINER_PATH
                if requests_ca_source == self._keeper_ca_source
                else self._REQUESTS_CA_CONTAINER_PATH
            )
            environment['REQUESTS_CA_BUNDLE'] = requests_ca_target
            requests_volume = self._get_ca_bundle_volume(
                requests_ca_source, requests_ca_target
            )
            if requests_volume not in volumes:
                volumes.append(requests_volume)

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

