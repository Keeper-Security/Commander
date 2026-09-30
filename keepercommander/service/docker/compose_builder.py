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
from typing import Dict, Any, List


class DockerComposeBuilder:
    """Builds docker-compose.yml for Commander + integration services."""
    
    def __init__(self, setup_result, config: Dict[str, Any], commander_service_name: str = 'commander',
                 commander_container_name: str = 'keeper-service',
                 commander_environment: Dict[str, str] = None):
        self.setup_result = setup_result
        self.config = config
        self.commander_service_name = commander_service_name
        self.commander_container_name = commander_container_name
        self.commander_environment = commander_environment or {}
        self._service_cmd_parts: List[str] = []
        self._volumes: List[str] = []
        self._services: Dict[str, Dict[str, Any]] = {}
        self._top_level_volumes: Dict[str, Any] = {}
        self._tailscale_sidecar_added = False

    def build(self) -> str:
        if self.commander_service_name not in self._services:
            self._services[self.commander_service_name] = self._build_commander_service()
        return self.to_yaml()

    def build_dict(self) -> Dict[str, Any]:
        if self.commander_service_name not in self._services:
            self._services[self.commander_service_name] = self._build_commander_service()
        self._add_tailscale_sidecar_if_enabled()
        result: Dict[str, Any] = {'services': self._services}
        if self._top_level_volumes:
            result['volumes'] = self._top_level_volumes
        return result
    
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

        # Tailscale is handled via a sidecar container (see _add_tailscale_sidecar_if_enabled),
        # not a service-create flag -- Docker deployments are headless and can't answer the
        # install/daemon-start prompts that -ts would otherwise trigger inside the container.

    def _add_docker_options(self) -> None:
        self._service_cmd_parts.extend([
            f"-ur {self.setup_result.record_uid}",
            f"--ksm-config {self.setup_result.b64_config}",
            f"--record {self.setup_result.record_uid}"
        ])

    def _add_tailscale_sidecar_if_enabled(self) -> None:
        """
        Add Tailscale as a sidecar (official tailscale/tailscale image) rather than
        a service-create flag. Docker deployments are headless -- Commander's own
        install/daemon-start prompts (tailscale_config.py) can't be answered inside
        a detached container. The sidecar authenticates via TS_AUTHKEY with no
        prompts. Ngrok/Cloudflare are unaffected -- they stay as service-create flags.

        Enabling Funnel must run *inside* the sidecar's own container, not a
        separate one -- verified empirically: `network_mode: service:X` only
        shares the network namespace, not the filesystem, so a second container
        can't reach tailscaled's control socket ("failed to connect to local
        tailscaled"). A `post_start` hook on the sidecar itself runs in its
        namespace and does work, but fires immediately on container start
        (not gated by healthcheck), so the hook command waits for `tailscale
        status` to succeed before calling `funnel` -- confirmed against a real
        `tailscale status --> then funnel --bg` run with a fresh state volume.
        """
        if self._tailscale_sidecar_added:
            return
        if not (self.config.get('tailscale_enabled') and self.config.get('tailscale_auth_key')):
            return
        self._tailscale_sidecar_added = True

        port = self.config['port']
        tags = self.config.get('tailscale_advertise_tags')
        # --advertise-tags must always be stated explicitly (empty if unused), never
        # omitted -- `tailscale up` requires every non-default setting to be re-specified
        # on each call or it errors out; omitting the flag doesn't clear a tag left by a
        # prior run (e.g. switching from an OAuth key to a plain key on the same node/volume).
        extra_args = f"--advertise-tags={tags or ''} --force-reauth"

        funnel_cmd = (
            f"until tailscale status >/dev/null 2>&1; do sleep 1; done; "
            f"tailscale funnel --bg --https=443 localhost:{port}"
        )

        # Matches the keeper-service[-<integration>] convention already used for the
        # commander container name (e.g. keeper-service-slack -> keeper-tailscale-slack).
        tailscale_container_name = self.commander_container_name.replace('service', 'tailscale', 1)

        self._services['tailscale'] = {
            'container_name': tailscale_container_name,
            'image': 'tailscale/tailscale:latest',
            'hostname': self.commander_service_name,
            'environment': {
                'TS_AUTHKEY': self.config['tailscale_auth_key'],
                'TS_EXTRA_ARGS': extra_args,
                'TS_STATE_DIR': '/var/lib/tailscale',
            },
            'volumes': ['tailscale-state:/var/lib/tailscale'],
            'healthcheck': {
                'test': ['CMD', 'tailscale', 'status'],
                'interval': '10s',
                'timeout': '5s',
                'retries': 12,
            },
            'post_start': [
                {'command': ['sh', '-c', funnel_cmd]},
            ],
            'restart': 'unless-stopped',
        }
        self._top_level_volumes['tailscale-state'] = None

        commander = self._services[self.commander_service_name]
        commander.pop('ports', None)
        commander['network_mode'] = 'service:tailscale'
        commander.setdefault('depends_on', {})['tailscale'] = {'condition': 'service_healthy'}


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

