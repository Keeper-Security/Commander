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
import json
from typing import Dict, Any, List

# containerboot swaps ${TS_CERT_DOMAIN} for the node's cert domain and re-applies on
# change. `$$` so Compose emits a literal `$` instead of interpolating it away.
TAILSCALE_CERT_DOMAIN_PLACEHOLDER = '$${TS_CERT_DOMAIN}'
TAILSCALE_SERVE_CONFIG_NAME = 'tailscale-serve-config'
TAILSCALE_SERVE_CONFIG_PATH = '/etc/tailscale/serve.json'


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
        self._top_level_configs: Dict[str, Any] = {}
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
        if self._top_level_configs:
            result['configs'] = self._top_level_configs
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
        Tailscale runs as a sidecar, not a service-create flag: Docker is headless, so
        Commander's own install/daemon prompts can't be answered. Ngrok/Cloudflare
        unaffected. Funnel is declared via TS_SERVE_CONFIG so containerboot applies it.
        """
        if self._tailscale_sidecar_added:
            return
        if not (self.config.get('tailscale_enabled') and self.config.get('tailscale_auth_key')):
            return
        self._tailscale_sidecar_added = True

        port = self.config['port']
        tags = self.config.get('tailscale_advertise_tags')
        # --advertise-tags always explicit: omitting it won't clear a prior run's tag.
        # No --force-reauth: containerboot logs in every start anyway, and re-validating
        # the key each boot breaks single-use keys from boot 2 and expired ones for good.
        extra_args = f"--advertise-tags={tags or ''}"

        # Declared, not scripted: containerboot re-applies on cert-domain change. A hook
        # couldn't - the hostname can land after `tailscale up` returns, stranding Funnel.
        host_port = f"{TAILSCALE_CERT_DOMAIN_PLACEHOLDER}:443"
        serve_config = json.dumps({
            'TCP': {'443': {'HTTPS': True}},
            'Web': {host_port: {'Handlers': {'/': {'Proxy': f'http://localhost:{port}'}}}},
            'AllowFunnel': {host_port: True},
        }, indent=2)
        self._top_level_configs[TAILSCALE_SERVE_CONFIG_NAME] = {'content': serve_config}

        # Surface the URL in `docker logs` (hook stdout is otherwise discarded, hence
        # /proc/1/fd/1). Print-only: Funnel is TS_SERVE_CONFIG's job, so losing this
        # costs only the log line. Must finish well inside `compose up` - Compose SIGKILLs
        # a hook still running when up completes and tears the project down, so the wait
        # is capped at ~8s (hostname normally lands ~2s in). A slower login just logs
        # nothing; `tailscale funnel status` is the fallback.
        sed_dns_name = r"""sed -n 's/.*"DNSName": *"\([^"]*\)\.".*/\1/p'"""
        url_hook = (
            f"i=0; while [ \"$$i\" -lt 8 ]; do "
            f"h=$$(tailscale status --json --peers=false 2>/dev/null | {sed_dns_name} | head -n1); "
            f"if [ -n \"$$h\" ]; then "
            f"echo \"Tailscale Funnel URL: https://$$h\" > /proc/1/fd/1; break; fi; "
            f"i=$$((i+1)); sleep 1; "
            f"done; exit 0"
        )

        # Matches the keeper-service[-<integration>] convention already used for the
        # commander container name (e.g. keeper-service-slack -> keeper-tailscale-slack).
        tailscale_container_name = self.commander_container_name.replace('service', 'tailscale', 1)

        self._services['tailscale'] = {
            'container_name': tailscale_container_name,
            'image': 'tailscale/tailscale:latest',
            'hostname': self.commander_service_name,
            # This container, not commander, owns the compose-network identity, so the
            # alias is what lets integration containers still resolve commander by name.
            'networks': {
                'default': {
                    'aliases': [self.commander_service_name],
                },
            },
            # Published here since commander's own `ports` is popped below - keeps
            # printer.py's localhost:<port> health check working.
            'ports': [f"127.0.0.1:{port}:{port}"],
            'environment': {
                'TS_AUTHKEY': self.config['tailscale_auth_key'],
                'TS_EXTRA_ARGS': extra_args,
                'TS_STATE_DIR': '/var/lib/tailscale',
                'TS_SERVE_CONFIG': TAILSCALE_SERVE_CONFIG_PATH,
            },
            'volumes': ['tailscale-state:/var/lib/tailscale'],
            # Single-file mount: edits to the JSON aren't watched, but it's generated.
            'configs': [
                {'source': TAILSCALE_SERVE_CONFIG_NAME, 'target': TAILSCALE_SERVE_CONFIG_PATH},
            ],
            # start_period absorbs a slow first login: a key-type switch burns `tailscale
            # up`'s 60s timeout plus a restart, which must not mark the sidecar unhealthy.
            'healthcheck': {
                'test': ['CMD', 'tailscale', 'status'],
                'interval': '10s',
                'timeout': '5s',
                'retries': 12,
                'start_period': '120s',
            },
            'post_start': [
                {'command': ['sh', '-c', url_hook]},
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

