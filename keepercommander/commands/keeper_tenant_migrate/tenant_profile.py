"""Tenant profile — shape description for one side of a migration.

This module changed direction in the two-shell refactor: profiles NO
LONGER carry auth data. Admins authenticate however Commander natively
supports (config file / SSO / MFA / …); the plugin reads the resulting
`params` in whichever shell it runs.

What profiles DO carry is the shape of each tenant's role in a
migration — region, MC scope, residency, compliance tags, plus the
`what_to_migrate` + `scope` fields that describe the run itself.

Storage: `~/.keeper/tenant_profiles.yaml` (YAML preferred, JSON fallback
when PyYAML is absent). Each run also writes a concrete `migration.yaml`
into its shared run-dir; the global registry is optional convenience.

Profile fields
--------------

  name              friendly handle
  tenant_type       enterprise | msp | mc | standalone
  region            US | EU | AU | CA | JP | GOV
  server            full hostname; optional if region is set
  mc                if tenant_type=mc: MC name/id for switch-to-mc
  parent_msp        documentation: MSP profile name this MC sits under
  data_residency    blocks migrations that would leave the region
  compliance_tags   gdpr / hipaa / soc2 / fedramp / ...
  what_to_migrate   list subset of STAGES
  scope             {mode: full|node|prefix, value: str}
  run_dir           shared-dir path for file hand-off between shells
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


REGIONS = ('US', 'EU', 'AU', 'CA', 'JP', 'GOV')
TENANT_TYPES = ('enterprise', 'msp', 'mc', 'standalone')
STAGES = ('structure', 'users', 'records', 'attachments', 'shares',
          'decommission')
SCOPE_MODES = ('full', 'node', 'prefix')

REGION_TO_SERVER = {
    'US': 'keepersecurity.com',
    'EU': 'keepersecurity.eu',
    'AU': 'keepersecurity.com.au',
    'CA': 'keepersecurity.ca',
    'JP': 'keepersecurity.jp',
    'GOV': 'govcloud.keepersecurity.us',
}

SERVER_TO_REGION = {v: k for k, v in REGION_TO_SERVER.items()}


class ProfileError(ValueError):
    """Invalid profile data."""


@dataclass
class TenantProfile:
    name: str
    tenant_type: str = 'enterprise'
    region: str = ''
    server: str = ''
    mc: str = ''
    parent_msp: str = ''
    data_residency: str = ''
    compliance_tags: List[str] = field(default_factory=list)
    # Shape of the migration run itself:
    what_to_migrate: List[str] = field(default_factory=list)
    scope: Dict[str, str] = field(default_factory=dict)
    run_dir: str = ''

    def validate(self) -> None:
        if not self.name:
            raise ProfileError('profile name required')
        if self.tenant_type not in TENANT_TYPES:
            raise ProfileError(
                f'tenant_type must be one of {TENANT_TYPES}; '
                f'got {self.tenant_type!r}'
            )
        if self.region and self.region not in REGIONS:
            raise ProfileError(
                f'region must be one of {REGIONS}; got {self.region!r}'
            )
        if self.data_residency and self.data_residency not in REGIONS:
            raise ProfileError(
                f'data_residency must be empty or one of {REGIONS}; '
                f'got {self.data_residency!r}'
            )
        if self.tenant_type == 'mc' and not self.mc:
            raise ProfileError('mc field required when tenant_type=mc')
        for s in self.what_to_migrate:
            if s not in STAGES:
                raise ProfileError(
                    f'what_to_migrate entry {s!r} not in {STAGES}'
                )
        if self.scope:
            mode = self.scope.get('mode', '')
            if mode and mode not in SCOPE_MODES:
                raise ProfileError(
                    f'scope.mode must be one of {SCOPE_MODES}; got {mode!r}'
                )

    @property
    def effective_server(self) -> str:
        if self.server:
            return self.server
        return REGION_TO_SERVER.get(self.region, '')

    @property
    def effective_region(self) -> str:
        if self.region:
            return self.region
        return SERVER_TO_REGION.get(self.server, '')

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TenantProfile':
        return cls(
            name=data.get('name', ''),
            tenant_type=data.get('tenant_type', 'enterprise'),
            region=data.get('region', ''),
            server=data.get('server', ''),
            mc=data.get('mc', ''),
            parent_msp=data.get('parent_msp', ''),
            data_residency=data.get('data_residency', ''),
            compliance_tags=list(data.get('compliance_tags') or []),
            what_to_migrate=list(data.get('what_to_migrate') or []),
            scope=dict(data.get('scope') or {}),
            run_dir=data.get('run_dir', ''),
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ─── Registry load / save ────────────────────────────────────────────────────


def default_registry_path() -> str:
    return os.path.expanduser('~/.keeper/tenant_profiles.yaml')


def _safe_load_yaml_or_json(text: str) -> Dict[str, Any]:
    """Best-effort parse: prefer YAML when PyYAML is present, fall back
    to JSON otherwise."""
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except ImportError:
        return json.loads(text) if text.strip() else {}


def _dump_yaml_or_json(data: Dict[str, Any]) -> str:
    try:
        import yaml
        return yaml.safe_dump(data, sort_keys=True, default_flow_style=False)
    except ImportError:
        return json.dumps(data, indent=2, sort_keys=True)


def load_registry(path: Optional[str] = None) -> Dict[str, TenantProfile]:
    """Return {profile_name: TenantProfile}. Empty when file is absent."""
    p = path or default_registry_path()
    if not os.path.exists(p):
        return {}
    with open(p) as f:
        data = _safe_load_yaml_or_json(f.read())
    profiles = {}
    for name, entry in (data.get('profiles') or {}).items():
        entry = dict(entry or {})
        entry['name'] = name
        profile = TenantProfile.from_dict(entry)
        profile.validate()
        profiles[name] = profile
    return profiles


def save_registry(profiles: Dict[str, TenantProfile],
                   path: Optional[str] = None) -> str:
    """Persist {name: profile}. Creates parent directory if missing; 0600."""
    p = path or default_registry_path()
    os.makedirs(os.path.dirname(os.path.abspath(p)) or '.', exist_ok=True)
    data = {'profiles': {name: prof.to_dict()
                          for name, prof in profiles.items()}}
    # name is the key; drop it from the nested dict to keep the file clean
    for name, entry in data['profiles'].items():
        entry.pop('name', None)
    with open(p, 'w') as f:
        f.write(_dump_yaml_or_json(data))
    os.chmod(p, 0o600)
    return p
