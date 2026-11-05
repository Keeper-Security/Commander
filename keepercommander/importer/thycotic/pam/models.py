#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, Iterator, List, Optional, Tuple


class PrincipalKind(str, Enum):
    USER = 'user'
    TEAM = 'team'


class RotationState(str, Enum):
    ENABLED = 'enabled'
    DISABLED = 'disabled'
    UNSUPPORTED = 'unsupported'


class PolicySource(str, Enum):
    """Where an effective RPC / launcher value came from."""
    SECRET = 'secret'
    POLICY_ENFORCED = 'policy-enforced'
    POLICY_DEFAULT = 'policy-default'
    TEMPLATE = 'template'

    @property
    def inherited(self) -> bool:
        return self is not PolicySource.SECRET


@dataclass(frozen=True)
class Principal:
    """A Delinea user or group, resolved to the identity used for Keeper matching."""
    kind: PrincipalKind
    source_id: int
    name: str
    email: str = ''


@dataclass(frozen=True)
class AccessGrant:
    """One principal's access, expressed as an NSF role name (``ROLE_NAME_MAP`` key)."""
    principal: Principal
    role: str


@dataclass(frozen=True)
class PasswordComplexity:
    length: int
    upper: int = 0
    lower: int = 0
    digits: int = 0
    symbols: int = 0

    def to_keeper(self) -> str:
        return f'{self.length},{self.upper},{self.lower},{self.digits},{self.symbols}'


@dataclass(frozen=True)
class ChangerMapping:
    """Crosswalk row: a Delinea password changer mapped to a Keeper PAM type."""
    changer_name: str
    record_type: str
    rotation: Optional[str]
    protocol: Optional[str]
    port: str = ''
    database_type: str = ''
    directory_type: str = ''
    operating_system: str = ''


@dataclass
class CrosswalkRow:
    """A password changer discovered on the tenant, with its current mapping."""
    changer_id: int
    changer_name: str
    templates: List[str] = field(default_factory=list)
    secret_count: int = 0
    mapping: Optional[ChangerMapping] = None


@dataclass(frozen=True)
class CrosswalkCheck:
    changer_name: str
    secret_id: int
    secret_name: str
    problems: Tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.problems


@dataclass
class RotationPolicy:
    """Effective Delinea RPC policy of one secret."""
    secret_id: int
    state: RotationState
    source: PolicySource
    changer_id: Optional[int] = None
    changer_name: str = ''
    schedule: dict = field(default_factory=lambda: {'type': 'on-demand'})
    complexity: Optional[PasswordComplexity] = None
    site_id: Optional[int] = None
    site_name: str = ''
    admin_secret_id: Optional[int] = None
    reason: str = ''

    @property
    def inherited(self) -> bool:
        return self.source.inherited


@dataclass
class SecretGrantTarget:
    """Secret-level grants applied to the imported record after ``pam project import``."""
    secret_id: int
    record_title: str
    folder_name: str
    grants: List[AccessGrant] = field(default_factory=list)


@dataclass(frozen=True)
class Finding:
    """Manual-action item surfaced in the dry-run and final report."""
    category: str
    item: str
    action: str

    def to_dict(self) -> dict:
        return {'category': self.category, 'item': self.item, 'action': self.action}


class FindingLog:
    """Ordered, de-duplicated Findings."""

    def __init__(self):
        self._items: Dict[Tuple[str, str], Finding] = {}

    def add(self, category: str, item: str, action: str) -> None:
        self._items.setdefault(
            (category, item), Finding(category, item, action))

    def extend(self, findings: Iterable[Finding]) -> None:
        for f in findings:
            self._items.setdefault((f.category, f.item), f)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self._items.values())

    def __len__(self) -> int:
        return len(self._items)
