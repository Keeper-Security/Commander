import json
from dataclasses import dataclass, field
from typing import List


@dataclass
class ScimUser:
    id: str = ''
    external_id: str = ''
    login: str = ''
    email: str = ''
    domain: str = ''
    full_name: str = ''
    first_name: str = ''
    last_name: str = ''
    active: bool = False
    groups: List[str] = field(default_factory=list)

    def __str__(self):
        scim_user = {
            'id': self.id,
            'external_id': self.external_id,
            'login': self.login,
            'email': self.email,
            'domain': self.domain,
            'full_name': self.full_name,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'active': self.active,
            'groups': self.groups,
        }
        return 'SCIM USER: ' + json.dumps(scim_user)


@dataclass
class ScimGroup:
    id: str = ''
    external_id: str = ''
    name: str = ''
    domain: str = ''

    def __str__(self):
        scim_group = {
            'id': self.id,
            'external_id': self.external_id,
            'name': self.name,
            'domain': self.domain,
        }
        return 'SCIM GROUP: ' + json.dumps(scim_group)
