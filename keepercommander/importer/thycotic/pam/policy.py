#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from typing import Any, Dict, Optional, Tuple

from .client import DelineaPamClient
from .models import PolicySource


class SecretPolicyResolver:
    """Finds the secret policy that governs a secret and resolves effective item values.

    Precedence, highest first:
      1. policy item with ``policyApplyType == 'Enforced'``
      2. the secret's own value
      3. policy item with ``policyApplyType == 'Default'``
      4. the caller's template fallback
    """

    def __init__(self, client: DelineaPamClient):
        self.client = client
        self._folder_policy: Dict[int, Optional[int]] = {}

    def policy_for(self, secret: dict) -> Optional[dict]:
        """SecretPolicyDetailModelV2 governing *secret*, or ``None``.

        Uses ``secret['secretPolicyId']`` unless ``enableInheritSecretPolicy`` is
        true; then walks ``parentFolderId`` while each folder's
        ``inheritSecretPolicy`` is true and takes the first ``secretPolicyId``.
        """
        if not isinstance(secret, dict):
            return None
        if secret.get('enableInheritSecretPolicy'):
            folder_id = secret.get('folderId')
            policy_id = self.folder_policy_id(folder_id) if isinstance(folder_id, int) else None
        else:
            policy_id = secret.get('secretPolicyId')
        if not isinstance(policy_id, int) or policy_id <= 0:
            return None
        return self.client.secret_policy(policy_id)

    def folder_policy_id(self, folder_id: int) -> Optional[int]:
        """Effective policy id of a folder (memoised in ``_folder_policy``)."""
        if folder_id in self._folder_policy:
            return self._folder_policy[folder_id]
        seen = set()
        current: Optional[int] = folder_id
        result: Optional[int] = None
        while isinstance(current, int) and current > 0 and current not in seen:
            seen.add(current)
            folder = self.client.folder(current)
            if not isinstance(folder, dict):
                break
            if folder.get('inheritSecretPolicy'):
                parent = folder.get('parentFolderId')
                current = parent if isinstance(parent, int) else None
                continue
            policy_id = folder.get('secretPolicyId')
            result = policy_id if isinstance(policy_id, int) and policy_id > 0 else None
            break
        self._folder_policy[folder_id] = result
        return result

    @staticmethod
    def effective(secret_value: Any, policy_item: Optional[dict],
                  template_value: Any = None) -> Tuple[Any, PolicySource]:
        """Apply the precedence above to one item.

        *policy_item* is a ``SecretPolicyItemOf*`` dict
        (``{'policyApplyType': 'NotSet'|'Default'|'Enforced', 'value': ...}``).
        """
        apply_type = (policy_item or {}).get('policyApplyType') or 'NotSet'
        if apply_type == 'Enforced':
            return policy_item.get('value'), PolicySource.POLICY_ENFORCED
        if secret_value is not None:
            return secret_value, PolicySource.SECRET
        if apply_type == 'Default':
            return policy_item.get('value'), PolicySource.POLICY_DEFAULT
        return template_value, PolicySource.TEMPLATE