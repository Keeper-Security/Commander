"""Defense-in-depth: refuse manifests whose field names suggest secrets.

The Pydantic schema already forbids unknown fields (`extra="forbid"`),
so today a YAML key like `password:` would be rejected at load time.
This guard exists as a second line of defense for when the schema
gains new fields in future — if any nested key name matches a
secret-flavoured pattern, refuse to load.

Scope: scans key NAMES only. Value-content analysis (entropy,
regex-against-known-credential-patterns) is out of scope here; that
belongs in a separate hardening if/when needed.
"""
import re
from typing import Any, List

_SUSPICIOUS = re.compile(
    r"("
    r"password|passwd|pwd|"
    r"secret|"
    r"token|"
    r"api_?key|"
    r"private_?key|"
    r"totp|"
    r"otp_?seed|"
    r"credentials|"
    r"master_password"
    r")",
    re.IGNORECASE,
)


def find_secret_fields(data: Any, path: str = "") -> List[str]:
    """Return paths whose key name matches the suspicious pattern."""
    findings: List[str] = []
    if isinstance(data, dict):
        for k, v in data.items():
            sub = f"{path}.{k}" if path else str(k)
            if isinstance(k, str) and _SUSPICIOUS.search(k):
                findings.append(sub)
            findings.extend(find_secret_fields(v, sub))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            findings.extend(find_secret_fields(item, f"{path}[{i}]"))
    return findings
