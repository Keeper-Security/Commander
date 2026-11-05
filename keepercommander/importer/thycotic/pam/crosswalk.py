#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander — Delinea PAM import

from dataclasses import replace
from typing import Dict, List, Optional

from .client import DelineaPamClient
from .models import ChangerMapping, CrosswalkCheck, CrosswalkRow


def _row(name: str, record_type: str, rotation: Optional[str], protocol: Optional[str], port: str,
         **extra: str) -> ChangerMapping:
    return ChangerMapping(changer_name=name, record_type=record_type, rotation=rotation,
                          protocol=protocol, port=port, **extra)


# Single source of truth for built-in changers, keyed by casefolded Delinea password type name.
# protocol is a pam_settings.connection protocol; databases without one (Oracle) use None.
# rotation None means Keeper has no built-in equivalent and the account is UNSUPPORTED.
DEFAULT_CROSSWALK: Dict[str, ChangerMapping] = {m.changer_name.casefold(): m for m in (
    _row('Windows Account', 'pamMachine', 'general',
         'rdp', '3389', operating_system='windows'),
    _row('Active Directory Account', 'pamDirectory', 'general',
         None, '636', directory_type='active_directory'),
    _row('OpenLDAP Account', 'pamDirectory', 'general',
         None, '636', directory_type='openldap'),
    _row('Unix Account (SSH)', 'pamMachine', 'general',
         'ssh', '22', operating_system='linux'),
    _row('Unix Account (SSH Key Rotation)', 'pamMachine',
         'general', 'ssh', '22', operating_system='linux'),
    _row('Unix Account (Telnet)', 'pamMachine', None,
         'telnet', '23', operating_system='linux'),
    _row('SQL Server Account', 'pamDatabase', 'general',
         'sql-server', '1433', database_type='mssql'),
    _row('MySQL Account', 'pamDatabase', 'general',
         'mysql', '3306', database_type='mysql'),
    _row('PostgreSQL Account', 'pamDatabase', 'general',
         'postgresql', '5432', database_type='postgresql'),
    _row('Oracle Account', 'pamDatabase', 'general',
         None, '1521', database_type='oracle'),
    _row('Cisco Account (SSH)', 'pamMachine', None, 'ssh', '22'),
    _row('Web Password', 'login', None, None, ''),
)}

FALLBACK_MAPPING = ChangerMapping(
    changer_name='', record_type='login', rotation=None, protocol=None)

TEMPLATE_COLUMNS = (
    'changer_id', 'changer_name', 'templates', 'secret_count',
    'record_type', 'rotation', 'protocol', 'port',
    'database_type', 'directory_type', 'operating_system',
)


class Crosswalk:
    """Delinea password changer to Keeper PAM type map.

    ``DEFAULT_CROSSWALK`` overlaid with rows loaded from an admin-edited CSV
    (``TEMPLATE_COLUMNS``; ``changer_id``, ``templates`` and ``secret_count``
    are informational and ignored on load).
    """

    def __init__(self, overrides: Optional[Dict[str, ChangerMapping]] = None):
        self.mappings: Dict[str, ChangerMapping] = {
            **DEFAULT_CROSSWALK, **(overrides or {})}

    @classmethod
    def load(cls, path: str) -> 'Crosswalk':
        """Read a CSV produced by ``write_template``; rows with empty ``record_type`` are skipped."""
        raise NotImplementedError

    def resolve(self, changer_name: str, password_type: Optional[dict] = None) -> Optional[ChangerMapping]:
        """Mapping for a changer, or ``None`` when unmapped.

        A non-zero ``customPort`` on the password type detail overrides the default port.
        """
        mapping = self.mappings.get((changer_name or '').casefold())
        custom_port = (password_type or {}).get('customPort')
        if mapping and custom_port:
            mapping = replace(mapping, port=str(custom_port))
        return mapping

    def discover(self, client: DelineaPamClient) -> List[CrosswalkRow]:
        """List every password changer on the tenant with protocol, port and usage.

        Changers come from ``client.password_types()``; templates and secret
        counts from ``client.secret_templates()`` joined on each template's
        ``passwordTypeId`` (``client.secret_template``). ``mapping`` is
        ``self.resolve(name, client.password_type(id))``.
        """
        raise NotImplementedError

    @staticmethod
    def write_template(rows: List[CrosswalkRow], path: str) -> None:
        """Write *rows* as CSV with ``TEMPLATE_COLUMNS``; unmapped rows leave mapping columns empty.

        Cells beginning with ``= + - @`` are prefixed with ``'`` (CSV injection).
        """
        raise NotImplementedError

    def check(self, client: DelineaPamClient, rows: List[CrosswalkRow], sample_size: int) -> List[CrosswalkCheck]:
        """Validate the map against up to *sample_size* real secrets per changer.

        Problems reported per sample: changer unmapped; no host field for a
        non-``login`` type; no username / password; non-numeric port;
        ``database_type`` / ``directory_type`` missing for pamDatabase / pamDirectory.
        Secret values are read only to test presence and never logged.
        """
        raise NotImplementedError
