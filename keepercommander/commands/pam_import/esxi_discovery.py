"""
ESXi Discovery Module

Reads host metadata via SOAP/pyvmomi: hardware, local users + roles +
permissions, network config, datastores, services, security, VMs.
Output: ESXiHostInfo dataclass (asdict-friendly).

Consumed by `pam project esxi-import` (`pam_import.esxi_import`) to
build pamMachine + pamUser + pamRemoteBrowser records. Mirrors the
`KCMDatabaseConnector` upstream pattern from `pam_import.kcm_import`
— in-process, no CLI of its own.

pyvmomi is a CONDITIONAL import; raises CommandError with install
hint when the operator invokes a command that needs it.
"""

import csv
import json
import logging
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from pyVim.connect import Disconnect, SmartConnect
    from pyVmomi import vim  # noqa: F401  (availability guard — re-exported)

    PYVMOMI_AVAILABLE = True
except ImportError:
    PYVMOMI_AVAILABLE = False

logger = logging.getLogger("keepercommander.pam_import.esxi_discovery")


# ============================================================================
# Data Classes
# ============================================================================


@dataclass
class ESXiUser:
    """ESXi local user"""

    username: str
    full_name: str
    shell_access: bool
    role: str
    role_id: int
    access_mode: str
    is_group: bool = False


@dataclass
class ESXiRole:
    """ESXi role definition"""

    name: str
    role_id: int
    system: bool
    privileges: List[str]
    description: str = ""


@dataclass
class ESXiNetwork:
    """Network configuration"""

    vswitches: List[str]
    port_groups: List[str]
    physical_nics: List[str]
    virtual_nics: List[str]
    dns_servers: List[str] = field(default_factory=list)


@dataclass
class ESXiDatastore:
    """Datastore information"""

    name: str
    type: str
    capacity_gb: float
    free_gb: float
    accessible: bool


@dataclass
class ESXiService:
    """Service status"""

    key: str
    label: str
    running: bool
    policy: str


@dataclass
class ESXiSecuritySettings:
    """Security configuration"""

    password_history: int
    account_lock_failures: int
    account_unlock_time: int
    password_max_days: int
    ssh_enabled: bool
    lockdown_mode: str
    default_shell_access: bool


@dataclass
class ESXiVMNic:
    """VM network interface"""

    name: str
    mac_address: str
    network: str
    ip_addresses: List[str] = field(default_factory=list)
    connected: bool = True


@dataclass
class ESXiVM:
    """Virtual machine information"""

    name: str
    uuid: str
    guest_id: str
    guest_full_name: str
    power_state: str
    num_cpu: int
    memory_mb: int
    ip_address: str  # Primary IP (empty when powered off OR tools missing)
    hostname: str
    nics: List[ESXiVMNic] = field(default_factory=list)
    tools_status: str = "unknown"
    tools_running: bool = False
    datastore: str = ""
    folder: str = ""
    annotation: str = ""
    # Phase 8.9: managed-object reference id (e.g., "vm-42"). Used to
    # cross-reference RetrieveAllPermissions() entries to specific VMs
    # so we know which user has access to which guest.
    entity_moid: str = ""
    # Phase 8.15: VM hardware compatibility version (e.g., "vmx-19").
    # Useful for compatibility checks but not strictly needed for PAM.
    hardware_version: str = ""


@dataclass
class ESXiPermission:
    """Phase 8.9: a single permission grant on an ESXi managed object.
    `auth_mgr.RetrieveAllPermissions()` returns these flattened across
    every entity (host, VM, datastore, folder, etc.). Capturing the
    entity context lets the import layer wire per-VM access."""

    principal: str
    entity_moid: str  # e.g., "vm-42", "ha-host", "datastore-3"
    entity_type: str  # e.g., "VirtualMachine", "HostSystem", "Datastore"
    entity_name: str  # resolved name for known entity types (VM name, etc.)
    role_id: int
    role: str
    propagate: bool
    is_group: bool


@dataclass
class ESXiHostInfo:
    """Complete ESXi host information"""

    hostname: str
    ip_address: str            # Phase 8.15.4: actual primary mgmt vNIC IP
    product_name: str
    version: str
    build: str
    api_version: str
    vendor: str
    model: str
    cpu_model: str
    cpu_cores: int
    cpu_sockets: int
    memory_gb: float
    license_key: str
    license_name: str
    discovered_at: str

    # Phase 8.15.4/5 additions; default empty for backwards compat with
    # existing state files that lack these keys
    connect_target: str = ""    # what was passed as host_address (FQDN/IP)
    service_tag: str = ""        # Dell ServiceTag, HPE Serial, etc.
    bios_version: str = ""

    users: List[ESXiUser] = field(default_factory=list)
    roles: List[ESXiRole] = field(default_factory=list)
    networks: Optional[ESXiNetwork] = None
    datastores: List[ESXiDatastore] = field(default_factory=list)
    services: List[ESXiService] = field(default_factory=list)
    security: Optional[ESXiSecuritySettings] = None
    vms: List[ESXiVM] = field(default_factory=list)
    # Phase 8.9: per-entity permission grants. The user→VM access map
    # is derived from this by filtering entries where
    # entity_type == "VirtualMachine" and grouping by entity_name.
    permissions: List["ESXiPermission"] = field(default_factory=list)


# ============================================================================
# Discovery Class
# ============================================================================


class ESXiDiscovery:
    """
    ESXi Host Discovery and Inventory

    Connects to ESXi hosts and discovers:
    - Hardware and software information
    - Users, roles, and permissions
    - Network configuration
    - Storage configuration
    - Security settings
    """

    def __init__(self, verify_ssl: bool = False, port: int = 443):
        if not PYVMOMI_AVAILABLE:
            raise ImportError("pyvmomi library not installed. Run: pip install pyvmomi")

        self.port = port
        self.ssl_context = self._create_ssl_context(verify_ssl)
        self._connection = None
        self._content = None
        self._host = None

    def _create_ssl_context(self, verify: bool) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def connect(self, host: str, username: str, password: str) -> bool:
        """Connect to ESXi host"""
        try:
            logger.info(f"Connecting to {host}:{self.port}")
            self._connection = SmartConnect(
                host=host, user=username, pwd=password, port=self.port, sslContext=self.ssl_context
            )
            self._content = self._connection.content

            # Get host system
            for child in self._content.rootFolder.childEntity:
                if hasattr(child, "hostFolder"):
                    for hf in child.hostFolder.childEntity:
                        if hasattr(hf, "host"):
                            self._host = hf.host[0]
                            break

            logger.info(f"Connected to {host}")
            return True
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def disconnect(self):
        """Disconnect from host"""
        if self._connection:
            try:
                Disconnect(self._connection)
            except Exception:
                pass
            self._connection = None
            self._content = None
            self._host = None

    def discover_host_info(self, host_address: str) -> Dict[str, Any]:
        """Discover basic host information.

        Phase 8.15 fixes:
        - `ip_address` is now the actual primary management vNIC IP from
          `host.config.network.vnic[]` (was wrongly set to host_address,
          which is the connection target — could be a FQDN).
        - `connect_target` (new) preserves what was passed as host_address
          for traceability.
        - `service_tag` (new) from `hw.systemInfo.otherIdentifyingInfo` —
          useful for support tickets (Dell ServiceTag, HPE Serial, etc.).
        - `bios_version` (new) from `hw.biosInfo.biosVersion`.
        """
        about = self._content.about
        hw = self._host.hardware if self._host else None

        # License info
        lic_mgr = self._content.licenseManager
        license_key = ""
        license_name = ""
        if lic_mgr.licenses:
            lic = lic_mgr.licenses[0]
            license_key = lic.licenseKey
            license_name = lic.name

        # Phase 8.15.4: actual mgmt NIC IP (was: host_address, mislabeled)
        ip_address = ""
        if self._host and self._host.config and self._host.config.network:
            for vnic in (self._host.config.network.vnic or []):
                if vnic.spec and vnic.spec.ip and vnic.spec.ip.ipAddress:
                    ip_address = vnic.spec.ip.ipAddress
                    break  # first vmk0/management
        if not ip_address:
            # Fall back to connection target so callers don't break,
            # but the field is now semantically correct most of the time.
            ip_address = host_address

        # Phase 8.15.5: service tag / serial from systemInfo.otherIdentifyingInfo
        service_tag = ""
        if hw and hw.systemInfo and getattr(hw.systemInfo, "otherIdentifyingInfo", None):
            for ident in hw.systemInfo.otherIdentifyingInfo:
                # Common identifier types: ServiceTag, EnclosureSerialNumberTag, SerialNumberTag
                key = (getattr(ident, "identifierType", None)
                       and getattr(ident.identifierType, "key", "") or "")
                if "Serial" in key or "Tag" in key:
                    val = getattr(ident, "identifierValue", "") or ""
                    if val and val != "Not Specified":
                        service_tag = val
                        break

        # Phase 8.15.5: BIOS version
        bios_version = ""
        if hw and getattr(hw, "biosInfo", None):
            bios_version = getattr(hw.biosInfo, "biosVersion", "") or ""

        return {
            "hostname": self._host.name if self._host else host_address,
            "ip_address": ip_address,
            "connect_target": host_address,
            "product_name": about.name,
            "version": about.version,
            "build": about.build,
            "api_version": about.apiVersion,
            "vendor": hw.systemInfo.vendor if hw else "Unknown",
            "model": hw.systemInfo.model if hw else "Unknown",
            "service_tag": service_tag,
            "bios_version": bios_version,
            "cpu_model": f"{hw.cpuInfo.hz / 1e9:.2f} GHz" if hw else "Unknown",
            "cpu_cores": hw.cpuInfo.numCpuCores if hw else 0,
            "cpu_sockets": hw.cpuInfo.numCpuPackages if hw else 0,
            "memory_gb": round(hw.memorySize / (1024**3), 1) if hw else 0,
            "license_key": license_key,
            "license_name": license_name,
            "discovered_at": datetime.utcnow().isoformat() + "Z",
        }

    def discover_users(self) -> List[ESXiUser]:
        """Discover local users and their roles"""
        users = []

        # Get user list
        user_dir = self._content.userDirectory
        user_list = user_dir.RetrieveUserGroups(
            domain=None, searchStr="", exactMatch=False, findUsers=True, findGroups=False
        )

        # Get permissions
        auth_mgr = self._content.authorizationManager
        permissions = auth_mgr.RetrieveAllPermissions()

        # Get access control entries
        access_entries = {}
        if self._host:
            cfg = self._host.configManager
            access_mgr = cfg.hostAccessManager
            entries = access_mgr.RetrieveHostAccessControlEntries()
            for entry in entries:
                access_entries[entry.principal] = entry.accessMode

        # Build role lookup
        role_lookup = {r.roleId: r.name for r in auth_mgr.roleList}

        # Build permission lookup
        perm_lookup = {}
        for perm in permissions:
            perm_lookup[perm.principal] = {
                "role_id": perm.roleId,
                "role": role_lookup.get(perm.roleId, "Unknown"),
                "propagate": perm.propagate,
                "group": perm.group,
            }

        for u in user_list:
            perm = perm_lookup.get(u.principal, {})
            users.append(
                ESXiUser(
                    username=u.principal,
                    full_name=u.fullName or "",
                    shell_access=getattr(u, "shellAccess", False),
                    role=perm.get("role", "NoAccess"),
                    role_id=perm.get("role_id", -5),
                    access_mode=access_entries.get(u.principal, "unknown"),
                    is_group=u.group,
                )
            )

        return users

    def discover_groups(self) -> List[Dict[str, Any]]:
        """Discover local groups"""
        groups = []

        user_dir = self._content.userDirectory
        group_list = user_dir.RetrieveUserGroups(
            domain=None, searchStr="", exactMatch=False, findUsers=False, findGroups=True
        )

        for g in group_list:
            groups.append({"name": g.principal, "full_name": g.fullName or ""})

        return groups

    def discover_roles(self) -> List[ESXiRole]:
        """Discover all available roles"""
        roles = []
        auth_mgr = self._content.authorizationManager

        for role in auth_mgr.roleList:
            roles.append(
                ESXiRole(
                    name=role.name,
                    role_id=role.roleId,
                    system=role.system,
                    privileges=list(role.privilege) if role.privilege else [],
                    description=role.info.summary if role.info else "",
                )
            )

        return roles

    def discover_privileges(self) -> Dict[str, List[str]]:
        """Discover all privileges grouped by category"""
        auth_mgr = self._content.authorizationManager
        privileges = {}

        for priv in auth_mgr.privilegeList:
            parts = priv.privId.split(".")
            category = parts[0]
            if category not in privileges:
                privileges[category] = []
            privileges[category].append(
                {
                    "id": priv.privId,
                    "name": priv.name,
                    "description": priv.onParent if hasattr(priv, "onParent") else "",
                }
            )

        return privileges

    def discover_network(self) -> ESXiNetwork:
        """Discover network configuration"""
        if not self._host:
            return ESXiNetwork([], [], [], [])

        cfg = self._host.configManager
        net = cfg.networkSystem
        net_info = net.networkInfo

        vswitches = [s.name for s in net_info.vswitch]
        port_groups = [p.spec.name for p in net_info.portgroup]
        pnics = [p.device for p in net_info.pnic]
        vnics = [v.device for v in net_info.vnic]

        # DNS
        dns_servers = []
        if net_info.dnsConfig:
            dns_servers = list(net_info.dnsConfig.address) if net_info.dnsConfig.address else []

        return ESXiNetwork(
            vswitches=vswitches,
            port_groups=port_groups,
            physical_nics=pnics,
            virtual_nics=vnics,
            dns_servers=dns_servers,
        )

    def discover_datastores(self) -> List[ESXiDatastore]:
        """Discover datastores"""
        datastores = []

        if not self._host:
            return datastores

        cfg = self._host.configManager
        ds_sys = cfg.datastoreSystem

        for ds in ds_sys.datastore:
            ds_type = "Unknown"
            if hasattr(ds.info, "vmfs") and ds.info.vmfs:
                ds_type = ds.info.vmfs.type
            elif hasattr(ds.info, "nas") and ds.info.nas:
                ds_type = "NFS"

            datastores.append(
                ESXiDatastore(
                    name=ds.name,
                    type=ds_type,
                    capacity_gb=round(ds.summary.capacity / (1024**3), 1),
                    free_gb=round(ds.summary.freeSpace / (1024**3), 1),
                    accessible=ds.summary.accessible,
                )
            )

        return datastores

    def discover_services(self) -> List[ESXiService]:
        """Discover services and their status"""
        services = []

        if not self._host:
            return services

        cfg = self._host.configManager
        svc_sys = cfg.serviceSystem

        for svc in svc_sys.serviceInfo.service:
            services.append(ESXiService(key=svc.key, label=svc.label, running=svc.running, policy=svc.policy))

        return services

    def discover_security(self) -> ESXiSecuritySettings:
        """Discover security settings"""
        if not self._host:
            return None

        cfg = self._host.configManager

        # Get advanced options
        adv_opt = cfg.advancedOption
        opts = adv_opt.QueryOptions()
        opt_dict = {opt.key: opt.value for opt in opts}

        # Get lockdown mode
        access_mgr = cfg.hostAccessManager
        lockdown = str(access_mgr.lockdownMode) if access_mgr else "unknown"

        # Check SSH status
        svc_sys = cfg.serviceSystem
        ssh_enabled = False
        for svc in svc_sys.serviceInfo.service:
            if svc.key == "TSM-SSH":
                ssh_enabled = svc.running
                break

        return ESXiSecuritySettings(
            password_history=opt_dict.get("Security.PasswordHistory", 0),
            account_lock_failures=opt_dict.get("Security.AccountLockFailures", 5),
            account_unlock_time=opt_dict.get("Security.AccountUnlockTime", 900),
            password_max_days=opt_dict.get("Security.PasswordMaxDays", 99999),
            ssh_enabled=ssh_enabled,
            lockdown_mode=lockdown,
            default_shell_access=opt_dict.get("Security.DefaultShellAccess", True),
        )

    def discover_permissions(self, vms: Optional[List[ESXiVM]] = None) -> List[ESXiPermission]:
        """Phase 8.9: walk RetrieveAllPermissions() and capture each grant
        with its entity context. The current discover_users() collapses
        these into a per-principal role lookup that loses the entity tie;
        this method preserves it so the import layer can wire per-VM
        access (alice has Admin on web-01, ReadOnly on db-01, etc.).

        Phase 8.11 (live-test L1 finding): single-host ESXi assigns perms
        at the root-folder level (`ha-folder-root`) or HostSystem level
        with `propagate=True`. Without expansion, the
        `entity_type=VirtualMachine` filter in vm_access_map returns
        empty even though every user effectively has access to every VM.
        We now expand propagated grants on KNOWN root entities into
        per-VM `ESXiPermission(entity_type="VirtualMachine", expanded=True)`
        entries — preserving the original permission AND emitting derived
        ones the import layer can act on. Direct per-VM grants (vCenter)
        are kept as-is and dedupe wins over expansion.

        `vms` is the list returned by discover_vms() — used to resolve
        entity_moid → entity_name for VirtualMachine permissions AND to
        materialise the expanded entries. Pass None to skip both paths."""
        if not self._content:
            return []
        auth_mgr = self._content.authorizationManager
        try:
            permissions = auth_mgr.RetrieveAllPermissions()
        except Exception as exc:
            logger.warning("RetrieveAllPermissions() failed: %s", exc)
            return []

        role_lookup = {r.roleId: r.name for r in auth_mgr.roleList}
        vm_moid_to_name: Dict[str, str] = {}
        if vms:
            vm_moid_to_name = {vm.entity_moid: vm.name for vm in vms if vm.entity_moid}

        # Known root entities whose propagated perms cover all VMs on a
        # single-host ESXi. Conservative: if entity_moid is NOT in this
        # set, we don't expand — vCenter sub-folder hierarchies need a
        # separate parent-traversal we don't implement, and over-granting
        # is the worse failure mode.
        ROOT_FOLDER_MOIDS = {"ha-folder-root", "ha-folder-vm", "group-d1"}

        out: List[ESXiPermission] = []
        for perm in permissions:
            entity = getattr(perm, "entity", None)
            entity_moid = getattr(entity, "_moId", "") if entity is not None else ""
            entity_type = type(entity).__name__ if entity is not None else ""
            # Strip the pyvmomi prefix (e.g., "vim.VirtualMachine" → "VirtualMachine")
            if "." in entity_type:
                entity_type = entity_type.rsplit(".", 1)[-1]
            entity_name = vm_moid_to_name.get(entity_moid, "") if entity_type == "VirtualMachine" else ""

            base = ESXiPermission(
                principal=perm.principal,
                entity_moid=entity_moid,
                entity_type=entity_type,
                entity_name=entity_name,
                role_id=perm.roleId,
                role=role_lookup.get(perm.roleId, "Unknown"),
                propagate=bool(perm.propagate),
                is_group=bool(getattr(perm, "group", False)),
            )
            out.append(base)

            # Expansion: propagated host/root-folder perms cover all VMs.
            # Only fire when we actually have VMs to materialise against.
            should_expand = (
                base.propagate
                and vms
                and (
                    base.entity_type == "HostSystem"
                    or (base.entity_type == "Folder" and base.entity_moid in ROOT_FOLDER_MOIDS)
                )
            )
            if should_expand:
                for vm in vms:
                    if not vm.entity_moid or not vm.name:
                        continue
                    out.append(
                        ESXiPermission(
                            principal=base.principal,
                            entity_moid=vm.entity_moid,
                            entity_type="VirtualMachine",
                            entity_name=vm.name,
                            role_id=base.role_id,
                            role=base.role,
                            propagate=False,  # already expanded; no further inheritance
                            is_group=base.is_group,
                        )
                    )

        # Dedupe: a (principal, entity_moid) pair may appear from both an
        # expansion and a direct grant. Keep the first occurrence — direct
        # grants are walked first in source order and override expansions
        # since they reflect the operator's explicit intent.
        seen: set = set()
        deduped: List[ESXiPermission] = []
        for p in out:
            key = (p.principal, p.entity_moid, p.role_id)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(p)
        return deduped

    def discover_vms(self) -> List[ESXiVM]:
        """Discover virtual machines and their network information"""
        vms = []

        if not self._host:
            return vms

        # Get all VMs on this host
        for vm in self._host.vm:
            try:
                config = vm.config
                summary = vm.summary
                guest = vm.guest

                if not config:
                    continue

                # Get primary IP address
                ip_address = ""
                hostname = ""
                nics = []

                if guest:
                    ip_address = guest.ipAddress or ""
                    hostname = guest.hostName or ""

                    # Get all NICs and their IPs
                    if guest.net:
                        for net_info in guest.net:
                            nic_ips = []
                            if net_info.ipConfig and net_info.ipConfig.ipAddress:
                                for ip_config in net_info.ipConfig.ipAddress:
                                    nic_ips.append(ip_config.ipAddress)

                            nics.append(
                                ESXiVMNic(
                                    name=net_info.deviceConfigId
                                    if hasattr(net_info, "deviceConfigId")
                                    else str(len(nics)),
                                    mac_address=net_info.macAddress or "",
                                    network=net_info.network or "",
                                    ip_addresses=nic_ips,
                                    connected=net_info.connected if hasattr(net_info, "connected") else True,
                                )
                            )

                # Get datastore
                datastore = ""
                if config.files and config.files.vmPathName:
                    # Extract datastore from path like "[datastore1] vm/vm.vmx"
                    path = config.files.vmPathName
                    if path.startswith("[") and "]" in path:
                        datastore = path[1 : path.index("]")]

                # Get folder path
                folder = ""
                parent = vm.parent
                while parent:
                    if hasattr(parent, "name"):
                        folder = f"{parent.name}/{folder}" if folder else parent.name
                    if not hasattr(parent, "parent"):
                        break
                    parent = parent.parent

                # Tools status
                tools_status = "unknown"
                tools_running = False
                if guest:
                    tools_status = guest.toolsStatus or "unknown"
                    tools_running = (
                        guest.toolsRunningStatus == "guestToolsRunning" if guest.toolsRunningStatus else False
                    )

                vms.append(
                    ESXiVM(
                        name=config.name,
                        uuid=config.uuid,
                        guest_id=config.guestId or "",
                        guest_full_name=config.guestFullName or "",
                        power_state=str(summary.runtime.powerState),
                        entity_moid=getattr(vm, "_moId", "") or "",
                        num_cpu=config.hardware.numCPU,
                        memory_mb=config.hardware.memoryMB,
                        ip_address=ip_address,
                        hostname=hostname,
                        nics=nics,
                        tools_status=tools_status,
                        tools_running=tools_running,
                        datastore=datastore,
                        folder=folder,
                        annotation=config.annotation or "",
                        # Phase 8.15.5: hardware compat version (e.g., "vmx-19")
                        hardware_version=getattr(config, "version", "") or "",
                    )
                )

                # Phase 8.15.4 warning: empty ip_address means the VM
                # is powered off OR has no guest tools running. Operator
                # impact: the pamMachine that gets created from this row
                # will have a `<UPDATE-IP-FOR-{name}>` placeholder hostname
                # — Web Vault launches will fail until the operator either
                # (a) powers on the VM and re-discovers, or (b) configures
                # static IP / DNS and edits the record post-import.
                if not ip_address:
                    if "poweredOff" in str(summary.runtime.powerState):
                        logger.warning(
                            "VM '%s' is POWERED OFF — pamHostname will be a "
                            "placeholder. Power on + re-discover for accurate "
                            "IP, OR configure static IP / DNS so the placeholder "
                            "resolves at gateway-launch time.", config.name)
                    elif not tools_running:
                        logger.warning(
                            "VM '%s' has no running guest tools — pamHostname "
                            "will be a placeholder. Install/start VMware Tools "
                            "or configure static IP / DNS for stable PAM record.",
                            config.name)

            except Exception as e:
                logger.warning(f"Error discovering VM: {e}")
                continue

        return vms

    def discover_all(self, host: str, username: str, password: str) -> ESXiHostInfo:
        """
        Perform full discovery of an ESXi host

        Returns complete ESXiHostInfo with all discovered data
        """
        if not self.connect(host, username, password):
            raise ConnectionError(f"Failed to connect to {host}")

        try:
            logger.info("Discovering host information...")
            host_info = self.discover_host_info(host)

            logger.info("Discovering users...")
            users = self.discover_users()

            logger.info("Discovering roles...")
            roles = self.discover_roles()

            logger.info("Discovering network...")
            network = self.discover_network()

            logger.info("Discovering datastores...")
            datastores = self.discover_datastores()

            logger.info("Discovering services...")
            services = self.discover_services()

            logger.info("Discovering security settings...")
            security = self.discover_security()

            logger.info("Discovering virtual machines...")
            vms = self.discover_vms()

            logger.info("Discovering per-entity permissions...")
            permissions = self.discover_permissions(vms=vms)

            return ESXiHostInfo(
                **host_info,
                users=users,
                roles=roles,
                networks=network,
                datastores=datastores,
                services=services,
                security=security,
                vms=vms,
                permissions=permissions,
            )
        finally:
            self.disconnect()

    def to_dict(self, host_info: ESXiHostInfo) -> Dict[str, Any]:
        """Convert ESXiHostInfo to dictionary"""
        data = asdict(host_info)
        # Convert nested dataclasses
        data["users"] = [asdict(u) for u in host_info.users]
        data["roles"] = [asdict(r) for r in host_info.roles]
        data["networks"] = asdict(host_info.networks) if host_info.networks else None
        data["datastores"] = [asdict(d) for d in host_info.datastores]
        data["services"] = [asdict(s) for s in host_info.services]
        data["security"] = asdict(host_info.security) if host_info.security else None
        data["vms"] = [self._vm_to_dict(vm) for vm in host_info.vms]
        data["permissions"] = [asdict(p) for p in host_info.permissions]
        return data

    def _vm_to_dict(self, vm: ESXiVM) -> Dict[str, Any]:
        """Convert ESXiVM to dictionary"""
        d = asdict(vm)
        d["nics"] = [asdict(nic) for nic in vm.nics]
        return d

    def to_json(self, host_info: ESXiHostInfo, indent: int = 2) -> str:
        """Convert ESXiHostInfo to JSON string"""
        return json.dumps(self.to_dict(host_info), indent=indent)

    def save_json(self, host_info: ESXiHostInfo, filepath: str):
        """Save discovery results to JSON file"""
        with open(filepath, "w") as f:
            f.write(self.to_json(host_info))
        logger.info(f"Saved discovery results to {filepath}")

    def save_csv(self, host_info: ESXiHostInfo, filepath: str):
        """Save users to CSV file"""
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Username", "Full Name", "Role", "Shell Access", "Access Mode"])
            for user in host_info.users:
                writer.writerow(
                    [user.username, user.full_name, user.role, user.shell_access, user.access_mode]
                )
        logger.info(f"Saved user list to {filepath}")


# ============================================================================
# CLI
