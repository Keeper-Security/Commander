import json
import logging
from .tunnel_helpers import generate_random_bytes, get_config_uid
from ....keeper_dag import DAG, EdgeType
from ....keeper_dag.connection.commander import Connection
from ....keeper_dag.types import RefType, PamGraphId
from ....keeper_dag.vertex import DAGVertex
from ....discovery_common.types import UserAclRotationSettings, UserAcl
from ....display import bcolors
from ....vault import PasswordRecord, TypedRecord
from ....proto import pam_pb2, router_pb2
from ...pam._layer_b import should_fallback_on_layer_b_error
from keeper_secrets_manager_core.utils import url_safe_str_to_bytes


def get_vertex_content(vertex):
    return_content = None
    if vertex is None:
        return return_content
    try:
        return_content = vertex.content_as_dict
    except Exception as e:
        import logging
        logging.debug(f"Error getting vertex content: {e}")
        return_content = None
    return return_content


# Resource meta version (int). Vault uses version >= 1 to read launch credentials from ACL.
# In set_resource_allowed: meta_version=None or 0 -> legacy (no version in meta); 1 -> v1.
# Future: add RESOURCE_META_VERSION_V2, etc. and handle them in build_resource_meta().
RESOURCE_META_VERSION_V1 = 1


def build_resource_meta_v1(allowed_settings, rotate_on_termination=False):
    """
    Build DAG resource meta payload in v1 format so vault uses ACL is_launch_credential for launch.
    Returns dict: {"version": <int>, "allowedSettings": allowed_settings, "rotateOnTermination": bool}.
    """
    if not isinstance(allowed_settings, dict):
        allowed_settings = {}
    return {
        "version": int(RESOURCE_META_VERSION_V1),
        "allowedSettings": dict(allowed_settings),
        "rotateOnTermination": bool(rotate_on_termination),
    }


def build_resource_meta(version, allowed_settings, rotate_on_termination=False):
    """
    Build DAG resource meta payload for the given version (int).
    version=1 -> v1 format; other values can be added for v2, v3, etc.
    """
    if version == RESOURCE_META_VERSION_V1:
        return build_resource_meta_v1(allowed_settings, rotate_on_termination)
    # Future: elif version == RESOURCE_META_VERSION_V2: return build_resource_meta_v2(...)
    raise ValueError(f"Unsupported resource meta version: {version}")


def ensure_resource_meta_v1(content):
    """
    Ensure existing meta content has version 1 and rotateOnTermination (for re-writes).
    Returns a copy with version=<int> and rotateOnTermination default False if missing.
    """
    if content is None:
        return build_resource_meta_v1({}, False)
    out = dict(content)
    out["version"] = int(RESOURCE_META_VERSION_V1)
    if "rotateOnTermination" not in out:
        out["rotateOnTermination"] = False
    # Normalize allowedSettings key if content used a different key (e.g. allowedSettings)
    if "allowedSettings" not in out and "allowed_settings" in out:
        out["allowedSettings"] = out.pop("allowed_settings", {})
    return out


def build_meta_version_upgrade():
    """Meta payload that bumps a resource's meta to v1 WITHOUT re-asserting any
    allowedSettings flags.

    Used by the launch-credential / version-upgrade Layer-B calls. krouter
    deep-merges the ``meta`` JSON edge (krouter Serialization.kt ``mergeJson``)
    and never deletes keys absent from the new payload, so an EMPTY
    ``allowedSettings`` preserves the server's current connections / portForwards /
    recording flags while still bumping ``version``. ``allowedSettings`` must be
    present (even if empty) because krouter strictly decodes the incoming meta
    into its non-nullable ``Meta.allowedSettings`` DTO before merging.

    This avoids the revert bug: ``set_resource_allowed``'s Layer-B path enables
    ``connections`` on the server but does not refresh the in-memory vertex, so a
    follow-up ``ensure_resource_meta_v1(get_vertex_content(...))`` would re-send a
    STALE ``connections=false`` that deep-merges and flips connections back off —
    making the vault hide the (still-present) connection port/protocol.
    """
    return {"version": int(RESOURCE_META_VERSION_V1), "allowedSettings": {}}


class TunnelDAG:
    def __init__(self, params, encrypted_session_token, encrypted_transmission_key, record_uid: str,
                 is_config=False, transmission_key=None):
        config_uid = None
        if not is_config:
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
        if not config_uid:
            config_uid = record_uid
        self.params = params  # retained for Layer-B router_configure_resource calls
        self.record = PasswordRecord()
        self.record.record_uid = config_uid
        self.record.record_key = generate_random_bytes(32)
        self.encrypted_session_token = encrypted_session_token
        self.encrypted_transmission_key = encrypted_transmission_key
        self.transmission_key = transmission_key
        self.conn = Connection(params=params,
                               encrypted_transmission_key=self.encrypted_transmission_key,
                               encrypted_session_token=self.encrypted_session_token,
                               transmission_key=self.transmission_key,
                               use_read_protobuf=False,
                               use_write_protobuf=False
                               )
        self.linking_dag = DAG(conn=self.conn, record=self.record,
                               graph_id=PamGraphId.PAM.value)
        try:
            self.linking_dag.load()
        except Exception as e:
            import logging
            logging.debug(f"Error loading config: {e}")

    def resource_belongs_to_config(self, resource_uid):
        if not self.linking_dag.has_graph:
            return False
        resource_vertex = self.linking_dag.get_vertex_by_uid(resource_uid)
        config_vertex = self.linking_dag.get_vertex_by_uid(self.record.record_uid)
        return resource_vertex and config_vertex.has(resource_vertex, EdgeType.LINK)

    def user_belongs_to_config(self, user_uid):
        if not self.linking_dag.has_graph:
            return False
        user_vertex = self.linking_dag.get_vertex_by_uid(user_uid)
        config_vertex = self.linking_dag.get_vertex_by_uid(self.record.record_uid)
        res_content = False
        if user_vertex and config_vertex and config_vertex.has(user_vertex, EdgeType.ACL):
            acl_edge = user_vertex.get_edge(config_vertex, EdgeType.ACL)
            _content = acl_edge.content_as_dict
            res_content = _content.get('belongs_to', False) if _content else False
        return res_content

    def check_tunneling_enabled_config(self, enable_connections=None, enable_tunneling=None,
                                       enable_rotation=None, enable_session_recording=None,
                                       enable_typescript_recording=None, remote_browser_isolation=None):
        if not self.linking_dag.has_graph:
            return False
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        content = get_vertex_content(config_vertex)
        if content is None or not content.get('allowedSettings'):
            return False

        allowed_settings = content['allowedSettings']
        if enable_connections and not allowed_settings.get("connections"):
            return False
        if enable_tunneling and not allowed_settings.get("portForwards"):
            return False
        if enable_rotation and not allowed_settings.get("rotation"):
            return False
        if allowed_settings.get("connections") and allowed_settings["connections"]:
            if enable_session_recording and not allowed_settings.get("sessionRecording"):
                return False
            if enable_typescript_recording and not allowed_settings.get("typescriptRecording"):
                return False
        if remote_browser_isolation and not allowed_settings.get("remoteBrowserIsolation"):
            return False
        return True

    @staticmethod
    def _convert_allowed_setting(value):
        """Converts on/off/default|any to True/False/None"""
        if value is None or isinstance(value, bool):
            return value
        return {"on": True, "off": False}.get(str(value).lower(), None)

    @classmethod
    def _is_allowed_setting_default_reset(cls, value):
        """True when input is on/off/default and resolves to default (remove key)."""
        return value is not None and cls._convert_allowed_setting(value) is None

    def edit_tunneling_config(self, connections=None, tunneling=None,
                              rotation=None, session_recording=None,
                              typescript_recording=None,
                              remote_browser_isolation=None,
                              ai_enabled=None, ai_session_terminate=None):
        resetting_allowed_settings = any(
            self._is_allowed_setting_default_reset(v)
            for v in (
                connections, tunneling, rotation, session_recording,
                typescript_recording, remote_browser_isolation,
                ai_enabled, ai_session_terminate,
            )
        )
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            config_vertex = self.linking_dag.add_vertex(uid=self.record.record_uid, vertex_type=RefType.PAM_NETWORK)

        if config_vertex.vertex_type != RefType.PAM_NETWORK:
            config_vertex.vertex_type = RefType.PAM_NETWORK
        content = get_vertex_content(config_vertex)
        if content and content.get('allowedSettings'):
            allowed_settings = dict(content['allowedSettings'])
            del content['allowedSettings']
            content = {'allowedSettings': allowed_settings}

        if content is None:
            content = {'allowedSettings': {}}
        if 'allowedSettings' not in content:
            content['allowedSettings'] = {}

        allowed_settings = content['allowedSettings']
        dirty = False

        # When no value in allowedSettings: client will substitute with default
        # rotation defaults to True, everything else defaults to False

        # switching to 3-state on/off/default: on/true, off/false,
        # None = Keep existing, 'default' = Reset to default (remove from dict)
        if connections is not None:
            connections = self._convert_allowed_setting(connections)
            if connections != allowed_settings.get("connections", None):
                dirty = True
                if connections is None:
                    allowed_settings.pop("connections", None)
                else:
                    allowed_settings["connections"] = connections

        if tunneling is not None:
            tunneling = self._convert_allowed_setting(tunneling)
            if tunneling != allowed_settings.get("portForwards", None):
                dirty = True
                if tunneling is None:
                    allowed_settings.pop("portForwards", None)
                else:
                    allowed_settings["portForwards"] = tunneling

        if rotation is not None:
            rotation = self._convert_allowed_setting(rotation)
            if rotation != allowed_settings.get("rotation", None):
                dirty = True
                if rotation is None:
                    allowed_settings.pop("rotation", None)
                else:
                    allowed_settings["rotation"] = rotation

        if session_recording is not None:
            session_recording = self._convert_allowed_setting(session_recording)
            if session_recording != allowed_settings.get("sessionRecording", None):
                dirty = True
                if session_recording is None:
                    allowed_settings.pop("sessionRecording", None)
                else:
                    allowed_settings["sessionRecording"] = session_recording

        if typescript_recording is not None:
            typescript_recording = self._convert_allowed_setting(typescript_recording)
            if typescript_recording != allowed_settings.get("typescriptRecording", None):
                dirty = True
                if typescript_recording is None:
                    allowed_settings.pop("typescriptRecording", None)
                else:
                    allowed_settings["typescriptRecording"] = typescript_recording

        if remote_browser_isolation is not None:
            remote_browser_isolation = self._convert_allowed_setting(remote_browser_isolation)
            if remote_browser_isolation != allowed_settings.get("remoteBrowserIsolation", None):
                dirty = True
                if remote_browser_isolation is None:
                    allowed_settings.pop("remoteBrowserIsolation", None)
                else:
                    allowed_settings["remoteBrowserIsolation"] = remote_browser_isolation

        if ai_enabled is not None:
            ai_enabled = self._convert_allowed_setting(ai_enabled)
            if ai_enabled != allowed_settings.get("aiEnabled", None):
                dirty = True
                if ai_enabled is None:
                    allowed_settings.pop("aiEnabled", None)
                else:
                    allowed_settings["aiEnabled"] = ai_enabled

        if ai_session_terminate is not None:
            ai_session_terminate = self._convert_allowed_setting(ai_session_terminate)
            if ai_session_terminate != allowed_settings.get("aiSessionTerminate", None):
                dirty = True
                if ai_session_terminate is None:
                    allowed_settings.pop("aiSessionTerminate", None)
                else:
                    allowed_settings["aiSessionTerminate"] = ai_session_terminate

        if dirty:
            # Primary: Layer-B configure_network_graph (permission-checked).
            # The configuration record's allowedSettings belong on the network
            # endpoint, not configure_resource — the latter bypasses per-feature
            # enforcement checks for remoteBrowserIsolation / rotation /
            # connections that the network endpoint enforces server-side.
            #
            # Fallback policy matches the other Layer-B endpoints: strict by
            # default; 404 / RRC denials fall back to legacy DAG-write only
            # when KEEPER_DAG_LB_FALLBACK=1 (per `should_fallback_on_layer_b_error`).
            # Transient errors (5xx, connection, timeout) always propagate.
            from ...pam.router_helper import router_configure_network_graph, get_router_url
            from ...pam._layer_b import is_layer_b_feature_disabled
            host = get_router_url(self.params)
            endpoint = 'configure_network_graph'
            if not resetting_allowed_settings and not is_layer_b_feature_disabled(host, endpoint):
                try:
                    config_uid_bytes = url_safe_str_to_bytes(self.record.record_uid)
                    rq = router_pb2.PAMNetworkConfigurationRequest(
                        recordUid=config_uid_bytes,
                        networkSettings=router_pb2.PAMNetworkSettings(
                            allowedSettings=json.dumps(allowed_settings).encode()
                        ),
                    )
                    router_configure_network_graph(self.params, rq)
                    logging.debug(
                        f"edit_tunneling_config: applied via configure_network_graph for {self.record.record_uid}"
                    )
                    return
                except Exception as err:
                    if not should_fallback_on_layer_b_error(err, host=host, endpoint=endpoint):
                        logging.error(f"configure_network_graph failed (no fallback): {err}", exc_info=True)
                        raise
                    logging.warning(
                        f"configure_network_graph denied/unavailable for {self.record.record_uid}; "
                        f"falling back to legacy DAG-write: {err}"
                    )

            # Fallback: legacy direct DAG-write.
            config_vertex.add_data(content=content, path='meta', needs_encryption=False)
            self.linking_dag.save()

    def get_all_owners(self, uid):
        owners = []
        if self.linking_dag.has_graph:
            vertex = self.linking_dag.get_vertex(uid)
            if vertex:
                owners = [owner.uid for owner in vertex.belongs_to_vertices()]
        return owners

    def user_belongs_to_resource(self, user_uid, resource_uid):
        user_vertex = self.linking_dag.get_vertex(user_uid)
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        res_content = False
        if user_vertex and resource_vertex and resource_vertex.has(user_vertex, EdgeType.ACL):
            acl_edge = user_vertex.get_edge(resource_vertex, EdgeType.ACL)
            _content = acl_edge.content_as_dict
            res_content = _content.get('belongs_to', False) if _content else False
        return res_content

    def get_resource_uid(self, user_uid):
        if not self.linking_dag.has_graph:
            return None
        resources = self.get_all_owners(user_uid)
        if len(resources) > 0:
            for resource in resources:
                if self.user_belongs_to_resource(user_uid, resource):
                    return resource
        return None

    def link_resource_to_config(self, resource_uid):
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            config_vertex = self.linking_dag.add_vertex(uid=self.record.record_uid)

        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            resource_vertex = self.linking_dag.add_vertex(uid=resource_uid)

        if not config_vertex.has(resource_vertex, EdgeType.LINK):
            resource_vertex.belongs_to(config_vertex, EdgeType.LINK)
            self.linking_dag.save()

    def link_user_to_config(self, user_uid):
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            config_vertex = self.linking_dag.add_vertex(uid=self.record.record_uid)
        # IAM-user link. Permission-check via set_record_rotation BEFORE the legacy
        # DAG write (server-side set_record_rotation with no
        # resource/saasConfiguration and noop=False permission-checks edit-access
        # on the pamUser record and sets is_iam_user atomically). No legacy fallback
        # - if the call fails, propagate so the unauthorized link is never written.
        self._permission_check_iam_user_link(user_uid)
        self.link_user(user_uid, config_vertex, belongs_to=True, is_iam_user=True)

    def _permission_check_iam_user_link(self, user_uid):
        """Call set_record_rotation(recordUid=user_uid, noop=False) to permission-check
        an is_iam_user link write. Raises on permission denial; no fallback. The
        server enforces edit-access on the pamUser record at the call boundary, so 
        the per-flag check that other Layer-B endpoints do is not needed here."""
        from ...pam.router_helper import router_set_record_rotation_information
        current_record_rotation = self.params.record_rotation_cache.get(user_uid)
        revision = (
            current_record_rotation.get('revision', 0)
            if current_record_rotation else 0
        )
        # IAM link: resourceUid must stay empty so krouter sets isIAM=true
        # (resourceUid.isEmpty && noop=False). Never copy resource_uid from cache.
        rq = router_pb2.RouterRecordRotationRequest(
            recordUid=url_safe_str_to_bytes(user_uid),
            configurationUid=url_safe_str_to_bytes(self.record.record_uid),
            revision=revision,
            resourceUid=b'',
            noop=False,
        )
        router_set_record_rotation_information(self.params, rq)
        logging.debug(
            f"is_iam_user link permission-checked via set_record_rotation for {user_uid}"
        )

    def link_user_to_config_with_options(self, user_uid, is_admin=None, belongs_to=None, is_iam_user=None):
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            config_vertex = self.linking_dag.add_vertex(uid=self.record.record_uid)

        # is_iam_user: route through set_record_rotation for the permission check.
        # No legacy fallback for this flag — if the server rejects,
        # propagate rather than write an unauthorized ACL edge locally.
        # is_admin (domain-controller admin on the config vertex): in development
        # server-side but has no new krouter API yet — legacy DAG-write only. When
        # the new API ships, gate the local write below behind it.
        # belongs_to: bare membership, no security-sensitive permission decision;
        # legacy write only.
        if is_iam_user is True:
            self._permission_check_iam_user_link(user_uid)

        source_vertex = config_vertex
        user_vertex = self.linking_dag.get_vertex(user_uid)
        if user_vertex is None:
            user_vertex = self.linking_dag.add_vertex(uid=user_uid, vertex_type=RefType.PAM_USER)

        # switching to 3-state on/off/default: on/true, off/false,
        # None = Keep existing, 'default' = Reset to default (remove from dict)
        states = {'on': True, 'off': False, 'default': '', 'none': None}

        content = {
            "belongs_to": states.get(str(belongs_to).lower()),
            "is_admin": states.get(str(is_admin).lower()),
            "is_iam_user": states.get(str(is_iam_user).lower())
        }
        if user_vertex.vertex_type != RefType.PAM_USER:
            user_vertex.vertex_type = RefType.PAM_USER

        dirty = False
        if source_vertex.has(user_vertex, EdgeType.ACL):
            acl_edge = user_vertex.get_edge(source_vertex, EdgeType.ACL)
            existing_content = acl_edge.content_as_dict or {}
            old_content = existing_content.copy()
            for key in list(existing_content.keys()):
                if content.get(key) is not None:
                    if content[key] == '':
                        existing_content.pop(key)
                    elif content[key] in (True, False):
                        existing_content[key] = content[key]
            content = {k: v for k, v in content.items() if v not in (None, '')}
            for k, v in content.items():
                existing_content.setdefault(k, v)
            if existing_content != old_content:
                dirty = True

            if dirty:
                user_vertex.belongs_to(source_vertex, EdgeType.ACL, content=existing_content)
                # user_vertex.add_data(content=existing_content, needs_encryption=False)
                self.linking_dag.save()
        else:
            content = {k: v for k, v in content.items() if v not in (None, '')}
            user_vertex.belongs_to(source_vertex, EdgeType.ACL, content=content)
            self.linking_dag.save()

    def unlink_user_from_resource(self, user_uid, resource_uid) -> bool:
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None or not self.resource_belongs_to_config(resource_uid):
            print(f"{bcolors.FAIL}Resource {resource_uid} does not belong to the configuration{bcolors.ENDC}")
            return False

        user_vertex = self.linking_dag.get_vertex(user_uid)
        if user_vertex is None or user_vertex.vertex_type != RefType.PAM_USER:
            return False

        if resource_vertex.has(user_vertex, EdgeType.ACL):
            acl_edge = user_vertex.get_edge(resource_vertex, EdgeType.ACL)
            edge_content = acl_edge.content_as_dict or {}
            link_keys = ('belongs_to', 'is_admin')  # "is_iam_user"
            dirty = any(key in link_keys for key in edge_content)
            if dirty:
                for link_key in link_keys:
                    edge_content.pop(link_key, None)
                user_vertex.belongs_to(resource_vertex, EdgeType.ACL, content=edge_content)
                self.linking_dag.save()
                return True

        return False

    def link_user_to_resource(self, user_uid, resource_uid, is_admin=None, belongs_to=None, is_launch_credential=None):
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None or not self.resource_belongs_to_config(resource_uid):
            print(f"{bcolors.FAIL}Resource {resource_uid} does not belong to the configuration{bcolors.ENDC}")
            return False

        # Layer-B: when setting an admin credential, route through configure_resource
        # for the permission check (addresses the "link unauthorized record as credentials"
        # security finding). On RRC_NOT_ALLOWED* with `KEEPER_DAG_LB_FALLBACK` enabled,
        # fall through to the legacy in-memory + save path.
        # Other flag-only paths (belongs_to / is_launch_credential without is_admin) stay
        # legacy because PAMResourceConfig doesn't model those flags independently.
        if is_admin is True:
            from ...pam.router_helper import router_configure_resource, get_router_url
            from ...pam._layer_b import is_layer_b_feature_disabled
            host = get_router_url(self.params)
            endpoint = 'configure_resource'
            if not is_layer_b_feature_disabled(host, endpoint):
                try:
                    # adminUid must ride ALONGSIDE connectUsers: krouter only flips
                    # is_admin on an already-existing ACL edge when connectUsers is
                    # present (UserRest.kt:295-318); a standalone adminUid no-ops on
                    # an existing edge (UserRest.kt:331-341). Send the resource's
                    # CURRENT launch credentials as connectUsers so the reconciliation
                    # sets is_admin without clearing any existing launch credential.
                    launch_uids = self.get_launch_credentials(resource_uid)
                    rq = pam_pb2.PAMResourceConfig(
                        recordUid=url_safe_str_to_bytes(resource_uid),
                        networkUid=url_safe_str_to_bytes(self.record.record_uid),
                        adminUid=url_safe_str_to_bytes(user_uid),
                        connectUsers=pam_pb2.UidList(
                            uids=[url_safe_str_to_bytes(u) for u in launch_uids]),
                    )
                    router_configure_resource(self.params, rq)
                    logging.debug(
                        f"link_user_to_resource: admin {user_uid} set on {resource_uid} via configure_resource"
                    )
                    return None
                except Exception as err:
                    if not should_fallback_on_layer_b_error(err, host=host, endpoint=endpoint):
                        logging.error(f"configure_resource failed (no fallback): {err}", exc_info=True)
                        raise
                    logging.warning(
                        f"configure_resource denied/unavailable for {resource_uid}; falling back to legacy "
                        f"DAG-write (KEEPER_DAG_LB_FALLBACK enabled): {err}"
                    )

        self.link_user(user_uid, resource_vertex, is_admin, belongs_to, is_launch_credential=is_launch_credential)
        return None

    def link_user(self, user_uid, source_vertex: DAGVertex, is_admin=None, belongs_to=None, is_iam_user=None,
                  is_launch_credential=None):

        user_vertex = self.linking_dag.get_vertex(user_uid)
        if user_vertex is None:
            user_vertex = self.linking_dag.add_vertex(uid=user_uid, vertex_type=RefType.PAM_USER)

        content = {}
        dirty = False
        if belongs_to is not None:
            content["belongs_to"] = bool(belongs_to)
        if is_admin is not None:
            content["is_admin"] = bool(is_admin)
        if is_iam_user is not None:
            content["is_iam_user"] = bool(is_iam_user)
        if is_launch_credential is not None:
            content["is_launch_credential"] = bool(is_launch_credential)

        if user_vertex.vertex_type != RefType.PAM_USER:
            user_vertex.vertex_type = RefType.PAM_USER

        if source_vertex.has(user_vertex, EdgeType.ACL):
            acl_edge = user_vertex.get_edge(source_vertex, EdgeType.ACL)
            existing_content = acl_edge.content_as_dict or {}
            for key in existing_content:
                if key not in content:
                    content[key] = existing_content[key]
            if content != existing_content:
                dirty = True

            if dirty:
                user_vertex.belongs_to(source_vertex, EdgeType.ACL, content=content)
                # user_vertex.add_data(content=content, needs_encryption=False)
                self.linking_dag.save()
        else:
            user_vertex.belongs_to(source_vertex, EdgeType.ACL, content=content)
            self.linking_dag.save()

    def link_saas_user(self, user_uid: str, saas_config_record: TypedRecord, pam_config_record_type: str) -> bool:

        logging.debug("linking saas user")

        if not self.linking_dag.has_graph:
            logging.error("linking graph is empty")
            return False

        configuration_vertex = self.linking_dag.get_root
        if configuration_vertex is None:
            logging.error("cannot find configuration vertex,")
            return False

        user_vertex = self.linking_dag.get_vertex(user_uid)
        if user_vertex is None:
            logging.debug("creating vertex for user")
            user_vertex = self.linking_dag.add_vertex(uid=user_uid, vertex_type=RefType.PAM_USER)

        acl_edge = user_vertex.get_edge(vertex=configuration_vertex, edge_type=EdgeType.ACL)
        if acl_edge is not None:
            logging.debug("have an existing ACL edge between the user and configuration")
            acl = acl_edge.content_as_object(UserAcl)
        else:
            logging.debug("do NOT have an ACL edge between the user and configuration")
            acl = UserAcl.default()

        plugin_field = saas_config_record.get_typed_field('text', 'SaaS Type')
        if plugin_field is None:
            logging.error("cannot get the plugin name from the SaaS configuration")
            return False

        plugin_name = plugin_field.value[0]

        if acl is not None and acl.rotation_settings is None:
            acl.rotation_settings = UserAclRotationSettings()

        logging.debug(f"plugin name is {plugin_name}")
        logging.debug(f"pam configuration record type is {pam_config_record_type}")

        if plugin_name == "AWS Access Key" and pam_config_record_type == "pamAwsConfiguration":
            logging.debug("pam configuration is AWS, the user belongs to the configuration")
            acl.belongs_to = True
        else:
            acl.belongs_to = False

        acl.rotation_settings.noop = True
        acl.is_iam_user = False
        acl.is_admin = False
        acl.rotation_settings.saas_record_uid_list = [saas_config_record.record_uid]

        user_vertex.belongs_to(vertex=configuration_vertex,
                               edge_type=EdgeType.ACL,
                               content=acl,
                               is_encrypted=False)

        self.linking_dag.save()

        return True

    def get_all_admins(self):
        if not self.linking_dag.has_graph:
            return []
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            return []
        admins = []
        for user_vertex in config_vertex.has_vertices(EdgeType.ACL):
            acl_edge = user_vertex.get_edge(config_vertex, EdgeType.ACL)
            if acl_edge:
                content = acl_edge.content_as_dict
                if content.get('is_admin'):
                    admins.append(user_vertex.uid)
        return admins

    def check_if_resource_has_admin(self, resource_uid):
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return False
        for user_vertex in resource_vertex.has_vertices(EdgeType.ACL):
            acl_edge = user_vertex.get_edge(resource_vertex, EdgeType.ACL)
            if acl_edge:
                content = acl_edge.content_as_dict
                if content.get('is_admin'):
                    return user_vertex.uid
        return False

    def check_if_resource_has_launch_credential(self, resource_uid):
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return False
        for user_vertex in resource_vertex.has_vertices(EdgeType.ACL):
            acl_edge = user_vertex.get_edge(resource_vertex, EdgeType.ACL)
            if acl_edge:
                content = acl_edge.content_as_dict
                if content.get('is_launch_credential'):
                    return user_vertex.uid
        return False

    def get_launch_credentials(self, resource_uid):
        """Return the list of user UIDs currently flagged is_launch_credential on the resource."""
        result = []
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return result
        for user_vertex in resource_vertex.has_vertices(EdgeType.ACL):
            acl_edge = user_vertex.get_edge(resource_vertex, EdgeType.ACL)
            if acl_edge:
                content = acl_edge.content_as_dict
                if content and content.get('is_launch_credential'):
                    result.append(user_vertex.uid)
        return result

    def clear_launch_credential_for_resource(self, resource_uid, exclude_user_uid=None):
        """Remove is_launch_credential from all users on a resource except exclude_user_uid."""
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return
        dirty = False
        for user_vertex in resource_vertex.has_vertices(EdgeType.ACL):
            if exclude_user_uid and user_vertex.uid == exclude_user_uid:
                continue
            acl_edge = user_vertex.get_edge(resource_vertex, EdgeType.ACL)
            if not acl_edge:
                continue
            edge_content = acl_edge.content_as_dict
            if edge_content and edge_content.get('is_launch_credential'):
                edge_content = dict(edge_content)
                edge_content.pop('is_launch_credential')
                user_vertex.belongs_to(resource_vertex, EdgeType.ACL, content=edge_content)
                dirty = True
        if dirty:
            self.linking_dag.save()

    def set_launch_credentials(self, resource_uid, launch_uid=None, admin_uid=None):
        """
        Set or clear the launch credential (and optionally the admin) for a resource
        via a single Layer-B configure_resource round-trip.

        krouter's connectUsers field has replacement semantics
        (UserRest.kt:generateResourceConnectionEdges): sending [launch_uid] sets
        is_launch_credential=true on that user AND clears it from every other user on
        the resource; sending [] clears it from every user. The meta field carries
        the v1 upgrade in the same call. This replaces the legacy 2-3 op sequence
        (clear + link + meta-upgrade) with one permission-checked round-trip.

        admin_uid (optional): when given, adminUid is sent in the SAME request as
        connectUsers. This is required for the admin to actually take effect on an
        ALREADY-EXISTING ACL edge: a standalone configure_resource(adminUid) with no
        connectUsers no-ops on an existing edge (UserRest.kt:331-341 only touches
        is_launch_credential), whereas adminUid alongside connectUsers flips is_admin
        on that edge (UserRest.kt:295-318). When admin and launch are different
        users, adminUid must not appear in connectUsers. When they are the same
        pamUser, krouter sets both is_admin and is_launch_credential on one edge
        (UserRest.kt:258-273).

        For a fresh launch_uid (no existing edge), krouter creates the new edge with
        belongs_to=null; a follow-up local DAG-write must set belongs_to=True AND
        preserve is_launch_credential (and is_admin when admin_uid == launch_uid).
        Writing belongs_to alone clobbers krouter flags (KC-1330). For existing
        edges where belongs_to is already true, an unchanged follow-up is a no-op.

        Fallback on RRC_NOT_ALLOWED* (or feature-disabled) with KEEPER_DAG_LB_FALLBACK
        enabled: legacy clear + link (if set) + admin link (if set) + meta-upgrade.
        """
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return

        # Version-only meta: bump to v1 (so the vault reads ACL launch credentials)
        # WITHOUT re-asserting a possibly-stale allowedSettings snapshot. See
        # build_meta_version_upgrade() — re-sending the in-memory allowedSettings
        # here would clobber connections that set_resource_allowed just enabled.
        upgraded_meta = build_meta_version_upgrade()
        uids = [url_safe_str_to_bytes(launch_uid)] if launch_uid is not None else []

        from ...pam.router_helper import router_configure_resource, get_router_url
        from ...pam._layer_b import is_layer_b_feature_disabled
        host = get_router_url(self.params)
        endpoint = 'configure_resource'
        if not is_layer_b_feature_disabled(host, endpoint):
            try:
                rq = pam_pb2.PAMResourceConfig(
                    recordUid=url_safe_str_to_bytes(resource_uid),
                    networkUid=url_safe_str_to_bytes(self.record.record_uid),
                    connectUsers=pam_pb2.UidList(uids=uids),
                    meta=json.dumps(upgraded_meta).encode(),
                )
                if admin_uid is not None:
                    rq.adminUid = url_safe_str_to_bytes(admin_uid)
                router_configure_resource(self.params, rq)
                logging.debug(
                    f"set_launch_credentials: resource={resource_uid} "
                    f"launch_uid={launch_uid} admin_uid={admin_uid} via configure_resource"
                )
                if launch_uid is not None:
                    link_kwargs = dict(belongs_to=True, is_launch_credential=True)
                    if admin_uid is not None and admin_uid == launch_uid:
                        link_kwargs['is_admin'] = True
                    self.link_user(launch_uid, resource_vertex, **link_kwargs)
                return
            except Exception as err:
                if not should_fallback_on_layer_b_error(err, host=host, endpoint=endpoint):
                    logging.error(f"configure_resource failed (no fallback): {err}", exc_info=True)
                    raise
                logging.warning(
                    f"configure_resource denied/unavailable for {resource_uid}; "
                    f"falling back to legacy DAG-write: {err}"
                )

        self.clear_launch_credential_for_resource(resource_uid, exclude_user_uid=launch_uid)
        if admin_uid is not None:
            # Legacy fallback: write is_admin directly on the resource ACL edge.
            self.link_user(admin_uid, resource_vertex, is_admin=True, belongs_to=True)
        if launch_uid is not None:
            self.link_user_to_resource(launch_uid, resource_uid,
                                       is_launch_credential=True, belongs_to=True)
        self.upgrade_resource_meta_to_v1(resource_uid)

    def upgrade_resource_meta_to_v1(self, resource_uid):
        """Ensure resource vertex meta has version >= 1 so vault reads ACL launch credentials."""
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            return
        content = get_vertex_content(resource_vertex)
        if content and content.get('version', 0) >= RESOURCE_META_VERSION_V1:
            return
        upgraded = ensure_resource_meta_v1(content)

        # Primary: Layer-B configure_resource (permission-checked). Send a
        # version-only meta — krouter deep-merges the meta edge, so an empty
        # allowedSettings bumps `version` (the `oldMetaVersion <= newMetaVersion`
        # upgrade check) while preserving the server's current flags. Re-sending
        # the in-memory `upgraded` here would clobber flags set earlier in the
        # same command (the Layer-B set_resource_allowed does not refresh the
        # in-memory vertex). See build_meta_version_upgrade().
        from ...pam.router_helper import router_configure_resource, get_router_url
        from ...pam._layer_b import is_layer_b_feature_disabled
        host = get_router_url(self.params)
        endpoint = 'configure_resource'
        if not is_layer_b_feature_disabled(host, endpoint):
            try:
                rq = pam_pb2.PAMResourceConfig(
                    recordUid=url_safe_str_to_bytes(resource_uid),
                    networkUid=url_safe_str_to_bytes(self.record.record_uid),
                    meta=json.dumps(build_meta_version_upgrade()).encode(),
                )
                router_configure_resource(self.params, rq)
                logging.debug(
                    f"upgrade_resource_meta_to_v1: applied to {resource_uid} via configure_resource"
                )
                return
            except Exception as err:
                if not should_fallback_on_layer_b_error(err, host=host, endpoint=endpoint):
                    logging.error(f"configure_resource failed (no fallback): {err}", exc_info=True)
                    raise
                logging.warning(
                    f"configure_resource denied/unavailable for {resource_uid}; "
                    f"falling back to legacy DAG-write: {err}"
                )

        # Fallback: legacy direct DAG-write.
        resource_vertex.add_data(content=upgraded, path='meta', needs_encryption=False)
        self.linking_dag.save()

    def check_if_resource_allowed(self, resource_uid, setting):
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        content = get_vertex_content(resource_vertex)
        return content.get('allowedSettings', {}).get(setting, False) if content else False

    def get_resource_setting(self, resource_uid: str, settings_name: str, setting: str) -> str:
        # Settings are tri-state (on|off|default) mapped to true|false|missing in JSON
        # When set to "default" (missing from JSON) that means look higher up the hierarchy
        # ex. rotation: user -> machine -> pam_config -> Gobal Default settings
        # Note: Different clients (even different client versions)
        # may have different view on these defaults (Commander, Web Vault, etc.)
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        content = get_vertex_content(resource_vertex)
        res = ''
        if content and isinstance(content, dict):
            if settings_name in content and isinstance(content[settings_name], dict):
                if setting in content[settings_name]:
                    value = content[settings_name][setting]
                    if isinstance(value, bool):
                        res = {True: 'on', False: 'off'}[value]
                    else:
                        res = str(value)
                else:
                    res = 'default'

        return res

    def set_resource_allowed(self, resource_uid, tunneling=None, connections=None, rotation=None,
                             session_recording=None, typescript_recording=None, remote_browser_isolation=None,
                             ai_enabled=None, ai_session_terminate=None,
                             allowed_settings_name='allowedSettings', is_config=False,
                             v_type: RefType=str(RefType.PAM_MACHINE), meta_version=None,
                             rotate_on_termination=None):
        resetting_allowed_settings = any(
            self._is_allowed_setting_default_reset(v)
            for v in (
                connections, tunneling, rotation, session_recording,
                typescript_recording, remote_browser_isolation,
                ai_enabled, ai_session_terminate,
            )
        )
        v_type = RefType(v_type)
        allowed_ref_types = [RefType.PAM_MACHINE, RefType.PAM_DATABASE, RefType.PAM_DIRECTORY, RefType.PAM_BROWSER]
        if v_type not in allowed_ref_types:
            # default to machine
            v_type = RefType.PAM_MACHINE

        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None:
            resource_vertex = self.linking_dag.add_vertex(uid=resource_uid, vertex_type=v_type)

        if resource_vertex.vertex_type not in allowed_ref_types:
            resource_vertex.vertex_type = v_type
        if is_config:
            resource_vertex.vertex_type = RefType.PAM_NETWORK
        dirty = False
        content = get_vertex_content(resource_vertex)
        if content is None:
            content = {allowed_settings_name: {}}
            dirty = True
        if allowed_settings_name not in content:
            content[allowed_settings_name] = {}
            dirty = True

        settings = content[allowed_settings_name]

        # When no value in allowedSettings: client will substitute with default
        # rotation defaults to True, everything else defaults to False

        # switching to 3-state on/off/default: on/true, off/false,
        # None = Keep existing, 'default' = Reset to default (remove from dict)
        if connections is not None:
            connections = self._convert_allowed_setting(connections)
            if connections != settings.get("connections", None):
                dirty = True
                if connections is None:
                    settings.pop("connections", None)
                else:
                    settings["connections"] = connections

        if tunneling is not None:
            tunneling = self._convert_allowed_setting(tunneling)
            if tunneling != settings.get("portForwards", None):
                dirty = True
                if tunneling is None:
                    settings.pop("portForwards", None)
                else:
                    settings["portForwards"] = tunneling

        if rotation is not None:
            rotation = self._convert_allowed_setting(rotation)
            if rotation != settings.get("rotation", None):
                dirty = True
                if rotation is None:
                    settings.pop("rotation", None)
                else:
                    settings["rotation"] = rotation

        if session_recording is not None:
            session_recording = self._convert_allowed_setting(session_recording)
            if session_recording != settings.get("sessionRecording", None):
                dirty = True
                if session_recording is None:
                    settings.pop("sessionRecording", None)
                else:
                    settings["sessionRecording"] = session_recording

        if typescript_recording is not None:
            typescript_recording = self._convert_allowed_setting(typescript_recording)
            if typescript_recording != settings.get("typescriptRecording", None):
                dirty = True
                if typescript_recording is None:
                    settings.pop("typescriptRecording", None)
                else:
                    settings["typescriptRecording"] = typescript_recording

        if remote_browser_isolation is not None:
            remote_browser_isolation = self._convert_allowed_setting(remote_browser_isolation)
            if remote_browser_isolation != settings.get("remoteBrowserIsolation", None):
                dirty = True
                if remote_browser_isolation is None:
                    settings.pop("remoteBrowserIsolation", None)
                else:
                    settings["remoteBrowserIsolation"] = remote_browser_isolation

        if ai_enabled is not None:
            ai_enabled = self._convert_allowed_setting(ai_enabled)
            if ai_enabled != settings.get("aiEnabled", None):
                dirty = True
                if ai_enabled is None:
                    settings.pop("aiEnabled", None)
                else:
                    settings["aiEnabled"] = ai_enabled

        if ai_session_terminate is not None:
            ai_session_terminate = self._convert_allowed_setting(ai_session_terminate)
            if ai_session_terminate != settings.get("aiSessionTerminate", None):
                dirty = True
                if ai_session_terminate is None:
                    settings.pop("aiSessionTerminate", None)
                else:
                    settings["aiSessionTerminate"] = ai_session_terminate

        if rotate_on_termination is not None:
            if content is None:
                content = {allowed_settings_name: {}}
                dirty = True
            current_rot = bool(content.get("rotateOnTermination", False))
            if rotate_on_termination != current_rot:
                dirty = True
                content = ensure_resource_meta_v1(dict(content))
                content["rotateOnTermination"] = bool(rotate_on_termination)

        if dirty:
            # Compute the meta payload (same shape legacy would write).
            if meta_version is not None and meta_version != 0:
                meta_payload = build_resource_meta(
                    meta_version,
                    content.get(allowed_settings_name, {}),
                    rotate_on_termination=bool(content.get("rotateOnTermination", False)),
                )
            else:
                meta_payload = content

            # Primary: Layer-B (permission-checked). is_config=True writes the
            # config record's network-level allowedSettings via configure_network_graph
            # (the same endpoint edit_tunneling_config uses). is_config=False writes
            # a resource's meta via configure_resource(meta=...); the server's
            # mergeJson handles any meta key (allowedSettings, pamRemoteBrowserSettings,
            # rotation, etc.). Same fallback policy as edit_tunneling_config and
            # link_user_to_resource: strict by default, opt INTO legacy fallback
            # via KEEPER_DAG_LB_FALLBACK=1.
            from ...pam.router_helper import (
                router_configure_resource, router_configure_network_graph, get_router_url
            )
            from ...pam._layer_b import is_layer_b_feature_disabled
            host = get_router_url(self.params)

            if not resetting_allowed_settings and is_config:
                endpoint = 'configure_network_graph'
                if not is_layer_b_feature_disabled(host, endpoint):
                    try:
                        inner_settings = meta_payload.get(allowed_settings_name, {})
                        rq = router_pb2.PAMNetworkConfigurationRequest(
                            recordUid=url_safe_str_to_bytes(resource_uid),
                            networkSettings=router_pb2.PAMNetworkSettings(
                                allowedSettings=json.dumps(inner_settings).encode()
                            ),
                        )
                        router_configure_network_graph(self.params, rq)
                        logging.debug(
                            f"set_resource_allowed: applied to config {resource_uid} via configure_network_graph"
                        )
                        return
                    except Exception as err:
                        if not should_fallback_on_layer_b_error(err, host=host, endpoint=endpoint):
                            logging.error(f"configure_network_graph failed (no fallback): {err}", exc_info=True)
                            raise
                        logging.warning(
                            f"configure_network_graph denied/unavailable for config {resource_uid}; "
                            f"falling back to legacy DAG-write: {err}"
                        )
            elif not resetting_allowed_settings:
                endpoint = 'configure_resource'
                if not is_layer_b_feature_disabled(host, endpoint):
                    try:
                        rq = pam_pb2.PAMResourceConfig(
                            recordUid=url_safe_str_to_bytes(resource_uid),
                            networkUid=url_safe_str_to_bytes(self.record.record_uid),
                            meta=json.dumps(meta_payload).encode(),
                        )
                        router_configure_resource(self.params, rq)
                        logging.debug(
                            f"set_resource_allowed: applied to resource {resource_uid} via configure_resource"
                        )
                        return
                    except Exception as err:
                        if not should_fallback_on_layer_b_error(err, host=host, endpoint=endpoint):
                            logging.error(f"configure_resource failed (no fallback): {err}", exc_info=True)
                            raise
                        logging.warning(
                            f"configure_resource denied/unavailable for resource {resource_uid}; "
                            f"falling back to legacy DAG-write: {err}"
                        )

            # Fallback: legacy direct DAG-write (also used when resetting any
            # allowedSettings key to default — krouter mergeJson never deletes
            # keys absent from a Layer-B payload).
            if meta_version is not None and meta_version != 0:
                resource_vertex.add_data(content=meta_payload, path='meta', needs_encryption=False)
            else:
                resource_vertex.add_data(content=content, path='meta', needs_encryption=False)
            self.linking_dag.save()

    def is_tunneling_config_set_up(self, resource_uid):
        if not self.linking_dag.has_graph:
            return False
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        return resource_vertex and config_vertex and config_vertex in resource_vertex.belongs_to_vertices()

    def remove_from_dag(self, uid):
        if not self.linking_dag.has_graph:
            return True

        vertex = self.linking_dag.get_vertex(uid)
        if vertex is None:
            return True

        vertex.delete()
        self.linking_dag.save(confirm=True)
        return None

    def print_tunneling_config(self, record_uid, pam_settings=None, config_uid=None):
        if not pam_settings and not config_uid:
            return
        self.linking_dag.load()
        vertex = self.linking_dag.get_vertex(record_uid)
        content = get_vertex_content(vertex)
        config_id = config_uid if config_uid else pam_settings.value[0].get('configUid') if pam_settings else None
        if content and content.get('allowedSettings'):
            allowed_settings = content['allowedSettings']
            print(f"{bcolors.OKGREEN}Settings configured for {record_uid}{bcolors.ENDC}")
            port_forwarding = f"{bcolors.OKBLUE}Enabled" if allowed_settings.get('portForwards') else \
                f"{bcolors.WARNING}Disabled"
            rotation = f"{bcolors.WARNING}Disabled" if (allowed_settings.get('rotation') and not allowed_settings['rotation']) else f"{bcolors.OKBLUE}Enabled"
            print(f"{bcolors.OKGREEN}\tRotation: {rotation}{bcolors.ENDC}")
            print(f"{bcolors.OKGREEN}\tTunneling: {port_forwarding}{bcolors.ENDC}")
            ai_enabled = f"{bcolors.OKBLUE}Enabled" if allowed_settings.get('aiEnabled') else \
                f"{bcolors.WARNING}Disabled"
            ai_terminate = f"{bcolors.OKBLUE}Enabled" if allowed_settings.get('aiSessionTerminate') else \
                f"{bcolors.WARNING}Disabled"
            print(f"{bcolors.OKGREEN}\tAI threat detection: {ai_enabled}{bcolors.ENDC}")
            print(f"{bcolors.OKGREEN}\tAI terminate session on detection: {ai_terminate}{bcolors.ENDC}")

            print(f"{bcolors.OKGREEN}Configuration: {config_id} {bcolors.ENDC}")
            if config_id is not None:
                config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
                config_content = get_vertex_content(config_vertex)
                if config_content and config_content.get('allowedSettings'):
                    config_allowed_settings = config_content['allowedSettings']
                    config_port_forwarding = f"{bcolors.OKBLUE}Enabled" if (
                        config_allowed_settings.get('portForwards')) else \
                        f"{bcolors.WARNING}Disabled"
                    config_rotation = f"{bcolors.WARNING}Disabled" if (config_allowed_settings.get('rotation') and
                                                                       not config_allowed_settings['rotation']) else \
                        f"{bcolors.OKBLUE}Enabled"
                    print(f"{bcolors.OKGREEN}\tRotation: {config_rotation}{bcolors.ENDC}")
                    print(f"{bcolors.OKGREEN}\tTunneling: {config_port_forwarding}{bcolors.ENDC}")
                    config_ai_enabled = f"{bcolors.OKBLUE}Enabled" if config_allowed_settings.get('aiEnabled') else \
                        f"{bcolors.WARNING}Disabled"
                    config_ai_terminate = f"{bcolors.OKBLUE}Enabled" if config_allowed_settings.get('aiSessionTerminate') else \
                        f"{bcolors.WARNING}Disabled"
                    print(f"{bcolors.OKGREEN}\tAI threat detection: {config_ai_enabled}{bcolors.ENDC}")
                    print(f"{bcolors.OKGREEN}\tAI terminate session on detection: {config_ai_terminate}{bcolors.ENDC}")