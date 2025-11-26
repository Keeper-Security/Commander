from ....commands.tunnel.port_forward.tunnel_helpers import generate_random_bytes, get_config_uid
from ....keeper_dag import DAG, EdgeType
from ....keeper_dag.connection.commander import Connection
from ....keeper_dag.types import RefType, PamEndpoints
from ....keeper_dag.vertex import DAGVertex
from ....display import bcolors
from ....vault import PasswordRecord


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


class TunnelDAG:
    def __init__(self, params, encrypted_session_token, encrypted_transmission_key, record_uid: str, is_config=False):
        config_uid = None
        if not is_config:
            config_uid = get_config_uid(params, encrypted_session_token, encrypted_transmission_key, record_uid)
        if not config_uid:
            config_uid = record_uid
        self.record = PasswordRecord()
        self.record.record_uid = config_uid
        self.record.record_key = generate_random_bytes(32)
        self.encrypted_session_token = encrypted_session_token
        self.encrypted_transmission_key = encrypted_transmission_key
        self.conn = Connection(params=params, encrypted_transmission_key=self.encrypted_transmission_key,
                               encrypted_session_token=self.encrypted_session_token,
                               use_write_protobuf=True
                               )
        self.linking_dag = DAG(conn=self.conn, record=self.record, graph_id=0, write_endpoint=PamEndpoints.PAM)
        try:
            self.linking_dag.load()
        except Exception as e:
            import logging
            logging.debug(f"Error loading config: {e}")

    def resource_belongs_to_config(self, resource_uid):
        if not self.linking_dag.has_graph:
            return False
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        return resource_vertex and config_vertex.has(resource_vertex, EdgeType.LINK)

    def user_belongs_to_config(self, user_uid):
        if not self.linking_dag.has_graph:
            return False
        user_vertex = self.linking_dag.get_vertex(user_uid)
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
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

    def edit_tunneling_config(self, connections=None, tunneling=None,
                              rotation=None, session_recording=None,
                              typescript_recording=None,
                              remote_browser_isolation=None):
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

        if dirty:
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
        self.link_user(user_uid, config_vertex, belongs_to=True, is_iam_user=True)

    def link_user_to_config_with_options(self, user_uid, is_admin=None, belongs_to=None, is_iam_user=None):
        config_vertex = self.linking_dag.get_vertex(self.record.record_uid)
        if config_vertex is None:
            config_vertex = self.linking_dag.add_vertex(uid=self.record.record_uid)

        # self.link_user(user_uid, config_vertex, is_admin, belongs_to, is_iam_user)
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

    def link_user_to_resource(self, user_uid, resource_uid, is_admin=None, belongs_to=None):
        resource_vertex = self.linking_dag.get_vertex(resource_uid)
        if resource_vertex is None or not self.resource_belongs_to_config(resource_uid):
            print(f"{bcolors.FAIL}Resource {resource_uid} does not belong to the configuration{bcolors.ENDC}")
            return False
        self.link_user(user_uid, resource_vertex, is_admin, belongs_to)
        return None

    def link_user(self, user_uid, source_vertex: DAGVertex, is_admin=None, belongs_to=None, is_iam_user=None):

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
                             allowed_settings_name='allowedSettings', is_config=False,
                             v_type: RefType=str(RefType.PAM_MACHINE)):
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

        if dirty:
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