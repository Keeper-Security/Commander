from __future__ import annotations
import json
from ..pam.router_helper import router_send_action_to_gateway
from ..pam.pam_dto import GatewayAction
from ..pam.router_helper import get_response_payload
from ...proto import pam_pb2
from ...display import bcolors
from ... import vault
from ...discovery_common.record_link import RecordLink
from ... import utils
import logging
import hmac
import hashlib
import os
from pydantic import BaseModel
from typing import Optional, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..discover import GatewayContext
    from ...params import KeeperParams
    from ...vault import TypedRecord
    from ...keeper_dag.vertex import DAGVertex


CATALOG_REPO = "Keeper-Security/discovery-and-rotation-saas-dev"


class GatewayActionSaasListCommandInputs:

    def __init__(self,
                 configuration_uid: str,
                 languages: Optional[List[str]] = None):

        if languages is None:
            languages = ["en_US"]

        self.configurationUid = configuration_uid
        self.languages = languages

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


class GatewayActionSaasListCommand(GatewayAction):

    def __init__(self, inputs: GatewayActionSaasListCommandInputs, conversation_id=None):
        super().__init__('saas-list', inputs=inputs, conversation_id=conversation_id, is_scheduled=True)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)


# These are from KDNRM saas_type.py
class SaasConfigEnum(BaseModel):
    value: str
    desc: Optional[str] = None
    code: Optional[str] = None


class SaasConfigItem(BaseModel):
    id: str
    label: str
    desc: str
    is_secret: bool = False
    desc_code: Optional[str] = None
    type: Optional[str] = "text"
    code: Optional[str] = None
    default_value: Optional[Any] = None
    enum_values: List[SaasConfigEnum] = []
    required: bool = False


class SaasPluginUsage(BaseModel):
    record_id: str
    plugin_name: str
    user_uids: List[str] = []


class SaasCatalog(BaseModel):
    name: str
    type: str = "catalog"
    author: Optional[str] = None
    email: Optional[str] = None
    summary: Optional[str] = None
    file: Optional[str] = None
    file_sig: Optional[str] = None
    allows_remote_management: Optional[bool] = False
    readme: Optional[str] = None
    fields: List[SaasConfigItem] = []
    installed: bool = False
    used_by: List[SaasPluginUsage] = []

    @property
    def file_name(self):
        return self.file.split(os.sep)[-1] if self.file else None


def get_gateway_saas_schema(params: KeeperParams, gateway_context: GatewayContext) -> Optional[List[dict]]:

    """
    Get a plugins list from the Gateway.

    Using the plugins from the Gateway handles problem with versions.
    We can work off the builtin, and custom, plugins available to the version of the Gateway.
    """

    if gateway_context is None:
        print(f"{bcolors.FAIL}The user record does not have the set gateway{bcolors.ENDC}")
        return None

    # Get schema information from the Gateway
    action_inputs = GatewayActionSaasListCommandInputs(
        configuration_uid=gateway_context.configuration_uid,
    )

    conversation_id = GatewayAction.generate_conversation_id()
    router_response = router_send_action_to_gateway(
        params=params,
        gateway_action=GatewayActionSaasListCommand(
            inputs=action_inputs,
            conversation_id=conversation_id),
        message_type=pam_pb2.CMT_GENERAL,
        is_streaming=False,
        destination_gateway_uid_str=gateway_context.gateway_uid
    )

    if router_response is None:
        print(f"{bcolors.FAIL}Did not get router response.{bcolors.ENDC}")
        return None

    response = router_response.get("response")
    logging.debug(f"Router Response: {response}")
    payload = get_response_payload(router_response)
    data = payload.get("data")
    if data is None:
        raise Exception("The router returned a failure.")
    elif data.get("success") is False:
        error = data.get("error")
        logging.debug(f"gateway returned: {error}")
        print(f"{bcolors.FAIL}Could not get a list of SaaS plugins available on the gateway.{bcolors.ENDC}")
        return None

    return data.get("data", [])


def find_user_saas_configurations(params: KeeperParams, gateway_context: GatewayContext) -> dict:

    """
    Find all the SaaS configuration being uses by a gateway.



    """

    record_linking = RecordLink(record=gateway_context.configuration,  params=params, logger=logging)

    def _walk_graph(v: DAGVertex, m: dict, pv: Optional[DAGVertex] = None):

        # Skip any disabled vertices
        if not v.active:
            return

        # Get the record for this vertex; skip is not a pamUser.
        record = vault.TypedRecord.load(params, v.uid)
        if record is not None and record.record_type == "pamUser" and pv is not None:
            acl = record_linking.get_acl(v.uid, pv.uid)
            if acl is not None and acl.rotation_settings is not None:
                config_record_uid_list = acl.rotation_settings.saas_record_uid_list
                if config_record_uid_list is not None:
                    for config_record_uid in config_record_uid_list:

                        if config_record_uid not in m:
                            config_record = vault.TypedRecord.load(params,
                                                                   config_record_uid)  # type: Optional[TypedRecord]
                            if config_record is None:
                                continue

                            plugin_name = next((f.value for f in config_record.custom if f.label == "SaaS Type"),
                                               None)
                            if plugin_name is None:
                                continue

                            m[config_record_uid] = SaasPluginUsage(
                                record_id=config_record_uid,
                                plugin_name=plugin_name[0]
                            )  # type: SaasPluginUsage

                        m[config_record_uid].user_uids.append(v.uid)

        for next_v in v.has_vertices():
            _walk_graph(
                v=next_v,
                pv=v,
                m=m
            )

    usage_map = {}
    _walk_graph(
        v=record_linking.dag.get_root,
        m=usage_map)

    return usage_map


def get_plugins_map(params: KeeperParams, gateway_context: GatewayContext) -> Optional[dict[str, SaasCatalog]]:

    """
    Get a map of all the available plugins.

    This will first get the latest catalog from the GitHub repo.
    The catalog will contain the plugin available from the repo and built in.

    Then the Gateway is checked for custom plugin; plugins outside our control.

    The result is a dictionary, with the plugin name as the key.

    """

    plugin_map = {}

    # #### GATEWAY PLUGINS

    # Get a list of installed plugins (custom and builtin) from the Gateway
    gateway_plugins = get_gateway_saas_schema(params, gateway_context)
    if gateway_plugins is None:
        return None

    # Add the Gateway plugins to map; all these plugins are installed.
    for plugin_dict in gateway_plugins:
        plugin = SaasCatalog.model_validate(plugin_dict)  # type: SaasCatalog
        plugin.installed = True
        plugin_map[plugin.name] = plugin

    # #### CATALOG PLUGINS

    # Get the latest release of the catalog.json
    api_url = f"https://api.github.com/repos/{CATALOG_REPO}/releases/latest"
    res = utils.ssl_aware_get(api_url)
    if res.ok is False:
        print("")
        print(f"{bcolors.FAIL}Could not get plugin catalog from GitHub.{bcolors.ENDC}")
        return None
    release_data = res.json()

    # Find the latest release URL
    assets = release_data.get("assets", [])
    asset = assets[0]
    download_url = asset["browser_download_url"]
    logging.debug(f"download {asset['name']} from {download_url}")

    # Download the latest the catalog.yml
    res = utils.ssl_aware_get(download_url)
    if res.ok is False:
        print("")
        print(f"{bcolors.FAIL}Could not download the plugin catalog from GitHub.{bcolors.ENDC}")
        return None

    # Get a mapping of all the plugins being used by the plugin name.
    # The group usage by plugin name; we can have multiple configuration for the same plugin
    # This return dictionary of config record UID to SaasPluginUsage
    plugin_usage = find_user_saas_configurations(params, gateway_context)
    plugin_usage_map = {}
    for config_record_uid in plugin_usage:  # type: str
        plugin_name = plugin_usage[config_record_uid].plugin_name
        if plugin_name not in plugin_usage_map:
            plugin_usage_map[plugin_name] = []
        plugin_usage_map[plugin_name].append(plugin_usage[config_record_uid])

    for plugin_dict in json.loads(res.content):  # type: dict
        if plugin_dict.get("type") == "builtin":
            continue

        plugin = SaasCatalog.model_validate(plugin_dict)  # type: SaasCatalog
        if plugin.name in plugin_map:
            logging.debug(f"found duplicate plugin {plugin.name}; using plugin from gateway.")
            continue
        plugin_map[plugin.name] = plugin

    return plugin_map


def make_script_signature(plugin_code_bytes: bytes) -> str:

    # To use HMAC, we need to have a key; the key is not a secret, we just want to make a unique digest.
    this_is_not_a_secret = b"NOT_IMPORTANT"
    return hmac.new(this_is_not_a_secret, plugin_code_bytes, hashlib.sha256).hexdigest()


def get_field_input(field, current_value: Optional[str] = None):

    logging.debug(field.model_dump_json())

    print(f"{bcolors.BOLD}{field.label}{bcolors.ENDC}")
    print(f"Description: {field.desc}")
    if field.required is True:
        print(f"{bcolors.WARNING}Field is required.{bcolors.ENDC}")
    if field.type == "multiline":
        print(f"Enter a file path to load value from file.")

    while True:
        prompt = "Enter value"
        extra_text = []
        valid_values = []
        if len(field.enum_values) > 0:
            valid_values = [str(x.value) for x in field.enum_values]
            extra_text.append(f"Allowed values: {bcolors.BOLD}" +
                              f"{bcolors.ENDC}, {bcolors.BOLD}".join(valid_values) + bcolors.ENDC)
        if current_value is not None:
            extra_text.append(f"Enter for current value '{bcolors.OKGREEN}{current_value}{bcolors.ENDC}'")
        if field.default_value is not None:
            extra_text.append(f"Enter for default value '{bcolors.OKBLUE}{field.default_value}{bcolors.ENDC}'")
        if len(extra_text) > 0:
            prompt += f" (" + "; ".join(extra_text) + ")"
        prompt += " > "
        value = input(prompt)
        if value == "":
            if current_value is not None:
                value = current_value
            elif field.default_value is not None:
                value = field.default_value
        elif os.path.exists(value):
            with open(value, "r") as fh:
                value = fh.read()
                fh.close()
        if len(valid_values) > 0 and value not in valid_values:
            print(f"{bcolors.FAIL}{value} is not a valid value.{bcolors.ENDC}")
            continue
        if value is not None:
            break
        if field.required is False:
            break

        print(f"{bcolors.FAIL}This field is required.{bcolors.ENDC}")

    return [value]


def get_record_field_value(record: TypedRecord, label: str) -> Optional[str]:

    field = next((f for f in record.custom if f.label == label), None)
    if field is None or field.value is None or len(field.value) == 0 or field.value[0] is None or field.value[0] == "":
        return None
    return field.value[0]


def set_record_field_value(record: TypedRecord, label: str, value: str, field_type: Optional[str] = "text"):

    if value is not None and isinstance(value, list):
        value = value[0]

    field = next((f for f in record.custom if f.label == label), None)
    if field is None or field.value is None or len(field.value) == 0 or field.value[0] is None or field.value[0] == "":
        if value is not None:
            record.custom.append(
                vault.TypedField.new_field(
                    field_label=label,
                    field_type=field_type,
                    field_value=[value]
                )
            )
    elif value is not None:
        field.value = [value]
    else:
        field.value = []
