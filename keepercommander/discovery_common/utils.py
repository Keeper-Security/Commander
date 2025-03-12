from __future__ import annotations
import os
from .constants import PAM_USER
from .types import DiscoveryObject
from keepercommander.keeper_dag.vertex import DAGVertex
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from keepercommander.keeper_dag.dag import DAG


def value_to_boolean(value):
    value = str(value)
    if value.lower() in ['true', 'yes', 'on', '1']:
        return True
    elif value.lower() in ['false', 'no', 'off', '0']:
        return False
    else:
        return None


def get_connection(**kwargs):

    """
    This method will return the proper connection based on the params passed in.

    If `ksm` and a KDNRM KSM instance, it will connect using keeper secret manager.
    If `params` and a KeeperParam instance, it will connect using Commander.
    If the env var `USE_LOCAL_DAG` is True, it will connect using the Local test DAG engine.

    It returns a child instance of the Connection class.
    """

    if value_to_boolean(os.environ.get("USE_LOCAL_DAG")) is True:
        from keepercommander.keeper_dag.connection.local import Connection
        conn = Connection()
    else:
        ksm = kwargs.get("ksm")
        params = kwargs.get("params")
        if ksm is not None:
            from keepercommander.keeper_dag.connection.ksm import Connection
            conn = Connection(config=ksm.storage_config)
        elif params is not None:
            from keepercommander.keeper_dag.connection.commander import Connection
            conn = Connection(params=params)
        else:
            raise ValueError("Must pass 'ksm' for KSK, 'params' for Commander. Found neither.")
    return conn


def split_user_and_domain(user: str) -> (Optional[str], Optional[str]):

    if user is None:
        return None, None

    domain = None

    if "\\" in user:
        user_parts = user.split("\\", maxsplit=1)
        user = user_parts[0]
        domain = user_parts[1]
    elif "@" in user:
        user_parts = user.split("@")
        domain = user_parts.pop()
        user = "@".join(user_parts)

    return user, domain


def user_check_list(user: str, name: Optional[str] = None, source: Optional[str] = None) -> List[str]:
    user, domain = split_user_and_domain(user)
    user = user.lower()
    check_list = [user, f".\\{user}", ]
    if name is not None:
        name = name.lower()
        check_list += [name, f".\\{name}"]
    if source is not None:
        check_list.append(f"{source.lower()}\\{user}")
        domain_parts = source.split(".")
        if len(domain_parts) > 1:
            check_list.append(f"{domain_parts[0]}\\{user}")
    if domain is not None:
        domain = domain.lower()
        check_list.append(f"{domain}\\{user}")
        domain_parts = domain.split(".")
        if len(domain_parts) > 1:
            check_list.append(f"{domain_parts[0]}\\{user}")

    return check_list


def user_in_lookup(user: str, lookup: dict, name: Optional[str] = None, source: Optional[str] = None) -> bool:

    for check_user in user_check_list(user, name, source):
        if check_user in lookup:
            return True
    return False



def find_user_vertex(graph: DAG, user: str, domain: Optional[str] = None) -> Optional[DAGVertex]:

    user_vertices = graph.search_content({"record_type": PAM_USER})
    for user_vertex in user_vertices:

        # Make sure the vertex is active, and has content data
        if user_vertex.active is False or user_vertex.has_data is False:
            continue
        content = DiscoveryObject.get_discovery_object(user_vertex)

        current_user, current_domain = split_user_and_domain(content.item.user)

        # If we are want a directory user and the current user is not one, or does not match the domain, then skip
        if domain is not None and (current_domain is None or domain.lower() != current_domain.lower()):
            continue

        if current_user.lower() == user.lower():
            return user_vertex

    return None
