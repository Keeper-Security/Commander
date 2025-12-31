from __future__ import annotations
import os
from .constants import PAM_USER
from .types import DiscoveryObject
from ..keeper_dag.vertex import DAGVertex
from .__version__ import __version__
from typing import List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ..keeper_dag.dag import DAG


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

    # if the connection is passed in, return it.
    if kwargs.get("connection") is not None:
        return kwargs.get("connection")

    ksm = kwargs.get("ksm")
    params = kwargs.get("params")
    logger = kwargs.get("logger")
    if value_to_boolean(os.environ.get("USE_LOCAL_DAG")):
        from ..keeper_dag.connection.local import Connection
        conn = Connection(logger=logger)
    else:
        use_read_protobuf = kwargs.get("use_read_protobuf")
        use_write_protobuf = kwargs.get("use_write_protobuf")

        if ksm is not None:
            from ..keeper_dag.connection.ksm import Connection
            conn = Connection(config=ksm.storage_config,
                              logger=logger,
                              use_read_protobuf=use_read_protobuf,
                              use_write_protobuf=use_write_protobuf)
        elif params is not None:
            from ..keeper_dag.connection.commander import Connection
            conn = Connection(params=params,
                              logger=logger,
                              use_read_protobuf=use_read_protobuf,
                              use_write_protobuf=use_write_protobuf)
        else:
            raise ValueError("Must pass 'ksm' for KSM, 'params' for Commander. Found neither.")
    return conn


def split_user_and_domain(user: str) -> Tuple[Optional[str], Optional[str]]:

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

    # TODO: Add boolean for tasks to include `local users` patterns.
    #       It appears that for task lists, directory users do not have domains.
    #       A problem could arise where the customer uses a local user and directory with the same name.
    check_list = [user, f".\\{user}"]
    if name is not None:
        name = name.lower()
        check_list += [name, f".\\{name}"]
    if source is not None:
        source = source.lower()
        check_list.append(f"{source[:15]}\\{user}")
        check_list.append(f"{user}@{source}")
        netbios_parts = source.split(".")
        if len(netbios_parts) > 1:
            check_list.append(f"{netbios_parts[0][:15]}\\{user}")
            check_list.append(f"{user}@{netbios_parts[0]}")
    if domain is not None:
        domain = domain.lower()
        check_list.append(f"{domain[:15]}\\{user}")
        check_list.append(f"{user}@{domain}")
        domain_parts = domain.split(".")
        if len(domain_parts) > 1:
            check_list.append(f"{domain_parts[0][:15]}\\{user}")
            check_list.append(f"{user}@{domain_parts[0]}")

    return list(set(check_list))


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


def make_agent(text) -> str:
    return f"{text}/{__version__}"
