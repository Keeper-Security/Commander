from __future__ import annotations
from .constants import VERTICES_SORT_MAP
from .types import DiscoveryObject
import logging
import functools
import re
from typing import List, Optional, Union, TYPE_CHECKING

Logger = Union[logging.RootLogger, logging.Logger]
if TYPE_CHECKING:
    from ..keeper_dag.vertex import DAGVertex


def sort_infra_name(vertices: List[DAGVertex]) -> List[DAGVertex]:
    """
    Sort the vertices by name in ascending order.
    """

    def _sort(t1: DAGVertex, t2: DAGVertex):
        t1_name = t1.content_as_dict.get("name")
        t2_name = t2.content_as_dict.get("name")
        if t1_name < t2_name:
            return -1
        elif t1_name > t2_name:
            return 1
        else:
            return 0

    return sorted(vertices, key=functools.cmp_to_key(_sort))


def sort_infra_host(vertices: List[DAGVertex]) -> List[DAGVertex]:
    """
    Sort the vertices by host name.

    Host name should appear first in ascending order.
    IP should appear second in ascending order.

    """

    def _is_ip(host: str) -> bool:
        if re.match(r'^\d+\.\d+\.\d+\.\d+', host) is not None:
            return True
        return False

    def _make_ip_number(ip: str) -> int:
        ip_port = ip.split(":")
        parts = ip_port[0].split(".")
        value = ""
        for part in parts:
            value += part.zfill(3)
        return int(value)

    def _sort(t1: DAGVertex, t2: DAGVertex):
        t1_name = t1.content_as_dict.get("name")
        t2_name = t2.content_as_dict.get("name")

        # Both names are ip addresses
        if _is_ip(t1_name) and _is_ip(t2_name):
            t1_num = _make_ip_number(t1_name)
            t2_num = _make_ip_number(t2_name)

            if t1_num < t2_num:
                return -1
            elif t1_num > t2_num:
                return 1
            else:
                return 0

        # T1 is an IP, T2 is a host name
        elif _is_ip(t1_name) and not _is_ip(t2_name):
            return 1
        # T2 is not an IP and T2 is an IP
        elif not _is_ip(t1_name) and _is_ip(t2_name):
            return -1
        # T1 and T2 are host name
        else:
            if t1_name < t2_name:
                return -1
            elif t1_name > t2_name:
                return 1
            else:
                return 0

    return sorted(vertices, key=functools.cmp_to_key(_sort))


def sort_infra_vertices(current_vertex: DAGVertex, logger: Optional[Logger] = None) -> dict:

    if logger is None:
        logger = logging.getLogger()

    # Make a map, record type to list of vertices (of that record type)
    record_type_to_vertices_map = {k: [] for k, v in VERTICES_SORT_MAP.items()}

    # Collate the vertices into a record type lookup.
    vertices = current_vertex.has_vertices()
    logger.debug(f"  found {len(vertices)} vertices")
    for vertex in vertices:
        if vertex.active is True:
            content = DiscoveryObject.get_discovery_object(vertex)
            logger.debug(f"  * {content.description}")
    for vertex in vertices:
        if vertex.active is False:
            logger.debug("  vertex is not active")
            continue
        # We can't load into a pydantic object since Pydantic has a problem with Union type.
        # We only want the record type, so it is too much work to try to get into an object.
        content_dict = vertex.content_as_dict
        record_type = content_dict.get("record_type")
        if record_type in record_type_to_vertices_map:
            record_type_to_vertices_map[record_type].append(vertex)

    # Sort the vertices for each record type.
    for k, v in VERTICES_SORT_MAP.items():
        if v["sort"] == "sort_infra_name":
            record_type_to_vertices_map[k] = sort_infra_name(record_type_to_vertices_map[k])
        elif v["sort"] == "sort_infra_host":
            record_type_to_vertices_map[k] = sort_infra_host(record_type_to_vertices_map[k])

    return record_type_to_vertices_map
