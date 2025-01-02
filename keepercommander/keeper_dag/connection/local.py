from . import ConnectionBase
import logging
from ..types import DataPayload, SyncData, EdgeType
import json
import os
from tabulate import tabulate

try:
    import sqlite3
    from contextlib import closing
except ImportError:
    raise Exception("Please install the sqlite3 module to use the Local connection.")

from typing import Optional, Union, Any, TYPE_CHECKING
if TYPE_CHECKING:
    Logger = Union[logging.RootLogger, logging.Logger]


class Connection(ConnectionBase):

    """
    BIG TIME NOTE

    This is a fake DAG engine used for unit tests.
    It tries best to emulate krouter/workflow.
    This is no substitute for testing against a krouter instance.
    """

    DB_FILE = "local_dag.db"
    DEBUG = 0

    def __init__(self, limit: int = 100, db_file: Optional[str] = None, db_dir:  Optional[str] = None,
                 logger: Optional[Any] = None):

        super().__init__(is_device=True, logger=logger)

        if db_file is None:
            db_file = os.environ.get("LOCAL_DAG_DB_FILE", Connection.DB_FILE)
        if db_dir is None:
            db_dir = os.environ.get("LOCAL_DAG_DIR", os.environ.get("HOME", os.environ.get("USERPROFILE", "./")))

        self.db_file = os.path.join(db_dir, db_file)
        self.limit = limit

        self.create_database()

    def debug(self, msg):
        if Connection.DEBUG == 1:
            logging.debug(f"DAG: {msg}")

    @staticmethod
    def get_record_uid(record: object) -> bytes:
        if hasattr(record, "record_uid") is True:
            return getattr(record, "record_uid")
        elif hasattr(record, "uid") is True:
            return getattr(record, "uid")
        raise Exception(f"Cannot find the record uid in object type: {type(record)}.")

    @staticmethod
    def get_key_bytes(record: object) -> bytes:
        if hasattr(record, "record_key_bytes") is True:
            return getattr(record, "record_key_bytes")
        elif hasattr(record, "record_key") is True:
            return getattr(record, "record_key")
        raise Exception("Cannot find the record key bytes in object.")

    def clear_database(self):
        try:
            os.unlink(self.db_file)
        except (Exception,):
            pass

    def create_database(self):

        self.debug("create local dag database")

        with closing(sqlite3.connect(self.db_file))as connection:
            with closing(connection.cursor()) as cursor:

                # This is based on workflow, Database.kt.
                # The UIDs are stored a character instead of bytes to make them more readable for debugging.

                # The 'type' columns are stored a TEXT.
                # This is because the WS wants text for the enum, but stores
                # it as an INTEGER.
                # We are just going to store it as a TEXT and avoid the middle man.

                cursor.execute(
                    """
CREATE TABLE IF NOT EXISTS dag_edges (
    graph_id INTEGER NOT NULL DEFAULT 0,
    edge_id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,
    head CHARACTER(22) NOT NULL,
    tail CHARACTER(22) NOT NULL,
    data BLOB,
    origin CHARACTER(22),
    path TEXT,
    created timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    creator_id BLOB(16) DEFAULT NULL,
    creator_type INTEGER DEFAULT NULL,
    creator_name TEXT DEFAULT NULL,
    FOREIGN KEY(head) REFERENCES dag_vertices(vertex_id),
    FOREIGN KEY(tail) REFERENCES dag_vertices(vertex_id)
)
                    """
                )

                cursor.execute(
                    """
CREATE TABLE IF NOT EXISTS dag_vertices (
    vertex_id CHARACTER(22) NOT NULL,
    type TEXT NOT NULL,
    name TEXT,
    owner_id BLOB(16) DEFAULT NULL
)
                    """
                )

                cursor.execute(
                    """
CREATE TABLE IF NOT EXISTS dag_streams (
    graph_id INTEGER NOT NULL,
    sync_point INTEGER PRIMARY KEY AUTOINCREMENT,
    vertex_id CHARACTER(22) NOT NULL,
    edge_id INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    deletion INTEGER NOT NULL DEFAULT 0,
    UNIQUE(vertex_id,edge_id),
    FOREIGN KEY(vertex_id) REFERENCES dag_vertices(vertex_id),
    FOREIGN KEY(edge_id) REFERENCES dag_edges(edge_id)
)
                    """
                )
                connection.commit()

        os.chmod(self.db_file, 0o777)

    @staticmethod
    def _payload_to_json(payload: Union[DataPayload, str]) -> str:

        # if payload is DataPayload
        if isinstance(payload, DataPayload):
            payload_data = payload.model_dump_json()
        elif isinstance(payload, str):
            payload_data = payload

            # make sure it is a valid json and raise and exception if not. make an exception for the case of a string
            # that is a valid json
            if not payload_data.startswith('{') and not payload_data.endswith('}'):
                raise Exception(f'Invalid payload: {payload_data}')

            # double check if it is a valid json inside the string
            json.loads(payload_data)
        else:
            raise Exception(f'Unsupported payload type: {type(payload)}')

        return json.loads(payload_data)

    def _find_stream_id(self, payload: DataPayload):

        data = Connection._payload_to_json(payload)

        # Find the vertex that does not belong to any other vertex.
        # This is normally root for a full DAG, but will be a vertex if adding additional edges.
        # 100% sure this could be written better.
        # 1000% sure this could be written better.
        # TODO: Only refs that are type PAM_NETWORK or PAM_USER can contain the stream id.
        #  Change code to ignore all other ref types.

        self.debug("finding stream id")

        # First check if we can route with existing edges in the database.
        stream_id = None
        with closing(sqlite3.connect(self.db_file)) as connection:
            with closing(connection.cursor()) as cursor:

                graph_id = data.get("graphId")

                stream_ids = {}

                runs = 0
                for item in data.get("dataList"):

                    # Get the head UID of the edge and then find an edge where the UID is the tail.
                    # If we find an edge, use its head to find an edge where the UID is the tail.
                    # Repeat until we can't find and edge, that is a stream ID
                    # Tally all the stream ID and take the best.
                    item_stream_id = item.get("ref")["value"]
                    current_stream_id = item_stream_id
                    while True:
                        self.debug(f"    check stream id {current_stream_id}")
                        sql = "SELECT head, edge_id FROM dag_edges WHERE tail=? AND graph_id=? AND type != ?"
                        res = cursor.execute(sql, (current_stream_id, graph_id, EdgeType.DATA.value))
                        row = res.fetchone()
                        if row is None:
                            self.debug(f"    no edge found")
                            if current_stream_id == item_stream_id:
                                current_stream_id = None
                            break
                        current_stream_id = row[0]
                        self.debug(f"      got {current_stream_id}")

                    if current_stream_id is not None:
                        if item_stream_id not in stream_ids:
                            stream_ids[current_stream_id] = 0
                        stream_ids[current_stream_id] += 1
                    else:
                        # If we didn't find anything with the tail, check starting with the head.
                        item_stream_id = item.get("parentRef")["value"]
                        current_stream_id = item_stream_id
                        while True:
                            self.debug(f"    check stream id {current_stream_id}")
                            sql = "SELECT head, edge_id FROM dag_edges WHERE tail=? AND graph_id=? AND type != ?"
                            res = cursor.execute(sql, (current_stream_id, graph_id, EdgeType.DATA.value))
                            row = res.fetchone()
                            if row is None:
                                self.debug(f"    no edge found")
                                if current_stream_id == item_stream_id:
                                    current_stream_id = None
                                break
                            current_stream_id = row[0]
                            self.debug(f"      got {current_stream_id}")

                        if current_stream_id is not None:
                            if item_stream_id not in stream_ids:
                                stream_ids[current_stream_id] = 0
                            stream_ids[current_stream_id] += 1

                    # Until we rewrite this, exit after we check 3 edges.
                    # This will slow down after a bunch of edges are added.
                    # We also fixed stuff in our code to prevent the errors we were seeing.
                    # Might want to switch to recursion.
                    # https://www.sqlite.org/lang_with.html
                    if runs > 3:
                        break
                    runs += 1

                if len(stream_ids) > 0:
                    sorted_stream_ids = [k for k, v in sorted(stream_ids.items(), key=lambda item: item[1])]
                    stream_id = sorted_stream_ids.pop()

        # If the stream id is None, this is the first save of the DAG.
        # No edges existed.
        # Compare the data list items.
        # The one without an edge with a tail if the stream id.
        if stream_id is None:
            self.debug("stream id None, edges might be new")
            # Get a starting spot
            found = {}
            for item in data.get("dataList"):
                head_uid = item.get("parentRef")["value"]
                found[head_uid] = True
            for item in data.get("dataList"):
                tail_uid = item.get("ref")["value"]
                found.pop(tail_uid, None)
            stream_ids = [uid for uid in found]
            if len(stream_ids) > 0:
                stream_id = stream_ids[0]

        # If we can't find stream ID, assume it's on the first item in the dataList
        if stream_id is None:
            item = data.get("dataList")[0]
            stream_id = item.get("parentRef")["value"] or  item.get("ref")["value"]

        return stream_id

    def add_data(self, payload: DataPayload):

        stream_id = self._find_stream_id(payload)
        self.debug(f"STREAM ID IS {stream_id}")

        data = Connection._payload_to_json(payload)

        with closing(sqlite3.connect(self.db_file)) as connection:
            with closing(connection.cursor()) as cursor:

                origin_id = data.get("origin")["value"]
                graph_id = data.get("graphId")

                saved_vertex = {}
                for item in data.get("dataList"):

                    tail_uid = item.get("ref")["value"]
                    tail_type = item.get("ref")["type"]
                    tail_name = item.get("ref")["name"]

                    head_uid = None
                    head_type = None
                    head_name = None
                    if item.get("parentRef") is not None:
                        head_uid = item.get("parentRef")["value"]
                        head_type = item.get("parentRef")["type"]
                        head_name = item.get("parentRef")["name"]

                    edge_type = item.get("type")
                    path = item.get("path")

                    sql = "INSERT INTO dag_edges (type, head, tail, data, origin, graph_id, path) "
                    sql += "VALUES (?,?,?,?,?,?,?)"
                    cursor.execute(sql, (
                        edge_type,
                        head_uid,
                        tail_uid,
                        item.get("content"),
                        origin_id,
                        graph_id,
                        path
                    ))
                    edge_id = cursor.lastrowid

                    sql = "INSERT INTO dag_streams (graph_id, vertex_id, edge_id, count) VALUES (?, ?, ?, ?)"
                    cursor.execute(sql, (
                        graph_id,
                        stream_id,
                        edge_id,
                        1
                    ))

                    if saved_vertex.get(tail_uid) is None:
                        # Type is RefType enum value
                        sql = "INSERT INTO dag_vertices (vertex_id, type, name) VALUES (?, ?, ?)"
                        cursor.execute(sql, (
                            tail_uid,
                            tail_type,
                            tail_name
                        ))
                        saved_vertex[tail_uid] = True
                    if saved_vertex.get(head_uid) is None:
                        # Type is RefType enum value
                        sql = "INSERT INTO dag_vertices (vertex_id, type, name) VALUES (?, ?, ?)"
                        cursor.execute(sql, (
                            head_uid,
                            head_type,
                            head_name
                        ))
                        saved_vertex[head_uid] = True

                connection.commit()

    def sync(self, stream_id: str, sync_point: Optional[int] = 0, graph_id: Optional[int] = 0) -> SyncData:

        self.debug(f"Sync: stream id {stream_id}, sync point {sync_point}, graph {graph_id}")

        edge_type_map = {
            EdgeType.DATA.value: "data",
            EdgeType.KEY.value: "key",
            EdgeType.LINK.value: "link",
            EdgeType.ACL.value: "acl",
            EdgeType.DELETION.value: "deletion",
            EdgeType.DENIAL.value: "denial",
            EdgeType.UNDENIAL.value: "undenial",
        }

        resp = {
            "syncPoint": 0,
            "data": [],
            "hasMore": False
        }

        with closing(sqlite3.connect(self.db_file)) as connection:
            with closing(connection.cursor()) as cursor:
                self.debug(f"... loading DAG, {stream_id}, {sync_point}, {self.limit + 1}")

                args = [stream_id, sync_point, graph_id]
                sql = "SELECT sync_point, edge_id FROM dag_streams WHERE vertex_id = ? AND deletion = 0 "\
                      "AND sync_point > ? AND graph_id=? ORDER BY sync_point ASC LIMIT ?"
                args.append(self.limit + 1)
                res = cursor.execute(sql, tuple(args))
                rows = list(res.fetchall())
                if len(rows) > self.limit:
                    resp["hasMore"] = True
                    rows.pop()
                for row in rows:
                    resp["syncPoint"] = row[0]

                    args = [row[1], graph_id]
                    sql = "SELECT head, tail, data, path, type FROM dag_edges WHERE edge_id = ? AND graph_id=?"
                    res = cursor.execute(sql, tuple(args))
                    edges = res.fetchone()

                    # If the head and tail are the same (DATA edge), then parent_ref is None.
                    # Else include a parent_ref
                    parent_ref = None
                    if edges[1] != edges[0]:

                        sql = "SELECT type FROM dag_vertices WHERE vertex_id = ?"
                        res = cursor.execute(sql, (edges[0],))
                        head_vertex = res.fetchone()

                        parent_ref = {
                            "type": head_vertex[0],
                            "value": edges[0],
                            "name": None
                        }

                    sql = "SELECT type FROM dag_vertices WHERE vertex_id = ?"
                    res = cursor.execute(sql, (edges[1],))
                    tail_vertex = res.fetchone()

                    resp["data"].append({
                        "type": edge_type_map.get(edges[4]),
                        "ref": {
                            "type": tail_vertex[0],
                            "value": edges[1],
                            "name": None
                        },
                        "parentRef": parent_ref,
                        "content": edges[2],
                        "path": edges[3],
                        "deletion": False
                    })

        sync_data_resp = SyncData.model_validate_json(json.dumps(resp))
        return sync_data_resp

    def debug_dump(self) -> str:

        ret = ""

        with closing(sqlite3.connect(self.db_file)) as connection:
            with closing(connection.cursor()) as cursor:

                cols = ["graph_id", "edge_id", "type", "head", "tail", "data", "origin", "path", "created",
                        "creator_id", "creator_type", "creator_name"]

                sql = f"SELECT {','.join(cols) } FROM dag_edges ORDER BY edge_id DESC"
                res = cursor.execute(sql,)

                ret += "dag_edges\n"
                ret += "=========\n"
                table = []
                for row in res.fetchall():
                    table.append(list(row))

                ret += tabulate(table, cols) + "\n\n"

                cols = ["e.graph_id", "e.edge_id", "v.vertex_id", "v.type", "v.name", "v.owner_id"]

                sql = f"SELECT {','.join(cols) } "\
                      "FROM dag_vertices v "\
                      "INNER JOIN dag_edges e ON e.tail = v.vertex_id "\
                      "ORDER BY e.graph_id DESC, e.edge_id DESC"
                res = cursor.execute(sql,)

                ret += "dag_vertices\n"
                ret += "============\n"
                table = []
                for row in res.fetchall():
                    table.append(list(row))

                ret += tabulate(table, cols) + "\n\n"

                cols = ["graph_id", "edge_id", "sync_point", "vertex_id", "count", "deletion"]

                sql = f"SELECT {','.join(cols) } FROM dag_streams ORDER BY edge_id DESC"
                res = cursor.execute(sql,)

                ret += "dag_streams\n"
                ret += "===========\n"
                table = []
                for row in res.fetchall():
                    table.append(list(row))

                ret += tabulate(table, cols) + "\n\n"

        return ret

    def update_edge_content(self, graph_id: int, head_uid: str, tail_uid: str, content: str):

        with closing(sqlite3.connect(self.db_file)) as connection:
            with closing(connection.cursor()) as cursor:

                sql = "UPDATE dag_edges SET data=? WHERE graph_id=? AND head=? AND tail=?"
                res = cursor.execute(sql, (content, graph_id, head_uid, tail_uid))

            connection.commit()

    def clear(self):

        with closing(sqlite3.connect(self.db_file)) as connection:
            with closing(connection.cursor()) as cursor:

                for table in ["dag_streams", "dag_edges", "dag_vertices"]:
                    sql = f"DELETE FROM {table}"
                    cursor.execute(sql, )

            connection.commit()
